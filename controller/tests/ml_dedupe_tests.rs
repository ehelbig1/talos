//! RFC 0011 — `DatasetService::dedupe_by_content` against a real database.
//!
//! Two properties that only SQL can demonstrate:
//!
//! 1. **Model-scoped grouping.** `md5(embedding::text)` is a content key only
//!    WITHIN one embedding model. During a partial re-embed a dataset holds the
//!    same text under two models (and, for pre-provenance rows, under no model
//!    at all); those must never collapse into one another. Both windows in
//!    `CONTENT_RANK_CTE` partition by `(embedding_model, content_key)`.
//! 2. **Population honesty.** Rows with no stored embedding have no content key
//!    and cannot be considered. `rows_without_embedding` says so, instead of
//!    letting the survey read as full coverage.

mod common;

use std::sync::Arc;
use talos_ml::{AppendExample, DatasetService, ExampleSource};
use uuid::Uuid;

/// Dimensionality of `ml_examples.embedding` (vector(1024) since migration
/// 20260711150000). A literal of any other width fails the INSERT.
const DIMS: usize = 1024;

fn set_master_key() {
    std::env::set_var(
        "TALOS_MASTER_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
}

/// A constant vector whose every component is `seed` — distinct seeds give
/// distinct vectors, and therefore distinct `md5(embedding::text)` keys.
fn vec_literal(seed: f32) -> String {
    let mut s = String::with_capacity(DIMS * 4 + 2);
    s.push('[');
    for i in 0..DIMS {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!("{seed}"));
    }
    s.push(']');
    s
}

async fn seed_user(pool: &sqlx::Pool<sqlx::Postgres>, id: Uuid) {
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) \
         VALUES ($1, $2, 'not-a-real-hash', true) ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(format!("{id}@ml-dedupe.test"))
    .execute(pool)
    .await
    .expect("seed user");
}

async fn seed_dataset(pool: &sqlx::Pool<sqlx::Postgres>, user_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO ml_datasets (id, user_id, name, task_type) \
         VALUES ($1, $2, $3, 'classification')",
    )
    .bind(id)
    .bind(user_id)
    .bind(format!("ds-{id}"))
    .execute(pool)
    .await
    .expect("seed dataset");
    id
}

async fn dataset_service(pool: &sqlx::Pool<sqlx::Postgres>) -> DatasetService {
    set_master_key();
    let sm = Arc::new(controller::secrets::SecretsManager::new(pool.clone()).unwrap());
    sm.initialize().await.unwrap();
    DatasetService::new(sm)
}

/// Append one row per key through the real service (encrypt + insert). No
/// embedder is configured in tests, so every row lands with `embedding IS
/// NULL`; the callers below stamp the vectors they need directly.
async fn append_rows(
    svc: &DatasetService,
    pool: &sqlx::Pool<sqlx::Postgres>,
    dataset_id: Uuid,
    keys: &[&str],
) {
    let tenancy = {
        let mut conn = pool.acquire().await.unwrap();
        svc.dataset_tenancy(&mut conn, dataset_id).await.unwrap()
    };
    let examples: Vec<AppendExample> = keys
        .iter()
        .map(|k| AppendExample {
            features_text: format!("Subject: {k}"),
            label: "archive".to_string(),
            source: ExampleSource::LlmProduction,
            example_key: Some((*k).to_string()),
        })
        .collect();
    let prepared = svc
        .prepare_examples(dataset_id, tenancy, examples)
        .await
        .unwrap();
    let mut conn = pool.acquire().await.unwrap();
    svc.insert_prepared(&mut conn, dataset_id, tenancy, prepared)
        .await
        .unwrap();
}

/// Stamp one row's embedding + provenance model directly (`None` = the
/// legacy, pre-provenance-migration shape).
async fn stamp(
    pool: &sqlx::Pool<sqlx::Postgres>,
    dataset_id: Uuid,
    key: &str,
    seed: f32,
    model: Option<&str>,
) {
    let affected = sqlx::query(
        "UPDATE ml_examples SET embedding = $1::vector, embedding_model = $2 \
         WHERE dataset_id = $3 AND example_key = $4",
    )
    .bind(vec_literal(seed))
    .bind(model)
    .bind(dataset_id)
    .bind(key)
    .execute(pool)
    .await
    .expect("stamp embedding")
    .rows_affected();
    assert_eq!(affected, 1, "expected to stamp exactly one row for {key}");
}

/// The fixture both tests share:
///   a1,a2 — same vector, same model      → ONE duplicate group
///   b1    — vector B, model-a
///   b2    — vector B, model-b            → cross-model, must NOT group with b1
///   n1,n2 — vector B, NO model           → their own group-space (not with b*)
///   e1    — no embedding at all          → invisible to content dedupe
async fn seeded_fixture(pool: &sqlx::Pool<sqlx::Postgres>) -> (DatasetService, Uuid) {
    let user = Uuid::new_v4();
    seed_user(pool, user).await;
    let ds = seed_dataset(pool, user).await;
    let svc = dataset_service(pool).await;
    append_rows(&svc, pool, ds, &["a1", "a2", "b1", "b2", "n1", "n2", "e1"]).await;
    stamp(pool, ds, "a1", 0.25, Some("model-a")).await;
    stamp(pool, ds, "a2", 0.25, Some("model-a")).await;
    stamp(pool, ds, "b1", 0.75, Some("model-a")).await;
    stamp(pool, ds, "b2", 0.75, Some("model-b")).await;
    stamp(pool, ds, "n1", 0.75, None).await;
    stamp(pool, ds, "n2", 0.75, None).await;
    (svc, ds)
}

#[tokio::test]
async fn content_dedupe_groups_within_an_embedding_model_only() {
    let (pool, _db) = common::isolated_db_pool().await;
    let (svc, ds) = seeded_fixture(&pool).await;
    let mut conn = pool.acquire().await.unwrap();

    let survey = svc
        .dedupe_by_content(&mut conn, ds, true, true)
        .await
        .expect("dry-run survey");

    // {a1,a2} and {n1,n2}. b1/b2 share a VECTOR but not a model, so they are
    // two groups of one. Without the model in the partition key, b1/b2/n1/n2
    // would collapse into a single group of four and `rows_removable` would be
    // 4 — that is the mutation this assertion catches.
    assert_eq!(survey.duplicate_groups, 2, "one pair per model space");
    assert_eq!(survey.rows_removable, 2);
    assert_eq!(
        survey.conflicting_groups, 0,
        "every row carries the same label"
    );

    // Re-embedding b2 onto model-a completes the backfill: now it IS the same
    // content under the same model, and the pair groups.
    stamp(&pool, ds, "b2", 0.75, Some("model-a")).await;
    let survey = svc
        .dedupe_by_content(&mut conn, ds, true, true)
        .await
        .expect("dry-run survey after re-embed");
    assert_eq!(survey.duplicate_groups, 3);
    assert_eq!(survey.rows_removable, 3);

    // And the delete removes exactly what the preview promised.
    let applied = svc
        .dedupe_by_content(&mut conn, ds, false, true)
        .await
        .expect("apply");
    assert_eq!(applied.rows_removed, 3);
    // The legacy NULL-model row survives as its own group's survivor — it was
    // never mixed into the model-a space.
    let surviving_null: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM ml_examples WHERE dataset_id = $1 AND embedding_model IS NULL \
           AND embedding IS NOT NULL",
    )
    .bind(ds)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(surviving_null, 1);
}

#[tokio::test]
async fn survey_discloses_the_rows_it_could_not_consider() {
    let (pool, _db) = common::isolated_db_pool().await;
    let (svc, ds) = seeded_fixture(&pool).await;
    let mut conn = pool.acquire().await.unwrap();

    let survey = svc
        .dedupe_by_content(&mut conn, ds, true, true)
        .await
        .expect("dry-run survey");

    // The fixture appends 7 rows and stamps 6 of them.
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ml_examples WHERE dataset_id = $1")
        .bind(ds)
        .fetch_one(&pool)
        .await
        .unwrap();
    let embedded: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM ml_examples WHERE dataset_id = $1 AND embedding IS NOT NULL",
    )
    .bind(ds)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(total, 7);
    assert_eq!(embedded, 6);
    assert_eq!(
        survey.rows_without_embedding,
        total - embedded,
        "the survey must state the population it could not see"
    );
    assert_eq!(survey.rows_without_embedding, 1);

    // The disclosure is reported in EXECUTED mode too, not just the preview —
    // an operator reading the applied result gets the same population caveat.
    let applied = svc
        .dedupe_by_content(&mut conn, ds, false, true)
        .await
        .expect("apply");
    assert_eq!(applied.rows_without_embedding, 1);
}
