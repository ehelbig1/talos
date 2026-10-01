//! `DatasetService::re_embed_batch_with` against a real database
//! (2026-10-01).
//!
//! Until this, a dataset row with no embedding, or with one from another
//! embedding model, had no repair path (`re_embed_examples` had no caller),
//! and there was no way to bring a dataset's vectors onto one embedding
//! runtime. The pass is driven here with its embedder supplied by the test —
//! the production wrapper passes the real local embedder — because the
//! statement is built with `format!`, which check 88 cannot see.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use talos_ml::{AppendExample, DatasetService, ExampleSource, ReEmbedScope};
use uuid::Uuid;

const DIMS: usize = 1024;
const ACTIVE: &str = "model-active";
const NO_BUDGET_LIMIT: Duration = Duration::from_secs(600);

fn set_master_key() {
    std::env::set_var(
        "TALOS_MASTER_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
}

/// The stand-in embedder: a vector that depends only on the text, so the
/// same text always yields the same bytes and two texts differ.
fn fake_vector(text: &str) -> Vec<f32> {
    let seed = text.bytes().fold(7u32, |acc, b| {
        acc.wrapping_mul(31).wrapping_add(u32::from(b))
    });
    (0..DIMS)
        .map(|i| ((seed.wrapping_add(i as u32) % 1000) as f32) / 1000.0)
        .collect()
}

fn vec_literal(v: &[f32]) -> String {
    format!(
        "[{}]",
        v.iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(",")
    )
}

async fn seed_user(pool: &sqlx::PgPool, id: Uuid) {
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) \
         VALUES ($1, $2, 'not-a-real-hash', true) ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(format!("{id}@ml-reembed.test"))
    .execute(pool)
    .await
    .expect("seed user");
}

async fn seed_dataset(pool: &sqlx::PgPool, user_id: Uuid) -> Uuid {
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

async fn dataset_service(pool: &sqlx::PgPool) -> DatasetService {
    set_master_key();
    let sm = Arc::new(controller::secrets::SecretsManager::new(pool.clone()).unwrap());
    sm.initialize().await.unwrap();
    DatasetService::new(sm)
}

/// Append `(key, text)` rows through the real service (encrypt + insert). No
/// embedder is configured in tests, so every row lands with no embedding.
async fn append(svc: &DatasetService, pool: &sqlx::PgPool, ds: Uuid, rows: &[(&str, &str)]) {
    let tenancy = {
        let mut conn = pool.acquire().await.unwrap();
        svc.dataset_tenancy(&mut conn, ds).await.unwrap()
    };
    let examples = rows
        .iter()
        .map(|(key, text)| AppendExample {
            features_text: (*text).to_string(),
            label: "archive".to_string(),
            source: ExampleSource::LlmProduction,
            example_key: Some((*key).to_string()),
        })
        .collect();
    let prepared = svc.prepare_examples(ds, tenancy, examples).await.unwrap();
    let mut conn = pool.acquire().await.unwrap();
    svc.insert_prepared(&mut conn, ds, tenancy, prepared)
        .await
        .unwrap();
}

async fn stamp(pool: &sqlx::PgPool, ds: Uuid, key: &str, vector: &[f32], model: Option<&str>) {
    let affected = sqlx::query(
        "UPDATE ml_examples SET embedding = $1::vector, embedding_model = $2 \
         WHERE dataset_id = $3 AND example_key = $4",
    )
    .bind(vec_literal(vector))
    .bind(model)
    .bind(ds)
    .bind(key)
    .execute(pool)
    .await
    .expect("stamp")
    .rows_affected();
    assert_eq!(affected, 1, "stamp {key}");
}

/// `(model, md5 of the stored vector)` for one row.
async fn stored(pool: &sqlx::PgPool, ds: Uuid, key: &str) -> (Option<String>, Option<String>) {
    sqlx::query_as(
        "SELECT embedding_model, md5(embedding::text) FROM ml_examples \
         WHERE dataset_id = $1 AND example_key = $2",
    )
    .bind(ds)
    .bind(key)
    .fetch_one(pool)
    .await
    .expect("read row")
}

async fn md5_of(pool: &sqlx::PgPool, vector: &[f32]) -> String {
    sqlx::query_scalar("SELECT md5(($1::vector)::text)")
        .bind(vec_literal(vector))
        .fetch_one(pool)
        .await
        .expect("md5")
}

async fn embed_ok(text: String) -> Option<Vec<f32>> {
    Some(fake_vector(&text))
}

#[tokio::test]
async fn stale_scope_repairs_only_the_rows_the_active_model_cannot_serve() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = Uuid::new_v4();
    seed_user(&pool, user).await;
    let ds = seed_dataset(&pool, user).await;
    let svc = dataset_service(&pool).await;
    append(
        &svc,
        &pool,
        ds,
        &[
            ("none", "text none"),
            ("other", "text other"),
            ("current", "text current"),
        ],
    )
    .await;
    stamp(
        &pool,
        ds,
        "other",
        &fake_vector("an older vector"),
        Some("model-old"),
    )
    .await;
    let kept = fake_vector("a vector this pass must not touch");
    stamp(&pool, ds, "current", &kept, Some(ACTIVE)).await;
    let dataset_stamp: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT updated_at FROM ml_datasets WHERE id = $1")
            .bind(ds)
            .fetch_one(&pool)
            .await
            .unwrap();

    let mut conn = pool.acquire().await.unwrap();
    let before = svc.re_embed_survey(&mut conn, ds, ACTIVE).await.unwrap();
    assert_eq!(
        (
            before.total,
            before.without_embedding,
            before.other_model,
            before.active_model
        ),
        (3, 1, 1, 1)
    );

    let pass = svc
        .re_embed_batch_with(
            &mut conn,
            ds,
            ReEmbedScope::Stale,
            None,
            100,
            NO_BUDGET_LIMIT,
            ACTIVE,
            embed_ok,
        )
        .await
        .expect("pass");
    assert_eq!(
        (
            pass.processed,
            pass.re_embedded,
            pass.unchanged,
            pass.failed
        ),
        (2, 2, 0, 0)
    );
    assert!(pass.done);

    let after = svc.re_embed_survey(&mut conn, ds, ACTIVE).await.unwrap();
    assert_eq!(
        (
            after.without_embedding,
            after.other_model,
            after.active_model
        ),
        (0, 0, 3)
    );
    for key in ["none", "other"] {
        let (model, md5) = stored(&pool, ds, key).await;
        assert_eq!(model.as_deref(), Some(ACTIVE), "{key}");
        assert_eq!(
            md5,
            Some(md5_of(&pool, &fake_vector(&format!("text {key}"))).await),
            "{key}"
        );
    }
    // The row the active model already serves was not rewritten.
    assert_eq!(
        stored(&pool, ds, "current").await.1,
        Some(md5_of(&pool, &kept).await)
    );
    // Re-embedding changes no label and no text: it must not trigger a retrain.
    let stamp_after: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT updated_at FROM ml_datasets WHERE id = $1")
            .bind(ds)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stamp_after, dataset_stamp);
}

#[tokio::test]
async fn all_scope_brings_every_row_onto_one_runtime_so_identical_content_groups_again() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = Uuid::new_v4();
    seed_user(&pool, user).await;
    let ds = seed_dataset(&pool, user).await;
    let svc = dataset_service(&pool).await;
    // Two rows with the SAME text, embedded by two runtimes of one model:
    // near-identical in practice, different bytes — here, plainly different.
    append(
        &svc,
        &pool,
        ds,
        &[
            ("old", "same text"),
            ("new", "same text"),
            ("solo", "other text"),
        ],
    )
    .await;
    stamp(
        &pool,
        ds,
        "old",
        &fake_vector("old runtime bytes"),
        Some(ACTIVE),
    )
    .await;
    stamp(&pool, ds, "new", &fake_vector("same text"), Some(ACTIVE)).await;
    stamp(&pool, ds, "solo", &fake_vector("other text"), Some(ACTIVE)).await;

    let mut conn = pool.acquire().await.unwrap();
    // The seam: identical content, two vectors, so content dedupe sees nothing.
    let seam = svc
        .dedupe_by_content(&mut conn, ds, true, true)
        .await
        .unwrap();
    assert_eq!(seam.duplicate_groups, 0);
    // Stale scope has nothing to do — every row carries the active model.
    let stale = svc
        .re_embed_batch_with(
            &mut conn,
            ds,
            ReEmbedScope::Stale,
            None,
            100,
            NO_BUDGET_LIMIT,
            ACTIVE,
            embed_ok,
        )
        .await
        .unwrap();
    assert_eq!((stale.processed, stale.done), (0, true));

    let pass = svc
        .re_embed_batch_with(
            &mut conn,
            ds,
            ReEmbedScope::All,
            None,
            100,
            NO_BUDGET_LIMIT,
            ACTIVE,
            embed_ok,
        )
        .await
        .unwrap();
    // Only "old" held different bytes; the other two were NOT rewritten.
    assert_eq!(
        (
            pass.processed,
            pass.re_embedded,
            pass.unchanged,
            pass.failed
        ),
        (3, 1, 2, 0)
    );
    assert!(pass.done);
    let closed = svc
        .dedupe_by_content(&mut conn, ds, true, true)
        .await
        .unwrap();
    assert_eq!(
        closed.duplicate_groups, 1,
        "identical content shares one vector again"
    );

    // A second full pass finds nothing to write.
    let again = svc
        .re_embed_batch_with(
            &mut conn,
            ds,
            ReEmbedScope::All,
            None,
            100,
            NO_BUDGET_LIMIT,
            ACTIVE,
            embed_ok,
        )
        .await
        .unwrap();
    assert_eq!((again.re_embedded, again.unchanged), (0, 3));
}

#[tokio::test]
async fn a_pass_is_bounded_resumable_and_steps_over_a_row_it_cannot_embed() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = Uuid::new_v4();
    seed_user(&pool, user).await;
    let ds = seed_dataset(&pool, user).await;
    let other_ds = seed_dataset(&pool, user).await;
    let svc = dataset_service(&pool).await;
    let rows: Vec<(String, String)> = (0..5)
        .map(|i| (format!("k{i}"), format!("text {i}")))
        .collect();
    let refs: Vec<(&str, &str)> = rows.iter().map(|(k, t)| (k.as_str(), t.as_str())).collect();
    append(&svc, &pool, ds, &refs).await;
    append(
        &svc,
        &pool,
        other_ds,
        &[("foreign", "text in another dataset")],
    )
    .await;

    let calls = Arc::new(AtomicUsize::new(0));
    // The embedder gives nothing for one text, like a provider timing out.
    let embed = |calls: Arc<AtomicUsize>| {
        move |text: String| {
            let calls = calls.clone();
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                (text != "text 2").then(|| fake_vector(&text))
            }
        }
    };

    let mut conn = pool.acquire().await.unwrap();
    let (mut after, mut processed, mut re_embedded, mut failed, mut passes) = (None, 0, 0, 0, 0);
    loop {
        let pass = svc
            .re_embed_batch_with(
                &mut conn,
                ds,
                ReEmbedScope::Stale,
                after,
                2,
                NO_BUDGET_LIMIT,
                ACTIVE,
                embed(calls.clone()),
            )
            .await
            .unwrap();
        passes += 1;
        processed += pass.processed;
        re_embedded += pass.re_embedded;
        failed += pass.failed;
        assert!(pass.processed <= 2, "the row limit bounds a pass");
        after = pass.next_after.or(after);
        if pass.done {
            break;
        }
        assert!(passes < 10, "the cursor must advance");
    }
    // Every row looked at exactly once, the failing one stepped over.
    assert_eq!((processed, re_embedded, failed), (5, 4, 1));
    assert_eq!(calls.load(Ordering::SeqCst), 5);
    assert_eq!(
        stored(&pool, ds, "k2").await,
        (None, None),
        "a failed row is left as it was"
    );
    // The other dataset's row was never touched.
    assert_eq!(stored(&pool, other_ds, "foreign").await, (None, None));

    // A spent budget still makes progress — one row — and is never "done".
    let fresh = seed_dataset(&pool, user).await;
    append(
        &svc,
        &pool,
        fresh,
        &[("a", "t a"), ("b", "t b"), ("c", "t c")],
    )
    .await;
    let cut = svc
        .re_embed_batch_with(
            &mut conn,
            fresh,
            ReEmbedScope::Stale,
            None,
            100,
            Duration::ZERO,
            ACTIVE,
            embed_ok,
        )
        .await
        .unwrap();
    assert_eq!((cut.processed, cut.re_embedded, cut.done), (1, 1, false));
    assert!(cut.next_after.is_some());

    // A vector of the wrong width is a failure, not a write.
    let wrong = svc
        .re_embed_batch_with(
            &mut conn,
            fresh,
            ReEmbedScope::Stale,
            cut.next_after,
            100,
            NO_BUDGET_LIMIT,
            ACTIVE,
            |_t: String| async { Some(vec![0.5f32; 8]) },
        )
        .await
        .unwrap();
    assert_eq!(
        (wrong.processed, wrong.re_embedded, wrong.failed),
        (2, 0, 2)
    );
}
