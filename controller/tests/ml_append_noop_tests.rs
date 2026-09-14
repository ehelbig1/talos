//! A re-append of an unchanged example is a no-op: no row rewrite, no touch of
//! `ml_datasets.updated_at`, and therefore no policy re-evaluation and no new
//! model version.
//!
//! Until 2026-09-14 the `(dataset_id, example_key)` upsert rewrote every
//! conflicting row and the append touched the dataset unconditionally. The
//! evaluator reads that touch as "the dataset changed", so the hourly
//! alert-triage run — which re-distills alerts it already taught — produced an
//! evaluation and a model version every hour: 129 of `ops-severity`'s 162
//! evaluations in 7 days were identical to the previous one. These tests drive
//! the REAL `DatasetService` against a real database and pin, by `xmin` and by
//! the dataset timestamp, which appends write and which do not.
//!
//! The embedder is deliberately dead (NULL embeddings): the no-op test must not
//! depend on vector equality, and a row whose embedding stays NULL must still
//! be recognised as unchanged.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use std::sync::Arc;
use talos_ml::{AppendExample, DatasetService, ExampleSource};
use uuid::Uuid;

fn set_master_key() {
    std::env::set_var(
        "TALOS_MASTER_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
}

fn declare_dead_embedding_provider() {
    std::env::set_var("EMBEDDING_API_URL", "http://127.0.0.1:1/v1/embeddings");
    std::env::set_var("EMBEDDING_MODEL", "talos-test-none");
    std::env::set_var("EMBEDDING_DIMENSIONS", "1024");
}

async fn seed_user(pool: &sqlx::PgPool, id: Uuid) {
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) \
         VALUES ($1, $2, 'x', true) ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(format!("{id}@ml-noop.test"))
    .execute(pool)
    .await
    .expect("seed user");
}

async fn seed_dataset(pool: &sqlx::PgPool, user_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO ml_datasets (id, user_id, name, task_type, updated_at) \
         VALUES ($1, $2, $3, 'classification', NOW() - INTERVAL '1 day')",
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
    talos_memory::register_memory_crypto_hook(Arc::new(
        talos_memory_crypto::SecretsManagerMemoryCrypto::new(sm.clone()),
    ));
    DatasetService::new(sm)
}

fn ex(key: &str, text: &str, label: &str, source: ExampleSource) -> AppendExample {
    AppendExample {
        features_text: text.to_string(),
        label: label.to_string(),
        source,
        example_key: Some(key.to_string()),
    }
}

/// One append, exactly as production callers do it: prepare outside any
/// transaction, then a short write.
async fn append(
    dsvc: &DatasetService,
    pool: &sqlx::PgPool,
    ds: Uuid,
    examples: Vec<AppendExample>,
) -> usize {
    let mut conn = pool.acquire().await.unwrap();
    let tenancy = dsvc.dataset_tenancy(&mut conn, ds).await.unwrap();
    let prepared = dsvc.prepare_examples(ds, tenancy, examples).await.unwrap();
    dsvc.insert_prepared(&mut conn, ds, tenancy, prepared)
        .await
        .unwrap()
}

async fn dataset_updated_at(pool: &sqlx::PgPool, ds: Uuid) -> chrono::DateTime<chrono::Utc> {
    sqlx::query_scalar("SELECT updated_at FROM ml_datasets WHERE id = $1")
        .bind(ds)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// `(example_key, xmin)` per row — a row's xmin changes exactly when a new
/// row version is written for it.
async fn row_versions(pool: &sqlx::PgPool, ds: Uuid) -> Vec<(String, String)> {
    sqlx::query_as(
        "SELECT example_key, xmin::text FROM ml_examples WHERE dataset_id = $1 ORDER BY example_key",
    )
    .bind(ds)
    .fetch_all(pool)
    .await
    .unwrap()
}

/// The evaluator's own decision, over the real stored timestamp: a model whose
/// last evaluation ATTEMPT was `attempt`, visited two hours later (well past the
/// one-hour debounce), with the dataset's CURRENT `updated_at`.
async fn evaluator_would_run(
    pool: &sqlx::PgPool,
    ds: Uuid,
    attempt: chrono::DateTime<chrono::Utc>,
) -> bool {
    talos_ml::lifecycle_job::should_evaluate(
        talos_ml::LifecycleState::Shadow,
        Some(attempt),
        dataset_updated_at(pool, ds).await,
        attempt + chrono::Duration::hours(2),
        chrono::Duration::seconds(talos_ml::lifecycle_job::DEFAULT_MIN_EVAL_INTERVAL_SECS),
    )
}

async fn db_now(pool: &sqlx::PgPool) -> chrono::DateTime<chrono::Utc> {
    sqlx::query_scalar("SELECT NOW()")
        .fetch_one(pool)
        .await
        .unwrap()
}

fn batch() -> Vec<AppendExample> {
    vec![
        ex(
            "a",
            "disk full on db-1",
            "critical",
            ExampleSource::LlmProduction,
        ),
        ex(
            "b",
            "nightly backup ok",
            "noise",
            ExampleSource::LlmProduction,
        ),
        ex(
            "c",
            "cert expires in 20 days",
            "low",
            ExampleSource::LlmProduction,
        ),
    ]
}

#[tokio::test]
async fn an_unchanged_reappend_writes_nothing_and_does_not_touch_the_dataset() {
    let (pool, _db) = common::isolated_db_pool().await;
    declare_dead_embedding_provider();
    let user = Uuid::new_v4();
    seed_user(&pool, user).await;
    let ds = seed_dataset(&pool, user).await;
    let dsvc = dataset_service(&pool).await;

    // CONTROL: a first append writes every row and touches the dataset.
    let before_first = dataset_updated_at(&pool, ds).await;
    assert_eq!(append(&dsvc, &pool, ds, batch()).await, 3);
    let after_first = dataset_updated_at(&pool, ds).await;
    assert!(
        after_first > before_first,
        "a real append must touch the dataset"
    );
    let fingerprints: i64 = sqlx::query_scalar(
        "SELECT COUNT(content_fingerprint) FROM ml_examples WHERE dataset_id = $1",
    )
    .bind(ds)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        fingerprints, 3,
        "every prepared row carries its fingerprint"
    );
    let versions = row_versions(&pool, ds).await;
    // An evaluation ran after the first append.
    let attempt = db_now(&pool).await;

    // THE CASE: the same batch again, exactly what the hourly re-distill sends.
    assert_eq!(
        append(&dsvc, &pool, ds, batch()).await,
        0,
        "an unchanged re-append is not a stored row"
    );
    assert_eq!(
        row_versions(&pool, ds).await,
        versions,
        "no new row version may be written for an unchanged example"
    );
    assert_eq!(
        dataset_updated_at(&pool, ds).await,
        after_first,
        "an unchanged re-append must not tell the policy evaluator the dataset changed"
    );
    // The consequence the whole change exists for: no re-evaluation, so no new
    // model version.
    assert!(
        !evaluator_would_run(&pool, ds, attempt).await,
        "the evaluator must decline after a no-op re-append"
    );
}

#[tokio::test]
async fn a_relabel_or_changed_text_under_the_same_key_is_written_and_touches() {
    let (pool, _db) = common::isolated_db_pool().await;
    declare_dead_embedding_provider();
    let user = Uuid::new_v4();
    seed_user(&pool, user).await;
    let ds = seed_dataset(&pool, user).await;
    let dsvc = dataset_service(&pool).await;
    append(&dsvc, &pool, ds, batch()).await;

    // A relabel of ONE row: exactly that row is rewritten.
    let attempt = db_now(&pool).await;
    assert!(
        !evaluator_would_run(&pool, ds, attempt).await,
        "control: nothing changed since the attempt"
    );
    let versions = row_versions(&pool, ds).await;
    let t0 = dataset_updated_at(&pool, ds).await;
    let mut relabel = batch();
    relabel[1].label = "low".to_string();
    assert_eq!(append(&dsvc, &pool, ds, relabel).await, 1);
    let after = row_versions(&pool, ds).await;
    assert_eq!(after[0], versions[0], "row a untouched");
    assert_ne!(after[1], versions[1], "row b relabelled");
    assert_eq!(after[2], versions[2], "row c untouched");
    let t1 = dataset_updated_at(&pool, ds).await;
    assert!(t1 > t0, "a relabel is a dataset change");
    assert!(
        evaluator_would_run(&pool, ds, attempt).await,
        "a real change must still reach the evaluator"
    );

    // NEW TEXT under an existing producer key (an ops dedup_key reused by a
    // newer alert): the label is unchanged, only the fingerprint differs.
    let mut retext = batch();
    retext[0].features_text = "disk full on db-2".to_string();
    retext[1].label = "low".to_string();
    assert_eq!(append(&dsvc, &pool, ds, retext).await, 1);
    assert!(dataset_updated_at(&pool, ds).await > t1);
}

#[tokio::test]
async fn a_row_written_before_the_fingerprint_is_rewritten_once_then_settles() {
    let (pool, _db) = common::isolated_db_pool().await;
    declare_dead_embedding_provider();
    let user = Uuid::new_v4();
    seed_user(&pool, user).await;
    let ds = seed_dataset(&pool, user).await;
    let dsvc = dataset_service(&pool).await;
    append(&dsvc, &pool, ds, batch()).await;
    // The pre-migration shape: no fingerprint on the stored row.
    sqlx::query(
        "UPDATE ml_examples SET content_fingerprint = NULL \
         WHERE dataset_id = $1 AND example_key = 'a'",
    )
    .bind(ds)
    .execute(&pool)
    .await
    .unwrap();

    assert_eq!(
        append(&dsvc, &pool, ds, batch()).await,
        1,
        "a NULL fingerprint is DISTINCT — the legacy row is rewritten once, backfilling it"
    );
    assert_eq!(
        append(&dsvc, &pool, ds, batch()).await,
        0,
        "and is a no-op from then on"
    );
}

#[tokio::test]
async fn a_correction_still_wins_and_a_bootstrap_reappend_over_it_writes_nothing() {
    let (pool, _db) = common::isolated_db_pool().await;
    declare_dead_embedding_provider();
    let user = Uuid::new_v4();
    seed_user(&pool, user).await;
    let ds = seed_dataset(&pool, user).await;
    let dsvc = dataset_service(&pool).await;
    append(&dsvc, &pool, ds, batch()).await;

    let fix = vec![ex(
        "a",
        "disk full on db-1",
        "high",
        ExampleSource::Correction,
    )];
    assert_eq!(
        append(&dsvc, &pool, ds, fix).await,
        1,
        "a correction overwrites"
    );

    let t = dataset_updated_at(&pool, ds).await;
    // The teacher re-labels the same text: the correction guard refuses it,
    // and a refused row must not be counted or touch the dataset.
    assert_eq!(append(&dsvc, &pool, ds, batch()).await, 0);
    assert_eq!(dataset_updated_at(&pool, ds).await, t);
    let (label, source): (String, String) = sqlx::query_as(
        "SELECT label_json->>'label', source FROM ml_examples \
         WHERE dataset_id = $1 AND example_key = 'a'",
    )
    .bind(ds)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((label.as_str(), source.as_str()), ("high", "correction"));
}

/// The fingerprint is DATASET-SCOPED: identical text in two datasets (here two
/// tenants) must not share a value, or the column would let a reader of the
/// table see which tenants hold the same content. Driven through the real
/// `prepare_examples`, so it pins the derivation production uses, not a
/// restatement of it.
#[tokio::test]
async fn identical_text_in_two_datasets_gets_unrelated_fingerprints() {
    let (pool, _db) = common::isolated_db_pool().await;
    declare_dead_embedding_provider();
    let dsvc = dataset_service(&pool).await;
    let mut datasets = Vec::new();
    for _ in 0..2 {
        let user = Uuid::new_v4();
        seed_user(&pool, user).await;
        let ds = seed_dataset(&pool, user).await;
        append(&dsvc, &pool, ds, batch()).await;
        datasets.push(ds);
    }
    let fingerprint = |ds: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, String>(
                "SELECT content_fingerprint FROM ml_examples \
                 WHERE dataset_id = $1 AND example_key = 'a'",
            )
            .bind(ds)
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    let a = fingerprint(datasets[0]).await;
    let b = fingerprint(datasets[1]).await;
    assert!(a.starts_with("cf1:") && b.starts_with("cf1:"), "{a} / {b}");
    assert_ne!(
        a, b,
        "same text, different datasets → unrelated fingerprints"
    );
    let key: String = sqlx::query_scalar(
        "SELECT example_key FROM ml_examples WHERE dataset_id = $1 AND example_key = 'a'",
    )
    .bind(datasets[0])
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_ne!(a, key);
}

/// A correction that CONFIRMS the teacher's label changes only `source` — and
/// that is still a change: corrections are pinned against growth-cap eviction,
/// weighted in the vote and counted by the promotion gate. It must be written.
#[tokio::test]
async fn a_correction_confirming_the_same_label_is_still_written() {
    let (pool, _db) = common::isolated_db_pool().await;
    declare_dead_embedding_provider();
    let user = Uuid::new_v4();
    seed_user(&pool, user).await;
    let ds = seed_dataset(&pool, user).await;
    let dsvc = dataset_service(&pool).await;
    append(&dsvc, &pool, ds, batch()).await;

    let t = dataset_updated_at(&pool, ds).await;
    let confirm = vec![ex(
        "a",
        "disk full on db-1",
        "critical",
        ExampleSource::Correction,
    )];
    assert_eq!(append(&dsvc, &pool, ds, confirm).await, 1);
    assert!(dataset_updated_at(&pool, ds).await > t);
    let source: String = sqlx::query_scalar(
        "SELECT source FROM ml_examples WHERE dataset_id = $1 AND example_key = 'a'",
    )
    .bind(ds)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(source, "correction");
}

/// The touch covers EVICTION too: an append that writes nothing but trims the
/// dataset past a (lowered) growth cap has changed the training set.
#[tokio::test]
async fn an_eviction_without_a_write_still_touches_the_dataset() {
    let (pool, _db) = common::isolated_db_pool().await;
    declare_dead_embedding_provider();
    let user = Uuid::new_v4();
    seed_user(&pool, user).await;
    let ds = seed_dataset(&pool, user).await;
    let dsvc = dataset_service(&pool).await;
    append(&dsvc, &pool, ds, batch()).await;
    sqlx::query(
        "UPDATE ml_datasets SET schema_json = '{\"max_examples\": 2}'::jsonb WHERE id = $1",
    )
    .bind(ds)
    .execute(&pool)
    .await
    .unwrap();
    let t = dataset_updated_at(&pool, ds).await;

    assert_eq!(append(&dsvc, &pool, ds, batch()).await, 0, "no row written");
    let remaining: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM ml_examples WHERE dataset_id = $1")
            .bind(ds)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, 2, "the cap evicted one row");
    assert!(
        dataset_updated_at(&pool, ds).await > t,
        "an eviction is a dataset change even when the append wrote nothing"
    );
}
