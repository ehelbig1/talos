//! RFC 0011 — the shared `talos_ml::resolve_disagreement` flow against a
//! real database: a correction appends a `source=correction` gold example
//! (built from the disagreement's OWN stored features) and flips the row
//! to `resolved`; a dismiss flips without appending; the flow is
//! idempotent; and it refuses to resolve another tenant's disagreement.
//! This is the ONE implementation both the MCP handler and the GraphQL
//! resolver call, so these invariants cover both surfaces.

mod common;

use std::sync::Arc;
use talos_ml::{resolve_disagreement, DatasetService, LifecycleService, ResolveError};
use uuid::Uuid;

fn set_master_key() {
    std::env::set_var(
        "TALOS_MASTER_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
}

async fn seed_user(pool: &sqlx::Pool<sqlx::Postgres>, id: Uuid) {
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) \
         VALUES ($1, $2, 'not-a-real-hash', true) ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(format!("{id}@ml-correction.test"))
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

async fn seed_model(pool: &sqlx::Pool<sqlx::Postgres>, user_id: Uuid, dataset_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO ml_models (id, user_id, name, task_type, dataset_id, config_json) \
         VALUES ($1, $2, $3, 'classification', $4, '{}'::jsonb)",
    )
    .bind(id)
    .bind(user_id)
    .bind(format!("m-{id}"))
    .bind(dataset_id)
    .execute(pool)
    .await
    .expect("seed model");
    id
}

async fn services(pool: &sqlx::Pool<sqlx::Postgres>) -> (LifecycleService, DatasetService) {
    set_master_key();
    let sm = Arc::new(controller::secrets::SecretsManager::new(pool.clone()).unwrap());
    sm.initialize().await.unwrap();
    talos_memory::register_memory_crypto_hook(Arc::new(
        talos_memory_crypto::SecretsManagerMemoryCrypto::new(sm.clone()),
    ));
    (LifecycleService::new(sm.clone()), DatasetService::new(sm))
}

/// Records one divergence and returns its id.
async fn seed_disagreement(
    ls: &LifecycleService,
    pool: &sqlx::Pool<sqlx::Postgres>,
    model: Uuid,
    user: Uuid,
    example_key: &str,
) -> Uuid {
    let mut conn = pool.acquire().await.unwrap();
    ls.record_disagreement(
        &mut conn,
        model,
        user,
        None,
        Some(example_key),
        "Subject: 50% off — weekend sale ends Sunday",
        Some(("to_read", 0.9)),
        "archive",
        "divergence",
    )
    .await
    .expect("record disagreement")
}

#[tokio::test]
async fn resolve_appends_correction_and_flips_status() {
    let (pool, _db) = common::isolated_db_pool().await;
    set_master_key();
    let user = Uuid::new_v4();
    seed_user(&pool, user).await;
    let ds = seed_dataset(&pool, user).await;
    let model = seed_model(&pool, user, ds).await;
    let (ls, dsvc) = services(&pool).await;
    let id = seed_disagreement(&ls, &pool, model, user, "msg-a").await;

    let outcome = resolve_disagreement(&pool, &ls, &dsvc, id, user, Some("archive"))
        .await
        .expect("resolve ok");
    assert_eq!(outcome.status, "resolved");
    assert!(outcome.correction_appended);

    // The disagreement flipped to resolved.
    let status: String = sqlx::query_scalar("SELECT status FROM ml_disagreements WHERE id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "resolved");

    // A gold correction landed in the dataset with the caller's label and
    // the disagreement's OWN example_key (trusted provenance).
    let (source, label, ekey): (String, String, Option<String>) = sqlx::query_as(
        "SELECT source, label_json->>'label', example_key FROM ml_examples \
         WHERE dataset_id = $1 AND source = 'correction'",
    )
    .bind(ds)
    .fetch_one(&pool)
    .await
    .expect("correction example exists");
    assert_eq!(source, "correction");
    assert_eq!(label, "archive");
    assert_eq!(ekey.as_deref(), Some("msg-a"));
}

#[tokio::test]
async fn resolve_is_idempotent_second_call_is_not_found() {
    let (pool, _db) = common::isolated_db_pool().await;
    set_master_key();
    let user = Uuid::new_v4();
    seed_user(&pool, user).await;
    let ds = seed_dataset(&pool, user).await;
    let model = seed_model(&pool, user, ds).await;
    let (ls, dsvc) = services(&pool).await;
    let id = seed_disagreement(&ls, &pool, model, user, "msg-b").await;

    resolve_disagreement(&pool, &ls, &dsvc, id, user, Some("archive"))
        .await
        .expect("first resolve ok");
    // Second resolve of an already-handled row is a clean NotFound.
    let err = resolve_disagreement(&pool, &ls, &dsvc, id, user, Some("archive"))
        .await
        .expect_err("second resolve rejected");
    assert!(matches!(err, ResolveError::NotFound));
}

#[tokio::test]
async fn dismiss_flips_status_without_appending() {
    let (pool, _db) = common::isolated_db_pool().await;
    set_master_key();
    let user = Uuid::new_v4();
    seed_user(&pool, user).await;
    let ds = seed_dataset(&pool, user).await;
    let model = seed_model(&pool, user, ds).await;
    let (ls, dsvc) = services(&pool).await;
    let id = seed_disagreement(&ls, &pool, model, user, "msg-c").await;

    let outcome = resolve_disagreement(&pool, &ls, &dsvc, id, user, None)
        .await
        .expect("dismiss ok");
    assert_eq!(outcome.status, "dismissed");
    assert!(!outcome.correction_appended);

    let status: String = sqlx::query_scalar("SELECT status FROM ml_disagreements WHERE id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "dismissed");
    let corrections: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM ml_examples WHERE dataset_id = $1 AND source = 'correction'",
    )
    .bind(ds)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(corrections, 0, "dismiss appends nothing");
}

#[tokio::test]
async fn resolve_refuses_another_tenants_disagreement() {
    let (pool, _db) = common::isolated_db_pool().await;
    set_master_key();
    let owner = Uuid::new_v4();
    let stranger = Uuid::new_v4();
    seed_user(&pool, owner).await;
    seed_user(&pool, stranger).await;
    let ds = seed_dataset(&pool, owner).await;
    let model = seed_model(&pool, owner, ds).await;
    let (ls, dsvc) = services(&pool).await;
    let id = seed_disagreement(&ls, &pool, model, owner, "msg-d").await;

    // The STRANGER tries to resolve the OWNER's disagreement.
    let err = resolve_disagreement(&pool, &ls, &dsvc, id, stranger, Some("archive"))
        .await
        .expect_err("cross-tenant resolve rejected");
    assert!(matches!(err, ResolveError::NotFound));

    // The owner's row is untouched (still pending) and no example leaked.
    let status: String = sqlx::query_scalar("SELECT status FROM ml_disagreements WHERE id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "pending", "owner's disagreement untouched");
    let corrections: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM ml_examples WHERE dataset_id = $1 AND source = 'correction'",
    )
    .bind(ds)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(corrections, 0);
}
