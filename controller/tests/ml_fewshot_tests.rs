//! `talos.ml.fewshot` server side against a real database: class-balanced
//! recency selection over `source='correction'` rows only, wire-cap
//! truncation, the k cap, and cross-tenant invisibility.

mod common;

use std::sync::Arc;
use talos_ml::{few_shot_for_model, DatasetService, ServeError};
use talos_ml::{AppendExample, ExampleSource};
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
         VALUES ($1, $2, 'x', true) ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(format!("{id}@ml-fewshot.test"))
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

async fn seed_model(
    pool: &sqlx::Pool<sqlx::Postgres>,
    user_id: Uuid,
    dataset_id: Uuid,
    name: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO ml_models (id, user_id, name, task_type, dataset_id, config_json) \
         VALUES ($1, $2, $3, 'classification', $4, '{}'::jsonb)",
    )
    .bind(id)
    .bind(user_id)
    .bind(name)
    .bind(dataset_id)
    .execute(pool)
    .await
    .expect("seed model");
    id
}

async fn dataset_service(pool: &sqlx::Pool<sqlx::Postgres>) -> DatasetService {
    set_master_key();
    let sm = Arc::new(controller::secrets::SecretsManager::new(pool.clone()).unwrap());
    sm.initialize().await.unwrap();
    DatasetService::new(sm)
}

fn ex(text: &str, label: &str, source: ExampleSource) -> AppendExample {
    AppendExample {
        features_text: text.to_string(),
        label: label.to_string(),
        source,
        example_key: None,
    }
}

#[tokio::test]
async fn few_shot_is_correction_only_balanced_and_recent() {
    let (pool, _db) = common::isolated_db_pool().await;
    set_master_key();
    let user = Uuid::new_v4();
    seed_user(&pool, user).await;
    let dataset_id = seed_dataset(&pool, user).await;
    seed_model(&pool, user, dataset_id, "fewshot-model").await;
    let dsvc = dataset_service(&pool).await;

    let mut conn = pool.acquire().await.unwrap();
    // Lopsided corrections (5 to_read, 2 archive) + noise rows from other
    // sources that MUST be excluded.
    let mut batch = vec![
        ex("tr-1", "to_read", ExampleSource::Correction),
        ex("tr-2", "to_read", ExampleSource::Correction),
        ex("tr-3", "to_read", ExampleSource::Correction),
        ex("tr-4", "to_read", ExampleSource::Correction),
        ex("tr-5", "to_read", ExampleSource::Correction),
        ex("ar-1", "archive", ExampleSource::Correction),
        ex("ar-2", "archive", ExampleSource::Correction),
    ];
    batch.push(ex("noise-1", "to_read", ExampleSource::LlmProduction));
    batch.push(ex("noise-2", "archive", ExampleSource::LlmBootstrap));
    dsvc.append_examples(&mut conn, dataset_id, batch)
        .await
        .expect("append");

    let out = few_shot_for_model(&dsvc, &mut conn, user, "fewshot-model", 4)
        .await
        .expect("few shot");
    assert_eq!(out.len(), 4, "k respected");
    // Round-robin balance: a 5:2 correction skew must still anchor both
    // classes — 4 slots → 2 per class, not 4 to_read.
    let to_read = out.iter().filter(|(_, l)| l == "to_read").count();
    let archive = out.iter().filter(|(_, l)| l == "archive").count();
    assert_eq!((to_read, archive), (2, 2), "class-balanced interleave");
    // No non-correction text leaks in.
    assert!(
        out.iter().all(|(t, _)| !t.starts_with("noise")),
        "correction-only"
    );
}

#[tokio::test]
async fn few_shot_truncates_features_to_wire_cap() {
    let (pool, _db) = common::isolated_db_pool().await;
    set_master_key();
    let user = Uuid::new_v4();
    seed_user(&pool, user).await;
    let dataset_id = seed_dataset(&pool, user).await;
    seed_model(&pool, user, dataset_id, "trunc-model").await;
    let dsvc = dataset_service(&pool).await;

    let mut conn = pool.acquire().await.unwrap();
    let long = "x".repeat(4096);
    dsvc.append_examples(
        &mut conn,
        dataset_id,
        vec![
            ex(&long, "a", ExampleSource::Correction),
            ex("short", "b", ExampleSource::Correction),
        ],
    )
    .await
    .expect("append");

    let out = few_shot_for_model(&dsvc, &mut conn, user, "trunc-model", 2)
        .await
        .expect("few shot");
    assert_eq!(out.len(), 2);
    for (text, _) in &out {
        assert!(
            text.len() <= talos_memory::ml_rpc::MAX_FEWSHOT_FEATURE_BYTES,
            "feature truncated to wire cap (got {})",
            text.len()
        );
    }
}

#[tokio::test]
async fn few_shot_empty_is_success_and_foreign_model_is_not_found() {
    let (pool, _db) = common::isolated_db_pool().await;
    set_master_key();
    let owner = Uuid::new_v4();
    seed_user(&pool, owner).await;
    let dataset_id = seed_dataset(&pool, owner).await;
    seed_model(&pool, owner, dataset_id, "fresh-model").await;
    let dsvc = dataset_service(&pool).await;

    let mut conn = pool.acquire().await.unwrap();
    // Fresh model, zero corrections: empty vec, NOT an error — the caller
    // proceeds with an unaugmented prompt.
    let out = few_shot_for_model(&dsvc, &mut conn, owner, "fresh-model", 6)
        .await
        .expect("empty is success");
    assert!(out.is_empty());

    // Foreign caller: NotFound (indistinguishable from absent).
    let stranger = Uuid::new_v4();
    seed_user(&pool, stranger).await;
    let err = few_shot_for_model(&dsvc, &mut conn, stranger, "fresh-model", 6)
        .await
        .expect_err("foreign model invisible");
    assert!(matches!(err, ServeError::NotFound));
}
