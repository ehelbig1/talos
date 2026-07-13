//! RFC 0011 — model deletion against a real database. Asserts the cascade
//! shape (versions/disagreements go with the model; examples go with the
//! dataset), the workflow-reference refusal, the shared-dataset guard, and
//! cross-tenant invisibility.

mod common;

use std::sync::Arc;
use talos_ml::{delete_model, provision_classifier, DatasetService, DeleteError, ProvisionInput};
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
    .bind(format!("{id}@ml-delete.test"))
    .execute(pool)
    .await
    .expect("seed user");
}

async fn seed_actor(pool: &sqlx::Pool<sqlx::Postgres>, id: Uuid, user_id: Uuid) {
    sqlx::query("INSERT INTO actors (id, user_id, name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(user_id)
        .bind(format!("actor-{id}"))
        .execute(pool)
        .await
        .expect("seed actor");
}

async fn dataset_service(pool: &sqlx::Pool<sqlx::Postgres>) -> DatasetService {
    set_master_key();
    let sm = Arc::new(controller::secrets::SecretsManager::new(pool.clone()).unwrap());
    sm.initialize().await.unwrap();
    DatasetService::new(sm)
}

fn input(name: &str, actor_id: Uuid) -> ProvisionInput {
    ProvisionInput {
        name: name.to_string(),
        labels: vec!["a".into(), "b".into()],
        actor_id,
        fallback_provider: None,
        fallback_model: None,
        allow_external_llm: false,
        k: None,
        confidence_threshold: None,
        max_examples: None,
        policy_override: None,
    }
}

async fn provisioned(pool: &sqlx::Pool<sqlx::Postgres>, name: &str) -> (Uuid, Uuid, Uuid) {
    let user = Uuid::new_v4();
    seed_user(pool, user).await;
    let actor = Uuid::new_v4();
    seed_actor(pool, actor, user).await;
    let dsvc = dataset_service(pool).await;
    let out = provision_classifier(pool, &dsvc, input(name, actor), user)
        .await
        .expect("provision");
    (user, out.model_id, out.dataset_id)
}

#[tokio::test]
async fn delete_removes_model_and_optionally_dataset() {
    let (pool, _db) = common::isolated_db_pool().await;
    set_master_key();
    let (user, model_id, dataset_id) = provisioned(&pool, "doomed").await;

    // Keep the dataset on the first pass.
    let out = delete_model(&pool, "doomed", false, user).await.unwrap();
    assert!(out.model_deleted);
    assert!(!out.dataset_deleted);
    let models: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ml_models WHERE id = $1")
        .bind(model_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(models, 0, "model row gone");
    let datasets: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ml_datasets WHERE id = $1")
        .bind(dataset_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(datasets, 1, "dataset survives without delete_dataset");

    // Second delete of the same name → NotFound (idempotence signal).
    let err = delete_model(&pool, "doomed", true, user)
        .await
        .expect_err("already gone");
    assert!(matches!(err, DeleteError::NotFound));

    // Re-provision against the surviving dataset name → the dataset-collision
    // guard from #481 fires (actionable), which is the documented recovery
    // path; delete the dataset via a fresh model + delete_dataset=true.
    let dsvc = dataset_service(&pool).await;
    let actor2 = Uuid::new_v4();
    seed_actor(&pool, actor2, user).await;
    let err = provision_classifier(&pool, &dsvc, input("doomed", actor2), user)
        .await
        .expect_err("dataset collision surfaced");
    assert!(matches!(err, talos_ml::ProvisionError::InvalidInput(_)));
}

#[tokio::test]
async fn delete_with_dataset_cascades_examples() {
    let (pool, _db) = common::isolated_db_pool().await;
    set_master_key();
    let (user, _model_id, dataset_id) = provisioned(&pool, "with-data").await;

    // Seed a raw example row (plaintext columns are fine for a count test —
    // the cascade is schema-level, not crypto-level).
    sqlx::query(
        "INSERT INTO ml_examples \
         (id, dataset_id, user_id, features_enc, features_key_id, features_format, \
          label_json, source) \
         VALUES ($1, $2, $3, $4, $5, 3, '\"a\"', 'llm_production')",
    )
    .bind(Uuid::new_v4())
    .bind(dataset_id)
    .bind(user)
    .bind(b"ciphertext".as_slice())
    .bind(Uuid::new_v4())
    .execute(&pool)
    .await
    .expect("seed example");

    let out = delete_model(&pool, "with-data", true, user).await.unwrap();
    assert!(out.dataset_deleted);
    let examples: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM ml_examples WHERE dataset_id = $1")
            .bind(dataset_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(examples, 0, "examples cascade with the dataset");
}

#[tokio::test]
async fn delete_refuses_workflow_referenced_model() {
    let (pool, _db) = common::isolated_db_pool().await;
    set_master_key();
    let (user, _model_id, _dataset_id) = provisioned(&pool, "in-use").await;

    // A workflow whose graph names the model in a node config.
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, module_uri, graph_json) \
         VALUES ($1, $2, 'wf', '', $3)",
    )
    .bind(Uuid::new_v4())
    .bind(user)
    .bind(serde_json::json!({
        "nodes": [{"id": "n1", "type": "m", "data": {"MODEL_NAME": "in-use"}}],
        "edges": []
    }))
    .execute(&pool)
    .await
    .expect("seed workflow");

    let err = delete_model(&pool, "in-use", false, user)
        .await
        .expect_err("referenced model refused");
    match err {
        DeleteError::ReferencedByWorkflows(n) => assert_eq!(n, 1),
        other => panic!("expected ReferencedByWorkflows, got {other:?}"),
    }
    // Underscore in a model name must not wildcard-match: a graph
    // containing "inXuse" would only match if `_` were left unescaped.
    let (user2, _m, _d) = provisioned(&pool, "under_score").await;
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, module_uri, graph_json) \
         VALUES ($1, $2, 'wf2', '', $3)",
    )
    .bind(Uuid::new_v4())
    .bind(user2)
    .bind(serde_json::json!({
        "nodes": [{"id": "n1", "data": {"MODEL_NAME": "underXscore"}}], "edges": []
    }))
    .execute(&pool)
    .await
    .unwrap();
    // "under_score" with unescaped `_` would LIKE-match "underXscore" —
    // the escaped version must NOT, so the delete succeeds.
    delete_model(&pool, "under_score", false, user2)
        .await
        .expect("escaped underscore does not false-positive");
}

#[tokio::test]
async fn delete_dataset_refuses_when_shared() {
    let (pool, _db) = common::isolated_db_pool().await;
    set_master_key();
    let (user, _model_id, dataset_id) = provisioned(&pool, "primary").await;

    // A second model pointing at the same dataset.
    sqlx::query(
        "INSERT INTO ml_models (id, user_id, name, task_type, dataset_id, config_json) \
         VALUES ($1, $2, 'sibling', 'classification', $3, '{}')",
    )
    .bind(Uuid::new_v4())
    .bind(user)
    .bind(dataset_id)
    .execute(&pool)
    .await
    .expect("seed sibling model");

    let err = delete_model(&pool, "primary", true, user)
        .await
        .expect_err("shared dataset refused");
    match err {
        DeleteError::DatasetShared(names) => assert_eq!(names, vec!["sibling".to_string()]),
        other => panic!("expected DatasetShared, got {other:?}"),
    }
    // Without delete_dataset it proceeds.
    delete_model(&pool, "primary", false, user)
        .await
        .expect("model-only delete ok");
}

#[tokio::test]
async fn delete_is_cross_tenant_invisible() {
    let (pool, _db) = common::isolated_db_pool().await;
    set_master_key();
    let (_owner, model_id, _dataset_id) = provisioned(&pool, "not-yours").await;
    let stranger = Uuid::new_v4();
    seed_user(&pool, stranger).await;

    let err = delete_model(&pool, "not-yours", true, stranger)
        .await
        .expect_err("cross-tenant delete refused");
    assert!(matches!(err, DeleteError::NotFound));
    let still: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ml_models WHERE id = $1")
        .bind(model_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(still, 1, "owner's model untouched");
}
