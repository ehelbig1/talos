//! RFC 0011 — one-call classifier provisioning against a real database.
//! Asserts the composed dataset + model + policy is created owner-scoped and
//! safe-by-default (born `llm_only`, `auto_advance` off, Tier-1 local
//! fallback), is idempotent on re-add, and refuses a foreign actor binding.

mod common;

use std::sync::Arc;
use talos_ml::{provision_classifier, DatasetService, ProvisionError, ProvisionInput};
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
    .bind(format!("{id}@ml-provision.test"))
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
        labels: vec!["urgent".into(), "normal".into(), "spam".into()],
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

#[tokio::test]
async fn provision_creates_llm_only_model_with_safe_defaults() {
    let (pool, _db) = common::isolated_db_pool().await;
    set_master_key();
    let user = Uuid::new_v4();
    seed_user(&pool, user).await;
    let actor = Uuid::new_v4();
    seed_actor(&pool, actor, user).await;
    let dsvc = dataset_service(&pool).await;

    let out = provision_classifier(&pool, &dsvc, input("triage", actor), user)
        .await
        .expect("provision ok");
    assert_eq!(out.lifecycle_state, "llm_only");
    assert!(!out.already_existed);

    // Model: born llm_only, safe policy (auto_advance OFF), digest actor +
    // Tier-1 local fallback baked into config.
    let (state, config, policy): (String, serde_json::Value, serde_json::Value) = sqlx::query_as(
        "SELECT lifecycle_state, config_json, policy_json FROM ml_models WHERE id = $1",
    )
    .bind(out.model_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(state, "llm_only");
    assert_eq!(policy["auto_advance"], serde_json::Value::Bool(false));
    assert!(policy["recall_floors"]["urgent"].is_number());
    assert_eq!(config["fallback"]["provider"], "ollama");
    assert_eq!(config["digest"]["actor_id"], actor.to_string());

    // Dataset: classification, owned by the user.
    let (task, ds_user): (String, Uuid) =
        sqlx::query_as("SELECT task_type, user_id FROM ml_datasets WHERE id = $1")
            .bind(out.dataset_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(task, "classification");
    assert_eq!(ds_user, user);
}

#[tokio::test]
async fn provision_is_idempotent_on_re_add() {
    let (pool, _db) = common::isolated_db_pool().await;
    set_master_key();
    let user = Uuid::new_v4();
    seed_user(&pool, user).await;
    let actor = Uuid::new_v4();
    seed_actor(&pool, actor, user).await;
    let dsvc = dataset_service(&pool).await;

    let first = provision_classifier(&pool, &dsvc, input("dupe", actor), user)
        .await
        .unwrap();
    let second = provision_classifier(&pool, &dsvc, input("dupe", actor), user)
        .await
        .unwrap();
    assert!(second.already_existed, "re-add reuses the existing model");
    assert_eq!(first.model_id, second.model_id);
    assert_eq!(first.dataset_id, second.dataset_id);

    // Exactly one model + one dataset were created.
    let models: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ml_models WHERE user_id = $1")
        .bind(user)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(models, 1);
}

#[tokio::test]
async fn provision_refuses_a_foreign_actor() {
    let (pool, _db) = common::isolated_db_pool().await;
    set_master_key();
    let owner = Uuid::new_v4();
    let stranger = Uuid::new_v4();
    seed_user(&pool, owner).await;
    seed_user(&pool, stranger).await;
    // The actor belongs to the STRANGER, not the provisioning caller.
    let foreign_actor = Uuid::new_v4();
    seed_actor(&pool, foreign_actor, stranger).await;
    let dsvc = dataset_service(&pool).await;

    let err = provision_classifier(&pool, &dsvc, input("x", foreign_actor), owner)
        .await
        .expect_err("cross-tenant actor rejected");
    assert!(matches!(err, ProvisionError::InvalidActor));

    // Nothing was created for the caller.
    let models: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ml_models WHERE user_id = $1")
        .bind(owner)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(models, 0);
}

#[tokio::test]
async fn provision_rejects_too_few_labels() {
    let (pool, _db) = common::isolated_db_pool().await;
    set_master_key();
    let user = Uuid::new_v4();
    seed_user(&pool, user).await;
    let actor = Uuid::new_v4();
    seed_actor(&pool, actor, user).await;
    let dsvc = dataset_service(&pool).await;

    let mut bad = input("y", actor);
    bad.labels = vec!["only_one".into()];
    let err = provision_classifier(&pool, &dsvc, bad, user)
        .await
        .expect_err("too few labels rejected");
    assert!(matches!(err, ProvisionError::InvalidInput(_)));
}

#[tokio::test]
async fn provision_refuses_a_retired_actor() {
    let (pool, _db) = common::isolated_db_pool().await;
    set_master_key();
    let user = Uuid::new_v4();
    seed_user(&pool, user).await;
    let actor = Uuid::new_v4();
    seed_actor(&pool, actor, user).await;
    sqlx::query("UPDATE actors SET status = 'terminated' WHERE id = $1")
        .bind(actor)
        .execute(&pool)
        .await
        .unwrap();
    let dsvc = dataset_service(&pool).await;

    // Owned but terminated: refused with a specific, actionable message
    // (mirrors setWorkflowActorId's rule) — a retired actor must not become
    // a fresh digest target.
    let err = provision_classifier(&pool, &dsvc, input("retired", actor), user)
        .await
        .expect_err("terminated actor rejected");
    match err {
        ProvisionError::InvalidInput(m) => assert!(m.contains("terminated"), "got: {m}"),
        other => panic!("expected InvalidInput, got {other:?}"),
    }
}

#[tokio::test]
async fn provision_reuse_requires_matching_labels_and_actor() {
    let (pool, _db) = common::isolated_db_pool().await;
    set_master_key();
    let user = Uuid::new_v4();
    seed_user(&pool, user).await;
    let actor = Uuid::new_v4();
    seed_actor(&pool, actor, user).await;
    let other_actor = Uuid::new_v4();
    seed_actor(&pool, other_actor, user).await;
    let dsvc = dataset_service(&pool).await;

    provision_classifier(&pool, &dsvc, input("compat", actor), user)
        .await
        .unwrap();

    // Same name, different labels → refused (would distill a foreign label
    // space into the existing dataset).
    let mut relabeled = input("compat", actor);
    relabeled.labels = vec!["ham".into(), "eggs".into()];
    let err = provision_classifier(&pool, &dsvc, relabeled, user)
        .await
        .expect_err("label mismatch rejected");
    match err {
        ProvisionError::InvalidInput(m) => assert!(m.contains("label set"), "got: {m}"),
        other => panic!("expected InvalidInput, got {other:?}"),
    }

    // Same name + labels, different actor → refused (digests would keep
    // routing to the ORIGINAL actor while the caller believes otherwise).
    let err = provision_classifier(&pool, &dsvc, input("compat", other_actor), user)
        .await
        .expect_err("actor mismatch rejected");
    match err {
        ProvisionError::InvalidInput(m) => assert!(m.contains("different actor"), "got: {m}"),
        other => panic!("expected InvalidInput, got {other:?}"),
    }

    // Fully matching request still reuses idempotently.
    let again = provision_classifier(&pool, &dsvc, input("compat", actor), user)
        .await
        .unwrap();
    assert!(again.already_existed);
}

#[tokio::test]
async fn provision_names_a_dataset_collision_instead_of_internal() {
    let (pool, _db) = common::isolated_db_pool().await;
    set_master_key();
    let user = Uuid::new_v4();
    seed_user(&pool, user).await;
    let actor = Uuid::new_v4();
    seed_actor(&pool, actor, user).await;
    let dsvc = dataset_service(&pool).await;

    // A dataset of the same name WITHOUT a model (the ml_create_dataset
    // path) must produce an actionable InvalidInput, not an opaque unique-
    // index Internal that fails identically on every retry.
    sqlx::query(
        "INSERT INTO ml_datasets (id, user_id, name, task_type, schema_json) \
         VALUES ($1, $2, 'orphan-ds', 'classification', '{}')",
    )
    .bind(Uuid::new_v4())
    .bind(user)
    .execute(&pool)
    .await
    .unwrap();

    let err = provision_classifier(&pool, &dsvc, input("orphan-ds", actor), user)
        .await
        .expect_err("dataset collision surfaced");
    match err {
        ProvisionError::InvalidInput(m) => assert!(m.contains("dataset"), "got: {m}"),
        other => panic!("expected InvalidInput, got {other:?}"),
    }
}

#[tokio::test]
async fn provision_rejects_non_positive_max_examples_and_warns_on_tier2() {
    let (pool, _db) = common::isolated_db_pool().await;
    set_master_key();
    let user = Uuid::new_v4();
    seed_user(&pool, user).await;
    let actor = Uuid::new_v4();
    seed_actor(&pool, actor, user).await;
    let dsvc = dataset_service(&pool).await;

    let mut bad = input("caps", actor);
    bad.max_examples = Some(0);
    let err = provision_classifier(&pool, &dsvc, bad, user)
        .await
        .expect_err("non-positive cap rejected");
    assert!(matches!(err, ProvisionError::InvalidInput(_)));

    // Default actor tier is tier2; allow_external_llm=false is therefore
    // advisory and the outcome must SAY so.
    let out = provision_classifier(&pool, &dsvc, input("caps", actor), user)
        .await
        .unwrap();
    let warning = out.locality_warning.expect("tier2 actor → warning");
    assert!(warning.contains("tier"), "got: {warning}");

    // A tier1 actor backs the contract — no warning.
    let t1_actor = Uuid::new_v4();
    seed_actor(&pool, t1_actor, user).await;
    sqlx::query("UPDATE actors SET max_llm_tier = 'tier1' WHERE id = $1")
        .bind(t1_actor)
        .execute(&pool)
        .await
        .unwrap();
    let out = provision_classifier(&pool, &dsvc, input("caps-t1", t1_actor), user)
        .await
        .unwrap();
    assert!(out.locality_warning.is_none());
}
