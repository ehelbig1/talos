//! A person's tap can teach the classifier: an `__ml_distill__` item marked
//! `human_confirmed` becomes a gold `correction` row, but only from a run an
//! action link started (2026-10-14).
//!
//! Until this date a human label could be recorded only through the operator
//! tools (`ml_resolve_disagreement`, `ml_append_examples`), so a workflow in
//! which the owner taps "this is the right answer" kept the confirmed labels
//! as few-shot examples in actor memory instead.
//!
//! Driven end to end, which `__ml_distill__` never had (see
//! `write_ceiling_hook_gate_tests` for why): the real `ControllerNodeHook`,
//! the real distill flow behind `DISTILL_CONTEXT`, the real `DatasetService`
//! (encryption, the content MAC, the upsert) against a migrated Postgres. The
//! run's start kind is what the engine hands the hook in
//! `NodeCompletionContext::started_by_kind`.
//!
//! ONE test function: `DISTILL_CONTEXT` is process-wide and set once.

mod common;

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use talos_workflow_engine_core::{NodeCompletionContext, NodeLifecycleHook, WriteCeiling};
use uuid::Uuid;

async fn seed(pool: &sqlx::PgPool) -> (Uuid, String) {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(user)
    .bind(format!("{user}@ml-human.test"))
    .execute(pool)
    .await
    .expect("seed user");
    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name, status) VALUES ($1, $2, $3, 'active')")
        .bind(actor)
        .bind(user)
        .bind(format!("ml-human-actor-{actor}"))
        .execute(pool)
        .await
        .expect("seed actor");
    let dataset = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO ml_datasets (id, user_id, name, task_type) \
         VALUES ($1, $2, $3, 'classification')",
    )
    .bind(dataset)
    .bind(user)
    .bind(format!("ds-{dataset}"))
    .execute(pool)
    .await
    .expect("seed dataset");
    let model = format!("made-up-classifier-{}", &actor.simple().to_string()[..8]);
    sqlx::query(
        "INSERT INTO ml_models (id, user_id, name, task_type, dataset_id, config_json) \
         VALUES ($1, $2, $3, 'classification', $4, '{}'::jsonb)",
    )
    .bind(Uuid::new_v4())
    .bind(user)
    .bind(&model)
    .bind(dataset)
    .execute(pool)
    .await
    .expect("seed model");
    (actor, model)
}

/// What the node hook does with one node output, under a given start kind.
fn complete(
    hook: &talos_engine::node_hook::ControllerNodeHook,
    actor: Uuid,
    started_by_kind: Option<&str>,
    output: &serde_json::Value,
) {
    hook.on_node_completed(
        NodeCompletionContext {
            workflow_id: Uuid::new_v4(),
            execution_id: Uuid::new_v4(),
            node_id: Uuid::new_v4(),
            node_label: Some("record_tap"),
            module_id: None,
            actor_id: Some(actor),
            max_write_ceiling: WriteCeiling::Write,
            http_verb_ceiling: None,
            started_by_kind,
            wall_time_ms: 1,
        },
        output,
    );
}

/// `example_key -> source` for the rows the dataset holds.
async fn sources(pool: &sqlx::PgPool) -> std::collections::HashMap<String, String> {
    sqlx::query_as::<_, (String, String)>(
        "SELECT example_key, source FROM ml_examples WHERE example_key IS NOT NULL",
    )
    .fetch_all(pool)
    .await
    .unwrap()
    .into_iter()
    .collect()
}

/// Wait until `key` has landed (the flow is spawned).
async fn landed(pool: &sqlx::PgPool, key: &str) -> std::collections::HashMap<String, String> {
    for _ in 0..200 {
        let s = sources(pool).await;
        if s.contains_key(key) {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("{key} never landed: {:?}", sources(pool).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_human_label_is_gold_only_from_a_run_an_action_link_started() {
    std::env::set_var(
        "TALOS_MASTER_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
    // No embedding provider is needed to append: an example lands without a
    // vector when the embedder is unreachable.
    std::env::set_var("EMBEDDING_API_URL", "http://127.0.0.1:1/v1/embeddings");
    std::env::set_var("EMBEDDING_MODEL", "talos-test-none");
    std::env::set_var("EMBEDDING_DIMENSIONS", "1024");

    let (pool, _db) = common::isolated_db_pool().await;
    let sm = Arc::new(controller::secrets::SecretsManager::new(pool.clone()).unwrap());
    sm.initialize().await.unwrap();
    let _ = talos_ml::DISTILL_CONTEXT.set(talos_ml::DistillContext {
        db_pool: pool.clone(),
        dataset_service: talos_ml::DatasetService::new(sm.clone()),
        lifecycle_service: talos_ml::LifecycleService::new(sm.clone()),
        secrets: sm.clone(),
    });
    let (actor, model) = seed(&pool).await;
    let hook = talos_engine::node_hook::ControllerNodeHook::new(pool.clone());

    // A tap: the person's label is gold; a model label beside it is not.
    complete(
        &hook,
        actor,
        Some("action_link"),
        &json!({ "__ml_distill__": { "model": model, "items": [
            { "features_text": "Subject: made-up invoice", "label": "keep",
              "example_key": "tap-1", "human_confirmed": true },
            { "features_text": "Subject: made-up newsletter", "label": "archive",
              "example_key": "teacher-1" }
        ] } }),
    );
    landed(&pool, "teacher-1").await;
    let s = landed(&pool, "tap-1").await;
    assert_eq!(s["tap-1"], "correction", "a tap's label is gold");
    assert_eq!(s["teacher-1"], "llm_production", "a model's label is not");

    // The single-item form carries the flag too.
    complete(
        &hook,
        actor,
        Some("action_link"),
        &json!({ "__ml_distill__": { "model": model,
            "features_text": "Subject: made-up receipt", "label": "keep",
            "example_key": "tap-2", "human_confirmed": true } }),
    );
    assert_eq!(landed(&pool, "tap-2").await["tap-2"], "correction");

    // Any other start: the claim is refused and nothing is appended for it,
    // while an ordinary item in the same envelope still lands.
    //
    // MUTATION that turns it red: make `admit_human_labels` admit every
    // start kind.
    for (i, kind) in [Some("schedule"), Some("manual"), Some("test"), None]
        .into_iter()
        .enumerate()
    {
        let forged = format!("forged-{i}");
        let ordinary = format!("ordinary-{i}");
        complete(
            &hook,
            actor,
            kind,
            &json!({ "__ml_distill__": { "model": model, "items": [
                { "features_text": format!("Subject: made-up claim {i}"), "label": "keep",
                  "example_key": forged, "human_confirmed": true },
                { "features_text": format!("Subject: made-up other {i}"), "label": "archive",
                  "example_key": ordinary }
            ] } }),
        );
        let s = landed(&pool, &ordinary).await;
        assert!(
            !s.contains_key(&forged),
            "{kind:?}: a human label was recorded from a run no tap started"
        );
        assert_eq!(s[&ordinary], "llm_production");
    }
}
