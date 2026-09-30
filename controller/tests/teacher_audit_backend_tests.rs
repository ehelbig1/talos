//! The teacher audit's two backends against a real database: where each
//! report is stored, and that a routine chat re-audit never erases a System
//! One comparison.
//!
//! The transport is a stub closure (the audit is transport-agnostic); what is
//! real is the audit loop, the gold slice (corrections appended through the
//! production `resolve_disagreement` flow, so they are encrypted like live
//! rows) and the `teacher_audit` writes.

mod common;

use std::sync::Arc;
use std::time::Duration;
use talos_ml::{
    resolve_disagreement, start_teacher_audit, DatasetService, LifecycleService, TeacherAuditError,
    TeacherBackend, TeacherRequest,
};
use uuid::Uuid;

fn set_master_key() {
    std::env::set_var(
        "TALOS_MASTER_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
}

async fn services(pool: &sqlx::Pool<sqlx::Postgres>) -> (LifecycleService, DatasetService) {
    set_master_key();
    let sm = Arc::new(controller::secrets::SecretsManager::new(pool.clone()).unwrap());
    sm.initialize().await.unwrap();
    (LifecycleService::new(sm.clone()), DatasetService::new(sm))
}

/// A user, a dataset, and a model whose config records two labels.
async fn seed(pool: &sqlx::Pool<sqlx::Postgres>) -> (Uuid, Uuid) {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) \
         VALUES ($1, $2, 'not-a-real-hash', true)",
    )
    .bind(user)
    .bind(format!("{user}@teacher-audit.test"))
    .execute(pool)
    .await
    .expect("seed user");
    let ds = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO ml_datasets (id, user_id, name, task_type) \
         VALUES ($1, $2, $3, 'classification')",
    )
    .bind(ds)
    .bind(user)
    .bind(format!("ds-{ds}"))
    .execute(pool)
    .await
    .expect("seed dataset");
    let model = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO ml_models (id, user_id, name, task_type, dataset_id, config_json) \
         VALUES ($1, $2, $3, 'classification', $4, \
                 '{\"labels\": [\"archive\", \"to_read\"], \
                   \"fallback\": {\"provider\": \"ollama\", \"model\": \"chat-teacher\"}}'::jsonb)",
    )
    .bind(model)
    .bind(user)
    .bind(format!("m-{model}"))
    .bind(ds)
    .execute(pool)
    .await
    .expect("seed model");
    (user, model)
}

/// Append `n` gold corrections through the production resolve flow.
async fn add_corrections(
    pool: &sqlx::Pool<sqlx::Postgres>,
    ls: &LifecycleService,
    dsvc: &DatasetService,
    model: Uuid,
    user: Uuid,
    n: usize,
) {
    for i in 0..n {
        let mut conn = pool.acquire().await.unwrap();
        let id = ls
            .record_disagreement(
                &mut conn,
                model,
                user,
                None,
                Some(&format!("msg-{i}")),
                &format!("Subject: synthetic example number {i}"),
                Some(("to_read", 0.9)),
                "archive",
                "divergence",
            )
            .await
            .expect("record disagreement");
        drop(conn);
        resolve_disagreement(pool, ls, dsvc, id, user, Some("archive"))
            .await
            .expect("resolve");
    }
}

async fn teacher_audit(pool: &sqlx::Pool<sqlx::Postgres>, model: Uuid) -> serde_json::Value {
    sqlx::query_scalar::<_, Option<serde_json::Value>>(
        "SELECT teacher_audit FROM ml_models WHERE id = $1",
    )
    .bind(model)
    .fetch_one(pool)
    .await
    .expect("read teacher_audit")
    .unwrap_or(serde_json::Value::Null)
}

/// Poll until the report at `pointer` is `complete` (the audit runs in a
/// spawned task).
async fn wait_complete(
    pool: &sqlx::Pool<sqlx::Postgres>,
    model: Uuid,
    pointer: &str,
) -> serde_json::Value {
    for _ in 0..100 {
        let v = teacher_audit(pool, model).await;
        if v.pointer(pointer).and_then(|s| s.as_str()) == Some("complete") {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!(
        "audit at {pointer} did not complete: {}",
        teacher_audit(pool, model).await
    );
}

/// Corrections seeded for the round-trip test: more than the audit's 8
/// few-shot anchors, so some rows are actually compared.
const GOLD_ROWS: usize = 12;

/// Rows the audit compared, asserting the rest were skipped as few-shot
/// anchors — every seeded correction is accounted for, and at least one was
/// compared (a report over zero rows would prove nothing).
fn compared_rows(report: &serde_json::Value) -> u64 {
    let compared = report["compared"].as_u64().expect("compared");
    let skipped = report["skipped_few_shot_anchors"]
        .as_u64()
        .expect("skipped");
    assert!(compared > 0, "the audit compared no rows: {report}");
    assert_eq!(compared + skipped, GOLD_ROWS as u64, "{report}");
    compared
}

fn answer(
    label: &'static str,
) -> impl Fn(TeacherRequest) -> std::future::Ready<anyhow::Result<String>> + Send + 'static {
    move |_r| std::future::ready(Ok(serde_json::json!({ "label": label }).to_string()))
}

#[tokio::test]
async fn a_system_one_audit_is_stored_beside_the_chat_teacher_and_survives_a_re_audit() {
    let (pool, _db) = common::isolated_db_pool().await;
    let (user, model) = seed(&pool).await;
    let (ls, dsvc) = services(&pool).await;
    // More corrections than the few-shot budget (8): a gold row that is also
    // an anchor is skipped by the audit's self-leakage guard, so with fewer
    // rows than anchors nothing would be compared at all.
    add_corrections(&pool, &ls, &dsvc, model, user, GOLD_ROWS).await;

    // Chat teacher: agrees with every correction ("archive").
    start_teacher_audit(
        &pool,
        &dsvc,
        user,
        model,
        100,
        None,
        TeacherBackend::Chat,
        answer("archive"),
    )
    .await
    .expect("chat audit starts");
    let v = wait_complete(&pool, model, "/status").await;
    assert_eq!(v["teacher"]["backend"], "chat");
    assert_eq!(v["teacher"]["model"], "chat-teacher");
    let compared = compared_rows(&v);
    assert_eq!(
        v["agree"], compared,
        "the chat stub agrees with every correction"
    );

    // System One: sees the label set, disagrees with every correction.
    let saw_labels = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let seen = saw_labels.clone();
    let so = move |r: TeacherRequest| {
        *seen.lock().unwrap() = r.labels.clone();
        std::future::ready(Ok(serde_json::json!({ "label": "to_read" }).to_string()))
    };
    let backend = TeacherBackend::SystemOne {
        model: "nimble:9b".into(),
    };
    start_teacher_audit(&pool, &dsvc, user, model, 100, None, backend, so)
        .await
        .expect("system one audit starts");
    let v = wait_complete(&pool, model, "/systemone/status").await;
    assert_eq!(v["systemone"]["teacher"]["backend"], "systemone");
    assert_eq!(v["systemone"]["teacher"]["model"], "nimble:9b");
    assert_eq!(compared_rows(&v["systemone"]), compared);
    assert_eq!(v["systemone"]["agree"], 0);
    assert_eq!(
        *saw_labels.lock().unwrap(),
        vec!["archive".to_string(), "to_read".to_string()]
    );
    // The chat teacher's report is untouched.
    assert_eq!(v["teacher"]["backend"], "chat");
    assert_eq!(v["agree"], compared);

    // A routine chat re-audit carries the System One comparison across.
    start_teacher_audit(
        &pool,
        &dsvc,
        user,
        model,
        100,
        None,
        TeacherBackend::Chat,
        answer("to_read"),
    )
    .await
    .expect("chat re-audit starts");
    // `start_teacher_audit` stamps `running` before it returns, so the
    // `complete` awaited here is the re-audit's own.
    let v = wait_complete(&pool, model, "/status").await;
    assert_eq!(v["agree"], 0, "the re-audit's own figure");
    assert_eq!(v["systemone"]["teacher"]["model"], "nimble:9b");
    assert_eq!(v["systemone"]["status"], "complete");
}

#[tokio::test]
async fn a_blank_system_one_model_is_refused_before_anything_runs() {
    let (pool, _db) = common::isolated_db_pool().await;
    let (user, model) = seed(&pool).await;
    let (_ls, dsvc) = services(&pool).await;
    let err = start_teacher_audit(
        &pool,
        &dsvc,
        user,
        model,
        100,
        None,
        TeacherBackend::SystemOne { model: "  ".into() },
        answer("archive"),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, TeacherAuditError::InvalidConfig(_)),
        "{err:?}"
    );
    assert!(
        teacher_audit(&pool, model).await.is_null(),
        "nothing may be stamped"
    );
}
