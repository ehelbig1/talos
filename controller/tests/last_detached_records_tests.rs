//! The last four operator actions whose `admin_event_log` record was written
//! by a detached task AFTER the change: execution pause / resume, the
//! failure-notification webhook, bulk archive, and the built-in marketplace
//! republish. Each change and its record are now one transaction, and the
//! detached helper (`spawn_log_admin_event`) no longer exists.
mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use serde_json::Value;
use sqlx::{Pool, Postgres};
use talos_execution_pause::{read_execution_pause, set_execution_paused_recorded, ExecutionPause};
use uuid::Uuid;

const NIL: &str = "00000000-0000-0000-0000-000000000000";

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'last detached')",
    )
    .bind(id)
    .bind(format!("last-detached-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

async fn seed_workflow(pool: &Pool<Postgres>, user: Uuid, name: &str, status: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, graph_json, module_uri, status, is_enabled) \
         VALUES ($1, $2, $3, '{\"nodes\":[],\"edges\":[]}', 'talos://t', $4, true)",
    )
    .bind(id)
    .bind(user)
    .bind(name)
    .bind(status)
    .execute(pool)
    .await
    .expect("seed workflow");
    id
}

/// `(event_type, user_id, resource_id, summary, details)`, oldest first.
async fn events(pool: &Pool<Postgres>) -> Vec<(String, Option<Uuid>, Option<Uuid>, String, Value)> {
    sqlx::query_as(
        "SELECT event_type, user_id, resource_id, summary, COALESCE(details, 'null'::jsonb) \
         FROM admin_event_log ORDER BY created_at, id",
    )
    .fetch_all(pool)
    .await
    .expect("events")
}

async fn hide_log(pool: &Pool<Postgres>) {
    sqlx::query("ALTER TABLE admin_event_log RENAME TO admin_event_log_away")
        .execute(pool)
        .await
        .expect("rename");
}

#[tokio::test]
async fn pause_and_resume_record_the_state_they_replaced() {
    let (pool, _db) = common::isolated_db_pool().await;
    let admin = seed_user(&pool).await;

    assert_eq!(
        set_execution_paused_recorded(&pool, true, admin)
            .await
            .unwrap(),
        ExecutionPause::Running
    );
    assert_eq!(
        read_execution_pause(&pool).await.unwrap(),
        ExecutionPause::Paused
    );
    // Pausing an already-paused deployment is still an operator's act.
    assert_eq!(
        set_execution_paused_recorded(&pool, true, admin)
            .await
            .unwrap(),
        ExecutionPause::Paused
    );
    assert_eq!(
        set_execution_paused_recorded(&pool, false, admin)
            .await
            .unwrap(),
        ExecutionPause::Paused
    );
    assert_eq!(
        read_execution_pause(&pool).await.unwrap(),
        ExecutionPause::Running
    );

    let ev = events(&pool).await;
    let got: Vec<(&str, &str, bool)> = ev
        .iter()
        .map(|e| {
            (
                e.0.as_str(),
                e.4["previous_state"].as_str().unwrap(),
                e.4["changed"].as_bool().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        got,
        vec![
            ("executions_paused", "running", true),
            ("executions_paused", "paused", false),
            ("executions_resumed", "paused", true),
        ]
    );
    assert!(ev.iter().all(|e| e.1 == Some(admin) && e.2.is_none()));

    // An unclassifiable stored flag is named as what it was.
    sqlx::query(
        "UPDATE system_settings SET value = '\"yes\"'::jsonb WHERE key = 'execution_paused'",
    )
    .execute(&pool)
    .await
    .unwrap();
    set_execution_paused_recorded(&pool, false, admin)
        .await
        .unwrap();
    assert_eq!(events(&pool).await[3].4["previous_state"], "unreadable");

    // A pause that cannot be recorded does not happen.
    hide_log(&pool).await;
    assert!(set_execution_paused_recorded(&pool, true, admin)
        .await
        .is_err());
    assert_eq!(
        read_execution_pause(&pool).await.unwrap(),
        ExecutionPause::Running,
        "the flag changed although its record could not be written"
    );
}

#[tokio::test]
async fn a_failure_webhook_change_records_the_url_it_replaced() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let stranger = seed_user(&pool).await;
    let repo = talos_workflow_repository::WorkflowRepository::new(pool.clone());
    let wf = seed_workflow(&pool, user, "hooked", "active").await;
    let url_of = |pool: Pool<Postgres>| async move {
        sqlx::query_scalar::<_, Option<String>>(
            "SELECT failure_webhook_url FROM workflows WHERE id = $1",
        )
        .bind(wf)
        .fetch_one(&pool)
        .await
        .unwrap()
    };

    // A stranger changes nothing and records nothing.
    assert_eq!(
        repo.set_failure_webhook_url_column(wf, stranger, Some("https://evil.example/x"))
            .await
            .unwrap(),
        0
    );
    assert_eq!(url_of(pool.clone()).await, None);
    assert!(events(&pool).await.is_empty());

    for url in [
        Some("https://a.example/hook"),
        Some("https://b.example/hook"),
        None,
    ] {
        assert_eq!(
            repo.set_failure_webhook_url_column(wf, user, url)
                .await
                .unwrap(),
            1
        );
        assert_eq!(url_of(pool.clone()).await.as_deref(), url);
    }
    let ev = events(&pool).await;
    assert_eq!(ev.len(), 3);
    for e in &ev {
        assert_eq!(e.0, "workflow_failure_webhook_changed");
        assert_eq!((e.1, e.2), (Some(user), Some(wf)));
    }
    assert_eq!(ev[0].4["webhook_url"], "https://a.example/hook");
    assert_eq!(ev[0].4["previous_webhook_url"], Value::Null);
    assert_eq!(ev[0].4["is_configured"], true);
    assert_eq!(ev[1].4["previous_webhook_url"], "https://a.example/hook");
    assert_eq!(ev[2].4["webhook_url"], Value::Null);
    assert_eq!(ev[2].4["previous_webhook_url"], "https://b.example/hook");
    assert_eq!(ev[2].4["is_configured"], false);
    assert!(ev[2].3.contains("cleared") && ev[0].3.contains("set"));

    hide_log(&pool).await;
    assert!(repo
        .set_failure_webhook_url_column(wf, user, Some("https://c.example/hook"))
        .await
        .is_err());
    assert_eq!(
        url_of(pool.clone()).await,
        None,
        "the URL changed without its record"
    );
}

#[tokio::test]
async fn a_bulk_archive_records_what_it_actually_archived() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let other = seed_user(&pool).await;
    let repo = talos_workflow_repository::WorkflowRepository::new(pool.clone());
    let a = seed_workflow(&pool, user, "old-a", "active").await;
    let b = seed_workflow(&pool, user, "old-b", "draft").await;
    let already = seed_workflow(&pool, user, "old-already", "archived").await;
    let theirs = seed_workflow(&pool, other, "old-theirs", "active").await;
    let status = |pool: Pool<Postgres>, id: Uuid| async move {
        sqlx::query_as::<_, (String, Option<String>)>(
            "SELECT status, workflow_type FROM workflows WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap()
    };
    let type_before = status(pool.clone(), a).await.1;

    // Nothing to archive: nothing recorded.
    assert_eq!(
        repo.archive_workflows_by_ids(&[already, theirs], user, None, "old-")
            .await
            .unwrap(),
        0
    );
    assert!(events(&pool).await.is_empty());
    assert_eq!(status(pool.clone(), theirs).await.0, "active");

    // No `set_type`: the workflow type is left as it was.
    assert_eq!(
        repo.archive_workflows_by_ids(&[a, already, theirs], user, None, "old-")
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        status(pool.clone(), a).await,
        ("archived".to_string(), type_before)
    );
    // With one: stamped.
    assert_eq!(
        repo.archive_workflows_by_ids(&[b], user, Some("test"), "old-")
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        status(pool.clone(), b).await,
        ("archived".to_string(), Some("test".to_string()))
    );

    let ev = events(&pool).await;
    assert_eq!(ev.len(), 2);
    assert_eq!(ev[0].0, "workflows_bulk_archived");
    assert_eq!((ev[0].1, ev[0].2), (Some(user), None));
    assert_eq!(ev[0].4["archived_count"], 1);
    assert_eq!(
        ev[0].4["archived_workflows"],
        serde_json::json!([{ "id": a, "name": "old-a" }]),
        "what was ARCHIVED — not the already-archived or the stranger's id it was handed"
    );
    assert_eq!(ev[0].4["prefix"], "old-");
    assert_eq!(ev[0].4["set_type"], Value::Null);
    assert_eq!(ev[0].4["listed_truncated"], false);
    assert_eq!(ev[1].4["set_type"], "test");

    let kept = seed_workflow(&pool, user, "old-kept", "active").await;
    hide_log(&pool).await;
    assert!(repo
        .archive_workflows_by_ids(&[kept], user, None, "old-")
        .await
        .is_err());
    assert_eq!(status(pool.clone(), kept).await.0, "active");
}

#[tokio::test]
async fn a_bulk_archive_record_lists_at_most_a_thousand_and_says_so() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = talos_workflow_repository::WorkflowRepository::new(pool.clone());
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "INSERT INTO workflows (id, user_id, name, graph_json, module_uri, status, is_enabled) \
         SELECT gen_random_uuid(), $1, 'bulk-' || g, '{\"nodes\":[],\"edges\":[]}', 'talos://t', 'active', true \
         FROM generate_series(1, 1001) g RETURNING id",
    )
    .bind(user)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        repo.archive_workflows_by_ids(&ids, user, None, "bulk-")
            .await
            .unwrap(),
        1001
    );
    let ev = events(&pool).await;
    assert_eq!(ev[0].4["archived_count"], 1001, "the TRUE count");
    assert_eq!(
        ev[0].4["archived_workflows"].as_array().unwrap().len(),
        1000
    );
    assert_eq!(ev[0].4["listed_truncated"], true);
}

#[tokio::test]
async fn the_marketplace_republish_is_one_recorded_transaction() {
    let (pool, _db) = common::isolated_db_pool().await;
    let admin = seed_user(&pool).await;
    let repo = talos_advanced_repository::AdvancedRepository::new(pool.clone());
    let nil: Uuid = NIL.parse().unwrap();

    // Two first-party templates not yet listed → published. Two, so that
    // `published` (≥ 2) and `removed_stale` (1) cannot be swapped unnoticed.
    let catalog = Uuid::new_v4();
    for (id, name) in [
        (catalog, "republish-catalog"),
        (Uuid::new_v4(), "republish-catalog-2"),
    ] {
        sqlx::query(
            "INSERT INTO modules (id, user_id, name, kind, description) \
             VALUES ($1, NULL, $2, 'catalog', 'a first-party template')",
        )
        .bind(id)
        .bind(name)
        .execute(&pool)
        .await
        .unwrap();
    }
    // A system listing pointing at a USER module → stale, removed.
    let sandbox = Uuid::new_v4();
    sqlx::query("INSERT INTO modules (id, user_id, name, kind) VALUES ($1, $2, 'republish-sandbox', 'sandbox')")
        .bind(sandbox)
        .bind(admin)
        .execute(&pool)
        .await
        .unwrap();
    let stale = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO module_marketplace (id, module_id, publisher_id, name, capability_world) \
         VALUES ($1, $2, $3, 'republish-stale', 'minimal-node')",
    )
    .bind(stale)
    .bind(sandbox)
    .bind(nil)
    .execute(&pool)
    .await
    .unwrap();
    let listed = |pool: Pool<Postgres>, module: Uuid| async move {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM module_marketplace WHERE module_id = $1)",
        )
        .bind(module)
        .fetch_one(&pool)
        .await
        .unwrap()
    };

    // Without its record, NEITHER half happens.
    hide_log(&pool).await;
    assert!(repo
        .republish_system_templates_recorded(admin)
        .await
        .is_err());
    assert!(
        listed(pool.clone(), sandbox).await,
        "the stale listing was removed without a record"
    );
    assert!(
        !listed(pool.clone(), catalog).await,
        "a template was published without a record"
    );
    sqlx::query("ALTER TABLE admin_event_log_away RENAME TO admin_event_log")
        .execute(&pool)
        .await
        .unwrap();

    let (published, removed) = repo
        .republish_system_templates_recorded(admin)
        .await
        .unwrap();
    assert!(published >= 2, "published {published}");
    assert_eq!(removed, 1);
    assert!(!listed(pool.clone(), sandbox).await);
    assert!(listed(pool.clone(), catalog).await);

    let ev = events(&pool).await;
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].0, "marketplace_built_in_templates_published");
    assert_eq!((ev[0].1, ev[0].2), (Some(admin), None));
    assert_eq!(ev[0].4["published"], published);
    assert_eq!(ev[0].4["removed_stale"], 1);
}

/// The three operator ML changes wrote their record AFTER the commit,
/// best-effort, although each handler held the open transaction. Driven
/// through the production MCP dispatch.
#[tokio::test]
async fn an_ml_policy_lifecycle_or_window_change_commits_with_its_record() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let state = mcp_common::mcp_state(pool.clone()).await;
    let model = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO ml_models (id, user_id, name, task_type, config_json, lifecycle_state, policy_json) \
         VALUES ($1, $2, 'audited-model', 'classification', '{}'::jsonb, 'llm_only', '{}'::jsonb)",
    )
    .bind(model)
    .bind(user)
    .execute(&pool)
    .await
    .expect("seed model");
    let call = |tool: &'static str, args: Value| {
        let state = state.clone();
        async move {
            controller::mcp::ml::dispatch(
                tool,
                Some(serde_json::json!(1)),
                &args,
                &state,
                mcp_common::agent(user),
            )
            .await
            .unwrap_or_else(|| panic!("{tool} is dispatched"))
        }
    };
    let row = |pool: Pool<Postgres>| async move {
        sqlx::query_as::<_, (String, Value, i64)>(
            "SELECT lifecycle_state, policy_json, shadow_epoch::bigint FROM ml_models WHERE id = $1",
        )
        .bind(model)
        .fetch_one(&pool)
        .await
        .unwrap()
    };
    let before = row(pool.clone()).await;

    let policy = serde_json::json!({ "min_examples": 50, "auto_advance": false });
    mcp_common::text_json(
        &call(
            "ml_set_policy",
            serde_json::json!({ "model_id": model, "policy": policy }),
        )
        .await,
    );
    mcp_common::text_json(
        &call(
            "ml_set_lifecycle",
            serde_json::json!({ "model_id": model, "state": "shadow" }),
        )
        .await,
    );
    mcp_common::text_json(
        &call(
            "ml_reset_shadow_window",
            serde_json::json!({ "model_name": "audited-model" }),
        )
        .await,
    );
    let after = row(pool.clone()).await;
    assert_eq!(after.0, "shadow");
    assert_eq!(after.1, policy);
    assert!(after.2 > before.2);

    let ev = events(&pool).await;
    let types: Vec<&str> = ev.iter().map(|e| e.0.as_str()).collect();
    assert_eq!(
        types,
        vec![
            "ml_policy_set",
            "ml_lifecycle_set",
            "ml_shadow_window_reset"
        ]
    );
    assert!(ev.iter().all(|e| e.1 == Some(user) && e.2 == Some(model)));
    assert_eq!(ev[0].4, policy);
    assert!(ev[1].3.contains("llm_only -> shadow"), "{}", ev[1].3);

    // Without its record, none of the three changes lands.
    hide_log(&pool).await;
    let new_policy = serde_json::json!({ "min_examples": 99, "auto_advance": true });
    for (tool, args) in [
        (
            "ml_set_policy",
            serde_json::json!({ "model_id": model, "policy": new_policy }),
        ),
        (
            "ml_set_lifecycle",
            serde_json::json!({ "model_id": model, "state": "teacher_only" }),
        ),
        (
            "ml_reset_shadow_window",
            serde_json::json!({ "model_name": "audited-model" }),
        ),
    ] {
        let refusal = mcp_common::error_message(&call(tool, args).await);
        assert!(
            !refusal.contains("admin_event_log"),
            "{tool}: no internal detail to the caller: {refusal}"
        );
    }
    assert_eq!(
        row(pool.clone()).await,
        after,
        "an ML change committed although its record could not be written"
    );
}

/// The structural half: there is no detached admin-event helper left to call.
/// TEXTUAL, stated as such — it reads the workspace's production sources.
#[test]
fn the_detached_admin_event_helper_is_gone() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut offenders = Vec::new();
    for entry in std::fs::read_dir(&root).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !(name.starts_with("talos-") || name == "controller" || name == "worker") {
            continue;
        }
        let src = entry.path().join("src");
        let mut stack = vec![src];
        while let Some(dir) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&dir) else {
                continue;
            };
            for f in rd.flatten() {
                let p = f.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().is_some_and(|e| e == "rs") {
                    let text = std::fs::read_to_string(&p).unwrap_or_default();
                    // The needle is split so this file would not match itself
                    // if it ever moved under a `src/`.
                    if text.contains(concat!("fn spawn_log_", "admin_event"))
                        || text.contains(concat!("::spawn_log_", "admin_event("))
                    {
                        offenders.push(p.display().to_string());
                    }
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "a detached admin-event writer is back: {offenders:?} — record inside the change's transaction"
    );
}
