//! `admin_event_log` is READABLE where the operator already looks.
//!
//! Until 2026-09-11 the table had four writers and no reader: it sits on the
//! platform-admin `query_paginated` deny list (credential-class detail), no MCP
//! tool selected from it, and the pentest scope's "confirm `admin_event_log`
//! has 2 entries" was a psql instruction. These tests drive the REAL MCP
//! dispatch over a real `McpState` and assert the two surfaces that now render
//! it — the workflow audit trail and the module history — scoped to the
//! resource, naming the actor of the change. The same binary pins that the
//! never-written `audit_events` table is gone from the migrated schema.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

#[path = "common/mod.rs"]
mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use common::{create_test_user, create_test_workflow, setup_test_context};
use mcp_common::{agent, mcp_state, text_json};
use serde_json::Value;
use uuid::Uuid;

async fn seed_admin_event(
    pool: &sqlx::PgPool,
    user: Uuid,
    event_type: &str,
    resource_type: &str,
    resource_id: Uuid,
    summary: &str,
) {
    sqlx::query(
        "INSERT INTO admin_event_log (user_id, event_type, resource_type, resource_id, summary, details) \
         VALUES ($1, $2, $3, $4, $5, NULL)",
    )
    .bind(user)
    .bind(event_type)
    .bind(resource_type)
    .bind(resource_id)
    .bind(summary)
    .execute(pool)
    .await
    .expect("seed admin event");
}

fn events<'a>(body: &'a Value) -> &'a [Value] {
    body.get("events")
        .and_then(|e| e.as_array())
        .map(|v| v.as_slice())
        .unwrap_or(&[])
}

#[tokio::test]
async fn the_workflow_audit_trail_renders_admin_actions_on_that_workflow_only() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let user = create_test_user(&ctx.auth_service, "admin_events@example.com").await;
    let wf = create_test_workflow(&pool, user, "admin-events-wf").await;
    let other_wf = create_test_workflow(&pool, user, "admin-events-other-wf").await;
    seed_admin_event(
        &pool,
        user,
        "workflow_actor_binding_changed",
        "workflow",
        wf,
        "actor binding changed to actor-1",
    )
    .await;
    seed_admin_event(
        &pool,
        user,
        "workflow_deleted",
        "workflow",
        other_wf,
        "deleted",
    )
    .await;

    let state = mcp_state(pool.clone()).await;
    let resp = controller::mcp::analytics::dispatch(
        "get_workflow_audit_trail",
        Some(serde_json::json!(1)),
        &serde_json::json!({ "workflow_id": wf.to_string() }),
        &state,
        agent(user),
    )
    .await
    .expect("get_workflow_audit_trail is dispatched");
    let body = text_json(&resp);
    let admin: Vec<&Value> = events(&body)
        .iter()
        .filter(|e| e.get("event_type").and_then(|t| t.as_str()) == Some("admin_action"))
        .collect();
    assert_eq!(
        admin.len(),
        1,
        "exactly this workflow's admin event: {body}"
    );
    assert_eq!(
        admin[0].get("admin_event_type").and_then(|v| v.as_str()),
        Some("workflow_actor_binding_changed")
    );
    assert_eq!(
        admin[0].get("by_user_id").and_then(|v| v.as_str()),
        Some(user.to_string().as_str()),
        "the actor of the change is named"
    );
    assert_eq!(
        admin[0].get("details").and_then(|v| v.as_str()),
        Some("actor binding changed to actor-1")
    );
    // CONTROL: a healthy read carries no disclosure — the ledger is clean.
    assert!(
        body.get("not_measured").is_none()
            || body["not_measured"]
                .as_array()
                .map(|a| a.is_empty())
                .unwrap_or(true),
        "a readable admin_event_log must not be disclosed as unmeasured: {body}"
    );
}

#[tokio::test]
async fn the_module_history_renders_admin_actions_on_that_module() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let user = create_test_user(&ctx.auth_service, "admin_events_mod@example.com").await;
    let module_id = Uuid::new_v4();
    sqlx::query("INSERT INTO modules (id, user_id, name, kind) VALUES ($1, $2, 'admin-events-module', 'sandbox')")
        .bind(module_id)
        .bind(user)
        .execute(&pool)
        .await
        .expect("seed module");
    seed_admin_event(
        &pool,
        user,
        "module_allowed_methods_updated",
        "module",
        module_id,
        "allowed_methods: GET → GET,POST",
    )
    .await;
    // An event on ANOTHER module must not leak into this one's history.
    seed_admin_event(
        &pool,
        user,
        "module_deleted",
        "module",
        Uuid::new_v4(),
        "deleted",
    )
    .await;

    let state = mcp_state(pool.clone()).await;
    let resp = controller::mcp::modules::dispatch(
        "get_module_history",
        Some(serde_json::json!(1)),
        &serde_json::json!({ "module_id": module_id.to_string() }),
        &state,
        agent(user),
    )
    .await
    .expect("get_module_history is dispatched");
    let body = text_json(&resp);
    let admin = body["admin_events"]
        .as_array()
        .expect("admin_events is a list when readable");
    assert_eq!(admin.len(), 1, "{body}");
    assert_eq!(
        admin[0].get("admin_event_type").and_then(|v| v.as_str()),
        Some("module_allowed_methods_updated")
    );
    assert_eq!(
        admin[0].get("by_user_id").and_then(|v| v.as_str()),
        Some(user.to_string().as_str())
    );
    assert_eq!(body["admin_events_unreadable"], Value::Bool(false));
}

/// `audit_events` — "Primary security audit ledger" in the docs, an
/// immutability trigger, a SOC 2 export — held zero rows since 2026-03 and had
/// no writer; the execution ledger is the S3 WORM chain. Dropped by migration
/// 20260911160000, and this pins that a migrated schema no longer carries it.
#[tokio::test]
async fn the_never_written_audit_events_table_is_gone() {
    let ctx = setup_test_context().await;
    let gone: bool = sqlx::query_scalar("SELECT to_regclass('audit_events') IS NULL")
        .fetch_one(&ctx.db_pool)
        .await
        .unwrap();
    assert!(gone, "audit_events must not exist on a migrated database");
    // The three real audit tables keep their immutability trigger.
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_trigger WHERE tgname IN \
         ('trg_admin_event_log_immutable','trg_auth_audit_log_immutable','trg_secret_audit_log_immutable')",
    )
    .fetch_one(&ctx.db_pool)
    .await
    .unwrap();
    assert_eq!(n, 3);
}
