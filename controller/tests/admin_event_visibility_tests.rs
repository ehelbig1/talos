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

/// The 65% of `admin_event_log` no per-resource surface can reach — events
/// about DELETED resources, bulk events with no `resource_id`, resource types
/// with no tool — has one reader, and its default view is the caller's OWN
/// actions. A second user's events must not leak into it (the table has no RLS
/// and no owner column; the event's `user_id` is the tenancy bind).
#[tokio::test]
async fn list_admin_events_lists_the_callers_own_actions_and_says_what_still_exists() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let me = create_test_user(&ctx.auth_service, "admin_events_list_me@example.com").await;
    let other = create_test_user(&ctx.auth_service, "admin_events_list_other@example.com").await;
    let live_wf = create_test_workflow(&pool, me, "admin-events-live-wf").await;
    let deleted_wf = Uuid::new_v4(); // never existed in this clone = "deleted"
    seed_admin_event(
        &pool,
        me,
        "workflow_deleted",
        "workflow",
        deleted_wf,
        "deleted it",
    )
    .await;
    seed_admin_event(
        &pool,
        me,
        "workflow_actor_binding_changed",
        "workflow",
        live_wf,
        "bound it",
    )
    .await;
    // A bulk event: resource_id NULL — presence is UNKNOWN, never false.
    sqlx::query(
        "INSERT INTO admin_event_log (user_id, event_type, resource_type, resource_id, summary) \
         VALUES ($1, 'workflows_bulk_deleted', 'workflow', NULL, 'bulk')",
    )
    .bind(me)
    .execute(&pool)
    .await
    .unwrap();
    // CONTROL: the other tenant's action must not appear in my view.
    seed_admin_event(
        &pool,
        other,
        "module_deleted",
        "module",
        Uuid::new_v4(),
        "theirs",
    )
    .await;

    let state = mcp_state(pool.clone()).await;
    let resp = controller::mcp::analytics::dispatch(
        "list_admin_events",
        Some(serde_json::json!(1)),
        &serde_json::json!({}),
        &state,
        agent(me),
    )
    .await
    .expect("list_admin_events is dispatched");
    let body = text_json(&resp);
    assert_eq!(body["scope"], Value::String("own_actions".into()), "{body}");
    let evs = events(&body);
    assert_eq!(
        evs.len(),
        3,
        "exactly my three events, not the other tenant's: {body}"
    );
    assert!(
        evs.iter()
            .all(|e| e["by_user_id"] == Value::String(me.to_string())),
        "every row is mine: {body}"
    );
    let by_type = |t: &str| {
        evs.iter()
            .find(|e| e["event_type"] == Value::String(t.into()))
            .unwrap_or_else(|| panic!("event {t} missing: {body}"))
    };
    assert_eq!(
        by_type("workflow_deleted")["resource_present"],
        Value::Bool(false)
    );
    assert_eq!(
        by_type("workflow_actor_binding_changed")["resource_present"],
        Value::Bool(true)
    );
    assert_eq!(
        by_type("workflows_bulk_deleted")["resource_present"],
        Value::Null
    );
    assert_eq!(body["has_more"], Value::Bool(false));

    // The other tenant sees exactly their own row.
    let resp = controller::mcp::analytics::dispatch(
        "list_admin_events",
        Some(serde_json::json!(2)),
        &serde_json::json!({ "resource_type": "module" }),
        &state,
        agent(other),
    )
    .await
    .unwrap();
    let body = text_json(&resp);
    let evs = events(&body);
    assert_eq!(evs.len(), 1, "{body}");
    assert_eq!(evs[0]["by_user_id"], Value::String(other.to_string()));
}

/// `all_users` is the platform-wide view: refused for an ordinary tenant (the
/// agent identity here carries `*`, and that is deliberately NOT enough — the
/// gate is `users.is_platform_admin`, the `get_secret_access_log` precedent),
/// and the only view that reaches system-authored rows with a NULL `user_id`.
#[tokio::test]
async fn list_admin_events_all_users_is_platform_admin_only_and_reaches_system_rows() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let me = create_test_user(&ctx.auth_service, "admin_events_all_me@example.com").await;
    let other = create_test_user(&ctx.auth_service, "admin_events_all_other@example.com").await;
    seed_admin_event(
        &pool,
        other,
        "module_deleted",
        "module",
        Uuid::new_v4(),
        "theirs",
    )
    .await;
    // System-authored (the CLI's worker-provisioning-token audit writes NULL).
    sqlx::query(
        "INSERT INTO admin_event_log (user_id, event_type, resource_type, resource_id, summary) \
         VALUES (NULL, 'worker_provisioning_token_minted', 'worker_provisioning_token', $1, 'minted')",
    )
    .bind(Uuid::new_v4())
    .execute(&pool)
    .await
    .unwrap();

    let state = mcp_state(pool.clone()).await;
    let args = serde_json::json!({ "all_users": true });
    let resp = controller::mcp::analytics::dispatch(
        "list_admin_events",
        Some(serde_json::json!(1)),
        &args,
        &state,
        agent(me),
    )
    .await
    .unwrap();
    // A refusal is an MCP tool error (`isError: true`, code -32601 — the
    // denied kind), not a JSON-RPC transport error.
    let denied = resp
        .result
        .as_ref()
        .map(|r| r["isError"] == Value::Bool(true) && r["errorCode"] == serde_json::json!(-32601))
        .unwrap_or(false);
    assert!(
        denied,
        "a non-platform-admin must be REFUSED, not narrowed: {:?}",
        resp.result
    );

    // CONTROL: my own view never includes either row.
    let resp = controller::mcp::analytics::dispatch(
        "list_admin_events",
        Some(serde_json::json!(2)),
        &serde_json::json!({}),
        &state,
        agent(me),
    )
    .await
    .unwrap();
    assert_eq!(events(&text_json(&resp)).len(), 0);

    sqlx::query("UPDATE users SET is_platform_admin = true WHERE id = $1")
        .bind(me)
        .execute(&pool)
        .await
        .unwrap();
    let resp = controller::mcp::analytics::dispatch(
        "list_admin_events",
        Some(serde_json::json!(3)),
        &args,
        &state,
        agent(me),
    )
    .await
    .unwrap();
    let body = text_json(&resp);
    assert_eq!(body["scope"], Value::String("all_users".into()), "{body}");
    let evs = events(&body);
    assert_eq!(
        evs.len(),
        2,
        "the other tenant's row AND the system row: {body}"
    );
    assert!(
        evs.iter().any(|e| e["by_user_id"].is_null()
            && e["resource_type"] == Value::String("worker_provisioning_token".into())),
        "the NULL-user system row is reachable only here: {body}"
    );
}

/// The actor summary shows the ceilings' CURRENT values; the admin events say
/// who moved them and when.
#[tokio::test]
async fn the_actor_summary_renders_admin_actions_on_that_actor() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let user = create_test_user(&ctx.auth_service, "admin_events_actor@example.com").await;
    let actor_id = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name) VALUES ($1, $2, 'admin-events-actor')")
        .bind(actor_id)
        .bind(user)
        .execute(&pool)
        .await
        .expect("seed actor");
    seed_admin_event(
        &pool,
        user,
        "actor_llm_tier_ceiling_set",
        "actor",
        actor_id,
        "tier2 -> tier1",
    )
    .await;
    // CONTROL: another actor's event stays off this summary.
    seed_admin_event(
        &pool,
        user,
        "actor_write_ceiling_set",
        "actor",
        Uuid::new_v4(),
        "other",
    )
    .await;

    let state = mcp_state(pool.clone()).await;
    let resp = controller::mcp::actor::dispatch(
        "get_actor_summary",
        Some(serde_json::json!(1)),
        &serde_json::json!({ "actor_id": actor_id.to_string() }),
        &state,
        agent(user),
    )
    .await
    .expect("get_actor_summary is dispatched");
    let body = text_json(&resp);
    let admin = body["admin_events"]
        .as_array()
        .unwrap_or_else(|| panic!("{body}"));
    assert_eq!(admin.len(), 1, "{body}");
    assert_eq!(
        admin[0]["admin_event_type"],
        Value::String("actor_llm_tier_ceiling_set".into())
    );
    assert_eq!(admin[0]["by_user_id"], Value::String(user.to_string()));
    assert_eq!(body["admin_events_unreadable"], Value::Bool(false));
}
