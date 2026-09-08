//! A read that FAILED must not render as a read that found nothing.
//!
//! Package 23 (2026-09-07) inventoried every awaited repository/service read in
//! `talos-mcp-handlers/src` + `talos-api/src` that is collapsed into a default,
//! and classified each site as a **claim** (the default becomes a statement a
//! caller reads), **fail-closed** (the default costs the caller a refusal) or
//! **decorative** (a label, a background task, a documented fallback). These
//! tests drive three of the repaired **claim** sites through the REAL MCP
//! dispatch, with the read made to fail deterministically by removing the
//! relation it names — package 22's mechanism: a statement that cannot run is
//! the cheapest reproducible database failure there is.
//!
//! Each test carries its own CONTROL (the same call against an intact schema),
//! because "the tool returned something unusual" is not evidence unless the
//! healthy shape is pinned in the same run: the whole contract is that a
//! healthy response stays byte-identical and only a degraded one changes.
//!
//! The database is a per-test `CREATE DATABASE … TEMPLATE` clone
//! (`common::isolated_db_pool`), so dropping a table here cannot reach any
//! other test or the developer's stack.

#[path = "common/mod.rs"]
mod common;
// The real `McpState` + response helpers, one home (2026-09-08).
#[path = "common/mcp.rs"]
mod mcp_common;

use mcp_common::{agent, error_message, mcp_state, text_json};

use std::sync::Arc;
use uuid::Uuid;

async fn seed_user(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, created_at, updated_at) \
         VALUES ($1, $2, 'x', NOW(), NOW())",
    )
    .bind(id)
    .bind(format!("p23-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

async fn seed_workflow(pool: &sqlx::PgPool, user_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, module_uri, graph_json, status, is_enabled) \
         VALUES ($1, $2, 'p23-summary', 'test:p23', '{\"nodes\":[],\"edges\":[]}', 'active', true)",
    )
    .bind(id)
    .bind(user_id)
    .execute(pool)
    .await
    .expect("seed workflow");
    id
}

// ───────────────────────────────────────────────────────────────────────────
// 1. `list_modules` — "you have no modules" must not be a database failure.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn list_modules_refuses_rather_than_reporting_an_empty_inventory() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let state = mcp_state(pool.clone()).await;
    let args = serde_json::json!({});

    // CONTROL: intact schema. The healthy answer is a listing, not an error.
    let ok = controller::mcp::modules::dispatch(
        "list_modules",
        Some(serde_json::json!(1)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("list_modules is dispatched");
    assert!(
        ok.error.is_none(),
        "control run must succeed: {:?}",
        ok.error
    );
    let body = text_json(&ok);
    assert_eq!(
        body.get("count").and_then(|c| c.as_i64()),
        Some(0),
        "a fresh user genuinely has no modules, and that must still be sayable"
    );

    // The read now cannot run. `user_modules` is the view the repository names.
    sqlx::query("DROP VIEW user_modules CASCADE")
        .execute(&pool)
        .await
        .expect("drop the view the read names");

    let degraded = controller::mcp::modules::dispatch(
        "list_modules",
        Some(serde_json::json!(2)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("list_modules is dispatched");

    let msg = error_message(&degraded);
    assert!(
        msg.contains("NOT a statement that you have none"),
        "a failed inventory read must refuse, and must say it is not an emptiness claim: {msg}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 2. `get_workflow_summary` — a per-field disclosure, not four zeros.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn workflow_summary_nulls_and_names_the_count_it_could_not_take() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let wf_id = seed_workflow(&pool, user_id).await;
    let state = mcp_state(pool.clone()).await;
    let args = serde_json::json!({ "workflow_id": wf_id.to_string() });

    // CONTROL: a healthy report carries the count and NO disclosure block —
    // `Readings::attach` is a no-op when nothing failed, which is what keeps
    // the healthy response byte-identical to the pre-fix one.
    let ok = controller::mcp::workflows::dispatch(
        "get_workflow_summary",
        Some(serde_json::json!(1)),
        &args,
        Arc::new(state.clone()),
        agent(user_id),
    )
    .await
    .expect("get_workflow_summary is dispatched");
    let healthy = text_json(&ok);
    assert_eq!(
        healthy.get("active_schedules").and_then(|v| v.as_i64()),
        Some(0),
        "control: a workflow with no schedules really does report 0"
    );
    assert!(
        healthy.get("measurement").is_none(),
        "control: a complete report must not grow a disclosure key"
    );

    // Only the SCHEDULE count is made unreadable. The rest of the report must
    // survive — a disclosure that swallows the whole tool is no more useful
    // than the zeros it replaces.
    sqlx::query("DROP TABLE workflow_schedules CASCADE")
        .execute(&pool)
        .await
        .expect("drop the table the count names");

    let degraded = controller::mcp::workflows::dispatch(
        "get_workflow_summary",
        Some(serde_json::json!(2)),
        &args,
        Arc::new(state.clone()),
        agent(user_id),
    )
    .await
    .expect("get_workflow_summary is dispatched");
    let body = text_json(&degraded);

    assert!(
        body.get("active_schedules").map(|v| v.is_null()) == Some(true),
        "an unreadable count must be null, never 0: {body}"
    );
    let not_measured = body
        .pointer("/measurement/not_measured")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(
        not_measured.iter().any(|v| v == "active_schedules"),
        "the null must be NAMED, so a reader can match it to the disclosure: {body}"
    );
    // The rest of the report is still there and still true.
    assert!(
        body.pointer("/workflow/name").is_some(),
        "the measurable half of the report must survive: {body}"
    );
    assert_eq!(
        body.pointer("/execution_stats_7d/total")
            .and_then(|v| v.as_i64()),
        Some(0),
        "the execution stats read is untouched and still answers"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 3. `resolve_actor_via_repo` — the resolver behind 20+ actor tools.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_unreadable_actor_registry_is_not_an_absent_actor() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let state = mcp_state(pool.clone()).await;
    let missing_actor = Uuid::new_v4();
    let args = serde_json::json!({ "actor_id": missing_actor.to_string() });

    // CONTROL: with the registry readable, an actor that genuinely is not
    // there still gets the not-found sentence. The fix must not blur that —
    // the anti-enumeration message is the whole reason `Ok(None)` is worded
    // the way it is.
    let ok = controller::mcp::actor::dispatch(
        "get_actor_summary",
        Some(serde_json::json!(1)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("get_actor_summary is dispatched");
    assert!(
        error_message(&ok).contains("not found or access denied"),
        "control: a genuinely absent actor keeps its message"
    );

    sqlx::query("DROP TABLE actors CASCADE")
        .execute(&pool)
        .await
        .expect("drop the table the ownership read names");

    let degraded = controller::mcp::actor::dispatch(
        "get_actor_summary",
        Some(serde_json::json!(2)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("get_actor_summary is dispatched");
    let msg = error_message(&degraded);
    assert!(
        msg.contains("Could not verify actor ownership"),
        "an unreadable registry must say so: {msg}"
    );
    assert!(
        msg.contains("NOT a statement that the actor is absent"),
        "and must refuse the reading the pre-fix message invited: {msg}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 4. `cleanup_module_versions` — a reference read that fails must HOLD the
//    module back, never delete it. Added by the orchestrator's validation:
//    reinstating main's `.unwrap_or_default()` at this site left the three
//    tests above green (a measured survivor on the one irreversible site in
//    the package), so this test exists to make that mutation red.
// ───────────────────────────────────────────────────────────────────────────

async fn seed_module(pool: &sqlx::PgPool, user_id: Uuid, name: &str, days_ago: i32) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO modules (id, user_id, name, kind, capability_world, compiled_at) \
         VALUES ($1, $2, $3, 'sandbox', 'minimal-node', NOW() - make_interval(days => $4::int))",
    )
    .bind(id)
    .bind(user_id)
    .bind(name)
    .bind(days_ago)
    .execute(pool)
    .await
    .expect("seed module");
    id
}

#[tokio::test]
async fn cleanup_module_versions_holds_back_rather_than_deleting_on_a_failed_reference_read() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let keeper = seed_module(&pool, user_id, "p23-cleanup-keeper", 0).await;
    let older = seed_module(&pool, user_id, "p23-cleanup-older", 1).await;
    let state = mcp_state(pool.clone()).await;

    // CONTROL: intact schema, dry run. The older module is a candidate and
    // nothing is unknown.
    let args = serde_json::json!({ "prefix": "p23-cleanup", "dry_run": true });
    let ok = controller::mcp::modules::dispatch(
        "cleanup_module_versions",
        Some(serde_json::json!(1)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("cleanup_module_versions is dispatched");
    assert!(
        ok.error.is_none(),
        "control run must succeed: {:?}",
        ok.error
    );
    let body = text_json(&ok);
    assert_eq!(
        body["kept"]["module_id"].as_str(),
        Some(keeper.to_string().as_str()),
        "the newest module is the keeper"
    );
    assert_eq!(
        body["unknown_references"].as_array().map(Vec::len),
        Some(0),
        "with the schema intact nothing is unknown"
    );

    // The reference read names `workflows`; take it away so the read FAILS
    // rather than returning an empty list.
    sqlx::query("DROP TABLE workflows CASCADE")
        .execute(&pool)
        .await
        .expect("drop the table the reference read names");

    let args = serde_json::json!({ "prefix": "p23-cleanup", "dry_run": false });
    let degraded = controller::mcp::modules::dispatch(
        "cleanup_module_versions",
        Some(serde_json::json!(2)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("cleanup_module_versions is dispatched");
    assert!(
        degraded.error.is_none(),
        "a failed reference read is disclosed in the body, not raised: {:?}",
        degraded.error
    );
    let body = text_json(&degraded);
    let unknown: Vec<String> = body["unknown_references"]
        .as_array()
        .expect("unknown_references is a list")
        .iter()
        .filter_map(|e| e["module_id"].as_str().map(str::to_owned))
        .collect();
    assert_eq!(
        unknown,
        vec![older.to_string()],
        "the older module must be HELD BACK under unknown_references"
    );
    assert_eq!(
        body["deleted"].as_array().map(Vec::len),
        Some(0),
        "nothing may be deleted on a failed reference read"
    );
    let still_there: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM modules WHERE id = $1")
        .bind(older)
        .fetch_one(&pool)
        .await
        .expect("count the older module");
    assert_eq!(
        still_there, 1,
        "the older module row must survive — this delete is irreversible"
    );
}
