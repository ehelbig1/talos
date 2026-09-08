//! The LAST tier of the read inventory's CLAIM sites, driven through the REAL
//! production surface.
//!
//! `docs/swallowed-reads-inventory.md`, re-measured on this tree before any
//! edit, carried **34** unrepaired `claim` sites — reads whose default becomes
//! a count, a list, a verdict or a "not found" a caller acts on. This package
//! takes ALL of them, and this binary drives the ones whose failure can be
//! INJECTED, each with its CONTROL in the same run.
//!
//! # The injection, and why it is mostly a column and not a table
//!
//! Package 31 measured that `DROP TABLE … CASCADE` can break an UNRELATED
//! lookup and make a test pass for the wrong reason. Almost every site here
//! needs one read of a table to SUCCEED and the next read of the SAME table to
//! FAIL, so the injection is `ALTER TABLE … DROP COLUMN <c>` where `<c>` is
//! named by the second statement and not the first. That is a sharper
//! instrument than a table drop and it is what makes these tests prove the
//! per-FIELD disclosure rather than a blanket refusal:
//!
//! | site | column dropped | the read that keeps working |
//! |---|---|---|
//! | `get_marketplace_stats` | `module_marketplace.name` | the aggregate stats |
//! | `star_module` | `module_marketplace.star_count` | `insert_star` |
//! | `get_workflow_changelog` | `workflows.is_enabled` | the version history |
//! | `get_session_context` | `workflows.readiness_score` | the other two sections |
//! | `find_module_alternatives` | `modules.category` | the target lookup (`kind AS category`) |
//! | `get_platform_info` | `modules.config_schema` | `static_tool_count` |
//! | `find_similar_workflows` | `workflows.name` | the source graph read |
//! | `dispatch_to_actor` | `workflows.name` | the solo-workflow probe (`SELECT id`) |
//!
//! # What this binary does NOT cover, stated rather than implied
//!
//! * **`actor_recall`'s `key_exists_at_all` probe.** `recall_exact` and
//!   `key_exists_at_all` read the SAME two columns of `actor_memory`
//!   (`actor_id`, `key`), and the second names no column the first does not —
//!   so there is no drop that breaks one and leaves the other. Its two
//!   MEASURED arms (`expired`, `never_set`) are pinned below; the `unknown`
//!   arm is not reachable from a relation-level injection.
//! * **`get_config_suggestions`** (two sites) refuses at its top with "LLM
//!   client not configured" — `McpState.llm_client` is `None` in every DB test
//!   — so neither read is reachable from here.
//! * **`import_workflow`'s `upsert_wasm_module`** needs a real compile of a
//!   bundle-supplied module before the write it misreported; the fix is a
//!   per-reason string on the refusal and is covered by a source pin.
//! * **`instantiate_workflow_pattern`** needs a built-in pattern whose modules
//!   are installed AND compiled; the two reads are pinned by source assertions.
//! * **`talos-api`'s `rotateEncryptionKey`** cannot be isolated at all: the
//!   rotation and the count read the same `encryption_keys` table, and the
//!   rotation must SUCCEED for the count to be reached.
//! * **`create_router`'s `/mcp/local` identity resolution** is a closure inside
//!   the router builder; it is covered by a source pin.

#[path = "common/mod.rs"]
mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use mcp_common::{agent, error_message, mcp_state, text_json};
use serde_json::Value;
use uuid::Uuid;

async fn seed_user(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, created_at, updated_at) \
         VALUES ($1, $2, 'x', NOW(), NOW())",
    )
    .bind(id)
    .bind(format!("p32-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

async fn seed_actor(pool: &sqlx::PgPool, user_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name, status) VALUES ($1, $2, $3, 'active')")
        .bind(id)
        .bind(user_id)
        .bind(format!("p32-actor-{}", id.simple()))
        .execute(pool)
        .await
        .expect("seed actor");
    id
}

const GRAPH: &str =
    "{\"nodes\":[{\"id\":\"n1\",\"type\":\"module\",\"data\":{\"label\":\"first\"}}],\"edges\":[]}";

async fn seed_workflow(pool: &sqlx::PgPool, user_id: Uuid, actor_id: Option<Uuid>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows \
             (id, user_id, actor_id, name, module_uri, graph_json, status, is_enabled, capabilities, readiness_score) \
         VALUES ($1, $2, $3, $4, 'test:p32', $5, 'active', true, ARRAY['p32-cap'], 55)",
    )
    .bind(id)
    .bind(user_id)
    .bind(actor_id)
    .bind(format!("p32-wf-{}", id.simple()))
    .bind(GRAPH)
    .execute(pool)
    .await
    .expect("seed workflow");
    id
}

async fn seed_module(pool: &sqlx::PgPool, user_id: Option<Uuid>, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO modules (id, user_id, name, kind, category, description, config_schema, \
                              allowed_secrets, allowed_hosts, capability_world, wasm_bytes) \
         VALUES ($1, $2, $3, 'catalog', 'utility', 'a p32 fixture module', '{}'::jsonb, \
                 ARRAY[]::text[], ARRAY[]::text[], 'minimal-node', '\\x00'::bytea)",
    )
    .bind(id)
    .bind(user_id)
    .bind(name)
    .execute(pool)
    .await
    .expect("seed module");
    id
}

async fn drop_column(pool: &sqlx::PgPool, table: &str, column: &str) {
    sqlx::query(&format!("ALTER TABLE {table} DROP COLUMN {column} CASCADE"))
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("drop {table}.{column}: {e}"));
}

async fn drop_relation(pool: &sqlx::PgPool, relation: &str) {
    sqlx::query(&format!("DROP TABLE IF EXISTS {relation} CASCADE"))
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("drop {relation}: {e}"));
}

fn not_measured(body: &Value) -> Vec<String> {
    body.pointer("/measurement/not_measured")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn text_body(resp: &controller::mcp::types::JsonRpcResponse) -> String {
    serde_json::to_value(resp)
        .ok()
        .and_then(|v| {
            v.pointer("/result/content/0/text")
                .and_then(|t| t.as_str())
                .map(str::to_string)
        })
        .unwrap_or_default()
}

// ───────────────────────────────────────────────────────────────────────────
// 1. `run_scratch_session` — an unreadable session is not a missing one.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_unreadable_scratch_session_is_not_a_session_that_does_not_exist() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let state = mcp_state(pool.clone()).await;
    let args = serde_json::json!({ "name": "p32-scratch" });

    // CONTROL: a session that really is absent keeps the pre-fix wording, so
    // the fix cannot pass by refusing everything.
    let absent = controller::mcp::advanced::dispatch(
        "run_scratch_session",
        Some(serde_json::json!(1)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("run_scratch_session is dispatched");
    assert!(
        error_message(&absent).contains("not found"),
        "control: a genuinely absent session keeps its wording: {}",
        error_message(&absent)
    );

    drop_relation(&pool, "scratch_sessions").await;

    let degraded = controller::mcp::advanced::dispatch(
        "run_scratch_session",
        Some(serde_json::json!(2)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("run_scratch_session is dispatched");
    let msg = error_message(&degraded);
    assert!(
        msg.contains("database failure") && !msg.contains("not found"),
        "an unreadable session must not be reported as absent — the saved code \
         may still be there. Got: {msg}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 2. `get_marketplace_stats` — an unread top-modules list is not "no downloads".
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_unread_top_modules_list_is_null_not_an_empty_leaderboard() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let module_id = seed_module(&pool, Some(user_id), "p32-listed-mod").await;
    sqlx::query(
        "INSERT INTO module_marketplace \
             (id, module_id, name, publisher_id, description, capability_world, version, \
              is_public, downloads, tags, verified, star_count) \
         VALUES ($1, $2, 'p32-listing', $3, 'd', 'minimal-node', '1.0.0', true, 7, \
                 ARRAY[]::text[], false, 0)",
    )
    .bind(Uuid::new_v4())
    .bind(module_id)
    .bind(user_id)
    .execute(&pool)
    .await
    .expect("seed listing");
    let state = mcp_state(pool.clone()).await;

    // CONTROL: the healthy report carries a real leaderboard and no disclosure.
    let ok = controller::mcp::advanced::dispatch(
        "get_marketplace_stats",
        Some(serde_json::json!(1)),
        &serde_json::json!({}),
        &state,
        agent(user_id),
    )
    .await
    .expect("get_marketplace_stats is dispatched");
    let healthy = text_json(&ok);
    assert_eq!(
        healthy
            .get("top_modules")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(1),
        "control: one downloaded listing must appear: {healthy}"
    );
    assert!(
        healthy.get("measurement").is_none(),
        "a healthy response carries no disclosure: {healthy}"
    );

    drop_column(&pool, "module_marketplace", "name").await;

    let resp = controller::mcp::advanced::dispatch(
        "get_marketplace_stats",
        Some(serde_json::json!(2)),
        &serde_json::json!({}),
        &state,
        agent(user_id),
    )
    .await
    .expect("get_marketplace_stats is dispatched");
    let body = text_json(&resp);
    assert!(
        body.get("top_modules").map(Value::is_null).unwrap_or(false),
        "an unread leaderboard must be null, never []: {body}"
    );
    assert!(
        not_measured(&body).contains(&"top_modules".to_string()),
        "the field must be named: {body}"
    );
    let note = body
        .get("top_modules_note")
        .and_then(Value::as_str)
        .unwrap_or("");
    assert!(
        note.contains("could not be read"),
        "the note must not go on vouching for the emptiness — pre-fix it said \
         an empty list is 'a real signal, not an error'. Got: {note}"
    );
    // The aggregate half is untouched: a per-FIELD disclosure, not a refusal.
    assert_eq!(
        body.get("total_listings").and_then(Value::as_i64),
        Some(1),
        "the measured half must survive: {body}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 3. `star_module` — an unread star count is not zero stars.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_unread_star_count_is_null_not_zero() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let listing_id = Uuid::new_v4();
    let module_id = seed_module(&pool, Some(user_id), "p32-starred-mod").await;
    sqlx::query(
        "INSERT INTO module_marketplace \
             (id, module_id, name, publisher_id, description, capability_world, version, \
              is_public, downloads, tags, verified, star_count) \
         VALUES ($1, $2, 'p32-star', $3, 'd', 'minimal-node', '1.0.0', true, 0, \
                 ARRAY[]::text[], false, 0)",
    )
    .bind(listing_id)
    .bind(module_id)
    .bind(user_id)
    .execute(&pool)
    .await
    .expect("seed listing");
    let state = mcp_state(pool.clone()).await;
    let args = serde_json::json!({ "listing_id": listing_id.to_string() });

    // First star: takes the increment path and returns a real count.
    let first = controller::mcp::advanced::dispatch(
        "star_module",
        Some(serde_json::json!(1)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("star_module is dispatched");
    assert_eq!(
        text_json(&first).get("star_count").and_then(Value::as_i64),
        Some(1),
        "control: the first star counts: {}",
        text_json(&first)
    );

    // CONTROL: starring again takes the already-starred branch and reports the
    // real count, so the degraded assertion below is about the READ and not
    // about the branch.
    let again = controller::mcp::advanced::dispatch(
        "star_module",
        Some(serde_json::json!(2)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("star_module is dispatched");
    let healthy = text_json(&again);
    assert_eq!(
        healthy.get("star_count").and_then(Value::as_i64),
        Some(1),
        "control: the already-starred branch reports the real count: {healthy}"
    );
    assert_eq!(
        healthy.get("already_starred").and_then(Value::as_bool),
        Some(true)
    );

    drop_column(&pool, "module_marketplace", "star_count").await;

    let degraded = controller::mcp::advanced::dispatch(
        "star_module",
        Some(serde_json::json!(3)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("star_module is dispatched");
    let body = text_json(&degraded);
    assert!(
        body.get("star_count").map(Value::is_null).unwrap_or(false),
        "an unread star count must be null, never 0 — 0 is 'nobody has starred \
         this' on the one branch reached only because somebody has: {body}"
    );
    assert!(not_measured(&body).contains(&"star_count".to_string()));
}

// ───────────────────────────────────────────────────────────────────────────
// 4 + 5. `get_workflow_changelog` / `get_workflow_call_tree` — an unreadable
//        workflow is not an absent or unowned one.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_unreadable_workflow_is_not_not_found_or_access_denied() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let wf_id = seed_workflow(&pool, user_id, None).await;
    let state = mcp_state(pool.clone()).await;
    let args = serde_json::json!({ "workflow_id": wf_id.to_string() });

    // CONTROL A: the real workflow renders a changelog.
    let ok = controller::mcp::analytics::dispatch(
        "get_workflow_changelog",
        Some(serde_json::json!(1)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("get_workflow_changelog is dispatched");
    assert!(
        text_json(&ok).get("workflow_id").is_some() || !text_body(&ok).is_empty(),
        "control: a real workflow renders: {}",
        text_body(&ok)
    );

    // CONTROL B: a genuinely absent workflow keeps the pre-fix wording.
    let absent = controller::mcp::analytics::dispatch(
        "get_workflow_changelog",
        Some(serde_json::json!(2)),
        &serde_json::json!({ "workflow_id": Uuid::new_v4().to_string() }),
        &state,
        agent(user_id),
    )
    .await
    .expect("get_workflow_changelog is dispatched");
    assert_eq!(
        error_message(&absent),
        "Workflow not found or access denied",
        "control: an absent workflow keeps its exact wording"
    );

    drop_column(&pool, "workflows", "is_enabled").await;

    let degraded = controller::mcp::analytics::dispatch(
        "get_workflow_changelog",
        Some(serde_json::json!(3)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("get_workflow_changelog is dispatched");
    let msg = error_message(&degraded);
    assert!(
        !msg.contains("not found or access denied") && msg.contains("UNKNOWN"),
        "an unreadable ownership check must not claim the workflow is absent or \
         unowned — both clauses are false while the database is the broken \
         thing. Got: {msg}"
    );

    // The call tree shares the read and had the identical defect one tool over.
    let tree = controller::mcp::analytics::dispatch(
        "get_workflow_call_tree",
        Some(serde_json::json!(4)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("get_workflow_call_tree is dispatched");
    let rendered = text_body(&tree);
    assert!(
        rendered.contains("could not be read") || rendered.contains("UNKNOWN"),
        "the call tree must say the node could not be READ, not that it was \
         deleted or un-shared. Got: {rendered}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 6. `get_workflow_performance_report` — an unread breakdown is null, and it
//    is null only when BOTH of its sources failed.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_unread_node_timing_breakdown_is_null_not_an_empty_list() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let actor_id = seed_actor(&pool, user_id).await;
    let wf_id = seed_workflow(&pool, user_id, Some(actor_id)).await;
    sqlx::query(
        "INSERT INTO workflow_executions \
             (id, workflow_id, user_id, actor_id, status, started_at, completed_at) \
         VALUES ($1, $2, $3, $4, 'completed', NOW() - INTERVAL '2 hours', NOW() - INTERVAL '1 hour')",
    )
    .bind(Uuid::new_v4())
    .bind(wf_id)
    .bind(user_id)
    .bind(actor_id)
    .execute(&pool)
    .await
    .expect("seed execution");
    let state = mcp_state(pool.clone()).await;
    let args = serde_json::json!({ "workflow_id": wf_id.to_string(), "days": 7 });

    // CONTROL: a genuinely empty breakdown is `[]` and carries no disclosure —
    // the report says "we looked and there is nothing", which is a real answer.
    let ok = controller::mcp::analytics::dispatch(
        "get_workflow_performance_report",
        Some(serde_json::json!(1)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("get_workflow_performance_report is dispatched");
    let healthy = text_json(&ok);
    assert!(
        healthy
            .get("node_timing_breakdown")
            .map(Value::is_array)
            .unwrap_or(false),
        "control: a measured empty breakdown stays a list: {healthy}"
    );
    assert!(
        healthy.get("measurement").is_none(),
        "a healthy response carries no disclosure: {healthy}"
    );

    drop_column(&pool, "workflow_executions", "output_data_enc").await;
    drop_relation(&pool, "execution_cost_rollup").await;

    let degraded = controller::mcp::analytics::dispatch(
        "get_workflow_performance_report",
        Some(serde_json::json!(2)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("get_workflow_performance_report is dispatched");
    let body = text_json(&degraded);
    assert!(
        body.get("node_timing_breakdown")
            .map(Value::is_null)
            .unwrap_or(false),
        "with BOTH sources unread the breakdown must be null, never [] — an \
         empty list is the report's own evidence that the workflow ran no \
         nodes: {body}"
    );
    let named = not_measured(&body);
    assert_eq!(
        named
            .iter()
            .filter(|f| *f == "node_timing_breakdown")
            .count(),
        1,
        "two failed sources feed ONE field and must be named ONCE: {body}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 7. `get_session_context` — an unread section is named, and only that one.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_unread_session_context_section_is_named_and_the_others_still_render() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let wf_id = seed_workflow(&pool, user_id, None).await;
    let state = mcp_state(pool.clone()).await;
    let args = serde_json::json!({ "task_description": "p32 wf task" });

    // CONTROL: the healthy report lists the workflow and says nothing about
    // degradation.
    let ok = controller::mcp::configuration::dispatch(
        "get_session_context",
        Some(serde_json::json!(1)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("get_session_context is dispatched");
    let healthy = text_body(&ok);
    assert!(
        healthy.contains(&wf_id.to_string()),
        "control: the workflow must be listed: {healthy}"
    );
    assert!(
        !healthy.contains("DEGRADED"),
        "a healthy report carries no degradation line: {healthy}"
    );

    drop_column(&pool, "workflows", "readiness_score").await;

    let resp = controller::mcp::configuration::dispatch(
        "get_session_context",
        Some(serde_json::json!(2)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("get_session_context is dispatched");
    let body = text_body(&resp);
    assert!(
        body.contains("DEGRADED") && body.contains("Top Workflows"),
        "the unread section must be NAMED — an empty list here reads as 'this \
         user has no ready workflows', which is what pushes an agent to build a \
         duplicate. Got: {body}"
    );
    assert!(
        !body.contains("Recently Used,") && !body.contains(", Matched"),
        "only the section that failed may be named — the other two reads still \
         answered. Got: {body}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 8. `preview_capability_dispatch` — the tool's whole answer, so it refuses.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_unreadable_capability_index_refuses_rather_than_answering_none() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let _wf = seed_workflow(&pool, user_id, None).await;
    let state = mcp_state(pool.clone()).await;
    let args = serde_json::json!({ "required_capabilities": ["p32-cap"] });

    // CONTROL A: a real match is reported.
    let ok = controller::mcp::graph::dispatch(
        "preview_capability_dispatch",
        Some(serde_json::json!(1)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("preview_capability_dispatch is dispatched");
    assert_eq!(
        text_json(&ok).get("match_count").and_then(Value::as_u64),
        Some(1),
        "control: the seeded workflow matches: {}",
        text_json(&ok)
    );

    // CONTROL B: a genuine no-match still answers 0 rather than refusing.
    let none = controller::mcp::graph::dispatch(
        "preview_capability_dispatch",
        Some(serde_json::json!(2)),
        &serde_json::json!({ "required_capabilities": ["p32-nothing-has-this"] }),
        &state,
        agent(user_id),
    )
    .await
    .expect("preview_capability_dispatch is dispatched");
    assert_eq!(
        text_json(&none).get("match_count").and_then(Value::as_u64),
        Some(0),
        "control: a measured zero is a real answer and must stay one"
    );

    drop_column(&pool, "workflows", "readiness_score").await;

    let degraded = controller::mcp::graph::dispatch(
        "preview_capability_dispatch",
        Some(serde_json::json!(3)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("preview_capability_dispatch is dispatched");
    let msg = error_message(&degraded);
    assert!(
        msg.contains("UNKNOWN"),
        "an unread capability index must refuse: `match_count: 0` here is read, \
         by the tool's own dispatch_note, as 'dispatch fails hard unless a \
         fallback is set'. Got: {msg}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 9 + 10. `find_module_alternatives` — both search paths, both fallbacks.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn two_failed_alternative_searches_refuse_rather_than_reporting_none() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    seed_module(&pool, Some(user_id), "p32-target").await;
    seed_module(&pool, Some(user_id), "p32-sibling").await;
    let state = mcp_state(pool.clone()).await;
    let by_name = serde_json::json!({ "module_name": "p32-target" });

    // CONTROL: the healthy path answers with a count and a search_method.
    let ok = controller::mcp::modules::dispatch(
        "find_module_alternatives",
        Some(serde_json::json!(1)),
        &by_name,
        &state,
        agent(user_id),
    )
    .await
    .expect("find_module_alternatives is dispatched");
    let healthy = text_json(&ok);
    assert!(
        healthy.get("count").is_some(),
        "control: the healthy path answers: {healthy}"
    );

    drop_column(&pool, "modules", "category").await;

    let degraded = controller::mcp::modules::dispatch(
        "find_module_alternatives",
        Some(serde_json::json!(2)),
        &by_name,
        &state,
        agent(user_id),
    )
    .await
    .expect("find_module_alternatives is dispatched");
    let msg = error_message(&degraded);
    assert!(
        msg.contains("NOT a report that no alternative module exists"),
        "when the similarity search AND its fallback both fail there is no \
         answer left — `count: 0` with a tip pointing at list_module_catalog is \
         a determinate negative over two queries that did not answer. Got: {msg}"
    );

    // The capability branch is the same shape with a different pair of reads.
    let by_cap = controller::mcp::modules::dispatch(
        "find_module_alternatives",
        Some(serde_json::json!(3)),
        &serde_json::json!({ "capability": "minimal" }),
        &state,
        agent(user_id),
    )
    .await
    .expect("find_module_alternatives is dispatched");
    let cap_msg = error_message(&by_cap);
    assert!(
        cap_msg.contains("NOT a report that no module provides this capability"),
        "the capability branch must refuse too: {cap_msg}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 11. `get_platform_info` — an unread catalog is null, and so is the total.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_unread_catalog_listing_nulls_the_tool_counts_rather_than_zeroing_them() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    seed_module(&pool, None, "p32-catalog-entry").await;
    let state = mcp_state(pool.clone()).await;

    // CONTROL: the healthy report carries three numbers that add up.
    let ok = controller::mcp::platform::dispatch(
        "get_platform_info",
        Some(serde_json::json!(1)),
        &serde_json::json!({}),
        &state,
        agent(user_id),
    )
    .await
    .expect("get_platform_info is dispatched");
    let healthy = text_json(&ok);
    let stat = healthy
        .get("static_tool_count")
        .and_then(Value::as_i64)
        .expect("static count");
    let cat = healthy
        .get("catalog_tool_count")
        .and_then(Value::as_i64)
        .expect("catalog count is measured on a healthy tree");
    assert_eq!(
        healthy.get("total_mcp_tools").and_then(Value::as_i64),
        Some(stat + cat),
        "control: the note's arithmetic must hold: {healthy}"
    );
    assert!(healthy.get("measurement").is_none());

    drop_column(&pool, "modules", "config_schema").await;

    let degraded = controller::mcp::platform::dispatch(
        "get_platform_info",
        Some(serde_json::json!(2)),
        &serde_json::json!({}),
        &state,
        agent(user_id),
    )
    .await
    .expect("get_platform_info is dispatched");
    let body = text_json(&degraded);
    assert!(
        body.get("catalog_tool_count")
            .map(Value::is_null)
            .unwrap_or(false),
        "an unread catalog must be null, never 0: {body}"
    );
    assert!(
        body.get("total_mcp_tools")
            .map(Value::is_null)
            .unwrap_or(false),
        "a total derived from an unread half must be null too — pre-fix it \
         silently equalled static_tool_count: {body}"
    );
    assert_eq!(
        body.get("static_tool_count").and_then(Value::as_i64),
        Some(stat),
        "the measured half must survive: {body}"
    );
    assert!(not_measured(&body).contains(&"catalog_tool_count".to_string()));
}

// ───────────────────────────────────────────────────────────────────────────
// 12. `find_similar_workflows` — the comparison set IS the answer.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_unreadable_comparison_set_refuses_rather_than_reporting_no_similar_workflows() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let source = seed_workflow(&pool, user_id, None).await;
    let _other = seed_workflow(&pool, user_id, None).await;
    let state = mcp_state(pool.clone()).await;
    let args = serde_json::json!({ "workflow_id": source.to_string() });

    // CONTROL: the healthy path finds the sibling (both graphs share `module`).
    let ok = controller::mcp::search::dispatch(
        "find_similar_workflows",
        Some(serde_json::json!(1)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("find_similar_workflows is dispatched");
    let healthy = text_json(&ok);
    assert_eq!(
        healthy.get("count").and_then(Value::as_u64),
        Some(1),
        "control: the sibling workflow is similar: {healthy}"
    );

    drop_column(&pool, "workflows", "name").await;

    let degraded = controller::mcp::search::dispatch(
        "find_similar_workflows",
        Some(serde_json::json!(2)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("find_similar_workflows is dispatched");
    let msg = error_message(&degraded);
    assert!(
        msg.contains("UNKNOWN"),
        "an unread comparison set must refuse — 'no similar workflows' is the \
         answer an agent uses to justify building a duplicate. Got: {msg}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 13. `dispatch_to_actor` — an unread candidate list is not "owns none".
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_unread_candidate_list_is_not_an_actor_that_owns_no_workflows() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let actor_id = seed_actor(&pool, user_id).await;
    let state = mcp_state(pool.clone()).await;
    let args = serde_json::json!({ "actor_id": actor_id.to_string(), "input": {} });

    // CONTROL A: an actor that genuinely owns nothing keeps the pre-fix
    // sentence, so the fix cannot pass by refusing everything.
    let none = controller::mcp::workflows::dispatch(
        "dispatch_to_actor",
        Some(serde_json::json!(1)),
        &args,
        std::sync::Arc::new(mcp_state(pool.clone()).await),
        agent(user_id),
    )
    .await
    .expect("dispatch_to_actor is dispatched");
    assert!(
        error_message(&none).contains("owns no active workflows"),
        "control: an actor with none keeps its wording: {}",
        error_message(&none)
    );

    // Two active workflows put the handler on the branch under test.
    let a = seed_workflow(&pool, user_id, Some(actor_id)).await;
    let b = seed_workflow(&pool, user_id, Some(actor_id)).await;

    // CONTROL B: with two, the candidates are listed.
    let listed = controller::mcp::workflows::dispatch(
        "dispatch_to_actor",
        Some(serde_json::json!(2)),
        &args,
        std::sync::Arc::new(mcp_state(pool.clone()).await),
        agent(user_id),
    )
    .await
    .expect("dispatch_to_actor is dispatched");
    let listed_msg = error_message(&listed);
    assert!(
        listed_msg.contains(&a.to_string()) && listed_msg.contains(&b.to_string()),
        "control: both candidates are listed: {listed_msg}"
    );

    drop_column(&pool, "workflows", "name").await;

    let degraded = controller::mcp::workflows::dispatch(
        "dispatch_to_actor",
        Some(serde_json::json!(3)),
        &args,
        std::sync::Arc::new(state),
        agent(user_id),
    )
    .await
    .expect("dispatch_to_actor is dispatched");
    let msg = error_message(&degraded);
    assert!(
        msg.contains("UNKNOWN") && !msg.contains("owns no active workflows"),
        "an unread candidate listing must not render the ZERO-workflow message \
         — this branch is reached only because the count is 0 OR 2+. Got: {msg}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 14. `get_workflow_quickstart` — an unread vault is not a missing credential.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_unreadable_vault_listing_does_not_fabricate_missing_secret_blockers() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let module_id = seed_module(&pool, Some(user_id), "p32-quickstart-mod").await;
    sqlx::query("UPDATE modules SET allowed_secrets = ARRAY['p32/secret'] WHERE id = $1")
        .bind(module_id)
        .execute(&pool)
        .await
        .expect("grant a secret to the module");
    let graph = format!(
        "{{\"nodes\":[{{\"id\":\"n1\",\"type\":\"{module_id}\",\"data\":{{\"label\":\"n\",\"config\":{{\"AUTH\":\"vault://p32/secret\"}}}}}}],\"edges\":[]}}"
    );
    let wf_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, module_uri, graph_json, status, is_enabled) \
         VALUES ($1, $2, $3, 'test:p32', $4, 'active', true)",
    )
    .bind(wf_id)
    .bind(user_id)
    .bind(format!("p32-qs-{}", wf_id.simple()))
    .bind(&graph)
    .execute(&pool)
    .await
    .expect("seed quickstart workflow");
    let state = std::sync::Arc::new(mcp_state(pool.clone()).await);
    let args = serde_json::json!({ "workflow_id": wf_id.to_string() });

    // CONTROL: a measured vault gives a boolean verdict.
    let ok = controller::mcp::workflows::dispatch(
        "get_workflow_quickstart",
        Some(serde_json::json!(1)),
        &args,
        state.clone(),
        agent(user_id),
    )
    .await
    .expect("get_workflow_quickstart is dispatched");
    let healthy = text_json(&ok);
    assert!(
        healthy
            .get("ready_to_run")
            .map(Value::is_boolean)
            .unwrap_or(false),
        "control: a measured verdict is a boolean: {healthy}"
    );
    assert!(healthy.get("measurement").is_none());
    // The fixture MUST reach the secrets branch, or the degraded assertions
    // below would pass vacuously — the shape package 22 records as a test that
    // proves nothing because the path it names was never entered.
    assert_eq!(
        healthy
            .get("secrets_status")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(1),
        "control: the node's vault:// reference must reach the secrets branch: {healthy}"
    );

    drop_relation(&pool, "secrets").await;

    let degraded = controller::mcp::workflows::dispatch(
        "get_workflow_quickstart",
        Some(serde_json::json!(2)),
        &args,
        state,
        agent(user_id),
    )
    .await
    .expect("get_workflow_quickstart is dispatched");
    let body = text_json(&degraded);
    assert!(
        body.get("ready_to_run")
            .map(Value::is_null)
            .unwrap_or(false),
        "a verdict computed from an unread vault must be null: {body}"
    );
    let blockers = body
        .get("blockers")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert!(
        !blockers
            .iter()
            .any(|b| b.get("type").and_then(Value::as_str) == Some("missing_secret")),
        "an unread vault must NOT fabricate a missing_secret blocker for a \
         credential that may already be provisioned: {body}"
    );
    assert_eq!(
        body.pointer("/secrets_status/0/provisioned"),
        Some(&Value::Null),
        "`provisioned` is three-valued: null, not false: {body}"
    );
    assert!(not_measured(&body).contains(&"secrets_status".to_string()));
}

// ───────────────────────────────────────────────────────────────────────────
// 15. `actor_recall` — the two MEASURED arms, pinned.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn actor_recall_tells_expired_from_never_set() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let actor_id = seed_actor(&pool, user_id).await;
    // `value_key_id` carries an FK to `encryption_keys`, so the fixture needs a
    // real DEK row even though the ciphertext is a placeholder.
    let dek_id: Uuid = sqlx::query_scalar(
        "INSERT INTO encryption_keys (id, encrypted_key, algorithm, active) \
         VALUES (gen_random_uuid(), '\\x00'::bytea, 'AES-256-GCM', false) RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("seed a DEK row");

    // allow-actor-memory-sql: the row is a fixture for the EXPIRY filter and is
    // never decrypted — `recall_exact` short-circuits on `expires_at`, so a
    // placeholder ciphertext is enough and going through the real writer would
    // need a second UPDATE to backdate the row anyway.
    sqlx::query(
        "INSERT INTO actor_memory \
             (id, actor_id, key, memory_type, value_enc, value_key_id, value_format, \
              expires_at, created_at, updated_at) \
         VALUES ($1, $2, 'p32/expired', 'episodic', '\\x00'::bytea, $3, 0, \
                 NOW() - INTERVAL '1 hour', NOW(), NOW())",
    )
    .bind(Uuid::new_v4())
    .bind(actor_id)
    .bind(dek_id)
    .execute(&pool)
    .await
    .expect("seed an expired memory");
    let state = mcp_state(pool.clone()).await;

    for (key, want) in [("p32/expired", "expired"), ("p32/absent", "never_set")] {
        let resp = controller::mcp::actor::dispatch(
            "actor_recall",
            Some(serde_json::json!(1)),
            &serde_json::json!({ "actor_id": actor_id.to_string(), "key": key }),
            &state,
            agent(user_id),
        )
        .await
        .expect("actor_recall is dispatched");
        let body = text_json(&resp);
        assert_eq!(
            body.get("reason").and_then(Value::as_str),
            Some(want),
            "the two MEASURED arms must keep their exact wording: {body}"
        );
        assert!(
            body.get("measurement").is_none(),
            "a measured answer carries no disclosure: {body}"
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// 16. Source pins for the sites no relation drop can reach.
// ───────────────────────────────────────────────────────────────────────────

/// The three call sites this binary cannot drive, pinned against the shape they
/// were repaired into. Weaker than a round trip and said so: it proves the
/// expression is present, never that it produces the right answer.
#[test]
fn the_unreachable_repairs_are_still_in_place() {
    let lib = include_str!("../../talos-mcp-handlers/src/lib.rs");
    assert!(
        lib.contains("local_identity_refusal"),
        "/mcp/local must REFUSE when no dev identity resolves; serving the \
         request identity-less made every tool report success while writing \
         nowhere"
    );
    assert!(
        !lib.contains("sysrepo.find_first_user_id().await.ok().flatten()"),
        "the swallowed dev-user read must stay gone"
    );

    let workflows = include_str!("../../talos-mcp-handlers/src/workflows.rs");
    assert!(
        workflows.contains("could not be WRITTEN (database failure) — the bundle is fine"),
        "import_workflow must not report a failed module WRITE as a bundle with \
         no source"
    );
    assert!(
        !workflows.contains("the following modules are missing (no source in bundle)"),
        "the one-reason-for-five-causes sentence must stay gone"
    );
    assert!(
        workflows.contains("Could not read the module catalog while resolving"),
        "instantiate_workflow_pattern must not tell an operator to install a \
         module whose absence it could not establish"
    );

    let advanced = include_str!("../../talos-mcp-handlers/src/advanced.rs");
    assert!(
        advanced.contains("Could not read the module config schemas"),
        "get_config_suggestions must not answer 'No missing required fields' \
         from an unread schema map"
    );
    assert!(
        advanced.contains("provisioned_note"),
        "get_config_suggestions must render `provisioned: null`, not false, for \
         an unread vault listing"
    );
}
