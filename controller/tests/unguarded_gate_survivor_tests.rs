//! One test per SITE for the fixes #779 shipped with none.
//!
//! Package 26 (#779) closed eight fail-OPEN gates and thirteen claim sites and
//! recorded, in its own notes, that reverting NINE of them left every test in
//! the workspace green. Its rule was one test per SHAPE; this binary's rule is
//! one test per SITE whose consequence is IRREVERSIBLE or AUTHORIZING, because
//! "the shape is pinned elsewhere" is exactly the reasoning that let
//! `cleanup_module_versions` survive package 23's mutation.
//!
//! Ordered by blast radius:
//!
//!  1. `add_node_to_workflow`'s ACTOR CAPABILITY-WORLD CEILING, and
//!  2. its MODULE-WORLD half — one gate with two reads, and MCP-545 repaired
//!     the runtime pair and missed both of these. It needs a seeded module row
//!     PLUS a graph PLUS an actor-bound workflow, which is why #779 skipped it.
//!  3. `submit_workflow_approval` — a failed approval WRITE answering "it may
//!     have already been decided", the one diagnosis that stops a retry on a
//!     HUMAN-approval gate.
//!  4. `export_workflow` / 5. `import_workflow` — a bundle whose `modules: []`
//!     is a corrupt backup byte-indistinguishable from a module-less workflow,
//!     and the importer that would reconstitute it.
//!  6. `create_webhook` — a uniqueness pre-flight nothing downstream backs.
//!  7. `get_module_dependents` — see the note on that test: its two reads are
//!     over the same table and the same columns, so the second is NOT
//!     isolable by this binary's mechanism, and the test pins what IS.
//!  8. `whoami` — a hardcoded literal rendered as this user's authorization
//!     ceiling.
//!  9. `build_execution_trace_json` — `sub_execution_count: 0` in three
//!     surfaces at once.
//!
//! `talos-api`'s `dlq_updates` is the tenth site and gets NO test here: its
//! permission refresh is three lines of local-variable assignment inside an
//! `async_stream!` in a subscription resolver, driven by a 60-second ticker,
//! with no seam a test can reach without restructuring the resolver. Stated
//! rather than left to look like coverage.
//!
//! Mechanism: package 22's. The relation each read names is removed in the
//! per-test isolated database, so the statement cannot run — the cheapest
//! reproducible database failure there is. Every test carries its CONTROL in
//! the same run, and for the gates the control is the one that matters: a
//! healthy gate must still refuse for the RIGHT reason, because "the tool
//! refused" is not evidence when the pre-fix path also refused.

#[path = "common/mod.rs"]
mod common;
// The real `McpState` + response helpers, one home (2026-09-08).
#[path = "common/mcp.rs"]
mod mcp_common;

use mcp_common::{agent, error_message, mcp_state, text_json};
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

async fn seed_user(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, created_at, updated_at) \
         VALUES ($1, $2, 'x', NOW(), NOW())",
    )
    .bind(id)
    .bind(format!("p29g-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

/// An actor with an explicit capability-world ceiling. `minimal-node` is the
/// column's own default; the tests that need a REFUSAL from a healthy gate
/// pass it, and the ones that need a PERMIT pass `automation-node`.
async fn seed_actor(pool: &sqlx::PgPool, user_id: Uuid, max_world: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO actors (id, user_id, name, max_capability_world) VALUES ($1, $2, $3, $4)",
    )
    .bind(id)
    .bind(user_id)
    .bind(format!("p29g-actor-{}", id.simple()))
    .bind(max_world)
    .execute(pool)
    .await
    .expect("seed actor");
    id
}

async fn seed_module(pool: &sqlx::PgPool, user_id: Uuid, world: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO modules (name, kind, user_id, capability_world, category) \
         VALUES ($1, 'sandbox', $2, $3, 'test') RETURNING id",
    )
    .bind(format!("p29g-mod-{}", Uuid::new_v4().simple()))
    .bind(user_id)
    .bind(world)
    .fetch_one(pool)
    .await
    .expect("seed module")
}

async fn seed_workflow(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    actor_id: Option<Uuid>,
    graph: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, actor_id, name, module_uri, graph_json, status, \
                                is_enabled) \
         VALUES ($1, $2, $3, $4, 'test:p29g', $5::jsonb, 'active', true)",
    )
    .bind(id)
    .bind(user_id)
    .bind(actor_id)
    .bind(format!("p29g-wf-{}", id.simple()))
    .bind(graph)
    .execute(pool)
    .await
    .expect("seed workflow");
    id
}

async fn seed_execution(pool: &sqlx::PgPool, wf_id: Uuid, user_id: Uuid, actor_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflow_executions \
             (id, workflow_id, user_id, actor_id, status, started_at) \
         VALUES ($1, $2, $3, $4, 'waiting', NOW() - INTERVAL '1 minute')",
    )
    .bind(id)
    .bind(wf_id)
    .bind(user_id)
    .bind(actor_id)
    .execute(pool)
    .await
    .expect("seed execution");
    id
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

// ───────────────────────────────────────────────────────────────────────────
// 1. `add_node_to_workflow` — the ACTOR capability-world ceiling.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn add_node_refuses_when_the_actor_ceiling_cannot_be_read() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let actor_id = seed_actor(&pool, user_id, "minimal-node").await;
    let wf_id = seed_workflow(&pool, user_id, Some(actor_id), r#"{"nodes":[],"edges":[]}"#).await;
    let state = Arc::new(mcp_state(pool.clone()).await);

    // CONTROL A: the gate WORKS. A `minimal-node` actor must not be able to
    // author an `automation-node` node, and the refusal must name the ceiling
    // — a test that only asserted "it refused" would pass with the gate gone,
    // because a later step refuses too.
    let over = serde_json::json!({
        "workflow_id": wf_id.to_string(),
        "node_id": "p29-node",
        "capability_world": "automation-node",
    });
    let refused = controller::mcp::workflows::dispatch(
        "add_node_to_workflow",
        Some(serde_json::json!(1)),
        &over,
        state.clone(),
        agent(user_id),
    )
    .await
    .expect("add_node_to_workflow is dispatched");
    let msg = error_message(&refused);
    assert!(
        msg.contains("exceeds actor's max_capability_world"),
        "control: a healthy gate refuses for the ceiling reason: {msg}"
    );

    // The ceiling read now cannot run. `try_get_actor_max_world` projects
    // exactly this column; `get_workflow_actor_id` above it reads
    // `workflows.actor_id`, so the handler still reaches the gate.
    sqlx::query("ALTER TABLE actors DROP COLUMN max_capability_world CASCADE")
        .execute(&pool)
        .await
        .expect("drop the column the ceiling read names");

    let degraded = controller::mcp::workflows::dispatch(
        "add_node_to_workflow",
        Some(serde_json::json!(2)),
        &over,
        state.clone(),
        agent(user_id),
    )
    .await
    .expect("add_node_to_workflow is dispatched");
    let msg = error_message(&degraded);
    assert!(
        msg.contains("ceiling could not be enforced"),
        "an unreadable ceiling must REFUSE and say the gate did not run: {msg}"
    );

    // And it must not have written. A gate whose refusal arrives after the
    // graph save is not a gate.
    let graph: String = sqlx::query_scalar("SELECT graph_json FROM workflows WHERE id = $1")
        .bind(wf_id)
        .fetch_one(&pool)
        .await
        .expect("read graph back");
    assert!(
        !graph.contains("p29-node"),
        "the refused node must not be in the stored graph: {graph}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 2. `add_node_to_workflow` — the MODULE-world half of the same gate.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn add_node_refuses_when_the_module_world_cannot_be_read() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    // A ceiling that PERMITS the module below, so the control is a success and
    // not an incidental refusal from the sibling half of the gate.
    let actor_id = seed_actor(&pool, user_id, "automation-node").await;
    let wf_id = seed_workflow(&pool, user_id, Some(actor_id), r#"{"nodes":[],"edges":[]}"#).await;
    let module_id = seed_module(&pool, user_id, "minimal-node").await;
    let state = Arc::new(mcp_state(pool.clone()).await);

    let args = serde_json::json!({
        "workflow_id": wf_id.to_string(),
        "node_id": "p29-mod-node",
        "module_id": module_id.to_string(),
    });

    // CONTROL: a module INSIDE the ceiling is added, and the row proves it.
    let ok = controller::mcp::workflows::dispatch(
        "add_node_to_workflow",
        Some(serde_json::json!(1)),
        &args,
        state.clone(),
        agent(user_id),
    )
    .await
    .expect("dispatched");
    assert!(ok.error.is_none(), "control must succeed: {:?}", ok.error);
    let graph: String = sqlx::query_scalar("SELECT graph_json FROM workflows WHERE id = $1")
        .bind(wf_id)
        .fetch_one(&pool)
        .await
        .expect("read graph back");
    assert!(
        graph.contains("p29-mod-node"),
        "control: the permitted node really landed: {graph}"
    );

    // `get_module_capability_worlds` projects `capability_world`; without it
    // the statement cannot run. The ACTOR ceiling read is on a different
    // table, so the handler still reaches this half of the gate.
    sqlx::query("ALTER TABLE modules DROP COLUMN capability_world CASCADE")
        .execute(&pool)
        .await
        .expect("drop the column the module-world read names");

    let second = serde_json::json!({
        "workflow_id": wf_id.to_string(),
        "node_id": "p29-mod-node-2",
        "module_id": module_id.to_string(),
    });
    let degraded = controller::mcp::workflows::dispatch(
        "add_node_to_workflow",
        Some(serde_json::json!(2)),
        &second,
        state.clone(),
        agent(user_id),
    )
    .await
    .expect("dispatched");
    let msg = error_message(&degraded);
    assert!(
        msg.contains("capability-world ceiling could not be enforced"),
        "an unreadable module world must refuse, not add the node: {msg}"
    );
    let graph: String = sqlx::query_scalar("SELECT graph_json FROM workflows WHERE id = $1")
        .bind(wf_id)
        .fetch_one(&pool)
        .await
        .expect("read graph back");
    assert!(
        !graph.contains("p29-mod-node-2"),
        "the refused node must not be in the stored graph: {graph}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 3. `submit_workflow_approval` — an unwritable decision is not a decided one.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_failed_approval_write_is_not_reported_as_already_decided() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let actor_id = seed_actor(&pool, user_id, "minimal-node").await;
    let wf_id = seed_workflow(&pool, user_id, None, r#"{"nodes":[],"edges":[]}"#).await;
    let exec_id = seed_execution(&pool, wf_id, user_id, actor_id).await;
    let state = mcp_state(pool.clone()).await;
    let args = serde_json::json!({
        "execution_id": exec_id.to_string(),
        "approved": true,
    });

    // CONTROL: with no pending approval row the honest zero-row diagnosis must
    // still be reachable and must still be the one rendered.
    let ok = controller::mcp::executions::dispatch(
        "submit_workflow_approval",
        Some(serde_json::json!(1)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("submit_workflow_approval is dispatched");
    let msg = error_message(&ok);
    assert!(
        msg.contains("No pending approval found"),
        "control: a real zero must keep its own diagnosis: {msg}"
    );

    sqlx::query("DROP TABLE execution_approvals CASCADE")
        .execute(&pool)
        .await
        .expect("drop the table the approval write names");

    let degraded = controller::mcp::executions::dispatch(
        "submit_workflow_approval",
        Some(serde_json::json!(2)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("submit_workflow_approval is dispatched");
    let msg = error_message(&degraded);
    assert!(
        msg.contains("the write failed"),
        "an unwritable decision must say the write failed: {msg}"
    );
    assert!(
        !msg.contains("No pending approval found"),
        "it must NOT be the diagnosis that stops a retry: {msg}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 4. `export_workflow` — a bundle is complete or it is not a bundle.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn export_workflow_refuses_rather_than_shipping_an_empty_module_list() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let module_id = seed_module(&pool, user_id, "minimal-node").await;
    // `extract_module_ids_from_graph_value` keys on `node.type` being a UUID,
    // so the bundle's module list is non-empty and the metadata read runs.
    let graph = format!(r#"{{"nodes":[{{"id":"n1","type":"{module_id}"}}],"edges":[]}}"#);
    let wf_id = seed_workflow(&pool, user_id, None, &graph).await;
    let state = Arc::new(mcp_state(pool.clone()).await);
    let args = serde_json::json!({ "workflow_id": wf_id.to_string() });

    // CONTROL: a healthy export really does carry the module.
    let ok = controller::mcp::workflows::dispatch(
        "export_workflow",
        Some(serde_json::json!(1)),
        &args,
        state.clone(),
        agent(user_id),
    )
    .await
    .expect("export_workflow is dispatched");
    let bundle = text_json(&ok);
    assert_eq!(
        bundle
            .pointer("/bundle/modules")
            .or_else(|| bundle.get("modules"))
            .and_then(|m| m.as_array())
            .map(|a| a.len()),
        Some(1),
        "control: the bundle carries its module: {bundle}"
    );

    sqlx::query("ALTER TABLE modules DROP COLUMN category CASCADE")
        .execute(&pool)
        .await
        .expect("drop a column the export metadata read projects");

    let degraded = controller::mcp::workflows::dispatch(
        "export_workflow",
        Some(serde_json::json!(2)),
        &args,
        state.clone(),
        agent(user_id),
    )
    .await
    .expect("export_workflow is dispatched");
    let msg = error_message(&degraded);
    assert!(
        msg.contains("No bundle was produced"),
        "a corrupt bundle must not be produced at all: {msg}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 5. `import_workflow` — an unreadable existence check is not "all missing".
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn import_workflow_refuses_rather_than_calling_every_module_missing() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let module_id = seed_module(&pool, user_id, "minimal-node").await;
    let state = Arc::new(mcp_state(pool.clone()).await);
    let bundle = serde_json::json!({
        "version": 1,
        "name": "p29-imported",
        "graph_json": { "nodes": [ { "id": "n1", "type": module_id.to_string() } ], "edges": [] },
        "modules": [],
    });
    let args = serde_json::json!({ "bundle": bundle });

    // CONTROL: the module EXISTS, so a healthy import succeeds and reports
    // nothing missing.
    let ok = controller::mcp::workflows::dispatch(
        "import_workflow",
        Some(serde_json::json!(1)),
        &args,
        state.clone(),
        agent(user_id),
    )
    .await
    .expect("import_workflow is dispatched");
    assert!(
        ok.error.is_none(),
        "control must succeed: {:?} / {:?}",
        ok.error,
        ok.result
    );

    sqlx::query("DROP TABLE modules CASCADE")
        .execute(&pool)
        .await
        .expect("drop the table the existence read names");

    let degraded = controller::mcp::workflows::dispatch(
        "import_workflow",
        Some(serde_json::json!(2)),
        &args,
        state.clone(),
        agent(user_id),
    )
    .await
    .expect("import_workflow is dispatched");
    let msg = error_message(&degraded);
    assert!(
        !msg.to_lowercase().contains("missing"),
        "a failed existence read must not name every module missing: {msg}"
    );
    assert!(
        msg.to_lowercase().contains("database"),
        "it must refuse as a database failure: {msg}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 6. `create_webhook` — a uniqueness bound nothing downstream backs.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn create_webhook_refuses_when_name_uniqueness_cannot_be_checked() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let wf_id = seed_workflow(&pool, user_id, None, r#"{"nodes":[],"edges":[]}"#).await;
    let state = mcp_state(pool.clone()).await;
    let args = serde_json::json!({
        "workflow_id": wf_id.to_string(),
        "name": "p29-hook",
    });

    // CONTROL: the first create succeeds, and a SECOND one with the same name
    // is refused BY THE GATE — so the gate is proven live before it is broken.
    let ok = controller::mcp::webhooks::dispatch(
        "create_webhook",
        Some(serde_json::json!(1)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("create_webhook is dispatched");
    assert!(ok.error.is_none(), "control must succeed: {:?}", ok.error);
    let dup = controller::mcp::webhooks::dispatch(
        "create_webhook",
        Some(serde_json::json!(2)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("create_webhook is dispatched");
    let msg = error_message(&dup);
    assert!(
        msg.to_lowercase().contains("already exists"),
        "control: the uniqueness gate really fires: {msg}"
    );

    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM webhook_triggers")
        .fetch_one(&pool)
        .await
        .expect("count webhooks");

    // The uniqueness read projects `EXISTS(… FROM webhook_triggers …)`; drop
    // the table and it cannot run. Nothing downstream backs this bound —
    // `webhook_triggers.name` carries no unique index — so a lifted gate here
    // creates the duplicate and keeps it.
    sqlx::query("ALTER TABLE webhook_triggers RENAME COLUMN name TO name_gone")
        .execute(&pool)
        .await
        .expect("rename the column the uniqueness read names");

    let degraded = controller::mcp::webhooks::dispatch(
        "create_webhook",
        Some(serde_json::json!(3)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("create_webhook is dispatched");
    let msg = error_message(&degraded);
    assert!(
        msg.contains("uniqueness could not be enforced"),
        "an unreadable uniqueness check must refuse: {msg}"
    );
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM webhook_triggers")
        .fetch_one(&pool)
        .await
        .expect("count webhooks");
    assert_eq!(
        before, after,
        "no webhook may be created when the gate could not run"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 7. `get_module_dependents` — what IS pinnable here, and what is not.
// ───────────────────────────────────────────────────────────────────────────

/// The INDIRECT read's disclosure cannot be reached by this binary's
/// mechanism, and saying so is worth more than a test that looks like
/// coverage: `find_workflows_referencing_module` (direct) and
/// `find_workflows_referencing_workflows` (indirect) read the SAME table
/// through the SAME columns (`id`, `name`, `graph_json`, `status`,
/// `updated_at`), so no schema-level failure breaks the second without
/// breaking the first — and the first already refuses, several lines above.
/// What this test pins is the pair that IS reachable: the direct read's
/// refusal, and a healthy response whose `indirect_count` is a MEASURED zero
/// rather than the `null` the disclosure emits. A mutation that reverts the
/// indirect read to `if let Ok(triples)` is caught by structural lint 74b,
/// not here, because that function builds a `Readings` ledger.
#[tokio::test]
async fn module_dependents_refuses_on_an_unreadable_dependency_scan() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let module_id = seed_module(&pool, user_id, "minimal-node").await;
    let graph = format!(r#"{{"nodes":[{{"id":"n1","type":"{module_id}"}}],"edges":[]}}"#);
    seed_workflow(&pool, user_id, None, &graph).await;
    let state = mcp_state(pool.clone()).await;
    let args = serde_json::json!({ "module_id": module_id.to_string() });

    // CONTROL: a healthy scan reports a MEASURED zero for the indirect leg —
    // `Some(0)`, not `null` — and carries no disclosure.
    let ok = controller::mcp::modules::dispatch(
        "get_module_dependents",
        Some(serde_json::json!(1)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("get_module_dependents is dispatched");
    let body = text_json(&ok);
    assert_eq!(
        body.get("direct_count").and_then(|v| v.as_u64()),
        Some(1),
        "control: the direct dependency is found: {body}"
    );
    assert_eq!(
        body.get("indirect_count").and_then(|v| v.as_u64()),
        Some(0),
        "control: a real zero stays a zero, not a null: {body}"
    );
    assert!(
        not_measured(&body).is_empty(),
        "control: nothing is disclosed on a healthy scan: {body}"
    );

    sqlx::query("ALTER TABLE workflows DROP COLUMN updated_at CASCADE")
        .execute(&pool)
        .await
        .expect("drop a column both dependency scans order by");

    let degraded = controller::mcp::modules::dispatch(
        "get_module_dependents",
        Some(serde_json::json!(2)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("get_module_dependents is dispatched");
    let msg = error_message(&degraded);
    assert!(
        msg.contains("Failed to query module dependents"),
        "an unreadable dependency scan must refuse, never answer zero: {msg}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 8. `whoami` — an authorization ceiling is not a hardcoded literal.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn whoami_nulls_the_ceiling_it_could_not_read() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let state = mcp_state(pool.clone()).await;
    let args = serde_json::json!({});

    // CONTROL: no grant row is a MEASURED answer — the column's documented
    // permissive default — so `http-node` must still be rendered, with no
    // disclosure. This is the arm that makes the degraded case meaningful:
    // the literal is right in one case and a fabrication in the other.
    let ok = controller::mcp::platform::dispatch(
        "whoami",
        Some(serde_json::json!(1)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("whoami is dispatched");
    let body = text_json(&ok);
    assert_eq!(
        body.get("capability_ceiling").and_then(|v| v.as_str()),
        Some("http-node"),
        "control: the documented default is a measured answer: {body}"
    );
    assert!(
        body.get("measurement").is_none(),
        "control: no disclosure on a healthy identity: {body}"
    );

    sqlx::query("DROP TABLE user_capability_grants CASCADE")
        .execute(&pool)
        .await
        .expect("drop the table the ceiling read names");

    let degraded = controller::mcp::platform::dispatch(
        "whoami",
        Some(serde_json::json!(2)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("whoami is dispatched");
    let body = text_json(&degraded);
    assert!(
        body.get("capability_ceiling")
            .map(|v| v.is_null())
            .unwrap_or(false),
        "an unreadable ceiling must be null, never the literal: {body}"
    );
    assert!(
        not_measured(&body).contains(&"capability_ceiling".to_string()),
        "the failed read must be named: {body}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 9. `build_execution_trace_json` — one swallow, three surfaces.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_execution_trace_nulls_the_child_count_it_could_not_read() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let actor_id = seed_actor(&pool, user_id, "minimal-node").await;
    let wf_id = seed_workflow(&pool, user_id, None, r#"{"nodes":[],"edges":[]}"#).await;
    let exec_id = seed_execution(&pool, wf_id, user_id, actor_id).await;
    let state = mcp_state(pool.clone()).await;
    let args = serde_json::json!({ "execution_id": exec_id.to_string() });

    // CONTROL: an execution that genuinely dispatched nothing reports a
    // measured zero.
    let ok = controller::mcp::executions::dispatch(
        "get_execution_trace",
        Some(serde_json::json!(1)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("get_execution_trace is dispatched");
    let body = text_json(&ok);
    assert_eq!(
        body.pointer("/summary/sub_execution_count")
            .and_then(|v| v.as_u64()),
        Some(0),
        "control: a real zero must stay sayable: {body}"
    );
    assert!(
        not_measured(&body).is_empty(),
        "control: no disclosure on a healthy trace: {body}"
    );

    // `list_child_executions` filters on `parent_execution_id`; the trace's
    // own execution read (`execution_row_columns!`) does not project it, so
    // the failure is isolated to the child list.
    sqlx::query("ALTER TABLE workflow_executions DROP COLUMN parent_execution_id CASCADE")
        .execute(&pool)
        .await
        .expect("drop the column the child read names");

    let degraded = controller::mcp::executions::dispatch(
        "get_execution_trace",
        Some(serde_json::json!(2)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("get_execution_trace is dispatched");
    let body = text_json(&degraded);
    assert!(
        body.pointer("/summary/sub_execution_count")
            .map(|v| v.is_null())
            .unwrap_or(false),
        "'dispatched no children' must not come from a read that failed: {body}"
    );
    assert!(
        not_measured(&body).contains(&"sub_executions".to_string()),
        "the failed read must be named: {body}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 10. Leg C — RFC 0012 P3's own recorded SILENT survivor.
// ───────────────────────────────────────────────────────────────────────────

/// P3 (2026-09-07) recorded that `get_workflow_sla_report`'s handler can pass
/// `child_runs: None` / `ledger_since: None` — "not consulted" — and every
/// test stays green, because the DB tests drive the repository read, the unit
/// tests drive the pure renderer, and neither can see a call site that
/// computes the right answer and DISCARDS it (checks 74b/79b's stated limit).
/// P3 called that one SILENT, unlike its sibling in the risk check which
/// self-discloses via `reason: "ledger_not_consulted"`, and left it open with
/// "the live read after deploy" as its honest guard.
///
/// This is that guard, in a test: a workflow with recorded child runs and NO
/// execution rows must report them, and a mutation that stops passing them
/// makes this fail rather than silently reverting the surface to
/// `not_measurable`.
#[tokio::test]
async fn the_sla_report_passes_the_child_runs_it_read() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let actor_id = seed_actor(&pool, user_id, "minimal-node").await;
    let parent_wf = seed_workflow(&pool, user_id, None, r#"{"nodes":[],"edges":[]}"#).await;
    let child_wf = seed_workflow(&pool, user_id, None, r#"{"nodes":[],"edges":[]}"#).await;
    let parent_exec = seed_execution(&pool, parent_wf, user_id, actor_id).await;

    // Three recorded runs, one of them failed: enough to clear
    // `LEDGER_MIN_RUNS` and to make the success rate a number that could only
    // have come from the ledger.
    for (i, status) in ["completed", "completed", "failed"].iter().enumerate() {
        sqlx::query(
            "INSERT INTO sub_workflow_runs \
                 (parent_execution_id, parent_workflow_id, parent_node_id, dispatch_kind, \
                  child_workflow_id, user_id, depth, started_at, completed_at, status, \
                  duration_ms) \
             VALUES ($1, $2, 'n1', 'sub_workflow', $3, $4, 1, \
                     NOW() - make_interval(hours => $5::int), \
                     NOW() - make_interval(hours => $5::int) + INTERVAL '1 second', $6, 1000)",
        )
        .bind(parent_exec)
        .bind(parent_wf)
        .bind(child_wf)
        .bind(user_id)
        .bind(i as i32 + 1)
        .bind(status)
        .execute(&pool)
        .await
        .expect("seed child run");
    }

    let state = mcp_state(pool.clone()).await;
    let body = text_json(
        &controller::mcp::analytics::dispatch(
            "get_workflow_sla_report",
            Some(serde_json::json!(1)),
            &serde_json::json!({ "workflow_id": child_wf.to_string() }),
            &state,
            agent(user_id),
        )
        .await
        .expect("get_workflow_sla_report is dispatched"),
    );

    assert_eq!(
        body.pointer("/child_runs/runs").and_then(|v| v.as_u64()),
        Some(3),
        "the handler must PASS the child runs it read, not drop them: {body}"
    );
    assert_eq!(
        body.get("total_executions").and_then(|v| v.as_u64()),
        Some(0),
        "this workflow really has no execution rows — that is the point: {body}"
    );
    assert!(
        body.pointer("/success_rate/actual")
            .map(|v| !v.is_null())
            .unwrap_or(false),
        "with the ledger consulted the rate is measurable: {body}"
    );

    // The CONTROL for the other direction: a workflow with neither execution
    // rows nor child runs must still report the honest not-measured shape, so
    // this test cannot pass by making everything look measured.
    let barren = seed_workflow(&pool, user_id, None, r#"{"nodes":[],"edges":[]}"#).await;
    let body = text_json(
        &controller::mcp::analytics::dispatch(
            "get_workflow_sla_report",
            Some(serde_json::json!(2)),
            &serde_json::json!({ "workflow_id": barren.to_string() }),
            &state,
            agent(user_id),
        )
        .await
        .expect("dispatched"),
    );
    assert!(
        body.pointer("/success_rate/actual")
            .map(|v| v.is_null())
            .unwrap_or(true),
        "no evidence at all must stay unmeasured: {body}"
    );
}
