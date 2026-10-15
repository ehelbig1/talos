//! Every graph writer passes the same gates (security review 2026-10-14,
//! package 12: G-7, G-10, G-11, G-26).
//!
//! Driven through the real MCP tool handlers against a database:
//!
//! * `duplicate_workflow` / `promote_workflow` are held to what
//!   `update_node_config` holds a config to — the per-node caps (with
//!   `update_node_config`'s own words), a patch lands in the node's `data`
//!   only, `__` keys dropped, a `skip_condition` parsed, `modifications`
//!   capped at 1 MB (G-11).
//! * The whole-graph writers run `validate_graph_structure`: a cycle and a
//!   501-node graph are refused; an import WARNS on a `skip_condition` that
//!   does not parse (G-26).
//! * `import_platform_state` holds a schedule to every schedule tool's checks,
//!   counts only what it wrote, and never replaces a valid schedule with an
//!   invalid one (G-10).
//! * An `expression_dispatch` node's declared `targets` are the owner's, by
//!   the action-link rule, on every writer (G-7, the write half; the run half
//!   is `talos-workflow-engine/tests/expression_dispatch_declared_targets.rs`).
//!
//! `common` harness (a template clone per test), so the migrated-database job
//! runs it. The binary sets `TALOS_RLS_SET_ROLE` off itself, for the reason
//! `action_link_targets_writer_tests` records: under `talos_app` the
//! `workflows` policy hides another user's row before the ownership
//! predicate this file pins is consulted.

mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use mcp_common::{agent, error_message, mcp_state, text_json};
use serde_json::{json, Value};
use sqlx::{Pool, Postgres};
use std::sync::Arc;
use uuid::Uuid;

use controller::mcp::types::JsonRpcResponse;
use controller::mcp::McpState;

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'gates')")
        .bind(id)
        .bind(format!("gates-{id}@example.com"))
        .execute(pool)
        .await
        .expect("seed user");
    id
}

/// A workflow row written by SQL, so a test can hold a graph no tool would
/// now store.
async fn seed_workflow(pool: &Pool<Postgres>, user: Uuid, name: &str, graph: &Value) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, graph_json, module_uri, status) \
         VALUES ($1, $2, $3, $4, 'talos://test-module', 'draft')",
    )
    .bind(id)
    .bind(user)
    .bind(format!("{name}-{id}"))
    .bind(graph.to_string())
    .execute(pool)
    .await
    .expect("seed workflow");
    id
}

async fn stored_graph(pool: &Pool<Postgres>, workflow: Uuid) -> Value {
    let text: String = sqlx::query_scalar("SELECT graph_json::text FROM workflows WHERE id = $1")
        .bind(workflow)
        .fetch_one(pool)
        .await
        .expect("workflow row");
    serde_json::from_str(&text).expect("stored graph is JSON")
}

async fn workflow_count(pool: &Pool<Postgres>, user: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM workflows WHERE user_id = $1")
        .bind(user)
        .fetch_one(pool)
        .await
        .expect("count")
}

fn refused(resp: &JsonRpcResponse) -> bool {
    resp.error.is_some()
        || resp
            .result
            .as_ref()
            .and_then(|r| r.get("isError"))
            .and_then(Value::as_bool)
            == Some(true)
}

fn leave_row_security_unenforced() {
    std::env::set_var("TALOS_RLS_SET_ROLE", "0");
}

struct Stack {
    pool: Pool<Postgres>,
    _db: common::TestDb,
    state: Arc<McpState>,
    me: Uuid,
    /// A workflow of mine: a legitimate dispatch target.
    own: Uuid,
    /// Another user's workflow.
    foreign: Uuid,
}

async fn stack() -> Stack {
    leave_row_security_unenforced();
    let (pool, db) = common::isolated_db_pool().await;
    let me = seed_user(&pool).await;
    let other = seed_user(&pool).await;
    let empty = json!({ "nodes": [], "edges": [] });
    let own = seed_workflow(&pool, me, "own-target", &empty).await;
    let foreign = seed_workflow(&pool, other, "foreign-target", &empty).await;
    let state = Arc::new(mcp_state(pool.clone()).await);
    Stack {
        pool,
        _db: db,
        state,
        me,
        own,
        foreign,
    }
}

async fn graph_tool(s: &Stack, tool: &str, args: Value) -> JsonRpcResponse {
    controller::mcp::graph::dispatch(tool, Some(json!(1)), &args, &s.state, agent(s.me))
        .await
        .unwrap_or_else(|| panic!("{tool} is dispatched"))
}

async fn workflow_tool(s: &Stack, tool: &str, args: Value) -> JsonRpcResponse {
    controller::mcp::workflows::dispatch(tool, Some(json!(1)), &args, s.state.clone(), agent(s.me))
        .await
        .unwrap_or_else(|| panic!("{tool} is dispatched"))
}

async fn advanced_tool(s: &Stack, tool: &str, args: Value) -> JsonRpcResponse {
    controller::mcp::advanced::dispatch(tool, Some(json!(1)), &args, &s.state, agent(s.me))
        .await
        .unwrap_or_else(|| panic!("{tool} is dispatched"))
}

async fn platform_tool(s: &Stack, tool: &str, args: Value) -> JsonRpcResponse {
    controller::mcp::platform::dispatch(tool, Some(json!(1)), &args, &s.state, agent(s.me))
        .await
        .unwrap_or_else(|| panic!("{tool} is dispatched"))
}

/// A module node (its `type` names a module that need not exist: nothing
/// here dispatches), with `data` when given.
fn module_node(id: &str, data: Option<Value>) -> Value {
    let mut node = json!({ "id": id, "type": Uuid::new_v4().to_string(),
                           "position": { "x": 0, "y": 0 } });
    if let Some(data) = data {
        node["data"] = data;
    }
    node
}

/// What `update_node_config(update_config)` says when it is given `config`
/// for `node` in a workflow holding `graph`. The words every other writer of
/// the same values must give.
async fn update_node_config_refusal(s: &Stack, graph: &Value, node: &str, config: Value) -> String {
    let wf = seed_workflow(&s.pool, s.me, "reference", graph).await;
    let resp = graph_tool(
        s,
        "update_node_config",
        json!({ "workflow_id": wf.to_string(), "node_id": node, "action": "update_config",
                "config": config }),
    )
    .await;
    assert!(
        refused(&resp),
        "update_node_config accepted {config}: {resp:?}"
    );
    error_message(&resp)
}

// ── duplicate_workflow (G-11) ───────────────────────────────────────────────

#[tokio::test]
async fn a_duplicate_with_timeout_secs_86400_is_refused_with_update_node_configs_message() {
    let s = stack().await;
    let graph = json!({ "nodes": [module_node("send", Some(json!({ "to": "x@example.com" })))],
                        "edges": [] });
    let patch = json!({ "timeout_secs": 86_400, "enforce_timeout": true });
    let expected = update_node_config_refusal(&s, &graph, "send", patch.clone()).await;

    let source = seed_workflow(&s.pool, s.me, "source", &graph).await;
    let before = workflow_count(&s.pool, s.me).await;
    let resp = graph_tool(
        &s,
        "duplicate_workflow",
        json!({ "workflow_id": source.to_string(),
                "modifications": { "patch_node_configs": { "send": patch } } }),
    )
    .await;
    assert!(
        refused(&resp),
        "a duplicate stored timeout_secs 86400: {resp:?}"
    );
    assert_eq!(error_message(&resp), expected);
    assert_eq!(
        workflow_count(&s.pool, s.me).await,
        before,
        "nothing is created"
    );
}

/// A node with no `data` took the patch at NODE level, so a patched `type`
/// repointed it. A patch now lands in `data` only: the node's `type` and
/// `kind` stay the source's, and a patched value is checked where the engine
/// reads it — `retry_count: 4000000000` is refused with `update_node_config`'s
/// words.
#[tokio::test]
async fn a_patched_type_lands_in_the_config_only_and_a_patched_retry_count_is_refused() {
    let s = stack().await;
    let bare = module_node("bare", None);
    let original_type = bare["type"].clone();
    let graph = json!({ "nodes": [bare], "edges": [] });
    let source = seed_workflow(&s.pool, s.me, "source", &graph).await;

    let resp = graph_tool(
        &s,
        "duplicate_workflow",
        json!({ "workflow_id": source.to_string(),
                "modifications": { "patch_node_configs": { "bare":
                    { "type": "system:collect", "kind": "collect", "note": "hi" } } } }),
    )
    .await;
    assert!(!refused(&resp), "{resp:?}");
    let copy = Uuid::parse_str(text_json(&resp)["workflow_id"].as_str().unwrap()).unwrap();
    let node = &stored_graph(&s.pool, copy).await["nodes"][0];
    assert_eq!(
        node["type"], original_type,
        "the node's type was repointed: {node}"
    );
    assert!(
        node.get("kind").is_none(),
        "a kind was set on the node: {node}"
    );
    assert_eq!(node["data"]["type"], "system:collect", "{node}");
    assert_eq!(node["data"]["note"], "hi", "{node}");

    let patch = json!({ "retry_count": 4_000_000_000u64 });
    let expected = update_node_config_refusal(&s, &graph, "bare", patch.clone()).await;
    let before = workflow_count(&s.pool, s.me).await;
    let resp = graph_tool(
        &s,
        "duplicate_workflow",
        json!({ "workflow_id": source.to_string(),
                "modifications": { "patch_node_configs": { "bare": patch } } }),
    )
    .await;
    assert!(
        refused(&resp),
        "a duplicate stored retry_count 4e9: {resp:?}"
    );
    assert_eq!(error_message(&resp), expected);
    assert_eq!(workflow_count(&s.pool, s.me).await, before);
}

#[tokio::test]
async fn a_duplicate_patch_is_held_to_update_node_configs_config_rules() {
    let s = stack().await;
    let graph = json!({ "nodes": [module_node("send", Some(json!({})))], "edges": [] });
    let source = seed_workflow(&s.pool, s.me, "source", &graph).await;

    // A skip_condition that does not parse is refused, as update_node_config
    // refuses it.
    let resp = graph_tool(
        &s,
        "duplicate_workflow",
        json!({ "workflow_id": source.to_string(),
                "modifications": { "patch_node_configs": { "send": { "skip_condition": "!!!(" } } } }),
    )
    .await;
    assert!(refused(&resp), "{resp:?}");
    assert!(error_message(&resp).contains("skip_condition"), "{resp:?}");

    // An engine-internal key is dropped, not stored.
    let resp = graph_tool(
        &s,
        "duplicate_workflow",
        json!({ "workflow_id": source.to_string(),
                "modifications": { "patch_node_configs": { "send":
                    { "__skip_condition": "true", "to": "y@example.com" } } } }),
    )
    .await;
    assert!(!refused(&resp), "{resp:?}");
    let copy = Uuid::parse_str(text_json(&resp)["workflow_id"].as_str().unwrap()).unwrap();
    let data = &stored_graph(&s.pool, copy).await["nodes"][0]["data"];
    assert!(data.get("__skip_condition").is_none(), "{data}");
    assert_eq!(data["to"], "y@example.com");
}

#[tokio::test]
async fn a_2_mb_modifications_is_refused() {
    let s = stack().await;
    let graph = json!({ "nodes": [module_node("send", Some(json!({})))], "edges": [] });
    let source = seed_workflow(&s.pool, s.me, "source", &graph).await;
    let before = workflow_count(&s.pool, s.me).await;
    let resp = graph_tool(
        &s,
        "duplicate_workflow",
        json!({ "workflow_id": source.to_string(),
                "modifications": { "patch_node_configs": { "send":
                    { "blob": "x".repeat(2 * 1024 * 1024) } } } }),
    )
    .await;
    assert!(refused(&resp), "{resp:?}");
    assert_eq!(
        error_message(&resp),
        "input payload must be ≤ 1 MB when serialized"
    );
    assert_eq!(workflow_count(&s.pool, s.me).await, before);
}

// ── promote_workflow (G-11) ─────────────────────────────────────────────────

#[tokio::test]
async fn a_promote_with_retry_count_9000_is_refused_with_update_node_configs_message() {
    let s = stack().await;
    let graph = json!({ "nodes": [module_node("send", Some(json!({ "label": "send" })))],
                        "edges": [] });
    let expected = update_node_config_refusal(
        &s,
        &graph,
        "send",
        json!({ "label": "send", "retry_count": 9000 }),
    )
    .await;
    let source = seed_workflow(&s.pool, s.me, "source", &graph).await;
    let before = workflow_count(&s.pool, s.me).await;
    let resp = advanced_tool(
        &s,
        "promote_workflow",
        json!({ "workflow_id": source.to_string(), "publish": false,
                "config_overrides": { "send": { "retry_count": 9000 } } }),
    )
    .await;
    assert!(
        refused(&resp),
        "a promote stored retry_count 9000: {resp:?}"
    );
    assert_eq!(error_message(&resp), expected);
    assert_eq!(workflow_count(&s.pool, s.me).await, before);

    // An override's skip_condition is parsed too.
    let resp = advanced_tool(
        &s,
        "promote_workflow",
        json!({ "workflow_id": source.to_string(), "publish": false,
                "config_overrides": { "send": { "skip_condition": "!!!(" } } }),
    )
    .await;
    assert!(refused(&resp), "{resp:?}");
    assert_eq!(workflow_count(&s.pool, s.me).await, before);
}

// ── whole-graph writers: structure (G-26) ───────────────────────────────────

fn chain(n: usize) -> Value {
    let nodes: Vec<Value> = (0..n)
        .map(|i| json!({ "id": format!("n{i}"), "type": "noop", "data": {} }))
        .collect();
    json!({ "nodes": nodes, "edges": [] })
}

#[tokio::test]
async fn an_import_with_a_cycle_or_501_nodes_is_refused_and_creates_nothing() {
    let s = stack().await;
    let cycle = json!({
        "nodes": [ { "id": "a", "type": "noop", "data": {} }, { "id": "b", "type": "noop", "data": {} } ],
        "edges": [ { "source": "a", "target": "b" }, { "source": "b", "target": "a" } ],
    });
    for (what, graph, words) in [
        ("a cycle", cycle, "cycle"),
        ("501 nodes", chain(501), "Workflow exceeds 500 node limit"),
    ] {
        let before = workflow_count(&s.pool, s.me).await;
        let resp = workflow_tool(
            &s,
            "import_workflow",
            json!({ "bundle": { "name": "imported", "graph_json": graph } }),
        )
        .await;
        assert!(refused(&resp), "import stored {what}: {resp:?}");
        assert!(error_message(&resp).contains(words), "{what}: {resp:?}");
        assert_eq!(workflow_count(&s.pool, s.me).await, before, "{what}");
    }
}

#[tokio::test]
async fn a_yaml_import_with_a_cycle_is_refused() {
    let s = stack().await;
    let yaml =
        "name: yaml-cycle\nnodes:\n  - id: a\n    module: noop\n  - id: b\n    module: noop\n\
                edges:\n  - from: a\n    to: b\n  - from: b\n    to: a\n";
    let before = workflow_count(&s.pool, s.me).await;
    let resp = workflow_tool(&s, "import_yaml_workflow", json!({ "yaml": yaml })).await;
    assert!(refused(&resp), "{resp:?}");
    assert!(error_message(&resp).contains("cycle"), "{resp:?}");
    assert_eq!(workflow_count(&s.pool, s.me).await, before);
}

/// I-6 (security review 2026-10-14): a YAML import of 501 nodes is refused
/// with `create_workflow`'s sentence, and nothing is stored.
#[tokio::test]
async fn a_yaml_import_of_501_nodes_is_refused_with_the_create_message() {
    let s = stack().await;
    let mut yaml = String::from("name: yaml-large\nnodes:\n");
    for i in 0..501 {
        yaml.push_str(&format!("  - id: n{i}\n    module: noop\n"));
    }
    let before = workflow_count(&s.pool, s.me).await;
    let resp = workflow_tool(&s, "import_yaml_workflow", json!({ "yaml": yaml })).await;
    assert!(refused(&resp), "{resp:?}");
    assert!(
        error_message(&resp).contains("Workflow exceeds 500 node limit"),
        "{resp:?}"
    );
    assert_eq!(workflow_count(&s.pool, s.me).await, before);
}

/// The documented import stance: an expression already live in an export is
/// restorable. It is imported, and the response says it will not gate.
#[tokio::test]
async fn an_import_warns_on_a_skip_condition_that_does_not_parse() {
    let s = stack().await;
    let graph = json!({ "nodes": [ { "id": "send", "type": "noop",
                                     "data": { "skip_condition": "!!!(" } } ], "edges": [] });
    let resp = workflow_tool(
        &s,
        "import_workflow",
        json!({ "bundle": { "name": "imported", "graph_json": graph } }),
    )
    .await;
    assert!(!refused(&resp), "{resp:?}");
    let body = text_json(&resp);
    let warnings = body["warnings"].as_array().expect("warnings");
    assert!(
        warnings[0]
            .as_str()
            .unwrap()
            .starts_with("node 'send': skip_condition"),
        "{body}"
    );
}

// ── import_platform_state schedules (G-10) ──────────────────────────────────

async fn import_manifest(s: &Stack, name: &str, schedule: Value) -> Value {
    let resp = platform_tool(
        s,
        "import_platform_state",
        json!({ "manifest": { "version": 2, "workflows": [
            { "name": name, "graph_json": { "nodes": [], "edges": [] }, "schedule": schedule }
        ] } }),
    )
    .await;
    assert!(!refused(&resp), "{resp:?}");
    text_json(&resp)
}

async fn stored_schedule(
    pool: &Pool<Postgres>,
    user: Uuid,
    name: &str,
) -> Option<(String, String, bool)> {
    sqlx::query_as::<_, (String, String, bool)>(
        "SELECT ws.cron_expression, ws.timezone, ws.next_trigger_at IS NOT NULL \
         FROM workflow_schedules ws JOIN workflows w ON w.id = ws.workflow_id \
         WHERE w.user_id = $1 AND w.name = $2",
    )
    .bind(user)
    .bind(name)
    .fetch_optional(pool)
    .await
    .expect("read schedule")
}

#[tokio::test]
async fn an_imported_schedule_is_held_to_the_schedule_tools_checks() {
    let s = stack().await;
    let name = "imported-schedule";

    // A valid schedule is imported and is due without the start-up backfill.
    let out = import_manifest(&s, name, json!({ "cron_expression": "0 9 * * *" })).await;
    assert_eq!(out["imported_schedules"], 1, "{out}");
    assert_eq!(
        stored_schedule(&s.pool, s.me, name).await,
        Some(("0 9 * * *".to_string(), "UTC".to_string(), true))
    );

    // A seconds field and an unknown timezone: each a warning, nothing
    // counted, and the valid schedule already there is kept.
    for (what, schedule) in [
        (
            "a seconds field",
            json!({ "cron_expression": "* * * * * *" }),
        ),
        (
            "an unknown timezone",
            json!({ "cron_expression": "0 10 * * *", "timezone": "Mars/Olympus_Mons" }),
        ),
    ] {
        let out = import_manifest(&s, name, schedule).await;
        assert_eq!(out["imported_schedules"], 0, "{what}: {out}");
        let warnings = out["warnings"].to_string();
        assert!(warnings.contains("schedule not imported"), "{what}: {out}");
        assert_eq!(
            stored_schedule(&s.pool, s.me, name).await,
            Some(("0 9 * * *".to_string(), "UTC".to_string(), true)),
            "{what}: the live schedule was replaced"
        );
    }
}

// ── expression_dispatch declared targets, the write half (G-7) ──────────────

fn dispatch_node(id: &str, targets: Option<Value>) -> Value {
    let mut data = json!({ "dispatch_expression": "inputs.route", "timeout_secs": 30 });
    if let Some(t) = targets {
        data["targets"] = t;
    }
    json!({ "id": id, "type": "system:dispatch", "kind": "dispatch", "data": data,
            "position": { "x": 0, "y": 0 } })
}

#[tokio::test]
async fn add_expression_dispatch_node_stores_only_the_callers_own_targets() {
    let s = stack().await;
    let mut answers = Vec::new();
    for id in [s.foreign, Uuid::new_v4()] {
        let wf = seed_workflow(&s.pool, s.me, "host", &json!({ "nodes": [], "edges": [] })).await;
        let resp = graph_tool(
            &s,
            "add_expression_dispatch_node",
            json!({ "workflow_id": wf.to_string(), "node_id": "route",
                    "dispatch_expression": "inputs.route", "targets": [id.to_string()] }),
        )
        .await;
        assert!(
            refused(&resp),
            "stored a target that is not the caller's: {resp:?}"
        );
        assert_eq!(stored_graph(&s.pool, wf).await["nodes"], json!([]));
        answers.push(error_message(&resp).replace(&id.to_string(), "<id>"));
    }
    assert_eq!(
        answers[0], answers[1],
        "a refusal must not say whether another user's workflow exists"
    );
    assert!(
        answers[0].contains("'route'"),
        "the node is named: {}",
        answers[0]
    );

    let wf = seed_workflow(&s.pool, s.me, "host", &json!({ "nodes": [], "edges": [] })).await;
    let resp = graph_tool(
        &s,
        "add_expression_dispatch_node",
        json!({ "workflow_id": wf.to_string(), "node_id": "route",
                "dispatch_expression": "inputs.route", "targets": [s.own.to_string()] }),
    )
    .await;
    assert!(!refused(&resp), "{resp:?}");
    assert_eq!(
        stored_graph(&s.pool, wf).await["nodes"][0]["data"]["targets"],
        json!([s.own.to_string()])
    );
}

/// Every writer holds the declaration to the same rule, not only the
/// dedicated tool: a config edit, an import, a malformed list.
#[tokio::test]
async fn every_graph_writer_refuses_a_foreign_or_malformed_dispatch_target() {
    let s = stack().await;
    let wf = seed_workflow(
        &s.pool,
        s.me,
        "host",
        &json!({ "nodes": [dispatch_node("route", Some(json!([s.own.to_string()])))], "edges": [] }),
    )
    .await;
    for (what, targets) in [
        ("another user's workflow", json!([s.foreign.to_string()])),
        ("a string where a list belongs", json!("everything")),
        ("no entries", json!([])),
    ] {
        let resp = graph_tool(
            &s,
            "update_node_config",
            json!({ "workflow_id": wf.to_string(), "node_id": "route", "action": "merge_config",
                    "config": { "targets": targets } }),
        )
        .await;
        assert!(refused(&resp), "update_node_config stored {what}: {resp:?}");
        assert!(error_message(&resp).contains("'route'"), "{what}: {resp:?}");
        assert_eq!(
            stored_graph(&s.pool, wf).await["nodes"][0]["data"]["targets"],
            json!([s.own.to_string()]),
            "{what}: the stored declaration is unchanged"
        );
    }

    let before = workflow_count(&s.pool, s.me).await;
    let resp = workflow_tool(
        &s,
        "import_workflow",
        json!({ "bundle": { "name": "imported", "graph_json":
            { "nodes": [dispatch_node("route", Some(json!([s.foreign.to_string()])))], "edges": [] } } }),
    )
    .await;
    assert!(
        refused(&resp),
        "import stored a foreign dispatch target: {resp:?}"
    );
    assert_eq!(workflow_count(&s.pool, s.me).await, before);

    // An undeclared node (the legacy reading) is still written.
    let resp = workflow_tool(
        &s,
        "import_workflow",
        json!({ "bundle": { "name": "imported", "graph_json":
            { "nodes": [dispatch_node("route", None)], "edges": [] } } }),
    )
    .await;
    assert!(!refused(&resp), "{resp:?}");
}

/// G2-2 (2026-10-15): a node naming its own workflow as a child is refused by
/// every graph UPDATE, not only by the `add_*_node` tools —
/// `update_node_config` here, the repository rule behind it
/// (`graph_caps::refuse_self_reference`) for the rest. The stored graph is
/// unchanged.
#[tokio::test]
async fn a_node_naming_its_own_workflow_as_a_child_is_refused_by_update_node_config() {
    let s = stack().await;
    let graph = json!({
        "nodes": [{ "id": "fanout", "kind": "ensemble", "type": "system:ensemble",
                    "position": { "x": 0, "y": 0 }, "data": { "label": "fanout" } }],
        "edges": [],
    });
    let wf = seed_workflow(&s.pool, s.me, "self-ref", &graph).await;
    let before = stored_graph(&s.pool, wf).await;
    let resp = graph_tool(
        &s,
        "update_node_config",
        json!({ "workflow_id": wf.to_string(), "node_id": "fanout", "action": "update_config",
                "config": { "child_workflow_id": wf.to_string() } }),
    )
    .await;
    assert!(refused(&resp), "a self-reference was stored: {resp:?}");
    assert_eq!(stored_graph(&s.pool, wf).await, before, "no graph change");

    // Another workflow of the same user is a legitimate child.
    let resp = graph_tool(
        &s,
        "update_node_config",
        json!({ "workflow_id": wf.to_string(), "node_id": "fanout", "action": "update_config",
                "config": { "child_workflow_id": s.own.to_string() } }),
    )
    .await;
    assert!(!refused(&resp), "{resp:?}");
}

/// G2-5 (2026-10-15): a node id beginning with `__` names the engine's own
/// records and is refused at write — an import of such a graph creates
/// nothing.
#[tokio::test]
async fn a_node_id_naming_an_engine_record_is_refused_at_write() {
    let s = stack().await;
    let before = workflow_count(&s.pool, s.me).await;
    let resp = workflow_tool(
        &s,
        "import_workflow",
        json!({ "bundle": { "name": "reserved-id", "graph_json": {
            "nodes": [module_node("__child_runs__", None)], "edges": [] } } }),
    )
    .await;
    assert!(refused(&resp), "{resp:?}");
    assert_eq!(
        workflow_count(&s.pool, s.me).await,
        before,
        "nothing created"
    );
}
