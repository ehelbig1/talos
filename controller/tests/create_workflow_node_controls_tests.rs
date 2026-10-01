//! `create_workflow` writes a module node's controls (2026-10-01).
//!
//! A node object carried retry fields but not `skip_condition`,
//! `continue_on_error` or `timeout_secs`; set there, they were dropped without
//! a word. Driven through the real tool handlers against a real clone: the
//! controls land on the stored graph node where the engine reads them, a
//! malformed one is refused and nothing is created, and
//! `set_continue_on_error` answers to the name every other surface uses.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use mcp_common::{agent, error_message, mcp_state, text_json};
use serde_json::{json, Value};
use sqlx::{Pool, Postgres};
use std::sync::Arc;
use uuid::Uuid;

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'controls')",
    )
    .bind(id)
    .bind(format!("controls-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

async fn seed_module(pool: &Pool<Postgres>, user: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO modules (id, user_id, name, wasm_bytes, capability_world, kind) \
         VALUES ($1, $2, $3, '\\x00'::bytea, 'minimal-node', 'sandbox')",
    )
    .bind(id)
    .bind(user)
    .bind(format!("controls-module-{id}"))
    .execute(pool)
    .await
    .expect("seed module");
    id
}

async fn stored_nodes(pool: &Pool<Postgres>, workflow: Uuid) -> Vec<Value> {
    let graph: Value = sqlx::query_scalar("SELECT graph_json::jsonb FROM workflows WHERE id = $1")
        .bind(workflow)
        .fetch_one(pool)
        .await
        .expect("workflow row");
    graph["nodes"].as_array().expect("nodes").clone()
}

fn node<'a>(nodes: &'a [Value], id: &str) -> &'a Value {
    nodes
        .iter()
        .find(|n| n["id"] == id)
        .unwrap_or_else(|| panic!("node {id} is stored"))
}

/// A tool refusal lives INSIDE `result` (`isError: true`), not in the JSON-RPC
/// `error` member.
fn refused(resp: &controller::mcp::types::JsonRpcResponse) -> bool {
    resp.error.is_some()
        || resp
            .result
            .as_ref()
            .and_then(|r| r.get("isError"))
            .and_then(|v| v.as_bool())
            == Some(true)
}

async fn workflow_count(pool: &Pool<Postgres>, user: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM workflows WHERE user_id = $1")
        .bind(user)
        .fetch_one(pool)
        .await
        .expect("count")
}

#[tokio::test]
async fn a_module_nodes_controls_are_stored_where_the_engine_reads_them() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let module = seed_module(&pool, user).await.to_string();
    let state = Arc::new(mcp_state(pool.clone()).await);

    let args = json!({
        "name": "controls-fan-in",
        "include_config_suggestions": false,
        "nodes": [
            {"id": "left", "module_id": module, "config": {"SIDE": "l"}, "continue_on_error": true, "timeout_secs": 45, "retry_count": 2},
            {"id": "right", "module_id": module, "continue_on_error": false},
            {"id": "join", "node_type": "collect"},
            {"id": "work", "module_id": module, "skip_condition": "count == 0"},
            {"id": "plain", "module_id": module}
        ],
        "edges": [
            {"source": "left", "target": "join"}, {"source": "right", "target": "join"},
            {"source": "join", "target": "work"}, {"source": "work", "target": "plain"}
        ]
    });
    let resp = controller::mcp::workflows::dispatch(
        "create_workflow",
        Some(json!(1)),
        &args,
        state.clone(),
        agent(user),
    )
    .await
    .expect("create_workflow is dispatched");
    let body = text_json(&resp);
    let workflow: Uuid = body["workflow_id"]
        .as_str()
        .expect("created")
        .parse()
        .unwrap();

    let nodes = stored_nodes(&pool, workflow).await;
    let left = node(&nodes, "left");
    assert_eq!(
        (
            left["continue_on_error"].as_bool(),
            left["timeout_secs"].as_u64(),
            left["retry_count"].as_u64()
        ),
        (Some(true), Some(45), Some(2))
    );
    assert_eq!(
        left["data"],
        json!({"SIDE": "l"}),
        "the module's own config is left alone"
    );
    assert_eq!(node(&nodes, "right")["continue_on_error"], false);
    assert_eq!(node(&nodes, "work")["skip_condition"], "count == 0");
    let plain = node(&nodes, "plain");
    for key in ["skip_condition", "continue_on_error", "timeout_secs"] {
        assert!(
            plain.get(key).is_none(),
            "a node that set no `{key}` stores none"
        );
    }

    // The engine's own loader reads them from there.
    let graph_json: String =
        sqlx::query_scalar("SELECT graph_json::text FROM workflows WHERE id = $1")
            .bind(workflow)
            .fetch_one(&pool)
            .await
            .unwrap();
    let rendered = controller::mcp::workflows::dispatch(
        "get_workflow",
        Some(json!(2)),
        &json!({"workflow_id": workflow.to_string()}),
        state.clone(),
        agent(user),
    )
    .await
    .expect("get_workflow is dispatched");
    let view = text_json(&rendered);
    let view_nodes = view["nodes"].as_array().expect("nodes in the view");
    assert_eq!(
        node(view_nodes, "left")["continue_on_error"],
        true,
        "the read tool shows the flag: {graph_json}"
    );
    assert_eq!(node(view_nodes, "work")["skip_condition"], "count == 0");

    // set_continue_on_error answers to the name every other surface uses.
    let set = controller::mcp::graph::dispatch(
        "set_continue_on_error",
        Some(json!(3)),
        &json!({"workflow_id": workflow.to_string(), "node_id": "plain", "continue_on_error": true}),
        state.as_ref(),
        agent(user),
    )
    .await
    .expect("set_continue_on_error is dispatched");
    assert!(!refused(&set), "the alias is accepted: {:?}", set.result);
    let after = stored_nodes(&pool, workflow).await;
    let plain = node(&after, "plain");
    let flagged = plain["continue_on_error"] == true || plain["data"]["continue_on_error"] == true;
    assert!(flagged, "the flag was written: {plain}");
    // Neither spelling: still a named refusal.
    let neither = controller::mcp::graph::dispatch(
        "set_continue_on_error",
        Some(json!(4)),
        &json!({"workflow_id": workflow.to_string(), "node_id": "plain"}),
        state.as_ref(),
        agent(user),
    )
    .await
    .expect("dispatched");
    assert!(refused(&neither) && error_message(&neither).contains("'enabled'"));
}

#[tokio::test]
async fn a_malformed_control_is_refused_and_nothing_is_created() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let module = seed_module(&pool, user).await.to_string();
    let state = Arc::new(mcp_state(pool.clone()).await);

    // The last three are the canonical per-node caps. Every graph MUTATION
    // tool already ran them; `create_workflow` inserted its graph without, so
    // a day-long node timeout or `retry_count: 9000` was storable here and
    // nowhere else.
    let cases: [(Value, &str); 8] = [
        (
            json!({"id": "n", "module_id": module, "continue_on_error": "true"}),
            "continue_on_error must be true or false",
        ),
        (
            json!({"id": "n", "module_id": module, "timeout_secs": 0}),
            "timeout_secs must be a whole number",
        ),
        (
            json!({"id": "n", "module_id": module, "skip_condition": "count == "}),
            "node 'n'",
        ),
        (
            json!({"id": "n", "module_id": module, "continue_on_error": true, "config": {"continue_on_error": false}}),
            "set it once",
        ),
        (
            json!({"id": "n", "node_type": "collect", "continue_on_error": true}),
            "set_continue_on_error",
        ),
        (
            json!({"id": "n", "module_id": module, "timeout_secs": 86400}),
            "per-node cap",
        ),
        (
            json!({"id": "n", "module_id": module, "config": {"timeout_secs": 86400}}),
            "per-node cap",
        ),
        (
            json!({"id": "n", "module_id": module, "retry_count": 9000}),
            "retry_count",
        ),
    ];
    for (bad_node, want) in cases {
        let args = json!({"name": format!("controls-bad-{}", Uuid::new_v4()), "include_config_suggestions": false, "nodes": [bad_node.clone()]});
        let resp = controller::mcp::workflows::dispatch(
            "create_workflow",
            Some(json!(1)),
            &args,
            state.clone(),
            agent(user),
        )
        .await
        .expect("dispatched");
        assert!(refused(&resp), "{bad_node} was accepted: {:?}", resp.result);
        let message = error_message(&resp);
        assert!(message.contains(want), "{bad_node} → {message}");
    }
    assert_eq!(
        workflow_count(&pool, user).await,
        0,
        "a refused create leaves no workflow behind"
    );

    // Control: the same node without the bad field is created.
    let args = json!({"name": "controls-good", "include_config_suggestions": false, "nodes": [{"id": "n", "module_id": module}]});
    let resp = controller::mcp::workflows::dispatch(
        "create_workflow",
        Some(json!(1)),
        &args,
        state,
        agent(user),
    )
    .await
    .expect("dispatched");
    assert!(!refused(&resp), "{:?}", resp.result);
    assert_eq!(workflow_count(&pool, user).await, 1);
}
