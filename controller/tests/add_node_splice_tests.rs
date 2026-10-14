//! Every `add_*_node` tool puts its node ON the path it was asked to sit on
//! (2026-10-13).
//!
//! `add_<kind>_node(connect_from: "a", connect_to: "b")` on a workflow that
//! already had `a → b` used to leave that edge in place beside the two new
//! ones: the output went round the new node as well as through it, and a
//! repeat call added the same edges again. The shared helper now replaces
//! the edge, keeps its condition on the way into the node, and adds no edge
//! twice. Driven through three of the tools, covering both ways a handler
//! reports its wiring.
//!
//! `common` harness (a template clone per test), so the migrated-database
//! job runs it.

mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use mcp_common::{agent, mcp_state};
use serde_json::{json, Value};
use sqlx::{Pool, Postgres};
use std::sync::Arc;
use uuid::Uuid;

use controller::mcp::types::JsonRpcResponse;
use controller::mcp::McpState;

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'splice')",
    )
    .bind(id)
    .bind(format!("splice-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

/// `fetch → send`, conditional on `count > 0`.
async fn seed_workflow(pool: &Pool<Postgres>, user: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let graph = json!({
        "nodes": [
            { "id": "fetch", "type": "system:collect", "kind": "collect", "data": {} },
            { "id": "send", "type": "system:collect", "kind": "collect", "data": {} },
        ],
        "edges": [
            { "source": "fetch", "target": "send", "edge_type": "conditional", "condition": "count > 0" },
        ],
    });
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, graph_json, module_uri, status) \
         VALUES ($1, $2, $3, $4, 'talos://test-module', 'draft')",
    )
    .bind(id)
    .bind(user)
    .bind(format!("splice-{id}"))
    .bind(graph.to_string())
    .execute(pool)
    .await
    .expect("seed workflow");
    id
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

async fn edges(pool: &Pool<Postgres>, workflow: Uuid) -> Vec<(String, String, Option<String>)> {
    let text: String = sqlx::query_scalar("SELECT graph_json::text FROM workflows WHERE id = $1")
        .bind(workflow)
        .fetch_one(pool)
        .await
        .expect("workflow row");
    let graph: Value = serde_json::from_str(&text).unwrap();
    let mut edges: Vec<_> = graph["edges"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            (
                e["source"].as_str().unwrap_or_default().to_string(),
                e["target"].as_str().unwrap_or_default().to_string(),
                e["condition"].as_str().map(str::to_string),
            )
        })
        .collect();
    edges.sort();
    edges
}

fn reply_text(resp: &JsonRpcResponse) -> String {
    serde_json::to_string(&resp.result).unwrap_or_default()
}

async fn check(tool: &str, extra: Value) {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let workflow = seed_workflow(&pool, user).await;
    let state: Arc<McpState> = Arc::new(mcp_state(pool.clone()).await);
    let mut args = json!({ "workflow_id": workflow.to_string(), "node_id": "middle",
                           "connect_from": "fetch", "connect_to": "send" });
    for (k, v) in extra.as_object().unwrap() {
        args[k] = v.clone();
    }
    let call = || async {
        controller::mcp::graph::dispatch(tool, Some(json!(1)), &args, &state, agent(user))
            .await
            .unwrap_or_else(|| panic!("{tool} is dispatched"))
    };

    let resp = call().await;
    assert!(!refused(&resp), "{tool}: {resp:?}");
    let want = vec![
        // The condition reads `fetch`'s output, where it was written.
        (
            "fetch".to_string(),
            "middle".to_string(),
            Some("count > 0".to_string()),
        ),
        ("middle".to_string(), "send".to_string(), None),
    ];
    assert_eq!(
        edges(&pool, workflow).await,
        want,
        "{tool}: no way round the new node"
    );
    let said = reply_text(&resp);
    assert!(
        said.contains("Replaced existing edge"),
        "{tool} did not say what it replaced: {said}"
    );
    assert!(said.contains("fetch → send"), "{tool}: {said}");

    // The same call again does not double the wiring.
    let again = call().await;
    assert!(!refused(&again), "{tool}: {again:?}");
    assert_eq!(
        edges(&pool, workflow).await,
        want,
        "{tool}: a repeat call added edges"
    );
    assert!(
        !reply_text(&again).contains("Replaced existing edge"),
        "{tool}: nothing left to replace"
    );
}

#[tokio::test]
async fn a_wait_node_put_on_an_existing_edge_replaces_it() {
    check("add_wait_node", json!({ "message": "hold for the owner" })).await;
}

#[tokio::test]
async fn a_verify_node_put_on_an_existing_edge_replaces_it() {
    check("add_verify_node", json!({ "condition": "count > 0" })).await;
}

/// A tool whose reply is its own JSON body rather than the shared wiring
/// text: it says what it replaced too.
#[tokio::test]
async fn a_pending_approvals_node_put_on_an_existing_edge_replaces_it() {
    check("add_pending_approvals_node", json!({})).await;
}
