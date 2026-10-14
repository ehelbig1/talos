//! Putting an `action_links` node on a path that already exists (2026-10-13).
//!
//! `add_action_links_node(connect_from: "compose", connect_to: "phone")` on a
//! workflow whose last edge was `compose → phone` (conditional on
//! `notify == true`) left three edges: the old one, still there, so the
//! unminted message was sent as well; `compose → links`; and `links → phone`
//! with no condition. Calling the tool again for the same node id to change
//! its `targets` added the incoming edge a second time and replaced the
//! node, losing `continue_on_error`. And `create_workflow` could not create
//! the node inline at all.
//!
//! Driven through the real tool handlers against a real database.
//!
//! `common` harness (a template clone per test), so the migrated-database
//! job runs it.

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
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'wiring')",
    )
    .bind(id)
    .bind(format!("wiring-{id}@example.com"))
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
    .bind(format!("wiring-module-{id}"))
    .execute(pool)
    .await
    .expect("seed module");
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

fn refused(resp: &JsonRpcResponse) -> bool {
    resp.error.is_some()
        || resp
            .result
            .as_ref()
            .and_then(|r| r.get("isError"))
            .and_then(Value::as_bool)
            == Some(true)
}

/// `(source, target, condition)` of every stored edge, sorted.
fn edges_of(graph: &Value) -> Vec<(String, String, Option<String>)> {
    let mut edges: Vec<_> = graph["edges"]
        .as_array()
        .expect("edges")
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

fn no_edge_is_stored_twice(graph: &Value) {
    let edges = edges_of(graph);
    let mut pairs: Vec<_> = edges.iter().map(|(s, t, _)| (s, t)).collect();
    pairs.dedup();
    assert_eq!(
        pairs.len(),
        edges.len(),
        "an edge is stored twice: {edges:?}"
    );
}

struct Stack {
    pool: Pool<Postgres>,
    _db: common::TestDb,
    state: Arc<McpState>,
    me: Uuid,
    module: Uuid,
    /// A workflow of mine for links to start.
    target: Uuid,
}

async fn stack() -> Stack {
    let (pool, db) = common::isolated_db_pool().await;
    let me = seed_user(&pool).await;
    let module = seed_module(&pool, me).await;
    let state = Arc::new(mcp_state(pool.clone()).await);
    let mut s = Stack {
        pool,
        _db: db,
        state,
        me,
        module,
        target: Uuid::nil(),
    };
    s.target = create(&s, "the-target", json!([]), json!([])).await;
    s
}

async fn workflow_tool(s: &Stack, tool: &str, args: Value) -> JsonRpcResponse {
    controller::mcp::workflows::dispatch(tool, Some(json!(1)), &args, s.state.clone(), agent(s.me))
        .await
        .unwrap_or_else(|| panic!("{tool} is dispatched"))
}

async fn graph_tool(s: &Stack, tool: &str, args: Value) -> JsonRpcResponse {
    controller::mcp::graph::dispatch(tool, Some(json!(1)), &args, &s.state, agent(s.me))
        .await
        .unwrap_or_else(|| panic!("{tool} is dispatched"))
}

async fn create(s: &Stack, name: &str, nodes: Value, edges: Value) -> Uuid {
    let resp = workflow_tool(
        s,
        "create_workflow",
        json!({ "name": format!("{name}-{}", Uuid::new_v4().simple()),
                "include_config_suggestions": false, "nodes": nodes, "edges": edges }),
    )
    .await;
    assert!(!refused(&resp), "create_workflow: {resp:?}");
    text_json(&resp)["workflow_id"]
        .as_str()
        .expect("created")
        .parse()
        .unwrap()
}

/// `compose → phone`, with the given condition on the edge.
async fn compose_then_phone(s: &Stack, condition: Option<&str>) -> Uuid {
    let module = s.module.to_string();
    let mut edge = json!({ "source": "compose", "target": "phone" });
    if let Some(condition) = condition {
        edge["condition"] = json!(condition);
    }
    create(
        s,
        "notify",
        json!([{ "id": "compose", "module_id": module }, { "id": "phone", "module_id": module }]),
        json!([edge]),
    )
    .await
}

fn add_links(workflow: Uuid, target: Uuid) -> Value {
    json!({ "workflow_id": workflow.to_string(), "node_id": "links",
            "targets": { "list": target.to_string() },
            "connect_from": "compose", "connect_to": "phone" })
}

#[tokio::test]
async fn the_node_replaces_the_edge_it_is_put_on_and_the_condition_moves_with_it() {
    let s = stack().await;
    let wf = compose_then_phone(&s, Some("notify == true")).await;
    assert_eq!(
        edges_of(&stored_graph(&s.pool, wf).await),
        vec![(
            "compose".into(),
            "phone".into(),
            Some("notify == true".into())
        )]
    );

    let resp = graph_tool(&s, "add_action_links_node", add_links(wf, s.target)).await;
    assert!(!refused(&resp), "{resp:?}");
    let reply = text_json(&resp);
    assert_eq!(reply["updated_existing"], false);
    assert_eq!(
        reply["replaced_edges"].as_array().map(Vec::len),
        Some(1),
        "{reply}"
    );
    assert_eq!(reply["replaced_edges"][0]["condition"], "notify == true");

    let graph = stored_graph(&s.pool, wf).await;
    assert_eq!(
        edges_of(&graph),
        vec![
            // Into the node: plain. The message is always handed to it.
            ("compose".into(), "links".into(), None),
            // Out of the node: what the replaced edge said.
            (
                "links".into(),
                "phone".into(),
                Some("notify == true".into())
            ),
        ],
        "the unminted message has no other way to the send node"
    );
    no_edge_is_stored_twice(&graph);

    let validation = workflow_tool(
        &s,
        "validate_workflow",
        json!({ "workflow_id": wf.to_string() }),
    )
    .await;
    assert!(!refused(&validation), "{validation:?}");
    let text = serde_json::to_string(&validation.result)
        .unwrap()
        .to_lowercase();
    assert!(!text.contains("duplicate"), "validate_workflow: {text}");
}

#[tokio::test]
async fn a_plain_edge_is_replaced_by_two_plain_edges_and_no_edge_means_two_are_added() {
    let s = stack().await;
    let wf = compose_then_phone(&s, None).await;
    let resp = graph_tool(&s, "add_action_links_node", add_links(wf, s.target)).await;
    assert!(!refused(&resp), "{resp:?}");
    let graph = stored_graph(&s.pool, wf).await;
    assert_eq!(
        edges_of(&graph),
        vec![
            ("compose".into(), "links".into(), None),
            ("links".into(), "phone".into(), None)
        ]
    );
    no_edge_is_stored_twice(&graph);

    // Two nodes with no edge between them: as before, both edges are added
    // and nothing is reported as replaced.
    let module = s.module.to_string();
    let wf = create(
        &s,
        "unwired",
        json!([{ "id": "compose", "module_id": module }, { "id": "phone", "module_id": module }]),
        json!([]),
    )
    .await;
    let resp = graph_tool(&s, "add_action_links_node", add_links(wf, s.target)).await;
    assert!(!refused(&resp), "{resp:?}");
    assert_eq!(text_json(&resp)["replaced_edges"], json!([]));
    assert_eq!(
        edges_of(&stored_graph(&s.pool, wf).await),
        vec![
            ("compose".into(), "links".into(), None),
            ("links".into(), "phone".into(), None)
        ]
    );
}

#[tokio::test]
async fn calling_it_again_for_the_same_node_updates_its_targets_and_nothing_else() {
    let s = stack().await;
    let wf = compose_then_phone(&s, Some("notify == true")).await;
    let first = graph_tool(&s, "add_action_links_node", add_links(wf, s.target)).await;
    assert!(!refused(&first), "{first:?}");
    // The author marks the node: a failed mint must not stop the message.
    let flagged = graph_tool(
        &s,
        "set_continue_on_error",
        json!({ "workflow_id": wf.to_string(), "node_id": "links", "continue_on_error": true }),
    )
    .await;
    assert!(!refused(&flagged), "{flagged:?}");
    let before = stored_graph(&s.pool, wf).await;
    let flag_before = before["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["id"] == "links")
        .expect("links")["data"]["continue_on_error"]
        .clone();
    assert_eq!(flag_before, true, "{before}");

    // The same call, with a second target added.
    let second_target = create(&s, "second-target", json!([]), json!([])).await;
    let mut again = add_links(wf, s.target);
    again["targets"]["bills"] = json!(second_target.to_string());
    let resp = graph_tool(&s, "add_action_links_node", again).await;
    assert!(!refused(&resp), "{resp:?}");
    let reply = text_json(&resp);
    assert_eq!(reply["updated_existing"], true, "{reply}");
    assert_eq!(reply["added_edges"], json!([]));

    let after = stored_graph(&s.pool, wf).await;
    assert_eq!(
        edges_of(&after),
        edges_of(&before),
        "no edge was added or changed"
    );
    no_edge_is_stored_twice(&after);
    let node = after["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["id"] == "links")
        .expect("links");
    assert_eq!(
        node["data"]["continue_on_error"], true,
        "the node's flag survives"
    );
    assert_eq!(
        node["data"]["targets"],
        json!({ "list": s.target.to_string(), "bills": second_target.to_string() })
    );

    // The id of a node that is something else is not taken over.
    let resp = graph_tool(
        &s,
        "add_action_links_node",
        json!({ "workflow_id": wf.to_string(), "node_id": "compose",
                "targets": { "list": s.target.to_string() } }),
    )
    .await;
    assert!(refused(&resp), "{resp:?}");
    assert!(error_message(&resp).contains("is not an action-links node"));
    assert_eq!(stored_graph(&s.pool, wf).await, after);
}

#[tokio::test]
async fn create_workflow_makes_the_node_inline_under_the_same_rule() {
    let s = stack().await;
    let module = s.module.to_string();
    let nodes = |targets: Value| {
        json!([
            { "id": "compose", "module_id": module },
            { "id": "links", "node_type": "action_links", "targets": targets, "ttl_hours": 24 },
            { "id": "phone", "module_id": module },
        ])
    };
    let edges = json!([
        { "source": "compose", "target": "links" },
        { "source": "links", "target": "phone", "condition": "notify == true" },
    ]);

    let wf = create(
        &s,
        "inline",
        nodes(json!({ "list": s.target.to_string() })),
        edges.clone(),
    )
    .await;
    let graph = stored_graph(&s.pool, wf).await;
    let node = graph["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["id"] == "links")
        .expect("links");
    assert_eq!(node["type"], "system:action_links");
    assert_eq!(node["kind"], "action_links");
    assert_eq!(
        node["data"],
        json!({ "targets": { "list": s.target.to_string() }, "ttl_hours": 24 })
    );

    // The same refusals as every other way of writing the node.
    let stranger = seed_user(&s.pool).await;
    let foreign = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, graph_json, module_uri, status) \
         VALUES ($1, $2, 'not-mine', '{}', 'talos://test-module', 'draft')",
    )
    .bind(foreign)
    .bind(stranger)
    .execute(&s.pool)
    .await
    .expect("seed foreign workflow");
    let count = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM workflows WHERE user_id = $1")
            .bind(s.me)
            .fetch_one(&s.pool)
            .await
            .unwrap()
    };
    let before = count().await;
    for (what, targets, names) in [
        (
            "another user's workflow",
            json!({ "list": foreign.to_string() }),
            "'list'",
        ),
        ("a malformed id", json!({ "list": "nope" }), "'list'"),
        ("no entries", json!({}), "1 to 16"),
        (
            "a bad name",
            json!({ "a b": s.target.to_string() }),
            "not usable",
        ),
    ] {
        let resp = workflow_tool(
            &s,
            "create_workflow",
            json!({ "name": format!("inline-refused-{}", Uuid::new_v4().simple()),
                    "include_config_suggestions": false,
                    "nodes": nodes(targets), "edges": edges }),
        )
        .await;
        assert!(refused(&resp), "{what}: {resp:?}");
        let message = error_message(&resp);
        assert!(
            message.contains("'links'") && message.contains(names),
            "{what}: the refusal names the node and what is wrong: {message}"
        );
    }
    assert_eq!(count().await, before, "no workflow was created");
}
