//! A node whose child reference makes its workflow run itself is refused
//! when it is written (security review 2026-10-14, G-2).
//!
//! The cross-workflow cycle walk ran only in the advisory
//! `validate_workflow`, and only `add_sub_workflow_node` refused a direct
//! self-reference. An `ensemble` whose child was its own workflow was stored,
//! and at run time fanned out `count` children per level until the depth
//! guard. `upsert_system_node` — the one helper behind every `add_*_node`
//! tool — now refuses a node that closes a cycle, before anything is saved.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

#[path = "common/mod.rs"]
mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use mcp_common::{agent, error_message, mcp_state};
use serde_json::{json, Value};
use sqlx::{Pool, Postgres};
use uuid::Uuid;

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(user)
    .bind(format!("{user}@cycle-gate.test"))
    .execute(pool)
    .await
    .expect("seed user");
    user
}

async fn graph_text(pool: &Pool<Postgres>, workflow: Uuid) -> String {
    sqlx::query_scalar("SELECT graph_json::text FROM workflows WHERE id = $1")
        .bind(workflow)
        .fetch_one(pool)
        .await
        .expect("workflow row")
}

async fn add_ensemble(
    state: &controller::mcp::McpState,
    user: Uuid,
    workflow: Uuid,
    child: Uuid,
) -> controller::mcp::types::JsonRpcResponse {
    controller::mcp::graph::dispatch(
        "add_ensemble_node",
        Some(json!(1)),
        &json!({
            "workflow_id": workflow.to_string(),
            "node_id": "fan_out",
            "child_workflow_id": child.to_string(),
            "count": 3,
            "consensus": "majority_vote",
        }),
        state,
        agent(user),
    )
    .await
    .expect("add_ensemble_node is dispatched")
}

fn refused(resp: &controller::mcp::types::JsonRpcResponse) -> bool {
    resp.error.is_some()
        || resp
            .result
            .as_ref()
            .and_then(|r| r.get("isError"))
            .and_then(Value::as_bool)
            == Some(true)
}

#[tokio::test]
async fn an_ensemble_of_its_own_workflow_is_refused_and_nothing_is_saved() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let a = common::create_test_workflow(&pool, user, "self-fan-out").await;
    let state = mcp_state(pool.clone()).await;
    let before = graph_text(&pool, a).await;

    let resp = add_ensemble(&state, user, a, a).await;
    assert!(refused(&resp), "A → A was stored: {resp:?}");
    assert!(error_message(&resp).contains("run itself"), "{resp:?}");
    assert_eq!(graph_text(&pool, a).await, before, "nothing was saved");
}

#[tokio::test]
async fn an_ensemble_that_reaches_its_workflow_through_another_is_refused() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let a = common::create_test_workflow(&pool, user, "cycle-a").await;
    let b = common::create_test_workflow(&pool, user, "cycle-b").await;
    let state = mcp_state(pool.clone()).await;

    // B → A is fine on its own…
    let resp = add_ensemble(&state, user, b, a).await;
    assert!(!refused(&resp), "B → A alone is not a cycle: {resp:?}");
    // …and A → B then closes A → B → A.
    let before = graph_text(&pool, a).await;
    let resp = add_ensemble(&state, user, a, b).await;
    assert!(refused(&resp), "A → B → A was stored: {resp:?}");
    assert_eq!(graph_text(&pool, a).await, before, "nothing was saved");
}
