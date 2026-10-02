//! A `fuel_budget` that cannot be read is refused by every tool that takes
//! one (2026-10-02).
//!
//! Four tools take a budget: `compile_custom_sandbox`, `hot_update_module`,
//! `install_module_from_catalog` and `add_node_to_workflow` (inline source).
//! Each used to read it field by field with a default behind every field, so
//! `"fuel_per_byte": "40"` or a misspelled `byte_per_item` sized the module at
//! the defaults and said nothing. The reader itself is unit-tested in
//! `talos_compilation::scaffold`; this drives the four HANDLERS, because a
//! parser that refuses proves nothing about a call site that ignores it.
//!
//! Each refusal must come BEFORE any compile or write: these tests run with
//! no compiler and no catalog on disk, so a handler that reached either
//! would fail for a different reason, and the message is asserted.
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
    sqlx::query("INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'fuel')")
        .bind(id)
        .bind(format!("fuel-{id}@example.com"))
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
    .bind(format!("fuel-module-{id}"))
    .execute(pool)
    .await
    .expect("seed module");
    id
}

async fn module_count(pool: &Pool<Postgres>, user: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM modules WHERE user_id = $1")
        .bind(user)
        .fetch_one(pool)
        .await
        .expect("count")
}

const SOURCE: &str = "pub fn run(input: String) -> Result<String, String> { Ok(input) }";

/// The budgets a caller is most likely to get wrong, with the field each
/// refusal must name.
fn unreadable_budgets() -> Vec<(Value, &'static str)> {
    vec![
        (
            json!({"expected_items": 5, "fuel_per_byte": "40"}),
            "fuel_budget.fuel_per_byte",
        ),
        (
            json!({"expected_items": 5, "fuel_per_byte": 500}),
            "fuel_budget.fuel_per_byte",
        ),
        (json!({"expected_items": "5"}), "fuel_budget.expected_items"),
        (
            json!({"expected_items": 5, "byte_per_item": 60000}),
            "no field 'byte_per_item'",
        ),
        (
            json!({"safety_multiplier": 10}),
            "fuel_budget.safety_multiplier",
        ),
        (json!(5_000_000), "fuel_budget must be an object"),
    ]
}

#[tokio::test]
async fn every_tool_that_takes_a_budget_refuses_one_it_cannot_read() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let module = seed_module(&pool, user).await;
    let state = Arc::new(mcp_state(pool.clone()).await);

    // A workflow for `add_node_to_workflow` to add to.
    let created = controller::mcp::workflows::dispatch(
        "create_workflow",
        Some(json!(1)),
        &json!({
            "name": "fuel-budget-target",
            "include_config_suggestions": false,
            "nodes": [{"id": "a", "module_id": module.to_string()}],
            "edges": []
        }),
        state.clone(),
        agent(user),
    )
    .await
    .expect("create_workflow is dispatched");
    let workflow = text_json(&created)["workflow_id"]
        .as_str()
        .expect("created")
        .to_string();
    let modules_before = module_count(&pool, user).await;

    for (budget, names) in unreadable_budgets() {
        let compile = controller::mcp::sandbox::dispatch(
            "compile_custom_sandbox",
            Some(json!(1)),
            &json!({"name": "fuel-probe", "rust_code": SOURCE, "capability_world": "minimal-node", "fuel_budget": budget}),
            &state,
            agent(user),
        )
        .await
        .expect("compile_custom_sandbox is dispatched");
        let hot_update = controller::mcp::sandbox::dispatch(
            "hot_update_module",
            Some(json!(1)),
            &json!({"module_id": module.to_string(), "fuel_budget": budget}),
            &state,
            agent(user),
        )
        .await
        .expect("hot_update_module is dispatched");
        let install = controller::mcp::modules::dispatch(
            "install_module_from_catalog",
            Some(json!(1)),
            &json!({"name": "llm-inference", "dry_run": true, "fuel_budget": budget}),
            &state,
            agent(user),
        )
        .await
        .expect("install_module_from_catalog is dispatched");
        let add_node = controller::mcp::workflows::dispatch(
            "add_node_to_workflow",
            Some(json!(1)),
            &json!({"workflow_id": workflow, "node_id": "inline", "rust_code": SOURCE, "capability_world": "minimal-node", "fuel_budget": budget}),
            state.clone(),
            agent(user),
        )
        .await
        .expect("add_node_to_workflow is dispatched");

        for (tool, resp) in [
            ("compile_custom_sandbox", &compile),
            ("hot_update_module", &hot_update),
            ("install_module_from_catalog", &install),
            ("add_node_to_workflow", &add_node),
        ] {
            let refusal = error_message(resp);
            assert!(
                refusal.contains(names),
                "{tool} with fuel_budget {budget}: expected a refusal naming `{names}`, got: {refusal}"
            );
        }
    }

    // Nothing was compiled, installed or added along the way.
    assert_eq!(module_count(&pool, user).await, modules_before);
    let nodes: i64 = sqlx::query_scalar(
        "SELECT jsonb_array_length(graph_json::jsonb->'nodes')::bigint FROM workflows WHERE id = $1::uuid",
    )
    .bind(&workflow)
    .fetch_one(&pool)
    .await
    .expect("workflow row");
    assert_eq!(nodes, 1);
}

/// CONTROL: an explicit `null` is "no budget", not an unreadable one. A hot
/// update of a module that does not exist gets past the budget check and is
/// refused for the module, never for the budget.
#[tokio::test]
async fn a_null_budget_is_no_budget() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let state = Arc::new(mcp_state(pool.clone()).await);

    let resp = controller::mcp::sandbox::dispatch(
        "hot_update_module",
        Some(json!(1)),
        &json!({"module_id": Uuid::new_v4().to_string(), "fuel_budget": null}),
        &state,
        agent(user),
    )
    .await
    .expect("hot_update_module is dispatched");
    let refusal = error_message(&resp);
    assert!(!refusal.contains("fuel_budget"), "{refusal}");
}
