//! `create_workflow_from_spec` compiles through the gates every other compile
//! path runs (2026-09-25).
//!
//! Before this the spec path compiled at the caller-named world with no role
//! gate, gave every network-capable world `allowed_hosts = ["*"]`, and on a
//! taken name OVERWROTE the existing module's WASM, world, hosts and secrets
//! through an UPDATE with no owner predicate and no audit record. Its explicit
//! `module_id` path also accepted any tenant's module UUID.
//!
//! These drive the REAL MCP handler and the REAL `InlineCompileService`, and
//! read every outcome back from the tables. None needs a WASM toolchain: each
//! refusal happens BEFORE the compile, and the persist half is driven with
//! `CompiledInline::prebuilt_for_tests` (the `test-support` feature).
//!
//! CI: `scripts/test-integration.sh` **CTRL_TESTS** (`common` harness ⇒ needs
//! `DATABASE_URL`, sub-leg 64b).

#[path = "common/mod.rs"]
mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use std::sync::Arc;

use controller::mcp::auth::AgentIdentity;
use mcp_common::{agent, error_message, mcp_state, text_json};
use talos_inline_compile_service::{
    CompiledInline, InlineCompileError, InlineCompileInput, NameCollision,
};
use uuid::Uuid;

async fn seed_user(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, created_at, updated_at) \
         VALUES ($1, $2, 'x', NOW(), NOW())",
    )
    .bind(id)
    .bind(format!("spec-gate-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

/// A module the user already owns, with grants the spec must not rewrite.
async fn seed_module(pool: &sqlx::PgPool, user_id: Uuid, name: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO modules (name, kind, user_id, capability_world, category, \
                              allowed_hosts, source_code, wasm_bytes) \
         VALUES ($1, 'extracted', $2, 'http-node', 'test', \
                 ARRAY['api.original.test'], 'original source', '\\x00'::bytea) \
         RETURNING id",
    )
    .bind(name)
    .bind(user_id)
    .fetch_one(pool)
    .await
    .expect("seed module")
}

async fn module_state(pool: &sqlx::PgPool, id: Uuid) -> (String, Vec<String>, String, Vec<u8>) {
    sqlx::query_as(
        "SELECT capability_world, allowed_hosts, source_code, wasm_bytes FROM modules WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("read module")
}

async fn workflow_count(pool: &sqlx::PgPool, user_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM workflows WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn call_spec(
    state: &Arc<controller::mcp::McpState>,
    who: Arc<AgentIdentity>,
    nodes: serde_json::Value,
) -> controller::mcp::types::JsonRpcResponse {
    controller::mcp::workflows::dispatch(
        "create_workflow_from_spec",
        Some(serde_json::json!(1)),
        &serde_json::json!({ "name": "spec-gate", "nodes": nodes }),
        state.clone(),
        who,
    )
    .await
    .expect("create_workflow_from_spec is dispatched")
}

fn inline_node(id: &str, world: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "rust_code": "fn run(input: serde_json::Value) -> serde_json::Value { input }",
        "capability_world": world,
    })
}

/// A taken name is REFUSED and the existing module is left exactly as it was.
/// Pre-fix this overwrote the module's world, hosts, source and WASM.
#[tokio::test]
async fn a_taken_name_is_refused_and_the_module_is_untouched() {
    let (pool, _db) = common::isolated_db_pool().await;
    let state = Arc::new(mcp_state(pool.clone()).await);
    let user = seed_user(&pool).await;
    let existing = seed_module(&pool, user, "spec-taken").await;
    let before = module_state(&pool, existing).await;

    let resp = call_spec(
        &state,
        agent(user),
        serde_json::json!([inline_node("spec-taken", "http-node")]),
    )
    .await;
    let msg = error_message(&resp);
    assert!(msg.contains("name_collision"), "{msg}");
    assert!(
        msg.contains(&existing.to_string()),
        "names the existing module: {msg}"
    );

    assert_eq!(
        module_state(&pool, existing).await,
        before,
        "nothing rewritten"
    );
    assert_eq!(workflow_count(&pool, user).await, 0, "no workflow created");
}

/// The role gate runs per compiled world. An agent whose role lacks
/// `automation` is refused an automation-node inline node; the CONTROL is the
/// same agent on an `http-node` node, which passes the gate and is refused
/// later for a different reason (the name is taken) — so the refusal above is
/// the gate's, not a coincidence of a later step.
#[tokio::test]
async fn the_role_gate_refuses_a_world_the_agent_lacks() {
    let (pool, _db) = common::isolated_db_pool().await;
    let state = Arc::new(mcp_state(pool.clone()).await);
    let user = seed_user(&pool).await;
    seed_module(&pool, user, "spec-role").await;
    let http_only = Arc::new(AgentIdentity {
        agent_id: Uuid::new_v4(),
        name: "spec-gate-http-only".to_string(),
        role_name: "http-only".to_string(),
        allowed_capabilities: vec!["http".to_string()],
        user_id: Some(user),
    });

    let refused = call_spec(
        &state,
        http_only.clone(),
        serde_json::json!([inline_node("spec-role", "automation-node")]),
    )
    .await;
    let msg = error_message(&refused);
    assert!(msg.contains("lacks capability"), "{msg}");
    assert!(msg.contains("automation-node"), "{msg}");

    let control = call_spec(
        &state,
        http_only,
        serde_json::json!([inline_node("spec-role", "http-node")]),
    )
    .await;
    let msg = error_message(&control);
    assert!(
        msg.contains("name_collision") && !msg.contains("lacks capability"),
        "control: an admitted world passes the gate and stops at the collision: {msg}"
    );
}

/// A spec never grants `"*"` hosts.
#[tokio::test]
async fn a_wildcard_host_is_refused() {
    let (pool, _db) = common::isolated_db_pool().await;
    let state = Arc::new(mcp_state(pool.clone()).await);
    let user = seed_user(&pool).await;
    let mut node = inline_node("spec-star", "http-node");
    node["allowed_hosts"] = serde_json::json!(["*"]);

    let msg = error_message(&call_spec(&state, agent(user), serde_json::json!([node])).await);
    assert!(msg.contains("allowed_hosts may not contain"), "{msg}");
    assert_eq!(workflow_count(&pool, user).await, 0);
}

/// An explicit `module_id` must be one the caller can see. Absent and foreign
/// are one answer; the CONTROL (the caller's own module) creates the workflow.
#[tokio::test]
async fn a_foreign_module_id_is_refused() {
    let (pool, _db) = common::isolated_db_pool().await;
    let state = Arc::new(mcp_state(pool.clone()).await);
    let user = seed_user(&pool).await;
    let stranger = seed_user(&pool).await;
    let foreign = seed_module(&pool, stranger, "someone-elses").await;
    let own = seed_module(&pool, user, "mine").await;

    let msg = error_message(
        &call_spec(
            &state,
            agent(user),
            serde_json::json!([{ "id": "n1", "module_id": foreign.to_string() }]),
        )
        .await,
    );
    assert!(msg.contains("not found or not accessible"), "{msg}");
    assert_eq!(workflow_count(&pool, user).await, 0);

    let ok = call_spec(
        &state,
        agent(user),
        serde_json::json!([{ "id": "n1", "module_id": own.to_string() }]),
    )
    .await;
    assert_eq!(text_json(&ok)["status"], "created");
}

fn persist_input<'a>(user: Uuid, name: &'a str, world: &'a str) -> InlineCompileInput<'a> {
    InlineCompileInput {
        user_id: user,
        workflow_id: Uuid::nil(),
        workflow_actor_id: None,
        node_id: name,
        rust_code: "fn run() {}",
        capability_world: world,
        explicit_allowed_hosts: Some(vec!["api.named.test".to_string()]),
        explicit_allowed_secrets: Some(vec![]),
        explicit_allowed_methods: Some(vec!["GET".to_string(), "POST".to_string()]),
        dependencies: None,
        integration_name: None,
        fuel_budget: None,
        on_name_collision: NameCollision::Refuse,
    }
}

/// The persist half: the module gets EXACTLY the declared grants — including
/// `allowed_methods`, which the service's mirror write dropped as a literal
/// `&[]` until 2026-09-25 — and a name taken between compile and persist is
/// refused rather than overwritten.
#[tokio::test]
async fn persist_writes_the_declared_grants_and_refuses_a_name_taken_meanwhile() {
    let (pool, _db) = common::isolated_db_pool().await;
    let state = Arc::new(mcp_state(pool.clone()).await);
    let user = seed_user(&pool).await;
    let svc = &state.inline_compile_service;

    let input = persist_input(user, "spec-persist", "http-node");
    let out = svc
        .persist_compiled(
            &input,
            CompiledInline::prebuilt_for_tests(&input, vec![0, 97, 115, 109]),
        )
        .await
        .expect("a fresh name persists");
    let (hosts, methods): (Vec<String>, Vec<String>) =
        sqlx::query_as("SELECT allowed_hosts, allowed_methods FROM modules WHERE id = $1")
            .bind(out.module_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(hosts, vec!["api.named.test".to_string()]);
    assert_eq!(methods, vec!["GET".to_string(), "POST".to_string()]);

    // Same name again, as if created between compile_checked and persist.
    let again = svc
        .persist_compiled(
            &input,
            CompiledInline::prebuilt_for_tests(&input, vec![1, 2, 3]),
        )
        .await;
    assert!(
        matches!(again, Err(InlineCompileError::NameCollision(_))),
        "{again:?}"
    );
    let wasm: Vec<u8> = sqlx::query_scalar("SELECT wasm_bytes FROM modules WHERE id = $1")
        .bind(out.module_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        wasm,
        vec![0, 97, 115, 109],
        "the refused persist wrote nothing"
    );
}

/// WASM compiled under one world cannot be recorded under another.
#[tokio::test]
async fn a_compiled_module_cannot_be_persisted_under_another_world() {
    let (pool, _db) = common::isolated_db_pool().await;
    let state = Arc::new(mcp_state(pool.clone()).await);
    let user = seed_user(&pool).await;

    let compiled_as = persist_input(user, "spec-mismatch", "http-node");
    let claimed = persist_input(user, "spec-mismatch", "minimal-node");
    let out = state
        .inline_compile_service
        .persist_compiled(
            &claimed,
            CompiledInline::prebuilt_for_tests(&compiled_as, vec![0]),
        )
        .await;
    assert!(
        matches!(out, Err(InlineCompileError::Internal(_))),
        "{out:?}"
    );
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM modules WHERE name = 'spec-mismatch'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
}
