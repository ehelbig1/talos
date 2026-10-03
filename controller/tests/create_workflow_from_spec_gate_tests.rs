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

async fn call_spec_with_edges(
    state: &Arc<controller::mcp::McpState>,
    who: Arc<AgentIdentity>,
    nodes: serde_json::Value,
    edges: serde_json::Value,
) -> controller::mcp::types::JsonRpcResponse {
    controller::mcp::workflows::dispatch(
        "create_workflow_from_spec",
        Some(serde_json::json!(1)),
        &serde_json::json!({ "name": "spec-structural", "nodes": nodes, "edges": edges }),
        state.clone(),
        who,
    )
    .await
    .expect("create_workflow_from_spec is dispatched")
}

/// A workflow of `owner`'s to name as a sub-workflow.
async fn seed_child_workflow(
    state: &Arc<controller::mcp::McpState>,
    pool: &sqlx::PgPool,
    owner: Uuid,
) -> Uuid {
    let module = seed_module(pool, owner, &format!("child-step-{owner}")).await;
    let created = call_spec(
        state,
        agent(owner),
        serde_json::json!([{ "id": "only", "module_id": module.to_string() }]),
    )
    .await;
    text_json(&created)["workflow_id"]
        .as_str()
        .expect("a workflow id")
        .parse()
        .expect("a uuid")
}

/// One call builds a fan-out with per-node retries, a labelled collect and a
/// sub-workflow that may fail — the shape that took one call plus five
/// follow-ups before 2026-10-03. Read back from the stored graph.
#[tokio::test]
async fn a_spec_stores_structural_nodes_and_per_node_controls() {
    let (pool, _db) = common::isolated_db_pool().await;
    let state = Arc::new(mcp_state(pool.clone()).await);
    let user = seed_user(&pool).await;
    let reader = seed_module(&pool, user, "reader").await;
    let child = seed_child_workflow(&state, &pool, user).await;

    let created = call_spec_with_edges(
        &state,
        agent(user),
        serde_json::json!([
            { "id": "bank_a", "module_id": reader.to_string(), "config": { "K": 1 },
              "retry_count": 1, "timeout_secs": 40, "continue_on_error": true },
            { "id": "bank_b", "module_id": reader.to_string() },
            { "id": "all", "node_type": "collect", "label_items": true },
            { "id": "money", "node_type": "sub_workflow", "sub_workflow_id": child.to_string(),
              "timeout_secs": 150, "continue_on_error": true },
        ]),
        serde_json::json!([
            { "source": "bank_a", "target": "all" },
            { "source": "bank_b", "target": "all" },
            { "source": "all", "target": "money" },
        ]),
    )
    .await;
    let body = text_json(&created);
    assert_eq!(body["status"], "created", "{body}");
    assert_eq!(body["node_count"], 4);

    let workflow_id: Uuid = body["workflow_id"].as_str().unwrap().parse().unwrap();
    let stored: String = sqlx::query_scalar("SELECT graph_json FROM workflows WHERE id = $1")
        .bind(workflow_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    let graph: serde_json::Value = serde_json::from_str(&stored).unwrap();
    let node = |id: &str| {
        graph["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["id"] == id)
            .unwrap_or_else(|| panic!("node {id} in {graph}"))
            .clone()
    };
    let bank = node("bank_a");
    assert_eq!(bank["type"], reader.to_string());
    assert_eq!(bank["data"], serde_json::json!({ "K": 1 }));
    assert_eq!(bank["retry_count"], 1);
    assert_eq!(bank["timeout_secs"], 40);
    assert_eq!(bank["continue_on_error"], true);
    assert!(
        node("bank_b").get("retry_count").is_none(),
        "nothing stated, nothing stamped: the engine applies the module's default"
    );
    assert_eq!(node("all")["type"], "system:collect");
    assert_eq!(
        node("all")["data"],
        serde_json::json!({ "label_items": true })
    );
    assert_eq!(node("money")["type"], "system:sub_workflow");
    assert_eq!(
        node("money")["data"],
        serde_json::json!({ "sub_workflow_id": child.to_string(), "timeout_secs": 150,
                            "continue_on_error": true })
    );

    // The engine accepts what was stored: the graph loads and validates.
    let validated = controller::mcp::workflows::dispatch(
        "validate_workflow",
        Some(serde_json::json!(2)),
        &serde_json::json!({ "workflow_id": workflow_id.to_string() }),
        state.clone(),
        agent(user),
    )
    .await
    .expect("validate_workflow is dispatched");
    let report = text_json(&validated);
    assert_eq!(report["valid"], true, "{report}");
}

/// A sub-workflow the caller cannot see is refused, in the one sentence used
/// for absent and foreign alike, and nothing is created. The CONTROL is the
/// test above: the caller's own child is accepted.
#[tokio::test]
async fn a_sub_workflow_the_caller_cannot_see_is_refused() {
    let (pool, _db) = common::isolated_db_pool().await;
    let state = Arc::new(mcp_state(pool.clone()).await);
    let user = seed_user(&pool).await;
    let stranger = seed_user(&pool).await;
    let foreign_child = seed_child_workflow(&state, &pool, stranger).await;
    let absent_child = Uuid::new_v4();

    let mut answers = Vec::new();
    for child in [foreign_child, absent_child] {
        let msg = error_message(
            &call_spec_with_edges(
                &state,
                agent(user),
                serde_json::json!([{ "id": "money", "node_type": "sub_workflow",
                                     "sub_workflow_id": child.to_string() }]),
                serde_json::json!([]),
            )
            .await,
        );
        assert!(
            msg.contains("does not exist or is not owned by you"),
            "{msg}"
        );
        answers.push(msg.replace(&child.to_string(), "<id>"));
    }
    assert_eq!(
        answers[0], answers[1],
        "a foreign workflow and an absent one get the same answer"
    );
    assert_eq!(workflow_count(&pool, user).await, 0, "nothing created");
}

/// A control the builder could not honour as written is refused before
/// anything is created — never accepted and dropped.
#[tokio::test]
async fn a_node_control_that_cannot_take_effect_is_refused() {
    let (pool, _db) = common::isolated_db_pool().await;
    let state = Arc::new(mcp_state(pool.clone()).await);
    let user = seed_user(&pool).await;
    let reader = seed_module(&pool, user, "reader").await;
    for (extra, want) in [
        (
            serde_json::json!({ "retry_count": "2" }),
            "retry_count must be a whole number",
        ),
        (serde_json::json!({ "retry_count": 9000 }), "retry_count"),
        (serde_json::json!({ "timeout_secs": 86400 }), "timeout_secs"),
        (
            serde_json::json!({ "continue_on_error": "yes" }),
            "continue_on_error must be true or false",
        ),
        (
            serde_json::json!({ "skip_condition": "count ==" }),
            "skip_condition",
        ),
        (
            serde_json::json!({ "node_type": "collector" }),
            "is not one of",
        ),
    ] {
        let mut node = serde_json::json!({ "id": "n1", "module_id": reader.to_string() });
        for (k, v) in extra.as_object().unwrap() {
            node[k] = v.clone();
        }
        let msg = error_message(
            &call_spec_with_edges(
                &state,
                agent(user),
                serde_json::json!([node]),
                serde_json::json!([]),
            )
            .await,
        );
        assert!(msg.contains(want), "{extra}: {msg}");
    }
    assert_eq!(workflow_count(&pool, user).await, 0, "nothing created");
}

/// The module-info tool shows all three grants and the fuel limit. Until
/// 2026-10-03 it showed hosts and secrets only, so a module that could make
/// no HTTP call (no verbs) looked the same as one that could.
#[tokio::test]
async fn module_info_reports_the_verbs_and_the_fuel_limit() {
    let (pool, _db) = common::isolated_db_pool().await;
    let state = Arc::new(mcp_state(pool.clone()).await);
    let user = seed_user(&pool).await;
    let module = seed_module(&pool, user, "info-probe").await;
    sqlx::query(
        "UPDATE modules SET allowed_methods = ARRAY['GET','POST'], max_fuel = 7000000, \
                dependencies = '{\"chrono\": \"0.4\"}'::jsonb WHERE id = $1",
    )
    .bind(module)
    .execute(&pool)
    .await
    .unwrap();

    let info = |id: Uuid, who: Uuid| {
        let state = state.clone();
        async move {
            controller::mcp::modules::dispatch(
                "get_module_info",
                Some(serde_json::json!(1)),
                &serde_json::json!({ "module_id": id.to_string() }),
                state.as_ref(),
                agent(who),
            )
            .await
            .expect("get_module_info is dispatched")
        }
    };
    let body = text_json(&info(module, user).await);
    assert_eq!(
        body["allowed_hosts"],
        serde_json::json!(["api.original.test"])
    );
    assert_eq!(body["allowed_methods"], serde_json::json!(["GET", "POST"]));
    assert_eq!(body["max_fuel"], 7_000_000);
    assert_eq!(body["dependencies"], serde_json::json!({ "chrono": "0.4" }));
    assert_eq!(body["language"], "rust");

    // A module that declares no verbs says so (it can make no HTTP call);
    // its fuel limit is the column's own default, and crates that were never
    // recorded read as null, not as "none".
    let bare = seed_module(&pool, user, "info-bare").await;
    let body = text_json(&info(bare, user).await);
    assert_eq!(body["allowed_methods"], serde_json::json!([]));
    assert!(body["max_fuel"].as_u64().is_some_and(|f| f > 0), "{body}");
    assert_eq!(body["dependencies"], serde_json::Value::Null);

    // Another user's module is still not shown.
    let stranger = seed_user(&pool).await;
    let refused = info(module, stranger).await;
    assert!(
        refused
            .result
            .as_ref()
            .and_then(|r| r.get("isError"))
            .and_then(serde_json::Value::as_bool)
            == Some(true)
            || refused.error.is_some(),
        "{refused:?}"
    );
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
