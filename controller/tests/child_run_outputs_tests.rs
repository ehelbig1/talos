//! A child run can be found, and looked into, however deep it ran
//! (2026-10-14).
//!
//! Workflow A runs B as a sub-workflow, and B runs C. Until this date:
//! `list_executions` for B or C showed none of those runs (a child run has no
//! `workflow_executions` row, RFC 0012), and nothing stored C's node outputs
//! — the parent node received C's collapsed output and the rest was dropped
//! with C's engine. C's ledger row also named, as its parent execution, the
//! synthetic id B's engine ran under, which names no row anywhere.
//!
//! Driven here end to end against real rows: the real reactor runs the chain
//! with the real ledger recorder, the real collector builds the stored output,
//! the real repository stores it (redaction, encryption at rest), and the real
//! handlers read it back (ownership, the path walk, the listing).
//!
//! Row security is left OFF in this binary (`TALOS_RLS_SET_ROLE=0`, read once
//! per process): the ownership test must prove the handler's own predicate,
//! which is all that refuses a stranger on a deployment with the switch off
//! (the default), and a developer `.env` that turns it on would otherwise let
//! row security answer in the predicate's place.
//!
//! `common` harness (a template clone per test), so the migrated-database job
//! runs it.

#[path = "common/mod.rs"]
mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use std::sync::Arc;
use std::time::Duration;

use mcp_common::{agent, error_message, mcp_state, text_json};
use serde_json::{json, Value};
use talos_engine::child_run_recorder::PostgresChildRunRecorder;
use talos_workflow_engine::WorkflowGraphBuilder;
use talos_workflow_engine_core::{SystemNodeKind, WasmModuleArtifact};
use talos_workflow_engine_test_utils::{
    dispatch::ScriptedDispatcher,
    memory::{InMemoryModuleFetcher, InMemoryWorkflowGraphStore},
    minimal_engine,
};
use uuid::Uuid;

/// Must run before the first scoped transaction: the switch is read once.
fn leave_row_security_unenforced() {
    std::env::set_var("TALOS_RLS_SET_ROLE", "0");
}

async fn seed_user(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, created_at, updated_at) \
         VALUES ($1, $2, 'x', NOW(), NOW())",
    )
    .bind(id)
    .bind(format!("child-run-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

async fn seed_workflow(pool: &sqlx::PgPool, user: Uuid, id: Uuid, graph: &Value) {
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, module_uri, graph_json, status, is_enabled) \
         VALUES ($1, $2, $3, 'test:child-run', $4, 'active', true)",
    )
    .bind(id)
    .bind(user)
    .bind(format!("child-run-wf-{}", id.simple()))
    .bind(graph.to_string())
    .execute(pool)
    .await
    .expect("seed workflow");
}

async fn seed_running_execution(pool: &sqlx::PgPool, user: Uuid, workflow: Uuid) -> Uuid {
    let actor_id = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name, status) VALUES ($1, $2, $3, 'active')")
        .bind(actor_id)
        .bind(user)
        .bind(format!("child-run-actor-{}", actor_id.simple()))
        .execute(pool)
        .await
        .expect("seed actor");
    let exec_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflow_executions (id, workflow_id, user_id, actor_id, status, started_at) \
         VALUES ($1, $2, $3, $4, 'running', NOW())",
    )
    .bind(exec_id)
    .bind(workflow)
    .bind(user)
    .bind(actor_id)
    .execute(pool)
    .await
    .expect("seed execution");
    exec_id
}

fn stub_artifact(id: Uuid) -> WasmModuleArtifact {
    WasmModuleArtifact {
        module_id: id,
        content_hash: "stub".into(),
        wasm_bytes: vec![],
        oci_url: None,
        max_fuel: 1_000_000,
        capability_world: "stub".into(),
        allowed_hosts: vec![],
        allowed_methods: vec![],
        allowed_secrets: vec![],
        requires_approval_for: vec![],
        integration_name: None,
        config: None,
    }
}

struct Chain {
    a: Uuid,
    b: Uuid,
    c: Uuid,
    exec_id: Uuid,
}

/// A → `assess` (sub_workflow B); B: `read` → `brief` (sub_workflow C);
/// C: `draft` → `notify`. Run for real and stored as a completed run.
async fn run_the_chain(
    pool: &sqlx::PgPool,
    state: &controller::mcp::McpState,
    owner: Uuid,
) -> Chain {
    let (a, b, c) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let (read, draft, notify) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let graph_a = WorkflowGraphBuilder::new()
        .add_system_node(
            "assess",
            SystemNodeKind::SubWorkflow {
                workflow_id: b,
                timeout_secs: 30,
            },
        )
        .build()
        .unwrap();
    let graph_b = WorkflowGraphBuilder::new()
        .add_module("read", read, None)
        .add_system_node(
            "brief",
            SystemNodeKind::SubWorkflow {
                workflow_id: c,
                timeout_secs: 30,
            },
        )
        .edge("read", "brief")
        .build()
        .unwrap();
    let graph_c = WorkflowGraphBuilder::new()
        .add_module("draft", draft, None)
        .add_module("notify", notify, None)
        .edge("draft", "notify")
        .build()
        .unwrap();
    seed_workflow(pool, owner, a, &graph_a).await;
    seed_workflow(pool, owner, b, &graph_b).await;
    seed_workflow(pool, owner, c, &graph_c).await;
    let exec_id = seed_running_execution(pool, owner, a).await;

    let mut engine = minimal_engine();
    engine.set_user_id(owner);
    engine.set_workflow_id(a);
    engine.set_child_run_recorder(Arc::new(PostgresChildRunRecorder::new(pool.clone())));
    engine.set_module_fetcher(Arc::new(
        InMemoryModuleFetcher::new()
            .with_module(read, stub_artifact(read))
            .with_module(draft, stub_artifact(draft))
            .with_module(notify, stub_artifact(notify)),
    ));
    engine.set_graph_store(Arc::new(
        InMemoryWorkflowGraphStore::new()
            .with_graph(b, graph_b)
            .with_graph(c, graph_c),
    ));
    engine.set_execution_timeout(Some(Duration::from_secs(30)));
    engine
        .load_graph_from_json(&graph_a.to_string())
        .await
        .expect("A loads");
    let dispatcher = Arc::new(
        ScriptedDispatcher::new()
            .with_response(read, json!({ "ticket": "made-up-1" }))
            .with_response(draft, json!({ "brief": "a drafted brief" }))
            .with_response(
                notify,
                json!({ "sent": true, "echoed": "Bearer ghp_abcdefghijklmnopqrstuvwx12" }),
            ),
    );
    let ctx = engine
        .run_with_transport(dispatcher, None, exec_id)
        .await
        .expect("the chain runs");
    let stored =
        talos_execution_result_collector::collect_success_output(&engine, &ctx, &json!({}));
    state
        .workflow_repo
        .mark_execution_completed(exec_id, &stored)
        .await
        .expect("finalize");
    Chain { a, b, c, exec_id }
}

async fn call(
    state: &controller::mcp::McpState,
    tool: &str,
    args: Value,
    as_user: Uuid,
) -> controller::mcp::types::JsonRpcResponse {
    controller::mcp::executions::dispatch(tool, Some(json!(1)), &args, state, agent(as_user))
        .await
        .unwrap_or_else(|| panic!("{tool} is dispatched"))
}

/// Both of the grandchild's node outputs are reachable through the path form,
/// redacted as every stored output is.
#[tokio::test]
async fn a_grandchild_runs_every_node_output_is_reachable_by_path() {
    leave_row_security_unenforced();
    let (pool, _db) = common::isolated_db_pool().await;
    let owner = seed_user(&pool).await;
    let state = mcp_state(pool.clone()).await;
    let chain = run_the_chain(&pool, &state, owner).await;

    let body = text_json(
        &call(
            &state,
            "get_sub_workflow_output",
            json!({ "execution_id": chain.exec_id.to_string(), "path": ["assess", "brief"] }),
            owner,
        )
        .await,
    );
    let run = &body["node"]["runs"][0];
    assert_eq!(run["workflow_id"], json!(chain.c.to_string()), "{body}");
    assert_eq!(run["status"], "completed", "{body}");
    assert_eq!(run["nodes"]["draft"]["brief"], "a drafted brief", "{body}");
    assert_eq!(run["nodes"]["notify"]["sent"], true, "{body}");
    assert!(
        !body.to_string().contains("ghp_abcdefghijklmnopqrstuvwx12"),
        "a child's node output came back unredacted: {body}"
    );

    // One level up: B's nodes, with C named as a child run of `brief`.
    let body = text_json(
        &call(
            &state,
            "get_sub_workflow_output",
            json!({ "execution_id": chain.exec_id.to_string(), "path": ["assess"] }),
            owner,
        )
        .await,
    );
    let run = &body["node"]["runs"][0];
    assert_eq!(run["nodes"]["read"]["ticket"], "made-up-1", "{body}");
    assert_eq!(run["child_runs"], json!(["brief"]), "{body}");

    // A path that names no child run says what does.
    let msg = error_message(
        &call(
            &state,
            "get_sub_workflow_output",
            json!({ "execution_id": chain.exec_id.to_string(), "path": ["assess", "read"] }),
            owner,
        )
        .await,
    );
    assert!(msg.contains("[\"brief\"]"), "{msg}");
}

/// A caller who does not own the run gets the answer a run that does not
/// exist gets, word for word.
#[tokio::test]
async fn a_stranger_reads_the_path_as_a_missing_execution() {
    leave_row_security_unenforced();
    let (pool, _db) = common::isolated_db_pool().await;
    let owner = seed_user(&pool).await;
    let stranger = seed_user(&pool).await;
    let state = mcp_state(pool.clone()).await;
    let chain = run_the_chain(&pool, &state, owner).await;

    let theirs = call(
        &state,
        "get_sub_workflow_output",
        json!({ "execution_id": chain.exec_id.to_string(), "path": ["assess", "brief"] }),
        stranger,
    )
    .await;
    let nowhere = call(
        &state,
        "get_sub_workflow_output",
        json!({ "execution_id": Uuid::new_v4().to_string(), "path": ["assess", "brief"] }),
        stranger,
    )
    .await;
    assert_eq!(
        serde_json::to_value(&theirs.result).unwrap(),
        serde_json::to_value(&nowhere.result).unwrap(),
        "another user's run must read exactly as a run that does not exist"
    );
    assert_eq!(
        serde_json::to_value(&theirs.error).unwrap(),
        serde_json::to_value(&nowhere.error).unwrap()
    );
    assert!(!serde_json::to_string(&theirs.result)
        .unwrap()
        .contains("a drafted brief"));
}

/// The child runs appear in their workflow's listing by default, with the
/// top-level execution and the path to read them by, and in its stats as a
/// separate block.
#[tokio::test]
async fn child_runs_are_listed_with_their_top_level_execution_and_path() {
    leave_row_security_unenforced();
    let (pool, _db) = common::isolated_db_pool().await;
    let owner = seed_user(&pool).await;
    let stranger = seed_user(&pool).await;
    let state = mcp_state(pool.clone()).await;
    let chain = run_the_chain(&pool, &state, owner).await;

    // The grandchild, C.
    let body = text_json(
        &call(
            &state,
            "list_executions",
            json!({ "workflow_id": chain.c.to_string(), "include_child_runs": true }),
            owner,
        )
        .await,
    );
    assert_eq!(
        body["count"], 0,
        "C has no execution row of its own: {body}"
    );
    assert_eq!(body["child_runs_total"], 1, "{body}");
    let c_run = &body["child_runs"][0];
    assert_eq!(c_run["kind"], "child");
    assert_eq!(
        c_run["execution_id"],
        json!(chain.exec_id.to_string()),
        "the grandchild names the TOP-LEVEL execution, not the synthetic id B ran under: {body}"
    );
    assert_eq!(c_run["path"], json!(["assess", "brief"]), "{body}");
    assert_eq!(c_run["parent_workflow_id"], json!(chain.b.to_string()));
    assert_eq!(c_run["depth"], 2);
    assert_eq!(c_run["status"], "completed");

    // The child, B.
    let body = text_json(
        &call(
            &state,
            "list_executions",
            json!({ "workflow_id": chain.b.to_string(), "include_child_runs": true }),
            owner,
        )
        .await,
    );
    let b_run = &body["child_runs"][0];
    assert_eq!(b_run["execution_id"], json!(chain.exec_id.to_string()));
    assert_eq!(b_run["path"], json!(["assess"]));
    assert_eq!(b_run["parent_workflow_id"], json!(chain.a.to_string()));

    // What a listing row says is what `get_sub_workflow_output` takes.
    let read_back = text_json(
        &call(
            &state,
            "get_sub_workflow_output",
            json!({ "execution_id": c_run["execution_id"], "path": c_run["path"] }),
            owner,
        )
        .await,
    );
    assert_eq!(
        read_back["node"]["runs"][0]["nodes"]["notify"]["sent"],
        true
    );

    // Listed by default (operator decision, 2026-10-14); `false` leaves the
    // list out and the envelope is as it was.
    let body = text_json(
        &call(
            &state,
            "list_executions",
            json!({ "workflow_id": chain.c.to_string() }),
            owner,
        )
        .await,
    );
    assert_eq!(
        body["child_runs_total"], 1,
        "listed without being asked: {body}"
    );
    let body = text_json(
        &call(
            &state,
            "list_executions",
            json!({ "workflow_id": chain.c.to_string(), "include_child_runs": false }),
            owner,
        )
        .await,
    );
    assert!(body.get("child_runs").is_none(), "{body}");

    // The stats count them in their own block, never in the totals.
    let stats = text_json(
        &controller::mcp::analytics::dispatch(
            "get_workflow_stats",
            Some(json!(1)),
            &json!({ "workflow_id": chain.c.to_string(), "days": 7 }),
            &state,
            agent(owner),
        )
        .await
        .expect("get_workflow_stats is dispatched"),
    );
    assert_eq!(stats["total"], 0, "C has no execution of its own: {stats}");
    assert_eq!(stats["child_runs"]["kind"], "child", "{stats}");
    assert_eq!(stats["child_runs"]["runs"], 1, "{stats}");
    assert_eq!(stats["child_runs"]["completed"], 1, "{stats}");
    assert_eq!(stats["child_runs"]["failed"], 0, "{stats}");

    // Another user's workflow is refused before any ledger read.
    let msg = error_message(
        &call(
            &state,
            "list_executions",
            json!({ "workflow_id": chain.c.to_string(), "include_child_runs": true }),
            stranger,
        )
        .await,
    );
    assert!(msg.contains("not found or access denied"), "{msg}");
}

/// The retention purge keeps a pinned run's grandchildren as it keeps its
/// children: the exemption reads the top-level execution, not the synthetic
/// id the grandchild's own parent ran under.
#[tokio::test]
async fn a_pinned_runs_grandchild_survives_the_ledger_purge() {
    leave_row_security_unenforced();
    let (pool, _db) = common::isolated_db_pool().await;
    let owner = seed_user(&pool).await;
    let state = mcp_state(pool.clone()).await;
    let chain = run_the_chain(&pool, &state, owner).await;

    sqlx::query("UPDATE workflow_executions SET is_pinned = true WHERE id = $1")
        .bind(chain.exec_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE sub_workflow_runs SET started_at = NOW() - interval '400 days'")
        .execute(&pool)
        .await
        .unwrap();
    let _ = talos_child_run_ledger::ChildRunLedger::new(pool.clone())
        .purge_older_than(30)
        .await
        .expect("purge");
    let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sub_workflow_runs WHERE depth = 2")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(left, 1, "the pinned run's grandchild was purged");
}
