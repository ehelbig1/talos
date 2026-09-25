//! A cancel must stop the ENGINE, not only the row and the workers.
//!
//! Until 2026-09-25 `cancel_execution` marked the `workflow_executions` row
//! and broadcast a `CancelCommand` to the worker fleet. The engine driving the
//! run — the thing that decides what is dispatched next — was never told: its
//! cancellation token was fired only by the crash-recovery fence, which read
//! `epoch` and nothing else. So a cancelled run kept dispatching every
//! remaining node while the MCP reply said "No further nodes will be
//! dispatched". And the one place the dispatch path DID learn the run was over
//! — the race-safe start row, born `cancelled` — was counted and then ignored.
//!
//! These drive the real service over a real database:
//!
//! * `cancel_execution` fires the stop signal of the run THIS process is
//!   driving, reports whether it did, and — the authorization half — never
//!   fires it for a caller who does not own the execution;
//! * `PostgresModuleExecutionStore::record_started` reports a row born
//!   `cancelled`, which is what makes the engine refuse the dispatch (the
//!   refusal itself is driven in `talos-workflow-engine/tests/cancellation.rs`).
mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use serde_json::json;
use sqlx::{Pool, Postgres};
use talos_execution_orchestration::EngineStop;
use talos_workflow_engine_core::{ExecutionStartedContext, ModuleExecutionStore, StartedRow};
use uuid::Uuid;

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'cancel test')",
    )
    .bind(id)
    .bind(format!("cancel-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

/// A workflow, its actor and one execution in `status`: `(execution, actor)`.
async fn seed_execution(pool: &Pool<Postgres>, user: Uuid, status: &str) -> (Uuid, Uuid) {
    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name) VALUES ($1, $2, $3)")
        .bind(actor)
        .bind(user)
        .bind(format!("cancel-actor-{actor}"))
        .execute(pool)
        .await
        .expect("actor");
    let wf = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, graph_json, module_uri, status, is_enabled) \
         VALUES ($1, $2, $3, '{\"nodes\":[],\"edges\":[]}', 'talos://t', 'active', true)",
    )
    .bind(wf)
    .bind(user)
    .bind(format!("cancel-wf-{wf}"))
    .execute(pool)
    .await
    .expect("workflow");
    let exec = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflow_executions (id, workflow_id, user_id, actor_id, status) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(exec)
    .bind(wf)
    .bind(user)
    .bind(actor)
    .bind(status)
    .execute(pool)
    .await
    .expect("execution");
    (exec, actor)
}

#[tokio::test]
async fn cancel_stops_the_engine_this_controller_is_driving() {
    let (pool, _db) = common::isolated_db_pool().await;
    let state = mcp_common::mcp_state(pool.clone()).await;
    let user = seed_user(&pool).await;
    let (exec, _) = seed_execution(&pool, user, "running").await;

    // This process is driving the run (what the engine-run chokepoints do).
    let run = talos_shutdown::inflight::global().track(exec);

    let outcome = state
        .execution_orchestration_service
        .cancel_execution(exec, user)
        .await
        .expect("cancel");
    assert!(outcome.marked);
    assert_eq!(outcome.engine, EngineStop::StoppedHere);
    assert!(
        run.stop_signal().is_cancelled(),
        "the engine driving the run must be told to stop"
    );
}

#[tokio::test]
async fn cancel_of_a_run_driven_elsewhere_says_it_stopped_nothing_here() {
    let (pool, _db) = common::isolated_db_pool().await;
    let state = mcp_common::mcp_state(pool.clone()).await;
    let user = seed_user(&pool).await;
    let (exec, _) = seed_execution(&pool, user, "running").await;

    let outcome = state
        .execution_orchestration_service
        .cancel_execution(exec, user)
        .await
        .expect("cancel");
    assert!(outcome.marked, "the row is still cancelled");
    assert_eq!(
        outcome.engine,
        EngineStop::NotRunningHere,
        "a controller not driving the run must not report it stopped"
    );
}

#[tokio::test]
async fn a_non_owner_cannot_stop_someone_elses_run() {
    let (pool, _db) = common::isolated_db_pool().await;
    let state = mcp_common::mcp_state(pool.clone()).await;
    let owner = seed_user(&pool).await;
    let stranger = seed_user(&pool).await;
    let (exec, _) = seed_execution(&pool, owner, "running").await;
    let run = talos_shutdown::inflight::global().track(exec);

    let outcome = state
        .execution_orchestration_service
        .cancel_execution(exec, stranger)
        .await
        .expect("cancel");
    assert!(!outcome.marked);
    assert_eq!(outcome.engine, EngineStop::NotAttempted);
    assert!(
        !run.stop_signal().is_cancelled(),
        "the stop signal is gated on the ownership-checked UPDATE, exactly as the broadcast is"
    );
    let status: String = sqlx::query_scalar("SELECT status FROM workflow_executions WHERE id = $1")
        .bind(exec)
        .fetch_one(&pool)
        .await
        .expect("status");
    assert_eq!(status, "running");
}

#[tokio::test]
async fn a_start_row_under_a_cancelled_execution_is_reported_born_cancelled() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let module = Uuid::new_v4();
    sqlx::query("INSERT INTO modules (id, user_id, name, kind) VALUES ($1, $2, $3, 'sandbox')")
        .bind(module)
        .bind(user)
        .bind(format!("cancel-module-{module}"))
        .execute(&pool)
        .await
        .expect("seed module");
    let store =
        talos_engine::module_execution_store::PostgresModuleExecutionStore::new(pool.clone());
    let input = json!({ "k": "v" });

    for (parent_status, expected) in [
        ("running", StartedRow::Running),
        ("cancelled", StartedRow::BornCancelled),
        ("failed", StartedRow::BornCancelled),
    ] {
        let (exec, actor) = seed_execution(&pool, user, parent_status).await;
        let row = Uuid::new_v4();
        let started = store
            .record_started(ExecutionStartedContext {
                id: row,
                module_id: module,
                user_id: user,
                workflow_execution_id: exec,
                input: &input,
                trigger_type: "manual",
                race_safe_status: true,
                actor_id: Some(actor),
            })
            .await
            .expect("record_started");
        assert_eq!(started, expected, "parent {parent_status}");
        let stored: String =
            sqlx::query_scalar("SELECT status FROM module_executions WHERE id = $1")
                .bind(row)
                .fetch_one(&pool)
                .await
                .expect("row");
        assert_eq!(
            stored == "cancelled",
            expected == StartedRow::BornCancelled,
            "the returned answer must match the row that was written"
        );
    }
}
