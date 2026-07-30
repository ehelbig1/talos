//! Where a WASM log line lands — and what the writer reports when it lands
//! nowhere.
//!
//! Every `wasm.log.{execution_id}` line the worker publishes is routed by the
//! controller's subscriber into `workflow_execution_logs` (when the id names a
//! workflow execution) or `module_execution_logs` (when it names a module
//! execution). BOTH inserts are `WHERE EXISTS`-guarded, so an id that names
//! neither silently affects zero rows.
//!
//! For months that was not a hypothetical: loop-body iterations dispatched
//! with `job_id: None`, the dispatcher minted a UUID that existed in neither
//! table, and every log line from every Loop iteration — host diagnostics AND
//! the guest's own `logging::log` — was discarded. `add_log` returned `Ok(())`
//! regardless because it matched `Ok(_)` and never looked at `rows_affected`,
//! and `get_execution_logs` returns `[]` for empty, so a discarded-log
//! execution was byte-identical to a silent one.
//!
//! These tests exercise the REAL `add_log` against a REAL Postgres so the
//! `WHERE EXISTS` predicate is the thing under test — a mock cannot fail the
//! way the production statement failed. They cover both halves of the fix:
//! that a line for a recorded execution row lands AND is readable back, and
//! that a line for an unknown id is reported as `NoExecutionRow` rather than
//! as success.

mod common;

use std::sync::Arc;

use talos_module_executions::{LogLevel, LogWriteOutcome, ModuleExecutionService};
use uuid::Uuid;

struct Fixture {
    pool: sqlx::Pool<sqlx::Postgres>,
    service: ModuleExecutionService,
    user: Uuid,
    module: Uuid,
    actor: Uuid,
    _db: common::TestDb,
}

async fn fixture() -> Fixture {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) \
         VALUES ($1, $2, 'x', true) ON CONFLICT (id) DO NOTHING",
    )
    .bind(user)
    .bind(format!("{user}@wasm-log-routing.test"))
    .execute(&pool)
    .await
    .expect("seed user");

    let module = Uuid::new_v4();
    sqlx::query("INSERT INTO modules (id, name, kind) VALUES ($1, $2, 'sandbox')")
        .bind(module)
        .bind(format!("m-{module}"))
        .execute(&pool)
        .await
        .expect("seed module");

    // actor_id is NOT NULL on module_executions post actor-universalization.
    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name) VALUES ($1, $2, $3)")
        .bind(actor)
        .bind(user)
        .bind(format!("actor-{actor}"))
        .execute(&pool)
        .await
        .expect("seed actor");

    let service = ModuleExecutionService::new(
        pool.clone(),
        Arc::new(talos_dlp_provider::DlpService::from_env()),
    );
    Fixture {
        pool,
        service,
        user,
        module,
        actor,
        _db,
    }
}

impl Fixture {
    /// Insert a `module_executions` row — the shape
    /// `ModuleExecutionStore::record_started` produces for a dispatched node
    /// (and now, for every loop-body iteration).
    async fn seed_execution_row(&self) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO module_executions \
             (id, module_id, user_id, actor_id, status, trigger_type) \
             VALUES ($1, $2, $3, $4, 'running', 'webhook')",
        )
        .bind(id)
        .bind(self.module)
        .bind(self.user)
        .bind(self.actor)
        .execute(&self.pool)
        .await
        .expect("seed module_executions row");
        id
    }

    async fn log_row_count(&self, execution_id: Uuid) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM module_execution_logs WHERE execution_id = $1")
            .bind(execution_id)
            .fetch_one(&self.pool)
            .await
            .expect("count log rows")
    }
}

/// The happy path: a line addressed to a REAL execution row is inserted, is
/// reported as `Inserted`, and reads back.
#[tokio::test]
async fn log_for_a_recorded_execution_is_inserted_and_readable() {
    let f = fixture().await;
    let exec_id = f.seed_execution_row().await;

    let outcome = f
        .service
        .add_log(
            exec_id,
            LogLevel::Info,
            "fetched 3 items".to_string(),
            Some(serde_json::json!({ "count": 3 })),
        )
        .await
        .expect("add_log must not error on the happy path");

    assert_eq!(
        outcome,
        LogWriteOutcome::Inserted,
        "a line for an existing execution row must report as inserted"
    );
    assert!(outcome.is_inserted());
    assert!(
        !outcome.is_orphaned(),
        "the orphan warn must NOT fire on the normal path"
    );
    assert_eq!(f.log_row_count(exec_id).await, 1);

    let logs = f
        .service
        .get_execution_logs(exec_id, f.user)
        .await
        .expect("logs readable");
    assert_eq!(logs.len(), 1);
    assert!(logs[0].message.contains("fetched 3 items"));
}

/// THE regression. A line addressed to an id with no `module_executions` row
/// is DISCARDED by the `WHERE EXISTS` guard. `add_log` must say so instead of
/// returning a bare success — the silence is what hid the loop-body log drop.
#[tokio::test]
async fn log_for_an_unknown_execution_id_reports_no_execution_row() {
    let f = fixture().await;
    // The id the pre-fix loop path effectively used: a fresh UUID that no
    // INSERT ever created a row for.
    let orphan_id = Uuid::new_v4();

    let outcome = f
        .service
        .add_log(
            orphan_id,
            LogLevel::Warn,
            "[host:dns-resolution-failed] hostname resolution failed".to_string(),
            None,
        )
        .await
        .expect("a dropped log is not an error — it must not fail the execution");

    assert_eq!(
        outcome,
        LogWriteOutcome::NoExecutionRow,
        "swallowing rows_affected here is exactly the bug: `Ok(())` for a line that was thrown \
         away made every Loop iteration's logs vanish without a trace"
    );
    assert!(outcome.is_orphaned(), "this is what drives the orphan warn");
    assert!(!outcome.is_inserted());
    assert_eq!(
        f.log_row_count(orphan_id).await,
        0,
        "nothing was written — the outcome is not merely pessimistic"
    );

    // And the surface an operator would consult confirms the ambiguity the
    // warn exists to resolve: a discarded-log execution is indistinguishable
    // from a silent one from here.
    let logs = f
        .service
        .get_execution_logs(orphan_id, f.user)
        .await
        .expect("read");
    assert!(
        logs.is_empty(),
        "`[]` — identical to an execution that genuinely logged nothing, which is why the \
         WRITER has to be the one that reports the drop"
    );
}

/// `add_log_best_effort` — the wrapper the WASM-log subscriber actually calls
/// — must propagate the same distinction, or the caller cannot warn.
#[tokio::test]
async fn best_effort_wrapper_propagates_the_outcome() {
    let f = fixture().await;
    let real = f.seed_execution_row().await;

    assert_eq!(
        f.service
            .add_log_best_effort(real, LogLevel::Info, "hello".to_string(), None)
            .await,
        LogWriteOutcome::Inserted
    );
    assert_eq!(
        f.service
            .add_log_best_effort(Uuid::new_v4(), LogLevel::Info, "hello".to_string(), None)
            .await,
        LogWriteOutcome::NoExecutionRow
    );
}

/// End-to-end for D1's payoff: a row created the way the loop path now
/// creates one (`PostgresModuleExecutionStore::record_started`) makes the
/// persist predicate match, so the iteration's logs survive. Before D1 the
/// loop's job id had no row and this path stored nothing.
#[tokio::test]
async fn a_row_recorded_by_the_execution_store_makes_loop_logs_persist() {
    use talos_workflow_engine_core::{ExecutionStartedContext, ModuleExecutionStore};

    let f = fixture().await;

    // A parent workflow execution, as a loop iteration always has.
    let workflow = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, name, user_id, module_uri, graph_json) \
         VALUES ($1, $2, $3, 'test-module', '{}'::jsonb)",
    )
    .bind(workflow)
    .bind(format!("wf-{workflow}"))
    .bind(f.user)
    .execute(&f.pool)
    .await
    .expect("seed workflow");
    let wf_exec = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflow_executions (id, workflow_id, user_id, status, actor_id) \
         VALUES ($1, $2, $3, 'running', $4)",
    )
    .bind(wf_exec)
    .bind(workflow)
    .bind(f.user)
    .bind(f.actor)
    .execute(&f.pool)
    .await
    .expect("seed workflow_execution");

    let store =
        talos_engine::module_execution_store::PostgresModuleExecutionStore::new(f.pool.clone());
    // The id the loop body now dispatches under.
    let iter_exec_id = Uuid::new_v4();
    store
        .record_started(ExecutionStartedContext {
            id: iter_exec_id,
            module_id: f.module,
            user_id: f.user,
            workflow_execution_id: wf_exec,
            input: &serde_json::json!({ "iteration": 0 }),
            trigger_type: "webhook",
            race_safe_status: true,
            actor_id: Some(f.actor),
        })
        .await
        .expect("record_started must succeed for a loop iteration");

    // Now the worker's log line for that job id has somewhere to land.
    let outcome = f
        .service
        .add_log(
            iter_exec_id,
            LogLevel::Info,
            "loop body says hello".to_string(),
            None,
        )
        .await
        .expect("add_log");
    assert_eq!(
        outcome,
        LogWriteOutcome::Inserted,
        "with a real row the loop iteration's logs persist — the whole point of D1"
    );

    // And they are reachable through the workflow-scoped tail the operator
    // uses, via module_execution_logs → module_executions.workflow_execution_id.
    let joined: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM module_execution_logs mel \
         JOIN module_executions me ON me.id = mel.execution_id \
         WHERE me.workflow_execution_id = $1",
    )
    .bind(wf_exec)
    .fetch_one(&f.pool)
    .await
    .expect("join count");
    assert_eq!(
        joined, 1,
        "the line must be reachable from the PARENT execution — an operator tails the workflow, \
         not the iteration"
    );
}
