//! Cost attribution: the fuel ledger writer.
//!
//! Records the fuel of every verified dispatch attempt into
//! `execution_cost_rollup`, and adds it to the attempt's
//! `module_executions.fuel_consumed`. This crate is the ONE writer of both
//! (2026-09-29). Until then the figure was read out of the module's OUTPUT
//! (`__fuel_consumed__`), which the worker can stamp only into a JSON object
//! and which a failed run does not have, so the hourly fuel budget missed
//! non-object outputs, failed and fuel-exhausted attempts, retried attempts,
//! loop bodies and module-bound dispatch. The figure now comes from the
//! signed `JobResult` via `talos_workflow_job_protocol::spent_fuel`, and the
//! identity from the CONTROLLER's own records, never from the worker.
//! Its readers live with their consumers — the hourly actor fuel gate
//! (`WorkflowRepository::create_execution_under_concurrency_limit`), adaptive
//! fuel, the fuel-headroom gauge, per-module fuel stats and the performance
//! report.
//!
//! Package BN (2026-09-15): this crate also carried `get_actor_cost_report` and
//! `check_fuel_budget`, a daily fuel budget with an alert threshold. Neither had
//! a caller anywhere in the workspace, nothing wrote the
//! `actor_budget_policies.fuel_budget_daily` / `fuel_alert_threshold_pct`
//! columns they read (0 of 5 policy rows set the budget), and `alert_triggered`
//! was computed for a report nobody requested — so a "daily fuel budget" existed
//! as a column, a comment and a documented backstop, and enforced nothing. The
//! functions and both columns are deleted (migration `20260915120000`).

use sqlx::PgPool;
use uuid::Uuid;

/// Whether the dispatch attempt a fuel row records succeeded.
///
/// The hourly fuel budget counts every row: a failed attempt spent its fuel.
/// Learners (adaptive fuel ceilings, the fuel usage report, the
/// fuel-exhaustion advisor) read `Completed` rows only, because a
/// fuel-exhausted attempt sits at its limit and would raise a learned ceiling
/// after every exhaustion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptOutcome {
    /// The attempt succeeded.
    Completed,
    /// The attempt failed, timed out, or ran out of fuel.
    Failed,
}

impl AttemptOutcome {
    /// The `execution_cost_rollup.outcome` spelling (CHECK-constrained).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }
}

/// One verified engine dispatch attempt's fuel. Every identity field comes
/// from the controller's dispatch context (`DispatchJob`), never the worker.
#[derive(Debug, Clone)]
pub struct DispatchFuel {
    /// The attempt's `module_executions` row (the wire `job_id`). A retried
    /// attempt shares its row, so the row's figure is the SUM of attempts.
    pub module_execution_id: Uuid,
    /// The workflow execution that owned the dispatch.
    pub execution_id: Uuid,
    /// The workflow the engine ran (a sub-workflow's own id). `None` = not
    /// known; the row then carries no workflow and is excluded from every
    /// report that joins `workflows`, but still counts toward the budget.
    pub workflow_id: Option<Uuid>,
    /// The node's graph label.
    pub node_label: Option<String>,
    /// The module that ran.
    pub module_id: Option<Uuid>,
    /// The actor the budget is charged to.
    pub actor_id: Option<Uuid>,
    /// The ROOT run's actor when the attempt ran inside a sub-workflow: the
    /// root is charged too, so a run cannot move its spend into children
    /// (security review 2026-10-14, G-8). The hourly fuel cap counts a row
    /// once for either actor.
    pub root_actor_id: Option<Uuid>,
    /// Fuel consumed (`> 0`).
    pub consumed: u64,
    /// The limit the worker enforced, when reported.
    pub limit: Option<u64>,
    /// Worker-measured execution time of the attempt.
    pub wall_time_ms: u64,
    /// Whether the attempt succeeded.
    pub outcome: AttemptOutcome,
}

fn db_i64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// The rollup INSERT for an engine attempt.
pub const INSERT_DISPATCH_FUEL_SQL: &str = "INSERT INTO execution_cost_rollup \
     (actor_id, workflow_id, execution_id, node_id, module_id, fuel_consumed, \
      wall_time_ms, max_fuel, outcome, root_actor_id) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)";

/// Adds an attempt's fuel to its `module_executions` row. Only the fuel
/// column is written: a status or `completed_at` write belongs to the
/// finalizers.
pub const ADD_MODULE_EXECUTION_FUEL_SQL: &str = "UPDATE module_executions \
     SET fuel_consumed = COALESCE(fuel_consumed, 0) + $2 \
     WHERE id = $1";

/// Record one engine dispatch attempt's fuel in both ledgers, atomically.
///
/// # Errors
/// Any database error; nothing is written in that case.
pub async fn record_dispatch_fuel(pool: &PgPool, fuel: &DispatchFuel) -> Result<(), sqlx::Error> {
    let consumed = db_i64(fuel.consumed);
    let mut tx = pool.begin().await?;
    sqlx::query(INSERT_DISPATCH_FUEL_SQL)
        .bind(fuel.actor_id)
        .bind(fuel.workflow_id)
        .bind(fuel.execution_id)
        .bind(fuel.node_label.as_deref())
        .bind(fuel.module_id)
        .bind(consumed)
        .bind(db_i64(fuel.wall_time_ms))
        .bind(fuel.limit.map(db_i64))
        .bind(fuel.outcome.as_str())
        .bind(fuel.root_actor_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(ADD_MODULE_EXECUTION_FUEL_SQL)
        .bind(fuel.module_execution_id)
        .bind(consumed)
        .execute(&mut *tx)
        .await?;
    tx.commit().await
}

/// Fire-and-forget [`record_dispatch_fuel`] for the dispatch hot path.
/// A failure is logged at WARN: a dropped row under-counts the budget, which
/// must be observable (MCP-441).
pub fn spawn_record_dispatch_fuel(pool: PgPool, fuel: DispatchFuel) {
    tokio::spawn(async move {
        if let Err(e) = record_dispatch_fuel(&pool, &fuel).await {
            tracing::warn!(
                module_execution_id = %fuel.module_execution_id,
                execution_id = %fuel.execution_id,
                error = %e,
                "fuel record failed — attempt not counted toward the fuel budget"
            );
        }
    });
}

/// Record a MODULE-BOUND attempt's fuel (webhook, Gmail/Calendar/GCP push,
/// DLQ replay). There is no workflow and no graph node; the actor, module and
/// execution are read from the attempt's own `module_executions` row inside
/// the same statement, so identity comes from the controller's record and
/// the two ledgers are written atomically.
///
/// ONCE per signed result (security review 2026-10-14, B-1): the rollup row
/// carries the result's nonce, `(execution_id, result_nonce)` is unique, and
/// `module_executions.fuel_consumed` is added to only when that row was
/// inserted. A copy of one result delivered again — to this replica or to
/// another, whose replay cache never saw it — records nothing. An empty nonce
/// binds NULL and is not deduplicated (an unsigned result; never a verified
/// one).
pub const RECORD_MODULE_BOUND_FUEL_SQL: &str = "WITH me AS ( \
         SELECT actor_id, module_id, COALESCE(workflow_execution_id, id) AS execution_id \
         FROM module_executions WHERE id = $1 \
     ), ins AS ( \
         INSERT INTO execution_cost_rollup \
             (actor_id, workflow_id, execution_id, node_id, module_id, fuel_consumed, \
              wall_time_ms, max_fuel, outcome, result_nonce) \
         SELECT actor_id, NULL, execution_id, NULL, module_id, $2, $3, $4, $5, NULLIF($6, '') \
         FROM me \
         ON CONFLICT (execution_id, result_nonce) WHERE result_nonce IS NOT NULL DO NOTHING \
         RETURNING 1 \
     ), upd AS ( \
         UPDATE module_executions \
         SET fuel_consumed = COALESCE(fuel_consumed, 0) + $2 \
         WHERE id = $1 AND EXISTS (SELECT 1 FROM ins) \
         RETURNING 1 \
     ) \
     SELECT EXISTS (SELECT 1 FROM me) AS found, EXISTS (SELECT 1 FROM upd) AS recorded";

/// What [`record_module_bound_fuel`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleBoundFuelRecord {
    /// Both ledgers were written.
    Recorded,
    /// This result's fuel was already recorded; nothing was written.
    AlreadyRecorded,
    /// The attempt has no `module_executions` row; nothing was written.
    NoRow,
}

/// See [`RECORD_MODULE_BOUND_FUEL_SQL`]. `result_nonce` is the VERIFIED
/// result's own `result_nonce`.
///
/// # Errors
/// Any database error.
pub async fn record_module_bound_fuel(
    pool: &PgPool,
    module_execution_id: Uuid,
    result_nonce: &str,
    consumed: u64,
    limit: Option<u64>,
    wall_time_ms: u64,
    outcome: AttemptOutcome,
) -> Result<ModuleBoundFuelRecord, sqlx::Error> {
    let (found, recorded): (bool, bool) = sqlx::query_as(RECORD_MODULE_BOUND_FUEL_SQL)
        .bind(module_execution_id)
        .bind(db_i64(consumed))
        .bind(db_i64(wall_time_ms))
        .bind(limit.map(db_i64))
        .bind(outcome.as_str())
        .bind(result_nonce)
        .fetch_one(pool)
        .await?;
    Ok(match (found, recorded) {
        (_, true) => ModuleBoundFuelRecord::Recorded,
        (true, false) => ModuleBoundFuelRecord::AlreadyRecorded,
        (false, false) => ModuleBoundFuelRecord::NoRow,
    })
}

/// Fire-and-forget [`record_module_bound_fuel`].
pub fn spawn_record_module_bound_fuel(
    pool: PgPool,
    module_execution_id: Uuid,
    result_nonce: String,
    consumed: u64,
    limit: Option<u64>,
    wall_time_ms: u64,
    outcome: AttemptOutcome,
) {
    tokio::spawn(async move {
        match record_module_bound_fuel(
            &pool,
            module_execution_id,
            &result_nonce,
            consumed,
            limit,
            wall_time_ms,
            outcome,
        )
        .await
        {
            Ok(ModuleBoundFuelRecord::Recorded) => {}
            Ok(ModuleBoundFuelRecord::AlreadyRecorded) => tracing::warn!(
                target: "talos_security",
                %module_execution_id,
                "fuel for this signed result was already recorded — a repeated \
                 delivery of one result; not counted again"
            ),
            Ok(ModuleBoundFuelRecord::NoRow) => tracing::warn!(
                %module_execution_id,
                "fuel record found no module_executions row — attempt not counted"
            ),
            Err(e) => tracing::warn!(
                %module_execution_id,
                error = %e,
                "fuel record failed — attempt not counted toward the fuel budget"
            ),
        }
    });
}
