//! Cost attribution: the per-node fuel ledger writer.
//!
//! Records fuel consumed by each node execution into `execution_cost_rollup`.
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

/// Record fuel consumption for a single node execution.
/// Called fire-and-forget from the engine after each node completes.
///
/// MCP-441: INSERT failures used to be swallowed by `let _ = ...await`.
/// If a schema-mismatch or FK violation hit (e.g. a migration is run
/// out of order), every fuel record was silently dropped and the cost
/// reports went to zero — operators only noticed when they queried
/// costs and saw nothing. Log at WARN so the failure is observable
/// while preserving the fire-and-forget contract.
pub fn record_fuel(
    pool: PgPool,
    actor_id: Option<Uuid>,
    workflow_id: Uuid,
    execution_id: Uuid,
    node_id: String,
    module_id: Option<Uuid>,
    fuel_consumed: i64,
    wall_time_ms: i64,
    max_fuel: Option<i64>,
) {
    tokio::spawn(async move {
        if let Err(e) = sqlx::query(
            "INSERT INTO execution_cost_rollup \
             (actor_id, workflow_id, execution_id, node_id, module_id, fuel_consumed, wall_time_ms, max_fuel) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(actor_id)
        .bind(workflow_id)
        .bind(execution_id)
        .bind(&node_id)
        .bind(module_id)
        .bind(fuel_consumed)
        .bind(wall_time_ms)
        .bind(max_fuel)
        .execute(&pool)
        .await
        {
            tracing::warn!(
                %workflow_id,
                %execution_id,
                node_id = %node_id,
                error = %e,
                "record_fuel INSERT failed — cost rollup row dropped"
            );
        }
    });
}
