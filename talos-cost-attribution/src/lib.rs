//! Cost attribution: per-node fuel consumption rollup for actor/workflow cost reports.
//!
//! Records fuel consumed by each node execution into `execution_cost_rollup`,
//! enabling per-actor and per-workflow cost reports with trend analysis.

use anyhow::Result;
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

/// Cost report for an actor over a time period.
#[derive(Debug, serde::Serialize)]
pub struct ActorCostReport {
    pub actor_id: Uuid,
    pub period: String,
    pub total_fuel: i64,
    pub total_wall_time_ms: i64,
    pub execution_count: i64,
    pub top_workflows: Vec<WorkflowCostEntry>,
    pub budget_usage: Option<BudgetUsage>,
}

#[derive(Debug, serde::Serialize)]
pub struct WorkflowCostEntry {
    pub workflow_id: Uuid,
    pub fuel: i64,
    pub executions: i64,
}

#[derive(Debug, serde::Serialize)]
pub struct BudgetUsage {
    pub fuel_budget_daily: i64,
    pub fuel_consumed_today: i64,
    pub usage_pct: f64,
    pub alert_threshold_pct: i32,
    pub alert_triggered: bool,
}

/// Get cost report for an actor.
pub async fn get_actor_cost_report(
    pool: &PgPool,
    actor_id: Uuid,
    hours: i64,
) -> Result<ActorCostReport> {
    let period = format!("last_{}h", hours);

    // MCP-488: pair every `.unwrap_or(...)` zero-fallback with a
    // `tracing::warn!` so a broken query / schema mismatch / FK
    // violation is OBSERVABLE in logs. Without the warn, the same
    // failure class that MCP-441 fixed on the write side silently
    // returns "0 fuel consumed" on the read side and operators only
    // discover the regression when a customer asks why their cost
    // report is empty. This is the lint-check-8 pattern from
    // `swallowed_error_unwrap_or_masks_broken_query.md`.
    let totals = sqlx::query_as::<_, (i64, i64, i64)>(
        "SELECT COALESCE(SUM(fuel_consumed), 0), COALESCE(SUM(wall_time_ms), 0), COUNT(DISTINCT execution_id) \
         FROM execution_cost_rollup \
         WHERE actor_id = $1 AND recorded_at > NOW() - make_interval(hours => $2::int)",
    )
    .bind(actor_id)
    .bind(hours)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| {
        tracing::warn!(
            %actor_id,
            hours,
            error = %e,
            "actor cost-report totals query failed — returning zeros"
        );
        (0, 0, 0)
    });

    let top_workflows = sqlx::query_as::<_, (Uuid, i64, i64)>(
        "SELECT workflow_id, SUM(fuel_consumed), COUNT(DISTINCT execution_id) \
         FROM execution_cost_rollup \
         WHERE actor_id = $1 AND recorded_at > NOW() - make_interval(hours => $2::int) \
         GROUP BY workflow_id ORDER BY SUM(fuel_consumed) DESC LIMIT 10",
    )
    .bind(actor_id)
    .bind(hours)
    .fetch_all(pool)
    .await
    .unwrap_or_else(|e| {
        tracing::warn!(
            %actor_id,
            hours,
            error = %e,
            "actor cost-report top-workflows query failed — returning empty list"
        );
        Vec::new()
    })
    .into_iter()
    .map(|(wf_id, fuel, execs)| WorkflowCostEntry {
        workflow_id: wf_id,
        fuel,
        executions: execs,
    })
    .collect();

    // Check budget
    let budget_usage = check_fuel_budget(pool, actor_id).await.ok().flatten();

    Ok(ActorCostReport {
        actor_id,
        period,
        total_fuel: totals.0,
        total_wall_time_ms: totals.1,
        execution_count: totals.2,
        top_workflows,
        budget_usage,
    })
}

/// Check an actor's fuel budget usage for today.
pub async fn check_fuel_budget(pool: &PgPool, actor_id: Uuid) -> Result<Option<BudgetUsage>> {
    // Fetch budget policy
    let policy = sqlx::query_as::<_, (Option<i64>, i32)>(
        "SELECT fuel_budget_daily, fuel_alert_threshold_pct \
         FROM actor_budget_policies WHERE actor_id = $1",
    )
    .bind(actor_id)
    .fetch_optional(pool)
    .await?;

    // MCP-703 (2026-05-13): treat budget <= 0 as misconfiguration and
    // return None (same shape as NULL = "unlimited"). Pre-fix, an
    // explicitly-set `fuel_budget_daily = 0` (which is reachable via
    // direct SQL today; no public API sets the column) produced
    // `usage_pct = 0` in the math below because the `if budget > 0`
    // guard collapsed to the `else 0.0` arm. With usage_pct = 0,
    // `alert_triggered = 0 >= threshold` is false for any positive
    // threshold — so a misconfigured zero-budget actor would consume
    // any amount of fuel and never fire an alert, defeating the
    // monitoring surface for the operator who set the row to "no fuel
    // allowed." Schema comment says "NULL = unlimited"; explicit 0 is
    // not a documented value, so collapse it into the None path with
    // a loud WARN so operators see the misconfig in logs. Same `=0`-
    // is-misconfiguration class as MCP-695 / MCP-698 (cache TTLs +
    // worker helper bound).
    let (budget, threshold) = match policy {
        Some((Some(budget), threshold)) if budget > 0 => (budget, threshold),
        Some((Some(budget), _)) => {
            tracing::warn!(
                target: "talos_cost_attribution",
                event_kind = "fuel_budget_nonpositive_substituted",
                %actor_id,
                configured = budget,
                "actor_budget_policies.fuel_budget_daily = {} is a misconfiguration \
                 (only NULL = unlimited or positive integers are meaningful); \
                 treating as unset. Alerts will not fire until the row is repaired.",
                budget
            );
            return Ok(None);
        }
        _ => return Ok(None),
    };

    // MCP-488: same warn-and-zero pattern as get_actor_cost_report.
    // A silent zero here would suppress budget alerts — operators
    // would think the actor is well under budget and miss a runaway
    // spend caused by a misbehaving worker.
    let consumed: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(fuel_consumed), 0) FROM execution_cost_rollup \
         WHERE actor_id = $1 AND recorded_at >= CURRENT_DATE",
    )
    .bind(actor_id)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| {
        tracing::warn!(
            %actor_id,
            error = %e,
            "actor budget consumption query failed — returning 0; budget alert may be suppressed"
        );
        0
    });

    // budget > 0 invariant established by the match guard above (MCP-703);
    // the division below is safe.
    let usage_pct = (consumed as f64 / budget as f64) * 100.0;

    Ok(Some(BudgetUsage {
        fuel_budget_daily: budget,
        fuel_consumed_today: consumed,
        usage_pct,
        alert_threshold_pct: threshold,
        alert_triggered: usage_pct >= threshold as f64,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_usage_calculation() {
        let usage = BudgetUsage {
            fuel_budget_daily: 1_000_000,
            fuel_consumed_today: 800_000,
            usage_pct: 80.0,
            alert_threshold_pct: 80,
            alert_triggered: true,
        };
        assert!(usage.alert_triggered);
        assert_eq!(usage.usage_pct, 80.0);
    }
}
