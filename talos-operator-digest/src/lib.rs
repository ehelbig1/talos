//! # Operator digest — the autonomy cockpit aggregation
//!
//! A single, time-windowed view of what the platform's AUTONOMOUS machinery
//! did, learned, and needs the operator to decide — the data behind the
//! `get_operator_digest` MCP tool, the `operator_digest` system node (and thus
//! the overnight-autonomy email), and the frontend "Autonomy" page.
//!
//! It is a **superset** of the `assistant_report` reader
//! (`talos-engine/src/assistant_report_reader.rs`): it reuses that report's
//! execution/cost/ML/judge rollups and ADDS the three things nothing else
//! surfaces —
//!   1. **Ran** — executions grouped by `trigger_type`, so AUTONOMOUS runs
//!      (scheduled / webhook / actor_dispatch) are legible apart from `manual`
//!      ones, plus schedule health.
//!   2. **Learned** — counts of what the loops PRODUCED (memory writes by
//!      `metadata.kind`, per-actor rank-weight fits) alongside ML loop health.
//!   3. **Needs me** — a UNIFIED decision inbox merging the four silos: pending
//!      approvals, ops-alert corrections, autonomous failures, and the active
//!      ops-alert backlog.
//!
//! ## Tenancy
//! Every query is scoped by the `user_id` the caller passes in (the execution's
//! resolved identity for the node path; the authenticated caller for the MCP /
//! GraphQL paths). No query is cross-tenant.
//!
//! ## Resilience
//! Each panel is best-effort: a failing data plane logs a warning and emits an
//! empty/partial section rather than sinking the whole digest — the email must
//! still send when e.g. the ML tables are momentarily unavailable.

use chrono::Utc;
use serde_json::{json, Value as JsonValue};
use sqlx::PgPool;
use talos_actor_repository::ActorRepository;
use talos_execution_repository::ExecutionRepository;
use talos_ops_alerts_repository::OpsAlertRepository;
use talos_schedule_repo::ScheduleRepository;
use uuid::Uuid;

/// `provenance->>'trigger_type'` values that denote AUTONOMOUS activity —
/// everything the platform did without an operator pressing a button. Anything
/// not in this set (i.e. `manual`) is operator-initiated.
const AUTONOMOUS_TRIGGERS: &[&str] = &["scheduled", "webhook", "actor_dispatch", "agent_dispatch"];

fn is_autonomous(trigger_type: &str) -> bool {
    AUTONOMOUS_TRIGGERS.contains(&trigger_type)
}

/// Composes the domain repositories into the operator digest. Cheap to
/// construct (each repo just wraps the shared pool via `Arc` clone).
pub struct OperatorDigestService {
    pool: PgPool,
    executions: ExecutionRepository,
    actors: ActorRepository,
    ops_alerts: OpsAlertRepository,
    schedules: ScheduleRepository,
}

impl OperatorDigestService {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            executions: ExecutionRepository::new(pool.clone()),
            actors: ActorRepository::new(pool.clone()),
            ops_alerts: OpsAlertRepository::new(pool.clone()),
            schedules: ScheduleRepository::new(pool.clone()),
            pool,
        }
    }

    /// Build the three-panel digest for `user_id` over the trailing `days`
    /// (clamped to `[1, 31]`). Best-effort per panel; the outer result only
    /// errors on a catastrophic failure that leaves nothing to report.
    pub async fn snapshot(&self, user_id: Uuid, days: u32) -> anyhow::Result<JsonValue> {
        let days = days.clamp(1, 31) as i32;

        Ok(json!({
            "window_days": days,
            "generated_at": Utc::now(),
            "ran": self.ran_panel(user_id, days).await,
            "learned": self.learned_panel(user_id, days).await,
            "needs_me": self.needs_me_panel(user_id, days).await,
            "cost": self.cost_panel(user_id, days).await,
        }))
    }

    /// Panel 1 — what ran, with AUTONOMOUS runs legible apart from manual ones.
    async fn ran_panel(&self, user_id: Uuid, days: i32) -> JsonValue {
        let by_trigger = self
            .executions
            .execution_counts_by_trigger_type(user_id, days)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(%user_id, error = %e, "operator_digest: trigger-type ledger failed");
                Vec::new()
            });

        let (mut autonomous_total, mut manual_total, mut failed_total) = (0i64, 0i64, 0i64);
        let by_trigger_type: Vec<JsonValue> = by_trigger
            .iter()
            .map(|(tt, total, completed, failed)| {
                let auto = is_autonomous(tt);
                if auto {
                    autonomous_total += total;
                } else {
                    manual_total += total;
                }
                failed_total += failed;
                json!({
                    "trigger_type": tt,
                    "autonomous": auto,
                    "runs": total,
                    "completed": completed,
                    "failed": failed,
                })
            })
            .collect();

        let by_workflow = self
            .executions
            .weekly_workflow_stats(user_id, days)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|(name, total, completed, failed)| {
                json!({ "name": name, "runs": total, "completed": completed, "failed": failed })
            })
            .collect::<Vec<_>>();

        let now = Utc::now();
        let schedules = self
            .schedules
            .list_for_user(user_id)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|s| {
                // "overdue" = enabled with a next_trigger_at in the past — a
                // schedule the ticker should have fired but hasn't.
                let overdue = s.is_enabled && s.next_trigger_at.is_some_and(|t| t < now);
                json!({
                    "workflow_name": s.workflow_name,
                    "cron": s.cron_expression,
                    "timezone": s.timezone,
                    "enabled": s.is_enabled,
                    "last_triggered_at": s.last_triggered_at,
                    "next_trigger_at": s.next_trigger_at,
                    "overdue": overdue,
                })
            })
            .collect::<Vec<_>>();

        json!({
            "autonomous_runs": autonomous_total,
            "manual_runs": manual_total,
            "failed_runs": failed_total,
            "by_trigger_type": by_trigger_type,
            "by_workflow": by_workflow,
            "schedules": schedules,
        })
    }

    /// Panel 2 — what the autonomous loops PRODUCED + learned.
    async fn learned_panel(&self, user_id: Uuid, days: i32) -> JsonValue {
        let memory_writes_by_kind =
            talos_memory::count_recent_writes_by_kind(&self.pool, user_id, days)
                .await
                .unwrap_or_else(|e| {
                    tracing::warn!(%user_id, error = %e, "operator_digest: memory-by-kind failed");
                    Vec::new()
                })
                .into_iter()
                .map(|(kind, count)| json!({ "kind": kind, "count": count }))
                .collect::<Vec<_>>();

        let rank_fits = self
            .actors
            .recent_rank_fits(user_id, days)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|(actor, n_examples, fitted_at)| {
                json!({ "actor": actor, "n_examples": n_examples, "fitted_at": fitted_at })
            })
            .collect::<Vec<_>>();

        // ML loop health (per-model lifecycle, promoted version, shadow
        // agreement) — reused verbatim from the assistant report's source.
        let ml = talos_ml::loop_health(&self.pool, user_id)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(%user_id, error = %e, "operator_digest: ml loop_health failed");
                json!({ "available": false })
            });

        let judge_scores = self
            .executions
            .weekly_judge_scores(user_id, days)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|s| {
                json!({
                    "name": s.workflow_name,
                    "runs": s.runs,
                    "avg_score": s.avg_score,
                    "pass_rate": s.pass_rate,
                    "worst_score": s.worst_score,
                })
            })
            .collect::<Vec<_>>();

        json!({
            "memory_writes_by_kind": memory_writes_by_kind,
            "rank_fits": rank_fits,
            "ml": ml,
            "judge_scores": judge_scores,
        })
    }

    /// Panel 3 — the UNIFIED operator-decision inbox: the four previously-siloed
    /// "needs a human" sources in one place, with a single `total` so the email
    /// subject can say "3 things need you."
    async fn needs_me_panel(&self, user_id: Uuid, days: i32) -> JsonValue {
        let approvals = self
            .executions
            .list_pending_approvals_for_user(user_id, 25)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|a| {
                json!({
                    "execution_id": a.execution_id,
                    "workflow_name": a.workflow_name,
                    "node_id": a.node_id,
                    "required_for": a.required_for,
                    "requested_at": a.requested_at,
                })
            })
            .collect::<Vec<_>>();

        let corrections = self
            .ops_alerts
            .correction_candidates(user_id, 5)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|a| {
                json!({
                    "id": a.id,
                    "title": a.title,
                    "severity": a.severity,
                    "source": a.source,
                    "occurrence_count": a.occurrence_count,
                })
            })
            .collect::<Vec<_>>();

        // Active ops-alert backlog (severity/source rollup) — the standing
        // triage load, not just this window's new items.
        let ops_backlog = self
            .ops_alerts
            .digest(user_id)
            .await
            .map(|d| {
                json!({
                    "active_by_severity": d.active_by_severity.iter()
                        .map(|(s, c)| json!({ "severity": s, "count": c })).collect::<Vec<_>>(),
                    "new_last_24h": d.new_last_24h,
                    "reopened_active": d.reopened_active,
                })
            })
            .unwrap_or_else(|e| {
                tracing::warn!(%user_id, error = %e, "operator_digest: ops digest failed");
                json!({ "active_by_severity": [], "new_last_24h": 0, "reopened_active": 0 })
            });

        // Autonomous failures in the window — from the trigger-type ledger, so
        // the count matches the "Ran" panel exactly.
        let autonomous_failures: i64 = self
            .executions
            .execution_counts_by_trigger_type(user_id, days)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|(tt, _, _, _)| is_autonomous(tt))
            .map(|(_, _, _, failed)| failed)
            .sum();

        let total = approvals.len() as i64 + corrections.len() as i64 + autonomous_failures;

        json!({
            "total": total,
            "pending_approvals": approvals,
            "ops_alert_corrections": corrections,
            "autonomous_failures": autonomous_failures,
            "ops_backlog": ops_backlog,
        })
    }

    /// Cost line — fuel + wall time + per-(provider, model) LLM token rollup.
    async fn cost_panel(&self, user_id: Uuid, days: i32) -> JsonValue {
        let (fuel_total, wall_ms_total) = self
            .executions
            .weekly_fuel_totals(user_id, days)
            .await
            .unwrap_or((0, 0));

        let llm_tokens = self
            .actors
            .llm_usage_by_user_window(user_id, days)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|u| {
                json!({
                    "provider": u.provider,
                    "model": u.model,
                    "prompt_tokens": u.prompt_tokens,
                    "completion_tokens": u.completion_tokens,
                    "calls": u.calls,
                })
            })
            .collect::<Vec<_>>();

        json!({
            "fuel_total": fuel_total,
            "wall_time_ms_total": wall_ms_total,
            "llm_tokens": llm_tokens,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autonomous_classification() {
        assert!(is_autonomous("scheduled"));
        assert!(is_autonomous("webhook"));
        assert!(is_autonomous("actor_dispatch"));
        assert!(is_autonomous("agent_dispatch")); // deprecated alias for actor_dispatch
        assert!(!is_autonomous("manual"));
        assert!(!is_autonomous("api"));
        assert!(!is_autonomous("")); // absent → treated as manual by the query's COALESCE
    }
}
