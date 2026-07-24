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
use talos_analytics_repository::{failure_rate_pct, AnalyticsRepository, TopFailureRow};
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
    analytics: AnalyticsRepository,
}

impl OperatorDigestService {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            executions: ExecutionRepository::new(pool.clone()),
            actors: ActorRepository::new(pool.clone()),
            ops_alerts: OpsAlertRepository::new(pool.clone()),
            schedules: ScheduleRepository::new(pool.clone()),
            analytics: AnalyticsRepository::new(pool.clone()),
            pool,
        }
    }

    /// Build the digest for `user_id` over the trailing `days` (clamped to
    /// `[1, 31]`): the three core panels (ran / learned / needs_me) plus the
    /// cost line and the fixed-24h reliability line. Best-effort per panel;
    /// the outer result only errors on a catastrophic failure that leaves
    /// nothing to report.
    pub async fn snapshot(&self, user_id: Uuid, days: u32) -> anyhow::Result<JsonValue> {
        let days = days.clamp(1, 31) as i32;

        Ok(json!({
            "window_days": days,
            "generated_at": Utc::now(),
            "ran": self.ran_panel(user_id, days).await,
            "learned": self.learned_panel(user_id, days).await,
            "needs_me": self.needs_me_panel(user_id, days).await,
            "cost": self.cost_panel(user_id, days).await,
            // Additive (2026-07-24): existing consumers (operator_digest
            // system node, get_operator_digest MCP tool, the frontend
            // Autonomy page) pass the snapshot through untouched, so a new
            // top-level section is safe. ALWAYS a fixed 24h window — it
            // mirrors the health dashboard's incident lens — regardless of
            // `window_days`.
            "reliability": self.reliability_panel(user_id).await,
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

    /// Reliability line — 24h failure rate + failed/completed counts + the
    /// top 3 failing workflows by 24h failures. Fixed 24h window by design
    /// (independent of `window_days`): it reuses the health dashboard's
    /// grouped rollup (`AnalyticsRepository::get_top_failures_24h`) and its
    /// failure-rate definition, so the digest and the dashboard can never
    /// disagree about whether last night was an incident.
    ///
    /// Best-effort like every other panel: an unavailable analytics plane
    /// yields `{ "available": false }` — never `0%` masquerading as healthy.
    async fn reliability_panel(&self, user_id: Uuid) -> JsonValue {
        let counts = match self.analytics.get_health_summary_counts(user_id).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(%user_id, error = %e, "operator_digest: reliability counts failed");
                return json!({ "available": false });
            }
        };
        let top = self
            .analytics
            .get_top_failures_24h(user_id)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(%user_id, error = %e, "operator_digest: top-failures rollup failed");
                Vec::new()
            });
        build_reliability_section(counts.failed_24h, counts.completed_24h, &top)
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

/// A 24h failure rate above this is flagged `degraded` (the status line
/// says so explicitly, so LLM compose nodes and the email template carry
/// the wording through without re-deriving the threshold).
const RELIABILITY_DEGRADED_THRESHOLD_PCT: f64 = 10.0;

/// Pure builder for the reliability section — testable without a DB.
///
/// `failure_rate_24h_pct` is `null` when the 24h window has no terminal
/// executions (rate over zero runs is meaningless; `0.0` would falsely
/// read "healthy"), matching `failure_rate_pct`'s contract. `degraded`
/// flips only when the rate strictly exceeds
/// [`RELIABILITY_DEGRADED_THRESHOLD_PCT`]. Error messages are previews,
/// not payloads — capped at ~200 bytes on a char boundary, same policy as
/// the health dashboard.
fn build_reliability_section(
    failed_24h: i64,
    completed_24h: i64,
    top_failures: &[TopFailureRow],
) -> JsonValue {
    let rate = failure_rate_pct(failed_24h, completed_24h);
    let degraded = rate.is_some_and(|r| r > RELIABILITY_DEGRADED_THRESHOLD_PCT);
    let status_line = match rate {
        None => "No terminal executions in the last 24h.".to_string(),
        Some(r) if degraded => format!(
            "24h failure rate {r}% ({failed_24h} failed / {completed_24h} completed) — DEGRADED (above the {RELIABILITY_DEGRADED_THRESHOLD_PCT}% threshold)."
        ),
        Some(r) => format!(
            "24h failure rate {r}% ({failed_24h} failed / {completed_24h} completed) — healthy."
        ),
    };

    let top: Vec<JsonValue> = top_failures
        .iter()
        .take(3)
        .map(|r| {
            json!({
                "workflow_id": r.workflow_id,
                "workflow_name": r.workflow_name,
                "failed_count_24h": r.failed_count,
                "last_failed_at": r.last_failed_at,
                "latest_error_preview": r
                    .latest_error_message
                    .as_deref()
                    .map(|m| talos_text_util::bounded_preview(m, 200).into_owned()),
            })
        })
        .collect();

    json!({
        "available": true,
        "failed_24h": failed_24h,
        "completed_24h": completed_24h,
        "failure_rate_24h_pct": rate,
        "degraded": degraded,
        "status_line": status_line,
        "top_failing_workflows_24h": top,
    })
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

    fn top_row(name: &str, failed: i64, err: Option<&str>) -> TopFailureRow {
        TopFailureRow {
            workflow_id: Uuid::new_v4(),
            workflow_name: name.to_string(),
            failed_count: failed,
            last_failed_at: Some(Utc::now()),
            latest_error_message: err.map(str::to_string),
        }
    }

    #[test]
    fn reliability_degraded_above_ten_percent() {
        // The motivating incident shape: 125 failed / 245 completed → 33.8%.
        let s = build_reliability_section(125, 245, &[]);
        assert_eq!(s["available"], true);
        assert_eq!(s["failed_24h"], 125);
        assert_eq!(s["completed_24h"], 245);
        assert_eq!(s["failure_rate_24h_pct"], 33.8);
        assert_eq!(s["degraded"], true);
        let line = s["status_line"].as_str().unwrap();
        assert!(
            line.contains("33.8%"),
            "status line carries the rate: {line}"
        );
        assert!(
            line.contains("DEGRADED"),
            "status line flags the threshold: {line}"
        );
    }

    #[test]
    fn reliability_healthy_at_or_below_threshold() {
        // Exactly 10.0% is NOT degraded — the flag fires strictly above.
        let s = build_reliability_section(1, 9, &[]);
        assert_eq!(s["failure_rate_24h_pct"], 10.0);
        assert_eq!(s["degraded"], false);
        assert!(s["status_line"].as_str().unwrap().contains("healthy"));

        let s = build_reliability_section(0, 50, &[]);
        assert_eq!(s["failure_rate_24h_pct"], 0.0);
        assert_eq!(s["degraded"], false);
    }

    #[test]
    fn reliability_null_rate_when_no_terminal_executions() {
        let s = build_reliability_section(0, 0, &[]);
        assert!(s["failure_rate_24h_pct"].is_null());
        assert_eq!(s["degraded"], false);
        assert!(s["status_line"]
            .as_str()
            .unwrap()
            .contains("No terminal executions"));
    }

    #[test]
    fn reliability_top_failures_capped_at_three_with_bounded_error_preview() {
        let long_err = "x".repeat(1000);
        let rows = vec![
            top_row("wf-a", 12, Some(&long_err)),
            top_row("wf-b", 7, Some("connection refused")),
            top_row("wf-c", 3, None),
            top_row("wf-d", 1, Some("should be cut by the top-3 cap")),
        ];
        let s = build_reliability_section(23, 100, &rows);
        let top = s["top_failing_workflows_24h"].as_array().unwrap();
        assert_eq!(top.len(), 3, "top failing workflows capped at 3");
        assert_eq!(top[0]["workflow_name"], "wf-a");
        assert_eq!(top[0]["failed_count_24h"], 12);
        // Error previews are bounded, not full payloads.
        assert!(top[0]["latest_error_preview"].as_str().unwrap().len() <= 220);
        assert!(top[2]["latest_error_preview"].is_null());
    }
}
