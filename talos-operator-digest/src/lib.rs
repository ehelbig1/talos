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

/// Narrowest window [`OperatorDigestService::snapshot`] will query.
pub const DIGEST_MIN_WINDOW_DAYS: u32 = 1;

/// Widest window [`OperatorDigestService::snapshot`] will query.
///
/// D3 (2026-07-29) makes every judge row ECHO this window, so the echo is only
/// truthful while this clamp is no wider than the clamp the judge query itself
/// applies ([`talos_execution_repository::JUDGE_SCORE_MAX_WINDOW_DAYS`]). A
/// silent widening here would make each row advertise a window the SQL never
/// used. `digest_window_never_exceeds_the_judge_query_window` pins the
/// relationship so the drift breaks a test instead of a report.
pub const DIGEST_MAX_WINDOW_DAYS: u32 = 31;

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
        let days = days.clamp(DIGEST_MIN_WINDOW_DAYS, DIGEST_MAX_WINDOW_DAYS) as i32;

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
        let mut ml = talos_ml::loop_health(&self.pool, user_id)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(%user_id, error = %e, "operator_digest: ml loop_health failed");
                json!({ "available": false })
            });
        annotate_correction_loop(&mut ml);

        let judge_scores = self
            .executions
            .weekly_judge_scores(user_id, days)
            .await
            .unwrap_or_default()
            .iter()
            .map(|s| judge_score_row(s, days))
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
                    // Without this the name reads as "these 5 alerts are
                    // miscategorised". They are not: they are simply the
                    // highest-leverage alerts never taught to the classifier.
                    "why_listed": "recurring and never corrected - the highest-leverage \
                                   alert to teach next, not a miscategorised one. \
                                   correct_ops_alert_severity once and every future \
                                   occurrence of this dedup_key inherits it",
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

/// What `failure_rate_24h_measurement.n` counts (D5, 2026-07-29).
///
/// Spelled out because `completed_24h` sits beside it and is NOT the
/// denominator on its own — the rate is over TERMINAL executions, i.e. the
/// sum of both counts.
pub const FAILURE_RATE_POPULATION: &str =
    "TERMINAL workflow executions in the trailing 24h (failed_24h + completed_24h); executions \
     still running, queued or suspended are in neither count";

/// Envelope the 24h failure rate with the denominator it was divided by and a
/// Wilson 95% interval.
///
/// Pure, so the compat rules pin without a database. `None` — rendered as an
/// explicit JSON `null` by the `json!` call site — exactly when
/// [`failure_rate_pct`] is `None`: an empty or nonsensical window has no rate
/// to bound. A `null` here means NOT MEASURED and must never be read as a
/// zero-width interval. Deliberately NOT
/// gated on a sample-size floor: an interval is a WIDTH, not a verdict, and
/// its whole job at n=3 is to be embarrassingly wide.
#[must_use]
fn failure_rate_measurement(
    failed_24h: i64,
    completed_24h: i64,
) -> Option<talos_measurement::Measurement> {
    let total = failed_24h.checked_add(completed_24h)?;
    if total <= 0 || failed_24h < 0 || completed_24h < 0 {
        return None;
    }
    Some(
        talos_measurement::Measurement::rate(
            u64::try_from(failed_24h).ok()?,
            u64::try_from(total).ok()?,
        )?
        .with_population(FAILURE_RATE_POPULATION)
        .with_window("trailing 24 hours"),
    )
}

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
        // D5 (2026-07-29): the same rate with its denominator and a Wilson
        // 95% interval. `failure_rate_24h_pct` alone reads identically for
        // 1-failure-in-3 (33.3%, DEGRADED) and 400-in-1200 (33.3%, DEGRADED),
        // and the first is noise while the second is an incident — the
        // `degraded` flag fires on both. The interval is what makes the
        // difference visible without changing the flag's behaviour.
        //
        // NOTE the unit change: `failure_rate_24h_pct` is a PERCENTAGE
        // (0-100) and `.value` here is the FRACTION (0-1) it was rounded
        // from, per the `Measurement` contract that percentage formatting is
        // a rendering decision. `n` = failed_24h + completed_24h, the same
        // denominator `failure_rate_pct` divides by. Explicit `null`
        // (never a [0, 0] interval) when the window is empty — exactly
        // where `failure_rate_24h_pct` itself is null, so the two fields
        // never disagree about whether anything was measured.
        "failure_rate_24h_measurement": failure_rate_measurement(failed_24h, completed_24h),
        "degraded": degraded,
        "status_line": status_line,
        "top_failing_workflows_24h": top,
    })
}

// ────────────────────────────────────────────────────────────────────
// Metric legibility (2026-07-26)
//
// Every panel below prints numbers whose NAMES imply a verdict the number
// doesn't actually carry. Three real misreads, all by an experienced reader:
//   * `gold: 0.15` reads as "the model is broken". Gold is the held-out slice
//     of the USER'S OWN CORRECTIONS — adversarial by construction. It measures
//     "has the model learned my overrides", not "is the model any good"
//     (that's the holdout accuracy, 0.84 for the same model).
//   * `ops_alert_corrections` reads as "5 alerts are miscategorised". The query
//     is `status<>'resolved' AND corrected_severity IS NULL ORDER BY
//     occurrence_count DESC` — i.e. the highest-LEVERAGE alerts you have never
//     taught the system about. Nothing is wrong with them.
//   * A judge pinned at 1.000 across every run reads as "quality is perfect".
//     It equally means the verdict is a shape check that cannot fail — which is
//     exactly what `pa-inbox-organizer-work` and `pa-chief-of-staff` both had.
//
// A number the reader must already know the provenance of is a number that
// will be misread. These helpers attach that provenance to the payload, so the
// cockpit reports what it MEASURED rather than a bare score. Same defect class
// as the `applied_max_fuel` reporting fix — see the MCP add-node handler.
// ────────────────────────────────────────────────────────────────────

/// Gold rows required before the band labels mean anything. Below this the
/// interval is wider than the bands themselves, so the honest answer is that
/// the slice cannot decide.
const MIN_GOLD_FOR_BAND_VERDICT: i64 = 40;

/// Minimum runs before a judge's score spread is worth interpreting. Below
/// this, "every run scored 1.0" is small-sample noise, not saturation.
const JUDGE_MIN_RUNS_FOR_SIGNAL: i64 = 5;

/// What `pass_rate_measurement.n` counts (D5, 2026-07-29).
///
/// Names the denominator explicitly because the row prints TWO plausible ones
/// right next to each other — `runs` (scored) and `total_verdicts`
/// (`runs + na_runs`) — and only the first is `pass_rate`'s.
pub const JUDGE_PASS_RATE_POPULATION: &str =
    "SCORED judge verdicts for this workflow in the window (`runs`); abstentions (`na_runs`) are \
     excluded from both the numerator and the denominator";

/// Build ONE `learned.judge_scores` row.
///
/// Extracted from `learned_panel`'s closure (2026-07-29 review) because the
/// two fields D3/D5 added — `window_days` and `pass_rate_measurement` — were
/// pinned only by a test-local RE-IMPLEMENTATION of this expression. Both
/// mutations that matter survived it: swapping the envelope's denominator from
/// the SCORED `runs` to `runs + na_runs` (the exact #606 FILTER semantics the
/// population string swears are honored), and deleting `window_days`
/// outright, each left the whole suite green. Per the house testing rule, the
/// logic now lives in one place and the tests call THIS.
///
/// `days` is the CLAMPED window actually queried (`snapshot` narrows to
/// `[DIGEST_MIN_WINDOW_DAYS, DIGEST_MAX_WINDOW_DAYS]` before this point, and
/// `weekly_judge_scores` clamps no narrower), never the caller's raw request.
#[must_use]
fn judge_score_row(s: &talos_execution_repository::JudgeScoreStat, days: i32) -> JsonValue {
    let signal = judge_signal(s.runs, s.avg_score, s.worst_score);
    json!({
        "name": s.workflow_name,
        // 2026-07-29: the row's grain is now (workflow, judge NODE), so
        // `name` alone no longer identifies it — a workflow with a rubric
        // judge and a structural coverage judge emits TWO rows with the same
        // name. The ids disambiguate them AND make the row actionable: they
        // are exactly the pair `probe_inline_judge` takes, which is what
        // `signal_note` tells a reader to run when the trend is saturated.
        "workflow_id": s.workflow_id.to_string(),
        "node_id": s.node_id.to_string(),
        // POPULATION: scored verdicts only. `runs + na_runs` is the number of
        // times the judge actually fired — the two are reported separately
        // (and named so) because every score below is over the scored
        // population alone.
        "runs": s.runs,
        "scored_runs": s.runs,
        "na_runs": s.na_runs,
        "total_verdicts": s.runs + s.na_runs,
        // D3 (2026-07-29): every row echoes the window it was aggregated
        // over. The snapshot carries a top-level `window_days`, but these rows
        // are lifted OUT of the envelope by every consumer that renders them
        // (the pa-autonomy-digest template iterates the array), and a
        // "runs: 5" with no window is unreadable — 5 runs in a day and 5 runs
        // in a month are opposite findings. The engine twin
        // (`talos-engine::assistant_report_reader`) already echoed
        // `trailing_days` on its judge block; this closes the asymmetry.
        "window_days": days,
        "avg_score": s.avg_score,
        "pass_rate": s.pass_rate,
        // D5 (2026-07-29): the same pass rate with its denominator and a
        // Wilson 95% interval attached. `pass_rate: 1.0` over 2 scored
        // verdicts and over 200 rendered identically; the interval is what
        // separates "this judge passes everything" from "this judge has barely
        // fired". n is the SCORED population (`runs`) — the same denominator
        // `pass_rate` itself uses, NOT `runs + na_runs`. An explicit `null`
        // (serde_json's `json!` nulls an Option, it does not drop the key)
        // when there is no pass rate to envelope — never a fabricated [0, 0]
        // interval, which would read as a measured certainty about a judge
        // that has scored nothing.
        "pass_rate_measurement": s.pass_rate.and_then(|p| {
            u64::try_from(s.runs).ok().and_then(|n| {
                talos_measurement::Measurement::from_fraction(p, n).map(|m| {
                    m.with_population(JUDGE_PASS_RATE_POPULATION)
                        .with_window(format!("trailing {days} days"))
                })
            })
        }),
        "worst_score": s.worst_score,
        // D5 (2026-07-28): one constant, shared with
        // `talos-engine::assistant_report_reader`, which carried a
        // byte-identical hand-copy. Two copies of a population disclosure is
        // two chances for it to stop describing the query it annotates.
        "population_note": talos_measurement::JUDGE_SCORE_POPULATION_NOTE,
        // A judge whose score never varies is not evidence of quality — it may
        // be a shape check that cannot fail.
        "signal": signal,
        "signal_note": judge_signal_note(signal, s.runs, s.na_runs, Some((s.workflow_id, s.node_id))),
    })
}

/// Classify what a judge's score distribution actually tells the operator.
///
/// `avg == worst` is an EXACT zero-spread test, not an approximation: `worst`
/// is the minimum and `avg` the mean, and a mean can equal a minimum only when
/// every observation is identical. So this needs no variance column.
///
/// A judge whose score never moves is the quality-signal twin of a registered
/// Prometheus metric that is never incremented (structural lint check 58): it
/// renders a dashboard that can never report a problem. Flagging it is the
/// whole point — a saturated judge is not evidence of quality.
///
/// `runs` is the SCORED population — verdicts where the judge abstained
/// (`not_applicable`) are already excluded upstream and never reach the
/// aggregates here. That is deliberate: an abstention says nothing about
/// score spread, so it must not dilute a saturation verdict. It does mean
/// `insufficient_runs` can be reported for a judge that fired many times,
/// which is why [`judge_signal_note`] takes the abstention count and states
/// it — the number alone would be misread as "this judge barely ran".
pub fn judge_signal(runs: i64, avg_score: Option<f64>, worst_score: Option<f64>) -> &'static str {
    if runs < JUDGE_MIN_RUNS_FOR_SIGNAL {
        return "insufficient_runs";
    }
    // Absent scores are not zero — report unknown rather than inventing a
    // verdict from a missing aggregate.
    let (Some(avg_score), Some(worst_score)) = (avg_score, worst_score) else {
        return "unknown";
    };
    if !avg_score.is_finite() || !worst_score.is_finite() {
        return "unknown";
    }
    if (avg_score - worst_score).abs() > f64::EPSILON {
        return "discriminating";
    }
    // Zero spread across enough runs: the verdict never varied.
    if avg_score >= 1.0 - f64::EPSILON {
        "saturated_pass"
    } else if avg_score <= f64::EPSILON {
        "saturated_fail"
    } else {
        "saturated_constant"
    }
}

/// One-line reading guide for a judge signal — shipped alongside the score so
/// the email/UI can render "why am I looking at this".
///
/// Takes the two populations because the signal alone is ambiguous once a
/// judge can abstain: `insufficient_runs` on `(runs = 2, na_runs = 0)` means
/// "this judge has barely fired", while the same signal on
/// `(runs = 2, na_runs = 15)` means "this judge fires constantly and almost
/// always has nothing to judge" — a completely different thing to go fix.
/// Reporting the bare signal would let the second case read as the first,
/// which is the defect this whole module exists to prevent.
///
/// `probe` is the row's `(workflow_id, node_id)` pair. When present, a
/// `saturated_pass` note gains the copy-pasteable command that ANSWERS it:
/// the base wording has told operators to "verify it in the FAILURE
/// direction" since the signal shipped, but until `probe_inline_judge`
/// existed there was no way to do that short of running the workflow against
/// live data — so the instruction sat unactioned. An instruction with no
/// mechanism is a misleading report field of its own.
pub fn judge_signal_note(
    signal: &str,
    runs: i64,
    na_runs: i64,
    probe: Option<(Uuid, Uuid)>,
) -> String {
    let base = judge_signal_note_base(signal);
    let pointer = judge_probe_pointer(signal, probe);
    if na_runs <= 0 {
        return format!("{base}{pointer}");
    }
    // State BOTH populations explicitly — `runs` counts scored verdicts only,
    // and a reader who assumes it counts invocations will misread every
    // number next to it.
    format!(
        "{base} ({runs} scored {}, {na_runs} abstained — the judge reported \
         nothing to judge on {}; scores and pass rate are over the scored \
         {} only){pointer}",
        if runs == 1 { "run" } else { "runs" },
        if na_runs == 1 {
            "that run"
        } else {
            "those runs"
        },
        if runs == 1 { "run" } else { "runs" },
    )
}

/// The copy-pasteable follow-up for a saturated-pass judge, or `""`.
///
/// Only `saturated_pass` gets it: that is the signal whose base wording asks
/// the operator to do something, and this is the something.
///
/// The command names BOTH tools because `judge_scores` does not record which
/// KIND of judge wrote the row — an inline-expression judge and an
/// LLM-as-judge sub-workflow land in the same table, and pointing an operator
/// at `probe_inline_judge` for a sub-workflow judge would be a confidently
/// wrong instruction. Naming the fork costs one clause and never misdirects.
fn judge_probe_pointer(signal: &str, probe: Option<(Uuid, Uuid)>) -> String {
    let Some((workflow_id, node_id)) = probe else {
        return String::new();
    };
    if signal != "saturated_pass" {
        return String::new();
    }
    format!(
        " — to verify: run probe_inline_judge(workflow_id=\"{workflow_id}\", \
         node_id=\"{node_id}\") with a case that SHOULD fail; if that node is a \
         sub-workflow judge instead, use test_subworkflow_contract(contract=\"judge\")"
    )
}

/// The signal-only half of [`judge_signal_note`]. Split out so the wording of
/// each verdict lives in exactly one place.
fn judge_signal_note_base(signal: &str) -> &'static str {
    match signal {
        "saturated_pass" => {
            "every run scored identically at the maximum — this judge has not been \
             observed to fail anything, so it may be a shape check rather than a \
             quality gate; verify it in the FAILURE direction before trusting the trend"
        }
        "saturated_fail" => {
            "every run scored identically at zero — the verdict is likely erroring or \
             inverted rather than measuring quality"
        }
        "saturated_constant" => {
            "every run returned the same non-extreme score — the verdict is probably \
             constant-valued and carries no signal"
        }
        "insufficient_runs" => "too few runs to interpret the spread yet",
        "discriminating" => "scores vary across runs — the trend is meaningful",
        _ => "score distribution could not be interpreted",
    }
}

/// State of a model's human-correction loop, derived from the gold slice.
///
/// `gold_accuracy` is accuracy on HELD-OUT CORRECTIONS, so a low value does not
/// mean "bad model" — it means the model still predicts what the user overrode.
/// Returns `None` when there is no gold slice to read (never claim a verdict
/// from a check that did not run — same rule as the freshness contracts).
pub fn correction_loop_state(
    corrections_banked: i64,
    gold_accuracy: Option<f64>,
    gold_total: Option<i64>,
) -> Option<&'static str> {
    let acc = gold_accuracy?;
    if !acc.is_finite() {
        return None;
    }
    if corrections_banked <= 0 {
        return Some("no_corrections_yet");
    }
    // A gold slice this small cannot separate the bands. At n=35 the 95%
    // interval spans roughly +/-0.17, so a value of 0.486 sits astride the 0.5
    // cut and ONE example flips the verdict — reporting a confident label there
    // is the same over-reading this module exists to prevent.
    if gold_total.is_some_and(|n| n < MIN_GOLD_FOR_BAND_VERDICT) {
        return Some("too_few_gold_to_judge");
    }
    if acc < 0.5 {
        Some("not_converging")
    } else if acc < 0.8 {
        Some("partially_learned")
    } else {
        Some("converged")
    }
}

/// Wilson score interval (95%) for a proportion.
///
/// MOVED to `talos-measurement` (2026-07-28) and re-exported here so the
/// digest's callers and tests keep one import path. Do NOT re-inline a local
/// copy: the digest, the model card and any future rate annotation must all
/// produce the same interval for the same counts, and a second copy is exactly
/// how the six piecemeal conventions this envelope replaces came about.
/// `wilson_is_not_reinlined_in_this_crate` below fails if a copy reappears.
pub use talos_measurement::wilson_interval_95;

/// Stamp `correction_loop` + `correction_loop_note` onto every model in a
/// `loop_health` payload, in place. Best-effort by design: an unexpected shape
/// (or a model with no gold slice) is left untouched rather than erroring —
/// this is a legibility annotation, and it must never be able to sink the
/// digest that carries it.
pub fn annotate_correction_loop(ml: &mut JsonValue) {
    let Some(models) = ml.get_mut("models").and_then(JsonValue::as_array_mut) else {
        return;
    };
    for m in models {
        let banked = m
            .get("corrections_banked")
            .and_then(JsonValue::as_i64)
            .unwrap_or(0);
        let gold_acc = m
            .get("gold")
            .and_then(|g| g.get("accuracy"))
            .and_then(JsonValue::as_f64);
        let gold_total = m
            .get("gold")
            .and_then(|g| g.get("total"))
            .and_then(JsonValue::as_i64);
        let gold_measured_at = m
            .get("gold")
            .and_then(|g| g.get("measured_at"))
            .and_then(JsonValue::as_str)
            .map(str::to_string);
        let Some(state) = correction_loop_state(banked, gold_acc, gold_total) else {
            continue;
        };
        let ci = gold_acc
            .zip(gold_total)
            .and_then(|(a, n)| wilson_interval_95(a, n));
        let Some(obj) = m.as_object_mut() else {
            continue;
        };
        obj.insert("correction_loop".into(), json!(state));
        obj.insert(
            "correction_loop_note".into(),
            json!(correction_loop_note(state)),
        );
        // WHEN the gold slice this verdict is drawn from was measured, lifted
        // to the model level next to the interval so a flat renderer (the
        // digest email) shows the age beside the band label. COPIED from the
        // payload — a `correction_loop: converged` from an eval that last ran
        // in April is a different fact from the same label measured today, and
        // the annotator has no business inventing the difference. Absent when
        // the version predates provenance capture; absent stays absent.
        if let Some(at) = gold_measured_at {
            obj.insert("gold_measured_at".into(), json!(at));
        }
        // Ship the interval next to the point estimate so nobody (including a
        // future me) reads a 35-row gold accuracy as a precise figure.
        if let Some((lo, hi)) = ci {
            obj.insert("gold_accuracy_ci95".into(), json!([lo, hi]));
        }
    }
}

/// Reading guide for [`correction_loop_state`].
pub fn correction_loop_note(state: &str) -> &'static str {
    match state {
        "not_converging" => {
            "gold = held-out USER CORRECTIONS, so this measures whether the model has \
             learned your overrides — NOT general quality (see holdout accuracy for \
             that). Below 0.5 the corrections are not moving the model, usually \
             because identical-content rows carrying the pre-correction label are \
             outvoting them. MEASURED ORDER OF LEVERS (2026-07-27): (1) dedupe the \
             dataset — removing content duplicates moved gold 0.227 -> 0.486 while \
             holdout ALSO rose 0.723 -> 0.802; (2) bank more corrections — 108 -> 143 \
             moved gold 0.094 -> 0.227. Raising correction_weight is NOT recommended \
             first: it was measured as a straight trade, buying gold 0.094 -> 0.219 by \
             giving up holdout 0.712 -> 0.617."
        }
        "too_few_gold_to_judge" => {
            "the gold slice is too small for the band labels to mean anything — its \
             confidence interval is wider than the bands. Read gold_accuracy_ci95, not \
             the point estimate, and bank more corrections to narrow it."
        }
        "partially_learned" => {
            "the model agrees with a majority of your held-out corrections but not yet \
             reliably; keep correcting"
        }
        "converged" => "the model reproduces your corrections on held-out examples",
        "no_corrections_yet" => "no corrections banked — nothing to learn from yet",
        _ => "correction-loop state could not be interpreted",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The motivating case: `pa-chief-of-staff` scored 1.0 on all 11 runs and
    /// `pa-inbox-organizer` on all 9. Both read as "perfect quality"; both were
    /// judges that had never been observed to fail anything.
    #[test]
    fn judge_pinned_at_max_is_flagged_saturated_not_perfect() {
        assert_eq!(judge_signal(11, Some(1.0), Some(1.0)), "saturated_pass");
        assert_eq!(judge_signal(9, Some(1.0), Some(1.0)), "saturated_pass");
        assert!(judge_signal_note("saturated_pass", 11, 0, None).contains("FAILURE direction"));
    }

    /// A judge that fires constantly but almost always has nothing to judge
    /// collapses to `insufficient_runs` on the SCORED count. The bare signal
    /// would read as "this judge barely ran" — the opposite of the truth —
    /// so the note must state both populations and name the cause.
    #[test]
    fn heavily_abstaining_judge_states_its_abstentions() {
        // 3 scored runs, 9 abstentions: 12 invocations, not 3.
        assert_eq!(judge_signal(3, Some(1.0), Some(1.0)), "insufficient_runs");
        let note = judge_signal_note("insufficient_runs", 3, 9, None);
        assert!(note.contains("3 scored runs"), "{note}");
        assert!(note.contains("9 abstained"), "{note}");
        assert!(note.contains("nothing to judge"), "{note}");
        // The base wording survives so the signal is still explained.
        assert!(note.contains("too few runs"), "{note}");
    }

    /// With no abstentions the note is byte-identical to the pre-feature
    /// wording — no reader of a normal judge sees new noise.
    #[test]
    fn note_is_unchanged_when_nothing_abstained() {
        for signal in [
            "saturated_pass",
            "saturated_fail",
            "saturated_constant",
            "insufficient_runs",
            "discriminating",
            "bogus",
        ] {
            assert_eq!(
                judge_signal_note(signal, 7, 0, None),
                judge_signal_note_base(signal),
                "{signal}"
            );
        }
    }

    /// Abstentions do not change the SIGNAL — only its explanation. A judge
    /// that saturated across enough scored runs is still saturated no matter
    /// how often it abstained; `runs` is already the scored population.
    #[test]
    fn abstentions_do_not_change_the_signal() {
        assert_eq!(judge_signal(9, Some(1.0), Some(1.0)), "saturated_pass");
        let note = judge_signal_note("saturated_pass", 9, 40, None);
        assert!(note.contains("FAILURE direction"), "{note}");
        assert!(note.contains("40 abstained"), "{note}");
    }

    /// Singular/plural, because these strings go into an operator email.
    #[test]
    fn note_counts_read_grammatically() {
        let one = judge_signal_note("insufficient_runs", 1, 1, None);
        assert!(one.contains("1 scored run,"), "{one}");
        assert!(one.contains("nothing to judge on that run"), "{one}");
        let many = judge_signal_note("insufficient_runs", 2, 3, None);
        assert!(many.contains("2 scored runs,"), "{many}");
        assert!(many.contains("nothing to judge on those runs"), "{many}");
    }

    /// `pa-inbox-organizer-work`: avg 0.556, worst 0.2 — a judge that genuinely
    /// varies. It must NOT be flagged, or the flag becomes noise.
    #[test]
    fn varying_judge_is_discriminating() {
        assert_eq!(
            judge_signal(9, Some(0.5555555555555557), Some(0.2)),
            "discriminating"
        );
    }

    /// Small samples must not be called saturated — three 1.0s is not evidence
    /// that a judge cannot fail.
    #[test]
    fn small_sample_is_not_saturation() {
        assert_eq!(judge_signal(1, Some(1.0), Some(1.0)), "insufficient_runs");
        assert_eq!(judge_signal(4, Some(1.0), Some(1.0)), "insufficient_runs");
        assert_eq!(judge_signal(5, Some(1.0), Some(1.0)), "saturated_pass");
    }

    /// A judge stuck at zero is broken, not "strict" — distinguish it from a
    /// judge stuck at max, since the operator actions differ.
    #[test]
    fn stuck_at_zero_is_distinct_from_stuck_at_max() {
        assert_eq!(judge_signal(10, Some(0.0), Some(0.0)), "saturated_fail");
        assert_eq!(judge_signal(10, Some(0.5), Some(0.5)), "saturated_constant");
    }

    /// NaN/inf must not be reported as a verdict.
    #[test]
    fn non_finite_scores_are_unknown() {
        assert_eq!(judge_signal(10, Some(f64::NAN), Some(0.0)), "unknown");
        assert_eq!(judge_signal(10, Some(1.0), Some(f64::INFINITY)), "unknown");
        assert_eq!(judge_signal(10, None, Some(1.0)), "unknown");
        assert_eq!(judge_signal(10, Some(1.0), None), "unknown");
    }

    /// The `inbox-classifier-personal` case: 108 corrections banked, gold
    /// accuracy 0.09. Must read as "corrections not learned", never as a
    /// general quality verdict.
    #[test]
    fn low_gold_with_banked_corrections_is_not_converging() {
        assert_eq!(
            correction_loop_state(108, Some(0.09375), Some(44)),
            Some("not_converging")
        );
        let note = correction_loop_note("not_converging");
        assert!(note.contains("USER CORRECTIONS"));
        assert!(
            note.contains("NOT general quality"),
            "the note must actively prevent the misread it exists to fix"
        );
    }

    /// No gold slice → no verdict. Never synthesise one from absence.
    #[test]
    fn absent_gold_yields_no_state() {
        assert_eq!(correction_loop_state(108, None, None), None);
        assert_eq!(correction_loop_state(0, None, None), None);
        assert_eq!(correction_loop_state(108, Some(f64::NAN), Some(44)), None);
    }

    /// The live 2026-07-27 reading: gold 0.486 on n=35 sat astride the 0.5 band
    /// cut, where ONE example flips the verdict. Refuse to call it.
    #[test]
    fn small_gold_slice_refuses_a_band_verdict() {
        assert_eq!(
            correction_loop_state(113, Some(0.4857), Some(35)),
            Some("too_few_gold_to_judge")
        );
        // Same accuracy, enough rows to mean something -> a real verdict.
        assert_eq!(
            correction_loop_state(113, Some(0.4857), Some(120)),
            Some("not_converging")
        );
    }

    /// The advice must reflect what was MEASURED, not the original guess:
    /// correction_weight was a straight trade, dedupe was a Pareto win.
    #[test]
    fn not_converging_note_does_not_recommend_correction_weight_first() {
        let note = correction_loop_note("not_converging");
        assert!(
            note.contains("dedupe"),
            "the measured first lever must lead"
        );
        assert!(
            note.contains("NOT recommended first"),
            "the disproven lever must be marked as such"
        );
    }

    #[test]
    fn wilson_interval_brackets_the_estimate_and_stays_in_range() {
        let (lo, hi) = wilson_interval_95(0.4857, 35).unwrap();
        assert!(
            lo < 0.4857 && hi > 0.4857,
            "interval must bracket the point"
        );
        assert!(
            lo > 0.32 && hi < 0.66,
            "n=35 is roughly +/-0.17, got [{lo},{hi}]"
        );
        // The degenerate cases the normal approximation gets wrong.
        let (zlo, zhi) = wilson_interval_95(0.0, 16).unwrap();
        assert_eq!(zlo, 0.0);
        assert!(zhi > 0.0 && zhi < 0.3, "0/16 is not 'exactly zero forever'");
        let (olo, ohi) = wilson_interval_95(1.0, 5).unwrap();
        assert_eq!(ohi, 1.0);
        assert!(olo < 1.0);
        // More rows must narrow it.
        let (wlo, whi) = wilson_interval_95(0.5, 35).unwrap();
        let (nlo, nhi) = wilson_interval_95(0.5, 350).unwrap();
        assert!((nhi - nlo) < (whi - wlo));
    }

    /// Mutation guard (2026-07-28): the Wilson interval MOVED to
    /// `talos-measurement`; this crate re-exports it. If someone re-inlines a
    /// local definition of it here — the exact way the six piecemeal
    /// conventions accumulated in the first place — the two copies can drift
    /// silently, because both compile and both look right. Assert
    /// structurally that no definition lives in this file.
    #[test]
    fn wilson_is_not_reinlined_in_this_crate() {
        // The needles are assembled with `concat!` so this test's own source
        // text is not a match for them — an `include_str!` self-scan that
        // matches itself is a test that can never pass.
        let src = include_str!("lib.rs");
        assert!(
            !src.contains(concat!("fn wilson", "_interval_95")),
            "wilson_interval_95 must stay a re-export of talos_measurement, \
             not a local definition — a second copy is a drift vector"
        );
        assert!(
            src.contains(concat!("pub use talos_measurement::", "wilson_interval_95")),
            "the re-export must remain so existing import paths resolve"
        );
        // And the re-exported function is the one that is pinned there.
        let (lo, hi) = wilson_interval_95(0.4857, 35).unwrap();
        assert_eq!(lo.to_bits(), 0.329_929_602_948_868_2_f64.to_bits());
        assert_eq!(hi.to_bits(), 0.644_298_965_431_609_8_f64.to_bits());
    }

    /// Mutation guard: the judge population note is one shared constant. A
    /// re-inlined literal here would let the digest's disclosure drift away
    /// from the assistant report's while both keep compiling.
    #[test]
    fn judge_population_note_is_the_shared_constant() {
        let src = include_str!("lib.rs");
        assert!(
            src.contains(concat!(
                "talos_measurement::",
                "JUDGE_SCORE_POPULATION_NOTE"
            )),
            "the digest must read the shared population note, not a copy"
        );
        assert!(
            !src.contains(concat!("reported nothing to ju", "dge and which are")),
            "a re-inlined copy of the population-note literal reappeared"
        );
        // …and the shared constant still says what the note claims.
        assert!(talos_measurement::JUDGE_SCORE_POPULATION_NOTE.contains("SCORED verdicts only"));
    }

    #[test]
    fn wilson_rejects_nonsense_inputs() {
        assert!(wilson_interval_95(0.5, 0).is_none());
        assert!(wilson_interval_95(0.5, -3).is_none());
        assert!(wilson_interval_95(f64::NAN, 10).is_none());
        assert!(wilson_interval_95(1.5, 10).is_none());
    }

    /// End-to-end over the real `loop_health` shape observed 2026-07-26: one
    /// model with a gold slice, one (`ops-severity`, llm_only) without.
    #[test]
    fn annotation_stamps_only_models_with_gold() {
        let mut ml = json!({"models": [
            {"name": "inbox-classifier-personal", "corrections_banked": 108,
             "gold": {"accuracy": 0.09375, "total": 32}},
            {"name": "ops-severity", "corrections_banked": 7, "gold": null},
        ]});
        annotate_correction_loop(&mut ml);
        let models = ml["models"].as_array().unwrap();
        // n=32 is below the band-verdict floor, so the honest label is the
        // refusal — and the CI must ride along with it.
        assert_eq!(models[0]["correction_loop"], "too_few_gold_to_judge");
        assert!(models[0]["gold_accuracy_ci95"].is_array());
        assert!(
            models[1].get("correction_loop").is_none(),
            "a model with no gold slice must get NO verdict, not a default one"
        );
        // The 2026-07-26 payload had no `measured_at` (the field did not
        // exist), and the annotator must not invent one.
        assert!(
            models[0].get("gold_measured_at").is_none(),
            "an unstamped gold slice must not acquire a timestamp here"
        );
    }

    /// D5 (2026-07-28): when `loop_health` carries the gold slice's
    /// measurement time, the digest lifts it to the model level beside the
    /// interval — a `converged` verdict from an eval that last ran in April is
    /// a different fact from the same verdict measured today, and the flat
    /// email renderer reads model-level keys.
    #[test]
    fn the_annotation_carries_the_gold_measurement_time_when_the_payload_has_one() {
        let mut ml = json!({"models": [
            {"name": "inbox-classifier-personal", "corrections_banked": 143,
             "gold": {"accuracy": 0.9, "total": 60, "source_version": 43,
                      "measured_at": "2026-07-27T09:30:00.000Z"}},
        ]});
        annotate_correction_loop(&mut ml);
        let m = &ml["models"][0];
        assert_eq!(m["correction_loop"], "converged");
        assert_eq!(
            m["gold_measured_at"], "2026-07-27T09:30:00.000Z",
            "the stamp must be COPIED from the payload, not derived"
        );
        // Idempotent + clock-free: re-annotating cannot move the timestamp.
        let before = ml.clone();
        annotate_correction_loop(&mut ml);
        assert_eq!(ml, before);
    }

    /// The annotation is decoration on a best-effort panel — every malformed
    /// shape must be a no-op, never a panic.
    #[test]
    fn annotation_tolerates_malformed_payloads() {
        for mut v in [
            json!({"available": false}),
            json!({"models": "not-an-array"}),
            json!({"models": [42, null, "x"]}),
            json!({"models": [{"gold": {"accuracy": "high"}}]}),
            json!(null),
        ] {
            annotate_correction_loop(&mut v); // must not panic
        }
    }

    #[test]
    fn correction_loop_bands() {
        assert_eq!(
            correction_loop_state(0, Some(0.1), Some(44)),
            Some("no_corrections_yet")
        );
        assert_eq!(
            correction_loop_state(5, Some(0.6), Some(44)),
            Some("partially_learned")
        );
        assert_eq!(
            correction_loop_state(5, Some(0.95), Some(44)),
            Some("converged")
        );
    }

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

/// D3 + D5 (2026-07-29): the judge-panel window echo and the two Wilson
/// intervals.
#[cfg(test)]
mod measurement_pr3_tests {
    use super::*;

    // ---- D5: failure-rate envelope ---------------------------------------

    /// The motivating pair: the SAME 33.3% rate over two populations that
    /// mean opposite things. The percentage alone cannot tell them apart and
    /// `degraded` fires on both; the interval is what separates them.
    #[test]
    fn failure_rate_envelope_separates_noise_from_an_incident() {
        let small = build_reliability_section(1, 2, &[]);
        let large = build_reliability_section(400, 800, &[]);
        assert_eq!(small["failure_rate_24h_pct"], 33.3);
        assert_eq!(large["failure_rate_24h_pct"], 33.3);
        assert_eq!(small["degraded"], true);
        assert_eq!(large["degraded"], true);

        let sm = &small["failure_rate_24h_measurement"];
        let lg = &large["failure_rate_24h_measurement"];
        // n is failed + completed — the TERMINAL count, not `completed_24h`.
        assert_eq!(sm["n"], 3);
        assert_eq!(lg["n"], 1200);
        // `.value` is the FRACTION the percentage was rounded from.
        assert!((sm["value"].as_f64().unwrap() - 1.0 / 3.0).abs() < 1e-12);
        let (slo, shi) = (
            sm["ci95"][0].as_f64().unwrap(),
            sm["ci95"][1].as_f64().unwrap(),
        );
        let (llo, lhi) = (
            lg["ci95"][0].as_f64().unwrap(),
            lg["ci95"][1].as_f64().unwrap(),
        );
        assert!(
            (shi - slo) > 10.0 * (lhi - llo),
            "n=3 must be visibly wider than n=1200: [{slo},{shi}] vs [{llo},{lhi}]"
        );
        // At n=3 the interval still admits a perfectly healthy system; at
        // n=1200 it does not. That is the whole point.
        assert!(
            slo < 0.10,
            "n=3 lower bound {slo} should not exclude health"
        );
        assert!(llo > 0.10, "n=1200 lower bound {llo} should exclude health");
    }

    /// The population is STATED, and names the sum rather than leaving a
    /// reader to pick between the two counts printed beside it.
    #[test]
    fn failure_rate_envelope_states_its_denominator_and_window() {
        let s = build_reliability_section(23, 100, &[]);
        let m = &s["failure_rate_24h_measurement"];
        assert_eq!(m["n"], 123);
        assert_eq!(m["population"], FAILURE_RATE_POPULATION);
        assert_eq!(m["window"], "trailing 24 hours");
        assert!(FAILURE_RATE_POPULATION.contains("failed_24h + completed_24h"));
    }

    /// `null`, not `[0, 0]`, and null in LOCKSTEP with the rate itself — an
    /// interval for a window with no runs would be a fabricated bound, and a
    /// null rate beside a present interval would be two fields disagreeing
    /// about whether anything was measured.
    #[test]
    fn failure_rate_envelope_is_null_on_an_empty_window() {
        let s = build_reliability_section(0, 0, &[]);
        assert!(s["failure_rate_24h_pct"].is_null());
        // The key IS present and IS null: `json!` nulls an `Option` rather
        // than dropping it. Pinned as an equality so a future switch to an
        // omitting shape is a deliberate, visible change.
        assert!(
            s.as_object()
                .unwrap()
                .contains_key("failure_rate_24h_measurement"),
            "the key is present-and-null, not dropped: {s}"
        );
        assert!(
            s["failure_rate_24h_measurement"].is_null(),
            "empty window must not carry an interval: {s}"
        );
        // Nonsense inputs are refused the same way.
        assert!(failure_rate_measurement(-1, 5).is_none());
        assert!(failure_rate_measurement(5, -1).is_none());
        assert!(failure_rate_measurement(i64::MAX, i64::MAX).is_none());
    }

    /// A real 0-failure and a real all-failed window DO get intervals — the
    /// refusal is about an empty denominator, not about extreme rates.
    #[test]
    fn failure_rate_envelope_survives_both_extremes() {
        let clean = failure_rate_measurement(0, 50).expect("0/50 is measurable");
        assert_eq!(clean.value, 0.0);
        assert_eq!(clean.n, 50);
        // 0 failures out of 50 does NOT prove the rate is zero forever.
        assert!(clean.ci95.unwrap()[1] > 0.0);
        let broken = failure_rate_measurement(50, 0).expect("50/50 is measurable");
        assert_eq!(broken.value, 1.0);
        assert_eq!(broken.ci95.unwrap()[0] < 1.0, true);
    }

    /// The envelope is ADDITIVE: every pre-D5 key keeps its value and type.
    #[test]
    fn reliability_section_is_additive_over_the_pre_d5_shape() {
        let s = build_reliability_section(125, 245, &[]);
        assert_eq!(s["available"], true);
        assert_eq!(s["failed_24h"], 125);
        assert_eq!(s["completed_24h"], 245);
        assert_eq!(s["failure_rate_24h_pct"], 33.8);
        assert_eq!(s["degraded"], true);
        assert!(s["status_line"].as_str().unwrap().contains("33.8%"));
        assert!(s["top_failing_workflows_24h"].is_array());
    }

    // ---- D3 + D5: the judge row ------------------------------------------

    /// Fixed ids so assertions can match the exact pointer text.
    fn probe_wf() -> Uuid {
        Uuid::parse_str("aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa").unwrap()
    }
    fn probe_node() -> Uuid {
        Uuid::parse_str("bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb").unwrap()
    }

    fn saturated_row(node: Uuid) -> JsonValue {
        judge_score_row(
            &talos_execution_repository::JudgeScoreStat {
                workflow_id: probe_wf(),
                node_id: node,
                workflow_name: "pa-inbox-organizer-work".to_string(),
                runs: 11,
                na_runs: 0,
                avg_score: Some(1.0),
                pass_rate: Some(1.0),
                worst_score: Some(1.0),
            },
            7,
        )
    }

    /// D4: the row's grain is (workflow, judge NODE), so `name` alone no
    /// longer identifies it — two judges in one workflow render as two rows
    /// with the same name. The ids are what tell them apart.
    #[test]
    fn judge_rows_of_one_workflow_are_distinguishable_by_node_id() {
        let a = saturated_row(probe_node());
        let b = saturated_row(Uuid::parse_str("cccccccc-3333-4333-8333-cccccccccccc").unwrap());
        assert_eq!(a["name"], b["name"], "same workflow, same name");
        assert_eq!(a["workflow_id"], b["workflow_id"]);
        assert_ne!(
            a["node_id"], b["node_id"],
            "two judges must not collapse into one identity"
        );
        assert_eq!(a["workflow_id"], json!(probe_wf().to_string()));
        assert_eq!(a["node_id"], json!(probe_node().to_string()));
    }

    /// D4: the saturated-pass note has told operators to "verify it in the
    /// FAILURE direction" since it shipped, with no mechanism to do so. It
    /// now carries the command, with THIS row's real ids — an instruction
    /// with no mechanism is a misleading report field of its own.
    #[test]
    fn saturated_pass_note_carries_a_copy_pasteable_probe_pointer() {
        let v = saturated_row(probe_node());
        assert_eq!(v["signal"], "saturated_pass");
        let note = v["signal_note"].as_str().unwrap();
        // The base instruction survives.
        assert!(note.contains("FAILURE direction"), "{note}");
        assert!(
            note.contains(&format!(
                "probe_inline_judge(workflow_id=\"{}\", node_id=\"{}\")",
                probe_wf(),
                probe_node()
            )),
            "the pointer must be copy-pasteable with the row's own ids: {note}"
        );
        assert!(note.contains("SHOULD fail"), "{note}");
        // `judge_scores` records no judge KIND, so the note must not send a
        // sub-workflow judge's operator to the inline-only tool.
        assert!(note.contains("test_subworkflow_contract"), "{note}");
    }

    /// Only `saturated_pass` gets the pointer — it is the one signal whose
    /// wording asks the operator to go do something.
    #[test]
    fn other_signals_do_not_gain_the_probe_pointer() {
        for signal in [
            "saturated_fail",
            "saturated_constant",
            "insufficient_runs",
            "discriminating",
            "unknown",
        ] {
            let note = judge_signal_note(signal, 7, 0, Some((probe_wf(), probe_node())));
            assert!(
                !note.contains("probe_inline_judge"),
                "{signal} must not carry the pointer: {note}"
            );
            assert_eq!(note, judge_signal_note_base(signal), "{signal}");
        }
    }

    /// The abstention clause and the pointer compose — a saturated judge that
    /// also abstains must report both, not one or the other.
    #[test]
    fn probe_pointer_composes_with_the_abstention_clause() {
        let note = judge_signal_note("saturated_pass", 9, 40, Some((probe_wf(), probe_node())));
        assert!(note.contains("40 abstained"), "{note}");
        assert!(note.contains("probe_inline_judge"), "{note}");
        assert!(note.contains("FAILURE direction"), "{note}");
    }

    /// Build the row through the PRODUCTION builder (`judge_score_row`, the
    /// one `learned_panel` calls), then read the envelope back out of it.
    ///
    /// The pre-review version of this helper RE-IMPLEMENTED the envelope
    /// expression, which meant the tests below passed against a copy: swapping
    /// production's denominator to `runs + na_runs` and deleting `window_days`
    /// entirely both left the suite green. Going through the real builder is
    /// what makes those mutations fail.
    fn row(
        pass_rate: Option<f64>,
        runs: i64,
        na_runs: i64,
        days: i32,
    ) -> (JsonValue, Option<talos_measurement::Measurement>) {
        let v = judge_score_row(
            &talos_execution_repository::JudgeScoreStat {
                workflow_id: probe_wf(),
                node_id: probe_node(),
                workflow_name: "pa-inbox-triage".to_string(),
                runs,
                na_runs,
                avg_score: Some(0.8),
                pass_rate,
                worst_score: Some(0.5),
            },
            days,
        );
        let m: Option<talos_measurement::Measurement> =
            serde_json::from_value(v["pass_rate_measurement"].clone())
                .expect("pass_rate_measurement is a Measurement or null");
        (v, m)
    }

    fn judge_pass_rate_measurement(
        pass_rate: Option<f64>,
        runs: i64,
        days: i32,
    ) -> Option<talos_measurement::Measurement> {
        row(pass_rate, runs, 0, days).1
    }

    /// D5: a judge that has passed everything twice and one that has passed
    /// everything two hundred times both print `pass_rate: 1.0`.
    #[test]
    fn judge_pass_rate_envelope_separates_two_from_two_hundred() {
        let few = judge_pass_rate_measurement(Some(1.0), 2, 7).expect("2 scored runs");
        let many = judge_pass_rate_measurement(Some(1.0), 200, 7).expect("200 scored runs");
        assert_eq!(few.value, 1.0);
        assert_eq!(many.value, 1.0);
        assert_eq!(few.n, 2);
        assert_eq!(many.n, 200);
        let flo = few.ci95.unwrap()[0];
        let mlo = many.ci95.unwrap()[0];
        assert!(
            flo < 0.4,
            "2-for-2 must not read as near-certainty, got lo={flo}"
        );
        assert!(mlo > 0.97, "200-for-200 should be tight, got lo={mlo}");
    }

    /// The denominator is the SCORED count, and the population says so —
    /// `total_verdicts` sits in the same JSON object and is the wrong one.
    ///
    /// The abstentions here are what make this bite: with `runs = 8` and
    /// `na_runs = 5` the two candidate denominators are 8 and 13, so an
    /// envelope built over `runs + na_runs` fails on `n` instead of quietly
    /// agreeing (the #606 `FILTER (WHERE NOT not_applicable)` semantics).
    #[test]
    fn judge_pass_rate_population_names_the_scored_denominator() {
        let (v, m) = row(Some(0.5), 8, 5, 7);
        let m = m.expect("8 scored runs");
        assert_eq!(v["runs"], 8);
        assert_eq!(v["na_runs"], 5);
        assert_eq!(v["total_verdicts"], 13);
        assert_eq!(m.n, 8, "n must be `runs`, never `total_verdicts`: {v}");
        assert_eq!(m.population.as_deref(), Some(JUDGE_PASS_RATE_POPULATION));
        assert!(JUDGE_PASS_RATE_POPULATION.contains("SCORED"));
        assert!(JUDGE_PASS_RATE_POPULATION.contains("na_runs"));
        assert_eq!(m.window.as_deref(), Some("trailing 7 days"));
    }

    /// An abstention-only judge (`runs = 0` ⇒ `pass_rate` NULL from the
    /// `NULLIF` in the query) gets no envelope — never a [0, 0].
    #[test]
    fn judge_pass_rate_envelope_absent_when_there_is_no_rate() {
        assert!(judge_pass_rate_measurement(None, 0, 7).is_none());
        assert!(judge_pass_rate_measurement(None, 12, 7).is_none());
        // A rate with a zero denominator is impossible upstream, but if it
        // arrived it would still be refused rather than enveloped.
        assert!(judge_pass_rate_measurement(Some(1.0), 0, 7).is_none());
        // …as would an out-of-range rate.
        assert!(judge_pass_rate_measurement(Some(1.5), 10, 7).is_none());
    }

    /// D3: the window travels ON the row, as a top-level `window_days` key.
    /// These rows are iterated out of the envelope by the pa-autonomy-digest
    /// template, where the snapshot's top-level `window_days` is not in scope.
    #[test]
    fn judge_row_window_matches_the_clamped_snapshot_window() {
        for requested in [0u32, 1, 7, 31, 90, u32::MAX] {
            let clamped = requested.clamp(DIGEST_MIN_WINDOW_DAYS, DIGEST_MAX_WINDOW_DAYS) as i32;
            let (v, m) = row(Some(1.0), 5, 0, clamped);
            assert_eq!(
                v["window_days"], clamped,
                "the row must echo the window it was aggregated over: {v}"
            );
            assert_eq!(
                m.unwrap().window.as_deref(),
                Some(&*format!("trailing {clamped} days"))
            );
        }
    }

    /// The echoed `window_days` is only truthful while the digest's own clamp
    /// is no WIDER than the clamp the judge query applies — otherwise a row
    /// would advertise a 31-day window that the SQL narrowed behind its back.
    /// Both bounds are now named constants so a drift in either fails here
    /// instead of shipping a mislabelled report.
    #[test]
    fn digest_window_never_exceeds_the_judge_query_window() {
        assert!(
            DIGEST_MAX_WINDOW_DAYS as i64
                <= talos_execution_repository::JUDGE_SCORE_MAX_WINDOW_DAYS as i64,
            "digest clamps to {DIGEST_MAX_WINDOW_DAYS}d but weekly_judge_scores narrows to {}d",
            talos_execution_repository::JUDGE_SCORE_MAX_WINDOW_DAYS
        );
        assert!(
            DIGEST_MIN_WINDOW_DAYS as i64
                >= talos_execution_repository::JUDGE_SCORE_MIN_WINDOW_DAYS as i64,
            "digest allows {DIGEST_MIN_WINDOW_DAYS}d but weekly_judge_scores widens to {}d",
            talos_execution_repository::JUDGE_SCORE_MIN_WINDOW_DAYS
        );
    }
}
