//! One question, one implementation: "this workflow's SLA-window stats" —
//! RFC 0012 P3.
//!
//! # What was measured before this module existed (2026-09-07)
//!
//! FOUR implementations of that question, and they DISAGREED:
//!
//! | site | window | denominator filter | p95 population | user scope |
//! |---|---|---|---|---|
//! | the 5-min breach monitor's INLINE SQL (`bootstrap/background.rs`) | `INTERVAL '24 hours'` | `completed_at IS NOT NULL` | every settled run | `user_id` |
//! | `AnalyticsRepository::get_sla_window_stats` (the 15-min degradation loop) | `hours` param | **none** | ditto, de facto | **none** |
//!
//! `get_sla_window_stats` and its `SlaWindowStats` were DELETED rather than
//! kept as a projection, for the reason RFC 0012 P2 deleted
//! `ReadinessBasis::from_scan`: it returned `Option`, so a failed read and an
//! empty window were the same value, and a future caller reaching for the
//! convenient name would silently re-acquire exactly the collapse this change
//! removed. Its one caller now reads [`read_sla_window_sources`] and handles
//! the three outcomes explicitly.
//! | `get_latency_percentiles_ms` (the MCP report) | `days` param | `status = 'completed'` | successful runs only | `user_id` |
//! | `get_performance_metrics` | `days` param | `status = 'completed'` | successful runs only | `user_id` |
//!
//! The first two ask the SAME question over the SAME window and answer it
//! differently: one counts in-flight executions in the denominator and the
//! other does not, so their success rates differ and two loops can reach
//! opposite verdicts against one stored threshold row on one tick. That is
//! check 85's class, and this module collapses those two.
//!
//! The last two are deliberately NOT collapsed here and the reason is stated
//! rather than assumed: they answer a different question — the latency
//! DISTRIBUTION of SUCCESSFUL runs over a days-window — and folding a failed
//! run's duration into `get_workflow_sla_report.duration.p50` would change a
//! number an operator reads without being asked to.
//!
//! # And it reads the child-run ledger
//!
//! A sub-workflow runs in-process and records no `workflow_executions` row, so
//! before this a threshold set on a child was SILENTLY INERT: the monitor's
//! `total == 0 => continue` fired on every tick. `sub_workflow_runs` (RFC 0012)
//! is the only table that can see those runs, and it carries `status`,
//! `duration_ms`, `started_at` and the parent's `user_id` — everything the
//! breach decision needs. Both populations are read in ONE statement over a
//! `UNION ALL`, with `GROUP BY ROLLUP` so the per-source split and the combined
//! percentile come from one pass.
//!
//! Success is `status = 'completed'` on BOTH sides. That is the one thing every
//! pre-existing implementation already agreed on, and it is not changed here.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use crate::readiness_basis::LEDGER_MIN_RUNS;

/// The window BOTH SLA loops evaluate over, in hours.
///
/// Was an `INTERVAL '24 hours'` literal in the 5-min monitor's inline SQL and
/// a hard-coded `24` argument in the 15-min loop's call. Named once so the two
/// cannot drift, and so the number in a webhook payload's `sources.window_hours`
/// is the number the query used.
pub const SLA_WINDOW_HOURS: i64 = 24;

/// One population's contribution to an SLA window.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct SlaSourceStats {
    /// Settled runs in the window.
    pub total: i64,
    /// How many reached `completed`.
    pub succeeded: i64,
    /// 95th percentile wall time, in milliseconds. `None` when `total == 0`.
    pub p95_ms: Option<f64>,
}

impl SlaSourceStats {
    /// Success rate as a percentage, or `None` over an empty population — a
    /// rate over nothing is not 100% and is not 0%, it does not exist.
    #[must_use]
    pub fn success_rate_pct(&self) -> Option<f64> {
        if self.total <= 0 {
            return None;
        }
        #[allow(clippy::cast_precision_loss)]
        Some((self.succeeded as f64 / self.total as f64) * 100.0)
    }

    /// Runs that did not reach `completed`.
    #[must_use]
    pub const fn failed(&self) -> i64 {
        self.total - self.succeeded
    }
}

/// Both populations for one workflow over one window, plus the ledger's floor.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SlaWindowSources {
    /// `workflow_executions` rows that SETTLED in the window.
    pub executions: SlaSourceStats,
    /// `sub_workflow_runs` rows in the window — this workflow as somebody's
    /// child. Every ledger row is settled by construction.
    pub child_runs: SlaSourceStats,
    /// The two unioned, including the combined p95 (computed over the union in
    /// the same statement, never by averaging two percentiles).
    pub combined: SlaSourceStats,
    /// The earliest run the ledger still holds, deployment-wide. `None` = the
    /// table is EMPTY, so `child_runs.total == 0` is UNKNOWN, not zero.
    pub ledger_since: Option<DateTime<Utc>>,
    /// The window this describes.
    pub window_hours: i64,
}

impl SlaWindowSources {
    /// An all-empty result, for a caller that could not read either source.
    #[must_use]
    pub const fn empty(window_hours: i64) -> Self {
        Self {
            executions: SlaSourceStats {
                total: 0,
                succeeded: 0,
                p95_ms: None,
            },
            child_runs: SlaSourceStats {
                total: 0,
                succeeded: 0,
                p95_ms: None,
            },
            combined: SlaSourceStats {
                total: 0,
                succeeded: 0,
                p95_ms: None,
            },
            ledger_since: None,
            window_hours,
        }
    }

    /// Did the ledger contribute a run? Drives the NOTHING-TO-SAY ⇒ NO KEY
    /// rule on every renderer.
    #[must_use]
    pub const fn ledger_contributed(&self) -> bool {
        self.child_runs.total > 0
    }

    /// One sentence naming the split. `None` when the ledger contributed
    /// nothing — the response then says exactly what it said before RFC 0012.
    #[must_use]
    pub fn population_note(&self) -> Option<String> {
        if !self.ledger_contributed() {
            return None;
        }
        let since = self
            .ledger_since
            .map_or_else(|| "an unknown date".to_string(), |s| s.to_rfc3339());
        Some(format!(
            "Measured over {} settled run(s) in the trailing {} hour(s): {} workflow_executions \
             row(s) ({} failed) and {} child run(s) from the RFC 0012 ledger ({} failed, \
             recorded since {}). A sub-workflow runs in-process and records no \
             workflow_executions row, so the ledger is the only table that can see those runs; \
             a period before {} is UNKNOWN, not zero.",
            self.combined.total,
            self.window_hours,
            self.executions.total,
            self.executions.failed(),
            self.child_runs.total,
            self.child_runs.failed(),
            since,
            since
        ))
    }
}

/// The thresholds an operator stored, exactly as `workflow_sla_thresholds`
/// holds them. Both are optional; a row with neither set is judgeable and
/// simply produces no breach.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct SlaThresholds {
    pub p95_latency_ms: Option<i64>,
    pub success_rate_pct: Option<f64>,
}

/// Which SLA metric a breach is about. Stable wire tokens — the webhook
/// payload's `metric` field has always been one of these two strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlaMetric {
    P95LatencyMs,
    SuccessRatePct,
}

impl SlaMetric {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::P95LatencyMs => "p95_latency_ms",
            Self::SuccessRatePct => "success_rate_pct",
        }
    }
}

/// One breach, ready to render.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SlaBreach {
    pub metric: SlaMetric,
    pub threshold: f64,
    pub actual: f64,
}

/// Why a threshold could not be evaluated this tick. Never a silent skip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlaNotEvaluated {
    /// Neither table holds a settled run in the window.
    NoRuns,
    /// The ONLY evidence is child runs, and there are fewer than
    /// [`LEDGER_MIN_RUNS`] of them.
    BelowLedgerFloor,
}

impl SlaNotEvaluated {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoRuns => "no_runs_in_window",
            Self::BelowLedgerFloor => "below_ledger_floor",
        }
    }
}

/// The breach decision for one threshold row.
#[derive(Debug, Clone, PartialEq)]
pub struct SlaBreachDecision {
    /// Every threshold this window breached. Empty is a real answer when
    /// `not_evaluated` is `None`.
    pub breaches: Vec<SlaBreach>,
    /// `Some` when the window could not be judged at all.
    pub not_evaluated: Option<SlaNotEvaluated>,
}

impl SlaBreachDecision {
    /// Did anything breach?
    #[must_use]
    pub fn fired(&self) -> bool {
        !self.breaches.is_empty()
    }
}

/// THE SLA breach decision. Pure, so the loop that uses it — which is
/// bin-private and undrivable from any test — keeps only wiring.
///
/// # The floor, and why it gates BOTH metrics
///
/// When the ONLY evidence is child runs, [`LEDGER_MIN_RUNS`] gates the
/// decision, for the reason `readiness_basis` argues and this surface makes
/// sharper: a single failed child run is a 0% success rate, and this is an
/// ALERTER, so that determinate negative pages somebody. The same argument
/// applies to p95 without weakening: a p95 over n=1 IS that one run's latency,
/// so a single slow cold start would fire a latency breach. Both are gated at
/// the same floor for the same reason.
///
/// The floor does NOT apply when `workflow_executions` holds runs: that is a
/// population the monitor already alerted on before RFC 0012, and adding a
/// refusal to it would be a behaviour change nobody asked for.
#[must_use]
pub fn decide_sla_breaches(
    sources: &SlaWindowSources,
    thresholds: &SlaThresholds,
) -> SlaBreachDecision {
    if sources.combined.total <= 0 {
        return SlaBreachDecision {
            breaches: Vec::new(),
            not_evaluated: Some(SlaNotEvaluated::NoRuns),
        };
    }
    if sources.executions.total <= 0 && sources.child_runs.total < LEDGER_MIN_RUNS {
        return SlaBreachDecision {
            breaches: Vec::new(),
            not_evaluated: Some(SlaNotEvaluated::BelowLedgerFloor),
        };
    }

    let mut breaches = Vec::new();
    // Strictly greater / strictly less, unchanged from the pre-P3 monitor.
    if let (Some(threshold), Some(actual)) = (thresholds.p95_latency_ms, sources.combined.p95_ms) {
        #[allow(clippy::cast_precision_loss)]
        let threshold_f = threshold as f64;
        if actual > threshold_f {
            breaches.push(SlaBreach {
                metric: SlaMetric::P95LatencyMs,
                threshold: threshold_f,
                actual,
            });
        }
    }
    if let (Some(threshold), Some(actual)) = (
        thresholds.success_rate_pct,
        sources.combined.success_rate_pct(),
    ) {
        if actual < threshold {
            breaches.push(SlaBreach {
                metric: SlaMetric::SuccessRatePct,
                threshold,
                actual,
            });
        }
    }
    SlaBreachDecision {
        breaches,
        not_evaluated: None,
    }
}

/// A SHORT, non-leaking class for a failed SLA read.
///
/// The alerter logs the class at WARN and the full chain at DEBUG: a WARN that
/// carries a whole error chain is a WARN nobody reads, and an alerter that
/// cannot measure must say so in the one channel it has without turning every
/// tick into a wall of text.
#[must_use]
pub fn sla_read_error_class(err: &anyhow::Error) -> &'static str {
    match err.root_cause().downcast_ref::<sqlx::Error>() {
        Some(sqlx::Error::PoolTimedOut) => "pool_timeout",
        Some(sqlx::Error::PoolClosed) => "pool_closed",
        Some(sqlx::Error::Io(_)) => "io",
        Some(sqlx::Error::Database(_)) => "database",
        Some(sqlx::Error::ColumnDecode { .. } | sqlx::Error::ColumnNotFound(_)) => "schema_drift",
        Some(_) => "sqlx_other",
        None => "other",
    }
}

/// Read both SLA populations for one workflow over `window_hours`, as ONE
/// statement plus the process-cached ledger floor.
///
/// Tenant-scoped on BOTH halves by the caller's `user_id`, and the ledger half
/// additionally runs under RLS via `child_run_stats_since`'s sibling contract —
/// this read uses the bare pool because its two callers are system tasks with
/// no tenant GUC, exactly like the retention sweep, and the app-layer predicate
/// is explicit on both sides of the union.
///
/// # Errors
/// Any database failure. Deliberately NOT collapsed into an empty result: an
/// alerter that cannot measure must be able to say so.
pub async fn read_sla_window_sources(
    pool: &sqlx::PgPool,
    workflow_id: Uuid,
    user_id: Uuid,
    window_hours: i64,
) -> Result<SlaWindowSources> {
    let hours = i32::try_from(window_hours).unwrap_or(i32::MAX);
    let rows = sqlx::query(
        "WITH runs AS ( \
             SELECT 'execution'::text AS src, \
                    (status = 'completed') AS ok, \
                    EXTRACT(EPOCH FROM (completed_at - started_at)) * 1000 AS dur_ms \
             FROM workflow_executions \
             WHERE workflow_id = $1 AND user_id = $2 \
               AND started_at > NOW() - make_interval(hours => $3::int) \
               AND completed_at IS NOT NULL \
             UNION ALL \
             SELECT 'child_run'::text, \
                    (status = 'completed'), \
                    duration_ms::double precision \
             FROM sub_workflow_runs \
             WHERE child_workflow_id = $1 AND user_id = $2 \
               AND started_at > NOW() - make_interval(hours => $3::int) \
         ) \
         SELECT src, \
                COUNT(*)::bigint AS total, \
                COUNT(*) FILTER (WHERE ok)::bigint AS succeeded, \
                PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY dur_ms) AS p95_ms \
         FROM runs \
         GROUP BY ROLLUP(src)",
    )
    .bind(workflow_id)
    .bind(user_id)
    .bind(hours)
    .fetch_all(pool)
    .await
    .context("read_sla_window_sources")?;

    let mut out = SlaWindowSources::empty(window_hours);
    for r in &rows {
        let stats = SlaSourceStats {
            total: r.try_get::<Option<i64>, _>("total")?.unwrap_or_default(),
            succeeded: r
                .try_get::<Option<i64>, _>("succeeded")?
                .unwrap_or_default(),
            p95_ms: r.try_get::<Option<f64>, _>("p95_ms")?,
        };
        // ROLLUP's grand-total row carries a NULL `src`.
        match r.try_get::<Option<String>, _>("src")?.as_deref() {
            Some("execution") => out.executions = stats,
            Some("child_run") => out.child_runs = stats,
            None => out.combined = stats,
            Some(other) => {
                anyhow::bail!("read_sla_window_sources: unexpected source label {other}")
            }
        }
    }
    // The floor is a DEPLOYMENT fact and is read the same way every other
    // consumer reads it. A failure here fails the whole read: a child-run count
    // without a floor beside it is the bare zero this whole phase refuses.
    out.ledger_since = talos_child_run_ledger::ChildRunLedger::new(pool.clone())
        .since()
        .await
        .context("read_sla_window_sources: ledger floor")?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src(total: i64, succeeded: i64, p95: Option<f64>) -> SlaSourceStats {
        SlaSourceStats {
            total,
            succeeded,
            p95_ms: p95,
        }
    }

    fn sources(exec: SlaSourceStats, child: SlaSourceStats, p95: Option<f64>) -> SlaWindowSources {
        SlaWindowSources {
            executions: exec,
            child_runs: child,
            combined: src(
                exec.total + child.total,
                exec.succeeded + child.succeeded,
                p95,
            ),
            ledger_since: Some(Utc::now() - chrono::Duration::days(3)),
            window_hours: 24,
        }
    }

    /// An empty window is NOT a compliant window, and it says which.
    ///
    /// MUTATION: return an empty `SlaBreachDecision` with `not_evaluated: None`.
    #[test]
    fn an_empty_window_is_not_evaluated_not_compliant() {
        let d = decide_sla_breaches(
            &sources(src(0, 0, None), src(0, 0, None), None),
            &SlaThresholds {
                p95_latency_ms: Some(10),
                success_rate_pct: Some(99.0),
            },
        );
        assert!(!d.fired());
        assert_eq!(d.not_evaluated, Some(SlaNotEvaluated::NoRuns));
    }

    /// The whole point of P3 for this surface: a threshold on a CHILD is no
    /// longer silently inert.
    ///
    /// MUTATION: drop the `child_runs` half of the union (the decision then
    /// returns `NoRuns` for a workflow that ran twenty times).
    #[test]
    fn a_child_only_population_can_now_breach() {
        let d = decide_sla_breaches(
            &sources(src(0, 0, None), src(20, 10, Some(9_000.0)), Some(9_000.0)),
            &SlaThresholds {
                p95_latency_ms: Some(5_000),
                success_rate_pct: Some(99.0),
            },
        );
        assert!(d.not_evaluated.is_none());
        assert_eq!(
            d.breaches.len(),
            2,
            "both thresholds breach: {:?}",
            d.breaches
        );
        assert!(d
            .breaches
            .iter()
            .any(|b| b.metric == SlaMetric::SuccessRatePct && (b.actual - 50.0).abs() < 1e-9));
    }

    /// ONE failed child run is not a 0% success rate an alerter may page on,
    /// and it is not a p95 either.
    ///
    /// MUTATION: `LEDGER_MIN_RUNS = 1`, or drop the floor branch.
    #[test]
    fn a_child_only_population_below_the_floor_is_not_evaluated() {
        let d = decide_sla_breaches(
            &sources(src(0, 0, None), src(1, 0, Some(60_000.0)), Some(60_000.0)),
            &SlaThresholds {
                p95_latency_ms: Some(1_000),
                success_rate_pct: Some(99.0),
            },
        );
        assert!(!d.fired(), "n=1 must not page anybody");
        assert_eq!(d.not_evaluated, Some(SlaNotEvaluated::BelowLedgerFloor));
    }

    /// The floor does NOT gate a population the monitor already alerted on.
    ///
    /// MUTATION: apply the floor whenever `combined.total < LEDGER_MIN_RUNS`.
    #[test]
    fn the_floor_does_not_refuse_an_execution_population() {
        let d = decide_sla_breaches(
            &sources(src(1, 0, Some(60_000.0)), src(0, 0, None), Some(60_000.0)),
            &SlaThresholds {
                p95_latency_ms: Some(1_000),
                success_rate_pct: Some(99.0),
            },
        );
        assert!(d.not_evaluated.is_none());
        assert_eq!(d.breaches.len(), 2);
    }

    /// A workflow the ledger says nothing about produces the pre-P3 answer,
    /// and NO population note — nothing to say ⇒ no key.
    ///
    /// MUTATION: return `Some(..)` from `population_note` unconditionally.
    #[test]
    fn a_workflow_with_no_child_runs_is_unchanged() {
        let s = sources(src(10, 10, Some(100.0)), src(0, 0, None), Some(100.0));
        let d = decide_sla_breaches(
            &s,
            &SlaThresholds {
                p95_latency_ms: Some(1_000),
                success_rate_pct: Some(99.0),
            },
        );
        assert!(!d.fired());
        assert!(d.not_evaluated.is_none());
        assert!(s.population_note().is_none());
        assert!(!s.ledger_contributed());
    }

    /// The split is disclosed whenever the ledger contributed, so a breach
    /// measured from 3 child runs cannot be mistaken for one from 300
    /// executions.
    #[test]
    fn a_hybrid_population_discloses_its_split() {
        let s = sources(src(2, 2, Some(50.0)), src(8, 4, Some(90.0)), Some(80.0));
        let note = s.population_note().expect("the split is disclosed");
        assert!(note.contains("2 workflow_executions row(s)"));
        assert!(note.contains("8 child run(s)"));
        assert!(note.contains("UNKNOWN, not zero"));
        assert_eq!(s.combined.success_rate_pct(), Some(60.0));
    }

    /// A threshold row with neither field set is judgeable and simply fires
    /// nothing — it must not read as "not evaluated".
    #[test]
    fn a_threshold_row_with_no_thresholds_fires_nothing_and_is_evaluated() {
        let d = decide_sla_breaches(
            &sources(src(5, 5, Some(1.0)), src(0, 0, None), Some(1.0)),
            &SlaThresholds::default(),
        );
        assert!(!d.fired());
        assert!(d.not_evaluated.is_none());
    }

    /// The comparisons are strict, unchanged from the pre-P3 monitor.
    #[test]
    fn a_metric_exactly_at_its_threshold_does_not_breach() {
        let d = decide_sla_breaches(
            &sources(src(100, 99, Some(1_000.0)), src(0, 0, None), Some(1_000.0)),
            &SlaThresholds {
                p95_latency_ms: Some(1_000),
                success_rate_pct: Some(99.0),
            },
        );
        assert!(!d.fired(), "equality is not a breach: {:?}", d.breaches);
    }
}
