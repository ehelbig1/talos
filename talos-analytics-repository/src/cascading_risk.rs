//! A sub-workflow's failure rate is MEASURABLE once the ledger can see it —
//! RFC 0012 P3.
//!
//! `get_workflow_risk_assessment`'s cascading-failure check reads
//! [`crate::AnalyticsRepository::get_risk_exec_counts_for_ids`] — seven days of
//! `workflow_executions`, and nothing else. A sub-workflow runs in-process and
//! records no row there, so every child landed in
//! `cascading_failure_check.sub_workflows_unmeasurable` and the HIGH-severity
//! `high_failure_sub_workflow` risk could not fire for any of them. #762
//! DISCLOSED that; it could not fix it, because nothing could answer the
//! question.
//!
//! Measured 2026-09-07 on a scratch database, driving the real production read:
//! a child with THREE recorded runs in the window, **all failed**, returns an
//! EMPTY map from `get_risk_exec_counts_for_ids` while
//! `ChildRunLedger::child_run_stats_since` returns `runs: 3, failed: 3`. So the
//! check reported a child failing 100% of its runs exactly as it reports one
//! that never ran.
//!
//! This module is the DECISION — pure, three-valued, and shared — that turns
//! the two reads into one verdict.
//!
//! # The HYBRID case, and why the two populations are unioned
//!
//! A workflow can be BOTH dispatched as a child and triggered directly, so both
//! tables can hold real runs of it inside one window. They are runs of the same
//! workflow, so the failure rate an operator cares about is over both:
//! numerator and denominator are unioned and the SPLIT is disclosed on the
//! finding, so a 40% rate measured from 5 execution rows and 15 child runs
//! cannot be mistaken for one measured from 20 execution rows.
//!
//! Keeping them separate was considered and rejected: it would report two
//! failure rates for one workflow under one category, and the reader would have
//! to combine them anyway — with no denominator to combine them on, since the
//! check renders one `description` string per child.
//!
//! # The floor applies to the CHILD-ONLY population, and only there
//!
//! [`crate::LEDGER_MIN_RUNS`] gates promotion when the EXECUTION side is empty,
//! for the reason `readiness_basis` argues at length: one recorded run makes a
//! single failure a "100% failure rate", which is the determinate negative this
//! whole class is about, in alerting form. When the execution side is non-empty
//! the check already had a population it was willing to judge — the ledger only
//! ADDS evidence to it — so the floor would be a new refusal on a finding that
//! fires today, and it is not applied there.
//!
//! # UNKNOWN is not zero, and "not consulted" is a third thing
//!
//! [`SubWorkflowRiskVerdict::Unmeasurable`] carries a
//! [`UnmeasurableReason`] rather than a bare absence, because *the ledger was
//! never read*, *the ledger holds no rows at all*, *the ledger was recording
//! and saw none*, and *the ledger saw some but below the floor* are four
//! different sentences an operator acts on differently — and the first is a
//! statement about this code path, not about the workflow.

use chrono::{DateTime, Utc};

use crate::readiness_basis::{ChildLedgerEvidence, LEDGER_MIN_RUNS};

/// The failure rate above which the cascading-failure check pushes a HIGH risk.
///
/// Unchanged from the pre-P3 handler (`fail_rate > 20.0`), and named here so
/// the threshold and the population it is applied to live in one place.
pub const HIGH_FAILURE_RATE_PCT: f64 = 20.0;

/// Which table(s) the failure rate was measured over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskPopulation {
    /// `workflow_executions` rows only — the pre-P3 answer, and still the
    /// answer for a workflow the ledger says nothing about.
    Executions,
    /// `sub_workflow_runs` only: the workflow has no execution rows in the
    /// window and at least [`LEDGER_MIN_RUNS`] recorded child runs.
    ChildRuns,
    /// Both tables hold runs of this workflow in the window.
    Both,
}

impl RiskPopulation {
    /// Stable wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Executions => "workflow_executions",
            Self::ChildRuns => "sub_workflow_runs",
            Self::Both => "workflow_executions+sub_workflow_runs",
        }
    }
}

/// A child whose failure rate the check COULD measure.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MeasuredSubWorkflow {
    /// Failed runs across the unioned population.
    pub failed: i64,
    /// Total runs across the unioned population.
    pub total: i64,
    /// `workflow_executions` rows in the window.
    pub execution_rows: i64,
    /// How many of those failed.
    pub execution_failed: i64,
    /// `sub_workflow_runs` rows in the window (at or after `ledger_since`).
    pub child_runs: i64,
    /// How many of those the ledger classified `failed`.
    pub child_runs_failed: i64,
    /// The earliest run the ledger still holds. `None` = the table is empty.
    pub ledger_since: Option<DateTime<Utc>>,
    /// Which table(s) the numbers came from.
    pub population: RiskPopulation,
}

impl MeasuredSubWorkflow {
    /// Failure rate over the unioned population, as a percentage.
    ///
    /// `total > 0` by construction — a verdict is only `Measured` when at
    /// least one side had rows — so this is never a rate over nothing.
    #[must_use]
    pub fn fail_rate_pct(&self) -> f64 {
        if self.total <= 0 {
            return 0.0;
        }
        #[allow(clippy::cast_precision_loss)]
        {
            (self.failed as f64 / self.total as f64) * 100.0
        }
    }

    /// Does this child clear the HIGH-severity bar?
    #[must_use]
    pub fn breaches(&self) -> bool {
        self.fail_rate_pct() > HIGH_FAILURE_RATE_PCT
    }

    /// Did the ledger contribute any run to this verdict?
    #[must_use]
    pub const fn ledger_contributed(&self) -> bool {
        self.child_runs > 0
    }

    /// One sentence naming the split, or `None` when the ledger contributed
    /// nothing — in which case the finding is exactly the pre-P3 one and
    /// gains no key.
    #[must_use]
    pub fn population_note(&self) -> Option<String> {
        if !self.ledger_contributed() {
            return None;
        }
        let since = self
            .ledger_since
            .map_or_else(|| "unknown".to_string(), |s| s.to_rfc3339());
        Some(format!(
            "Measured over {} run(s): {} workflow_executions row(s) ({} failed) and {} \
             child run(s) from the RFC 0012 ledger ({} failed, recorded since {}). A \
             sub-workflow runs in-process and records no workflow_executions row, so the \
             ledger is the only table that can see those runs; a period before {} is \
             UNKNOWN, not zero.",
            self.total,
            self.execution_rows,
            self.execution_failed,
            self.child_runs,
            self.child_runs_failed,
            since,
            since
        ))
    }
}

/// Why a child's failure rate could not be measured. Four distinct sentences,
/// because an operator acts on them differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnmeasurableReason {
    /// The ledger was not read on this path — a statement about the CODE, not
    /// about the workflow. Kept distinct so a wiring regression cannot render
    /// as "this child has no evidence".
    LedgerNotConsulted,
    /// The ledger holds no rows at all, so its zero is UNKNOWN.
    LedgerEmpty,
    /// The ledger was recording throughout and saw no run of this child.
    NoRunsRecorded,
    /// The ledger saw some runs, but fewer than [`LEDGER_MIN_RUNS`].
    BelowLedgerFloor,
}

impl UnmeasurableReason {
    /// Stable wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LedgerNotConsulted => "ledger_not_consulted",
            Self::LedgerEmpty => "ledger_empty",
            Self::NoRunsRecorded => "no_runs_recorded",
            Self::BelowLedgerFloor => "below_ledger_floor",
        }
    }
}

/// A child the check could not judge, WITH the numbers behind that.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UnmeasurableSubWorkflow {
    /// Why.
    pub reason: UnmeasurableReason,
    /// Recorded child runs in the window. `0` here MEANS the reason above —
    /// never read it as "it did not run".
    pub child_runs: i64,
    /// How many of those failed.
    pub child_runs_failed: i64,
    /// The ledger's floor, when it was read.
    pub ledger_since: Option<DateTime<Utc>>,
    /// The start of the window asked about, when the ledger was read.
    pub window_start: Option<DateTime<Utc>>,
}

impl UnmeasurableSubWorkflow {
    /// One sentence for the operator. Always names the floor when there is
    /// one: a count without it cannot be told from the period nobody was
    /// recording.
    #[must_use]
    pub fn note(&self) -> String {
        match self.reason {
            UnmeasurableReason::LedgerNotConsulted => {
                "The child-run ledger was NOT consulted for this workflow, so nothing here \
                 says how often it actually runs. This is a statement about this code path, \
                 not about the workflow."
                    .to_string()
            }
            UnmeasurableReason::LedgerEmpty => {
                "No workflow_executions rows in the window, and the child-run ledger \
                 (sub_workflow_runs) holds no rows at all — so a zero here is UNKNOWN, not \
                 evidence that this sub-workflow is healthy."
                    .to_string()
            }
            UnmeasurableReason::NoRunsRecorded => format!(
                "No workflow_executions rows in the window, and the child-run ledger has been \
                 recording since {} and recorded NO run of this workflow. Anything before that \
                 date is UNKNOWN — nobody was recording. (An id can also appear here because it \
                 is not yours or no longer exists; the two are indistinguishable from these \
                 queries.)",
                self.ledger_since
                    .map_or_else(|| "an unknown date".to_string(), |s| s.to_rfc3339())
            ),
            UnmeasurableReason::BelowLedgerFloor => format!(
                "No workflow_executions rows in the window, and {} recorded child run(s) \
                 ({} failed) since {} — below the {}-run floor at which a failure RATE is a \
                 rate rather than an anecdote. Not judged, and not called healthy.",
                self.child_runs,
                self.child_runs_failed,
                self.ledger_since
                    .map_or_else(|| "an unknown date".to_string(), |s| s.to_rfc3339()),
                LEDGER_MIN_RUNS
            ),
        }
    }
}

/// The check's answer for ONE child.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SubWorkflowRiskVerdict {
    /// There was a population to judge.
    Measured(MeasuredSubWorkflow),
    /// There was not, and this says why.
    Unmeasurable(UnmeasurableSubWorkflow),
}

/// THE cascading-failure decision. One implementation, one caller today, and
/// pure so it is testable without a database.
///
/// `exec` is `get_risk_exec_counts_for_ids`' `(failed, total)` for this child —
/// `None` when the id is ABSENT from that sparse map, which means *no rows in
/// the window* OR *not this user's workflow*, indistinguishably.
///
/// `ledger` is `None` when the ledger was NOT consulted (no reader wired, or
/// the read failed) — deliberately not the same value as "consulted and holds
/// nothing", which is `Some(evidence)` with `runs: 0`.
#[must_use]
pub fn classify_sub_workflow_risk(
    exec: Option<(i64, i64)>,
    ledger: Option<ChildLedgerEvidence>,
) -> SubWorkflowRiskVerdict {
    let (exec_failed, exec_total) = exec.unwrap_or((0, 0));
    let exec_total = exec_total.max(0);
    let exec_failed = exec_failed.max(0);
    let (child_runs, child_failed) = ledger.map_or((0, 0), |e| (e.runs.max(0), e.failed.max(0)));
    let ledger_since = ledger.and_then(|e| e.ledger_since);

    // The execution side is a population the check already judged before RFC
    // 0012; the ledger only widens it, so no floor applies here.
    if exec_total > 0 {
        return SubWorkflowRiskVerdict::Measured(MeasuredSubWorkflow {
            failed: exec_failed + child_failed,
            total: exec_total + child_runs,
            execution_rows: exec_total,
            execution_failed: exec_failed,
            child_runs,
            child_runs_failed: child_failed,
            ledger_since,
            population: if child_runs > 0 {
                RiskPopulation::Both
            } else {
                RiskPopulation::Executions
            },
        });
    }

    // Child-only: the floor protects the RATE claim.
    if child_runs >= LEDGER_MIN_RUNS {
        return SubWorkflowRiskVerdict::Measured(MeasuredSubWorkflow {
            failed: child_failed,
            total: child_runs,
            execution_rows: 0,
            execution_failed: 0,
            child_runs,
            child_runs_failed: child_failed,
            ledger_since,
            population: RiskPopulation::ChildRuns,
        });
    }

    let reason = match ledger {
        None => UnmeasurableReason::LedgerNotConsulted,
        Some(e) if e.ledger_since.is_none() => UnmeasurableReason::LedgerEmpty,
        Some(e) if e.runs > 0 => UnmeasurableReason::BelowLedgerFloor,
        Some(_) => UnmeasurableReason::NoRunsRecorded,
    };
    SubWorkflowRiskVerdict::Unmeasurable(UnmeasurableSubWorkflow {
        reason,
        child_runs,
        child_runs_failed: child_failed,
        ledger_since,
        window_start: ledger.map(|e| e.window_start),
    })
}

/// The window the cascading-failure check measures over, in days.
///
/// Pinned to the `INTERVAL '7 days'` in
/// `AnalyticsRepository::get_risk_exec_counts_for_ids` — the ledger read must
/// cover the same period or the two halves of one union would describe
/// different windows.
pub const RISK_WINDOW_DAYS: i64 = 7;

/// The start of the cascading-failure window relative to `now`.
#[must_use]
pub fn risk_window_start(now: DateTime<Utc>) -> DateTime<Utc> {
    now - chrono::Duration::days(RISK_WINDOW_DAYS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(runs: i64, failed: i64, since: Option<DateTime<Utc>>) -> ChildLedgerEvidence {
        ChildLedgerEvidence {
            runs,
            failed,
            last_started_at: None,
            ledger_since: since,
            window_start: Utc::now() - chrono::Duration::days(RISK_WINDOW_DAYS),
        }
    }

    fn a_floor() -> Option<DateTime<Utc>> {
        Some(Utc::now() - chrono::Duration::days(30))
    }

    /// The window the ledger read uses must be the one the execution read
    /// uses, or the two halves of a union describe different periods.
    #[test]
    fn the_risk_window_matches_the_execution_window() {
        let src = include_str!("lib.rs");
        assert!(
            src.contains("started_at > NOW() - INTERVAL '7 days'"),
            "get_risk_exec_counts_for_ids no longer uses a 7-day window"
        );
        assert_eq!(RISK_WINDOW_DAYS, 7);
    }

    /// A1, as a pure decision: three recorded runs, all failed, no execution
    /// rows. Pre-P3 this was `unmeasurable` and pushed nothing.
    ///
    /// MUTATION that turns it red: return `Unmeasurable` whenever
    /// `exec_total == 0`, i.e. the pre-P3 behaviour.
    #[test]
    fn a_totally_failing_child_is_now_measured_and_breaches() {
        let v = classify_sub_workflow_risk(None, Some(evidence(3, 3, a_floor())));
        let SubWorkflowRiskVerdict::Measured(m) = v else {
            panic!("expected Measured, got {v:?}");
        };
        assert_eq!((m.failed, m.total), (3, 3));
        assert!((m.fail_rate_pct() - 100.0).abs() < f64::EPSILON);
        assert!(m.breaches());
        assert_eq!(m.population, RiskPopulation::ChildRuns);
    }

    /// BELOW the floor a single failed run is NOT a 100% failure rate.
    ///
    /// MUTATION: `LEDGER_MIN_RUNS = 1`.
    #[test]
    fn one_failed_child_run_is_not_a_hundred_percent_failure_rate() {
        let v = classify_sub_workflow_risk(None, Some(evidence(1, 1, a_floor())));
        let SubWorkflowRiskVerdict::Unmeasurable(u) = v else {
            panic!("expected Unmeasurable, got {v:?}");
        };
        assert_eq!(u.reason, UnmeasurableReason::BelowLedgerFloor);
        assert_eq!(u.child_runs, 1);
        assert!(u.note().contains("below the 3-run floor"));
    }

    /// "Not consulted" is a statement about the code path and must not render
    /// as "no evidence about this workflow".
    ///
    /// MUTATION: fold `None` into the `NoRunsRecorded` arm.
    #[test]
    fn a_ledger_that_was_not_read_says_so() {
        let v = classify_sub_workflow_risk(None, None);
        let SubWorkflowRiskVerdict::Unmeasurable(u) = v else {
            panic!("expected Unmeasurable");
        };
        assert_eq!(u.reason, UnmeasurableReason::LedgerNotConsulted);
        assert!(u.note().contains("NOT consulted"));
        assert!(u.ledger_since.is_none());
    }

    /// An EMPTY ledger's zero is UNKNOWN and renders differently from a ledger
    /// that was recording and saw nothing.
    ///
    /// MUTATION: drop the `ledger_since.is_none()` arm.
    #[test]
    fn an_empty_ledger_and_a_silent_one_are_different_sentences() {
        let empty = classify_sub_workflow_risk(None, Some(evidence(0, 0, None)));
        let silent = classify_sub_workflow_risk(None, Some(evidence(0, 0, a_floor())));
        let (SubWorkflowRiskVerdict::Unmeasurable(e), SubWorkflowRiskVerdict::Unmeasurable(s)) =
            (empty, silent)
        else {
            panic!("expected two Unmeasurable verdicts");
        };
        assert_eq!(e.reason, UnmeasurableReason::LedgerEmpty);
        assert_eq!(s.reason, UnmeasurableReason::NoRunsRecorded);
        assert_ne!(e.note(), s.note());
    }

    /// HYBRID: both tables hold runs, and the rate is over both with the split
    /// disclosed.
    ///
    /// MUTATION: drop `child_runs` from the union (`total: exec_total`), which
    /// returns 50% instead of 20%.
    #[test]
    fn a_hybrid_child_is_measured_over_both_tables_with_the_split_disclosed() {
        let v = classify_sub_workflow_risk(Some((1, 2)), Some(evidence(8, 0, a_floor())));
        let SubWorkflowRiskVerdict::Measured(m) = v else {
            panic!("expected Measured");
        };
        assert_eq!((m.failed, m.total), (1, 10));
        assert!((m.fail_rate_pct() - 10.0).abs() < f64::EPSILON);
        assert!(!m.breaches(), "10% must not clear a 20% bar");
        assert_eq!(m.population, RiskPopulation::Both);
        let note = m.population_note().expect("split is disclosed");
        assert!(note.contains("2 workflow_executions row(s)"));
        assert!(note.contains("8 child run(s)"));
    }

    /// The floor does NOT gate a population the check already judged: two
    /// execution rows, one failed, is the pre-P3 finding and stays one.
    ///
    /// MUTATION: apply the floor to the `exec_total > 0` branch too.
    #[test]
    fn the_floor_does_not_refuse_a_finding_that_fires_today() {
        let v = classify_sub_workflow_risk(Some((1, 2)), Some(evidence(0, 0, a_floor())));
        let SubWorkflowRiskVerdict::Measured(m) = v else {
            panic!("expected Measured");
        };
        assert_eq!(m.population, RiskPopulation::Executions);
        assert!(m.breaches());
        assert!(
            m.population_note().is_none(),
            "nothing to say about the ledger ⇒ no key"
        );
    }

    /// The bar is STRICTLY greater, unchanged from the pre-P3 handler.
    #[test]
    fn exactly_twenty_percent_does_not_breach() {
        let v = classify_sub_workflow_risk(Some((1, 5)), None);
        let SubWorkflowRiskVerdict::Measured(m) = v else {
            panic!("expected Measured");
        };
        assert!((m.fail_rate_pct() - 20.0).abs() < f64::EPSILON);
        assert!(!m.breaches());
    }
}
