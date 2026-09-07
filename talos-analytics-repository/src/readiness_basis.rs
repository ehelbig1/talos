//! A child's reliability and freshness are UNMEASURABLE, not zero.
//!
//! `execute_subworkflow_graph` runs a child IN-PROCESS and records no
//! `workflow_executions` row — measured 2026-09-05: ZERO rows carrying
//! `parent_execution_id` across the live table AND the archive, platform-wide,
//! over 10 140 execution rows. Two of the four readiness components are read
//! from that table and from nothing else:
//!
//! | component | max | source |
//! |---|---|---|
//! | reliability | 50 | `workflow_executions` success rate × run-count ramp |
//! | freshness | 20 | `MAX(workflow_executions.started_at)` |
//! | documentation | 20 | `workflows.description` / node descriptions / `capabilities` |
//! | risk | 10 | the graph's timeout + error edges, and `secrets.expires_at` |
//!
//! So for a workflow a parent dispatches into, 70 of the 100 points are scored
//! from a table that is structurally silent about it, and the three scorers
//! that exist all award 0 for both. Measured on the reference deployment
//! 2026-09-05 — every one of the four parent-dispatched workflows on the fleet:
//!
//! ```text
//! cos-team-recall  19   parent pa-chief-of-staff  (the flagship's daily team gather)
//! pa-ask           19   parent pa-ask-email       (runs per inbound email)
//! pa-quality-judge 19   parents pa-chief-of-staff, pa-daily-brief, pa-meeting-prep
//! stress-05-child  14   parent stress-05-parent
//! ```
//!
//! …against a fleet whose other rows sit at 40–87. The hourly recompute in
//! `controller/src/bootstrap/background.rs` PERSISTS those numbers to
//! `workflows.readiness_score`, and `get_all_readiness_scores` then reads them
//! back and sorts ascending — so the flagship's own daily sub-workflow reads as
//! the least production-ready workflow on the platform, and
//! `below_50_count` counts it.
//!
//! # Why the score is not renormalised to 100
//!
//! Two renderings were considered and rejected before this one:
//!
//! * **Score the two components as 0 out of 100** (today's behaviour). That is
//!   a determinate negative asserted about a state the reader cannot represent
//!   — the misleading-report class this repository already lints for in checks
//!   74, 76, 79 and 81. "Never run" and "runs constantly, invisibly" render
//!   identically.
//! * **Score the measurable 30 and scale it up to 100.** That FABRICATES. A
//!   child with a description, capabilities, node descriptions, a timeout and
//!   error edges would report **100/100 — fully production-ready** on zero
//!   execution evidence whatsoever, which is a worse claim than the one it
//!   replaces because it is confident in the reassuring direction.
//!
//! What is left is to shrink the DENOMINATOR and say so: a child scores *N of
//! 30 measurable points*, its two unmeasurable components are named, and
//! [`ReadinessOutcome::comparable_to_fleet`] is false. The shrunken denominator
//! is the thing that tells a reader the two numbers are not on one scale; a
//! number out of 100 does not, however it was derived.
//!
//! # RFC 0012 P2 — when the ledger CAN measure it
//!
//! Everything above is a rule for reading silence. `sub_workflow_runs` (RFC
//! 0012 P1) is the first thing that can ANSWER the question, so a child with
//! enough recorded runs is no longer unmeasurable: reliability becomes the
//! ledger's success rate and freshness the age of its newest recorded run,
//! both through the SAME [`crate::compute_reliability_score`] /
//! [`crate::compute_freshness_score`] the full scale uses, and the score goes
//! back on the 100-point denominator as
//! [`ReadinessBasis::LedgerMeasured`].
//!
//! **This is not the renormalisation that was rejected above.** The rejected
//! rendering scaled a 30-point score UP to 100 with nothing new measured; this
//! one measures the two missing components and then scores all four. The
//! difference is evidence, and the floor below is what makes it evidence
//! rather than a gesture.
//!
//! ## The floor, and why it is [`LEDGER_MIN_RUNS`] = 3
//!
//! Below the floor a child STAYS on the 30-point basis, with the ledger count
//! and the floor DISCLOSED — never scaled up. Three values were considered:
//!
//! * **1.** Rejected. One recorded run promotes the child to the fleet scale,
//!   and if that single run failed the row then reports reliability `0/50` as
//!   a fleet-comparable fact. A determinate negative from one observation is
//!   the defect this module exists to refuse, in a new shape.
//! * **10** — the saturation point of the reliability ramp
//!   (`s · min(n/10, 1) · 50`). Rejected as too high: it keeps a child that
//!   has demonstrably run nine times on a denominator whose stated reason is
//!   *"nothing can measure this"*, which stops being true at the first row.
//! * **3.** Chosen. Three observations is the smallest number from which a
//!   success RATE is a rate rather than an anecdote, and the ramp already
//!   discounts thin evidence on its own — at n=3 a perfect child earns 15 of
//!   50 reliability points, so promotion cannot flatter it. What the floor
//!   protects is the DENOMINATOR claim (`comparable_to_fleet`), not the
//!   arithmetic.
//!
//! ## UNKNOWN is still not zero
//!
//! The ledger has a first row. A count over a 30-day window that starts before
//! `ChildRunLedger::since` covers only `[since, now]`, and the earlier part is
//! *nobody was recording*. Measured 2026-09-07: the floor is ~11 h old, so the
//! ledger covers **1.5%** of the readiness window. So
//! [`ChildLedgerEvidence`] carries the floor and the window start, and every
//! disclosure renders both beside the count.
//!
//! # REPORT semantics, and how UNKNOWN renders
//!
//! Child-ness is decided by [`ChildReferenceScan::parents_of`] — the REPORT
//! accessor — not `protection_for`. A parent whose graph could not be read
//! therefore does NOT make the workflow a child: it is scored on the full
//! 100-point scale exactly as before, with reliability 0. That is the wrong
//! direction for a report, so the incompleteness must travel to the caller by
//! NAME: every consumer surfaces
//! [`ChildReferenceScan::unreadable_parents`] beside the score, saying that a
//! workflow one of those parents dispatches into may still be scored as if it
//! had never run. Silence there would be the same defect one level down.

use chrono::{DateTime, Utc};
use talos_child_workflow_refs::ChildReferenceScan;
use uuid::Uuid;

/// The readiness points a parent-dispatched workflow can actually earn:
/// documentation (20) + risk (10).
///
/// Derived from the component maxima rather than written as a literal, so it
/// cannot drift from them — `child_max_matches_the_component_maxima` pins it.
pub const CHILD_MEASURABLE_MAX: i32 = DOCUMENTATION_MAX + RISK_MAX;

/// Full-scale maximum: every component measurable.
pub const FULL_MAX: i32 = RELIABILITY_MAX + DOCUMENTATION_MAX + FRESHNESS_MAX + RISK_MAX;

pub const RELIABILITY_MAX: i32 = 50;
pub const DOCUMENTATION_MAX: i32 = 20;
pub const FRESHNESS_MAX: i32 = 20;
pub const RISK_MAX: i32 = 10;

/// How many recorded child runs the ledger must hold, inside the readiness
/// window, before a child is scored on the FULL 100-point scale.
///
/// See the module header for the three values considered and why this one.
/// Below it the child keeps the [`CHILD_MEASURABLE_MAX`] denominator and the
/// shortfall is disclosed — a partial score is NEVER scaled up.
pub const LEDGER_MIN_RUNS: i64 = 3;

/// What the child-run ledger holds for one child, as the scorer sees it.
///
/// Deliberately a plain struct rather than `talos_child_run_ledger`'s own
/// type: this crate owns the BASIS decision and must not acquire a dependency
/// on the repository that answers it. The caller maps
/// `ChildRunLedger::child_run_stats_since` + `ChildRunLedger::since` onto this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChildLedgerEvidence {
    /// Recorded runs of this child in `[max(window_start, ledger_since), now]`.
    pub runs: i64,
    /// How many of those the ledger classified `failed`.
    pub failed: i64,
    /// `started_at` of the newest recorded run.
    pub last_started_at: Option<DateTime<Utc>>,
    /// The ledger's own floor — the earliest run it still holds, across all
    /// tenants. `None` means the table is EMPTY, which is not "zero runs".
    pub ledger_since: Option<DateTime<Utc>>,
    /// The start of the window the caller asked about (30 days ago, for every
    /// current caller). Rendered beside `ledger_since` so a reader can see how
    /// much of the window the ledger could speak for.
    pub window_start: DateTime<Utc>,
}

impl ChildLedgerEvidence {
    /// No rows, no floor — the shape a caller builds when `since()` says the
    /// table is empty. `runs` is 0 and MEANS UNKNOWN, which is why nothing
    /// here may be rendered as a bare zero.
    #[must_use]
    pub const fn unrecorded(window_start: DateTime<Utc>) -> Self {
        Self {
            runs: 0,
            failed: 0,
            last_started_at: None,
            ledger_since: None,
            window_start,
        }
    }

    /// Enough recorded runs to put this child back on the fleet scale.
    #[must_use]
    pub const fn meets_floor(&self) -> bool {
        self.runs >= LEDGER_MIN_RUNS
    }

    /// Success rate over the recorded runs, or `None` when there are none —
    /// a rate over zero runs has no value, and `0.0` there would render
    /// "nothing recorded" as "everything failed".
    #[must_use]
    pub fn success_rate(&self) -> Option<f64> {
        if self.runs <= 0 {
            return None;
        }
        #[allow(clippy::cast_precision_loss)]
        Some((self.runs - self.failed).max(0) as f64 / self.runs as f64)
    }

    /// The two execution-derived components, from the ledger, through the SAME
    /// pure functions the full scale uses — so a ledger-measured child and a
    /// top-level workflow with the same evidence score identically.
    #[must_use]
    pub fn components(&self, now: DateTime<Utc>) -> (f64, f64) {
        let reliability = crate::compute_reliability_score(self.success_rate(), self.runs);
        let days = self
            .last_started_at
            .map(|t| now.signed_duration_since(t).num_days());
        (reliability, crate::compute_freshness_score(days))
    }

    /// One sentence naming what the ledger holds and from when. Never a bare
    /// count: a count without the floor beside it cannot be told apart from
    /// the period nobody was recording.
    #[must_use]
    pub fn disclosure(&self) -> String {
        match self.ledger_since {
            None => {
                "The child-run ledger holds no rows at all, so `0 runs` here is UNKNOWN, not zero."
                    .to_string()
            }
            Some(since) => {
                let coverage = if since > self.window_start {
                    format!(
                        " The ledger's earliest surviving row is {}, which is AFTER the start of this \
                         window ({}), so the earlier part of the window is UNKNOWN — nobody was \
                         recording — and is not counted as zero.",
                        since.to_rfc3339(),
                        self.window_start.to_rfc3339()
                    )
                } else {
                    String::new()
                };
                format!(
                    "{} child run(s) recorded since {}, of which {} failed.{}",
                    self.runs,
                    since.to_rfc3339(),
                    self.failed,
                    coverage
                )
            }
        }
    }
}

/// The components an execution-blind workflow cannot be scored on, in the
/// order they are rendered.
pub const EXECUTION_DERIVED_COMPONENTS: &[&str] = &["reliability", "freshness"];

/// The one sentence every surface uses for why those two are unmeasurable.
/// Shared so three reports cannot describe the same fact three ways.
pub const CHILD_UNMEASURED_REASON: &str =
    "A parent dispatches into this workflow as a sub-workflow, which runs in-process and \
     records no workflow_executions row. Reliability and freshness are read from that table \
     and from nothing else, so they are UNMEASURABLE here — not zero. The score is out of the \
     measurable components only and is not comparable to a full-scale score.";

/// Which scale a readiness score is on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadinessBasis {
    /// Nothing dispatches into this workflow, so its execution rows are the
    /// whole story. Scored out of [`FULL_MAX`].
    FullScale,
    /// An enabled parent's graph names this workflow through one of the eight
    /// child-dispatch keys, and the child-run ledger cannot yet measure it.
    /// Scored out of [`CHILD_MEASURABLE_MAX`].
    ParentDispatched {
        /// Parent names, as [`ChildReferenceScan::parents_of`] returned them:
        /// sorted, deduplicated, and only parents whose graph actually parsed.
        parents: Vec<String>,
        /// What the ledger held when it was consulted. `None` = it was NOT
        /// consulted on this path (no reader wired, or the read failed), which
        /// is a THIRD state and not "zero runs" — the disclosure says which.
        ledger: Option<ChildLedgerEvidence>,
    },
    /// A parent-dispatched workflow the LEDGER can measure: at least
    /// [`LEDGER_MIN_RUNS`] recorded runs inside the window. Scored out of
    /// [`FULL_MAX`], with reliability and freshness computed from
    /// `sub_workflow_runs` instead of `workflow_executions`.
    ///
    /// This is the ONLY way a child returns to the fleet scale. It is not the
    /// rejected renormalisation: the two missing components were MEASURED, not
    /// inferred from the other two.
    LedgerMeasured {
        /// Parent names, same accessor and same semantics as
        /// [`Self::ParentDispatched`].
        parents: Vec<String>,
        /// The evidence the promotion rests on, rendered on every surface.
        ledger: ChildLedgerEvidence,
    },
}

impl ReadinessBasis {
    /// The REPORT answer for one workflow, from one scan and the child-run
    /// ledger.
    ///
    /// Deliberately `parents_of` and not `protection_for`: see the module
    /// header. A caller MUST also render `scan.unreadable_parents()`.
    ///
    /// **There is deliberately no `from_scan(scan, id)` convenience.** RFC
    /// 0012 P2 deleted it, for the reason P1 made `ChildRunSite` an enum with
    /// an explicit `Untracked` variant rather than an `Option`: a caller must
    /// STATE that it did not consult the ledger instead of defaulting into it.
    /// The two-argument form had zero production callers by the end of P2 and
    /// exactly one remaining behaviour — silently scoring every child on the
    /// 30-point basis — so a future scorer that forgot the ledger would have
    /// looked identical to one that could not read it.
    ///
    /// `evidence` is `None` when the ledger was not consulted on this path —
    /// which is NOT the same as "the ledger holds nothing", and the two render
    /// differently. Promotion to [`Self::LedgerMeasured`] requires
    /// [`ChildLedgerEvidence::meets_floor`]; below it the basis is
    /// [`Self::ParentDispatched`] carrying the evidence so the shortfall can
    /// be stated instead of silently rounding to the 30-point scale.
    #[must_use]
    pub fn from_scan_with_ledger(
        scan: &ChildReferenceScan,
        workflow_id: Uuid,
        evidence: Option<ChildLedgerEvidence>,
    ) -> Self {
        let parents = scan.parents_of(workflow_id);
        if parents.is_empty() {
            return Self::FullScale;
        }
        match evidence {
            Some(ev) if ev.meets_floor() => Self::LedgerMeasured {
                parents: parents.to_vec(),
                ledger: ev,
            },
            other => Self::ParentDispatched {
                parents: parents.to_vec(),
                ledger: other,
            },
        }
    }

    /// Stable wire token, rendered as `score_basis`.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::FullScale => "full_scale",
            Self::ParentDispatched { .. } => "measurable_components_only",
            Self::LedgerMeasured { .. } => "ledger",
        }
    }

    /// The parents behind a `ParentDispatched` basis, empty otherwise.
    #[must_use]
    pub fn parents(&self) -> &[String] {
        match self {
            Self::FullScale => &[],
            Self::ParentDispatched { parents, .. } | Self::LedgerMeasured { parents, .. } => {
                parents
            }
        }
    }

    /// True for BOTH child bases. A caller asking "is this somebody's child?"
    /// must keep getting `true` after a ledger promotion — the workflow did
    /// not stop being a child, it stopped being unmeasurable — so every
    /// `runs_as_child_of` renderer keeps working unchanged.
    #[must_use]
    pub const fn is_parent_dispatched(&self) -> bool {
        matches!(
            self,
            Self::ParentDispatched { .. } | Self::LedgerMeasured { .. }
        )
    }

    /// True only for a child scored on the SHRUNKEN denominator. This is the
    /// predicate a `below_50`-style exclusion must use: a ledger-measured
    /// child is on the fleet scale and must NOT be excluded, or the platform's
    /// most-used sub-workflows vanish from the one count that would notice
    /// them degrading.
    #[must_use]
    pub const fn is_unmeasurable_child(&self) -> bool {
        matches!(self, Self::ParentDispatched { .. })
    }

    /// The ledger evidence behind this basis, when there is any.
    #[must_use]
    pub const fn ledger(&self) -> Option<&ChildLedgerEvidence> {
        match self {
            Self::FullScale => None,
            Self::ParentDispatched { ledger, .. } => ledger.as_ref(),
            Self::LedgerMeasured { ledger, .. } => Some(ledger),
        }
    }

    /// The denominator this basis scores on.
    #[must_use]
    pub const fn max_points(&self) -> i32 {
        match self {
            Self::FullScale | Self::LedgerMeasured { .. } => FULL_MAX,
            Self::ParentDispatched { .. } => CHILD_MEASURABLE_MAX,
        }
    }
}

/// The four raw component scores, before the basis is applied.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ReadinessComponents {
    pub reliability: f64,
    pub documentation: f64,
    pub freshness: f64,
    pub risk: f64,
}

/// A scored workflow, on a named scale.
#[derive(Debug, Clone, PartialEq)]
pub struct ReadinessOutcome {
    /// Points earned. On a `ParentDispatched` basis this EXCLUDES the two
    /// execution-derived components rather than counting them as zero.
    pub score: i32,
    /// The denominator. `100` at full scale, [`CHILD_MEASURABLE_MAX`] for a
    /// child. Every renderer must emit it beside `score`.
    pub max_points: i32,
    pub basis: ReadinessBasis,
    /// Components excluded from `score`/`max_points` because nothing could
    /// measure them. Empty at full scale.
    pub unmeasured: &'static [&'static str],
}

impl ReadinessOutcome {
    /// False when this number is on a shrunken denominator, so a caller cannot
    /// rank it against a full-scale score, count it under a fleet-wide
    /// threshold, or average it in.
    #[must_use]
    pub const fn comparable_to_fleet(&self) -> bool {
        self.max_points == FULL_MAX
    }

    /// One sentence for the operator, or `None` at full scale.
    #[must_use]
    pub fn note(&self) -> Option<String> {
        match &self.basis {
            ReadinessBasis::FullScale => None,
            ReadinessBasis::ParentDispatched { parents, ledger } => {
                let ledger_clause = match ledger {
                    None => {
                        " The child-run ledger was NOT consulted on this path, so nothing here \
                              says how often it actually runs."
                            .to_string()
                    }
                    Some(ev) => format!(
                        " {} That is below the {}-run floor at which the ledger can score \
                         reliability and freshness, so this score stays on the measurable \
                         components — it is NOT scaled up to 100.",
                        ev.disclosure(),
                        LEDGER_MIN_RUNS
                    ),
                };
                Some(format!(
                    "Scored {}/{} on the MEASURABLE components only (documentation, risk). \
                     Dispatched by: {}. {}{}",
                    self.score,
                    self.max_points,
                    parents.join(", "),
                    CHILD_UNMEASURED_REASON,
                    ledger_clause
                ))
            }
            ReadinessBasis::LedgerMeasured { parents, ledger } => Some(format!(
                "Scored {}/{} on the FULL scale. Dispatched by: {}. Reliability and freshness \
                 come from the child-run ledger (sub_workflow_runs), not from \
                 workflow_executions — a sub-workflow runs in-process and records no row there. \
                 {} This score IS comparable to a top-level workflow's.",
                self.score,
                self.max_points,
                parents.join(", "),
                ledger.disclosure()
            )),
        }
    }
}

/// THE readiness score. One implementation, three scorers.
///
/// The three callers — `get_readiness_breakdown`, `validate_workflow`, and the
/// hourly recompute in `controller/src/bootstrap/background.rs` — already
/// disagree about the reliability INPUT (the breakdown excludes acknowledged
/// failures; the background loop counts them), and #758 chose to DISCLOSE that
/// rather than unify it. That decision stands: what is unified here is the
/// BASIS — whether the number is on a 100-point scale at all — because three
/// answers to *that* is three different denominators rendered under one field
/// name.
#[must_use]
pub fn score_readiness(c: ReadinessComponents, basis: ReadinessBasis) -> ReadinessOutcome {
    match basis {
        // Two bases, ONE arm: a ledger-measured child is scored exactly like a
        // top-level workflow, because by then all four components have been
        // measured. Splitting these would be the first place the two scales
        // could drift apart.
        ReadinessBasis::FullScale | ReadinessBasis::LedgerMeasured { .. } => ReadinessOutcome {
            score: (c.reliability + c.documentation + c.freshness + c.risk).round() as i32,
            max_points: FULL_MAX,
            basis,
            unmeasured: &[],
        },
        ReadinessBasis::ParentDispatched { .. } => ReadinessOutcome {
            score: (c.documentation + c.risk).round() as i32,
            max_points: CHILD_MEASURABLE_MAX,
            basis,
            unmeasured: EXECUTION_DERIVED_COMPONENTS,
        },
    }
}

/// Is a page-scoped child exclusion COMPLETE over the population it summarises?
///
/// `get_all_readiness_scores` returns `ORDER BY COALESCE(readiness_score, 0)
/// ASC LIMIT 50` — the LOWEST scorers — beside a population-wide
/// `below_50_count`. The child scan behind the per-row annotations is scoped to
/// that page (an uncapped "read every enabled workflow's graph" is the
/// unbounded payload `talos_child_workflow_refs` documents as the thing it
/// refuses to do), so the question is whether a child can exist in the
/// population but off the page.
///
/// It cannot, WHEN the page's highest score exceeds [`CHILD_MEASURABLE_MAX`]:
/// a freshly-scored child is at most 30 points, the page is the ascending
/// prefix of the population, so a page reaching past 30 has already swallowed
/// every row at or below 30 and therefore every child. When the page's top
/// score is ≤ 30 the page may have been truncated among rows a child could be
/// hiding in, and the caller must say the exclusion is PARTIAL.
///
/// **RFC 0012 P2 narrows what this predicate speaks about, and the narrowing
/// is deliberate.** Only an UNMEASURABLE child (`ParentDispatched`) is excluded
/// from `below_50_count`; a LEDGER-MEASURED child is on the fleet scale and is
/// counted like any other workflow. So the population this completeness
/// argument covers is exactly the ≤30 rows, which is the population the
/// argument was always about — a ledger-measured child scoring 47 is a real
/// below-50 finding and must not be silently excluded.
///
/// The residual gap, stated rather than implied: a child whose STORED score is
/// stale from before this change (>30, computed on the old full scale) sorts
/// above the page and is invisible to the scan. It self-corrects on the next
/// hourly recompute, and it is the quiet direction — such a row is counted in
/// `below_50_count` only if it is also below 50.
#[must_use]
pub fn child_exclusion_is_complete(page_scores: &[i32], page_len: usize, page_limit: i64) -> bool {
    // A page shorter than the limit IS the whole population — nothing was cut.
    if (page_len as i64) < page_limit {
        return true;
    }
    page_scores.iter().copied().max().unwrap_or(0) > CHILD_MEASURABLE_MAX
}

#[cfg(test)]
mod tests {
    use super::*;
    use talos_child_workflow_refs::ParentGraphRow;

    const CHILD: &str = "11111111-1111-4111-8111-111111111111";
    const OTHER: &str = "22222222-2222-4222-8222-222222222222";

    fn sub_graph(child: &str) -> String {
        format!(
            r#"{{"nodes":[{{"id":"n","type":"system:sub_workflow","data":{{"sub_workflow_id":"{child}"}}}}],"edges":[]}}"#
        )
    }

    fn parent(name: &str, graph: Option<&str>) -> ParentGraphRow {
        ParentGraphRow {
            id: Uuid::new_v4(),
            name: name.to_string(),
            graph_json: graph.map(ToString::to_string),
        }
    }

    /// A well-documented, low-risk workflow with ZERO execution evidence.
    fn documented_but_unrun() -> ReadinessComponents {
        ReadinessComponents {
            reliability: 0.0,
            documentation: 20.0,
            freshness: 0.0,
            risk: 10.0,
        }
    }

    #[test]
    fn child_max_matches_the_component_maxima() {
        assert_eq!(CHILD_MEASURABLE_MAX, 30);
        assert_eq!(FULL_MAX, 100);
        assert_eq!(
            FULL_MAX - CHILD_MEASURABLE_MAX,
            RELIABILITY_MAX + FRESHNESS_MAX,
            "the excluded points are exactly the execution-derived components"
        );
    }

    /// F1, as a pure unit: the live shape of all four fleet children.
    #[test]
    fn a_child_is_scored_on_the_measurable_components_only() {
        let child: Uuid = CHILD.parse().unwrap();
        let scan = ChildReferenceScan::build(
            &[parent("pa-chief-of-staff", Some(&sub_graph(CHILD)))],
            &[child],
        );
        let basis = ReadinessBasis::from_scan_with_ledger(&scan, child, None);
        assert!(basis.is_parent_dispatched());

        let out = score_readiness(documented_but_unrun(), basis);
        assert_eq!(out.score, 30, "documentation 20 + risk 10");
        assert_eq!(out.max_points, 30, "the denominator shrinks, it is not 100");
        assert!(!out.comparable_to_fleet());
        assert_eq!(out.unmeasured, ["reliability", "freshness"]);
        assert!(out.note().unwrap().contains("pa-chief-of-staff"));
    }

    /// The renormalisation that was REJECTED. A child scoring full marks on
    /// everything measurable must NOT read as 100 — that is the fabrication
    /// this basis exists to refuse, and it is worse than the zero it replaces.
    #[test]
    fn a_perfect_child_does_not_report_a_perfect_full_scale_score() {
        let child: Uuid = CHILD.parse().unwrap();
        let scan = ChildReferenceScan::build(&[parent("p", Some(&sub_graph(CHILD)))], &[child]);
        let out = score_readiness(
            documented_but_unrun(),
            ReadinessBasis::from_scan_with_ledger(&scan, child, None),
        );
        assert_ne!(out.score, 100);
        assert_ne!(out.max_points, FULL_MAX);
    }

    /// The positive control the assertion above cannot supply on its own: a
    /// TOP-LEVEL workflow with zero runs is still scored 0 reliability out of
    /// 100, because for it the silence in `workflow_executions` really does
    /// mean it never ran.
    #[test]
    fn a_top_level_workflow_with_no_runs_is_still_scored_zero_reliability() {
        let orphan: Uuid = OTHER.parse().unwrap();
        let scan = ChildReferenceScan::build(&[parent("p", Some(&sub_graph(CHILD)))], &[orphan]);
        let basis = ReadinessBasis::from_scan_with_ledger(&scan, orphan, None);
        assert_eq!(basis, ReadinessBasis::FullScale);

        let out = score_readiness(documented_but_unrun(), basis);
        assert_eq!(out.score, 30, "30 of 100 — genuinely unready");
        assert_eq!(out.max_points, FULL_MAX);
        assert!(out.comparable_to_fleet());
        assert!(out.unmeasured.is_empty());
        assert_eq!(out.note(), None);
    }

    /// UNKNOWN renders as FULL SCALE, deliberately — `parents_of` is the
    /// REPORT accessor. The incompleteness is the caller's to surface, from
    /// `unreadable_parents`, and this test pins the pairing so a future
    /// "helpful" switch to `protection_for` is a visible change.
    #[test]
    fn an_unreadable_parent_does_not_make_a_workflow_a_child() {
        let child: Uuid = CHILD.parse().unwrap();
        let broken = format!(r#"{{"nodes": [ "{CHILD}" "#);
        let scan = ChildReferenceScan::build(&[parent("half-written", Some(&broken))], &[child]);

        assert_eq!(
            ReadinessBasis::from_scan_with_ledger(&scan, child, None),
            ReadinessBasis::FullScale
        );
        assert_eq!(
            scan.unreadable_parents(),
            ["half-written".to_string()],
            "…and the caller has the name it must render beside the score"
        );
    }

    // ── RFC 0012 P2: the ledger ────────────────────────────────────────────
    //
    // Every test below pins NEW behaviour — `LedgerMeasured` does not exist on
    // pristine `origin/main`, so there is no main-vocabulary twin to fail
    // against and the burden is carried by MUTATION. Each names its mutation;
    // the results are in AGENT_NOTES.md.

    fn at(mins_ago: i64) -> DateTime<Utc> {
        Utc::now() - chrono::Duration::minutes(mins_ago)
    }

    fn evidence(runs: i64, failed: i64) -> ChildLedgerEvidence {
        ChildLedgerEvidence {
            runs,
            failed,
            last_started_at: Some(at(30)),
            ledger_since: Some(at(60 * 24)),
            window_start: at(60 * 24 * 30),
        }
    }

    /// The FLOOR. One recorded run must not put a child on the fleet scale —
    /// if it had failed, the row would then report `0/50` reliability as a
    /// fleet-comparable fact from ONE observation.
    ///
    /// MUTATION that turns it red: `LEDGER_MIN_RUNS = 0` (or 1).
    #[test]
    fn below_the_floor_a_child_stays_on_the_shrunken_denominator() {
        let child: Uuid = CHILD.parse().unwrap();
        let scan = ChildReferenceScan::build(&[parent("p", Some(&sub_graph(CHILD)))], &[child]);
        for runs in 0..LEDGER_MIN_RUNS {
            let basis =
                ReadinessBasis::from_scan_with_ledger(&scan, child, Some(evidence(runs, 0)));
            let out = score_readiness(documented_but_unrun(), basis);
            assert_eq!(out.max_points, CHILD_MEASURABLE_MAX, "{runs} run(s)");
            assert!(!out.comparable_to_fleet(), "{runs} run(s)");
            assert_eq!(out.score, 30, "never scaled up to 100");
            // …and the shortfall is STATED, with the floor and the ledger's
            // start, so the reader can tell it from "the ledger is not wired".
            let note = out.note().unwrap();
            assert!(
                note.contains(&format!("{runs} child run(s) recorded since")),
                "{note}"
            );
            assert!(
                note.contains(&format!("below the {LEDGER_MIN_RUNS}-run floor")),
                "{note}"
            );
        }
    }

    /// At the floor the child returns to the FULL scale — and the two
    /// execution components are real measurements, not inferences from the
    /// other two.
    ///
    /// MUTATION that turns it red: score `LedgerMeasured` on
    /// `CHILD_MEASURABLE_MAX`, or drop the `LedgerMeasured` arm from
    /// `from_scan_with_ledger`.
    #[test]
    fn at_the_floor_the_ledger_puts_the_child_back_on_the_fleet_scale() {
        let child: Uuid = CHILD.parse().unwrap();
        let scan = ChildReferenceScan::build(&[parent("p", Some(&sub_graph(CHILD)))], &[child]);
        let ev = evidence(LEDGER_MIN_RUNS, 0);
        let basis = ReadinessBasis::from_scan_with_ledger(&scan, child, Some(ev));
        assert!(basis.is_parent_dispatched(), "it is still somebody's child");
        assert!(
            !basis.is_unmeasurable_child(),
            "…but no longer unmeasurable"
        );
        assert_eq!(basis.as_str(), "ledger");

        let (reliability, freshness) = ev.components(Utc::now());
        let out = score_readiness(
            ReadinessComponents {
                reliability,
                documentation: 20.0,
                freshness,
                risk: 10.0,
            },
            basis,
        );
        assert_eq!(out.max_points, FULL_MAX);
        assert!(out.comparable_to_fleet());
        assert!(out.unmeasured.is_empty());
        // 3 perfect runs: the ramp gives 3/10 of 50 = 15; freshness 20.
        assert_eq!(
            out.score, 65,
            "20 doc + 10 risk + 15 reliability + 20 freshness"
        );
    }

    /// Reliability comes from the LEDGER's own failures, through the SAME
    /// shared ramp the full scale uses.
    ///
    /// MUTATION that turns it red: compute `success_rate` as `1.0`, or read
    /// reliability from anywhere but `ChildLedgerEvidence`.
    #[test]
    fn failed_ledger_runs_lower_reliability() {
        let clean = evidence(10, 0).components(Utc::now()).0;
        let half = evidence(10, 5).components(Utc::now()).0;
        let dead = evidence(10, 10).components(Utc::now()).0;
        assert!(
            (clean - 50.0).abs() < f64::EPSILON,
            "10 clean runs saturate the ramp"
        );
        assert!((half - 25.0).abs() < f64::EPSILON);
        assert!((dead - 0.0).abs() < f64::EPSILON);
        assert!(clean > half && half > dead);
    }

    /// A rate over ZERO runs has no value. `0.0` there would render "nothing
    /// recorded" as "everything failed" — the determinate negative again.
    #[test]
    fn a_success_rate_over_no_runs_is_none() {
        assert_eq!(ChildLedgerEvidence::unrecorded(at(60)).success_rate(), None);
        assert_eq!(evidence(0, 0).success_rate(), None);
        assert_eq!(evidence(4, 1).success_rate(), Some(0.75));
    }

    /// UNKNOWN is not zero. An EMPTY ledger and a ledger whose floor is inside
    /// the window are two different statements, and neither is "0 runs".
    ///
    /// MUTATION that turns it red: drop the coverage clause from
    /// `ChildLedgerEvidence::disclosure`.
    #[test]
    fn a_window_the_ledger_does_not_cover_is_disclosed_as_unknown() {
        let empty = ChildLedgerEvidence::unrecorded(at(60 * 24 * 30));
        assert!(empty.disclosure().contains("no rows at all"));
        assert!(empty.disclosure().contains("UNKNOWN"));

        // The live shape at the time of writing: the ledger's floor is ~11 h
        // old against a 30-day window, so 29 of the 30 days are UNKNOWN.
        let partial = ChildLedgerEvidence {
            runs: 2,
            failed: 0,
            last_started_at: Some(at(30)),
            ledger_since: Some(at(11 * 60)),
            window_start: at(60 * 24 * 30),
        };
        let d = partial.disclosure();
        assert!(d.contains("UNKNOWN"), "{d}");
        assert!(d.contains("nobody was recording"), "{d}");

        // A floor OLDER than the window covers it fully and says nothing extra.
        let full = ChildLedgerEvidence {
            ledger_since: Some(at(60 * 24 * 60)),
            ..partial
        };
        assert!(
            !full.disclosure().contains("UNKNOWN"),
            "{}",
            full.disclosure()
        );
    }

    /// A ledger that was NOT CONSULTED is a third state, distinct from an
    /// empty one. Collapsing them would make "we did not look" read as "it
    /// never ran".
    #[test]
    fn an_unconsulted_ledger_says_so_rather_than_reporting_zero() {
        let child: Uuid = CHILD.parse().unwrap();
        let scan = ChildReferenceScan::build(&[parent("p", Some(&sub_graph(CHILD)))], &[child]);
        let out = score_readiness(
            documented_but_unrun(),
            ReadinessBasis::from_scan_with_ledger(&scan, child, None),
        );
        let note = out.note().unwrap();
        assert!(note.contains("NOT consulted"), "{note}");
        assert!(!note.contains("0 child run(s)"), "{note}");
    }

    /// The `below_50` exclusion predicate must follow the BASIS. A
    /// ledger-measured child is on the fleet scale, so excluding it would hide
    /// the platform's most-used sub-workflows from the one count that would
    /// notice them degrading.
    ///
    /// MUTATION that turns it red: make `is_unmeasurable_child` an alias of
    /// `is_parent_dispatched`.
    #[test]
    fn the_below_50_exclusion_follows_the_basis_not_the_child_ness() {
        let child: Uuid = CHILD.parse().unwrap();
        let scan = ChildReferenceScan::build(&[parent("p", Some(&sub_graph(CHILD)))], &[child]);

        let unmeasurable =
            ReadinessBasis::from_scan_with_ledger(&scan, child, Some(evidence(1, 0)));
        let measured = ReadinessBasis::from_scan_with_ledger(&scan, child, Some(evidence(9, 9)));

        assert!(
            unmeasurable.is_unmeasurable_child(),
            "excluded from below_50"
        );
        assert!(
            !measured.is_unmeasurable_child(),
            "a ledger-measured child that fails every run IS a real below-50 finding"
        );
        assert_eq!(unmeasurable.max_points(), CHILD_MEASURABLE_MAX);
        assert_eq!(measured.max_points(), FULL_MAX);
    }

    /// A workflow NOTHING dispatches into is untouched by any of this — the
    /// positive control, and the reason `from_scan` can delegate here.
    #[test]
    fn ledger_evidence_never_promotes_a_non_child() {
        let orphan: Uuid = OTHER.parse().unwrap();
        let scan = ChildReferenceScan::build(&[parent("p", Some(&sub_graph(CHILD)))], &[orphan]);
        assert_eq!(
            ReadinessBasis::from_scan_with_ledger(&scan, orphan, Some(evidence(500, 0))),
            ReadinessBasis::FullScale
        );
    }

    #[test]
    fn a_short_page_is_the_whole_population() {
        assert!(child_exclusion_is_complete(&[10, 20], 2, 50));
        assert!(
            child_exclusion_is_complete(&[], 0, 50),
            "an empty page excludes nothing and hides nothing"
        );
    }

    #[test]
    fn a_full_page_reaching_past_the_child_ceiling_is_complete() {
        let mut scores: Vec<i32> = (0..49).collect();
        scores.push(31);
        assert!(child_exclusion_is_complete(&scores, 50, 50));
    }

    #[test]
    fn a_full_page_capped_below_the_child_ceiling_is_partial() {
        let scores = vec![30; 50];
        assert!(
            !child_exclusion_is_complete(&scores, 50, 50),
            "a child could sit at 30 just off the end of this page"
        );
    }
}
