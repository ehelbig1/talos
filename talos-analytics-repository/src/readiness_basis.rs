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
    /// child-dispatch keys. Scored out of [`CHILD_MEASURABLE_MAX`].
    ParentDispatched {
        /// Parent names, as [`ChildReferenceScan::parents_of`] returned them:
        /// sorted, deduplicated, and only parents whose graph actually parsed.
        parents: Vec<String>,
    },
}

impl ReadinessBasis {
    /// The REPORT answer for one workflow, from one scan.
    ///
    /// Deliberately `parents_of` and not `protection_for`: see the module
    /// header. A caller MUST also render `scan.unreadable_parents()`.
    #[must_use]
    pub fn from_scan(scan: &ChildReferenceScan, workflow_id: Uuid) -> Self {
        let parents = scan.parents_of(workflow_id);
        if parents.is_empty() {
            Self::FullScale
        } else {
            Self::ParentDispatched {
                parents: parents.to_vec(),
            }
        }
    }

    /// Stable wire token, rendered as `score_basis`.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::FullScale => "full_scale",
            Self::ParentDispatched { .. } => "measurable_components_only",
        }
    }

    /// The parents behind a `ParentDispatched` basis, empty otherwise.
    #[must_use]
    pub fn parents(&self) -> &[String] {
        match self {
            Self::FullScale => &[],
            Self::ParentDispatched { parents } => parents,
        }
    }

    #[must_use]
    pub const fn is_parent_dispatched(&self) -> bool {
        matches!(self, Self::ParentDispatched { .. })
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
            ReadinessBasis::ParentDispatched { parents } => Some(format!(
                "Scored {}/{} on the MEASURABLE components only (documentation, risk). \
                 Dispatched by: {}. {}",
                self.score,
                self.max_points,
                parents.join(", "),
                CHILD_UNMEASURED_REASON
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
        ReadinessBasis::FullScale => ReadinessOutcome {
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
        let basis = ReadinessBasis::from_scan(&scan, child);
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
            ReadinessBasis::from_scan(&scan, child),
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
        let basis = ReadinessBasis::from_scan(&scan, orphan);
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
            ReadinessBasis::from_scan(&scan, child),
            ReadinessBasis::FullScale
        );
        assert_eq!(
            scan.unreadable_parents(),
            ["half-written".to_string()],
            "…and the caller has the name it must render beside the score"
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
