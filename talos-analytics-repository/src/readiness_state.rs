//! "Has this workflow been scored?" — ONE decision, over BOTH timestamps.
//!
//! `workflows` carries two timestamp columns for what an operator reads as one
//! fact, and until 2026-09-05 every reader anchored on only one of them:
//!
//! | column | writer | statement |
//! |---|---|---|
//! | `readiness_scored_at` | the on-demand `get_readiness_breakdown` tool | [`crate::AnalyticsRepository::set_workflow_readiness_score`] |
//! | `readiness_computed_at` | the hourly background recompute in `controller/src/bootstrap/background.rs` | `UPDATE workflows SET readiness_score = $1, readiness_computed_at = NOW() …` |
//!
//! Both write `readiness_score`. Neither writes the other's timestamp. So on
//! the reference deployment, measured 2026-09-05: `readiness_computed_at` was
//! set on 36 of 36 workflows (max 15:34 that same day) while
//! `readiness_scored_at` was set on **1** — and `get_all_readiness_scores`
//! answered `unscored_count: 27` of 28 and `score_state: "unscored"` per row,
//! *beside a `readiness_score` of 87*, telling the operator to run a tool to
//! compute a score that already existed and was an hour old. The flagship
//! `pa-chief-of-staff` reported `score_age_hours: 986` against a score
//! recomputed that afternoon.
//!
//! The previous fix in this area (MCP-1211) collapsed a two-STATEMENT write
//! into one atomic UPDATE so the score and its timestamp could not diverge —
//! correct, and it left the reader's predicate intact because it never saw the
//! **second writer**. A determinate "unscored" is the misleading-report class:
//! a negative asserted for a state the reader cannot represent.
//!
//! # Why the columns are NOT collapsed
//!
//! It is tempting to make both writers stamp both columns, or to migrate
//! `readiness_scored_at = COALESCE(readiness_scored_at, readiness_computed_at)`
//! and drop one. Measured against the two writers, that would be lossy: the
//! two scorers are **not the same function**. The arithmetic is shared —
//! `compute_reliability_score` is literally the background loop's inline
//! expression — but the reliability INPUT differs:
//!
//! * the background scorer counts every execution in the 30-day window;
//! * [`crate::AnalyticsRepository::get_readiness_exec_data`] adds
//!   `AND NOT (status = 'failed' AND acknowledged_at IS NOT NULL)`, excluding
//!   failures an operator has already acknowledged.
//!
//! So the two agree except on a workflow with an acknowledged failure in the
//! window, where the background number is the LOWER one. A single timestamp
//! cannot say which scorer produced the number sitting in `readiness_score`,
//! and reporting the wrong provenance is the same defect one level down. The
//! columns stay; the READER is taught to read both and to name the scorer.

use chrono::{DateTime, Utc};

/// Which writer last stamped `readiness_score`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessScorer {
    /// `get_readiness_breakdown` — the full component breakdown. Excludes
    /// acknowledged failures from the reliability component.
    Breakdown,
    /// The hourly background recompute. Counts acknowledged failures.
    BackgroundRecompute,
}

impl ReadinessScorer {
    /// Stable wire token. Rendered as `scored_by`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Breakdown => "get_readiness_breakdown",
            Self::BackgroundRecompute => "hourly_recompute",
        }
    }

    /// One sentence an operator can act on, naming what this scorer's number
    /// does and does not account for. Rendered as `note` beside `scored_by`.
    #[must_use]
    pub const fn note(self) -> &'static str {
        match self {
            Self::Breakdown => {
                "Scored by get_readiness_breakdown, which excludes acknowledged failures from \
                 the reliability component."
            }
            Self::BackgroundRecompute => {
                "Scored by the hourly background recompute. Unlike get_readiness_breakdown it \
                 counts acknowledged failures against reliability, so its number can be lower; \
                 call get_readiness_breakdown for the component breakdown."
            }
        }
    }
}

/// The classified answer for one workflow row.
///
/// `is_unscored` and `label` are kept on one struct — rather than each consumer
/// re-deriving its own — so the per-row `score_state` field and the summary's
/// `unscored_count` can never disagree again. That was MCP-1211's rule and it
/// still holds; what changed is the input set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadinessState {
    /// True only when NEITHER writer has ever stamped this row.
    pub is_unscored: bool,
    /// `"unscored"` | `"scored_zero"` | `"scored"`.
    pub label: &'static str,
    /// The EFFECTIVE timestamp: the more recent of the two columns. `None`
    /// only when `is_unscored`.
    pub scored_at: Option<DateTime<Utc>>,
    /// Which writer that timestamp came from. `None` only when `is_unscored`.
    pub scored_by: Option<ReadinessScorer>,
}

/// Classify a readiness row from the three columns the DB returns.
///
/// The rule: a row is unscored only when BOTH timestamps are NULL. Otherwise
/// the more recent timestamp wins and names its scorer — because that is the
/// writer whose arithmetic produced the `readiness_score` now on the row.
///
/// Ties (both columns bit-identical) resolve to [`ReadinessScorer::Breakdown`].
/// Nothing writes both in one statement, so a tie is a clock coincidence, and
/// preferring the breakdown keeps the pre-2026-09-05 answer for the only rows
/// that used to be classified as scored at all.
#[must_use]
pub fn classify_readiness_state(
    raw_score: Option<i32>,
    scored_at: Option<DateTime<Utc>>,
    computed_at: Option<DateTime<Utc>>,
) -> ReadinessState {
    let effective = match (scored_at, computed_at) {
        (None, None) => None,
        (Some(s), None) => Some((s, ReadinessScorer::Breakdown)),
        (None, Some(c)) => Some((c, ReadinessScorer::BackgroundRecompute)),
        (Some(s), Some(c)) => {
            if c > s {
                Some((c, ReadinessScorer::BackgroundRecompute))
            } else {
                Some((s, ReadinessScorer::Breakdown))
            }
        }
    };

    let is_unscored = effective.is_none();
    let score = raw_score.unwrap_or(0);
    let label = if is_unscored {
        "unscored"
    } else if score == 0 {
        // scored, genuinely zero — needs improvement
        "scored_zero"
    } else {
        "scored"
    };

    ReadinessState {
        is_unscored,
        label,
        scored_at: effective.map(|(t, _)| t),
        scored_by: effective.map(|(_, by)| by),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(y: i32, mo: u32, d: u32, h: u32) -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, y, mo, d, h, 0, 0).unwrap()
    }

    /// F1, as a pure unit: the live shape on 35 of 36 dev-fleet rows.
    #[test]
    fn a_background_recompute_is_not_unscored() {
        let s = classify_readiness_state(Some(87), None, Some(t(2026, 9, 5, 14)));
        assert!(!s.is_unscored, "a row the background scorer stamped today");
        assert_eq!(s.label, "scored");
        assert_eq!(s.scored_at, Some(t(2026, 9, 5, 14)));
        assert_eq!(s.scored_by, Some(ReadinessScorer::BackgroundRecompute));
    }

    /// The positive control the negative assertion above cannot supply on its
    /// own: a row nobody has scored is STILL unscored.
    #[test]
    fn a_never_scored_row_is_still_unscored() {
        let s = classify_readiness_state(None, None, None);
        assert!(s.is_unscored);
        assert_eq!(s.label, "unscored");
        assert_eq!(s.scored_at, None);
        assert_eq!(s.scored_by, None);
    }

    /// A non-null `readiness_score` with neither timestamp — the shape
    /// MCP-1211 identified (a score from an initial insert) — is still
    /// unscored. Widening the input set must not weaken this.
    #[test]
    fn a_score_without_either_timestamp_is_still_unscored() {
        let s = classify_readiness_state(Some(22), None, None);
        assert!(s.is_unscored);
        assert_eq!(s.label, "unscored");
    }

    #[test]
    fn a_breakdown_scored_row_names_the_breakdown() {
        let s = classify_readiness_state(Some(85), Some(t(2026, 7, 26, 12)), None);
        assert_eq!(s.scored_by, Some(ReadinessScorer::Breakdown));
        assert_eq!(s.label, "scored");
    }

    /// `pa-chief-of-staff`'s live shape: breakdown-scored in July, recomputed
    /// today. The reported age must come from TODAY, not from July — the
    /// column that made it report `score_age_hours: 986`.
    #[test]
    fn the_more_recent_of_the_two_wins() {
        let s =
            classify_readiness_state(Some(87), Some(t(2026, 7, 26, 12)), Some(t(2026, 9, 5, 14)));
        assert_eq!(s.scored_at, Some(t(2026, 9, 5, 14)));
        assert_eq!(s.scored_by, Some(ReadinessScorer::BackgroundRecompute));

        // …and the other direction, so this is not passing because the newer
        // column simply always wins by position.
        let s =
            classify_readiness_state(Some(87), Some(t(2026, 9, 5, 14)), Some(t(2026, 7, 26, 12)));
        assert_eq!(s.scored_at, Some(t(2026, 9, 5, 14)));
        assert_eq!(s.scored_by, Some(ReadinessScorer::Breakdown));
    }

    #[test]
    fn a_scored_zero_row_is_scored_not_unscored() {
        let s = classify_readiness_state(Some(0), None, Some(t(2026, 9, 5, 14)));
        assert!(!s.is_unscored);
        assert_eq!(s.label, "scored_zero");
    }

    /// Inverse drift: a timestamp written but the score not yet. Classified
    /// "scored_zero" so an operator can see the scoring pipeline at least ran.
    /// Carried over verbatim from the handler-side tests this replaced.
    #[test]
    fn a_timestamp_without_a_score_is_scored_zero_not_unscored() {
        for (s_at, c_at) in [
            (Some(t(2026, 5, 7, 0)), None),
            (None, Some(t(2026, 5, 7, 0))),
        ] {
            let s = classify_readiness_state(None, s_at, c_at);
            assert!(!s.is_unscored);
            assert_eq!(s.label, "scored_zero");
        }
    }

    /// A tie resolves to the breakdown. Stated because it is a choice, not a
    /// consequence.
    #[test]
    fn a_tie_names_the_breakdown() {
        let ts = t(2026, 9, 5, 14);
        let s = classify_readiness_state(Some(50), Some(ts), Some(ts));
        assert_eq!(s.scored_by, Some(ReadinessScorer::Breakdown));
    }

    /// The two consumers of this function — the per-row `score_state` label
    /// and the summary's `unscored_count` — must agree for every input.
    #[test]
    fn the_label_and_the_flag_never_disagree() {
        let stamps = [None, Some(t(2026, 9, 1, 0)), Some(t(2026, 9, 2, 0))];
        for score in [None, Some(0), Some(22), Some(100)] {
            for s_at in stamps {
                for c_at in stamps {
                    let st = classify_readiness_state(score, s_at, c_at);
                    assert_eq!(
                        st.is_unscored,
                        st.label == "unscored",
                        "score={score:?} scored_at={s_at:?} computed_at={c_at:?}"
                    );
                    assert_eq!(
                        st.is_unscored,
                        st.scored_at.is_none(),
                        "an unscored row has no effective timestamp and vice versa"
                    );
                    assert_eq!(st.scored_at.is_none(), st.scored_by.is_none());
                }
            }
        }
    }
}
