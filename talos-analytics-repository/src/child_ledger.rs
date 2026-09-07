//! Reading the child-run ledger for the readiness scorers — RFC 0012 P2.
//!
//! `ReadinessBasis` is a pure decision and must stay one, so the type it
//! decides over ([`ChildLedgerEvidence`]) is a plain struct in
//! [`crate::readiness_basis`] and THIS module is the one place that fills it
//! from `sub_workflow_runs`.
//!
//! # Why one function and not four
//!
//! Four surfaces ask this question — the hourly recompute, the on-demand
//! breakdown, `validate_workflow`, and the readiness list — and #762 already
//! recorded what happens when a shared decision grows a second implementation.
//! What is shared here is the READ, including the two things easiest to get
//! wrong independently:
//!
//! * the window is `max(caller window, ledger floor)` in EFFECT, because rows
//!   before [`ChildRunLedger::since`] do not exist and a count over them is
//!   UNKNOWN rather than zero — the floor travels on every evidence value so
//!   the renderer can say which;
//! * a child with NO rows is ABSENT from the batched map, and this module is
//!   what turns that absence into an explicit zero-with-a-floor rather than
//!   letting each caller invent one.
//!
//! # UNKNOWN has two shapes and they are not merged
//!
//! `Ok(map)` with a missing key means *the ledger was read and holds nothing
//! for this child*; `Err` means *the ledger could not be read*. The callers
//! render the second as `ledger: None` on the basis — "not consulted" — which
//! is deliberately NOT the same sentence as "no rows".

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use talos_child_run_ledger::ChildRunLedger;
use uuid::Uuid;

use crate::readiness_basis::ChildLedgerEvidence;

/// The readiness window every scorer uses, in days. The three reliability
/// queries all say `interval '30 days'`; the ledger read must agree or a
/// child's evidence would cover a different period from its siblings'.
pub const READINESS_WINDOW_DAYS: i64 = 30;

/// The start of the readiness window relative to `now`.
#[must_use]
pub fn readiness_window_start(now: DateTime<Utc>) -> DateTime<Utc> {
    now - chrono::Duration::days(READINESS_WINDOW_DAYS)
}

/// Ledger evidence for a batch of children, as ONE grouped query plus the
/// process-cached floor.
///
/// `child_workflow_ids` is the candidate list — the page, or the hourly
/// batch's ids for one user — never the whole fleet, and never one call per
/// row. Every id asked about appears in the returned map: a child with no
/// recorded runs gets `runs: 0` WITH the floor attached, which is what lets
/// the renderer say "the ledger has been recording since D and saw none"
/// rather than a bare zero.
///
/// # Errors
/// Any database failure, from either the floor read or the batched count.
pub async fn child_ledger_evidence(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    child_workflow_ids: &[Uuid],
    now: DateTime<Utc>,
) -> anyhow::Result<HashMap<Uuid, ChildLedgerEvidence>> {
    child_ledger_evidence_since(
        pool,
        user_id,
        child_workflow_ids,
        readiness_window_start(now),
    )
    .await
}

/// The same read over an ARBITRARY window start.
///
/// [`child_ledger_evidence`] is the readiness projection of this function, and
/// this is the one place the floor arithmetic lives. RFC 0012 P3 needed it
/// because the cascading-failure check in `get_workflow_risk_assessment` asks
/// the same question over ITS window — seven days, not thirty — and a second
/// implementation of "read the floor, clamp the window to it, turn an absent
/// key into a zero-WITH-a-floor" is exactly the drift #762 and check 85
/// record. The WINDOW moves; the arithmetic does not.
///
/// # Errors
/// Any database failure, from either the floor read or the batched count.
pub async fn child_ledger_evidence_since(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    child_workflow_ids: &[Uuid],
    window_start: DateTime<Utc>,
) -> anyhow::Result<HashMap<Uuid, ChildLedgerEvidence>> {
    if child_workflow_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let ledger = ChildRunLedger::new(pool.clone());
    // The FLOOR first, and it is not user-scoped by design (see
    // `ChildRunLedger::since`). A failure here fails the whole read rather
    // than being defaulted: a count without a floor is the bare zero this
    // whole phase exists to refuse.
    let ledger_since = ledger.since().await?;
    // Rows before the floor cannot exist, so the query window is the later of
    // the two — which also keeps the scan off the index's cold tail.
    let query_from = match ledger_since {
        Some(since) if since > window_start => since,
        _ => window_start,
    };
    let stats = ledger
        .child_run_stats_since(child_workflow_ids, user_id, query_from)
        .await?;

    let mut out = HashMap::with_capacity(child_workflow_ids.len());
    for id in child_workflow_ids {
        let s = stats.get(id);
        out.insert(
            *id,
            ChildLedgerEvidence {
                runs: s.map_or(0, |s| s.runs),
                failed: s.map_or(0, |s| s.failed),
                last_started_at: s.and_then(|s| s.last_started_at),
                ledger_since,
                window_start,
            },
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The window must be the SAME 30 days the three reliability queries use.
    /// A ledger read over a different period would score a child's reliability
    /// against a window no sibling shares.
    #[test]
    fn the_ledger_window_matches_the_execution_window() {
        let src = include_str!("lib.rs");
        assert!(
            src.contains("started_at > NOW() - interval '30 days'"),
            "the reliability queries no longer use a 30-day window"
        );
        assert_eq!(READINESS_WINDOW_DAYS, 30);
    }
}
