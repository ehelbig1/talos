//! Postgres adapter for [`talos_workflow_engine_core::ChildRunRecorder`] —
//! the write port behind the child-run ledger (RFC 0012 P1).
//!
//! Thin, BEST-EFFORT adapter over [`talos_child_run_ledger::ChildRunLedger`]
//! (all SQL stays in the leaf crate). Modelled on
//! [`PostgresJudgeScoreRecorder`](crate::judge_score_recorder::PostgresJudgeScoreRecorder),
//! with one deliberate difference: the engine AWAITS this call rather than
//! spawning it, because a spawned write is the orphaning shape
//! `docs/platform-primitive-checklist.md` warns about and one INSERT after a
//! run that took seconds is not worth that risk.
//!
//! A failure is logged and dropped — it MUST NEVER fail the child, the parent
//! node, or the workflow; a ledger that can fail a run is a routing
//! dependency, not a ledger. **But a dropped write is not free**: a
//! sub-workflow leaves no `workflow_executions` row, so this table is the only
//! evidence a child ran, and silence here is indistinguishable from "this
//! child never ran" — which is the exact reading the ledger exists to remove.
//! That is what `talos_child_run_record_failures_total` is for, and why both
//! of its label values are stamped here and pre-seeded at zero.

use async_trait::async_trait;
use sqlx::PgPool;
use talos_child_run_ledger::ChildRunLedger;
use talos_workflow_engine_core::ChildRunRecord;

/// Records child runs into `sub_workflow_runs`.
pub struct PostgresChildRunRecorder {
    ledger: ChildRunLedger,
}

impl PostgresChildRunRecorder {
    /// Bind a recorder to a pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            ledger: ChildRunLedger::new(pool),
        }
    }
}

/// The `event_kind` every child-run record failure carries. One token, so an
/// operator greps for one thing.
pub const CHILD_RUN_RECORD_FAILED: &str = "child_run_record_failed";

#[async_trait]
impl talos_workflow_engine_core::ChildRunRecorder for PostgresChildRunRecorder {
    async fn record(&self, record: ChildRunRecord) {
        let parent_execution_id = record.parent_execution_id;
        let child_workflow_id = record.child_workflow_id;
        let dispatch_kind = record.dispatch_kind.as_str();
        if let Err(e) = self.ledger.record(record).await {
            tracing::warn!(
                target: "talos_audit",
                event_kind = CHILD_RUN_RECORD_FAILED,
                %parent_execution_id,
                %child_workflow_id,
                dispatch_kind,
                error = %e,
                "child-run ledger write failed; the run happened and nothing records it"
            );
            if let Some(m) = talos_metrics::global() {
                // `insert` covers every failure the ledger surfaces: the pool
                // acquire is inside sqlx's `execute` here, so this adapter has
                // one arm. `acquire` is stamped by the pre-flight check below,
                // which exists so the two are distinguishable rather than
                // folded — a saturated pool and a broken statement are
                // different operator problems.
                m.child_run_record_failures_total
                    .with_label_values(&[if is_pool_exhaustion(&e) {
                        "acquire"
                    } else {
                        "insert"
                    }])
                    .inc();
            }
        }
    }
}

/// Is this failure "no connection was available" rather than "the statement
/// failed"? A saturated pool and a broken INSERT are different operator
/// problems and must not fold into one label.
///
/// Pure, so it is unit-testable without a database — sqlx's `PoolTimedOut` is
/// the only variant that means the statement never ran.
#[must_use]
pub fn is_pool_exhaustion(e: &anyhow::Error) -> bool {
    matches!(
        e.downcast_ref::<sqlx::Error>(),
        Some(sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pool_timeout_is_an_acquire_failure_and_a_broken_statement_is_not() {
        let timed_out: anyhow::Error = anyhow::Error::new(sqlx::Error::PoolTimedOut);
        assert!(is_pool_exhaustion(&timed_out));
        let row_not_found: anyhow::Error = anyhow::Error::new(sqlx::Error::RowNotFound);
        assert!(!is_pool_exhaustion(&row_not_found));
        // A plain anyhow error (the `.context(...)` wrapper the ledger adds)
        // must still classify by its SOURCE, not by being un-downcastable at
        // the top level.
        let wrapped = anyhow::Error::new(sqlx::Error::PoolClosed).context("record_child_run");
        assert!(
            is_pool_exhaustion(&wrapped),
            "a contextualised pool failure must still read as an acquire failure"
        );
    }
}
