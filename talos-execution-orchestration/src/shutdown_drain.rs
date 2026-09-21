//! What a controller does with the runs it is driving when it is told to
//! stop: wait for them, then fail — at once and with the real reason — the
//! ones that did not finish.
//!
//! Until 2026-09-21 a `SIGTERM` simply ended the process. Each run in flight
//! died with the runtime and its row stayed `running` for about an hour, until
//! the stale sweep closed it. See `talos_shutdown::inflight` for why the set
//! of runs is this process's own registry and never a table query.

use std::time::Duration;

use sqlx::PgPool;
use talos_shutdown::inflight::InFlightRuns;

/// Stored as the run's `error_message`. States the cause and that the
/// workflow's own budget did not fire, so nobody tunes a timeout over it.
pub const INTERRUPTED_BY_SHUTDOWN: &str =
    "Interrupted: the controller driving this run shut down before it finished, and the run \
     did not complete within the shutdown grace period. The workflow's own execution budget \
     did not expire. Re-run it if its work is still wanted.";

/// What happened to the runs in flight at shutdown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShutdownDrainReport {
    /// Runs in flight when the drain began.
    pub in_flight_at_start: usize,
    /// Runs still in flight when the grace period ended.
    pub outlasted_grace: usize,
    /// Of those, the rows this call failed. `None`: the write did not answer,
    /// so the rows stay `running` and the stale sweep remains their backstop.
    pub failed_now: Option<u64>,
    /// How long the drain waited.
    pub waited: Duration,
}

/// Wait up to `grace` for `runs` to empty, then fail what is left.
///
/// Never returns an error: this runs on the way out of the process, and a
/// database that cannot be reached must not turn a shutdown into a hang or a
/// panic. The failure is logged and disclosed in the report.
pub async fn drain_in_flight_runs(
    pool: &PgPool,
    runs: &InFlightRuns,
    grace: Duration,
) -> ShutdownDrainReport {
    let outcome = runs.drain(grace).await;
    let mut report = ShutdownDrainReport {
        in_flight_at_start: outcome.at_start,
        outlasted_grace: outcome.remaining.len(),
        failed_now: Some(0),
        waited: outcome.waited,
    };
    if outcome.remaining.is_empty() {
        if outcome.at_start > 0 {
            tracing::info!(
                target: "talos_controller",
                event_kind = "shutdown_drain_clean",
                in_flight_at_start = outcome.at_start,
                waited_ms = u64::try_from(outcome.waited.as_millis()).unwrap_or(u64::MAX),
                "Every workflow run this controller was driving finished before shutdown"
            );
        }
        return report;
    }

    match talos_workflow_repository::fail_runs_interrupted_by_shutdown(
        pool,
        &outcome.remaining,
        INTERRUPTED_BY_SHUTDOWN,
    )
    .await
    {
        Ok(failed) => {
            report.failed_now = Some(failed);
            // Their module rows need no statement here: the
            // `cancel_siblings_on_workflow_fail` trigger cancels a failed run's
            // `running` module rows in the same transaction.
            tracing::warn!(
                target: "talos_controller",
                event_kind = "shutdown_drain_interrupted_runs",
                outlasted_grace = outcome.remaining.len(),
                failed_now = failed,
                grace_secs = grace.as_secs(),
                "Workflow runs were still in flight when the shutdown grace period ended; \
                 they have been failed now rather than left for the stale sweep"
            );
        }
        Err(e) => {
            report.failed_now = None;
            tracing::error!(
                target: "talos_controller",
                event_kind = "shutdown_drain_fail_write_failed",
                outlasted_grace = outcome.remaining.len(),
                error = %e,
                "Could not fail the runs interrupted by shutdown; they stay 'running' until \
                 the stale sweep closes them"
            );
        }
    }
    report
}
