//! Split-brain fencing for crash-recovery resumes (F4, RFC 0003 durable
//! execution).
//!
//! The crash-recovery claim flips a stale `running` row to `resuming` under
//! `FOR UPDATE SKIP LOCKED`, so two *sweeps* can't double-claim it. That does
//! not stop a live-but-slow ORIGINAL controller (GC pause / network partition /
//! a node that runs longer than the stale window) from continuing to drive the
//! execution that a restarting controller then reclaims. Both would dispatch
//! the same nodes.
//!
//! Terminal-state corruption is already prevented — every terminal write guards
//! `WHERE status = 'running'` (or `'resuming'`), so a superseded controller's
//! finalize no-ops. What remains is the *continued dispatch* of new nodes by a
//! controller that no longer owns the execution (duplicate side effects). This
//! module reduces that window for **resumed** runs: a controller that resumes
//! via [`run_with_seed_fenced`] holds the `epoch` it claimed and a lightweight
//! heartbeat polls the row's current epoch. When the epoch moves on (another
//! claim/reclaim bumped it — see
//! `ExecutionRepository::claim_stuck_execution_for_resume` /
//! `reclaim_orphaned_resuming`), the resumer has been superseded and the
//! engine's [`CancellationToken`] is fired, aborting the run promptly instead of
//! racing to completion against a row another controller owns.
//!
//! The epoch — not status — is the disambiguator: a superseded resumer and the
//! legitimate next resumer can BOTH observe `resuming`, but only one holds the
//! current epoch. See `docs/split-brain-fencing-design.md`.
//!
//! ## Status: a run that is already over (2026-09-25)
//!
//! The heartbeat also reads `status`, and stops the run when the row has
//! become TERMINAL — `cancelled` by an operator, `failed` by the stale sweep
//! or an operator cleanup, `completed` by anyone but this controller (which
//! only finalizes after the run returns). An operator cancel stops a run
//! driven by THIS process at once, through `talos_shutdown::inflight`; this
//! poll is the cross-replica backstop for a run another controller is
//! driving, bounded by [`FENCE_HEARTBEAT_SECS`], and only on the fenced
//! paths listed below. On every path, the first module dispatch after the
//! row turned terminal is refused anyway: its start row is born `cancelled`
//! (`StartedRow::BornCancelled`) and the engine stops the run.
//!
//! ## Fresh-run coverage
//!
//! Fencing now covers THREE entry paths:
//! - the resume path (`crash_recovery::resume_execution` → [`run_with_seed_fenced`]);
//! - the PRIMARY fresh-run path (`trigger.rs` → [`run_with_trigger_input_fenced`]),
//!   which observes the row's current `epoch` (0 for a fresh INSERT) and aborts
//!   if a reclaim bumps it; and
//! - the SCHEDULER (`talos-scheduler` → both [`run_with_trigger_input_fenced`]
//!   and [`run_with_seed_fenced`]). Scheduled runs are long-lived `running`
//!   rows — the likeliest to outlast the stale window and be reclaimed while
//!   the scheduler is still dispatching — so they're the highest-value
//!   non-resume site.
//!
//! ## Remaining unfenced fresh-run sites
//!
//! The inbound-webhook paths are NOT fenced. The SYNC path (`auto_respond=true`)
//! is bounded by `sync_timeout` (≤120s, under the stale window), and a reclaim
//! there would abort the inline run the caller is waiting on. The ASYNC path
//! creates its row as `Queued` and never marks it `running`, and crash recovery
//! only reclaims `running` rows — so a webhook async run is never reclaimed,
//! there is never a resumer, and there is no split-brain for a fence to close
//! (a fence there would be inert and unnecessary).
//!
//! Other `run_with_trigger_input_via_nats` call sites also dispatch WITHOUT a
//! fence: `retry.rs`, `replay.rs`, continuation/approval resume
//! (`talos-continuation-trigger`), the MCP trigger handlers
//! (`talos-mcp-handlers`), and the GraphQL `triggerWorkflow` mutation
//! (`talos-api`). For those, the exposure is unchanged and bounded: a stale
//! original keeps dispatching alongside a resumer, but terminal writes are
//! status-guarded (no terminal-state corruption / lost-update), so the only
//! effect is the at-least-once duplicate node dispatch the durable-execution
//! contract already documents (`crash_recovery` module docs).
//! [`run_with_trigger_input_fenced`] is reusable, so extending each site is a
//! matter of reading the row's epoch and threading [`was_fenced`] into that
//! site's failure handling — tracked as follow-up work, done per-site because
//! each owns its own terminal-write logic.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value as JsonValue;
use sqlx::{Pool, Postgres};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use talos_workflow_engine::{ParallelWorkflowEngine, WorkflowEngineError};
use talos_workflow_engine_core::{WorkerSharedKey, WorkflowContext};

use crate::nats_run::{run_with_seed_via_nats, run_with_trigger_input_via_nats};

/// How often the fence heartbeat re-reads the execution's epoch. Short enough
/// to bound a superseded controller's wasted dispatch to a few nodes, long
/// enough that the single-row primary-key lookup is negligible load.
const FENCE_HEARTBEAT_SECS: u64 = 10;

/// Aborts a spawned heartbeat task when dropped — including on a panic unwind
/// of the run future. Manually reaping the heartbeat after `run(...).await`
/// (the old `token.cancel(); heartbeat.await`) is skipped if the run PANICS,
/// orphaning a task that polls the DB every tick forever. A drop guard reaps it
/// on every exit path. `abort()` is safe for the heartbeat: it's a stateless
/// poll loop, so a forced cancel at its next await point leaks nothing.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Run a crash-recovery resume under an epoch fence.
///
/// Sets a [`CancellationToken`] on `engine`, spawns a heartbeat that aborts the
/// run if the execution's `epoch` advances past `my_epoch` (i.e. another
/// controller claimed/reclaimed it), runs the seed path to completion, then
/// stops the heartbeat. Returns whatever the run returns; a fence abort surfaces
/// as [`WorkflowEngineError::Cancelled`] — test it with [`was_fenced`] so the
/// caller does NOT then mark the row failed (it now belongs to another
/// controller, or a reclaim already failed it).
pub async fn run_with_seed_fenced(
    engine: &mut ParallelWorkflowEngine,
    nats_client: Arc<async_nats::Client>,
    worker_shared_key: Option<WorkerSharedKey>,
    initial_results: HashMap<Uuid, JsonValue>,
    execution_id: Uuid,
    pool: Pool<Postgres>,
    my_epoch: i64,
) -> Result<WorkflowContext, WorkflowEngineError> {
    let token = CancellationToken::new();
    engine.set_cancellation_token(Some(token.clone()));

    let operator_cancelled = Arc::new(AtomicBool::new(false));
    // Reaped on EVERY exit (return or panic) via the drop guard — see AbortOnDrop.
    let _heartbeat = AbortOnDrop(tokio::spawn(epoch_fence_heartbeat(
        pool,
        execution_id,
        my_epoch,
        token.clone(),
        operator_cancelled.clone(),
    )));

    let result = run_with_seed_via_nats(
        engine,
        nats_client,
        worker_shared_key,
        initial_results,
        execution_id,
    )
    .await;

    // `_heartbeat`'s drop aborts the task here (and on a panic unwind). No manual
    // `token.cancel()` needed — abort stops the poll loop.
    attribute_stop(result, &operator_cancelled)
}

/// Run a FRESH workflow execution (trigger-input entry path) under an epoch
/// fence — the same protection [`run_with_seed_fenced`] gives the resume path,
/// extended to original fresh runs.
///
/// A fresh execution row starts at `epoch = 0` (the column default; see
/// migration `20260602140000`). A crash-recovery claim/reclaim bumps
/// `epoch + 1`. So if this fresh run goes stale (GC pause / partition / a node
/// slower than the stale window) and a restarting controller reclaims the row,
/// the heartbeat sees the epoch advance past `my_epoch` and aborts this
/// now-superseded original controller — instead of letting it keep dispatching
/// alongside the resumer (duplicate side effects).
///
/// `my_epoch` MUST be the epoch the row currently holds (read it; do NOT
/// hard-code 0). Passing a value that does not match the row's epoch causes the
/// heartbeat to abort a healthy run on its first tick — a silent lost execution,
/// worse than the duplicate-dispatch window this closes. The caller should fall
/// back to the unfenced path if it can't read the epoch.
///
/// A fence abort surfaces as [`WorkflowEngineError::Cancelled`]; test it with
/// [`was_fenced`] so the caller does NOT mark the row failed — it now belongs to
/// the resumer (or a reclaim already failed it).
pub async fn run_with_trigger_input_fenced(
    engine: &mut ParallelWorkflowEngine,
    nats_client: Arc<async_nats::Client>,
    worker_shared_key: Option<WorkerSharedKey>,
    trigger_input: JsonValue,
    execution_id: Uuid,
    pool: Pool<Postgres>,
    my_epoch: i64,
) -> Result<WorkflowContext, WorkflowEngineError> {
    let token = CancellationToken::new();
    engine.set_cancellation_token(Some(token.clone()));

    let operator_cancelled = Arc::new(AtomicBool::new(false));
    // Reaped on EVERY exit (return or panic) via the drop guard — see AbortOnDrop.
    let _heartbeat = AbortOnDrop(tokio::spawn(epoch_fence_heartbeat(
        pool,
        execution_id,
        my_epoch,
        token.clone(),
        operator_cancelled.clone(),
    )));

    let result = run_with_trigger_input_via_nats(
        engine,
        nats_client,
        worker_shared_key,
        trigger_input,
        execution_id,
    )
    .await;

    // `_heartbeat`'s drop aborts the task here (and on a panic unwind).
    attribute_stop(result, &operator_cancelled)
}

/// A fence stop caused by an OPERATOR cancel (the heartbeat saw the row turn
/// `cancelled`) is reported as [`WorkflowEngineError::CancelledByOperator`],
/// not as a fence.
fn attribute_stop(
    result: Result<WorkflowContext, WorkflowEngineError>,
    operator_cancelled: &AtomicBool,
) -> Result<WorkflowContext, WorkflowEngineError> {
    match result {
        Err(WorkflowEngineError::Cancelled) if operator_cancelled.load(Ordering::Acquire) => {
            Err(WorkflowEngineError::CancelledByOperator)
        }
        other => other,
    }
}

/// True when the run stopped because an operator cancelled its execution —
/// in this controller (`run_tracked`) or seen by the fence heartbeat. The row
/// is already `cancelled`: do not mark it failed, and do not count a fence.
pub fn was_cancelled_by_operator(err: &WorkflowEngineError) -> bool {
    matches!(err, WorkflowEngineError::CancelledByOperator)
}

/// True when `err` is the cancellation a fence abort produces. Lets callers
/// branch without naming the engine error enum: a fenced resume must NOT be
/// marked failed by this controller.
pub fn was_fenced(err: &WorkflowEngineError) -> bool {
    matches!(err, WorkflowEngineError::Cancelled)
}

/// What one fence poll decided.
#[derive(Debug, Clone, PartialEq, Eq)]
enum FenceDecision {
    /// The row is still this controller's and still live.
    Continue,
    /// Another claim/reclaim advanced the epoch: this controller was superseded.
    Superseded { observed_epoch: i64 },
    /// The row is terminal — cancelled by an operator, or finalized by
    /// another writer. Nobody is waiting on this run any more.
    Terminal { status: String },
    /// The row no longer exists.
    Vanished,
}

/// Pure: the fence's verdict on one observation of the row. Supersede is
/// checked first — a superseded controller must stop whatever the status
/// says, and the log line should name the reason that is about ownership.
fn fence_decision(my_epoch: i64, observed: Option<(i64, &str)>) -> FenceDecision {
    match observed {
        None => FenceDecision::Vanished,
        Some((epoch, _)) if epoch != my_epoch => FenceDecision::Superseded {
            observed_epoch: epoch,
        },
        Some((_, status @ ("cancelled" | "failed" | "completed"))) => FenceDecision::Terminal {
            status: status.to_string(),
        },
        Some(_) => FenceDecision::Continue,
    }
}

/// Poll the execution's epoch AND status every [`FENCE_HEARTBEAT_SECS`];
/// cancel `token` (aborting the engine) the moment the epoch no longer equals
/// `my_epoch`, the row turns terminal, or the row vanishes. The caller
/// dropping the heartbeat ends the poll. A transient query error is logged and
/// retried (a DB blip must not abort a healthy run; a real supersede or cancel
/// persists and trips next tick).
async fn epoch_fence_heartbeat(
    pool: Pool<Postgres>,
    execution_id: Uuid,
    my_epoch: i64,
    token: CancellationToken,
    operator_cancelled: Arc<AtomicBool>,
) {
    let mut tick = tokio::time::interval(Duration::from_secs(FENCE_HEARTBEAT_SECS));
    // Skip the immediate first tick — there's nothing to check until at least
    // one interval has elapsed, and it avoids a redundant query at t=0.
    tick.tick().await;
    loop {
        tokio::select! {
            // Caller cancelled (run finished) — stop polling.
            () = token.cancelled() => break,
            _ = tick.tick() => {
                let observed = match current_ownership(&pool, execution_id).await {
                    Ok(observed) => observed,
                    Err(e) => {
                        tracing::warn!(
                            %execution_id, error = %e,
                            "crash-recovery FENCE: heartbeat query failed; will retry next tick"
                        );
                        continue;
                    }
                };
                match fence_decision(
                    my_epoch,
                    observed.as_ref().map(|(epoch, status)| (*epoch, status.as_str())),
                ) {
                    FenceDecision::Continue => {}
                    FenceDecision::Superseded { observed_epoch } => {
                        tracing::warn!(
                            %execution_id, held_epoch = my_epoch, observed_epoch,
                            "crash-recovery FENCE: epoch advanced — this controller was \
                             superseded by another claim/reclaim; aborting the resume"
                        );
                        token.cancel();
                        break;
                    }
                    FenceDecision::Terminal { status } => {
                        if status == "cancelled" {
                            operator_cancelled.store(true, Ordering::Release);
                        }
                        tracing::info!(
                            %execution_id, %status,
                            "execution FENCE: the execution is no longer running (an operator \
                             cancel, or finalized by another writer); stopping this run — no \
                             further nodes will be dispatched"
                        );
                        token.cancel();
                        break;
                    }
                    FenceDecision::Vanished => {
                        tracing::warn!(
                            %execution_id, held_epoch = my_epoch,
                            "crash-recovery FENCE: execution row no longer exists; aborting the resume"
                        );
                        token.cancel();
                        break;
                    }
                }
            }
        }
    }
}

/// Single-row primary-key read of the ownership epoch and status. Returns
/// `None` if the row is gone.
async fn current_ownership(
    pool: &Pool<Postgres>,
    execution_id: Uuid,
) -> Result<Option<(i64, String)>, sqlx::Error> {
    sqlx::query_as("SELECT epoch, status FROM workflow_executions WHERE id = $1")
        .bind(execution_id)
        .fetch_optional(pool)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `was_fenced` is the contract BOTH fenced paths (resume + fresh-run) rely
    /// on to decide whether to mark the row failed: a fence abort (Cancelled)
    /// must NOT be marked failed (another controller owns the row), but any
    /// other error (e.g. Timeout) MUST still be marked failed. A regression
    /// here would either clobber a new owner's row (false-true) or leak a
    /// genuinely-failed execution back into the claimable set (false-false).
    #[test]
    fn the_fence_stops_a_run_whose_row_turned_terminal() {
        for status in ["cancelled", "failed", "completed"] {
            assert_eq!(
                fence_decision(3, Some((3, status))),
                FenceDecision::Terminal {
                    status: status.to_string()
                },
                "{status}"
            );
        }
        for live in ["running", "resuming", "queued", "waiting"] {
            assert_eq!(
                fence_decision(3, Some((3, live))),
                FenceDecision::Continue,
                "{live}"
            );
        }
    }

    #[test]
    fn supersede_is_reported_before_status() {
        assert_eq!(
            fence_decision(3, Some((4, "cancelled"))),
            FenceDecision::Superseded { observed_epoch: 4 }
        );
        assert_eq!(fence_decision(3, None), FenceDecision::Vanished);
    }

    #[test]
    fn an_operator_cancel_is_not_reported_as_a_fence() {
        let flag = AtomicBool::new(true);
        let err = attribute_stop(Err(WorkflowEngineError::Cancelled), &flag).unwrap_err();
        assert!(was_cancelled_by_operator(&err));
        assert!(!was_fenced(&err));
        // Control: a supersede leaves the flag unset and stays a fence.
        let flag = AtomicBool::new(false);
        let err = attribute_stop(Err(WorkflowEngineError::Cancelled), &flag).unwrap_err();
        assert!(was_fenced(&err));
        assert!(!was_cancelled_by_operator(&err));
    }

    #[test]
    fn was_fenced_only_matches_cancellation() {
        assert!(was_fenced(&WorkflowEngineError::Cancelled));
        assert!(!was_fenced(&WorkflowEngineError::Timeout {
            secs: 30,
            attribution: String::new()
        }));
    }
}
