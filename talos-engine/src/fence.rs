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
//! The inbound-webhook ASYNC path (`talos-webhooks`, `auto_respond=false`) is
//! also fenced; the webhook SYNC path is intentionally not (bounded by
//! `sync_timeout` ≤120s, under the stale window, and a reclaim there would abort
//! the inline run the caller is waiting on).
//!
//! Other `run_with_trigger_input_via_nats` call sites still dispatch WITHOUT a
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

    let heartbeat = tokio::spawn(epoch_fence_heartbeat(
        pool,
        execution_id,
        my_epoch,
        token.clone(),
    ));

    let result = run_with_seed_via_nats(
        engine,
        nats_client,
        worker_shared_key,
        initial_results,
        execution_id,
    )
    .await;

    // Stop the heartbeat (idempotent — it may have already cancelled to abort
    // a fenced run) and reap the task so it can't outlive the resume.
    token.cancel();
    let _ = heartbeat.await;

    result
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

    let heartbeat = tokio::spawn(epoch_fence_heartbeat(
        pool,
        execution_id,
        my_epoch,
        token.clone(),
    ));

    let result = run_with_trigger_input_via_nats(
        engine,
        nats_client,
        worker_shared_key,
        trigger_input,
        execution_id,
    )
    .await;

    // Stop the heartbeat (idempotent — it may have already cancelled to abort a
    // fenced run) and reap the task so it can't outlive the run.
    token.cancel();
    let _ = heartbeat.await;

    result
}

/// True when `err` is the cancellation a fence abort produces. Lets callers
/// branch without naming the engine error enum: a fenced resume must NOT be
/// marked failed by this controller.
pub fn was_fenced(err: &WorkflowEngineError) -> bool {
    matches!(err, WorkflowEngineError::Cancelled)
}

/// Poll the execution's epoch every [`FENCE_HEARTBEAT_SECS`]; cancel `token`
/// (aborting the engine) the moment the epoch no longer equals `my_epoch`, the
/// row vanishes, or — implicitly — the caller cancels the token to signal the
/// run finished. A transient query error is logged and retried (a DB blip must
/// not abort a healthy resume; a real supersede persists and trips next tick).
async fn epoch_fence_heartbeat(
    pool: Pool<Postgres>,
    execution_id: Uuid,
    my_epoch: i64,
    token: CancellationToken,
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
                match current_epoch(&pool, execution_id).await {
                    Ok(Some(epoch)) if epoch == my_epoch => { /* still ours */ }
                    Ok(Some(epoch)) => {
                        tracing::warn!(
                            %execution_id, held_epoch = my_epoch, observed_epoch = epoch,
                            "crash-recovery FENCE: epoch advanced — this controller was \
                             superseded by another claim/reclaim; aborting the resume"
                        );
                        token.cancel();
                        break;
                    }
                    Ok(None) => {
                        tracing::warn!(
                            %execution_id, held_epoch = my_epoch,
                            "crash-recovery FENCE: execution row no longer exists; aborting the resume"
                        );
                        token.cancel();
                        break;
                    }
                    Err(e) => tracing::warn!(
                        %execution_id, error = %e,
                        "crash-recovery FENCE: epoch heartbeat query failed; will retry next tick"
                    ),
                }
            }
        }
    }
}

/// Single-column primary-key read of the current ownership epoch. Returns
/// `None` if the row is gone.
async fn current_epoch(
    pool: &Pool<Postgres>,
    execution_id: Uuid,
) -> Result<Option<i64>, sqlx::Error> {
    let row: Option<(i64,)> = sqlx::query_as("SELECT epoch FROM workflow_executions WHERE id = $1")
        .bind(execution_id)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.0))
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
    fn was_fenced_only_matches_cancellation() {
        assert!(was_fenced(&WorkflowEngineError::Cancelled));
        assert!(!was_fenced(&WorkflowEngineError::Timeout { secs: 30 }));
    }
}
