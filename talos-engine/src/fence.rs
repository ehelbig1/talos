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
//! ## Scope limitation — fresh runs are NOT actively fenced
//!
//! The heartbeat is installed ONLY on the resume path
//! (`crash_recovery::resume_execution` → [`run_with_seed_fenced`]). The
//! ORIGINAL fresh-run controller (`trigger.rs` → `run_with_trigger_input_via_nats`)
//! runs WITHOUT an epoch heartbeat. So if a fresh run goes stale (GC pause /
//! partition / a node slower than the stale window) and a restarting controller
//! reclaims it, the original is NOT aborted — it keeps dispatching alongside the
//! resumer until it next blocks/completes. This is bounded, not unbounded:
//! terminal writes are status-guarded (no terminal-state corruption or
//! lost-update on the row), so the only exposure is the at-least-once duplicate
//! node dispatch the durable-execution contract already documents
//! (`crash_recovery` module docs). Tightening this — stamping an epoch at fresh
//! INSERT and fencing the fresh-run path the same way — is a tracked follow-up;
//! do NOT read this module as fencing the original fresh-run controller today.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value as JsonValue;
use sqlx::{Pool, Postgres};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use talos_workflow_engine::{ParallelWorkflowEngine, WorkflowEngineError};
use talos_workflow_engine_core::{WorkerSharedKey, WorkflowContext};

use crate::nats_run::run_with_seed_via_nats;

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
