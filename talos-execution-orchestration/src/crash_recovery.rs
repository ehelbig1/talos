//! Controller-startup crash recovery for checkpointed executions (RFC 0003,
//! durable execution).
//!
//! When the controller restarts, any execution that was mid-flight is left
//! wedged in `running` — its in-process engine task died with the process.
//! If `EXECUTION_CHECKPOINTING_ENABLED` was on, the engine periodically
//! persisted its node-result set to `workflow_executions.checkpoint_encrypted`
//! (heartbeating `updated_at` via the `BEFORE UPDATE` trigger). This module
//! finds those orphans on startup and resumes them from their last checkpoint
//! instead of failing them.
//!
//! Safety model (the parts that matter):
//! - **Exactly-once claim.** [`ExecutionRepository::claim_stuck_execution_for_resume`]
//!   flips `running -> resuming` in a single `FOR UPDATE SKIP LOCKED` +
//!   status-guarded UPDATE, so two controllers (or two sweeps) can never both
//!   pick up the same row.
//! - **Reclaim runs once, first.** [`ExecutionRepository::reclaim_orphaned_resuming`]
//!   fails any row stuck in `resuming` longer than the stale window — these are
//!   leftovers from a *prior* recovery that itself crashed mid-dispatch. It runs
//!   before the claim loop, so it can never touch a resume this sweep is about
//!   to dispatch (those don't exist yet). A resume that crashes again ends up
//!   `resuming`-and-stale and is failed by the next restart's reclaim — one
//!   attempt, then terminal, no infinite resume loop.
//! - **Terminal on dispatch failure.** Any error before/at hand-off (deleted
//!   workflow, engine build failure, NATS dispatch failure) flips the row
//!   `resuming -> failed` so it never leaks back into the claimable set. The
//!   engine itself owns the terminal write on a *successful* hand-off (its bare
//!   `UPDATE ... WHERE id = $1` moves the row out of `resuming`).
//! - **Actor / tier re-stamp.** The original `actor_id` (or the workflow's bound
//!   default) is re-applied so the `max_llm_tier` data-egress ceiling survives
//!   the restart — a tier-1 execution must not resume as tier-2.

use std::sync::Arc;

use sqlx::PgPool;
use uuid::Uuid;

use talos_actor_repository::ActorRepository;
use talos_engine::builder::{for_workflow, EngineOpts};
use talos_engine::checkpoint_store::load_checkpoint_for_resume;
use talos_engine::nats_run::run_with_seed_via_nats;
use talos_execution_repository::{ExecutionRepository, StuckExecutionForResume};
use talos_registry::ModuleRegistry;
use talos_secrets_manager::SecretsManager;
use talos_workflow_engine_core::WorkerSharedKey;

/// Cap on concurrent resume dispatches so a mass crash (many in-flight
/// executions at restart) doesn't stampede NATS / the worker pool. Resumes
/// queue behind this rather than launching all at once.
const MAX_CONCURRENT_RESUMES: usize = 8;

/// Dependencies the resume path needs. Bundled so the per-row spawn can take
/// one cheap-to-clone struct instead of eight positional args.
#[derive(Clone)]
pub struct RecoveryDeps {
    pub db_pool: PgPool,
    pub registry: Arc<ModuleRegistry>,
    pub secrets_manager: Arc<SecretsManager>,
    pub actor_repo: Arc<ActorRepository>,
    pub execution_repo: Arc<ExecutionRepository>,
    pub worker_shared_key: Option<WorkerSharedKey>,
    pub nats_client: Arc<async_nats::Client>,
}

/// Sweep orphaned checkpointed executions and resume them from their last
/// checkpoint. Intended to run once at controller startup (flag-gated by the
/// caller on `EXECUTION_CHECKPOINTING_ENABLED`).
///
/// `stale_after_minutes` is the age beyond which a `running` row is considered
/// orphaned. It MUST be smaller than the stuck-execution cleanup timeout so a
/// recoverable execution is resumed before any unrelated cleanup task could
/// fail it; the caller enforces that ordering.
pub async fn recover_stuck_executions(deps: RecoveryDeps, stale_after_minutes: i64) {
    if stale_after_minutes <= 0 {
        tracing::warn!(
            stale_after_minutes,
            "crash-recovery: non-positive stale window — skipping sweep"
        );
        return;
    }

    // 1. Fail any rows wedged in `resuming` from a prior interrupted recovery.
    //    Runs BEFORE the claim loop, so it never races a resume this sweep
    //    dispatches.
    match deps
        .execution_repo
        .reclaim_orphaned_resuming(stale_after_minutes)
        .await
    {
        Ok(n) if n > 0 => tracing::warn!(
            reclaimed = n,
            "crash-recovery: failed {n} execution(s) wedged in 'resuming' from a prior interrupted recovery"
        ),
        Ok(_) => {}
        Err(e) => tracing::error!(error = %e, "crash-recovery: reclaim_orphaned_resuming failed"),
    }

    // 2. Claim + resume loop, bounded concurrency. Each claim atomically flips
    //    the globally-oldest stale `running` row to `resuming`; the loop ends
    //    when no stale row remains.
    let sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_RESUMES));
    let mut handles = Vec::new();
    let mut claimed = 0usize;

    loop {
        match deps
            .execution_repo
            .claim_stuck_execution_for_resume(stale_after_minutes)
            .await
        {
            Ok(Some(row)) => {
                claimed += 1;
                // acquire_owned only errors if the semaphore is closed, which
                // we never do — hold the permit for the spawned task's life.
                let permit = sem
                    .clone()
                    .acquire_owned()
                    .await
                    .expect("crash-recovery semaphore is never closed");
                let deps = deps.clone();
                handles.push(tokio::spawn(async move {
                    let _permit = permit;
                    resume_one(deps, row).await;
                }));
            }
            Ok(None) => break,
            Err(e) => {
                tracing::error!(error = %e, "crash-recovery: claim failed — stopping sweep early");
                break;
            }
        }
    }

    if claimed == 0 {
        tracing::debug!("crash-recovery: no orphaned executions to resume");
        return;
    }

    tracing::info!(
        claimed,
        "crash-recovery: claimed {claimed} orphaned execution(s); awaiting resume dispatch"
    );
    for h in handles {
        // A panicked resume task is logged but must not abort the sweep.
        if let Err(e) = h.await {
            tracing::error!(error = %e, "crash-recovery: a resume task panicked");
        }
    }
    tracing::info!("crash-recovery: startup sweep complete");
}

/// Resume a single claimed (`resuming`) execution. Owns the terminal-fail
/// transition for every failure mode up to and including NATS hand-off; the
/// engine owns the terminal write on a successful hand-off.
async fn resume_one(deps: RecoveryDeps, row: StuckExecutionForResume) {
    let exec_id = row.id;

    // The workflow was deleted between the original run and this restart — we
    // have no graph to resume against. Fail terminally.
    let Some(graph_json) = row.graph_json else {
        fail(&deps, exec_id, "crash-recovery: workflow was deleted before resume").await;
        tracing::warn!(execution_id = %exec_id, "crash-recovery: workflow deleted — marked failed");
        return;
    };

    // Re-stamp the original actor (or the workflow's bound default) so the
    // per-actor `max_llm_tier` ceiling is re-applied on resume. `for_workflow`
    // fail-closes to tier-1 if the actor row can't be read.
    let opts = EngineOpts::for_run(row.workflow_id, graph_json)
        .with_effective_actor(row.actor_id, row.workflow_default_actor_id);

    let engine = match for_workflow(
        deps.registry.clone(),
        deps.secrets_manager.clone(),
        deps.actor_repo.clone(),
        row.user_id,
        opts,
    )
    .await
    {
        Ok(e) => e,
        Err(e) => {
            // DLP-scrub: build errors can carry parsed-graph text (parity with
            // the trigger / scheduler engine-build arms).
            let redacted = talos_dlp_provider::redact_str(&e.to_string());
            fail(
                &deps,
                exec_id,
                &format!("crash-recovery: engine build failed: {redacted}"),
            )
            .await;
            tracing::error!(execution_id = %exec_id, error = %redacted, "crash-recovery: engine build failed");
            return;
        }
    };

    // Load the persisted node-result set (reads the `resuming` row). Empty means
    // the execution was claimed before its first checkpoint landed — resume from
    // scratch (at-least-once; the workflow's idempotency design owns dedupe).
    let initial_results = load_checkpoint_for_resume(
        &deps.db_pool,
        deps.worker_shared_key.as_ref().map(WorkerSharedKey::as_bytes),
        Some(deps.secrets_manager.clone()),
        exec_id,
    )
    .await;
    if initial_results.is_empty() {
        tracing::warn!(
            execution_id = %exec_id,
            "crash-recovery: no checkpoint found — resuming from scratch (at-least-once)"
        );
    } else {
        tracing::info!(
            execution_id = %exec_id,
            checkpointed_nodes = initial_results.len(),
            "crash-recovery: resuming from checkpoint"
        );
    }

    // ALWAYS the seed path — `run_with_seed_via_nats` resumes from the
    // checkpointed node set. A trigger-input path would inject a synthetic
    // `__trigger__` and re-seed the roots, double-executing completed nodes.
    match run_with_seed_via_nats(
        &engine,
        deps.nats_client.clone(),
        deps.worker_shared_key.clone(),
        initial_results,
        exec_id,
    )
    .await
    {
        // The engine wrote the terminal status (completed / failed / waiting),
        // moving the row out of `resuming`.
        Ok(_ctx) => tracing::info!(execution_id = %exec_id, "crash-recovery: execution resumed"),
        Err(e) => {
            let redacted = talos_dlp_provider::redact_str(&e.to_string());
            fail(
                &deps,
                exec_id,
                &format!("crash-recovery: resume dispatch failed: {redacted}"),
            )
            .await;
            tracing::error!(execution_id = %exec_id, error = %redacted, "crash-recovery: resume dispatch failed");
        }
    }
}

/// Status-guarded terminal fail (`resuming -> failed`). Logs if the guarded
/// UPDATE doesn't land (row already moved on, or DB error) but never panics —
/// a failure here just leaves the row for the next restart's reclaim.
async fn fail(deps: &RecoveryDeps, exec_id: Uuid, message: &str) {
    match deps
        .execution_repo
        .fail_resuming_execution(exec_id, message)
        .await
    {
        Ok(true) => {}
        Ok(false) => tracing::warn!(
            execution_id = %exec_id,
            "crash-recovery: fail transition was a no-op (row no longer 'resuming')"
        ),
        Err(e) => tracing::error!(
            execution_id = %exec_id,
            error = %e,
            "crash-recovery: failed to mark execution failed — will be reclaimed on next restart"
        ),
    }
}
