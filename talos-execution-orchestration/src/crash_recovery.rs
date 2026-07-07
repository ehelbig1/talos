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
//!   `resuming -> failed` so it never leaks back into the claimable set. On a
//!   *successful* run, `resume_one` writes the terminal status itself
//!   (`mark_execution_{completed,waiting}`, which accept `resuming` as well as
//!   `running`) — the engine run does not persist execution status; every run
//!   caller finalizes afterward.
//! - **Actor / tier re-stamp.** The original `actor_id` (or the workflow's bound
//!   default) is re-applied so the `max_llm_tier` data-egress ceiling survives
//!   the restart — a tier-1 execution must not resume as tier-2.

use std::sync::Arc;

use sqlx::PgPool;
use uuid::Uuid;

use talos_actor_repository::ActorRepository;
use talos_engine::builder::{for_workflow, EngineOpts};
use talos_engine::checkpoint_store::load_checkpoint_for_resume;
use talos_execution_repository::{ExecutionRepository, StuckExecutionForResume};
use talos_registry::ModuleRegistry;
use talos_secrets_manager::SecretsManager;
use talos_workflow_engine_core::WorkerSharedKey;

/// Cap on concurrent resume dispatches so a mass crash (many in-flight
/// executions at restart) doesn't stampede NATS / the worker pool. Resumes
/// queue behind this rather than launching all at once.
const MAX_CONCURRENT_RESUMES: usize = 8;

/// Which platform path claimed the row and is driving this resume. The
/// resume kernel ([`resume_one`]) is shared between controller-startup
/// crash recovery and the approval-decision resume path
/// (`ExecutionOrchestrationService::resume_waiting_execution`); the
/// origin parameterises log prefixes and metric recording so an
/// operator reading logs can tell a restart sweep from a human
/// approval, and approval resumes don't inflate the
/// `talos_crash_recovery_total` counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResumeOrigin {
    /// Startup sweep over orphaned `running` rows (RFC 0003).
    CrashRecovery,
    /// An approval decision resumed a `waiting` (suspended) execution.
    ApprovalDecision,
}

impl ResumeOrigin {
    /// Stable log-message prefix. `CrashRecovery` MUST stay
    /// `"crash-recovery"` — operators grep/alert on the historical
    /// message text.
    pub(crate) fn label(self) -> &'static str {
        match self {
            ResumeOrigin::CrashRecovery => "crash-recovery",
            ResumeOrigin::ApprovalDecision => "approval-resume",
        }
    }

    /// Only the startup sweep records `talos_crash_recovery_total`.
    fn records_metrics(self) -> bool {
        matches!(self, ResumeOrigin::CrashRecovery)
    }
}

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
        Ok(n) if n > 0 => {
            record_outcome("reclaimed", n);
            tracing::warn!(
                reclaimed = n,
                "crash-recovery: failed {n} execution(s) wedged in 'resuming' from a prior interrupted recovery"
            );
        }
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
                    resume_one(deps, row, ResumeOrigin::CrashRecovery).await;
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
///
/// Shared kernel: called by the startup crash-recovery sweep above AND by
/// `ExecutionOrchestrationService::resume_waiting_execution` (the
/// approval-decision path). Both claim the row into `resuming` first —
/// every downstream guard (`load_checkpoint_for_resume` statuses, the
/// `mark_execution_{completed,waiting}` finalizers, `fail_resuming_execution`)
/// keys on that state, so the kernel is origin-agnostic.
pub(crate) async fn resume_one(
    deps: RecoveryDeps,
    row: StuckExecutionForResume,
    origin: ResumeOrigin,
) {
    let exec_id = row.id;
    let origin_label = origin.label();

    // The workflow was deleted between the original run and this restart — we
    // have no graph to resume against. Fail terminally.
    let Some(graph_json) = row.graph_json else {
        fail(
            &deps,
            exec_id,
            origin,
            &format!("{origin_label}: workflow was deleted before resume"),
        )
        .await;
        tracing::warn!(execution_id = %exec_id, "{origin_label}: workflow deleted — marked failed");
        return;
    };

    // Re-stamp the original actor (or the workflow's bound default) so the
    // per-actor `max_llm_tier` ceiling is re-applied on resume. `for_workflow`
    // fail-closes to tier-1 if the actor row can't be read.
    let opts = EngineOpts::for_run(row.workflow_id, graph_json)
        .with_effective_actor(row.actor_id, row.workflow_default_actor_id);

    let mut engine = match for_workflow(
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
                origin,
                &format!("{origin_label}: engine build failed: {redacted}"),
            )
            .await;
            tracing::error!(execution_id = %exec_id, error = %redacted, "{origin_label}: engine build failed");
            return;
        }
    };

    // Load the persisted node-result set (reads the `resuming` row). Empty means
    // the execution was claimed before its first checkpoint landed — resume from
    // scratch (at-least-once; the workflow's idempotency design owns dedupe).
    //
    // Strip paused-node placeholders (`__waiting__: true` envelopes) from the
    // seed: the pause/resume contract (see `WaitOutcome` /
    // `ConfidenceGateOutcome::Pause` in talos-workflow-engine) is that the
    // paused node's committed "output" is a transient snapshot marker, NOT a
    // completed result. Seeding it verbatim would mark the paused node as
    // already-completed — its successors would run with the waiting envelope
    // as their input, and a confidence gate would never re-consult its
    // approval row. Removing the entry makes the reactor re-dispatch the
    // paused node (its parents are still seeded), and the gate's
    // `check_or_request` fast path then observes the recorded
    // approved/denied decision.
    let initial_results = strip_waiting_placeholder_seeds(
        load_checkpoint_for_resume(
            &deps.db_pool,
            deps.worker_shared_key
                .as_ref()
                .map(WorkerSharedKey::as_bytes),
            Some(deps.secrets_manager.clone()),
            exec_id,
        )
        .await,
    );
    if initial_results.is_empty() {
        tracing::warn!(
            execution_id = %exec_id,
            "{origin_label}: no checkpoint found — resuming from scratch (at-least-once)"
        );
    } else {
        tracing::info!(
            execution_id = %exec_id,
            checkpointed_nodes = initial_results.len(),
            "{origin_label}: resuming from checkpoint"
        );
    }

    // ALWAYS the seed path — `run_with_seed_fenced` resumes from the
    // checkpointed node set. A trigger-input path would inject a synthetic
    // `__trigger__` and re-seed the roots, double-executing completed nodes.
    //
    // The run is wrapped in an epoch fence (F4): a heartbeat aborts it if the
    // execution's `epoch` advances past `row.epoch` (this claim's bumped value),
    // which means another controller has claimed/reclaimed the row out from
    // under us. `engine` must be `mut` so the fence can set its cancellation
    // token.
    match talos_engine::fence::run_with_seed_fenced(
        &mut engine,
        deps.nats_client.clone(),
        deps.worker_shared_key.clone(),
        initial_results,
        exec_id,
        deps.db_pool.clone(),
        row.epoch,
    )
    .await
    {
        // Finalize the resumed run. `run_with_seed_via_nats` (run under the
        // fence) does NOT write the execution's terminal status — every other
        // run caller (trigger / scheduler / retry / replay) finalizes after the
        // run returns, and the resume path must too. Without this the row stays
        // `resuming` forever (the worker re-runs the graph, but nothing moves
        // the execution out of `resuming` → it's eventually force-failed by the
        // stale sweep). `mark_execution_{completed,waiting}` accept `resuming`
        // as well as `running` (talos-workflow-repository) so this finalize
        // matches the claimed row. `ctx.waiting` distinguishes a run that
        // yielded (sub-workflow / approval / sleep) from one that finished.
        Ok(ctx) => {
            let mut aggregated = serde_json::Map::new();
            for (node_id, output) in &ctx.results {
                aggregated.insert(node_id.to_string(), output.clone());
            }
            let output_json = serde_json::Value::Object(aggregated);
            let wf_repo = talos_workflow_repository::WorkflowRepository::new(deps.db_pool.clone())
                .with_encryption(deps.secrets_manager.clone());
            let finalize = if ctx.waiting {
                wf_repo.mark_execution_waiting(exec_id, &output_json).await
            } else {
                wf_repo
                    .mark_execution_completed(exec_id, &output_json)
                    .await
            };
            if let Err(e) = finalize {
                tracing::error!(
                    execution_id = %exec_id,
                    error = %e,
                    "{origin_label}: failed to finalize resumed execution — row may remain 'resuming'"
                );
            }
            if origin.records_metrics() {
                record_outcome("resumed", 1);
            }
            tracing::info!(
                execution_id = %exec_id,
                waiting = ctx.waiting,
                "{origin_label}: execution resumed"
            );
        }
        // Fenced: another controller superseded this resume (epoch advanced).
        // Do NOT mark the row failed — it now belongs to the new owner, or a
        // reclaim already failed it. Failing here would clobber the new owner's
        // `resuming` row. Just count it and move on.
        Err(ref e) if talos_engine::fence::was_fenced(e) => {
            if origin.records_metrics() {
                record_outcome("fenced", 1);
            }
            tracing::warn!(
                execution_id = %exec_id,
                held_epoch = row.epoch,
                "{origin_label}: resume fenced — superseded by another controller; leaving the row to its new owner"
            );
        }
        Err(e) => {
            let redacted = talos_dlp_provider::redact_str(&e.to_string());
            fail(
                &deps,
                exec_id,
                origin,
                &format!("{origin_label}: resume dispatch failed: {redacted}"),
            )
            .await;
            tracing::error!(execution_id = %exec_id, error = %redacted, "{origin_label}: resume dispatch failed");
        }
    }
}

/// Drop paused-node placeholder entries (JSON objects carrying
/// `__waiting__: true`) from a checkpoint seed so the paused node
/// re-dispatches on resume instead of being treated as completed.
///
/// Pure — unit-tested below without a database. Real node outputs are
/// preserved untouched, including non-object values and objects that
/// merely mention the key with a non-`true` value.
fn strip_waiting_placeholder_seeds(
    mut seed: std::collections::HashMap<Uuid, serde_json::Value>,
) -> std::collections::HashMap<Uuid, serde_json::Value> {
    seed.retain(|_, v| {
        v.get(talos_workflow_engine_core::reserved_keys::WAITING)
            .and_then(serde_json::Value::as_bool)
            != Some(true)
    });
    seed
}

#[cfg(test)]
mod strip_waiting_placeholder_tests {
    use super::strip_waiting_placeholder_seeds;
    use serde_json::json;
    use std::collections::HashMap;
    use uuid::Uuid;

    #[test]
    fn strips_waiting_envelopes_keeps_real_outputs() {
        let paused = Uuid::new_v4();
        let completed = Uuid::new_v4();
        let mut seed = HashMap::new();
        seed.insert(
            paused,
            json!({"__waiting__": true, "__confidence_used__": 0.42, "message": "paused"}),
        );
        seed.insert(
            completed,
            json!({"result": "ok", "__confidence_used__": 0.9}),
        );

        let out = strip_waiting_placeholder_seeds(seed);
        assert!(!out.contains_key(&paused), "paused node must re-dispatch");
        assert!(out.contains_key(&completed), "real output must survive");
    }

    #[test]
    fn keeps_non_object_and_non_true_waiting_values() {
        let scalar = Uuid::new_v4();
        let waiting_false = Uuid::new_v4();
        let waiting_string = Uuid::new_v4();
        let mut seed = HashMap::new();
        seed.insert(scalar, json!("plain string output"));
        seed.insert(waiting_false, json!({"__waiting__": false}));
        // A string "true" is not the engine's pause marker — only the
        // boolean form is emitted by WaitOutcome / ConfidenceGateOutcome.
        seed.insert(waiting_string, json!({"__waiting__": "true"}));

        let out = strip_waiting_placeholder_seeds(seed);
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn empty_seed_stays_empty() {
        let out = strip_waiting_placeholder_seeds(HashMap::new());
        assert!(out.is_empty());
    }
}

/// Record a crash-recovery outcome on the `talos_crash_recovery_total{outcome}`
/// counter. No-op until `talos_metrics::set_global` has run (it runs at
/// controller startup, before this sweep is spawned) — never unwraps, so it's
/// inert in tests and in any process without metrics wired.
fn record_outcome(outcome: &str, n: u64) {
    if n == 0 {
        return;
    }
    if let Some(m) = talos_metrics::global() {
        m.crash_recovery_total
            .with_label_values(&[outcome])
            .inc_by(n as f64);
    }
}

/// Status-guarded terminal fail (`resuming -> failed`). Logs if the guarded
/// UPDATE doesn't land (row already moved on, or DB error) but never panics —
/// a failure here just leaves the row for the next restart's reclaim.
async fn fail(deps: &RecoveryDeps, exec_id: Uuid, origin: ResumeOrigin, message: &str) {
    let origin_label = origin.label();
    // Count the recovery's decision to give up on this execution (deleted
    // workflow / engine-build error / dispatch error all route through here).
    if origin.records_metrics() {
        record_outcome("failed", 1);
    }
    match deps
        .execution_repo
        .fail_resuming_execution(exec_id, message)
        .await
    {
        Ok(true) => {}
        Ok(false) => tracing::warn!(
            execution_id = %exec_id,
            "{origin_label}: fail transition was a no-op (row no longer 'resuming')"
        ),
        Err(e) => tracing::error!(
            execution_id = %exec_id,
            error = %e,
            "{origin_label}: failed to mark execution failed — will be reclaimed on next restart"
        ),
    }
}
