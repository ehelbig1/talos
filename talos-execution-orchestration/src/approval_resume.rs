//! Approval-decision resume of a suspended (`waiting`) execution.
//!
//! When a confidence-gate (`on_low_confidence: "pause"`) or approval node
//! suspends a run, the engine records a pending `execution_approvals` row
//! and the finalizers (post-#423) park the execution at
//! `status = 'waiting'`. Recording the human decision
//! (`submit_workflow_approval` MCP tool, GraphQL approve/deny mutations)
//! only flips the approval row — something must then RESUME the waiting
//! execution so the gate re-evaluates, observes the recorded decision via
//! `ApprovalGate::check_or_request`'s fast path, and proceeds (approved)
//! or fails loudly (denied).
//!
//! This module is that wiring. It reuses the crash-recovery resume kernel
//! ([`crate::crash_recovery::resume_one`]) — claim → engine rebuild with
//! actor/tier re-stamp → checkpoint seed → fenced NATS run → finalize —
//! rather than reimplementing the resume, and differs from the startup
//! sweep only in the claim:
//!
//! * **By-id, tenant-scoped claim.**
//!   [`ExecutionRepository::claim_waiting_execution_for_resume`] flips
//!   `waiting -> resuming` atomically with `AND user_id = $caller`, so
//!   ownership is enforced inside the authoritative write, not just by
//!   the caller's earlier advisory read.
//! * **Single resume, ever.** The single-status precondition means a
//!   concurrent approval submission, the GraphQL `resumeWorkflow`
//!   mutation, or a racing inline Human_Approval_Gate NATS signal can't
//!   produce a second dispatch: the loser observes zero rows and reports
//!   `NotWaiting`. The claim's `epoch + 1` bump additionally fences any
//!   controller still driving the row (F4).
//! * **Full trigger-authorization gate BEFORE the claim** (MCP-726
//!   parity with the GraphQL `resumeWorkflow` mutation): actor status,
//!   budget, and capability-ceiling drift are re-checked, and a denied
//!   resume leaves the row in `waiting` (recoverable) rather than
//!   stranding it in `resuming`.

use crate::crash_recovery::{resume_one, RecoveryDeps, ResumeOrigin};
use crate::errors::OrchestrationError;
use crate::trigger::map_trigger_auth_error;
use crate::ExecutionOrchestrationService;
use uuid::Uuid;

/// What the resume attempt did. Both variants are successful protocol
/// outcomes — callers surface them honestly rather than treating
/// `NotWaiting` as an error (the decision itself was already recorded).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitingResumeOutcome {
    /// This caller won the `waiting -> resuming` claim and the resume
    /// dispatch was spawned. The execution's terminal status is written
    /// by the background task once the engine run finishes.
    Resumed,
    /// The execution was not in `waiting` state (or another resume path
    /// claimed it first). Nothing was dispatched.
    NotWaiting,
}

impl ExecutionOrchestrationService {
    /// Resume a suspended (`waiting`) execution after an approval
    /// decision was recorded for it.
    ///
    /// Ownership: the execution must belong to `user_id` — enforced by
    /// the advisory read AND inside the atomic claim itself. Returns
    /// [`WaitingResumeOutcome::NotWaiting`] when the execution exists
    /// but isn't suspended (e.g. an inline Human_Approval_Gate run that
    /// was unblocked over NATS, or a module-approval retry flow), so
    /// callers can report `resume_triggered: false` without failing the
    /// approval write that already landed.
    /// `writable_org_ids`: org-aware scoping for the GraphQL
    /// `resumeWorkflow` path (org editors may resume org-owned
    /// executions); pass `&[]` for strict user-only scoping (the MCP
    /// approval path). Applied uniformly to the advisory read, the
    /// authorization-gate graph fetch, and the atomic claim.
    pub async fn resume_waiting_execution(
        &self,
        execution_id: Uuid,
        user_id: Uuid,
        writable_org_ids: &[Uuid],
    ) -> Result<WaitingResumeOutcome, OrchestrationError> {
        // Dispatch requires NATS — check before touching the row so a
        // NATS-less deployment can't strand the execution in 'resuming'.
        let Some(nats_client) = self.nats_client.clone() else {
            return Err(OrchestrationError::DispatchFailed(
                "NATS client not available".to_string(),
            ));
        };

        // 1. Advisory load + ownership check (tenant-scoped read). The
        //    authoritative gates are the claim below; this read exists to
        //    distinguish "not yours / doesn't exist" from "not waiting"
        //    and to fetch the actor for the authorization gate.
        let exec = self
            .execution_repo
            .get_execution_resume_gate(execution_id, user_id, writable_org_ids)
            .await
            .map_err(OrchestrationError::Internal)?
            .ok_or(OrchestrationError::ExecutionNotFound(execution_id))?;

        if exec.status != "waiting" {
            return Ok(WaitingResumeOutcome::NotWaiting);
        }

        // 2. Full trigger-authorization gate (MCP-726 / MCP-652 shape,
        //    mirroring the GraphQL `resumeWorkflow` mutation): while the
        //    execution was paused the operator may have suspended /
        //    terminated the bound actor or downgraded its capability
        //    ceiling. Gate against the DRAFT graph — the same definition
        //    the resume kernel will run (`claim_*` returns
        //    `workflows.graph_json`). Runs BEFORE the claim so a denied
        //    resume leaves the row in 'waiting' (recoverable by fixing
        //    the actor and re-submitting), never stuck in 'resuming'.
        if exec.actor_id.is_some() {
            let graph_json = self
                .execution_repo
                .get_workflow_graph_for_user_or_orgs(exec.workflow_id, user_id, writable_org_ids)
                .await
                .map_err(OrchestrationError::Internal)?
                .ok_or(OrchestrationError::WorkflowNotFound(exec.workflow_id))?;

            talos_workflow_authorization::authorize_workflow_trigger(
                &self.workflow_repo,
                &self.actor_repo,
                &self.db_pool,
                exec.actor_id,
                user_id,
                &graph_json,
            )
            .await
            .map_err(map_trigger_auth_error)?;
        }

        // 3. Atomic, tenant-scoped claim: `waiting -> resuming`. This is
        //    the double-resume guard — everything before it is advisory.
        let Some(row) = self
            .execution_repo
            .claim_waiting_execution_for_resume(execution_id, user_id, writable_org_ids)
            .await
            .map_err(OrchestrationError::Internal)?
        else {
            // Lost the race (concurrent resume / status moved on). The
            // winner owns the dispatch; report honestly.
            tracing::info!(
                execution_id = %execution_id,
                "approval-resume: claim was a no-op — execution no longer 'waiting' \
                 (another resume path won, or the run already moved on)"
            );
            return Ok(WaitingResumeOutcome::NotWaiting);
        };

        // 4. Hand the claimed row to the shared resume kernel in the
        //    background — same spawn shape as trigger/retry/replay
        //    dispatch. The kernel owns every failure mode from here on
        //    (terminal-fail on build/dispatch error, fence handling,
        //    ctx.waiting-aware finalize).
        let deps = RecoveryDeps {
            db_pool: self.db_pool.clone(),
            registry: self.registry.clone(),
            secrets_manager: self.secrets_manager.clone(),
            actor_repo: self.actor_repo.clone(),
            execution_repo: self.execution_repo.clone(),
            worker_shared_key: self.worker_shared_key.clone(),
            nats_client,
        };
        tracing::info!(
            execution_id = %execution_id,
            workflow_id = %row.workflow_id,
            "approval-resume: claimed waiting execution — dispatching resume"
        );
        tokio::spawn(async move {
            resume_one(deps, row, ResumeOrigin::ApprovalDecision).await;
        });

        Ok(WaitingResumeOutcome::Resumed)
    }

    /// Record an approval decision for a suspended (`waiting`) execution
    /// and resume it — the SAME two-step write path
    /// `submit_workflow_approval` uses ([`ExecutionRepository::
    /// update_execution_approval_decision`] then
    /// [`Self::resume_waiting_execution`]), consolidated so the one-click
    /// email-link HTTP handler and the MCP tool share one code path and
    /// no resume logic is duplicated.
    ///
    /// Scope: the DB-backed confidence-gate pause ONLY. It does NOT touch
    /// the inline Human_Approval_Gate Redis/NATS signalling — those
    /// executions are `running`, not `waiting`, and are never targets of
    /// an approval-link token (tokens are minted from the pending /
    /// suspended approval set). Ownership is enforced by `user_id` (the
    /// value the token row bound at mint) on both the decision write and
    /// the resume claim.
    ///
    /// [`ApprovalDecisionOutcome::decision_recorded`] is `false` when no
    /// pending `execution_approvals` row was flipped — i.e. the execution
    /// was already decided or is not awaiting approval. Callers render an
    /// "already decided" page rather than an error in that case; nothing
    /// is resumed.
    pub async fn apply_waiting_approval_decision(
        &self,
        execution_id: Uuid,
        user_id: Uuid,
        approved: bool,
        reason: Option<&str>,
    ) -> Result<ApprovalDecisionOutcome, OrchestrationError> {
        // Ownership re-check (defense in depth — the token already bound
        // user_id at mint). Never differentiate "not yours" from
        // "doesn't exist" to the caller; the HTTP layer maps both to the
        // uniform invalid-link page.
        match self
            .execution_repo
            .get_workflow_execution_owner(execution_id)
            .await
            .map_err(OrchestrationError::Internal)?
        {
            Some(owner) if owner == user_id => {}
            _ => return Err(OrchestrationError::ExecutionNotFound(execution_id)),
        }

        // 1. Record the decision on the pending execution_approvals row.
        let status_val = if approved { "approved" } else { "denied" };
        let db_rows_updated = self
            .execution_repo
            .update_execution_approval_decision(execution_id, status_val, user_id, reason)
            .await
            .map_err(OrchestrationError::Internal)?;

        if db_rows_updated == 0 {
            // No pending approval → already decided / not waiting. Nothing
            // to resume; the decided-state is authoritative here.
            return Ok(ApprovalDecisionOutcome {
                decision_recorded: false,
                resumed: false,
            });
        }

        // 2. Resume the suspended execution so the gate re-evaluates and
        //    observes the decision (approved → proceed, denied → fail
        //    loudly). Fires for BOTH decisions.
        let resumed = matches!(
            self.resume_waiting_execution(execution_id, user_id, &[])
                .await?,
            WaitingResumeOutcome::Resumed
        );

        Ok(ApprovalDecisionOutcome {
            decision_recorded: true,
            resumed,
        })
    }
}

/// Result of [`ExecutionOrchestrationService::apply_waiting_approval_decision`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalDecisionOutcome {
    /// A pending `execution_approvals` row was flipped to the decision.
    /// `false` means the execution was already decided or not awaiting
    /// approval — callers render "already decided", not an error.
    pub decision_recorded: bool,
    /// The suspended execution was claimed and a resume dispatched. Only
    /// possible when `decision_recorded` is `true`.
    pub resumed: bool,
}
