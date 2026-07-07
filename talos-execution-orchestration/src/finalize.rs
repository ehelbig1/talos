//! Success-path finalization for engine runs — the `ctx.waiting` branch.
//!
//! Regression fixed 2026-07-07 (found by live testing): the r295 service
//! extraction carried over `mark_execution_completed` for every `Ok(wf_ctx)`
//! but dropped the `wf_ctx.waiting` branch the pre-extraction handler had.
//! A confidence-gate/wait-node pause therefore FINALIZED the execution as
//! `completed` on the canonical trigger path (and retry/replay): the engine
//! correctly created the pending approval request and returned
//! `waiting: true`, but the row went terminal, the "finished successfully"
//! event fired, and the later approval had nothing to resume. The
//! crash-recovery path, the scheduler, the GraphQL mutations, and the MCP
//! draft handler all kept the branch — only this crate's three success
//! finalizers lost it.
//!
//! One helper, three call sites (trigger / retry / replay), so the branch
//! can't drift apart again.

use serde_json::Value as JsonValue;
use uuid::Uuid;

/// How the engine run ended, from the finalizer's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SuccessKind {
    /// Terminal: every node ran to completion.
    Completed,
    /// NOT terminal: the engine yielded on a wait/approval pause
    /// (`WorkflowContext::waiting`). The execution row must stay
    /// resumable (`status = 'waiting'`) and no terminal side effects
    /// (completed event, scratchpad trace, completion webhooks) may fire.
    Waiting,
}

/// The two finalize writes, abstracted over the repository: the trigger
/// path holds a `WorkflowRepository`, retry/replay hold an
/// `ExecutionRepository` — both expose the identical guarded UPDATEs.
pub(crate) trait FinalizeRepo {
    fn mark_waiting(
        &self,
        execution_id: Uuid,
        output: &JsonValue,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    fn mark_completed(
        &self,
        execution_id: Uuid,
        output: &JsonValue,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
}

impl FinalizeRepo for talos_workflow_repository::WorkflowRepository {
    async fn mark_waiting(&self, execution_id: Uuid, output: &JsonValue) -> anyhow::Result<()> {
        self.mark_execution_waiting(execution_id, output).await
    }
    async fn mark_completed(&self, execution_id: Uuid, output: &JsonValue) -> anyhow::Result<()> {
        self.mark_execution_completed(execution_id, output).await
    }
}

impl FinalizeRepo for talos_execution_repository::ExecutionRepository {
    async fn mark_waiting(&self, execution_id: Uuid, output: &JsonValue) -> anyhow::Result<()> {
        self.mark_execution_waiting(execution_id, output).await
    }
    async fn mark_completed(&self, execution_id: Uuid, output: &JsonValue) -> anyhow::Result<()> {
        self.mark_execution_completed(execution_id, output).await
    }
}

/// Persist the success outcome of an engine run, honoring `ctx.waiting`.
///
/// Returns the [`SuccessKind`] so the caller can gate its own
/// path-specific side effects (terminal events, trace capture) on it.
pub(crate) async fn finalize_engine_success(
    repo: &impl FinalizeRepo,
    execution_id: Uuid,
    ctx_waiting: bool,
    output_json: &JsonValue,
    path: &'static str,
) -> SuccessKind {
    if ctx_waiting {
        if let Err(e) = repo.mark_waiting(execution_id, output_json).await {
            tracing::error!(
                execution_id = %execution_id,
                err = %e,
                path,
                "failed to mark execution as waiting — row may stay 'running' and \
                 the pending approval will have nothing to resume"
            );
        } else {
            tracing::info!(
                execution_id = %execution_id,
                path,
                "execution paused (waiting) — awaiting external resume/approval"
            );
        }
        SuccessKind::Waiting
    } else {
        if let Err(e) = repo.mark_completed(execution_id, output_json).await {
            tracing::error!(
                execution_id = %execution_id,
                err = %e,
                path,
                "failed to mark execution as completed"
            );
        }
        SuccessKind::Completed
    }
}
