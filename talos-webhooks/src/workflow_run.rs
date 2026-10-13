//! What the webhook router does with a workflow run once it has an engine:
//! the output it stores, and how a run that returned is recorded.
//!
//! Until 2026-10-13 the router's row was created `queued` and never claimed
//! as `running`. The success finalizers take only a `running` (or
//! `resuming`) row, so a webhook run that SUCCEEDED was never recorded as
//! completed: the row stayed `queued`. In the default, asynchronous mode the
//! router did not finalize at all; its spawned task logged a failure and
//! wrote nothing. A failed run was recorded only in the synchronous mode.
//!
//! The router now claims the row before the run, and both modes record the
//! outcome here.

use serde_json::Value as JsonValue;
use sqlx::PgPool;
use talos_workflow_engine::{ParallelWorkflowEngine, WorkflowEngineError};
use talos_workflow_engine_core::WorkflowContext;
use talos_workflow_repository::WorkflowRepository;
use uuid::Uuid;

/// A finished run's node outputs, keyed by label, without the synthetic
/// trigger seed and without skipped nodes. NOT redacted: the synchronous
/// mode returns this to the caller that sent the request and owns the data;
/// what is stored is [`talos_dlp_provider::redact_json`] of it.
#[must_use]
pub(crate) fn run_output(engine: &ParallelWorkflowEngine, ctx: &WorkflowContext) -> JsonValue {
    let node_labels = engine.node_labels();
    let mut output = serde_json::Map::new();
    for (nid, result) in &ctx.results {
        let key = node_labels
            .get(nid)
            .cloned()
            .unwrap_or_else(|| nid.to_string());
        if key == "__trigger__" {
            continue;
        }
        if result
            .get("__skipped")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            continue;
        }
        output.insert(key, ParallelWorkflowEngine::unwrap_output(result).clone());
    }
    JsonValue::Object(output)
}

/// How an asynchronous webhook run that has returned is recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsyncRunRecord {
    /// The run finished; the row is `completed`.
    Completed,
    /// The run paused (an approval, a wait node); the row is `waiting`.
    Waiting,
    /// The run failed; the row is `failed`, with its error and the outputs
    /// of the nodes that completed.
    Failed,
    /// An operator cancelled the execution: the row is already `cancelled`
    /// and nothing is written.
    LeftCancelled,
    /// Another controller reclaimed the row (the fence fired): it belongs to
    /// that controller now and nothing is written.
    LeftToNewOwner,
}

/// Which record a returned run gets. Pure, so the rule is tested without a
/// database: a cancelled or superseded run must never be marked failed.
#[must_use]
pub(crate) fn classify_async_run(
    run: &Result<WorkflowContext, WorkflowEngineError>,
) -> AsyncRunRecord {
    match run {
        Ok(ctx) if ctx.waiting => AsyncRunRecord::Waiting,
        Ok(_) => AsyncRunRecord::Completed,
        Err(e) if talos_engine::fence::was_cancelled_by_operator(e) => {
            AsyncRunRecord::LeftCancelled
        }
        Err(e) if talos_engine::fence::was_fenced(e) => AsyncRunRecord::LeftToNewOwner,
        Err(_) => AsyncRunRecord::Failed,
    }
}

/// Record an asynchronous webhook run that has returned.
///
/// * Finished or paused: the DLP-redacted output is stored through the
///   encryption-aware repository, as the synchronous mode stores it.
/// * Failed: the error is DLP-redacted and written by the dispatcher's own
///   failure statement (which never clobbers a terminal row), and then the
///   outputs of the nodes that completed are attached.
/// * Cancelled by an operator, or superseded by another controller: nothing
///   is written. The row is already `cancelled`, or is someone else's.
///
/// Every write is logged when it fails and never propagated: this runs in a
/// detached task after the HTTP response has gone.
pub async fn record_async_run(
    engine: &ParallelWorkflowEngine,
    wf_repo: &WorkflowRepository,
    db_pool: &PgPool,
    execution_id: Uuid,
    workflow_id: Uuid,
    run: Result<WorkflowContext, WorkflowEngineError>,
) -> AsyncRunRecord {
    let record = classify_async_run(&run);
    match (record, run) {
        (AsyncRunRecord::Completed | AsyncRunRecord::Waiting, Ok(ctx)) => {
            let stored = talos_dlp_provider::redact_json(&run_output(engine, &ctx));
            let written = if record == AsyncRunRecord::Waiting {
                wf_repo.mark_execution_waiting(execution_id, &stored).await
            } else {
                wf_repo
                    .mark_execution_completed(execution_id, &stored)
                    .await
            };
            if let Err(e) = written {
                tracing::error!(
                    %execution_id,
                    %workflow_id,
                    error = %e,
                    "Failed to record an async webhook run's outcome; the row keeps its \
                     non-terminal status until the stale-execution sweeper finalizes it"
                );
            }
        }
        (AsyncRunRecord::Failed, Err(e)) => {
            // The same redaction as the synchronous mode: an engine error
            // regularly wraps an upstream body.
            let err_msg = talos_dlp_provider::redact_str(&format!("{e:?}"));
            tracing::error!(
                %execution_id,
                %workflow_id,
                error = %err_msg,
                "Workflow execution failed (async)"
            );
            if let Err(db_err) = talos_workflow_repository::fail_workflow_execution_unless_terminal(
                db_pool,
                execution_id,
                &err_msg,
            )
            .await
            {
                tracing::warn!(
                    target: "talos_rpc",
                    %execution_id,
                    error = %db_err,
                    "Failed to mark an async webhook execution failed — the row keeps its \
                     non-terminal status"
                );
            }
            talos_execution_result_collector::keep_failed_run_outputs(
                engine,
                execution_id,
                |outputs| async move {
                    wf_repo
                        .attach_failed_run_outputs(execution_id, &outputs)
                        .await
                },
            )
            .await;
        }
        (AsyncRunRecord::LeftCancelled, _) => tracing::info!(
            %execution_id,
            "async webhook run stopped — the execution was cancelled by an operator"
        ),
        (AsyncRunRecord::LeftToNewOwner, _) => tracing::warn!(
            %execution_id,
            "async webhook run fenced — superseded by a crash-recovery reclaim; \
             leaving the row to its new owner"
        ),
        // `classify_async_run` pairs each record with its `Ok` / `Err`.
        (AsyncRunRecord::Completed | AsyncRunRecord::Waiting, Err(_))
        | (AsyncRunRecord::Failed, Ok(_)) => {}
    }
    record
}

#[cfg(test)]
mod tests {
    use super::{classify_async_run, AsyncRunRecord};
    use talos_workflow_engine::WorkflowEngineError;
    use talos_workflow_engine_core::WorkflowContext;

    /// A run an operator cancelled, and a run another controller took over,
    /// are not failures. Marking either `failed` would overwrite a
    /// `cancelled` row's meaning or clobber the new owner's row.
    #[test]
    fn a_cancelled_or_superseded_run_is_left_alone_and_only_a_real_error_is_a_failure() {
        let waiting = WorkflowContext {
            waiting: true,
            ..Default::default()
        };
        assert_eq!(
            classify_async_run(&Ok(WorkflowContext::default())),
            AsyncRunRecord::Completed
        );
        assert_eq!(classify_async_run(&Ok(waiting)), AsyncRunRecord::Waiting);
        assert_eq!(
            classify_async_run(&Err(WorkflowEngineError::CancelledByOperator)),
            AsyncRunRecord::LeftCancelled
        );
        assert_eq!(
            classify_async_run(&Err(WorkflowEngineError::Cancelled)),
            AsyncRunRecord::LeftToNewOwner
        );
        assert_eq!(
            classify_async_run(&Err(WorkflowEngineError::execution(
                "node 'send' failed: refused"
            ))),
            AsyncRunRecord::Failed
        );
    }

    /// The router is not driven here (its run needs NATS), so the three
    /// things it must do are held as written, in order: claim the queued row
    /// as running BEFORE either mode runs the engine; run the asynchronous
    /// mode under the fence; and record that run when it returns. Each was
    /// missing, and a webhook run that succeeded was never recorded.
    #[test]
    fn the_router_claims_its_row_before_the_run_and_records_the_async_run() {
        let router = include_str!("router.rs");
        let claim = router
            .find(".mark_execution_running_from_queued(execution_id)")
            .expect("the router claims its queued row");
        let modes = router
            .find("if auto_respond {\n            // Synchronous mode")
            .expect("the two modes");
        assert!(claim < modes, "the row is claimed after a mode has started");
        let async_mode = &router[router
            .find("// Async mode: spawn the engine")
            .expect("the asynchronous mode")..];
        let fenced = async_mode
            .find("run_with_trigger_input_fenced_at_row_epoch(")
            .expect("the asynchronous run is fenced");
        let recorded = async_mode
            .find("workflow_run::record_async_run(")
            .expect("the asynchronous run is recorded");
        assert!(fenced < recorded);
        // And neither mode runs the engine anywhere else in the file but the
        // synchronous arm's one inline call.
        assert_eq!(
            router
                .matches("nats_run::run_with_trigger_input_via_nats(")
                .count(),
            1,
            "a workflow run was added to the router outside the two recorded modes"
        );
    }
}
