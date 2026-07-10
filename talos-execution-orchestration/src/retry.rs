//! In-place retry of a failed/cancelled execution.
//!
//! Behaviour matches the historical `handle_retry_execution` in
//! `talos-mcp-handlers/src/executions.rs`:
//!
//!   1. Load the execution row; refuse if not visible to the caller.
//!   2. Refuse if status is anything other than `failed` / `cancelled` —
//!      retrying a running or queued execution is meaningless and
//!      retrying a completed one would mask the success.
//!   3. Extract the original `trigger_input` from `output_data`
//!      (stored there by the result-collector at completion time).
//!   4. Reset the execution row to `running` IN PLACE — no new
//!      execution record. Provenance chain is unchanged. Callers who
//!      want a new linkable record use `replay` instead.
//!   5. Resolve the workflow graph: prefer the active published
//!      version, fall back to the draft graph.
//!   6. Build a fresh engine and spawn the dispatch in a background
//!      task so this method returns promptly. The spawned task is
//!      responsible for updating the execution row's terminal status
//!      after the run completes.

use talos_engine::builder::{for_workflow, EngineOpts};
use talos_engine::nats_run::run_with_trigger_input_via_nats;
use talos_execution_result_collector as result_collector;

use crate::errors::OrchestrationError;
use crate::input::RetryInput;
use crate::outcome::{ExecutionOutcome, ExecutionStatus, TriggerMetadata, TriggerType};
use crate::trigger::map_trigger_auth_error;
use crate::ExecutionOrchestrationService;

impl ExecutionOrchestrationService {
    /// Reset a failed/cancelled execution to `running` and re-dispatch.
    ///
    /// Returns immediately after enqueuing the background dispatch.
    /// The execution row's terminal status is updated by the spawned
    /// task once the run completes; callers poll
    /// `get_execution_status` to observe the result.
    pub async fn retry(&self, input: RetryInput) -> Result<ExecutionOutcome, OrchestrationError> {
        let RetryInput {
            execution_id,
            user_id,
        } = input;

        // 1. Load + ownership check (single SQL round-trip).
        let exec = self
            .execution_repo
            .get_execution(execution_id, user_id)
            .await
            .map_err(OrchestrationError::Internal)?
            .ok_or(OrchestrationError::ExecutionNotFound(execution_id))?;

        // 2. Status gate. The historical handler exposes the current
        // status in the error message — preserve that for parity.
        if exec.status != "failed" && exec.status != "cancelled" {
            return Err(OrchestrationError::StatusConflict(format!(
                "can only retry failed or cancelled executions (current status: {})",
                exec.status
            )));
        }

        let workflow_id = exec.workflow_id;
        let actor_id = exec.actor_id;
        let trigger_input = result_collector::extract_trigger_input(exec.output_data.as_ref());

        // 2.5. Load the graph: prefer the active published version,
        // fall back to the draft. Both lookups can return None — that
        // means the workflow row was deleted or rotated out of view
        // since the original execution was created.
        //
        // MCP-707 (2026-05-13): hoisted ABOVE the auth gate +
        // `mark_execution_running` so the ceiling re-verification has
        // the graph it needs. Pre-fix this load ran AFTER mark — we'd
        // have to UNDO the mark on auth failure, which is fragile.
        // Loading early costs nothing on the happy path and moves the
        // cheap fail (deleted workflow) ahead of the expensive admission.
        let graph_json = match self
            .execution_repo
            .get_active_version_graph(workflow_id, user_id)
            .await
            .map_err(OrchestrationError::Internal)?
        {
            Some((_, graph)) => graph,
            None => self
                .execution_repo
                .get_workflow_graph_for_user(workflow_id, user_id)
                .await
                .map_err(OrchestrationError::Internal)?
                .ok_or(OrchestrationError::WorkflowNotFound(workflow_id))?,
        };

        // 2.6. Full trigger-time authorization gate. Subsumes the
        // MCP-557 actor-budget gate AND re-verifies the capability-
        // world ceiling against the resolved graph + the inherited
        // actor's CURRENT `max_capability_world`.
        //
        // MCP-707 (2026-05-13): pre-fix this path called only
        // `check_execution_allowed(actor_id)` (the MCP-557 budget
        // gate). An operator who downgraded an actor's ceiling from
        // e.g. `agent-node` to `http-node` would expect retry to
        // refuse the higher-privilege modules; the pre-fix path slipped
        // through because the ceiling gate only ran on the original
        // trigger. The dispatch-path-authorization sweep memory
        // explicitly tags `authorize_workflow_trigger` as
        // "preferred — also re-verifies capability ceiling against the
        // stored graph" but retry+replay had settled for budget-only;
        // this closes the remaining gap. Sibling fixes in this commit
        // cover the replay path (same shape).
        //
        // A retry resets `started_at = NOW()` via
        // `mark_execution_running` below, so the retried row enters
        // the rolling 1-hour window — the budget check stays
        // necessary.
        //
        // Phase D2 (PR #461 follow-up): CAPTURE the gate-resolved actor
        // instead of discarding it. Pre-fix this path ran the gate,
        // threw the answer away, and built the engine from a bare
        // `EngineOpts::for_run` — so EVERY retry (including of a
        // Tier-2-actor workflow) ran actorless at the engine's Tier-1
        // fail-safe: external-LLM nodes that succeeded on the original
        // run failed on retry (keys filtered, hosts denied) and
        // `__memory_write__` envelopes were silently dropped, while the
        // row was stamped with the inherited actor.
        let effective_actor = match talos_workflow_authorization::resolve_effective_actor(
            &self.workflow_repo,
            &self.actor_repo,
            &self.db_pool,
            actor_id,
            user_id,
            &graph_json,
        )
        .await
        {
            Ok(resolved) => resolved,
            Err(e) => return Err(map_trigger_auth_error(e)),
        };

        // 3. In-place reset to running BEFORE the engine build so that
        // status is consistent for any concurrent observer; if the
        // engine build fails below we mark it failed again with the
        // build error.
        //
        // MCP-693 (2026-05-13): the repo helper now precondition-checks
        // `status IN ('failed', 'cancelled')` atomically. If two
        // parallel retries land for the same execution_id, the first
        // wins (rows_affected = 1) and the second sees `false` —
        // abort with StatusConflict so the second retry doesn't spawn
        // a duplicate engine racing against the first.
        let admitted = self
            .execution_repo
            .mark_execution_running(execution_id)
            .await
            .map_err(OrchestrationError::Internal)?;
        if !admitted {
            return Err(OrchestrationError::StatusConflict(format!(
                "execution {} was already retried (concurrent caller won the transition); \
                 poll get_execution_status to observe the in-flight retry",
                execution_id
            )));
        }

        // 5. Engine build. Build before spawning so we surface graph-
        // load errors synchronously to the caller; only the dispatch
        // itself goes async.
        let nats = self
            .nats_client
            .as_ref()
            .ok_or_else(|| {
                OrchestrationError::DispatchFailed("NATS client not available".to_string())
            })?
            .clone();

        let mut engine = match for_workflow(
            self.registry.clone(),
            self.secrets_manager.clone(),
            self.actor_repo.clone(),
            user_id,
            EngineOpts::for_run(workflow_id, graph_json.clone())
                .with_effective_actor(effective_actor, None),
        )
        .await
        {
            Ok(e) => e,
            Err(err) => {
                // Engine build failed — re-mark execution as failed
                // with the build error so the row reflects reality.
                // Best-effort: if the mark fails too, log but return
                // the original engine error.
                if let Err(db_err) = self
                    .execution_repo
                    .mark_execution_failed(execution_id, "Graph load failed", None)
                    .await
                {
                    tracing::error!(
                        execution_id = %execution_id,
                        err = %db_err,
                        "retry: failed to mark execution as failed after engine build error"
                    );
                }
                return Err(OrchestrationError::Internal(anyhow::anyhow!(
                    "engine build failed: {}",
                    err
                )));
            }
        };

        // 6. Spawn the dispatch. The spawned task owns the engine and
        // handles terminal-status updates.
        let repo_for_task = self.execution_repo.clone();
        let worker_key = self.worker_shared_key.clone();
        let trigger_input_for_storage = trigger_input.clone();
        tokio::spawn(async move {
            match run_with_trigger_input_via_nats(
                &mut engine,
                nats,
                worker_key,
                trigger_input,
                execution_id,
            )
            .await
            {
                Ok(wf_ctx) => {
                    let output_json = result_collector::collect_success_output(
                        &engine,
                        &wf_ctx,
                        &trigger_input_for_storage,
                    );
                    // Honor `wf_ctx.waiting` — see finalize.rs.
                    crate::finalize::finalize_engine_success(
                        repo_for_task.as_ref(),
                        execution_id,
                        wf_ctx.waiting,
                        &output_json,
                        "retry",
                    )
                    .await;
                }
                Err(e) => {
                    // MCP-447: DLP-redact the engine error before
                    // persisting. Same rationale as trigger.rs:
                    // upstream API failures carry tokens that must not
                    // land in workflow_executions.error_message.
                    //
                    // MCP-1167 (2026-05-17): truncate-AT-SOURCE before
                    // redact (sibling to the trigger.rs fix in the
                    // same commit). The engine error `e.to_string()` is
                    // unbounded; truncate-first bounds the regex pass
                    // cost at the source. 4 KiB matches the
                    // mark_execution_failed inner cap (MCP-1161).
                    let raw_err_full = e.to_string();
                    let raw_err: &str = if raw_err_full.len() > 4096 {
                        talos_text_util::truncate_at_char_boundary(&raw_err_full, 4096)
                    } else {
                        raw_err_full.as_str()
                    };
                    let redacted_err = talos_dlp_provider::redact_str(raw_err);
                    if let Err(db_err) = repo_for_task
                        .mark_execution_failed(
                            execution_id,
                            &format!("Retry failed: {}", redacted_err),
                            None,
                        )
                        .await
                    {
                        tracing::error!(
                            execution_id = %execution_id,
                            err = %db_err,
                            "retry: failed to mark execution as failed"
                        );
                    }
                }
            }
        });

        Ok(ExecutionOutcome {
            execution_id,
            status: ExecutionStatus::Running,
            metadata: TriggerMetadata {
                trigger_type: TriggerType::Retry,
                parent_execution_id: None,
                actor_id,
                workflow_id,
            },
            trace: None,
        })
    }
}
