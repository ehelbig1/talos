//! Replay an existing execution as a NEW execution row.
//!
//! Two flavours, both routed through `replay_common`:
//!
//!   * `replay` — re-runs with the original trigger_input verbatim.
//!   * `replay_with_input` — re-runs with caller-provided overrides
//!     deep-merged into the original trigger_input.
//!
//! Both create a fresh execution row whose `parent_execution_id`
//! points at the original — provenance chains stay walkable so the
//! execution-lineage tooling can attribute every replay back to the
//! root run. This is the fundamental difference from `retry`, which
//! resets the existing row in place and produces no new record.

use serde_json::Value;
use uuid::Uuid;

use talos_engine::builder::{for_workflow, EngineOpts};
use talos_engine::nats_run::run_with_trigger_input_via_nats;
use talos_execution_result_collector as result_collector;

use crate::deep_merge::deep_merge;
use crate::errors::OrchestrationError;
use crate::input::{ReplayInput, ReplayWithInputInput};
use crate::outcome::{ExecutionOutcome, ExecutionStatus, TriggerMetadata, TriggerType};
use crate::trigger::map_trigger_auth_error;
use crate::ExecutionOrchestrationService;

/// Hard cap on `input_overrides` size for `replay_with_input`. The
/// limit is per-call (not aggregate) and applies after JSON
/// serialisation. Above 1 MiB the WASM job-protocol payload starts
/// becoming a fuel sink in worker-side parsing.
const REPLAY_OVERRIDE_MAX_BYTES: usize = 1_000_000;

impl ExecutionOrchestrationService {
    /// Re-run a prior execution with its original `trigger_input`.
    pub async fn replay(&self, input: ReplayInput) -> Result<ExecutionOutcome, OrchestrationError> {
        self.replay_common(
            input.original_execution_id,
            input.user_id,
            input.replay_agent_id,
            None,
            TriggerType::Replay,
        )
        .await
    }

    /// Re-run a prior execution with caller-provided overrides
    /// deep-merged on top of the original `trigger_input`.
    pub async fn replay_with_input(
        &self,
        input: ReplayWithInputInput,
    ) -> Result<ExecutionOutcome, OrchestrationError> {
        // Size check before any DB work — cheapest rejection path.
        let serialised_len = serde_json::to_string(&input.input_overrides)
            .map(|s| s.len())
            .unwrap_or(0);
        if serialised_len > REPLAY_OVERRIDE_MAX_BYTES {
            return Err(OrchestrationError::InvalidArgument(format!(
                "input_overrides must be ≤ {} bytes when serialised (got {})",
                REPLAY_OVERRIDE_MAX_BYTES, serialised_len
            )));
        }

        self.replay_common(
            input.original_execution_id,
            input.user_id,
            input.replay_agent_id,
            Some(input.input_overrides),
            TriggerType::ReplayWithInput,
        )
        .await
    }

    /// Shared replay orchestration. The two public methods differ only
    /// in (a) override validation + merging and (b) the provenance
    /// `trigger_type` label; everything else is identical.
    async fn replay_common(
        &self,
        original_execution_id: Uuid,
        user_id: Uuid,
        // Caller-supplied override of which actor's budget to debit.
        // Currently unused at this layer because we inherit actor_id
        // from the parent execution row (matching historical
        // behaviour); kept on the public API so future callers can
        // pass an explicit actor without breaking compat.
        _replay_agent_id_override: Option<Uuid>,
        input_overrides: Option<Value>,
        trigger_type: TriggerType,
    ) -> Result<ExecutionOutcome, OrchestrationError> {
        // 1. Platform-level pause gate. Drains background dispatch
        // without ripping out the queue.
        let paused = self
            .execution_repo
            .is_execution_paused()
            .await
            .map_err(OrchestrationError::Internal)?;
        if paused {
            return Err(OrchestrationError::ExecutionPaused);
        }

        // 2. Load the original execution (single SQL with ownership
        // check baked in via user_id).
        let orig = self
            .execution_repo
            .get_execution(original_execution_id, user_id)
            .await
            .map_err(OrchestrationError::Internal)?
            .ok_or(OrchestrationError::ExecutionNotFound(original_execution_id))?;

        let workflow_id = orig.workflow_id;
        let inherited_actor_id = orig.actor_id;
        let output_data = orig.output_data;

        // 3. Workflow enabled check. is_workflow_enabled returns
        // Option<bool>: None means the workflow row is gone, false
        // means explicitly disabled. Both refuse the replay. Hoisted
        // above the auth gate so a deleted/disabled workflow short-
        // circuits before the (slightly more expensive) ceiling
        // re-verification work.
        let enabled = self
            .execution_repo
            .is_workflow_enabled(workflow_id)
            .await
            .map_err(OrchestrationError::Internal)?;
        match enabled {
            Some(true) => {}
            Some(false) => return Err(OrchestrationError::WorkflowDisabled(workflow_id)),
            None => return Err(OrchestrationError::WorkflowNotFound(workflow_id)),
        }

        // 4. Load the workflow graph (latest draft path; matches the
        // historical replay behaviour. Active-published-version
        // preference is intentional only for retry — replay starts
        // from the workflow's current canonical graph). Hoisted above
        // the auth gate so the ceiling re-verification has the graph
        // it needs.
        let graph_json = self
            .execution_repo
            .get_workflow_graph_for_user(workflow_id, user_id)
            .await
            .map_err(OrchestrationError::Internal)?
            .ok_or(OrchestrationError::WorkflowNotFound(workflow_id))?;

        // 5. Full trigger-time authorization gate. Subsumes the
        // budget check (`check_execution_allowed`) AND re-verifies
        // the capability-world ceiling against the CURRENT workflow
        // graph + the inherited actor's CURRENT
        // `max_capability_world`.
        //
        // MCP-707 (2026-05-13): pre-fix this path called only
        // `check_execution_allowed(actor_id)` — budget-only, no
        // ceiling re-verification. An operator who downgraded an
        // actor's ceiling from e.g. `agent-node` to `http-node`
        // would expect every subsequent dispatch surface to refuse
        // the higher-privilege modules; replay slipped through
        // because the ceiling gate only ran on the original trigger.
        // Same dispatch-path-authorization class as MCP-555 / -557 /
        // -564 / -565 / -651 / -652 / -672 (the prior sweep) — see
        // `dispatch_path_authorization_sweep.md`. The memory file
        // explicitly tags `authorize_workflow_trigger` as
        // "preferred — also re-verifies capability ceiling against
        // the stored graph" but retry+replay had settled for budget-
        // only; this closes the remaining gap.
        //
        // Inherits the original execution's actor — replay debits
        // the same budget as the original AND must respect the same
        // ceiling. `Unbound` (no actor) skips all three sub-checks,
        // matching pre-fix semantics for unbound executions.
        if let Err(e) = talos_workflow_authorization::authorize_workflow_trigger(
            &self.workflow_repo,
            &self.actor_repo,
            &self.db_pool,
            inherited_actor_id,
            user_id,
            &graph_json,
        )
        .await
        {
            return Err(map_trigger_auth_error(e));
        }

        // 6. Recover the original trigger input from the stored output
        // bundle, then optionally merge overrides on top.
        let mut trigger_input = result_collector::extract_trigger_input(output_data.as_ref());
        if let Some(overrides) = input_overrides {
            deep_merge(&mut trigger_input, &overrides);
        }

        // 7. Mint a new execution_id and create the row with parent
        // lineage + provenance metadata so the replay-chain tooling
        // can walk forward + backward from this run.
        let new_execution_id = Uuid::new_v4();
        let provenance = inherited_actor_id.map(|actor_id| {
            serde_json::json!({
                "actor_id": actor_id,
                "parent_execution_id": original_execution_id,
                "trigger_type": trigger_type.as_str(),
            })
        });
        self.execution_repo
            .create_replay_execution(
                new_execution_id,
                workflow_id,
                user_id,
                original_execution_id,
                inherited_actor_id,
                provenance.as_ref(),
            )
            .await
            .map_err(OrchestrationError::Internal)?;

        // 8. Engine build — synchronous so graph-load errors surface
        // to the caller rather than being silently buried in the
        // spawned task. On build failure we mark the new row as
        // failed so the user sees the error in get_execution_status.
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
            EngineOpts::for_run(workflow_id, graph_json.clone()),
        )
        .await
        {
            Ok(e) => e,
            Err(err) => {
                // MCP-563: DLP-scrub the engine error before persisting.
                // Parity with the in-spawn-task failure path below
                // (line ~267) and trigger.rs's spawn-task path — both
                // already redact. Without this, a graph-load failure
                // from a workflow whose JSON contains an upstream
                // API token (loaded into actor_context, leaked via
                // a deserialize error message) would land verbatim in
                // workflow_executions.error_message and be queryable
                // via get_execution_status.
                let redacted_err =
                    talos_dlp_provider::redact_str(&format!("Graph load failed: {}", err));
                if let Err(db_err) = self
                    .execution_repo
                    .mark_execution_failed(new_execution_id, &redacted_err, None)
                    .await
                {
                    tracing::error!(
                        execution_id = %new_execution_id,
                        err = %db_err,
                        "replay: failed to mark execution as failed after engine build error"
                    );
                }
                return Err(OrchestrationError::Internal(anyhow::anyhow!(
                    "engine build failed: {}",
                    err
                )));
            }
        };

        // 9. Spawn the dispatch + terminal-status update + (on
        // failure) failure-alert publish. Cloning the values the
        // task captures: repo, nats client (for alert publish),
        // shared key, trigger input.
        let repo_for_task = self.execution_repo.clone();
        let nats_for_alert = self.nats_client.clone();
        let worker_key = self.worker_shared_key.clone();
        let trigger_input_for_storage = trigger_input.clone();

        tokio::spawn(async move {
            match run_with_trigger_input_via_nats(
                &mut engine,
                nats,
                worker_key,
                trigger_input,
                new_execution_id,
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
                        new_execution_id,
                        wf_ctx.waiting,
                        &output_json,
                        "replay",
                    )
                    .await;
                }
                Err(e) => {
                    // MCP-447: DLP-redact once at the source so both
                    // sinks (DB row + alert pipeline) see the same
                    // redacted form. Same rationale as trigger.rs.
                    //
                    // MCP-1167 (2026-05-17): truncate-AT-SOURCE before
                    // redact (sibling to the trigger.rs/retry.rs fix
                    // in the same commit). Engine error unbounded;
                    // truncate-first bounds the regex pass at source.
                    let raw_err_full = e.to_string();
                    let raw_err: &str = if raw_err_full.len() > 4096 {
                        talos_text_util::truncate_at_char_boundary(&raw_err_full, 4096)
                    } else {
                        raw_err_full.as_str()
                    };
                    let redacted_err = talos_dlp_provider::redact_str(raw_err);
                    let fail_output =
                        result_collector::collect_failure_output(&trigger_input_for_storage);
                    if let Err(db_err) = repo_for_task
                        .mark_execution_failed(new_execution_id, &redacted_err, Some(&fail_output))
                        .await
                    {
                        tracing::error!(
                            execution_id = %new_execution_id,
                            err = %db_err,
                            "replay: failed to mark execution as failed"
                        );
                    }
                    result_collector::publish_execution_failure_alert(
                        &repo_for_task,
                        nats_for_alert.as_deref(),
                        user_id,
                        workflow_id,
                        new_execution_id,
                        &redacted_err,
                    )
                    .await;
                }
            }
        });

        Ok(ExecutionOutcome {
            execution_id: new_execution_id,
            status: ExecutionStatus::Running,
            metadata: TriggerMetadata {
                trigger_type,
                parent_execution_id: Some(original_execution_id),
                actor_id: inherited_actor_id,
                workflow_id,
            },
            trace: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn override_size_limit_constant_is_one_mib() {
        // Tripwire — bumping this past 1 MiB needs a worker fuel
        // budget review. The job-protocol envelope caps at 8 MiB
        // before NATS rejects, but worker parsing time scales with
        // payload size and 1 MiB is the historical safe ceiling.
        assert_eq!(REPLAY_OVERRIDE_MAX_BYTES, 1_000_000);
    }
}
