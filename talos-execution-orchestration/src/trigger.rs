//! Workflow trigger orchestration.
//!
//! Mirrors `handle_trigger_workflow` in
//! `talos-mcp-handlers/src/workflows.rs` (~493 lines pre-extraction).
//! The orchestration covers a long checklist:
//!
//!   1. Platform-pause gate.
//!   2. Workflow load + ownership + enabled check.
//!   3. Active-version graph load.
//!   4. Per-workflow concurrency limit.
//!   5. Authorization (capability ceiling, actor budget, graph ownership).
//!   6. Input schema validation, including dry-run mode that returns
//!      structured schema + errors without dispatching.
//!   7. Input size cap (1 MiB serialised).
//!   8. Optional actor-context injection (memory + scratchpad lifted
//!      into `__actor_context__`).
//!   9. Trigger-type allowlist resolution.
//!  10. Parent + root execution lineage resolution.
//!  11. Execution row creation with full lineage.
//!  12. Reuse-event analytics ping.
//!  13. Audit log on the owning actor.
//!  14. Unbound-actor warning if the graph has memory-write nodes
//!      but no actor is bound.
//!  15. Engine build with effective-actor + actor-context + dry-run.
//!  16. Spawned dispatch (semaphore-bounded) with terminal-status
//!      update + scratchpad trace + failure-alert + failure-webhook.
//!  17. Optional sync-wait via `wait_for_terminal_status`; the trace
//!      JSON itself is rendered by the caller (kept out of this
//!      crate to avoid a `talos-mcp-handlers`-shaped dep cycle).

use std::sync::OnceLock;

use tokio::sync::Semaphore;
use uuid::Uuid;

use talos_engine::builder::{for_workflow, BuildError, EngineOpts};
use talos_engine::nats_run::run_with_trigger_input_via_nats;
use talos_engine::user_errors::render_graph_load_error;
use talos_execution_result_collector as result_collector;

use crate::count_memory_write_nodes::count_memory_write_nodes;
use crate::errors::OrchestrationError;
use crate::failure_webhook::dispatch_failure_webhook;
use crate::input::TriggerInput;
use crate::outcome::{
    DryRunResult, ExecutionOutcome, ExecutionStatus, TriggerMetadata, TriggerOutcome, TriggerType,
};
use crate::ExecutionOrchestrationService;

/// Hard cap on the trigger input payload size (post-serialisation).
/// Mirrors the 1 MiB ceiling on replay overrides — same worker fuel
/// reasoning applies.
const TRIGGER_INPUT_MAX_BYTES: usize = 1_000_000;

/// Maximum sync-wait window the caller can request. The repository
/// helper enforces this internally too; the local cap is
/// belt-and-braces and surfaces the value in the public contract.
const SYNC_WAIT_MAX_MS: u64 = 30_000;

/// Per-actor scratchpad memory for the captured node-output trace.
/// Every dispatched execution that has an actor binding writes one
/// row at completion under this key prefix. Used by Phase 5.2
/// reasoning-trace tooling.
fn scratchpad_trace_key(execution_id: Uuid) -> String {
    format!("execution/{}/trace", execution_id)
}

/// Map `TriggerAuthError` variants to the matching `OrchestrationError`.
/// `TriggerAuthError` doesn't implement `Display` (it carries
/// structured fields a string couldn't fully convey for the
/// capability-ceiling case), so we enumerate the variants explicitly.
/// Messages match the historical `trigger_auth_error_to_response` in
/// `talos-mcp-handlers/src/utils.rs` so callers see byte-identical
/// user-facing text.
///
/// MCP-707 (2026-05-13): promoted from `fn` to `pub(crate) fn` so
/// `replay.rs` and `retry.rs` can route their newly-added
/// `authorize_workflow_trigger` calls through the same mapping. All
/// three dispatch surfaces (trigger / replay / retry) now share one
/// canonical user-facing string for each `TriggerAuthError` variant —
/// future tweaks to the rejection messages happen here once.
pub(crate) fn map_trigger_auth_error(
    err: talos_workflow_authorization::TriggerAuthError,
) -> OrchestrationError {
    use talos_workflow_authorization::TriggerAuthError;
    match err {
        TriggerAuthError::ActorArchived => OrchestrationError::AuthorizationDenied(
            "Actor is archived — this is an IRREVERSIBLE terminal state. \
             Archived actors cannot dispatch executions. Create a new actor instead."
                .to_string(),
        ),
        TriggerAuthError::ActorTerminated => OrchestrationError::AuthorizationDenied(
            "Actor is terminated — this is an IRREVERSIBLE terminal state. \
             Terminated actors cannot dispatch executions. Create a new actor instead."
                .to_string(),
        ),
        TriggerAuthError::ActorNotFoundOrInactive => {
            OrchestrationError::AuthorizationDenied("Actor not found or access denied".to_string())
        }
        TriggerAuthError::ExecutionDenied(msg) => OrchestrationError::AuthorizationDenied(msg),
        TriggerAuthError::CapabilityCeilingViolation {
            module_id,
            module_world,
            max_world,
            req_rank,
            max_rank,
        } => OrchestrationError::AuthorizationDenied(format!(
            "Capability ceiling violation: workflow node {} uses '{}' world (rank {}) \
             which exceeds this agent's ceiling '{}' (rank {}). \
             Remove the node or ask an operator to raise the ceiling.",
            module_id, module_world, req_rank, max_world, max_rank
        )),
        TriggerAuthError::Database(err) => OrchestrationError::Internal(err),
    }
}

/// Process-wide semaphore for spawned dispatch tasks. Capacity comes
/// from `TALOS_MAX_CONCURRENT_EXECUTIONS` (default 3), matching the
/// pre-extraction handler. The OnceLock pattern means the env var is
/// read once at first dispatch.
///
/// MCP-638 (2026-05-13): clamp the configured value to ≥ 1. Pre-fix
/// `TALOS_MAX_CONCURRENT_EXECUTIONS=0` parsed successfully to `usize 0`
/// and `Semaphore::new(0)` never admits an `acquire().await` — every
/// spawned dispatch task blocks forever. The trigger caller already
/// returned `Ok(TriggerOutcome::Dispatched(...))` so the execution
/// row stays in `running` indefinitely with no engine work happening.
/// Operator sees zombie rows accumulate and no obvious cause. An
/// operator who wants "no concurrency" actually wants `=1` (serial
/// dispatch); the `=0` shape has no legitimate meaning, so clamp it
/// up rather than letting the deadlock land. WARN on the clamp so
/// the misconfiguration surfaces in the log.
fn exec_semaphore() -> &'static Semaphore {
    static SEMAPHORE: OnceLock<Semaphore> = OnceLock::new();
    SEMAPHORE.get_or_init(|| {
        let raw = std::env::var("TALOS_MAX_CONCURRENT_EXECUTIONS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(3);
        let max = if raw == 0 {
            tracing::warn!(
                target: "talos_execution_orchestration",
                event_kind = "exec_semaphore_zero_clamped",
                configured = raw,
                clamped_to = 1,
                "TALOS_MAX_CONCURRENT_EXECUTIONS=0 would deadlock every \
                 dispatch (Semaphore::new(0) never admits). Clamping to 1 \
                 (serial dispatch). Set =1 explicitly to silence this warning."
            );
            1
        } else {
            raw
        };
        Semaphore::new(max)
    })
}

impl ExecutionOrchestrationService {
    /// Trigger a workflow execution.
    ///
    /// Returns `TriggerOutcome::Dispatched(_)` on success; the embedded
    /// `ExecutionOutcome` reports the final status, which is normally
    /// `Running` (sync-wait disabled) or whatever terminal status the
    /// row reached when sync-wait succeeded. The trace itself is the
    /// caller's responsibility to render — keeps protocol shape out
    /// of this crate.
    ///
    /// Returns `TriggerOutcome::DryRun(_)` when the caller passed
    /// `dry_run = true` AND the workflow has an input_schema; the
    /// service performs validation and reports schema + errors
    /// without dispatching. `dry_run = true` on a workflow with no
    /// schema returns `DryRun` with `schema = None` and empty errors,
    /// matching the pre-extraction "operator hint" behaviour.
    #[allow(clippy::too_many_lines)]
    pub async fn trigger(&self, input: TriggerInput) -> Result<TriggerOutcome, OrchestrationError> {
        let TriggerInput {
            workflow_id,
            user_id,
            trigger_input: input_payload_arg,
            trigger_agent_id,
            inject_memory_context,
            dry_run,
            wait_ms,
        } = input;

        // 1. Platform-level pause gate.
        if self
            .workflow_repo
            .is_execution_paused()
            .await
            .map_err(OrchestrationError::Internal)?
        {
            return Err(OrchestrationError::ExecutionPaused);
        }

        // 2. Workflow load + ownership + is_enabled.
        let wf_record = self
            .workflow_repo
            .get_workflow(workflow_id, user_id)
            .await
            .map_err(OrchestrationError::Internal)?
            .ok_or(OrchestrationError::WorkflowNotFound(workflow_id))?;
        if !wf_record.is_enabled {
            return Err(OrchestrationError::WorkflowDisabled(workflow_id));
        }

        // 3. Active-version graph load.
        let (graph_json, version_id) = self
            .workflow_repo
            .get_active_version_graph(workflow_id, user_id)
            .await
            .map_err(OrchestrationError::Internal)?
            .ok_or(OrchestrationError::WorkflowNotFound(workflow_id))?;

        // 4. Authorization (capability ceiling + actor budget + graph
        // ownership). This is the canonical gate; mirroring
        // `authorize_workflow_creator` for the create-time path.
        //
        // Note: order swapped vs. the pre-r296 inline handler. The
        // concurrency-limit check moved DOWN to the row-creation step
        // (now atomic with the INSERT in
        // `create_execution_under_concurrency_limit`); we still want
        // authorization to fail fast before any further DB work, so
        // it's promoted here.
        // Phase D2: resolve the effective actor ONCE — the gate returns it, and
        // we stamp the execution row + build the engine with the SAME value so
        // authorization, attribution, and runtime tier can't diverge. We pass
        // the explicit-or-workflow actor in; the gate (Phase D1) falls back to
        // the user's default actor when both are None, so this is never None on
        // success.
        let effective_actor: Option<Uuid> =
            match talos_workflow_authorization::resolve_effective_actor(
                &self.workflow_repo,
                &self.actor_repo,
                &self.db_pool,
                trigger_agent_id.or(wf_record.actor_id),
                user_id,
                &graph_json,
            )
            .await
            {
                Ok(resolved) => resolved,
                Err(e) => return Err(map_trigger_auth_error(e)),
            };

        // 6. Input schema validation. The validation service handles
        // dry-run vs. dispatch-mode internally; we surface the four
        // possible outcomes as typed paths.
        let validation = talos_workflow_validation::WorkflowValidationService::check_trigger_input(
            &self.workflow_repo,
            workflow_id,
            user_id,
            &input_payload_arg,
            dry_run,
        )
        .await;
        match validation {
            talos_workflow_validation::InputSchemaCheck::NoSchema
            | talos_workflow_validation::InputSchemaCheck::Valid => {}
            talos_workflow_validation::InputSchemaCheck::Invalid(errors) => {
                return Err(OrchestrationError::ValidationFailed(errors.join("; ")));
            }
            talos_workflow_validation::InputSchemaCheck::DryRun { schema, errors } => {
                return Ok(TriggerOutcome::DryRun(DryRunResult {
                    workflow_id,
                    schema,
                    errors,
                }));
            }
        }

        // 7. Input size cap. The replay path enforces the same limit;
        // both gates serve to keep the worker job-protocol envelope
        // under wire-format budgets.
        let serialised_len = serde_json::to_string(&input_payload_arg)
            .map(|s| s.len())
            .unwrap_or(0);
        if serialised_len > TRIGGER_INPUT_MAX_BYTES {
            return Err(OrchestrationError::InvalidArgument(format!(
                "input payload must be ≤ {} bytes when serialised (got {})",
                TRIGGER_INPUT_MAX_BYTES, serialised_len
            )));
        }

        // Mint the execution id EARLY (before step 8) so actor-context
        // injection can stamp memory-rank provenance rows with it. This is
        // just UUID generation — the execution row INSERT stays at step 11
        // and reuses this same id. Flag-off, the only observable effect is
        // that the id exists a few lines sooner (inert).
        let execution_id = Uuid::new_v4();

        // 8. Actor-context injection — GROUNDING BY DEFAULT (Tier 2). Memory is
        // injected into `__actor_context__` when the workflow is ACTOR-BOUND
        // (`wf_record.actor_id`, the binding — NOT the effective/default actor,
        // whose shared pool would cross-contaminate; this matches the scheduler),
        // UNLESS the workflow opts out via a top-level `inject_memory: false` in
        // graph_json — OR when the caller explicitly passed
        // `inject_memory_context=true`.
        //
        // SECURITY: a DEFAULTED injection uses the CURATED scope (durable
        // semantic+episodic only) so transient `working` memory never lands in
        // an execution trace by default; an EXPLICIT caller opt-in gets the FULL
        // scope (the trigger tool docs warn that working memory can carry
        // sensitive values). Tenancy: `wf_record.actor_id` is the workflow's own
        // actor (workflow loaded WHERE user_id = caller; actor bound only after
        // ownership validation), and recall is single-actor — no cross-tenant path.
        let mut input_payload = input_payload_arg;
        let max_memories = 10; // Historical default — keep in lockstep with the inline handler.

        // Parse graph_json ONCE here (reused for `priority` at step 11). Large
        // graphs make a double-parse wasteful.
        let graph_val = serde_json::from_str::<serde_json::Value>(&graph_json).ok();
        let opted_out = graph_val
            .as_ref()
            .and_then(|v| v.get("inject_memory"))
            .and_then(|b| b.as_bool())
            == Some(false);
        let explicit = inject_memory_context;
        // PERF (A1a): the default actor-bound injection assembles the full
        // per-actor memory view (graph-RAG + several DB round-trips) at trigger
        // time. Skip that assembly when the graph has NO node that could consume
        // `__actor_context__` — i.e. EVERY node explicitly set
        // `needs_memory: false`. Conservative and cheap (walks the
        // already-parsed `graph_val`, no module lookups): any node without an
        // explicit `false` is treated as a potential consumer, so we only skip
        // when the whole graph opted out. An EXPLICIT caller opt-in always
        // assembles (the caller asked for it). NOTE: this only flips
        // `should_inject` to false — `inject_actor_context_into_input` still runs
        // and performs its unconditional reserved-key strip (the A2 spoof
        // guard); it just returns before the expensive assembly.
        let graph_may_consume_memory = |graph: Option<&serde_json::Value>| -> bool {
            let Some(nodes) = graph
                .and_then(|g| g.get("nodes"))
                .and_then(|n| n.as_array())
            else {
                return true; // unparseable / unknown shape → assemble (conservative)
            };
            if nodes.is_empty() {
                return true;
            }
            // May consume unless EVERY node explicitly opted out.
            nodes.iter().any(|node| {
                node.get("data")
                    .and_then(|d| d.get("needs_memory"))
                    .and_then(|v| v.as_bool())
                    != Some(false)
            })
        };
        // Fleet-wide kill-switch is the OUTERMOST gate: off ⇒ skip the whole
        // assembly here (the dispatch chokepoints also refuse injection, so this
        // is purely to avoid the wasted graph-RAG/DB work on the hot trigger
        // path). See `talos_config::actor_context_injection_enabled`.
        let should_inject = talos_config::actor_context_injection_enabled()
            && !opted_out
            && (explicit
                || (wf_record.actor_id.is_some() && graph_may_consume_memory(graph_val.as_ref())));
        let inject_actor = if explicit {
            trigger_agent_id.or(wf_record.actor_id)
        } else {
            wf_record.actor_id
        };
        let inject_scope = if explicit {
            talos_workflow_repository::MemoryScope::Full
        } else {
            talos_workflow_repository::MemoryScope::Curated
        };
        talos_actor_memory_service::inject_actor_context_into_input(
            &self.workflow_repo,
            &mut input_payload,
            inject_actor,
            should_inject,
            max_memories,
            wf_record.description.as_deref(),
            Some(execution_id),
            inject_scope,
        )
        .await;

        // 9. Trigger-type allowlist + actor-aware default. We always
        // resolve the canonical default ("manual" with no actor,
        // "actor_dispatch" with one) — explicit caller-supplied
        // values aren't part of our public input today.
        let trigger_type_str =
            talos_workflow_authorization::resolve_trigger_type(None, trigger_agent_id.is_some())
                .map_err(OrchestrationError::InvalidArgument)?;

        // 10. Lineage resolution: parent → root walk lives in the
        // execution repo, with migration-safe fallback. Callers
        // wanting cross-workflow provenance pass parent_execution_id
        // separately (not part of this method's public contract yet
        // — leave None to match the dispatch_to_actor / scheduler
        // surface which never populates it).
        let parent_execution_id: Option<Uuid> = None;
        let root_execution_id = self
            .execution_repo
            .resolve_root_from_parent(parent_execution_id, user_id)
            .await;

        // 11. Mint the execution row. `execution_id` was generated above
        // (step 8) so provenance recording could reference it; the row
        // INSERT below uses that same id. Priority comes from the graph
        // metadata if present, defaulting to "normal".
        let priority = graph_val
            .as_ref()
            .and_then(|v| {
                v.get("priority")
                    .and_then(|p| p.as_str())
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| "normal".to_string());
        let trigger_provenance = trigger_agent_id.map(|a| {
            serde_json::json!({
                "actor_id": a,
                "trigger_type": trigger_type_str,
            })
        });
        // Atomic concurrency-check + INSERT in one transaction.
        // Pre-r296 these were two separate SQL calls with a TOCTOU
        // window: two parallel triggers could both pass the count
        // check then both INSERT. The transactional helper locks the
        // workflow row so concurrent admissions serialise.
        let admission = self
            .workflow_repo
            .create_execution_under_concurrency_limit(
                execution_id,
                workflow_id,
                user_id,
                version_id,
                Some(&priority),
                effective_actor,
                trigger_provenance.as_ref(),
                parent_execution_id,
                root_execution_id,
                talos_workflow_repository::InitialExecutionStatus::Running,
            )
            .await
            .map_err(OrchestrationError::Internal)?;
        match admission {
            talos_workflow_repository::ConcurrencyAdmission::Created => {}
            talos_workflow_repository::ConcurrencyAdmission::LimitReached { limit, running } => {
                return Err(OrchestrationError::ConcurrencyLimitExceeded(format!(
                    "workflow has reached its concurrency limit ({} running, max {}); \
                     wait for running executions to complete or increase the limit",
                    running, limit
                )));
            }
            talos_workflow_repository::ConcurrencyAdmission::ActorBudgetExceeded {
                kind,
                limit,
                count,
            } => {
                // Atomic backstop fired (the fast-fail pre-check let a
                // concurrent burst slip through). Surface the same
                // budget-exceeded shape the pre-check uses.
                return Err(OrchestrationError::AuthorizationDenied(
                    talos_workflow_repository::actor_budget_exceeded_message(kind, limit, count),
                ));
            }
        }

        // 12. Best-effort analytics + audit log. Both are advisory —
        // failures land in tracing, never fail the trigger.
        if let Err(e) = self
            .workflow_repo
            .record_reuse_event(workflow_id, "trigger")
            .await
        {
            tracing::warn!(
                workflow_id = %workflow_id,
                err = %e,
                "trigger: record_reuse_event failed (non-fatal)"
            );
        }
        if let Some(actor_id) = trigger_agent_id {
            talos_actor_repository::spawn_log_action(
                self.db_pool.clone(),
                actor_id,
                "workflow_executed",
                Some(workflow_id),
                Some(execution_id),
                format!("Triggered workflow execution {}", execution_id),
                Some(serde_json::json!({
                    "execution_id": execution_id,
                    "trigger_type": trigger_type_str,
                    "priority": priority,
                })),
            );
        }

        // 13. Unbound-actor warning. Post-D2 `effective_actor` is the
        // gate-resolved actor (default-actor fallback included), so this now
        // only fires in the rare resolution-failure case where it stayed None
        // AND the graph has a memory-write node — the gap that would silently
        // drop __memory_write__ envelopes at execution time.
        let effective_actor_id = effective_actor;
        if effective_actor_id.is_none() {
            let unbound = count_memory_write_nodes(&graph_json);
            if unbound > 0 {
                tracing::warn!(
                    workflow_id = %workflow_id,
                    execution_id = %execution_id,
                    unbound_memory_write_node_count = unbound,
                    "trigger: workflow has {} node(s) with MEMORY_WRITE_KEY but no actor is bound — \
                     every __memory_write__ envelope will be silently dropped. Pass actor_id to trigger, \
                     or call set_workflow_actor_id to bind a default actor on the workflow.",
                    unbound
                );
            }
        }

        // 14. Engine build. Lift any caller-provided __actor_context__
        // out so the engine propagates it to ALL nodes (the builder
        // attaches it as a property; not just on the root payload).
        let lifted_actor_context = input_payload.get("__actor_context__").cloned();
        let nats = self
            .nats_client
            .as_ref()
            .ok_or_else(|| {
                OrchestrationError::DispatchFailed("NATS client not available".to_string())
            })?
            .clone();

        let opts = EngineOpts::for_run(workflow_id, graph_json)
            // Phase D2: the gate-resolved actor (already incorporates the
            // explicit→workflow→default fallback) so the engine tier matches
            // the stamped execution row.
            .with_effective_actor(effective_actor, None)
            .with_actor_context(lifted_actor_context)
            .with_dry_run(dry_run);
        let workflow_repo_for_task = self.workflow_repo.clone();
        let mut engine = match for_workflow(
            self.registry.clone(),
            self.secrets_manager.clone(),
            self.actor_repo.clone(),
            user_id,
            opts,
        )
        .await
        {
            Ok(e) => e,
            Err(BuildError::GraphLoad(engine_err)) => {
                // MCP-563: DLP-scrub user_msg before persisting.
                // render_graph_load_error's default arm passes the
                // engine's Display through verbatim (LoadGraph(String)
                // body), which could include parsed JSON content
                // carrying a secret. Parity with the spawn-task path
                // below (~line 511) which already redacts.
                let user_msg = render_graph_load_error(&engine_err);
                let redacted_msg = talos_dlp_provider::redact_str(&user_msg);
                if let Err(db_err) = workflow_repo_for_task
                    .mark_execution_failed(execution_id, &redacted_msg, None)
                    .await
                {
                    tracing::error!(
                        execution_id = %execution_id,
                        err = %db_err,
                        "trigger: failed to mark execution as failed after graph load error"
                    );
                }
                // Surface the DLP-redacted, actionable message to the
                // caller as a WORKFLOW-DEFINITION error (empty/malformed
                // graph) — not `Internal`, which would swallow it into a
                // generic "Internal server error" AND page as a server-side
                // failure. `redacted_msg` (not `user_msg`) because a
                // malformed-graph body could echo a secret.
                return Err(OrchestrationError::GraphLoadFailed(redacted_msg));
            }
        };

        // 15. Spawn the dispatch. Capture everything the task needs.
        let nats_for_alert = self.nats_client.clone();
        let exec_repo_for_alert = self.execution_repo.clone();
        let worker_key = self.worker_shared_key.clone();
        let trigger_input_for_storage = input_payload.clone();
        let trace_actor_id = trigger_agent_id;
        let event_sender = self.event_sender.clone();
        let db_pool_for_events = self.db_pool.clone();
        // F4 fresh-run fence (FU-1): the pool drives the epoch heartbeat that
        // aborts this run if a crash-recovery reclaim bumps the row's epoch out
        // from under us. See `talos_engine::fence::run_with_trigger_input_fenced`.
        let db_pool_for_fence = self.db_pool.clone();

        tokio::spawn(async move {
            // F4 fresh-run fence (FU-1): read the row's epoch BEFORE the
            // semaphore park below. The park can block for MINUTES behind the
            // concurrency cap; reading the epoch AFTER it would observe a value
            // a crash-recovery reclaim already bumped DURING the wait, and the
            // heartbeat would then never trip (it would match the already-bumped
            // epoch — the split-brain this fence exists to close). Reading
            // before the park captures the true at-dispatch epoch (0 for a fresh
            // INSERT), so a reclaim during the wait bumps PAST it and the fence
            // aborts this superseded original on the first tick. We read the
            // actual epoch (not a hard-coded 0) so a future INSERT that stamps a
            // non-zero epoch doesn't cause a false abort. A read failure falls
            // back to the unfenced path (best-effort hardening; status-guarded
            // terminal writes still prevent corruption).
            let fence_epoch = exec_repo_for_alert
                .current_execution_epoch(execution_id)
                .await;

            // Cap concurrent in-flight engine runs. The acquire blocks
            // when the global limit is saturated; tasks queue rather
            // than starting in parallel.
            let _permit = exec_semaphore().acquire().await;

            let run_result = match fence_epoch {
                Ok(Some(my_epoch)) => {
                    talos_engine::fence::run_with_trigger_input_fenced(
                        &mut engine,
                        nats,
                        worker_key,
                        input_payload,
                        execution_id,
                        db_pool_for_fence,
                        my_epoch,
                    )
                    .await
                }
                other => {
                    if let Err(e) = other {
                        tracing::warn!(
                            execution_id = %execution_id,
                            error = %e,
                            "trigger: could not read epoch for fresh-run fence; running unfenced"
                        );
                    } else {
                        tracing::warn!(
                            execution_id = %execution_id,
                            "trigger: execution row missing when reading epoch for fence; running unfenced"
                        );
                    }
                    run_with_trigger_input_via_nats(
                        &mut engine,
                        nats,
                        worker_key,
                        input_payload,
                        execution_id,
                    )
                    .await
                }
            };

            match run_result {
                Ok(wf_ctx) => {
                    let output_json = result_collector::collect_success_output(
                        &engine,
                        &wf_ctx,
                        &trigger_input_for_storage,
                    );
                    // Honor `wf_ctx.waiting` (confidence-gate / wait-node
                    // pause): the execution is NOT terminal — persist
                    // status='waiting' so the pending approval has
                    // something to resume. See finalize.rs for the
                    // regression history (r295 extraction dropped this
                    // branch; found live 2026-07-07).
                    let kind = crate::finalize::finalize_engine_success(
                        workflow_repo_for_task.as_ref(),
                        execution_id,
                        wf_ctx.waiting,
                        &output_json,
                        "trigger",
                    )
                    .await;

                    // Live event: broadcast to executionUpdates
                    // subscribers + persist to execution_events (see
                    // terminal_event.rs — semantics inherited from the
                    // pre-migration GraphQL store_and_send! macro).
                    // Waiting is announced as Waiting, not Completed —
                    // subscribers must not see a paused run as finished.
                    let (event_status, event_msg) = match kind {
                        crate::finalize::SuccessKind::Completed => (
                            talos_engine::events::ExecutionStatus::Completed,
                            "Workflow finished successfully".to_string(),
                        ),
                        crate::finalize::SuccessKind::Waiting => (
                            talos_engine::events::ExecutionStatus::Waiting,
                            "Workflow paused — awaiting approval/resume".to_string(),
                        ),
                    };
                    crate::terminal_event::emit_terminal_event(
                        &db_pool_for_events,
                        event_sender.as_ref(),
                        execution_id,
                        event_status,
                        event_msg,
                        wf_ctx.trace_id.clone(),
                    )
                    .await;

                    // Phase 5.2: Reasoning-trace capture under the actor's
                    // scratchpad memory. Best-effort; failures land in
                    // tracing, never propagate. Skipped for WAITING runs —
                    // the outputs are partial; the resume path finalizes
                    // the run and a partial trace keyed by execution_id
                    // would masquerade as the full one.
                    let trace_actor_id =
                        trace_actor_id.filter(|_| kind == crate::finalize::SuccessKind::Completed);
                    if let Some(actor_id) = trace_actor_id {
                        let trace_value = serde_json::json!({
                            "execution_id": execution_id,
                            "workflow_id": workflow_id,
                            "node_outputs": &output_json,
                            "captured_at": chrono::Utc::now().to_rfc3339(),
                        });
                        if let Err(e) = workflow_repo_for_task
                            .upsert_scratchpad_trace(
                                actor_id,
                                &scratchpad_trace_key(execution_id),
                                &trace_value,
                            )
                            .await
                        {
                            tracing::warn!(
                                execution_id = %execution_id,
                                err = %e,
                                "trigger: scratchpad trace upsert failed (non-fatal)"
                            );
                        }
                    }
                }
                // F4 fresh-run fence (FU-1): a fence abort means a
                // crash-recovery reclaim superseded this controller (the row's
                // epoch advanced). Do NOT mark the row failed — it now belongs
                // to the resumer, or a reclaim already failed it; clobbering it
                // would corrupt the new owner's state. Just log and bow out,
                // mirroring the resume path's `was_fenced` handling.
                Err(ref e) if talos_engine::fence::was_fenced(e) => {
                    tracing::warn!(
                        execution_id = %execution_id,
                        "trigger: fresh run fenced — superseded by a crash-recovery reclaim; \
                         leaving the row to its new owner"
                    );
                }
                Err(e) => {
                    let fail_output =
                        result_collector::collect_failure_output(&trigger_input_for_storage);
                    // MCP-447: redact the engine error string ONCE at the
                    // source so all three downstream sinks (DB row,
                    // alert pipeline, user-configured webhook) see the
                    // same redacted form. Pre-fix, only
                    // publish_execution_failure_alert redacted (closed
                    // in MCP-443); mark_execution_failed persisted the
                    // raw error to workflow_executions.error_message
                    // and dispatch_failure_webhook POSTed it to the
                    // user-configured webhook URL (third-party surface
                    // — Slack/PagerDuty/whatever). An upstream API
                    // returning "HTTP 401 invalid token sk-proj-xxx" or
                    // a Bearer header echoed back would propagate to
                    // every audit surface.
                    //
                    // MCP-1167 (2026-05-17): truncate-AT-SOURCE before
                    // redact. The engine error `e.to_string()` is
                    // unbounded — wasmtime traces, NATS-relayed upstream
                    // HTTP response bodies, multi-MB stack traces all
                    // possible. Pre-fix the source redact_str walked
                    // the full unbounded string before fanning out to
                    // three sinks. MCP-1161 fixed the DB sink by
                    // truncate-then-redact INSIDE mark_execution_failed,
                    // but the alert pipeline and webhook sinks still
                    // received the unbounded redacted string, and the
                    // source redact_str cost was unbounded for every
                    // failure. Truncate at source bounds all three
                    // sinks AND the regex pass cost. 4 KiB matches
                    // the MCP-1161 ceiling on the parallel DB column.
                    let raw_err_full = e.to_string();
                    let raw_err: &str = if raw_err_full.len() > 4096 {
                        talos_text_util::truncate_at_char_boundary(&raw_err_full, 4096)
                    } else {
                        raw_err_full.as_str()
                    };
                    let redacted_err = talos_dlp_provider::redact_str(raw_err);
                    if let Err(db_err) = workflow_repo_for_task
                        .mark_execution_failed(execution_id, &redacted_err, Some(&fail_output))
                        .await
                    {
                        tracing::error!(
                            execution_id = %execution_id,
                            err = %db_err,
                            "trigger: failed to mark execution as failed"
                        );
                    }

                    // Cancel still-running sibling module_executions.
                    // The DB trigger trg_cancel_siblings_on_workflow_fail
                    // (migration 20260327000001) handles this atomically;
                    // the explicit call here is defence-in-depth for
                    // pre-trigger pods or migration-rollback scenarios.
                    if let Err(cancel_err) = workflow_repo_for_task
                        .cancel_running_module_executions(execution_id)
                        .await
                    {
                        tracing::warn!(
                            execution_id = %execution_id,
                            err = %cancel_err,
                            "trigger: cancel_running_module_executions failed (non-fatal)"
                        );
                    }

                    result_collector::publish_execution_failure_alert(
                        &exec_repo_for_alert,
                        nats_for_alert.as_deref(),
                        user_id,
                        workflow_id,
                        execution_id,
                        &redacted_err,
                    )
                    .await;

                    dispatch_failure_webhook(
                        &workflow_repo_for_task,
                        workflow_id,
                        execution_id,
                        &redacted_err,
                    )
                    .await;

                    // Live terminal event (already-redacted error — the
                    // MCP-447 single-source redaction above covers this
                    // fourth sink too).
                    crate::terminal_event::emit_terminal_event(
                        &db_pool_for_events,
                        event_sender.as_ref(),
                        execution_id,
                        talos_engine::events::ExecutionStatus::Failed,
                        format!("Workflow failed: {}", redacted_err),
                        None,
                    )
                    .await;
                }
            }
        });

        // 16. Optional sync wait. Cap is enforced both here and in the
        // repo helper. Final-status string maps to ExecutionStatus;
        // unknown strings degrade to Running so the caller still gets
        // a well-formed outcome and can poll for the real status.
        //
        // MCP-1196 (2026-05-17): `wait_ms: Option<u64>` is typed-
        // unsigned at the input boundary (TriggerInput), so a caller-
        // supplied negative value is unreachable. The unwrap-then-cap
        // shape on the next line is safe under that invariant. Lint
        // check 12 was previously blind to identifier-constant `.min`
        // args; the tightened regex now flags this site and the marker
        // below documents the typed-unsigned rationale (same shape as
        // the other allow-min-only-clamp opt-outs in module-templates).
        let mut final_status = ExecutionStatus::Running;
        // allow-min-only-clamp: wait_ms is Option<u64>, typed-unsigned at input boundary
        let wait = wait_ms.unwrap_or(0).min(SYNC_WAIT_MAX_MS);
        if wait > 0 {
            if let Some(status_str) = self
                .execution_repo
                .wait_for_terminal_status(
                    execution_id,
                    user_id,
                    std::time::Duration::from_millis(wait),
                )
                .await
            {
                final_status = match status_str.as_str() {
                    "completed" => ExecutionStatus::Completed,
                    "failed" => ExecutionStatus::Failed,
                    "cancelled" => ExecutionStatus::Cancelled,
                    "timed_out" => ExecutionStatus::TimedOut,
                    _ => ExecutionStatus::Running,
                };
            }
        }

        Ok(TriggerOutcome::Dispatched(ExecutionOutcome {
            execution_id,
            status: final_status,
            metadata: TriggerMetadata {
                trigger_type: TriggerType::Manual,
                parent_execution_id,
                actor_id: effective_actor_id,
                workflow_id,
            },
            trace: None,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semaphore_init_uses_env_var_when_set() {
        // We can't easily exercise the OnceLock from a test without
        // hitting the global, so this just confirms the module
        // constants and key path are stable.
        assert_eq!(TRIGGER_INPUT_MAX_BYTES, 1_000_000);
        assert_eq!(SYNC_WAIT_MAX_MS, 30_000);
        assert_eq!(
            scratchpad_trace_key(uuid::Uuid::nil()),
            "execution/00000000-0000-0000-0000-000000000000/trace"
        );
    }
}
