//! Continuation-workflow dispatch — the canonical path for kicking off
//! a downstream workflow when an approval gate or workflow suspension
//! is resolved.
//!
//! Lifted from `controller/src/mcp/advanced.rs` so non-MCP callers
//! (notably the webhook receiver, which may resolve approval gates
//! via inbound HMAC-signed POSTs) can dispatch continuations without
//! reaching back into the MCP module tree. Both call sites now
//! exercise the same code path; behaviour parity is preserved.

use std::sync::Arc;

use talos_actor_repository::ActorRepository;
use talos_advanced_repository::AdvancedRepository;
use talos_engine::builder::{for_workflow, BuildError, EngineOpts};
use talos_engine::nats_run::run_with_trigger_input_via_nats;
use talos_engine::user_errors::render_graph_load_error;
use talos_registry::ModuleRegistry;
use talos_secrets_manager::SecretsManager;
use talos_workflow_repository::WorkflowRepository;
use uuid::Uuid;

/// Discriminates which platform primitive is dispatching a
/// continuation workflow. Emitted into the continuation workflow's
/// trigger input as `triggered_by` and used to pick the right ID
/// field name (`approval_gate_id` vs `suspension_id`) so consumers
/// can trust the shape.
#[derive(Clone, Copy, Debug)]
pub enum TriggerSourceKind {
    ApprovalGate,
    WorkflowSuspension,
    /// A Gmail push notification (Pub/Sub) whose watch row carries a
    /// bound `workflow_id`. `source_id` is the watch channel UUID; the
    /// triggered workflow re-fetches its own mail, so the trigger
    /// payload only carries `{source, email_address, history_id}`.
    GmailPush,
}

impl TriggerSourceKind {
    fn triggered_by(self) -> &'static str {
        match self {
            TriggerSourceKind::ApprovalGate => "approval_gate",
            TriggerSourceKind::WorkflowSuspension => "workflow_suspension",
            TriggerSourceKind::GmailPush => "gmail_push",
        }
    }
    fn id_field(self) -> &'static str {
        match self {
            TriggerSourceKind::ApprovalGate => "approval_gate_id",
            TriggerSourceKind::WorkflowSuspension => "suspension_id",
            TriggerSourceKind::GmailPush => "gmail_channel_id",
        }
    }
}

/// Trigger and dispatch a continuation workflow when an approval gate
/// or workflow suspension is resolved.
///
/// Creates a queued execution record, then immediately spawns the workflow engine
/// (mirroring how `trigger_workflow` dispatches — in-process via ParallelWorkflowEngine,
/// not via a separate NATS workflow-dispatch message).
///
/// `source_kind` controls how the continuation workflow sees its trigger
/// input: approval gates produce `{approval_gate_id, payload, triggered_by:
/// "approval_gate"}`; suspensions produce `{suspension_id, payload,
/// triggered_by: "workflow_suspension"}`. Previously both used the
/// `approval_gate_id` label regardless of source, forcing suspension
/// consumers to either read a misleading field or guess.
///
/// Returns the new execution ID on success, or None if any setup step fails.
pub async fn trigger_continuation_workflow(
    db_pool: &sqlx::PgPool,
    registry: Arc<ModuleRegistry>,
    nats_client: Option<Arc<async_nats::Client>>,
    secrets_manager: Arc<SecretsManager>,
    user_id: Uuid,
    workflow_id: Uuid,
    payload: &serde_json::Value,
    source_id: Uuid,
    source_kind: TriggerSourceKind,
) -> Option<String> {
    let repo = Arc::new(AdvancedRepository::new(db_pool.clone()));
    let execution_id = Uuid::new_v4();
    let trigger_payload = serde_json::json!({
        source_kind.id_field(): source_id.to_string(),
        "payload": payload,
        "triggered_by": source_kind.triggered_by(),
    });

    // MCP-708 (2026-05-13): upgraded from MCP-564's budget-only
    // `check_execution_allowed` to the full
    // `authorize_workflow_trigger` gate (status + budget +
    // capability-ceiling re-verification against the stored graph).
    // Same dispatch-path-authorization sweep as MCP-707 for
    // retry/replay — budget-only let operator-downgraded actor
    // ceilings drift open across approval-gate-resolution and
    // workflow-suspension-resume dispatch.
    //
    // Pre-fix bypass scenario: actor A had `max_capability_world =
    // agent-node` at T0; user built workflow W with agent-node
    // modules and an approval-gate continuation. Operator at T1
    // downgrades A to `http-node`. At T2 the gate is resolved (or
    // a suspension is resumed via webhook); pre-fix the budget
    // check passed and the continuation workflow's agent-node
    // modules ran against the now-http-node-ceilinged A.
    //
    // Fetch graph_json + actor_id in one round-trip so we can run
    // the full gate. Fail-CLOSED on DB error — MCP-707's contract.
    // Previously MCP-564 fail-OPENED on DB error "to avoid wedging
    // the continuation path on transient DB blips"; we tighten this
    // because the bypass class (privilege drift) outweighs the
    // dev-friendliness of fail-open. Operators with intermittent
    // DB issues will see a clear "denied by DB error" warn instead
    // of silently elevated privilege.
    let actor_repo = Arc::new(ActorRepository::new(db_pool.clone()));
    let workflow_repo_for_auth = Arc::new(WorkflowRepository::new(db_pool.clone()));
    let workflow_row: Option<(Option<Uuid>, String)> =
        match sqlx::query_as::<_, (Option<Uuid>, String)>(
            "SELECT actor_id, graph_json FROM workflows WHERE id = $1 AND user_id = $2",
        )
        .bind(workflow_id)
        .bind(user_id)
        .fetch_optional(db_pool)
        .await
        {
            Ok(row) => row,
            Err(e) => {
                tracing::warn!(
                    target: "talos_continuation_trigger",
                    event_kind = "continuation_workflow_lookup_failed",
                    workflow_id = %workflow_id,
                    error = %e,
                    "MCP-708: workflow lookup for auth gate failed — failing closed"
                );
                return None;
            }
        };
    let (workflow_actor_id, graph_json) = match workflow_row {
        Some(row) => row,
        None => {
            tracing::warn!(
                target: "talos_continuation_trigger",
                event_kind = "continuation_workflow_not_found",
                workflow_id = %workflow_id,
                "MCP-708: continuation target workflow not visible to user — denied"
            );
            return None;
        }
    };
    // Phase D2 parity (PR #461 follow-up): the gate runs UNCONDITIONALLY
    // and its resolved actor is captured for the engine binding below.
    // Pre-fix, unbound continuations skipped the gate AND the engine was
    // built with no actor at all — in fact even a BOUND workflow's actor
    // never reached the engine here, so every approval-gate resume ran at
    // the engine's Tier-1 fail-safe (external-LLM nodes denied,
    // `__memory_write__` dropped): the pre-approval half of a run and the
    // post-approval half executed at different tiers.
    let denied_actor_source = if workflow_actor_id.is_some() {
        "workflow-bound"
    } else {
        "user-default-actor"
    };
    let effective_actor_id: Option<Uuid> = {
        match talos_workflow_authorization::resolve_effective_actor(
            &workflow_repo_for_auth,
            &actor_repo,
            db_pool,
            workflow_actor_id,
            user_id,
            &graph_json,
        )
        .await
        {
            Ok(resolved) => resolved,
            Err(talos_workflow_authorization::TriggerAuthError::ActorArchived)
            | Err(talos_workflow_authorization::TriggerAuthError::ActorTerminated)
            | Err(talos_workflow_authorization::TriggerAuthError::ActorNotFoundOrInactive) => {
                tracing::warn!(
                    target: "talos_continuation_trigger",
                    event_kind = "continuation_dispatch_denied_actor_state",
                    source_id = %source_id,
                    source_kind = ?source_kind,
                    workflow_id = %workflow_id,
                    actor_id = ?workflow_actor_id,
                    %user_id,
                    denied_actor_source,
                    "MCP-708: continuation dispatch denied — actor not in a runnable state"
                );
                return None;
            }
            Err(talos_workflow_authorization::TriggerAuthError::ExecutionDenied(reason)) => {
                tracing::warn!(
                    target: "talos_continuation_trigger",
                    event_kind = "continuation_dispatch_denied_by_budget",
                    source_id = %source_id,
                    source_kind = ?source_kind,
                    workflow_id = %workflow_id,
                    actor_id = ?workflow_actor_id,
                    %user_id,
                    denied_actor_source,
                    reason = %reason,
                    "MCP-708: continuation dispatch denied by actor budget/status gate"
                );
                return None;
            }
            Err(talos_workflow_authorization::TriggerAuthError::CapabilityCeilingViolation {
                module_id,
                module_world,
                max_world,
                ..
            }) => {
                tracing::warn!(
                    target: "talos_continuation_trigger",
                    event_kind = "continuation_dispatch_denied_capability_ceiling",
                    source_id = %source_id,
                    source_kind = ?source_kind,
                    workflow_id = %workflow_id,
                    actor_id = ?workflow_actor_id,
                    %user_id,
                    denied_actor_source,
                    %module_id,
                    %module_world,
                    %max_world,
                    "MCP-708: continuation dispatch denied — node exceeds actor capability ceiling"
                );
                return None;
            }
            Err(talos_workflow_authorization::TriggerAuthError::Database(e)) => {
                tracing::warn!(
                    target: "talos_continuation_trigger",
                    event_kind = "continuation_dispatch_denied_db_error",
                    workflow_id = %workflow_id,
                    actor_id = ?workflow_actor_id,
                    %user_id,
                    denied_actor_source,
                    error = %e,
                    "MCP-708: continuation dispatch denied — auth-gate DB error (fail-closed)"
                );
                return None;
            }
        }
    };

    // 1. Create execution record (queued; transitions to running in the spawn below)
    if let Err(e) = repo
        .insert_queued_execution(execution_id, workflow_id, user_id, &trigger_payload)
        .await
    {
        tracing::error!(
            source_id = %source_id,
            source_kind = ?source_kind,
            "trigger_continuation_workflow: INSERT failed: {}",
            e
        );
        return None;
    }

    // 2. Write back continuation_execution_id to the source record so
    //    the gate/suspension row can be joined back to its continuation
    //    execution for audit. Only approval gates have this back-pointer
    //    column today; suspensions are joined via `mark_suspension_resumed`
    //    by the caller.
    // MCP-741 (2026-05-13): log set_gate_execution_id failures. Pre-fix
    // a DB failure here silently lost the audit back-pointer linking
    // approval-gate row → continuation execution. Sibling
    // `mark_suspension_resumed` (caller-side, for the suspension
    // variant) propagates errors normally; this one was the lone
    // swallow site. Continue rather than early-return because the
    // continuation itself can still proceed — the back-pointer is
    // for audit / UI joins only.
    if matches!(source_kind, TriggerSourceKind::ApprovalGate) {
        if let Err(e) = repo.set_gate_execution_id(source_id, execution_id).await {
            tracing::warn!(
                target: "talos_audit",
                source_id = %source_id,
                execution_id = %execution_id,
                error = %e,
                "set_gate_execution_id failed — audit back-pointer from approval gate to continuation execution will be missing"
            );
        }
    }

    // 3. Load workflow graph
    let graph_json = match repo.get_workflow_graph_json(workflow_id, user_id).await {
        Ok(Some(g)) => g,
        Ok(None) => {
            tracing::error!(
                execution_id = %execution_id,
                "Continuation workflow {} not found — marking failed",
                workflow_id
            );
            // MCP-741: log fail_execution failures. If the DB is
            // itself the cause of the primary error, the marking
            // call will also fail — leaving the execution row stuck
            // in 'running' status forever. Operators reading the
            // primary ERROR log line would expect the row to be
            // marked failed; without this WARN they have no signal
            // that the marking itself failed.
            if let Err(mark_err) = repo
                .fail_execution(execution_id, "Workflow not found")
                .await
            {
                tracing::warn!(
                    target: "talos_audit",
                    execution_id = %execution_id,
                    error = %mark_err,
                    "fail_execution UPDATE failed — execution row may remain in 'running' status (operator intervention needed)"
                );
            }
            return None;
        }
        Err(e) => {
            tracing::error!(
                execution_id = %execution_id,
                "Continuation workflow {} graph fetch failed: {}",
                workflow_id,
                e
            );
            if let Err(mark_err) = repo
                .fail_execution(execution_id, "Workflow not found")
                .await
            {
                tracing::warn!(
                    target: "talos_audit",
                    execution_id = %execution_id,
                    error = %mark_err,
                    "fail_execution UPDATE failed after graph-fetch error — execution row may remain in 'running' status"
                );
            }
            return None;
        }
    };

    // 4. Require NATS (needed for WASM node dispatch within the engine)
    let nats = match nats_client {
        Some(nc) => nc,
        None => {
            tracing::error!(
                execution_id = %execution_id,
                "NATS unavailable — cannot dispatch continuation workflow"
            );
            if let Err(mark_err) = repo.fail_execution(execution_id, "NATS unavailable").await {
                tracing::warn!(
                    target: "talos_audit",
                    execution_id = %execution_id,
                    error = %mark_err,
                    "fail_execution UPDATE failed after NATS-unavailable — execution row may remain in 'running' status"
                );
            }
            return None;
        }
    };

    // 5. Build engine via the canonical builder. TimeoutPolicy::Honor lets
    //    the engine read execution_timeout_secs from graph_json during
    //    load_graph_from_json — pre-load extraction was redundant
    //    (engine.rs::parse_graph_document overwrites the field on load).
    //    Reuses the actor_repo built for the MCP-564 budget gate above.
    //
    // MCP-683: keep a SecretsManager clone for the post-run encryption-
    // aware persistence; the builder consumes the Arc below.
    let sm_for_persist = secrets_manager.clone();
    let mut engine = match for_workflow(
        registry,
        secrets_manager,
        actor_repo,
        user_id,
        // Phase D2: bind the gate-resolved actor so the resumed half of
        // the run executes at the same tier (and with the same
        // `__memory_write__` capability) as the pre-suspension half.
        EngineOpts::for_run(workflow_id, graph_json.clone())
            .with_effective_actor(effective_actor_id, workflow_actor_id),
    )
    .await
    {
        Ok(e) => e,
        Err(BuildError::GraphLoad(engine_err)) => {
            // MCP-563: DLP-scrub the engine error before persisting +
            // logging. The default arm of render_graph_load_error
            // passes the engine's Display through verbatim
            // (LoadGraph(String) body), which could include parsed
            // JSON content carrying a secret. Parity with the
            // spawn-task path below (~line 240) which already redacts.
            let user_msg = render_graph_load_error(&engine_err);
            let error_msg = talos_dlp_provider::redact_str(&user_msg);
            tracing::error!(execution_id = %execution_id, "{}", error_msg);
            // MCP-741: log fail_execution failures — see L264 above.
            if let Err(mark_err) = repo.fail_execution(execution_id, &error_msg).await {
                tracing::warn!(
                    target: "talos_audit",
                    execution_id = %execution_id,
                    error = %mark_err,
                    "fail_execution UPDATE failed after engine-build error — execution row may remain in 'running' status"
                );
            }
            return None;
        }
    };

    let worker_key = talos_workflow_job_protocol::load_worker_shared_key().ok();

    tracing::info!(
        execution_id = %execution_id,
        workflow_id = %workflow_id,
        source_id = %source_id,
        source_kind = ?source_kind,
        "Dispatching continuation workflow execution"
    );

    // Clone trigger_payload so we keep one copy after the engine consumes
    // its own (used for the `__trigger_input__` round-trip on the
    // success path below).
    let trigger_input_for_storage = trigger_payload.clone();

    // MCP-683 (2026-05-13): also clone the pool for the
    // encryption-aware persistence path. The post-run write replaces
    // a raw `output_data = $2` UPDATE through
    // `AdvancedRepository::complete_execution` that bypassed
    // Phase A encryption for every approval-gate / suspension-resume
    // continuation. Sibling of MCP-682.
    let db_pool_for_persist = db_pool.clone();

    // Spawn the engine run — same pattern as trigger_workflow / enqueue_workflow
    tokio::spawn(async move {
        if let Err(e) = repo.set_execution_running(execution_id).await {
            tracing::error!(execution_id = %execution_id, "Failed to mark running: {}", e);
        }

        match run_with_trigger_input_via_nats(
            &mut engine,
            nats,
            worker_key,
            trigger_payload,
            execution_id,
        )
        .await
        {
            Ok(ctx) => {
                // MCP-517: route through the canonical
                // `collect_success_output` helper so this dispatch path
                // produces the same output shape as
                // `trigger_workflow` / replay / retry / scheduler /
                // webhook / handoff. Pre-fix the continuation path
                // built its output manually and:
                //   * did NOT filter __skipped nodes (so a skipped
                //     branch's "{__skipped:true,reason:...}" envelope
                //     leaked into the stored output)
                //   * did NOT call `ParallelWorkflowEngine::unwrap_output`
                //     so node results that carry an `__output__`
                //     envelope persisted the wrapped form instead
                //     of the raw payload — breaking downstream
                //     consumers that match on the bare value
                //   * did NOT round-trip `__trigger_input__` into the
                //     stored output, so any `replay_execution` /
                //     `retry_execution` against this continuation
                //     re-ran with an empty trigger payload
                //   * did NOT include `__node_timings__`, so
                //     `get_execution_cost` / `get_execution_timeline`
                //     / `get_execution_waterfall` / the perf report
                //     reported zero nodes for continuation runs.
                let output_json = talos_execution_result_collector::collect_success_output(
                    &engine,
                    &ctx,
                    &trigger_input_for_storage,
                );
                // MCP-683: encryption-aware persistence. Dispatch on
                // `ctx.waiting` so a suspended continuation lands in
                // 'waiting' (no `completed_at`) and a finished one
                // lands in 'completed' — same shape the scheduler and
                // GraphQL trigger paths produce. The previous
                // `AdvancedRepository::complete_execution` set
                // `completed_at = NOW()` even for `waiting` rows,
                // which made suspended continuations look finished
                // to time-based queries; the new path leaves
                // `completed_at` NULL on `waiting`.
                let wf_repo = WorkflowRepository::new(db_pool_for_persist.clone())
                    .with_encryption(sm_for_persist.clone());
                let persist_result = if ctx.waiting {
                    wf_repo
                        .mark_execution_waiting(execution_id, &output_json)
                        .await
                } else {
                    wf_repo
                        .mark_execution_completed(execution_id, &output_json)
                        .await
                };
                if let Err(e) = persist_result {
                    tracing::error!(
                        execution_id = %execution_id,
                        ctx_waiting = ctx.waiting,
                        error = %e,
                        "MCP-683: failed to persist continuation outcome — \
                         execution will appear stuck in 'running' state"
                    );
                }
            }
            Err(e) => {
                // MCP-452: DLP-redact the engine error before
                // persistence and logging. Same secret-leak class
                // closed across the trigger/replay/retry/scheduler/
                // webhook/engine-chain paths in MCP-447..451.
                let redacted_err = talos_dlp_provider::redact_str(&e.to_string());
                let error_msg = format!("Continuation workflow failed: {}", redacted_err);
                tracing::error!(execution_id = %execution_id, "{}", error_msg);
                // MCP-741: log fail_execution + cancel_running_module_executions
                // failures. If the DB is the reason the engine run failed,
                // these cleanup calls will likely also fail; without WARN
                // the execution + child module rows stay 'running' with no
                // operational signal.
                if let Err(mark_err) = repo.fail_execution(execution_id, &error_msg).await {
                    tracing::warn!(
                        target: "talos_audit",
                        execution_id = %execution_id,
                        error = %mark_err,
                        "fail_execution UPDATE failed after engine-run error — execution row may remain in 'running' status"
                    );
                }
                if let Err(cancel_err) = repo.cancel_running_module_executions(execution_id).await {
                    tracing::warn!(
                        target: "talos_audit",
                        execution_id = %execution_id,
                        error = %cancel_err,
                        "cancel_running_module_executions failed — child module_executions rows may remain in 'running' status"
                    );
                }
            }
        }
    });

    Some(execution_id.to_string())
}
