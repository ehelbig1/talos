//! Actor-to-actor handoff orchestration: status/chain/budget/
//! authorization gates, execution-record insert, dual audit logs, and
//! the background engine dispatch. Ported verbatim from
//! `talos-mcp-handlers/src/actor.rs::handle_handoff_to_actor`
//! (Round 43 + the MCP-259/727/803/460 hardening stack).
//!
//! The gate SEQUENCE is part of the locked contract: a multiply-invalid
//! request must surface the same first-failing-check error it did
//! pre-extraction, so argument parsing stays interleaved with the
//! DB-backed status checks exactly as the handler had it.

use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

use talos_actor_repository::spawn_log_action;
use talos_workflow_authorization::TriggerAuthError;

use crate::{json_type_name, ActorLifecycleService};

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Failure modes from [`ActorLifecycleService::handoff`]. Every message
/// is byte-identical to the pre-extraction handler; `jsonrpc_code()`
/// preserves the handler's -32602 (argument shape) vs -32000
/// (operational rejection) split.
#[derive(Debug, Error)]
pub enum HandoffError {
    /// JSON-RPC `-32602`: bad argument shape (including the 1 MB input
    /// cap). Message verbatim from the pre-extraction handler.
    #[error("{0}")]
    InvalidArgs(String),

    #[error("from_actor not found or access denied")]
    FromActorNotFound,

    #[error(
        "from_actor is archived — archived actors cannot initiate handoffs. Create a new actor instead."
    )]
    FromActorArchived,

    #[error(
        "from_actor is terminated — terminated actors cannot initiate handoffs. Create a new actor instead."
    )]
    FromActorTerminated,

    #[error("to_actor not found or access denied")]
    ToActorNotFound,

    #[error(
        "to_actor is archived — archived actors cannot receive handoffs. Create a new actor instead."
    )]
    ToActorArchived,

    #[error(
        "to_actor is terminated — terminated actors cannot receive handoffs. Create a new actor instead."
    )]
    ToActorTerminated,

    #[error(
        "handoff_cycle_detected: actor {from_actor_id} already appears in handoff chain {existing_chain:?}. Aborting to prevent infinite loop."
    )]
    CycleDetected {
        from_actor_id: Uuid,
        existing_chain: Vec<String>,
    },

    #[error(
        "handoff_depth_exceeded: chain is {chain_len} hops deep (max_depth={max_depth}). Increase max_depth or redesign the chain."
    )]
    DepthExceeded { chain_len: usize, max_depth: usize },

    /// `from_actor` failed the status+budget precheck; the inner string
    /// is the precheck's user-facing message verbatim.
    #[error("from_actor budget check failed: {0}")]
    FromActorBudget(String),

    #[error("Workflow not found or access denied")]
    WorkflowNotFound,

    /// `to_actor` failed `authorize_workflow_trigger`. Pre-rendered via
    /// [`render_trigger_auth_error`] — the `Database` arm collapses to a
    /// generic string (detail is logged server-side by the service).
    #[error("{0}")]
    AuthorizationRejected(String),

    #[error("Failed to create execution record")]
    ExecutionInsertFailed,

    #[error("NATS client not available")]
    NatsUnavailable,

    /// Engine graph-load failure, rendered via
    /// `talos_engine::user_errors::render_graph_load_error` (operator-
    /// grade text; the raw engine error is DLP-redacted and persisted on
    /// the execution row, never returned raw).
    #[error("{0}")]
    GraphLoad(String),
}

impl HandoffError {
    /// Stable JSON-RPC error code for protocol wrappers.
    pub fn jsonrpc_code(&self) -> i32 {
        match self {
            Self::InvalidArgs(_) => -32602,
            _ => -32000,
        }
    }

    /// Caller-safe message for the protocol response. All variants
    /// render fixed or pre-collapsed strings — DB/engine detail is
    /// logged by the service, never surfaced here.
    pub fn user_facing_message(&self) -> String {
        self.to_string()
    }
}

/// Render a `TriggerAuthError` into the handoff-specific rejection
/// message. Strings verbatim from the pre-extraction handler's match.
/// `chain_len` is the pre-hop chain length (the message reports
/// `chain_len + 1` as the attempted depth). Pure — the CAPABILITY /
/// DATABASE logging the handler did stays in the service caller.
pub fn render_trigger_auth_error(
    e: &TriggerAuthError,
    chain_len: usize,
    max_depth: usize,
) -> String {
    match e {
        TriggerAuthError::ActorArchived => {
            "to_actor is archived — cannot receive handoffs".to_string()
        }
        TriggerAuthError::ActorTerminated => {
            "to_actor is terminated — cannot receive handoffs".to_string()
        }
        TriggerAuthError::ActorNotFoundOrInactive => {
            "to_actor not found, not active, or belongs to a different user".to_string()
        }
        TriggerAuthError::ExecutionDenied(s) => {
            format!(
                "to_actor budget check failed: {} (chain at depth {} of {})",
                s,
                chain_len + 1,
                max_depth
            )
        }
        TriggerAuthError::CapabilityCeilingViolation {
            module_id,
            module_world,
            max_world,
            ..
        } => {
            format!(
                "to_actor cannot receive handoff: module {} requires capability '{}' but to_actor ceiling is '{}'. \
                 The actor's capability ceiling may have been downgraded since the workflow was authored.",
                module_id, module_world, max_world
            )
        }
        TriggerAuthError::Database(_) => "Database error during to_actor authorization".to_string(),
    }
}

// -----------------------------------------------------------------------------
// Outcome
// -----------------------------------------------------------------------------

/// Successful handoff: the execution record is inserted and the engine
/// run is dispatched in the background; the caller reports "triggered"
/// immediately.
#[derive(Debug, Clone)]
pub struct HandoffOutcome {
    pub execution_id: Uuid,
    pub from_actor_id: Uuid,
    pub to_actor_id: Uuid,
    pub workflow_id: Uuid,
    /// The extended chain (existing hops + this hop's from_actor).
    pub handoff_chain: Vec<String>,
    pub max_depth: usize,
}

impl HandoffOutcome {
    /// MCP tool-response body — field set and values preserved
    /// byte-for-byte from the pre-extraction handler.
    pub fn to_tool_body(&self) -> Value {
        serde_json::json!({
            "execution_id": self.execution_id,
            "status": "triggered",
            "to_actor_id": self.to_actor_id,
            "from_actor_id": self.from_actor_id,
            "workflow_id": self.workflow_id,
            "chain_depth": self.handoff_chain.len(),
            "handoff_chain": self.handoff_chain,
            "max_depth": self.max_depth,
        })
    }
}

// -----------------------------------------------------------------------------
// Worker shared key
// -----------------------------------------------------------------------------

/// Load the worker shared key, logging (not erroring) on failure —
/// downstream dispatch refuses unsigned jobs in production. Verbatim
/// copy of `talos-mcp-handlers/src/utils.rs::load_worker_shared_key_logged`
/// (the handler crate depends on this one, so it can't be imported).
fn load_worker_shared_key_logged(
    operation: &str,
) -> Option<talos_workflow_engine_core::WorkerSharedKey> {
    match talos_workflow_job_protocol::load_worker_shared_key() {
        Ok(key) => Some(key),
        Err(reason) => {
            tracing::error!(
                operation,
                reason,
                "WORKER_SHARED_KEY load failed; downstream dispatch refuses to send \
                 unsigned jobs in production. Generate one via `openssl rand -hex 32` \
                 and set WORKER_SHARED_KEY (or WORKER_SHARED_KEY_FILE) in the controller \
                 deployment."
            );
            None
        }
    }
}

// -----------------------------------------------------------------------------
// Orchestration
// -----------------------------------------------------------------------------

impl ActorLifecycleService {
    /// Hand off a workflow from one actor to another: verify both ends,
    /// enforce chain cycle/depth safety, gate on the initiator's budget
    /// and the receiver's full trigger authorization (capability ceiling
    /// included — MCP-727), insert the execution record with
    /// `actor_id = to_actor_id`, write both audit-log entries, and spawn
    /// the engine run. Returns as soon as the dispatch is spawned.
    pub async fn handoff(
        &self,
        user_id: Uuid,
        args: &Value,
    ) -> Result<HandoffOutcome, HandoffError> {
        // Parse from_actor_id (must belong to user)
        let from_str = match args.get("from_actor_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return Err(HandoffError::InvalidArgs("Missing from_actor_id".into())),
        };
        let from_actor_id: Uuid = match from_str.parse() {
            Ok(id) => id,
            Err(_) => {
                return Err(HandoffError::InvalidArgs(
                    "Invalid from_actor_id UUID".into(),
                ))
            }
        };
        // Parse budget_debit for cost attribution recording (default: 1.0, not a hard cap).
        // MCP-259 (2026-05-10): pre-fix `as_f64().unwrap_or(1.0)` collapsed
        // wrong-type into the default (`budget_debit: "0.5"` string → 1.0,
        // operator's intended debit lost). Also: NaN < 0.0 is false so
        // NaN passed the post-check, propagating into per-actor cost
        // tracking. Inf same. Now distinguishes absent / wrong-type and
        // rejects NaN/Inf at the boundary.
        let budget_debit: f64 = match args.get("budget_debit") {
            None | Some(Value::Null) => 1.0,
            Some(v) => match v.as_f64() {
                Some(n) if !n.is_finite() => {
                    return Err(HandoffError::InvalidArgs(
                        "budget_debit must be a finite number".into(),
                    ))
                }
                Some(n) if n < 0.0 => {
                    return Err(HandoffError::InvalidArgs(format!(
                        "budget_debit must be non-negative, got {n}"
                    )))
                }
                Some(n) => n,
                None => {
                    let kind = json_type_name(v);
                    return Err(HandoffError::InvalidArgs(format!(
                        "budget_debit must be a number, got {kind}"
                    )));
                }
            },
        };
        // Parse optional parent_execution_id for cross-workflow provenance linking.
        // Validate format when present — a malformed UUID would silently become None
        // and break the lineage chain without any feedback to the caller.
        let parent_exec_id: Option<Uuid> = match args.get("parent_execution_id") {
            None => None,
            Some(v) => match v.as_str() {
                None => {
                    return Err(HandoffError::InvalidArgs(
                        "parent_execution_id must be a string".into(),
                    ))
                }
                Some(s) => match s.parse::<Uuid>() {
                    Ok(id) => Some(id),
                    Err(_) => {
                        return Err(HandoffError::InvalidArgs(format!(
                            "parent_execution_id is not a valid UUID: '{s}'"
                        )))
                    }
                },
            },
        };
        // Verify from_actor belongs to user and is not in a terminal state.
        // Uses the user-scoped repository helper so auth + status fetch live in
        // one audited site.
        let from_status: Option<String> = self
            .actor_repo
            .get_actor_status_for_user(from_actor_id, user_id)
            .await
            .unwrap_or(None);
        match from_status.as_deref() {
            None => return Err(HandoffError::FromActorNotFound),
            Some("archived") => return Err(HandoffError::FromActorArchived),
            Some("terminated") => return Err(HandoffError::FromActorTerminated),
            _ => {}
        }

        // Parse to_actor_id (must belong to user)
        let to_str = match args.get("to_actor_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return Err(HandoffError::InvalidArgs("Missing to_actor_id".into())),
        };
        let to_actor_id: Uuid = match to_str.parse() {
            Ok(id) => id,
            Err(_) => return Err(HandoffError::InvalidArgs("Invalid to_actor_id UUID".into())),
        };
        // Verify to_actor belongs to user and is not in a terminal state.
        // Same user-scoped repo helper — keeps both ends of the handoff
        // symmetric and auditable.
        let to_status: Option<String> = self
            .actor_repo
            .get_actor_status_for_user(to_actor_id, user_id)
            .await
            .unwrap_or(None);
        match to_status.as_deref() {
            None => return Err(HandoffError::ToActorNotFound),
            Some("archived") => return Err(HandoffError::ToActorArchived),
            Some("terminated") => return Err(HandoffError::ToActorTerminated),
            _ => {}
        }

        // Parse workflow_id (same accept/reject shape as the canonical
        // `require_uuid` helper the handler used).
        let wf_id: Uuid = match args
            .get("workflow_id")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
        {
            Some(id) => id,
            None => {
                return Err(HandoffError::InvalidArgs(
                    "Invalid or missing 'workflow_id'".into(),
                ))
            }
        };

        // ── Handoff chain safety checks ───────────────────────────────────────
        // Extract the existing chain from the input payload (propagated by each hop)
        let existing_chain: Vec<String> = args
            .get("input")
            .and_then(|v| v.get("__handoff_chain__"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let max_depth_raw: u64 = match args.get("max_depth") {
            None => 5,
            Some(v) => {
                // Negative integers serialize as i64 in JSON; as_u64() returns None for them,
                // which would silently fall through to the default. Catch them explicitly.
                if v.as_i64().is_some_and(|n| n < 0) {
                    return Err(HandoffError::InvalidArgs(format!(
                        "max_depth must be between 1 and 10, got {}",
                        v.as_i64().unwrap_or_default()
                    )));
                }
                match v.as_u64() {
                    Some(n) => n,
                    None => {
                        return Err(HandoffError::InvalidArgs(
                            "max_depth must be a positive integer".into(),
                        ))
                    }
                }
            }
        };
        if !(1..=10).contains(&max_depth_raw) {
            return Err(HandoffError::InvalidArgs(format!(
                "max_depth must be between 1 and 10, got {max_depth_raw}"
            )));
        }
        let max_depth = max_depth_raw as usize;

        // Cycle detection: if from_actor already appears in the chain, we have a loop
        if existing_chain
            .iter()
            .any(|id| id == &from_actor_id.to_string())
        {
            return Err(HandoffError::CycleDetected {
                from_actor_id,
                existing_chain,
            });
        }

        // Depth enforcement: chain length already at or beyond limit
        if existing_chain.len() >= max_depth {
            return Err(HandoffError::DepthExceeded {
                chain_len: existing_chain.len(),
                max_depth,
            });
        }

        // Budget check for from_actor (source — initiating the handoff).
        if let Err(msg) = talos_actor_repository::budget_precheck::check_execution_allowed(
            &self.db_pool,
            from_actor_id,
        )
        .await
        {
            return Err(HandoffError::FromActorBudget(msg));
        }

        // Load workflow graph (must belong to user). Loaded BEFORE the
        // to_actor authorization so the auth gate has something to check
        // module worlds against.
        let graph_json = match self
            .actor_repo
            .get_workflow_graph_for_user(wf_id, user_id)
            .await
            .unwrap_or(None)
        {
            Some(g) => g,
            None => return Err(HandoffError::WorkflowNotFound),
        };

        // MCP-727 (2026-05-13): full `authorize_workflow_trigger` for the
        // to_actor (the actor that will EXECUTE the handed-off workflow).
        // Pre-fix this was budget-only via `check_execution_allowed`, so an
        // actor with downgraded `max_capability_world` could still receive
        // handoffs targeting workflows containing modules above their
        // current ceiling — a privilege-escalation surface (actor A with
        // agent-node ceiling hands off an agent-node workflow to actor B
        // whose ceiling was downgraded to http-node, and B's execution
        // dispatches anyway). Same drift class as MCP-707 (retry/replay),
        // MCP-708 (scheduler/chain/continuation), MCP-726 (GraphQL resume).
        //
        // from_actor gets only the budget+status check above because it's
        // the initiator (which the chain/cycle/depth checks above already
        // gated); the workflow runs AS the to_actor, so the ceiling check
        // belongs to to_actor.
        if let Err(e) = talos_workflow_authorization::authorize_workflow_trigger(
            &self.workflow_repo,
            &self.actor_repo,
            &self.db_pool,
            Some(to_actor_id),
            user_id,
            &graph_json,
        )
        .await
        {
            match &e {
                TriggerAuthError::CapabilityCeilingViolation {
                    module_id,
                    module_world,
                    max_world,
                    ..
                } => {
                    tracing::warn!(
                        from_actor = %from_actor_id,
                        to_actor = %to_actor_id,
                        workflow_id = %wf_id,
                        module_id = %module_id,
                        module_world = %module_world,
                        max_world = %max_world,
                        "handoff_to_actor: BLOCKED — to_actor capability ceiling violation (likely ceiling-drift)"
                    );
                }
                TriggerAuthError::Database(db_err) => {
                    tracing::error!(
                        to_actor_id = %to_actor_id,
                        workflow_id = %wf_id,
                        error = %db_err,
                        "handoff_to_actor: authorization DB error"
                    );
                }
                _ => {}
            }
            return Err(HandoffError::AuthorizationRejected(
                render_trigger_auth_error(&e, existing_chain.len(), max_depth),
            ));
        }

        // Validate input size before cloning into the execution pipeline.
        if let Some(input_val) = args.get("input") {
            if serde_json::to_string(input_val)
                .map(|s| s.len())
                .unwrap_or(0)
                > 1_048_576
            {
                return Err(HandoffError::InvalidArgs("input exceeds 1 MB limit".into()));
            }
        }
        // Build enriched input with handoff metadata
        let mut input_payload = args.get("input").cloned().unwrap_or(serde_json::json!({}));
        let new_chain: Vec<String>;
        if let Some(obj) = input_payload.as_object_mut() {
            obj.insert(
                "__handoff_from__".to_string(),
                serde_json::json!(from_actor_id.to_string()),
            );
            obj.insert(
                "__handoff_depth__".to_string(),
                serde_json::json!(existing_chain.len() + 1),
            );
            // Extend __handoff_chain__ — existing_chain is already extracted above; rebuild authoritatively
            let mut chain_arr = existing_chain.clone();
            chain_arr.push(from_actor_id.to_string());
            new_chain = chain_arr.clone();
            obj.insert(
                "__handoff_chain__".to_string(),
                serde_json::json!(chain_arr),
            );
        } else {
            new_chain = vec![from_actor_id.to_string()];
        }

        // Create execution record with actor_id = to_actor_id
        let exec_id = Uuid::new_v4();
        let version_id = self
            .actor_repo
            .get_active_workflow_version_id(wf_id)
            .await
            .unwrap_or(None);

        // Resolve root_execution_id (application-level lineage, no FK constraint).
        // If the parent has a root_execution_id, inherit it; otherwise the parent IS the root.
        let root_exec_id: Option<Uuid> = if let Some(pid) = parent_exec_id {
            self.actor_repo
                .resolve_root_execution_id(pid, user_id)
                .await
                .unwrap_or(Some(pid))
        } else {
            None
        };

        let provenance = serde_json::json!({
            "handoff_from": from_actor_id,
            "trigger_type": "actor_handoff",
            "budget_units_debited": budget_debit
        });
        if let Err(e) = self
            .actor_repo
            .insert_handoff_execution(
                exec_id,
                wf_id,
                user_id,
                version_id,
                to_actor_id,
                &provenance,
                parent_exec_id,
                root_exec_id,
            )
            .await
        {
            tracing::error!(execution_id = %exec_id, "handoff_to_actor: failed to create execution record: {:#}", e);
            return Err(HandoffError::ExecutionInsertFailed);
        }

        // Audit log for from_actor (initiated the handoff)
        spawn_log_action(
            self.db_pool.clone(),
            from_actor_id,
            "workflow_handoff",
            Some(wf_id),
            Some(exec_id),
            format!(
                "Handed off workflow {} to actor {} (chain depth {})",
                wf_id,
                to_actor_id,
                new_chain.len()
            ),
            Some(serde_json::json!({
                "to_actor_id": to_actor_id,
                "execution_id": exec_id,
                "chain_depth": new_chain.len(),
                "handoff_chain": new_chain,
                "budget_units_debited": budget_debit
            })),
        );

        // Audit log for to_actor (received the handoff)
        spawn_log_action(
            self.db_pool.clone(),
            to_actor_id,
            "workflow_handoff_received",
            Some(wf_id),
            Some(exec_id),
            format!(
                "Received handoff from actor {} for workflow {} (chain depth {})",
                from_actor_id,
                wf_id,
                new_chain.len()
            ),
            Some(serde_json::json!({
                "from_actor_id": from_actor_id,
                "execution_id": exec_id,
                "chain_depth": new_chain.len(),
                "handoff_chain": new_chain,
                "budget_units_debited": budget_debit
            })),
        );

        // Spawn engine run
        let registry = self.registry.clone();
        let actor_repo = self.actor_repo.clone();
        let nats = match self.nats_client.as_ref().cloned() {
            Some(nc) => nc,
            None => {
                // MCP-803 (2026-05-14): log execution-state UPDATE failures.
                // Pre-fix `let _ = ...await` discarded the Result so a transient
                // DB UPDATE failure on top of the NATS-unavailable error left
                // the execution row stuck in 'running' state with no operator
                // signal that the failure-marking itself failed. Same class as
                // MCP-802 (enqueue_workflow batch) and MCP-741 (continuation-
                // trigger cleanup). WARN with `target: "talos_audit"`.
                if let Err(ue) = actor_repo.fail_execution_nats_unavailable(exec_id).await {
                    tracing::warn!(
                        target: "talos_audit",
                        execution_id = %exec_id,
                        error = %ue,
                        "handoff_to_actor: fail_execution_nats_unavailable UPDATE failed — row may stay in 'running' state masking the NATS-unavailable failure"
                    );
                }
                return Err(HandoffError::NatsUnavailable);
            }
        };
        let secrets_manager = self.secrets_manager.clone();

        // Build via the canonical EngineBuilder. Handoff has actor-REQUIRED
        // semantics: `with_actor_id(to_actor_id)` (not `with_effective_actor`)
        // makes that explicit. The fail-closed Tier1 contract on
        // apply_actor_to_engine is preserved by the builder.
        let opts = talos_engine::builder::EngineOpts::for_run(wf_id, graph_json)
            .with_actor_id(to_actor_id);
        let mut engine = match talos_engine::builder::for_workflow(
            registry,
            secrets_manager,
            self.actor_repo.clone(),
            user_id,
            opts,
        )
        .await
        {
            Ok(e) => e,
            Err(talos_engine::builder::BuildError::GraphLoad(engine_err)) => {
                // MCP-460: DLP-redact the engine error before persistence,
                // same class as MCP-447..452. The user-facing message
                // returned to the MCP caller via `render_graph_load_error`
                // is already operator-grade text; only the DB row needs
                // redaction here.
                let redacted = talos_dlp_provider::redact_str(&engine_err.to_string());
                // MCP-803: log UPDATE failure — see fail_execution_nats_unavailable
                // arm above for full rationale.
                if let Err(ue) = actor_repo.fail_execution(exec_id, &redacted).await {
                    tracing::warn!(
                        target: "talos_audit",
                        execution_id = %exec_id,
                        primary_error = %engine_err,
                        update_error = %ue,
                        "handoff_to_actor: fail_execution UPDATE failed (graph-load arm) — row may stay in 'running' state masking the real graph-load failure"
                    );
                }
                return Err(HandoffError::GraphLoad(
                    talos_engine::user_errors::render_graph_load_error(&engine_err),
                ));
            }
        };

        let input_payload_for_storage = input_payload.clone();
        let worker_key = load_worker_shared_key_logged(file!());

        tokio::spawn(async move {
            match talos_engine::nats_run::run_with_trigger_input_via_nats(
                &mut engine,
                nats,
                worker_key,
                input_payload,
                exec_id,
            )
            .await
            {
                Ok(ctx) => {
                    let output_json = talos_execution_result_collector::collect_success_output(
                        &engine,
                        &ctx,
                        &input_payload_for_storage,
                    );
                    // MCP-803: log UPDATE failure on the success arm. Engine
                    // completed but row stays 'running' masks completion.
                    if let Err(ue) = actor_repo.complete_execution(exec_id, &output_json).await {
                        tracing::warn!(
                            target: "talos_audit",
                            execution_id = %exec_id,
                            error = %ue,
                            "handoff_to_actor: complete_execution UPDATE failed — row may stay in 'running' state despite successful engine completion"
                        );
                    }
                }
                Err(e) => {
                    // MCP-460: DLP-redact the engine run error before
                    // persistence. Mirrors the trigger / replay / retry
                    // paths that already redact.
                    let redacted = talos_dlp_provider::redact_str(&e.to_string());
                    // MCP-803: log UPDATE failure on the error arm. Highest
                    // stakes — primary engine failure compounded by the
                    // failure-marking UPDATE failure leaves the row in
                    // 'running' masking the real engine error from
                    // observability. WARN includes both error chains so
                    // operator dashboards correlate root cause.
                    if let Err(ue) = actor_repo.fail_execution(exec_id, &redacted).await {
                        tracing::warn!(
                            target: "talos_audit",
                            execution_id = %exec_id,
                            primary_error = %e,
                            update_error = %ue,
                            "handoff_to_actor: fail_execution UPDATE failed (engine-error arm) — row may mask the real engine failure as 'running'"
                        );
                    }
                }
            }
        });

        Ok(HandoffOutcome {
            execution_id: exec_id,
            from_actor_id,
            to_actor_id,
            workflow_id: wf_id,
            handoff_chain: new_chain,
            max_depth,
        })
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Error strings locked verbatim (r304 discipline) ────────────────────

    #[test]
    fn error_strings_locked_verbatim() {
        assert_eq!(
            HandoffError::FromActorNotFound.user_facing_message(),
            "from_actor not found or access denied"
        );
        assert_eq!(
            HandoffError::FromActorArchived.user_facing_message(),
            "from_actor is archived — archived actors cannot initiate handoffs. Create a new actor instead."
        );
        assert_eq!(
            HandoffError::FromActorTerminated.user_facing_message(),
            "from_actor is terminated — terminated actors cannot initiate handoffs. Create a new actor instead."
        );
        assert_eq!(
            HandoffError::ToActorNotFound.user_facing_message(),
            "to_actor not found or access denied"
        );
        assert_eq!(
            HandoffError::ToActorArchived.user_facing_message(),
            "to_actor is archived — archived actors cannot receive handoffs. Create a new actor instead."
        );
        assert_eq!(
            HandoffError::ToActorTerminated.user_facing_message(),
            "to_actor is terminated — terminated actors cannot receive handoffs. Create a new actor instead."
        );
        assert_eq!(
            HandoffError::WorkflowNotFound.user_facing_message(),
            "Workflow not found or access denied"
        );
        assert_eq!(
            HandoffError::ExecutionInsertFailed.user_facing_message(),
            "Failed to create execution record"
        );
        assert_eq!(
            HandoffError::NatsUnavailable.user_facing_message(),
            "NATS client not available"
        );
        assert_eq!(
            HandoffError::FromActorBudget("Actor not found".into()).user_facing_message(),
            "from_actor budget check failed: Actor not found"
        );
    }

    #[test]
    fn cycle_and_depth_strings_locked() {
        let id: Uuid = "a3bb189e-8bf9-3888-9912-ace4e6543002".parse().unwrap();
        let err = HandoffError::CycleDetected {
            from_actor_id: id,
            existing_chain: vec![id.to_string()],
        };
        assert_eq!(
            err.user_facing_message(),
            format!(
                "handoff_cycle_detected: actor {} already appears in handoff chain {:?}. Aborting to prevent infinite loop.",
                id,
                vec![id.to_string()]
            )
        );
        let err = HandoffError::DepthExceeded {
            chain_len: 5,
            max_depth: 5,
        };
        assert_eq!(
            err.user_facing_message(),
            "handoff_depth_exceeded: chain is 5 hops deep (max_depth=5). Increase max_depth or redesign the chain."
        );
    }

    #[test]
    fn jsonrpc_codes_stable() {
        assert_eq!(HandoffError::InvalidArgs("x".into()).jsonrpc_code(), -32602);
        assert_eq!(
            HandoffError::InvalidArgs("input exceeds 1 MB limit".into()).jsonrpc_code(),
            -32602
        );
        assert_eq!(HandoffError::FromActorNotFound.jsonrpc_code(), -32000);
        assert_eq!(HandoffError::ToActorArchived.jsonrpc_code(), -32000);
        assert_eq!(
            HandoffError::FromActorBudget("x".into()).jsonrpc_code(),
            -32000
        );
        assert_eq!(HandoffError::WorkflowNotFound.jsonrpc_code(), -32000);
        assert_eq!(
            HandoffError::AuthorizationRejected("x".into()).jsonrpc_code(),
            -32000
        );
        assert_eq!(HandoffError::ExecutionInsertFailed.jsonrpc_code(), -32000);
        assert_eq!(HandoffError::NatsUnavailable.jsonrpc_code(), -32000);
        assert_eq!(HandoffError::GraphLoad("x".into()).jsonrpc_code(), -32000);
    }

    // ── render_trigger_auth_error strings locked ────────────────────────────

    #[test]
    fn auth_error_rendering_locked() {
        assert_eq!(
            render_trigger_auth_error(&TriggerAuthError::ActorArchived, 0, 5),
            "to_actor is archived — cannot receive handoffs"
        );
        assert_eq!(
            render_trigger_auth_error(&TriggerAuthError::ActorTerminated, 0, 5),
            "to_actor is terminated — cannot receive handoffs"
        );
        assert_eq!(
            render_trigger_auth_error(&TriggerAuthError::ActorNotFoundOrInactive, 0, 5),
            "to_actor not found, not active, or belongs to a different user"
        );
        assert_eq!(
            render_trigger_auth_error(
                &TriggerAuthError::ExecutionDenied("Actor budget exceeded".into()),
                2,
                5
            ),
            "to_actor budget check failed: Actor budget exceeded (chain at depth 3 of 5)"
        );
        let module_id: Uuid = "a3bb189e-8bf9-3888-9912-ace4e6543002".parse().unwrap();
        assert_eq!(
            render_trigger_auth_error(
                &TriggerAuthError::CapabilityCeilingViolation {
                    module_id,
                    module_world: "agent-node".into(),
                    max_world: "http-node".into(),
                    req_rank: 6,
                    max_rank: 3,
                },
                0,
                5
            ),
            format!(
                "to_actor cannot receive handoff: module {} requires capability 'agent-node' but to_actor ceiling is 'http-node'. \
                 The actor's capability ceiling may have been downgraded since the workflow was authored.",
                module_id
            )
        );
    }

    #[test]
    fn auth_database_error_never_leaks_detail() {
        let msg = render_trigger_auth_error(
            &TriggerAuthError::Database(anyhow::anyhow!(
                "SELECT max_capability_world FROM actors failed: connection refused to 10.0.0.3"
            )),
            0,
            5,
        );
        assert_eq!(msg, "Database error during to_actor authorization");
        assert!(!msg.contains("SELECT"));
        assert!(!msg.contains("10.0.0.3"));
    }

    // ── Outcome shape locked ────────────────────────────────────────────────

    #[test]
    fn tool_body_shape_locked() {
        let exec_id: Uuid = "11111111-1111-1111-1111-111111111111".parse().unwrap();
        let from: Uuid = "22222222-2222-2222-2222-222222222222".parse().unwrap();
        let to: Uuid = "33333333-3333-3333-3333-333333333333".parse().unwrap();
        let wf: Uuid = "44444444-4444-4444-4444-444444444444".parse().unwrap();
        let outcome = HandoffOutcome {
            execution_id: exec_id,
            from_actor_id: from,
            to_actor_id: to,
            workflow_id: wf,
            handoff_chain: vec![from.to_string()],
            max_depth: 5,
        };
        let body = outcome.to_tool_body();
        assert_eq!(body["execution_id"], serde_json::json!(exec_id));
        assert_eq!(body["status"], "triggered");
        assert_eq!(body["to_actor_id"], serde_json::json!(to));
        assert_eq!(body["from_actor_id"], serde_json::json!(from));
        assert_eq!(body["workflow_id"], serde_json::json!(wf));
        assert_eq!(body["chain_depth"], 1);
        assert_eq!(body["handoff_chain"], serde_json::json!([from.to_string()]));
        assert_eq!(body["max_depth"], 5);
        assert_eq!(
            body.as_object().unwrap().len(),
            8,
            "response field set must stay stable"
        );
    }
}
