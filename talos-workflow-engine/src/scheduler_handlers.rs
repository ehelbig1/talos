//! Per-`SystemNodeKind` dispatch handlers used inside the scheduler loop.
//!
//! Each `try_dispatch_*` method short-circuits if `node_meta[node_id]`
//! does not match its specific [`SystemNodeKind`] variant, returning
//! `None`. If the variant matches, the method computes the node's
//! output (optionally awaiting sub-workflow dispatch), emits any
//! lifecycle events that belong with the handler's semantics, and
//! returns `Some(output)`. The scheduler caller then inserts the
//! output into `results` and unblocks successors uniformly via
//! [`ParallelWorkflowEngine::unblock_successors`].
//!
//! Splitting each handler out of the reactor loop keeps the scheduler
//! body focused on topology (ready queue, futures, chain routing) and
//! lets each kind's semantics stay auditable in isolation.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use talos_workflow_engine_core::reserved_keys::output_reports_error;

use petgraph::graph::NodeIndex;
use petgraph::Direction;
use serde_json::{json, Value as JsonValue};
use talos_workflow_engine_core::{
    DispatchJob, EdgeLogic, ExecutionStartedContext, NodeDispatcher, SystemNodeKind,
    WorkerSharedKey,
};

// AGENT_LOOP_MAX_HISTORY is now an engine field — see
// `ParallelWorkflowEngine::agent_loop_max_history`. We read through
// `self.agent_loop_max_history()` below so each engine can configure
// the window size independently.
use uuid::Uuid;

use crate::engine::ParallelWorkflowEngine;

/// Outcome of [`ParallelWorkflowEngine::try_dispatch_confidence_gate`].
///
/// The confidence gate is unusual among the local handlers because a
/// low-confidence signal can pause the entire workflow for human
/// approval — the scheduler needs to short-circuit the reactor and
/// return a [`WorkflowContext`] with `waiting: true`. Other handlers
/// just compute an output, so they can fit the uniform
/// `Option<JsonValue>` contract; this one can't.
///
/// The handler emits the node's output in both variants; the caller
/// inserts it into the accumulated `results` map and then either
/// continues the reactor or returns early with the fully-accumulated
/// map wrapped in a waiting-state context.
#[cfg(feature = "llm-primitives")]
pub(crate) enum ConfidenceGateOutcome {
    /// Gate's decision is a normal node output; caller inserts into
    /// `results` and unblocks successors as usual.
    Proceed(JsonValue),
    /// Low-confidence branch requested a pause. Caller inserts the
    /// output into its accumulated `results` map, then returns early
    /// with a [`WorkflowContext`] built from that map.
    Pause { waiting_output: JsonValue },
    /// `on_low_confidence: "error"` fired — caller should route this
    /// as a node failure through `handle_completed_future` so the
    /// workflow actually fails, matching the tool's documented
    /// contract. Prior versions stored the error envelope and let
    /// the workflow return `completed` despite the gate rejecting
    /// its input — same class of bug as the verify-node fix (b69aad5).
    Halt(String),
}

/// Outcome of [`ParallelWorkflowEngine::try_dispatch_wait`].
///
/// Wait shares the pause-the-reactor shape with `ConfidenceGate` but
/// isn't gated behind `llm-primitives`. The caller treats the
/// `waiting_output` as the Wait node's transient "output" — it lands
/// in the returned `WorkflowContext.results` so the consumer's
/// [`CheckpointStore`](talos_workflow_engine_core::CheckpointStore)
/// can persist it alongside every other completed node, and the
/// scheduler bails before unblocking successors.
///
/// Resume semantics: the caller invokes
/// [`run_with_seed_with_transport`](crate::ParallelWorkflowEngine::run_with_seed_with_transport)
/// with the Wait node's id mapped to the external input that should
/// stand in as the Wait node's actual output. The reactor treats it
/// as already-completed and successors see the substituted value via
/// their gathered inputs.
pub(crate) enum WaitOutcome {
    /// Fresh run reached a `Wait` node — pause and snapshot.
    Pause { waiting_output: JsonValue },
}

impl ParallelWorkflowEngine {
    /// Decrement every successor's pending-count and push nodes whose
    /// count reached zero onto the ready queue.
    ///
    /// Every local-computation handler calls this after inserting its
    /// output into `results`. The two-phase update — decrement first,
    /// then check zero — is load-bearing: a node with two pending
    /// predecessors decrements twice, and only the second decrement
    /// should enqueue it.
    pub(crate) fn unblock_successors(
        &self,
        node_idx: NodeIndex,
        pending: &mut HashMap<NodeIndex, usize>,
        ready: &mut VecDeque<NodeIndex>,
    ) {
        for child in self.graph.neighbors_directed(node_idx, Direction::Outgoing) {
            if let Some(cnt) = pending.get_mut(&child) {
                let was_positive = *cnt > 0;
                if was_positive {
                    *cnt -= 1;
                }
                // Enqueue only on the TRANSITION to zero, and remove the entry so
                // a parent completing later (possible under early-ready fan-in)
                // can't re-enter and double-enqueue this child. Mirrors the
                // removal in `handle_node_success`. Pre-fix, an unconditional
                // `if *cnt == 0` re-enqueued a child whose counter was already 0.
                if was_positive && *cnt == 0 {
                    pending.remove(&child);
                    ready.push_back(child);
                }
            }
        }
    }

    /// [`SystemNodeKind::Collect`] — aggregate every parent branch's
    /// output into a single `{count, items: [...]}` envelope.
    pub(crate) fn try_dispatch_collect(
        &self,
        node_idx: NodeIndex,
        node_id: Uuid,
        execution_id: Uuid,
        results: &HashMap<Uuid, JsonValue>,
    ) -> Option<JsonValue> {
        let (_, _, Some(SystemNodeKind::Collect)) = self.node_meta.get(&node_id)? else {
            return None;
        };
        let collected = self.collect_parent_outputs_for_node(node_idx, results);
        let parent_count = collected.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        self.emit_node_lifecycle_events(
            execution_id,
            node_id,
            "Completed",
            format!("collected {parent_count} branch outputs into items array"),
        );
        Some(collected)
    }

    /// [`SystemNodeKind::OpsAlertsDigest`] — controller-side read of the
    /// ops-alerts triage store through the injected
    /// [`talos_workflow_engine_core::OpsAlertsReader`] port.
    ///
    /// Returns `None` when the node is not an `OpsAlertsDigest` system
    /// node. Otherwise ALWAYS returns `Some(envelope)` — a missing
    /// reader (out-of-tree consumer), missing tenant identity, or a
    /// storage error degrade to `{"available": false, "error": …}`
    /// rather than failing the workflow: the primary consumer is a
    /// daily-brief compose node, and a briefing without its alerts
    /// section beats no briefing. Real errors are logged server-side;
    /// the envelope carries only a generic message (no schema/query
    /// detail leaks into node output, which is user-visible).
    ///
    /// Tenancy: `self.user_id` — the execution's resolved identity
    /// (set via actor binding at engine build), never node config.
    pub(crate) async fn try_dispatch_ops_alerts_digest(
        &self,
        node_id: Uuid,
        execution_id: Uuid,
    ) -> Option<JsonValue> {
        let (_, _, Some(SystemNodeKind::OpsAlertsDigest { top_limit })) =
            self.node_meta.get(&node_id)?
        else {
            return None;
        };
        let top_limit = *top_limit;

        let unavailable = |reason: &str| {
            serde_json::json!({
                "available": false,
                "error": reason,
            })
        };

        let Some(reader) = self.ops_alerts_reader.clone() else {
            tracing::warn!(
                %node_id,
                "ops_alerts_digest: no OpsAlertsReader wired — emitting unavailable envelope"
            );
            self.emit_node_lifecycle_events(
                execution_id,
                node_id,
                "Completed",
                "ops-alerts digest unavailable (reader not wired)".to_string(),
            );
            return Some(unavailable(
                "ops-alerts store not available in this deployment",
            ));
        };
        let Some(user_id) = self.user_id else {
            tracing::warn!(
                %node_id,
                "ops_alerts_digest: execution has no resolved user identity — emitting \
                 unavailable envelope"
            );
            self.emit_node_lifecycle_events(
                execution_id,
                node_id,
                "Completed",
                "ops-alerts digest unavailable (no tenant identity)".to_string(),
            );
            return Some(unavailable("execution has no tenant identity"));
        };

        // Defensive timeout so a stalled store can't wedge the reactor
        // (the injected impl's pool has its own timeouts; this is the
        // engine-side backstop).
        const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
        let output =
            match tokio::time::timeout(READ_TIMEOUT, reader.snapshot(user_id, top_limit)).await {
                Ok(Ok(mut snapshot)) => {
                    if let Some(obj) = snapshot.as_object_mut() {
                        obj.insert("available".to_string(), serde_json::json!(true));
                    }
                    self.emit_node_lifecycle_events(
                        execution_id,
                        node_id,
                        "Completed",
                        format!("ops-alerts digest fetched (top_limit {top_limit})"),
                    );
                    snapshot
                }
                Ok(Err(e)) => {
                    tracing::warn!(%node_id, error = %e, "ops_alerts_digest: snapshot failed");
                    self.emit_node_lifecycle_events(
                        execution_id,
                        node_id,
                        "Completed",
                        "ops-alerts digest unavailable (storage error)".to_string(),
                    );
                    unavailable("ops-alerts read failed")
                }
                Err(_) => {
                    tracing::warn!(%node_id, "ops_alerts_digest: snapshot timed out");
                    self.emit_node_lifecycle_events(
                        execution_id,
                        node_id,
                        "Completed",
                        "ops-alerts digest unavailable (timeout)".to_string(),
                    );
                    unavailable("ops-alerts read timed out")
                }
            };
        Some(output)
    }

    /// [`SystemNodeKind::PendingApprovals`] — controller-side read of
    /// the caller's pending human approvals plus freshly-minted
    /// one-click approve/reject capability URLs, through the injected
    /// [`talos_workflow_engine_core::PendingApprovalsReader`] port.
    ///
    /// Returns `None` when the node is not a `PendingApprovals` system
    /// node. Otherwise ALWAYS returns `Some(envelope)` — a missing
    /// reader (out-of-tree consumer), missing tenant identity, or a
    /// storage error degrade to `{"available": false, "reason": …}`
    /// rather than failing the workflow: the primary consumer is a
    /// notify-after-pause compose node, and a notifier without its
    /// approvals section beats a failed workflow.
    ///
    /// SECURITY: the minted URLs are capability secrets. They must
    /// transit node output (that is the entire point of the node), but
    /// we NEVER log them or the underlying tokens — only counts. Real
    /// errors are logged server-side; the envelope carries only a
    /// generic reason (no schema/query detail leaks into node output,
    /// which is user-visible).
    ///
    /// Tenancy: `self.user_id` — the execution's resolved identity (set
    /// via actor binding at engine build), never node config.
    pub(crate) async fn try_dispatch_pending_approvals(
        &self,
        node_id: Uuid,
        execution_id: Uuid,
    ) -> Option<JsonValue> {
        let (_, _, Some(SystemNodeKind::PendingApprovals { limit })) =
            self.node_meta.get(&node_id)?
        else {
            return None;
        };
        let limit = *limit;

        let unavailable = |reason: &str| {
            serde_json::json!({
                "available": false,
                "reason": reason,
            })
        };

        let Some(reader) = self.pending_approvals_reader.clone() else {
            tracing::warn!(
                %node_id,
                "pending_approvals: no PendingApprovalsReader wired — emitting unavailable envelope"
            );
            self.emit_node_lifecycle_events(
                execution_id,
                node_id,
                "Completed",
                "pending-approvals unavailable (reader not wired)".to_string(),
            );
            return Some(unavailable(
                "pending-approvals store not available in this deployment",
            ));
        };
        let Some(user_id) = self.user_id else {
            tracing::warn!(
                %node_id,
                "pending_approvals: execution has no resolved user identity — emitting \
                 unavailable envelope"
            );
            self.emit_node_lifecycle_events(
                execution_id,
                node_id,
                "Completed",
                "pending-approvals unavailable (no tenant identity)".to_string(),
            );
            return Some(unavailable("execution has no tenant identity"));
        };

        // Defensive timeout so a stalled store (or a slow token mint)
        // can't wedge the reactor. The reader's own mint step is already
        // timeout-bounded and best-effort; this is the engine-side
        // backstop.
        const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
        let output = match tokio::time::timeout(READ_TIMEOUT, reader.pending(user_id, limit)).await
        {
            Ok(Ok(mut snapshot)) => {
                let count = snapshot
                    .get("count")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
                if let Some(obj) = snapshot.as_object_mut() {
                    obj.insert("available".to_string(), serde_json::json!(true));
                }
                self.emit_node_lifecycle_events(
                    execution_id,
                    node_id,
                    "Completed",
                    // Count only — never the URLs (capability secrets).
                    format!("pending-approvals fetched ({count} pending, limit {limit})"),
                );
                snapshot
            }
            Ok(Err(e)) => {
                tracing::warn!(%node_id, error = %e, "pending_approvals: read failed");
                self.emit_node_lifecycle_events(
                    execution_id,
                    node_id,
                    "Completed",
                    "pending-approvals unavailable (storage error)".to_string(),
                );
                unavailable("pending-approvals read failed")
            }
            Err(_) => {
                tracing::warn!(%node_id, "pending_approvals: read timed out");
                self.emit_node_lifecycle_events(
                    execution_id,
                    node_id,
                    "Completed",
                    "pending-approvals unavailable (timeout)".to_string(),
                );
                unavailable("pending-approvals read timed out")
            }
        };
        Some(output)
    }

    /// [`SystemNodeKind::AssistantReport`] — controller-side weekly
    /// activity + learning-health snapshot through the injected
    /// [`talos_workflow_engine_core::AssistantReportReader`] port.
    /// Identical contract to
    /// [`Self::try_dispatch_ops_alerts_digest`]: `None` when the node
    /// isn't this kind; otherwise ALWAYS `Some(envelope)`, degrading to
    /// `{"available": false, "error": …}` (generic message only — real
    /// errors log server-side) rather than failing the workflow.
    pub(crate) async fn try_dispatch_assistant_report(
        &self,
        node_id: Uuid,
        execution_id: Uuid,
    ) -> Option<JsonValue> {
        let (_, _, Some(SystemNodeKind::AssistantReport { days })) =
            self.node_meta.get(&node_id)?
        else {
            return None;
        };
        let days = *days;

        let unavailable = |reason: &str| {
            serde_json::json!({
                "available": false,
                "error": reason,
            })
        };

        let Some(reader) = self.assistant_report_reader.clone() else {
            tracing::warn!(
                %node_id,
                "assistant_report: no AssistantReportReader wired — emitting unavailable envelope"
            );
            self.emit_node_lifecycle_events(
                execution_id,
                node_id,
                "Completed",
                "assistant report unavailable (reader not wired)".to_string(),
            );
            return Some(unavailable(
                "assistant report not available in this deployment",
            ));
        };
        let Some(user_id) = self.user_id else {
            tracing::warn!(
                %node_id,
                "assistant_report: execution has no resolved user identity — emitting \
                 unavailable envelope"
            );
            self.emit_node_lifecycle_events(
                execution_id,
                node_id,
                "Completed",
                "assistant report unavailable (no tenant identity)".to_string(),
            );
            return Some(unavailable("execution has no tenant identity"));
        };

        // Larger backstop than the digest node's — this snapshot runs
        // several aggregate queries.
        const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
        let output = match tokio::time::timeout(READ_TIMEOUT, reader.snapshot(user_id, days)).await
        {
            Ok(Ok(mut snapshot)) => {
                if let Some(obj) = snapshot.as_object_mut() {
                    obj.insert("available".to_string(), serde_json::json!(true));
                }
                self.emit_node_lifecycle_events(
                    execution_id,
                    node_id,
                    "Completed",
                    format!("assistant report fetched ({days}d window)"),
                );
                snapshot
            }
            Ok(Err(e)) => {
                tracing::warn!(%node_id, error = %e, "assistant_report: snapshot failed");
                self.emit_node_lifecycle_events(
                    execution_id,
                    node_id,
                    "Completed",
                    "assistant report unavailable (storage error)".to_string(),
                );
                unavailable("assistant report read failed")
            }
            Err(_) => {
                tracing::warn!(%node_id, "assistant_report: snapshot timed out");
                self.emit_node_lifecycle_events(
                    execution_id,
                    node_id,
                    "Completed",
                    "assistant report unavailable (timeout)".to_string(),
                );
                unavailable("assistant report read timed out")
            }
        };
        Some(output)
    }

    /// [`SystemNodeKind::OperatorDigest`] — controller-side autonomy-cockpit
    /// snapshot (ran / learned / `needs_me` over a trailing window) through the
    /// injected [`talos_workflow_engine_core::OperatorDigestReader`] port.
    /// Identical contract to [`Self::try_dispatch_assistant_report`]: `None`
    /// when the node isn't this kind; otherwise ALWAYS `Some(envelope)`,
    /// degrading to `{"available": false, "error": …}` (generic message only —
    /// real errors log server-side) rather than failing the workflow.
    pub(crate) async fn try_dispatch_operator_digest(
        &self,
        node_id: Uuid,
        execution_id: Uuid,
    ) -> Option<JsonValue> {
        let (_, _, Some(SystemNodeKind::OperatorDigest { days })) = self.node_meta.get(&node_id)?
        else {
            return None;
        };
        let days = *days;

        let unavailable = |reason: &str| {
            serde_json::json!({
                "available": false,
                "error": reason,
            })
        };

        let Some(reader) = self.operator_digest_reader.clone() else {
            tracing::warn!(
                %node_id,
                "operator_digest: no OperatorDigestReader wired — emitting unavailable envelope"
            );
            self.emit_node_lifecycle_events(
                execution_id,
                node_id,
                "Completed",
                "operator digest unavailable (reader not wired)".to_string(),
            );
            return Some(unavailable(
                "operator digest not available in this deployment",
            ));
        };
        let Some(user_id) = self.user_id else {
            tracing::warn!(
                %node_id,
                "operator_digest: execution has no resolved user identity — emitting \
                 unavailable envelope"
            );
            self.emit_node_lifecycle_events(
                execution_id,
                node_id,
                "Completed",
                "operator digest unavailable (no tenant identity)".to_string(),
            );
            return Some(unavailable("execution has no tenant identity"));
        };

        const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
        let output = match tokio::time::timeout(READ_TIMEOUT, reader.snapshot(user_id, days)).await
        {
            Ok(Ok(mut snapshot)) => {
                if let Some(obj) = snapshot.as_object_mut() {
                    obj.insert("available".to_string(), serde_json::json!(true));
                }
                self.emit_node_lifecycle_events(
                    execution_id,
                    node_id,
                    "Completed",
                    format!("operator digest fetched ({days}d window)"),
                );
                snapshot
            }
            Ok(Err(e)) => {
                tracing::warn!(%node_id, error = %e, "operator_digest: snapshot failed");
                self.emit_node_lifecycle_events(
                    execution_id,
                    node_id,
                    "Completed",
                    "operator digest unavailable (storage error)".to_string(),
                );
                unavailable("operator digest read failed")
            }
            Err(_) => {
                tracing::warn!(%node_id, "operator_digest: snapshot timed out");
                self.emit_node_lifecycle_events(
                    execution_id,
                    node_id,
                    "Completed",
                    "operator digest unavailable (timeout)".to_string(),
                );
                unavailable("operator digest read timed out")
            }
        };
        Some(output)
    }

    /// [`SystemNodeKind::Synthesize`] — collect parent outputs, then
    /// (optionally) transform the collected value through a Rhai
    /// expression.
    pub(crate) fn try_dispatch_synthesize(
        &self,
        node_idx: NodeIndex,
        node_id: Uuid,
        execution_id: Uuid,
        results: &HashMap<Uuid, JsonValue>,
    ) -> Option<JsonValue> {
        let (_, _, Some(SystemNodeKind::Synthesize { synthesis_expr })) =
            self.node_meta.get(&node_id)?
        else {
            return None;
        };
        let synthesis_expr = synthesis_expr.clone();
        let synthesized = self.synthesize_parent_outputs(node_idx, results, &synthesis_expr);

        // Recover parent_count for event logging from the synthesized output
        // (it may be an object with "count" if no expression was applied, or
        // arbitrary if a Rhai expression transformed it).
        let parent_count = synthesized
            .get("count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        self.emit_node_lifecycle_events(
            execution_id,
            node_id,
            "Completed",
            format!("synthesized {parent_count} branch outputs"),
        );

        Some(synthesized)
    }

    /// [`SystemNodeKind::Verify`] — evaluate a condition against the
    /// node's gathered input and emit a pass/fail outcome.
    ///
    /// Returns `None` when the node is not a Verify system node.
    /// Returns `Some(Ok(value))` when the caller should store `value`
    /// as the node's output and continue (pass, or `on_failure:
    /// "passthrough"`).
    /// Returns `Some(Err(message))` when `on_failure: "error"` fired
    /// and the caller should route this as a node failure through the
    /// normal completion path (which halts the workflow unless the
    /// node has `continue_on_error` set or an error edge catches it).
    ///
    /// The previous signature returned `Option<JsonValue>`
    /// unconditionally — the error envelope was stored but the workflow
    /// completed anyway, silently contradicting the tool documentation
    /// that promised "workflow fails with verification error".
    pub(crate) fn try_dispatch_verify(
        &self,
        node_idx: NodeIndex,
        node_id: Uuid,
        execution_id: Uuid,
        results: &HashMap<Uuid, JsonValue>,
    ) -> Option<Result<JsonValue, String>> {
        let (
            _,
            _,
            Some(SystemNodeKind::Verify {
                condition,
                check_label,
                on_failure,
            }),
        ) = self.node_meta.get(&node_id)?
        else {
            return None;
        };
        let check_label = check_label
            .clone()
            .unwrap_or_else(|| "output quality".to_string());
        let on_failure_owned = on_failure.clone();
        let (verify_result, passed) =
            self.evaluate_verify_node(node_idx, results, condition, &check_label, on_failure);

        self.emit_node_lifecycle_events(
            execution_id,
            node_id,
            if passed { "Completed" } else { "Failed" },
            format!(
                "Verify '{check_label}': {}",
                if passed { "PASSED" } else { "FAILED" }
            ),
        );

        // Pass OR on_failure="passthrough": forward the result and
        // continue. Only the explicit "error" mode converts into a
        // workflow-level failure so the documented contract holds.
        if passed || on_failure_owned == "passthrough" {
            Some(Ok(verify_result))
        } else {
            // Extract a concise error message from the synthesized
            // envelope so the completion-handler failure-path sees
            // the same text the envelope carries.
            let err_msg = verify_result
                .get("error_message")
                .and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_else(|| {
                    format!("Verification '{check_label}' failed (condition: {condition})")
                });
            Some(Err(err_msg))
        }
    }

    /// [`SystemNodeKind::Wait`] — pause the workflow until an external
    /// signal resumes it.
    ///
    /// Returns `None` when the node is not a `Wait`; otherwise a
    /// [`WaitOutcome::Pause`] carrying a `__waiting__: true` envelope
    /// the caller stores in `results` before returning a
    /// `WorkflowContext { waiting: true, .. }`.
    ///
    /// Resume contract: the caller invokes
    /// [`run_with_seed_with_transport`](crate::ParallelWorkflowEngine::run_with_seed_with_transport)
    /// with `seed[wait_node_id]` set to whatever value should stand
    /// in as the Wait node's "output" for downstream consumers.
    /// Common shapes: the webhook payload that triggered the resume,
    /// the human approver's verdict, a timer-fired sentinel, etc.
    /// The engine never inspects this value — it just routes it to
    /// the Wait node's successors via their gathered inputs.
    pub(crate) fn try_dispatch_wait(
        &self,
        node_id: Uuid,
        execution_id: Uuid,
    ) -> Option<WaitOutcome> {
        let (_, _, Some(SystemNodeKind::Wait { message })) = self.node_meta.get(&node_id)? else {
            return None;
        };
        let waiting_output = if let Some(m) = message {
            json!({
                "__waiting__": true,
                "node_id": node_id.to_string(),
                "execution_id": execution_id.to_string(),
                "message": m,
            })
        } else {
            json!({
                "__waiting__": true,
                "node_id": node_id.to_string(),
                "execution_id": execution_id.to_string(),
            })
        };
        tracing::info!(
            %node_id,
            %execution_id,
            "Wait node reached — pausing workflow"
        );
        Some(WaitOutcome::Pause { waiting_output })
    }

    /// [`SystemNodeKind::WhileLoop`] — run the body *locally* (no
    /// module dispatch), re-evaluating the condition after each pass.
    /// Output records the final iteration count and last wrapped value.
    pub(crate) fn try_dispatch_while_loop(
        &self,
        node_idx: NodeIndex,
        node_id: Uuid,
        results: &HashMap<Uuid, JsonValue>,
    ) -> Option<JsonValue> {
        let (
            _,
            _,
            Some(SystemNodeKind::WhileLoop {
                condition,
                max_iterations,
            }),
        ) = self.node_meta.get(&node_id)?
        else {
            return None;
        };
        let condition = condition.clone();
        let max_iters = *max_iterations;

        let mut current_output = self.gather_inputs(node_idx, results);
        let mut iteration = 0u32;
        while iteration < max_iters {
            if !self.eval_bool_kinded(
                crate::condition_eval::ConditionKind::WhileLoop,
                &condition,
                &current_output,
            ) {
                break;
            }
            iteration += 1;
            current_output = json!({
                "__loop_iteration": iteration,
                "__loop_input": current_output,
            });
        }
        if iteration >= max_iters {
            tracing::warn!(
                %node_id,
                max_iterations = max_iters,
                "WhileLoop reached maximum iterations"
            );
        }
        Some(json!({
            "iterations": iteration,
            "output": current_output,
        }))
    }

    /// [`SystemNodeKind::RepeatLoop`] — fixed-count pass-through; the
    /// output records the iteration count and the gathered input.
    pub(crate) fn try_dispatch_repeat_loop(
        &self,
        node_idx: NodeIndex,
        node_id: Uuid,
        results: &HashMap<Uuid, JsonValue>,
    ) -> Option<JsonValue> {
        let (_, _, Some(SystemNodeKind::RepeatLoop { count })) = self.node_meta.get(&node_id)?
        else {
            return None;
        };
        let count = *count;
        let inputs = self.gather_inputs(node_idx, results);
        Some(json!({
            "iterations": count,
            "input": inputs,
        }))
    }

    /// [`SystemNodeKind::InlineJudge`] — evaluate a verdict expression
    /// directly via the engine's `ExpressionEvaluator` instead of
    /// dispatching a separate sub-workflow.
    ///
    /// Returns `None` when the node is not an `InlineJudge`; otherwise
    /// the verdict envelope (same shape as
    /// [`Self::dispatch_judge`](ParallelWorkflowEngine::dispatch_judge)).
    #[cfg(feature = "llm-primitives")]
    pub(crate) fn try_dispatch_inline_judge(
        &self,
        node_idx: NodeIndex,
        node_id: Uuid,
        results: &HashMap<Uuid, JsonValue>,
    ) -> Option<JsonValue> {
        let (
            _,
            _,
            Some(SystemNodeKind::InlineJudge {
                verdict_expr,
                pass_threshold,
                on_failure,
            }),
        ) = self.node_meta.get(&node_id)?
        else {
            return None;
        };
        let verdict_expr = verdict_expr.clone();
        let pass_threshold = *pass_threshold;
        let on_failure = on_failure.clone();
        let parent_inputs = self.gather_inputs(node_idx, results);
        Some(self.dispatch_inline_judge(parent_inputs, &verdict_expr, pass_threshold, &on_failure))
    }

    /// [`SystemNodeKind::Judge`] — run an LLM-as-judge sub-workflow.
    #[cfg(feature = "llm-primitives")]
    pub(crate) async fn try_dispatch_judge(
        &self,
        node_idx: NodeIndex,
        node_id: Uuid,
        dispatcher: &Arc<dyn NodeDispatcher>,
        worker_shared_key: &Option<WorkerSharedKey>,
        results: &HashMap<Uuid, JsonValue>,
    ) -> Option<JsonValue> {
        let (
            _,
            _,
            Some(SystemNodeKind::Judge {
                judge_workflow_id,
                rubric,
                pass_threshold,
                on_failure,
                timeout_secs: _,
            }),
        ) = self.node_meta.get(&node_id)?
        else {
            return None;
        };
        let judge_wf_id = *judge_workflow_id;
        let rubric = rubric.clone();
        let pass_threshold = *pass_threshold;
        let on_failure = on_failure.clone();
        let parent_inputs = self.gather_inputs(node_idx, results);

        Some(
            self.dispatch_judge(
                parent_inputs,
                judge_wf_id,
                rubric,
                pass_threshold,
                &on_failure,
                dispatcher.clone(),
                worker_shared_key.clone(),
            )
            .await,
        )
    }

    /// [`SystemNodeKind::ReflectiveRetry`] — run a child workflow and,
    /// on failure, invoke a reflection workflow before retrying.
    #[cfg(feature = "llm-primitives")]
    pub(crate) async fn try_dispatch_reflective_retry(
        &self,
        node_idx: NodeIndex,
        node_id: Uuid,
        dispatcher: &Arc<dyn NodeDispatcher>,
        worker_shared_key: &Option<WorkerSharedKey>,
        results: &HashMap<Uuid, JsonValue>,
    ) -> Option<JsonValue> {
        let (
            _,
            _,
            Some(SystemNodeKind::ReflectiveRetry {
                child_workflow_id,
                reflection_workflow_id,
                max_retries,
                timeout_secs: _,
            }),
        ) = self.node_meta.get(&node_id)?
        else {
            return None;
        };
        let child_wf_id = *child_workflow_id;
        let reflection_wf_id = *reflection_workflow_id;
        let max_retries = *max_retries;
        let initial_input = self.gather_inputs(node_idx, results);

        Some(
            self.dispatch_reflective_retry(
                initial_input,
                child_wf_id,
                reflection_wf_id,
                max_retries,
                dispatcher.clone(),
                worker_shared_key.clone(),
            )
            .await,
        )
    }

    /// [`SystemNodeKind::LlmDispatch`] — route to one of several child
    /// workflows based on a classifier's output.
    #[cfg(feature = "llm-primitives")]
    #[tracing::instrument(
        level = "info",
        name = "llm_dispatch",
        skip_all,
        fields(node_id = %node_id),
    )]
    pub(crate) async fn try_dispatch_llm_dispatch(
        &self,
        node_idx: NodeIndex,
        node_id: Uuid,
        dispatcher: &Arc<dyn NodeDispatcher>,
        worker_shared_key: &Option<WorkerSharedKey>,
        results: &HashMap<Uuid, JsonValue>,
    ) -> Option<JsonValue> {
        let (
            _,
            _,
            Some(SystemNodeKind::LlmDispatch {
                classifier_workflow_id,
                routes,
                fallback_workflow_id,
                timeout_secs: _,
            }),
        ) = self.node_meta.get(&node_id)?
        else {
            return None;
        };
        let classifier_wf_id = *classifier_workflow_id;
        let routes = routes.clone();
        let fallback_wf_id = *fallback_workflow_id;
        let inputs = self.gather_inputs(node_idx, results);

        Some(
            self.dispatch_llm_dispatch(
                inputs,
                classifier_wf_id,
                routes,
                fallback_wf_id,
                dispatcher.clone(),
                worker_shared_key.clone(),
            )
            .await,
        )
    }

    /// True iff `node_id` is a [`SystemNodeKind::SubWorkflow`] node.
    /// Used by the reactor loop to drain ready sub-workflow siblings
    /// for batched parallel dispatch (see the `SubWorkflow` handler in
    /// `engine.rs::run_with_seed_with_transport_cancellable`).
    pub(crate) fn is_sub_workflow_node(&self, node_id: Uuid) -> bool {
        matches!(
            self.node_meta
                .get(&node_id)
                .and_then(|(_, _, kind)| kind.as_ref()),
            Some(SystemNodeKind::SubWorkflow { .. })
        )
    }

    /// [`SystemNodeKind::SubWorkflow`] — invoke another workflow by
    /// id, seeded with this node's gathered input.
    ///
    /// Emits `node_started` / `node_completed` (or `node_failed`) events on
    /// the parent's `execution_id` so the per-node trace surfaces the
    /// dispatch as a real node with measurable duration. Without these
    /// events the parent trace showed only a wall-clock gap before
    /// downstream nodes started — operators had to know the workflow
    /// architecture to read the gap as "sub-workflow LLM latency."
    /// `node_started` is fire-and-forget (matches regular module dispatch);
    /// `node_completed` / `node_failed` are awaited so the parent trace
    /// orders correctly relative to downstream `node_started` events.
    pub(crate) async fn try_dispatch_sub_workflow(
        &self,
        node_idx: NodeIndex,
        node_id: Uuid,
        execution_id: Uuid,
        dispatcher: &Arc<dyn NodeDispatcher>,
        worker_shared_key: &Option<WorkerSharedKey>,
        results: &HashMap<Uuid, JsonValue>,
    ) -> Option<JsonValue> {
        let (
            _,
            _,
            Some(SystemNodeKind::SubWorkflow {
                workflow_id: sub_wf_id,
                timeout_secs: _,
            }),
        ) = self.node_meta.get(&node_id)?
        else {
            return None;
        };
        let sub_wf_id = *sub_wf_id;
        let inputs = self.gather_inputs(node_idx, results);
        // Propagate the parent's `__trigger_input__` into the child's
        // trigger envelope so the scaffold's "always preserved" contract
        // survives sub-workflow composition. Without this, a chained
        // pipeline like `orchestrator → pr-triage → ask-my-memory` loses
        // the user's original question at the first hop — the child
        // sees only its direct upstream's output and has no way to
        // reach the outer trigger.
        //
        // The child's `extract_trigger_input` helper unwraps the
        // `__trigger_input__` key, so downstream nodes see the *root*
        // user trigger no matter how deep the composition. When the
        // upstream output is itself a map, we merge rather than
        // replace — upstream fields still reach the child, plus the
        // preserved outer trigger as a reserved key.
        let parent_trigger = self.extract_trigger_input(results);
        let child_trigger = match (parent_trigger, &inputs) {
            (Some(pti), JsonValue::Object(existing)) => {
                let mut merged = existing.clone();
                merged.insert("__trigger_input__".to_string(), pti);
                JsonValue::Object(merged)
            }
            (Some(pti), _) => {
                // Non-object upstream (scalar or null): build an envelope
                // so the __trigger_input__ key has somewhere to live.
                let mut m = serde_json::Map::new();
                if !inputs.is_null() {
                    m.insert("input".to_string(), inputs.clone());
                }
                m.insert("__trigger_input__".to_string(), pti);
                JsonValue::Object(m)
            }
            (None, _) => inputs,
        };
        tracing::info!(
            %node_id,
            sub_workflow_id = %sub_wf_id,
            "SubWorkflow node — executing sub-workflow"
        );
        // Fire-and-forget node_started so downstream node_started events
        // aren't held up by the event sink's network I/O.
        crate::emit_event_spawn(
            &self.event_sink,
            talos_workflow_engine_core::NodeEventWrite {
                execution_id,
                event_type: "node_started".to_string(),
                node_id: Some(node_id),
                status: "Running".to_string(),
                log_message: None,
                iteration_index: None,
                error_class: None,
                // `node_started` for the sub-workflow span. The measurement is
                // bound on the matching completion/failure event below.
                duration_ms: None,
            },
        );
        let dispatch_started = std::time::Instant::now();
        let output = self
            .dispatch_subworkflow(
                child_trigger,
                sub_wf_id,
                dispatcher.clone(),
                worker_shared_key.clone(),
            )
            .await;
        let elapsed_ms = dispatch_started.elapsed().as_millis() as u64;
        // Awaited completion event preserves ordering with the next
        // dispatch loop's node_started — without it, a fast downstream
        // node could race ahead of this node_completed in the events
        // table and the trace builder would show out-of-order activity.
        let is_error = output_reports_error(&output);
        let (event_type, status, log_message) = if is_error {
            (
                "node_failed",
                "Failed",
                output
                    .get("error_message")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
            )
        } else {
            (
                "node_completed",
                "Completed",
                Some(format!("sub_workflow duration_ms={}", elapsed_ms)),
            )
        };
        if let Some(ref sink) = self.event_sink {
            sink.emit(talos_workflow_engine_core::NodeEventWrite {
                execution_id,
                event_type: event_type.to_string(),
                node_id: Some(node_id),
                status: status.to_string(),
                log_message,
                iteration_index: None,
                error_class: None,
                // MONOTONIC: `dispatch_started` above is a
                // `std::time::Instant`. Before this, `elapsed_ms` was
                // FORMATTED INTO PROSE on the success branch
                // (`log_message = "sub_workflow duration_ms={}"`) while the
                // `duration_ms` COLUMN it belongs in was left to the
                // trigger's wall-clock subtraction — a measurement rendered
                // to a string beside the field that wanted it. It is bound
                // on BOTH branches: a sub-workflow that fails took just as
                // long as one that succeeded.
                duration_ms: talos_workflow_engine_core::NodeEventWrite::monotonic_ms(elapsed_ms),
            })
            .await;
        }
        Some(output)
    }

    /// [`SystemNodeKind::FanIn`] — join parent-branch outputs per the
    /// configured [`JoinMode`](talos_workflow_engine_core::JoinMode)
    /// and (optionally) transform via an aggregation expression.
    pub(crate) fn try_dispatch_fan_in(
        &self,
        node_idx: NodeIndex,
        node_id: Uuid,
        results: &HashMap<Uuid, JsonValue>,
    ) -> Option<JsonValue> {
        let (
            _,
            _,
            Some(SystemNodeKind::FanIn {
                join_mode,
                aggregation_expr,
            }),
        ) = self.node_meta.get(&node_id)?
        else {
            return None;
        };
        Some(self.aggregate_fan_in(node_idx, results, join_mode, aggregation_expr))
    }

    /// Generic skip-condition check that fires before any node-kind
    /// handler. When the node's `__skip_condition` expression evaluates
    /// truthy, returns `Some(__skipped envelope)`; the scheduler
    /// inserts the envelope into `results` and unblocks successors
    /// without dispatching the node.
    ///
    /// The trigger node's output is overlaid onto the skip-condition
    /// context so expressions can reference trigger-level fields
    /// without every upstream chain explicitly propagating them.
    ///
    /// # An expression that FAILS to evaluate is not an expression that
    /// returned false
    ///
    /// This is the platform's one FAIL-OPEN condition. `false` here means
    /// "do not skip", so a broken expression RUNS the node its author gated —
    /// a typo in `"dry_run == true"` fires the send. The default is
    /// deliberately NOT flipped (failing closed would silently DROP work, and
    /// would change behaviour for every workflow whose condition is merely
    /// currently-false), so the failure is made VISIBLE instead:
    ///
    /// * `talos_condition_eval_failures_total{kind="skip_condition"}` — the
    ///   alertable signal, incremented in
    ///   [`ParallelWorkflowEngine::eval_condition`].
    /// * a `condition_eval_failed` WARN carrying the node id and label, so an
    ///   operator can answer "which node ran because its gate broke?" from
    ///   the logs of a single execution.
    ///
    /// Authoring-time validation is the cheaper catch and is enforced on
    /// every MCP write path (`add_skip_condition`, `add_node_to_workflow`,
    /// `update_node_config` update/merge) — a skip condition that cannot
    /// PARSE is now rejected before it is ever persisted. This path remains
    /// the backstop for the failures parsing cannot see: an unbound variable,
    /// a non-bool result, an operation-limit trip.
    pub(crate) fn check_skip_condition(
        &self,
        node_idx: NodeIndex,
        node_id: Uuid,
        execution_id: Uuid,
        results: &HashMap<Uuid, JsonValue>,
    ) -> Option<JsonValue> {
        let skip_cond = self
            .node_configs
            .get(&node_id)
            .and_then(|cfg| cfg.get("__skip_condition"))
            .and_then(|v| v.as_str())?;
        let mut skip_context = self.gather_inputs(node_idx, results);
        if let Some(trigger_id) = self
            .node_labels
            .iter()
            .find(|(_, label)| label.as_str() == "__trigger__")
            .map(|(uuid, _)| *uuid)
        {
            if let Some(trigger_val) = results.get(&trigger_id) {
                if let (Some(obj), Some(ctx_obj)) =
                    (trigger_val.as_object(), skip_context.as_object_mut())
                {
                    for (k, v) in obj {
                        ctx_obj.entry(k.clone()).or_insert(v.clone());
                    }
                }
            }
        }
        match self.eval_condition(
            crate::condition_eval::ConditionKind::Skip,
            skip_cond,
            &skip_context,
        ) {
            Ok(true) => {}
            // Evaluated cleanly and said "don't skip" — the ordinary case.
            Ok(false) => return None,
            Err(error) => {
                // The counter and the kind-level WARN already fired inside
                // `eval_condition`. This second line adds what only this call
                // site knows: WHICH node ran anyway. Without it the operator
                // has a rate but no way to reach the workflow. The node label
                // and uuid only — never the context, which `eval_condition`
                // already logged scrubbed.
                tracing::warn!(
                    target: "talos_workflow_engine",
                    event_kind = "skip_condition_failed_open",
                    %execution_id,
                    %node_id,
                    node_label = %self.progress_label(node_id),
                    skip_condition = %skip_cond,
                    error = %error,
                    "skip_condition could not be evaluated — the node was NOT \
                     skipped and RAN. Validate the expression with \
                     test_condition against a representative payload."
                );
                return None;
            }
        }
        tracing::info!(
            %node_id,
            skip_condition = %skip_cond,
            "Node skipped by skip_condition"
        );
        self.emit_node_skipped_event(execution_id, node_id);
        Some(serde_json::json!({
            "__skipped": true,
            "reason": "skip_condition",
        }))
    }

    /// [`SystemNodeKind::ErrorHandler`] — filter by error pattern.
    ///
    /// Returns `None` when the node either isn't an `ErrorHandler` or
    /// its pattern (if any) matched the upstream error — the scheduler
    /// falls through to regular single-node dispatch. Returns
    /// `Some(__skipped envelope)` when the pattern was set and did not
    /// match — the node is short-circuited without running its module.
    pub(crate) fn try_dispatch_error_handler(
        &self,
        node_idx: NodeIndex,
        node_id: Uuid,
        results: &HashMap<Uuid, JsonValue>,
    ) -> Option<JsonValue> {
        let (_, _, Some(SystemNodeKind::ErrorHandler { error_pattern })) =
            self.node_meta.get(&node_id)?
        else {
            return None;
        };
        // No pattern → fall through to regular dispatch. The handler
        // module runs on *every* upstream error.
        let pattern = error_pattern.as_ref()?;
        let inputs = self.gather_inputs(node_idx, results);
        let error_msg = inputs
            .get("error_message")
            .or_else(|| {
                // Check parent outputs for `__error` payloads.
                inputs
                    .as_object()
                    .and_then(|obj| obj.values().find_map(|v| v.get("error_message")))
            })
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if error_msg.contains(pattern.as_str()) {
            // Pattern matched: let regular dispatch handle this error.
            return None;
        }
        // Pattern didn't match: short-circuit; the handler module
        // doesn't run and the error propagates down untouched.
        Some(serde_json::json!({
            "__skipped": true,
            "reason": "error_pattern_mismatch",
        }))
    }

    /// [`SystemNodeKind::DynamicDispatch`] — evaluate a Rhai
    /// expression against the gathered input to select a target
    /// workflow (by UUID or name), then run it via the adapter set's
    /// sub-engine path.
    ///
    /// Returns:
    ///   - `None` — not a `DynamicDispatch` node
    ///   - `Some(Ok(value))` — dispatch succeeded; caller stores and continues
    ///   - `Some(Err(message))` — dispatch target unresolved or sub-workflow
    ///     failed; caller should route through the normal completion-failure
    ///     path so the workflow actually fails (respecting `continue_on_error`
    ///     + error edges). Prior versions stored the error envelope and let
    ///     the workflow return `completed` despite the dispatch failing —
    ///     same class of bug as verify-node (b69aad5) and `confidence_gate`
    ///     (a7dd2b3); this commit is the third instance of the same fix.
    pub(crate) async fn try_dispatch_dynamic_dispatch(
        &self,
        node_idx: NodeIndex,
        node_id: Uuid,
        dispatcher: &Arc<dyn NodeDispatcher>,
        worker_shared_key: &Option<WorkerSharedKey>,
        results: &HashMap<Uuid, JsonValue>,
    ) -> Option<Result<JsonValue, String>> {
        let (
            _,
            _,
            Some(SystemNodeKind::DynamicDispatch {
                dispatch_expression,
                timeout_secs: _,
            }),
        ) = self.node_meta.get(&node_id)?
        else {
            return None;
        };
        let expression = dispatch_expression.clone();
        let inputs = self.gather_inputs(node_idx, results);

        tracing::info!(
            %node_id,
            expression = %expression,
            "DynamicDispatch node — evaluating dispatch expression"
        );

        let dispatch_target = evaluate_dispatch_expression(&expression, &inputs);

        // Resolve the target + run the sub-workflow, building either
        // the success envelope or an error message. The error message
        // flows through `handle_completed_future` at the reactor's
        // caller so continue_on_error + error edges still work.
        let outcome: Result<JsonValue, String> = match dispatch_target {
            Err(e) => Err(e),
            Ok(target_id_or_name) => {
                let target_wf_id: Option<Uuid> = if let Ok(id) = Uuid::parse_str(&target_id_or_name)
                {
                    Some(id)
                } else if let Some(store) = self.graph_store_arc() {
                    store
                        .resolve_by_name(
                            &target_id_or_name,
                            self.user_id().unwrap_or_else(Uuid::nil),
                        )
                        .await
                        .map_err(|e| {
                            tracing::warn!(error = %e, "DB query failed during execution");
                            e
                        })
                        .ok()
                        .flatten()
                } else {
                    None
                };

                match target_wf_id {
                    None => {
                        // Loud signal: a `DynamicDispatch` target that
                        // can't be resolved is almost always a missing
                        // `WorkflowGraphStore::resolve_by_name`
                        // override. The default-impl returns `None`
                        // for everything; without this warning the
                        // failure surfaces only as the per-node error
                        // envelope, which is easy to miss in logs.
                        let store_wired = self.graph_store_arc().is_some();
                        tracing::warn!(
                            %node_id,
                            target = %target_id_or_name,
                            graph_store_wired = store_wired,
                            "DynamicDispatch could not resolve target. \
                             If `target` is a name (not a UUID), make sure your \
                             WorkflowGraphStore impl overrides `resolve_by_name` — \
                             the default trait impl returns None for every name."
                        );
                        Err(format!(
                            "Could not resolve dispatch target: {target_id_or_name}"
                        ))
                    }
                    Some(sub_wf_id) => {
                        tracing::info!(
                            %node_id,
                            dispatched_workflow_id = %sub_wf_id,
                            "DynamicDispatch resolved to workflow"
                        );
                        let sub_result = self
                            .run_dispatched_subworkflow(
                                sub_wf_id,
                                &inputs,
                                dispatcher,
                                worker_shared_key,
                                DispatchedOrigin::DynamicDispatch {
                                    resolved_target: target_id_or_name.clone(),
                                },
                            )
                            .await;
                        // `run_dispatched_subworkflow` returns a JsonValue that
                        // may itself carry `__error: true` when the child
                        // failed. Promote that into the Err variant so the
                        // workflow-level failure path engages — matches the
                        // capability_dispatch caller's detection.
                        let is_error = output_reports_error(&sub_result);
                        if is_error {
                            let msg = sub_result
                                .get("error_message")
                                .and_then(|v| v.as_str())
                                .unwrap_or("DynamicDispatch sub-workflow failed")
                                .to_string();
                            Err(msg)
                        } else {
                            Ok(sub_result)
                        }
                    }
                }
            }
        };

        Some(outcome)
    }

    /// [`SystemNodeKind::CapabilityDispatch`] — find the best-matching
    /// workflow for the declared required capabilities and run it.
    pub(crate) async fn try_dispatch_capability_dispatch(
        &self,
        node_idx: NodeIndex,
        node_id: Uuid,
        dispatcher: &Arc<dyn NodeDispatcher>,
        worker_shared_key: &Option<WorkerSharedKey>,
        results: &HashMap<Uuid, JsonValue>,
    ) -> Option<JsonValue> {
        let (
            _,
            _,
            Some(SystemNodeKind::CapabilityDispatch {
                required_capabilities,
                fallback_workflow_id,
                timeout_secs: _,
            }),
        ) = self.node_meta.get(&node_id)?
        else {
            return None;
        };
        let caps = required_capabilities.clone();
        let fallback = *fallback_workflow_id;
        let inputs = self.gather_inputs(node_idx, results);

        tracing::info!(
            %node_id,
            capabilities = ?caps,
            "CapabilityDispatch node — finding best matching workflow"
        );

        let Some(store) = self.graph_store_arc() else {
            return Some(serde_json::json!({
                "__error": true,
                "error_message": "Registry not available for capability dispatch",
            }));
        };

        let matching_row = store
            .resolve_by_capabilities(&caps, self.user_id().unwrap_or_else(Uuid::nil))
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "DB query failed during execution");
                e
            })
            .ok()
            .flatten();

        let (sub_wf_id, sub_wf_name, is_fallback) = match matching_row {
            Some((id, name)) => (id, name, false),
            None => match fallback {
                Some(fb_id) => {
                    tracing::info!(
                        %node_id,
                        fallback_workflow_id = %fb_id,
                        required_capabilities = ?caps,
                        "CapabilityDispatch: no capability match — invoking fallback workflow"
                    );
                    (fb_id, "<fallback>".to_string(), true)
                }
                None => {
                    // Loud signal: same shape as DynamicDispatch's
                    // unresolved-target warning. The default
                    // `WorkflowGraphStore::resolve_by_capabilities` impl
                    // returns None for every input, so a missing override
                    // looks identical to "no workflow matches" without
                    // this warning.
                    tracing::warn!(
                        %node_id,
                        required_capabilities = ?caps,
                        "CapabilityDispatch could not resolve a workflow and no \
                         fallback_workflow_id is set. If you have workflows \
                         declaring these capabilities, make sure your \
                         WorkflowGraphStore impl overrides \
                         `resolve_by_capabilities` — the default trait impl \
                         returns None for every input."
                    );
                    return Some(serde_json::json!({
                        "__error": true,
                        "error_message": format!("No workflow found matching capabilities: {caps:?}"),
                    }));
                }
            },
        };
        tracing::info!(
            %node_id,
            dispatched_workflow_id = %sub_wf_id,
            dispatched_workflow_name = %sub_wf_name,
            is_fallback,
            "CapabilityDispatch resolved to workflow"
        );

        Some(
            self.run_dispatched_subworkflow(
                sub_wf_id,
                &inputs,
                dispatcher,
                worker_shared_key,
                DispatchedOrigin::CapabilityDispatch {
                    workflow_name: sub_wf_name,
                    matched_capabilities: caps,
                    is_fallback,
                },
            )
            .await,
        )
    }

    /// Shared body for [`SystemNodeKind::DynamicDispatch`] and
    /// [`SystemNodeKind::CapabilityDispatch`]: hydrate a sub-engine
    /// from the target workflow's graph JSON, inject a `__trigger__`
    /// node carrying the parent input, run via
    /// `run_with_seed_with_transport`, and fold the labeled outputs
    /// into a result envelope.
    async fn run_dispatched_subworkflow(
        &self,
        sub_wf_id: Uuid,
        inputs: &JsonValue,
        dispatcher: &Arc<dyn NodeDispatcher>,
        worker_shared_key: &Option<WorkerSharedKey>,
        origin: DispatchedOrigin,
    ) -> JsonValue {
        if !self.has_module_fetcher() {
            return serde_json::json!({
                "__error": true,
                "error_message": "Registry not available for dispatch execution",
            });
        }
        let user_id = self.user_id().unwrap_or_else(Uuid::nil);
        let Some(graph_json) = self.get_sub_workflow_graph(sub_wf_id, user_id).await else {
            return origin.not_found_error(sub_wf_id);
        };
        let mut sub_engine = match self.adapter_set().into_engine_with_graph(&graph_json) {
            Ok(e) => e,
            Err(e) => return origin.build_error(e),
        };

        // Fail-closed binding (H2 + identity): dynamic/capability dispatch
        // builds a sub-engine that inherits the PARENT identity + ceilings
        // verbatim. Rebind to the dispatch-target's OWN actor (memory scope)
        // and narrow to most-restrictive(parent, target actor) on each ceiling
        // axis so a target workflow bound to a stricter actor can't run at the
        // caller's looser tier/write ceiling or read the caller's memory.
        self.bind_subengine_actor_and_ceilings(&mut sub_engine, sub_wf_id, user_id)
            .await;

        let clean_input = if let Some(obj) = inputs.as_object() {
            let mut cleaned = obj.clone();
            cleaned.retain(|k, _| !k.starts_with("__"));
            serde_json::Value::Object(cleaned)
        } else {
            inputs.clone()
        };

        let trigger_node_id = Uuid::new_v4();
        sub_engine.add_node(trigger_node_id, None, None, None);
        sub_engine
            .node_labels
            .insert(trigger_node_id, "__trigger__".to_string());
        let root_indices: Vec<petgraph::graph::NodeIndex> = sub_engine
            .graph
            .node_indices()
            .filter(|&idx| {
                sub_engine.graph[idx] != trigger_node_id
                    && sub_engine
                        .graph
                        .neighbors_directed(idx, Direction::Incoming)
                        .count()
                        == 0
            })
            .collect();
        for root_idx in &root_indices {
            let root_id = sub_engine.graph[*root_idx];
            let _ = sub_engine.add_edge(
                trigger_node_id,
                root_id,
                EdgeLogic {
                    source_handle: "output".to_string(),
                    target_handle: "input".to_string(),
                    mapping: None,
                    condition: None,
                    edge_type: "default".to_string(),
                },
            );
        }

        let mut initial_results = HashMap::new();
        initial_results.insert(trigger_node_id, clean_input);
        let sub_labels = sub_engine.node_labels.clone();
        let sub_execution_id = Uuid::new_v4();
        match sub_engine
            .run_with_seed_with_transport(
                dispatcher.clone(),
                worker_shared_key.clone(),
                initial_results,
                sub_execution_id,
            )
            .await
        {
            Ok(ctx) => {
                let mut sub_outputs = serde_json::Map::new();
                origin.stamp_prelude(&mut sub_outputs, sub_wf_id);
                for (nid, output) in &ctx.results {
                    if output
                        .get("__skipped")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                    {
                        continue;
                    }
                    let key = sub_labels
                        .get(nid)
                        .cloned()
                        .unwrap_or_else(|| nid.to_string());
                    if key == "__trigger__" {
                        continue;
                    }
                    sub_outputs.insert(key, ParallelWorkflowEngine::unwrap_output(output).clone());
                }
                serde_json::Value::Object(sub_outputs)
            }
            Err(e) => origin.run_error(sub_wf_id, e),
        }
    }

    /// [`SystemNodeKind::AgentLoop`] and [`SystemNodeKind::ReActLoop`]
    /// — ReAct-style iteration that re-invokes a sub-workflow body
    /// with per-iteration history injection, stopping when the body
    /// emits a `finished: true` signal or `max_iterations` is reached.
    ///
    /// Both variants share the same field shape
    /// (`body_workflow_id`, `max_iterations`, `inject_history`,
    /// `timeout_secs`) and identical runtime semantics — the variants
    /// differ only in authoring provenance (`AgentLoop` is the general
    /// shape, `ReActLoop` is the explicit `ReAct` annotation). This one
    /// dispatcher handles both so they cannot diverge at runtime.
    ///
    /// Returns `None` when the node is neither; otherwise the loop's
    /// aggregated output (or an error envelope when the pre-conditions
    /// aren't met: no user context, missing body workflow, etc.).
    #[cfg(feature = "llm-primitives")]
    #[tracing::instrument(
        level = "info",
        name = "agent_loop",
        skip_all,
        fields(node_id = %node_id),
    )]
    pub(crate) async fn try_dispatch_agent_loop(
        &self,
        node_idx: NodeIndex,
        node_id: Uuid,
        dispatcher: &Arc<dyn NodeDispatcher>,
        worker_shared_key: &Option<WorkerSharedKey>,
        results: &HashMap<Uuid, JsonValue>,
    ) -> Option<JsonValue> {
        let (body_wf_id, max_iters, do_inject_history, timeout_secs) =
            match self.node_meta.get(&node_id)? {
                (
                    _,
                    _,
                    Some(
                        SystemNodeKind::AgentLoop {
                            body_workflow_id,
                            max_iterations,
                            inject_history,
                            timeout_secs,
                        }
                        | SystemNodeKind::ReActLoop {
                            body_workflow_id,
                            max_iterations,
                            inject_history,
                            timeout_secs,
                        },
                    ),
                ) => (
                    *body_workflow_id,
                    *max_iterations,
                    *inject_history,
                    *timeout_secs,
                ),
                _ => return None,
            };
        let inputs = self.gather_inputs(node_idx, results);

        tracing::info!(
            %node_id,
            body_workflow_id = %body_wf_id,
            max_iterations = max_iters,
            "AgentLoop — starting ReAct iteration loop"
        );

        if !self.has_module_fetcher() {
            return Some(serde_json::json!({
                "__error": true,
                "error_message": "Registry not available for AgentLoop execution",
            }));
        }
        let Some(user_id) = self.user_id() else {
            return Some(serde_json::json!({
                "__error": true,
                "error_message": "user_id required for sub-workflow execution",
            }));
        };
        let Some(graph_json) = self.get_sub_workflow_graph(body_wf_id, user_id).await else {
            return Some(serde_json::json!({
                "__error": true,
                "error_message": format!("AgentLoop body workflow {body_wf_id} not found"),
            }));
        };

        let dispatcher_al = dispatcher.clone();
        let worker_shared_key_al = worker_shared_key.clone();
        let adapter_set_al = self.adapter_set();
        let inputs_al = inputs.clone();
        // Capture before the async move so each iteration sees the
        // engine-configured cap rather than the (now-removed) global
        // const. `0` is the documented disable sentinel — see
        // `set_agent_loop_max_history`.
        let max_history = self.agent_loop_max_history();
        // Fail-closed binding (H2 + identity), resolved ONCE before the loop
        // (a single DB lookup, not per-iteration) while `self` is in scope —
        // the `async move` below captures only `adapter_set_al`, not `self`.
        // The body workflow is fixed across iterations, so the resolved
        // binding is invariant. `SubworkflowBinding` is `Copy`, so it moves
        // into the closure by value; the per-iteration apply is an associated
        // fn (no `self` capture).
        let sub_binding = self.resolve_subworkflow_binding(body_wf_id, user_id).await;
        let agent_result =
            match tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), async move {
                let mut history: Vec<JsonValue> = Vec::new();
                let mut last_output = serde_json::json!({});
                let mut finished = false;
                // Track total iterations separately from history.len() —
                // history is capped at max_history entries (sliding
                // window), so history.len() would under-report when
                // max_iters > max_history.
                let mut iterations_run: u32 = 0;

                for iteration in 1..=max_iters {
                    // Build iteration input: start with clean parent inputs.
                    let mut iter_input = if let Some(obj) = inputs_al.as_object() {
                        let mut cleaned = obj.clone();
                        cleaned.retain(|k, _| !k.starts_with("__"));
                        cleaned
                    } else {
                        serde_json::Map::new()
                    };

                    iter_input.insert(
                        "__agent_iteration__".to_string(),
                        serde_json::json!(iteration),
                    );

                    if do_inject_history && max_history > 0 && !history.is_empty() {
                        iter_input.insert(
                            "__agent_history__".to_string(),
                            serde_json::Value::Array(history.clone()),
                        );
                    }

                    let iter_input_value = serde_json::Value::Object(iter_input);

                    let iter_result =
                        match adapter_set_al.clone().into_engine_with_graph(&graph_json) {
                            Ok(mut sub_engine) => {
                                // Fail-closed binding (H2 + identity): the
                                // per-iteration sub-engine inherits the PARENT
                                // identity + ceilings from `adapter_set_al`;
                                // rebind to the body-workflow's own actor and
                                // tighten to the pre-resolved
                                // most-restrictive(parent, body-actor) ceilings.
                                if let Some(binding) = sub_binding {
                                    ParallelWorkflowEngine::apply_subworkflow_binding(
                                        &mut sub_engine,
                                        &binding,
                                    );
                                }
                                let sub_execution_id = Uuid::new_v4();
                                let trigger_node_id = Uuid::new_v4();
                                sub_engine.add_node(trigger_node_id, None, None, None);
                                sub_engine
                                    .node_labels
                                    .insert(trigger_node_id, "__trigger__".to_string());

                                let root_indices: Vec<petgraph::graph::NodeIndex> = sub_engine
                                    .graph
                                    .node_indices()
                                    .filter(|&idx| {
                                        sub_engine.graph[idx] != trigger_node_id
                                            && sub_engine
                                                .graph
                                                .neighbors_directed(idx, Direction::Incoming)
                                                .count()
                                                == 0
                                    })
                                    .collect();
                                for root_idx in &root_indices {
                                    let root_id = sub_engine.graph[*root_idx];
                                    let _ = sub_engine.add_edge(
                                        trigger_node_id,
                                        root_id,
                                        EdgeLogic {
                                            source_handle: "output".to_string(),
                                            target_handle: "input".to_string(),
                                            mapping: None,
                                            condition: None,
                                            edge_type: "default".to_string(),
                                        },
                                    );
                                }

                                let mut initial_results = HashMap::new();
                                initial_results.insert(trigger_node_id, iter_input_value);

                                let sub_labels = sub_engine.node_labels.clone();
                                match sub_engine
                                    .run_with_seed_with_transport(
                                        dispatcher_al.clone(),
                                        worker_shared_key_al.clone(),
                                        initial_results,
                                        sub_execution_id,
                                    )
                                    .await
                                {
                                    Ok(ctx) => {
                                        let mut sub_outputs = serde_json::Map::new();
                                        for (nid, output) in &ctx.results {
                                            if output
                                                .get("__skipped")
                                                .and_then(|v| v.as_bool())
                                                .unwrap_or(false)
                                            {
                                                continue;
                                            }
                                            let key = sub_labels
                                                .get(nid)
                                                .cloned()
                                                .unwrap_or_else(|| nid.to_string());
                                            if key == "__trigger__" {
                                                continue;
                                            }
                                            // Strip reserved `__*` metadata keys (e.g.
                                            // `__fuel_consumed__`, `__dispatched_by`) from
                                            // the per-node body output. These are worker
                                            // / engine annotations, not user payload —
                                            // and when inject_history=true, the full
                                            // iter_result is fed back into the NEXT
                                            // iteration's module input. Leaving `__*`
                                            // keys in place balloons the input JSON the
                                            // body must re-parse, causing `__fuel_consumed__`
                                            // to appear to accumulate across iterations
                                            // (21k → 54k → 79k). Mirrors the iter_input
                                            // cleanup at the top of the loop body.
                                            let mut cleaned =
                                                ParallelWorkflowEngine::unwrap_output(output)
                                                    .clone();
                                            if let Some(obj) = cleaned.as_object_mut() {
                                                obj.retain(|k, _| !k.starts_with("__"));
                                            }
                                            sub_outputs.insert(key, cleaned);
                                        }
                                        // Single-terminal collapse — matches the convention
                                        // used by `collapse_subworkflow_output` for judge /
                                        // ensemble / sub_workflow. Without this, the
                                        // iter_result is a label-wrapped map (e.g.
                                        // `{"step": {"finished": true}}`) and the
                                        // finished-signal check at the top level misses
                                        // the flag — the loop runs to max_iterations
                                        // despite the body clearly signalling done.
                                        if sub_outputs.len() == 1 {
                                            sub_outputs
                                                .into_values()
                                                .next()
                                                .unwrap_or(serde_json::Value::Null)
                                        } else {
                                            serde_json::Value::Object(sub_outputs)
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            iteration,
                                            error = %e,
                                            "AgentLoop body workflow failed on iteration"
                                        );
                                        serde_json::json!({
                                            "__error": true,
                                            "error_message": e.to_string(),
                                        })
                                    }
                                }
                            }
                            Err(e) => serde_json::json!({
                                "__error": true,
                                "error_message": format!("Failed to build agent body: {e}"),
                            }),
                        };

                    // Check for finish signals in the iteration output.
                    let iter_finished = iter_result
                        .get("finished")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                        || iter_result
                            .get("action")
                            .and_then(|v| v.as_str())
                            .map(|s| s.eq_ignore_ascii_case("FINISH"))
                            .unwrap_or(false);

                    // Cap history entries to prevent unbounded memory
                    // growth when inject_history is true and iterations
                    // produce large outputs. `max_history == 0` opts
                    // out of history accumulation entirely (matches
                    // `inject_history: false` semantics on the loop).
                    iterations_run += 1;
                    if max_history > 0 {
                        if history.len() >= max_history {
                            history.remove(0);
                        }
                        history.push(iter_result.clone());
                    }
                    last_output = iter_result;

                    if iter_finished {
                        finished = true;
                        break;
                    }
                }

                if !finished {
                    tracing::warn!(
                        max_iterations = max_iters,
                        "AgentLoop reached max_iterations without finish signal"
                    );
                }

                serde_json::json!({
                    "iterations": iterations_run,
                    "finished": finished,
                    "history": history,
                    "final_output": last_output,
                })
            })
            .await
            {
                Ok(result) => result,
                Err(_) => {
                    tracing::warn!(
                        %node_id,
                        timeout_secs,
                        "AgentLoop timed out"
                    );
                    serde_json::json!({
                        "__error": true,
                        "error_message": format!("AgentLoop timed out after {timeout_secs}s"),
                    })
                }
            };

        Some(agent_result)
    }

    /// [`SystemNodeKind::Loop`] — re-dispatch a body node until
    /// `condition` returns false or `max_iterations` is hit.
    ///
    /// The body node id is read from the loop node's `body_node_id`
    /// config key. Each iteration merges the previous iteration's
    /// output into the body's input and injects `iteration_count`
    /// / `iteration` into the evaluation context so conditions like
    /// `iteration_count < 3` work without the body echoing the counter.
    pub(crate) async fn try_dispatch_loop(
        &self,
        node_idx: NodeIndex,
        node_id: Uuid,
        execution_id: Uuid,
        dispatcher: &Arc<dyn NodeDispatcher>,
        worker_shared_key: &Option<WorkerSharedKey>,
        results: &HashMap<Uuid, JsonValue>,
    ) -> Option<JsonValue> {
        let (
            _,
            _,
            Some(SystemNodeKind::Loop {
                condition,
                max_iterations,
            }),
        ) = self.node_meta.get(&node_id)?
        else {
            return None;
        };
        let condition = condition.clone();
        let max_iters = *max_iterations;
        let inputs = self.gather_inputs(node_idx, results);

        // Find the body_node_id from node config.
        let body_node_id_str = self
            .node_configs
            .get(&node_id)
            .and_then(|c| c.get("body_node_id"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let loop_result = match body_node_id_str {
            None => serde_json::json!({
                "__error": true,
                "error_message": "Loop node missing body_node_id in config",
                "termination_reason": "no_body_node",
            }),
            Some(body_rf_id) => {
                let body_uuid = self
                    .node_labels
                    .iter()
                    .find(|(_, label)| label.as_str() == body_rf_id)
                    .map(|(uuid, _)| *uuid);
                let body_module_id = body_uuid
                    .and_then(|u| self.node_meta.get(&u))
                    .and_then(|(mid, _, _)| *mid);

                match (body_uuid, body_module_id) {
                    (None, _) => serde_json::json!({
                        "__error": true,
                        "error_message": format!("Body node '{}' not found in workflow", body_rf_id),
                        "termination_reason": "body_not_found",
                    }),
                    (Some(_), None) => serde_json::json!({
                        "__error": true,
                        "error_message": format!("Body node '{}' has no module_id", body_rf_id),
                        "termination_reason": "body_missing_module",
                    }),
                    (Some(body_uuid), Some(body_module_id)) => {
                        self.run_loop_iterations(
                            node_id,
                            execution_id,
                            body_uuid,
                            body_module_id,
                            inputs,
                            &condition,
                            max_iters,
                            dispatcher,
                            worker_shared_key,
                            results,
                        )
                        .await
                    }
                }
            }
        };

        Some(loop_result)
    }

    /// Close out one loop iteration's `module_executions` row.
    ///
    /// Every exit path from a dispatched iteration calls this — success,
    /// `__error` envelope, and dispatch error alike — so a per-iteration row
    /// can never linger in `'running'` after the loop ends. A stuck-running
    /// row is not a cosmetic defect: the crash-recovery and stale-execution
    /// sweeps read that status, and "running" rows that nothing will ever
    /// complete are exactly the phantom the race-safe INSERT exists to avoid.
    ///
    /// Payload/error redaction and the best-effort contract live in the
    /// shared `finalize_module_execution_row` chokepoint
    /// (`engine_dispatch_single.rs`), which every engine dispatch path now
    /// routes through. This wrapper stays for the loop path's call sites and
    /// for the name the surrounding code reads by.
    async fn complete_loop_iteration_row(
        &self,
        iter_exec_id: Uuid,
        status: &str,
        output: &JsonValue,
        duration_ms: Option<i32>,
        error_message: Option<&str>,
    ) {
        self.finalize_module_execution_row(
            iter_exec_id,
            status,
            output,
            duration_ms,
            error_message,
        )
        .await;
    }

    /// Body of the [`SystemNodeKind::Loop`] iteration loop. Kept on
    /// its own method so the happy path in
    /// [`try_dispatch_loop`](Self::try_dispatch_loop) stays readable —
    /// this is the inner "per-iteration: evaluate condition, dispatch
    /// body, collect output" machinery.
    #[allow(clippy::too_many_arguments)]
    async fn run_loop_iterations(
        &self,
        node_id: Uuid,
        execution_id: Uuid,
        body_uuid: Uuid,
        body_module_id: Uuid,
        inputs: JsonValue,
        condition: &str,
        max_iters: u32,
        dispatcher: &Arc<dyn NodeDispatcher>,
        worker_shared_key: &Option<WorkerSharedKey>,
        results: &HashMap<Uuid, JsonValue>,
    ) -> JsonValue {
        let mut current_input = inputs.clone();
        let mut iteration = 0u32;
        let mut last_output = current_input.clone();
        // Distinguishes how the loop exited so the outer scheduler
        // (and downstream consumers) can tell "condition stopped it"
        // from "body failed silently". Initialized to `condition_false`
        // — the fallthrough path once the condition evaluates false.
        // Rewritten below for the max-iterations / body-error /
        // module-fetch-error paths.
        let mut termination_reason: &'static str = "condition_false";
        let mut terminating_error: Option<String> = None;

        // Extract `__trigger_input__` to inject into every loop iteration.
        // Source: (1) gathered inputs, (2) the `__trigger__` node's
        // output in `results`.
        let trigger_input_val = inputs
            .as_object()
            .and_then(|o| o.get("__trigger_input__"))
            .cloned()
            .or_else(|| {
                self.node_labels
                    .iter()
                    .find(|(_, label)| label.as_str() == "__trigger__")
                    .and_then(|(uuid, _)| results.get(uuid))
                    .cloned()
            });

        // MCP-H6: hoist the per-iteration DB-read costs out of the
        // loop body. Pre-fix every iteration re-ran:
        //   1. `fetch_module(body_uuid)` — 1 SELECT against `modules`
        //      (no in-process cache).
        //   2. `build_encrypted_secrets(body_module_id, exec, key)` —
        //      1 SELECT against `secrets` + per-row AES decrypt +
        //      LLM-keys resolve + AES encrypt of the result.
        // For a 100-iteration loop that's ~300 extra DB round-trips
        // per execution (3 SELECTs × 100 iterations). Module bytes
        // and module-grant secrets are invariant across iterations —
        // resolve them once at loop entry and reuse. If the loop
        // exits without dispatching the body (condition false on
        // entry), we eat the prefetch cost but the cache is one
        // SELECT, not 100.
        //
        // 2026-05-28 audit Perf#6 semantic note: the cached
        // `encrypted_secrets` captures vault values AT LOOP ENTRY.
        // SecretsManager's LLM-keys cache has a 60s TTL so rotations
        // normally propagate within a minute; a long-running loop
        // (e.g. 100 iters × 10s/iter = ~17 min) holds the snapshot
        // for the loop's full lifetime. This matches the workflow
        // execution-consistency model (one execution = one secret
        // snapshot) — an operator who rotates a vault key mid-run
        // sees the new value on the NEXT execution, not the
        // in-flight one. Document the semantic so future readers
        // don't mistake it for a cache-invalidation bug.
        let cached_wasm_module = match self
            .fetch_module(body_uuid)
            .await
            .map_err(|e| anyhow::anyhow!(e))
        {
            Ok(m) => Some(m),
            Err(e) => {
                // Defer the error report to the first iteration so the
                // shape of the engine output is identical to pre-fix.
                tracing::warn!(
                    body_uuid = %body_uuid,
                    err = %e,
                    "loop body module fetch failed at prefetch"
                );
                None
            }
        };
        // RFC 0010 P3 (D3b): resolve once in whichever form the sealing mode
        // needs (inline WSK envelope OR plaintext for claim-based sealing), then
        // clone per iteration. Using the shared helper means loop bodies seal
        // exactly like single-node dispatches, so they don't fail the worker
        // downgrade guard under `TALOS_ENVELOPE_SEALING=required`.
        let cached_dispatch_secrets = self
            .build_dispatch_secrets(body_module_id, execution_id, worker_shared_key)
            .await;

        // Canonical `modules.id` for the per-iteration `module_executions`
        // rows below. Hoisted out of the loop for the same reason the module
        // bytes and secrets are (MCP-H6): a store impl is free to make this a
        // DB round-trip, and the answer is invariant across iterations.
        let iter_module_id = match self.module_execution_store {
            Some(ref store) => store.resolve_module_id(body_module_id).await,
            None => body_module_id,
        };

        while iteration < max_iters {
            // Evaluate condition against current output + loop metadata.
            // `iteration_count` is injected so conditions like
            // `iteration_count < 3` work without the body having to
            // explicitly echo the counter in its output.
            if iteration > 0 {
                let condition_ctx = if let Some(mut obj) = last_output.as_object().cloned() {
                    obj.entry("iteration_count".to_string())
                        .or_insert(serde_json::json!(iteration));
                    obj.entry("iteration".to_string())
                        .or_insert(serde_json::json!(iteration));
                    serde_json::Value::Object(obj)
                } else {
                    serde_json::json!({
                        "iteration_count": iteration,
                        "iteration": iteration,
                        "output": last_output,
                    })
                };
                if !self.eval_bool_kinded(
                    crate::condition_eval::ConditionKind::Loop,
                    condition,
                    &condition_ctx,
                ) {
                    break;
                }
            }

            iteration += 1;

            // Log iteration event via the engine's shared emit helper.
            self.emit_loop_iteration_event(execution_id, node_id, iteration, max_iters);

            // MCP-H6: reuse the prefetched module bytes. If the
            // prefetch failed, surface it now (same shape as pre-fix
            // failure).
            let wasm_module = match cached_wasm_module.as_ref() {
                Some(m) => m.clone(),
                None => {
                    let msg = "Module fetch failed at loop-body prefetch".to_string();
                    last_output = serde_json::json!({
                        "__error": true,
                        "error_message": msg.clone(),
                    });
                    termination_reason = "module_fetch_error";
                    terminating_error = Some(msg);
                    break;
                }
            };

            // The successful `cached_wasm_module` above was fetched via
            // fetch_module(body_uuid) -> get_module_for_execution(.., user_id),
            // which requires (and pre-warmed the redis cache under) this
            // user_id. So it's Some here, and it's the exact id the
            // `redis:wasm:` URI below must be scoped to (L-27). Fail-closed
            // on the unreachable None rather than emitting an unscoped key.
            let loop_user_id = match self.user_id() {
                Some(uid) => uid,
                None => {
                    let msg = "user_id required for loop-body dispatch".to_string();
                    last_output = serde_json::json!({
                        "__error": true,
                        "error_message": msg.clone(),
                    });
                    termination_reason = "module_fetch_error";
                    terminating_error = Some(msg);
                    break;
                }
            };

            // Flat-merge input + config (same pattern as regular node dispatch).
            let mut merged_input = serde_json::Map::new();
            if let Some(obj) = current_input.as_object() {
                for (k, v) in obj {
                    merged_input.insert(k.clone(), v.clone());
                }
            }
            if let Some(cfg) = self.node_configs.get(&body_uuid) {
                if cfg.is_object() && !cfg.as_object().map(|m| m.is_empty()).unwrap_or(true) {
                    merged_input.insert("config".to_string(), cfg.clone());
                    if let Some(obj) = cfg.as_object() {
                        for (k, v) in obj {
                            merged_input.entry(k.clone()).or_insert(v.clone());
                        }
                    }
                }
            }
            if !current_input.is_null() && current_input != serde_json::json!({}) {
                merged_input
                    .entry("input".to_string())
                    .or_insert(current_input.clone());
            }
            if let Some(ref ti) = trigger_input_val {
                merged_input.insert("__trigger_input__".to_string(), ti.clone());
            }
            merged_input
                .entry("iteration_count".to_string())
                .or_insert(serde_json::json!(iteration));
            merged_input
                .entry("iteration".to_string())
                .or_insert(serde_json::json!(iteration));
            let job_input = serde_json::Value::Object(merged_input);

            let body_timeout_secs = self.node_timeout_for(body_uuid).unwrap_or(30);
            // MCP-H6: reuse the prefetched encrypted_secrets. The DEK,
            // module-grant secrets, and LLM keys are invariant across
            // loop iterations, so re-resolving + re-encrypting per
            // iteration is wasted work. Clone is cheap (a small Vec<u8> +
            // nonce, or the resolved plaintext map under claim-based sealing).
            let dispatch_secrets = cached_dispatch_secrets.clone();

            // Pre-INSERT a `module_executions` row for THIS iteration, then
            // dispatch under its id — the same contract the single-node
            // (`engine_dispatch_single.rs`) and pipeline-step
            // (`engine_dispatch_pipeline.rs`) paths already honour.
            //
            // WHY (2026-07-30): this used to pass `job_id: None`, and
            // `NatsDispatcher::dispatch` minted a fresh UUID for the wire.
            // The worker stamps that UUID as the execution id on every log
            // line it publishes to `wasm.log.{id}` — but the id existed in
            // NEITHER `workflow_executions` NOR `module_executions`, so both
            // of the subscriber's `WHERE EXISTS`-guarded inserts selected
            // zero rows. Every iteration of every Loop node lost ALL of its
            // logs: host diagnostics (the `[host:*]` reason classes) AND the
            // guest's own `talos::core::logging::log`. `get_execution_logs`
            // then returned `[]`, which reads as "the module printed
            // nothing" rather than "we threw its output away". Minting the
            // id HERE and recording the row is what makes the id real.
            //
            // The row is also the per-iteration status/output record the
            // loop path never had; it is completed below on every exit path
            // so it can't linger in 'running'.
            let iter_exec_id = Uuid::new_v4();
            if let Some(ref store) = self.module_execution_store {
                if let Err(db_err) = store
                    .record_started(ExecutionStartedContext {
                        id: iter_exec_id,
                        module_id: iter_module_id,
                        user_id: loop_user_id,
                        workflow_execution_id: execution_id,
                        input: &job_input,
                        trigger_type: "webhook",
                        // Race-safe, matching single-node dispatch: a loop
                        // node runs concurrently with sibling nodes in the
                        // parallel scheduler, so a sibling's failure UPDATE
                        // can land between this INSERT and the dispatch.
                        // (Pipeline steps set this false because they are
                        // dispatched atomically as one chain.)
                        race_safe_status: true,
                        actor_id: self.actor_id(),
                    })
                    .await
                {
                    // Non-fatal: losing the audit row must not fail the
                    // iteration. It does mean this iteration's logs will be
                    // dropped downstream — which the subscriber now reports
                    // as `wasm_log_orphaned` instead of swallowing.
                    tracing::error!(
                        %iter_exec_id,
                        "module_execution_store.record_started failed for loop iteration: {}",
                        db_err
                    );
                }
            }
            let iter_started = std::time::Instant::now();

            let body_job = DispatchJob {
                execution_id,
                node_id: body_uuid,
                module_id: body_module_id,
                // Keyed to the `module_executions` row INSERTed just above,
                // so the worker's `wasm.log.{job_id}` lines have somewhere
                // to land. Never `None` here — see the block above.
                job_id: Some(iter_exec_id),
                user_id: self.user_id(),
                actor_id: self.actor_id(),
                // User-scoped redis URI (L-27): `wasm:{user_id}:{module_id}`,
                // the key the registry pre-warmed under this same `loop_user_id`
                // in the fetch above. The worker strips `redis:` and GETs it.
                module_uri: wasm_module.oci_url.clone().unwrap_or_else(|| {
                    talos_workflow_engine_core::scoped_wasm_redis_uri(loop_user_id, body_module_id)
                }),
                // Embed bytes directly so the worker doesn't depend on
                // a Redis pre-warm under a key the engine doesn't
                // control — bypasses the `wasm:{uid}:{id}` vs
                // `wasm:{id}` mismatch that broke loop iteration > 0.
                // Matches the single-node dispatch pattern in
                // `engine_dispatch_single.rs`.
                //
                // 2026-05-28 audit Perf#7 follow-up (tracked, NOT
                // shipped in the post-7879f4b sweep): each loop
                // iteration clones the full WASM blob into a fresh
                // `DispatchJob`. For a 5 MB module × 100 iters that
                // is ~500 MB of controller-side allocator churn.
                // Fix is wire-compatible (`Arc<Vec<u8>>` on both
                // `DispatchJob.wasm_bytes` and
                // `JobRequest.wasm_bytes` — `serde::Serialize` for
                // `Arc<T>` delegates to `T`, so on-wire bytes are
                // identical). Deferred: blast radius spans ~30-50
                // construction / read sites across the dispatcher
                // impls, and the savings only matter for long-loop /
                // large-module workloads. Treat as its own focused
                // PR (`perf(protocol): Arc inline wasm_bytes`) so a
                // subtle serde/Tokio interaction can be isolated
                // and reverted if needed without entangling other
                // changes.
                wasm_bytes: if crate::dispatch_bytes::embeds_inline(&wasm_module.wasm_bytes) {
                    Some(wasm_module.wasm_bytes.clone())
                } else {
                    None
                },
                // Hash is load-bearing only when the worker has to
                // fetch bytes by URI (OCI modules and oversized
                // interpreter-toolchain components — see `dispatch_bytes`);
                // inline bytes are already covered by the job-envelope HMAC.
                expected_wasm_hash: if crate::dispatch_bytes::embeds_inline(&wasm_module.wasm_bytes)
                {
                    None
                } else {
                    Some(wasm_module.content_hash.clone())
                },
                capability_world: Some(wasm_module.capability_world.clone()),
                integration_name: wasm_module.integration_name.clone(),
                input_payload: job_input,
                timeout: std::time::Duration::from_secs(body_timeout_secs),
                // Same workflow wall-clock deadline the single-node path
                // stamps: a loop body dispatches through the SAME
                // `NodeDispatcher::dispatch` / `execute_job_with_retry`
                // loop, so it clamps identically. Re-read per iteration
                // (this literal is inside the iteration loop), which is
                // what makes iteration N see less budget than iteration
                // 0 rather than the run-start value.
                deadline: self.progress.deadline(),
                // Per-node fuel precedence: the loop-body node's graph-JSON
                // `data.max_fuel` override (if set) > module-row default, then
                // the adaptive learned ceiling as a floor, clamped to the
                // engine-configured per-node ceiling. The body node's `data`
                // lands in `node_configs[body_uuid]` at graph load, so its
                // override is read via `node_config_max_fuel` — pre-fix this
                // passed a hardcoded `None`, so a body node with an explicit
                // `max_fuel` was silently ignored and the (often lower)
                // module-row default won. Shared decision point with the single
                // + pipeline paths (see `resolve_node_max_fuel`).
                max_fuel: self.resolve_node_max_fuel(
                    &body_uuid,
                    self.node_config_max_fuel(&body_uuid),
                    wasm_module.max_fuel,
                ),
                allowed_hosts: wasm_module.allowed_hosts.clone(),
                allowed_methods: wasm_module.allowed_methods.clone(),
                allowed_secrets: wasm_module.allowed_secrets.clone(),
                allowed_sql_operations: vec![],
                allow_tier2_exposure: false,
                encrypted_secrets_ciphertext: dispatch_secrets.encrypted.ciphertext,
                encrypted_secrets_nonce: dispatch_secrets.encrypted.nonce,
                // RFC 0010 P3 (D3b): claim-based sealing when the flag is on
                // (else these are None/empty and the inline ciphertext above is
                // used) — loop bodies now seal like single-node dispatches.
                plaintext_secrets: dispatch_secrets.plaintext,
                secret_paths: dispatch_secrets.secret_paths,
                priority: 100,
                dry_run: self.dry_run,
                max_llm_tier: self.max_llm_tier,
                max_write_ceiling: self.max_write_ceiling,
                egress_scope: self.egress_scope,
                // Loop-body idempotency is a follow-up; the single-node dispatch
                // path carries the engine-stamped key today.
                idempotency_key: None,
                max_retries: 2,
                backoff_ms: 500,
                retry_condition: None,
                retry_delay_expr: None,
                // Retries inside a loop iteration are internal and
                // should not inflate workflow-level retry metrics.
                emit_retry_events: false,
            };

            let dispatch_outcome = dispatcher.dispatch(body_job).await;
            // MONOTONIC (`iter_started` is an `Instant`). Wrapped in `Some` so
            // the DB keeps it instead of re-deriving `completed_at -
            // started_at`, which counts host-suspend time as work.
            let iter_duration_ms =
                Some(i32::try_from(iter_started.elapsed().as_millis()).unwrap_or(i32::MAX));

            match dispatch_outcome {
                Ok(result) => {
                    // Unwrap the engine envelope so the next iteration
                    // receives clean output, not double-wrapped input.
                    let clean = Self::unwrap_output(&result.output).clone();
                    // Body returned an `__error` envelope — treat as a
                    // body failure so the termination reason reflects
                    // reality instead of silently rolling up "looks like
                    // we ran N iterations" to the caller.
                    if output_reports_error(&clean) {
                        let msg = clean
                            .get("error_message")
                            .and_then(|v| v.as_str())
                            .unwrap_or("loop body returned an error envelope")
                            .to_string();
                        // The dispatch succeeded but the BODY reported an
                        // error — record 'failed', not 'completed'. Same
                        // reasoning as the `__error` check itself: a row
                        // that says "completed" for a failed iteration is
                        // the misleading-field class in the audit log.
                        self.complete_loop_iteration_row(
                            iter_exec_id,
                            "failed",
                            &clean,
                            iter_duration_ms,
                            Some(&msg),
                        )
                        .await;
                        last_output = clean;
                        termination_reason = "body_error";
                        terminating_error = Some(msg);
                        break;
                    }
                    self.complete_loop_iteration_row(
                        iter_exec_id,
                        "completed",
                        &clean,
                        iter_duration_ms,
                        None,
                    )
                    .await;
                    last_output = clean.clone();
                    current_input = clean;
                }
                Err(e) => {
                    let msg = e.to_string();
                    self.complete_loop_iteration_row(
                        iter_exec_id,
                        "failed",
                        &serde_json::Value::Null,
                        iter_duration_ms,
                        Some(&msg),
                    )
                    .await;
                    last_output = serde_json::json!({
                        "__error": true,
                        "error_message": msg.clone(),
                    });
                    termination_reason = "body_error";
                    terminating_error = Some(msg);
                    break;
                }
            }
        }

        if iteration >= max_iters && terminating_error.is_none() {
            tracing::warn!(
                %node_id,
                max_iterations = max_iters,
                "Loop reached maximum iterations"
            );
            termination_reason = "max_iterations";
        }

        let mut out = serde_json::Map::with_capacity(5);
        out.insert("iterations".to_string(), serde_json::json!(iteration));
        out.insert("output".to_string(), last_output);
        out.insert(
            "termination_reason".to_string(),
            serde_json::Value::String(termination_reason.to_string()),
        );
        if let Some(msg) = terminating_error {
            // Lift the error to the top level so the outer scheduler's
            // `__error` check (honoring `continue_on_error`) fires on
            // the loop node itself. Previously the error was nested
            // under `output`, which the scheduler didn't inspect — a
            // failed iteration silently produced a "completed" workflow.
            out.insert("__error".to_string(), serde_json::Value::Bool(true));
            out.insert("error_message".to_string(), serde_json::Value::String(msg));
        }
        serde_json::Value::Object(out)
    }

    /// [`SystemNodeKind::ConfidenceGate`] — evaluate the confidence
    /// signal and either emit a normal output or pause the workflow
    /// for approval.
    ///
    /// Returns `None` when the node is not a `ConfidenceGate`;
    /// otherwise a [`ConfidenceGateOutcome`] telling the caller
    /// whether to proceed or pause the scheduler.
    #[cfg(feature = "llm-primitives")]
    pub(crate) async fn try_dispatch_confidence_gate(
        &self,
        node_idx: NodeIndex,
        node_id: Uuid,
        execution_id: Uuid,
        results: &HashMap<Uuid, JsonValue>,
    ) -> Option<ConfidenceGateOutcome> {
        let (
            _,
            _,
            Some(SystemNodeKind::ConfidenceGate {
                threshold,
                confidence_path,
                on_low_confidence,
            }),
        ) = self.node_meta.get(&node_id)?
        else {
            return None;
        };
        match self
            .evaluate_confidence_gate(
                node_idx,
                results,
                execution_id,
                *threshold,
                confidence_path,
                on_low_confidence,
            )
            .await
        {
            Ok(gate_result) => {
                // The error mode of the gate synthesizes an
                // `{__error: true, error_message: ..., __confidence_used__: ...}`
                // envelope and returns it via `Ok`. That looks like a
                // "proceed with this value" result to the scheduler,
                // which then continues the workflow — silently
                // contradicting the documented contract that
                // `on_low_confidence: "error"` halts execution.
                //
                // Detect the marker and convert to `Halt` so the caller
                // can route through the normal failure path (where
                // continue_on_error + error edges still work).
                let is_error_envelope = output_reports_error(&gate_result);
                if is_error_envelope {
                    let msg = gate_result
                        .get("error_message")
                        .and_then(|v| v.as_str())
                        .map(String::from)
                        .unwrap_or_else(|| "Confidence gate rejected input".to_string());
                    Some(ConfidenceGateOutcome::Halt(msg))
                } else {
                    Some(ConfidenceGateOutcome::Proceed(gate_result))
                }
            }
            Err(waiting_json) => Some(ConfidenceGateOutcome::Pause {
                waiting_output: waiting_json,
            }),
        }
    }

    /// [`SystemNodeKind::Ensemble`] — run N copies of a child
    /// workflow and consolidate the outputs via a consensus strategy.
    #[cfg(feature = "llm-primitives")]
    #[tracing::instrument(
        level = "info",
        name = "ensemble",
        skip_all,
        fields(node_id = %node_id),
    )]
    pub(crate) async fn try_dispatch_ensemble(
        &self,
        node_idx: NodeIndex,
        node_id: Uuid,
        dispatcher: &Arc<dyn NodeDispatcher>,
        worker_shared_key: &Option<WorkerSharedKey>,
        results: &HashMap<Uuid, JsonValue>,
    ) -> Option<JsonValue> {
        let (
            _,
            _,
            Some(SystemNodeKind::Ensemble {
                child_workflow_id,
                count,
                consensus,
                judge_workflow_id,
                timeout_secs: _,
            }),
        ) = self.node_meta.get(&node_id)?
        else {
            return None;
        };
        let child_wf_id = *child_workflow_id;
        let run_count = *count;
        let consensus_strategy = consensus.clone();
        let judge_wf_id_opt = *judge_workflow_id;
        let inputs = self.gather_inputs(node_idx, results);

        Some(
            self.dispatch_ensemble(
                inputs,
                child_wf_id,
                run_count,
                consensus_strategy,
                judge_wf_id_opt,
                dispatcher.clone(),
                worker_shared_key.clone(),
            )
            .await,
        )
    }
}

/// Where a dispatched sub-workflow originated, for shaping the output
/// envelope and error messages. `DynamicDispatch` and
/// `CapabilityDispatch` share the sub-engine-build machinery but need
/// different `__`-prefixed metadata keys in the returned envelope.
enum DispatchedOrigin {
    DynamicDispatch {
        /// The string the dispatch expression evaluated to (typically a
        /// workflow id or name). Stamped on the output as
        /// `__dispatch_branch__` so traces show which branch fired
        /// without re-running with verbose logging.
        resolved_target: String,
    },
    CapabilityDispatch {
        workflow_name: String,
        matched_capabilities: Vec<String>,
        /// True when the capability lookup returned no match and the
        /// node's `fallback_workflow_id` was invoked instead. Stamped
        /// on the output as `__capability_dispatch_fallback`.
        is_fallback: bool,
    },
}

impl DispatchedOrigin {
    fn not_found_error(&self, sub_wf_id: Uuid) -> JsonValue {
        match self {
            Self::DynamicDispatch { .. } => serde_json::json!({
                "__error": true,
                "error_message": format!("Dispatched workflow {sub_wf_id} not found"),
            }),
            Self::CapabilityDispatch { .. } => serde_json::json!({
                "__error": true,
                "error_message": format!("Capability-dispatched workflow {sub_wf_id} graph not found"),
            }),
        }
    }

    fn build_error(&self, e: impl std::fmt::Display) -> JsonValue {
        match self {
            Self::DynamicDispatch { .. } => serde_json::json!({
                "__error": true,
                "error_message": format!("Failed to build dispatched workflow engine: {e}"),
            }),
            Self::CapabilityDispatch { .. } => serde_json::json!({
                "__error": true,
                "error_message": format!("Failed to build capability-dispatched engine: {e}"),
            }),
        }
    }

    fn run_error(&self, sub_wf_id: Uuid, e: impl std::fmt::Display) -> JsonValue {
        match self {
            Self::DynamicDispatch { .. } => {
                tracing::error!(dispatched_workflow_id = %sub_wf_id, error = %e, "Dispatched workflow failed");
                serde_json::json!({
                    "__error": true,
                    "error_message": format!("Dispatched workflow failed: {e}"),
                })
            }
            Self::CapabilityDispatch { .. } => {
                tracing::error!(dispatched_workflow_id = %sub_wf_id, error = %e, "Capability-dispatched workflow failed");
                serde_json::json!({
                    "__error": true,
                    "error_message": format!("Capability-dispatched workflow failed: {e}"),
                })
            }
        }
    }

    /// Seed the output envelope with origin-specific metadata keys
    /// before the labeled per-node outputs get folded in.
    ///
    /// Every dispatch origin stamps `__dispatched_by` and
    /// `__dispatch_branch__` so callers can introspect dispatch
    /// behaviour from the trace alone — no need to re-run with
    /// verbose logging or correlate by workflow id.
    fn stamp_prelude(&self, out: &mut serde_json::Map<String, JsonValue>, sub_wf_id: Uuid) {
        out.insert(
            "__dispatched_workflow_id__".to_string(),
            serde_json::json!(sub_wf_id.to_string()),
        );
        match self {
            Self::DynamicDispatch { resolved_target } => {
                out.insert(
                    "__dispatched_by".to_string(),
                    serde_json::json!("expression_dispatch"),
                );
                out.insert(
                    "__dispatch_branch__".to_string(),
                    serde_json::json!(resolved_target),
                );
            }
            Self::CapabilityDispatch {
                workflow_name,
                matched_capabilities,
                is_fallback,
            } => {
                out.insert(
                    "__dispatched_by".to_string(),
                    serde_json::json!("capability_dispatch"),
                );
                out.insert(
                    "__dispatched_workflow_name".to_string(),
                    serde_json::json!(workflow_name),
                );
                out.insert(
                    "__matched_capabilities".to_string(),
                    serde_json::json!(matched_capabilities),
                );
                // The branch label: the first matched capability, or
                // "<fallback>" when the lookup missed and the node's
                // fallback_workflow_id ran instead.
                let branch = if *is_fallback {
                    "<fallback>".to_string()
                } else {
                    matched_capabilities
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "<unspecified>".to_string())
                };
                out.insert("__dispatch_branch__".to_string(), serde_json::json!(branch));
                if *is_fallback {
                    out.insert(
                        "__capability_dispatch_fallback".to_string(),
                        serde_json::json!(true),
                    );
                }
            }
        }
    }
}

/// Evaluate a `DynamicDispatch` Rhai expression against the node's
/// gathered input and return the result as a string (typically a
/// workflow UUID or name).
///
/// The engine comes from `talos_rhai_sandbox::sandboxed_engine`, the ONE
/// sandbox builder for the workspace, under the `Dispatch` profile.
///
/// Before 2026-07-29 this function hand-rolled its own engine and was the
/// worst of the four such copies: it set a 10 000-operation cap, disabled
/// `eval`, and installed the dummy module resolver — but had **no**
/// `print`/`debug` discard and **no** call-depth or string/array/map caps.
/// The missing discard was a live DLP hole: `rhai::Engine::new()` wires
/// both builtins to `println!`, so a stored dispatch expression of
/// `print(inputs); "some-workflow"` dumped every gathered node input —
/// post-interpolation secrets, email bodies — to the controller's stdout
/// and therefore its container logs, past every DLP boundary the
/// persistence path applies. Dispatch expressions are the highest-risk of
/// the four: caller-authored expressions over caller-adjacent node output.
///
/// Routing through the builder therefore *adds* the discard plus the
/// depth/size caps this site never had, and keeps the 10 000-operation
/// budget as a NAMED profile (see `SandboxProfile::Dispatch`, which records
/// that the 10× is inherited from the workspace fold rather than derived,
/// and why narrowing it is a separate decision). The scope-push semantics
/// below are untouched.
///
/// # The added size caps ARE an observable change
///
/// "Adds the caps this site never had" is not the same as "changes nothing".
/// Dispatch scope carries whole gathered node outputs, and rhai applies
/// `max_string_size` / `max_array_size` / `max_map_size` to the `&mut`
/// receiver of every method call — using an AGGREGATE, RECURSIVE size for
/// that value. So under the caps:
///
/// * reads and property navigation of an oversized payload still work
///   (`route`, `inputs.route`, `nested.body`, `arr[0]`, `big == "z"`);
/// * a method call on one now fails — `inputs.body.contains("urgent")` on a
///   100 KB body, `items.len()` on a 600-element array, or even
///   `inputs.len()` when the total string content under `inputs` exceeds
///   64 KiB — with `Dispatch expression evaluation failed: Length of string
///   too large`.
///
/// Pinned below by `dispatch_size_cap_semantics`, and accepted rather than
/// deferred because the live deployment stores zero dispatch expressions
/// (checked 2026-07-29) while an uncapped engine could grow a 16 MiB string
/// inside the 10 000-operation budget. Both halves of that reasoning, and
/// the re-measure instruction for other deployments, are recorded on
/// `SandboxProfile::Dispatch`. If a deployment DOES have big-payload
/// dispatch expressions, the fix is a per-profile size cap in the builder —
/// not a hand-rolled engine here.
fn evaluate_dispatch_expression(expression: &str, inputs: &JsonValue) -> Result<String, String> {
    let rhai_engine =
        talos_rhai_sandbox::sandboxed_engine(talos_rhai_sandbox::SandboxProfile::Dispatch);
    let mut scope = rhai::Scope::new();
    // Push top-level input keys as bare scope variables (so `route == "A"` works),
    // using serde conversion so nested objects/arrays stay structured rather than
    // being stringified. Mirrors the edge-condition evaluator in
    // controller::engine::rhai_helpers::evaluate_condition.
    if let Some(obj) = inputs.as_object() {
        for (k, v) in obj {
            if let Ok(dyn_val) = rhai::serde::to_dynamic(v) {
                scope.push_dynamic(k.clone(), dyn_val);
            }
        }
    }
    // Also expose the full input payload as `input`, `ctx`, and `inputs` so
    // expressions can use `input.route`, `ctx.route`, or `inputs.route` —
    // matches the access patterns documented for edge conditions.
    if let Ok(whole) = rhai::serde::to_dynamic(inputs) {
        scope.push_dynamic("input", whole.clone());
        scope.push_dynamic("ctx", whole.clone());
        scope.push_dynamic("inputs", whole);
    }
    match rhai_engine.eval_with_scope::<rhai::Dynamic>(&mut scope, expression) {
        Ok(result) => {
            let s = result.to_string();
            if s.is_empty() {
                Err("Dispatch expression returned empty string".to_string())
            } else {
                Ok(s)
            }
        }
        Err(e) => Err(format!("Dispatch expression evaluation failed: {e}")),
    }
}

/// `evaluate_dispatch_expression` had ZERO test coverage before 2026-07-29,
/// which is how its engine config drifted 10× from every other Rhai site and
/// lost the `print`/`debug` discard without anything noticing. These pin the
/// behaviour the sandbox-builder refactor must preserve, plus the two things
/// it deliberately changes.
#[cfg(test)]
mod dispatch_expression_tests {
    use super::evaluate_dispatch_expression;
    use serde_json::json;

    /// The documented access patterns: bare top-level keys, and the whole
    /// payload as `input` / `ctx` / `inputs`. Unchanged by the refactor.
    #[test]
    fn resolves_every_documented_access_pattern() {
        let inputs = json!({ "route": "workflow-a", "nested": { "target": "workflow-b" } });
        for expr in [
            "route",
            "input.route",
            "ctx.route",
            "inputs.route",
            "nested.target",
        ] {
            let got = evaluate_dispatch_expression(expr, &inputs)
                .unwrap_or_else(|e| panic!("`{expr}` should evaluate: {e}"));
            let want = if expr == "nested.target" {
                "workflow-b"
            } else {
                "workflow-a"
            };
            assert_eq!(got, want, "`{expr}`");
        }
    }

    /// Conditional routing — the shape a real `DynamicDispatch` node stores.
    #[test]
    fn evaluates_a_conditional_route() {
        let inputs = json!({ "score": 82 });
        assert_eq!(
            evaluate_dispatch_expression(
                r#"if score > 50 { "high-wf" } else { "low-wf" }"#,
                &inputs
            ),
            Ok("high-wf".to_string())
        );
        let inputs = json!({ "score": 12 });
        assert_eq!(
            evaluate_dispatch_expression(
                r#"if score > 50 { "high-wf" } else { "low-wf" }"#,
                &inputs
            ),
            Ok("low-wf".to_string())
        );
    }

    /// An empty result is an error, not a dispatch to "" — and an eval
    /// failure keeps its operator-recognised message prefix.
    #[test]
    fn empty_and_failing_expressions_stay_errors() {
        let inputs = json!({ "route": "" });
        assert_eq!(
            evaluate_dispatch_expression("route", &inputs),
            Err("Dispatch expression returned empty string".to_string())
        );
        let err = evaluate_dispatch_expression("this is not rhai (", &inputs)
            .expect_err("a syntax error must not route");
        assert!(
            err.starts_with("Dispatch expression evaluation failed:"),
            "error prefix changed: {err}"
        );
    }

    /// SECURITY: dynamic code execution stays blocked at this site.
    #[test]
    fn dynamic_eval_is_blocked() {
        let inputs = json!({});
        assert!(evaluate_dispatch_expression(r#"eval("\"wf\"")"#, &inputs).is_err());
    }

    /// DLP (the fix): a dispatch expression containing `print(inputs)` used
    /// to write every gathered node input to the controller's stdout. It is
    /// now discarded — but `print` stays a CALLABLE no-op, so the expression
    /// still routes to exactly the same workflow instead of becoming a parse
    /// error and failing the node on deploy.
    #[test]
    fn print_is_a_no_op_and_does_not_change_the_route() {
        let inputs = json!({ "route": "workflow-a", "secret": "sk-not-a-real-key" });
        assert_eq!(
            evaluate_dispatch_expression("print(inputs); route", &inputs),
            Ok("workflow-a".to_string()),
            "print must remain callable and route-neutral"
        );
        assert_eq!(
            evaluate_dispatch_expression("debug(secret); route", &inputs),
            Ok("workflow-a".to_string()),
        );
    }

    /// Pins the `SandboxProfile::Dispatch` decision: this site keeps a
    /// 10 000-operation budget, so an expression that costs more than the
    /// 1 000-op `Expression` budget still routes here. The second half is
    /// the point — the same expression FAILS under the Expression profile,
    /// which is the evidence that "just normalise dispatch to 1 000" would
    /// have been an observable behaviour change to stored graphs, not a
    /// cleanup. See `SandboxProfile::Dispatch`'s docs for why that decision
    /// was deferred rather than taken here.
    #[test]
    fn the_dispatch_operation_budget_is_load_bearing_versus_expression() {
        // ~900 loop iterations: comfortably over 1 000 operations, well
        // under 10 000.
        let expr = r#"let n = 0; for i in 0..900 { n += 1; } "wf-" + n"#;
        let inputs = serde_json::json!({});

        assert_eq!(
            evaluate_dispatch_expression(expr, &inputs),
            Ok("wf-900".to_string()),
            "the Dispatch profile's 10 000-op budget must still cover this"
        );

        let expression_profile =
            talos_rhai_sandbox::sandboxed_engine(talos_rhai_sandbox::SandboxProfile::Expression);
        let err = expression_profile
            .eval::<rhai::Dynamic>(expr)
            .expect_err("the 1 000-op Expression budget must NOT cover this");
        assert!(
            err.to_string().to_lowercase().contains("operation"),
            "expected an operations-exceeded error, got: {err}"
        );
    }
    /// The OTHER half of the profile decision, and the sharpest behaviour
    /// risk in the sandbox-builder change: this site previously set NO
    /// `max_string_size` / `max_array_size` / `max_map_size`, so the caps are
    /// newly live here. Pins exactly which expression shapes that changes, so
    /// a future reader debugging a `Length of string too large` from a
    /// dispatch node finds the semantics written down instead of rediscovering
    /// them.
    ///
    /// The rule (rhai 1.24 `src/eval/data_check.rs`): the caps are not
    /// applied when the host pushes a value into scope, but they ARE applied
    /// to the result of every call and to the `&mut` receiver of every method
    /// call — against an AGGREGATE, RECURSIVE size of that value.
    #[test]
    fn dispatch_size_cap_semantics() {
        let inputs = json!({
            "route": "workflow-a",
            "big": "x".repeat(200_000),
            "arr": (0..600).collect::<Vec<i64>>(),
            "nested": { "target": "workflow-b", "body": "y".repeat(100_000) },
        });

        // (1) Reads and property navigation of oversized values are FINE —
        // the caps do not apply at scope-push time. Every real dispatch
        // expression observed in the wild is one of these shapes.
        for (expr, want) in [
            ("route", "workflow-a"),
            ("inputs.route", "workflow-a"),
            ("nested.target", "workflow-b"),
            (
                r#"if big == "z" { "hit" } else { "workflow-a" }"#,
                "workflow-a",
            ),
            (
                r#"if arr[0] == 0 { "workflow-a" } else { "hit" }"#,
                "workflow-a",
            ),
        ] {
            assert_eq!(
                evaluate_dispatch_expression(expr, &inputs).as_deref(),
                Ok(want),
                "reading an oversized payload must still route: `{expr}`"
            );
        }

        // (2) A METHOD CALL whose receiver is oversized now fails. Each of
        // these routed before 2026-07-29 and errors after.
        for (expr, marker) in [
            (r#"if big.len() > 3 { "a" } else { "b" }"#, "string"),
            (r#"if big.contains("x") { "a" } else { "b" }"#, "string"),
            (
                r#"if nested.body.starts_with("y") { "a" } else { "b" }"#,
                "string",
            ),
            (r#"if arr.len() > 3 { "a" } else { "b" }"#, "array"),
            (
                r#"if arr.filter(|x| x > 500).len() > 3 { "a" } else { "b" }"#,
                "array",
            ),
            // Aggregate + recursive: `inputs` has four keys, but the total
            // string content beneath it is 300 KB.
            (r#"if inputs.len() > 3 { "a" } else { "b" }"#, "string"),
        ] {
            let err = evaluate_dispatch_expression(expr, &inputs)
                .expect_err(&format!("`{expr}` must be refused by the size caps"));
            assert!(
                err.starts_with("Dispatch expression evaluation failed:")
                    && err.to_lowercase().contains("too large")
                    && err.to_lowercase().contains(marker),
                "`{expr}`: expected a {marker}-too-large error, got: {err}"
            );
        }

        // (3) The same shapes on a NORMAL-sized payload are unaffected —
        // the caps bite on size, not on method calls as such.
        let small = json!({ "arr": [1, 2, 3], "body": "short", "route": "workflow-a" });
        assert_eq!(
            evaluate_dispatch_expression(
                r#"if arr.len() == 3 && body.contains("sho") { route } else { "other" }"#,
                &small
            )
            .as_deref(),
            Ok("workflow-a")
        );
    }
}

#[cfg(test)]
mod loop_iteration_execution_row_tests {
    //! Loop bodies must dispatch under a REAL execution-row id.
    //!
    //! Regression cover for the 2026-07-30 finding: `run_loop_iterations`
    //! passed `job_id: None`, the NATS dispatcher minted a fresh UUID for the
    //! wire, and the worker stamped that UUID onto every `wasm.log.{id}` line
    //! it published. The id named no row in `workflow_executions` OR
    //! `module_executions`, so both of the log subscriber's `WHERE EXISTS`
    //! inserts matched nothing and every iteration of every Loop node lost
    //! ALL of its logs — host diagnostics and the guest's own
    //! `talos::core::logging::log` alike.
    //!
    //! These tests drive the REAL `run_loop_iterations` (not a re-implementation
    //! of its logic) through the in-memory adapters, and assert on the recorded
    //! store calls — i.e. that the row EXISTS, not merely that the field is
    //! `Some`. `Some(<uuid nobody recorded>)` would be the same bug wearing a
    //! different mask.

    use std::sync::Arc;

    use serde_json::json;
    use talos_workflow_engine_core::{NodeDispatcher, SystemNodeKind, WasmModuleArtifact};
    use talos_workflow_engine_test_utils::capture::{
        CaptureModuleExecutionStore, ExecutionStoreCall,
    };
    use talos_workflow_engine_test_utils::dispatch::ScriptedDispatcher;
    use talos_workflow_engine_test_utils::memory::InMemoryModuleFetcher;
    use talos_workflow_engine_test_utils::noop::StubExpressionEvaluator;
    use uuid::Uuid;

    use crate::engine::ParallelWorkflowEngine;

    fn stub_artifact(module_id: Uuid) -> WasmModuleArtifact {
        WasmModuleArtifact {
            module_id,
            content_hash: "stub".into(),
            wasm_bytes: vec![1, 2, 3],
            oci_url: None,
            max_fuel: 1_000_000,
            capability_world: "stub".into(),
            allowed_hosts: vec![],
            allowed_methods: vec![],
            allowed_secrets: vec![],
            requires_approval_for: vec![],
            integration_name: None,
            config: None,
        }
    }

    /// Engine wired with the in-memory adapters a loop dispatch needs:
    /// a module fetcher, a user, an actor, and a recording execution store.
    fn engine_with_loop(
        loop_node: Uuid,
        body_node: Uuid,
        body_module: Uuid,
        store: Arc<CaptureModuleExecutionStore>,
    ) -> ParallelWorkflowEngine {
        let mut engine = ParallelWorkflowEngine::new();
        engine.set_user_id(Uuid::new_v4());
        // Bare `set_actor_id` needs no opt-out here: lint check 29 excludes
        // `talos-workflow-engine/**` wholesale, and check 3 (whose
        // `allow-agent-context-key` marker an earlier draft pasted onto this
        // line) only greps `__agent_context__`, in other crates. An inert
        // opt-out reads as "this tripped a lint and was excused" — a claim
        // neither check would ever make.
        engine.set_actor_id(Uuid::new_v4());
        // A bare engine has no evaluator, and `eval_bool` fail-closes to
        // false — which would silently stop every loop after one iteration
        // and make these tests pass for the wrong reason.
        engine.set_expression_evaluator(Arc::new(StubExpressionEvaluator::new().with_bool(true)));
        engine.set_module_execution_store(store);
        engine.set_module_fetcher(Arc::new(
            InMemoryModuleFetcher::new().with_module(body_module, stub_artifact(body_module)),
        ));
        engine.add_node(
            loop_node,
            None,
            None,
            Some(SystemNodeKind::Loop {
                max_iterations: 3,
                condition: "true".into(),
            }),
        );
        engine.add_node(body_node, Some(body_module), None, None);
        engine
    }

    fn started_calls(store: &CaptureModuleExecutionStore) -> Vec<ExecutionStoreCall> {
        store
            .calls()
            .into_iter()
            .filter(|c| matches!(c, ExecutionStoreCall::Started { .. }))
            .collect()
    }

    /// THE regression: every dispatched iteration carries a `job_id` that a
    /// `record_started` call actually created a row for.
    #[tokio::test]
    async fn every_loop_iteration_dispatches_under_a_recorded_execution_row() {
        let store = Arc::new(CaptureModuleExecutionStore::new());
        let loop_node = Uuid::new_v4();
        let body_node = Uuid::new_v4();
        let body_module = Uuid::new_v4();
        let engine = engine_with_loop(loop_node, body_node, body_module, store.clone());

        let dispatcher = Arc::new(
            ScriptedDispatcher::new().with_response(body_module, json!({ "keep_going": true })),
        );
        let dyn_dispatcher: Arc<dyn NodeDispatcher> = dispatcher.clone();

        let out = engine
            .run_loop_iterations(
                loop_node,
                Uuid::new_v4(),
                body_node,
                body_module,
                json!({ "seed": 1 }),
                "true", // condition: keep looping until max_iters
                3,
                &dyn_dispatcher,
                &None,
                &std::collections::HashMap::new(),
            )
            .await;

        assert_eq!(out["iterations"], json!(3), "loop ran to its cap");
        let jobs = dispatcher.jobs();
        assert_eq!(jobs.len(), 3, "one dispatch per iteration");

        // The ids the store was told about — i.e. the rows that exist.
        let recorded: Vec<Uuid> = started_calls(&store)
            .into_iter()
            .map(|c| match c {
                ExecutionStoreCall::Started { id, .. } => id,
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(recorded.len(), 3, "one execution row per iteration");

        for (i, job) in jobs.iter().enumerate() {
            let job_id = job.job_id.unwrap_or_else(|| {
                panic!(
                    "iteration {i} dispatched with job_id: None — the worker would mint its own \
                     id and every log line for this iteration would be discarded"
                )
            });
            assert!(
                recorded.contains(&job_id),
                "iteration {i} dispatched under {job_id}, which no record_started call created a \
                 row for — the log-persist predicate would miss it just the same"
            );
        }
        // Distinct per iteration: sharing one row across iterations would
        // collapse their logs and their status into one another.
        let mut unique = recorded.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), 3, "each iteration gets its OWN row");
    }

    /// The row's parentage and attribution must match the dispatch, or the
    /// `module_execution_logs → module_executions → workflow_execution_id`
    /// join that `tail_worker_logs` walks won't find the lines.
    #[tokio::test]
    async fn loop_iteration_row_is_bound_to_the_parent_execution_and_module() {
        let store = Arc::new(CaptureModuleExecutionStore::new());
        let loop_node = Uuid::new_v4();
        let body_node = Uuid::new_v4();
        let body_module = Uuid::new_v4();
        let engine = engine_with_loop(loop_node, body_node, body_module, store.clone());
        let execution_id = Uuid::new_v4();

        let dispatcher: Arc<dyn NodeDispatcher> =
            Arc::new(ScriptedDispatcher::new().with_response(body_module, json!({ "ok": true })));

        engine
            .run_loop_iterations(
                loop_node,
                execution_id,
                body_node,
                body_module,
                json!({}),
                "true",
                1,
                &dispatcher,
                &None,
                &std::collections::HashMap::new(),
            )
            .await;

        let started = started_calls(&store);
        assert_eq!(started.len(), 1);
        match &started[0] {
            ExecutionStoreCall::Started {
                module_id,
                workflow_execution_id,
                trigger_type,
                race_safe_status,
                actor_id,
                ..
            } => {
                assert_eq!(*module_id, body_module, "row must name the BODY module");
                assert_eq!(
                    *workflow_execution_id, execution_id,
                    "row must hang off the parent workflow execution"
                );
                // Must be a value the module_executions trigger_type CHECK
                // accepts; matches the single-node dispatch path.
                assert_eq!(trigger_type, "webhook");
                assert!(
                    *race_safe_status,
                    "loop nodes run concurrently with sibling nodes — a sibling failure between \
                     INSERT and dispatch must land the row as cancelled, not phantom-running"
                );
                assert!(actor_id.is_some(), "row inherits the engine's actor");
            }
            _ => unreachable!(),
        }
    }

    /// Rows must never be left in `running`. The stuck-execution sweeper and
    /// the sibling-cancel trigger both read that status; a loop that leaks
    /// N phantom running rows per run poisons both.
    #[tokio::test]
    async fn every_started_row_is_completed_on_success_and_on_failure() {
        // Success path.
        let store = Arc::new(CaptureModuleExecutionStore::new());
        let (l, b, m) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let engine = engine_with_loop(l, b, m, store.clone());
        let dispatcher: Arc<dyn NodeDispatcher> =
            Arc::new(ScriptedDispatcher::new().with_response(m, json!({ "ok": true })));
        engine
            .run_loop_iterations(
                l,
                Uuid::new_v4(),
                b,
                m,
                json!({}),
                "true",
                2,
                &dispatcher,
                &None,
                &std::collections::HashMap::new(),
            )
            .await;
        let calls = store.calls();
        let started: Vec<Uuid> = calls
            .iter()
            .filter_map(|c| match c {
                ExecutionStoreCall::Started { id, .. } => Some(*id),
                _ => None,
            })
            .collect();
        let completed: Vec<(Uuid, String)> = calls
            .iter()
            .filter_map(|c| match c {
                ExecutionStoreCall::Completed { id, status, .. } => Some((*id, status.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(started.len(), 2);
        assert_eq!(completed.len(), 2, "no row left in 'running'");
        for id in &started {
            let done = completed.iter().find(|(cid, _)| cid == id);
            assert_eq!(
                done.map(|(_, s)| s.as_str()),
                Some("completed"),
                "row {id} must be completed"
            );
        }

        // Dispatch-failure path: the row still has to be closed out, and as
        // 'failed' — a 'completed' row for a failed iteration is the
        // misleading-field class in the audit log.
        let store = Arc::new(CaptureModuleExecutionStore::new());
        let (l, b, m) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let engine = engine_with_loop(l, b, m, store.clone());
        let dispatcher: Arc<dyn NodeDispatcher> =
            Arc::new(ScriptedDispatcher::new().with_error(m, "transport exploded"));
        engine
            .run_loop_iterations(
                l,
                Uuid::new_v4(),
                b,
                m,
                json!({}),
                "true",
                2,
                &dispatcher,
                &None,
                &std::collections::HashMap::new(),
            )
            .await;
        let calls = store.calls();
        let completed: Vec<(Uuid, String, Option<String>)> = calls
            .iter()
            .filter_map(|c| match c {
                ExecutionStoreCall::Completed {
                    id,
                    status,
                    error_message,
                    ..
                } => Some((*id, status.clone(), error_message.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(completed.len(), 1, "the failing iteration's row is closed");
        assert_eq!(completed[0].1, "failed");
        assert!(
            completed[0]
                .2
                .as_deref()
                .is_some_and(|e| e.contains("transport exploded")),
            "the failure reason is recorded on the row"
        );
    }

    /// A body that returns an `__error` envelope succeeded at the transport
    /// layer but FAILED as work. The row must say so.
    #[tokio::test]
    async fn error_envelope_records_the_row_as_failed() {
        let store = Arc::new(CaptureModuleExecutionStore::new());
        let (l, b, m) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let engine = engine_with_loop(l, b, m, store.clone());
        let dispatcher: Arc<dyn NodeDispatcher> =
            Arc::new(ScriptedDispatcher::new().with_response(
                m,
                json!({ "__error": true, "error_message": "body blew up" }),
            ));
        engine
            .run_loop_iterations(
                l,
                Uuid::new_v4(),
                b,
                m,
                json!({}),
                "true",
                3,
                &dispatcher,
                &None,
                &std::collections::HashMap::new(),
            )
            .await;
        let completed: Vec<(String, Option<String>)> = store
            .calls()
            .iter()
            .filter_map(|c| match c {
                ExecutionStoreCall::Completed {
                    status,
                    error_message,
                    ..
                } => Some((status.clone(), error_message.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].0, "failed");
        assert!(completed[0]
            .1
            .as_deref()
            .is_some_and(|e| e.contains("body blew up")));
    }

    /// An engine with no store still dispatches under a stable minted id
    /// (test/embedded configurations must not regress into a panic or an
    /// unset job_id).
    #[tokio::test]
    async fn storeless_engine_still_stamps_a_job_id() {
        let mut engine = ParallelWorkflowEngine::new();
        engine.set_user_id(Uuid::new_v4());
        engine.set_expression_evaluator(Arc::new(StubExpressionEvaluator::new().with_bool(true)));
        let (l, b, m) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        engine.set_module_fetcher(Arc::new(
            InMemoryModuleFetcher::new().with_module(m, stub_artifact(m)),
        ));
        engine.add_node(
            l,
            None,
            None,
            Some(SystemNodeKind::Loop {
                max_iterations: 1,
                condition: "true".into(),
            }),
        );
        engine.add_node(b, Some(m), None, None);

        let dispatcher = Arc::new(ScriptedDispatcher::new().with_response(m, json!({ "ok": 1 })));
        let dyn_dispatcher: Arc<dyn NodeDispatcher> = dispatcher.clone();
        engine
            .run_loop_iterations(
                l,
                Uuid::new_v4(),
                b,
                m,
                json!({}),
                "true",
                1,
                &dyn_dispatcher,
                &None,
                &std::collections::HashMap::new(),
            )
            .await;
        assert!(dispatcher.jobs()[0].job_id.is_some());
    }
}
