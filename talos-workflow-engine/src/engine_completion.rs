//! Post-dispatch completion handlers — extracted from engine.rs
//!
//! These three methods are the hand-off between a future returning
//! from `executing.next().await` and the reactor's bookkeeping
//! (results map, pending counts, ready queue, lifecycle hook). They
//! split into:
//!
//! * `handle_completed_future` — the dispatch entry point. Routes
//!   `Ok` to `handle_node_success` and `Err` to `handle_node_failure`.
//! * `handle_node_success` — size-guard, sanitize, store, fire
//!   `on_node_completed`, walk successors with `FanIn` / edge-condition
//!   awareness.
//! * `handle_node_failure` — DLP-scrub, emit `node_failed`, route to
//!   error edges / `continue_on_error` / scheduler-fatal abort.
//!
//! Pure code movement from the previous engine.rs location — no
//! behaviour change. Lifted out so the reactor body in
//! `run_scheduler_loop` reads as a sequence of named handler calls
//! and so this ~400-line failure-and-success-routing block stays
//! auditable in isolation.

use std::collections::{HashMap, VecDeque};

use petgraph::graph::NodeIndex;
use petgraph::Direction;
use serde_json::Value as JsonValue;
use talos_workflow_engine_core::NodeEventWrite;
use uuid::Uuid;

use crate::engine::ParallelWorkflowEngine;
use crate::validation::sanitize_node_output;

/// Extract a retry-classifier tag from an error message shaped like
/// `"Job failed (non-transient: <class>): <detail>"`.
///
/// The NATS dispatcher (and any dispatcher following the same format)
/// wraps a `RetryClassifier::is_transient == false` decision with that
/// prefix before returning it to the engine. Surfacing the tag on the
/// `node_failed` event lets downstream analytics correlate the earlier
/// `retry_skipped` event with the terminal `node_failed` without
/// string-parsing `log_message`.
///
/// Returns `None` when the prefix isn't present — the error is either
/// transient (the classifier said so) or came from a dispatcher that
/// doesn't use this wire format.
fn extract_non_transient_class(error_msg: &str) -> Option<String> {
    let marker = "(non-transient: ";
    let start = error_msg.find(marker)? + marker.len();
    let rest = &error_msg[start..];
    let end = rest.find(')')?;
    Some(rest[..end].to_string())
}

impl ParallelWorkflowEngine {
    /// Route a system-node output envelope through the reactor's
    /// normal success/failure paths based on the `__error: true`
    /// marker on synthesized rejection envelopes.
    ///
    /// System nodes (judge / ensemble / `reflective_retry` / `llm_dispatch`
    /// / `inline_judge` / verify / `confidence_gate` / `expression_dispatch`)
    /// synthesize their "rejected" output as `{__error: true,
    /// error_message: "..."}` rather than bubbling a Rust `Err`. The
    /// reactor used to store these envelopes as "successful" node
    /// outputs and mark the workflow `completed`, silently
    /// contradicting every one of those tools' documented contracts
    /// ("workflow fails", "blocks downstream", "halts execution",
    /// etc.).
    ///
    /// This helper closes the loop: the marker triggers
    /// `handle_completed_future` with `Err(message)`, which respects
    /// `continue_on_error` and error-edge routing identically to
    /// regular module failures. Without the marker, we fall through
    /// to the normal insert-and-unblock-successors path.
    ///
    /// Consolidates the fix pattern from three earlier single-site
    /// commits (verify-node: b69aad5, `confidence_gate`: a7dd2b3,
    /// `expression_dispatch`: a941df4) so every system-node caller in
    /// the reactor body uses one consistent mechanism.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn route_system_node_output(
        &self,
        node_idx: NodeIndex,
        output: JsonValue,
        execution_id: Uuid,
        chains_ctx: Option<(&[Vec<NodeIndex>], &HashMap<NodeIndex, usize>)>,
        exec_ctx: &Option<Box<dyn talos_workflow_engine_core::ExecutionSanitizer>>,
        results: &mut HashMap<Uuid, JsonValue>,
        pending: &mut HashMap<NodeIndex, usize>,
        ready: &mut VecDeque<NodeIndex>,
    ) -> Result<(), String> {
        let is_error = output
            .get("__error")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if is_error {
            let msg = output
                .get("error_message")
                .and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_else(|| "system node rejected output".to_string());
            self.handle_completed_future(
                node_idx,
                Err(msg),
                execution_id,
                0,
                chains_ctx,
                exec_ctx,
                results,
                pending,
                ready,
            )
            .await
        } else {
            let node_id = self.graph[node_idx];
            results.insert(node_id, output);
            self.unblock_successors(node_idx, pending, ready);
            Ok(())
        }
    }

    /// Post-completion processing for a node whose dispatch future
    /// just returned from `executing.next().await`.
    ///
    /// Handles both the `Ok(output)` and `Err(error_message)` paths:
    ///
    /// * **Success.** Size-guard the output, sanitize it, insert into
    ///   `results`, fire the `on_node_completed` hook, clear pending
    ///   counts for any interior chain nodes (primary scheduler only),
    ///   then walk successors decrementing pending counts, applying
    ///   `FanIn` early-ready rules and edge-condition evaluation.
    ///
    /// * **Failure.** DLP-scrub the error, emit `node_failed`, and
    ///   route based on node topology: if the node has outgoing error
    ///   edges they fire; if the node has `__continue_on_error` set we
    ///   propagate a `__continued` envelope and keep going; otherwise
    ///   we notify the hook and return `Err` so the scheduler bails.
    ///
    /// `chains_ctx` is the primary scheduler's chain-detection output
    /// (chains slice + `node_to_chain` map); `None` for the seeded
    /// scheduler, which doesn't run pipeline batching. `wall_time_ms`
    /// is 0 on the primary (no per-node timing) and the measured
    /// elapsed time on the seeded scheduler (threaded back through
    /// `WorkflowContext.node_timings`).
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn handle_completed_future(
        &self,
        finished_idx: NodeIndex,
        exec_result: Result<JsonValue, String>,
        execution_id: Uuid,
        wall_time_ms: u64,
        chains_ctx: Option<(&[Vec<NodeIndex>], &HashMap<NodeIndex, usize>)>,
        exec_ctx: &Option<Box<dyn talos_workflow_engine_core::ExecutionSanitizer>>,
        results: &mut HashMap<Uuid, JsonValue>,
        pending: &mut HashMap<NodeIndex, usize>,
        ready: &mut VecDeque<NodeIndex>,
    ) -> Result<(), String> {
        let finished_id = self.graph[finished_idx];
        match exec_result {
            Ok(output) => {
                self.handle_node_success(
                    finished_idx,
                    finished_id,
                    output,
                    execution_id,
                    wall_time_ms,
                    chains_ctx,
                    results,
                    pending,
                    ready,
                )
                .await;
                Ok(())
            }
            Err(error_msg) => {
                self.handle_node_failure(
                    finished_idx,
                    finished_id,
                    error_msg,
                    execution_id,
                    wall_time_ms,
                    chains_ctx,
                    exec_ctx,
                    results,
                    pending,
                    ready,
                )
                .await
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_node_success(
        &self,
        finished_idx: NodeIndex,
        finished_id: Uuid,
        output: JsonValue,
        execution_id: Uuid,
        wall_time_ms: u64,
        chains_ctx: Option<(&[Vec<NodeIndex>], &HashMap<NodeIndex, usize>)>,
        results: &mut HashMap<Uuid, JsonValue>,
        pending: &mut HashMap<NodeIndex, usize>,
        ready: &mut VecDeque<NodeIndex>,
    ) {
        // Log `node_completed` synchronously so child `node_started`
        // events (fire-and-forget) are always ordered after this insert
        // in the DB — fixes causally-inconsistent timelines.
        if let Some(ref sink) = self.event_sink {
            sink.emit(NodeEventWrite {
                execution_id,
                event_type: "node_completed".to_string(),
                node_id: Some(finished_id),
                status: "Completed".to_string(),
                log_message: None,
                iteration_index: None,
                error_class: None,
            })
            .await;
        }

        // Per-node output size guard: reject outputs larger than the
        // engine-configured ceiling (default 5 MiB; override via
        // `set_max_node_output_bytes`). A single misbehaving node can
        // otherwise produce a multi-MB JSON value that is then cloned
        // into every downstream node's gathered_inputs and the final
        // aggregated workflow output, cascading into memory
        // exhaustion.
        let max_output_bytes = self.max_node_output_bytes;
        let output = match serde_json::to_vec(&output) {
            Ok(bytes) if bytes.len() > max_output_bytes => {
                tracing::warn!(
                    node_id = %finished_id,
                    bytes = bytes.len(),
                    limit = max_output_bytes,
                    "Node output exceeds configured size limit — replacing with error"
                );
                serde_json::json!({
                    "__error": true,
                    "error": format!(
                        "Node output too large ({} bytes > {} byte limit). \
                         Reduce the amount of data returned by this node.",
                        bytes.len(), max_output_bytes
                    )
                })
            }
            _ => output,
        };
        let mut output = output;
        sanitize_node_output(&mut output);
        results.insert(finished_id, output.clone());

        // Post-completion hook: drives fuel attribution,
        // `__memory_write__` persistence, and any future cross-cutting
        // per-node observers. Fire-and-forget — the hook returns
        // quickly; impls spawn internally. The primary scheduler
        // doesn't track wall time (wall_time_ms == 0); the seeded
        // scheduler threads it through from `node_start_times`.
        if let Some(hook) = self.node_hook.as_ref() {
            let node_label = self.node_labels.get(&finished_id).map(String::as_str);
            let module_id = self.node_meta.get(&finished_id).and_then(|(m, _, _)| *m);
            hook.on_node_completed(
                talos_workflow_engine_core::NodeCompletionContext {
                    workflow_id: self.workflow_id.unwrap_or(execution_id),
                    execution_id,
                    node_id: finished_id,
                    node_label,
                    module_id,
                    actor_id: self.actor_id,
                    wall_time_ms,
                },
                &output,
            );
        }

        // Phase C (opt-in): best-effort per-node checkpoint. Disabled
        // unless the controller wired a CheckpointStore onto the top-level
        // engine (sub-workflow engines never carry one — see
        // `CheckpointConfig`). `results` already includes the node that
        // just finished (inserted above), so the snapshot is complete
        // through this node. Debounced by `every_n` to bound re-encryption
        // cost; spawned so a slow store never stalls dispatch; failures are
        // logged, not propagated (resume just falls back to the last good
        // checkpoint, re-running at most the trailing `every_n` nodes).
        if let Some(cp) = self.checkpoint.as_ref() {
            let n = cp.dirty.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            if n % cp.every_n == 0 {
                let snapshot = serde_json::Value::Object(
                    results
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.clone()))
                        .collect(),
                );
                let store = cp.store.clone();
                tokio::spawn(async move {
                    if let Err(e) = store.save(execution_id, &snapshot).await {
                        tracing::warn!(
                            %execution_id,
                            error = %e,
                            "per-node checkpoint save failed (best-effort; resume \
                             falls back to the last good checkpoint)"
                        );
                    }
                });
            }
        }

        // Chain execution: clear `pending` for interior chain nodes so
        // their would-be successors (already run inside the pipeline)
        // don't wait on them. Primary scheduler only — seeded path
        // doesn't run pipeline batching.
        if let Some((chains, node_to_chain)) = chains_ctx {
            if let Some(&chain_idx) = node_to_chain.get(&finished_idx) {
                for &n in &chains[chain_idx] {
                    pending.insert(n, 0);
                }
            }
        }

        // Decrement children counters for finished_idx's successors.
        // On SUCCESS, skip error-edge children (they only fire on failure).
        for child in self
            .graph
            .neighbors_directed(finished_idx, Direction::Outgoing)
        {
            let is_error_edge = self
                .graph
                .edges_connecting(finished_idx, child)
                .any(|e| e.weight().edge_type == "error");
            if is_error_edge {
                let child_id = self.graph[child];
                results.insert(child_id, serde_json::json!({"__skipped": true}));
                continue;
            }
            if let Some(cnt) = pending.get_mut(&child) {
                // Guard the decrement: under early-ready join modes the counter
                // may already be 0 when a parent completes (see the removal note
                // below), and an unguarded `*cnt -= 1` on 0 underflows — a panic
                // in debug, a wrap to usize::MAX in release.
                if *cnt > 0 {
                    *cnt -= 1;
                }

                // FanIn early-ready logic: some join modes don't
                // require ALL parents to complete.
                self.apply_fan_in_early_ready(child, pending);

                if pending.get(&child).copied().unwrap_or(1) == 0 {
                    // The join is satisfied — this child's fate is decided
                    // exactly once here. Remove its `pending` entry so a parent
                    // that completes LATER (possible under the `Any`/`N`/
                    // `Majority` join modes, which zero the counter before every
                    // parent finishes) can't re-enter this block: without the
                    // removal that late parent would underflow the counter and
                    // re-enqueue the child, double-dispatching its entire
                    // downstream subgraph. Termination keys on `ready`/`executing`,
                    // not `pending`, so early removal is safe.
                    pending.remove(&child);
                    // Check edge conditions before enqueuing.
                    let child_node_id = self.graph[child];
                    let mut condition_failed = false;
                    for edge_ref in self.graph.edges_connecting(finished_idx, child) {
                        tracing::debug!(
                            condition = ?edge_ref.weight().condition,
                            edge_type = %edge_ref.weight().edge_type,
                            child = %child_node_id,
                            "Evaluating edge"
                        );
                        if let Some(ref cond) = edge_ref.weight().condition {
                            let unwrapped = Self::unwrap_output(&output);
                            if !self.eval_bool(cond, unwrapped) {
                                tracing::info!(
                                    child_node_id = %child_node_id,
                                    condition = %cond,
                                    output_keys = ?unwrapped
                                        .as_object()
                                        .map(|m| m.keys().cloned().collect::<Vec<_>>())
                                        .unwrap_or_default(),
                                    "Edge condition false — child node will be skipped"
                                );
                                condition_failed = true;
                                break;
                            }
                        }
                    }
                    if condition_failed {
                        tracing::info!(
                            node_id = %child_node_id,
                            "Skipping node: edge condition evaluated to false"
                        );
                        results.insert(child_node_id, serde_json::json!({"__skipped": true}));
                        // Cascade skip: decrement pending counts for the
                        // skipped node's children. Those grandchildren
                        // get picked up when their pending reaches 0 in
                        // a future iteration.
                        for grandchild in self.graph.neighbors_directed(child, Direction::Outgoing)
                        {
                            if let Some(gc_cnt) = pending.get_mut(&grandchild) {
                                if *gc_cnt > 0 {
                                    *gc_cnt -= 1;
                                }
                            }
                        }
                    } else {
                        ready.push_back(child);
                    }
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_node_failure(
        &self,
        finished_idx: NodeIndex,
        finished_id: Uuid,
        error_msg: String,
        execution_id: Uuid,
        wall_time_ms: u64,
        chains_ctx: Option<(&[Vec<NodeIndex>], &HashMap<NodeIndex, usize>)>,
        exec_ctx: &Option<Box<dyn talos_workflow_engine_core::ExecutionSanitizer>>,
        results: &mut HashMap<Uuid, JsonValue>,
        pending: &mut HashMap<NodeIndex, usize>,
        ready: &mut VecDeque<NodeIndex>,
    ) -> Result<(), String> {
        // Two-pass scrub: value-based (known secrets) then regex DLP.
        let error_msg = self.redact_str(
            &exec_ctx
                .as_ref()
                .map(|c| c.redact_error(&error_msg))
                .unwrap_or_else(|| error_msg.clone()),
        );
        // Log `node_failed` synchronously — same ordering guarantee as
        // `node_completed`: child routing happens after this commit.
        if let Some(ref sink) = self.event_sink {
            sink.emit(NodeEventWrite {
                execution_id,
                event_type: "node_failed".to_string(),
                node_id: Some(finished_id),
                status: "Failed".to_string(),
                log_message: Some(error_msg.clone()),
                iteration_index: None,
                // Best-effort extract: when an upstream dispatcher
                // wraps a non-transient classifier decision as
                // `"Job failed (non-transient: <class>): ..."`, surface
                // the class here so analytics pipelines can correlate
                // `retry_skipped` → `node_failed` without matching on
                // the prose in `log_message`.
                error_class: extract_non_transient_class(&error_msg),
            })
            .await;
        }

        let error_children: Vec<NodeIndex> = self
            .graph
            .neighbors_directed(finished_idx, Direction::Outgoing)
            .filter(|&child_idx| {
                if let Some(edge_idx) = self.graph.find_edge(finished_idx, child_idx) {
                    self.graph[edge_idx].edge_type == "error"
                } else {
                    false
                }
            })
            .collect();

        if !error_children.is_empty() {
            // Route error to error-handler nodes instead of failing.
            let error_payload = serde_json::json!({
                "__error": true,
                "error_message": error_msg,
                "failed_node": self
                    .node_labels
                    .get(&finished_id)
                    .cloned()
                    .unwrap_or_else(|| finished_id.to_string()),
            });
            results.insert(finished_id, error_payload);
            tracing::info!(
                %finished_id,
                error_handlers = error_children.len(),
                "Node failed but has error handler edges — routing to error handlers"
            );

            // Chain interior nodes get their pending cleared too —
            // primary scheduler only.
            if let Some((chains, node_to_chain)) = chains_ctx {
                if let Some(&chain_idx) = node_to_chain.get(&finished_idx) {
                    for &n in &chains[chain_idx] {
                        pending.insert(n, 0);
                    }
                }
            }

            // Unblock ONLY error-edge children; skip default /
            // conditional children because the parent failed and the
            // success path is dead.
            for child in self
                .graph
                .neighbors_directed(finished_idx, Direction::Outgoing)
            {
                let has_error_edge = self
                    .graph
                    .edges_connecting(finished_idx, child)
                    .any(|e| e.weight().edge_type == "error");
                if !has_error_edge {
                    let child_id = self.graph[child];
                    results.insert(child_id, serde_json::json!({"__skipped": true}));
                    continue;
                }

                if let Some(cnt) = pending.get_mut(&child) {
                    if *cnt > 0 {
                        *cnt -= 1;
                    }
                    self.apply_fan_in_early_ready(child, pending);
                    if pending.get(&child).copied().unwrap_or(1) == 0 {
                        ready.push_back(child);
                    }
                }
            }
            return Ok(());
        }

        if self
            .node_configs
            .get(&finished_id)
            .and_then(|c| c.get("__continue_on_error"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            // `continue_on_error`: store the error envelope and keep
            // executing. Downstream nodes see the `__error: true`
            // output on their gathered inputs.
            tracing::info!(
                %finished_id,
                "Node failed but continue_on_error is set — continuing execution"
            );
            results.insert(
                finished_id,
                serde_json::json!({
                    "__error": true,
                    "error_message": error_msg,
                    "__continued": true,
                }),
            );
            for child in self
                .graph
                .neighbors_directed(finished_idx, Direction::Outgoing)
            {
                if let Some(cnt) = pending.get_mut(&child) {
                    if *cnt > 0 {
                        *cnt -= 1;
                    }
                    if pending.get(&child).copied().unwrap_or(1) == 0 {
                        ready.push_back(child);
                    }
                }
            }
            return Ok(());
        }

        // No error handlers, no continue_on_error → the failure
        // propagates. Notify the lifecycle hook (DLQ + sibling-cancel
        // responsibility; the hook spawns both SQL writes so they
        // don't delay the return).
        if let Some(hook) = self.node_hook.as_ref() {
            let node_label = self.node_labels.get(&finished_id).map(String::as_str);
            let module_id = self.node_meta.get(&finished_id).and_then(|(m, _, _)| *m);
            hook.on_node_failed(
                talos_workflow_engine_core::NodeCompletionContext {
                    workflow_id: self.workflow_id.unwrap_or(execution_id),
                    execution_id,
                    node_id: finished_id,
                    node_label,
                    module_id,
                    actor_id: self.actor_id,
                    wall_time_ms,
                },
                &error_msg,
                results.get(&finished_id),
            );
        }
        let node_label = self
            .node_labels
            .get(&finished_id)
            .cloned()
            .unwrap_or_else(|| finished_id.to_string());
        // Clear prefetch cache before returning so unconsumed WASM
        // modules (potentially MBs each) are not retained in the
        // engine's `Arc` for the lifetime of the caller.
        self.module_prefetch_cache.clear();
        Err(format!("node '{node_label}' failed: {error_msg}"))
    }
}

#[cfg(test)]
mod tests {
    use super::extract_non_transient_class;

    #[test]
    fn extracts_classifier_tag_from_canonical_wrapper() {
        let msg = "Job failed (non-transient: auth): invalid token";
        assert_eq!(extract_non_transient_class(msg), Some("auth".to_string()));
    }

    #[test]
    fn extracts_multiword_classifier_tag() {
        let msg = "Job failed (non-transient: invalid_input): bad schema";
        assert_eq!(
            extract_non_transient_class(msg),
            Some("invalid_input".to_string())
        );
    }

    #[test]
    fn returns_none_when_marker_absent() {
        assert!(extract_non_transient_class("some other failure").is_none());
        assert!(extract_non_transient_class("").is_none());
    }

    #[test]
    fn returns_none_when_closing_paren_missing() {
        // Truncated / malformed wrapper — don't guess.
        assert!(extract_non_transient_class("Job failed (non-transient: auth").is_none());
    }
}
