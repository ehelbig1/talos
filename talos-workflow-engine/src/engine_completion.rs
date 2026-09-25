//! Post-dispatch completion handlers — extracted from engine.rs
//!
//! These methods are the hand-off between a finished node and the
//! reactor's bookkeeping (results map, join table, ready queue, lifecycle
//! hook). They split into:
//!
//! * `handle_completed_future` — the dispatch entry point. Routes
//!   `Ok` to `handle_node_success` and `Err` to `handle_node_failure`.
//! * `handle_node_success` — size-guard, sanitize, store, fire
//!   `on_node_completed`, release successors.
//! * `handle_node_failure` — DLP-scrub, emit `node_failed`, route to
//!   error edges / `continue_on_error` / scheduler-fatal abort.
//! * `release_successors` — the ONE successor-release path: resolves every
//!   outgoing edge (condition, error-edge type) and cascades skips. Every
//!   commit in the reactor, of every node kind, ends here.
//!
//! Lifted out of engine.rs so the reactor body in `run_scheduler_loop`
//! reads as a sequence of named handler calls and so the
//! failure-and-success-routing block stays auditable in isolation.

use std::collections::{HashMap, VecDeque};
use talos_workflow_engine_core::reserved_keys::{error_reason, output_reports_error};

use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use petgraph::Direction;
use serde_json::Value as JsonValue;
use talos_workflow_engine_core::{EdgeLogic, JoinMode, NodeEventWrite, SystemNodeKind};
use uuid::Uuid;

use crate::engine::ParallelWorkflowEngine;
use crate::join_state::{EdgeResolution, JoinVerdict, Joins};
use crate::validation::sanitize_node_output;

/// How a node's fate decides its OUTGOING edges — the argument to
/// [`ParallelWorkflowEngine::release_successors`], the ONE place a finished
/// node hands work to its children.
///
/// Every node kind — a worker-dispatched module, an inline system node, a
/// sub-workflow, a skip — goes through the same edge loop, so "a conditional
/// edge is followed only when its condition holds" and "an error edge fires
/// only on failure" mean the same thing after every one of them. Until
/// 2026-09-25 only the module success path applied either rule; every other
/// commit decremented its children's counters and nothing else, so a judge's
/// `passthrough` verdict ran both of its conditional branches and a
/// sub-workflow's error handler ran when the sub-workflow succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Release {
    /// The node committed an output (read back from `results`). An error edge
    /// resolves inactive; a conditional edge resolves active only when its
    /// condition holds against that output; any other edge is active.
    Succeeded,
    /// The node's own gate skipped it (`skip_condition`, an `ErrorHandler`
    /// whose pattern did not match). It neither produced output nor failed:
    /// an error edge is inactive, a CONDITIONAL edge is inactive without
    /// being evaluated (there is no output to test it against), and an
    /// unconditional edge stays active — its child runs and sees the skip
    /// envelope, as it always has.
    SkippedItself,
    /// The node failed and has error edges: only the error edges are active.
    FailedToErrorEdges,
    /// The node failed under `continue_on_error`: every edge carries the
    /// failure envelope, conditions unevaluated — the historical contract of
    /// that path. See [`EdgeResolution::ActiveAfterFailure`] for why it does
    /// not satisfy an early-ready join by itself.
    ContinuedAfterFailure,
}

/// The envelope written for a node whose every incoming edge resolved
/// inactive. `reason` distinguishes it from a node that skipped ITSELF
/// (`skip_condition`, `error_pattern_mismatch`).
fn inactive_inputs_skip_envelope() -> JsonValue {
    serde_json::json!({
        "__skipped": true,
        "reason": "no_active_input",
    })
}

fn is_error_edge(edge: &EdgeLogic) -> bool {
    edge.edge_type == "error"
}

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
    /// to the normal insert-and-release-successors path.
    ///
    /// Consolidates the fix pattern from three earlier single-site
    /// commits (verify-node: b69aad5, `confidence_gate`: a7dd2b3,
    /// `expression_dispatch`: a941df4) so every system-node caller in
    /// the reactor body uses one consistent mechanism.
    ///
    /// `wall_time_ms` is MONOTONIC elapsed milliseconds for the dispatch,
    /// or `0` meaning UNKNOWN — never "instantaneous"; it is bound onto
    /// whichever completion event the failure path writes, exactly as on
    /// the module-dispatch path (see `handle_completed_future`). Callers
    /// that evaluate their system node SYNCHRONOUSLY IN PROCESS start no
    /// timer and pass a literal `0`; `try_dispatch_sub_workflow` measures
    /// its own dispatch and passes the real reading, so a sub-workflow
    /// that FAILS is timed the same as one that succeeds.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn route_system_node_output(
        &self,
        node_idx: NodeIndex,
        output: JsonValue,
        execution_id: Uuid,
        wall_time_ms: u64,
        chains_ctx: Option<(&[Vec<NodeIndex>], &HashMap<NodeIndex, usize>)>,
        exec_ctx: &Option<Box<dyn talos_workflow_engine_core::ExecutionSanitizer>>,
        results: &mut HashMap<Uuid, JsonValue>,
        joins: &mut Joins,
        ready: &mut VecDeque<NodeIndex>,
    ) -> Result<(), String> {
        // Timeout attribution: the commit chokepoint for system nodes
        // that route their output here instead of through the
        // `commit_and_release!` macro. Counted once for both branches; the
        // `executing.next()` completion path marks its own nodes and
        // never reaches this function, so there is no double count.
        self.progress.mark_finished(self.graph[node_idx]);
        // The failure REASON, where the envelope carries one. An envelope
        // with no `error_message` field — the mis-shaped `{"__error":
        // "…"}` string form #733 taught the classifier to read — used to
        // fail the run under the generic wording below, discarding the
        // very text that caused the failure.
        let reason = if output_reports_error(&output) {
            Some(error_reason(&output).unwrap_or_else(|| "system node rejected output".to_string()))
        } else {
            None
        };
        if let Some(msg) = reason {
            self.handle_completed_future(
                node_idx,
                Err(msg),
                execution_id,
                wall_time_ms,
                chains_ctx,
                exec_ctx,
                results,
                joins,
                ready,
            )
            .await
        } else {
            let node_id = self.graph[node_idx];
            results.insert(node_id, output);
            self.release_successors(node_idx, Release::Succeeded, results, joins, ready);
            Ok(())
        }
    }

    /// Post-completion processing for a node whose dispatch future
    /// just returned from `executing.next().await`.
    ///
    /// Handles both the `Ok(output)` and `Err(error_message)` paths:
    ///
    /// * **Success.** Size-guard the output, sanitize it, insert into
    ///   `results`, fire the `on_node_completed` hook, decide any interior
    ///   chain nodes (primary scheduler only), then release successors
    ///   through [`Self::release_successors`].
    ///
    /// * **Failure.** DLP-scrub the error, emit `node_failed`, and
    ///   route based on node topology: if the node has outgoing error
    ///   edges they fire; if the node has `__continue_on_error` set we
    ///   propagate a `__continued` envelope and keep going; otherwise
    ///   we notify the hook and return `Err` so the scheduler bails.
    ///
    /// `chains_ctx` is the primary scheduler's chain-detection output
    /// (chains slice + `node_to_chain` map); `None` for the seeded
    /// scheduler, which doesn't run pipeline batching.
    ///
    /// `wall_time_ms` is MONOTONIC elapsed milliseconds, or `0` meaning
    /// UNKNOWN — never "instantaneous". It is read off the
    /// `std::time::Instant` that `run_scheduler_loop` parks in
    /// `node_start_times` immediately before dispatching the node, and
    /// `run_scheduler_loop` is shared by BOTH entry points.
    ///
    /// This corrected a false claim, in the same spirit as #708's
    /// correction of #707's column comment. The previous text said the
    /// value "is 0 on the primary (no per-node timing) and the measured
    /// elapsed time on the seeded scheduler". There is no such split: the
    /// dispatch path measures every module node on either entry point.
    /// What is really `0` is a per-CALLER property — the four sites that
    /// evaluate a system node SYNCHRONOUSLY IN PROCESS and never start a
    /// timer (`route_system_node_output`, plus the verify /
    /// confidence-gate / dynamic-dispatch failure branches) pass a
    /// literal `0`. Believing the old text would make it look as though
    /// binding this value to `execution_events.duration_ms` covered only
    /// resumed runs, when it in fact covers ~89% of all completion rows.
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
        joins: &mut Joins,
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
                    joins,
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
                    joins,
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
        joins: &mut Joins,
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
                // MONOTONIC. `wall_time_ms` reaches us from
                // `run_scheduler_loop`, which reads it back off the
                // `std::time::Instant` it parked in `node_start_times`
                // immediately before dispatching this node — the same clock,
                // and very nearly the same span, as the `dispatch_started`
                // that #707 rescued for `module_executions`. Until now it
                // went only to the `on_node_completed` hook, and the trigger
                // rewrote this event's `duration_ms` as
                // `completed - started` wall clock: 2.79x inflated in
                // aggregate on this host, 17x on the worst execution.
                // `monotonic_ms` maps the `0` unknown-sentinel back to
                // `None`, so the four literal-`0` callers below keep
                // deriving exactly as they do today.
                duration_ms: NodeEventWrite::monotonic_ms(wall_time_ms),
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
        // A module's committed output is the next node's gathered INPUT, so an
        // engine-authored INPUT key riding on it (a module that echoes its
        // input, a custom dispatcher, an LLM asked to "return the input plus a
        // field") would be inherited by every successor whose own dispatch
        // declines to write that key. Strip the fixed list here — ONE list,
        // the same one the trigger-seed install and the controller seam use.
        // Output-side protocol keys (`__error`, `__continued`,
        // `__memory_write__`, `__ops_alert__`, `__ml_distill__`,
        // `__fuel_consumed__`, `__judge_*`, …) are NOT on that list and pass
        // through untouched — see `ENGINE_AUTHORED_INPUT_KEYS`.
        talos_workflow_engine_core::reserved_keys::strip_engine_authored_keys(&mut output);

        // ── Write ceiling on the `__memory_write__` envelope (#750) ──
        // A module reaches actor_memory two ways: an `agent_memory::set` host
        // call (gated in the worker) and a returned `__memory_write__`
        // envelope (this path, which had NO gate — so a `readonly` actor was
        // refused one and permitted the other on the same job). Applied HERE,
        // before `results.insert`, so a refused envelope never reaches the
        // stored output, the downstream nodes' gathered inputs, or the
        // lifecycle hook that would persist it. The ceiling is the ENGINE's
        // — on a sub-engine that is the value `bind_subengine_actor_and_ceilings`
        // already narrowed, so a sub-workflow bound to a stricter actor is
        // gated at the stricter ceiling.
        let refused_memory_write = crate::write_ceiling_gate::apply_memory_write_ceiling(
            &mut output,
            self.max_write_ceiling,
            crate::write_ceiling_gate::controller_write_ceiling_enforced(),
            |s| self.redact_str(s),
        );
        results.insert(finished_id, output.clone());
        if let Some(ref refusal) = refused_memory_write {
            // DEBUG, not WARN, and deliberately so: the ONE operator-facing
            // WARN for a refusal is emitted by the hook
            // (`ControllerNodeHook::record_memory_write_refusal`), which owns
            // the audit vocabulary and the metric. Logging it at WARN here too
            // would double-count every refusal for anyone grepping
            // `talos_audit`. This line exists to carry the `execution_id` the
            // hook signature does not receive, and to leave a breadcrumb on an
            // engine wired with no hook at all.
            tracing::debug!(
                key = %refusal.key,
                node_id = %finished_id,
                actor_id = ?self.actor_id,
                %execution_id,
                "write-ceiling: __memory_write__ envelope removed from node output"
            );
            if let Some(hook) = self.node_hook.as_ref() {
                hook.on_memory_write_refused(
                    self.actor_id,
                    Some(finished_id),
                    &refusal.key,
                    self.max_write_ceiling,
                );
            }
        }

        // Post-completion hook: drives fuel attribution,
        // `__memory_write__` persistence, and any future cross-cutting
        // per-node observers. Fire-and-forget — the hook returns
        // quickly; impls spawn internally. `wall_time_ms` is the
        // monotonic reading from `node_start_times` on BOTH entry points
        // (see the note on `handle_completed_future`); `0` means the
        // caller started no timer, not that the node was instantaneous.
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
                    max_write_ceiling: self.max_write_ceiling,
                    http_verb_ceiling: self.http_verb_ceiling,
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
                // The snapshot's cardinality (count of completed nodes) is the
                // monotonic sequence number: it only grows over the execution's
                // life and continues across a resume (the resumed engine seeds
                // `results` from the loaded checkpoint). The store drops a save
                // whose seq is below the stored one, so a reordered stale write
                // can't clobber newer resume material. `as i64` is safe — node
                // counts are far below i64::MAX.
                let seq = results.len() as i64;
                let store = cp.store.clone();
                tokio::spawn(async move {
                    if let Err(e) = store.save(execution_id, &snapshot, seq).await {
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

        // Chain execution: the chain's nodes ran inside the pipeline, so
        // decide them all — none may be enqueued again by a later
        // resolution. Primary scheduler only — the seeded path doesn't run
        // pipeline batching.
        self.decide_chain_members(finished_idx, chains_ctx, joins);

        self.release_successors(finished_idx, Release::Succeeded, results, joins, ready);
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
        joins: &mut Joins,
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
                // Same monotonic value as the success path — the failure
                // branch of `handle_completed_future` receives the identical
                // `wall_time_ms`, so coverage here is symmetric rather than
                // half-labelled. A node that fails after 110 s of retries is
                // a 110 s node; the four in-process evaluation paths that
                // pass a literal `0` supply no measurement and fall through
                // to the derivation via `monotonic_ms`.
                duration_ms: NodeEventWrite::monotonic_ms(wall_time_ms),
            })
            .await;
        }

        let error_edges = self
            .graph
            .edges_directed(finished_idx, Direction::Outgoing)
            .filter(|e| is_error_edge(e.weight()))
            .count();

        if error_edges > 0 {
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
                error_handlers = error_edges,
                "Node failed but has error handler edges — routing to error handlers"
            );

            // Chain interior nodes are decided too — primary scheduler only.
            self.decide_chain_members(finished_idx, chains_ctx, joins);

            // Only the error edges carry the failure; the success path is
            // dead, and its children cascade as skipped unless another live
            // edge reaches them.
            self.release_successors(
                finished_idx,
                Release::FailedToErrorEdges,
                results,
                joins,
                ready,
            );
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
            self.release_successors(
                finished_idx,
                Release::ContinuedAfterFailure,
                results,
                joins,
                ready,
            );
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
                    max_write_ceiling: self.max_write_ceiling,
                    http_verb_ceiling: self.http_verb_ceiling,
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

    /// Resolve every outgoing edge of `finished_idx` according to `how`, then
    /// enqueue each child whose fate that decides and cascade each child it
    /// skips. The ONE successor-release path: the module completion handler,
    /// the system-node router, both failure routes and every inline commit in
    /// the reactor call it, and nothing else may touch the join table's
    /// verdicts.
    ///
    /// A node skipped here is written as
    /// `{"__skipped": true, "reason": "no_active_input"}` and its own outgoing
    /// edges resolve inactive in turn, iteratively, so the cascade reaches the
    /// bottom of the graph in one call and every node it reaches is RECORDED
    /// as skipped. Because a node's verdict depends only on the set of its
    /// resolved edges (see [`Joins`]), the outcome does not depend on the
    /// order in which parents finish.
    ///
    /// Conditions are evaluated against the output already committed to
    /// `results` for `finished_idx` — the sanitized, size-guarded value the
    /// children will actually receive.
    pub(crate) fn release_successors(
        &self,
        finished_idx: NodeIndex,
        how: Release,
        results: &mut HashMap<Uuid, JsonValue>,
        joins: &mut Joins,
        ready: &mut VecDeque<NodeIndex>,
    ) {
        // Decide every edge first, against an immutable view of the committed
        // output; the verdicts below then write skip envelopes into `results`.
        let resolutions: Vec<(NodeIndex, EdgeResolution)> = {
            let committed = results.get(&self.graph[finished_idx]);
            self.graph
                .edges_directed(finished_idx, Direction::Outgoing)
                .map(|edge| {
                    (
                        edge.target(),
                        self.resolve_edge(edge.weight(), how, committed),
                    )
                })
                .collect()
        };

        let mut to_skip: VecDeque<NodeIndex> = VecDeque::new();
        for (child, resolution) in resolutions {
            self.apply_join_verdict(child, resolution, joins, ready, &mut to_skip);
        }
        while let Some(skipped) = to_skip.pop_front() {
            let skipped_id = self.graph[skipped];
            tracing::info!(
                node_id = %skipped_id,
                "Skipping node: no incoming edge carried output (false condition, \
                 error edge off a success, success edge off a failure, or skipped parent)"
            );
            results.insert(skipped_id, inactive_inputs_skip_envelope());
            let children: Vec<NodeIndex> = self
                .graph
                .edges_directed(skipped, Direction::Outgoing)
                .map(|edge| edge.target())
                .collect();
            for child in children {
                self.apply_join_verdict(
                    child,
                    EdgeResolution::Inactive,
                    joins,
                    ready,
                    &mut to_skip,
                );
            }
        }
    }

    fn apply_join_verdict(
        &self,
        child: NodeIndex,
        resolution: EdgeResolution,
        joins: &mut Joins,
        ready: &mut VecDeque<NodeIndex>,
        to_skip: &mut VecDeque<NodeIndex>,
    ) {
        match joins.resolve(child, resolution, self.fan_in_join_mode(child)) {
            JoinVerdict::Run => ready.push_back(child),
            JoinVerdict::Skip => to_skip.push_back(child),
            JoinVerdict::Waiting | JoinVerdict::AlreadyDecided => {}
        }
    }

    /// How one outgoing edge resolves for a node that finished `how`.
    fn resolve_edge(
        &self,
        edge: &EdgeLogic,
        how: Release,
        committed: Option<&JsonValue>,
    ) -> EdgeResolution {
        let error_edge = is_error_edge(edge);
        match how {
            Release::FailedToErrorEdges => {
                if error_edge {
                    EdgeResolution::Active
                } else {
                    EdgeResolution::Inactive
                }
            }
            Release::ContinuedAfterFailure => EdgeResolution::ActiveAfterFailure,
            Release::SkippedItself => {
                if error_edge || edge.condition.is_some() {
                    EdgeResolution::Inactive
                } else {
                    EdgeResolution::Active
                }
            }
            Release::Succeeded => {
                if error_edge {
                    return EdgeResolution::Inactive;
                }
                let Some(cond) = edge.condition.as_deref() else {
                    return EdgeResolution::Active;
                };
                let context = committed.map_or(&JsonValue::Null, |v| Self::unwrap_output(v));
                if self.eval_bool_kinded(crate::condition_eval::ConditionKind::Edge, cond, context)
                {
                    EdgeResolution::Active
                } else {
                    tracing::info!(
                        condition = %cond,
                        output_keys = ?context
                            .as_object()
                            .map(|m| m.keys().cloned().collect::<Vec<_>>())
                            .unwrap_or_default(),
                        "Edge condition false — the edge will not carry output"
                    );
                    EdgeResolution::Inactive
                }
            }
        }
    }

    /// The `FanIn` join mode of `idx`, or `None` for every other node kind
    /// (which waits for all of its incoming edges).
    fn fan_in_join_mode(&self, idx: NodeIndex) -> Option<&JoinMode> {
        match self.node_meta.get(&self.graph[idx]) {
            Some((_, _, Some(SystemNodeKind::FanIn { join_mode, .. }))) => Some(join_mode),
            _ => None,
        }
    }

    /// A pipeline chain completes as ONE future keyed on its tail: decide
    /// every member so none is enqueued again. No-op on the seeded scheduler,
    /// which runs no chains.
    fn decide_chain_members(
        &self,
        finished_idx: NodeIndex,
        chains_ctx: Option<(&[Vec<NodeIndex>], &HashMap<NodeIndex, usize>)>,
        joins: &mut Joins,
    ) {
        if let Some((chains, node_to_chain)) = chains_ctx {
            if let Some(&chain_idx) = node_to_chain.get(&finished_idx) {
                for &n in &chains[chain_idx] {
                    joins.decide(n);
                }
            }
        }
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
