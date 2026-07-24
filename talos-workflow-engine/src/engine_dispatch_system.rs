//! System-node evaluation helpers — extracted from engine.rs.
//!
//! Hosts the per-kind computation the scheduler-side `try_dispatch_*`
//! wrappers (see `scheduler_handlers`) and the reactor loop lean on:
//! fan-in aggregation (`aggregate_fan_in`, `apply_fan_in_early_ready`),
//! synthesize / verify / confidence-gate evaluation, input gathering
//! and accumulated-context memoization, module artifact fetching, the
//! world-aware memory-injection gate (`node_needs_memory_for_world`),
//! and the node-lifecycle event emitters. Pure code movement from the
//! previous engine.rs location — no behaviour change. Lifted out so
//! each helper's semantics stay auditable in isolation.

use std::collections::HashMap;
use std::sync::Arc;

use petgraph::graph::NodeIndex;
use petgraph::Direction;
use serde_json::{Map, Value as JsonValue};
use talos_workflow_engine_core::{JoinMode, ModuleFetcher, NodeEventWrite, SystemNodeKind};
use uuid::Uuid;

use crate::emit_event_spawn;
use crate::engine::ParallelWorkflowEngine;

impl ParallelWorkflowEngine {
    /// Whether `node_id` declares it consumes the injected
    /// `__actor_context__` (its `needs_memory` graph-json field). Defaults
    /// to `true` for any node without the field — an existing graph
    /// behaves exactly as before. Consulted at dispatch time only when
    /// `talos_config::smart_memory_context_enabled()` is ON; when OFF the
    /// context is injected into every node regardless (byte-identical to
    /// the legacy path). See
    /// [`talos_workflow_engine_core::reserved_keys::should_inject_actor_context`].
    pub(crate) fn node_needs_memory(&self, node_id: Uuid) -> bool {
        talos_workflow_engine_core::reserved_keys::node_needs_memory_from_config(
            self.node_configs.get(&node_id),
        )
    }

    /// Capability-world-aware variant of [`node_needs_memory`](Self::node_needs_memory).
    ///
    /// An EXPLICIT `needs_memory` in node config always wins. When absent, the
    /// default is `false` for pure-egress/send worlds (http / network /
    /// messaging — see [`talos_capability_world::world_defaults_no_memory`]) and
    /// `true` for every other world. This keeps the injected `__actor_context__`
    /// memory view OUT of the "send" leg of the delivery-node-pattern by default
    /// — a security default that matters now that a `tier1` actor can be
    /// `egress=public` (so injected memory could otherwise egress). Call this at
    /// dispatch, where the node's resolved `capability_world` is known.
    pub(crate) fn node_needs_memory_for_world(
        &self,
        node_id: Uuid,
        capability_world: &str,
    ) -> bool {
        talos_workflow_engine_core::reserved_keys::explicit_needs_memory(
            self.node_configs.get(&node_id),
        )
        .unwrap_or_else(|| !talos_capability_world::world_defaults_no_memory(capability_world))
    }

    /// Gather inputs for a node based on completed parent results.
    ///
    /// - **Single parent**: passes the parent output directly (unwrapped)
    /// - **Multiple parents**: wraps outputs in an object keyed by user-defined
    ///   node label (from `node_labels`) or falling back to the internal UUID.
    pub(crate) fn gather_inputs(
        &self,
        node_idx: NodeIndex,
        results: &HashMap<Uuid, JsonValue>,
    ) -> JsonValue {
        let parents: Vec<(Uuid, &JsonValue)> = self
            .graph
            .neighbors_directed(node_idx, Direction::Incoming)
            .filter_map(|p_idx| {
                let pid = self.graph[p_idx];
                results.get(&pid).map(|out| (pid, Self::unwrap_output(out)))
            })
            .collect();

        match parents.len() {
            0 => JsonValue::Object(Map::new()),
            1 => {
                // Single parent: pass output directly — no UUID wrapping.
                parents[0].1.clone()
            }
            _ => {
                // Multiple parents: key by user-defined label or internal UUID.
                let mut map = Map::new();
                for (pid, output) in parents {
                    let key = self
                        .node_labels
                        .get(&pid)
                        .cloned()
                        .unwrap_or_else(|| pid.to_string());
                    map.insert(key, output.clone());
                }
                JsonValue::Object(map)
            }
        }
    }

    /// Load the Wasm bytecode for a given node ID (enforces user ownership).
    ///
    /// Three layers: the engine-local speculative-prefetch cache, a
    /// "no fetcher configured" MVP fallback for dev harnesses, and — in
    /// the normal case — a delegation to the configured
    /// [`ModuleFetcher`] which owns the real resolution pipeline
    /// (primary lookup, stale-ref-by-name, template fallback,
    /// precompiled-template fallback, Redis cache warm-up).
    pub(crate) async fn fetch_module(
        &self,
        node_id: Uuid,
    ) -> Result<talos_workflow_engine_core::WasmModuleArtifact, String> {
        if let Some(cached) = self.module_prefetch_cache.remove(&node_id) {
            tracing::debug!(node_id = %node_id, "fetch_module: speculative prefetch cache hit");
            return Ok(cached.1);
        }
        // P2: per-execution artifact cache keyed on the resolved module_id. A
        // workflow reusing one module across M nodes/branches would otherwise
        // re-SELECT the full wasm_bytes blob M times per run. Populated lazily
        // by `fetch_module_artifact_cached`; scoped to this engine instance, so
        // it never leaks across executions. The speculative-prefetch cache
        // above is consulted first and remains authoritative for nodes that
        // were pre-warmed while a slow predecessor ran.
        let module_id = self.resolve_module_id(node_id);
        let Some(fetcher) = self.module_fetcher.as_ref() else {
            // Dev / smoke-test convenience: a bare `ParallelWorkflowEngine::new()`
            // with no services wired up falls through to a local wasm artifact.
            // Gated on `debug_assertions` so release binaries never read arbitrary
            // files off disk when a caller misconfigures — they get a clear error
            // instead.
            #[cfg(debug_assertions)]
            {
                let bytes =
                    std::fs::read("example-node/target/wasm32-wasi/release/my_first_node.wasm")
                        .map_err(|e| format!("failed to read wasm module: {}", e))?;
                return Ok(talos_workflow_engine_core::WasmModuleArtifact {
                    module_id,
                    content_hash: "example".to_string(),
                    wasm_bytes: bytes,
                    oci_url: None,
                    max_fuel: 1_000_000,
                    capability_world: "unknown".to_string(),
                    allowed_hosts: vec![],
                    allowed_methods: vec![],
                    allowed_secrets: vec![],
                    requires_approval_for: vec![],
                    integration_name: None,
                    config: None,
                });
            }
            #[cfg(not(debug_assertions))]
            return Err(
                "engine has no module fetcher configured; construct with `with_services` \
                 or call `set_module_fetcher` before dispatching"
                    .to_string(),
            );
        };
        let user_id = self.user_id.ok_or_else(|| {
            "Module execution requires user context (user_id not set)".to_string()
        })?;
        let artifact = self
            .fetch_module_artifact_cached(fetcher, module_id, user_id)
            .await?;
        // Single-node dispatch wants an owned artifact; deep-clone the cached
        // value out of the Arc. The expensive DB round-trip is what we cache —
        // this clone is unavoidable for the owned-artifact callers and is the
        // same allocation the pre-cache code already made.
        Ok((*artifact).clone())
    }

    /// Fetch a module artifact through the per-execution cache (P2).
    ///
    /// Caches by **resolved `module_id`** for the lifetime of this engine
    /// instance: module bytes are run-invariant, so M nodes/branches that
    /// dispatch the same module incur exactly one `fetcher.fetch` (one
    /// full-`wasm_bytes` SELECT) per run instead of M. Returns an `Arc` so
    /// callers that only need to read fields (the pipeline path) share the
    /// allocation with no clone; the owned-artifact caller (`fetch_module`)
    /// clones once at the boundary.
    ///
    /// Concurrency: two nodes for the same module can race here while the pool
    /// has free slots. Both may issue a `fetch` on a cold cache; the second
    /// writer's `insert` simply overwrites with an identical artifact (the
    /// bytes are run-invariant), so the only cost of the race is a redundant
    /// fetch, never an inconsistent result. We deliberately don't hold a
    /// per-key lock across the `.await` to avoid serializing independent module
    /// loads.
    pub(crate) async fn fetch_module_artifact_cached(
        &self,
        fetcher: &Arc<dyn ModuleFetcher>,
        module_id: Uuid,
        user_id: Uuid,
    ) -> Result<Arc<talos_workflow_engine_core::WasmModuleArtifact>, String> {
        if let Some(cached) = self.module_artifact_cache.get(&module_id) {
            tracing::debug!(module_id = %module_id, "fetch_module: per-execution artifact cache hit");
            return Ok(cached.clone());
        }
        let artifact = fetcher
            .fetch(module_id, user_id)
            .await
            .map_err(|e| e.to_string())?;
        let artifact = Arc::new(artifact);
        self.module_artifact_cache
            .insert(module_id, artifact.clone());
        Ok(artifact)
    }

    // ── Shared node-type helpers ──────────────────────────────────────────
    // The following methods extract duplicated per-node-type logic that was
    // previously inlined in both `run()` and `run_with_seed()`.  Each helper
    // performs the pure computation for a local-dispatch node kind and returns
    // the output `JsonValue` to be inserted into the results map.  The caller
    // is responsible for inserting the result, emitting lifecycle events, and
    // unblocking successors.

    /// Aggregate parent outputs for a `FanIn` node.
    ///
    /// Collects all incoming node outputs and combines them according to
    /// `join_mode`.  If `aggregation_expr` is provided, it is evaluated as a
    /// Rhai condition against the aggregated value — on failure the result is
    /// replaced with `{"__aggregation_failed": true}`.
    pub(crate) fn aggregate_fan_in(
        &self,
        node_idx: NodeIndex,
        results: &HashMap<Uuid, JsonValue>,
        join_mode: &JoinMode,
        aggregation_expr: &Option<String>,
    ) -> JsonValue {
        let node_id = self.graph[node_idx];
        let parent_outputs: Vec<&JsonValue> = self
            .graph
            .neighbors_directed(node_idx, Direction::Incoming)
            .filter_map(|p| results.get(&self.graph[p]))
            .collect();

        let aggregated = match join_mode {
            JoinMode::All => serde_json::json!(parent_outputs),
            JoinMode::Any => parent_outputs
                .first()
                .map(|v| (*v).clone())
                .unwrap_or(serde_json::json!(null)),
            JoinMode::Majority => serde_json::json!(parent_outputs),
            JoinMode::N(_) => serde_json::json!(parent_outputs),
            // `JoinMode` is `#[non_exhaustive]`; default unknown future
            // variants to the conservative `All`-shaped aggregation.
            _ => serde_json::json!(parent_outputs),
        };

        let final_result = if let Some(expr) = aggregation_expr {
            if self.eval_bool(expr, &aggregated) {
                aggregated
            } else {
                serde_json::json!({"__aggregation_failed": true})
            }
        } else {
            aggregated
        };

        tracing::info!(
            node_id = %node_id,
            join_mode = ?join_mode,
            parent_count = parent_outputs.len(),
            "FanIn aggregation completed locally"
        );

        final_result
    }

    /// Gather and collect parent outputs for a Collect node.
    ///
    /// Strips engine-internal metadata (`__`-prefixed keys) from each branch
    /// output — EXCEPT error markers (`__error`, `__continued`), which are
    /// preserved so downstream handlers have a reliable signal when a
    /// `continue_on_error` parent errored. `error_message` is already a
    /// non-prefixed field and passes through unconditionally.
    pub(crate) fn collect_parent_outputs_for_node(
        &self,
        node_idx: NodeIndex,
        results: &HashMap<Uuid, JsonValue>,
    ) -> JsonValue {
        let node_id = self.graph[node_idx];
        let parent_outputs: Vec<JsonValue> = self
            .graph
            .neighbors_directed(node_idx, Direction::Incoming)
            .filter_map(|p| results.get(&self.graph[p]).cloned())
            .map(|v| {
                if let JsonValue::Object(mut obj) = v {
                    obj.retain(|k, _| !k.starts_with("__") || k == "__error" || k == "__continued");
                    JsonValue::Object(obj)
                } else {
                    v
                }
            })
            .collect();

        let parent_count = parent_outputs.len();
        let collected = serde_json::json!({
            "items": parent_outputs,
            "count": parent_count,
        });

        tracing::info!(
            node_id = %node_id,
            parent_count,
            "Collect node gathered all parent outputs into object"
        );

        collected
    }

    /// Build accumulated context from all completed node results so far.
    ///
    /// Returns a JSON object keyed by node label containing each prior node's
    /// output, with engine-internal `__`-prefixed keys stripped from values.
    /// Nodes whose labels start with `__` (engine internals like `__trigger__`)
    /// are omitted entirely. Returns `None` if no user-visible results exist.
    ///
    /// The result is wrapped in [`Arc`] so the single per-version build can be
    /// shared by reference across every node dispatched at that version — the
    /// per-node envelope only deep-clones the inner value at the point it
    /// actually injects `__accumulated__`, and concurrent in-flight dispatches
    /// share one allocation instead of each rebuilding from scratch. The loop
    /// memoizes the `Arc` against a results-version counter (see
    /// `build_accumulated_context_memo`), so the O(N) build runs once per
    /// committed result rather than once per node dispatch (was O(N²·S)).
    pub(crate) fn build_accumulated_context(
        node_labels: &HashMap<Uuid, String>,
        results: &HashMap<Uuid, JsonValue>,
    ) -> Option<Arc<serde_json::Value>> {
        let accumulated: Map<String, JsonValue> = results
            .iter()
            .filter_map(|(id, val)| {
                let label = node_labels
                    .get(id)
                    .cloned()
                    .unwrap_or_else(|| id.to_string());
                // Skip engine-internal nodes (trigger, etc.)
                if label.starts_with("__") {
                    return None;
                }
                // Strip __-prefixed metadata keys from the value
                let cleaned = if let JsonValue::Object(obj) = val {
                    let mut c = obj.clone();
                    c.retain(|k, _| !k.starts_with("__"));
                    JsonValue::Object(c)
                } else {
                    val.clone()
                };
                Some((label, cleaned))
            })
            .collect();

        if accumulated.is_empty() {
            None
        } else {
            Some(Arc::new(JsonValue::Object(accumulated)))
        }
    }

    /// Memoized wrapper over [`build_accumulated_context`].
    ///
    /// The accumulated context is a pure function of `(node_labels, results)`.
    /// `node_labels` is fixed for the lifetime of a run and `results` only ever
    /// grows (the reactor loop only ever `insert`s, never removes), so the loop
    /// bumps `version` on every commit and this helper rebuilds — and clones the
    /// shared `Arc` for the caller — only when the cached version is stale.
    /// Behaviour is byte-for-byte identical to calling `build_accumulated_context`
    /// directly at each dispatch site; only the redundant rebuilds are elided.
    pub(crate) fn build_accumulated_context_memo(
        node_labels: &HashMap<Uuid, String>,
        results: &HashMap<Uuid, JsonValue>,
        version: u64,
        memo: &mut Option<(u64, Option<Arc<serde_json::Value>>)>,
    ) -> Option<Arc<serde_json::Value>> {
        if let Some((cached_version, cached)) = memo {
            if *cached_version == version {
                return cached.clone();
            }
        }
        let built = Self::build_accumulated_context(node_labels, results);
        *memo = Some((version, built.clone()));
        built
    }

    /// Compute the Synthesize node output.
    ///
    /// Collects parent outputs (stripping `__`-prefixed metadata EXCEPT error
    /// markers `__error` / `__continued`, so downstream synthesis can detect
    /// errored branches), optionally evaluates a Rhai `synthesis_expr`, and
    /// returns the synthesized value. Array size is capped at 500 to match
    /// Rhai limits.
    pub(crate) fn synthesize_parent_outputs(
        &self,
        node_idx: NodeIndex,
        results: &HashMap<Uuid, JsonValue>,
        synthesis_expr: &Option<String>,
    ) -> JsonValue {
        let node_id = self.graph[node_idx];
        let parent_outputs: Vec<JsonValue> = self
            .graph
            .neighbors_directed(node_idx, Direction::Incoming)
            .filter_map(|p| results.get(&self.graph[p]).cloned())
            .map(|v| {
                if let JsonValue::Object(mut obj) = v {
                    obj.retain(|k, _| !k.starts_with("__") || k == "__error" || k == "__continued");
                    JsonValue::Object(obj)
                } else {
                    v
                }
            })
            .collect();

        let parent_count = parent_outputs.len();

        if parent_count > 500 {
            tracing::warn!(
                node_id = %node_id,
                parent_count,
                "Synthesize: parent_outputs exceeds 500 items — truncating to 500"
            );
        }
        let parent_outputs: Vec<JsonValue> = parent_outputs.into_iter().take(500).collect();
        let parent_count = parent_outputs.len();

        let synthesized = if let Some(ref expr) = synthesis_expr {
            let items_json = serde_json::json!({
                "items": &parent_outputs,
                "count": parent_count,
            });
            match self.eval_json(expr, &items_json) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(
                        node_id = %node_id,
                        error = %e,
                        "Synthesize Rhai expression failed — falling back to raw collect"
                    );
                    serde_json::json!({ "items": &parent_outputs, "count": parent_count })
                }
            }
        } else {
            serde_json::json!({ "items": &parent_outputs, "count": parent_count })
        };

        tracing::info!(
            node_id = %node_id,
            parent_count,
            has_expr = synthesis_expr.is_some(),
            "Synthesize node processed parent outputs"
        );

        synthesized
    }

    /// Evaluate a Verify node against its parent output.
    ///
    /// Returns `(result_json, passed)` where `passed` indicates whether the
    /// verification condition was satisfied.  The caller uses `passed` to
    /// select the event status string ("Completed" vs "Failed").
    pub(crate) fn evaluate_verify_node(
        &self,
        node_idx: NodeIndex,
        results: &HashMap<Uuid, JsonValue>,
        condition: &str,
        check_label: &str,
        on_failure: &str,
    ) -> (JsonValue, bool) {
        let node_id = self.graph[node_idx];
        let parent_output = self.gather_inputs(node_idx, results);
        let passed = self.eval_bool(condition, &parent_output);

        let verify_result = if passed {
            let mut out = parent_output;
            if let Some(obj) = out.as_object_mut() {
                obj.insert("__verified__".to_string(), serde_json::json!(true));
                obj.insert(
                    "__check_label__".to_string(),
                    serde_json::Value::String(check_label.to_string()),
                );
            }
            out
        } else if on_failure == "passthrough" {
            let mut out = parent_output;
            if let Some(obj) = out.as_object_mut() {
                obj.insert("__verified__".to_string(), serde_json::json!(false));
                obj.insert(
                    "__verification_failed__".to_string(),
                    serde_json::json!(true),
                );
                obj.insert(
                    "__check_label__".to_string(),
                    serde_json::Value::String(check_label.to_string()),
                );
                obj.insert(
                    "__verification_condition__".to_string(),
                    serde_json::Value::String(condition.to_string()),
                );
            }
            out
        } else {
            serde_json::json!({
                "__error": true,
                "error_message": format!(
                    "Verification failed for '{}': condition '{}' evaluated to false. \
                     Wire an error edge from this verify node to a fix-up workflow, or \
                     set on_failure: 'passthrough' to route conditionally downstream.",
                    check_label, condition
                ),
                "__verified__": false,
                "__check_label__": check_label,
            })
        };

        tracing::info!(
            node_id = %node_id,
            check_label = %check_label,
            passed,
            on_failure = %on_failure,
            "Verify node evaluated"
        );

        (verify_result, passed)
    }

    /// Evaluate a `ConfidenceGate` node against its parent output.
    ///
    /// Returns `Ok(result_json)` for pass/passthrough/error modes, or
    /// `Err(waiting_json)` when the gate is paused awaiting approval.
    /// The caller must handle the `Err` case by early-returning from the
    /// reactor loop with a `waiting: true` `WorkflowContext`.
    #[tracing::instrument(
        level = "info",
        name = "confidence_gate",
        skip_all,
        fields(
            execution_id = %execution_id,
            threshold,
            on_low_confidence,
        ),
    )]
    pub(crate) async fn evaluate_confidence_gate(
        &self,
        node_idx: NodeIndex,
        results: &HashMap<Uuid, JsonValue>,
        execution_id: Uuid,
        threshold: f64,
        confidence_path: &str,
        on_low_confidence: &str,
    ) -> Result<JsonValue, JsonValue> {
        let node_id = self.graph[node_idx];
        let parent_inputs = self.gather_inputs(node_idx, results);
        let confidence = parent_inputs
            .get(confidence_path)
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);

        if confidence >= threshold {
            let mut out = if let Some(obj) = parent_inputs.as_object() {
                obj.clone()
            } else {
                serde_json::Map::new()
            };
            out.insert(
                "__confidence_gate_passed__".to_string(),
                serde_json::json!(true),
            );
            out.insert(
                "__confidence_used__".to_string(),
                serde_json::json!(confidence),
            );
            return Ok(serde_json::Value::Object(out));
        }

        match on_low_confidence {
            "passthrough" => {
                let mut out = if let Some(obj) = parent_inputs.as_object() {
                    obj.clone()
                } else {
                    serde_json::Map::new()
                };
                out.insert(
                    "__confidence_gate_failed__".to_string(),
                    serde_json::json!(true),
                );
                out.insert(
                    "__confidence_used__".to_string(),
                    serde_json::json!(confidence),
                );
                Ok(serde_json::Value::Object(out))
            }
            "error" => Ok(serde_json::json!({
                "__error": true,
                "error_message": format!(
                    "Confidence gate: {:.3} < threshold {:.3}",
                    confidence, threshold
                ),
                "__confidence_used__": confidence,
            })),
            _ => {
                // "pause" — create approval request and suspend
                if let Some(ref gate) = self.approval_gate {
                    let required_for = vec!["low_confidence".to_string()];
                    match gate
                        .check_or_request(execution_id, node_id, &required_for, None)
                        .await
                    {
                        Ok(talos_workflow_engine_core::ApprovalStatus::Approved) => {
                            let mut out = if let Some(obj) = parent_inputs.as_object() {
                                obj.clone()
                            } else {
                                serde_json::Map::new()
                            };
                            out.insert(
                                "__confidence_gate_passed__".to_string(),
                                serde_json::json!(true),
                            );
                            out.insert(
                                "__confidence_used__".to_string(),
                                serde_json::json!(confidence),
                            );
                            out.insert(
                                "__confidence_gate_approved__".to_string(),
                                serde_json::json!(true),
                            );
                            Ok(serde_json::Value::Object(out))
                        }
                        Ok(talos_workflow_engine_core::ApprovalStatus::Pending) => {
                            Err(serde_json::json!({
                                "__waiting__": true,
                                "__confidence_used__": confidence,
                                "message": format!(
                                    "Confidence gate paused: {:.3} < threshold {:.3}. Awaiting approval.",
                                    confidence, threshold
                                ),
                            }))
                        }
                        Ok(talos_workflow_engine_core::ApprovalStatus::Denied { reason }) => {
                            Ok(serde_json::json!({
                                "__error": true,
                                "error_message": reason,
                            }))
                        }
                        // Fail-closed for non_exhaustive future variants.
                        Ok(_) => Ok(serde_json::json!({
                            "__error": true,
                            "error_message": "ConfidenceGate approval gate returned an unrecognized status",
                        })),
                        Err(e) => Ok(serde_json::json!({
                            "__error": true,
                            "error_message": format!("ConfidenceGate approval error: {}", e),
                        })),
                    }
                } else {
                    Ok(serde_json::json!({
                        "__error": true,
                        "error_message": "ConfidenceGate pause requires an approval gate",
                    }))
                }
            }
        }
    }

    /// `FanIn` early-ready: apply a [`JoinMode::Any`] / `Majority` /
    /// `N(k)` short-circuit on `child` if it's a `FanIn` node and enough
    /// parents have completed to satisfy the join. Mutates `pending`
    /// by zeroing the child's counter when the join is satisfied.
    /// `JoinMode::All` waits for every parent and is the default
    /// zero-action branch.
    pub(crate) fn apply_fan_in_early_ready(
        &self,
        child: NodeIndex,
        pending: &mut HashMap<NodeIndex, usize>,
    ) {
        let Some((_, _, Some(SystemNodeKind::FanIn { join_mode, .. }))) =
            self.node_meta.get(&self.graph[child])
        else {
            return;
        };
        let total_parents = self
            .graph
            .neighbors_directed(child, Direction::Incoming)
            .count();
        let cnt = *pending.get(&child).unwrap_or(&0);
        // `saturating_sub`: defence-in-depth against a stale/underflowed counter
        // so the completed-parent count can never wrap (the removal in
        // `handle_node_success` is the primary guard).
        let completed_parents = total_parents.saturating_sub(cnt);
        match join_mode {
            JoinMode::Any => {
                if cnt > 0 {
                    pending.insert(child, 0);
                }
            }
            JoinMode::Majority => {
                if completed_parents > total_parents / 2 && cnt > 0 {
                    pending.insert(child, 0);
                }
            }
            JoinMode::N(n) => {
                if completed_parents >= *n as usize && cnt > 0 {
                    pending.insert(child, 0);
                }
            }
            JoinMode::All => {} // default: wait for everyone
            // `JoinMode` is `#[non_exhaustive]`; default to `All`-style
            // wait-for-everyone behavior for unknown variants until the
            // engine adds explicit handling.
            _ => {}
        }
    }

    /// Fire-and-forget emit of a `node_skipped` event. Used by the
    /// skip-condition pre-filter so the scheduler's standard dispatch
    /// branches don't each have to remember to log the skip.
    pub(crate) fn emit_node_skipped_event(&self, execution_id: Uuid, node_id: Uuid) {
        emit_event_spawn(
            &self.event_sink,
            NodeEventWrite {
                execution_id,
                event_type: "node_skipped".to_string(),
                node_id: Some(node_id),
                status: "Skipped".to_string(),
                log_message: None,
                iteration_index: None,
                error_class: None,
            },
        );
    }

    /// Fire-and-forget emit of a `loop_iteration` event. Used by the
    /// `Loop`-variant handler to log progress without blocking the
    /// dispatch loop on the event sink.
    pub(crate) fn emit_loop_iteration_event(
        &self,
        execution_id: Uuid,
        node_id: Uuid,
        iteration: u32,
        max_iters: u32,
    ) {
        emit_event_spawn(
            &self.event_sink,
            NodeEventWrite {
                execution_id,
                event_type: "loop_iteration".to_string(),
                node_id: Some(node_id),
                status: "Running".to_string(),
                log_message: Some(format!("Loop iteration {iteration}/{max_iters}")),
                iteration_index: Some(iteration as i32),
                error_class: None,
            },
        );
    }

    pub(crate) fn emit_node_lifecycle_events(
        &self,
        execution_id: Uuid,
        node_id: Uuid,
        status: &str,
        log_message: String,
    ) {
        let Some(sink) = self.event_sink.as_ref() else {
            return;
        };
        let sink = Arc::clone(sink);
        let status = status.to_string();
        tokio::spawn(async move {
            sink.emit(NodeEventWrite {
                execution_id,
                event_type: "node_started".to_string(),
                node_id: Some(node_id),
                status: "Running".to_string(),
                log_message: None,
                iteration_index: None,
                error_class: None,
            })
            .await;
            sink.emit(NodeEventWrite {
                execution_id,
                event_type: "node_completed".to_string(),
                node_id: Some(node_id),
                status,
                log_message: Some(log_message),
                iteration_index: None,
                error_class: None,
            })
            .await;
        });
    }
}
