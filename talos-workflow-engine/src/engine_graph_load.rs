//! Graph loading and mutation — extracted from engine.rs.
//!
//! Hosts the graph-JSON ingestion path (`load_graph_from_json` /
//! `load_from_graph_json` → `parse_graph_document`), the pre-run
//! caches it warms (`populate_sub_workflow_cache`,
//! `preload_rate_limits_and_subflows`, `get_sub_workflow_graph`),
//! and the programmatic graph mutators (`add_node`, `add_edge`,
//! `ensure_trigger_node_wired_to_roots`). Pure code movement from the
//! previous engine.rs location — no behaviour change. Lifted out so
//! the parse/ingest surface stays auditable in isolation alongside
//! `graph_parser`.

use std::collections::{HashMap, HashSet};

use petgraph::Direction;
use serde_json::Value as JsonValue;
use talos_workflow_engine_core::{EdgeLogic, SystemNodeKind};
use uuid::Uuid;

use crate::engine::ParallelWorkflowEngine;
use crate::graph_parser::{parse_system_node_kind, read_node_retry_policy_with_actor_cap};

impl ParallelWorkflowEngine {
    /// Populate this engine's graph from a parsed React-Flow JSON
    /// value. Accepts `&Value` so callers holding a pre-parsed graph
    /// (cached sub-workflow map, [`WorkflowGraphStore`] return) don't
    /// pay a second `serde_json::from_str`; callers holding a raw
    /// string parse once at their boundary before calling.
    ///
    /// The full wire shape is documented in
    /// [`docs/graph-json-schema.md`](https://github.com/aegix-dev/talos-workflow-engine/blob/main/docs/graph-json-schema.md).
    /// Summary: an object with `nodes: []` + `edges: []` + optional
    /// `execution_timeout_secs`. Each node carries `id` (UUID), an
    /// optional module `type` / built-in `kind` discriminator, an
    /// optional per-kind `data` payload, and retry/skip hints. Each
    /// edge carries `source` / `target` plus optional `sourceHandle`,
    /// `targetHandle`, and `logic` condition.
    ///
    /// Optional `execution_timeout_secs` at the graph root overrides
    /// the default 300 s timeout. Nodes with no resolvable
    /// `module_id` (non-UUID `type` and no `data.moduleId`) are
    /// silently skipped — the engine treats them as presentation-
    /// only annotations, matching the React Flow frontend's
    /// behavior.
    ///
    /// This replaced the pre-extraction `from_graph_json` associated
    /// function that took `Arc<ModuleRegistry>` directly. Call sites
    /// now chain `self.new_subengine().load_from_graph_json(&g)?;`
    /// which decouples the engine from any single concrete adapter
    /// type.
    ///
    /// [`WorkflowGraphStore`]: talos_workflow_engine_core::WorkflowGraphStore
    pub fn load_from_graph_json(
        &mut self,
        graph: &JsonValue,
    ) -> Result<(), crate::WorkflowEngineError> {
        self.parse_graph_document(graph)
    }

    /// Collect all statically-known sub-workflow IDs from `node_meta` and batch-fetch
    /// their `graph_json` in a single query. Populates `self.sub_workflow_cache`.
    ///
    /// Called once at the start of `run()` / `run_with_seed()` to eliminate N+1 queries
    /// during node dispatch. Nodes whose workflow IDs are resolved at runtime
    /// (`DynamicDispatch`, `CapabilityDispatch`) will fall back to individual queries
    /// via `get_sub_workflow_graph()` on cache miss.
    async fn populate_sub_workflow_cache(&mut self) {
        let (store, user_id) = match (self.graph_store.as_ref(), self.user_id) {
            (Some(s), Some(u)) => (s, u),
            _ => return, // No graph store or no user_id — nothing to prefetch.
        };

        // Walk all node_meta entries and collect every referenced workflow UUID.
        let mut ids: HashSet<Uuid> = HashSet::new();
        for (_, _, kind) in self.node_meta.values() {
            match kind {
                Some(SystemNodeKind::SubWorkflow { workflow_id, .. }) => {
                    ids.insert(*workflow_id);
                }
                #[cfg(feature = "llm-primitives")]
                Some(SystemNodeKind::AgentLoop {
                    body_workflow_id, ..
                }) => {
                    ids.insert(*body_workflow_id);
                }
                #[cfg(feature = "llm-primitives")]
                Some(SystemNodeKind::Judge {
                    judge_workflow_id, ..
                }) => {
                    ids.insert(*judge_workflow_id);
                }
                #[cfg(feature = "llm-primitives")]
                Some(SystemNodeKind::Ensemble {
                    child_workflow_id,
                    judge_workflow_id,
                    ..
                }) => {
                    ids.insert(*child_workflow_id);
                    if let Some(jid) = judge_workflow_id {
                        ids.insert(*jid);
                    }
                }
                #[cfg(feature = "llm-primitives")]
                Some(SystemNodeKind::ReflectiveRetry {
                    child_workflow_id,
                    reflection_workflow_id,
                    ..
                }) => {
                    ids.insert(*child_workflow_id);
                    ids.insert(*reflection_workflow_id);
                }
                #[cfg(feature = "llm-primitives")]
                Some(SystemNodeKind::LlmDispatch {
                    classifier_workflow_id,
                    routes,
                    fallback_workflow_id,
                    ..
                }) => {
                    ids.insert(*classifier_workflow_id);
                    for wf_id in routes.values() {
                        ids.insert(*wf_id);
                    }
                    if let Some(fb) = fallback_workflow_id {
                        ids.insert(*fb);
                    }
                }
                #[cfg(feature = "llm-primitives")]
                Some(SystemNodeKind::ReActLoop {
                    body_workflow_id, ..
                }) => {
                    ids.insert(*body_workflow_id);
                }
                _ => {}
            }
        }

        // Remove nil UUIDs (used as sentinel for missing workflow_id).
        ids.remove(&Uuid::nil());

        if ids.is_empty() {
            return;
        }

        let id_vec: Vec<Uuid> = ids.into_iter().collect();
        tracing::info!(
            count = id_vec.len(),
            "Populating sub-workflow cache with batch query"
        );

        let rows = match store.get_graphs(&id_vec, user_id).await {
            Ok(map) => map,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Failed to batch-fetch sub-workflow graphs — falling back to per-node queries"
                );
                return;
            }
        };

        for (wf_id, graph_json) in rows {
            self.sub_workflow_cache.insert(wf_id, graph_json);
        }

        tracing::info!(
            cached = self.sub_workflow_cache.len(),
            "Sub-workflow cache populated"
        );
    }

    /// Look up a sub-workflow's graph JSON, checking the pre-populated cache first.
    /// Falls back to an individual DB query on cache miss (e.g., `DynamicDispatch`
    /// targets that are resolved at runtime).
    pub(crate) async fn get_sub_workflow_graph(
        &self,
        sub_wf_id: Uuid,
        user_id: Uuid,
    ) -> Option<JsonValue> {
        // Fast path: cache hit.
        if let Some(cached) = self.sub_workflow_cache.get(&sub_wf_id) {
            return Some(cached.clone());
        }
        // Cache miss — fall back to an individual query via the trait.
        tracing::debug!(
            workflow_id = %sub_wf_id,
            "Sub-workflow cache miss — falling back to individual query"
        );
        let store = self.graph_store.as_ref()?;
        match store.get_graph(sub_wf_id, user_id).await {
            Ok(g) => g,
            Err(e) => {
                tracing::warn!(error = %e, "sub-workflow graph query failed");
                None
            }
        }
    }

    /// Load a workflow graph from a JSON string (React Flow format).
    ///
    /// Parses nodes and edges from the JSON and populates the internal graph.
    pub async fn load_graph_from_json(
        &mut self,
        graph_json: &str,
    ) -> Result<(), crate::WorkflowEngineError> {
        let graph: serde_json::Value = serde_json::from_str(graph_json)
            .map_err(|e| crate::WorkflowEngineError::GraphJson(e.into()))?;

        // Full synchronous parse — nodes, system nodes, reserved-key
        // lifts, edges, execution_timeout_secs. The sync entry point
        // `load_from_graph_json` shares this exact parser, so the two
        // public methods never diverge.
        self.parse_graph_document(&graph)?;
        // Async follow-ups: rate-limit pre-load + sub-workflow graph
        // prefetch. Kept out of `parse_graph_document` so the sync entry
        // point doesn't need a runtime.
        self.preload_rate_limits_and_subflows().await;
        Ok(())
    }

    /// Async post-parse: batch-load per-module rate limits and
    /// pre-fetch all sub-workflow graphs referenced by system nodes.
    /// Eliminates N+1 queries during node dispatch.
    async fn preload_rate_limits_and_subflows(&mut self) {
        if let Some(ref fetcher) = self.module_fetcher {
            let module_ids: Vec<Uuid> = self
                .node_meta
                .values()
                .filter_map(|(mid, _, _)| *mid)
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();

            if !module_ids.is_empty() {
                let rate_limits = fetcher.load_rate_limits(&module_ids).await;
                for (id, limit) in rate_limits {
                    self.rate_limits.insert(id, limit);
                }
                if !self.rate_limits.is_empty() {
                    tracing::info!(
                        rate_limited_modules = self.rate_limits.len(),
                        "Loaded module rate limits for workflow",
                    );
                }
            }
        }
        self.populate_sub_workflow_cache().await;
    }

    /// Single authoritative synchronous parser for React-Flow graph JSON.
    ///
    /// Accepts both the `&Value` entry point ([`load_from_graph_json`])
    /// and the `&str` entry point ([`load_graph_from_json`], after JSON
    /// parsing) delegate here, so the two public methods see exactly the
    /// same parser semantics:
    ///
    /// * Module nodes (`type = <uuid>` or `data.moduleId = <uuid>`) and
    ///   system nodes (`type = "system:<kind>"` or an explicit `kind`
    ///   field) are both recognised.
    /// * `execution_timeout_secs` at the graph root overrides the
    ///   default.
    /// * `skip_condition` / `continue_on_error` are lifted into reserved
    ///   `__skip_condition` / `__continue_on_error` node-config keys.
    /// * Edges carry `sourceHandle` / `targetHandle` / `condition` /
    ///   `edge_type` when present.
    ///
    /// Returns [`crate::WorkflowEngineError::EmptyGraph`] when `nodes`
    /// is missing or empty (the engine refuses to run a graph with no
    /// work). Parse-time failures surface as
    /// [`crate::WorkflowEngineError::GraphJson`]; other load-time
    /// rejections surface as
    /// [`crate::WorkflowEngineError::LoadGraph`].
    ///
    /// Async follow-ups (rate-limit pre-load, sub-workflow graph
    /// prefetch) are intentionally out of scope — see
    /// [`load_graph_from_json`] for where they run.
    ///
    /// [`load_from_graph_json`]: Self::load_from_graph_json
    /// [`load_graph_from_json`]: Self::load_graph_from_json
    pub(crate) fn parse_graph_document(
        &mut self,
        graph: &JsonValue,
    ) -> Result<(), crate::WorkflowEngineError> {
        let empty_vec = vec![];
        let nodes = graph
            .get("nodes")
            .and_then(|n| n.as_array())
            .unwrap_or(&empty_vec);

        if nodes.is_empty() {
            return Err(crate::WorkflowEngineError::EmptyGraph);
        }

        if let Some(timeout) = graph
            .get("execution_timeout_secs")
            .and_then(JsonValue::as_u64)
        {
            self.execution_timeout_secs = timeout;
        }

        // Map RF node ID → unique engine node UUID. The node_id in the
        // engine graph MUST be unique per node (not per module) to
        // allow the same module in multiple nodes without creating
        // false cycle detections.
        let mut rf_to_node: HashMap<String, Uuid> = HashMap::new();

        for node in nodes {
            let rf_id = node.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let module_id_str = node
                .get("type")
                .and_then(|v| v.as_str())
                .filter(|s| Uuid::parse_str(s).is_ok())
                .or_else(|| {
                    node.get("data")
                        .and_then(|d| d.get("moduleId"))
                        .and_then(|v| v.as_str())
                });
            if let Some(module_id_str) = module_id_str {
                if let Ok(module_id) = Uuid::parse_str(module_id_str) {
                    // Reuse RF ID if it's a UUID, else derive a
                    // deterministic UUID from the string via SHA-256.
                    let node_id = Uuid::parse_str(rf_id).unwrap_or_else(|_| {
                        use sha2::{Digest, Sha256};
                        let hash = Sha256::digest(rf_id.as_bytes());
                        let mut bytes = [0u8; 16];
                        bytes.copy_from_slice(&hash[..16]);
                        Uuid::from_bytes(bytes)
                    });
                    rf_to_node.insert(rf_id.to_string(), node_id);
                    self.node_labels.insert(node_id, rf_id.to_string());

                    if let Some(data) = node.get("data").cloned() {
                        if data.is_object()
                            && !data.as_object().map(|m| m.is_empty()).unwrap_or(true)
                        {
                            self.node_configs.insert(node_id, data.clone());
                        }
                        // skip_condition → reserved `__skip_condition`.
                        if let Some(skip_cond) = data
                            .get("skip_condition")
                            .and_then(|v| v.as_str())
                            .or_else(|| node.get("skip_condition").and_then(|v| v.as_str()))
                            .or_else(|| {
                                node.get("config")
                                    .and_then(|c| c.get("skip_condition"))
                                    .and_then(|v| v.as_str())
                            })
                        {
                            let entry = self
                                .node_configs
                                .entry(node_id)
                                .or_insert_with(|| serde_json::json!({}));
                            entry.as_object_mut().map(|m| {
                                m.insert(
                                    "__skip_condition".to_string(),
                                    serde_json::json!(skip_cond),
                                )
                            });
                        }
                        // continue_on_error → reserved `__continue_on_error`.
                        if data
                            .get("continue_on_error")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false)
                            || node
                                .get("continue_on_error")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false)
                        {
                            let entry = self
                                .node_configs
                                .entry(node_id)
                                .or_insert_with(|| serde_json::json!({}));
                            entry.as_object_mut().map(|m| {
                                m.insert("__continue_on_error".to_string(), serde_json::json!(true))
                            });
                        }
                    } else {
                        // Node has no "data" — check top-level and config.skip_condition.
                        if let Some(skip_cond) = node
                            .get("skip_condition")
                            .and_then(|v| v.as_str())
                            .or_else(|| {
                                node.get("config")
                                    .and_then(|c| c.get("skip_condition"))
                                    .and_then(|v| v.as_str())
                            })
                        {
                            let entry = self
                                .node_configs
                                .entry(node_id)
                                .or_insert_with(|| serde_json::json!({}));
                            entry.as_object_mut().map(|m| {
                                m.insert(
                                    "__skip_condition".to_string(),
                                    serde_json::json!(skip_cond),
                                )
                            });
                        }
                        if let Some(true) = node
                            .get("continue_on_error")
                            .and_then(|v| v.as_bool())
                            .or_else(|| {
                                node.get("config")
                                    .and_then(|c| c.get("continue_on_error"))
                                    .and_then(|v| v.as_bool())
                            })
                        {
                            let entry = self
                                .node_configs
                                .entry(node_id)
                                .or_insert_with(|| serde_json::json!({}));
                            entry.as_object_mut().map(|m| {
                                m.insert("__continue_on_error".to_string(), serde_json::json!(true))
                            });
                        }
                    }

                    let kind = node
                        .get("kind")
                        .and_then(|k| k.as_str())
                        .and_then(|k| parse_system_node_kind(k, node));
                    let retry_policy = read_node_retry_policy_with_actor_cap(node, self.actor_id);
                    self.add_node(node_id, Some(module_id), retry_policy, kind);
                    let node_timeout_secs: Option<u64> = node
                        .get("data")
                        .and_then(|d| d.get("timeout_secs"))
                        .or_else(|| node.get("timeout_secs"))
                        .and_then(|v| v.as_u64());
                    if let Some(t) = node_timeout_secs {
                        self.node_timeouts.insert(node_id, t);
                    }
                }
            } else if node
                .get("type")
                .and_then(|v| v.as_str())
                .map(|s| s.starts_with("system:"))
                .unwrap_or(false)
            {
                // System node: no module_id, but has a kind.
                let node_id = Uuid::parse_str(rf_id).unwrap_or_else(|_| {
                    use sha2::{Digest, Sha256};
                    let hash = Sha256::digest(rf_id.as_bytes());
                    let mut bytes = [0u8; 16];
                    bytes.copy_from_slice(&hash[..16]);
                    Uuid::from_bytes(bytes)
                });
                rf_to_node.insert(rf_id.to_string(), node_id);
                self.node_labels.insert(node_id, rf_id.to_string());

                if let Some(data) = node.get("data").cloned() {
                    if data.is_object() && !data.as_object().map(|m| m.is_empty()).unwrap_or(true) {
                        self.node_configs.insert(node_id, data.clone());
                    }
                    if let Some(skip_cond) = data
                        .get("skip_condition")
                        .and_then(|v| v.as_str())
                        .or_else(|| node.get("skip_condition").and_then(|v| v.as_str()))
                    {
                        let entry = self
                            .node_configs
                            .entry(node_id)
                            .or_insert_with(|| serde_json::json!({}));
                        entry.as_object_mut().map(|m| {
                            m.insert("__skip_condition".to_string(), serde_json::json!(skip_cond))
                        });
                    }
                    if data
                        .get("continue_on_error")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                        || node
                            .get("continue_on_error")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false)
                    {
                        let entry = self
                            .node_configs
                            .entry(node_id)
                            .or_insert_with(|| serde_json::json!({}));
                        entry.as_object_mut().map(|m| {
                            m.insert("__continue_on_error".to_string(), serde_json::json!(true))
                        });
                    }
                }

                // Derive kind from explicit "kind" field first, then fall back
                // to the "system:" type suffix — handles nodes emitted by
                // builders that omit the "kind" field redundantly.
                let kind_str: Option<&str> =
                    node.get("kind").and_then(|k| k.as_str()).or_else(|| {
                        node.get("type")
                            .and_then(|t| t.as_str())
                            .and_then(|t| t.strip_prefix("system:"))
                    });
                let kind = kind_str.and_then(|k| parse_system_node_kind(k, node));
                self.add_node(node_id, None, None, kind);
            }
        }

        let empty_edges = vec![];
        let edges = graph
            .get("edges")
            .and_then(|e| e.as_array())
            .unwrap_or(&empty_edges);

        for edge in edges {
            let src_rf = edge.get("source").and_then(|v| v.as_str()).unwrap_or("");
            let tgt_rf = edge.get("target").and_then(|v| v.as_str()).unwrap_or("");
            if let (Some(&src), Some(&tgt)) = (rf_to_node.get(src_rf), rf_to_node.get(tgt_rf)) {
                let _ = self.add_edge(
                    src,
                    tgt,
                    EdgeLogic {
                        source_handle: edge
                            .get("sourceHandle")
                            .and_then(|v| v.as_str())
                            .unwrap_or("output")
                            .to_string(),
                        target_handle: edge
                            .get("targetHandle")
                            .and_then(|v| v.as_str())
                            .unwrap_or("input")
                            .to_string(),
                        mapping: None,
                        condition: edge
                            .get("condition")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        edge_type: edge
                            .get("edge_type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("default")
                            .to_string(),
                    },
                );
            }
        }

        Ok(())
    }

    // Checkpoint load is handled by the consumer's `CheckpointStore`
    // impl (see `talos_workflow_engine_core::CheckpointStore`). Callers
    // invoke `store.load(id)` themselves and feed the result into
    // `run_with_seed`.

    /// Extract module UUIDs referenced in a `graph_json` string.
    ///
    /// Useful for consumers that maintain a workflow → module junction
    /// table in their own storage.
    pub fn extract_module_ids(graph_json: &str) -> Vec<Uuid> {
        let graph: serde_json::Value = match serde_json::from_str(graph_json) {
            Ok(v) => v,
            Err(_) => return vec![],
        };

        let empty_vec = vec![];
        let nodes = graph
            .get("nodes")
            .and_then(|n| n.as_array())
            .unwrap_or(&empty_vec);

        // Preallocate to nodes.len() — most nodes have a module_id,
        // so the eventual length is close to nodes.len(). Avoids the
        // repeated 2x reallocation cycle in graphs > 8 nodes.
        let mut module_ids = Vec::with_capacity(nodes.len());
        for node in nodes {
            let module_id_str = node
                .get("type")
                .and_then(|v| v.as_str())
                .filter(|s| Uuid::parse_str(s).is_ok())
                .or_else(|| {
                    node.get("data")
                        .and_then(|d| d.get("moduleId"))
                        .and_then(|v| v.as_str())
                });
            if let Some(id_str) = module_id_str {
                if let Ok(uuid) = Uuid::parse_str(id_str) {
                    module_ids.push(uuid);
                }
            }
        }
        module_ids.sort();
        module_ids.dedup();
        module_ids
    }

    /// Resolve the actual module UUID for a node.
    /// Nodes have their own unique IDs in the graph; the `module_id` (which WASM to load)
    /// is stored in `node_meta`. Falls back to `node_id` for backwards compatibility.
    pub(crate) fn resolve_module_id(&self, node_id: Uuid) -> Uuid {
        self.node_meta
            .get(&node_id)
            .and_then(|(mid, _, _)| *mid)
            .unwrap_or(node_id)
    }

    /// Add a node to the engine's graph.
    ///
    /// `id` is the engine-local node UUID; `module_id` is the
    /// resolved module to dispatch (or `None` for system-only
    /// nodes); `retry_policy` overrides the workflow-level default;
    /// `kind` carries the [`SystemNodeKind`] discriminator (or
    /// `None` for plain module nodes).
    ///
    /// Calls past [`max_workflow_nodes`](Self::max_workflow_nodes)
    /// emit a `tracing::warn!` and are silently dropped — by
    /// design, so a misbehaving graph generator can't exhaust
    /// memory before dispatch starts. Raise the cap via
    /// [`set_max_workflow_nodes`](Self::set_max_workflow_nodes) if
    /// the limit is too low for legitimate use.
    pub fn add_node(
        &mut self,
        id: Uuid,
        module_id: Option<Uuid>,
        retry_policy: Option<talos_workflow_engine_core::RetryPolicy>,
        kind: Option<SystemNodeKind>,
    ) {
        if self.graph.node_count() >= self.max_workflow_nodes {
            tracing::warn!(
                node_count = self.graph.node_count(),
                max = self.max_workflow_nodes,
                "Workflow graph exceeds maximum node count — ignoring add_node"
            );
            return;
        }
        let idx = self.graph.add_node(id);
        self.node_map.insert(id, idx);
        self.node_meta.insert(id, (module_id, retry_policy, kind));
    }

    /// Add a directed edge between two nodes already present in the
    /// graph. Returns `Err(WorkflowEngineError::LoadGraph)` if either
    /// endpoint is unknown — typically a typo in the graph builder.
    #[allow(dead_code)]
    pub fn add_edge(
        &mut self,
        from: Uuid,
        to: Uuid,
        logic: EdgeLogic,
    ) -> Result<(), crate::WorkflowEngineError> {
        let from_idx = *self.node_map.get(&from).ok_or_else(|| {
            crate::WorkflowEngineError::load_graph(format!("Edge source node {} not found", from))
        })?;
        let to_idx = *self.node_map.get(&to).ok_or_else(|| {
            crate::WorkflowEngineError::load_graph(format!("Edge target node {} not found", to))
        })?;
        self.graph.add_edge(from_idx, to_idx, logic);
        Ok(())
    }

    /// Install a synthetic `__trigger__` root node that carries the
    /// caller-supplied trigger input, wiring it to every current root
    /// so root-level nodes execute with the trigger as their input.
    ///
    /// Idempotent: if a `__trigger__` node is already present (for
    /// instance because this method ran once before), its Uuid is
    /// reused and only missing trigger → root edges are added. That
    /// means repeat invocations with the same or an expanded graph
    /// produce the same wiring without stacking parallel triggers.
    ///
    /// Returns the Uuid of the trigger node so the caller can seed
    /// `initial_results` with it before dispatching the engine.
    ///
    /// Shared by [`execute_subworkflow_graph`](Self::execute_subworkflow_graph)
    /// (operating on a fresh sub-engine) and
    /// [`run_with_trigger_input_transport`](Self::run_with_trigger_input_transport)
    /// (operating on the top-level engine). Kept private so the
    /// `__trigger__` mechanism stays an implementation detail of the
    /// crate — future refactors can replace it with a native seeding
    /// path without a public-API break.
    pub(crate) fn ensure_trigger_node_wired_to_roots(&mut self) -> Uuid {
        // Reuse an existing synthetic trigger if one is already
        // registered. The label is the authoritative marker — the
        // Uuid itself is engine-generated and opaque to callers.
        let existing = self
            .node_labels
            .iter()
            .find(|(_, label)| label.as_str() == talos_workflow_engine_core::reserved_keys::TRIGGER)
            .map(|(uuid, _)| *uuid);

        let trigger_node_id = match existing {
            Some(id) => id,
            None => {
                let id = Uuid::new_v4();
                self.add_node(id, None, None, None);
                self.node_labels.insert(
                    id,
                    talos_workflow_engine_core::reserved_keys::TRIGGER.to_string(),
                );
                id
            }
        };

        // Roots are every node with zero incoming edges, excluding the
        // trigger itself. Collect root Uuids (not NodeIndices) so the
        // subsequent `add_edge` calls — which do their own index
        // lookup — stay correct if the graph is mutated between
        // iterations.
        let root_ids: Vec<Uuid> = self
            .graph
            .node_indices()
            .filter_map(|idx| {
                let id = self.graph[idx];
                if id == trigger_node_id {
                    return None;
                }
                let in_degree = self
                    .graph
                    .neighbors_directed(idx, Direction::Incoming)
                    .count();
                if in_degree == 0 {
                    Some(id)
                } else {
                    None
                }
            })
            .collect();

        for root_id in root_ids {
            // `add_edge` is a no-op-ish idempotent operation only for
            // structurally distinct edges; petgraph does allow
            // duplicates. On a fresh trigger node every `add_edge`
            // adds a new edge exactly once. On a reused trigger node,
            // we only add an edge if one doesn't already exist —
            // otherwise repeat invocations would stack parallel edges
            // from trigger → the same root, and the scheduler would
            // see the root with in-degree > 1 (breaking the root
            // identification on the next call).
            let trigger_idx = self.node_map[&trigger_node_id];
            let root_idx = self.node_map[&root_id];
            let already_wired = self
                .graph
                .edges_connecting(trigger_idx, root_idx)
                .next()
                .is_some();
            if !already_wired {
                let _ = self.add_edge(
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
        }

        trigger_node_id
    }
}
