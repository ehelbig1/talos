//! Typed, programmatic construction of the React-Flow `graph_json`
//! shape accepted by
//! [`ParallelWorkflowEngine::load_from_graph_json`](crate::ParallelWorkflowEngine::load_from_graph_json).
//!
//! The parser is React-Flow-shaped, which is useful when workflows are
//! authored in a visual editor but awkward when a consumer wants to
//! build a graph from Rust code. [`WorkflowGraphBuilder`] is the
//! idiomatic bridge — call `add_module` / `add_system_node` / `edge`
//! methods, then `build()` returns the exact `serde_json::Value` the
//! parser expects. Feed it into `load_from_graph_json` (or pass to a
//! [`WorkflowGraphStore`](talos_workflow_engine_core::WorkflowGraphStore)
//! impl for persistence).
//!
//! # Error reporting
//!
//! Every configuration-time problem — an `add_system_node` variant the
//! JSON parser has no branch for, a `with_skip_condition` referencing
//! an id that doesn't exist — is **accumulated** rather than returned
//! at the call site. The fluent chain stays unbroken; [`build`] is the
//! single fallibility point. This design surfaces *all* misconfigurations
//! in one shot instead of stopping at the first one, and avoids the
//! common silent-no-op footgun where typos in node ids just drop the
//! intended configuration on the floor.
//!
//! [`build`]: WorkflowGraphBuilder::build
//!
//! # Example
//!
//! ```
//! use std::time::Duration;
//! use serde_json::json;
//! use uuid::Uuid;
//! use talos_workflow_engine::WorkflowGraphBuilder;
//! use talos_workflow_engine_core::SystemNodeKind;
//!
//! let module_id = Uuid::new_v4();
//! let graph = WorkflowGraphBuilder::new()
//!     .execution_timeout(Duration::from_secs(600))
//!     .add_module("fetch", module_id, Some(json!({ "url": "https://example.com" })))
//!     .add_system_node(
//!         "aggregate",
//!         SystemNodeKind::Collect,
//!     )
//!     .edge("fetch", "aggregate")
//!     .build()
//!     .expect("graph is well-formed");
//!
//! // `graph` is a JSON value with the same shape React Flow produces.
//! assert_eq!(graph["nodes"].as_array().unwrap().len(), 2);
//! assert_eq!(graph["edges"].as_array().unwrap().len(), 1);
//! ```
//!
//! # Preferred construction paths by scenario
//!
//! | Scenario | Preferred path |
//! |---|---|
//! | Workflow authored in React Flow (visual editor) | Hand-written JSON / editor output |
//! | In-process Rust consumers building graphs programmatically | [`WorkflowGraphBuilder`] |
//! | Dynamic / generated workflows with lots of variation | [`WorkflowGraphBuilder`] |
//! | Low-level edge cases (custom node types, third-party extensions) | [`WorkflowGraphBuilder::add_raw_node`] / `add_raw_edge` |
//!
//! All three produce `serde_json::Value`s with the same shape; the
//! engine's parser is the single source of truth for what's accepted.

use std::fmt;
use std::time::Duration;

use serde_json::{json, Map, Value as JsonValue};
use talos_workflow_engine_core::SystemNodeKind;
use uuid::Uuid;

/// One configuration-time problem accumulated while building a graph.
///
/// Surfaced as part of [`BuildError`] when [`WorkflowGraphBuilder::build`]
/// is called. Each variant names the method that produced it, so error
/// messages unambiguously point at the offending builder call.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WorkflowGraphBuilderError {
    /// A `.with_*` mutator was called with an `id` that did not match
    /// any node previously added to the builder. Typical cause: a typo
    /// in the id string, or calling the mutator before the node was
    /// added.
    UnknownNodeId {
        /// The id the caller passed.
        id: String,
        /// The mutator method that rejected it (for instance,
        /// `"with_skip_condition"`).
        method: &'static str,
    },
}

impl fmt::Display for WorkflowGraphBuilderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownNodeId { id, method } => write!(
                f,
                "{method}: no node with id {id:?} has been added to the builder"
            ),
        }
    }
}

impl std::error::Error for WorkflowGraphBuilderError {}

/// Aggregate of every [`WorkflowGraphBuilderError`] accumulated during
/// a builder session. Returned by [`WorkflowGraphBuilder::build`] when
/// at least one error was recorded.
///
/// Display formats every contained error, one per line, so forwarding
/// through `{err}` / `anyhow::Error` produces a readable multi-line
/// diagnostic. Callers that need the individual errors can match on
/// [`BuildError::errors`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildError {
    errors: Vec<WorkflowGraphBuilderError>,
}

impl BuildError {
    /// Borrow the individual errors. Always non-empty: a `BuildError`
    /// is only constructed when at least one problem was recorded.
    #[must_use]
    pub fn errors(&self) -> &[WorkflowGraphBuilderError] {
        &self.errors
    }

    /// Consume the aggregate and return the owned vector.
    #[must_use]
    pub fn into_errors(self) -> Vec<WorkflowGraphBuilderError> {
        self.errors
    }
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = self.errors.len();
        writeln!(f, "WorkflowGraphBuilder::build failed with {n} error(s):")?;
        for (i, e) in self.errors.iter().enumerate() {
            writeln!(f, "  [{}] {e}", i + 1)?;
        }
        Ok(())
    }
}

impl std::error::Error for BuildError {}

/// Build a React-Flow-shaped `graph_json` programmatically.
///
/// See the [module-level docs](crate::graph_builder) for an example
/// and the error-reporting model. The builder is `#[must_use]`-friendly:
/// every mutator returns `self`, so chained calls compile to `build()`
/// or nothing.
#[derive(Debug, Default, Clone)]
#[must_use]
pub struct WorkflowGraphBuilder {
    nodes: Vec<JsonValue>,
    edges: Vec<JsonValue>,
    execution_timeout_secs: Option<u64>,
    errors: Vec<WorkflowGraphBuilderError>,
}

impl WorkflowGraphBuilder {
    /// Build an empty graph. Call `add_module` / `add_system_node` /
    /// `edge` to populate, then `build()` to emit the JSON.
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the default workflow-level execution timeout.
    ///
    /// Sub-second values are truncated to whole seconds. Zero is
    /// accepted verbatim (the parser reads this back as "0s timeout,"
    /// which the engine treats as "use the default" at run time).
    pub fn execution_timeout(mut self, timeout: Duration) -> Self {
        self.execution_timeout_secs = Some(timeout.as_secs());
        self
    }

    /// Add a user-provided module node.
    ///
    /// * `id` — workflow-local node identifier. Accepts any
    ///   human-readable string; the engine derives a stable `Uuid`
    ///   from the string if it isn't already a UUID.
    /// * `module_id` — the module that executes at this node.
    /// * `config` — optional per-node configuration forwarded to the
    ///   worker. Shape is module-defined.
    pub fn add_module(
        mut self,
        id: impl Into<String>,
        module_id: Uuid,
        config: Option<JsonValue>,
    ) -> Self {
        let id = id.into();
        let mut node = Map::new();
        node.insert("id".to_string(), JsonValue::String(id));
        node.insert("type".to_string(), JsonValue::String(module_id.to_string()));
        if let Some(data) = config {
            node.insert("data".to_string(), data);
        }
        self.nodes.push(JsonValue::Object(node));
        self
    }

    /// Add a built-in system node for a [`SystemNodeKind`] variant.
    ///
    /// Serializes the variant into the React-Flow `kind` + `data` shape
    /// the engine's parser accepts. Every [`SystemNodeKind`] variant
    /// round-trips through this method; there is no "unsupported"
    /// subset. LLM-flavored variants are only present when compiled
    /// with the `llm-primitives` feature; passing one without the
    /// feature is a compile-time error.
    pub fn add_system_node(mut self, id: impl Into<String>, kind: SystemNodeKind) -> Self {
        let id = id.into();
        let (kind_str, data) = serialize_system_node_kind(&kind);
        let mut node = Map::new();
        node.insert("id".to_string(), JsonValue::String(id));
        // The engine's full parser (`load_graph_from_json`) dispatches
        // system-only nodes on the `type: "system:<kind>"` prefix AND
        // reads the kind from the `kind` field. Emit both so the node
        // round-trips through either dispatch path.
        node.insert(
            "type".to_string(),
            JsonValue::String(format!("system:{kind_str}")),
        );
        node.insert("kind".to_string(), JsonValue::String(kind_str.to_string()));
        node.insert("data".to_string(), data);
        self.nodes.push(JsonValue::Object(node));
        self
    }

    /// Add a completely custom node shape. Use when a feature isn't
    /// covered by the typed helpers (e.g. experimental kinds in a
    /// fork, or node-type strings consumed by a custom parser in a
    /// downstream fork of this engine).
    ///
    /// The engine's stock parser silently skips nodes it doesn't
    /// recognize — see
    /// [`ParallelWorkflowEngine::load_from_graph_json`](crate::ParallelWorkflowEngine::load_from_graph_json).
    pub fn add_raw_node(mut self, node: JsonValue) -> Self {
        self.nodes.push(node);
        self
    }

    /// Attach a skip-condition expression to the node with `id`.
    ///
    /// The engine reads this into the node's config under the reserved
    /// `__skip_condition` key; when the expression evaluates truthy at
    /// dispatch time, the node short-circuits without running.
    ///
    /// If no node with `id` has been added, a
    /// [`WorkflowGraphBuilderError::UnknownNodeId`] is recorded and
    /// surfaced at [`build`](Self::build).
    pub fn with_skip_condition(
        mut self,
        id: impl AsRef<str>,
        condition: impl Into<String>,
    ) -> Self {
        let id = id.as_ref();
        let condition: String = condition.into();
        if let Some(obj) = self.find_node_obj_mut(id) {
            obj.insert("skip_condition".to_string(), JsonValue::String(condition));
        } else {
            self.errors.push(WorkflowGraphBuilderError::UnknownNodeId {
                id: id.to_string(),
                method: "with_skip_condition",
            });
        }
        self
    }

    /// Mark the node with `id` as `continue_on_error`.
    ///
    /// When set, a dispatch failure on this node does not fail the
    /// workflow — downstream nodes still run with the failed node's
    /// error envelope as input.
    ///
    /// If no node with `id` has been added, a
    /// [`WorkflowGraphBuilderError::UnknownNodeId`] is recorded and
    /// surfaced at [`build`](Self::build).
    pub fn with_continue_on_error(mut self, id: impl AsRef<str>) -> Self {
        let id = id.as_ref();
        if let Some(obj) = self.find_node_obj_mut(id) {
            obj.insert("continue_on_error".to_string(), JsonValue::Bool(true));
        } else {
            self.errors.push(WorkflowGraphBuilderError::UnknownNodeId {
                id: id.to_string(),
                method: "with_continue_on_error",
            });
        }
        self
    }

    /// Attach a per-node retry policy.
    ///
    /// * `max_retries` — max transient-failure retries (timeouts do
    ///   not retry; see the retry-classifier trait).
    /// * `backoff_ms` — base backoff between retries, in ms.
    /// * `condition` — optional expression evaluated against the
    ///   error output to decide whether to retry.
    /// * `delay_expression` — optional expression returning the next
    ///   retry delay in ms, computed from the error output.
    ///
    /// If no node with `id` has been added, a
    /// [`WorkflowGraphBuilderError::UnknownNodeId`] is recorded and
    /// surfaced at [`build`](Self::build).
    pub fn with_retry(
        mut self,
        id: impl AsRef<str>,
        max_retries: u32,
        backoff_ms: u64,
        condition: Option<String>,
        delay_expression: Option<String>,
    ) -> Self {
        let id = id.as_ref();
        if let Some(obj) = self.find_node_obj_mut(id) {
            obj.insert("retry_count".to_string(), json!(max_retries));
            obj.insert("retry_backoff_ms".to_string(), json!(backoff_ms));
            if let Some(c) = condition {
                obj.insert("retry_condition".to_string(), JsonValue::String(c));
            }
            if let Some(d) = delay_expression {
                obj.insert("retry_delay_expression".to_string(), JsonValue::String(d));
            }
        } else {
            self.errors.push(WorkflowGraphBuilderError::UnknownNodeId {
                id: id.to_string(),
                method: "with_retry",
            });
        }
        self
    }

    /// Add an edge from `source` to `target` with the default
    /// `output → input` handle pair and no condition.
    pub fn edge(self, source: impl Into<String>, target: impl Into<String>) -> Self {
        self.edge_with_handles(source, target, "output", "input")
    }

    /// Add an edge that fires only when `condition` evaluates truthy
    /// against the source node's output.
    pub fn edge_condition(
        self,
        source: impl Into<String>,
        target: impl Into<String>,
        condition: impl Into<String>,
    ) -> Self {
        let mut builder = self.edge(source, target);
        let last = builder.edges.last_mut().and_then(|e| e.as_object_mut());
        if let Some(obj) = last {
            obj.insert("condition".to_string(), JsonValue::String(condition.into()));
        }
        builder
    }

    /// Add an edge with explicit `source`/`target` handles. Use when
    /// a node has multiple outputs (e.g. `on_failure` / `on_success`
    /// or LLM-dispatch route names).
    pub fn edge_with_handles(
        mut self,
        source: impl Into<String>,
        target: impl Into<String>,
        source_handle: impl Into<String>,
        target_handle: impl Into<String>,
    ) -> Self {
        let edge = json!({
            "source": source.into(),
            "target": target.into(),
            "sourceHandle": source_handle.into(),
            "targetHandle": target_handle.into(),
        });
        self.edges.push(edge);
        self
    }

    /// Add a completely custom edge shape. Use when a feature isn't
    /// covered by the typed helpers (e.g. non-default `edge_type`,
    /// mapping expressions, experimental keys).
    pub fn add_raw_edge(mut self, edge: JsonValue) -> Self {
        self.edges.push(edge);
        self
    }

    /// Emit the assembled graph as a JSON value ready to feed into
    /// [`ParallelWorkflowEngine::load_from_graph_json`](crate::ParallelWorkflowEngine::load_from_graph_json)
    /// or a consumer's
    /// [`WorkflowGraphStore`](talos_workflow_engine_core::WorkflowGraphStore).
    ///
    /// # Errors
    ///
    /// Returns [`BuildError`] containing every
    /// [`WorkflowGraphBuilderError`] accumulated during the builder
    /// chain (unknown node ids, unsupported system node kinds, etc.).
    /// If you need the partial JSON regardless of errors — for example
    /// to feed a linter or diff tool — use [`build_partial`](Self::build_partial).
    pub fn build(self) -> Result<JsonValue, BuildError> {
        if !self.errors.is_empty() {
            return Err(BuildError {
                errors: self.errors,
            });
        }
        Ok(Self::assemble_root(
            self.nodes,
            self.edges,
            self.execution_timeout_secs,
        ))
    }

    /// Emit the assembled graph and the accumulated errors side-by-side.
    ///
    /// Useful for tooling that wants to show *all* problems while still
    /// rendering a best-effort graph, or for tests that assert on the
    /// exact shape of both sides.
    #[must_use]
    pub fn build_partial(self) -> (JsonValue, Vec<WorkflowGraphBuilderError>) {
        let value = Self::assemble_root(self.nodes, self.edges, self.execution_timeout_secs);
        (value, self.errors)
    }

    /// Borrow any errors accumulated so far without consuming the
    /// builder. Useful in tests to assert on mid-chain state.
    #[must_use]
    pub fn errors(&self) -> &[WorkflowGraphBuilderError] {
        &self.errors
    }

    fn find_node_obj_mut(&mut self, id: &str) -> Option<&mut Map<String, JsonValue>> {
        self.nodes
            .iter_mut()
            .find(|n| n.get("id").and_then(|v| v.as_str()) == Some(id))
            .and_then(|n| n.as_object_mut())
    }

    fn assemble_root(
        nodes: Vec<JsonValue>,
        edges: Vec<JsonValue>,
        execution_timeout_secs: Option<u64>,
    ) -> JsonValue {
        let mut root = Map::new();
        root.insert("nodes".to_string(), JsonValue::Array(nodes));
        root.insert("edges".to_string(), JsonValue::Array(edges));
        if let Some(secs) = execution_timeout_secs {
            root.insert("execution_timeout_secs".to_string(), json!(secs));
        }
        JsonValue::Object(root)
    }
}

/// Map a [`SystemNodeKind`] back into the `(kind_string, data_json)`
/// pair the React-Flow parser reads.
///
/// Kept in one place so parser drift is easy to audit: every variant
/// here corresponds 1:1 to an `else if k == "..."` branch in
/// `engine.rs::load_from_graph_json` / `parse_llm_system_node_kind`.
/// The match is exhaustive; every [`SystemNodeKind`] variant has a
/// serialization. Adding a new variant to the enum requires adding a
/// branch here and in the parser.
#[allow(clippy::too_many_lines)]
fn serialize_system_node_kind(kind: &SystemNodeKind) -> (&'static str, JsonValue) {
    match kind {
        SystemNodeKind::Wait { message } => (
            "wait",
            match message {
                Some(m) => json!({ "message": m }),
                None => json!({}),
            },
        ),
        SystemNodeKind::WhileLoop {
            condition,
            max_iterations,
        } => (
            "while_loop",
            json!({
                "condition": condition,
                "max_iterations": max_iterations,
            }),
        ),
        SystemNodeKind::RepeatLoop { count } => (
            "repeat_loop",
            json!({
                "count": count,
            }),
        ),
        SystemNodeKind::ErrorHandler { error_pattern } => (
            "error_handler",
            match error_pattern {
                Some(p) => json!({ "error_pattern": p }),
                None => json!({}),
            },
        ),
        SystemNodeKind::FanIn {
            join_mode,
            aggregation_expr,
        } => (
            "fan_in",
            // `JoinMode` derives Serialize/Deserialize; round-trip uses
            // the default externally-tagged form (`"All"` / `"Any"` /
            // `"Majority"` / `{"N": n}`). Keeping the derive output
            // stable avoids parser/serializer drift.
            match aggregation_expr {
                Some(expr) => json!({
                    "join_mode": join_mode,
                    "aggregation_expr": expr,
                }),
                None => json!({ "join_mode": join_mode }),
            },
        ),
        SystemNodeKind::SubWorkflow {
            workflow_id,
            timeout_secs,
        } => (
            "sub_workflow",
            json!({
                "sub_workflow_id": workflow_id.to_string(),
                "timeout_secs": timeout_secs,
            }),
        ),
        SystemNodeKind::Loop {
            max_iterations,
            condition,
        } => (
            "loop",
            json!({
                "max_iterations": max_iterations,
                "condition": condition,
            }),
        ),
        SystemNodeKind::Collect => ("collect", json!({})),
        SystemNodeKind::OpsAlertsDigest { top_limit } => {
            ("ops_alerts_digest", json!({ "top_limit": top_limit }))
        }
        SystemNodeKind::PendingApprovals { limit } => {
            ("pending_approvals", json!({ "limit": limit }))
        }
        SystemNodeKind::AssistantReport { days } => ("assistant_report", json!({ "days": days })),
        SystemNodeKind::Synthesize { synthesis_expr } => (
            "synthesize",
            match synthesis_expr {
                Some(e) => json!({ "synthesis_expr": e }),
                None => json!({}),
            },
        ),
        SystemNodeKind::Verify {
            condition,
            check_label,
            on_failure,
        } => (
            "verify",
            json!({
                "condition": condition,
                "check_label": check_label,
                "on_failure": on_failure,
            }),
        ),
        SystemNodeKind::DynamicDispatch {
            dispatch_expression,
            timeout_secs,
        } => (
            "dispatch",
            json!({
                "dispatch_expression": dispatch_expression,
                "timeout_secs": timeout_secs,
            }),
        ),
        SystemNodeKind::CapabilityDispatch {
            required_capabilities,
            fallback_workflow_id,
            timeout_secs,
        } => (
            "capability_dispatch",
            json!({
                "required_capabilities": required_capabilities,
                "fallback_workflow_id": fallback_workflow_id.map(|u| u.to_string()),
                "timeout_secs": timeout_secs,
            }),
        ),
        #[cfg(feature = "llm-primitives")]
        SystemNodeKind::AgentLoop {
            body_workflow_id,
            max_iterations,
            inject_history,
            timeout_secs,
        } => (
            "agent_loop",
            json!({
                "body_workflow_id": body_workflow_id.to_string(),
                "max_iterations": max_iterations,
                "inject_history": inject_history,
                "timeout_secs": timeout_secs,
            }),
        ),
        #[cfg(feature = "llm-primitives")]
        SystemNodeKind::Judge {
            judge_workflow_id,
            rubric,
            pass_threshold,
            on_failure,
            timeout_secs,
        } => (
            "judge",
            json!({
                "judge_workflow_id": judge_workflow_id.to_string(),
                "rubric": rubric,
                "pass_threshold": pass_threshold,
                "on_failure": on_failure,
                "timeout_secs": timeout_secs,
            }),
        ),
        #[cfg(feature = "llm-primitives")]
        SystemNodeKind::InlineJudge {
            verdict_expr,
            pass_threshold,
            on_failure,
        } => (
            "inline_judge",
            json!({
                "verdict_expr": verdict_expr,
                "pass_threshold": pass_threshold,
                "on_failure": on_failure,
            }),
        ),
        #[cfg(feature = "llm-primitives")]
        SystemNodeKind::Ensemble {
            child_workflow_id,
            count,
            consensus,
            judge_workflow_id,
            timeout_secs,
        } => (
            "ensemble",
            json!({
                "child_workflow_id": child_workflow_id.to_string(),
                "count": count,
                "consensus": consensus,
                "judge_workflow_id": judge_workflow_id.map(|id| id.to_string()),
                "timeout_secs": timeout_secs,
            }),
        ),
        #[cfg(feature = "llm-primitives")]
        SystemNodeKind::ConfidenceGate {
            threshold,
            confidence_path,
            on_low_confidence,
        } => (
            "confidence_gate",
            json!({
                "threshold": threshold,
                "confidence_path": confidence_path,
                "on_low_confidence": on_low_confidence,
            }),
        ),
        #[cfg(feature = "llm-primitives")]
        SystemNodeKind::ReActLoop {
            body_workflow_id,
            max_iterations,
            inject_history,
            timeout_secs,
        } => (
            "react_loop",
            json!({
                "body_workflow_id": body_workflow_id.to_string(),
                "max_iterations": max_iterations,
                "inject_history": inject_history,
                "timeout_secs": timeout_secs,
            }),
        ),
        #[cfg(feature = "llm-primitives")]
        SystemNodeKind::ReflectiveRetry {
            child_workflow_id,
            reflection_workflow_id,
            max_retries,
            timeout_secs,
        } => (
            "reflective_retry",
            json!({
                "child_workflow_id": child_workflow_id.to_string(),
                "reflection_workflow_id": reflection_workflow_id.to_string(),
                "max_retries": max_retries,
                "timeout_secs": timeout_secs,
            }),
        ),
        #[cfg(feature = "llm-primitives")]
        SystemNodeKind::LlmDispatch {
            classifier_workflow_id,
            routes,
            fallback_workflow_id,
            timeout_secs,
        } => (
            "llm_dispatch",
            json!({
                "classifier_workflow_id": classifier_workflow_id.to_string(),
                "routes": routes.iter().map(|(k, v)| (k.clone(), v.to_string())).collect::<std::collections::HashMap<_, _>>(),
                "fallback_workflow_id": fallback_workflow_id.map(|id| id.to_string()),
                "timeout_secs": timeout_secs,
            }),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_builder_produces_empty_nodes_and_edges() {
        let g = WorkflowGraphBuilder::new().build().unwrap();
        assert_eq!(g["nodes"].as_array().unwrap().len(), 0);
        assert_eq!(g["edges"].as_array().unwrap().len(), 0);
        assert!(g.get("execution_timeout_secs").is_none());
    }

    #[test]
    fn execution_timeout_is_rendered() {
        let g = WorkflowGraphBuilder::new()
            .execution_timeout(Duration::from_secs(123))
            .build()
            .unwrap();
        assert_eq!(g["execution_timeout_secs"].as_u64(), Some(123));
    }

    #[test]
    fn add_module_emits_react_flow_shape() {
        let module_id = Uuid::new_v4();
        let g = WorkflowGraphBuilder::new()
            .add_module("fetch", module_id, Some(json!({ "url": "x" })))
            .build()
            .unwrap();
        let node = &g["nodes"][0];
        assert_eq!(node["id"].as_str(), Some("fetch"));
        assert_eq!(node["type"].as_str(), Some(module_id.to_string().as_str()));
        assert_eq!(node["data"]["url"].as_str(), Some("x"));
    }

    #[test]
    fn add_system_node_fan_in_round_trips() {
        let g = WorkflowGraphBuilder::new()
            .add_system_node(
                "join",
                SystemNodeKind::FanIn {
                    join_mode: talos_workflow_engine_core::JoinMode::Majority,
                    aggregation_expr: Some("sum".to_string()),
                },
            )
            .build()
            .unwrap();
        let node = &g["nodes"][0];
        assert_eq!(node["kind"].as_str(), Some("fan_in"));
        assert_eq!(node["type"].as_str(), Some("system:fan_in"));
        assert_eq!(node["data"]["join_mode"].as_str(), Some("Majority"));
        assert_eq!(node["data"]["aggregation_expr"].as_str(), Some("sum"));
    }

    #[test]
    fn add_system_node_fan_in_with_n_variant_round_trips() {
        let g = WorkflowGraphBuilder::new()
            .add_system_node(
                "join",
                SystemNodeKind::FanIn {
                    join_mode: talos_workflow_engine_core::JoinMode::N(3),
                    aggregation_expr: None,
                },
            )
            .build()
            .unwrap();
        let node = &g["nodes"][0];
        assert_eq!(node["data"]["join_mode"]["N"].as_u64(), Some(3));
        assert!(node["data"].get("aggregation_expr").is_none());
    }

    #[test]
    fn add_system_node_error_handler_round_trips() {
        let g = WorkflowGraphBuilder::new()
            .add_system_node(
                "eh",
                SystemNodeKind::ErrorHandler {
                    error_pattern: Some("timeout".to_string()),
                },
            )
            .build()
            .unwrap();
        let node = &g["nodes"][0];
        assert_eq!(node["kind"].as_str(), Some("error_handler"));
        assert_eq!(node["data"]["error_pattern"].as_str(), Some("timeout"));
    }

    #[test]
    fn add_system_node_while_loop_round_trips() {
        let g = WorkflowGraphBuilder::new()
            .add_system_node(
                "w",
                SystemNodeKind::WhileLoop {
                    condition: "x < 10".into(),
                    max_iterations: 5,
                },
            )
            .build()
            .unwrap();
        let node = &g["nodes"][0];
        assert_eq!(node["kind"].as_str(), Some("while_loop"));
        assert_eq!(node["data"]["condition"].as_str(), Some("x < 10"));
        assert_eq!(node["data"]["max_iterations"].as_u64(), Some(5));
    }

    #[test]
    fn add_system_node_repeat_loop_round_trips() {
        let g = WorkflowGraphBuilder::new()
            .add_system_node("r", SystemNodeKind::RepeatLoop { count: 3 })
            .build()
            .unwrap();
        let node = &g["nodes"][0];
        assert_eq!(node["kind"].as_str(), Some("repeat_loop"));
        assert_eq!(node["data"]["count"].as_u64(), Some(3));
    }

    #[test]
    fn edge_default_handles() {
        let g = WorkflowGraphBuilder::new().edge("a", "b").build().unwrap();
        let edge = &g["edges"][0];
        assert_eq!(edge["source"].as_str(), Some("a"));
        assert_eq!(edge["target"].as_str(), Some("b"));
        assert_eq!(edge["sourceHandle"].as_str(), Some("output"));
        assert_eq!(edge["targetHandle"].as_str(), Some("input"));
    }

    #[test]
    fn edge_condition_attaches_to_last_edge() {
        let g = WorkflowGraphBuilder::new()
            .edge("a", "b")
            .edge_condition("b", "c", "ok == true")
            .build()
            .unwrap();
        let second = &g["edges"][1];
        assert_eq!(second["source"].as_str(), Some("b"));
        assert_eq!(second["condition"].as_str(), Some("ok == true"));
        // First edge untouched.
        assert!(g["edges"][0].get("condition").is_none());
    }

    #[test]
    fn with_skip_condition_and_continue_on_error_modify_matching_node() {
        let module_id = Uuid::new_v4();
        let g = WorkflowGraphBuilder::new()
            .add_module("fetch", module_id, None)
            .with_skip_condition("fetch", "upstream.skip")
            .with_continue_on_error("fetch")
            .build()
            .unwrap();
        let node = &g["nodes"][0];
        assert_eq!(node["skip_condition"].as_str(), Some("upstream.skip"));
        assert_eq!(node["continue_on_error"].as_bool(), Some(true));
    }

    #[test]
    fn with_retry_policy_is_read_at_top_level() {
        let module_id = Uuid::new_v4();
        let g = WorkflowGraphBuilder::new()
            .add_module("fetch", module_id, None)
            .with_retry(
                "fetch",
                3,
                500,
                Some("error_code == 429".into()),
                Some("min(5000, base * 2)".into()),
            )
            .build()
            .unwrap();
        let node = &g["nodes"][0];
        assert_eq!(node["retry_count"].as_u64(), Some(3));
        assert_eq!(node["retry_backoff_ms"].as_u64(), Some(500));
        assert_eq!(node["retry_condition"].as_str(), Some("error_code == 429"));
        assert_eq!(
            node["retry_delay_expression"].as_str(),
            Some("min(5000, base * 2)")
        );
    }

    #[test]
    fn with_missing_id_records_unknown_node_error() {
        let err = WorkflowGraphBuilder::new()
            .with_skip_condition("nonexistent", "something")
            .build()
            .expect_err("typo in id must fail build");
        assert_eq!(err.errors().len(), 1);
        // The enum is `#[non_exhaustive]` and carries only `UnknownNodeId`
        // today; the bare `match` still compiles if new variants land, at
        // which point this test should expand.
        match &err.errors()[0] {
            WorkflowGraphBuilderError::UnknownNodeId { id, method } => {
                assert_eq!(id, "nonexistent");
                assert_eq!(*method, "with_skip_condition");
            }
        }
    }

    #[test]
    fn multiple_errors_all_surface_at_build() {
        let err = WorkflowGraphBuilder::new()
            .with_skip_condition("typo_a", "x")
            .with_continue_on_error("typo_b")
            .with_retry("typo_c", 1, 100, None, None)
            .build()
            .expect_err("multiple errors must fail build");
        assert_eq!(err.errors().len(), 3);
        // Display of the aggregate surfaces every one.
        let rendered = format!("{err}");
        assert!(rendered.contains("typo_a"));
        assert!(rendered.contains("typo_b"));
        assert!(rendered.contains("typo_c"));
    }

    #[test]
    fn build_partial_returns_graph_and_errors_side_by_side() {
        let module_id = Uuid::new_v4();
        let (graph, errors) = WorkflowGraphBuilder::new()
            .add_module("fetch", module_id, None)
            .with_skip_condition("typo", "x")
            .build_partial();
        assert_eq!(graph["nodes"].as_array().unwrap().len(), 1);
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn errors_accessor_exposes_mid_chain_state() {
        let builder = WorkflowGraphBuilder::new().with_skip_condition("typo", "x");
        assert_eq!(builder.errors().len(), 1);
    }

    #[test]
    fn raw_node_and_edge_passthrough() {
        let g = WorkflowGraphBuilder::new()
            .add_raw_node(json!({ "id": "custom", "type": "experimental" }))
            .add_raw_edge(json!({ "source": "a", "target": "b", "edge_type": "on_failure" }))
            .build()
            .unwrap();
        assert_eq!(g["nodes"][0]["type"].as_str(), Some("experimental"));
        assert_eq!(g["edges"][0]["edge_type"].as_str(), Some("on_failure"));
    }

    #[test]
    fn system_node_collect_has_empty_data() {
        let g = WorkflowGraphBuilder::new()
            .add_system_node("c", SystemNodeKind::Collect)
            .build()
            .unwrap();
        assert_eq!(g["nodes"][0]["kind"].as_str(), Some("collect"));
        assert!(g["nodes"][0]["data"].as_object().unwrap().is_empty());
    }

    #[test]
    fn system_node_capability_dispatch_emits_capabilities_array() {
        let g = WorkflowGraphBuilder::new()
            .add_system_node(
                "cap",
                SystemNodeKind::CapabilityDispatch {
                    required_capabilities: vec!["llm".into(), "rag".into()],
                    fallback_workflow_id: None,
                    timeout_secs: 30,
                },
            )
            .build()
            .unwrap();
        let caps = &g["nodes"][0]["data"]["required_capabilities"];
        assert_eq!(caps[0].as_str(), Some("llm"));
        assert_eq!(caps[1].as_str(), Some("rag"));
    }

    #[tokio::test]
    async fn previously_unsupported_kinds_round_trip_through_parser() {
        // End-to-end: builder emits → engine parses → engine dispatches
        // the right handler. Catches drift between `serialize_system_node_kind`
        // and the kind-decoding branches in `load_graph_from_json`.
        use crate::ParallelWorkflowEngine;

        let graph = WorkflowGraphBuilder::new()
            .add_system_node(
                "fan",
                SystemNodeKind::FanIn {
                    join_mode: talos_workflow_engine_core::JoinMode::N(2),
                    aggregation_expr: Some("count".into()),
                },
            )
            .add_system_node(
                "eh",
                SystemNodeKind::ErrorHandler {
                    error_pattern: Some("rate_limited".into()),
                },
            )
            .add_system_node(
                "w",
                SystemNodeKind::WhileLoop {
                    condition: "cursor != null".into(),
                    max_iterations: 7,
                },
            )
            .add_system_node("r", SystemNodeKind::RepeatLoop { count: 4 })
            .build()
            .unwrap();

        let json_str = serde_json::to_string(&graph).unwrap();

        let mut engine = ParallelWorkflowEngine::new();
        engine
            .load_graph_from_json(&json_str)
            .await
            .expect("parser accepts builder output for all four kinds");
        assert_eq!(engine.graph().node_count(), 4);

        // node_meta should carry the decoded kind. Each label maps to
        // a UUID via `node_labels`; we check the expected variant.
        let find = |label: &str| {
            engine
                .node_labels()
                .iter()
                .find(|(_, l)| l.as_str() == label)
                .map(|(u, _)| *u)
                .and_then(|u| engine.node_meta().get(&u))
                .and_then(|(_, _, k)| k.clone())
                .unwrap_or_else(|| panic!("no kind decoded for {label}"))
        };

        assert!(matches!(
            find("fan"),
            SystemNodeKind::FanIn {
                join_mode: talos_workflow_engine_core::JoinMode::N(2),
                aggregation_expr: Some(ref e),
            } if e == "count"
        ));
        assert!(matches!(
            find("eh"),
            SystemNodeKind::ErrorHandler { error_pattern: Some(ref p) } if p == "rate_limited"
        ));
        assert!(matches!(
            find("w"),
            SystemNodeKind::WhileLoop {
                condition: ref c,
                max_iterations: 7,
            } if c == "cursor != null"
        ));
        assert!(matches!(find("r"), SystemNodeKind::RepeatLoop { count: 4 }));
    }

    #[tokio::test]
    async fn round_trip_through_load_graph_from_json() {
        // End-to-end: build a graph, serialize, parse, verify topology.
        use crate::ParallelWorkflowEngine;

        let module_id = Uuid::new_v4();
        let graph = WorkflowGraphBuilder::new()
            .execution_timeout(Duration::from_secs(42))
            .add_module("fetch", module_id, Some(json!({ "url": "x" })))
            .add_system_node("aggregate", SystemNodeKind::Collect)
            .edge("fetch", "aggregate")
            .build()
            .unwrap();

        let json_str = serde_json::to_string(&graph).unwrap();

        let mut engine = ParallelWorkflowEngine::new();
        engine
            .load_graph_from_json(&json_str)
            .await
            .expect("parser accepts builder output");

        // Both parsers read nodes + edges identically — assert on those.
        assert_eq!(engine.graph().node_count(), 2);
        assert_eq!(engine.graph().edge_count(), 1);
    }

    #[test]
    fn round_trip_through_load_from_graph_json_module_only() {
        // Complement to the async round-trip test: exercise the sync
        // `load_from_graph_json(&Value)` path.
        use crate::ParallelWorkflowEngine;

        let m1 = Uuid::new_v4();
        let m2 = Uuid::new_v4();
        let graph = WorkflowGraphBuilder::new()
            .execution_timeout(Duration::from_secs(42))
            .add_module("a", m1, None)
            .add_module("b", m2, None)
            .edge("a", "b")
            .build()
            .unwrap();

        let mut engine = ParallelWorkflowEngine::new();
        engine
            .load_from_graph_json(&graph)
            .expect("parser accepts builder output");

        assert_eq!(engine.graph().node_count(), 2);
        assert_eq!(engine.graph().edge_count(), 1);
        assert_eq!(engine.execution_timeout_secs(), 42);
    }

    #[test]
    fn sync_parser_now_accepts_system_nodes() {
        // Regression test for the parser unification. Before the two
        // parsers were merged, `load_from_graph_json(&Value)` skipped
        // any node without a module_id — so a pure-system-node graph
        // would load as empty. After unification, the sync parser
        // handles system nodes identically to the async parser.
        use crate::ParallelWorkflowEngine;

        let graph = WorkflowGraphBuilder::new()
            .add_system_node("collect_a", SystemNodeKind::Collect)
            .add_system_node("collect_b", SystemNodeKind::Collect)
            .edge("collect_a", "collect_b")
            .build()
            .unwrap();

        let mut engine = ParallelWorkflowEngine::new();
        engine
            .load_from_graph_json(&graph)
            .expect("sync parser accepts system-only graphs");

        // Previously 0 — the sync parser dropped system nodes silently.
        assert_eq!(engine.graph().node_count(), 2);
        assert_eq!(engine.graph().edge_count(), 1);
    }

    #[test]
    fn sync_parser_rejects_empty_nodes() {
        // Regression test for the empty-nodes policy unification.
        // Pre-Phase 3 the sync parser accepted empty graphs; both
        // entry points now reject them consistently.
        use crate::ParallelWorkflowEngine;

        let graph = WorkflowGraphBuilder::new().build().unwrap();
        let mut engine = ParallelWorkflowEngine::new();
        let err = engine
            .load_from_graph_json(&graph)
            .expect_err("empty-nodes graph must be rejected");
        assert!(matches!(err, crate::WorkflowEngineError::EmptyGraph));
    }

    #[cfg(feature = "llm-primitives")]
    #[test]
    fn system_node_judge_emits_rubric_and_threshold() {
        let judge_wf = Uuid::new_v4();
        let g = WorkflowGraphBuilder::new()
            .add_system_node(
                "judge",
                SystemNodeKind::Judge {
                    judge_workflow_id: judge_wf,
                    rubric: "rate 0-1".into(),
                    pass_threshold: Some(0.8),
                    on_failure: "error".into(),
                    timeout_secs: 60,
                },
            )
            .build()
            .unwrap();
        let node = &g["nodes"][0];
        assert_eq!(node["kind"].as_str(), Some("judge"));
        assert_eq!(
            node["data"]["judge_workflow_id"].as_str(),
            Some(judge_wf.to_string().as_str())
        );
        assert_eq!(node["data"]["rubric"].as_str(), Some("rate 0-1"));
        assert_eq!(node["data"]["pass_threshold"].as_f64(), Some(0.8));
    }

    #[cfg(feature = "llm-primitives")]
    #[test]
    fn system_node_inline_judge_round_trips_through_builder() {
        let g = WorkflowGraphBuilder::new()
            .add_system_node(
                "verify_score",
                SystemNodeKind::InlineJudge {
                    verdict_expr: "{score: input.confidence, passed: input.confidence > 0.5, reasoning: '', feedback: ''}".into(),
                    pass_threshold: Some(0.5),
                    on_failure: "error".into(),
                },
            )
            .build()
            .unwrap();
        let node = &g["nodes"][0];
        assert_eq!(node["kind"].as_str(), Some("inline_judge"));
        assert_eq!(node["type"].as_str(), Some("system:inline_judge"));
        assert_eq!(
            node["data"]["verdict_expr"].as_str().unwrap_or(""),
            "{score: input.confidence, passed: input.confidence > 0.5, reasoning: '', feedback: ''}"
        );
        assert_eq!(node["data"]["pass_threshold"].as_f64(), Some(0.5));
    }

    // ───────────────────────────────────────────────────────────────
    // Exhaustive builder → parser round-trips.
    //
    // Each test below builds a node with a variant, serializes to
    // JSON, and asserts that the engine's parser decodes it back to
    // the same variant with the same field values. This is the form
    // that catches drift between `serialize_system_node_kind` and
    // `parse_system_node_kind` / `parse_llm_system_node_kind`.
    // ───────────────────────────────────────────────────────────────

    /// Round-trip `kind` through builder emit + engine parse, returning
    /// the decoded `SystemNodeKind` for further assertions.
    async fn round_trip_kind(label: &str, kind: SystemNodeKind) -> SystemNodeKind {
        use crate::ParallelWorkflowEngine;

        let graph = WorkflowGraphBuilder::new()
            .add_system_node(label, kind)
            .build()
            .unwrap();
        let json_str = serde_json::to_string(&graph).unwrap();

        let mut engine = ParallelWorkflowEngine::new();
        engine
            .load_graph_from_json(&json_str)
            .await
            .expect("parser accepts builder output");

        let uuid = engine
            .node_labels()
            .iter()
            .find(|(_, l)| l.as_str() == label)
            .map(|(u, _)| *u)
            .unwrap_or_else(|| panic!("no node labeled {label} in engine graph"));
        engine
            .node_meta()
            .get(&uuid)
            .and_then(|(_, _, k)| k.clone())
            .unwrap_or_else(|| panic!("no kind decoded for {label}"))
    }

    #[tokio::test]
    async fn system_node_wait_round_trips() {
        let with_msg = round_trip_kind(
            "wait_msg",
            SystemNodeKind::Wait {
                message: Some("approval".into()),
            },
        )
        .await;
        assert!(matches!(
            with_msg,
            SystemNodeKind::Wait { message: Some(ref m) } if m == "approval"
        ));

        let no_msg = round_trip_kind("wait_nomsg", SystemNodeKind::Wait { message: None }).await;
        assert!(matches!(no_msg, SystemNodeKind::Wait { message: None }));
    }

    #[tokio::test]
    async fn system_node_sub_workflow_round_trips() {
        let wf_id = Uuid::new_v4();
        let decoded = round_trip_kind(
            "sub",
            SystemNodeKind::SubWorkflow {
                workflow_id: wf_id,
                timeout_secs: 120,
            },
        )
        .await;
        assert!(matches!(
            decoded,
            SystemNodeKind::SubWorkflow { workflow_id, timeout_secs: 120 } if workflow_id == wf_id
        ));
    }

    #[tokio::test]
    async fn system_node_loop_round_trips() {
        let decoded = round_trip_kind(
            "loop_node",
            SystemNodeKind::Loop {
                max_iterations: 7,
                condition: "i < n".into(),
            },
        )
        .await;
        assert!(matches!(
            decoded,
            SystemNodeKind::Loop { max_iterations: 7, condition: ref c } if c == "i < n"
        ));
    }

    #[tokio::test]
    async fn system_node_collect_round_trips() {
        let decoded = round_trip_kind("collect_node", SystemNodeKind::Collect).await;
        assert!(matches!(decoded, SystemNodeKind::Collect));
    }

    #[tokio::test]
    async fn system_node_ops_alerts_digest_round_trips() {
        let decoded = round_trip_kind(
            "ops_digest",
            SystemNodeKind::OpsAlertsDigest { top_limit: 7 },
        )
        .await;
        assert!(matches!(
            decoded,
            SystemNodeKind::OpsAlertsDigest { top_limit: 7 }
        ));

        // The parser clamps hand-authored out-of-range values (the
        // builder can't produce them, so round-trip through the raw
        // parser directly).
        let oversized = serde_json::json!({
            "id": "ops_digest_big",
            "type": "system:ops_alerts_digest",
            "kind": "ops_alerts_digest",
            "data": { "top_limit": 9999 },
        });
        let parsed = crate::graph_parser::parse_system_node_kind("ops_alerts_digest", &oversized);
        assert!(matches!(
            parsed,
            Some(SystemNodeKind::OpsAlertsDigest { top_limit: 25 })
        ));
    }

    #[tokio::test]
    async fn system_node_pending_approvals_round_trips() {
        let decoded = round_trip_kind(
            "pending_appr",
            SystemNodeKind::PendingApprovals { limit: 7 },
        )
        .await;
        assert!(matches!(
            decoded,
            SystemNodeKind::PendingApprovals { limit: 7 }
        ));

        // The parser clamps hand-authored out-of-range values (the
        // builder can't produce them, so round-trip through the raw
        // parser directly).
        let oversized = serde_json::json!({
            "id": "pending_appr_big",
            "type": "system:pending_approvals",
            "kind": "pending_approvals",
            "data": { "limit": 9999 },
        });
        let parsed = crate::graph_parser::parse_system_node_kind("pending_approvals", &oversized);
        assert!(matches!(
            parsed,
            Some(SystemNodeKind::PendingApprovals { limit: 25 })
        ));
    }

    #[tokio::test]
    async fn system_node_assistant_report_round_trips() {
        let decoded =
            round_trip_kind("weekly_report", SystemNodeKind::AssistantReport { days: 7 }).await;
        assert!(matches!(
            decoded,
            SystemNodeKind::AssistantReport { days: 7 }
        ));
        let oversized = serde_json::json!({
            "id": "wr_big",
            "type": "system:assistant_report",
            "kind": "assistant_report",
            "data": { "days": 999 },
        });
        let parsed = crate::graph_parser::parse_system_node_kind("assistant_report", &oversized);
        assert!(matches!(
            parsed,
            Some(SystemNodeKind::AssistantReport { days: 31 })
        ));
    }

    #[tokio::test]
    async fn system_node_synthesize_round_trips() {
        let with_expr = round_trip_kind(
            "synth_expr",
            SystemNodeKind::Synthesize {
                synthesis_expr: Some("items | avg".into()),
            },
        )
        .await;
        assert!(matches!(
            with_expr,
            SystemNodeKind::Synthesize { synthesis_expr: Some(ref e) } if e == "items | avg"
        ));

        let no_expr = round_trip_kind(
            "synth_none",
            SystemNodeKind::Synthesize {
                synthesis_expr: None,
            },
        )
        .await;
        assert!(matches!(
            no_expr,
            SystemNodeKind::Synthesize {
                synthesis_expr: None
            }
        ));
    }

    #[tokio::test]
    async fn system_node_verify_round_trips() {
        let decoded = round_trip_kind(
            "verify_node",
            SystemNodeKind::Verify {
                condition: "resp.status == 200".into(),
                check_label: Some("http_ok".into()),
                on_failure: "error".into(),
            },
        )
        .await;
        assert!(matches!(
            decoded,
            SystemNodeKind::Verify {
                condition: ref c,
                check_label: Some(ref l),
                on_failure: ref f,
            } if c == "resp.status == 200" && l == "http_ok" && f == "error"
        ));
    }

    #[tokio::test]
    async fn system_node_dynamic_dispatch_round_trips() {
        let decoded = round_trip_kind(
            "dispatch_node",
            SystemNodeKind::DynamicDispatch {
                dispatch_expression: "classifier.route".into(),
                timeout_secs: 45,
            },
        )
        .await;
        assert!(matches!(
            decoded,
            SystemNodeKind::DynamicDispatch {
                dispatch_expression: ref e,
                timeout_secs: 45,
            } if e == "classifier.route"
        ));
    }

    #[tokio::test]
    async fn system_node_capability_dispatch_round_trips() {
        let decoded = round_trip_kind(
            "cap_node",
            SystemNodeKind::CapabilityDispatch {
                required_capabilities: vec!["llm".into(), "rag".into()],
                fallback_workflow_id: Some(uuid::Uuid::from_u128(0x1234)),
                timeout_secs: 30,
            },
        )
        .await;
        let SystemNodeKind::CapabilityDispatch {
            required_capabilities,
            fallback_workflow_id,
            timeout_secs,
        } = decoded
        else {
            panic!("expected CapabilityDispatch");
        };
        assert_eq!(required_capabilities, vec!["llm".to_string(), "rag".into()]);
        assert_eq!(fallback_workflow_id, Some(uuid::Uuid::from_u128(0x1234)));
        assert_eq!(timeout_secs, 30);
    }

    #[cfg(feature = "llm-primitives")]
    #[tokio::test]
    async fn system_node_agent_loop_round_trips() {
        let wf_id = Uuid::new_v4();
        let decoded = round_trip_kind(
            "agent",
            SystemNodeKind::AgentLoop {
                body_workflow_id: wf_id,
                max_iterations: 12,
                inject_history: false,
                timeout_secs: 90,
            },
        )
        .await;
        assert!(matches!(
            decoded,
            SystemNodeKind::AgentLoop {
                body_workflow_id: w,
                max_iterations: 12,
                inject_history: false,
                timeout_secs: 90,
            } if w == wf_id
        ));
    }

    #[cfg(feature = "llm-primitives")]
    #[tokio::test]
    async fn system_node_judge_round_trips_through_parser() {
        let wf_id = Uuid::new_v4();
        let decoded = round_trip_kind(
            "judge_node",
            SystemNodeKind::Judge {
                judge_workflow_id: wf_id,
                rubric: "rate 0-1".into(),
                pass_threshold: Some(0.8),
                on_failure: "passthrough".into(),
                timeout_secs: 60,
            },
        )
        .await;
        assert!(matches!(
            decoded,
            SystemNodeKind::Judge {
                judge_workflow_id: w,
                rubric: ref r,
                pass_threshold: Some(t),
                on_failure: ref onf,
                timeout_secs: 60,
            } if w == wf_id && r == "rate 0-1" && (t - 0.8).abs() < f64::EPSILON && onf == "passthrough"
        ));
    }

    #[cfg(feature = "llm-primitives")]
    #[tokio::test]
    async fn system_node_inline_judge_round_trips_through_parser() {
        let decoded = round_trip_kind(
            "ij",
            SystemNodeKind::InlineJudge {
                verdict_expr: "{score: 1.0, passed: true, reasoning: '', feedback: ''}".into(),
                pass_threshold: Some(0.5),
                on_failure: "passthrough".into(),
            },
        )
        .await;
        assert!(matches!(
            decoded,
            SystemNodeKind::InlineJudge {
                verdict_expr: ref e,
                pass_threshold: Some(t),
                on_failure: ref onf,
            } if e.contains("passed: true") && (t - 0.5).abs() < f64::EPSILON && onf == "passthrough"
        ));
    }

    #[cfg(feature = "llm-primitives")]
    #[tokio::test]
    async fn system_node_ensemble_round_trips() {
        let child = Uuid::new_v4();
        let judge = Uuid::new_v4();
        let decoded = round_trip_kind(
            "ens",
            SystemNodeKind::Ensemble {
                child_workflow_id: child,
                count: 5,
                consensus: "majority_vote".into(),
                judge_workflow_id: Some(judge),
                timeout_secs: 90,
            },
        )
        .await;
        assert!(matches!(
            decoded,
            SystemNodeKind::Ensemble {
                child_workflow_id: c,
                count: 5,
                consensus: ref k,
                judge_workflow_id: Some(j),
                timeout_secs: 90,
            } if c == child && j == judge && k == "majority_vote"
        ));
    }

    #[cfg(feature = "llm-primitives")]
    #[tokio::test]
    async fn system_node_confidence_gate_round_trips() {
        let decoded = round_trip_kind(
            "cg",
            SystemNodeKind::ConfidenceGate {
                threshold: 0.65,
                confidence_path: "out.conf".into(),
                on_low_confidence: "pause".into(),
            },
        )
        .await;
        assert!(matches!(
            decoded,
            SystemNodeKind::ConfidenceGate {
                threshold: t,
                confidence_path: ref p,
                on_low_confidence: ref a,
            } if (t - 0.65).abs() < f64::EPSILON && p == "out.conf" && a == "pause"
        ));
    }

    #[cfg(feature = "llm-primitives")]
    #[tokio::test]
    async fn system_node_react_loop_round_trips() {
        let wf_id = Uuid::new_v4();
        let decoded = round_trip_kind(
            "react",
            SystemNodeKind::ReActLoop {
                body_workflow_id: wf_id,
                max_iterations: 8,
                inject_history: true,
                timeout_secs: 120,
            },
        )
        .await;
        assert!(matches!(
            decoded,
            SystemNodeKind::ReActLoop {
                body_workflow_id: w,
                max_iterations: 8,
                inject_history: true,
                timeout_secs: 120,
            } if w == wf_id
        ));
    }

    #[cfg(feature = "llm-primitives")]
    #[tokio::test]
    async fn system_node_reflective_retry_round_trips() {
        let child = Uuid::new_v4();
        let reflection = Uuid::new_v4();
        let decoded = round_trip_kind(
            "rr",
            SystemNodeKind::ReflectiveRetry {
                child_workflow_id: child,
                reflection_workflow_id: reflection,
                max_retries: 3,
                timeout_secs: 75,
            },
        )
        .await;
        assert!(matches!(
            decoded,
            SystemNodeKind::ReflectiveRetry {
                child_workflow_id: c,
                reflection_workflow_id: r,
                max_retries: 3,
                timeout_secs: 75,
            } if c == child && r == reflection
        ));
    }

    #[cfg(feature = "llm-primitives")]
    #[tokio::test]
    async fn system_node_llm_dispatch_round_trips() {
        let classifier = Uuid::new_v4();
        let support = Uuid::new_v4();
        let billing = Uuid::new_v4();
        let fallback = Uuid::new_v4();
        let mut routes = std::collections::HashMap::new();
        routes.insert("support".to_string(), support);
        routes.insert("billing".to_string(), billing);

        let decoded = round_trip_kind(
            "lld",
            SystemNodeKind::LlmDispatch {
                classifier_workflow_id: classifier,
                routes: routes.clone(),
                fallback_workflow_id: Some(fallback),
                timeout_secs: 60,
            },
        )
        .await;
        let SystemNodeKind::LlmDispatch {
            classifier_workflow_id,
            routes: decoded_routes,
            fallback_workflow_id,
            timeout_secs,
        } = decoded
        else {
            panic!("expected LlmDispatch");
        };
        assert_eq!(classifier_workflow_id, classifier);
        assert_eq!(fallback_workflow_id, Some(fallback));
        assert_eq!(timeout_secs, 60);
        assert_eq!(decoded_routes.get("support"), Some(&support));
        assert_eq!(decoded_routes.get("billing"), Some(&billing));
        assert_eq!(decoded_routes.len(), 2);
    }
}
