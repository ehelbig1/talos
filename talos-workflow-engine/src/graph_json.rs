//! Schema, typed inspection, and validation for the React-Flow `graph_json`
//! shape the engine accepts at
//! [`ParallelWorkflowEngine::load_graph_from_json`](crate::ParallelWorkflowEngine::load_graph_from_json).
//!
//! Two consumer-facing surfaces:
//!
//! * [`SCHEMA_DOC`] — the canonical schema reference, embedded as a
//!   `&'static str` at compile time. Useful when shipping a CLI that
//!   prints the schema, generating documentation, or pasting into
//!   developer tooling. Reads identically to the `docs/graph-json-schema.md`
//!   file in the repo.
//! * [`validate`] — parse a `graph_json` string, structurally check the
//!   top-level shape, classify each node, and return a
//!   [`GraphSummary`] (node / edge counts, system-kinds seen, soft
//!   warnings) without instantiating a [`ParallelWorkflowEngine`].
//!   Hard parse failures bubble through [`GraphJsonError`].
//!
//! The engine's own parser is the authoritative reader; this module
//! deliberately mirrors a documented subset rather than re-implementing
//! every dispatch-time check, so the two cannot drift on
//! dispatch-relevant fields.
//!
//! [`ParallelWorkflowEngine`]: crate::ParallelWorkflowEngine

use std::fmt;

use serde_json::Value as JsonValue;

/// Canonical schema reference embedded at compile time.
///
/// Reads identically to the `docs/graph-json-schema.md` file in the
/// source tree. Useful for CLIs that print the schema (`my-cli
/// schema`), for embedding into editor tooltips, or for asserting in
/// downstream tests that the schema in your bundled docs matches the
/// version your engine pinned against.
///
/// The string is the raw markdown source — render or strip markdown
/// at the consumer side as needed.
pub const SCHEMA_DOC: &str = include_str!("../../docs/workflow-engine/graph-json-schema.md");

/// System-node `kind` strings the engine accepts in `graph_json` input,
/// excluding the LLM-gated set. Keep in sync with the parser branches in
/// [`crate::graph_parser::parse_system_node_kind`] and the serializer in
/// [`crate::graph_builder`]; `all_kinds_classified_as_known` in this
/// module's tests round-trips every builder-emitted kind through
/// [`known_system_kind`] so drift surfaces immediately.
const KNOWN_SYSTEM_KINDS_BASE: &[&str] = &[
    "wait",
    "sub_workflow",
    "loop",
    "while_loop",
    "repeat_loop",
    "fan_in",
    "error_handler",
    "collect",
    "ops_alerts_digest",
    "pending_approvals",
    "assistant_report",
    "synthesize",
    "verify",
    "dispatch",
    "capability_dispatch",
];

/// LLM-gated system-node `kind` strings, accepted only when the
/// `llm-primitives` feature is enabled.
const KNOWN_SYSTEM_KINDS_LLM: &[&str] = &[
    "agent_loop",
    "react_loop",
    "judge",
    "inline_judge",
    "ensemble",
    "confidence_gate",
    "reflective_retry",
    "llm_dispatch",
];

/// Hard structural error from [`validate`].
///
/// Soft issues (skipped nodes, unrecognized fields) flow through
/// [`GraphSummary::warnings`] instead.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GraphJsonError {
    /// Input was not valid JSON.
    #[error("graph_json is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),

    /// Top-level value was not a JSON object.
    #[error("graph_json must be a JSON object at the top level (got {found})")]
    NotAnObject {
        /// Name of the unexpected JSON type at the top level.
        found: &'static str,
    },

    /// `nodes` field was present but not an array.
    #[error("graph_json `nodes` field must be an array (got {found})")]
    NodesNotArray {
        /// Name of the unexpected JSON type for `nodes`.
        found: &'static str,
    },

    /// `edges` field was present but not an array.
    #[error("graph_json `edges` field must be an array (got {found})")]
    EdgesNotArray {
        /// Name of the unexpected JSON type for `edges`.
        found: &'static str,
    },
}

/// Structured summary of a `graph_json` payload.
///
/// All counts reflect raw structure — the engine's own parser may
/// silently skip nodes the validator counted (presentation-only
/// annotations whose `type` is not a UUID and whose `kind` is not a
/// known system kind). [`Self::warnings`] captures the same soft
/// problems the engine would skip past.
#[derive(Debug, Clone, Default)]
pub struct GraphSummary {
    /// Total nodes in the `nodes` array.
    pub node_count: usize,
    /// Total edges in the `edges` array.
    pub edge_count: usize,
    /// Nodes whose `type` field parses as a `Uuid` (or carry
    /// `data.moduleId`) — these dispatch to a worker module.
    pub module_node_count: usize,
    /// Nodes whose `kind` matches a known system-node kind.
    pub system_node_count: usize,
    /// Nodes the engine would silently skip (no `module_id` and no
    /// known `kind`). Often React-Flow editor annotations.
    pub annotation_node_count: usize,
    /// `execution_timeout_secs` field if present at the top level.
    pub execution_timeout_secs: Option<u64>,
    /// Sorted, deduplicated list of system `kind` strings observed.
    /// Useful for quick "does this graph use LLM nodes?" checks.
    pub system_node_kinds: Vec<String>,
    /// Soft issues that would not fail engine load but are worth
    /// surfacing (missing `id`, edge whose `source`/`target` is empty,
    /// unknown system `kind`, etc.). Each entry is a one-line message.
    pub warnings: Vec<String>,
}

/// Parse and structurally validate a `graph_json` string without
/// constructing a [`ParallelWorkflowEngine`](crate::ParallelWorkflowEngine).
///
/// Hard structural issues (invalid JSON, top-level not an object,
/// `nodes` / `edges` field is wrong type) bubble through
/// [`GraphJsonError`]. Soft issues (skipped nodes, unrecognized
/// `kind`) accumulate in [`GraphSummary::warnings`] so the caller
/// can surface them in CI logs or editor diagnostics without failing
/// the parse.
///
/// LLM-gated kinds (`judge`, `ensemble`, `agent_loop`, ...) are
/// classified as known system kinds only when the `llm-primitives`
/// feature is active on this crate. With the feature disabled they
/// land in the warnings list — matching the engine's own dispatch-
/// time behavior of rejecting the kind.
///
/// # Errors
///
/// Returns [`GraphJsonError`] when the input is not parseable JSON,
/// not a top-level object, or has a non-array `nodes`/`edges` field.
pub fn validate(graph_json: &str) -> Result<GraphSummary, GraphJsonError> {
    let value: JsonValue = serde_json::from_str(graph_json)?;
    validate_value(&value)
}

/// Like [`validate`], but operates on a pre-parsed
/// [`serde_json::Value`]. Use when the caller already holds a parsed
/// graph — for example when reading from a
/// [`WorkflowGraphStore`](talos_workflow_engine_core::WorkflowGraphStore)
/// that returned a `Value`.
///
/// # Errors
///
/// Same hard-error contract as [`validate`], minus the
/// JSON-parse arm.
pub fn validate_value(value: &JsonValue) -> Result<GraphSummary, GraphJsonError> {
    let obj = value.as_object().ok_or(GraphJsonError::NotAnObject {
        found: json_type_name(value),
    })?;

    let mut summary = GraphSummary {
        execution_timeout_secs: obj
            .get("execution_timeout_secs")
            .and_then(JsonValue::as_u64),
        ..Default::default()
    };

    if let Some(nodes_field) = obj.get("nodes") {
        let nodes = nodes_field
            .as_array()
            .ok_or(GraphJsonError::NodesNotArray {
                found: json_type_name(nodes_field),
            })?;
        summary.node_count = nodes.len();

        let mut kinds_seen: std::collections::BTreeSet<String> = Default::default();
        for (idx, node) in nodes.iter().enumerate() {
            classify_node(idx, node, &mut summary, &mut kinds_seen);
        }
        summary.system_node_kinds = kinds_seen.into_iter().collect();
    }

    if let Some(edges_field) = obj.get("edges") {
        let edges = edges_field
            .as_array()
            .ok_or(GraphJsonError::EdgesNotArray {
                found: json_type_name(edges_field),
            })?;
        summary.edge_count = edges.len();

        for (idx, edge) in edges.iter().enumerate() {
            inspect_edge(idx, edge, &mut summary);
        }
    }

    Ok(summary)
}

fn classify_node(
    idx: usize,
    node: &JsonValue,
    summary: &mut GraphSummary,
    kinds_seen: &mut std::collections::BTreeSet<String>,
) {
    let id = node.get("id").and_then(JsonValue::as_str);
    if id.is_none_or(str::is_empty) {
        summary
            .warnings
            .push(format!("node[{idx}] missing or empty `id`"));
    }

    let type_field = node.get("type").and_then(JsonValue::as_str);
    let module_via_type = type_field
        .filter(|s| uuid::Uuid::parse_str(s).is_ok())
        .is_some();
    let module_via_data = node
        .get("data")
        .and_then(|d| d.get("moduleId"))
        .and_then(JsonValue::as_str)
        .filter(|s| uuid::Uuid::parse_str(s).is_ok())
        .is_some();
    let is_module = module_via_type || module_via_data;

    let kind_field = node.get("kind").and_then(JsonValue::as_str);
    if let Some(kind) = kind_field {
        kinds_seen.insert(kind.to_string());
        if known_system_kind(kind) {
            summary.system_node_count += 1;
        } else if known_llm_system_kind(kind) {
            // Known kind, but the consuming binary disabled the feature.
            summary.warnings.push(format!(
                "node[{idx}] `kind: {kind}` is an LLM-gated system kind but the \
                 `llm-primitives` feature is disabled on talos-workflow-engine; \
                 the engine will reject this node at dispatch time"
            ));
            summary.annotation_node_count += 1;
        } else {
            summary.warnings.push(format!(
                "node[{idx}] `kind: {kind}` is not a known system kind; \
                 the engine will reject this node at dispatch time"
            ));
            summary.annotation_node_count += 1;
        }
        return;
    }

    if is_module {
        summary.module_node_count += 1;
    } else {
        // No module_id and no system kind — engine treats as annotation.
        summary.annotation_node_count += 1;
        if type_field.is_some_and(|t| !t.is_empty()) {
            summary.warnings.push(format!(
                "node[{idx}] has `type` but it is neither a UUID nor a known \
                 system kind; the engine will silently skip this node"
            ));
        }
    }
}

fn inspect_edge(idx: usize, edge: &JsonValue, summary: &mut GraphSummary) {
    let src = edge.get("source").and_then(JsonValue::as_str);
    if src.is_none_or(str::is_empty) {
        summary
            .warnings
            .push(format!("edge[{idx}] missing or empty `source`"));
    }
    let tgt = edge.get("target").and_then(JsonValue::as_str);
    if tgt.is_none_or(str::is_empty) {
        summary
            .warnings
            .push(format!("edge[{idx}] missing or empty `target`"));
    }
}

#[cfg(feature = "llm-primitives")]
fn known_system_kind(kind: &str) -> bool {
    KNOWN_SYSTEM_KINDS_BASE.contains(&kind) || KNOWN_SYSTEM_KINDS_LLM.contains(&kind)
}

#[cfg(not(feature = "llm-primitives"))]
fn known_system_kind(kind: &str) -> bool {
    KNOWN_SYSTEM_KINDS_BASE.contains(&kind)
}

#[cfg(feature = "llm-primitives")]
fn known_llm_system_kind(_kind: &str) -> bool {
    // With the feature on, LLM kinds are part of `known_system_kind`.
    // The validator never enters the warning branch for them.
    false
}

#[cfg(not(feature = "llm-primitives"))]
fn known_llm_system_kind(kind: &str) -> bool {
    KNOWN_SYSTEM_KINDS_LLM.contains(&kind)
}

fn json_type_name(v: &JsonValue) -> &'static str {
    match v {
        JsonValue::Null => "null",
        JsonValue::Bool(_) => "bool",
        JsonValue::Number(_) => "number",
        JsonValue::String(_) => "string",
        JsonValue::Array(_) => "array",
        JsonValue::Object(_) => "object",
    }
}

impl fmt::Display for GraphSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "graph_json: {} nodes ({} module, {} system, {} annotation), {} edges",
            self.node_count,
            self.module_node_count,
            self.system_node_count,
            self.annotation_node_count,
            self.edge_count,
        )?;
        if let Some(secs) = self.execution_timeout_secs {
            writeln!(f, "  execution_timeout_secs: {secs}")?;
        }
        if !self.system_node_kinds.is_empty() {
            writeln!(f, "  system kinds: {}", self.system_node_kinds.join(", "))?;
        }
        if !self.warnings.is_empty() {
            writeln!(f, "  warnings ({}):", self.warnings.len())?;
            for w in &self.warnings {
                writeln!(f, "    - {w}")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn schema_doc_is_non_empty() {
        assert!(SCHEMA_DOC.contains("graph_json"));
        assert!(SCHEMA_DOC.contains("nodes"));
    }

    #[test]
    fn empty_object_validates_to_zero_counts() {
        let s = validate("{}").expect("empty object is valid");
        assert_eq!(s.node_count, 0);
        assert_eq!(s.edge_count, 0);
        assert!(s.warnings.is_empty());
    }

    #[test]
    fn invalid_json_errors() {
        let err = validate("{not json").expect_err("must reject invalid JSON");
        assert!(matches!(err, GraphJsonError::Json(_)));
    }

    #[test]
    fn top_level_array_errors() {
        let err = validate("[1, 2, 3]").expect_err("must reject non-object");
        match err {
            GraphJsonError::NotAnObject { found } => assert_eq!(found, "array"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn nodes_must_be_array() {
        let err = validate(r#"{"nodes": 5}"#).expect_err("non-array nodes is hard error");
        assert!(matches!(err, GraphJsonError::NodesNotArray { .. }));
    }

    #[test]
    fn edges_must_be_array() {
        let err = validate(r#"{"edges": "not-array"}"#).expect_err("non-array edges is hard error");
        assert!(matches!(err, GraphJsonError::EdgesNotArray { .. }));
    }

    #[test]
    fn module_node_classified_by_uuid_type() {
        let g = json!({
            "nodes": [{ "id": "n1", "type": uuid::Uuid::new_v4().to_string() }],
        });
        let s = validate_value(&g).unwrap();
        assert_eq!(s.module_node_count, 1);
        assert_eq!(s.system_node_count, 0);
        assert!(s.warnings.is_empty());
    }

    #[test]
    fn module_node_classified_by_data_module_id() {
        let g = json!({
            "nodes": [{
                "id": "n1",
                "type": "experimental",
                "data": { "moduleId": uuid::Uuid::new_v4().to_string() }
            }],
        });
        let s = validate_value(&g).unwrap();
        assert_eq!(s.module_node_count, 1);
        // type is non-UUID and non-system-kind, but moduleId saves it →
        // no warning about silent-skip.
        assert!(s.warnings.is_empty(), "warnings: {:?}", s.warnings);
    }

    #[test]
    fn known_system_kind_classified_correctly() {
        let g = json!({
            "nodes": [
                { "id": "a", "kind": "wait" },
                { "id": "b", "kind": "collect" },
            ],
        });
        let s = validate_value(&g).unwrap();
        assert_eq!(s.system_node_count, 2);
        assert_eq!(s.system_node_kinds, vec!["collect", "wait"]);
    }

    #[test]
    fn all_base_kinds_classified_as_known() {
        // Drift guard: every base `kind` string the builder / parser
        // handles must round-trip as "known" through the validator.
        // If a new variant is added to `SystemNodeKind` without a
        // corresponding entry in `KNOWN_SYSTEM_KINDS_BASE`, the
        // validator will warn "unknown system kind" on valid graphs
        // — this test catches that drift before release.
        let nodes: Vec<_> = KNOWN_SYSTEM_KINDS_BASE
            .iter()
            .enumerate()
            .map(|(i, k)| json!({ "id": format!("n{i}"), "kind": k }))
            .collect();
        let g = json!({ "nodes": nodes });
        let s = validate_value(&g).unwrap();
        assert_eq!(s.system_node_count, KNOWN_SYSTEM_KINDS_BASE.len());
        assert!(
            s.warnings.is_empty(),
            "expected no warnings for builder-emitted kinds, got: {:?}",
            s.warnings
        );
    }

    #[cfg(feature = "llm-primitives")]
    #[test]
    fn all_llm_kinds_classified_as_known_when_feature_on() {
        let nodes: Vec<_> = KNOWN_SYSTEM_KINDS_LLM
            .iter()
            .enumerate()
            .map(|(i, k)| json!({ "id": format!("n{i}"), "kind": k }))
            .collect();
        let g = json!({ "nodes": nodes });
        let s = validate_value(&g).unwrap();
        assert_eq!(s.system_node_count, KNOWN_SYSTEM_KINDS_LLM.len());
        assert!(
            s.warnings.is_empty(),
            "expected no warnings for LLM kinds with feature on, got: {:?}",
            s.warnings
        );
    }

    #[test]
    fn unknown_kind_warns_and_counts_as_annotation() {
        let g = json!({
            "nodes": [{ "id": "x", "kind": "bogus" }],
        });
        let s = validate_value(&g).unwrap();
        assert_eq!(s.annotation_node_count, 1);
        assert_eq!(s.system_node_count, 0);
        assert_eq!(s.warnings.len(), 1);
        assert!(s.warnings[0].contains("bogus"));
    }

    #[cfg(feature = "llm-primitives")]
    #[test]
    fn llm_kind_recognized_when_feature_on() {
        let g = json!({
            "nodes": [{ "id": "j", "kind": "judge" }],
        });
        let s = validate_value(&g).unwrap();
        assert_eq!(s.system_node_count, 1);
        assert!(s.warnings.is_empty());
    }

    #[cfg(not(feature = "llm-primitives"))]
    #[test]
    fn llm_kind_warns_when_feature_off() {
        let g = json!({
            "nodes": [{ "id": "j", "kind": "judge" }],
        });
        let s = validate_value(&g).unwrap();
        assert_eq!(s.system_node_count, 0);
        assert_eq!(s.annotation_node_count, 1);
        assert_eq!(s.warnings.len(), 1);
        assert!(s.warnings[0].contains("llm-primitives"));
    }

    #[test]
    fn missing_node_id_warns() {
        let g = json!({ "nodes": [{ "type": uuid::Uuid::new_v4().to_string() }] });
        let s = validate_value(&g).unwrap();
        assert!(s
            .warnings
            .iter()
            .any(|w| w.contains("missing or empty `id`")));
    }

    #[test]
    fn edge_missing_source_or_target_warns() {
        let g = json!({
            "edges": [{ "target": "x" }, { "source": "" }],
        });
        let s = validate_value(&g).unwrap();
        assert!(s.warnings.iter().any(|w| w.contains("source")));
        assert!(s.warnings.iter().any(|w| w.contains("target")));
    }

    #[test]
    fn execution_timeout_extracted() {
        let g = json!({ "execution_timeout_secs": 600 });
        let s = validate_value(&g).unwrap();
        assert_eq!(s.execution_timeout_secs, Some(600));
    }

    #[test]
    fn display_renders_summary() {
        let g = json!({
            "nodes": [
                { "id": "a", "type": uuid::Uuid::new_v4().to_string() },
                { "id": "b", "kind": "collect" },
            ],
            "edges": [{ "source": "a", "target": "b" }],
        });
        let s = validate_value(&g).unwrap();
        let rendered = s.to_string();
        assert!(rendered.contains("2 nodes"));
        assert!(rendered.contains("1 module"));
        assert!(rendered.contains("1 system"));
        assert!(rendered.contains("collect"));
    }
}
