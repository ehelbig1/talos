//! YAML workflow parse/validate/convert helpers.
//!
//! The data shape (`YamlWorkflow`, `YamlNode`, `YamlEdge`,
//! `WorkflowSettings`) lives in `talos-workflow-types` so downstream
//! tooling (CI linters, IDE plugins) can consume the schema without
//! depending on the controller binary. The functions in this module
//! cover the controller-side concerns: `serde_yaml` parsing, `anyhow`-
//! flavoured validation errors, and graph-JSON ↔ YAML conversion.
//!
//! Inherent methods on `YamlWorkflow` are not possible because the type
//! lives in another crate; callers use `parse_yaml(..)` /
//! `to_yaml(&wf)` / `validate(&wf)` / `from_graph_json(..)` instead.

use anyhow::Result;
use serde_json::Value as JsonValue;

pub use talos_workflow_types::{WorkflowSettings, YamlEdge, YamlNode, YamlWorkflow};

/// MCP-500: maximum accepted YAML input size for `parse_yaml`. A
/// legitimate workflow YAML is typically a few KB to ~50 KB; 1 MiB
/// gives generous headroom for the largest real-world manifest while
/// preventing a deeply-nested YAML bomb (anchors / aliases / nested
/// maps) from chewing through controller memory before the parser
/// even produces an error. Override at process start via
/// `TALOS_MAX_YAML_BYTES` if a tenant has a genuinely huge workflow.
pub const DEFAULT_MAX_YAML_BYTES: usize = 1_048_576;

fn max_yaml_bytes() -> usize {
    use std::sync::OnceLock;
    static CACHED: OnceLock<usize> = OnceLock::new();
    *CACHED.get_or_init(|| {
        std::env::var("TALOS_MAX_YAML_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|&n: &usize| n > 0)
            .unwrap_or(DEFAULT_MAX_YAML_BYTES)
    })
}

/// Parse a YAML string into a workflow definition. Validates structure
/// before returning.
///
/// MCP-500: rejects inputs larger than `TALOS_MAX_YAML_BYTES` (default
/// 1 MiB) before invoking the parser. `serde_yaml` has no built-in
/// DoS protection — without an up-front cap, an authenticated user
/// submitting a YAML-bomb manifest could exhaust the controller's
/// memory during parse. The size check runs in O(1) ahead of the
/// parser's O(n) work, so the cap is the cheap-fail boundary.
pub fn parse_yaml(yaml: &str) -> Result<YamlWorkflow> {
    let cap = max_yaml_bytes();
    if yaml.len() > cap {
        anyhow::bail!(
            "Workflow YAML exceeds size limit ({} bytes; max {} bytes). \
             Set TALOS_MAX_YAML_BYTES to raise the cap.",
            yaml.len(),
            cap
        );
    }
    let workflow: YamlWorkflow = serde_yaml::from_str(yaml)?;
    validate(&workflow)?;
    Ok(workflow)
}

/// Serialize a workflow to YAML string.
pub fn to_yaml(workflow: &YamlWorkflow) -> Result<String> {
    Ok(serde_yaml::to_string(workflow)?)
}

/// Validate the workflow definition for structural correctness.
///
/// MCP-500: also rejects empty / whitespace-only node IDs and empty
/// edge endpoints. Pre-fix, a malformed `from_graph_json` result
/// (where a source `nodes[].id` was missing) would produce a node with
/// `id: ""` that round-tripped through YAML cleanly and only failed at
/// engine execution time with a confusing message. Catching it here
/// gives an actionable parse-time error and prevents the empty-ID
/// node from masking a duplicate-empty-string check elsewhere (since
/// "" == "" matches but most users wouldn't intend it).
pub fn validate(workflow: &YamlWorkflow) -> Result<()> {
    // Check for empty / duplicate node IDs.
    let mut seen = std::collections::HashSet::new();
    for node in &workflow.nodes {
        if node.id.trim().is_empty() {
            anyhow::bail!("Workflow contains a node with an empty or whitespace-only id");
        }
        if !seen.insert(&node.id) {
            anyhow::bail!("Duplicate node ID: '{}'", node.id);
        }
    }
    // Check that all edge endpoints reference existing nodes
    for edge in &workflow.edges {
        if edge.from.trim().is_empty() || edge.to.trim().is_empty() {
            anyhow::bail!(
                "Edge has empty endpoint (from='{}', to='{}')",
                edge.from,
                edge.to
            );
        }
        if !seen.contains(&edge.from) {
            anyhow::bail!("Edge references unknown source node: '{}'", edge.from);
        }
        if !seen.contains(&edge.to) {
            anyhow::bail!("Edge references unknown target node: '{}'", edge.to);
        }
        if edge.from == edge.to {
            anyhow::bail!("Self-loop detected on node: '{}'", edge.from);
        }
    }
    Ok(())
}

/// Convert a workflow's graph_json + metadata into a YamlWorkflow for export.
pub fn from_graph_json(
    name: &str,
    description: &str,
    graph_json: &JsonValue,
    capabilities: &[String],
) -> Result<YamlWorkflow> {
    let nodes = graph_json
        .get("nodes")
        .and_then(|n| n.as_array())
        .map(|arr| {
            arr.iter()
                .map(|n| YamlNode {
                    id: n
                        .get("id")
                        .and_then(|i| i.as_str())
                        .unwrap_or("")
                        .to_string(),
                    module: n
                        .get("type")
                        .and_then(|t| t.as_str())
                        .unwrap_or("")
                        .to_string(),
                    capability_world: None,
                    rust_code: None,
                    js_code: None,
                    python_code: None,
                    config: n
                        .get("data")
                        .and_then(|d| d.as_object())
                        .cloned()
                        .unwrap_or_default(),
                    node_type: n
                        .get("data")
                        .and_then(|d| d.get("systemNodeKind"))
                        .and_then(|s| s.as_str())
                        .map(String::from),
                    // MCP-962 sibling: saturating u64→u32 conversion on
                    // the YAML import path; mirrors the graph_parser fix
                    // for the React-Flow JSON path. Pre-fix `as u32`
                    // silently wrapped a misconfigured `retry_count:
                    // 5_000_000_000` into ~705M retries.
                    retry_count: n
                        .get("retry_count")
                        .and_then(|r| r.as_u64())
                        .map(|v| u32::try_from(v).unwrap_or(u32::MAX))
                        .unwrap_or(0),
                    continue_on_error: n
                        .get("continue_on_error")
                        .and_then(|c| c.as_bool())
                        .unwrap_or(false),
                    skip_condition: n
                        .get("skip_condition")
                        .and_then(|s| s.as_str())
                        .map(String::from),
                    version: None,
                })
                .collect()
        })
        .unwrap_or_default();

    let edges = graph_json
        .get("edges")
        .and_then(|e| e.as_array())
        .map(|arr| {
            arr.iter()
                .map(|e| YamlEdge {
                    from: e
                        .get("source")
                        .and_then(|s| s.as_str())
                        .unwrap_or("")
                        .to_string(),
                    to: e
                        .get("target")
                        .and_then(|t| t.as_str())
                        .unwrap_or("")
                        .to_string(),
                    condition: e
                        .get("condition")
                        .and_then(|c| c.as_str())
                        .map(String::from),
                    edge_type: e
                        .get("edge_type")
                        .and_then(|t| t.as_str())
                        .map(String::from),
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(YamlWorkflow {
        name: name.to_string(),
        description: description.to_string(),
        capabilities: capabilities.to_vec(),
        nodes,
        edges,
        settings: WorkflowSettings::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_yaml_workflow() {
        let yaml = r#"
name: test-workflow
description: A test workflow
nodes:
  - id: producer
    module: inline
    capability_world: minimal-node
    rust_code: |
      fn run(input: String) -> Result<String, String> {
          Ok("{\"hello\": \"world\"}".to_string())
      }
  - id: consumer
    module: http-request
    config:
      URL: "https://example.com"
      METHOD: "POST"
edges:
  - from: producer
    to: consumer
"#;
        let wf = parse_yaml(yaml).unwrap();
        assert_eq!(wf.name, "test-workflow");
        assert_eq!(wf.nodes.len(), 2);
        assert_eq!(wf.edges.len(), 1);
        assert_eq!(wf.edges[0].from, "producer");
        assert_eq!(wf.edges[0].to, "consumer");
    }

    #[test]
    fn rejects_duplicate_node_ids() {
        let yaml = r#"
name: bad-workflow
nodes:
  - id: same
    module: echo
  - id: same
    module: echo
"#;
        assert!(parse_yaml(yaml).is_err());
    }

    #[test]
    fn rejects_unknown_edge_target() {
        let yaml = r#"
name: bad-edges
nodes:
  - id: a
    module: echo
edges:
  - from: a
    to: nonexistent
"#;
        assert!(parse_yaml(yaml).is_err());
    }

    #[test]
    fn rejects_self_loop() {
        let yaml = r#"
name: loop
nodes:
  - id: a
    module: echo
edges:
  - from: a
    to: a
"#;
        assert!(parse_yaml(yaml).is_err());
    }

    #[test]
    fn parse_rejects_oversized_yaml() {
        // MCP-500: cap defaults to 1 MiB. Build a YAML string > cap.
        let big = "a".repeat(DEFAULT_MAX_YAML_BYTES + 100);
        let yaml = format!("name: x\ndescription: |\n  {}", big);
        let err = parse_yaml(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("size limit"),
            "expected size-limit error, got {}",
            err
        );
    }

    #[test]
    fn validate_rejects_empty_node_id() {
        // MCP-500: an empty id is malformed; catch it at parse time
        // rather than letting it slip through to engine execution.
        let yaml = r#"
name: bad
nodes:
  - id: ""
    module: echo
"#;
        let err = parse_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("empty"),
            "expected empty-id error, got {}",
            err
        );
    }

    #[test]
    fn validate_rejects_whitespace_only_node_id() {
        // Trim-then-check: tabs / spaces / mixed whitespace fail too.
        let yaml = "name: bad\nnodes:\n  - id: \"   \"\n    module: echo\n";
        let err = parse_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("empty"),
            "expected empty-id error, got {}",
            err
        );
    }

    #[test]
    fn roundtrip_yaml_serialization() {
        let wf = YamlWorkflow {
            name: "roundtrip".to_string(),
            description: "test".to_string(),
            capabilities: vec!["data-transform".to_string()],
            nodes: vec![YamlNode {
                id: "n1".to_string(),
                module: "echo".to_string(),
                capability_world: Some("minimal-node".to_string()),
                rust_code: None,
                js_code: None,
                python_code: None,
                config: serde_json::Map::new(),
                node_type: None,
                retry_count: 0,
                continue_on_error: false,
                skip_condition: None,
                version: None,
            }],
            edges: vec![],
            settings: WorkflowSettings::default(),
        };
        let yaml_str = to_yaml(&wf).unwrap();
        let parsed = parse_yaml(&yaml_str).unwrap();
        assert_eq!(parsed.name, "roundtrip");
        assert_eq!(parsed.nodes.len(), 1);
    }
}
