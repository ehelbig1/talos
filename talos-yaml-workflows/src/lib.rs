//! YAML workflow parse/validate/convert helpers.
//!
//! The data shape (`YamlWorkflow`, `YamlNode`, `YamlEdge`,
//! `WorkflowSettings`) lives in `talos-workflow-types` so downstream
//! tooling (CI linters, IDE plugins) can consume the schema without
//! depending on the controller binary. The functions in this module
//! cover the controller-side concerns: YAML parsing (`serde-saphyr`), `anyhow`-
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
/// 1 MiB) before invoking the parser. Without an up-front cap, an
/// authenticated user submitting a YAML-bomb manifest could exhaust the
/// controller's memory during parse. The size check runs in O(1) ahead of
/// the parser's O(n) work, so the cap is the cheap-fail boundary. (The
/// parser, `serde-saphyr`, also budgets what one document may expand to;
/// this cap is ours and does not depend on it.)
///
/// The parser was `serde_yaml` until 2026-10-12. That crate is deprecated
/// and parses with `unsafe-libyaml`, a machine translation of C to unsafe
/// Rust whose repository is archived (RUSTSEC-2024-0449): this function
/// hands it text a user wrote. `serde-saphyr` parses in safe Rust.
/// `a_document_in_the_old_export_format_still_imports` pins that a file an
/// earlier release exported is read to the same values.
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
    let workflow: YamlWorkflow = serde_saphyr::from_str_with_options(yaml, parse_options())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    validate(&workflow)?;
    Ok(workflow)
}

/// How workflow YAML is read.
///
/// * `strict_booleans`: only `true` and `false` are booleans. The parser's
///   default also reads `yes`, `no`, `on` and `off` as booleans (YAML 1.1);
///   `serde_yaml` did not, and it WROTE such strings unquoted — so with the
///   default, a config value `"yes"` in a file an earlier release exported
///   would come back as `true`.
/// * `with_snippet: false`: a parse error names a line and a column and does
///   not quote the document. The text is a user's workflow, config values
///   included, and this error is both returned and logged.
fn parse_options() -> serde_saphyr::Options {
    serde_saphyr::options! {
        strict_booleans: true,
        with_snippet: false,
    }
}

/// Serialize a workflow to YAML string.
pub fn to_yaml(workflow: &YamlWorkflow) -> Result<String> {
    Ok(serde_saphyr::to_string(workflow)?)
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

    /// A file exported before the parser changed (2026-10-12) must still
    /// import, to the same values and the same JSON types. This document is
    /// in the style `serde_yaml` 0.9 wrote: block mappings, sequences at the
    /// parent's indent, single quotes around strings that would otherwise
    /// read as another type, `|` for text with line breaks.
    #[test]
    fn a_document_in_the_old_export_format_still_imports() {
        let exported = r#"name: nightly-report
description: 'Runs at 02:00: reads, composes, sends'
capabilities:
- report
- email
nodes:
- id: fetch
  module: http-get
  capability_world: http-node
  config:
    URL: https://api.example.test/v3/items?limit=50&sort=-updated
    AUTH_HEADER: Bearer vault://example/token
    SCHEDULE: 0 2 * * 1-5
    MAX_RESULTS: 50
    RATIO: 0.25
    DRY_RUN: false
    LABEL: 'true'
    ANSWER: yes
    SWITCH: off
    ZIP: '02134'
    NOTHING: null
    EMPTY: ''
    TAGS:
    - a
    - 'b: c'
    NESTED:
      depth: 2
      on: yes
    max_fuel: 4000000
  retry_count: 2
- id: compose
  module: inline
  rust_code: |
    pub fn run(input: String) -> Result<String, String> {
        // a "quoted" word, a colon: and a # that is not a comment
        Ok(input)
    }
  continue_on_error: true
  skip_condition: input.items.len() == 0
edges:
- from: fetch
  to: compose
"#;
        let wf = parse_yaml(exported).expect("an old export imports");
        assert_eq!(wf.name, "nightly-report");
        assert_eq!(wf.description, "Runs at 02:00: reads, composes, sends");
        assert_eq!(wf.capabilities, ["report", "email"]);
        assert_eq!((wf.nodes.len(), wf.edges.len()), (2, 1));

        let fetch = &wf.nodes[0];
        assert_eq!(
            (fetch.id.as_str(), fetch.module.as_str(), fetch.retry_count),
            ("fetch", "http-get", 2)
        );
        assert_eq!(fetch.capability_world.as_deref(), Some("http-node"));
        let expected = serde_json::json!({
            "URL": "https://api.example.test/v3/items?limit=50&sort=-updated",
            "AUTH_HEADER": "Bearer vault://example/token",
            "SCHEDULE": "0 2 * * 1-5",
            "MAX_RESULTS": 50,
            "RATIO": 0.25,
            "DRY_RUN": false,
            // Quoted, so a string: not the boolean and not the number.
            "LABEL": "true",
            // Unquoted, as the old exporter wrote them: still strings.
            "ANSWER": "yes",
            "SWITCH": "off",
            "ZIP": "02134",
            "NOTHING": null,
            "EMPTY": "",
            "TAGS": ["a", "b: c"],
            // YAML 1.2, as before: `yes` is a string, not a boolean.
            "NESTED": {"depth": 2, "on": "yes"},
            "max_fuel": 4_000_000,
        });
        assert_eq!(serde_json::Value::Object(fetch.config.clone()), expected);

        let compose = &wf.nodes[1];
        assert_eq!(
            compose.rust_code.as_deref(),
            Some(
                "pub fn run(input: String) -> Result<String, String> {\n    // a \"quoted\" word, a colon: and a # that is not a comment\n    Ok(input)\n}\n"
            )
        );
        assert!(compose.continue_on_error);
        assert_eq!(
            compose.skip_condition.as_deref(),
            Some("input.items.len() == 0")
        );

        // What this release exports, this release imports to the same thing.
        let again = parse_yaml(&to_yaml(&wf).expect("export")).expect("import");
        assert_eq!(
            serde_json::to_value(&again).expect("json"),
            serde_json::to_value(&wf).expect("json")
        );
    }

    /// A string that looks like another type goes out and comes back a string.
    #[test]
    fn strings_that_look_like_other_types_survive_a_round_trip() {
        let looks = [
            "yes",
            "no",
            "on",
            "off",
            "y",
            "n",
            "Yes",
            "ON",
            "true",
            "false",
            "True",
            "null",
            "~",
            "",
            "123",
            "0123",
            "1e3",
            "0x1f",
            "-5",
            "3.14",
            ".inf",
            "2026-10-12",
            " leading",
            "trailing ",
            "a: b",
            "- item",
            "# not a comment",
            "*alias",
            "&anchor",
            "{braces}",
            "[brackets]",
            "multi\nline",
            "tab\there",
            "quote's \"both\"",
            "@at",
            "%pct",
        ];
        let mut config = serde_json::Map::new();
        for (i, s) in looks.iter().enumerate() {
            config.insert(format!("K{i:02}"), serde_json::json!(s));
        }
        let wf = YamlWorkflow {
            name: "looks".to_string(),
            description: "yes".to_string(),
            capabilities: vec!["no".to_string(), "123".to_string()],
            nodes: vec![YamlNode {
                id: "n1".to_string(),
                module: "echo".to_string(),
                capability_world: None,
                rust_code: None,
                js_code: None,
                python_code: None,
                config: config.clone(),
                node_type: None,
                retry_count: 0,
                continue_on_error: false,
                skip_condition: None,
                version: None,
            }],
            edges: vec![],
            settings: WorkflowSettings::default(),
        };
        let back = parse_yaml(&to_yaml(&wf).expect("export")).expect("import");
        assert_eq!(back.description, "yes");
        assert_eq!(back.capabilities, ["no", "123"]);
        for (key, value) in &config {
            assert_eq!(back.nodes[0].config.get(key), Some(value), "{key}");
        }
    }

    /// A parse error says where, and does not quote the document: it is
    /// returned and logged, and the document is a user's config.
    #[test]
    fn a_parse_error_does_not_quote_the_document() {
        let err = parse_yaml("name: x\nnodes:\n- id: a\n  config:\n    TOKEN: sk-do-not-echo-this\n   bad: [unclosed\n")
            .expect_err("malformed")
            .to_string();
        assert!(!err.contains("sk-do-not-echo-this"), "{err}");
        assert!(!err.is_empty());
    }

    /// Our size cap is checked before the parser runs; a large but ordinary
    /// document under it is still read.
    #[test]
    fn a_large_ordinary_document_is_read() {
        let mut yaml = String::from("name: big\nnodes:\n");
        for i in 0..2000 {
            yaml.push_str(&format!(
                "- id: n{i}\n  module: echo\n  config:\n    A: {i}\n    B: text {i}\n"
            ));
        }
        assert!(yaml.len() < DEFAULT_MAX_YAML_BYTES);
        assert_eq!(
            parse_yaml(&yaml).expect("a large document").nodes.len(),
            2000
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
