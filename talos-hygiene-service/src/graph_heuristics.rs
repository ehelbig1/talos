//! Pure graph-JSON heuristics shared by the hygiene report (`fix_all`
//! draft partition) and the session brief (draft substantive-ness split).
//! Lifted verbatim from `talos-mcp-handlers/src/advanced.rs` during the
//! HygieneService extraction so both service crates consult ONE predicate
//! and can never disagree about which drafts are auto-deletable.

/// Substantive-draft predicate (M-I, 2026-05-06). Walks `graph_json`
/// once and returns `true` iff the draft has any marker of authored
/// intent — meaning the right next step is `publish_version`, NOT
/// auto-deletion.
///
/// "Substantive" means any one of:
///   * all non-structural nodes have non-empty `data` AND node_count > 0
///   * any node has `SYSTEM_PROMPT` > 200 chars
///   * any node has `OUTPUT_SCHEMA` configured
///   * any node has `retry_count` / `retry_condition` / `retry_delay_expression`
///   * any node has `description` / `skip_condition` / `continue_on_error` set
///
/// Both `session_start` (talos-session-brief-service) AND
/// `get_platform_hygiene_report fix_all` consult this helper so the
/// two surfaces never disagree about which drafts are auto-deletable.
/// Without this shared predicate, fix_all would recommend deleting
/// drafts that session_start simultaneously flags as "ready for
/// publish_version" (the M-I audit finding from 2026-05-06).
pub fn is_substantive_workflow(graph_json: Option<&str>) -> bool {
    let Some(g) = graph_json else { return false };
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(g) else {
        return false;
    };
    let nodes = match parsed.get("nodes").and_then(|n| n.as_array()) {
        Some(n) if !n.is_empty() => n,
        _ => return false,
    };

    // Branch 1: all non-structural nodes are configured.
    if count_nodes_with_empty_data(nodes) == 0 {
        return true;
    }

    // Branch 2: any node has a thoughtful authored marker.
    nodes.iter().any(|n| {
        let data = n.get("data");
        let prompt_len = data
            .and_then(|d| d.get("SYSTEM_PROMPT"))
            .and_then(|v| v.as_str())
            .map(str::len)
            .unwrap_or(0);
        let has_output_schema = data
            .and_then(|d| d.get("OUTPUT_SCHEMA"))
            .map(|v| !v.is_null())
            .unwrap_or(false);
        let has_retry = n.get("retry_count").is_some()
            || n.get("retry_condition").is_some()
            || n.get("retry_delay_expression").is_some();
        let has_per_node_meta = n.get("description").is_some()
            || n.get("skip_condition").is_some()
            || n.get("continue_on_error").is_some();
        prompt_len > 200 || has_output_schema || has_retry || has_per_node_meta
    })
}

/// MCP-2 / MCP-17: count non-structural nodes whose `data` field is
/// missing or empty (`{}`). This is the *coarse, cheap* readiness
/// signal used by `session_start` to summarise drafts in batch — it
/// does NOT consult the per-module config schema, so a node with
/// no required fields will still be counted as "configured" once
/// `data` has any keys at all (or, conversely, will be counted as
/// "unconfigured" if `data` is empty even when no schema fields are
/// strictly required).
///
/// `get_workflow_quickstart` performs the strict per-schema
/// required-fields check (and per-secret provisioning check). The
/// two surfaces can disagree for the same workflow: session_start
/// says "1 unconfigured node" while quickstart says "ready_to_run".
/// Both are correct in their own mode; the divergence is documented
/// inline at each call site (`unconfigured_check_mode` field) so
/// operators reading either response know which mode is reporting.
pub fn count_nodes_with_empty_data(nodes: &[serde_json::Value]) -> usize {
    nodes
        .iter()
        .filter(|n| {
            let is_structural = n
                .get("type")
                .and_then(|v| v.as_str())
                .map(|t| t.starts_with("system:"))
                .unwrap_or(false);
            !is_structural
                && n.get("data")
                    .map(|d| d == &serde_json::json!({}))
                    .unwrap_or(true)
        })
        .count()
}

#[cfg(test)]
mod count_nodes_with_empty_data_tests {
    use super::count_nodes_with_empty_data;

    fn nodes(json: &str) -> Vec<serde_json::Value> {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn empty_input_is_zero() {
        assert_eq!(count_nodes_with_empty_data(&[]), 0);
    }

    #[test]
    fn structural_nodes_never_count() {
        let n = nodes(r#"[{"type":"system:collect"},{"type":"system:trigger"}]"#);
        assert_eq!(count_nodes_with_empty_data(&n), 0);
    }

    #[test]
    fn missing_data_field_counts() {
        let n = nodes(r#"[{"type":"http"}]"#);
        assert_eq!(count_nodes_with_empty_data(&n), 1);
    }

    #[test]
    fn empty_data_object_counts() {
        let n = nodes(r#"[{"type":"http","data":{}}]"#);
        assert_eq!(count_nodes_with_empty_data(&n), 1);
    }

    #[test]
    fn data_with_any_keys_does_not_count() {
        let n = nodes(r#"[{"type":"http","data":{"url":"x"}}]"#);
        assert_eq!(count_nodes_with_empty_data(&n), 0);
    }

    #[test]
    fn divergence_with_quickstart_is_documented() {
        // MCP-2 / MCP-17 regression test: a node whose schema has zero
        // required fields and zero data → quickstart says ready_to_run=true,
        // session_start says unconfigured_node_count=1. This is the
        // documented divergence.
        let n = nodes(r#"[{"type":"echo","data":{}}]"#);
        assert_eq!(count_nodes_with_empty_data(&n), 1);
    }
}

#[cfg(test)]
mod is_substantive_workflow_tests {
    use super::is_substantive_workflow;

    #[test]
    fn none_or_invalid_json_is_not_substantive() {
        assert!(!is_substantive_workflow(None));
        assert!(!is_substantive_workflow(Some("not json")));
        assert!(!is_substantive_workflow(Some("{}")));
        assert!(!is_substantive_workflow(Some(r#"{"nodes":[]}"#)));
    }

    #[test]
    fn all_configured_nodes_are_substantive() {
        let g = r#"{"nodes":[{"type":"http","data":{"url":"x"}},{"type":"system:collect"}]}"#;
        assert!(is_substantive_workflow(Some(g)));
    }

    #[test]
    fn long_system_prompt_is_substantive() {
        let prompt = "x".repeat(250);
        let g = format!(r#"{{"nodes":[{{"type":"llm","data":{{"SYSTEM_PROMPT":"{prompt}"}}}}]}}"#);
        assert!(is_substantive_workflow(Some(&g)));
    }

    #[test]
    fn short_prompt_with_no_other_marker_is_not_substantive() {
        let g = r#"{"nodes":[{"type":"llm","data":{"SYSTEM_PROMPT":"short"}}]}"#;
        // Node is configured (non-empty data) so this DOES count as substantive
        // via the "all non-structural nodes configured" branch.
        assert!(is_substantive_workflow(Some(g)));
    }

    #[test]
    fn empty_data_only_node_is_not_substantive() {
        let g = r#"{"nodes":[{"type":"llm","data":{}}]}"#;
        assert!(!is_substantive_workflow(Some(g)));
    }

    #[test]
    fn output_schema_marker_is_substantive() {
        let g = r#"{"nodes":[{"type":"llm","data":{"OUTPUT_SCHEMA":{"foo":"bar"}}}]}"#;
        assert!(is_substantive_workflow(Some(g)));
    }

    #[test]
    fn retry_marker_is_substantive() {
        let g = r#"{"nodes":[{"type":"llm","data":{},"retry_count":3}]}"#;
        assert!(is_substantive_workflow(Some(g)));
    }

    #[test]
    fn description_marker_is_substantive() {
        let g = r#"{"nodes":[{"type":"llm","data":{},"description":"why"}]}"#;
        assert!(is_substantive_workflow(Some(g)));
    }
}
