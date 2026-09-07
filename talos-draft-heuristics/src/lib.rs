//! Pure graph-JSON heuristics for classifying an unpublished DRAFT workflow.
//!
//! # Why this is a leaf crate
//!
//! Three crates with no edge between them ask the same question about the same
//! column, and two of them ACT on the answer:
//!
//! * `talos-hygiene-service` — `fix_all`'s auto-DELETE partition (M-I, 2026-05-06);
//! * `talos-advanced-repository` — `session_start`'s unattended auto-ARCHIVE sweep;
//! * `talos-session-brief-service` — `session_start`'s draft DISPLAY, whose
//!   substantive half is rendered as *"ready for `publish_version`"*.
//!
//! Until 2026-09-05 the predicate lived in `talos-hygiene-service`, whose own
//! doc comment claimed *"Both `session_start` … AND `get_platform_hygiene_report
//! fix_all` consult this helper so the two surfaces never disagree"* — and
//! `session_start` in fact carried an INLINE COPY of the same walk, while the
//! archive sweep consulted nothing at all. An ALL-sites claim is load-bearing
//! only if the sites are structurally unable to drift, which is why this is a
//! move into a leaf crate (`serde_json` and nothing else) rather than a third
//! copy — the same reasoning that produced `talos-child-workflow-refs`.
//! `talos-hygiene-service` re-exports both functions, so its existing import
//! paths keep resolving.

/// What a draft's `graph_json` says about the human who left it there.
///
/// Three-valued because the destructive paths need the third value.
/// `is_substantive_workflow` collapses [`Self::Unreadable`] into "not
/// substantive" — the shape every caller had before this split — but a sweep
/// that ARCHIVES or DELETES must not read *"I could not tell"* as *"nobody
/// shaped this"*. Same rule `talos-child-workflow-refs` applies to a parent
/// whose graph will not parse: UNKNOWN is not NO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DraftIntent {
    /// The graph carries a marker of authored intent. The right next step is
    /// `publish_version`, never auto-cleanup.
    Substantive,
    /// The graph parsed and carries no such marker: a scaffolding leftover as
    /// far as this predicate can see.
    Scaffolding,
    /// Absent, or not parseable as JSON at all. `workflows.graph_json` is
    /// `text NOT NULL`, so this is reachable — a `text` column can hold
    /// anything — and it is deliberately NOT folded into `Scaffolding`.
    Unreadable,
}

impl DraftIntent {
    /// True only for [`Self::Substantive`].
    #[must_use]
    pub fn is_substantive(self) -> bool {
        matches!(self, Self::Substantive)
    }

    /// True when an automated cleanup path must leave this draft alone —
    /// [`Self::Substantive`] (a human shaped it) or [`Self::Unreadable`]
    /// (nobody can say whether a human shaped it).
    #[must_use]
    pub fn blocks_automated_cleanup(self) -> bool {
        !matches!(self, Self::Scaffolding)
    }

    /// Operator-facing explanation, or `None` when the draft is genuinely
    /// scaffolding. Wording is deliberately the same shape `fix_all` already
    /// prints under `substantive_drafts_skipped` so one operator reading two
    /// surfaces sees one vocabulary.
    #[must_use]
    pub fn cleanup_block_reason(self) -> Option<&'static str> {
        match self {
            Self::Scaffolding => None,
            Self::Substantive => Some(
                "Has SYSTEM_PROMPT/OUTPUT_SCHEMA/retry/description markers — automated cleanup \
                  refused. Use publish_version, or archive it explicitly via archive_workflow.",
            ),
            Self::Unreadable => Some(
                "graph_json could not be read, so nothing here says whether a human shaped this \
                  draft — automated cleanup refused. Archive it explicitly via archive_workflow \
                  if it really is a leftover.",
            ),
        }
    }
}

/// Classify a draft's `graph_json`. THE one implementation — every
/// substantive-ness question in this workspace resolves here, including
/// [`is_substantive_workflow`], which is defined in terms of it.
#[must_use]
pub fn classify_draft_intent(graph_json: Option<&str>) -> DraftIntent {
    let Some(g) = graph_json else {
        return DraftIntent::Unreadable;
    };
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(g) else {
        return DraftIntent::Unreadable;
    };
    // A graph that parses but names no nodes is a genuine empty scaffold (the
    // `in_progress_drafts` case), NOT an unreadable one: the read succeeded
    // and the answer is "there is nothing here".
    let nodes = match parsed.get("nodes").and_then(|n| n.as_array()) {
        Some(n) if !n.is_empty() => n,
        _ => return DraftIntent::Scaffolding,
    };

    // Branch 1: all non-structural nodes are configured.
    if count_nodes_with_empty_data(nodes) == 0 {
        return DraftIntent::Substantive;
    }

    // Branch 2: any node has a thoughtful authored marker.
    let thoughtful = nodes.iter().any(|n| {
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
    });
    if thoughtful {
        DraftIntent::Substantive
    } else {
        DraftIntent::Scaffolding
    }
}

/// Substantive-draft predicate (M-I, 2026-05-06). Returns `true` iff the draft
/// has any marker of authored intent — meaning the right next step is
/// `publish_version`, NOT auto-cleanup.
///
/// "Substantive" means any one of:
///   * all non-structural nodes have non-empty `data` AND node_count > 0
///   * any node has `SYSTEM_PROMPT` > 200 chars
///   * any node has `OUTPUT_SCHEMA` configured
///   * any node has `retry_count` / `retry_condition` / `retry_delay_expression`
///   * any node has `description` / `skip_condition` / `continue_on_error` set
///
/// A thin two-valued view over [`classify_draft_intent`], byte-for-byte the
/// pre-2026-09-05 behaviour: `None`, unparseable JSON and an empty node list
/// all answer `false`. A caller driving a DESTRUCTIVE path should prefer the
/// classifier, whose [`DraftIntent::Unreadable`] arm those three collapse into
/// — `false` there means "delete it", and "I could not read the graph" is not
/// grounds to delete anything.
#[must_use]
pub fn is_substantive_workflow(graph_json: Option<&str>) -> bool {
    classify_draft_intent(graph_json).is_substantive()
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

#[cfg(test)]
mod classify_draft_intent_tests {
    use super::{classify_draft_intent, is_substantive_workflow, DraftIntent};

    /// The split the destructive paths need. `is_substantive_workflow` answers
    /// `false` for all three of these; only two of them mean "safe to archive".
    #[test]
    fn unreadable_is_not_scaffolding() {
        assert_eq!(classify_draft_intent(None), DraftIntent::Unreadable);
        assert_eq!(
            classify_draft_intent(Some("not json")),
            DraftIntent::Unreadable
        );
        // Parsed, but names nothing: a genuine empty scaffold.
        assert_eq!(classify_draft_intent(Some("{}")), DraftIntent::Scaffolding);
        assert_eq!(
            classify_draft_intent(Some(r#"{"nodes":[]}"#)),
            DraftIntent::Scaffolding
        );
        // …and every one of them is still "not substantive" to the old view,
        // so no existing caller changed behaviour.
        for g in [None, Some("not json"), Some("{}"), Some(r#"{"nodes":[]}"#)] {
            assert!(!is_substantive_workflow(g), "{g:?}");
        }
    }

    #[test]
    fn only_scaffolding_may_be_swept() {
        assert!(!DraftIntent::Scaffolding.blocks_automated_cleanup());
        assert!(DraftIntent::Substantive.blocks_automated_cleanup());
        assert!(DraftIntent::Unreadable.blocks_automated_cleanup());
        assert!(DraftIntent::Scaffolding.cleanup_block_reason().is_none());
        // A blocked draft must always be able to SAY why: a sweep that
        // silently declines to act is its own small misleading report.
        assert!(DraftIntent::Substantive.cleanup_block_reason().is_some());
        assert!(DraftIntent::Unreadable.cleanup_block_reason().is_some());
    }

    /// The two blocked arms must be distinguishable to an operator, not just
    /// to the type system — the reasons are what the response prints.
    #[test]
    fn the_two_block_reasons_are_different_text() {
        assert_ne!(
            DraftIntent::Substantive.cleanup_block_reason(),
            DraftIntent::Unreadable.cleanup_block_reason()
        );
    }

    #[test]
    fn a_bare_node_is_scaffolding_and_a_shaped_one_is_not() {
        assert_eq!(
            classify_draft_intent(Some(r#"{"nodes":[{"type":"m","data":{}}]}"#)),
            DraftIntent::Scaffolding
        );
        assert_eq!(
            classify_draft_intent(Some(
                r#"{"nodes":[{"type":"m","data":{},"retry_count":2}]}"#
            )),
            DraftIntent::Substantive
        );
    }
}
