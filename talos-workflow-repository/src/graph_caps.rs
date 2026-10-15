//! The per-node and workflow caps, checked where a graph is WRITTEN.
//!
//! `talos_workflow_types::validate_graph_timeouts` is the one rule for what a
//! stored graph may ask of the engine: a workflow wall clock of 1 to 3600 s,
//! per-node `timeout_secs` / `retry_count` / `retry_backoff_ms`, repeat-loop
//! counts, route counts and expression lengths. The engine reads those
//! values straight from the stored graph and does not clamp them again.
//!
//! Until 2026-10-15 the rule was called by the HANDLERS that remembered to:
//! `save_graph_json`, `create_workflow`, the two imports and the GraphQL
//! mutations did; `duplicate_workflow` and `promote_workflow` did not, and
//! stored a node with `timeout_secs: 86400` or `retry_count: 4000000000`
//! (security review 2026-10-14, G-11). It now also sits here, in front of
//! every statement that writes `workflows.graph_json`, beside the
//! action-link targets rule: a tool cannot reach the column without passing
//! it, and a tool added later inherits it. `scripts/check-graph-writers.py`
//! refuses a statement whose function has not called [`refuse_over_cap_graph`]
//! first.
//!
//! A handler may still run the same rule earlier for its own message; the
//! words are the rule's either way. A refusal travels as a typed error inside
//! `anyhow` ([`GraphCapsRefusal`]); a caller that can show it reads it with
//! [`graph_caps_refusal`] (or every graph-write refusal at once with
//! [`crate::graph_write_refusal`]), and one that does not still refuses.

use anyhow::Result;

/// A write that would store a graph over a cap. `Display` is the rule's own
/// sentence, which names the node and the field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphCapsRefusal(pub String);

impl std::fmt::Display for GraphCapsRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for GraphCapsRefusal {}

/// Refuse `graph_json` when it is over a cap
/// (`talos_workflow_types::validate_graph_timeouts`). Pure: no database read.
/// Text that is not JSON passes, as it does in the rule: the engine cannot
/// load it, and its parse error is the better message.
///
/// # Errors
/// [`GraphCapsRefusal`], inside `anyhow`.
pub fn refuse_over_cap_graph(graph_json: &str) -> Result<()> {
    talos_workflow_types::validate_graph_timeouts(graph_json)
        .map_err(|msg| anyhow::Error::new(GraphCapsRefusal(msg)))?;
    // The node and edge counts, here too (security review 2026-10-14, I-6):
    // a writer that skips `validate_graph_structure` (an import, a
    // duplicate, add-node one at a time) cannot store a graph the engine will
    // not load.
    if let Ok(graph) = serde_json::from_str::<serde_json::Value>(graph_json) {
        let count = |key: &str| {
            graph
                .get(key)
                .and_then(|v| v.as_array())
                .map_or(0, Vec::len)
        };
        if let Some(refusal) = talos_workflow_engine_core::graph_limits::graph_size_refusal(
            count("nodes"),
            count("edges"),
        ) {
            return Err(anyhow::Error::new(GraphCapsRefusal(refusal)));
        }
    }
    Ok(())
}

/// The refusal a graph write failed with, when it failed on a cap.
#[must_use]
pub fn graph_caps_refusal(error: &anyhow::Error) -> Option<&GraphCapsRefusal> {
    error.downcast_ref::<GraphCapsRefusal>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_over_cap_node_is_a_typed_refusal_with_the_rules_words() {
        let graph = serde_json::json!({ "nodes": [
            { "id": "send", "type": "x", "data": { "timeout_secs": 86_400 } }
        ]})
        .to_string();
        let error = refuse_over_cap_graph(&graph).unwrap_err();
        let refusal = graph_caps_refusal(&error).expect("typed refusal");
        assert_eq!(
            refusal.0,
            talos_workflow_types::validate_graph_timeouts(&graph).unwrap_err()
        );
        assert!(refusal.0.contains("'send'"), "{refusal}");
        assert!(graph_caps_refusal(&anyhow::anyhow!("connection reset")).is_none());
    }

    /// I-6: a graph over the node or edge count is refused here, with the
    /// sentence `create_workflow` uses.
    #[test]
    fn an_over_size_graph_is_refused_at_the_write() {
        let nodes: Vec<_> = (0..=talos_workflow_engine_core::graph_limits::MAX_GRAPH_NODES)
            .map(|i| serde_json::json!({ "id": format!("n{i}"), "type": "x", "data": {} }))
            .collect();
        let graph = serde_json::json!({ "nodes": nodes, "edges": [] }).to_string();
        let error = refuse_over_cap_graph(&graph).unwrap_err();
        assert_eq!(
            graph_caps_refusal(&error).expect("typed").0,
            talos_workflow_engine_core::graph_limits::graph_size_refusal(
                talos_workflow_engine_core::graph_limits::MAX_GRAPH_NODES + 1,
                0
            )
            .unwrap()
        );
    }

    #[test]
    fn a_graph_within_the_caps_and_text_that_is_not_json_pass() {
        assert!(refuse_over_cap_graph(r#"{"nodes":[{"id":"a","retry_count":3}]}"#).is_ok());
        assert!(refuse_over_cap_graph("{not json").is_ok());
    }
}
