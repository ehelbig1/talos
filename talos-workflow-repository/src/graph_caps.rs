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
        // A node id beginning with `__` names the engine's own records (the
        // trigger root, `__child_runs__`, `__node_timings__`,
        // `__trigger_input__`): a node so named could stand in for one in
        // the stored output (security review 2026-10-15, G2-5). Refused at
        // every writer, here, in front of the statement.
        if let Some(id) = reserved_node_id(&graph) {
            return Err(anyhow::Error::new(GraphCapsRefusal(format!(
                "node id '{id}' begins with `__`, which names the engine's own records; \
                 rename the node"
            ))));
        }
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

/// The first node id in `graph` that begins with `__`, if any.
fn reserved_node_id(graph: &serde_json::Value) -> Option<&str> {
    graph
        .get("nodes")?
        .as_array()?
        .iter()
        .filter_map(|n| n.get("id").and_then(serde_json::Value::as_str))
        .find(|id| id.starts_with("__"))
}

/// Refuse a graph in which a node names the workflow being written as its
/// own child — `A → A`, through any child-workflow reference
/// (`talos_workflow_engine_core::child_workflow_refs`). Pure. Called in front
/// of every statement that UPDATEs a workflow's graph (an INSERT writes a new
/// id no node can name yet); `scripts/check-graph-writers.py` holds it there
/// (security review 2026-10-15, G2-2: the refusal lived in the `add_*_node`
/// tools only, so `update_node_config`, the imports and GraphQL stored a
/// self-reference that burned a run's whole child budget). A cycle through
/// OTHER workflows needs their graphs and is the validator's
/// (`sub_workflow_cycle_for_write`).
///
/// # Errors
/// [`GraphCapsRefusal`], inside `anyhow`.
pub fn refuse_self_reference(graph_json: &str, workflow_id: uuid::Uuid) -> Result<()> {
    let Ok(graph) = serde_json::from_str::<serde_json::Value>(graph_json) else {
        return Ok(());
    };
    let Some(nodes) = graph.get("nodes").and_then(serde_json::Value::as_array) else {
        return Ok(());
    };
    for node in nodes {
        for (key, child) in talos_workflow_engine_core::collect_child_workflow_references(node) {
            if child == workflow_id {
                let id = node
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("?");
                return Err(anyhow::Error::new(GraphCapsRefusal(format!(
                    "node '{id}' names this workflow as its own child (`{key}`), which would \
                     run it inside itself until the run's child budget is spent; point it at \
                     another workflow"
                ))));
            }
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
    fn a_node_id_beginning_with_two_underscores_is_refused() {
        for id in ["__child_runs__", "__node_timings__", "__x"] {
            let g = serde_json::json!({ "nodes": [{ "id": id, "type": "x" }], "edges": [] });
            let err = refuse_over_cap_graph(&g.to_string()).expect_err(id);
            assert!(graph_caps_refusal(&err).is_some(), "{id}");
        }
        let ok = serde_json::json!({ "nodes": [{ "id": "a_b", "type": "x" }], "edges": [] });
        assert!(refuse_over_cap_graph(&ok.to_string()).is_ok());
    }

    #[test]
    fn a_graph_naming_its_own_workflow_as_a_child_is_refused() {
        let me = uuid::Uuid::new_v4();
        let other = uuid::Uuid::new_v4();
        let graph = |child: uuid::Uuid| {
            serde_json::json!({ "nodes": [{ "id": "e", "type": "system:ensemble",
                "data": { "child_workflow_id": child.to_string() } }], "edges": [] })
            .to_string()
        };
        let err = refuse_self_reference(&graph(me), me).expect_err("self");
        assert!(graph_caps_refusal(&err).is_some());
        assert!(refuse_self_reference(&graph(other), me).is_ok());
        assert!(refuse_self_reference("not json", me).is_ok());
    }

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
