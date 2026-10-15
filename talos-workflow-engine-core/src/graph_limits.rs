//! How large a stored workflow graph may be: the one home for the node and
//! edge counts.
//!
//! The node count was the engine's own load cap
//! (`talos_workflow_engine::DEFAULT_MAX_WORKFLOW_NODES`, now this constant),
//! and `create_workflow` spelled both numbers as literals. A writer that
//! takes a whole graph (`talos_workflow_creation_helpers::validate_graph_structure`)
//! reads them here, so a graph a writer accepts is a graph the engine loads.

/// Most nodes a workflow graph may have. The engine refuses to load more.
pub const MAX_GRAPH_NODES: usize = 500;

/// Most edges a workflow graph may have.
pub const MAX_GRAPH_EDGES: usize = 2000;

/// The refusal for a graph of `nodes` nodes and `edges` edges, or `None` when
/// it is within both limits — the ONE sentence every writer answers with
/// (security review 2026-10-14, I-6: each surface had its own number, and a
/// 1 MiB YAML import of ten thousand nodes was stored).
#[must_use]
pub fn graph_size_refusal(nodes: usize, edges: usize) -> Option<String> {
    if nodes > MAX_GRAPH_NODES {
        return Some(format!("Workflow exceeds {MAX_GRAPH_NODES} node limit"));
    }
    if edges > MAX_GRAPH_EDGES {
        return Some(format!("Workflow exceeds {MAX_GRAPH_EDGES} edge limit"));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_limits_are_inclusive_and_say_which() {
        assert_eq!(graph_size_refusal(MAX_GRAPH_NODES, MAX_GRAPH_EDGES), None);
        assert!(graph_size_refusal(MAX_GRAPH_NODES + 1, 0)
            .unwrap()
            .contains("node"));
        assert!(graph_size_refusal(0, MAX_GRAPH_EDGES + 1)
            .unwrap()
            .contains("edge"));
    }
}
