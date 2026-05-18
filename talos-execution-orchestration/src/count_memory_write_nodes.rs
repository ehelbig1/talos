//! Pure helper for the unbound-actor warning at trigger time.
//!
//! Walks `graph_json` and counts nodes that declare a non-empty
//! `MEMORY_WRITE_KEY` config. The trigger orchestration uses this to
//! warn loudly when a workflow has memory-write nodes but no actor
//! is bound — every `__memory_write__` envelope from those nodes
//! would be silently dropped at execution time, so we surface the
//! gap before spending an LLM call on output that won't persist.
//!
//! Lifted from `talos-mcp-handlers/src/workflows.rs::count_memory_write_nodes`
//! verbatim — same `data` / `config` dual-shape detection, same
//! malformed-JSON safety (returns 0 instead of panicking).

pub fn count_memory_write_nodes(graph_json: &str) -> usize {
    let Ok(graph) = serde_json::from_str::<serde_json::Value>(graph_json) else {
        return 0;
    };
    let Some(nodes) = graph.get("nodes").and_then(|v| v.as_array()) else {
        return 0;
    };
    nodes
        .iter()
        .filter(|n| {
            // Workflows authored in the visual editor land in the
            // `data` shape; ones produced by the discovery-call
            // synthesiser land in `config`. Both forms appear in
            // production graphs, hence the dual lookup.
            let from_data = n
                .get("data")
                .and_then(|d| d.get("MEMORY_WRITE_KEY"))
                .and_then(|v| v.as_str())
                .map(|s| !s.is_empty())
                .unwrap_or(false);
            let from_config = n
                .get("config")
                .and_then(|d| d.get("MEMORY_WRITE_KEY"))
                .and_then(|v| v.as_str())
                .map(|s| !s.is_empty())
                .unwrap_or(false);
            from_data || from_config
        })
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_json_returns_zero() {
        assert_eq!(count_memory_write_nodes("{not json"), 0);
    }

    #[test]
    fn missing_nodes_array_returns_zero() {
        assert_eq!(count_memory_write_nodes(r#"{"edges": []}"#), 0);
    }

    #[test]
    fn empty_nodes_array_returns_zero() {
        assert_eq!(count_memory_write_nodes(r#"{"nodes": []}"#), 0);
    }

    #[test]
    fn data_shape_counted() {
        let g = r#"{
            "nodes": [
                {"id": "a", "data": {"MEMORY_WRITE_KEY": "k1"}},
                {"id": "b", "data": {}}
            ]
        }"#;
        assert_eq!(count_memory_write_nodes(g), 1);
    }

    #[test]
    fn config_shape_counted() {
        let g = r#"{
            "nodes": [
                {"id": "a", "config": {"MEMORY_WRITE_KEY": "k1"}},
                {"id": "b", "config": {"MEMORY_WRITE_KEY": ""}}
            ]
        }"#;
        // Empty string is falsy — not counted.
        assert_eq!(count_memory_write_nodes(g), 1);
    }

    #[test]
    fn either_shape_counts_once() {
        // A node with the key in BOTH shapes still counts once.
        let g = r#"{
            "nodes": [
                {"id": "a", "data": {"MEMORY_WRITE_KEY": "k"}, "config": {"MEMORY_WRITE_KEY": "k"}}
            ]
        }"#;
        assert_eq!(count_memory_write_nodes(g), 1);
    }

    #[test]
    fn mixed_graph() {
        let g = r#"{
            "nodes": [
                {"id": "a", "data": {"MEMORY_WRITE_KEY": "k1"}},
                {"id": "b", "config": {"MEMORY_WRITE_KEY": "k2"}},
                {"id": "c"}
            ]
        }"#;
        assert_eq!(count_memory_write_nodes(g), 2);
    }
}
