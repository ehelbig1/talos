//! User-facing rendering of `talos_workflow_engine::WorkflowEngineError`.
//!
//! The engine's `Display` output is correct but generic ("graph load failed: …").
//! MCP callers are humans and agents who benefit from a concrete next action
//! — especially for `EmptyGraph` (the commonest mistake: "I created a
//! workflow and tried to run it"). This module centralises the mapping so
//! every call site that loads a graph reports the same message.
//!
//! Match on the typed variant, never the string body: per the engine's
//! documentation, only variants are stable.

use talos_workflow_engine::WorkflowEngineError;

/// Render a graph-load failure for an MCP caller. The returned string is
/// already fully-qualified (no extra prefix needed) and includes actionable
/// remediation when the variant supports one.
///
/// Prefer this over ad-hoc `format!("Failed to load graph: {}", e)` so that:
///   1. Empty-graph failures never leak the old "Workflow has no nodes"
///      message — they surface a specific hint pointing at
///      `add_node_to_workflow`.
///   2. Any future typed variant added to the engine (per the engine's
///      `#[non_exhaustive]` / promotion policy) can be mapped here exactly
///      once rather than in every caller.
pub fn render_graph_load_error(e: &WorkflowEngineError) -> String {
    match e {
        WorkflowEngineError::EmptyGraph => String::from(
            "Workflow has no nodes — cannot run an empty graph. \
             Add at least one node via add_node_to_workflow(workflow_id, node_id, module_id), \
             or install a catalog module first with install_module_from_catalog.",
        ),
        // Engine adds typed variants over time under a documented non-exhaustive
        // policy. The default keeps parity with previous controller output so
        // nothing regresses while new variants are awaiting explicit handling.
        other => format!("Failed to load graph: {}", other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_graph_returns_actionable_hint() {
        let msg = render_graph_load_error(&WorkflowEngineError::EmptyGraph);
        // Caller-relevant facts: no nodes + the two tools that fix it.
        assert!(msg.contains("no nodes"));
        assert!(msg.contains("add_node_to_workflow"));
        assert!(msg.contains("install_module_from_catalog"));
    }

    #[test]
    fn non_empty_graph_falls_through_to_engine_display() {
        // Build a non-EmptyGraph variant. `LoadGraph(String)` is the
        // catch-all the engine uses when no typed variant fits — exactly
        // the case the default arm preserves parity for.
        let err = WorkflowEngineError::LoadGraph("malformed json".to_string());
        let msg = render_graph_load_error(&err);
        assert!(msg.starts_with("Failed to load graph: "));
        assert!(msg.contains("malformed json"));
    }

    #[test]
    fn empty_graph_does_not_leak_engine_display() {
        // Regression guard: if a future change accidentally falls through
        // for EmptyGraph, the engine's Display ("workflow graph has no
        // nodes") would replace our hint. Catch that.
        let msg = render_graph_load_error(&WorkflowEngineError::EmptyGraph);
        assert!(
            !msg.starts_with("Failed to load graph: "),
            "EmptyGraph must not fall through to the generic engine Display"
        );
    }
}
