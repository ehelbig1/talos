//! The structural checks every writer of a WHOLE graph runs, and the
//! authoring-time Rhai parse they share.
//!
//! `create_workflow` built its graph from parts and checked each part (node
//! ids, counts, acyclicity, a `skip_condition` that parses). The writers that
//! take a graph whole — `import_workflow`, `import_yaml_workflow`, GraphQL
//! `createWorkflow` / `updateWorkflow` — and the two that copy one with
//! changes (`duplicate_workflow`, `promote_workflow`) ran none of it
//! (security review 2026-10-14, G-26 / G-11). [`validate_graph_structure`]
//! is the one function they all call, on the graph as it will be stored.
//!
//! A `skip_condition` is reported, not refused, by the function: it is the
//! platform's one FAIL-OPEN expression, and the caller decides. An authoring
//! path refuses an unparseable one; an import WARNS, because refusing an
//! expression that is already live in an export would make an existing
//! workflow unrestorable (the stance `create_workflow`'s comments record).

use serde_json::Value;
use std::collections::HashSet;

use talos_workflow_engine_core::graph_limits::graph_size_refusal;

// Thread-local Rhai validation engine — created once per thread, reused for syntax checks.
// `rhai::Engine` contains `Rc` and is not `Send`; `thread_local!` avoids that constraint.
//
// COMPILE-ONLY, and deliberately NOT built by `talos_rhai_sandbox::sandboxed_engine`
// (the builder every EVALUATING engine must come from — lint check 63). Two
// independent reasons this engine cannot leak to stdout, either of which
// would be sufficient:
//   1. `new_raw()`, not `new()`. `Engine::new()` is what installs the
//      `println!`-backed `print`/`debug` handlers; `new_raw()` leaves both
//      as `None`, and rhai's dispatch site is `if let Some(ref print) =
//      self.print` — a `None` handler emits nothing and still yields unit.
//      `new_raw()` also registers no StandardPackage at all.
//   2. Nothing here evaluates. The only method called on this engine is
//      `Engine::compile` (see `validate_rhai_expression` below), which
//      parses to AST and never dispatches a function call, so `print`
//      cannot fire regardless of the handler.
// A dry-run that DOES evaluate (`dry_run_retry_condition`) deliberately
// routes to `talos_engine::rhai_helpers::evaluate_condition_with_error`,
// i.e. the production sandbox, rather than evaluating on this engine.
//
// DO NOT add an `eval` / `run` / `call_fn` / `eval_ast` call on this engine.
// Reason 2 above is what makes the exemption sound, and check 63 exempts
// `new_raw()` by construction, so it CANNOT catch such an addition. Nor is
// stdout the only exposure: `Engine::RAW` starts from `Limits::new()`, whose
// `num_operations` is `None` — no operation cap at all — so an eval here
// would let one authoring request spin a controller thread forever.
// Evaluating anything means `talos_rhai_sandbox::sandboxed_engine`.
std::thread_local! {
    static RHAI_VALIDATION_ENGINE: rhai::Engine = {
        let mut e = rhai::Engine::new_raw();
        e.disable_symbol("eval");
        e
    };
}

fn with_rhai_validation_engine<F, R>(f: F) -> R
where
    F: FnOnce(&rhai::Engine) -> R,
{
    RHAI_VALIDATION_ENGINE.with(f)
}

/// Compile-only Rhai syntax check used by every handler that accepts a
/// user-supplied expression (edge condition, retry condition, retry
/// delay, dispatch expression, skip condition, …).
///
/// On failure, returns a single user-facing error string that names the
/// `field_name` and includes the line/column from `rhai::ParseError`.
/// Callers map this to a caller-facing refusal verbatim — no error-class branching
/// needed.
pub fn validate_rhai_expression(field_name: &str, source: &str) -> Result<(), String> {
    with_rhai_validation_engine(|eng| eng.compile(source)).map_err(|e| {
        format!(
            "{} Rhai syntax error at line {}, column {}: {}",
            field_name,
            e.position().line().unwrap_or(0),
            e.position().position().unwrap_or(0),
            e
        )
    })?;
    Ok(())
}

/// The ONE authoring-time gate for a node's `skip_condition`, on every write
/// path that accepts one as a named parameter.
///
/// # Why a skip condition earns its own gate
///
/// `skip_condition` is the platform's only FAIL-OPEN expression. At runtime an
/// expression that cannot be evaluated defaults to `false`, and `false` on a
/// skip condition means "do not skip" — so a broken gate RUNS the node its
/// author wrote it to stop. A typo in `"dry_run == true"` fires the send, the
/// workflow reports `completed`, and the only evidence is a counter
/// (`talos_condition_eval_failures_total{kind="skip_condition"}`) plus a WARN.
/// Rejecting at authoring time is the cheapest possible catch: an expression
/// that cannot PARSE can never gate anything, so persisting it is never right.
///
/// # What this proves, and what it cannot
///
/// PARSE only. It cannot see the failure that actually bit — an unbound
/// variable (`input.dry_run` when the trigger key binds bare as `dry_run`)
/// parses perfectly and only fails at eval, against a context this function
/// does not have. `test_condition` with a representative payload is the tool
/// for that half, and `add_skip_condition` attaches
/// `dry_run_skip_condition`'s warning (in `talos-mcp-handlers`) pointing there.
///
/// Returns the TRIMMED expression so callers persist exactly what was
/// validated (MCP-235: whitespace slipped past the empty check, then Rhai
/// returned unit `()` at runtime — a non-bool, i.e. the fail-open case).
pub fn validate_skip_condition(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("skip_condition must be non-empty and non-whitespace".to_string());
    }
    if raw.len() > 2000 {
        return Err("skip_condition must be ≤ 2000 characters".to_string());
    }
    validate_rhai_expression("skip_condition", trimmed)?;
    Ok(trimmed.to_string())
}

/// The `skip_condition` the engine's graph loader would install for this
/// node: the first STRING among `data.skip_condition`, `skip_condition` and
/// `config.skip_condition`, read only when the node has `data` (the loader's
/// order, `engine_graph_load`).
#[must_use]
pub fn stored_skip_condition(node: &Value) -> Option<&str> {
    let data = node.get("data")?;
    data.get("skip_condition")
        .and_then(Value::as_str)
        .or_else(|| node.get("skip_condition").and_then(Value::as_str))
        .or_else(|| {
            node.get("config")
                .and_then(|c| c.get("skip_condition"))
                .and_then(Value::as_str)
        })
}

/// What [`validate_graph_structure`] found that it does not decide on.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GraphStructure {
    /// One sentence per node whose `skip_condition` does not parse, naming
    /// the node. An authoring caller refuses on the first; an import warns.
    pub skip_condition_faults: Vec<String>,
}

/// The structural checks a stored graph is held to, run on the graph as it
/// will be written: `nodes` and `edges` are arrays (or absent), at most
/// [`talos_workflow_engine_core::graph_limits::MAX_GRAPH_NODES`] nodes and
/// [`talos_workflow_engine_core::graph_limits::MAX_GRAPH_EDGES`] edges, every node id
/// usable ([`crate::validate_node_ids`]), no directed cycle among declared
/// nodes ([`crate::validate_acyclic`]). Each node's `skip_condition` is
/// parsed and reported in [`GraphStructure::skip_condition_faults`].
///
/// # Errors
/// The first structural fault, as the sentence a caller is shown.
pub fn validate_graph_structure(graph: &Value) -> Result<GraphStructure, String> {
    let empty: Vec<Value> = Vec::new();
    let nodes = match graph.get("nodes") {
        None | Some(Value::Null) => &empty,
        Some(Value::Array(nodes)) => nodes,
        Some(_) => return Err("graph_json.nodes must be an array".to_string()),
    };
    let edges = match graph.get("edges") {
        None | Some(Value::Null) => &empty,
        Some(Value::Array(edges)) => edges,
        Some(_) => return Err("graph_json.edges must be an array".to_string()),
    };
    if let Some(refusal) = graph_size_refusal(nodes.len(), edges.len()) {
        return Err(refusal);
    }
    crate::validate_node_ids(nodes)?;
    let node_ids: HashSet<&str> = nodes
        .iter()
        .filter_map(|n| n.get("id").and_then(Value::as_str))
        .collect();
    crate::validate_acyclic(edges, &node_ids)?;

    let mut structure = GraphStructure::default();
    for node in nodes {
        let Some(expr) = stored_skip_condition(node) else {
            continue;
        };
        if let Err(msg) = validate_skip_condition(expr) {
            let label = node
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("<unnamed node>");
            structure.skip_condition_faults.push(format!(
                "node '{}': {msg}",
                talos_text_util::bounded_preview(label, 64)
            ));
        }
    }
    Ok(structure)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use talos_workflow_engine_core::graph_limits::{MAX_GRAPH_EDGES, MAX_GRAPH_NODES};

    #[test]
    fn a_well_formed_graph_passes_with_nothing_to_report() {
        let graph = json!({
            "nodes": [
                { "id": "a", "type": "m", "data": { "skip_condition": "dry_run == true" } },
                { "id": "b", "type": "m", "data": {} },
            ],
            "edges": [ { "source": "a", "target": "b" } ],
        });
        assert_eq!(
            validate_graph_structure(&graph),
            Ok(GraphStructure::default())
        );
        assert_eq!(
            validate_graph_structure(&json!({})),
            Ok(GraphStructure::default())
        );
    }

    #[test]
    fn counts_are_held_to_the_one_home() {
        let nodes: Vec<Value> = (0..=MAX_GRAPH_NODES)
            .map(|i| json!({ "id": format!("n{i}"), "data": {} }))
            .collect();
        assert_eq!(
            validate_graph_structure(&json!({ "nodes": nodes })),
            Err(format!("Workflow exceeds {MAX_GRAPH_NODES} node limit"))
        );
        let edges: Vec<Value> = (0..=MAX_GRAPH_EDGES)
            .map(|_| json!({ "source": "a", "target": "b" }))
            .collect();
        assert_eq!(
            validate_graph_structure(&json!({ "nodes": [], "edges": edges })),
            Err(format!("Workflow exceeds {MAX_GRAPH_EDGES} edge limit"))
        );
    }

    #[test]
    fn a_cycle_a_bad_id_and_a_non_array_are_refused() {
        let cycle = json!({
            "nodes": [ { "id": "a" }, { "id": "b" } ],
            "edges": [ { "source": "a", "target": "b" }, { "source": "b", "target": "a" } ],
        });
        assert!(validate_graph_structure(&cycle)
            .unwrap_err()
            .contains("cycle"));
        let bad_id = json!({ "nodes": [ { "id": "a b" } ] });
        assert!(validate_graph_structure(&bad_id)
            .unwrap_err()
            .contains("may only contain"));
        assert_eq!(
            validate_graph_structure(&json!({ "nodes": {} })),
            Err("graph_json.nodes must be an array".to_string())
        );
    }

    #[test]
    fn an_unparseable_skip_condition_is_reported_not_refused() {
        let graph = json!({ "nodes": [
            { "id": "send", "data": { "skip_condition": "!!!(" } },
            { "id": "top", "skip_condition": "((", "data": {} },
            // No `data`: the loader installs nothing, so there is nothing to parse.
            { "id": "bare", "skip_condition": "((" },
        ]});
        let found = validate_graph_structure(&graph).expect("structure is fine");
        assert_eq!(found.skip_condition_faults.len(), 2, "{found:?}");
        assert!(found.skip_condition_faults[0].starts_with("node 'send': skip_condition"));
        assert!(found.skip_condition_faults[1].starts_with("node 'top': skip_condition"));
    }
}
