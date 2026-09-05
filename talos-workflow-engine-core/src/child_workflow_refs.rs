//! Which workflows does this graph dispatch into?
//!
//! A parent node names its child workflow in the node's flat `data` object,
//! and [`SystemNodeKind`](crate::SystemNodeKind) reads **eight distinct key
//! names across eight node kinds** — one typed parser each in
//! `talos-workflow-engine`'s `graph_parser.rs`:
//!
//! | node kind | key(s) under `data` |
//! |---|---|
//! | `sub_workflow` | `sub_workflow_id` |
//! | `capability_dispatch` | `fallback_workflow_id` |
//! | `agent_loop`, `react_loop` | `body_workflow_id` |
//! | `judge` | `judge_workflow_id` |
//! | `ensemble` | `child_workflow_id`, `judge_workflow_id` |
//! | `reflective_retry` | `child_workflow_id`, `reflection_workflow_id` |
//! | `llm_dispatch` | `classifier_workflow_id`, `fallback_workflow_id`, **`routes.<label>`** |
//!
//! Seven of the eight share the `*_workflow_id` suffix, and that CONVENTION is
//! the contract here rather than a hardcoded list — a hardcoded list goes stale
//! the first time a ninth node kind lands, and the engine's own list lives
//! inside eight separate parser arms with no shared constant to import.
//!
//! **`llm_dispatch`'s `routes` is the exception, and it is the reason this
//! module exists rather than the suffix filter alone.** Route targets are the
//! VALUES of an arbitrarily-keyed object (`{"billing": "<uuid>", "support":
//! "<uuid>"}`), so no key-name rule can see them. The suffix-only predecessor
//! documented that as its residual gap; it is closed here.
//!
//! # Why this lives in the engine-core crate
//!
//! Because the readers do. The reference set answers a question three
//! unrelated surfaces ask — the risk assessor ("does this parent dispatch into
//! a workflow that fails a lot?"), the hygiene report ("is this workflow
//! dormant, or is it somebody's child?"), and validation — and a second copy
//! is the class this repository lints for. `talos-workflow-validation`
//! re-exports it under its historical name; nothing re-implements it.
//!
//! # What a graph scan can and cannot tell you
//!
//! It sees a STATIC reference. It does NOT see:
//!
//! * `capability_dispatch`, whose primary target is resolved at run time from
//!   `required_capabilities` — only its optional static `fallback_workflow_id`
//!   is visible here;
//! * `dispatch` (`DynamicDispatch`), which names an expression, not an id;
//! * a workflow invoked by an approval-gate or suspension
//!   `continuation_workflow_id` — that is a column on
//!   `workflow_approval_gates` / `workflow_suspensions`, not a graph key, and
//!   a continuation is dispatched as a REAL execution, so it leaves a
//!   `workflow_executions` row and needs no graph inference.

use uuid::Uuid;

/// Suffix shared by seven of the eight keys through which a node names another
/// workflow.
pub const CHILD_WORKFLOW_ID_SUFFIX: &str = "_workflow_id";

/// `data` keys whose VALUE is an object of `label -> workflow-id`, not a
/// workflow id itself. Today: `llm_dispatch`'s classification routes.
pub const CHILD_WORKFLOW_ID_MAP_KEYS: &[&str] = &["routes"];

/// Every workflow one node dispatches into, as `(data key, workflow id)`.
///
/// Route targets are reported under the key `"routes.<label>"` so a caller
/// rendering the key can say which branch of the dispatch it came from.
/// Malformed values and unrelated keys are skipped rather than reported as a
/// reference to a workflow that does not exist.
#[must_use]
pub fn collect_child_workflow_references(node: &serde_json::Value) -> Vec<(String, Uuid)> {
    let Some(data) = node.get("data").and_then(serde_json::Value::as_object) else {
        return Vec::new();
    };
    let mut out: Vec<(String, Uuid)> = data
        .iter()
        .filter(|(k, _)| k.ends_with(CHILD_WORKFLOW_ID_SUFFIX))
        .filter_map(|(k, v)| {
            let id = v.as_str()?.parse::<Uuid>().ok()?;
            Some((k.clone(), id))
        })
        .collect();

    for map_key in CHILD_WORKFLOW_ID_MAP_KEYS {
        let Some(routes) = data.get(*map_key).and_then(serde_json::Value::as_object) else {
            continue;
        };
        for (label, v) in routes {
            if let Some(id) = v.as_str().and_then(|s| s.parse::<Uuid>().ok()) {
                out.push((format!("{map_key}.{label}"), id));
            }
        }
    }
    out
}

/// Every workflow a whole graph dispatches into, deduplicated.
///
/// Takes the graph as TEXT because that is how `workflows.graph_json` is
/// stored. A graph that does not parse, or has no `nodes` array, yields an
/// EMPTY list — the caller learns nothing about that workflow's children, and
/// must not read the empty list as "this workflow has no children". Callers
/// that make a claim to an operator should distinguish the two; see
/// [`child_workflow_ids_checked`].
#[must_use]
pub fn child_workflow_ids(graph_json: &str) -> Vec<Uuid> {
    child_workflow_ids_checked(graph_json).unwrap_or_default()
}

/// [`child_workflow_ids`], but `None` when the graph could not be read at all.
///
/// `None` means *the graph did not parse, or carried no `nodes` array* —
/// unknown, not empty. `Some(vec![])` means *parsed, and names no child*.
/// A report that excludes a workflow from a DELETE recommendation because it
/// is somebody's child must not silently treat an unparseable parent as one
/// that references nothing.
#[must_use]
pub fn child_workflow_ids_checked(graph_json: &str) -> Option<Vec<Uuid>> {
    let graph: serde_json::Value = serde_json::from_str(graph_json).ok()?;
    let nodes = graph.get("nodes")?.as_array()?;
    let mut ids: Vec<Uuid> = nodes
        .iter()
        .flat_map(collect_child_workflow_references)
        .map(|(_, id)| id)
        .collect();
    ids.sort_unstable();
    ids.dedup();
    Some(ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const A: &str = "11111111-1111-4111-8111-111111111111";
    const B: &str = "22222222-2222-4222-8222-222222222222";

    /// Every SCALAR key `graph_parser.rs` dispatches a child through, as of
    /// 2026-09-05. Carried over from the validation crate's own pin.
    #[test]
    fn every_engine_scalar_key_is_collected() {
        for key in [
            "sub_workflow_id",
            "judge_workflow_id",
            "child_workflow_id",
            "body_workflow_id",
            "fallback_workflow_id",
            "reflection_workflow_id",
            "classifier_workflow_id",
        ] {
            let node = json!({"id": "n1", "data": { key: A }});
            let refs = collect_child_workflow_references(&node);
            assert_eq!(refs.len(), 1, "{key} must be collected");
            assert_eq!(refs[0].0, key);
            assert_eq!(refs[0].1.to_string(), A);
        }
    }

    /// The eighth site, and the one the suffix convention structurally cannot
    /// see: `llm_dispatch` route targets are object VALUES under arbitrary
    /// class labels.
    #[test]
    fn llm_dispatch_route_targets_are_collected() {
        let node = json!({"id": "n1", "data": {
            "classifier_workflow_id": A,
            "routes": { "billing": B, "support": A },
        }});
        let refs = collect_child_workflow_references(&node);
        assert_eq!(refs.len(), 3, "classifier + two routes");
        let mut keys: Vec<&str> = refs.iter().map(|(k, _)| k.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["classifier_workflow_id", "routes.billing", "routes.support"],
            "the route label must survive into the key so a caller can name the branch"
        );
    }

    #[test]
    fn multiple_references_on_one_node_are_all_collected() {
        let node = json!({"id": "n1", "data": {
            "child_workflow_id": A,
            "judge_workflow_id": B,
        }});
        assert_eq!(collect_child_workflow_references(&node).len(), 2);
    }

    #[test]
    fn malformed_and_unrelated_keys_are_ignored() {
        let node = json!({"id": "n1", "data": {
            "sub_workflow_id": "not-a-uuid",
            "workflow_name": "reporting",
            "max_fuel": 8_000_000,
            "routes": { "billing": "also-not-a-uuid", "n": 3 },
        }});
        assert!(collect_child_workflow_references(&node).is_empty());
        assert!(collect_child_workflow_references(&json!({"id": "n1"})).is_empty());
    }

    #[test]
    fn a_whole_graph_yields_deduplicated_ids() {
        let graph = json!({
            "nodes": [
                {"id": "a", "type": "system:judge", "data": {"judge_workflow_id": A}},
                {"id": "b", "type": "system:sub_workflow", "data": {"sub_workflow_id": B}},
                // the same judge again — a graph may reuse one child
                {"id": "c", "type": "system:judge", "data": {"judge_workflow_id": A}},
                {"id": "d", "type": "module", "data": {"module_id": "x"}},
            ],
            "edges": [],
        })
        .to_string();
        let ids = child_workflow_ids(&graph);
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&A.parse().unwrap()));
        assert!(ids.contains(&B.parse().unwrap()));
    }

    /// UNKNOWN and EMPTY are different answers, and a caller that suppresses a
    /// delete recommendation on the strength of "this is somebody's child"
    /// must be able to tell them apart.
    #[test]
    fn an_unreadable_graph_is_unknown_not_empty() {
        assert_eq!(child_workflow_ids_checked("{not json"), None);
        assert_eq!(child_workflow_ids_checked("{}"), None, "no nodes array");
        assert_eq!(
            child_workflow_ids_checked(r#"{"nodes": "x"}"#),
            None,
            "nodes present but not an array"
        );
        assert_eq!(
            child_workflow_ids_checked(r#"{"nodes": [], "edges": []}"#),
            Some(vec![]),
            "an empty graph parsed fine and names no child"
        );
    }
}
