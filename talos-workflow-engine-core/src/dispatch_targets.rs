//! Which workflows an `expression_dispatch` node may start: the author's
//! declared set.
//!
//! An `expression_dispatch` node (kind `dispatch`) evaluates a Rhai
//! expression against its input and runs the workflow the result names, by
//! UUID or by name. The documented idiom is `inputs.route`, so whoever
//! controls that field (a webhook caller, text that reached an upstream
//! module) chose which of the owner's workflows ran — any of them (security
//! review 2026-10-14, G-7). Tenancy held: the target is resolved and loaded
//! under the running user.
//!
//! The GRAPH AUTHOR now says which workflows the node may start, as
//! `action_links` and `llm_dispatch` already do: `data.targets`, a list of
//! workflow UUIDs. When it is declared, the workflow the expression resolves
//! to must be in it, or the node fails (and the refusal is counted). When it
//! is NOT declared the node keeps its old behaviour (any of the owner's
//! workflows); that is the legacy reading, and is to become a validation
//! warning.
//!
//! Like `action_links`' `targets`, the rule is read two ways:
//!
//! * **At a WRITE**, strictly ([`check_dispatch_targets`]): a list of 1 to
//!   [`MAX_DISPATCH_TARGETS`] workflow UUIDs; whether each is the owner's is
//!   asked by `talos_workflow_repository::action_link_targets` in front of
//!   every statement that writes a graph.
//! * **By the ENGINE**, leniently but closed ([`parse_dispatch_targets`]):
//!   absent is the legacy "undeclared"; present but unreadable admits
//!   nothing, so a hand-edited list cannot widen what the node may start.

use std::collections::{BTreeSet, HashSet};

use serde_json::Value as JsonValue;
use uuid::Uuid;

use crate::action_links::{graph_nodes, node_id_shown};

/// Most workflows one `expression_dispatch` node may declare.
pub const MAX_DISPATCH_TARGETS: usize = 32;

/// The configuration key the declared set lives under, in the node's `data`.
pub const DISPATCH_TARGETS_KEY: &str = "targets";

/// Whether the engine may read this graph node as an `expression_dispatch`
/// node: the loader takes the kind from `kind`, or from a `system:` `type`.
/// Either spelling is held to the rule.
#[must_use]
pub fn is_expression_dispatch_node(node: &JsonValue) -> bool {
    node.get("kind").and_then(JsonValue::as_str) == Some("dispatch")
        || node.get("type").and_then(JsonValue::as_str) == Some("system:dispatch")
}

/// The engine's reading of a node's `targets`.
///
/// * `None` — not declared (absent or `null`): the legacy behaviour, any of
///   the owner's workflows.
/// * `Some(set)` — declared. The UUID entries of a list, at most
///   [`MAX_DISPATCH_TARGETS`] of them. A value that is not a list, or a list
///   with no UUID in it, is `Some` of an EMPTY set: a declaration the engine
///   cannot read admits nothing rather than falling back to "anything".
#[must_use]
pub fn parse_dispatch_targets(raw: Option<&JsonValue>) -> Option<Vec<Uuid>> {
    let raw = raw?;
    if raw.is_null() {
        return None;
    }
    let mut set = BTreeSet::new();
    if let Some(entries) = raw.as_array() {
        for entry in entries {
            if set.len() >= MAX_DISPATCH_TARGETS {
                break;
            }
            if let Some(id) = entry.as_str().and_then(|s| Uuid::parse_str(s).ok()) {
                set.insert(id);
            }
        }
    }
    Some(set.into_iter().collect())
}

/// Whether a node whose declared set is `declared` may start `resolved`.
/// An undeclared set admits every workflow the resolver found for the
/// running user (the legacy behaviour).
#[must_use]
pub fn dispatch_target_admitted(declared: Option<&[Uuid]>, resolved: Uuid) -> bool {
    declared.is_none_or(|set| set.contains(&resolved))
}

/// What is wrong with one `expression_dispatch` node's `targets` as WRITTEN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchTargetsFault {
    /// `targets` is given but is not a list.
    NotAList,
    /// Fewer than one or more than [`MAX_DISPATCH_TARGETS`] entries.
    Count(usize),
    /// The entry at this position is not a workflow UUID.
    NotAWorkflowId(usize),
    /// The workflow does not exist or is not the owner's. ONE answer for
    /// both: a refusal never says whether another user's workflow exists.
    NotAccessible {
        /// The id as the caller wrote it.
        workflow_id: Uuid,
    },
}

impl std::fmt::Display for DispatchTargetsFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAList => write!(
                f,
                "'targets' must be a list of workflow UUIDs (the workflows this node may start)"
            ),
            Self::Count(got) => write!(
                f,
                "'targets' must name 1 to {MAX_DISPATCH_TARGETS} workflows; got {got}"
            ),
            Self::NotAWorkflowId(at) => write!(f, "'targets'[{at}] must be a workflow UUID"),
            Self::NotAccessible { workflow_id } => write!(
                f,
                "Target workflow {workflow_id} not found or not accessible"
            ),
        }
    }
}

/// The strict reading of a `targets` value, for a WRITE. `Ok(None)` when it
/// is not declared (absent or `null`).
///
/// # Errors
/// The first fault, in list order.
pub fn check_dispatch_targets(
    raw: Option<&JsonValue>,
) -> Result<Option<Vec<Uuid>>, DispatchTargetsFault> {
    let Some(raw) = raw.filter(|v| !v.is_null()) else {
        return Ok(None);
    };
    let Some(entries) = raw.as_array() else {
        return Err(DispatchTargetsFault::NotAList);
    };
    if entries.is_empty() || entries.len() > MAX_DISPATCH_TARGETS {
        return Err(DispatchTargetsFault::Count(entries.len()));
    }
    let mut set = BTreeSet::new();
    for (at, entry) in entries.iter().enumerate() {
        let Some(id) = entry.as_str().and_then(|s| Uuid::parse_str(s).ok()) else {
            return Err(DispatchTargetsFault::NotAWorkflowId(at));
        };
        set.insert(id);
    }
    Ok(Some(set.into_iter().collect()))
}

/// A write that would store an `expression_dispatch` node the rule refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchTargetsRefusal {
    /// The node's id (bounded and printable).
    pub node: String,
    /// What is wrong.
    pub fault: DispatchTargetsFault,
}

impl std::fmt::Display for DispatchTargetsRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Expression-dispatch node '{}': {}",
            self.node, self.fault
        )
    }
}

impl std::error::Error for DispatchTargetsRefusal {}

/// One `expression_dispatch` node's declared, checked targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeDispatchTargets {
    /// The node's id (bounded and printable).
    pub node: String,
    /// The workflows it may start.
    pub targets: Vec<Uuid>,
}

/// Every `expression_dispatch` node in a graph that DECLARES targets, read
/// strictly. A node that declares none is not listed (the legacy reading).
///
/// # Errors
/// The first node (in graph order) whose `targets` breaks the rule.
pub fn dispatch_targets_in_graph(
    graph: &JsonValue,
) -> Result<Vec<NodeDispatchTargets>, DispatchTargetsRefusal> {
    let mut out = Vec::new();
    for node in graph_nodes(graph).filter(|n| is_expression_dispatch_node(n)) {
        let raw = node.get("data").and_then(|d| d.get(DISPATCH_TARGETS_KEY));
        match check_dispatch_targets(raw) {
            Ok(None) => {}
            Ok(Some(targets)) => out.push(NodeDispatchTargets {
                node: node_id_shown(node),
                targets,
            }),
            Err(fault) => {
                return Err(DispatchTargetsRefusal {
                    node: node_id_shown(node),
                    fault,
                })
            }
        }
    }
    Ok(out)
}

/// The workflows a STORED graph's `expression_dispatch` nodes declare, read
/// as the engine reads them. Used to tell what a write introduces from what
/// the workflow already held.
#[must_use]
pub fn stored_dispatch_target_ids(graph: &JsonValue) -> HashSet<Uuid> {
    graph_nodes(graph)
        .filter(|node| is_expression_dispatch_node(node))
        .filter_map(|node| {
            parse_dispatch_targets(node.get("data").and_then(|d| d.get(DISPATCH_TARGETS_KEY)))
        })
        .flatten()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    #[test]
    fn an_undeclared_set_is_the_legacy_reading_and_admits_any_resolved_workflow() {
        assert_eq!(parse_dispatch_targets(None), None);
        assert_eq!(parse_dispatch_targets(Some(&JsonValue::Null)), None);
        assert!(dispatch_target_admitted(None, id(7)));
    }

    #[test]
    fn a_declared_set_admits_only_its_members() {
        let raw = json!([id(1).to_string(), id(2).to_string()]);
        let declared = parse_dispatch_targets(Some(&raw)).expect("declared");
        assert!(dispatch_target_admitted(Some(&declared), id(1)));
        assert!(!dispatch_target_admitted(Some(&declared), id(3)));
    }

    #[test]
    fn a_declaration_the_engine_cannot_read_admits_nothing() {
        for raw in [
            json!("not a list"),
            json!({"a": id(1).to_string()}),
            json!([1, "x"]),
        ] {
            let declared = parse_dispatch_targets(Some(&raw)).expect("declared");
            assert!(declared.is_empty(), "{raw}");
            assert!(!dispatch_target_admitted(Some(&declared), id(1)), "{raw}");
        }
    }

    #[test]
    fn the_engine_reads_at_most_the_cap() {
        let raw = JsonValue::Array(
            (0..(MAX_DISPATCH_TARGETS as u128 + 5))
                .map(|n| json!(id(n + 1).to_string()))
                .collect(),
        );
        assert_eq!(
            parse_dispatch_targets(Some(&raw)).unwrap().len(),
            MAX_DISPATCH_TARGETS
        );
    }

    #[test]
    fn a_write_is_held_to_the_strict_form() {
        assert_eq!(check_dispatch_targets(None), Ok(None));
        assert_eq!(check_dispatch_targets(Some(&JsonValue::Null)), Ok(None));
        assert_eq!(
            check_dispatch_targets(Some(&json!("x"))),
            Err(DispatchTargetsFault::NotAList)
        );
        assert_eq!(
            check_dispatch_targets(Some(&json!([]))),
            Err(DispatchTargetsFault::Count(0))
        );
        assert_eq!(
            check_dispatch_targets(Some(&json!([id(1).to_string(), "nope"]))),
            Err(DispatchTargetsFault::NotAWorkflowId(1))
        );
        let too_many = JsonValue::Array(
            (0..=MAX_DISPATCH_TARGETS as u128)
                .map(|n| json!(id(n + 1).to_string()))
                .collect(),
        );
        assert_eq!(
            check_dispatch_targets(Some(&too_many)),
            Err(DispatchTargetsFault::Count(MAX_DISPATCH_TARGETS + 1))
        );
        assert_eq!(
            check_dispatch_targets(Some(&json!([id(2).to_string(), id(2).to_string()]))),
            Ok(Some(vec![id(2)]))
        );
    }

    #[test]
    fn a_graph_lists_only_dispatch_nodes_that_declare_and_names_the_bad_one() {
        let graph = json!({ "nodes": [
            { "id": "legacy", "kind": "dispatch", "data": { "dispatch_expression": "route" } },
            { "id": "declared", "type": "system:dispatch",
              "data": { "dispatch_expression": "route", "targets": [id(1).to_string()] } },
            { "id": "links", "kind": "action_links", "data": { "targets": [] } },
        ]});
        let found = dispatch_targets_in_graph(&graph).expect("valid");
        assert_eq!(
            found,
            vec![NodeDispatchTargets {
                node: "declared".into(),
                targets: vec![id(1)]
            }]
        );
        assert_eq!(stored_dispatch_target_ids(&graph), HashSet::from([id(1)]));

        let bad = json!({ "nodes": [
            { "id": "d", "kind": "dispatch", "data": { "targets": "x" } },
        ]});
        let refusal = dispatch_targets_in_graph(&bad).unwrap_err();
        assert_eq!(refusal.node, "d");
        assert_eq!(
            refusal.to_string(),
            "Expression-dispatch node 'd': 'targets' must be a list of workflow UUIDs (the \
             workflows this node may start)"
        );
    }
}
