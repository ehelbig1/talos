//! What a child run's nodes produced, kept for the parent run's stored output.
//!
//! A sub-workflow runs in-process and records no `workflow_executions` row
//! (RFC 0012). Its parent node receives the child's COLLAPSED output — with
//! one terminal node, that node's output and nothing else — so until
//! 2026-10-14 the outputs of every other node of a child, and everything a
//! grandchild did, were dropped when the child's engine was. Whether a
//! grandchild's notification node ran had to be inferred from what it wrote.
//!
//! This module keeps them, bounded, on the engine that dispatched the child.
//! The result collector writes them into the parent execution's stored output
//! under [`CHILD_RUNS_KEY`], beside `__node_timings__`: the same row, the same
//! encryption, the same retention, the same ownership check and the same DLP
//! pass as the parent's own node outputs. They are NOT put in any node's
//! output, so no downstream node ever receives them.
//!
//! The child-run ledger (`sub_workflow_runs`) still holds no payload. That
//! decision stands: this is the parent run's record, not the ledger's.
//!
//! # Shape
//!
//! ```json
//! { "assess": { "runs": [ {
//!       "workflow_id": "…", "kind": "sub_workflow", "status": "completed",
//!       "nodes": { "read": {…}, "brief": {…} },
//!       "child_runs": { "brief": { "runs": [ … ] } }
//!   } ], "runs_not_kept": 0 } }
//! ```
//!
//! Keyed by the dispatching node's label, as the stored node outputs are.
//! `child_runs` is the child engine's own record, so the nesting follows the
//! nesting of the runs.
//!
//! # Bounds
//!
//! * At most [`MAX_RUNS_PER_NODE`] runs per node (an ensemble or a reflective
//!   retry runs several); the newest are kept and `runs_not_kept` counts the
//!   rest.
//! * A run's `nodes` and `child_runs` count against [`CHILD_RUN_OUTPUTS_MAX_BYTES`]
//!   per engine. A run that would cross it keeps its metadata and says
//!   `outputs_omitted: {reason: "too_large", bytes}` instead — never a subset,
//!   so a reader cannot mistake a node that did not fit for one that did not
//!   run.
//! * The collector adds the record only when the whole stored output still
//!   fits the execution-payload ceiling, so keeping it can never cost a run
//!   the outputs it stored before.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use serde_json::{Map, Value as JsonValue};
use uuid::Uuid;

/// The reserved key the record is stored under in an execution's output.
pub const CHILD_RUNS_KEY: &str = "__child_runs__";

/// The most runs kept per dispatching node.
pub const MAX_RUNS_PER_NODE: usize = 8;

/// The most bytes (as JSON) of child-run outputs one engine keeps.
pub const CHILD_RUN_OUTPUTS_MAX_BYTES: usize = 1024 * 1024;

/// Where a child engine sits under the top-level execution: the execution's
/// id and the node labels leading down to it. A top-level engine has none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubflowLineage {
    /// The top-level execution.
    pub root_execution_id: Uuid,
    /// The labels of the dispatching nodes, outermost first.
    pub node_path: Vec<String>,
}

/// One child run, as kept.
pub(crate) struct KeptChildRun {
    pub workflow_id: Uuid,
    pub kind: &'static str,
    pub completed: bool,
    /// The child's node outputs, keyed by label.
    pub nodes: Map<String, JsonValue>,
    /// The child engine's own record of ITS children, if it kept any.
    pub child_runs: Option<JsonValue>,
}

#[derive(Default)]
struct NodeRuns {
    runs: VecDeque<(JsonValue, usize)>,
    not_kept: u64,
}

/// The record one engine keeps of the child runs its nodes dispatched.
#[derive(Default)]
pub(crate) struct ChildRunOutputs {
    by_node: BTreeMap<String, NodeRuns>,
    bytes: usize,
}

pub(crate) type ChildRunOutputsSlot = Arc<Mutex<ChildRunOutputs>>;

impl ChildRunOutputs {
    /// Keep one run of the child dispatched by node `label`.
    pub(crate) fn keep(&mut self, label: &str, run: KeptChildRun) {
        let mut entry = Map::new();
        entry.insert(
            "workflow_id".into(),
            JsonValue::String(run.workflow_id.to_string()),
        );
        entry.insert("kind".into(), JsonValue::String(run.kind.to_string()));
        entry.insert(
            "status".into(),
            JsonValue::String(if run.completed { "completed" } else { "failed" }.into()),
        );
        let mut payload = Map::new();
        payload.insert("nodes".into(), JsonValue::Object(run.nodes));
        if let Some(c) = run.child_runs {
            payload.insert("child_runs".into(), c);
        }
        let payload_bytes = serde_json::to_vec(&payload).map_or(usize::MAX, |b| b.len());
        // Make room in this node's list first, so the oldest run's bytes are
        // given back before the new run is measured against the bound.
        let node = self.by_node.entry(label.to_string()).or_default();
        while node.runs.len() >= MAX_RUNS_PER_NODE {
            if let Some((_, b)) = node.runs.pop_front() {
                self.bytes = self.bytes.saturating_sub(b);
            }
            node.not_kept = node.not_kept.saturating_add(1);
        }
        let kept_bytes = if self.bytes.saturating_add(payload_bytes) <= CHILD_RUN_OUTPUTS_MAX_BYTES
        {
            entry.extend(payload);
            payload_bytes
        } else {
            entry.insert(
                "outputs_omitted".into(),
                serde_json::json!({
                    "reason": "too_large",
                    "bytes": payload_bytes,
                    "limit_bytes": CHILD_RUN_OUTPUTS_MAX_BYTES,
                }),
            );
            0
        };
        self.bytes = self.bytes.saturating_add(kept_bytes);
        if let Some(node) = self.by_node.get_mut(label) {
            node.runs.push_back((JsonValue::Object(entry), kept_bytes));
        }
    }

    /// The record as stored, or `None` when no child run was kept.
    pub(crate) fn to_json(&self) -> Option<JsonValue> {
        if self.by_node.is_empty() {
            return None;
        }
        let mut out = Map::new();
        for (label, node) in &self.by_node {
            out.insert(
                label.clone(),
                serde_json::json!({
                    "runs": node.runs.iter().map(|(r, _)| r.clone()).collect::<Vec<_>>(),
                    "runs_not_kept": node.not_kept,
                }),
            );
        }
        Some(JsonValue::Object(out))
    }

    pub(crate) fn clear(&mut self) {
        self.by_node.clear();
        self.bytes = 0;
    }
}

/// Project a child engine's results map into its stored node outputs: keyed
/// by label, the synthetic trigger and skipped nodes dropped, each output
/// unwrapped — exactly as a top-level run's outputs are stored.
pub(crate) fn project_node_outputs(
    results: &std::collections::HashMap<Uuid, JsonValue>,
    labels: &std::collections::HashMap<Uuid, String>,
) -> Map<String, JsonValue> {
    let mut out = Map::new();
    for (nid, output) in results {
        if output
            .get("__skipped")
            .and_then(JsonValue::as_bool)
            .unwrap_or(false)
        {
            continue;
        }
        let label = labels.get(nid).cloned().unwrap_or_else(|| nid.to_string());
        if label == "__trigger__" {
            continue;
        }
        out.insert(
            label,
            crate::ParallelWorkflowEngine::unwrap_output(output).clone(),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(nodes: JsonValue) -> KeptChildRun {
        KeptChildRun {
            workflow_id: Uuid::nil(),
            kind: "sub_workflow",
            completed: true,
            nodes: nodes.as_object().cloned().unwrap_or_default(),
            child_runs: None,
        }
    }

    #[test]
    fn nothing_kept_is_no_record() {
        assert!(ChildRunOutputs::default().to_json().is_none());
    }

    #[test]
    fn a_kept_run_carries_every_node() {
        let mut k = ChildRunOutputs::default();
        k.keep(
            "assess",
            run(serde_json::json!({"a": {"x": 1}, "b": {"y": 2}})),
        );
        let j = k.to_json().unwrap();
        let r = &j["assess"]["runs"][0];
        assert_eq!(r["status"], "completed");
        assert_eq!(r["nodes"]["a"]["x"], 1);
        assert_eq!(r["nodes"]["b"]["y"], 2);
        assert_eq!(j["assess"]["runs_not_kept"], 0);
    }

    #[test]
    fn only_the_newest_runs_per_node_are_kept() {
        let mut k = ChildRunOutputs::default();
        for i in 0..(MAX_RUNS_PER_NODE + 3) {
            k.keep("loop", run(serde_json::json!({"n": {"i": i}})));
        }
        let j = k.to_json().unwrap();
        let runs = j["loop"]["runs"].as_array().unwrap();
        assert_eq!(runs.len(), MAX_RUNS_PER_NODE);
        assert_eq!(runs[0]["nodes"]["n"]["i"], 3);
        assert_eq!(j["loop"]["runs_not_kept"], 3);
    }

    #[test]
    fn a_run_over_the_byte_bound_keeps_its_metadata_and_says_so() {
        let mut k = ChildRunOutputs::default();
        let big = "x".repeat(CHILD_RUN_OUTPUTS_MAX_BYTES);
        k.keep("big", run(serde_json::json!({"n": big})));
        k.keep("small", run(serde_json::json!({"n": 1})));
        let j = k.to_json().unwrap();
        let r = &j["big"]["runs"][0];
        assert!(r.get("nodes").is_none(), "never a subset of a run's nodes");
        assert_eq!(r["outputs_omitted"]["reason"], "too_large");
        assert_eq!(r["status"], "completed");
        assert_eq!(j["small"]["runs"][0]["nodes"]["n"], 1);
    }

    #[test]
    fn evicted_runs_give_their_bytes_back() {
        let mut k = ChildRunOutputs::default();
        let chunk = "x".repeat(CHILD_RUN_OUTPUTS_MAX_BYTES / (MAX_RUNS_PER_NODE + 1));
        for _ in 0..(MAX_RUNS_PER_NODE * 4) {
            k.keep("loop", run(serde_json::json!({"n": chunk})));
        }
        let j = k.to_json().unwrap();
        let runs = j["loop"]["runs"].as_array().unwrap();
        assert!(
            runs.iter().all(|r| r.get("nodes").is_some()),
            "a steady loop under the bound keeps every kept run's outputs"
        );
    }
}
