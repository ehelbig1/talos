//! The child-run ledger's write path, as a value — RFC 0012 P2.
//!
//! P1 wrote the ledger from ONE place: the tail of
//! [`ParallelWorkflowEngine::execute_subworkflow_graph`], reading everything
//! it needed off `&self`. That covered the five node kinds whose dispatcher
//! routes through that chokepoint and was structurally blind to four others
//! (`dispatch`, `capability_dispatch`, `agent_loop`, `react_loop`), which
//! hydrate a child engine at a DIFFERENT site — measured, not assumed: every
//! `AdapterSet::into_engine_with_graph` call in the workspace was enumerated
//! and there are three.
//!
//! Two of those four run inside an `async move` that captures the adapter set
//! and NOT `self`, so `&self` is unavailable at the moment the child settles.
//! This module is the answer, and it keeps P1's invariant rather than trading
//! it away: [`ChildRunReporter`] is a small `Clone` value carrying everything
//! the write needs, built from `&self` once, and **the INSERT still happens in
//! exactly one function** — [`ChildRunReporter::record`]. Capturing a resolved
//! value before the loop is the house pattern here already (`sub_binding` in
//! `try_dispatch_agent_loop` does the same thing for the same reason).
//!
//! # Two rules P1 recorded and this must not drop
//!
//! 1. A ledger is never a routing dependency: `record` returns `()` and the
//!    recorder swallows its own failures.
//! 2. `status` is CLASSIFIED, never shape-assumed — [`classify_collapsed`] is
//!    check 77's shared classifier, the same one the reactor uses to decide
//!    the parent node's fate, so the ledger and the run cannot disagree about
//!    whether a child failed.

use std::sync::Arc;

use serde_json::Value as JsonValue;
use talos_workflow_engine_core::reserved_keys::output_reports_error;
use talos_workflow_engine_core::{
    ChildRunOrigin, ChildRunRecord, ChildRunRecorder, ChildRunStatus, OutputSanitizer,
};
use uuid::Uuid;

use crate::engine::ParallelWorkflowEngine;

/// Everything the ONE write site needs, detached from `&self`.
///
/// `Clone` and free of borrows so it can be moved into an `async move` — which
/// is the whole reason it exists. Cheap: three `Arc` bumps, a `String` and two
/// integers, built once per dispatch and never per iteration.
#[derive(Clone)]
pub(crate) struct ChildRunReporter {
    recorder: Option<Arc<dyn ChildRunRecorder>>,
    sanitizer: Option<Arc<dyn OutputSanitizer>>,
    /// `None` when this engine has no `workflow_id` — `parent_workflow_id` is
    /// NOT NULL and there is nothing honest to put there, so nothing is
    /// written. Same three-guard shape as `record_judge_score`.
    parent_workflow_id: Option<Uuid>,
    /// The graph-facing node id (`"n3"`, `"team_gather"`), resolved from the
    /// engine's own label map so that mapping keeps one home.
    parent_node_label: String,
    /// The child ran one level deeper than this engine.
    depth: i16,
    origin: ChildRunOrigin,
}

/// How a settled child ended, and what to say about it.
///
/// One type so every caller answers the same two questions, and so a new
/// dispatch site cannot invent a third answer.
pub(crate) struct ChildRunOutcome {
    pub status: ChildRunStatus,
    /// Raw error text. Redacted and capped by the writer, never by the caller
    /// — the cap is not a redaction and neither is the caller's business.
    pub error: Option<String>,
}

/// Classify a child's COLLAPSED output.
///
/// check 77's classifier and nothing else: only absent / `null` / `false` /
/// `""` mean success. A module (or a custom dispatcher, or an LLM) can author
/// `__error` and `.as_bool()` reads every non-boolean value as a clean run.
pub(crate) fn classify_collapsed(collapsed: &JsonValue) -> ChildRunOutcome {
    if output_reports_error(collapsed) {
        ChildRunOutcome {
            status: ChildRunStatus::Failed,
            error: collapsed
                .get("error_message")
                .and_then(JsonValue::as_str)
                .map(ToString::to_string),
        }
    } else {
        ChildRunOutcome {
            status: ChildRunStatus::Completed,
            error: None,
        }
    }
}

impl ParallelWorkflowEngine {
    /// Build the reporter for one dispatch.
    ///
    /// `node_id` is the parent's engine node UUID; the graph-facing label is
    /// resolved HERE so the mapping has one home and so the closure that
    /// eventually calls `record` needs no label map of its own.
    pub(crate) fn child_run_reporter(&self, origin: ChildRunOrigin) -> ChildRunReporter {
        let parent_node_label = match origin {
            ChildRunOrigin::Node { node_id, .. } => self
                .node_labels
                .get(&node_id)
                .cloned()
                .unwrap_or_else(|| node_id.to_string()),
            ChildRunOrigin::Untracked => String::new(),
        };
        ChildRunReporter {
            recorder: self.child_run_recorder.clone(),
            sanitizer: self.output_sanitizer.clone(),
            parent_workflow_id: self.workflow_id,
            parent_node_label,
            depth: i16::try_from(self.current_subflow_depth.saturating_add(1)).unwrap_or(i16::MAX),
            origin,
        }
    }
}

impl ChildRunReporter {
    /// Persist one child run. **THE** write site for the whole ledger.
    ///
    /// Silent no-op with no recorder, on an `Untracked` origin (the
    /// `test_subworkflow_contract` probe, a one-off embedder call), or with no
    /// `workflow_id`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn record(
        &self,
        child_workflow_id: Uuid,
        user_id: Uuid,
        child_actor_id: Option<Uuid>,
        started_at_unix_ms: i64,
        duration_ms: i64,
        outcome: ChildRunOutcome,
    ) {
        let Some(recorder) = self.recorder.as_ref() else {
            return;
        };
        let ChildRunOrigin::Node {
            execution_id, kind, ..
        } = self.origin
        else {
            return;
        };
        let Some(parent_workflow_id) = self.parent_workflow_id else {
            return;
        };
        // Redaction. On the `Ok` branch this is defence in depth —
        // `run_scheduler_loop` DLP-scrubs the whole results map on its way out
        // — but on an engine error string it is the ONLY pass, which is why it
        // is applied on every arm rather than only where a mutation would be
        // caught.
        let error_class = outcome.error.map(|e| {
            self.sanitizer
                .as_ref()
                .map_or_else(|| e.clone(), |s| s.redact_str(&e))
        });
        recorder
            .record(ChildRunRecord {
                parent_execution_id: execution_id,
                parent_workflow_id,
                parent_node_id: self.parent_node_label.clone(),
                dispatch_kind: kind,
                child_workflow_id,
                user_id,
                actor_id: child_actor_id,
                depth: self.depth,
                started_at_unix_ms,
                duration_ms,
                status: outcome.status,
                error_class,
            })
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_string_error_flag_is_a_failed_child() {
        // check 77: `.as_bool()` reads this as a CLEAN run, which is exactly
        // the disagreement between the ledger and the run this classifier
        // exists to prevent.
        let out = classify_collapsed(&serde_json::json!({
            "__error": "upstream 502",
            "error_message": "upstream 502",
        }));
        assert_eq!(out.status, ChildRunStatus::Failed);
        assert_eq!(out.error.as_deref(), Some("upstream 502"));
    }

    #[test]
    fn the_success_envelope_shapes_are_completed() {
        for v in [
            serde_json::json!({}),
            serde_json::json!({"__error": null}),
            serde_json::json!({"__error": false}),
            serde_json::json!({"__error": ""}),
            serde_json::json!({"result": 1}),
        ] {
            assert_eq!(
                classify_collapsed(&v).status,
                ChildRunStatus::Completed,
                "{v}"
            );
        }
    }
}
