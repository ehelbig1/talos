//! Per-run workflow state.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;

/// Mutable state that accumulates as a workflow runs.
///
/// The executor owns one `WorkflowContext` per run. Each completed node's
/// output is recorded in `results` keyed by node id, so downstream nodes
/// can gather inputs from their parents.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WorkflowContext {
    /// Mapping from a node's UUID to its output payload.
    pub results: HashMap<Uuid, JsonValue>,
    /// Whether the workflow is paused at a `Wait` node.
    pub waiting: bool,
    /// OpenTelemetry trace ID for distributed-tracing correlation.
    pub trace_id: Option<String>,
    /// Per-node execution timing: node label -> duration in milliseconds.
    pub node_timings: HashMap<String, u64>,
}
