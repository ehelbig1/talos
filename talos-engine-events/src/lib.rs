use async_graphql::{Enum, SimpleObject};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use uuid::Uuid;

#[derive(Enum, Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum ExecutionStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Skipped,
    Waiting,
    /// Workflow has finished and the final output is available.
    /// Used by streaming consumers to receive the final result.
    OutputReady,
}

#[derive(SimpleObject, Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionEvent {
    pub execution_id: Uuid,
    pub node_id: Option<Uuid>,
    pub status: ExecutionStatus,
    pub log_message: Option<String>,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub iteration_index: Option<u32>,
    pub iteration_total: Option<u32>,
    /// Wall-clock duration in ms from node_started to this event. Present on completion events.
    #[serde(default)]
    pub duration_ms: Option<i64>,
    /// Final output JSON. Only populated on `OutputReady` events for streaming consumers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<serde_json::Value>,
}

impl ExecutionEvent {
    /// Create a new event without output data (the common case).
    pub fn new(execution_id: Uuid, node_id: Option<Uuid>, status: ExecutionStatus) -> Self {
        Self {
            execution_id,
            node_id,
            status,
            log_message: None,
            trace_id: None,
            span_id: None,
            iteration_index: None,
            iteration_total: None,
            duration_ms: None,
            output: None,
        }
    }
}

#[derive(SimpleObject, Clone, Debug, Serialize, Deserialize)]
pub struct DlqEvent {
    pub id: Uuid,
    pub workflow_id: Option<Uuid>,
    pub execution_id: Option<Uuid>,
    pub node_id: Option<Uuid>,
    pub error_message: Option<String>,
    pub payload: Option<String>,
    pub created_at: String,
    pub replayed_at: Option<String>,
    /// M T6-1: workflow owner. Stamped at emit time so the
    /// subscription filter doesn't need a per-event DB lookup. None
    /// when the trigger has been deleted (`webhook_triggers.workflow_id`
    /// is `ON DELETE SET NULL`) — the subscription treats None as
    /// platform-admin-only-visible.
    #[serde(default)]
    pub user_id: Option<Uuid>,
    /// M T6-1: workflow's organisation. Same emit-time stamp.
    /// Subscribers gated to org membership view events with
    /// matching `org_id`.
    #[serde(default)]
    pub org_id: Option<Uuid>,
}

#[derive(SimpleObject, Clone, Debug, Serialize, Deserialize)]
pub struct WorkflowExecutionEvent {
    pub workflow_id: Uuid,
    pub execution_id: Uuid,
    pub user_id: Uuid,
    pub status: String,
    pub started_at: String,
    pub error_message: Option<String>,
}

#[derive(SimpleObject, Clone, Debug, Serialize, Deserialize)]
pub struct CompilationEvent {
    pub job_id: Uuid,
    pub user_id: Uuid,
    pub status: String, // "starting", "scaffolding", "auditing", "building", "success", "failed"
    pub message: Option<String>,
    pub progress: Option<f32>, // 0.0 to 1.0
}

pub type ExecutionEventSender = broadcast::Sender<ExecutionEvent>;
pub type DlqEventSender = broadcast::Sender<DlqEvent>;
pub type WorkflowExecutionSender = broadcast::Sender<WorkflowExecutionEvent>;
pub type CompilationEventSender = broadcast::Sender<CompilationEvent>;
