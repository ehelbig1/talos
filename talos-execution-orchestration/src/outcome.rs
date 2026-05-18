//! Result types returned from `ExecutionOrchestrationService` methods.
//!
//! `retry`, `replay`, `replay_with_input` return `ExecutionOutcome`
//! directly — they always dispatch (or fail with a typed error).
//! `trigger` returns `TriggerOutcome` so the dry-run validation path
//! can surface schema + errors without dispatching.

use serde_json::Value;
use uuid::Uuid;

/// Outcome of a successful trigger / replay / retry.
///
/// All four orchestration methods return this same shape — the variant
/// of operation is captured in `metadata.trigger_type`. `trace` is
/// `Some` only when the caller asked for synchronous-wait behaviour
/// (`TriggerInput::wait_ms = Some(_)`) and the execution reached a
/// terminal status before the timeout. Otherwise the caller polls
/// `get_execution_status` with the returned `execution_id`.
pub struct ExecutionOutcome {
    pub execution_id: Uuid,
    pub status: ExecutionStatus,
    pub metadata: TriggerMetadata,
    pub trace: Option<Value>,
}

/// Status snapshot at the moment the service returns. For async
/// dispatches (the common case) this is `Queued` or `Running` — the
/// real terminal status is observed via the execution row downstream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
    TimedOut,
}

impl ExecutionStatus {
    /// Stable string form for the JSON response surface. Matches the
    /// values the rest of the platform stamps into `executions.status`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::TimedOut => "timed_out",
        }
    }
}

/// Provenance metadata stamped on the outcome. `trigger_type`
/// disambiguates `manual` / `replay` / `replay_with_input` / `retry`
/// for downstream consumers (analytics, audit log, scratchpad
/// tracing). `parent_execution_id` is set when the new execution
/// was derived from an existing one (replay variants); `None` for
/// fresh manual triggers and retries (which reuse the same row).
pub struct TriggerMetadata {
    pub trigger_type: TriggerType,
    pub parent_execution_id: Option<Uuid>,
    pub actor_id: Option<Uuid>,
    pub workflow_id: Uuid,
}

/// Stable label for the kind of orchestration operation that produced
/// the execution. Stamped into the execution row's metadata for
/// downstream attribution + audit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TriggerType {
    Manual,
    Replay,
    ReplayWithInput,
    Retry,
}

impl TriggerType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Replay => "replay",
            Self::ReplayWithInput => "replay_with_input",
            Self::Retry => "retry",
        }
    }
}

/// Outcome of a trigger call. Distinct from `ExecutionOutcome` because
/// the trigger surface supports a dry-run validation mode that
/// returns schema + errors without dispatching anything.
pub enum TriggerOutcome {
    /// The trigger dispatched normally; the dispatched execution's
    /// metadata is in the wrapped `ExecutionOutcome`.
    Dispatched(ExecutionOutcome),
    /// The caller passed `validate_input=true`; the validation result
    /// is reported here without dispatching. `schema` is `None` when
    /// the workflow has no input_schema attached.
    DryRun(DryRunResult),
}

/// Schema-validation report returned from the dry-run path. Mirrors
/// the historical `mcp_text` body the inline handler emitted; the
/// protocol layer is responsible for choosing the JSON-RPC vs
/// GraphQL vs HTTP wire shape.
pub struct DryRunResult {
    pub workflow_id: Uuid,
    pub schema: Option<Value>,
    pub errors: Vec<String>,
}
