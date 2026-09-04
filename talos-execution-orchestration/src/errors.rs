//! Typed orchestration errors.
//!
//! Every public method on `ExecutionOrchestrationService` returns
//! `Result<_, OrchestrationError>`. Callers (MCP handlers, GraphQL
//! resolvers) map variants to protocol-specific status codes — the
//! service itself never speaks JSON-RPC, GraphQL extensions, or HTTP.
//!
//! The variant set is deliberately narrow: each one tells the caller
//! a different action class (caller-fix-able vs. retry-later vs.
//! never-fixable-by-caller). Errors that don't fit a specific class
//! land in `Internal`; `Database` is split out so callers can
//! distinguish "the DB went away" from "the caller asked for
//! something nonsensical" without parsing strings.

use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum OrchestrationError {
    /// Caller-fix-able shape problem (UUID didn't parse, payload too
    /// large, mutually-exclusive flags both set).
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Workflow row missing or not visible to the caller. Distinct from
    /// `AuthorizationDenied` so the handler can decide whether to leak
    /// "exists but you can't see it" vs. "doesn't exist" — both map to
    /// "not found" externally for tenant isolation, but logs benefit
    /// from the distinction.
    #[error("workflow not found: {0}")]
    WorkflowNotFound(Uuid),

    /// Execution row missing or not visible to the caller.
    #[error("execution not found: {0}")]
    ExecutionNotFound(Uuid),

    /// The execution EXISTS and the caller may see it, but the retention
    /// sweep moved it to `workflow_executions_archive` — so it cannot be
    /// acted on. Deliberately NOT folded into `ExecutionNotFound`: that is
    /// the defect this variant exists to prevent. An operator told "not
    /// found or access denied" about a row `list_archived_executions`
    /// happily returns goes looking for a permissions problem that isn't
    /// there. Carries the archival timestamp so the caller can say WHEN.
    #[error("execution {0} was archived at {1}")]
    ExecutionArchived(Uuid, chrono::DateTime<chrono::Utc>),

    /// Caller paused workflow execution globally (`pause_executions`
    /// MCP tool). Re-fires once `resume_executions` is called.
    #[error("workflow execution is currently paused at the platform level")]
    ExecutionPaused,

    /// Workflow `is_enabled = false`. Different from `Paused` because
    /// this is a per-workflow toggle, not a platform-wide drain.
    #[error("workflow {0} is disabled")]
    WorkflowDisabled(Uuid),

    /// Wrong source state for the operation. Examples: retry on a
    /// running execution, replay on a missing workflow row, ack on
    /// an already-acknowledged execution.
    #[error("status conflict: {0}")]
    StatusConflict(String),

    /// Authorization layer (capability ceiling, actor budget, graph
    /// ownership) refused the operation. Bundles the talos-workflow-
    /// authorization error message — the layer already returns
    /// human-readable strings.
    #[error("authorization denied: {0}")]
    AuthorizationDenied(String),

    /// Input failed schema validation (when a workflow has an attached
    /// input schema). Includes the schema-validation error path.
    #[error("input validation failed: {0}")]
    ValidationFailed(String),

    /// Workflow has a per-workflow concurrency cap and we'd exceed it.
    /// Distinct from `ExecutionPaused` because the caller can retry
    /// once running executions complete.
    #[error("concurrency limit exceeded: {0}")]
    ConcurrencyLimitExceeded(String),

    /// NATS dispatch couldn't be performed. Production paths fail
    /// closed if the worker shared signing key is missing — that
    /// surfaces here, not as `Internal`, so the handler can render
    /// a useful message.
    #[error("dispatch failed: {0}")]
    DispatchFailed(String),

    /// SQL-layer failure. Surfaced separately from `Internal` so the
    /// handler can decide whether to retry or just log.
    #[error(transparent)]
    Database(#[from] sqlx::Error),

    /// The workflow's stored graph could not be loaded into an engine —
    /// most commonly an EMPTY graph (a workflow created with no nodes and
    /// then triggered), or a malformed stored `graph_json`. This is a
    /// WORKFLOW-DEFINITION problem the caller can fix (add a node, re-save
    /// the graph), NOT a server fault — so it surfaces the actionable
    /// message verbatim (already rendered by
    /// `talos_engine::user_errors::render_graph_load_error` AND
    /// DLP-redacted by the caller) and is NOT logged as a server-side
    /// failure. Separated from `Internal` for exactly this reason (found
    /// in regression round 6: empty-graph triggers returned a useless
    /// "Internal server error" and paged as a server failure).
    #[error("{0}")]
    GraphLoadFailed(String),

    /// Catch-all for engine-builder failures, repository helper errors
    /// that don't surface a typed variant, and other infrastructure
    /// concerns the caller can't fix.
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl OrchestrationError {
    /// Stable JSON-RPC error code for MCP handlers. Maps the variant
    /// to the closest standard code so different MCP clients render
    /// the failure consistently.
    ///
    /// References: JSON-RPC 2.0 §5.1 (-32700..-32600 reserved by
    /// spec), Talos custom range starts at -32000.
    pub fn jsonrpc_code(&self) -> i32 {
        match self {
            Self::InvalidArgument(_) | Self::ValidationFailed(_) | Self::GraphLoadFailed(_) => {
                -32602
            }
            Self::WorkflowNotFound(_) | Self::ExecutionNotFound(_) => -32001,
            // Same class as a status conflict: the row is real, the operation
            // is refused because of the row's CURRENT state. Not -32001 —
            // that code means "no such thing".
            Self::ExecutionArchived(..) => -32003,
            Self::ExecutionPaused | Self::WorkflowDisabled(_) | Self::StatusConflict(_) => -32003,
            Self::AuthorizationDenied(_) => -32004,
            Self::ConcurrencyLimitExceeded(_) => -32005,
            Self::DispatchFailed(_) | Self::Database(_) | Self::Internal(_) => -32000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jsonrpc_codes_are_stable() {
        // Tripwire — changing these codes breaks downstream MCP clients
        // that switch on numeric code. Update the documented mapping
        // before flipping a value here.
        assert_eq!(
            OrchestrationError::InvalidArgument("x".into()).jsonrpc_code(),
            -32602
        );
        // GraphLoadFailed (empty/malformed graph) is a client-error code —
        // an actionable workflow-definition problem, not a server fault.
        assert_eq!(
            OrchestrationError::GraphLoadFailed("Workflow has no nodes".into()).jsonrpc_code(),
            -32602
        );
        assert_eq!(
            OrchestrationError::WorkflowNotFound(Uuid::nil()).jsonrpc_code(),
            -32001
        );
        assert_eq!(OrchestrationError::ExecutionPaused.jsonrpc_code(), -32003);
        assert_eq!(
            OrchestrationError::AuthorizationDenied("denied".into()).jsonrpc_code(),
            -32004
        );
        assert_eq!(
            OrchestrationError::ConcurrencyLimitExceeded("3 of 3".into()).jsonrpc_code(),
            -32005
        );
        assert_eq!(
            OrchestrationError::DispatchFailed("nats down".into()).jsonrpc_code(),
            -32000
        );
        // ExecutionArchived is a STATUS-CONFLICT code, NOT the -32001
        // not-found code its sibling uses. The row exists and the caller may
        // see it; the operation is refused because of where the row now
        // lives. Filing it under -32001 would tell an MCP client switching on
        // the numeric code that there is no such execution — the same lie the
        // string form used to tell, one layer down.
        assert_eq!(
            OrchestrationError::ExecutionArchived(Uuid::nil(), chrono::Utc::now()).jsonrpc_code(),
            -32003
        );
        assert_ne!(
            OrchestrationError::ExecutionArchived(Uuid::nil(), chrono::Utc::now()).jsonrpc_code(),
            OrchestrationError::ExecutionNotFound(Uuid::nil()).jsonrpc_code(),
            "archived and absent must not share a code"
        );
    }
}
