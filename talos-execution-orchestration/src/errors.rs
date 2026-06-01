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
            Self::InvalidArgument(_) | Self::ValidationFailed(_) => -32602,
            Self::WorkflowNotFound(_) | Self::ExecutionNotFound(_) => -32001,
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
    }
}
