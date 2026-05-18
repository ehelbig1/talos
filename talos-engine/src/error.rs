use thiserror::Error;
use uuid::Uuid;

// MCP-915 (2026-05-14): `enqueue_to_dlq` was removed. It was a stub
// with zero callers AND missing two correctness requirements that the
// LIVE DLQ-insert path in `node_hook.rs:307` already implements:
//
//   1. MCP-466 DLP scrubbing — `talos_dlp_provider::redact_str()` on
//      error_message + `redact_json()` on payload. The CLAUDE.md
//      persistence-boundary DLP rule REQUIRES this; the stub bound
//      raw values, which would have leaked `sk-*` / `ghp_*` / Bearer
//      tokens into the DLQ table (readable via MCP/GraphQL).
//   2. Sibling-cancellation logic — UPDATE module_executions SET
//      status = 'cancelled' after enqueue. The stub omitted this,
//      leaving in-flight sibling rows in 'running' forever.
//
// Wiring the stub up would have re-introduced both bugs. The live
// code at `node_hook.rs::dispatch_node_failure` is the canonical home.
// Same delete-vs-wire-in pattern as MCP-907 (`validate_password_strength`).

#[derive(Error, Debug)]
pub enum EngineError {
    #[error("Workflow contains a cycle")]
    CycleDetected,

    #[error("Module execution requires user context (user_id not set)")]
    MissingUserContext,

    #[error("Missing user ID for module {0} in chain")]
    MissingUserIdForModule(Uuid),

    #[error("Failed to prepare module: {0}")]
    ModulePreparationFailed(String),

    #[error("Failed to load module {0} into cache: {1}")]
    ModuleCacheLoadFailed(Uuid, String),

    #[error("Failed to get module config: {0}")]
    ModuleConfigFailed(String),

    #[error("Failed to read wasm module {0} for user {1}: {2}")]
    WasmReadFailed(Uuid, Uuid, String),

    #[error("Module access denied: node {node_id} for user {user_id}. Details: {details}")]
    ModuleAccessDenied {
        node_id: Uuid,
        user_id: Uuid,
        details: String,
    },

    #[error("Failed to fetch module {module_id} for user {user_id}: {details}")]
    ModuleFetchFailed {
        module_id: Uuid,
        user_id: Uuid,
        details: String,
    },

    #[error("Failed to serialize job request: {0}")]
    JobSerializationFailed(String),

    #[error("Failed to sign job request: {0}")]
    JobSignFailed(String),

    #[error("Job execution timed out via NATS")]
    NatsTimeout,

    #[error("NATS request failed: {0}")]
    NatsRequestFailed(String),

    #[error("Job result signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    #[error("Failed to parse job result: {0}")]
    ResultParseFailed(String),

    #[error("Invalid graph JSON: {0}")]
    InvalidGraphJson(String),

    #[error("Workflow has no nodes")]
    EmptyWorkflow,

    #[error("Job execution failed: {0:?}")]
    JobExecutionFailed(serde_json::Value),

    #[error("Node {node_id} failed: {details}")]
    NodeFailed { node_id: Uuid, details: String },

    #[error(transparent)]
    DatabaseError(#[from] sqlx::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
