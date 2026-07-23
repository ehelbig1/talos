/// WorkflowRepository — centralises all SQL for the workflows domain.
///
/// Follows the ModuleExecutionService pattern: plain struct, `new(db_pool)`,
/// all methods `pub async fn`, return `anyhow::Result<T>` so callers can `?`.
/// Handlers in `mcp/workflows.rs` should be thin wrappers that call these
/// methods and format the JSON-RPC response.
use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use std::collections::HashMap;
use talos_dlp_provider::bound_execution_payload;
use uuid::Uuid;

mod actor_context;
mod executions;
mod graph_export;
mod search;
mod stats;
mod templates;
mod workflows;

pub use actor_context::MemoryScope;
pub use executions::*;
pub use graph_export::*;
pub use search::*;
pub use stats::*;
pub use templates::*;
pub use workflows::*;

// ─────────────────────────────────────────────────────────────────────────────
// Repository
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct WorkflowRepository {
    db_pool: PgPool,
    /// Optional SecretsManager. When wired (`with_encryption`), the
    /// `mark_execution_*` and `update_execution_output` methods encrypt
    /// `output_data` at rest the same way `ExecutionRepository` and
    /// `ActorRepository::complete_execution` do (N T5-N1). Without this
    /// hook the methods fall back to plaintext writes — the historical
    /// behavior — but a row that was previously written via the
    /// encrypted path then re-written via the plaintext path keeps its
    /// stale ciphertext, so the encrypted branch's read order
    /// (ciphertext preferred when both columns are populated) would
    /// surface OLD output. The plaintext branch therefore NULLs the
    /// ciphertext columns symmetrically.
    secrets_manager: Option<std::sync::Arc<talos_secrets_manager::SecretsManager>>,
    /// Optional broadcast channel for newly-created execution rows.
    /// Mirrors `ExecutionRepository::workflow_execution_tx` — the
    /// cap-aware batch admission helper emits one event per admitted
    /// row so GraphQL subscribers see queued executions appear in the
    /// dashboard. Without this hook the helper still works, just
    /// without real-time notifications.
    workflow_execution_tx:
        Option<tokio::sync::broadcast::Sender<talos_engine_events::WorkflowExecutionEvent>>,
}

impl WorkflowRepository {
    pub fn new(db_pool: PgPool) -> Self {
        Self {
            db_pool,
            secrets_manager: None,
            workflow_execution_tx: None,
        }
    }

    /// Builder: attach SecretsManager so `mark_execution_*` and
    /// `update_execution_output` encrypt `output_data` at rest. Mirrors
    /// `ActorRepository::with_encryption` and the equivalent helper on
    /// `ExecutionRepository`. Wiring is opt-in so test contexts and
    /// pre-encryption migration paths continue to work unchanged.
    pub fn with_encryption(
        mut self,
        sm: std::sync::Arc<talos_secrets_manager::SecretsManager>,
    ) -> Self {
        self.secrets_manager = Some(sm);
        self
    }

    /// Builder: attach the broadcast channel for execution-creation
    /// events. The cap-aware batch admission helper emits one event
    /// per admitted row.
    pub fn with_workflow_execution_sender(
        mut self,
        tx: tokio::sync::broadcast::Sender<talos_engine_events::WorkflowExecutionEvent>,
    ) -> Self {
        self.workflow_execution_tx = Some(tx);
        self
    }
}
