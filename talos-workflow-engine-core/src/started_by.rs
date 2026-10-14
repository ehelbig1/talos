//! Read-side port: how an execution was started (2026-10-14).
//!
//! The controller records what started a run on its row
//! (`workflow_executions.provenance.started_by`, read back for every row by
//! `talos_workflow_repository::started_by`). The engine reads that word ONCE,
//! when a top-level run starts, and hands it to every module it dispatches
//! as [`crate::reserved_keys::STARTED_BY`]. A child engine is given its
//! parent's word and never reads a row: it runs under a synthetic execution
//! id that names none.
//!
//! Reading the row, rather than having each start path tell the engine,
//! covers every path that creates an execution (eleven insert statements
//! today) and the paths that re-run one (retry, resume, crash recovery) with
//! the same answer the listing gives, and a new start path needs no change
//! here to be covered.
//!
//! `None` (no resolver, no row, a failed read) means the key is absent from
//! every node's input: unknown, never a guess.

use async_trait::async_trait;
use uuid::Uuid;

/// Resolve the start kind of one execution.
#[async_trait]
pub trait StartedByResolver: Send + Sync {
    /// The `kind` of what started `execution_id` (owned by `user_id`), or
    /// `None` when it cannot be read. Impls MUST NOT fail the run: swallow
    /// and log their own errors.
    async fn started_by_kind(&self, execution_id: Uuid, user_id: Option<Uuid>) -> Option<String>;
}
