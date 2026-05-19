//! Pluggable fire-and-forget sink for per-node execution events.
//!
//! The executor emits lifecycle events (`node_started`, `node_completed`,
//! `node_failed`, `node_retrying`, `loop_iteration`, etc.) as it runs. An
//! [`EventSink`] is the consumer's hook to persist, forward, or ignore
//! those events — typical impls are a Postgres INSERT, an append-only
//! log, an in-memory capture for tests, or a no-op.
//!
//! # Fire-and-forget is the default
//!
//! The executor typically spawns `emit` calls onto its async runtime
//! so events never block the dispatch loop, and a stuck sink never
//! stalls a job. A small number of ordering-critical sites call
//! `sink.emit(event).await` directly — impls used on that path must
//! be fast and local. The helper that wraps the common spawn pattern
//! lives next to the executor (it depends on a specific async
//! runtime), not in this crate.

use async_trait::async_trait;
use uuid::Uuid;

/// One event written to the execution-events log.
///
/// `event_type` and `status` are free-form strings because backing
/// stores often evolve their taxonomy over time without a matching
/// Rust enum — impls that want validation can do so at emit time.
///
/// Extending this struct is a breaking change for external
/// constructors (typically custom dispatchers emitting events). A
/// [`Default`] impl is provided so callers can use struct-update
/// syntax (`NodeEventWrite { execution_id, event_type, ..Default::default() }`)
/// and remain forward-compatible.
#[derive(Debug, Clone, Default)]
pub struct NodeEventWrite {
    /// Parent workflow execution id.
    pub execution_id: Uuid,
    /// Event category (e.g. `"node_started"`, `"node_completed"`,
    /// `"node_failed"`, `"node_retrying"`, `"loop_iteration"`,
    /// `"node_skipped"`, `"retry_skipped"`, `"node_input"`).
    pub event_type: String,
    /// Node that produced the event, or `None` for workflow-level events.
    pub node_id: Option<Uuid>,
    /// Coarse status (`"Running"`, `"Completed"`, `"Failed"`, `"Skipped"`,
    /// `"Input"`).
    pub status: String,
    /// Optional human-readable detail — an error summary on
    /// `node_failed`, a retry reason on `node_retrying`, etc.
    pub log_message: Option<String>,
    /// Loop iteration counter for events emitted from a repeating body
    /// (`AgentLoop`, `ReActLoop`, `WhileLoop`). `None` for one-shot
    /// events.
    pub iteration_index: Option<i32>,
    /// Stable error-classification tag when the event describes a
    /// classifier decision, `None` otherwise.
    ///
    /// Populated today on `retry_skipped` events with the tag the
    /// [`RetryClassifier`](crate::RetryClassifier) produced (e.g.
    /// `"auth"`, `"invalid_input"`, `"unknown"`) so downstream
    /// analysis tooling can surface *why* an explicit `retry_count`
    /// was short-circuited without string-parsing `log_message`.
    /// Other event types currently leave this `None`; future variants
    /// may populate it consistently with `event_type`.
    pub error_class: Option<String>,
}

/// Persist or forward per-node execution events.
///
/// # Emission paths
///
/// The executor calls [`emit`](Self::emit) in two distinct patterns:
///
/// 1. **Fire-and-forget** (the common case): the executor hands the
///    emit to a runtime-specific spawn helper that detaches it into
///    its own task. A slow impl here is harmless; the dispatch loop
///    never waits.
/// 2. **Synchronous** on a handful of ordering-critical sites
///    (`node_completed` / `node_failed`), where the executor awaits
///    `emit` directly before routing to child nodes so observers see a
///    causally consistent timeline. **Impls used on this path MUST be
///    fast and local** — a network round-trip per event will stall the
///    dispatch loop under load.
///
/// # Error handling
///
/// Impls are responsible for their own error handling (logging,
/// dropping, retrying). The method returns `()` rather than `Result`
/// because no caller acts on the outcome — an event-persistence
/// failure is an observability concern, not a workflow concern.
///
/// # Authorization
///
/// Impls do **not** validate that `event.execution_id` belongs to any
/// particular user or tenant; the caller owns authorization. Backing
/// stores with tenant isolation should enforce it at the storage
/// layer (foreign-key scope, row-level security), not at the event
/// write.
#[async_trait]
pub trait EventSink: Send + Sync {
    /// Emit `event`. See the trait-level docs for the two emission
    /// paths and their latency expectations.
    async fn emit(&self, event: NodeEventWrite);
}
