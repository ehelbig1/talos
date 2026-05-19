//! Pluggable per-node execution audit log.
//!
//! The executor writes a row for every node / pipeline-step dispatch:
//! a "running" row at dispatch time and a "completed" / "failed" /
//! "timeout" / "cancelled" row when the worker reports back. Consumers
//! use these rows for observability dashboards, per-module latency
//! histograms, and retry audit trails. Concrete storage (Postgres
//! `module_executions` table, an S3 append log, an in-memory ring
//! buffer for tests) is the impl's choice.
//!
//! # Why a separate trait
//!
//! This could plausibly fold into [`crate::NodeLifecycleHook`], but
//! `NodeLifecycleHook` fires **once per node completion**;
//! [`ModuleExecutionStore`] writes rows at **two distinct points**
//! (pre-dispatch "running" INSERT + post-dispatch UPDATE) and the
//! engine holds row ids across that boundary. Splitting keeps each
//! trait focused.

use async_trait::async_trait;
use serde_json::Value as JsonValue;
use uuid::Uuid;

use crate::BoxError;

/// Arguments for [`ModuleExecutionStore::record_started`].
///
/// Grouped into a context struct (rather than a long parameter list)
/// so adding a new field is a non-breaking change for existing trait
/// impls. New fields should be added at the end; downstream impls
/// destructure by name.
///
/// `input` is borrowed — callers own the payload and no impl needs to
/// outlive the call. Impls that must persist the payload (a Postgres
/// store might bind it via sqlx; in-memory capture stores clone it)
/// copy what they need.
pub struct ExecutionStartedContext<'a> {
    /// Row id for this dispatch. Must match the `id` passed to
    /// [`ModuleExecutionStore::record_completed`] when the worker
    /// returns.
    pub id: Uuid,
    /// Canonical module id used when recording the execution row. The
    /// engine calls
    /// [`ModuleExecutionStore::resolve_module_id`] first to map any
    /// template / alias id onto this.
    pub module_id: Uuid,
    /// Owning user for the dispatch.
    pub user_id: Uuid,
    /// Parent `workflow_executions.id`.
    pub workflow_execution_id: Uuid,
    /// Input payload shipped to the worker. May contain plaintext
    /// values resolved from `vault://` references, so the manual
    /// `Debug` impl redacts this field.
    pub input: &'a JsonValue,
    /// Trigger origin tag (`"webhook"`, `"scheduled"`, `"manual"`, …).
    pub trigger_type: &'a str,
    /// When `true`, the row enters as `"cancelled"` if the parent
    /// workflow has already been flipped to a terminal state
    /// (`failed` / `cancelled`) by a sibling node failure, and
    /// `"running"` otherwise. Single-node dispatch paths set this
    /// true to close the race between a sibling's failure UPDATE and
    /// the current node's INSERT under concurrent load. Pipeline
    /// steps (which dispatch atomically as a unit) set this false —
    /// there's no concurrent sibling to race against.
    pub race_safe_status: bool,
}

impl std::fmt::Debug for ExecutionStartedContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecutionStartedContext")
            .field("id", &self.id)
            .field("module_id", &self.module_id)
            .field("user_id", &self.user_id)
            .field("workflow_execution_id", &self.workflow_execution_id)
            .field("input", &"<redacted — may contain plaintext secrets>")
            .field("trigger_type", &self.trigger_type)
            .field("race_safe_status", &self.race_safe_status)
            .finish()
    }
}

/// Record per-dispatch execution rows.
#[async_trait]
pub trait ModuleExecutionStore: Send + Sync {
    /// Insert a "running" row for a dispatched node or pipeline step.
    ///
    /// See [`ExecutionStartedContext`] for the per-field semantics,
    /// including the race-safe-status contract.
    ///
    /// Impls SHOULD be idempotent on `id` collision (a Postgres-backed
    /// impl might use `INSERT ... ON CONFLICT DO NOTHING`).
    /// Observability readers tolerate a missing row (unknown run)
    /// better than a duplicate-key error that aborts dispatch.
    async fn record_started(&self, ctx: ExecutionStartedContext<'_>) -> Result<(), BoxError>;

    /// Update an existing row with completion state. `status` is one
    /// of `"completed"` / `"failed"` / `"timeout"` / `"cancelled"`
    /// (free-form to match the backing table's check constraint;
    /// impls that enforce an enum validate here).
    async fn record_completed(
        &self,
        id: Uuid,
        status: &str,
        output: &JsonValue,
        duration_ms: i32,
        error_message: Option<&str>,
    ) -> Result<(), BoxError>;

    /// Resolve a logical module identifier (e.g. a template id) to the
    /// canonical id used when recording execution rows. Impls backed
    /// by a `node_templates ↔ wasm_modules` split map the template id
    /// to the matching wasm_modules row (most recent compile);
    /// simpler stores return the input unchanged.
    ///
    /// When the input is already canonical, or no mapping exists, the
    /// impl returns the input as-is. The engine records whatever value
    /// is returned; consumers are expected to reject unknown ids at
    /// their storage layer rather than expecting the engine to paper
    /// over a missing row.
    async fn resolve_module_id(&self, id_or_template: Uuid) -> Uuid;
}
