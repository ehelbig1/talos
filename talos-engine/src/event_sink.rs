//! Talos-side support for the engine's [`EventSink`] trait.
//!
//! The trait itself and the event shape live in
//! [`talos_workflow_engine_core`] — this module re-exports them for
//! convenience and adds [`PostgresEventSink`], the default Talos impl
//! backed by the `execution_events` table.
//!
//! The fire-and-forget `emit_event_spawn` helper lives in the
//! `talos-workflow-engine` crate (see `talos_workflow_engine::emit_event_spawn`);
//! dispatch adapters import it from there directly.

use async_trait::async_trait;
use sqlx::{Pool, Postgres};

pub use talos_workflow_engine_core::{EventSink, NodeEventWrite};

/// Postgres-backed sink that writes to the `execution_events` table.
///
/// Errors are logged at `warn` level and swallowed — an event-
/// persistence failure is an observability hole but must never
/// propagate into the dispatch loop.
pub struct PostgresEventSink {
    pool: Pool<Postgres>,
}

impl PostgresEventSink {
    /// Build a sink bound to `pool`.
    #[must_use]
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

impl std::fmt::Debug for PostgresEventSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresEventSink")
            .field("pool", &self.pool)
            .finish()
    }
}

#[async_trait]
impl EventSink for PostgresEventSink {
    async fn emit(&self, event: NodeEventWrite) {
        // MCP-966 (2026-05-15): DLP-redact log_message at persistence
        // boundary. Pre-fix this sink — the canonical engine-side
        // event sink used by every node event in the workflow
        // engine — bound `event.log_message` straight into the
        // INSERT. `log_message` is arbitrary node-emitted text
        // (HTTP response bodies, raw error text echoing
        // Authorization headers, partial outputs from misconfigured
        // workflows); secrets matching `sk-*`, `ghp_*`, Bearer
        // tokens, etc. leaked into the `execution_events.log_message`
        // column and stayed there for replay / log aggregators / DB
        // backups. Sibling to MCP-965 on the GraphQL `store_and_send!`
        // path (talos-api/src/schema/workflows/mutations.rs) — same
        // class as MCP-466 / MCP-481-484 persistence-boundary DLP
        // sweep. The redact_str helper is infallible (returns input
        // unchanged on internal error) so this doesn't introduce a
        // new failure mode on the event-emit hot path.
        //
        // MCP-1165 (2026-05-17): truncate-then-redact discipline.
        // Sibling sweep to MCP-1160/1161/1162/1163/1164. The
        // `log_message: Option<String>` field on NodeEventWrite is
        // caller-supplied (engine emits the strings; nothing bounds
        // the input). Node errors routinely echo HTTP response
        // bodies (multi-MB possible), retry reasons echo wasmtime
        // traces. Pre-fix the redact_str regex pass walked the
        // entire string AND the unbounded result landed in
        // `execution_events.log_message` (no DB-side length cap),
        // loaded by every replay/audit query. This sink runs on
        // every node event in every workflow execution — the
        // canonical engine hot path. 8 KiB ceiling matches the
        // sibling cap on `workflow_execution_logs.message`
        // (MAX_LOG_MESSAGE_LENGTH=10K chars; 8 KiB bytes ≈ same
        // order, conservative on bytes vs chars).
        let redacted_log_message = event.log_message.as_deref().map(|m| {
            let truncated: &str = if m.len() > 8192 {
                talos_text_util::truncate_at_char_boundary(m, 8192)
            } else {
                m
            };
            talos_dlp_provider::redact_str(truncated)
        });
        if let Err(e) = sqlx::query(
            "INSERT INTO execution_events \
             (execution_id, event_type, node_id, status, log_message, iteration_index, error_class) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(event.execution_id)
        .bind(&event.event_type)
        .bind(event.node_id)
        .bind(&event.status)
        .bind(redacted_log_message.as_deref())
        .bind(event.iteration_index)
        // `error_class` is populated by the NATS dispatcher on retry_skipped
        // events and by engine::handle_node_failure on node_failed events.
        // Legacy events pre-dating engine v0.2 will have None — the column
        // is nullable to accommodate that.
        .bind(event.error_class.as_deref())
        .execute(&self.pool)
        .await
        {
            // `warn` (not `debug`): an event-persistence failure is an
            // observability hole — the audit trail is silently missing
            // rows until it's fixed. sqlx error text may include
            // table/column names but never row values, so no secret leak.
            tracing::warn!(
                error = %e,
                execution_id = %event.execution_id,
                event_type = %event.event_type,
                "Failed to persist execution event — dropped",
            );
        }
    }
}
