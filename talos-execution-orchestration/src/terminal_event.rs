//! Terminal execution-event emission (broadcast + persistence).
//!
//! Extracted from the GraphQL `trigger_workflow` resolver's
//! `store_and_send!` macro when that resolver migrated onto
//! `ExecutionOrchestrationService` (2026-07-01). Because the service
//! owns the emission now, MCP-triggered executions produce the same
//! live `executionUpdates` events GraphQL-triggered ones always did —
//! previously the broadcast fired only from the GraphQL-inline path.
//!
//! Semantics preserved from the macro:
//! - Broadcast FIRST so live subscribers get the event even if the DB
//!   persistence fails.
//! - `log_message` is truncated at 8 KiB (MCP-1194 ceiling) then
//!   DLP-redacted (MCP-965) before landing in
//!   `execution_events.log_message`.
//! - Persistence failure is logged and swallowed — an observability
//!   hole must never fail the dispatch path.
//!
//! Only workflow-level terminal events flow through here (node-level
//! events are the engine `PostgresEventSink`'s job), so the
//! `event_type` mapping is the two-arm subset of the macro's table.

use talos_engine::events::{ExecutionEvent, ExecutionStatus};
use uuid::Uuid;

/// Broadcast + persist a workflow-level terminal event. `status` must
/// be `Completed` or `Failed`; anything else is logged and dropped
/// (this helper deliberately doesn't cover node-level events).
pub(crate) async fn emit_terminal_event(
    pool: &sqlx::PgPool,
    sender: Option<&tokio::sync::broadcast::Sender<ExecutionEvent>>,
    execution_id: Uuid,
    status: ExecutionStatus,
    log_message: String,
    trace_id: Option<String>,
) {
    let event_type = match status {
        ExecutionStatus::Completed => "completed",
        ExecutionStatus::Failed => "failed",
        other => {
            tracing::warn!(
                %execution_id,
                ?other,
                "emit_terminal_event called with a non-terminal status — dropped"
            );
            return;
        }
    };

    let event = ExecutionEvent {
        execution_id,
        node_id: None,
        status,
        trace_id,
        span_id: None,
        log_message: Some(log_message),
        iteration_index: None,
        iteration_total: None,
        duration_ms: None,
        output: None,
    };

    // Broadcast first — live subscribers must see the event even if the
    // insert below fails. A send error just means no subscribers.
    if let Some(sender) = sender {
        let _ = sender.send(event.clone());
    }

    // MCP-1194 truncate-then-redact, matching the macro byte-for-byte.
    let redacted_log_message = event.log_message.as_deref().map(|m| {
        let truncated: &str = if m.len() > 8192 {
            talos_text_util::truncate_at_char_boundary(m, 8192)
        } else {
            m
        };
        talos_dlp_provider::redact_str(truncated)
    });

    if let Err(db_err) = sqlx::query(
        r#"
        INSERT INTO execution_events (execution_id, event_type, node_id, status, log_message)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(event.execution_id)
    .bind(event_type)
    .bind(event.node_id)
    .bind(format!("{:?}", event.status))
    .bind(&redacted_log_message)
    .execute(pool)
    .await
    {
        tracing::error!(
            %execution_id,
            error = %db_err,
            "failed to persist terminal execution event"
        );
    }
}
