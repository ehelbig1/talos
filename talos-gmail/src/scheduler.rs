//! Hourly Gmail watch-channel renewal task.
//!
//! Gmail `users.watch` subscriptions expire every 7 days (Google's
//! hard cap). This task lists every watch row expiring within the
//! next 24 hours and renews it, mirroring the gcal scheduler pattern.
//!
//! The loop CONTROL FLOW lives in
//! `talos_integration_helpers::renewal::run_renewal_scheduler`; this
//! module only supplies the Gmail-specific hooks (log lines, audit
//! event types, metadata shapes) via [`RenewableIntegration`]. The
//! hook bodies are byte-for-byte the pre-extraction emissions —
//! operators grep for them and the watch-channel summary service
//! joins on the metadata keys — and living here keeps the
//! `talos_gmail::scheduler` tracing target stable.

use super::watch::{GmailWatchRow, GmailWatchService};
use async_trait::async_trait;
use std::sync::Arc;
use talos_integration_helpers::audit::{
    insert_channel_audit, truncate_and_redact_error, ChannelAuditEvent,
};
use talos_integration_helpers::renewal::{run_renewal_scheduler, RenewableIntegration};
use uuid::Uuid;

/// Private adapter so implementing the (public) helper trait doesn't
/// widen `GmailWatchService`'s API surface — `renew_watch` and
/// `get_watches_needing_renewal` stay `pub(crate)`.
struct GmailRenewer(Arc<GmailWatchService>);

#[async_trait]
impl RenewableIntegration for GmailRenewer {
    type Row = GmailWatchRow;
    type Renewed = GmailWatchRow;

    async fn list_needing_renewal(&self) -> anyhow::Result<Vec<(Uuid, GmailWatchRow)>> {
        self.0.get_watches_needing_renewal().await
    }

    async fn renew(&self, user_id: Uuid, row: &GmailWatchRow) -> anyhow::Result<GmailWatchRow> {
        self.0.renew_watch(user_id, row.id).await
    }

    fn log_shutdown(&self) {
        tracing::info!(
            target: "talos_audit",
            event_kind = "gmail_renewal_task_shutdown",
            "Gmail watch renewal task shutting down (clean)"
        );
    }

    fn log_cycle_start(&self) {
        tracing::info!("🔄 Running Gmail watch renewal task");
    }

    fn log_no_rows(&self) {
        tracing::debug!("No gmail watches need renewal");
    }

    fn log_row_count(&self, count: usize) {
        tracing::info!(count, "gmail watches needing renewal");
    }

    fn log_renewing(&self, user_id: Uuid, row: &GmailWatchRow) {
        tracing::info!(
            channel_uuid = %row.id,
            %user_id,
            "🔁 Renewing gmail watch"
        );
    }

    async fn on_renewed(&self, user_id: Uuid, old: &GmailWatchRow, new: &GmailWatchRow) {
        tracing::info!(
            new_expiration_ms = %new.expiration_ms,
            "✅ gmail watch renewed"
        );
        if let Err(db_err) = insert_channel_audit(
            &self.0.pool,
            ChannelAuditEvent {
                integration_id: Some(new.integration_id),
                user_id,
                event_type: "gmail_channel_renewed",
                target: Some(&new.email_address),
                success: true,
                error_message: None,
                metadata: serde_json::json!({
                    "old_channel_uuid": old.id.to_string(),
                    "new_channel_uuid": new.id.to_string(),
                    "new_expiration_ms": new.expiration_ms,
                }),
            },
        )
        .await
        {
            tracing::error!(error = %db_err, "audit log insert failed");
        }
    }

    async fn on_renewal_failed(&self, user_id: Uuid, old: &GmailWatchRow, e: &anyhow::Error) {
        tracing::error!(
            channel_uuid = %old.id,
            error = %e,
            "gmail watch renewal failed"
        );
        // MCP-980 (2026-05-15) + MCP-1181 (2026-05-17): the Google API
        // error is truncated at 1 KiB FIRST, then DLP-redacted before
        // persistence into the audit log's error_message column —
        // OAuth failure responses commonly echo refresh_token bytes in
        // the error description. Both steps live in the canonical
        // `truncate_and_redact_error` helper.
        let redacted_err = truncate_and_redact_error(&e.to_string());
        if let Err(db_err) = insert_channel_audit(
            &self.0.pool,
            ChannelAuditEvent {
                integration_id: Some(old.integration_id),
                user_id,
                event_type: "gmail_channel_renewal_failed",
                target: Some(&old.email_address),
                success: false,
                error_message: Some(&redacted_err),
                metadata: serde_json::json!({
                    "channel_uuid": old.id.to_string(),
                    "topic_name": old.topic_name,
                }),
            },
        )
        .await
        {
            tracing::error!(error = %db_err, "audit log insert failed");
        }
    }

    fn log_list_failed(&self, e: &anyhow::Error) {
        tracing::error!(error = %e, "failed to list gmail watches needing renewal");
    }
}

/// MCP-1156 (2026-05-16): shutdown-aware renewal loop.
///
/// Pre-fix `gmail_renewal_task` was an infinite `loop { tick.await; … }`
/// with no shutdown channel. On controller SIGTERM the spawn was
/// force-aborted mid-iteration — operators saw no "task shutting down"
/// log line and could not correlate stop-time against deploy events.
/// Sibling pattern to MCP-994 (bcrypt cache revocation sweep), which
/// already plumbs a `tokio::sync::watch::Receiver<bool>` for graceful
/// termination. Same lifecycle-observability class as the MCP-1119–1130
/// NATS subscriber supervisor sweep.
///
/// The renewal cadence is hourly — a graceful abort window is rarely
/// observed in practice — but the explicit shutdown path gives
/// operators a clean event-kind to grep for at restart boundaries.
pub async fn gmail_renewal_task(
    service: Arc<GmailWatchService>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    run_renewal_scheduler(Arc::new(GmailRenewer(service)), shutdown_rx).await;
}
