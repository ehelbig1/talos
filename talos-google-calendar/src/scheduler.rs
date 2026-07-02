//! Google Calendar watch-channel renewal background task.
//!
//! Runs hourly, lists all channels whose `integration_state.idx_ts_1`
//! (stored expiration) falls within the next 24 hours, and re-creates
//! them. Audit rows go to `google_calendar_audit_log`.
//!
//! Channel storage lives in `integration_state` (integration_name =
//! `"gcal"`) — the scheduler uses the `WatchService` facade in
//! `watch.rs`.
//!
//! The loop CONTROL FLOW lives in
//! `talos_integration_helpers::renewal::run_renewal_scheduler`; this
//! module only supplies the gcal-specific hooks (log lines, audit
//! event types, metadata shapes) via [`RenewableIntegration`]. The
//! hook bodies are byte-for-byte the pre-extraction emissions —
//! operators grep for them and the watch-channel summary service
//! joins on the metadata keys — and living here keeps the
//! `talos_google_calendar::scheduler` tracing target stable.

use super::{GoogleCalendarService, WatchChannel};
use async_trait::async_trait;
use std::sync::Arc;
use talos_integration_helpers::audit::{
    insert_channel_audit, truncate_and_redact_error, ChannelAuditEvent,
};
use talos_integration_helpers::renewal::{run_renewal_scheduler, RenewableIntegration};
use uuid::Uuid;

/// Private adapter so implementing the (public) helper trait doesn't
/// widen `GoogleCalendarService`'s API surface.
struct GcalRenewer(Arc<GoogleCalendarService>);

#[async_trait]
impl RenewableIntegration for GcalRenewer {
    type Row = WatchChannel;
    type Renewed = WatchChannel;

    async fn list_needing_renewal(&self) -> anyhow::Result<Vec<(Uuid, WatchChannel)>> {
        self.0.get_channels_needing_renewal().await
    }

    async fn renew(&self, user_id: Uuid, row: &WatchChannel) -> anyhow::Result<WatchChannel> {
        self.0.renew_watch_channel(user_id, row.id).await
    }

    fn log_shutdown(&self) {
        tracing::info!(
            target: "talos_audit",
            event_kind = "gcal_renewal_task_shutdown",
            "Google Calendar channel renewal task shutting down (clean)"
        );
    }

    fn log_cycle_start(&self) {
        tracing::info!("🔄 Running Google Calendar channel renewal task");
    }

    fn log_no_rows(&self) {
        tracing::debug!("No gcal channels need renewal");
    }

    fn log_row_count(&self, count: usize) {
        tracing::info!(count, "gcal channels needing renewal");
    }

    fn log_renewing(&self, user_id: Uuid, channel: &WatchChannel) {
        tracing::info!(
            channel_uuid = %channel.id,
            calendar = %channel.calendar_id,
            %user_id,
            "🔁 Renewing gcal watch channel"
        );
    }

    async fn on_renewed(&self, user_id: Uuid, channel: &WatchChannel, new_channel: &WatchChannel) {
        tracing::info!(
            new_expiration = %new_channel.expiration,
            "✅ gcal channel renewed"
        );
        if let Err(db_err) = insert_channel_audit(
            &self.0.db_pool,
            ChannelAuditEvent {
                integration_id: Some(new_channel.integration_id),
                user_id,
                event_type: "channel_renewed",
                target: Some(&new_channel.calendar_id),
                success: true,
                error_message: None,
                metadata: serde_json::json!({
                    "old_channel_id": channel.channel_id,
                    "new_channel_id": new_channel.channel_id,
                    "new_expiration": new_channel.expiration,
                }),
            },
        )
        .await
        {
            tracing::error!(error = %db_err, "audit log insert failed");
        }
    }

    async fn on_renewal_failed(&self, user_id: Uuid, channel: &WatchChannel, e: &anyhow::Error) {
        tracing::error!(
            channel_uuid = %channel.id,
            error = %e,
            "gcal channel renewal failed"
        );

        // MCP-980 + MCP-1181: the Google API error is truncated at
        // 1 KiB FIRST, then DLP-redacted before audit-log persist —
        // OAuth-error bytes ride Google's error_description on
        // token-rejection paths. Both steps live in the canonical
        // `truncate_and_redact_error` helper.
        let redacted_err = truncate_and_redact_error(&e.to_string());
        if let Err(db_err) = insert_channel_audit(
            &self.0.db_pool,
            ChannelAuditEvent {
                integration_id: Some(channel.integration_id),
                user_id,
                event_type: "channel_renewal_failed",
                target: Some(&channel.calendar_id),
                success: false,
                error_message: Some(&redacted_err),
                // channel_uuid is the key the watch_channel_service
                // uses to join failures back to the list-view row.
                // Without it, the panel would have no way to show
                // a per-row "renewal failing" badge — the only
                // signal of OAuth / credential death would be the
                // expiration counter ticking down in silence.
                metadata: serde_json::json!({
                    "channel_uuid": channel.id.to_string(),
                    "google_channel_id": channel.channel_id,
                }),
            },
        )
        .await
        {
            tracing::error!(error = %db_err, "audit log insert failed");
        }
    }

    fn log_list_failed(&self, e: &anyhow::Error) {
        tracing::error!(error = %e, "Failed to list channels needing renewal");
    }
}

/// MCP-1156 (2026-05-16): shutdown-aware renewal loop.
///
/// Sibling fix to `talos_gmail::scheduler::gmail_renewal_task`. Pre-fix
/// the gcal channel renewal was an infinite `loop { tick.await; … }`
/// with no shutdown channel — controller SIGTERM force-aborted the
/// spawn mid-iteration, no operator-greppable shutdown event. Plumbed
/// the same `tokio::sync::watch::Receiver<bool>` that the gmail twin
/// uses (and that the MCP-994 bcrypt revocation sweep already uses)
/// so both Google integrations expose a uniform `*_shutdown` audit
/// event-kind for restart-boundary correlation.
pub async fn channel_renewal_task(
    service: Arc<GoogleCalendarService>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    run_renewal_scheduler(Arc::new(GcalRenewer(service)), shutdown_rx).await;
}
