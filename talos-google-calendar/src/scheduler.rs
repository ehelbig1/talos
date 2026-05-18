//! Google Calendar watch-channel renewal background task.
//!
//! Runs hourly, lists all channels whose `integration_state.idx_ts_1`
//! (stored expiration) falls within the next 24 hours, and re-creates
//! them. Audit rows go to `google_calendar_audit_log`.
//!
//! Channel storage lives in `integration_state` (integration_name =
//! `"gcal"`) — the scheduler uses the `WatchService` facade in
//! `watch.rs`.

use super::GoogleCalendarService;
use std::sync::Arc;
use tokio::time::{interval, Duration};

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
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let mut interval = interval(Duration::from_secs(3600)); // every hour

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                tracing::info!(
                    target: "talos_audit",
                    event_kind = "gcal_renewal_task_shutdown",
                    "Google Calendar channel renewal task shutting down (clean)"
                );
                return;
            }
            _ = interval.tick() => {}
        }

        tracing::info!("🔄 Running Google Calendar channel renewal task");

        match service.get_channels_needing_renewal().await {
            Ok(channels) => {
                if channels.is_empty() {
                    tracing::debug!("No gcal channels need renewal");
                    continue;
                }

                tracing::info!(count = channels.len(), "gcal channels needing renewal");

                for (user_id, channel) in channels {
                    tracing::info!(
                        channel_uuid = %channel.id,
                        calendar = %channel.calendar_id,
                        %user_id,
                        "🔁 Renewing gcal watch channel"
                    );

                    match service.renew_watch_channel(user_id, channel.id).await {
                        Ok(new_channel) => {
                            tracing::info!(
                                new_expiration = %new_channel.expiration,
                                "✅ gcal channel renewed"
                            );

                            if let Err(db_err) = sqlx::query(
                                "INSERT INTO google_calendar_audit_log \
                                 (integration_id, user_id, event_type, calendar_id, success, metadata) \
                                 VALUES ($1, $2, $3, $4, $5, $6)",
                            )
                            .bind(new_channel.integration_id)
                            .bind(user_id)
                            .bind("channel_renewed")
                            .bind(&new_channel.calendar_id)
                            .bind(true)
                            .bind(serde_json::json!({
                                "old_channel_id": channel.channel_id,
                                "new_channel_id": new_channel.channel_id,
                                "new_expiration": new_channel.expiration,
                            }))
                            .execute(&service.db_pool)
                            .await
                            {
                                tracing::error!(error = %db_err, "audit log insert failed");
                            }
                        }
                        Err(e) => {
                            tracing::error!(
                                channel_uuid = %channel.id,
                                error = %e,
                                "gcal channel renewal failed"
                            );

                            // MCP-980: DLP-redact Google API error
                            // before audit-log persist. Sibling of
                            // the gmail/scheduler.rs site — same
                            // OAuth-error-bytes-in-error_description
                            // class.
                            //
                            // MCP-1181 (2026-05-17): truncate AT 1 KiB
                            // BEFORE redact_str so a verbose Google
                            // error envelope can't blow up the regex-
                            // pass cost AND can't blow past reasonable
                            // column-storage size. Matches the
                            // truncate-first discipline applied in
                            // MCP-1028 for `gmail_integration_audit_log
                            // .error_message` and `slack_integration_
                            // audit_log.error_message`; the
                            // `google_calendar_audit_log.error_message`
                            // writers were the holdouts.
                            let raw_err = e.to_string();
                            let truncated_err: &str = if raw_err.len() > 1024 {
                                talos_text_util::truncate_at_char_boundary(&raw_err, 1024)
                            } else {
                                &raw_err
                            };
                            let redacted_err = talos_dlp_provider::redact_str(truncated_err);
                            if let Err(db_err) = sqlx::query(
                                "INSERT INTO google_calendar_audit_log \
                                 (integration_id, user_id, event_type, calendar_id, success, error_message, metadata) \
                                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
                            )
                            .bind(channel.integration_id)
                            .bind(user_id)
                            .bind("channel_renewal_failed")
                            .bind(&channel.calendar_id)
                            .bind(false)
                            .bind(&redacted_err)
                            // channel_uuid is the key the watch_channel_service
                            // uses to join failures back to the list-view row.
                            // Without it, the panel would have no way to show
                            // a per-row "renewal failing" badge — the only
                            // signal of OAuth / credential death would be the
                            // expiration counter ticking down in silence.
                            .bind(serde_json::json!({
                                "channel_uuid": channel.id.to_string(),
                                "google_channel_id": channel.channel_id,
                            }))
                            .execute(&service.db_pool)
                            .await
                            {
                                tracing::error!(error = %db_err, "audit log insert failed");
                            }
                        }
                    }
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to list channels needing renewal");
            }
        }
    }
}
