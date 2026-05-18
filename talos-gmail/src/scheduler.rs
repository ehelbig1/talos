//! Hourly Gmail watch-channel renewal task.
//!
//! Gmail `users.watch` subscriptions expire every 7 days (Google's
//! hard cap). This task lists every watch row expiring within the
//! next 24 hours and renews it, mirroring the gcal scheduler pattern.

use super::watch::GmailWatchService;
use std::sync::Arc;
use tokio::time::{interval, Duration};

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
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let mut tick = interval(Duration::from_secs(3600));

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                tracing::info!(
                    target: "talos_audit",
                    event_kind = "gmail_renewal_task_shutdown",
                    "Gmail watch renewal task shutting down (clean)"
                );
                return;
            }
            _ = tick.tick() => {}
        }

        tracing::info!("🔄 Running Gmail watch renewal task");

        match service.get_watches_needing_renewal().await {
            Ok(rows) => {
                if rows.is_empty() {
                    tracing::debug!("No gmail watches need renewal");
                    continue;
                }
                tracing::info!(count = rows.len(), "gmail watches needing renewal");

                for (user_id, row) in rows {
                    tracing::info!(
                        channel_uuid = %row.id,
                        email = %row.email_address,
                        %user_id,
                        "🔁 Renewing gmail watch"
                    );
                    match service.renew_watch(user_id, row.id).await {
                        Ok(new) => {
                            tracing::info!(
                                new_expiration_ms = %new.expiration_ms,
                                "✅ gmail watch renewed"
                            );
                            if let Err(db_err) = sqlx::query(
                                "INSERT INTO google_calendar_audit_log \
                                 (integration_id, user_id, event_type, calendar_id, success, metadata) \
                                 VALUES ($1, $2, $3, $4, $5, $6)",
                            )
                            .bind(new.integration_id)
                            .bind(user_id)
                            .bind("gmail_channel_renewed")
                            .bind(&new.email_address)
                            .bind(true)
                            .bind(serde_json::json!({
                                "old_channel_uuid": row.id.to_string(),
                                "new_channel_uuid": new.id.to_string(),
                                "new_expiration_ms": new.expiration_ms,
                            }))
                            .execute(&service.pool)
                            .await
                            {
                                tracing::error!(error = %db_err, "audit log insert failed");
                            }
                        }
                        Err(e) => {
                            tracing::error!(
                                channel_uuid = %row.id,
                                error = %e,
                                "gmail watch renewal failed"
                            );
                            // MCP-980 (2026-05-15): DLP-redact Google
                            // API error before persistence into the
                            // audit log's error_message column. The
                            // gmail/gcal watch-renew flow exchanges
                            // OAuth tokens against Google's APIs, and
                            // failure responses on that path commonly
                            // echo `invalid_token`, `invalid_grant`
                            // with the offending refresh_token bytes
                            // in the error description for diagnostic
                            // purposes. Same arbitrary-text DLP class
                            // as MCP-967..979 sweep. Sibling tracing
                            // log redaction already isn't needed
                            // (the `error = %e` shape ships the
                            // server-side tracing pipeline only;
                            // operator-trust scope).
                            //
                            // MCP-1181 (2026-05-17): truncate-first at
                            // 1 KiB before redact_str so a verbose
                            // Google API error envelope can't amplify
                            // regex-pass cost or blow past reasonable
                            // column-storage size. Last site in the
                            // google_calendar_audit_log writer sweep
                            // (siblings: gcal scheduler.rs, gcal
                            // watch.rs, gmail watch.rs), mirroring the
                            // MCP-1028 truncate-first pattern from
                            // gmail_integration_audit_log writers.
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
                            .bind(row.integration_id)
                            .bind(user_id)
                            .bind("gmail_channel_renewal_failed")
                            .bind(&row.email_address)
                            .bind(false)
                            .bind(&redacted_err)
                            .bind(serde_json::json!({
                                "channel_uuid": row.id.to_string(),
                                "topic_name": row.topic_name,
                            }))
                            .execute(&service.pool)
                            .await
                            {
                                tracing::error!(error = %db_err, "audit log insert failed");
                            }
                        }
                    }
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to list gmail watches needing renewal");
            }
        }
    }
}
