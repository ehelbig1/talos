use super::GoogleCalendarService;
use std::sync::Arc;
use tokio::time::{interval, Duration};

/// Background task that renews Google Calendar watch channels before they expire
pub async fn channel_renewal_task(service: Arc<GoogleCalendarService>) {
    let mut interval = interval(Duration::from_secs(3600)); // Run every hour

    loop {
        interval.tick().await;

        tracing::info!("🔄 Running Google Calendar channel renewal task");

        match service.get_channels_needing_renewal().await {
            Ok(channels) => {
                if channels.is_empty() {
                    tracing::debug!("No channels need renewal");
                    continue;
                }

                tracing::info!("📋 Found {} channels needing renewal", channels.len());

                for channel in channels {
                    tracing::info!(
                        "🔁 Renewing channel {} for calendar {}",
                        channel.id,
                        channel.calendar_id
                    );

                    match service.renew_watch_channel(channel.id).await {
                        Ok(new_channel) => {
                            tracing::info!(
                                "✅ Successfully renewed channel. New expiration: {}",
                                new_channel.expiration
                            );

                            // Log to audit table
                            if let Err(db_err) = sqlx::query(
                                "INSERT INTO google_calendar_audit_log
                                 (integration_id, event_type, calendar_id, success, metadata)
                                 VALUES ($1, $2, $3, $4, $5)",
                            )
                            .bind(new_channel.integration_id)
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
                                tracing::error!("Database operation failed: {}", db_err);
                            }
                        }
                        Err(e) => {
                            tracing::error!("❌ Failed to renew channel {}: {}", channel.id, e);

                            // Log failure to audit table
                            if let Err(db_err) = sqlx::query(
                                "INSERT INTO google_calendar_audit_log
                                 (integration_id, event_type, calendar_id, success, error_message)
                                 VALUES ($1, $2, $3, $4, $5)",
                            )
                            .bind(channel.integration_id)
                            .bind("channel_renewal_failed")
                            .bind(&channel.calendar_id)
                            .bind(false)
                            .bind(e.to_string())
                            .execute(&service.db_pool)
                            .await
                            {
                                tracing::error!("Database operation failed: {}", db_err);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                tracing::error!("❌ Failed to get channels needing renewal: {}", e);
            }
        }
    }
}
