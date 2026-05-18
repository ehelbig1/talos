use super::{GoogleCalendarService, WatchChannel};
use crate::google_calendar::api::GoogleCalendarApiClient;
use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
// sqlx types are used via fully qualified paths; the explicit import is unnecessary.
use uuid::Uuid;

impl GoogleCalendarService {
    /// Create a new watch channel for a calendar, or re-point an existing one.
    ///
    /// If an active watch channel already exists for the given
    /// (integration_id, calendar_id) pair, this method simply updates its
    /// `module_id` to the new module and returns without making a Google API
    /// call.  This avoids orphaned Google channels and ensures the new module
    /// starts receiving webhook events immediately.
    pub async fn create_watch_channel(
        &self,
        integration_id: Uuid,
        calendar_id: &str,
        webhook_url: &str,
        module_id: Option<Uuid>, // WASM module to execute when webhook arrives
    ) -> Result<WatchChannel> {
        // Validate webhook URL (HTTPS required in production)
        let is_production = std::env::var("ENVIRONMENT").unwrap_or_default() == "production";
        if is_production && !webhook_url.starts_with("https://") {
            anyhow::bail!("Webhook URL must use HTTPS in production environment");
        }

        // If an active channel already exists for this integration+calendar,
        // update its module_id and return it without touching the Google API.
        let existing = sqlx::query_as::<
            _,
            (
                Uuid,
                Uuid,
                String,
                String,
                String,
                String,
                DateTime<Utc>,
                Option<String>,
                String,
                bool,
                Option<Uuid>,
                DateTime<Utc>,
                DateTime<Utc>,
            ),
        >(
            "UPDATE google_calendar_watch_channels
             SET module_id = $3, updated_at = NOW()
             WHERE integration_id = $1 AND calendar_id = $2 AND is_active = true
             RETURNING id, integration_id, calendar_id, channel_id, resource_id,
                       webhook_url, expiration, sync_token, verification_token,
                       is_active, module_id, created_at, updated_at",
        )
        .bind(integration_id)
        .bind(calendar_id)
        .bind(module_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("Failed to check for existing watch channel")?;

        if let Some(row) = existing {
            tracing::info!(
                "♻️  Reusing existing watch channel for calendar '{}' (updating module_id → {:?})",
                calendar_id,
                module_id
            );
            return Ok(WatchChannel {
                id: row.0,
                integration_id: row.1,
                calendar_id: row.2,
                channel_id: row.3,
                resource_id: row.4,
                webhook_url: row.5,
                expiration: row.6,
                sync_token: row.7,
                verification_token: row.8,
                is_active: row.9,
                module_id: row.10,
                created_at: row.11,
                updated_at: row.12,
            });
        }

        // Get integration to get access token
        let integration = sqlx::query_as::<_, (Uuid, Uuid, Uuid, String, String, DateTime<Utc>, String, bool, DateTime<Utc>, DateTime<Utc>)>(
            "SELECT id, user_id, oauth_account_id, access_token, refresh_token, expires_at, scope, is_active, created_at, updated_at
             FROM google_calendar_integrations
             WHERE id = $1 AND is_active = true"
        )
        .bind(integration_id)
        .fetch_one(&self.db_pool)
        .await
        .context("Integration not found")?;

        let mut integration_obj = super::GoogleCalendarIntegration {
            id: integration.0,
            user_id: integration.1,
            oauth_account_id: integration.2,
            access_token: integration.3,
            refresh_token: integration.4,
            expires_at: integration.5,
            scope: integration.6,
            is_active: integration.7,
            created_at: integration.8,
            updated_at: integration.9,
        };

        // Refresh token if needed
        self.refresh_token_if_needed(&mut integration_obj).await?;

        // Generate secure random verification token (32 bytes = 64 hex chars)
        use rand::Rng;
        let verification_token: String = {
            let random_bytes: [u8; 32] = rand::thread_rng().gen();
            hex::encode(random_bytes)
        };

        // Create watch channel
        let api_client = GoogleCalendarApiClient::new();
        let channel_id = Uuid::new_v4().to_string();

        let watch_response = api_client
            .create_watch(
                &integration_obj.access_token,
                calendar_id,
                &channel_id,
                webhook_url,
                Some(&verification_token),
            )
            .await
            .context("Failed to create watch channel")?;

        // Parse expiration timestamp
        let expiration_ms = watch_response
            .expiration
            .parse::<i64>()
            .context("Invalid expiration timestamp")?;
        let expiration =
            DateTime::from_timestamp_millis(expiration_ms).context("Invalid expiration")?;

        // Store in database with verification token and module_id
        let channel = sqlx::query_as::<_, (Uuid, Uuid, String, String, String, String, DateTime<Utc>, Option<String>, String, bool, Option<Uuid>, DateTime<Utc>, DateTime<Utc>)>(
            "INSERT INTO google_calendar_watch_channels
             (integration_id, calendar_id, channel_id, resource_id, webhook_url, expiration, verification_token, module_id, is_active)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true)
             RETURNING id, integration_id, calendar_id, channel_id, resource_id, webhook_url, expiration, sync_token, verification_token, is_active, module_id, created_at, updated_at"
        )
        .bind(integration_id)
        .bind(calendar_id)
        .bind(&channel_id)
        .bind(&watch_response.resource_id)
        .bind(webhook_url)
        .bind(expiration)
        .bind(&verification_token)
        .bind(module_id)
        .fetch_one(&self.db_pool)
        .await
        .context("Failed to store watch channel")?;

        Ok(WatchChannel {
            id: channel.0,
            integration_id: channel.1,
            calendar_id: channel.2,
            channel_id: channel.3,
            resource_id: channel.4,
            webhook_url: channel.5,
            expiration: channel.6,
            sync_token: channel.7,
            verification_token: channel.8,
            is_active: channel.9,
            module_id: channel.10,
            created_at: channel.11,
            updated_at: channel.12,
        })
    }

    /// Renew a watch channel before it expires
    pub async fn renew_watch_channel(&self, channel_id: Uuid) -> Result<WatchChannel> {
        // Get existing channel
        let old_channel = sqlx::query_as::<_, (Uuid, Uuid, String, String, String, String, DateTime<Utc>, Option<String>, String, bool, Option<Uuid>, DateTime<Utc>, DateTime<Utc>)>(
            "SELECT id, integration_id, calendar_id, channel_id, resource_id, webhook_url, expiration, sync_token, verification_token, is_active, module_id, created_at, updated_at
             FROM google_calendar_watch_channels
             WHERE id = $1"
        )
        .bind(channel_id)
        .fetch_one(&self.db_pool)
        .await
        .context("Channel not found")?;

        // Stop old channel
        let integration = sqlx::query_as::<_, (Uuid, Uuid, Uuid, String, String, DateTime<Utc>, String, bool, DateTime<Utc>, DateTime<Utc>)>(
            "SELECT id, user_id, oauth_account_id, access_token, refresh_token, expires_at, scope, is_active, created_at, updated_at
             FROM google_calendar_integrations
             WHERE id = $1"
        )
        .bind(old_channel.1)
        .fetch_one(&self.db_pool)
        .await
        .context("Integration not found")?;

        let mut integration_obj = super::GoogleCalendarIntegration {
            id: integration.0,
            user_id: integration.1,
            oauth_account_id: integration.2,
            access_token: integration.3,
            refresh_token: integration.4,
            expires_at: integration.5,
            scope: integration.6,
            is_active: integration.7,
            created_at: integration.8,
            updated_at: integration.9,
        };

        self.refresh_token_if_needed(&mut integration_obj).await?;

        let api_client = GoogleCalendarApiClient::new();

        // Try to stop old channel (ignore errors if already expired)
        let _ = api_client
            .stop_watch(
                &integration_obj.access_token,
                &old_channel.3,
                &old_channel.4,
            )
            .await;

        // Create new channel (preserve module_id from old channel)
        let new_channel = self
            .create_watch_channel(
                old_channel.1,
                &old_channel.2,
                &old_channel.5,
                old_channel.10,
            )
            .await?;

        // Copy sync token from old channel
        if let Some(sync_token) = old_channel.7 {
            sqlx::query(
                "UPDATE google_calendar_watch_channels
                 SET sync_token = $1
                 WHERE id = $2",
            )
            .bind(&sync_token)
            .bind(new_channel.id)
            .execute(&self.db_pool)
            .await?;
        }

        // Deactivate old channel
        sqlx::query(
            "UPDATE google_calendar_watch_channels
             SET is_active = false
             WHERE id = $1",
        )
        .bind(channel_id)
        .execute(&self.db_pool)
        .await?;

        Ok(new_channel)
    }

    /// Get channels that need renewal (expire within 24 hours)
    pub async fn get_channels_needing_renewal(&self) -> Result<Vec<WatchChannel>> {
        let threshold = Utc::now() + Duration::hours(24);

        let channels = sqlx::query_as::<_, (Uuid, Uuid, String, String, String, String, DateTime<Utc>, Option<String>, String, bool, Option<Uuid>, DateTime<Utc>, DateTime<Utc>)>(
            "SELECT id, integration_id, calendar_id, channel_id, resource_id, webhook_url, expiration, sync_token, verification_token, is_active, module_id, created_at, updated_at
             FROM google_calendar_watch_channels
             WHERE is_active = true AND expiration < $1
             ORDER BY expiration ASC"
        )
        .bind(threshold)
        .fetch_all(&self.db_pool)
        .await?
        .into_iter()
        .map(|(id, integration_id, calendar_id, channel_id, resource_id, webhook_url, expiration, sync_token, verification_token, is_active, module_id, created_at, updated_at)| {
            WatchChannel {
                id,
                integration_id,
                calendar_id,
                channel_id,
                resource_id,
                webhook_url,
                expiration,
                sync_token,
                verification_token,
                is_active,
                module_id,
                created_at,
                updated_at,
            }
        })
        .collect();

        Ok(channels)
    }

    /// Sync events for a watch channel
    pub async fn sync_channel_events(&self, channel_id: Uuid) -> Result<Vec<serde_json::Value>> {
        // Get channel
        let channel = sqlx::query_as::<_, (Uuid, Uuid, String, String, String, String, DateTime<Utc>, Option<String>, String, bool, Option<Uuid>, DateTime<Utc>, DateTime<Utc>)>(
            "SELECT id, integration_id, calendar_id, channel_id, resource_id, webhook_url, expiration, sync_token, verification_token, is_active, module_id, created_at, updated_at
             FROM google_calendar_watch_channels
             WHERE id = $1"
        )
        .bind(channel_id)
        .fetch_one(&self.db_pool)
        .await
        .context("Channel not found")?;

        let channel_obj = WatchChannel {
            id: channel.0,
            integration_id: channel.1,
            calendar_id: channel.2,
            channel_id: channel.3,
            resource_id: channel.4,
            webhook_url: channel.5,
            expiration: channel.6,
            sync_token: channel.7,
            verification_token: channel.8,
            is_active: channel.9,
            module_id: channel.10,
            created_at: channel.11,
            updated_at: channel.12,
        };

        // Get integration
        let integration = sqlx::query_as::<_, (Uuid, Uuid, Uuid, String, String, DateTime<Utc>, String, bool, DateTime<Utc>, DateTime<Utc>)>(
            "SELECT id, user_id, oauth_account_id, access_token, refresh_token, expires_at, scope, is_active, created_at, updated_at
             FROM google_calendar_integrations
             WHERE id = $1"
        )
        .bind(channel_obj.integration_id)
        .fetch_one(&self.db_pool)
        .await
        .context("Integration not found")?;

        let mut integration_obj = super::GoogleCalendarIntegration {
            id: integration.0,
            user_id: integration.1,
            oauth_account_id: integration.2,
            access_token: integration.3,
            refresh_token: integration.4,
            expires_at: integration.5,
            scope: integration.6,
            is_active: integration.7,
            created_at: integration.8,
            updated_at: integration.9,
        };

        self.refresh_token_if_needed(&mut integration_obj).await?;

        // Sync events
        let api_client = GoogleCalendarApiClient::new();
        let (events, new_sync_token) = api_client
            .sync_events(
                &integration_obj.access_token,
                &channel_obj.calendar_id,
                channel_obj.sync_token.as_deref(),
            )
            .await
            .context("Failed to sync events")?;

        // Update sync token
        sqlx::query(
            "UPDATE google_calendar_watch_channels
             SET sync_token = $1, updated_at = NOW()
             WHERE id = $2",
        )
        .bind(&new_sync_token)
        .bind(channel_id)
        .execute(&self.db_pool)
        .await?;

        // Convert events to JSON
        let events_json: Vec<serde_json::Value> = events
            .into_iter()
            .map(|e| serde_json::to_value(e).unwrap_or(serde_json::json!({})))
            .collect();

        Ok(events_json)
    }

    /// Stop a watch channel
    pub async fn stop_watch_channel(&self, channel_id: Uuid) -> Result<()> {
        // Get channel
        let channel = sqlx::query_as::<_, (Uuid, Uuid, String, String, String, String, DateTime<Utc>, Option<String>, String, bool, Option<Uuid>, DateTime<Utc>, DateTime<Utc>)>(
            "SELECT id, integration_id, calendar_id, channel_id, resource_id, webhook_url, expiration, sync_token, verification_token, is_active, module_id, created_at, updated_at
             FROM google_calendar_watch_channels
             WHERE id = $1"
        )
        .bind(channel_id)
        .fetch_one(&self.db_pool)
        .await
        .context("Channel not found")?;

        // Get integration
        let integration = sqlx::query_as::<_, (Uuid, Uuid, Uuid, String, String, DateTime<Utc>, String, bool, DateTime<Utc>, DateTime<Utc>)>(
            "SELECT id, user_id, oauth_account_id, access_token, refresh_token, expires_at, scope, is_active, created_at, updated_at
             FROM google_calendar_integrations
             WHERE id = $1"
        )
        .bind(channel.1)
        .fetch_one(&self.db_pool)
        .await
        .context("Integration not found")?;

        let mut integration_obj = super::GoogleCalendarIntegration {
            id: integration.0,
            user_id: integration.1,
            oauth_account_id: integration.2,
            access_token: integration.3,
            refresh_token: integration.4,
            expires_at: integration.5,
            scope: integration.6,
            is_active: integration.7,
            created_at: integration.8,
            updated_at: integration.9,
        };

        self.refresh_token_if_needed(&mut integration_obj).await?;

        // Stop channel via API
        let api_client = GoogleCalendarApiClient::new();
        api_client
            .stop_watch(&integration_obj.access_token, &channel.3, &channel.4)
            .await?;

        // Mark as inactive
        sqlx::query(
            "UPDATE google_calendar_watch_channels
             SET is_active = false, updated_at = NOW()
             WHERE id = $1",
        )
        .bind(channel_id)
        .execute(&self.db_pool)
        .await?;

        Ok(())
    }
}
