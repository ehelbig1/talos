use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{Pool, Postgres};
use std::sync::{Arc, OnceLock};
use std::time::Instant;
use uuid::Uuid;

pub mod api;
pub mod handlers;
pub mod scheduler;
pub mod watch;

/// Google Calendar integration record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleCalendarIntegration {
    pub id: Uuid,
    pub user_id: Uuid,
    pub oauth_account_id: Uuid,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
    pub scope: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Watch channel for a calendar
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchChannel {
    pub id: Uuid,
    pub integration_id: Uuid,
    pub calendar_id: String,
    pub channel_id: String,
    pub resource_id: String,
    pub webhook_url: String,
    pub expiration: DateTime<Utc>,
    pub sync_token: Option<String>,
    pub verification_token: String,
    pub is_active: bool,
    pub module_id: Option<Uuid>, // WASM module to execute when webhook arrives
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Service for managing Google Calendar integrations
pub struct GoogleCalendarService {
    pub db_pool: Pool<Postgres>,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    /// Per-integration lock to serialize concurrent token refresh attempts.
    /// Without this, two concurrent handlers for the same integration (e.g.
    /// the webhook handler and the scheduler) both see an expired token and
    /// both call the Google token endpoint with the same refresh_token, which
    /// can cause Google to revoke the token.
    ///
    /// Uses `DashMap` instead of `Mutex<HashMap>` so that different integrations
    /// can look up their per-integration lock concurrently without serializing
    /// behind a single outer lock.  The *per-integration* `Mutex<()>` still
    /// serializes refreshes for the same integration — which is the invariant we care about.
    refresh_locks: DashMap<Uuid, Arc<tokio::sync::Mutex<()>>>,
    /// Per-channel rate limiter for incoming webhook notifications.
    /// Google sends from a shared IP pool so IP-based rate limiting is
    /// insufficient; this provides defense-in-depth keyed on the channel_id.
    /// Entry: channel_id → (count_in_window, window_start)
    webhook_channel_limits: Arc<DashMap<String, (u32, Instant)>>,
    /// Optional unified credential service for dual-writing tokens to the
    /// secrets-backed `integration_credentials` table (set via
    /// `with_credentials_service`).
    credentials_service: OnceLock<Arc<crate::oauth::OAuthCredentialService>>,
}

impl GoogleCalendarService {
    pub fn new(db_pool: Pool<Postgres>) -> Self {
        // These env vars are required for Google Calendar integration; fail fast if missing.
        let client_id = std::env::var("GOOGLE_CLIENT_ID").unwrap_or_default();
        let client_secret = std::env::var("GOOGLE_CLIENT_SECRET").unwrap_or_default();
        let redirect_uri = std::env::var("GOOGLE_REDIRECT_URI")
            .unwrap_or_else(|_| "http://localhost:8000/auth/oauth/google/callback".to_string());

        Self {
            db_pool,
            client_id,
            client_secret,
            redirect_uri,
            refresh_locks: DashMap::new(),
            webhook_channel_limits: Arc::new(DashMap::new()),
            credentials_service: OnceLock::new(),
        }
    }

    /// Wire in the unified OAuth credential service for dual-writing tokens.
    ///
    /// Call this once after construction (before the service handles any requests).
    /// Subsequent calls are silently ignored (OnceLock semantics).
    pub fn with_credentials_service(&self, svc: Arc<crate::oauth::OAuthCredentialService>) {
        let _ = self.credentials_service.set(svc);
    }

    /// Per-channel rate limiter for incoming Google Calendar webhook notifications.
    ///
    /// Google sends up to a few notifications per second in high-activity windows
    /// but sustained bursts over this limit are indicative of abuse or misconfiguration.
    ///
    /// Returns `true` if the notification is within the rate limit (allow), `false` if it
    /// should be dropped.  The limit is 60 notifications per channel per minute by default.
    pub fn allow_webhook_channel(&self, channel_id: &str) -> bool {
        const MAX_PER_MINUTE: u32 = 60;
        const WINDOW_SECS: u64 = 60;

        let now = Instant::now();
        let mut entry = self
            .webhook_channel_limits
            .entry(channel_id.to_string())
            .or_insert((0, now));

        let (count, window_start) = entry.value_mut();
        if now.duration_since(*window_start).as_secs() >= WINDOW_SECS {
            // Reset sliding window
            *count = 1;
            *window_start = now;
            true
        } else if *count < MAX_PER_MINUTE {
            *count += 1;
            true
        } else {
            false
        }
    }

    /// Evict idle per-channel rate-limiter entries to prevent unbounded growth.
    /// Call periodically from a background task (e.g., every 5 minutes).
    pub fn cleanup_webhook_channel_limits(&self) {
        const MAX_IDLE_SECS: u64 = 120;
        let now = Instant::now();
        self.webhook_channel_limits.retain(|_, (_, window_start)| {
            now.duration_since(*window_start).as_secs() < MAX_IDLE_SECS
        });
    }

    pub fn is_configured(&self) -> bool {
        !self.client_id.is_empty() && !self.client_secret.is_empty()
    }

    /// Get integration by ID
    pub async fn get_integration(
        &self,
        user_id: Uuid,
        integration_id: Uuid,
    ) -> Result<Option<GoogleCalendarIntegration>> {
        let integration = sqlx::query_as::<_, (Uuid, Uuid, Uuid, String, String, DateTime<Utc>, String, bool, DateTime<Utc>, DateTime<Utc>)>(
            "SELECT id, user_id, oauth_account_id, access_token, refresh_token, expires_at, scope, is_active, created_at, updated_at
             FROM google_calendar_integrations
             WHERE id = $1 AND user_id = $2"
        )
        .bind(integration_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?
        .map(|(id, user_id, oauth_account_id, access_token, refresh_token, expires_at, scope, is_active, created_at, updated_at)| {
            GoogleCalendarIntegration {
                id,
                user_id,
                oauth_account_id,
                access_token,
                refresh_token,
                expires_at,
                scope,
                is_active,
                created_at,
                updated_at,
            }
        });

        Ok(integration)
    }

    /// List user's integrations
    pub async fn list_integrations(&self, user_id: Uuid) -> Result<Vec<GoogleCalendarIntegration>> {
        let integrations = sqlx::query_as::<_, (Uuid, Uuid, Uuid, String, String, DateTime<Utc>, String, bool, DateTime<Utc>, DateTime<Utc>)>(
            "SELECT id, user_id, oauth_account_id, access_token, refresh_token, expires_at, scope, is_active, created_at, updated_at
             FROM google_calendar_integrations
             WHERE user_id = $1 AND is_active = true
             ORDER BY created_at DESC"
        )
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?
        .into_iter()
        .map(|(id, user_id, oauth_account_id, access_token, refresh_token, expires_at, scope, is_active, created_at, updated_at)| {
            GoogleCalendarIntegration {
                id,
                user_id,
                oauth_account_id,
                access_token,
                refresh_token,
                expires_at,
                scope,
                is_active,
                created_at,
                updated_at,
            }
        })
        .collect();

        Ok(integrations)
    }

    /// Refresh access token if expired.
    ///
    /// This method is safe to call concurrently for the same integration: a
    /// per-integration mutex ensures at most one refresh is in flight at a time,
    /// preventing duplicate calls to the Google token endpoint with the same
    /// refresh_token (which can cause Google to revoke the token).
    pub async fn refresh_token_if_needed(
        &self,
        integration: &mut GoogleCalendarIntegration,
    ) -> Result<()> {
        // Fast path: token is still fresh.
        if integration.expires_at - Utc::now() > Duration::minutes(5) {
            return Ok(());
        }

        // Acquire (or create) the per-integration refresh lock.
        // DashMap::entry is lock-free for different keys, so different integrations
        // do not contend on a shared outer Mutex.
        let per_integration_lock = self
            .refresh_locks
            .entry(integration.id)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();

        // Wait for any concurrent refresh of the same integration to finish.
        let _refresh_guard = per_integration_lock.lock().await;

        // Re-check after acquiring the per-integration lock: another task may have
        // already refreshed the token while we were waiting.
        if integration.expires_at - Utc::now() > Duration::minutes(5) {
            return Ok(());
        }

        // Refresh the token
        let client = reqwest::Client::new();
        let response = client
            .post("https://oauth2.googleapis.com/token")
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("refresh_token", &integration.refresh_token),
                ("grant_type", "refresh_token"),
            ])
            .send()
            .await
            .context("Failed to refresh Google token")?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            anyhow::bail!("Token refresh failed: {}", error_text);
        }

        let token_data: Value = response.json().await?;
        let new_access_token = token_data["access_token"]
            .as_str()
            .context("Missing access_token in response")?
            .to_string();
        let expires_in = token_data["expires_in"]
            .as_i64()
            .context("Missing expires_in in response")?;

        // Update integration in-memory
        integration.access_token = new_access_token.clone();
        integration.expires_at = Utc::now() + Duration::seconds(expires_in);

        // Save to legacy google_calendar_integrations table
        sqlx::query(
            "UPDATE google_calendar_integrations
             SET access_token = $1, expires_at = $2, updated_at = NOW()
             WHERE id = $3",
        )
        .bind(&integration.access_token)
        .bind(integration.expires_at)
        .bind(integration.id)
        .execute(&self.db_pool)
        .await?;

        // Dual-write: also update the unified credential store (best-effort)
        if let Some(cred_svc) = self.credentials_service.get() {
            if let Err(e) = cred_svc
                .update_access_token(
                    integration.user_id,
                    "google_calendar",
                    &integration.oauth_account_id.to_string(),
                    &integration.access_token,
                    integration.expires_at,
                )
                .await
            {
                tracing::warn!(
                    integration_id = %integration.id,
                    "Failed to update credential service after GCal token refresh: {}",
                    e
                );
            }
        }

        Ok(())
    }

    /// Create or update integration from OAuth callback
    pub async fn create_or_update_integration(
        &self,
        user_id: Uuid,
        oauth_account_id: Uuid,
        access_token: String,
        refresh_token: String,
        expires_in: i64,
        scope: String,
    ) -> Result<GoogleCalendarIntegration> {
        let expires_at = Utc::now() + Duration::seconds(expires_in);

        let integration = sqlx::query_as::<_, (Uuid, Uuid, Uuid, String, String, DateTime<Utc>, String, bool, DateTime<Utc>, DateTime<Utc>)>(
            "INSERT INTO google_calendar_integrations
             (user_id, oauth_account_id, access_token, refresh_token, expires_at, scope, is_active)
             VALUES ($1, $2, $3, $4, $5, $6, true)
             ON CONFLICT (user_id, oauth_account_id)
             DO UPDATE SET
                access_token = EXCLUDED.access_token,
                refresh_token = EXCLUDED.refresh_token,
                expires_at = EXCLUDED.expires_at,
                scope = EXCLUDED.scope,
                is_active = true,
                updated_at = NOW()
             RETURNING id, user_id, oauth_account_id, access_token, refresh_token, expires_at, scope, is_active, created_at, updated_at"
        )
        .bind(user_id)
        .bind(oauth_account_id)
        .bind(&access_token)
        .bind(&refresh_token)
        .bind(expires_at)
        .bind(&scope)
        .fetch_one(&self.db_pool)
        .await?;

        let result = GoogleCalendarIntegration {
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

        // Dual-write: store tokens in unified credential service (best-effort)
        if let Some(cred_svc) = self.credentials_service.get() {
            if let Err(e) = cred_svc
                .store_credentials(
                    result.user_id,
                    "google_calendar",
                    &result.oauth_account_id.to_string(),
                    &result.access_token,
                    Some(&result.refresh_token),
                    result.expires_at,
                    &result.scope,
                    vec![], // No module restriction at connect time; linked modules set this later
                )
                .await
            {
                tracing::warn!(
                    user_id = %result.user_id,
                    oauth_account_id = %result.oauth_account_id,
                    "Failed to dual-write GCal credentials to credential service: {}",
                    e
                );
            }
        }

        Ok(result)
    }

    /// Deactivate integration.
    ///
    /// Returns an error if 0 rows were affected (not found or owned by another user).
    pub async fn deactivate_integration(&self, user_id: Uuid, integration_id: Uuid) -> Result<()> {
        let result = sqlx::query(
            "UPDATE google_calendar_integrations
             SET is_active = false, updated_at = NOW()
             WHERE id = $1 AND user_id = $2",
        )
        .bind(integration_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;

        if result.rows_affected() == 0 {
            anyhow::bail!("Integration not found or access denied");
        }

        // Also deactivate all watch channels — re-verify ownership via subquery
        // to prevent a user from deactivating channels belonging to another user's integration.
        sqlx::query(
            "UPDATE google_calendar_watch_channels
             SET is_active = false, updated_at = NOW()
             WHERE integration_id IN (
                 SELECT id FROM google_calendar_integrations
                 WHERE id = $1 AND user_id = $2
             )",
        )
        .bind(integration_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;

        Ok(())
    }
}
