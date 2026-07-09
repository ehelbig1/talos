use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use sqlx::{Pool, Postgres};
use std::sync::{Arc, OnceLock};
use std::time::Instant;
use uuid::Uuid;

pub mod admin;
pub mod api;
pub mod handlers;
pub mod scheduler;
pub mod watch;
pub mod watch_channel_service;
pub mod webhook_token;

/// Google Calendar integration metadata.
///
/// Tokens are NOT stored here — they live exclusively in the unified
/// `integration_credentials` table and are accessed via the
/// `OAuthCredentialService` / `SecretsManager`. This matches the
/// Atlassian integration pattern and ensures a single refresh path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleCalendarIntegration {
    pub id: Uuid,
    pub user_id: Uuid,
    pub oauth_account_id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub scope: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Ownership probe: does `user_id` own an ACTIVE integration `integration_id`?
///
/// Takes the caller's pool explicitly so callers that only have a pool (not a
/// constructed `GoogleCalendarService`) can run the check — e.g. the GraphQL
/// `create_module_from_template` auto-setup path, which must verify ownership
/// BEFORE creating watch channels with the integration's credentials, and must
/// distinguish "not owned" (security event) from a DB probe failure (the
/// caller maps `Err` separately — see MCP-840).
pub async fn user_owns_active_integration(
    pool: &Pool<Postgres>,
    integration_id: Uuid,
    user_id: Uuid,
) -> Result<bool> {
    let owned: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM google_calendar_integrations
            WHERE id = $1 AND user_id = $2 AND is_active = true
        )",
    )
    .bind(integration_id)
    .bind(user_id)
    .fetch_one(pool)
    .await
    .context("failed to probe google_calendar_integrations ownership")?;
    Ok(owned)
}

/// Watch channel for a calendar
#[derive(Clone, Serialize, Deserialize)]
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

// Custom Debug so a stray `{:?}` never prints `verification_token` — the
// X-Goog-Channel-Token shared secret used to authenticate inbound Google
// Calendar webhooks. The Serialize impl (DB/API round-trips) is unaffected.
impl std::fmt::Debug for WatchChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WatchChannel")
            .field("id", &self.id)
            .field("integration_id", &self.integration_id)
            .field("calendar_id", &self.calendar_id)
            .field("channel_id", &self.channel_id)
            .field("resource_id", &self.resource_id)
            .field("webhook_url", &self.webhook_url)
            .field("expiration", &self.expiration)
            .field("sync_token", &self.sync_token)
            .field("verification_token", &"[REDACTED]")
            .field("is_active", &self.is_active)
            .field("module_id", &self.module_id)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

/// Service for managing Google Calendar integrations
pub struct GoogleCalendarService {
    pub db_pool: Pool<Postgres>,
    /// Shared SecretsManager from `McpState` / app init. MUST be the
    /// same instance used everywhere else in the controller — the
    /// per-call fresh-instance pattern we used pre-r233 silently loaded
    /// an env-derived KEK that diverged from the production Vault/KMS-
    /// backed KEK on every deployment that used a non-env KEK provider,
    /// causing OAuth-token DEK unwrap to fail at WARN level and tokens
    /// to come back empty. Centralising on the shared instance closes
    /// the door (`scripts/lint-structural.sh` check 4 enforces this
    /// for new code).
    pub(crate) secrets_manager: Arc<talos_secrets_manager::SecretsManager>,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    /// Redirect URI for the DEDICATED Calendar OAuth connect flow
    /// (`/api/google-calendar/callback`), distinct from `redirect_uri`
    /// (the SSO-login callback `/auth/oauth/google/callback`). The
    /// dedicated flow avoids the SSO account-link guard that 500s for
    /// existing password accounts. Read from `GOOGLE_CALENDAR_REDIRECT_URI`.
    /// Must be registered as an Authorized redirect URI on the Google
    /// OAuth client alongside the SSO one.
    pub connect_redirect_uri: String,
    // Token refresh locks removed — refresh is now handled entirely by
    // the centralized OAuthCredentialService which has its own per-
    // credential DashMap lock keyed on "provider:user_id:provider_key".
    /// Per-channel rate limiter for incoming webhook notifications.
    /// Google sends from a shared IP pool so IP-based rate limiting is
    /// insufficient; this provides defense-in-depth keyed on the channel_id.
    /// Entry: channel_id → (count_in_window, window_start)
    webhook_channel_limits: Arc<DashMap<String, (u32, Instant)>>,
    /// Optional unified credential service for dual-writing tokens to the
    /// secrets-backed `integration_credentials` table (set via
    /// `with_credentials_service`).
    credentials_service: OnceLock<Arc<talos_oauth::OAuthCredentialService>>,
    /// Worker shared HMAC key, used to sign + verify Google Calendar
    /// webhook tokens. Set via `with_worker_shared_key` at startup.
    /// Without it, `create_watch_channel` fails closed — signed tokens
    /// are required for every channel we register with Google.
    pub(crate) shared_key: OnceLock<Vec<u8>>,
    /// Per-`(user_id, integration_id, calendar_id)` serialization lock
    /// for `create_watch_channel`. Without it, two concurrent calls
    /// for the same calendar both see "no existing channel" and both
    /// issue a Google API create — leaving one orphaned Google-side
    /// channel and a last-writer-wins row in integration_state.
    ///
    /// The lock is process-local; cross-controller coordination would
    /// require a Redis lock or DB advisory lock. Single-controller is
    /// the current deployment, so the DashMap-backed
    /// `talos_integration_helpers::state_store::CreateLockMap` suffices.
    pub(crate) create_channel_locks:
        talos_integration_helpers::state_store::CreateLockMap<(Uuid, Uuid, String)>,
}

impl GoogleCalendarService {
    pub fn new(
        db_pool: Pool<Postgres>,
        secrets_manager: Arc<talos_secrets_manager::SecretsManager>,
    ) -> Self {
        // These env vars are required for Google Calendar integration; fail fast if missing.
        let client_id = std::env::var("GOOGLE_CLIENT_ID").unwrap_or_default();
        let client_secret = std::env::var("GOOGLE_CLIENT_SECRET").unwrap_or_default();
        let redirect_uri = std::env::var("GOOGLE_REDIRECT_URI")
            .unwrap_or_else(|_| "http://localhost:8000/auth/oauth/google/callback".to_string());
        // Dedicated Calendar connect callback (distinct from the SSO one above).
        // Empty env → default; treat blank as unset (empty-env class).
        let connect_redirect_uri = std::env::var("GOOGLE_CALENDAR_REDIRECT_URI")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| "http://localhost:8000/api/google-calendar/callback".to_string());

        Self {
            db_pool,
            secrets_manager,
            client_id,
            client_secret,
            redirect_uri,
            connect_redirect_uri,
            webhook_channel_limits: Arc::new(DashMap::new()),
            credentials_service: OnceLock::new(),
            shared_key: OnceLock::new(),
            create_channel_locks: talos_integration_helpers::state_store::CreateLockMap::new(),
        }
    }

    /// Wire in the unified OAuth credential service for dual-writing tokens.
    ///
    /// Call this once after construction (before the service handles any requests).
    /// Subsequent calls are silently ignored (OnceLock semantics).
    pub fn with_credentials_service(&self, svc: Arc<talos_oauth::OAuthCredentialService>) {
        let _ = self.credentials_service.set(svc);
    }

    /// Wire in the worker shared HMAC key used for webhook-token
    /// signing + verification. Call once at startup, before any
    /// watch channels are created.
    ///
    /// Rejects empty keys: HMAC-SHA256 accepts any key length including
    /// zero, but an empty key means the MAC is computed from publicly
    /// known data only — trivially forgeable by anyone who can read
    /// the sign/verify code. Returns `Err` at startup instead of
    /// silently accepting a keyless deployment.
    pub fn with_worker_shared_key(&self, key: Vec<u8>) -> Result<()> {
        if key.len() < 16 {
            anyhow::bail!(
                "WORKER_SHARED_KEY must be at least 16 bytes (got {}); aborting startup",
                key.len()
            );
        }
        let _ = self.shared_key.set(key);
        Ok(())
    }

    /// Evict idle entries from the `create_channel_locks` DashMap.
    /// Called periodically so an environment that churns through
    /// integrations doesn't accumulate one tokio::Mutex per (user,
    /// integration, calendar) tuple forever.
    ///
    /// Uses `Arc::strong_count == 1` as the liveness signal: if no
    /// other task is currently holding an Arc clone of the lock, we
    /// can safely drop our entry. A call that takes the lock will
    /// re-create it on demand.
    pub fn cleanup_create_channel_locks(&self) {
        self.create_channel_locks.cleanup();
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

    /// Generate the Google Calendar OAuth authorization URL for the DEDICATED
    /// connect flow. `user_id` is bound into the CSRF state token so the
    /// callback recovers identity from the token — never a session cookie
    /// (see the `OAuthIntegration` impl for the anti-hijack rationale).
    /// Returns `(authorization_url, csrf_state_token)`.
    pub async fn get_authorization_url(&self, user_id: Uuid) -> Result<(String, String)> {
        talos_oauth::authorization_url(&self.db_pool, self, user_id).await
    }

    /// Handle the dedicated Calendar OAuth callback: the shared driver consumes
    /// + validates the single-use CSRF state token (format / tenancy / expiry)
    /// and only then hands the validated `ConsumedOAuthState` to
    /// `complete_callback`, which exchanges the code and stores the integration.
    pub async fn handle_callback(
        &self,
        code: String,
        state: String,
    ) -> Result<GoogleCalendarIntegration> {
        talos_oauth::handle_oauth_callback(&self.db_pool, self, &code, &state).await
    }

    /// Get integration by ID
    pub async fn get_integration(
        &self,
        user_id: Uuid,
        integration_id: Uuid,
    ) -> Result<Option<GoogleCalendarIntegration>> {
        let integration = sqlx::query_as::<_, (Uuid, Uuid, Uuid, DateTime<Utc>, String, bool, DateTime<Utc>, DateTime<Utc>)>(
            "SELECT id, user_id, oauth_account_id, expires_at, scope, is_active, created_at, updated_at
             FROM google_calendar_integrations
             WHERE id = $1 AND user_id = $2"
        )
        .bind(integration_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?
        .map(|(id, user_id, oauth_account_id, expires_at, scope, is_active, created_at, updated_at)| {
            GoogleCalendarIntegration {
                id,
                user_id,
                oauth_account_id,
                expires_at,
                scope,
                is_active,
                created_at,
                updated_at,
            }
        });

        Ok(integration)
    }

    /// Get a fresh access token for a Calendar integration via the unified
    /// credential service. Triggers a proactive refresh if the token is
    /// nearing expiry (delegated to `OAuthCredentialService`).
    ///
    /// This is the ONLY path for reading Calendar tokens at runtime —
    /// the `google_calendar_integrations` table stores metadata only.
    pub async fn get_access_token(
        &self,
        integration: &GoogleCalendarIntegration,
    ) -> Result<String> {
        let vault_path = format!(
            "oauth/google_calendar/{}/{}",
            integration.user_id, integration.oauth_account_id
        );
        let access_token_path = format!("{}/access_token", vault_path);

        // Proactive refresh via the centralized credential service.
        if let Some(cred_svc) = self.credentials_service.get() {
            let _ = cred_svc
                .refresh_oauth_token_if_needed(&access_token_path)
                .await;
        }

        // Read the token from the secrets vault using the SHARED
        // SecretsManager (same instance the rest of the controller uses).
        // The pre-r233 per-call construction here silently failed when
        // the production KEK provider differed from the env-derived one
        // — see the field-level docstring on `secrets_manager`.
        let secrets = self
            .secrets_manager
            .get_secrets_by_paths(
                std::slice::from_ref(&access_token_path),
                Some(integration.user_id),
            )
            .await
            .context("Failed to fetch Calendar access token from vault")?;

        secrets.get(&access_token_path).cloned().ok_or_else(|| {
            anyhow::anyhow!(
                "Calendar access token not found at vault path '{}'. \
                 Reconnect the Google Calendar integration.",
                access_token_path
            )
        })
    }

    /// List user's integrations
    pub async fn list_integrations(&self, user_id: Uuid) -> Result<Vec<GoogleCalendarIntegration>> {
        let integrations = sqlx::query_as::<_, (Uuid, Uuid, Uuid, DateTime<Utc>, String, bool, DateTime<Utc>, DateTime<Utc>)>(
            "SELECT id, user_id, oauth_account_id, expires_at, scope, is_active, created_at, updated_at
             FROM google_calendar_integrations
             WHERE user_id = $1 AND is_active = true
             ORDER BY created_at DESC"
        )
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?
        .into_iter()
        .map(|(id, user_id, oauth_account_id, expires_at, scope, is_active, created_at, updated_at)| {
            GoogleCalendarIntegration {
                id,
                user_id,
                oauth_account_id,
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

    // Refresh access token if expired.
    //
    // Token refresh is handled entirely by the centralized
    // OAuthCredentialService::refresh_oauth_token_if_needed (credentials.rs).
    // The proactive_token_refresh_task (refresh_task.rs) queries
    // integration_credentials for expiring tokens every 5 minutes and
    // refreshes them via the unified path. The per-provider DashMap refresh
    // lock and custom threshold that used to live here have been removed
    // to eliminate the competing-refresh-path class of bugs.
    //
    // To get a fresh token for API calls, use `self.get_access_token()`
    // which delegates to the credential service + SecretsManager.

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
        // MCP-960..962 sibling + chrono panic defense: route through
        // the canonical helper so a caller passing a negative or
        // huge i64 (provider misbehavior, manual override) doesn't
        // produce expires_at in the past (immediate-expiry +
        // refresh-storm) or trip `chrono::Duration::seconds`'
        // internal i64-ms overflow panic. Clamp negatives to None
        // (helper defaults to 3600s) and saturate excess to u64.
        let expires_at = talos_oauth::oauth_expires_at(u64::try_from(expires_in).ok());

        // The google_calendar_integrations table was migrated to encrypted
        // token storage (access_token_enc / refresh_token_enc bytea columns).
        // The old plaintext access_token / refresh_token columns no longer
        // exist. We store only the metadata (scope, expiry, active flag)
        // here and delegate token storage to the unified credential service
        // (integration_credentials) which handles encryption + the vault
        // path that WASM modules resolve via vault:// references.
        let integration = sqlx::query_as::<_, (Uuid, Uuid, Uuid, DateTime<Utc>, String, bool, DateTime<Utc>, DateTime<Utc>)>(
            "INSERT INTO google_calendar_integrations
             (user_id, oauth_account_id, expires_at, scope, is_active)
             VALUES ($1, $2, $3, $4, true)
             ON CONFLICT (user_id, oauth_account_id)
             DO UPDATE SET
                expires_at = EXCLUDED.expires_at,
                scope = EXCLUDED.scope,
                is_active = true,
                updated_at = NOW()
             RETURNING id, user_id, oauth_account_id, expires_at, scope, is_active, created_at, updated_at"
        )
        .bind(user_id)
        .bind(oauth_account_id)
        .bind(expires_at)
        .bind(&scope)
        .fetch_one(&self.db_pool)
        .await
        .context("Failed to upsert google_calendar_integrations row")?;

        let result = GoogleCalendarIntegration {
            id: integration.0,
            user_id: integration.1,
            oauth_account_id: integration.2,
            expires_at: integration.3,
            scope: integration.4,
            is_active: integration.5,
            created_at: integration.6,
            updated_at: integration.7,
        };

        // Store tokens via the unified credential service (encrypted,
        // vault-resolvable). This is the canonical token path — WASM
        // modules reference it as vault://oauth/google_calendar/{user_id}/
        // {account_id}/access_token. The proactive refresh task picks up
        // tokens here via the same provider="google_calendar" path.
        if let Some(cred_svc) = self.credentials_service.get() {
            cred_svc
                .store_credentials(
                    result.user_id,
                    "google_calendar",
                    &result.oauth_account_id.to_string(),
                    &access_token,
                    Some(&refresh_token),
                    result.expires_at,
                    &result.scope,
                    vec![],
                )
                .await
                .context("Failed to store GCal credentials in vault")?;
        } else {
            anyhow::bail!(
                "Credential service not configured — cannot store Google Calendar tokens. \
                 Contact your platform administrator."
            );
        }

        Ok(result)
    }

    /// Deactivate integration.
    ///
    /// Five-step disconnect:
    ///   1. Recover oauth_account_id (provider_key) from the active row.
    ///   2. Best-effort revoke at Google + delete vault tokens via
    ///      `OAuthCredentialService::revoke_and_cleanup`.
    ///   3. Soft-delete the `google_calendar_integrations` row (auth gate).
    ///   4. Stop every watch channel this integration owns (existing behaviour).
    ///
    /// Returns an error if step 3 affects 0 rows (not found or owned by
    /// another user). Steps 2 and 4 are best-effort.
    pub async fn deactivate_integration(&self, user_id: Uuid, integration_id: Uuid) -> Result<()> {
        // Step 1: recover oauth_account_id used as provider_key in vault paths.
        let oauth_account_id: Option<Uuid> = sqlx::query_scalar(
            "SELECT oauth_account_id FROM google_calendar_integrations \
             WHERE id = $1 AND user_id = $2 AND is_active = TRUE",
        )
        .bind(integration_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;

        // Step 2: best-effort revoke + vault cleanup.
        if let (Some(oid), Some(cred_svc)) = (oauth_account_id, self.credentials_service.get()) {
            if let Err(e) = cred_svc
                .revoke_and_cleanup(user_id, "google_calendar", &oid.to_string())
                .await
            {
                tracing::warn!(
                    user_id = %user_id,
                    integration_id = %integration_id,
                    error = %e,
                    "google_calendar revoke_and_cleanup failed — proceeding with metadata flip"
                );
            }
        }

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

        // Cascade: stop every watch channel this integration owns.
        // Channels live in integration_state; list + iterate + stop.
        // Errors on individual channels are logged but don't abort
        // the disconnect — the user-facing intent is "turn it off,"
        // even if Google's side fails on a given channel.
        use talos_memory::integration_state_rpc::{IntegrationOp, IntegrationOpResult, ListFilter};
        if let Ok(IntegrationOpResult::Entries { entries }) = talos_integration_state::execute_op(
            &self.db_pool,
            crate::watch::GCAL_INTEGRATION_NAME,
            user_id,
            IntegrationOp::List {
                filter: ListFilter::default(),
                limit: 500,
            },
        )
        .await
        {
            for entry in entries {
                // Decode just enough to check ownership + get the
                // internal uuid — reuse the row type from watch.rs.
                #[derive(serde::Deserialize)]
                struct IdOnly {
                    id: uuid::Uuid,
                    integration_id: uuid::Uuid,
                }
                let Ok(ids) = serde_json::from_str::<IdOnly>(&entry.value) else {
                    continue;
                };
                if ids.integration_id != integration_id {
                    continue;
                }
                if let Err(e) = self.stop_watch_channel(user_id, ids.id).await {
                    tracing::warn!(
                        channel_uuid = %ids.id,
                        error = %e,
                        "stop_watch_channel failed during disconnect; row may linger until TTL"
                    );
                }
            }
        }

        Ok(())
    }
}

/// Dedicated Google Calendar OAuth flow — mirrors the canonical `talos-slack`
/// `OAuthIntegration` reference implementation. The public
/// [`GoogleCalendarService::get_authorization_url`] /
/// [`GoogleCalendarService::handle_callback`] methods delegate to the
/// `talos_oauth` drivers, which run the CSRF / PKCE / single-use / tenancy
/// handling and call back into these provider-specific pieces. Consume-before-
/// exchange is enforced by the driver, so this flow cannot skip validation.
#[async_trait::async_trait]
impl talos_oauth::OAuthIntegration for GoogleCalendarService {
    type Connected = GoogleCalendarIntegration;

    fn provider(&self) -> &'static str {
        "google_calendar"
    }

    fn authorize_request(&self) -> Result<talos_oauth::AuthorizeRequest<'static>> {
        if !self.is_configured() {
            return Err(anyhow::anyhow!(
                "Google Calendar OAuth is not configured. Set GOOGLE_CLIENT_ID, \
                 GOOGLE_CLIENT_SECRET, and GOOGLE_CALENDAR_REDIRECT_URI"
            ));
        }
        Ok(talos_oauth::AuthorizeRequest {
            provider: "google_calendar",
            auth_url: "https://accounts.google.com/o/oauth2/v2/auth",
            token_url: "https://oauth2.googleapis.com/token",
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
            // The DEDICATED callback, NOT the SSO one — bypasses the login
            // account-link guard that 500s for existing password accounts.
            redirect_uri: self.connect_redirect_uri.clone(),
            // Least-privilege: read-only calendar + email (for the connected-
            // account label). `openid` is required for the userinfo lookup.
            scopes: &[
                "https://www.googleapis.com/auth/calendar.readonly",
                "https://www.googleapis.com/auth/calendar.events.readonly",
                "https://www.googleapis.com/auth/userinfo.email",
                "openid",
            ],
            // access_type=offline + prompt=consent → Google returns a
            // refresh_token on EVERY consent (not just the first), so reconnects
            // re-provision a working refresh token cleanly.
            extra_params: &[("access_type", "offline"), ("prompt", "consent")],
        })
    }

    async fn complete_callback(
        &self,
        _pool: &sqlx::PgPool,
        code: &str,
        consumed: talos_oauth::ConsumedOAuthState,
    ) -> Result<GoogleCalendarIntegration> {
        // SECURITY: user_id comes from the state token (bound at connect time),
        // NOT the callback request — the CSRF single-use / PKCE scrub / format /
        // tenancy consume already happened in the shared driver before this call.
        let user_id = consumed.user_id;

        // ---- 1. Exchange the authorization code for tokens ------------------
        let mut form: Vec<(&str, String)> = vec![
            ("grant_type", "authorization_code".to_string()),
            ("code", code.to_string()),
            ("client_id", self.client_id.clone()),
            ("client_secret", self.client_secret.clone()),
            ("redirect_uri", self.connect_redirect_uri.clone()),
        ];
        if let Some(verifier) = consumed.pkce_verifier {
            form.push(("code_verifier", verifier));
        }

        // Fixed trusted host → hardened client (redirect-none + connect timeout,
        // lint 49) with a capped body read (lint 31).
        let http = talos_http_utils::trusted_client::build_integration_client(
            std::time::Duration::from_secs(15),
        );
        let token_resp = http
            .post("https://oauth2.googleapis.com/token")
            .form(&form)
            .send()
            .await
            .context("Google Calendar token exchange request failed")?;
        #[derive(serde::Deserialize)]
        struct TokenResponse {
            access_token: String,
            refresh_token: Option<String>,
            expires_in: Option<i64>,
            scope: Option<String>,
        }
        let tokens: TokenResponse = talos_http_body::read_json_capped(token_resp)
            .await
            .context("Failed to parse Google Calendar token response")?;

        // access_type=offline + prompt=consent should always return a refresh
        // token; fail loudly rather than storing an empty one that would break
        // the next refresh.
        let refresh_token = tokens.refresh_token.ok_or_else(|| {
            anyhow::anyhow!(
                "Google did not return a refresh_token — reconnect and grant offline access"
            )
        })?;
        let scope = tokens.scope.unwrap_or_else(|| {
            "https://www.googleapis.com/auth/calendar.readonly,\
             https://www.googleapis.com/auth/calendar.events.readonly"
                .to_string()
        });

        // ---- 2. Identify the connected Google account -----------------------
        let userinfo_resp = http
            .get("https://www.googleapis.com/oauth2/v2/userinfo")
            .bearer_auth(&tokens.access_token)
            .send()
            .await
            .context("Google userinfo request failed")?;
        #[derive(serde::Deserialize)]
        struct UserInfo {
            id: String,
            email: Option<String>,
        }
        let userinfo: UserInfo = talos_http_body::read_json_capped(userinfo_resp)
            .await
            .context("Failed to parse Google userinfo response")?;

        // Derive a STABLE oauth_account_id from Google's immutable account id so
        // reconnecting the SAME account UPDATEs (UNIQUE(user_id, oauth_account_id))
        // instead of duplicating. No longer an oauth_accounts FK (migration
        // 20260708210000) — it's purely the per-account vault-key segment.
        let oauth_account_id = {
            use sha2::{Digest, Sha256};
            let digest = Sha256::digest(userinfo.id.as_bytes());
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&digest[..16]);
            Uuid::from_bytes(bytes)
        };

        // ---- 3. Store integration + credentials (encrypted, vault-resolvable) -
        let integration = self
            .create_or_update_integration(
                user_id,
                oauth_account_id,
                tokens.access_token,
                refresh_token,
                tokens.expires_in.unwrap_or(3600),
                scope,
            )
            .await?;

        // Human-readable connected-account label for the settings UI. Done as a
        // targeted UPDATE so `create_or_update_integration` (shared with the
        // legacy SSO path) keeps its signature. Non-fatal on failure — the
        // integration is fully functional without the label.
        if let Some(email) = userinfo.email.as_deref() {
            if let Err(e) = sqlx::query(
                "UPDATE google_calendar_integrations \
                 SET account_email = $1, updated_at = NOW() WHERE id = $2",
            )
            .bind(email)
            .bind(integration.id)
            .execute(&self.db_pool)
            .await
            {
                tracing::warn!(
                    error = %e,
                    integration_id = %integration.id,
                    "Failed to set google_calendar_integrations.account_email label"
                );
            }
        }

        Ok(integration)
    }
}
