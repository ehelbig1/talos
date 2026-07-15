use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};
use std::sync::Arc;
use std::sync::LazyLock;
use uuid::Uuid;

use talos_oauth::OAuthCredentialService;
use talos_secrets_manager::SecretsManager;

/// Shared reqwest client for Google Cloud OAuth token exchange + userinfo
/// fetch. Mirrors the per-crate shared-client pattern used by talos-gmail /
/// talos-google-calendar. Hardening contract: timeout(15s) +
/// connect_timeout(5s) + redirect::Policy::none() (all baked into
/// `build_integration_client`, lint 49).
static OAUTH_HTTP_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    talos_http_utils::trusted_client::build_integration_client(std::time::Duration::from_secs(15))
});

/// Consent tier of a Google Cloud connection (Phase C).
///
/// The two tiers are SEPARATE OAuth consents with separate provider strings,
/// so their tokens live under separate vault namespaces:
///
/// * `Read`  → provider `"google_cloud"`, scope `cloud-platform.read-only`.
///   Vault: `oauth/google_cloud/{user}/{provider_key}/…`
/// * `Write` → provider `"google_cloud_write"`, scopes `pubsub` +
///   `monitoring` (deliberately NOT `cloud-platform` — Google bounds a
///   leaked/abused write token server-side to Pub/Sub + Monitoring, which is
///   everything the provisioning module family needs and nothing more).
///   Vault: `oauth/google_cloud_write/{user}/{provider_key}/…`
///
/// The distinct provider segment is a structural grant boundary: a module
/// with `requires_secrets: ["oauth/google_cloud/*"]` cannot name the write
/// token at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GcpTier {
    Read,
    Write,
}

impl GcpTier {
    /// The OAuth provider string — state-token match key AND vault-path
    /// segment.
    pub fn provider_str(self) -> &'static str {
        match self {
            GcpTier::Read => "google_cloud",
            GcpTier::Write => "google_cloud_write",
        }
    }

    /// DB representation for `google_cloud_integrations.tier`.
    pub fn as_db_str(self) -> &'static str {
        match self {
            GcpTier::Read => "read",
            GcpTier::Write => "write",
        }
    }

    /// Scopes requested at consent time for this tier.
    pub fn scopes(self) -> &'static [&'static str] {
        match self {
            // Read-only Cloud Platform access + account identity.
            GcpTier::Read => &[
                "https://www.googleapis.com/auth/cloud-platform.read-only",
                "https://www.googleapis.com/auth/userinfo.email",
                "openid",
            ],
            // Provisioning: Pub/Sub (topics/subscriptions) + Monitoring
            // (notification channels) + account identity. NOT cloud-platform:
            // scope narrowing is the blast-radius bound — see enum docs.
            GcpTier::Write => &[
                "https://www.googleapis.com/auth/pubsub",
                "https://www.googleapis.com/auth/monitoring",
                "https://www.googleapis.com/auth/userinfo.email",
                "openid",
            ],
        }
    }

    /// Fallback `scope` string if Google omits `scope` in the token response.
    fn fallback_scope(self) -> String {
        self.scopes().join(",")
    }
}

/// Google Cloud account integration metadata.
///
/// Tokens are NOT stored here — they live exclusively in the unified
/// `integration_credentials` table and are accessed via the
/// `OAuthCredentialService` / `SecretsManager`. This matches the Gmail /
/// Google Calendar / Atlassian integration pattern.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct GoogleCloudIntegration {
    pub id: Uuid,
    pub user_id: Uuid,
    /// Stable per-account key (Sha256(google_account_id)[..16] as a UUID),
    /// used as the vault-path segment. Mirrors gcal's `oauth_account_id`.
    pub provider_key: Uuid,
    pub account_email: Option<String>,
    pub account_name: Option<String>,
    pub token_expires_at: Option<DateTime<Utc>>,
    pub scope: Option<String>,
    /// Consent tier: `'read'` (Phase A default) or `'write'` (Phase C
    /// provisioning). See [`GcpTier`].
    pub tier: String,
    pub is_active: bool,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Simplified version for API responses (no sensitive tokens).
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct GoogleCloudIntegrationInfo {
    pub id: Uuid,
    pub account_email: Option<String>,
    pub account_name: Option<String>,
    pub scope: Option<String>,
    /// `'read'` or `'write'` — surfaced so the settings UI can badge the
    /// provisioning connection distinctly.
    pub tier: String,
    pub is_active: bool,
    pub created_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub token_expires_at: Option<DateTime<Utc>>,
}

impl From<GoogleCloudIntegration> for GoogleCloudIntegrationInfo {
    fn from(integration: GoogleCloudIntegration) -> Self {
        Self {
            id: integration.id,
            account_email: integration.account_email,
            account_name: integration.account_name,
            scope: integration.scope,
            tier: integration.tier,
            is_active: integration.is_active,
            created_at: integration.created_at,
            last_used_at: integration.last_used_at,
            token_expires_at: integration.token_expires_at,
        }
    }
}

/// Service for managing Google Cloud account integrations.
///
/// One instance per consent [`GcpTier`]: the read instance (Phase A) and the
/// write instance (Phase C provisioning) share the same OAuth client + env
/// config but differ in provider string + requested scopes. Construct with
/// [`Self::new`] (read) or [`Self::new_write`].
pub struct GoogleCloudIntegrationService {
    db_pool: Pool<Postgres>,
    /// Which consent tier this instance drives.
    tier: GcpTier,
    client_id: Option<String>,
    client_secret: Option<String>,
    redirect_uri: Option<String>,
    /// SecretsManager for token-at-rest decryption on read (set via
    /// `with_secrets_manager`).
    secrets_manager: Option<Arc<SecretsManager>>,
    /// Unified OAuth credential service for token storage + refresh (set via
    /// `with_credentials_service`).
    credentials_service: Option<Arc<OAuthCredentialService>>,
}

/// Hand-written redacting `Debug` so a stray `{:?}` never dumps the OAuth
/// `client_secret` into logs (lint 37 — the class PR #124 swept).
impl std::fmt::Debug for GoogleCloudIntegrationService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GoogleCloudIntegrationService")
            .field("tier", &self.tier)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("redirect_uri", &self.redirect_uri)
            .field("has_secrets_manager", &self.secrets_manager.is_some())
            .field(
                "has_credentials_service",
                &self.credentials_service.is_some(),
            )
            .finish()
    }
}

impl GoogleCloudIntegrationService {
    /// Read-tier (Phase A) instance.
    pub fn new(db_pool: Pool<Postgres>) -> Result<Self> {
        Self::new_with_tier(db_pool, GcpTier::Read)
    }

    /// Write-tier (Phase C provisioning) instance. Same OAuth client / env
    /// config as the read tier — a SEPARATE consent with elevated scopes.
    pub fn new_write(db_pool: Pool<Postgres>) -> Result<Self> {
        Self::new_with_tier(db_pool, GcpTier::Write)
    }

    fn new_with_tier(db_pool: Pool<Postgres>, tier: GcpTier) -> Result<Self> {
        Ok(Self {
            db_pool,
            tier,
            // Empty-env class (MCP-710): a helm placeholder `""` must read as
            // unset, not `Some("")` — otherwise `is_configured()` returns true
            // while every OAuth URL carries an empty client_id.
            client_id: std::env::var("GOOGLE_CLOUD_CLIENT_ID")
                .ok()
                .filter(|v| !v.is_empty()),
            client_secret: std::env::var("GOOGLE_CLOUD_CLIENT_SECRET")
                .ok()
                .filter(|v| !v.is_empty()),
            redirect_uri: std::env::var("GOOGLE_CLOUD_REDIRECT_URI")
                .ok()
                .filter(|v| !v.is_empty()),
            secrets_manager: None,
            credentials_service: None,
        })
    }

    /// The consent tier this instance drives.
    pub fn tier(&self) -> GcpTier {
        self.tier
    }

    /// DB pool accessor — used by the shared callback handler to peek the
    /// state token's provider for tier routing.
    pub fn db_pool(&self) -> &Pool<Postgres> {
        &self.db_pool
    }

    /// Attach a SecretsManager to enable token-at-rest decryption.
    pub fn with_secrets_manager(mut self, sm: Arc<SecretsManager>) -> Self {
        self.secrets_manager = Some(sm);
        self
    }

    /// Attach a unified OAuth credential service for token storage.
    pub fn with_credentials_service(mut self, svc: Arc<OAuthCredentialService>) -> Self {
        self.credentials_service = Some(svc);
        self
    }

    /// Check if Google Cloud OAuth is configured.
    pub fn is_configured(&self) -> bool {
        self.client_id.is_some() && self.client_secret.is_some() && self.redirect_uri.is_some()
    }

    /// Get a fresh access token for a Google Cloud integration via the unified
    /// credential service. Proactively refreshes when nearing expiry.
    ///
    /// This is the canonical path for reading GCP tokens at runtime.
    pub async fn get_access_token(&self, user_id: Uuid, provider_key: Uuid) -> Result<String> {
        let access_token_path = format!(
            "oauth/{}/{}/{}/access_token",
            self.tier.provider_str(),
            user_id,
            provider_key
        );

        // Proactive refresh via the centralized credential service.
        if let Some(ref cred_svc) = self.credentials_service {
            let _ = cred_svc
                .refresh_oauth_token_if_needed(&access_token_path)
                .await;
        }

        // Read the token from the secrets vault (user-scoped).
        let sm = self
            .secrets_manager
            .as_ref()
            .ok_or_else(|| anyhow!("SecretsManager not configured"))?;
        let secrets = sm
            .get_secrets_by_paths(std::slice::from_ref(&access_token_path), Some(user_id))
            .await
            .context("Failed to fetch Google Cloud access token from vault")?;

        // Path deliberately NOT in the message (it embeds user_id — the
        // MCP-988 oauth-path-PII class); callers log user_id as a
        // structured field already.
        secrets.get(&access_token_path).cloned().ok_or_else(|| {
            anyhow!(
                "Google Cloud access token not found in vault. \
                 Reconnect the Google Cloud integration."
            )
        })
    }

    /// Generate the OAuth authorization URL for connecting a GCP account.
    /// Stores `user_id` in the state token so the callback can identify the
    /// user without session auth.
    pub async fn get_authorization_url(&self, user_id: Uuid) -> Result<(String, String)> {
        talos_oauth::authorization_url(&self.db_pool, self, user_id).await
    }

    /// Handle the OAuth callback and store the integration. `user_id` is
    /// recovered from the state token, so this does NOT require session auth.
    pub async fn handle_callback(
        &self,
        code: String,
        state: String,
    ) -> Result<GoogleCloudIntegration> {
        talos_oauth::handle_oauth_callback(&self.db_pool, self, &code, &state).await
    }
}

/// Shared OAuth flow contract — the `talos_oauth` drivers run the CSRF /
/// PKCE / single-use / tenancy handling and call back into these three
/// provider-specific pieces, making consume-before-exchange structural.
/// `talos-slack` is the canonical reference implementation of this shape.
#[async_trait::async_trait]
impl talos_oauth::OAuthIntegration for GoogleCloudIntegrationService {
    type Connected = GoogleCloudIntegration;

    fn provider(&self) -> &'static str {
        self.tier.provider_str()
    }

    fn authorize_request(&self) -> Result<talos_oauth::AuthorizeRequest<'static>> {
        if !self.is_configured() {
            return Err(anyhow!(
                "Google Cloud OAuth is not configured. Set GOOGLE_CLOUD_CLIENT_ID, \
                 GOOGLE_CLOUD_CLIENT_SECRET, and GOOGLE_CLOUD_REDIRECT_URI"
            ));
        }

        Ok(talos_oauth::AuthorizeRequest {
            provider: self.tier.provider_str(),
            auth_url: "https://accounts.google.com/o/oauth2/v2/auth",
            token_url: "https://oauth2.googleapis.com/token",
            client_id: self
                .client_id
                .clone()
                .ok_or_else(|| anyhow!("GOOGLE_CLOUD_CLIENT_ID not set"))?,
            client_secret: self
                .client_secret
                .clone()
                .ok_or_else(|| anyhow!("GOOGLE_CLOUD_CLIENT_SECRET not set"))?,
            redirect_uri: self
                .redirect_uri
                .clone()
                .ok_or_else(|| anyhow!("GOOGLE_CLOUD_REDIRECT_URI not set"))?,
            // Per-tier scope set: read-only Cloud Platform (Phase A) or the
            // scope-narrowed provisioning set (Phase C) — see [`GcpTier`].
            scopes: self.tier.scopes(),
            // Offline access + forced consent to always get a refresh token.
            extra_params: &[("access_type", "offline"), ("prompt", "consent")],
        })
    }

    async fn complete_callback(
        &self,
        _pool: &sqlx::PgPool,
        code: &str,
        consumed: talos_oauth::ConsumedOAuthState,
    ) -> Result<GoogleCloudIntegration> {
        // SECURITY: user_id comes from the state token (bound at connect time),
        // NOT the callback's session cookie. CSRF single-use / PKCE scrub /
        // format-gate / tenancy consume already happened in the shared driver.
        let user_id = consumed.user_id;
        let pkce_verifier_secret = consumed.pkce_verifier;

        let client_id = self
            .client_id
            .clone()
            .ok_or_else(|| anyhow!("GOOGLE_CLOUD_CLIENT_ID not set"))?;
        let client_secret = self
            .client_secret
            .clone()
            .ok_or_else(|| anyhow!("GOOGLE_CLOUD_CLIENT_SECRET not set"))?;
        let redirect_uri = self
            .redirect_uri
            .clone()
            .ok_or_else(|| anyhow!("GOOGLE_CLOUD_REDIRECT_URI not set"))?;

        // ---- 1. Exchange code for tokens ------------------------------------
        // This POST carries client_secret + code + code_verifier. Routed
        // through the shared hardened OAUTH_HTTP_CLIENT (redirect-none,
        // connect timeout). Body preview is DLP-scrubbed before logging.
        let mut token_body = serde_json::json!({
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
        });
        if let Some(verifier) = pkce_verifier_secret {
            token_body["code_verifier"] = serde_json::Value::String(verifier);
        }

        let token_resp = OAUTH_HTTP_CLIENT
            .post("https://oauth2.googleapis.com/token")
            .json(&token_body)
            .send()
            .await
            .context("Failed to reach Google token endpoint")?;

        if !token_resp.status().is_success() {
            let status = token_resp.status();
            let body = talos_http_body::read_error_text_capped(token_resp).await;
            let preview = talos_text_util::truncate_at_char_boundary(&body, 500);
            let redacted = talos_dlp_provider::redact_str(preview);
            tracing::error!(
                status = %status,
                body_len = body.len(),
                body_preview = %redacted,
                "Google Cloud token exchange failed"
            );
            return Err(anyhow!(
                "Google Cloud token exchange failed (HTTP {})",
                status
            ));
        }

        #[derive(serde::Deserialize)]
        struct TokenResponse {
            access_token: String,
            refresh_token: Option<String>,
            expires_in: Option<u64>,
            scope: Option<String>,
        }

        let token_data: TokenResponse = talos_http_body::read_json_capped(token_resp)
            .await
            .context("Failed to parse Google Cloud token response")?;

        let access_token = token_data.access_token;
        // access_type=offline + prompt=consent should always return a refresh
        // token; fail loudly rather than storing an empty one that breaks the
        // next refresh (mirrors gcal).
        let refresh_token = token_data.refresh_token.ok_or_else(|| {
            anyhow!("Google did not return a refresh_token — reconnect and grant offline access")
        })?;
        // Route through the canonical helper so a u64 expires_in > i64::MAX
        // can't wrap to a negative i64 (immediate-expiry + refresh-storm).
        let token_expires_at = talos_oauth::oauth_expires_at(token_data.expires_in);
        let scope = token_data
            .scope
            .unwrap_or_else(|| self.tier.fallback_scope());

        // ---- 2. Identify the connected Google account -----------------------
        let userinfo_resp = OAUTH_HTTP_CLIENT
            .get("https://www.googleapis.com/oauth2/v2/userinfo")
            .bearer_auth(&access_token)
            .send()
            .await
            .context("Google userinfo request failed")?;
        #[derive(serde::Deserialize)]
        struct UserInfo {
            id: String,
            email: Option<String>,
            name: Option<String>,
        }
        let userinfo: UserInfo = talos_http_body::read_json_capped(userinfo_resp)
            .await
            .context("Failed to parse Google userinfo response")?;

        // Derive a STABLE provider_key from Google's immutable account id so
        // reconnecting the SAME account UPDATEs (UNIQUE(user_id, provider_key))
        // instead of duplicating. Identical algorithm to gcal's
        // oauth_account_id derivation.
        let provider_key = derive_provider_key(&userinfo.id);
        let account_email = userinfo.email.clone();
        let account_name = userinfo.name.clone();

        // ---- 3. Upsert the integration row + store credentials --------------
        let integration = self
            .upsert_integration(
                user_id,
                provider_key,
                account_email,
                account_name,
                token_expires_at,
                Some(scope.clone()),
            )
            .await?;

        // Store tokens in the unified credential service (required). The
        // tier's provider string keys the vault namespace — this is what
        // keeps read-module grants (`oauth/google_cloud/*`) structurally
        // unable to name the write token.
        if let Some(cred_svc) = &self.credentials_service {
            cred_svc
                .store_credentials(
                    user_id,
                    self.tier.provider_str(),
                    &provider_key.to_string(),
                    &access_token,
                    Some(refresh_token.as_str()),
                    token_expires_at,
                    &scope,
                    vec![],
                )
                .await
                .context("Failed to store Google Cloud credentials in vault")?;
        } else {
            anyhow::bail!("Credential service not configured — cannot store Google Cloud tokens");
        }

        // Best-effort audit (shared channel-lifecycle log). Tier-qualified
        // event name: a WRITE consent is a materially different privilege
        // grant and must be distinguishable in the audit trail.
        self.audit(
            Some(integration.id),
            user_id,
            match self.tier {
                GcpTier::Read => "google_cloud_connected",
                GcpTier::Write => "google_cloud_write_connected",
            },
            integration.account_email.as_deref(),
            true,
        )
        .await;

        Ok(integration)
    }
}

/// Derive the stable per-account provider_key from Google's immutable
/// account id: `Uuid::from_bytes(Sha256(google_account_id)[..16])`.
/// Same algorithm gcal uses for its `oauth_account_id`.
pub fn derive_provider_key(google_account_id: &str) -> Uuid {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(google_account_id.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    Uuid::from_bytes(bytes)
}

impl GoogleCloudIntegrationService {
    /// Insert or update a Google Cloud integration (metadata only). Tokens are
    /// stored exclusively in the unified credential service.
    async fn upsert_integration(
        &self,
        user_id: Uuid,
        provider_key: Uuid,
        account_email: Option<String>,
        account_name: Option<String>,
        token_expires_at: DateTime<Utc>,
        scope: Option<String>,
    ) -> Result<GoogleCloudIntegration> {
        let integration = sqlx::query_as::<_, GoogleCloudIntegration>(
            r#"
            INSERT INTO google_cloud_integrations (
                user_id, provider_key, account_email, account_name,
                token_expires_at, scope, tier
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (user_id, provider_key, tier)
            DO UPDATE SET
                account_email = EXCLUDED.account_email,
                account_name = EXCLUDED.account_name,
                token_expires_at = EXCLUDED.token_expires_at,
                scope = EXCLUDED.scope,
                is_active = TRUE,
                updated_at = NOW()
            RETURNING *
            "#,
        )
        .bind(user_id)
        .bind(provider_key)
        .bind(&account_email)
        .bind(&account_name)
        .bind(token_expires_at)
        .bind(&scope)
        .bind(self.tier.as_db_str())
        .fetch_one(&self.db_pool)
        .await
        .context("Failed to upsert Google Cloud integration")?;

        Ok(integration)
    }

    /// Get all active integrations for a user.
    pub async fn get_user_integrations(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<GoogleCloudIntegrationInfo>> {
        let integrations = sqlx::query_as::<_, GoogleCloudIntegrationInfo>(
            r#"
            SELECT id, account_email, account_name, scope, tier, is_active,
                   created_at, last_used_at, token_expires_at
            FROM google_cloud_integrations
            WHERE user_id = $1 AND is_active = TRUE
            ORDER BY created_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;

        Ok(integrations)
    }

    /// Get one integration's public info (ownership-gated).
    pub async fn get_integration_info(
        &self,
        integration_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<GoogleCloudIntegrationInfo>> {
        let integration = sqlx::query_as::<_, GoogleCloudIntegrationInfo>(
            r#"
            SELECT id, account_email, account_name, scope, tier, is_active,
                   created_at, last_used_at, token_expires_at
            FROM google_cloud_integrations
            WHERE id = $1 AND user_id = $2 AND is_active = TRUE
            "#,
        )
        .bind(integration_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;

        Ok(integration)
    }

    /// Get one integration row (ownership-gated).
    pub async fn get_integration(
        &self,
        integration_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<GoogleCloudIntegration>> {
        let integration = sqlx::query_as::<_, GoogleCloudIntegration>(
            r#"
            SELECT *
            FROM google_cloud_integrations
            WHERE id = $1 AND user_id = $2 AND is_active = TRUE
            "#,
        )
        .bind(integration_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;

        Ok(integration)
    }

    /// Disconnect (deactivate) an integration.
    ///
    /// Three-step disconnect:
    ///   1. Look up the row to recover the provider_key for vault paths.
    ///   2. `OAuthCredentialService::revoke_and_cleanup` — revokes at Google,
    ///      deletes vault token entries, soft-deletes the unified credential row.
    ///   3. Soft-delete the `google_cloud_integrations` row (authorisation gate
    ///      via `WHERE user_id = $2`).
    pub async fn disconnect_integration(&self, integration_id: Uuid, user_id: Uuid) -> Result<()> {
        // Step 1: recover provider_key + the ROW's tier (+ email for the
        // audit label). The tier comes from the row, not `self.tier` — the
        // settings UI disconnects both tiers through one handler, and a
        // write-tier row must revoke + clean up under
        // `oauth/google_cloud_write/*`, not the read namespace.
        let row: Option<(Uuid, Option<String>, String)> = sqlx::query_as(
            "SELECT provider_key, account_email, tier FROM google_cloud_integrations \
             WHERE id = $1 AND user_id = $2 AND is_active = TRUE",
        )
        .bind(integration_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;

        let (provider_key, account_email, row_tier) = match row {
            Some((pk, email, tier)) => (Some(pk), email, tier),
            None => (None, None, "read".to_string()),
        };
        // Fail-closed mapping: an unexpected tier value revokes nothing
        // rather than revoking the wrong namespace.
        let row_provider = match row_tier.as_str() {
            "read" => Some("google_cloud"),
            "write" => Some("google_cloud_write"),
            other => {
                tracing::warn!(
                    integration_id = %integration_id,
                    tier = other,
                    "Unknown google_cloud integration tier — skipping credential revoke"
                );
                None
            }
        };

        // Step 2: best-effort provider revoke + vault cleanup.
        if let (Some(pk), Some(provider), Some(cred_svc)) =
            (provider_key, row_provider, &self.credentials_service)
        {
            if let Err(e) = cred_svc
                .revoke_and_cleanup(user_id, provider, &pk.to_string())
                .await
            {
                tracing::warn!(
                    user_id = %user_id,
                    integration_id = %integration_id,
                    error = %e,
                    "Google Cloud revoke_and_cleanup failed — proceeding with metadata flip"
                );
            }
        }

        // Step 3: soft-delete the metadata row (authorisation gate).
        let result = sqlx::query(
            "UPDATE google_cloud_integrations SET is_active = FALSE, updated_at = NOW() \
             WHERE id = $1 AND user_id = $2",
        )
        .bind(integration_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;

        if result.rows_affected() == 0 {
            anyhow::bail!("Integration not found or access denied");
        }

        self.audit(
            Some(integration_id),
            user_id,
            match row_tier.as_str() {
                "write" => "google_cloud_write_disconnected",
                _ => "google_cloud_disconnected",
            },
            account_email.as_deref(),
            true,
        )
        .await;

        Ok(())
    }

    /// Mark integration as used (update last_used_at).
    pub async fn mark_used(&self, integration_id: Uuid) -> Result<()> {
        sqlx::query("UPDATE google_cloud_integrations SET last_used_at = NOW() WHERE id = $1")
            .bind(integration_id)
            .execute(&self.db_pool)
            .await?;
        Ok(())
    }

    /// Best-effort write to the shared channel-lifecycle audit log
    /// (`google_calendar_audit_log` — the name is historical; it is the shared
    /// integration-events log). Non-fatal on failure.
    async fn audit(
        &self,
        integration_id: Option<Uuid>,
        user_id: Uuid,
        event_type: &str,
        target: Option<&str>,
        success: bool,
    ) {
        let ev = talos_integration_helpers::audit::ChannelAuditEvent {
            integration_id,
            user_id,
            event_type,
            target,
            success,
            error_message: None,
            metadata: serde_json::Value::Null,
        };
        if let Err(e) =
            talos_integration_helpers::audit::insert_channel_audit(&self.db_pool, ev).await
        {
            tracing::warn!(
                user_id = %user_id,
                event_type,
                error = %e,
                "google_cloud audit log insert failed"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_key_is_deterministic() {
        let a = derive_provider_key("1234567890");
        let b = derive_provider_key("1234567890");
        assert_eq!(
            a, b,
            "same google account id must derive the same provider_key"
        );
    }

    #[test]
    fn provider_key_differs_per_account() {
        let a = derive_provider_key("1234567890");
        let b = derive_provider_key("0987654321");
        assert_ne!(
            a, b,
            "different google account ids must derive different keys"
        );
    }

    #[test]
    fn provider_key_matches_gcal_algorithm() {
        // Independent reimplementation of the gcal derivation (lib.rs:724-730):
        // Uuid::from_bytes(Sha256(id)[..16]). Must match byte-for-byte.
        use sha2::{Digest, Sha256};
        let id = "108234567890123456789";
        let digest = Sha256::digest(id.as_bytes());
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        let expected = Uuid::from_bytes(bytes);
        assert_eq!(derive_provider_key(id), expected);
    }

    #[test]
    fn tier_provider_strings_are_distinct_namespaces() {
        // The provider string is the vault-path segment; distinctness is the
        // structural grant boundary between read modules and the write token.
        assert_eq!(GcpTier::Read.provider_str(), "google_cloud");
        assert_eq!(GcpTier::Write.provider_str(), "google_cloud_write");
        assert!(!GcpTier::Write
            .provider_str()
            .eq(GcpTier::Read.provider_str()));
    }

    #[test]
    fn write_tier_scopes_are_narrowed_not_cloud_platform() {
        // SECURITY INVARIANT: the write tier must never request the broad
        // `cloud-platform` scope (or any scope outside pubsub + monitoring +
        // identity). Scope narrowing is the server-side blast-radius bound
        // for the provisioning token — Google refuses compute/IAM/storage
        // calls with this token no matter what a module tries.
        let scopes = GcpTier::Write.scopes();
        assert!(
            !scopes
                .iter()
                .any(|s| *s == "https://www.googleapis.com/auth/cloud-platform"),
            "write tier must not request cloud-platform"
        );
        assert!(scopes.contains(&"https://www.googleapis.com/auth/pubsub"));
        assert!(scopes.contains(&"https://www.googleapis.com/auth/monitoring"));
        // Identity-only extras.
        let allowed: &[&str] = &[
            "https://www.googleapis.com/auth/pubsub",
            "https://www.googleapis.com/auth/monitoring",
            "https://www.googleapis.com/auth/userinfo.email",
            "openid",
        ];
        for s in scopes {
            assert!(allowed.contains(s), "unexpected write-tier scope: {s}");
        }
    }

    #[test]
    fn read_tier_scopes_stay_read_only() {
        let scopes = GcpTier::Read.scopes();
        assert!(scopes.contains(&"https://www.googleapis.com/auth/cloud-platform.read-only"));
        assert!(
            !scopes.iter().any(|s| s.contains("/auth/pubsub")
                || *s == "https://www.googleapis.com/auth/monitoring"),
            "read tier must not carry write scopes"
        );
    }

    #[test]
    fn write_refresh_token_path_is_host_reserved() {
        // The write tier's refresh_token must be blocked from guest reads by
        // the shared deny-list (worker `check_secret_allowlist` imports this
        // predicate). The 4-segment oauth path shape qualifies automatically;
        // this test pins that the write provider's paths keep that shape.
        assert!(
            talos_workflow_job_protocol::is_controller_internal_vault_path(
                "oauth/google_cloud_write/1a361562-e551-41aa-9cb4-6f8988b035f7/9c4d/refresh_token"
            ),
            "write-tier refresh token must be host-reserved"
        );
        // The access token stays module-grantable (that's the point of the
        // tier — provisioning modules use it via vault:// with method+host
        // pinning).
        assert!(
            !talos_workflow_job_protocol::is_controller_internal_vault_path(
                "oauth/google_cloud_write/1a361562-e551-41aa-9cb4-6f8988b035f7/9c4d/access_token"
            )
        );
    }

    #[tokio::test]
    async fn debug_redacts_client_secret() {
        let svc = GoogleCloudIntegrationService {
            db_pool: sqlx::postgres::PgPoolOptions::new()
                .connect_lazy("postgres://localhost/unused")
                .expect("lazy pool"),
            tier: GcpTier::Read,
            client_id: Some("public-client-id".into()),
            client_secret: Some("SUPER_SECRET_VALUE_XYZ".into()),
            redirect_uri: Some("https://example.com/api/gcp/callback".into()),
            secrets_manager: None,
            credentials_service: None,
        };
        let dbg = format!("{:?}", svc);
        assert!(
            !dbg.contains("SUPER_SECRET_VALUE_XYZ"),
            "client_secret leaked: {dbg}"
        );
        assert!(
            dbg.contains("[REDACTED]"),
            "redaction marker missing: {dbg}"
        );
    }
}
