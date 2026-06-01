use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Duration, Utc};
use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl,
    Scope, TokenUrl,
};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};
use std::sync::Arc;
use std::sync::LazyLock;

/// Shared reqwest client for Gmail OAuth token exchange + userinfo
/// fetch. Mirrors the per-crate shared-client pattern that MCP-1110 /
/// MCP-1111 / the 2026-05-28 audit landed for talos-memory,
/// talos-search-service, and talos-atlassian. Pre-fix the token-
/// exchange + userinfo paths each built a fresh `reqwest::Client`
/// per call — TLS context init + connection-pool reset per OAuth
/// callback, defeating keep-alive against oauth2.googleapis.com /
/// googleapis.com.
///
/// Hardening contract preserved: timeout(15s) + connect_timeout(5s) +
/// redirect::Policy::none(). MCP-533 hardening invariants preserved.
static OAUTH_HTTP_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .connect_timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Gmail OAuth: failed to build hardened reqwest client")
});
use uuid::Uuid;

use talos_oauth::OAuthCredentialService;
use talos_secrets_manager::SecretsManager;

/// Gmail account integration metadata.
///
/// Tokens are NOT stored here — they live exclusively in the unified
/// `integration_credentials` table and are accessed via the
/// `OAuthCredentialService` / `SecretsManager`. This matches the
/// Atlassian integration pattern.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct GmailIntegration {
    pub id: Uuid,
    pub user_id: Uuid,
    pub email_address: String,
    pub account_name: Option<String>,
    pub token_expires_at: Option<DateTime<Utc>>,
    pub scope: Option<String>,
    pub is_active: bool,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
}

impl GmailIntegration {
    /// Convenience accessor for the email used as provider_key in the
    /// credential service vault path.
    pub fn email(&self) -> &str {
        &self.email_address
    }
}

/// Simplified version for API responses (without sensitive tokens)
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct GmailIntegrationInfo {
    pub id: Uuid,
    pub email_address: String,
    pub account_name: Option<String>,
    pub scope: Option<String>,
    pub is_active: bool,
    pub created_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub token_expires_at: Option<DateTime<Utc>>,
}

impl From<GmailIntegration> for GmailIntegrationInfo {
    fn from(integration: GmailIntegration) -> Self {
        Self {
            id: integration.id,
            email_address: integration.email_address,
            account_name: integration.account_name,
            scope: integration.scope,
            is_active: integration.is_active,
            created_at: integration.created_at,
            last_used_at: integration.last_used_at,
            token_expires_at: integration.token_expires_at,
        }
    }
}

/// Service for managing Gmail account integrations
pub struct GmailIntegrationService {
    db_pool: Pool<Postgres>,
    client_id: Option<String>,
    client_secret: Option<String>,
    redirect_uri: Option<String>,
    /// SecretsManager for encrypting tokens at rest (set via `with_secrets_manager`).
    secrets_manager: Option<Arc<SecretsManager>>,
    /// Unified OAuth credential service for dual-write (set via `with_credentials_service`).
    credentials_service: Option<Arc<OAuthCredentialService>>,
}

impl GmailIntegrationService {
    pub fn new(db_pool: Pool<Postgres>) -> Result<Self> {
        Ok(Self {
            db_pool,
            // MCP-710 (2026-05-13): treat empty env as unset.
            // Helm placeholder `gmailClientId: ""` would previously
            // produce `Some("")`, which makes `is_configured()`
            // return true (line ~145) while every OAuth URL the
            // service generates carries empty client_id — Google
            // rejects with a confusing "Missing required parameter"
            // and operators chase the wrong root cause. Same
            // empty-env class as MCP-590/591/592/653/etc.
            client_id: std::env::var("GMAIL_CLIENT_ID").ok().filter(|v| !v.is_empty()),
            client_secret: std::env::var("GMAIL_CLIENT_SECRET").ok().filter(|v| !v.is_empty()),
            redirect_uri: std::env::var("GMAIL_REDIRECT_URI").ok().filter(|v| !v.is_empty()),
            secrets_manager: None,
            credentials_service: None,
        })
    }

    /// Attach a SecretsManager to enable token-at-rest encryption.
    pub fn with_secrets_manager(mut self, sm: Arc<SecretsManager>) -> Self {
        self.secrets_manager = Some(sm);
        self
    }

    /// Attach a unified OAuth credential service for dual-write token storage.
    pub fn with_credentials_service(mut self, svc: Arc<OAuthCredentialService>) -> Self {
        self.credentials_service = Some(svc);
        self
    }

    /// Get a fresh access token for a Gmail integration via the unified
    /// credential service. Triggers a proactive refresh if the token is
    /// nearing expiry (delegated to `OAuthCredentialService`).
    ///
    /// This is the canonical path for reading Gmail tokens at runtime.
    pub async fn get_access_token(&self, user_id: Uuid, email: &str) -> Result<String> {
        let access_token_path = format!("oauth/gmail/{}/{}/access_token", user_id, email);

        // Proactive refresh via the centralized credential service.
        if let Some(ref cred_svc) = self.credentials_service {
            let _ = cred_svc
                .refresh_oauth_token_if_needed(&access_token_path)
                .await;
        }

        // Read the token from the secrets vault.
        let sm = self
            .secrets_manager
            .as_ref()
            .ok_or_else(|| anyhow!("SecretsManager not configured"))?;
        let secrets = sm
            .get_secrets_by_paths(std::slice::from_ref(&access_token_path), Some(user_id))
            .await
            .context("Failed to fetch Gmail access token from vault")?;

        secrets.get(&access_token_path).cloned().ok_or_else(|| {
            anyhow!(
                "Gmail access token not found at vault path '{}'. \
                 Reconnect the Gmail integration.",
                access_token_path
            )
        })
    }

    /// Check if Gmail OAuth is configured
    pub fn is_configured(&self) -> bool {
        self.client_id.is_some() && self.client_secret.is_some() && self.redirect_uri.is_some()
    }

    /// Generate OAuth authorization URL for connecting a Gmail account.
    /// Stores `user_id` in the state token so the callback can identify the
    /// user without requiring session auth (cross-site redirects from OAuth
    /// providers may not carry session cookies).
    pub async fn get_authorization_url(&self, user_id: Uuid) -> Result<(String, String)> {
        if !self.is_configured() {
            return Err(anyhow!(
                "Gmail OAuth is not configured. Set GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET, and GMAIL_REDIRECT_URI"
            ));
        }

        // Unwraps replaced with explicit error handling for better observability.
        let client_id = self
            .client_id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("GMAIL_CLIENT_ID not set"))?;
        let client_secret = self
            .client_secret
            .clone()
            .ok_or_else(|| anyhow::anyhow!("GMAIL_CLIENT_SECRET not set"))?;
        let redirect_uri = self
            .redirect_uri
            .clone()
            .ok_or_else(|| anyhow::anyhow!("GMAIL_REDIRECT_URI not set"))?;

        let client = BasicClient::new(
            ClientId::new(client_id),
            Some(ClientSecret::new(client_secret)),
            AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())?,
            Some(TokenUrl::new(
                "https://oauth2.googleapis.com/token".to_string(),
            )?),
        )
        .set_redirect_uri(RedirectUrl::new(redirect_uri)?);

        // PKCE (Proof Key for Code Exchange) prevents authorization code
        // interception attacks. Google supports S256 challenges. Matches the
        // Atlassian integration's PKCE implementation for consistency.
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let (auth_url, csrf_token) = client
            .authorize_url(CsrfToken::new_random)
            // Request Gmail API scopes
            .add_scope(Scope::new(
                "https://www.googleapis.com/auth/gmail.readonly".to_string(),
            ))
            .add_scope(Scope::new(
                "https://www.googleapis.com/auth/gmail.modify".to_string(),
            ))
            .add_scope(Scope::new(
                "https://www.googleapis.com/auth/userinfo.email".to_string(),
            ))
            // Request offline access to get refresh token
            .add_extra_param("access_type", "offline")
            .add_extra_param("prompt", "consent")
            .set_pkce_challenge(pkce_challenge)
            .url();

        let state_secret = csrf_token.secret().to_string();

        // Persist state token + PKCE verifier + user_id so the callback can
        // validate CSRF, complete the PKCE exchange, and identify the user
        // without session auth (cross-site redirects may not carry cookies).
        sqlx::query(
            "INSERT INTO oauth_state_tokens (state_token, provider, pkce_verifier, user_id) VALUES ($1, $2, $3, $4)",
        )
        .bind(&state_secret)
        .bind("gmail")
        .bind(pkce_verifier.secret())
        .bind(user_id)
        .execute(&self.db_pool)
        .await
        .context("Failed to store Gmail OAuth state token")?;

        Ok((auth_url.to_string(), state_secret))
    }

    /// Handle OAuth callback and store the integration.
    /// `user_id` is recovered from the state token (stored during `get_authorization_url`),
    /// so this handler does NOT require session authentication.
    pub async fn handle_callback(&self, code: String, state: String) -> Result<GmailIntegration> {
        // Validate CSRF state token (single-use, atomic) and recover user_id + PKCE verifier.
        let state_row = sqlx::query_as::<_, (Uuid, Option<String>, Option<Uuid>)>(
            "UPDATE oauth_state_tokens \
             SET used = true \
             WHERE state_token = $1 AND provider = $2 AND used = false AND expires_at > NOW() \
             RETURNING id, pkce_verifier, user_id",
        )
        .bind(&state)
        .bind("gmail")
        .fetch_optional(&self.db_pool)
        .await
        .context("Failed to validate Gmail OAuth state token")?;

        let (state_id, pkce_verifier_secret, user_id_opt) = state_row.ok_or_else(|| {
            anyhow!("Invalid or expired OAuth state token. This may indicate a CSRF attack.")
        })?;

        // MCP-1096 (2026-05-16): scrub pkce_verifier post-consume.
        // See talos-slack::handle_callback for the full rationale —
        // defense-in-depth against a read-only DB compromise during
        // the 10-min cleanup window.
        if let Err(e) =
            sqlx::query("UPDATE oauth_state_tokens SET pkce_verifier = NULL WHERE id = $1")
                .bind(state_id)
                .execute(&self.db_pool)
                .await
        {
            tracing::warn!(
                state_id = %state_id,
                "Failed to scrub pkce_verifier after Gmail OAuth consume: {}",
                e
            );
        }

        let user_id = user_id_opt.ok_or_else(|| {
            anyhow!("State token missing user_id — cannot identify the initiating user")
        })?;
        // Build OAuth client – handle missing configuration explicitly
        let client_id = self
            .client_id
            .clone()
            .ok_or_else(|| anyhow!("GMAIL_CLIENT_ID not set"))?;
        let client_secret = self
            .client_secret
            .clone()
            .ok_or_else(|| anyhow!("GMAIL_CLIENT_SECRET not set"))?;
        let redirect_uri = self
            .redirect_uri
            .clone()
            .ok_or_else(|| anyhow!("GMAIL_REDIRECT_URI not set"))?;

        // Exchange code for tokens via direct reqwest (not oauth2 crate — Google
        // accepts form-urlencoded but the crate swallows error details on failure).
        // MCP-533: this POST carries `client_secret` + `code` +
        // `code_verifier`. `redirect(Policy::none())` + loud
        // `.expect()` instead of `unwrap_or_else(Client::new)` so a
        // TLS-init failure surfaces immediately rather than silently
        // re-enabling default redirects.
        //
        // 2026-05-28 audit Perf#9: route through the per-crate
        // `OAUTH_HTTP_CLIENT` so TLS context + connection pool stay
        // shared across token exchange + userinfo + (any future)
        // refresh path. Mirrors the talos-atlassian fix.

        // Build the token exchange form. Include the PKCE code_verifier
        // when present — this completes the S256 challenge/verifier handshake
        // and prevents authorization code interception attacks.
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
            // MCP-529: DLP-scrub the body preview before tracing. The
            // Google OAuth token endpoint error responses include the
            // text of failed requests on some error classes — and the
            // request body itself contains the `client_secret` /
            // `code_verifier` / `refresh_token`. Pre-fix the bare
            // body_preview rode any echoed credential into the log
            // aggregator. Same DLP boundary as MCP-527 / MCP-528.
            let body = crate::http_body::read_error_text_capped(token_resp).await;
            let preview =
                talos_text_util::truncate_at_char_boundary(&body, 500);
            let redacted = talos_dlp_provider::redact_str(preview);
            tracing::error!(
                status = %status,
                body_len = body.len(),
                body_preview = %redacted,
                "Gmail token exchange failed"
            );
            return Err(anyhow!("Gmail token exchange failed (HTTP {})", status));
        }

        #[derive(serde::Deserialize)]
        struct TokenResponse {
            access_token: String,
            refresh_token: Option<String>,
            expires_in: Option<u64>,
        }

        let token_data: TokenResponse = token_resp
            .json()
            .await
            .context("Failed to parse Gmail token response")?;

        let access_token = token_data.access_token;
        let refresh_token = token_data.refresh_token;
        // MCP-960..962 sibling + chrono panic defense: route through
        // the canonical helper so a misbehaving provider returning a
        // u64 expires_in > i64::MAX doesn't wrap to a negative i64
        // (immediate-expiry + refresh-storm) or trip
        // `chrono::Duration::seconds`' internal i64-ms overflow panic.
        let token_expires_at = Some(talos_oauth::oauth_expires_at(token_data.expires_in));

        // Get user's email address
        // MCP-533: GET with `bearer_auth(access_token)` — same Mode-B
        // hardening as the token-exchange POST above.
        // Perf#9: route through the shared OAUTH_HTTP_CLIENT.
        let user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo";
        let user_info: serde_json::Value = OAUTH_HTTP_CLIENT
            .get(user_info_url)
            .bearer_auth(&access_token)
            .send()
            .await?
            .json()
            .await?;

        let email_address = user_info["email"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing email in user info"))?
            .to_string();

        let account_name = user_info["name"].as_str().map(|s| s.to_string());

        // Store or update integration
        let integration = self
            .upsert_integration(
                user_id,
                email_address,
                account_name,
                access_token,
                refresh_token,
                token_expires_at,
                Some("gmail.readonly,gmail.modify,userinfo.email".to_string()),
            )
            .await?;

        // Log the event
        self.log_event(
            Some(integration.id),
            Some(user_id),
            "connected",
            true,
            None,
            None,
        )
        .await;

        Ok(integration)
    }

    /// Insert or update a Gmail integration (metadata only).
    ///
    /// Tokens are stored exclusively in the unified credential service —
    /// the gmail_integrations table holds only metadata (scope, expiry,
    /// account info). This matches the Atlassian and Calendar patterns.
    #[allow(clippy::too_many_arguments)]
    async fn upsert_integration(
        &self,
        user_id: Uuid,
        email_address: String,
        account_name: Option<String>,
        access_token: String,
        refresh_token: Option<String>,
        token_expires_at: Option<DateTime<Utc>>,
        scope: Option<String>,
    ) -> Result<GmailIntegration> {
        let integration = sqlx::query_as::<_, GmailIntegration>(
            r#"
            INSERT INTO gmail_integrations (
                user_id, email_address, account_name,
                token_expires_at, scope
            )
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (user_id, email_address)
            DO UPDATE SET
                account_name = EXCLUDED.account_name,
                token_expires_at = EXCLUDED.token_expires_at,
                scope = EXCLUDED.scope,
                is_active = TRUE,
                updated_at = NOW()
            RETURNING *
            "#,
        )
        .bind(user_id)
        .bind(&email_address)
        .bind(account_name)
        .bind(token_expires_at)
        .bind(&scope)
        .fetch_one(&self.db_pool)
        .await
        .context("Failed to upsert Gmail integration")?;

        // Store tokens in the unified credential service (required).
        if let Some(cred_svc) = &self.credentials_service {
            cred_svc
                .store_credentials(
                    user_id,
                    "gmail",
                    &email_address,
                    &access_token,
                    refresh_token.as_deref(),
                    token_expires_at.unwrap_or_else(|| Utc::now() + Duration::hours(1)),
                    scope.as_deref().unwrap_or(""),
                    vec![],
                )
                .await
                .context("Failed to store Gmail credentials in vault")?;
        } else {
            anyhow::bail!("Credential service not configured — cannot store Gmail tokens");
        }

        Ok(integration)
    }

    /// Get all integrations for a user
    pub async fn get_user_integrations(&self, user_id: Uuid) -> Result<Vec<GmailIntegrationInfo>> {
        let integrations = sqlx::query_as::<_, GmailIntegrationInfo>(
            r#"
            SELECT id, email_address, account_name, scope, is_active, created_at, last_used_at, token_expires_at
            FROM gmail_integrations
            WHERE user_id = $1 AND is_active = TRUE
            ORDER BY created_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;

        Ok(integrations)
    }

    pub async fn get_integration_info(
        &self,
        integration_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<GmailIntegrationInfo>> {
        let integration = sqlx::query_as::<_, GmailIntegrationInfo>(
            r#"
            SELECT id, email_address, account_name, scope, is_active, created_at, last_used_at, token_expires_at
            FROM gmail_integrations
            WHERE id = $1 AND user_id = $2 AND is_active = TRUE
            "#,
        )
        .bind(integration_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;

        Ok(integration)
    }

    /// Get a specific integration
    pub async fn get_integration(
        &self,
        integration_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<GmailIntegration>> {
        let integration = sqlx::query_as::<_, GmailIntegration>(
            r#"
            SELECT *
            FROM gmail_integrations
            WHERE id = $1 AND user_id = $2 AND is_active = TRUE
            "#,
        )
        .bind(integration_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;

        Ok(integration)
    }

    /// Get integration with valid access token (refresh if needed).
    ///
    /// Returns the decrypted access token, refreshing if expired.
    /// Decrypts `access_token_enc` via the `SecretsManager`.
    /// Plaintext fallback columns were dropped by migrations 036 + 20260310001300.
    pub async fn get_integration_with_token(
        &self,
        integration_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<(GmailIntegration, String)>> {
        let integration = match self.get_integration(integration_id, user_id).await? {
            Some(i) => i,
            None => return Ok(None),
        };

        // Read access token from the unified credential service. The
        // centralized proactive refresh task handles expiry — no need
        // for inline refresh logic here. This replaces the old inline
        // decrypt-check-refresh-update cycle that competed with the
        // centralized OAuthCredentialService.
        let email = &integration.email();
        let access_token = self
            .get_access_token(user_id, email)
            .await
            .context("Failed to get Gmail access token from credential service")?;

        Ok(Some((integration, access_token)))
    }

    // update_access_token removed — token refresh is handled entirely by
    // the centralized OAuthCredentialService. The _enc columns it wrote to
    // were dropped by migration 20260413000003.

    /// Disconnect (deactivate) an integration.
    ///
    /// Three-step disconnect (best-effort revoke + cleanup):
    ///   1. Look up the row to recover the email (provider_key) for vault paths.
    ///   2. Call `OAuthCredentialService::revoke_and_cleanup` — revokes at
    ///      Google, deletes vault token entries, soft-deletes the unified
    ///      `integration_credentials` row.
    ///   3. Soft-delete the `gmail_integrations` row (authorisation gate via
    ///      `WHERE user_id = $2` — `rows_affected() == 0` = not yours).
    ///
    /// Vault cleanup happens even when provider revoke fails so a flaky
    /// Google response doesn't strand secrets in the local store.
    pub async fn disconnect_integration(&self, integration_id: Uuid, user_id: Uuid) -> Result<()> {
        // Step 1: recover the email — needed as `provider_key` for vault paths.
        // Read with active=true filter so we don't try to revoke for an
        // already-disconnected integration.
        let email: Option<String> = sqlx::query_scalar(
            "SELECT email_address FROM gmail_integrations \
             WHERE id = $1 AND user_id = $2 AND is_active = TRUE",
        )
        .bind(integration_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;

        // Step 2: best-effort provider revoke + vault cleanup.
        if let (Some(em), Some(cred_svc)) = (email.as_deref(), &self.credentials_service) {
            if let Err(e) = cred_svc.revoke_and_cleanup(user_id, "gmail", em).await {
                tracing::warn!(
                    user_id = %user_id,
                    integration_id = %integration_id,
                    error = %e,
                    "Gmail revoke_and_cleanup failed — proceeding with metadata flip"
                );
            }
        }

        // Step 3: soft-delete the metadata row (authorisation gate).
        let result = sqlx::query(
            "UPDATE gmail_integrations SET is_active = FALSE, updated_at = NOW() WHERE id = $1 AND user_id = $2",
        )
        .bind(integration_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;

        if result.rows_affected() == 0 {
            anyhow::bail!("Integration not found or access denied");
        }

        self.log_event(
            Some(integration_id),
            Some(user_id),
            "disconnected",
            true,
            None,
            None,
        )
        .await;

        Ok(())
    }

    /// Mark integration as used (update last_used_at)
    pub async fn mark_used(&self, integration_id: Uuid) -> Result<()> {
        sqlx::query("UPDATE gmail_integrations SET last_used_at = NOW() WHERE id = $1")
            .bind(integration_id)
            .execute(&self.db_pool)
            .await?;

        Ok(())
    }

    /// Log an integration event
    async fn log_event(
        &self,
        integration_id: Option<Uuid>,
        user_id: Option<Uuid>,
        event_type: &str,
        success: bool,
        error_message: Option<&str>,
        metadata: Option<serde_json::Value>,
    ) {
        // MCP-483: DLP-scrub the error_message and metadata before
        // persisting to `gmail_integration_audit_log`. The audit log
        // receives Google API error responses verbatim — those can
        // include refresh_token / access_token values in the
        // `error_description` field or echoed back in the body when
        // a token is rejected. Same persistence-boundary rule as
        // MCP-482 for oauth_audit_log and MCP-481 for worker logs.
        //
        // MCP-1028 (2026-05-15): truncate-then-redact discipline;
        // sibling-parity with MCP-1012/1018. Google API error bodies
        // run ~200-500 chars; 1024 covers every legitimate failure
        // while bounding regex-pass cost.
        let scrubbed_err = error_message.map(|e| {
            let truncated: &str = if e.len() > 1024 {
                talos_text_util::truncate_at_char_boundary(e, 1024)
            } else {
                e
            };
            talos_dlp_provider::redact_str(truncated)
        });
        let scrubbed_err_ref = scrubbed_err.as_deref();
        // MCP-1197 (2026-05-17): measure-first-then-redact via
        // `redact_json_bounded`. Caller-supplied metadata can pack
        // unbounded data (e.g. webhook-replay events with large
        // history-id arrays); the 1 MiB cap prevents audit-table /
        // WAL bloat under a wide outage. Returning `None` drops the
        // metadata column to NULL — error_message + event_type still
        // persist. Sibling of `bound_log_details` (MCP-1195).
        let scrubbed_meta = metadata
            .as_ref()
            .and_then(talos_dlp_provider::redact_json_bounded);
        let result = sqlx::query(
            "INSERT INTO gmail_integration_audit_log (integration_id, user_id, event_type, success, error_message, metadata) VALUES ($1, $2, $3, $4, $5, $6)"
        )
        .bind(integration_id)
        .bind(user_id)
        .bind(event_type)
        .bind(success)
        .bind(scrubbed_err_ref)
        .bind(&scrubbed_meta)
        .execute(&self.db_pool)
        .await;

        if let Err(e) = result {
            tracing::error!("Failed to log Gmail integration event: {}", e);
        }
    }
}
