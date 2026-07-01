use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};
use std::sync::Arc;
use std::sync::LazyLock;

/// Shared reqwest client for Slack OAuth callback (oauth.v2.access).
/// Mirrors the per-crate shared-client pattern (MCP-1110/1111 +
/// 2026-05-28 Perf#9 audit). Pre-fix the callback built a fresh
/// `reqwest::Client` per OAuth completion — TLS init + pool reset
/// per call, defeating keep-alive against slack.com. Hardening
/// contract preserved: timeout(15s) + connect_timeout(5s) +
/// redirect::Policy::none() (form bodies aren't stripped on
/// same-origin redirects).
static OAUTH_HTTP_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    talos_http_utils::trusted_client::build_integration_client(std::time::Duration::from_secs(15))
});
use uuid::Uuid;

/// Slack workspace integration metadata.
///
/// Tokens are NOT stored here — they live exclusively in the unified
/// `integration_credentials` table and are accessed via the
/// `OAuthCredentialService` / `SecretsManager`. This matches the
/// Atlassian integration pattern.
#[derive(Clone, sqlx::FromRow)]
pub struct SlackIntegration {
    pub id: Uuid,
    pub user_id: Uuid,
    pub team_id: String,
    pub team_name: String,
    pub team_domain: Option<String>,
    pub bot_user_id: Option<String>,
    pub app_id: Option<String>,
    pub scope: Option<String>,
    pub verification_token: Option<String>,
    pub is_active: bool,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
}

// Custom Debug so a stray `{:?}` never prints the Slack verification token
// (used to authenticate inbound Slack events). All other fields are non-secret.
impl std::fmt::Debug for SlackIntegration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlackIntegration")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("team_id", &self.team_id)
            .field("team_name", &self.team_name)
            .field("team_domain", &self.team_domain)
            .field("bot_user_id", &self.bot_user_id)
            .field("app_id", &self.app_id)
            .field("scope", &self.scope)
            .field(
                "verification_token",
                &self.verification_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("is_active", &self.is_active)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("last_used_at", &self.last_used_at)
            .finish()
    }
}

/// Simplified version for API responses (without sensitive tokens)
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SlackIntegrationInfo {
    pub id: Uuid,
    pub team_id: String,
    pub team_name: String,
    pub team_domain: Option<String>,
    pub bot_user_id: Option<String>,
    pub scope: Option<String>,
    pub is_active: bool,
    pub created_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
}

impl From<SlackIntegration> for SlackIntegrationInfo {
    fn from(integration: SlackIntegration) -> Self {
        Self {
            id: integration.id,
            team_id: integration.team_id,
            team_name: integration.team_name,
            team_domain: integration.team_domain,
            bot_user_id: integration.bot_user_id,
            scope: integration.scope,
            is_active: integration.is_active,
            created_at: integration.created_at,
            last_used_at: integration.last_used_at,
        }
    }
}

/// Service for managing Slack workspace integrations
pub struct SlackIntegrationService {
    db_pool: Pool<Postgres>,
    client_id: Option<String>,
    client_secret: Option<String>,
    redirect_uri: Option<String>,
    secrets_manager: Option<Arc<talos_secrets_manager::SecretsManager>>,
    credentials_service: Option<Arc<talos_oauth::OAuthCredentialService>>,
}

impl SlackIntegrationService {
    pub fn new(db_pool: Pool<Postgres>) -> Result<Self> {
        Ok(Self {
            db_pool,
            // MCP-710 (2026-05-13): empty-env class — see GmailIntegrationService.
            client_id: std::env::var("SLACK_CLIENT_ID")
                .ok()
                .filter(|v| !v.is_empty()),
            client_secret: std::env::var("SLACK_CLIENT_SECRET")
                .ok()
                .filter(|v| !v.is_empty()),
            redirect_uri: std::env::var("SLACK_REDIRECT_URI")
                .ok()
                .filter(|v| !v.is_empty()),
            secrets_manager: None,
            credentials_service: None,
        })
    }

    /// Attach a SecretsManager so that OAuth tokens are encrypted at rest.
    pub fn with_secrets_manager(mut self, sm: Arc<talos_secrets_manager::SecretsManager>) -> Self {
        self.secrets_manager = Some(sm);
        self
    }

    /// Attach the unified credential service for vault-resolvable token storage.
    pub fn with_credentials_service(
        mut self,
        svc: Arc<talos_oauth::OAuthCredentialService>,
    ) -> Self {
        self.credentials_service = Some(svc);
        self
    }

    /// Check if Slack OAuth is configured
    pub fn is_configured(&self) -> bool {
        self.client_id.is_some() && self.client_secret.is_some() && self.redirect_uri.is_some()
    }

    /// Generate OAuth authorization URL for connecting a Slack workspace.
    ///
    /// `user_id` is bound into the state token so the callback can recover
    /// it without trusting a session cookie. Without this binding, an
    /// attacker who completes the Slack consent flow against their own
    /// account can hand a victim a callback URL (`code` + their own
    /// `state`) — the victim's logged-in cookie ID then becomes the
    /// `user_id` the integration is linked to, attaching the attacker's
    /// Slack workspace to the victim's Talos account.
    pub async fn get_authorization_url(&self, user_id: Uuid) -> Result<(String, String)> {
        // Delegate to the shared driver — it builds the authorize URL from
        // `authorize_request()` and persists the PKCE + CSRF state token bound
        // to `user_id`. See the `OAuthIntegration` impl below.
        talos_oauth::authorization_url(&self.db_pool, self, user_id).await
    }

    /// Handle OAuth callback and store the integration
    pub async fn handle_callback(&self, code: String, state: String) -> Result<SlackIntegration> {
        // Delegate to the shared driver — it consumes + validates the CSRF state
        // token (single-use, format, tenancy) and only then hands the validated
        // `ConsumedOAuthState` to `complete_callback()`. See the
        // `OAuthIntegration` impl below.
        talos_oauth::handle_oauth_callback(&self.db_pool, self, &code, &state).await
    }
}

/// Canonical reference implementation of the shared OAuth flow contract.
///
/// The public [`SlackIntegrationService::get_authorization_url`] /
/// [`SlackIntegrationService::handle_callback`] methods delegate to the
/// `talos_oauth` drivers, which run the CSRF / PKCE / single-use / tenancy
/// handling and call back into these three provider-specific pieces.
#[async_trait::async_trait]
impl talos_oauth::OAuthIntegration for SlackIntegrationService {
    type Connected = SlackIntegration;

    fn provider(&self) -> &'static str {
        "slack"
    }

    fn authorize_request(&self) -> Result<talos_oauth::AuthorizeRequest<'static>> {
        if !self.is_configured() {
            return Err(anyhow!(
                "Slack OAuth is not configured. Set SLACK_CLIENT_ID, SLACK_CLIENT_SECRET, and SLACK_REDIRECT_URI"
            ));
        }

        // Authorize URL + PKCE + CSRF state token (bound to user_id) via the
        // shared flow helper — the CSRF/PKCE/tenancy handling lives in one place.
        Ok(talos_oauth::AuthorizeRequest {
            provider: "slack",
            auth_url: "https://slack.com/oauth/v2/authorize",
            token_url: "https://slack.com/api/oauth.v2.access",
            client_id: self
                .client_id
                .clone()
                .ok_or_else(|| anyhow!("SLACK_CLIENT_ID not set"))?,
            client_secret: self
                .client_secret
                .clone()
                .ok_or_else(|| anyhow!("SLACK_CLIENT_SECRET not set"))?,
            redirect_uri: self
                .redirect_uri
                .clone()
                .ok_or_else(|| anyhow!("SLACK_REDIRECT_URI not set"))?,
            // Bot token scopes.
            scopes: &[
                "channels:read",
                "users:read",
                "channels:history",
                "chat:write",
            ],
            extra_params: &[("user_scope", "")],
        })
    }

    async fn complete_callback(
        &self,
        _pool: &sqlx::PgPool,
        code: &str,
        consumed: talos_oauth::ConsumedOAuthState,
    ) -> Result<SlackIntegration> {
        // SECURITY: user_id comes from the state token (bound at connect time),
        // NOT the callback's session cookie — otherwise an attacker who completes
        // Slack consent on their own account could hand a victim a callback URL
        // and link the attacker's workspace to the victim. The CSRF single-use /
        // PKCE scrub / format-gate / tenancy consume already happened in the
        // shared driver (talos_oauth::consume_oauth_state) before this call.
        let user_id = consumed.user_id;
        let pkce_verifier_secret = consumed.pkce_verifier;

        // Build the token exchange. Include PKCE code_verifier when present.
        let mut token_params: Vec<(&str, String)> = vec![
            (
                "client_id",
                self.client_id
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("SLACK_CLIENT_ID not set"))?,
            ),
            (
                "client_secret",
                self.client_secret
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("SLACK_CLIENT_SECRET not set"))?,
            ),
            ("code", code.to_string()),
        ];
        if let Some(verifier) = pkce_verifier_secret {
            token_params.push(("code_verifier", verifier));
        }

        // MCP-533: Mode-B credential-leak surface. This POST carries
        // `client_secret` + `code` + (when present) `code_verifier`
        // in its form body to slack.com/api/oauth.v2.access. Two
        // pre-fix gaps:
        //
        // 1. `Client::builder()…build()` with no `.redirect(Policy::none())`
        //    leaves the default 10-redirect policy in place. A 302 from
        //    slack.com to any same-origin host (or a future open-redirect
        //    bug) would re-issue the POST — including the secret-bearing
        //    form body — to the redirect target. reqwest strips ONLY
        //    `Authorization` on cross-origin redirects; form bodies are
        //    never stripped.
        //
        // 2. `.unwrap_or_else(|_| reqwest::Client::new())` is the exact
        //    anti-pattern called out in the SSRF-redirect memory: it
        //    silently re-enables default redirect-following on TLS-init
        //    failure (the only realistic cause of `.build()` failing).
        //    `.expect(…)` is correct here — TLS init failure is a
        //    deployment problem that must be loud, not silently
        //    downgraded into a security regression. The sibling
        //    `talos-slack::SlackApiClient` (bot-token-bearing
        //    chat.postMessage etc.) was fixed in MCP-471; this OAuth
        //    callback path was missed because it builds a one-shot
        //    client inline instead of going through the shared client.
        // Perf#9: route through the shared OAUTH_HTTP_CLIENT defined
        // at module scope — TLS context + connection pool stay shared
        // across all OAuth callbacks. See the module-level static for
        // the security-rationale doc-comment.
        // Cap the response body (lint-31 / unbounded-read class). slack.com is a
        // fixed trusted host, but every other OAuth callback reads through the
        // shared capped-body crate; this brings the Slack token exchange to parity.
        let token_resp = OAUTH_HTTP_CLIENT
            .post("https://slack.com/api/oauth.v2.access")
            .form(&token_params)
            .send()
            .await?;
        let oauth_response: serde_json::Value =
            talos_http_body::read_json_capped(token_resp).await?;

        if !oauth_response["ok"].as_bool().unwrap_or(false) {
            let error = oauth_response["error"].as_str().unwrap_or("unknown");
            return Err(anyhow!("Slack OAuth error: {}", error));
        }

        // Extract team info
        let team = oauth_response["team"]
            .as_object()
            .ok_or_else(|| anyhow!("Missing team info"))?;
        let team_id = team["id"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing team ID"))?
            .to_string();
        let team_name = team["name"].as_str().unwrap_or("Unknown").to_string();

        // Extract bot token
        let bot_token = oauth_response
            .get("access_token")
            .and_then(|t| t.as_str())
            .ok_or_else(|| anyhow!("Missing bot token"))?
            .to_string();

        let bot_user_id = oauth_response
            .get("bot_user_id")
            .and_then(|b| b.as_str())
            .map(|s| s.to_string());

        let app_id = oauth_response
            .get("app_id")
            .and_then(|a| a.as_str())
            .map(|s| s.to_string());

        let scope = oauth_response
            .get("scope")
            .and_then(|s| s.as_str())
            .map(|s| s.to_string());

        // Get verification token from app info (if available)
        // Note: Slack is deprecating verification tokens in favor of signing secrets
        // For now, users will need to manually add verification tokens from Slack app settings
        let verification_token: Option<String> = None;

        // Store or update integration
        let bot_token_clone = bot_token.clone();
        let integration = self
            .upsert_integration(
                user_id,
                team_id,
                team_name,
                None, // team_domain - could fetch this with another API call if needed
                bot_token,
                bot_user_id,
                None, // access_token (user token, if requested)
                app_id,
                scope,
                verification_token,
            )
            .await?;

        // Dual-write: store bot token in the unified credential service so
        // WASM modules can access it via vault://oauth/slack/{user_id}/{team_id}/
        // access_token. Bot tokens don't expire, so we use a 10-year expiry.
        // The proactive refresh task will see this token but skip it because
        // the expiry is far in the future.
        if let Some(ref cred_svc) = self.credentials_service {
            let granted_scope = integration.scope.clone().unwrap_or_default();
            if let Err(e) = cred_svc
                .store_credentials(
                    user_id,
                    "slack",
                    &integration.team_id,
                    &bot_token_clone,
                    None, // Slack bot tokens don't use refresh tokens
                    chrono::Utc::now() + chrono::Duration::days(3650), // 10 years — bot tokens don't expire
                    &granted_scope,
                    vec![],
                )
                .await
            {
                tracing::error!(
                    user_id = %user_id,
                    team_id = %integration.team_id,
                    error = %e,
                    "Failed to store Slack credentials in vault"
                );
            } else {
                tracing::info!(
                    user_id = %user_id,
                    team_id = %integration.team_id,
                    "Slack credentials stored in unified credential service"
                );
            }
        }

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
}

impl SlackIntegrationService {
    /// Insert or update a Slack integration.
    /// Insert or update a Slack integration (metadata only).
    ///
    /// Tokens are NOT stored in this table — they go to the unified
    /// credential service in the `handle_callback` function. This
    /// upsert only handles metadata (team info, scopes, etc.).
    async fn upsert_integration(
        &self,
        user_id: Uuid,
        team_id: String,
        team_name: String,
        team_domain: Option<String>,
        _bot_token: String,
        bot_user_id: Option<String>,
        _access_token: Option<String>,
        app_id: Option<String>,
        scope: Option<String>,
        verification_token: Option<String>,
    ) -> Result<SlackIntegration> {
        let integration = sqlx::query_as::<_, SlackIntegration>(
            r#"
            INSERT INTO slack_integrations (
                user_id, team_id, team_name, team_domain,
                bot_user_id, app_id, scope, verification_token
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (user_id, team_id)
            DO UPDATE SET
                team_name = EXCLUDED.team_name,
                team_domain = EXCLUDED.team_domain,
                bot_user_id = EXCLUDED.bot_user_id,
                app_id = EXCLUDED.app_id,
                scope = EXCLUDED.scope,
                verification_token = EXCLUDED.verification_token,
                is_active = TRUE,
                updated_at = NOW()
            RETURNING *
            "#,
        )
        .bind(user_id)
        .bind(team_id)
        .bind(team_name)
        .bind(team_domain)
        .bind(bot_user_id)
        .bind(app_id)
        .bind(scope)
        .bind(verification_token)
        .fetch_one(&self.db_pool)
        .await
        .context("Failed to upsert Slack integration")?;

        Ok(integration)
    }

    /// Return the effective bot token for this integration via the unified
    /// credential service (vault://oauth/slack/{user_id}/{team_id}/access_token).
    ///
    /// This is the ONLY token read path — no fallback to legacy encrypted
    /// columns. Integrations must be connected (or reconnected) through the
    /// OAuth flow which dual-writes to the credential service.
    pub async fn resolve_bot_token(&self, integration: &SlackIntegration) -> Result<String> {
        let vault_path = format!(
            "oauth/slack/{}/{}/access_token",
            integration.user_id, integration.team_id
        );
        let sm = self
            .secrets_manager
            .as_ref()
            .ok_or_else(|| anyhow!("SecretsManager not configured"))?;
        let secrets = sm
            .get_secrets_by_paths(std::slice::from_ref(&vault_path), Some(integration.user_id))
            .await
            .context("Failed to fetch Slack bot token from vault")?;

        secrets.get(&vault_path).cloned().ok_or_else(|| {
            anyhow!(
                "Slack bot token not found at '{}'. Reconnect the Slack integration.",
                vault_path
            )
        })
    }

    /// Get all integrations for a user
    pub async fn get_user_integrations(&self, user_id: Uuid) -> Result<Vec<SlackIntegrationInfo>> {
        let integrations = sqlx::query_as::<_, SlackIntegrationInfo>(
            r#"
            SELECT id, team_id, team_name, team_domain, bot_user_id, scope, is_active, created_at, last_used_at
            FROM slack_integrations
            WHERE user_id = $1 AND is_active = TRUE
            ORDER BY created_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;

        Ok(integrations)
    }

    /// Get a specific integration
    pub async fn get_integration(
        &self,
        integration_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<SlackIntegrationInfo>> {
        let integration = sqlx::query_as::<_, SlackIntegrationInfo>(
            r#"
            SELECT id, team_id, team_name, team_domain, bot_user_id, scope, is_active, created_at, last_used_at
            FROM slack_integrations
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
    /// Calls Slack's `auth.revoke` to invalidate the bot token at the
    /// workspace, deletes vault tokens, then soft-deletes the metadata row.
    /// Vault cleanup proceeds even if Slack's revoke fails so a transient
    /// upstream blip doesn't strand the secret locally.
    pub async fn disconnect_integration(&self, integration_id: Uuid, user_id: Uuid) -> Result<()> {
        // Recover team_id (provider_key for vault paths) from the active row.
        let team_id: Option<String> = sqlx::query_scalar(
            "SELECT team_id FROM slack_integrations \
             WHERE id = $1 AND user_id = $2 AND is_active = TRUE",
        )
        .bind(integration_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;

        if let (Some(tid), Some(cred_svc)) = (team_id.as_deref(), &self.credentials_service) {
            if let Err(e) = cred_svc.revoke_and_cleanup(user_id, "slack", tid).await {
                tracing::warn!(
                    user_id = %user_id,
                    integration_id = %integration_id,
                    error = %e,
                    "Slack revoke_and_cleanup failed — proceeding with metadata flip"
                );
            }
        }

        let result = sqlx::query(
            "UPDATE slack_integrations SET is_active = FALSE, updated_at = NOW() WHERE id = $1 AND user_id = $2"
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
        sqlx::query("UPDATE slack_integrations SET last_used_at = NOW() WHERE id = $1")
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
        // MCP-483: DLP-scrub error_message + metadata before
        // persisting to `slack_integration_audit_log`. Slack API
        // errors can include the bot token or signing secret echoed
        // back in `error_description` / `warning` fields on token-
        // related failures. Same persistence-boundary rule as
        // MCP-482 (OAuth audit) and the Gmail equivalent in MCP-483.
        //
        // MCP-1028 (2026-05-15): truncate-then-redact discipline,
        // sibling-parity with MCP-1012/1018. Slack API error
        // payloads run small but truncate-first means the regex
        // pass cost is bounded regardless of upstream verbosity.
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
        // unbounded data on bulk-event paths; 1 MiB cap prevents
        // audit-table / WAL bloat. Returning `None` drops the
        // metadata column to NULL — error_message + event_type still
        // persist. Sibling of `bound_log_details` (MCP-1195).
        let scrubbed_meta = metadata
            .as_ref()
            .and_then(talos_dlp_provider::redact_json_bounded);
        let result = sqlx::query(
            "INSERT INTO slack_integration_audit_log (integration_id, user_id, event_type, success, error_message, metadata) VALUES ($1, $2, $3, $4, $5, $6)"
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
            tracing::error!("Failed to log Slack integration event: {}", e);
        }
    }
}
