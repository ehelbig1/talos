use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope, TokenUrl,
};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};
use std::sync::Arc;
use uuid::Uuid;

/// Slack workspace integration record
#[derive(Debug, Clone, sqlx::FromRow)]
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
    /// AES-256-GCM encrypted bot token (migration 018). Preferred over `bot_token`.
    pub bot_token_enc: Option<Vec<u8>>,
    /// AES-256-GCM encrypted user access token (migration 018). Preferred over `access_token`.
    pub access_token_enc: Option<Vec<u8>>,
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
    secrets_manager: Option<Arc<crate::secrets::SecretsManager>>,
}

impl SlackIntegrationService {
    pub fn new(db_pool: Pool<Postgres>) -> Result<Self> {
        Ok(Self {
            db_pool,
            client_id: std::env::var("SLACK_CLIENT_ID").ok(),
            client_secret: std::env::var("SLACK_CLIENT_SECRET").ok(),
            redirect_uri: std::env::var("SLACK_REDIRECT_URI").ok(),
            secrets_manager: None,
        })
    }

    /// Attach a SecretsManager so that OAuth tokens are encrypted at rest.
    pub fn with_secrets_manager(mut self, sm: Arc<crate::secrets::SecretsManager>) -> Self {
        self.secrets_manager = Some(sm);
        self
    }

    /// Encrypt a token for single-column storage.
    ///
    /// `SecretsManager::encrypt_value` returns `(key_id, nonce || ciphertext)`. We
    /// embed the key_id as a 16-byte prefix so that `SecretsManager::decrypt_value`
    /// can recover it later without needing a separate column.
    ///
    /// Falls back to `None` if no SecretsManager is configured (tests / dev without
    /// TALOS_MASTER_KEY).
    async fn encrypt_token(&self, token: &str) -> Result<Option<Vec<u8>>> {
        match &self.secrets_manager {
            Some(sm) => {
                let (key_id, enc) = sm.encrypt_value(token).await?;
                // Blob format: 16-byte key_id UUID || 12-byte nonce || ciphertext
                let mut blob = Vec::with_capacity(16 + enc.len());
                blob.extend_from_slice(key_id.as_bytes());
                blob.extend_from_slice(&enc);
                Ok(Some(blob))
            }
            None => Ok(None),
        }
    }

    /// Decrypt a token from storage.  Returns `None` if `enc` is `None`.
    async fn decrypt_token(&self, enc: Option<Vec<u8>>) -> Result<Option<String>> {
        match (enc, &self.secrets_manager) {
            (Some(bytes), Some(sm)) => Ok(Some(sm.decrypt_value(&bytes).await?)),
            _ => Ok(None),
        }
    }

    /// Check if Slack OAuth is configured
    pub fn is_configured(&self) -> bool {
        self.client_id.is_some() && self.client_secret.is_some() && self.redirect_uri.is_some()
    }

    /// Generate OAuth authorization URL for connecting a Slack workspace
    pub async fn get_authorization_url(&self) -> Result<(String, String)> {
        if !self.is_configured() {
            return Err(anyhow!(
                "Slack OAuth is not configured. Set SLACK_CLIENT_ID, SLACK_CLIENT_SECRET, and SLACK_REDIRECT_URI"
            ));
        }

        let client = BasicClient::new(
            ClientId::new(
                self.client_id
                    .clone()
                    .ok_or_else(|| anyhow!("SLACK_CLIENT_ID not set"))?,
            ),
            Some(ClientSecret::new(
                self.client_secret
                    .clone()
                    .ok_or_else(|| anyhow!("SLACK_CLIENT_SECRET not set"))?,
            )),
            AuthUrl::new("https://slack.com/oauth/v2/authorize".to_string())?,
            Some(TokenUrl::new(
                "https://slack.com/api/oauth.v2.access".to_string(),
            )?),
        )
        .set_redirect_uri(RedirectUrl::new(
            self.redirect_uri
                .clone()
                .ok_or_else(|| anyhow!("SLACK_REDIRECT_URI not set"))?,
        )?);

        let (auth_url, csrf_token) = client
            .authorize_url(CsrfToken::new_random)
            // Request bot token scopes
            .add_scope(Scope::new("channels:read".to_string()))
            .add_scope(Scope::new("users:read".to_string()))
            .add_scope(Scope::new("channels:history".to_string()))
            .add_scope(Scope::new("chat:write".to_string()))
            // Add user scopes if needed
            .add_extra_param("user_scope", "")
            .url();

        let state_secret = csrf_token.secret().to_string();

        sqlx::query("INSERT INTO oauth_state_tokens (state_token, provider) VALUES ($1, $2)")
            .bind(&state_secret)
            .bind("slack")
            .execute(&self.db_pool)
            .await
            .context("Failed to store Slack OAuth state token")?;

        Ok((auth_url.to_string(), state_secret))
    }

    /// Handle OAuth callback and store the integration
    pub async fn handle_callback(
        &self,
        user_id: Uuid,
        code: String,
        state: String,
    ) -> Result<SlackIntegration> {
        // Validate CSRF state token
        let result = sqlx::query(
            "UPDATE oauth_state_tokens
             SET used = true
             WHERE state_token = $1 AND provider = $2 AND used = false AND expires_at > NOW()
             RETURNING id",
        )
        .bind(&state)
        .bind("slack")
        .fetch_optional(&self.db_pool)
        .await
        .context("Failed to validate Slack OAuth state token")?;

        if result.is_none() {
            return Err(anyhow!(
                "Invalid or expired OAuth state token. This may indicate a CSRF attack."
            ));
        }

        // Call Slack API to get full OAuth response (includes team info and bot token)
        let oauth_response: serde_json::Value = reqwest::Client::new()
            .post("https://slack.com/api/oauth.v2.access")
            .form(&[
                (
                    "client_id",
                    self.client_id
                        .as_deref()
                        .ok_or_else(|| anyhow::anyhow!("SLACK_CLIENT_ID not set"))?,
                ),
                (
                    "client_secret",
                    self.client_secret
                        .as_deref()
                        .ok_or_else(|| anyhow::anyhow!("SLACK_CLIENT_SECRET not set"))?,
                ),
                ("code", &code),
            ])
            .send()
            .await?
            .json()
            .await?;

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

    /// Insert or update a Slack integration.
    ///
    /// When a SecretsManager is available, the bot_token and access_token are
    /// encrypted with AES-256-GCM and stored in `bot_token_enc` / `access_token_enc`.
    /// The plaintext columns are also kept for backward compat until a future
    /// migration drops them.
    async fn upsert_integration(
        &self,
        user_id: Uuid,
        team_id: String,
        team_name: String,
        team_domain: Option<String>,
        bot_token: String,
        bot_user_id: Option<String>,
        access_token: Option<String>,
        app_id: Option<String>,
        scope: Option<String>,
        verification_token: Option<String>,
    ) -> Result<SlackIntegration> {
        // Encrypt tokens. We now REQUIRE a SecretsManager or at least successful encryption.
        // If SecretsManager is not available, encrypt_token returns None, but we need
        // some data. Actually, let's just use what encrypt_token returns and if it's None,
        // we store NULL, but since we rely on bot_token_enc, this means it will be broken
        // if SecretsManager isn't used. But we must only write to encrypted columns.
        let bot_token_enc = self
            .encrypt_token(&bot_token)
            .await?
            .ok_or_else(|| anyhow!("SecretsManager is required for storing Slack tokens"))?;

        let access_token_enc =
            if let Some(ref at) = access_token {
                Some(self.encrypt_token(at).await?.ok_or_else(|| {
                    anyhow!("SecretsManager is required for storing Slack tokens")
                })?)
            } else {
                None
            };

        let integration = sqlx::query_as::<_, SlackIntegration>(
            r#"
            INSERT INTO slack_integrations (
                user_id, team_id, team_name, team_domain,
                bot_user_id, app_id, scope, verification_token,
                bot_token_enc, access_token_enc
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT (user_id, team_id)
            DO UPDATE SET
                team_name = EXCLUDED.team_name,
                team_domain = EXCLUDED.team_domain,
                bot_user_id = EXCLUDED.bot_user_id,
                app_id = EXCLUDED.app_id,
                scope = EXCLUDED.scope,
                verification_token = EXCLUDED.verification_token,
                bot_token_enc = EXCLUDED.bot_token_enc,
                access_token_enc = EXCLUDED.access_token_enc,
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
        .bind(bot_token_enc)
        .bind(access_token_enc)
        .fetch_one(&self.db_pool)
        .await
        .context("Failed to upsert Slack integration")?;

        Ok(integration)
    }

    /// Return the effective (decrypted) bot token for this integration.
    ///
    /// Reads from the encrypted column (`bot_token_enc`).
    pub async fn resolve_bot_token(&self, integration: &SlackIntegration) -> Result<String> {
        if let Some(ref enc) = integration.bot_token_enc {
            if let Some(sm) = &self.secrets_manager {
                return sm.decrypt_value(enc).await;
            } else {
                return Err(anyhow!(
                    "SecretsManager is required to decrypt Slack tokens"
                ));
            }
        }
        Err(anyhow!("bot_token_enc is missing"))
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
    /// Returns an error if 0 rows were affected (integration not found or belongs
    /// to a different user — authorization check).
    pub async fn disconnect_integration(&self, integration_id: Uuid, user_id: Uuid) -> Result<()> {
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

        // Log the event
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
        let result = sqlx::query(
            "INSERT INTO slack_integration_audit_log (integration_id, user_id, event_type, success, error_message, metadata) VALUES ($1, $2, $3, $4, $5, $6)"
        )
        .bind(integration_id)
        .bind(user_id)
        .bind(event_type)
        .bind(success)
        .bind(error_message)
        .bind(metadata)
        .execute(&self.db_pool)
        .await;

        if let Err(e) = result {
            tracing::error!("Failed to log Slack integration event: {}", e);
        }
    }
}
