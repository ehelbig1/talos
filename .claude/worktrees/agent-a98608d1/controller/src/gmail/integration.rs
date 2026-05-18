use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Duration, Utc};
use oauth2::reqwest::async_http_client;
use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl,
    RefreshToken, Scope, TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};
use std::sync::Arc;
use uuid::Uuid;

use crate::oauth::OAuthCredentialService;
use crate::secrets::SecretsManager;

/// Gmail account integration record
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
    /// AES-256-GCM encrypted access token (nonce || ciphertext).
    /// Added by migration 020. Preferred over plaintext `access_token` when present.
    pub access_token_enc: Option<Vec<u8>>,
    /// AES-256-GCM encrypted refresh token (nonce || ciphertext).
    /// Added by migration 020.
    pub refresh_token_enc: Option<Vec<u8>>,
    /// References `encryption_keys.id` used for the _enc columns.
    /// Required for deterministic decryption after DEK rotation.
    pub token_key_id: Option<Uuid>,
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
            client_id: std::env::var("GMAIL_CLIENT_ID").ok(),
            client_secret: std::env::var("GMAIL_CLIENT_SECRET").ok(),
            redirect_uri: std::env::var("GMAIL_REDIRECT_URI").ok(),
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

    /// Check if Gmail OAuth is configured
    pub fn is_configured(&self) -> bool {
        self.client_id.is_some() && self.client_secret.is_some() && self.redirect_uri.is_some()
    }

    /// Generate OAuth authorization URL for connecting a Gmail account
    pub async fn get_authorization_url(&self) -> Result<(String, String)> {
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
            .url();

        Ok((auth_url.to_string(), csrf_token.secret().to_string()))
    }

    /// Handle OAuth callback and store the integration
    pub async fn handle_callback(&self, user_id: Uuid, code: String) -> Result<GmailIntegration> {
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

        let client = BasicClient::new(
            ClientId::new(client_id),
            Some(ClientSecret::new(client_secret)),
            AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())?,
            Some(TokenUrl::new(
                "https://oauth2.googleapis.com/token".to_string(),
            )?),
        )
        .set_redirect_uri(RedirectUrl::new(redirect_uri)?);

        // Exchange code for tokens
        let token_response = client
            .exchange_code(AuthorizationCode::new(code))
            .request_async(async_http_client)
            .await
            .context("Failed to exchange authorization code for token")?;

        let access_token = token_response.access_token().secret().to_string();
        let refresh_token = token_response
            .refresh_token()
            .map(|t| t.secret().to_string());
        let expires_in = token_response.expires_in();
        let token_expires_at =
            expires_in.map(|d| Utc::now() + Duration::seconds(d.as_secs() as i64));

        // Get user's email address
        let user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo";
        let user_info: serde_json::Value = reqwest::Client::new()
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

    /// Insert or update a Gmail integration.
    ///
    /// When a `SecretsManager` is configured, tokens are also stored in the
    /// `_enc` columns (AES-256-GCM encrypted). The plaintext columns are kept
    /// for backwards compatibility until migration 02x drops them.
    ///
    /// When an `OAuthCredentialService` is configured, tokens are dual-written
    /// to the unified `integration_credentials` table backed by the secrets store.
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
        // Encrypt tokens. SecretsManager MUST be available.
        let sm = self
            .secrets_manager
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SecretsManager is required to encrypt Gmail tokens"))?;

        let (key_id, at_enc) = sm
            .encrypt_value(&access_token)
            .await
            .context("Failed to encrypt access_token")?;

        let rt_enc = if let Some(ref rt) = refresh_token {
            let (_, rt_bytes) = sm
                .encrypt_value(rt)
                .await
                .context("Failed to encrypt refresh_token")?;
            Some(rt_bytes)
        } else {
            None
        };

        let integration = sqlx::query_as::<_, GmailIntegration>(
            r#"
            INSERT INTO gmail_integrations (
                user_id, email_address, account_name,
                token_expires_at, scope,
                access_token_enc, refresh_token_enc, token_key_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (user_id, email_address)
            DO UPDATE SET
                account_name = EXCLUDED.account_name,
                
                token_expires_at = EXCLUDED.token_expires_at,
                scope = EXCLUDED.scope,
                is_active = TRUE,
                updated_at = NOW(),
                access_token_enc = EXCLUDED.access_token_enc,
                refresh_token_enc = EXCLUDED.refresh_token_enc,
                token_key_id = EXCLUDED.token_key_id
            RETURNING *
            "#,
        )
        .bind(user_id)
        .bind(&email_address)
        .bind(account_name)
        .bind(token_expires_at)
        .bind(&scope)
        .bind(&at_enc)
        .bind(&rt_enc)
        .bind(key_id)
        .fetch_one(&self.db_pool)
        .await
        .context("Failed to upsert Gmail integration")?;

        // Dual-write to unified credential service (best-effort)
        if let Some(cred_svc) = &self.credentials_service {
            if let Err(e) = cred_svc
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
            {
                tracing::warn!(
                    user_id = %user_id,
                    email = %email_address,
                    "Failed to dual-write Gmail credentials to credential service: {}",
                    e
                );
            }
        }

        Ok(integration)
    }

    /// Get all integrations for a user
    pub async fn get_user_integrations(&self, user_id: Uuid) -> Result<Vec<GmailIntegrationInfo>> {
        let integrations = sqlx::query_as::<_, GmailIntegrationInfo>(
            r#"
            SELECT id, email_address, account_name, scope, is_active, created_at, last_used_at
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
            SELECT id, email_address, account_name, scope, is_active, created_at, last_used_at
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
    /// Prefers the AES-256-GCM encrypted `access_token_enc` column (added by
    /// migration 020) over the legacy plaintext `access_token` column, decrypting
    /// via the `SecretsManager` when available.
    pub async fn get_integration_with_token(
        &self,
        integration_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<(GmailIntegration, String)>> {
        let mut integration = match self.get_integration(integration_id, user_id).await? {
            Some(i) => i,
            None => return Ok(None),
        };

        // Decrypt access token
        let mut access_token;
        if let (Some(sm), Some(enc), Some(key_id)) = (
            &self.secrets_manager,
            &integration.access_token_enc,
            integration.token_key_id,
        ) {
            match sm.decrypt_value_by_key(key_id, enc).await {
                Ok(decrypted) => {
                    access_token = decrypted;
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("Failed to decrypt access_token_enc: {}", e));
                }
            }
        } else {
            return Err(anyhow::anyhow!(
                "access_token_enc missing or SecretsManager not available"
            ));
        }

        // Check if token is expired or about to expire
        if let Some(expires_at) = integration.token_expires_at {
            if expires_at < Utc::now() + Duration::minutes(5) {
                // Token expired or expiring soon — refresh using decrypted refresh_token
                let refresh_token = if let (Some(sm), Some(enc), Some(key_id)) = (
                    &self.secrets_manager,
                    &integration.refresh_token_enc,
                    integration.token_key_id,
                ) {
                    match sm.decrypt_value_by_key(key_id, enc).await {
                        Ok(decrypted) => Some(decrypted),
                        Err(_) => None,
                    }
                } else {
                    None
                };

                if let Some(ref rt) = refresh_token {
                    match self.refresh_access_token(rt).await {
                        Ok((new_access_token, new_expires_at)) => {
                            access_token = new_access_token.clone();
                            integration = self
                                .update_access_token(
                                    integration.id,
                                    user_id,
                                    new_access_token,
                                    new_expires_at,
                                )
                                .await?;
                        }
                        Err(e) => {
                            tracing::error!("Failed to refresh Gmail access token: {}", e);
                        }
                    }
                }
            }
        }

        Ok(Some((integration, access_token)))
    }

    /// Refresh access token using refresh token
    async fn refresh_access_token(
        &self,
        refresh_token: &str,
    ) -> Result<(String, Option<DateTime<Utc>>)> {
        let client_id = self
            .client_id
            .clone()
            .ok_or_else(|| anyhow!("GMAIL_CLIENT_ID not set"))?;
        let client_secret = self
            .client_secret
            .clone()
            .ok_or_else(|| anyhow!("GMAIL_CLIENT_SECRET not set"))?;
        let client = BasicClient::new(
            ClientId::new(client_id),
            Some(ClientSecret::new(client_secret)),
            AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())?,
            Some(TokenUrl::new(
                "https://oauth2.googleapis.com/token".to_string(),
            )?),
        );

        let token_response = client
            .exchange_refresh_token(&RefreshToken::new(refresh_token.to_string()))
            .request_async(async_http_client)
            .await
            .context("Failed to refresh access token")?;

        let access_token = token_response.access_token().secret().to_string();
        let expires_in = token_response.expires_in();
        let expires_at = expires_in.map(|d| Utc::now() + Duration::seconds(d.as_secs() as i64));

        Ok((access_token, expires_at))
    }

    /// Update access token in database (called after a token refresh).
    ///
    /// `user_id` is included in the WHERE clause as a defense-in-depth guard: even
    /// though callers have already loaded the integration by `(id, user_id)`, including
    /// the owner here ensures that a programmer error (passing the wrong integration_id)
    /// cannot accidentally update another user's record.
    ///
    /// When `SecretsManager` is configured, also encrypts the new token and
    /// updates the `access_token_enc` / `token_key_id` columns so that the
    /// encrypted store stays in sync with the plaintext fallback.
    async fn update_access_token(
        &self,
        integration_id: Uuid,
        user_id: Uuid,
        access_token: String,
        token_expires_at: Option<DateTime<Utc>>,
    ) -> Result<GmailIntegration> {
        // Encrypt the refreshed token. SecretsManager must be available.
        let sm = self
            .secrets_manager
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SecretsManager is required to encrypt Gmail tokens"))?;

        let (key_id, at_enc) = sm
            .encrypt_value(&access_token)
            .await
            .context("Failed to encrypt refreshed access_token")?;

        // Write the new enc columns unconditionally.
        let integration = sqlx::query_as::<_, GmailIntegration>(
            r#"
            UPDATE gmail_integrations
            SET token_expires_at = $2,
                updated_at = NOW(),
                access_token_enc = $3,
                token_key_id = $4
            WHERE id = $1 AND user_id = $5
            RETURNING *
            "#,
        )
        .bind(integration_id)
        .bind(token_expires_at)
        .bind(at_enc)
        .bind(key_id)
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await?;

        Ok(integration)
    }

    /// Disconnect (deactivate) an integration.
    ///
    /// Returns an error if 0 rows were affected — this means the integration either
    /// doesn't exist or belongs to a different user (authorization check).
    pub async fn disconnect_integration(&self, integration_id: Uuid, user_id: Uuid) -> Result<()> {
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
        let result = sqlx::query(
            "INSERT INTO gmail_integration_audit_log (integration_id, user_id, event_type, success, error_message, metadata) VALUES ($1, $2, $3, $4, $5, $6)"
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
            tracing::error!("Failed to log Gmail integration event: {}", e);
        }
    }
}
