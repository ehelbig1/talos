pub mod credentials;
pub use credentials::OAuthCredentialService;

use anyhow::{anyhow, Context, Result};
// NOTE: We deliberately avoid the `openidconnect` crate to prevent pulling the
// vulnerable `rsa` dependency (RUSTSEC‑2023‑0071). All token verification is
// performed with constant‑time primitives from the `ring` crate via the custom
// `OAuthService` implementation.
use chrono::{DateTime, Utc};
use oauth2::reqwest::async_http_client;
use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl,
    Scope, TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};
use uuid::Uuid;

/// OAuth provider enum
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OAuthProvider {
    Google,
    Okta,
    Snyk,
}

impl OAuthProvider {
    pub fn as_str(&self) -> &str {
        match self {
            OAuthProvider::Google => "google",
            OAuthProvider::Okta => "okta",
            OAuthProvider::Snyk => "snyk",
        }
    }

    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "google" => Ok(OAuthProvider::Google),
            "okta" => Ok(OAuthProvider::Okta),
            "snyk" => Ok(OAuthProvider::Snyk),
            _ => Err(anyhow!("Unsupported OAuth provider: {}", s)),
        }
    }
}

/// OAuth account record
#[derive(Debug, Clone)]
pub struct OAuthAccount {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider: String,
    pub provider_user_id: String,
    pub email: String,
    pub name: Option<String>,
    pub picture_url: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub last_login_at: Option<DateTime<Utc>>,
}

/// User info from OAuth provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthUserInfo {
    pub provider_user_id: String,
    pub email: String,
    pub email_verified: bool,
    pub name: Option<String>,
    pub picture: Option<String>,
    // Optional tokens for service integrations (e.g., Google Calendar, Gmail)
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_in: Option<i64>,
    pub scope: Option<String>,
}

/// OAuth service for handling Google, Okta, and Snyk authentication
pub struct OAuthService {
    db_pool: Pool<Postgres>,
    google_client_id: Option<String>,
    google_client_secret: Option<String>,
    google_redirect_uri: Option<String>,
    okta_domain: Option<String>,
    okta_client_id: Option<String>,
    okta_client_secret: Option<String>,
    okta_redirect_uri: Option<String>,
    snyk_client_id: Option<String>,
    snyk_client_secret: Option<String>,
    snyk_redirect_uri: Option<String>,
    redis_client: Option<std::sync::Arc<redis::Client>>,
}

impl OAuthService {
    pub fn new(
        db_pool: Pool<Postgres>,
        redis_client: Option<std::sync::Arc<redis::Client>>,
    ) -> Result<Self> {
        Ok(Self {
            db_pool,
            google_client_id: std::env::var("GOOGLE_CLIENT_ID").ok(),
            google_client_secret: std::env::var("GOOGLE_CLIENT_SECRET").ok(),
            google_redirect_uri: std::env::var("GOOGLE_REDIRECT_URI").ok(),
            okta_domain: std::env::var("OKTA_DOMAIN").ok(),
            okta_client_id: std::env::var("OKTA_CLIENT_ID").ok(),
            okta_client_secret: std::env::var("OKTA_CLIENT_SECRET").ok(),
            okta_redirect_uri: std::env::var("OKTA_REDIRECT_URI").ok(),
            snyk_client_id: std::env::var("SNYK_CLIENT_ID").ok(),
            snyk_client_secret: std::env::var("SNYK_CLIENT_SECRET").ok(),
            snyk_redirect_uri: std::env::var("SNYK_REDIRECT_URI").ok(),
            redis_client,
        })
    }

    /// Check if a provider is configured
    pub fn is_provider_enabled(&self, provider: &OAuthProvider) -> bool {
        match provider {
            OAuthProvider::Google => {
                self.google_client_id.is_some()
                    && self.google_client_secret.is_some()
                    && self.google_redirect_uri.is_some()
            }
            OAuthProvider::Okta => {
                self.okta_domain.is_some()
                    && self.okta_client_id.is_some()
                    && self.okta_client_secret.is_some()
                    && self.okta_redirect_uri.is_some()
            }
            OAuthProvider::Snyk => {
                self.snyk_client_id.is_some()
                    && self.snyk_client_secret.is_some()
                    && self.snyk_redirect_uri.is_some()
            }
        }
    }

    /// Store a CSRF state token in the database.
    ///
    /// `provider` is a free-form string (e.g. "google", "gmail", "slack") stored in the
    /// `oauth_state_tokens.provider` column.  Using `&str` instead of `&OAuthProvider`
    /// allows integration-specific providers ("gmail") that are separate from the main
    /// authentication provider enum.
    pub async fn store_state_token(&self, state_token: &str, provider: &str) -> Result<()> {
        sqlx::query("INSERT INTO oauth_state_tokens (state_token, provider) VALUES ($1, $2)")
            .bind(state_token)
            .bind(provider)
            .execute(&self.db_pool)
            .await
            .context("Failed to store OAuth state token")?;

        Ok(())
    }

    /// Validate and consume a CSRF state token (atomic — sets `used = true`).
    ///
    /// `provider` must match the value used in `store_state_token`.  Returns an error
    /// if the token is unknown, already used, or expired (10-minute TTL).
    ///
    /// Defence-in-depth: in addition to the DB-level `used` flag, the nonce is also
    /// tracked in Redis (when available) with a 10-minute TTL to catch replay
    /// attempts that might slip through in multi-instance deployments with DB
    /// replication lag. If Redis is unavailable, the operation proceeds with a
    /// warning (graceful degradation).
    ///
    /// All OAuth flows must have a valid, unexpired, unconsumed state token in the
    /// database.  Previous code skipped validation for JSON-shaped state values
    /// (e.g. `{"source":"google-calendar"}`); that bypass has been removed because
    /// any caller could craft a `{…}` string to circumvent CSRF protection.
    pub async fn validate_state_token(&self, state_token: &str, provider: &str) -> Result<()> {
        // Check Redis nonce first (if available) for replay prevention
        let redis_nonce_key = format!("oauth_nonce:{}", state_token);
        if let Some(redis) = &self.redis_client {
            match redis.get_multiplexed_tokio_connection().await {
                Ok(mut con) => {
                    // Check if nonce was already consumed
                    let already_consumed: Option<String> = redis::cmd("GET")
                        .arg(&redis_nonce_key)
                        .query_async(&mut con)
                        .await
                        .unwrap_or(None);

                    if already_consumed.is_some() {
                        return Err(anyhow!(
                            "OAuth state token has already been consumed (replay detected)."
                        ));
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "Redis unavailable for OAuth nonce check — proceeding with DB-only validation"
                    );
                }
            }
        }

        // DB-level atomic consumption
        let result = sqlx::query(
            "UPDATE oauth_state_tokens
             SET used = true
             WHERE state_token = $1 AND provider = $2 AND used = false AND expires_at > NOW()
             RETURNING id",
        )
        .bind(state_token)
        .bind(provider)
        .fetch_optional(&self.db_pool)
        .await
        .context("Failed to validate OAuth state token")?;

        if result.is_none() {
            return Err(anyhow!(
                "Invalid or expired OAuth state token. This may indicate a CSRF attack."
            ));
        }

        // Mark nonce as consumed in Redis with 10-minute TTL
        if let Some(redis) = &self.redis_client {
            match redis.get_multiplexed_tokio_connection().await {
                Ok(mut con) => {
                    let _: Result<(), _> = redis::cmd("SET")
                        .arg(&redis_nonce_key)
                        .arg("consumed")
                        .arg("EX")
                        .arg(600) // 10 minutes TTL
                        .query_async(&mut con)
                        .await
                        .map_err(|e| {
                            tracing::warn!(
                                error = %e,
                                "Failed to mark OAuth nonce as consumed in Redis"
                            );
                        });
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "Redis unavailable for OAuth nonce marking — DB-level protection is still active"
                    );
                }
            }
        }

        Ok(())
    }

    /// Clean up expired OAuth state tokens
    /// This should be called periodically (e.g., hourly) to prevent database bloat
    /// and ensure that expired tokens cannot be replayed
    pub async fn cleanup_expired_state_tokens(&self) -> Result<u64> {
        let result = sqlx::query!("DELETE FROM oauth_state_tokens WHERE expires_at < NOW()")
            .execute(&self.db_pool)
            .await
            .context("Failed to cleanup expired OAuth state tokens")?;

        let deleted_count = result.rows_affected();
        if deleted_count > 0 {
            tracing::info!("Cleaned up {} expired OAuth state tokens", deleted_count);
        }

        Ok(deleted_count)
    }

    /// Generate OAuth authorization URL
    pub async fn get_authorization_url(
        &self,
        provider: OAuthProvider,
        extra_scopes: Option<Vec<String>>,
    ) -> Result<(String, String)> {
        if !self.is_provider_enabled(&provider) {
            return Err(anyhow!(
                "{} OAuth is not configured. Set environment variables.",
                provider.as_str()
            ));
        }

        let (auth_url, csrf_token) = match provider {
            OAuthProvider::Google => self.get_google_auth_url(extra_scopes).await,
            OAuthProvider::Okta => self.get_okta_auth_url().await,
            OAuthProvider::Snyk => self.get_snyk_auth_url().await,
        }?;

        // Store state token for CSRF validation
        self.store_state_token(&csrf_token, provider.as_str())
            .await?;

        Ok((auth_url, csrf_token))
    }

    /// Google OAuth authorization URL
    async fn get_google_auth_url(
        &self,
        extra_scopes: Option<Vec<String>>,
    ) -> Result<(String, String)> {
        // `client` is not used after creation; rename to `_client` to avoid dead_code warning.
        let _client = BasicClient::new(
            ClientId::new(
                self.google_client_id
                    .clone()
                    .ok_or_else(|| anyhow!("Google client ID not configured"))?,
            ),
            Some(ClientSecret::new(
                self.google_client_secret
                    .clone()
                    .ok_or_else(|| anyhow!("Google client secret not configured"))?,
            )),
            AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())?,
            Some(TokenUrl::new(
                "https://oauth2.googleapis.com/token".to_string(),
            )?),
        )
        // The redirect URI must match the one used in the auth request.
        .set_redirect_uri(RedirectUrl::new(
            self.google_redirect_uri
                .clone()
                .ok_or_else(|| anyhow!("Google redirect URI not configured"))?,
        )?);
        let mut req = _client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("profile".to_string()));

        if let Some(scopes) = extra_scopes {
            for scope in scopes {
                req = req.add_scope(Scope::new(scope));
            }
            req = req.add_extra_param("access_type", "offline");
            req = req.add_extra_param("prompt", "consent");
        }
        let (auth_url, csrf_token) = req.url();

        Ok((auth_url.to_string(), csrf_token.secret().to_string()))
    }

    /// Okta OIDC authorization URL
    async fn get_okta_auth_url(&self) -> Result<(String, String)> {
        // Build Okta URLs manually – Okta follows the standard OAuth2 endpoints.
        let domain = self
            .okta_domain
            .clone()
            .ok_or_else(|| anyhow!("Okta domain not configured"))?;
        let auth_endpoint = format!("https://{domain}/oauth2/v1/authorize");
        let token_endpoint = format!("https://{domain}/oauth2/v1/token");

        // The client is built for future token exchange but not needed for the current flow.
        // Prefix with underscore to silence the unused-variable warning.
        let _client = BasicClient::new(
            ClientId::new(
                self.okta_client_id
                    .clone()
                    .ok_or_else(|| anyhow!("Okta client ID not configured"))?,
            ),
            Some(ClientSecret::new(
                self.okta_client_secret
                    .clone()
                    .ok_or_else(|| anyhow!("Okta client secret not configured"))?,
            )),
            AuthUrl::new(auth_endpoint)?,
            Some(TokenUrl::new(token_endpoint)?),
        )
        .set_redirect_uri(RedirectUrl::new(
            self.okta_redirect_uri
                .clone()
                .ok_or_else(|| anyhow!("Okta redirect URI not configured"))?,
        )?);

        let (auth_url, csrf_token) = _client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .url();

        Ok((auth_url.to_string(), csrf_token.secret().to_string()))
    }

    /// Snyk OAuth authorization URL
    async fn get_snyk_auth_url(&self) -> Result<(String, String)> {
        // The OAuth client is constructed for completeness but not used directly in this flow.
        let _client = BasicClient::new(
            ClientId::new(
                self.snyk_client_id
                    .clone()
                    .ok_or_else(|| anyhow!("Snyk client ID not configured"))?,
            ),
            Some(ClientSecret::new(
                self.snyk_client_secret
                    .clone()
                    .ok_or_else(|| anyhow!("Snyk client secret not configured"))?,
            )),
            AuthUrl::new("https://app.snyk.io/oauth2/authorize".to_string())?,
            Some(TokenUrl::new(
                "https://api.snyk.io/oauth2/token".to_string(),
            )?),
        )
        .set_redirect_uri(RedirectUrl::new(
            self.snyk_redirect_uri
                .clone()
                .ok_or_else(|| anyhow!("Snyk redirect URI not configured"))?,
        )?);

        let (auth_url, csrf_token) = _client
            .authorize_url(CsrfToken::new_random)
            // Snyk scopes: offline.access for refresh tokens, plus API access scopes
            .add_scope(Scope::new("offline.access".to_string()))
            .add_scope(Scope::new("org.read".to_string()))
            .add_scope(Scope::new("org.project.read".to_string()))
            .add_scope(Scope::new("org.report.read".to_string()))
            .url();

        Ok((auth_url.to_string(), csrf_token.secret().to_string()))
    }

    /// Handle OAuth callback and get user info
    pub async fn handle_callback(
        &self,
        provider: OAuthProvider,
        code: String,
        state_token: Option<String>,
    ) -> Result<OAuthUserInfo> {
        // Validate CSRF state token
        if let Some(state) = state_token {
            self.validate_state_token(&state, provider.as_str()).await?;
        } else {
            return Err(anyhow!(
                "Missing OAuth state parameter. CSRF protection requires state token."
            ));
        }

        match provider {
            OAuthProvider::Google => self.handle_google_callback(code).await,
            OAuthProvider::Okta => self.handle_okta_callback(code).await,
            OAuthProvider::Snyk => self.handle_snyk_callback(code).await,
        }
    }

    /// Handle Google OAuth callback
    async fn handle_google_callback(&self, code: String) -> Result<OAuthUserInfo> {
        // Construct OAuth client; not used directly in this flow.
        let _client = BasicClient::new(
            ClientId::new(
                self.google_client_id
                    .clone()
                    .ok_or_else(|| anyhow!("Google client ID not configured"))?,
            ),
            Some(ClientSecret::new(
                self.google_client_secret
                    .clone()
                    .ok_or_else(|| anyhow!("Google client secret not configured"))?,
            )),
            AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())?,
            Some(TokenUrl::new(
                "https://oauth2.googleapis.com/token".to_string(),
            )?),
        )
        .set_redirect_uri(RedirectUrl::new(
            self.google_redirect_uri
                .clone()
                .ok_or_else(|| anyhow!("Google redirect URI not configured"))?,
        )?);

        // Exchange code for token – Google requires client credentials in the request body
        // rather than HTTP Basic auth, which the `oauth2` crate defaults to. To ensure
        // compatibility we perform a manual POST request mirroring the original implementation.
        let token_endpoint = "https://oauth2.googleapis.com/token";
        let params = [
            ("code", code.as_str()),
            (
                "client_id",
                self.google_client_id
                    .as_deref()
                    .ok_or_else(|| anyhow!("Google client ID not configured"))?,
            ),
            (
                "client_secret",
                self.google_client_secret
                    .as_deref()
                    .ok_or_else(|| anyhow!("Google client secret not configured"))?,
            ),
            (
                "redirect_uri",
                self.google_redirect_uri
                    .as_deref()
                    .ok_or_else(|| anyhow!("Google redirect URI not configured"))?,
            ),
            ("grant_type", "authorization_code"),
        ];
        let token_resp = reqwest::Client::new()
            .post(token_endpoint)
            .form(&params)
            .send()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to request token endpoint");
                anyhow!("Failed to exchange authorization code for token: {}", e)
            })?;
        let token_response = token_resp
            .json::<oauth2::basic::BasicTokenResponse>()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to parse token response");
                anyhow!("Failed to parse token response: {}", e)
            })?;

        // Get user info from Google
        let user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo";
        let user_info = reqwest::Client::new()
            .get(user_info_url)
            .bearer_auth(token_response.access_token().secret())
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        Ok(OAuthUserInfo {
            provider_user_id: user_info["id"]
                .as_str()
                .ok_or_else(|| anyhow!("Missing user ID"))?
                .to_string(),
            email: user_info["email"]
                .as_str()
                .ok_or_else(|| anyhow!("Missing email"))?
                .to_string(),
            email_verified: user_info["verified_email"]
                .as_bool()
                .ok_or_else(|| anyhow!("Missing verified_email field in Google user info"))?,
            name: user_info["name"].as_str().map(|s| s.to_string()),
            picture: user_info["picture"].as_str().map(|s| s.to_string()),
            // Include tokens for Google Calendar/Gmail integrations
            access_token: Some(token_response.access_token().secret().to_string()),
            refresh_token: token_response
                .refresh_token()
                .map(|t| t.secret().to_string()),
            expires_in: token_response.expires_in().map(|d| d.as_secs() as i64),
            // `scopes()` returns an Option<&[Scope]>. Annotate the slice type so Rust can infer
            // the closure parameter.
            // `scopes()` returns `Option<&Vec<Scope>>`; map over the Vec reference.
            scope: token_response.scopes().map(|scopes| {
                scopes
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(" ")
            }),
        })
    }

    /// Handle Okta OIDC callback
    async fn handle_okta_callback(&self, code: String) -> Result<OAuthUserInfo> {
        // Build Okta client (same as get_okta_auth_url)
        let domain = self
            .okta_domain
            .clone()
            .ok_or_else(|| anyhow!("Okta domain not configured"))?;
        let auth_endpoint = format!("https://{domain}/oauth2/v1/authorize");
        let token_endpoint = format!("https://{domain}/oauth2/v1/token");

        let client = BasicClient::new(
            ClientId::new(
                self.okta_client_id
                    .clone()
                    .ok_or_else(|| anyhow!("Okta client ID not configured"))?,
            ),
            Some(ClientSecret::new(
                self.okta_client_secret
                    .clone()
                    .ok_or_else(|| anyhow!("Okta client secret not configured"))?,
            )),
            AuthUrl::new(auth_endpoint)?,
            Some(TokenUrl::new(token_endpoint)?),
        )
        .set_redirect_uri(RedirectUrl::new(
            self.okta_redirect_uri
                .clone()
                .ok_or_else(|| anyhow!("Okta redirect URI not configured"))?,
        )?);

        // Exchange code for token
        let token_response = client
            .exchange_code(AuthorizationCode::new(code))
            .request_async(async_http_client)
            .await
            .context("Failed to exchange authorization code for token")?;

        // Retrieve userinfo via Okta's userinfo endpoint
        let userinfo_endpoint = format!("https://{domain}/oauth2/v1/userinfo");
        let user_info = reqwest::Client::new()
            .get(&userinfo_endpoint)
            .bearer_auth(token_response.access_token().secret())
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        Ok(OAuthUserInfo {
            provider_user_id: user_info["sub"]
                .as_str()
                .ok_or_else(|| anyhow!("Missing user ID"))?
                .to_string(),
            email: user_info["email"]
                .as_str()
                .ok_or_else(|| anyhow!("Missing email"))?
                .to_string(),
            email_verified: user_info["email_verified"]
                .as_bool()
                .ok_or_else(|| anyhow!("Missing email_verified field in Okta user info"))?,
            name: user_info["name"].as_str().map(|s| s.to_string()),
            picture: user_info["picture"].as_str().map(|s| s.to_string()),
            // Okta is for authentication only; token data is not persisted.
            access_token: None,
            refresh_token: None,
            expires_in: None,
            scope: None,
        })
    }

    /// Handle Snyk OAuth callback
    async fn handle_snyk_callback(&self, code: String) -> Result<OAuthUserInfo> {
        let client = BasicClient::new(
            ClientId::new(
                self.snyk_client_id
                    .clone()
                    .ok_or_else(|| anyhow!("Snyk client ID not configured"))?,
            ),
            Some(ClientSecret::new(
                self.snyk_client_secret
                    .clone()
                    .ok_or_else(|| anyhow!("Snyk client secret not configured"))?,
            )),
            AuthUrl::new("https://app.snyk.io/oauth2/authorize".to_string())?,
            Some(TokenUrl::new(
                "https://api.snyk.io/oauth2/token".to_string(),
            )?),
        )
        .set_redirect_uri(RedirectUrl::new(
            self.snyk_redirect_uri
                .clone()
                .ok_or_else(|| anyhow!("Snyk redirect URI not configured"))?,
        )?);

        // Exchange code for token
        let token_response = client
            .exchange_code(AuthorizationCode::new(code))
            .request_async(async_http_client)
            .await
            .context("Failed to exchange authorization code for Snyk token")?;

        // Get user info from Snyk API
        let user_info_url = "https://api.snyk.io/rest/self?version=2024-01-04";
        let user_info = reqwest::Client::new()
            .get(user_info_url)
            .bearer_auth(token_response.access_token().secret())
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        // Snyk API returns: { "data": { "id": "...", "attributes": { "email": "...", "name": "...", "username": "..." } } }
        let data = user_info["data"]
            .as_object()
            .ok_or_else(|| anyhow!("Invalid Snyk user info response"))?;
        let attrs = data["attributes"]
            .as_object()
            .ok_or_else(|| anyhow!("Missing attributes in Snyk response"))?;

        Ok(OAuthUserInfo {
            provider_user_id: data["id"]
                .as_str()
                .ok_or_else(|| anyhow!("Missing user ID in Snyk response"))?
                .to_string(),
            email: attrs["email"]
                .as_str()
                .ok_or_else(|| anyhow!("Missing email in Snyk response"))?
                .to_string(),
            email_verified: true, // Snyk doesn't provide this, assume verified
            name: attrs["name"].as_str().map(|s| s.to_string()),
            picture: None, // Snyk doesn't provide avatar URLs
            // Include tokens for Snyk API integrations
            access_token: Some(token_response.access_token().secret().to_string()),
            refresh_token: token_response
                .refresh_token()
                .map(|t| t.secret().to_string()),
            expires_in: token_response.expires_in().map(|d| d.as_secs() as i64),
            // Annotate slice type for `scopes()` as above.
            // Convert the list of scopes into a space‑separated string.
            scope: token_response.scopes().map(|scopes| {
                scopes
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(" ")
            }),
        })
    }

    /// Link OAuth account to existing user or create new user
    pub async fn link_or_create_user(
        &self,
        provider: OAuthProvider,
        user_info: OAuthUserInfo,
        existing_user_id: Option<Uuid>,
    ) -> Result<(Uuid, bool)> {
        // Require a verified email address before allowing account creation or linking.
        // Accepting unverified emails could allow an attacker to claim another user's
        // account by registering with that email at a permissive OAuth provider.
        if !user_info.email_verified {
            anyhow::bail!(
                "OAuth login rejected: email address '{}' is not verified by the provider. \
                 Please verify your email with {} before signing in.",
                user_info.email,
                provider.as_str()
            );
        }

        // Check if OAuth account already exists
        if let Some(existing) = self
            .get_oauth_account(&provider, &user_info.provider_user_id)
            .await?
        {
            // Update last login
            sqlx::query!(
                "UPDATE oauth_accounts SET last_login_at = NOW() WHERE id = $1",
                existing.id
            )
            .execute(&self.db_pool)
            .await?;

            return Ok((existing.user_id, false)); // existing user
        }

        // If linking to existing user (explicit intent — user is already authenticated)
        if let Some(user_id) = existing_user_id {
            self.link_oauth_account(user_id, provider, user_info)
                .await?;
            return Ok((user_id, false));
        }

        // Check if user exists by email
        let existing_user = sqlx::query!(
            "SELECT id FROM users WHERE email = $1 AND is_active = true",
            user_info.email
        )
        .fetch_optional(&self.db_pool)
        .await?;

        let is_new_user = existing_user.is_none();
        let user_id = if let Some(user) = existing_user {
            // Link to existing user
            self.link_oauth_account(user.id, provider.clone(), user_info)
                .await?;
            user.id
        } else {
            // Create new user.
            // SECURITY: OAuth accounts have no password. Store a bcrypt hash of a
            // fixed sentinel string so that password verification always fails for
            // these accounts (bcrypt::verify returns false, never true).
            // Using "" would work in practice but is ambiguous and error-prone.
            let sentinel_hash = bcrypt::hash("__talos_oauth_account_no_password__", 4)
                .map_err(|e| anyhow::anyhow!("Failed to create sentinel hash: {}", e))?;
            let new_user_id = sqlx::query_scalar!(
                "INSERT INTO users (email, password_hash, name, is_active)
                 VALUES ($1, $2, $3, true)
                 RETURNING id",
                user_info.email,
                sentinel_hash,
                user_info.name
            )
            .fetch_one(&self.db_pool)
            .await?;

            // Link OAuth account
            self.link_oauth_account(new_user_id, provider, user_info)
                .await?;

            new_user_id
        };

        Ok((user_id, is_new_user)) // return true if new user created
    }

    /// Link OAuth account to user
    async fn link_oauth_account(
        &self,
        user_id: Uuid,
        provider: OAuthProvider,
        user_info: OAuthUserInfo,
    ) -> Result<Uuid> {
        let account_id = sqlx::query_scalar!(
            r#"
            INSERT INTO oauth_accounts (
                user_id, provider, provider_user_id, email, name, picture_url, last_login_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, NOW())
            ON CONFLICT (user_id, provider)
            DO UPDATE SET
                provider_user_id = EXCLUDED.provider_user_id,
                email = EXCLUDED.email,
                name = EXCLUDED.name,
                picture_url = EXCLUDED.picture_url,
                last_login_at = NOW(),
                updated_at = NOW()
            RETURNING id
            "#,
            user_id,
            provider.as_str(),
            user_info.provider_user_id,
            user_info.email,
            user_info.name,
            user_info.picture
        )
        .fetch_one(&self.db_pool)
        .await
        .context("Failed to link OAuth account")?;

        Ok(account_id)
    }

    /// Get OAuth account by provider and provider user ID
    async fn get_oauth_account(
        &self,
        provider: &OAuthProvider,
        provider_user_id: &str,
    ) -> Result<Option<OAuthAccount>> {
        let account = sqlx::query_as!(
            OAuthAccount,
            r#"
            SELECT id, user_id, provider, provider_user_id, email, name, picture_url,
                   metadata, created_at, updated_at, last_login_at
            FROM oauth_accounts
            WHERE provider = $1 AND provider_user_id = $2
            "#,
            provider.as_str(),
            provider_user_id
        )
        .fetch_optional(&self.db_pool)
        .await?;

        Ok(account)
    }

    /// Get all OAuth accounts for a user
    pub async fn get_user_oauth_accounts(&self, user_id: Uuid) -> Result<Vec<OAuthAccount>> {
        let accounts = sqlx::query_as!(
            OAuthAccount,
            r#"
            SELECT id, user_id, provider, provider_user_id, email, name, picture_url,
                   metadata, created_at, updated_at, last_login_at
            FROM oauth_accounts
            WHERE user_id = $1
            "#,
            user_id
        )
        .fetch_all(&self.db_pool)
        .await?;

        Ok(accounts)
    }

    /// Unlink OAuth account
    pub async fn unlink_oauth_account(&self, user_id: Uuid, provider: OAuthProvider) -> Result<()> {
        let result = sqlx::query!(
            "DELETE FROM oauth_accounts WHERE user_id = $1 AND provider = $2",
            user_id,
            provider.as_str()
        )
        .execute(&self.db_pool)
        .await?;

        if result.rows_affected() == 0 {
            anyhow::bail!("OAuth account not found or access denied");
        }

        Ok(())
    }

    /// Log OAuth event
    pub async fn log_oauth_event(
        &self,
        user_id: Option<Uuid>,
        provider: &OAuthProvider,
        event_type: &str,
        success: bool,
        error_message: Option<&str>,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO oauth_audit_log (user_id, provider, event_type, success, error_message)
            VALUES ($1, $2, $3, $4, $5)
            "#,
            user_id,
            provider.as_str(),
            event_type,
            success,
            error_message
        )
        .execute(&self.db_pool)
        .await
        .ok(); // Don't fail if logging fails

        Ok(())
    }
}
