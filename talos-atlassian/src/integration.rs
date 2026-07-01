use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl,
    Scope, TokenUrl,
};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};
use std::sync::Arc;
use std::sync::LazyLock;

/// Shared reqwest client for Atlassian OAuth (token exchange +
/// refresh). Mirrors the per-crate shared-client pattern that
/// MCP-1110 / MCP-1111 landed for talos-memory + talos-search-service,
/// and the 2026-05-28 Perf#9 sweep extended to gmail + slack. Pre-fix
/// the refresh path built a fresh `reqwest::Client` per call — TLS
/// context init + connection pool reset per refresh, defeating
/// keep-alive against auth.atlassian.com. Now serves both token
/// exchange (callback path) and refresh.
///
/// Same hardening contract as the inline builder it replaces:
/// timeout(15s) + connect_timeout(5s) + redirect::Policy::none().
/// Build-failure fall-back panics via .expect() so a misconfigured
/// rustls/TLS stack surfaces loudly at startup rather than
/// indefinitely-retrying refresh tasks.
static REFRESH_HTTP_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .connect_timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Atlassian OAuth: failed to build hardened reqwest client")
});
use uuid::Uuid;

use talos_oauth::OAuthCredentialService;

// ── Types ────────────────────────────────────────────────────────────────

/// Atlassian integration record (DB row).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AtlassianIntegration {
    pub id: Uuid,
    pub user_id: Uuid,
    pub cloud_id: String,
    pub site_url: String,
    pub display_name: Option<String>,
    pub scope: Option<String>,
    pub account_id: Option<String>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Safe version for API responses (no tokens).
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AtlassianIntegrationInfo {
    pub id: Uuid,
    pub cloud_id: String,
    pub site_url: String,
    pub display_name: Option<String>,
    pub scope: Option<String>,
    pub account_id: Option<String>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

/// A single Atlassian Cloud site from the accessible-resources endpoint.
#[derive(Debug, Deserialize)]
pub struct AccessibleResource {
    pub id: String,
    pub url: String,
    pub name: String,
    pub scopes: Vec<String>,
}

// ── Service ──────────────────────────────────────────────────────────────

pub struct AtlassianIntegrationService {
    db_pool: Pool<Postgres>,
    client_id: Option<String>,
    client_secret: Option<String>,
    redirect_uri: Option<String>,
    credentials_service: Option<Arc<OAuthCredentialService>>,
}

impl AtlassianIntegrationService {
    pub fn new(db_pool: Pool<Postgres>) -> Result<Self> {
        Ok(Self {
            db_pool,
            // MCP-710 (2026-05-13): empty-env class — see GmailIntegrationService.
            client_id: std::env::var("ATLASSIAN_CLIENT_ID")
                .ok()
                .filter(|v| !v.is_empty()),
            client_secret: std::env::var("ATLASSIAN_CLIENT_SECRET")
                .ok()
                .filter(|v| !v.is_empty()),
            redirect_uri: std::env::var("ATLASSIAN_REDIRECT_URI")
                .ok()
                .filter(|v| !v.is_empty()),
            credentials_service: None,
        })
    }

    pub fn with_credentials_service(mut self, svc: Arc<OAuthCredentialService>) -> Self {
        self.credentials_service = Some(svc);
        self
    }

    pub fn is_configured(&self) -> bool {
        self.client_id.is_some() && self.client_secret.is_some() && self.redirect_uri.is_some()
    }

    // ── OAuth flow ───────────────────────────────────────────────────

    /// Generate Atlassian OAuth 2.0 (3LO) authorization URL with PKCE.
    /// Stores `user_id` in the state token so the callback can identify the
    /// user without requiring session auth (cross-site redirects from OAuth
    /// providers may not carry session cookies).
    pub async fn get_authorization_url(&self, user_id: Uuid) -> Result<(String, String)> {
        if !self.is_configured() {
            return Err(anyhow!(
                "Atlassian OAuth is not configured. Set ATLASSIAN_CLIENT_ID, \
                 ATLASSIAN_CLIENT_SECRET, and ATLASSIAN_REDIRECT_URI."
            ));
        }

        let client_id = self.client_id.clone().unwrap();
        let client_secret = self.client_secret.clone().unwrap();
        let redirect_uri = self.redirect_uri.clone().unwrap();

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let client = BasicClient::new(
            ClientId::new(client_id),
            Some(ClientSecret::new(client_secret)),
            AuthUrl::new("https://auth.atlassian.com/authorize".to_string())?,
            Some(TokenUrl::new(
                "https://auth.atlassian.com/oauth/token".to_string(),
            )?),
        )
        .set_redirect_uri(RedirectUrl::new(redirect_uri)?);

        let (auth_url, csrf_token) = client
            .authorize_url(CsrfToken::new_random)
            // Classic scopes
            .add_scope(Scope::new("read:jira-work".to_string()))
            .add_scope(Scope::new("write:jira-work".to_string()))
            .add_scope(Scope::new("read:jira-user".to_string()))
            .add_scope(Scope::new("offline_access".to_string()))
            // Granular scopes — read
            .add_scope(Scope::new("read:issue:jira".to_string()))
            .add_scope(Scope::new("read:issue-details:jira".to_string()))
            .add_scope(Scope::new("read:project:jira".to_string()))
            .add_scope(Scope::new("read:jql:jira".to_string()))
            .add_scope(Scope::new("read:user:jira".to_string()))
            // Granular scopes — write (comments, transitions)
            .add_scope(Scope::new("write:comment:jira".to_string()))
            .add_scope(Scope::new("write:issue:jira".to_string()))
            .add_extra_param("audience", "api.atlassian.com")
            .add_extra_param("prompt", "consent")
            .set_pkce_challenge(pkce_challenge)
            .url();

        let state_secret = csrf_token.secret().to_string();

        // Store state token + PKCE verifier + user_id for callback validation.
        sqlx::query(
            "INSERT INTO oauth_state_tokens (state_token, provider, pkce_verifier, user_id) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(&state_secret)
        .bind("atlassian")
        .bind(pkce_verifier.secret())
        .bind(user_id)
        .execute(&self.db_pool)
        .await
        .context("Failed to store Atlassian OAuth state token")?;

        Ok((auth_url.to_string(), state_secret))
    }

    /// Handle the OAuth callback: validate CSRF, exchange code, discover cloud sites,
    /// store integration + encrypted credentials.
    /// `user_id` is recovered from the state token (stored during `get_authorization_url`),
    /// so this handler does NOT require session authentication.
    pub async fn handle_callback(
        &self,
        code: String,
        state: String,
    ) -> Result<AtlassianIntegration> {
        // 0. Format-gate the state value before the DB lookup — same check the
        // login flow applies on store + validate (MCP-1171 symmetry). `$1`
        // binding already isolates injection; this closes the defense
        // asymmetry + the multi-KB-state DoS-amplification on consume.
        talos_oauth::validate_oauth_state_token_format(&state)?;
        // 1. Validate CSRF state token (single-use, atomic) and recover user_id.
        let state_row = sqlx::query_as::<_, (Uuid, Option<String>, Option<Uuid>)>(
            "UPDATE oauth_state_tokens \
             SET used = true \
             WHERE state_token = $1 AND provider = $2 AND used = false AND expires_at > NOW() \
             RETURNING id, pkce_verifier, user_id",
        )
        .bind(&state)
        .bind("atlassian")
        .fetch_optional(&self.db_pool)
        .await
        .context("Failed to validate Atlassian OAuth state token")?;

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
                "Failed to scrub pkce_verifier after Atlassian OAuth consume: {}",
                e
            );
        }

        let user_id = user_id_opt.ok_or_else(|| {
            anyhow!("State token missing user_id — cannot identify the initiating user")
        })?;

        // 2. Exchange authorization code for tokens.
        // Atlassian's token endpoint requires application/json (not form-urlencoded),
        // so we call it directly with reqwest instead of the oauth2 crate's built-in client.
        let client_id = self.client_id.clone().unwrap();
        let client_secret = self.client_secret.clone().unwrap();
        let redirect_uri = self.redirect_uri.clone().unwrap();

        // MCP-533: Mode-B credential-leak hardening. Token-exchange
        // POST carries `client_secret` + `code` + `code_verifier`.
        // Default redirect policy + `unwrap_or_else(|_| Client::new())`
        // would silently re-enable redirects on TLS-init failure,
        // forwarding the secret-bearing form body to redirect targets.
        // Perf#9: route through the shared REFRESH_HTTP_CLIENT — the
        // module-level static carries identical hardening.

        let mut token_body = serde_json::json!({
            "grant_type": "authorization_code",
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
        });

        if let Some(verifier) = pkce_verifier_secret {
            token_body["code_verifier"] = serde_json::Value::String(verifier);
        }

        let token_resp = REFRESH_HTTP_CLIENT
            .post("https://auth.atlassian.com/oauth/token")
            .json(&token_body)
            .send()
            .await
            .context("Failed to reach Atlassian token endpoint")?;

        if !token_resp.status().is_success() {
            let status = token_resp.status();
            let body = talos_http_body::read_error_text_capped(token_resp).await;
            // SECURITY: Log body length only — error bodies may echo client_secret or refresh_token.
            tracing::error!(
                status = %status,
                body_len = body.len(),
                "Atlassian token exchange failed"
            );
            return Err(anyhow!("Atlassian token exchange failed (HTTP {})", status));
        }

        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
            refresh_token: Option<String>,
            expires_in: Option<u64>,
            /// Space-separated list of scopes actually granted by the user.
            /// May be missing or a subset of requested scopes if the user
            /// declined some consent screens.
            #[serde(default)]
            scope: Option<String>,
        }

        let token_data: TokenResponse = talos_http_body::read_json_capped(token_resp)
            .await
            .context("Failed to parse Atlassian token response")?;

        let access_token = token_data.access_token;
        let refresh_token = token_data.refresh_token;
        // MCP-960..962 sibling + chrono panic defense: route through
        // the canonical helper so a misbehaving provider returning a
        // u64 expires_in > i64::MAX doesn't wrap to a negative i64
        // (immediate-expiry + refresh-storm) or trip
        // `chrono::Duration::seconds`' internal i64-ms overflow panic.
        let token_expires_at = talos_oauth::oauth_expires_at(token_data.expires_in);
        // Persist the granted scope string verbatim so operators can diagnose
        // "Unauthorized; scope does not match" errors by comparing what was
        // requested (in get_authorization_url) against what was granted. If
        // Atlassian omits the scope field, fall back to the full requested
        // set so the column is non-empty.
        let granted_scope = token_data.scope.unwrap_or_else(|| {
            "read:jira-work write:jira-work read:jira-user offline_access \
             read:issue:jira read:issue-details:jira read:project:jira \
             read:jql:jira read:user:jira write:comment:jira write:issue:jira"
                .to_string()
        });

        // 3. Discover accessible Atlassian Cloud sites.
        // MCP-533: this GET carries `Bearer access_token` — same
        // credential-leak hardening as the token-exchange POST above.
        // Perf#9: route through the shared REFRESH_HTTP_CLIENT.
        let resources_resp = REFRESH_HTTP_CLIENT
            .get("https://api.atlassian.com/oauth/token/accessible-resources")
            .bearer_auth(&access_token)
            .send()
            .await
            .context("Failed to fetch Atlassian accessible resources")?;

        let mut resources: Vec<AccessibleResource> =
            talos_http_body::read_json_capped(resources_resp)
                .await
                .context("Failed to parse Atlassian accessible resources")?;

        // Cap the number of entries to prevent excessive memory use from
        // unexpectedly large responses — we only need the first site.
        resources.truncate(100);

        let site = resources
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("No accessible Atlassian Cloud sites found for this account"))?;

        // Fetch the user's Jira account ID for JQL queries
        let account_id: Option<String> = {
            let myself_resp = REFRESH_HTTP_CLIENT
                .get(format!(
                    "https://api.atlassian.com/ex/jira/{}/rest/api/3/myself",
                    site.id
                ))
                .bearer_auth(&access_token)
                .send()
                .await;
            match myself_resp {
                Ok(resp) if resp.status().is_success() => {
                    talos_http_body::read_json_capped::<serde_json::Value>(resp)
                        .await
                        .ok()
                        .and_then(|v| {
                            v.get("accountId")
                                .and_then(|a| a.as_str())
                                .map(|s| s.to_string())
                        })
                }
                Ok(resp) => {
                    tracing::warn!(status = %resp.status(), "Could not fetch Jira /myself — account_id unavailable");
                    None
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to reach Jira /myself endpoint");
                    None
                }
            }
        };

        // 4. Store credentials via unified credential service (encrypted).
        if let Some(creds) = &self.credentials_service {
            creds
                .store_credentials(
                    user_id,
                    "atlassian",
                    &site.id,
                    &access_token,
                    refresh_token.as_deref(),
                    token_expires_at,
                    &granted_scope,
                    vec![],
                )
                .await
                .context("Failed to store Atlassian credentials")?;
        } else {
            return Err(anyhow!("Credential service not configured — cannot store OAuth tokens. Contact your platform administrator."));
        }

        // 5. Upsert integration record.
        let integration = sqlx::query_as::<_, AtlassianIntegration>(
            "INSERT INTO atlassian_integrations \
                 (user_id, cloud_id, site_url, display_name, scope, account_id) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (user_id, cloud_id) DO UPDATE \
             SET site_url = EXCLUDED.site_url, \
                 display_name = EXCLUDED.display_name, \
                 scope = EXCLUDED.scope, \
                 account_id = EXCLUDED.account_id, \
                 is_active = true, \
                 updated_at = now() \
             RETURNING *",
        )
        .bind(user_id)
        .bind(&site.id)
        .bind(&site.url)
        .bind(&site.name)
        .bind(&granted_scope)
        .bind(&account_id)
        .fetch_one(&self.db_pool)
        .await
        .context("Failed to upsert Atlassian integration")?;

        tracing::info!(
            user_id = %user_id,
            cloud_id = %site.id,
            site = %site.url,
            account_id_present = account_id.is_some(),
            "Atlassian integration connected"
        );

        Ok(integration)
    }

    // ── CRUD ─────────────────────────────────────────────────────────

    pub async fn get_user_integrations(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<AtlassianIntegrationInfo>> {
        let rows = sqlx::query_as::<_, AtlassianIntegrationInfo>(
            "SELECT id, cloud_id, site_url, display_name, scope, account_id, is_active, created_at, updated_at \
             FROM atlassian_integrations \
             WHERE user_id = $1 \
             ORDER BY created_at DESC",
        )
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await
        .context("Failed to list Atlassian integrations")?;

        Ok(rows)
    }

    pub async fn disconnect_integration(&self, integration_id: Uuid, user_id: Uuid) -> Result<()> {
        // Recover cloud_id (provider_key for vault paths) from the active row.
        // Atlassian doesn't expose a public revoke endpoint, but vault cleanup
        // is still important — refresh tokens stored locally would survive
        // disconnect otherwise and remain valid until Atlassian's own expiry.
        let cloud_id: Option<String> = sqlx::query_scalar(
            "SELECT cloud_id FROM atlassian_integrations \
             WHERE id = $1 AND user_id = $2 AND is_active = TRUE",
        )
        .bind(integration_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("Failed to look up Atlassian integration for disconnect")?;

        if let (Some(cid), Some(cred_svc)) = (cloud_id.as_deref(), &self.credentials_service) {
            if let Err(e) = cred_svc.revoke_and_cleanup(user_id, "atlassian", cid).await {
                tracing::warn!(
                    user_id = %user_id,
                    integration_id = %integration_id,
                    error = %e,
                    "Atlassian revoke_and_cleanup failed — proceeding with metadata flip"
                );
            }
        }

        let result = sqlx::query(
            "UPDATE atlassian_integrations SET is_active = false, updated_at = now() \
             WHERE id = $1 AND user_id = $2",
        )
        .bind(integration_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await
        .context("Failed to disconnect Atlassian integration")?;

        if result.rows_affected() == 0 {
            return Err(anyhow!("Integration not found or access denied"));
        }

        tracing::info!(
            user_id = %user_id,
            integration_id = %integration_id,
            "Atlassian integration disconnected"
        );

        Ok(())
    }

    // ── Token access (for WASM modules / workflows) ──────────────────

    /// Get a valid access token for a user's Atlassian integration.
    /// Refreshes automatically if expired (with per-credential locking).
    pub async fn get_access_token(&self, user_id: Uuid, cloud_id: &str) -> Result<String> {
        let creds = self
            .credentials_service
            .as_ref()
            .ok_or_else(|| anyhow!("Credential service not configured"))?;

        // Try to get a valid (non-expired) token first.
        match creds
            .get_valid_access_token(user_id, "atlassian", cloud_id)
            .await
        {
            Ok(token) => return Ok(token),
            Err(_) => {
                // Token expired or missing — attempt refresh.
            }
        }

        // Refresh: acquire per-credential lock to prevent concurrent refresh storms.
        let lock = creds.get_refresh_lock("atlassian", user_id, cloud_id);
        let _guard = lock.lock().await;

        // Re-check after lock (another task may have refreshed while we waited).
        if let Ok(token) = creds
            .get_valid_access_token(user_id, "atlassian", cloud_id)
            .await
        {
            return Ok(token);
        }

        // Read the refresh token from the vault using the same path convention.
        let refresh_token = creds
            .get_refresh_token(user_id, "atlassian", cloud_id)
            .await
            .context("Failed to read Atlassian refresh token from vault")?;

        let client_id = self
            .client_id
            .clone()
            .ok_or_else(|| anyhow!("ATLASSIAN_CLIENT_ID not set"))?;
        let client_secret = self
            .client_secret
            .clone()
            .ok_or_else(|| anyhow!("ATLASSIAN_CLIENT_SECRET not set"))?;

        // Atlassian token refresh via POST to auth.atlassian.com/oauth/token.
        // MCP-533: same Mode-B credential-leak hardening as the token-
        // exchange path above. Refresh body carries `client_secret` +
        // `refresh_token` — both must not ride a stray redirect.
        // MCP-1110/1111 sibling: route through the per-crate
        // `REFRESH_HTTP_CLIENT` so TLS context + connection pool stay
        // shared across all refreshes.
        let resp = REFRESH_HTTP_CLIENT
            .post("https://auth.atlassian.com/oauth/token")
            .json(&serde_json::json!({
                "grant_type": "refresh_token",
                "client_id": client_id,
                "client_secret": client_secret,
                "refresh_token": refresh_token,
            }))
            .send()
            .await
            .context("Atlassian token refresh request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = talos_http_body::read_error_text_capped(resp).await;
            // SECURITY: Log body server-side with length only — error bodies may echo
            // client_secret or refresh_token values.
            tracing::error!(
                status = %status,
                body_len = body.len(),
                "Atlassian token refresh failed"
            );
            return Err(anyhow!("Atlassian token refresh failed (HTTP {})", status));
        }

        #[derive(Deserialize)]
        struct RefreshResponse {
            access_token: String,
            refresh_token: Option<String>,
            expires_in: Option<u64>,
            /// MCP-468: per RFC 6749 §5.1 a refresh response MAY include
            /// `scope` reflecting the actual scope of the new access
            /// token. If present, use it (the user may have downgraded
            /// consent server-side); if absent, preserve the originally-
            /// granted scope from the DB instead of clobbering with a
            /// hardcoded subset.
            #[serde(default)]
            scope: Option<String>,
        }

        let token_resp: RefreshResponse = talos_http_body::read_json_capped(resp)
            .await
            .context("Failed to parse Atlassian refresh response")?;

        // MCP-960..962 sibling + chrono panic defense: see token-exchange
        // call site above.
        let new_expires_at = talos_oauth::oauth_expires_at(token_resp.expires_in);

        // MCP-468: prefer the refresh response's scope, fall back to the
        // existing DB value, only resort to the requested-superset list
        // when both are absent (defensive default — should not happen in
        // production because refresh only fires for existing credentials).
        let scope_for_store = if let Some(s) = token_resp.scope.as_deref() {
            s.to_string()
        } else {
            match creds
                .get_credential_scope(user_id, "atlassian", cloud_id)
                .await
            {
                Ok(Some(existing)) => existing,
                Ok(None) | Err(_) => {
                    // No DB row or read failure — fall back to the full
                    // originally-requested set so the column stays
                    // non-empty. Matches the handle_callback fallback.
                    "read:jira-work write:jira-work read:jira-user offline_access \
                     read:issue:jira read:issue-details:jira read:project:jira \
                     read:jql:jira read:user:jira write:comment:jira write:issue:jira"
                        .to_string()
                }
            }
        };

        // Store the new tokens (Atlassian uses rotating refresh tokens).
        creds
            .store_credentials(
                user_id,
                "atlassian",
                cloud_id,
                &token_resp.access_token,
                token_resp.refresh_token.as_deref(),
                new_expires_at,
                &scope_for_store,
                vec![],
            )
            .await
            .context("Failed to store refreshed Atlassian credentials")?;

        Ok(token_resp.access_token)
    }
}
