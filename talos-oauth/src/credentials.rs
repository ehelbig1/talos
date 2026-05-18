use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use sqlx::{Pool, Postgres};
use std::sync::Arc;
use uuid::Uuid;

use talos_secrets_manager::SecretsManager;

/// Service for storing and retrieving OAuth credentials using the secrets manager.
///
/// Credentials are stored as encrypted secrets under structured key paths:
///   `oauth/{provider}/{user_id}/{provider_key}/access_token`
///   `oauth/{provider}/{user_id}/{provider_key}/refresh_token`
///
/// The `integration_credentials` table holds non-sensitive metadata (secret paths,
/// expiry, scope) for efficient lookups and refresh-decision queries.
///
/// Token refresh is serialized per-credential via `refresh_locks` (DashMap of
/// per-key `tokio::sync::Mutex<()>`), matching the pattern used in
/// `GoogleCalendarService::refresh_locks`.
pub struct OAuthCredentialService {
    db_pool: Pool<Postgres>,
    secrets_manager: Arc<SecretsManager>,
    /// Per-credential refresh locks: key = `"{provider}:{user_id}:{provider_key}"`
    refresh_locks: DashMap<String, Arc<tokio::sync::Mutex<()>>>,
}

/// Non-sensitive metadata for a stored OAuth integration credential.
#[derive(Debug, Clone)]
pub struct IntegrationCredential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider: String,
    pub provider_key: String,
    pub access_token_secret_path: Option<String>,
    pub refresh_token_secret_path: Option<String>,
    pub token_expires_at: Option<DateTime<Utc>>,
    pub scope: Option<String>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl OAuthCredentialService {
    pub fn new(db_pool: Pool<Postgres>, secrets_manager: Arc<SecretsManager>) -> Self {
        Self {
            db_pool,
            secrets_manager,
            refresh_locks: DashMap::new(),
        }
    }

    /// Returns a reference to the database connection pool.
    pub fn db_pool(&self) -> &Pool<Postgres> {
        &self.db_pool
    }

    // -------------------------------------------------------------------------
    // Key path helpers
    // -------------------------------------------------------------------------

    fn access_token_path(provider: &str, user_id: Uuid, provider_key: &str) -> String {
        format!(
            "oauth/{}/{}/{}/access_token",
            provider, user_id, provider_key
        )
    }

    fn refresh_token_path(provider: &str, user_id: Uuid, provider_key: &str) -> String {
        format!(
            "oauth/{}/{}/{}/refresh_token",
            provider, user_id, provider_key
        )
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /// Store (or update) OAuth credentials for a given integration.
    ///
    /// - Upserts the access and optional refresh tokens as encrypted secrets.
    /// - Inserts or updates the `integration_credentials` metadata record.
    ///
    /// `allowed_modules` limits which WASM modules can read the token via the
    /// secrets interface — set to the UUID(s) of linked modules (defence-in-depth).
    pub async fn store_credentials(
        &self,
        user_id: Uuid,
        provider: &str,
        provider_key: &str,
        access_token: &str,
        refresh_token: Option<&str>,
        expires_at: DateTime<Utc>,
        scope: &str,
        allowed_modules: Vec<Uuid>,
    ) -> Result<()> {
        let at_path = Self::access_token_path(provider, user_id, provider_key);
        let rt_path = Self::refresh_token_path(provider, user_id, provider_key);

        // Upsert access token secret
        self.upsert_secret(
            &format!("{} {} access token", provider, provider_key),
            &at_path,
            access_token,
            Some(&format!(
                "OAuth access token for {} {}",
                provider, provider_key
            )),
            user_id,
            allowed_modules.clone(),
        )
        .await
        .context("Failed to upsert access token secret")?;

        // Upsert refresh token secret (when provided)
        let has_refresh = if let Some(rt) = refresh_token {
            self.upsert_secret(
                &format!("{} {} refresh token", provider, provider_key),
                &rt_path,
                rt,
                Some(&format!(
                    "OAuth refresh token for {} {}",
                    provider, provider_key
                )),
                user_id,
                allowed_modules.clone(),
            )
            .await
            .context("Failed to upsert refresh token secret")?;
            true
        } else {
            false
        };

        let rt_path_ref: Option<&str> = if has_refresh { Some(&rt_path) } else { None };

        // Upsert integration_credentials metadata record
        sqlx::query(
            r#"
            INSERT INTO integration_credentials
                (user_id, provider, provider_key, access_token_secret_path,
                 refresh_token_secret_path, token_expires_at, scope, is_active)
            VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE)
            ON CONFLICT (user_id, provider, provider_key) DO UPDATE SET
                access_token_secret_path = EXCLUDED.access_token_secret_path,
                refresh_token_secret_path = COALESCE(
                    EXCLUDED.refresh_token_secret_path,
                    integration_credentials.refresh_token_secret_path
                ),
                token_expires_at = EXCLUDED.token_expires_at,
                scope = EXCLUDED.scope,
                is_active = TRUE,
                updated_at = NOW()
            "#,
        )
        .bind(user_id)
        .bind(provider)
        .bind(provider_key)
        .bind(&at_path)
        .bind(rt_path_ref)
        .bind(expires_at)
        .bind(scope)
        .execute(&self.db_pool)
        .await
        .context("Failed to upsert integration_credentials record")?;

        tracing::info!(
            user_id = %user_id,
            provider = %provider,
            provider_key = %provider_key,
            "Stored OAuth credentials"
        );

        Ok(())
    }

    /// Retrieve the access token for an integration credential.
    ///
    /// Returns the raw token string. Callers are responsible for token refresh
    /// when `token_expires_at` is near; use `get_refresh_lock` to serialize
    /// concurrent refreshes and `update_access_token` after a successful refresh.
    pub async fn get_valid_access_token(
        &self,
        user_id: Uuid,
        provider: &str,
        provider_key: &str,
    ) -> Result<String> {
        let at_path = Self::access_token_path(provider, user_id, provider_key);
        self.secrets_manager
            .get_secret(
                &at_path,
                talos_secrets_manager::SecretRequestor::User(user_id),
                &[],
            )
            .await
            .context("Failed to retrieve access token from secrets")
    }

    /// Retrieve the refresh token for an integration credential.
    pub async fn get_refresh_token(
        &self,
        user_id: Uuid,
        provider: &str,
        provider_key: &str,
    ) -> Result<String> {
        let rt_path = Self::refresh_token_path(provider, user_id, provider_key);
        self.secrets_manager
            .get_secret(
                &rt_path,
                talos_secrets_manager::SecretRequestor::User(user_id),
                &[],
            )
            .await
            .context("Failed to retrieve refresh token from secrets")
    }

    /// Update the stored access token after a successful OAuth refresh.
    ///
    /// Uses `upsert_secret` instead of `update_secret` so that legacy integrations
    /// created before the unified credential store (which never had `store_credentials`
    /// called for them) automatically get the secret row created on first refresh.
    pub async fn update_access_token(
        &self,
        user_id: Uuid,
        provider: &str,
        provider_key: &str,
        new_token: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<()> {
        let at_path = Self::access_token_path(provider, user_id, provider_key);

        self.upsert_secret(
            &format!("{} {} access token", provider, provider_key),
            &at_path,
            new_token,
            Some(&format!(
                "OAuth access token for {} {}",
                provider, provider_key
            )),
            user_id,
            vec![], // No per-module restriction on refresh writes
        )
        .await
        .context("Failed to update access token secret")?;

        let result = sqlx::query(
            "UPDATE integration_credentials
             SET token_expires_at = $1, updated_at = NOW()
             WHERE user_id = $2 AND provider = $3 AND provider_key = $4",
        )
        .bind(expires_at)
        .bind(user_id)
        .bind(provider)
        .bind(provider_key)
        .execute(&self.db_pool)
        .await
        .context("Failed to update integration_credentials expiry")?;

        if result.rows_affected() == 0 {
            tracing::debug!(
                user_id = %user_id,
                provider = %provider,
                provider_key = %provider_key,
                "update_access_token: no integration_credentials row (legacy integration predating migration 019)"
            );
        }

        Ok(())
    }

    /// MCP-468: read the `scope` column for a single existing credential row.
    /// Used by provider-specific refresh paths to preserve the originally-granted
    /// scope when the refresh response does not echo it back. Without this,
    /// `store_credentials` would overwrite the column with whatever the caller
    /// passed in — historically a hardcoded subset of the requested scopes,
    /// which mis-represented what the persisted access token can actually do.
    ///
    /// Returns `Ok(None)` when there is no matching active row (refresh on a
    /// disconnected integration is a no-op upstream anyway).
    pub async fn get_credential_scope(
        &self,
        user_id: Uuid,
        provider: &str,
        provider_key: &str,
    ) -> Result<Option<String>> {
        let scope: Option<Option<String>> = sqlx::query_scalar(
            "SELECT scope FROM integration_credentials \
             WHERE user_id = $1 AND provider = $2 AND provider_key = $3 AND is_active = TRUE",
        )
        .bind(user_id)
        .bind(provider)
        .bind(provider_key)
        .fetch_optional(&self.db_pool)
        .await
        .context("Failed to read integration_credentials.scope")?;
        // The outer Option is row presence; the inner Option is the nullable column.
        // Collapse to a single Option so callers don't have to nest matches.
        Ok(scope.flatten())
    }

    /// List active integration credentials for a user, optionally filtered by provider.
    pub async fn list_credentials(
        &self,
        user_id: Uuid,
        provider: Option<&str>,
    ) -> Result<Vec<IntegrationCredential>> {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            user_id: Uuid,
            provider: String,
            provider_key: String,
            access_token_secret_path: Option<String>,
            refresh_token_secret_path: Option<String>,
            token_expires_at: Option<DateTime<Utc>>,
            scope: Option<String>,
            is_active: bool,
            created_at: DateTime<Utc>,
            updated_at: DateTime<Utc>,
        }

        let rows = if let Some(p) = provider {
            sqlx::query_as::<_, Row>(
                "SELECT id, user_id, provider, provider_key, access_token_secret_path,
                        refresh_token_secret_path, token_expires_at, scope, is_active,
                        created_at, updated_at
                 FROM integration_credentials
                 WHERE user_id = $1 AND provider = $2 AND is_active = TRUE
                 ORDER BY created_at DESC",
            )
            .bind(user_id)
            .bind(p)
            .fetch_all(&self.db_pool)
            .await?
        } else {
            sqlx::query_as::<_, Row>(
                "SELECT id, user_id, provider, provider_key, access_token_secret_path,
                        refresh_token_secret_path, token_expires_at, scope, is_active,
                        created_at, updated_at
                 FROM integration_credentials
                 WHERE user_id = $1 AND is_active = TRUE
                 ORDER BY created_at DESC",
            )
            .bind(user_id)
            .fetch_all(&self.db_pool)
            .await?
        };

        Ok(rows
            .into_iter()
            .map(|r| IntegrationCredential {
                id: r.id,
                user_id: r.user_id,
                provider: r.provider,
                provider_key: r.provider_key,
                access_token_secret_path: r.access_token_secret_path,
                refresh_token_secret_path: r.refresh_token_secret_path,
                token_expires_at: r.token_expires_at,
                scope: r.scope,
                is_active: r.is_active,
                created_at: r.created_at,
                updated_at: r.updated_at,
            })
            .collect())
    }

    /// Soft-delete an integration credential row by id (sets is_active = false).
    ///
    /// Provider-specific code should prefer `revoke_and_cleanup`, which:
    /// (a) calls the provider's revoke endpoint best-effort, (b) deletes the
    /// access/refresh-token vault entries, and (c) soft-deletes the
    /// `integration_credentials` row keyed on `(provider, provider_key)`.
    /// This method is kept for completeness — verifies ownership via
    /// `rows_affected() == 0`.
    pub async fn disconnect(&self, user_id: Uuid, integration_id: Uuid) -> Result<()> {
        let result = sqlx::query(
            "UPDATE integration_credentials
             SET is_active = FALSE, updated_at = NOW()
             WHERE id = $1 AND user_id = $2",
        )
        .bind(integration_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;

        if result.rows_affected() == 0 {
            anyhow::bail!("Integration not found or access denied");
        }

        Ok(())
    }

    /// Full disconnect path for a provider integration: revoke at the provider,
    /// delete vault token entries, and soft-delete the `integration_credentials`
    /// row.
    ///
    /// Best-effort by design — every step is independently logged. A failed
    /// provider revoke does NOT prevent vault cleanup; a missing vault entry
    /// does NOT prevent the metadata flip. Caller still owns the
    /// provider-specific table soft-delete (e.g.
    /// `gmail_integrations.is_active = false`).
    ///
    /// `provider`/`provider_key` must match what was used in
    /// `store_credentials` (e.g. `("gmail", "alice@example.com")`,
    /// `("atlassian", "<cloud_id>")`).
    pub async fn revoke_and_cleanup(
        &self,
        user_id: Uuid,
        provider: &str,
        provider_key: &str,
    ) -> Result<()> {
        // Step 1: best-effort fetch of refresh + access tokens before deletion.
        // Refresh token revoke is preferred — for Google, revoking a refresh
        // token revokes every access token issued from that grant in one call.
        // Reading missing rows isn't a hard error; just means there's no token
        // left to revoke (already cleaned up, or never stored).
        let refresh_token = self
            .get_refresh_token(user_id, provider, provider_key)
            .await
            .ok();
        let access_token = self
            .try_get_access_token(user_id, provider, provider_key)
            .await;

        // Step 2: best-effort provider revoke. Prefer refresh_token (broader
        // revocation scope) but fall back to access_token. Failures are logged
        // — the local cleanup below proceeds regardless so a flaky provider
        // doesn't strand secrets in the vault.
        let token_for_revoke = refresh_token.as_deref().or(access_token.as_deref());
        if let Some(tok) = token_for_revoke {
            match super::revoke_at_provider(provider, tok).await {
                Ok(true) => tracing::info!(
                    target: "talos_oauth_revoke",
                    user_id = %user_id,
                    provider,
                    "OAuth token revoked at provider"
                ),
                Ok(false) => tracing::debug!(
                    target: "talos_oauth_revoke",
                    user_id = %user_id,
                    provider,
                    "Provider has no public revoke endpoint — skipping (vault cleanup proceeds)"
                ),
                Err(e) => tracing::warn!(
                    target: "talos_oauth_revoke",
                    user_id = %user_id,
                    provider,
                    error = %e,
                    "Provider revoke failed — proceeding with local cleanup"
                ),
            }
        } else {
            tracing::debug!(
                target: "talos_oauth_revoke",
                user_id = %user_id,
                provider,
                "No token in vault to revoke — proceeding with metadata cleanup"
            );
        }

        // Step 3: delete vault entries (access_token + refresh_token).
        // delete_secret bails on "not found"; tolerate that since revoke
        // already happened and we want the metadata flip to land regardless.
        let at_path = Self::access_token_path(provider, user_id, provider_key);
        let rt_path = Self::refresh_token_path(provider, user_id, provider_key);
        if let Err(e) = self
            .secrets_manager
            .delete_secret(&at_path, Some(user_id), &[])
            .await
        {
            tracing::debug!(
                target: "talos_oauth_revoke",
                user_id = %user_id,
                provider,
                error = %e,
                "delete access_token vault entry: not present or already removed"
            );
        }
        if let Err(e) = self
            .secrets_manager
            .delete_secret(&rt_path, Some(user_id), &[])
            .await
        {
            tracing::debug!(
                target: "talos_oauth_revoke",
                user_id = %user_id,
                provider,
                error = %e,
                "delete refresh_token vault entry: not present or already removed"
            );
        }

        // Step 4: soft-delete integration_credentials by (provider, provider_key).
        // Tolerate 0 rows — legacy integrations predating the unified table
        // don't have a row here; the provider-specific table soft-delete is
        // the authoritative gate.
        // allow-sqlx-swallow: `.map_err` below logs the cause at WARN
        // with `target: "talos_oauth_revoke"` before the `let _` discards
        // the Result. Operator visibility preserved via the logged error.
        let _ = sqlx::query(
            "UPDATE integration_credentials
             SET is_active = FALSE, updated_at = NOW()
             WHERE user_id = $1 AND provider = $2 AND provider_key = $3",
        )
        .bind(user_id)
        .bind(provider)
        .bind(provider_key)
        .execute(&self.db_pool)
        .await
        .map_err(|e| {
            tracing::warn!(
                target: "talos_oauth_revoke",
                user_id = %user_id,
                provider,
                error = %e,
                "integration_credentials soft-delete failed"
            );
            e
        });

        // Drop the per-credential refresh lock so a fresh reconnect doesn't
        // inherit the now-stale Mutex (it's cheap to recreate; failing to
        // remove it just keeps a dead Mutex parked in the DashMap until the
        // map's eviction threshold is hit).
        let lock_key = format!("{}:{}:{}", provider, user_id, provider_key);
        self.refresh_locks.remove(&lock_key);

        tracing::info!(
            user_id = %user_id,
            provider,
            "OAuth disconnect complete (revoke + vault cleanup)"
        );

        Ok(())
    }

    /// Internal helper: read access_token from vault without erroring if the
    /// row is missing (returns None instead).
    async fn try_get_access_token(
        &self,
        user_id: Uuid,
        provider: &str,
        provider_key: &str,
    ) -> Option<String> {
        self.get_valid_access_token(user_id, provider, provider_key)
            .await
            .ok()
    }

    /// Refresh every OAuth token in a batch of vault paths (best-effort).
    ///
    /// Filters the slice to paths starting with `"oauth/"` and calls
    /// `refresh_oauth_token_if_needed` on each. Errors are best-effort — if a
    /// refresh fails, the original token may still be valid, and the worker
    /// will surface any auth failure with a clear error. Refresh OUTCOMES are
    /// logged (success / skipped / failed) so that 401s downstream can be
    /// traced back to the refresh layer via `target: "talos_oauth_refresh"`
    /// log events.
    pub async fn refresh_oauth_tokens_in_batch(&self, vault_paths: &[String]) {
        // MCP-544: parallelize the refresh fan-out. Pre-fix this loop
        // ran serially — N tokens × ~200-500 ms each = up to several
        // seconds blocking every workflow dispatch with multiple OAuth
        // modules. Each call already holds a per-credential mutex via
        // `get_refresh_lock`, so distinct credentials parallelize safely;
        // the cap (8 concurrent) matches `TALOS_CHAIN_CONCURRENCY` so
        // we don't fire 100+ HTTP requests at the OAuth providers if a
        // pathological workflow references dozens of OAuth modules.
        const REFRESH_CONCURRENCY: usize = 8;
        use futures::stream::{self, StreamExt};
        stream::iter(vault_paths.iter().filter(|vp| vp.starts_with("oauth/")))
            .for_each_concurrent(REFRESH_CONCURRENCY, |vp| async move {
                match self.refresh_oauth_token_if_needed(vp).await {
                    Ok(true) => tracing::info!(
                        target: "talos_oauth_refresh",
                        vault_path = %vp,
                        outcome = "refreshed",
                        "OAuth token refreshed before dispatch"
                    ),
                    Ok(false) => tracing::debug!(
                        target: "talos_oauth_refresh",
                        vault_path = %vp,
                        outcome = "skipped",
                        "OAuth token still valid — no refresh needed"
                    ),
                    Err(e) => tracing::warn!(
                        target: "talos_oauth_refresh",
                        vault_path = %vp,
                        outcome = "failed",
                        error = %e,
                        "OAuth token refresh failed — worker may see 401. \
                         Check env vars (GOOGLE_CLIENT_ID/SECRET, ATLASSIAN_CLIENT_ID/SECRET), \
                         refresh_token validity, and integration_credentials.token_expires_at."
                    ),
                }
            })
            .await;
    }

    /// Given a vault:// path like `oauth/{provider}/{user_id}/{provider_key}/access_token`,
    /// check if the token is expiring soon and refresh it proactively.
    ///
    /// Returns `Ok(true)` if refreshed, `Ok(false)` if still valid, `Err` on failure.
    /// This is called by the engine's vault pre-fetch path before dispatching jobs.
    pub async fn refresh_oauth_token_if_needed(&self, vault_path: &str) -> Result<bool> {
        // Parse the vault path: oauth/{provider}/{user_id}/{provider_key}/access_token
        let parts: Vec<&str> = vault_path.split('/').collect();
        if parts.len() != 5 || parts[0] != "oauth" || parts[4] != "access_token" {
            return Ok(false); // Not an OAuth access token path
        }
        let provider = parts[1];
        let user_id: Uuid = parts[2]
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid user_id in vault path"))?;
        let provider_key = parts[3];

        // Threshold MUST match (or exceed) the lookahead window used by the
        // proactive refresh task (`oauth/refresh_task.rs`). If this threshold
        // is tighter than the task's query window, the task will find a token
        // expiring within its window but refuse to refresh it — creating a
        // dead zone where the token eventually expires and causes 401s during
        // workflow execution. Observed incident: gmail/follow-up-detector
        // 401 on 2026-04-11 while the refresh task logged "still valid".
        use super::REFRESH_THRESHOLD_MINUTES;
        let expiry: Option<DateTime<Utc>> = sqlx::query_scalar(
            "SELECT token_expires_at FROM integration_credentials \
             WHERE user_id = $1 AND provider = $2 AND provider_key = $3 AND is_active = TRUE",
        )
        .bind(user_id)
        .bind(provider)
        .bind(provider_key)
        .fetch_optional(&self.db_pool)
        .await?
        .flatten();

        // Decision: refresh when the token is (a) within the threshold of
        // expiring, or (b) has NO tracked expiry at all. The NULL case
        // previously `assumed valid` and skipped refresh — but that's exactly
        // the OAuth flow shape we hit after a fresh bootstrap where the
        // credentials row exists but nobody populated `token_expires_at`.
        // Attempting refresh is safe: if the stored access_token is still
        // valid, the provider returns the same token + a populated expiry,
        // which gets stored and makes future calls go down the (a) path.
        let needs_refresh = match expiry {
            Some(exp) => {
                exp - chrono::Utc::now() < chrono::Duration::minutes(REFRESH_THRESHOLD_MINUTES)
            }
            None => true, // No expiry tracked — optimistically refresh to populate it
        };

        if !needs_refresh {
            return Ok(false);
        }

        // Acquire per-credential lock to prevent concurrent refresh storms
        let lock = self.get_refresh_lock(provider, user_id, provider_key);
        let _guard = lock.lock().await;

        // Re-check after acquiring lock (another task may have refreshed)
        let expiry_recheck: Option<DateTime<Utc>> = sqlx::query_scalar(
            "SELECT token_expires_at FROM integration_credentials \
             WHERE user_id = $1 AND provider = $2 AND provider_key = $3 AND is_active = TRUE",
        )
        .bind(user_id)
        .bind(provider)
        .bind(provider_key)
        .fetch_optional(&self.db_pool)
        .await?
        .flatten();

        // Only short-circuit if the expiry was BOTH populated AND pushed
        // safely past the threshold by another task. A NULL expiry here
        // still warrants a refresh — matches the optimistic path above.
        if let Some(exp) = expiry_recheck {
            if exp - chrono::Utc::now() >= chrono::Duration::minutes(REFRESH_THRESHOLD_MINUTES) {
                return Ok(false); // Another task refreshed while we waited
            }
        }

        // Read refresh token from vault
        let refresh_token = self
            .get_refresh_token(user_id, provider, provider_key)
            .await?;

        // Look up provider's token endpoint and client credentials from env
        let (token_url, client_id, client_secret) = match provider {
            // MCP-710 (2026-05-13): empty-env class. `.filter(|v|
            // !v.is_empty())` so `GOOGLE_CLIENT_ID=""` (helm placeholder)
            // falls through to `GMAIL_CLIENT_ID` rather than shadowing
            // it with the empty string. Without this, the refresh
            // request to Google's token endpoint carries empty
            // client_id and Google returns 400 "invalid_client".
            "atlassian" => (
                "https://auth.atlassian.com/oauth/token",
                std::env::var("ATLASSIAN_CLIENT_ID").ok().filter(|v| !v.is_empty()),
                std::env::var("ATLASSIAN_CLIENT_SECRET").ok().filter(|v| !v.is_empty()),
            ),
            "gmail" | "google_calendar" => (
                "https://oauth2.googleapis.com/token",
                std::env::var("GOOGLE_CLIENT_ID")
                    .ok()
                    .filter(|v| !v.is_empty())
                    .or_else(|| std::env::var("GMAIL_CLIENT_ID").ok().filter(|v| !v.is_empty())),
                std::env::var("GOOGLE_CLIENT_SECRET")
                    .ok()
                    .filter(|v| !v.is_empty())
                    .or_else(|| std::env::var("GMAIL_CLIENT_SECRET").ok().filter(|v| !v.is_empty())),
            ),
            "slack" => {
                // Slack bot tokens don't expire. If the proactive refresh task
                // finds this token (because it has a far-future expiry in
                // integration_credentials), we skip it gracefully. User tokens
                // (which do expire) are not stored in the credential service yet.
                return Ok(false);
            }
            _ => {
                tracing::warn!(
                    provider,
                    "No token refresh endpoint configured for provider"
                );
                return Ok(false);
            }
        };

        let cid = client_id
            .ok_or_else(|| anyhow::anyhow!("Missing client_id env var for {} refresh", provider))?;
        let csec = client_secret.ok_or_else(|| {
            anyhow::anyhow!("Missing client_secret env var for {} refresh", provider)
        })?;

        // Call the token endpoint
        // MCP-533: refresh body carries `client_secret` +
        // `refresh_token` — Mode-B credential-leak surface. Disable
        // redirect-following and fail loudly on TLS init rather than
        // silently re-enabling default redirects via
        // `unwrap_or_else(|_| Client::new())`.
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .connect_timeout(std::time::Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("OAuth credentials refresh: failed to build hardened reqwest client");

        let resp = http
            .post(token_url)
            .json(&serde_json::json!({
                "grant_type": "refresh_token",
                "client_id": cid,
                "client_secret": csec,
                "refresh_token": refresh_token,
            }))
            .send()
            .await
            .context("Token refresh request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            // SECURITY: Log body length only — error bodies may echo client_secret or refresh_token.
            tracing::error!(provider, %status, body_len = body.len(), "OAuth token refresh failed");
            anyhow::bail!("Token refresh failed (HTTP {})", status);
        }

        #[derive(serde::Deserialize)]
        struct RefreshResponse {
            access_token: String,
            refresh_token: Option<String>,
            expires_in: Option<u64>,
            /// Granted scopes for the new access token. Providers may omit
            /// this and return the same scope set as the previous token.
            #[serde(default)]
            scope: Option<String>,
        }

        let token_data: RefreshResponse = resp
            .json()
            .await
            .context("Failed to parse refresh response")?;
        let new_expires = chrono::Utc::now()
            + chrono::Duration::seconds(token_data.expires_in.unwrap_or(3600) as i64);

        // Preserve the previously-persisted scope if the refresh response omits
        // it, otherwise overwrite with what the provider actually granted. This
        // gives operators an accurate audit trail when scope drift causes a
        // 401/403 mismatch (e.g. Jira "Unauthorized; scope does not match").
        let scope_to_persist: String = match token_data.scope.as_deref() {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => sqlx::query_scalar::<_, Option<String>>(
                "SELECT scope FROM integration_credentials \
                 WHERE user_id = $1 AND provider = $2 AND provider_key = $3 AND is_active = TRUE",
            )
            .bind(user_id)
            .bind(provider)
            .bind(provider_key)
            .fetch_optional(&self.db_pool)
            .await
            .ok()
            .flatten()
            .flatten()
            .unwrap_or_default(),
        };

        // Store the new tokens
        self.store_credentials(
            user_id,
            provider,
            provider_key,
            &token_data.access_token,
            token_data.refresh_token.as_deref(),
            new_expires,
            &scope_to_persist,
            vec![],
        )
        .await
        .context("Failed to store refreshed credentials")?;

        tracing::info!(
            provider,
            provider_key,
            expires_in = ?token_data.expires_in,
            "Auto-refreshed OAuth token before workflow execution"
        );

        Ok(true)
    }

    /// Get (or create) the per-credential refresh mutex.
    ///
    /// Lock key: `"{provider}:{user_id}:{provider_key}"`
    ///
    /// Callers should hold this lock for the entire refresh-check-then-update
    /// sequence to prevent duplicate token refresh calls (double-spend).
    ///
    /// The map is bounded: if it exceeds 1000 entries, all locks are cleared
    /// before inserting the new one. Locks are cheap to recreate — a cleared
    /// entry at worst causes one extra concurrent refresh attempt.
    pub fn get_refresh_lock(
        &self,
        provider: &str,
        user_id: Uuid,
        provider_key: &str,
    ) -> Arc<tokio::sync::Mutex<()>> {
        // MCP-914 (2026-05-14): prevent unbounded growth via Arc-refcount
        // eviction, NOT `clear()`. Pre-fix the over-threshold branch
        // called `self.refresh_locks.clear()` unconditionally — including
        // entries held by in-flight refresh tasks. That created a window
        // where:
        //   1. Task A holds `lock_a` (Arc clone) mid-refresh
        //   2. New `get_refresh_lock` call pushes count > MAX → `clear()`
        //   3. Task B (same account as A) reaches the entry-API path
        //      below, sees no entry, inserts a NEW Arc<Mutex<()>>
        //   4. Both A and B's refreshes now race — duplicate refresh
        //      tokens minted, OAuth provider's reuse-detection
        //      invalidates one (or both) leaving the credential broken
        //
        // Canonical fix shape: `retain(|_, lock| Arc::strong_count(lock) > 1)`
        // — keep entries with other holders, drop only the un-referenced
        // ones. Lifted verbatim from `talos_google_calendar::
        // GoogleCalendarService::cleanup_create_channel_locks` which
        // already uses the safe pattern.
        const MAX_REFRESH_LOCKS: usize = 1000;
        if self.refresh_locks.len() > MAX_REFRESH_LOCKS {
            let before = self.refresh_locks.len();
            self.refresh_locks
                .retain(|_, lock| Arc::strong_count(lock) > 1);
            tracing::debug!(
                before,
                after = self.refresh_locks.len(),
                "Evicted idle refresh_locks (strong_count == 1)"
            );
        }

        let key = format!("{}:{}:{}", provider, user_id, provider_key);
        self.refresh_locks
            .entry(key)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /// Upsert a secret by key_path: create if not present, update if already stored.
    ///
    /// Uses optimistic create-then-update to avoid a TOCTOU race condition:
    /// a SELECT EXISTS followed by INSERT can fail under concurrent requests for
    /// the same key_path. Instead we attempt the create and fall back to update
    /// if a duplicate-key error is returned.
    async fn upsert_secret(
        &self,
        name: &str,
        key_path: &str,
        value: &str,
        description: Option<&str>,
        owner_user_id: Uuid,
        allowed_modules: Vec<Uuid>,
    ) -> Result<()> {
        match self
            .secrets_manager
            .create_secret(
                name,
                key_path,
                value,
                description,
                owner_user_id,
                allowed_modules,
                None, // OAuth credentials are user-owned, not org-scoped
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(create_err) => {
                // If the key already exists (UNIQUE_VIOLATION, SQLState 23505), update it.
                // Check the error chain for a sqlx::Error::Database with the right code
                // rather than doing fragile string matching on the error message.
                if is_pg_unique_violation(&create_err) {
                    self.secrets_manager
                        .update_secret(key_path, value, Some(owner_user_id), &[])
                        .await
                } else {
                    Err(create_err)
                }
            }
        }
    }
}

/// Returns true if `err` was caused by a PostgreSQL UNIQUE_VIOLATION (SQLState 23505).
fn is_pg_unique_violation(err: &anyhow::Error) -> bool {
    err.chain()
        .find_map(|cause| {
            cause.downcast_ref::<sqlx::Error>().and_then(|e| match e {
                sqlx::Error::Database(db_err) => Some(db_err.as_ref()),
                _ => None,
            })
        })
        .map(|db_err| db_err.code().as_deref() == Some("23505"))
        .unwrap_or(false)
}

#[cfg(test)]
#[path = "credentials_tests.rs"]
mod tests;
