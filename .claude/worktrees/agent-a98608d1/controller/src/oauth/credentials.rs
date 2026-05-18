use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use sqlx::{Pool, Postgres};
use std::sync::Arc;
use uuid::Uuid;

use crate::secrets::SecretsManager;

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
            .get_secret(&at_path, crate::secrets::SecretRequestor::User(user_id))
            .await
            .context("Failed to retrieve access token from secrets")
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

    /// Soft-delete an integration credential (sets is_active = false).
    ///
    /// Verifies user ownership before updating (`rows_affected() == 0` means
    /// the row doesn't exist or belongs to a different user).
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

    /// Get (or create) the per-credential refresh mutex.
    ///
    /// Lock key: `"{provider}:{user_id}:{provider_key}"`
    ///
    /// Callers should hold this lock for the entire refresh-check-then-update
    /// sequence to prevent duplicate token refresh calls (double-spend).
    pub fn get_refresh_lock(
        &self,
        provider: &str,
        user_id: Uuid,
        provider_key: &str,
    ) -> Arc<tokio::sync::Mutex<()>> {
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
                Some(owner_user_id),
                allowed_modules,
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
                        .update_secret(key_path, value, Some(owner_user_id))
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
