#![allow(dead_code, unused_imports, unused_mut, unused_variables)]
use anyhow::{anyhow, Context, Result};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration as StdDuration, Instant};
use tokio::sync::Mutex;
// API key structs contain fields not currently accessed by the test suite.
use sqlx::{Pool, Postgres};
use uuid::Uuid;

/// API Key scopes for permission control
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiKeyScope {
    /// Read-only access to workflows
    WorkflowsRead,
    /// Full access to workflows
    WorkflowsWrite,
    /// Read-only access to secrets
    SecretsRead,
    /// Full access to secrets
    SecretsWrite,
    /// Access to webhooks
    WebhooksAccess,
    /// Full admin access
    Admin,
}

use std::fmt;

impl ApiKeyScope {
    pub fn from_string(s: &str) -> Option<Self> {
        match s {
            "workflows:read" => Some(ApiKeyScope::WorkflowsRead),
            "workflows:write" => Some(ApiKeyScope::WorkflowsWrite),
            "secrets:read" => Some(ApiKeyScope::SecretsRead),
            "secrets:write" => Some(ApiKeyScope::SecretsWrite),
            "webhooks:access" => Some(ApiKeyScope::WebhooksAccess),
            "admin" => Some(ApiKeyScope::Admin),
            _ => None,
        }
    }
}

impl fmt::Display for ApiKeyScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ApiKeyScope::WorkflowsRead => "workflows:read",
            ApiKeyScope::WorkflowsWrite => "workflows:write",
            ApiKeyScope::SecretsRead => "secrets:read",
            ApiKeyScope::SecretsWrite => "secrets:write",
            ApiKeyScope::WebhooksAccess => "webhooks:access",
            ApiKeyScope::Admin => "admin",
        };
        write!(f, "{}", s)
    }
}

/// API Key record
#[derive(Debug, Clone)]
pub struct ApiKey {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub key_prefix: String,
    pub scopes: Vec<ApiKeyScope>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub usage_count: i32,
}

/// API Key service
pub struct ApiKeyService {
    db_pool: Pool<Postgres>,
    // Simple in‑memory rate limiter: prefix -> (count, window_start)
    // Allows X requests per minute per key prefix.
    rate_limiter: Arc<Mutex<HashMap<String, (usize, Instant)>>>,
}

impl ApiKeyService {
    pub fn new(db_pool: Pool<Postgres>) -> Self {
        Self {
            db_pool,
            rate_limiter: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Generate a new API key
    /// Format: talos_<prefix>_<secret>
    /// Example: talos_sk_1a2b3c4d5e6f7g8h9i0j
    pub fn generate_key() -> (String, String) {
        let mut rng = rand::thread_rng();

        // Generate prefix (8 chars)
        let prefix_bytes: Vec<u8> = (0..4).map(|_| rng.gen()).collect();
        let prefix = hex::encode(prefix_bytes);

        // Generate secret (32 bytes = 64 hex chars)
        let secret_bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        let secret = hex::encode(secret_bytes);

        let full_key = format!("talos_sk_{}{}", prefix, secret);

        (full_key, prefix)
    }

    /// Create a new API key
    /// Returns (full_key, id, expires_at) - full key only shown once!
    pub async fn create_api_key(
        &self,
        user_id: Uuid,
        name: &str,
        scopes: Vec<ApiKeyScope>,
        expires_in_days: Option<i64>,
    ) -> Result<(String, Uuid, Option<DateTime<Utc>>)> {
        // Generate key
        let (full_key, prefix) = Self::generate_key();

        // Hash the full key for storage using a blocking task to avoid blocking the async runtime.
        let full_key_clone = full_key.clone();
        // Use a configurable bcrypt cost; default to DEFAULT_COST (12).
        let cost: u32 = std::env::var("API_KEY_BCRYPT_COST")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_COST);
        let key_hash = tokio::task::spawn_blocking(move || hash(&full_key_clone, cost))
            .await
            .context("Bcrypt hashing panicked")??;

        // Calculate expiration
        let expires_at = expires_in_days.map(|days| Utc::now() + Duration::days(days));

        // Convert scopes to strings
        let scope_strings: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();

        // Insert into database and return the ID and expires_at using RETURNING
        // This avoids the N+1 query problem of fetching all keys to find the new one
        let record = sqlx::query!(
            "INSERT INTO api_keys (user_id, name, key_hash, key_prefix, scopes, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING id, expires_at",
            user_id,
            name,
            key_hash,
            prefix,
            &scope_strings[..],
            expires_at
        )
        .fetch_one(&self.db_pool)
        .await
        .context("Failed to create API key")?;

        tracing::info!("Created API key '{}' for user {}", name, user_id);

        // Return the full key (only time it's returned!) along with metadata
        Ok((full_key, record.id, record.expires_at))
    }

    /// Validate an API key and return the user_id and scopes
    pub async fn validate_key(&self, api_key: &str) -> Result<(Uuid, Vec<ApiKeyScope>)> {
        // ---- Rate limiting ---------------------------------------------------
        // Simple token bucket: max 60 requests per minute per key prefix.
        const LIMIT: usize = 60;
        const WINDOW: StdDuration = StdDuration::from_secs(60);

        // Basic format validation first.
        if !api_key.starts_with("talos_sk_") {
            tracing::warn!("API key validation failed: malformed prefix");
            return Err(anyhow!("Invalid API key format"));
        }

        let key_without_prefix = api_key.strip_prefix("talos_sk_").ok_or_else(|| {
            tracing::warn!("API key validation failed: missing prefix");
            anyhow!("Malformed API key: missing prefix")
        })?;

        let prefix: String = key_without_prefix.chars().take(8).collect();
        if prefix.chars().count() < 8 {
            tracing::warn!("API key validation failed: short prefix");
            return Err(anyhow!("Invalid API key format"));
        }

        // Rate limit check/update.
        {
            let mut map = self.rate_limiter.lock().await;
            // Prevent unbounded memory growth from random prefixes
            if map.len() > 10000 {
                map.retain(|_, (_, start)| start.elapsed() <= WINDOW);
            }
            let entry = map.entry(prefix.clone()).or_insert((0, Instant::now()));
            let (ref mut count, ref mut start) = *entry;
            if start.elapsed() > WINDOW {
                *count = 0;
                *start = Instant::now();
            }
            if *count >= LIMIT {
                tracing::warn!("API key rate limit exceeded for prefix {}", prefix);
                return Err(anyhow!("Rate limit exceeded"));
            }
            *count += 1;
        }

        // Find keys with matching prefix
        let keys = sqlx::query!(
            "SELECT id, user_id, key_hash, scopes, expires_at, is_active
             FROM api_keys
             WHERE key_prefix = $1 AND is_active = true",
            prefix
        )
        .fetch_all(&self.db_pool)
        .await?;

        // Try to verify against each key with this prefix
        for key_record in keys {
            // Check expiration
            if let Some(expires_at) = key_record.expires_at {
                if expires_at < Utc::now() {
                    continue;
                }
            }

            // Verify hash (offloaded to blocking thread pool to avoid blocking async executor)
            let api_key_owned = api_key.to_string();
            let key_hash_clone = key_record.key_hash.clone();
            let hash_match = tokio::task::spawn_blocking(move || {
                verify(&api_key_owned, &key_hash_clone).unwrap_or(false)
            })
            .await
            .unwrap_or(false);
            if hash_match {
                // Update last used and verify it's still active (prevent TOCTOU)
                let update_result = sqlx::query(
                    "UPDATE api_keys
                     SET last_used_at = NOW(), usage_count = usage_count + 1
                     WHERE id = $1 AND is_active = true",
                )
                .bind(key_record.id)
                .execute(&self.db_pool)
                .await;

                if let Ok(res) = update_result {
                    if res.rows_affected() == 0 {
                        tracing::warn!("API key was deactivated during validation");
                        return Err(anyhow!("Invalid or expired API key"));
                    }
                } else {
                    tracing::warn!("Failed to update API key usage stats");
                    // Continue anyway to keep auth flow fast on DB blips
                }

                // Parse scopes
                let scopes: Vec<ApiKeyScope> = key_record
                    .scopes
                    .iter()
                    .filter_map(|s| ApiKeyScope::from_string(s))
                    .collect();

                return Ok((key_record.user_id, scopes));
            } else {
                tracing::warn!("API key hash mismatch for prefix {}", prefix);
            }
        }

        tracing::warn!("API key validation failed: no matching active key");
        Err(anyhow!("Invalid or expired API key"))
    }

    /// Get a specific API key
    pub async fn get_key(&self, key_id: Uuid, user_id: Uuid) -> Result<ApiKey> {
        let r = sqlx::query!(
            "SELECT id, user_id, name, key_prefix, scopes, created_at, expires_at,
                    last_used_at, is_active, usage_count
             FROM api_keys
             WHERE id = $1 AND user_id = $2",
            key_id,
            user_id
        )
        .fetch_optional(&self.db_pool)
        .await?
        .ok_or_else(|| anyhow::anyhow!("API key not found"))?;

        let scopes: Vec<ApiKeyScope> = r
            .scopes
            .into_iter()
            .filter_map(|s| ApiKeyScope::from_string(&s))
            .collect();

        Ok(ApiKey {
            id: r.id,
            user_id: r.user_id,
            name: r.name,
            key_prefix: r.key_prefix,
            scopes,
            created_at: r.created_at,
            expires_at: r.expires_at,
            last_used_at: r.last_used_at,
            is_active: r.is_active,
            usage_count: r.usage_count,
        })
    }

    /// List API keys for a user (returns metadata only, not actual keys)
    pub async fn list_keys(&self, user_id: Uuid) -> Result<Vec<ApiKey>> {
        let records = sqlx::query!(
            "SELECT id, user_id, name, key_prefix, scopes, created_at, expires_at,
                    last_used_at, is_active, usage_count
             FROM api_keys
             WHERE user_id = $1
             ORDER BY created_at DESC",
            user_id
        )
        .fetch_all(&self.db_pool)
        .await?;

        Ok(records
            .into_iter()
            .map(|r| ApiKey {
                id: r.id,
                user_id: r.user_id,
                name: r.name,
                key_prefix: r.key_prefix,
                scopes: r
                    .scopes
                    .iter()
                    .filter_map(|s| ApiKeyScope::from_string(s))
                    .collect(),
                created_at: r.created_at,
                expires_at: r.expires_at,
                last_used_at: r.last_used_at,
                is_active: r.is_active,
                usage_count: r.usage_count,
            })
            .collect())
    }

    /// List API keys for a user with pagination (returns metadata only, not actual keys)
    pub async fn list_keys_paginated(
        &self,
        user_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ApiKey>> {
        let records = sqlx::query!(
            "SELECT id, user_id, name, key_prefix, scopes, created_at, expires_at,
                    last_used_at, is_active, usage_count
             FROM api_keys
             WHERE user_id = $1
             ORDER BY created_at DESC
             LIMIT $2 OFFSET $3",
            user_id,
            limit,
            offset
        )
        .fetch_all(&self.db_pool)
        .await?;

        Ok(records
            .into_iter()
            .map(|r| ApiKey {
                id: r.id,
                user_id: r.user_id,
                name: r.name,
                key_prefix: r.key_prefix,
                scopes: r
                    .scopes
                    .iter()
                    .filter_map(|s| ApiKeyScope::from_string(s))
                    .collect(),
                created_at: r.created_at,
                expires_at: r.expires_at,
                last_used_at: r.last_used_at,
                is_active: r.is_active,
                usage_count: r.usage_count,
            })
            .collect())
    }

    /// Revoke an API key
    pub async fn revoke_key(&self, key_id: Uuid, user_id: Uuid) -> Result<()> {
        let result = sqlx::query!(
            "UPDATE api_keys
             SET is_active = false
             WHERE id = $1 AND user_id = $2",
            key_id,
            user_id
        )
        .execute(&self.db_pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(anyhow!("API key not found or not owned by user"));
        }

        tracing::info!("Revoked API key {} for user {}", key_id, user_id);
        Ok(())
    }

    /// Delete an API key permanently
    pub async fn delete_key(&self, key_id: Uuid, user_id: Uuid) -> Result<()> {
        let result = sqlx::query!(
            "DELETE FROM api_keys
             WHERE id = $1 AND user_id = $2",
            key_id,
            user_id
        )
        .execute(&self.db_pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(anyhow!("API key not found or not owned by user"));
        }

        tracing::info!("Deleted API key {} for user {}", key_id, user_id);
        Ok(())
    }

    /// Rotate an API key (creates new key, deactivates old one)
    pub async fn rotate_key(&self, key_id: Uuid, user_id: Uuid) -> Result<String> {
        // Get existing key details
        let old_key = sqlx::query!(
            "SELECT name, scopes, expires_at
             FROM api_keys
             WHERE id = $1 AND user_id = $2 AND is_active = true",
            key_id,
            user_id
        )
        .fetch_optional(&self.db_pool)
        .await?
        .ok_or_else(|| anyhow!("API key not found or already inactive"))?;

        // Parse scopes
        let scopes: Vec<ApiKeyScope> = old_key
            .scopes
            .iter()
            .filter_map(|s| ApiKeyScope::from_string(s))
            .collect();

        // Calculate days until expiration (if applicable)
        let expires_in_days = old_key.expires_at.map(|exp| {
            let duration = exp - Utc::now();
            duration.num_days()
        });

        // Create new key (returns tuple: key, id, expires_at)
        let (new_key, _new_id, _new_expires) = self
            .create_api_key(user_id, &old_key.name, scopes, expires_in_days)
            .await?;

        // Deactivate old key
        sqlx::query!(
            "UPDATE api_keys SET is_active = false WHERE id = $1",
            key_id
        )
        .execute(&self.db_pool)
        .await?;

        tracing::info!("Rotated API key {} for user {}", key_id, user_id);

        Ok(new_key)
    }

    /// Clean up expired API keys
    pub async fn cleanup_expired_keys(&self) -> Result<u64> {
        let result = sqlx::query!(
            "UPDATE api_keys
             SET is_active = false
             WHERE expires_at < NOW() AND is_active = true"
        )
        .execute(&self.db_pool)
        .await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key() {
        let (key1, prefix1) = ApiKeyService::generate_key();
        let (key2, prefix2) = ApiKeyService::generate_key();

        // Keys should be different
        assert_ne!(key1, key2);
        assert_ne!(prefix1, prefix2);

        // Keys should have correct format
        assert!(key1.starts_with("talos_sk_"));
        assert_eq!(prefix1.len(), 8);

        // Keys should be long enough (prefix + secret)
        assert!(key1.len() > 50);
    }

    #[test]
    fn test_scope_conversion() {
        let scope = ApiKeyScope::WorkflowsRead;
        let scope_str = scope.to_string();
        assert_eq!(scope_str, "workflows:read");

        let parsed = ApiKeyScope::from_string(&scope_str);
        assert_eq!(parsed, Some(ApiKeyScope::WorkflowsRead));
    }

    #[test]
    fn test_invalid_scope() {
        let parsed = ApiKeyScope::from_string("invalid:scope");
        assert_eq!(parsed, None);
    }
}
