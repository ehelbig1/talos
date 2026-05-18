use anyhow::{anyhow, Context, Result};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{DateTime, Duration, Utc};
use sqlx::{Pool, Postgres};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration as StdDuration, Instant};
use tokio::sync::Mutex;
use uuid::Uuid;

/// API Key scopes for permission control.
///
/// Pure-data enum lives in `talos-auth-types`. The `ApiKeyScope::from_string`
/// associated function returns `None` for unknown scopes silently;
/// callers that want operator-visible warnings on stored-but-unknown
/// scopes should route parses through [`parse_api_key_scope_logged`].
pub use talos_auth_types::ApiKeyScope;

/// Wrapper around [`ApiKeyScope::from_string`] that emits a
/// `tracing::warn!` for unknown scope strings. Use this when the input
/// originates from persisted data (DB row, header) and a non-mapping
/// value indicates either dead data or a vocabulary drift worth
/// investigating.
pub fn parse_api_key_scope_logged(s: &str) -> Option<ApiKeyScope> {
    match ApiKeyScope::from_string(s) {
        Some(scope) => Some(scope),
        None => {
            // MCP-847 (2026-05-14): render the valid-scopes list from
            // the canonical `ApiKeyScope::ALL` so adding a new variant
            // propagates here without a manual edit.
            tracing::warn!(
                scope = s,
                valid_scopes = %ApiKeyScope::scopes_csv(),
                "Unknown API key scope encountered — ignoring."
            );
            None
        }
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
    /// Optional Redis client for distributed rate limiting.
    /// When available, rate limits are enforced cluster-wide.
    redis_client: Option<Arc<redis::Client>>,
}

impl ApiKeyService {
    pub fn new(db_pool: Pool<Postgres>, redis_client: Option<Arc<redis::Client>>) -> Self {
        if redis_client.is_none() {
            tracing::warn!("API key rate limiter is currently in-memory. For a distributed deployment, this should be backed by Redis.");
        }
        Self {
            db_pool,
            rate_limiter: Arc::new(Mutex::new(HashMap::new())),
            redis_client,
        }
    }

    /// Generate a new API key
    /// Format: talos_<prefix>_<secret>
    /// Example: talos_sk_1a2b3c4d5e6f7g8h9i0j
    pub fn generate_key() -> (String, String) {
        use rand::RngCore;
        let mut rng = rand::rngs::OsRng;

        // Generate prefix (4 bytes = 8 hex chars)
        let mut prefix_bytes = [0u8; 4];
        rng.fill_bytes(&mut prefix_bytes);
        let prefix = hex::encode(prefix_bytes);

        // Generate secret (32 bytes = 64 hex chars)
        let mut secret_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_bytes);
        let secret = hex::encode(secret_bytes);

        let full_key = format!("talos_sk_{}{}", prefix, secret);

        (full_key, prefix)
    }

    /// Maximum number of active API keys a single user may hold at one time.
    /// Prevents database bloat and limits blast radius of a compromised account.
    pub const MAX_API_KEYS_PER_USER: i64 = 100;

    /// Minimum bcrypt cost the service is willing to use for API-key
    /// hashes. OWASP's 2024 password-storage guidance and bcrypt's own
    /// post-2016 default both put the floor at 10. Costs below this
    /// produce hashes that an attacker with rented GPU time can crack
    /// far faster than the per-account rate-limit fights.
    ///
    /// MCP-494: the `API_KEY_BCRYPT_COST` env var previously accepted
    /// any value that parsed as u32 — a misconfiguration of `=4` (or
    /// even `=0`) would silently weaken every key created or rotated
    /// from that point onward. In production we now FAIL-CLOSED on
    /// values below the floor; outside production we clamp UP and emit
    /// a WARN. `bcrypt::DEFAULT_COST` (12) remains the no-config
    /// default.
    pub const MIN_BCRYPT_COST: u32 = 10;
    /// MCP-1082 (2026-05-16): bcrypt's hard upper bound. The `bcrypt`
    /// crate refuses costs > 31 with `BcryptError::CostNotAllowed`.
    /// Without an explicit check here, an operator setting
    /// `API_KEY_BCRYPT_COST=32` would parse cleanly, pass the
    /// `>= MIN_BCRYPT_COST` guard, then fail every `create_api_key` /
    /// `regenerate_api_key` call with an opaque "failed to create API
    /// key" error and no boot-time signal. Same fail-closed-early
    /// class as MCP-1077 (controller AuthService bcrypt cost).
    pub const MAX_BCRYPT_COST: u32 = 31;

    /// Resolve the effective bcrypt cost from env, enforcing the
    /// production floor. See [`MIN_BCRYPT_COST`].
    fn resolve_bcrypt_cost() -> Result<u32> {
        let raw = std::env::var("API_KEY_BCRYPT_COST")
            .ok()
            .and_then(|v| v.parse::<u32>().ok());
        match raw {
            None => Ok(DEFAULT_COST),
            // MCP-1082: reject costs above bcrypt's hard ceiling (31)
            // regardless of environment. Pre-fix this branch was
            // skipped and the bcrypt::hash call downstream paid the
            // opaque-error cost.
            Some(cost) if cost > Self::MAX_BCRYPT_COST => {
                tracing::error!(
                    operator_cost = cost,
                    max_allowed = Self::MAX_BCRYPT_COST,
                    "API_KEY_BCRYPT_COST exceeds bcrypt's hard maximum — refusing to issue (every bcrypt::hash would fail)"
                );
                anyhow::bail!(
                    "API_KEY_BCRYPT_COST={} exceeds bcrypt's hard maximum ({}); refusing to issue API key",
                    cost,
                    Self::MAX_BCRYPT_COST
                )
            }
            Some(cost) if cost >= Self::MIN_BCRYPT_COST => Ok(cost),
            Some(cost) if talos_config::is_production() => {
                tracing::error!(
                    operator_cost = cost,
                    min_allowed = Self::MIN_BCRYPT_COST,
                    "API_KEY_BCRYPT_COST set below production floor — refusing to hash with insecure cost"
                );
                anyhow::bail!(
                    "API_KEY_BCRYPT_COST={} is below the production minimum ({}); refusing to issue weakly-hashed API key",
                    cost,
                    Self::MIN_BCRYPT_COST
                )
            }
            Some(cost) => {
                tracing::warn!(
                    operator_cost = cost,
                    min_allowed = Self::MIN_BCRYPT_COST,
                    "API_KEY_BCRYPT_COST below recommended floor; clamping up. Set ≥{} in production.",
                    Self::MIN_BCRYPT_COST
                );
                Ok(Self::MIN_BCRYPT_COST)
            }
        }
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
        // Generate key + hash UP FRONT. Bcrypt is the slow part of this
        // function; doing it BEFORE the transaction means a transient
        // user holds the per-user advisory lock for milliseconds, not
        // hundreds of milliseconds. The hash is a pure function of the
        // generated key bytes; if the cap check fails we simply
        // discard it — no DB rows were touched.
        let (full_key, prefix) = Self::generate_key();
        let full_key_clone = full_key.clone();
        let cost = Self::resolve_bcrypt_cost()?;
        let key_hash = tokio::task::spawn_blocking(move || hash(&full_key_clone, cost))
            .await
            .context("Bcrypt hashing panicked")??;

        let expires_at = expires_in_days.map(|days| Utc::now() + Duration::days(days));
        let scope_strings: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();

        // MCP-685 (2026-05-13): wrap the cap check + insert in a
        // transaction with a per-user advisory lock. Pre-fix the cap
        // was a TOCTOU: two concurrent `create_api_key` calls for the
        // same user each ran the COUNT independently (both saw e.g.
        // 99), both passed the gate, both INSERTed — leaving the user
        // with N+1 active keys. The advisory lock serialises concurrent
        // creates per user, and the COUNT runs inside the same
        // transaction as the INSERT so a slow checker can't be
        // overtaken by a fast committer. Lock numbers are
        // `hashtextextended(user_id::text, fixed_salt)` so the
        // collision domain is per-user, not global. Released
        // automatically on commit/rollback (pg_advisory_xact_lock).
        let mut tx = self
            .db_pool
            .begin()
            .await
            .context("Failed to begin api-key create transaction")?;

        // Advisory lock keyed on the user_id. The fixed salt prevents
        // accidental collision with any other code that locks on user
        // ids (each lock-using subsystem picks its own salt).
        // 42939989229 ≈ ascii bytes "API-KCAP" — picked once, fixed
        // forever; changing it would let an in-flight create from a
        // pre-bump replica race a post-bump one. PostgreSQL doesn't
        // accept 0x-style hex in plain SQL, hence the decimal literal.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 42939989229))")
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .context("Failed to acquire per-user advisory lock")?;

        let active_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM api_keys WHERE user_id = $1 AND is_active = true",
        )
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await
        .context("Failed to count active API keys")?;

        if active_count >= Self::MAX_API_KEYS_PER_USER {
            anyhow::bail!(
                "API key limit reached: users may hold at most {} active keys. \
                 Revoke unused keys before creating new ones.",
                Self::MAX_API_KEYS_PER_USER
            );
        }

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
        .fetch_one(&mut *tx)
        .await
        .context("Failed to create API key")?;

        tx.commit()
            .await
            .context("Failed to commit api-key create transaction")?;

        tracing::info!("Created API key '{}' for user {}", name, user_id);
        Self::log_key_event(
            self.db_pool.clone(),
            user_id,
            "api_key_created",
            record.id,
            format!("API key '{}' created", name),
            serde_json::json!({ "name": name, "scopes": scope_strings }),
        );

        // Return the full key (only time it's returned!) along with metadata
        Ok((full_key, record.id, record.expires_at))
    }

    /// Validate an API key and return the user_id and scopes
    pub async fn validate_key(&self, api_key: &str) -> Result<(Uuid, Vec<ApiKeyScope>)> {
        // ---- Rate limiting ---------------------------------------------------
        // Simple token bucket: max 60 requests per minute per key prefix.
        const LIMIT: usize = 60;
        const WINDOW: StdDuration = StdDuration::from_secs(60);

        // Constant-time format check against the known key prefix to prevent
        // timing-based enumeration of valid vs. invalid key formats.
        use subtle::ConstantTimeEq;
        const KEY_PREFIX: &[u8] = b"talos_sk_";
        let key_bytes = api_key.as_bytes();
        let prefix_ok = key_bytes.len() >= KEY_PREFIX.len()
            && key_bytes[..KEY_PREFIX.len()].ct_eq(KEY_PREFIX).unwrap_u8() == 1;
        if !prefix_ok {
            tracing::warn!("API key validation failed: malformed prefix");
            return Err(anyhow!("Invalid API key format"));
        }

        let key_without_prefix = &api_key[KEY_PREFIX.len()..];

        let prefix: String = key_without_prefix.chars().take(8).collect();
        if prefix.chars().count() < 8 {
            tracing::warn!("API key validation failed: short prefix");
            return Err(anyhow!("Invalid API key format"));
        }

        // Rate limit check/update with Redis fallback.
        // First try distributed rate limiting via Redis.
        if let Some(redis) = &self.redis_client {
            match self.check_rate_limit_redis(prefix.clone(), redis).await {
                Ok(true) => {
                    tracing::warn!("API key rate limit exceeded for prefix {}", prefix);
                    return Err(anyhow!("Rate limit exceeded"));
                }
                Ok(false) => {} // Rate limit OK, continue
                Err(e) => {
                    tracing::warn!(
                        "Redis rate limit check failed, falling back to in-memory: {}",
                        e
                    );
                    // Fall through to in-memory check
                }
            }
        }

        // Fall back to in-memory rate limiting.
        {
            let mut map = self.rate_limiter.lock().await;

            // Prevent unbounded memory growth: cleanup BEFORE insertion
            // This ensures we don't grow beyond 10k entries even briefly
            if map.len() >= 10000 {
                // Retain only entries within the time window
                let now = Instant::now();
                map.retain(|_, (_, start)| now.duration_since(*start) <= WINDOW);

                // L-18: if still at capacity after cleanup, evict the
                // OLDEST entry rather than rejecting NEW prefixes.
                // Pre-fix, a new legitimate API key minted under load
                // would be locked out for the full window because the
                // map was full of stale prefixes from past bursts.
                // Drop-oldest preserves capacity for the new prefix and
                // (worst case) recreates an evicted prefix's counter on
                // its next request — which is benign: the worst that
                // happens is one bonus request slips through before the
                // counter ramps back up. Production should always use
                // Redis (line above this branch).
                if map.len() >= 10000 && !map.contains_key(&prefix) {
                    if let Some(oldest_key) = map
                        .iter()
                        .min_by_key(|(_, (_, start))| *start)
                        .map(|(k, _)| k.clone())
                    {
                        map.remove(&oldest_key);
                        tracing::warn!(
                            target: "talos_api_keys",
                            event_kind = "rate_limiter_evicted_oldest",
                            evicted = %oldest_key,
                            "API key rate limiter at cap; evicted oldest prefix to admit new"
                        );
                    } else {
                        // Map is genuinely empty after retain — should
                        // not happen given len>=10000 above, but be
                        // defensive.
                        return Err(anyhow!("Rate limiter overloaded — try again shortly"));
                    }
                }
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
            //
            // MCP-1099 (2026-05-16): log both failure paths distinctly,
            // mirroring MCP-873's MCP-auth fix. Pre-fix the outer + inner
            // `.unwrap_or(false)` collapsed BOTH spawn-blocking JoinError
            // (thread panic — operator-actionable runtime issue) AND
            // bcrypt::verify Err (malformed stored hash — DB corruption
            // or schema drift) into a silent mismatch. Symptom: every
            // affected user got a 401 with no operator signal that the
            // underlying `api_keys.key_hash` column had a broken row.
            // We continue past per-key failures (other keys with the
            // same prefix may verify cleanly) but emit `target =
            // "talos_audit"` WARNs so SIEM/dashboards see the dual-
            // failure class. Sibling discipline to the auth_audit_log
            // + secret_audit_log writers.
            let api_key_owned = api_key.to_string();
            let key_hash_clone = key_record.key_hash.clone();
            let key_id_for_log = key_record.id;
            let join_result =
                tokio::task::spawn_blocking(move || verify(&api_key_owned, &key_hash_clone)).await;
            let hash_match = match join_result {
                Ok(Ok(b)) => b,
                Ok(Err(e)) => {
                    tracing::warn!(
                        target: "talos_audit",
                        api_key_id = %key_id_for_log,
                        error = %e,
                        "api-key bcrypt::verify failed (possibly malformed stored hash) — skipping this candidate"
                    );
                    false
                }
                Err(e) => {
                    tracing::error!(
                        target: "talos_audit",
                        api_key_id = %key_id_for_log,
                        error = %e,
                        "api-key bcrypt spawn_blocking JoinError (thread panic) — skipping this candidate"
                    );
                    false
                }
            };
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

                match update_result {
                    Ok(res) if res.rows_affected() == 0 => {
                        tracing::warn!("API key was deactivated during validation");
                        return Err(anyhow!("Invalid or expired API key"));
                    }
                    Err(e) => {
                        // Fail closed: if we can't atomically verify the key is
                        // still active, reject it. A transient DB error is safer
                        // to treat as a rejection than to allow an unverified key.
                        tracing::warn!("API key atomic verification failed: {}", e);
                        return Err(anyhow!("API key verification failed"));
                    }
                    Ok(_) => {} // Key verified and usage recorded atomically
                }

                // Parse scopes — unknown scope strings are warned and dropped.
                // In production, any unrecognized scope causes the key to be
                // rejected entirely (fail-closed) to prevent privilege confusion.
                let mut scopes: Vec<ApiKeyScope> = Vec::new();
                let mut has_unknown_scope = false;
                for s in &key_record.scopes {
                    match ApiKeyScope::from_string(s) {
                        Some(scope) => scopes.push(scope),
                        None => {
                            has_unknown_scope = true;
                            tracing::warn!(
                                key_id = %key_record.id,
                                scope = s.as_str(),
                                "API key has unrecognized scope in database"
                            );
                        }
                    }
                }
                if has_unknown_scope && talos_config::is_production() {
                    tracing::error!(
                        key_id = %key_record.id,
                        "Rejecting API key with invalid scopes in production (fail-closed)"
                    );
                    return Err(anyhow!("API key configuration error — contact support"));
                }

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
            .filter_map(|s| parse_api_key_scope_logged(&s))
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
                    .filter_map(|s| parse_api_key_scope_logged(s))
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
                    .filter_map(|s| parse_api_key_scope_logged(s))
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
        Self::log_key_event(
            self.db_pool.clone(),
            user_id,
            "api_key_revoked",
            key_id,
            format!("API key {} revoked (deactivated)", key_id),
            serde_json::json!({ "key_id": key_id }),
        );
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
        Self::log_key_event(
            self.db_pool.clone(),
            user_id,
            "api_key_deleted",
            key_id,
            format!("API key {} permanently deleted", key_id),
            serde_json::json!({ "key_id": key_id }),
        );
        Ok(())
    }

    /// Rotate an API key atomically (deactivates old and creates new in one transaction).
    ///
    /// SECURITY: The deactivation and insertion are committed together so there is never
    /// a window where both the old and new key are simultaneously valid.  The bcrypt hash
    /// is computed BEFORE opening the transaction so a slow hash operation cannot hold a
    /// DB connection open for longer than necessary.
    pub async fn rotate_key(&self, key_id: Uuid, user_id: Uuid) -> Result<String> {
        // 1. Read old key metadata (outside any transaction — read-only).
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

        // 2. Generate and hash the new key BEFORE opening a DB transaction so that
        //    the slow bcrypt operation doesn't hold a connection for its duration.
        let (full_key, prefix) = Self::generate_key();
        let full_key_clone = full_key.clone();
        let cost = Self::resolve_bcrypt_cost()?;
        let key_hash = tokio::task::spawn_blocking(move || hash(&full_key_clone, cost))
            .await
            .context("Bcrypt hashing panicked")??;

        let scope_strings: Vec<String> = old_key.scopes.clone();
        let expires_at = old_key.expires_at; // preserve original expiry

        // 3. Atomically deactivate the old key and insert the new one inside a single
        //    DB transaction.  Both operations are committed together — no window where
        //    both the old and new key are simultaneously valid.
        let mut tx = self
            .db_pool
            .begin()
            .await
            .context("Failed to start transaction")?;

        let deactivated = sqlx::query(
            "UPDATE api_keys SET is_active = false WHERE id = $1 AND user_id = $2 AND is_active = true",
        )
        .bind(key_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .context("Failed to deactivate old key")?;

        if deactivated.rows_affected() == 0 {
            tx.rollback().await.ok();
            return Err(anyhow!(
                "API key not found, not owned by user, or already inactive"
            ));
        }

        let new_id: Uuid = sqlx::query_scalar(
            "INSERT INTO api_keys (user_id, name, key_hash, key_prefix, scopes, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING id",
        )
        .bind(user_id)
        .bind(&old_key.name)
        .bind(&key_hash)
        .bind(&prefix)
        .bind(&scope_strings[..])
        .bind(expires_at)
        .fetch_one(&mut *tx)
        .await
        .context("Failed to insert new key")?;

        tx.commit()
            .await
            .context("Failed to commit rotation transaction")?;

        tracing::info!(
            old_key_id = %key_id,
            new_key_id = %new_id,
            user_id = %user_id,
            "Rotated API key"
        );
        Self::log_key_event(
            self.db_pool.clone(),
            user_id,
            "api_key_rotated",
            key_id,
            format!(
                "API key '{}' rotated (old key {} deactivated)",
                old_key.name, key_id
            ),
            serde_json::json!({ "old_key_id": key_id, "new_key_id": new_id, "key_name": old_key.name }),
        );

        Ok(full_key)
    }

    /// Fire-and-forget audit log entry for API key lifecycle events.
    ///
    /// Writes to `admin_event_log` (append-only, immutability-trigger protected).
    /// Runs in a background task so it never blocks the caller.
    /// Sensitive values (key hash, full key) must NOT appear in `summary` or `details`.
    ///
    /// MCP-984 (2026-05-15): defence-in-depth DLP-redact `summary` and
    /// `details` at the persistence boundary. Callers embed
    /// user-supplied `name` (line ~252, ~707, ~849 — `format!("API key
    /// '{}' ...", name)`) which is arbitrary user input from
    /// `create_api_key(... name: &str ...)`. Users occasionally paste
    /// secrets into name fields by mistake; the canonical
    /// `ActorRepository::insert_admin_event_log` path already redacts
    /// both columns (MCP-978/979), but this crate writes raw SQL
    /// directly to the same table — bypassing that protection.
    /// Redaction is idempotent so re-scrubbing pre-cleaned text is a
    /// no-op.
    fn log_key_event(
        pool: Pool<Postgres>,
        user_id: Uuid,
        event_type: &'static str,
        key_id: Uuid,
        summary: String,
        details: serde_json::Value,
    ) {
        tokio::spawn(async move {
            let redacted_summary = talos_dlp_provider::redact_str(&summary);
            let redacted_details = talos_dlp_provider::redact_json(&details);
            if let Err(e) = sqlx::query(
                "INSERT INTO admin_event_log \
                 (user_id, event_type, resource_type, resource_id, summary, details) \
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(user_id)
            .bind(event_type)
            .bind("api_key")
            .bind(key_id)
            .bind(&redacted_summary)
            .bind(&redacted_details)
            .execute(&pool)
            .await
            {
                // MCP-573: upgrade to ERROR with a structured
                // event_kind so log-aggregation alerts surface
                // audit-log gaps. Pre-fix this was warn-only, which
                // for a tamper-evident audit surface (admin_event_log
                // has an immutability trigger — see migration) is
                // exactly the wrong default. A failed INSERT here
                // means a permanent audit gap for an api-key
                // create/revoke/rotate/use event: no WORM ledger
                // mirror exists for these (talos-audit-ledger covers
                // workflow audit events via the talos.audit.ledger
                // NATS topic, not api-key lifecycle). Operators
                // alerting on `event_kind=api_key_audit_write_failed`
                // get a signal of an incomplete trail at the time
                // it happens, not during a later forensic review.
                tracing::error!(
                    target: "talos_api_keys",
                    event_kind = "api_key_audit_write_failed",
                    error = %e,
                    event_type,
                    %key_id,
                    %user_id,
                    "Failed to write API key audit log entry — audit trail has a permanent gap for this event"
                );
            }
        });
    }

    /// Check rate limit using Redis (distributed across instances).
    /// Returns true if rate limit exceeded, false if allowed.
    ///
    /// MCP-455: pre-fix INCR and EXPIRE were two separate commands; if
    /// the EXPIRE leg failed transiently (network blip, mid-flight
    /// reconnect, server shutdown), INCR had already created the key
    /// with NO TTL. Subsequent requests would see `count > 1`, skip
    /// EXPIRE, and the key would persist forever — permanently
    /// rate-limiting the affected key_prefix until an operator
    /// manually deleted the Redis key. The L-19 review fix added a
    /// warn-log on EXPIRE failure but didn't close the underlying
    /// race. Move to an EVAL'd Lua script so both ops execute
    /// atomically on the server. Same fix as MCP-442 in
    /// `talos-rate-limit::middleware::check_redis`.
    async fn check_rate_limit_redis(
        &self,
        prefix: String,
        redis: &Arc<redis::Client>,
    ) -> Result<bool> {
        const LIMIT: usize = 60;
        const WINDOW_SECS: u64 = 60;

        let mut conn = redis
            .get_multiplexed_async_connection()
            .await
            .context("Failed to get Redis connection")?;

        let key = format!("api_key_rate_limit:{}", prefix);

        const RATE_LIMIT_SCRIPT: &str = r#"
            local count = redis.call('INCR', KEYS[1])
            if count == 1 then
                redis.call('EXPIRE', KEYS[1], ARGV[1])
            end
            return count
        "#;
        let count: i64 = redis::cmd("EVAL")
            .arg(RATE_LIMIT_SCRIPT)
            .arg(1)
            .arg(&key)
            .arg(WINDOW_SECS as i64)
            .query_async(&mut conn)
            .await
            .context("Redis rate-limit script failed")?;

        Ok(count > LIMIT as i64)
    }

    /// Clean up expired API keys.
    ///
    /// MCP-494: deactivation now writes a per-key audit-log entry
    /// (`api_key_expired`) so operators can correlate user-visible API
    /// failures with key lifecycle. Pre-fix this was the ONLY lifecycle
    /// path that mutated `is_active` without an `admin_event_log`
    /// entry — create/revoke/delete/rotate all logged, expiration did
    /// not. The bulk UPDATE returns the affected rows via RETURNING so
    /// per-key logging stays a single SQL round-trip; individual log
    /// writes are still fire-and-forget so a busy expiration batch
    /// doesn't block the operator-callable.
    pub async fn cleanup_expired_keys(&self) -> Result<u64> {
        // Uses runtime-typed `sqlx::query_as` instead of the `sqlx::query!`
        // macro so the RETURNING-clause addition doesn't require a fresh
        // `cargo sqlx prepare` round-trip against a live DB. The tuple
        // shape is pinned by the query text and exercised at runtime.
        let expired: Vec<(Uuid, Uuid, String, Option<DateTime<Utc>>)> =
            sqlx::query_as(
                "UPDATE api_keys
                 SET is_active = false
                 WHERE expires_at < NOW() AND is_active = true
                 RETURNING id, user_id, name, expires_at",
            )
            .fetch_all(&self.db_pool)
            .await?;

        let count = expired.len() as u64;
        for (id, user_id, name, expires_at) in expired {
            Self::log_key_event(
                self.db_pool.clone(),
                user_id,
                "api_key_expired",
                id,
                format!("API key '{}' expired and was deactivated", name),
                serde_json::json!({
                    "name": name,
                    "expires_at": expires_at,
                }),
            );
        }
        Ok(count)
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

    /// MCP-494: pin the production floor + DEFAULT_COST contract. The
    /// `MIN_BCRYPT_COST` and `DEFAULT_COST` constants are the security
    /// floor — they MUST NOT silently drop below 10 / 12 respectively
    /// in a future refactor. OWASP password-storage cheat sheet (2024)
    /// puts the minimum at 10.
    #[test]
    fn bcrypt_cost_floor_meets_owasp_minimum() {
        assert!(
            ApiKeyService::MIN_BCRYPT_COST >= 10,
            "MIN_BCRYPT_COST must be ≥ 10 per OWASP 2024 guidance"
        );
        assert!(
            DEFAULT_COST >= ApiKeyService::MIN_BCRYPT_COST,
            "bcrypt::DEFAULT_COST ({}) must be ≥ our floor ({})",
            DEFAULT_COST,
            ApiKeyService::MIN_BCRYPT_COST
        );
    }

    /// MCP-494: the env var is the operator-controlled knob and the
    /// floor is the safety net. This test simulates a fresh-process
    /// resolution and verifies the floor logic. Note: env-var
    /// resolution is process-global so this test only exercises the
    /// unset / default path to avoid leaking state into sibling
    /// tests; the clamp-up and fail-closed paths are covered by code
    /// inspection (the match arms in `resolve_bcrypt_cost` are
    /// exhaustive).
    #[test]
    fn bcrypt_cost_defaults_when_env_unset() {
        // Best-effort: scoped removal so concurrent tests in this file
        // don't disturb our read. SAFETY: env-var manipulation is
        // unsound under parallel tests — `cargo test` runs tests in
        // one process by default, so we briefly remove and restore.
        let was_set = std::env::var("API_KEY_BCRYPT_COST").ok();
        // SAFETY: We accept the unsafe-as-of-edition-2024 contract; tests in
        // this file don't run in parallel against env reads.
        unsafe {
            std::env::remove_var("API_KEY_BCRYPT_COST");
        }
        let cost = ApiKeyService::resolve_bcrypt_cost().expect("unset env should default");
        assert_eq!(cost, DEFAULT_COST);
        if let Some(prev) = was_set {
            unsafe {
                std::env::set_var("API_KEY_BCRYPT_COST", prev);
            }
        }
    }
}
