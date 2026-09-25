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
/// bcrypt's hard input-truncation limit (bytes). Input past this is ignored.
const BCRYPT_INPUT_LIMIT: usize = 72;
/// Fixed, non-secret preamble consumed inside the bcrypt window:
/// `talos_sk_` (9) + the 8-hex-char prefix (which is ALSO verified separately
/// via the constant-time prefix check + DB lookup).
const KEY_PREAMBLE_LEN: usize = "talos_sk_".len() + 8;
/// Compile-time guard (security review 2026-07-19, L4): the secret entropy that
/// survives bcrypt's 72-byte truncation must stay above 128 bits. Each surviving
/// hex char is 4 bits. Fails to compile if a future key-layout change erodes it
/// (e.g. a longer scheme tag or prefix pushing more of the secret past the
/// cliff) — forcing a deliberate key-format migration instead of a silent
/// weakening. No weakness today: 220 bits are verified.
const _: () = assert!(
    (BCRYPT_INPUT_LIMIT - KEY_PREAMBLE_LEN) * 4 >= 128,
    "API key layout change pushed verified secret entropy below 128 bits — \
     hash the secret separately or SHA-256-prehash before bcrypt (this needs a \
     key-format migration; existing keys were hashed with the old layout)"
);

/// Failed validations a key prefix may spend per [`FAILURE_WINDOW`] before
/// the legacy bcrypt path refuses it.
const FAILURE_LIMIT: usize = 60;
const FAILURE_WINDOW: StdDuration = StdDuration::from_secs(60);
/// Bound on the in-memory limiter map.
const RATE_LIMITER_MAX_ENTRIES: usize = 10_000;
/// Minimum seconds between two `last_used_at` / `usage_count` writes per key.
const USAGE_WRITE_INTERVAL_SECS: i32 = 60;

/// SHA-256 hex digest of a full API key, as stored in `api_keys.key_digest`.
/// A plain hash is sufficient: the key carries 256 random bits, so there is
/// nothing for a slow or keyed hash to protect against brute force.
#[must_use]
pub fn api_key_digest(full_key: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(full_key.as_bytes()))
}

/// Constant-time equality of a stored and a presented digest.
#[must_use]
pub fn digest_matches(stored: &str, presented: &str) -> bool {
    use subtle::ConstantTimeEq;
    stored.len() == presented.len()
        && stored.as_bytes().ct_eq(presented.as_bytes()).unwrap_u8() == 1
}

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
    ///
    /// Security review 2026-07-19 (L4): bcrypt truncates its input at 72 bytes,
    /// so only the first 72 chars of the 81-char key are verified. The fixed
    /// preamble (`talos_sk_` + 8-hex prefix) consumes 17 bytes, leaving 55 of
    /// the 64 secret hex chars — 220 bits — inside the verified window (the
    /// 8-hex prefix is ALSO verified independently via the constant-time prefix
    /// check + DB lookup). 220 bits is far above any practical threshold, so
    /// there is no weakness today; the static assertion below simply guarantees
    /// a FUTURE layout change (a longer scheme tag / prefix) can't silently push
    /// the verified secret entropy below 128 bits without failing the build.
    /// A real fix (hash the secret alone, or SHA-256-prehash) would invalidate
    /// every already-issued key, so it is deliberately deferred to a key-format
    /// migration rather than done implicitly here.
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
        // `key_hash` (bcrypt) is still written so a controller rolled back to
        // a bcrypt-only verifier keeps accepting keys minted by this one.
        let (record_id, record_expires_at): (Uuid, Option<DateTime<Utc>>) = sqlx::query_as(
            "INSERT INTO api_keys (user_id, name, key_hash, key_digest, key_prefix, scopes, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             RETURNING id, expires_at",
        )
        .bind(user_id)
        .bind(name)
        .bind(&key_hash)
        .bind(api_key_digest(&full_key))
        .bind(&prefix)
        .bind(&scope_strings[..])
        .bind(expires_at)
        .fetch_one(&mut *tx)
        .await
        .context("Failed to create API key")?;

        Self::record_key_event(
            &mut tx,
            user_id,
            "api_key_created",
            record_id,
            &format!("API key '{}' created", name),
            serde_json::json!({ "name": name, "scopes": scope_strings }),
        )
        .await?;

        tx.commit()
            .await
            .context("Failed to commit api-key create transaction")?;

        tracing::info!("Created API key '{}' for user {}", name, user_id);

        // Return the full key (only time it's returned!) along with metadata
        Ok((full_key, record_id, record_expires_at))
    }

    /// Validate an API key and return the user_id and scopes.
    ///
    /// 2026-09-26: a key is checked by a constant-time compare of its SHA-256
    /// digest (`api_keys.key_digest`), not bcrypt on every request — the key
    /// is 256 random bits, so a slow hash buys nothing and cost ~100 ms of CPU
    /// per authenticated call. Rows minted before the digest existed are
    /// bcrypt-verified ONCE and upgraded in place. The per-prefix limiter now
    /// counts FAILED validations only: a correct key is never limited (it was
    /// capped at 60/min, and anyone who knew the visible prefix could spend
    /// that budget), and the budget still guards the legacy bcrypt path. A key
    /// whose owner is deactivated no longer validates.
    pub async fn validate_key(&self, api_key: &str) -> Result<(Uuid, Vec<ApiKeyScope>)> {
        // Constant-time format check against the known key prefix to prevent
        // timing-based enumeration of valid vs. invalid key formats.
        use subtle::ConstantTimeEq;
        const KEY_PREFIX: &[u8] = b"talos_sk_";
        let key_bytes = api_key.as_bytes();
        let prefix_ok = key_bytes.len() >= KEY_PREFIX.len()
            && key_bytes[..KEY_PREFIX.len()].ct_eq(KEY_PREFIX).unwrap_u8() == 1;
        if !prefix_ok {
            tracing::warn!("API key validation failed: malformed prefix");
            talos_metrics::record_api_key_validation(talos_metrics::ApiKeyValidation::Invalid);
            return Err(anyhow!("Invalid API key format"));
        }

        let key_without_prefix = &api_key[KEY_PREFIX.len()..];

        let prefix: String = key_without_prefix.chars().take(8).collect();
        if prefix.chars().count() < 8 {
            tracing::warn!("API key validation failed: short prefix");
            talos_metrics::record_api_key_validation(talos_metrics::ApiKeyValidation::Invalid);
            return Err(anyhow!("Invalid API key format"));
        }

        // Candidates with this prefix whose OWNER is still active.
        let keys: Vec<(
            Uuid,
            Uuid,
            String,
            Option<String>,
            Vec<String>,
            Option<DateTime<Utc>>,
        )> = sqlx::query_as(
            "SELECT k.id, k.user_id, k.key_hash, k.key_digest, k.scopes, k.expires_at
                 FROM api_keys k
                 JOIN users u ON u.id = k.user_id AND u.is_active = true
                 WHERE k.key_prefix = $1 AND k.is_active = true",
        )
        .bind(&prefix)
        .fetch_all(&self.db_pool)
        .await?;

        // `expired` is reported only when every candidate was past its expiry
        // — see `talos_metrics::ApiKeyValidation`.
        let now = Utc::now();
        let presented = api_key_digest(api_key);
        let mut expired_seen = false;
        let mut live = Vec::with_capacity(keys.len());
        for k in keys {
            if k.5.is_some_and(|e| e < now) {
                expired_seen = true;
            } else {
                live.push(k);
            }
        }

        let mut matched = live
            .iter()
            .find(|k| {
                k.3.as_deref()
                    .is_some_and(|d| digest_matches(d, &presented))
            })
            .map(|k| (k.0, k.1, k.4.clone()));

        // Legacy rows (no digest yet): bcrypt, behind the failure budget.
        let legacy: Vec<_> = live.iter().filter(|k| k.3.is_none()).collect();
        if matched.is_none() && !legacy.is_empty() {
            if self.failures_exceeded(&prefix).await {
                tracing::warn!("API key rate limit exceeded for prefix {}", prefix);
                talos_metrics::record_api_key_validation(
                    talos_metrics::ApiKeyValidation::RateLimited,
                );
                talos_metrics::record_rate_limit_hit(talos_metrics::RateLimitKind::ApiKey);
                return Err(anyhow!("Rate limit exceeded"));
            }
            for key_record in legacy {
                // MCP-1099: a JoinError (thread panic) and a bcrypt Err
                // (malformed stored hash) are logged distinctly and skip
                // this candidate; other keys with the prefix may verify.
                let api_key_owned = zeroize::Zeroizing::new(api_key.to_string());
                let key_hash_clone = key_record.2.clone();
                let key_id_for_log = key_record.0;
                let join_result = tokio::task::spawn_blocking(move || {
                    verify(api_key_owned.as_str(), &key_hash_clone)
                })
                .await;
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
                    // Upgrade once; later validations take the digest path.
                    if let Err(e) = sqlx::query(
                        "UPDATE api_keys SET key_digest = $2 WHERE id = $1 AND key_digest IS NULL",
                    )
                    .bind(key_record.0)
                    .bind(&presented)
                    .execute(&self.db_pool)
                    .await
                    {
                        tracing::warn!(
                            api_key_id = %key_record.0,
                            error = %e,
                            "api-key digest upgrade failed; the key stays on the bcrypt path"
                        );
                    }
                    matched = Some((key_record.0, key_record.1, key_record.4.clone()));
                    break;
                }
            }
        }

        let Some((key_id, user_id, stored_scopes)) = matched else {
            self.charge_failure(&prefix).await;
            tracing::warn!("API key validation failed: no matching active key");
            talos_metrics::record_api_key_validation(if expired_seen {
                talos_metrics::ApiKeyValidation::Expired
            } else {
                talos_metrics::ApiKeyValidation::Invalid
            });
            return Err(anyhow!("Invalid or expired API key"));
        };

        // Usage bookkeeping, at most once per `USAGE_WRITE_INTERVAL_SECS` per
        // key: a write per request was a row update on every authenticated
        // call. `usage_count` therefore counts those writes, not requests. A
        // failed write fails closed (a database we cannot write is not one we
        // trust to have answered the read above).
        if let Err(e) = sqlx::query(
            "UPDATE api_keys
             SET last_used_at = NOW(), usage_count = usage_count + 1
             WHERE id = $1 AND is_active = true
               AND (last_used_at IS NULL
                    OR last_used_at < NOW() - make_interval(secs => $2::int))",
        )
        .bind(key_id)
        .bind(USAGE_WRITE_INTERVAL_SECS)
        .execute(&self.db_pool)
        .await
        {
            tracing::warn!("API key usage write failed: {}", e);
            return Err(anyhow!("API key verification failed"));
        }

        // Parse scopes — unknown scope strings are warned and dropped.
        // In production, any unrecognized scope causes the key to be
        // rejected entirely (fail-closed) to prevent privilege confusion.
        let mut scopes: Vec<ApiKeyScope> = Vec::new();
        let mut has_unknown_scope = false;
        for s in &stored_scopes {
            match ApiKeyScope::from_string(s) {
                Some(scope) => scopes.push(scope),
                None => {
                    has_unknown_scope = true;
                    tracing::warn!(
                        key_id = %key_id,
                        scope = s.as_str(),
                        "API key has unrecognized scope in database"
                    );
                }
            }
        }
        if has_unknown_scope && talos_config::is_production() {
            tracing::error!(
                key_id = %key_id,
                "Rejecting API key with invalid scopes in production (fail-closed)"
            );
            talos_metrics::record_api_key_validation(talos_metrics::ApiKeyValidation::Invalid);
            return Err(anyhow!("API key configuration error — contact support"));
        }

        talos_metrics::record_api_key_validation(talos_metrics::ApiKeyValidation::Valid);
        Ok((user_id, scopes))
    }

    /// Has `prefix` spent its failed-validation budget in the current window?
    /// Redis first (fleet-wide); the in-memory map when Redis is absent or
    /// fails.
    async fn failures_exceeded(&self, prefix: &str) -> bool {
        if let Some(redis) = &self.redis_client {
            match Self::redis_failures(prefix, redis, false).await {
                Ok(n) => return n >= FAILURE_LIMIT as i64,
                Err(e) => tracing::warn!(
                    "Redis rate limit check failed, falling back to in-memory: {}",
                    e
                ),
            }
        }
        let map = self.rate_limiter.lock().await;
        map.get(prefix).is_some_and(|(count, start)| {
            start.elapsed() <= FAILURE_WINDOW && *count >= FAILURE_LIMIT
        })
    }

    /// Count one failed validation against `prefix`.
    async fn charge_failure(&self, prefix: &str) {
        if let Some(redis) = &self.redis_client {
            match Self::redis_failures(prefix, redis, true).await {
                Ok(_) => return,
                Err(e) => tracing::warn!(
                    "Redis rate limit charge failed, falling back to in-memory: {}",
                    e
                ),
            }
        }
        let mut map = self.rate_limiter.lock().await;
        // Prevent unbounded memory growth: cleanup BEFORE insertion.
        if map.len() >= RATE_LIMITER_MAX_ENTRIES {
            let now = Instant::now();
            map.retain(|_, (_, start)| now.duration_since(*start) <= FAILURE_WINDOW);
            // L-18: still at capacity — evict the OLDEST entry rather than
            // refusing to track a new prefix.
            if map.len() >= RATE_LIMITER_MAX_ENTRIES && !map.contains_key(prefix) {
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
                }
            }
        }
        let entry = map.entry(prefix.to_string()).or_insert((0, Instant::now()));
        if entry.1.elapsed() > FAILURE_WINDOW {
            *entry = (0, Instant::now());
        }
        entry.0 += 1;
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
             ORDER BY created_at DESC, id DESC
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
        let mut tx = self.db_pool.begin().await?;
        let result = sqlx::query!(
            "UPDATE api_keys
             SET is_active = false
             WHERE id = $1 AND user_id = $2",
            key_id,
            user_id
        )
        .execute(&mut *tx)
        .await?;

        if result.rows_affected() == 0 {
            return Err(anyhow!("API key not found or not owned by user"));
        }

        Self::record_key_event(
            &mut tx,
            user_id,
            "api_key_revoked",
            key_id,
            &format!("API key {} revoked (deactivated)", key_id),
            serde_json::json!({ "key_id": key_id }),
        )
        .await?;
        tx.commit().await?;
        tracing::info!("Revoked API key {} for user {}", key_id, user_id);
        Ok(())
    }

    /// Delete an API key permanently
    pub async fn delete_key(&self, key_id: Uuid, user_id: Uuid) -> Result<()> {
        let mut tx = self.db_pool.begin().await?;
        let result = sqlx::query!(
            "DELETE FROM api_keys
             WHERE id = $1 AND user_id = $2",
            key_id,
            user_id
        )
        .execute(&mut *tx)
        .await?;

        if result.rows_affected() == 0 {
            return Err(anyhow!("API key not found or not owned by user"));
        }

        Self::record_key_event(
            &mut tx,
            user_id,
            "api_key_deleted",
            key_id,
            &format!("API key {} permanently deleted", key_id),
            serde_json::json!({ "key_id": key_id }),
        )
        .await?;
        tx.commit().await?;
        tracing::info!("Deleted API key {} for user {}", key_id, user_id);
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
            "INSERT INTO api_keys (user_id, name, key_hash, key_digest, key_prefix, scopes, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             RETURNING id",
        )
        .bind(user_id)
        .bind(&old_key.name)
        .bind(&key_hash)
        .bind(api_key_digest(&full_key))
        .bind(&prefix)
        .bind(&scope_strings[..])
        .bind(expires_at)
        .fetch_one(&mut *tx)
        .await
        .context("Failed to insert new key")?;

        Self::record_key_event(
            &mut tx,
            user_id,
            "api_key_rotated",
            key_id,
            &format!(
                "API key '{}' rotated (old key {} deactivated)",
                old_key.name, key_id
            ),
            serde_json::json!({ "old_key_id": key_id, "new_key_id": new_id, "key_name": old_key.name }),
        )
        .await?;

        tx.commit()
            .await
            .context("Failed to commit rotation transaction")?;

        tracing::info!(
            old_key_id = %key_id,
            new_key_id = %new_id,
            user_id = %user_id,
            "Rotated API key"
        );

        Ok(full_key)
    }

    /// The audit record of an API-key lifecycle change, written on the
    /// change's own transaction: a key is never created, rotated, revoked,
    /// deleted or expired without its row in `admin_event_log`, and a record
    /// is never written for a change that rolled back. Until 2026-09-18 this
    /// was a detached `tokio::spawn` after the commit — a failed or dropped
    /// task left a permanent gap — AND the GraphQL resolvers wrote a second
    /// copy of the same event, so every change was recorded twice.
    async fn record_key_event(
        conn: &mut sqlx::PgConnection,
        user_id: Uuid,
        event_type: &'static str,
        key_id: Uuid,
        summary: &str,
        details: serde_json::Value,
    ) -> Result<()> {
        talos_admin_event_log::insert_on_conn(
            conn,
            Some(user_id),
            event_type,
            "api_key",
            Some(key_id),
            summary,
            Some(&details),
        )
        .await
        .context("Failed to record the API key lifecycle event")
    }

    /// Read (`charge = false`) or increment (`charge = true`) the fleet-wide
    /// failed-validation count for `prefix`.
    ///
    /// MCP-455: the increment is an EVAL'd Lua script so INCR and EXPIRE run
    /// atomically — a separate EXPIRE that failed left a key with no TTL that
    /// rate-limited the prefix forever.
    async fn redis_failures(prefix: &str, redis: &Arc<redis::Client>, charge: bool) -> Result<i64> {
        let mut conn = redis
            .get_multiplexed_async_connection()
            .await
            .context("Failed to get Redis connection")?;

        let key = format!("api_key_rate_limit:{}", prefix);
        if !charge {
            let count: Option<i64> = redis::cmd("GET")
                .arg(&key)
                .query_async(&mut conn)
                .await
                .context("Redis rate-limit read failed")?;
            return Ok(count.unwrap_or(0));
        }

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
            .arg(FAILURE_WINDOW.as_secs() as i64)
            .query_async(&mut conn)
            .await
            .context("Redis rate-limit script failed")?;
        Ok(count)
    }

    /// Clean up expired API keys.
    ///
    /// MCP-494: deactivation now writes a per-key audit-log entry
    /// (`api_key_expired`) so operators can correlate user-visible API
    /// failures with key lifecycle. Pre-fix this was the ONLY lifecycle
    /// path that mutated `is_active` without an `admin_event_log`
    /// entry — create/revoke/delete/rotate all logged, expiration did
    /// not. The bulk UPDATE returns the affected rows via RETURNING so
    /// per-key logging needs no second read; each key's record is written in
    /// the same transaction as the bulk UPDATE (2026-09-18 — it was a
    /// detached task per key), so an expiry is never committed without its
    /// record.
    pub async fn cleanup_expired_keys(&self) -> Result<u64> {
        // Uses runtime-typed `sqlx::query_as` instead of the `sqlx::query!`
        // macro so the RETURNING-clause addition doesn't require a fresh
        // `cargo sqlx prepare` round-trip against a live DB. The tuple
        // shape is pinned by the query text and exercised at runtime.
        let mut tx = self.db_pool.begin().await?;
        let expired: Vec<(Uuid, Uuid, String, Option<DateTime<Utc>>)> = sqlx::query_as(
            "UPDATE api_keys
                 SET is_active = false
                 WHERE expires_at < NOW() AND is_active = true
                 RETURNING id, user_id, name, expires_at",
        )
        .fetch_all(&mut *tx)
        .await?;

        let count = expired.len() as u64;
        for (id, user_id, name, expires_at) in expired {
            Self::record_key_event(
                &mut tx,
                user_id,
                "api_key_expired",
                id,
                &format!("API key '{}' expired and was deactivated", name),
                serde_json::json!({
                    "name": name,
                    "expires_at": expires_at,
                }),
            )
            .await?;
        }
        tx.commit().await?;
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
    fn the_digest_is_sha256_hex_and_compares_in_constant_time() {
        // SHA-256("abc"), the FIPS 180-2 test vector.
        assert_eq!(
            api_key_digest("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let (key, _) = ApiKeyService::generate_key();
        let d = api_key_digest(&key);
        assert!(digest_matches(&d, &api_key_digest(&key)));
        let (other, _) = ApiKeyService::generate_key();
        assert!(!digest_matches(&d, &api_key_digest(&other)));
        assert!(!digest_matches(&d, &d[..63]));
    }

    /// Only FAILED validations spend the per-prefix budget: 60 charges trip
    /// it, and a prefix nobody failed on is never over.
    #[tokio::test]
    async fn the_limiter_counts_failures_only() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused@localhost/unused")
            .expect("lazy pool");
        let svc = ApiKeyService::new(pool, None);
        assert!(!svc.failures_exceeded("aaaaaaaa").await);
        for _ in 0..FAILURE_LIMIT - 1 {
            svc.charge_failure("aaaaaaaa").await;
        }
        assert!(!svc.failures_exceeded("aaaaaaaa").await);
        svc.charge_failure("aaaaaaaa").await;
        assert!(svc.failures_exceeded("aaaaaaaa").await);
        assert!(!svc.failures_exceeded("bbbbbbbb").await);
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
    /// Both are compile-time pins: a floor that regresses fails the build
    /// of the test target, not a test run.
    const _: () = assert!(
        ApiKeyService::MIN_BCRYPT_COST >= 10,
        "MIN_BCRYPT_COST must be ≥ 10 per OWASP 2024 guidance"
    );
    const _: () = assert!(
        DEFAULT_COST >= ApiKeyService::MIN_BCRYPT_COST,
        "bcrypt::DEFAULT_COST must be ≥ our MIN_BCRYPT_COST floor"
    );

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
