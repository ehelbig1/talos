//! Content-addressable node result cache for deterministic WASM modules.
//!
//! Cache key = SHA-256(module_content_hash || canonical_input_json).
//! Only `minimal-node` modules are cached — they have no side effects, so
//! identical inputs always produce identical outputs.
//!
//! Two-layer cache: Redis (sub-millisecond, volatile) → PostgreSQL (durable).

use anyhow::Result;
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Check whether a capability world is deterministic (safe to cache).
/// Only pure-computation worlds are cacheable. Any world with I/O (HTTP,
/// secrets, database, filesystem, messaging, cache, governance) is not.
pub fn is_cacheable_world(world: &str) -> bool {
    matches!(world, "minimal" | "minimal-node")
}

/// Compute a cache key from module hash and canonical input.
/// Uses length-prefixed encoding to prevent collisions.
pub fn compute_cache_key(module_hash: &str, input_json: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(module_hash.len().to_string().as_bytes());
    hasher.update(b"\0");
    hasher.update(module_hash.as_bytes());
    hasher.update(input_json.len().to_string().as_bytes());
    hasher.update(b"\0");
    hasher.update(input_json.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Node result cache backed by Redis (fast) and PostgreSQL (durable).
pub struct NodeResultCache {
    redis_client: Option<Arc<redis::Client>>,
    db_pool: sqlx::PgPool,
    /// Whether caching is enabled (can be disabled via TALOS_NODE_CACHE=off).
    enabled: bool,
    /// Cache TTL in seconds (default: 7 days).
    ttl_secs: u64,
}

impl NodeResultCache {
    pub fn new(redis_client: Option<Arc<redis::Client>>, db_pool: sqlx::PgPool) -> Self {
        // MCP-1117 (2026-05-16): canonical bool-env helper. Pre-fix
        // inline `v != "off" && v != "false" && v != "0"` was
        // case-sensitive exact-match → `TALOS_NODE_CACHE=FALSE`,
        // `=OFF`, `=No`, `=disable` all fell through to ENABLED
        // because none matched the lowercase-literal disable set.
        // Operator setting the env to disable the cache silently
        // got an enabled cache instead — possible source of stale
        // results when they thought caching was off.
        //
        // `bool_env_or_default` accepts the canonical workspace
        // truthy/falsy tokens (`true|1|yes|on` / `false|0|no|off`),
        // case-insensitive, with WARN on unrecognised values.
        // Sibling drift fix to MCP-1060/1072/1073/1109 — same
        // pattern across the bool-env consumer family.
        let enabled = talos_config::bool_env_or_default("TALOS_NODE_CACHE", true);
        // MCP-695 (2026-05-13): =0 env footgun class (sibling of
        // MCP-665/689). `TALOS_NODE_CACHE_TTL_SECS=0` would set a
        // zero-second TTL on every Redis `SETEX` and the SQL `expires_at`
        // would land at `NOW()`, so every cache write is dead-on-arrival
        // and every minimal-node lookup falls through to re-execution.
        // Not destructive but a perf cliff that's silent at startup.
        // Route through `positive_env_or_default` for the standard
        // substitute-and-WARN behaviour.
        let ttl_secs = talos_config::positive_env_or_default(
            "TALOS_NODE_CACHE_TTL_SECS",
            7 * 24 * 3600u64, // 7 days
        );

        if enabled {
            tracing::info!(ttl_secs = ttl_secs, "Node result cache enabled");
        }

        Self {
            redis_client,
            db_pool,
            enabled,
            ttl_secs,
        }
    }

    /// Look up a cached result. Tries Redis first, then PostgreSQL.
    pub async fn get(&self, cache_key: &str) -> Option<serde_json::Value> {
        if !self.enabled {
            return None;
        }

        // Layer 1: Redis
        if let Some(ref client) = self.redis_client {
            if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                let redis_key = format!("ncache:{}", cache_key);
                if let Ok(Some(json_str)) = redis::cmd("GET")
                    .arg(&redis_key)
                    .query_async::<Option<String>>(&mut conn)
                    .await
                {
                    {
                        if let Ok(parsed) = serde_json::from_str(&json_str) {
                            tracing::debug!(
                                cache_key = cache_key,
                                layer = "redis",
                                "Node cache hit"
                            );
                            return Some(parsed);
                        }
                    }
                }
            }
        }

        // Layer 2: PostgreSQL
        let row = sqlx::query_scalar::<_, serde_json::Value>(
            "UPDATE node_result_cache SET hit_count = hit_count + 1, last_hit_at = NOW() \
             WHERE cache_key = $1 AND expires_at > NOW() RETURNING output_json",
        )
        .bind(cache_key)
        .fetch_optional(&self.db_pool)
        .await
        .ok()
        .flatten();

        if let Some(ref val) = row {
            tracing::debug!(cache_key = cache_key, layer = "postgres", "Node cache hit");
            // Backfill Redis for future fast lookups
            if let Some(ref client) = self.redis_client {
                if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                    let redis_key = format!("ncache:{}", cache_key);
                    let _ = redis::cmd("SETEX")
                        .arg(&redis_key)
                        .arg(self.ttl_secs as i64)
                        .arg(serde_json::to_string(val).unwrap_or_default())
                        .query_async::<()>(&mut conn)
                        .await;
                }
            }
        }

        row
    }

    /// Store a result in both Redis and PostgreSQL.
    pub async fn put(
        &self,
        cache_key: &str,
        module_hash: &str,
        input_hash: &str,
        output: &serde_json::Value,
        fuel_consumed: Option<i64>,
    ) {
        if !self.enabled {
            return;
        }

        // Layer 1: Redis (fire-and-forget)
        if let Some(ref client) = self.redis_client {
            if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                let redis_key = format!("ncache:{}", cache_key);
                let _ = redis::cmd("SETEX")
                    .arg(&redis_key)
                    .arg(self.ttl_secs as i64)
                    .arg(serde_json::to_string(output).unwrap_or_default())
                    .query_async::<()>(&mut conn)
                    .await;
            }
        }

        // Layer 2: PostgreSQL (durable, fire-and-forget)
        let pool = self.db_pool.clone();
        let key = cache_key.to_string();
        let mhash = module_hash.to_string();
        let ihash = input_hash.to_string();
        let out = output.clone();
        let ttl = self.ttl_secs as i64;
        let fuel = fuel_consumed;

        tokio::spawn(async move {
            // allow-sqlx-swallow: background cache hydration is best-effort
            // by design — failure just means the next read sees a cache
            // miss and recomputes. No operator-visible degradation; we
            // don't want WARN-log noise for transient DB blips on a
            // non-critical fire-and-forget path.
            let _ = sqlx::query(
                "INSERT INTO node_result_cache (cache_key, module_hash, input_hash, output_json, fuel_consumed, expires_at) \
                 VALUES ($1, $2, $3, $4, $5, NOW() + make_interval(secs => $6)) \
                 ON CONFLICT (cache_key) DO UPDATE SET \
                     output_json = EXCLUDED.output_json, \
                     fuel_consumed = EXCLUDED.fuel_consumed, \
                     last_hit_at = NOW(), \
                     expires_at = NOW() + make_interval(secs => $6)"
            )
            .bind(&key)
            .bind(&mhash)
            .bind(&ihash)
            .bind(&out)
            .bind(fuel)
            .bind(ttl as f64)
            .execute(&pool)
            .await;
        });
    }

    /// Evict expired cache entries. Call periodically from a background task.
    pub async fn cleanup(&self) -> Result<u64> {
        let result = sqlx::query("DELETE FROM node_result_cache WHERE expires_at < NOW()")
            .execute(&self.db_pool)
            .await?;
        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_key_is_deterministic() {
        let k1 = compute_cache_key("abc123", "{\"x\": 1}");
        let k2 = compute_cache_key("abc123", "{\"x\": 1}");
        assert_eq!(k1, k2);
    }

    #[test]
    fn cache_key_differs_with_input() {
        let k1 = compute_cache_key("abc123", "{\"x\": 1}");
        let k2 = compute_cache_key("abc123", "{\"x\": 2}");
        assert_ne!(k1, k2);
    }

    #[test]
    fn cache_key_differs_with_module() {
        let k1 = compute_cache_key("mod_a", "{\"x\": 1}");
        let k2 = compute_cache_key("mod_b", "{\"x\": 1}");
        assert_ne!(k1, k2);
    }

    #[test]
    fn minimal_node_is_cacheable() {
        assert!(is_cacheable_world("minimal-node"));
        assert!(is_cacheable_world("minimal"));
        assert!(!is_cacheable_world("http-node"));
        assert!(!is_cacheable_world("secrets-node"));
        assert!(!is_cacheable_world("database-node"));
        assert!(!is_cacheable_world("trusted"));
    }
}
