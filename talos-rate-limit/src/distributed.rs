//! Distributed rate limiting with Redis backend.
//!
//! Provides:
//! - Sliding window rate limiting
//! - Token bucket algorithm
//! - Per-user, per-tenant, and per-endpoint limits
//! - Atomic operations using Redis Lua scripts

use anyhow::Result;
use redis::AsyncCommands;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Rate limit configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests allowed in the window
    pub max_requests: u32,
    /// Window duration in seconds
    pub window_secs: u64,
    /// Burst capacity (token bucket only)
    pub burst: u32,
}

impl RateLimitConfig {
    /// API rate limit: 100 requests per minute
    pub fn api() -> Self {
        Self {
            max_requests: 100,
            window_secs: 60,
            burst: 20,
        }
    }

    /// Webhook rate limit: 60 requests per minute
    pub fn webhook() -> Self {
        Self {
            max_requests: 60,
            window_secs: 60,
            burst: 10,
        }
    }

    /// Strict rate limit: 10 requests per minute
    pub fn strict() -> Self {
        Self {
            max_requests: 10,
            window_secs: 60,
            burst: 2,
        }
    }
}

/// Rate limit check result
#[derive(Debug, Clone)]
pub struct RateLimitResult {
    /// Whether the request is allowed
    pub allowed: bool,
    /// Remaining requests in window
    pub remaining: u32,
    /// Seconds until reset
    pub reset_after_secs: u64,
    /// Total limit
    pub limit: u32,
}

/// Distributed rate limiter using Redis sliding window
pub struct DistributedRateLimiter {
    redis: Arc<redis::Client>,
    default_config: RateLimitConfig,
}

impl DistributedRateLimiter {
    /// Create new rate limiter
    pub fn new(redis: Arc<redis::Client>, config: RateLimitConfig) -> Self {
        Self {
            redis,
            default_config: config,
        }
    }

    /// Check rate limit for a key
    pub async fn check(
        &self,
        key: &str,
        config: Option<&RateLimitConfig>,
    ) -> Result<RateLimitResult> {
        let config = config.unwrap_or(&self.default_config);
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;

        let window_start = now - (config.window_secs * 1000);

        let mut conn = self.redis.get_multiplexed_async_connection().await?;

        // MCP-475: per-request unique member for ZADD. Pre-fix the script
        // used `now` as BOTH the sorted-set score AND the member. Sorted
        // sets dedup on member, so concurrent requests landing in the
        // same millisecond would collapse to a single ZADD entry —
        // every script after the first saw `current < limit` (because
        // its own ZADD was a no-op against the existing member), so
        // each request was reported as allowed and the rate counter
        // undercounted by exactly the same-millisecond burst size.
        // Trivially exploitable under high QPS or with timing-control
        // (e.g. async batched POST). A UUID member is unique across
        // any clock granularity AND across Redis cluster failover.
        let member = uuid::Uuid::new_v4().to_string();

        // Lua script for atomic rate limit check using sorted set
        let script = r#"
            local key = KEYS[1]
            local now = tonumber(ARGV[1])
            local window_start = tonumber(ARGV[2])
            local limit = tonumber(ARGV[3])
            local window = tonumber(ARGV[4])
            local member = ARGV[5]

            -- Remove old entries
            redis.call('ZREMRANGEBYSCORE', key, 0, window_start)

            -- Count current entries
            local current = redis.call('ZCARD', key)

            -- Check if allowed
            if current < limit then
                -- Add current request with a per-request unique member;
                -- score remains `now` so window eviction logic is unchanged.
                redis.call('ZADD', key, now, member)
                -- Set expiry
                redis.call('EXPIRE', key, window)
                return {1, limit - current - 1, window}
            else
                local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
                local reset = (oldest[2] / 1000) + window - (now / 1000)
                return {0, 0, reset}
            end
        "#;

        let result: Vec<i64> = redis::cmd("EVAL")
            .arg(script)
            .arg(1)
            .arg(key)
            .arg(now)
            .arg(window_start)
            .arg(config.max_requests)
            .arg(config.window_secs)
            .arg(member)
            .query_async(&mut conn)
            .await?;

        Ok(RateLimitResult {
            allowed: result[0] == 1,
            remaining: result[1] as u32,
            reset_after_secs: result[2] as u64,
            limit: config.max_requests,
        })
    }

    /// Get current count for key
    pub async fn get_count(&self, key: &str) -> Result<u32> {
        let mut conn = self.redis.get_multiplexed_async_connection().await?;

        let count: i64 = redis::cmd("ZCARD").arg(key).query_async(&mut conn).await?;

        Ok(count as u32)
    }

    /// Reset rate limit for key
    pub async fn reset(&self, key: &str) -> Result<()> {
        let mut conn = self.redis.get_multiplexed_async_connection().await?;

        let _: () = conn.del(key).await?;
        Ok(())
    }
}

/// Builder for rate limit keys
pub struct RateLimitKeyBuilder;

impl RateLimitKeyBuilder {
    /// Key for IP-based rate limiting
    pub fn ip(ip: &str) -> String {
        format!("ratelimit:ip:{}", ip)
    }

    /// Key for user-based rate limiting
    pub fn user(user_id: uuid::Uuid) -> String {
        format!("ratelimit:user:{}", user_id)
    }

    /// Key for API key-based rate limiting
    pub fn api_key(key_prefix: &str) -> String {
        format!("ratelimit:apikey:{}", key_prefix)
    }

    /// Key for tenant-based rate limiting
    pub fn tenant(tenant_id: uuid::Uuid) -> String {
        format!("ratelimit:tenant:{}", tenant_id)
    }

    /// Key for endpoint-based rate limiting
    pub fn endpoint(user_id: uuid::Uuid, path: &str) -> String {
        format!("ratelimit:endpoint:{}:{}", user_id, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_config() {
        let api = RateLimitConfig::api();
        assert_eq!(api.max_requests, 100);
        assert_eq!(api.window_secs, 60);

        let strict = RateLimitConfig::strict();
        assert_eq!(strict.max_requests, 10);
    }

    #[test]
    fn test_key_builder() {
        let ip_key = RateLimitKeyBuilder::ip("192.168.1.1");
        assert!(ip_key.contains("192.168.1.1"));

        let user_key = RateLimitKeyBuilder::user(uuid::Uuid::new_v4());
        assert!(user_key.starts_with("ratelimit:user:"));
    }
}
