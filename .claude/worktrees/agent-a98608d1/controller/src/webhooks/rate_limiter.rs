use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Token bucket rate limiter with smooth per-second refill.
///
/// Uses a continuous token bucket where tokens are added proportionally to
/// elapsed time, enforcing the `max_requests_per_minute` over a 60-second window.
/// The bucket starts full, so callers get a burst of `max_requests_per_minute`
/// immediately and then refill at a steady rate thereafter.
pub struct RateLimiter {
    buckets: Arc<DashMap<Uuid, TokenBucket>>,
}

struct TokenBucket {
    /// Fractional tokens remaining (f64 for smooth sub-second refill).
    tokens: f64,
    max_tokens: f64,
    last_refill: Instant,
    /// How many tokens accumulate per second.
    tokens_per_second: f64,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            buckets: Arc::new(DashMap::new()),
        }
    }

    /// Returns true if the request is allowed under the rate limit.
    /// `max_requests_per_minute == 0` always denies.
    pub fn allow(&self, id: Uuid, max_requests_per_minute: usize) -> bool {
        if max_requests_per_minute == 0 {
            return false;
        }

        let tokens_per_second = max_requests_per_minute as f64 / 60.0;
        let max = max_requests_per_minute as f64;

        let mut entry = self.buckets.entry(id).or_insert_with(|| TokenBucket {
            tokens: max,
            max_tokens: max,
            last_refill: Instant::now(),
            tokens_per_second,
        });

        let bucket = entry.value_mut();

        // Add tokens proportional to elapsed time (smooth refill).
        let now = Instant::now();
        let elapsed_secs = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens =
            (bucket.tokens + elapsed_secs * bucket.tokens_per_second).min(bucket.max_tokens);
        bucket.last_refill = now;

        // Consume one token if available.
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Remove buckets that have been idle longer than `max_age`.
    /// Call periodically (e.g., via a background task) to prevent memory growth.
    pub fn cleanup(&self, max_age: Duration) {
        let now = Instant::now();
        self.buckets
            .retain(|_, bucket| now.duration_since(bucket.last_refill) < max_age);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let limiter = RateLimiter::new();
        let id = Uuid::new_v4();

        // A fresh bucket starts full, so all 10 requests should succeed.
        for _ in 0..10 {
            assert!(limiter.allow(id, 10));
        }
    }

    #[test]
    fn test_rate_limiter_blocks_when_exceeded() {
        let limiter = RateLimiter::new();
        let id = Uuid::new_v4();

        // Consume all 5 tokens.
        for _ in 0..5 {
            assert!(limiter.allow(id, 5));
        }

        // Next request should be denied.
        assert!(!limiter.allow(id, 5));
    }

    #[test]
    fn test_rate_limiter_refills_over_time() {
        let limiter = RateLimiter::new();
        let id = Uuid::new_v4();

        // Use 600 req/min so 1 token refills every 100ms.
        let limit = 600usize;

        // Consume all tokens.
        for _ in 0..limit {
            limiter.allow(id, limit);
        }

        // Should be denied immediately.
        assert!(!limiter.allow(id, limit));

        // After 110ms, at least 1 token should have refilled (600/min = 10/sec).
        thread::sleep(Duration::from_millis(110));
        assert!(limiter.allow(id, limit));
    }

    #[test]
    fn test_rate_limiter_zero_limit_always_denies() {
        let limiter = RateLimiter::new();
        let id = Uuid::new_v4();
        assert!(!limiter.allow(id, 0));
    }

    #[test]
    fn test_rate_limiter_separate_ids_independent() {
        let limiter = RateLimiter::new();
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();

        // Exhaust id1.
        for _ in 0..3 {
            limiter.allow(id1, 3);
        }
        assert!(!limiter.allow(id1, 3));

        // id2 should still be fresh.
        assert!(limiter.allow(id2, 3));
    }
}
