// MCP-946 (2026-05-15): kept `#![allow(dead_code)]`. The `allow`
// method on `RateLimiter` is currently unused — production flow
// uses `IpRateLimiter` via a different plumbing path. Vestigial,
// tracked for cleanup follow-up.
#![allow(dead_code)]

use dashmap::DashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Read the configured per-user aggregate webhook rate limit (requests per minute).
/// Defaults to 300 rpm; override via `TALOS_WEBHOOK_USER_RPM` environment variable.
/// Call once at application startup and pass the result to `allow_for_trigger` to avoid
/// per-request env-var lookups and to keep the rate limiter itself testable.
pub fn configured_user_webhook_rpm() -> usize {
    std::env::var("TALOS_WEBHOOK_USER_RPM")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300)
}

/// Token bucket rate limiter with smooth per-second refill.
///
/// Uses a continuous token bucket where tokens are added proportionally to
/// elapsed time, enforcing the `max_requests_per_minute` over a 60-second window.
/// The bucket starts full, so callers get a burst of `max_requests_per_minute`
/// immediately and then refill at a steady rate thereafter.
///
/// Two maps are maintained:
///   - `buckets`: per-trigger-id limit (operator-configured, default 60 rpm)
///   - `user_buckets`: per-user aggregate limit (default 300 rpm via `TALOS_WEBHOOK_USER_RPM`)
///
/// A request must pass **both** checks. This prevents a user from registering
/// N triggers and distributing requests to bypass per-trigger limits.
pub struct RateLimiter {
    buckets: Arc<DashMap<Uuid, TokenBucket>>,
    user_buckets: Arc<DashMap<Uuid, TokenBucket>>,
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
            user_buckets: Arc::new(DashMap::new()),
        }
    }

    /// Returns true if the request is allowed under the rate limit.
    /// `max_requests_per_minute == 0` always denies.
    pub fn allow(&self, id: Uuid, max_requests_per_minute: usize) -> bool {
        if max_requests_per_minute == 0 {
            return false;
        }
        Self::consume_token(&self.buckets, id, max_requests_per_minute)
    }

    /// Check both per-trigger and per-user aggregate rate limits.
    ///
    /// Returns `(trigger_ok, user_ok)` so callers can emit distinct log messages.
    /// Both must be true for the request to proceed. The per-trigger bucket is
    /// consumed only when the user aggregate limit is also satisfied — this prevents
    /// the per-trigger limit from being drained when the user is already throttled.
    ///
    /// `user_max_rpm`: read once at startup via `configured_user_webhook_rpm()` and
    /// passed here, keeping this method pure and testable without env-var coupling.
    pub fn allow_for_trigger(
        &self,
        trigger_id: Uuid,
        trigger_max_rpm: usize,
        user_id: Uuid,
        user_max_rpm: usize,
    ) -> (bool, bool) {
        // Check user aggregate first (cheaper — avoids per-trigger bucket churn).
        let user_ok =
            user_max_rpm == 0 || Self::consume_token(&self.user_buckets, user_id, user_max_rpm);
        if !user_ok {
            return (true, false); // Per-trigger not consumed; user throttled.
        }
        let trigger_ok = Self::consume_token(&self.buckets, trigger_id, trigger_max_rpm);
        (trigger_ok, true)
    }

    /// Internal: consume one token from a bucket map entry. Returns true if allowed.
    fn consume_token(map: &DashMap<Uuid, TokenBucket>, id: Uuid, max_rpm: usize) -> bool {
        if max_rpm == 0 {
            return false;
        }
        let tokens_per_second = max_rpm as f64 / 60.0;
        let max = max_rpm as f64;

        let mut entry = map.entry(id).or_insert_with(|| TokenBucket {
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
        self.user_buckets
            .retain(|_, bucket| now.duration_since(bucket.last_refill) < max_age);
    }
}

// ============================================================================
// Circuit Breaker: per-IP auth failure tracking
// ============================================================================
//
// An IP that fails authentication CB_OPEN_THRESHOLD times within
// CB_FAILURE_WINDOW gets blocked for CB_BLOCK_DURATION. This prevents
// brute-force probers from paying repeated HMAC CPU costs and DB round trips.
// Keyed on IpAddr (not trigger ID) so one attacker probing many triggers trips
// the breaker once.

const CB_OPEN_THRESHOLD: u32 = 10;
const CB_BLOCK_DURATION: Duration = Duration::from_secs(60);
const CB_FAILURE_WINDOW: Duration = Duration::from_secs(300);

/// MCP-526: test-only override for CB_BLOCK_DURATION so the unit
/// test for the post-block re-block path doesn't have to wait the
/// full production block duration. Atomically swappable; only used
/// by the regression test below.
#[cfg(test)]
static TEST_BLOCK_DURATION_MS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(60_000);

#[cfg(test)]
fn current_block_duration() -> Duration {
    Duration::from_millis(TEST_BLOCK_DURATION_MS.load(std::sync::atomic::Ordering::Relaxed))
}

#[cfg(not(test))]
fn current_block_duration() -> Duration {
    CB_BLOCK_DURATION
}
/// Types of authentication/authorization failures tracked by the circuit breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitBreakerFailureType {
    RateLimitExceeded,
    InvalidSignature,
    InvalidVerificationToken,
    IpNotAllowed,
    TriggerDisabled,
    TriggerNotFound,
    InternalError,
}

impl fmt::Display for CircuitBreakerFailureType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CircuitBreakerFailureType::RateLimitExceeded => write!(f, "RateLimitExceeded"),
            CircuitBreakerFailureType::InvalidSignature => write!(f, "InvalidSignature"),
            CircuitBreakerFailureType::InvalidVerificationToken => {
                write!(f, "InvalidVerificationToken")
            }
            CircuitBreakerFailureType::IpNotAllowed => write!(f, "IpNotAllowed"),
            CircuitBreakerFailureType::TriggerDisabled => write!(f, "TriggerDisabled"),
            CircuitBreakerFailureType::TriggerNotFound => write!(f, "TriggerNotFound"),
            CircuitBreakerFailureType::InternalError => write!(f, "InternalError"),
        }
    }
}

struct CbRecord {
    consecutive_failures: u32,
    blocked_until: Option<Instant>,
    last_failure: Instant,
}

pub struct CircuitBreaker {
    records: Arc<DashMap<IpAddr, CbRecord>>,
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new()
    }
}

impl CircuitBreaker {
    pub fn new() -> Self {
        Self {
            records: Arc::new(DashMap::new()),
        }
    }

    /// Returns `true` if the IP is currently blocked.
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        self.records
            .get(&ip)
            .and_then(|r| r.blocked_until)
            .map(|until| until > Instant::now())
            .unwrap_or(false)
    }

    /// Record an authentication failure for an IP with specific failure type.
    /// If failures reach the threshold, block the IP.
    /// Returns true if this failure caused the circuit breaker to open.
    pub fn record_failure_with_type(
        &self,
        ip: IpAddr,
        failure_type: CircuitBreakerFailureType,
    ) -> bool {
        let now = Instant::now();
        let mut entry = self.records.entry(ip).or_insert_with(|| CbRecord {
            consecutive_failures: 0,
            blocked_until: None,
            last_failure: now,
        });
        let record = entry.value_mut();

        // Reset counter if the IP has been quiet for the failure window.
        if now.duration_since(record.last_failure) >= CB_FAILURE_WINDOW {
            record.consecutive_failures = 0;
            record.blocked_until = None;
        }

        // MCP-526: clear `blocked_until` once the block has actually
        // expired. Pre-fix the field was set on first threshold-cross
        // and never re-cleared except by the 5-minute quiet-window
        // reset above. Combined with the re-block check
        // (`blocked_until.is_none()`), this meant: once an IP had been
        // blocked once, the breaker became INERT against further
        // failures from that IP. Every failure also updates
        // `last_failure = now`, so the quiet window never elapses for
        // an actively-probing attacker — they get unlimited free
        // failed-auth attempts post-block, the exact threat the
        // breaker exists to throttle. Clearing the marker here means
        // the very next failure after block expiry re-trips the
        // threshold check (the failure counter is already ≥10), so
        // a confirmed attacker is re-blocked every 60s on the next
        // attempt. The 5-min quiet-window reset above still grants
        // a clean slate to genuinely-quiet IPs.
        if let Some(until) = record.blocked_until {
            if until <= now {
                record.blocked_until = None;
            }
        }

        record.consecutive_failures += 1;
        record.last_failure = now;

        let mut opened = false;
        if record.consecutive_failures >= CB_OPEN_THRESHOLD && record.blocked_until.is_none() {
            let block_duration = current_block_duration();
            record.blocked_until = Some(now + block_duration);
            opened = true;
            tracing::warn!(
                ip = %ip,
                failures = record.consecutive_failures,
                failure_type = %failure_type,
                "Circuit breaker opened: IP blocked for {}s",
                block_duration.as_secs()
            );
        } else {
            tracing::debug!(
                ip = %ip,
                failures = record.consecutive_failures,
                failure_type = %failure_type,
                "Circuit breaker recorded failure"
            );
        }
        opened
    }

    /// Record an authentication failure for an IP.
    /// Backwards-compatible wrapper that uses InvalidSignature as the failure type.
    pub fn record_failure(&self, ip: IpAddr) {
        self.record_failure_with_type(ip, CircuitBreakerFailureType::InvalidSignature);
    }

    /// Record a successful authentication for an IP.
    ///
    /// MCP-439: a success does NOT wipe the IP's accumulated failure
    /// history. In a multi-tenant deployment, any attacker who controls
    /// even one valid trigger could otherwise interleave 9 failed probes
    /// against victim triggers with 1 successful call to their own
    /// trigger to reset the counter indefinitely — the
    /// `CB_OPEN_THRESHOLD` (10 failures within 5 min) would never be
    /// reached. Failures now decay only via the 5-minute quiet window
    /// in `record_failure_with_type`, which fires when an IP has no
    /// failures (legitimate or otherwise) for `CB_FAILURE_WINDOW`. A
    /// blocked IP's `blocked_until` is preserved so a race where a
    /// blocked IP somehow gets a success doesn't unblock them early.
    pub fn record_success(&self, _ip: IpAddr) {
        // Intentionally no-op. Failures expire via CB_FAILURE_WINDOW,
        // not via interleaved successes.
    }

    /// Remove stale entries where `last_failure + max_age <= now`.
    /// Call periodically to prevent unbounded memory growth.
    pub fn cleanup(&self, max_age: Duration) {
        let now = Instant::now();
        self.records
            .retain(|_, r| now.duration_since(r.last_failure) < max_age);
    }

    /// Return a snapshot of all currently-blocked IPs for observability.
    /// Each entry is (ip, blocked_until Instant).
    pub fn blocked_ips(&self) -> Vec<(IpAddr, Instant)> {
        let now = Instant::now();
        self.records
            .iter()
            .filter_map(|entry| {
                entry
                    .blocked_until
                    .filter(|&until| until > now)
                    .map(|until| (*entry.key(), until))
            })
            .collect()
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

    #[test]
    fn test_allow_for_trigger_per_trigger_limit() {
        // With a high user RPM (10_000), the per-trigger limit of 3 governs.
        // user_max_rpm is passed directly — no env-var dependency, safe for parallel tests.
        let limiter = RateLimiter::new();
        let trigger_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        // Exhaust the per-trigger bucket (limit = 3).
        for _ in 0..3 {
            let (tok, uok) = limiter.allow_for_trigger(trigger_id, 3, user_id, 10_000);
            assert!(tok && uok);
        }
        // Next request should be denied at the trigger level; user bucket still has tokens.
        let (tok, uok) = limiter.allow_for_trigger(trigger_id, 3, user_id, 10_000);
        assert!(!tok, "trigger bucket should be exhausted");
        assert!(uok, "user bucket should still have tokens");
    }

    #[test]
    fn test_allow_for_trigger_user_aggregate_limit() {
        // User aggregate RPM = 3. Each trigger has a high per-trigger limit (1000).
        // Distributing requests across two triggers must not bypass the user limit.
        let limiter = RateLimiter::new();
        let user_id = Uuid::new_v4();
        let trigger1 = Uuid::new_v4();
        let trigger2 = Uuid::new_v4();

        for i in 0..3_usize {
            let t = if i % 2 == 0 { trigger1 } else { trigger2 };
            let (tok, uok) = limiter.allow_for_trigger(t, 1000, user_id, 3);
            assert!(tok && uok, "Request {i} should be allowed");
        }
        // 4th request should fail at user level regardless of which trigger.
        let (_, uok) = limiter.allow_for_trigger(trigger1, 1000, user_id, 3);
        assert!(!uok, "User aggregate limit should be enforced");
    }

    #[test]
    fn test_allow_for_trigger_different_users_independent() {
        // user1 and user2 each have their own user bucket (user_max_rpm = 2).
        let limiter = RateLimiter::new();
        let trigger = Uuid::new_v4();
        let user1 = Uuid::new_v4();
        let user2 = Uuid::new_v4();

        // Exhaust user1's aggregate bucket.
        limiter.allow_for_trigger(trigger, 1000, user1, 2);
        limiter.allow_for_trigger(trigger, 1000, user1, 2);
        let (_, uok) = limiter.allow_for_trigger(trigger, 1000, user1, 2);
        assert!(!uok, "user1 should be throttled");

        // user2 has a fresh bucket and should be unaffected.
        let (tok, uok) = limiter.allow_for_trigger(Uuid::new_v4(), 1000, user2, 2);
        assert!(tok && uok, "user2 should not be throttled");
    }

    #[test]
    fn test_circuit_breaker_records_different_failure_types() {
        let cb = CircuitBreaker::new();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Record failures of different types - all should count toward threshold
        for _ in 0..5 {
            cb.record_failure_with_type(ip, CircuitBreakerFailureType::TriggerNotFound);
            cb.record_failure_with_type(ip, CircuitBreakerFailureType::InvalidSignature);
        }

        // Should now be blocked
        assert!(cb.is_blocked(ip));
    }

    #[test]
    fn test_circuit_breaker_returns_opened_status() {
        let cb = CircuitBreaker::new();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Record 9 failures - should return false (not opened yet)
        for _ in 0..9 {
            let opened =
                cb.record_failure_with_type(ip, CircuitBreakerFailureType::InvalidSignature);
            assert!(!opened);
        }

        // 10th failure should open the circuit
        let opened = cb.record_failure_with_type(ip, CircuitBreakerFailureType::InvalidSignature);
        assert!(opened);
        assert!(cb.is_blocked(ip));
    }

    #[test]
    fn test_circuit_breaker_success_does_not_wipe_failure_history() {
        // MCP-439: record_success MUST NOT reset consecutive_failures.
        // Otherwise an attacker who controls one valid trigger can
        // interleave 9 failed probes with 1 success to keep the
        // counter below the threshold forever.
        let cb = CircuitBreaker::new();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // 9 failures — one short of the threshold (10).
        for _ in 0..9 {
            cb.record_failure_with_type(ip, CircuitBreakerFailureType::InvalidSignature);
        }
        assert!(!cb.is_blocked(ip), "9 failures should not yet block");

        // A success must NOT wipe the failure history.
        cb.record_success(ip);
        assert!(!cb.is_blocked(ip), "success alone does not block");

        // ONE more failure must trip the breaker — proving the 9 prior
        // failures were preserved across the intervening success.
        let opened = cb.record_failure_with_type(ip, CircuitBreakerFailureType::InvalidSignature);
        assert!(
            opened,
            "10th failure must open the breaker even after a success"
        );
        assert!(cb.is_blocked(ip), "IP must now be blocked");
    }

    #[test]
    fn test_circuit_breaker_reblocks_after_block_expires() {
        // MCP-526: post-block re-block path. Pre-fix the breaker became
        // inert after first block expiry — `blocked_until` stayed Some
        // (in the past), `is_blocked()` returned false, and the
        // re-block check `blocked_until.is_none()` returned false too.
        // Every subsequent failure also updated `last_failure = now`,
        // so the 5-min quiet-window reset never fired for an
        // actively-probing attacker. Net: confirmed attacker got
        // unlimited free failed-auth attempts post-block.
        //
        // Shorten the block duration so the test runs fast. The
        // production CB_BLOCK_DURATION (60s) is what matters in prod;
        // this test only validates the state-machine transition.
        TEST_BLOCK_DURATION_MS.store(50, std::sync::atomic::Ordering::Relaxed);

        let cb = CircuitBreaker::new();
        let ip: IpAddr = "10.0.0.42".parse().unwrap();

        // 10 failures → first block opens.
        for _ in 0..10 {
            cb.record_failure_with_type(ip, CircuitBreakerFailureType::InvalidSignature);
        }
        assert!(cb.is_blocked(ip), "first block must open after 10 failures");

        // Wait for the (shortened) block to expire.
        thread::sleep(Duration::from_millis(80));
        assert!(
            !cb.is_blocked(ip),
            "block must expire after CB_BLOCK_DURATION"
        );

        // The very next failure must re-trip the breaker — pre-fix
        // this stayed silent and the IP kept failing freely.
        let opened = cb.record_failure_with_type(ip, CircuitBreakerFailureType::InvalidSignature);
        assert!(
            opened,
            "the first failure after block expiry must re-open the breaker"
        );
        assert!(
            cb.is_blocked(ip),
            "IP must be blocked again on the post-expiry failure"
        );

        // Restore the production value for any later test in the same process.
        TEST_BLOCK_DURATION_MS.store(60_000, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn test_circuit_breaker_attacker_cannot_bypass_via_interleaved_success() {
        // MCP-439 regression test: simulate an attacker who controls a
        // valid trigger and alternates 1 success + N failures to try
        // to keep the breaker below the threshold. Even with successes
        // interleaved, accumulated failures must cross the threshold.
        let cb = CircuitBreaker::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // 5 cycles of (1 success, 1 failure). 5 failures total.
        for _ in 0..5 {
            cb.record_success(ip);
            cb.record_failure_with_type(ip, CircuitBreakerFailureType::InvalidSignature);
        }
        assert!(!cb.is_blocked(ip), "5 failures < threshold");

        // 5 more cycles. Now 10 failures total.
        for _ in 0..5 {
            cb.record_success(ip);
            cb.record_failure_with_type(ip, CircuitBreakerFailureType::InvalidSignature);
        }
        assert!(
            cb.is_blocked(ip),
            "interleaved successes must NOT save the attacker — \
             10 accumulated failures must still trip the breaker"
        );
    }
}
