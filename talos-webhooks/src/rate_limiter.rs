use dashmap::DashMap;
use std::fmt;
use std::net::{IpAddr, Ipv6Addr};
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
// Circuit Breaker: auth-failure tracking keyed per (source, trigger)
// ============================================================================
//
// A source that fails authentication against ONE trigger CB_OPEN_THRESHOLD
// times within CB_FAILURE_WINDOW is blocked for CB_BLOCK_DURATION — for THAT
// trigger only. GitHub / Slack deliver every tenant's webhooks from shared IP
// ranges, so a breaker keyed on the IP alone let one tenant's stale signing
// secret block every other tenant behind that IP. The only IP-wide signal is
// the pre-lookup one: a source naming CB_IP_WIDE_DISTINCT_UNKNOWN distinct
// trigger ids that do not exist is enumerating, and is blocked for every
// trigger. It counts DISTINCT ids, so a sender still posting to one deleted
// trigger can never trip it.
//
// Sources are keyed on the IPv4 address, or the IPv6 /64 (one subscriber's
// allocation — per-address keying is free to rotate around).

const CB_OPEN_THRESHOLD: u32 = 10;
const CB_IP_WIDE_DISTINCT_UNKNOWN: usize = 20;
#[cfg_attr(test, allow(dead_code))] // tests swap in `TEST_BLOCK_DURATION_MS`
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
/// Types of failures a webhook request can end in. Only the failures that
/// say something about the SENDER count — see
/// [`CircuitBreakerFailureType::breaker_scope`].
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

/// Which breaker record a counted failure lands in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BreakerScope {
    /// A credential failure against one trigger: blocks that trigger only.
    Trigger(Uuid),
    /// Unknown trigger ids (pre-lookup): blocks the source for every trigger.
    SourceWide,
}

impl CircuitBreakerFailureType {
    /// Where (if anywhere) this failure is counted for `trigger_id`.
    ///
    /// F3: a failure about the TRIGGER's state (disabled, its per-trigger rate
    /// limit, an internal error on our side) says nothing about the sender and
    /// is never counted. A wrong signature / verification token / source IP is
    /// evidence about the sender — but only for the trigger it failed against.
    /// An unknown trigger id is the pre-lookup probe signal, counted source-wide
    /// by DISTINCT id.
    pub fn breaker_scope(self, trigger_id: Uuid) -> Option<BreakerScope> {
        match self {
            CircuitBreakerFailureType::InvalidSignature
            | CircuitBreakerFailureType::InvalidVerificationToken
            | CircuitBreakerFailureType::IpNotAllowed => Some(BreakerScope::Trigger(trigger_id)),
            CircuitBreakerFailureType::TriggerNotFound => Some(BreakerScope::SourceWide),
            CircuitBreakerFailureType::RateLimitExceeded
            | CircuitBreakerFailureType::TriggerDisabled
            | CircuitBreakerFailureType::InternalError => None,
        }
    }
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

/// The source key: an IPv4 address (IPv4-mapped IPv6 unwrapped), or an IPv6
/// address truncated to its /64.
#[must_use]
pub fn breaker_source(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(Ipv6Addr::from(
                u128::from(v6) & 0xffff_ffff_ffff_ffff_0000_0000_0000_0000,
            )),
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct BreakerKey {
    source: IpAddr,
    scope: BreakerScope,
}

struct CbRecord {
    consecutive_failures: u32,
    /// Distinct unknown trigger ids (source-wide scope only), capped.
    unknown_ids: Vec<Uuid>,
    blocked_until: Option<Instant>,
    last_failure: Instant,
}

pub struct CircuitBreaker {
    records: Arc<DashMap<BreakerKey, CbRecord>>,
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

    fn scope_blocked(&self, source: IpAddr, scope: BreakerScope, now: Instant) -> bool {
        self.records
            .get(&BreakerKey { source, scope })
            .and_then(|r| r.blocked_until)
            .is_some_and(|until| until > now)
    }

    /// Is a request from `ip` to `trigger_id` blocked — by that trigger's own
    /// record or by the source-wide one? Runs before any DB work (the trigger
    /// id comes from the path).
    pub fn is_blocked(&self, ip: IpAddr, trigger_id: Uuid) -> bool {
        let source = breaker_source(ip);
        let now = Instant::now();
        self.scope_blocked(source, BreakerScope::SourceWide, now)
            || self.scope_blocked(source, BreakerScope::Trigger(trigger_id), now)
    }

    /// Record a failure of `failure_type` from `ip` against `trigger_id`.
    /// Returns true if this failure opened (or re-opened) a block.
    ///
    /// The ONE chokepoint for F3: failure types with no
    /// [`CircuitBreakerFailureType::breaker_scope`] are ignored here.
    pub fn record_failure_with_type(
        &self,
        ip: IpAddr,
        trigger_id: Uuid,
        failure_type: CircuitBreakerFailureType,
    ) -> bool {
        let Some(scope) = failure_type.breaker_scope(trigger_id) else {
            tracing::debug!(
                ip = %ip,
                failure_type = %failure_type,
                "Circuit breaker: trigger-state failure not counted (shared sender IPs)"
            );
            return false;
        };
        let source = breaker_source(ip);
        let now = Instant::now();
        let mut entry = self
            .records
            .entry(BreakerKey { source, scope })
            .or_insert_with(|| CbRecord {
                consecutive_failures: 0,
                unknown_ids: Vec::new(),
                blocked_until: None,
                last_failure: now,
            });
        let record = entry.value_mut();

        // Reset counter if the source has been quiet for the failure window.
        if now.duration_since(record.last_failure) >= CB_FAILURE_WINDOW {
            record.consecutive_failures = 0;
            record.unknown_ids.clear();
            record.blocked_until = None;
        }

        // MCP-526: clear an EXPIRED block so the next failure re-trips the
        // threshold check. Every failure updates `last_failure`, so the quiet
        // window above never elapses for an actively-probing source — without
        // this the breaker went inert after its first block.
        if let Some(until) = record.blocked_until {
            if until <= now {
                record.blocked_until = None;
            }
        }

        record.last_failure = now;
        let tripped = match scope {
            BreakerScope::Trigger(_) => {
                record.consecutive_failures += 1;
                record.consecutive_failures >= CB_OPEN_THRESHOLD
            }
            BreakerScope::SourceWide => {
                if record.unknown_ids.len() < CB_IP_WIDE_DISTINCT_UNKNOWN
                    && !record.unknown_ids.contains(&trigger_id)
                {
                    record.unknown_ids.push(trigger_id);
                }
                record.unknown_ids.len() >= CB_IP_WIDE_DISTINCT_UNKNOWN
            }
        };

        let mut opened = false;
        if tripped && record.blocked_until.is_none() {
            let block_duration = current_block_duration();
            record.blocked_until = Some(now + block_duration);
            opened = true;
            tracing::warn!(
                source = %source,
                scope = ?scope,
                failure_type = %failure_type,
                "Circuit breaker opened for {}s",
                block_duration.as_secs()
            );
        } else {
            tracing::debug!(
                source = %source,
                scope = ?scope,
                failures = record.consecutive_failures,
                failure_type = %failure_type,
                "Circuit breaker recorded failure"
            );
        }
        opened
    }

    /// Record a successful authentication for an IP.
    ///
    /// MCP-439: a success does NOT wipe accumulated failure history — an
    /// attacker holding one valid trigger could otherwise interleave successes
    /// with failed probes to keep the counter below the threshold forever.
    /// Failures decay only via the `CB_FAILURE_WINDOW` quiet window.
    pub fn record_success(&self, _ip: IpAddr) {
        // Intentionally no-op.
    }

    /// Operator reset: forget every record for `ip`'s source (all scopes),
    /// unblocking it. Returns how many records were removed.
    pub fn reset_source(&self, ip: IpAddr) -> usize {
        let source = breaker_source(ip);
        let before = self.records.len();
        self.records.retain(|k, _| k.source != source);
        before.saturating_sub(self.records.len())
    }

    /// Remove stale entries where `last_failure + max_age <= now`.
    /// Call periodically to prevent unbounded memory growth.
    pub fn cleanup(&self, max_age: Duration) {
        let now = Instant::now();
        self.records
            .retain(|_, r| now.duration_since(r.last_failure) < max_age);
    }

    /// Currently-blocked sources for observability, one entry per source
    /// (the latest `blocked_until` across its scopes). A source blocked for a
    /// single trigger is listed too — the entry does not say which trigger.
    pub fn blocked_ips(&self) -> Vec<(IpAddr, Instant)> {
        let now = Instant::now();
        let mut by_source: std::collections::HashMap<IpAddr, Instant> =
            std::collections::HashMap::new();
        for entry in self.records.iter() {
            if let Some(until) = entry.blocked_until.filter(|&until| until > now) {
                let slot = by_source.entry(entry.key().source).or_insert(until);
                if until > *slot {
                    *slot = until;
                }
            }
        }
        by_source.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    const T: Uuid = Uuid::from_u128(0x7);

    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let limiter = RateLimiter::new();
        let id = Uuid::new_v4();

        // A fresh bucket starts full, so all 10 requests should succeed.
        for _ in 0..10 {
            assert!(limiter.allow_for_trigger(id, 10, Uuid::nil(), 0).0);
        }
    }

    #[test]
    fn test_rate_limiter_blocks_when_exceeded() {
        let limiter = RateLimiter::new();
        let id = Uuid::new_v4();

        // Consume all 5 tokens.
        for _ in 0..5 {
            assert!(limiter.allow_for_trigger(id, 5, Uuid::nil(), 0).0);
        }

        // Next request should be denied.
        assert!(!limiter.allow_for_trigger(id, 5, Uuid::nil(), 0).0);
    }

    #[test]
    fn test_rate_limiter_refills_over_time() {
        let limiter = RateLimiter::new();
        let id = Uuid::new_v4();

        // Use 600 req/min so 1 token refills every 100ms.
        let limit = 600usize;

        // Consume all tokens.
        for _ in 0..limit {
            limiter.allow_for_trigger(id, limit, Uuid::nil(), 0);
        }

        // Should be denied immediately.
        assert!(!limiter.allow_for_trigger(id, limit, Uuid::nil(), 0).0);

        // After 110ms, at least 1 token should have refilled (600/min = 10/sec).
        thread::sleep(Duration::from_millis(110));
        assert!(limiter.allow_for_trigger(id, limit, Uuid::nil(), 0).0);
    }

    #[test]
    fn test_rate_limiter_zero_limit_always_denies() {
        let limiter = RateLimiter::new();
        let id = Uuid::new_v4();
        assert!(!limiter.allow_for_trigger(id, 0, Uuid::nil(), 0).0);
    }

    #[test]
    fn test_rate_limiter_separate_ids_independent() {
        let limiter = RateLimiter::new();
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();

        // Exhaust id1.
        for _ in 0..3 {
            limiter.allow_for_trigger(id1, 3, Uuid::nil(), 0);
        }
        assert!(!limiter.allow_for_trigger(id1, 3, Uuid::nil(), 0).0);

        // id2 should still be fresh.
        assert!(limiter.allow_for_trigger(id2, 3, Uuid::nil(), 0).0);
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
    fn test_circuit_breaker_counts_only_auth_failures() {
        // F3: trigger-state failures (disabled / rate-limited / internal) are
        // NOT evidence about the sender and must not move the breaker.
        let cb = CircuitBreaker::new();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        for _ in 0..5 {
            assert!(!cb.record_failure_with_type(
                ip,
                T,
                CircuitBreakerFailureType::TriggerDisabled
            ));
            assert!(!cb.record_failure_with_type(
                ip,
                T,
                CircuitBreakerFailureType::RateLimitExceeded
            ));
            assert!(!cb.record_failure_with_type(ip, T, CircuitBreakerFailureType::InternalError));
            cb.record_failure_with_type(ip, T, CircuitBreakerFailureType::InvalidSignature);
        }
        assert!(!cb.is_blocked(ip, T));

        for _ in 0..3 {
            cb.record_failure_with_type(ip, T, CircuitBreakerFailureType::InvalidVerificationToken);
        }
        for _ in 0..2 {
            cb.record_failure_with_type(ip, T, CircuitBreakerFailureType::IpNotAllowed);
        }
        assert!(cb.is_blocked(ip, T));
    }

    #[test]
    fn breaker_scopes_partition_the_failure_types() {
        use CircuitBreakerFailureType::*;
        for t in [InvalidSignature, InvalidVerificationToken, IpNotAllowed] {
            assert_eq!(t.breaker_scope(T), Some(BreakerScope::Trigger(T)), "{t}");
        }
        assert_eq!(
            TriggerNotFound.breaker_scope(T),
            Some(BreakerScope::SourceWide)
        );
        for t in [RateLimitExceeded, TriggerDisabled, InternalError] {
            assert_eq!(t.breaker_scope(T), None, "{t} is a trigger-state failure");
        }
    }

    /// One tenant's stale secret, delivered from a shared sender IP, blocks
    /// that tenant's trigger only — every other trigger behind the IP flows.
    #[test]
    fn a_failing_trigger_does_not_block_other_triggers_behind_the_same_ip() {
        let cb = CircuitBreaker::new();
        let ip: IpAddr = "140.82.112.1".parse().unwrap();
        let other = Uuid::from_u128(0x8);
        for _ in 0..CB_OPEN_THRESHOLD {
            cb.record_failure_with_type(ip, T, CircuitBreakerFailureType::InvalidSignature);
        }
        assert!(cb.is_blocked(ip, T));
        assert!(!cb.is_blocked(ip, other));
    }

    /// A sender still posting to ONE deleted trigger never trips the
    /// source-wide block; a source naming many distinct unknown ids does.
    #[test]
    fn source_wide_block_counts_distinct_unknown_trigger_ids() {
        let cb = CircuitBreaker::new();
        let ip: IpAddr = "140.82.112.2".parse().unwrap();
        let deleted = Uuid::from_u128(0x9);
        for _ in 0..100 {
            cb.record_failure_with_type(ip, deleted, CircuitBreakerFailureType::TriggerNotFound);
        }
        assert!(!cb.is_blocked(ip, T));

        let mut opened = false;
        for i in 0..CB_IP_WIDE_DISTINCT_UNKNOWN as u128 {
            opened |= cb.record_failure_with_type(
                ip,
                Uuid::from_u128(0x1000 + i),
                CircuitBreakerFailureType::TriggerNotFound,
            );
        }
        assert!(opened);
        assert!(
            cb.is_blocked(ip, T),
            "source-wide block covers every trigger"
        );
    }

    #[test]
    fn ipv6_sources_are_keyed_on_their_64() {
        let cb = CircuitBreaker::new();
        for i in 0..CB_OPEN_THRESHOLD {
            let ip: IpAddr = format!("2001:db8:1:2::{:x}", i + 1).parse().unwrap();
            cb.record_failure_with_type(ip, T, CircuitBreakerFailureType::InvalidSignature);
        }
        assert!(cb.is_blocked("2001:db8:1:2:ffff::1".parse().unwrap(), T));
        assert!(!cb.is_blocked("2001:db8:1:3::1".parse().unwrap(), T));
        assert_eq!(
            breaker_source("::ffff:10.1.2.3".parse().unwrap()),
            "10.1.2.3".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn reset_source_clears_every_scope() {
        let cb = CircuitBreaker::new();
        let ip: IpAddr = "140.82.112.3".parse().unwrap();
        for _ in 0..CB_OPEN_THRESHOLD {
            cb.record_failure_with_type(ip, T, CircuitBreakerFailureType::InvalidSignature);
        }
        assert!(cb.is_blocked(ip, T));
        assert_eq!(cb.blocked_ips().len(), 1);
        assert_eq!(cb.reset_source(ip), 1);
        assert!(!cb.is_blocked(ip, T));
    }

    #[test]
    fn test_circuit_breaker_returns_opened_status() {
        let cb = CircuitBreaker::new();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Record 9 failures - should return false (not opened yet)
        for _ in 0..9 {
            let opened =
                cb.record_failure_with_type(ip, T, CircuitBreakerFailureType::InvalidSignature);
            assert!(!opened);
        }

        // 10th failure should open the circuit
        let opened =
            cb.record_failure_with_type(ip, T, CircuitBreakerFailureType::InvalidSignature);
        assert!(opened);
        assert!(cb.is_blocked(ip, T));
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
            cb.record_failure_with_type(ip, T, CircuitBreakerFailureType::InvalidSignature);
        }
        assert!(!cb.is_blocked(ip, T), "9 failures should not yet block");

        // A success must NOT wipe the failure history.
        cb.record_success(ip);
        assert!(!cb.is_blocked(ip, T), "success alone does not block");

        // ONE more failure must trip the breaker — proving the 9 prior
        // failures were preserved across the intervening success.
        let opened =
            cb.record_failure_with_type(ip, T, CircuitBreakerFailureType::InvalidSignature);
        assert!(
            opened,
            "10th failure must open the breaker even after a success"
        );
        assert!(cb.is_blocked(ip, T), "IP must now be blocked");
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
            cb.record_failure_with_type(ip, T, CircuitBreakerFailureType::InvalidSignature);
        }
        assert!(
            cb.is_blocked(ip, T),
            "first block must open after 10 failures"
        );

        // Wait for the (shortened) block to expire.
        thread::sleep(Duration::from_millis(80));
        assert!(
            !cb.is_blocked(ip, T),
            "block must expire after CB_BLOCK_DURATION"
        );

        // The very next failure must re-trip the breaker — pre-fix
        // this stayed silent and the IP kept failing freely.
        let opened =
            cb.record_failure_with_type(ip, T, CircuitBreakerFailureType::InvalidSignature);
        assert!(
            opened,
            "the first failure after block expiry must re-open the breaker"
        );
        assert!(
            cb.is_blocked(ip, T),
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
            cb.record_failure_with_type(ip, T, CircuitBreakerFailureType::InvalidSignature);
        }
        assert!(!cb.is_blocked(ip, T), "5 failures < threshold");

        // 5 more cycles. Now 10 failures total.
        for _ in 0..5 {
            cb.record_success(ip);
            cb.record_failure_with_type(ip, T, CircuitBreakerFailureType::InvalidSignature);
        }
        assert!(
            cb.is_blocked(ip, T),
            "interleaved successes must NOT save the attacker — \
             10 accumulated failures must still trip the breaker"
        );
    }
}
