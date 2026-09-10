//! Per-USER token bucket for expensive, authenticated operations.
//!
//! The controller's HTTP layer limits by client IP (`middleware`) and the
//! auth endpoints by identifier through Redis (`distributed`). Neither
//! prices an AUTHENTICATED caller's use of an expensive resolver: one
//! session can drive `createWorkflowFromDescription` (an LLM round trip),
//! `testModule` (synchronous WASM, up to 120 s) or `testRhaiExpression` (a
//! 100 KB script evaluated inline) as fast as the per-IP bucket allows,
//! and behind a shared egress IP that bucket is shared with everyone else.
//!
//! This is the same in-memory governor shape as `IpRateLimiter`
//! (`DashMapStateStore`, one bucket per key) keyed on the user's `Uuid`,
//! with the hygiene `IpRateLimiter` gets from the controller's 5-minute
//! sweep loop folded in: the map is swept OPPORTUNISTICALLY from the check
//! path — every `SWEEP_EVERY_CHECKS` checks, and immediately whenever it
//! grows past `max_tracked` — so a `LazyLock` static in a library crate needs
//! no background task and no wiring. `retain_recent` drops every key whose
//! bucket is back at "fresh", i.e. every user quiet for a full window, so the
//! steady-state size is the number of users active in the last minute; the
//! `max_tracked` bound is the ceiling on how many DISTINCT users can be
//! mid-window at once before a sweep is forced (10 000 by default — far
//! above any deployment this repository knows of, and each entry is a few
//! dozen bytes).
//!
//! Not distributed: on a multi-replica controller each replica holds its own
//! buckets, so the effective ceiling is `replicas × per_minute`. Stated
//! rather than hidden; the Redis limiter exists for the case where that
//! matters (auth brute force), and these operations are expensive enough
//! per call that a per-replica bound is still a bound.

use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU64, Ordering};

use governor::clock::{Clock, DefaultClock};
use governor::state::keyed::DashMapStateStore;
use governor::{Quota, RateLimiter};
use uuid::Uuid;

/// Force a `retain_recent` sweep every this many checks, so an idle-user
/// entry never outlives the window by more than a few thousand requests.
const SWEEP_EVERY_CHECKS: u64 = 4096;

/// Default bound on distinct users tracked at once before a sweep is forced.
pub const DEFAULT_MAX_TRACKED_USERS: usize = 10_000;

/// Outcome of a refused check — how long until one token is available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThrottleExceeded {
    /// Seconds (rounded UP, minimum 1) until the caller may retry.
    pub retry_after_secs: u64,
    /// The configured ceiling, for the caller-facing message.
    pub per_minute: u32,
}

/// A per-user token bucket: `per_minute` tokens replenished evenly over a
/// minute, so a caller may burst up to `per_minute` and is then admitted
/// one call per `60 / per_minute` seconds.
pub struct PerUserThrottle {
    limiter: RateLimiter<Uuid, DashMapStateStore<Uuid>, DefaultClock>,
    /// The limiter's own clock, held so `wait_time_from` is measured on the
    /// same instant source (`RateLimiter` exposes no clock accessor in
    /// governor 0.6).
    clock: DefaultClock,
    per_minute: u32,
    max_tracked: usize,
    checks: AtomicU64,
}

impl PerUserThrottle {
    /// `per_minute == 0` is treated as 1 rather than "deny everything": a
    /// zero from a mis-set env var must not take a mutation off the air
    /// (`env_rate_limit` already substitutes the default for `0`, so this is
    /// belt-and-braces).
    pub fn per_minute(per_minute: u32) -> Self {
        Self::with_max_tracked(per_minute, DEFAULT_MAX_TRACKED_USERS)
    }

    pub fn with_max_tracked(per_minute: u32, max_tracked: usize) -> Self {
        let n = NonZeroU32::new(per_minute).unwrap_or(NonZeroU32::MIN);
        let clock = DefaultClock::default();
        Self {
            limiter: RateLimiter::dashmap_with_clock(Quota::per_minute(n), &clock),
            clock,
            per_minute: n.get(),
            max_tracked: max_tracked.max(1),
            checks: AtomicU64::new(0),
        }
    }

    /// Admit one call for `user`, or say how long until one would be admitted.
    pub fn check(&self, user: Uuid) -> Result<(), ThrottleExceeded> {
        self.maybe_sweep();
        match self.limiter.check_key(&user) {
            Ok(()) => Ok(()),
            Err(not_until) => {
                let wait = not_until.wait_time_from(self.clock.now());
                // Round UP so a caller who waits exactly this long is admitted.
                let secs = wait.as_secs() + u64::from(wait.subsec_nanos() > 0);
                Err(ThrottleExceeded {
                    retry_after_secs: secs.max(1),
                    per_minute: self.per_minute,
                })
            }
        }
    }

    /// The configured ceiling.
    pub fn per_minute_limit(&self) -> u32 {
        self.per_minute
    }

    /// Distinct users currently holding a bucket (test/metrics accessor).
    pub fn tracked_users(&self) -> usize {
        self.limiter.len()
    }

    /// Drop every bucket that is back at full capacity and reclaim map
    /// capacity. Called opportunistically by `check`; exposed so a sweep
    /// loop may also call it.
    pub fn sweep(&self) {
        self.limiter.retain_recent();
        self.limiter.shrink_to_fit();
    }

    fn maybe_sweep(&self) {
        let n = self.checks.fetch_add(1, Ordering::Relaxed) + 1;
        if n.is_multiple_of(SWEEP_EVERY_CHECKS) || self.limiter.len() > self.max_tracked {
            self.sweep();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_then_refuse_then_other_user_unaffected() {
        let t = PerUserThrottle::per_minute(2);
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        assert!(t.check(a).is_ok());
        assert!(t.check(a).is_ok());
        let refused = t
            .check(a)
            .expect_err("third call in the same minute is refused");
        assert_eq!(refused.per_minute, 2);
        assert!(
            (1..=30).contains(&refused.retry_after_secs),
            "one token replenishes every 30 s at 2/min, got {}",
            refused.retry_after_secs
        );
        // Buckets are PER USER.
        assert!(t.check(b).is_ok());
        assert_eq!(t.tracked_users(), 2);
    }

    #[test]
    fn zero_means_one_not_deny_all() {
        let t = PerUserThrottle::per_minute(0);
        assert_eq!(t.per_minute_limit(), 1);
        let u = Uuid::new_v4();
        assert!(t.check(u).is_ok());
        assert!(t.check(u).is_err());
    }

    /// The map is bounded from the check path: once more than `max_tracked`
    /// users hold a bucket the next check sweeps. With a generous quota every
    /// one-shot user is back at "fresh" immediately, so the sweep removes
    /// them and the map does not grow with distinct-users-ever-seen.
    #[test]
    fn map_is_bounded_by_opportunistic_sweep() {
        let t = PerUserThrottle::with_max_tracked(1_000_000, 8);
        for _ in 0..8 {
            assert!(t.check(Uuid::new_v4()).is_ok());
        }
        assert_eq!(t.tracked_users(), 8);
        // The ninth check sees len (8) == max_tracked, not > — admitted and
        // tracked; the tenth sees 9 > 8 and sweeps before checking.
        assert!(t.check(Uuid::new_v4()).is_ok());
        assert_eq!(t.tracked_users(), 9);
        // `retain_recent` keeps a key whose theoretical arrival time is still
        // in the FUTURE — at 10^6/min that is 60 µs after its last check, and
        // the loop above runs faster than that. Let every bucket age past it.
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(t.check(Uuid::new_v4()).is_ok());
        assert!(
            t.tracked_users() <= 2,
            "sweep must have evicted the fresh buckets, got {}",
            t.tracked_users()
        );
    }

    /// A user who is still mid-window SURVIVES the sweep — bounding the map
    /// must not reset anyone's bucket.
    #[test]
    fn sweep_keeps_active_buckets() {
        let t = PerUserThrottle::per_minute(1);
        let busy = Uuid::new_v4();
        assert!(t.check(busy).is_ok());
        t.sweep();
        assert!(t.check(busy).is_err(), "bucket must survive the sweep");
    }
}
