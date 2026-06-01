//! M-2 (2026-05-22): per-user daily Tier-2 `expose_secret` fallback
//! counter for when Redis is unavailable.
//!
//! Pre-fix the worker used a single process-wide `Arc<AtomicU64>` as
//! the in-memory fallback. Under Redis outage in a multi-tenant
//! deployment that meant the FIRST user to hit the fallback counter
//! could exhaust the cap, blocking every other user on the same
//! worker pod until the process restarted (the counter never
//! reset in memory — only Redis resets daily).
//!
//! This module gives each user their own (date, counter) pair, so a
//! tenant exhausting the cap doesn't deny service to siblings, AND
//! the counter resets at the day-rollover automatically. Lock-free
//! on the hot path: read-only DashMap lookup + `fetch_add` on the
//! counter cell. The map is bounded by distinct-users-ever-seen
//! during a Redis outage — small in practice; periodic prune of
//! stale-date entries keeps it tight.
//!
//! Fail-closed by design: when Redis is down OR unconfigured AND
//! the per-user counter exceeds the daily cap, `expose_secret`
//! returns `Ratelimited` — never silently bypasses.

use chrono::NaiveDate;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use uuid::Uuid;

/// Per-user fallback counter for the Tier-2 `expose_secret` daily cap.
///
/// Shared across all executions in a worker process via `Arc<ExposeFallback>`;
/// clone the Arc to hand it to a new `TalosContext`.
#[derive(Debug, Default)]
pub struct ExposeFallback {
    inner: DashMap<Uuid, UserSlot>,
}

#[derive(Debug)]
struct UserSlot {
    date: NaiveDate,
    count: AtomicU64,
}

/// Verdict returned by [`ExposeFallback::check_and_increment`].
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum FallbackVerdict {
    /// Within the daily cap. Carries the post-increment count for logging.
    Allowed { count: u64 },
    /// Cap exceeded for `(user_id, today)`. Carries the count for logging.
    Denied { count: u64 },
}

impl ExposeFallback {
    /// Construct an empty fallback table. The first
    /// `check_and_increment(user, today, cap)` call lazily allocates
    /// the per-user slot.
    pub fn new() -> Self {
        Self::default()
    }

    /// Atomically check the per-user daily cap and increment the
    /// counter for `(user_id, today)`. Resets the counter (in-place,
    /// O(1)) when the stored date doesn't match `today`.
    ///
    /// `cap` is the daily limit; pass [`MAX_TIER2_EXPOSES_PER_USER_PER_DAY`]
    /// from the host-fn caller. Comparing `count < cap` after the
    /// increment matches the documented "100 calls per user per day"
    /// semantics — count == cap means we just hit the cap on this call.
    ///
    /// **Concurrency:** lock-free on the hot path. The DashMap's
    /// `entry()` API serializes writers to the same shard, so the
    /// "is the date today? if not, reset" check is atomic against
    /// other writers to the same `user_id`. Reads for OTHER users
    /// proceed in parallel.
    pub fn check_and_increment(
        &self,
        user_id: Uuid,
        today: NaiveDate,
        cap: u64,
    ) -> FallbackVerdict {
        // Common case: slot already exists for today. One read-only
        // DashMap probe + one atomic increment, no allocation.
        if let Some(slot) = self.inner.get(&user_id) {
            if slot.date == today {
                let after = slot.count.fetch_add(1, Ordering::Relaxed) + 1;
                return if after <= cap {
                    FallbackVerdict::Allowed { count: after }
                } else {
                    FallbackVerdict::Denied { count: after }
                };
            }
            // Stale date — fall through to the date-rollover path.
        }
        // Cold path: slot is missing or stale. Use entry() to serialize
        // concurrent date-rollovers — the second writer sees the slot
        // already reset to today and just increments.
        let mut entry = self.inner.entry(user_id).or_insert_with(|| UserSlot {
            date: today,
            count: AtomicU64::new(0),
        });
        if entry.date != today {
            entry.date = today;
            entry.count.store(0, Ordering::Relaxed);
        }
        let after = entry.count.fetch_add(1, Ordering::Relaxed) + 1;
        if after <= cap {
            FallbackVerdict::Allowed { count: after }
        } else {
            FallbackVerdict::Denied { count: after }
        }
    }

    /// Drop entries whose `date` is older than `today`. Cheap O(N)
    /// pass; intended for a low-frequency background sweep (once per
    /// hour is plenty). Not called on the hot path.
    pub fn prune_stale(&self, today: NaiveDate) {
        self.inner.retain(|_, slot| slot.date >= today);
    }

    /// Distinct-user count in the table. Test/observability aid.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// `true` when no user has hit the fallback path yet.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ymd(y: i32, m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, d).unwrap()
    }

    #[test]
    fn first_call_is_allowed_with_count_1() {
        let f = ExposeFallback::new();
        let v = f.check_and_increment(Uuid::nil(), ymd(2026, 5, 22), 5);
        assert_eq!(v, FallbackVerdict::Allowed { count: 1 });
    }

    #[test]
    fn cap_at_boundary_is_allowed_then_denied() {
        let f = ExposeFallback::new();
        let u = Uuid::nil();
        let d = ymd(2026, 5, 22);
        for expected in 1..=5 {
            assert_eq!(
                f.check_and_increment(u, d, 5),
                FallbackVerdict::Allowed { count: expected }
            );
        }
        // 6th call — over cap.
        assert_eq!(
            f.check_and_increment(u, d, 5),
            FallbackVerdict::Denied { count: 6 }
        );
    }

    #[test]
    fn other_user_is_independent() {
        let f = ExposeFallback::new();
        let a = Uuid::from_u128(1);
        let b = Uuid::from_u128(2);
        let d = ymd(2026, 5, 22);

        // User A exhausts their cap.
        for _ in 0..5 {
            assert!(matches!(
                f.check_and_increment(a, d, 5),
                FallbackVerdict::Allowed { .. }
            ));
        }
        assert!(matches!(
            f.check_and_increment(a, d, 5),
            FallbackVerdict::Denied { .. }
        ));

        // User B starts fresh — the regression we're fixing in M-2.
        assert_eq!(
            f.check_and_increment(b, d, 5),
            FallbackVerdict::Allowed { count: 1 }
        );
    }

    #[test]
    fn day_rollover_resets_counter() {
        let f = ExposeFallback::new();
        let u = Uuid::nil();
        let d1 = ymd(2026, 5, 22);
        let d2 = ymd(2026, 5, 23);

        for _ in 0..5 {
            f.check_and_increment(u, d1, 5);
        }
        // Exhausted on d1.
        assert!(matches!(
            f.check_and_increment(u, d1, 5),
            FallbackVerdict::Denied { .. }
        ));
        // New day — counter resets.
        assert_eq!(
            f.check_and_increment(u, d2, 5),
            FallbackVerdict::Allowed { count: 1 }
        );
    }

    #[test]
    fn prune_drops_stale_entries() {
        let f = ExposeFallback::new();
        let u1 = Uuid::from_u128(1);
        let u2 = Uuid::from_u128(2);
        let yesterday = ymd(2026, 5, 21);
        let today = ymd(2026, 5, 22);
        f.check_and_increment(u1, yesterday, 5);
        f.check_and_increment(u2, today, 5);
        assert_eq!(f.len(), 2);
        f.prune_stale(today);
        assert_eq!(f.len(), 1);
        // u2's slot survived.
        assert!(f.inner.contains_key(&u2));
        assert!(!f.inner.contains_key(&u1));
    }

    #[test]
    fn concurrent_increments_count_correctly() {
        use std::sync::Arc;
        use std::thread;

        let f = Arc::new(ExposeFallback::new());
        let u = Uuid::nil();
        let d = ymd(2026, 5, 22);
        // 100 threads × 10 increments = 1000 increments. With cap=10_000
        // every call is Allowed; the final count must be exactly 1000.
        let mut handles = Vec::new();
        for _ in 0..100 {
            let f = Arc::clone(&f);
            handles.push(thread::spawn(move || {
                for _ in 0..10 {
                    f.check_and_increment(u, d, 10_000);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // Read the counter directly via one more increment.
        let v = f.check_and_increment(u, d, 10_000);
        assert_eq!(v, FallbackVerdict::Allowed { count: 1001 });
    }
}
