//! In-memory [`RateLimitStore`] impls for tests.
//!
//! Two shapes:
//!
//! * [`CountingRateLimitStore`] — backs onto a sliding window per
//!   `module_id`, counts every call so tests can assert on dispatch
//!   patterns. The "did the engine consult the rate-limit store?"
//!   companion to [`InMemoryWorkflowGraphStore`](crate::memory::InMemoryWorkflowGraphStore).
//! * [`AlwaysAllowRateLimitStore`] — always returns `1`. Useful when
//!   the test cares about wiring shape, not rate-limit behaviour.
//!
//! Both are `Send + Sync`. Counters are
//! [`std::sync::Mutex`]-protected — fine for the engine's per-node
//! dispatch path; would be cause for refactoring under high
//! contention.
//!
//! [`RateLimitStore`]: talos_workflow_engine_core::RateLimitStore

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use talos_workflow_engine_core::{BoxError, RateLimitStore};
use uuid::Uuid;

/// In-memory [`RateLimitStore`] that tracks per-module counters in a
/// sliding window plus the full call log for test assertions.
///
/// # When to use
///
/// Production deployments wire a Redis-backed `RateLimitStore`; tests
/// don't have one. This impl gives integration tests the same trait
/// boundary the engine talks to in production, without spinning up a
/// shared store.
///
/// The window resets the same way the engine's in-memory default
/// does — `record_and_count(id, window_secs)` either continues the
/// current window for `id` (incrementing by 1) or starts a new
/// window when the previous one expired.
///
/// # Example
///
/// ```
/// use std::sync::Arc;
/// use talos_workflow_engine_test_utils::rate_limit::CountingRateLimitStore;
///
/// # async fn demo() {
/// let store = Arc::new(CountingRateLimitStore::new());
/// // engine.set_rate_limit_store(store.clone());
/// // ... run workflows ...
/// assert_eq!(store.call_count(), 0);
/// # }
/// ```
///
/// [`RateLimitStore`]: talos_workflow_engine_core::RateLimitStore
#[derive(Default)]
pub struct CountingRateLimitStore {
    /// Per-module sliding-window state: (`window_start`, count).
    windows: Mutex<HashMap<Uuid, (Instant, u32)>>,
    /// Every call landed by the engine, in arrival order. Useful for
    /// asserting "exactly N dispatches" or "module X was metered
    /// before module Y".
    calls: Mutex<Vec<Uuid>>,
}

impl CountingRateLimitStore {
    /// Build an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Total `record_and_count` calls landed since construction
    /// (across every module).
    #[must_use]
    pub fn call_count(&self) -> usize {
        self.calls.lock().expect("calls lock").len()
    }

    /// Per-module call count.
    #[must_use]
    pub fn calls_for(&self, module_id: Uuid) -> usize {
        self.calls
            .lock()
            .expect("calls lock")
            .iter()
            .filter(|&&m| m == module_id)
            .count()
    }

    /// Snapshot the entire ordered call log. Owned `Vec` so the
    /// caller can hold it across awaits without holding the mutex.
    #[must_use]
    pub fn calls(&self) -> Vec<Uuid> {
        self.calls.lock().expect("calls lock").clone()
    }

    /// Current count for `module_id` in its active window. Returns
    /// `0` if the module has never been recorded.
    #[must_use]
    pub fn current_count(&self, module_id: Uuid) -> u32 {
        self.windows
            .lock()
            .expect("windows lock")
            .get(&module_id)
            .map_or(0, |(_, c)| *c)
    }
}

impl std::fmt::Debug for CountingRateLimitStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CountingRateLimitStore")
            .field("call_count", &self.call_count())
            .finish()
    }
}

#[async_trait]
impl RateLimitStore for CountingRateLimitStore {
    async fn record_and_count(&self, module_id: Uuid, window_secs: u64) -> Result<u32, BoxError> {
        // Log first so a test can correlate "this call happened" with
        // any rate-limit decision the engine makes from the result.
        self.calls.lock().expect("calls lock").push(module_id);

        let now = Instant::now();
        let mut windows = self.windows.lock().expect("windows lock");
        let entry = windows.entry(module_id).or_insert((now, 0));
        if now.duration_since(entry.0) > Duration::from_secs(window_secs) {
            entry.0 = now;
            entry.1 = 0;
        }
        entry.1 += 1;
        Ok(entry.1)
    }
}

/// [`RateLimitStore`] that always returns `1` — every dispatch is
/// the first in its window. Use when the test cares about wiring
/// shape but not the metering behaviour.
///
/// [`RateLimitStore`]: talos_workflow_engine_core::RateLimitStore
#[derive(Clone, Copy, Debug, Default)]
pub struct AlwaysAllowRateLimitStore;

impl AlwaysAllowRateLimitStore {
    /// Build a new instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl RateLimitStore for AlwaysAllowRateLimitStore {
    async fn record_and_count(&self, _module_id: Uuid, _window_secs: u64) -> Result<u32, BoxError> {
        Ok(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn counting_store_increments_within_window() {
        let store = CountingRateLimitStore::new();
        let m = Uuid::new_v4();
        assert_eq!(store.record_and_count(m, 60).await.unwrap(), 1);
        assert_eq!(store.record_and_count(m, 60).await.unwrap(), 2);
        assert_eq!(store.record_and_count(m, 60).await.unwrap(), 3);
        assert_eq!(store.calls_for(m), 3);
        assert_eq!(store.call_count(), 3);
        assert_eq!(store.current_count(m), 3);
    }

    #[tokio::test]
    async fn counting_store_isolates_per_module() {
        let store = CountingRateLimitStore::new();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        store.record_and_count(a, 60).await.unwrap();
        store.record_and_count(b, 60).await.unwrap();
        store.record_and_count(a, 60).await.unwrap();
        assert_eq!(store.current_count(a), 2);
        assert_eq!(store.current_count(b), 1);
        // Ordered log preserves arrival order — important for tests
        // that assert on the engine's per-dispatch metering sequence.
        assert_eq!(store.calls(), vec![a, b, a]);
    }

    #[tokio::test]
    async fn counting_store_resets_on_zero_window() {
        // window_secs = 0 → every call lands in a fresh window;
        // the count is always 1 because Instant::now() always
        // exceeds the just-stored Instant by some non-zero amount.
        // Confirms the rollover branch fires.
        let store = CountingRateLimitStore::new();
        let m = Uuid::new_v4();
        assert_eq!(store.record_and_count(m, 0).await.unwrap(), 1);
        // Tiny sleep to guarantee `now > stored + 0s`.
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert_eq!(store.record_and_count(m, 0).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn always_allow_store_returns_one() {
        let store = AlwaysAllowRateLimitStore::new();
        let m = Uuid::new_v4();
        for _ in 0..100 {
            assert_eq!(store.record_and_count(m, 60).await.unwrap(), 1);
        }
    }
}
