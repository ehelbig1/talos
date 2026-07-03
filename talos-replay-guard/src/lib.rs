//! Distributed replay-nonce guard (codebase-review finding #2).
//!
//! The signed-NATS layers (`talos_workflow_job_protocol`,
//! `talos_memory::rpc_auth`) each enforce single-use of a nonce with a
//! **process-local** cache. That is sufficient on a single controller, but the
//! platform runs the controller horizontally scaled: an attacker who captures a
//! signed message can replay it to a *different* replica within the freshness
//! window and the per-process cache never sees it. HMAC + freshness still hold,
//! so the property degrades from "single-use" to "freshness-window-bounded
//! replay across the fleet".
//!
//! This crate closes that gap with a shared, atomic single-use store — an
//! **additive layer** consulted *after* the existing sync HMAC + freshness +
//! process-local checks pass. It changes nothing until an operator registers a
//! guard at boot ([`register_shared_replay_guard`]); with none registered,
//! [`shared_replay_guard`] returns `None` and the caller's behaviour is
//! byte-identical to today.
//!
//! ## Design notes
//!
//! - The check is **async** and lives at the async NATS-subscriber boundary, so
//!   the sync verify core (`SignedMessage::verify_core`) is untouched — no
//!   blocking Redis call on the executor, no signature churn through the
//!   `SignedMessage` trait.
//! - [`ReplayOutcome::Unavailable`] is returned on backend error; the caller
//!   decides fail-open vs. fail-closed. Fail-open is the safe default because
//!   the process-local cache already caught within-replica replays and HMAC +
//!   freshness still gate forgery and stale-replay — a Redis blip degrades to
//!   the pre-existing behaviour, it does not open a forgery hole.
//! - Keys must be namespaced by the caller (subject / message-type + identity +
//!   nonce) so a memory-RPC nonce can't collide with a job-result nonce.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Result of an atomic check-and-record against the shared store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayOutcome {
    /// First sighting of this key within its TTL — recorded. Admit the message.
    Fresh,
    /// The key was already recorded within its TTL — this is a replay. Reject.
    Replay,
    /// The backend could not be reached / errored. The caller applies its fail
    /// policy (see [`fail_closed_from_env`]).
    Unavailable,
}

/// A shared, atomic single-use store for nonces across controller replicas.
#[async_trait]
pub trait ReplayGuard: Send + Sync {
    /// Atomically record `key` with a `ttl_secs` expiry.
    ///
    /// Returns [`ReplayOutcome::Fresh`] on the first sighting (and records it),
    /// [`ReplayOutcome::Replay`] if `key` was already recorded and unexpired,
    /// and [`ReplayOutcome::Unavailable`] on backend error.
    ///
    /// `ttl_secs` MUST be `>=` the verifier's freshness window so a still-fresh
    /// message can never have had its key evicted (the same lifetime-≥-window
    /// invariant the process-local caches maintain).
    async fn check_and_record(&self, key: &str, ttl_secs: u64) -> ReplayOutcome;

    /// Short label for logs/metrics.
    fn name(&self) -> &'static str {
        "replay-guard"
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Hard cap for the process-local guard's map, matching the sync caches.
const PROCESS_LOCAL_HARD_CAP: usize = 200_000;

/// In-process [`ReplayGuard`] backed by a `Mutex<HashMap>` with TTL eviction.
///
/// This is the trait's reference implementation and a drop-in for tests and
/// single-replica deploys. It does NOT provide cross-replica protection — for
/// that, register a [`RedisReplayGuard`]. Semantics mirror the existing
/// `JobNonceCache` (sweep-on-insert past `2×ttl`, hard-cap aggressive sweep).
#[derive(Default)]
pub struct ProcessLocalReplayGuard {
    /// key -> unix-secs expiry.
    seen: Mutex<HashMap<String, u64>>,
}

impl ProcessLocalReplayGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Current entry count (for health/metrics). Returns 0 if the lock is
    /// poisoned (the hot path is poison-tolerant, so the map stays usable).
    pub fn len(&self) -> usize {
        self.seen.lock().map(|g| g.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl ReplayGuard for ProcessLocalReplayGuard {
    async fn check_and_record(&self, key: &str, ttl_secs: u64) -> ReplayOutcome {
        let now = now_secs();
        let expiry = now.saturating_add(ttl_secs);
        let mut g = match self.seen.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        // Sweep expired entries (cheap only above a small size).
        if g.len() > 1024 {
            g.retain(|_, exp| *exp > now);
        }
        match g.get(key) {
            Some(exp) if *exp > now => return ReplayOutcome::Replay,
            _ => {}
        }
        if g.len() >= PROCESS_LOCAL_HARD_CAP {
            g.retain(|_, exp| *exp > now);
        }
        g.insert(key.to_string(), expiry);
        ReplayOutcome::Fresh
    }

    fn name(&self) -> &'static str {
        "process-local"
    }
}

/// Redis-backed [`ReplayGuard`] — the cross-replica store.
///
/// Uses `SET <key> 1 NX PX <ttl_ms>`: Redis atomically sets the key only if it
/// does not exist, so exactly one replica across the fleet gets the `OK`
/// (Fresh); every other attempt within the TTL gets `nil` (Replay). Redis is
/// already a required, prod-TLS-gated dependency, so this adds no new
/// infrastructure.
#[derive(Clone)]
pub struct RedisReplayGuard {
    conn: redis::aio::ConnectionManager,
    prefix: String,
}

impl RedisReplayGuard {
    /// Connect a guard from a shared `redis::Client`. The `ConnectionManager`
    /// multiplexes + auto-reconnects, so this is created once at boot and cheap
    /// to clone per call.
    pub async fn connect(client: &redis::Client) -> redis::RedisResult<Self> {
        let conn = redis::aio::ConnectionManager::new(client.clone()).await?;
        Ok(Self {
            conn,
            prefix: "talos:nonce:".to_string(),
        })
    }

    /// Override the key prefix (default `talos:nonce:`).
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }
}

#[async_trait]
impl ReplayGuard for RedisReplayGuard {
    async fn check_and_record(&self, key: &str, ttl_secs: u64) -> ReplayOutcome {
        let full = format!("{}{}", self.prefix, key);
        // PX takes milliseconds; keep it >= the freshness window and never 0.
        let ttl_ms = ttl_secs.saturating_mul(1000).max(1);
        let mut conn = self.conn.clone();
        // SET NX returns Some("OK") when it set the key, None when it existed.
        let res: redis::RedisResult<Option<String>> = redis::cmd("SET")
            .arg(&full)
            .arg(1i64)
            .arg("NX")
            .arg("PX")
            .arg(ttl_ms)
            .query_async(&mut conn)
            .await;
        match res {
            Ok(Some(_)) => ReplayOutcome::Fresh,
            Ok(None) => ReplayOutcome::Replay,
            Err(e) => {
                tracing::warn!(
                    target: "talos_security",
                    error = %e,
                    "distributed replay guard: Redis unavailable — falling back to per-replica \
                     replay protection (HMAC + freshness still enforced)"
                );
                ReplayOutcome::Unavailable
            }
        }
    }

    fn name(&self) -> &'static str {
        "redis"
    }
}

// ── Global registration (mirrors talos_memory::rpc_auth::register_hmac_key_ring) ──

static SHARED: OnceLock<Arc<dyn ReplayGuard>> = OnceLock::new();

/// Register the process-wide shared replay guard. Call ONCE at controller boot.
/// Returns `Err` if a guard was already registered (a second call is a wiring
/// bug — the guard is immutable for the process lifetime).
pub fn register_shared_replay_guard(guard: Arc<dyn ReplayGuard>) -> Result<(), &'static str> {
    SHARED
        .set(guard)
        .map_err(|_| "shared replay guard already registered")
}

/// The registered shared replay guard, or `None` if none was registered (the
/// default — callers then rely solely on their process-local cache, exactly as
/// before this crate existed).
pub fn shared_replay_guard() -> Option<Arc<dyn ReplayGuard>> {
    SHARED.get().cloned()
}

/// Whether an [`ReplayOutcome::Unavailable`] result should be treated as a
/// rejection (fail-closed) rather than admitted (fail-open).
///
/// Default is fail-OPEN: a Redis blip degrades to the pre-existing per-replica
/// protection, which is strictly no worse than before this layer existed, and
/// HMAC + freshness still gate forgery/stale-replay. High-assurance deploys set
/// `TALOS_REPLAY_FAIL_CLOSED=1` to instead refuse messages the shared store
/// couldn't vet.
pub fn fail_closed_from_env() -> bool {
    matches!(
        std::env::var("TALOS_REPLAY_FAIL_CLOSED").ok().as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

/// Resolve an [`ReplayOutcome`] into an admit/reject decision under a fail
/// policy. `true` = admit, `false` = reject as replay.
#[must_use]
pub fn admit(outcome: ReplayOutcome, fail_closed: bool) -> bool {
    match outcome {
        ReplayOutcome::Fresh => true,
        ReplayOutcome::Replay => false,
        ReplayOutcome::Unavailable => !fail_closed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn process_local_fresh_then_replay() {
        let g = ProcessLocalReplayGuard::new();
        assert_eq!(g.check_and_record("k1", 60).await, ReplayOutcome::Fresh);
        assert_eq!(g.check_and_record("k1", 60).await, ReplayOutcome::Replay);
        // A different key is independent.
        assert_eq!(g.check_and_record("k2", 60).await, ReplayOutcome::Fresh);
        assert_eq!(g.len(), 2);
    }

    #[tokio::test]
    async fn process_local_expired_key_is_fresh_again() {
        let g = ProcessLocalReplayGuard::new();
        // ttl 0 → expiry == now, so `*exp > now` is false on the next lookup.
        assert_eq!(g.check_and_record("k", 0).await, ReplayOutcome::Fresh);
        assert_eq!(g.check_and_record("k", 0).await, ReplayOutcome::Fresh);
    }

    #[test]
    fn admit_policy() {
        assert!(admit(ReplayOutcome::Fresh, false));
        assert!(admit(ReplayOutcome::Fresh, true));
        assert!(!admit(ReplayOutcome::Replay, false));
        assert!(!admit(ReplayOutcome::Replay, true));
        // Unavailable: fail-open admits, fail-closed rejects.
        assert!(admit(ReplayOutcome::Unavailable, false));
        assert!(!admit(ReplayOutcome::Unavailable, true));
    }

    #[test]
    fn registration_is_single_shot() {
        // NB: OnceLock is process-global; keep this the only test that registers
        // so it doesn't race sibling tests.
        let g: Arc<dyn ReplayGuard> = Arc::new(ProcessLocalReplayGuard::new());
        assert!(register_shared_replay_guard(g.clone()).is_ok());
        assert!(register_shared_replay_guard(g).is_err());
        assert!(shared_replay_guard().is_some());
    }

    // Live-Redis integration test — gated on TALOS_TEST_REDIS_URL so it is a
    // no-op in environments without a Redis. Run with e.g.
    //   TALOS_TEST_REDIS_URL=redis://127.0.0.1:6379 cargo test -p talos-replay-guard -- --nocapture
    #[tokio::test]
    async fn redis_fresh_then_replay_when_available() {
        let Ok(url) = std::env::var("TALOS_TEST_REDIS_URL") else {
            eprintln!("skipping: TALOS_TEST_REDIS_URL unset");
            return;
        };
        let client = redis::Client::open(url).expect("open redis client");
        let guard = match RedisReplayGuard::connect(&client).await {
            Ok(g) => g,
            Err(e) => {
                eprintln!("skipping: cannot connect to Redis: {e}");
                return;
            }
        };
        // A unique key per run so reruns don't collide on the same Redis.
        let key = format!("itest:{}:{}", std::process::id(), now_secs());
        assert_eq!(
            guard.check_and_record(&key, 60).await,
            ReplayOutcome::Fresh,
            "first sighting must be Fresh"
        );
        assert_eq!(
            guard.check_and_record(&key, 60).await,
            ReplayOutcome::Replay,
            "second sighting within TTL must be Replay (cross-replica single-use)"
        );
    }

    // Explicit cross-replica model: TWO independent RedisReplayGuard instances
    // (each stands in for a separate controller replica) share ONE Redis. A
    // nonce admitted by replica A must be rejected by replica B — the exact
    // property `crossreplica_replay_ok` in the RPC subscribers relies on, which
    // the per-process nonce caches cannot provide. Gated on TALOS_TEST_REDIS_URL.
    #[tokio::test]
    async fn two_replicas_share_single_use_via_redis() {
        let Ok(url) = std::env::var("TALOS_TEST_REDIS_URL") else {
            eprintln!("skipping: TALOS_TEST_REDIS_URL unset");
            return;
        };
        let client = redis::Client::open(url).expect("open redis client");
        // Two guards built independently, as two replicas would at their own boots.
        let (replica_a, replica_b) = match (
            RedisReplayGuard::connect(&client).await,
            RedisReplayGuard::connect(&client).await,
        ) {
            (Ok(a), Ok(b)) => (a, b),
            _ => {
                eprintln!("skipping: cannot connect to Redis");
                return;
            }
        };
        let key = format!("itest-2rep:{}:{}", std::process::id(), now_secs());

        // Replica A sees the message first → admits it.
        assert_eq!(
            replica_a.check_and_record(&key, 60).await,
            ReplayOutcome::Fresh,
            "replica A must admit the first sighting"
        );
        // The SAME signed message replayed to replica B → rejected fleet-wide,
        // even though replica B's own process-local cache never saw it.
        assert_eq!(
            replica_b.check_and_record(&key, 60).await,
            ReplayOutcome::Replay,
            "replica B must reject a nonce already recorded by replica A"
        );
        // And a genuinely different nonce is still independently admitted by B.
        let other = format!("{key}:other");
        assert_eq!(
            replica_b.check_and_record(&other, 60).await,
            ReplayOutcome::Fresh,
            "a distinct nonce must remain admissible"
        );
    }
}
