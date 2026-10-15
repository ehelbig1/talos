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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

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

    /// Forget `key`, so it can be recorded again. For a caller that recorded
    /// a single-use credential and then answered its sender with a retryable
    /// failure (the Jira receiver, 2026-10-14): the sender's retry, which may
    /// carry the same credential, must not be refused as a replay. Best
    /// effort — a backend error leaves the key to expire with its TTL.
    async fn release(&self, _key: &str) {}

    /// Whether the guard can reach its store now. A guard registered while
    /// its store was down answers `false` until it connects.
    fn connected(&self) -> bool {
        true
    }

    /// Short label for logs/metrics.
    fn name(&self) -> &'static str {
        "replay-guard"
    }
}

/// Redis-backed [`ReplayGuard`] — the cross-replica store.
///
/// Uses `SET <key> 1 NX PX <ttl_ms>`: Redis atomically sets the key only if it
/// does not exist, so exactly one replica across the fleet gets the `OK`
/// (Fresh); every other attempt within the TTL gets `nil` (Replay). Redis is
/// already a required, prod-TLS-gated dependency, so this adds no new
/// infrastructure.
///
/// A guard built by [`Self::registering`] holds no connection until Redis
/// first answers: every call until then is [`ReplayOutcome::Unavailable`],
/// which the caller's [`ReplayPolicy`] refuses when failing closed, and the
/// guard tries to connect again (at most once per [`RECONNECT_EVERY`]).
/// Until 2026-10-15 a guard whose first connect failed was never registered,
/// and a process with no guard admitted every message for its lifetime
/// (security review round 2, B2-2).
#[derive(Clone)]
pub struct RedisReplayGuard {
    client: redis::Client,
    conn: Arc<tokio::sync::OnceCell<redis::aio::ConnectionManager>>,
    /// Unix millis before which no new connect is attempted.
    next_connect_ms: Arc<AtomicU64>,
    prefix: String,
}

/// How often a guard with no connection tries to make one.
pub const RECONNECT_EVERY: std::time::Duration = std::time::Duration::from_secs(1);

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

impl RedisReplayGuard {
    /// Connect a guard from a shared `redis::Client`, or fail. The
    /// `ConnectionManager` multiplexes + auto-reconnects, so this is created
    /// once at boot and cheap to clone per call.
    pub async fn connect(client: &redis::Client) -> redis::RedisResult<Self> {
        let guard = Self::pending(client);
        let conn = talos_redis::manager(client.clone()).await?;
        let _ = guard.conn.set(conn);
        Ok(guard)
    }

    /// A guard to REGISTER whether or not Redis answers now: the second
    /// value says whether it connected. One that did not answers
    /// [`ReplayOutcome::Unavailable`] until Redis does.
    pub async fn registering(client: &redis::Client) -> (Self, Result<(), redis::RedisError>) {
        let guard = Self::pending(client);
        match talos_redis::manager(client.clone()).await {
            Ok(conn) => {
                let _ = guard.conn.set(conn);
                (guard, Ok(()))
            }
            Err(e) => {
                guard.next_connect_ms.store(
                    now_ms().saturating_add(RECONNECT_EVERY.as_millis() as u64),
                    Ordering::Relaxed,
                );
                (guard, Err(e))
            }
        }
    }

    fn pending(client: &redis::Client) -> Self {
        Self {
            client: client.clone(),
            conn: Arc::new(tokio::sync::OnceCell::new()),
            next_connect_ms: Arc::new(AtomicU64::new(0)),
            prefix: "talos:nonce:".to_string(),
        }
    }

    /// Override the key prefix (default `talos:nonce:`).
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    /// The connection, making one when none was made and a try is due.
    async fn connection(&self) -> Option<redis::aio::ConnectionManager> {
        if let Some(conn) = self.conn.get() {
            return Some(conn.clone());
        }
        let due = self.next_connect_ms.load(Ordering::Relaxed);
        let now = now_ms();
        if now < due
            || self
                .next_connect_ms
                .compare_exchange(
                    due,
                    now.saturating_add(RECONNECT_EVERY.as_millis() as u64),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_err()
        {
            return None;
        }
        match talos_redis::manager(self.client.clone()).await {
            Ok(conn) => {
                tracing::info!(
                    target: "talos_security",
                    "distributed replay guard: Redis answered — the shared store is in use"
                );
                Some(self.conn.get_or_init(|| async { conn }).await.clone())
            }
            Err(e) => {
                tracing::warn!(
                    target: "talos_security",
                    error = %e,
                    "distributed replay guard: Redis still unreachable"
                );
                None
            }
        }
    }
}

#[async_trait]
impl ReplayGuard for RedisReplayGuard {
    async fn check_and_record(&self, key: &str, ttl_secs: u64) -> ReplayOutcome {
        let Some(mut conn) = self.connection().await else {
            return ReplayOutcome::Unavailable;
        };
        let full = format!("{}{}", self.prefix, key);
        // PX takes milliseconds; keep it >= the freshness window and never 0.
        let ttl_ms = ttl_secs.saturating_mul(1000).max(1);
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
                // The outcome only: whether it is refused or admitted is the
                // caller's policy, which logs it (2026-10-15, B2-9 — this line
                // said "falling back to per-replica protection" while a
                // fail-closed caller refused).
                tracing::warn!(
                    target: "talos_security",
                    error = %e,
                    "distributed replay guard: Redis unavailable for a check"
                );
                ReplayOutcome::Unavailable
            }
        }
    }

    async fn release(&self, key: &str) {
        let Some(mut conn) = self.connection().await else {
            return;
        };
        let full = format!("{}{}", self.prefix, key);
        let res: redis::RedisResult<i64> =
            redis::cmd("DEL").arg(&full).query_async(&mut conn).await;
        if let Err(e) = res {
            tracing::warn!(
                target: "talos_security",
                error = %e,
                "distributed replay guard: a released key could not be deleted; it expires with its TTL"
            );
        }
    }

    fn connected(&self) -> bool {
        self.conn.get().is_some()
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
/// Security review 2026-07-19 (L1): the default is now **fail-CLOSED in
/// production**, fail-open in dev. When the shared replay store is unreachable,
/// a production controller refuses the cross-replica-unvetted message rather
/// than admitting it on the strength of only the per-replica cache — closing
/// the window where a captured signed WRITE RPC (state durability / memory
/// Set/Delete) could be replayed to a *different* replica inside the 60 s
/// freshness window. HMAC + freshness + per-replica nonce still hold either way.
///
/// This is an availability/security trade: a Redis blip will reject RPCs in
/// prod until it recovers. Operators who prioritise availability opt out
/// explicitly with `TALOS_REPLAY_FAIL_CLOSED=0`; the env var (any of
/// 1/true/yes/on or 0/false/no/off) always wins over the environment default.
pub fn fail_closed_from_env() -> bool {
    // Unset (or an unrecognised value): fail-closed in prod, open in dev.
    talos_config::bool_env("TALOS_REPLAY_FAIL_CLOSED").unwrap_or_else(talos_config::is_production)
}

/// Resolve an [`ReplayOutcome`] into an admit/reject decision under a fail
/// policy. `true` = admit, `false` = reject as replay. For a caller that has
/// a guard in hand; [`ReplayPolicy::decide`] also answers for no guard.
#[must_use]
pub fn admit(outcome: ReplayOutcome, fail_closed: bool) -> bool {
    match outcome {
        ReplayOutcome::Fresh => true,
        ReplayOutcome::Replay => false,
        ReplayOutcome::Unavailable => !fail_closed,
    }
}

/// The switch that turns the shared guard on, read in ONE place (the
/// controller and the worker each read it by name until 2026-10-15).
pub const DISTRIBUTED_REPLAY: &str = "TALOS_DISTRIBUTED_REPLAY";

/// Whether this process is meant to have a shared guard.
#[must_use]
pub fn distributed_replay_from_env() -> bool {
    talos_config::bool_env_or_default(DISTRIBUTED_REPLAY, false)
}

/// What a process does with a nonce the shared store must vouch for: whether
/// a shared guard is meant to be there ([`DISTRIBUTED_REPLAY`]) and whether a
/// store that cannot answer refuses ([`fail_closed_from_env`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayPolicy {
    pub distributed: bool,
    pub fail_closed: bool,
}

/// What a nonce comes to under a [`ReplayPolicy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayVerdict {
    /// Admit it.
    Admit,
    /// The store has seen it: a replay. Refuse.
    Replay,
    /// The store could not vouch for it — down, or never registered — and
    /// the policy fails closed. Refuse.
    StoreUnavailable,
}

impl ReplayPolicy {
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            distributed: distributed_replay_from_env(),
            fail_closed: fail_closed_from_env(),
        }
    }

    /// THE decision, for a guard's answer or for no guard at all (`None`).
    /// No guard is "no store to vouch" exactly as a guard that cannot reach
    /// its store is, when the switch says there should be one: a process
    /// whose guard was never registered (no Redis configured, or a build
    /// that skipped it) refuses when failing closed, where until 2026-10-15
    /// it admitted everything for its lifetime (security review round 2,
    /// B2-2). With the switch off, no guard is the configured posture and
    /// the process-local caches are the whole defence, as before.
    #[must_use]
    pub fn decide(self, outcome: Option<ReplayOutcome>) -> ReplayVerdict {
        match outcome {
            Some(ReplayOutcome::Fresh) => ReplayVerdict::Admit,
            Some(ReplayOutcome::Replay) => ReplayVerdict::Replay,
            Some(ReplayOutcome::Unavailable) | None => {
                let meant_to_vouch = outcome.is_some() || self.distributed;
                if meant_to_vouch && self.fail_closed {
                    ReplayVerdict::StoreUnavailable
                } else {
                    ReplayVerdict::Admit
                }
            }
        }
    }

    /// Ask `guard` (if any) about `key` and decide.
    pub async fn check(
        self,
        guard: Option<&dyn ReplayGuard>,
        key: &str,
        ttl_secs: u64,
    ) -> ReplayVerdict {
        let outcome = match guard {
            Some(guard) => Some(guard.check_and_record(key, ttl_secs).await),
            None => None,
        };
        self.decide(outcome)
    }

    /// [`Self::check`] against the registered guard.
    pub async fn check_shared(self, key: &str, ttl_secs: u64) -> ReplayVerdict {
        self.check(shared_replay_guard().as_deref(), key, ttl_secs)
            .await
    }
}

/// The shared guard's state, for `security_audit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardState {
    /// No guard is registered.
    NotRegistered,
    /// A guard is registered; `connected` says whether its store answers.
    Registered { connected: bool },
}

#[must_use]
pub fn guard_state() -> GuardState {
    match shared_replay_guard() {
        None => GuardState::NotRegistered,
        Some(guard) => GuardState::Registered {
            connected: guard.connected(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test double: a guard that never sees a replay. (The in-process
    /// reference implementation had no production caller and was deleted;
    /// the process-local caches live in the signed-message crates.)
    struct AlwaysFresh;

    #[async_trait]
    impl ReplayGuard for AlwaysFresh {
        async fn check_and_record(&self, _key: &str, _ttl_secs: u64) -> ReplayOutcome {
            ReplayOutcome::Fresh
        }
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
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

    /// B2-2 (2026-10-15): with the switch on, a process that has NO guard
    /// refuses when failing closed — the production default — exactly as a
    /// guard that cannot reach its store does. With the switch off, no guard
    /// is the configured posture and admits.
    #[test]
    fn a_missing_guard_in_production_refuses_when_failing_closed() {
        let closed = ReplayPolicy {
            distributed: true,
            fail_closed: true,
        };
        assert_eq!(closed.decide(None), ReplayVerdict::StoreUnavailable);
        assert_eq!(
            closed.decide(Some(ReplayOutcome::Unavailable)),
            ReplayVerdict::StoreUnavailable
        );
        assert_eq!(
            closed.decide(Some(ReplayOutcome::Fresh)),
            ReplayVerdict::Admit
        );
        assert_eq!(
            closed.decide(Some(ReplayOutcome::Replay)),
            ReplayVerdict::Replay
        );

        let open = ReplayPolicy {
            distributed: true,
            fail_closed: false,
        };
        assert_eq!(open.decide(None), ReplayVerdict::Admit);
        assert_eq!(
            open.decide(Some(ReplayOutcome::Unavailable)),
            ReplayVerdict::Admit
        );
        assert_eq!(
            open.decide(Some(ReplayOutcome::Replay)),
            ReplayVerdict::Replay
        );

        let off = ReplayPolicy {
            distributed: false,
            fail_closed: true,
        };
        assert_eq!(
            off.decide(None),
            ReplayVerdict::Admit,
            "no guard by configuration"
        );
    }

    /// B2-2: a guard registered while Redis is down is registered, says it is
    /// not connected, and answers `Unavailable` — which the fail-closed
    /// policy refuses — instead of not existing.
    #[tokio::test]
    async fn a_guard_registered_while_redis_is_down_answers_unavailable() {
        // Port 1 on loopback: nothing listens, the connect is refused.
        let client = redis::Client::open("redis://127.0.0.1:1/").expect("client");
        let (guard, connected) = RedisReplayGuard::registering(&client).await;
        assert!(connected.is_err());
        assert!(!guard.connected());
        let outcome = guard.check_and_record("k", 60).await;
        assert_eq!(outcome, ReplayOutcome::Unavailable);
        let closed = ReplayPolicy {
            distributed: true,
            fail_closed: true,
        };
        assert_eq!(
            closed.decide(Some(outcome)),
            ReplayVerdict::StoreUnavailable
        );
    }

    #[test]
    fn registration_is_single_shot() {
        // NB: OnceLock is process-global; keep this the only test that registers
        // so it doesn't race sibling tests.
        let g: Arc<dyn ReplayGuard> = Arc::new(AlwaysFresh);
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

    /// A guard registered while Redis answers is connected and works.
    #[tokio::test]
    async fn a_guard_registered_while_redis_answers_is_connected() {
        let Ok(url) = std::env::var("TALOS_TEST_REDIS_URL") else {
            eprintln!("skipping: TALOS_TEST_REDIS_URL unset");
            return;
        };
        let client = redis::Client::open(url).expect("open redis client");
        let (guard, connected) = RedisReplayGuard::registering(&client).await;
        connected.expect("Redis answers");
        assert!(guard.connected());
        let key = format!("itest-registering:{}:{}", std::process::id(), now_secs());
        assert_eq!(guard.check_and_record(&key, 60).await, ReplayOutcome::Fresh);
        assert_eq!(
            guard.check_and_record(&key, 60).await,
            ReplayOutcome::Replay
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
