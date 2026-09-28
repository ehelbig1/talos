//! Fleet-wide admission to one local inference backend — RFC 0014 P3b.
//!
//! ## The defect this closes
//!
//! The in-flight gate ([`crate::gate`]) is a semaphore inside ONE process. The
//! controller and every worker replica each have their own, so a backend that
//! serves one request at a time still sees one request per process. Measured
//! over 30 days on the reference deployment (one worker, one controller): 108
//! worker requests arrived while a controller call held the backend, ~14 s of
//! waiting each, charged to the worker call's own deadlines because the worker
//! could not see it.
//!
//! ## Shape
//!
//! A counting semaphore in Redis, keyed per backend, taken AFTER the process's
//! own gate (so a process has at most `cap` callers in the fleet queue and its
//! other calls queue locally, where no Redis round trip is spent):
//!
//! * **holders** — a sorted set of lease tokens scored by lease expiry;
//! * **waiters** — a sorted set of tokens scored by a ticket (`INCR`), so the
//!   queue is FIFO across processes;
//! * **alive** — each waiter's liveness expiry, refreshed on every poll, so a
//!   waiter whose process died leaves the queue within [`FleetTiming::alive`].
//!
//! One Lua script does every transition, on Redis's own clock (`TIME`), so no
//! two hosts' clocks are ever compared. A holder renews its lease in the
//! background; a holder that dies stops renewing and its lease expires within
//! [`FleetTiming::lease`].
//!
//! ## It never refuses, and Redis is not on the critical path
//!
//! * A Redis error or a Redis call slower than [`FleetTiming::redis_call`]
//!   makes the call proceed on its process's gate alone — the P3a behaviour —
//!   and the transition is logged once, not per call.
//! * A fleet wait that outlasts the caller's wait cap proceeds UNGATED, exactly
//!   as the process gate does.
//! * A lease that is lost (expired while its renewal could not reach Redis)
//!   is counted and logged; the call is not interrupted.
//!
//! Over-admission is the only failure mode, and it is harmless: the backend
//! queues what it cannot serve, which is what happened before this module.
//! There is no fencing token because the protected resource (Ollama) cannot
//! check one; the lease token only stops a holder renewing a lease it lost.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use redis::aio::ConnectionManager;
use sha2::{Digest, Sha256};
use tokio::time::Instant;

/// Admission transitions, as a closed set of metric labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FleetOutcome {
    /// Admitted by the fleet queue.
    Leased,
    /// The fleet queue did not admit the call within the caller's wait cap;
    /// the call proceeded ungated.
    WaitExpired,
    /// Redis failed or was too slow; the call proceeded on its process's gate.
    Unavailable,
    /// A held lease could not be renewed before it expired.
    LeaseLost,
}

impl FleetOutcome {
    pub const ALL: [FleetOutcome; 4] = [
        FleetOutcome::Leased,
        FleetOutcome::WaitExpired,
        FleetOutcome::Unavailable,
        FleetOutcome::LeaseLost,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            FleetOutcome::Leased => "leased",
            FleetOutcome::WaitExpired => "wait_expired",
            FleetOutcome::Unavailable => "unavailable",
            FleetOutcome::LeaseLost => "lease_lost",
        }
    }
}

/// Where each process records [`FleetOutcome`]s: the worker into its OTEL
/// counter, the controller into its Prometheus registry.
pub type FleetSink = dyn Fn(FleetOutcome) + Send + Sync;

/// The timing of the fleet queue. [`FleetTiming::PRODUCTION`] in production; a
/// value only so the tests can run it at millisecond scale.
#[derive(Debug, Clone, Copy)]
pub struct FleetTiming {
    /// How long a lease lives without renewal: how long a dead holder can hold
    /// the backend's slot.
    pub lease: Duration,
    /// How often a live holder renews. Well under `lease`, so one slow renewal
    /// does not lose it.
    pub renew_every: Duration,
    /// How long a waiter stays in the queue without polling: how long a dead
    /// waiter can stand ahead of live ones.
    pub alive: Duration,
    /// How often a waiter asks whether it is at the front.
    pub poll: Duration,
    /// The bound on any one Redis call. Past it the call counts as Redis
    /// being unavailable.
    pub redis_call: Duration,
}

impl FleetTiming {
    pub const PRODUCTION: Self = Self {
        lease: Duration::from_secs(30),
        renew_every: Duration::from_secs(10),
        alive: Duration::from_secs(5),
        poll: Duration::from_millis(200),
        redis_call: Duration::from_secs(2),
    };
}

/// Every transition of the queue. `KEYS`: holders, waiters, alive, ticket.
/// `ARGV`: op, token, cap, lease ms, alive ms, idle ms.
///
/// `acquire` returns `-1` when the token holds a lease (newly or already),
/// otherwise its position behind the free slots (`>= 1`). `renew` returns `1`
/// when the lease was extended and `0` when it no longer exists. `release`
/// returns `0`.
const SCRIPT: &str = r#"
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
local dead = redis.call('ZRANGEBYSCORE', KEYS[3], '-inf', now)
for _, w in ipairs(dead) do
  redis.call('ZREM', KEYS[2], w)
end
redis.call('ZREMRANGEBYSCORE', KEYS[3], '-inf', now)
local op = ARGV[1]
local token = ARGV[2]
local idle = tonumber(ARGV[6])
local function keep()
  for i = 1, 4 do
    redis.call('PEXPIRE', KEYS[i], idle)
  end
end
if op == 'release' then
  redis.call('ZREM', KEYS[1], token)
  redis.call('ZREM', KEYS[2], token)
  redis.call('ZREM', KEYS[3], token)
  return 0
end
local lease_until = now + tonumber(ARGV[4])
if op == 'renew' then
  if redis.call('ZSCORE', KEYS[1], token) then
    redis.call('ZADD', KEYS[1], lease_until, token)
    keep()
    return 1
  end
  return 0
end
if redis.call('ZSCORE', KEYS[1], token) then
  redis.call('ZADD', KEYS[1], lease_until, token)
  keep()
  return -1
end
if not redis.call('ZSCORE', KEYS[2], token) then
  redis.call('ZADD', KEYS[2], redis.call('INCR', KEYS[4]), token)
end
redis.call('ZADD', KEYS[3], now + tonumber(ARGV[5]), token)
local free = tonumber(ARGV[3]) - redis.call('ZCARD', KEYS[1])
local rank = redis.call('ZRANK', KEYS[2], token)
if rank < free then
  redis.call('ZREM', KEYS[2], token)
  redis.call('ZREM', KEYS[3], token)
  redis.call('ZADD', KEYS[1], lease_until, token)
  keep()
  return -1
end
keep()
return rank - free + 1
"#;

/// The four keys of one backend's queue. A hash tag keeps them in one cluster
/// slot, which a multi-key script requires.
#[derive(Debug, Clone)]
struct Keys([String; 4]);

impl Keys {
    fn for_backend(backend_url: &str) -> Self {
        let id = backend_id(backend_url);
        let base = format!("talos:llm-admit:{{{id}}}");
        Keys([
            format!("{base}:holders"),
            format!("{base}:waiters"),
            format!("{base}:alive"),
            format!("{base}:ticket"),
        ])
    }
}

/// The queue's identity for a backend URL: the SHA-256 of the URL with its
/// case and any trailing `/` normalised, so a URL carrying credentials never
/// reaches a key name. Two processes naming the same backend by different
/// URLs get different queues — they fall back to P3a's per-process bound
/// against each other, never to refusal.
pub fn backend_id(backend_url: &str) -> String {
    let normalised = backend_url
        .trim()
        .trim_end_matches('/')
        .to_ascii_lowercase();
    let digest = Sha256::digest(normalised.as_bytes());
    digest[..8].iter().map(|b| format!("{b:02x}")).collect()
}

struct Inner {
    conn: ConnectionManager,
    script: redis::Script,
    keys: Keys,
    cap: usize,
    timing: FleetTiming,
    sink: Option<Arc<FleetSink>>,
    /// Whether the last Redis call failed — so a Redis outage logs once when
    /// it starts and once when it ends, not once per call.
    degraded: AtomicBool,
}

/// Fleet-wide admission to one backend. Cheap to clone.
#[derive(Clone)]
pub struct FleetAdmission {
    inner: Arc<Inner>,
}

/// The result of asking the fleet queue for a slot.
pub enum FleetAcquire {
    /// Admitted. Hold the lease for the whole exchange.
    Leased(FleetLease),
    /// Not admitted within the wait cap; proceed ungated.
    WaitExpired,
    /// Redis failed; proceed on the process's gate.
    Unavailable,
}

impl FleetAdmission {
    /// Connect to `client` for the backend at `backend_url`, with `cap` slots
    /// fleet-wide.
    pub async fn connect(
        client: redis::Client,
        backend_url: &str,
        cap: usize,
        timing: FleetTiming,
        sink: Option<Arc<FleetSink>>,
    ) -> redis::RedisResult<Self> {
        let conn = tokio::time::timeout(timing.redis_call * 5, ConnectionManager::new(client))
            .await
            .map_err(|_| {
                redis::RedisError::from((redis::ErrorKind::IoError, "connect timed out"))
            })??;
        Ok(Self {
            inner: Arc::new(Inner {
                conn,
                script: redis::Script::new(SCRIPT),
                keys: Keys::for_backend(backend_url),
                cap: cap.max(1),
                timing,
                sink,
                degraded: AtomicBool::new(false),
            }),
        })
    }

    /// Wait for a slot until `deadline`. `on_queue` runs once, the first time
    /// the call has to wait (the process gate's observer uses it).
    pub async fn acquire<F, Fut>(&self, deadline: Instant, on_queue: F) -> FleetAcquire
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let token = uuid_like_token();
        // Leaves the queue however this future ends — admitted, expired, or
        // dropped by a caller that gave up.
        let mut waiting = WaiterGuard {
            admission: Some(self.clone()),
            token: token.clone(),
        };
        let mut on_queue = Some(on_queue);
        loop {
            match self.inner.call("acquire", &token).await {
                Err(()) => {
                    self.record(FleetOutcome::Unavailable);
                    return FleetAcquire::Unavailable;
                }
                Ok(-1) => {
                    waiting.admission = None;
                    self.record(FleetOutcome::Leased);
                    return FleetAcquire::Leased(FleetLease::start(self.clone(), token));
                }
                Ok(_position) => {
                    if let Some(f) = on_queue.take() {
                        f().await;
                    }
                }
            }
            let next = Instant::now() + self.inner.timing.poll;
            if next >= deadline {
                tokio::time::sleep_until(deadline).await;
                // One last look: the slot may have freed during the sleep.
                if let Ok(-1) = self.inner.call("acquire", &token).await {
                    waiting.admission = None;
                    self.record(FleetOutcome::Leased);
                    return FleetAcquire::Leased(FleetLease::start(self.clone(), token));
                }
                self.record(FleetOutcome::WaitExpired);
                return FleetAcquire::WaitExpired;
            }
            tokio::time::sleep_until(next).await;
        }
    }

    fn record(&self, outcome: FleetOutcome) {
        if let Some(sink) = &self.inner.sink {
            sink(outcome);
        }
    }
}

impl Inner {
    /// One script call, bounded by `redis_call`. `Err(())` is Redis failing or
    /// too slow; the error is logged here, once per outage.
    async fn call(&self, op: &str, token: &str) -> Result<i64, ()> {
        let mut conn = self.conn.clone();
        let mut inv = self.script.prepare_invoke();
        for k in &self.keys.0 {
            inv.key(k);
        }
        inv.arg(op)
            .arg(token)
            .arg(self.cap)
            .arg(self.timing.lease.as_millis() as u64)
            .arg(self.timing.alive.as_millis() as u64)
            .arg(self.idle_ms());
        let result =
            tokio::time::timeout(self.timing.redis_call, inv.invoke_async::<i64>(&mut conn)).await;
        match result {
            Ok(Ok(v)) => {
                if self.degraded.swap(false, Ordering::Relaxed) {
                    tracing::info!("local LLM fleet admission: Redis reachable again");
                }
                Ok(v)
            }
            Ok(Err(e)) => {
                self.degrade(&e.to_string());
                Err(())
            }
            Err(_) => {
                self.degrade("Redis call timed out");
                Err(())
            }
        }
    }

    fn degrade(&self, why: &str) {
        if !self.degraded.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                error = why,
                "local LLM fleet admission: Redis unavailable; calls proceed on their \
                 process's gate until it returns"
            );
        }
    }

    /// Idle keys expire: long after any live lease or waiter would have.
    fn idle_ms(&self) -> u64 {
        (self.timing.lease.max(self.timing.alive) * 4).as_millis() as u64
    }
}

/// A random token naming one admission attempt.
fn uuid_like_token() -> String {
    use std::sync::atomic::AtomicU64;
    static SEQ: AtomicU64 = AtomicU64::new(0);
    static PROCESS: OnceLock<String> = OnceLock::new();
    let process = PROCESS.get_or_init(|| {
        let mut h = Sha256::new();
        h.update(std::process::id().to_le_bytes());
        h.update(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
                .to_le_bytes(),
        );
        h.update(format!("{:?}", std::thread::current().id()).as_bytes());
        h.finalize()[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    });
    format!("{process}-{}", SEQ.fetch_add(1, Ordering::Relaxed))
}

/// Removes a waiter from the queue when its acquire ends without a lease.
struct WaiterGuard {
    admission: Option<FleetAdmission>,
    token: String,
}

impl Drop for WaiterGuard {
    fn drop(&mut self) {
        if let Some(a) = self.admission.take() {
            release_in_background(a, std::mem::take(&mut self.token));
        }
    }
}

fn release_in_background(admission: FleetAdmission, token: String) {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            let _ = admission.inner.call("release", &token).await;
        });
    }
    // With no runtime the entry expires on its own: a waiter within
    // `alive`, a holder within `lease`.
}

/// A held fleet slot. Renewed in the background; released on drop.
pub struct FleetLease {
    admission: FleetAdmission,
    token: String,
    renew: tokio::task::JoinHandle<()>,
}

impl FleetLease {
    fn start(admission: FleetAdmission, token: String) -> Self {
        let a = admission.clone();
        let t = token.clone();
        let renew = tokio::spawn(async move {
            loop {
                tokio::time::sleep(a.inner.timing.renew_every).await;
                match a.inner.call("renew", &t).await {
                    Ok(1) => {}
                    Ok(_) => {
                        tracing::warn!(
                            "local LLM fleet admission: lease expired before it could be \
                             renewed; the call continues"
                        );
                        a.record(FleetOutcome::LeaseLost);
                        return;
                    }
                    // Logged by `call`; the next renewal may still be in time.
                    Err(()) => {}
                }
            }
        });
        Self {
            admission,
            token,
            renew,
        }
    }
}

impl FleetLease {
    /// Stop renewing and forget the lease WITHOUT releasing it — what a
    /// process that dies while holding one looks like to the rest of the
    /// fleet. For the tests only.
    #[doc(hidden)]
    pub fn abandon(self) {
        self.renew.abort();
        // Leaks one `Arc` and a string: this is a test hook.
        std::mem::forget(self);
    }
}

impl std::fmt::Debug for FleetLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FleetLease").finish_non_exhaustive()
    }
}

impl Drop for FleetLease {
    fn drop(&mut self) {
        self.renew.abort();
        release_in_background(self.admission.clone(), std::mem::take(&mut self.token));
    }
}

/// This process's fleet admission, when [`install`] found Redis.
static FLEET: OnceLock<FleetAdmission> = OnceLock::new();

/// Opt-out for the fleet queue: `false` keeps each process on its own gate
/// (the P3a behaviour). Default on when Redis is configured.
pub const FLEET_ADMISSION_ENV: &str = "TALOS_LOCAL_LLM_FLEET_ADMISSION";

/// Install this process's fleet admission for the backend at `backend_url`.
/// Call once at boot. The fleet cap is the process gate's cap
/// ([`crate::gate::max_in_flight`]), which is the backend's slot count; a cap
/// of 0 (gate disabled) or [`FLEET_ADMISSION_ENV`]=false installs nothing, and
/// so does a Redis that cannot be reached at boot — every case leaves calls on
/// the process gate, never refused.
pub async fn install(client: redis::Client, backend_url: &str, sink: Option<Arc<FleetSink>>) {
    let cap = crate::gate::max_in_flight();
    if cap == 0 {
        return;
    }
    if !talos_config::bool_env_or_default(FLEET_ADMISSION_ENV, true) {
        tracing::info!("local LLM fleet admission: off ({FLEET_ADMISSION_ENV}=false)");
        return;
    }
    match FleetAdmission::connect(client, backend_url, cap, FleetTiming::PRODUCTION, sink).await {
        Ok(a) => {
            if FLEET.set(a).is_ok() {
                tracing::info!(
                    cap,
                    backend = %backend_id(backend_url),
                    "local LLM fleet admission: on — this process queues with the fleet"
                );
            }
        }
        Err(e) => tracing::warn!(
            error = %e,
            "local LLM fleet admission: Redis unreachable at boot; this process stays on \
             its own gate"
        ),
    }
}

/// This process's fleet admission, if installed.
pub fn installed() -> Option<&'static FleetAdmission> {
    FLEET.get()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_backend_id_ignores_case_and_a_trailing_slash_and_hides_the_url() {
        let a = backend_id("http://host.docker.internal:11434");
        assert_eq!(a, backend_id("HTTP://Host.Docker.Internal:11434/"));
        assert_ne!(a, backend_id("http://ollama:11434"));
        assert_eq!(a.len(), 16);
        assert!(!backend_id("http://user:secret@ollama:11434").contains("secret"));
    }

    #[test]
    fn the_keys_share_one_cluster_slot() {
        let k = Keys::for_backend("http://ollama:11434");
        let tag = |s: &str| s[s.find('{').unwrap()..=s.find('}').unwrap()].to_string();
        assert!(k.0.iter().all(|key| tag(key) == tag(&k.0[0])));
    }

    #[test]
    fn outcome_labels_are_distinct() {
        let mut labels: Vec<_> = FleetOutcome::ALL.iter().map(|o| o.as_str()).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), FleetOutcome::ALL.len());
    }

    #[test]
    fn production_timing_renews_well_inside_the_lease() {
        let t = FleetTiming::PRODUCTION;
        assert!(t.renew_every * 2 < t.lease);
        assert!(t.poll < t.alive);
        assert!(t.redis_call < t.renew_every);
    }

    #[test]
    fn tokens_are_unique_within_a_process() {
        assert_ne!(uuid_like_token(), uuid_like_token());
    }
}
