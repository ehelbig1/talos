//! The controller's view of which worker processes are currently running.
//!
//! # What this crate's answer means — and what it is not
//!
//! A [`WorkerHeartbeat`] is HMAC-signed under `WORKER_SHARED_KEY`, which is
//! **fleet-shared**. Any process holding that key can mint a heartbeat naming
//! any `worker_id`. So the fleet view answers "is *a* process claiming to be
//! this worker publishing right now?" — a **liveness hint for observability**.
//! It is emphatically NOT:
//!
//! * a trust signal. It must never refresh, extend or create trust in a
//!   signing identity. `worker_identities.last_liveness_at` has exactly ONE
//!   writer — the Ed25519 proof-of-possession endpoint (#631), where the
//!   credential is the worker's OWN key rather than a fleet-shared one. This
//!   crate must not gain a database dependency; the invariant is asserted in
//!   [`tests::heartbeat_never_touches_the_trust_boundary`] and by structural
//!   lint check 67, not left to a comment.
//! * an input to job routing. `find_best_worker` exists but has no production
//!   caller; making dispatch depend on this view is a behavioural change with
//!   its own blast radius.
//!
//! # History (why the shape changed in 2026-08)
//!
//! Until then `start_worker_management` had **zero call sites**, nothing
//! anywhere published a heartbeat, and the message keyed on a `Uuid` where
//! `worker_identities.worker_id` is operator/pod text. The view was therefore
//! permanently empty AND unjoinable — dead code that looked alive, which twice
//! led a design to propose intersecting the identity registry against it. That
//! intersection would have deactivated the entire fleet's signing keys on the
//! first sweep. Both times grounding caught it.
//!
//! # Bounding and eviction (stated, because the key is caller-supplied)
//!
//! The map is keyed on a `worker_id` that arrives over the bus, so it is an
//! attacker-influenceable growth surface for anyone holding the shared key.
//! Two independent bounds:
//!
//! * **Hard cap** [`MAX_TRACKED_WORKERS`]. At the cap, a heartbeat naming an
//!   id that is not already tracked is dropped with a rate-limited WARN.
//!   Existing entries keep updating, so a full map degrades to "no NEW workers
//!   are visible" rather than to eviction churn of the real fleet.
//! * **Staleness prune** every [`PRUNE_INTERVAL`], removing entries not seen
//!   within [`STALE_AFTER`]. A worker that stops heartbeating therefore leaves
//!   the view within `STALE_AFTER + PRUNE_INTERVAL` (90s at defaults) — the
//!   window quoted anywhere this view's freshness is described.
//!
//! Neither bound is LRU: entries leave only by going stale or by the process
//! restarting. That is deliberate — an LRU keyed on caller-supplied ids lets a
//! flood evict the real fleet, which is worse than refusing the flood.

use dashmap::DashMap;
use futures::StreamExt;
use std::sync::Arc;
use talos_workflow_job_protocol::{WorkerHeartbeat, WORKER_HEARTBEAT_MAX_AGE_SECS};
use tokio::time::{Duration, Instant};

/// Maximum distinct `worker_id`s tracked at once.
///
/// Sized well above any plausible fleet (the registry's own bounded fleet
/// query caps at 200 rows) and well below anything that could pressure memory:
/// each entry is a heartbeat plus an `Instant`, so 4096 entries is on the
/// order of hundreds of kilobytes. The cap exists for the malicious case, not
/// the organic one.
pub const MAX_TRACKED_WORKERS: usize = 4096;

/// How long after its last heartbeat a worker is considered stale and dropped
/// from the view. Two missed heartbeats at the 30s default publish interval,
/// and equal to the protocol's own freshness window — a heartbeat older than
/// this would not verify anyway, so keeping the entry longer would assert
/// liveness on evidence the protocol has already declared expired.
pub const STALE_AFTER: Duration = Duration::from_secs(WORKER_HEARTBEAT_MAX_AGE_SECS);

/// How often the prune task runs. The eviction window a reader should quote is
/// `STALE_AFTER + PRUNE_INTERVAL`, not `STALE_AFTER` alone.
pub const PRUNE_INTERVAL: Duration = Duration::from_secs(30);

/// Tracks the state of a single worker in the fleet.
#[derive(Debug, Clone)]
pub struct WorkerState {
    pub heartbeat: WorkerHeartbeat,
    pub last_seen: Instant,
}

/// Manages the registry of active workers, processing heartbeats and pruning stale entries.
pub struct WorkerManager {
    /// Thread-safe map of `worker_id` → last known state. Bounded by
    /// [`MAX_TRACKED_WORKERS`]; see the module header for the eviction policy.
    ///
    /// NOTE THE ABSENT FIELD: there is no database pool, no repository and no
    /// HTTP client here, and that is a security property rather than an
    /// oversight. A heartbeat is minted under a fleet-shared key, so a
    /// `WorkerManager` that could write to `worker_identities` would let any
    /// shared-key holder keep any worker's signing key trusted forever.
    workers: DashMap<String, WorkerState>,
    /// The shared key used to verify HMAC signatures on heartbeats.
    shared_key: Vec<u8>,
    /// Heartbeats refused because the map was at [`MAX_TRACKED_WORKERS`].
    /// Read by the fleet-gauge sweep so the condition is visible rather than
    /// only logged.
    capacity_drops: std::sync::atomic::AtomicU64,
}

impl WorkerManager {
    /// Creates a new WorkerManager with the given shared secret key.
    pub fn new(shared_key: Vec<u8>) -> Self {
        Self {
            workers: DashMap::new(),
            shared_key,
            capacity_drops: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Processes an incoming heartbeat, verifying its signature and updating the registry.
    ///
    /// **This is the single primary `verify()` caller for `WorkerHeartbeat` in
    /// the controller process** (CLAUDE.md verify-once rule). Any additional
    /// consumer must use `verify_no_replay()`, or both will fail
    /// deterministically on the shared process-local nonce cache. There is no
    /// such consumer today: everything downstream reads the map this populates
    /// rather than the message.
    pub fn handle_heartbeat(&self, hb: WorkerHeartbeat) -> anyhow::Result<()> {
        // 1. Verify signature, freshness and replay. `WORKER_HEARTBEAT_MAX_AGE_SECS`
        //    is the stated replay bound: outside it the message is refused on
        //    freshness; inside it the nonce cache refuses a second use.
        if let Err(e) = hb.verify(&self.shared_key, WORKER_HEARTBEAT_MAX_AGE_SECS) {
            return Err(anyhow::anyhow!(
                "Invalid heartbeat signature from worker {}: {}",
                hb.worker_id,
                e
            ));
        }

        // 2. Bound the map. Checked AFTER verification so an unsigned flood
        //    cannot burn the capacity budget, and only for ids we are not
        //    already tracking so a full map still refreshes the real fleet.
        if !self.workers.contains_key(&hb.worker_id) && self.workers.len() >= MAX_TRACKED_WORKERS {
            let n = self
                .capacity_drops
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // Log the first drop and then every 1000th: the flood case is
            // exactly when an unrated log line becomes its own DoS.
            if n == 0 || n % 1000 == 0 {
                tracing::warn!(
                    target: "talos_worker_fleet",
                    event_kind = "fleet_view_at_capacity",
                    cap = MAX_TRACKED_WORKERS,
                    drops = n + 1,
                    "worker fleet view is at capacity; heartbeats from NEW worker ids are \
                     being dropped. Tracked workers still refresh. If this is not an \
                     attack, the shared key is being used by more distinct worker ids \
                     than the fleet has."
                );
            }
            return Ok(());
        }

        // 3. Update the registry with the latest metrics and timestamp.
        self.workers.insert(
            hb.worker_id.clone(),
            WorkerState {
                heartbeat: hb,
                last_seen: Instant::now(),
            },
        );

        Ok(())
    }

    /// Returns a list of all currently active workers.
    pub fn get_active_workers(&self) -> Vec<WorkerHeartbeat> {
        self.workers
            .iter()
            .map(|kv| kv.value().heartbeat.clone())
            .collect()
    }

    /// Whether `worker_id` has heartbeated within the staleness window.
    ///
    /// **A `false` means "no heartbeat seen", NOT "that worker is gone".** A
    /// worker on a build that predates heartbeat publishing, or one whose
    /// heartbeats are dropped, is indistinguishable from a departed one. No
    /// caller may treat `false` as evidence of departure — see
    /// `controller::bootstrap::background::publish_worker_build_skew`, which
    /// declines to narrow its population for exactly this reason.
    pub fn has_recent_heartbeat(&self, worker_id: &str) -> bool {
        self.workers.contains_key(worker_id)
    }

    /// Returns a list of workers that possess a specific capability.
    pub fn get_workers_with_capability(&self, capability: &str) -> Vec<WorkerHeartbeat> {
        self.workers
            .iter()
            .filter(|kv| {
                kv.value()
                    .heartbeat
                    .capabilities
                    .contains(&capability.to_string())
            })
            .map(|kv| kv.value().heartbeat.clone())
            .collect()
    }

    /// Finds the "best" worker that satisfies all required capabilities.
    /// Returns None if no suitable worker is found.
    /// Currently uses a simple heuristic: lowest CPU usage.
    ///
    /// NO PRODUCTION CALLER. Job routing does not consult the fleet view;
    /// wiring it in is a scheduling change with its own blast radius and is
    /// deliberately a separate decision.
    pub fn find_best_worker(&self, required_caps: &[String]) -> Option<WorkerHeartbeat> {
        self.workers
            .iter()
            .filter(|kv| {
                let worker_caps = &kv.value().heartbeat.capabilities;
                // Check if worker has ALL required capabilities.
                required_caps.iter().all(|req| worker_caps.contains(req))
            })
            .min_by(|a, b| {
                // Heuristic: Pick the one with the lowest CPU usage.
                let cpu_a = a.value().heartbeat.cpu_usage_pct;
                let cpu_b = b.value().heartbeat.cpu_usage_pct;
                cpu_a
                    .partial_cmp(&cpu_b)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|kv| kv.value().heartbeat.clone())
    }

    /// Returns the number of currently registered workers.
    pub fn worker_count(&self) -> usize {
        self.workers.len()
    }

    /// The self-reported build string of every live worker, in no particular
    /// order and WITHOUT the identities they belong to.
    ///
    /// Deliberately anonymous. The one consumer is a metrics sweep, and
    /// `worker_id` is caller-supplied on the bus — handing it out beside a
    /// build string invites it into a metric label, which is unbounded
    /// cardinality driven by anyone holding the shared key. The comparison
    /// itself is done by the caller so this crate needs no dependency on the
    /// identity-registry crate (see
    /// [`tests::heartbeat_never_touches_the_trust_boundary`]).
    pub fn live_build_versions(&self) -> Vec<Option<String>> {
        self.workers
            .iter()
            .map(|kv| kv.value().heartbeat.build_version.clone())
            .collect()
    }

    /// Cumulative heartbeats refused because the map was at
    /// [`MAX_TRACKED_WORKERS`], since process start.
    pub fn capacity_drops(&self) -> u64 {
        self.capacity_drops
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The `worker_id`s heartbeating within the staleness window.
    ///
    /// **Set-membership use only.** These strings arrive over the bus under a
    /// fleet-shared key, so they are caller-supplied: they must never become a
    /// metric label, a log line's stable field, or a database key. The single
    /// consumer intersects them against rows the controller already has
    /// (`count_skewed_live_workers`) and emits only a COUNT.
    ///
    /// **An empty result means "nothing has been observed", NOT "no worker
    /// exists".** A caller that treats absence as departure must first
    /// establish that the view is populated at all — see
    /// `controller::bootstrap::background::heartbeat_silence_is_authoritative`
    /// for why even a populated view is not sufficient on its own.
    pub fn live_worker_ids(&self) -> std::collections::HashSet<String> {
        self.workers.iter().map(|kv| kv.key().clone()).collect()
    }

    /// Returns the fleet utilization as a fraction (0.0 – 1.0).
    ///
    /// Utilization is defined as the proportion of workers whose CPU usage
    /// exceeds the `busy_threshold_pct`.  Returns 0.0 when the fleet is empty.
    pub fn fleet_utilization(&self, busy_threshold_pct: f32) -> f64 {
        let total = self.workers.len();
        if total == 0 {
            return 0.0;
        }
        let busy = self
            .workers
            .iter()
            .filter(|kv| kv.value().heartbeat.cpu_usage_pct > busy_threshold_pct)
            .count();
        busy as f64 / total as f64
    }

    /// Returns `true` if the fleet is saturated (all workers above threshold).
    /// Useful for backpressure decisions.
    pub fn is_fleet_saturated(&self, busy_threshold_pct: f32) -> bool {
        if self.workers.is_empty() {
            return true; // No workers available at all.
        }
        self.workers
            .iter()
            .all(|kv| kv.value().heartbeat.cpu_usage_pct > busy_threshold_pct)
    }

    /// Removes workers that haven't sent a heartbeat within the specified duration.
    pub fn prune_stale(&self, max_age: Duration) {
        let now = Instant::now();
        let initial_count = self.workers.len();
        self.workers.retain(|_, state| {
            if now.duration_since(state.last_seen) >= max_age {
                tracing::info!("Pruning stale worker: {}", state.heartbeat.worker_id);
                false
            } else {
                true
            }
        });

        let pruned = initial_count - self.workers.len();
        if pruned > 0 {
            tracing::info!("Pruned {} stale workers from fleet", pruned);
        }
    }
}

/// Spawns the background tasks for heartbeat subscription and stale worker pruning.
pub async fn start_worker_management(
    manager: Arc<WorkerManager>,
    nats: async_nats::Client,
) -> anyhow::Result<()> {
    // 1. Subscribe to all worker heartbeats.
    // Workers publish to talos.workers.heartbeat.<worker_id>
    //
    // MCP-1120 (2026-05-16): supervisor loop re-binds the subscription
    // on stream-end. Sibling of MCP-1119 (audit-ledger JetStream
    // supervisor). Pre-fix the spawned task exited when
    // `subscriber.next()` returned None (NATS disconnect, subscription
    // dropped server-side, client reconnect window) → no new
    // heartbeats observed → the prune task at line ~181 still ran
    // → every worker appeared stale within `prune_stale` window
    // (60s) → worker manager thought the entire fleet was down →
    // orchestration broke until controller restart.
    //
    // The async-nats Client handles connection-level reconnects
    // transparently, but the per-subject Subscription is a separate
    // logical handle that can end (server-side unsubscribe, client
    // re-init). The supervisor re-binds on that boundary.
    let manager_hb = manager.clone();
    let nats_hb = nats.clone();
    tokio::spawn(async move {
        tracing::info!(
            target: "talos_worker_fleet",
            event_kind = "heartbeat_listener_started",
            subject = talos_workflow_job_protocol::subjects::WORKERS_HEARTBEAT_WILDCARD,
            stale_after_secs = STALE_AFTER.as_secs(),
            prune_interval_secs = PRUNE_INTERVAL.as_secs(),
            max_tracked_workers = MAX_TRACKED_WORKERS,
            "Worker heartbeat listener started"
        );
        let mut backoff_secs: u64 = 1;
        loop {
            let mut subscriber = match nats_hb
                .subscribe(talos_workflow_job_protocol::subjects::WORKERS_HEARTBEAT_WILDCARD)
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(
                        target: "talos_worker_fleet",
                        event_kind = "heartbeat_subscribe_failed",
                        error = %e,
                        backoff_secs,
                        "Worker-fleet heartbeat subscribe failed; retrying after backoff"
                    );
                    tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                    backoff_secs = (backoff_secs * 2).min(60);
                    continue;
                }
            };
            backoff_secs = 1;
            while let Some(msg) = subscriber.next().await {
                match serde_json::from_slice::<WorkerHeartbeat>(&msg.payload) {
                    Ok(hb) => {
                        if let Err(e) = manager_hb.handle_heartbeat(hb) {
                            tracing::warn!("Heartbeat verification failed: {}", e);
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to deserialize worker heartbeat: {}", e);
                    }
                }
            }
            tracing::warn!(
                target: "talos_worker_fleet",
                event_kind = "heartbeat_subscriber_rebinding",
                "Worker heartbeat subscriber stream ended; supervisor re-binding"
            );
            // Don't tight-loop if NATS is wedged.
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });

    // 2. Periodic pruning task. Combined with STALE_AFTER this is the stated
    //    eviction window: a worker that stops heartbeating leaves the view
    //    within STALE_AFTER + PRUNE_INTERVAL.
    let manager_prune = manager.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(PRUNE_INTERVAL);
        loop {
            interval.tick().await;
            manager_prune.prune_stale(STALE_AFTER);
        }
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x42; 32];

    fn signed(worker_id: &str, build: Option<&str>) -> WorkerHeartbeat {
        let mut hb = WorkerHeartbeat {
            worker_id: worker_id.to_string(),
            capabilities: vec!["wasm".to_string()],
            cpu_usage_pct: 10.0,
            build_version: build.map(str::to_string),
            signature: vec![],
            heartbeat_nonce: String::new(),
        };
        hb.sign(&KEY).unwrap();
        hb
    }

    /// **D5 — THE SECURITY BOUNDARY.** A heartbeat proves a process is
    /// running; a #631 liveness ping proves the KEY HOLDER is running. The
    /// heartbeat rides a FLEET-SHARED key, so if it could refresh trust, any
    /// shared-key holder could keep any worker's signing key trusted forever
    /// and the reaper would never act.
    ///
    /// Asserted structurally rather than behaviourally, because the honest
    /// claim is "this code CANNOT write to the trust boundary", not "this
    /// particular call did not". Two independent legs:
    ///  * the crate has no dependency it could reach the identity table
    ///    through (no sqlx, no worker-identity repository — the repository
    ///    crate is a dev-dependency for `builds_match` only... which would be
    ///    a hole, so the check is on the DEPENDENCIES table specifically);
    ///  * no source line in this crate names the trust-boundary column or its
    ///    writer.
    ///
    /// Structural lint check 67 enforces the same thing outside the test
    /// harness, so deleting this test does not silently reopen it.
    ///
    /// TWO SCOPE LIMITS, stated because a source scan is easy to over-read.
    /// (1) It stops at this file's `#[cfg(test)]` line — a rule that scans for
    /// forbidden strings necessarily CONTAINS them, and without the cut this
    /// test would fail on its own literals. So a write inside a test module is
    /// invisible here; that is the safe direction (test code is not production
    /// code) and check 67 makes the same cut for the same reason.
    /// (2) It is textual and single-crate, so a write reached through a
    /// re-exported alias, or performed by ANOTHER crate holding an
    /// `Arc<WorkerManager>`, would not show up. The dependency leg below is
    /// what turns that from "unlikely" into "has no path at all".
    #[test]
    fn heartbeat_never_touches_the_trust_boundary() {
        let full = include_str!("lib.rs");
        let production = full.split("\n#[cfg(test)]").next().unwrap_or(full);
        assert!(
            production.len() < full.len(),
            "the #[cfg(test)] cut point must exist, or this test silently scans \
             its own literals and can only ever fail"
        );
        for forbidden in ["last_liveness_at", "touch_liveness", "worker_identities"] {
            // The module header names them while explaining the rule; only
            // CODE lines are the concern.
            for (i, line) in production.lines().enumerate() {
                let t = line.trim_start();
                let is_comment = t.starts_with("//") || t.starts_with("*");
                assert!(
                    is_comment || !line.contains(forbidden),
                    "line {} writes to the trust boundary ({forbidden}): {line}",
                    i + 1
                );
            }
        }

        let manifest = include_str!("../Cargo.toml");
        let deps = manifest
            .split("[dependencies]")
            .nth(1)
            .expect("manifest has a [dependencies] section");
        let deps = deps.split("\n[").next().unwrap_or(deps);
        for forbidden in ["sqlx", "talos-worker-identity-repository", "reqwest"] {
            assert!(
                !deps.contains(forbidden),
                "talos-worker-fleet must not depend on {forbidden}: a heartbeat is minted \
                 under a fleet-shared key and must never be able to reach the identity \
                 registry"
            );
        }
    }

    /// The verify-once rule (CLAUDE.md): exactly one primary `verify()` caller
    /// per signed message per process. Two would fail deterministically on the
    /// shared nonce cache — the r300/r301 total outage.
    ///
    /// This crate is where the controller's only `WorkerHeartbeat` consumer
    /// lives, so "one call site here" is the whole of the rule for that
    /// message type today. It is not a workspace-wide guarantee: a future
    /// second consumer in another crate must use `verify_no_replay()`, and the
    /// only thing that catches a mistake there is review.
    ///
    /// Scanned over the production half only, for the same reason as the test
    /// above — the predicate below necessarily contains the string it looks
    /// for.
    #[test]
    fn exactly_one_primary_verify_call_site() {
        let full = include_str!("lib.rs");
        let production = full.split("\n#[cfg(test)]").next().unwrap_or(full);
        let primary = production
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                !t.starts_with("//") && t.contains("hb.verify(")
            })
            .count();
        assert_eq!(
            primary, 1,
            "WorkerHeartbeat must have exactly one primary verify() caller; a passive \
             observer uses verify_no_replay()"
        );
    }

    #[tokio::test]
    async fn tracks_a_worker_by_its_text_id() {
        let m = WorkerManager::new(KEY.to_vec());
        m.handle_heartbeat(signed("dev-worker-fleet", Some("0.1.0+abc1234")))
            .unwrap();
        assert!(m.has_recent_heartbeat("dev-worker-fleet"));
        assert_eq!(m.get_active_workers()[0].worker_id, "dev-worker-fleet");
    }

    #[tokio::test]
    async fn refuses_a_heartbeat_signed_with_the_wrong_key() {
        let m = WorkerManager::new(vec![0x01; 32]);
        assert!(m.handle_heartbeat(signed("w1", None)).is_err());
        assert_eq!(m.worker_count(), 0);
    }

    #[tokio::test]
    async fn the_map_is_bounded_and_reports_its_drops() {
        let m = WorkerManager::new(KEY.to_vec());
        for i in 0..MAX_TRACKED_WORKERS {
            m.handle_heartbeat(signed(&format!("w{i}"), None)).unwrap();
        }
        assert_eq!(m.worker_count(), MAX_TRACKED_WORKERS);

        // A NEW id at the cap is dropped...
        m.handle_heartbeat(signed("overflow", None)).unwrap();
        assert_eq!(m.worker_count(), MAX_TRACKED_WORKERS);
        assert!(!m.has_recent_heartbeat("overflow"));
        assert_eq!(m.capacity_drops(), 1);

        // ...but an ALREADY-TRACKED id still refreshes, so a flood cannot
        // blind the view to the real fleet.
        m.handle_heartbeat(signed("w0", None)).unwrap();
        assert!(m.has_recent_heartbeat("w0"));
    }

    #[tokio::test]
    async fn a_worker_that_stops_heartbeating_leaves_the_view() {
        let m = WorkerManager::new(KEY.to_vec());
        m.handle_heartbeat(signed("w1", None)).unwrap();
        // Nothing is evicted before the window...
        m.prune_stale(Duration::from_secs(3600));
        assert_eq!(m.worker_count(), 1);
        // ...and everything is once it elapses.
        m.prune_stale(Duration::from_secs(0));
        assert_eq!(m.worker_count(), 0);
    }

    /// The build accessor hands out builds WITHOUT the identities they belong
    /// to. That is the anti-cardinality rule made structural: a caller that
    /// never receives `worker_id` cannot label a metric with it.
    #[tokio::test]
    async fn live_build_versions_are_anonymous() {
        let m = WorkerManager::new(KEY.to_vec());
        m.handle_heartbeat(signed("same", Some("0.1.0+aaaaaaa")))
            .unwrap();
        m.handle_heartbeat(signed("no-build", None)).unwrap();

        let mut builds = m.live_build_versions();
        builds.sort();
        assert_eq!(builds, vec![None, Some("0.1.0+aaaaaaa".to_string())]);
    }
}
