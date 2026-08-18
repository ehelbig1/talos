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
//!   are visible" rather than to eviction churn of the real fleet. State that
//!   precisely: what a flood cannot displace is the ALREADY-TRACKED fleet. A
//!   worker that boots, is renamed, or is rescheduled DURING a flood presents
//!   a new id and is refused like any other, so it stays invisible until the
//!   flood ages out — which is why `capacity_drops` is exported as a gauge
//!   rather than only logged.
//! * **Staleness prune** every [`PRUNE_INTERVAL`], removing entries not seen
//!   within [`STALE_AFTER`]. A worker that stops heartbeating therefore leaves
//!   the view within `STALE_AFTER + PRUNE_INTERVAL` (90s at defaults) — the
//!   window quoted anywhere this view's freshness is described.
//!
//! Neither bound is LRU: entries leave only by going stale or by the process
//! restarting. That is deliberate — an LRU keyed on caller-supplied ids lets a
//! flood evict the real fleet, which is worse than refusing the flood.
//!
//! # Two maps, and why the second one exists (2026-08)
//!
//! [`WorkerManager`] keeps a SECOND, observability-only map keyed on the
//! reported BUILD rather than on `worker_id`. It exists because the first map
//! cannot answer "is some running process on a different build than the
//! controller?" whenever replicas share one `worker_id` — the posture the
//! chart writes out inline (`TALOS_WORKER_ID: "fleet"`) and the one the dev
//! stack runs.
//!
//! The mechanism, stated exactly, because the imprecise version of it is
//! wrong. `handle_heartbeat` ends in `workers.insert(worker_id, …)`, so on a
//! shared id every replica overwrites the same entry: the map retains ONE
//! build, whichever replica spoke last. A per-`worker_id` skew count over that
//! map therefore ALTERNATES on a mixed-build fleet — 1 when the skewed replica
//! wrote last, 0 when the matching one did — and an alert with a `for:`
//! duration needs its condition to hold CONTINUOUSLY, so the timer resets
//! forever. **Be precise about the scope of that defect**: a UNIFORMLY skewed
//! fleet (every replica on one build that differs from the controller's) reads
//! steadily 1 and alerts correctly. The unfireable case is the MIXED one — a
//! roll that got stuck partway, which is exactly what a version-coupled
//! signing incident looks like.
//!
//! No counting function can repair that, because the second build is destroyed
//! at insert time, before anything gets to count it. Retention is the fix, so
//! the build observations are retained separately. Keying the PRIMARY map on
//! `(worker_id, build)` was rejected: it would move [`WorkerManager::worker_count`],
//! which is the scheduler's dispatch barrier.
//!
//! The build map carries the same two bounds for the same reason — its key is
//! also caller-supplied — with one addition. `WorkerHeartbeat.build_version`
//! has NO charset or length validation of its own (unlike `worker_id`, which
//! `validate_worker_id` gates before the MAC), so a value is normalised
//! through [`well_formed_build_key`] before it can become a key. Signing bounds
//! WHO can inflate this map to holders of the fleet-shared key; it does not
//! bound HOW MUCH, which is what [`MAX_TRACKED_BUILDS`] is for. This is not a
//! new trust boundary — the same holder already floods the `worker_id` map and
//! already inflates the same gauges — it is a second key space with the same
//! property, and it is bounded the same way.
//!
//! # The `None` bucket, and what a reader may NOT conclude from it
//!
//! [`WorkerManager::live_distinct_builds`] returns `Option<String>`, and the
//! `None` element is a REAL observation: some process heartbeated and reported
//! no build this crate could use. Its consumer splits the population three
//! ways — provably skewed, unverifiable, and agreeing — and `None` always
//! lands in UNVERIFIABLE, never in skewed. That direction is deliberate (#578:
//! absence of evidence is not evidence of skew) and it creates a trap on the
//! way out:
//!
//! **A zero skew count over a population containing an unverifiable bucket is
//! not a clean bill of health.** "0 skewed of 2 live builds" describes a fleet
//! in which one of the two builds was never checked. An absence rendered as a
//! negative result is the failure this whole area of the repo exists to stop,
//! so the unverifiable count is exported as its own series
//! (`talos_worker_fleet_unverifiable_builds`) rather than being folded away —
//! the denominator includes it, so it must be visible beside it. The three
//! series decompose exactly: `live_builds == skew + unverifiable + agreeing`.
//!
//! Concretely, when the unverifiable count is non-zero a reader MAY conclude
//! "at least that many distinct builds are running that I could not compare",
//! and MAY NOT conclude anything about whether they match. When it EQUALS
//! `live_builds`, no comparison was possible at all — which happens for every
//! observed build at once if THIS CONTROLLER's own build has no usable sha, so
//! it is as often a statement about the controller as about the fleet.

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

/// Maximum distinct build values tracked at once in the build-keyed map.
///
/// Deliberately FAR smaller than [`MAX_TRACKED_WORKERS`], because the honest
/// organic maximum is tiny: a healthy fleet has 1, a fleet mid-roll has 2, a
/// pathological one that stacked three rollouts has 3. 64 leaves an order of
/// magnitude of headroom over anything real while keeping the flood ceiling
/// low — and unlike the worker map, a full build map does not hide a worker:
/// its only consumer is a COUNT of builds, so saturation is visible in
/// `talos_worker_fleet_capacity_dropped_builds` and nothing else degrades.
pub const MAX_TRACKED_BUILDS: usize = 64;

/// Longest build string that may become a key in the build map.
///
/// Matches the `validate_worker_id` bound (128) on purpose: the same argument
/// applies to both, and picking a different number here would invite the
/// question of which one is right.
pub const MAX_BUILD_VERSION_LEN: usize = 128;

/// Whether a reported build may be used verbatim as a key in the build map.
///
/// The charset is `validate_worker_id`'s plus `+`, which real build strings
/// need (`{version}+{sha}[-dirty]`). A value failing this is NOT discarded —
/// discarding would make the worker that sent it vanish from the builds view
/// entirely — it is folded into the `None` ("no usable build reported")
/// bucket, where it is counted as UNVERIFIABLE rather than as skew. That is
/// the safe direction in both senses: a malformed build cannot fabricate skew,
/// and it cannot hide a worker either. Every malformed value collapses onto
/// that one key, so this is also what bounds the key LENGTH — no caller-
/// supplied string longer than [`MAX_BUILD_VERSION_LEN`] is ever retained.
pub fn well_formed_build_key(build: &str) -> bool {
    !build.is_empty()
        && build.len() <= MAX_BUILD_VERSION_LEN
        && build
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+'))
}

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
    /// Reported BUILD → when that build was last observed, over the same
    /// staleness window as `workers`. See the module header: this map exists
    /// because `workers` is last-write-wins on `worker_id`, so on a shared-id
    /// fleet it retains only one of the builds actually running.
    ///
    /// `None` is a real key — "a worker heartbeated and reported no usable
    /// build" — and every malformed value collapses onto it (see
    /// [`well_formed_build_key`]). It is deliberately NOT an absence.
    ///
    /// The same absent-field note applies as for `workers`: no pool, no
    /// repository, no HTTP client. Nothing here may write
    /// `worker_identities.last_liveness_at`.
    builds: DashMap<Option<String>, Instant>,
    /// Build observations refused because the build map was at
    /// [`MAX_TRACKED_BUILDS`]. Separate from `capacity_drops` on purpose —
    /// conflating two different refusal causes into one number is the
    /// misleading-report-field defect this whole area exists to remove.
    build_capacity_drops: std::sync::atomic::AtomicU64,
}

impl WorkerManager {
    /// Creates a new WorkerManager with the given shared secret key.
    pub fn new(shared_key: Vec<u8>) -> Self {
        Self {
            workers: DashMap::new(),
            shared_key,
            capacity_drops: std::sync::atomic::AtomicU64::new(0),
            builds: DashMap::new(),
            build_capacity_drops: std::sync::atomic::AtomicU64::new(0),
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
            // The id is echoed ONLY once `validate_worker_id` has accepted it
            // — bounded to MAX_WORKER_ID_LEN and to `[A-Za-z0-9._-]`, so it
            // cannot inject newlines into the log or carry a megabyte of bus
            // payload into it. `verify()` runs that charset check FIRST, so a
            // rejected id is exactly the one we must not print; the caller
            // gets its length instead, which is the diagnostic that matters.
            let id_is_wellformed =
                talos_workflow_job_protocol::validate_worker_id(&hb.worker_id).is_ok();
            return Err(if id_is_wellformed {
                anyhow::anyhow!("Invalid heartbeat from worker {}: {e}", hb.worker_id)
            } else {
                anyhow::anyhow!(
                    "Invalid heartbeat from a malformed worker_id ({} bytes, not echoed): {e}",
                    hb.worker_id.len()
                )
            });
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
            if n == 0 || n.is_multiple_of(1000) {
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
        let now = Instant::now();
        self.record_build_observation(hb.build_version.as_deref(), now);
        self.workers.insert(
            hb.worker_id.clone(),
            WorkerState {
                heartbeat: hb,
                last_seen: now,
            },
        );

        Ok(())
    }

    /// Record that SOME process is running `build`, in the map that survives
    /// the `worker_id` collision.
    ///
    /// Reached only after the heartbeat has verified AND passed the worker-map
    /// capacity gate: a heartbeat refused there is refused entirely, so a
    /// flood cannot spend the worker budget and the build budget at once.
    ///
    /// A malformed or over-long build is folded into the `None` bucket rather
    /// than dropped — see [`well_formed_build_key`] for why that is the safe
    /// direction — so the key space this map can ever hold is
    /// `{None} ∪ {well-formed strings ≤ MAX_BUILD_VERSION_LEN}`, capped at
    /// [`MAX_TRACKED_BUILDS`].
    fn record_build_observation(&self, build: Option<&str>, now: Instant) {
        let key: Option<String> = match build {
            Some(b) if well_formed_build_key(b) => Some(b.to_string()),
            // Reported nothing, reported "", or reported something that must
            // not become a key: all are "no usable build", i.e. unverifiable.
            _ => None,
        };

        // Same bound shape as the worker map: at the cap a NEW key is refused
        // while tracked keys keep refreshing, so saturation degrades to "no
        // new build is visible" rather than to eviction churn of the real
        // ones. Not LRU, for the same reason.
        if !self.builds.contains_key(&key) && self.builds.len() >= MAX_TRACKED_BUILDS {
            let n = self
                .build_capacity_drops
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if n == 0 || n.is_multiple_of(1000) {
                tracing::warn!(
                    target: "talos_worker_fleet",
                    event_kind = "fleet_build_view_at_capacity",
                    cap = MAX_TRACKED_BUILDS,
                    drops = n + 1,
                    // The build string itself is NOT logged. It is
                    // caller-supplied under the fleet-shared key, and a
                    // rate-limited log line is still a log line.
                    "worker fleet BUILD view is at capacity; observations of NEW build \
                     values are being dropped. Tracked builds still refresh. A real \
                     fleet has one build, or two mid-roll — this many distinct values \
                     means the shared key is being used to publish fabricated ones."
                );
            }
            return;
        }

        self.builds.insert(key, now);
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

    /// The DISTINCT builds observed within the staleness window — the
    /// population every `talos_worker_fleet_*_builds` gauge is computed over.
    ///
    /// **Use this, not [`Self::live_build_versions`], for skew detection.**
    /// That one is per-tracked-`worker_id` and so retains only the last
    /// writer's build when replicas share an id; this one retains every build
    /// that was actually observed. On a mixed-build shared-id fleet the former
    /// alternates and the latter is steady, which is the whole reason this
    /// method exists (module header).
    ///
    /// Anonymous for the same reason as its sibling: no `worker_id` comes out,
    /// so a caller-supplied string cannot become a metric label. What DOES
    /// come out is the caller-supplied BUILD string — also never a label, and
    /// bounded on the way in by [`well_formed_build_key`].
    ///
    /// **This is a count of BUILDS, not of processes.** Five workers on one
    /// skewed build are one element here. Detection is unaffected (the alert
    /// asks `> 0`); the MAGNITUDE is not recoverable from it.
    pub fn live_distinct_builds(&self) -> Vec<Option<String>> {
        self.builds.iter().map(|kv| kv.key().clone()).collect()
    }

    /// Cumulative build observations refused because the build map was at
    /// [`MAX_TRACKED_BUILDS`], since process start. Distinct from
    /// [`Self::capacity_drops`], which counts heartbeats refused by the
    /// WORKER map.
    pub fn build_capacity_drops(&self) -> u64 {
        self.build_capacity_drops
            .load(std::sync::atomic::Ordering::Relaxed)
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
    ///
    /// Prunes BOTH maps on the same tick and against the same `max_age`, so a
    /// build cannot outlive the workers that reported it: were the build map
    /// pruned more slowly, a rolled-away build would keep the skew alert
    /// firing after the fleet was fixed, which is the failure the `for:`
    /// duration is supposed to prevent.
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

        // The build value is NOT logged (caller-supplied under a shared key);
        // the count is.
        let builds_before = self.builds.len();
        self.builds
            .retain(|_, last_seen| now.duration_since(*last_seen) < max_age);
        let builds_pruned = builds_before - self.builds.len();
        if builds_pruned > 0 {
            tracing::info!("Pruned {} stale builds from fleet view", builds_pruned);
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
    ///    through — no sqlx, no worker-identity repository, no HTTP client.
    ///    (The scan is deliberately on the `[dependencies]` table only. This
    ///    crate happens to have no `[dev-dependencies]` section at all, so
    ///    today the distinction is moot; it is written this way so that
    ///    ADDING one for a test helper cannot quietly re-open the path, and
    ///    so the assertion keeps meaning the same thing if it does.)
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
    ///
    /// THREE SCOPE LIMITS, two of which were holes until they were closed by
    /// mutation during review; stating them is the point, since a guard
    /// believed to be tighter than it is, is worse than a loose one.
    /// (1) It matched the literal receiver name `hb.verify(`, so a second
    /// call site on a differently-named binding (`beat.verify(`) was
    /// invisible. Now it matches `.verify(` on any receiver — which does NOT
    /// also match `verify_no_replay(`, because the paren must follow
    /// `verify` immediately, so the passive-observer entry point stays legal.
    /// (2) It counted LINES, so two calls on one line read as one. It now
    /// counts occurrences.
    /// (3) It reads THIS FILE only, via `include_str!`. A second file in this
    /// crate would be invisible, so the crate being single-file is asserted
    /// directly below rather than assumed — adding a `mod` fails here and
    /// forces the scan to be widened (structural lint check 67 already scans
    /// the whole `src/` directory and is the model to copy).
    #[test]
    fn exactly_one_primary_verify_call_site() {
        let full = include_str!("lib.rs");
        let production = full.split("\n#[cfg(test)]").next().unwrap_or(full);

        for (i, line) in production.lines().enumerate() {
            let t = line.trim_start();
            assert!(
                !(t.starts_with("mod ") || t.starts_with("pub mod ")),
                "line {}: this crate gained a second source file, which this test \
                 cannot see — widen the scan before adding it: {line}",
                i + 1
            );
        }

        let primary: usize = production
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .map(|l| l.matches(".verify(").count())
            .sum();
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
    /// **THE ACCEPTANCE CASE: a simulated mixed-build shared-id fleet.**
    ///
    /// This is the honest substitute for a two-build deployment, which cannot
    /// be observed on the dev stack because both replicas run the same build.
    /// It drives the exact shape a stuck rolling deploy produces — two
    /// processes, ONE `worker_id` (the posture the chart writes out inline),
    /// two different builds — and asserts BOTH halves of the claim:
    ///
    ///   * the OLD per-`worker_id` population alternates, so a `> 0` alert
    ///     with a `for:` duration on it can never hold; and
    ///   * the NEW build-keyed population is steady across the same
    ///     alternation, so the same alert can.
    ///
    /// Proving only the second half would leave "the old one could not fire"
    /// asserted rather than demonstrated.
    #[tokio::test]
    async fn a_mixed_build_shared_id_fleet_flaps_per_id_but_is_steady_per_build() {
        const ID: &str = "dev-worker-fleet";
        const CONTROLLER: &str = "0.1.0+aaaaaaa";
        const ROLLED: &str = "0.1.0+bbbbbbb";

        let m = WorkerManager::new(KEY.to_vec());

        // Ten publish rounds of two replicas sharing one id, alternating which
        // one wrote last. A real fleet's ordering is arbitrary; alternating is
        // the clearest way to show the per-id view changing under a fleet that
        // is not changing.
        let mut per_id_readings = Vec::new();
        for round in 0..10 {
            let (first, second) = if round % 2 == 0 {
                (CONTROLLER, ROLLED)
            } else {
                (ROLLED, CONTROLLER)
            };
            m.handle_heartbeat(signed(ID, Some(first))).unwrap();
            m.handle_heartbeat(signed(ID, Some(second))).unwrap();

            // The worker map holds exactly one entry the whole time: the
            // shared id collapses both replicas onto it.
            assert_eq!(m.worker_count(), 1, "round {round}");

            let per_id = m.live_build_versions();
            assert_eq!(per_id.len(), 1, "round {round}: one id, one entry");
            per_id_readings.push(per_id[0].clone());
        }

        // OLD SHAPE. The retained build is whichever replica spoke last, so a
        // sweep sampling this population sees the skewed build only some of
        // the time. A gauge derived from it is therefore not continuously
        // non-zero, and `expr > 0` + `for: 30m` cannot be satisfied.
        assert!(
            per_id_readings.iter().any(|b| b.as_deref() == Some(ROLLED))
                && per_id_readings
                    .iter()
                    .any(|b| b.as_deref() == Some(CONTROLLER)),
            "the per-id population must be shown ALTERNATING, otherwise this \
             test does not demonstrate why the old gauge could not hold a for:"
        );

        // NEW SHAPE. Both builds are retained regardless of write order, so
        // the skewed build is present on EVERY sample, not some of them.
        let mut distinct = m.live_distinct_builds();
        distinct.sort();
        assert_eq!(
            distinct,
            vec![Some(CONTROLLER.to_string()), Some(ROLLED.to_string())],
            "the build-keyed population must retain BOTH builds"
        );

        // And it is steady: re-sampling after either replica writes again
        // returns the same set. This is the property the `for:` needs.
        for round in 0..4 {
            let last = if round % 2 == 0 { CONTROLLER } else { ROLLED };
            m.handle_heartbeat(signed(ID, Some(last))).unwrap();
            let mut d = m.live_distinct_builds();
            d.sort();
            assert_eq!(
                d,
                vec![Some(CONTROLLER.to_string()), Some(ROLLED.to_string())],
                "round {round}: the build population must not depend on write order"
            );
        }
    }

    /// A UNIFORMLY skewed shared-id fleet was never the broken case, and
    /// saying so is the difference between an accurate defect report and an
    /// overstated one. Every replica on one non-controller build retains ONE
    /// build, steadily — the old gauge held its `for:` here and the new one
    /// must too.
    #[tokio::test]
    async fn a_uniformly_skewed_fleet_was_already_steady_and_stays_steady() {
        let m = WorkerManager::new(KEY.to_vec());
        for _ in 0..6 {
            m.handle_heartbeat(signed("dev-worker-fleet", Some("0.1.0+bbbbbbb")))
                .unwrap();
            assert_eq!(m.live_build_versions().len(), 1);
            assert_eq!(
                m.live_distinct_builds(),
                vec![Some("0.1.0+bbbbbbb".to_string())]
            );
        }
    }

    /// The build map is bounded and reports its own drops, and its counter is
    /// SEPARATE from the worker map's — one number covering two different
    /// refusal causes is the misleading-report-field defect.
    #[tokio::test]
    async fn the_build_map_is_bounded_and_reports_its_drops_separately() {
        let m = WorkerManager::new(KEY.to_vec());
        // One id, many distinct builds: this is the flood shape the worker-map
        // cap cannot see, because the worker map has exactly one entry.
        for i in 0..MAX_TRACKED_BUILDS + 50 {
            m.handle_heartbeat(signed("w", Some(&format!("9.9.9+bui{i:04}"))))
                .unwrap();
        }
        assert_eq!(m.worker_count(), 1, "the worker cap never engages here");
        assert_eq!(m.live_distinct_builds().len(), MAX_TRACKED_BUILDS);
        assert_eq!(m.build_capacity_drops(), 50);
        assert_eq!(
            m.capacity_drops(),
            0,
            "a build-map refusal must not be reported as a worker-map refusal"
        );
    }

    /// A malformed or over-long build is folded into the `None` bucket, never
    /// retained verbatim. Two properties at once: the key space stays bounded
    /// in LENGTH, and the worker does not VANISH from the builds view (it is
    /// counted unverifiable, which is what "we saw a process and cannot
    /// compare its build" means).
    #[tokio::test]
    async fn a_malformed_build_becomes_unverifiable_not_a_key() {
        let m = WorkerManager::new(KEY.to_vec());
        let huge = "0.1.0+".to_string() + &"a".repeat(MAX_BUILD_VERSION_LEN);
        m.handle_heartbeat(signed("w1", Some(&huge))).unwrap();
        m.handle_heartbeat(signed("w2", Some("has space and \n newline")))
            .unwrap();
        m.handle_heartbeat(signed("w3", Some(""))).unwrap();
        m.handle_heartbeat(signed("w4", None)).unwrap();

        assert_eq!(
            m.live_distinct_builds(),
            vec![None],
            "every unusable value collapses onto the one unverifiable key"
        );
        assert!(well_formed_build_key("0.1.0+abc1234-dirty"));
        assert!(!well_formed_build_key(&huge));
        assert!(!well_formed_build_key(""));
    }

    /// Both maps prune on the same tick against the same window. A build that
    /// outlived its workers would keep the skew alert firing after the fleet
    /// was rolled — the exact failure a `for:` duration exists to prevent.
    #[tokio::test]
    async fn pruning_clears_the_build_view_too() {
        let m = WorkerManager::new(KEY.to_vec());
        m.handle_heartbeat(signed("w", Some("0.1.0+aaaaaaa")))
            .unwrap();
        m.handle_heartbeat(signed("w", Some("0.1.0+bbbbbbb")))
            .unwrap();
        assert_eq!(m.live_distinct_builds().len(), 2);

        m.prune_stale(Duration::from_secs(3600));
        assert_eq!(m.live_distinct_builds().len(), 2, "still fresh");

        m.prune_stale(Duration::from_secs(0));
        assert_eq!(m.worker_count(), 0);
        assert!(
            m.live_distinct_builds().is_empty(),
            "a stale build must leave the view with its workers"
        );
    }

    /// PINS THE ORDERING CLAIM, which a doc comment alone cannot hold: a
    /// heartbeat refused by the WORKER-map capacity gate must not still spend
    /// the BUILD budget. If `record_build_observation` were ever hoisted above
    /// that gate's early return, one flood would consume both bounds at once.
    #[tokio::test]
    async fn a_heartbeat_refused_at_the_worker_cap_never_reaches_the_build_map() {
        let m = WorkerManager::new(KEY.to_vec());
        for i in 0..MAX_TRACKED_WORKERS {
            m.handle_heartbeat(signed(&format!("w{i}"), Some("0.1.0+aaaaaaa")))
                .unwrap();
        }
        assert_eq!(
            m.live_distinct_builds(),
            vec![Some("0.1.0+aaaaaaa".to_string())]
        );

        // A NEW id at the cap: refused, and its build must be refused with it.
        m.handle_heartbeat(signed("overflow", Some("0.1.0+bbbbbbb")))
            .unwrap();
        assert_eq!(m.capacity_drops(), 1);
        assert_eq!(
            m.live_distinct_builds(),
            vec![Some("0.1.0+aaaaaaa".to_string())],
            "a heartbeat dropped at the worker cap must not register a build"
        );
        assert_eq!(m.build_capacity_drops(), 0, "that is not a build-cap drop");
    }

    /// The `None` bucket is a real element of the population, so a caller
    /// splitting it three ways gets a total that adds up. This is the shape
    /// the gauges rely on: an unverifiable build sits in the DENOMINATOR, so
    /// it must also be visible in its own numerator or a 0 skew reads as a
    /// clean bill of health over something never checked.
    #[tokio::test]
    async fn an_unverifiable_build_stays_in_the_population_as_its_own_bucket() {
        let m = WorkerManager::new(KEY.to_vec());
        m.handle_heartbeat(signed("w1", Some("0.1.0+aaaaaaa")))
            .unwrap();
        m.handle_heartbeat(signed("w2", Some("0.1.0+bbbbbbb")))
            .unwrap();
        m.handle_heartbeat(signed("w3", None)).unwrap();

        let population = m.live_distinct_builds();
        assert_eq!(population.len(), 3, "None is an element, not an absence");
        assert!(
            population.contains(&None),
            "an unreported build must remain visible to the consumer that \
             classifies it, rather than being silently dropped"
        );
    }

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
