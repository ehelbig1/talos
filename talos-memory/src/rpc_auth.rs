//! Shared HMAC auth for talos-memory's NATS-RPC surface.
//!
//! Every RPC request carries an HMAC-SHA256 signature over
//! `subject || actor_id || nonce || canonical_body`. The key is the
//! same `WORKER_SHARED_KEY` used by `talos_workflow_job_protocol` for `JobRequest`
//! signing, registered once at process startup on both sides.
//!
//! ## Why this exists
//!
//! Without it, any process that can publish to the NATS bus can issue
//! a memory/graph/database/state request for any `actor_id`. The
//! worker runs arbitrary guest WASM, so a compromised sandbox could
//! otherwise forge cross-tenant queries. The signature is verified
//! on the controller side before the request touches any state.
//!
//! ## Design invariants
//!
//! - **Canonical bytes, not JSON.** RPC request types serialize their
//!   bodies via `#[derive(Serialize)]` structs with fixed field
//!   declaration order — never `serde_json::json!({...})`, because
//!   that produces a `Value::Object` whose byte encoding depends on
//!   whether the `preserve_order` feature is enabled in the dep
//!   graph. Using structs pins the order at compile time.
//! - **Subject binding.** `subject` is a const `SUBJECT_NAME` per
//!   RPC type (e.g. `"memory_rpc"`), included in the MAC input so a
//!   valid memory signature cannot be replayed as a graph request.
//! - **Actor binding.** `actor_id` is in the MAC input; cross-actor
//!   replay is rejected even for the same subject.
//! - **Freshness.** Every request carries a `timestamp_ms` field
//!   inside the signed body; subscribers reject requests older than
//!   [`PAST_WINDOW_MS`] (60 s), and reject future-dated requests
//!   beyond [`FUTURE_WINDOW_MS`] (5 s) so a compromised worker can't
//!   grant itself a bigger replay window by signing into the future.
//!   Combined with the per-subject
//!   timeouts this keeps the practical replay window to seconds.
//! - **Constant-time verify.** `verify` uses `subtle::ConstantTimeEq`
//!   — timing side-channels here would let an attacker bias MAC
//!   bytes.
//!
//! ## Key rotation
//!
//! [`register_hmac_key`] uses `OnceLock::set` and is **idempotent**:
//! subsequent calls after the first are silently ignored. This means
//! rotating `WORKER_SHARED_KEY` requires restarting both the
//! controller and the worker. Live rotation is intentionally not
//! supported — a rotation that lands on one side but not the other
//! would break every in-flight RPC.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// Maximum age of a request we'll accept at the controller. 60 s is
/// comfortably longer than any legitimate NATS round-trip plus worker-
/// side queueing, while short enough to bound replay.
pub const PAST_WINDOW_MS: i64 = 60_000;
/// Maximum *future* skew we'll tolerate. Tight because worker + controller
/// sit on the same NATS cluster and should be within seconds of each
/// other via NTP. A larger future window would extend the effective
/// replay window (once a future-dated signature becomes current, it
/// stays valid through PAST_WINDOW_MS).
pub const FUTURE_WINDOW_MS: i64 = 5_000;

/// Current wall-clock ms since Unix epoch. Returns 0 on catastrophic
/// clock failure (pre-1970) — `verify_freshness` treats 0 as always
/// stale, so that degrades safely.
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// True when `timestamp_ms` is within the accepted window. We allow
/// [`PAST_WINDOW_MS`] in the past (for legitimate latency/queueing)
/// and only [`FUTURE_WINDOW_MS`] in the future (clock skew tolerance).
/// Asymmetry matters: a symmetric window would let an attacker
/// pre-date a signature `+W` into the future and replay it for
/// `W + PAST_WINDOW_MS` total, doubling the effective replay window.
pub fn verify_freshness(timestamp_ms: i64) -> bool {
    if timestamp_ms <= 0 {
        return false;
    }
    let now = now_ms();
    let delta = now - timestamp_ms;
    (-FUTURE_WINDOW_MS..=PAST_WINDOW_MS).contains(&delta)
}

// ============================================================================
// Nonce replay cache (two-generation, sharded)
// ============================================================================
//
// The signature + freshness window proves a request was minted by the
// HMAC-key holder within `PAST_WINDOW_MS`. But without nonce tracking,
// an attacker who captures one signed request can replay it N times
// within that window (60 s). For write operations (`Set`, `Delete`,
// state writes, UPDATE queries) replay is a real exposure.
//
// ## Design
//
// **Two-generation rotating maps.** Eviction by full scan is O(n)
// per insert; under sustained load the scan dominates RPC latency.
// Instead we keep two `DashMap`s — `current` and `previous` — and
// rotate them every `PAST_WINDOW_MS` (the full freshness window). On
// lookup we check both; on insert we write to `current`. Every
// rotation drops `previous` in O(1) and promotes `current` to
// `previous`.
//
// **Lifetime invariant (replay-coverage).** An entry inserted at time
// `t` is dropped only after it has been `previous` for a full rotation
// interval. Worst case — inserted an instant before a rotation — it is
// promoted to `previous` immediately and then survives until the NEXT
// rotation, i.e. one full `PAST_WINDOW_MS`. Best case — inserted just
// after a rotation — it stays in `current` for one interval, then in
// `previous` for another, i.e. `2 * PAST_WINDOW_MS`. So every entry
// lives between `PAST_WINDOW_MS` (60 s) and `2 * PAST_WINDOW_MS`
// (120 s) before being dropped.
//
// Because the guaranteed MINIMUM lifetime (60 s) >= the freshness
// window (`PAST_WINDOW_MS` = 60 s) that `verify_freshness` accepts, a
// captured request can NEVER be both (a) still fresh enough to pass
// `verify_freshness` AND (b) already evicted from both generations.
// No replay is admitted within the freshness window. (Earlier this
// rotated every `PAST_WINDOW_MS / 2`, which dropped pre-rotation
// entries after only ~30 s while freshness still accepted them to
// 60 s — leaving a ~30 s replay band. Fixed by widening residency to
// the full window rather than shrinking the freshness window, which
// preserves the documented 60 s no-replay invariant.)
//
// **Memory stays bounded.** `NONCE_CACHE_MAX_ENTRIES` caps each
// generation regardless of the rotation interval, so the cache holds
// at most `2 * NONCE_CACHE_MAX_ENTRIES` entries at any instant.
// Doubling per-generation residency (30 s → 60 s) does NOT make the
// cache unbounded — it only means a generation can fill closer to its
// cap before being dropped; the cap itself is unchanged.
//
// **DashMap, not Mutex<HashMap>.** A single global `Mutex` would
// serialize every RPC across all four subscribers. `DashMap`
// provides sharded internal locks so concurrent writes that hit
// different shards don't contend.
//
// Keyed by `(subject, actor_id, nonce)`. Nonces are 16-byte random
// hex — collision across actors is astronomical (2^64 preimage) so
// keying by actor is defense-in-depth, not strictly required.

use arc_swap::ArcSwap;
use dashmap::DashMap;
use std::time::{Duration, Instant};

/// Upper bound on concurrently-tracked nonces *per generation*. With
/// two generations we accommodate up to 2× this count at peak.
const NONCE_CACHE_MAX_ENTRIES: usize = 50_000;

/// L-2: process-lifetime counter of cap-hit rejections from the nonce
/// cache. Operators check via [`nonce_cache_stats`] alongside the
/// structured `event_kind = "nonce_cache_cap_hit"` event emitted on
/// every increment. Atomic + Relaxed because the metric is a tally,
/// not a synchronisation point.
static NONCE_CACHE_REJECTIONS_TOTAL: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// L-2: snapshot the nonce-cache cap-hit counter. Returns
/// `(rejections_total, configured_cap)`. Callers wire this into a
/// Prometheus gauge or operator-facing health endpoint.
pub fn nonce_cache_stats() -> (u64, usize) {
    (
        NONCE_CACHE_REJECTIONS_TOTAL.load(std::sync::atomic::Ordering::Relaxed),
        NONCE_CACHE_MAX_ENTRIES,
    )
}

#[derive(Eq, PartialEq, Hash, Clone)]
struct NonceKey {
    subject: &'static str,
    actor_id: Uuid,
    nonce: String,
}

/// Two-generation cache implemented as a pair of `ArcSwap<DashMap>`
/// pointers. Rotation is a true O(1) atomic pointer swap — the old
/// `previous` is dropped via Arc refcount, the prior `current` is
/// promoted to `previous`, and a fresh empty `DashMap` becomes the
/// new `current`.
///
/// Why this matters over my prior `clear()/insert/clear()` design:
///   - **No rotation race.** The previous design had a window
///     between `previous.clear()` and the repopulation loop where a
///     valid nonce was momentarily absent from both maps —
///     a replay could slip through.
///   - **No double-presence false positives.** During repopulation
///     the same nonce briefly existed in both maps; the
///     contains_key short-circuit treated that as a replay.
///   - **True O(1) rotation.** No iteration over current's keys —
///     just three Arc swaps.
struct NonceCache {
    current: ArcSwap<DashMap<NonceKey, ()>>,
    previous: ArcSwap<DashMap<NonceKey, ()>>,
    /// Wall-clock when `current` was last promoted. `std::sync::Mutex`
    /// rather than atomic because `Instant` lacks an atomic primitive
    /// in stable std. Lock is held only briefly during rotation.
    rotated_at: std::sync::Mutex<Instant>,
}

impl NonceCache {
    fn new() -> Self {
        Self {
            current: ArcSwap::from(Arc::new(DashMap::with_capacity(
                NONCE_CACHE_MAX_ENTRIES / 4,
            ))),
            previous: ArcSwap::from(Arc::new(DashMap::new())),
            rotated_at: std::sync::Mutex::new(Instant::now()),
        }
    }

    /// Rotation cadence. Set to the FULL [`PAST_WINDOW_MS`] (not
    /// `PAST_WINDOW_MS / 2`) so the two-generation design guarantees a
    /// minimum per-entry lifetime of one full window: an entry inserted
    /// immediately before a rotation is promoted to `previous` and
    /// survives until the next rotation, i.e. `PAST_WINDOW_MS`. That
    /// minimum (60 s) >= the freshness window [`verify_freshness`]
    /// accepts (60 s), so a still-fresh captured request can never have
    /// been evicted from both generations — no replay within the
    /// freshness window. Memory remains bounded by
    /// [`NONCE_CACHE_MAX_ENTRIES`] per generation independent of this
    /// interval (≤ `2 * NONCE_CACHE_MAX_ENTRIES` total).
    fn rotation_interval() -> Duration {
        Duration::from_millis(PAST_WINDOW_MS as u64)
    }

    /// Check + record. Returns `true` when fresh (and inserts);
    /// `false` on replay.
    ///
    /// Linearizable per-key: the check-and-insert on `current` is
    /// atomic via DashMap's per-shard `entry()` lock. Two concurrent
    /// calls with the same nonce cannot both observe "absent" and
    /// both succeed — exactly one wins, the other sees `Occupied`
    /// and is rejected. This closes the TOCTOU gap the prior
    /// `contains_key + insert` pattern had.
    ///
    /// Cross-generation correctness: we read `previous` separately
    /// (it's read-only here — only rotation mutates it). Both Arc
    /// snapshots stay valid for the lifetime of this call even if
    /// a rotation lands between the two `load()`s, so the local
    /// view is consistent.
    fn check_and_record(&self, key: NonceKey) -> bool {
        self.rotate_if_due();

        // Snapshot both generations. ArcSwap::load returns a Guard
        // that's a cheap clone of the current pointer; both maps
        // remain valid through the Arc even if rotation happens
        // between the two reads.
        let current = self.current.load();
        let previous = self.previous.load();

        if previous.contains_key(&key) {
            return false;
        }

        // Soft cap check BEFORE we acquire the entry lock. DashMap's
        // `len()` walks every shard's read lock, and walking past a
        // shard we already hold a write lock on (via `entry()`) would
        // deadlock the same thread against itself. A racy overshoot
        // by a few entries between the cap check and the insert is
        // acceptable — the cap is defense-in-depth, not a strict
        // boundary.
        if current.len() >= NONCE_CACHE_MAX_ENTRIES {
            // L-2: structured event so dashboards can graph cap-hit
            // rate. Operators sizing NONCE_CACHE_MAX_ENTRIES need to
            // distinguish "always near cap" (raise the cap) from
            // "spiked once during a load test" (no action). Same
            // counter pattern as the RPC subscriber metrics.
            NONCE_CACHE_REJECTIONS_TOTAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::warn!(
                target: "talos_rpc",
                event_kind = "nonce_cache_cap_hit",
                size = current.len(),
                cap = NONCE_CACHE_MAX_ENTRIES,
                rejections_total = NONCE_CACHE_REJECTIONS_TOTAL.load(std::sync::atomic::Ordering::Relaxed),
                "nonce cache current generation at capacity; rejecting request"
            );
            return false;
        }

        // Atomic check-and-insert. Entry holds the shard's write
        // lock until it drops; `v.insert(())` lands before the lock
        // release. Bound to a local so the Entry temporary drops
        // BEFORE the `current` Guard at end-of-fn, satisfying the
        // borrow checker.
        use dashmap::mapref::entry::Entry;
        let admitted = match current.entry(key) {
            Entry::Occupied(_) => false,
            Entry::Vacant(v) => {
                v.insert(());
                true
            }
        };
        admitted
    }

    /// Rotate generations if the interval has elapsed. Atomic via
    /// `ArcSwap::store` — readers see the swap as instantaneous.
    fn rotate_if_due(&self) {
        let due = {
            let guard = match self.rotated_at.lock() {
                Ok(g) => g,
                Err(_) => return, // poisoned — best effort
            };
            guard.elapsed() >= Self::rotation_interval()
        };
        if !due {
            return;
        }
        let mut guard = match self.rotated_at.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        // Re-check inside the critical section to avoid double-
        // rotation when many threads observe `due` at once.
        if guard.elapsed() < Self::rotation_interval() {
            return;
        }

        // Order matters. We must NOT swap `current` to empty first
        // and then swap the old current into `previous` — between
        // those two atomic stores there's a window where a reader
        // looking for a key that was just in `current` finds neither
        // map containing it (current is empty, previous still holds
        // the previous-previous generation). That window is enough
        // to admit a replay that the cache should have caught.
        //
        // Correct order: promote `current` into `previous` first
        // (briefly both pointers reference the same DashMap, which
        // is fine — readers checking `current OR previous` still
        // find the key). Only after that has landed do we install
        // the fresh empty `current`. At every instant during
        // rotation, every key that was in either generation is
        // visible from at least one of the two pointers.
        let new_current = std::sync::Arc::new(DashMap::with_capacity(NONCE_CACHE_MAX_ENTRIES / 4));
        let current_snapshot = self.current.load_full();
        // Atomically swap `previous` to point at the same DashMap as
        // `current`. The OLD `previous` (true previous-previous, no
        // longer needed) drops here via the Arc returned by `swap`.
        let _dropped_prev = self.previous.swap(current_snapshot);
        // Now atomically install the fresh empty map as `current`.
        // Readers between this and the prior swap saw `current` ==
        // `previous` == old current — both lookups still hit.
        self.current.store(new_current);

        *guard = Instant::now();
    }

    #[cfg(test)]
    fn clear(&self) {
        self.current.store(Arc::new(DashMap::with_capacity(
            NONCE_CACHE_MAX_ENTRIES / 4,
        )));
        self.previous.store(Arc::new(DashMap::new()));
        if let Ok(mut g) = self.rotated_at.lock() {
            *g = Instant::now();
        }
    }

    /// Test-only: rewind `rotated_at` so the next `check_and_record`
    /// (which calls `rotate_if_due`) sees a full rotation interval as
    /// elapsed and performs exactly one rotation. This lets the
    /// lifetime/replay-coverage tests exercise the rotation math
    /// deterministically without sleeping for `PAST_WINDOW_MS`.
    #[cfg(test)]
    fn force_age_one_interval(&self) {
        if let Ok(mut g) = self.rotated_at.lock() {
            // Subtract slightly more than one interval so the
            // `elapsed() >= interval` check in `rotate_if_due` fires.
            *g = Instant::now() - Self::rotation_interval() - Duration::from_millis(1);
        }
    }
}

static NONCE_CACHE: std::sync::LazyLock<NonceCache> = std::sync::LazyLock::new(NonceCache::new);

/// MCP-1137 (2026-05-16): canonical nonce shape — exactly 32 lowercase
/// hex chars (16 random bytes encoded by [`random_nonce`]).
///
/// Every legitimate producer in the workspace routes through
/// `random_nonce()` and therefore emits the canonical 32-hex shape. A
/// non-canonical nonce reaching [`check_and_record_nonce`] indicates one
/// of two things, both of which we want to reject:
///
/// 1. **Insider DoS against the replay cache.** A compromised worker
///    with a valid HMAC key could submit oversized nonces in signed RPC
///    requests. Each non-replayed nonce is cloned into a `NonceKey`
///    and stored in the per-generation `DashMap` until rotation. With
///    `NONCE_CACHE_MAX_ENTRIES = 50_000` and a 1-MiB nonce, the cache
///    could grow to ~50 GiB per generation (100 GiB across both),
///    pinning controller process memory. Capping the nonce to its
///    canonical 32 bytes bounds the worst-case footprint to
///    50_000 × 32 × 2 ≈ 3.2 MiB.
/// 2. **Shape-variation gaps.** Equality on `NonceKey` is exact-bytes
///    via DashMap; an attacker who could submit shape-variant nonces
///    (uppercase hex, padded with whitespace, base64-rather-than-hex,
///    etc.) could re-encode the same logical replay value as multiple
///    distinct keys, bypassing the dedup. Strict canonical form closes
///    that surface.
///
/// Sibling defense-in-depth class as MCP-1005 (memory_rpc
/// exclude_kinds), MCP-1006 (state_rpc value bytes), MCP-432 (key
/// length cap). Caps the most-trusted message field at the central
/// chokepoint so EVERY signed-RPC subscriber inherits the bound.
fn is_canonical_nonce(nonce: &str) -> bool {
    const CANONICAL_NONCE_LEN: usize = 32;
    if nonce.len() != CANONICAL_NONCE_LEN {
        return false;
    }
    nonce
        .bytes()
        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Check whether this nonce has been seen for the given subject +
/// actor. Returns `true` when the nonce is fresh (and atomically
/// records it); `false` indicates a replay that must be rejected.
///
/// MCP-1137: rejects non-canonical nonces BEFORE allocating the
/// `NonceKey` or touching the cache. See [`is_canonical_nonce`] for the
/// rationale; in short, this caps the worst-case cache footprint and
/// closes shape-variation gaps that could let the same logical replay
/// land as multiple keys.
pub fn check_and_record_nonce(subject: &'static str, actor_id: Uuid, nonce: &str) -> bool {
    if !is_canonical_nonce(nonce) {
        tracing::warn!(
            target: "talos_rpc",
            event_kind = "nonce_non_canonical_rejected",
            subject,
            %actor_id,
            nonce_len = nonce.len(),
            "Rejected non-canonical nonce in signed RPC request — expected 32 lowercase hex chars"
        );
        return false;
    }
    let key = NonceKey {
        subject,
        actor_id,
        nonce: nonce.to_string(),
    };
    NONCE_CACHE.check_and_record(key)
}

#[cfg(test)]
pub(crate) fn clear_nonce_cache_for_test() {
    NONCE_CACHE.clear();
}

/// Test-only: rewind the global nonce cache's rotation clock by one
/// full rotation interval so the next `check_and_record_nonce` triggers
/// exactly one rotation. Used by the replay-coverage tests to age an
/// entry past a rotation boundary without real-time sleeps.
#[cfg(test)]
pub(crate) fn force_age_nonce_cache_one_interval_for_test() {
    NONCE_CACHE.force_age_one_interval();
}

/// Test-only serialization lock for the process-global nonce cache.
///
/// `NONCE_CACHE` is a `OnceLock<ArcSwap<…>>` shared across the
/// process. Tests that exercise it (`clear_nonce_cache_for_test()`
/// + `check_and_record_nonce`) must serialize so one test's cache
/// reset doesn't blast another's just-inserted entries mid-trial.
/// Pre-fix, `concurrent_same_nonce_admits_exactly_one` failed
/// intermittently with "both threads got true" when another test
/// (`nonce_replay_is_rejected`, `concurrent_distinct_nonces_all_admitted`)
/// ran in parallel and clobbered the racing pair's expected state.
///
/// Acquire via `nonce_test_lock()` (poison-recovering) at the top of
/// every test that touches `NONCE_CACHE`. The lock is held across
/// the test's entire body — including across spawned worker threads
/// when the test deliberately races them against each other; the
/// inner threads share the test's lock-protected scope but don't
/// race other tests.
#[cfg(test)]
pub(crate) static NONCE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
pub(crate) fn nonce_test_lock() -> std::sync::MutexGuard<'static, ()> {
    NONCE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Serialize a JSON value to its canonical byte form: object keys
/// sorted lexicographically, recursively. This makes signing bytes
/// independent of `serde_json::Map`'s internal type (BTreeMap vs
/// IndexMap with `preserve_order` enabled) and independent of the
/// order in which the caller inserted keys. Without this, two
/// processes serializing the same logical JSON could produce
/// different bytes, and HMAC verification would fail for any RPC
/// whose signed body contained a `Value::Object`.
///
/// Matches [RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785) in
/// the common case (ASCII keys, standard numbers); we don't need the
/// full number-canonicalisation dance because our callers don't feed
/// floating-point edge cases into signed bodies.
/// Deepest JSON nesting we'll canonicalise. Matches `serde_json`'s
/// default recursion limit so any payload serde was willing to parse,
/// we're willing to sign. Exceeding this returns an empty byte buffer
/// — `verify()` then fails, not the process. 128 is well within the
/// stack budget (each frame is small).
pub const MAX_CANONICAL_DEPTH: usize = 128;

pub fn canonical_json_bytes(v: &serde_json::Value) -> Vec<u8> {
    let mut out = Vec::new();
    if !write_canonical(v, &mut out, 0) {
        // Depth exceeded — return empty so HMAC verify fails closed.
        tracing::warn!(
            max_depth = MAX_CANONICAL_DEPTH,
            "canonical_json_bytes: nesting exceeded — returning empty"
        );
        return Vec::new();
    }
    out
}

/// Returns `false` if the input exceeds [`MAX_CANONICAL_DEPTH`];
/// callers should treat that as a signing failure.
fn write_canonical(v: &serde_json::Value, out: &mut Vec<u8>, depth: usize) -> bool {
    if depth > MAX_CANONICAL_DEPTH {
        return false;
    }
    use serde_json::Value;
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Value::Number(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Value::String(s) => {
            // Reuse serde_json's string escaping so embedded quotes,
            // unicode, and control chars are handled correctly.
            if let Ok(bytes) = serde_json::to_vec(s) {
                out.extend_from_slice(&bytes);
            }
        }
        Value::Array(arr) => {
            out.push(b'[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                if !write_canonical(item, out, depth + 1) {
                    return false;
                }
            }
            out.push(b']');
        }
        Value::Object(map) => {
            // Keys sorted lexicographically — this is the whole point.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push(b'{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                if let Ok(key_bytes) = serde_json::to_vec(*key) {
                    out.extend_from_slice(&key_bytes);
                }
                out.push(b':');
                if let Some(val) = map.get(*key) {
                    if !write_canonical(val, out, depth + 1) {
                        return false;
                    }
                }
            }
            out.push(b'}');
        }
    }
    true
}

/// Process-wide HMAC key slot. The worker registers it at startup
/// (from `WORKER_SHARED_KEY`); the controller registers the same
/// value for subscriber verification.
static HMAC_KEY: OnceLock<Arc<Vec<u8>>> = OnceLock::new();

/// Install the shared HMAC key. Idempotent — subsequent calls are
/// silently ignored so live-reload doesn't double-install.
///
/// **Conflict diagnostics.** If a second call arrives with a key that
/// differs from the first, we log a `tracing::error!` event with
/// SHA-256 fingerprints of both keys (never the raw bytes — the keys
/// ARE the secret). This catches the operator-config bug class where
/// two different env vars or two different startup paths register
/// different keys: the first wins silently and every cross-process
/// signed RPC then fails with "MAC verification failed", with no
/// breadcrumb pointing at the dual registration. Comparison itself
/// is constant-time so the diagnostic doesn't leak key bytes via
/// timing.
pub fn register_hmac_key(key: Arc<Vec<u8>>) {
    if let Err(rejected) = HMAC_KEY.set(key) {
        // Slot already occupied. Compare against the existing key.
        // `existing` is the canonical winner; `rejected` is the
        // call that just lost. If the bytes match this is a benign
        // re-registration (e.g. two startup paths both calling us
        // with the same env-derived value). If they differ this is
        // a config bug we want loud about.
        if let Some(existing) = HMAC_KEY.get() {
            let same = existing.as_slice().ct_eq(rejected.as_slice()).unwrap_u8() == 1;
            if !same {
                use sha2::Digest;
                let cur_fp = format!("{:x}", Sha256::digest(existing.as_slice()));
                let new_fp = format!("{:x}", Sha256::digest(rejected.as_slice()));
                tracing::error!(
                    current_key_fingerprint = %&cur_fp[..16],
                    rejected_key_fingerprint = %&new_fp[..16],
                    "HMAC key re-registration with a DIFFERENT key — ignored. \
                     Only the first registered key takes effect; subsequent \
                     RPC signing/verification will use that key. This is a \
                     process-config bug — verify a single canonical \
                     WORKER_SHARED_KEY value across all startup paths."
                );
            }
        }
    }
}

/// True when a key has been registered. Exposed so subscribers can
/// refuse to start if auth is not configured.
pub fn is_ready() -> bool {
    HMAC_KEY.get().is_some()
}

/// Build the canonical signing payload for an RPC request.
///
/// Format: `subject || \0 || actor_id || \0 || nonce || \0 || body`
///
/// `subject` binds the signature to a specific RPC kind so a valid
/// `memory_rpc` signature can't be replayed as a `graph_rpc` request.
/// `actor_id` prevents cross-actor replay. `nonce` prevents replay
/// of the same request within the same actor.
fn signing_payload(subject: &str, actor_id: Uuid, nonce: &str, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(subject.len() + 36 + nonce.len() + body.len() + 4);
    out.extend_from_slice(subject.as_bytes());
    out.push(0);
    out.extend_from_slice(actor_id.as_bytes());
    out.push(0);
    out.extend_from_slice(nonce.as_bytes());
    out.push(0);
    out.extend_from_slice(body);
    out
}

/// Sign a request. Returns `None` when no key has been registered.
pub fn sign(subject: &str, actor_id: Uuid, nonce: &str, body: &[u8]) -> Option<Vec<u8>> {
    let key = HMAC_KEY.get()?;
    let mut mac = HmacSha256::new_from_slice(key).ok()?;
    mac.update(&signing_payload(subject, actor_id, nonce, body));
    Some(mac.finalize().into_bytes().to_vec())
}

/// Constant-time signature verification.
pub fn verify(subject: &str, actor_id: Uuid, nonce: &str, body: &[u8], signature: &[u8]) -> bool {
    let Some(key) = HMAC_KEY.get() else {
        // Fail closed — we don't accept unsigned requests even when
        // the subscriber forgot to register.
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return false;
    };
    mac.update(&signing_payload(subject, actor_id, nonce, body));
    let expected = mac.finalize().into_bytes();
    expected.as_slice().ct_eq(signature).unwrap_u8() == 1
}

/// Generate a fresh 16-byte cryptographically random nonce encoded
/// as hex (32-char output).
///
/// **Why this matters.** The nonce is the load-bearing replay-defence
/// primitive. Without unpredictability:
///   - An attacker who knows approximate request timing could predict
///     the next nonce, fabricate it, and have it pre-rejected by the
///     replay cache (DoS, but more importantly proves the design
///     assumption is broken).
///   - With low entropy, birthday-paradox collisions become practical,
///     and a collision = the cache rejects a *legitimate* request as
///     a replay (false-positive DoS).
///
/// The prior implementation built nonces from
/// `SystemTime::now().as_nanos()` XOR'd with a stack-variable address.
/// Real entropy was 30–50 bits in the best case (ASLR enabled) and
/// near-zero in the worst case (containers / hardened systems with
/// ASLR disabled). Replaced here with `OsRng` (which on Linux pulls
/// from `getrandom(2)` / `/dev/urandom`, i.e. the kernel's CSPRNG),
/// reseeded automatically by the kernel.
///
/// `thread_rng()` would also be acceptable (ChaCha12 reseeded from
/// OsRng) and slightly faster, but for a 16-byte draw the cost
/// difference is in nanoseconds and `OsRng` removes any ambiguity
/// about whether the per-thread PRNG was reseeded recently enough.
pub fn random_nonce() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);

    // Pre-allocate the exact output length (32 hex chars) and write
    // each byte as two lowercase hex chars without per-byte heap
    // allocations. `format!("{:02x}", b)` would allocate a 2-char
    // String per byte — wasteful for a hot path that runs once per RPC.
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(32);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod nonce_quality_tests {
    use super::random_nonce;
    use std::collections::HashSet;

    /// 100k draws from a 128-bit RNG should yield zero collisions
    /// with overwhelming probability (birthday-paradox: collision
    /// probability ≈ k²/2N ≈ 10¹⁰ / 2¹²⁹ ≈ 10⁻²⁹). The prior
    /// implementation, with ~40 bits of effective entropy, would
    /// fail this test inside a few thousand draws.
    #[test]
    fn random_nonce_no_collisions_at_scale() {
        const N: usize = 100_000;
        let mut seen: HashSet<String> = HashSet::with_capacity(N);
        for _ in 0..N {
            let n = random_nonce();
            assert!(
                seen.insert(n.clone()),
                "collision after {} draws — RNG entropy is broken",
                seen.len()
            );
        }
    }

    /// Output shape: 32 lowercase hex chars, every char in [0-9a-f].
    #[test]
    fn random_nonce_has_correct_shape() {
        for _ in 0..1000 {
            let n = random_nonce();
            assert_eq!(n.len(), 32, "expected 32-char hex output");
            assert!(
                n.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')),
                "non-hex char in nonce: {n}"
            );
        }
    }

    /// Sanity check on byte-level distribution: across 10k draws
    /// (160k bytes total), every byte value 0x00-0xff should appear
    /// at least once. A constant-output RNG (or one with very low
    /// entropy) would fail this trivially. Not a proof of uniformity
    /// — that requires real statistical tests — but a cheap regression
    /// guard.
    #[test]
    fn random_nonce_byte_coverage() {
        let mut seen_bytes = [false; 256];
        for _ in 0..10_000 {
            let n = random_nonce();
            // Decode back to bytes.
            for chunk in n.as_bytes().chunks(2) {
                let hi = (chunk[0] as char).to_digit(16).unwrap() as u8;
                let lo = (chunk[1] as char).to_digit(16).unwrap() as u8;
                seen_bytes[((hi << 4) | lo) as usize] = true;
            }
        }
        let unseen: Vec<usize> = seen_bytes
            .iter()
            .enumerate()
            .filter_map(|(i, &b)| if !b { Some(i) } else { None })
            .collect();
        assert!(
            unseen.is_empty(),
            "byte values never produced after 160k bytes: {unseen:?} \
             — RNG distribution is suspiciously narrow"
        );
    }
}

#[cfg(test)]
mod nonce_cache_concurrency_tests {
    use super::*;
    use std::sync::Barrier;
    use std::thread;

    /// Two threads racing the same nonce must produce exactly one
    /// `true` (the winner) and one `false` (the loser). Prior to the
    /// `entry()` fix, the `contains_key + insert` pattern allowed
    /// both threads to observe `false` from `contains_key` and both
    /// to insert, returning `true` from both calls — admitting a
    /// replay.
    #[test]
    fn concurrent_same_nonce_admits_exactly_one() {
        let _g = nonce_test_lock();
        clear_nonce_cache_for_test();
        // Run many trials; race conditions are timing-dependent and
        // a single trial can hide them. 200 trials × 2 threads =
        // 400 racing pairs; even a 1% TOCTOU window would surface.
        for trial in 0..200 {
            clear_nonce_cache_for_test();
            let actor = uuid::Uuid::new_v4();
            // MCP-1137: must be a canonical 32-hex nonce —
            // `is_canonical_nonce` rejects shape variants. Each
            // `random_nonce()` is fresh by construction, so trial
            // uniqueness is already implicit.
            let nonce = random_nonce();
            let barrier = std::sync::Arc::new(Barrier::new(2));

            let n1 = nonce.clone();
            let b1 = barrier.clone();
            let h1 = thread::spawn(move || {
                b1.wait();
                check_and_record_nonce("memory_rpc", actor, &n1)
            });

            let n2 = nonce.clone();
            let b2 = barrier.clone();
            let h2 = thread::spawn(move || {
                b2.wait();
                check_and_record_nonce("memory_rpc", actor, &n2)
            });

            let r1 = h1.join().unwrap();
            let r2 = h2.join().unwrap();
            // Exactly one true, exactly one false.
            assert_ne!(
                r1, r2,
                "trial {trial}: both threads got {r1} — TOCTOU race admitted a replay"
            );
        }
    }

    /// 100 threads racing 100 distinct nonces should all succeed —
    /// no false rejection from cache pressure or shard contention.
    #[test]
    fn concurrent_distinct_nonces_all_admitted() {
        let _g = nonce_test_lock();
        clear_nonce_cache_for_test();
        let actor = uuid::Uuid::new_v4();
        let barrier = std::sync::Arc::new(Barrier::new(100));
        let mut handles = Vec::with_capacity(100);
        for _ in 0..100 {
            let b = barrier.clone();
            handles.push(thread::spawn(move || {
                // MCP-1137: canonical 32-hex nonces only. Each
                // `random_nonce()` is fresh (16 random bytes hex-
                // encoded) so 100 distinct draws are statistically
                // certain.
                let nonce = random_nonce();
                b.wait();
                check_and_record_nonce("memory_rpc", actor, &nonce)
            }));
        }
        let results: Vec<bool> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let admitted = results.iter().filter(|&&x| x).count();
        assert_eq!(
            admitted, 100,
            "expected all 100 distinct nonces admitted; got {admitted}"
        );
    }

    /// Replay-coverage invariant (MEDIUM replay-gap fix): an entry must
    /// survive at least one FULL rotation cycle so a captured request
    /// that is still within the freshness window can never have been
    /// evicted from both generations.
    ///
    /// With `rotation_interval == PAST_WINDOW_MS` and two generations,
    /// an entry inserted just before a rotation is promoted to
    /// `previous` and survives until the next rotation — a guaranteed
    /// minimum lifetime of one full `PAST_WINDOW_MS`. We simulate the
    /// worst case (insert, then one rotation immediately after) by
    /// rewinding the rotation clock so the next call rotates exactly
    /// once, then assert the nonce is still detected as a replay.
    #[test]
    fn nonce_survives_one_full_rotation_cycle() {
        let _g = nonce_test_lock();
        clear_nonce_cache_for_test();
        let actor = uuid::Uuid::new_v4();
        let nonce = random_nonce();

        // First sight: admitted, lands in `current`.
        assert!(
            check_and_record_nonce("memory_rpc", actor, &nonce),
            "first sighting of a fresh nonce must be admitted"
        );

        // Age the cache by one full interval. The NEXT check_and_record
        // will rotate exactly once: `current` (holding our nonce) is
        // promoted to `previous`, a fresh empty `current` is installed.
        // This models a request captured an instant before a rotation —
        // the worst case for entry lifetime.
        force_age_nonce_cache_one_interval_for_test();

        // Replay of the SAME nonce: must still be rejected. It now lives
        // in `previous`; the rotation that happened on this very call
        // moved it there but did NOT drop it. This is the band that the
        // old `PAST_WINDOW_MS / 2` interval failed to cover.
        assert!(
            !check_and_record_nonce("memory_rpc", actor, &nonce),
            "nonce aged just under PAST_WINDOW_MS must still be a replay \
             (survives at least one full rotation cycle)"
        );

        // A different fresh nonce on the same call path is still
        // admitted — the surviving entry didn't block unrelated traffic
        // and the rotation left `current` writable.
        let other = random_nonce();
        assert!(
            check_and_record_nonce("memory_rpc", actor, &other),
            "a distinct fresh nonce must still be admitted after rotation"
        );
    }

    /// After TWO full rotation cycles, the original entry has aged out
    /// of both generations (current → previous → dropped). This pins
    /// the UPPER bound of the lifetime so the test for the lower bound
    /// above isn't trivially satisfied by an entry that never expires.
    #[test]
    fn nonce_evicted_after_two_full_rotation_cycles() {
        let _g = nonce_test_lock();
        clear_nonce_cache_for_test();
        let actor = uuid::Uuid::new_v4();
        let nonce = random_nonce();

        assert!(check_and_record_nonce("memory_rpc", actor, &nonce));

        // First rotation: nonce current → previous (still tracked).
        force_age_nonce_cache_one_interval_for_test();
        assert!(
            !check_and_record_nonce("memory_rpc", actor, &nonce),
            "after one rotation the nonce is in `previous`, still a replay"
        );

        // Second rotation: nonce previous → dropped. At this point a
        // real request would also be stale (>= 2 * PAST_WINDOW_MS old)
        // and rejected by verify_freshness, so re-admission here is
        // outside the security-relevant window.
        force_age_nonce_cache_one_interval_for_test();
        assert!(
            check_and_record_nonce("memory_rpc", actor, &nonce),
            "after two full rotations the nonce has aged out of both \
             generations and is re-admitted (upper bound of lifetime)"
        );
    }
}

/// MCP-1137 (2026-05-16): canonical nonce shape gate.
#[cfg(test)]
mod canonical_nonce_tests {
    use super::*;

    #[test]
    fn accepts_random_nonce_output() {
        for _ in 0..100 {
            assert!(
                is_canonical_nonce(&random_nonce()),
                "random_nonce() output must pass canonical check by construction"
            );
        }
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(!is_canonical_nonce(""));
        assert!(!is_canonical_nonce("a")); // too short
        assert!(!is_canonical_nonce(&"a".repeat(31))); // one shy
        assert!(!is_canonical_nonce(&"a".repeat(33))); // one over
        assert!(!is_canonical_nonce(&"a".repeat(1024))); // wildly oversized
        assert!(!is_canonical_nonce(&"a".repeat(1_000_000))); // DoS shape
    }

    #[test]
    fn rejects_non_hex_chars() {
        assert!(!is_canonical_nonce("ABCDEF0123456789ABCDEF0123456789")); // uppercase
        assert!(!is_canonical_nonce("g0000000000000000000000000000000")); // 'g' not hex
        assert!(!is_canonical_nonce("0000000000000000000000000000000-")); // dash
        assert!(!is_canonical_nonce("0000000000000000000000000000000 ")); // space
        assert!(!is_canonical_nonce("0000000000000000000000000000000\0")); // null
    }

    #[test]
    fn rejects_uppercase_hex_canonical_length() {
        // Same logical bytes as a canonical nonce, but uppercase hex.
        // Reject — equality on NonceKey is byte-exact, so admitting
        // uppercase opens a shape-variation gap that lets the same
        // logical value re-land as a fresh cache key.
        assert!(!is_canonical_nonce("1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D"));
    }

    #[test]
    fn accepts_canonical_lowercase_hex() {
        assert!(is_canonical_nonce("1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d"));
        assert!(is_canonical_nonce("00000000000000000000000000000000"));
        assert!(is_canonical_nonce("ffffffffffffffffffffffffffffffff"));
    }

    /// End-to-end: `check_and_record_nonce` rejects non-canonical
    /// nonces without polluting the cache (no entry inserted on the
    /// rejection path).
    #[test]
    fn check_and_record_rejects_non_canonical() {
        let _g = nonce_test_lock();
        clear_nonce_cache_for_test();
        let actor = Uuid::new_v4();

        // Non-canonical shape: rejected.
        assert!(!check_and_record_nonce("memory_rpc", actor, "not-canonical"));
        assert!(!check_and_record_nonce(
            "memory_rpc",
            actor,
            &"a".repeat(1_000_000)
        ));

        // After rejection, a canonical nonce admits cleanly — the
        // rejection path did not insert anything that would shadow it.
        let n = random_nonce();
        assert!(check_and_record_nonce("memory_rpc", actor, &n));
        // Replay of the same canonical nonce: rejected as expected.
        assert!(!check_and_record_nonce("memory_rpc", actor, &n));
    }
}
