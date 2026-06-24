//! Worker-side `job_id` idempotency cache (FU-2 / review finding R2-5).
//!
//! ## The problem
//!
//! The controller's NATS dispatcher retries a job on a **transport delivery
//! error** (`Ok(Err(..))` from `request`), re-signing the payload with a FRESH
//! `job_nonce` (so the worker's replay-nonce cache can't reject it — see
//! `dispatcher::resign_payload_for_retry`). The `job_id` is preserved across the
//! retry. Without idempotency here, a transport error that occurs AFTER the
//! worker already executed (the module ran and produced side effects, but the
//! reply was lost on the wire) causes the retry to **re-execute the module** —
//! a double side effect (double HTTP POST / webhook / DB write).
//!
//! ## Why a simple completed-result cache is sufficient
//!
//! The dispatcher does NOT retry on timeout — only on a transport error
//! (`dispatcher::dispatch_with_retry`). A transport-error retry therefore
//! arrives only AFTER the original request's send failed, by which time the
//! original execution has finished and produced its terminal `JobResult`. So
//! the retry is **sequential** with the original: a cache of recently-completed
//! results, checked before execution and populated after the result is signed
//! (but before publish, so a retry-after-publish-failure still finds it), turns
//! the re-execution into a cheap re-publish of the identical signed result.
//!
//! The cached result is re-published **as-is** (no re-signing): `JobResult`
//! verification at the controller allows a 300 s freshness window
//! (`max_age_secs = 300`), which dwarfs the bounded retry window (a few retries
//! × per-call timeout + backoff, with timeouts not retried at all), so a
//! re-published result is always comfortably fresh.
//!
//! ## What this does NOT cover (documented, bounded)
//!
//! - **Concurrent** redelivery of the same `job_id` while the original is still
//!   executing is NOT deduped (both miss the not-yet-populated cache and run).
//!   Core NATS request-reply is at-most-once, so this requires an at-least-once
//!   transport (JetStream) redelivering mid-flight — rare, and no worse than
//!   today (which dedupes nothing). Adding single-flight waiting was rejected as
//!   not worth the deadlock surface for the incidence.
//! - `dry_run` single jobs are never cached (no side effects; cheap to re-run).
//!   (`PipelineJobRequest` carries no `dry_run` flag, so the pipeline cache has
//!   no equivalent skip.)
//! - Results larger than [`MAX_CACHED_RESULT_BYTES`] are not cached (bounds
//!   memory; large outputs are rare and a double-run of one is the residual).
//!
//! ## Memory bounds
//!
//! TTL eviction ([`CACHE_TTL`], read-path + a periodic sweep per the CLAUDE.md
//! cache rule) plus a hard entry cap ([`MAX_ENTRIES`]) and the per-result size
//! cap. Steady-state footprint is `min(rate × TTL, MAX_ENTRIES)` entries, each
//! ≤ `MAX_CACHED_RESULT_BYTES`.

use std::sync::LazyLock;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use talos_workflow_job_protocol::JobResult;
use uuid::Uuid;

/// How long a completed result stays re-publishable. Must exceed the controller
/// retry window (seconds) and stay within the `JobResult` 300 s freshness window
/// (a result older than that can't be validated by the controller anyway, so
/// caching it longer is pointless). 90 s is comfortably inside both bounds.
const CACHE_TTL: Duration = Duration::from_secs(90);

/// Hard cap on cached entries. At the cap a sweep is attempted; if still full,
/// new results are simply not cached (that job falls back to re-execution on a
/// retry — no worse than the pre-FU-2 behavior). Bounds worst-case memory to
/// `MAX_ENTRIES × MAX_CACHED_RESULT_BYTES`.
const MAX_ENTRIES: usize = 4096;

/// Per-result size cap. Results whose serialized form exceeds this are not
/// cached, so a single huge output can't dominate the budget. 256 KiB covers
/// the overwhelming majority of module outputs.
const MAX_CACHED_RESULT_BYTES: usize = 256 * 1024;

struct Entry<V> {
    result: V,
    stored_at: Instant,
}

/// A bounded, TTL-evicting cache of completed results keyed on `job_id`.
///
/// Generic over the cached value `V` so the single-job path stores the typed
/// `JobResult` (re-published via `publish_result_with_retry`) and the pipeline
/// path stores the already-serialized publish `Bytes` (re-published verbatim) —
/// the bound/TTL/sweep logic is identical for both.
pub(crate) struct JobResultCache<V> {
    map: DashMap<Uuid, Entry<V>>,
}

impl<V: Clone> JobResultCache<V> {
    fn new() -> Self {
        Self {
            map: DashMap::new(),
        }
    }

    /// Return the cached result for `job_id` if present and not expired.
    pub(crate) fn get(&self, job_id: Uuid) -> Option<V> {
        self.get_at(job_id, Instant::now())
    }

    fn get_at(&self, job_id: Uuid, now: Instant) -> Option<V> {
        let entry = self.map.get(&job_id)?;
        if now.duration_since(entry.stored_at) <= CACHE_TTL {
            Some(entry.result.clone())
        } else {
            // Expired but not yet swept; treat as a miss (the sweep reaps it).
            None
        }
    }

    /// Cache a completed (signed) result. `serialized_len` is the size of the
    /// result as it will be published; oversized results are skipped. No-op for
    /// a result whose serialized form exceeds the size cap or when the cache is
    /// full of live entries.
    pub(crate) fn put(&self, job_id: Uuid, result: V, serialized_len: usize) {
        self.put_at(job_id, result, serialized_len, Instant::now());
    }

    fn put_at(&self, job_id: Uuid, result: V, serialized_len: usize, now: Instant) {
        if serialized_len > MAX_CACHED_RESULT_BYTES {
            return;
        }
        // Only enforce the cap when this would be a NEW key (overwriting an
        // existing key, e.g. a same-job re-store, doesn't grow the map).
        if self.map.len() >= MAX_ENTRIES && !self.map.contains_key(&job_id) {
            self.sweep_at(now);
            if self.map.len() >= MAX_ENTRIES {
                return; // still full — skip caching; the job just isn't deduped
            }
        }
        self.map.insert(
            job_id,
            Entry {
                result,
                stored_at: now,
            },
        );
    }

    /// Drop expired entries. Called from a periodic sweep task and from the
    /// put-path when at capacity.
    pub(crate) fn sweep(&self) {
        self.sweep_at(Instant::now());
    }

    fn sweep_at(&self, now: Instant) {
        self.map
            .retain(|_, e| now.duration_since(e.stored_at) <= CACHE_TTL);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.map.len()
    }
}

/// Process-global completed single-job-result cache. Keyed on `job_id` (a fresh
/// v4 UUID per dispatch, preserved across transport retries), so there is no
/// cross-job key collision.
pub(crate) static JOB_RESULT_CACHE: LazyLock<JobResultCache<JobResult>> =
    LazyLock::new(JobResultCache::new);

/// Process-global completed PIPELINE-result cache. Same transport-retry
/// double-execution exposure as the single-job path; the pipeline handler
/// publishes already-serialized `Bytes` (post size-gating), so we cache and
/// re-publish those bytes verbatim rather than the typed `PipelineJobResult`.
pub(crate) static PIPELINE_PAYLOAD_CACHE: LazyLock<JobResultCache<bytes::Bytes>> =
    LazyLock::new(JobResultCache::new);

/// Interval for the background sweep of expired entries. Read-path eviction
/// handles active job_ids; this reaps entries for workers that go idle so the
/// map can't retain expired results indefinitely (CLAUDE.md cache rule:
/// TTL cache = read-path eviction + periodic sweep).
pub(crate) const SWEEP_INTERVAL_SECS: u64 = 60;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn result(job_id: Uuid) -> JobResult {
        JobResult {
            job_id,
            status: talos_workflow_job_protocol::JobStatus::Success,
            output_payload: json!({"ok": true}),
            logs: vec![],
            execution_time_ms: 1,
            signature: vec![],
            result_nonce: String::new(),
            worker_id: String::new(),
        }
    }

    #[test]
    fn put_then_get_returns_the_result() {
        let cache: JobResultCache<JobResult> = JobResultCache::new();
        let id = Uuid::new_v4();
        let t0 = Instant::now();
        cache.put_at(id, result(id), 100, t0);
        let got = cache.get_at(id, t0 + Duration::from_secs(1));
        assert!(got.is_some(), "a freshly cached result must be returned");
        assert_eq!(got.unwrap().job_id, id);
    }

    #[test]
    fn miss_for_unknown_job() {
        let cache: JobResultCache<JobResult> = JobResultCache::new();
        assert!(cache.get(Uuid::new_v4()).is_none());
    }

    #[test]
    fn expired_entry_is_a_miss() {
        let cache: JobResultCache<JobResult> = JobResultCache::new();
        let id = Uuid::new_v4();
        let t0 = Instant::now();
        cache.put_at(id, result(id), 100, t0);
        // Just past the TTL.
        let got = cache.get_at(id, t0 + CACHE_TTL + Duration::from_secs(1));
        assert!(got.is_none(), "an entry past the TTL must read as a miss");
    }

    #[test]
    fn oversized_result_is_not_cached() {
        let cache: JobResultCache<JobResult> = JobResultCache::new();
        let id = Uuid::new_v4();
        let t0 = Instant::now();
        cache.put_at(id, result(id), MAX_CACHED_RESULT_BYTES + 1, t0);
        assert!(
            cache.get_at(id, t0).is_none(),
            "a result larger than the size cap must not be cached"
        );
    }

    #[test]
    fn sweep_drops_only_expired() {
        let cache: JobResultCache<JobResult> = JobResultCache::new();
        let old = Uuid::new_v4();
        let fresh = Uuid::new_v4();
        let t0 = Instant::now();
        cache.put_at(old, result(old), 100, t0);
        let later = t0 + CACHE_TTL - Duration::from_secs(1);
        cache.put_at(fresh, result(fresh), 100, later);
        // Sweep at a time where `old` is expired but `fresh` is not.
        cache.sweep_at(t0 + CACHE_TTL + Duration::from_secs(1));
        assert!(cache
            .get_at(old, t0 + CACHE_TTL + Duration::from_secs(1))
            .is_none());
        assert!(cache
            .get_at(fresh, later + Duration::from_secs(1))
            .is_some());
    }

    #[test]
    fn re_store_same_job_does_not_grow_map() {
        let cache: JobResultCache<JobResult> = JobResultCache::new();
        let id = Uuid::new_v4();
        let t0 = Instant::now();
        cache.put_at(id, result(id), 100, t0);
        cache.put_at(id, result(id), 100, t0);
        assert_eq!(
            cache.len(),
            1,
            "re-storing the same job_id must not grow the map"
        );
    }

    #[test]
    fn generic_cache_works_for_pipeline_bytes() {
        // The pipeline path caches the published payload `Bytes`; same TTL +
        // size-cap logic via the generic `JobResultCache<V>`.
        let cache: JobResultCache<bytes::Bytes> = JobResultCache::new();
        let id = Uuid::new_v4();
        let t0 = Instant::now();
        let payload = bytes::Bytes::from_static(b"signed-pipeline-result");

        cache.put_at(id, payload.clone(), payload.len(), t0);
        assert_eq!(
            cache.get_at(id, t0 + Duration::from_secs(1)),
            Some(payload.clone())
        );

        // Oversized payload is not cached.
        let other = Uuid::new_v4();
        cache.put_at(other, payload.clone(), MAX_CACHED_RESULT_BYTES + 1, t0);
        assert!(cache.get_at(other, t0).is_none());

        // Expiry applies to the bytes instance too.
        assert!(cache
            .get_at(id, t0 + CACHE_TTL + Duration::from_secs(1))
            .is_none());
    }
}
