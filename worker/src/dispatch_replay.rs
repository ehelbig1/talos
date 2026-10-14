//! A dispatch is run once by the fleet, not once per worker (security review
//! 2026-10-14, B-5).
//!
//! A worker's replay defence for a `JobRequest` was its process-local nonce
//! cache. Workers share a queue group, so a captured, still-fresh dispatch
//! re-published on `talos.jobs` landed on a worker that had never seen its
//! nonce and ran again, with its secrets and its egress. The idempotency cache
//! caught only a job that had already SUCCEEDED (failures are deliberately not
//! cached: the dispatcher's own retry re-sends a failed job under the same
//! `job_id` and a fresh nonce, and must re-run).
//!
//! The fix is the controller's own cross-replica guard (`talos_replay_guard`,
//! Redis `SET NX`) keyed on the dispatch's `(job_id, job_nonce)`. No honest
//! path ever sends one nonce twice — every controller re-send is re-signed — so
//! a second sighting is a replay. It is asked only for a request whose
//! signature and freshness already verified (so nothing unsigned can write a
//! key), before the idempotency cache and before execution, and a refused
//! dispatch is dropped WITHOUT a reply: the reply topic is the original
//! dispatcher's, which may still be waiting on the live attempt.

use talos_replay_guard::{ReplayGuard, ReplayOutcome};
use uuid::Uuid;

/// Key prefix in the shared store; distinct from the controller's RPC keys.
pub(crate) const KEY_PREFIX: &str = "talos:jobnonce:";

/// How long a dispatch nonce is remembered: the worker's 300 s dispatch
/// freshness window plus a minute, so no still-verifiable dispatch is
/// forgotten (the guard's lifetime ≥ window invariant).
pub(crate) const NONCE_TTL_SECS: u64 = 360;

/// The key one dispatch is remembered under. `kind` keeps single-node jobs
/// and pipelines apart.
pub(crate) fn dispatch_key(kind: &str, job_id: Uuid, nonce: &str) -> String {
    format!("{kind}:{job_id}:{nonce}")
}

/// Is this the first time the fleet sees this dispatch? `true` with no
/// guard registered (one worker, or no shared store: the process-local
/// cache is then the whole defence, as before). An unreachable store
/// refuses when `fail_closed` (the production default).
pub(crate) async fn first_use_fleet_wide(
    guard: Option<&dyn ReplayGuard>,
    key: &str,
    fail_closed: bool,
) -> bool {
    let Some(guard) = guard else {
        return true;
    };
    let outcome = guard.check_and_record(key, NONCE_TTL_SECS).await;
    talos_replay_guard::admit(outcome, fail_closed) && outcome != ReplayOutcome::Replay
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Mutex;

    /// Two workers sharing one store: the store stands in for Redis.
    #[derive(Default)]
    struct SharedStore(Mutex<HashSet<String>>);

    #[async_trait::async_trait]
    impl ReplayGuard for SharedStore {
        async fn check_and_record(&self, key: &str, _ttl_secs: u64) -> ReplayOutcome {
            if self.0.lock().expect("lock").insert(key.to_string()) {
                ReplayOutcome::Fresh
            } else {
                ReplayOutcome::Replay
            }
        }
        fn name(&self) -> &'static str {
            "test"
        }
    }

    struct Down;

    #[async_trait::async_trait]
    impl ReplayGuard for Down {
        async fn check_and_record(&self, _key: &str, _ttl_secs: u64) -> ReplayOutcome {
            ReplayOutcome::Unavailable
        }
        fn name(&self) -> &'static str {
            "down"
        }
    }

    /// B-5: one dispatch replayed to a second worker that shares the store
    /// runs exactly once; a re-send under a fresh nonce (every honest
    /// re-send) runs.
    #[tokio::test]
    async fn a_replayed_dispatch_runs_once_across_two_workers() {
        let store = SharedStore::default();
        let job = Uuid::from_u128(1);
        let key = dispatch_key("job", job, "1760000000:aa");
        let (worker_a, worker_b): (&dyn ReplayGuard, &dyn ReplayGuard) = (&store, &store);
        let ran = [
            first_use_fleet_wide(Some(worker_a), &key, true).await,
            first_use_fleet_wide(Some(worker_b), &key, true).await,
        ];
        assert_eq!(ran.iter().filter(|r| **r).count(), 1);
        let resend = dispatch_key("job", job, "1760000001:bb");
        assert!(first_use_fleet_wide(Some(worker_b), &resend, true).await);
        // A pipeline with the same id and nonce is a different dispatch.
        assert!(
            first_use_fleet_wide(
                Some(worker_a),
                &dispatch_key("pipeline", job, "1760000000:aa"),
                true
            )
            .await
        );
    }

    #[tokio::test]
    async fn an_unreachable_store_refuses_only_when_failing_closed() {
        let key = dispatch_key("job", Uuid::from_u128(2), "1760000000:cc");
        assert!(!first_use_fleet_wide(Some(&Down), &key, true).await);
        assert!(first_use_fleet_wide(Some(&Down), &key, false).await);
        assert!(first_use_fleet_wide(None, &key, true).await);
    }
}
