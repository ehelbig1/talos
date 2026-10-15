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

use std::sync::LazyLock;
use talos_replay_guard::{ReplayGuard, ReplayPolicy, ReplayVerdict};
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

/// Is this the first time the fleet sees this dispatch? The answer is
/// [`talos_replay_guard::ReplayPolicy::decide`]'s, for the registered guard or
/// for none: with `TALOS_DISTRIBUTED_REPLAY` on, a worker whose guard was never
/// registered refuses when failing closed (the production default) — until
/// 2026-10-15 it ran every dispatch for its lifetime (security review round 2,
/// B2-2). With the switch off, the process-local cache is the whole defence.
pub(crate) async fn fleet_verdict(
    guard: Option<&dyn ReplayGuard>,
    key: &str,
    policy: ReplayPolicy,
) -> ReplayVerdict {
    policy.check(guard, key, NONCE_TTL_SECS).await
}

/// Why a verified dispatch was not run, as counted
/// (`talos_worker_dispatch_refused_total{reason}`).
pub(crate) fn refusal_label(verdict: ReplayVerdict) -> Option<&'static str> {
    match verdict {
        ReplayVerdict::Admit => None,
        ReplayVerdict::Replay => Some("replay"),
        ReplayVerdict::StoreUnavailable => Some("store_unavailable"),
    }
}

/// Every label [`refusal_label`] can return, pre-seeded at 0.
const REFUSAL_LABELS: [&str; 2] = ["replay", "store_unavailable"];

static REFUSED: LazyLock<Option<prometheus::IntCounterVec>> = LazyLock::new(|| {
    let c = prometheus::IntCounterVec::new(
        prometheus::Opts::new(
            "talos_worker_dispatch_refused_total",
            "Verified dispatches the worker did not run, by reason: replay (the fleet \
             already saw its nonce; never answered) or store_unavailable (the shared \
             replay store could not vouch for it under fail-closed; answered Failed).",
        ),
        &["reason"],
    )
    .ok()?;
    prometheus::default_registry()
        .register(Box::new(c.clone()))
        .ok()?;
    Some(c)
});

/// Pre-seed both reasons at 0: their healthy value is 0 forever, which an
/// absent series would render identically.
pub(crate) fn seed() {
    if let Some(c) = REFUSED.as_ref() {
        for reason in REFUSAL_LABELS {
            c.with_label_values(&[reason]).inc_by(0);
        }
    }
}

/// Count one refused dispatch.
pub(crate) fn record_refusal(verdict: ReplayVerdict) {
    if let (Some(c), Some(reason)) = (REFUSED.as_ref(), refusal_label(verdict)) {
        c.with_label_values(&[reason]).inc();
    }
}

/// The error a dispatch refused for want of the replay store is answered
/// with: its marker reads as transient to the dispatcher's classifier, so the
/// dispatcher re-sends under a fresh nonce after its backoff instead of
/// waiting out the attempt window (B2-3). One home:
/// `talos_reason_class::dispatch`.
pub(crate) const STORE_UNAVAILABLE_ERROR: &str =
    talos_reason_class::dispatch::REPLAY_STORE_UNAVAILABLE_MESSAGE;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Mutex;
    use talos_replay_guard::ReplayOutcome;

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

    const CLOSED: ReplayPolicy = ReplayPolicy {
        distributed: true,
        fail_closed: true,
    };
    const OPEN: ReplayPolicy = ReplayPolicy {
        distributed: true,
        fail_closed: false,
    };

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
            fleet_verdict(Some(worker_a), &key, CLOSED).await,
            fleet_verdict(Some(worker_b), &key, CLOSED).await,
        ];
        assert_eq!(
            ran.iter().filter(|r| **r == ReplayVerdict::Admit).count(),
            1
        );
        assert!(ran.contains(&ReplayVerdict::Replay));
        let resend = dispatch_key("job", job, "1760000001:bb");
        assert_eq!(
            fleet_verdict(Some(worker_b), &resend, CLOSED).await,
            ReplayVerdict::Admit
        );
        // A pipeline with the same id and nonce is a different dispatch.
        assert_eq!(
            fleet_verdict(
                Some(worker_a),
                &dispatch_key("pipeline", job, "1760000000:aa"),
                CLOSED
            )
            .await,
            ReplayVerdict::Admit
        );
    }

    #[tokio::test]
    async fn an_unreachable_store_refuses_only_when_failing_closed() {
        let key = dispatch_key("job", Uuid::from_u128(2), "1760000000:cc");
        assert_eq!(
            fleet_verdict(Some(&Down), &key, CLOSED).await,
            ReplayVerdict::StoreUnavailable
        );
        assert_eq!(
            fleet_verdict(Some(&Down), &key, OPEN).await,
            ReplayVerdict::Admit
        );
    }

    /// B2-2 (2026-10-15): a worker whose guard was never registered refuses
    /// a dispatch when the switch is on and it fails closed; with the switch
    /// off it runs it, the process cache being the whole defence.
    #[tokio::test]
    async fn a_missing_guard_in_production_refuses_when_failing_closed() {
        let key = dispatch_key("job", Uuid::from_u128(3), "1760000000:dd");
        assert_eq!(
            fleet_verdict(None, &key, CLOSED).await,
            ReplayVerdict::StoreUnavailable
        );
        assert_eq!(fleet_verdict(None, &key, OPEN).await, ReplayVerdict::Admit);
        let off = ReplayPolicy {
            distributed: false,
            fail_closed: true,
        };
        assert_eq!(fleet_verdict(None, &key, off).await, ReplayVerdict::Admit);
    }

    /// B2-3: a refused dispatch is counted by reason, both reasons exported
    /// from boot; an admitted one is not counted.
    #[test]
    fn a_refused_dispatch_is_counted_by_reason() {
        seed();
        let read = |reason: &str| {
            REFUSED
                .as_ref()
                .expect("registered")
                .with_label_values(&[reason])
                .get()
        };
        let (replay, unavailable) = (read("replay"), read("store_unavailable"));
        record_refusal(ReplayVerdict::Replay);
        record_refusal(ReplayVerdict::StoreUnavailable);
        record_refusal(ReplayVerdict::StoreUnavailable);
        record_refusal(ReplayVerdict::Admit);
        assert_eq!(read("replay"), replay + 1);
        assert_eq!(read("store_unavailable"), unavailable + 2);
        let text = {
            use prometheus::Encoder as _;
            let mut buf = Vec::new();
            prometheus::TextEncoder::new()
                .encode(&prometheus::default_registry().gather(), &mut buf)
                .unwrap();
            String::from_utf8(buf).unwrap()
        };
        for reason in REFUSAL_LABELS {
            assert!(
                text.contains(&format!(
                    "talos_worker_dispatch_refused_total{{reason=\"{reason}\"}}"
                )),
                "{reason} must be exported"
            );
        }
    }

    /// The answer to a refusal for want of the store carries the marker the
    /// controller's classifier reads as transient
    /// (`talos_retry_intelligence`'s
    /// `a_dispatch_refused_for_want_of_the_replay_store_is_retried`).
    #[test]
    fn the_store_unavailable_answer_carries_its_marker() {
        assert_eq!(
            talos_reason_class::token(STORE_UNAVAILABLE_ERROR),
            Some(talos_reason_class::dispatch::REPLAY_STORE_UNAVAILABLE)
        );
    }
}
