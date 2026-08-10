//! Worker-side fleet heartbeat publisher.
//!
//! # What it is, and what it deliberately is not
//!
//! Every `TALOS_WORKER_HEARTBEAT_INTERVAL_SECS` (default 30) this publishes a
//! signed [`WorkerHeartbeat`] to `talos.workers.heartbeat.<worker_id>`, giving
//! the controller a live view of which worker processes are running.
//!
//! **The signature is an HMAC under the FLEET-SHARED `WORKER_SHARED_KEY`.** Any
//! process holding that key can mint a heartbeat naming any `worker_id`, so a
//! heartbeat is evidence that *a* process is running and *claims* to be this
//! worker. That makes it an observability signal and nothing more. It is a
//! strictly weaker statement than the `liveness` module's ping, which is an
//! Ed25519 proof of possession of THIS worker's own registered private key —
//! and it is why the controller must never let a heartbeat refresh, extend or
//! create trust in a signing identity (`talos-worker-fleet`'s
//! `heartbeat_never_touches_the_trust_boundary`, structural lint check 67).
//!
//! Do not "upgrade" this to the Ed25519 result-signing key to close that gap.
//! The gap is the point: two independent signals with different strengths are
//! more useful than one, and the fleet view is deliberately cheap — it needs no
//! controller HTTP path, so it works in the default chart posture where the
//! liveness ping is blocked at the network layer
//! (`networkPolicy.workerControllerEgress` is opt-in, default false).
//!
//! # Failure posture
//!
//! Best-effort and detached, like self-registration and the liveness pinger. A
//! failed publish is logged and retried on the next tick; it never fails a job.
//! Unlike the liveness ping, ceasing to heartbeat is ALWAYS safe: nothing is
//! persisted, no reaper consumes it, and the worst outcome is that the
//! controller's fleet view loses this worker after
//! `STALE_AFTER + PRUNE_INTERVAL` (90s at defaults) — a visibility loss, never
//! a trust loss.

use std::time::Duration;

use talos_workflow_job_protocol::{subjects, WorkerHeartbeat, WORKER_HEARTBEAT_MAX_AGE_SECS};

/// Default seconds between heartbeats.
///
/// Chosen against the controller's staleness window rather than picked round:
/// the fleet view drops a worker after `WORKER_HEARTBEAT_MAX_AGE_SECS` (60s) of
/// silence, so 30s means a worker must miss TWO consecutive publishes before it
/// disappears from the view. One dropped message on a busy bus must not make a
/// healthy worker vanish.
pub(crate) const DEFAULT_HEARTBEAT_INTERVAL_SECS: u64 = 30;

/// Lower clamp: a typo must not turn the publisher into a bus flood.
const MIN_HEARTBEAT_INTERVAL_SECS: u64 = 5;

/// Upper clamp, DERIVED from the protocol's freshness window rather than
/// written as a literal: an interval at or above `WORKER_HEARTBEAT_MAX_AGE_SECS`
/// would let a healthy worker age out of the fleet view between publishes, so
/// the ceiling is three quarters of the window. Deriving it means a change to
/// the window cannot silently invalidate this clamp.
const MAX_HEARTBEAT_INTERVAL_SECS: u64 = WORKER_HEARTBEAT_MAX_AGE_SECS * 3 / 4;

/// Resolve the publish interval. ONLY an explicit `0` disables publishing;
/// anything unparseable falls back to the default and is reported so the caller
/// can WARN.
///
/// The fallback direction is copied from `liveness::resolve_liveness_interval`,
/// where `parse().ok()?` silently disabling the pinger on a typo escalated to a
/// worker being reaped alive. Here the stakes are far lower — a disabled
/// heartbeat only blinds the fleet view — but a config typo should never
/// silently switch a mechanism off in either module, and having the two agree
/// means a reader who learns the rule once has learned it for both.
///
/// Returns `(interval, config_was_garbage)`.
pub(crate) fn resolve_heartbeat_interval(raw: Option<&str>) -> (Option<Duration>, bool) {
    let (secs, garbage) = match raw.map(str::trim) {
        None | Some("") => (DEFAULT_HEARTBEAT_INTERVAL_SECS, false),
        Some(v) => match v.parse::<u64>() {
            Ok(n) => (n, false),
            Err(_) => (DEFAULT_HEARTBEAT_INTERVAL_SECS, true),
        },
    };
    if secs == 0 {
        return (None, garbage);
    }
    (
        Some(Duration::from_secs(secs.clamp(
            MIN_HEARTBEAT_INTERVAL_SECS,
            MAX_HEARTBEAT_INTERVAL_SECS,
        ))),
        garbage,
    )
}

/// Build one signed heartbeat. Pure given its inputs, so the field binding and
/// the signature are unit-testable without a bus.
///
/// `cpu_usage_pct` is published as `0.0` and that is deliberate, not a stub
/// left behind: **this worker does not measure CPU.** Publishing a fabricated
/// or proxy value (semaphore occupancy dressed up as CPU) would be the
/// misleading-report-field defect — a number whose name implies a measurement
/// it does not carry. Every consumer of the field is documented as reading a
/// constant; capacity-aware dispatch would need a real measurement first.
pub(crate) fn build_heartbeat(
    worker_id: &str,
    build_version: Option<String>,
    key: &[u8],
) -> Result<WorkerHeartbeat, String> {
    let mut hb = WorkerHeartbeat {
        worker_id: worker_id.to_string(),
        // True and minimal: this process runs WASM modules. Not a capability
        // negotiation surface — nothing routes on it.
        capabilities: vec!["wasm".to_string()],
        cpu_usage_pct: 0.0,
        build_version,
        signature: Vec::new(),
        heartbeat_nonce: String::new(),
    };
    hb.sign(key)?;
    Ok(hb)
}

/// Run the periodic heartbeat publish loop forever. Safe to spawn detached;
/// returns immediately (with an info log) when publishing is disabled.
pub async fn run_heartbeat_publisher(nats: async_nats::Client, shared_key: Vec<u8>) {
    let raw = std::env::var("TALOS_WORKER_HEARTBEAT_INTERVAL_SECS").ok();
    let (resolved, garbage) = resolve_heartbeat_interval(raw.as_deref());
    if garbage {
        tracing::warn!(
            target: "talos_worker_fleet",
            event_kind = "worker_heartbeat_interval_unparseable",
            default_secs = DEFAULT_HEARTBEAT_INTERVAL_SECS,
            "TALOS_WORKER_HEARTBEAT_INTERVAL_SECS is not a number; falling back to \
             the default interval rather than disabling the fleet heartbeat"
        );
    }
    let Some(interval) = resolved else {
        tracing::info!(
            target: "talos_worker_fleet",
            "worker fleet heartbeat disabled (TALOS_WORKER_HEARTBEAT_INTERVAL_SECS=0); \
             this worker will not appear in the controller's live fleet view. No trust \
             or liveness consequence — the identity reaper consumes the Ed25519 \
             liveness ping, never this heartbeat"
        );
        return;
    };

    let worker_id = crate::worker_identity::worker_identity();
    let build_version = crate::self_register::worker_build_version();
    let subject = subjects::worker_heartbeat_for(worker_id);

    tracing::info!(
        target: "talos_worker_fleet",
        event_kind = "worker_heartbeat_publisher_started",
        interval_secs = interval.as_secs(),
        subject = %subject,
        "worker fleet heartbeat publisher started"
    );

    let mut ticker = tokio::time::interval(interval);
    // Fire the first heartbeat immediately: a worker that has just booted is
    // exactly when an operator most wants to see it in the fleet view, and
    // there is no registration race to avoid (nothing is persisted).
    loop {
        ticker.tick().await;
        let hb = match build_heartbeat(worker_id, Some(build_version.clone()), &shared_key) {
            Ok(hb) => hb,
            Err(e) => {
                // Signing can only fail on a malformed worker_id or a bad key —
                // both are boot-time configuration faults that will not fix
                // themselves, so say so once per tick rather than silently.
                tracing::warn!(
                    target: "talos_worker_fleet",
                    error = %e,
                    "could not sign fleet heartbeat; skipping this tick"
                );
                continue;
            }
        };
        let payload = match serde_json::to_vec(&hb) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    target: "talos_worker_fleet",
                    error = %e,
                    "could not serialize fleet heartbeat; skipping this tick"
                );
                continue;
            }
        };
        // Fire-and-forget: no flush, no retry. A heartbeat is superseded by the
        // next one within `interval`, so retrying a lost one would only put a
        // stale reading on the bus. Contrast `publish_bytes_with_retry`, which
        // flushes because a lost JobResult hangs an execution.
        if let Err(e) = nats.publish(subject.clone(), payload.into()).await {
            tracing::warn!(
                target: "talos_worker_fleet",
                error = %e,
                "fleet heartbeat publish failed; retrying next tick"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x42; 32];

    #[test]
    fn interval_defaults_clamps_and_disables() {
        let secs = |r: Option<&str>| resolve_heartbeat_interval(r).0;
        assert_eq!(
            secs(None),
            Some(Duration::from_secs(DEFAULT_HEARTBEAT_INTERVAL_SECS))
        );
        assert_eq!(secs(Some("20")), Some(Duration::from_secs(20)));
        assert_eq!(
            secs(Some("1")),
            Some(Duration::from_secs(MIN_HEARTBEAT_INTERVAL_SECS))
        );
        assert_eq!(
            secs(Some("99999")),
            Some(Duration::from_secs(MAX_HEARTBEAT_INTERVAL_SECS))
        );
        assert_eq!(secs(Some("0")), None, "only an explicit 0 disables");
    }

    /// Same regression guard as `liveness::resolve_liveness_interval`: an
    /// unparseable value must NOT switch the mechanism off silently.
    #[test]
    fn a_garbage_interval_keeps_publishing_and_reports_itself() {
        for bad in ["thirty", "3O", "30s", "-1"] {
            let (interval, garbage) = resolve_heartbeat_interval(Some(bad));
            assert_eq!(
                interval,
                Some(Duration::from_secs(DEFAULT_HEARTBEAT_INTERVAL_SECS)),
                "{bad:?} must fall back to the default"
            );
            assert!(garbage, "{bad:?} must be reported so the caller can WARN");
        }
    }

    /// The clamp ceiling must stay strictly below the controller's staleness
    /// window, or a worker configured at the maximum would flap in and out of
    /// the fleet view while perfectly healthy. Pinned because the two numbers
    /// live in different crates.
    #[test]
    fn the_slowest_configurable_interval_still_keeps_a_worker_visible() {
        assert!(MAX_HEARTBEAT_INTERVAL_SECS < WORKER_HEARTBEAT_MAX_AGE_SECS);
        assert!(MIN_HEARTBEAT_INTERVAL_SECS < DEFAULT_HEARTBEAT_INTERVAL_SECS);
        assert!(DEFAULT_HEARTBEAT_INTERVAL_SECS <= MAX_HEARTBEAT_INTERVAL_SECS);
    }

    #[test]
    fn a_built_heartbeat_verifies_and_carries_the_build() {
        let hb = build_heartbeat("dev-worker-fleet", Some("0.1.0+abc1234".into()), &KEY).unwrap();
        assert_eq!(hb.worker_id, "dev-worker-fleet");
        assert_eq!(hb.build_version.as_deref(), Some("0.1.0+abc1234"));
        assert_eq!(
            hb.cpu_usage_pct, 0.0,
            "this worker does not measure CPU; publishing a proxy would be a \
             number whose name implies a measurement it does not carry"
        );
        hb.verify_no_replay(&KEY, WORKER_HEARTBEAT_MAX_AGE_SECS)
            .expect("a freshly built heartbeat verifies");
    }

    /// The subject a worker publishes on must be the one the controller's
    /// wildcard subscription covers. A mismatch here is invisible to the
    /// compiler and would leave the fleet view empty exactly as it was before.
    #[test]
    fn the_publish_subject_is_covered_by_the_controller_wildcard() {
        let subject = subjects::worker_heartbeat_for("dev-worker-fleet");
        assert_eq!(subject, "talos.workers.heartbeat.dev-worker-fleet");
        let wildcard = subjects::WORKERS_HEARTBEAT_WILDCARD;
        assert_eq!(wildcard, "talos.workers.heartbeat.>");
        let prefix = wildcard.trim_end_matches('>');
        assert!(subject.starts_with(prefix) && subject.len() > prefix.len());
    }

    /// Guest WASM code must not be able to publish here. The enforcement lives
    /// in `talos_worker_runtime::host::limits::reject_reserved_topic_prefix`
    /// and is pinned there (`rejects_talos_internal_subjects` already names
    /// `talos.workers.heartbeat.worker-1` explicitly); that predicate is
    /// crate-private, so what THIS test can add is the other half of the
    /// implication — that the subject a worker actually publishes on stays
    /// under the `talos.` namespace the deny-list keys on. A rename that moved
    /// the heartbeat out of the namespace would pass the deny-list's own tests
    /// and fail here.
    ///
    /// It matters more than usual because the heartbeat's key is FLEET-SHARED:
    /// if a guest could publish here it could forge a fleet member.
    #[test]
    fn guests_cannot_publish_to_the_heartbeat_subject() {
        assert!(subjects::worker_heartbeat_for("anything").starts_with(subjects::NAMESPACE_PREFIX));
        assert!(subjects::WORKERS_HEARTBEAT_WILDCARD.starts_with(subjects::NAMESPACE_PREFIX));
    }

    /// A malformed identity is refused at build time rather than published.
    #[test]
    fn a_malformed_worker_id_is_refused_before_publish() {
        assert!(build_heartbeat("bad:id", None, &KEY).is_err());
    }
}
