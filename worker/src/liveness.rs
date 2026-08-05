//! Worker-side periodic liveness ping — the refresh half of "bound how long a
//! departed worker's signing key stays trusted".
//!
//! # Why this exists
//!
//! A worker's Ed25519 public key enters the controller's trusted verify ring at
//! boot registration and, before this, left it only when an operator ran
//! `deactivate-worker-identity` by hand. Every worker that ever registered — a
//! CI container, a review rig, a scaled-down replica, a crashed pod — therefore
//! left a permanently trusted signing identity behind.
//!
//! The obvious fix (decay on `worker_identities.last_seen_at`) is wrong, because
//! that column is written ONLY at boot registration: age-based reaping would
//! deactivate a long-lived HEALTHY worker. And the liveness signal that appears
//! to exist does not — nothing publishes `talos.workers.heartbeat.*`
//! (`WorkerHeartbeat` is built only in tests), `start_worker_management` has no
//! call sites, and its `worker_id` is a `Uuid` where `worker_identities` uses
//! operator/pod text. So the refresh had to be built. This is it.
//!
//! # What it sends
//!
//! An Ed25519 proof-of-possession over `(worker_id, public_key, issued_at_ms,
//! nonce)` under a domain separate from the registration proof, to
//! `POST /internal/worker-liveness`. No bearer token: the worker's own
//! registered key is the credential. That is deliberate — a worker admitted by
//! a SINGLE-USE provisioning token has burned it and has no reusable bearer, so
//! any scheme reusing the registration endpoint's auth would fail to refresh
//! exactly those workers and the controller's sweep would reap them alive.
//!
//! # Failure posture
//!
//! Best-effort and non-blocking, like self-registration. A failed ping is
//! logged and retried on the next tick; it never fails the worker. Missing a
//! ping is safe — the controller's window is many multiples of the interval, so
//! only sustained silence (a departed worker) crosses it.
//!
//! Config:
//!   * `TALOS_CONTROLLER_URL`                  — required; unset ⇒ no pinging.
//!   * `TALOS_WORKER_LIVENESS_INTERVAL_SECS`   — default 60, clamped 10..=3600.
//!     `0` disables pinging (the worker then never participates, so its key is
//!     never auto-reaped — the pre-change behaviour).

use std::time::Duration;

use talos_workflow_job_protocol::{sign_worker_liveness_proof, DispatchSigningKey};

/// Default seconds between liveness pings. 60s against the controller's default
/// 24h window means a departed worker misses 1440 consecutive pings before its
/// key is reaped — no transient outage, deploy, or network blip resembles that,
/// which is what keeps the safe direction safe.
pub(crate) const DEFAULT_LIVENESS_INTERVAL_SECS: u64 = 60;

/// Resolve the ping interval. `Some(0)` in the env means "disabled" and yields
/// `None`; anything else is clamped into a sane band so a typo cannot turn the
/// pinger into a request flood (10s) or make it useless (1h).
pub(crate) fn resolve_liveness_interval(raw: Option<&str>) -> Option<Duration> {
    let secs = match raw.map(str::trim) {
        None | Some("") => DEFAULT_LIVENESS_INTERVAL_SECS,
        Some(v) => v.parse::<u64>().ok()?,
    };
    if secs == 0 {
        return None;
    }
    Some(Duration::from_secs(secs.clamp(10, 3600)))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn random_nonce() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Build the JSON ping body. Pure and deterministic given its inputs, so the
/// field binding is unit-testable without a network.
pub(crate) fn build_liveness_body(
    worker_id: &str,
    public_key: &[u8; 32],
    issued_at_ms: u64,
    nonce: &str,
    signing_key: &DispatchSigningKey,
) -> serde_json::Value {
    let proof = sign_worker_liveness_proof(signing_key, worker_id, public_key, issued_at_ms, nonce);
    serde_json::json!({
        "worker_id": worker_id,
        "public_key": hex::encode(public_key),
        "issued_at_ms": issued_at_ms,
        "nonce": nonce,
        "proof": hex::encode(proof),
    })
}

/// Run the periodic liveness ping loop forever. Safe to spawn detached; returns
/// immediately (with an info log) when pinging is not configured.
pub async fn run_liveness_pinger(signing_key: &'static DispatchSigningKey) {
    let Some(base_url) = std::env::var("TALOS_CONTROLLER_URL")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
    else {
        tracing::info!(
            target: "talos_security",
            "worker liveness pinger disabled (TALOS_CONTROLLER_URL unset); this \
             worker's registered key will never be auto-reaped"
        );
        return;
    };
    let raw_interval = std::env::var("TALOS_WORKER_LIVENESS_INTERVAL_SECS").ok();
    let Some(interval) = resolve_liveness_interval(raw_interval.as_deref()) else {
        tracing::info!(
            target: "talos_security",
            "worker liveness pinger disabled (TALOS_WORKER_LIVENESS_INTERVAL_SECS=0); \
             this worker's registered key will never be auto-reaped"
        );
        return;
    };

    let worker_id = crate::worker_identity::worker_identity();
    let public_key = signing_key.verifying_key().to_bytes();
    let url = format!(
        "{}/internal/worker-liveness",
        base_url.trim_end_matches('/')
    );

    // Explicit redirect policy (lint check 32) + bounded timeouts. The target is
    // a fixed in-cluster host, not a user-supplied URL, so this is not an
    // SSRF-checked path.
    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                target: "talos_security",
                error = %e,
                "worker liveness pinger: failed to build HTTP client; disabled"
            );
            return;
        }
    };

    tracing::info!(
        target: "talos_security",
        interval_secs = interval.as_secs(),
        "worker liveness pinger started"
    );

    let mut ticker = tokio::time::interval(interval);
    // Skip the immediate first tick: boot self-registration has just run (or is
    // running) and already stamps the row's registration clock. Pinging into a
    // race with it buys nothing.
    ticker.tick().await;
    loop {
        ticker.tick().await;
        let body = build_liveness_body(
            worker_id,
            &public_key,
            now_ms(),
            &random_nonce(),
            signing_key,
        );
        match client.post(&url).json(&body).send().await {
            Ok(resp) if resp.status().is_success() => {}
            Ok(resp) => {
                let status = resp.status();
                if status == reqwest::StatusCode::NOT_FOUND {
                    // Either this controller predates the endpoint (a mixed
                    // rollout — harmless, the key simply stays unreapable) or
                    // this worker's identity is no longer active, which IS
                    // loud: its signed results will not verify. The worker
                    // cannot tell these apart and must not guess, so it says
                    // exactly that.
                    tracing::warn!(
                        target: "talos_security",
                        event_kind = "worker_liveness_not_found",
                        "worker liveness ping returned 404: either the controller \
                         predates the liveness endpoint, or this worker's key is no \
                         longer an active identity and its results will not verify"
                    );
                } else {
                    tracing::warn!(
                        target: "talos_security",
                        event_kind = "worker_liveness_rejected",
                        status = %status,
                        "worker liveness ping rejected; retrying next tick"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    target: "talos_security",
                    error = %e,
                    "worker liveness ping failed; retrying next tick"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interval_defaults_clamps_and_disables() {
        assert_eq!(
            resolve_liveness_interval(None),
            Some(Duration::from_secs(DEFAULT_LIVENESS_INTERVAL_SECS))
        );
        assert_eq!(
            resolve_liveness_interval(Some("")),
            Some(Duration::from_secs(DEFAULT_LIVENESS_INTERVAL_SECS))
        );
        assert_eq!(
            resolve_liveness_interval(Some("120")),
            Some(Duration::from_secs(120))
        );
        // Clamped at both ends — a typo can neither flood nor neuter the pinger.
        assert_eq!(
            resolve_liveness_interval(Some("1")),
            Some(Duration::from_secs(10))
        );
        assert_eq!(
            resolve_liveness_interval(Some("99999")),
            Some(Duration::from_secs(3600))
        );
        // Explicit opt-out.
        assert_eq!(resolve_liveness_interval(Some("0")), None);
        // Garbage disables rather than silently defaulting: a misconfigured
        // interval must not read as a working one. Not pinging is the safe
        // direction (the key stays trusted, i.e. the pre-change behaviour).
        assert_eq!(resolve_liveness_interval(Some("sixty")), None);
    }

    #[test]
    fn liveness_body_is_signed_over_every_field() {
        use talos_workflow_job_protocol::verify_worker_liveness_proof;
        let sk = DispatchSigningKey::from_bytes(&[9u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let body = build_liveness_body("w-1", &pk, 1_700_000_000_000, "abc", &sk);

        assert_eq!(body["worker_id"], "w-1");
        assert_eq!(body["public_key"], hex::encode(pk));
        // No bearer token, and nothing else, rides along: the body is exactly
        // the proof and the fields it binds.
        let obj = body.as_object().expect("object");
        let mut keys: Vec<_> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["issued_at_ms", "nonce", "proof", "public_key", "worker_id"]
        );

        let proof = hex::decode(body["proof"].as_str().unwrap()).unwrap();
        verify_worker_liveness_proof(&pk, "w-1", 1_700_000_000_000, "abc", &proof)
            .expect("the body's own proof verifies");
        // ...and does not verify for a different worker_id.
        assert!(
            verify_worker_liveness_proof(&pk, "w-2", 1_700_000_000_000, "abc", &proof).is_err()
        );
    }
}
