//! RFC 0010 P2 inc.4d — worker-side boot-time self-registration.
//!
//! An autoscaling worker registers its Ed25519 identity key with the controller
//! at boot by POSTing a proof-of-possession-signed request to
//! `POST /internal/worker-key`, so the controller can verify this worker's
//! `JobResult`/RPC signatures without an operator pre-provisioning the key via
//! `TALOS_WORKER_PUBLIC_KEYS` or the `register-worker-identity` CLI.
//!
//! Best-effort and non-blocking: it runs in a background task off the boot path.
//! On persistent failure it logs loudly and gives up rather than crashing — the
//! worker can still process jobs, and its results simply won't verify until the
//! key is registered (here on a later boot, or out-of-band via the CLI/env). A
//! client error other than 429 is not retried (a bad token or proof won't fix
//! itself). Registration is idempotent, so a retry — or a later reboot — is safe.
//!
//! The endpoint is trust-on-first-use per worker_id: the first registered key
//! becomes this worker's identity, and later boots may only refresh that SAME
//! key. A 409 means the worker_id is already bound to a different key — a
//! signing-key rotation must be registered by an operator
//! (`controller register-worker-identity`) before the rebooted worker's
//! self-registration will refresh it.
//!
//! Config (all must be present to enable self-registration):
//!   * `TALOS_CONTROLLER_URL`            — controller base URL (in-cluster).
//!   * `TALOS_WORKER_REGISTRATION_TOKEN` — shared bearer token (matches the
//!                                         controller's env).
//!   * `TALOS_WORKER_SIGNING_KEY`        — already required for result signing;
//!                                         the caller passes the resolved key in.
//! Optional:
//!   * `TALOS_WORKER_SUPPORTS_SEALING`   — advertise P3/D3b capability (default
//!                                         false).

use std::time::Duration;

use talos_workflow_job_protocol::{sign_worker_registration_proof, DispatchSigningKey};

const MAX_ATTEMPTS: u32 = 5;

/// Build the JSON registration body, signing a proof-of-possession over the
/// canonical message so every field is bound to the worker's private key. Pure
/// and deterministic given its inputs — unit-testable without a network.
pub(crate) fn build_registration_body(
    worker_id: &str,
    public_key: &[u8; 32],
    supports_sealing: bool,
    issued_at_ms: u64,
    nonce: &str,
    signing_key: &DispatchSigningKey,
) -> serde_json::Value {
    let proof = sign_worker_registration_proof(
        signing_key,
        worker_id,
        public_key,
        supports_sealing,
        issued_at_ms,
        nonce,
    );
    serde_json::json!({
        "worker_id": worker_id,
        "public_key": hex::encode(public_key),
        "supports_sealing": supports_sealing,
        "issued_at_ms": issued_at_ms,
        "nonce": nonce,
        "proof": hex::encode(proof),
    })
}

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn bool_env(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            matches!(v.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
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

/// Attempt boot-time self-registration. No-op (with an info log) when the
/// controller URL or registration token is not configured. Runs its own retry
/// loop with exponential backoff; safe to spawn detached.
pub async fn register_worker_identity_at_boot(signing_key: &'static DispatchSigningKey) {
    let Some(base_url) = non_empty_env("TALOS_CONTROLLER_URL") else {
        tracing::info!(
            target: "talos_security",
            "worker self-registration skipped (TALOS_CONTROLLER_URL unset); \
             relying on TALOS_WORKER_PUBLIC_KEYS / register-worker-identity CLI"
        );
        return;
    };
    let Some(token) = non_empty_env("TALOS_WORKER_REGISTRATION_TOKEN") else {
        tracing::info!(
            target: "talos_security",
            "worker self-registration skipped (TALOS_WORKER_REGISTRATION_TOKEN unset)"
        );
        return;
    };

    let worker_id = crate::worker_identity::worker_identity();
    let supports_sealing = bool_env("TALOS_WORKER_SUPPORTS_SEALING");
    let public_key = signing_key.verifying_key().to_bytes();
    let url = format!("{}/internal/worker-key", base_url.trim_end_matches('/'));

    // Explicit redirect policy (lint check 32) + bounded timeouts; the target is
    // a fixed in-cluster host (not a user-supplied URL), so this is not an
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
                "worker self-registration: failed to build HTTP client; skipping"
            );
            return;
        }
    };

    for attempt in 1..=MAX_ATTEMPTS {
        // Fresh nonce + timestamp per attempt so a retried request is inside the
        // controller's freshness window.
        let issued_at_ms = now_ms();
        let nonce = random_nonce();
        let body = build_registration_body(
            worker_id,
            &public_key,
            supports_sealing,
            issued_at_ms,
            &nonce,
            signing_key,
        );

        match client
            .post(&url)
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!(
                    target: "talos_security",
                    worker_id = %worker_id,
                    supports_sealing,
                    "worker self-registered its Ed25519 identity (RFC 0010 P2 inc.4)"
                );
                return;
            }
            Ok(resp) => {
                let status = resp.status();
                tracing::warn!(
                    target: "talos_security",
                    worker_id = %worker_id,
                    %status,
                    attempt,
                    "worker self-registration was rejected"
                );
                // A client error other than 429 (bad token / bad proof /
                // validation) won't be fixed by retrying — bail early.
                if status.is_client_error() && status != reqwest::StatusCode::TOO_MANY_REQUESTS {
                    tracing::warn!(
                        target: "talos_security",
                        "self-registration returned a client error; not retrying. \
                         Ensure the token matches and the key is otherwise registered."
                    );
                    return;
                }
            }
            Err(e) => {
                tracing::warn!(
                    target: "talos_security",
                    attempt,
                    error = %e,
                    "worker self-registration request failed (controller not ready?)"
                );
            }
        }

        if attempt < MAX_ATTEMPTS {
            // 2, 4, 8, 16 s.
            tokio::time::sleep(Duration::from_secs(2u64.pow(attempt))).await;
        }
    }

    tracing::warn!(
        target: "talos_security",
        worker_id = %worker_id,
        attempts = MAX_ATTEMPTS,
        "worker self-registration did not succeed; results may be rejected until \
         the key is registered (CLI/env). Registration is idempotent — a reboot retries."
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use talos_workflow_job_protocol::verify_worker_registration_proof;

    #[test]
    fn registration_body_shape_and_proof_verify() {
        let sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
        let pk = sk.verifying_key().to_bytes();
        let body =
            build_registration_body("worker-42", &pk, true, 1_700_000_000_000, "nonce-1", &sk);

        // Shape: hex fields, echoed scalars.
        assert_eq!(body["worker_id"], "worker-42");
        assert_eq!(body["public_key"], hex::encode(pk));
        assert_eq!(body["supports_sealing"], true);
        assert_eq!(body["issued_at_ms"], 1_700_000_000_000u64);

        // The proof in the body verifies against the body's own fields — i.e. the
        // controller would accept it — and binds supports_sealing (flipping it
        // fails).
        let proof = hex::decode(body["proof"].as_str().unwrap()).unwrap();
        verify_worker_registration_proof(
            &pk,
            "worker-42",
            true,
            1_700_000_000_000,
            "nonce-1",
            &proof,
        )
        .expect("body's proof must verify for the body's fields");
        assert!(verify_worker_registration_proof(
            &pk,
            "worker-42",
            false, // flipped
            1_700_000_000_000,
            "nonce-1",
            &proof
        )
        .is_err());
    }

    #[test]
    fn bool_env_parses_truthy_tokens() {
        std::env::set_var("TALOS_TEST_SEALING_FLAG", "yes");
        assert!(bool_env("TALOS_TEST_SEALING_FLAG"));
        std::env::set_var("TALOS_TEST_SEALING_FLAG", "0");
        assert!(!bool_env("TALOS_TEST_SEALING_FLAG"));
        std::env::remove_var("TALOS_TEST_SEALING_FLAG");
        assert!(!bool_env("TALOS_TEST_SEALING_FLAG"));
    }
}
