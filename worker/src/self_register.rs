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
//!   * `TALOS_WORKER_REGISTRATION_TOKEN` — bearer credential: either the
//!                                         fleet-shared token (matches the
//!                                         controller's env) or a single-use
//!                                         provisioning token minted for THIS
//!                                         worker_id via
//!                                         `controller mint-worker-provisioning-token`.
//!   * `TALOS_WORKER_SIGNING_KEY`        — already required for result signing;
//!                                         the caller passes the resolved key in.
//! Optional:
//!   * `TALOS_WORKER_SUPPORTS_SEALING`   — advertise P3/D3b capability (default
//!                                         false).
//!
//! It also reports its WRITE-CEILING ENFORCEMENT POSTURE
//! (`TALOS_WRITE_CEILING_ENFORCED` / `TALOS_WRITE_CEILING_STRICT_EGRESS`) so
//! controller-side operator surfaces can stop describing `max_write_ceiling`
//! in the abstract. That posture is read from
//! [`talos_worker_runtime::context::write_ceiling_enforcement`] — the SAME
//! `OnceLock`s the host-fn gates consult — never from a second env read here,
//! because a report that can disagree with the gate it describes is worse than
//! no report. Like `build_version` it is DIAGNOSTIC ONLY and deliberately
//! outside the proof-of-possession; see [`build_registration_body`].

use std::time::Duration;

use talos_workflow_job_protocol::{sign_worker_registration_proof, DispatchSigningKey};

const MAX_ATTEMPTS: u32 = 5;

/// This worker's build string, in the SAME composite shape the controller
/// stamps for itself (`get_platform_info` / `session_start.server_version`):
/// `TALOS_VERSION` verbatim when set (docker-compose / CI override), else
/// `{cargo_pkg_version}+{git_sha}{-dirty?}` from `worker/build.rs`.
///
/// Mirroring the controller's composition exactly is the whole point — the
/// controller compares the `+sha[-dirty]` suffix of the two strings to decide
/// whether the fleet is on one build. A different composition here would make
/// every healthy registration look like skew.
pub(crate) fn worker_build_version() -> String {
    std::env::var("TALOS_VERSION").unwrap_or_else(|_| {
        format!(
            "{}+{}{}",
            env!("CARGO_PKG_VERSION"),
            env!("GIT_SHA"),
            if env!("GIT_DIRTY") == "true" {
                "-dirty"
            } else {
                ""
            }
        )
    })
}

/// Build the JSON registration body, signing a proof-of-possession over the
/// canonical message so every field is bound to the worker's private key. Pure
/// and deterministic given its inputs — unit-testable without a network.
pub(crate) fn build_registration_body(
    worker_id: &str,
    public_key: &[u8; 32],
    supports_sealing: bool,
    issued_at_ms: u64,
    nonce: &str,
    build_version: &str,
    write_ceiling: talos_worker_runtime::context::WriteCeilingEnforcement,
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
        // DIAGNOSTIC ONLY, and deliberately NOT bound into the
        // proof-of-possession above.
        //
        // Why not sign it: (a) binding it would dress a self-reported,
        // unverifiable string up as a security claim — the signature would
        // prove "the key-holder said this", never "this is the running
        // build", so it buys no trust it doesn't already have; and (b) the
        // PoP message is a fixed wire format shared with older controllers,
        // so extending it would break proof compatibility during any mixed
        // deploy for exactly zero gain. Nothing on the controller side is
        // allowed to BRANCH on this value — it is logged, compared for a
        // WARN, and reported in get_platform_info. That is the full list.
        //
        // An old controller ignores the extra field (the request struct
        // carries no `deny_unknown_fields`), so this is safe to send at any
        // point in a rollout.
        "build_version": build_version,
        // DIAGNOSTIC ONLY, unsigned, for exactly the reasons above — plus one
        // that is specific to these two.
        //
        // What they are: what THIS process will do with the signed
        // `max_write_ceiling` it receives, read from the same OnceLocks the
        // mutating host-fn gates read. Before they existed, no controller
        // surface could distinguish a deployment where a `readonly` actor is a
        // live control from one where it is a decorative column — every
        // operator tool printed the same sentence for both.
        //
        // Why signing them would be pointless rather than merely costly: a
        // signature would prove "the key-holder said this", never "this
        // process refuses mutations". The only claim worth binding is one the
        // controller could act on, and it must not act on this one at all.
        // Note which way a lie runs — a worker can only report enforcement it
        // is NOT performing, which makes an operator more cautious, never more
        // permissive; the real boundary is `write_ceiling_denies` inside this
        // process, which no wire field can reach.
        "write_ceiling_enforced": write_ceiling.enforced,
        "write_ceiling_strict_egress": write_ceiling.strict_egress,
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
    let build_version = worker_build_version();
    // From the runtime's own gate readers, not a second env parse here.
    let write_ceiling = talos_worker_runtime::context::write_ceiling_enforcement();
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
            &build_version,
            write_ceiling,
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
                    build_version = %build_version,
                    write_ceiling_enforced = write_ceiling.enforced,
                    write_ceiling_strict_egress = write_ceiling.strict_egress,
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
    use talos_worker_runtime::context::WriteCeilingEnforcement;
    use talos_workflow_job_protocol::verify_worker_registration_proof;

    /// Fixture posture with the two bits DIFFERENT, so a swapped field
    /// assignment anywhere on the wire path is visible. Both-true or both-false
    /// fixtures cannot see a swap, which is why this is asymmetric.
    const POSTURE: WriteCeilingEnforcement = WriteCeilingEnforcement {
        enforced: true,
        strict_egress: false,
    };

    #[test]
    fn registration_body_shape_and_proof_verify() {
        let sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
        let pk = sk.verifying_key().to_bytes();
        let body = build_registration_body(
            "worker-42",
            &pk,
            true,
            1_700_000_000_000,
            "nonce-1",
            "0.1.0+abc1234",
            POSTURE,
            &sk,
        );

        // Shape: hex fields, echoed scalars.
        assert_eq!(body["worker_id"], "worker-42");
        assert_eq!(body["public_key"], hex::encode(pk));
        assert_eq!(body["supports_sealing"], true);
        assert_eq!(body["issued_at_ms"], 1_700_000_000_000u64);
        assert_eq!(body["build_version"], "0.1.0+abc1234");

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

    /// The build-identity handshake must be invisible to the SECURITY layer:
    /// the proof-of-possession is over `(worker_id, key, sealing, ts, nonce)`
    /// only, so two bodies that differ ONLY in `build_version` must carry
    /// byte-identical proofs — which is exactly what makes a new worker's body
    /// verifiable by an OLD controller that has never heard of the field.
    ///
    /// If someone later "improves" this by binding build_version into the PoP,
    /// this test fails loudly and names the compatibility break.
    #[test]
    fn build_version_does_not_affect_the_proof() {
        let sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
        let pk = sk.verifying_key().to_bytes();

        let mk = |bv: &str| {
            build_registration_body(
                "worker-42",
                &pk,
                true,
                1_700_000_000_000,
                "nonce-1",
                bv,
                POSTURE,
                &sk,
            )
        };
        let a = mk("0.1.0+aaaaaaa");
        let b = mk("9.9.9+bbbbbbb-dirty");
        let empty = mk("");

        assert_eq!(a["proof"], b["proof"], "proof must not bind build_version");
        assert_eq!(a["proof"], empty["proof"]);

        // ...and every OTHER field is identical too, so the only wire delta an
        // old controller sees is one unknown key it ignores.
        for field in [
            "worker_id",
            "public_key",
            "supports_sealing",
            "issued_at_ms",
            "nonce",
        ] {
            assert_eq!(a[field], b[field], "field {field} must be unchanged");
        }

        // The proof still verifies standalone — i.e. an old controller, which
        // never reads build_version, accepts the new body.
        let proof = hex::decode(b["proof"].as_str().unwrap()).unwrap();
        verify_worker_registration_proof(
            &pk,
            "worker-42",
            true,
            1_700_000_000_000,
            "nonce-1",
            &proof,
        )
        .expect("old controller must accept a new worker's body");
    }

    /// The write-ceiling enforcement posture must reach the wire UNSWAPPED and
    /// must not touch the proof-of-possession.
    ///
    /// Two independent failure modes, both silent without this test:
    ///
    /// 1. **Swap.** `enforced` and `strict_egress` are both `bool`, threaded
    ///    through a JSON body, a request struct, five repository signatures and
    ///    a report. A transposition compiles and would make the controller
    ///    advertise a strict-egress narrowing that is off while calling the
    ///    live mutation gate off — the report inverted on both axes. The
    ///    fixture is deliberately asymmetric (`true`/`false`) so the swap is
    ///    detectable at all; a `true`/`true` fixture would pass either way.
    ///
    /// 2. **Signing it.** Binding these into the PoP would break proof
    ///    compatibility with any controller that has not rolled yet, for zero
    ///    security gain (a signature proves the key-holder SAID it, never that
    ///    the process ENFORCES it). Two bodies differing only in the posture
    ///    must therefore carry byte-identical proofs — which is also what lets
    ///    an OLD controller, which has never heard of these fields, accept a
    ///    NEW worker's body.
    #[test]
    fn write_ceiling_flags_travel_unswapped_and_unsigned() {
        let sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
        let pk = sk.verifying_key().to_bytes();

        let mk = |p: WriteCeilingEnforcement| {
            build_registration_body(
                "worker-42",
                &pk,
                true,
                1_700_000_000_000,
                "nonce-1",
                "0.1.0+abc1234",
                p,
                &sk,
            )
        };

        // 1 — unswapped, and asymmetric so the assertion has content.
        let body = mk(POSTURE);
        assert_eq!(body["write_ceiling_enforced"], true);
        assert_eq!(body["write_ceiling_strict_egress"], false);
        // ...and the other way round, so neither field is hard-coded.
        let flipped = mk(WriteCeilingEnforcement {
            enforced: false,
            strict_egress: true,
        });
        assert_eq!(flipped["write_ceiling_enforced"], false);
        assert_eq!(flipped["write_ceiling_strict_egress"], true);

        // 2 — the posture is outside the proof, so the proofs are identical
        // and every OTHER field is untouched.
        assert_eq!(
            body["proof"], flipped["proof"],
            "the proof must not bind the write-ceiling posture"
        );
        for field in [
            "worker_id",
            "public_key",
            "supports_sealing",
            "issued_at_ms",
            "nonce",
            "build_version",
        ] {
            assert_eq!(
                body[field], flipped[field],
                "field {field} must be unchanged"
            );
        }

        // An old controller — which never reads these fields — still accepts it.
        let proof = hex::decode(flipped["proof"].as_str().unwrap()).unwrap();
        verify_worker_registration_proof(
            &pk,
            "worker-42",
            true,
            1_700_000_000_000,
            "nonce-1",
            &proof,
        )
        .expect("old controller must accept a new worker's body");
    }

    /// The composed string must be parseable by the controller's suffix
    /// comparison: exactly one `+`, non-empty on both sides.
    #[test]
    fn worker_build_version_has_the_composite_shape() {
        // TALOS_VERSION unset → composite. (Set-then-remove so a stray value in
        // the ambient env can't make this test lie.)
        std::env::remove_var("TALOS_VERSION");
        let v = worker_build_version();
        let (pkg, sha) = v.split_once('+').expect("composite is `{pkg}+{sha}`");
        assert!(!pkg.is_empty(), "package version must be present");
        assert!(!sha.is_empty(), "sha (or `unknown`) must be present");

        // The override wins verbatim — this is how compose/CI pins a version.
        std::env::set_var("TALOS_VERSION", "1.2.3+deadbee");
        assert_eq!(worker_build_version(), "1.2.3+deadbee");
        std::env::remove_var("TALOS_VERSION");
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
