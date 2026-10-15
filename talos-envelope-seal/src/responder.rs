//! RFC 0010 P3 (D3b) — the controller-side claim responder.
//!
//! A per-replica NATS subscriber on the claim subject the dispatcher stamps into
//! every `sealing == 1` `JobRequest.claim_inbox`. For each `SecretClaim` it runs
//! the tested [`handle_secret_claim`] kernel (authenticate → single-claim take →
//! seal) and replies a [`ClaimResponse`] on the message's reply subject.
//!
//! This is the SINGLE primary `verify()` caller for `SecretClaim` in the
//! controller process (per the r300/r301 verify-once rule). It is deliberately
//! thin — all logic lives in `handle_secret_claim`, which is unit-tested; the
//! only thing here that a broker is needed to exercise is the subscribe/reply
//! plumbing, covered by the P3 live-NATS integration test.

use std::sync::Arc;

use async_nats::Client;
use futures::StreamExt;
use talos_workflow_job_protocol::{ClaimResponse, DispatchSigningKey, SecretClaim};

use crate::{handle_secret_claim, InFlightSeals};

/// The largest `SecretClaim` a worker sends, in bytes, with ample headroom: a
/// claim is two ids, a 32-byte key, a nonce and a 64-byte signature (security
/// review 2026-10-14, B-6). A larger message is dropped unread.
pub const MAX_CLAIM_BYTES: usize = 16 * 1024;

/// Claims handled at once per replica. Sealing is CPU-cheap, so this is a
/// bound on a flood, not on legitimate traffic (one claim per sealed
/// dispatch). Above it a claim is dropped unread; the worker's claim times out
/// and its dispatch fails, as for any lost claim.
pub const MAX_CLAIMS_IN_FLIGHT: usize = 64;

/// Whether a claim message is taken, and why not.
#[derive(Debug)]
enum ClaimIntake {
    Admitted(tokio::sync::OwnedSemaphorePermit),
    TooLarge,
    Saturated,
}

/// Decide whether a claim is read, before it is parsed: its raw length, then
/// one of the responder's slots (held for the claim's whole handling).
fn claim_intake(slots: &Arc<tokio::sync::Semaphore>, payload_len: usize) -> ClaimIntake {
    if payload_len > MAX_CLAIM_BYTES {
        return ClaimIntake::TooLarge;
    }
    match slots.clone().try_acquire_owned() {
        Ok(slot) => ClaimIntake::Admitted(slot),
        Err(_) => ClaimIntake::Saturated,
    }
}

/// Run the claim responder loop until the subscription closes. Spawn this once
/// at controller boot on the process's claim subject (the same string the
/// dispatcher stamps into `JobRequest.claim_inbox`). `max_age_secs` is the
/// freshness window for incoming claims.
pub async fn run_claim_responder(
    nc: Arc<Client>,
    claim_subject: String,
    in_flight: Arc<InFlightSeals>,
    controller_key: Arc<DispatchSigningKey>,
    max_age_secs: u64,
) -> Result<(), String> {
    let mut sub = nc
        .subscribe(claim_subject.clone())
        .await
        .map_err(|e| format!("claim responder subscribe: {e}"))?;
    tracing::info!(
        target: "talos_security",
        %claim_subject,
        "RFC 0010 P3 claim responder listening"
    );

    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CLAIMS_IN_FLIGHT));
    // Per-claim work is tracked here, never a bare `tokio::spawn`: the tasks
    // are bounded by `slots` and end with the responder.
    let mut handling: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
    let mut dropped: u64 = 0;
    loop {
        let msg = tokio::select! {
            Some(_) = handling.join_next(), if !handling.is_empty() => continue,
            next = sub.next() => match next {
                Some(m) => m,
                None => break,
            },
        };
        let slot = match claim_intake(&slots, msg.payload.len()) {
            ClaimIntake::Admitted(slot) => slot,
            refused => {
                dropped += 1;
                let reason = if matches!(refused, ClaimIntake::TooLarge) {
                    "too_large"
                } else {
                    "saturated"
                };
                // Every drop is counted (B2-3, 2026-10-15); at most one line
                // per 1 024 drops: a flood is not a log flood.
                talos_metrics::record_claim_dropped(reason);
                if dropped % 1024 == 1 {
                    tracing::warn!(
                        target: "talos_security",
                        reason,
                        dropped,
                        "claim dropped unread"
                    );
                }
                continue;
            }
        };
        let Some(reply) = msg.reply.clone() else {
            tracing::warn!(
                target: "talos_security",
                "claim message had no reply subject; dropping"
            );
            continue;
        };
        let in_flight = in_flight.clone();
        let controller_key = controller_key.clone();
        let nc = nc.clone();
        // Handle each claim on its own task so a slow seal never head-of-line
        // blocks the responder. Sealing is CPU-cheap (2 X25519 + AES-GCM), so
        // this is bounded by concurrency, not latency.
        handling.spawn(async move {
            let _slot = slot;
            let response = build_response(&msg.payload, &in_flight, &controller_key, max_age_secs);
            match serde_json::to_vec(&response) {
                Ok(bytes) => {
                    if let Err(e) = nc.publish(reply, bytes.into()).await {
                        tracing::warn!(
                            target: "talos_security",
                            error = %e,
                            "failed to publish ClaimResponse"
                        );
                    }
                }
                Err(e) => tracing::error!(
                    target: "talos_security",
                    error = %e,
                    "failed to serialize ClaimResponse"
                ),
            }
        });
    }

    tracing::warn!(
        target: "talos_security",
        %claim_subject,
        "claim responder subscription closed"
    );
    Ok(())
}

/// Parse a raw claim payload and produce the response. Split out so it is
/// testable without a broker. All rejection reasons collapse to a generic
/// message on the wire — the worker never learns which check failed.
fn build_response(
    payload: &[u8],
    in_flight: &InFlightSeals,
    controller_key: &DispatchSigningKey,
    max_age_secs: u64,
) -> ClaimResponse {
    let claim: SecretClaim = match serde_json::from_slice(payload) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(target: "talos_security", error = %e, "malformed SecretClaim");
            return ClaimResponse::Rejected {
                reason: "malformed claim".to_string(),
            };
        }
    };
    match handle_secret_claim(&claim, in_flight, controller_key, max_age_secs) {
        Ok(sealed) => ClaimResponse::Sealed(sealed),
        Err(e) => {
            tracing::warn!(
                target: "talos_security",
                worker_id = %claim.worker_id,
                error = %e,
                "SecretClaim rejected"
            );
            ClaimResponse::Rejected {
                reason: "claim rejected".to_string(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SealContext;
    use crate::REGISTRY_TEST_LOCK as REGISTRY_LOCK;
    use std::collections::HashMap;
    use talos_workflow_job_protocol::{set_dynamic_worker_public_keys, WorkerEphemeral};

    /// Security review 2026-10-14, B-6: a claim is read only when it is
    /// small enough and a slot is free; the check runs on the raw length,
    /// before any parse.
    #[test]
    fn a_claim_is_read_only_within_its_size_and_the_responders_slots() {
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        assert!(matches!(
            claim_intake(&slots, MAX_CLAIM_BYTES + 1),
            ClaimIntake::TooLarge
        ));
        let held = match claim_intake(&slots, 100) {
            ClaimIntake::Admitted(slot) => slot,
            other => panic!("expected a slot, got {other:?}"),
        };
        assert!(matches!(claim_intake(&slots, 100), ClaimIntake::Saturated));
        drop(held);
        assert!(matches!(
            claim_intake(&slots, 100),
            ClaimIntake::Admitted(_)
        ));
    }

    #[test]
    fn build_response_seals_valid_claim_and_rejects_garbage() {
        let _g = REGISTRY_LOCK.lock().unwrap();
        let worker_sk = talos_workflow_job_protocol::generate_dispatch_signing_key();
        set_dynamic_worker_public_keys(vec![(
            "resp-worker".to_string(),
            worker_sk.verifying_key(),
        )]);
        let controller_sk = talos_workflow_job_protocol::generate_dispatch_signing_key();

        let exec = uuid::Uuid::new_v4();
        let in_flight = InFlightSeals::new();
        let map: HashMap<String, String> =
            [("k".to_string(), "v".to_string())].into_iter().collect();
        in_flight.register(exec, SealContext::new(&map).unwrap());

        let we = WorkerEphemeral::generate();
        let claim =
            SecretClaim::new_signed(exec, "resp-worker".into(), we.public_key(), &worker_sk);
        let payload = serde_json::to_vec(&claim).unwrap();

        // Valid claim → Sealed.
        let resp = build_response(&payload, &in_flight, &controller_sk, 60);
        assert!(matches!(resp, ClaimResponse::Sealed(_)));

        // Garbage payload → Rejected.
        let resp2 = build_response(b"not-a-claim", &in_flight, &controller_sk, 60);
        assert!(matches!(resp2, ClaimResponse::Rejected { .. }));
    }

    /// The Sealed response produced through the responder's parse layer must
    /// actually open on the worker side to the registered plaintext — the
    /// end-to-end wire contract, not just an enum-variant check.
    #[test]
    fn build_response_sealed_payload_opens_to_registered_secrets() {
        let _g = REGISTRY_LOCK.lock().unwrap();
        let worker_sk = talos_workflow_job_protocol::generate_dispatch_signing_key();
        let worker_vk = worker_sk.verifying_key();
        set_dynamic_worker_public_keys(vec![("resp-open".to_string(), worker_vk)]);
        let controller_sk = talos_workflow_job_protocol::generate_dispatch_signing_key();
        let controller_vk = controller_sk.verifying_key();

        let exec = uuid::Uuid::new_v4();
        let in_flight = InFlightSeals::new();
        let map: HashMap<String, String> = [("gh/token".to_string(), "ghp_secret42".to_string())]
            .into_iter()
            .collect();
        in_flight.register(exec, SealContext::new(&map).unwrap());

        let we = WorkerEphemeral::generate();
        let claim = SecretClaim::new_signed(exec, "resp-open".into(), we.public_key(), &worker_sk);
        let payload = serde_json::to_vec(&claim).unwrap();

        let ClaimResponse::Sealed(sealed) =
            build_response(&payload, &in_flight, &controller_sk, 60)
        else {
            panic!("expected Sealed response");
        };
        sealed
            .verify(&controller_vk, 60)
            .expect("worker verifies the controller signature");
        let plaintext = we
            .open(
                &sealed.epk_c,
                exec,
                "resp-open",
                &sealed.ciphertext,
                &sealed.nonce,
            )
            .expect("worker opens the sealed secrets");
        let recovered: HashMap<String, String> = serde_json::from_slice(&plaintext).unwrap();
        assert_eq!(recovered, map);
    }

    /// All handler-level rejection reasons collapse to ONE generic string on
    /// the wire — the worker (or an on-bus observer) never learns which check
    /// failed (unknown worker vs bad signature vs already-claimed), and no
    /// key material or exec detail leaks in the reason text.
    #[test]
    fn build_response_rejections_are_generic_and_leak_nothing() {
        let _g = REGISTRY_LOCK.lock().unwrap();
        let worker_sk = talos_workflow_job_protocol::generate_dispatch_signing_key();
        let forger_sk = talos_workflow_job_protocol::generate_dispatch_signing_key();
        set_dynamic_worker_public_keys(vec![(
            "resp-generic".to_string(),
            worker_sk.verifying_key(),
        )]);
        let controller_sk = talos_workflow_job_protocol::generate_dispatch_signing_key();

        let in_flight = InFlightSeals::new(); // nothing dispatched
        let we = WorkerEphemeral::generate();

        // (a) valid signature, unknown execution
        let unknown_exec = SecretClaim::new_signed(
            uuid::Uuid::new_v4(),
            "resp-generic".into(),
            we.public_key(),
            &worker_sk,
        );
        // (b) unregistered worker id
        let ghost = SecretClaim::new_signed(
            uuid::Uuid::new_v4(),
            "resp-ghost".into(),
            we.public_key(),
            &forger_sk,
        );
        // (c) registered worker id, wrong signing key
        let forged = SecretClaim::new_signed(
            uuid::Uuid::new_v4(),
            "resp-generic".into(),
            we.public_key(),
            &forger_sk,
        );

        for claim in [&unknown_exec, &ghost, &forged] {
            let payload = serde_json::to_vec(claim).unwrap();
            match build_response(&payload, &in_flight, &controller_sk, 60) {
                ClaimResponse::Rejected { reason } => {
                    assert_eq!(
                        reason, "claim rejected",
                        "every handler rejection must collapse to the generic reason"
                    );
                }
                ClaimResponse::Sealed(_) => panic!("claim must be rejected"),
            }
        }

        // Malformed payloads get their own (still generic) parse-failure reason.
        match build_response(b"\x00\x01garbage", &in_flight, &controller_sk, 60) {
            ClaimResponse::Rejected { reason } => assert_eq!(reason, "malformed claim"),
            ClaimResponse::Sealed(_) => panic!("garbage must be rejected"),
        }
    }

    /// Single-claim through the responder layer: the first parsed claim
    /// seals; a redelivered/duplicate claim for the same exec is rejected.
    #[test]
    fn build_response_second_claim_for_same_exec_rejected() {
        let _g = REGISTRY_LOCK.lock().unwrap();
        let worker_sk = talos_workflow_job_protocol::generate_dispatch_signing_key();
        set_dynamic_worker_public_keys(vec![("resp-dup".to_string(), worker_sk.verifying_key())]);
        let controller_sk = talos_workflow_job_protocol::generate_dispatch_signing_key();

        let exec = uuid::Uuid::new_v4();
        let in_flight = InFlightSeals::new();
        let map: HashMap<String, String> =
            [("k".to_string(), "v".to_string())].into_iter().collect();
        in_flight.register(exec, SealContext::new(&map).unwrap());

        let we1 = WorkerEphemeral::generate();
        let first = SecretClaim::new_signed(exec, "resp-dup".into(), we1.public_key(), &worker_sk);
        let resp1 = build_response(
            &serde_json::to_vec(&first).unwrap(),
            &in_flight,
            &controller_sk,
            60,
        );
        assert!(
            matches!(resp1, ClaimResponse::Sealed(_)),
            "first claim seals"
        );

        let we2 = WorkerEphemeral::generate();
        let second = SecretClaim::new_signed(exec, "resp-dup".into(), we2.public_key(), &worker_sk);
        let resp2 = build_response(
            &serde_json::to_vec(&second).unwrap(),
            &in_flight,
            &controller_sk,
            60,
        );
        match resp2 {
            ClaimResponse::Rejected { reason } => assert_eq!(reason, "claim rejected"),
            ClaimResponse::Sealed(_) => {
                panic!("second claim for the same exec must be rejected (single-claim)")
            }
        }
    }
}
