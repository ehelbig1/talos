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

    while let Some(msg) = sub.next().await {
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
        tokio::spawn(async move {
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
    use std::collections::HashMap;
    use talos_workflow_job_protocol::{set_dynamic_worker_public_keys, WorkerEphemeral};

    static REGISTRY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn build_response_seals_valid_claim_and_rejects_garbage() {
        let _g = REGISTRY_LOCK.lock().unwrap();
        let worker_sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
        set_dynamic_worker_public_keys(vec![(
            "resp-worker".to_string(),
            worker_sk.verifying_key(),
        )]);
        let controller_sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);

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
}
