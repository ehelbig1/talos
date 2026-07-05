//! RFC 0010 P3 (D3b) — live-NATS integration test for the claim responder ↔
//! worker-client handshake.
//!
//! Exercises the two halves that only a real broker can validate: the
//! controller-side [`run_claim_responder`] subscription + reply, and a
//! worker-style `SecretClaim` request/`SealedSecrets` open over NATS. This is
//! the responder↔client leg the RFC's test plan mandates gating on live NATS.
//!
//! Gated on `TALOS_TEST_NATS_URL` (mirrors `talos-replay-guard`'s Redis gating)
//! so it no-ops where no broker is available; it runs in `quality.yml`'s
//! env-gated integration suite. To run locally:
//! `TALOS_TEST_NATS_URL=nats://127.0.0.1:4222 cargo test -p talos-envelope-seal --test nats_claim_integration`

use std::collections::HashMap;
use std::sync::Arc;

use talos_envelope_seal::{run_claim_responder, InFlightSeals, SealContext};
use talos_workflow_job_protocol::{
    set_dynamic_worker_public_keys, ClaimResponse, DispatchSigningKey, SecretClaim, WorkerEphemeral,
};

fn nats_url() -> Option<String> {
    std::env::var("TALOS_TEST_NATS_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

/// Drive one claim through a real broker and assert the sealed secrets open;
/// then assert the single-claim property (second claim for the same exec is
/// rejected) and the unknown-execution rejection.
#[tokio::test]
async fn claim_handshake_over_live_nats() {
    let Some(url) = nats_url() else {
        eprintln!("skipping: set TALOS_TEST_NATS_URL to run");
        return;
    };

    // Worker + controller long-term keys.
    let worker_sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
    set_dynamic_worker_public_keys(vec![("it-worker".to_string(), worker_sk.verifying_key())]);
    let controller_sk = Arc::new(DispatchSigningKey::generate(&mut rand::rngs::OsRng));
    let controller_vk = controller_sk.verifying_key();

    // Register one in-flight seal context.
    let exec = uuid::Uuid::new_v4();
    let in_flight = Arc::new(InFlightSeals::new());
    let secrets: HashMap<String, String> =
        [("anthropic/api_key".to_string(), "sk-ant-it".to_string())]
            .into_iter()
            .collect();
    in_flight.register(exec, SealContext::new(&secrets).unwrap());

    // Spawn the responder on a unique subject.
    let nc = Arc::new(async_nats::connect(&url).await.expect("connect nats"));
    let subject = format!("talos.test.claims.{exec}");
    {
        let nc = nc.clone();
        let subject = subject.clone();
        let in_flight = in_flight.clone();
        let controller_sk = controller_sk.clone();
        tokio::spawn(async move {
            let _ = run_claim_responder(nc, subject, in_flight, controller_sk, 60).await;
        });
    }
    // Give the subscription a moment to establish.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // --- Worker side: build a claim, request it, open the reply. ---
    let we = WorkerEphemeral::generate();
    let claim = SecretClaim::new_signed(exec, "it-worker".into(), we.public_key(), &worker_sk);
    let reply = nc
        .request(subject.clone(), serde_json::to_vec(&claim).unwrap().into())
        .await
        .expect("claim request");
    let resp: ClaimResponse = serde_json::from_slice(&reply.payload).unwrap();
    let sealed = match resp {
        ClaimResponse::Sealed(s) => s,
        ClaimResponse::Rejected { reason } => panic!("expected sealed, got rejected: {reason}"),
    };
    sealed
        .verify(&controller_vk, 60)
        .expect("controller sig verifies");
    let plaintext = we
        .open(
            &sealed.epk_c,
            exec,
            "it-worker",
            &sealed.ciphertext,
            &sealed.nonce,
        )
        .expect("open sealed secrets");
    let recovered: HashMap<String, String> = serde_json::from_slice(&plaintext).unwrap();
    assert_eq!(recovered.get("anthropic/api_key").unwrap(), "sk-ant-it");

    // --- Single-claim: a second claim for the same exec is rejected. ---
    let we2 = WorkerEphemeral::generate();
    let claim2 = SecretClaim::new_signed(exec, "it-worker".into(), we2.public_key(), &worker_sk);
    let reply2 = nc
        .request(subject.clone(), serde_json::to_vec(&claim2).unwrap().into())
        .await
        .expect("second claim request");
    let resp2: ClaimResponse = serde_json::from_slice(&reply2.payload).unwrap();
    assert!(
        matches!(resp2, ClaimResponse::Rejected { .. }),
        "second claim for the same execution must be rejected (single-claim)"
    );

    // --- Unknown execution → rejected. ---
    let unknown = uuid::Uuid::new_v4();
    let we3 = WorkerEphemeral::generate();
    let claim3 = SecretClaim::new_signed(unknown, "it-worker".into(), we3.public_key(), &worker_sk);
    let reply3 = nc
        .request(subject, serde_json::to_vec(&claim3).unwrap().into())
        .await
        .expect("unknown claim request");
    let resp3: ClaimResponse = serde_json::from_slice(&reply3.payload).unwrap();
    assert!(matches!(resp3, ClaimResponse::Rejected { .. }));
}
