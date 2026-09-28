//! `JobProgress` signing and verification (RFC 0014 P2).

use super::*;
use talos_workflow_engine_core::{WorkerKeyRing, WorkerSharedKey};

fn ring() -> WorkerKeyRing {
    WorkerKeyRing::single(WorkerSharedKey::new(vec![0x5Au8; 32]))
}

fn job() -> Uuid {
    Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap()
}

fn signed_hmac(state: JobProgressState) -> JobProgress {
    let mut p = JobProgress::new(job(), 2, state);
    p.sign_with_worker_id(ring().signing_key().as_bytes(), "worker-a")
        .unwrap();
    p
}

#[test]
fn the_signed_bytes_are_domain_tagged_and_bind_every_field() {
    let mut p = JobProgress::new(job(), 2, JobProgressState::Waiting);
    p.worker_id = "worker-a".to_string();
    p.progress_nonce = "1700000000:abcd".to_string();
    assert_eq!(
        String::from_utf8(p.signing_payload()).unwrap(),
        "progress:11111111-2222-3333-4444-555555555555:2:waiting:1700000000:abcd:worker-a"
    );
}

#[test]
fn an_hmac_report_verifies_once_and_its_replay_is_refused() {
    let p = signed_hmac(JobProgressState::Waiting);
    p.verify_dispatch(&ring(), &[], 300, true)
        .expect("fresh report");
    let replay = p.verify_dispatch(&ring(), &[], 300, true).unwrap_err();
    assert!(replay.to_string().contains("already seen"), "{replay}");
}

#[test]
fn the_observer_verify_never_records_the_nonce() {
    let p = signed_hmac(JobProgressState::Admitted);
    p.verify_no_replay_dispatch(&ring(), &[], 300, true)
        .unwrap();
    p.verify_no_replay_dispatch(&ring(), &[], 300, true)
        .unwrap();
    // The primary verifier still gets its one recording.
    p.verify_dispatch(&ring(), &[], 300, true).unwrap();
}

#[test]
fn changing_any_signed_field_breaks_the_signature() {
    let base = signed_hmac(JobProgressState::Admitted);
    let mut state = base.clone();
    state.state = JobProgressState::Waiting;
    let mut attempt = base.clone();
    attempt.dispatch_attempt = 3;
    let mut id = base.clone();
    id.job_id = Uuid::nil();
    let mut who = base;
    who.worker_id = "worker-b".to_string();
    for (what, p) in [
        ("state", state),
        ("attempt", attempt),
        ("job_id", id),
        ("worker_id", who),
    ] {
        let e = p
            .verify_no_replay_dispatch(&ring(), &[], 300, true)
            .unwrap_err();
        assert_eq!(e.kind(), VerifyFailureKind::BadSignature, "{what}: {e}");
    }
}

#[test]
fn a_report_signed_with_another_key_is_refused() {
    let mut p = JobProgress::new(job(), 0, JobProgressState::Waiting);
    p.sign_with_worker_id(&[0x11u8; 32], "worker-a").unwrap();
    let e = p
        .verify_no_replay_dispatch(&ring(), &[], 300, true)
        .unwrap_err();
    assert_eq!(e.kind(), VerifyFailureKind::BadSignature);
}

#[test]
fn ed25519_reports_verify_against_the_workers_key_only() {
    let sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
    let other = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
    let mut p = JobProgress::new(job(), 1, JobProgressState::Waiting);
    p.sign_ed25519_with_worker_id(&sk, "worker-a").unwrap();
    assert_eq!(p.crypto_scheme, CRYPTO_SCHEME_ED25519);
    assert!(p
        .verify_no_replay_dispatch(&ring(), &[other.verifying_key()], 300, true)
        .is_err());
    p.verify_dispatch(&ring(), &[sk.verifying_key()], 300, true)
        .unwrap();
    assert!(JobProgress::new(job(), 1, JobProgressState::Waiting)
        .sign_ed25519_with_worker_id(&sk, "")
        .is_err());
}

#[test]
fn legacy_hmac_is_refused_under_ed25519_only_enforcement() {
    let p = signed_hmac(JobProgressState::Waiting);
    let e = p
        .verify_no_replay_dispatch(&ring(), &[], 300, false)
        .unwrap_err();
    assert_eq!(e.kind(), VerifyFailureKind::SchemeRefused);
}

#[test]
fn a_report_is_never_a_valid_result_and_a_result_never_a_report() {
    // Same key, same job, same nonce and worker: the domain tag keeps the two
    // payloads apart, so one signature can never serve for the other message.
    let p = signed_hmac(JobProgressState::Admitted);
    let mut r = JobResult {
        job_id: p.job_id,
        status: JobStatus::Success,
        output_payload: serde_json::json!({}).into(),
        logs: vec![],
        execution_time_ms: 0,
        signature: p.signature.clone(),
        result_nonce: p.progress_nonce.clone(),
        worker_id: p.worker_id.clone(),
        crypto_scheme: CRYPTO_SCHEME_HMAC,
        llm_usage: vec![],
    };
    assert_ne!(r.signing_payload(), p.signing_payload());
    assert!(r
        .verify_no_replay_dispatch(&ring(), &[], 300, true)
        .is_err());
    r.sign_with_worker_id(ring().signing_key().as_bytes(), "worker-a")
        .unwrap();
    let mut forged = p;
    forged.signature = r.signature.clone();
    forged.progress_nonce = r.result_nonce.clone();
    assert!(forged
        .verify_no_replay_dispatch(&ring(), &[], 300, true)
        .is_err());
}

#[test]
fn the_wire_shape_round_trips_with_snake_case_states() {
    let p = signed_hmac(JobProgressState::Waiting);
    let wire = serde_json::to_value(&p).unwrap();
    assert_eq!(wire["state"], "waiting");
    let back: JobProgress = serde_json::from_value(wire).unwrap();
    back.verify_no_replay_dispatch(&ring(), &[], 300, true)
        .unwrap();
}

#[test]
fn the_progress_subject_hangs_off_the_signed_reply_inbox() {
    assert_eq!(
        subjects::job_progress_for("_INBOX.abc"),
        "_INBOX.abc.progress"
    );
    assert!(nats_permissions::worker_may_publish(
        &subjects::job_progress_for("_INBOX.abcdef.1")
    ));
}
