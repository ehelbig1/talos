//! Which dispatch a `JobResult` answers (security review 2026-10-14, B-9).

use super::*;

fn job() -> Uuid {
    Uuid::from_u128(1)
}

fn execution() -> Uuid {
    Uuid::from_u128(2)
}

fn live(attempt: u32) -> DispatchIdentity {
    DispatchIdentity {
        job_id: job(),
        dispatch_attempt: attempt,
        workflow_execution_id: execution(),
    }
}

fn result(attempt: u32, execution: Option<Uuid>) -> JobResult {
    JobResult {
        dispatch_attempt: attempt,
        workflow_execution_id: execution,
        job_id: job(),
        status: JobStatus::Success,
        output_payload: serde_json::json!({"out": 1}).into(),
        logs: vec![],
        execution_time_ms: 1,
        signature: vec![],
        result_nonce: String::new(),
        worker_id: String::new(),
        crypto_scheme: CRYPTO_SCHEME_HMAC,
        llm_usage: vec![],
        fuel: None,
    }
}

#[test]
fn a_result_answers_only_the_attempt_and_execution_it_names() {
    assert_eq!(
        result(1, Some(execution())).answers(&live(1)),
        ResultAnswer::ThisDispatch
    );
    // A slow attempt's result while the next attempt is awaited.
    assert_eq!(
        result(0, Some(execution())).answers(&live(1)),
        ResultAnswer::EarlierAttempt
    );
    // An attempt never sent.
    assert_eq!(
        result(2, Some(execution())).answers(&live(1)),
        ResultAnswer::Mismatch
    );
    // Another execution's result for the same job id.
    assert_eq!(
        result(1, Some(Uuid::from_u128(3))).answers(&live(1)),
        ResultAnswer::Mismatch
    );
    // Another job.
    let mut other = result(1, Some(execution()));
    other.job_id = Uuid::from_u128(9);
    assert_eq!(other.answers(&live(1)), ResultAnswer::Mismatch);
}

#[test]
fn a_pre_binding_workers_result_is_unbound_and_an_attempt_alone_is_refused() {
    assert_eq!(result(0, None).answers(&live(0)), ResultAnswer::Unbound);
    assert_eq!(result(0, None).answers(&live(3)), ResultAnswer::Unbound);
    // No worker sends an attempt without its execution.
    assert_eq!(result(1, None).answers(&live(1)), ResultAnswer::Mismatch);
}

#[test]
fn the_binding_is_signed_and_a_bound_result_still_verifies() {
    let key = [0x5Au8; 32];
    let mut r = result(2, Some(execution()));
    r.sign_with_worker_id(&key, "worker-a").unwrap();
    let ring = talos_workflow_engine_core::WorkerKeyRing::single(
        talos_workflow_engine_core::WorkerSharedKey::new(key.to_vec()),
    );
    r.verify_no_replay_dispatch(&ring, &[], 300, true)
        .expect("a bound result verifies");
    let mut moved = r.clone();
    moved.dispatch_attempt = 3;
    assert!(moved
        .verify_no_replay_dispatch(&ring, &[], 300, true)
        .is_err());
    let mut unbound = r;
    unbound.workflow_execution_id = None;
    assert!(unbound
        .verify_no_replay_dispatch(&ring, &[], 300, true)
        .is_err());
}
