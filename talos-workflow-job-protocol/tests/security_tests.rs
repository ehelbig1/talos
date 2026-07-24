//! Security boundary tests for the job protocol.
//!
//! These tests cover oversized payload rejection, HMAC nonce validation,
//! nonce replay detection, and tampered job request handling.

use serde_json::json;
use talos_workflow_job_protocol::{
    EgressScope, EncryptedSecrets, JobRequest, JobResult, JobStatus, LlmTier, PipelineJobRequest,
    PipelineStep, WriteCeiling,
};
use uuid::Uuid;

fn test_key() -> Vec<u8> {
    vec![0x42u8; 32]
}

fn make_job_request() -> JobRequest {
    JobRequest {
        crypto_scheme: 0,
        sealing: 0,
        secret_paths: Vec::new(),
        claim_inbox: None,
        job_id: Uuid::new_v4(),
        workflow_execution_id: Uuid::new_v4(),
        module_uri: "file://tmp/module.wasm".to_string(),
        input_payload: json!({"key": "value"}),
        encrypted_secrets: EncryptedSecrets::empty(),
        timeout_ms: 5000,
        allowed_hosts: vec!["example.com".to_string()],
        allowed_methods: vec!["GET".to_string()],
        allowed_secrets: vec![],
        allowed_sql_operations: vec![],
        allow_tier2_exposure: false,
        priority: 100,
        deadline_unix_secs: 0,
        cancellation_token: None,
        signature: vec![],
        max_llm_tier: LlmTier::default(),
        max_write_ceiling: WriteCeiling::default(),
        egress_scope: None,
        job_nonce: String::new(),
        actor_id: None,
        wasm_bytes: None,
        capability_world: None,
        expected_wasm_hash: None,
        integration_name: None,
        user_id: Uuid::nil(),
        max_fuel: 0,
        dry_run: false,
        reply_topic: None,
        idempotency_key: None,
    }
}

fn make_pipeline_step() -> PipelineStep {
    PipelineStep {
        module_id: Uuid::new_v4(),
        module_uri: "file://tmp/module.wasm".to_string(),
        wasm_bytes: Some(vec![0x00, 0x61, 0x73, 0x6d]),
        config: json!({"setting": "value"}),
        allowed_hosts: vec!["api.example.com".to_string()],
        allowed_methods: vec!["GET".to_string()],
        encrypted_secrets: EncryptedSecrets::empty(),
        max_fuel: 1_000_000,
        max_memory_mb: 128,
        timeout_ms: 30_000,
        allowed_secrets: vec![],
        allowed_sql_operations: vec![],
        allow_tier2_exposure: false,
        priority: 100,
        cancellation_token: None,
        expected_wasm_hash: None,
        integration_name: None,
        max_retries: 0,
        retry_backoff_ms: 0,
    }
}

// ===========================================================================
// Note: Oversized payload rejection tests removed — deserialize_job_request,
// deserialize_pipeline_job_request, MAX_PAYLOAD_SIZE, and ProtocolError are
// not yet part of the public API. Those tests should be added back when the
// safe deserialization functions are implemented.
// ===========================================================================

// ===========================================================================
// HMAC nonce with invalid hex characters
// ===========================================================================

#[test]
fn nonce_with_invalid_hex_is_rejected() {
    let key = test_key();
    let mut req = make_job_request();
    req.sign(&key).unwrap();

    // Replace the random hex component with invalid hex characters.
    let parts: Vec<&str> = req.job_nonce.splitn(2, ':').collect();
    req.job_nonce = format!("{}:ZZZZ_not_hex!!!!", parts[0]);

    let result = req.verify(&key, 300);
    assert!(result.is_err(), "Nonce with invalid hex must be rejected");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("invalid hex"),
        "Error should mention invalid hex: {}",
        err_msg
    );
}

#[test]
fn nonce_with_missing_random_component_is_rejected() {
    let key = test_key();
    let mut req = make_job_request();
    req.sign(&key).unwrap();

    // Remove the random hex portion (leave only the timestamp).
    let ts = req.job_nonce.split(':').next().unwrap().to_string();
    req.job_nonce = ts; // No colon, no hex

    let result = req.verify(&key, 300);
    assert!(
        result.is_err(),
        "Nonce without random component must be rejected"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("malformed"),
        "Error should mention malformed nonce: {}",
        err_msg
    );
}

#[test]
fn nonce_with_non_numeric_timestamp_is_rejected() {
    let key = test_key();
    let mut req = make_job_request();
    req.sign(&key).unwrap();

    req.job_nonce = "not_a_number:deadbeef".to_string();
    let result = req.verify(&key, 300);
    assert!(
        result.is_err(),
        "Nonce with non-numeric timestamp must be rejected"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("invalid timestamp"),
        "Error should mention invalid timestamp: {}",
        err_msg
    );
}

#[test]
fn nonce_with_empty_hex_is_rejected() {
    let key = test_key();
    let mut req = make_job_request();
    req.sign(&key).unwrap();

    let ts = req.job_nonce.split(':').next().unwrap().to_string();
    req.job_nonce = format!("{}:", ts); // Colon present but empty hex

    // Empty string is valid hex (decodes to empty vec), so this modifies the
    // signing payload, causing HMAC verification to fail.
    let result = req.verify(&key, 300);
    assert!(
        result.is_err(),
        "Nonce with empty hex should fail verification (signature mismatch)"
    );
}

// ===========================================================================
// HMAC nonce replay (same nonce used twice / expired nonce)
// ===========================================================================

#[test]
fn expired_nonce_is_rejected() {
    let key = test_key();
    let mut req = make_job_request();
    req.sign(&key).unwrap();

    // Forge the nonce to have a very old timestamp (10 minutes ago).
    let old_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .saturating_sub(600); // 10 minutes ago

    let hex_part = req.job_nonce.split_once(':').unwrap().1.to_string();
    req.job_nonce = format!("{}:{}", old_ts, hex_part);

    // Re-sign with the old nonce is not possible without knowledge of the
    // signing payload construction, but we can test that the verify step
    // catches the stale timestamp even if the signature were somehow valid.
    // In practice, the signature will also fail because the nonce changed.
    let result = req.verify(&key, 300);
    assert!(
        result.is_err(),
        "Nonce older than max_age_secs must be rejected"
    );
}

#[test]
fn nonce_freshness_boundary() {
    let key = test_key();
    let mut req = make_job_request();
    req.sign(&key).unwrap();

    // A freshly signed request (within the last second) should verify fine
    // with a generous max_age_secs.
    req.verify(&key, 300)
        .expect("Fresh nonce should verify within 300s window");

    // With max_age_secs = 0, even a freshly signed nonce might fail because
    // the clock has advanced by at least 0 seconds since signing.
    // This is implementation-dependent, but let's verify max_age_secs=0
    // is extremely strict.
    // Note: This may or may not fail depending on timing. We just verify
    // that the function doesn't panic.
    let _result = req.verify(&key, 0);
}

// ===========================================================================
// Tampered job request (modified after signing)
// ===========================================================================

#[test]
fn tampered_input_payload_fails_verification() {
    let key = test_key();
    let mut req = make_job_request();
    req.sign(&key).unwrap();

    // Tamper: change the input payload.
    req.input_payload = json!({"injected": "malicious_data"});

    let result = req.verify(&key, 300);
    assert!(
        result.is_err(),
        "Tampered input_payload must invalidate the signature"
    );
}

#[test]
fn tampered_egress_scope_fails_verification() {
    // An on-wire attacker must not be able to flip a signed egress_scope —
    // e.g. downgrade a `public` job to `local` (DoS) or, worse, lift a
    // `local` (air-gapped) actor's block to `public` to exfiltrate.
    let key = test_key();
    let mut req = make_job_request();
    req.egress_scope = Some(EgressScope::Public);
    req.sign(&key).unwrap();
    req.egress_scope = Some(EgressScope::Local);
    assert!(
        req.verify(&key, 300).is_err(),
        "Tampered egress_scope must invalidate the signature"
    );
}

#[test]
fn stripping_signed_egress_scope_fails_verification() {
    // Stripping the override (Some → None) would fall an air-gapped-via-override
    // actor back to its tier-derived default. Because the field is bound ONLY
    // when Some, stripping it changes the signed bytes → verification fails.
    let key = test_key();
    let mut req = make_job_request();
    req.egress_scope = Some(EgressScope::Local);
    req.sign(&key).unwrap();
    req.egress_scope = None;
    assert!(
        req.verify(&key, 300).is_err(),
        "Stripping a signed egress_scope must invalidate the signature"
    );
}

#[test]
fn default_none_egress_scope_signature_is_stable() {
    // The default (None) appends nothing to the signing payload, so a
    // round-trip signs+verifies exactly as before the field existed.
    let key = test_key();
    let mut req = make_job_request();
    assert!(req.egress_scope.is_none());
    req.sign(&key).unwrap();
    assert!(
        req.verify(&key, 300).is_ok(),
        "default-None egress_scope must sign+verify cleanly"
    );
}

#[test]
fn tampered_timeout_fails_verification() {
    let key = test_key();
    let mut req = make_job_request();
    req.sign(&key).unwrap();

    // Tamper: increase the timeout (attacker wants longer execution).
    req.timeout_ms = 999_999;

    let result = req.verify(&key, 300);
    assert!(
        result.is_err(),
        "Tampered timeout_ms must invalidate the signature"
    );
}

#[test]
fn tampered_allowed_hosts_fails_verification() {
    let key = test_key();
    let mut req = make_job_request();
    req.sign(&key).unwrap();

    // Tamper: add an attacker-controlled host.
    req.allowed_hosts.push("evil.com".to_string());

    let result = req.verify(&key, 300);
    assert!(
        result.is_err(),
        "Tampered allowed_hosts must invalidate the signature"
    );
}

#[test]
fn tampered_wasm_bytes_fails_verification() {
    let key = test_key();
    let mut req = make_job_request();
    req.wasm_bytes = Some(vec![0x00, 0x61, 0x73, 0x6d]); // valid WASM magic
    req.sign(&key).unwrap();

    // Tamper: replace WASM bytes with malicious code.
    req.wasm_bytes = Some(vec![0xFF, 0xFF, 0xFF, 0xFF]);

    let result = req.verify(&key, 300);
    assert!(
        result.is_err(),
        "Tampered wasm_bytes must invalidate the signature"
    );
}

// Note: user_id and required_capabilities fields were removed from the protocol.
// Tamper tests for those fields are no longer applicable.

// ===========================================================================
// Pipeline-specific tamper tests
// ===========================================================================

#[test]
fn pipeline_tampered_step_count_fails() {
    let key = test_key();
    let mut req = PipelineJobRequest {
        crypto_scheme: 0,
        sealing: 0,
        secret_paths: Vec::new(),
        claim_inbox: None,
        job_id: Uuid::new_v4(),
        workflow_execution_id: Uuid::new_v4(),
        steps: vec![make_pipeline_step()],
        total_timeout_ms: 30_000,
        share_sandbox: false,
        signature: vec![],
        max_llm_tier: LlmTier::default(),
        max_write_ceiling: WriteCeiling::default(),
        egress_scope: None,
        reply_topic: None,
        job_nonce: String::new(),
        user_id: Uuid::new_v4(),
    };
    req.sign(&key).unwrap();

    // Tamper: inject an additional step.
    req.steps.push(make_pipeline_step());

    let result = req.verify(&key, 300);
    assert!(
        result.is_err(),
        "Adding a step after signing must invalidate the signature"
    );
}

#[test]
fn pipeline_tampered_share_sandbox_fails() {
    let key = test_key();
    let mut req = PipelineJobRequest {
        crypto_scheme: 0,
        sealing: 0,
        secret_paths: Vec::new(),
        claim_inbox: None,
        job_id: Uuid::new_v4(),
        workflow_execution_id: Uuid::new_v4(),
        steps: vec![make_pipeline_step()],
        total_timeout_ms: 30_000,
        share_sandbox: false,
        signature: vec![],
        max_llm_tier: LlmTier::default(),
        max_write_ceiling: WriteCeiling::default(),
        egress_scope: None,
        reply_topic: None,
        job_nonce: String::new(),
        user_id: Uuid::new_v4(),
    };
    req.sign(&key).unwrap();

    // Tamper: enable sandbox sharing (could leak data between steps).
    req.share_sandbox = true;

    let result = req.verify(&key, 300);
    assert!(
        result.is_err(),
        "Tampered share_sandbox must invalidate the signature"
    );
}

// ===========================================================================
// Signing with wrong key
// ===========================================================================

#[test]
fn wrong_key_fails_verification() {
    let key_a = vec![0x42u8; 32];
    let key_b = vec![0xFFu8; 32];

    let mut req = make_job_request();
    req.sign(&key_a).unwrap();

    let result = req.verify(&key_b, 300);
    assert!(
        result.is_err(),
        "Verification with a different key must fail"
    );
}

#[test]
fn unsigned_request_fails_verification() {
    let key = test_key();
    let req = make_job_request();
    // Never signed — signature is empty, nonce is empty.
    let result = req.verify(&key, 300);
    assert!(result.is_err(), "Unsigned request must fail verification");
}

// ===========================================================================
// JobResult tamper tests
// ===========================================================================

#[test]
fn tampered_job_result_status_fails() {
    let key = test_key();
    let mut result = JobResult {
        llm_usage: vec![],
        crypto_scheme: 0,
        job_id: Uuid::new_v4(),
        status: JobStatus::Failed,
        output_payload: json!({"error": "something went wrong"}),
        logs: vec![],
        execution_time_ms: 100,
        signature: vec![],
        result_nonce: String::new(),
        worker_id: String::new(),
    };
    result.sign(&key).unwrap();

    // Tamper: change status from Failed to Success.
    result.status = JobStatus::Success;

    assert!(
        result.verify(&key, 300).is_err(),
        "Tampered job result status must invalidate the signature"
    );
}

#[test]
fn tampered_job_result_execution_time_fails() {
    let key = test_key();
    let mut result = JobResult {
        llm_usage: vec![],
        crypto_scheme: 0,
        job_id: Uuid::new_v4(),
        status: JobStatus::Success,
        output_payload: json!({}),
        logs: vec![],
        execution_time_ms: 100,
        signature: vec![],
        result_nonce: String::new(),
        worker_id: String::new(),
    };
    result.sign(&key).unwrap();

    // Tamper: inflate execution time to affect billing.
    result.execution_time_ms = 999_999;

    assert!(
        result.verify(&key, 300).is_err(),
        "Tampered execution_time_ms must invalidate the signature"
    );
}

// ------------------------------------------------------------------
// integration_name tamper-evidence
// ------------------------------------------------------------------

#[test]
fn tampered_job_request_user_id_fails() {
    let key = test_key();
    let mut req = make_job_request();
    req.user_id = Uuid::new_v4();
    req.sign(&key).unwrap();

    // Tamper: swap to a different user_id. A NATS-channel attacker
    // without this binding could redirect a module's integration_state
    // writes into another user's namespace. The HMAC now covers
    // user_id so this must fail verify.
    req.user_id = Uuid::new_v4();

    assert!(
        req.verify(&key, 300).is_err(),
        "Tampered user_id must invalidate the signature"
    );
}

#[test]
fn tampered_job_request_user_id_to_nil_fails() {
    let key = test_key();
    let mut req = make_job_request();
    req.user_id = Uuid::new_v4();
    req.sign(&key).unwrap();

    // Swap to Uuid::nil() (the sentinel the worker treats as 'no user
    // context'). Even though nil would route to 'not available' at the
    // host fn, the tamper must still fail verify at the transport layer.
    req.user_id = Uuid::nil();

    assert!(
        req.verify(&key, 300).is_err(),
        "user_id swap to nil must invalidate the signature"
    );
}

#[test]
fn tampered_job_request_integration_name_fails() {
    let key = test_key();
    let mut req = make_job_request();
    req.integration_name = Some("gcal".to_string());
    req.sign(&key).unwrap();

    // Tamper: swap the integration namespace on the wire. Without
    // integration_name in the HMAC commitment, a NATS-channel attacker
    // could redirect a module's integration_state writes into a
    // different integration's namespace. This test locks that in.
    req.integration_name = Some("gmail".to_string());

    assert!(
        req.verify(&key, 300).is_err(),
        "Tampered integration_name must invalidate the signature"
    );
}

#[test]
fn tampered_job_request_integration_name_unset_to_set_fails() {
    let key = test_key();
    let mut req = make_job_request();
    req.integration_name = None; // non-integration module
    req.sign(&key).unwrap();

    // Tamper: promote a non-integration module into an integration by
    // setting a name. Must fail verify.
    req.integration_name = Some("gcal".to_string());

    assert!(
        req.verify(&key, 300).is_err(),
        "Promoting a non-integration module via integration_name must fail verify"
    );
}

#[test]
fn tampered_pipeline_step_integration_name_fails() {
    let key = test_key();
    let mut req = PipelineJobRequest {
        crypto_scheme: 0,
        sealing: 0,
        secret_paths: Vec::new(),
        claim_inbox: None,
        job_id: Uuid::new_v4(),
        workflow_execution_id: Uuid::new_v4(),
        steps: vec![{
            let mut s = make_pipeline_step();
            s.integration_name = Some("gcal".to_string());
            s
        }],
        total_timeout_ms: 60_000,
        share_sandbox: false,
        signature: vec![],
        max_llm_tier: LlmTier::default(),
        max_write_ceiling: WriteCeiling::default(),
        egress_scope: None,
        reply_topic: None,
        job_nonce: String::new(),
        user_id: Uuid::new_v4(),
    };
    req.sign(&key).unwrap();

    // Tamper: swap the step's integration_name.
    req.steps[0].integration_name = Some("gmail".to_string());

    assert!(
        req.verify(&key, 300).is_err(),
        "Tampered step integration_name must invalidate the pipeline signature"
    );
}

// ------------------------------------------------------------------
// verify_no_replay — passive-observer pattern (regression for the
// dual-publish/dual-verify bug where a primary verify() and a
// secondary subscriber verify() both racing on the shared
// JOB_NONCE_CACHE caused "result_nonce already seen" on every job).
// ------------------------------------------------------------------

fn signed_job_result(key: &[u8]) -> JobResult {
    let mut result = JobResult {
        llm_usage: vec![],
        crypto_scheme: 0,
        job_id: Uuid::new_v4(),
        status: JobStatus::Success,
        output_payload: json!({"ok": true}),
        logs: vec![],
        execution_time_ms: 42,
        signature: vec![],
        result_nonce: String::new(),
        worker_id: String::new(),
    };
    result.sign(key).unwrap();
    result
}

#[test]
fn verify_no_replay_accepts_repeated_calls() {
    // The whole point of `verify_no_replay`: same nonce can be
    // verified multiple times without tripping the replay cache.
    // This is what unblocks the dispatcher + subscriber pattern.
    let key = test_key();
    let result = signed_job_result(&key);

    assert!(result.verify_no_replay(&key, 300).is_ok());
    assert!(result.verify_no_replay(&key, 300).is_ok());
    assert!(result.verify_no_replay(&key, 300).is_ok());
}

#[test]
fn verify_no_replay_rejects_tampered_signature() {
    // HMAC enforcement is preserved — only the cache check is dropped.
    let key = test_key();
    let mut result = signed_job_result(&key);
    result.execution_time_ms = 999_999; // tamper

    assert!(result.verify_no_replay(&key, 300).is_err());
}

#[test]
fn verify_no_replay_rejects_wrong_key() {
    // HMAC under wrong key fails — forgery prevention preserved.
    let result = signed_job_result(&test_key());
    let wrong_key = vec![0x01u8; 32];

    assert!(result.verify_no_replay(&wrong_key, 300).is_err());
}

#[test]
fn verify_no_replay_rejects_malformed_nonce() {
    let key = test_key();
    let mut result = signed_job_result(&key);
    result.result_nonce = "not-a-valid-nonce".to_string();

    let err = result.verify_no_replay(&key, 300).unwrap_err();
    assert!(
        err.contains("malformed result_nonce") || err.contains("invalid"),
        "expected nonce-shape error, got: {}",
        err
    );
}

#[test]
fn primary_verify_then_secondary_verify_no_replay_both_succeed() {
    // The intended dispatcher (primary) + subscriber (secondary)
    // call pattern. Pre-fix, the second call hit "already seen".
    // Post-fix, the secondary uses verify_no_replay and succeeds.
    let key = test_key();
    let result = signed_job_result(&key);

    // Primary verifier records the nonce in the cache.
    result
        .verify(&key, 300)
        .expect("primary verify must succeed");

    // Secondary verifier (passive observer) must succeed even though
    // the nonce is already in the cache — that is the whole point.
    result
        .verify_no_replay(&key, 300)
        .expect("verify_no_replay must succeed after primary verify");
}

#[test]
fn primary_verify_still_rejects_actual_replay() {
    // Replay protection is still enforced on the PRIMARY path.
    // Two distinct `verify()` calls on the same nonce — the second
    // one (a real replay attempt) must be rejected. This guards
    // against accidentally weakening the security invariant while
    // splitting the API.
    let key = test_key();
    let result = signed_job_result(&key);

    result.verify(&key, 300).expect("first verify must succeed");
    let err = result
        .verify(&key, 300)
        .expect_err("second verify must be rejected as replay");
    assert!(
        err.contains("already seen"),
        "expected replay rejection, got: {}",
        err
    );
}

#[test]
fn verify_no_replay_does_not_pollute_cache_for_subsequent_verify() {
    // verify_no_replay must NOT record the nonce — otherwise a
    // call site that uses verify_no_replay first would block a
    // subsequent legitimate primary verify().
    let key = test_key();
    let result = signed_job_result(&key);

    result
        .verify_no_replay(&key, 300)
        .expect("verify_no_replay must succeed");
    // Primary verify() must still succeed: verify_no_replay didn't
    // touch the cache.
    result
        .verify(&key, 300)
        .expect("primary verify after verify_no_replay must succeed");
}

// ------------------------------------------------------------------
// PipelineJobResult — verify_no_replay parity with JobResult.
// Pipeline results have only one verifier today (the engine
// dispatcher). The worker dual-publishes pipeline results to the
// reply inbox AND `talos.pipeline.results.{job_id}`, so adding a
// future audit subscriber would silently re-introduce the JobResult
// dual-verify bug. These tests + the API split fix the latent issue
// before it becomes a production regression.
// ------------------------------------------------------------------

fn signed_pipeline_result(key: &[u8]) -> talos_workflow_job_protocol::PipelineJobResult {
    let mut result = talos_workflow_job_protocol::PipelineJobResult {
        llm_usage: vec![],
        crypto_scheme: 0,
        job_id: Uuid::new_v4(),
        overall_status: JobStatus::Success,
        step_results: vec![],
        final_output: json!({"ok": true}),
        total_time_ms: 42,
        signature: vec![],
        result_nonce: String::new(),
        worker_id: String::new(),
    };
    result.sign(key).unwrap();
    result
}

#[test]
fn pipeline_verify_no_replay_accepts_repeated_calls() {
    let key = test_key();
    let result = signed_pipeline_result(&key);

    assert!(result.verify_no_replay(&key, 300).is_ok());
    assert!(result.verify_no_replay(&key, 300).is_ok());
    assert!(result.verify_no_replay(&key, 300).is_ok());
}

#[test]
fn pipeline_verify_no_replay_rejects_tampered_signature() {
    let key = test_key();
    let mut result = signed_pipeline_result(&key);
    result.total_time_ms = 999_999; // tamper

    assert!(result.verify_no_replay(&key, 300).is_err());
}

#[test]
fn pipeline_verify_no_replay_rejects_wrong_key() {
    let result = signed_pipeline_result(&test_key());
    let wrong_key = vec![0x01u8; 32];

    assert!(result.verify_no_replay(&wrong_key, 300).is_err());
}

#[test]
fn pipeline_verify_no_replay_rejects_malformed_nonce() {
    let key = test_key();
    let mut result = signed_pipeline_result(&key);
    result.result_nonce = "not-a-valid-nonce".to_string();

    let err = result.verify_no_replay(&key, 300).unwrap_err();
    assert!(
        err.contains("malformed result_nonce") || err.contains("invalid"),
        "expected nonce-shape error, got: {}",
        err
    );
}

#[test]
fn pipeline_primary_verify_then_secondary_verify_no_replay_both_succeed() {
    // The future-proof guarantee: if a second pipeline-result
    // consumer is added (audit subscriber, metrics emitter), it can
    // use verify_no_replay() and won't collide with the dispatcher's
    // primary verify().
    let key = test_key();
    let result = signed_pipeline_result(&key);

    result
        .verify(&key, 300)
        .expect("primary verify must succeed");
    result
        .verify_no_replay(&key, 300)
        .expect("verify_no_replay must succeed after primary verify");
}

#[test]
fn pipeline_primary_verify_still_rejects_actual_replay() {
    // Replay protection invariant: same nonce, two distinct
    // verify() calls — the second is a real replay attempt and
    // must be rejected. Locks in that splitting the API didn't
    // weaken the primary path.
    let key = test_key();
    let result = signed_pipeline_result(&key);

    result.verify(&key, 300).expect("first verify must succeed");
    let err = result
        .verify(&key, 300)
        .expect_err("second verify must be rejected as replay");
    assert!(
        err.contains("already seen"),
        "expected replay rejection, got: {}",
        err
    );
}

#[test]
fn pipeline_verify_no_replay_does_not_pollute_cache() {
    let key = test_key();
    let result = signed_pipeline_result(&key);

    result
        .verify_no_replay(&key, 300)
        .expect("verify_no_replay must succeed");
    result
        .verify(&key, 300)
        .expect("primary verify after verify_no_replay must succeed");
}

// ────────────────────────────────────────────────────────────────────
// L-11: worker_id binding. A worker's self-reported identity is part
// of the signed canonical bytes; an on-wire attacker who flips the
// worker_id (e.g. to point blame at a different pod for forensic
// confusion) breaks the HMAC.
// ────────────────────────────────────────────────────────────────────

#[test]
fn tampered_job_result_worker_id_fails() {
    let key = test_key();
    let mut result = JobResult {
        llm_usage: vec![],
        crypto_scheme: 0,
        job_id: Uuid::new_v4(),
        status: JobStatus::Success,
        output_payload: json!({"ok": true}),
        logs: vec![],
        execution_time_ms: 7,
        signature: vec![],
        result_nonce: String::new(),
        worker_id: String::new(),
    };
    result
        .sign_with_worker_id(&key, "worker-a")
        .expect("sign with worker-a");
    // Forge: keep signature, swap worker_id to a different pod's
    // identity. The HMAC must reject — the worker_id is part of the
    // signing payload.
    result.worker_id = "worker-b".into();
    assert!(
        result.verify(&key, 300).is_err(),
        "worker_id tamper must fail HMAC verification"
    );
}

#[test]
fn tampered_pipeline_result_worker_id_fails() {
    let key = test_key();
    let mut result = talos_workflow_job_protocol::PipelineJobResult {
        llm_usage: vec![],
        crypto_scheme: 0,
        job_id: Uuid::new_v4(),
        step_results: vec![],
        final_output: json!({"step": "ok"}),
        overall_status: JobStatus::Success,
        total_time_ms: 7,
        signature: vec![],
        result_nonce: String::new(),
        worker_id: String::new(),
    };
    result
        .sign_with_worker_id(&key, "worker-a")
        .expect("sign with worker-a");
    result.worker_id = "worker-b".into();
    assert!(
        result.verify(&key, 300).is_err(),
        "pipeline worker_id tamper must fail HMAC verification"
    );
}

#[test]
fn worker_id_invalid_chars_rejected_at_sign_time() {
    // Validation happens BEFORE HMAC compute, so a malformed
    // worker_id fails closed without producing an artifact at all.
    let key = test_key();
    let mut result = JobResult {
        llm_usage: vec![],
        crypto_scheme: 0,
        job_id: Uuid::new_v4(),
        status: JobStatus::Success,
        output_payload: json!({"ok": true}),
        logs: vec![],
        execution_time_ms: 7,
        signature: vec![],
        result_nonce: String::new(),
        worker_id: String::new(),
    };
    // Embedded colon — would shift the signing-payload field
    // boundary if accepted.
    let err = result
        .sign_with_worker_id(&key, "worker:1")
        .expect_err("colon must be rejected");
    assert!(
        err.contains("worker_id"),
        "error must name the offending field — got: {err}"
    );
    // Signature must NOT have been written (fail-closed contract).
    assert!(
        result.signature.is_empty(),
        "signature must not be set when worker_id validation fails"
    );
}

#[test]
fn worker_id_empty_passes_for_backcompat() {
    // The bare `sign()` wrapper leaves worker_id empty for test
    // fixtures; empty must still verify cleanly.
    let key = test_key();
    let mut result = JobResult {
        llm_usage: vec![],
        crypto_scheme: 0,
        job_id: Uuid::new_v4(),
        status: JobStatus::Success,
        output_payload: json!({"ok": true}),
        logs: vec![],
        execution_time_ms: 7,
        signature: vec![],
        result_nonce: String::new(),
        worker_id: String::new(),
    };
    result.sign(&key).expect("bare sign must succeed");
    result
        .verify(&key, 300)
        .expect("bare sign result must verify");
    assert_eq!(result.worker_id, "");
}
