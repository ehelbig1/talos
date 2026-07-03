//! Basic serialization / deserialization tests for the shared job protocol.

use serde_json::json;
use talos_workflow_job_protocol::{
    EncryptedSecrets, JobRequest, JobResult, JobStatus, LlmTier, PipelineJobRequest,
    PipelineJobResult, PipelineStep, PipelineStepResult,
};
use uuid::Uuid;

#[test]
fn job_request_roundtrip() {
    let req = JobRequest {
        crypto_scheme: 0,
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
        signature: vec![0, 1, 2, 3],
        job_nonce: "0:deadbeef".to_string(),
        actor_id: None,
        wasm_bytes: None,
        capability_world: None,
        expected_wasm_hash: None,
        integration_name: None,
        user_id: Uuid::nil(),
        max_fuel: 0,
        dry_run: false,
        reply_topic: None,
        max_llm_tier: LlmTier::default(),
    };
    let ser = serde_json::to_string(&req).expect("serialize request");
    let de: JobRequest = serde_json::from_str(&ser).expect("deserialize request");
    assert_eq!(req.job_id, de.job_id);
    assert_eq!(req.module_uri, de.module_uri);
}

#[test]
fn job_result_roundtrip() {
    let res = JobResult {
        crypto_scheme: 0,
        job_id: Uuid::new_v4(),
        status: JobStatus::Success,
        output_payload: json!({"out": 42}),
        logs: vec!["log entry".to_string()],
        execution_time_ms: 123,
        signature: vec![],
        result_nonce: String::new(),
        worker_id: String::new(),
    };
    let ser = serde_json::to_string(&res).expect("serialize result");
    let de: JobResult = serde_json::from_str(&ser).expect("deserialize result");
    assert_eq!(res.job_id, de.job_id);
    assert_eq!(de.status, JobStatus::Success);
}

// ============================================================================
// Pipeline protocol tests
// ============================================================================

fn test_key() -> Vec<u8> {
    vec![0x42u8; 32]
}

fn make_pipeline_step() -> PipelineStep {
    PipelineStep {
        module_id: Uuid::new_v4(),
        // Provide a placeholder URI; the actual WASM bytes are supplied via `wasm_bytes`.
        module_uri: "file://tmp/module.wasm".to_string(),
        wasm_bytes: Some(vec![0x00, 0x61, 0x73, 0x6d]), // minimal WASM magic bytes
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
    }
}

#[test]
fn pipeline_job_request_roundtrip() {
    let req = PipelineJobRequest {
        crypto_scheme: 0,
        job_id: Uuid::new_v4(),
        workflow_execution_id: Uuid::new_v4(),
        steps: vec![make_pipeline_step(), make_pipeline_step()],
        total_timeout_ms: 120_000,
        share_sandbox: true,
        signature: vec![],
        max_llm_tier: LlmTier::default(),
        reply_topic: None,
        job_nonce: "0:deadbeef".to_string(),
        user_id: Uuid::new_v4(),
    };

    let ser = serde_json::to_string(&req).expect("serialize PipelineJobRequest");
    let de: PipelineJobRequest =
        serde_json::from_str(&ser).expect("deserialize PipelineJobRequest");

    assert_eq!(req.job_id, de.job_id);
    assert_eq!(req.workflow_execution_id, de.workflow_execution_id);
    assert_eq!(req.steps.len(), de.steps.len());
    assert_eq!(req.total_timeout_ms, de.total_timeout_ms);
    assert_eq!(req.share_sandbox, de.share_sandbox);
}

#[test]
fn pipeline_job_request_sign_and_verify() {
    let key = test_key();
    let mut req = PipelineJobRequest {
        crypto_scheme: 0,
        job_id: Uuid::new_v4(),
        workflow_execution_id: Uuid::new_v4(),
        steps: vec![make_pipeline_step()],
        total_timeout_ms: 30_000,
        share_sandbox: false,
        signature: vec![],
        max_llm_tier: LlmTier::default(),
        reply_topic: None,
        job_nonce: String::new(),
        user_id: Uuid::new_v4(),
    };

    req.sign(&key).expect("sign pipeline job request");
    assert!(!req.signature.is_empty());
    assert!(!req.job_nonce.is_empty());

    // Fresh signature should verify.
    req.verify(&key, 300).expect("verify pipeline job request");
}

#[test]
fn pipeline_job_request_tampered_step_fails() {
    let key = test_key();
    let mut req = PipelineJobRequest {
        crypto_scheme: 0,
        job_id: Uuid::new_v4(),
        workflow_execution_id: Uuid::new_v4(),
        steps: vec![make_pipeline_step()],
        total_timeout_ms: 30_000,
        share_sandbox: false,
        signature: vec![],
        max_llm_tier: LlmTier::default(),
        reply_topic: None,
        job_nonce: String::new(),
        user_id: Uuid::new_v4(),
    };
    req.sign(&key).unwrap();

    // Tamper: replace the WASM bytes of the first step.
    req.steps[0].wasm_bytes = Some(vec![0xFF, 0xFF, 0xFF, 0xFF]);

    assert!(
        req.verify(&key, 300).is_err(),
        "Tampered WASM bytes must invalidate the signature"
    );
}

#[test]
fn pipeline_job_result_roundtrip() {
    let step_id = Uuid::new_v4();
    let res = PipelineJobResult {
        crypto_scheme: 0,
        job_id: Uuid::new_v4(),
        overall_status: JobStatus::Success,
        step_results: vec![PipelineStepResult {
            module_id: step_id,
            status: JobStatus::Success,
            output: json!({"value": 42}),
            execution_time_ms: 50,
            error: None,
        }],
        final_output: json!({"value": 42}),
        total_time_ms: 100,
        signature: vec![],
        result_nonce: String::new(),
        worker_id: String::new(),
    };

    let ser = serde_json::to_string(&res).expect("serialize PipelineJobResult");
    let de: PipelineJobResult = serde_json::from_str(&ser).expect("deserialize PipelineJobResult");

    assert_eq!(res.job_id, de.job_id);
    assert_eq!(de.overall_status, JobStatus::Success);
    assert_eq!(de.step_results.len(), 1);
    assert_eq!(de.step_results[0].module_id, step_id);
}

#[test]
fn pipeline_job_result_sign_and_verify() {
    let key = test_key();
    let mut res = PipelineJobResult {
        crypto_scheme: 0,
        job_id: Uuid::new_v4(),
        overall_status: JobStatus::Success,
        step_results: vec![],
        final_output: json!({"answer": 84}),
        total_time_ms: 150,
        signature: vec![],
        result_nonce: String::new(),
        worker_id: String::new(),
    };

    res.sign(&key).expect("sign pipeline job result");
    assert!(!res.signature.is_empty());
    assert!(!res.result_nonce.is_empty());

    res.verify(&key, 300).expect("verify pipeline job result");
}

#[test]
fn pipeline_job_result_tampered_output_fails() {
    let key = test_key();
    let mut res = PipelineJobResult {
        crypto_scheme: 0,
        job_id: Uuid::new_v4(),
        overall_status: JobStatus::Success,
        step_results: vec![],
        final_output: json!({"answer": 84}),
        total_time_ms: 150,
        signature: vec![],
        result_nonce: String::new(),
        worker_id: String::new(),
    };
    res.sign(&key).unwrap();

    // Tamper: replace the final output.
    res.final_output = json!({"answer": 999});

    assert!(
        res.verify(&key, 300).is_err(),
        "Tampered final_output must invalidate the signature"
    );
}
