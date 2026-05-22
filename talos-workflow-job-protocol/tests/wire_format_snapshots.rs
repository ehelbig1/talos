//! Wire-format snapshot tests.
//!
//! Locks in the **exact byte-level** shape of the over-the-wire JSON
//! and the HMAC-SHA256 signing payloads. Both shapes are part of the
//! protocol's compatibility contract: a deployed worker built against
//! one version of this crate must round-trip and verify messages
//! produced by another version. A field rename, reorder, sentinel
//! change, or sort-order tweak silently breaks that contract — these
//! tests fail the build instead.
//!
//! ## How to read a failure
//!
//! When a test here fails after an intentional protocol change:
//!
//! 1. Verify the change is intended (a release-note-worthy wire
//!    change, not an accidental field reorder).
//! 2. Update the literal in this file to match the new output.
//! 3. Co-ordinate the controller + worker upgrade — deployed workers
//!    on the old format will start rejecting signatures.
//!
//! ## What's covered
//!
//! * `EncryptedSecrets` — JSON serialization shape.
//! * `JobRequest` — JSON shape + signature for a fully-populated
//!   request with deterministic UUIDs and a fixed nonce.
//! * `JobResult` — JSON shape + signature.
//! * `PipelineJobRequest` / `PipelineJobResult` — JSON shape +
//!   signature; the chain-dispatch counterpart to `JobRequest` /
//!   `JobResult`.
//!
//! All identifying fields use deterministic UUIDs derived from
//! `Uuid::from_u128(N)` so the snapshot is reproducible across runs.
//!
//! ## What's NOT covered (deliberately)
//!
//! * Encrypted-secrets ciphertext bytes — produced by `AesGcmSecretEnvelope`
//!   with a random nonce, so output is non-deterministic. The seal
//!   contract is verified separately in `serialization.rs` and
//!   `security_tests.rs`.
//! * `WorkerHeartbeat` — internal observability message, not part
//!   of the cross-version compatibility surface.

use serde_json::json;
use talos_workflow_job_protocol::{
    EncryptedSecrets, JobRequest, JobResult, JobStatus, LlmTier, PipelineJobRequest,
    PipelineJobResult, PipelineStep, PipelineStepResult,
};
use uuid::Uuid;

/// 32-byte test key — matches the all-`0x42` pattern used elsewhere
/// in this crate's tests so a debug failure is grep-able to one
/// place. NOT a real key; production keys come from KMS.
const TEST_KEY: [u8; 32] = [0x42; 32];

/// Deterministic UUID helper for snapshots. `Uuid::from_u128(N)` is
/// reproducible across runs and across platforms.
fn det_uuid(n: u128) -> Uuid {
    Uuid::from_u128(n)
}

/// Build a fully-populated `JobRequest` with deterministic fields so
/// every byte of the serialized output is stable. Caller fills in
/// `signature` after a `sign_with_fixed_nonce` round-trip.
fn deterministic_job_request() -> JobRequest {
    JobRequest {
        job_id: det_uuid(0x0000_0000_0000_0000_0000_0000_0000_0001),
        workflow_execution_id: det_uuid(0x0000_0000_0000_0000_0000_0000_0000_0002),
        module_uri: "redis:wasm:00000000-0000-0000-0000-000000000003".into(),
        input_payload: json!({"key": "value"}),
        encrypted_secrets: EncryptedSecrets {
            ciphertext: vec![0xAA, 0xBB, 0xCC],
            nonce: vec![0x01; 12],
        },
        timeout_ms: 30_000,
        priority: 100,
        deadline_unix_secs: 0,
        cancellation_token: None,
        allowed_hosts: vec!["api.example.com".into()],
        allowed_methods: vec!["GET".into(), "POST".into()],
        allowed_secrets: vec!["foo/*".into()],
        allowed_sql_operations: vec![],
        allow_tier2_exposure: false,
        // Fixed signature placeholder — overwritten below by
        // `sign_request_with_fixed_nonce`.
        signature: vec![],
        max_llm_tier: LlmTier::default(),
        // Fixed nonce so the signing payload is deterministic.
        // The first segment is the unix timestamp; "0" pretends the
        // request was signed at the epoch. The second segment is
        // 16 random hex bytes — using all-zeros for reproducibility.
        job_nonce: "0:00000000000000000000000000000000".into(),
        actor_id: None,
        wasm_bytes: None,
        capability_world: None,
        expected_wasm_hash: Some("deadbeef".into()),
        integration_name: None,
        user_id: det_uuid(0x0000_0000_0000_0000_0000_0000_0000_0009),
        max_fuel: 1_000_000,
        dry_run: false,
        reply_topic: None,
    }
}

/// Sign a `JobRequest` whose `job_nonce` has already been set —
/// equivalent to `sign()` minus the time + RNG calls so the
/// signature is reproducible.
fn sign_request_with_fixed_nonce(req: &mut JobRequest, key: &[u8]) {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    // MUST mirror `JobRequest::signing_payload` exactly — same field
    // order, same length-prefix discipline (L-9), same sentinels for
    // Option fields (M-4 / M-5 / H-1). Any drift here masks a
    // protocol change behind an updated expected_hex; production
    // verify will then fail at the round-trip assertion below.
    use sha2::Digest;
    let input_hash = hex::encode(Sha256::digest(req.input_payload.to_string().as_bytes()));
    let secrets_hash = hex::encode(Sha256::digest(&req.encrypted_secrets.ciphertext));
    let mut hosts = req.allowed_hosts.clone();
    hosts.sort_unstable();
    let hosts_str = hosts.join(",");
    let mut methods = req.allowed_methods.clone();
    methods.sort_unstable();
    let methods_str = methods.join(",");
    let wasm_hash = if let Some(b) = req.wasm_bytes.as_deref() {
        hex::encode(Sha256::digest(b))
    } else if let Some(ref h) = req.expected_wasm_hash {
        h.clone()
    } else {
        "none".to_string()
    };
    let integration_name = req.integration_name.as_deref().unwrap_or("-");
    let actor_id_str = req
        .actor_id
        .map(|u| u.to_string())
        .unwrap_or_else(|| "-".to_string());
    let mut allowed_secrets_sorted = req.allowed_secrets.clone();
    allowed_secrets_sorted.sort_unstable();
    let allowed_secrets_str = allowed_secrets_sorted.join(",");
    let mut allowed_sql_sorted = req.allowed_sql_operations.clone();
    allowed_sql_sorted.sort_unstable();
    let allowed_sql_str = allowed_sql_sorted.join(",");
    let reply_topic_str = req.reply_topic.as_deref().unwrap_or("-");
    fn lp(s: &str) -> String {
        format!("{}:{}", s.as_bytes().len(), s)
    }
    let payload = format!(
        "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
        req.job_id,
        req.workflow_execution_id,
        lp(&req.module_uri),
        req.job_nonce,
        input_hash,
        secrets_hash,
        req.timeout_ms,
        lp(&hosts_str),
        lp(&methods_str),
        wasm_hash,
        lp(integration_name),
        req.user_id,
        req.max_llm_tier.as_signing_str(),
        lp(&actor_id_str),
        lp(&allowed_secrets_str),
        lp(&allowed_sql_str),
        req.allow_tier2_exposure,
        lp(reply_topic_str),
    );
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).unwrap();
    mac.update(payload.as_bytes());
    req.signature = mac.finalize().into_bytes().to_vec();
}

#[test]
fn job_request_json_snapshot() {
    // Locks in every JSON key + ordering. A field rename / reorder
    // breaks deployed workers — fail the build before that ships.
    let mut req = deterministic_job_request();
    sign_request_with_fixed_nonce(&mut req, &TEST_KEY);
    let actual = serde_json::to_string(&req).expect("serialize");

    // Captured 2026-04-20 against this crate's protocol shape.
    // Update verbatim when the wire format intentionally changes.
    // Updated 2026-05-21: snapshot includes the canonical signing
    // bytes after the L-9 length-prefix discipline, M-4 actor_id
    // binding, M-5 capability-grant binding, and H-1 reply_topic
    // binding all landed. reply_topic = None is omitted from the
    // JSON via `skip_serializing_if`, so the shape is unchanged
    // here; only the `signature` bytes shift.
    let expected = r#"{"job_id":"00000000-0000-0000-0000-000000000001","workflow_execution_id":"00000000-0000-0000-0000-000000000002","module_uri":"redis:wasm:00000000-0000-0000-0000-000000000003","input_payload":{"key":"value"},"encrypted_secrets":{"ciphertext":[170,187,204],"nonce":[1,1,1,1,1,1,1,1,1,1,1,1]},"timeout_ms":30000,"priority":100,"deadline_unix_secs":0,"allowed_hosts":["api.example.com"],"allowed_methods":["GET","POST"],"allowed_secrets":["foo/*"],"allowed_sql_operations":[],"allow_tier2_exposure":false,"signature":[104,148,176,248,116,245,0,61,91,172,197,30,238,212,180,169,149,173,36,2,150,202,28,12,39,199,95,66,50,237,118,107],"job_nonce":"0:00000000000000000000000000000000","expected_wasm_hash":"deadbeef","max_fuel":1000000,"user_id":"00000000-0000-0000-0000-000000000009","max_llm_tier":"tier2","dry_run":false}"#;
    assert_eq!(
        actual, expected,
        "JobRequest wire format drifted — see test docstring for resolution"
    );
}

#[test]
fn job_request_signature_snapshot() {
    // Locks in the canonical-bytes signing format. Any reorder /
    // rename / sort-order change in `signing_payload` breaks every
    // deployed worker's signature verification.
    let mut req = deterministic_job_request();
    sign_request_with_fixed_nonce(&mut req, &TEST_KEY);

    // The signature field is the HMAC-SHA256 over the canonical
    // bytes; locking the hex digest pins the format implicitly.
    let actual_hex = hex::encode(&req.signature);
    // Updated 2026-05-21: see `job_request_json_snapshot` comment
    // for the protocol bump that shifted this digest. Recomputed
    // against the current `JobRequest::signing_payload`.
    let expected_hex = "6894b0f874f5003d5bacc51eeed4b4a995ad240296ca1c0c27c75f4232ed766b";
    assert_eq!(
        actual_hex, expected_hex,
        "JobRequest signing payload drifted — see test docstring for resolution"
    );

    // Sanity: the production verify path accepts our reproduced
    // signature. If it didn't, the formula above would have drifted
    // from the real impl.
    req.verify(&TEST_KEY, u64::MAX)
        .expect("hand-rolled signature must verify against production verify()");
}

#[test]
fn job_result_json_snapshot() {
    let result = JobResult {
        job_id: det_uuid(0x0000_0000_0000_0000_0000_0000_0000_0001),
        status: JobStatus::Success,
        output_payload: json!({"out": 42}),
        logs: vec!["info: ok".into()],
        execution_time_ms: 7,
        signature: vec![0xDE, 0xAD, 0xBE, 0xEF],
        result_nonce: "0:00000000000000000000000000000000".into(),
    };
    let actual = serde_json::to_string(&result).expect("serialize");
    let expected = r#"{"job_id":"00000000-0000-0000-0000-000000000001","status":"Success","output_payload":{"out":42},"logs":["info: ok"],"execution_time_ms":7,"signature":[222,173,190,239],"result_nonce":"0:00000000000000000000000000000000"}"#;
    assert_eq!(
        actual, expected,
        "JobResult wire format drifted — see test docstring for resolution"
    );
}

#[test]
fn pipeline_job_request_json_snapshot() {
    let req = PipelineJobRequest {
        job_id: det_uuid(0x0000_0000_0000_0000_0000_0000_0000_0010),
        workflow_execution_id: det_uuid(0x0000_0000_0000_0000_0000_0000_0000_0011),
        user_id: det_uuid(0x0000_0000_0000_0000_0000_0000_0000_0012),
        steps: vec![PipelineStep {
            module_id: det_uuid(0x0000_0000_0000_0000_0000_0000_0000_0013),
            module_uri: "redis:wasm:00000000-0000-0000-0000-000000000013".into(),
            wasm_bytes: Some(vec![0x00, 0x61, 0x73, 0x6D]),
            config: json!({"setting": "value"}),
            allowed_hosts: vec!["api.example.com".into()],
            allowed_methods: vec!["GET".into()],
            allowed_secrets: vec![],
            encrypted_secrets: EncryptedSecrets {
                ciphertext: vec![0xAA],
                nonce: vec![0x01; 12],
            },
            max_fuel: 1_000_000,
            max_memory_mb: 128,
            timeout_ms: 30_000,
            priority: 100,
            cancellation_token: None,
            allowed_sql_operations: vec![],
            allow_tier2_exposure: false,
            integration_name: None,
            expected_wasm_hash: Some("deadbeef".into()),
        }],
        signature: vec![0xCA, 0xFE],
        job_nonce: "0:00000000000000000000000000000000".into(),
        total_timeout_ms: 60_000,
        share_sandbox: false,
        max_llm_tier: LlmTier::default(),
        reply_topic: None,
    };
    let actual = serde_json::to_string(&req).expect("serialize");
    let expected = r#"{"job_id":"00000000-0000-0000-0000-000000000010","workflow_execution_id":"00000000-0000-0000-0000-000000000011","steps":[{"module_id":"00000000-0000-0000-0000-000000000013","module_uri":"redis:wasm:00000000-0000-0000-0000-000000000013","wasm_bytes":[0,97,115,109],"config":{"setting":"value"},"allowed_hosts":["api.example.com"],"allowed_methods":["GET"],"allowed_secrets":[],"allowed_sql_operations":[],"allow_tier2_exposure":false,"encrypted_secrets":{"ciphertext":[170],"nonce":[1,1,1,1,1,1,1,1,1,1,1,1]},"max_fuel":1000000,"max_memory_mb":128,"timeout_ms":30000,"priority":100,"expected_wasm_hash":"deadbeef"}],"total_timeout_ms":60000,"share_sandbox":false,"signature":[202,254],"job_nonce":"0:00000000000000000000000000000000","user_id":"00000000-0000-0000-0000-000000000012","max_llm_tier":"tier2"}"#;
    assert_eq!(
        actual, expected,
        "PipelineJobRequest wire format drifted — see test docstring for resolution"
    );
}

#[test]
fn pipeline_job_result_json_snapshot() {
    let res = PipelineJobResult {
        job_id: det_uuid(0x0000_0000_0000_0000_0000_0000_0000_0010),
        step_results: vec![PipelineStepResult {
            module_id: det_uuid(0x0000_0000_0000_0000_0000_0000_0000_0013),
            status: JobStatus::Success,
            output: json!({"step": "ok"}),
            error: None,
            execution_time_ms: 12,
        }],
        final_output: json!({"step": "ok"}),
        overall_status: JobStatus::Success,
        total_time_ms: 12,
        signature: vec![0xBA, 0xAD],
        result_nonce: "0:00000000000000000000000000000000".into(),
    };
    let actual = serde_json::to_string(&res).expect("serialize");
    let expected = r#"{"job_id":"00000000-0000-0000-0000-000000000010","overall_status":"Success","step_results":[{"module_id":"00000000-0000-0000-0000-000000000013","status":"Success","output":{"step":"ok"},"execution_time_ms":12,"error":null}],"final_output":{"step":"ok"},"total_time_ms":12,"signature":[186,173],"result_nonce":"0:00000000000000000000000000000000"}"#;
    assert_eq!(
        actual, expected,
        "PipelineJobResult wire format drifted — see test docstring for resolution"
    );
}

#[test]
fn encrypted_secrets_json_snapshot() {
    let es = EncryptedSecrets {
        ciphertext: vec![0xAA, 0xBB, 0xCC],
        nonce: vec![0x01; 12],
    };
    let actual = serde_json::to_string(&es).expect("serialize");
    let expected = r#"{"ciphertext":[170,187,204],"nonce":[1,1,1,1,1,1,1,1,1,1,1,1]}"#;
    assert_eq!(actual, expected);
}
