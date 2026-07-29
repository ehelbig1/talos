//! Wire-format snapshot tests for the signed memory / integration-state RPCs.
//!
//! Locks in the **exact byte-level** shape of the over-the-wire JSON and the
//! HMAC-SHA256 signing payloads, mirroring
//! `talos-workflow-job-protocol/tests/wire_format_snapshots.rs` for the other
//! signed-wire surface.
//!
//! ## Why this file exists
//!
//! Until now the memory RPCs' only signing coverage was BEHAVIOURAL: sign →
//! wire hop → verify, all inside one process running one build. That shape
//! cannot catch a CONSISTENT both-sides change. Reorder the `MemoryOp::Set`
//! fields, rename a JSON key, swap the envelope prefix order in
//! `sign_body_bytes`, or move a field in or out of the signed body, and every
//! behavioural test still passes — while a deployed worker signing the old
//! layout and a controller verifying the new one reject every honest request.
//! That is a fleet-wide outage with a green test suite, and it is exactly the
//! failure mode #598 shipped through once already.
//!
//! Literal expected JSON + a literal expected MAC hex freeze the wire
//! independently of the implementation, so a both-sides drift fails loudly
//! here instead of quietly in production.
//!
//! ## How to read a failure
//!
//! 1. Verify the change is intended (a release-note-worthy wire change, not
//!    an accidental field reorder or a "harmless" struct tidy-up).
//! 2. Update the literal in this file to match the new output.
//! 3. Co-ordinate the controller + worker upgrade — a mixed fleet fails EVERY
//!    memory / integration-state RPC closed until both halves run the new
//!    code. `make up` rolls both together.
//!
//! ## What's covered
//!
//! * `MemoryRpcRequest` carrying `MemoryOp::Set` — JSON shape + signature.
//! * `IntegrationStateRequest` carrying `IntegrationOp::Set` — JSON shape +
//!   signature.
//!
//! Both fixtures carry the 2-cycle poison float
//! (`talos_workflow_job_protocol::test_support::POISON_2CYCLE`), so the
//! snapshots ALSO pin that the raw text minted on the send side is the exact
//! text a signature is taken over: normalise or re-derive it anywhere and
//! both the JSON literal and the hex change.
//!
//! ## What's NOT covered (deliberately)
//!
//! The scalar-only RPC families (`graph_rpc`, `database_rpc`, `state_rpc`,
//! `ml_rpc`) bind strings and ints through a fixed-tag concatenation and
//! carry no `serde_json::Value`; their wire shape is pinned by the
//! behavioural specs in `src/lib.rs`. The two `Set` paths are the ones whose
//! signature covers raw JSON text, which is what needs freezing.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::Arc;
use talos_memory::integration_state_rpc::{
    IndexedSlots, IntegrationOp, IntegrationStateRequest, SUBJECT_NAME as INTEGRATION_SUBJECT,
};
use talos_memory::memory_rpc::{MemoryOp, MemoryRpcRequest, SUBJECT_NAME as MEMORY_SUBJECT};
use talos_memory::rpc_auth::{self, RawSigned};
use talos_workflow_job_protocol::test_support::POISON_2CYCLE;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// 32-byte test key — matches the all-`0x42` pattern the job-protocol
/// snapshots use so a debug failure is grep-able to one place. NOT a real
/// key; production keys come from `WORKER_SHARED_KEY`.
const TEST_KEY: [u8; 32] = [0x42; 32];

/// Fixed nonce: 32 lowercase hex chars, the canonical shape
/// `rpc_auth::random_nonce` emits and `is_canonical_nonce` accepts.
const TEST_NONCE: &str = "0123456789abcdef0123456789abcdef";

/// Fixed signing timestamp (2025-06-15T14:26:40Z in epoch ms). Any constant
/// works; it is pinned so the LE prefix of the signed body is deterministic.
/// Deliberately NOT `now_ms()` — see `verify()`'s freshness gate, which the
/// companion "formula matches production" tests exercise separately.
const TEST_TIMESTAMP_MS: i64 = 1_750_000_000_000;

/// Deterministic UUID helper. `Uuid::from_u128(N)` is reproducible across
/// runs and platforms.
fn det_uuid(n: u128) -> Uuid {
    Uuid::from_u128(n)
}

/// Register the process-global HMAC key. `register_hmac_key` wraps a
/// `OnceLock::set`, so this is idempotent and first-caller-wins; this test
/// binary is its own process, so `TEST_KEY` is always the winner here.
fn ensure_test_key() {
    rpc_auth::register_hmac_key(Arc::new(TEST_KEY.to_vec()));
}

/// The RPC signing envelope, mirrored from the private
/// `rpc_auth::signing_payload`: `subject || 0 || actor_id(16) || 0 || nonce
/// || 0 || body`.
///
/// Mirrored rather than called so the snapshot pins the ENVELOPE too, not
/// just the per-RPC body. `subject` binds a signature to one RPC kind,
/// `actor_id` blocks cross-actor replay, `nonce` blocks same-actor replay —
/// dropping any of them from this concatenation is a silent authorisation
/// downgrade that no behavioural test would notice.
fn hmac_over(subject: &str, actor_id: Uuid, nonce: &str, body: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(subject.as_bytes());
    payload.push(0);
    payload.extend_from_slice(actor_id.as_bytes());
    payload.push(0);
    payload.extend_from_slice(nonce.as_bytes());
    payload.push(0);
    payload.extend_from_slice(body);

    let mut mac = <HmacSha256 as Mac>::new_from_slice(&TEST_KEY).expect("32-byte key");
    mac.update(&payload);
    mac.finalize().into_bytes().to_vec()
}

/// Mirror of the private `memory_rpc::sign_body_bytes`:
/// `timestamp_ms (i64 LE) || op.raw_bytes()`.
fn memory_body(op: &RawSigned<MemoryOp>, timestamp_ms: i64) -> Vec<u8> {
    let mut buf = timestamp_ms.to_le_bytes().to_vec();
    buf.extend_from_slice(op.raw_bytes());
    buf
}

/// Mirror of the private `integration_state_rpc::sign_body_bytes`:
/// `name_len (u32 LE) || name || user_id (16) || timestamp_ms (i64 LE) ||
/// op.raw_bytes()`.
fn integration_body(
    integration_name: &str,
    user_id: Uuid,
    op: &RawSigned<IntegrationOp>,
    timestamp_ms: i64,
) -> Vec<u8> {
    let mut buf = (integration_name.len() as u32).to_le_bytes().to_vec();
    buf.extend_from_slice(integration_name.as_bytes());
    buf.extend_from_slice(user_id.as_bytes());
    buf.extend_from_slice(&timestamp_ms.to_le_bytes());
    buf.extend_from_slice(op.raw_bytes());
    buf
}

/// The fixture op: a `Set` carrying the 2-cycle poison float, so the
/// snapshot pins the exact float SPELLING that gets signed.
fn fixture_memory_op() -> MemoryOp {
    MemoryOp::Set {
        key: "digest/ratios".to_string(),
        value: serde_json::json!({"ratio": POISON_2CYCLE}),
        memory_type: "episodic".to_string(),
        ttl_hours: Some(24.0),
        metadata: Some(serde_json::json!({"kind": "daily_brief"})),
    }
}

fn fixture_integration_op() -> IntegrationOp {
    IntegrationOp::Set {
        key: "watch_channel/abc".to_string(),
        value: serde_json::json!({"drift_ratio": POISON_2CYCLE}),
        ttl_seconds: Some(3600),
        slots: IndexedSlots::default(),
    }
}

/// Build the deterministic memory request at a caller-chosen timestamp.
/// Bypasses `new_signed` (which draws `now_ms()` + a random nonce) but signs
/// with the same formula — the companion test proves the two agree.
fn deterministic_memory_request(timestamp_ms: i64) -> MemoryRpcRequest {
    let actor_id = det_uuid(0x0000_0000_0000_0000_0000_0000_0000_0001);
    let op = RawSigned::from(fixture_memory_op());
    let signature = hmac_over(
        MEMORY_SUBJECT,
        actor_id,
        TEST_NONCE,
        &memory_body(&op, timestamp_ms),
    );
    MemoryRpcRequest {
        actor_id,
        op,
        timestamp_ms,
        nonce: TEST_NONCE.to_string(),
        signature,
        worker_id: String::new(),
        crypto_scheme: 0,
    }
}

fn deterministic_integration_request(timestamp_ms: i64) -> IntegrationStateRequest {
    let actor_id = det_uuid(0x0000_0000_0000_0000_0000_0000_0000_0002);
    let user_id = det_uuid(0x0000_0000_0000_0000_0000_0000_0000_0003);
    let integration_name = "gmail".to_string();
    let op = RawSigned::from(fixture_integration_op());
    let signature = hmac_over(
        INTEGRATION_SUBJECT,
        actor_id,
        TEST_NONCE,
        &integration_body(&integration_name, user_id, &op, timestamp_ms),
    );
    IntegrationStateRequest {
        integration_name,
        actor_id,
        user_id,
        op,
        timestamp_ms,
        nonce: TEST_NONCE.to_string(),
        signature,
        worker_id: String::new(),
        crypto_scheme: 0,
    }
}

#[test]
fn memory_set_request_json_snapshot() {
    ensure_test_key();
    let req = deterministic_memory_request(TEST_TIMESTAMP_MS);
    let actual = serde_json::to_string(&req).expect("serialize");

    // Captured 2026-07-29 against this crate's protocol shape. Update
    // verbatim when the wire format INTENTIONALLY changes — see the module
    // docstring for the deploy-ordering consequence.
    //
    // Note the float spelling `5.455171886890906e-115`: that is the exact
    // text minted once by `RawSigned::from` and covered by the signature.
    // Any scheme that re-derives it can land on `…8909045e-115` instead.
    let expected = r#"{"actor_id":"00000000-0000-0000-0000-000000000001","op":{"op":"set","key":"digest/ratios","value":{"ratio":5.455171886890906e-115},"memory_type":"episodic","ttl_hours":24.0,"metadata":{"kind":"daily_brief"}},"timestamp_ms":1750000000000,"nonce":"0123456789abcdef0123456789abcdef","signature":[54,239,193,161,153,111,129,75,94,152,25,113,82,223,176,92,22,168,213,162,1,133,185,130,54,46,221,52,59,53,154,207],"worker_id":"","crypto_scheme":0}"#;
    assert_eq!(
        actual, expected,
        "MemoryRpcRequest wire format drifted — see module docstring for resolution"
    );
}

#[test]
fn memory_set_request_signature_snapshot() {
    ensure_test_key();
    let req = deterministic_memory_request(TEST_TIMESTAMP_MS);

    // Locks in the full signing formula: the envelope
    // (subject/actor/nonce framing) AND the body
    // (`timestamp_ms` LE || op raw text). Any reorder, rename, or
    // added/removed bound field changes this digest.
    let actual_hex = hex::encode(&req.signature);
    let expected_hex = "36efc1a1996f814b5e98197152dfb05c16a8d5a20185b982362edd343b359acf";
    assert_eq!(
        actual_hex, expected_hex,
        "memory_rpc signing payload drifted — see module docstring for resolution"
    );
}

#[test]
fn integration_set_request_json_snapshot() {
    ensure_test_key();
    let req = deterministic_integration_request(TEST_TIMESTAMP_MS);
    let actual = serde_json::to_string(&req).expect("serialize");

    let expected = r#"{"integration_name":"gmail","actor_id":"00000000-0000-0000-0000-000000000002","user_id":"00000000-0000-0000-0000-000000000003","op":{"op":"set","key":"watch_channel/abc","value":{"drift_ratio":5.455171886890906e-115},"ttl_seconds":3600},"timestamp_ms":1750000000000,"nonce":"0123456789abcdef0123456789abcdef","signature":[84,160,229,188,251,17,223,172,134,90,54,151,143,130,59,8,117,5,179,2,17,88,184,107,133,82,135,71,111,86,137,203],"worker_id":"","crypto_scheme":0}"#;
    assert_eq!(
        actual, expected,
        "IntegrationStateRequest wire format drifted — see module docstring for resolution"
    );
}

#[test]
fn integration_set_request_signature_snapshot() {
    ensure_test_key();
    let req = deterministic_integration_request(TEST_TIMESTAMP_MS);

    let actual_hex = hex::encode(&req.signature);
    let expected_hex = "54a0e5bcfb11dfac865a36978f823b087505b3021158b86b855287476f5689cb";
    assert_eq!(
        actual_hex, expected_hex,
        "integration_state_rpc signing payload drifted — see module docstring for resolution"
    );
}

/// The snapshots above hand-roll the signing formula; this proves the
/// hand-rolled version is the PRODUCTION one.
///
/// Without it the snapshots would be self-referential — a drift in
/// `sign_body_bytes` or `signing_payload` could be masked by "updating the
/// expected hex", and the frozen bytes would describe a formula nothing
/// actually uses. The request is stamped with a live timestamp because
/// `verify()`'s first gate is freshness (60 s past / 5 s future).
#[test]
fn memory_snapshot_formula_is_the_production_formula() {
    ensure_test_key();
    let req = deterministic_memory_request(rpc_auth::now_ms());
    req.verify()
        .expect("hand-rolled signature must satisfy production verify()");

    // And it survives the real wire hop unchanged.
    let bytes = serde_json::to_vec(&req).expect("serialize");
    let received: MemoryRpcRequest = serde_json::from_slice(&bytes).expect("deserialize");
    assert_eq!(received.op.raw_bytes(), req.op.raw_bytes());
    received
        .verify()
        .expect("hand-rolled signature must verify after the wire hop");
}

/// Integration-state twin of the above — the two surfaces have independent
/// signing formulas, so one proof does not carry to the other.
#[test]
fn integration_snapshot_formula_is_the_production_formula() {
    ensure_test_key();
    let req = deterministic_integration_request(rpc_auth::now_ms());
    req.verify()
        .expect("hand-rolled signature must satisfy production verify()");

    let bytes = serde_json::to_vec(&req).expect("serialize");
    let received: IntegrationStateRequest = serde_json::from_slice(&bytes).expect("deserialize");
    assert_eq!(received.op.raw_bytes(), req.op.raw_bytes());
    received
        .verify()
        .expect("hand-rolled signature must verify after the wire hop");
}

/// The snapshot fixtures must be reachable through the PRODUCTION
/// constructor too — otherwise a future sign-time gate could start rejecting
/// the shape these snapshots freeze, and the snapshots would be pinning a
/// message the system can no longer emit.
#[test]
fn snapshot_fixtures_pass_the_production_sign_time_gates() {
    ensure_test_key();
    assert!(
        MemoryRpcRequest::new_signed(det_uuid(1), fixture_memory_op()).is_some(),
        "the memory fixture must still be signable by new_signed"
    );
    assert!(
        IntegrationStateRequest::new_signed(
            "gmail".to_string(),
            det_uuid(2),
            det_uuid(3),
            fixture_integration_op(),
        )
        .is_some(),
        "the integration fixture must still be signable by new_signed"
    );
}
