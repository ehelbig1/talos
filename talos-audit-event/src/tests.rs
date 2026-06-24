use super::*;

// Sign an event with an explicit key (tests don't rely on the process-global
// signing key, which is unset in the test environment).
fn hmac_sign(event: &AuditEvent, key: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(event.calculate_hash().as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[test]
fn calculate_hash_is_deterministic_and_sha256() {
    let event = AuditEvent {
        workflow_id: "wf-123".to_string(),
        execution_id: "exec-456".to_string(),
        sequence_num: 1,
        timestamp: 1234567890,
        actor: "agent:test".to_string(),
        action: "test:action".to_string(),
        payload: r#"{"key":"value"}"#.to_string(),
        previous_hash: "genesis".to_string(),
        hmac_signature: None,
    };
    let h1 = event.calculate_hash();
    let h2 = event.calculate_hash();
    assert_eq!(h1, h2);
    assert_eq!(h1.len(), 64);
}

#[test]
fn hash_changes_with_field() {
    let base = AuditEvent {
        workflow_id: "wf-123".to_string(),
        execution_id: "exec-456".to_string(),
        sequence_num: 1,
        timestamp: 1234567890,
        actor: "agent:test".to_string(),
        action: "test:action".to_string(),
        payload: r#"{"key":"value"}"#.to_string(),
        previous_hash: "genesis".to_string(),
        hmac_signature: None,
    };
    let mut other = base.clone();
    other.sequence_num = 2;
    assert_ne!(base.calculate_hash(), other.calculate_hash());
}

#[test]
fn length_prefix_resists_delimiter_injection() {
    let mut a = AuditEvent {
        workflow_id: "wf-123".to_string(),
        execution_id: "exec-456".to_string(),
        sequence_num: 1,
        timestamp: 1234567890,
        actor: "agent:test".to_string(),
        action: "test:action".to_string(),
        payload: "a:b".to_string(),
        previous_hash: "genesis".to_string(),
        hmac_signature: None,
    };
    let h1 = a.calculate_hash();
    a.payload = "ab".to_string();
    assert_ne!(h1, a.calculate_hash());
}

#[test]
fn ledger_genesis_and_append_chain() {
    let mut ledger = ExecutionLedger::new("wf-123", "exec-456");
    assert_eq!(ledger.current_sequence, 0);
    assert_eq!(ledger.last_hash.len(), 64);
    let genesis = ledger.last_hash.clone();

    let e1 = ledger.append("agent:test", "action:1", "payload1");
    assert_eq!(e1.sequence_num, 1);
    assert_eq!(e1.previous_hash, genesis);
    assert_eq!(ledger.last_hash, e1.calculate_hash());

    let e2 = ledger.append("agent:test", "action:2", "payload2");
    assert_eq!(e2.sequence_num, 2);
    assert_eq!(e2.previous_hash, e1.calculate_hash());
}

#[test]
fn distinct_executions_have_distinct_genesis() {
    let a = ExecutionLedger::new("wf-123", "exec-456");
    let b = ExecutionLedger::new("wf-123", "exec-789");
    let c = ExecutionLedger::new("wf-abc", "exec-456");
    assert_ne!(a.last_hash, b.last_hash);
    assert_ne!(a.last_hash, c.last_hash);
    assert_ne!(b.last_hash, c.last_hash);
}

#[test]
fn genesis_resists_pipe_and_empty_id_collisions() {
    assert_ne!(
        ExecutionLedger::new("wf|x", "ec1").last_hash,
        ExecutionLedger::new("wf", "x|ec1").last_hash
    );
    assert_ne!(
        ExecutionLedger::new("", "ec1").last_hash,
        ExecutionLedger::new("ec1", "").last_hash
    );
}

#[test]
fn verify_signature_round_trip() {
    let key = b"0123456789abcdef0123456789abcdef".to_vec();
    let mut event = AuditEvent {
        workflow_id: "wf".to_string(),
        execution_id: "ex".to_string(),
        sequence_num: 1,
        timestamp: 1,
        actor: "a".to_string(),
        action: "act".to_string(),
        payload: "p".to_string(),
        previous_hash: "g".to_string(),
        hmac_signature: None,
    };
    event.hmac_signature = Some(hmac_sign(&event, &key));
    assert_eq!(event.verify_signature(&[key.clone()]), Some(true));
    // Wrong key -> invalid.
    assert_eq!(
        event.verify_signature(&[b"wrong-key".to_vec()]),
        Some(false)
    );
    // Tampered payload -> invalid (hash changes under the same signature).
    let mut tampered = event.clone();
    tampered.payload = "p2".to_string();
    assert_eq!(tampered.verify_signature(&[key]), Some(false));
    // Unsigned -> None.
    let mut unsigned = event.clone();
    unsigned.hmac_signature = None;
    assert_eq!(unsigned.verify_signature(&[b"k".to_vec()]), None);
}

// ── verify_chain ────────────────────────────────────────────────────────────

fn build_chain(workflow: &str, exec: &str, n: u64) -> Vec<AuditEvent> {
    let mut ledger = ExecutionLedger::new(workflow, exec);
    (1..=n)
        .map(|i| ledger.append("worker", "act", &format!("payload-{i}")))
        .collect()
}

#[test]
fn verify_chain_accepts_valid_unsigned_chain() {
    let events = build_chain("wf", "ex", 5);
    let report = verify_chain("wf", "ex", &events, &[]);
    assert!(report.ok, "breaks: {:?}", report.breaks);
    assert_eq!(report.total_events, 5);
    assert!(!report.signatures_checked);
}

#[test]
fn verify_chain_is_order_independent() {
    let mut events = build_chain("wf", "ex", 4);
    events.reverse(); // arrives out of order
    assert!(verify_chain("wf", "ex", &events, &[]).ok);
}

#[test]
fn verify_chain_detects_sequence_gap() {
    let mut events = build_chain("wf", "ex", 4);
    events.remove(1); // drop seq 2 -> gap
    let report = verify_chain("wf", "ex", &events, &[]);
    assert!(!report.ok);
    assert!(report.breaks.iter().any(|b| matches!(
        b,
        ChainBreak::SequenceGap {
            expected: 2,
            found: 3
        }
    )));
}

#[test]
fn verify_chain_detects_tampered_payload_via_linkage() {
    let mut events = build_chain("wf", "ex", 4);
    // Tamper a middle event's payload: its recomputed hash changes, so the
    // NEXT event's previous_hash no longer links.
    events[1].payload = "tampered".to_string();
    let report = verify_chain("wf", "ex", &events, &[]);
    assert!(!report.ok);
    assert!(report
        .breaks
        .iter()
        .any(|b| matches!(b, ChainBreak::LinkageMismatch { seq: 3, .. })));
}

#[test]
fn verify_chain_detects_genesis_mismatch() {
    let mut events = build_chain("wf", "ex", 3);
    events[0].previous_hash = "not-the-genesis".to_string();
    let report = verify_chain("wf", "ex", &events, &[]);
    assert!(report
        .breaks
        .iter()
        .any(|b| matches!(b, ChainBreak::GenesisMismatch { seq: 1, .. })));
}

#[test]
fn verify_chain_detects_duplicate_sequence() {
    let mut events = build_chain("wf", "ex", 3);
    let dup = events[1].clone();
    events.push(dup);
    let report = verify_chain("wf", "ex", &events, &[]);
    assert!(report
        .breaks
        .iter()
        .any(|b| matches!(b, ChainBreak::DuplicateSequence { seq: 2 })));
}

#[test]
fn verify_chain_checks_signatures_when_keys_present() {
    let key = b"0123456789abcdef0123456789abcdef".to_vec();
    let mut events = build_chain("wf", "ex", 3);
    for e in &mut events {
        e.hmac_signature = Some(hmac_sign(e, &key));
    }
    // All valid + signed.
    let report = verify_chain("wf", "ex", &events, &[key.clone()]);
    assert!(report.ok, "breaks: {:?}", report.breaks);
    assert!(report.signatures_checked);

    // Forge one signature -> BadSignature.
    events[1].hmac_signature = Some("deadbeef".to_string());
    let report = verify_chain("wf", "ex", &events, &[key.clone()]);
    assert!(report
        .breaks
        .iter()
        .any(|b| matches!(b, ChainBreak::BadSignature { seq: 2 })));

    // Strip one signature -> Unsigned (only flagged because keys configured).
    events[1].hmac_signature = None;
    let report = verify_chain("wf", "ex", &events, &[key]);
    assert!(report
        .breaks
        .iter()
        .any(|b| matches!(b, ChainBreak::Unsigned { seq: 2 })));
}

// ── audit_signing_key entropy floor (MCP-579 floor raise, 2026-06-23) ──
//
// These exercise the real production decision helpers
// (`effective_key_entropy_bytes` + `MIN_KEY_ENTROPY_BYTES`) used by
// `audit_signing_key()` — NOT a test-local shadow. The loader itself can't
// be unit-tested in isolation (process-global `OnceLock` + env var +
// `is_production()`), so the floor logic is extracted and tested directly.
// `accepts(k)` mirrors the loader's accept/reject predicate exactly.
fn accepts(k: &str) -> bool {
    !k.is_empty() && effective_key_entropy_bytes(k) >= MIN_KEY_ENTROPY_BYTES
}

#[test]
fn entropy_floor_rejects_32_hex_char_key() {
    // 32 hex chars = `openssl rand -hex 16` = only 16 bytes of real entropy.
    // This is the exact trap the old `len() < 32` raw-string check missed.
    let k = "0123456789abcdef0123456789abcdef"; // 32 chars, all hex
    assert_eq!(k.len(), 32);
    assert_eq!(effective_key_entropy_bytes(k), 16);
    assert!(!accepts(k), "16-byte-entropy hex key must be REJECTED");
}

#[test]
fn entropy_floor_accepts_64_hex_char_key() {
    // 64 hex chars = `openssl rand -hex 32` = 32 bytes of entropy — the
    // canonical full-strength operator key.
    let k = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    assert_eq!(k.len(), 64);
    assert_eq!(effective_key_entropy_bytes(k), 32);
    assert!(accepts(k), "64-hex-char key must be ACCEPTED");
}

#[test]
fn entropy_floor_accepts_32_byte_non_hex_key() {
    // A 32-char NON-hex string (e.g. base64-ish / passphrase) has 32 bytes
    // of raw entropy and must NOT be hex-folded down to 16 — the `g`/`-`
    // make it non-hex so entropy = full byte length.
    let k = "this-is-a-32-byte-raw-secret!!gg"; // 32 chars, contains non-hex
    assert_eq!(k.len(), 32);
    assert!(!k.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(effective_key_entropy_bytes(k), 32);
    assert!(accepts(k), "32-byte raw non-hex key must be ACCEPTED");
}

#[test]
fn entropy_floor_rejects_short_raw_key() {
    // A short non-hex key (16 chars raw) is below the 32-byte floor.
    let k = "short-raw-key-xy"; // 16 chars, non-hex ('s','r','k','y','-')
    assert_eq!(k.len(), 16);
    assert!(!k.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(effective_key_entropy_bytes(k), 16);
    assert!(!accepts(k), "16-byte raw key must be REJECTED");

    // Boundary: 31 raw bytes rejected, 32 raw bytes accepted.
    let raw31: String = "z".repeat(31); // 'z' is non-hex
    let raw32: String = "z".repeat(32);
    assert!(!accepts(&raw31), "31-byte raw key must be REJECTED");
    assert!(accepts(&raw32), "32-byte raw key must be ACCEPTED");
}

#[test]
fn entropy_floor_hex_boundary_is_64_chars() {
    // 62 hex chars = 31 decoded bytes -> rejected; 64 -> 32 bytes -> accepted.
    let hex62: String = "a".repeat(62);
    let hex64: String = "a".repeat(64);
    assert_eq!(effective_key_entropy_bytes(&hex62), 31);
    assert_eq!(effective_key_entropy_bytes(&hex64), 32);
    assert!(
        !accepts(&hex62),
        "62-hex-char key (31 bytes) must be REJECTED"
    );
    assert!(
        accepts(&hex64),
        "64-hex-char key (32 bytes) must be ACCEPTED"
    );

    // Odd-length all-hex-digit string is NOT treated as hex (can't decode to
    // whole bytes) -> falls through to raw-length entropy. 33 'a' chars is
    // odd, so entropy = 33 raw bytes (accepted, but via the raw path).
    let odd: String = "a".repeat(33);
    assert_eq!(effective_key_entropy_bytes(&odd), 33);
}
