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
        dispatch_attempt: 0,
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
        dispatch_attempt: 0,
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
        dispatch_attempt: 0,
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
        dispatch_attempt: 0,
    };
    event.hmac_signature = Some(hmac_sign(&event, &key));
    assert_eq!(
        event.verify_signature(std::slice::from_ref(&key)),
        Some(true)
    );
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

/// An EXACT redelivery of one event is a transport/producer artefact, not
/// tamper evidence: nothing has been altered, added or removed from the
/// chain — one event arrived twice. It is REPORTED (so an operator can see
/// the ledger is carrying redundant copies) and it does NOT flip `ok`.
///
/// Measured on the live dev stack 2026-09-07: the first audit-chain sweep
/// that ever completed reported `jobs_failed=1` on exactly this shape — one
/// object whose two lines were byte-identical (same `sequence_num`, same
/// `previous_hash`, same `hash`, same `hmac_signature`, same `timestamp`) —
/// under the message "possible tampering, deletion, reorder, or corruption".
#[test]
fn verify_chain_reports_an_identical_redelivery_as_delivery_not_tampering() {
    let mut events = build_chain("wf", "ex", 3);
    let dup = events[1].clone(); // byte-identical copy of seq 2
    events.push(dup);
    let report = verify_chain("wf", "ex", &events, &[]);
    assert!(
        report
            .breaks
            .iter()
            .any(|b| matches!(b, ChainBreak::DuplicateDelivery { seq: 2 })),
        "breaks: {:?}",
        report.breaks
    );
    assert!(
        !report
            .breaks
            .iter()
            .any(|b| matches!(b, ChainBreak::DuplicateSequence { .. })),
        "an identical copy must not be reported as conflicting: {:?}",
        report.breaks
    );
    assert!(
        report.ok,
        "a duplicate DELIVERY is the only finding, so the chain still verifies: {:?}",
        report.breaks
    );
}

/// The control, and the reason `DuplicateDelivery` may not be defined as
/// "two rows share a sequence": two events claiming ONE sequence with
/// DIFFERENT content is a substitution — one of them is not what the
/// producer wrote — and stays positive tamper evidence.
///
/// This is also the MAJORITY of the live population: 161 of the 196 affected
/// prefixes measured 2026-09-07 carry copies that differ in `timestamp`
/// (hence in hash and signature), because the producer appended one anchor
/// per retry attempt and the attempts straddled a one-second boundary.
#[test]
fn verify_chain_keeps_conflicting_duplicates_as_tamper_evidence() {
    let mut events = build_chain("wf", "ex", 3);
    let mut dup = events[1].clone();
    dup.timestamp += 1; // same sequence, different content
    events.push(dup);
    let report = verify_chain("wf", "ex", &events, &[]);
    assert!(
        report
            .breaks
            .iter()
            .any(|b| matches!(b, ChainBreak::DuplicateSequence { seq: 2 })),
        "breaks: {:?}",
        report.breaks
    );
    assert!(!report.ok, "conflicting content must not verify");
}

/// The signature half of the comparison, kept separate so a
/// `DuplicateDelivery` predicate that only compares hashes goes red here.
/// Two copies with identical CONTENT but different signatures cannot both
/// have been produced by a key holder over that content — one signature was
/// substituted.
#[test]
fn verify_chain_treats_a_resigned_copy_as_conflicting() {
    let key = b"0123456789abcdef0123456789abcdef".to_vec();
    let mut events = build_chain("wf", "ex", 3);
    for e in &mut events {
        e.hmac_signature = Some(hmac_sign(e, &key));
    }
    let mut dup = events[1].clone();
    dup.hmac_signature = Some("00".repeat(32));
    events.push(dup);
    let report = verify_chain("wf", "ex", &events, &[key.clone()]);
    assert!(
        report
            .breaks
            .iter()
            .any(|b| matches!(b, ChainBreak::DuplicateSequence { seq: 2 })),
        "breaks: {:?}",
        report.breaks
    );
    assert!(!report.ok);
}

#[test]
fn verify_chain_checks_signatures_when_keys_present() {
    let key = b"0123456789abcdef0123456789abcdef".to_vec();
    let mut events = build_chain("wf", "ex", 3);
    for e in &mut events {
        e.hmac_signature = Some(hmac_sign(e, &key));
    }
    // All valid + signed.
    let report = verify_chain("wf", "ex", &events, std::slice::from_ref(&key));
    assert!(report.ok, "breaks: {:?}", report.breaks);
    assert!(report.signatures_checked);

    // Forge one signature -> BadSignature.
    events[1].hmac_signature = Some("deadbeef".to_string());
    let report = verify_chain("wf", "ex", &events, std::slice::from_ref(&key));
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

// ── verify_chain_anchored (terminal anchor / tail-truncation detection) ────

#[test]
fn terminal_anchor_intact_chain_passes() {
    let mut ledger = ExecutionLedger::new("wf", "ex");
    for i in 1..=3u64 {
        ledger.append("worker", "act", &format!("payload-{i}"));
    }
    let mut events: Vec<AuditEvent> = Vec::new();
    let mut rebuild = ExecutionLedger::new("wf", "ex");
    for i in 1..=3u64 {
        events.push(rebuild.append("worker", "act", &format!("payload-{i}")));
    }
    let anchor = rebuild.append_terminal_anchor("worker");
    assert_eq!(anchor.action, TERMINAL_ANCHOR_ACTION);
    assert_eq!(anchor.sequence_num, 4);
    events.push(anchor);

    let report = verify_chain_anchored("wf", "ex", &events, &[]);
    assert!(report.ok, "chain breaks: {:?}", report.chain.breaks);
    assert!(report.chain.ok);
    assert_eq!(report.anchor, AnchorVerdict::Anchored { total_events: 4 });
    assert!(!report.anchor.is_hard_failure());
}

#[test]
fn terminal_anchor_detects_tail_truncation_before_anchor() {
    // 5 events + anchor (6 total). Delete the two events immediately before
    // the anchor — the classic "trim the incriminating tail but the anchor
    // row survives" shape. Both the gap AND the anchor count check fire.
    let mut ledger = ExecutionLedger::new("wf", "ex");
    let mut events: Vec<AuditEvent> = (1..=5u64)
        .map(|i| ledger.append("worker", "act", &format!("payload-{i}")))
        .collect();
    events.push(ledger.append_terminal_anchor("worker"));

    events.remove(4); // seq 5
    events.remove(3); // seq 4

    let report = verify_chain_anchored("wf", "ex", &events, &[]);
    assert!(!report.ok);
    assert_eq!(
        report.anchor,
        AnchorVerdict::CountMismatch {
            committed: 6,
            found: 4
        }
    );
    assert!(report.anchor.is_hard_failure());
}

#[test]
fn terminal_anchor_deleted_tail_including_anchor_is_soft_unanchored() {
    // Deleting the tail INCLUDING the anchor leaves a structurally valid
    // 1..3 chain that is indistinguishable from a legacy pre-anchor chain —
    // the verdict is the soft `Unanchored`, surfaced for callers that know
    // the execution completed post-rollout, but `ok` is preserved.
    let mut ledger = ExecutionLedger::new("wf", "ex");
    let mut events: Vec<AuditEvent> = (1..=5u64)
        .map(|i| ledger.append("worker", "act", &format!("payload-{i}")))
        .collect();
    events.push(ledger.append_terminal_anchor("worker"));

    events.truncate(3); // drop seq 4, 5, and the anchor (seq 6)

    let report = verify_chain_anchored("wf", "ex", &events, &[]);
    assert!(report.chain.ok, "breaks: {:?}", report.chain.breaks);
    assert_eq!(report.anchor, AnchorVerdict::Unanchored);
    assert!(report.ok, "unanchored must NOT hard-fail");
}

#[test]
fn unanchored_legacy_chain_gets_soft_verdict_not_failure() {
    let events = build_chain("wf", "ex", 4);
    let report = verify_chain_anchored("wf", "ex", &events, &[]);
    assert!(report.ok);
    assert!(report.chain.ok);
    assert_eq!(report.anchor, AnchorVerdict::Unanchored);
    assert!(!report.anchor.is_hard_failure());
}

#[test]
fn terminal_anchor_tampered_count_is_caught_even_unsigned() {
    // The anchor is the LAST event — nothing chains onto it, so (unsigned)
    // its payload can be rewritten without any LinkageMismatch. The count
    // check is what catches it.
    let mut ledger = ExecutionLedger::new("wf", "ex");
    let mut events: Vec<AuditEvent> = (1..=2u64)
        .map(|i| ledger.append("worker", "act", &format!("payload-{i}")))
        .collect();
    events.push(ledger.append_terminal_anchor("worker"));
    let last = events.len() - 1;
    events[last].payload = format!("{{\"{TERMINAL_ANCHOR_TOTAL_EVENTS_FIELD}\":7}}");

    let report = verify_chain_anchored("wf", "ex", &events, &[]);
    assert!(!report.ok);
    assert_eq!(
        report.anchor,
        AnchorVerdict::CountMismatch {
            committed: 7,
            found: 3
        }
    );
    // With HMAC keys configured the same tamper ALSO trips BadSignature.
    let key = b"0123456789abcdef0123456789abcdef".to_vec();
    let mut signed = events.clone();
    for e in &mut signed {
        e.hmac_signature = Some(hmac_sign(e, &key));
    }
    signed[last].payload = format!("{{\"{TERMINAL_ANCHOR_TOTAL_EVENTS_FIELD}\":7}}");
    signed[last].hmac_signature = events[last].hmac_signature.clone(); // keep pre-tamper (absent) sig? no — resign below
    signed[last].hmac_signature = Some(hmac_sign(
        &{
            let mut clean = signed[last].clone();
            clean.payload = format!("{{\"{TERMINAL_ANCHOR_TOTAL_EVENTS_FIELD}\":3}}");
            clean
        },
        &key,
    )); // signature over the ORIGINAL (count=3) payload
    let report = verify_chain_anchored("wf", "ex", &signed, &[key]);
    assert!(!report.ok);
    assert!(report
        .chain
        .breaks
        .iter()
        .any(|b| matches!(b, ChainBreak::BadSignature { seq: 3 })));
}

#[test]
fn terminal_anchor_not_last_event_is_hard_failure() {
    // Events appended AFTER the anchor = post-completion writes.
    let mut ledger = ExecutionLedger::new("wf", "ex");
    let mut events: Vec<AuditEvent> = (1..=2u64)
        .map(|i| ledger.append("worker", "act", &format!("payload-{i}")))
        .collect();
    events.push(ledger.append_terminal_anchor("worker")); // seq 3
    events.push(ledger.append("worker", "act", "sneaky-post-completion")); // seq 4

    let report = verify_chain_anchored("wf", "ex", &events, &[]);
    assert!(!report.ok);
    assert_eq!(
        report.anchor,
        AnchorVerdict::NotTerminal {
            anchor_seq: 3,
            last_seq: 4
        }
    );
    // The chain itself is structurally intact — only the anchor check fires.
    assert!(report.chain.ok, "breaks: {:?}", report.chain.breaks);
}

#[test]
fn terminal_anchor_malformed_payload_is_hard_failure() {
    let mut ledger = ExecutionLedger::new("wf", "ex");
    let mut events: Vec<AuditEvent> = (1..=2u64)
        .map(|i| ledger.append("worker", "act", &format!("payload-{i}")))
        .collect();
    // An anchor-typed event appended with a junk payload (producer bug or
    // tamper) must fail loud, never silently skip the count check.
    events.push(ledger.append("worker", TERMINAL_ANCHOR_ACTION, "not-json"));

    let report = verify_chain_anchored("wf", "ex", &events, &[]);
    assert!(!report.ok);
    assert_eq!(report.anchor, AnchorVerdict::MalformedAnchor { seq: 3 });
}

#[test]
fn terminal_anchor_multiple_anchors_is_hard_failure() {
    let mut ledger = ExecutionLedger::new("wf", "ex");
    let mut events: Vec<AuditEvent> = (1..=2u64)
        .map(|i| ledger.append("worker", "act", &format!("payload-{i}")))
        .collect();
    events.push(ledger.append_terminal_anchor("worker"));
    events.push(ledger.append_terminal_anchor("worker"));

    let report = verify_chain_anchored("wf", "ex", &events, &[]);
    assert!(!report.ok);
    assert_eq!(report.anchor, AnchorVerdict::MultipleAnchors { count: 2 });
}

#[test]
fn terminal_anchor_commits_count_including_itself() {
    // Producer invariant: committed total == anchor's own sequence_num ==
    // full chain length including the anchor.
    let mut ledger = ExecutionLedger::new("wf", "ex");
    ledger.append("worker", "act", "p1");
    let anchor = ledger.append_terminal_anchor("worker");
    assert_eq!(anchor.sequence_num, 2);
    let payload: serde_json::Value = serde_json::from_str(&anchor.payload).unwrap();
    assert_eq!(
        payload
            .get(TERMINAL_ANCHOR_TOTAL_EVENTS_FIELD)
            .and_then(|v| v.as_u64()),
        Some(2)
    );
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

// ---------------------------------------------------------------------------
// Signing self-test — the sign→verify round trip `security_audit` reports from.
// ---------------------------------------------------------------------------

#[test]
fn signing_selftest_verifies_under_a_matching_key() {
    let key = b"0123456789abcdef0123456789abcdef".to_vec();
    assert_eq!(
        crate::signing_selftest(Some(&key), std::slice::from_ref(&key)),
        crate::SigningSelfTest::Verified
    );
}

/// The control-ABSENT arm: no signing key at all.
#[test]
fn signing_selftest_reports_not_signed_without_a_key() {
    assert_eq!(
        crate::signing_selftest(None, &[]),
        crate::SigningSelfTest::NotSigned
    );
    // A verifier key set on its own signs nothing.
    let key = b"0123456789abcdef0123456789abcdef".to_vec();
    assert_eq!(
        crate::signing_selftest(None, std::slice::from_ref(&key)),
        crate::SigningSelfTest::NotSigned
    );
}

/// The control-PRESENT-BUT-BROKEN arm, and the reason this self-test exists:
/// a signing key that no verifier key accepts produces audit events that look
/// signed and fail `verify_chain`. A presence check cannot see this.
#[test]
fn signing_selftest_reports_rejection_when_signer_and_verifier_disagree() {
    let signing = b"0123456789abcdef0123456789abcdef".to_vec();
    let verifying = b"ffffffffffffffffffffffffffffffff".to_vec();
    assert_eq!(
        crate::signing_selftest(Some(&signing), std::slice::from_ref(&verifying)),
        crate::SigningSelfTest::SignatureRejected
    );
    // An EMPTY verifier set is the shape a below-entropy-floor key produces:
    // `audit_verify_keys()` drops it, so nothing can accept the signature.
    assert_eq!(
        crate::signing_selftest(Some(&signing), &[]),
        crate::SigningSelfTest::SignatureRejected
    );
}

/// `sign_with_hash_using` must produce byte-identical output to the HMAC
/// construction the rest of this suite signs with — otherwise the self-test
/// would be validating a different signature than production writes.
#[test]
fn sign_with_hash_using_matches_the_canonical_hmac_construction() {
    let key = b"0123456789abcdef0123456789abcdef";
    let mut ev = AuditEvent {
        workflow_id: "wf".to_string(),
        execution_id: "ex".to_string(),
        sequence_num: 7,
        timestamp: 1_700_000_000,
        actor: "agent:test".to_string(),
        action: "act".to_string(),
        payload: "{\"a\":1}".to_string(),
        previous_hash: "prev".to_string(),
        hmac_signature: None,
        dispatch_attempt: 0,
    };
    let expected = hmac_sign(&ev, key);
    let hash = ev.calculate_hash();
    ev.sign_with_hash_using(&hash, key);

    assert_eq!(ev.hmac_signature.as_deref(), Some(expected.as_str()));
}

/// The anchored verifier must agree with the chain report about the same
/// events. Before the dedupe, an identical redelivery of a one-event chain
/// produced TWO hard failures from one benign copy: the anchor commits
/// `total_events: 1` and the verifier counted 2 (`CountMismatch`), and the
/// duplicated anchor also read as `MultipleAnchors`. That is the exact shape
/// of the live finding (`total_events=2`, one anchor, seq 1).
#[test]
fn an_identical_redelivered_anchor_still_verifies_as_anchored() {
    let mut ledger = ExecutionLedger::new("wf", "ex");
    let anchor = ledger.append_terminal_anchor("worker");
    let events = vec![anchor.clone(), anchor];
    let report = verify_chain_anchored("wf", "ex", &events, &[]);
    assert_eq!(report.anchor, AnchorVerdict::Anchored { total_events: 1 });
    assert!(report.ok, "{:?}", report);
    assert!(report
        .chain
        .breaks
        .iter()
        .any(|b| matches!(b, ChainBreak::DuplicateDelivery { seq: 1 })));
}

/// The control for the dedupe: two anchors that DIFFER stay a hard failure.
/// This is the majority shape on the live ledger — one anchor per retry
/// attempt, attempts straddling a one-second `timestamp` boundary.
#[test]
fn two_conflicting_anchors_stay_a_hard_failure() {
    let mut ledger = ExecutionLedger::new("wf", "ex");
    let anchor = ledger.append_terminal_anchor("worker");
    let mut second = anchor.clone();
    second.timestamp += 1;
    let report = verify_chain_anchored("wf", "ex", &[anchor, second], &[]);
    assert!(!report.ok, "{:?}", report);
    assert_eq!(report.anchor, AnchorVerdict::MultipleAnchors { count: 2 });
}

// ============================================================================
// Attempt-0 byte-for-byte fixture (pinned 2026-09-07, BEFORE `dispatch_attempt`)
// ============================================================================

/// Deterministic attempt-0 event, hashed and HMAC-signed under a fixed key.
///
/// PINNED BEFORE the `dispatch_attempt` field existed. Every object already in
/// the WORM bucket was written by a producer whose events carried no attempt
/// index; the partitioning change must leave their hash and HMAC inputs
/// untouched or every one of them stops verifying. A behavioural sign→verify
/// test cannot see a CONSISTENT both-sides drift — only a literal can.
#[test]
fn attempt_zero_event_hash_and_hmac_are_pinned() {
    let ev = AuditEvent {
        workflow_id: "wf-fixture".to_string(),
        execution_id: "exec-fixture".to_string(),
        sequence_num: 1,
        timestamp: 1_700_000_000,
        actor: "worker".to_string(),
        action: "execution_complete".to_string(),
        payload: r#"{"total_events":1}"#.to_string(),
        previous_hash: ExecutionLedger::genesis_hash("wf-fixture", "exec-fixture"),
        hmac_signature: None,
        dispatch_attempt: 0,
    };
    assert_eq!(
        ev.calculate_hash(),
        "6f3c29fb35b224a76315baee68f88d2550be59c394957a6ea1e1d31ca3bc4433"
    );
    assert_eq!(
        hmac_sign(&ev, b"fixture-key-0123456789abcdef0123"),
        "35cb8dcc6005f15bc03980dc79b10278f363721ef8fcb5cf14fb204e2c6ab864"
    );
    assert_eq!(
        ExecutionLedger::genesis_hash("wf-fixture", "exec-fixture"),
        "1e2a75a27dc45f8f14460bbc20406b60ca1b89250d8230136226822ffe38c21f"
    );
}

// ============================================================================
// Per-dispatch-attempt partitioning
// ============================================================================

/// THE test this change exists for.
///
/// A controller re-dispatch re-uses the same `job_id`, so the second attempt's
/// worker mints a FRESH ledger — same genesis, `sequence_num` restarting at 1.
/// Before `dispatch_attempt` existed the verifier had no key to tell those two
/// chains apart and reported `DuplicateSequence` — positive tamper evidence —
/// on a job that had merely been retried. Measured on the live bucket
/// 2026-09-07: ~150 prefixes carry more than one object, and the largest
/// (11 and 12 copies) match `node_retrying` rows one-for-one.
#[test]
fn two_dispatch_attempts_verify_as_two_chains() {
    let mut a0 = ExecutionLedger::new_for_attempt("wf", "ex", 0);
    let mut a1 = ExecutionLedger::new_for_attempt("wf", "ex", 1);
    let mut events = vec![a0.append("worker", "act", "one")];
    events.push(a0.append_terminal_anchor("worker"));
    // Attempt 1's records are CONFLICTING with attempt 0's under the
    // pre-partition rule — same sequence, different content — which is the
    // majority live shape (161 of 196 prefixes measured 2026-09-07, differing
    // by a `timestamp` that straddled a whole-second boundary). Modelled here
    // as a different payload, because mutating a record AFTER `append` would
    // break the chain link the ledger already committed to. So this test
    // cannot pass by the byte-identical `DuplicateDelivery` route.
    events.push(a1.append("worker", "act", "two"));
    events.push(a1.append_terminal_anchor("worker"));

    let report = verify_chain("wf", "ex", &events, &[]);
    assert!(
        report.ok,
        "two attempts of one job are two chains, not a substitution: {:?}",
        report.breaks
    );
    assert!(
        report.breaks.is_empty(),
        "no break of any kind is expected: {:?}",
        report.breaks
    );
    assert_eq!(report.total_events, 4, "every persisted record is counted");
    assert_eq!(
        report.attempts.len(),
        2,
        "one report per dispatch attempt: {:?}",
        report.attempts
    );
    assert_eq!(report.attempts[0].dispatch_attempt, 0);
    assert_eq!(report.attempts[1].dispatch_attempt, 1);
    assert!(report.attempts.iter().all(|a| a.ok));
    assert!(report.attempts.iter().all(|a| a.total_events == 2));

    // The anchor verdict partitions too: each attempt carries exactly one
    // terminal anchor committing its OWN length, so the pre-partition reading
    // (`MultipleAnchors`, a hard failure) must not survive.
    let anchored = verify_chain_anchored("wf", "ex", &events, &[]);
    assert!(anchored.ok, "anchor: {:?}", anchored.anchor);
    assert!(matches!(
        anchored.anchor,
        AnchorVerdict::Anchored { total_events: 2 }
    ));
    assert_eq!(anchored.attempt_anchors.len(), 2);
}

/// The CONTROL. Partitioning must not become a way to launder a substitution:
/// two conflicting records at the SAME attempt and the SAME sequence are still
/// tamper evidence, and `ok` must still be false.
#[test]
fn conflicting_records_within_one_attempt_stay_tamper_evidence() {
    let mut a1 = ExecutionLedger::new_for_attempt("wf", "ex", 1);
    let first = a1.append("worker", "act", "one");
    let mut conflicting = first.clone();
    conflicting.timestamp += 1; // same attempt, same sequence, different content
    let events = vec![first, conflicting];

    let report = verify_chain("wf", "ex", &events, &[]);
    assert!(
        report
            .breaks
            .iter()
            .any(|b| matches!(b, ChainBreak::DuplicateSequence { seq: 1 })),
        "breaks: {:?}",
        report.breaks
    );
    assert!(
        !report.ok,
        "a substitution within one attempt must not verify"
    );
    assert_eq!(report.attempts.len(), 1);
    assert!(!report.attempts[0].ok);
    assert_eq!(report.attempts[0].dispatch_attempt, 1);
}

/// A single-attempt chain must be indistinguishable from the pre-change
/// answer: one attempt report, and the top-level fields unchanged.
#[test]
fn a_single_attempt_chain_reports_exactly_one_partition() {
    let events = build_chain("wf", "ex", 3);
    let report = verify_chain("wf", "ex", &events, &[]);
    assert!(report.ok);
    assert_eq!(report.attempts.len(), 1);
    assert_eq!(report.attempts[0].dispatch_attempt, 0);
    assert_eq!(report.attempts[0].total_events, 3);
}

/// Each attempt links to the SAME genesis — the attempt is a PARTITION key,
/// never a genesis input, so an old chain and a new one share one rule.
#[test]
fn every_attempt_links_to_the_same_genesis() {
    let g = ExecutionLedger::genesis_hash("wf", "ex");
    let mut a2 = ExecutionLedger::new_for_attempt("wf", "ex", 2);
    let first = a2.append("worker", "act", "one");
    assert_eq!(first.previous_hash, g);
    assert_eq!(first.dispatch_attempt, 2);
}

/// An attempt-0 event serialises WITHOUT the field, so every object already in
/// the bucket round-trips byte-for-byte; a non-zero attempt carries it.
#[test]
fn attempt_zero_is_omitted_from_the_wire_and_non_zero_is_not() {
    let mut a0 = ExecutionLedger::new("wf", "ex");
    let e0 = a0.append("worker", "act", "p");
    let j0 = serde_json::to_string(&e0).expect("serialize");
    assert!(
        !j0.contains("dispatch_attempt"),
        "attempt-0 wire text must be byte-identical to the pre-field format: {j0}"
    );

    let mut a1 = ExecutionLedger::new_for_attempt("wf", "ex", 1);
    let e1 = a1.append("worker", "act", "p");
    let j1 = serde_json::to_string(&e1).expect("serialize");
    assert!(j1.contains(r#""dispatch_attempt":1"#), "{j1}");

    // And a legacy object with no field deserialises to attempt 0.
    let back: AuditEvent = serde_json::from_str(&j0).expect("deserialize");
    assert_eq!(back.dispatch_attempt, 0);
}

/// The attempt is part of the HASH, so it cannot be edited on a persisted
/// record without breaking the signature — the partition key is as
/// tamper-evident as every other field.
#[test]
fn the_attempt_is_bound_into_the_event_hash() {
    let mut a0 = ExecutionLedger::new("wf", "ex");
    let e0 = a0.append("worker", "act", "p");
    let mut moved = e0.clone();
    moved.dispatch_attempt = 1;
    assert_ne!(
        e0.calculate_hash(),
        moved.calculate_hash(),
        "moving an event between attempts must change its hash"
    );
    let key = b"0123456789abcdef0123456789abcdef".to_vec();
    let mut signed = e0.clone();
    signed.hmac_signature = Some(hmac_sign(&signed, &key));
    let mut relabelled = signed.clone();
    relabelled.dispatch_attempt = 1;
    assert_eq!(relabelled.verify_signature(&[key]), Some(false));
}

/// The 2026-09-11 defect, as a test. A standalone dispatch (module-bound
/// webhook / push) is signed on the wire with `workflow_execution_id = job_id`,
/// so the WORKER seals its ledger under `genesis(job, job)`. `talos-engine`'s
/// chain runner then rewrote `module_executions.workflow_execution_id` to the
/// chain run it fired, and the verifier — which reads that column — expected
/// `genesis(run, job)`: `GenesisMismatch` at sequence 1, "possible tampering",
/// on every module-bound dispatch that fired a chain. The chain is untouched
/// in both arms below; only the verifier's idea of the key space moves.
#[test]
fn a_chain_sealed_under_the_standalone_genesis_fails_under_a_reparented_one() {
    let job = "2d369773-e36d-4258-9166-b6e37b447f4c";
    let chain_run = "942a8b84-14c1-4332-98ba-0eb21694b36b";
    let mut ledger = ExecutionLedger::new(job, job);
    let e1 = ledger.append("worker", "execution_complete", "{\"total_events\":1}");
    let events = vec![e1];

    let under_contract = verify_chain(job, job, &events, &[]);
    assert!(under_contract.ok, "{:?}", under_contract.breaks);
    assert!(under_contract.breaks.is_empty());

    let reparented = verify_chain(chain_run, job, &events, &[]);
    assert!(!reparented.ok);
    assert!(
        matches!(
            reparented.breaks.as_slice(),
            [ChainBreak::GenesisMismatch { seq: 1, .. }]
        ),
        "moving the key space under a sealed chain reads as tampering: {:?}",
        reparented.breaks
    );
    assert!(reparented.breaks[0].is_tamper_evidence());
}
