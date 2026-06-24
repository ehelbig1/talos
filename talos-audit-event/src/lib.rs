//! Shared cryptographic audit-event primitives.
//!
//! SINGLE SOURCE OF TRUTH for the hash-chained, HMAC-signed audit events
//! that flow over `talos.audit.ledger`. The **producer** (the worker, via
//! [`ExecutionLedger`]) and every **verifier** (the controller-side WORM
//! persister's inline check, and the offline [`verify_chain`] sweep) MUST
//! use the SAME [`AuditEvent::calculate_hash`] / [`AuditEvent::verify_signature`]
//! code — a divergent copy would silently break tamper detection. This crate
//! exists so neither side re-implements the canonical hashing/signing.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AuditEvent {
    pub workflow_id: String,
    pub execution_id: String,
    pub sequence_num: u64,
    pub timestamp: i64,
    pub actor: String,         // e.g., "agent:gpt-4", "human:manager@company.com"
    pub action: String,        // e.g., "mcp:request_tool", "wasi:human_approval"
    pub payload: String,       // The exact JSON sent or received
    pub previous_hash: String, // The cryptographic link
    /// HMAC-SHA256 signature over the event hash, proving the event was created
    /// by an entity holding the signing key. Enables tamper detection even if an
    /// attacker gains direct database access.
    ///
    /// Absent for events created before signing was introduced; verifiers should
    /// treat missing signatures as "unverified" rather than "invalid".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hmac_signature: Option<String>,
}

impl AuditEvent {
    /// Generates the immutable signature for this exact moment in time.
    ///
    /// Uses length-prefixed encoding (`len:value`) for each field to prevent
    /// delimiter injection attacks. The `:` delimiter in the old format allowed
    /// field values containing `:` to shift field boundaries and forge events.
    pub fn calculate_hash(&self) -> String {
        let mut hasher = Sha256::new();

        // Length-prefixed encoding: each field is encoded as `{byte_len}\0{value}`
        // so that no field value can shift boundaries (null bytes cannot appear in
        // valid UTF-8 string fields).
        fn lp(s: &str) -> Vec<u8> {
            let mut out = s.len().to_string().into_bytes();
            out.push(0); // null byte separator
            out.extend_from_slice(s.as_bytes());
            out
        }

        let seq_str = self.sequence_num.to_string();
        let ts_str = self.timestamp.to_string();

        // Build the canonical event representation with length-prefixed fields
        let mut event_bytes = Vec::new();
        event_bytes.extend_from_slice(&lp(&self.workflow_id));
        event_bytes.extend_from_slice(&lp(&self.execution_id));
        event_bytes.extend_from_slice(&lp(&seq_str));
        event_bytes.extend_from_slice(&lp(&ts_str));
        event_bytes.extend_from_slice(&lp(&self.actor));
        event_bytes.extend_from_slice(&lp(&self.action));
        event_bytes.extend_from_slice(&lp(&self.payload));

        // Hash the current event WITH the previous hash (pipe-separated for chain link)
        hasher.update(self.previous_hash.as_bytes());
        hasher.update(b"|");
        hasher.update(&event_bytes);

        format!("{:x}", hasher.finalize())
    }

    /// Sign this event using HMAC-SHA256 if a signing key is configured.
    /// Mutates `hmac_signature` in place. Call after `calculate_hash()`.
    pub fn sign(&mut self) {
        let hash = self.calculate_hash();
        self.sign_with_hash(&hash);
    }

    /// Fast-path variant of `sign` for callers that already computed the
    /// event hash (e.g. `ExecutionLedger::append`, which needs the hash
    /// for the chain link anyway). SHA-256 over event payloads is the hot
    /// path on every WASM action and can hash hundreds of KB; doing it
    /// twice per event was MCP-490's wasted-work bug. Logically identical
    /// to `sign()`.
    pub fn sign_with_hash(&mut self, event_hash: &str) {
        if let Some(key) = audit_signing_key() {
            use hmac::{Hmac, Mac};
            if let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key) {
                mac.update(event_hash.as_bytes());
                self.hmac_signature = Some(hex::encode(mac.finalize().into_bytes()));
            }
        }
    }

    /// Verify this event's HMAC signature against the provided keys.
    /// Returns `Some(true)` if the signature is valid, `Some(false)` if
    /// invalid, and `None` if the event is unsigned.
    pub fn verify_signature(&self, keys: &[Vec<u8>]) -> Option<bool> {
        let sig_hex = self.hmac_signature.as_ref()?;
        let sig_bytes = match hex::decode(sig_hex) {
            Ok(b) => b,
            Err(_) => return Some(false),
        };

        let event_hash = self.calculate_hash();

        for key in keys {
            use hmac::{Hmac, Mac};
            if let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key) {
                mac.update(event_hash.as_bytes());
                // Use constant-time verification
                if mac.verify_slice(&sig_bytes).is_ok() {
                    return Some(true);
                }
            }
        }
        Some(false)
    }
}

/// Cached audit signing key, loaded once from `TALOS_AUDIT_SIGNING_KEY`.
///
/// When set, every audit event is HMAC-SHA256 signed before publishing.
/// This provides tamper detection: an attacker who gains database access
/// cannot forge events without the signing key.
///
/// Entropy requirement: the key must carry at least 32 bytes (256 bits) of
/// *effective entropy*. The check decodes hex first — an all-hex value needs
/// >= 64 hex chars (>= 32 decoded bytes); any other value (raw binary /
/// base64 / passphrase) needs >= 32 bytes of raw length. A 32-hex-char key
/// (`openssl rand -hex 16`, only 16 bytes) is REJECTED and signing is
/// disabled. The canonical full-strength key is `openssl rand -hex 32`
/// (a 64-char hex string). The accepted key bytes are the raw UTF-8 string
/// (NOT the hex-decoded form), so this floor never alters an existing
/// signature.
///
/// Key rotation: set `TALOS_AUDIT_SIGNING_KEY_PREVIOUS` (comma-separated)
/// for verification of events signed with older keys.
static AUDIT_SIGNING_KEY: std::sync::OnceLock<Option<Vec<u8>>> = std::sync::OnceLock::new();

/// Minimum effective key entropy, in bytes, for HMAC-SHA256 signing.
/// HMAC-SHA256 needs a full 256-bit key for collision resistance.
pub(crate) const MIN_KEY_ENTROPY_BYTES: usize = 32;

/// Effective key entropy, in BYTES, of a raw `TALOS_AUDIT_SIGNING_KEY`
/// string value.
///
/// MCP-579 (2026-06-23 floor raise): the original check compared
/// `k.into_bytes().len() < 32` against the RAW UTF-8 string — so a
/// 32-hex-char key (`openssl rand -hex 16`, only **16 bytes** of real
/// entropy) passed, because the ASCII string is 32 chars. Operators almost
/// universally generate keys as hex (`openssl rand -hex 32` → a 64-char hex
/// string carrying 32 bytes of entropy), so the right floor is on the
/// *decoded* entropy:
/// - all-hex string (even length) → entropy = `len / 2` decoded bytes
/// - any other string (binary/base64/passphrase) → entropy = byte length
///
/// We do NOT hex-decode the key for use — the signing/verification bytes
/// stay the raw UTF-8 string (`into_bytes()` / `as_bytes()`) so this change
/// can't alter any already-emitted signature or desync from the raw-bytes
/// `TALOS_AUDIT_SIGNING_KEY_PREVIOUS` verification path. This function only
/// decides *acceptance*; the accepted bytes are unchanged.
pub(crate) fn effective_key_entropy_bytes(raw: &str) -> usize {
    let is_hex = !raw.is_empty()
        && raw.len().is_multiple_of(2)
        && raw.bytes().all(|b| b.is_ascii_hexdigit());
    if is_hex {
        raw.len() / 2
    } else {
        raw.len()
    }
}

/// The current signing key, or `None` when signing is disabled. Used by the
/// producer to sign and as the first verification key.
///
/// A key whose *effective entropy* (see [`effective_key_entropy_bytes`]) is
/// below [`MIN_KEY_ENTROPY_BYTES`] (32 bytes / 256 bits) is REJECTED — a
/// 32-hex-char key (16 bytes) returns `None` (signing disabled) rather than
/// silently signing with a forge-weak key. A 64-hex-char key (the
/// `openssl rand -hex 32` output) and a >=32-byte raw binary/base64 key are
/// accepted; the accepted bytes are the raw UTF-8 string unchanged.
pub fn audit_signing_key() -> &'static Option<Vec<u8>> {
    AUDIT_SIGNING_KEY.get_or_init(|| {
        // MCP-671: route through `talos_config::is_production()` so a
        // helm-rendered `RUST_ENV=""` doesn't downgrade the production-only
        // audit-signing alerts to dev-level WARN/INFO. A SIEM pipeline keys
        // on the structured `event_kind = "audit_signing_disabled_in_production"`.
        let is_production = talos_config::is_production();
        match std::env::var("TALOS_AUDIT_SIGNING_KEY") {
            Ok(k) if !k.is_empty() => {
                let entropy = effective_key_entropy_bytes(&k);
                if entropy < MIN_KEY_ENTROPY_BYTES {
                    // MCP-579: a < 32-byte-effective-entropy HMAC-SHA256 key
                    // is a forge-risk surface. A 32-hex-char key (16 bytes
                    // decoded) is the canonical trap. REJECT it (fail closed
                    // to unsigned + the same loud-in-prod alert below) rather
                    // than sign with a weak key — a forgeable signature is
                    // worse than an explicit "unsigned" posture the verifier
                    // can detect. Loud at ERROR in production (SIEM alert),
                    // WARN in dev (test harnesses use short keys).
                    if is_production {
                        tracing::error!(
                            target: "talos_audit",
                            event_kind = "audit_signing_key_weak_in_production",
                            key_len = k.len(),
                            effective_entropy_bytes = entropy,
                            "TALOS_AUDIT_SIGNING_KEY has only {} bytes of effective entropy in \
                             production (raw length {} chars) — HMAC-SHA256 requires 32+ bytes \
                             (256 bits). The key is REJECTED and audit events will NOT be signed \
                             until it is rotated. A 32-hex-char key is only 16 bytes of entropy; \
                             generate a full-strength key via: openssl rand -hex 32",
                            entropy,
                            k.len()
                        );
                    } else {
                        tracing::warn!(
                            "TALOS_AUDIT_SIGNING_KEY has only {} bytes of effective entropy \
                             (raw length {} chars) — 32+ bytes required for HMAC-SHA256; \
                             key REJECTED, signing disabled. Generate via: openssl rand -hex 32",
                            entropy,
                            k.len()
                        );
                    }
                    return None;
                }
                tracing::info!("Audit event signing enabled");
                Some(k.into_bytes())
            }
            _ => {
                // MCP-579: unsigned audit events in production = no tamper
                // detection. Loud in production, quiet in dev where it's normal.
                if is_production {
                    tracing::error!(
                        target: "talos_audit",
                        event_kind = "audit_signing_disabled_in_production",
                        "TALOS_AUDIT_SIGNING_KEY not set in production — audit events will NOT \
                         be HMAC-signed. DB-write attackers can forge events undetected. \
                         Generate a key via: openssl rand -hex 32, then set TALOS_AUDIT_SIGNING_KEY \
                         on all worker pods + the controller."
                    );
                } else {
                    tracing::info!("TALOS_AUDIT_SIGNING_KEY not set — audit events will not be signed");
                }
                None
            }
        }
    })
}

/// The full set of keys a VERIFIER accepts: the current
/// `TALOS_AUDIT_SIGNING_KEY` first, then each comma-separated entry of
/// `TALOS_AUDIT_SIGNING_KEY_PREVIOUS` (key-rotation overlap). Empty when
/// signing is disabled — callers treat that as "cannot verify" rather than
/// "invalid". Pairs with [`AuditEvent::verify_signature`].
pub fn audit_verify_keys() -> Vec<Vec<u8>> {
    let mut keys = Vec::new();
    if let Some(current) = audit_signing_key() {
        keys.push(current.clone());
    }
    if let Ok(prev) = std::env::var("TALOS_AUDIT_SIGNING_KEY_PREVIOUS") {
        for part in prev.split(',') {
            let trimmed = part.trim();
            if !trimmed.is_empty() {
                keys.push(trimmed.as_bytes().to_vec());
            }
        }
    }
    keys
}

use chrono::Utc;

/// A local tracker for the cryptographic ledger of a specific execution.
pub struct ExecutionLedger {
    pub workflow_id: String,
    pub execution_id: String,
    pub current_sequence: u64,
    pub last_hash: String,
}

impl ExecutionLedger {
    pub fn new(workflow_id: &str, execution_id: &str) -> Self {
        Self {
            workflow_id: workflow_id.to_string(),
            execution_id: execution_id.to_string(),
            current_sequence: 0,
            last_hash: Self::genesis_hash(workflow_id, execution_id),
        }
    }

    /// Compute the genesis (event-0) hash for a ledger.
    ///
    /// MCP-490: length-prefixed (not pipe-separated) so two distinct
    /// `(workflow_id, execution_id)` tuples can't collide to the same
    /// genesis hash — matching the per-event `calculate_hash` discipline.
    pub fn genesis_hash(workflow_id: &str, execution_id: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"genesis:");
        hasher.update(workflow_id.len().to_string().as_bytes());
        hasher.update(b"\0");
        hasher.update(workflow_id.as_bytes());
        hasher.update(execution_id.len().to_string().as_bytes());
        hasher.update(b"\0");
        hasher.update(execution_id.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Appends a new event to the ledger, calculating the proper sequence,
    /// cryptographic link, and HMAC signature (if a signing key is configured).
    pub fn append(&mut self, actor: &str, action: &str, payload: &str) -> AuditEvent {
        self.current_sequence += 1;

        let mut event = AuditEvent {
            workflow_id: self.workflow_id.clone(),
            execution_id: self.execution_id.clone(),
            sequence_num: self.current_sequence,
            timestamp: Utc::now().timestamp(),
            actor: actor.to_string(),
            action: action.to_string(),
            payload: payload.to_string(),
            previous_hash: self.last_hash.clone(),
            hmac_signature: None,
        };

        // Finalize the cryptographic link (one SHA-256 pass, reused for both
        // the chain link and the HMAC input — MCP-490).
        let current_hash = event.calculate_hash();
        event.sign_with_hash(&current_hash);

        // Update the ledger pointer
        self.last_hash = current_hash;

        event
    }
}

// ============================================================================
// Offline chain verification (finding #2, Layer 2)
// ============================================================================

/// A single integrity failure found while verifying a persisted chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ChainBreak {
    /// `sequence_num` is not contiguous — a record is missing (deletion / a
    /// never-persisted event). `expected` is the next sequence we required.
    SequenceGap { expected: u64, found: u64 },
    /// Two records share a `sequence_num`.
    DuplicateSequence { seq: u64 },
    /// The first event's `previous_hash` does not match the deterministic
    /// genesis hash for `(workflow_id, execution_id)`.
    GenesisMismatch {
        seq: u64,
        expected: String,
        found: String,
    },
    /// An event's `previous_hash` does not equal the recomputed hash of the
    /// preceding event — the chain link is broken (reorder / substitution).
    LinkageMismatch {
        seq: u64,
        expected_previous: String,
        found_previous: String,
    },
    /// The event carries an HMAC signature that does not verify against any
    /// configured key — forged or altered content.
    BadSignature { seq: u64 },
    /// The event is unsigned. Only reported when verification keys ARE
    /// configured (otherwise "unverified" is the expected steady state).
    Unsigned { seq: u64 },
}

/// The result of verifying a persisted audit chain for one execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChainVerificationReport {
    pub execution_id: String,
    pub workflow_id: String,
    pub total_events: usize,
    /// `true` iff there are no `breaks` AND (when keys are configured) every
    /// event verified its signature.
    pub ok: bool,
    /// Whether HMAC verification was attempted (keys configured). When false,
    /// `Unsigned`/`BadSignature` are not asserted — the chain is structurally
    /// verified but its authenticity is "unverified".
    pub signatures_checked: bool,
    pub breaks: Vec<ChainBreak>,
}

/// Verify a persisted audit chain for a single execution, end to end.
///
/// This is the stateful "completeness" check deliberately kept OUT of the
/// streaming persister: it needs the full, ordered record set, which is only
/// reliable once everything is at rest. It re-derives every hash canonically
/// (so it trusts no stored hash) and checks, in order:
///   1. sequence contiguity (1..N, no gaps, no duplicates) — catches deletion
///      / never-persisted events that S3 Object Lock alone cannot detect;
///   2. genesis: event 1's `previous_hash` == `genesis_hash(workflow, exec)`;
///   3. linkage: each event's `previous_hash` == the recomputed hash of its
///      predecessor — catches reorder / substitution;
///   4. per-event HMAC signature (when `keys` is non-empty).
///
/// `events` need not be pre-sorted; they are sorted by `sequence_num` here.
/// Pure and deterministic — unit-testable without S3.
pub fn verify_chain(
    workflow_id: &str,
    execution_id: &str,
    events: &[AuditEvent],
    keys: &[Vec<u8>],
) -> ChainVerificationReport {
    let signatures_checked = !keys.is_empty();
    let mut breaks = Vec::new();

    let mut sorted: Vec<&AuditEvent> = events.iter().collect();
    sorted.sort_by_key(|e| e.sequence_num);

    let mut expected_seq: u64 = 1;
    let mut prev_hash = ExecutionLedger::genesis_hash(workflow_id, execution_id);

    for (idx, event) in sorted.iter().enumerate() {
        // Duplicate vs gap on sequence_num.
        if idx > 0 && event.sequence_num == sorted[idx - 1].sequence_num {
            breaks.push(ChainBreak::DuplicateSequence {
                seq: event.sequence_num,
            });
            continue;
        }
        if event.sequence_num != expected_seq {
            breaks.push(ChainBreak::SequenceGap {
                expected: expected_seq,
                found: event.sequence_num,
            });
            // The end-of-iteration `expected_seq = event.sequence_num + 1`
            // re-bases us, so a single gap doesn't cascade a break per row.
        }

        // Chain linkage: event 1 links to genesis, event N links to event N-1.
        if event.previous_hash != prev_hash {
            if event.sequence_num == 1 {
                breaks.push(ChainBreak::GenesisMismatch {
                    seq: event.sequence_num,
                    expected: prev_hash.clone(),
                    found: event.previous_hash.clone(),
                });
            } else {
                breaks.push(ChainBreak::LinkageMismatch {
                    seq: event.sequence_num,
                    expected_previous: prev_hash.clone(),
                    found_previous: event.previous_hash.clone(),
                });
            }
        }

        // Authenticity.
        if signatures_checked {
            match event.verify_signature(keys) {
                Some(true) => {}
                Some(false) => breaks.push(ChainBreak::BadSignature {
                    seq: event.sequence_num,
                }),
                None => breaks.push(ChainBreak::Unsigned {
                    seq: event.sequence_num,
                }),
            }
        }

        prev_hash = event.calculate_hash();
        expected_seq = event.sequence_num + 1;
    }

    ChainVerificationReport {
        execution_id: execution_id.to_string(),
        workflow_id: workflow_id.to_string(),
        total_events: sorted.len(),
        ok: breaks.is_empty(),
        signatures_checked,
        breaks,
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
