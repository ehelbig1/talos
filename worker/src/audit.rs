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
}

/// Cached audit signing key, loaded once from `TALOS_AUDIT_SIGNING_KEY`.
///
/// When set, every audit event is HMAC-SHA256 signed before publishing.
/// This provides tamper detection: an attacker who gains database access
/// cannot forge events without the signing key.
///
/// Key rotation: set `TALOS_AUDIT_SIGNING_KEY_PREVIOUS` (comma-separated)
/// for verification of events signed with older keys.
static AUDIT_SIGNING_KEY: std::sync::OnceLock<Option<Vec<u8>>> = std::sync::OnceLock::new();

fn audit_signing_key() -> &'static Option<Vec<u8>> {
    AUDIT_SIGNING_KEY.get_or_init(|| {
        // MCP-671 (2026-05-13): route through `talos_config::is_production()`
        // so a helm-rendered `RUST_ENV=""` doesn't downgrade the
        // production-only audit-signing alerts (ERROR for missing key,
        // ERROR for short key) to dev-level WARN/INFO. Without the
        // proper gate, a SIEM pipeline looking for the structured
        // `event_kind = "audit_signing_disabled_in_production"` event
        // would silently miss it. Sibling site of MCP-668 (which
        // closed the same family in worker/src/main.rs).
        let is_production = talos_config::is_production();
        match std::env::var("TALOS_AUDIT_SIGNING_KEY") {
            Ok(k) if !k.is_empty() => {
                let key_bytes = k.into_bytes();
                if key_bytes.len() < 32 {
                    // MCP-579: weak HMAC-SHA256 signing key is a real
                    // forge-risk surface. An attacker with DB access
                    // who's also seen one valid (event_hash, signature)
                    // pair can grind a < 32-byte key materially faster
                    // than the ~256 bits SHA-256 nominally provides.
                    // In production, surface at ERROR with structured
                    // event_kind so log-aggregation alerts page the
                    // operator at startup; in dev, keep the existing
                    // WARN so test harnesses with short keys aren't
                    // noisy.
                    if is_production {
                        tracing::error!(
                            target: "talos_audit",
                            event_kind = "audit_signing_key_weak_in_production",
                            key_len = key_bytes.len(),
                            "TALOS_AUDIT_SIGNING_KEY is only {} bytes in production — \
                             HMAC-SHA256 requires 32+ bytes for full collision resistance. \
                             Tamper-detection on audit events is materially weakened until \
                             the key is rotated. Generate via: openssl rand -hex 32",
                            key_bytes.len()
                        );
                    } else {
                        tracing::warn!(
                            "TALOS_AUDIT_SIGNING_KEY is only {} bytes — 32+ bytes recommended for HMAC-SHA256",
                            key_bytes.len()
                        );
                    }
                }
                tracing::info!("Audit event signing enabled");
                Some(key_bytes)
            }
            _ => {
                // MCP-579: unsigned audit events in production = no
                // tamper detection. An attacker with DB access can
                // forge or alter events freely. Same elevated-signal
                // pattern as MCP-574 (DLP disabled) and MCP-570
                // (audit consumer offline) — loud in production,
                // quiet in dev where it's normal.
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

impl AuditEvent {
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
    pub(crate) fn sign_with_hash(&mut self, event_hash: &str) {
        if let Some(key) = audit_signing_key() {
            use hmac::{Hmac, Mac};
            if let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key) {
                mac.update(event_hash.as_bytes());
                self.hmac_signature = Some(hex::encode(mac.finalize().into_bytes()));
            }
        }
    }

    /// Verify this event's HMAC signature against the provided keys.
    /// Returns `true` if signature is valid, `false` if invalid, and `None` if unsigned.
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

use chrono::Utc;

/// A local tracker for the cryptographic ledger of a specific execution
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
    /// MCP-490: previously used pipe-separated concatenation
    /// `format!("genesis:{}|{}", workflow_id, execution_id)`. With a
    /// pipe character in either id (UUIDs don't have them, but the API
    /// accepts arbitrary strings — `mcp_set_workflow_actor_id` lets an
    /// operator stamp a custom workflow_id), two distinct
    /// `(workflow_id, execution_id)` tuples could produce the same
    /// genesis hash — e.g. `("wf|x", "ec1")` and `("wf", "x|ec1")` both
    /// serialize to `"genesis:wf|x|ec1"`. The per-event `calculate_hash`
    /// already uses length-prefix encoding to prevent exactly this
    /// delimiter-injection class; the genesis hash should match for
    /// defense-in-depth.
    fn genesis_hash(workflow_id: &str, execution_id: &str) -> String {
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

    /// Appends a new event to the ledger, calculating the proper sequence, cryptographic link,
    /// and HMAC signature (if a signing key is configured).
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

        // Finalize the cryptographic link (one SHA-256 pass, reused
        // for both the chain link and the HMAC input — MCP-490).
        let current_hash = event.calculate_hash();
        event.sign_with_hash(&current_hash);

        // Update the ledger pointer
        self.last_hash = current_hash;

        event
    }
}

#[cfg(test)]
#[path = "audit_tests.rs"]
mod tests;
