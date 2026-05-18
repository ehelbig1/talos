//! Workflow definition signing — HMAC-SHA256 signatures on published workflow versions.
//!
//! When `TALOS_WORKFLOW_SIGNING_KEY` is set, every `publish_version` call
//! computes SHA-256(graph_json) and signs it with HMAC-SHA256. The signature
//! is stored alongside the version and can be verified before execution.

use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use zeroize::Zeroizing;

/// L-11: SIGNING_KEY held in `Zeroizing<Vec<u8>>` so the in-heap copy of
/// the HMAC root is wiped if the OnceLock is ever rebuilt or process
/// drops. Process-lifetime, but heap-dump exposure is bounded.
static SIGNING_KEY: OnceLock<Option<Zeroizing<Vec<u8>>>> = OnceLock::new();

/// L-12: when `TALOS_WORKFLOW_SIGNING_KEY` is SET but malformed (bad hex,
/// short, etc.), strict deploys want fail-fast rather than silently
/// disabling signing. This function indicates whether the operator
/// explicitly opted in to fail-fast via `TALOS_WORKFLOW_SIGNING_STRICT=true`.
///
/// MCP-1060 (2026-05-15): routed through the canonical
/// `bool_env_or_default` helper. Pre-fix this was an inline copy of the
/// `matches!(v.trim().to_ascii_lowercase().as_str(), "true" | "1" | "yes")`
/// predicate — one of three sibling sites that drifted slightly (the
/// worker site additionally accepted `"on"`). The canonical helper now
/// also accepts `"on"` here, which is a strict-superset behaviour
/// change in the direction of operator-friendliness.
fn strict_mode() -> bool {
    talos_config::bool_env_or_default("TALOS_WORKFLOW_SIGNING_STRICT", false)
}

fn signing_key() -> &'static Option<Zeroizing<Vec<u8>>> {
    SIGNING_KEY.get_or_init(|| {
        match std::env::var("TALOS_WORKFLOW_SIGNING_KEY") {
            Ok(k) if !k.is_empty() => {
                // Decode as hex for consistency with WORKER_SHARED_KEY and
                // TALOS_MASTER_KEY, which are both hex-encoded 32-byte keys.
                // Reject raw-string keys to avoid weak/short signing material.
                let trimmed = k.trim();
                match hex::decode(trimmed) {
                    Ok(key_bytes) if key_bytes.len() >= 32 => {
                        tracing::info!(
                            "Workflow definition signing enabled (key: {} bytes)",
                            key_bytes.len()
                        );
                        Some(Zeroizing::new(key_bytes))
                    }
                    Ok(key_bytes) => {
                        // L-12: SET-but-too-short. In strict mode, panic
                        // so the operator notices the misconfiguration
                        // immediately rather than silently shipping with
                        // signing off.
                        if strict_mode() {
                            panic!(
                                "TALOS_WORKFLOW_SIGNING_KEY is too short ({} bytes, minimum 32) \
                                 and TALOS_WORKFLOW_SIGNING_STRICT=true. \
                                 Generate with: openssl rand -hex 32",
                                key_bytes.len()
                            );
                        }
                        tracing::error!(
                            "TALOS_WORKFLOW_SIGNING_KEY is too short ({} bytes, minimum 32). \
                             Workflow signing disabled. Generate with: openssl rand -hex 32",
                            key_bytes.len()
                        );
                        None
                    }
                    Err(e) => {
                        // L-12: SET-but-not-hex. Same strict-mode handling.
                        if strict_mode() {
                            panic!(
                                "TALOS_WORKFLOW_SIGNING_KEY is not valid hex ({e}) and \
                                 TALOS_WORKFLOW_SIGNING_STRICT=true. \
                                 Generate with: openssl rand -hex 32"
                            );
                        }
                        tracing::error!(
                            "TALOS_WORKFLOW_SIGNING_KEY is not valid hex: {e}. \
                             Workflow signing disabled. Generate with: openssl rand -hex 32"
                        );
                        None
                    }
                }
            }
            _ => {
                // env not set — disable path is the documented "off" case
                // and is expected during dev. NOT affected by strict mode.
                tracing::info!(
                    "TALOS_WORKFLOW_SIGNING_KEY not set — workflow definitions will not be signed"
                );
                None
            }
        }
    })
}

/// Compute SHA-256 hash of a graph_json string.
pub fn hash_graph(graph_json: &str) -> String {
    let digest = Sha256::digest(graph_json.as_bytes());
    hex::encode(digest)
}

/// Sign a graph hash using HMAC-SHA256. Returns None if no signing key is configured.
pub fn sign_graph_hash(graph_hash: &str) -> Option<String> {
    let key = signing_key().as_ref()?;
    use hmac::{Hmac, Mac};
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_slice()).ok()?;
    mac.update(graph_hash.as_bytes());
    Some(hex::encode(mac.finalize().into_bytes()))
}

/// Verify a graph signature.
///
/// Returns:
///   * `None` — signing key is NOT configured (i.e. `TALOS_WORKFLOW_SIGNING_KEY`
///     unset). Caller may decide to accept or reject based on their policy.
///   * `Some(true)` — signing key configured AND signature is valid.
///   * `Some(false)` — signing key configured AND signature is invalid.
///
/// MCP-498: previously a malformed-hex `signature` argument collapsed to
/// `None` via `hex::decode(...).ok()?`, semantically conflating "signing
/// not configured" with "garbage signature input". A defensive caller
/// that reads `None` as "signing disabled — accept anyway" would then
/// accept a garbage signature on a strict-signing system. Treat any
/// failure to parse the signature when a key IS configured as
/// verification failed (`Some(false)`); the only `None` path is the
/// genuinely-no-key case.
pub fn verify_graph_signature(graph_hash: &str, signature: &str) -> Option<bool> {
    let key = signing_key().as_ref()?;
    use hmac::{Hmac, Mac};
    let mut mac = match Hmac::<Sha256>::new_from_slice(key.as_slice()) {
        Ok(m) => m,
        // Hmac::new_from_slice on a length-validated key shouldn't fail;
        // if it ever does, treat as verification-failed rather than
        // pretending signing is disabled.
        Err(_) => return Some(false),
    };
    mac.update(graph_hash.as_bytes());
    let sig_bytes = match hex::decode(signature) {
        Ok(b) => b,
        Err(_) => return Some(false),
    };
    Some(mac.verify_slice(&sig_bytes).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_deterministic() {
        let h1 = hash_graph("{\"nodes\": [], \"edges\": []}");
        let h2 = hash_graph("{\"nodes\": [], \"edges\": []}");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 hex
    }

    #[test]
    fn hash_changes_with_content() {
        let h1 = hash_graph("{\"nodes\": [1]}");
        let h2 = hash_graph("{\"nodes\": [2]}");
        assert_ne!(h1, h2);
    }

    /// MCP-498: verify the malformed-hex path. We can't reliably toggle
    /// the global signing key in a unit test (OnceLock is process-scoped
    /// and other tests in the workspace may have observed the unset
    /// state), so we exercise the function and assert one of two
    /// allowed outcomes:
    ///   1. Key configured (`Some(_)`) → malformed hex MUST return
    ///      `Some(false)`, never `None`.
    ///   2. Key not configured (`None`) → both valid and malformed
    ///      hex return `None`. We can't differentiate further.
    /// The point of the regression is that case 1's `Some(false)`
    /// shape is preserved.
    #[test]
    fn verify_does_not_swallow_malformed_hex_as_not_configured() {
        let hash = hash_graph("{}");
        let malformed = "not-hex-zzzz!!!";
        // Probe with a known-valid hex (not the right signature) to
        // detect which key-state we're in.
        let probe = verify_graph_signature(&hash, "00");
        match probe {
            Some(_) => {
                // Signing key is configured. Malformed hex MUST be
                // Some(false), not None.
                let r = verify_graph_signature(&hash, malformed);
                assert_eq!(
                    r,
                    Some(false),
                    "malformed-hex signature with key configured must be Some(false), got {:?}",
                    r
                );
            }
            None => {
                // Signing not configured. Both inputs return None.
                let r = verify_graph_signature(&hash, malformed);
                assert_eq!(r, None);
            }
        }
    }
}
