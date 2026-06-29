//! GitHub App webhook signature verification (RFC 0008 B5).
//!
//! A GitHub App has ONE webhook URL and ONE webhook secret; every installation's
//! events are delivered there, HMAC-signed with that App-level secret. This is
//! the same `X-Hub-Signature-256` scheme Phase A already verifies for per-trigger
//! webhooks (`HMAC-SHA256(secret, raw_body)`, compared constant-time) — B5 just
//! points it at the App webhook secret (`GithubAppConfig::webhook_secret`).
//!
//! Pure + network-free so it's unit-testable; the App-webhook RECEIVER that calls
//! it (extract the header, then route the verified delivery to a workflow by
//! installation/repo) is the remaining wiring.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// Verify a GitHub App webhook delivery.
///
/// * `signature` — the `X-Hub-Signature-256` header value (`"sha256=<hex>"`), or
///   `None` if absent.
/// * `body` — the **raw** request body bytes (GitHub signs the bytes as sent).
/// * `secret` — the App webhook secret (`GITHUB_APP_WEBHOOK_SECRET`).
///
/// Constant-time comparison. **Fails closed** on an empty secret, a missing or
/// malformed signature header, or any HMAC error — never returns `true` by
/// accident.
pub fn verify_app_webhook_signature(signature: Option<&str>, body: &[u8], secret: &str) -> bool {
    // Empty secret would HMAC to a fixed value an attacker could compute — refuse.
    if secret.is_empty() {
        return false;
    }
    let Some(sig) = signature else {
        return false;
    };
    let Some(hash_hex) = sig.strip_prefix("sha256=") else {
        return false;
    };

    let mut mac = match Hmac::<Sha256>::new_from_slice(secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(body);
    let expected = hex::encode(mac.finalize().into_bytes());

    // Constant-time compare of the hex strings (lengths differ → not equal).
    expected.as_bytes().ct_eq(hash_hex.as_bytes()).unwrap_u8() == 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    fn sign(body: &[u8], secret: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body);
        format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
    }

    #[test]
    fn accepts_valid_signature() {
        let body = br#"{"action":"opened"}"#;
        let sig = sign(body, "whsec");
        assert!(verify_app_webhook_signature(Some(&sig), body, "whsec"));
    }

    #[test]
    fn rejects_wrong_secret() {
        let body = br#"{"action":"opened"}"#;
        let sig = sign(body, "whsec");
        assert!(!verify_app_webhook_signature(Some(&sig), body, "different"));
    }

    #[test]
    fn rejects_tampered_body() {
        let body = br#"{"action":"opened"}"#;
        let sig = sign(body, "whsec");
        assert!(!verify_app_webhook_signature(
            Some(&sig),
            br#"{"action":"closed"}"#,
            "whsec"
        ));
    }

    #[test]
    fn rejects_missing_signature() {
        assert!(!verify_app_webhook_signature(None, b"body", "whsec"));
    }

    #[test]
    fn rejects_empty_secret() {
        let body = b"body";
        // Even a signature computed under the empty secret must not pass.
        let sig = sign(body, "");
        assert!(!verify_app_webhook_signature(Some(&sig), body, ""));
    }

    #[test]
    fn rejects_missing_sha256_prefix() {
        let body = b"body";
        let raw_hex = {
            let mut mac = Hmac::<Sha256>::new_from_slice(b"whsec").unwrap();
            mac.update(body);
            hex::encode(mac.finalize().into_bytes())
        };
        // Same hex but without the "sha256=" prefix → rejected.
        assert!(!verify_app_webhook_signature(Some(&raw_hex), body, "whsec"));
    }

    #[test]
    fn rejects_garbage_signature() {
        assert!(!verify_app_webhook_signature(
            Some("sha256=notvalidhex"),
            b"body",
            "whsec"
        ));
        assert!(!verify_app_webhook_signature(
            Some("v0=abc"),
            b"body",
            "whsec"
        ));
    }
}
