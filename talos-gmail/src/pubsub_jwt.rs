//! Pub/Sub push-JWT verification for the Gmail integration.
//!
//! The JWT-verification kernel (JWK cache + single-flight refresh +
//! backoff atomic + RS256/iss/aud/exp validation) was lifted into
//! `talos_integration_helpers::google_jwt` (2026-07) so Gmail and
//! Google Cloud share ONE verifier. This file is now a thin,
//! Gmail-specific wrapper:
//!
//!   * [`PubsubJwtVerifier`] pins the operator-configured `audience` +
//!     service-account `email` and composes
//!     [`GoogleOidcVerifier::verify_signed`] +
//!     [`GoogleOidcClaims::require_service_account`] behind the
//!     UNCHANGED `new(audience, email)` / `verify(token)` API the
//!     controller wiring already depends on.
//!   * [`GmailNotification`] + [`decode_gmail_notification`] stay here —
//!     the `{ emailAddress, historyId }` payload is Gmail-specific.
//!
//! The push envelope types (`PubsubPushEnvelope` / `PubsubPushMessage`)
//! and `GOOGLE_ISSUER` are re-exported from the kernel so existing
//! `use super::pubsub_jwt::...` paths keep resolving.

use serde::{Deserialize, Serialize};
use talos_integration_helpers::google_jwt::GoogleOidcVerifier;

// Re-export the shared kernel types so downstream `use
// super::pubsub_jwt::{...}` imports (handlers.rs) keep resolving
// unchanged after the lift.
pub use talos_integration_helpers::google_jwt::{
    GoogleOidcClaims, PubsubPushEnvelope, PubsubPushMessage, VerifyError, GOOGLE_ISSUER,
};

/// Gmail's Pub/Sub push-JWT verifier. Holds the shared
/// [`GoogleOidcVerifier`] plus the operator-configured expectations
/// (audience + the `gmail-api-push@system.gserviceaccount.com`
/// service-account email). Public API is byte-for-byte unchanged from
/// the pre-lift implementation so `controller/src/main.rs` needs no
/// changes.
pub struct PubsubJwtVerifier {
    inner: GoogleOidcVerifier,
    /// Audience value configured on the operator's Pub/Sub
    /// subscription (`--push-auth-token-audience=...`). Typically the
    /// webhook URL itself.
    expected_audience: String,
    /// Email of the service account configured with the subscription.
    /// For Gmail push this is `gmail-api-push@system.gserviceaccount.com`
    /// UNLESS the operator overrides it.
    expected_email: String,
}

impl PubsubJwtVerifier {
    /// Build a verifier. Doesn't fetch keys at construction — first
    /// use triggers a refresh, so startup isn't blocked on Google's
    /// CDN.
    pub fn new(expected_audience: String, expected_email: String) -> Self {
        Self {
            inner: GoogleOidcVerifier::new(),
            expected_audience,
            expected_email,
        }
    }

    /// Inject a pre-populated key set for tests. Wraps the kernel's
    /// `with_keys_for_test` (enabled cross-crate via the helpers
    /// `test-util` feature in dev-dependencies).
    #[cfg(test)]
    pub(crate) fn with_keys_for_test(
        expected_audience: String,
        expected_email: String,
        keys: std::collections::HashMap<String, jsonwebtoken::DecodingKey>,
    ) -> Self {
        Self {
            inner: GoogleOidcVerifier::with_keys_for_test(keys),
            expected_audience,
            expected_email,
        }
    }

    /// Verify a Pub/Sub push JWT end-to-end: signature + standard
    /// claims against the pinned audience, THEN the Gmail service
    /// account. Returns the typed claims on success; every other
    /// return path is an `Err` a caller should map to `401
    /// Unauthorized` at the HTTP boundary.
    pub async fn verify(&self, token: &str) -> Result<GoogleOidcClaims, VerifyError> {
        let claims = self
            .inner
            .verify_signed(token, &self.expected_audience)
            .await?;
        claims.require_service_account(&self.expected_email)?;
        Ok(claims)
    }
}

// ---------------------------------------------------------------------------
// Gmail-specific inner payload (decoded from the push envelope's base64
// `data`). Stays Gmail-side — the envelope types are shared, the payload
// shape is not.
// ---------------------------------------------------------------------------

/// Gmail-specific payload decoded from `PubsubPushMessage::data`.
#[derive(Debug, Deserialize, Serialize)]
pub struct GmailNotification {
    #[serde(rename = "emailAddress")]
    pub email_address: String,
    /// Google returns history_id as either a string or number across
    /// different code paths; deserialize as untyped then coerce.
    #[serde(rename = "historyId", deserialize_with = "deserialize_string_or_u64")]
    pub history_id: u64,
}

/// Accept either `"12345"` or `12345` for the historyId field — Google
/// inconsistently stringifies it across client libraries.
fn deserialize_string_or_u64<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    use serde::de::Error;
    let v = serde_json::Value::deserialize(d)?;
    match v {
        serde_json::Value::String(s) => s.parse::<u64>().map_err(D::Error::custom),
        serde_json::Value::Number(n) => n
            .as_u64()
            .ok_or_else(|| D::Error::custom("historyId not a u64")),
        _ => Err(D::Error::custom("historyId must be string or number")),
    }
}

/// Convenience: decode the inner Gmail notification from an
/// already-verified envelope. Base64 + JSON; errors are opaque to
/// avoid telling an attacker which step of the decode failed.
pub fn decode_gmail_notification(
    env: &PubsubPushEnvelope,
) -> Result<GmailNotification, &'static str> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let decoded = STANDARD
        .decode(env.message.data.as_bytes())
        .map_err(|_| "invalid push payload")?;
    serde_json::from_slice::<GmailNotification>(&decoded).map_err(|_| "invalid push payload")
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header};
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::pkcs8::EncodePublicKey;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use serde_json::json;
    use std::collections::HashMap;

    // The 12 core rejection paths (signature / aud / iss / expired /
    // backoff / unknown-kid / missing-kid / HS256 / alg-none / tampered /
    // require_service_account happy+reject) live in
    // `talos_integration_helpers::google_jwt::tests`. Here we cover the
    // GMAIL-WRAPPER-specific paths: the service-account composition
    // (wrong email / unverified email surfaced through `verify()`) and
    // the Gmail notification envelope decode.

    fn keypair() -> (EncodingKey, DecodingKey, String) {
        let priv_key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let pub_key = RsaPublicKey::from(&priv_key);
        let priv_pem = priv_key.to_pkcs1_pem(Default::default()).unwrap();
        let pub_pem = pub_key.to_public_key_pem(Default::default()).unwrap();
        let enc = EncodingKey::from_rsa_pem(priv_pem.as_bytes()).unwrap();
        let dec = DecodingKey::from_rsa_pem(pub_pem.as_bytes()).unwrap();
        (enc, dec, "test-kid-1".to_string())
    }

    fn make_verifier(dec: DecodingKey, kid: &str) -> PubsubJwtVerifier {
        let mut map = HashMap::new();
        map.insert(kid.to_string(), dec);
        PubsubJwtVerifier::with_keys_for_test(
            "https://example/webhook".into(),
            "gmail-api-push@system.gserviceaccount.com".into(),
            map,
        )
    }

    fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }

    fn sign(enc: &EncodingKey, kid: &str, claims: serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        encode(&header, &claims, enc).unwrap()
    }

    #[tokio::test]
    async fn wrong_email_rejected() {
        let (enc, dec, kid) = keypair();
        let v = make_verifier(dec, &kid);
        let token = sign(
            &enc,
            &kid,
            json!({
                "iss": GOOGLE_ISSUER,
                "email": "another-service@system.gserviceaccount.com",
                "email_verified": true,
                "aud": "https://example/webhook",
                "iat": now(),
                "exp": now() + 300,
            }),
        );
        assert!(matches!(
            v.verify(&token).await.expect_err("must reject"),
            VerifyError::WrongEmail
        ));
    }

    #[tokio::test]
    async fn email_not_verified_rejected() {
        let (enc, dec, kid) = keypair();
        let v = make_verifier(dec, &kid);
        let token = sign(
            &enc,
            &kid,
            json!({
                "iss": GOOGLE_ISSUER,
                "email": "gmail-api-push@system.gserviceaccount.com",
                "email_verified": false,
                "aud": "https://example/webhook",
                "iat": now(),
                "exp": now() + 300,
            }),
        );
        assert!(matches!(
            v.verify(&token).await.expect_err("must reject"),
            VerifyError::EmailNotVerified
        ));
    }

    #[test]
    fn decode_gmail_notification_handles_string_history_id() {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        let inner = r#"{"emailAddress":"a@b.com","historyId":"12345"}"#;
        let env = PubsubPushEnvelope {
            message: PubsubPushMessage {
                data: STANDARD.encode(inner),
                message_id: "m1".into(),
                publish_time: None,
            },
            subscription: "sub".into(),
        };
        let n = decode_gmail_notification(&env).unwrap();
        assert_eq!(n.email_address, "a@b.com");
        assert_eq!(n.history_id, 12345);
    }

    #[test]
    fn decode_gmail_notification_handles_number_history_id() {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        let inner = r#"{"emailAddress":"a@b.com","historyId":999}"#;
        let env = PubsubPushEnvelope {
            message: PubsubPushMessage {
                data: STANDARD.encode(inner),
                message_id: "m1".into(),
                publish_time: None,
            },
            subscription: "sub".into(),
        };
        let n = decode_gmail_notification(&env).unwrap();
        assert_eq!(n.history_id, 999);
    }

    #[test]
    fn decode_gmail_notification_rejects_garbage() {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        let env = PubsubPushEnvelope {
            message: PubsubPushMessage {
                data: STANDARD.encode("not json"),
                message_id: "m1".into(),
                publish_time: None,
            },
            subscription: "sub".into(),
        };
        assert!(decode_gmail_notification(&env).is_err());

        let env2 = PubsubPushEnvelope {
            message: PubsubPushMessage {
                data: "*not*base64*".into(),
                message_id: "m1".into(),
                publish_time: None,
            },
            subscription: "sub".into(),
        };
        assert!(decode_gmail_notification(&env2).is_err());
    }
}
