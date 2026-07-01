//! Pub/Sub push-JWT verification for the Gmail integration.
//!
//! # Threat model
//!
//! The Gmail watch API dispatches mailbox-change notifications through
//! Google Cloud Pub/Sub. When we configure our subscription in "push"
//! mode with `--push-auth-service-account=...`, every push arrives
//! with an `Authorization: Bearer <jwt>` header. The JWT is signed by
//! Google (RS256) against their rotating OIDC keys published at
//! `https://www.googleapis.com/oauth2/v3/certs`.
//!
//! Without verifying the JWT, our `/api/gmail/pubsub` endpoint would
//! be a public unauthenticated dispatcher — any attacker who knows
//! our URL could publish arbitrary `(emailAddress, historyId)`
//! payloads and make us fetch + dispatch mailbox history for any
//! user we have an integration with.
//!
//! This module:
//!
//!   1. Fetches + caches Google's JWKs, refreshing when a token's
//!      `kid` is unknown or once an hour (whichever comes first).
//!      Single-flight refresh prevents a thundering herd when a
//!      flurry of pushes arrives after a key rotation.
//!   2. Verifies the token's signature, expiry, audience, and
//!      issuer-email claims.
//!   3. Returns typed claims so the caller can trust `email_address`
//!      / `message_id` without re-parsing.
//!
//! # What we validate, field by field
//!
//! | Claim           | Expected                                                |
//! |-----------------|---------------------------------------------------------|
//! | Signature       | RS256 against Google's current public key for the `kid` |
//! | `iss`           | `https://accounts.google.com`                           |
//! | `email`         | `<operator-configured>` — typically `gmail-api-push@…`  |
//! | `email_verified`| `true`                                                  |
//! | `aud`           | operator-configured `GMAIL_PUBSUB_AUDIENCE`             |
//! | `exp` / `iat`   | jsonwebtoken's default leeway handles mild clock skew   |
//!
//! # Rotation + refresh strategy
//!
//! Google rotates RSA keys roughly daily. Each key has a `kid` which
//! appears in the JWT header. Our cache is keyed by `kid`, so a
//! post-rotation token with a new `kid` triggers a single refresh
//! (the first caller wins the `Mutex`, everyone else waits). If a
//! fetch fails we return the cached keys and log — we'd rather serve
//! occasionally-stale pushes than 500 every delivery for the hour
//! it takes Google's CDN to heal.

use arc_swap::ArcSwap;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// Google's OIDC issuer. MUST match `iss` on valid Pub/Sub push JWTs.
pub const GOOGLE_ISSUER: &str = "https://accounts.google.com";

/// Where Google publishes its RSA public keys. Not operator-configurable
/// — this is a fixed, versioned URL.
const GOOGLE_JWK_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";

/// Minimum interval between forced JWK refreshes. Google rotates
/// roughly once a day; 1h is generous. A token with an unknown `kid`
/// forces an immediate refresh regardless of this TTL.
const JWK_REFRESH_INTERVAL_SECS: i64 = 3600;

/// On fetch failure we want to retry sooner than the normal TTL so
/// we pick up Google's CDN heal quickly — but not so fast we hammer
/// their endpoint once per push during a sustained outage. 60 s is
/// a reasonable middle ground; a fresh `kid` from a rotation can
/// wait one minute without the whole flow breaking.
const JWK_REFRESH_BACKOFF_SECS: i64 = 60;

/// HTTP timeout for the JWK fetch. Short enough that a stuck call
/// doesn't pile up under push load; long enough to clear the
/// occasional slow CDN hop.
const JWK_FETCH_TIMEOUT_SECS: u64 = 5;

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("malformed JWT header")]
    MalformedHeader,
    #[error("unsupported algorithm (expected RS256)")]
    WrongAlgorithm,
    #[error("missing key id (kid) in JWT header")]
    MissingKid,
    #[error("unknown signing key — Google may have rotated")]
    UnknownKey,
    #[error("signature / claim verification failed: {0}")]
    Invalid(String),
    #[error("email claim did not match expected service account")]
    WrongEmail,
    #[error("email_verified claim was not true")]
    EmailNotVerified,
    #[error("could not fetch Google JWKs: {0}")]
    JwkFetchFailed(String),
}

/// Typed claims extracted from a valid push JWT. The caller uses
/// these (not the raw JWT) so the verification contract is enforced
/// in one place.
#[derive(Debug, Clone, Deserialize)]
pub struct PubsubClaims {
    #[serde(rename = "iss")]
    pub issuer: String,
    pub email: String,
    #[serde(default)]
    pub email_verified: bool,
    #[serde(rename = "aud")]
    pub audience: String,
    #[serde(rename = "exp")]
    pub expires_at: i64,
    #[serde(rename = "iat")]
    pub issued_at: i64,
}

/// Individual JWK as returned by Google's certs endpoint. We only
/// decode the fields we need; everything else is ignored.
#[derive(Debug, Deserialize)]
struct Jwk {
    kid: String,
    #[serde(rename = "kty")]
    _kty: String,
    n: String,
    e: String,
}

#[derive(Debug, Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

pub struct PubsubJwtVerifier {
    /// Keys indexed by `kid`. Hot-swapped atomically on refresh so
    /// readers never see a half-built map.
    keys: ArcSwap<HashMap<String, DecodingKey>>,
    /// Unix-secs timestamp of the last successful refresh.
    last_refreshed: AtomicI64,
    /// Unix-secs timestamp until which we skip `fetch_jwks` on
    /// unknown-kid requests. Set when a fetch fails; cleared (by
    /// being overrun) on the next successful fetch.
    ///
    /// Separate from `last_refreshed` because the two serve
    /// different purposes: `last_refreshed` drives the 1-hour TTL,
    /// `backoff_until` prevents hammering Google during an outage
    /// regardless of whether cached keys are stale. Without this a
    /// sustained JWKs outage turns every push into a 5s timeout.
    backoff_until: AtomicI64,
    /// Single-flight guard: only one task fetches Google's JWKs at a
    /// time, even under a flood of concurrent pushes with unknown kids.
    refresh_lock: Mutex<()>,
    http: reqwest::Client,
    /// Audience value configured on the operator's Pub/Sub
    /// subscription (`--push-auth-token-audience=...`). Typically
    /// the webhook URL itself.
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
            keys: ArcSwap::new(Arc::new(HashMap::new())),
            last_refreshed: AtomicI64::new(0),
            backoff_until: AtomicI64::new(0),
            refresh_lock: Mutex::new(()),
            // MCP-534: defence-in-depth even though this client only
            // fetches Google's public JWK set (no Bearer token to leak).
            // Disable redirects so a future code change that adds an
            // auth header here doesn't reopen the credential-leak
            // surface; replace the `unwrap_or_else(Client::new)`
            // anti-pattern with a loud `.expect()` per the convention.
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(JWK_FETCH_TIMEOUT_SECS))
                .connect_timeout(Duration::from_secs(2))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("PubsubJwtVerifier: failed to build hardened reqwest client"),
            expected_audience,
            expected_email,
        }
    }

    /// Inject a pre-populated key set. Used by unit tests against a
    /// locally-generated RSA keypair; production code never calls
    /// this. Crate-visible so integration tests can also exercise
    /// the verifier without hitting the network.
    #[cfg(test)]
    pub(crate) fn with_keys_for_test(
        expected_audience: String,
        expected_email: String,
        keys: HashMap<String, DecodingKey>,
    ) -> Self {
        Self {
            keys: ArcSwap::new(Arc::new(keys)),
            last_refreshed: AtomicI64::new(i64::MAX),
            backoff_until: AtomicI64::new(0),
            refresh_lock: Mutex::new(()),
            http: reqwest::Client::new(),
            expected_audience,
            expected_email,
        }
    }

    /// Verify a Pub/Sub push JWT end-to-end. Returns the typed claims
    /// on success; every other return path is an `Err` a caller
    /// should map to `401 Unauthorized` at the HTTP boundary.
    pub async fn verify(&self, token: &str) -> Result<PubsubClaims, VerifyError> {
        // 1. Decode header unverified so we can look up the right key.
        let header = decode_header(token).map_err(|_| VerifyError::MalformedHeader)?;
        if header.alg != Algorithm::RS256 {
            return Err(VerifyError::WrongAlgorithm);
        }
        let kid = header.kid.ok_or(VerifyError::MissingKid)?;

        // 2. Find the key. If unknown or our cache is old, refresh
        //    Google's JWKs and try once more.
        let key = match self.find_key(&kid) {
            Some(k) => k,
            None => {
                self.refresh_if_stale_or_unknown(&kid).await?;
                self.find_key(&kid).ok_or(VerifyError::UnknownKey)?
            }
        };

        // 3. Verify signature + standard claims in one shot. Validation
        //    checks iss, aud, exp automatically when configured below.
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[&self.expected_audience]);
        validation.set_issuer(&[GOOGLE_ISSUER]);
        validation.leeway = 60; // tolerate ≤60s clock skew

        let data = decode::<PubsubClaims>(token, &key, &validation)
            .map_err(|e| VerifyError::Invalid(e.to_string()))?;
        let claims = data.claims;

        // 4. Non-standard claims — the jsonwebtoken crate doesn't
        //    know about `email` / `email_verified`, so enforce
        //    them ourselves. Prevents an attacker with a DIFFERENT
        //    Google-signed service-account token (e.g. a developer's
        //    own SA) from delivering pushes.
        if claims.email != self.expected_email {
            return Err(VerifyError::WrongEmail);
        }
        if !claims.email_verified {
            return Err(VerifyError::EmailNotVerified);
        }

        Ok(claims)
    }

    fn find_key(&self, kid: &str) -> Option<DecodingKey> {
        self.keys.load().get(kid).cloned()
    }

    /// Refresh JWKs if either (a) the given `kid` isn't cached, or
    /// (b) it's been longer than the refresh interval since we last
    /// fetched. Serialized by a Mutex so N concurrent pushes with
    /// unknown kids result in ONE outbound fetch, not N.
    ///
    /// Skipped during an active backoff window — the caller ends up
    /// with `UnknownKey` if the kid isn't cached, which maps to 401
    /// at the HTTP boundary. Prevents sustained Google-side outages
    /// from turning every push into a 5 s timeout.
    async fn refresh_if_stale_or_unknown(&self, kid: &str) -> Result<(), VerifyError> {
        let now = chrono::Utc::now().timestamp();
        let last = self.last_refreshed.load(Ordering::Relaxed);
        let stale = now.saturating_sub(last) >= JWK_REFRESH_INTERVAL_SECS;

        if !stale && self.find_key(kid).is_some() {
            return Ok(());
        }

        // Respect active backoff. Returning Ok here lets the caller
        // fall through to the "UnknownKey" branch on its own lookup
        // — we don't want to propagate JwkFetchFailed twice, and
        // cached keys may still verify some in-flight tokens.
        if now < self.backoff_until.load(Ordering::Relaxed) {
            return Ok(());
        }

        let _guard = self.refresh_lock.lock().await;
        // Re-check after acquiring the lock — another caller may
        // have refreshed (or set the backoff) while we were waiting.
        let now = chrono::Utc::now().timestamp();
        if self.find_key(kid).is_some()
            && now.saturating_sub(self.last_refreshed.load(Ordering::Relaxed))
                < JWK_REFRESH_INTERVAL_SECS
        {
            return Ok(());
        }
        if now < self.backoff_until.load(Ordering::Relaxed) {
            return Ok(());
        }

        self.fetch_jwks().await
    }

    /// Fetch JWKs from Google, parse, hot-swap. On failure we keep
    /// the existing cache + record a short-lived failure timestamp
    /// so the next push doesn't immediately re-fetch. Without the
    /// backoff, a sustained Google outage would turn every push
    /// into a 5-second timeout + JwkFetchFailed response.
    async fn fetch_jwks(&self) -> Result<(), VerifyError> {
        let result = async {
            let resp = self
                .http
                .get(GOOGLE_JWK_URL)
                .send()
                .await
                .map_err(|e| VerifyError::JwkFetchFailed(e.to_string()))?;
            if !resp.status().is_success() {
                return Err(VerifyError::JwkFetchFailed(format!(
                    "unexpected status {}",
                    resp.status()
                )));
            }
            let set: JwkSet = talos_http_body::read_json_capped(resp)
                .await
                .map_err(|e| VerifyError::JwkFetchFailed(format!("parse: {e}")))?;

            let mut map: HashMap<String, DecodingKey> = HashMap::with_capacity(set.keys.len());
            for jwk in set.keys {
                // n / e are base64url-encoded big-endian integers in JWK format.
                match DecodingKey::from_rsa_components(&jwk.n, &jwk.e) {
                    Ok(dk) => {
                        map.insert(jwk.kid, dk);
                    }
                    Err(e) => {
                        tracing::warn!(
                            kid = %jwk.kid,
                            error = %e,
                            "skipping malformed JWK"
                        );
                    }
                }
            }
            self.keys.store(Arc::new(map));
            Ok(())
        }
        .await;

        let now = chrono::Utc::now().timestamp();
        match &result {
            Ok(_) => {
                self.last_refreshed.store(now, Ordering::Relaxed);
                // Any earlier backoff is implicitly cleared — a
                // time in the past is !< now.
            }
            Err(e) => {
                // Stamp the explicit backoff deadline. The staleness
                // check alone isn't enough: unknown-kid requests
                // always fall through to `fetch_jwks`, so without
                // this marker every push would still hammer Google.
                self.backoff_until
                    .store(now + JWK_REFRESH_BACKOFF_SECS, Ordering::Relaxed);
                tracing::warn!(
                    error = %e,
                    backoff_secs = JWK_REFRESH_BACKOFF_SECS,
                    "JWK refresh failed; backing off"
                );
            }
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Shape of a Pub/Sub push request. Not part of JWT verification per se —
// lives here so every consumer of the verifier gets a single canonical
// parser for the envelope.
// ---------------------------------------------------------------------------

/// Top-level Pub/Sub push envelope. Pub/Sub wraps each message like
/// this:
///
/// ```text
/// POST /api/gmail/pubsub
/// Authorization: Bearer <jwt>
/// Content-Type: application/json
///
/// {
///   "message": {
///     "data": "<base64-encoded payload>",
///     "messageId": "...",
///     "publishTime": "..."
///   },
///   "subscription": "projects/.../subscriptions/..."
/// }
/// ```
#[derive(Debug, Deserialize)]
pub struct PubsubPushEnvelope {
    pub message: PubsubPushMessage,
    pub subscription: String,
}

#[derive(Debug, Deserialize)]
pub struct PubsubPushMessage {
    /// Base64-encoded JSON. For Gmail specifically, the decoded form is
    /// `{ "emailAddress": "…", "historyId": "…" }`.
    pub data: String,
    #[serde(rename = "messageId")]
    pub message_id: String,
    #[serde(default)]
    #[serde(rename = "publishTime")]
    pub publish_time: Option<String>,
}

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
    use jsonwebtoken::{encode, EncodingKey, Header};
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::pkcs8::EncodePublicKey;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use serde_json::json;

    /// Build a keypair + the matching `DecodingKey`, returning both
    /// ready to use.
    fn keypair() -> (EncodingKey, DecodingKey, String) {
        // 2048-bit RSA; deterministic random isn't needed for tests.
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
    async fn happy_path_returns_claims() {
        let (enc, dec, kid) = keypair();
        let v = make_verifier(dec, &kid);
        let token = sign(
            &enc,
            &kid,
            json!({
                "iss": GOOGLE_ISSUER,
                "email": "gmail-api-push@system.gserviceaccount.com",
                "email_verified": true,
                "aud": "https://example/webhook",
                "iat": now(),
                "exp": now() + 300,
            }),
        );
        let claims = v.verify(&token).await.expect("should verify");
        assert_eq!(claims.email, "gmail-api-push@system.gserviceaccount.com");
        assert_eq!(claims.audience, "https://example/webhook");
    }

    #[tokio::test]
    async fn wrong_audience_rejected() {
        let (enc, dec, kid) = keypair();
        let v = make_verifier(dec, &kid);
        let token = sign(
            &enc,
            &kid,
            json!({
                "iss": GOOGLE_ISSUER,
                "email": "gmail-api-push@system.gserviceaccount.com",
                "email_verified": true,
                "aud": "https://WRONG.example/webhook",
                "iat": now(),
                "exp": now() + 300,
            }),
        );
        match v.verify(&token).await.expect_err("must reject") {
            VerifyError::Invalid(_) => {} // audience mismatch surfaces here
            e => panic!("expected Invalid, got {e:?}"),
        }
    }

    #[tokio::test]
    async fn wrong_issuer_rejected() {
        let (enc, dec, kid) = keypair();
        let v = make_verifier(dec, &kid);
        let token = sign(
            &enc,
            &kid,
            json!({
                "iss": "https://evil.com",
                "email": "gmail-api-push@system.gserviceaccount.com",
                "email_verified": true,
                "aud": "https://example/webhook",
                "iat": now(),
                "exp": now() + 300,
            }),
        );
        assert!(v.verify(&token).await.is_err());
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

    #[tokio::test]
    async fn expired_rejected() {
        let (enc, dec, kid) = keypair();
        let v = make_verifier(dec, &kid);
        let token = sign(
            &enc,
            &kid,
            json!({
                "iss": GOOGLE_ISSUER,
                "email": "gmail-api-push@system.gserviceaccount.com",
                "email_verified": true,
                "aud": "https://example/webhook",
                "iat": now() - 3600,
                "exp": now() - 600, // 10 min ago
            }),
        );
        assert!(v.verify(&token).await.is_err());
    }

    #[tokio::test]
    async fn backoff_window_suppresses_refetch_on_unknown_kid() {
        // After a fetch failure sets `backoff_until` in the future,
        // a subsequent unknown-kid request MUST return UnknownKey
        // without triggering another fetch. Regression guard for a
        // bug where the backoff marker existed but the refresh
        // path ignored it, causing every push during an outage to
        // repeat the 5 s HTTP timeout.
        let (enc, dec, kid) = keypair();
        let v = make_verifier(dec, &kid);
        // Simulate a past failure: backoff is still active.
        let now = chrono::Utc::now().timestamp();
        v.backoff_until.store(now + 60, Ordering::Relaxed);
        // Force last_refreshed into the past so the staleness check
        // also says "fetch!" — we want to confirm the backoff, not
        // the cache hit, is what short-circuits.
        v.last_refreshed.store(0, Ordering::Relaxed);
        // Token references a kid the cache has never seen.
        let token = sign(
            &enc,
            "never-seen-kid",
            json!({
                "iss": GOOGLE_ISSUER,
                "email": "gmail-api-push@system.gserviceaccount.com",
                "email_verified": true,
                "aud": "https://example/webhook",
                "iat": now,
                "exp": now + 300,
            }),
        );
        let err = v.verify(&token).await.expect_err("must reject");
        // UnknownKey, not JwkFetchFailed — proves we didn't try to
        // fetch during the backoff window.
        assert!(
            matches!(err, VerifyError::UnknownKey),
            "expected UnknownKey during backoff, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn unknown_kid_rejected_when_network_unavailable() {
        let (enc, dec, _kid) = keypair();
        // Register the key under a DIFFERENT kid; the token will
        // reference an unknown kid. Since the test verifier has no
        // live JWK URL, refresh is effectively a no-op and we land
        // in UnknownKey.
        let v = make_verifier(dec, "another-kid");
        // Push last_refreshed back so a refresh is attempted — which
        // will fail in tests because the HTTP client won't reach
        // Google from this process.
        v.last_refreshed.store(0, Ordering::Relaxed);
        let token = sign(
            &enc,
            "token-references-this-kid",
            json!({
                "iss": GOOGLE_ISSUER,
                "email": "gmail-api-push@system.gserviceaccount.com",
                "email_verified": true,
                "aud": "https://example/webhook",
                "iat": now(),
                "exp": now() + 300,
            }),
        );
        let err = v.verify(&token).await.expect_err("must reject");
        assert!(
            matches!(
                err,
                VerifyError::UnknownKey | VerifyError::JwkFetchFailed(_)
            ),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn missing_kid_rejected() {
        let (enc, dec, kid) = keypair();
        let v = make_verifier(dec, &kid);
        // Manually craft a token without kid.
        let header = Header::new(Algorithm::RS256); // no kid
        let token = encode(
            &header,
            &json!({
                "iss": GOOGLE_ISSUER,
                "email": "gmail-api-push@system.gserviceaccount.com",
                "email_verified": true,
                "aud": "https://example/webhook",
                "iat": now(),
                "exp": now() + 300,
            }),
            &enc,
        )
        .unwrap();
        assert!(matches!(
            v.verify(&token).await.expect_err("must reject"),
            VerifyError::MissingKid
        ));
    }

    #[tokio::test]
    async fn hs256_algorithm_rejected() {
        // Even if someone managed to produce a valid HS256 JWT with
        // the right claims (e.g. by leaking our HMAC key), we must
        // refuse to treat it as a Pub/Sub push. RS256 only.
        let enc = EncodingKey::from_secret(b"leaked-hmac-key");
        let header = Header::new(Algorithm::HS256);
        // No kid needed for HS256; we'll reject before key lookup.
        let token = encode(
            &header,
            &json!({
                "iss": GOOGLE_ISSUER,
                "email": "gmail-api-push@system.gserviceaccount.com",
                "email_verified": true,
                "aud": "https://example/webhook",
                "iat": now(),
                "exp": now() + 300,
            }),
            &enc,
        )
        .unwrap();
        let (_, dec, kid) = keypair();
        let v = make_verifier(dec, &kid);
        assert!(matches!(
            v.verify(&token).await.expect_err("must reject"),
            VerifyError::WrongAlgorithm
        ));
    }

    #[tokio::test]
    async fn none_algorithm_rejected_upstream() {
        // `alg: "none"` tokens are a classic JWT attack. The
        // `jsonwebtoken` crate refuses to decode_header these, so we
        // stop at MalformedHeader — good.
        let (_, dec, kid) = keypair();
        let v = make_verifier(dec, &kid);
        // Construct a fake "alg: none" token manually.
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let header_b64 = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let payload_b64 = URL_SAFE_NO_PAD.encode(br#"{"iss":"https://accounts.google.com"}"#);
        let token = format!("{}.{}.", header_b64, payload_b64);
        let err = v.verify(&token).await.expect_err("must reject");
        assert!(
            matches!(
                err,
                VerifyError::MalformedHeader | VerifyError::WrongAlgorithm
            ),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn tampered_signature_rejected() {
        let (enc, dec, kid) = keypair();
        let v = make_verifier(dec, &kid);
        let token = sign(
            &enc,
            &kid,
            json!({
                "iss": GOOGLE_ISSUER,
                "email": "gmail-api-push@system.gserviceaccount.com",
                "email_verified": true,
                "aud": "https://example/webhook",
                "iat": now(),
                "exp": now() + 300,
            }),
        );
        // Flip a bit in the signature segment.
        let mut bytes = token.into_bytes();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let tampered = String::from_utf8(bytes).unwrap();
        assert!(v.verify(&tampered).await.is_err());
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
