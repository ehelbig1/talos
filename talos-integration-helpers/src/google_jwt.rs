//! Google OIDC push-JWT verification — the shared kernel.
//!
//! Lifted from `talos-gmail::pubsub_jwt` (2026-07) so BOTH Gmail's
//! Pub/Sub push receiver AND Google Cloud's Monitoring push receiver
//! verify Google-signed OIDC tokens through one implementation. The
//! gmail-specific wrapper (`talos_gmail::pubsub_jwt::PubsubJwtVerifier`)
//! composes [`GoogleOidcVerifier::verify_signed`] +
//! [`GoogleOidcClaims::require_service_account`] and keeps its
//! `new(audience, email)` / `verify(token)` API byte-for-byte.
//!
//! # Threat model
//!
//! Google Cloud push subscriptions (Pub/Sub push, Monitoring
//! notification channels) POST to our endpoint with an
//! `Authorization: Bearer <jwt>` header when configured with
//! `--push-auth-service-account=...`. The JWT is signed by Google
//! (RS256) against their rotating OIDC keys at
//! `https://www.googleapis.com/oauth2/v3/certs`.
//!
//! Without verifying the JWT, a push endpoint is a public,
//! unauthenticated dispatcher — any attacker who knows the URL could
//! POST arbitrary payloads and make us dispatch work.
//!
//! This module:
//!   1. Fetches + caches Google's JWKs, refreshing when a token's
//!      `kid` is unknown or once an hour (whichever comes first).
//!      Single-flight refresh prevents a thundering herd when a
//!      flurry of pushes arrives after a key rotation.
//!   2. Verifies the token's signature, expiry, audience, and issuer
//!      ([`verify_signed`](GoogleOidcVerifier::verify_signed)).
//!   3. Leaves the non-standard `email` / `email_verified` service-
//!      account check to the caller
//!      ([`require_service_account`](GoogleOidcClaims::require_service_account)),
//!      because the expected service-account email is per-integration
//!      (and even per-watch, for Google Cloud).
//!
//! # What `verify_signed` validates, field by field
//!
//! | Claim           | Expected                                                |
//! |-----------------|---------------------------------------------------------|
//! | Signature       | RS256 against Google's current public key for the `kid` |
//! | `iss`           | `https://accounts.google.com`                           |
//! | `aud`           | operator-configured audience (passed per call)          |
//! | `exp` / `iat`   | jsonwebtoken's default leeway handles mild clock skew   |
//!
//! # Rotation + refresh strategy
//!
//! Google rotates RSA keys roughly daily. Each key has a `kid` which
//! appears in the JWT header. The cache is keyed by `kid`, so a
//! post-rotation token with a new `kid` triggers a single refresh
//! (the first caller wins the `Mutex`, everyone else waits). If a
//! fetch fails we return the cached keys and log — we'd rather serve
//! occasionally-stale pushes than 500 every delivery for the hour it
//! takes Google's CDN to heal. A dedicated `backoff_until` atomic
//! (SEPARATE from the TTL marker) stops a sustained JWKs outage from
//! turning every push into a 5 s HTTP timeout (regression `13ea09c`).

use arc_swap::ArcSwap;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

pub use talos_metrics::{JwkRefreshOutcome, PushIntegration, PushRefusalReason};

/// Google's OIDC issuer. MUST match `iss` on valid Google push JWTs.
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

impl VerifyError {
    /// The `reason` label this refusal is counted under on
    /// `talos_google_push_refusals_total`. Exhaustive, so a new variant
    /// cannot ship uncounted.
    #[must_use]
    pub fn refusal_reason(&self) -> PushRefusalReason {
        match self {
            Self::MalformedHeader => PushRefusalReason::MalformedHeader,
            Self::WrongAlgorithm => PushRefusalReason::WrongAlgorithm,
            Self::MissingKid => PushRefusalReason::MissingKid,
            Self::UnknownKey => PushRefusalReason::UnknownKey,
            Self::Invalid(_) => PushRefusalReason::Invalid,
            Self::WrongEmail => PushRefusalReason::WrongEmail,
            Self::EmailNotVerified => PushRefusalReason::EmailNotVerified,
            Self::JwkFetchFailed(_) => PushRefusalReason::JwkFetchFailed,
        }
    }
}

/// Count a push refusal that never reached the verifier (or that a caller
/// logs itself). Metric only — the caller owns the log line.
pub fn record_push_refusal(integration: PushIntegration, reason: PushRefusalReason) {
    talos_metrics::record_google_push_refusal(integration, reason);
}

/// Count one push that PASSED authentication. The positive twin of
/// [`record_push_refusal`]: a push stream that stops refuses nothing, so only
/// this count can say it went quiet (`TalosGooglePushSilent`). Each
/// integration records it at the one point its authentication completes —
/// Gmail inside `PubsubJwtVerifier::verify`, GCP after its per-watch
/// service-account check.
pub fn record_push_accepted(integration: PushIntegration) {
    talos_metrics::record_google_push_accepted(integration);
}

/// Count a push that arrived with no `Authorization: Bearer` header.
pub fn record_missing_bearer(integration: PushIntegration) {
    record_push_refusal(integration, PushRefusalReason::MissingBearer);
}

/// Whether one refusal's per-push log line is folded into the backoff
/// window's summary instead of being written at WARN. Only the
/// `UnknownKey` refusals produced INSIDE an open backoff window qualify:
/// they are the consequence of the one fetch failure already logged at
/// WARN, and on 2026-09-12 one such failure produced 92 of them in 60 s.
/// Every other refusal, and an unknown key with NO backoff open (a rotation
/// the fetch could not resolve), stays at WARN.
#[must_use]
pub fn refusal_log_is_folded(err: &VerifyError, in_backoff: bool) -> bool {
    in_backoff && matches!(err, VerifyError::UnknownKey)
}

/// Typed claims extracted from a valid Google push JWT. The caller
/// uses these (not the raw JWT) so the verification contract is
/// enforced in one place. `email` / `email_verified` are NOT checked
/// by [`GoogleOidcVerifier::verify_signed`] — call
/// [`require_service_account`](Self::require_service_account) to
/// enforce the expected service account.
#[derive(Debug, Clone, Deserialize)]
pub struct GoogleOidcClaims {
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

impl GoogleOidcClaims {
    /// Enforce the non-standard `email` / `email_verified` claims — the
    /// `jsonwebtoken` crate doesn't know about them, so callers must
    /// enforce them explicitly. Prevents an attacker with a DIFFERENT
    /// Google-signed service-account token (e.g. a developer's own SA)
    /// from delivering pushes.
    ///
    /// Kept separate from signature verification because the expected
    /// service-account email is per-integration and — for Google Cloud
    /// — per-watch (each watch row carries its own `expected_sa_email`).
    pub fn require_service_account(&self, expected_email: &str) -> Result<(), VerifyError> {
        if self.email != expected_email {
            return Err(VerifyError::WrongEmail);
        }
        if !self.email_verified {
            return Err(VerifyError::EmailNotVerified);
        }
        Ok(())
    }
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

/// Verifies Google-signed OIDC push JWTs. Holds ONLY the JWK cache +
/// refresh machinery — the expected audience is passed per call and
/// the expected service-account email is enforced separately by the
/// caller, so a single verifier serves multiple integrations (and,
/// within one integration, multiple watch channels).
pub struct GoogleOidcVerifier {
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
    /// `UnknownKey` refusals produced while `backoff_until` was in the
    /// future. Swapped to 0 by the next fetch attempt (the window's close)
    /// and reported ONCE there, so a backoff window costs one summary line
    /// rather than one WARN per refused push. Every refusal is still
    /// counted individually on `talos_google_push_refusals_total`.
    backoff_refusals: AtomicU64,
    /// Single-flight guard: only one task fetches Google's JWKs at a
    /// time, even under a flood of concurrent pushes with unknown kids.
    refresh_lock: Mutex<()>,
    http: reqwest::Client,
}

impl Default for GoogleOidcVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl GoogleOidcVerifier {
    /// Build a verifier. Doesn't fetch keys at construction — first
    /// use triggers a refresh, so startup isn't blocked on Google's
    /// CDN.
    pub fn new() -> Self {
        Self {
            keys: ArcSwap::new(Arc::new(HashMap::new())),
            last_refreshed: AtomicI64::new(0),
            backoff_until: AtomicI64::new(0),
            backoff_refusals: AtomicU64::new(0),
            refresh_lock: Mutex::new(()),
            // MCP-534: defence-in-depth even though this client only
            // fetches Google's public JWK set (no Bearer token to leak).
            // Disable redirects so a future code change that adds an
            // auth header here doesn't reopen the credential-leak
            // surface; replace the `unwrap_or_else(Client::new)`
            // anti-pattern with a loud `.expect()` per the convention.
            http: talos_http_utils::trusted_client::hardened_client_builder(Duration::from_secs(
                JWK_FETCH_TIMEOUT_SECS,
            ))
            .connect_timeout(Duration::from_secs(2))
            .build()
            .expect("GoogleOidcVerifier: failed to build hardened reqwest client"),
        }
    }

    /// Inject a pre-populated key set. Used by unit tests against a
    /// locally-generated RSA keypair; production code never calls
    /// this. Available to downstream crates' tests via the `test-util`
    /// feature (no workspace test-util convention exists yet, so the
    /// feature is declared locally).
    #[cfg(any(test, feature = "test-util"))]
    pub fn with_keys_for_test(keys: HashMap<String, DecodingKey>) -> Self {
        Self {
            keys: ArcSwap::new(Arc::new(keys)),
            last_refreshed: AtomicI64::new(i64::MAX),
            backoff_until: AtomicI64::new(0),
            backoff_refusals: AtomicU64::new(0),
            refresh_lock: Mutex::new(()),
            http: reqwest::Client::new(),
        }
    }

    /// Verify a Google push JWT's signature + standard claims against
    /// `expected_audience`. Returns the typed claims on success; every
    /// other return path is an `Err` a caller should map to `401
    /// Unauthorized` at the HTTP boundary.
    ///
    /// Does NOT check `email` / `email_verified` — the caller enforces
    /// the expected service account via
    /// [`GoogleOidcClaims::require_service_account`].
    pub async fn verify_signed(
        &self,
        token: &str,
        expected_audience: &str,
    ) -> Result<GoogleOidcClaims, VerifyError> {
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
                match self.find_key(&kid) {
                    Some(k) => k,
                    None => {
                        if self.in_backoff() {
                            self.backoff_refusals.fetch_add(1, Ordering::Relaxed);
                        }
                        return Err(VerifyError::UnknownKey);
                    }
                }
            }
        };

        // 3. Verify signature + standard claims in one shot. Validation
        //    checks iss, aud, exp automatically when configured below.
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[expected_audience]);
        validation.set_issuer(&[GOOGLE_ISSUER]);
        validation.leeway = 60; // tolerate ≤60s clock skew

        let data = decode::<GoogleOidcClaims>(token, &key, &validation)
            .map_err(|e| VerifyError::Invalid(e.to_string()))?;
        Ok(data.claims)
    }

    fn find_key(&self, kid: &str) -> Option<DecodingKey> {
        self.keys.load().get(kid).cloned()
    }

    /// Whether a JWK fetch failure has closed refreshes for now.
    #[must_use]
    pub fn in_backoff(&self) -> bool {
        chrono::Utc::now().timestamp() < self.backoff_until.load(Ordering::Relaxed)
    }

    /// `UnknownKey` refusals produced inside the currently open backoff
    /// window (0 when none is open or none were refused).
    #[must_use]
    pub fn refused_in_backoff_window(&self) -> u64 {
        self.backoff_refusals.load(Ordering::Relaxed)
    }

    /// Count AND log one refused push. The ONE place a push handler reports
    /// a `VerifyError`: every refusal moves
    /// `talos_google_push_refusals_total{integration,reason}`; an
    /// `UnknownKey` inside an open backoff window is logged at DEBUG with
    /// the running count (the window's close writes the WARN summary), every
    /// other refusal at WARN.
    pub fn report_refusal(&self, integration: PushIntegration, err: &VerifyError) {
        record_push_refusal(integration, err.refusal_reason());
        if refusal_log_is_folded(err, self.in_backoff()) {
            tracing::debug!(
                integration = integration.as_str(),
                error = %err,
                refused_in_window = self.refused_in_backoff_window(),
                "google push: JWT refused during JWK backoff (summarised when the window closes)"
            );
        } else {
            tracing::warn!(
                integration = integration.as_str(),
                error = %err,
                "google push: JWT verification failed"
            );
        }
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
        // A fetch attempt is only reachable once any earlier backoff has
        // expired, so it is the CLOSE of that window: take the refusals it
        // accumulated and report them once, whatever this attempt's outcome.
        let refused_in_previous_window = self.backoff_refusals.swap(0, Ordering::Relaxed);
        match &result {
            Ok(_) => {
                self.last_refreshed.store(now, Ordering::Relaxed);
                // Any earlier backoff is implicitly cleared — a
                // time in the past is !< now.
                talos_metrics::record_google_jwk_refresh(JwkRefreshOutcome::Ok);
                if refused_in_previous_window > 0 {
                    tracing::warn!(
                        refused_in_previous_window,
                        backoff_secs = JWK_REFRESH_BACKOFF_SECS,
                        "JWK refresh recovered; pushes carrying an unknown key were refused \
                         (401, Pub/Sub retries) during the backoff window that just closed"
                    );
                }
            }
            Err(e) => {
                // Stamp the explicit backoff deadline. The staleness
                // check alone isn't enough: unknown-kid requests
                // always fall through to `fetch_jwks`, so without
                // this marker every push would still hammer Google.
                self.backoff_until
                    .store(now + JWK_REFRESH_BACKOFF_SECS, Ordering::Relaxed);
                talos_metrics::record_google_jwk_refresh(JwkRefreshOutcome::Failed);
                tracing::warn!(
                    error = %e,
                    backoff_secs = JWK_REFRESH_BACKOFF_SECS,
                    refused_in_previous_window,
                    "JWK refresh failed; backing off — unknown-key pushes are refused (401) \
                     until the window closes and are summarised then"
                );
            }
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Shape of a Pub/Sub push request. Not part of JWT verification per se —
// lives here so every consumer of the verifier gets a single canonical
// parser for the envelope (Gmail push AND Google Cloud Monitoring push).
// ---------------------------------------------------------------------------

/// Top-level Pub/Sub push envelope. Pub/Sub wraps each message like
/// this:
///
/// ```text
/// POST /api/<integ>/pubsub
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
    /// Base64-encoded JSON. The decoded form is integration-specific
    /// (Gmail: `{ emailAddress, historyId }`; Cloud Monitoring: an
    /// incident envelope).
    pub data: String,
    #[serde(rename = "messageId")]
    pub message_id: String,
    #[serde(default)]
    #[serde(rename = "publishTime")]
    pub publish_time: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::pkcs8::EncodePublicKey;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use serde_json::json;

    const TEST_AUDIENCE: &str = "https://example/webhook";
    const TEST_SA: &str = "gmail-api-push@system.gserviceaccount.com";

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

    fn make_verifier(dec: DecodingKey, kid: &str) -> GoogleOidcVerifier {
        let mut map = HashMap::new();
        map.insert(kid.to_string(), dec);
        GoogleOidcVerifier::with_keys_for_test(map)
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
                "email": TEST_SA,
                "email_verified": true,
                "aud": TEST_AUDIENCE,
                "iat": now(),
                "exp": now() + 300,
            }),
        );
        let claims = v
            .verify_signed(&token, TEST_AUDIENCE)
            .await
            .expect("should verify");
        assert_eq!(claims.email, TEST_SA);
        assert_eq!(claims.audience, TEST_AUDIENCE);
        // The service-account check is a separate, composable step.
        claims.require_service_account(TEST_SA).expect("sa matches");
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
                "email": TEST_SA,
                "email_verified": true,
                "aud": "https://WRONG.example/webhook",
                "iat": now(),
                "exp": now() + 300,
            }),
        );
        match v
            .verify_signed(&token, TEST_AUDIENCE)
            .await
            .expect_err("must reject")
        {
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
                "email": TEST_SA,
                "email_verified": true,
                "aud": TEST_AUDIENCE,
                "iat": now(),
                "exp": now() + 300,
            }),
        );
        assert!(v.verify_signed(&token, TEST_AUDIENCE).await.is_err());
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
                "email": TEST_SA,
                "email_verified": true,
                "aud": TEST_AUDIENCE,
                "iat": now() - 3600,
                "exp": now() - 600, // 10 min ago
            }),
        );
        assert!(v.verify_signed(&token, TEST_AUDIENCE).await.is_err());
    }

    #[tokio::test]
    async fn backoff_window_suppresses_refetch_on_unknown_kid() {
        // After a fetch failure sets `backoff_until` in the future,
        // a subsequent unknown-kid request MUST return UnknownKey
        // without triggering another fetch. Regression guard for a
        // bug where the backoff marker existed but the refresh
        // path ignored it, causing every push during an outage to
        // repeat the 5 s HTTP timeout (13ea09c).
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
                "email": TEST_SA,
                "email_verified": true,
                "aud": TEST_AUDIENCE,
                "iat": now,
                "exp": now + 300,
            }),
        );
        let err = v
            .verify_signed(&token, TEST_AUDIENCE)
            .await
            .expect_err("must reject");
        // UnknownKey, not JwkFetchFailed — proves we didn't try to
        // fetch during the backoff window.
        assert!(
            matches!(err, VerifyError::UnknownKey),
            "expected UnknownKey during backoff, got: {err:?}"
        );
    }

    /// Every `VerifyError` arm has its own `reason` label and the mapping
    /// moves exactly that series on an explicit registry — the metric half
    /// of `report_refusal`, without racing `set_global`.
    #[test]
    fn every_verify_error_counts_under_its_own_reason() {
        let errs = [
            VerifyError::MalformedHeader,
            VerifyError::WrongAlgorithm,
            VerifyError::MissingKid,
            VerifyError::UnknownKey,
            VerifyError::Invalid("x".into()),
            VerifyError::WrongEmail,
            VerifyError::EmailNotVerified,
            VerifyError::JwkFetchFailed("x".into()),
        ];
        let mut seen = std::collections::HashSet::new();
        let m = talos_metrics::TalosMetrics::new().unwrap();
        for e in &errs {
            let r = e.refusal_reason();
            assert!(
                seen.insert(r.as_str()),
                "duplicate reason label {}",
                r.as_str()
            );
            talos_metrics::record_google_push_refusal_on(&m, PushIntegration::Gcp, r);
        }
        // Eight verifier arms + missing_bearer = the closed set of nine.
        assert_eq!(seen.len() + 1, PushRefusalReason::ALL.len());
        let out = m.render_prometheus().unwrap();
        for e in &errs {
            assert!(out.contains(&format!(
                "talos_google_push_refusals_total{{integration=\"gcp\",reason=\"{}\"}} 1",
                e.refusal_reason().as_str()
            )));
        }
    }

    /// Inside an open backoff window an unknown kid is COUNTED on the
    /// verifier (the per-window summary's number) and its log line is
    /// folded; a refusal for any other reason in the same window — and an
    /// unknown key with no window open — is not folded and does not count.
    #[tokio::test]
    async fn unknown_key_refusals_inside_backoff_are_counted_and_folded() {
        let (enc, dec, kid) = keypair();
        let v = make_verifier(dec, &kid);
        v.backoff_until.store(now() + 60, Ordering::Relaxed);
        assert!(v.in_backoff());

        // Three pushes with a rotated kid during the window.
        for _ in 0..3 {
            let token = sign(&enc, "rotated-kid", json!({"aud": TEST_AUDIENCE}));
            let err = v
                .verify_signed(&token, TEST_AUDIENCE)
                .await
                .expect_err("unknown kid");
            assert!(matches!(err, VerifyError::UnknownKey));
            assert!(refusal_log_is_folded(&err, v.in_backoff()));
        }
        assert_eq!(v.refused_in_backoff_window(), 3);

        // Control: a KNOWN kid with a bad audience in the same window is a
        // real refusal — not folded, not counted toward the window.
        let token = sign(
            &enc,
            &kid,
            json!({
                "iss": GOOGLE_ISSUER, "aud": "https://elsewhere", "exp": now() + 300, "iat": now(),
                "email": TEST_SA, "email_verified": true,
            }),
        );
        let err = v
            .verify_signed(&token, TEST_AUDIENCE)
            .await
            .expect_err("wrong aud");
        assert!(matches!(err, VerifyError::Invalid(_)));
        assert!(!refusal_log_is_folded(&err, v.in_backoff()));
        assert_eq!(v.refused_in_backoff_window(), 3);

        // Control: the same UnknownKey with NO window open stays at WARN.
        assert!(!refusal_log_is_folded(&VerifyError::UnknownKey, false));
        // report_refusal must not panic without a global registry.
        v.report_refusal(PushIntegration::Gmail, &VerifyError::UnknownKey);
    }

    /// SOURCE PIN, stated as textual: both push handlers must report a
    /// refusal through the verifier (count + folded log) and count a missing
    /// bearer, and neither may carry its own per-push WARN again. A guard at
    /// the primitive cannot see a call site (checks 74b/79b's limit); this is
    /// the cheap second copy.
    #[test]
    fn both_push_handlers_report_refusals_through_the_verifier() {
        let gmail = include_str!("../../talos-gmail/src/handlers.rs");
        let gcp = include_str!("../../talos-google-cloud/src/handlers.rs");
        for (name, src, integration) in [
            ("gmail", gmail, "PushIntegration::Gmail"),
            ("gcp", gcp, "PushIntegration::Gcp"),
        ] {
            assert!(
                src.contains(".report_refusal("),
                "{name}: no report_refusal call"
            );
            assert!(
                src.contains(&format!("record_missing_bearer(\n{}", ""))
                    || src.contains("record_missing_bearer("),
                "{name}: missing-bearer refusal not counted"
            );
            assert!(src.contains(integration), "{name}: wrong integration label");
            assert!(
                !src.contains("pubsub: JWT verification failed"),
                "{name}: per-push WARN reinstated beside the verifier's reporting"
            );
        }
        // GCP's service-account step is a refusal too, counted where it is logged.
        assert!(gcp.contains("record_push_refusal(PushIntegration::Gcp, e.refusal_reason())"));
    }

    /// SOURCE PIN, stated as textual: each integration counts an ACCEPTED
    /// push exactly once, at the point its authentication completes — Gmail
    /// after `require_service_account` inside `PubsubJwtVerifier::verify`,
    /// GCP after its per-watch `require_service_account` and before the
    /// envelope is decoded. Gmail's placement is also driven behaviourally
    /// (`talos-gmail` pubsub_jwt tests); GCP's positive path needs a persisted
    /// watch row, so this pin is its only guard there.
    #[test]
    fn both_integrations_count_an_accepted_push_where_authentication_completes() {
        let gmail = include_str!("../../talos-gmail/src/pubsub_jwt.rs");
        let gcp = include_str!("../../talos-google-cloud/src/handlers.rs");
        let body = |src: &'static str, start: &str, end: &str| -> &'static str {
            let a = src.find(start).expect("start anchor");
            let b = a + src[a..].find(end).expect("end anchor");
            &src[a..b]
        };
        let gmail_verify = body(gmail, "pub async fn verify(", "pub fn report_refusal(");
        let gcp_handler = body(gcp, "pub async fn pubsub_push_handler(", "#[cfg(test)]");
        for (name, region, accept, after) in [
            (
                "gmail",
                gmail_verify,
                "PushIntegration::Gmail,\n        );",
                "claims.require_service_account(&self.expected_email)?;",
            ),
            (
                "gcp",
                gcp_handler,
                "record_push_accepted(PushIntegration::Gcp);",
                "claims.require_service_account(&row.expected_sa_email)",
            ),
        ] {
            let at = region
                .find(accept)
                .unwrap_or_else(|| panic!("{name}: no accepted-push count"));
            assert_eq!(
                region.matches("record_push_accepted(").count(),
                1,
                "{name}: counted exactly once"
            );
            let auth = region.find(after).expect("authentication step");
            assert!(at > auth, "{name}: counted before authentication completes");
        }
        let decode = gcp_handler
            .find("let env: PubsubPushEnvelope")
            .expect("decode");
        let at = gcp_handler.find("record_push_accepted(").unwrap();
        assert!(at < decode, "gcp: counted before the envelope is decoded (a malformed body is still an authenticated delivery)");
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
                "email": TEST_SA,
                "email_verified": true,
                "aud": TEST_AUDIENCE,
                "iat": now(),
                "exp": now() + 300,
            }),
        );
        let err = v
            .verify_signed(&token, TEST_AUDIENCE)
            .await
            .expect_err("must reject");
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
                "email": TEST_SA,
                "email_verified": true,
                "aud": TEST_AUDIENCE,
                "iat": now(),
                "exp": now() + 300,
            }),
            &enc,
        )
        .unwrap();
        assert!(matches!(
            v.verify_signed(&token, TEST_AUDIENCE)
                .await
                .expect_err("must reject"),
            VerifyError::MissingKid
        ));
    }

    #[tokio::test]
    async fn hs256_algorithm_rejected() {
        // Even if someone managed to produce a valid HS256 JWT with
        // the right claims (e.g. by leaking an HMAC key), we must
        // refuse to treat it as a Google push. RS256 only.
        let enc = EncodingKey::from_secret(b"leaked-hmac-key");
        let header = Header::new(Algorithm::HS256);
        // No kid needed for HS256; we'll reject before key lookup.
        let token = encode(
            &header,
            &json!({
                "iss": GOOGLE_ISSUER,
                "email": TEST_SA,
                "email_verified": true,
                "aud": TEST_AUDIENCE,
                "iat": now(),
                "exp": now() + 300,
            }),
            &enc,
        )
        .unwrap();
        let (_, dec, kid) = keypair();
        let v = make_verifier(dec, &kid);
        assert!(matches!(
            v.verify_signed(&token, TEST_AUDIENCE)
                .await
                .expect_err("must reject"),
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
        let err = v
            .verify_signed(&token, TEST_AUDIENCE)
            .await
            .expect_err("must reject");
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
                "email": TEST_SA,
                "email_verified": true,
                "aud": TEST_AUDIENCE,
                "iat": now(),
                "exp": now() + 300,
            }),
        );
        // Flip a bit in the signature segment.
        let mut bytes = token.into_bytes();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let tampered = String::from_utf8(bytes).unwrap();
        assert!(v.verify_signed(&tampered, TEST_AUDIENCE).await.is_err());
    }

    #[test]
    fn require_service_account_rejects_wrong_email() {
        let claims = GoogleOidcClaims {
            issuer: GOOGLE_ISSUER.into(),
            email: "attacker-sa@evil.iam.gserviceaccount.com".into(),
            email_verified: true,
            audience: TEST_AUDIENCE.into(),
            expires_at: now() + 300,
            issued_at: now(),
        };
        assert!(matches!(
            claims
                .require_service_account("legit-sa@proj.iam.gserviceaccount.com")
                .expect_err("must reject"),
            VerifyError::WrongEmail
        ));
    }

    #[test]
    fn require_service_account_rejects_unverified_email() {
        let claims = GoogleOidcClaims {
            issuer: GOOGLE_ISSUER.into(),
            email: TEST_SA.into(),
            email_verified: false,
            audience: TEST_AUDIENCE.into(),
            expires_at: now() + 300,
            issued_at: now(),
        };
        assert!(matches!(
            claims
                .require_service_account(TEST_SA)
                .expect_err("must reject"),
            VerifyError::EmailNotVerified
        ));
    }
}
