//! Authentication of an inbound Jira webhook delivery.
//!
//! Atlassian sends each dynamic-webhook delivery with
//! `Authorization: Bearer <JWT>` and says only that the token "is signed with
//! the app's client secret". The algorithm and the claims are not documented
//! (2026-10-12), so this verifier is deliberately the narrowest thing that can
//! be justified today:
//!
//! * the signature must verify under the app's client secret, with an HMAC
//!   algorithm (HS256 / HS384 / HS512) and no other. `none` and every
//!   asymmetric algorithm are refused by name BEFORE any key is used;
//! * `exp` is REQUIRED (since 2026-10-14) and must be at most
//!   [`MAX_TOKEN_LIFETIME_SECS`] in the future; `nbf` is honoured when
//!   present (60 s leeway). The shape log below showed the claims a real
//!   delivery carries — `context, exp, iat, iss, jti, sub`, HS256 — so the
//!   requirement refuses only what Atlassian does not send. A token is
//!   single-use: the receiver keeps a replay cache keyed on the token's hash
//!   for as long as an `exp` can be valid (security review 2026-10-14, F-2);
//! * `aud`, `iss` and `sub` are not checked: their VALUES for an OAuth 2.0
//!   app's delivery are undocumented, and a guessed value would refuse every
//!   real delivery. The token carries no `qsh`, so it is not bound to the
//!   request body; the replay cache is what stops one token carrying a second
//!   body.
//!
//! The first delivery this process authenticates logs the header `alg`, the
//! sorted NAMES of its claims and the token's lifetime in seconds (never a
//! claim value) so this validation can be tightened further.
//!
//! The comparison of the MAC is the `jsonwebtoken` crate's (constant time);
//! nothing here compares secret material.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use std::sync::atomic::{AtomicBool, Ordering};

/// Longest bearer token read. A delivery JWT is a few hundred bytes; anything
/// near this is not one, and is refused before base64 or HMAC work.
pub const MAX_JWT_BYTES: usize = 8 * 1024;

/// Shortest client secret the receiver will verify with. `hmac` accepts a key
/// of any length including zero, and an empty key signs public data with a
/// public key. Atlassian's client secrets are far longer than this.
pub const MIN_CLIENT_SECRET_BYTES: usize = 16;

/// Clock skew tolerated on `exp` / `nbf`, in seconds.
pub const LEEWAY_SECS: u64 = 60;

/// Furthest in the future a token's `exp` may be. The receiver's replay
/// cache remembers a token for at least this long plus [`LEEWAY_SECS`], so no
/// token it accepts can outlive its memory of having seen it.
pub const MAX_TOKEN_LIFETIME_SECS: u64 = 60 * 60;

/// Why a delivery's token was refused. A closed set: the handler logs the
/// word and never the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtRefusal {
    /// Not three base64url segments with a JSON header, or too long.
    Malformed,
    /// The header names an algorithm other than HS256 / HS384 / HS512.
    AlgorithmNotAccepted,
    /// The header names critical extensions (`crit`); none are understood.
    CriticalHeader,
    /// The MAC does not verify under the app's client secret.
    BadSignature,
    /// `exp` is in the past (beyond the leeway).
    Expired,
    /// `nbf` is in the future (beyond the leeway).
    NotYetValid,
    /// The token verified structurally but a claim is malformed.
    InvalidClaims,
    /// The token carries no `exp`: it would never stop being usable.
    MissingExpiry,
    /// `exp` is further out than [`MAX_TOKEN_LIFETIME_SECS`]: a token that
    /// outlives the replay cache's memory of it could be used twice.
    ExpiryTooFar,
}

impl JwtRefusal {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::AlgorithmNotAccepted => "algorithm_not_accepted",
            Self::CriticalHeader => "critical_header",
            Self::BadSignature => "bad_signature",
            Self::Expired => "expired",
            Self::NotYetValid => "not_yet_valid",
            Self::InvalidClaims => "invalid_claims",
            Self::MissingExpiry => "missing_expiry",
            Self::ExpiryTooFar => "expiry_too_far",
        }
    }
}

/// What a verified token says about itself, for the one-time shape log. No
/// claim VALUE is kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedJwt {
    pub alg: &'static str,
    /// Sorted, bounded, and limited to plain names.
    pub claim_names: Vec<String>,
    /// `exp`, in Unix seconds. Always present on a verified token; the
    /// receiver remembers the token until then (plus the leeway).
    pub expires_at: u64,
    /// `exp - iat` when the token carries an `iat`, for the shape log.
    pub lifetime_secs: Option<u64>,
}

/// THE algorithm restriction: the only names this receiver will verify.
///
/// A token whose header names anything else — `none`, RS256, ES256, PS256,
/// EdDSA, or a name nobody has heard of — is refused here, before a key is
/// built. The secret is an HMAC key; treating it as any other kind of key is
/// never meaningful.
#[must_use]
pub fn accepted_algorithm(name: &str) -> Option<(Algorithm, &'static str)> {
    match name {
        "HS256" => Some((Algorithm::HS256, "HS256")),
        "HS384" => Some((Algorithm::HS384, "HS384")),
        "HS512" => Some((Algorithm::HS512, "HS512")),
        _ => None,
    }
}

#[derive(serde::Deserialize)]
struct Header {
    alg: String,
    #[serde(default)]
    crit: Option<serde::de::IgnoredAny>,
}

/// Verify a delivery's bearer token against the app's client secret.
///
/// Pure: no I/O, no clock other than the system time `jsonwebtoken` reads for
/// `exp` / `nbf`. The caller has already refused a secret shorter than
/// [`MIN_CLIENT_SECRET_BYTES`].
pub fn verify_delivery_jwt(token: &str, client_secret: &[u8]) -> Result<VerifiedJwt, JwtRefusal> {
    if token.is_empty() || token.len() > MAX_JWT_BYTES {
        return Err(JwtRefusal::Malformed);
    }
    let mut segments = token.split('.');
    let (Some(header_b64), Some(_claims), Some(_mac), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Err(JwtRefusal::Malformed);
    };
    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| JwtRefusal::Malformed)?;
    let header: Header =
        serde_json::from_slice(&header_bytes).map_err(|_| JwtRefusal::Malformed)?;

    // The algorithm is decided from the header's own text, before the library
    // is asked anything.
    let (algorithm, alg) =
        accepted_algorithm(&header.alg).ok_or(JwtRefusal::AlgorithmNotAccepted)?;
    // RFC 7515 §4.1.11: refuse a token naming critical header extensions this
    // verifier does not understand. It understands none.
    if header.crit.is_some() {
        return Err(JwtRefusal::CriticalHeader);
    }

    let mut validation = Validation::new(algorithm);
    // `exp` required (a real delivery carries it); nothing else is.
    validation.set_required_spec_claims(&["exp"]);
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.validate_aud = false;
    validation.leeway = LEEWAY_SECS;

    let data = decode::<serde_json::Map<String, serde_json::Value>>(
        token,
        &DecodingKey::from_secret(client_secret),
        &validation,
    )
    .map_err(|e| match e.kind() {
        ErrorKind::InvalidSignature => JwtRefusal::BadSignature,
        ErrorKind::ExpiredSignature => JwtRefusal::Expired,
        ErrorKind::ImmatureSignature => JwtRefusal::NotYetValid,
        ErrorKind::InvalidAlgorithm | ErrorKind::InvalidAlgorithmName => {
            JwtRefusal::AlgorithmNotAccepted
        }
        ErrorKind::InvalidToken | ErrorKind::Base64(_) | ErrorKind::Utf8(_) => {
            JwtRefusal::Malformed
        }
        ErrorKind::MissingRequiredClaim(_) => JwtRefusal::MissingExpiry,
        _ => JwtRefusal::InvalidClaims,
    })?;

    let claim_u64 = |name: &str| data.claims.get(name).and_then(serde_json::Value::as_u64);
    let expires_at = claim_u64("exp").ok_or(JwtRefusal::InvalidClaims)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    if expires_at > now.saturating_add(MAX_TOKEN_LIFETIME_SECS + LEEWAY_SECS) {
        return Err(JwtRefusal::ExpiryTooFar);
    }

    Ok(VerifiedJwt {
        alg,
        claim_names: plain_claim_names(data.claims.keys().map(String::as_str)),
        expires_at,
        lifetime_secs: claim_u64("iat").map(|iat| expires_at.saturating_sub(iat)),
    })
}

/// Most claim names recorded, and the longest one recorded verbatim.
const MAX_CLAIM_NAMES: usize = 32;
const MAX_CLAIM_NAME_LEN: usize = 64;

/// The claim NAMES of a verified token, sorted, for the shape log. A name
/// that is not a short plain identifier is recorded as `<other>`: the names
/// come from a token Atlassian signed, but a log line is not the place to
/// find out what else a name can hold.
fn plain_claim_names<'a>(names: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut out: Vec<String> = names
        .map(|name| {
            let plain = !name.is_empty()
                && name.len() <= MAX_CLAIM_NAME_LEN
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'));
            if plain {
                name.to_string()
            } else {
                "<other>".to_string()
            }
        })
        .collect();
    out.sort();
    out.dedup();
    out.truncate(MAX_CLAIM_NAMES);
    out
}

static SHAPE_LOGGED: AtomicBool = AtomicBool::new(false);

/// Log the header `alg` and the claim NAMES of the first delivery this
/// process authenticates. Once per process: the point is to learn the claim
/// set from a real delivery, not to log every one.
pub fn log_shape_once(verified: &VerifiedJwt) {
    if SHAPE_LOGGED.swap(true, Ordering::Relaxed) {
        return;
    }
    tracing::info!(
        event_kind = "jira_webhook_jwt_shape",
        alg = verified.alg,
        claim_names = %verified.claim_names.join(","),
        lifetime_secs = ?verified.lifetime_secs,
        "first authenticated Jira webhook delivery in this process: its JWT header alg, \
         claim NAMES (never values) and lifetime, recorded so the receiver's validation can \
         be tightened"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header as JwtHeader};

    const SECRET: &[u8] = b"test-client-secret-of-enough-length";

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn signed(alg: Algorithm, claims: &serde_json::Value, secret: &[u8]) -> String {
        encode(
            &JwtHeader::new(alg),
            claims,
            &EncodingKey::from_secret(secret),
        )
        .expect("sign")
    }

    /// A token with an arbitrary header and a signature that is not one.
    fn hand_built(header: &serde_json::Value, claims: &serde_json::Value, mac: &str) -> String {
        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string()),
            mac
        )
    }

    #[test]
    fn a_token_signed_with_the_client_secret_is_accepted_under_each_hmac_algorithm() {
        for (alg, name) in [
            (Algorithm::HS256, "HS256"),
            (Algorithm::HS384, "HS384"),
            (Algorithm::HS512, "HS512"),
        ] {
            let token = signed(
                alg,
                &serde_json::json!({"iss": "example", "exp": now() + 120, "zeta": 1}),
                SECRET,
            );
            let verified = verify_delivery_jwt(&token, SECRET).expect("accepted");
            assert_eq!(verified.alg, name);
            assert_eq!(verified.claim_names, ["exp", "iss", "zeta"]);
        }
    }

    /// A real delivery carries `exp` (the shape log on a live stack:
    /// `context, exp, iat, iss, jti, sub`). A token without one would never
    /// stop being usable, so it is refused (security review 2026-10-14, F-2).
    #[test]
    fn a_token_without_exp_is_refused() {
        let token = signed(
            Algorithm::HS256,
            &serde_json::json!({"anything": true}),
            SECRET,
        );
        assert_eq!(
            verify_delivery_jwt(&token, SECRET),
            Err(JwtRefusal::MissingExpiry)
        );
        // An `aud` nobody configured is not a reason to refuse.
        let token = signed(
            Algorithm::HS256,
            &serde_json::json!({"aud": "some-client-id", "exp": now() + 120}),
            SECRET,
        );
        assert!(verify_delivery_jwt(&token, SECRET).is_ok());
    }

    /// An `exp` further out than the replay cache remembers a token could be
    /// used again once forgotten.
    #[test]
    fn a_token_with_a_far_future_exp_is_refused() {
        let far = signed(
            Algorithm::HS256,
            &serde_json::json!({"exp": now() + MAX_TOKEN_LIFETIME_SECS + LEEWAY_SECS + 120}),
            SECRET,
        );
        assert_eq!(
            verify_delivery_jwt(&far, SECRET),
            Err(JwtRefusal::ExpiryTooFar)
        );
        let near = signed(
            Algorithm::HS256,
            &serde_json::json!({"exp": now() + MAX_TOKEN_LIFETIME_SECS, "iat": now()}),
            SECRET,
        );
        let verified = verify_delivery_jwt(&near, SECRET).expect("an hour is accepted");
        assert_eq!(verified.lifetime_secs, Some(MAX_TOKEN_LIFETIME_SECS));
    }

    #[test]
    fn a_token_signed_with_another_secret_or_tampered_with_is_refused() {
        let claims = serde_json::json!({"exp": now() + 120});
        let other = signed(
            Algorithm::HS256,
            &claims,
            b"another-secret-of-enough-length-",
        );
        assert_eq!(
            verify_delivery_jwt(&other, SECRET),
            Err(JwtRefusal::BadSignature)
        );

        // The right secret, then the claims swapped under the same MAC.
        let good = signed(Algorithm::HS256, &claims, SECRET);
        let mut parts: Vec<&str> = good.split('.').collect();
        let forged_claims = URL_SAFE_NO_PAD.encode(r#"{"exp":99999999999}"#);
        parts[1] = &forged_claims;
        assert_eq!(
            verify_delivery_jwt(&parts.join("."), SECRET),
            Err(JwtRefusal::BadSignature)
        );
    }

    /// `none` and every asymmetric algorithm are refused BY NAME. (The
    /// library would also fail to verify them with an HMAC key; the reason
    /// asserted here is this module's own gate, which runs first.)
    #[test]
    fn a_token_naming_none_or_an_asymmetric_algorithm_is_refused_by_name() {
        let claims = serde_json::json!({"exp": now() + 120});
        for alg in [
            "none", "None", "NONE", "RS256", "RS384", "RS512", "PS256", "ES256", "ES384", "EdDSA",
            "hs256", "HS1", "",
        ] {
            let header = serde_json::json!({"alg": alg, "typ": "JWT"});
            for mac in ["", "AAAA"] {
                assert_eq!(
                    verify_delivery_jwt(&hand_built(&header, &claims, mac), SECRET),
                    Err(JwtRefusal::AlgorithmNotAccepted),
                    "alg {alg:?} mac {mac:?}"
                );
            }
        }
    }

    #[test]
    fn an_expired_or_not_yet_valid_token_is_refused_and_the_leeway_is_a_minute() {
        let expired = signed(
            Algorithm::HS256,
            &serde_json::json!({"exp": now() - 600}),
            SECRET,
        );
        assert_eq!(
            verify_delivery_jwt(&expired, SECRET),
            Err(JwtRefusal::Expired)
        );
        let just_expired = signed(
            Algorithm::HS256,
            &serde_json::json!({"exp": now() - 20}),
            SECRET,
        );
        assert!(
            verify_delivery_jwt(&just_expired, SECRET).is_ok(),
            "inside the leeway"
        );
        let early = signed(
            Algorithm::HS256,
            &serde_json::json!({"nbf": now() + 600, "exp": now() + 1200}),
            SECRET,
        );
        assert_eq!(
            verify_delivery_jwt(&early, SECRET),
            Err(JwtRefusal::NotYetValid)
        );
    }

    #[test]
    fn a_token_that_is_not_one_is_refused_before_any_key_is_used() {
        for junk in ["", "a", "a.b", "a.b.c.d", "....", "!!!.e30.AAAA"] {
            assert_eq!(
                verify_delivery_jwt(junk, SECRET),
                Err(JwtRefusal::Malformed),
                "{junk:?}"
            );
        }
        let long = "a".repeat(MAX_JWT_BYTES + 1);
        assert_eq!(
            verify_delivery_jwt(&long, SECRET),
            Err(JwtRefusal::Malformed)
        );
        // A header that is JSON but names no algorithm.
        let no_alg = hand_built(
            &serde_json::json!({"typ": "JWT"}),
            &serde_json::json!({}),
            "",
        );
        assert_eq!(
            verify_delivery_jwt(&no_alg, SECRET),
            Err(JwtRefusal::Malformed)
        );
    }

    #[test]
    fn a_token_naming_critical_extensions_is_refused() {
        let header = serde_json::json!({"alg": "HS256", "crit": ["exp"], "exp": 1});
        let token = hand_built(&header, &serde_json::json!({}), "AAAA");
        assert_eq!(
            verify_delivery_jwt(&token, SECRET),
            Err(JwtRefusal::CriticalHeader)
        );
    }

    #[test]
    fn claim_names_are_sorted_bounded_and_plain() {
        let names = plain_claim_names(
            ["zeta", "alpha", "has space", "qsh", "", "alpha"]
                .into_iter()
                .chain(std::iter::once("x".repeat(65).leak() as &str)),
        );
        assert_eq!(names, ["<other>", "alpha", "qsh", "zeta"]);
        let many: Vec<String> = (0..100).map(|i| format!("claim{i:03}")).collect();
        assert_eq!(
            plain_claim_names(many.iter().map(String::as_str)).len(),
            MAX_CLAIM_NAMES
        );
    }

    #[test]
    fn every_refusal_is_a_plain_word() {
        for r in [
            JwtRefusal::Malformed,
            JwtRefusal::AlgorithmNotAccepted,
            JwtRefusal::CriticalHeader,
            JwtRefusal::BadSignature,
            JwtRefusal::Expired,
            JwtRefusal::NotYetValid,
            JwtRefusal::InvalidClaims,
            JwtRefusal::MissingExpiry,
            JwtRefusal::ExpiryTooFar,
        ] {
            assert!(r
                .as_str()
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b == b'_'));
        }
    }
}
