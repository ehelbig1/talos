//! GitHub App JWT minting (RS256).
//!
//! A GitHub App authenticates to mint installation tokens with a short-lived
//! JWT, RS256-signed with the App's private key (`iss` = App id). This module
//! parses the key and produces that JWT.
//!
//! **Signing backend = `ring` (constant-time).** GitHub requires RS256, which is
//! an RSA *private-key* operation — exactly what RUSTSEC-2023-0071 (the Marvin
//! timing sidechannel in the `rsa` crate) targets, and for which there is no
//! upstream fix. `ring`'s RSA implementation performs blinding and is not
//! affected, so the signing path here never touches the vulnerable code. The
//! `rsa` crate is used ONLY to normalize the key PEM to PKCS#8 (a parse/encode
//! operation, not signing/decryption).

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};

use crate::error::GithubAppError;

/// GitHub caps an App JWT's lifetime at 10 minutes.
pub const MAX_APP_JWT_TTL_SECS: i64 = 600;

/// Backdate `iat` by this much to tolerate mild clock skew between us and
/// GitHub (GitHub's own docs recommend backdating ~60s).
const IAT_BACKDATE_SECS: i64 = 60;

/// A parsed GitHub App RSA signing key, ready to mint App JWTs.
///
/// Construct once (it parses + validates the key) and reuse for many
/// [`AppSigningKey::build_app_jwt`] calls.
pub struct AppSigningKey {
    key_pair: RsaKeyPair,
}

impl std::fmt::Debug for AppSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never expose key material via Debug.
        f.write_str("AppSigningKey(<redacted RSA private key>)")
    }
}

impl AppSigningKey {
    /// Parse a GitHub App private key from PEM. Accepts both the PKCS#1
    /// encoding (`-----BEGIN RSA PRIVATE KEY-----`, GitHub's download default)
    /// and PKCS#8 (`-----BEGIN PRIVATE KEY-----`).
    ///
    /// The key is normalized to PKCS#8 (via the `rsa` crate — parse/encode only)
    /// and handed to `ring` for signing. Intermediate private-key material lives
    /// in zeroizing buffers and is wiped on drop.
    pub fn from_pem(pem: &str) -> Result<Self, GithubAppError> {
        use rsa::pkcs1::DecodeRsaPrivateKey;
        use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
        use rsa::RsaPrivateKey;

        // Try PKCS#8 first, then PKCS#1. `RsaPrivateKey` zeroizes on drop.
        let key = RsaPrivateKey::from_pkcs8_pem(pem)
            .or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem))
            .map_err(|e| {
                GithubAppError::InvalidKey(format!(
                    "not a valid PKCS#8 or PKCS#1 RSA private key PEM: {e}"
                ))
            })?;

        // `to_pkcs8_der` returns a zeroizing `SecretDocument`; pass its bytes
        // straight to ring without an intermediate plaintext copy.
        let der = key
            .to_pkcs8_der()
            .map_err(|e| GithubAppError::InvalidKey(format!("PKCS#8 re-encode failed: {e}")))?;

        let key_pair = RsaKeyPair::from_pkcs8(der.as_bytes()).map_err(|e| {
            GithubAppError::InvalidKey(format!(
                "signing backend rejected key (GitHub App keys must be ≥2048-bit RSA): {e}"
            ))
        })?;

        Ok(Self { key_pair })
    }

    /// Build an RS256-signed GitHub App JWT.
    ///
    /// * `app_id` — the numeric App id; becomes the `iss` claim.
    /// * `now_unix` — current time in Unix seconds, injected for testability.
    /// * `ttl_secs` — token lifetime; clamped to `1..=600` (GitHub's 10-min cap).
    ///
    /// `iat` is backdated 60s for clock-skew tolerance; `exp = now + ttl`.
    pub fn build_app_jwt(
        &self,
        app_id: &str,
        now_unix: i64,
        ttl_secs: i64,
    ) -> Result<String, GithubAppError> {
        if app_id.trim().is_empty() {
            return Err(GithubAppError::InvalidAppId("empty".to_string()));
        }
        let ttl = ttl_secs.clamp(1, MAX_APP_JWT_TTL_SECS);

        let header = serde_json::json!({ "alg": "RS256", "typ": "JWT" });
        let claims = serde_json::json!({
            "iat": now_unix - IAT_BACKDATE_SECS,
            "exp": now_unix + ttl,
            "iss": app_id,
        });

        // serde_json::to_vec on a json!() Value cannot fail.
        let signing_input = format!(
            "{}.{}",
            B64.encode(serde_json::to_vec(&header).expect("serialize JWT header")),
            B64.encode(serde_json::to_vec(&claims).expect("serialize JWT claims")),
        );

        // ring's RSA signing uses the rng for blinding — part of why it's
        // constant-time / Marvin-resistant.
        let rng = SystemRandom::new();
        let mut signature = vec![0u8; self.key_pair.public().modulus_len()];
        self.key_pair
            .sign(
                &RSA_PKCS1_SHA256,
                &rng,
                signing_input.as_bytes(),
                &mut signature,
            )
            .map_err(|e| GithubAppError::Signing(e.to_string()))?;

        Ok(format!("{signing_input}.{}", B64.encode(signature)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    use rsa::RsaPrivateKey;

    /// Generate a fresh 2048-bit test keypair at runtime (no embedded secrets):
    /// returns (PKCS#8 PEM, PKCS#1 PEM, SPKI public PEM).
    fn test_keys() -> (String, String, String) {
        let mut rng = rand::thread_rng();
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("generate test key");
        let pkcs8 = priv_key
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap()
            .as_str()
            .to_string();
        let pkcs1 = priv_key.to_pkcs1_pem(LineEnding::LF).unwrap().to_string();
        let pub_pem = priv_key
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        (pkcs8, pkcs1, pub_pem)
    }

    fn verify(jwt: &str, pub_pem: &str, expect_iss: &str) -> serde_json::Value {
        let dk = DecodingKey::from_rsa_pem(pub_pem.as_bytes()).unwrap();
        let mut v = Validation::new(Algorithm::RS256);
        v.set_issuer(&[expect_iss]);
        // now_unix is fixed (deterministic), so don't validate against the wall clock.
        v.validate_exp = false;
        decode::<serde_json::Value>(jwt, &dk, &v)
            .expect("ring-signed JWT must verify under jsonwebtoken")
            .claims
    }

    #[test]
    fn ring_signed_jwt_verifies_under_jsonwebtoken_pkcs8() {
        let (pkcs8, _pkcs1, pub_pem) = test_keys();
        let key = AppSigningKey::from_pem(&pkcs8).unwrap();
        let now = 1_700_000_000;
        let jwt = key.build_app_jwt("123456", now, 600).unwrap();
        let claims = verify(&jwt, &pub_pem, "123456");
        assert_eq!(claims["iss"], "123456");
        assert_eq!(claims["iat"], now - 60);
        assert_eq!(claims["exp"], now + 600);
    }

    #[test]
    fn accepts_pkcs1_pem_github_default_format() {
        let (_pkcs8, pkcs1, pub_pem) = test_keys();
        let key = AppSigningKey::from_pem(&pkcs1).unwrap();
        let jwt = key.build_app_jwt("99", 1_700_000_000, 300).unwrap();
        let claims = verify(&jwt, &pub_pem, "99");
        assert_eq!(claims["exp"], 1_700_000_000 + 300);
    }

    #[test]
    fn header_declares_rs256() {
        let (pkcs8, _, _) = test_keys();
        let key = AppSigningKey::from_pem(&pkcs8).unwrap();
        let jwt = key.build_app_jwt("1", 1_700_000_000, 600).unwrap();
        let header = jsonwebtoken::decode_header(&jwt).unwrap();
        assert_eq!(header.alg, Algorithm::RS256);
    }

    #[test]
    fn ttl_is_clamped_to_github_max() {
        let (pkcs8, _, pub_pem) = test_keys();
        let key = AppSigningKey::from_pem(&pkcs8).unwrap();
        let now = 1_700_000_000;
        // Request a year; GitHub caps at 600s.
        let jwt = key.build_app_jwt("7", now, 31_536_000).unwrap();
        let claims = verify(&jwt, &pub_pem, "7");
        assert_eq!(claims["exp"], now + MAX_APP_JWT_TTL_SECS);
    }

    #[test]
    fn ttl_floor_is_one_second() {
        let (pkcs8, _, pub_pem) = test_keys();
        let key = AppSigningKey::from_pem(&pkcs8).unwrap();
        let now = 1_700_000_000;
        let jwt = key.build_app_jwt("7", now, 0).unwrap();
        let claims = verify(&jwt, &pub_pem, "7");
        assert_eq!(claims["exp"], now + 1);
    }

    #[test]
    fn empty_app_id_rejected() {
        let (pkcs8, _, _) = test_keys();
        let key = AppSigningKey::from_pem(&pkcs8).unwrap();
        assert!(key.build_app_jwt("   ", 1_700_000_000, 600).is_err());
    }

    #[test]
    fn garbage_pem_rejected() {
        assert!(AppSigningKey::from_pem("not a pem").is_err());
        assert!(AppSigningKey::from_pem(
            "-----BEGIN RSA PRIVATE KEY-----\noops\n-----END RSA PRIVATE KEY-----"
        )
        .is_err());
    }

    #[test]
    fn debug_does_not_leak_key() {
        let (pkcs8, _, _) = test_keys();
        let key = AppSigningKey::from_pem(&pkcs8).unwrap();
        let dbg = format!("{key:?}");
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains("PRIVATE"));
    }
}
