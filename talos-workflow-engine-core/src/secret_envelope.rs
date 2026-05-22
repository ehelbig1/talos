//! Pluggable encryption envelope for per-dispatch secrets.
//!
//! The executor resolves plaintext secrets through a
//! [`SecretsResolver`](crate::SecretsResolver), then hands them to a
//! [`SecretEnvelope`] to seal before wire transmission. The envelope
//! owns the algorithm choice; the engine treats its output as opaque
//! bytes.
//!
//! # Security invariants impls MUST uphold
//!
//! * Generate a fresh content-encryption key for each call. Static
//!   keys across calls enable replay if the shared key later leaks.
//! * Generate a fresh nonce for each call. A reused nonce under the
//!   same key breaks the confidentiality and integrity of AEAD schemes.
//! * Authenticate the ciphertext (AEAD or encrypt-then-MAC). Plain
//!   CTR/CBC without MAC is not acceptable — the engine does not add
//!   an outer MAC.
//! * Return an error rather than returning plaintext-in-ciphertext-
//!   field on failure. The engine's dispatch guard rails assume a
//!   non-empty ciphertext implies a real seal.
//!
//! The reference `AesGcmSecretEnvelope` shipped in the
//! `talos-workflow-job-protocol` crate satisfies all of the above.
//! Consumers whose workers speak a different wire format implement
//! this trait themselves; consumers who don't need encryption (a
//! pure in-process executor) can still prefer the default — the
//! per-call AES cost is single-digit microseconds on typical
//! workloads.

use std::collections::HashMap;
use std::fmt;

use async_trait::async_trait;

use crate::BoxError;

/// Minimum AEAD nonce length accepted by
/// [`validate_seal_output`]. AES-GCM's 96-bit nonce is the practical
/// floor; larger-nonce schemes (XChaCha20-Poly1305 at 192 bits,
/// AES-SIV at 128 bits) comfortably clear this bound.
pub const MIN_SEAL_NONCE_LEN: usize = 12;

/// Structural violation produced by [`validate_seal_output`].
///
/// The engine treats every variant the same way — dispatches the node
/// with an empty sealed pair, which fails the node cleanly rather
/// than forwarding corrupted bytes. Consumers reusing
/// [`validate_seal_output`] from their own dispatcher impls can map
/// the variants onto their own error taxonomy.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SealValidationError {
    /// One of `ciphertext` / `nonce` was empty while the other was
    /// non-empty. Impossible to decrypt; almost certainly a bug in the
    /// envelope impl.
    MismatchedEmptyNonEmpty {
        /// Whether the ciphertext was the empty one.
        ciphertext_empty: bool,
        /// Whether the nonce was the empty one.
        nonce_empty: bool,
    },
    /// The nonce was shorter than [`MIN_SEAL_NONCE_LEN`]. Nearly all
    /// modern AEADs require at least 12 bytes.
    NonceTooShort {
        /// The nonce length the envelope returned.
        actual: usize,
        /// The minimum the engine requires.
        minimum: usize,
    },
}

impl fmt::Display for SealValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MismatchedEmptyNonEmpty {
                ciphertext_empty,
                nonce_empty,
            } => write!(
                f,
                "SecretEnvelope::seal returned a mismatched (ciphertext, nonce) pair: ciphertext_empty={ciphertext_empty}, nonce_empty={nonce_empty}"
            ),
            Self::NonceTooShort { actual, minimum } => write!(
                f,
                "SecretEnvelope::seal returned a nonce shorter than the AEAD minimum: actual={actual}, minimum={minimum}"
            ),
        }
    }
}

impl std::error::Error for SealValidationError {}

/// Validate a [`SecretEnvelope::seal`] output against the engine's
/// documented structural invariants.
///
/// Returns `Ok(())` when the `(ciphertext, nonce)` pair is safe to
/// forward on the wire; returns a [`SealValidationError`] otherwise.
///
/// Accepted shapes:
///
/// * `(empty, empty)` — the documented sentinel for "nothing to seal."
/// * `(non-empty, non-empty)` with `nonce.len() >= MIN_SEAL_NONCE_LEN`.
///
/// Rejected shapes:
///
/// * Mismatched (one empty, one non-empty).
/// * `(non-empty, non-empty)` with `nonce.len() < MIN_SEAL_NONCE_LEN`.
///
/// This is a **structural** check, not a cryptographic one. It cannot
/// detect an identity-function envelope (ciphertext equal to plaintext
/// bytes) or a constant-nonce envelope — the engine has no way to
/// audit AEAD semantics without the key. Verifying AEAD quality is the
/// envelope impl's responsibility; this helper catches obvious
/// configuration mistakes (e.g. a stub returning `(bytes, vec![])`).
///
/// The engine's reference dispatch path calls this after every
/// `seal` and logs rejections at `tracing::error!`. External
/// [`NodeDispatcher`] impls that build their own `DispatchJob` from
/// a `SecretEnvelope::seal` result are encouraged to reuse this
/// helper for identical guarantees.
///
/// [`NodeDispatcher`]: crate::NodeDispatcher
pub fn validate_seal_output(ciphertext: &[u8], nonce: &[u8]) -> Result<(), SealValidationError> {
    match (ciphertext.is_empty(), nonce.is_empty()) {
        (true, true) => Ok(()),
        (false, false) => {
            if nonce.len() < MIN_SEAL_NONCE_LEN {
                Err(SealValidationError::NonceTooShort {
                    actual: nonce.len(),
                    minimum: MIN_SEAL_NONCE_LEN,
                })
            } else {
                Ok(())
            }
        }
        (c, n) => Err(SealValidationError::MismatchedEmptyNonEmpty {
            ciphertext_empty: c,
            nonce_empty: n,
        }),
    }
}

/// Seals a plaintext secrets map into a `(ciphertext, nonce)` pair
/// authenticated under `shared_key`.
#[async_trait]
pub trait SecretEnvelope: Send + Sync {
    /// Encrypt `secrets` under `shared_key`, returning
    /// `(ciphertext, nonce)`.
    ///
    /// * `secrets` — plaintext `key → value` map. Impls MUST NOT log
    ///   or persist the plaintext.
    /// * `shared_key` — pre-shared authentication key. Borrowed; the
    ///   impl must not retain it past the call. Typical impls use it
    ///   as both the HMAC key for an outer MAC and as an input to a
    ///   per-call KDF that derives the content-encryption key.
    ///
    /// Returns `(ciphertext_bytes, nonce_bytes)`. Both are opaque to
    /// the engine — it forwards them verbatim into the wire format.
    ///
    /// An empty `secrets` map is a valid input. Impls may return an
    /// empty `ciphertext` + empty `nonce` as a sentinel meaning
    /// "nothing to seal"; the reference impl does this.
    ///
    /// # Output contract (enforced by the engine)
    ///
    /// The engine validates every `seal` result against these rules
    /// before forwarding the pair on the wire:
    ///
    /// 1. **Both empty, or both non-empty.** Returning a non-empty
    ///    ciphertext with an empty nonce (or vice versa) is treated
    ///    as a configuration bug and rejected.
    /// 2. **When non-empty, the nonce MUST be at least 12 bytes.**
    ///    AES-GCM's 96-bit nonce is the practical minimum; schemes
    ///    with larger nonces (XChaCha20-Poly1305 at 192 bits)
    ///    comfortably satisfy this bound. A shorter nonce is
    ///    treated as a misconfigured envelope and rejected.
    ///
    /// Violations are logged at `tracing::error!` with the node id
    /// and the envelope is treated as if it had returned an error —
    /// the engine substitutes an empty sealed pair, which the
    /// dispatcher forwards as "no secrets." This fails the node
    /// (missing secrets) rather than sending corrupted ciphertext.
    async fn seal(
        &self,
        secrets: &HashMap<String, String>,
        shared_key: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), BoxError>;

    /// L-1 (2026-05-22): same contract as [`Self::seal`], with `aad`
    /// bound into the AEAD authentication tag.
    ///
    /// The recommended `aad` is the dispatching job's identifier
    /// (e.g. `job_id.as_bytes()` — the raw 16-byte UUID). Binding
    /// that into the tag makes a transposed ciphertext (lifted from
    /// one JobRequest into another under the same shared key) fail
    /// to decrypt at the worker, providing an in-protocol integrity
    /// gate independent of the JobRequest HMAC.
    ///
    /// The default impl ignores `aad` and falls through to [`Self::seal`]
    /// — this keeps existing custom envelopes compiling without
    /// modification. Production envelopes (the reference
    /// `AesGcmSecretEnvelope`) override this method.
    async fn seal_with_aad(
        &self,
        secrets: &HashMap<String, String>,
        shared_key: &[u8],
        _aad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), BoxError> {
        self.seal(secrets, shared_key).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_both_empty_sentinel() {
        assert!(validate_seal_output(&[], &[]).is_ok());
    }

    #[test]
    fn accepts_full_aes_gcm_shape() {
        // 12-byte nonce (GCM floor), arbitrary ciphertext >= 1 byte.
        assert!(validate_seal_output(&[0u8; 32], &[0u8; 12]).is_ok());
    }

    #[test]
    fn accepts_larger_nonce() {
        // XChaCha20 nonces are 24 bytes — still valid.
        assert!(validate_seal_output(&[0u8; 16], &[0u8; 24]).is_ok());
    }

    #[test]
    fn rejects_short_nonce() {
        // 8 bytes — below MIN_SEAL_NONCE_LEN.
        match validate_seal_output(&[0u8; 32], &[0u8; 8]) {
            Err(SealValidationError::NonceTooShort { actual, minimum }) => {
                assert_eq!(actual, 8);
                assert_eq!(minimum, MIN_SEAL_NONCE_LEN);
            }
            other => panic!("expected NonceTooShort, got {other:?}"),
        }
    }

    #[test]
    fn rejects_empty_nonce_with_ciphertext() {
        match validate_seal_output(&[0u8; 32], &[]) {
            Err(SealValidationError::MismatchedEmptyNonEmpty {
                ciphertext_empty,
                nonce_empty,
            }) => {
                assert!(!ciphertext_empty);
                assert!(nonce_empty);
            }
            other => panic!("expected MismatchedEmptyNonEmpty, got {other:?}"),
        }
    }

    #[test]
    fn rejects_empty_ciphertext_with_nonce() {
        match validate_seal_output(&[], &[0u8; 12]) {
            Err(SealValidationError::MismatchedEmptyNonEmpty {
                ciphertext_empty,
                nonce_empty,
            }) => {
                assert!(ciphertext_empty);
                assert!(!nonce_empty);
            }
            other => panic!("expected MismatchedEmptyNonEmpty, got {other:?}"),
        }
    }

    #[test]
    fn error_display_has_context() {
        // Smoke test the Display impls so tracing output is useful.
        let e = SealValidationError::NonceTooShort {
            actual: 4,
            minimum: 12,
        };
        let s = format!("{e}");
        assert!(s.contains("actual=4"), "got: {s}");
        assert!(s.contains("minimum=12"), "got: {s}");
    }
}
