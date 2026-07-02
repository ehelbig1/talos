//! Typed errors for the SecretsManager DECRYPT + DEK-resolve paths.
//!
//! Before this module every decrypt path surfaced `anyhow::Result`, so a
//! caller (or the audit pipeline) could not tell an *unknown format version*
//! from a *missing DEK* from a real *AES-GCM tag mismatch* from a plain
//! `sqlx` error without string-matching the `Display` output. String-matching
//! is brittle (the messages carry version numbers / key ids for operator
//! logs and are expected to evolve) and it leaks classification logic into
//! every caller.
//!
//! [`SecretsError`] gives the decrypt-and-DEK-resolve paths a stable,
//! matchable failure taxonomy. It follows the same shape the codebase
//! converged on for `ReplayError` / `ManifestError`:
//!   * a `thiserror` enum,
//!   * a [`SecretsError::user_facing_message`] accessor that collapses every
//!     variant to a generic, client-safe string.
//!
//! # SECURITY INVARIANTS (locked in by unit tests in `manager.rs`)
//!
//! * No variant carries plaintext, ciphertext, key material, or a derived
//!   subkey. [`SecretsError::Aead`] deliberately carries **no** detail — an
//!   AES-GCM open failure must not become a padding/AAD oracle, and its
//!   `Display` is a fixed generic string.
//! * [`SecretsError::user_facing_message`] never leaks a key id, a format
//!   version number, the word "aead"/"decrypt", schema names, or crypto
//!   internals. It exists for surfaces that can reach a client. The richer
//!   `Display`/`Debug` (which MAY name a format version or key id, for
//!   operator logs only) must never be forwarded to a client boundary.
//! * The enum derives `Debug` only over fields that are themselves
//!   non-sensitive (a format version `i16`, a key-id `Uuid`, a `sqlx::Error`,
//!   an `anyhow::Error`) — never over secret bytes. This keeps it clear of
//!   lint check 37 (secret-holding structs must redact in `Debug`).

use thiserror::Error;
use uuid::Uuid;

/// Failure taxonomy for the SecretsManager decrypt + DEK-resolution paths.
///
/// Callers that need to distinguish failure classes (e.g. the audit pipeline
/// deciding whether a decrypt miss is a benign format skew vs. a KMS/DEK
/// outage vs. a tamper signal) match on the variant. Callers that only need
/// to surface a generic message to a client call
/// [`SecretsError::user_facing_message`].
#[derive(Debug, Error)]
pub enum SecretsError {
    /// The row's `encryption_format_version` is not one this build knows how
    /// to decrypt (only v0/v1/v2/v3/v4 are defined). Almost always means the
    /// row was written by a NEWER code version, or a corrupt/NULL-coalesced
    /// format column. The number is carried for operator logs only — it is
    /// scrubbed from [`Self::user_facing_message`].
    #[error("unknown encryption_format_version {0}; this build only decrypts v0/v1/v2/v3/v4 (row may have been written by a newer code version)")]
    UnknownFormat(i16),

    /// The DEK named by a row's `encryption_key_id` could not be resolved —
    /// the `encryption_keys` row is absent (never provisioned, deleted, or
    /// pointing at a foreign key id). Distinct from [`Self::Aead`]: the key
    /// material was never obtained, so no crypto was attempted. The key id is
    /// carried for operator logs only — scrubbed from the user-facing message.
    #[error("data-encryption key {key_id} could not be resolved")]
    MissingDek { key_id: Uuid },

    /// AES-GCM open failed: authentication-tag mismatch, wrong key/AAD, or a
    /// malformed/too-short ciphertext. This is the tamper / corruption / AAD
    /// mismatch signal.
    ///
    /// SECURITY: this variant deliberately carries **no** detail — not the
    /// key id, not the AAD, not the ciphertext, not the underlying
    /// `aes_gcm::Error`. Surfacing any of those would risk turning a decrypt
    /// failure into an oracle. `Display` is a fixed generic string.
    #[error("authenticated decryption failed")]
    Aead,

    /// Decrypted bytes were not valid UTF-8 (a stored value that should have
    /// been a UTF-8 string was not). No plaintext bytes are carried.
    #[error("decrypted value was not valid UTF-8")]
    Serde,

    /// A database error occurred while fetching a DEK or a ciphertext row.
    /// `#[from]` so `?` on a raw `sqlx` call in a converted path maps here
    /// automatically.
    #[error("database error")]
    Database(#[from] sqlx::Error),

    /// Catch-all for internal failures that are neither a clean format skew,
    /// a missing DEK, a tag mismatch, nor a bare `sqlx` error — e.g. a KEK
    /// provider (Vault / KMS) round-trip failure surfaced as `anyhow`, or a
    /// cipher-init failure. Collapsed to a generic message at the boundary.
    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl SecretsError {
    /// Generic, client-safe message for any surface that could reach an API
    /// client. Collapses EVERY variant to a fixed string — never leaks a key
    /// id, a format version number, schema names, the word "aead", or any
    /// crypto internal. Locked in by `user_facing_message_leaks_nothing` in
    /// `manager.rs`.
    ///
    /// Operators who need the fine-grained classification read it off the
    /// variant (or the `tracing`-logged `Display`), NOT off this string.
    pub fn user_facing_message(&self) -> &'static str {
        "Secret decryption failed"
    }

    /// True when this failure is an authentication-tag mismatch / malformed
    /// ciphertext — the tamper/corruption signal. Convenience for the audit
    /// pipeline, which treats this differently from a benign format skew or a
    /// transient DEK/KMS outage.
    pub fn is_tamper_signal(&self) -> bool {
        matches!(self, Self::Aead)
    }
}
