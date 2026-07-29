//! Keyed content fingerprints — the ONE derivation for "this example's
//! identity is its content".
//!
//! ## Why keyed
//!
//! Two producers need a dedupe key for an item that arrived without one: the
//! DISTILL fallback ([`crate::distill`]) and the gray-band review router
//! ([`crate::active_learning`]). Both used to compute
//! `"ch:" + sha256(features_text)` inline, and both PERSIST the result — in
//! `ml_examples.example_key` / `ml_disagreements.example_key`, in the same row
//! as the AEAD ciphertext of that very text.
//!
//! An unkeyed hash there is a confirmation oracle: an attacker holding a
//! database backup (or a read primitive via SQLi) hashes candidate plaintexts
//! offline and learns which ones the tenant holds — no key, no decryption, no
//! interaction. That directly contradicted the policy the sibling dedupe paths
//! state and honour (`DatasetService::CONTENT_RANK_CTE`,
//! `LifecycleService::pending_disagreements`): a plaintext-derived fingerprint
//! must not be persisted next to the ciphertext.
//!
//! [`content_key`] replaces both derivations with an HMAC under a server-side
//! purpose key ([`talos_secrets_manager::SecretsManager::ml_content_mac_key`]).
//! Same dedupe behaviour; the offline oracle is gone, because recomputing a
//! fingerprint now requires a key that is only derivable by a party who can
//! also unwrap the DEKs.
//!
//! ## The `ch:` → `ck1:` seam (deliberate, bounded, self-healing)
//!
//! Rows written before this change carry `ch:<sha256>`; rows written after
//! carry `ck1:<hmac>`. They never match each other. There is NO data migration
//! and NO decrypt sweep — re-keying an old row would mean decrypting every
//! example's plaintext just to re-fingerprint it, which is a much larger
//! plaintext exposure than the problem being fixed. The consequences are
//! bounded and already have a backstop:
//!
//! * the gray-band `EXISTS(... example_key = $2 AND status='pending')` probe
//!   may re-admit one already-queued item once across the seam — bounded by
//!   the pending window and the daily cap;
//! * the `ml_examples` `(dataset_id, example_key)` upsert may mint ONE
//!   duplicate row per distinct content across the seam. That duplicate is
//!   collapsed by `DatasetService::dedupe_by_content`, which keys on the
//!   EMBEDDING, not on `example_key` — so it is era-independent by
//!   construction, and it already runs automatically on every append.
//!
//! The same reasoning covers a future purpose-key rotation (a KEK rotation, or
//! a global-DEK rotation on the KMS-backed fallback path): a new key starts a
//! new fingerprint era with exactly these bounded, self-healing effects.
//!
//! ## What is NOT a content fingerprint
//!
//! Producer-supplied `example_key`s (a Gmail message id, an ops-alert
//! `dedup_key`) are IDENTITY keys, not content-derived, and are stored
//! verbatim — unchanged by this module. They are already plaintext by design
//! (the ops `dedup_key` is a plaintext column in `ops_alerts`), and they carry
//! no information about the encrypted text beyond what the producer already
//! published elsewhere.

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Prefix of a keyed content fingerprint. Distinct from the retired `"ch:"`
/// (unkeyed sha256) so the two eras are distinguishable at a glance in the
/// database and can never be mistaken for one another.
pub const CONTENT_KEY_PREFIX: &str = "ck1:";

/// Exact length of a [`content_key`] output: `"ck1:"` + 64 hex chars.
/// Comfortably under the 512-byte `example_key` cap and under Postgres's
/// btree row limit for the `(dataset_id, example_key)` index.
pub const CONTENT_KEY_LEN: usize = CONTENT_KEY_PREFIX.len() + 64;

/// Keyed content fingerprint of `features_text` under `mac_key`.
///
/// Pure: the key is passed in (never derived here) so this function is unit
/// testable against a FIXED test vector, and so callers derive the real key
/// ONCE per batch rather than per item.
///
/// Deterministic for a given `(mac_key, features_text)` — that is the whole
/// point: identical content must upsert onto one row instead of appending a
/// duplicate every time a poll loop re-sees it.
#[must_use]
pub fn content_key(mac_key: &[u8], features_text: &str) -> String {
    // HMAC accepts a key of any length (RFC 2104 pads/hashes as needed), so
    // this cannot fail for any caller-supplied key.
    let mut mac =
        <Hmac<Sha256>>::new_from_slice(mac_key).expect("HMAC-SHA256 accepts keys of any length");
    mac.update(features_text.as_bytes());
    let tag = mac.finalize().into_bytes();
    format!("{CONTENT_KEY_PREFIX}{}", hex::encode(tag))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIXED test key. Never the real derivation chain — a KEK-derived value
    /// must never appear in a test expectation.
    const TEST_KEY: [u8; 32] = [0x2au8; 32];

    /// Wire-format pin. This freezes the derivation the way the signing-format
    /// snapshots do: any change to the algorithm, the key handling, the input
    /// encoding, or the prefix breaks this exact string. In particular,
    /// swapping the HMAC back to a bare `sha256(features_text)` fails here.
    #[test]
    fn content_key_matches_the_pinned_vector() {
        assert_eq!(
            content_key(&TEST_KEY, "Subject: same email"),
            "ck1:edd37a3dbfc264aab7ce4f988b53236ba2c0b460c07b61e107900db3ba19842f"
        );
    }

    #[test]
    fn content_key_is_stable_and_content_sensitive() {
        let a = content_key(&TEST_KEY, "Subject: same email");
        let b = content_key(&TEST_KEY, "Subject: same email");
        let c = content_key(&TEST_KEY, "Subject: different email");
        assert_eq!(a, b, "identical text → identical key (this is the dedupe)");
        assert_ne!(a, c, "different text → different key");
    }

    /// The keying is load-bearing: the same text under a different MAC key
    /// must not produce the same fingerprint, or the confirmation oracle is
    /// back (an attacker could just use a key of their choosing).
    #[test]
    fn distinct_mac_keys_yield_distinct_fingerprints() {
        let other = [0x2bu8; 32];
        assert_ne!(
            content_key(&TEST_KEY, "Subject: same email"),
            content_key(&other, "Subject: same email")
        );
    }

    #[test]
    fn content_key_shape_fits_the_example_key_cap() {
        let k = content_key(&TEST_KEY, "anything");
        assert!(k.starts_with(CONTENT_KEY_PREFIX));
        assert_eq!(k.len(), CONTENT_KEY_LEN);
        assert_eq!(k.len(), 68);
        assert!(k.len() <= crate::distill::MAX_EXAMPLE_KEY_BYTES);
        assert!(
            k[CONTENT_KEY_PREFIX.len()..]
                .chars()
                .all(|c| c.is_ascii_hexdigit()),
            "body must be plain hex — it is compared, indexed and logged as an id"
        );
    }

    /// Structural guard replacing the old cross-file byte-compatibility test:
    /// the two producers must ROUTE THROUGH this primitive, not re-implement
    /// it. Drift is then a compile-level impossibility rather than something a
    /// test has to keep noticing. Also proves no unkeyed plaintext hash was
    /// re-introduced at either site.
    #[test]
    fn both_producers_route_through_this_primitive() {
        for (name, src) in [
            ("distill.rs", include_str!("distill.rs")),
            ("active_learning.rs", include_str!("active_learning.rs")),
        ] {
            assert!(
                src.contains("content_identity::content_key("),
                "{name} must derive its fallback example_key via content_identity::content_key"
            );
            assert!(
                !src.contains("Sha256"),
                "{name} must not hash plaintext itself — that is the unkeyed \
                 confirmation-oracle derivation this module replaced"
            );
        }
    }
}
