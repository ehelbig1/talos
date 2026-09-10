//! Domain-tagged AEAD contexts — the ONE home for per-column AAD tags.
//!
//! Every v3/v4 blob derives its AES key as
//! `HKDF(ikm = DEK, salt = DEK_PER_ROW_AEAD_LABEL, info = aad)` and binds the
//! same `aad` into the GCM tag. That partitions the key space PER CONTEXT —
//! but only as finely as the AAD bytes distinguish contexts. Two columns
//! that both use the bare `user_id` bytes as AAD derive the SAME subkey for
//! the same user, so a ciphertext from one column is a valid ciphertext for
//! the other: `users.totp_secret` and
//! `user_audit_settings.auth_headers_encrypted` were exactly that pair, and
//! the swap failed only because a TOTP seed does not parse as a JSON header
//! map. That is a parser standing where the AEAD should have stood.
//!
//! The fix is a per-column DOMAIN TAG prefixed onto the id:
//! `<tag>\0<id-bytes>`. The NUL separator keeps the tag prefix-free (no
//! tag is a prefix of another followed by id bytes), and the tags live here
//! as `pub const`s so a third column cannot re-derive one under a different
//! spelling. Readers try the tagged AAD first and fall back to the bare id
//! for rows written before the tag existed — see
//! [`crate::SecretsManager::decrypt_versioned_tagged`].
//!
//! Which columns are tagged today, and which deliberately are NOT:
//! * [`TOTP_SECRET_TAG`] — `users.totp_secret` (id = `users.id`).
//! * [`OTLP_AUTH_HEADERS_TAG`] — `user_audit_settings.auth_headers_encrypted`
//!   (id = `user_id`).
//! * NOT tagged: every column whose AAD is its OWN ROW ID (`secrets.id`,
//!   `webhook_triggers.id`, `workflow_executions.id`, `module_executions.id`,
//!   `actor_memory (actor_id, key)`). A row id is unique across tables by
//!   construction (UUIDv4), so two such columns never share a context — the
//!   collision needs a SHARED foreign id, which is what `user_id` is.

use uuid::Uuid;

/// AAD domain tag for `users.totp_secret`. Terminated with NUL so the tag
/// is unambiguous against the id bytes that follow.
pub const TOTP_SECRET_TAG: &[u8] = b"totp\0";

/// AAD domain tag for `user_audit_settings.auth_headers_encrypted`.
pub const OTLP_AUTH_HEADERS_TAG: &[u8] = b"otlp-auth-headers\0";

/// Build the tagged AAD `<table_tag> || <id bytes>` for a user-keyed column.
///
/// `table_tag` MUST be one of the `pub const` tags in this module (the
/// function does not enforce that — it cannot, a tag is just bytes — which
/// is why they are consts and not string literals at the call sites).
#[must_use]
pub fn aad_for(table_tag: &[u8], id: Uuid) -> Vec<u8> {
    let mut aad = Vec::with_capacity(table_tag.len() + 16);
    aad.extend_from_slice(table_tag);
    aad.extend_from_slice(id.as_bytes());
    aad
}

/// Which AAD a tagged reader decrypted a row under. Returned by
/// [`crate::SecretsManager::decrypt_versioned_tagged`] so the caller can
/// log (at debug) whether the row is on the new tagged context or still on
/// the pre-tag bare-id context, and so a test can assert the path taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AadPath {
    /// Decrypted under `aad_for(tag, id)` — a post-tag write.
    Tagged,
    /// Decrypted under the bare `id.as_bytes()` — a pre-tag row that will
    /// be re-encrypted on its column's next write. Still a valid ciphertext
    /// for every OTHER column keyed on the same bare id until then.
    LegacyBareId,
    /// A v0 row: no AAD is bound at all, so the tag question does not
    /// arise. Reported separately so a v0 row is not miscounted as tagged.
    LegacyNoAad,
}

impl AadPath {
    /// Stable lowercase label for log fields.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AadPath::Tagged => "tagged",
            AadPath::LegacyBareId => "legacy_bare_id",
            AadPath::LegacyNoAad => "legacy_no_aad",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tagged_aad_is_tag_then_id_bytes() {
        let id = Uuid::new_v4();
        let aad = aad_for(TOTP_SECRET_TAG, id);
        assert_eq!(&aad[..TOTP_SECRET_TAG.len()], TOTP_SECRET_TAG);
        assert_eq!(&aad[TOTP_SECRET_TAG.len()..], id.as_bytes());
        assert_eq!(aad.len(), TOTP_SECRET_TAG.len() + 16);
    }

    #[test]
    fn tags_are_nul_terminated_and_distinct() {
        for tag in [TOTP_SECRET_TAG, OTLP_AUTH_HEADERS_TAG] {
            assert_eq!(tag.last(), Some(&0u8), "tag must end in NUL");
            assert_eq!(
                tag.iter().filter(|b| **b == 0).count(),
                1,
                "exactly one NUL, at the end"
            );
        }
        assert_ne!(TOTP_SECRET_TAG, OTLP_AUTH_HEADERS_TAG);
    }

    #[test]
    fn same_id_under_different_tags_yields_different_aad() {
        let id = Uuid::new_v4();
        assert_ne!(
            aad_for(TOTP_SECRET_TAG, id),
            aad_for(OTLP_AUTH_HEADERS_TAG, id),
            "the whole point: two columns keyed on one user must not share an AAD"
        );
        // And neither equals the pre-tag bare context.
        assert_ne!(aad_for(TOTP_SECRET_TAG, id), id.as_bytes().to_vec());
        assert_ne!(aad_for(OTLP_AUTH_HEADERS_TAG, id), id.as_bytes().to_vec());
    }

    #[test]
    fn aad_path_labels_are_stable() {
        assert_eq!(AadPath::Tagged.as_str(), "tagged");
        assert_eq!(AadPath::LegacyBareId.as_str(), "legacy_bare_id");
        assert_eq!(AadPath::LegacyNoAad.as_str(), "legacy_no_aad");
    }
}
