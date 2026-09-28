//! Binding a wrapped DEK to the `encryption_keys` row that stores it
//! (RFC 0013).
//!
//! The KEK wrap of a DEK carries the row's identity as associated data, so a
//! wrapped blob moved into another row — another org's, or between the global
//! and an org scope — fails to unwrap instead of silently serving the wrong
//! tenant's key. This module is the ONE home of that encoding: every wrap and
//! unwrap of an `encryption_keys` row derives its AAD here.

use anyhow::{anyhow, Result};
use uuid::Uuid;

/// Domain-separation tag at the head of every bound AAD. Versioned so a future
/// encoding cannot collide with this one.
pub const DEK_WRAP_AAD_TAG: &[u8] = b"talos-dek-wrap/v2";

/// `encryption_keys.wrap_format` of a bound wrap — the only format a row may
/// have since RFC 0013 phase 3 (`CHECK (wrap_format = 2)`).
pub const BOUND_WRAP_FORMAT: i16 = 2;

/// Refuse a row whose wrap is not bound to it. The schema's CHECK already
/// forbids one; this is the reader's own guard, so a dropped constraint cannot
/// quietly bring back an unbound read — the swap RFC 0013 exists to stop.
pub fn ensure_bound(wrap_format: i16) -> Result<()> {
    if wrap_format == BOUND_WRAP_FORMAT {
        Ok(())
    } else {
        Err(anyhow!(
            "encryption_keys.wrap_format {wrap_format} refused: only DEK wraps bound to their \
             row ({BOUND_WRAP_FORMAT}) are read since RFC 0013 phase 3"
        ))
    }
}

/// The identity a wrapped DEK is bound to: its `encryption_keys` row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DekRowIdentity {
    pub key_id: Uuid,
    /// `None` for the global DEK, `Some` for an organization's root DEK.
    pub org_id: Option<Uuid>,
}

impl DekRowIdentity {
    #[must_use]
    pub const fn new(key_id: Uuid, org_id: Option<Uuid>) -> Self {
        Self { key_id, org_id }
    }

    /// `TAG || key_id (16 bytes) || 0x00` for the global DEK, or
    /// `TAG || key_id || 0x01 || org_id (16 bytes)` for an org DEK.
    ///
    /// Fixed-width fields behind an explicit scope byte, so no two identities
    /// share an encoding. UUID bytes are the RFC 4122 (big-endian) order.
    #[must_use]
    pub fn bound_aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(DEK_WRAP_AAD_TAG.len() + 16 + 1 + 16);
        aad.extend_from_slice(DEK_WRAP_AAD_TAG);
        aad.extend_from_slice(self.key_id.as_bytes());
        match self.org_id {
            None => aad.push(0x00),
            Some(org_id) => {
                aad.push(0x01);
                aad.extend_from_slice(org_id.as_bytes());
            }
        }
        aad
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: Uuid = Uuid::from_u128(0x1111_1111_1111_1111_1111_1111_1111_1111);
    const B: Uuid = Uuid::from_u128(0x2222_2222_2222_2222_2222_2222_2222_2222);

    #[test]
    fn the_encoding_is_pinned() {
        let global = DekRowIdentity::new(A, None).bound_aad();
        let mut expected = b"talos-dek-wrap/v2".to_vec();
        expected.extend([0x11; 16]);
        expected.push(0x00);
        assert_eq!(global, expected);

        let org = DekRowIdentity::new(A, Some(B)).bound_aad();
        let mut expected = b"talos-dek-wrap/v2".to_vec();
        expected.extend([0x11; 16]);
        expected.push(0x01);
        expected.extend([0x22; 16]);
        assert_eq!(org, expected);
    }

    #[test]
    fn every_part_of_the_identity_changes_the_aad() {
        let base = DekRowIdentity::new(A, Some(B)).bound_aad();
        assert_ne!(base, DekRowIdentity::new(B, Some(B)).bound_aad(), "key id");
        assert_ne!(base, DekRowIdentity::new(A, Some(A)).bound_aad(), "org id");
        assert_ne!(base, DekRowIdentity::new(A, None).bound_aad(), "scope");
    }

    #[test]
    fn only_a_bound_wrap_is_accepted() {
        assert!(ensure_bound(BOUND_WRAP_FORMAT).is_ok());
        for refused in [0, 1, 3] {
            assert!(ensure_bound(refused).is_err(), "format {refused}");
        }
    }
}
