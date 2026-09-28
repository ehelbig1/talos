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

/// How a stored `encryption_keys.encrypted_key` was wrapped
/// (`encryption_keys.wrap_format`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapFormat {
    /// `1`: no associated data — every row written before RFC 0013.
    Unbound,
    /// `2`: bound to the row's `(id, org_id)` via [`DekRowIdentity::bound_aad`].
    Bound,
}

impl WrapFormat {
    /// Parse the stored column. An unknown value is an error, never a guess:
    /// reading it as either format would be choosing an AAD for a row nobody
    /// knows how to read.
    pub fn from_db(value: i16) -> Result<Self> {
        match value {
            1 => Ok(Self::Unbound),
            2 => Ok(Self::Bound),
            other => Err(anyhow!("unknown encryption_keys.wrap_format {other}")),
        }
    }

    /// The stored column value.
    #[must_use]
    pub const fn as_db(self) -> i16 {
        match self {
            Self::Unbound => 1,
            Self::Bound => 2,
        }
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

    /// The AAD a row stored in `format` was wrapped with: empty for
    /// [`WrapFormat::Unbound`] (byte-identical to the pre-RFC wrap).
    #[must_use]
    pub fn aad_for(&self, format: WrapFormat) -> Vec<u8> {
        match format {
            WrapFormat::Unbound => Vec::new(),
            WrapFormat::Bound => self.bound_aad(),
        }
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
    fn unbound_rows_read_with_an_empty_aad() {
        let id = DekRowIdentity::new(A, Some(B));
        assert!(id.aad_for(WrapFormat::Unbound).is_empty());
        assert_eq!(id.aad_for(WrapFormat::Bound), id.bound_aad());
    }

    #[test]
    fn the_column_round_trips_and_refuses_unknown_values() {
        for f in [WrapFormat::Unbound, WrapFormat::Bound] {
            assert_eq!(WrapFormat::from_db(f.as_db()).unwrap(), f);
        }
        assert!(WrapFormat::from_db(0).is_err());
        assert!(WrapFormat::from_db(3).is_err());
    }
}
