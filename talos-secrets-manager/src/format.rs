//! Typed on-disk AEAD format versions.
//!
//! Pre-extraction (2026-07-24) the v0–v4 format dispatch lived as raw
//! `i16` comparisons against five associated constants, repeated at
//! each decrypt dispatcher with subtly different accepted sets (the
//! `secrets` table never accepts v2; the generic path does). That was
//! fail-closed but not exhaustive: adding a v5 required *remembering*
//! every dispatch site. [`SecretFormat`] makes the format a closed
//! enum — every `match` on it is compiler-checked, so a new variant
//! forces every dispatch site to decide its routing explicitly.
//!
//! The numeric constants remain the cross-crate public surface (the
//! per-table `*_format` columns and their CHECK constraints speak
//! `i16`); they are defined FROM the enum so the two can never drift.
//!
//! Doc detail for each format's crypto semantics lives on the
//! constants in `manager.rs` (v3's birthday-bound rationale, v4's
//! per-org DEK isolation) — this module only owns identity + routing.

use crate::SecretsError;

/// A known on-disk AEAD format version. Constructing one is only
/// possible through [`SecretFormat::from_version`], which fails closed
/// on anything unknown — so holding a `SecretFormat` is proof the
/// version was validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretFormat {
    /// v0 — legacy AES-GCM under the DEK, no AAD.
    V0Legacy,
    /// v1 — AAD-bound (row id) under the DEK.
    V1Aad,
    /// v2 — AAD-bound with a caller-reconstructed per-slot tag folded
    /// into the AAD. Module-payload bundles only; identical to v1 at
    /// the crypto layer.
    V2AadSlotTagged,
    /// v3 — AAD-bound AND per-context HKDF-derived subkey of the
    /// GLOBAL DEK.
    V3Derived,
    /// v4 — v3's derivation with a per-ORGANIZATION root DEK as IKM.
    /// Decrypts identically to v3 (the row's `key_id` names the DEK).
    V4OrgDerived,
}

/// How a validated format routes at DECRYPT time. v1/v2 are identical
/// at the crypto layer (caller-supplied AAD under the DEK); v3/v4 are
/// identical (per-context derived subkey, DEK resolved by the row's
/// `key_id`). Collapsing the pairs here keeps the dispatchers honest:
/// the routing equivalence is stated once, not re-derived per site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptRoute {
    /// Decrypt under the DEK with empty AAD (v0).
    LegacyNoAad,
    /// Decrypt under the DEK with the caller-supplied AAD (v1, v2).
    CallerAad,
    /// Derive the per-context subkey from the DEK named by `key_id`,
    /// then decrypt with the caller-supplied AAD (v3, v4).
    DerivedAad,
}

impl SecretFormat {
    /// Validate a raw per-row format column value. Fails closed with
    /// [`SecretsError::UnknownFormat`] on anything outside v0–v4 —
    /// including negatives — preserving the 2026-05-28 audit S2#9
    /// posture (a v(N)-reader against a v(N+1)-writer must surface
    /// loudly at dispatch, never mis-decrypt silently).
    pub fn from_version(v: i16) -> Result<Self, SecretsError> {
        match v {
            0 => Ok(Self::V0Legacy),
            1 => Ok(Self::V1Aad),
            2 => Ok(Self::V2AadSlotTagged),
            3 => Ok(Self::V3Derived),
            4 => Ok(Self::V4OrgDerived),
            other => Err(SecretsError::UnknownFormat(other)),
        }
    }

    /// The on-disk column value for this format.
    pub const fn as_version(self) -> i16 {
        match self {
            Self::V0Legacy => 0,
            Self::V1Aad => 1,
            Self::V2AadSlotTagged => 2,
            Self::V3Derived => 3,
            Self::V4OrgDerived => 4,
        }
    }

    /// Crypto-layer decrypt routing (see [`DecryptRoute`]).
    pub const fn decrypt_route(self) -> DecryptRoute {
        match self {
            Self::V0Legacy => DecryptRoute::LegacyNoAad,
            Self::V1Aad | Self::V2AadSlotTagged => DecryptRoute::CallerAad,
            Self::V3Derived | Self::V4OrgDerived => DecryptRoute::DerivedAad,
        }
    }
}

#[cfg(test)]
mod format_tests {
    use super::*;

    #[test]
    fn round_trips_every_known_version() {
        for v in 0..=4i16 {
            let f = SecretFormat::from_version(v).expect("known version");
            assert_eq!(f.as_version(), v);
        }
    }

    #[test]
    fn unknown_versions_fail_closed() {
        for v in [-1i16, 5, 99, i16::MAX, i16::MIN] {
            let err = SecretFormat::from_version(v).expect_err("unknown must fail");
            assert!(
                matches!(err, SecretsError::UnknownFormat(x) if x == v),
                "expected UnknownFormat({v}); got {err:?}"
            );
        }
    }

    #[test]
    fn routing_collapses_the_documented_pairs() {
        use DecryptRoute::*;
        assert_eq!(SecretFormat::V0Legacy.decrypt_route(), LegacyNoAad);
        assert_eq!(SecretFormat::V1Aad.decrypt_route(), CallerAad);
        assert_eq!(SecretFormat::V2AadSlotTagged.decrypt_route(), CallerAad);
        assert_eq!(SecretFormat::V3Derived.decrypt_route(), DerivedAad);
        assert_eq!(SecretFormat::V4OrgDerived.decrypt_route(), DerivedAad);
    }
}
