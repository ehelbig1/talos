// MCP-943 (2026-05-15): kept `#![allow(dead_code)]` deliberately. The
// crate is a documented placeholder per MCP-704 (controller/src/main.rs
// around line 900): `SecretsRotation::new()` is NOT wired into
// controller boot — actual rotation lives in `SecretsManager::
// rotate_master_key` / `rotate_dek` and runs only when invoked
// manually. The in-memory `KeyVersion` tracker never persists
// anywhere. Removing the attribute would surface dead-field /
// dead-method warnings without operator-actionable cleanup until a
// real automatic-rotation implementation lands. Sibling of
// talos-feature-flags / talos-tenancy placeholder retention.
#![allow(dead_code)]
//! Automatic secrets rotation with zero-downtime transitions.
//!
//! Supports rotation of:
//! - JWT signing keys
//! - Encryption keys (DEKs, master key)
//! - API keys
//! - Database credentials

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use uuid::Uuid;

/// Key rotation policy
#[derive(Debug, Clone)]
pub struct RotationPolicy {
    /// Rotation interval
    pub interval: Duration,
    /// Grace period (old key still valid)
    pub grace_period: Duration,
    /// Auto-rotate enabled
    pub auto_rotate: bool,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            interval: Duration::days(90),
            grace_period: Duration::days(7),
            auto_rotate: true,
        }
    }
}

/// Key version metadata
#[derive(Debug, Clone)]
pub struct KeyVersion {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub is_primary: bool,
    pub algorithm: String,
}

/// Secrets rotation manager
pub struct SecretsRotation {
    keys: HashMap<String, Vec<KeyVersion>>,
}

impl SecretsRotation {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// Rotate JWT signing key
    pub fn rotate_jwt_key(&mut self) -> Result<KeyVersion> {
        // Mark current as expiring
        if let Some(versions) = self.keys.get_mut("jwt") {
            for v in versions.iter_mut() {
                v.is_primary = false;
            }
        }

        // Create new primary
        let new_key = KeyVersion {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            expires_at: None,
            is_primary: true,
            algorithm: "HS256".to_string(),
        };

        self.keys
            .entry("jwt".to_string())
            .or_default()
            .push(new_key.clone());

        Ok(new_key)
    }

    /// Get current primary key
    pub fn get_primary_key(&self, key_type: &str) -> Option<&KeyVersion> {
        self.keys
            .get(key_type)?
            .iter()
            .find(|k| k.is_primary && !self.is_expired(k))
    }

    fn is_expired(&self, key: &KeyVersion) -> bool {
        key.expires_at.map(|exp| Utc::now() > exp).unwrap_or(false)
    }
}

impl Default for SecretsRotation {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default policy is the documented 90-day interval / 7-day grace /
    /// auto-rotate-on posture. Locked in so a silent default change (e.g. a
    /// refactor flipping `auto_rotate` to false) surfaces at test time — when
    /// the placeholder is eventually wired into controller boot (MCP-704),
    /// these defaults become operator-visible behavior.
    #[test]
    fn default_policy_is_90d_interval_7d_grace_auto_on() {
        let policy = RotationPolicy::default();
        assert_eq!(policy.interval, Duration::days(90));
        assert_eq!(policy.grace_period, Duration::days(7));
        assert!(policy.auto_rotate);
    }

    /// Missing-key error path: a manager that has never rotated has no
    /// primary key for any key type.
    #[test]
    fn fresh_manager_has_no_primary_key() {
        let rotation = SecretsRotation::new();
        assert!(rotation.get_primary_key("jwt").is_none());
        assert!(rotation.get_primary_key("dek").is_none());
        assert!(rotation.get_primary_key("").is_none());
    }

    /// `Default` must behave identically to `new()` (both start empty).
    #[test]
    fn default_impl_matches_new() {
        let rotation = SecretsRotation::default();
        assert!(rotation.keys.is_empty());
        assert!(rotation.get_primary_key("jwt").is_none());
    }

    /// First rotation creates exactly one version, marked primary, with the
    /// expected algorithm and no expiry, and `get_primary_key` returns it.
    #[test]
    fn first_rotation_creates_single_primary() {
        let mut rotation = SecretsRotation::new();
        let created = rotation.rotate_jwt_key().expect("rotation succeeds");
        assert!(created.is_primary);
        assert_eq!(created.algorithm, "HS256");
        assert!(created.expires_at.is_none());

        let primary = rotation
            .get_primary_key("jwt")
            .expect("primary exists after rotation");
        assert_eq!(primary.id, created.id);
        assert_eq!(rotation.keys["jwt"].len(), 1);
    }

    /// Key-version transition: a second rotation demotes the prior primary.
    /// Exactly one version is primary afterwards, and it is the NEW one —
    /// the zero-downtime invariant (`get_primary_key` never returns a
    /// rotated-out key, never returns two candidates).
    #[test]
    fn rotation_demotes_prior_primary_exactly_one_primary_remains() {
        let mut rotation = SecretsRotation::new();
        let first = rotation.rotate_jwt_key().unwrap();
        let second = rotation.rotate_jwt_key().unwrap();
        assert_ne!(first.id, second.id, "each rotation mints a fresh key id");

        let versions = &rotation.keys["jwt"];
        assert_eq!(
            versions.len(),
            2,
            "old key is retained for grace-period reads"
        );
        let primaries: Vec<_> = versions.iter().filter(|v| v.is_primary).collect();
        assert_eq!(primaries.len(), 1, "exactly one primary after rotation");
        assert_eq!(primaries[0].id, second.id, "the NEW key is the primary");

        let resolved = rotation.get_primary_key("jwt").unwrap();
        assert_eq!(resolved.id, second.id);
    }

    /// Idempotency of re-running rotation: N rotations always leave the
    /// manager in a consistent state — N retained versions, exactly one
    /// primary, and `get_primary_key` resolves to the most recent rotation's
    /// key every time. Re-running rotation never corrupts the version chain.
    #[test]
    fn repeated_rotation_keeps_single_primary_invariant() {
        let mut rotation = SecretsRotation::new();
        let mut last_id = None;
        for n in 1..=10 {
            let created = rotation.rotate_jwt_key().unwrap();
            last_id = Some(created.id);
            let versions = &rotation.keys["jwt"];
            assert_eq!(versions.len(), n, "every rotation retains prior versions");
            assert_eq!(
                versions.iter().filter(|v| v.is_primary).count(),
                1,
                "exactly one primary after rotation {n}"
            );
            assert_eq!(rotation.get_primary_key("jwt").unwrap().id, created.id);
        }
        assert_eq!(
            rotation.get_primary_key("jwt").unwrap().id,
            last_id.unwrap()
        );
    }

    /// An expired primary must NOT be returned — the expiry gate inside
    /// `get_primary_key` fails closed rather than serving a stale key.
    #[test]
    fn get_primary_key_ignores_expired_primary() {
        let mut rotation = SecretsRotation::new();
        rotation.keys.insert(
            "jwt".to_string(),
            vec![KeyVersion {
                id: Uuid::new_v4(),
                created_at: Utc::now() - Duration::days(100),
                expires_at: Some(Utc::now() - Duration::hours(1)),
                is_primary: true,
                algorithm: "HS256".to_string(),
            }],
        );
        assert!(
            rotation.get_primary_key("jwt").is_none(),
            "an expired primary must not be served"
        );
    }

    /// A primary with a FUTURE expiry is still valid and must be returned
    /// (the grace-period window shape: expiring-but-not-yet-expired).
    #[test]
    fn get_primary_key_returns_future_expiring_primary() {
        let mut rotation = SecretsRotation::new();
        let id = Uuid::new_v4();
        rotation.keys.insert(
            "jwt".to_string(),
            vec![KeyVersion {
                id,
                created_at: Utc::now(),
                expires_at: Some(Utc::now() + Duration::days(7)),
                is_primary: true,
                algorithm: "HS256".to_string(),
            }],
        );
        assert_eq!(rotation.get_primary_key("jwt").unwrap().id, id);
    }

    /// Malformed-record shape: a version list where NOTHING is primary (e.g.
    /// state persisted mid-rotation by a future implementation) resolves to
    /// `None` rather than arbitrarily promoting a non-primary key.
    #[test]
    fn version_list_without_primary_resolves_to_none() {
        let mut rotation = SecretsRotation::new();
        rotation.keys.insert(
            "jwt".to_string(),
            vec![KeyVersion {
                id: Uuid::new_v4(),
                created_at: Utc::now(),
                expires_at: None,
                is_primary: false,
                algorithm: "HS256".to_string(),
            }],
        );
        assert!(rotation.get_primary_key("jwt").is_none());
    }

    /// Rotation only touches the "jwt" key family — versions registered
    /// under other key types keep their primary flag untouched.
    #[test]
    fn jwt_rotation_does_not_demote_other_key_types() {
        let mut rotation = SecretsRotation::new();
        let dek_id = Uuid::new_v4();
        rotation.keys.insert(
            "dek".to_string(),
            vec![KeyVersion {
                id: dek_id,
                created_at: Utc::now(),
                expires_at: None,
                is_primary: true,
                algorithm: "AES-256-GCM".to_string(),
            }],
        );
        rotation.rotate_jwt_key().unwrap();
        assert_eq!(
            rotation.get_primary_key("dek").unwrap().id,
            dek_id,
            "rotating jwt must not demote the dek primary"
        );
    }

    /// GAP (documented placeholder behavior, not fixed here): `rotate_jwt_key`'s
    /// comment says "Mark current as expiring", but it only clears `is_primary`
    /// — it never stamps `expires_at` on the demoted key. Consequently
    /// `RotationPolicy::grace_period` is never applied and rotated-out keys
    /// remain non-expired (valid for verification) FOREVER, not just for the
    /// grace window. Consistent with the crate-level MCP-704 placeholder note
    /// (`SecretsRotation` is not wired into controller boot), but a real
    /// implementation must stamp `expires_at = now + grace_period` on demotion.
    /// This test locks in the CURRENT behavior so the gap is visible.
    #[test]
    fn rotated_out_keys_are_never_expired_grace_period_unenforced() {
        let mut rotation = SecretsRotation::new();
        let first = rotation.rotate_jwt_key().unwrap();
        rotation.rotate_jwt_key().unwrap();

        let old = rotation.keys["jwt"]
            .iter()
            .find(|v| v.id == first.id)
            .expect("demoted key retained");
        assert!(!old.is_primary, "demoted key loses primary");
        assert!(
            old.expires_at.is_none(),
            "current behavior: demotion does NOT stamp expires_at (grace period unenforced)"
        );
    }
}
