// MCP-940 (2026-05-15): kept `#![allow(dead_code)]` deliberately here.
// The crate is a documented placeholder — see MCP-705 in controller/src/
// main.rs around line 866: `FeatureFlagService::new(db_pool)` is NOT
// wired into controller boot, and `load_flag` is a stub returning
// `Ok(None)` (no migration, no DB layer). The `db_pool` and `cache`
// struct fields, plus several `pub fn` methods, are genuinely unused
// until a real implementation lands. Removing the attribute would
// surface those warnings on every workspace build without any
// operator-actionable cleanup — the path forward is to land the real
// implementation, not to delete the placeholder struct (which a
// future caller will need to seat against).
#![allow(dead_code)]
//! Feature flags service for gradual rollouts and A/B testing.
//!
//! Supports:
//! - Boolean flags (on/off)
//! - Percentage rollouts (X% of users)
//! - User-based targeting
//! - Tenant-based targeting

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Feature flag value types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum FlagValue {
    Boolean { enabled: bool },
    Percentage { percent: u8, seed: String },
    UserList { users: Vec<Uuid> },
    TenantList { tenants: Vec<Uuid> },
}

/// Feature flag definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureFlag {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub value: FlagValue,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: Uuid,
}

/// Feature flag service
pub struct FeatureFlagService {
    db_pool: Pool<Postgres>,
    cache: Arc<RwLock<HashMap<String, FeatureFlag>>>,
}

impl FeatureFlagService {
    /// Create new service
    pub fn new(db_pool: Pool<Postgres>) -> Self {
        Self {
            db_pool,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check if flag is enabled for user/tenant
    pub async fn is_enabled(
        &self,
        name: &str,
        user_id: Option<Uuid>,
        tenant_id: Option<Uuid>,
    ) -> Result<bool> {
        let flag = self.load_flag(name).await?;

        Ok(flag
            .map(|f| self.evaluate_flag(&f, user_id, tenant_id))
            .unwrap_or(false))
    }

    /// Evaluate flag value
    fn evaluate_flag(
        &self,
        flag: &FeatureFlag,
        user_id: Option<Uuid>,
        tenant_id: Option<Uuid>,
    ) -> bool {
        match &flag.value {
            FlagValue::Boolean { enabled } => *enabled,
            FlagValue::Percentage { percent, seed } => {
                if let Some(uid) = user_id {
                    let hash = Self::hash_user_id(uid, seed);
                    (hash % 100) < *percent as u64
                } else {
                    false
                }
            }
            FlagValue::UserList { users } => {
                user_id.map(|uid| users.contains(&uid)).unwrap_or(false)
            }
            FlagValue::TenantList { tenants } => {
                tenant_id.map(|tid| tenants.contains(&tid)).unwrap_or(false)
            }
        }
    }

    /// Hash user ID for percentage rollout.
    ///
    /// Uses SHA-256 over (uuid_bytes || seed_bytes), folded to u64 via the first
    /// 8 bytes of the digest. MUST be deterministic across:
    ///   * process restarts (same user lands in the same bucket after deploy)
    ///   * multi-instance deployments (every replica answers the same)
    ///   * individual requests within a session
    ///
    /// `std::collections::hash_map::DefaultHasher` is SipHash with a
    /// process-randomized key, so it produces a *different* answer in every
    /// process and breaks the percentage-rollout determinism contract. A user
    /// who happens to be in the "rolled-out 50%" bucket on one pod would flip
    /// to the "not yet" bucket on another — features would appear and
    /// disappear depending on which replica served the request. SHA-256 is
    /// keyless and cryptographically stable.
    fn hash_user_id(user_id: Uuid, seed: &str) -> u64 {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(user_id.as_bytes());
        hasher.update(seed.as_bytes());
        let digest = hasher.finalize();
        let bytes: [u8; 8] = digest[..8]
            .try_into()
            .expect("SHA-256 always yields 32 bytes");
        u64::from_be_bytes(bytes)
    }

    /// Load flag from database
    async fn load_flag(&self, _name: &str) -> Result<Option<FeatureFlag>> {
        // Placeholder - would query database
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flag_value_boolean_serialization() {
        let flag = FeatureFlag {
            id: Uuid::new_v4(),
            name: "dark-mode".to_string(),
            description: "Enable dark mode".to_string(),
            value: FlagValue::Boolean { enabled: true },
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: Uuid::new_v4(),
        };

        let json = serde_json::to_value(&flag).unwrap();
        assert_eq!(json["name"], "dark-mode");
        assert_eq!(json["value"]["type"], "Boolean");
        assert_eq!(json["value"]["value"]["enabled"], true);

        // Round-trip deserialization
        let deserialized: FeatureFlag = serde_json::from_value(json).unwrap();
        assert_eq!(deserialized.name, "dark-mode");
        match deserialized.value {
            FlagValue::Boolean { enabled } => assert!(enabled),
            _ => panic!("Expected Boolean variant"),
        }
    }

    #[test]
    fn test_flag_value_percentage_serialization() {
        let flag_value = FlagValue::Percentage {
            percent: 50,
            seed: "test-seed".to_string(),
        };
        let json = serde_json::to_value(&flag_value).unwrap();
        assert_eq!(json["type"], "Percentage");
        assert_eq!(json["value"]["percent"], 50);

        let deserialized: FlagValue = serde_json::from_value(json).unwrap();
        match deserialized {
            FlagValue::Percentage { percent, seed } => {
                assert_eq!(percent, 50);
                assert_eq!(seed, "test-seed");
            }
            _ => panic!("Expected Percentage variant"),
        }
    }

    #[test]
    fn test_hash_user_id_is_deterministic_within_process() {
        let uid = Uuid::parse_str("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap();
        let a = FeatureFlagService::hash_user_id(uid, "rollout-seed");
        let b = FeatureFlagService::hash_user_id(uid, "rollout-seed");
        assert_eq!(a, b, "same input must produce same hash");
    }

    #[test]
    fn test_hash_user_id_is_stable_across_versions() {
        // Pinning known-vector: if this assertion breaks, we have silently
        // re-bucketed every user in every rollout. Bumping the hash function
        // must be a deliberate, versioned migration — not an accidental
        // refactor — so this test guards the rollout-determinism contract.
        let uid = Uuid::parse_str("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap();
        let h = FeatureFlagService::hash_user_id(uid, "rollout-seed");
        // SHA-256(uuid_bytes || "rollout-seed")[..8] big-endian:
        assert_eq!(h, 0x9ac0_d2a7_270e_75fb);
    }

    #[test]
    fn test_hash_user_id_seed_changes_bucket() {
        let uid = Uuid::parse_str("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap();
        let a = FeatureFlagService::hash_user_id(uid, "seed-a");
        let b = FeatureFlagService::hash_user_id(uid, "seed-b");
        assert_ne!(a, b, "different seed must produce different hash");
    }

    #[test]
    fn test_percentage_bucket_is_stable() {
        // Repeated evaluations of the rollout-bucket math must collapse to a
        // single answer. With DefaultHasher this loop could flake mid-run
        // (different SipHash key each call would mean a random 0..99 each
        // iteration); under SHA-256 every iteration produces the same bucket.
        let uid = Uuid::parse_str("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap();
        let bucket = |u| FeatureFlagService::hash_user_id(u, "stable-seed") % 100;
        let first = bucket(uid);
        for _ in 0..10 {
            assert_eq!(bucket(uid), first);
        }
    }

    #[test]
    fn test_flag_value_user_list_serialization() {
        let user_id = Uuid::new_v4();
        let flag_value = FlagValue::UserList {
            users: vec![user_id],
        };
        let json = serde_json::to_value(&flag_value).unwrap();
        assert_eq!(json["type"], "UserList");

        let deserialized: FlagValue = serde_json::from_value(json).unwrap();
        match deserialized {
            FlagValue::UserList { users } => {
                assert_eq!(users.len(), 1);
                assert_eq!(users[0], user_id);
            }
            _ => panic!("Expected UserList variant"),
        }
    }
}
