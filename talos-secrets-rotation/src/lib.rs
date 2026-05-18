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
