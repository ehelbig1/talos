//! `vault://` reference resolution utilities shared across MCP handlers and the engine.
//!
//! This module centralizes the logic for:
//! 1. Extracting `vault://<path>` references from a JSON config object.
//! 2. Replacing those references with the resolved plaintext secret values
//!    in the payload (top-level, `"config"` sub-object, and `"input"` sub-object).
//!
//! Why centralize? Previously, `run_sandbox`, `test_module`, and the engine
//! each had their own inline extraction loops. Divergence between them caused
//! modules to behave differently across execution paths (e.g., `run_sandbox`
//! passing literal `"vault://..."` strings to the module, while `test_module`
//! and the engine injected plaintext). This module guarantees identical
//! behavior everywhere.
//!
//! Runtime enforcement of `allowed_secrets` is in `worker/src/host_impl.rs`
//! via `talos_workflow_job_protocol::vault_path_permitted` — callers here are responsible
//! for fetching the permitted secrets and passing them to `replace_vault_values`.

use std::collections::HashMap;
use std::fmt;

/// A detected `vault://` reference in a config object: `(config_key, vault_path)`.
///
/// `vault_path` is the path with the `vault://` prefix already stripped,
/// matching the form stored in the vault and accepted by
/// `SecretsManager::get_secrets_by_paths`.
pub type VaultRef = (String, String);

/// Error returned from [`replace_vault_values`] when a referenced
/// secret cannot be substituted.
///
/// Matching on the variant is stable across 0.x releases; display
/// output is informational and may change. The enum is
/// `#[non_exhaustive]` so future variants are additive.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VaultResolverError {
    /// A `vault://<path>` reference in `refs` was not present in the
    /// `resolved` map. Typical causes: the secret hasn't been set,
    /// the path is misspelled, or the caller forgot to include the
    /// path in the allowlist passed to
    /// `SecretsManager::get_secrets_by_paths`.
    SecretNotResolved {
        /// The config key whose value referenced the missing secret.
        config_key: String,
        /// The vault path (prefix stripped) that failed to resolve.
        vault_path: String,
    },
}

impl fmt::Display for VaultResolverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SecretNotResolved {
                config_key,
                vault_path,
            } => write!(
                f,
                "Config key '{config_key}' references vault://{vault_path} but the secret \
                 could not be resolved. Ensure the secret exists (set_secret) and the path \
                 is correct."
            ),
        }
    }
}

impl std::error::Error for VaultResolverError {}

/// Extract every `vault://<path>` reference from the top-level string values
/// of a JSON config object. Malformed refs (empty path after prefix) are skipped.
///
/// Only scans top-level keys — nested objects are not recursed into, matching
/// the engine's dispatch convention where node config is a flat key/value map.
pub fn extract_vault_refs(config: &serde_json::Value) -> Vec<VaultRef> {
    let mut refs = Vec::new();
    if let Some(obj) = config.as_object() {
        for (k, v) in obj {
            if let Some(val_str) = v.as_str() {
                if let Some(path) = val_str.strip_prefix("vault://") {
                    if !path.is_empty() {
                        refs.push((k.clone(), path.to_string()));
                    }
                }
            }
        }
    }
    refs
}

/// Replace `vault://<path>` references in the payload with their resolved
/// plaintext values. Substitutes in three locations to cover both the
/// caller-supplied input shape and the engine's dispatch convention:
///   - Top-level payload keys (e.g. `payload["AUTH_HEADER"]`)
///   - `payload["config"]["AUTH_HEADER"]` (standard config sub-object)
///   - `payload["input"]["AUTH_HEADER"]` (upstream-output convention)
///
/// Returns [`VaultResolverError::SecretNotResolved`] if any `vault_path`
/// in `refs` is absent from `resolved` — so the developer sees
/// "secret not found" instead of a confusing downstream failure.
pub fn replace_vault_values(
    payload: &mut serde_json::Value,
    resolved: &HashMap<String, String>,
    refs: &[VaultRef],
) -> Result<(), VaultResolverError> {
    for (config_key, vault_path) in refs {
        let plaintext = resolved.get(vault_path.as_str()).ok_or_else(|| {
            VaultResolverError::SecretNotResolved {
                config_key: config_key.clone(),
                vault_path: vault_path.clone(),
            }
        })?;
        let resolved_value = serde_json::Value::String(plaintext.clone());

        if let Some(obj) = payload.as_object_mut() {
            // Top-level replacement
            if obj
                .get(config_key)
                .and_then(|v| v.as_str())
                .map(|s| s.starts_with("vault://"))
                .unwrap_or(false)
            {
                obj.insert(config_key.clone(), resolved_value.clone());
            }
            // "config" sub-object replacement
            if let Some(cfg) = obj.get_mut("config").and_then(|c| c.as_object_mut()) {
                if cfg
                    .get(config_key)
                    .and_then(|v| v.as_str())
                    .map(|s| s.starts_with("vault://"))
                    .unwrap_or(false)
                {
                    cfg.insert(config_key.clone(), resolved_value.clone());
                }
            }
            // "input" sub-object replacement (upstream-convention)
            if let Some(inp) = obj.get_mut("input").and_then(|c| c.as_object_mut()) {
                if inp
                    .get(config_key)
                    .and_then(|v| v.as_str())
                    .map(|s| s.starts_with("vault://"))
                    .unwrap_or(false)
                {
                    inp.insert(config_key.clone(), resolved_value);
                }
            }
        }
    }
    Ok(())
}

/// Augment an `allowed_secrets` list with every vault path found in `refs`,
/// deduplicating. Returns a new list ready to pass to `get_secrets_by_paths`.
///
/// Used by sandbox handlers so that callers who pass `vault://...` directly
/// in config (without pre-declaring it in `allowed_secrets`) still get the
/// secret fetched for them.
pub fn merge_vault_refs_into_allowlist(
    mut allowed_secrets: Vec<String>,
    refs: &[VaultRef],
) -> Vec<String> {
    for (_key, vault_path) in refs {
        if !allowed_secrets.contains(vault_path) {
            allowed_secrets.push(vault_path.clone());
        }
    }
    allowed_secrets
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extract_finds_top_level_vault_refs() {
        let cfg = json!({
            "AUTH_HEADER": "vault://oauth/gmail/token",
            "MAX_RESULTS": "10",
            "API_KEY": "vault://anthropic/api_key",
            "URL": "https://example.com"
        });
        let refs = extract_vault_refs(&cfg);
        assert_eq!(refs.len(), 2);
        assert!(refs
            .iter()
            .any(|(k, p)| k == "AUTH_HEADER" && p == "oauth/gmail/token"));
        assert!(refs
            .iter()
            .any(|(k, p)| k == "API_KEY" && p == "anthropic/api_key"));
    }

    #[test]
    fn extract_skips_empty_path() {
        // "vault://" with no path after is malformed — should not be included.
        let cfg = json!({ "BROKEN": "vault://" });
        let refs = extract_vault_refs(&cfg);
        assert!(refs.is_empty());
    }

    #[test]
    fn extract_ignores_non_strings() {
        let cfg = json!({ "MAX": 10, "ENABLED": true });
        let refs = extract_vault_refs(&cfg);
        assert!(refs.is_empty());
    }

    #[test]
    fn replace_substitutes_top_level() {
        let mut payload = json!({
            "AUTH_HEADER": "vault://oauth/gmail/token",
            "URL": "https://example.com"
        });
        let refs = vec![("AUTH_HEADER".to_string(), "oauth/gmail/token".to_string())];
        let mut resolved = HashMap::new();
        resolved.insert(
            "oauth/gmail/token".to_string(),
            "actual-token-value".to_string(),
        );

        replace_vault_values(&mut payload, &resolved, &refs).unwrap();
        assert_eq!(
            payload["AUTH_HEADER"].as_str().unwrap(),
            "actual-token-value"
        );
        assert_eq!(payload["URL"].as_str().unwrap(), "https://example.com");
    }

    #[test]
    fn replace_substitutes_in_config_subobject() {
        let mut payload = json!({
            "config": {
                "AUTH_HEADER": "vault://oauth/gmail/token",
                "MAX": "10"
            }
        });
        let refs = vec![("AUTH_HEADER".to_string(), "oauth/gmail/token".to_string())];
        let mut resolved = HashMap::new();
        resolved.insert("oauth/gmail/token".to_string(), "actual-token".to_string());

        replace_vault_values(&mut payload, &resolved, &refs).unwrap();
        assert_eq!(
            payload["config"]["AUTH_HEADER"].as_str().unwrap(),
            "actual-token"
        );
        assert_eq!(payload["config"]["MAX"].as_str().unwrap(), "10");
    }

    #[test]
    fn replace_returns_error_when_secret_missing() {
        let mut payload = json!({ "AUTH_HEADER": "vault://missing/path" });
        let refs = vec![("AUTH_HEADER".to_string(), "missing/path".to_string())];
        let resolved = HashMap::new();

        let err = replace_vault_values(&mut payload, &resolved, &refs)
            .expect_err("missing secret must error");
        // The enum is `#[non_exhaustive]` and carries only `SecretNotResolved`
        // today; the bare `match` still compiles if new variants land, at
        // which point this test should expand.
        match &err {
            VaultResolverError::SecretNotResolved {
                config_key,
                vault_path,
            } => {
                assert_eq!(config_key, "AUTH_HEADER");
                assert_eq!(vault_path, "missing/path");
            }
        }
        // Display still carries both fields for human-readable logs.
        let rendered = format!("{err}");
        assert!(rendered.contains("AUTH_HEADER"));
        assert!(rendered.contains("missing/path"));
    }

    #[test]
    fn merge_dedupes_paths() {
        let allowed = vec!["oauth/gmail".to_string()];
        let refs = vec![
            ("A".to_string(), "oauth/gmail".to_string()), // duplicate
            ("B".to_string(), "anthropic/api_key".to_string()),
        ];
        let merged = merge_vault_refs_into_allowlist(allowed, &refs);
        assert_eq!(merged.len(), 2);
        assert!(merged.contains(&"oauth/gmail".to_string()));
        assert!(merged.contains(&"anthropic/api_key".to_string()));
    }
}
