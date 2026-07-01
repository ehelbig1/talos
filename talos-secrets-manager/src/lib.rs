//! Envelope-encryption secrets manager for the Talos platform.
//!
//! This crate is the transport-free core of the SecretsManager. It owns:
//! * the `SecretsManager` struct (DEK cache, LLM-keys cache, encrypt/decrypt
//!   primitives, master-key rotation),
//! * the [`kek_provider::KekProvider`] trait + `EnvKekProvider` (local
//!   AES-GCM wrap/unwrap of DEKs),
//! * [`vault_kek_provider::VaultTransitProvider`] (HashiCorp Vault Transit
//!   wrap/unwrap),
//! * [`kek_rewrap`] (Phase 4 dual-wrap soak helpers).
//!
//! Two pieces stay in the controller crate because they pull in transport
//! / domain concerns this crate intentionally avoids:
//! * `controller::secrets::handlers` — axum HTTP handlers.
//! * `controller::secrets::resolver::ControllerSecretsResolver` — the
//!   OAuth-aware resolver (depends on `OAuthCredentialService`, which
//!   itself depends on this crate; keeping the resolver in controller
//!   avoids a circular workspace dep until the OAuth crate is extracted).
//!
//! `vault_resolver` (string-substitution helpers for `vault://` references
//! inside workflow node configs) lives in `talos-workflow-engine` and is
//! re-exported by `controller::secrets::vault_resolver` for convenience.

pub mod integration_state_crypto;
pub mod kek_provider;
pub mod kek_rewrap;
pub mod provider;
pub mod vault_kek_provider;

mod identifier;
mod manager;

pub use identifier::{SecretIdentifier, SecretResolveError};
pub use manager::*;

/// MCP-1150 (2026-05-16): canonical vault key_path validator.
///
/// MCP-1201 (2026-05-17): MCP secret-write handlers were removed; the
/// only remaining caller is `talos-api::validation::validate_vault_key_path`
/// for the GraphQL create/update/delete secret mutations. The helper
/// is kept here (rather than inlined into talos-api) because the
/// secrets-manager crate is the canonical home for secret-storage
/// validation — any future cross-protocol surface that grows secret
/// mutations inherits the same rules by construction.
///
/// Returns `Ok(())` for canonical key_paths matching the rule set:
///   * 1 ≤ length ≤ 200 bytes
///   * each byte in `[a-z0-9_/-]` (lowercase only — uppercase would
///     duplicate via case-sensitive `vault_path_permitted` matchers)
///   * does not start with `/`
///   * does not end with `/`
///   * does not contain `//`
///
/// Returns `Err(&'static str)` with a generic message naming the
/// failure mode. Caller wraps into its protocol-specific error type
/// (talos-api uses `safe_err`, MCP uses `mcp_error`). Static-str
/// return avoids alloc on the happy path AND lets both callers avoid
/// pulling in anyhow for a leaf validator.
pub fn validate_vault_key_path(key_path: &str) -> Result<(), &'static str> {
    if key_path.is_empty() || key_path.len() > 200 {
        return Err("key_path must be 1-200 characters");
    }
    if !key_path
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_' || c == '/')
    {
        return Err(
            "key_path may only contain lowercase alphanumeric characters, hyphens (-), underscores (_), and forward-slashes (/)",
        );
    }
    if key_path.starts_with('/') || key_path.ends_with('/') || key_path.contains("//") {
        return Err(
            "key_path must not start or end with '/', and must not contain consecutive slashes",
        );
    }
    Ok(())
}

/// MCP-1152 (2026-05-16): canonical secret-namespace validator.
///
/// MCP-1201 (2026-05-17): the original MCP `handle_set_secret` /
/// `handle_set_secret_namespace` callers were removed (MCP is now
/// read-only for secrets). The validator is retained here so future
/// cross-protocol consumers (the GraphQL surface, if it grows
/// secret-namespace operations) inherit the same rules by
/// construction. Sits alongside `validate_vault_key_path` so all
/// secret-storage validation lives in ONE crate.
///
/// Rules (preserved byte-for-byte from the original inline copies):
///   * length ≤ 50 bytes
///   * each char in `[a-z0-9-]`
///
/// Empty namespace is intentionally allowed at this validator boundary
/// — historically the MCP handler substituted the default "default"
/// string upstream so the empty case never reached this validator.
/// Current GraphQL callers should perform the equivalent substitution
/// in their input layer.
pub fn validate_secret_namespace(namespace: &str) -> Result<(), &'static str> {
    if namespace.len() > 50 {
        return Err("Namespace too long (max 50 chars)");
    }
    if !namespace
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err("Namespace must be lowercase alphanumeric with hyphens only");
    }
    Ok(())
}

#[cfg(test)]
mod validate_vault_key_path_tests {
    use super::validate_vault_key_path;

    #[test]
    fn accepts_canonical_shapes() {
        for p in [
            "api_key",
            "anthropic/api_key",
            "github_pat",
            "database/connection_url",
            "stripe/api/key",
            "x",
            "a-b_c/d-e_f",
        ] {
            assert!(
                validate_vault_key_path(p).is_ok(),
                "must accept canonical key_path: {p}"
            );
        }
    }

    #[test]
    fn rejects_empty_and_oversize() {
        assert!(validate_vault_key_path("").is_err());
        let oversize = "a".repeat(201);
        assert!(validate_vault_key_path(&oversize).is_err());
        let max = "a".repeat(200);
        assert!(validate_vault_key_path(&max).is_ok());
    }

    #[test]
    fn rejects_uppercase() {
        assert!(validate_vault_key_path("API_KEY").is_err());
        assert!(validate_vault_key_path("anthropic/API_KEY").is_err());
    }

    #[test]
    fn rejects_non_alphanumeric() {
        for bad in ["api key", "api.key", "api+key", "api@key", "api:key"] {
            assert!(
                validate_vault_key_path(bad).is_err(),
                "must reject: {bad:?}"
            );
        }
    }

    #[test]
    fn rejects_leading_trailing_slash() {
        for bad in ["/api_key", "api_key/", "/anthropic/api_key/"] {
            assert!(
                validate_vault_key_path(bad).is_err(),
                "must reject: {bad:?}"
            );
        }
    }

    #[test]
    fn rejects_consecutive_slashes() {
        assert!(validate_vault_key_path("anthropic//api_key").is_err());
        assert!(validate_vault_key_path("a///b").is_err());
    }

    #[test]
    fn rejects_control_chars_and_traversal() {
        for bad in [
            "anthropic/\0api_key",
            "../secrets",
            "\tapi_key",
            "anthropic/\napi_key",
        ] {
            assert!(
                validate_vault_key_path(bad).is_err(),
                "must reject: {bad:?}"
            );
        }
    }
}

// Re-export `Zeroizing` so callers (e.g. talos-api's rotate_master_key
// mutation) can pass `Zeroizing<Vec<u8>>` for the master key without
// adding `zeroize` as a direct dependency. The wiped-on-drop guarantee
// becomes part of the crate's public API contract.
pub use zeroize::Zeroizing;

#[cfg(test)]
mod validate_secret_namespace_tests {
    use super::validate_secret_namespace;

    #[test]
    fn accepts_canonical_shapes() {
        for ns in [
            "",
            "default",
            "production",
            "team-1",
            "a-b-c",
            "x1y2z3",
            "tenant-prod-eu",
        ] {
            assert!(
                validate_secret_namespace(ns).is_ok(),
                "must accept canonical namespace: {ns:?}"
            );
        }
    }

    #[test]
    fn rejects_oversize() {
        let oversize = "a".repeat(51);
        assert!(validate_secret_namespace(&oversize).is_err());
        let max = "a".repeat(50);
        assert!(validate_secret_namespace(&max).is_ok());
    }

    #[test]
    fn rejects_uppercase() {
        for bad in ["DEFAULT", "Production", "team-A"] {
            assert!(
                validate_secret_namespace(bad).is_err(),
                "must reject uppercase: {bad}"
            );
        }
    }

    #[test]
    fn rejects_non_alphanumeric_non_hyphen() {
        for bad in [
            "team_prod", // underscore
            "team.prod", // dot
            "team/prod", // slash
            "team prod", // space
            "team:prod", // colon
            "team@prod", // at-sign
        ] {
            assert!(
                validate_secret_namespace(bad).is_err(),
                "must reject: {bad}"
            );
        }
    }

    #[test]
    fn rejects_control_chars() {
        for bad in ["team\0prod", "team\nprod", "team\tprod"] {
            assert!(
                validate_secret_namespace(bad).is_err(),
                "must reject control char: {bad:?}"
            );
        }
    }
}
