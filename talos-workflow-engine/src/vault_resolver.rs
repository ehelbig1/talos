//! `vault://` reference resolution utilities shared across MCP handlers and the engine.
//!
//! This module centralizes the logic for:
//! 1. Extracting `vault://<path>` references from a JSON config object.
//! 2. Verifying each reference can be honoured, WITHOUT substituting anything
//!    into the payload — the guest receives the literal, exactly as it does in
//!    production, and the worker resolves at the outbound call.
//!
//! Why centralize? Previously, `run_sandbox`, `test_module`, and the engine
//! each had their own inline extraction loops, and modules behaved differently
//! across execution paths.
//!
//! **The direction of that divergence was recorded backwards until 2026-09-23.**
//! This doc used to say "`run_sandbox` passing literal `vault://...` strings to
//! the module, while `test_module` and the engine injected plaintext", and
//! claimed the module "guarantees identical behavior everywhere". The ENGINE
//! never injected plaintext: `secrets_pipeline::extract_vault_paths` states
//! that "payload substitution happens on the worker side via
//! `EncryptedSecrets`", so dispatch delivers the LITERAL and the worker
//! resolves at the outbound call — which is exactly what
//! `get_rust_scaffold`'s security invariant tells module authors. The two
//! SANDBOX handlers were the outliers, and they were the ones putting a
//! credential in the guest.
//!
//! The literal is now what every path delivers. What stays centralized is
//! reference EXTRACTION, the allowlist merge, and
//! [`check_vault_refs_resolvable`] — never substitution.
//!
//! Runtime enforcement of `allowed_secrets` is in `worker/src/host_impl.rs`
//! via `talos_workflow_job_protocol::vault_path_permitted` — callers here are responsible
//! for fetching the permitted secrets and passing them to the worker.

use std::collections::HashMap;
use std::fmt;

// Detection moved to `talos-workflow-job-protocol`, next to
// `vault_path_permitted`: authoring-time checkers need to see exactly the
// references the runtime acts on, and they cannot depend on this crate.
// Re-exported so every existing call site keeps resolving.
pub use talos_workflow_job_protocol::{extract_vault_refs, VaultRef};

/// Error returned from [`check_vault_refs_resolvable`] when a referenced
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
    /// A `vault://<path>` reference targeted a host-internal path that must
    /// never be substituted into a module payload — currently OAuth refresh
    /// tokens (`oauth/.../refresh_token`). Controller-side mirror of the
    /// worker's reserved-path deny-list (PR #118): refresh tokens are
    /// consumed only by the controller's token-refresh loop; modules use the
    /// sibling `access_token`. LLM provider keys are intentionally NOT
    /// rejected here — declaring `vault://anthropic/api_key` as a header is the
    /// documented BYO-key pattern, gated per-tier by the worker.
    ReservedHostPath {
        /// The config key whose value referenced the reserved path.
        config_key: String,
        /// The reserved vault path (prefix stripped).
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
                 could not be resolved. Ensure the secret exists (dashboard Settings → Secrets, or the GraphQL \
                 createSecret mutation) and the path \
                 is correct."
            ),
            Self::ReservedHostPath {
                config_key,
                vault_path,
            } => write!(
                f,
                "Config key '{config_key}' references vault://{vault_path}, a host-internal \
                 path that cannot be substituted into a module payload. OAuth refresh tokens \
                 are controller-only; use the sibling access_token instead."
            ),
        }
    }
}

impl std::error::Error for VaultResolverError {}

/// Verify every `vault://` reference in `refs` can be honoured — WITHOUT
/// substituting anything into the payload.
///
/// This replaced `replace_vault_values` on 2026-09-23. That function wrote the
/// resolved PLAINTEXT into the payload root, `config` and `input`, and its own
/// module doc claimed "`test_module` and the engine injected plaintext … this
/// module guarantees identical behavior everywhere". Measured, the ENGINE did
/// no such thing: `secrets_pipeline::extract_vault_paths` says in as many
/// words that "payload substitution happens on the worker side via
/// `EncryptedSecrets`", so real dispatch delivers the LITERAL `vault://…` and
/// the worker resolves it at the moment of the outbound call. The helper
/// written to END divergence had become the divergence, and the surface that
/// diverged was the one that handed a guest the credential.
///
/// So the two things worth keeping are kept, and the substitution is gone:
///
/// * **The reserved-path refusal.** A host-internal OAuth refresh token must
///   never be fetched into a job's secret map at all. The worker refuses to
///   RESOLVE one (`is_reserved_host_secret_path`), but refusing here means it
///   is never fetched, never sealed and never on the wire — and the caller
///   gets a sentence instead of a silent drop.
/// * **The resolvability check.** Production fails at fetch time with a bare
///   `Notfound`; a test surface can say which config key named which path.
///   That is a deliberate test-time EXTRA, stated rather than silent: it makes
///   the test stricter than production, never more permissive.
///
/// # Errors
/// [`VaultResolverError::ReservedHostPath`] for a controller-internal path,
/// [`VaultResolverError::SecretNotResolved`] when a referenced path is absent
/// from `resolved`.
pub fn check_vault_refs_resolvable(
    resolved: &HashMap<String, String>,
    refs: &[VaultRef],
) -> Result<(), VaultResolverError> {
    for (config_key, vault_path) in refs {
        // #118 controller-side mirror: a host-internal OAuth refresh token is
        // consumed by the controller's refresh loop; modules read the sibling
        // `access_token`. `is_controller_internal && !is_llm` isolates the
        // refresh-token case — LLM provider keys stay legitimate (the
        // documented `vault://anthropic/api_key` BYO-key pattern), and their
        // tier ceiling is enforced by the worker plus `retain_wire_safe_secrets`.
        if talos_workflow_job_protocol::is_controller_internal_vault_path(vault_path)
            && !talos_workflow_job_protocol::is_llm_provider_vault_path(vault_path)
        {
            return Err(VaultResolverError::ReservedHostPath {
                config_key: config_key.clone(),
                vault_path: vault_path.clone(),
            });
        }
        if !resolved.contains_key(vault_path.as_str()) {
            return Err(VaultResolverError::SecretNotResolved {
                config_key: config_key.clone(),
                vault_path: vault_path.clone(),
            });
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
    use super::{
        check_vault_refs_resolvable, extract_vault_refs, merge_vault_refs_into_allowlist,
        VaultResolverError,
    };
    use std::collections::HashMap;

    fn resolved(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    /// `extract_vault_refs` scans the TOP LEVEL of the value it is given; the
    /// sandbox handlers rely on config keys being mirrored to the payload
    /// root. Every fixture below asserts the refs were actually found first —
    /// without that, a shape mistake makes the whole case pass vacuously,
    /// which is exactly what the first draft of these tests did.
    fn refs_of(v: &serde_json::Value) -> Vec<(String, String)> {
        let r = extract_vault_refs(v);
        assert!(!r.is_empty(), "fixture extracted no refs — it cannot fail");
        r
    }

    #[test]
    fn a_resolvable_reference_passes() {
        let payload = serde_json::json!({ "AUTH_HEADER": "Bearer vault://jira/token" });
        let refs = refs_of(&payload);
        assert_eq!(refs[0].1, "jira/token");
        check_vault_refs_resolvable(&resolved(&[("jira/token", "s3cr3t")]), &refs)
            .expect("resolvable");
    }

    /// The guarantee that the guest keeps the literal is a TYPE guarantee, not
    /// an assertion: `check_vault_refs_resolvable` has no payload parameter, so
    /// it cannot write into one. Substitution would require changing the
    /// signature, which is what the sandbox source pins watch for.
    #[test]
    fn the_checker_cannot_reach_a_payload_at_all() {
        let refs = refs_of(&serde_json::json!({ "A": "vault://x/y" }));
        // Compiles only because the checker takes the resolved map and the
        // refs — nothing it could mutate.
        let _: Result<(), VaultResolverError> =
            check_vault_refs_resolvable(&resolved(&[("x/y", "v")]), &refs);
    }

    #[test]
    fn an_unresolvable_reference_names_the_key_and_the_path() {
        let refs = refs_of(&serde_json::json!({ "AUTH": "vault://nope/missing" }));
        let err = check_vault_refs_resolvable(&HashMap::new(), &refs).expect_err("must refuse");
        assert_eq!(
            err,
            VaultResolverError::SecretNotResolved {
                config_key: "AUTH".to_string(),
                vault_path: "nope/missing".to_string(),
            }
        );
        let msg = err.to_string();
        assert!(msg.contains("AUTH"), "{msg}");
        assert!(msg.contains("nope/missing"), "{msg}");
    }

    #[test]
    fn a_host_internal_refresh_token_is_refused_before_it_is_ever_fetched() {
        let refs = refs_of(&serde_json::json!({
            "R": "vault://oauth/gmail/u1/primary/refresh_token"
        }));
        // Refused even though it WOULD have resolved — the point is that it is
        // never fetched into a job's secret map, not that it is missing.
        let err = check_vault_refs_resolvable(
            &resolved(&[("oauth/gmail/u1/primary/refresh_token", "rt")]),
            &refs,
        )
        .expect_err("refresh tokens are controller-only");
        assert!(matches!(err, VaultResolverError::ReservedHostPath { .. }));
        assert!(
            !err.to_string().contains("rt"),
            "the value must not be echoed"
        );
    }

    /// The CONTROL for the refusal above: an LLM provider key is a legitimate
    /// reference (the documented BYO-key pattern). Its tier ceiling is enforced
    /// by the worker and by `retain_wire_safe_secrets`, not here.
    #[test]
    fn an_llm_provider_key_is_not_reserved_here() {
        let refs = refs_of(&serde_json::json!({ "K": "vault://anthropic/api_key" }));
        check_vault_refs_resolvable(&resolved(&[("anthropic/api_key", "sk-x")]), &refs)
            .expect("BYO-key pattern stays legitimate");
    }

    #[test]
    fn the_allowlist_merge_deduplicates() {
        let refs = refs_of(&serde_json::json!({
            "A": "vault://x/y", "B": "vault://x/y", "C": "vault://p/q"
        }));
        let merged = merge_vault_refs_into_allowlist(vec!["x/y".to_string()], &refs);
        assert_eq!(merged.iter().filter(|s| *s == "x/y").count(), 1);
        assert!(merged.contains(&"p/q".to_string()));
    }
}
