//! One-stop secret resolution + sealing pipeline for node dispatch.
//!
//! [`build_encrypted_secrets_for`] is the single place the engine
//! resolves per-node secrets and seals them into the opaque
//! `(ciphertext, nonce)` pair the wire format carries. It's called
//! both from methods on [`ParallelWorkflowEngine`] that hold `&self`
//! and from `async move` sub-workflow dispatch closures that can't
//! borrow `self`, so it lives as a free function taking every
//! dependency by reference.
//!
//! The pipeline ordering is load-bearing — see the function doc.
//! Previously this logic was duplicated at four dispatch sites and
//! drift between copies caused a production bug (loop-node secrets
//! injection gap). Keeping one copy prevents recurrence.
//!
//! [`ParallelWorkflowEngine`]: crate::ParallelWorkflowEngine

use talos_workflow_engine_core::{SecretEnvelope, SecretsResolver};
use uuid::Uuid;

/// Run the full node-dispatch secret pipeline and return encrypted
/// ciphertext.
///
/// Pipeline order — preserved across every caller to avoid silent
/// override differences between copies:
///
/// 1. Module-grant secrets for `node_id`.
/// 2. Statically-declared `extra_paths` (from `wasm_module.allowed_secrets`).
///    Empty slice for callers without a declared set.
/// 3. OAuth refresh hook on `vault_paths`.
/// 4. Dynamic `vault_paths` (extracted from node config). Overwrites any
///    overlapping keys from steps 1-2 because later writes win in
///    `HashMap::extend`.
/// 5. Canonical LLM-provider keys for `user_id`.
/// 6. AES-256-GCM encrypt the combined map under `worker_shared_key`.
///
/// Errors at any resolve step are logged and the offending set is
/// skipped — the node still gets whatever secrets *did* resolve. If
/// the combined map is empty, the function returns
/// `EncryptedSecrets::empty()` (empty ciphertext) rather than
/// encrypting an empty map.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn build_encrypted_secrets_for(
    resolver: &dyn SecretsResolver,
    envelope: &dyn SecretEnvelope,
    node_id: Uuid,
    user_id: Option<Uuid>,
    vault_paths: &[String],
    extra_paths: &[String],
    worker_shared_key: &[u8],
    // LLM tier ceiling — when `Tier1`, skips the LLM-provider key
    // pre-fetch entirely. Defense in depth: the worker's `get_llm_api_key`
    // and HTTP-host gates already refuse external providers, but bounding
    // what crosses the wire (encrypted or not) tightens the blast radius
    // if a future bypass slips through.
    max_llm_tier: talos_workflow_engine_core::LlmTier,
    // L-1 (2026-05-22): AEAD additional-authenticated-data binding.
    // Callers pass the dispatching workflow execution id
    // (`workflow_execution_id.as_bytes()`) — that ties the AES-GCM tag
    // to the specific execution this ciphertext is meant for, so a
    // ciphertext transposed into a different execution (even under the
    // same shared key) fails tag validation at the worker, which
    // unseals with the same AAD from `JobRequest.workflow_execution_id`.
    aad: &[u8],
) -> talos_workflow_job_protocol::EncryptedSecrets {
    // 1. Module-grant secrets.
    let mut secrets_map = resolver
        .resolve_module_secrets(node_id)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, %node_id, "resolve_module_secrets failed");
            Default::default()
        });

    // 2. Statically-declared extra paths (module's `allowed_secrets` list).
    //
    // Tier-1 defense in depth: drop any LLM-provider vault path from the
    // declared set before resolving. A module that declares
    // `allowed_secrets: ["*"]` (the common wildcard default, expanded to
    // a concrete path set upstream) or that names `anthropic/api_key`
    // directly would otherwise resolve an external-provider key and seal
    // it into a tier-1 job's `encrypted_secrets`. The worker's deny-list
    // refuses to *use* it, but per the documented invariant a tier-1 job
    // must never carry such a key on the wire (encrypted or otherwise) —
    // we drop it here so a future worker-side bypass ends at "no key
    // present" rather than "key present but refused". Same rationale as
    // the step-5 LLM-prefetch skip below.
    let extra_paths = filter_tier1_paths(extra_paths, max_llm_tier);
    if !extra_paths.is_empty() {
        match resolver.resolve_by_paths(&extra_paths, user_id).await {
            Ok(declared) => secrets_map.extend(declared),
            Err(e) => tracing::warn!(error = %e, "Failed to fetch module declared secrets"),
        }
    }

    // 3-4. OAuth refresh + dynamic vault paths.
    //
    // Tier-1 defense in depth (mirrors step 2): a node whose config
    // contains `vault://anthropic/api_key` would otherwise seal that key
    // into a tier-1 job. Filter the LLM-provider paths out of the dynamic
    // set too, before both the OAuth refresh hook and the resolve.
    let vault_paths = filter_tier1_paths(vault_paths, max_llm_tier);
    if !vault_paths.is_empty() {
        resolver.refresh_vault_paths(&vault_paths).await;
        match resolver.resolve_by_paths(&vault_paths, user_id).await {
            Ok(v) => secrets_map.extend(v),
            Err(e) => tracing::error!(
                error = %e,
                ?vault_paths,
                %node_id,
                "Failed to pre-fetch vault:// secrets — node will fail"
            ),
        }
    }

    // 4b. Backstop on the RESOLVED set. `filter_tier1_paths` (steps 2-4)
    // filters the path LIST before resolution, but a `["*"]` allowed_secrets
    // grant is passed RAW to the resolver (engine_dispatch_single / _pipeline
    // pass `wasm_module.allowed_secrets` verbatim), and its `is_wildcard`
    // branch expands `"*"` to EVERY user secret INSIDE the resolver — after the
    // list filter already ran. `filter_tier1_paths` only matches concrete LLM
    // paths, never the literal `"*"`, so for a wildcard grant it was a no-op
    // and host-internal secrets rode the wildcard into `secrets_map`. Re-filter
    // the resolved set by actual key_path so this holds regardless of how a
    // path entered (wildcard / explicit / module grant). Runs BEFORE step 5 so
    // Tier-2's intentional LLM-key prefetch below is unaffected.
    retain_wire_safe_secrets(&mut secrets_map, max_llm_tier);

    // 5. LLM-provider keys. Errors swallowed: a missing/broken LLM-key
    // vault shouldn't fail nodes that don't use llm::*.
    //
    // Tier-1 jobs SKIP this entirely — the keys would just sit in the
    // worker's secret cache waiting to be (incorrectly) resolved by some
    // future bypass. Skipping the prefetch means a hypothetical bypass
    // ends at "no key available" instead of "key available but refused
    // by tier check" — much narrower exploit surface.
    if !matches!(max_llm_tier, talos_workflow_engine_core::LlmTier::Tier1) {
        match resolver.resolve_llm_keys(user_id).await {
            Ok(keys) => secrets_map.extend(keys),
            Err(e) => tracing::debug!(
                error = %e,
                "Failed to pre-fetch LLM vault keys — worker will fall back to env vars"
            ),
        }
    } else {
        tracing::debug!(
            %node_id,
            "Tier-1 job — skipping LLM provider key pre-fetch (defense in depth)"
        );
    }

    // 6. Seal via the pluggable envelope. Empty-map short-circuit
    // matches the reference impl's sentinel; callers read an empty
    // ciphertext as "no secrets to forward."
    if secrets_map.is_empty() {
        return talos_workflow_job_protocol::EncryptedSecrets::empty();
    }
    // L-1: route through the AAD-binding seal so the per-job AEAD
    // context is part of the AES-GCM tag. The default trait impl
    // falls back to plain `seal` (no AAD) so custom envelopes that
    // haven't migrated still compile and produce decryptable bytes
    // when paired with a worker on the legacy decrypt path.
    match envelope
        .seal_with_aad(&secrets_map, worker_shared_key, aad)
        .await
    {
        Ok((ciphertext, nonce)) => {
            // Validate the seal output structurally — a misconfigured
            // envelope that returns a short nonce or a mismatched
            // empty/non-empty pair would send corrupted bytes on the
            // wire. Fail closed (empty ciphertext → node dispatches
            // with no secrets → node fails cleanly) rather than
            // forwarding the bad output.
            if let Err(e) = talos_workflow_engine_core::validate_seal_output(&ciphertext, &nonce) {
                tracing::error!(
                    %node_id,
                    error = %e,
                    "SecretEnvelope::seal output failed structural validation — dispatching with empty ciphertext"
                );
                return talos_workflow_job_protocol::EncryptedSecrets::empty();
            }
            // Separate check: the envelope accepted the structural
            // contract (returned the empty-empty sentinel) but did so
            // on a non-empty input. We forwarded no secrets; the node
            // is about to fail with a secrets-unavailable error, so
            // surface the root cause in the logs.
            if ciphertext.is_empty() && nonce.is_empty() {
                tracing::error!(
                    %node_id,
                    secret_count = secrets_map.len(),
                    "SecretEnvelope::seal returned the empty sentinel for a non-empty secrets map — node will dispatch without secrets"
                );
            }
            talos_workflow_job_protocol::EncryptedSecrets { ciphertext, nonce }
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                %node_id,
                "SecretEnvelope::seal failed — dispatching node with empty ciphertext"
            );
            talos_workflow_job_protocol::EncryptedSecrets::empty()
        }
    }
}

/// Tier-1 LLM-provider path filter (single source of truth for the
/// step-2 and step-4 defense-in-depth drop).
///
/// For [`LlmTier::Tier2`] this is an identity copy — tier-2 behavior is
/// unchanged. For [`LlmTier::Tier1`] it drops every path for which
/// [`talos_workflow_job_protocol::is_llm_provider_vault_path`] returns
/// true, so an external-provider key (`anthropic/api_key`,
/// `openai/api_key`, `gemini/api_key`) declared via a module's
/// `allowed_secrets` (including the `["*"]` wildcard expanded to a
/// concrete path set upstream) or referenced via a `vault://…` node
/// config entry never gets resolved into — and therefore never sealed
/// into — a tier-1 job's `encrypted_secrets`.
///
/// [`LlmTier::Tier1`]: talos_workflow_engine_core::LlmTier::Tier1
/// [`LlmTier::Tier2`]: talos_workflow_engine_core::LlmTier::Tier2
pub(crate) fn filter_tier1_paths(
    paths: &[String],
    max_llm_tier: talos_workflow_engine_core::LlmTier,
) -> Vec<String> {
    if matches!(max_llm_tier, talos_workflow_engine_core::LlmTier::Tier1) {
        paths
            .iter()
            .filter(|p| !talos_workflow_job_protocol::is_llm_provider_vault_path(p))
            .cloned()
            .collect()
    } else {
        paths.to_vec()
    }
}

/// Drop host-internal secrets from a RESOLVED secret map before it is sealed
/// onto the wire. The complement to [`filter_tier1_paths`]: that filters the
/// path *list* before resolution, but a `["*"]` wildcard grant expands to
/// concrete paths *inside* the resolver (after the list filter ran), so
/// host-internal secrets can still surface in the resolved map. This is the
/// backstop on the actual resolved `key_path`s:
///   * OAuth refresh tokens (`oauth/.../refresh_token`) — host-internal
///     (controller refresh loop only; the worker denies guest reads). No host
///     function consumes them, so drop UNCONDITIONALLY: they must never be on
///     the wire. The sibling `access_token` is NOT matched, so it survives.
///   * LLM provider keys for Tier-1 — the documented "a tier-1 job must never
///     carry an LLM key on the wire" invariant. Tier-2 keeps them for the
///     host `llm::*` path (re-added by step 5 of `build_encrypted_secrets_for`).
pub(crate) fn retain_wire_safe_secrets(
    secrets: &mut std::collections::HashMap<String, String>,
    max_llm_tier: talos_workflow_engine_core::LlmTier,
) {
    secrets.retain(|path, _| {
        let is_llm = talos_workflow_job_protocol::is_llm_provider_vault_path(path);
        // is_controller_internal == is_llm OR oauth-refresh, so the
        // `&& !is_llm` isolates the oauth-refresh-token case.
        let is_oauth_refresh =
            talos_workflow_job_protocol::is_controller_internal_vault_path(path) && !is_llm;
        if is_oauth_refresh {
            return false;
        }
        if is_llm && matches!(max_llm_tier, talos_workflow_engine_core::LlmTier::Tier1) {
            return false;
        }
        true
    });
}

/// Extract `vault://…` paths from a node config, stripping the prefix.
///
/// Thin wrapper over [`crate::vault_resolver::extract_vault_refs`] that
/// drops the config-key side of each tuple. The engine doesn't need
/// per-key tracking because payload substitution happens on the worker
/// side via [`talos_workflow_job_protocol::EncryptedSecrets`].
pub(crate) fn extract_vault_paths(config: &serde_json::Value) -> Vec<String> {
    crate::vault_resolver::extract_vault_refs(config)
        .into_iter()
        .map(|(_key, path)| path)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{filter_tier1_paths, retain_wire_safe_secrets};
    use std::collections::HashMap;
    use talos_workflow_engine_core::LlmTier;

    fn paths() -> Vec<String> {
        vec![
            "anthropic/api_key".to_string(),
            "openai/api_key".to_string(),
            "gemini/api_key".to_string(),
            "stripe/secret_key".to_string(),
            "github/token".to_string(),
        ]
    }

    #[test]
    fn tier1_drops_all_llm_provider_paths() {
        let out = filter_tier1_paths(&paths(), LlmTier::Tier1);
        // No LLM-provider key survives for a tier-1 job.
        assert!(!out.iter().any(|p| p == "anthropic/api_key"));
        assert!(!out.iter().any(|p| p == "openai/api_key"));
        assert!(!out.iter().any(|p| p == "gemini/api_key"));
        // Non-LLM secrets are untouched — tier-1 nodes still get their
        // Stripe / GitHub credentials.
        assert_eq!(
            out,
            vec!["stripe/secret_key".to_string(), "github/token".to_string()]
        );
    }

    #[test]
    fn tier2_is_an_identity_copy() {
        let input = paths();
        let out = filter_tier1_paths(&input, LlmTier::Tier2);
        // Tier-2 behavior is unchanged — every path including the LLM
        // provider keys is preserved.
        assert_eq!(out, input);
    }

    #[test]
    fn tier1_wildcard_expansion_drops_llm_paths() {
        // Simulates an `allowed_secrets: ["*"]` grant expanded upstream
        // to a concrete path set that happens to include a provider key.
        let expanded = vec![
            "anthropic/api_key".to_string(),
            "service/db_url".to_string(),
        ];
        let out = filter_tier1_paths(&expanded, LlmTier::Tier1);
        assert_eq!(out, vec!["service/db_url".to_string()]);
    }

    #[test]
    fn tier1_empty_input_yields_empty() {
        let out = filter_tier1_paths(&[], LlmTier::Tier1);
        assert!(out.is_empty());
    }

    // --- retain_wire_safe_secrets: the resolved-map backstop ---------------
    // These model the `["*"]` wildcard case the LIST filter (filter_tier1_paths)
    // can't reach: the resolver has already expanded the wildcard to concrete
    // key_paths in the map, so the backstop must filter on the actual paths.

    fn resolved() -> HashMap<String, String> {
        HashMap::from([
            ("anthropic/api_key".to_string(), "llm".to_string()),
            (
                "oauth/gmail/u1/primary/refresh_token".to_string(),
                "rt".to_string(),
            ),
            (
                "oauth/gmail/u1/primary/access_token".to_string(),
                "at".to_string(),
            ),
            ("stripe/secret_key".to_string(), "sk".to_string()),
        ])
    }

    #[test]
    fn retain_drops_oauth_refresh_token_on_every_tier() {
        for tier in [LlmTier::Tier1, LlmTier::Tier2] {
            let mut m = resolved();
            retain_wire_safe_secrets(&mut m, tier);
            assert!(
                !m.contains_key("oauth/gmail/u1/primary/refresh_token"),
                "refresh token must never be on the wire ({tier:?})"
            );
            // The sibling access_token is module-readable and must survive.
            assert!(
                m.contains_key("oauth/gmail/u1/primary/access_token"),
                "access token must be preserved ({tier:?})"
            );
            // Ordinary module secrets untouched.
            assert!(m.contains_key("stripe/secret_key"));
        }
    }

    #[test]
    fn retain_drops_llm_keys_only_for_tier1() {
        // Tier-1: LLM key dropped (the wildcard bypass of the "never on the
        // wire" invariant this whole backstop closes).
        let mut t1 = resolved();
        retain_wire_safe_secrets(&mut t1, LlmTier::Tier1);
        assert!(
            !t1.contains_key("anthropic/api_key"),
            "tier-1 must not carry an LLM key on the wire, even via a wildcard grant"
        );

        // Tier-2: LLM key kept — the host `llm::*` path legitimately needs it.
        let mut t2 = resolved();
        retain_wire_safe_secrets(&mut t2, LlmTier::Tier2);
        assert!(
            t2.contains_key("anthropic/api_key"),
            "tier-2 keeps LLM keys for host llm::* consumption"
        );
    }
}
