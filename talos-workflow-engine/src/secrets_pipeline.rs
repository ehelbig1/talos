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
/// `EncryptedSecrets::default()` (empty ciphertext) rather than
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
    if !extra_paths.is_empty() {
        match resolver.resolve_by_paths(extra_paths, user_id).await {
            Ok(declared) => secrets_map.extend(declared),
            Err(e) => tracing::warn!(error = %e, "Failed to fetch module declared secrets"),
        }
    }

    // 3-4. OAuth refresh + dynamic vault paths.
    if !vault_paths.is_empty() {
        resolver.refresh_vault_paths(vault_paths).await;
        match resolver.resolve_by_paths(vault_paths, user_id).await {
            Ok(v) => secrets_map.extend(v),
            Err(e) => tracing::error!(
                error = %e,
                ?vault_paths,
                %node_id,
                "Failed to pre-fetch vault:// secrets — node will fail"
            ),
        }
    }

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
        return talos_workflow_job_protocol::EncryptedSecrets::default();
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
                return talos_workflow_job_protocol::EncryptedSecrets::default();
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
            talos_workflow_job_protocol::EncryptedSecrets::default()
        }
    }
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
