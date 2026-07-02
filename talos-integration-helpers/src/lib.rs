//! Cross-integration helpers for the push-notification pattern.
//!
//! Both `talos-google-calendar` and `talos-gmail` (and any future
//! integration that follows `docs/integration-pattern.md`) share a
//! small set of types/functions for surfacing watch-channel renewal
//! failures to the API layer. Lifting them here breaks what would
//! otherwise be a dep edge from gmail → google-calendar — purely an
//! artefact of the original co-located code, not a real domain
//! coupling.
//!
//! Currently exported:
//! - [`RenewalFailure`] — public API shape for the most-recent
//!   failed renewal of a watch channel. Distinct from internal row
//!   types so adding controller-private fields cannot accidentally
//!   leak into HTTP responses.
//! - [`looks_like_oauth_failure`] — heuristic over the rendered
//!   error string. False positives mean we surface a "Reconnect your
//!   account" banner when the real issue is transient; false
//!   negatives mean the per-row badge still fires but the banner
//!   stays hidden, so the user always sees SOMETHING is wrong.
//! - [`admin`] — the two-gate operator-endpoint auth
//!   (`ENABLE_ADMIN_OPS` + constant-time `X-Admin-Secret`) and the
//!   `admin_*` audit writer.
//! - [`audit`] — writers for the shared channel-lifecycle audit log
//!   plus the canonical truncate-then-DLP-redact error scrub.
//! - [`renewal`] — the generic renewal-scheduler kernel
//!   ([`renewal::RenewableIntegration`] + [`renewal::run_renewal_scheduler`]).
//! - [`state_store`] — watch-row plumbing over `integration_state`
//!   ([`state_store::ChannelStore`], [`state_store::ttl_with_grace`],
//!   [`state_store::CreateLockMap`]).

pub mod admin;
pub mod audit;
pub mod renewal;
pub mod state_store;

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::sync::Arc;
use talos_secrets_manager::SecretsManager;
use talos_workflow_job_protocol::EncryptedSecrets;
use uuid::Uuid;

/// Build the `encrypted_secrets` payload for a module-bound webhook
/// dispatch (Gmail push, Google-Calendar push, generic webhook).
///
/// Mirrors the canonical pattern in
/// `ParallelWorkflowEngine::build_encrypted_secrets`:
///   1. Pull the module's authorised secrets (`allowed_modules` ∋ module_id).
///   2. Layer in the LLM provider keys for `user_id` so
///      `talos::core::llm::*` host functions resolve. Module-declared
///      keys win on conflict (`HashMap::entry(...).or_insert`).
///   3. AES-256-GCM-encrypt the merged map under
///      `WORKER_SHARED_KEY` for transport on the wire.
///
/// Returns `EncryptedSecrets::empty()` (empty ciphertext) when:
///   * `secrets_manager` is `None` (dev/bootstrap path),
///   * `WORKER_SHARED_KEY` is not configured, or
///   * encryption itself fails.
///
/// All three paths are logged but non-fatal — the dispatch still
/// publishes a job; the worker simply won't see secrets. This
/// matches the `Default::default()` behaviour the call sites had
/// before the LLM-keys gap was discovered, except now the typical
/// production case (manager present, shared key configured)
/// actually populates the field.
///
/// `Zeroizing<String>` from the LLM-keys cache is cloned at the map
/// boundary into a plain `String`; the cache copy zeroizes when
/// `llm_keys` is dropped at the end of this function.
/// L-1 (2026-05-22): the `execution_id` parameter is bound as AEAD
/// AAD on the AES-GCM tag — the worker decrypts with the same AAD
/// pulled from `JobRequest.workflow_execution_id`. Callers MUST pass
/// the SAME `execution_id` they will set on the JobRequest;
/// otherwise the worker's tag check fails and the dispatch errors
/// with "decryption failed".
pub async fn build_dispatch_encrypted_secrets(
    secrets_manager: Option<&Arc<SecretsManager>>,
    module_id: Uuid,
    user_id: Uuid,
    execution_id: Uuid,
) -> EncryptedSecrets {
    let Some(sm) = secrets_manager else {
        tracing::debug!(
            module_id = %module_id,
            "encrypted_secrets skipped: SecretsManager unavailable in dispatch context"
        );
        return EncryptedSecrets::empty();
    };

    let Ok(key) = talos_workflow_job_protocol::load_worker_shared_key() else {
        tracing::warn!(
            module_id = %module_id,
            "encrypted_secrets skipped: WORKER_SHARED_KEY not configured"
        );
        return EncryptedSecrets::empty();
    };

    // MCP-589: route through the user-scoped variant so a malicious
    // user with a secret declaring `allowed_modules: [shared_module]`
    // can't poison the encrypted-secrets payload for another user's
    // dispatch via key_path collision. Global secrets
    // (owner_user_id IS NULL) still surface.
    let mut secrets_map = sm
        .get_module_secrets_for_user(module_id, user_id)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(
                module_id = %module_id,
                user_id = %user_id,
                error = %e,
                "Failed to load module secrets for dispatch — proceeding with LLM keys only"
            );
            Default::default()
        });

    // MCP-779 (2026-05-13): log LLM-keys load failures. Pre-fix the
    // `if let Ok(llm_keys) = ...` silently swallowed Err — a module
    // declaring a `vault://anthropic/api_key` header would dispatch
    // without that key, and the worker would fail to resolve the
    // vault:// substitution with no log signal on the controller
    // side correlating the worker-side failure back to the LLM-keys
    // load. Sibling paths in this function (module secrets at line
    // ~85, encryption failure at line ~106, missing WORKER_SHARED_KEY
    // at line ~70) all log; this branch was the drift. Same
    // operator-visibility class as MCP-733..778 fire-and-forget
    // sweep — DEBUG (not WARN) because a missing LLM key is the
    // common case for modules that don't need one; sibling
    // `ParallelWorkflowEngine::build_encrypted_secrets` follows the
    // same DEBUG convention.
    match sm.get_llm_vault_keys(Some(user_id)).await {
        Ok(llm_keys) => {
            for (k, v) in llm_keys {
                secrets_map
                    .entry(k)
                    .or_insert_with(|| v.as_str().to_string());
            }
        }
        Err(e) => {
            tracing::debug!(
                module_id = %module_id,
                user_id = %user_id,
                error = %e,
                "Failed to load LLM vault keys for dispatch — module-declared secrets still resolved, but vault://<provider>/api_key headers will fail at the worker if the module needs them"
            );
        }
    }

    // L-1: bind execution_id as AEAD AAD on the AES-GCM tag — the
    // worker decrypts with the same AAD pulled from
    // `JobRequest.workflow_execution_id`. Empty secrets_map still
    // returns `EncryptedSecrets::empty()` (empty ciphertext +
    // empty nonce) — that path bypasses AAD entirely on both sides.
    match EncryptedSecrets::encrypt_with_aad(&secrets_map, key.as_bytes(), execution_id.as_bytes())
    {
        Ok(es) => es,
        Err(e) => {
            tracing::warn!(
                module_id = %module_id,
                error = %e,
                "Failed to encrypt dispatch secrets — proceeding without them"
            );
            EncryptedSecrets::empty()
        }
    }
}

/// Public API shape for the most-recent failed renewal attempt on a
/// watch channel. Surfaces in `WatchChannelSummary::recent_failure`
/// for both Gmail and Google-Calendar list endpoints.
#[derive(Serialize, Debug, Clone)]
pub struct RenewalFailure {
    pub error_message: String,
    pub failed_at: DateTime<Utc>,
    /// True if the error text matches OAuth/credential-failure
    /// heuristics — the caller can surface a "Reconnect your
    /// Google account" banner instead of a generic "renewal
    /// failing" badge.
    pub likely_oauth_failure: bool,
}

/// Heuristic match over an error message — true when the rendered
/// text looks like an OAuth / credential failure (HTTP 401, invalid
/// grant/token, "reconnect" hints, refresh-token revoke text). Used
/// to decide whether the API surface should ask the user to
/// reconnect the integration vs. just show a transient-renewal
/// warning.
///
/// Conservative on the false-negative side: signals that don't match
/// fall back to a generic per-row badge instead of the louder
/// reconnect banner.
pub fn looks_like_oauth_failure(err: &str) -> bool {
    let lowered = err.to_ascii_lowercase();
    const OAUTH_SIGNALS: &[&str] = &[
        "invalid_grant",
        "invalid grant",
        "invalid_token",
        "invalid token",
        "unauthorized",
        "access_token",
        "access token not found",
        "refresh",
        "reconnect",
        "token revoked",
        "expired or revoked",
        "401",
    ];
    OAUTH_SIGNALS.iter().any(|sig| lowered.contains(sig))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looks_like_oauth_failure_matches_real_error_shapes() {
        let cases = [
            "Token refresh failed: invalid_grant",
            "HTTP 401 Unauthorized",
            "access token not found",
            "OAuth token revoked",
            "Token expired or revoked",
            "Please reconnect your account",
        ];
        for msg in cases {
            assert!(
                looks_like_oauth_failure(msg),
                "expected oauth-failure match for: {msg}"
            );
        }
    }

    #[test]
    fn looks_like_oauth_failure_false_negative_on_transient_errors() {
        let cases = [
            "HTTP 503 Service Unavailable",
            "connection reset by peer",
            "DNS resolution failed",
        ];
        for msg in cases {
            assert!(
                !looks_like_oauth_failure(msg),
                "expected transient (non-oauth) for: {msg}"
            );
        }
    }
}
