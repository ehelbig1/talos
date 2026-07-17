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
//! - [`google_jwt`] — Google OIDC push-JWT verification shared by Gmail
//!   (Pub/Sub push) and Google Cloud (Monitoring push):
//!   [`google_jwt::GoogleOidcVerifier`] + the envelope types.

pub mod admin;
pub mod audit;
pub mod google_jwt;
pub mod renewal;
pub mod state_store;

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use talos_secrets_manager::SecretsManager;
use talos_workflow_job_protocol::EncryptedSecrets;
use uuid::Uuid;

/// A process-local handle to the shared claim-based-sealing machinery, injected
/// into module-bound dispatch contexts by the controller.
///
/// This is a deliberately thin, decoupled mirror of
/// `talos_workflow_engine_nats::EnvelopeSealingHandle` (the same `in_flight` +
/// `claim_subject` fields). It lives here — in the crate the three integration
/// stacks (gmail / gcal / webhooks) already depend on — so those crates never
/// take a dependency on the engine-NATS layer just to name the type. The
/// controller resolves the ONE process-wide `EnvelopeSealingHandle` (the same
/// `InFlightSeals` the claim responder subscribes to) and bridges it into this
/// shape at wiring time.
#[derive(Clone)]
pub struct ModuleSealingHandle {
    /// The shared, process-wide in-flight seal store the claim responder reads.
    /// MUST be the same instance the responder was spawned with — a second
    /// store would register seals the responder never sees.
    pub in_flight: Arc<talos_envelope_seal::InFlightSeals>,
    /// The replica-local claim subject stamped into `JobRequest.claim_inbox`.
    pub claim_subject: String,
}

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

    let secrets_map = resolve_dispatch_secrets_map(sm, module_id, user_id).await;

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

/// Resolve the PLAINTEXT merged secrets map for a module-bound dispatch — the
/// module's authorised secrets layered with the user's LLM provider keys
/// (module-declared keys win on conflict). This is the pre-encryption step
/// factored out of [`build_dispatch_encrypted_secrets`] so the claim-based
/// sealing path ([`prepare_module_dispatch_secrets`]) can register the same
/// values in `InFlightSeals` instead of AES-GCM-encrypting them under the
/// worker shared key. The returned map is the caller's responsibility to
/// consume promptly — it holds plaintext secret values.
async fn resolve_dispatch_secrets_map(
    sm: &Arc<SecretsManager>,
    module_id: Uuid,
    user_id: Uuid,
) -> HashMap<String, String> {
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
    // load. Same operator-visibility class as MCP-733..778
    // fire-and-forget sweep — DEBUG (not WARN) because a missing LLM
    // key is the common case for modules that don't need one; sibling
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

    secrets_map
}

/// How a module-bound dispatch should carry its secrets, spread onto the
/// `JobRequest` at the call site. Exactly one of two shapes:
///   * **inline** — `sealing == 0`, a non-empty (or empty) WSK
///     `encrypted_secrets` envelope (today's behaviour), or
///   * **claim-sealed** — `sealing == SEALING_CLAIM_ECIES`, empty
///     `encrypted_secrets`, `claim_inbox = Some(subject)`, plaintext already
///     registered in the shared `InFlightSeals` for the worker to claim.
pub struct DispatchSecretDelivery {
    pub encrypted_secrets: EncryptedSecrets,
    pub sealing: u8,
    pub claim_inbox: Option<String>,
    pub secret_paths: Vec<String>,
}

/// Prepare the secret-delivery fields for a module-bound (fire-and-forget)
/// dispatch, honouring the envelope-sealing policy.
///
/// * When `sealing_handle` is `Some` (the controller passes it only when
///   `TALOS_ENVELOPE_SEALING` is `audit`/`required` AND an Ed25519 controller
///   signing key is configured) AND the module actually has secrets, the
///   plaintext is registered in the shared `InFlightSeals` keyed on
///   `execution_id` and the request is stamped for a worker claim
///   (`sealing = SEALING_CLAIM_ECIES`, `claim_inbox`, empty
///   `encrypted_secrets`). This is the path that satisfies the worker's
///   `required`-mode downgrade guard, which refuses `sealing == 0` dispatches
///   that carry a non-empty WSK envelope.
/// * Otherwise (sealing off, or no handle available, or the module has no
///   secrets) it falls back to the inline WSK envelope — byte-identical to the
///   pre-M4 behaviour. A no-secret dispatch yields an EMPTY envelope, which the
///   `required` guard allows, so no-secret module pushes keep working.
///
/// Fire-and-forget note: the registered seal is bounded by
/// `InFlightSeals::sweep_older_than` (the controller runs a periodic sweep) —
/// unlike the engine's request/reply dispatcher, these paths cannot `discard`
/// after awaiting a result. The worker claims within milliseconds of receiving
/// the job, so an entry only lingers if the worker died before claiming; the
/// sweep reclaims it. Callers SHOULD additionally `discard` on a known publish
/// failure to shrink that window (see the call sites).
///
/// `execution_id` MUST equal the `JobRequest.job_id` / `workflow_execution_id`
/// the caller sets (the worker's `SecretClaim` keys on it), and — on the inline
/// path — is bound as AES-GCM AAD, exactly as `build_dispatch_encrypted_secrets`
/// requires.
pub async fn prepare_module_dispatch_secrets(
    secrets_manager: Option<&Arc<SecretsManager>>,
    module_id: Uuid,
    user_id: Uuid,
    execution_id: Uuid,
    sealing_handle: Option<&ModuleSealingHandle>,
) -> DispatchSecretDelivery {
    // No SecretsManager (dev/bootstrap) → no secrets to deliver either way.
    let Some(sm) = secrets_manager else {
        return DispatchSecretDelivery {
            encrypted_secrets: EncryptedSecrets::empty(),
            sealing: 0,
            claim_inbox: None,
            secret_paths: Vec::new(),
        };
    };

    let secrets_map = resolve_dispatch_secrets_map(sm, module_id, user_id).await;
    finish_dispatch_delivery(secrets_map, execution_id, sealing_handle, module_id)
}

/// Pure (DB-free) delivery decision: given the already-resolved plaintext map,
/// choose the claim-sealed vs inline shape. Split out of
/// [`prepare_module_dispatch_secrets`] so the branch logic is unit-testable
/// without a `SecretsManager` / Postgres. `module_id` is used only for log
/// correlation.
fn finish_dispatch_delivery(
    secrets_map: HashMap<String, String>,
    execution_id: Uuid,
    sealing_handle: Option<&ModuleSealingHandle>,
    module_id: Uuid,
) -> DispatchSecretDelivery {
    // A no-secret dispatch carries an empty envelope on both paths — the
    // worker's `required` guard allows `sealing == 0` with an empty envelope,
    // so there's nothing to seal and no reason to spin up a claim.
    if secrets_map.is_empty() {
        return DispatchSecretDelivery {
            encrypted_secrets: EncryptedSecrets::empty(),
            sealing: 0,
            claim_inbox: None,
            secret_paths: Vec::new(),
        };
    }

    // Claim-based sealing path: register the plaintext for the worker to claim,
    // sealed to its ephemeral key. No plaintext (nor a WSK-openable envelope)
    // touches the wire.
    if let Some(handle) = sealing_handle {
        match talos_envelope_seal::SealContext::new(&secrets_map) {
            Ok(ctx) => {
                // Sorted keys for a stable, signature-bound `secret_paths` (the
                // claim protocol keys on exec_id + the worker's ephemeral key,
                // not on these paths — they're audit/integrity metadata).
                let mut secret_paths: Vec<String> = secrets_map.keys().cloned().collect();
                secret_paths.sort();
                handle.in_flight.register(execution_id, ctx);
                return DispatchSecretDelivery {
                    encrypted_secrets: EncryptedSecrets::empty(),
                    sealing: talos_workflow_job_protocol::SEALING_CLAIM_ECIES,
                    claim_inbox: Some(handle.claim_subject.clone()),
                    secret_paths,
                };
            }
            Err(e) => {
                // Serialization of a HashMap<String,String> cannot realistically
                // fail; on the defensive error we FALL THROUGH to the inline WSK
                // path rather than dropping the secrets. Under `required` the
                // worker then refuses the inline envelope (fail-closed, loud) —
                // never a silent plaintext leak.
                tracing::error!(
                    target: "talos_security",
                    module_id = %module_id,
                    error = %e,
                    "prepare_module_dispatch_secrets: failed to build seal context; \
                     falling back to inline envelope (refused under `required`)"
                );
            }
        }
    }

    // Inline WSK envelope path (sealing off / no handle / seal-build fallback).
    let encrypted_secrets = match talos_workflow_job_protocol::load_worker_shared_key() {
        Ok(key) => {
            match EncryptedSecrets::encrypt_with_aad(
                &secrets_map,
                key.as_bytes(),
                execution_id.as_bytes(),
            ) {
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
        Err(_) => {
            tracing::warn!(
                module_id = %module_id,
                "encrypted_secrets skipped: WORKER_SHARED_KEY not configured"
            );
            EncryptedSecrets::empty()
        }
    };
    DispatchSecretDelivery {
        encrypted_secrets,
        sealing: 0,
        claim_inbox: None,
        secret_paths: Vec::new(),
    }
}

#[cfg(test)]
mod dispatch_delivery_tests {
    use super::*;

    fn map_of(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn handle() -> ModuleSealingHandle {
        ModuleSealingHandle {
            in_flight: Arc::new(talos_envelope_seal::InFlightSeals::new()),
            claim_subject: "_INBOX.claim-test".to_string(),
        }
    }

    #[test]
    fn no_secrets_is_empty_inline_regardless_of_handle() {
        // A no-secret dispatch never seals and never registers — an empty
        // envelope is allowed under `required`, so the worker runs it as-is.
        let h = handle();
        let d = finish_dispatch_delivery(HashMap::new(), Uuid::new_v4(), Some(&h), Uuid::new_v4());
        assert_eq!(d.sealing, 0);
        assert!(d.claim_inbox.is_none());
        assert!(d.secret_paths.is_empty());
        assert!(d.encrypted_secrets.ciphertext.is_empty());
        assert!(
            h.in_flight.is_empty(),
            "no seal registered for a no-secret dispatch"
        );
    }

    #[test]
    fn secrets_with_handle_registers_and_stamps_claim() {
        // SECURITY: with a handle AND secrets, the plaintext is registered for a
        // worker claim and the request is stamped `sealing = SEALING_CLAIM_ECIES`
        // with an EMPTY envelope — the shape the worker's `required` guard
        // accepts and no WSK-openable ciphertext on the wire.
        let h = handle();
        let exec = Uuid::new_v4();
        let d = finish_dispatch_delivery(
            map_of(&[("anthropic/api_key", "sk-x"), ("gmail/token", "t")]),
            exec,
            Some(&h),
            Uuid::new_v4(),
        );
        assert_eq!(d.sealing, talos_workflow_job_protocol::SEALING_CLAIM_ECIES);
        assert_eq!(d.claim_inbox.as_deref(), Some("_INBOX.claim-test"));
        assert!(
            d.encrypted_secrets.ciphertext.is_empty(),
            "no WSK envelope on the sealed path"
        );
        // secret_paths = sorted keys (stable, signature-bound audit metadata).
        assert_eq!(d.secret_paths, vec!["anthropic/api_key", "gmail/token"]);
        // The seal is claimable exactly once, keyed on the execution id.
        assert!(
            h.in_flight.take(exec).is_some(),
            "plaintext registered for claim"
        );
        assert!(h.in_flight.take(exec).is_none(), "single-claim");
    }

    #[test]
    fn secrets_without_handle_uses_inline_path() {
        // No handle (sealing off) → inline path, sealing stays 0. Without a
        // WORKER_SHARED_KEY in the test env the envelope is empty, but crucially
        // NOTHING is registered for a claim (no handle to register into).
        let exec = Uuid::new_v4();
        let d = finish_dispatch_delivery(
            map_of(&[("anthropic/api_key", "sk-x")]),
            exec,
            None,
            Uuid::new_v4(),
        );
        assert_eq!(d.sealing, 0);
        assert!(d.claim_inbox.is_none());
        assert!(d.secret_paths.is_empty());
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
