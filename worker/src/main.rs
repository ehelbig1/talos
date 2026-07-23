//! Talos Worker - WASM Execution Engine
//!
//! Production-grade worker with:
//! - OpenTelemetry metrics (Prometheus)
//! - Distributed tracing (Jaeger)
//! - Health checks
//! - Graceful shutdown
//! - NATS-based job queue
//! - HMAC-signed job verification
//! - AES-256-GCM encrypted secrets in transit

use async_nats::Client;
use async_nats::Subscriber;
use futures_util::stream::StreamExt;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use talos_workflow_job_protocol::{
    load_worker_key_ring, JobRequest, JobResult, JobStatus, PipelineJobRequest, PipelineJobResult,
    PipelineStepResult,
};
use worker::error_sanitize::sanitize_error_message;
use worker::job_span::JobSpan;
use worker::module_fetcher::{
    self, enforce_production_sigstore_policy_explicit, parse_cosign_version, parse_semver_triple,
    resolve_and_hash_cosign_binary, validate_sigstore_identity_regexp, FetchedModule,
    SigstorePolicy,
};
use worker::runtime::{PipelineStepSpec, RetryPolicy, SecurityPolicy};
use worker::secret_claim;
use worker::worker_identity;
use worker::{circuit_breaker, metrics, metrics_server, sql_validator};

use worker::runtime::TalosRuntime;

/// Default maximum concurrent single-node job executions. Overridable via
/// `TALOS_MAX_CONCURRENT_JOBS`; see [`max_concurrent_jobs`].
const DEFAULT_MAX_CONCURRENT_JOBS: usize = 100;
/// Default maximum concurrent pipeline job executions (heavier — multi-step).
/// Overridable via `TALOS_MAX_CONCURRENT_PIPELINE_JOBS`; see
/// [`max_concurrent_pipeline_jobs`].
const DEFAULT_MAX_CONCURRENT_PIPELINE_JOBS: usize = 20;

/// Maximum concurrent single-node job executions (env `TALOS_MAX_CONCURRENT_JOBS`).
///
/// Reuses the canonical `nonzero_env_or_default` footgun guard: a
/// non-numeric or `<= 0` value would create a `Semaphore` that permits
/// nothing (silent worker stall), so it is rejected with a WARN and the
/// default is substituted (`>= 1` by construction). Same class as the
/// documented `=0`/negative env-var footgun pattern.
fn max_concurrent_jobs() -> usize {
    worker::runtime::nonzero_env_or_default(
        "TALOS_MAX_CONCURRENT_JOBS",
        DEFAULT_MAX_CONCURRENT_JOBS,
    )
}

/// Maximum concurrent pipeline job executions (env `TALOS_MAX_CONCURRENT_PIPELINE_JOBS`).
/// Same footgun guard as [`max_concurrent_jobs`].
fn max_concurrent_pipeline_jobs() -> usize {
    worker::runtime::nonzero_env_or_default(
        "TALOS_MAX_CONCURRENT_PIPELINE_JOBS",
        DEFAULT_MAX_CONCURRENT_PIPELINE_JOBS,
    )
}

// ============================================================================
// RELIABILITY: Result Publishing with Retry
// ============================================================================

/// Publish a serialized payload to a NATS topic with exponential backoff retry.
async fn publish_bytes_with_retry(
    nc: &async_nats::Client,
    topic: String,
    payload: bytes::Bytes,
    max_attempts: u32,
) -> Result<(), String> {
    let mut backoff_ms = 100u64;
    for attempt in 0..max_attempts {
        // `publish()` only enqueues into the client's outbound buffer — it returns
        // Ok before the server has seen the message. Every caller of this helper is
        // delivering a signed JobResult / reply, and the controller's reply-inbox
        // await has no independent timeout floor, so a message dropped between the
        // local buffer and the broker (connection blip, buffer discard) is a SILENT
        // loss that hangs the execution until the 30-min stale sweep. `flush()`
        // drains the buffer to the server and awaits acceptance, turning that loss
        // into a retriable error instead of a false success. Cost is one round-trip
        // per job result (infrequent) — acceptable for delivery-critical results.
        let sent = match nc.publish(topic.clone(), payload.clone()).await {
            Ok(()) => nc.flush().await.map_err(|e| e.to_string()),
            Err(e) => Err(e.to_string()),
        };
        match sent {
            Ok(()) => {
                if attempt > 0 {
                    ::tracing::info!(topic, attempt, "Published (flushed) after retries");
                }
                return Ok(());
            }
            Err(e) => {
                if attempt < max_attempts - 1 {
                    ::tracing::warn!(
                        topic,
                        attempt = attempt + 1,
                        max_attempts,
                        error = %e,
                        "Failed to publish+flush, retrying"
                    );
                    tokio::time::sleep(tokio::time::Duration::from_millis(backoff_ms)).await;
                    backoff_ms = (backoff_ms * 2).min(5_000);
                } else {
                    return Err(format!(
                        "Failed to publish+flush to {} after {} attempts: {}",
                        topic, max_attempts, e
                    ));
                }
            }
        }
    }
    Err("Unexpected retry loop exit".to_string())
}

/// Publish result to NATS with exponential backoff retry.
///
/// Single-publish architecture (post-r301): the result is published to
/// EXACTLY ONE subject per call:
///
///  * `Some(reply)` (NATS request-reply): publish to the inbox the
///    requester is awaiting on. The requester (engine dispatcher,
///    webhook dispatcher, gmail/gcal handlers, etc.) verifies the
///    result inline and writes durable state through its own path.
///  * `None` (true fire-and-forget): publish to the global
///    `talos.results.{job_id}` topic so the controller's
///    `talos.results.*` audit subscriber can update `module_executions`
///    durably. There is no inline requester to consume the reply.
///
/// Pre-r301 the worker dual-published to BOTH the reply inbox AND
/// `talos.results.{job_id}` "for logging/audit". The controller had
/// two verifiers consuming these (the dispatcher + the audit
/// subscriber) and both ran `JobResult::verify()`, sharing the
/// process-local `JOB_NONCE_CACHE`. Once `WORKER_SHARED_KEY` started
/// loading reliably (post-r294 vault bootstrap fix), the second
/// verifier always hit "result_nonce already seen" and EVERY workflow
/// execution failed (r300 was the protocol-level mitigation;
/// single-publish is the source-level architectural fix).
///
/// Today, every NATS-dispatched path uses request-reply (engine,
/// webhooks, gmail, gcal); `run_sandbox` and `test_module` run WASM
/// in-process and don't hit NATS at all. Audit subscriber-only paths
/// don't currently exist, but the fire-and-forget code path is kept
/// for future use (e.g. async work-queue dispatches that don't await
/// the result inline).
/// H-1: Reconcile the wire-format NATS `msg.reply` (untrusted —
/// flows over an unsigned header an attacker can modify) with the
/// HMAC-bound `JobRequest::reply_topic` (signed, trustworthy when
/// present). Returns the subject the worker SHOULD publish the
/// signed JobResult to, or `None` if no reply path is available.
///
/// Decision matrix:
/// - (Some(signed), Some(wire)) where signed == wire → trust both;
///   return Some(signed). Hot path.
/// - (Some(signed), Some(wire)) where signed != wire → log a
///   SECURITY-level warning AND publish to the SIGNED value. The
///   wire value is attacker-controllable; the signed value is the
///   one the controller committed to.
/// - (Some(signed), None) → publish to the signed value. Indicates
///   the wire header was stripped in transit (rare; treat the
///   signed value as authoritative).
/// - (None, Some(wire)) → publish to the wire value. Backward-compat
///   path for controllers / transports that don't pre-allocate
///   inboxes. The legacy "trust msg.reply" exposure remains but
///   only when reply_topic isn't bound.
/// - (None, None) → no reply path; the worker logs the result
///   elsewhere (e.g. fire-and-forget topic).
///
/// Pure function so the policy is unit-testable without a NATS
/// broker. The `job_id` parameter is for log correlation only.
pub(crate) fn pick_trusted_reply_topic(
    job_id: uuid::Uuid,
    signed: Option<&str>,
    wire: Option<&str>,
) -> Option<String> {
    match (signed, wire) {
        (Some(s), Some(w)) if s == w => Some(s.to_string()),
        (Some(s), Some(w)) => {
            ::tracing::error!(
                job_id = %job_id,
                signed_reply = %s,
                wire_reply = %w,
                "SECURITY: H-1 reply_topic mismatch — wire msg.reply does not match \
                 HMAC-bound JobRequest.reply_topic. Publishing to the SIGNED value; \
                 wire value is likely attacker-tampered."
            );
            Some(s.to_string())
        }
        (Some(s), None) => {
            ::tracing::warn!(
                job_id = %job_id,
                signed_reply = %s,
                "H-1: msg.reply stripped in transit; publishing to HMAC-bound reply_topic"
            );
            Some(s.to_string())
        }
        (None, Some(w)) => Some(w.to_string()),
        (None, None) => {
            // L-12 (2026-05-22): the result will be published to the
            // global `talos.results.{job_id}` topic by the caller
            // (publish_result_with_retry). That path is intended for the
            // controller's audit subscriber — but if neither the
            // signed `reply_topic` NOR the wire `msg.reply` is set AND
            // the operator hasn't configured an audit subscriber, the
            // result effectively disappears (broker delivers to zero
            // subscribers, no error returned). Emit a structured event
            // here so the condition is visible in dashboards and a
            // misconfigured dispatch path doesn't degrade silently.
            //
            // `target: "talos_worker_metrics"` lets operators alert via
            // a single filter; `event_kind` is the stable identifier.
            ::tracing::warn!(
                target: "talos_worker_metrics",
                job_id = %job_id,
                event_kind = "job_result_no_reply",
                "neither signed reply_topic nor wire msg.reply set — result \
                 will publish to the global audit topic only. If no audit \
                 subscriber is configured this result is lost."
            );
            None
        }
    }
}

// L-11 (2026-05-22): The worker's self-reported identity, bound into
// every signed `JobResult` / `PipelineJobResult` via
// `sign_with_worker_id`, is `worker::worker_identity` — the canonical
// resolver lives in the library so both the binary AND library code
// (e.g. `host_impl::build_signed_agent_envelope`) share the same
// `OnceLock`-cached value. (The binary previously carried a thin
// wrapper fn; now that the binary consumes the library crate directly
// the wrapper is gone and call sites use the imported fn.)

#[cfg(test)]
mod worker_identity_tests {
    use super::worker_identity;

    #[test]
    fn returns_validatable_id() {
        let id = worker_identity();
        // Whatever the resolution branch, the output must satisfy the
        // protocol's validator — that's what the worker is going to
        // pass to `sign_with_worker_id` in production.
        talos_workflow_job_protocol::validate_worker_id(id)
            .expect("resolved worker_id must satisfy validate_worker_id");
    }

    #[test]
    fn cached_across_calls() {
        // OnceLock semantics: stable address means stable string.
        let a: &'static str = worker_identity();
        let b: &'static str = worker_identity();
        assert_eq!(a.as_ptr(), b.as_ptr(), "worker_identity must be cached");
    }
}

/// M-7: Hard ceiling on the serialized JobResult bytes the worker
/// will attempt to publish to NATS. Without a pre-publish cap, an
/// oversized `output_payload` (legitimately large or hostile) silently
/// fails at the broker layer (default NATS `max_payload` is 1 MiB)
/// and the controller times out waiting for a reply that will never
/// arrive. The worker has already done the work; the failure is in
/// the last-mile transport with no signal to either side.
///
/// 4 MiB matches the typical `max_payload` we configure on the NATS
/// JetStream servers in production (it can be bumped via NATS config).
/// `WORKER_MAX_JOB_RESULT_BYTES=0` falls back to the default; an
/// explicit positive value overrides.
const DEFAULT_MAX_JOB_RESULT_BYTES: usize = 4 * 1024 * 1024;

fn max_job_result_bytes() -> usize {
    std::env::var("WORKER_MAX_JOB_RESULT_BYTES")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_MAX_JOB_RESULT_BYTES)
}

/// M-7: Replace an oversized `JobResult` with a small "output too
/// large" error result that still signs and publishes successfully.
/// Pure data transform so the policy is unit-testable.
///
/// Preserves `job_id`, `status` (downgraded to `Failed`), and
/// `execution_time_ms` so callers can still correlate; drops the
/// oversized `output_payload` and `logs` (replaces with a single
/// diagnostic line). The new result MUST be re-signed by the caller
/// before publishing — the signature carries `output_hash` so it
/// would be invalid otherwise.
fn truncate_oversized_job_result(
    result: &JobResult,
    serialized_len: usize,
    cap: usize,
) -> JobResult {
    JobResult {
        // Preserve the token accounting — the usage was real even though
        // the oversized output is dropped, and the entry vec is small
        // (capped at MAX_LLM_USAGE_ENTRIES) so it can't re-breach the cap.
        llm_usage: result.llm_usage.clone(),
        crypto_scheme: 0,
        job_id: result.job_id,
        status: JobStatus::Failed,
        output_payload: serde_json::json!({
            "error": "job_result_too_large",
            "diag": {
                "serialized_bytes": serialized_len,
                "cap_bytes": cap,
                "note": "Worker dropped the original output_payload to keep \
                         under WORKER_MAX_JOB_RESULT_BYTES. Reduce module \
                         output size or raise the cap if this is legitimate."
            }
        }),
        logs: vec![format!(
            "[host] dropped {serialized_len}-byte result (cap {cap})"
        )],
        execution_time_ms: result.execution_time_ms,
        signature: vec![],
        result_nonce: String::new(),
        worker_id: String::new(),
    }
}

async fn publish_result_with_retry(
    nc: &async_nats::Client,
    result: &JobResult,
    max_attempts: u32,
    reply_topic: Option<String>,
    shared_key: &talos_workflow_engine_core::WorkerKeyRing,
) -> Result<(), String> {
    // Serialize once so we can size-check before deciding how to
    // publish. serde_json::to_vec on a JobResult is cheap (single
    // pass) and we'd serialize anyway downstream.
    let serialized = match serde_json::to_vec(&result) {
        Ok(v) => v,
        Err(e) => {
            return Err(format!("Failed to serialize result: {}", e));
        }
    };

    let cap = max_job_result_bytes();
    let payload = if serialized.len() > cap {
        // M-7: degrade to a "result too large" error message so the
        // controller gets a signed Failed status instead of a silent
        // broker rejection + timeout. Sign the replacement; bail with
        // a Err only if signing itself fails (which would indicate the
        // shared key is mis-configured and is already loud upstream).
        ::tracing::error!(
            job_id = %result.job_id,
            serialized_bytes = serialized.len(),
            cap_bytes = cap,
            "JobResult exceeds NATS publish cap — substituting a small Failed result so the controller doesn't time out"
        );
        let mut replacement = truncate_oversized_job_result(result, serialized.len(), cap);
        // L-11: bind the worker's identity into the signature so the
        // controller's audit log records which pod emitted the
        // truncated-replacement result. RFC 0010 P2: prefer the per-worker
        // Ed25519 key when configured, else legacy HMAC. See `sign_job_result`.
        if let Err(e) = sign_job_result(&mut replacement, shared_key) {
            return Err(format!("Failed to sign oversized-result replacement: {e}"));
        }
        match serde_json::to_vec(&replacement) {
            Ok(v) => bytes::Bytes::from(v),
            Err(e) => return Err(format!("Failed to serialize replacement: {e}")),
        }
    } else {
        bytes::Bytes::from(serialized)
    };

    if let Some(reply) = reply_topic {
        publish_bytes_with_retry(nc, reply, payload, max_attempts).await
    } else {
        let result_topic = format!("talos.results.{}", result.job_id);
        publish_bytes_with_retry(nc, result_topic, payload, max_attempts).await
    }
}

/// Build the uniform "failed" `JobResult` shape used by every
/// pre-dispatch rejection path in [`execute_job`] (deadline, secret
/// decryption, module acquisition, hash checks): `status: Failed`,
/// `output_payload: {"error": msg}`, elapsed time from `start`, and
/// empty logs/signature/nonce/worker-id (the publish path signs it).
fn failed_result(job_id: uuid::Uuid, start: &std::time::Instant, msg: &str) -> JobResult {
    JobResult {
        llm_usage: vec![],
        crypto_scheme: 0,
        job_id,
        status: JobStatus::Failed,
        output_payload: json!({ "error": msg }),
        logs: vec![],
        execution_time_ms: start.elapsed().as_millis() as u64,
        signature: vec![],
        result_nonce: String::new(),
        worker_id: String::new(),
    }
}

/// Worker-side gate for the MCP-1212 signature-failure diagnostic (the
/// enriched `output_payload` built in `signature_failure_payload`). OFF by
/// default — the rich payload echoes UNAUTHENTICATED attacker-controllable
/// request fields into a result the worker then signs and publishes. Same
/// env var as the controller's dispatch-side diagnostic so one setting
/// lights up both halves during an investigation. Read once at first use;
/// changing the env after boot has no effect.
static WORKER_SIGNATURE_DIAG_ENABLED: std::sync::LazyLock<bool> = std::sync::LazyLock::new(|| {
    matches!(
        std::env::var("TALOS_SIGNATURE_DIAG").as_deref(),
        Ok("1" | "true")
    )
});

/// Build the `output_payload` for a signature-verification failure.
///
/// `diag_enabled == false` (production default): a generic error only —
/// no request-derived bytes reach the signed result. `true`: the full
/// MCP-1212 field dump for controller↔worker divergence debugging.
/// Pure function so both shapes are unit-testable (see
/// `signature_failure_payload_tests`).
fn signature_failure_payload(
    diag_enabled: bool,
    req: &JobRequest,
    verify_error: &str,
) -> serde_json::Value {
    if !diag_enabled {
        return json!({ "error": "signature verification failed" });
    }
    let (worker_input_hash, worker_secrets_hash, worker_input_byte_len) = req.diag_hashes();
    json!({
        "error": "signature verification failed",
        "diag": {
            "verify_error": verify_error,
            "worker_input_hash": worker_input_hash,
            "worker_secrets_hash": worker_secrets_hash,
            "worker_input_byte_len": worker_input_byte_len,
            "signature_byte_len": req.signature.len(),
            "job_nonce": req.job_nonce,
            "module_uri": req.module_uri,
            "actor_id": req.actor_id.map(|u| u.to_string()),
            "user_id": req.user_id.to_string(),
            "allowed_hosts": req.allowed_hosts,
            "allowed_methods": req.allowed_methods,
            "allowed_secrets": req.allowed_secrets,
            "allowed_sql_operations": req.allowed_sql_operations,
            "allow_tier2_exposure": req.allow_tier2_exposure,
            "integration_name": req.integration_name,
            "expected_wasm_hash": req.expected_wasm_hash,
            "timeout_ms": req.timeout_ms,
            "note": "Compare these worker-computed values against the controller's `signature_diag` WARN log entry for the same job_id to identify which signed field diverged (enable it on the controller with TALOS_SIGNATURE_DIAG=1)."
        }
    })
}

#[cfg(test)]
mod signature_failure_payload_tests {
    use super::*;
    use talos_workflow_job_protocol::{EncryptedSecrets, LlmTier};
    use uuid::Uuid;

    fn unauthenticated_req() -> JobRequest {
        JobRequest {
            crypto_scheme: 0,
            sealing: 0,
            secret_paths: Vec::new(),
            claim_inbox: None,
            job_id: Uuid::new_v4(),
            workflow_execution_id: Uuid::new_v4(),
            module_uri: "wasm://attacker-chosen/v1".to_string(),
            input_payload: serde_json::json!({"x": 1}),
            encrypted_secrets: EncryptedSecrets::empty(),
            timeout_ms: 30000,
            priority: 100,
            deadline_unix_secs: 0,
            cancellation_token: None,
            allowed_hosts: vec!["attacker-chosen-host".to_string()],
            allowed_methods: vec![],
            allowed_secrets: vec!["attacker-chosen-secret".to_string()],
            allowed_sql_operations: vec![],
            allow_tier2_exposure: false,
            signature: vec![1, 2, 3],
            max_llm_tier: LlmTier::default(),
            max_write_ceiling: talos_workflow_job_protocol::WriteCeiling::default(),
            job_nonce: "attacker-chosen-nonce".to_string(),
            actor_id: None,
            wasm_bytes: None,
            capability_world: None,
            integration_name: None,
            user_id: Uuid::nil(),
            expected_wasm_hash: None,
            max_fuel: 0,
            dry_run: false,
            reply_topic: None,
        }
    }

    /// Default (diag OFF): no attacker-supplied byte may reach the payload
    /// the worker will sign and publish — generic error only.
    #[test]
    fn diag_disabled_emits_generic_error_only() {
        let payload = signature_failure_payload(false, &unauthenticated_req(), "hmac mismatch");
        assert_eq!(
            payload,
            serde_json::json!({ "error": "signature verification failed" })
        );
        let raw = payload.to_string();
        for tainted in ["attacker-chosen", "hmac mismatch"] {
            assert!(
                !raw.contains(tainted),
                "unauthenticated request bytes leaked into signed result: {tainted}"
            );
        }
    }

    /// Diag ON (explicit operator opt-in): full MCP-1212 field dump.
    #[test]
    fn diag_enabled_carries_divergence_fields() {
        let payload = signature_failure_payload(true, &unauthenticated_req(), "hmac mismatch");
        let diag = payload.get("diag").expect("diag block present");
        assert_eq!(diag["verify_error"], "hmac mismatch");
        assert_eq!(diag["module_uri"], "wasm://attacker-chosen/v1");
        assert!(diag.get("worker_input_hash").is_some());
    }
}

/// RFC 0010 P1: worker-side dispatch-verify configuration, resolved once from
/// env. The worker holds only the controller's *public* key(s), so it can verify
/// an Ed25519-signed dispatch but cannot forge one — the asymmetric half of the
/// worker-trust boundary.
struct DispatchVerifyConfig {
    /// Controller Ed25519 public key(s). Index 0 is current;
    /// `TALOS_CONTROLLER_PUBLIC_KEY_PREVIOUS` (comma-separated) adds rotated-out
    /// keys for an overlap window. Empty ⇒ Ed25519 dispatches cannot be verified.
    ed_keys: Vec<talos_workflow_job_protocol::DispatchVerifyingKey>,
    /// Whether legacy HMAC (scheme 0) dispatches are still accepted. `true` (the
    /// default) is the rollout posture; `TALOS_DISPATCH_REQUIRE_ED25519=1` flips
    /// it to `false` — the RFC 0010 P4 enforcement flip that refuses HMAC once
    /// the fleet is fully on Ed25519.
    accept_legacy_hmac: bool,
}

/// RFC 0010 P3 (D3b): whether `TALOS_ENVELOPE_SEALING=required` — the worker
/// downgrade-guard flag. Under `required` the worker refuses a `sealing == 0`
/// (inline WSK) dispatch. `off`/`audit`/unset → `false` (both schemes handled).
/// Cached; the flag is fixed for the process lifetime.
fn worker_sealing_required() -> bool {
    static CACHE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *CACHE.get_or_init(|| {
        matches!(
            std::env::var("TALOS_ENVELOPE_SEALING")
                .ok()
                .map(|v| v.trim().to_ascii_lowercase())
                .as_deref(),
            Some("required")
        )
    })
}

/// Load [`DispatchVerifyConfig`] once. Malformed public keys are skipped with a
/// loud warning (so one bad key can't strand the worker), and enabling
/// enforcement without a usable key is logged as an error — the worker then
/// fails closed per-request (rejecting is safe; admitting a forgery is not).
fn dispatch_verify_config() -> &'static DispatchVerifyConfig {
    static CFG: std::sync::OnceLock<DispatchVerifyConfig> = std::sync::OnceLock::new();
    CFG.get_or_init(|| {
        let mut ed_keys = Vec::new();
        if let Ok(cur) = std::env::var("TALOS_CONTROLLER_PUBLIC_KEY") {
            match talos_workflow_job_protocol::parse_ed25519_verifying_key_hex(&cur) {
                Ok(k) => ed_keys.push(k),
                Err(e) => ::tracing::error!(error = %e, "TALOS_CONTROLLER_PUBLIC_KEY is invalid — Ed25519 dispatch verification disabled"),
            }
        }
        if let Ok(prev) = std::env::var("TALOS_CONTROLLER_PUBLIC_KEY_PREVIOUS") {
            for (i, part) in prev.split(',').map(str::trim).filter(|s| !s.is_empty()).enumerate() {
                match talos_workflow_job_protocol::parse_ed25519_verifying_key_hex(part) {
                    Ok(k) => ed_keys.push(k),
                    Err(e) => ::tracing::warn!(index = i, error = %e, "skipping invalid TALOS_CONTROLLER_PUBLIC_KEY_PREVIOUS entry"),
                }
            }
        }
        let require_ed25519 = matches!(
            std::env::var("TALOS_DISPATCH_REQUIRE_ED25519").ok().as_deref(),
            Some("1") | Some("true") | Some("yes") | Some("on")
        );
        if require_ed25519 && ed_keys.is_empty() {
            ::tracing::error!(
                target: "talos_security",
                "TALOS_DISPATCH_REQUIRE_ED25519 is on but no valid TALOS_CONTROLLER_PUBLIC_KEY \
                 is configured — the worker will reject ALL dispatches (fail-closed)"
            );
        }
        DispatchVerifyConfig { ed_keys, accept_legacy_hmac: !require_ed25519 }
    })
}

/// RFC 0010 P2: the worker's per-instance Ed25519 **result-signing** key,
/// resolved once from `TALOS_WORKER_SIGNING_KEY` (a 32-byte hex seed sourced
/// from a Secret / KMS — never a committed plaintext). `None` (the default) ⇒
/// results keep the legacy `WORKER_SHARED_KEY` HMAC path (scheme 0). `Some` ⇒
/// every `JobResult` / `PipelineJobResult` is signed Ed25519 (scheme 1) under
/// this key; the controller verifies against the matching public key registered
/// for this worker's id in `TALOS_WORKER_PUBLIC_KEYS`. Because the controller
/// holds only the public half, a compromised worker can forge results as itself
/// but never as another worker — the asymmetric result-path boundary.
///
/// A present-but-malformed seed fails closed to HMAC (loud error) rather than
/// stranding the worker with no way to sign a result at all.
fn worker_result_signing_key() -> Option<&'static talos_workflow_job_protocol::DispatchSigningKey> {
    static CFG: std::sync::OnceLock<Option<talos_workflow_job_protocol::DispatchSigningKey>> =
        std::sync::OnceLock::new();
    CFG.get_or_init(|| {
        let raw = std::env::var("TALOS_WORKER_SIGNING_KEY").ok()?;
        match talos_workflow_job_protocol::parse_ed25519_signing_key_hex(&raw) {
            Ok(sk) => {
                ::tracing::info!(
                    target: "talos_security",
                    "TALOS_WORKER_SIGNING_KEY loaded — signing job results with per-worker Ed25519 (RFC 0010 P2)"
                );
                Some(sk)
            }
            Err(e) => {
                ::tracing::error!(
                    target: "talos_security",
                    error = %e,
                    "TALOS_WORKER_SIGNING_KEY is invalid — falling back to legacy HMAC result signing"
                );
                None
            }
        }
    })
    .as_ref()
}

/// Sign a `JobResult`, preferring the per-worker Ed25519 key when configured
/// (RFC 0010 P2) and falling back to the legacy `WORKER_SHARED_KEY` HMAC. Binds
/// the worker's identity into the signature either way (L-11). Single source of
/// truth for every `JobResult` sign site so the scheme can't diverge between the
/// happy path and the oversized-result replacement path.
fn sign_job_result(
    result: &mut JobResult,
    shared_key: &talos_workflow_engine_core::WorkerKeyRing,
) -> Result<(), String> {
    match worker_result_signing_key() {
        Some(sk) => result.sign_ed25519_with_worker_id(sk, worker_identity()),
        None => result.sign_with_worker_id(shared_key.signing_key().as_bytes(), worker_identity()),
    }
}

/// Ed25519-preferring signer for `PipelineJobResult`; see [`sign_job_result`].
fn sign_pipeline_result(
    result: &mut PipelineJobResult,
    shared_key: &talos_workflow_engine_core::WorkerKeyRing,
) -> Result<(), String> {
    match worker_result_signing_key() {
        Some(sk) => result.sign_ed25519_with_worker_id(sk, worker_identity()),
        None => result.sign_with_worker_id(shared_key.signing_key().as_bytes(), worker_identity()),
    }
}

/// Execute the Wasm module for a given job with observability.
///
/// * Verifies the dispatch signature (Ed25519 or legacy HMAC) before executing.
/// * Decrypts secrets from `req.encrypted_secrets` using the shared key.
/// * Passes decrypted secrets to the runtime so WASM modules can access them
///   via the `secrets::get-secret` host function.
#[::tracing::instrument(name = "job-execution", skip_all)]
async fn execute_job(
    cx: &opentelemetry::Context,
    req: JobRequest,
    runtime: Arc<TalosRuntime>,
    shared_key: talos_workflow_engine_core::WorkerKeyRing,
    // RFC 0010 P3 (D3b): NATS client for the secret-claim round-trip when a
    // dispatch arrives with `sealing == SEALING_CLAIM_ECIES`.
    nc: &async_nats::Client,
) -> JobResult {
    let start = std::time::Instant::now();

    // The `#[instrument]` span above is THE job span; wrap it and link it to the
    // propagated controller trace context. All `_span.*` calls below set
    // attributes / events / status on it, exported via the otel bridge layer.
    let mut _span = JobSpan::current_with_parent(cx);
    _span.set_attribute("job_id", &req.job_id.to_string());
    _span.set_attribute("module_uri", &req.module_uri);

    // SECURITY: verify the dispatch signature + nonce freshness (300 s window).
    // RFC 0010 P1: `verify_dispatch` routes on the request's `crypto_scheme` —
    // Ed25519 against the controller public key(s), or legacy HMAC against the
    // WORKER_SHARED_KEY ring (accepted while `accept_legacy_hmac`, refused once
    // TALOS_DISPATCH_REQUIRE_ED25519 flips it off). Ring-aware on the HMAC side
    // so a rolling WORKER_SHARED_KEY rotation doesn't reject controller-signed
    // jobs.
    let dvc = dispatch_verify_config();
    if let Err(e) = req.verify_dispatch(&shared_key, &dvc.ed_keys, 300, dvc.accept_legacy_hmac) {
        ::tracing::error!(job_id = %req.job_id, error = %e, "Job signature verification failed");
        _span.set_attribute("error", "signature_verification_failed");
        _span.end_error("Signature verification failed");

        // MCP-1212 (2026-05-18): diagnostic enrichment for signature
        // verification failures — recompute the per-field hashes that
        // `signing_payload()` consumes so the operator can identify which
        // signed field diverged between controller and worker.
        //
        // 2026-07-01 hardening: the enriched payload is now gated behind
        // `TALOS_SIGNATURE_DIAG=1` on the WORKER (same env the controller
        // uses for its side of the diagnostic), default OFF. The request
        // failed authentication, yet the rich variant echoes
        // attacker-supplied fields (module_uri, allowed_secrets, hashes)
        // into a JobResult that the publish path then SIGNS with the
        // worker key — a free sign-chosen-strings oracle plus a field-hash
        // oracle for an on-NATS attacker. Default is a generic error;
        // enable the env on both sides while investigating a real
        // controller↔worker signing divergence, then unset it.
        return JobResult {
            llm_usage: vec![],
            crypto_scheme: 0,
            job_id: req.job_id,
            status: JobStatus::Failed,
            output_payload: signature_failure_payload(*WORKER_SIGNATURE_DIAG_ENABLED, &req, &e),
            logs: vec![],
            execution_time_ms: start.elapsed().as_millis() as u64,
            signature: vec![],
            result_nonce: String::new(),
            worker_id: String::new(),
        };
    }

    // DEADLINE CHECK: Reject jobs whose deadline has already passed.
    if req.deadline_unix_secs > 0 {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if now_secs > req.deadline_unix_secs {
            _span.set_attribute("error", "deadline_expired");
            _span.end_error("Job deadline expired before execution started");
            return failed_result(req.job_id, &start, "job deadline expired");
        }
    }

    // RFC 0010 P3 (D3b): downgrade guard. Under `TALOS_ENVELOPE_SEALING=required`
    // the worker refuses a legacy inline dispatch that would DECRYPT a WSK
    // envelope — the enforcement point that stops an on-wire downgrade from
    // forcing the fleet-wide key back into use. A `sealing == 0` dispatch with an
    // EMPTY `encrypted_secrets` decrypts nothing (a no-secret node), so it is
    // allowed even under `required` — otherwise every secretless node (transforms,
    // routers, …) would break. Only a non-empty WSK ciphertext under `required` is
    // a refused downgrade. Under `off`/`audit` both schemes are handled.
    if worker_sealing_required()
        && req.sealing != talos_workflow_job_protocol::SEALING_CLAIM_ECIES
        && !req.encrypted_secrets.ciphertext.is_empty()
    {
        ::tracing::error!(
            target: "talos_security",
            job_id = %req.job_id,
            "TALOS_ENVELOPE_SEALING=required but dispatch carries a sealing=0 WSK envelope — refusing"
        );
        _span.end_error("envelope sealing required; inline dispatch refused");
        return failed_result(
            req.job_id,
            &start,
            "envelope sealing required; inline dispatch refused",
        );
    }

    // SECURITY: obtain the job's secrets.
    // - `sealing == 1` (P3): claim them via a signed `SecretClaim` to the
    //   controller's `claim_inbox`; the controller seals to this worker's fresh
    //   ephemeral key and the reply opens under it (forward secrecy). Fail-closed
    //   on any claim/verify/open error — never run secretless.
    // - `sealing == 0` (legacy): decrypt the inline WSK envelope. L-1
    //   (2026-05-22): AAD = workflow_execution_id binds the AES-GCM tag to this
    //   execution (already HMAC-bound in the signing payload), so a transposed
    //   ciphertext fails the tag check here.
    let secrets: HashMap<String, String> = if req.sealing
        == talos_workflow_job_protocol::SEALING_CLAIM_ECIES
    {
        let Some(signing_key) = worker_result_signing_key() else {
            ::tracing::error!(
                target: "talos_security",
                job_id = %req.job_id,
                "sealing=1 dispatch requires TALOS_WORKER_SIGNING_KEY to sign the claim"
            );
            _span.end_error("sealing=1 requires a worker signing key");
            return failed_result(
                req.job_id,
                &start,
                "sealing=1 dispatch requires a worker signing key",
            );
        };
        match secret_claim::claim_secrets(
            nc,
            req.job_id,
            req.claim_inbox.as_deref(),
            worker_identity(),
            signing_key,
            &dvc.ed_keys,
        )
        .await
        {
            Ok(map) => map,
            Err(e) => {
                ::tracing::error!(
                    target: "talos_security",
                    job_id = %req.job_id,
                    error = %e,
                    "RFC 0010 P3 secret claim failed"
                );
                _span.end_error("secret claim failed");
                return failed_result(req.job_id, &start, "failed to obtain sealed secrets");
            }
        }
    } else if req.encrypted_secrets.is_empty() {
        HashMap::new()
    } else {
        match req
            .encrypted_secrets
            .decrypt_with_ring(&shared_key, req.workflow_execution_id.as_bytes())
        {
            Ok(s) => s,
            Err(e) => {
                ::tracing::error!(job_id = %req.job_id, error = %e, "Failed to decrypt job secrets");
                _span.end_error("Secret decryption failed");

                return failed_result(req.job_id, &start, "failed to decrypt job secrets");
            }
        }
    };

    // Load the Wasm module bytes — acquisition (inline bytes / OCI pull
    // with Sigstore + layer-digest verification / Redis cache /
    // filesystem fallback) lives in `worker::module_fetcher::fetch`,
    // which also documents the attestation model. On failure the
    // FetchError message is byte-for-byte the string the inline code
    // previously placed in the failed result and the span status.
    let FetchedModule {
        bytes: wasm_bytes,
        attested_in_this_run: bytes_attested_in_this_run,
    } = match module_fetcher::fetch(&req, &runtime, &mut _span).await {
        Ok(fetched) => fetched,
        Err(e) => {
            _span.end_error(&e.message);
            return failed_result(req.job_id, &start, &e.message);
        }
    };

    // SECURITY: Verify WASM content hash when inline bytes were not provided.
    // `req.expected_wasm_hash` is set by the controller from `wasm_modules.content_hash`
    // (the SHA-256 recorded at compile time) and covered by the HMAC signing payload,
    // so an attacker who compromises the storage layer (Redis, OCI, filesystem) cannot
    // substitute malicious bytes without the mismatch being detected here.
    //
    // When `wasm_bytes` was provided inline the HMAC already covers sha256(bytes) — no
    // additional check needed.  We only verify when the worker loaded bytes from a URI.
    if req.wasm_bytes.is_none() {
        if let Some(ref expected) = req.expected_wasm_hash {
            use sha2::{Digest, Sha256};
            let actual = hex::encode(Sha256::digest(&wasm_bytes));
            if actual != *expected {
                ::tracing::error!(
                    job_id = %req.job_id,
                    module_uri = %req.module_uri,
                    expected_hash = %expected,
                    actual_hash = %actual,
                    "SECURITY: WASM content hash mismatch — possible storage tampering, refusing execution"
                );
                _span.end_error("wasm_hash_mismatch");
                return failed_result(
                    req.job_id,
                    &start,
                    "WASM integrity check failed: content hash mismatch",
                );
            }
            ::tracing::debug!(
                job_id = %req.job_id,
                module_uri = %req.module_uri,
                hash = %actual,
                "WASM content hash verified"
            );
        } else if !bytes_attested_in_this_run {
            // No hash commitment from the controller AND the bytes did not
            // pass Sigstore + layer-digest checks in this run — i.e. they
            // came from an OCI cache fallback, `redis:wasm:` fetch, or
            // filesystem load with nothing cryptographically tying them
            // to the controller's recorded `wasm_modules.content_hash`.
            //
            // A Redis-write attacker (compromised pod, shared infra) could
            // substitute arbitrary WASM into the cache — without
            // `expected_wasm_hash` we have no evidence to detect it.
            //
            // M-5: gate this fallback on a POSITIVE opt-in
            // (`TALOS_ALLOW_UNATTESTED_WASM=1`) instead of "if not
            // production". Pre-fix a dev image accidentally promoted to
            // production, or a container with `RUST_ENV` unset, would
            // silently accept arbitrary cache bytes. The new policy is
            // fail-closed by default: misconfiguration refuses to run.
            // Operators who need the dev shortcut must set the env var
            // explicitly. The legacy production gate stays as
            // belt-and-braces — production never accepts unattested
            // bytes regardless of the override.
            let is_prod = talos_config::is_production();
            let allow_unattested = std::env::var("TALOS_ALLOW_UNATTESTED_WASM")
                .ok()
                .map(|v| matches!(v.as_str(), "1" | "true" | "yes"))
                .unwrap_or(false);
            let block_unattested = is_prod || !allow_unattested;
            if block_unattested {
                ::tracing::error!(
                    job_id = %req.job_id,
                    module_uri = %req.module_uri,
                    "SECURITY: refusing to execute WASM loaded from unverified storage \
                     (cache/redis/filesystem) without expected_wasm_hash. Either supply \
                     a hash or load from a path that Sigstore-verifies in this run"
                );
                _span.end_error("unattested_wasm_no_hash");
                return failed_result(
                    req.job_id,
                    &start,
                    "WASM integrity check failed: no hash and no in-run attestation",
                );
            }
            ::tracing::warn!(
                job_id = %req.job_id,
                module_uri = %req.module_uri,
                "WASM loaded from unattested storage without expected_wasm_hash \
                 (TALOS_ALLOW_UNATTESTED_WASM=1 set — would fail closed without this override). \
                 Always supply expected_wasm_hash or attest in-run via Sigstore in production."
            );
        } else {
            // Bytes were attested in this run via Sigstore + digest checks.
            // No expected_wasm_hash supplied is OK — the in-run attestation
            // is the trust root.
            ::tracing::debug!(
                job_id = %req.job_id,
                module_uri = %req.module_uri,
                "WASM attested via in-run Sigstore + layer-digest verification"
            );
        }
    }

    // Build execution context for automatic logging to database
    _span.add_event("executing_wasm");
    let execution_context = Some((
        req.workflow_execution_id.to_string(), // workflow_id
        req.job_id.to_string(),                // execution_id (for NATS logging)
        req.module_uri.clone(),                // module_id
    ));

    // Build per-module security policy from the job request.
    let security_policy = SecurityPolicy {
        allowed_secrets: req.allowed_secrets.clone(),
        allowed_sql_operations: req.allowed_sql_operations.clone(),
        allow_tier2_exposure: req.allow_tier2_exposure,
        integration_name: req.integration_name.clone(),
    };

    // Parse the capability world hint from the controller.  When present and non-Unknown,
    // the runtime uses it instead of re-inspecting the WASM binary.  This is critical for
    // sandbox modules whose Wizer-snapshotted binary may have lost embedded WIT world-name
    // strings that inspect_component relies on.
    let capability_world_hint: Option<worker::wit_inspector::CapabilityWorld> =
        req.capability_world.as_deref().and_then(|s| s.parse().ok());

    // Honor the controller-supplied `timeout_ms` from the job request. The
    // controller has already sourced it from the node's `timeout_secs` (or the
    // per-env `WASM_EXECUTION_TIMEOUT_SECS` default). Fallback: use the same
    // `WASM_EXECUTION_TIMEOUT_SECS` env var (60s default) when the request
    // didn't specify. Previously both timeouts were hardcoded 30s, which
    // silently capped agent-node modules calling `llm::complete` even when
    // the author set `timeout_secs: 120` on the node.
    // MCP-642 (2026-05-13): if WASM_EXECUTION_TIMEOUT_SECS=0 AND the
    // caller didn't specify req.timeout_ms, the job timeout below
    // becomes 0ms → every job times out instantly. Same MCP-639 class.
    // 120s default kept in lockstep with DEFAULT_NODE_TIMEOUT_SECS
    // (talos-workflow-engine) and get_wasm_config so the worker's fallback job
    // timeout matches the controller's reply-wait and the operator-reported value.
    let worker_fallback_secs: u64 =
        worker::runtime::nonzero_env_or_default("WASM_EXECUTION_TIMEOUT_SECS", 120);
    let job_timeout_ms: u64 = if req.timeout_ms > 0 {
        req.timeout_ms
    } else {
        worker_fallback_secs.saturating_mul(1000)
    };
    let job_timeout = std::time::Duration::from_millis(job_timeout_ms);
    // R2 token ledger: worker-owned accumulator shared with the job's
    // TalosContext; drained into the signed JobResult on EVERY branch below
    // (success, failure, timeout) — tokens spent before a trap are spent.
    let llm_usage_acc: worker::context::LlmUsageAcc =
        std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    match tokio::time::timeout(
        job_timeout,
        runtime.execute_job_with_full_features(
            &wasm_bytes,
            req.allowed_hosts.clone(),
            req.allowed_methods.clone(),
            128,
            req.input_payload.clone(),
            None, // No custom file sandbox
            execution_context,
            secrets,
            None,        // token_sender
            job_timeout, // per-job timeout — matches the outer tokio::time::timeout
            RetryPolicy::default(),
            None, // No result caching for NATS jobs — each execution must be fresh
            security_policy,
            capability_world_hint,
            if req.max_fuel > 0 {
                Some(req.max_fuel)
            } else {
                None
            },
            req.dry_run,
            req.actor_id,
            req.user_id,
            req.max_llm_tier,
            req.max_write_ceiling,
            req.egress_scope,
            Some(llm_usage_acc.clone()),
        ),
    )
    .await
    {
        Ok(Ok(output)) => {
            let duration_ms = start.elapsed().as_millis() as u64;
            _span.set_attribute_int("duration_ms", duration_ms as i64);
            _span.end_success();

            JobResult {
                llm_usage: worker::context::drain_llm_usage_entries(&llm_usage_acc),
                crypto_scheme: 0,
                job_id: req.job_id,
                status: JobStatus::Success,
                output_payload: output,
                logs: vec![],
                execution_time_ms: duration_ms,
                signature: vec![],
                result_nonce: String::new(),
                worker_id: String::new(),
            }
        }
        Ok(Err(e)) => {
            let duration_ms = start.elapsed().as_millis() as u64;
            let error_msg = format!("execution failure: {}", e);
            let sanitized_error = sanitize_error_message(&error_msg);
            _span.set_attribute("error", &sanitized_error);
            _span.set_attribute_int("duration_ms", duration_ms as i64);
            _span.end_error(&sanitized_error);

            JobResult {
                llm_usage: worker::context::drain_llm_usage_entries(&llm_usage_acc),
                crypto_scheme: 0,
                job_id: req.job_id,
                status: JobStatus::Failed,
                output_payload: json!({"error": sanitized_error}),
                logs: vec![],
                execution_time_ms: duration_ms,
                signature: vec![],
                result_nonce: String::new(),
                worker_id: String::new(),
            }
        }
        Err(_) => {
            let duration_ms = start.elapsed().as_millis() as u64;
            let error_msg = "execution timed out after 30 seconds".to_string();
            _span.set_attribute("error", &error_msg);
            _span.set_attribute_int("duration_ms", duration_ms as i64);
            _span.end_error(&error_msg);

            JobResult {
                // Timeout drops the execution future, but usage folded
                // before the deadline is preserved via the shared Arc.
                // A detached in-flight stream reader could in principle
                // fold shortly after this drain — those late tokens are
                // deliberately dropped rather than racing the signature.
                llm_usage: worker::context::drain_llm_usage_entries(&llm_usage_acc),
                crypto_scheme: 0,
                job_id: req.job_id,
                status: JobStatus::Failed,
                output_payload: json!({"error": error_msg}),
                logs: vec![],
                execution_time_ms: duration_ms,
                signature: vec![],
                result_nonce: String::new(),
                worker_id: String::new(),
            }
        }
    }
}

/// Execute a pipeline job dispatched via NATS.
///
/// * Verifies the HMAC signature and nonce freshness.
/// * Decrypts per-step secrets.
/// * Runs `execute_pipeline()` on the runtime.
/// * Signs and publishes the `PipelineJobResult`.
#[::tracing::instrument(name = "pipeline-execution", skip_all)]
async fn execute_pipeline_job(
    cx: &opentelemetry::Context,
    req: PipelineJobRequest,
    runtime: Arc<TalosRuntime>,
    shared_key: talos_workflow_engine_core::WorkerKeyRing,
    // RFC 0010 P3 (D3b): NATS client for the secret-claim round-trip when a
    // pipeline dispatch arrives with `sealing == SEALING_CLAIM_ECIES`.
    nc: &async_nats::Client,
) -> PipelineJobResult {
    use talos_workflow_job_protocol::JobStatus;

    let start = std::time::Instant::now();
    // The `#[instrument]` span above is THE pipeline span; wrap + link it to the
    // propagated controller trace context (see `execute_job` for the rationale).
    let mut _span = JobSpan::current_with_parent(cx);

    // SECURITY: verify the dispatch signature + nonce freshness (300 s window).
    // RFC 0010 P1: scheme-dispatched (Ed25519 or legacy HMAC), ring-aware on the
    // HMAC side for rolling WORKER_SHARED_KEY rotation. See `execute_job`.
    let dvc = dispatch_verify_config();
    if let Err(e) = req.verify_dispatch(&shared_key, &dvc.ed_keys, 300, dvc.accept_legacy_hmac) {
        ::tracing::error!(job_id = %req.job_id, error = %e, "Pipeline job signature verification failed");
        _span.set_attribute("error", "signature_verification_failed");
        _span.end_error("Signature verification failed");
        return PipelineJobResult {
            llm_usage: vec![],
            crypto_scheme: 0,
            job_id: req.job_id,
            overall_status: JobStatus::Failed,
            step_results: vec![],
            final_output: serde_json::json!({"error": "pipeline signature verification failed"}),
            total_time_ms: start.elapsed().as_millis() as u64,
            signature: vec![],
            result_nonce: String::new(),
            worker_id: String::new(),
        };
    }

    // Helper for the fail-closed returns below (span mutation stays inline).
    let fail = |msg: &str| PipelineJobResult {
        llm_usage: vec![],
        crypto_scheme: 0,
        job_id: req.job_id,
        overall_status: JobStatus::Failed,
        step_results: vec![],
        final_output: serde_json::json!({ "error": msg }),
        total_time_ms: start.elapsed().as_millis() as u64,
        signature: vec![],
        result_nonce: String::new(),
        worker_id: String::new(),
    };

    // RFC 0010 P3 (D3b) downgrade guard: under `TALOS_ENVELOPE_SEALING=required`
    // refuse a legacy pipeline that would DECRYPT a WSK envelope in ANY step. A
    // `sealing == 1` pipeline uses the claim path below; a `sealing == 0` pipeline
    // whose steps all carry empty envelopes (no-secret steps) decrypts nothing and
    // is allowed even under `required`. Only a non-empty WSK ciphertext under
    // `required` is a refused downgrade.
    if worker_sealing_required()
        && req.sealing != talos_workflow_job_protocol::SEALING_CLAIM_ECIES
        && req
            .steps
            .iter()
            .any(|s| !s.encrypted_secrets.ciphertext.is_empty())
    {
        ::tracing::error!(
            target: "talos_security",
            job_id = %req.job_id,
            "TALOS_ENVELOPE_SEALING=required but a pipeline step carries a sealing=0 WSK envelope — refusing"
        );
        _span.end_error("envelope sealing required; inline pipeline refused");
        return fail("envelope sealing required; inline pipeline refused");
    }

    // Validate maximum pipeline timeout to prevent indefinitely tying up workers.
    // MCP-642: =0 would reject every pipeline job (req.total_timeout_ms > 0
    // always exceeds 0). Substitute default + WARN.
    let max_timeout_ms: u64 =
        worker::runtime::nonzero_env_or_default("WASM_MAX_PIPELINE_TIMEOUT_MS", 3_600_000);

    if req.total_timeout_ms > max_timeout_ms {
        ::tracing::warn!(
            job_id = %req.job_id,
            requested_ms = req.total_timeout_ms,
            max_ms = max_timeout_ms,
            "Pipeline job rejected: timeout exceeds maximum"
        );
        _span.end_error("Timeout exceeds maximum");
        return PipelineJobResult {
            llm_usage: vec![],
            crypto_scheme: 0,
            job_id: req.job_id,
            overall_status: JobStatus::Failed,
            step_results: vec![],
            final_output: serde_json::json!({"error": format!("Requested total timeout ({}ms) exceeds maximum allowed ({}ms)", req.total_timeout_ms, max_timeout_ms)}),
            total_time_ms: start.elapsed().as_millis() as u64,
            signature: vec![],
            result_nonce: String::new(),
            worker_id: String::new(),
        };
    }

    // RFC 0010 P3 (D3b): under claim-based sealing, ONE claim to the controller
    // returns the per-step secrets vector (aligned index-for-index with
    // `req.steps`). Fail-closed on any claim / verify / open / shape error — a
    // pipeline whose secrets can't be obtained must not run secretless.
    let claimed_secrets: Option<Vec<std::collections::HashMap<String, String>>> = if req.sealing
        == talos_workflow_job_protocol::SEALING_CLAIM_ECIES
    {
        let Some(signing_key) = worker_result_signing_key() else {
            ::tracing::error!(
                target: "talos_security",
                job_id = %req.job_id,
                "sealing=1 pipeline requires TALOS_WORKER_SIGNING_KEY to sign the claim"
            );
            _span.end_error("sealing=1 requires a worker signing key");
            return fail("sealing=1 pipeline requires a worker signing key");
        };
        match secret_claim::claim_secrets_raw(
            nc,
            req.job_id,
            req.claim_inbox.as_deref(),
            worker_identity(),
            signing_key,
            &dvc.ed_keys,
        )
        .await
        {
            Ok(raw) => {
                match serde_json::from_slice::<Vec<std::collections::HashMap<String, String>>>(&raw)
                {
                    Ok(v) => Some(v),
                    Err(e) => {
                        ::tracing::error!(target: "talos_security", job_id = %req.job_id, error = %e, "malformed pipeline claim payload");
                        _span.end_error("malformed pipeline claim payload");
                        return fail("malformed sealed pipeline secrets");
                    }
                }
            }
            Err(e) => {
                ::tracing::error!(target: "talos_security", job_id = %req.job_id, error = %e, "RFC 0010 P3 pipeline secret claim failed");
                _span.end_error("pipeline secret claim failed");
                return fail("failed to obtain sealed pipeline secrets");
            }
        }
    } else {
        None
    };

    // Build PipelineStepSpecs. Under claim-based sealing use the claimed per-step
    // map for step `i`; otherwise decrypt the step's inline WSK envelope.
    // L-1: AAD = workflow_execution_id, shared across all steps in
    // this pipeline (matches the encryption-side binding).
    let mut step_specs: Vec<PipelineStepSpec> = Vec::with_capacity(req.steps.len());
    for (i, step) in req.steps.iter().enumerate() {
        let secrets = if let Some(ref per_step) = claimed_secrets {
            per_step.get(i).cloned().unwrap_or_default()
        } else if step.encrypted_secrets.is_empty() {
            std::collections::HashMap::new()
        } else {
            match step
                .encrypted_secrets
                .decrypt_with_ring(&shared_key, req.workflow_execution_id.as_bytes())
            {
                Ok(s) => s,
                Err(e) => {
                    ::tracing::error!(job_id = %req.job_id, error = %e, "Failed to decrypt pipeline step secrets");
                    _span.end_error("Secret decryption failed");
                    return PipelineJobResult {
                        llm_usage: vec![],
                        crypto_scheme: 0,
                        job_id: req.job_id,
                        overall_status: JobStatus::Failed,
                        step_results: vec![],
                        final_output: serde_json::json!({"error": "failed to decrypt step secrets"}),
                        total_time_ms: start.elapsed().as_millis() as u64,
                        signature: vec![],
                        result_nonce: String::new(),
                        worker_id: String::new(),
                    };
                }
            }
        };

        step_specs.push(PipelineStepSpec {
            module_id: step.module_id.to_string(),
            wasm_bytes: step.wasm_bytes.clone().unwrap_or_default(),
            config: step.config.clone(),
            allowed_hosts: step.allowed_hosts.clone(),
            allowed_methods: step.allowed_methods.clone(),
            secrets,
            max_fuel: step.max_fuel,
            max_memory_mb: step.max_memory_mb,
            timeout: std::time::Duration::from_millis(step.timeout_ms),
            security_policy: SecurityPolicy {
                allowed_secrets: step.allowed_secrets.clone(),
                allowed_sql_operations: step.allowed_sql_operations.clone(),
                allow_tier2_exposure: step.allow_tier2_exposure,
                integration_name: step.integration_name.clone(),
            },
            user_id: Some(req.user_id),
        });
    }

    let overall_timeout = std::time::Duration::from_millis(req.total_timeout_ms);

    // R2 token ledger: worker-owned accumulator shared with every step's
    // context; drained into the signed PipelineJobResult on BOTH branches
    // (a mid-pipeline bail still reports the completed steps' tokens).
    let llm_usage_acc: worker::context::LlmUsageAcc =
        std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

    match runtime
        .execute_pipeline(
            &req.workflow_execution_id.to_string(),
            step_specs,
            overall_timeout,
            req.share_sandbox,
            req.max_llm_tier,
            req.max_write_ceiling,
            req.egress_scope,
            Some(llm_usage_acc.clone()),
        )
        .await
    {
        Ok(pipeline_result) => {
            let total_time_ms = start.elapsed().as_millis() as u64;
            _span.set_attribute_int("duration_ms", total_time_ms as i64);
            _span.end_success();

            let step_results: Vec<PipelineStepResult> = req
                .steps
                .iter()
                .zip(pipeline_result.step_outputs.iter())
                .zip(pipeline_result.step_times_ms.iter())
                .map(|((step, output), &time_ms)| PipelineStepResult {
                    module_id: step.module_id,
                    status: JobStatus::Success,
                    output: output.clone(),
                    execution_time_ms: time_ms,
                    error: None,
                })
                .collect();

            PipelineJobResult {
                llm_usage: worker::context::drain_llm_usage_entries(&llm_usage_acc),
                crypto_scheme: 0,
                job_id: req.job_id,
                overall_status: JobStatus::Success,
                step_results,
                final_output: pipeline_result.final_output,
                total_time_ms,
                signature: vec![],
                result_nonce: String::new(),
                worker_id: String::new(),
            }
        }
        Err(e) => {
            let total_time_ms = start.elapsed().as_millis() as u64;
            let error_msg = format!("pipeline execution failure: {}", e);
            let sanitized_error = sanitize_error_message(&error_msg);
            _span.set_attribute("error", &sanitized_error);
            _span.set_attribute_int("duration_ms", total_time_ms as i64);
            _span.end_error(&sanitized_error);

            PipelineJobResult {
                llm_usage: worker::context::drain_llm_usage_entries(&llm_usage_acc),
                crypto_scheme: 0,
                job_id: req.job_id,
                overall_status: JobStatus::Failed,
                step_results: vec![],
                final_output: serde_json::json!({"error": sanitized_error}),
                total_time_ms,
                signature: vec![],
                result_nonce: String::new(),
                worker_id: String::new(),
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // rustls 0.23 requires an explicit CryptoProvider when the dep graph
    // contains more than one. We pull rustls in via redis (tls-rustls) and
    // reqwest. install_default is idempotent — Err means another caller
    // already installed one, which is fine.
    let _ = rustls::crypto::ring::default_provider().install_default();

    println!("=== Talos Worker Starting ===\n");

    // ========================================================================
    // SECURITY: Load and validate the shared key at startup.
    // Fail-fast if the key is absent or malformed — never start with no auth.
    // ========================================================================

    // Load the full verify/decrypt-ring (current + WORKER_SHARED_KEY_PREVIOUS).
    // The worker SIGNS results + RPC with the current key only; it VERIFIES
    // controller-signed jobs and DECRYPTS secrets against the whole ring, so a
    // rolling WORKER_SHARED_KEY rotation doesn't break either side mid-roll.
    let shared_key =
        load_worker_key_ring().map_err(|e| anyhow::anyhow!("WORKER_SHARED_KEY error: {}", e))?;
    // M-3 (partial): log a SHA-256 fingerprint of the shared key at
    // startup so config drift between controller and worker is visible
    // without exposing the key material. Operators can grep both
    // process logs for `worker_shared_key_fp=` and confirm they match
    // — if they don't, all signed RPCs will fail verification and the
    // error surfaces here instead of as opaque "signature verification
    // failed" later. We log only the first 8 hex chars (32 bits) which
    // is enough to detect mismatch with negligible info leak.
    {
        let fp_short = talos_workflow_job_protocol::worker_key_fingerprint(
            shared_key.signing_key().as_bytes(),
        );
        let verify_count = shared_key.verify_keys().len();
        println!(
            "[0/5] Loaded WORKER_SHARED_KEY (32 bytes, fp={fp_short}, verify_keys={verify_count})"
        );
        ::tracing::info!(
            worker_shared_key_fp = %fp_short,
            verify_key_count = verify_count,
            "WORKER_SHARED_KEY loaded; compare this fingerprint against the controller's log line for drift detection"
        );
        for prev in shared_key.verify_keys().iter().skip(1) {
            ::tracing::info!(
                previous_worker_shared_key_fp =
                    %talos_workflow_job_protocol::worker_key_fingerprint(prev.as_bytes()),
                "WORKER_SHARED_KEY_PREVIOUS accepted for verify/decrypt (rotation in progress)"
            );
        }
    }

    // Wasm-security review 2026-05-22 (MEDIUM-4): production gate. In
    // production we refuse to boot unless the operator has made an
    // explicit Sigstore choice (required / audit / disabled). Pre-fix,
    // `from_env` silently fell through to `Disabled` when the env var
    // was unset — the operator's monitoring saw a clean startup and
    // had no signal that signature verification was off. Mirrors the
    // `TALOS_AOT_HMAC_KEY` boot discipline so production failures are
    // loud and immediate. Dev/test hosts (`is_production() == false`)
    // continue to see the silent default.
    enforce_production_sigstore_policy_explicit()?;

    // L-4: Sigstore startup sanity — verify `cosign` is actually
    // executable when policy is non-Disabled. Pre-fix the missing
    // binary surfaced as a per-pull "cosign_unavailable" error;
    // production deploys that THOUGHT verification was running
    // discovered the gap only when an unsigned artifact slipped
    // through (or, in Required mode, when every pull failed).
    // Failing at boot in Required mode is loud, immediate, and
    // points at the right config knob.
    {
        let sigstore_policy = SigstorePolicy::from_env();
        if sigstore_policy != SigstorePolicy::Disabled {
            match tokio::process::Command::new("cosign")
                .arg("version")
                .output()
                .await
            {
                Ok(out) if out.status.success() => {
                    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                    let version_line = stdout.lines().next().unwrap_or("(unknown)").to_string();

                    // M5 (2026-05-22): version-pin cosign so a swapped-in
                    // older binary (predating critical CVE fixes) or a
                    // replaced binary doesn't silently pass through.
                    // `TALOS_COSIGN_MIN_VERSION` is the minimum
                    // semver-ish version accepted; default `2.0.0`
                    // matches the cosign 2.x line which is the
                    // long-supported branch with hardened defaults.
                    //
                    // Parse rule: pull the first dotted `X.Y.Z` token
                    // out of stdout (cosign output format has shifted
                    // across versions; the version triple is the only
                    // stable shape). Fail-closed in Required mode if
                    // we can't parse anything; warn-and-continue under
                    // Audit. This is operator-tunable via the env so
                    // a future cosign 3.x bump doesn't require code
                    // changes.
                    let min_version = std::env::var("TALOS_COSIGN_MIN_VERSION")
                        .ok()
                        .filter(|v| !v.is_empty())
                        .unwrap_or_else(|| "2.0.0".to_string());
                    match parse_cosign_version(&stdout) {
                        Some((maj, min, patch)) => {
                            let parsed_observed = (maj, min, patch);
                            let parsed_min = parse_semver_triple(&min_version).unwrap_or((2, 0, 0));
                            if parsed_observed < parsed_min {
                                let msg = format!(
                                    "cosign version {}.{}.{} is below required minimum {} \
                                     (set TALOS_COSIGN_MIN_VERSION to override)",
                                    parsed_observed.0,
                                    parsed_observed.1,
                                    parsed_observed.2,
                                    min_version,
                                );
                                if sigstore_policy == SigstorePolicy::Required {
                                    return Err(anyhow::anyhow!(
                                        "Sigstore startup sanity check failed: {msg}"
                                    ));
                                }
                                ::tracing::warn!(
                                    cosign_version = %version_line,
                                    min_version = %min_version,
                                    "{msg} (Audit mode: continuing)"
                                );
                            }
                        }
                        None => {
                            if sigstore_policy == SigstorePolicy::Required {
                                return Err(anyhow::anyhow!(
                                    "Could not parse cosign version from stdout: {version_line:?}. \
                                     Required policy refuses to boot without a verified version pin."
                                ));
                            }
                            ::tracing::warn!(
                                stdout = %stdout,
                                "Could not parse cosign version — version-pin check skipped (Audit mode)"
                            );
                        }
                    }

                    // M5 part B: optional SHA-256 pin of the cosign
                    // binary itself. When set, the worker hashes the
                    // resolved cosign executable and refuses to boot
                    // if the hash doesn't match. This closes the
                    // "swap cosign with a wrapper that always exits 0"
                    // attack path. Most operators won't set this;
                    // sigstore-enforcement clusters that want defense
                    // in depth absolutely should.
                    //
                    // L-3 (2026-05-22): under Required policy, advise
                    // operators who run WITHOUT a hash pin that an
                    // attacker with worker-pod write access (sidecar
                    // exploit, init-container compromise) can swap the
                    // cosign binary for a wrapper that always exits 0 —
                    // bypassing every other Sigstore gate. Loud WARN at
                    // startup so the gap is visible in production logs;
                    // not fail-closed because Required-without-pin is a
                    // legitimate (if weaker) deployment posture and the
                    // pin requires per-image hash bookkeeping operators
                    // may roll out separately from this code change.
                    let cosign_pin = std::env::var("TALOS_COSIGN_SHA256")
                        .ok()
                        .filter(|v| !v.is_empty());
                    if cosign_pin.is_none() && sigstore_policy == SigstorePolicy::Required {
                        ::tracing::warn!(
                            policy = ?sigstore_policy,
                            "TALOS_COSIGN_SHA256 not set under Required Sigstore policy — \
                             cosign binary will not be hash-verified at startup. Set \
                             TALOS_COSIGN_SHA256 to the sha256 of the bundled cosign \
                             binary for defense-in-depth against binary-swap attacks."
                        );
                    }
                    if let Some(expected_sha256) = cosign_pin {
                        match resolve_and_hash_cosign_binary().await {
                            Ok(actual) => {
                                use subtle::ConstantTimeEq as _;
                                let actual_lower = actual.to_lowercase();
                                let expected_lower = expected_sha256.trim().to_lowercase();
                                let eq: bool = actual_lower
                                    .as_bytes()
                                    .ct_eq(expected_lower.as_bytes())
                                    .into();
                                if !eq {
                                    if sigstore_policy == SigstorePolicy::Required {
                                        return Err(anyhow::anyhow!(
                                            "cosign binary sha256 mismatch: expected {expected_lower}, \
                                             got {actual_lower}. Required policy refuses to boot."
                                        ));
                                    }
                                    ::tracing::warn!(
                                        expected = %expected_lower,
                                        actual = %actual_lower,
                                        "cosign binary sha256 mismatch (Audit mode: continuing)"
                                    );
                                } else {
                                    ::tracing::info!(
                                        sha256 = %actual_lower,
                                        "cosign binary sha256 pin verified"
                                    );
                                }
                            }
                            Err(e) => {
                                if sigstore_policy == SigstorePolicy::Required {
                                    return Err(anyhow::anyhow!(
                                        "Could not hash cosign binary for SHA-256 pin: {e}. \
                                         Required policy refuses to boot."
                                    ));
                                }
                                ::tracing::warn!(
                                    error = %e,
                                    "Could not hash cosign binary — sha256 pin check skipped (Audit mode)"
                                );
                            }
                        }
                    }

                    ::tracing::info!(
                        cosign_version = %version_line,
                        policy = ?sigstore_policy,
                        "Sigstore startup sanity check: cosign binary OK"
                    );
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                    if sigstore_policy == SigstorePolicy::Required {
                        return Err(anyhow::anyhow!(
                            "cosign binary present but `cosign version` exited non-zero (stderr: {stderr}). \
                             Required policy refuses to boot."
                        ));
                    }
                    ::tracing::warn!(
                        stderr = %stderr,
                        "Sigstore startup sanity check: cosign returned non-zero — verifications will fail"
                    );
                }
                Err(e) => {
                    if sigstore_policy == SigstorePolicy::Required {
                        return Err(anyhow::anyhow!(
                            "cosign binary not executable ({e}) and Sigstore policy is Required. \
                             Install cosign in the worker image or set TALOS_SIGSTORE_REQUIRED=audit \
                             during migration."
                        ));
                    }
                    ::tracing::warn!(
                        error = %e,
                        "Sigstore startup sanity check: cosign not executable — Audit mode will warn-and-continue on every pull"
                    );
                }
            }
        }
    }

    // M-1: validate Sigstore identity regexp at startup so an operator
    // who set `TALOS_SIGSTORE_REQUIRED=true` with a permissive pattern
    // discovers the policy is broken HERE — not silently per-pull when
    // every malicious-signature artifact passes verification. In
    // `Required` mode any rejection is fatal; in `Audit` mode we WARN
    // and continue (audit is the migration window). `Disabled` mode
    // skips this entirely.
    {
        let sigstore_policy_at_startup = SigstorePolicy::from_env();
        if sigstore_policy_at_startup != SigstorePolicy::Disabled {
            let regexp = std::env::var("TALOS_SIGSTORE_IDENTITY_REGEXP").unwrap_or_default();
            match validate_sigstore_identity_regexp(&regexp) {
                Ok(()) => {
                    ::tracing::info!(
                        policy = ?sigstore_policy_at_startup,
                        "Sigstore identity regexp validated at startup"
                    );
                }
                Err(rejection) => match sigstore_policy_at_startup {
                    SigstorePolicy::Required => {
                        return Err(anyhow::anyhow!(
                            "TALOS_SIGSTORE_IDENTITY_REGEXP rejected at startup ({:?}): {}. \
                             Fix the env var and restart — \
                             refusing to run under Required policy with broken config.",
                            rejection,
                            rejection.human_reason()
                        ));
                    }
                    SigstorePolicy::Audit => {
                        ::tracing::warn!(
                            rejection = ?rejection,
                            reason = %rejection.human_reason(),
                            "TALOS_SIGSTORE_IDENTITY_REGEXP rejected under Audit policy — \
                             would fail closed under Required"
                        );
                    }
                    SigstorePolicy::Disabled => unreachable!(),
                },
            }
        }
    }

    // Install the same key into talos-memory's RPC auth slot so the
    // WIT `agent_memory::*` and `graph_memory::*` host functions can
    // sign their NATS requests. The controller registers the same
    // key on its side for verification (see controller/src/main.rs).
    // Worker only SIGNS its outbound RPC (controller verifies), so the
    // current/signing key is all rpc_auth needs here.
    talos_memory::rpc_auth::register_hmac_key(Arc::new(
        shared_key.signing_key().as_bytes().to_vec(),
    ));

    // RFC 0010 P2 inc.3: when a per-worker Ed25519 key is provisioned
    // (TALOS_WORKER_SIGNING_KEY — the SAME key used to sign job results),
    // also register it as the RPC signing identity so memory/graph/database/
    // state/integration-state requests are signed Ed25519 under this worker's
    // id. The controller resolves the matching public key by worker_id and
    // verifies asymmetrically; the HMAC key above stays registered so the
    // controller's dual-verify accepts either scheme during rollout. Absent
    // the key, RPC signing stays on the legacy HMAC path unchanged.
    if let Some(rpc_signing_key) = worker_result_signing_key() {
        talos_memory::rpc_auth::register_ed25519_signing_key(
            worker_identity().to_string(),
            Arc::new(rpc_signing_key.clone()),
        );
        ::tracing::info!(
            target: "talos_security",
            worker_id = %worker_identity(),
            "Registered per-worker Ed25519 RPC signing identity (RFC 0010 P2 inc.3)"
        );

        // RFC 0010 P2 inc.4d: self-register this worker's public key with the
        // controller (if TALOS_CONTROLLER_URL + TALOS_WORKER_REGISTRATION_TOKEN
        // are set). Best-effort and detached so it never blocks boot or job
        // processing; the signing key is `&'static` (OnceLock), so it moves into
        // the task cleanly.
        tokio::spawn(worker::self_register::register_worker_identity_at_boot(
            rpc_signing_key,
        ));
    }

    // M-3 (2026-05-22): log the SQL empty-allowlist policy at startup
    // so operators can confirm the mode they're running. Default is
    // `DenyMutations` (least-privilege); `AllowAllNonDdl` is the
    // legacy permissive mode reachable via
    // `TALOS_SQL_PERMISSIVE_EMPTY_ALLOWLIST=1`. Logged at INFO so it
    // appears once at boot without spamming normal traffic.
    {
        let sql_policy = sql_validator::EmptyAllowlistPolicy::from_env();
        match sql_policy {
            sql_validator::EmptyAllowlistPolicy::DenyMutations => {
                ::tracing::info!(
                    policy = "DenyMutations",
                    "SQL validator: empty allowlist permits SELECT/EXPLAIN only (default)"
                );
            }
            sql_validator::EmptyAllowlistPolicy::AllowAllNonDdl => {
                ::tracing::warn!(
                    policy = "AllowAllNonDdl",
                    "SQL validator: legacy permissive mode is enabled via \
                     TALOS_SQL_PERMISSIVE_EMPTY_ALLOWLIST — JobRequests with empty \
                     allowed_sql_operations admit every non-DDL non-AlwaysBlocked \
                     statement type. Prefer setting allowed_sql_operations explicitly."
                );
            }
        }
    }

    // ========================================================================
    // OBSERVABILITY INITIALIZATION
    // ========================================================================

    println!("[1/5] Initializing observability...");

    if let Err(e) = metrics::init_telemetry() {
        eprintln!("Warning: Failed to initialize metrics: {}", e);
        eprintln!("    Continuing without metrics...");
    } else {
        println!("      Metrics initialized");
    }

    // Initialise OTel tracing FIRST — `init_tracing` installs the SDK provider
    // (+ the W3C propagator used by `extract_trace_context`). The otel bridge
    // layer in the subscriber below pulls a tracer from that provider, so the
    // provider must exist before the subscriber is built.
    let jaeger_endpoint = std::env::var("JAEGER_ENDPOINT")
        .ok()
        .or_else(|| Some("http://localhost:4317".to_string()));

    if let Some(endpoint) = jaeger_endpoint.as_ref() {
        match worker::tracing::init_tracing("talos-worker", Some(endpoint)) {
            Ok(_) => println!("      Tracing initialized (endpoint: {})", endpoint),
            Err(e) => {
                eprintln!("Warning: Failed to initialize tracing: {}", e);
                eprintln!("    Continuing without tracing...");
            }
        }
    }

    // Install the tracing subscriber. The fmt layer keeps host_impl.rs
    // `tracing::warn!`/`info!` (security checks, vault allowlist, SSRF blocks,
    // rate limits) in `docker logs` (RUST_LOG, default: worker=info,warn). The
    // optional OTel bridge layer — present only when `init_tracing` installed a
    // provider above (OTLP endpoint configured) — exports the worker's `tracing`
    // spans to OTLP so each `job-execution` span (and the host-function spans
    // nested under it) appears in the trace backend, linked to the controller's
    // `workflow` span via the propagated context.
    //
    // PERF: the worker is the hot WASM-execution path. Span volume is bounded by
    // the global EnvFilter (info/warn) AND the otel sampler: the SDK default is
    // ParentBased(AlwaysOn), so jobs that carry a sampled controller context
    // inherit its decision; root jobs (e.g. module-bound gmail/gcal dispatch with
    // no controller span) sample at AlwaysOn. High-throughput deployments should
    // configure a ratio sampler on the controller (the parent) to bound export.
    {
        use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("worker=info,warn"));
        let otel_layer = worker::tracing::sdk_tracer("talos-worker")
            .map(|tracer| tracing_opentelemetry::layer().with_tracer(tracer));
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().with_target(true).with_thread_ids(false))
            .with(otel_layer)
            .init();
    }

    // MCP-580: spawn the circuit-breaker periodic cleanup task so the
    // per-host `records` DashMap doesn't grow monotonically with
    // distinct hosts seen across the worker's lifetime. Idempotent at
    // the breaker level (only Closed stale entries get evicted; Open /
    // HalfOpen are preserved). Pre-fix the cleanup() method existed
    // but had zero callers.
    circuit_breaker::spawn_periodic_cleanup();

    // FU-2 (R2-5): periodically sweep the job-idempotency cache so expired
    // completed-result entries don't linger on a worker that goes idle.
    // Read-path eviction handles active job_ids; this is the companion sweep
    // (CLAUDE.md cache rule: TTL cache = read-path eviction + periodic sweep).
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(
            worker::job_idempotency::SWEEP_INTERVAL_SECS,
        ));
        tick.tick().await; // skip the immediate first tick
        loop {
            tick.tick().await;
            worker::job_idempotency::JOB_RESULT_CACHE.sweep();
            worker::job_idempotency::PIPELINE_PAYLOAD_CACHE.sweep();
        }
    });

    // ========================================================================
    // NATS CONNECTION
    // ========================================================================

    println!("\n[2/5] Connecting to NATS...");
    // MCP-631: empty-env hardening — `NATS_URL=""` (Helm placeholder)
    // would otherwise produce an empty URL and NATS connect fails with
    // a confusing parse error rather than using the default.
    let nats_url = std::env::var("NATS_URL")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "nats://127.0.0.1:4222".to_string());

    // Sanitize the URL for logging — strip embedded credentials (nats://user:pass@host).
    let nats_url_safe = {
        let mut u = nats_url.clone();
        if let Some(at) = u.find('@') {
            let scheme_end = u.find("://").map(|i| i + 3).unwrap_or(0);
            u.replace_range(scheme_end..at + 1, "[credentials]@");
        }
        u
    };

    // SECURITY: Use authenticated connection when NATS_USER + NATS_PASSWORD are set.
    // MCP-631: empty-env hardening — pre-fix, `NATS_USER=""` +
    // `NATS_PASSWORD=""` (Helm placeholder) produced
    // `(Some(""), Some(""))` which matched the authenticated branch
    // BELOW, BYPASSING the production-mode auth gate. The worker
    // would then attempt to authenticate with empty credentials; if
    // the NATS server happened to allow anonymous connections (no
    // auth file), the worker would silently connect anonymously
    // despite the operator's intent. Treating empty as unset routes
    // the request through the unauthenticated branch where the
    // production gate refuses it. Sibling to MCP-590/591/592 family.
    let nats_user = std::env::var("NATS_USER").ok().filter(|v| !v.is_empty());
    let nats_password = std::env::var("NATS_PASSWORD")
        .ok()
        .filter(|v| !v.is_empty());
    // MCP-668 (2026-05-13): route through `talos_config::is_production()` so
    // a helm-rendered empty `RUST_ENV=""` doesn't bypass this gate. Raw
    // `unwrap_or_default()` produced `""` which !== `"production"`, allowing
    // the worker to fall through to unauthenticated NATS even in prod.
    // Same empty-env-var family as MCP-590/591/592/630/631 and the
    // MCP-653 RUST_ENV long-tail closure.
    let is_production = talos_config::is_production();

    // SECURITY (2026-07-19, L5): in production, REFUSE to start on a plaintext
    // NATS URL — same fail-closed posture the controller enforces
    // (tls-prod-gate-nats). The worker sends HMAC-signed job RESULTS and
    // receives decrypted secrets over this bus; cleartext on the wire is a
    // transmission-security violation (HIPAA §164.312(e) / SOC2 CC6.7). Before
    // this gate the worker only required NATS *auth* in prod and relied on
    // NATS_CA_FILE being set to force TLS — an operator with a plaintext
    // `nats://` URL and no CA file transmitted credentials + payloads in the
    // clear where the controller would have refused to boot.
    // tls-prod-gate-nats
    if is_production && !nats_url.starts_with("tls://") && !nats_url.starts_with("nats+tls://") {
        return Err(anyhow::anyhow!(
            "NATS_URL must use TLS (tls:// or nats+tls://) in production — refusing to \
             start. Got scheme: '{}'.",
            nats_url.split("://").next().unwrap_or("<unknown>")
        ));
    }

    let nc: Client = match (nats_user, nats_password) {
        (Some(user), Some(pass)) => {
            // apply_nats_ca adds the in-cluster NATS CA + requires TLS when
            // NATS_CA_FILE is set (tls:// URL); no-op otherwise.
            let opts = async_nats::ConnectOptions::new().user_and_password(user, pass);
            match talos_nats_tls::apply_nats_ca(opts).connect(&nats_url).await {
                Ok(c) => {
                    println!(
                        "      Connected to NATS (authenticated) at {}",
                        nats_url_safe
                    );
                    c
                }
                Err(e) => {
                    eprintln!("Failed to connect to NATS at {}: {}", nats_url_safe, e);
                    eprintln!("   Check NATS_USER/NATS_PASSWORD credentials.");
                    return Err(anyhow::anyhow!(e));
                }
            }
        }
        _ => {
            // SECURITY: In production, require NATS authentication to prevent
            // unauthorized job submission and message interception.
            if is_production {
                eprintln!("CRITICAL SECURITY ERROR: NATS_USER and NATS_PASSWORD must be set in production.");
                eprintln!(
                    "   Unauthenticated NATS connections are not allowed in production mode."
                );
                return Err(anyhow::anyhow!(
                    "NATS authentication required in production (set NATS_USER and NATS_PASSWORD)"
                ));
            }
            ::tracing::warn!(
                "NATS_USER/NATS_PASSWORD not set — connecting without authentication. \
                 This is acceptable for development but MUST NOT be used in production."
            );
            let opts = talos_nats_tls::apply_nats_ca(async_nats::ConnectOptions::new());
            match opts.connect(&nats_url).await {
                Ok(c) => {
                    println!(
                        "      Connected to NATS (unauthenticated) at {}",
                        nats_url_safe
                    );
                    c
                }
                Err(e) => {
                    eprintln!("Failed to connect to NATS at {}: {}", nats_url_safe, e);
                    eprintln!("   Make sure a NATS server is running.");
                    return Err(anyhow::anyhow!(e));
                }
            }
        }
    };

    // Retrieve configurable NATS queue topics or use defaults.
    // This enables per-customer VPC "Edge Node" routing.
    // MCP-631: empty-env hardening — empty NATS topic would silently
    // subscribe to "" which behaves as an unsubscribed topic and the
    // worker would receive no jobs without a loud error.
    let single_job_topic = std::env::var("NATS_JOB_TOPIC")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "talos.jobs".to_string());
    let pipeline_job_topic = std::env::var("NATS_PIPELINE_TOPIC")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "talos.pipeline.jobs".to_string());
    // Use the topic names as the queue groups so multiple edge nodes on the same topic load-balance
    let queue_group = single_job_topic.clone();
    let pipeline_queue_group = pipeline_job_topic.clone();

    let mut sub: Subscriber = nc
        .queue_subscribe(single_job_topic.clone(), queue_group.clone())
        .await?;
    println!(
        "      Subscribed to '{}' queue (group: {})",
        single_job_topic, queue_group
    );

    let mut pipeline_sub: Subscriber = nc
        .queue_subscribe(pipeline_job_topic.clone(), pipeline_queue_group.clone())
        .await?;
    println!(
        "      Subscribed to '{}' queue (group: {})",
        pipeline_job_topic, pipeline_queue_group
    );

    // ========================================================================
    // RUNTIME INITIALIZATION (with NATS client for logging)
    // ========================================================================

    // ========================================================================
    // REDIS CONNECTION (Phase 1: Decoupled Read Path)
    // ========================================================================

    println!("\n[2.5/5] Connecting to Redis...");
    let redis_client = if let Ok(redis_url) = std::env::var("REDIS_URL") {
        // SECURITY: Require TLS (rediss://) in production to prevent credential
        // and data interception on the network.
        if is_production && !redis_url.starts_with("rediss://") {
            eprintln!("FATAL: REDIS_URL must use rediss:// (TLS) in production");
            std::process::exit(1);
        }
        match redis::Client::open(redis_url.as_str()) {
            Ok(client) => {
                // Test connection
                match client.get_multiplexed_async_connection().await {
                    Ok(_) => {
                        println!(
                            "      Connected to Redis at {}",
                            redis_url.split('@').next_back().unwrap_or("redis")
                        );
                        Some(Arc::new(client))
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to connect to Redis: {}. WASM cache interface will be unavailable.", e);
                        None
                    }
                }
            }
            Err(e) => {
                eprintln!("Warning: Failed to create Redis client: {}. WASM cache interface will be unavailable.", e);
                None
            }
        }
    } else {
        println!("      REDIS_URL not configured. WASM cache interface will be unavailable.");
        None
    };

    // Fleet-wide job idempotency tier (2026-07-01): jobs arrive via a NATS
    // queue group, so a controller transport-retry can land on a DIFFERENT
    // worker whose in-process result cache is cold — re-executing side
    // effects. Backing the cache with the same Redis makes dedup fleet-wide;
    // absent/unreachable Redis degrades to same-worker-only (the old
    // behavior), never an error.
    if let Some(ref client) = redis_client {
        worker::job_idempotency::init_redis(client.as_ref().clone()).await;
    }

    // PostgreSQL connection block removed Phase 2.10. Worker is now
    // credential-free: the WIT `database::execute_query` host
    // function dispatches via signed NATS-RPC to the controller
    // (Phase 2.3). DATABASE_URL is intentionally not read here.

    println!("\n[3/5] Creating WASM runtime...");
    let runtime = Arc::new(TalosRuntime::with_resources(
        redis_client.clone(),       // Redis client for WASM fetching and caching
        Some(Arc::new(nc.clone())), // NATS client for WASM log publishing
        None,                       // No file system sandbox for now
    )?);
    println!("      Runtime created with NATS logging enabled (worker is credential-free; database access via NATS-RPC)");

    // M1 (2026-05-22): start the epoch-interruption ticker. Wasmtime
    // checks the engine's epoch counter at every loop backedge and
    // function entry; without a ticker the counter never advances and
    // the per-Store `set_epoch_deadline(N)` calls below would either
    // (a) never trip (deadline always in the future) or (b) trip at
    // the first yield (deadline == current epoch == 0). The ticker
    // gives the worker a third independent kill switch alongside fuel
    // + tokio wall-clock timeout. Cheap (one atomic increment per
    // EPOCH_TICK_INTERVAL_MS) and the JoinHandle is dropped so the
    // task runs for the lifetime of the process.
    let _epoch_ticker_handle = worker::runtime::spawn_epoch_ticker(runtime.engine_handle());
    println!("      Epoch-interruption ticker started (third kill switch alongside fuel + wall-clock timeout)");

    // ========================================================================
    // METRICS SERVER
    // ========================================================================

    println!("\n[4/5] Starting metrics server...");
    let metrics_port = std::env::var("METRICS_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(9090);

    let _metrics_handle = metrics_server::start_metrics_server(runtime.clone(), metrics_port)
        .expect("Failed to start metrics server — ensure METRICS_AUTH_TOKENS is set");

    println!("      Metrics server running on port {}", metrics_port);
    println!(
        "         - Metrics: http://localhost:{}/metrics",
        metrics_port
    );
    println!(
        "         - Health:  http://localhost:{}/health",
        metrics_port
    );

    // ========================================================================
    // JOB PROCESSING LOOP
    // ========================================================================

    println!("\n[5/5] Starting job processing...");
    println!("\n=== Worker Ready ===");
    println!(
        "Listening for jobs on {} (queue: {})",
        nats_url, single_job_topic
    );

    // Resolve concurrency caps ONCE and bind to locals — the shutdown
    // drain loop below compares `available_permits()` against these same
    // values, so they must not be re-read from env (an operator changing
    // the env mid-process can't happen, but re-reading would also re-emit
    // the WARN and risk drift).
    let max_concurrent_jobs = max_concurrent_jobs();
    let max_concurrent_pipeline_jobs = max_concurrent_pipeline_jobs();

    // Capacity sanity gate: the single-job semaphore must never hand out
    // more permits than the pooling allocator can instantiate. If
    // `max_concurrent_jobs > TOTAL_COMPONENT_INSTANCES`, a job could
    // acquire a permit, then fail to get a pooling slot at instantiation
    // — turning clean semaphore back-pressure into instantiation errors
    // under saturation. Pipeline jobs each fan out into sub-instances, so
    // the single-job cap is the tightest of the two to check. WARN rather
    // than panic so an operator who deliberately raised the allocator's
    // total isn't blocked, but the misconfiguration is loud.
    let total_component_instances = worker::runtime::TOTAL_COMPONENT_INSTANCES as usize;
    if max_concurrent_jobs > total_component_instances {
        ::tracing::warn!(
            max_concurrent_jobs,
            total_component_instances,
            "TALOS_MAX_CONCURRENT_JOBS exceeds the pooling allocator's total_component_instances — jobs may acquire a concurrency permit but fail to instantiate under saturation; lower the concurrency cap or raise total_component_instances in runtime.rs"
        );
    } else {
        ::tracing::info!(
            max_concurrent_jobs,
            max_concurrent_pipeline_jobs,
            total_component_instances,
            "Job concurrency caps within pooling-allocator capacity"
        );
    }

    let semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrent_jobs));
    let pipeline_semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrent_pipeline_jobs));

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // ── Single-node jobs task ─────────────────────────────────────────────
    let single_nc = nc.clone();
    let single_runtime = runtime.clone();
    let single_key = shared_key.clone();
    let single_sem = semaphore.clone();
    let mut single_shutdown = shutdown_rx.clone();

    let single_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = single_shutdown.changed() => break,
                permit_res = single_sem.clone().acquire_owned() => {
                    let permit = match permit_res {
                        Ok(p) => p,
                        Err(_) => break,
                    };

                    tokio::select! {
                        _ = single_shutdown.changed() => break,
                        msg_opt = sub.next() => {
                            let msg = match msg_opt {
                                Some(m) => m,
                                None => break,
                            };

                            let cx = if let Some(ref headers) = msg.headers {
                                worker::trace_nats::extract_trace_context(headers)
                            } else {
                                opentelemetry::Context::new()
                            };

                            // SECURITY: cap payload size before deserialization to prevent
                            // memory exhaustion from oversized NATS messages.
                            const MAX_JOB_PAYLOAD_BYTES: usize = 32 * 1024 * 1024; // 32 MB
                            if msg.payload.len() > MAX_JOB_PAYLOAD_BYTES {
                                ::tracing::error!(
                                    payload_bytes = msg.payload.len(),
                                    "SECURITY: rejecting oversized job payload"
                                );
                                continue;
                            }
                            let req: JobRequest = match serde_json::from_slice(&msg.payload) {
                                Ok(r) => r,
                                Err(e) => {
                                    ::tracing::error!(error = %e, "Failed to decode job request");
                                    continue;
                                }
                            };

                            ::tracing::info!(job_id = %req.job_id, module_uri = %req.module_uri, "Received job");

                            let nc_clone = single_nc.clone();
                            let runtime_clone = single_runtime.clone();
                            let key_clone = single_key.clone();
                            let wire_reply = msg.reply.map(|r: async_nats::Subject| r.to_string());
                            // H-1: prefer the HMAC-bound `req.reply_topic`
                            // over the unsigned wire `msg.reply`. See
                            // `pick_trusted_reply_topic` for the matrix.
                            let reply_to = pick_trusted_reply_topic(
                                req.job_id,
                                req.reply_topic.as_deref(),
                                wire_reply.as_deref(),
                            );

                            tokio::task::spawn(async move {
                                // FU-2 (R2-5) idempotency: a controller transport-retry re-sends
                                // the same job_id (with a fresh nonce) AFTER the original
                                // executed. Re-publish the cached signed result instead of
                                // re-running the module (which would repeat side effects). The
                                // cached result is still within the 300s JobResult freshness
                                // window, so it's re-published as-is. dry_run jobs are never
                                // cached (no side effects, cheap to re-run).
                                //
                                // SECURITY (self-review fix): the cache must ONLY be consulted
                                // for an AUTHENTICATED request. `execute_job` verifies the
                                // request HMAC, but it runs AFTER this cache check — so without
                                // gating here, an on-NATS attacker could send an unsigned
                                // JobRequest with a known (non-secret) job_id and exfiltrate the
                                // cached signed result to an attacker-chosen reply inbox,
                                // bypassing the "no result leaves the worker without a valid
                                // HMAC" invariant. We pre-verify with the NO-REPLAY variant
                                // (HMAC + freshness, but NOT the nonce cache) so the cache-miss
                                // path's `execute_job` → `verify_with_ring` still records the
                                // nonce exactly once. A forged request fails this pre-check and
                                // falls through to `execute_job`, which returns the signed
                                // verification-failure diagnostic without running the module.
                                let request_authentic =
                                    req.verify_no_replay_with_ring(&key_clone, 300).is_ok();
                                if request_authentic && !req.dry_run {
                                    // Tier 1: in-process (same-worker retry, free).
                                    // Tier 2: Redis (queue-group retry landed on a
                                    // DIFFERENT worker). Redis-sourced bytes are NOT
                                    // trusted blindly — the result's own HMAC is
                                    // re-verified and its job_id matched before
                                    // re-publish, so a Redis compromise can neither
                                    // inject forged results nor cross-wire jobs;
                                    // verification failure falls through to normal
                                    // re-execution.
                                    let cached = match worker::job_idempotency::JOB_RESULT_CACHE
                                        .get(req.job_id)
                                    {
                                        Some(c) => Some(c),
                                        None => worker::job_idempotency::shared_get(
                                            worker::job_idempotency::REDIS_JOB_PREFIX,
                                            req.job_id,
                                        )
                                        .await
                                        .and_then(|bytes| {
                                            match serde_json::from_slice::<JobResult>(&bytes) {
                                                Ok(r)
                                                    if r.job_id == req.job_id
                                                        && r.verify_no_replay_with_ring(
                                                            &key_clone, 300,
                                                        )
                                                        .is_ok() =>
                                                {
                                                    Some(r)
                                                }
                                                _ => {
                                                    ::tracing::warn!(
                                                        job_id = %req.job_id,
                                                        "idempotency: shared Redis entry failed \
                                                         verification — ignoring, re-executing"
                                                    );
                                                    None
                                                }
                                            }
                                        }),
                                    };
                                    if let Some(cached) = cached {
                                        ::tracing::info!(
                                            job_id = %req.job_id,
                                            "idempotency: re-publishing cached result for re-seen \
                                             job_id (transport retry); skipping re-execution"
                                        );
                                        if let Err(e) = publish_result_with_retry(
                                            &nc_clone, &cached, 3, reply_to, &key_clone,
                                        )
                                        .await
                                        {
                                            ::tracing::error!(job_id = %req.job_id, error = %e, "CRITICAL: Failed to publish cached job result");
                                        }
                                        drop(permit);
                                        return;
                                    }
                                }

                                let mut result = execute_job(&cx, req.clone(), runtime_clone, key_clone.clone(), &nc_clone).await;

                                // L-11: bind worker identity for audit attribution.
                                // RFC 0010 P2: Ed25519 when configured, else HMAC.
                                if let Err(e) = sign_job_result(&mut result, &key_clone) {
                                    ::tracing::error!(job_id = %result.job_id, error = %e, "CRITICAL: Failed to sign job result");
                                }

                                // FU-2: cache the SIGNED terminal result BEFORE publishing, so a
                                // retry that arrives because the *reply* (not the execution)
                                // failed still finds it. Keyed on job_id; bounded by TTL + size +
                                // count (see `job_idempotency`). Written to BOTH tiers: the
                                // in-process map (same-worker retry) and Redis (retry landing on
                                // a sibling queue-group worker).
                                if !req.dry_run {
                                    match serde_json::to_vec(&result) {
                                        Ok(bytes) => {
                                            worker::job_idempotency::JOB_RESULT_CACHE.put(
                                                result.job_id,
                                                result.clone(),
                                                bytes.len(),
                                            );
                                            worker::job_idempotency::shared_put(
                                                worker::job_idempotency::REDIS_JOB_PREFIX,
                                                result.job_id,
                                                &bytes,
                                            )
                                            .await;
                                        }
                                        Err(e) => ::tracing::warn!(
                                            job_id = %result.job_id, error = %e,
                                            "idempotency: could not serialize result for cache sizing; not caching"
                                        ),
                                    }
                                }

                                match result.status {
                                    JobStatus::Success => {
                                        ::tracing::info!(job_id = %result.job_id, duration_ms = result.execution_time_ms, "Job completed");
                                    }
                                    JobStatus::Failed => {
                                        ::tracing::warn!(job_id = %result.job_id, duration_ms = result.execution_time_ms, "Job failed");
                                    }
                                    _ => {}
                                }

                                if let Err(e) = publish_result_with_retry(
                                    &nc_clone,
                                    &result,
                                    3,
                                    reply_to,
                                    &key_clone,
                                )
                                .await
                                {
                                    ::tracing::error!(job_id = %result.job_id, error = %e, "CRITICAL: Failed to publish job result");
                                }

                                drop(permit);
                            });
                        }
                    }
                }
            }
        }
    });

    // ── Pipeline jobs task ────────────────────────────────────────────────
    let pipe_nc = nc.clone();
    let pipe_runtime = runtime.clone();
    let pipe_key = shared_key.clone();
    let pipe_sem = pipeline_semaphore.clone();
    let mut pipe_shutdown = shutdown_rx.clone();

    let pipe_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = pipe_shutdown.changed() => break,
                permit_res = pipe_sem.clone().acquire_owned() => {
                    let permit = match permit_res {
                        Ok(p) => p,
                        Err(_) => break,
                    };

                    tokio::select! {
                        _ = pipe_shutdown.changed() => break,
                        msg_opt = pipeline_sub.next() => {
                            let msg = match msg_opt {
                                Some(m) => m,
                                None => break,
                            };

                            let cx = if let Some(ref headers) = msg.headers {
                                worker::trace_nats::extract_trace_context(headers)
                            } else {
                                opentelemetry::Context::new()
                            };

                            // SECURITY: cap payload size before deserialization.
                            const MAX_PIPELINE_PAYLOAD_BYTES: usize = 32 * 1024 * 1024; // 32 MB
                            if msg.payload.len() > MAX_PIPELINE_PAYLOAD_BYTES {
                                ::tracing::error!(
                                    payload_bytes = msg.payload.len(),
                                    "SECURITY: rejecting oversized pipeline job payload"
                                );
                                continue;
                            }
                            let req: PipelineJobRequest = match serde_json::from_slice(&msg.payload) {
                                Ok(r) => r,
                                Err(e) => {
                                    ::tracing::error!(error = %e, "Failed to decode pipeline job request");
                                    continue;
                                }
                            };

                            ::tracing::info!(job_id = %req.job_id, steps = req.steps.len(), "Received pipeline job");

                            let nc_clone = pipe_nc.clone();
                            let runtime_clone = pipe_runtime.clone();
                            let key_clone = pipe_key.clone();
                            let wire_reply = msg.reply.clone().map(|r: async_nats::Subject| r.to_string());
                            // H-1: see `pick_trusted_reply_topic` —
                            // pipeline path uses the same wire/signed
                            // reconciliation as single-node jobs.
                            let reply_to = pick_trusted_reply_topic(
                                req.job_id,
                                req.reply_topic.as_deref(),
                                wire_reply.as_deref(),
                            );

                            tokio::task::spawn(async move {
                                // FU-2 (R2-5) pipeline idempotency: a controller transport-retry
                                // re-sends the same job_id (fresh nonce) AFTER the original ran.
                                // Re-publish the cached signed payload bytes instead of re-running
                                // the pipeline (which would repeat every step's side effects). The
                                // bytes are still within the 300s JobResult freshness window, so
                                // they're re-published as-is. (PipelineJobRequest has no dry_run.)
                                //
                                // SECURITY (self-review fix): only an AUTHENTICATED request may
                                // consult the cache — otherwise an on-NATS attacker could
                                // exfiltrate a cached signed pipeline result to an attacker-chosen
                                // inbox with an unsigned request carrying a known job_id. Pre-verify
                                // with the NO-REPLAY variant (so the miss-path's full verify still
                                // records the nonce once); a forged request falls through to
                                // execute_pipeline_job, which returns a signed verification failure.
                                let request_authentic =
                                    req.verify_no_replay_with_ring(&key_clone, 300).is_ok();
                                if request_authentic {
                                    // Tier 1: in-process; tier 2: Redis (retry on a
                                    // sibling queue-group worker). Redis bytes are
                                    // deserialized + HMAC-verified + job_id-matched
                                    // before the ORIGINAL bytes are re-published —
                                    // same trust model as the single-job path.
                                    let cached = match worker::job_idempotency::PIPELINE_PAYLOAD_CACHE
                                        .get(req.job_id)
                                    {
                                        Some(c) => Some(c),
                                        None => worker::job_idempotency::shared_get(
                                            worker::job_idempotency::REDIS_PIPELINE_PREFIX,
                                            req.job_id,
                                        )
                                        .await
                                        .and_then(|bytes| {
                                            match serde_json::from_slice::<PipelineJobResult>(&bytes) {
                                                Ok(r)
                                                    if r.job_id == req.job_id
                                                        && r.verify_no_replay_with_ring(
                                                            &key_clone, 300,
                                                        )
                                                        .is_ok() =>
                                                {
                                                    Some(bytes::Bytes::from(bytes))
                                                }
                                                _ => {
                                                    ::tracing::warn!(
                                                        job_id = %req.job_id,
                                                        "idempotency: shared Redis pipeline entry \
                                                         failed verification — ignoring, re-executing"
                                                    );
                                                    None
                                                }
                                            }
                                        }),
                                    };
                                    if let Some(cached) = cached
                                    {
                                    ::tracing::info!(
                                        job_id = %req.job_id,
                                        "idempotency: re-publishing cached pipeline result for \
                                         re-seen job_id (transport retry); skipping re-execution"
                                    );
                                    let publish_result = if let Some(reply) = reply_to {
                                        publish_bytes_with_retry(&nc_clone, reply, cached, 3).await
                                    } else {
                                        let result_topic =
                                            format!("talos.pipeline.results.{}", req.job_id);
                                        publish_bytes_with_retry(&nc_clone, result_topic, cached, 3).await
                                    };
                                    if let Err(e) = publish_result {
                                        ::tracing::error!(job_id = %req.job_id, error = %e, "CRITICAL: Failed to publish cached pipeline result");
                                    }
                                    drop(permit);
                                    return;
                                    }
                                }

                                let mut result =
                                    execute_pipeline_job(&cx, req.clone(), runtime_clone, key_clone.clone(), &nc_clone).await;

                                // L-11: bind worker identity for audit attribution.
                                // RFC 0010 P2: Ed25519 when configured, else HMAC.
                                if let Err(e) = sign_pipeline_result(&mut result, &key_clone) {
                                    ::tracing::error!(job_id = %result.job_id, error = %e, "CRITICAL: Failed to sign pipeline result");
                                }

                                match result.overall_status {
                                    JobStatus::Success => {
                                        ::tracing::info!(
                                            job_id = %result.job_id,
                                            duration_ms = result.total_time_ms,
                                            steps = result.step_results.len(),
                                            "Pipeline completed"
                                        );
                                    }
                                    JobStatus::Failed => {
                                        ::tracing::warn!(
                                            job_id = %result.job_id,
                                            duration_ms = result.total_time_ms,
                                            "Pipeline failed"
                                        );
                                    }
                                    _ => {}
                                }

                                // M-7: size-gate pipeline results too. Same
                                // motivation as single-node: oversized payloads
                                // silently fail at the NATS broker; degrade to a
                                // small Failed result so the controller gets a
                                // signed reply.
                                let serialized = serde_json::to_vec(&result).unwrap_or_default();
                                let cap = max_job_result_bytes();
                                let payload = if serialized.len() > cap {
                                    ::tracing::error!(
                                        job_id = %result.job_id,
                                        serialized_bytes = serialized.len(),
                                        cap_bytes = cap,
                                        "PipelineJobResult exceeds NATS publish cap — substituting Failed status"
                                    );
                                    let mut replacement = PipelineJobResult {
                                        llm_usage: vec![],
                                        crypto_scheme: 0,
                                        job_id: result.job_id,
                                        overall_status: JobStatus::Failed,
                                        step_results: vec![],
                                        final_output: serde_json::json!({
                                            "error": "pipeline_result_too_large",
                                            "diag": {
                                                "serialized_bytes": serialized.len(),
                                                "cap_bytes": cap,
                                                "note": "Worker dropped the original step_results/final_output to keep \
                                                         under WORKER_MAX_JOB_RESULT_BYTES. Reduce per-step output size or \
                                                         raise the cap if this is legitimate."
                                            }
                                        }),
                                        total_time_ms: result.total_time_ms,
                                        signature: vec![],
                                        result_nonce: String::new(),
                                        worker_id: String::new(),
                                    };
                                    // L-11: bind worker identity for audit attribution.
                                    // RFC 0010 P2: Ed25519 when configured, else HMAC.
                                    if let Err(e) = sign_pipeline_result(&mut replacement, &key_clone) {
                                        ::tracing::error!(
                                            job_id = %result.job_id,
                                            error = %e,
                                            "Failed to sign oversized pipeline replacement"
                                        );
                                    }
                                    bytes::Bytes::from(
                                        serde_json::to_vec(&replacement).unwrap_or_default(),
                                    )
                                } else {
                                    bytes::Bytes::from(serialized)
                                };

                                // FU-2: cache the final signed payload bytes BEFORE publishing, so
                                // a retry that arrives because the *reply* (not the execution)
                                // failed re-publishes the identical bytes instead of re-running the
                                // pipeline. `Bytes::clone` is a cheap refcount bump. Written to
                                // BOTH tiers (in-process + Redis) — see the single-job put site.
                                worker::job_idempotency::PIPELINE_PAYLOAD_CACHE.put(
                                    result.job_id,
                                    payload.clone(),
                                    payload.len(),
                                );
                                worker::job_idempotency::shared_put(
                                    worker::job_idempotency::REDIS_PIPELINE_PREFIX,
                                    result.job_id,
                                    &payload,
                                )
                                .await;

                                // Single-publish architecture (mirrors single-job
                                // results, see publish_result_with_retry above for
                                // the full rationale + r301 context). Pipeline
                                // results have only one consumer today (the engine
                                // dispatcher via request-reply), so the
                                // pre-existing fire-and-forget path was already
                                // unused in practice. Adding a second consumer in
                                // the future + verify() at both → would re-enter
                                // the JOB_NONCE_CACHE race we just unlanded.
                                let publish_result = if let Some(reply) = reply_to {
                                    publish_bytes_with_retry(&nc_clone, reply, payload, 3).await
                                } else {
                                    let result_topic = format!("talos.pipeline.results.{}", result.job_id);
                                    publish_bytes_with_retry(&nc_clone, result_topic, payload, 3).await
                                };
                                if let Err(e) = publish_result {
                                    ::tracing::error!(job_id = %result.job_id, error = %e, "CRITICAL: Failed to publish pipeline result");
                                }

                                drop(permit);
                            });
                        }
                    }
                }
            }
        }
    });

    tokio::select! {
        // MCP-667 (2026-05-13): listen for BOTH SIGTERM and SIGINT via
        // the shared `talos_shutdown::wait_for_shutdown` helper. Pre-fix
        // the worker only handled SIGINT (Ctrl+C); under K8s pod
        // termination the kubelet sends SIGTERM, which was unobserved —
        // in-flight WASM executions, NATS publishes, and result-
        // collector flushes were aborted at SIGKILL after the grace
        // period elapsed instead of draining cleanly. Sibling fix to
        // the controller-side change at `with_graceful_shutdown` —
        // both binaries now route through the same shutdown surface
        // that carries the MCP-501 install-failure handling.
        _ = talos_shutdown::wait_for_shutdown() => {
            ::tracing::info!("Shutdown signal received, draining in-flight jobs...");
            let _ = shutdown_tx.send(true);
        }
        _ = single_handle => {},
        _ = pipe_handle => {},
    }

    // ========================================================================
    // GRACEFUL SHUTDOWN
    // ========================================================================

    println!("\n=== Shutting Down ===");

    println!("[1/3] Waiting for in-flight jobs to complete...");
    let shutdown_timeout = tokio::time::Duration::from_secs(30);
    let drain_start = std::time::Instant::now();

    while (semaphore.available_permits() < max_concurrent_jobs
        || pipeline_semaphore.available_permits() < max_concurrent_pipeline_jobs
        || runtime.active_executions() > 0)
        && drain_start.elapsed() < shutdown_timeout
    {
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    if runtime.active_executions() > 0 {
        ::tracing::warn!(
            remaining = runtime.active_executions(),
            "Forcing shutdown with jobs still running"
        );
    } else {
        ::tracing::info!("All in-flight jobs drained successfully");
    }
    println!("      All jobs completed");

    println!("[2/3] Flushing traces...");
    worker::tracing::shutdown_tracing();
    println!("      Traces flushed");

    println!("[3/3] Closing connections...");
    drop(nc);
    println!("      Connections closed");

    println!("\nWorker shutdown complete");
    Ok(())
}
#[cfg(test)]
mod result_publish_tests {
    use super::*;

    // Serial guard for env-mutating tests in this module. Without it,
    // cargo's parallel test runner can race on the global env.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // ─── M-7: JobResult publish-size cap ──────────────────────────────────

    #[test]
    fn truncate_oversized_replaces_payload_and_marks_failed() {
        let original = JobResult {
            llm_usage: vec![],
            crypto_scheme: 0,
            job_id: uuid::Uuid::new_v4(),
            status: JobStatus::Success,
            output_payload: serde_json::json!({"huge": "x".repeat(10_000)}),
            logs: vec!["a".to_string(); 1000],
            execution_time_ms: 42,
            signature: vec![0; 32],
            result_nonce: "1700000000:abc".to_string(),
            worker_id: String::new(),
        };
        let replacement = truncate_oversized_job_result(&original, 10_000_000, 4_000_000);
        // Identity bound: same job_id so the controller can correlate.
        assert_eq!(replacement.job_id, original.job_id);
        // Status downgraded to Failed — the original Success is no
        // longer accurate because the result didn't reach the
        // controller.
        assert_eq!(replacement.status, JobStatus::Failed);
        // Payload replaced with a small diagnostic blob.
        assert!(replacement.output_payload.get("error").is_some());
        assert!(replacement.output_payload.get("diag").is_some());
        // Logs and execution time preserved for correlation.
        assert!(!replacement.logs.is_empty());
        assert_eq!(replacement.execution_time_ms, 42);
        // Signature MUST be cleared so the caller can't accidentally
        // publish an unsigned replacement (the caller is expected to
        // re-sign before publishing).
        assert!(replacement.signature.is_empty());
        assert!(replacement.result_nonce.is_empty());
    }

    #[test]
    fn truncate_oversized_replacement_serializes_under_cap() {
        // The replacement itself must fit comfortably under any
        // reasonable cap, otherwise we'd loop forever.
        let original = JobResult {
            llm_usage: vec![],
            crypto_scheme: 0,
            job_id: uuid::Uuid::new_v4(),
            status: JobStatus::Success,
            output_payload: serde_json::json!({"huge": "x".repeat(10_000_000)}),
            logs: vec![],
            execution_time_ms: 0,
            signature: vec![],
            result_nonce: String::new(),
            worker_id: String::new(),
        };
        let replacement = truncate_oversized_job_result(&original, 10_000_000, 4_000_000);
        let bytes = serde_json::to_vec(&replacement).unwrap();
        // Replacement is small — well under any realistic cap.
        assert!(
            bytes.len() < 4096,
            "replacement should serialize to a small payload; got {} bytes",
            bytes.len()
        );
    }

    #[test]
    fn max_job_result_bytes_uses_default_when_unset() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("WORKER_MAX_JOB_RESULT_BYTES");
        assert_eq!(max_job_result_bytes(), DEFAULT_MAX_JOB_RESULT_BYTES);
    }

    #[test]
    fn max_job_result_bytes_respects_override() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("WORKER_MAX_JOB_RESULT_BYTES", "8388608"); // 8 MiB
        assert_eq!(max_job_result_bytes(), 8_388_608);
        std::env::remove_var("WORKER_MAX_JOB_RESULT_BYTES");
    }

    // ─── B2: env-tunable concurrency caps ─────────────────────────────────

    #[test]
    fn concurrency_caps_use_defaults_when_unset() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("TALOS_MAX_CONCURRENT_JOBS");
        std::env::remove_var("TALOS_MAX_CONCURRENT_PIPELINE_JOBS");
        assert_eq!(max_concurrent_jobs(), DEFAULT_MAX_CONCURRENT_JOBS);
        assert_eq!(
            max_concurrent_pipeline_jobs(),
            DEFAULT_MAX_CONCURRENT_PIPELINE_JOBS
        );
    }

    #[test]
    fn concurrency_caps_respect_positive_override() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("TALOS_MAX_CONCURRENT_JOBS", "42");
        std::env::set_var("TALOS_MAX_CONCURRENT_PIPELINE_JOBS", "7");
        assert_eq!(max_concurrent_jobs(), 42);
        assert_eq!(max_concurrent_pipeline_jobs(), 7);
        std::env::remove_var("TALOS_MAX_CONCURRENT_JOBS");
        std::env::remove_var("TALOS_MAX_CONCURRENT_PIPELINE_JOBS");
    }

    #[test]
    fn concurrency_cap_zero_falls_back_to_default() {
        // =0/negative footgun guard: a 0 Semaphore permits nothing and
        // would silently stall the worker. `nonzero_env_or_default`
        // substitutes the default (>= 1) with a WARN.
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("TALOS_MAX_CONCURRENT_JOBS", "0");
        assert_eq!(max_concurrent_jobs(), DEFAULT_MAX_CONCURRENT_JOBS);
        std::env::remove_var("TALOS_MAX_CONCURRENT_JOBS");
    }

    #[test]
    fn concurrency_cap_negative_falls_back_to_default() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("TALOS_MAX_CONCURRENT_PIPELINE_JOBS", "-5");
        assert_eq!(
            max_concurrent_pipeline_jobs(),
            DEFAULT_MAX_CONCURRENT_PIPELINE_JOBS
        );
        std::env::remove_var("TALOS_MAX_CONCURRENT_PIPELINE_JOBS");
    }

    #[test]
    fn concurrency_cap_non_numeric_falls_back_to_default() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("TALOS_MAX_CONCURRENT_JOBS", "lots");
        assert_eq!(max_concurrent_jobs(), DEFAULT_MAX_CONCURRENT_JOBS);
        std::env::remove_var("TALOS_MAX_CONCURRENT_JOBS");
    }

    #[test]
    fn default_concurrency_within_pooling_capacity() {
        // The startup capacity gate in `main()` WARNs when
        // max_concurrent_jobs > TOTAL_COMPONENT_INSTANCES. Pin the
        // shipped defaults so a future bump that would silently exceed
        // the pooling allocator's instance ceiling trips here first.
        let total = worker::runtime::TOTAL_COMPONENT_INSTANCES as usize;
        assert!(
            DEFAULT_MAX_CONCURRENT_JOBS <= total,
            "default single-job concurrency {DEFAULT_MAX_CONCURRENT_JOBS} exceeds pooling total_component_instances {total}"
        );
        assert!(
            DEFAULT_MAX_CONCURRENT_PIPELINE_JOBS <= total,
            "default pipeline concurrency {DEFAULT_MAX_CONCURRENT_PIPELINE_JOBS} exceeds pooling total_component_instances {total}"
        );
    }

    // ─── H-1: pick_trusted_reply_topic decision matrix ────────────────────
    //
    // The whole point of H-1 is that a NATS-channel attacker who
    // substitutes `msg.reply` cannot redirect the worker's signed
    // JobResult to an attacker-controlled subject. These tests pin
    // the policy at the function boundary so a future "simplification"
    // can't silently re-introduce the regression.

    #[test]
    fn pick_reply_signed_and_wire_match() {
        let jid = uuid::Uuid::new_v4();
        let r = pick_trusted_reply_topic(jid, Some("_INBOX.abc"), Some("_INBOX.abc"));
        assert_eq!(r.as_deref(), Some("_INBOX.abc"));
    }

    #[test]
    fn pick_reply_signed_and_wire_mismatch_returns_signed() {
        // SECURITY: an attacker substituted `msg.reply` — the worker
        // MUST publish to the signed value, not the wire value.
        let jid = uuid::Uuid::new_v4();
        let r = pick_trusted_reply_topic(jid, Some("_INBOX.legit"), Some("talos.admin.commands"));
        assert_eq!(
            r.as_deref(),
            Some("_INBOX.legit"),
            "wire taking priority would be the security regression"
        );
    }

    #[test]
    fn pick_reply_signed_only() {
        // msg.reply stripped in transit; signed value is authoritative.
        let jid = uuid::Uuid::new_v4();
        let r = pick_trusted_reply_topic(jid, Some("_INBOX.signed"), None);
        assert_eq!(r.as_deref(), Some("_INBOX.signed"));
    }

    #[test]
    fn pick_reply_wire_only_backward_compat() {
        // Legacy controller / non-NATS transport that doesn't
        // pre-allocate inboxes. The worker accepts msg.reply
        // verbatim — this is the path the H-1 binding closes for
        // upgraded controllers but keeps available for old ones.
        let jid = uuid::Uuid::new_v4();
        let r = pick_trusted_reply_topic(jid, None, Some("_INBOX.legacy"));
        assert_eq!(r.as_deref(), Some("_INBOX.legacy"));
    }

    #[test]
    fn pick_reply_neither_present() {
        let jid = uuid::Uuid::new_v4();
        let r = pick_trusted_reply_topic(jid, None, None);
        assert_eq!(r, None);
    }

    #[test]
    fn pick_reply_mismatch_does_not_publish_to_attacker_subject() {
        // Specific regression guard: an attacker substituting a
        // sensitive admin subject MUST NOT result in the worker
        // publishing there. This is the whole point of H-1.
        let jid = uuid::Uuid::new_v4();
        let bad_subjects = [
            "talos.admin.commands",
            "talos.jobs",          // would create a NATS loop
            "talos.pipeline.jobs", // same
            "$SYS.REQ.ACCOUNT",    // NATS system subject
            "_INBOX.attacker.xyz", // inbox-prefix but not the signed one
        ];
        for bad in bad_subjects {
            let r = pick_trusted_reply_topic(jid, Some("_INBOX.legit"), Some(bad));
            assert_eq!(
                r.as_deref(),
                Some("_INBOX.legit"),
                "H-1 regression: wire subject {bad:?} leaked through"
            );
        }
    }
}
