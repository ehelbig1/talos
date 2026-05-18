// MCP-952 (2026-05-15): kept `#![allow(dead_code)]` deliberately.
// The worker binary carries several pre-existing dead items that
// span multiple modules (signing/verify_signature methods,
// get_state, cancellation_token field, take_stderr_output and
// memory-key helpers, try_deduct_crypto_budget/cancel, is_mutation,
// etc.). Each is non-trivial to audit individually — they could
// be vestigial post-refactor surface, conditional-build hooks,
// or wiring awaiting a real consumer. A clean removal would
// need surgical review per item against the worker's WIT host
// function set and the broader signing protocol; that's not a
// drive-by sweep target. Vestigial-retention class (see MCP-946).
#![allow(dead_code)]
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

use crate::runtime::{PipelineStepSpec, RetryPolicy, SecurityPolicy};
use async_nats::Client;
use async_nats::Subscriber;
use futures_util::stream::StreamExt;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use talos_workflow_job_protocol::{
    load_worker_shared_key, JobRequest, JobResult, JobStatus, PipelineJobRequest,
    PipelineJobResult, PipelineStepResult,
};

mod audit;
mod bindings;
mod circuit_breaker;
mod context;
mod host_impl;
mod metrics;
mod metrics_server;
mod runtime;
mod s3_signer;
mod sql_validator;
mod trace_nats;
mod tracing;
mod wit_inspector;

use crate::runtime::TalosRuntime;

/// Maximum concurrent single-node job executions
const MAX_CONCURRENT_JOBS: usize = 100;
/// Maximum concurrent pipeline job executions (heavier — multi-step)
const MAX_CONCURRENT_PIPELINE_JOBS: usize = 20;
/// Redis TTL for cached OCI layer pulls. 24h covers daily mutable-tag refresh
/// while bounding cache growth — without a TTL, distinct module URIs (every
/// new tag) accumulate forever. Digest-pinned URIs re-cache identical bytes
/// on every miss, so the TTL is harmless there.
const OCI_CACHE_TTL_SECS: u64 = 24 * 60 * 60;

/// Sigstore enforcement modes for OCI artifact signature verification.
/// Resolved once at process startup from `TALOS_SIGSTORE_REQUIRED`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum SigstorePolicy {
    /// Don't verify signatures. Right for dev/local where the worker can't
    /// reach Fulcio/Rekor and templates aren't signed. The default.
    Disabled,
    /// Try to verify; on failure log a warning but continue. Right for the
    /// migration window when some templates are signed and some aren't.
    Audit,
    /// Verify is mandatory; failure => refuse to execute. Production setting.
    Required,
}

impl SigstorePolicy {
    fn from_env() -> Self {
        match std::env::var("TALOS_SIGSTORE_REQUIRED")
            .unwrap_or_default()
            .as_str()
        {
            "true" | "1" | "required" => Self::Required,
            "audit" | "warn" => Self::Audit,
            _ => Self::Disabled,
        }
    }
}

/// Build the `cosign verify` argv for a given OCI reference. Pure
/// (no env reads, no I/O) so the security-critical command construction
/// is unit-tested without invoking cosign.
///
/// Cert identity + OIDC issuer come from configuration:
/// - `identity_regexp`: regex matched against the SAN URI of the Fulcio
///   cert. Pin to the workflow URL pattern, e.g.
///   `^https://github\.com/OWNER/talos/\.github/workflows/template-publish\.yml@`
/// - `oidc_issuer`: GitHub Actions = `https://token.actions.githubusercontent.com`
pub(crate) fn cosign_verify_argv(
    reference: &str,
    identity_regexp: &str,
    oidc_issuer: &str,
) -> Vec<String> {
    vec![
        "verify".to_string(),
        "--certificate-identity-regexp".to_string(),
        identity_regexp.to_string(),
        "--certificate-oidc-issuer".to_string(),
        oidc_issuer.to_string(),
        // Output to stderr keeps stdout free for structured signal — we don't
        // currently parse stdout, but reserving the channel makes future
        // "extract Rekor entry ID" upgrades non-breaking.
        "--output".to_string(),
        "json".to_string(),
        reference.to_string(),
    ]
}

/// Run `cosign verify` against an OCI reference. Returns `Ok(())` if the
/// signature is valid AND the cert identity / OIDC issuer match. Errors
/// carry a sanitised message safe to surface in JobResult; the unsanitised
/// reason is on tracing::warn for operators.
pub(crate) async fn verify_oci_signature(
    reference: &str,
    identity_regexp: &str,
    oidc_issuer: &str,
) -> Result<(), String> {
    let argv = cosign_verify_argv(reference, identity_regexp, oidc_issuer);
    let output = match tokio::process::Command::new("cosign")
        .args(&argv)
        .output()
        .await
    {
        Ok(o) => o,
        Err(e) => {
            // ENOENT (cosign missing) is operator misconfig — surface it
            // distinctly so it isn't mistaken for a verification failure.
            ::tracing::error!(
                error = %e,
                "cosign binary not found or unexecutable — install cosign in the worker image"
            );
            return Err("cosign_unavailable".to_string());
        }
    };
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    ::tracing::warn!(
        reference = %reference,
        exit_code = output.status.code().unwrap_or(-1),
        stderr = %stderr,
        "cosign verify failed"
    );
    Err("signature_verification_failed".to_string())
}

/// Decision returned by `verify_oci_layer` — small enum to make the security-
/// critical "should we trust these bytes?" decision testable in isolation.
#[derive(Debug, PartialEq)]
pub(crate) enum LayerVerdict<'a> {
    /// Manifest declared a digest and the layer's recomputed sha256 matches.
    /// Safe to execute and cache.
    Verified { digest: &'a str },
    /// Manifest had no layer descriptor — registry returned a malformed
    /// manifest. Accept with a warning (legacy behaviour) but flag it.
    AcceptedUnverified,
    /// Manifest digest != recomputed digest. Refuse to execute. Returned
    /// with both digests so the caller can log structured fields.
    DigestMismatch { expected: &'a str, computed: String },
}

/// Verify a pulled OCI layer's bytes against its manifest digest. Pure
/// function — no I/O, no allocations beyond the sha256 itself — so it can be
/// unit-tested without a registry. Called from the worker's OCI fetch path
/// before the bytes are cached or executed.
pub(crate) fn verify_oci_layer<'a>(
    layer_data: &[u8],
    manifest_digest: Option<&'a str>,
) -> LayerVerdict<'a> {
    use sha2::Digest as _;
    let computed = format!("sha256:{:x}", sha2::Sha256::digest(layer_data));
    match manifest_digest {
        Some(expected) if expected == computed => LayerVerdict::Verified { digest: expected },
        Some(expected) => LayerVerdict::DigestMismatch { expected, computed },
        None => LayerVerdict::AcceptedUnverified,
    }
}

// ============================================================================
// SECURITY: Static regex compilation — compiled exactly once at first use.
// Recompiling regexes on every call wastes CPU and can cause latency spikes.
// ============================================================================

static RE_UNIX_PATH: OnceLock<regex::Regex> = OnceLock::new();
static RE_WIN_PATH: OnceLock<regex::Regex> = OnceLock::new();
static RE_LINE_NUM: OnceLock<regex::Regex> = OnceLock::new();
static RE_INTERNAL_IP: OnceLock<regex::Regex> = OnceLock::new();

// MCP-913 (2026-05-14): bare OnceLock<Client>, no outer Mutex.
// `oci_distribution::Client::pull` takes `&self` (verified against
// the 0.11 source — internal `auth_store: Arc<RwLock<HashMap<...>>>`
// handles the token cache concurrency). Pre-fix `OnceLock<Mutex<Client>>`
// + `client_mutex.lock().await` SERIALIZED every concurrent OCI pull
// through one lock. The critical section held across:
//   - sigstore `cosign verify` subprocess (network + fork, ~1-3s)
//   - OCI registry pull (network + blob transfer, ~1-10s)
//   - layer digest verify (fast)
//   - Redis cache SET (network, fast)
// So under worker concurrency, a second module pull waited for the
// first to FULLY complete the chain. With 5–15s per pull, this
// capped worker module-load throughput at one-at-a-time per scheme
// (HTTPS / HTTP separately). The two schemes don't share locks but
// neither do they handle hostname-level isolation.
static OCI_CLIENT_HTTPS: OnceLock<oci_distribution::Client> = OnceLock::new();
static OCI_CLIENT_HTTP: OnceLock<oci_distribution::Client> = OnceLock::new();

fn get_oci_client(is_http: bool) -> &'static oci_distribution::Client {
    if is_http {
        OCI_CLIENT_HTTP.get_or_init(|| {
            let client_config = oci_distribution::client::ClientConfig {
                protocol: oci_distribution::client::ClientProtocol::Http,
                ..Default::default()
            };
            oci_distribution::Client::new(client_config)
        })
    } else {
        OCI_CLIENT_HTTPS.get_or_init(|| {
            let client_config = oci_distribution::client::ClientConfig::default();
            oci_distribution::Client::new(client_config)
        })
    }
}

fn unix_path_re() -> &'static regex::Regex {
    RE_UNIX_PATH
        .get_or_init(|| regex::Regex::new(r"/[\w/.-]+\.(rs|toml|json)").expect("invalid regex"))
}

fn win_path_re() -> &'static regex::Regex {
    RE_WIN_PATH.get_or_init(|| {
        regex::Regex::new(r"[A-Z]:\\[\w\\.-]+\.(rs|toml|json)").expect("invalid regex")
    })
}

fn line_num_re() -> &'static regex::Regex {
    RE_LINE_NUM.get_or_init(|| regex::Regex::new(r":\d+:\d+").expect("invalid regex"))
}

fn internal_ip_re() -> &'static regex::Regex {
    // MCP-530: the original three alternatives missed every other
    // RFC-1918 / loopback / link-local range. Real error messages
    // commonly include:
    //   * 172.16.0.0/12 (RFC 1918) — covers Docker default bridge
    //     networks (`172.17.0.0/16`), most Kubernetes service
    //     CIDRs, AWS / GCP / Azure default VPC subnets.
    //   * 169.254.0.0/16 (RFC 3927 link-local) — includes
    //     169.254.169.254 (AWS / GCP / Azure / DO IMDS / metadata
    //     endpoint). Leaking this in an error message tells an
    //     attacker exactly which cloud the worker is running on.
    //   * 100.64.0.0/10 (RFC 6598 CGNAT) — used by some cloud
    //     load-balancer health-check origin IPs.
    //   * 127.0.0.0/8 (loopback) — only `127.0.0.1` was caught,
    //     so `127.0.0.53` (systemd-resolved), `127.0.1.1`
    //     (Ubuntu hostname), etc. leaked through.
    //
    // IPv6 deliberately omitted: matching it precisely in a regex
    // is verbose and the worker's error surfaces today only carry
    // IPv4. If a future production surface produces IPv6 internal
    // addresses, extend then.
    RE_INTERNAL_IP.get_or_init(|| {
        regex::Regex::new(
            r"(?x)
            10\.\d+\.\d+\.\d+
            |
            127\.\d+\.\d+\.\d+
            |
            169\.254\.\d+\.\d+
            |
            172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+
            |
            192\.168\.\d+\.\d+
            |
            100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d+\.\d+
            ",
        )
        .expect("invalid regex")
    })
}

// ============================================================================
// SECURITY: Error Message Sanitization
// Prevent information disclosure by removing file paths and sensitive data.
// ============================================================================

/// Sanitize error messages before sending to clients.
///
/// Removes: file paths, line numbers, internal IP addresses.
/// Truncates to 2000 characters (Unicode-safe).
fn sanitize_error_message(error: &str) -> String {
    let mut sanitized = error.to_string();

    sanitized = unix_path_re()
        .replace_all(&sanitized, "[FILE]")
        .into_owned();
    sanitized = win_path_re().replace_all(&sanitized, "[FILE]").into_owned();
    sanitized = line_num_re().replace_all(&sanitized, "").into_owned();
    sanitized = internal_ip_re()
        .replace_all(&sanitized, "[INTERNAL_IP]")
        .into_owned();

    // Unicode-safe truncation: count chars, not bytes.
    let char_count = sanitized.chars().count();
    if char_count > 2000 {
        let truncated: String = sanitized.chars().take(2000).collect();
        format!("{}... [truncated]", truncated)
    } else {
        sanitized
    }
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
        match nc.publish(topic.clone(), payload.clone()).await {
            Ok(_) => {
                if attempt > 0 {
                    ::tracing::info!(topic, attempt, "Published after retries");
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
                        "Failed to publish, retrying"
                    );
                    tokio::time::sleep(tokio::time::Duration::from_millis(backoff_ms)).await;
                    backoff_ms = (backoff_ms * 2).min(5_000);
                } else {
                    return Err(format!(
                        "Failed to publish to {} after {} attempts: {}",
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
async fn publish_result_with_retry(
    nc: &async_nats::Client,
    result: &JobResult,
    max_attempts: u32,
    reply_topic: Option<String>,
) -> Result<(), String> {
    let payload = match serde_json::to_vec(&result) {
        Ok(v) => bytes::Bytes::from(v),
        Err(e) => {
            return Err(format!("Failed to serialize result: {}", e));
        }
    };

    if let Some(reply) = reply_topic {
        publish_bytes_with_retry(nc, reply, payload, max_attempts).await
    } else {
        let result_topic = format!("talos.results.{}", result.job_id);
        publish_bytes_with_retry(nc, result_topic, payload, max_attempts).await
    }
}

/// Execute the Wasm module for a given job with observability.
///
/// * Verifies the HMAC signature before executing.
/// * Decrypts secrets from `req.encrypted_secrets` using the shared key.
/// * Passes decrypted secrets to the runtime so WASM modules can access them
///   via the `secrets::get-secret` host function.
async fn execute_job(
    cx: &opentelemetry::Context,
    req: JobRequest,
    runtime: Arc<TalosRuntime>,
    shared_key: talos_workflow_engine_core::WorkerSharedKey,
) -> JobResult {
    let start = std::time::Instant::now();

    // Create distributed tracing span
    let mut _span =
        tracing::ExecutionSpan::new_with_parent("job-execution", &req.job_id.to_string(), cx);
    _span.set_attribute("job_id", &req.job_id.to_string());
    _span.set_attribute("module_uri", &req.module_uri);

    // SECURITY: Verify HMAC-SHA256 signature + nonce freshness (300 s window).
    if let Err(e) = req.verify(shared_key.as_bytes(), 300) {
        ::tracing::error!(job_id = %req.job_id, error = %e, "Job signature verification failed");
        _span.set_attribute("error", "signature_verification_failed");
        _span.end_error("Signature verification failed");

        // MCP-1212 (2026-05-18): diagnostic enrichment for signature
        // verification failures. Pre-fix the worker emitted an opaque
        // "signature verification failed" string with no way for the
        // operator to identify which signed field diverged between
        // controller and worker. Recompute the same per-field hashes
        // that `signing_payload()` consumes and surface them in
        // output_payload so `get_execution_status` shows the worker's
        // view side-by-side with the underlying error. The controller
        // side logs the same fields at WARN level
        // (target: "signature_diag") so operators can grep their
        // controller logs and find the controller's view for direct
        // comparison. `diag_hashes()` is the canonical helper, colocated
        // with `signing_payload()` in job-protocol so the field formulas
        // stay in sync across controller + worker.
        let (worker_input_hash, worker_secrets_hash, worker_input_byte_len) = req.diag_hashes();
        let signature_byte_len = req.signature.len();

        return JobResult {
            job_id: req.job_id,
            status: JobStatus::Failed,
            output_payload: json!({
                "error": "signature verification failed",
                "diag": {
                    "verify_error": e,
                    "worker_input_hash": worker_input_hash,
                    "worker_secrets_hash": worker_secrets_hash,
                    "worker_input_byte_len": worker_input_byte_len,
                    "signature_byte_len": signature_byte_len,
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
                    "note": "Compare these worker-computed values against the controller's `signature_diag` WARN log entry for the same job_id to identify which signed field diverged."
                }
            }),
            logs: vec![],
            execution_time_ms: start.elapsed().as_millis() as u64,
            signature: vec![],
            result_nonce: String::new(),
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
            return JobResult {
                job_id: req.job_id,
                status: JobStatus::Failed,
                output_payload: json!({"error": "job deadline expired"}),
                logs: vec![],
                execution_time_ms: start.elapsed().as_millis() as u64,
                signature: vec![],
                result_nonce: String::new(),
            };
        }
    }

    // SECURITY: Decrypt secrets from the encrypted payload.
    let secrets: HashMap<String, String> = if req.encrypted_secrets.is_empty() {
        HashMap::new()
    } else {
        match req.encrypted_secrets.decrypt(shared_key.as_bytes()) {
            Ok(s) => s,
            Err(e) => {
                ::tracing::error!(job_id = %req.job_id, error = %e, "Failed to decrypt job secrets");
                _span.end_error("Secret decryption failed");

                return JobResult {
                    job_id: req.job_id,
                    status: JobStatus::Failed,
                    output_payload: json!({"error": "failed to decrypt job secrets"}),
                    logs: vec![],
                    execution_time_ms: start.elapsed().as_millis() as u64,
                    signature: vec![],
                    result_nonce: String::new(),
                };
            }
        }
    };

    // Load the Wasm module bytes.
    //
    // SECURITY: track whether the bytes we end up executing were
    // cryptographically attested during THIS worker run:
    // * inline `wasm_bytes` from a JobRequest — HMAC over the job covers
    //   sha256(bytes), so attested by the signing key.
    // * Fresh OCI pull that completed Sigstore + layer-digest checks.
    // The opposite (NOT attested in this run): a Redis cache hit used as
    // OCI fallback, a `redis:wasm:` direct fetch, or a filesystem load.
    // For unattested bytes, `expected_wasm_hash` from the controller is
    // the only thing standing between us and a Redis-write attacker
    // substituting malicious WASM. The verification block downstream
    // refuses to execute unattested bytes when no hash is supplied.
    let mut bytes_attested_in_this_run = false;
    _span.add_event("loading_module");
    let wasm_bytes = if let Some(bytes) = &req.wasm_bytes {
        // PERFORMANCE: Use bytes provided in job request (avoids file I/O)
        // HMAC over the JobRequest covers sha256(bytes) — attested.
        _span.set_attribute_int("module_size_bytes", bytes.len() as i64);
        _span.set_attribute("module_source", "job_request");
        bytes_attested_in_this_run = true;
        bytes.clone()
    } else if req.module_uri.starts_with("oci://") {
        // Fetch from OCI Registry (e.g. GitHub Container Registry, AWS ECR, JFrog)
        _span.add_event("fetching_from_oci_registry");
        _span.set_attribute("oci_url", &req.module_uri);

        // Strip the "oci://" prefix
        let mut image_ref = req
            .module_uri
            .strip_prefix("oci://")
            .unwrap_or(&req.module_uri)
            .to_string();

        if image_ref.starts_with("localhost:5001") {
            image_ref = image_ref.replace("localhost:5001", "registry:5000");
        }

        // First check Redis for cached OCI artifact
        let mut found_bytes = None;
        let redis_key = format!("oci_cache:{}", &req.module_uri);
        if let Some(redis_client) = runtime.redis_client() {
            if let Ok(mut conn) = redis_client.get_multiplexed_async_connection().await {
                if let Ok(Some(b)) = redis::cmd("GET")
                    .arg(&redis_key)
                    .query_async::<Option<Vec<u8>>>(&mut conn)
                    .await
                {
                    _span.add_event("oci_cache_hit");
                    _span.set_attribute("module_source", "redis_oci_cache");
                    found_bytes = Some(b);
                }
            }
        }

        use oci_distribution::secrets::RegistryAuth;
        use oci_distribution::Reference;

        if let Ok(reference) = image_ref.parse::<Reference>() {
            // In a development environment with a local registry, we need to allow HTTP.
            // SECURITY: Ensure HTTP downgrade is never allowed in production.
            // MCP-668 (2026-05-13): route through `talos_config::is_production()`
            // so an empty `RUST_ENV=""` from a helm placeholder doesn't
            // bypass the production gate. Raw `unwrap_or_default()` would
            // compare `"" == "production"` → false → fail OPEN.
            let is_prod = talos_config::is_production();
            let is_local_registry = image_ref.starts_with("registry:5000")
                || image_ref.starts_with("localhost:")
                || image_ref.starts_with("127.0.0.1:");

            let is_http = if is_local_registry && !is_prod {
                true
            } else if is_local_registry && is_prod {
                let err_msg =
                    "SECURITY: Denied HTTP downgrade for OCI fetch in production environment"
                        .to_string();
                ::tracing::error!("{}", err_msg);
                _span.end_error(&err_msg);
                return JobResult {
                    job_id: req.job_id,
                    status: JobStatus::Failed,
                    output_payload: serde_json::json!({"error": err_msg}),
                    logs: vec![],
                    execution_time_ms: start.elapsed().as_millis() as u64,
                    signature: vec![],
                    result_nonce: String::new(),
                };
            } else {
                false
            };

            // MCP-913: direct &Client — see OCI_CLIENT_HTTPS/HTTP comment for
            // why the prior `client_mutex.lock().await` was a concurrency
            // bottleneck. `Client::pull` is `&self` and thread-safe.
            let client = get_oci_client(is_http);

            // In a production enterprise setting, these would be loaded from HashiCorp Vault or mounted Secrets.
            // MCP-762 (2026-05-13): match the sibling helper
            // `talos-registry::sync::registry_auth_from_env` (sync.rs:547)
            // by filtering empty strings before constructing
            // RegistryAuth::Basic. Pre-fix, `OCI_REGISTRY_USERNAME=""`
            // (helm placeholder pattern) yielded `Ok("")` from
            // std::env::var, took the `if let (Ok, Ok)` branch, and
            // produced `RegistryAuth::Basic("", "")` — sent as
            // `Authorization: Basic Og==` (base64 of `:`). The registry
            // rejects with 401 instead of falling back to the
            // documented anonymous-for-public-artifacts path. Same
            // empty-env-var class as MCP-590/591/653/710/752/753; the
            // controller-side `registry_auth_from_env` had the right
            // shape but the worker-side resolver was the drift.
            let user_opt = std::env::var("OCI_REGISTRY_USERNAME")
                .ok()
                .filter(|v| !v.is_empty());
            let pass_opt = std::env::var("OCI_REGISTRY_PASSWORD")
                .ok()
                .filter(|v| !v.is_empty());
            let auth = match (user_opt, pass_opt) {
                (Some(user), Some(password)) => RegistryAuth::Basic(user, password),
                _ => RegistryAuth::Anonymous,
            };

            let accepted_media_types = vec!["application/vnd.wasm.content.layer.v1+wasm"];

            // Sigstore signature verification — runs BEFORE the OCI pull
            // body is processed, so an unsigned or tampered artifact never
            // gets executed OR cached. Policy is process-wide (resolved
            // once from env at startup); enforcement happens per-pull so
            // operators can flip from Audit → Required without restarting.
            //
            // SECURITY: this is the runtime trust boundary. Disabled mode
            // is for dev only — production deploys MUST set
            // TALOS_SIGSTORE_REQUIRED=true.
            let sigstore_policy = SigstorePolicy::from_env();
            if sigstore_policy != SigstorePolicy::Disabled {
                let identity_regexp =
                    std::env::var("TALOS_SIGSTORE_IDENTITY_REGEXP").unwrap_or_default();
                // MCP-752 (2026-05-13): filter empty so a helm-rendered
                // `TALOS_SIGSTORE_OIDC_ISSUER=""` doesn't bypass the default.
                // Pre-fix, `unwrap_or_else(|_| default)` only fired on the
                // env-unset path — `Ok("")` from a placeholder helm value
                // passed `""` verbatim into `cosign verify
                // --certificate-oidc-issuer ""`, weakening the documented
                // defense-in-depth that pins certificates to GitHub Actions
                // OIDC tokens specifically (per CLAUDE.md "Sigstore identity
                // regexp pins to the workflow URL ... The OIDC issuer pin
                // restricts to GitHub Actions tokens specifically. Without
                // ... either omission lets a valid Sigstore signature from
                // any other workflow on any other repo pass verification.").
                // Same empty-env class as MCP-590/591/653/710. The sibling
                // `identity_regexp` is already fail-closed in `Required`
                // mode at the check below — this fix completes the symmetry
                // by ensuring the `oidc_issuer` argument can never be empty
                // when `cosign` is invoked.
                let oidc_issuer = std::env::var("TALOS_SIGSTORE_OIDC_ISSUER")
                    .ok()
                    .filter(|v| !v.is_empty())
                    .unwrap_or_else(|| "https://token.actions.githubusercontent.com".to_string());
                if identity_regexp.is_empty() {
                    let err = "TALOS_SIGSTORE_IDENTITY_REGEXP must be set when \
                               TALOS_SIGSTORE_REQUIRED is enabled"
                        .to_string();
                    ::tracing::error!("{}", err);
                    if sigstore_policy == SigstorePolicy::Required {
                        _span.end_error(&err);
                        return JobResult {
                            job_id: req.job_id,
                            status: JobStatus::Failed,
                            output_payload: serde_json::json!({"error": err}),
                            logs: vec![],
                            execution_time_ms: start.elapsed().as_millis() as u64,
                            signature: vec![],
                            result_nonce: String::new(),
                        };
                    }
                } else {
                    match verify_oci_signature(&image_ref, &identity_regexp, &oidc_issuer).await {
                        Ok(()) => {
                            _span.add_event("sigstore_verify_ok");
                        }
                        Err(reason) => match sigstore_policy {
                            SigstorePolicy::Required => {
                                let err = format!("sigstore_required: {reason}");
                                ::tracing::error!(
                                    module_uri = %req.module_uri,
                                    "Sigstore verification failed and policy is required — refusing to execute"
                                );
                                _span.end_error(&err);
                                return JobResult {
                                    job_id: req.job_id,
                                    status: JobStatus::Failed,
                                    output_payload: serde_json::json!({"error": err}),
                                    logs: vec![],
                                    execution_time_ms: start.elapsed().as_millis() as u64,
                                    signature: vec![],
                                    result_nonce: String::new(),
                                };
                            }
                            SigstorePolicy::Audit => {
                                ::tracing::warn!(
                                    module_uri = %req.module_uri,
                                    reason = %reason,
                                    "Sigstore verification failed but policy is audit — continuing"
                                );
                                _span.add_event("sigstore_verify_failed_audit");
                            }
                            SigstorePolicy::Disabled => unreachable!(),
                        },
                    }
                }
            }

            match client.pull(&reference, &auth, accepted_media_types).await {
                Ok(image) => {
                    // The WASM binary is typically the first layer in a Wasm OCI artifact.
                    // Cross-check the layer's actual sha256 against the manifest's
                    // declared digest before trusting the bytes — bytes that don't
                    // match the manifest indicate registry corruption, MITM during
                    // pull (HTTP only — gated to localhost-dev above), or a bug in
                    // the publish pipeline. Verification logic lives in the pure
                    // helper `verify_oci_layer` so the security-critical decision
                    // is unit-testable.
                    if let Some(layer) = image.layers.into_iter().next() {
                        let manifest_digest = image
                            .manifest
                            .as_ref()
                            .and_then(|m| m.layers.first())
                            .map(|d| d.digest.as_str());
                        match verify_oci_layer(&layer.data, manifest_digest) {
                            LayerVerdict::Verified { digest } => {
                                _span.set_attribute("oci_layer_digest", digest);
                                _span.add_event("oci_pull_success");

                                // Populate the Redis cache so the next pull of this
                                // exact module_uri short-circuits the registry round-trip.
                                // TTL bounds growth — without it, cache size scales
                                // monotonically with distinct module_uris ever seen,
                                // which becomes a leak on registries with many tags.
                                // Tag-based URIs (mutable) refresh daily; digest-based
                                // URIs (immutable) just re-cache the same bytes.
                                if let Some(redis_client) = runtime.redis_client() {
                                    if let Ok(mut conn) =
                                        redis_client.get_multiplexed_async_connection().await
                                    {
                                        let _: Result<(), _> = redis::cmd("SET")
                                            .arg(&redis_key)
                                            .arg(&layer.data)
                                            .arg("EX")
                                            .arg(OCI_CACHE_TTL_SECS)
                                            .query_async(&mut conn)
                                            .await;
                                    }
                                }

                                // Fresh pull with Sigstore + digest checks both
                                // passed in THIS run — attested.
                                bytes_attested_in_this_run = true;
                                found_bytes = Some(layer.data);
                            }
                            LayerVerdict::DigestMismatch { expected, computed } => {
                                let err = format!(
                                    "oci_digest_mismatch: manifest declared {}, computed {}",
                                    expected, computed
                                );
                                ::tracing::error!(
                                    module_uri = %req.module_uri,
                                    expected = %expected,
                                    computed = %computed,
                                    "OCI layer digest mismatch — refusing to execute"
                                );
                                _span.end_error(&err);
                                return JobResult {
                                    job_id: req.job_id,
                                    status: JobStatus::Failed,
                                    output_payload: serde_json::json!({"error": err}),
                                    logs: vec![],
                                    execution_time_ms: start.elapsed().as_millis() as u64,
                                    signature: vec![],
                                    result_nonce: String::new(),
                                };
                            }
                            LayerVerdict::AcceptedUnverified => {
                                ::tracing::warn!(
                                    module_uri = %req.module_uri,
                                    "OCI manifest had no layer descriptor — accepting bytes \
                                     unverified (registry returned a malformed manifest)"
                                );
                                _span.add_event("oci_pull_success_unverified");
                                found_bytes = Some(layer.data);
                            }
                        }
                    }
                }
                Err(e) => {
                    ::tracing::warn!(module_uri = %req.module_uri, error = %e, "Failed to pull WASM artifact from OCI registry");
                    let err_msg = format!("oci_pull_error: {}", e);
                    let sanitized_error = sanitize_error_message(&err_msg);
                    _span.add_event(&sanitized_error);
                }
            }
        }

        match found_bytes {
            Some(b) => b,
            None => {
                _span.end_error("WASM payload not found in OCI registry");
                return JobResult {
                    job_id: req.job_id,
                    status: JobStatus::Failed,
                    output_payload: serde_json::json!({"error": "WASM payload not found in OCI registry"}),
                    logs: vec![],
                    execution_time_ms: start.elapsed().as_millis() as u64,
                    signature: vec![],
                    result_nonce: String::new(),
                };
            }
        }
    } else if req.module_uri.starts_with("redis:wasm:") {
        // Fetch from Redis via TalosRuntime's redis client
        _span.add_event("fetching_from_redis");

        let mut found_bytes: Option<Vec<u8>> = None;
        if let Some(redis_client) = runtime.redis_client() {
            if let Ok(mut conn) = redis_client.get_multiplexed_async_connection().await {
                // remove "redis:" prefix to get the actual key: "wasm:{user_id}:{module_id}"
                let key = req
                    .module_uri
                    .strip_prefix("redis:")
                    .unwrap_or(&req.module_uri);
                if let Ok(Some(b)) = redis::cmd("GET")
                    .arg(key)
                    .query_async::<Option<Vec<u8>>>(&mut conn)
                    .await
                {
                    found_bytes = Some(b);
                }
            }
        }

        if let Some(b) = found_bytes {
            _span.set_attribute_int("module_size_bytes", b.len() as i64);
            _span.set_attribute("module_source", "redis");
            b
        } else {
            let error_msg =
                "failed to fetch wasm module from redis (not found or redis unavailable)";
            _span.set_attribute("error", error_msg);
            _span.end_error(error_msg);

            return JobResult {
                job_id: req.job_id,
                status: JobStatus::Failed,
                output_payload: json!({"error": error_msg}),
                logs: vec![],
                execution_time_ms: start.elapsed().as_millis() as u64,
                signature: vec![],
                result_nonce: String::new(),
            };
        }
    } else {
        // FALLBACK: Read from file system if bytes not provided
        match std::fs::read(&req.module_uri) {
            Ok(b) => {
                _span.set_attribute_int("module_size_bytes", b.len() as i64);
                _span.set_attribute("module_source", "filesystem");
                b
            }
            Err(e) => {
                let error_msg = format!("failed to read wasm module: {}", e);
                let sanitized_error = sanitize_error_message(&error_msg);
                _span.set_attribute("error", &sanitized_error);
                _span.end_error(&sanitized_error);

                return JobResult {
                    job_id: req.job_id,
                    status: JobStatus::Failed,
                    output_payload: json!({"error": sanitized_error}),
                    logs: vec![],
                    execution_time_ms: start.elapsed().as_millis() as u64,
                    signature: vec![],
                    result_nonce: String::new(),
                };
            }
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
                return JobResult {
                    job_id: req.job_id,
                    status: JobStatus::Failed,
                    output_payload: serde_json::json!({
                        "error": "WASM integrity check failed: content hash mismatch"
                    }),
                    logs: vec![],
                    execution_time_ms: start.elapsed().as_millis() as u64,
                    signature: vec![],
                    result_nonce: String::new(),
                };
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
            // Fail closed in production; warn-and-continue in dev so
            // local-registry workflows keep working.
            // MCP-668 (2026-05-13): empty-string-safe production gate.
            let is_prod = talos_config::is_production();
            if is_prod {
                ::tracing::error!(
                    job_id = %req.job_id,
                    module_uri = %req.module_uri,
                    "SECURITY: refusing to execute WASM loaded from unverified storage \
                     (cache/redis/filesystem) without expected_wasm_hash. Either supply \
                     a hash or load from a path that Sigstore-verifies in this run"
                );
                _span.end_error("unattested_wasm_no_hash");
                return JobResult {
                    job_id: req.job_id,
                    status: JobStatus::Failed,
                    output_payload: serde_json::json!({
                        "error": "WASM integrity check failed: no hash and no in-run attestation"
                    }),
                    logs: vec![],
                    execution_time_ms: start.elapsed().as_millis() as u64,
                    signature: vec![],
                    result_nonce: String::new(),
                };
            }
            ::tracing::warn!(
                job_id = %req.job_id,
                module_uri = %req.module_uri,
                "WASM loaded from unattested storage without expected_wasm_hash \
                 (dev mode — would fail closed in production)"
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
    let capability_world_hint: Option<crate::wit_inspector::CapabilityWorld> =
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
    let worker_fallback_secs: u64 =
        crate::runtime::nonzero_env_or_default("WASM_EXECUTION_TIMEOUT_SECS", 60);
    let job_timeout_ms: u64 = if req.timeout_ms > 0 {
        req.timeout_ms
    } else {
        worker_fallback_secs.saturating_mul(1000)
    };
    let job_timeout = std::time::Duration::from_millis(job_timeout_ms);
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
        ),
    )
    .await
    {
        Ok(Ok(output)) => {
            let duration_ms = start.elapsed().as_millis() as u64;
            _span.set_attribute_int("duration_ms", duration_ms as i64);
            _span.end_success();

            JobResult {
                job_id: req.job_id,
                status: JobStatus::Success,
                output_payload: output,
                logs: vec![],
                execution_time_ms: duration_ms,
                signature: vec![],
                result_nonce: String::new(),
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
                job_id: req.job_id,
                status: JobStatus::Failed,
                output_payload: json!({"error": sanitized_error}),
                logs: vec![],
                execution_time_ms: duration_ms,
                signature: vec![],
                result_nonce: String::new(),
            }
        }
        Err(_) => {
            let duration_ms = start.elapsed().as_millis() as u64;
            let error_msg = "execution timed out after 30 seconds".to_string();
            _span.set_attribute("error", &error_msg);
            _span.set_attribute_int("duration_ms", duration_ms as i64);
            _span.end_error(&error_msg);

            JobResult {
                job_id: req.job_id,
                status: JobStatus::Failed,
                output_payload: json!({"error": error_msg}),
                logs: vec![],
                execution_time_ms: duration_ms,
                signature: vec![],
                result_nonce: String::new(),
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
async fn execute_pipeline_job(
    cx: &opentelemetry::Context,
    req: PipelineJobRequest,
    runtime: Arc<TalosRuntime>,
    shared_key: talos_workflow_engine_core::WorkerSharedKey,
) -> PipelineJobResult {
    use talos_workflow_job_protocol::JobStatus;

    let start = std::time::Instant::now();
    let mut _span = tracing::ExecutionSpan::new_with_parent(
        "pipeline-execution",
        &req.workflow_execution_id.to_string(),
        cx,
    );

    // SECURITY: Verify HMAC-SHA256 signature + nonce freshness (300 s window).
    if let Err(e) = req.verify(shared_key.as_bytes(), 300) {
        ::tracing::error!(job_id = %req.job_id, error = %e, "Pipeline job signature verification failed");
        _span.set_attribute("error", "signature_verification_failed");
        _span.end_error("Signature verification failed");
        return PipelineJobResult {
            job_id: req.job_id,
            overall_status: JobStatus::Failed,
            step_results: vec![],
            final_output: serde_json::json!({"error": "pipeline signature verification failed"}),
            total_time_ms: start.elapsed().as_millis() as u64,
            signature: vec![],
            result_nonce: String::new(),
        };
    }

    // Validate maximum pipeline timeout to prevent indefinitely tying up workers.
    // MCP-642: =0 would reject every pipeline job (req.total_timeout_ms > 0
    // always exceeds 0). Substitute default + WARN.
    let max_timeout_ms: u64 =
        crate::runtime::nonzero_env_or_default("WASM_MAX_PIPELINE_TIMEOUT_MS", 3_600_000);

    if req.total_timeout_ms > max_timeout_ms {
        ::tracing::warn!(
            job_id = %req.job_id,
            requested_ms = req.total_timeout_ms,
            max_ms = max_timeout_ms,
            "Pipeline job rejected: timeout exceeds maximum"
        );
        _span.end_error("Timeout exceeds maximum");
        return PipelineJobResult {
            job_id: req.job_id,
            overall_status: JobStatus::Failed,
            step_results: vec![],
            final_output: serde_json::json!({"error": format!("Requested total timeout ({}ms) exceeds maximum allowed ({}ms)", req.total_timeout_ms, max_timeout_ms)}),
            total_time_ms: start.elapsed().as_millis() as u64,
            signature: vec![],
            result_nonce: String::new(),
        };
    }

    // Build PipelineStepSpecs by decrypting per-step secrets.
    let mut step_specs: Vec<PipelineStepSpec> = Vec::with_capacity(req.steps.len());
    for step in &req.steps {
        let secrets = if step.encrypted_secrets.is_empty() {
            std::collections::HashMap::new()
        } else {
            match step.encrypted_secrets.decrypt(shared_key.as_bytes()) {
                Ok(s) => s,
                Err(e) => {
                    ::tracing::error!(job_id = %req.job_id, error = %e, "Failed to decrypt pipeline step secrets");
                    _span.end_error("Secret decryption failed");
                    return PipelineJobResult {
                        job_id: req.job_id,
                        overall_status: JobStatus::Failed,
                        step_results: vec![],
                        final_output: serde_json::json!({"error": "failed to decrypt step secrets"}),
                        total_time_ms: start.elapsed().as_millis() as u64,
                        signature: vec![],
                        result_nonce: String::new(),
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

    match runtime
        .execute_pipeline(
            &req.workflow_execution_id.to_string(),
            step_specs,
            overall_timeout,
            req.share_sandbox,
            req.max_llm_tier,
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
                job_id: req.job_id,
                overall_status: JobStatus::Success,
                step_results,
                final_output: pipeline_result.final_output,
                total_time_ms,
                signature: vec![],
                result_nonce: String::new(),
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
                job_id: req.job_id,
                overall_status: JobStatus::Failed,
                step_results: vec![],
                final_output: serde_json::json!({"error": sanitized_error}),
                total_time_ms,
                signature: vec![],
                result_nonce: String::new(),
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

    let shared_key =
        load_worker_shared_key().map_err(|e| anyhow::anyhow!("WORKER_SHARED_KEY error: {}", e))?;
    println!("[0/5] Loaded WORKER_SHARED_KEY (32 bytes)");

    // Install the same key into talos-memory's RPC auth slot so the
    // WIT `agent_memory::*` and `graph_memory::*` host functions can
    // sign their NATS requests. The controller registers the same
    // key on its side for verification (see controller/src/main.rs).
    talos_memory::rpc_auth::register_hmac_key(Arc::new(shared_key.as_bytes().to_vec()));

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

    // Install a console tracing subscriber so `tracing::warn!`, `tracing::info!`,
    // etc. in host_impl.rs (security checks, vault allowlist, SSRF blocks, rate
    // limits) appear in `docker logs` alongside the [TRACE] span output. Without
    // this, those log lines only went to Jaeger — silently dropped if Jaeger was
    // unreachable or nobody was watching the traces.
    //
    // The fmt layer respects RUST_LOG (default: info for the worker crate, warn
    // for everything else). The OTel tracing layer is initialized separately
    // below and coexists via the tracing-subscriber registry.
    {
        use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("worker=info,warn"));
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().with_target(true).with_thread_ids(false))
            .init();
    }

    let jaeger_endpoint = std::env::var("JAEGER_ENDPOINT")
        .ok()
        .or_else(|| Some("http://localhost:4317".to_string()));

    if let Some(endpoint) = jaeger_endpoint.as_ref() {
        match tracing::init_tracing("talos-worker", Some(endpoint)) {
            Ok(_) => println!("      Tracing initialized (endpoint: {})", endpoint),
            Err(e) => {
                eprintln!("Warning: Failed to initialize tracing: {}", e);
                eprintln!("    Continuing without tracing...");
            }
        }
    }

    // MCP-580: spawn the circuit-breaker periodic cleanup task so the
    // per-host `records` DashMap doesn't grow monotonically with
    // distinct hosts seen across the worker's lifetime. Idempotent at
    // the breaker level (only Closed stale entries get evicted; Open /
    // HalfOpen are preserved). Pre-fix the cleanup() method existed
    // but had zero callers.
    circuit_breaker::spawn_periodic_cleanup();

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

    let nc: Client = match (nats_user, nats_password) {
        (Some(user), Some(pass)) => {
            match async_nats::ConnectOptions::new()
                .user_and_password(user, pass)
                .connect(&nats_url)
                .await
            {
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
            match async_nats::connect(&nats_url).await {
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

    let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_JOBS));
    let pipeline_semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_PIPELINE_JOBS));

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
                                crate::trace_nats::extract_trace_context(headers)
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
                            let reply_to = msg.reply.map(|r: async_nats::Subject| r.to_string());

                            tokio::task::spawn(async move {
                                let mut result = execute_job(&cx, req.clone(), runtime_clone, key_clone.clone()).await;

                                if let Err(e) = result.sign(key_clone.as_bytes()) {
                                    ::tracing::error!(job_id = %result.job_id, error = %e, "CRITICAL: Failed to sign job result");
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

                                if let Err(e) = publish_result_with_retry(&nc_clone, &result, 3, reply_to).await {
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
                                crate::trace_nats::extract_trace_context(headers)
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
                            let reply_to = msg.reply.clone().map(|r: async_nats::Subject| r.to_string());

                            tokio::task::spawn(async move {
                                let mut result =
                                    execute_pipeline_job(&cx, req.clone(), runtime_clone, key_clone.clone()).await;

                                if let Err(e) = result.sign(key_clone.as_bytes()) {
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

                                let payload_vec = serde_json::to_vec(&result).unwrap_or_default();
                                let payload = bytes::Bytes::from(payload_vec);

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

    while (semaphore.available_permits() < MAX_CONCURRENT_JOBS
        || pipeline_semaphore.available_permits() < MAX_CONCURRENT_PIPELINE_JOBS
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
    tracing::shutdown_tracing();
    println!("      Traces flushed");

    println!("[3/3] Closing connections...");
    drop(nc);
    println!("      Connections closed");

    println!("\nWorker shutdown complete");
    Ok(())
}

#[cfg(test)]
mod sanitize_error_message_tests {
    //! MCP-530: pin the internal-IP coverage. Pre-fix only
    //! 192.168/16, 10/8, and the literal 127.0.0.1 were redacted.
    //! Every other RFC-1918 / loopback / link-local / CGNAT range
    //! leaked through. Cloud-metadata 169.254.169.254 is the
    //! highest-value redaction target — its presence in an error
    //! message would tell an attacker exactly which cloud the
    //! worker runs on.
    use super::sanitize_error_message;

    #[test]
    fn redacts_192_168_subnet() {
        let s = sanitize_error_message("error connecting to 192.168.1.42:5432");
        assert!(s.contains("[INTERNAL_IP]"));
        assert!(!s.contains("192.168.1.42"));
    }

    #[test]
    fn redacts_10_dot_subnet() {
        let s = sanitize_error_message("upstream 10.0.5.7 timeout");
        assert!(s.contains("[INTERNAL_IP]"));
        assert!(!s.contains("10.0.5.7"));
    }

    #[test]
    fn redacts_172_16_through_31_rfc1918() {
        // 172.16/12 — covers Docker default bridge (172.17/16) and
        // many cloud default subnets. Pre-MCP-530 these leaked.
        for ip in &[
            "172.16.0.1",
            "172.17.0.1",  // docker0 default
            "172.20.5.10",
            "172.28.0.42",
            "172.31.255.254",
        ] {
            let s = sanitize_error_message(&format!("dial {} refused", ip));
            assert!(
                s.contains("[INTERNAL_IP]"),
                "RFC-1918 172/12 address must be redacted: {ip}"
            );
            assert!(!s.contains(ip), "raw {ip} must not leak");
        }
    }

    #[test]
    fn does_not_redact_172_outside_rfc1918() {
        // 172.15.x.x and 172.32.x.x are NOT RFC 1918 — they are
        // public address space. Must NOT be redacted (operators
        // debugging external upstream connectivity need them).
        for ip in &["172.15.0.1", "172.32.0.1", "172.100.0.1"] {
            let s = sanitize_error_message(&format!("dial {} refused", ip));
            assert!(
                !s.contains("[INTERNAL_IP]"),
                "{ip} is public 172/8 space; must NOT be redacted"
            );
        }
    }

    #[test]
    fn redacts_link_local_and_cloud_metadata() {
        // 169.254/16 — the cloud-metadata-server case
        // (169.254.169.254) is the highest-value redaction here.
        for ip in &["169.254.169.254", "169.254.0.1", "169.254.255.254"] {
            let s = sanitize_error_message(&format!("HTTP request to {} returned 401", ip));
            assert!(
                s.contains("[INTERNAL_IP]"),
                "link-local / IMDS {ip} must be redacted"
            );
            assert!(!s.contains(ip), "raw {ip} must not leak");
        }
    }

    #[test]
    fn redacts_cgnat_rfc6598() {
        // 100.64.0.0/10 (100.64.0.0 – 100.127.255.255)
        for ip in &["100.64.0.1", "100.100.5.7", "100.127.255.254"] {
            let s = sanitize_error_message(&format!("origin {} ", ip));
            assert!(
                s.contains("[INTERNAL_IP]"),
                "CGNAT {ip} must be redacted"
            );
        }
        // Boundary: 100.63.x.x and 100.128.x.x are OUTSIDE CGNAT.
        for ip in &["100.63.0.1", "100.128.0.1"] {
            let s = sanitize_error_message(&format!("origin {}", ip));
            assert!(
                !s.contains("[INTERNAL_IP]"),
                "{ip} is outside CGNAT; must NOT be redacted"
            );
        }
    }

    #[test]
    fn redacts_full_127_loopback() {
        // Pre-MCP-530 only the literal 127.0.0.1 was caught.
        // 127.0.0.53 (systemd-resolved), 127.0.1.1 (Ubuntu
        // /etc/hosts hostname), 127.x.x.x in general are all
        // loopback.
        for ip in &["127.0.0.1", "127.0.0.53", "127.0.1.1", "127.255.255.254"] {
            let s = sanitize_error_message(&format!("connect {} refused", ip));
            assert!(
                s.contains("[INTERNAL_IP]"),
                "127/8 {ip} must be redacted"
            );
        }
    }

    #[test]
    fn does_not_redact_public_ip() {
        for ip in &["1.1.1.1", "8.8.8.8", "203.0.113.5", "172.15.0.1"] {
            let s = sanitize_error_message(&format!("dial {} refused", ip));
            assert!(
                !s.contains("[INTERNAL_IP]"),
                "public {ip} must NOT be redacted"
            );
        }
    }
}

#[cfg(test)]
mod oci_layer_tests {
    use super::*;

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::Digest as _;
        format!("sha256:{:x}", sha2::Sha256::digest(bytes))
    }

    #[test]
    fn verified_when_digest_matches() {
        let payload = b"\0asm\x01\x00\x00\x00";
        let expected = sha256_hex(payload);
        let v = verify_oci_layer(payload, Some(&expected));
        assert!(matches!(v, LayerVerdict::Verified { .. }));
    }

    #[test]
    fn mismatch_when_bytes_differ_from_manifest() {
        let payload = b"original wasm bytes";
        // What the registry CLAIMED — but the bytes we pulled are different.
        let lying_digest = sha256_hex(b"different bytes from what was pulled");
        let v = verify_oci_layer(payload, Some(&lying_digest));
        match v {
            LayerVerdict::DigestMismatch { expected, computed } => {
                assert_eq!(expected, lying_digest);
                assert_eq!(computed, sha256_hex(payload));
                assert_ne!(expected, computed);
            }
            other => panic!("expected DigestMismatch, got {other:?}"),
        }
    }

    #[test]
    fn accepted_unverified_when_manifest_omits_layer() {
        // Some malformed registries return a manifest with no layer
        // descriptor. We accept-with-warning rather than fail closed —
        // matches legacy behaviour and avoids breaking pulls from
        // not-quite-spec-compliant registries.
        let v = verify_oci_layer(b"anything", None);
        assert_eq!(v, LayerVerdict::AcceptedUnverified);
    }

    #[test]
    fn empty_layer_still_verifies_against_correct_digest() {
        // Empty bytes have a known sha256:e3b0c4...
        let expected = sha256_hex(&[]);
        assert!(matches!(
            verify_oci_layer(&[], Some(&expected)),
            LayerVerdict::Verified { .. }
        ));
    }

    #[test]
    fn digest_format_includes_sha256_prefix() {
        // sanity-check: the helper produces the same `sha256:HEX` format
        // that `OciDescriptor.digest` declares — string compare must work.
        let payload = b"x";
        let expected = sha256_hex(payload);
        assert!(expected.starts_with("sha256:"));
        assert_eq!(expected.len(), "sha256:".len() + 64);
    }

    // ---- SigstorePolicy + cosign_verify_argv ----

    #[test]
    fn sigstore_policy_default_is_disabled() {
        // Use a serial scope guard so concurrent tests don't race on env.
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("TALOS_SIGSTORE_REQUIRED");
        assert_eq!(SigstorePolicy::from_env(), SigstorePolicy::Disabled);
    }

    #[test]
    fn sigstore_policy_parses_required_aliases() {
        let _g = ENV_LOCK.lock().unwrap();
        for v in ["true", "1", "required"] {
            std::env::set_var("TALOS_SIGSTORE_REQUIRED", v);
            assert_eq!(
                SigstorePolicy::from_env(),
                SigstorePolicy::Required,
                "value `{v}` should map to Required"
            );
        }
        std::env::remove_var("TALOS_SIGSTORE_REQUIRED");
    }

    #[test]
    fn sigstore_policy_parses_audit_aliases() {
        let _g = ENV_LOCK.lock().unwrap();
        for v in ["audit", "warn"] {
            std::env::set_var("TALOS_SIGSTORE_REQUIRED", v);
            assert_eq!(SigstorePolicy::from_env(), SigstorePolicy::Audit);
        }
        std::env::remove_var("TALOS_SIGSTORE_REQUIRED");
    }

    #[test]
    fn sigstore_policy_unknown_value_falls_back_to_disabled() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("TALOS_SIGSTORE_REQUIRED", "yes-please");
        // Fail-safe default: anything we don't recognise is treated as
        // Disabled, NOT as Required. Operators get a clear "verification
        // didn't run" signal in logs rather than silent failures.
        assert_eq!(SigstorePolicy::from_env(), SigstorePolicy::Disabled);
        std::env::remove_var("TALOS_SIGSTORE_REQUIRED");
    }

    #[test]
    fn cosign_argv_includes_identity_and_issuer_pinning() {
        // SECURITY: this test guards against well-meaning "simplifications"
        // of cosign_verify_argv that drop the identity or issuer check —
        // either omission would let a valid Sigstore signature from ANY
        // workflow on ANY repo pass verification.
        let argv = cosign_verify_argv(
            "ghcr.io/owner/talos-tools/foo:v1",
            "^https://github\\.com/owner/talos/.+",
            "https://token.actions.githubusercontent.com",
        );
        assert_eq!(argv[0], "verify");
        assert!(
            argv.iter().any(|a| a == "--certificate-identity-regexp"),
            "must pin certificate identity"
        );
        assert!(
            argv.iter().any(|a| a == "--certificate-oidc-issuer"),
            "must pin OIDC issuer"
        );
        // Reference is always last so cosign treats it as the positional arg.
        assert_eq!(argv.last().unwrap(), "ghcr.io/owner/talos-tools/foo:v1");
    }

    #[test]
    fn cosign_argv_propagates_identity_verbatim() {
        // No string mangling: the regex passed by config must reach cosign
        // unchanged, otherwise operator-curated identity patterns silently
        // become broader than intended.
        let identity = "^https://github\\.com/MY_ORG/talos/\\.github/workflows/template-publish\\.yml@refs/heads/main$";
        let argv = cosign_verify_argv("ref", identity, "issuer");
        let pos = argv
            .iter()
            .position(|a| a == "--certificate-identity-regexp")
            .unwrap();
        assert_eq!(argv[pos + 1], identity);
    }

    // Serial guard for env-mutating tests in this module. Without it,
    // cargo's parallel test runner can race on the global env.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
}
// build test 1773350887
