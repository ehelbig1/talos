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

use crate::runtime::PipelineStepSpec;
use async_nats::Client;
use async_nats::Subscriber;
use futures_util::stream::StreamExt;
use job_protocol::{
    load_worker_shared_key, JobRequest, JobResult, JobStatus, PipelineJobRequest,
    PipelineJobResult, PipelineStepResult,
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};



mod audit;
mod bindings;
mod context;
mod host_impl;
mod metrics;
mod metrics_server;
mod runtime;
mod trace_nats;
mod tracing;
mod wit_inspector;

use crate::runtime::TalosRuntime;

/// Maximum concurrent single-node job executions
const MAX_CONCURRENT_JOBS: usize = 100;
/// Maximum concurrent pipeline job executions (heavier — multi-step)
const MAX_CONCURRENT_PIPELINE_JOBS: usize = 20;

// ============================================================================
// SECURITY: Static regex compilation — compiled exactly once at first use.
// Recompiling regexes on every call wastes CPU and can cause latency spikes.
// ============================================================================

static RE_UNIX_PATH: OnceLock<regex::Regex> = OnceLock::new();
static RE_WIN_PATH: OnceLock<regex::Regex> = OnceLock::new();
static RE_LINE_NUM: OnceLock<regex::Regex> = OnceLock::new();
static RE_INTERNAL_IP: OnceLock<regex::Regex> = OnceLock::new();

static OCI_CLIENT_HTTPS: OnceLock<tokio::sync::Mutex<oci_distribution::Client>> = OnceLock::new();
static OCI_CLIENT_HTTP: OnceLock<tokio::sync::Mutex<oci_distribution::Client>> = OnceLock::new();

fn get_oci_client(is_http: bool) -> &'static tokio::sync::Mutex<oci_distribution::Client> {
    if is_http {
        OCI_CLIENT_HTTP.get_or_init(|| {
            let client_config = oci_distribution::client::ClientConfig { protocol: oci_distribution::client::ClientProtocol::Http, ..Default::default() };
            tokio::sync::Mutex::new(oci_distribution::Client::new(client_config))
        })
    } else {
        OCI_CLIENT_HTTPS.get_or_init(|| {
            let client_config = oci_distribution::client::ClientConfig::default();
            tokio::sync::Mutex::new(oci_distribution::Client::new(client_config))
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
    RE_INTERNAL_IP.get_or_init(|| {
        regex::Regex::new(r"192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|127\.0\.0\.1")
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
                    println!("Published after {} retries", attempt);
                }
                return Ok(());
            }
            Err(e) => {
                if attempt < max_attempts - 1 {
                    eprintln!(
                        "Failed to publish to {} (attempt {}/{}): {}",
                        topic,
                        attempt + 1,
                        max_attempts,
                        e
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

/// Publish result to NATS with exponential backoff retry
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

    // If a reply topic is provided (via NATS request-reply), publish there.
    if let Some(reply) = reply_topic {
        publish_bytes_with_retry(nc, reply, payload.clone(), max_attempts).await?;
    }

    // Always publish to the global results topic for logging/audit purposes
    let result_topic = format!("talos.results.{}", result.job_id);
    publish_bytes_with_retry(nc, result_topic, payload, max_attempts).await
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
    shared_key: Arc<Vec<u8>>,
) -> JobResult {
    let start = std::time::Instant::now();

    // Create distributed tracing span
    let mut _span =
        tracing::ExecutionSpan::new_with_parent("job-execution", &req.job_id.to_string(), cx);
    _span.set_attribute("job_id", &req.job_id.to_string());
    _span.set_attribute("module_uri", &req.module_uri);

    // SECURITY: Verify HMAC-SHA256 signature + nonce freshness (300 s window).
    if let Err(e) = req.verify(&shared_key, 300) {
        eprintln!("Job signature verification failed: {}", e);
        _span.set_attribute("error", "signature_verification_failed");
        _span.end_error("Signature verification failed");

        return JobResult {
            job_id: req.job_id,
            status: JobStatus::Failed,
            output_payload: json!({"error": "signature verification failed"}),
            logs: vec![],
            execution_time_ms: start.elapsed().as_millis() as u64,
            signature: vec![],
            result_nonce: String::new(),
        };
    }

    // SECURITY: Decrypt secrets from the encrypted payload.
    let secrets: HashMap<String, String> = if req.encrypted_secrets.is_empty() {
        HashMap::new()
    } else {
        match req.encrypted_secrets.decrypt(&shared_key) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to decrypt job secrets: {}", e);
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

    // Load the Wasm module bytes
    _span.add_event("loading_module");
    let wasm_bytes = if let Some(bytes) = &req.wasm_bytes {
        // PERFORMANCE: Use bytes provided in job request (avoids file I/O)
        _span.set_attribute_int("module_size_bytes", bytes.len() as i64);
        _span.set_attribute("module_source", "job_request");
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
            let is_prod = std::env::var("RUST_ENV").unwrap_or_default() == "production";
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

            let client_mutex = get_oci_client(is_http);
            let client = client_mutex.lock().await;

            // In a production enterprise setting, these would be loaded from HashiCorp Vault or mounted Secrets
            let auth = if let (Ok(user), Ok(password)) = (
                std::env::var("OCI_REGISTRY_USERNAME"),
                std::env::var("OCI_REGISTRY_PASSWORD"),
            ) {
                RegistryAuth::Basic(user, password)
            } else {
                RegistryAuth::Anonymous
            };

            let accepted_media_types = vec!["application/vnd.wasm.content.layer.v1+wasm"];

            match client.pull(&reference, &auth, accepted_media_types).await {
                Ok(image) => {
                    // The WASM binary is typically the first layer in a Wasm OCI artifact
                    if let Some(layer) = image.layers.into_iter().next() {
                        found_bytes = Some(layer.data);
                        _span.add_event("oci_pull_success");
                    }
                }
                Err(e) => {
                    eprintln!(
                        "Failed to pull WASM artifact from OCI registry {}: {}",
                        req.module_uri, e
                    );
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

    // Build execution context for automatic logging to database
    _span.add_event("executing_wasm");
    let execution_context = Some((
        req.workflow_execution_id.to_string(), // workflow_id
        req.job_id.to_string(),                // execution_id (for NATS logging)
        req.module_uri.clone(),                // module_id
    ));

    // Default to 30s timeout if not specified (we can use 30s as a hard limit for individual jobs)
    match tokio::time::timeout(
        std::time::Duration::from_secs(30),
        runtime.execute_job_with_context(
            &wasm_bytes,
            req.allowed_hosts.clone(),
            req.allowed_methods.clone(),
            128,
            req.input_payload.clone(),
            None, // No custom file sandbox
            execution_context,
            secrets,
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
    shared_key: Arc<Vec<u8>>,
) -> PipelineJobResult {
    use job_protocol::JobStatus;

    let start = std::time::Instant::now();
    let mut _span = tracing::ExecutionSpan::new_with_parent(
        "pipeline-execution",
        &req.workflow_execution_id.to_string(),
        cx,
    );

    // SECURITY: Verify HMAC-SHA256 signature + nonce freshness (300 s window).
    if let Err(e) = req.verify(&shared_key, 300) {
        eprintln!("Pipeline job signature verification failed: {}", e);
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
    let max_timeout_ms = std::env::var("WASM_MAX_PIPELINE_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(3_600_000); // 1 hour default

    if req.total_timeout_ms > max_timeout_ms {
        eprintln!(
            "Pipeline job rejected: requested timeout ({}ms) exceeds maximum ({}ms)",
            req.total_timeout_ms, max_timeout_ms
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
            match step.encrypted_secrets.decrypt(&shared_key) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Failed to decrypt pipeline step secrets: {}", e);
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
        });
    }

    let overall_timeout = std::time::Duration::from_millis(req.total_timeout_ms);

    match runtime
        .execute_pipeline(
            &req.workflow_execution_id.to_string(),
            step_specs,
            overall_timeout,
            req.share_sandbox,
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
    println!("=== Talos Worker Starting ===\n");

    // ========================================================================
    // SECURITY: Load and validate the shared key at startup.
    // Fail-fast if the key is absent or malformed — never start with no auth.
    // ========================================================================

    let shared_key = Arc::new(
        load_worker_shared_key().map_err(|e| anyhow::anyhow!("WORKER_SHARED_KEY error: {}", e))?,
    );
    println!("[0/5] Loaded WORKER_SHARED_KEY (32 bytes)");

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

    // ========================================================================
    // NATS CONNECTION
    // ========================================================================

    println!("\n[2/5] Connecting to NATS...");
    let nats_url =
        std::env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string());

    // SECURITY: Use authenticated connection when NATS_USER + NATS_PASSWORD are set.
    let nats_user = std::env::var("NATS_USER").ok();
    let nats_password = std::env::var("NATS_PASSWORD").ok();

    let nc: Client = match (nats_user, nats_password) {
        (Some(user), Some(pass)) => {
            match async_nats::ConnectOptions::new()
                .user_and_password(user, pass)
                .connect(&nats_url)
                .await
            {
                Ok(c) => {
                    println!("      Connected to NATS (authenticated) at {}", nats_url);
                    c
                }
                Err(e) => {
                    eprintln!("Failed to connect to NATS at {}: {}", nats_url, e);
                    eprintln!("   Check NATS_USER/NATS_PASSWORD credentials.");
                    return Err(anyhow::anyhow!(e));
                }
            }
        }
        _ => match async_nats::connect(&nats_url).await {
            Ok(c) => {
                println!("      Connected to NATS at {}", nats_url);
                c
            }
            Err(e) => {
                eprintln!("Failed to connect to NATS at {}: {}", nats_url, e);
                eprintln!("   Make sure a NATS server is running.");
                return Err(anyhow::anyhow!(e));
            }
        },
    };

    // Retrieve configurable NATS queue topics or use defaults.
    // This enables per-customer VPC "Edge Node" routing.
    let single_job_topic =
        std::env::var("NATS_JOB_TOPIC").unwrap_or_else(|_| "talos.jobs".to_string());
    let pipeline_job_topic =
        std::env::var("NATS_PIPELINE_TOPIC").unwrap_or_else(|_| "talos.pipeline.jobs".to_string());
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

    println!("\n[3/5] Creating WASM runtime...");
    let runtime = Arc::new(TalosRuntime::with_resources(
        redis_client.clone(),       // Redis client for WASM fetching and caching
        Some(Arc::new(nc.clone())), // NATS client for WASM log publishing
        None,                       // Postgres pool
        None,                       // No file system sandbox for now
    )?);
    println!("      Runtime created with NATS logging enabled");

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

                            let req: JobRequest = match serde_json::from_slice(&msg.payload) {
                                Ok(r) => r,
                                Err(e) => {
                                    eprintln!("Failed to decode job request: {}", e);
                                    continue;
                                }
                            };

                            println!("Received job: {} (module: {})", req.job_id, req.module_uri);

                            let nc_clone = single_nc.clone();
                            let runtime_clone = single_runtime.clone();
                            let key_clone = single_key.clone();
                            let reply_to = msg.reply.map(|r: async_nats::Subject| r.to_string());

                            tokio::task::spawn(async move {
                                let mut result = execute_job(&cx, req.clone(), runtime_clone, key_clone.clone()).await;

                                if let Err(e) = result.sign(&key_clone) {
                                    eprintln!("CRITICAL: Failed to sign job result for {}: {}", result.job_id, e);
                                }

                                match result.status {
                                    JobStatus::Success => {
                                        println!("Job completed: {} ({}ms)",
                                            result.job_id, result.execution_time_ms);
                                    }
                                    JobStatus::Failed => {
                                        eprintln!("Job failed: {} ({}ms) - {:?}",
                                            result.job_id, result.execution_time_ms, result.output_payload);
                                    }
                                    _ => {}
                                }

                                if let Err(e) = publish_result_with_retry(&nc_clone, &result, 3, reply_to).await {
                                    eprintln!("CRITICAL: Failed to publish job result: {}", e);
                                    eprintln!("   Job ID: {}", result.job_id);
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

                            let req: PipelineJobRequest = match serde_json::from_slice(&msg.payload) {
                                Ok(r) => r,
                                Err(e) => {
                                    eprintln!("Failed to decode pipeline job request: {}", e);
                                    continue;
                                }
                            };

                            println!(
                                "Received pipeline job: {} ({} steps)",
                                req.job_id,
                                req.steps.len()
                            );

                            let nc_clone = pipe_nc.clone();
                            let runtime_clone = pipe_runtime.clone();
                            let key_clone = pipe_key.clone();
                            let reply_to = msg.reply.clone().map(|r: async_nats::Subject| r.to_string());

                            tokio::task::spawn(async move {
                                let mut result =
                                    execute_pipeline_job(&cx, req.clone(), runtime_clone, key_clone.clone()).await;

                                if let Err(e) = result.sign(&key_clone) {
                                    eprintln!(
                                        "CRITICAL: Failed to sign pipeline result for {}: {}",
                                        result.job_id, e
                                    );
                                }

                                match result.overall_status {
                                    JobStatus::Success => {
                                        println!(
                                            "Pipeline completed: {} ({}ms, {} steps)",
                                            result.job_id,
                                            result.total_time_ms,
                                            result.step_results.len()
                                        );
                                    }
                                    JobStatus::Failed => {
                                        eprintln!(
                                            "Pipeline failed: {} ({}ms) - {:?}",
                                            result.job_id,
                                            result.total_time_ms,
                                            result.final_output
                                        );
                                    }
                                    _ => {}
                                }

                                let payload_vec = serde_json::to_vec(&result).unwrap_or_default();
                                let payload = bytes::Bytes::from(payload_vec);
                                if let Some(reply) = reply_to {
                                    if let Err(e) = publish_bytes_with_retry(&nc_clone, reply, payload.clone(), 3).await {
                                        eprintln!("CRITICAL: Failed to publish to reply topic: {}", e);
                                    }
                                }

                                let result_topic = format!("talos.pipeline.results.{}", result.job_id);
                                if let Err(e) = publish_bytes_with_retry(&nc_clone, result_topic, payload, 3).await {
                                    eprintln!("CRITICAL: {}", e);
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
        _ = tokio::signal::ctrl_c() => {
            println!("\nShutdown signal received");
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
    let start = std::time::Instant::now();

    while semaphore.available_permits() < MAX_CONCURRENT_JOBS
        || pipeline_semaphore.available_permits() < MAX_CONCURRENT_PIPELINE_JOBS
    {
        if start.elapsed() > shutdown_timeout {
            eprintln!("Shutdown timeout — some jobs may not have completed");
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
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
