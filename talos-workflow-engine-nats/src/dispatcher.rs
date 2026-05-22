//! [`NodeDispatcher`] implementation backed by a signed-NATS job
//! protocol (`talos_workflow_job_protocol::JobRequest` + HMAC signing).
//!
//! Takes a [`DispatchJob`] from the engine, builds a signed
//! `JobRequest`, serializes it, publishes to the right priority
//! subject, and runs the engine's retry loop (including `node_retrying`
//! / `retry_skipped` event emission) until a `JobResult` comes back —
//! then unwraps it into a [`DispatchResult`] the engine can consume.
//!
//! This adapter is where every NATS-specific detail of dispatch lives:
//! wire-format version of the `JobRequest` struct, the HMAC signing
//! algorithm, the topic convention, the result-signature verification,
//! etc.

use std::sync::Arc;

use async_trait::async_trait;
use talos_workflow_engine::emit_event_spawn;
use talos_workflow_engine_core::{
    BoxError, ChainDispatchRequest, ChainDispatchResult, ChainStepResult, DispatchJob,
    DispatchResult, EventSink, ExpressionEvaluator, JobTransport, NodeDispatcher, NodeEventWrite,
    RetryClassifier, StepStatus, WorkerSharedKey,
};
use talos_workflow_job_protocol::{
    EncryptedSecrets, JobRequest, JobResult, JobStatus, PipelineJobRequest, PipelineJobResult,
    PipelineStep,
};
use uuid::Uuid;

// NATS edge routing helpers.
// `priority` enables topic-level priority lanes: jobs with priority >= 200
// are routed to a dedicated `.priority` sub-topic so workers can subscribe
// to high-priority work first.

/// Subject prefix used for job + pipeline subjects.
///
/// Defaults to `"workflow"`, producing `workflow.jobs[.<user>][.priority]`
/// and `workflow.pipeline.jobs[...]`. Override via the
/// `WORKFLOW_NATS_PREFIX` env var when deploying alongside an existing
/// worker pool that subscribes to a different prefix (e.g. set it to
/// a product-specific value in that product's process environment).
/// Read once at process start via [`std::sync::LazyLock`] — changing
/// the env var after boot has no effect.
static SUBJECT_PREFIX: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    std::env::var("WORKFLOW_NATS_PREFIX").unwrap_or_else(|_| "workflow".to_string())
});

fn edge_routing_enabled() -> bool {
    std::env::var("ENABLE_EDGE_ROUTING").as_deref() == Ok("true")
}

pub(crate) fn get_single_job_topic(user_id: Option<Uuid>, priority: u8) -> String {
    let prefix = SUBJECT_PREFIX.as_str();
    let base = if edge_routing_enabled() {
        if let Some(uid) = user_id {
            format!("{prefix}.jobs.{uid}")
        } else {
            format!("{prefix}.jobs")
        }
    } else {
        format!("{prefix}.jobs")
    };
    if priority >= 200 {
        format!("{base}.priority")
    } else {
        base
    }
}

pub(crate) fn get_pipeline_job_topic(user_id: Option<Uuid>, priority: u8) -> String {
    let prefix = SUBJECT_PREFIX.as_str();
    let base = if edge_routing_enabled() {
        if let Some(uid) = user_id {
            format!("{prefix}.pipeline.jobs.{uid}")
        } else {
            format!("{prefix}.pipeline.jobs")
        }
    } else {
        format!("{prefix}.pipeline.jobs")
    };
    if priority >= 200 {
        format!("{base}.priority")
    } else {
        base
    }
}

/// H-1: route the outbound request through the inbox-aware
/// transport method when an inbox was pre-allocated, falling back
/// to the legacy `request` path otherwise. Keeps the retry-loop
/// call sites tidy (one helper instead of an `if`/`else` inlined
/// inside the timeout wrapper).
async fn send_with_optional_inbox(
    transport: &dyn JobTransport,
    topic: &str,
    reply_inbox: Option<&str>,
    payload: Vec<u8>,
) -> Result<Vec<u8>, talos_workflow_engine_core::BoxError> {
    match reply_inbox {
        Some(inbox) => transport.request_with_reply_inbox(topic, inbox, payload).await,
        None => transport.request(topic, payload).await,
    }
}

/// Dispatch a NATS request with retry and exponential backoff.
///
/// Retries both NATS delivery errors and application-level job failures.
/// Timeouts are **not** retried because they indicate the job ran but took too long.
///
/// MCP-1212: when `pipeline_resign_key` is provided, the payload is
/// deserialized as a `PipelineJobRequest`, re-signed with a fresh
/// nonce, and re-serialized before each retry. Without this, every
/// retry re-sends the same `job_nonce` and the worker's nonce cache
/// rejects it as replay (see `execute_job_with_retry` for the same
/// fix on the single-node path).
pub(crate) async fn dispatch_with_retry(
    transport: &dyn JobTransport,
    topic: String,
    payload: Vec<u8>,
    timeout_secs: u64,
    max_retries: u32,
    base_backoff_ms: u64,
    pipeline_resign_key: Option<&[u8]>,
    // H-1: when `Some(inbox)`, every transport.request goes through
    // the inbox-aware path so the wire `msg.reply` matches the
    // HMAC-bound `reply_topic` in the JobRequest. When `None`, falls
    // back to the legacy unsigned-reply path for transports that
    // don't pre-allocate inboxes (in-process test stubs, etc.).
    reply_inbox: Option<String>,
) -> Result<Vec<u8>, String> {
    let mut attempts: u32 = 0;
    let mut current_payload = payload;
    loop {
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            send_with_optional_inbox(
                transport,
                &topic,
                reply_inbox.as_deref(),
                current_payload.clone(),
            ),
        )
        .await;

        match result {
            Ok(Ok(response)) => return Ok(response),
            Ok(Err(e)) => {
                attempts += 1;
                if attempts > max_retries {
                    return Err(format!(
                        "Job dispatch failed after {} attempts: {}",
                        attempts, e
                    ));
                }
                let backoff = base_backoff_ms.saturating_mul(2u64.pow(attempts - 1));
                // Add jitter (up to 25% of backoff) using system time nanos to
                // avoid pulling in an extra RNG dependency.
                let jitter = backoff / 4;
                let jitter_val = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .subsec_nanos() as u64
                    % jitter.max(1);
                let delay = backoff + jitter_val;
                tracing::warn!(
                    attempt = attempts,
                    max_retries,
                    backoff_ms = delay,
                    "Job dispatch failed, retrying: {}",
                    e
                );
                // MCP-1212: re-sign with a fresh nonce before retrying so
                // the worker's nonce cache doesn't reject the retry as
                // replay. See `execute_job_with_retry`.
                if let Some(key) = pipeline_resign_key {
                    current_payload =
                        resign_pipeline_payload_for_retry(&current_payload, key)
                            .unwrap_or(current_payload);
                }
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            }
            Err(_timeout) => {
                // Timeouts are NOT retried – they indicate the job ran but took too long.
                return Err("Job execution timed out".to_string());
            }
        }
    }
}

/// MCP-1212: pipeline-path sibling of `resign_payload_for_retry`. Same
/// shape, different concrete type. Returns None on parse/sign/serialize
/// failure; caller falls back to the original payload.
fn resign_pipeline_payload_for_retry(payload: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    let mut req: PipelineJobRequest = match serde_json::from_slice(payload) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "resign_pipeline_payload_for_retry: failed to deserialize \
                 PipelineJobRequest; falling back to original payload"
            );
            return None;
        }
    };
    if let Err(e) = req.sign(key) {
        tracing::warn!(
            error = %e,
            job_id = %req.job_id,
            "resign_pipeline_payload_for_retry: re-sign failed"
        );
        return None;
    }
    match serde_json::to_vec(&req) {
        Ok(bytes) => Some(bytes),
        Err(e) => {
            tracing::warn!(
                error = %e,
                job_id = %req.job_id,
                "resign_pipeline_payload_for_retry: re-serialize failed"
            );
            None
        }
    }
}

/// Execute a job via NATS with full retry logic for both transport and application errors.
///
/// Retries on:
/// - NATS delivery failures (connection issues)
/// - Application-level job failures (WASM module returns error)
///
/// Does NOT retry:
/// - Timeouts (job ran but took too long)
/// - Signature verification failures (security issue)
/// - Serialization errors (deterministic failures)
#[allow(clippy::too_many_arguments)]
pub(crate) async fn execute_job_with_retry(
    transport: &dyn JobTransport,
    topic: String,
    payload: Vec<u8>,
    timeout_secs: u64,
    max_retries: u32,
    base_backoff_ms: u64,
    worker_shared_key: Option<&[u8]>,
    retry_condition: Option<&str>,
    retry_delay_expr: Option<&str>,
    // Optional event tracking: when provided, a `node_retrying` / `retry_skipped`
    // event is emitted per retry so that `retries_attempted` (= start_count - 1)
    // remains accurate in observers. Taken by value; `Arc<dyn EventSink>`
    // clone is ~4ns per call and retry is not a hot path, so the saved
    // refcount bump does not justify a `None`-awkward `&Option` param.
    event_sink: Option<Arc<dyn EventSink>>,
    event_execution_id: Uuid,
    event_node_id: Uuid,
    // Policy traits: the retry classifier decides transient-vs-permanent on
    // unconditional failures, and the expression evaluator evaluates
    // `retry_condition` / `retry_delay_expression` strings. Both are
    // `&dyn` so the dispatcher owns shared `Arc`s internally and only
    // passes references into the loop.
    retry_classifier: &dyn RetryClassifier,
    expression_evaluator: &dyn ExpressionEvaluator,
    // H-1: see `dispatch_with_retry` for the contract.
    reply_inbox: Option<String>,
) -> Result<serde_json::Value, String> {
    let mut attempts: u32 = 0;
    let mut current_payload = payload;
    loop {
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            send_with_optional_inbox(
                transport,
                &topic,
                reply_inbox.as_deref(),
                current_payload.clone(),
            ),
        )
        .await;

        match result {
            Ok(Ok(response)) => {
                // Parse job result
                let job_result: JobResult = serde_json::from_slice(&response)
                    .map_err(|e| format!("Failed to parse job result: {}", e))?;

                // Verify signature if worker key is available.
                // L-4: typed Primary verifier — this dispatcher is the
                // sole inline consumer of the reply on this inbox, and
                // it converts the result into the engine's durable
                // side effect. Any audit observer subscribing to a
                // separate `talos.results.*` topic uses
                // `Verifier::Observer` (see controller/src/main.rs).
                if let Some(key) = worker_shared_key {
                    if let Err(e) = job_result.verify_as(
                        key,
                        300,
                        talos_workflow_job_protocol::Verifier::Primary,
                    ) {
                        return Err(format!("Job result signature verification failed: {}", e));
                    }
                    // L-11 (2026-05-22): record the worker_id committed to
                    // by the signed result. `worker_id` is the
                    // self-reported identity of the worker process that
                    // produced this result (HMAC-bound by
                    // `sign_with_worker_id`). Logging it here gives
                    // operators forensic attribution per job — if a
                    // result is malformed or anomalous, the worker pod
                    // is identifiable in the audit trail.
                    //
                    // Empty `worker_id` indicates a pre-L-11 worker or a
                    // test fixture; that's expected during deployment
                    // rollouts and is not an error.
                    if !job_result.worker_id.is_empty() {
                        tracing::debug!(
                            target: "talos_job_audit",
                            job_id = %job_result.job_id,
                            worker_id = %job_result.worker_id,
                            "JobResult verified — worker attribution recorded"
                        );
                    }
                }

                // Check both job-level status AND payload-level success field.
                // WASM modules like database-query return JobStatus::Success but
                // include {"success": false, "error": "..."} in the payload when
                // the query itself fails. We treat payload success:false as a
                // retryable application error.
                let payload_success_false = job_result
                    .output_payload
                    .get("success")
                    .and_then(|v| v.as_bool())
                    == Some(false);

                let is_success =
                    matches!(job_result.status, JobStatus::Success) && !payload_success_false;

                if is_success {
                    return Ok(job_result.output_payload);
                } else {
                    // Application-level failure — check retry_condition before retrying.
                    // Default to retry (true) on evaluation error: retry_condition is meant to
                    // BLOCK retrying in known-permanent-error scenarios. If the condition can't
                    // evaluate (e.g. the referenced variable isn't in the error payload), the
                    // safer default is to let the retry happen rather than silently dropping it.
                    if let Some(cond) = retry_condition {
                        let should_retry = expression_evaluator
                            .try_eval_bool(cond, &job_result.output_payload)
                            .unwrap_or(true);
                        if !should_retry {
                            let err_msg = job_result
                                .output_payload
                                .get("error")
                                .and_then(|e| e.as_str())
                                .map(String::from)
                                .unwrap_or_else(|| job_result.output_payload.to_string());
                            tracing::info!(
                                retry_condition = cond,
                                "Retry condition evaluated to false — skipping retries"
                            );
                            return Err(format!(
                                "Job failed (retry_condition not met): {}",
                                err_msg
                            ));
                        }
                    }

                    // Smart retry default: when no explicit retry_condition is set,
                    // classify the error and skip retries for non-transient failures
                    // (auth errors, fuel exhaustion, missing secrets, etc.).
                    if retry_condition.is_none() && max_retries > 0 {
                        let err_for_classify = job_result
                            .output_payload
                            .get("error")
                            .and_then(|e| e.as_str())
                            .unwrap_or("");
                        let classification = retry_classifier.classify(err_for_classify);
                        if !retry_classifier.is_transient(&classification) {
                            tracing::info!(
                                error_type = %classification,
                                "Non-transient error classified — skipping retries \
                                 (no retry_condition configured)"
                            );
                            emit_event_spawn(
                                &event_sink,
                                NodeEventWrite {
                                    execution_id: event_execution_id,
                                    event_type: "retry_skipped".to_string(),
                                    node_id: Some(event_node_id),
                                    status: "Failed".to_string(),
                                    log_message: Some(format!(
                                        "Retry skipped: error classified as '{}' (non-transient)",
                                        classification
                                    )),
                                    iteration_index: None,
                                    error_class: Some(classification.clone()),
                                },
                            );
                            return Err(format!(
                                "Job failed (non-transient: {}): {}",
                                classification, err_for_classify
                            ));
                        }
                    }

                    attempts += 1;
                    if attempts > max_retries {
                        let err_msg = job_result
                            .output_payload
                            .get("error")
                            .and_then(|e| e.as_str())
                            .map(String::from)
                            .unwrap_or_else(|| job_result.output_payload.to_string());
                        // MCP-1212 (2026-05-18): include the failure
                        // payload's `diag` object (when present) in the
                        // returned error so operators can identify the
                        // diverged field from `get_execution_status`
                        // without pod-shell access. The worker's
                        // signature-verification-failure path enriches
                        // output_payload.diag with worker-side hashes;
                        // pre-fix this path only kept the opaque
                        // "error" string and threw the diag away.
                        let diag_suffix = match job_result.output_payload.get("diag") {
                            Some(d) => format!(" | diag: {}", d),
                            None => String::new(),
                        };
                        return Err(format!(
                            "Job failed after {} attempts: {}{}",
                            attempts, err_msg, diag_suffix
                        ));
                    }

                    // Compute delay: try retry_delay_expression first, fall back to exponential backoff
                    let delay = if let Some(expr) = retry_delay_expr {
                        match expression_evaluator.eval_i64(expr, &job_result.output_payload) {
                            Some(ms) if ms > 0 => (ms as u64).min(60_000),
                            _ => {
                                let backoff =
                                    base_backoff_ms.saturating_mul(2u64.pow(attempts - 1));
                                let jitter = backoff / 4;
                                let jitter_val = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .subsec_nanos()
                                    as u64
                                    % jitter.max(1);
                                backoff + jitter_val
                            }
                        }
                    } else {
                        let backoff = base_backoff_ms.saturating_mul(2u64.pow(attempts - 1));
                        let jitter = backoff / 4;
                        let jitter_val = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .subsec_nanos() as u64
                            % jitter.max(1);
                        backoff + jitter_val
                    };

                    let err_msg = job_result
                        .output_payload
                        .get("error")
                        .and_then(|e| e.as_str())
                        .unwrap_or("unknown error");
                    tracing::warn!(
                        attempt = attempts,
                        max_retries,
                        backoff_ms = delay,
                        "Job execution failed, retrying: {}",
                        err_msg
                    );
                    // Emit a `node_retrying` event (distinct from `node_started`)
                    // so observers can tell retry attempts apart from initial
                    // starts or fan-out parallel starts.  The attempt number is
                    // stored in `iteration_index` (1 = first retry, 2 = second,
                    // …) and in `log_message` for human readers.
                    // `retries_attempted` in get_execution_trace counts
                    // `node_retrying` rows, not `node_started` rows.
                    let retry_num = attempts as i32; // 1-based: attempts was just incremented
                    emit_event_spawn(
                        &event_sink,
                        NodeEventWrite {
                            execution_id: event_execution_id,
                            event_type: "node_retrying".to_string(),
                            node_id: Some(event_node_id),
                            status: "Running".to_string(),
                            log_message: Some(format!("Retry attempt {}", retry_num)),
                            iteration_index: Some(retry_num),
                            error_class: None,
                        },
                    );
                    // MCP-1212 (2026-05-18): re-sign the payload BEFORE
                    // sleeping into the next retry. Pre-fix every retry
                    // re-sent the SAME signed bytes (same job_nonce). The
                    // worker's first attempt succeeded at signature verify
                    // and inserted the nonce into JOB_NONCE_CACHE; the
                    // retry then deterministically failed with
                    // "job_nonce already seen (replay attempt within
                    // 300-second window)" which masqueraded in the final
                    // error as "signature verification failed" — hiding
                    // the original attempt-1 failure (typically a
                    // transient LLM/network issue). Re-signing generates
                    // a fresh nonce + signature so the retry is a NEW
                    // signed message from the cache's perspective. No
                    // security impact: a fresh nonce + valid HMAC is
                    // exactly what a non-retry dispatch would produce.
                    if let Some(key) = worker_shared_key {
                        current_payload =
                            resign_payload_for_retry(&current_payload, key)
                                .unwrap_or(current_payload);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                }
            }
            Ok(Err(e)) => {
                // NATS delivery failure — retry
                attempts += 1;
                if attempts > max_retries {
                    return Err(format!(
                        "Job dispatch failed after {} attempts: {}",
                        attempts, e
                    ));
                }
                let backoff = base_backoff_ms.saturating_mul(2u64.pow(attempts - 1));
                let jitter_val = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .subsec_nanos() as u64
                    % (backoff / 4).max(1);
                let delay = backoff + jitter_val;
                tracing::warn!(
                    attempt = attempts,
                    max_retries,
                    backoff_ms = delay,
                    "NATS dispatch failed, retrying: {}",
                    e
                );
                // Re-sign on NATS-dispatch-failure retries too — same
                // rationale as the application-error retry path above.
                // NATS delivery failure means the worker may or may not
                // have seen the original payload (e.g. ack-lost-on-the-
                // wire). Fresh nonce protects against the partial-delivery
                // edge case where the worker did receive it and cached
                // the nonce before the controller's request timed out.
                if let Some(key) = worker_shared_key {
                    current_payload =
                        resign_payload_for_retry(&current_payload, key)
                            .unwrap_or(current_payload);
                }
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            }
            Err(_timeout) => {
                return Err("Job execution timed out".to_string());
            }
        }
    }
}

/// MCP-1212: deserialize a signed JobRequest payload, re-sign it with a
/// fresh nonce, re-serialize. Used by the retry path to prevent
/// nonce-replay rejection on retries. Returns None on parse/sign/serialize
/// failure — caller falls back to the original payload (the worst case
/// is the pre-fix behavior: retry deterministically fails nonce-replay,
/// no worse than before). Cheap: serde_json over a JobRequest is fast
/// and retries are not on the hot path.
fn resign_payload_for_retry(payload: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    let mut req: JobRequest = match serde_json::from_slice(payload) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "resign_payload_for_retry: failed to deserialize JobRequest for re-sign; \
                 falling back to original payload (retry will likely fail nonce-replay)"
            );
            return None;
        }
    };
    if let Err(e) = req.sign(key) {
        tracing::warn!(
            error = %e,
            job_id = %req.job_id,
            "resign_payload_for_retry: re-sign failed; falling back to original payload"
        );
        return None;
    }
    match serde_json::to_vec(&req) {
        Ok(bytes) => Some(bytes),
        Err(e) => {
            tracing::warn!(
                error = %e,
                job_id = %req.job_id,
                "resign_payload_for_retry: re-serialize failed; falling back to original payload"
            );
            None
        }
    }
}

/// Dispatches workflow nodes via a signed-NATS job protocol.
///
/// Built once per engine run from `(transport, event_sink,
/// worker_shared_key)`. Holding an `Arc` of each collaborator keeps
/// per-node dispatch cheap (single refcount bump).
pub struct NatsNodeDispatcher {
    transport: Arc<dyn JobTransport>,
    event_sink: Option<Arc<dyn EventSink>>,
    /// Shared key used for both HMAC signing of the request and
    /// verification of the response. `None` disables signing — used by
    /// test harnesses that don't need the round-trip.
    worker_shared_key: Option<WorkerSharedKey>,
    /// Policy trait for classifying dispatch errors into
    /// transient-vs-permanent. Drives the "smart retry default" path
    /// (skip retries on auth / fuel / missing-secret errors even when
    /// `max_retries > 0`).
    retry_classifier: Arc<dyn RetryClassifier>,
    /// Policy trait for evaluating `retry_condition` / `retry_delay_expression`
    /// expressions against the error payload. Wraps the sandboxed
    /// `rhai::Engine` in production; tests plug in their own impl.
    expression_evaluator: Arc<dyn ExpressionEvaluator>,
}

impl NatsNodeDispatcher {
    /// Build a dispatcher. `event_sink` may be `None` when there's no
    /// execution-event persistence configured; `worker_shared_key` may
    /// be `None` in test harnesses. `retry_classifier` and
    /// `expression_evaluator` are required — they drive the retry loop's
    /// classification + expression-evaluation decisions and have no
    /// sensible no-op fallback (a dispatcher that classifies every
    /// error as "transient" would retry forever on hard failures).
    #[must_use]
    pub fn new(
        transport: Arc<dyn JobTransport>,
        event_sink: Option<Arc<dyn EventSink>>,
        worker_shared_key: Option<WorkerSharedKey>,
        retry_classifier: Arc<dyn RetryClassifier>,
        expression_evaluator: Arc<dyn ExpressionEvaluator>,
    ) -> Self {
        Self {
            transport,
            event_sink,
            worker_shared_key,
            retry_classifier,
            expression_evaluator,
        }
    }
}

impl std::fmt::Debug for NatsNodeDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `WorkerSharedKey`'s own `Debug` impl is redacted; forwarding to
        // it keeps the "never log raw key bytes" invariant in one place.
        f.debug_struct("NatsNodeDispatcher")
            .field("worker_shared_key", &self.worker_shared_key)
            .finish_non_exhaustive()
    }
}

/// Slack added to the Tokio-outer retry timeout so the worker-side
/// sandbox can finish gracefully before the outer timer cancels the
/// request. The wire-format `timeout_ms` stays at the bare
/// `DispatchJob::timeout` — only the cancellation wrap around
/// `execute_job_with_retry` gets this extra grace.
const TOKIO_WRAP_GRACE_SECS: u64 = 5;

#[async_trait]
impl NodeDispatcher for NatsNodeDispatcher {
    async fn dispatch(&self, job: DispatchJob) -> Result<DispatchResult, BoxError> {
        // Zero-timeout sanity check: combined with the outer grace this
        // would surface as "cancel after ~5 s" for every job, which is
        // almost certainly not what the caller intended. `DispatchJob`'s
        // `Default` ships a positive budget; a zero value here is either
        // a manual misconfiguration or an old caller that predates the
        // default fix.
        if job.timeout.is_zero() {
            tracing::warn!(
                execution_id = %job.execution_id,
                node_id = %job.node_id,
                "DispatchJob::timeout is zero — jobs will cancel under the dispatcher's grace window. \
                 Set `timeout` explicitly or use `DispatchJob::default()` for a 60 s budget."
            );
        }

        // H-1: pre-allocate a reply inbox so we can bind it into the
        // signed `JobRequest::reply_topic`. NatsTransport returns
        // `Some(inbox)`; test transports / non-NATS impls return
        // `None`, in which case we fall back to the legacy
        // trust-msg.reply path. Doing this BEFORE signing is the
        // whole point — once signed, the worker can verify wire
        // `msg.reply` against the HMAC-protected value.
        let reply_inbox = self.transport.new_reply_inbox();

        // 1. Assemble the wire-format `JobRequest`.
        let mut req = JobRequest {
            // Reuse a caller-supplied job id when present so a
            // pre-INSERTed `module_executions` row with that id stays
            // correlated with the worker's update. Fresh UUID
            // otherwise.
            job_id: job.job_id.unwrap_or_else(uuid::Uuid::new_v4),
            workflow_execution_id: job.execution_id,
            module_uri: job.module_uri,
            input_payload: job.input_payload,
            encrypted_secrets: EncryptedSecrets {
                ciphertext: job.encrypted_secrets_ciphertext,
                nonce: job.encrypted_secrets_nonce,
            },
            timeout_ms: job.timeout.as_millis() as u64,
            priority: job.priority,
            deadline_unix_secs: 0,
            cancellation_token: None,
            allowed_hosts: job.allowed_hosts,
            allowed_methods: job.allowed_methods,
            allowed_secrets: job.allowed_secrets,
            allowed_sql_operations: job.allowed_sql_operations,
            allow_tier2_exposure: job.allow_tier2_exposure,
            signature: vec![],
            job_nonce: String::new(),
            actor_id: job.actor_id,
            wasm_bytes: job.wasm_bytes,
            capability_world: job.capability_world,
            integration_name: job.integration_name,
            expected_wasm_hash: job.expected_wasm_hash,
            max_fuel: job.max_fuel,
            dry_run: job.dry_run,
            // Wire format uses `Uuid::nil()` as the "no user context"
            // sentinel. The trait surface uses `Option<Uuid>`; translate
            // at the boundary so the engine-side API is explicit while
            // preserving wire compat with existing workers.
            user_id: job.user_id.unwrap_or_else(uuid::Uuid::nil),
            max_llm_tier: job.max_llm_tier,
            // H-1: stamp the pre-allocated inbox into the request
            // BEFORE signing. The worker will verify wire
            // `msg.reply == req.reply_topic` and refuse to publish
            // results to anything else.
            reply_topic: reply_inbox.clone(),
        };

        // 2. Sign.
        if let Some(key) = self.worker_shared_key.as_ref() {
            req.sign(key.as_bytes())
                .map_err(|e| -> BoxError { format!("Failed to sign job request: {e}").into() })?;
        }

        // MCP-1212 (2026-05-18): controller-side signature diagnostic.
        // Emits the per-field hashes / lengths consumed by `signing_payload()`
        // at WARN level so operators investigating a worker-side
        // "signature verification failed" can grep their controller logs
        // for the same job_id and diff field-by-field against the worker's
        // enriched failure JobResult.output_payload (see worker/src/main.rs
        // verify-fail branch). WARN is loud enough to bypass default
        // RUST_LOG=info filtering. Only fires when worker_shared_key is
        // configured — dev installs without a key produce no diag.
        // `diag_hashes()` is colocated with `signing_payload()` in
        // job-protocol so the field formulas stay in sync.
        {
            let (controller_input_hash, controller_secrets_hash, controller_input_byte_len) =
                req.diag_hashes();
            tracing::warn!(
                target: "signature_diag",
                job_id = %req.job_id,
                workflow_execution_id = %req.workflow_execution_id,
                module_uri = %req.module_uri,
                controller_input_hash = %controller_input_hash,
                controller_secrets_hash = %controller_secrets_hash,
                controller_input_byte_len,
                signature_byte_len = req.signature.len(),
                job_nonce = %req.job_nonce,
                actor_id = ?req.actor_id,
                user_id = %req.user_id,
                "signature_diag: controller-side signed-field snapshot"
            );
        }

        // 3. Serialize.
        let payload = serde_json::to_vec(&req)
            .map_err(|e| -> BoxError { format!("Failed to serialize job request: {e}").into() })?;

        // 4. Topic. A `None` user_id stays on the tenant-agnostic
        // `workflow.jobs` subject instead of being sent to
        // `workflow.jobs.00000000-...` — which no worker subscribes to
        // under `ENABLE_EDGE_ROUTING=true`.
        let topic = get_single_job_topic(job.user_id, req.priority);

        // 5. Retry loop + result verification + event emission.
        // `execute_job_with_retry` owns the outer cancellation wrap,
        // retry classification, backoff+jitter, result signature
        // verification, and `node_retrying` / `retry_skipped`
        // emission. The outer wrap gets `TOKIO_WRAP_GRACE_SECS` of
        // slack over the wire-format WASM budget.
        let event_sink = if job.emit_retry_events {
            self.event_sink.clone()
        } else {
            None
        };
        let output = execute_job_with_retry(
            self.transport.as_ref(),
            topic,
            payload,
            job.timeout.as_secs() + TOKIO_WRAP_GRACE_SECS,
            job.max_retries,
            job.backoff_ms,
            self.worker_shared_key
                .as_ref()
                .map(WorkerSharedKey::as_bytes),
            job.retry_condition.as_deref(),
            job.retry_delay_expr.as_deref(),
            event_sink,
            job.execution_id,
            job.node_id,
            self.retry_classifier.as_ref(),
            self.expression_evaluator.as_ref(),
            // H-1: thread the signed reply inbox down so the retry
            // loop publishes via `request_with_reply_inbox` instead
            // of the unsigned-reply `request`.
            reply_inbox,
        )
        .await
        .map_err(|e| -> BoxError { e.into() })?;

        Ok(DispatchResult { output })
    }

    async fn dispatch_chain(
        &self,
        request: ChainDispatchRequest,
    ) -> Result<ChainDispatchResult, BoxError> {
        // 1. Map `DispatchJob`s into wire-format `PipelineStep`s. The
        // step shape is a strict subset of JobRequest's per-node fields
        // (no per-step user/actor/dry_run — those are chain-level).
        let steps: Vec<PipelineStep> = request
            .steps
            .iter()
            .map(|job| PipelineStep {
                module_id: job.module_id,
                module_uri: job.module_uri.clone(),
                wasm_bytes: job.wasm_bytes.clone(),
                config: job.input_payload.clone(),
                allowed_hosts: job.allowed_hosts.clone(),
                allowed_methods: job.allowed_methods.clone(),
                allowed_secrets: job.allowed_secrets.clone(),
                allowed_sql_operations: job.allowed_sql_operations.clone(),
                allow_tier2_exposure: job.allow_tier2_exposure,
                encrypted_secrets: EncryptedSecrets {
                    ciphertext: job.encrypted_secrets_ciphertext.clone(),
                    nonce: job.encrypted_secrets_nonce.clone(),
                },
                max_fuel: job.max_fuel,
                // Default per-step memory; the core trait no longer
                // carries a per-job value (see the equivalent note in
                // `dispatch` above for the rationale).
                max_memory_mb: 128,
                timeout_ms: job.timeout.as_millis() as u64,
                priority: job.priority,
                cancellation_token: None,
                expected_wasm_hash: job.expected_wasm_hash.clone(),
                integration_name: job.integration_name.clone(),
            })
            .collect();

        let max_priority = steps.iter().map(|s| s.priority).max().unwrap_or(100);

        // H-1: pre-allocate a reply inbox so we can bind it into the
        // signed `PipelineJobRequest::reply_topic`. Same shape as
        // the single-node `dispatch` above.
        let reply_inbox = self.transport.new_reply_inbox();

        // 2. Assemble the chain-level wire request.
        let mut req = PipelineJobRequest {
            job_id: request.job_id.unwrap_or_else(uuid::Uuid::new_v4),
            workflow_execution_id: request.workflow_execution_id,
            steps,
            total_timeout_ms: request.total_timeout.as_millis() as u64,
            share_sandbox: request.share_sandbox,
            signature: vec![],
            job_nonce: String::new(),
            // Wire format takes a non-optional `Uuid`; substitute
            // `Uuid::nil()` at the boundary (same mapping as single-node
            // dispatch above).
            user_id: request.user_id.unwrap_or_else(uuid::Uuid::nil),
            max_llm_tier: request.max_llm_tier,
            // H-1: bind the pre-allocated inbox into the signing
            // payload. Worker will refuse to publish anywhere else.
            reply_topic: reply_inbox.clone(),
        };

        // 3. Sign (chain-level HMAC, independent of any per-step signing).
        if let Some(key) = self.worker_shared_key.as_ref() {
            req.sign(key.as_bytes()).map_err(|e| -> BoxError {
                format!("Failed to sign pipeline request: {e}").into()
            })?;
        }

        // 4. Serialize.
        let payload = serde_json::to_vec(&req).map_err(|e| -> BoxError {
            format!("Failed to serialize pipeline request: {e}").into()
        })?;

        // 5. Topic. A `None` user_id stays on the tenant-agnostic
        // `workflow.pipeline.jobs` subject (same contract as single
        // dispatch above).
        let topic = get_pipeline_job_topic(request.user_id, max_priority);

        // 6. Chain retry loop via `dispatch_with_retry` (not
        // `execute_job_with_retry`). Chain-level retry observability
        // is deliberately not emitted here — pipelines complete as a
        // single unit at the engine level. When a chain-retry
        // observability surface becomes a real need, add an
        // `emit_retry_events` field back to `ChainDispatchRequest`
        // and route through `execute_job_with_retry` with a synthetic
        // per-attempt event.
        let response_bytes = dispatch_with_retry(
            self.transport.as_ref(),
            topic,
            payload,
            request.total_timeout.as_secs(),
            request.max_retries,
            request.backoff_ms,
            self.worker_shared_key
                .as_ref()
                .map(WorkerSharedKey::as_bytes),
            // H-1: signed reply inbox so the worker publishes the
            // pipeline result to the HMAC-bound subject only.
            reply_inbox,
        )
        .await
        .map_err(|e| -> BoxError { e.into() })?;

        // 7. Parse + verify.
        let result: PipelineJobResult = serde_json::from_slice(&response_bytes)
            .map_err(|e| -> BoxError { format!("Failed to parse pipeline result: {e}").into() })?;
        if let Some(key) = self.worker_shared_key.as_ref() {
            // L-4: PipelineJobResult Primary verifier — same role as
            // the JobResult dispatcher above.
            result
                .verify_as(
                    key.as_bytes(),
                    300,
                    talos_workflow_job_protocol::Verifier::Primary,
                )
                .map_err(|e| -> BoxError {
                    format!("Pipeline result signature verification failed: {e}").into()
                })?;
            // L-11: forensic attribution — see the matching block in
            // `dispatch_single` above for the security rationale.
            if !result.worker_id.is_empty() {
                tracing::debug!(
                    target: "talos_job_audit",
                    job_id = %result.job_id,
                    worker_id = %result.worker_id,
                    "PipelineJobResult verified — worker attribution recorded"
                );
            }
        }

        // 8. Map per-step results back into the abstract shape.
        let steps: Vec<ChainStepResult> = result
            .step_results
            .into_iter()
            .map(|sr| ChainStepResult {
                module_id: sr.module_id,
                status: map_job_status(sr.status),
                output: sr.output,
                error: sr.error,
                execution_time_ms: sr.execution_time_ms,
            })
            .collect();

        Ok(ChainDispatchResult {
            steps,
            final_output: result.final_output,
            overall_status: map_job_status(result.overall_status),
        })
    }
}

/// Job-protocol `JobStatus` → core `StepStatus`. Any unknown variant
/// maps to `Failed` — the core trait's status taxonomy is deliberately
/// narrower than the wire-format's, and callers only act on the
/// three-way distinction.
fn map_job_status(status: JobStatus) -> StepStatus {
    match status {
        JobStatus::Success => StepStatus::Success,
        JobStatus::TimedOut => StepStatus::TimedOut,
        _ => StepStatus::Failed,
    }
}
