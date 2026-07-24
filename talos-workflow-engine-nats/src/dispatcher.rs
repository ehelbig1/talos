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

/// Gate for the MCP-1212 controller-side signature diagnostic (see the
/// dispatch site below). OFF by default: the diagnostic fired at WARN on
/// EVERY successful dispatch, which is one loud field-dump per job in
/// steady state — noise that drowns real WARNs. Set `TALOS_SIGNATURE_DIAG=1`
/// (or `true`) on the controller to re-enable it while investigating a
/// worker-side "signature verification failed", then unset it. The worker's
/// enriched failure `JobResult.output_payload` (worker/src/main.rs) is gated
/// behind the SAME env var (2026-07-01 — the unconditional variant let an
/// unauthenticated request get attacker-chosen fields signed by the worker
/// key), so set it on BOTH sides while investigating.
/// Read once at process start — changing the env var after boot has no effect.
static SIGNATURE_DIAG_ENABLED: std::sync::LazyLock<bool> = std::sync::LazyLock::new(|| {
    matches!(
        std::env::var("TALOS_SIGNATURE_DIAG").as_deref(),
        Ok("1" | "true")
    )
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
        Some(inbox) => {
            transport
                .request_with_reply_inbox(topic, inbox, payload)
                .await
        }
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
    // RFC 0010 P3 (M3 fix): invoked before EACH send (initial + every
    // retry) so a claim-based-sealed pipeline can re-arm its InFlightSeals
    // entry. The worker's claim single-TAKES the seal per attempt, so
    // without re-registration a retry can't re-claim and fails closed under
    // `TALOS_ENVELOPE_SEALING=required`. `None` for non-sealed dispatches.
    on_before_send: Option<&(dyn Fn() + Send + Sync)>,
) -> Result<Vec<u8>, String> {
    let mut attempts: u32 = 0;
    let mut current_payload = payload;
    loop {
        // Re-arm the seal before every attempt (register() overwrites, so
        // this is idempotent on the first attempt and restores the entry the
        // previous attempt's claim consumed).
        if let Some(rearm) = on_before_send {
            rearm();
        }
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
                    current_payload = resign_pipeline_payload_for_retry(&current_payload, key)
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
    // RFC 0010 P1: re-sign under the configured dispatch scheme (see the
    // single-job resign path for rationale).
    let sign_result = match talos_workflow_job_protocol::configured_dispatch_signer() {
        Some(signer) => signer.sign_pipeline(&mut req),
        None => req.sign(key),
    };
    if let Err(e) = sign_result {
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
    // Signing key used to RE-SIGN the payload on retry (fresh nonce). Always
    // the current key.
    worker_shared_key: Option<&[u8]>,
    // Verify-ring for the worker's signed RESULT — current key plus any staged
    // previous keys. `None` skips result verification (test harnesses).
    verify_ring: Option<&talos_workflow_engine_core::WorkerKeyRing>,
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
    // RFC 0010 P3 (M3 fix): re-arm hook, invoked before EACH send. See
    // `dispatch_with_retry` for the rationale — the worker's claim
    // single-takes the seal per attempt, so a retry must re-register it.
    on_before_send: Option<&(dyn Fn() + Send + Sync)>,
    // R2 token ledger: usage hook, invoked once per VERIFIED JobResult
    // (per attempt — failed attempts spent tokens too) carrying non-empty
    // `llm_usage`. The hook owner attaches identity from the
    // controller-side dispatch context.
    on_llm_usage: Option<&(dyn Fn(Vec<talos_workflow_job_protocol::LlmUsageEntry>) + Send + Sync)>,
) -> Result<serde_json::Value, String> {
    let mut attempts: u32 = 0;
    let mut current_payload = payload;
    loop {
        // Re-arm the seal before every attempt (see `dispatch_with_retry`).
        if let Some(rearm) = on_before_send {
            rearm();
        }
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
                if let Some(ring) = verify_ring {
                    // RFC 0010 P2: `verify_dispatch` routes on the result's
                    // `crypto_scheme` — Ed25519 against the public key(s)
                    // registered for THIS worker_id in TALOS_WORKER_PUBLIC_KEYS,
                    // or legacy HMAC against the ring while
                    // `result_accept_legacy_hmac()` (the rollout posture;
                    // TALOS_RESULT_REQUIRE_ED25519 flips it off for P4). This is
                    // the sole inline Primary consumer, so it records the nonce
                    // exactly once (verify-once rule).
                    let worker_ed_keys =
                        talos_workflow_job_protocol::worker_public_keys(&job_result.worker_id);
                    if let Err(e) = job_result.verify_dispatch(
                        ring,
                        &worker_ed_keys,
                        300,
                        talos_workflow_job_protocol::result_accept_legacy_hmac(),
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

                // R2 token ledger: record the verified result's usage BEFORE
                // the success/retry branching — a failed attempt's tokens
                // were spent regardless of whether we retry. Placed after
                // signature verification so an on-wire forgery can't inflate
                // another actor's ledger. (When `verify_ring` is None — test
                // harnesses only — the hook still fires; production always
                // verifies.)
                if let Some(hook) = on_llm_usage {
                    if !job_result.llm_usage.is_empty() {
                        hook(job_result.llm_usage.clone());
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
                    // MCP-961 sibling: saturating u32→i32 conversion.
                    // `attempts` is bounded by the retry-policy
                    // max_retries (typically <= 10) but defense-in-depth
                    // against future producers passing unbounded values.
                    let retry_num = i32::try_from(attempts).unwrap_or(i32::MAX);
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
                        current_payload = resign_payload_for_retry(&current_payload, key)
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
                        resign_payload_for_retry(&current_payload, key).unwrap_or(current_payload);
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
    // RFC 0010 P1: re-sign under the configured dispatch scheme so a retry
    // matches the primary path (Ed25519 when configured, else HMAC).
    let sign_result = match talos_workflow_job_protocol::configured_dispatch_signer() {
        Some(signer) => signer.sign_job(&mut req),
        None => req.sign(key),
    };
    if let Err(e) = sign_result {
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
    /// Shared key used for HMAC signing of the request (and re-signing on
    /// retry). `None` disables signing — used by test harnesses that don't
    /// need the round-trip. Signing always uses the CURRENT key.
    worker_shared_key: Option<WorkerSharedKey>,
    /// Verify-ring for the worker's signed RESULT (current + any staged
    /// `WORKER_SHARED_KEY_PREVIOUS`). Defaults in `new` to a single-key ring
    /// over `worker_shared_key`, so behavior is unchanged unless the
    /// construction path injects previous keys via
    /// [`with_worker_key_ring`](Self::with_worker_key_ring). Lets a worker
    /// result signed under a staged previous key verify during a rolling
    /// `WORKER_SHARED_KEY` rotation.
    worker_key_ring: Option<talos_workflow_engine_core::WorkerKeyRing>,
    /// RFC 0010 P1: optional dispatch signer. When `Some`, JobRequest /
    /// PipelineJobRequest are signed under this signer's scheme (Ed25519 or
    /// HMAC) instead of the bare `worker_shared_key` HMAC path. `None` (the
    /// default) preserves the exact pre-P1 HMAC signing behavior, so a deploy
    /// that doesn't configure Ed25519 is unchanged. Note `worker_shared_key`
    /// remains for envelope encryption + result-verify regardless.
    dispatch_signer: Option<talos_workflow_job_protocol::DispatchSigner>,
    /// Policy trait for classifying dispatch errors into
    /// transient-vs-permanent. Drives the "smart retry default" path
    /// (skip retries on auth / fuel / missing-secret errors even when
    /// `max_retries > 0`).
    retry_classifier: Arc<dyn RetryClassifier>,
    /// Policy trait for evaluating `retry_condition` / `retry_delay_expression`
    /// expressions against the error payload. Wraps the sandboxed
    /// `rhai::Engine` in production; tests plug in their own impl.
    expression_evaluator: Arc<dyn ExpressionEvaluator>,
    /// RFC 0010 P3 (D3b): claim-based sealing handle. `Some` when the controller
    /// wired an `InFlightSeals` + the process claim-responder subject (via
    /// [`with_envelope_sealing`](Self::with_envelope_sealing)); `None` (default)
    /// keeps the legacy inline WSK envelope path. A `DispatchJob` that arrives
    /// with `plaintext_secrets` but no handle here is refused (fail-closed) —
    /// plaintext must never fall back onto the wire.
    envelope: Option<EnvelopeSealingHandle>,
    /// R2 token ledger: optional controller-installed usage recorder,
    /// invoked once per VERIFIED result (single-node and pipeline) that
    /// carries non-empty `llm_usage`. `None` (default) drops usage — test
    /// harnesses and consumers that don't account.
    llm_usage_sink: Option<LlmUsageSink>,
}

/// The controller-provided pieces the dispatcher needs to route a claim-based
/// dispatch. Canonical definition lives in `talos-envelope-seal` (the crate
/// every sealing participant depends on) so the module-bound integration paths
/// name the SAME type without a dep edge on this engine-NATS layer; re-exported
/// here to keep existing `talos_workflow_engine_nats::EnvelopeSealingHandle`
/// paths resolving.
pub use talos_envelope_seal::EnvelopeSealingHandle;

/// R2 token ledger: one verified result's LLM usage, attributed with the
/// CONTROLLER's own dispatch identity (`DispatchJob` /
/// `ChainDispatchRequest` fields the engine stamped from its execution
/// records) — the worker-supplied result contributes ONLY the
/// provider/model/token counts, never the identity.
#[derive(Debug, Clone)]
pub struct LlmUsageReport {
    /// Workflow execution that owned the dispatch (controller-side).
    pub execution_id: Uuid,
    /// Actor bound to the dispatch, when actor-owned (controller-side).
    pub actor_id: Option<Uuid>,
    /// Owning user of the dispatch (controller-side).
    pub user_id: Option<Uuid>,
    /// Verified per-(provider, model) usage from the SIGNED result.
    pub entries: Vec<talos_workflow_job_protocol::LlmUsageEntry>,
}

/// Controller-installed recorder for [`LlmUsageReport`]s. MUST be
/// non-blocking (spawn DB writes internally) — it runs inline on the
/// dispatch hot path right after result verification.
pub type LlmUsageSink = Arc<dyn Fn(LlmUsageReport) + Send + Sync>;

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
        let worker_key_ring = worker_shared_key
            .clone()
            .map(talos_workflow_engine_core::WorkerKeyRing::single);
        Self {
            transport,
            event_sink,
            worker_shared_key,
            worker_key_ring,
            dispatch_signer: None,
            retry_classifier,
            expression_evaluator,
            envelope: None,
            llm_usage_sink: None,
        }
    }

    /// R2 token ledger: install the usage recorder. The dispatcher calls it
    /// once per verified result carrying non-empty `llm_usage`, with the
    /// identity taken from the CONTROLLER-side dispatch context. Omit it to
    /// drop usage (default).
    #[must_use]
    pub fn with_llm_usage_sink(mut self, sink: LlmUsageSink) -> Self {
        self.llm_usage_sink = Some(sink);
        self
    }

    /// RFC 0010 P3 (D3b): install the claim-based sealing handle. When set, a
    /// `DispatchJob` carrying `plaintext_secrets` is registered in
    /// `handle.in_flight` (keyed on the wire `job_id`) and its `JobRequest` is
    /// stamped `sealing = 1` + `claim_inbox = handle.claim_subject`, with no
    /// secrets on the wire. Omit it to keep the legacy inline WSK path.
    #[must_use]
    pub fn with_envelope_sealing(mut self, handle: EnvelopeSealingHandle) -> Self {
        self.envelope = Some(handle);
        self
    }

    /// RFC 0010 P1: install the dispatch signer (Ed25519 or explicit HMAC).
    /// When set, it takes precedence over the bare `worker_shared_key` HMAC path
    /// at every request-signing site. Omit it to keep the legacy HMAC behavior.
    #[must_use]
    pub fn with_dispatch_signer(
        mut self,
        signer: talos_workflow_job_protocol::DispatchSigner,
    ) -> Self {
        self.dispatch_signer = Some(signer);
        self
    }

    /// Override the result verify-ring (e.g. to add `WORKER_SHARED_KEY_PREVIOUS`
    /// keys for a rolling rotation). The ring's signing key SHOULD match
    /// `worker_shared_key`; only the additional previous keys widen what the
    /// dispatcher will accept when verifying a worker result. Signing is
    /// unaffected — it always uses `worker_shared_key`.
    #[must_use]
    pub fn with_worker_key_ring(mut self, ring: talos_workflow_engine_core::WorkerKeyRing) -> Self {
        self.worker_key_ring = Some(ring);
        self
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
    async fn dispatch(&self, mut job: DispatchJob) -> Result<DispatchResult, BoxError> {
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

        // RFC 0010 P3 (D3b): pull out the claim-based sealing inputs before the
        // literal moves the rest of `job`. `job_id` is the wire id AND the
        // InFlightSeals key the worker's claim will name (SecretClaim.exec_id).
        let job_id = job.job_id.unwrap_or_else(uuid::Uuid::new_v4);
        let claim_plaintext = job.plaintext_secrets.take();
        let claim_secret_paths = std::mem::take(&mut job.secret_paths);

        // 1. Assemble the wire-format `JobRequest`.
        let mut req = JobRequest {
            crypto_scheme: 0,
            sealing: 0,
            secret_paths: Vec::new(),
            claim_inbox: None,
            // Reuse a caller-supplied job id when present so a
            // pre-INSERTed `module_executions` row with that id stays
            // correlated with the worker's update. Fresh UUID
            // otherwise.
            job_id,
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
            max_write_ceiling: job.max_write_ceiling,
            egress_scope: job.egress_scope,
            // H-1: stamp the pre-allocated inbox into the request
            // BEFORE signing. The worker will verify wire
            // `msg.reply == req.reply_topic` and refuse to publish
            // results to anything else.
            reply_topic: reply_inbox.clone(),
        };

        // RFC 0010 P3 (D3b): when the engine resolved PLAINTEXT secrets for this
        // dispatch (claim-based sealing on), register them in InFlightSeals keyed
        // on the wire job_id and stamp the sealing fields into the request BEFORE
        // signing (so `sealing` + `secret_paths` + `claim_inbox` are bound and a
        // downgrade / claim-redirect fails verification). No plaintext reaches
        // the wire — the worker obtains the values via a signed claim to
        // `claim_inbox`, sealed to its ephemeral key. Fail-closed when plaintext
        // was resolved but no envelope handle is wired.
        // RFC 0010 P3 (M3 fix): the re-arm closure is built here and invoked
        // by `execute_job_with_retry` before EVERY send attempt so a retry can
        // re-claim after the prior attempt's single-take. Built once, holds an
        // Arc<InFlightSeals> + the plaintext, and rebuilds+re-registers the
        // SealContext each call. `None` when this dispatch isn't sealed.
        let seal_rearm: Option<Box<dyn Fn() + Send + Sync>> =
            if let Some(plaintext) = claim_plaintext {
                let handle = self.envelope.as_ref().ok_or_else(|| -> BoxError {
                    "RFC 0010 P3: dispatch carried plaintext_secrets but no envelope \
                 sealing handle is wired — refusing to dispatch (fail-closed, no \
                 plaintext on the wire)"
                        .into()
                })?;
                // Fail-closed early: verify the plaintext can be sealed BEFORE we
                // dispatch, so an unsealable payload is rejected at dispatch time
                // rather than surfacing as a claim failure on every attempt.
                talos_envelope_seal::SealContext::new(&plaintext)
                    .map_err(|e| -> BoxError { format!("build seal context: {e}").into() })?;
                req.sealing = talos_workflow_job_protocol::SEALING_CLAIM_ECIES;
                req.claim_inbox = Some(handle.claim_subject.clone());
                req.secret_paths = claim_secret_paths;
                // encrypted_secrets stays empty (the engine set ciphertext/nonce
                // empty on the claim-based path).
                let in_flight = handle.in_flight.clone();
                Some(Box::new(move || {
                    // Rebuild + register before each send. register() overwrites,
                    // so the first (pre-dispatch) call arms it and every retry
                    // restores the entry the previous claim consumed. SealContext
                    // construction only fails on a serialization error that a
                    // HashMap<String,String> cannot produce; on the defensive Err
                    // we skip re-registration → the claim fails → the job fails
                    // closed (never a plaintext leak).
                    if let Ok(ctx) = talos_envelope_seal::SealContext::new(&plaintext) {
                        in_flight.register(job_id, ctx);
                    }
                }))
            } else {
                None
            };

        // 2. Sign. RFC 0010 P1: prefer the configured dispatch signer (Ed25519
        // or explicit HMAC); fall back to the bare worker_shared_key HMAC path
        // when no signer is installed (unchanged pre-P1 behavior).
        if let Some(signer) = self.dispatch_signer.as_ref() {
            signer
                .sign_job(&mut req)
                .map_err(|e| -> BoxError { format!("Failed to sign job request: {e}").into() })?;
        } else if let Some(key) = self.worker_shared_key.as_ref() {
            req.sign(key.as_bytes())
                .map_err(|e| -> BoxError { format!("Failed to sign job request: {e}").into() })?;
        }

        // MCP-1212 (2026-05-18): controller-side signature diagnostic.
        // Emits the per-field hashes / lengths consumed by `signing_payload()`
        // at WARN level so operators investigating a worker-side
        // "signature verification failed" can grep their controller logs
        // for the same job_id and diff field-by-field against the worker's
        // enriched failure JobResult.output_payload (see worker/src/main.rs
        // verify-fail branch). `diag_hashes()` is colocated with
        // `signing_payload()` in job-protocol so the field formulas stay in
        // sync.
        //
        // 2026-07-01: gated behind `TALOS_SIGNATURE_DIAG` (default OFF). It
        // previously fired on EVERY successful dispatch — one loud field-dump
        // per job in steady state, drowning real WARNs. It's a break-glass
        // aid for an active signature-mismatch incident, not steady-state
        // telemetry; enable the env var while investigating, then unset it.
        // The worker's enriched failure JobResult still carries the same
        // fields unconditionally, so the primary diagnostic is unaffected.
        if *SIGNATURE_DIAG_ENABLED {
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
        // R2 token ledger: per-attempt usage hook. Identity comes from the
        // CONTROLLER-side DispatchJob (stamped by the engine from its own
        // execution records), never from the worker's result.
        let usage_hook: Option<
            Box<dyn Fn(Vec<talos_workflow_job_protocol::LlmUsageEntry>) + Send + Sync>,
        > = self.llm_usage_sink.as_ref().map(|sink| {
            let sink = sink.clone();
            let (execution_id, actor_id, user_id) = (job.execution_id, job.actor_id, job.user_id);
            Box::new(
                move |entries: Vec<talos_workflow_job_protocol::LlmUsageEntry>| {
                    sink(LlmUsageReport {
                        execution_id,
                        actor_id,
                        user_id,
                        entries,
                    });
                },
            )
                as Box<dyn Fn(Vec<talos_workflow_job_protocol::LlmUsageEntry>) + Send + Sync>
        });
        let result = execute_job_with_retry(
            self.transport.as_ref(),
            topic,
            payload,
            job.timeout.as_secs() + TOKIO_WRAP_GRACE_SECS,
            job.max_retries,
            job.backoff_ms,
            self.worker_shared_key
                .as_ref()
                .map(WorkerSharedKey::as_bytes),
            self.worker_key_ring.as_ref(),
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
            // RFC 0010 P3 (M3): re-arm the seal before each attempt.
            seal_rearm.as_deref(),
            // R2 token ledger: record verified per-attempt usage.
            usage_hook.as_deref(),
        )
        .await;

        // RFC 0010 P3: the worker's claim TAKES the seal context on success;
        // discard here bounds InFlightSeals if the job failed before any claim
        // (worker died / claim rejected). No-op when nothing was registered or
        // the context was already taken.
        if let Some(handle) = self.envelope.as_ref() {
            handle.in_flight.discard(job_id);
        }

        let output = result.map_err(|e| -> BoxError { e.into() })?;
        Ok(DispatchResult { output })
    }

    async fn dispatch_chain(
        &self,
        request: ChainDispatchRequest,
    ) -> Result<ChainDispatchResult, BoxError> {
        // RFC 0010 P3 (D3b): claim-based sealing is active for this pipeline when
        // the engine resolved PLAINTEXT for any step (`build_dispatch_secrets_for`
        // sets `plaintext_secrets` under the flag; the per-step
        // `encrypted_secrets_ciphertext` is empty in that case). We collect every
        // step's plaintext into ONE per-step vector, sealed in a single claim.
        let job_id = request.job_id.unwrap_or_else(uuid::Uuid::new_v4);
        let claim_based = request.steps.iter().any(|j| j.plaintext_secrets.is_some());
        // Per-step plaintext maps, aligned index-for-index with `steps`. Steps
        // with no secrets contribute an empty map so the vector stays aligned.
        let per_step_secrets: Vec<std::collections::HashMap<String, String>> = request
            .steps
            .iter()
            .map(|j| j.plaintext_secrets.clone().unwrap_or_default())
            .collect();
        // Union of the per-step secret NAMES (not values) for the signed
        // `secret_paths` metadata.
        let claim_secret_paths: Vec<String> = {
            let mut names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
            for j in &request.steps {
                names.extend(j.secret_paths.iter().cloned());
            }
            names.into_iter().collect()
        };

        // 1. Map `DispatchJob`s into wire-format `PipelineStep`s. The
        // step shape is a strict subset of JobRequest's per-node fields
        // (no per-step user/actor/dry_run — those are chain-level).
        // Under claim-based sealing every step's `encrypted_secrets` is already
        // empty (the engine put the values in `plaintext_secrets` instead), so
        // this mapping is correct for both paths without a branch.
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
                // Per-step retry policy (2026-07-24): executed IN-WORKER by
                // the pipeline step loop, gated by the worker's transient
                // classifier. The engine stamps these from each step node's
                // own retry policy (method-aware default when absent) — see
                // `engine_dispatch_pipeline`. HMAC-bound via the
                // conditional `:retries=` signing segment.
                max_retries: job.max_retries,
                retry_backoff_ms: job.backoff_ms,
            })
            .collect();

        let max_priority = steps.iter().map(|s| s.priority).max().unwrap_or(100);

        // H-1: pre-allocate a reply inbox so we can bind it into the
        // signed `PipelineJobRequest::reply_topic`. Same shape as
        // the single-node `dispatch` above.
        let reply_inbox = self.transport.new_reply_inbox();

        // 2. Assemble the chain-level wire request.
        let mut req = PipelineJobRequest {
            crypto_scheme: 0,
            sealing: 0,
            secret_paths: Vec::new(),
            claim_inbox: None,
            job_id,
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
            max_write_ceiling: request.max_write_ceiling,
            egress_scope: request.egress_scope,
            // H-1: bind the pre-allocated inbox into the signing
            // payload. Worker will refuse to publish anywhere else.
            reply_topic: reply_inbox.clone(),
        };

        // RFC 0010 P3 (D3b): register the per-step plaintext as ONE sealed claim
        // for this pipeline BEFORE signing (so `sealing`/`secret_paths`/
        // `claim_inbox` are bound). The worker claims once and gets the per-step
        // vector back. No plaintext reaches the wire. Fail-closed if plaintext was
        // resolved but no envelope handle is wired.
        // RFC 0010 P3 (M3 fix): re-arm closure, invoked before EVERY send by
        // `dispatch_with_retry` so a pipeline retry re-claims after the prior
        // attempt's single-take. Holds an Arc<InFlightSeals> + the serialized
        // per-step seal bytes; rebuilds+re-registers the SealContext each call.
        let seal_rearm: Option<Box<dyn Fn() + Send + Sync>> = if claim_based {
            let handle = self.envelope.as_ref().ok_or_else(|| -> BoxError {
                "RFC 0010 P3: pipeline carried plaintext_secrets but no envelope sealing handle \
                 is wired — refusing to dispatch (fail-closed, no plaintext on the wire)"
                    .into()
            })?;
            let bytes = serde_json::to_vec(&per_step_secrets).map_err(|e| -> BoxError {
                format!("serialize pipeline seal payload: {e}").into()
            })?;
            req.sealing = talos_workflow_job_protocol::SEALING_CLAIM_ECIES;
            req.claim_inbox = Some(handle.claim_subject.clone());
            req.secret_paths = claim_secret_paths;
            let in_flight = handle.in_flight.clone();
            Some(Box::new(move || {
                // register() overwrites; the first call arms it and each retry
                // restores the entry the previous claim consumed. `from_bytes`
                // is infallible (it just wraps the already-serialized bytes),
                // so re-cloning the Vec per attempt is the only cost (retry is
                // not a hot path).
                in_flight.register(
                    job_id,
                    talos_envelope_seal::SealContext::from_bytes(bytes.clone()),
                );
            }))
        } else {
            None
        };

        // 3. Sign (chain-level, independent of any per-step signing). RFC 0010
        // P1: prefer the configured dispatch signer; else the legacy HMAC path.
        if let Some(signer) = self.dispatch_signer.as_ref() {
            signer.sign_pipeline(&mut req).map_err(|e| -> BoxError {
                format!("Failed to sign pipeline request: {e}").into()
            })?;
        } else if let Some(key) = self.worker_shared_key.as_ref() {
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
            // RFC 0010 P3 (M3): re-arm the seal before each attempt.
            seal_rearm.as_deref(),
        )
        .await;

        // RFC 0010 P3: discard the pipeline seal context after dispatch (the
        // worker's claim TOOK it on success; this bounds InFlightSeals if the
        // pipeline failed before any claim). No-op when unregistered/taken.
        if let Some(handle) = self.envelope.as_ref() {
            handle.in_flight.discard(job_id);
        }

        let response_bytes = response_bytes.map_err(|e| -> BoxError { e.into() })?;

        // 7. Parse + verify.
        let result: PipelineJobResult = serde_json::from_slice(&response_bytes)
            .map_err(|e| -> BoxError { format!("Failed to parse pipeline result: {e}").into() })?;
        if let Some(ring) = self.worker_key_ring.as_ref() {
            // L-4 / RFC 0010 P2: PipelineJobResult Primary verifier — same role
            // as the JobResult dispatcher above. `verify_dispatch` routes on the
            // result's `crypto_scheme`: Ed25519 against the keys registered for
            // this worker_id, or legacy HMAC against the ring while
            // `result_accept_legacy_hmac()`. Records the nonce exactly once.
            let worker_ed_keys = talos_workflow_job_protocol::worker_public_keys(&result.worker_id);
            result
                .verify_dispatch(
                    ring,
                    &worker_ed_keys,
                    300,
                    talos_workflow_job_protocol::result_accept_legacy_hmac(),
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

        // R2 token ledger: record the verified pipeline's whole-chain usage.
        // Identity from the CONTROLLER-side ChainDispatchRequest / step
        // DispatchJobs (engine-stamped) — never from the worker result.
        if let Some(sink) = self.llm_usage_sink.as_ref() {
            if !result.llm_usage.is_empty() {
                sink(LlmUsageReport {
                    execution_id: request.workflow_execution_id,
                    actor_id: request.steps.iter().find_map(|s| s.actor_id),
                    user_id: request.user_id,
                    entries: result.llm_usage.clone(),
                });
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

/// RFC 0010 P3 (D3b) — full dispatch→claim→seal→open loop over LIVE NATS.
///
/// This is the top of the test pyramid: it drives the REAL `NatsNodeDispatcher`
/// (with an `EnvelopeSealingHandle` + Ed25519 dispatch signer) and the REAL
/// claim responder against a real broker, plus an in-test "worker" that runs the
/// exact same job-protocol claim primitives the production `worker::secret_claim`
/// path uses. It asserts the security-critical guarantees end to end:
///   - the wire `JobRequest` carries `sealing=1` + a `claim_inbox`, empty
///     `encrypted_secrets`, and NO plaintext secret bytes;
///   - the dispatch signature (including the bound sealing fields) verifies;
///   - a signed claim yields sealed secrets that open to the exact input map;
///   - the in-flight seal context is consumed (single-claim) after the job;
///   - a second claim for the same execution is rejected.
///
/// Gated on `TALOS_TEST_NATS_URL` so it no-ops without a broker (runs in
/// `quality.yml`'s env-gated suite).
#[cfg(test)]
mod p3_full_loop_tests {
    use super::{get_single_job_topic, EnvelopeSealingHandle, NatsNodeDispatcher};
    use futures::StreamExt;
    use std::collections::HashMap;
    use std::sync::Arc;
    use talos_workflow_engine_core::{
        BoxError, DispatchJob, ExpressionEvaluator, NodeDispatcher, RetryClassifier, WorkerKeyRing,
        WorkerSharedKey,
    };
    use talos_workflow_job_protocol::{
        set_dynamic_worker_public_keys, ClaimResponse, DispatchSigner, DispatchSigningKey,
        JobRequest, JobResult, JobStatus, SecretClaim, WorkerEphemeral, SEALING_CLAIM_ECIES,
    };

    struct NoRetry;
    impl RetryClassifier for NoRetry {
        fn classify(&self, _error: &str) -> String {
            "permanent".to_string()
        }
        fn is_transient(&self, _class: &str) -> bool {
            false
        }
    }
    struct TrueEval;
    impl ExpressionEvaluator for TrueEval {
        fn eval_bool(&self, _expression: &str, _context: &serde_json::Value) -> bool {
            true
        }
        fn try_eval_bool(
            &self,
            _expression: &str,
            _context: &serde_json::Value,
        ) -> Result<bool, BoxError> {
            Ok(true)
        }
        fn eval_i64(&self, _expression: &str, _context: &serde_json::Value) -> Option<i64> {
            None
        }
        fn eval_json(
            &self,
            _expression: &str,
            _context: &serde_json::Value,
        ) -> Result<serde_json::Value, BoxError> {
            Ok(serde_json::Value::Null)
        }
    }

    fn nats_url() -> Option<String> {
        std::env::var("TALOS_TEST_NATS_URL")
            .ok()
            .filter(|s| !s.is_empty())
    }

    /// `set_dynamic_worker_public_keys` REPLACES the process-global worker-key
    /// registry, so the two live-NATS tests (different worker ids) must not run
    /// concurrently or one clobbers the other's key → claims get rejected. An
    /// async mutex serializes them across their `.await` points (a std mutex held
    /// across await would not be Send-safe). `--test-threads=1` would also fix it,
    /// but the lock keeps the tests robust under the default parallel runner.
    static NATS_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn full_claim_loop_over_live_nats() {
        let Some(url) = nats_url() else {
            eprintln!("skipping: set TALOS_TEST_NATS_URL to run");
            return;
        };
        let _reg_guard = NATS_TEST_LOCK.lock().await;
        const SECRET_VALUE: &str = "sk-ant-SUPERSECRET-DO-NOT-LEAK";
        let worker_id = "e2e-worker";

        // Keys: controller Ed25519 (signs dispatch + SealedSecrets), worker
        // Ed25519 (signs the claim), shared HMAC key (signs the JobResult).
        let controller_sk = Arc::new(DispatchSigningKey::generate(&mut rand::rngs::OsRng));
        let controller_vk = controller_sk.verifying_key();
        let worker_sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
        set_dynamic_worker_public_keys(vec![(worker_id.to_string(), worker_sk.verifying_key())]);
        let shared = WorkerSharedKey::new(vec![7u8; 32]);
        let ring = WorkerKeyRing::single(shared.clone());

        let nc = Arc::new(async_nats::connect(&url).await.expect("connect nats"));

        // Responder + shared in-flight store.
        let in_flight = Arc::new(talos_envelope_seal::InFlightSeals::new());
        let claim_subject = nc.new_inbox();
        {
            let (nc2, subj, inf, ck) = (
                nc.clone(),
                claim_subject.clone(),
                in_flight.clone(),
                controller_sk.clone(),
            );
            tokio::spawn(async move {
                let _ = talos_envelope_seal::run_claim_responder(nc2, subj, inf, ck, 300).await;
            });
        }

        // Real dispatcher: Ed25519 signer + envelope handle.
        let dispatcher = NatsNodeDispatcher::new(
            crate::NatsTransport::shared(nc.clone()),
            None,
            Some(shared.clone()),
            Arc::new(NoRetry),
            Arc::new(TrueEval),
        )
        .with_dispatch_signer(DispatchSigner::Ed25519(controller_sk.clone()))
        .with_envelope_sealing(EnvelopeSealingHandle {
            in_flight: in_flight.clone(),
            claim_subject: claim_subject.clone(),
        });

        // Subscribe the in-test worker to the job topic BEFORE dispatch (core
        // NATS drops messages with no subscriber).
        let job_topic = get_single_job_topic(None, 100);
        let worker_sub = nc.subscribe(job_topic).await.expect("worker subscribe");
        // Let the responder + worker subscriptions establish.
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;

        // The in-test worker: the exact production claim protocol.
        let observed: Arc<tokio::sync::Mutex<Option<HashMap<String, String>>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        let worker_task = {
            let (nc, ring, observed, controller_vk) =
                (nc.clone(), ring.clone(), observed.clone(), controller_vk);
            let shared = shared.clone();
            let worker_sk = worker_sk.clone();
            let mut sub = worker_sub;
            tokio::spawn(async move {
                let msg = sub.next().await.expect("worker received a job");
                let raw = msg.payload.clone();
                let req: JobRequest = serde_json::from_slice(&raw).expect("parse JobRequest");

                // --- security guarantees on the wire ---
                assert_eq!(req.sealing, SEALING_CLAIM_ECIES, "wire must be sealing=1");
                assert!(req.claim_inbox.is_some(), "wire must carry claim_inbox");
                assert!(
                    req.encrypted_secrets.ciphertext.is_empty(),
                    "no inline ciphertext on a claim dispatch"
                );
                assert!(
                    !String::from_utf8_lossy(&raw).contains("SUPERSECRET"),
                    "PLAINTEXT SECRET LEAKED ONTO THE WIRE"
                );
                // Dispatch signature (incl. the bound sealing fields) verifies.
                req.verify_dispatch(&ring, &[controller_vk], 300, true)
                    .expect("dispatch signature (with sealing fields) must verify");

                // --- claim → open (production job-protocol primitives) ---
                let we = WorkerEphemeral::generate();
                let claim = SecretClaim::new_signed(
                    req.job_id,
                    worker_id.to_string(),
                    we.public_key(),
                    &worker_sk,
                );
                let reply = nc
                    .request(
                        req.claim_inbox.clone().unwrap(),
                        serde_json::to_vec(&claim).unwrap().into(),
                    )
                    .await
                    .expect("claim request");
                let resp: ClaimResponse = serde_json::from_slice(&reply.payload).unwrap();
                let sealed = match resp {
                    ClaimResponse::Sealed(s) => s,
                    ClaimResponse::Rejected { reason } => panic!("claim rejected: {reason}"),
                };
                sealed.verify(&controller_vk, 300).expect("controller sig");
                let plaintext = we
                    .open(
                        &sealed.epk_c,
                        req.job_id,
                        worker_id,
                        &sealed.ciphertext,
                        &sealed.nonce,
                    )
                    .expect("open sealed secrets");
                let map: HashMap<String, String> = serde_json::from_slice(&plaintext).unwrap();
                *observed.lock().await = Some(map);

                // Send back a signed JobResult so the dispatcher completes.
                let mut jr = JobResult {
                    llm_usage: vec![],
                    job_id: req.job_id,
                    status: JobStatus::Success,
                    output_payload: serde_json::json!({"ok": true}),
                    logs: vec![],
                    execution_time_ms: 1,
                    signature: vec![],
                    result_nonce: String::new(),
                    worker_id: String::new(),
                    crypto_scheme: 0,
                };
                jr.sign_with_worker_id(shared.as_bytes(), worker_id)
                    .unwrap();
                nc.publish(
                    req.reply_topic.clone().unwrap(),
                    serde_json::to_vec(&jr).unwrap().into(),
                )
                .await
                .unwrap();
                let _ = nc.flush().await;
            })
        };

        // Dispatch a job whose secrets are resolved as PLAINTEXT (claim-based).
        let job_id = uuid::Uuid::new_v4();
        let secret_map: HashMap<String, String> =
            [("anthropic/api_key".to_string(), SECRET_VALUE.to_string())]
                .into_iter()
                .collect();
        let job = DispatchJob {
            job_id: Some(job_id),
            module_uri: "test:noop".to_string(),
            input_payload: serde_json::json!({}),
            plaintext_secrets: Some(secret_map),
            secret_paths: vec!["anthropic/api_key".to_string()],
            timeout: std::time::Duration::from_secs(10),
            ..Default::default()
        };

        let result = dispatcher.dispatch(job).await.expect("dispatch completes");
        assert_eq!(result.output, serde_json::json!({"ok": true}));
        worker_task.await.unwrap();

        // The worker received the exact secret, sealed to its ephemeral key.
        let got = observed.lock().await.take().expect("worker saw secrets");
        assert_eq!(got.get("anthropic/api_key").unwrap(), SECRET_VALUE);

        // Single-claim: the context was consumed, so a replayed claim is rejected.
        assert!(
            in_flight.is_empty(),
            "seal context must be consumed after claim"
        );
        let we2 = WorkerEphemeral::generate();
        let replay =
            SecretClaim::new_signed(job_id, worker_id.to_string(), we2.public_key(), &worker_sk);
        let reply = nc
            .request(claim_subject, serde_json::to_vec(&replay).unwrap().into())
            .await
            .unwrap();
        let resp: ClaimResponse = serde_json::from_slice(&reply.payload).unwrap();
        assert!(
            matches!(resp, ClaimResponse::Rejected { .. }),
            "replayed claim for a consumed execution must be rejected"
        );
    }

    /// RFC 0010 P3 (D3b) — full PIPELINE claim loop over live NATS. Drives the
    /// real `dispatch_chain` (Ed25519 signer + envelope handle) and the responder,
    /// with an in-test worker running the exact pipeline claim path
    /// (`execute_pipeline_job` uses `claim_secrets_raw` → per-step `Vec<HashMap>`).
    /// Asserts: the wire `PipelineJobRequest` is sealing=1 + claim_inbox with EVERY
    /// step's `encrypted_secrets` empty and NO plaintext on the wire; the signed
    /// sealing fields verify; ONE claim yields the per-step secret vector aligned
    /// to the steps; the seal context is consumed after.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn full_pipeline_claim_loop_over_live_nats() {
        use super::get_pipeline_job_topic;
        use talos_workflow_engine_core::ChainDispatchRequest;
        use talos_workflow_job_protocol::{PipelineJobRequest, PipelineJobResult};

        let Some(url) = nats_url() else {
            eprintln!("skipping: set TALOS_TEST_NATS_URL to run");
            return;
        };
        let _reg_guard = NATS_TEST_LOCK.lock().await;
        const S0: &str = "sk-STEP0-SUPERSECRET";
        const S1: &str = "sk-STEP1-SUPERSECRET";
        let worker_id = "e2e-pipe-worker";

        let controller_sk = Arc::new(DispatchSigningKey::generate(&mut rand::rngs::OsRng));
        let controller_vk = controller_sk.verifying_key();
        let worker_sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
        set_dynamic_worker_public_keys(vec![(worker_id.to_string(), worker_sk.verifying_key())]);
        let shared = WorkerSharedKey::new(vec![9u8; 32]);
        let ring = WorkerKeyRing::single(shared.clone());

        let nc = Arc::new(async_nats::connect(&url).await.expect("connect nats"));
        let in_flight = Arc::new(talos_envelope_seal::InFlightSeals::new());
        let claim_subject = nc.new_inbox();
        {
            let (nc2, subj, inf, ck) = (
                nc.clone(),
                claim_subject.clone(),
                in_flight.clone(),
                controller_sk.clone(),
            );
            tokio::spawn(async move {
                let _ = talos_envelope_seal::run_claim_responder(nc2, subj, inf, ck, 300).await;
            });
        }

        let dispatcher = NatsNodeDispatcher::new(
            crate::NatsTransport::shared(nc.clone()),
            None,
            Some(shared.clone()),
            Arc::new(NoRetry),
            Arc::new(TrueEval),
        )
        .with_dispatch_signer(DispatchSigner::Ed25519(controller_sk.clone()))
        .with_envelope_sealing(EnvelopeSealingHandle {
            in_flight: in_flight.clone(),
            claim_subject: claim_subject.clone(),
        });

        let topic = get_pipeline_job_topic(None, 100);
        let mut sub = nc.subscribe(topic).await.expect("worker subscribe");
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;

        let observed: Arc<tokio::sync::Mutex<Option<Vec<HashMap<String, String>>>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        let worker_task = {
            let (nc, ring, observed, controller_vk) =
                (nc.clone(), ring.clone(), observed.clone(), controller_vk);
            let shared = shared.clone();
            tokio::spawn(async move {
                let msg = sub.next().await.expect("worker received a pipeline job");
                let raw = msg.payload.clone();
                let req: PipelineJobRequest = serde_json::from_slice(&raw).expect("parse pipeline");

                assert_eq!(req.sealing, SEALING_CLAIM_ECIES, "wire must be sealing=1");
                assert!(req.claim_inbox.is_some(), "wire must carry claim_inbox");
                assert!(
                    req.steps
                        .iter()
                        .all(|s| s.encrypted_secrets.ciphertext.is_empty()),
                    "no inline step ciphertext on a claim pipeline"
                );
                assert!(
                    !String::from_utf8_lossy(&raw).contains("SUPERSECRET"),
                    "PLAINTEXT SECRET LEAKED ONTO THE WIRE"
                );
                req.verify_dispatch(&ring, &[controller_vk], 300, true)
                    .expect("pipeline dispatch signature (with sealing fields) must verify");

                // ONE claim → per-step secret vector.
                let we = WorkerEphemeral::generate();
                let claim = SecretClaim::new_signed(
                    req.job_id,
                    worker_id.to_string(),
                    we.public_key(),
                    &worker_sk,
                );
                let reply = nc
                    .request(
                        req.claim_inbox.clone().unwrap(),
                        serde_json::to_vec(&claim).unwrap().into(),
                    )
                    .await
                    .expect("claim request");
                let resp: ClaimResponse = serde_json::from_slice(&reply.payload).unwrap();
                let sealed = match resp {
                    ClaimResponse::Sealed(s) => s,
                    ClaimResponse::Rejected { reason } => panic!("claim rejected: {reason}"),
                };
                sealed.verify(&controller_vk, 300).expect("controller sig");
                let plaintext = we
                    .open(
                        &sealed.epk_c,
                        req.job_id,
                        worker_id,
                        &sealed.ciphertext,
                        &sealed.nonce,
                    )
                    .expect("open sealed secrets");
                let per_step: Vec<HashMap<String, String>> =
                    serde_json::from_slice(&plaintext).unwrap();
                *observed.lock().await = Some(per_step);

                let mut pr = PipelineJobResult {
                    llm_usage: vec![],
                    job_id: req.job_id,
                    overall_status: talos_workflow_job_protocol::JobStatus::Success,
                    step_results: vec![],
                    final_output: serde_json::json!({"ok": true}),
                    total_time_ms: 1,
                    signature: vec![],
                    result_nonce: String::new(),
                    worker_id: String::new(),
                    crypto_scheme: 0,
                };
                pr.sign_with_worker_id(shared.as_bytes(), worker_id)
                    .unwrap();
                nc.publish(
                    req.reply_topic.clone().unwrap(),
                    serde_json::to_vec(&pr).unwrap().into(),
                )
                .await
                .unwrap();
                let _ = nc.flush().await;
            })
        };

        let mk = |v: &str| DispatchJob {
            module_uri: "test:noop".to_string(),
            input_payload: serde_json::json!({}),
            plaintext_secrets: Some(HashMap::from([("api/key".to_string(), v.to_string())])),
            secret_paths: vec!["api/key".to_string()],
            timeout: std::time::Duration::from_secs(10),
            ..Default::default()
        };
        let job_id = uuid::Uuid::new_v4();
        let request = ChainDispatchRequest {
            workflow_execution_id: uuid::Uuid::new_v4(),
            user_id: None,
            job_id: Some(job_id),
            steps: vec![mk(S0), mk(S1)],
            share_sandbox: false,
            max_llm_tier: talos_workflow_engine_core::LlmTier::Tier2,
            max_write_ceiling: talos_workflow_engine_core::WriteCeiling::Write,
            egress_scope: None,
            total_timeout: std::time::Duration::from_secs(20),
            max_retries: 0,
            backoff_ms: 0,
            retry_condition: None,
            retry_delay_expr: None,
        };

        dispatcher
            .dispatch_chain(request)
            .await
            .expect("chain dispatch completes");
        worker_task.await.unwrap();

        let per_step = observed
            .lock()
            .await
            .take()
            .expect("worker saw per-step secrets");
        assert_eq!(per_step.len(), 2, "one map per step");
        assert_eq!(per_step[0].get("api/key").unwrap(), S0);
        assert_eq!(per_step[1].get("api/key").unwrap(), S1);
        assert!(
            in_flight.is_empty(),
            "pipeline seal context must be consumed"
        );
    }

    /// Security-critical fail-closed path (no broker needed, so it always runs):
    /// if a dispatch carries resolved PLAINTEXT secrets but no envelope handle is
    /// wired (a misconfiguration — sealing on without the controller Ed25519 key),
    /// the dispatcher MUST refuse rather than let plaintext fall onto the wire.
    /// The transport panics if used, proving nothing is sent.
    #[tokio::test]
    async fn dispatch_with_plaintext_but_no_envelope_handle_fails_closed() {
        use async_trait::async_trait;

        struct PanicTransport;
        #[async_trait]
        impl talos_workflow_engine_core::JobTransport for PanicTransport {
            async fn request(&self, _topic: &str, _payload: Vec<u8>) -> Result<Vec<u8>, BoxError> {
                panic!("transport must NOT be used when a plaintext dispatch is refused");
            }
        }

        // No `with_envelope_sealing` → no handle.
        let dispatcher = NatsNodeDispatcher::new(
            Arc::new(PanicTransport),
            None,
            None,
            Arc::new(NoRetry),
            Arc::new(TrueEval),
        );

        let secret_map: HashMap<String, String> =
            [("anthropic/api_key".to_string(), "sk-ant-SECRET".to_string())]
                .into_iter()
                .collect();
        let job = DispatchJob {
            plaintext_secrets: Some(secret_map),
            timeout: std::time::Duration::from_secs(5),
            ..Default::default()
        };

        let err = dispatcher
            .dispatch(job)
            .await
            .expect_err("dispatch with plaintext but no handle must fail closed");
        let msg = err.to_string();
        assert!(
            msg.contains("envelope") && msg.contains("fail-closed"),
            "expected a fail-closed envelope error, got: {msg}"
        );
    }
}
