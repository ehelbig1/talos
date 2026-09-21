//! The `talos.results.*` observer: the ONLY finalizer for the fire-and-forget
//! module-bound dispatches (Gmail / Google-Calendar / GCP Monitoring push and
//! the webhook DLQ replay), whose worker result has no reply inbox and lands
//! on `talos.results.<job_id>`.
//!
//! Until 2026-09-21 this lived inline in the controller binary and bound the
//! subject with a plain `subscribe`, so NATS delivered every result to EVERY
//! controller replica. The write is status-guarded, so no replica wrote a
//! wrong row — but each of the N−1 losers still verified the signature, read
//! the row and sealed the output (package CZ) before its UPDATE matched
//! nothing, logged "completed" for a transition it did not make, and an
//! unparseable or unverifiable result was counted and WARNed once per replica
//! instead of once. It now queue-subscribes in
//! [`CONTROLLER_RESULTS_QUEUE_GROUP`]: one replica handles each result.
//!
//! Observer role (verify-once rule): this site calls the NO-REPLAY verifier
//! and never touches the nonce cache.

use std::sync::Arc;

use futures::StreamExt;
use talos_module_executions::ModuleExecutionService;
use talos_task_supervision::{spawn_supervised, BackgroundTask};
use talos_workflow_engine_core::WorkerKeyRing;
use talos_workflow_job_protocol::subjects::{CONTROLLER_RESULTS_QUEUE_GROUP, RESULTS_WILDCARD};

/// What the observer did with one message. Returned so a test can tell which
/// replica handled a result without reading logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservedResult {
    /// A `Success` result was handed to the completion writer.
    Completed,
    /// A `Failed` / `TimedOut` result was handed to the failure writer.
    Failed,
    /// The payload was not a `JobResult`; counted and WARNed.
    Unparseable,
    /// The signature or freshness check refused it; nothing was written.
    Unverified,
    /// The writer returned an error; WARNed.
    WriteFailed,
}

/// Record a `talos.results.*` message that would not deserialize into a
/// `JobResult`: bump `talos_job_results_dropped_unparseable_total` and say so
/// at WARN.
///
/// This was a bare `tracing::debug!` until 2026-08. Debug is not enabled by
/// default, so the drop left NO operator-visible trace — while the engine
/// dispatcher, handling the SAME condition on the SAME signed message type,
/// fails the node outright (`talos-workflow-engine-nats::dispatcher`,
/// `map_err(…)?`). Two handlers of one message, opposite treatment.
///
/// Debug WOULD have been defensible if the subscription were broad enough to
/// carry other traffic. It is not: `talos.results.*` is a single-token
/// wildcard, its only publisher is the worker's no-reply-topic branch,
/// pipeline results use `talos.pipeline.results.*`, and guest WASM is denied
/// the entire `talos.` prefix (`RESERVED_PUBLISH_PREFIXES`). An unparseable
/// message there is an anomaly by construction.
///
/// And the drop is expensive. This subscriber is the ONLY finalizer for the
/// FOUR fire-and-forget dispatch paths that publish with no reply inbox
/// (`reply_topic: None` and no wire `msg.reply`, so the worker's
/// `pick_trusted_reply_topic` takes its `(None, None)` arm and
/// `publish_result_with_retry` falls through to `talos.results.<job_id>`):
/// Gmail push, Google-Calendar push, GCP Monitoring Pub/Sub, and the webhook
/// **DLQ replay** (`talos_webhooks::router::dispatch_replay`, a bare
/// `nats.publish`, whose own comment names this subscriber by
/// `RESULTS_WILDCARD`). The LIVE webhook path is NOT one of them — it uses
/// `nats.request()`, so a wire reply exists and the result goes to that inbox.
/// Count the set from the publish call, not from the `reply_topic: None`
/// literal: two other comments in this repo enumerate "three" and name two
/// different threes. Losing one message loses that execution's
/// terminal status write, its `output_data`, and the `__ops_alert__` ingest
/// that hangs off `complete_execution_from_worker`; the stale sweep then
/// rewrites the row to `'timeout'`. That is the #638 shape.
///
/// **The serde error text is NOT logged.** It is derived from the message
/// payload, which on this path is worker output — the same secret-bearing
/// class the sibling failure log DLP-redacts. `serde_json` error text quotes
/// input around the failure point for several error kinds. Presence and count
/// only; `classify` is a closed set of `&'static str` and never a label.
///
/// Not routed through a shared warn-and-count helper — see the detector block
/// in `talos_metrics::TalosMetrics` for why a macro would re-blind check 58.
pub fn record_unparseable_job_result(err: &serde_json::Error) {
    if let Some(m) = talos_metrics::global() {
        m.job_results_dropped_unparseable_total.inc();
    }
    tracing::warn!(
        target: "talos_controller",
        event_kind = "job_result_unparseable",
        classify = classify_job_result_parse_error(err),
        "Job result on talos.results.* discarded: payload did not deserialize \
         into a JobResult. This subscriber is the only finalizer for \
         fire-and-forget module-bound dispatches, so the execution's terminal \
         status, output and ops-alert ingest are lost and the stale sweep will \
         mark it 'timeout'. Error text withheld (it can quote worker output)."
    );
}

/// Closed-set shape hint for a `JobResult` parse failure, safe to log because
/// it is derived only from `serde_json::Error::classify()` — a four-valued
/// enum — and never from the payload bytes.
///
/// `Eof` is the one worth naming: an EMPTY payload classifies `Eof`, and an
/// empty payload is what a NATS `503 no-responders` control message carries.
/// Nothing should ever send one to `talos.results.*` (it is a reply-inbox
/// mechanism), so seeing `Eof` here means something is publishing an empty
/// body to a subject only the worker should touch.
pub fn classify_job_result_parse_error(err: &serde_json::Error) -> &'static str {
    match err.classify() {
        serde_json::error::Category::Eof => "eof_empty_or_truncated",
        serde_json::error::Category::Syntax => "syntax",
        serde_json::error::Category::Data => "schema_mismatch",
        serde_json::error::Category::Io => "io",
    }
}

/// Handle one `talos.results.*` payload: parse, verify (no-replay), write.
pub async fn handle_result_message(
    payload: &[u8],
    service: &ModuleExecutionService,
    key_ring: Option<&WorkerKeyRing>,
) -> ObservedResult {
    let result = match serde_json::from_slice::<talos_workflow_job_protocol::JobResult>(payload) {
        Ok(r) => r,
        Err(e) => {
            record_unparseable_job_result(&e);
            return ObservedResult::Unparseable;
        }
    };
    let job_id = result.job_id;

    // SECURITY: Verify HMAC-SHA256 signature + freshness
    // window. Rejects results injected by any process that
    // can publish to NATS but does not know the pre-shared
    // key.
    //
    // Post-r301 the worker single-publishes: it sends a
    // result to EITHER the request-reply inbox OR
    // `talos.results.{job_id}` based on whether the
    // requester awaited the reply, never both. So this
    // subscriber only sees results that no other in-process
    // verifier has handled — there's no second verify to
    // race.
    //
    // We still call `verify_no_replay` here (not `verify`)
    // as defense-in-depth: it keeps this subscriber
    // safe-by-default if a future code path re-introduces a
    // dual-publish or a sibling subscriber, and the side
    // effect (`UPDATE module_executions WHERE status IN
    // ('pending','running')`) is idempotent under replay
    // anyway. HMAC + freshness still catch forgery and
    // stale-replay; the worker is the primary
    // replay-cache writer for fire-and-forget results.
    //
    // Today every NATS-dispatched code path uses
    // request-reply, so this subscriber is mostly dormant
    // — kept as the canonical landing point for future
    // truly-async dispatches (work-queue style).
    // L-4: typed Observer verifier — this audit
    // subscriber on `talos.results.*` only writes
    // an idempotent UPDATE; primary verification
    // happens at the request-reply inbox in the
    // engine dispatcher / webhook handler. Using
    // `Verifier::Observer` documents the role at
    // the type level so a future refactor can't
    // accidentally convert this site to a primary
    // verifier and reintroduce the r300 regression.
    if let Some(ring) = key_ring {
        // RFC 0010 P2: scheme-routing Observer verify —
        // Ed25519 against the keys registered for this
        // worker_id, or legacy HMAC against the ring
        // while `result_accept_legacy_hmac()`. NEVER
        // records the replay cache (Observer role): the
        // request-reply dispatcher is the sole Primary
        // verifier, per the verify-once rule.
        let worker_ed_keys = talos_workflow_job_protocol::worker_public_keys(&result.worker_id);
        if let Err(e) = result.verify_no_replay_dispatch(
            ring,
            &worker_ed_keys,
            300,
            talos_workflow_job_protocol::result_accept_legacy_hmac(),
        ) {
            tracing::warn!(
                target: "talos_security",
                job_id = %job_id,
                failure_kind = e.kind().label(),
                liveness = e.is_liveness(),
                age_secs = e.age_secs(),
                "{}",
                talos_workflow_job_protocol::describe_verify_failure(
                    "Job result",
                    &e,
                )
            );
            return ObservedResult::Unverified;
        }
    }
    tracing::debug!(
        "📥 Received job result: {} ({:?}, {}ms)",
        job_id,
        result.status,
        result.execution_time_ms
    );

    let terminal = if matches!(
        result.status,
        talos_workflow_job_protocol::JobStatus::Success
    ) {
        ObservedResult::Completed
    } else {
        ObservedResult::Failed
    };
    match result.status {
        talos_workflow_job_protocol::JobStatus::Success => {
            if let Err(e) = service
                .complete_execution_from_worker(
                    job_id,
                    // Storage takes the PARSED payload; the
                    // signature that covered the raw wire text
                    // was already verified above.
                    Some(result.output_payload.into_value()),
                    // `None`, NOT `result.execution_time_ms`.
                    //
                    // The worker's value IS a real monotonic
                    // measurement, but of a DIFFERENT SPAN:
                    // its own `execute_job`, which excludes the
                    // NATS round trip and any queue wait. Every
                    // other `duration_source = 'monotonic'` row
                    // in this table is a CONTROLLER-side
                    // dispatch span (the engine's
                    // `dispatch_started`, the webhook router's
                    // `wasm_start`). Storing a worker span under
                    // the same label would put two
                    // non-comparable quantities in one column —
                    // the mixed-meaning hazard `duration_source`
                    // exists to prevent.
                    //
                    // This subscriber has no controller-side
                    // timer to offer instead: it is a
                    // fire-and-forget observer of the global
                    // audit topic and never held the dispatch.
                    // So the trigger's `completed_at -
                    // started_at` derivation stays, correctly
                    // labelled `'wallclock'`, and a reader knows
                    // to distrust it.
                    None,
                )
                .await
            {
                tracing::warn!("Failed to mark execution {} as completed: {}", job_id, e);
                return ObservedResult::WriteFailed;
            } else {
                tracing::info!(
                    "✅ Execution {} completed ({}ms)",
                    job_id,
                    result.execution_time_ms
                );
            }
        }
        talos_workflow_job_protocol::JobStatus::Failed
        | talos_workflow_job_protocol::JobStatus::TimedOut => {
            let error_msg = result
                .output_payload
                .value()
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("Worker reported failure")
                .to_string();
            // `error_type` — the CAUSE. #744 derived it
            // at the ENGINE's finalizer and left this
            // observer's non-timeout arm passing
            // `None`, so a plain `Failed` result whose
            // text names its own cause stored nothing.
            //
            // TimedOut takes the STATUS, which is a
            // harder fact than the prose and needs no
            // guess — through the named constant, not a
            // second inline literal, because
            // `classify_error` answers with that exact
            // spelling and two spellings of one bucket
            // is the drift the shared home exists to
            // prevent (pinned by
            // `the_timeout_bucket_spelling_is_the_classifiers`).
            // Everything else derives from the same
            // text this call is about to store.
            let error_type = if matches!(
                result.status,
                talos_workflow_job_protocol::JobStatus::TimedOut
            ) {
                Some(talos_engine::module_error_type::TIMEOUT_BUCKET.to_string())
            } else {
                talos_engine::module_error_type::derive_error_type("failed", Some(&error_msg))
                    .map(str::to_string)
            };

            if let Err(e) = service
                .fail_execution_from_worker(
                    job_id,
                    error_msg.clone(),
                    error_type,
                    // `None` for the same reason as the
                    // success arm above: this observer holds
                    // no controller-side timer, and the
                    // worker's span is not the one every other
                    // 'monotonic' row in this column measures.
                    None,
                )
                .await
            {
                tracing::warn!("Failed to mark execution {} as failed: {}", job_id, e);
                return ObservedResult::WriteFailed;
            } else {
                // MCP-989 (2026-05-15): DLP-redact the
                // failure preview at the operator-log
                // boundary. `fail_execution_from_worker`
                // redacts before persisting to
                // `module_executions.error_message`
                // (MCP-968), but this INFO log was
                // taking the first 100 chars of the
                // ORIGINAL worker-supplied error_msg.
                // Worker failures regularly carry
                // upstream auth errors that echo the
                // rejected token in the body; secret-
                // shaped prefixes must not land in
                // operator log pipelines. Same
                // wrapper class as the two
                // talos-module-executions sites
                // closed in this MCP.
                let preview: String = talos_dlp_provider::redact_str(&error_msg)
                    .chars()
                    .take(100)
                    .collect();
                tracing::info!("❌ Execution {} failed: {}", job_id, preview);
            }
        }
    }
    terminal
}

/// Bind the subject. ONE bind site: a queue group, so NATS delivers each
/// result to one controller replica.
pub async fn bind_subscription(
    nats: &async_nats::Client,
) -> Result<async_nats::Subscriber, async_nats::SubscribeError> {
    nats.queue_subscribe(RESULTS_WILDCARD, CONTROLLER_RESULTS_QUEUE_GROUP.to_string())
        .await
}

/// Spawn the supervised observer. A stream end (NATS reconnect, server-side
/// unsubscribe) re-binds after 1 s instead of ending the task (MCP-1122); a
/// subscribe failure backs off, doubling to 60 s.
pub fn spawn_job_result_observer(
    nats: Arc<async_nats::Client>,
    service: Arc<ModuleExecutionService>,
    key_ring: Option<WorkerKeyRing>,
) {
    spawn_supervised(BackgroundTask::JobResultSubscriber, async move {
        tracing::info!("Starting job result subscriber on topic: talos.results.*");
        let mut backoff_secs: u64 = 1;
        loop {
            let mut sub = match bind_subscription(&nats).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(
                        target: "talos_controller",
                        event_kind = "job_result_subscribe_failed",
                        error = %e,
                        backoff_secs,
                        "Failed to subscribe to job results; retrying after backoff"
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                    backoff_secs = (backoff_secs * 2).min(60);
                    continue;
                }
            };
            backoff_secs = 1;
            tracing::info!("Job result subscriber active");
            while let Some(msg) = sub.next().await {
                let _ = handle_result_message(&msg.payload, &service, key_ring.as_ref()).await;
            }
            tracing::warn!(
                target: "talos_controller",
                event_kind = "job_result_subscriber_rebinding",
                "Job result subscriber stream ended; supervisor re-binding"
            );
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    /// The observer is a long-lived loop and goes through `spawn_supervised`.
    #[test]
    fn the_observer_is_supervised() {
        assert_eq!(
            talos_task_supervision::production_spawn_counts(include_str!("lib.rs")),
            (1, 0)
        );
    }

    /// TEXTUAL, stated as such: the loop binds through the one bind site and
    /// nothing in this crate plain-subscribes.
    #[test]
    fn the_subject_is_bound_once_and_in_a_queue_group() {
        let code: String = include_str!("lib.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap()
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(code.matches("queue_subscribe(").count(), 1);
        assert_eq!(code.matches(".subscribe(").count(), 0);
        assert_eq!(code.matches("bind_subscription(&nats)").count(), 1);
    }
}
