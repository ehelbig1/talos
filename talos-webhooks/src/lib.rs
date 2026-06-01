// MCP-946 (2026-05-15): kept `#![allow(dead_code)]` deliberately.
// The crate carries several pre-existing dead items audited in this
// sweep but not removable in a one-shot doc-style sweep:
//   * `DLQ_MAX_PENDING` const + `enqueue_webhook_dlq` function:
//     vestigial OLD-DLQ surface superseded by `DlqService` (stored
//     on WebhookRouter at line ~245). The old function does
//     DLP-aware header sanitization that no caller reaches.
//   * `event_sender: tokio::sync::broadcast::Sender<ExecutionEvent>`
//     field on WebhookRouter: stored in the constructor but never
//     read. Either the broadcast logic was supposed to wire up
//     and didn't, or the field is leftover from a refactor.
//   * `allow` method in src/rate_limiter.rs: dead implementation
//     (the WebhookRouter uses the IpRateLimiter via different
//     plumbing).
// Each needs careful surgical removal (constructor signature
// changes ripple to main.rs + tests for event_sender; the DLQ
// helpers contain non-trivial security logic worth verifying isn't
// the new path's de-facto contract). Tracked as cleanup follow-ups.
#![allow(dead_code)]
//! Webhook router manages incoming webhook requests with security features
//! including circuit breakers, rate limiting, HMAC verification, and DLQ support.
use anyhow::{Context, Result};
use axum::{
    body::Bytes,
    extract::Path,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension,
};
use sqlx::{Pool, Postgres, Row};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;
use uuid::Uuid;

use talos_engine::events::ExecutionEvent;
use talos_module_executions::ModuleExecutionService;
use talos_registry::ModuleRegistry;
use talos_secrets_manager::SecretsManager;
use talos_worker_fleet::WorkerManager;
use talos_workflow_engine_core::WorkerSharedKey;

#[allow(
    clippy::needless_borrow,
    clippy::needless_borrows_for_generic_args,
    clippy::option_as_ref_deref,
    clippy::too_many_arguments,
    clippy::unused_async
)]
mod rate_limiter;
pub use rate_limiter::CircuitBreaker;
pub use rate_limiter::CircuitBreakerFailureType;
use rate_limiter::RateLimiter;

// ============================================================================
// Dead Letter Queue (DLQ) System — Bounded, Backpressure-Aware
// ============================================================================

/// Maximum number of pending DLQ entries before dropping.
const DLQ_MAX_PENDING: usize = 10_000;
/// DLQ channel capacity for async processing.
const DLQ_CHANNEL_CAPACITY: usize = 1_000;

/// DLQ entry for failed webhook payloads.
#[derive(Debug, Clone)]
pub(crate) struct DlqEntry {
    trigger_id: Option<Uuid>,
    source_ip: Option<String>,
    drop_reason: String,
    headers: serde_json::Value,
    payload: serde_json::Value,
}

/// Global DLQ metrics for monitoring.
#[derive(Debug, Default)]
pub struct DlqMetrics {
    pub enqueued: AtomicUsize,
    pub dropped_queue_full: AtomicUsize,
    pub dropped_null_payload: AtomicUsize,
    pub db_errors: AtomicUsize,
}

impl DlqMetrics {
    pub fn new() -> Self {
        Self::default()
    }
}

/// DLQ service handle — cloneable reference to the async processor.
#[derive(Clone)]
pub struct DlqService {
    sender: mpsc::Sender<DlqEntry>,
    pub metrics: Arc<DlqMetrics>,
    pub dlq_event_sender: tokio::sync::broadcast::Sender<talos_engine::events::DlqEvent>,
    /// MCP-1131 (2026-05-16): shutdown signal for the background batch
    /// processor. Notified once from the controller's graceful_shutdown
    /// callback so the processor can flush its in-memory batch before
    /// the tokio runtime aborts it. The MCP-667 comment at
    /// `controller/src/main.rs` graceful_shutdown explicitly flagged
    /// "DLQ messages in-flight" as a known concern; this closes that
    /// gap.
    shutdown_notify: Arc<tokio::sync::Notify>,
}

impl DlqService {
    /// Create a new DLQ service with a background processor.
    pub fn new(
        db_pool: Pool<Postgres>,
        dlq_event_sender: tokio::sync::broadcast::Sender<talos_engine::events::DlqEvent>,
    ) -> Self {
        let (sender, mut receiver) = mpsc::channel::<DlqEntry>(DLQ_CHANNEL_CAPACITY);
        let metrics = Arc::new(DlqMetrics::new());
        let metrics_clone = metrics.clone();
        let dlq_tx = dlq_event_sender.clone();
        let shutdown_notify = Arc::new(tokio::sync::Notify::new());
        let shutdown_notify_task = shutdown_notify.clone();

        // Spawn background processor
        tokio::spawn(async move {
            let mut batch: Vec<DlqEntry> = Vec::with_capacity(100);
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));

            loop {
                tokio::select! {
                    biased;
                    // MCP-1131: shutdown arm — flush in-memory batch
                    // before the tokio runtime aborts this task on
                    // graceful controller shutdown.
                    _ = shutdown_notify_task.notified() => {
                        // Drain any entries already queued but not yet
                        // delivered to recv() so we don't lose them
                        // either. try_recv loops until empty.
                        while let Ok(entry) = receiver.try_recv() {
                            batch.push(entry);
                        }
                        if !batch.is_empty() {
                            tracing::info!(
                                target: "talos_webhooks",
                                event_kind = "dlq_shutdown_final_flush",
                                batch_size = batch.len(),
                                "DLQ processor flushing on graceful shutdown"
                            );
                            Self::flush_batch(&db_pool, &batch, &metrics_clone, &dlq_tx).await;
                            batch.clear();
                        }
                        break;
                    }
                    Some(entry) = receiver.recv() => {
                        batch.push(entry);
                        if batch.len() >= 100 {
                            Self::flush_batch(&db_pool, &batch, &metrics_clone, &dlq_tx).await;
                            batch.clear();
                        }
                    }
                    _ = interval.tick() => {
                        if !batch.is_empty() {
                            Self::flush_batch(&db_pool, &batch, &metrics_clone, &dlq_tx).await;
                            batch.clear();
                        }
                    }
                }
            }
        });

        Self {
            sender,
            metrics,
            dlq_event_sender,
            shutdown_notify,
        }
    }

    /// MCP-1131: signal the background batch processor to flush its
    /// in-memory batch and exit. Called by the controller's
    /// graceful_shutdown callback before the tokio runtime aborts
    /// the spawned task. Idempotent: subsequent calls are no-ops
    /// because `Notify::notify_one` only wakes the first waiter
    /// and the processor `break`s out of the loop on first
    /// notification.
    pub fn shutdown(&self) {
        self.shutdown_notify.notify_one();
    }

    /// Try to enqueue a DLQ entry. Returns false if channel is full.
    pub(crate) fn try_enqueue(&self, entry: DlqEntry) -> bool {
        match self.sender.try_send(entry) {
            Ok(_) => {
                self.metrics.enqueued.fetch_add(1, Ordering::Relaxed);
                // MCP-567: mirror the in-process atomic to the
                // process-global Prometheus counter. Pre-fix the DLQ
                // metrics in `talos-metrics` were registered but
                // never incremented anywhere — operators alerting on
                // `talos_dlq_drops_total > 0` got false-negatives
                // (always zero, looks like "no DLQ activity").
                if let Some(m) = talos_metrics::global() {
                    m.dlq_entries_total.inc();
                }
                true
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                self.metrics
                    .dropped_queue_full
                    .fetch_add(1, Ordering::Relaxed);
                if let Some(m) = talos_metrics::global() {
                    // Both: webhook-specific + generic DLQ drop counters
                    // (today they track the same path; the generic one
                    // is the future-proof aggregate if more DLQ paths
                    // land).
                    m.webhook_dlq_drops_total.inc();
                    m.dlq_drops_total.inc();
                }
                tracing::warn!("DLQ channel full — dropping webhook payload");
                false
            }
            Err(e) => {
                tracing::error!("DLQ channel error: {}", e);
                false
            }
        }
    }

    async fn flush_batch(
        db_pool: &Pool<Postgres>,
        batch: &Vec<DlqEntry>,
        metrics: &Arc<DlqMetrics>,
        dlq_tx: &tokio::sync::broadcast::Sender<talos_engine::events::DlqEvent>,
    ) {
        for entry in batch {
            // M T6-1: resolve workflow ownership at emit time so the
            // dlq_updates subscription can filter per-org without a
            // per-event DB lookup. Single statement: INSERT into
            // webhook_dlq RETURNING the new row's id+created_at AND
            // the JOINed workflow_id/user_id/org_id from
            // webhook_triggers→workflows. NULL on either side when
            // trigger or workflow has been deleted.
            let result = sqlx::query(
                r#"
                WITH inserted AS (
                    INSERT INTO webhook_dlq (trigger_id, source_ip, drop_reason, headers, payload)
                    VALUES ($1, $2::inet, $3, $4, $5)
                    RETURNING id, trigger_id, created_at
                )
                SELECT i.id, i.created_at, w.id AS workflow_id, w.user_id, w.org_id
                FROM inserted i
                LEFT JOIN webhook_triggers wt ON wt.id = i.trigger_id
                LEFT JOIN workflows w ON w.id = wt.workflow_id
                "#,
            )
            .bind(entry.trigger_id)
            .bind(&entry.source_ip)
            .bind(&entry.drop_reason)
            .bind(&entry.headers)
            .bind(&entry.payload)
            .fetch_one(db_pool)
            .await;

            match result {
                Ok(row) => {
                    // Broadcast event for real-time UI updates
                    let _ = dlq_tx.send(talos_engine::events::DlqEvent {
                        id: row.get("id"),
                        workflow_id: row.try_get("workflow_id").ok(),
                        execution_id: None,
                        node_id: None,
                        error_message: Some(entry.drop_reason.clone()),
                        payload: Some(entry.payload.to_string()),
                        created_at: row
                            .get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                            .to_rfc3339(),
                        replayed_at: None,
                        user_id: row.try_get("user_id").ok(),
                        org_id: row.try_get("org_id").ok(),
                    });
                }
                Err(e) => {
                    metrics.db_errors.fetch_add(1, Ordering::Relaxed);
                    // MCP-567: mirror to Prometheus. See try_enqueue.
                    if let Some(m) = talos_metrics::global() {
                        m.dlq_db_errors_total.inc();
                    }
                    tracing::error!("Failed to persist DLQ entry: {}", e);
                }
            }
        }
    }
}

// ============================================================================

/// Maximum webhook payload size (1 MB) to prevent memory exhaustion attacks.
const MAX_WEBHOOK_PAYLOAD_SIZE: usize = 1024 * 1024;

/// Webhook router manages incoming webhook requests
#[derive(Clone)]
pub struct WebhookRouter {
    db_pool: Pool<Postgres>,
    registry: Arc<ModuleRegistry>,
    secrets_manager: Arc<SecretsManager>,
    rate_limiter: Arc<RateLimiter>, // No RwLock needed - DashMap is lock-free
    circuit_breaker: Arc<CircuitBreaker>,
    nats_client: Arc<async_nats::Client>,
    worker_shared_key: Option<WorkerSharedKey>,
    worker_manager: Option<Arc<WorkerManager>>,
    module_execution_service: Option<Arc<ModuleExecutionService>>,
    event_sender: tokio::sync::broadcast::Sender<ExecutionEvent>,
    dlq_service: DlqService,
    /// Optional Redis-backed deduplication. When present, identical webhook deliveries
    /// (same trigger + same payload fingerprint) within the 1-hour window are suppressed.
    dedup: Option<std::sync::Arc<talos_idempotency::WebhookDeduplication>>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct WebhookTrigger {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub module_id: Option<Uuid>,
    pub workflow_id: Option<Uuid>,
    pub verification_token: Option<String>,
    /// Encrypted signing secret (nonce || ciphertext). Decrypted on demand via SecretsManager.
    /// The legacy plaintext `signing_secret` column has been removed.
    pub signing_secret_enc: Option<Vec<u8>>,
    pub signing_key_id: Option<Uuid>,
    /// MCP-S2: AEAD AAD format version for `signing_secret_enc`.
    /// 0 = legacy no-AAD, 1 = AAD-bound to `id`. Decrypt dispatches via
    /// `SecretsManager::decrypt_versioned`.
    #[sqlx(default)]
    pub signing_secret_format: i16,
    pub allowed_ips: Option<Vec<String>>,
    pub enabled: bool,
    pub auto_respond: bool,
    pub queue_events: bool,
    pub max_requests_per_minute: i32,
    /// When true, the webhook handler waits for workflow completion and returns
    /// the output in the HTTP response body. Enables synchronous request-response
    /// patterns (e.g., Slack slash commands, API gateways).
    pub sync_response: bool,
    /// Maximum seconds to wait for workflow completion in sync mode.
    /// Returns HTTP 504 Gateway Timeout if exceeded.
    pub sync_timeout_secs: i32,
}

/// Auth-downgrade guard predicate (MEDIUM finding).
///
/// Returns `true` when the webhook MUST fail closed because an HMAC
/// signing secret was CONFIGURED on the trigger (`signing_secret_enc`
/// present) but could not be RESOLVED (decryption failed, so the
/// decrypted secret is `None`). In that state the handler must NOT fall
/// through to the static `verification_token` branch — doing so would be
/// a silent HMAC -> static-token auth downgrade, re-enabling a long-lived
/// UUID token the operator was told is permanently off once a signing
/// secret is set.
///
/// Pure function so the security-critical predicate is unit-tested without
/// a DB pool / SecretsManager / NATS (`handle_webhook` is not isolatable).
pub(crate) fn webhook_must_fail_closed_on_hmac(
    hmac_configured: bool,
    hmac_secret_resolved: bool,
) -> bool {
    hmac_configured && !hmac_secret_resolved
}

/// Absolute difference in seconds between `now_secs` and a caller-supplied
/// `ts_secs` (a webhook timestamp header), using overflow-free `i64::abs_diff`.
///
/// `(now_secs - ts_secs).abs()` is NOT safe here: `ts_secs` is parsed from an
/// attacker-controlled header, so a value near `i64::MIN` overflows the
/// subtraction. In debug builds that panics (a request-triggered DoS); in
/// release the wrapped result can land on `i64::MIN`, whose `.abs()` stays
/// negative — so a `> window` freshness check silently PASSES a stale request.
/// `abs_diff` returns `u64` and cannot overflow, so the freshness gate holds
/// for every possible `ts_secs`.
fn webhook_timestamp_skew_secs(now_secs: i64, ts_secs: i64) -> u64 {
    now_secs.abs_diff(ts_secs)
}

impl WebhookRouter {
    /// MCP-1131 (2026-05-16): signal the DLQ batch processor to flush
    /// its in-memory batch and exit before tokio aborts the task.
    /// Called by the controller's graceful_shutdown callback. Closes
    /// the explicit "DLQ messages in-flight" concern from MCP-667.
    pub fn shutdown_dlq(&self) {
        self.dlq_service.shutdown();
    }

    /// Creates a new `WebhookRouter`. Returns an error if the WASM runtime cannot be initialized.
    pub fn new(
        db_pool: Pool<Postgres>,
        registry: Arc<ModuleRegistry>,
        secrets_manager: Arc<SecretsManager>,
        nats_client: Arc<async_nats::Client>,
        worker_shared_key: Option<WorkerSharedKey>,
        circuit_breaker: Arc<CircuitBreaker>,
        worker_manager: Option<Arc<WorkerManager>>,
        module_execution_service: Option<Arc<ModuleExecutionService>>,
        event_sender: tokio::sync::broadcast::Sender<ExecutionEvent>,
        dlq_event_sender: tokio::sync::broadcast::Sender<talos_engine::events::DlqEvent>,
        dedup: Option<std::sync::Arc<talos_idempotency::WebhookDeduplication>>,
    ) -> anyhow::Result<Self> {
        let dlq_service = DlqService::new(db_pool.clone(), dlq_event_sender);
        Ok(Self {
            db_pool,
            registry,
            secrets_manager,
            rate_limiter: Arc::new(RateLimiter::new()), // No RwLock - DashMap is lock‑free
            circuit_breaker,
            nats_client,
            worker_shared_key,
            worker_manager,
            module_execution_service,
            event_sender,
            dlq_service,
            dedup,
        })
    }

    /// Enqueue a dropped webhook payload into the dead-letter queue.
    /// Uses the bounded DLQ service with backpressure — never blocks the response path.
    fn enqueue_dlq(
        &self,
        trigger_id: Option<Uuid>,
        source_ip: Option<std::net::IpAddr>,
        drop_reason: &'static str,
        headers: &axum::http::HeaderMap,
        body: &axum::body::Bytes,
    ) {
        // Build a sanitized header map (strip auth material).
        // Rather than maintaining an exact allowlist, pattern-match on substrings that
        // commonly appear in sensitive headers — this catches custom auth schemes too.
        fn header_is_sensitive(name: &str) -> bool {
            let n = name.to_lowercase();
            n == "cookie"
                || n.contains("auth")
                || n.contains("token")
                || n.contains("secret")
                || n.contains("key")
                || n.contains("credential")
                || n.contains("password")
                || n.contains("signature")
        }
        let mut header_map = serde_json::Map::new();
        for (name, value) in headers.iter() {
            if header_is_sensitive(name.as_str()) {
                // Record presence but not value, so the DLQ entry is debuggable without leaking secrets.
                header_map.insert(
                    name.to_string(),
                    serde_json::Value::String("[redacted]".to_string()),
                );
                continue;
            }
            if let Ok(v) = value.to_str() {
                // MCP-974 (2026-05-15): DLP-redact non-sensitive
                // header VALUES too. The name-based `header_is_sensitive`
                // filter catches canonical auth headers (cookie, Bearer,
                // signature, etc.) but a misconfigured client can stash
                // a secret in any custom header — `X-Trace-Id`,
                // `X-Customer-Ref`, etc. — and operators can't enumerate
                // every third-party convention. The sibling
                // `enqueue_webhook_dlq` site (line ~2877) already runs
                // `redact_str` on each non-sensitive header value; this
                // brings the entry-level DLQ path in line.
                let scrubbed = talos_dlp_provider::redact_str(v);
                header_map.insert(name.to_string(), serde_json::Value::String(scrubbed));
            }
        }
        let headers_json = serde_json::Value::Object(header_map);

        // Parse and DLP-scrub the payload
        let payload_json =
            serde_json::from_slice::<serde_json::Value>(body).unwrap_or(serde_json::Value::Null);

        // Skip null payloads (parse failure on empty bodies)
        if payload_json.is_null() {
            self.dlq_service
                .metrics
                .dropped_null_payload
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // MCP-567: mirror to Prometheus. Null-payload drops are
            // counted under the generic `dlq_drops_total` (same as
            // queue-full drops) so operators can alert on "any DLQ
            // drop" without enumerating reasons.
            if let Some(m) = talos_metrics::global() {
                m.dlq_drops_total.inc();
            }
            return;
        }

        let scrubbed_payload = talos_dlp_provider::redact_json(&payload_json);

        let entry = DlqEntry {
            trigger_id,
            source_ip: source_ip.map(|ip| ip.to_string()),
            drop_reason: drop_reason.to_string(),
            headers: headers_json,
            payload: scrubbed_payload,
        };

        // Try to enqueue — may drop if channel is full (backpressure)
        if !self.dlq_service.try_enqueue(entry) {
            tracing::warn!(
                trigger_id = ?trigger_id,
                drop_reason = drop_reason,
                "DLQ entry dropped due to channel capacity"
            );
        }
    }

    /// Handle an incoming webhook request
    pub async fn handle_webhook(
        &self,
        trigger_id: Uuid,
        headers: &HeaderMap,
        body: Bytes,
        source_ip: Option<IpAddr>,
    ) -> Result<Response> {
        let start_time = Instant::now();

        // SECURITY: Validate content type to prevent MIME-confusion attacks.
        // Browsers allow cross-origin POST with text/plain (no preflight), so accepting
        // text/plain would enable CSRF attacks where a victim's browser sends a
        // text/plain body that happens to parse as JSON. Only accept true JSON types.
        // application/x-www-form-urlencoded is kept for legacy webhook senders.
        // text/plain and application/octet-stream are intentionally excluded.
        if let Some(content_type) = headers.get("content-type").and_then(|v| v.to_str().ok()) {
            let content_type_lower = content_type.to_lowercase();
            let allowed_types = ["application/json", "application/x-www-form-urlencoded"];
            if !allowed_types
                .iter()
                .any(|&t| content_type_lower.starts_with(t))
            {
                tracing::warn!(
                    trigger_id = %trigger_id,
                    content_type = %content_type,
                    "Rejected webhook with disallowed content type"
                );
                return Ok((
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "Unsupported content type",
                )
                    .into_response());
            }
        }

        // SECURITY: Validate payload size (already limited by middleware, but double-check)
        if body.len() > MAX_WEBHOOK_PAYLOAD_SIZE {
            tracing::warn!(
                trigger_id = %trigger_id,
                size = body.len(),
                max = MAX_WEBHOOK_PAYLOAD_SIZE,
                "Rejected webhook with oversized payload"
            );
            return Ok((StatusCode::PAYLOAD_TOO_LARGE, "Payload too large").into_response());
        }

        // 0. Circuit breaker check — cheapest gate, runs before any DB query or HMAC.
        if let Some(ip) = source_ip {
            if self.circuit_breaker.is_blocked(ip) {
                tracing::warn!(
                    trigger_id = %trigger_id,
                    ip = %ip,
                    "Circuit breaker open: blocking request from repeatedly-failing IP"
                );
                // Persist to DLQ so the payload can be replayed later
                if !body.is_empty() {
                    self.enqueue_dlq(
                        Some(trigger_id),
                        source_ip,
                        "circuit_breaker",
                        headers,
                        &body,
                    );
                }
                return Ok((StatusCode::TOO_MANY_REQUESTS, "Too many requests").into_response());
            }
        }

        // 1. Lookup trigger configuration
        let trigger = self.get_trigger(trigger_id).await?;

        if !trigger.enabled {
            tracing::warn!(
                trigger_id = %trigger_id,
                "Webhook trigger is disabled"
            );
            // Trigger disabled counts as auth failure for CB tracking
            if let Some(ip) = source_ip {
                self.circuit_breaker
                    .record_failure_with_type(ip, CircuitBreakerFailureType::TriggerDisabled);
            }
            return Ok((StatusCode::NOT_FOUND, "Not found").into_response());
        }

        // 2. Check rate limit (lock-free with DashMap).
        // Two limits are checked: per-trigger (operator-configured) and per-user
        // aggregate (TALOS_WEBHOOK_USER_RPM, default 300). Both must pass.
        // This prevents a user from registering N triggers to bypass per-trigger limits.
        let user_max_rpm = rate_limiter::configured_user_webhook_rpm();
        // MCP-813 (2026-05-14): defense-in-depth read-side clamp. MCP-812
        // closed the write-time path (GraphQL `create_webhook_trigger`
        // now rejects max_requests_per_minute outside [1, 10000]), but
        // the column type is `INTEGER` (signed i32) and legacy rows or
        // direct-SQL inserts can still carry negative or zero values.
        // Pre-fix `trigger.max_requests_per_minute as usize` on 64-bit
        // platforms underflows `-1i32 as usize` to 18446744073709551615,
        // which the token-bucket treats as "unlimited burst". Mirror
        // the write-time bounds [1, 10000] at the cast site so a
        // misconfigured row caps at sane per-trigger throughput rather
        // than effectively disabling the per-trigger limit. The
        // aggregate per-user limit at the second bucket still applies.
        // Sibling defense to MCP-811 / MCP-767 (the read-side
        // counterpart to the write-side bounds).
        let trigger_rpm = trigger.max_requests_per_minute.clamp(1, 10_000) as usize;
        let (trigger_ok, user_ok) = self.rate_limiter.allow_for_trigger(
            trigger_id,
            trigger_rpm,
            trigger.user_id,
            user_max_rpm,
        );
        if !trigger_ok || !user_ok {
            if !trigger_ok {
                tracing::warn!(trigger_id = %trigger_id, "Webhook per-trigger rate limit exceeded");
            } else {
                tracing::warn!(
                    trigger_id = %trigger_id,
                    user_id = %trigger.user_id,
                    "Webhook per-user aggregate rate limit exceeded"
                );
            }
            // Sustained hammering indicates abuse; count as a CB failure.
            if let Some(ip) = source_ip {
                self.circuit_breaker
                    .record_failure_with_type(ip, CircuitBreakerFailureType::RateLimitExceeded);
            }
            // Persist to DLQ so the payload can be replayed later
            if !body.is_empty() {
                self.enqueue_dlq(Some(trigger_id), source_ip, "rate_limit", headers, &body);
            }
            self.log_request(
                trigger_id,
                headers,
                &body,
                source_ip,
                StatusCode::TOO_MANY_REQUESTS.as_u16() as i32,
                None,
                0,
                0,
                false,
                Some("Rate limit exceeded"),
            )
            .await;
            return Ok((StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded").into_response());
        }

        // 3. Check IP allowlist
        if let Some(allowed_ips) = &trigger.allowed_ips {
            if !allowed_ips.is_empty() {
                if let Some(ip) = source_ip {
                    // Parse stored strings to IpAddr before comparing — string equality
                    // fails for equivalent addresses with different representations
                    // (e.g. "::ffff:1.2.3.4" vs "1.2.3.4", or leading zeros).
                    // Invalid entries are logged as an operator error and treated as
                    // non-matching (deny by default), but should not reach this path
                    // since create_webhook_trigger validates IPs at insertion time.
                    let mut allowed = false;
                    for stored in allowed_ips {
                        if let Ok(network) = stored.parse::<ipnetwork::IpNetwork>() {
                            if network.contains(ip) {
                                allowed = true;
                                break;
                            }
                        } else if let Ok(a) = stored.parse::<std::net::IpAddr>() {
                            if a == ip {
                                allowed = true;
                                break;
                            }
                        } else {
                            tracing::error!(
                                trigger_id = %trigger_id,
                                invalid_ip = %stored,
                                "Malformed IP/CIDR in allowed_ips list — failing immediately"
                            );
                            self.log_request(
                                trigger_id,
                                headers,
                                &body,
                                source_ip,
                                StatusCode::INTERNAL_SERVER_ERROR.as_u16() as i32,
                                None,
                                0,
                                0,
                                false,
                                Some("Invalid IP/CIDR configuration"),
                            )
                            .await;
                            return Ok((
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "Invalid IP/CIDR configuration",
                            )
                                .into_response());
                        }
                    }
                    if !allowed {
                        tracing::warn!(
                            trigger_id = %trigger_id,
                            ip = %ip,
                            "IP not in allowlist"
                        );
                        // IP allowlist rejection counts as auth failure for CB tracking
                        self.circuit_breaker
                            .record_failure_with_type(ip, CircuitBreakerFailureType::IpNotAllowed);
                        self.log_request(
                            trigger_id,
                            headers,
                            &body,
                            source_ip,
                            StatusCode::FORBIDDEN.as_u16() as i32,
                            None,
                            0,
                            0,
                            false,
                            Some("IP not allowed"),
                        )
                        .await;
                        return Ok((StatusCode::FORBIDDEN, "Forbidden").into_response());
                    }
                }
            }
        }

        // 4. Verify request authenticity.
        //
        //    Priority: HMAC signing_secret (strongest) → verification_token (static fallback).
        //    If neither is configured the webhook is open (no authentication).
        //
        //    The signing secret is stored encrypted (AES-256-GCM via SecretsManager).
        //    It is decrypted in-memory here and never written to any log.
        // L T2-3: SecretsManager::decrypt_value_by_key returns
        // Zeroizing<String> so the HMAC signing secret is wiped from
        // the heap on drop. The HMAC verifier takes `&str`; the deref
        // path works transparently.
        //
        // MEDIUM (auth downgrade): distinguish "HMAC was CONFIGURED" from
        // "HMAC secret RESOLVED". The presence of a stored encrypted
        // signing secret (`signing_secret_enc`) is the operator's intent
        // to require HMAC; the operator-facing create_webhook contract
        // guarantees the static-token fallback is PERMANENTLY off once a
        // signing secret is set. `decrypted_signing_secret` becomes None
        // not only when no secret is configured, but ALSO when decryption
        // FAILS (key rotation, DEK/KMS outage, corrupted ciphertext,
        // AAD/format mismatch). Without tracking the configured-flag
        // separately, a transient decrypt failure would silently fall
        // through to the verification_token branch below — re-enabling a
        // long-lived static UUID token the operator believes is off. We
        // fail closed instead: configured-but-unresolved => 401.
        let hmac_configured = trigger.signing_secret_enc.is_some();
        let decrypted_signing_secret: Option<zeroize::Zeroizing<String>> = match (
            &trigger.signing_secret_enc,
            trigger.signing_key_id,
        ) {
            (Some(enc), Some(key_id)) => {
                // MCP-S2: dispatch on the per-row format version. v0 rows
                // (existing pre-fix) decrypt with empty AAD; v1 rows
                // decrypt with AAD = trigger.id bytes. A swapped
                // ciphertext (attacker DB-write) fails AES-GCM tag
                // verification on v1 rows and is logged as a decryption
                // failure — the webhook then falls back to
                // verification_token (or rejects, depending on policy).
                match self
                    .secrets_manager
                    .decrypt_versioned(
                        key_id,
                        enc,
                        trigger.id.as_bytes(),
                        trigger.signing_secret_format,
                    )
                    .await
                {
                    Ok(s) => Some(s),
                    Err(e) => {
                        // Do NOT leak the internal error detail (or any
                        // secret/ciphertext) to the response — log it at
                        // WARN with only the trigger id so operators can
                        // correlate to a DEK/rotation/KMS outage. The
                        // caller gets a generic 401 from the fail-closed
                        // branch below (hmac_configured && None).
                        tracing::warn!(
                            trigger_id = %trigger_id,
                            "Failed to decrypt webhook signing secret — HMAC is configured but the \
                             secret could not be resolved (DEK/KMS outage, key rotation, corrupted \
                             ciphertext, or AAD/format mismatch); failing closed: {}",
                            e
                        );
                        None
                    }
                }
            }
            _ => None,
        };
        if let Some(ref signing_secret) = decrypted_signing_secret {
            // MCP-1100 (2026-05-16): GitHub-format webhooks include no
            // timestamp header, so their HMAC signature is replayable
            // indefinitely without the deduplication store. Slack
            // (`x-slack-signature`) and the generic format
            // (`x-signature` + `x-webhook-timestamp`) both bind a
            // timestamp into the signed material with a ±5-minute
            // freshness window — replays past that window fail. GitHub
            // (`x-hub-signature-256`) signs the body alone, and the
            // ONLY replay defense is the dedup-store lookup later in
            // this handler. If dedup is unavailable (production
            // deployment without REDIS_URL, or Redis hard-down between
            // boot and the request), a captured GitHub webhook can be
            // replayed against the controller indefinitely with a
            // valid signature.
            //
            // Refuse the GitHub format up front when dedup isn't
            // available — caller sees the same Unauthorized response
            // as a signature-mismatch, so no information disclosure
            // about the deployment state. Slack / generic flows are
            // unaffected (their timestamp check still binds replays).
            if headers.contains_key("x-hub-signature-256") && self.dedup.is_none() {
                tracing::warn!(
                    trigger_id = %trigger_id,
                    "GitHub-format webhook received but webhook deduplication is not configured — \
                     refusing to authenticate without replay protection. Configure REDIS_URL so \
                     WebhookDeduplication is wired up."
                );
                if let Some(ip) = source_ip {
                    self.circuit_breaker
                        .record_failure_with_type(ip, CircuitBreakerFailureType::InvalidSignature);
                }
                self.log_request(
                    trigger_id,
                    headers,
                    &body,
                    source_ip,
                    StatusCode::UNAUTHORIZED.as_u16() as i32,
                    None,
                    0,
                    0,
                    false,
                    Some("Invalid signature"),
                )
                .await;
                return Ok((StatusCode::UNAUTHORIZED, "Invalid signature").into_response());
            }
            // HMAC path — verifies integrity and authenticity of the full payload.
            if !self.verify_hmac_signature(headers, &body, signing_secret) {
                tracing::warn!(
                    trigger_id = %trigger_id,
                    "HMAC signature verification failed"
                );
                if let Some(ip) = source_ip {
                    self.circuit_breaker
                        .record_failure_with_type(ip, CircuitBreakerFailureType::InvalidSignature);
                }
                self.log_request(
                    trigger_id,
                    headers,
                    &body,
                    source_ip,
                    StatusCode::UNAUTHORIZED.as_u16() as i32,
                    None,
                    0,
                    0,
                    false,
                    Some("Invalid signature"),
                )
                .await;
                return Ok((StatusCode::UNAUTHORIZED, "Invalid signature").into_response());
            }
        } else if webhook_must_fail_closed_on_hmac(
            hmac_configured,
            decrypted_signing_secret.is_some(),
        ) {
            // FAIL CLOSED: HMAC was configured on this trigger
            // (`signing_secret_enc` is present) but the secret could not
            // be decrypted (see the WARN logged at the decrypt site).
            // Falling through to the static-token branch here would be a
            // silent HMAC -> static-token auth DOWNGRADE: the
            // verification_token is a long-lived UUID the operator was
            // told is permanently disabled once a signing secret is set.
            // A transient DEK/KMS/rotation outage must NEVER re-enable it.
            // Mirror the GitHub-format `dedup.is_none()` fail-closed shape
            // above — generic 401, no internal detail in the response.
            tracing::warn!(
                trigger_id = %trigger_id,
                "Webhook has an HMAC signing secret configured but it could not be resolved — \
                 refusing to fall back to the static verification token (auth-downgrade guard). \
                 Check for a DEK/KMS outage or in-progress key rotation."
            );
            if let Some(ip) = source_ip {
                self.circuit_breaker
                    .record_failure_with_type(ip, CircuitBreakerFailureType::InvalidSignature);
            }
            self.log_request(
                trigger_id,
                headers,
                &body,
                source_ip,
                StatusCode::UNAUTHORIZED.as_u16() as i32,
                None,
                0,
                0,
                false,
                Some("Invalid signature"),
            )
            .await;
            return Ok((StatusCode::UNAUTHORIZED, "Invalid signature").into_response());
        } else if let Some(expected_token) = &trigger.verification_token {
            // Static token fallback — used when the caller cannot compute HMAC
            // (e.g. simple webhook forwarders).  The caller must supply the token
            // in the X-Verification-Token header.  Comparison is constant-time to
            // prevent timing side-channels.
            use subtle::ConstantTimeEq;
            let provided = headers
                .get("x-verification-token")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            // MCP-629 (2026-05-12): empty-string ct_eq bypass class. The
            // storage path always sets `verification_token` to a fresh
            // `Uuid::new_v4()` (36 chars), so an empty stored token is
            // impossible via the documented surface. But defense-in-depth
            // requires the verify path to reject empty values: pre-fix,
            // a stored `expected_token = ""` combined with a request
            // missing the X-Verification-Token header (so
            // `provided = ""`) would have produced
            // `ct_eq(&[], &[]) == 1` and authenticated. Same auth-bypass
            // class as MCP-590/591/592/628 — auth gates must reject
            // empty values before constant-time compare.
            if expected_token.is_empty() || provided.is_empty() {
                tracing::warn!(
                    trigger_id = %trigger_id,
                    expected_empty = expected_token.is_empty(),
                    provided_empty = provided.is_empty(),
                    "Verification token rejected: empty value (storage path enforces UUID; \
                     either header missing or stored token bypassed validation)"
                );
                if let Some(ip) = source_ip {
                    self.circuit_breaker.record_failure_with_type(
                        ip,
                        CircuitBreakerFailureType::InvalidVerificationToken,
                    );
                }
                return Ok((StatusCode::UNAUTHORIZED, "Invalid verification token").into_response());
            }
            if expected_token
                .as_bytes()
                .ct_eq(provided.as_bytes())
                .unwrap_u8()
                != 1
            {
                tracing::warn!(
                    trigger_id = %trigger_id,
                    "Verification token check failed"
                );
                if let Some(ip) = source_ip {
                    self.circuit_breaker.record_failure_with_type(
                        ip,
                        CircuitBreakerFailureType::InvalidVerificationToken,
                    );
                }
                self.log_request(
                    trigger_id,
                    headers,
                    &body,
                    source_ip,
                    StatusCode::UNAUTHORIZED.as_u16() as i32,
                    None,
                    0,
                    0,
                    false,
                    Some("Invalid verification token"),
                )
                .await;
                return Ok((StatusCode::UNAUTHORIZED, "Invalid verification token").into_response());
            }
        }

        // 5. Deduplication: suppress re-delivery of the same webhook within the window.
        //    Event fingerprint = first recognizable signature header, else SHA-256 of body.
        //    Using the signature ensures that retries with the same payload are suppressed
        //    without false-positives for intentionally repeated payloads with different content.
        if let Some(ref dedup) = self.dedup {
            let raw_event_id: String = headers
                .get("x-signature")
                .or_else(|| headers.get("x-hub-signature-256"))
                .or_else(|| headers.get("x-slack-signature"))
                .or_else(|| headers.get("x-github-delivery"))
                .or_else(|| headers.get("x-request-id"))
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string())
                .unwrap_or_else(|| {
                    // Fall back to SHA-256 of the body as a stable fingerprint.
                    use sha2::{Digest, Sha256};
                    let mut hasher = Sha256::new();
                    hasher.update(&body);
                    hex::encode(hasher.finalize())
                });

            // MCP-1101 (2026-05-16): bound the Redis key length by
            // hashing oversized event_ids. Legitimate signature/delivery
            // headers are ≤128 chars (GitHub UUID = 36, Slack `v0=…` =
            // 67, GitHub `sha256=…` = 71, generic `X-Signature` 64-128
            // hex chars). HTTP headers themselves can carry ~64KB —
            // pre-fix a malicious sender could ship a 64KB event_id and
            // get the controller to write a 64KB Redis key in the
            // `webhook:processed:<trigger>:` namespace per request. At
            // the trigger's max-requests-per-minute (default 60), that's
            // ~4MB of Redis memory burned per attacker-controlled
            // trigger per minute. Also bounds the log line size
            // downstream (event_id = %event_id at line ~840). 512 covers
            // any legitimate format with comfortable headroom.
            const MAX_EVENT_ID_LEN: usize = 512;
            let event_id: String = if raw_event_id.len() > MAX_EVENT_ID_LEN {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(raw_event_id.as_bytes());
                tracing::warn!(
                    trigger_id = %trigger_id,
                    raw_len = raw_event_id.len(),
                    "Oversized webhook event-id header — hashing to bound Redis key size"
                );
                hex::encode(hasher.finalize())
            } else {
                raw_event_id
            };

            match dedup.is_duplicate(trigger_id, &event_id).await {
                Ok(true) => {
                    tracing::info!(
                        trigger_id = %trigger_id,
                        event_id = %event_id,
                        "Suppressed duplicate webhook delivery"
                    );
                    // Return 200 so the sender does not retry; log at INFO not WARN.
                    return Ok((StatusCode::OK, "OK").into_response());
                }
                Ok(false) => {}
                Err(e) => {
                    // Dedup unavailable — log and continue rather than blocking the request.
                    tracing::warn!(
                        trigger_id = %trigger_id,
                        "Webhook deduplication check failed (non-fatal): {}",
                        e
                    );
                }
            }
        }

        // 6. Handle Trigger (Module or Workflow)
        if let Some(module_id) = trigger.module_id {
            // Load WASM module (pass user_id to enforce ownership)
            let _module_bytes = match self
                .registry
                .get_module_bytes(module_id, trigger.user_id)
                .await
            {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::error!(
                        trigger_id = %trigger_id,
                        module_id = %module_id,
                        error = %e,
                        "Failed to load WASM module"
                    );
                    self.log_request(
                        trigger_id,
                        headers,
                        &body,
                        source_ip,
                        StatusCode::INTERNAL_SERVER_ERROR.as_u16() as i32,
                        None,
                        0,
                        0,
                        false,
                        Some(&format!("Failed to load module: {}", e)),
                    )
                    .await;
                    return Ok((StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
                        .into_response());
                }
            };

            // 6. Get module config and resolve secrets (pass user_id to enforce ownership)
            let module_config = match self
                .registry
                .get_module_config(module_id, trigger.user_id)
                .await
            {
                Ok(Some(config)) => config,
                Ok(None) => serde_json::json!({}),
                Err(e) => {
                    tracing::error!(
                        trigger_id = %trigger_id,
                        error = %e,
                        "Failed to get module config"
                    );
                    self.log_request(
                        trigger_id,
                        headers,
                        &body,
                        source_ip,
                        StatusCode::INTERNAL_SERVER_ERROR.as_u16() as i32,
                        None,
                        0,
                        0,
                        false,
                        Some(&format!("Failed to get module config: {}", e)),
                    )
                    .await;
                    return Ok((StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
                        .into_response());
                }
            };

            // 7. Parse raw body into JSON (or keep as string) and wrap with config.
            let body_str = match std::str::from_utf8(&body) {
                Ok(s) => s.to_string(),
                Err(_) => {
                    tracing::warn!(
                        trigger_id = %trigger_id,
                        "Webhook body contains invalid UTF-8; rejecting request"
                    );
                    return Ok(
                        (StatusCode::BAD_REQUEST, "Invalid UTF-8 in request body").into_response()
                    );
                }
            };
            let payload_value = serde_json::from_str::<serde_json::Value>(&body_str)
                .unwrap_or(serde_json::Value::String(body_str.clone()));

            // Wrap webhook payload with config. `__trigger_input__` honors the
            // scaffold contract that original trigger fields are ALWAYS reachable
            // via `data["__trigger_input__"]` — webhooks deliver at data["input"]
            // for the primary path, but modules that follow the standard
            // "trigger-input escape hatch" pattern also resolve here. Cheap
            // duplication; prevents the "works from trigger_workflow but not
            // from webhook" DX trap (pain point #13, 2026-04-23).
            let wrapped_input = serde_json::json!({
                "config": module_config,
                "input": payload_value.clone(),
                "__trigger_input__": payload_value,
            });

            // 8. Execute WASM module
            let wasm_start = Instant::now();
            let job_id = Uuid::new_v4();

            // Phase A: encrypt the webhook payload at rest before insert.
            // self.secrets_manager is always present at WebhookRouter
            // construction (constructor takes Arc<SecretsManager>), so the
            // bundle's `encrypting()` flag should always be true here —
            // the conditional write keeps the codepath robust to future
            // configurations where SecretsManager might be optional.
            // MCP-S2: AAD = job_id binds the webhook payload ciphertext
            // to its module_executions row.
            let payload_bundle = match talos_module_payload_encryption::encrypt_payload_bundle(
                Some(&self.secrets_manager),
                job_id,
                Some(&payload_value),
                None,
                None,
            )
            .await
            {
                Ok(b) => b,
                Err(e) => {
                    tracing::error!("Failed to encrypt webhook payload: {}", e);
                    talos_module_payload_encryption::EncryptedPayloadBundle::default()
                }
            };
            // MCP-987 (2026-05-15): DLP-redact the plaintext-fallback
            // path. When `encrypt_payload_bundle` succeeds (the
            // production-default branch), `pt_payload` is None and the
            // ciphertext lands in `input_data_enc` — operators querying
            // `module_executions.input_data` see NULL and can't read
            // anything sensitive. When encryption fails (KMS outage,
            // DEK rotation race, SecretsManager wiring gap), we fall
            // back to binding plaintext to `input_data`. Webhook
            // bodies routinely carry secrets — provider callbacks
            // echo bearer tokens for diagnostic purposes, signing
            // signatures land in the JSON payload itself. Without
            // redaction the failure path silently lands raw user
            // input + secret-shaped values in a queryable column.
            // Same defense-in-depth shape as MCP-971/972/975 on
            // workflow_executions; sibling fix at
            // talos-engine/src/module_execution_store.rs.
            let redacted_pt_payload = if payload_bundle.encrypting() {
                None
            } else {
                Some(talos_dlp_provider::redact_json(&payload_value))
            };
            if let Err(e) = sqlx::query(
                "INSERT INTO module_executions (id, module_id, user_id, status, \
                  input_data, input_data_enc, payload_enc_key_id, payload_format, \
                  workflow_execution_id, trigger_type, started_at)
                 VALUES ($1, $2, $3, 'running', $4, $5, $6, $7, $8, 'webhook', NOW())
                 ON CONFLICT DO NOTHING",
            )
            .bind(job_id)
            .bind(module_id)
            .bind(trigger.user_id)
            .bind(redacted_pt_payload.as_ref())
            .bind(payload_bundle.input_enc.as_deref())
            .bind(payload_bundle.key_id)
            .bind(payload_bundle.format_version)
            .bind(None::<Uuid>)
            .execute(&self.db_pool)
            .await
            {
                tracing::error!("Failed to insert module_execution for webhook: {}", e);
            }

            let registry = self.registry.clone();
            let nats = self.nats_client.clone();
            let secrets_manager = self.secrets_manager.clone();
            let worker_shared_key_clone = self.worker_shared_key.clone();
            let user_id = trigger.user_id;

            let result = tokio::spawn({
                let input_payload = wrapped_input.clone();
                async move {
                    let exec_info = match registry.get_execution_info(module_id, user_id).await {
                        Ok(info) => info,
                        Err(e) => {
                            tracing::error!(
                                "Failed to prepare webhook module {} for execution: {}",
                                module_id,
                                e
                            );
                            return Err(anyhow::anyhow!("Module not available"));
                        }
                    };

                    // MCP-1144 (2026-05-16): route through the canonical
                    // helper `talos_integration_helpers::build_dispatch_encrypted_secrets`.
                    // Pre-fix this site inlined ~50 lines duplicating the
                    // composition logic that already lived in the helper
                    // — module-declared secrets via `get_module_secrets_for_user`
                    // (MCP-589 user-scoped) PLUS host-reserved LLM keys
                    // via `get_llm_vault_keys(Some(user_id))`. The
                    // MCP-1143 DLQ replay fix already mirrored this logic;
                    // collapsing both into the helper kills the future-drift
                    // hazard. Same logging discipline as the helper
                    // (DEBUG on common-case missing LLM keys, WARN on
                    // shared-key or encryption failure).
                    let encrypted_secrets =
                        talos_integration_helpers::build_dispatch_encrypted_secrets(
                            Some(&secrets_manager),
                            module_id,
                            user_id,
                            // L-1: AAD = job_id (= workflow_execution_id
                            // below). The worker's decrypt AAD will be
                            // pulled from `workflow_execution_id`.
                            job_id,
                        )
                        .await;
                    let mut req = talos_workflow_job_protocol::JobRequest {
                        job_id,
                        workflow_execution_id: job_id, // Standalone webhook uses same ID
                        module_uri: exec_info.module_uri,
                        input_payload,
                        encrypted_secrets,
                        timeout_ms: 3_000,
                        allowed_hosts: exec_info.allowed_hosts,
                        allowed_methods: exec_info.allowed_methods,
                        allowed_secrets: exec_info.allowed_secrets,
                        allowed_sql_operations: vec![],
                        allow_tier2_exposure: false,
                        priority: 100,
                        deadline_unix_secs: 0,
                        cancellation_token: None,
                        signature: vec![],
                        // Webhook-trigger module dispatch — module-bound
                        // (the webhook fires a configured module, not an
                        // actor's workflow). Tier ceiling does not apply
                        // at this layer; see gmail/dispatch.rs for the
                        // same rationale and the recommended workflow-
                        // wrapper approach for tier-1 use cases.
                        max_llm_tier: talos_workflow_job_protocol::LlmTier::default(),
                        job_nonce: String::new(),
                        wasm_bytes: None,
                        capability_world: None,
                        // MCP-1090: propagate per-module integration_name.
                        // Modules belonging to integrations (e.g., GitHub
                        // webhook → GitHub integration module) need
                        // integration_state access for OAuth tokens and
                        // watch metadata. Hardcoded None silently broke
                        // every integration_state call from such modules.
                        integration_name: exec_info.integration_name.clone(),
                        expected_wasm_hash: Some(exec_info.content_hash.clone()),
                        // MCP-1089: propagate per-module max_fuel.
                        max_fuel: exec_info.max_fuel,
                        dry_run: false,
                        reply_topic: None,
                        actor_id: None,
                        user_id,
                    };

                    if let Some(key) = &worker_shared_key_clone {
                        req.sign(key.as_bytes())
                            .map_err(|e| anyhow::anyhow!("Failed to sign job request: {}", e))?;
                    }
                    let payload = serde_json::to_vec(&req).map_err(|e| anyhow::anyhow!(e))?;

                    // Request-reply pattern via NATS.
                    // MCP-1065 (2026-05-15): canonical edge-routing resolver.
                    let topic_to_use = if talos_config::edge_routing_enabled() {
                        format!("talos.jobs.{}", user_id)
                    } else {
                        "talos.jobs".to_string()
                    };

                    let response = tokio::time::timeout(
                        std::time::Duration::from_secs(3),
                        nats.request(topic_to_use, payload.into()),
                    )
                    .await
                    .map_err(|_| anyhow::anyhow!("WASM execution timed out after 3s"))??;

                    let result: talos_workflow_job_protocol::JobResult =
                        serde_json::from_slice(&response.payload)
                            .map_err(|e| anyhow::anyhow!(e))?;

                    // SECURITY: Verify the JobResult HMAC signature before
                    // treating its `output_payload` as authoritative. Without
                    // this gate, an attacker who can publish to NATS could
                    // forge a `JobResult { status: Success, output_payload:
                    // <attacker-controlled> }` to this reply inbox and the
                    // webhook handler would return the forged bytes as the
                    // HTTP response.
                    //
                    // This handler is the SOLE in-process consumer of this
                    // reply (worker single-publishes to either reply_topic
                    // XOR `talos.results.{job_id}` per CLAUDE.md verify-once
                    // rule, and we use NATS request-reply with an
                    // auto-generated inbox subject — the controller's
                    // `talos.results.*` subscriber does not see this
                    // payload). L-4: `Verifier::Primary` makes the role
                    // explicit at the call site — this is the canonical
                    // primary verifier for results on this reply inbox.
                    if let Some(key) = &worker_shared_key_clone {
                        if let Err(e) = result.verify_as(
                            key.as_bytes(),
                            300,
                            talos_workflow_job_protocol::Verifier::Primary,
                        ) {
                            tracing::warn!(
                                trigger_id = %trigger_id,
                                "Webhook job result signature verification failed: {}",
                                e
                            );
                            return Err(anyhow::anyhow!("Job result verification failed"));
                        }
                    }

                    match result.status {
                        talos_workflow_job_protocol::JobStatus::Success => {
                            Ok(result.output_payload.to_string())
                        }
                        _ => Err(anyhow::anyhow!(
                            "Execution failed: {}",
                            result.output_payload
                        )),
                    }
                }
            })
            .await;

            // MCP-961 sibling: saturating u128→i32 conversion. Pre-fix
            // `as i32` wrapped for durations > i32::MAX ms (~24.8 days).
            // The webhook timeout bounds practical exposure, but the
            // column type is i32 — saturating keeps the column
            // monotonic under any future timeout policy change.
            let wasm_duration_ms =
                i32::try_from(wasm_start.elapsed().as_millis()).unwrap_or(i32::MAX);

            let (response_body, success, error_msg) = match result {
                Ok(Ok(output)) => {
                    // Auth passed and execution succeeded — clear any CB failures for this IP.
                    if let Some(ip) = source_ip {
                        self.circuit_breaker.record_success(ip);
                    }
                    (output, true, None)
                }
                Ok(Err(e)) => {
                    tracing::error!(
                        trigger_id = %trigger_id,
                        error = %e,
                        "WASM execution failed"
                    );
                    (String::new(), false, Some(e.to_string()))
                }
                Err(e) => {
                    tracing::error!(
                        trigger_id = %trigger_id,
                        error = %e,
                        "WASM task panicked"
                    );
                    (String::new(), false, Some(format!("Task panicked: {}", e)))
                }
            };

            // MCP-961 sibling: see wasm_duration_ms above — saturating
            // u128→i32 conversion bounds the column under any future
            // timeout policy change.
            let total_duration_ms =
                i32::try_from(start_time.elapsed().as_millis()).unwrap_or(i32::MAX);

            // Decoupled Write Path: Async Logging & State Updates
            let status_code = if success {
                StatusCode::OK
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            let response_body_clone = response_body.clone();
            let error_msg_clone = error_msg.clone();
            let headers_clone = headers.clone();
            let body_clone = body.clone();
            let router_clone = self.clone();
            let trigger_user_id = trigger.user_id;

            tokio::spawn(async move {
                // 10. Update statistics
                router_clone
                    .update_trigger_stats(trigger_id, trigger_user_id, success, total_duration_ms)
                    .await;

                // 11. Log request
                router_clone
                    .log_request(
                        trigger_id,
                        &headers_clone,
                        &body_clone,
                        source_ip,
                        status_code.as_u16() as i32,
                        if success {
                            Some(&response_body_clone)
                        } else {
                            None
                        },
                        total_duration_ms,
                        wasm_duration_ms,
                        success,
                        error_msg_clone.as_deref(),
                    )
                    .await;
            });

            // 12. Chain to downstream workflow nodes
            let output_value = serde_json::from_str::<serde_json::Value>(&response_body)
                .unwrap_or(serde_json::Value::String(response_body.clone()));
            let nats = self.nats_client.clone();
            let secrets_manager = self.secrets_manager.clone();
            let db_pool = self.db_pool.clone();
            let worker_shared_key_for_chain = self.worker_shared_key.clone();
            let redis_client = self.registry.redis_client.clone();
            let trigger_error = error_msg.clone();
            let router_for_chain = self.clone();
            tokio::spawn(async move {
                if let Err(e) = talos_engine::workflow_chains::run_workflow_chains(
                    nats,
                    secrets_manager,
                    &db_pool,
                    worker_shared_key_for_chain,
                    redis_client,
                    router_for_chain.worker_manager.clone(),
                    router_for_chain.module_execution_service.clone(),
                    module_id,
                    user_id,
                    output_value,
                    trigger_id,
                    job_id,
                    trigger_error,
                )
                .await
                {
                    tracing::error!("Failed to run workflow chains: {}", e);
                }
            });

            // 13. Return response
            if trigger.auto_respond {
                if success {
                    Ok((status_code, response_body).into_response())
                } else {
                    // MCP-926 (2026-05-14): always return generic
                    // "Internal server error" to the webhook caller on
                    // failure. Pre-fix `error_msg.unwrap_or_else(...)`
                    // looked defensive but was effectively
                    // `error_msg.unwrap()` — `error_msg` is set to
                    // `Some(e.to_string())` on EVERY failure branch
                    // (WASM-error at ~line 1116, task-panic at ~line
                    // 1124), so the fallback never fired. The webhook
                    // response body always carried the full
                    // `anyhow::Error` chain (sqlx detail, workflow
                    // node internals, panic-message stack frames) to
                    // whoever hit the URL — and webhook URLs are
                    // public-facing by design. Same class as
                    // MCP-923/924/925 but on the public webhook
                    // surface instead of the user-authed integration
                    // REST handlers. Full error is already captured
                    // server-side via `tracing::error!` at the WASM/
                    // panic branches AND stored in
                    // `webhook_request_log` via `log_request` —
                    // operators and the trigger owner have full
                    // detail through both paths.
                    Ok(
                        (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
                            .into_response(),
                    )
                }
            } else {
                Ok((StatusCode::OK, "OK").into_response())
            }
        } else if let Some(workflow_id) = trigger.workflow_id {
            // Workflow Trigger Path
            let body_str = std::str::from_utf8(&body).unwrap_or("");
            let input_payload = serde_json::from_str::<serde_json::Value>(body_str)
                .unwrap_or(serde_json::Value::String(body_str.to_string()));

            self.trigger_workflow_execution(
                workflow_id,
                trigger.user_id,
                input_payload,
                trigger_id,
                trigger.auto_respond,
                trigger.sync_timeout_secs,
            )
            .await
        } else {
            Ok((
                StatusCode::BAD_REQUEST,
                "Webhook trigger has no module or workflow associated",
            )
                .into_response())
        }
    }

    /// Triggers a workflow execution directly from a webhook.
    ///
    /// Behaviour split by `auto_respond`:
    /// * `false` (async, default): spawn the engine, return 202 + queued
    ///   `execution_id` immediately. Caller polls.
    /// * `true` (synchronous): run the engine inline under a
    ///   `tokio::time::timeout(sync_timeout_secs, ...)`, collect the
    ///   per-node output, return 200 + JSON inline. On timeout the
    ///   engine continues in the background — caller gets 504 + the
    ///   `execution_id` so they can poll later.
    ///
    /// Both paths use `run_with_trigger_input_via_nats` (the canonical
    /// trigger-seed entry — wires the synthetic `__trigger__` node
    /// correctly). The previous implementation seeded with a random
    /// UUID, which silently produced workflows that never saw the
    /// webhook input.
    async fn trigger_workflow_execution(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        input_payload: serde_json::Value,
        trigger_id: Uuid,
        auto_respond: bool,
        sync_timeout_secs: i32,
    ) -> Result<Response> {
        let execution_id = Uuid::new_v4();

        // 1. Fetch the workflow's graph + actor binding BEFORE creating
        //    the execution row so the row carries the workflow's bound
        //    actor_id and provenance.trigger_type='webhook' from the
        //    start. Pre-fix (MCP-20/21, 2026-05-07) the webhook path
        //    INSERTed with no provenance and no actor_id — same bug
        //    class as the scheduler — so analytics queries that filter
        //    by `provenance->>'trigger_type'` and per-actor counts both
        //    missed webhook-triggered runs.
        #[derive(sqlx::FromRow)]
        struct WorkflowDispatchRow {
            graph_json: String,
            actor_id: Option<Uuid>,
        }
        let wf_row = match sqlx::query_as::<_, WorkflowDispatchRow>(
            "SELECT graph_json, actor_id FROM workflows WHERE id = $1 AND user_id = $2",
        )
        .bind(workflow_id)
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(
                    workflow_id = %workflow_id,
                    error = %e,
                    "Failed to fetch workflow graph from database"
                );
                return Ok((StatusCode::NOT_FOUND, "Workflow not found").into_response());
            }
        };
        let graph_json = wf_row.graph_json;

        // MCP-565: trigger-time authorization (budget + status +
        // capability-ceiling re-verify). Mirrors the GraphQL +
        // execution-orchestration trigger paths — see the comment on
        // `authorize_workflow_trigger`. Pre-fix the webhook path
        // bypassed:
        //   * actor-suspended check (operator could resume actor's
        //     workflows by webhook even after `update_actor_status`),
        //   * hourly + lifetime budget caps (a misbehaving upstream
        //     could fire continuously past `max_executions_per_hour`),
        //   * capability-ceiling re-verification (a post-create graph
        //     edit that escalated a node's world wouldn't be re-checked
        //     against the actor's `max_capability_world`).
        // The MCP-555 / MCP-557 / MCP-564 sweep covered scheduler /
        // chains / retry / continuation; this closes the last surface.
        // No-op when `wf_row.actor_id` is None — module-bound dispatch
        // intentionally has no owning actor and skips the gate.
        if wf_row.actor_id.is_some() {
            use talos_workflow_authorization::{authorize_workflow_trigger, TriggerAuthError};
            let workflow_repo_for_auth =
                talos_workflow_repository::WorkflowRepository::new(self.db_pool.clone());
            let actor_repo_for_auth =
                talos_actor_repository::ActorRepository::new(self.db_pool.clone());
            match authorize_workflow_trigger(
                &workflow_repo_for_auth,
                &actor_repo_for_auth,
                &self.db_pool,
                wf_row.actor_id,
                user_id,
                &graph_json,
            )
            .await
            {
                Ok(_) => {}
                Err(TriggerAuthError::ActorNotFoundOrInactive)
                | Err(TriggerAuthError::ActorArchived)
                | Err(TriggerAuthError::ActorTerminated) => {
                    tracing::warn!(
                        target: "talos_webhooks",
                        event_kind = "webhook_dispatch_denied_actor_state",
                        workflow_id = %workflow_id,
                        trigger_id = %trigger_id,
                        "MCP-565: webhook dispatch denied — actor not in a runnable state"
                    );
                    return Ok((StatusCode::FORBIDDEN, "Actor not runnable").into_response());
                }
                Err(TriggerAuthError::ExecutionDenied(reason)) => {
                    tracing::warn!(
                        target: "talos_webhooks",
                        event_kind = "webhook_dispatch_denied_by_budget",
                        workflow_id = %workflow_id,
                        trigger_id = %trigger_id,
                        reason = %reason,
                        "MCP-565: webhook dispatch denied by actor budget/status gate"
                    );
                    return Ok(
                        (StatusCode::TOO_MANY_REQUESTS, "Actor budget exceeded").into_response()
                    );
                }
                Err(TriggerAuthError::CapabilityCeilingViolation { .. }) => {
                    tracing::warn!(
                        target: "talos_webhooks",
                        event_kind = "webhook_dispatch_denied_capability_ceiling",
                        workflow_id = %workflow_id,
                        trigger_id = %trigger_id,
                        "MCP-565: webhook dispatch denied — workflow exceeds actor capability ceiling"
                    );
                    return Ok((
                        StatusCode::FORBIDDEN,
                        "Workflow capability exceeds actor ceiling",
                    )
                        .into_response());
                }
                Err(TriggerAuthError::Database(e)) => {
                    tracing::error!(
                        target: "talos_webhooks",
                        event_kind = "webhook_dispatch_auth_db_error",
                        workflow_id = %workflow_id,
                        error = %e,
                        "MCP-565: webhook dispatch authorization DB error — failing closed"
                    );
                    return Err(anyhow::anyhow!("Internal authorization error"));
                }
            }
        }

        // 2. Create the execution row via the canonical
        //    `create_execution_under_concurrency_limit` helper. This
        //    consolidates webhook-triggered runs onto the same write
        //    path used by trigger_workflow / scheduler, with:
        //      • TOCTOU-safe concurrency gate (SELECT FOR UPDATE on
        //        the workflows row + COUNT + INSERT in one tx),
        //      • actor_id stamped on the row (MCP-21),
        //      • provenance.trigger_type='webhook' + trigger_id stamped
        //        for analytics filters (MCP-20).
        //
        //    allow-trigger-type-column: JSON object key in provenance literal,
        //    not a SQL column reference.
        let provenance = serde_json::json!({
            "trigger_type": "webhook",
            "trigger_id": trigger_id.to_string(),
        });
        let workflow_repo =
            talos_workflow_repository::WorkflowRepository::new(self.db_pool.clone());
        let admission = match workflow_repo
            .create_execution_under_concurrency_limit(
                execution_id,
                workflow_id,
                user_id,
                None, // version_id — webhook runs the active graph
                None, // priority — defaults to "normal"
                wf_row.actor_id,
                Some(&provenance),
                None, // parent_execution_id
                None, // root_execution_id
                talos_workflow_repository::InitialExecutionStatus::Queued,
            )
            .await
        {
            Ok(a) => a,
            Err(e) => {
                tracing::error!("Failed to create execution record: {}", e);
                return Err(anyhow::anyhow!("Internal server error"));
            }
        };
        if let talos_workflow_repository::ConcurrencyAdmission::LimitReached { limit, .. } =
            admission
        {
            return Ok((
                StatusCode::TOO_MANY_REQUESTS,
                format!("Concurrency limit reached: {}", limit),
            )
                .into_response());
        }

        // Canonical engine builder. TimeoutPolicy::Honor closes a latent
        // bug: pre-r227, this site never set execution_timeout_secs at all,
        // so a workflow with `execution_timeout_secs: 60` in its graph_json
        // was silently using the engine compile-time default (300 s) when
        // triggered via webhook — the same regression class r225 fixed for
        // the scheduler. The for_workflow path goes through
        // load_graph_from_json which now correctly populates the field
        // from the JSON.
        //
        // Actor-binding behavior preserved: if wf_row.actor_id is Some,
        // the engine is stamped with that actor_id + max_llm_tier so
        // __memory_write__ + tier-1 enforcement work as before
        // (pain-point-#15 close-out from 2026-04-23 stays intact).
        let actor_repo = std::sync::Arc::new(talos_actor_repository::ActorRepository::new(
            self.db_pool.clone(),
        ));
        let mut opts = talos_engine::builder::EngineOpts::for_run(workflow_id, graph_json.clone());
        if let Some(aid) = wf_row.actor_id {
            opts = opts.with_actor_id(aid);
        }
        let mut engine = match talos_engine::builder::for_workflow(
            self.registry.clone(),
            self.secrets_manager.clone(),
            actor_repo,
            user_id,
            opts,
        )
        .await
        {
            Ok(e) => e,
            Err(e) => {
                // MCP-993 (2026-05-15): DLP-redact the error in the
                // operator-log surface too. Builder errors can wrap
                // registry / secrets-manager failures whose anyhow
                // context strings include caller-supplied identifiers
                // (vault paths, module IDs as substrings of upstream
                // API error bodies). Sibling MCP-989/990 — operator
                // logs containing worker/WASM-adjacent error chains
                // need the same DLP discipline as the persistence
                // path that follows (MCP-449 line ~1534).
                let redacted_for_log = talos_dlp_provider::redact_str(&format!("{:?}", e));
                tracing::error!(
                    workflow_id = %workflow_id,
                    error = %redacted_for_log,
                    "Failed to build engine for webhook trigger"
                );
                // MCP-449: DLP-redact the engine error before it lands
                // in the DB row. Same secret-leak class as MCP-447.
                let redacted = talos_dlp_provider::redact_str(&format!("{:?}", e));
                // MCP-743 (2026-05-13): log the UPDATE result. Pre-fix
                // `let _ = sqlx::query(...).await` discarded the result;
                // if the DB UPDATE itself failed (pool exhaustion,
                // deadlock, etc.) the execution row was left in its
                // initial 'queued' state with no recorded failure
                // reason — operator dashboards saw an execution that
                // never moved past queued and no log signal explaining
                // why. Same operator-visibility class as MCP-733..742.
                if let Err(db_err) = sqlx::query(
                    "UPDATE workflow_executions SET status = 'failed', error_message = $2, completed_at = NOW() WHERE id = $1",
                )
                .bind(execution_id)
                .bind(format!("Failed to load graph: {}", redacted))
                .execute(&self.db_pool)
                .await
                {
                    tracing::warn!(
                        target: "talos_rpc",
                        execution_id = %execution_id,
                        workflow_id = %workflow_id,
                        error = %db_err,
                        "Failed to mark webhook execution failed after graph-load error — execution row left in queued state",
                    );
                }
                return Ok((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to load workflow graph",
                )
                    .into_response());
            }
        };

        let nats = self.nats_client.clone();
        let worker_shared_key = self.worker_shared_key.clone();

        // Stats update (fire-and-forget) — same in both modes.
        let router_clone = self.clone();
        tokio::spawn(async move {
            router_clone
                .update_trigger_stats(trigger_id, user_id, true, 0)
                .await;
        });

        if auto_respond {
            // Synchronous mode: wait inline up to sync_timeout_secs for the
            // engine to complete and return per-node output as the HTTP body.
            // MCP-1091: clamp at the read boundary to defend against legacy
            // / direct-DB-written rows outside the MCP creation validator's
            // 1..=120 range. Pre-fix a stored `sync_timeout_secs = -1` cast
            // straight to `u64::MAX`, giving an effectively-infinite timeout
            // that pinned a worker connection indefinitely. Sibling class to
            // MCP-767/811/812/997 (caller-supplied-negative clamp lint).
            let timeout_secs = sync_timeout_secs.clamp(1, 120) as u64;
            let timeout = std::time::Duration::from_secs(timeout_secs);
            let _trigger_input_for_storage = input_payload.clone();
            let db_pool = self.db_pool.clone();

            // We move `engine` into the run; capture node_labels first.
            // After completion node_labels is still valid since engine is borrowed.
            let run_fut = talos_engine::nats_run::run_with_trigger_input_via_nats(
                &mut engine,
                nats,
                worker_shared_key,
                input_payload,
                execution_id,
            );

            match tokio::time::timeout(timeout, run_fut).await {
                Ok(Ok(ctx)) => {
                    let node_labels = engine.node_labels();
                    let mut output = serde_json::Map::new();
                    for (nid, result) in &ctx.results {
                        let key = node_labels
                            .get(nid)
                            .cloned()
                            .unwrap_or_else(|| nid.to_string());
                        if key == "__trigger__" {
                            continue;
                        }
                        if result
                            .get("__skipped")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false)
                        {
                            continue;
                        }
                        let clean =
                            talos_workflow_engine::ParallelWorkflowEngine::unwrap_output(result)
                                .clone();
                        output.insert(key, clean);
                    }
                    let output_value = serde_json::Value::Object(output);
                    // Persist the SCRUBBED output to workflow_executions, return
                    // the UNSCRUBBED output to the caller — they triggered the
                    // request and own the data; the audit log is what gets DLP.
                    let scrubbed_for_storage = talos_dlp_provider::redact_json(&output_value);
                    // MCP-682 (2026-05-13): route through encryption-aware
                    // repository so sync-response webhook completions land
                    // in `output_data_enc` on Phase A deployments. Pre-fix
                    // the raw UPDATE wrote plaintext only, bypassing the
                    // encryption-at-rest guarantee.
                    let wf_repo =
                        talos_workflow_repository::WorkflowRepository::new(db_pool.clone())
                            .with_encryption(self.secrets_manager.clone());
                    if let Err(e) = wf_repo
                        .mark_execution_completed(execution_id, &scrubbed_for_storage)
                        .await
                    {
                        tracing::error!(
                            execution_id = %execution_id,
                            error = %e,
                            "Failed to mark webhook execution completed"
                        );
                    }

                    let body = serde_json::json!({
                        "execution_id": execution_id,
                        "status": "completed",
                        "output": output_value,
                    })
                    .to_string();
                    Ok((
                        StatusCode::OK,
                        [(axum::http::header::CONTENT_TYPE, "application/json")],
                        body,
                    )
                        .into_response())
                }
                Ok(Err(e)) => {
                    // MCP-449 + MCP-993: DLP-redact the engine error.
                    // CRITICAL on this path because `err_msg` is fanned
                    // out to THREE surfaces:
                    //   - The operator-log line below (MCP-993 — workflow
                    //     execution errors regularly wrap upstream API
                    //     bodies / module output strings that contain
                    //     secret-shaped values).
                    //   - The DB row (MCP-449 — error_message column).
                    //   - The HTTP response body returned to the webhook
                    //     caller (external system: Slack, GitHub, etc.).
                    //     The external caller would otherwise see any
                    //     token echoed back by a failing upstream call.
                    let err_msg = talos_dlp_provider::redact_str(&format!("{:?}", e));
                    tracing::error!(
                        execution_id = %execution_id,
                        error = %err_msg,
                        "Workflow sync execution failed"
                    );
                    // MCP-743 (2026-05-13): log the failure-UPDATE result
                    // — see the matching site above for the operator-
                    // visibility rationale. The execution row would
                    // otherwise be stuck in 'queued' even though the
                    // caller saw 500 + the redacted error in the body.
                    if let Err(db_err) = sqlx::query(
                        "UPDATE workflow_executions SET status = 'failed', error_message = $2, completed_at = NOW() WHERE id = $1",
                    )
                    .bind(execution_id)
                    .bind(&err_msg)
                    .execute(&db_pool)
                    .await
                    {
                        tracing::warn!(
                            target: "talos_rpc",
                            execution_id = %execution_id,
                            error = %db_err,
                            "Failed to mark webhook execution failed after sync run error — execution row left in queued state",
                        );
                    }
                    let body = serde_json::json!({
                        "execution_id": execution_id,
                        "status": "failed",
                        "error": err_msg,
                    })
                    .to_string();
                    Ok((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        [(axum::http::header::CONTENT_TYPE, "application/json")],
                        body,
                    )
                        .into_response())
                }
                Err(_elapsed) => {
                    // Timeout: the engine future was dropped on timeout, so
                    // the workflow is NOT actually still running. Mark the
                    // execution failed with a clear timeout reason and
                    // return 504 + execution_id so the caller can find the
                    // record in their history.
                    tracing::warn!(
                        execution_id = %execution_id,
                        sync_timeout_secs = timeout_secs,
                        "Sync webhook execution exceeded sync_timeout_secs",
                    );
                    let err_msg = format!(
                        "Synchronous webhook execution exceeded sync_timeout_secs={}s. \
                         Reduce workflow complexity, raise sync_timeout_secs (max 120), \
                         or set auto_respond=false to use async dispatch.",
                        timeout_secs
                    );
                    // MCP-743 (2026-05-13): log the failure-UPDATE
                    // result on the sync-timeout path. Without this,
                    // a DB hiccup at the exact moment a sync webhook
                    // times out leaves the execution row in 'queued'
                    // forever AND the caller receives 504 — operator
                    // sees an indefinitely-queued execution with no
                    // explanation, indistinguishable from a stuck
                    // dispatcher.
                    if let Err(db_err) = sqlx::query(
                        "UPDATE workflow_executions SET status = 'failed', error_message = $2, completed_at = NOW() WHERE id = $1",
                    )
                    .bind(execution_id)
                    .bind(&err_msg)
                    .execute(&db_pool)
                    .await
                    {
                        tracing::warn!(
                            target: "talos_rpc",
                            execution_id = %execution_id,
                            sync_timeout_secs = timeout_secs,
                            error = %db_err,
                            "Failed to mark webhook execution failed after sync timeout — execution row left in queued state",
                        );
                    }
                    let body = serde_json::json!({
                        "execution_id": execution_id,
                        "status": "timeout",
                        "error": err_msg,
                    })
                    .to_string();
                    Ok((
                        StatusCode::GATEWAY_TIMEOUT,
                        [(axum::http::header::CONTENT_TYPE, "application/json")],
                        body,
                    )
                        .into_response())
                }
            }
        } else {
            // Async mode: spawn engine, return 202 immediately.
            tokio::spawn(async move {
                if let Err(e) = talos_engine::nats_run::run_with_trigger_input_via_nats(
                    &mut engine,
                    nats,
                    worker_shared_key,
                    input_payload,
                    execution_id,
                )
                .await
                {
                    tracing::error!(
                        execution_id = %execution_id,
                        workflow_id = %workflow_id,
                        error = ?e,
                        "Workflow execution failed (async)"
                    );
                }
            });

            let body = serde_json::json!({
                "execution_id": execution_id,
                "status": "queued",
            })
            .to_string();
            Ok((
                StatusCode::ACCEPTED,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                body,
            )
                .into_response())
        }
    }

    async fn get_trigger(&self, trigger_id: Uuid) -> Result<WebhookTrigger> {
        sqlx::query_as::<_, WebhookTrigger>(
            r#"
            SELECT id, user_id, name, module_id, workflow_id,
                   verification_token,
                   signing_secret_enc, signing_key_id, signing_secret_format,
                   allowed_ips, enabled, auto_respond, queue_events, max_requests_per_minute,
                   COALESCE(sync_response, false) as sync_response,
                   COALESCE(sync_timeout_secs, 30) as sync_timeout_secs
            FROM webhook_triggers
            WHERE id = $1
            "#,
        )
        .bind(trigger_id)
        .fetch_one(&self.db_pool)
        .await
        .context("Webhook trigger not found")
    }

    /// Verify HMAC signature from webhook request
    /// Supports multiple header formats (Slack, GitHub, etc.)
    // Made public to enable external testing of HMAC verification logic.
    #[must_use]
    pub fn verify_hmac_signature(
        &self,
        headers: &HeaderMap,
        body: &Bytes,
        signing_secret: &str,
    ) -> bool {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        use subtle::ConstantTimeEq;

        // MCP-628 (2026-05-12): defense-in-depth empty-secret rejection.
        // `Hmac::<Sha256>::new_from_slice` accepts ANY length key
        // (including empty) — for HMAC-SHA256 the spec defines the
        // computation deterministically on every key length. So with
        // `signing_secret = ""`, the verifier would happily compute
        // `HMAC-SHA256("", body)` and an attacker who knows the body
        // could trivially forge a "valid" signature.
        //
        // The storage path (MCP `create_webhook` handler) enforces a
        // 16-char minimum (MCP-202), so empty secrets cannot be stored
        // via that path. But the runtime should still fail closed in
        // case a legacy migration / direct-SQL write / future code path
        // produces an empty secret — the verify function is the last
        // line of defense and shouldn't trust the storage invariant.
        if signing_secret.is_empty() {
            tracing::warn!(
                target: "talos_webhooks",
                event_kind = "webhook_hmac_secret_empty",
                "HMAC signing_secret is empty — failing closed (storage path enforces ≥16 chars; \
                 a non-empty-then-empty value here means storage was bypassed)"
            );
            return false;
        }

        // Try Slack signature format first (X-Slack-Signature)
        if let Some(signature) = headers.get("x-slack-signature") {
            if let Ok(sig_str) = signature.to_str() {
                // Slack format: v0=<hash>
                if let Some(hash_hex) = sig_str.strip_prefix("v0=") {
                    if let Some(timestamp) = headers.get("x-slack-request-timestamp") {
                        if let Ok(ts_str) = timestamp.to_str() {
                            // Enforce timestamp freshness (±5 minutes) to prevent replay attacks.
                            // Slack's own documentation recommends this check.
                            if let Ok(ts_secs) = ts_str.parse::<i64>() {
                                let now_secs = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_secs() as i64)
                                    .unwrap_or(0);
                                // Overflow-free skew (see webhook_timestamp_skew_secs).
                                if webhook_timestamp_skew_secs(now_secs, ts_secs) > 300 {
                                    tracing::warn!(
                                        timestamp = ts_secs,
                                        now = now_secs,
                                        "Slack request timestamp is outside the ±5 minute window — replay attack?"
                                    );
                                    return false;
                                }
                            } else {
                                tracing::warn!(
                                    "Slack X-Slack-Request-Timestamp is not a valid integer"
                                );
                                return false;
                            }

                            // Create basestring: version:timestamp:body
                            let base_string = format!("v0:{}:", ts_str);
                            let mut full_message = base_string.into_bytes();
                            full_message.extend_from_slice(body);

                            // Compute HMAC
                            let mut mac =
                                match Hmac::<Sha256>::new_from_slice(signing_secret.as_bytes()) {
                                    Ok(m) => m,
                                    Err(_) => {
                                        tracing::error!("Invalid HMAC secret size");
                                        return false;
                                    }
                                };
                            mac.update(&full_message);
                            let result = mac.finalize();
                            let expected = hex::encode(result.into_bytes());

                            return expected.as_bytes().ct_eq(hash_hex.as_bytes()).unwrap_u8() == 1;
                        }
                    }
                }
            }
        }

        // Try GitHub signature format (X-Hub-Signature-256)
        if let Some(signature) = headers.get("x-hub-signature-256") {
            if let Ok(sig_str) = signature.to_str() {
                if let Some(hash_hex) = sig_str.strip_prefix("sha256=") {
                    let mut mac = match Hmac::<Sha256>::new_from_slice(signing_secret.as_bytes()) {
                        Ok(m) => m,
                        Err(_) => {
                            tracing::error!("Invalid HMAC secret size");
                            return false;
                        }
                    };
                    mac.update(body);
                    let result = mac.finalize();
                    let expected = hex::encode(result.into_bytes());

                    return expected.as_bytes().ct_eq(hash_hex.as_bytes()).unwrap_u8() == 1;
                }
            }
        }

        // Try generic X-Signature header
        if let Some(signature) = headers.get("x-signature") {
            if let Ok(sig_str) = signature.to_str() {
                // Enforce timestamp freshness (±5 minutes) to prevent replay attacks.
                // Senders must include X-Webhook-Timestamp (Unix seconds, UTC).
                // Requests without a timestamp header are rejected — this is a breaking
                // change for callers that do not send the header, but prevents indefinite
                // replay of any captured signed request.
                let timestamp_valid = if let Some(ts_hdr) = headers.get("x-webhook-timestamp") {
                    if let Ok(ts_str) = ts_hdr.to_str() {
                        if let Ok(ts_secs) = ts_str.parse::<i64>() {
                            let now_secs = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs() as i64)
                                .unwrap_or(0);
                            // Overflow-free skew (see webhook_timestamp_skew_secs):
                            // the timestamp-bound HMAC below is the primary replay
                            // defense, but the freshness gate must hold on its own.
                            let skew = webhook_timestamp_skew_secs(now_secs, ts_secs);
                            if skew > 300 {
                                tracing::warn!(
                                    timestamp = ts_secs,
                                    now = now_secs,
                                    skew_secs = skew,
                                    "Generic webhook timestamp outside ±5 minute window — replay attack?"
                                );
                                false
                            } else {
                                true
                            }
                        } else {
                            tracing::warn!("X-Webhook-Timestamp is not a valid integer");
                            false
                        }
                    } else {
                        tracing::warn!("X-Webhook-Timestamp header contains non-UTF8 bytes");
                        false
                    }
                } else {
                    tracing::warn!("Generic webhook HMAC request missing X-Webhook-Timestamp header — replay protection requires this header");
                    false
                };

                if !timestamp_valid {
                    return false;
                }

                // Include timestamp in the HMAC to bind the signature to a specific
                // point in time (prevents timestamp-stripping attacks).
                let ts_bytes = headers
                    .get("x-webhook-timestamp")
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or("")
                    .as_bytes();

                let mut mac = match Hmac::<Sha256>::new_from_slice(signing_secret.as_bytes()) {
                    Ok(m) => m,
                    Err(_) => {
                        tracing::error!("Invalid HMAC secret size");
                        return false;
                    }
                };
                // Sign timestamp + body so the signature commits to when the request was made.
                // Senders must use the same construction: HMAC-SHA256(secret, timestamp + "." + body)
                mac.update(ts_bytes);
                mac.update(b".");
                mac.update(body);
                let result = mac.finalize();
                let expected = hex::encode(result.into_bytes());

                return expected.as_bytes().ct_eq(sig_str.as_bytes()).unwrap_u8() == 1;
            }
        }

        // No recognized signature header found
        tracing::warn!("No recognized signature header found in request");
        false
    }

    async fn update_trigger_stats(
        &self,
        trigger_id: Uuid,
        user_id: Uuid,
        success: bool,
        response_time_ms: i32,
    ) {
        let result = if success {
            sqlx::query(
                r#"
                UPDATE webhook_triggers
                SET last_triggered_at = NOW(),
                    trigger_count = trigger_count + 1,
                    success_count = success_count + 1,
                    avg_response_ms = COALESCE(
                        (avg_response_ms * success_count + $3::float) / (success_count + 1),
                        $3::float
                    )
                WHERE id = $1 AND user_id = $2
                "#,
            )
            .bind(trigger_id)
            .bind(user_id)
            .bind(response_time_ms as f64)
            .execute(&self.db_pool)
            .await
        } else {
            sqlx::query(
                r#"
                UPDATE webhook_triggers
                SET last_triggered_at = NOW(),
                    trigger_count = trigger_count + 1,
                    error_count = error_count + 1
                WHERE id = $1 AND user_id = $2
                "#,
            )
            .bind(trigger_id)
            .bind(user_id)
            .execute(&self.db_pool)
            .await
        };

        if let Err(e) = result {
            tracing::error!(
                trigger_id = %trigger_id,
                error = %e,
                "Failed to update trigger stats"
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn log_request(
        &self,
        trigger_id: Uuid,
        headers: &HeaderMap,
        body: &Bytes,
        source_ip: Option<IpAddr>,
        status_code: i32,
        response_body: Option<&str>,
        response_time_ms: i32,
        wasm_execution_ms: i32,
        success: bool,
        error_message: Option<&str>,
    ) {
        // Convert headers to JSON
        let headers_json: HashMap<String, String> = headers
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_string(),
                    v.to_str().unwrap_or("[binary]").to_string(),
                )
            })
            .collect();

        // MCP-1018 (2026-05-15): truncate the User-Agent to 1 KB at a
        // UTF-8 char boundary BEFORE the DLP scan. Sibling-parity to
        // talos-auth's auth_audit_log writer (MCP-478 truncation +
        // MCP-1012 redact). HTTP allows ~64 KB header values; a
        // 64 KB UA fed straight to `redact_str` pays O(N × pattern_count)
        // regex work per webhook request, and lands a 64 KB string
        // in `webhook_request_log.user_agent` queryable via
        // `webhookRequestLog`. Walk backwards from byte 1024 to the
        // nearest char boundary so a multi-byte UTF-8 sequence
        // (localised UAs do this in practice) isn't truncated
        // mid-codepoint and panic.
        //
        // MCP-1050 (2026-05-15): route through canonical
        // `talos_text_util::truncate_at_char_boundary` — the inline
        // walk-back was an exact reimplementation of the helper.
        let user_agent = headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(|ua| {
                talos_dlp_provider::redact_str(talos_text_util::truncate_at_char_boundary(ua, 1024))
            });
        // MCP-977 (2026-05-15): redact the standalone user_agent
        // column. The full header map is already redacted via
        // `redact_json` on `scrubbed_headers` below, but the
        // `user_agent` column is extracted out separately and was
        // bound raw — sibling drift to MCP-974 (entry-level DLQ
        // header drift). A misbehaving / malicious webhook source
        // could stash a secret in the User-Agent header
        // ("python-requests/2.31 (token=sk-...)"), and the bare
        // column would land unscrubbed even while the header map
        // copy was scrubbed.

        let ip_str = source_ip.map(|ip| ip.to_string());

        // Convert body bytes to string (or use placeholder for binary data).
        // Strip ASCII control characters (except \t, \n, \r) to prevent log injection.
        let body_str_owned: String;
        let body_str = match std::str::from_utf8(body.as_ref()) {
            Ok(s) => {
                body_str_owned = s
                    .chars()
                    .filter(|c| !c.is_ascii_control() || matches!(c, '\t' | '\n' | '\r'))
                    .take(65_535) // cap logged body at 64 KiB
                    .collect();
                body_str_owned.as_str()
            }
            Err(_) => "[binary data]",
        };

        // MCP-484: DLP-scrub every caller-controlled field before
        // persisting to `webhook_request_log`. Inbound webhooks
        // routinely carry secrets in headers (`Authorization: Bearer
        // ...`, `X-Api-Key: sk-...`) and in bodies (e.g. provider
        // callbacks that echo a token in the JSON payload for
        // diagnostic purposes). Pre-fix every webhook request landed
        // raw — operator's debug tool was also a long-lived
        // secret-leak surface queryable via `webhook_request_log_view`
        // and the GraphQL `webhookRequestLog` connection.
        //
        // `redact_str` handles the body / response_body / error
        // strings; `redact_json` recursively scrubs the header
        // JSONB blob so individual header values get scanned for
        // secret-shaped substrings independently. Same persistence-
        // boundary rule as MCP-481/482/483.
        let scrubbed_body = talos_dlp_provider::redact_str(body_str);
        let scrubbed_headers = serde_json::to_value(&headers_json)
            .ok()
            .as_ref()
            .map(talos_dlp_provider::redact_json);
        // MCP-1160 (2026-05-17): truncate-then-redact for response_body
        // + error_message. Pre-fix both fields ran `redact_str` on the
        // RAW caller-supplied string. `response_body` is the WASM
        // module's output (`output` at the `result` match above); WASM
        // outputs are unbounded by default while the inbound webhook
        // body is already capped at 1 MiB by the route layer
        // (MCP-1158/1159 sweep) AND truncated to 64 KiB before logging
        // (line ~2253 `take(65_535)`). `error_message` is a
        // wasmtime error trace (`e.to_string()` lines ~1265/1273) which
        // can include multi-KB stack info. Without a cap, the DLP
        // regex pass walked the full string per row — sibling drift
        // class to MCP-1012/1018/1027/1028 (auth_audit_log /
        // webhook_request_log user_agent / oauth_audit_log /
        // slack+gmail integration_audit_log) where truncate-first
        // bounds the regex-pass cost AND the persisted row size.
        // 64 KiB ceiling on `response_body` matches the body_str
        // truncation on the inbound side; 4 KiB on `error_message`
        // matches the talos-engine/sandbox wasmtime trace ceiling
        // (4 KiB covers every legitimate trace plus headroom).
        let scrubbed_response = response_body.map(|r| {
            let truncated: &str = if r.len() > 65_536 {
                talos_text_util::truncate_at_char_boundary(r, 65_536)
            } else {
                r
            };
            talos_dlp_provider::redact_str(truncated)
        });
        let scrubbed_response_ref = scrubbed_response.as_deref();
        let scrubbed_err = error_message.map(|e| {
            let truncated: &str = if e.len() > 4096 {
                talos_text_util::truncate_at_char_boundary(e, 4096)
            } else {
                e
            };
            talos_dlp_provider::redact_str(truncated)
        });
        let scrubbed_err_ref = scrubbed_err.as_deref();
        let result = sqlx::query!(
            r#"
            INSERT INTO webhook_request_log (
                trigger_id, method, headers, body, source_ip, user_agent,
                status_code, response_body, response_time_ms, wasm_execution_ms,
                success, error_message
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            "#,
            trigger_id,
            "POST",
            scrubbed_headers,
            scrubbed_body,
            ip_str.as_deref(),
            user_agent.as_deref(),
            status_code,
            scrubbed_response_ref,
            response_time_ms,
            wasm_execution_ms,
            success,
            scrubbed_err_ref
        )
        .execute(&self.db_pool)
        .await;

        if let Err(e) = result {
            tracing::error!(
                trigger_id = %trigger_id,
                error = %e,
                "Failed to log webhook request"
            );
        }
    }

    /// Evict idle token-bucket entries from the in-memory webhook rate limiter.
    ///
    /// Call periodically from a background task to prevent unbounded memory
    /// growth when many unique webhook tokens are hit over the lifetime of the
    /// process.  Buckets inactive for more than `max_idle` are removed.
    pub fn cleanup_rate_limiter(&self) {
        self.rate_limiter
            .cleanup(std::time::Duration::from_secs(600)); // evict buckets idle > 10 min
    }

    /// Evict stale circuit-breaker records (IPs quiet for more than `max_age`).
    /// Call periodically alongside `cleanup_rate_limiter`.
    pub fn cleanup_circuit_breaker(&self) {
        self.circuit_breaker
            .cleanup(std::time::Duration::from_secs(600)); // evict records idle > 10 min
    }

    /// Expose a reference to the circuit breaker for MCP tools and tests.
    pub fn circuit_breaker(&self) -> &Arc<CircuitBreaker> {
        &self.circuit_breaker
    }

    /// Re-dispatch a DLQ payload directly to the workflow/module execution path.
    /// Bypasses circuit-breaker, rate-limiter, IP allowlist, and HMAC verification
    /// (the payload was already authenticated when first received; it was dropped
    /// only due to a transient CB/rate-limit condition).
    pub async fn dispatch_replay(&self, trigger_id: Uuid, body: Vec<u8>) -> Result<()> {
        let trigger = self.get_trigger(trigger_id).await?;

        let body_str = std::str::from_utf8(&body).unwrap_or("");
        let input_payload = serde_json::from_str::<serde_json::Value>(body_str)
            .unwrap_or(serde_json::Value::String(body_str.to_string()));

        if let Some(workflow_id) = trigger.workflow_id {
            // Replay path is fire-and-forget — never returns the result inline.
            // Force async mode regardless of trigger.auto_respond so the replayer
            // doesn't block on a long-running workflow.
            self.trigger_workflow_execution(
                workflow_id,
                trigger.user_id,
                input_payload,
                trigger_id,
                false, // auto_respond: replay never waits inline
                trigger.sync_timeout_secs,
            )
            .await?;
        } else if let Some(module_id) = trigger.module_id {
            let module_config = self
                .registry
                .get_module_config(module_id, trigger.user_id)
                .await?
                .unwrap_or(serde_json::json!({}));

            let wrapped_input = serde_json::json!({
                "config": module_config,
                "input": input_payload,
            });

            let job_id = Uuid::new_v4();
            let registry = self.registry.clone();
            let nats = self.nats_client.clone();
            let secrets_manager = self.secrets_manager.clone();
            let worker_shared_key_clone = self.worker_shared_key.clone();
            let user_id = trigger.user_id;

            tokio::spawn(async move {
                let exec_info = match registry.get_execution_info(module_id, user_id).await {
                    Ok(info) => info,
                    Err(e) => {
                        tracing::error!(
                            trigger_id = %trigger_id,
                            "DLQ replay: failed to load execution info: {}",
                            e
                        );
                        return;
                    }
                };

                let mut req = talos_workflow_job_protocol::JobRequest {
                    job_id,
                    workflow_execution_id: job_id,
                    module_uri: exec_info.module_uri,
                    input_payload: wrapped_input,
                    // MCP-1144 (2026-05-16): canonical helper. The
                    // MCP-1143 fix mirrored the live path's inline
                    // composition here; MCP-1144 collapses both into
                    // `talos_integration_helpers::build_dispatch_encrypted_secrets`
                    // so neither site can drift from the other in the
                    // future. Module-declared secrets PLUS host-reserved
                    // LLM keys; MCP-589 user-scoping.
                    encrypted_secrets: talos_integration_helpers::build_dispatch_encrypted_secrets(
                        Some(&secrets_manager),
                        module_id,
                        user_id,
                        // L-1: AAD = job_id (= workflow_execution_id
                        // above). DLQ replay reuses the same id
                        // shape as the live path.
                        job_id,
                    )
                    .await,
                    timeout_ms: 3_000,
                    allowed_hosts: exec_info.allowed_hosts,
                    allowed_methods: exec_info.allowed_methods,
                    allowed_secrets: exec_info.allowed_secrets,
                    allowed_sql_operations: vec![],
                    allow_tier2_exposure: false,
                    priority: 100,
                    deadline_unix_secs: 0,
                    cancellation_token: None,
                    signature: vec![],
                    job_nonce: String::new(),
                    // DLQ replay path — module-bound dispatch (no actor
                    // context). The original failed dispatch already had
                    // its tier resolved in the live path; the replay
                    // re-runs the same module without actor binding.
                    max_llm_tier: talos_workflow_job_protocol::LlmTier::default(),
                    wasm_bytes: None,
                    capability_world: None,
                    // MCP-1090: propagate integration_name (DLQ replay).
                    integration_name: exec_info.integration_name.clone(),
                    expected_wasm_hash: Some(exec_info.content_hash.clone()),
                    // MCP-1089: propagate per-module max_fuel (DLQ replay path).
                    max_fuel: exec_info.max_fuel,
                    dry_run: false,
                    reply_topic: None,
                    actor_id: None,
                    user_id,
                };

                if let Some(key) = &worker_shared_key_clone {
                    if let Err(e) = req.sign(key.as_bytes()) {
                        tracing::error!(trigger_id = %trigger_id, "DLQ replay: sign failed: {}", e);
                        return;
                    }
                }

                let payload = match serde_json::to_vec(&req) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::error!(trigger_id = %trigger_id, "DLQ replay: serialize failed: {}", e);
                        return;
                    }
                };

                // MCP-1065 (2026-05-15): canonical edge-routing resolver.
                let topic = if talos_config::edge_routing_enabled() {
                    format!("talos.jobs.{}", user_id)
                } else {
                    "talos.jobs".to_string()
                };

                if let Err(e) = nats.publish(topic, payload.into()).await {
                    tracing::error!(trigger_id = %trigger_id, "DLQ replay: NATS publish failed: {}", e);
                } else {
                    tracing::info!(trigger_id = %trigger_id, job_id = %job_id, "DLQ replay dispatched");
                }
            });
        } else {
            return Err(anyhow::anyhow!(
                "Trigger {} has no module or workflow associated",
                trigger_id
            ));
        }

        Ok(())
    }

    /// Clean up old webhook request logs (default retention: 90 days)
    /// MCP-997 (2026-05-15): refuse non-positive `retention_days`.
    /// Sibling caller-supplied-negative class as MCP-767/811/812 — a
    /// negative value would convert `NOW() - INTERVAL '1 day' * -N`
    /// into `NOW() + INTERVAL`, matching every row and purging the
    /// entire webhook request log table.
    pub async fn cleanup_request_logs(&self, retention_days: i64) -> Result<u64> {
        if retention_days <= 0 {
            tracing::warn!(
                target: "talos_audit",
                retention_days,
                "webhook-request-log cleanup refused: retention_days must be positive (would purge entire log)"
            );
            return Ok(0);
        }
        let result = sqlx::query(
            "DELETE FROM webhook_request_log WHERE created_at < NOW() - INTERVAL '1 day' * $1",
        )
        .bind(retention_days)
        .execute(&self.db_pool)
        .await?;

        Ok(result.rows_affected())
    }
}

/// Axum handler for webhook requests
pub async fn webhook_handler(
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Path(trigger_id): Path<Uuid>,
    headers: HeaderMap,
    Extension(webhook_router): Extension<Arc<WebhookRouter>>,
    Extension(trusted_proxies): Extension<Arc<talos_rate_limit::TrustedProxies>>,
    body: Bytes,
) -> Response {
    // Use the canonical RFC 7239 §5.2 right-to-left XFF walk
    // (`rate_limit::extract_client_ip`). The previous leftmost read was
    // exploitable: a client behind a trusted proxy could prepend `X-Forwarded-For:
    // <preferred-ip>` and Traefik would append the real client to the right,
    // leaving `<preferred-ip>, real_client_ip` in the header. Reading leftmost
    // would let the attacker spoof their `source_ip` for both rate-limit
    // accounting and the per-trigger `allowed_ips` allowlist gate.
    //
    // The right-to-left walk skips trusted-proxy entries from the right and
    // returns the first non-trusted entry — the actual original client.
    let direct_ip = addr.ip();
    let source_ip = Some(talos_rate_limit::extract_client_ip(
        direct_ip,
        &headers,
        &trusted_proxies,
    ));

    match webhook_router
        .handle_webhook(trigger_id, &headers, body, source_ip)
        .await
    {
        Ok(response) => response,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("not found") {
                (StatusCode::NOT_FOUND, "Webhook not found").into_response()
            } else if msg.contains("rate limit") || msg.contains("Rate limit") {
                (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded").into_response()
            } else if msg.contains("IP") || msg.contains("not allowed") {
                (StatusCode::FORBIDDEN, "Forbidden").into_response()
            } else {
                tracing::error!(
                    trigger_id = %trigger_id,
                    error = %e,
                    "Webhook handler error"
                );
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
            }
        }
    }
}

use serde::Deserialize;

#[derive(Deserialize)]
pub struct ApprovalPayload {
    pub approved: bool,
}

pub async fn approval_handler(
    Path(execution_id): Path<String>,
    Extension(user_id): Extension<uuid::Uuid>,
    Extension(db_pool): Extension<Pool<Postgres>>,
    Extension(redis_client): Extension<Option<std::sync::Arc<redis::Client>>>,
    Extension(nats_client): Extension<Option<std::sync::Arc<async_nats::Client>>>,
    axum::Json(payload): axum::Json<ApprovalPayload>,
) -> impl IntoResponse {
    // SECURITY: Verify the authenticated user owns this workflow execution before
    // allowing them to approve/reject it.  Without this check, any authenticated
    // user who knows (or guesses) an execution UUID can hijack another user's
    // approval gate.
    let exec_uuid = match uuid::Uuid::parse_str(&execution_id) {
        Ok(u) => u,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid execution ID").into_response(),
    };

    // MCP-535: distinguish DB-error from row-missing. The previous
    // `.unwrap_or(None)` collapsed both into "owner = None" → 404. The
    // authorization decision is still fail-closed (DB error → 404 is
    // safe) but operators lost the signal: every approval lookup
    // returning 404 during a Postgres outage looked like users typing
    // bad UUIDs. Log the DB error explicitly so it surfaces in
    // metrics/alerts; behaviour is unchanged.
    let owner: Option<(uuid::Uuid,)> =
        match sqlx::query_as("SELECT user_id FROM workflow_executions WHERE id = $1")
            .bind(exec_uuid)
            .fetch_optional(&db_pool)
            .await
        {
            Ok(row) => row,
            Err(e) => {
                tracing::error!(
                    execution_id = %execution_id,
                    error = %e,
                    "approval_handler: workflow_executions ownership lookup failed; \
                     treating as not-found (fail-closed)"
                );
                None
            }
        };

    match owner {
        Some((owner_id,)) if owner_id == user_id => {} // authorised
        Some(_) => {
            // MCP-1102 (2026-05-16): return the same 404 + "Execution
            // not found" body as the genuine-missing branch below to
            // avoid leaking existence. Pre-fix, an attacker with a list
            // of execution UUIDs (leaked dashboard screenshot, log
            // exfiltration, predictable test-fixture IDs) could
            // distinguish "this UUID exists but belongs to someone
            // else" (403) from "this UUID does not exist" (404). For
            // workflow executions specifically this confirms cross-
            // tenant activity: an attacker probing 100 candidate UUIDs
            // learns which ones map to real users without ever passing
            // ownership. Same tenant-isolation discipline noted in
            // CLAUDE.md (`SECURITY: Verify the authenticated user owns
            // …` already enforced; the leak was the differentiated
            // status code, not the access check itself). Server-side
            // WARN retains the distinction for forensics.
            tracing::warn!(
                user_id = %user_id,
                execution_id = %execution_id,
                "Approval attempt rejected: execution belongs to a different user"
            );
            return (StatusCode::NOT_FOUND, "Execution not found").into_response();
        }
        None => {
            return (StatusCode::NOT_FOUND, "Execution not found").into_response();
        }
    }

    tracing::info!(
        user_id = %user_id,
        execution_id = %execution_id,
        "User is resolving approval for execution"
    );
    let redis = match redis_client {
        Some(r) => r,
        None => return (StatusCode::INTERNAL_SERVER_ERROR, "Redis not available").into_response(),
    };
    let nats = match nats_client {
        Some(n) => n,
        None => return (StatusCode::INTERNAL_SERVER_ERROR, "NATS not available").into_response(),
    };

    let mut con = match redis.get_multiplexed_tokio_connection().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to get Redis connection: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Redis error").into_response();
        }
    };

    // The frontend UI calls this webhook with the workflow_execution_id, not the specific node's execution_id.
    let redis_key = format!("approval:{}", execution_id);
    // MCP-999 (2026-05-15): same MCP-535 distinction-of-failures rule
    // applied to the workflow_approval_gates lookups above, now on the
    // Redis side. Pre-fix `.unwrap_or(None)` silently collapsed an
    // Err(redis_error) into Ok(None), and the next branch returns 404
    // "Approval request not found or expired" — indistinguishable to
    // operators from a genuinely missing/expired key. During a Redis
    // outage every legitimate approval click hits this code path and
    // the only operator-facing signal is a "404 not found" without
    // correlation to Redis availability. Fail-closed posture preserved
    // (no key → 404), but the Err arm now logs at error! level with
    // structured context so monitoring can alert on the underlying
    // cause. Sibling site at talos-mcp-handlers/src/executions.rs:6136
    // (`submit_workflow_approval` MCP tool) fixed in the same commit.
    let reply_topic: Option<String> = match redis::cmd("GET")
        .arg(&redis_key)
        .query_async::<Option<String>>(&mut con)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(
                execution_id = %execution_id,
                error = %e,
                "approval_handler: Redis GET for approval reply-topic failed; \
                 returning not-found (fail-closed)"
            );
            None
        }
    };

    let topic = match reply_topic {
        Some(t) => t,
        None => {
            return (
                StatusCode::NOT_FOUND,
                "Approval request not found or expired",
            )
                .into_response()
        }
    };

    // SECURITY: validate topic before publishing. The topic is read from Redis, where it
    // was written by a WASM module. Reject wildcards (*,>) and enforce printable ASCII
    // to prevent NATS subject injection (publishing to unintended subjects).
    {
        let topic_bytes = topic.as_bytes();
        let is_safe = !topic.is_empty()
            && topic.len() <= 512
            && topic_bytes
                .iter()
                .all(|&b| b.is_ascii() && b >= 0x20 && b != b'*' && b != b'>');
        if !is_safe {
            tracing::error!(
                execution_id = %execution_id,
                "SECURITY: approval reply topic from Redis failed validation — aborting publish"
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Invalid approval routing data",
            )
                .into_response();
        }
    }

    let response_str = if payload.approved { "true" } else { "false" };

    if let Err(e) = nats.publish(topic, response_str.into()).await {
        tracing::error!("Failed to publish approval to NATS: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to send approval").into_response();
    }

    (StatusCode::OK, "Approval processed").into_response()
}

/// GET handler for approval gate URLs.
///
/// Returns a confirmation page with a POST form. The state-changing
/// resolution happens in [`approval_gate_handler`] (POST), never in
/// this GET — link previewers (Slack/Teams/Gmail unfurl workers),
/// browser prefetch, and corporate proxy scanners routinely GET
/// shared URLs, so approving on bare GET would silently auto-resolve
/// gates whenever the URL was shared. RFC 7231 §4.2.1: GET is a safe
/// method and must not have observable side effects.
///
/// The preview looks up the gate to show title + description so the
/// reviewer knows what they're about to decide on, and refuses to
/// show a form for gates that are expired / already resolved.
pub async fn approval_gate_preview(
    Path((token, action)): Path<(String, String)>,
    Extension(db_pool): Extension<Pool<Postgres>>,
) -> impl IntoResponse {
    let is_approve = match action.as_str() {
        "approve" => true,
        "reject" => false,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                axum::response::Html("<h1>Invalid action</h1><p>Use /approve or /reject.</p>"),
            )
                .into_response()
        }
    };
    if token.len() != 64 || !token.chars().all(|c| c.is_ascii_hexdigit()) {
        return (
            StatusCode::BAD_REQUEST,
            axum::response::Html("<h1>Invalid token</h1>"),
        )
            .into_response();
    }
    let row: Option<(
        String,
        String,
        Option<String>,
        chrono::DateTime<chrono::Utc>,
    )> = match sqlx::query_as(
        "SELECT status, title, description, expires_at \
             FROM workflow_approval_gates \
             WHERE token = $1",
    )
    .bind(&token)
    .fetch_optional(&db_pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            // MCP-535: don't mask DB errors as "gate not found". Renders
            // the same 404 page (we can't show the user a 500 without
            // breaking the approval-link UX), but the operator gets a
            // structured log to drive alerting on Postgres availability.
            tracing::error!(
                token_len = token.len(),
                error = %e,
                "approval gate preview: workflow_approval_gates lookup failed; \
                 returning not-found"
            );
            None
        }
    };
    let (status, title, description, expires_at) = match row {
        Some(r) => r,
        None => {
            return (
                StatusCode::NOT_FOUND,
                axum::response::Html("<h1>Approval gate not found</h1><p>The link may have expired or already been used.</p>"),
            )
                .into_response()
        }
    };
    if status != "pending" {
        let msg = format!(
            "<h1>Already resolved</h1><p>This gate was already <strong>{}</strong>.</p>",
            status
        );
        return (StatusCode::CONFLICT, axum::response::Html(msg)).into_response();
    }
    if expires_at <= chrono::Utc::now() {
        return (
            StatusCode::GONE,
            axum::response::Html("<h1>Gate expired</h1>"),
        )
            .into_response();
    }

    let (verb, colour) = if is_approve {
        ("Approve", "#22c55e")
    } else {
        ("Reject", "#ef4444")
    };
    let title_safe = html_escape(&title);
    let description_safe = description.as_deref().map(html_escape).unwrap_or_default();

    // Auto-submitting forms are a footgun — require a human click to
    // POST. The `action` attribute posts back to the same URL.
    let html = format!(
        r#"<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>Talos — Confirm {verb}</title>
<style>
  body{{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f8fafc}}
  .card{{background:#fff;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.08);padding:48px 56px;text-align:left;max-width:520px}}
  h1{{color:{colour};font-size:1.75rem;margin-bottom:8px}}
  h2{{color:#0f172a;font-size:1.125rem;margin:0 0 4px 0}}
  p.desc{{color:#475569;margin:8px 0 24px}}
  form{{display:inline-block;margin-top:8px}}
  button{{background:{colour};color:#fff;border:0;border-radius:8px;padding:12px 24px;font-size:1rem;cursor:pointer}}
  button:hover{{filter:brightness(0.95)}}
  .muted{{color:#94a3b8;font-size:.875rem;margin-top:16px}}
</style></head><body>
<div class="card">
  <h1>Confirm {verb}</h1>
  <h2>{title_safe}</h2>
  <p class="desc">{description_safe}</p>
  <form method="POST" action="">
    <button type="submit">{verb}</button>
  </form>
  <p class="muted">This action is final and cannot be undone.</p>
</div></body></html>"#
    );
    (StatusCode::OK, axum::response::Html(html)).into_response()
}

/// Minimal HTML escape for dynamic content embedded in the preview
/// page (gate title, description). The approval page is served with
/// a tight CSP, but defence in depth is cheap here and the gate fields
/// are user-provided at creation time.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Human-accessible approval gate handler (POST).
///
/// Called when a human submits the confirmation form rendered by
/// [`approval_gate_preview`]. Authentication is the cryptographically
/// random token embedded in the URL path. No session cookie or API
/// key is required.
///
/// On success returns a minimal HTML page confirming the decision.
pub async fn approval_gate_handler(
    Path((token, action)): Path<(String, String)>,
    Extension(db_pool): Extension<Pool<Postgres>>,
    Extension(nats_client): Extension<Option<Arc<async_nats::Client>>>,
    Extension(registry): Extension<Arc<ModuleRegistry>>,
    // Shared SecretsManager — wired into the axum router as
    // `Option<Arc<SecretsManager>>` (always Some on production startup).
    // Required so trigger_continuation_workflow can pass it through to
    // the engine instead of constructing per call.
    Extension(secrets_manager): Extension<Option<Arc<SecretsManager>>>,
) -> impl IntoResponse {
    // Validate action
    let is_approve = match action.as_str() {
        "approve" => true,
        "reject" => false,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                axum::response::Html("<h1>Invalid action</h1><p>Use /approve or /reject.</p>"),
            )
                .into_response()
        }
    };

    // Sanitise token: must be 64 hex chars (32 bytes)
    if token.len() != 64 || !token.chars().all(|c| c.is_ascii_hexdigit()) {
        return (
            StatusCode::BAD_REQUEST,
            axum::response::Html("<h1>Invalid token</h1>"),
        )
            .into_response();
    }

    // Look up the gate — we compare status and expiry atomically in the UPDATE
    // 2026-05-28 audit follow-up (low confidence): the WHERE token = $1
    // lookup uses Postgres byte-level comparator, not the canonical
    // workspace `subtle::ConstantTimeEq` discipline used elsewhere
    // (csrf, api-keys, totp, registry signature, webhook HMAC). The
    // 64-char hex pre-filter at line 2976 bounds attack surface in
    // practice. A proper hardening would (1) add `token_hash` column
    // (SHA-256 prefix index), (2) lookup by hash, (3) ct_eq the full
    // token after fetch. Deferred — schema change with backfill cost.
    let row: Option<(
        uuid::Uuid,
        String,
        Option<uuid::Uuid>,
        serde_json::Value,
        uuid::Uuid,
    )> = match sqlx::query_as(
        "SELECT id, status, continuation_workflow_id, payload, user_id \
         FROM workflow_approval_gates \
         WHERE token = $1",
    )
    .bind(&token)
    .fetch_optional(&db_pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            // MCP-535: see the preview-path comment above — same rationale.
            // Approve/reject is an action endpoint, so masking a DB error
            // as 404 also means the operator user thinks the link expired
            // when in fact Postgres just hiccupped. Log it.
            tracing::error!(
                token_len = token.len(),
                error = %e,
                "approval gate action: workflow_approval_gates lookup failed; \
                 returning not-found"
            );
            None
        }
    };

    let (gate_id, current_status, continuation_wf_id, payload, user_id) = match row {
        Some(r) => r,
        None => {
            return (
                StatusCode::NOT_FOUND,
                axum::response::Html("<h1>Approval gate not found</h1><p>The link may have expired or already been used.</p>"),
            )
                .into_response()
        }
    };

    if current_status != "pending" {
        let msg = format!(
            "<h1>Already resolved</h1><p>This gate was already <strong>{}</strong>.</p>",
            current_status
        );
        return (StatusCode::CONFLICT, axum::response::Html(msg)).into_response();
    }

    let new_status = if is_approve { "approved" } else { "rejected" };

    let updated = sqlx::query(
        "UPDATE workflow_approval_gates \
         SET status = $1, resolved_at = NOW(), resolved_by_type = 'human_url' \
         WHERE id = $2 AND status = 'pending' AND expires_at > NOW()",
    )
    .bind(new_status)
    .bind(gate_id)
    .execute(&db_pool)
    .await
    .map(|r| r.rows_affected())
    .unwrap_or(0);

    if updated == 0 {
        return (
            StatusCode::GONE,
            axum::response::Html("<h1>Gate expired or already resolved</h1>"),
        )
            .into_response();
    }

    // Trigger the continuation workflow if approved.
    // Uses the same engine-dispatch path as trigger_workflow so the execution actually runs.
    let triggered_msg = if is_approve {
        if let Some(cwf_id) = continuation_wf_id {
            // Skip the trigger if the SecretsManager extension wasn't wired
            // — this path is exercised in tests with a stub router. In
            // production it's always Some(...) so this is just a safety guard.
            let Some(sm) = secrets_manager.clone() else {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "SecretsManager extension missing",
                )
                    .into_response();
            };
            let exec_id = talos_continuation_trigger::trigger_continuation_workflow(
                &db_pool,
                registry,
                nats_client,
                sm,
                user_id,
                cwf_id,
                &payload,
                gate_id,
                talos_continuation_trigger::TriggerSourceKind::ApprovalGate,
            )
            .await;

            if exec_id.is_some() {
                "<p>The continuation workflow has been triggered.</p>"
            } else {
                "<p>Note: The continuation workflow could not be triggered automatically. Please start it manually.</p>"
            }
        } else {
            ""
        }
    } else {
        ""
    };

    let (icon, heading, colour) = if is_approve {
        ("✅", "Approved", "#22c55e")
    } else {
        ("❌", "Rejected", "#ef4444")
    };

    let html = format!(
        r#"<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>Talos — Gate {heading}</title>
<style>
  body{{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f8fafc}}
  .card{{background:#fff;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.08);padding:48px 56px;text-align:center;max-width:480px}}
  h1{{color:{colour};font-size:2rem;margin-bottom:8px}}
  p{{color:#64748b;margin:0}}
</style></head><body>
<div class="card">
  <div style="font-size:4rem">{icon}</div>
  <h1>{heading}</h1>
  <p>The approval gate has been <strong>{new_status}</strong>.</p>
  {triggered_msg}
  <p style="margin-top:24px;font-size:.875rem">You may close this tab.</p>
</div></body></html>"#
    );

    (StatusCode::OK, axum::response::Html(html)).into_response()
}

// ────────────────────────────────────────────────────────────────────────────
// Webhook DLQ — fire-and-forget persistence of dropped payloads
// ────────────────────────────────────────────────────────────────────────────

/// Enqueue a dropped webhook payload into the dead-letter queue.
///
/// Fire-and-forget via `tokio::spawn` — never blocks the response path.
/// Authorization headers (Authorization, Cookie) are stripped before storage.
/// Payload is DLP-scrubbed before storage.
fn enqueue_webhook_dlq(
    pool: sqlx::PgPool,
    trigger_id: Option<Uuid>,
    source_ip: Option<std::net::IpAddr>,
    drop_reason: &'static str,
    headers: &axum::http::HeaderMap,
    body: &axum::body::Bytes,
) {
    // MCP-525: build a sanitized header map.
    //
    // Pre-fix the skip list missed several alt-auth header conventions
    // that real third-party integrations use:
    //   * `X-Auth-Token` (Atlassian Forge, some Microsoft surfaces)
    //   * `X-Access-Token` (assorted REST APIs)
    //   * `Proxy-Authorization` (HTTP RFC 7235)
    //   * `X-Goog-Api-Key`, `X-Goog-User-Project` (Google APIs)
    //   * `X-Anthropic-Api-Key` (rare but used in some self-hosted)
    //   * `X-Amz-Security-Token` (AWS STS via sigv4)
    //
    // And header VALUES never went through DLP at all — only the body
    // did. A legitimate caller whose webhook was dropped (trigger not
    // found, rate-limited, etc.) could leak any `sk-…` / `ghp_…` /
    // `Bearer …` / 20-char AWS access key embedded in a custom header
    // into `webhook_dlq.headers`. Operators inspecting the DLQ would
    // see those literals verbatim until manual rotation. Now: skip
    // list expanded AND every surviving header value runs through
    // `talos_dlp_provider::redact_str` before persistence, same
    // boundary the body has gone through since the DLQ feature
    // shipped.
    let skip_headers = [
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-verification-token",
        "x-auth-token",
        "x-access-token",
        "x-csrf-token",
        "x-goog-api-key",
        "x-goog-user-project",
        "x-amz-security-token",
        "x-anthropic-api-key",
    ];
    let mut header_map = serde_json::Map::new();
    for (name, value) in headers.iter() {
        let name_lower = name.as_str().to_lowercase();
        if skip_headers.contains(&name_lower.as_str()) {
            continue;
        }
        if let Ok(v) = value.to_str() {
            // DLP-redact the value before storage. Catches secrets
            // embedded in non-listed custom integration headers
            // (operator can't enumerate every third-party convention).
            let scrubbed = talos_dlp_provider::redact_str(v);
            header_map.insert(name.to_string(), serde_json::Value::String(scrubbed));
        }
    }
    let headers_json = serde_json::Value::Object(header_map);

    // Parse and DLP-scrub the payload
    let payload_json =
        serde_json::from_slice::<serde_json::Value>(body).unwrap_or(serde_json::Value::Null);
    let scrubbed_payload = talos_dlp_provider::redact_json(&payload_json);

    // Skip null payloads (parse failure on empty bodies)
    if scrubbed_payload.is_null() {
        return;
    }

    let source_ip_str = source_ip.map(|ip| ip.to_string());

    tokio::spawn(async move {
        let result = sqlx::query(
            "INSERT INTO webhook_dlq (trigger_id, source_ip, drop_reason, headers, payload) \
             VALUES ($1, $2::inet, $3, $4, $5)",
        )
        .bind(trigger_id)
        .bind(source_ip_str.as_deref())
        .bind(drop_reason)
        .bind(&headers_json)
        .bind(&scrubbed_payload)
        .execute(&pool)
        .await;

        if let Err(e) = result {
            tracing::warn!("Failed to enqueue webhook DLQ entry: {}", e);
        }
    });
}

// ────────────────────────────────────────────────────────────────────────────
// Suspension callback handler — no auth (correlation_id IS the bearer token)
// ────────────────────────────────────────────────────────────────────────────

/// POST /api/callbacks/:correlation_id
///
/// Called by external systems to resume a workflow suspension.
/// The correlation_id (256-bit random) acts as the bearer token.
/// No authentication middleware — the secrecy of the URL IS the auth.
pub async fn suspension_callback_handler(
    Path(correlation_id): axum::extract::Path<String>,
    Extension(db_pool): Extension<sqlx::PgPool>,
    Extension(registry): Extension<Arc<talos_registry::ModuleRegistry>>,
    Extension(nats_client): Extension<Option<Arc<async_nats::Client>>>,
    Extension(secrets_manager): Extension<Option<Arc<SecretsManager>>>,
    body: axum::body::Bytes,
) -> axum::response::Response {
    // Validate: exactly 64 lowercase hex chars
    if correlation_id.len() != 64 || !correlation_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return (
            StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({
                "error": "Not found"
            })),
        )
            .into_response();
    }

    // Parse body as JSON payload (treat parse errors as empty payload, not 400)
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or(serde_json::json!({}));

    // Atomic check-and-claim: a single UPDATE...WHERE status='waiting'...RETURNING
    // closes the TOCTOU window between SELECT (status='waiting') and UPDATE
    // (mark resumed). Without this, two concurrent POSTs to the same
    // correlation_id both pass a separate SELECT and both fire the
    // continuation workflow before either UPDATE lands. With the atomic
    // claim, exactly one wins; the loser gets None and returns 404.
    let row = sqlx::query(
        "UPDATE workflow_suspensions \
         SET status='resumed', resumed_at=now(), resumed_by='callback_url', resumed_payload=$1 \
         WHERE correlation_id = $2 AND status = 'waiting' \
         RETURNING id, user_id, continuation_workflow_id",
    )
    .bind(&payload)
    .bind(&correlation_id)
    .fetch_optional(&db_pool)
    .await;

    let row = match row {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                axum::Json(serde_json::json!({
                    "error": "Suspension not found or already consumed"
                })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("suspension_callback_handler DB claim failed: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({
                    "error": "Internal error"
                })),
            )
                .into_response();
        }
    };

    use sqlx::Row;
    let suspension_id: Uuid = row.get("id");
    let user_id: Uuid = row.get("user_id");
    let continuation_id: Option<Uuid> = row.get("continuation_workflow_id");

    // Trigger continuation workflow if configured
    let exec_id = if let Some(wf_id) = continuation_id {
        let Some(sm) = secrets_manager.clone() else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({"error": "SecretsManager extension missing"})),
            )
                .into_response();
        };
        talos_continuation_trigger::trigger_continuation_workflow(
            &db_pool,
            registry,
            nats_client,
            sm,
            user_id,
            wf_id,
            &payload,
            suspension_id,
            talos_continuation_trigger::TriggerSourceKind::WorkflowSuspension,
        )
        .await
    } else {
        None
    };

    // Note: the suspension was already marked resumed by the atomic
    // claim UPDATE above. No second UPDATE is needed.

    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "resumed": true,
            "execution_id": exec_id,
        })),
    )
        .into_response()
}

#[cfg(test)]
mod timestamp_skew_tests {
    use super::webhook_timestamp_skew_secs;

    // The webhook freshness gate (`skew > 300 → reject`) must hold for EVERY
    // caller-supplied timestamp. `(now - ts).abs()` did not: ts near i64::MIN
    // overflows (debug panic; release .abs()-of-wrapped-MIN is negative, so the
    // `> 300` check silently passes a stale request). abs_diff is overflow-free.
    #[test]
    fn normal_skew_is_exact() {
        assert_eq!(
            webhook_timestamp_skew_secs(1_700_000_300, 1_700_000_000),
            300
        );
        assert_eq!(
            webhook_timestamp_skew_secs(1_700_000_000, 1_700_000_300),
            300
        );
        assert_eq!(webhook_timestamp_skew_secs(1_700_000_000, 1_700_000_000), 0);
    }

    #[test]
    fn extreme_timestamps_yield_huge_skew_not_panic_or_negative() {
        let now = 1_700_000_000i64;
        // The exact crafted value that made `(now - ts)` wrap to i64::MIN under
        // the old code (now - 2^63), plus the i64 extremes. All must produce a
        // huge skew that is comfortably > the 300s window — i.e. REJECTED.
        for ts in [
            i64::MIN,
            i64::MAX,
            now.wrapping_sub(i64::MIN), // = now + 2^63 region
            -9_223_372_035_154_775_808, // ≈ now - 2^63: old code → skew == i64::MIN (negative!)
        ] {
            let skew = webhook_timestamp_skew_secs(now, ts);
            assert!(
                skew > 300,
                "ts={ts} produced skew={skew}, which would PASS the freshness gate"
            );
        }
    }
}

#[cfg(test)]
mod auth_downgrade_tests {
    use super::webhook_must_fail_closed_on_hmac;

    // MEDIUM (auth downgrade): the predicate must fail closed ONLY when an
    // HMAC signing secret was configured but could not be resolved.
    #[test]
    fn configured_but_unresolved_fails_closed() {
        // signing_secret_enc present, decryption failed -> 401, no fallback.
        assert!(webhook_must_fail_closed_on_hmac(true, false));
    }

    #[test]
    fn configured_and_resolved_does_not_fail_closed() {
        // Normal HMAC path — verification proceeds against the secret.
        assert!(!webhook_must_fail_closed_on_hmac(true, true));
    }

    #[test]
    fn not_configured_allows_static_token_fallback() {
        // No signing secret configured -> static verification_token branch
        // is legitimately reachable; the guard must NOT fire.
        assert!(!webhook_must_fail_closed_on_hmac(false, false));
        // Degenerate (resolved-but-not-configured) is impossible in practice
        // but must also not fail closed.
        assert!(!webhook_must_fail_closed_on_hmac(false, true));
    }
}
