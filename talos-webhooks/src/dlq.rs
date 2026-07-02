use sqlx::{Pool, Postgres, Row};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use uuid::Uuid;

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
    pub(crate) trigger_id: Option<Uuid>,
    pub(crate) source_ip: Option<String>,
    pub(crate) drop_reason: String,
    pub(crate) headers: serde_json::Value,
    pub(crate) payload: serde_json::Value,
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
