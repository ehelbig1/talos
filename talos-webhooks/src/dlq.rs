use sqlx::{Pool, Postgres, Row};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use uuid::Uuid;

// ============================================================================
// Dead Letter Queue (DLQ) System — Bounded, Backpressure-Aware
// ============================================================================

/// Maximum number of PENDING (not yet replayed) `webhook_dlq` rows. Pre-auth
/// drops (circuit breaker, rate limit) are sender-driven, so without a cap a
/// sender over a trigger's limit grows the table without bound between
/// retention sweeps. Enforced per batch in `flush_batch`.
const DLQ_MAX_PENDING: usize = 10_000;
/// DLQ channel capacity for async processing.
const DLQ_CHANNEL_CAPACITY: usize = 1_000;

/// Key under which `enqueue_dlq` records, INSIDE the stored `headers` JSONB
/// map, whether the dropped request had passed the auth gate. A JSON field on
/// an existing column rather than a schema change. The value is a JSON `bool`
/// written LAST by the engine, so a sender-supplied header of the same name
/// (header tokens may contain `_`) is overwritten and could only ever have
/// been a string anyway.
pub const DLQ_AUTHENTICATED_KEY: &str = "__talos_dlq_authenticated";

/// Was this DLQ entry captured AFTER the request authenticated?
///
/// Strict: only a JSON `true` under [`DLQ_AUTHENTICATED_KEY`] counts. A
/// missing map, a missing key (every row written before the marker existed —
/// all of which were captured above the auth gate), a string `"true"`, or
/// `false` all answer `false`, and `dispatch_replay` refuses on `false`.
pub fn dlq_entry_was_authenticated(headers: Option<&serde_json::Value>) -> bool {
    matches!(
        headers.and_then(|h| h.get(DLQ_AUTHENTICATED_KEY)),
        Some(serde_json::Value::Bool(true))
    )
}

/// Why `dispatch_replay` refused to re-dispatch an entry. Carried inside the
/// `anyhow::Error` so the GraphQL mutation can `downcast_ref` and show the
/// operator the actual reason (both are caller-safe: neither names a table, a
/// query or a secret) while every OTHER failure keeps the generic
/// "Replay failed" that hides internals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayRefused {
    /// The entry was captured above the auth gate (F2).
    Unauthenticated,
    /// The trigger is disabled; the live path refuses it at step 1.
    TriggerDisabled,
}

impl std::fmt::Display for ReplayRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplayRefused::Unauthenticated => f.write_str(
                "DLQ entry was captured before the request was authenticated (dropped at the \
                 circuit-breaker or rate-limit gate, ahead of signature / verification-token \
                 checks) — replaying it would dispatch a never-verified payload as the trigger's \
                 owner. Refused; if the sender is legitimate, have it re-deliver.",
            ),
            ReplayRefused::TriggerDisabled => f.write_str(
                "Webhook trigger is disabled — the live delivery path refuses this trigger, so \
                 replay does too. Enable the trigger before replaying.",
            ),
        }
    }
}

impl std::error::Error for ReplayRefused {}

/// DLQ entry for failed webhook payloads.
#[derive(Debug, Clone)]
pub(crate) struct DlqEntry {
    pub(crate) trigger_id: Option<Uuid>,
    pub(crate) source_ip: Option<String>,
    pub(crate) drop_reason: String,
    pub(crate) headers: serde_json::Value,
    pub(crate) payload: serde_json::Value,
}

/// The entries of `batch` that fit under `cap` given `pending` rows already
/// stored. Authenticated (replayable) entries are kept before pre-auth drop
/// records, each in arrival order. `pending == None` (count unreadable) keeps
/// everything.
fn select_within_cap(batch: &[DlqEntry], pending: Option<usize>, cap: usize) -> Vec<&DlqEntry> {
    let Some(pending) = pending else {
        return batch.iter().collect();
    };
    let budget = cap.saturating_sub(pending);
    let (auth, pre_auth): (Vec<&DlqEntry>, Vec<&DlqEntry>) = batch
        .iter()
        .partition(|e| dlq_entry_was_authenticated(Some(&e.headers)));
    auth.into_iter().chain(pre_auth).take(budget).collect()
}

/// Global DLQ metrics for monitoring.
#[derive(Debug, Default)]
pub struct DlqMetrics {
    pub enqueued: AtomicUsize,
    pub dropped_queue_full: AtomicUsize,
    pub dropped_null_payload: AtomicUsize,
    /// Entries dropped because the table already held `DLQ_MAX_PENDING`.
    pub dropped_at_cap: AtomicUsize,
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

        // Spawn background processor.
        //
        // 2026-09-08: supervised. This is the (b)/(c) shape the wrapper
        // exists for — the `Notify` arm flushes and `break`s, so the loop
        // CAN stop while the process runs on, and every DLQ write after
        // that point is silently dropped at the channel with no signal
        // anywhere. Note the `Some(entry) = receiver.recv()` arm does NOT
        // end the loop when every sender is dropped: an unmatched pattern
        // disables that branch for one `select!` evaluation only, and the
        // interval arm can never disable, so the loop keeps running.
        talos_task_supervision::spawn_supervised(
            talos_task_supervision::BackgroundTask::DlqBatchProcessor,
            async move {
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
                            break talos_task_supervision::TaskExit::ShuttingDown;
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
            },
        );

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
        batch: &[DlqEntry],
        metrics: &Arc<DlqMetrics>,
        dlq_tx: &tokio::sync::broadcast::Sender<talos_engine::events::DlqEvent>,
    ) {
        // One bounded count per batch (index-only on `idx_webhook_dlq_pending`).
        // An unreadable count does not drop anything: the DLQ is a record, and
        // a failing count means the inserts below will likely fail and be
        // counted as `db_errors` anyway.
        let pending = match sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM (SELECT 1 FROM webhook_dlq WHERE replayed_at IS NULL LIMIT $1) p",
        )
        .bind(DLQ_MAX_PENDING as i64)
        .fetch_one(db_pool)
        .await
        {
            Ok(n) => Some(usize::try_from(n).unwrap_or(DLQ_MAX_PENDING)),
            Err(e) => {
                tracing::warn!(error = %e, "dlq: pending-count read failed; cap not applied to this batch");
                None
            }
        };
        let kept = select_within_cap(batch, pending, DLQ_MAX_PENDING);
        let dropped = batch.len() - kept.len();
        if dropped > 0 {
            metrics.dropped_at_cap.fetch_add(dropped, Ordering::Relaxed);
            if let Some(m) = talos_metrics::global() {
                m.webhook_dlq_drops_total.inc_by(dropped as f64);
                m.dlq_drops_total.inc_by(dropped as f64);
            }
            tracing::warn!(
                dropped,
                cap = DLQ_MAX_PENDING,
                "webhook DLQ at its pending cap — dropping entries (unauthenticated first)"
            );
        }
        for entry in kept {
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
                    let (id, created_at) = match (
                        row.try_get::<Uuid, _>("id"),
                        row.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
                    ) {
                        (Ok(id), Ok(at)) => (id, at),
                        (Err(e), _) | (_, Err(e)) => {
                            tracing::error!(error = %e, "dlq: inserted row unreadable; no event emitted");
                            continue;
                        }
                    };
                    // These three are LEFT JOIN columns, so None is a real
                    // value — but `.ok()` also erased schema drift, and
                    // flush_batch returns () so there is no `?` to reach for.
                    // Read them once, loudly: drift is logged and the
                    // fire-and-forget event still goes out.
                    let ownership: std::result::Result<
                        (Option<Uuid>, Option<Uuid>, Option<Uuid>),
                        sqlx::Error,
                    > = (|| {
                        Ok((
                            row.try_get::<Option<Uuid>, _>("workflow_id")?,
                            row.try_get::<Option<Uuid>, _>("user_id")?,
                            row.try_get::<Option<Uuid>, _>("org_id")?,
                        ))
                    })();
                    if let Err(ref e) = ownership {
                        tracing::error!(
                            error = %e,
                            "dlq: could not read workflow/user/org ownership columns — \
                             emitting the event UNSCOPED; this is schema drift, not an \
                             unowned webhook"
                        );
                    }
                    let (wf_id, ev_user_id, ev_org_id) = ownership.unwrap_or((None, None, None));
                    // Broadcast event for real-time UI updates
                    let _ = dlq_tx.send(talos_engine::events::DlqEvent {
                        id,
                        workflow_id: wf_id,
                        execution_id: None,
                        node_id: None,
                        error_message: Some(entry.drop_reason.clone()),
                        payload: Some(entry.payload.to_string()),
                        created_at: created_at.to_rfc3339(),
                        replayed_at: None,
                        user_id: ev_user_id,
                        org_id: ev_org_id,
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

/// **The wiring nothing else can see.** The DLQ batch processor goes through
/// `talos_task_supervision::spawn_supervised`; reverting that site to a
/// bare `tokio::spawn` is behaviourally identical on a healthy process
/// and completely silent on a dead one — no metric moves, no log line
/// appears, and every operator surface keeps reporting the subsystem as
/// configured. Structural lint check 58 cannot see it either: it asks
/// whether a metric has an increment SITE, not whether anything reaches
/// one.
///
/// The counting rule lives in `talos_task_supervision` so the pins in
/// the eight crates that carry one cannot drift; its stated limits
/// (textual, per-file, blind to WHICH task is named) apply here.
#[cfg(test)]
mod authenticity_marker_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_a_json_true_under_the_marker_counts() {
        assert!(dlq_entry_was_authenticated(Some(&json!({
            DLQ_AUTHENTICATED_KEY: true,
            "content-type": "application/json"
        }))));
    }

    #[test]
    fn legacy_rows_and_forgeries_read_as_unauthenticated() {
        // No headers at all.
        assert!(!dlq_entry_was_authenticated(None));
        // Pre-marker row: a header map with no stamp.
        assert!(!dlq_entry_was_authenticated(Some(&json!({
            "content-type": "application/json"
        }))));
        // Explicitly unauthenticated (both live enqueue sites today).
        assert!(!dlq_entry_was_authenticated(Some(&json!({
            DLQ_AUTHENTICATED_KEY: false
        }))));
        // A sender-supplied header of the same name can only be a string.
        assert!(!dlq_entry_was_authenticated(Some(&json!({
            DLQ_AUTHENTICATED_KEY: "true"
        }))));
        // Not an object.
        assert!(!dlq_entry_was_authenticated(Some(&json!("true"))));
    }
}

#[cfg(test)]
mod task_supervision_pin {
    #[test]
    fn the_long_lived_loop_is_supervised() {
        let (supervised, bare) =
            talos_task_supervision::production_spawn_counts(include_str!("dlq.rs"));
        assert_eq!(
            supervised, 1,
            "The DLQ batch processor must still go through spawn_supervised"
        );
        assert_eq!(
            bare, 0,
            "the set of deliberately-unsupervised one-shot spawns in this file changed"
        );
    }
}

#[cfg(test)]
mod pending_cap_tests {
    use super::*;

    fn entry(authenticated: bool, n: u32) -> DlqEntry {
        DlqEntry {
            trigger_id: None,
            source_ip: None,
            drop_reason: format!("r{n}"),
            headers: serde_json::json!({ DLQ_AUTHENTICATED_KEY: authenticated }),
            payload: serde_json::json!({}),
        }
    }

    #[test]
    fn the_cap_keeps_replayable_entries_first() {
        let batch = vec![
            entry(false, 1),
            entry(true, 2),
            entry(false, 3),
            entry(true, 4),
        ];
        let kept: Vec<_> = select_within_cap(&batch, Some(8), 10)
            .into_iter()
            .map(|e| e.drop_reason.clone())
            .collect();
        assert_eq!(kept, vec!["r2", "r4"]);
        assert!(select_within_cap(&batch, Some(10), 10).is_empty());
        assert!(select_within_cap(&batch, Some(50), 10).is_empty());
        assert_eq!(select_within_cap(&batch, Some(0), 10).len(), 4);
    }

    #[test]
    fn an_unreadable_count_drops_nothing() {
        let batch = vec![entry(false, 1), entry(true, 2)];
        assert_eq!(select_within_cap(&batch, None, 0).len(), 2);
    }
}
