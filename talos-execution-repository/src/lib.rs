/// ExecutionRepository — centralises all SQL for the executions domain.
///
/// Follows the WorkflowRepository pattern: plain struct, `new(db_pool)`,
/// all methods `pub async fn`, return `anyhow::Result<T>` so callers can `?`.
/// Handlers in `mcp/executions.rs` should be thin wrappers that call these
/// methods and format the JSON-RPC response.
use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// Row DTOs
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct ExecutionRow {
    pub id: Uuid,
    pub workflow_id: Uuid,
    pub status: String,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub output_data: Option<serde_json::Value>,
    pub error_message: Option<String>,
    pub is_pinned: bool,
    pub pin_note: Option<String>,
    pub replayed_from_id: Option<Uuid>,
    pub actor_id: Option<Uuid>,
    pub workflow_version_id: Option<Uuid>,
    pub priority: Option<i32>,
    pub is_test_execution: bool,
    pub provenance: Option<serde_json::Value>,
    pub acknowledged_at: Option<chrono::DateTime<chrono::Utc>>,
    pub acknowledgement_reason: Option<String>,
}

#[derive(Debug)]
pub struct ExecutionSummary {
    pub id: Uuid,
    pub workflow_id: Uuid,
    pub workflow_name: Option<String>,
    pub status: String,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
    pub is_pinned: bool,
    pub priority: Option<i32>,
    pub pin_note: Option<String>,
}

#[derive(Debug)]
pub struct NodeHistoryEvent {
    pub execution_id: Uuid,
    pub event_type: String,
    pub status: Option<String>,
    pub log_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub execution_started_at: Option<DateTime<Utc>>,
}

#[derive(Debug)]
pub struct ExecutionEvent {
    pub event_type: String,
    pub node_id: Option<Uuid>,
    pub status: Option<String>,
    pub log_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub iteration_index: Option<i32>,
    /// Wall-clock duration in ms from node_started to completion. Auto-computed by DB trigger.
    pub duration_ms: Option<i64>,
    /// Machine-readable failure class stamped by the engine/dispatcher on
    /// `node_failed` and `retry_skipped` events. Values include
    /// `"non-transient"`, `"transient"`, `"not_found"`, classifier tags.
    /// Null on success events and on rows pre-dating engine v0.2.
    pub error_class: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Repository
// ─────────────────────────────────────────────────────────────────────────────

pub struct ExecutionRepository {
    db_pool: PgPool,
    /// Optional SecretsManager for encrypting/decrypting execution output at rest.
    /// When present AND `TALOS_ENCRYPT_EXECUTION_OUTPUT` is not "false", output is
    /// encrypted via AES-256-GCM before storage. When absent, output is stored as
    /// plaintext JSONB (legacy/dev mode).
    secrets_manager: Option<Arc<talos_secrets_manager::SecretsManager>>,
    /// Optional sender for broadcasting workflow execution lifecycle events.
    workflow_execution_tx:
        Option<tokio::sync::broadcast::Sender<talos_engine_events::WorkflowExecutionEvent>>,
}

/// Single row returned by `tail_workflow_logs`.
#[derive(Debug, Clone)]
pub struct WorkflowLogRow {
    pub id: Uuid,
    pub execution_id: Uuid,
    pub node_id: Option<Uuid>,
    pub level: String,
    pub message: String,
    pub metadata: Option<serde_json::Value>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Single row returned by `list_child_executions`.
#[derive(Debug, Clone)]
pub struct ChildExecutionRow {
    pub execution_id: Uuid,
    pub workflow_id: Uuid,
    pub workflow_name: Option<String>,
    pub status: String,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub error_message: Option<String>,
}

/// MCP-1211 (2026-05-18): workflow whose recent executions terminated a
/// loop node via the `max_iterations` safety cap. Returned by
/// [`ExecutionRepository::find_loop_capped_workflows_24h`]. Lives here
/// (rather than analytics-repo) because the underlying query must
/// decrypt `output_data_enc` and only this crate has the
/// `SecretsManager`-backed decrypt path.
#[derive(Debug, Clone)]
pub struct LoopCappedWorkflowRow {
    pub workflow_id: Uuid,
    pub workflow_name: String,
    pub occurrence_count: i64,
    pub last_seen: Option<chrono::DateTime<chrono::Utc>>,
}

/// Outcome of [`ExecutionRepository::re_encrypt_outputs_to_org`].
#[derive(Debug, Clone, Default)]
pub struct OutputReEncryptStats {
    pub re_encrypted: u64,
    pub failed: u64,
}

impl ExecutionRepository {
    pub fn new(db_pool: PgPool) -> Self {
        Self {
            db_pool,
            secrets_manager: None,
            workflow_execution_tx: None,
        }
    }

    /// Attach a sender for workflow execution lifecycle events.
    pub fn with_workflow_execution_sender(
        mut self,
        tx: tokio::sync::broadcast::Sender<talos_engine_events::WorkflowExecutionEvent>,
    ) -> Self {
        self.workflow_execution_tx = Some(tx);
        self
    }

    /// Append a worker-emitted log line to `workflow_execution_logs`.
    ///
    /// Returns `Ok(true)` when the row was written, `Ok(false)` when
    /// `execution_id` is NOT a `workflow_executions` row (the caller should
    /// fall back to the module-log table). The insert is guarded by
    /// `WHERE EXISTS (… workflow_executions …)` so a standalone-module
    /// `execution_id` is a clean 0-row no-op instead of tripping the FK
    /// constraint — Postgres logged the latter as an `ERROR` line per
    /// standalone-module log, which was noisy for log-based alerting.
    /// Genuine failures (the per-execution 5000-entry rate-limit trigger,
    /// DB outage) still surface as `Err` so the caller doesn't misroute a
    /// real workflow log to the module table.
    pub async fn add_workflow_log(
        &self,
        execution_id: Uuid,
        node_id: Option<Uuid>,
        level: &str,
        message: &str,
        metadata: Option<&serde_json::Value>,
    ) -> Result<bool> {
        // Caller-side defense in depth: trigger enforces 5000-entry cap;
        // we cap individual messages here so a single rogue log line
        // can't bloat the table. Keep in sync with module_executions::MAX_LOG_MESSAGE_LENGTH.
        const MAX_MSG_LEN: usize = 8 * 1024;
        let trimmed: String = if message.chars().count() > MAX_MSG_LEN {
            let mut s: String = message.chars().take(MAX_MSG_LEN).collect();
            s.push_str(&format!(
                "... (truncated {} chars)",
                message.chars().count() - MAX_MSG_LEN
            ));
            s
        } else {
            message.to_string()
        };
        // Strip control chars except newlines/tabs (mirror module logger).
        let sanitized: String = trimmed
            .chars()
            .filter(|c| !c.is_control() || matches!(*c, '\n' | '\t' | '\r'))
            .collect();
        // MCP-481: DLP-scrub the log message before persisting to
        // `workflow_execution_logs.message`. Mirrors the same fix in
        // `talos-module-executions::add_log` — both log surfaces are
        // queryable via `tail_worker_logs` and the GraphQL log
        // subscription, and a WASM module / engine event that emits
        // a Bearer / sk- / ghp_ token would otherwise land it raw in
        // long-lived log storage. Same persistence-boundary rule the
        // DLQ / failure-alert paths follow (MCP-443/447/466).
        let sanitized = talos_dlp_provider::redact_str(&sanitized);

        // MCP-561: DLP-scrub the `metadata` JSONB column too. MCP-481
        // covered `message` but `metadata` is a JSON value that may
        // ALSO carry secrets when a WASM module emits structured
        // tracing fields — e.g. `metadata: {"http_response_body":
        // "Unauthorized: sk-ant-xxx", "request_headers": {...}}`. The
        // same persistence-boundary applies: the row is queryable via
        // `tail_worker_logs` (and surfaces in the GraphQL log
        // subscription), so an unscrubbed leak lives in long-lived log
        // storage and reaches operator dashboards. Use the
        // depth-bounded `redact_json` (MCP-559) so a pathologically
        // nested metadata payload can't trigger the stack-overflow
        // class through this path either.
        //
        // MCP-562: also cap metadata size at 1 MB so the workflow log
        // path mirrors `talos-module-executions::add_log`'s
        // `validate_jsonb_size` ceiling. The WASM log subscriber in
        // `controller::main` shuttles WASM-supplied metadata straight
        // into this path; without a cap a NATS-allowed 1 MB metadata
        // payload bloats workflow_execution_logs unboundedly (the
        // table has a 5000-row trigger but no per-row size limit).
        // Same defense-in-depth as the module-log path; oversized
        // metadata is dropped with a warn rather than failing the
        // log write (best-effort contract: the message still lands).
        //
        // MCP-1162 (2026-05-17): check size BEFORE redact_json. Pre-fix
        // sequence was `redact_json(v)` → `to_string(redacted)` →
        // size-check → drop-if-oversized. A malicious or buggy WASM
        // module emitting 10 MB metadata paid the full
        // O(N × pattern_count) regex pass via `redact_json` on every
        // log entry, only to have the result dropped at the size gate.
        //
        // MCP-1206 (2026-05-17): collapsed the inline measure-first
        // block to the canonical `talos_dlp_provider::redact_json_bounded`
        // helper. Same 1 MiB cap (`MAX_LOG_METADATA_BYTES`), same
        // measure-first-then-redact discipline. The canonical helper
        // emits a generic `log_metadata_oversized_dropped` warn; this
        // call site adds a tracing span carrying `execution_id` so
        // the operator-correlation context the inline implementation
        // previously stamped into the warn record is preserved on the
        // surrounding span instead.
        let scrubbed_metadata = {
            let _span = tracing::trace_span!(
                "add_workflow_log_metadata_bound",
                %execution_id,
            )
            .entered();
            metadata.and_then(talos_dlp_provider::redact_json_bounded)
        };

        // Guarded insert (see method doc): write only when execution_id is
        // really a workflow_executions row, so a standalone-module id is a
        // 0-row no-op rather than an FK-violation ERROR in the Postgres log.
        let result = sqlx::query(
            "INSERT INTO workflow_execution_logs \
                 (execution_id, node_id, level, message, metadata) \
             SELECT $1, $2, $3, $4, $5 \
             WHERE EXISTS (SELECT 1 FROM workflow_executions WHERE id = $1)",
        )
        .bind(execution_id)
        .bind(node_id)
        .bind(level)
        .bind(sanitized)
        .bind(scrubbed_metadata)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Tail logs for a workflow execution. Filters by optional node_id /
    /// minimum level / since timestamp. Caller MUST authorize the
    /// execution_id against the user — this method does NOT check.
    /// Returns ascending-by-created_at; cap defaults to 500, max 5000.
    pub async fn tail_workflow_logs(
        &self,
        execution_id: Uuid,
        node_id: Option<Uuid>,
        min_level: Option<&str>,
        since: Option<chrono::DateTime<chrono::Utc>>,
        limit: i64,
    ) -> Result<Vec<WorkflowLogRow>> {
        let limit = limit.clamp(1, 5000);
        // Level rank: DEBUG < INFO < WARN < ERROR. We filter "rows whose
        // level rank >= caller's min_level rank" via a subquery rather than
        // dynamic SQL.
        let min_rank = match min_level.unwrap_or("DEBUG") {
            "DEBUG" => 0,
            "INFO" => 1,
            "WARN" => 2,
            "ERROR" => 3,
            _ => 0,
        };
        // UNION across two sources:
        //   1. workflow_execution_logs — direct workflow-scoped lines (engine
        //      events, future native workflow logging).
        //   2. module_execution_logs scoped to child module_executions of this
        //      workflow_execution. The worker publishes wasm.log.{exec_id} where
        //      exec_id is the per-NODE module_executions.id, so today every
        //      `talos::core::logging::log` call from inside a workflow node lands
        //      here. The JOIN routes them back to the parent workflow_execution.
        let rows = sqlx::query(
            "WITH unified AS ( \
                SELECT id, execution_id, node_id, level, message, metadata, created_at \
                FROM workflow_execution_logs \
                WHERE execution_id = $1 \
              UNION ALL \
                SELECT mel.id, $1::uuid AS execution_id, NULL::uuid AS node_id, \
                       mel.level, mel.message, mel.metadata, mel.created_at \
                FROM module_execution_logs mel \
                JOIN module_executions me ON me.id = mel.execution_id \
                WHERE me.workflow_execution_id = $1 \
             ) \
             SELECT * FROM unified \
             WHERE ($2::uuid IS NULL OR node_id = $2) \
               AND ($3::timestamptz IS NULL OR created_at >= $3) \
               AND CASE level \
                     WHEN 'DEBUG' THEN 0 \
                     WHEN 'INFO'  THEN 1 \
                     WHEN 'WARN'  THEN 2 \
                     WHEN 'ERROR' THEN 3 \
                     ELSE 0 END >= $4 \
             ORDER BY created_at ASC \
             LIMIT $5",
        )
        .bind(execution_id)
        .bind(node_id)
        .bind(since)
        .bind(min_rank)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;

        rows.iter()
            .map(|r| -> Result<WorkflowLogRow> {
                Ok(WorkflowLogRow {
                    id: r.try_get::<Option<_>, _>("id")?.unwrap_or_default(),
                    execution_id: r
                        .try_get::<Option<_>, _>("execution_id")?
                        .unwrap_or(execution_id),
                    node_id: r.try_get::<Option<_>, _>("node_id")?,
                    level: r.try_get::<Option<_>, _>("level")?.unwrap_or_default(),
                    message: r.try_get::<Option<_>, _>("message")?.unwrap_or_default(),
                    metadata: r.try_get::<Option<_>, _>("metadata")?,
                    created_at: r
                        .try_get("created_at")
                        .unwrap_or_else(|_| chrono::Utc::now()),
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    /// Create with SecretsManager for output encryption at rest.
    pub fn with_encryption(
        db_pool: PgPool,
        sm: Arc<talos_secrets_manager::SecretsManager>,
    ) -> Self {
        Self {
            db_pool,
            secrets_manager: Some(sm),
            workflow_execution_tx: None,
        }
    }

    /// Returns true if output encryption is enabled (SecretsManager present + not disabled).
    fn output_encryption_enabled(&self) -> bool {
        self.secrets_manager.is_some()
            && std::env::var("TALOS_ENCRYPT_EXECUTION_OUTPUT")
                .map(|v| v != "false")
                .unwrap_or(true)
    }

    /// Encrypt a JSON value for storage. Returns (key_id, encrypted_bytes,
    /// format_version). MCP-S2: `exec_id` is bound as AAD so an attacker
    /// with DB write capability can't swap user B's output_data_enc onto
    /// user A's execution row to leak it through the read path.
    ///
    /// Per-org DEK arc: encrypts under the execution's tenant org root DEK (v4).
    /// The execution's tenant IS the workflow's org (RFC 0004/0005), so resolve
    /// it via the WORKFLOW — `workflows.org_id` is stamped at every insert site,
    /// whereas `workflow_executions.org_id` is intentionally NOT auto-stamped
    /// (high-write perf exclusion, migration 20260529140000) and is usually NULL
    /// on new rows. `None` (no workflow org) → v3 global. The returned
    /// `format_version` (3 or 4) is bound by every caller, so a v4 row is never
    /// mislabeled. AAD stays = exec_id; decrypt keys off the stored key_id.
    async fn encrypt_output(
        &self,
        exec_id: Uuid,
        output: &serde_json::Value,
    ) -> Result<(Uuid, Vec<u8>, i16)> {
        let sm = self
            .secrets_manager
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SecretsManager not available for output encryption"))?;
        let json_str = serde_json::to_string(output)?;
        let org_row: Option<Option<Uuid>> = sqlx::query_scalar(
            "SELECT w.org_id FROM workflow_executions we \
             JOIN workflows w ON w.id = we.workflow_id WHERE we.id = $1",
        )
        .bind(exec_id)
        .fetch_optional(&self.db_pool)
        .await?;
        let org_id = org_row.flatten();
        sm.encrypt_value_aad_v4_or_global(&json_str, org_id, exec_id.as_bytes())
            .await
    }

    /// Decrypt encrypted output bytes back to JSON. Dispatches on the
    /// per-row `output_data_format` column (0 = legacy no-AAD, 1 =
    /// AAD-bound to exec_id).
    async fn decrypt_output(
        &self,
        exec_id: Uuid,
        key_id: Uuid,
        encrypted: &[u8],
        format_version: i16,
    ) -> Result<serde_json::Value> {
        let sm = self
            .secrets_manager
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SecretsManager not available for output decryption"))?;
        let json_str = sm
            .decrypt_versioned(key_id, encrypted, exec_id.as_bytes(), format_version)
            .await?;
        serde_json::from_str(&json_str).map_err(Into::into)
    }

    /// Per-org DEK arc: migrate EXISTING encrypted execution outputs to their
    /// workflow's org root DEK (format v4). Sibling of the secrets / actor_memory
    /// sweeps; the cutover only converts NEW writes, this brings stored rows over
    /// so the global DEK can retire for execution output.
    ///
    /// Selects rows with an encrypted output not already on v4 whose workflow has
    /// an org, then decrypts + re-encrypts via the SAME helpers the live write
    /// path uses — `encrypt_output` resolves the workflow's org (the execution
    /// tenant). Outputs whose workflow has no org stay on the global DEK.
    /// `workflow_executions.org_id` is left as-is (the high-write perf exclusion);
    /// the org is authoritative via the workflow join. Lost-write guard: the
    /// UPDATE only fires while the row is still on the (key, format) we read.
    /// No-op when no SecretsManager is wired.
    pub async fn re_encrypt_outputs_to_org(&self) -> Result<OutputReEncryptStats> {
        if self.secrets_manager.is_none() {
            return Ok(OutputReEncryptStats::default());
        }

        let rows = sqlx::query(
            "SELECT we.id, we.output_data_enc, we.output_enc_key_id, we.output_data_format \
             FROM workflow_executions we JOIN workflows w ON w.id = we.workflow_id \
             WHERE we.output_data_enc IS NOT NULL \
               AND we.output_data_format <> $1 \
               AND w.org_id IS NOT NULL",
        )
        .bind(talos_secrets_manager::SecretsManager::AAD_FORMAT_V4_ORG_DERIVED)
        .fetch_all(&self.db_pool)
        .await
        .map_err(|e| anyhow::anyhow!("re_encrypt_outputs_to_org: select stale rows: {e}"))?;

        let mut re_encrypted = 0u64;
        let mut failed = 0u64;
        for r in &rows {
            let exec_id: Uuid = r.get("id");
            let enc: Vec<u8> = r.get("output_data_enc");
            let key_id: Uuid = r.get("output_enc_key_id");
            let fmt: i16 = r.get("output_data_format");

            let value = match self.decrypt_output(exec_id, key_id, &enc, fmt).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(%exec_id, "output per-org sweep: decrypt failed: {e}");
                    failed += 1;
                    continue;
                }
            };
            let (new_key_id, new_enc, new_fmt) = match self.encrypt_output(exec_id, &value).await {
                Ok(t) => t,
                Err(e) => {
                    tracing::error!(%exec_id, "output per-org sweep: re-encrypt failed: {e}");
                    failed += 1;
                    continue;
                }
            };

            match sqlx::query(
                "UPDATE workflow_executions \
                 SET output_data_enc = $1, output_enc_key_id = $2, output_data_format = $3 \
                 WHERE id = $4 AND output_enc_key_id = $5 AND output_data_format = $6",
            )
            .bind(&new_enc)
            .bind(new_key_id)
            .bind(new_fmt)
            .bind(exec_id)
            .bind(key_id)
            .bind(fmt)
            .execute(&self.db_pool)
            .await
            {
                Ok(res) => {
                    if res.rows_affected() > 0 {
                        re_encrypted += 1;
                    } else {
                        tracing::debug!(%exec_id, "output per-org sweep: row concurrently re-keyed; skipped");
                    }
                }
                Err(e) => {
                    tracing::error!(%exec_id, "output per-org sweep: update failed: {e}");
                    failed += 1;
                }
            }
        }

        tracing::info!(
            re_encrypted,
            failed,
            "Per-org execution-output re-encryption sweep complete"
        );
        Ok(OutputReEncryptStats {
            re_encrypted,
            failed,
        })
    }

    /// Read output_data from a row, transparently decrypting if stored encrypted.
    /// Falls back to plaintext `output_data` column ONLY for legacy rows (where
    /// `output_data_enc` is NULL). If encrypted data exists but decryption fails,
    /// returns None rather than falling back to plaintext — this prevents returning
    /// ciphertext if the plaintext column somehow contains the encrypted bytes.
    ///
    /// MCP-S2: the row's `id` is read alongside the ciphertext so the
    /// decrypt path can dispatch on `output_data_format` and supply the
    /// correct AAD bytes. Callers MUST SELECT `id` + `output_data_format`
    /// in their query — without them, decryption falls back to v0.
    async fn read_output_from_row(
        &self,
        row: &sqlx::postgres::PgRow,
    ) -> Result<Option<serde_json::Value>> {
        let enc_bytes: Option<Vec<u8>> = row.try_get::<Option<_>, _>("output_data_enc")?;
        let enc_key_id: Option<Uuid> = row.try_get::<Option<_>, _>("output_enc_key_id")?;

        if let (Some(bytes), Some(key_id)) = (enc_bytes, enc_key_id) {
            // Encrypted row — the AAD format version and row `id` are
            // load-bearing for AEAD dispatch. MCP-S2 twin of lint check 34:
            // a MISSING/renamed `output_data_format` column must NOT silently
            // default to v0 here (that would dispatch the wrong AAD and fail
            // decryption on a v3/v4 row → silent data loss). The contract above
            // requires callers to SELECT `id` + `output_data_format`; enforce
            // it by failing loud (return None + error log) instead of guessing.
            let format_version: i16 = match row.try_get("output_data_format") {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(
                        err = ?e,
                        "output_data_format unreadable for an encrypted row — cannot dispatch AEAD; \
                         returning None (caller must SELECT output_data_format)"
                    );
                    return Ok(None);
                }
            };
            let exec_id: Uuid = match row.try_get("id") {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(
                        err = ?e,
                        "row id unreadable for an encrypted row — cannot supply AEAD AAD; returning None"
                    );
                    return Ok(None);
                }
            };
            // Decrypt or fail. Do NOT fall back to plaintext.
            match self
                .decrypt_output(exec_id, key_id, &bytes, format_version)
                .await
            {
                Ok(val) => return Ok(Some(val)),
                Err(e) => {
                    tracing::error!(
                        err = ?e,
                        "Failed to decrypt execution output — returning None (will not fall back to plaintext)"
                    );
                    return Ok(None);
                }
            }
        }

        // Legacy row (no encrypted data) — read plaintext column
        row.try_get::<Option<_>, _>("output_data")
            .map_err(Into::into)
    }

    /// MCP-1211: find workflows whose recent executions terminated a loop
    /// node via the `max_iterations` safety cap. Returned alongside
    /// `failing_workflows` / `long_running_executions` in
    /// `get_health_dashboard` so operators get a per-workflow aggregate
    /// view of silent loop-cap waste.
    ///
    /// Lives in ExecutionRepository (not AnalyticsRepository) because
    /// output_data is stored encrypted in PG 16 (column `output_data_enc`,
    /// AES-256-GCM). A pure JSONB query `output_data @? ...` can't see
    /// encrypted bytes — it only matches legacy plaintext rows, which the
    /// deployment no longer produces. We must read + decrypt + filter in
    /// Rust. The 24h time window + status='completed' + a hard 500-row
    /// cap on the candidate SELECT bound the decrypt cost (typical
    /// daily volume is well under that). The candidate SELECT itself
    /// runs against the indexed `started_at` predicate.
    ///
    /// Scopes on `w.user_id` (workflow owner) — the same scoping used
    /// by `get_failing_workflows` (the working sibling). Initial cut
    /// scoped on `we.user_id` (execution-triggerer) but that column
    /// can be NULL for scheduled-trigger runs and out-of-band-callback
    /// runs, which silently filtered the daily-brief row out.
    ///
    /// Status filter: exclude only `archived`, NOT `draft`. The
    /// `get_failing_workflows` sibling excludes BOTH archived AND
    /// draft, but that's wrong in practice — a workflow can be
    /// `status: 'draft'` while still scheduled and running daily
    /// (operators publish-once-then-edit semantics). Excluding
    /// drafts hides every loop_max_iterations occurrence from those
    /// workflows. Diagnosed live: daily-brief was draft, hit the
    /// loop cap, was filtered out. Surfacing the draft executions
    /// IS the right operator UX — draft is a hint about authoring
    /// state, not a signal that the workflow shouldn't be observed.
    ///
    /// Scan shape: output_data is `{"<node_uuid>": {"termination_reason":
    /// "max_iterations", "iterations": N, ...}, ...}`. We iterate the
    /// top-level keys and check each value for `termination_reason ==
    /// "max_iterations"`. Engine-internal keys (prefixed `__`) are
    /// skipped — they don't carry node output.
    pub async fn find_loop_capped_workflows_24h(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<LoopCappedWorkflowRow>> {
        // MCP-S2 follow-up: project `we.id` + `we.output_data_format`
        // so `read_output_from_row` can dispatch v1 (AAD-bound)
        // ciphertexts via decrypt_versioned. Pre-fix omitted both;
        // every v1 row's decrypt fell back to v0 path with empty AAD,
        // AES-GCM tag check failed, row silently skipped → the
        // dashboard hid all loop-capped workflows in the last 24 h.
        let rows = sqlx::query(
            "SELECT we.id, we.workflow_id, w.name, we.completed_at, \
                    we.output_data, we.output_data_enc, we.output_enc_key_id, \
                    we.output_data_format \
             FROM workflow_executions we \
             JOIN workflows w ON w.id = we.workflow_id \
             WHERE w.user_id = $1 \
               AND we.started_at > NOW() - INTERVAL '24 hours' \
               AND we.status = 'completed' \
               AND (w.status IS NULL OR w.status != 'archived') \
             ORDER BY we.completed_at DESC LIMIT 500",
        )
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;

        // Aggregate by workflow_id in-memory.
        use std::collections::HashMap;
        let mut agg: HashMap<Uuid, (String, i64, Option<chrono::DateTime<chrono::Utc>>)> =
            HashMap::new();
        for r in rows {
            let Some(output) = self.read_output_from_row(&r).await? else {
                continue;
            };
            let Some(obj) = output.as_object() else {
                continue;
            };
            let has_loop_cap = obj.iter().any(|(k, v)| {
                if k.starts_with("__") {
                    return false;
                }
                v.get("termination_reason").and_then(|t| t.as_str()) == Some("max_iterations")
            });
            if !has_loop_cap {
                continue;
            }
            let workflow_id: Uuid = r.get("workflow_id");
            let workflow_name: String = r.try_get::<Option<String>, _>("name")?.unwrap_or_default();
            let completed_at: Option<chrono::DateTime<chrono::Utc>> =
                r.try_get::<Option<_>, _>("completed_at")?;
            let entry = agg
                .entry(workflow_id)
                .or_insert_with(|| (workflow_name.clone(), 0, None));
            entry.1 += 1;
            if let Some(c) = completed_at {
                entry.2 = Some(match entry.2 {
                    Some(prev) if prev > c => prev,
                    _ => c,
                });
            }
        }
        let mut out: Vec<LoopCappedWorkflowRow> = agg
            .into_iter()
            .map(
                |(workflow_id, (workflow_name, occurrence_count, last_seen))| {
                    LoopCappedWorkflowRow {
                        workflow_id,
                        workflow_name,
                        occurrence_count,
                        last_seen,
                    }
                },
            )
            .collect();
        out.sort_by(|a, b| {
            b.occurrence_count
                .cmp(&a.occurrence_count)
                .then(b.last_seen.cmp(&a.last_seen))
        });
        out.truncate(10);
        Ok(out)
    }

    // ── System settings ────────────────────────────────────────────────────

    /// Returns true if global execution queue is paused.
    pub async fn is_execution_paused(&self) -> Result<bool> {
        let paused: Option<bool> = sqlx::query_scalar(
            "SELECT (value)::text = 'true' FROM system_settings WHERE key = 'execution_paused'",
        )
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(paused.unwrap_or(false))
    }

    /// Upserts the execution_paused system setting.
    pub async fn set_execution_paused(&self, paused: bool) -> Result<()> {
        let value = if paused { "true" } else { "false" };
        sqlx::query(
            "INSERT INTO system_settings (key, value) VALUES ('execution_paused', $1) \
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(value)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    // ── Execution reads ────────────────────────────────────────────────────

    /// Batch sibling to [`get_execution`]. Single round-trip via
    /// `WHERE id = ANY($1) AND user_id = $2`, replacing the per-id
    /// `get_execution` loop used by report-style handlers (comparison,
    /// lineage tree, etc.). Per-row decryption runs sequentially after
    /// the SELECT — multiple rows often share a DEK, so the cache makes
    /// repeated key-fetches O(1) after the first.
    ///
    /// Empty input short-circuits without touching the DB. Result rows
    /// are returned in DB-default order (no ORDER BY); callers who need
    /// the original input ordering should index by id.
    ///
    /// Security: same user-bound scoping as `get_execution` — an attacker
    /// passing another user's id sees that row excluded from the result.
    pub async fn get_executions_by_ids(
        &self,
        exec_ids: &[Uuid],
        user_id: Uuid,
    ) -> Result<Vec<ExecutionRow>> {
        if exec_ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows = sqlx::query(
            "SELECT id, workflow_id, status, started_at, completed_at, output_data, \
                    output_data_enc, output_enc_key_id, output_data_format, \
                    error_message, is_pinned, pin_note, replayed_from_id, actor_id, \
                    workflow_version_id, priority, is_test_execution, provenance, \
                    acknowledged_at, acknowledgement_reason \
             FROM workflow_executions WHERE id = ANY($1) AND user_id = $2",
        )
        .bind(exec_ids)
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let output_data = self.read_output_from_row(&r).await?;
            out.push(ExecutionRow {
                id: r.get("id"),
                workflow_id: r.get("workflow_id"),
                status: r.get("status"),
                started_at: r.try_get::<Option<_>, _>("started_at")?,
                completed_at: r.try_get::<Option<_>, _>("completed_at")?,
                output_data,
                error_message: r.try_get::<Option<_>, _>("error_message")?,
                is_pinned: r.try_get::<Option<_>, _>("is_pinned")?.unwrap_or(false),
                pin_note: r.try_get::<Option<_>, _>("pin_note")?,
                replayed_from_id: r.try_get::<Option<_>, _>("replayed_from_id")?,
                actor_id: r.try_get::<Option<_>, _>("actor_id")?,
                workflow_version_id: r.try_get::<Option<_>, _>("workflow_version_id")?,
                priority: r.try_get::<Option<_>, _>("priority")?,
                is_test_execution: r
                    .try_get::<Option<_>, _>("is_test_execution")?
                    .unwrap_or(false),
                provenance: r.try_get::<Option<_>, _>("provenance")?,
                acknowledged_at: r.try_get::<Option<_>, _>("acknowledged_at")?,
                acknowledgement_reason: r.try_get::<Option<_>, _>("acknowledgement_reason")?,
            });
        }
        Ok(out)
    }

    /// Full execution record for a user-scoped ID. Returns None if not found/access denied.
    /// Transparently decrypts output if stored encrypted.
    pub async fn get_execution(
        &self,
        exec_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<ExecutionRow>> {
        // RFC 0005 S3: self-scope on a per-user tx so the
        // workflow_executions RLS policy backstops the read for ALL callers
        // (the MCP execution handlers + the GraphQL module-execution
        // resolver), with no per-caller change. The query already filters
        // `user_id = $2`; the scope's user-clause mirrors it.
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let row = sqlx::query(
            "SELECT id, workflow_id, status, started_at, completed_at, output_data, \
                    output_data_enc, output_enc_key_id, output_data_format, \
                    error_message, is_pinned, pin_note, replayed_from_id, actor_id, \
                    workflow_version_id, priority, is_test_execution, provenance, \
                    acknowledged_at, acknowledgement_reason \
             FROM workflow_executions WHERE id = $1 AND user_id = $2",
        )
        .bind(exec_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;

        let Some(r) = row else { return Ok(None) };
        let output_data = self.read_output_from_row(&r).await?;
        Ok(Some(ExecutionRow {
            id: r.get("id"),
            workflow_id: r.get("workflow_id"),
            status: r.get("status"),
            started_at: r.try_get::<Option<_>, _>("started_at")?,
            completed_at: r.try_get::<Option<_>, _>("completed_at")?,
            output_data,
            error_message: r.try_get::<Option<_>, _>("error_message")?,
            is_pinned: r.try_get::<Option<_>, _>("is_pinned")?.unwrap_or(false),
            pin_note: r.try_get::<Option<_>, _>("pin_note")?,
            replayed_from_id: r.try_get::<Option<_>, _>("replayed_from_id")?,
            actor_id: r.try_get::<Option<_>, _>("actor_id")?,
            workflow_version_id: r.try_get::<Option<_>, _>("workflow_version_id")?,
            priority: r.try_get::<Option<_>, _>("priority")?,
            is_test_execution: r
                .try_get::<Option<_>, _>("is_test_execution")?
                .unwrap_or(false),
            provenance: r.try_get::<Option<_>, _>("provenance")?,
            acknowledged_at: r.try_get::<Option<_>, _>("acknowledged_at")?,
            acknowledgement_reason: r.try_get::<Option<_>, _>("acknowledgement_reason")?,
        }))
    }

    /// Executions for a workflow (paginated). Left joins workflow to get name.
    /// Total count of executions for a workflow scoped to a user. Used by
    /// `list_executions` to populate the pagination envelope (`total`,
    /// `has_more`). Separate from `list_executions` so the LIMIT / OFFSET
    /// page query stays cheap; the count can be approximated server-side
    /// in a future optimisation if it becomes a hot path.
    pub async fn count_executions(&self, wf_id: Uuid, user_id: Uuid) -> Result<i64> {
        // RFC 0005 S3: self-scope (see get_execution).
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM workflow_executions WHERE workflow_id = $1 AND user_id = $2",
        )
        .bind(wf_id)
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(count)
    }

    pub async fn list_executions(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ExecutionSummary>> {
        // RFC 0005 S3: self-scope (see get_execution). The LEFT JOIN to
        // workflows also picks up the workflows RLS backstop.
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let rows = sqlx::query(
            "SELECT e.id, e.workflow_id, w.name AS workflow_name, e.status, \
                    e.started_at, e.completed_at, e.error_message, e.is_pinned, \
                    e.priority, e.pin_note \
             FROM workflow_executions e \
             LEFT JOIN workflows w ON w.id = e.workflow_id \
             WHERE e.workflow_id = $1 AND e.user_id = $2 \
             ORDER BY e.started_at DESC, e.id DESC LIMIT $3 OFFSET $4",
        )
        .bind(wf_id)
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;

        rows.into_iter()
            .map(|r| -> Result<ExecutionSummary> {
                Ok(ExecutionSummary {
                    id: r.get("id"),
                    workflow_id: r.get("workflow_id"),
                    workflow_name: r.try_get::<Option<_>, _>("workflow_name")?,
                    status: r.get("status"),
                    started_at: r.try_get::<Option<_>, _>("started_at")?,
                    completed_at: r.try_get::<Option<_>, _>("completed_at")?,
                    error_message: r.try_get::<Option<_>, _>("error_message")?,
                    is_pinned: r.try_get::<Option<_>, _>("is_pinned")?.unwrap_or(false),
                    priority: r.try_get::<Option<_>, _>("priority")?,
                    pin_note: r.try_get::<Option<_>, _>("pin_note")?,
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    /// Most recent execution for a workflow (for watch_execution workflow_id lookup).
    pub async fn get_latest_execution_for_workflow(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<ExecutionRow>> {
        let row = sqlx::query(
            "SELECT id, workflow_id, status, started_at, completed_at, output_data, \
                    output_data_enc, output_enc_key_id, output_data_format, \
                    error_message, is_pinned, pin_note, replayed_from_id, actor_id, \
                    workflow_version_id, priority, is_test_execution, provenance \
             FROM workflow_executions \
             WHERE workflow_id = $1 AND user_id = $2 \
             ORDER BY started_at DESC NULLS LAST \
             LIMIT 1",
        )
        .bind(wf_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;

        let Some(r) = row else { return Ok(None) };
        let output_data = self.read_output_from_row(&r).await?;
        Ok(Some(ExecutionRow {
            id: r.get("id"),
            workflow_id: r.get("workflow_id"),
            status: r.get("status"),
            started_at: r.try_get::<Option<_>, _>("started_at")?,
            completed_at: r.try_get::<Option<_>, _>("completed_at")?,
            output_data,
            error_message: r.try_get::<Option<_>, _>("error_message")?,
            is_pinned: r.try_get::<Option<_>, _>("is_pinned")?.unwrap_or(false),
            pin_note: r.try_get::<Option<_>, _>("pin_note")?,
            replayed_from_id: r.try_get::<Option<_>, _>("replayed_from_id")?,
            actor_id: r.try_get::<Option<_>, _>("actor_id")?,
            workflow_version_id: r.try_get::<Option<_>, _>("workflow_version_id")?,
            priority: r.try_get::<Option<_>, _>("priority")?,
            is_test_execution: r
                .try_get::<Option<_>, _>("is_test_execution")?
                .unwrap_or(false),
            provenance: r.try_get::<Option<_>, _>("provenance")?,
            acknowledged_at: None,
            acknowledgement_reason: None,
        }))
    }

    /// Recent executions across all workflows, with optional status filter. Cap at 50.
    pub async fn list_recent_executions(
        &self,
        user_id: Uuid,
        limit: i64,
        status_filter: Option<&str>,
    ) -> Result<Vec<ExecutionSummary>> {
        let rows = sqlx::query(
            "SELECT e.id, e.workflow_id, w.name AS workflow_name, e.status, \
                    e.started_at, e.completed_at, e.error_message, e.is_pinned, \
                    e.priority, e.pin_note \
             FROM workflow_executions e \
             LEFT JOIN workflows w ON w.id = e.workflow_id \
             WHERE e.user_id = $1 AND ($2::text IS NULL OR e.status = $2) \
             ORDER BY e.started_at DESC LIMIT $3",
        )
        .bind(user_id)
        .bind(status_filter)
        .bind(limit.min(50))
        .fetch_all(&self.db_pool)
        .await?;

        rows.into_iter()
            .map(|r| -> Result<ExecutionSummary> {
                Ok(ExecutionSummary {
                    id: r.get("id"),
                    workflow_id: r.get("workflow_id"),
                    workflow_name: r.try_get::<Option<_>, _>("workflow_name")?,
                    status: r.get("status"),
                    started_at: r.try_get::<Option<_>, _>("started_at")?,
                    completed_at: r.try_get::<Option<_>, _>("completed_at")?,
                    error_message: r.try_get::<Option<_>, _>("error_message")?,
                    is_pinned: r.try_get::<Option<_>, _>("is_pinned")?.unwrap_or(false),
                    priority: r.try_get::<Option<_>, _>("priority")?,
                    pin_note: r.try_get::<Option<_>, _>("pin_note")?,
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    /// All pinned executions for a user.
    pub async fn list_pinned_executions(&self, user_id: Uuid) -> Result<Vec<ExecutionSummary>> {
        let rows = sqlx::query(
            "SELECT e.id, e.workflow_id, w.name AS workflow_name, e.status, \
                    e.started_at, e.completed_at, e.error_message, e.is_pinned, \
                    e.priority, e.pin_note \
             FROM workflow_executions e \
             LEFT JOIN workflows w ON w.id = e.workflow_id \
             WHERE e.user_id = $1 AND e.is_pinned = true \
             ORDER BY e.started_at DESC LIMIT 1000",
        )
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;

        rows.into_iter()
            .map(|r| -> Result<ExecutionSummary> {
                Ok(ExecutionSummary {
                    id: r.get("id"),
                    workflow_id: r.get("workflow_id"),
                    workflow_name: r.try_get::<Option<_>, _>("workflow_name")?,
                    status: r.get("status"),
                    started_at: r.try_get::<Option<_>, _>("started_at")?,
                    completed_at: r.try_get::<Option<_>, _>("completed_at")?,
                    error_message: r.try_get::<Option<_>, _>("error_message")?,
                    is_pinned: r.try_get::<Option<_>, _>("is_pinned")?.unwrap_or(false),
                    priority: r.try_get::<Option<_>, _>("priority")?,
                    pin_note: r.try_get::<Option<_>, _>("pin_note")?,
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    /// Walk the replayed_from_id chain up to max_depth. Returns ordered list oldest→newest.
    ///
    /// MCP-658 (2026-05-13): single recursive-CTE round trip instead of
    /// max_depth+1 sequential queries. Pre-fix the handler-side caller
    /// passed max_depth=20, so a request hit Postgres 20 times back-to-back
    /// for a deep replay chain — 20 ms wall time with the local pool, but
    /// 20× connection-slot occupancy under concurrent load. The recursive
    /// CTE walks the same chain in one query and Postgres handles cycle
    /// detection natively via the implicit ROW visited-set when paired
    /// with the depth cap. The `user_id = $2` predicate fires on every
    /// recursive expansion so a chain crossing into another tenant's row
    /// (an audit-log corruption scenario) terminates instead of leaking
    /// cross-tenant rows.
    pub async fn get_execution_replay_chain(
        &self,
        exec_id: Uuid,
        user_id: Uuid,
        max_depth: usize,
    ) -> Result<Vec<ExecutionRow>> {
        // Cap at i32 — Postgres expects a signed int bind for the depth
        // comparator. usize → i32 truncation is safe because every real
        // caller passes a small constant (<=20) and the chain length is
        // bounded by execution-replay product semantics.
        let depth_cap: i32 = max_depth.try_into().unwrap_or(i32::MAX);

        let rows = sqlx::query(
            "WITH RECURSIVE chain AS ( \
                 SELECT id, workflow_id, status, started_at, completed_at, output_data, \
                        error_message, is_pinned, pin_note, replayed_from_id, actor_id, \
                        workflow_version_id, priority, is_test_execution, provenance, \
                        0 AS depth \
                 FROM workflow_executions \
                 WHERE id = $1 AND user_id = $2 \
               UNION ALL \
                 SELECT we.id, we.workflow_id, we.status, we.started_at, we.completed_at, \
                        we.output_data, we.error_message, we.is_pinned, we.pin_note, \
                        we.replayed_from_id, we.actor_id, we.workflow_version_id, \
                        we.priority, we.is_test_execution, we.provenance, \
                        c.depth + 1 \
                 FROM workflow_executions we \
                 JOIN chain c ON we.id = c.replayed_from_id \
                 WHERE we.user_id = $2 AND c.depth < $3 \
             ) \
             SELECT id, workflow_id, status, started_at, completed_at, output_data, \
                    error_message, is_pinned, pin_note, replayed_from_id, actor_id, \
                    workflow_version_id, priority, is_test_execution, provenance \
             FROM chain ORDER BY depth ASC",
        )
        .bind(exec_id)
        .bind(user_id)
        .bind(depth_cap)
        .fetch_all(&self.db_pool)
        .await?;

        let mut chain: Vec<ExecutionRow> = rows
            .into_iter()
            .map(|r| -> Result<ExecutionRow> {
                Ok(ExecutionRow {
                    id: r.get("id"),
                    workflow_id: r.get("workflow_id"),
                    status: r.get("status"),
                    started_at: r.try_get::<Option<_>, _>("started_at")?,
                    completed_at: r.try_get::<Option<_>, _>("completed_at")?,
                    output_data: r.try_get::<Option<_>, _>("output_data")?,
                    error_message: r.try_get::<Option<_>, _>("error_message")?,
                    is_pinned: r.try_get::<Option<_>, _>("is_pinned")?.unwrap_or(false),
                    pin_note: r.try_get::<Option<_>, _>("pin_note")?,
                    replayed_from_id: r.try_get::<Option<_>, _>("replayed_from_id")?,
                    actor_id: r.try_get::<Option<_>, _>("actor_id")?,
                    workflow_version_id: r.try_get::<Option<_>, _>("workflow_version_id")?,
                    priority: r.try_get::<Option<_>, _>("priority")?,
                    is_test_execution: r
                        .try_get::<Option<_>, _>("is_test_execution")?
                        .unwrap_or(false),
                    provenance: r.try_get::<Option<_>, _>("provenance")?,
                    acknowledged_at: None,
                    acknowledgement_reason: None,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        chain.reverse(); // oldest → newest
        Ok(chain)
    }

    // ── Execution events ───────────────────────────────────────────────────

    /// All events for an execution, ordered by created_at ASC. Hard cap at 1000.
    pub async fn list_execution_events(&self, exec_id: Uuid) -> Result<Vec<ExecutionEvent>> {
        let rows = sqlx::query(
            "SELECT event_type, node_id, status, log_message, created_at, iteration_index, duration_ms, error_class \
             FROM execution_events WHERE execution_id = $1 ORDER BY created_at ASC LIMIT 1000",
        )
        .bind(exec_id)
        .fetch_all(&self.db_pool)
        .await?;

        rows.into_iter()
            .map(|r| -> Result<ExecutionEvent> {
                Ok(ExecutionEvent {
                    event_type: r.get("event_type"),
                    node_id: r.try_get::<Option<_>, _>("node_id")?,
                    status: r.try_get::<Option<_>, _>("status")?,
                    log_message: r.try_get::<Option<_>, _>("log_message")?,
                    created_at: r.get("created_at"),
                    iteration_index: r.try_get::<Option<_>, _>("iteration_index")?,
                    duration_ms: r.try_get::<Option<_>, _>("duration_ms")?,
                    error_class: r.try_get::<Option<_>, _>("error_class")?,
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    /// Events for a specific node in an execution.
    pub async fn list_execution_events_for_node(
        &self,
        exec_id: Uuid,
        node_id: Uuid,
    ) -> Result<Vec<ExecutionEvent>> {
        let rows = sqlx::query(
            "SELECT event_type, node_id, status, log_message, created_at, iteration_index, duration_ms, error_class \
             FROM execution_events \
             WHERE execution_id = $1 AND node_id = $2 \
             ORDER BY created_at ASC LIMIT 1000",
        )
        .bind(exec_id)
        .bind(node_id)
        .fetch_all(&self.db_pool)
        .await?;

        rows.into_iter()
            .map(|r| -> Result<ExecutionEvent> {
                Ok(ExecutionEvent {
                    event_type: r.get("event_type"),
                    node_id: r.try_get::<Option<_>, _>("node_id")?,
                    status: r.try_get::<Option<_>, _>("status")?,
                    log_message: r.try_get::<Option<_>, _>("log_message")?,
                    created_at: r.get("created_at"),
                    iteration_index: r.try_get::<Option<_>, _>("iteration_index")?,
                    duration_ms: r.try_get::<Option<_>, _>("duration_ms")?,
                    error_class: r.try_get::<Option<_>, _>("error_class")?,
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    // ── Workflow reads (used by execution handlers) ────────────────────────

    /// Check workflow exists (any user).
    pub async fn workflow_exists_any_user(&self, wf_id: Uuid) -> Result<bool> {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM workflows WHERE id = $1)")
                .bind(wf_id)
                .fetch_one(&self.db_pool)
                .await?;
        Ok(exists)
    }

    /// Validate workflow ownership + get graph_json in one query.
    /// Returns Some(graph_json) if found for user, None if not found/access denied.
    /// SECURITY: Always includes user_id constraint to prevent cross-user access.
    pub async fn get_workflow_graph_for_user(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<String>> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT graph_json FROM workflows WHERE id = $1 AND user_id = $2")
                .bind(wf_id)
                .bind(user_id)
                .fetch_optional(&self.db_pool)
                .await?;
        Ok(row.map(|(gj,)| gj))
    }

    /// Check if workflow is enabled (used before replay/retry).
    pub async fn is_workflow_enabled(&self, wf_id: Uuid) -> Result<Option<bool>> {
        let enabled: Option<bool> =
            sqlx::query_scalar("SELECT is_enabled FROM workflows WHERE id = $1")
                .bind(wf_id)
                .fetch_optional(&self.db_pool)
                .await?;
        Ok(enabled)
    }

    /// Try active published version first. Returns (version_id, graph_json) if found.
    pub async fn get_active_version_graph(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<(Uuid, String)>> {
        // Scoped by user_id via JOIN on workflows. All current callers check
        // ownership upstream (handle_enqueue_workflow / handle_retry_execution
        // both verify via get_workflow_graph_for_user / get_execution before
        // reaching this), but the SQL itself enforces it as defense in depth
        // — a future refactor that calls this without an upstream check
        // would silently leak another user's active graph otherwise.
        let row: Option<(Uuid, String)> = sqlx::query_as(
            "SELECT v.id, v.graph_json::text \
             FROM workflow_versions v \
             JOIN workflows w ON w.id = v.workflow_id \
             WHERE v.workflow_id = $1 AND v.is_active = true AND w.user_id = $2",
        )
        .bind(wf_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(row)
    }

    // ── Create executions ──────────────────────────────────────────────────

    /// Standard execution insert. status is 'running' or 'queued'.
    /// priority is omitted — the column DEFAULT 'normal' applies. Explicitly binding None for a
    /// TEXT NOT NULL DEFAULT column would override the DEFAULT with NULL and violate the constraint.
    pub async fn create_execution(
        &self,
        exec_id: Uuid,
        wf_id: Uuid,
        user_id: Uuid,
        version_id: Option<Uuid>,
        actor_id: Option<Uuid>,
        status: &str,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO workflow_executions \
             (id, workflow_id, user_id, status, started_at, workflow_version_id, actor_id) \
             VALUES ($1, $2, $3, $4, NOW(), $5, $6)",
        )
        .bind(exec_id)
        .bind(wf_id)
        .bind(user_id)
        .bind(status)
        .bind(version_id)
        .bind(actor_id)
        .execute(&self.db_pool)
        .await?;

        if let Some(ref tx) = self.workflow_execution_tx {
            let _ = tx.send(talos_engine_events::WorkflowExecutionEvent {
                workflow_id: wf_id,
                execution_id: exec_id,
                user_id,
                status: status.to_string(),
                started_at: chrono::Utc::now().to_rfc3339(),
                error_message: None,
            });
        }
        Ok(())
    }

    /// Batch sibling to [`create_execution`] for callers that enqueue N
    /// executions sharing the same workflow_id / user_id / version_id /
    /// actor_id / status (e.g. `enqueue_workflow`'s bulk path). Single
    /// `INSERT ... SELECT ... UNNEST` round-trip replaces the prior
    /// per-input loop, and converts the prior best-effort-prefix
    /// failure mode into a clean all-or-nothing transaction — either
    /// every row queues or none do, so no caller can observe a partial
    /// state where some inputs got executions and some didn't.
    ///
    /// Empty input short-circuits without touching the DB. The
    /// per-execution event emission on the `workflow_execution_tx`
    /// channel mirrors `create_execution`'s post-INSERT behaviour.
    ///
    /// Security: same row shape and same scoping as `create_execution` —
    /// `user_id` is bound on every row and the FK on `workflow_id`
    /// enforces existence. Callers must verify ownership of `wf_id`
    /// against `user_id` upstream (handler-side responsibility, identical
    /// to `create_execution`).
    pub async fn create_executions_batch_for_workflow(
        &self,
        exec_ids: &[Uuid],
        wf_id: Uuid,
        user_id: Uuid,
        version_id: Option<Uuid>,
        actor_id: Option<Uuid>,
        status: &str,
    ) -> Result<()> {
        if exec_ids.is_empty() {
            return Ok(());
        }
        sqlx::query(
            "INSERT INTO workflow_executions \
             (id, workflow_id, user_id, status, started_at, workflow_version_id, actor_id) \
             SELECT eid, $2, $3, $4, NOW(), $5, $6 \
             FROM UNNEST($1::uuid[]) AS eid",
        )
        .bind(exec_ids)
        .bind(wf_id)
        .bind(user_id)
        .bind(status)
        .bind(version_id)
        .bind(actor_id)
        .execute(&self.db_pool)
        .await?;

        if let Some(ref tx) = self.workflow_execution_tx {
            let started_at = chrono::Utc::now().to_rfc3339();
            for &exec_id in exec_ids {
                let _ = tx.send(talos_engine_events::WorkflowExecutionEvent {
                    workflow_id: wf_id,
                    execution_id: exec_id,
                    user_id,
                    status: status.to_string(),
                    started_at: started_at.clone(),
                    error_message: None,
                });
            }
        }
        Ok(())
    }

    /// Replay execution — includes replayed_from_id and provenance chain.
    pub async fn create_replay_execution(
        &self,
        exec_id: Uuid,
        wf_id: Uuid,
        user_id: Uuid,
        replayed_from_id: Uuid,
        actor_id: Option<Uuid>,
        provenance: Option<&serde_json::Value>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO workflow_executions \
             (id, workflow_id, user_id, status, started_at, replayed_from_id, actor_id, provenance) \
             VALUES ($1, $2, $3, 'running', NOW(), $4, $5, $6)",
        )
        .bind(exec_id)
        .bind(wf_id)
        .bind(user_id)
        .bind(replayed_from_id)
        .bind(actor_id)
        .bind(provenance)
        .execute(&self.db_pool)
        .await?;

        if let Some(ref tx) = self.workflow_execution_tx {
            let _ = tx.send(talos_engine_events::WorkflowExecutionEvent {
                workflow_id: wf_id,
                execution_id: exec_id,
                user_id,
                status: "running".to_string(),
                started_at: chrono::Utc::now().to_rfc3339(),
                error_message: None,
            });
        }
        Ok(())
    }

    /// Test execution — sets is_test_execution = true.
    pub async fn create_test_execution(
        &self,
        exec_id: Uuid,
        wf_id: Uuid,
        user_id: Uuid,
        version_id: Option<Uuid>,
        priority: Option<i32>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO workflow_executions \
             (id, workflow_id, user_id, status, started_at, workflow_version_id, is_test_execution, priority) \
             VALUES ($1, $2, $3, 'running', NOW(), $4, true, $5)",
        )
        .bind(exec_id)
        .bind(wf_id)
        .bind(user_id)
        .bind(version_id)
        .bind(priority)
        .execute(&self.db_pool)
        .await?;

        if let Some(ref tx) = self.workflow_execution_tx {
            let _ = tx.send(talos_engine_events::WorkflowExecutionEvent {
                workflow_id: wf_id,
                execution_id: exec_id,
                user_id,
                status: "running".to_string(),
                started_at: chrono::Utc::now().to_rfc3339(),
                error_message: None,
            });
        }
        Ok(())
    }

    // ── Status updates ─────────────────────────────────────────────────────

    /// Reset execution back to running (used by retry — clears error/output/completed_at).
    ///
    /// MCP-693 (2026-05-13): atomic precondition `status IN ('failed',
    /// 'cancelled')` + bool return. Pre-fix, two parallel
    /// `retry(execution_id, user_id)` calls could both pass the
    /// caller-level status gate (both see `status='failed'`) then
    /// both UPDATE — neither saw the other's transition. The result
    /// was TWO concurrent engines dispatching for the SAME
    /// execution_id, racing on terminal-status writes and
    /// double-counting against the actor's hourly cap. Sibling shape
    /// to `mark_execution_running_from_queued` which had the
    /// precondition all along. Returns `true` if this caller won the
    /// transition; `false` if another concurrent caller already
    /// re-marked the row running (caller must abort the retry).
    pub async fn mark_execution_running(&self, exec_id: Uuid) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE workflow_executions \
             SET status = 'running', error_message = NULL, completed_at = NULL, \
                 started_at = NOW(), output_data = NULL, \
                 output_data_enc = NULL, output_enc_key_id = NULL \
             WHERE id = $1 AND status IN ('failed', 'cancelled')",
        )
        .bind(exec_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Transition queued → running for enqueue dispatch. Returns true if updated.
    pub async fn mark_execution_running_from_queued(&self, exec_id: Uuid) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE workflow_executions SET status = 'running', started_at = NOW() \
             WHERE id = $1 AND status = 'queued'",
        )
        .bind(exec_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Mark completed with output JSON. Encrypts output at rest when SecretsManager is available.
    /// Mark an execution as `waiting` with intermediate output. Encrypts
    /// output at rest when SecretsManager is available, mirroring
    /// `mark_execution_completed`. Used by the scheduler when an
    /// in-progress workflow yields (e.g. waiting on a sub-workflow,
    /// approval gate, or sleep node).
    pub async fn mark_execution_waiting(
        &self,
        exec_id: Uuid,
        output: &serde_json::Value,
    ) -> Result<()> {
        // Split-brain guard: `AND status = 'running'`, matching the
        // `mark_execution_completed` / `mark_execution_failed` siblings
        // (and the workflow-repository `mark_execution_waiting`). Pre-fix
        // this was the lone bare `WHERE id = $1` terminal-state writer —
        // the MCP-975 sweep added the DLP redaction here but missed the
        // status guard. Without it, a controller that has been superseded
        // (its row claimed `running -> resuming` by another controller's
        // crash-recovery sweep, or already finalized) could still write
        // 'waiting' and RESURRECT a terminal/claimed execution back into
        // the active/resumable set. The guard makes the superseded write a
        // clean no-op. Safe at every call site: each one's `else` branch
        // calls `mark_execution_completed` (already `status = 'running'`)
        // on the same row, so the row is provably 'running' here.
        let res = if self.output_encryption_enabled() {
            // MCP-S2: encrypt_output binds AAD = exec_id so a swap of
            // output_data_enc across rows is detected on read.
            let (key_id, enc_bytes, format_version) = self.encrypt_output(exec_id, output).await?;
            sqlx::query(
                "UPDATE workflow_executions \
                 SET status = 'waiting', output_data = NULL, \
                     output_data_enc = $1, output_enc_key_id = $2, \
                     output_data_format = $3 \
                 WHERE id = $4 AND status IN ('running', 'resuming')",
            )
            .bind(&enc_bytes)
            .bind(key_id)
            .bind(format_version)
            .bind(exec_id)
            .execute(&self.db_pool)
            .await?
        } else {
            // MCP-975 (2026-05-15): same plaintext-fallback DLP fix
            // as the MCP-971/972 sweep (sibling repository's
            // mark_execution_waiting + workflow-repo's). Wait-node
            // outputs commonly carry HTTP-callback response bodies
            // from upstream services; same arbitrary-text class.
            let redacted = talos_dlp_provider::redact_json(output);
            sqlx::query(
                "UPDATE workflow_executions SET status = 'waiting', output_data = $2 \
                 WHERE id = $1 AND status IN ('running', 'resuming')",
            )
            .bind(exec_id)
            .bind(&redacted)
            .execute(&self.db_pool)
            .await?
        };
        if res.rows_affected() == 0 {
            // The row was no longer 'running' — already terminal, or claimed
            // for resume by another controller (split-brain). The suspend is
            // correctly dropped; surface it so a superseded controller is
            // observable rather than silently no-op'ing.
            tracing::warn!(
                execution_id = %exec_id,
                "mark_execution_waiting no-op: row not in 'running' (already terminal \
                 or claimed for crash-recovery resume) — suspend write dropped"
            );
        }
        Ok(())
    }

    pub async fn mark_execution_completed(
        &self,
        exec_id: Uuid,
        output: &serde_json::Value,
    ) -> Result<()> {
        let result = if self.output_encryption_enabled() {
            let (key_id, enc_bytes, format_version) = self.encrypt_output(exec_id, output).await?;
            sqlx::query(
                "UPDATE workflow_executions \
                 SET status = 'completed', output_data = NULL, \
                     output_data_enc = $1, output_enc_key_id = $2, \
                     output_data_format = $3, completed_at = NOW() \
                 WHERE id = $4 AND status IN ('running', 'resuming')",
            )
            .bind(&enc_bytes)
            .bind(key_id)
            .bind(format_version)
            .bind(exec_id)
            .execute(&self.db_pool)
            .await?
        } else {
            // MCP-971: DLP-redact plaintext-fallback output. Sibling
            // to the workflow-repository fix above.
            let redacted = talos_dlp_provider::redact_json(output);
            sqlx::query(
                "UPDATE workflow_executions \
                 SET status = 'completed', output_data = $1, completed_at = NOW() \
                 WHERE id = $2 AND status IN ('running', 'resuming')",
            )
            .bind(&redacted)
            .bind(exec_id)
            .execute(&self.db_pool)
            .await?
        };
        if result.rows_affected() > 0 {
            if let Some(ref tx) = self.workflow_execution_tx {
                // Fetch user_id and workflow_id to broadcast properly
                let row = sqlx::query!("SELECT user_id, workflow_id, started_at FROM workflow_executions WHERE id = $1", exec_id)
                    .fetch_one(&self.db_pool).await;
                if let Ok(r) = row {
                    let _ = tx.send(talos_engine_events::WorkflowExecutionEvent {
                        workflow_id: r.workflow_id,
                        execution_id: exec_id,
                        user_id: r.user_id,
                        status: "completed".to_string(),
                        started_at: r.started_at.to_rfc3339(),
                        error_message: None,
                    });
                }
            }
        }
        Ok(())
    }

    /// Mark failed. output is optional (some paths have partial output).
    /// Encrypts output at rest when SecretsManager is available.
    pub async fn mark_execution_failed(
        &self,
        exec_id: Uuid,
        error: &str,
        output: Option<&serde_json::Value>,
    ) -> Result<()> {
        // MCP-967 (2026-05-15): sibling of the workflow-repository
        // mark_execution_failed redaction. Both repositories have
        // legacy-duplicate copies of this method (different ownership
        // models — the workflow-repo variant wires the SecretsManager;
        // the execution-repo variant uses output_encryption_enabled).
        // Both bind `error` directly into workflow_executions.error_message
        // and both need DLP scrubbing for the same reasons documented at
        // the workflow-repo callsite.
        //
        // MCP-1193 (2026-05-17): truncate-then-redact discipline.
        // Sibling holdout to MCP-1161 (WorkflowRepository::mark_
        // execution_failed) and MCP-1164 (AdvancedRepository +
        // ActorRepository fail_execution). This was the fourth and
        // final writer to `workflow_executions.error_message` — the
        // legacy execution-repository variant remained un-truncated
        // through both prior sweeps because it lives in a separate
        // crate that wasn't touched. The error string here originates
        // from engine failure paths (wasmtime traces, NATS-relayed
        // upstream HTTP response bodies) and is unbounded; pre-fix
        // the DLP regex pass walked the full string AND the
        // unbounded result landed in a column with no DB-side cap.
        // 4 KiB matches every sibling writer's ceiling.
        let truncated: &str = if error.len() > 4096 {
            talos_text_util::truncate_at_char_boundary(error, 4096)
        } else {
            error
        };
        let redacted_error = talos_dlp_provider::redact_str(truncated);
        let result = if self.output_encryption_enabled() {
            // Encrypt optional output if present. MCP-S2: AAD = exec_id
            // when there's something to encrypt; format_version = v1
            // regardless so the column invariant ("post-fix writes
            // always write v1") holds even on no-output failure paths.
            let (enc_bytes, enc_key_id, enc_format) = if let Some(out) = output {
                let (kid, bytes, version) = self.encrypt_output(exec_id, out).await?;
                (Some(bytes), Some(kid), version)
            } else {
                (
                    None,
                    None,
                    talos_secrets_manager::SecretsManager::AAD_FORMAT_V1,
                )
            };
            sqlx::query(
                "UPDATE workflow_executions \
                 SET status = 'failed', error_message = $1, output_data = NULL, \
                     output_data_enc = $2, output_enc_key_id = $3, \
                     output_data_format = $4, completed_at = NOW() \
                 WHERE id = $5 AND status IN ('running', 'resuming')",
            )
            .bind(&redacted_error)
            .bind(enc_bytes.as_deref())
            .bind(enc_key_id)
            .bind(enc_format)
            .bind(exec_id)
            .execute(&self.db_pool)
            .await?
        } else {
            // MCP-971: DLP-redact plaintext-fallback output. Sibling
            // to the workflow-repository fix above.
            let redacted_output = output.map(talos_dlp_provider::redact_json);
            sqlx::query(
                "UPDATE workflow_executions \
                 SET status = 'failed', error_message = $1, output_data = $2, completed_at = NOW() \
                 WHERE id = $3 AND status IN ('running', 'resuming')",
            )
            .bind(&redacted_error)
            .bind(redacted_output.as_ref())
            .bind(exec_id)
            .execute(&self.db_pool)
            .await?
        };
        if result.rows_affected() > 0 {
            if let Some(ref tx) = self.workflow_execution_tx {
                let row = sqlx::query!("SELECT user_id, workflow_id, started_at FROM workflow_executions WHERE id = $1", exec_id)
                    .fetch_one(&self.db_pool).await;
                if let Ok(r) = row {
                    let _ = tx.send(talos_engine_events::WorkflowExecutionEvent {
                        workflow_id: r.workflow_id,
                        execution_id: exec_id,
                        user_id: r.user_id,
                        status: "failed".to_string(),
                        started_at: r.started_at.to_rfc3339(),
                        // Broadcast the SAME DLP-redacted+truncated string the DB
                        // row stores (`redacted_error`, computed above), NOT the
                        // raw `error`. This event flows to the `workflow_execution_updates`
                        // GraphQL subscription, so a raw engine error echoing an
                        // upstream `Bearer`/`sk-`/… token would leak to subscribers
                        // even though the persisted row is clean. Keeping the live
                        // channel in lockstep with the persisted row is the same
                        // discipline as MCP-1011's `scrub_wasm_log_for_broadcast`.
                        error_message: Some(redacted_error.clone()),
                    });
                }
            }
        }
        Ok(())
    }

    /// Cancel if in cancellable state. Returns true if cancelled, false if wrong state.
    pub async fn mark_execution_cancelled(&self, exec_id: Uuid, user_id: Uuid) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE workflow_executions \
             SET status = 'cancelled', error_message = 'Cancelled by user', completed_at = NOW() \
             WHERE id = $1 AND user_id = $2 AND status IN ('running', 'queued', 'pending', 'resuming')",
        )
        .bind(exec_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Cancel all queued executions for a workflow. Returns the count cancelled and their IDs.
    /// Applies only to 'queued' status — running executions are not affected.
    pub async fn cancel_queued_executions_for_workflow(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Uuid>> {
        let rows: Vec<(Uuid,)> = sqlx::query_as(
            "UPDATE workflow_executions \
             SET status = 'cancelled', error_message = 'Batch cancelled by user', completed_at = NOW() \
             WHERE id IN ( \
                 SELECT id FROM workflow_executions \
                 WHERE workflow_id = $1 AND user_id = $2 AND status = 'queued' \
                 LIMIT $3 \
             ) \
             RETURNING id",
        )
        .bind(wf_id)
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    /// Acknowledge a failed execution (records reason, excludes from reliability score).
    pub async fn acknowledge_execution_failure(
        &self,
        exec_id: Uuid,
        user_id: Uuid,
        reason: &str,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE workflow_executions \
             SET acknowledged_at = now(), acknowledgement_reason = $1 \
             WHERE id = $2 AND user_id = $3",
        )
        .bind(reason)
        .bind(exec_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    // ── Pin / unpin ────────────────────────────────────────────────────────

    /// Pin an execution. Returns true if updated.
    pub async fn pin_execution(
        &self,
        exec_id: Uuid,
        user_id: Uuid,
        note: Option<&str>,
    ) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE workflow_executions SET is_pinned = true, pin_note = $1 \
             WHERE id = $2 AND user_id = $3",
        )
        .bind(note)
        .bind(exec_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Unpin an execution. Returns true if updated.
    pub async fn unpin_execution(&self, exec_id: Uuid, user_id: Uuid) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE workflow_executions SET is_pinned = false, pin_note = NULL \
             WHERE id = $1 AND user_id = $2",
        )
        .bind(exec_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    // ── Cleanup & alerts ───────────────────────────────────────────────────

    /// List stuck 'running' executions for the resume-after-restart path.
    ///
    /// Returns everything the resume needs in ONE query (LEFT JOIN against
    /// `workflows`):
    /// * `id`, `workflow_id`, `user_id`, `checkpoint_data` — basic dispatch
    ///   identity.
    /// * `actor_id` — the actor that originally triggered this execution
    ///   (NULL = anonymous trigger).
    /// * `workflow_default_actor_id` — the workflow's bound default actor
    ///   from `workflows.actor_id`, used as a fallback when `actor_id` is
    ///   NULL (mirrors the `arg.or(wf_record.actor_id)` semantics in
    ///   `handle_trigger_workflow`).
    /// * `graph_json` — the workflow definition the engine needs to load.
    ///
    /// **Why both actor columns matter**: re-stamping the original actor on
    /// resume keeps `max_llm_tier` enforcement intact across pod restarts.
    /// A tier-1 actor's resumed run must NOT silently lose its
    /// data-egress ceiling because the pod that originally booted the
    /// engine got rescheduled.
    pub async fn list_stuck_executions_for_resume(
        &self,
        stale_after_minutes: i64,
    ) -> Result<Vec<StuckExecutionForResume>> {
        let rows = sqlx::query_as::<_, StuckExecutionForResume>(
            "SELECT \
                e.id, \
                e.workflow_id, \
                e.user_id, \
                e.checkpoint_data, \
                e.actor_id, \
                w.actor_id AS workflow_default_actor_id, \
                w.graph_json \
             FROM workflow_executions e \
             LEFT JOIN workflows w ON w.id = e.workflow_id \
             WHERE e.status = 'running' \
               AND e.updated_at < NOW() - make_interval(mins => $1::int)",
        )
        .bind(stale_after_minutes)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows)
    }

    /// Mark stuck 'running' executions as 'failed' after timeout_minutes,
    /// scoped to a single user. Returns the number of executions cleaned up.
    ///
    /// Cross-tenant cleanup is deliberately not supported here — a single
    /// MCP-authenticated caller forcing every other tenant's stuck
    /// executions into 'failed' is destructive (downstream retries,
    /// alerts, SLA accounting) and isn't needed by the legitimate
    /// hygiene paths, which already operate per-user.
    pub async fn cleanup_stale_executions(
        &self,
        timeout_minutes: i64,
        user_id: Uuid,
    ) -> Result<u64> {
        // MCP-1062 (2026-05-15): refuse non-positive `timeout_minutes`.
        // Sibling caller-supplied-negative class as MCP-997. With
        // `make_interval(mins => -N)` the predicate flips to
        // `started_at < NOW() + INTERVAL`, marking every running
        // execution for the user as 'failed' — destructive at user
        // scope.
        if timeout_minutes <= 0 {
            tracing::warn!(
                target: "talos_audit",
                timeout_minutes,
                %user_id,
                "stale-executions cleanup refused: timeout_minutes must be positive (would mark every running execution as failed)"
            );
            return Ok(0);
        }
        let result = sqlx::query(
            "UPDATE workflow_executions \
             SET status = 'failed', \
                 error_message = CONCAT('Cleaned up: execution was stale (running for over ', $1::text, ' minutes)'), \
                 completed_at = NOW() \
             WHERE status = 'running' AND user_id = $2 \
               AND started_at < NOW() - make_interval(mins => $1::int)",
        )
        .bind(timeout_minutes)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Atomically CLAIM one orphaned `running` execution for crash recovery
    /// (RFC 0003 durable execution). Returns everything the resume needs, or
    /// `None` when nothing is claimable.
    ///
    /// Exactly-once across replicas: the inner `SELECT … FOR UPDATE SKIP
    /// LOCKED` picks a single candidate row and row-locks it, so concurrent
    /// claimers on other replicas skip it and grab a *different* row (or
    /// none); the status-guarded `UPDATE … WHERE status='running'` then flips
    /// it `running → resuming`. A row in `resuming` is invisible to every
    /// `WHERE status='running'` cleanup, so it can't be failed out from under
    /// recovery. `graph_json` / `workflow_default_actor_id` come from
    /// correlated subqueries (NULL if the workflow was deleted — caller
    /// treats NULL graph as a hard skip).
    ///
    /// `stale_after_minutes` is the orphan threshold: a `running` row whose
    /// `updated_at` (advanced on each checkpoint save) is older than this is
    /// presumed orphaned. Must be positive (a non-positive value would claim
    /// every running execution); refused with `None`.
    pub async fn claim_stuck_execution_for_resume(
        &self,
        stale_after_minutes: i64,
    ) -> Result<Option<StuckExecutionForResume>> {
        if stale_after_minutes <= 0 {
            tracing::warn!(
                target: "talos_audit",
                stale_after_minutes,
                "crash-recovery claim refused: stale_after_minutes must be positive"
            );
            return Ok(None);
        }
        // `epoch = epoch + 1` fences the original controller (F4): if it was
        // alive-but-slow, the epoch it holds (the pre-claim value) no longer
        // matches the row, so its fence heartbeat sees the mismatch and aborts.
        // The bumped value is returned so the resumer can heartbeat against it.
        let row = sqlx::query_as::<_, StuckExecutionForResume>(
            "WITH claimed AS ( \
                 SELECT id FROM workflow_executions \
                 WHERE status = 'running' \
                   AND updated_at < NOW() - make_interval(mins => $1::int) \
                 ORDER BY updated_at ASC \
                 LIMIT 1 \
                 FOR UPDATE SKIP LOCKED \
             ) \
             UPDATE workflow_executions e \
             SET status = 'resuming', updated_at = NOW(), epoch = e.epoch + 1 \
             FROM claimed c \
             WHERE e.id = c.id AND e.status = 'running' \
             RETURNING e.id, e.workflow_id, e.user_id, e.checkpoint_data, e.actor_id, e.epoch, \
                       (SELECT w.actor_id FROM workflows w WHERE w.id = e.workflow_id) \
                           AS workflow_default_actor_id, \
                       (SELECT w.graph_json FROM workflows w WHERE w.id = e.workflow_id) \
                           AS graph_json",
        )
        .bind(stale_after_minutes)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(row)
    }

    /// Terminal exit for a claimed (`resuming`) execution whose resume could
    /// not be dispatched (decrypt fail, engine build fail, NATS down, deleted
    /// workflow). Status-guarded on `resuming` so it never clobbers a row the
    /// engine already moved on. Returns true if it transitioned a row.
    pub async fn fail_resuming_execution(&self, id: Uuid, error_message: &str) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE workflow_executions \
             SET status = 'failed', error_message = $2, completed_at = NOW() \
             WHERE id = $1 AND status = 'resuming'",
        )
        .bind(id)
        .bind(error_message)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Read the current ownership `epoch` for an execution, or `None` if the
    /// row is gone. The fence heartbeat polls this: when the value moves past
    /// the epoch the running controller holds, that controller has been
    /// superseded (another claim/reclaim bumped it) and must abort. Cheap
    /// single-column primary-key lookup.
    pub async fn current_execution_epoch(&self, id: Uuid) -> Result<Option<i64>> {
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT epoch FROM workflow_executions WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.db_pool)
                .await?;
        Ok(row.map(|r| r.0))
    }

    /// Reclaim executions wedged in `resuming` (a replica crashed *during*
    /// recovery, before the engine took over). Older than `grace_minutes` →
    /// `failed`, so they never get stuck. Run once at startup before the main
    /// claim sweep. Returns the count reclaimed. Non-positive grace refused.
    pub async fn reclaim_orphaned_resuming(&self, grace_minutes: i64) -> Result<u64> {
        if grace_minutes <= 0 {
            tracing::warn!(
                target: "talos_audit",
                grace_minutes,
                "reclaim_orphaned_resuming refused: grace_minutes must be positive"
            );
            return Ok(0);
        }
        // `epoch = epoch + 1` fences a resumer that itself went slow: when this
        // reclaim fails its `resuming` row, the bump invalidates the epoch that
        // resumer holds, so its fence heartbeat sees the mismatch and aborts
        // rather than continuing to drive a now-`failed` row.
        let result = sqlx::query(
            "UPDATE workflow_executions \
             SET status = 'failed', \
                 error_message = 'resume interrupted (controller restarted during recovery)', \
                 completed_at = NOW(), epoch = epoch + 1 \
             WHERE status = 'resuming' \
               AND updated_at < NOW() - make_interval(mins => $1::int)",
        )
        .bind(grace_minutes)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Upsert failure alert with occurrence counter.
    pub async fn upsert_execution_failure_alert(
        &self,
        user_id: Uuid,
        wf_id: Uuid,
        exec_id: Uuid,
        message: &str,
    ) -> Result<()> {
        // N-L (2026-05-06): snapshot workflow_name into the alert row
        // so post-delete reads still surface meaningful operator
        // context. See `talos-workflow-repository::upsert_execution_failure_alert`
        // for the same pattern.
        sqlx::query(
            "INSERT INTO workflow_alerts (user_id, workflow_id, execution_id, message, workflow_name) \
             VALUES ($1, $2, $3, $4, (SELECT name FROM workflows WHERE id = $2)) \
             ON CONFLICT (workflow_id, message) WHERE acknowledged = false \
             DO UPDATE SET occurrence_count = workflow_alerts.occurrence_count + 1, \
                           last_occurred_at = NOW(), \
                           execution_id = EXCLUDED.execution_id, \
                           acknowledged = false",
        )
        .bind(user_id)
        .bind(wf_id)
        .bind(exec_id)
        .bind(message)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    // ── Additional methods ─────────────────────────────────────────────────

    /// Events after a specific timestamp (for watch_execution polling). Hard cap at 1000.
    pub async fn list_execution_events_since(
        &self,
        exec_id: Uuid,
        since: DateTime<Utc>,
    ) -> Result<Vec<ExecutionEvent>> {
        let rows = sqlx::query(
            "SELECT event_type, node_id, status, log_message, created_at, iteration_index, duration_ms, error_class \
             FROM execution_events WHERE execution_id = $1 AND created_at > $2 \
             ORDER BY created_at ASC LIMIT 1000",
        )
        .bind(exec_id)
        .bind(since)
        .fetch_all(&self.db_pool)
        .await?;

        rows.into_iter()
            .map(|r| -> Result<ExecutionEvent> {
                Ok(ExecutionEvent {
                    event_type: r.get("event_type"),
                    node_id: r.try_get::<Option<_>, _>("node_id")?,
                    status: r.try_get::<Option<_>, _>("status")?,
                    log_message: r.try_get::<Option<_>, _>("log_message")?,
                    created_at: r.get("created_at"),
                    iteration_index: r.try_get::<Option<_>, _>("iteration_index")?,
                    duration_ms: r.try_get::<Option<_>, _>("duration_ms")?,
                    error_class: r.try_get::<Option<_>, _>("error_class")?,
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    /// Direct child executions replayed from a given execution (for replay chain forward walk).
    pub async fn list_execution_descendants(
        &self,
        exec_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<Uuid>> {
        let ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM workflow_executions WHERE replayed_from_id = $1 AND user_id = $2 \
             ORDER BY started_at ASC LIMIT 10000",
        )
        .bind(exec_id)
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(ids)
    }

    /// Node execution history across multiple workflow runs for a specific node.
    pub async fn list_node_execution_history(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
        node_uuid: Uuid,
        limit: i64,
    ) -> Result<Vec<NodeHistoryEvent>> {
        let rows = sqlx::query(
            "SELECT ee.execution_id, ee.event_type, ee.status, ee.log_message, ee.created_at, \
                    we.started_at AS execution_started_at \
             FROM execution_events ee \
             JOIN workflow_executions we ON we.id = ee.execution_id \
             WHERE we.workflow_id = $1 AND we.user_id = $2 AND ee.node_id = $3 \
             ORDER BY ee.created_at DESC LIMIT $4",
        )
        .bind(wf_id)
        .bind(user_id)
        .bind(node_uuid)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;

        rows.into_iter()
            .map(|r| -> Result<NodeHistoryEvent> {
                Ok(NodeHistoryEvent {
                    execution_id: r.get("execution_id"),
                    event_type: r.get("event_type"),
                    status: r.try_get::<Option<_>, _>("status")?,
                    log_message: r.try_get::<Option<_>, _>("log_message")?,
                    created_at: r.get("created_at"),
                    execution_started_at: r.try_get::<Option<_>, _>("execution_started_at")?,
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    /// Recent executions for a workflow with full output_data — used by get_execution_delta.
    /// Returns up to `limit` completed/failed executions ordered newest-first.
    /// SECURITY: always includes user_id constraint.
    pub async fn list_executions_with_output(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<ExecutionRow>> {
        let rows = sqlx::query(
            "SELECT id, workflow_id, status, started_at, completed_at, output_data, \
                    output_data_enc, output_enc_key_id, output_data_format, \
                    error_message, is_pinned, pin_note, replayed_from_id, actor_id, \
                    workflow_version_id, priority, is_test_execution, provenance \
             FROM workflow_executions \
             WHERE workflow_id = $1 AND user_id = $2 AND status IN ('completed', 'failed') \
             ORDER BY started_at DESC \
             LIMIT $3",
        )
        .bind(wf_id)
        .bind(user_id)
        .bind(limit.clamp(2, 20))
        .fetch_all(&self.db_pool)
        .await?;

        let mut result = Vec::with_capacity(rows.len());
        for r in &rows {
            let output_data = self.read_output_from_row(r).await?;
            result.push(ExecutionRow {
                id: r.get("id"),
                workflow_id: r.get("workflow_id"),
                status: r.get("status"),
                started_at: r.try_get::<Option<_>, _>("started_at")?,
                completed_at: r.try_get::<Option<_>, _>("completed_at")?,
                output_data,
                error_message: r.try_get::<Option<_>, _>("error_message")?,
                is_pinned: r.try_get::<Option<_>, _>("is_pinned")?.unwrap_or(false),
                pin_note: r.try_get::<Option<_>, _>("pin_note")?,
                replayed_from_id: r.try_get::<Option<_>, _>("replayed_from_id")?,
                actor_id: r.try_get::<Option<_>, _>("actor_id")?,
                workflow_version_id: r.try_get::<Option<_>, _>("workflow_version_id")?,
                priority: r.try_get::<Option<_>, _>("priority")?,
                is_test_execution: r
                    .try_get::<Option<_>, _>("is_test_execution")?
                    .unwrap_or(false),
                provenance: r.try_get::<Option<_>, _>("provenance")?,
                acknowledged_at: None,
                acknowledgement_reason: None,
            });
        }
        Ok(result)
    }

    /// Update workflow graph_json (used by analyze_execution_failure apply_fix path).
    /// SECURITY: always includes user_id constraint.
    pub async fn update_workflow_graph(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
        graph_json: &str,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE workflows SET graph_json = $1, updated_at = NOW() \
             WHERE id = $2 AND user_id = $3",
        )
        .bind(graph_json)
        .bind(wf_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    /// Poll [`get_execution`] every 150 ms until the execution reaches a
    /// terminal status (`completed` / `failed` / `cancelled`) or `timeout`
    /// elapses. Returns:
    /// * `Some(status)` when a terminal row was observed within the window
    ///   — caller can then fetch the full trace.
    /// * `None` when the deadline elapsed without the row going terminal —
    ///   the execution is still running; the caller should report that
    ///   rather than blocking the request indefinitely.
    ///
    /// Caps `timeout` at 30 s — same hard ceiling as the pre-extraction
    /// inline polling loop. Caller-side validation can clamp lower if
    /// needed; this is the absolute upper bound.
    pub async fn wait_for_terminal_status(
        &self,
        execution_id: Uuid,
        user_id: Uuid,
        timeout: std::time::Duration,
    ) -> Option<String> {
        const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(150);
        const MAX_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
        let timeout = timeout.min(MAX_TIMEOUT);
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            tokio::time::sleep(POLL_INTERVAL).await;
            if let Ok(Some(row)) = self.get_execution(execution_id, user_id).await {
                if matches!(row.status.as_str(), "completed" | "failed" | "cancelled") {
                    return Some(row.status);
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
        }
    }

    /// Resolve the root execution id for a freshly-created child execution.
    ///
    /// Given the optional `parent_exec_id` supplied by a `trigger_workflow`
    /// caller, return the value to stamp into the new execution's
    /// `root_execution_id` column:
    /// * `None` when there's no parent — the new execution IS its own root
    ///   and `root_execution_id` stays NULL.
    /// * `Some(root)` when the parent itself has a `root_execution_id` —
    ///   inherit it so deep chains don't lose the original root.
    /// * `Some(parent_exec_id)` when the parent exists but has no root yet
    ///   (it's a top-level execution) — the parent IS the root.
    ///
    /// Migration-safe: if the `root_execution_id` column doesn't exist yet,
    /// or any DB error occurs, the parent is treated as the root rather
    /// than failing the trigger. Mirrors pre-extraction behavior.
    pub async fn resolve_root_from_parent(
        &self,
        parent_exec_id: Option<Uuid>,
        user_id: Uuid,
    ) -> Option<Uuid> {
        let pid = parent_exec_id?;
        match self.get_execution_root_id(pid, user_id).await {
            Ok(Some(root)) => Some(root),
            Ok(None) | Err(_) => Some(pid),
        }
    }

    /// Resolve the root execution ID for cross-workflow lineage tracking.
    ///
    /// Returns `Ok(Some(root_id))` when the execution has an explicit root,
    /// `Ok(None)` when the row exists but `root_execution_id` is NULL or the row is not found.
    /// Callers that need migration-safe fallback should treat `Err` the same as `Ok(None)`.
    pub async fn get_execution_root_id(
        &self,
        execution_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<Uuid>> {
        let row: Option<(Option<Uuid>,)> = sqlx::query_as(
            "SELECT root_execution_id FROM workflow_executions WHERE id = $1 AND user_id = $2",
        )
        .bind(execution_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(row.and_then(|(root,)| root))
    }

    // ── Lineage queries (handle_get_execution_lineage) ─────────────────────

    /// Fetch stable base columns for an execution — verifies ownership and existence.
    /// Returns `(status, workflow_id_str, actor_id_str, trigger_type)`.
    /// Returns `Err` only on a real DB failure.
    pub async fn get_execution_base(
        &self,
        execution_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<(String, String, Option<String>, Option<String>)>> {
        sqlx::query_as(
            "SELECT status, workflow_id::text, actor_id::text, \
                    COALESCE(provenance->>'trigger_type', 'manual') \
             FROM workflow_executions WHERE id = $1 AND user_id = $2",
        )
        .bind(execution_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await
        .map_err(Into::into)
    }

    /// Fetch `(root_execution_id, parent_execution_id)` for an execution —
    /// used to resolve the lineage tree root. Returns `Err` if the lineage
    /// columns don't exist yet (pre-migration); caller treats that as "use exec_id as root".
    pub async fn get_execution_lineage_root(
        &self,
        execution_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<(Option<Uuid>, Option<Uuid>)>> {
        sqlx::query_as(
            "SELECT root_execution_id, parent_execution_id \
             FROM workflow_executions WHERE id = $1 AND user_id = $2",
        )
        .bind(execution_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await
        .map_err(Into::into)
    }

    /// List the direct child executions of `parent_execution_id` with timing
    /// info. Used by `build_execution_trace_json` to surface sub-workflow
    /// dispatch latency that is otherwise invisible in the parent trace
    /// (pain point #2 from aegix_dev_pain_points.md). Capped at 64 rows
    /// because a single parent rarely fans out beyond ~10 sub-workflows;
    /// the cap is a defence against runaway dispatch loops.
    pub async fn list_child_executions(
        &self,
        parent_execution_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<ChildExecutionRow>> {
        let rows = sqlx::query(
            "SELECT we.id, we.workflow_id, we.status, we.started_at, we.completed_at, \
                    we.error_message, w.name AS workflow_name \
             FROM workflow_executions we \
             LEFT JOIN workflows w ON w.id = we.workflow_id \
             WHERE we.parent_execution_id = $1 AND we.user_id = $2 \
             ORDER BY we.started_at NULLS LAST LIMIT 64",
        )
        .bind(parent_execution_id)
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;
        rows.iter()
            .map(|r| -> Result<ChildExecutionRow> {
                Ok(ChildExecutionRow {
                    execution_id: r.get("id"),
                    workflow_id: r.get("workflow_id"),
                    workflow_name: r.try_get("workflow_name").ok(),
                    status: r.try_get::<Option<_>, _>("status")?.unwrap_or_default(),
                    started_at: r.try_get("started_at").ok(),
                    completed_at: r.try_get("completed_at").ok(),
                    error_message: r.try_get("error_message").ok(),
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    /// Fetch all executions in a lineage tree rooted at `root_id`.
    /// Returns `(id, parent_id, root_id, status, workflow_id_str, trigger_type, actor_id_str)`.
    pub async fn get_execution_lineage_tree(
        &self,
        root_id: Uuid,
        user_id: Uuid,
    ) -> Result<
        Vec<(
            Uuid,
            Option<Uuid>,
            Option<Uuid>,
            String,
            String,
            Option<String>,
            Option<String>,
        )>,
    > {
        sqlx::query_as(
            "SELECT id, parent_execution_id, root_execution_id, status, workflow_id::text, \
                    COALESCE(provenance->>'trigger_type', 'manual'), actor_id::text \
             FROM workflow_executions \
             WHERE (id = $1 OR root_execution_id = $1) AND user_id = $2 \
             ORDER BY id LIMIT 10000",
        )
        .bind(root_id)
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await
        .map_err(Into::into)
    }

    // ── resources.rs MCP-handler support ───────────────────────────────────

    /// Recent module_executions for MCP `resources/list`. Returns id, module_id,
    /// status — enough to render the resource URIs. Capped at 10 (handler
    /// surfaces the most recent only).
    pub async fn list_recent_module_executions_for_user(
        &self,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<ModuleExecutionResourceRow>> {
        let rows = sqlx::query(
            "SELECT id, module_id, status, error_message \
             FROM module_executions \
             WHERE user_id = $1 \
             ORDER BY started_at DESC NULLS LAST \
             LIMIT $2",
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        rows.iter()
            .map(|r| -> Result<ModuleExecutionResourceRow> {
                Ok(ModuleExecutionResourceRow {
                    id: r.get("id"),
                    module_id: r.get("module_id"),
                    status: r.get("status"),
                    error_message: r.try_get::<Option<_>, _>("error_message")?,
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    /// Verify that a module_execution exists and is owned by the given user.
    /// Used by `resources/read` to gate log access.
    pub async fn module_execution_owned_by(
        &self,
        execution_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool> {
        let owns: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM module_executions WHERE id = $1 AND user_id = $2)",
        )
        .bind(execution_id)
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(owns)
    }

    /// All log lines for a single module_execution (caller must verify ownership
    /// first via `module_execution_owned_by`).
    pub async fn list_module_execution_logs(
        &self,
        execution_id: Uuid,
    ) -> Result<Vec<ModuleExecutionLogRow>> {
        let rows = sqlx::query(
            "SELECT level, message, created_at \
             FROM module_execution_logs \
             WHERE execution_id = $1 \
             ORDER BY created_at ASC",
        )
        .bind(execution_id)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| ModuleExecutionLogRow {
                level: r.get("level"),
                message: r.get("message"),
                created_at: r.get("created_at"),
            })
            .collect())
    }

    /// Single module_execution detail (id/module_id/status/error/output).
    /// Returns None when the row doesn't exist OR isn't owned by the user.
    ///
    /// MCP-681 (2026-05-13): pre-fix the SELECT projected only the
    /// plaintext `output_data` column. With module-payload encryption
    /// enabled (Phase A — migration 20260424030501), the writer sets
    /// `output_data = NULL` and stores the JSON in `output_data_enc +
    /// payload_enc_key_id`. So this read silently returned
    /// `output_data: None` for every encrypted execution, and the
    /// `talos://executions/<uuid>` MCP resource showed `output_data:
    /// null` regardless of actual data. Sibling fix-class to MCP-680
    /// (which closed the same blindness on `workflow_executions.output_data_enc`).
    ///
    /// Note: `module_executions` uses `payload_enc_key_id` (shared for
    /// `input_data_enc + output_data_enc + trigger_metadata_enc`),
    /// distinct from `workflow_executions.output_enc_key_id`. Don't
    /// conflate the two — wrong column name surfaces as the test
    /// regression captured in `talos-replay-service::tests`.
    pub async fn get_module_execution_for_user(
        &self,
        execution_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<ModuleExecutionDetailRow>> {
        // MCP-S2 follow-up: project `payload_format` so the decrypt
        // dispatcher can route v1 (AAD-bound) rows correctly. Pre-fix
        // this site used `decrypt_value_by_key` (no AAD) against
        // ciphertexts that post-MCP-S2 writers stamp with AAD =
        // execution_id, silently failing decrypt for every v1 row and
        // surfacing `output_data: null` in the operator UI.
        let row: Option<(
            Uuid,
            Uuid,
            String,
            Option<String>,
            Option<serde_json::Value>,
            Option<Vec<u8>>,
            Option<Uuid>,
            i16,
        )> = sqlx::query_as(
            "SELECT id, module_id, status, error_message, \
                    output_data, output_data_enc, payload_enc_key_id, payload_format \
             FROM module_executions \
             WHERE id = $1 AND user_id = $2",
        )
        .bind(execution_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        let Some((
            id,
            module_id,
            status,
            error_message,
            plaintext,
            enc_bytes,
            key_id,
            payload_format,
        )) = row
        else {
            return Ok(None);
        };
        let output_data = match (&self.secrets_manager, enc_bytes, key_id) {
            (Some(sm), Some(bytes), Some(kid)) => {
                // 2026-05-28 review (low): route through the shared slot-AAD
                // helper (Output slot). v2 rows are slot-bound; v0/v1 rows still
                // decrypt (helper returns row-id-only AAD below v2).
                match talos_module_payload_encryption::decrypt_payload_slot(
                    sm,
                    kid,
                    &bytes,
                    id,
                    talos_module_payload_encryption::PayloadSlot::Output,
                    payload_format,
                )
                .await
                {
                    Ok(s) => serde_json::from_str(&s).ok(),
                    Err(e) => {
                        tracing::warn!(
                            err = ?e,
                            execution_id = %execution_id,
                            "get_module_execution_for_user: decrypt failed — surfacing None for output"
                        );
                        None
                    }
                }
            }
            _ => plaintext,
        };
        Ok(Some(ModuleExecutionDetailRow {
            id,
            module_id,
            status,
            error_message,
            output_data,
        }))
    }

    // ── executions.rs MCP-handler support ──────────────────────────────────

    /// List pending approvals across all of the user's executions, joined
    /// with workflow name. Returns
    /// `(execution_id, node_id, required_for, requested_at, workflow_id, workflow_name)`
    /// — kept as a tuple so the caller's existing `iter().map()` shape works
    /// with minimal change.
    pub async fn list_pending_approvals_for_user(
        &self,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<PendingApprovalRow>> {
        let rows: Vec<(
            Uuid,
            Uuid,
            Vec<String>,
            Option<DateTime<Utc>>,
            Option<Uuid>,
            Option<String>,
        )> = sqlx::query_as(
            r#"
            SELECT a.execution_id, a.node_id, a.required_for, a.requested_at,
                   we.workflow_id, w.name
            FROM execution_approvals a
            LEFT JOIN workflow_executions we ON we.id = a.execution_id AND we.user_id = $1
            LEFT JOIN workflows w ON w.id = we.workflow_id
            WHERE a.status = 'pending' AND we.user_id = $1
            ORDER BY a.requested_at ASC
            LIMIT $2
            "#,
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(
                |(exec_id, node_id, required_for, requested_at, workflow_id, workflow_name)| {
                    PendingApprovalRow {
                        execution_id: exec_id,
                        node_id,
                        required_for,
                        requested_at,
                        workflow_id,
                        workflow_name,
                    }
                },
            )
            .collect())
    }

    /// Fetch the `user_id` (owner) of a workflow_execution row. Returns
    /// `Ok(None)` when the row doesn't exist. Used by `submit_workflow_approval`
    /// for ownership-check before allowing a decision write.
    pub async fn get_workflow_execution_owner(&self, execution_id: Uuid) -> Result<Option<Uuid>> {
        let row: Option<(Uuid,)> =
            sqlx::query_as("SELECT user_id FROM workflow_executions WHERE id = $1")
                .bind(execution_id)
                .fetch_optional(&self.db_pool)
                .await?;
        Ok(row.map(|(u,)| u))
    }

    /// Update a pending execution_approvals row with a decision (approved/denied
    /// + reason + decided_by). Returns rows affected (0 = no pending approval).
    pub async fn update_execution_approval_decision(
        &self,
        execution_id: Uuid,
        decision_status: &str,
        decided_by: Uuid,
        reason: Option<&str>,
    ) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE execution_approvals \
             SET status = $1, decided_at = NOW(), decided_by = $2, reason = $3 \
             WHERE execution_id = $4 AND status = 'pending'",
        )
        .bind(decision_status)
        .bind(decided_by)
        .bind(reason)
        .bind(execution_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Decide an `execution_approvals` row BY APPROVAL ID (contrast the
    /// sibling `update_execution_approval_decision`, keyed on execution_id)
    /// with an ownership JOIN on the owning workflow. Takes the caller's
    /// transaction rather than the repo pool: the GraphQL approve/deny
    /// mutations run this on a `begin_user_scoped` tx so the workflows RLS
    /// policy backstops the `w.user_id = $1` gate (RFC 0005 S3 —
    /// execution_approvals has no policy itself). Do NOT route this through
    /// `self.db_pool`; that would silently drop the RLS backstop.
    /// Returns rows affected (0 = not found or not owned).
    pub async fn decide_execution_approval_scoped(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        approval_id: Uuid,
        user_id: Uuid,
        decision_status: &str,
        reason: Option<&str>,
    ) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE execution_approvals \
             SET status = $1, decided_at = NOW(), decided_by = $2, reason = $3 \
             FROM workflows w \
             WHERE execution_approvals.id = $4 \
               AND w.id = execution_approvals.workflow_id AND w.user_id = $2",
        )
        .bind(decision_status)
        .bind(user_id)
        .bind(reason)
        .bind(approval_id)
        .execute(&mut **tx)
        .await?;
        Ok(result.rows_affected())
    }

    /// Workflow dead-letter-queue entries for a user, newest first. Takes
    /// the caller's transaction: the GraphQL `dead_letter_queue` query runs
    /// this on a `begin_user_scoped` tx so the workflows RLS policy
    /// backstops the ownership JOIN (RFC 0005 S3 — dead_letter_queue has no
    /// policy of its own). Do NOT route this through `self.db_pool`; that
    /// would silently drop the RLS backstop.
    pub async fn list_dead_letter_queue_scoped(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<DeadLetterQueueRow>> {
        let rows = sqlx::query_as::<_, DeadLetterQueueRow>(
            "SELECT d.id, d.workflow_id, d.execution_id, d.node_id, d.error_message, \
                    d.payload::text AS payload, d.created_at, d.replayed_at, d.replayed_by \
             FROM dead_letter_queue d \
             JOIN workflows w ON w.id = d.workflow_id \
             WHERE w.user_id = $1 \
             ORDER BY d.created_at DESC \
             LIMIT $2",
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&mut **tx)
        .await?;
        Ok(rows)
    }

    /// Latest `node_input` event for a (execution_id, node_id) pair.
    /// Returns the raw `log_message` text, which the handler parses as JSON
    /// or surfaces as a plain string.
    pub async fn get_latest_node_input_event(
        &self,
        execution_id: Uuid,
        node_id: Uuid,
    ) -> Result<Option<String>> {
        let msg: Option<Option<String>> = sqlx::query_scalar(
            "SELECT log_message FROM execution_events \
             WHERE execution_id = $1 AND node_id = $2 AND event_type = 'node_input' \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(execution_id)
        .bind(node_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(msg.flatten())
    }
}

/// Workflow DLQ row returned by `list_dead_letter_queue_scoped`.
/// `payload` arrives pre-cast to text (JSONB column).
#[derive(Debug, sqlx::FromRow)]
pub struct DeadLetterQueueRow {
    pub id: Uuid,
    pub workflow_id: Uuid,
    pub execution_id: Uuid,
    pub node_id: Uuid,
    pub error_message: String,
    pub payload: Option<String>,
    pub created_at: DateTime<Utc>,
    pub replayed_at: Option<DateTime<Utc>>,
    pub replayed_by: Option<Uuid>,
}

/// Row returned by `list_recent_module_executions_for_user`.
#[derive(Debug)]
pub struct ModuleExecutionResourceRow {
    pub id: Uuid,
    pub module_id: Uuid,
    pub status: String,
    pub error_message: Option<String>,
}

/// Log line returned by `list_module_execution_logs`.
#[derive(Debug)]
pub struct ModuleExecutionLogRow {
    pub level: String,
    pub message: String,
    pub created_at: DateTime<Utc>,
}

/// Detail row returned by `get_module_execution_for_user`.
#[derive(Debug)]
pub struct ModuleExecutionDetailRow {
    pub id: Uuid,
    pub module_id: Uuid,
    pub status: String,
    pub error_message: Option<String>,
    pub output_data: Option<serde_json::Value>,
}

/// Pending-approval row returned by `list_pending_approvals_for_user`.
#[derive(Debug)]
pub struct PendingApprovalRow {
    pub execution_id: Uuid,
    pub node_id: Uuid,
    pub required_for: Vec<String>,
    pub requested_at: Option<DateTime<Utc>>,
    pub workflow_id: Option<Uuid>,
    pub workflow_name: Option<String>,
}

/// Row returned by `list_stuck_executions_for_resume`.
///
/// Carries everything the resume-after-restart path needs to
/// reconstruct an engine identical (in identity + tier ceiling) to
/// the one that was running before the controller restarted.
#[derive(Debug, sqlx::FromRow)]
pub struct StuckExecutionForResume {
    pub id: Uuid,
    pub workflow_id: Uuid,
    pub user_id: Uuid,
    pub checkpoint_data: Option<serde_json::Value>,
    /// The actor that originally triggered this execution (NULL = anonymous).
    pub actor_id: Option<Uuid>,
    /// The ownership epoch AFTER this claim's `epoch + 1` bump. The resumer
    /// heartbeats against this value; if the DB epoch later moves past it
    /// (another claim/reclaim), the resumer has been superseded and aborts.
    pub epoch: i64,
    /// The workflow's bound default actor — fallback when `actor_id` is
    /// NULL (LEFT-JOINed; NULL if the workflow row was deleted between
    /// trigger and resume).
    pub workflow_default_actor_id: Option<Uuid>,
    /// The workflow definition. NULL only if the workflow row was deleted
    /// between trigger and resume — caller treats NULL as a hard skip.
    pub graph_json: Option<String>,
}
