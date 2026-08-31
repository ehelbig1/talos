use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use sqlx::PgPool;
use uuid::Uuid;

#[cfg(test)]
#[path = "module_executions_tests.rs"]
mod tests;

/// What actually happened to a log line handed to
/// [`ModuleExecutionService::add_log`].
///
/// WHY this exists (2026-07-30): `add_log` used to return `Result<()>` and
/// matched the INSERT's `Ok(_)` while IGNORING `rows_affected`. Its INSERT is
/// `... SELECT $1,$2,$3,$4 WHERE EXISTS (SELECT 1 FROM module_executions
/// WHERE id = $1)`, so a line addressed to an id with no `module_executions`
/// row affects ZERO rows and returns `Ok`. Caller and operator alike saw
/// success. Every iteration of every Loop node was losing its logs that way
/// for months, and nothing in the system said so — the one signal that could
/// have reported it (a `trace!` on the FK-violation `Err` arm) was made
/// unreachable by the very `WHERE EXISTS` guard that stopped the FK errors.
///
/// A `bool` would collapse the two DIFFERENT ways a line fails to land:
/// "there is no such execution" (a routing/attribution bug — someone's logs
/// are being discarded) and "this execution hit its log cap" (working as
/// designed). Calling the second one "orphaned" in an operator warning would
/// reproduce the misleading-report-field class this type exists to close.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogWriteOutcome {
    /// A row was inserted into `module_execution_logs`.
    Inserted,
    /// No `module_executions` row matched the id — the `WHERE EXISTS` guard
    /// selected nothing and the line was **discarded**. The line is gone;
    /// nothing else in the system records it.
    NoExecutionRow,
    /// The per-execution log-cap trigger rejected the insert. Deliberate
    /// back-pressure, not a routing bug.
    RateLimited,
    /// The write itself failed (DB outage, etc.). Only produced by
    /// [`ModuleExecutionService::add_log_best_effort`], which swallows the
    /// error after logging it; `add_log` propagates it instead.
    WriteFailed,
}

impl LogWriteOutcome {
    /// Did the line actually land in `module_execution_logs`?
    pub fn is_inserted(self) -> bool {
        matches!(self, Self::Inserted)
    }

    /// Was the line dropped because no execution row owns it?
    ///
    /// This is the ONLY variant that means "someone's logs are being
    /// silently thrown away" — the caller should say so loudly.
    pub fn is_orphaned(self) -> bool {
        matches!(self, Self::NoExecutionRow)
    }
}

/// Module execution status
#[derive(Debug, Clone, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "text")]
pub enum ExecutionStatus {
    #[sqlx(rename = "pending")]
    Pending,
    #[sqlx(rename = "running")]
    Running,
    #[sqlx(rename = "completed")]
    Completed,
    #[sqlx(rename = "failed")]
    Failed,
    #[sqlx(rename = "timeout")]
    Timeout,
    /// Set by the sibling-cancellation path (migration 20260327000003 added
    /// it to the DB CHECK in March 2026; this variant lagged 3.5 months —
    /// every history read over a module with a cancelled execution failed
    /// with a decode error until 2026-07-14).
    #[sqlx(rename = "cancelled")]
    Cancelled,
}

impl ExecutionStatus {
    /// The canonical status set — MUST match the module_executions status
    /// CHECK constraint (migrations/20260327000003). The drift test below
    /// fails if a DB-legal value can't decode through this enum; when the
    /// CHECK gains a value, add it here AND to this list in the same PR.
    pub const ALL: &'static [(&'static str, ExecutionStatus)] = &[
        ("pending", ExecutionStatus::Pending),
        ("running", ExecutionStatus::Running),
        ("completed", ExecutionStatus::Completed),
        ("failed", ExecutionStatus::Failed),
        ("timeout", ExecutionStatus::Timeout),
        ("cancelled", ExecutionStatus::Cancelled),
    ];
}

impl std::fmt::Display for ExecutionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Running => write!(f, "running"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
            Self::Timeout => write!(f, "timeout"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

/// Trigger type for module execution
#[derive(Debug, Clone, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "text")]
pub enum TriggerType {
    #[sqlx(rename = "webhook")]
    Webhook,
    #[sqlx(rename = "manual")]
    Manual,
    #[sqlx(rename = "scheduled")]
    Scheduled,
    #[sqlx(rename = "test")]
    Test,
}

impl std::fmt::Display for TriggerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Webhook => write!(f, "webhook"),
            Self::Manual => write!(f, "manual"),
            Self::Scheduled => write!(f, "scheduled"),
            Self::Test => write!(f, "test"),
        }
    }
}

/// Log level for execution logs
#[derive(Debug, Clone, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "text")]
pub enum LogLevel {
    #[sqlx(rename = "DEBUG")]
    Debug,
    #[sqlx(rename = "INFO")]
    Info,
    #[sqlx(rename = "WARN")]
    Warn,
    #[sqlx(rename = "ERROR")]
    Error,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Debug => write!(f, "DEBUG"),
            Self::Info => write!(f, "INFO"),
            Self::Warn => write!(f, "WARN"),
            Self::Error => write!(f, "ERROR"),
        }
    }
}

/// Module execution record
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ModuleExecution {
    pub id: Uuid,
    pub module_id: Uuid,
    pub user_id: Uuid,
    pub status: ExecutionStatus,
    pub trigger_type: TriggerType,
    pub trigger_metadata: Option<JsonValue>,
    pub input_data: Option<JsonValue>,
    pub output_data: Option<JsonValue>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub duration_ms: Option<i32>,
    pub error_message: Option<String>,
    pub error_type: Option<String>,
    pub fuel_consumed: Option<i64>,
    pub memory_used_mb: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// When the payload-retention sweep cleared this row's AEAD payloads.
    ///
    /// `None` means this row was NEVER pruned — so a `None` `input_data` /
    /// `output_data` on it means the payload was never written, not that it
    /// was taken away. That distinction is the whole reason the column
    /// exists: 22,370 of 36,065 live rows have never had an output (the
    /// ledger-finalizer outage relabelled by migration `20260812120000`), and
    /// without a tombstone a pruned row and one of those is indistinguishable.
    pub payload_pruned_at: Option<DateTime<Utc>>,
    /// `octet_length(input_data_enc)` at prune time. `None` when never pruned
    /// OR when the slot was empty at prune time.
    pub pruned_input_bytes: Option<i32>,
    /// `octet_length(output_data_enc)` at prune time. `None` when never pruned
    /// OR when the slot was empty — the common case, since no `timeout` row
    /// ever carried an output.
    pub pruned_output_bytes: Option<i32>,
}

/// Outcome of [`ModuleExecutionService::prune_terminal_payloads`].
///
/// Counts and byte totals only. No execution id, module name, tenant
/// identifier or payload content — the caller logs this verbatim.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PayloadRetentionStats {
    /// Rows whose payloads were cleared.
    pub pruned_rows: u64,
    /// Sum of `octet_length(input_data_enc)` over the pruned rows.
    pub input_bytes_freed: i64,
    /// Sum of `octet_length(output_data_enc)` over the pruned rows.
    pub output_bytes_freed: i64,
    /// Batches executed. A sweep that stops on the batch cap rather than on
    /// an empty batch will resume from where it left off on the next tick.
    pub batches: u32,
}

/// Outcome of [`ModuleExecutionService::delete_expired_executions`].
///
/// Counts only. No execution id, module name, tenant identifier or payload
/// content — the caller logs this verbatim.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RowRetentionStats {
    /// Rows DELETEd. Each also removed its `module_execution_logs` children by
    /// cascade, which this count does NOT include.
    pub deleted_rows: u64,
    /// Batches executed. A sweep that stops on the batch cap rather than on a
    /// short batch resumes where it left off on the next tick.
    pub batches: u32,
    /// Rows old enough to delete that were SKIPPED because their parent
    /// `workflow_executions` row still exists.
    ///
    /// This field is what makes `deleted_rows == 0` interpretable. Zero
    /// deletions with `Some(0)` means nothing was old enough; zero deletions
    /// with `Some(n)` for large `n` means the age floor IS being reached but
    /// parents are outliving it — a working sweep, not a broken predicate.
    ///
    /// **`Option`, not a bare `i64` defaulting to 0.** The probe is
    /// best-effort — a failed count must not abort the sweep it only annotates
    /// — but reporting `0` on failure would make "measured, nothing was
    /// skipped" and "the probe errored, nothing was ever measured" the same
    /// number, in the one field whose entire job is to disambiguate a zero.
    /// `None` means unmeasured, and the sweep WARNs when it happens.
    pub retained_parent_alive: Option<i64>,
}

/// Module execution log entry
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ModuleExecutionLog {
    pub id: Uuid,
    pub execution_id: Uuid,
    pub level: LogLevel,
    pub message: String,
    pub metadata: Option<JsonValue>,
    pub created_at: DateTime<Utc>,
}

/// Outcome of [`ModuleExecutionService::re_encrypt_module_payloads_to_org`].
#[derive(Debug, Clone, Default)]
pub struct ModulePayloadReEncryptStats {
    pub re_encrypted: u64,
    pub failed: u64,
}

/// Service for managing module executions
pub struct ModuleExecutionService {
    db_pool: PgPool,
    dlp: std::sync::Arc<talos_dlp_provider::DlpService>,
    /// Optional SecretsManager — when set, payload columns
    /// (input_data, output_data, trigger_metadata) are encrypted at
    /// rest using the active KEK provider. None in tests + legacy
    /// construction sites where wiring is deferred.
    secrets_manager: Option<std::sync::Arc<talos_secrets_manager::SecretsManager>>,
}

impl ModuleExecutionService {
    /// Maximum log entries allowed per execution (prevents DoS)
    pub const MAX_LOGS_PER_EXECUTION: i64 = 1000;

    /// Maximum error message length (prevents DB bloat)
    pub const MAX_ERROR_MESSAGE_LENGTH: usize = 10_000;

    /// Maximum JSONB field size in bytes (prevents DB bloat)
    /// 1MB limit - reasonable for most use cases, prevents abuse
    pub const MAX_JSONB_SIZE_BYTES: usize = 1_048_576; // 1MB

    /// Maximum log message length in characters (prevents DB bloat)
    pub const MAX_LOG_MESSAGE_LENGTH: usize = 10_000;

    pub fn new(db_pool: PgPool, dlp: std::sync::Arc<talos_dlp_provider::DlpService>) -> Self {
        Self {
            db_pool,
            dlp,
            secrets_manager: None,
        }
    }

    /// Builder: attach SecretsManager so create/complete/fail paths
    /// encrypt payload columns at rest. Mirrors the
    /// `ExecutionRepository::with_encryption` pattern.
    #[must_use]
    pub fn with_encryption(
        mut self,
        sm: std::sync::Arc<talos_secrets_manager::SecretsManager>,
    ) -> Self {
        self.secrets_manager = Some(sm);
        self
    }

    /// Encrypt a payload bundle. Thin wrapper over the shared
    /// `module_payload_encryption::encrypt_payload_bundle` so all writer
    /// paths (this service, engine store, webhooks) produce identical
    /// wire format under the same DEK.
    ///
    /// MCP-S2: `module_execution_id` is bound as AAD across all three
    /// slots so an attacker with DB write capability can't swap one
    /// row's payload columns onto another row of the same key_id.
    async fn encrypt_payload_bundle(
        &self,
        module_execution_id: Uuid,
        workflow_execution_id: Option<Uuid>,
        input: Option<&JsonValue>,
        output: Option<&JsonValue>,
        trigger: Option<&JsonValue>,
    ) -> Result<(
        Option<Uuid>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        i16,
    )> {
        let bundle = talos_module_payload_encryption::encrypt_payload_bundle(
            self.secrets_manager.as_ref(),
            module_execution_id,
            workflow_execution_id,
            input,
            output,
            trigger,
        )
        .await?;
        Ok((
            bundle.key_id,
            bundle.input_enc,
            bundle.output_enc,
            bundle.trigger_enc,
            bundle.format_version,
        ))
    }

    /// Decrypt a payload column read from a row. Prefers ciphertext when
    /// SecretsManager is wired and `enc_bytes` is Some; falls back to
    /// the plaintext column for legacy rows.
    ///
    /// MCP-S2: `module_execution_id` + `format_version` together drive
    /// the AAD-binding dispatch. v0 rows route through empty-AAD;
    /// v1 rows require AAD = module_execution_id bytes.
    ///
    /// 2026-05-28 review (low): `slot` selects the per-column AAD so v2 rows
    /// are decrypted with their slot-bound AAD. The shared
    /// `talos_module_payload_encryption::decrypt_payload_slot` builds the AAD
    /// for both writer and reader — keeping the two in lockstep across the
    /// v1→v2 change. v0/v1 rows still decrypt (the helper returns row-id-only
    /// AAD below v2).
    async fn read_payload(
        &self,
        module_execution_id: Uuid,
        slot: talos_module_payload_encryption::PayloadSlot,
        plaintext: Option<JsonValue>,
        enc_bytes: Option<Vec<u8>>,
        key_id: Option<Uuid>,
        format_version: i16,
    ) -> Result<Option<JsonValue>> {
        if let (Some(sm), Some(bytes), Some(kid)) = (&self.secrets_manager, &enc_bytes, key_id) {
            let s = talos_module_payload_encryption::decrypt_payload_slot(
                sm,
                kid,
                bytes,
                module_execution_id,
                slot,
                format_version,
            )
            .await?;
            let v: JsonValue = serde_json::from_str(&s)?;
            return Ok(Some(v));
        }
        Ok(plaintext)
    }

    /// Per-org DEK arc: migrate EXISTING module-execution payloads to their
    /// workflow's org root DEK (format v4). Last of the per-org sweeps. The
    /// cutover only converts NEW writes; this brings stored rows over so the
    /// global DEK can retire for module payloads.
    ///
    /// Selects rows not already v4 with an encrypted payload whose workflow has
    /// an org, decrypts each present slot, then re-encrypts the whole bundle via
    /// `encrypt_payload_bundle` (passing `workflow_execution_id`, which resolves
    /// the workflow's org → v4). All three slots share one key + format, so the
    /// re-encrypt rewrites them together. Standalone / org-less rows are not
    /// selected (no org). Lost-write guard: the UPDATE only fires while the row
    /// is still on the (key, format) we read. No-op without a SecretsManager.
    pub async fn re_encrypt_module_payloads_to_org(&self) -> Result<ModulePayloadReEncryptStats> {
        use sqlx::Row;
        use talos_module_payload_encryption::PayloadSlot;
        let Some(sm) = self.secrets_manager.clone() else {
            return Ok(ModulePayloadReEncryptStats::default());
        };
        const V4: i16 = talos_secrets_manager::SecretsManager::AAD_FORMAT_V4_ORG_DERIVED;

        let rows = sqlx::query(
            "SELECT me.id, me.workflow_execution_id, me.payload_enc_key_id, me.payload_format, \
                    me.input_data_enc, me.output_data_enc, me.trigger_metadata_enc \
             FROM module_executions me \
             JOIN workflow_executions we ON we.id = me.workflow_execution_id \
             JOIN workflows w ON w.id = we.workflow_id \
             WHERE me.payload_format <> $1 AND w.org_id IS NOT NULL \
               AND (me.input_data_enc IS NOT NULL OR me.output_data_enc IS NOT NULL \
                    OR me.trigger_metadata_enc IS NOT NULL)",
        )
        .bind(V4)
        .fetch_all(&self.db_pool)
        .await
        .context("re_encrypt_module_payloads_to_org: select stale rows")?;

        let mut re_encrypted = 0u64;
        let mut failed = 0u64;
        for r in &rows {
            let id: Uuid = r.try_get("id")?;
            let wei: Option<Uuid> = r.try_get::<Option<_>, _>("workflow_execution_id")?;
            let key_id: Option<Uuid> = r.try_get::<Option<_>, _>("payload_enc_key_id")?;
            let old_format: i16 = r.try_get("payload_format")?;
            let input_enc: Option<Vec<u8>> = r.try_get::<Option<_>, _>("input_data_enc")?;
            let output_enc: Option<Vec<u8>> = r.try_get::<Option<_>, _>("output_data_enc")?;
            let trigger_enc: Option<Vec<u8>> = r.try_get::<Option<_>, _>("trigger_metadata_enc")?;

            let res: Result<bool> = async {
                // Decrypt each present slot under its current key/format.
                let input = self
                    .read_payload(id, PayloadSlot::Input, None, input_enc, key_id, old_format)
                    .await?;
                let output = self
                    .read_payload(
                        id,
                        PayloadSlot::Output,
                        None,
                        output_enc,
                        key_id,
                        old_format,
                    )
                    .await?;
                let trigger = self
                    .read_payload(
                        id,
                        PayloadSlot::Trigger,
                        None,
                        trigger_enc,
                        key_id,
                        old_format,
                    )
                    .await?;

                // Re-encrypt the whole bundle under the workflow's org DEK (v4).
                let bundle = talos_module_payload_encryption::encrypt_payload_bundle(
                    Some(&sm),
                    id,
                    wei,
                    input.as_ref(),
                    output.as_ref(),
                    trigger.as_ref(),
                )
                .await?;

                // Lost-write guard: only update while still on (old_key, old_format).
                let result = sqlx::query(
                    "UPDATE module_executions \
                     SET input_data_enc = $1, output_data_enc = $2, trigger_metadata_enc = $3, \
                         payload_enc_key_id = $4, payload_format = $5 \
                     WHERE id = $6 AND payload_format = $7 \
                       AND payload_enc_key_id IS NOT DISTINCT FROM $8",
                )
                .bind(bundle.input_enc.as_deref())
                .bind(bundle.output_enc.as_deref())
                .bind(bundle.trigger_enc.as_deref())
                .bind(bundle.key_id)
                .bind(bundle.format_version)
                .bind(id)
                .bind(old_format)
                .bind(key_id)
                .execute(&self.db_pool)
                .await?;
                Ok(result.rows_affected() > 0)
            }
            .await;

            match res {
                Ok(true) => re_encrypted += 1,
                Ok(false) => {
                    tracing::debug!(module_execution_id = %id, "module-payload sweep: row concurrently re-keyed; skipped");
                }
                Err(e) => {
                    tracing::error!(module_execution_id = %id, "module-payload sweep: {e}");
                    failed += 1;
                }
            }
        }

        tracing::info!(
            re_encrypted,
            failed,
            "Per-org module-payload re-encryption sweep complete"
        );
        Ok(ModulePayloadReEncryptStats {
            re_encrypted,
            failed,
        })
    }

    /// Validate JSONB field size to prevent database bloat
    /// Returns error if serialized JSON exceeds MAX_JSONB_SIZE_BYTES
    fn validate_jsonb_size(value: &Option<JsonValue>, field_name: &str) -> Result<()> {
        if let Some(json) = value {
            let serialized = serde_json::to_string(json)
                .context("Failed to serialize JSON for size validation")?;

            let watermark = (Self::MAX_JSONB_SIZE_BYTES as f64 * 0.8) as usize;
            if serialized.len() >= watermark {
                tracing::warn!(
                    "WATERMARK WARNING: {} is {} bytes, approaching {} byte limit",
                    field_name,
                    serialized.len(),
                    Self::MAX_JSONB_SIZE_BYTES
                );
            }
            if serialized.len() > Self::MAX_JSONB_SIZE_BYTES {
                tracing::error!(
                    "Data size limit exceeded for {}: {} bytes > {} bytes",
                    field_name,
                    serialized.len(),
                    Self::MAX_JSONB_SIZE_BYTES
                );
                anyhow::bail!("Data size limit exceeded. Please reduce the size of the payload.");
            }
        }
        Ok(())
    }

    /// Helper to sanitize error messages (strip control chars and truncate to prevent DB bloat)
    /// - Removes control characters (0x00-0x1F, 0x7F-0x9F) except tab, newline, carriage return
    /// - Truncates by characters (not bytes) to avoid UTF-8 boundary panics
    /// - Limits to 10,000 characters to prevent database bloat
    fn sanitize_error_message(message: String) -> String {
        const MAX_CHARS: usize = 10_000;

        // First, strip control characters (prevents log injection, ANSI escape codes, null bytes)
        let cleaned: String = message
            .chars()
            .filter(|c| {
                let code = *c as u32;
                // Keep printable ASCII, tabs, newlines, carriage returns, and all non-ASCII
                matches!(code, 0x20..=0x7E | 0x09 | 0x0A | 0x0D) || code >= 0x80
            })
            .collect();

        let char_count = cleaned.chars().count();

        if char_count <= MAX_CHARS {
            return cleaned;
        }

        // Safely truncate at character boundary
        let truncated: String = cleaned.chars().take(MAX_CHARS).collect();
        let remaining_chars = char_count - MAX_CHARS;

        format!(
            "{}... (truncated {} more characters)",
            truncated, remaining_chars
        )
    }

    /// Create a new module execution record
    /// This should be called when starting execution (non-blocking)
    /// Validates JSONB field sizes to prevent database bloat
    ///
    /// Accepts an optional pre-generated `execution_id` (pass `Uuid::new_v4()` to
    /// auto-generate), plus an optional `workflow_execution_id` to link this
    /// module execution to a parent workflow run.
    pub async fn create_execution(
        &self,
        module_id: Uuid,
        user_id: Uuid,
        execution_id: Uuid,
        trigger_type: TriggerType,
        trigger_metadata: Option<JsonValue>,
        input_data: Option<JsonValue>,
        workflow_execution_id: Option<Uuid>,
        actor_id: Option<Uuid>,
    ) -> Result<Uuid> {
        // MCP-1163 (2026-05-17): validate size BEFORE redact_json.
        // Pre-fix the redact pass ran on the FULL input_data even
        // when oversized — `validate_jsonb_size` would then `bail!`
        // and the whole call returned Err, so the regex pass on the
        // to-be-rejected value was pure waste. A malicious or buggy
        // caller spamming 10 MB input_data burned multi-MB ×
        // pattern_count regex work per `create_execution` attempt
        // before the size gate triggered. Sibling sweep to MCP-1162
        // which closed the same inverted ordering on
        // `add_workflow_log.metadata`. Run size-check first against
        // the ORIGINAL value; redact only when under cap.
        Self::validate_jsonb_size(&input_data, "input_data")?;
        Self::validate_jsonb_size(&trigger_metadata, "trigger_metadata")?;

        // Redact PII from input_data before persisting (defense in depth —
        // even encrypted columns benefit from DLP scrubbing in case the
        // KEK is ever compromised).
        let input_data = input_data.as_ref().map(|v| self.dlp.redact_json(v));

        // Phase A encryption: when SecretsManager is wired, encrypt input
        // and trigger payloads at rest. The plaintext columns are written
        // as NULL, the *_enc columns hold the ciphertext, and the
        // partial-index `idx_module_executions_needs_payload_encryption`
        // does NOT match (so backfill skips this row).
        //
        // MCP-S2: AAD = execution_id binds each ciphertext to its row.
        let (key_id, input_enc, _output_enc, trigger_enc, payload_format) = self
            .encrypt_payload_bundle(
                execution_id,
                workflow_execution_id,
                input_data.as_ref(),
                None,
                trigger_metadata.as_ref(),
            )
            .await?;
        let encrypting = key_id.is_some();

        sqlx::query(
            r#"
            INSERT INTO module_executions (
                id, module_id, user_id, status, trigger_type,
                trigger_metadata, input_data,
                trigger_metadata_enc, input_data_enc, payload_enc_key_id,
                payload_format,
                workflow_execution_id, actor_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            "#,
        )
        .bind(execution_id)
        .bind(module_id)
        .bind(user_id)
        .bind(ExecutionStatus::Pending.to_string())
        .bind(trigger_type.to_string())
        // Plaintext columns: NULL when encryption is on, value otherwise.
        .bind(if encrypting {
            None
        } else {
            trigger_metadata.as_ref()
        })
        .bind(if encrypting {
            None
        } else {
            input_data.as_ref()
        })
        .bind(trigger_enc.as_deref())
        .bind(input_enc.as_deref())
        .bind(key_id)
        .bind(payload_format)
        .bind(workflow_execution_id)
        .bind(actor_id)
        .execute(&self.db_pool)
        .await
        .context("Failed to create module execution")?;

        tracing::debug!(
            "Created module execution {} for module {}",
            execution_id,
            module_id
        );

        Ok(execution_id)
    }

    /// Update execution status to running
    /// Verifies user_id ownership to prevent unauthorized modifications
    pub async fn mark_running(&self, execution_id: Uuid, user_id: Uuid) -> Result<()> {
        let result = sqlx::query!(
            r#"
            UPDATE module_executions
            SET status = $1, started_at = NOW()
            WHERE id = $2 AND user_id = $3
            "#,
            ExecutionStatus::Running.to_string(),
            execution_id,
            user_id
        )
        .execute(&self.db_pool)
        .await
        .context("Failed to mark execution as running")?;

        // Verify the update happened (user owns the execution)
        if result.rows_affected() == 0 {
            anyhow::bail!("Execution not found or access denied");
        }

        Ok(())
    }

    /// Complete an execution successfully with output
    /// Verifies user_id ownership to prevent unauthorized modifications
    /// Validates output_data size to prevent database bloat
    pub async fn complete_execution(
        &self,
        execution_id: Uuid,
        user_id: Uuid,
        output_data: Option<JsonValue>,
        fuel_consumed: Option<i64>,
        memory_used_mb: Option<i32>,
    ) -> Result<()> {
        // MCP-1163 (2026-05-17): validate size BEFORE redact_json
        // (sibling to the create_execution fix above and to
        // MCP-1162's add_workflow_log fix). The oversized payload
        // is rejected either way; pre-fix the regex pass ran first
        // and the work was discarded at the size gate.
        Self::validate_jsonb_size(&output_data, "output_data")?;
        // DLP: redact PII from output before storage (defense in depth)
        let output_data = output_data.map(|v| talos_dlp_provider::redact_json(&v));

        // Phase A encryption: encrypt output payload at rest. The
        // existing payload_enc_key_id from create_execution stays valid
        // (same DEK), so a successful encrypt here just stores another
        // ciphertext under the same key.
        //
        // MCP-S2: AAD = execution_id, matching the row that
        // create_execution populated. Per-org DEK arc: pass
        // workflow_execution_id = None so encrypt_payload_bundle resolves the
        // SAME org from the existing row (create_execution already created it),
        // keeping the shared payload_enc_key_id consistent.
        let (key_id, _input_enc, output_enc, _trigger_enc, payload_format) = self
            .encrypt_payload_bundle(execution_id, None, None, output_data.as_ref(), None)
            .await?;
        let encrypting = key_id.is_some();

        // MCP-S2: use dynamic `sqlx::query` (not `query!` macro) since
        // the new `payload_format` column isn't in the offline cache
        // yet. Same approach as the TOTP migration's `query_as` site.
        let pt_output = if encrypting {
            None
        } else {
            output_data.as_ref()
        };
        // MCP-S2 follow-up: only update `payload_format` when we wrote
        // a new ciphertext on this UPDATE. The empty-bundle short-
        // circuit in `encrypt_payload_bundle` returns `format_version
        // = 0` for the no-output case, which would otherwise overwrite
        // the row's v1 stamp from `create_execution` and break
        // subsequent reads of input_data_enc / trigger_metadata_enc on
        // the SAME row. Preserve the prior format unless we're
        // actually writing new ciphertext.
        let format_arg: Option<i16> = if encrypting {
            Some(payload_format)
        } else {
            None
        };
        let result = sqlx::query(
            r#"
            UPDATE module_executions
            SET
                status = $1,
                completed_at = NOW(),
                output_data = $2,
                output_data_enc = $3,
                payload_enc_key_id = COALESCE(payload_enc_key_id, $4),
                payload_format = COALESCE($5, payload_format),
                fuel_consumed = $6,
                memory_used_mb = $7
            WHERE id = $8 AND user_id = $9
            "#,
        )
        .bind(ExecutionStatus::Completed.to_string())
        .bind(pt_output)
        .bind(output_enc.as_deref())
        .bind(key_id)
        .bind(format_arg)
        .bind(fuel_consumed)
        .bind(memory_used_mb)
        .bind(execution_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await
        .context("Failed to complete execution")?;

        // Verify the update happened (user owns the execution)
        if result.rows_affected() == 0 {
            anyhow::bail!("Execution not found or access denied");
        }

        tracing::debug!("Completed module execution {}", execution_id);

        Ok(())
    }

    /// Fail an execution with error details
    /// Verifies user_id ownership to prevent unauthorized modifications
    pub async fn fail_execution(
        &self,
        execution_id: Uuid,
        user_id: Uuid,
        error_message: String,
        error_type: Option<String>,
    ) -> Result<()> {
        // MCP-1163 (2026-05-17): sanitize+truncate BEFORE DLP redact.
        // Pre-fix `redact_str` ran on the FULL unbounded
        // `error_message: String` — the regex pass walked the entire
        // multi-MB error (caller-supplied, no upstream cap) only to
        // have `sanitize_error_message` truncate to 10K chars
        // immediately after. `redact_str` is O(N × pattern_count); on
        // a multi-MB error string that's enormous wasted work that
        // ends up discarded. Sibling sweep to MCP-1160 (response_body
        // + error_message on webhook_request_log) and MCP-1161
        // (mark_execution_failed.error on workflow_executions) — same
        // truncate-then-redact discipline. `sanitize_error_message`
        // strips control chars AND truncates to 10K chars, so running
        // it first bounds the redact pass to 10K too.
        let sanitized_message = Self::sanitize_error_message(error_message);
        // DLP: redact PII from the sanitized + bounded error message.
        let sanitized_message = talos_dlp_provider::redact_str(&sanitized_message);

        let result = sqlx::query!(
            r#"
            UPDATE module_executions
            SET
                status = $1,
                completed_at = NOW(),
                error_message = $2,
                error_type = $3
            WHERE id = $4 AND user_id = $5
            "#,
            ExecutionStatus::Failed.to_string(),
            sanitized_message,
            error_type,
            execution_id,
            user_id
        )
        .execute(&self.db_pool)
        .await
        .context("Failed to mark execution as failed")?;

        // Verify the update happened (user owns the execution)
        if result.rows_affected() == 0 {
            anyhow::bail!("Execution not found or access denied");
        }

        tracing::debug!(
            "Failed module execution {}: {}",
            execution_id,
            sanitized_message
        );

        Ok(())
    }

    /// Mark execution as timed out
    /// Verifies user_id ownership to prevent unauthorized modifications
    pub async fn timeout_execution(&self, execution_id: Uuid, user_id: Uuid) -> Result<()> {
        let result = sqlx::query!(
            r#"
            UPDATE module_executions
            SET
                status = $1,
                completed_at = NOW(),
                error_type = 'timeout'
            WHERE id = $2 AND user_id = $3
            "#,
            ExecutionStatus::Timeout.to_string(),
            execution_id,
            user_id
        )
        .execute(&self.db_pool)
        .await
        .context("Failed to mark execution as timeout")?;

        // Verify the update happened (user owns the execution)
        if result.rows_affected() == 0 {
            anyhow::bail!("Execution not found or access denied");
        }

        Ok(())
    }

    /// Add a log entry to an execution
    /// - Sanitizes message (strips control chars, truncates to 10K chars)
    /// - Validates metadata size (max 1MB)
    /// - Rate limiting is enforced by database trigger (migration 013/015)
    ///
    /// Returns `Ok(outcome)` — including for a rate-limited or orphaned line,
    /// which are non-fatal by design (a log write must never fail an
    /// execution). **Callers must inspect the [`LogWriteOutcome`]**: `Ok` does
    /// NOT mean the line was stored. See that type for why a `bool` isn't
    /// enough and why the distinction is load-bearing.
    pub async fn add_log(
        &self,
        execution_id: Uuid,
        level: LogLevel,
        message: String,
        metadata: Option<JsonValue>,
    ) -> Result<LogWriteOutcome> {
        // Sanitize message (strip control chars, truncate if too long)
        let mut sanitized_message: String = message
            .chars()
            .take(Self::MAX_LOG_MESSAGE_LENGTH)
            .filter(|c| !c.is_control() || *c == '\n' || *c == '\t' || *c == '\r')
            .collect();
        if message.chars().count() > Self::MAX_LOG_MESSAGE_LENGTH {
            let remaining = message.chars().count() - Self::MAX_LOG_MESSAGE_LENGTH;
            sanitized_message = format!("{}... (truncated {} chars)", sanitized_message, remaining);
        }
        // MCP-481: DLP-scrub the WASM-supplied log message before
        // persisting to `module_execution_logs.message`. WASM modules
        // can `talos::core::logging::log` arbitrary strings — a
        // buggy or malicious module that printf-debugs a secret
        // (Bearer token, sk-*, ghp_*, OAuth refresh token resolved
        // via vault://) would otherwise land that secret raw in
        // long-lived log storage queryable via the
        // `tail_worker_logs` MCP tool / GraphQL log subscription.
        // Same persistence-boundary DLP rule the rest of the platform
        // follows (DLQ, failure alerts, output_data, etc.).
        let sanitized_message = talos_dlp_provider::redact_str(&sanitized_message);

        // Validate metadata size (prevent bloat/DoS)
        Self::validate_jsonb_size(&metadata, "log metadata")?;

        // MCP-561: DLP-scrub the metadata JSONB field too. MCP-481
        // covered `message` but `metadata` is the structured field a
        // WASM module emits alongside the message — typical shape is
        // `{"http_response_body": "...", "request_headers": {...}}`,
        // which routinely echoes Bearer tokens or sk-* keys from
        // upstream API errors. The same persistence-boundary rule
        // applies: this row is queryable via `tail_worker_logs` /
        // GraphQL log subscription, so an unscrubbed leak lives in
        // long-lived log storage and surfaces in operator dashboards.
        // Uses the depth-bounded `redact_json` (MCP-559) so a
        // pathologically nested metadata payload can't trigger the
        // stack-overflow class through this path either.
        let scrubbed_metadata = metadata.map(|v| talos_dlp_provider::redact_json(&v));

        // Database trigger handles rate limiting automatically
        // - Increments log_count atomically
        // - Raises exception if > 1000 logs
        // This is O(1) instead of O(N²) COUNT query!

        let result = sqlx::query!(
            r#"
            INSERT INTO module_execution_logs (execution_id, level, message, metadata)
            SELECT $1, $2, $3, $4
            WHERE EXISTS (SELECT 1 FROM module_executions WHERE id = $1)
            "#,
            execution_id,
            level.to_string(),
            sanitized_message,
            scrubbed_metadata
        )
        .execute(&self.db_pool)
        .await;

        // Handle rate limit exception gracefully
        match result {
            // `rows_affected() == 0` is the ONLY signal that the `WHERE
            // EXISTS` guard above selected nothing, i.e. the line was
            // addressed to an id with no `module_executions` row and has been
            // discarded. Swallowing it (the pre-2026-07-30 `Ok(_) => Ok(())`)
            // is what made the loop-body log drop invisible.
            Ok(r) if r.rows_affected() > 0 => Ok(LogWriteOutcome::Inserted),
            Ok(_) => Ok(LogWriteOutcome::NoExecutionRow),
            Err(e) => {
                let error_msg = e.to_string();

                // Check if this is a rate limit error from the trigger
                if error_msg.contains("exceeded maximum log entries")
                    || error_msg.contains("check_violation")
                {
                    tracing::warn!(
                        "Execution {} exceeded max log entries ({}), dropping log: {}",
                        execution_id,
                        Self::MAX_LOGS_PER_EXECUTION,
                        sanitized_message.chars().take(50).collect::<String>()
                    );
                    // Return Ok to not fail the execution - just drop the log
                    Ok(LogWriteOutcome::RateLimited)
                } else if error_msg.contains("violates foreign key constraint")
                    || error_msg.contains("is not present in table")
                {
                    // Belt-and-braces fallback, NOT the live path: the
                    // `WHERE EXISTS` guard on the INSERT means a missing
                    // parent row yields zero affected rows (handled above),
                    // never an FK violation. This arm survives only so that
                    // removing the guard degrades to the same OUTCOME value
                    // instead of an error. It deliberately emits no log line
                    // of its own — the previous `trace!` here claimed to
                    // report dropped logs while being unreachable, which is
                    // the same "absence reads as a negative result" class
                    // this whole change exists to close. The caller warns.
                    Ok(LogWriteOutcome::NoExecutionRow)
                } else {
                    // Real database error - propagate it
                    Err(e).context("Failed to add execution log")
                }
            }
        }
    }

    /// Get execution by ID (with authorization check).
    ///
    /// MCP-681 (2026-05-13): pre-fix the `sqlx::query_as!` projected
    /// only the plaintext `input_data` / `output_data` /
    /// `trigger_metadata` columns. With module-payload encryption
    /// enabled (Phase A — migration 20260424030501), the writer sets
    /// those three columns to NULL and stores ciphertext in
    /// `input_data_enc` / `output_data_enc` / `trigger_metadata_enc`
    /// (shared key in `payload_enc_key_id`). So this read returned
    /// `input_data: None` / `output_data: None` / `trigger_metadata:
    /// None` for every encrypted execution. Sibling fix-class to
    /// MCP-680 (workflow_executions output blindness).
    ///
    /// Switched to raw `sqlx::query` row-extraction so the 21-column
    /// projection fits (sqlx tuple FromRow caps at 16 columns), then
    /// decrypt via the repo's existing `read_payload` helper.
    pub async fn get_execution(
        &self,
        execution_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<ModuleExecution>> {
        use sqlx::Row as _;
        let row = sqlx::query(
            "SELECT
                id, module_id, user_id, status, trigger_type,
                trigger_metadata, input_data, output_data,
                trigger_metadata_enc, input_data_enc, output_data_enc, payload_enc_key_id,
                payload_format,
                started_at, completed_at, duration_ms,
                error_message, error_type,
                fuel_consumed, memory_used_mb,
                created_at, updated_at,
                payload_pruned_at, pruned_input_bytes, pruned_output_bytes
            FROM module_executions
            WHERE id = $1 AND user_id = $2",
        )
        .bind(execution_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("Failed to fetch execution")?;
        let Some(r) = row else {
            return Ok(None);
        };
        let pt_trigger: Option<JsonValue> = r.try_get::<Option<_>, _>("trigger_metadata")?;
        let pt_input: Option<JsonValue> = r.try_get::<Option<_>, _>("input_data")?;
        let pt_output: Option<JsonValue> = r.try_get::<Option<_>, _>("output_data")?;
        let enc_trigger: Option<Vec<u8>> = r.try_get::<Option<_>, _>("trigger_metadata_enc")?;
        let enc_input: Option<Vec<u8>> = r.try_get::<Option<_>, _>("input_data_enc")?;
        let enc_output: Option<Vec<u8>> = r.try_get::<Option<_>, _>("output_data_enc")?;
        let key_id: Option<Uuid> = r.try_get::<Option<_>, _>("payload_enc_key_id")?;
        // Fail loud: payload_format drives AEAD dispatch. Defaulting to v0 is
        // only safe when the row carries NO encrypted payload; with ciphertext
        // present a silent v0 dispatches the wrong AAD and fails decryption on a
        // v3/v4 row (MCP-S2 / lint-check-34 twin).
        let payload_format: i16 = match r.try_get("payload_format") {
            Ok(v) => v,
            Err(e) if enc_trigger.is_some() || enc_input.is_some() || enc_output.is_some() => {
                return Err(anyhow::anyhow!(
                    "payload_format unreadable for an encrypted module-execution row — cannot \
                     dispatch AEAD (caller must SELECT payload_format): {e}"
                ));
            }
            Err(_) => 0,
        };
        use talos_module_payload_encryption::PayloadSlot;
        let trigger_metadata = self
            .read_payload(
                execution_id,
                PayloadSlot::Trigger,
                pt_trigger,
                enc_trigger,
                key_id,
                payload_format,
            )
            .await?;
        let input_data = self
            .read_payload(
                execution_id,
                PayloadSlot::Input,
                pt_input,
                enc_input,
                key_id,
                payload_format,
            )
            .await?;
        let output_data = self
            .read_payload(
                execution_id,
                PayloadSlot::Output,
                pt_output,
                enc_output,
                key_id,
                payload_format,
            )
            .await?;
        Ok(Some(ModuleExecution {
            id: r.try_get("id")?,
            module_id: r.try_get("module_id")?,
            user_id: r.try_get("user_id")?,
            status: r.try_get("status")?,
            trigger_type: r.try_get("trigger_type")?,
            trigger_metadata,
            input_data,
            output_data,
            started_at: r.try_get("started_at")?,
            completed_at: r.try_get("completed_at")?,
            duration_ms: r.try_get("duration_ms")?,
            error_message: r.try_get("error_message")?,
            error_type: r.try_get("error_type")?,
            fuel_consumed: r.try_get("fuel_consumed")?,
            memory_used_mb: r.try_get("memory_used_mb")?,
            created_at: r.try_get("created_at")?,
            updated_at: r.try_get("updated_at")?,
            payload_pruned_at: r.try_get("payload_pruned_at")?,
            pruned_input_bytes: r.try_get("pruned_input_bytes")?,
            pruned_output_bytes: r.try_get("pruned_output_bytes")?,
        }))
    }

    /// Get recent executions for a module (with authorization).
    ///
    /// MCP-681: same encryption-aware projection as `get_execution`.
    /// Pre-fix returned `input_data: None` / `output_data: None` /
    /// `trigger_metadata: None` for every row on encryption-enabled
    /// deploys. Iterates row-by-row through `read_payload` for
    /// transparent decryption.
    pub async fn get_module_executions(
        &self,
        module_id: Uuid,
        user_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ModuleExecution>> {
        use sqlx::Row as _;
        let rows = sqlx::query(
            "SELECT
                id, module_id, user_id, status, trigger_type,
                trigger_metadata, input_data, output_data,
                trigger_metadata_enc, input_data_enc, output_data_enc, payload_enc_key_id,
                payload_format,
                started_at, completed_at, duration_ms,
                error_message, error_type,
                fuel_consumed, memory_used_mb,
                created_at, updated_at,
                payload_pruned_at, pruned_input_bytes, pruned_output_bytes
            FROM module_executions
            WHERE module_id = $1 AND user_id = $2
            ORDER BY started_at DESC, id DESC
            LIMIT $3 OFFSET $4",
        )
        .bind(module_id)
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db_pool)
        .await
        .context("Failed to fetch module executions")?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let exec_id: Uuid = r.try_get("id")?;
            let pt_trigger: Option<JsonValue> = r.try_get::<Option<_>, _>("trigger_metadata")?;
            let pt_input: Option<JsonValue> = r.try_get::<Option<_>, _>("input_data")?;
            let pt_output: Option<JsonValue> = r.try_get::<Option<_>, _>("output_data")?;
            let enc_trigger: Option<Vec<u8>> = r.try_get::<Option<_>, _>("trigger_metadata_enc")?;
            let enc_input: Option<Vec<u8>> = r.try_get::<Option<_>, _>("input_data_enc")?;
            let enc_output: Option<Vec<u8>> = r.try_get::<Option<_>, _>("output_data_enc")?;
            let key_id: Option<Uuid> = r.try_get::<Option<_>, _>("payload_enc_key_id")?;
            // Fail loud (same rule as the single-row path): payload_format is
            // load-bearing for AEAD dispatch when ciphertext is present.
            let payload_format: i16 = match r.try_get("payload_format") {
                Ok(v) => v,
                Err(e) if enc_trigger.is_some() || enc_input.is_some() || enc_output.is_some() => {
                    return Err(anyhow::anyhow!(
                        "payload_format unreadable for an encrypted module-execution row — cannot \
                         dispatch AEAD (caller must SELECT payload_format): {e}"
                    ));
                }
                Err(_) => 0,
            };
            use talos_module_payload_encryption::PayloadSlot;
            let trigger_metadata = self
                .read_payload(
                    exec_id,
                    PayloadSlot::Trigger,
                    pt_trigger,
                    enc_trigger,
                    key_id,
                    payload_format,
                )
                .await?;
            let input_data = self
                .read_payload(
                    exec_id,
                    PayloadSlot::Input,
                    pt_input,
                    enc_input,
                    key_id,
                    payload_format,
                )
                .await?;
            let output_data = self
                .read_payload(
                    exec_id,
                    PayloadSlot::Output,
                    pt_output,
                    enc_output,
                    key_id,
                    payload_format,
                )
                .await?;
            out.push(ModuleExecution {
                id: r.try_get("id")?,
                module_id: r.try_get("module_id")?,
                user_id: r.try_get("user_id")?,
                status: r.try_get("status")?,
                trigger_type: r.try_get("trigger_type")?,
                trigger_metadata,
                input_data,
                output_data,
                started_at: r.try_get("started_at")?,
                completed_at: r.try_get("completed_at")?,
                duration_ms: r.try_get("duration_ms")?,
                error_message: r.try_get("error_message")?,
                error_type: r.try_get("error_type")?,
                fuel_consumed: r.try_get("fuel_consumed")?,
                memory_used_mb: r.try_get("memory_used_mb")?,
                created_at: r.try_get("created_at")?,
                updated_at: r.try_get("updated_at")?,
                payload_pruned_at: r.try_get("payload_pruned_at")?,
                pruned_input_bytes: r.try_get("pruned_input_bytes")?,
                pruned_output_bytes: r.try_get("pruned_output_bytes")?,
            });
        }
        Ok(out)
    }

    /// Get logs for an execution (with authorization via execution ownership)
    pub async fn get_execution_logs(
        &self,
        execution_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<ModuleExecutionLog>> {
        // SECURITY: JOIN with module_executions to enforce user_id ownership in the query itself
        let records = sqlx::query_as!(
            ModuleExecutionLog,
            r#"
            SELECT
                logs.id, logs.execution_id,
                logs.level as "level: LogLevel",
                logs.message, logs.metadata, logs.created_at
            FROM module_execution_logs logs
            JOIN module_executions execs ON logs.execution_id = execs.id
            WHERE logs.execution_id = $1 AND execs.user_id = $2
            ORDER BY logs.created_at ASC
            "#,
            execution_id,
            user_id
        )
        .fetch_all(&self.db_pool)
        .await
        .context("Failed to fetch execution logs")?;

        Ok(records)
    }

    /// Batched per-execution log fetch for the GraphQL
    /// `ModuleExecutionLogLoader` DataLoader, capping rows PER execution_id
    /// via a ROW_NUMBER() window (MCP-1191 — an uncapped `= ANY($1)` fan-out
    /// let one request pull ~1M rows).
    ///
    /// SECURITY: deliberately NOT user-scoped — the DataLoader is only
    /// invoked from ComplexObject resolvers whose parent `ModuleExecution`
    /// rows were already fetched through user-scoped queries. Do not call
    /// from a surface that hasn't pre-scoped the execution ids.
    pub async fn get_execution_logs_batched(
        &self,
        execution_ids: &[Uuid],
        per_execution_cap: i32,
    ) -> Result<Vec<ModuleExecutionLog>> {
        let records = sqlx::query_as::<_, ModuleExecutionLog>(
            r#"
            SELECT id, execution_id, level, message, metadata, created_at
            FROM (
                SELECT id, execution_id, level, message, metadata, created_at,
                       ROW_NUMBER() OVER (
                           PARTITION BY execution_id ORDER BY created_at ASC
                       ) AS rn
                FROM module_execution_logs
                WHERE execution_id = ANY($1)
            ) numbered
            WHERE rn <= $2
            ORDER BY execution_id, created_at ASC
            "#,
        )
        .bind(execution_ids)
        .bind(per_execution_cap)
        .fetch_all(&self.db_pool)
        .await
        .context("Failed to batch-fetch execution logs")?;

        Ok(records)
    }

    // ==================== Best-Effort Helper Methods ====================
    // These methods log errors instead of propagating them, useful for
    // non-critical operations that shouldn't block execution

    /// Mark execution as running (best effort - logs error on failure)
    pub async fn mark_running_best_effort(&self, execution_id: Uuid, user_id: Uuid) {
        if let Err(e) = self.mark_running(execution_id, user_id).await {
            tracing::warn!(
                "Failed to mark execution {} as running: {}",
                execution_id,
                e
            );
        }
    }

    /// Add log entry (best effort - logs error on failure).
    ///
    /// Returns the [`LogWriteOutcome`] so a caller that can distinguish
    /// "stored" from "silently discarded" is able to say so. Callers with
    /// nothing useful to do with the answer may ignore it (it is not
    /// `#[must_use]`), but a caller that is the LAST routing hop for a log
    /// line — the WASM-log subscriber — must check
    /// [`LogWriteOutcome::is_orphaned`] and warn.
    pub async fn add_log_best_effort(
        &self,
        execution_id: Uuid,
        level: LogLevel,
        message: String,
        metadata: Option<JsonValue>,
    ) -> LogWriteOutcome {
        match self
            .add_log(execution_id, level, message.clone(), metadata)
            .await
        {
            Ok(outcome) => outcome,
            Err(e) => {
                // MCP-989 (2026-05-15): DLP-redact the message preview that
                // lands in the WARN log. `add_log` redacts before INSERT
                // (MCP-481), but this wrapper kept a copy of the ORIGINAL
                // unredacted `message` and previewed its first 50 chars when
                // the DB write failed. A WASM module emitting a log message
                // like "sk-ant-XXXXX rejected by API" would land the secret
                // prefix in operator logs — secret-shaped content needs the
                // same DLP discipline on the operator-log boundary as on
                // the persistence boundary (sibling class to MCP-852/853/
                // 854/921 — `info!`/`warn!` of WASM-supplied content).
                let preview: String = talos_dlp_provider::redact_str(&message)
                    .chars()
                    .take(50)
                    .collect();
                tracing::warn!(
                    "Failed to add log to execution {}: {} (message: {})",
                    execution_id,
                    e,
                    preview
                );
                LogWriteOutcome::WriteFailed
            }
        }
    }

    /// Complete execution (best effort - logs error on failure)
    pub async fn complete_execution_best_effort(
        &self,
        execution_id: Uuid,
        user_id: Uuid,
        output_data: Option<JsonValue>,
        fuel_consumed: Option<i64>,
        memory_used_mb: Option<i32>,
    ) {
        if let Err(e) = self
            .complete_execution(
                execution_id,
                user_id,
                output_data,
                fuel_consumed,
                memory_used_mb,
            )
            .await
        {
            tracing::warn!("Failed to complete execution {}: {}", execution_id, e);
        }
    }

    /// Fail execution (best effort - logs error on failure)
    pub async fn fail_execution_best_effort(
        &self,
        execution_id: Uuid,
        user_id: Uuid,
        error_message: String,
        error_type: Option<String>,
    ) {
        if let Err(e) = self
            .fail_execution(execution_id, user_id, error_message.clone(), error_type)
            .await
        {
            // MCP-989: DLP-redact the error preview before logging. The
            // canonical `fail_execution` redacts before INSERT (MCP-968);
            // this wrapper kept the un-redacted `error_message` to log
            // its first 50 chars on persist-failure. Worker-supplied
            // failure text routinely echoes upstream API auth detail
            // (HTTP 401 bodies often include the rejected Bearer token
            // in error_description); operator logs are not the right
            // place to surface raw secret content.
            let preview: String = talos_dlp_provider::redact_str(&error_message)
                .chars()
                .take(50)
                .collect();
            tracing::warn!(
                "Failed to mark execution {} as failed: {} (original error: {})",
                execution_id,
                e,
                preview
            );
        }
    }

    /// Timeout execution (best effort - logs error on failure)
    pub async fn timeout_execution_best_effort(&self, execution_id: Uuid, user_id: Uuid) {
        if let Err(e) = self.timeout_execution(execution_id, user_id).await {
            tracing::warn!(
                "Failed to mark execution {} as timeout: {}",
                execution_id,
                e
            );
        }
    }

    /// Complete an execution from a trusted worker result (no user_id ownership check).
    ///
    /// This is the internal path used by the NATS result subscriber when the worker
    /// reports a successful execution.  The result has already been HMAC-verified by the
    /// worker, so the extra ownership check that `complete_execution` performs is not
    /// needed here.
    ///
    /// `duration_ms` is caller-wins, exactly as on
    /// [`ModuleExecutionStore::record_completed`](talos_workflow_engine_core::ModuleExecutionStore::record_completed):
    /// `Some(n)` is stored verbatim and labelled `duration_source = 'monotonic'`,
    /// `None` leaves both columns unset so the
    /// `calculate_module_execution_duration()` BEFORE UPDATE trigger derives
    /// `completed_at - started_at` and stamps `'wallclock'` itself.
    ///
    /// **`Some(n)` is a claim about the CLOCK, and the caller must be able to
    /// make it.** Pass `Some` only for a `std::time::Instant::elapsed()`
    /// measurement — never a value subtracted from two timestamps, and never a
    /// placeholder. `'monotonic'` is what tells a reader the number is immune
    /// to a host suspend; on the live stack wall and monotonic have diverged by
    /// 8.1 hours, so a mislabelled row is not a rounding error.
    ///
    /// The webhook module-dispatch caller passes its own `wasm_start.elapsed()`
    /// — a controller-side `Instant` across the dispatch, the same span class
    /// the engine's `record_completed` rows carry. The audit-topic result
    /// subscriber passes `None`; see its call site for why the worker's
    /// self-reported `JobResult::execution_time_ms` is deliberately not used
    /// there.
    pub async fn complete_execution_from_worker(
        &self,
        execution_id: Uuid,
        output_data: Option<JsonValue>,
        duration_ms: Option<i32>,
    ) -> Result<()> {
        // MCP-1199 (2026-05-17): validate size BEFORE redact_json —
        // sibling holdout to MCP-1163's `complete_execution` fix on
        // lines 402-409 of this same file. Worker-supplied output is
        // unbounded (no caller-side cap on the NATS reply path), so
        // pre-fix the redact pass walked the FULL unbounded JSON
        // before `validate_jsonb_size` rejected it — pure waste under
        // any oversized-input attack/buggy module. Same MCP-1162
        // measure-first family. Inverting the order also closes the
        // sibling-sweep gap: when retrofitting a discipline to N
        // copies of the same write path, sweep ALL of them.
        Self::validate_jsonb_size(&output_data, "output_data")?;
        // Apply regex-based DLP before storage.  Value-based scrubbing is not applied
        // here because the worker result path doesn't have access to node configs —
        // the engine's run/run_with_seed methods handle value-based scrubbing for
        // workflow-level output.  Regex patterns still catch standard credential formats.
        let output_data = output_data.map(|v| talos_dlp_provider::redact_json(&v));

        // $1 = output_data, $2 = duration_ms, $3 = execution_id
        //
        // RETURNING actor_id serves the `__ops_alert__` chokepoint below: a
        // row comes back ONLY when this call actually transitioned the
        // execution (the status guard filters replays/late duplicates), and
        // it carries the actor whose tenancy the ingest resolves against.
        //
        // `duration_source` is bound from the SAME parameter as `duration_ms`
        // (#707's rule), so the label can never disagree with what it
        // describes: there is no statement that writes one without the other.
        let transitioned = sqlx::query(
            r#"
            UPDATE module_executions
            SET
                status = 'completed',
                output_data = $1,
                duration_ms = $2,
                duration_source = CASE WHEN $2::int4 IS NULL
                                       THEN NULL ELSE 'monotonic' END,
                completed_at = NOW()
            WHERE id = $3 AND status IN ('pending', 'running')
            RETURNING actor_id
            "#,
        )
        .bind(&output_data)
        .bind(duration_ms)
        .bind(execution_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("Failed to complete execution from worker result")?;

        // `__ops_alert__` protocol for MODULE-BOUND dispatches (GCP
        // Monitoring Pub/Sub, Gmail/GCal watches, inbound webhooks, the
        // fire-and-forget `talos.results.*` subscriber): every such result
        // funnels through this method, making it the sibling chokepoint of
        // the engine's node hook. Engine-dispatched workflow nodes never
        // reach here (request-reply → engine hook), so an envelope is
        // ingested exactly once. Gated on the transition (no replay
        // double-bumps) and on envelope presence (zero cost otherwise).
        if let Some(row) = transitioned {
            if let Some(ref output) = output_data {
                if talos_ops_alerts_repository::envelope::output_has_envelope(output) {
                    use sqlx::Row as _;
                    let actor_id = row.try_get::<Option<Uuid>, _>("actor_id")?;
                    talos_ops_alerts_repository::envelope::spawn_ingest_from_output(
                        self.db_pool.clone(),
                        actor_id,
                        output,
                        "module_result",
                    );
                }
            }
        }

        tracing::debug!("Worker completed module execution {}", execution_id);
        Ok(())
    }

    /// Fail an execution from a trusted worker result (no user_id ownership check).
    ///
    /// Same trust model as `complete_execution_from_worker`, and the same
    /// caller-wins `duration_ms` contract — see that method for what `Some(n)`
    /// asserts. A failed dispatch took just as long as a successful one, so
    /// the measurement is no less real; the only difference is that the row
    /// records what it was doing when it stopped.
    pub async fn fail_execution_from_worker(
        &self,
        execution_id: Uuid,
        error_message: String,
        error_type: Option<String>,
        duration_ms: Option<i32>,
    ) -> Result<()> {
        let error_message: String = error_message
            .chars()
            .take(10_000)
            .filter(|c| !c.is_control() || *c == '\n' || *c == '\t' || *c == '\r')
            .collect();
        // MCP-968 (2026-05-15): DLP-redact after the 10k char cap +
        // control-char filter. Pre-fix this method bound the sanitized
        // (but unscrubbed) `error_message` directly into
        // `module_executions.error_message`. The sibling
        // `complete_execution_from_worker` ALREADY redacts `output_data`
        // via `redact_json` (line 909), AND other methods in this same
        // file redact at write boundaries (lines 393, 456, 555, 572,
        // 909) — `fail_execution_from_worker` was the lone unscrubbed
        // sibling on the error-message path. Worker-supplied failure
        // text is arbitrary: HTTP response bodies, panic strings,
        // upstream API errors — same secret-bearing class as
        // log_message (MCP-965/966) and workflow_executions
        // error_message (MCP-967).
        let error_message = talos_dlp_provider::redact_str(&error_message);

        // $1 = error_message, $2 = error_type, $3 = duration_ms,
        // $4 = execution_id.
        //
        // `duration_source` bound from the SAME parameter as `duration_ms` —
        // see `complete_execution_from_worker` for the rule.
        sqlx::query(
            r#"
            UPDATE module_executions
            SET
                status = 'failed',
                error_message = $1,
                error_type = $2,
                duration_ms = $3,
                duration_source = CASE WHEN $3::int4 IS NULL
                                       THEN NULL ELSE 'monotonic' END,
                completed_at = NOW()
            WHERE id = $4 AND status IN ('pending', 'running')
            "#,
        )
        .bind(&error_message)
        .bind(error_type)
        .bind(duration_ms)
        .bind(execution_id)
        .execute(&self.db_pool)
        .await
        .context("Failed to fail execution from worker result")?;

        tracing::debug!(
            "Worker failed module execution {}: {}",
            execution_id,
            error_message.chars().take(100).collect::<String>()
        );
        Ok(())
    }

    /// The furthest rank any payload reader reaches into a module's completed
    /// history, and therefore the floor under `corpus_keep`.
    ///
    /// Two readers decrypt `module_executions` payloads from arbitrarily-old
    /// rows, and both are rank-bounded rather than age-bounded:
    ///
    /// * `ModuleRepository::list_completed_module_executions` — backs the MCP
    ///   tool `replay_module_regression`, whose handler clamps the caller's
    ///   `limit` to `[1, 20]`.
    /// * `ModuleRepository::find_latest_completed_execution_io` — backs
    ///   `generate_typed_scaffold`, a hard `LIMIT 1`.
    ///
    /// Both order by exactly `completed_at DESC NULLS LAST, started_at DESC`,
    /// which is why the sweep's `corpus` CTE can use the identical key and be
    /// provably disjoint from their reach. **If the `[1, 20]` clamp is ever
    /// widened, this constant must move with it** — the two are the same fact
    /// stated in two crates.
    pub const REPLAY_REACH: i64 = 20;

    /// Terminal statuses. The `module_executions` CHECK constraint admits six
    /// values; these are the four the sweep may touch, and `pending` /
    /// `running` are the two it must never touch (a running row's
    /// `input_data_enc` is the live dispatch payload). Kept as a constant so
    /// the candidate filter and the under-lock re-check cannot drift apart.
    const TERMINAL_STATUSES: [&'static str; 4] = ["completed", "failed", "cancelled", "timeout"];

    /// Clear the AEAD payloads of old terminal module executions, leaving a
    /// tombstone behind.
    ///
    /// **This is irreversible.** `input_data_enc` / `output_data_enc` are
    /// AES-GCM ciphertexts; there is no decrypt-and-restore and the only
    /// recovery is a backup restore. The caller is expected to gate this
    /// behind an explicitly-enabled operator flag.
    ///
    /// # Why the predicate has the shape it does
    ///
    /// A plain "older than N days" policy is NOT safe here, and building one
    /// was the trap this method exists to avoid. No payload read in the
    /// workspace is bounded by age; the two replay/scaffold readers are
    /// bounded by RANK within a module. For a module that ran a handful of
    /// times and then went quiet, its most recent completed rows are also its
    /// oldest — an age policy nulls exactly those and the replay corpus goes
    /// silently empty, which is how `ReplayService` shipped as a no-op once
    /// already.
    ///
    /// So the predicate is conjunctive:
    ///
    /// 1. terminal status only — never `pending` / `running`;
    /// 2. `created_at` older than `retention_days` — the age BELT, whose
    ///    natural value is `EXECUTION_RETENTION_DAYS`, because that is when
    ///    this platform already DELETES the whole parent `workflow_executions`
    ///    row (and CASCADEs `execution_events` with it). Retention parity;
    /// 3. not among the `corpus_keep` most recent `completed` rows for its
    ///    `(module_id, user_id)`, ranked by the readers' own ORDER BY;
    /// 4. it still has a payload — which makes the sweep idempotent and keeps
    ///    it off the rows that never had one.
    ///
    /// `corpus_keep` is clamped up to [`Self::REPLAY_REACH`]: a caller asking
    /// to keep fewer than the readers can reach would be asking for the
    /// silent-empty-corpus failure by configuration.
    ///
    /// # Side effect worth knowing
    ///
    /// `trigger_module_execution_updated_at` is an unconditional
    /// `BEFORE UPDATE FOR EACH ROW` trigger, so `updated_at` moves on every
    /// pruned row and no value set here can prevent it. Nothing in the
    /// workspace filters or orders on `module_executions.updated_at` (it is
    /// projected for display only), and `payload_pruned_at` sits beside it to
    /// explain the movement. `duration_ms` is NOT recomputed: the duration
    /// trigger fires only when `completed_at` transitions from NULL, which
    /// this statement never does.
    pub async fn prune_terminal_payloads(
        &self,
        retention_days: i32,
        corpus_keep: i64,
        batch_size: i64,
    ) -> Result<PayloadRetentionStats> {
        // Fail closed on a destructive misconfiguration rather than
        // substituting a default and pruning something. Same `=0`/negative
        // footgun family as MCP-1063 — with `retention_days = 0` the age belt
        // becomes `created_at < NOW()`, i.e. every terminal row on the first
        // sweep.
        if retention_days <= 0 {
            tracing::error!(
                target: "talos_module_executions",
                event_kind = "payload_retention_refused_nonpositive_days",
                retention_days,
                "module-payload retention refused: retention_days must be positive \
                 (would prune every terminal row on the first sweep)"
            );
            return Ok(PayloadRetentionStats::default());
        }
        if batch_size <= 0 {
            return Ok(PayloadRetentionStats::default());
        }
        let corpus_keep = corpus_keep.max(Self::REPLAY_REACH);

        let mut stats = PayloadRetentionStats::default();
        // Bound the whole sweep, not just each batch: a first run against a
        // long-unswept table should not hold the pool for an unbounded number
        // of rounds. Whatever is left is picked up on the next tick, because
        // the predicate is self-excluding once a row is tombstoned.
        const MAX_BATCHES_PER_SWEEP: u32 = 20;

        while stats.batches < MAX_BATCHES_PER_SWEEP {
            let rows: Vec<(Option<i32>, Option<i32>)> = sqlx::query_as(
                r#"
                WITH corpus AS (
                    SELECT id FROM (
                        SELECT id,
                               row_number() OVER (
                                   PARTITION BY module_id, user_id
                                   ORDER BY completed_at DESC NULLS LAST, started_at DESC
                               ) AS rn
                        FROM module_executions
                        WHERE status = 'completed'
                    ) ranked
                    WHERE rn <= $2
                ),
                candidates AS (
                    SELECT me.id,
                           octet_length(me.input_data_enc)  AS ib,
                           octet_length(me.output_data_enc) AS ob
                    FROM module_executions me
                    WHERE me.status = ANY($4)
                      AND me.created_at < NOW() - make_interval(days => $1::int)
                      AND (me.input_data_enc IS NOT NULL OR me.output_data_enc IS NOT NULL)
                      AND me.payload_pruned_at IS NULL
                      AND NOT EXISTS (SELECT 1 FROM corpus c WHERE c.id = me.id)
                    ORDER BY me.created_at
                    LIMIT $3
                )
                UPDATE module_executions m
                SET input_data_enc     = NULL,
                    output_data_enc    = NULL,
                    payload_pruned_at  = NOW(),
                    pruned_input_bytes = c.ib,
                    pruned_output_bytes = c.ob
                FROM candidates c
                WHERE m.id = c.id
                  AND m.status = ANY($4)
                RETURNING c.ib, c.ob
                "#,
            )
            .bind(retention_days)
            .bind(corpus_keep)
            .bind(batch_size)
            .bind(&Self::TERMINAL_STATUSES[..])
            .fetch_all(&self.db_pool)
            .await
            .context("module-payload retention sweep failed")?;

            let batch_len = rows.len() as u64;
            stats.batches += 1;
            stats.pruned_rows += batch_len;
            for (ib, ob) in &rows {
                stats.input_bytes_freed += i64::from(ib.unwrap_or(0));
                stats.output_bytes_freed += i64::from(ob.unwrap_or(0));
            }
            if batch_len < batch_size as u64 {
                break; // last batch
            }
        }
        Ok(stats)
    }

    /// DELETE old terminal `module_executions` rows whose parent
    /// `workflow_executions` row no longer exists.
    ///
    /// **This is irreversible, and strictly more destructive than
    /// [`Self::prune_terminal_payloads`].** That sweep clears two BYTEA columns
    /// and leaves a `payload_pruned_at` tombstone, so the row's status,
    /// duration, fuel and error text stay readable and a later reader can tell
    /// what happened. This removes the row itself: there is no tombstone, and a
    /// deleted execution is indistinguishable from one that never ran. Each
    /// deleted row also CASCADEs its `module_execution_logs` children
    /// (`node_execution_logs_execution_id_fkey`). The caller is expected to gate
    /// this behind an explicitly-enabled operator flag.
    ///
    /// # Why this exists when the payload sweep already frees the space
    ///
    /// Payload pruning bounds BYTES. Only row deletion bounds ROW COUNT, and
    /// row count is the thing that grows without limit. Measured 2026-08-28:
    /// 36,942 rows accumulated over 51 days (~724/day, matching the ~730/day
    /// the registry's eviction LATERAL already documents), 133 MB total, of
    /// which 21 MB heap + 27 MB across 19 indexes is untouchable by a payload
    /// sweep, plus 37 MB of `module_execution_logs` that only a row DELETE
    /// reclaims.
    ///
    /// # Why the predicate has the shape it does
    ///
    /// Four conjunctive clauses, three of them load-bearing safety:
    ///
    /// 1. **terminal status only** — never `pending` / `running`. A live row is
    ///    an in-flight dispatch; deleting it would strand the worker's result.
    /// 2. **`created_at` older than `retention_days`** — the age BELT, whose
    ///    natural value is `EXECUTION_RETENTION_DAYS`, because that is when this
    ///    platform already DELETEs the parent `workflow_executions` row.
    /// 3. **the parent is gone** — `NOT EXISTS` against `workflow_executions`.
    ///    This is what makes the sweep a *gap closure* rather than an
    ///    independent retention policy: it deletes only what the parent sweep
    ///    would already have taken had the FK that was never added been there.
    ///    Measured 2026-08-28, this costs nothing — of the 9,018 rows older than
    ///    30 days, all 9,018 are already parentless, and 0 old rows have a
    ///    surviving parent. It is pure insurance against a future fleet where
    ///    a parent outlives the age floor (the parent sweep skips
    ///    `status='queued'`, so a long-queued execution does exactly that).
    ///
    ///    **`workflow_execution_id IS NULL` satisfies this clause**, which is
    ///    correct but non-obvious: `we.id = NULL` matches no row, so `NOT
    ///    EXISTS` is TRUE. A standalone module run (`run_sandbox`,
    ///    `test_module`) has no workflow parent by design, so age is the only
    ///    bound it can have. On the dev fleet 0 of 36,942 rows are in this
    ///    state — every row is webhook-triggered — so this arm is presently
    ///    unexercised in production data and is covered by unit test
    ///    `deletes_a_parentless_standalone_run`.
    /// 4. **not among the `corpus_keep` most recent `completed` rows for its
    ///    `(module_id, user_id)`** — ranked by the readers' own ORDER BY. This
    ///    is the clause an age-only policy would omit and be wrong for, and the
    ///    argument is identical to the one on `prune_terminal_payloads`, only
    ///    with higher stakes: nulling a payload leaves the row visible to
    ///    `replay_module_regression` (which then finds an empty payload);
    ///    deleting it removes the row from the corpus ranking entirely. No
    ///    reader in the workspace is bounded by AGE; the replay and scaffold
    ///    readers are bounded by RANK, so for a module that ran a few times a
    ///    year ago and went quiet, its entire corpus is also its oldest data.
    ///
    /// # RLS
    ///
    /// Both tables have FORCE row-level security. Their `USING` clauses are
    /// `NULLIF(current_setting(..., true), '') IS NULL OR ...`, i.e. they
    /// PERMIT when no tenant setting is bound, which is the case on the bare
    /// system pool this sweep uses. That is load-bearing for clause 3: if
    /// `workflow_executions` ever gains a policy that DENIES on unset, every
    /// live parent would become invisible here and the guard would flip from
    /// "delete only orphans" to "delete everything old".
    ///
    /// # What this deliberately does not do
    ///
    /// It does not report bytes freed. `octet_length` on the payload columns
    /// would force a detoast of every row on its way out — reading ~5000 TOAST
    /// entries per batch purely to produce a log number. `prune_terminal_payloads`
    /// can afford it because it is already rewriting the row; this cannot.
    /// Operators read reclaimed space from `pg_total_relation_size`.
    ///
    /// # Known behavioural coupling
    ///
    /// `talos_registry`'s eviction LATERAL reads `MAX(started_at)` per module
    /// at unbounded age to order WASM-cache eviction. A module whose every
    /// execution is deleted here falls back to `COALESCE(e.last_exec,
    /// m.created_at)`. That fallback exists precisely for this change (see the
    /// `eviction_order!` comment, which names a future retention policy as the
    /// reason it is not `NULLS FIRST`). Clause 4 keeps up to `corpus_keep`
    /// completed rows per module, so a module with any successful history keeps
    /// a `last_exec`; only a module whose runs were ALL non-`completed` and all
    /// older than the age floor loses it, and for that module `created_at` is
    /// the honest answer.
    pub async fn delete_expired_executions(
        &self,
        retention_days: i32,
        corpus_keep: i64,
        batch_size: i64,
    ) -> Result<RowRetentionStats> {
        // Fail closed on a destructive misconfiguration rather than
        // substituting a default and deleting something. `talos_config` already
        // routes the env var through `positive_env_or_default`; this is the
        // function-boundary half of the same defense, and it is what protects a
        // caller that computes the value rather than reading the env. With
        // `retention_days = 0` the age belt becomes `created_at < NOW()`, i.e.
        // every terminal parentless row on the first sweep.
        if retention_days <= 0 {
            tracing::error!(
                target: "talos_module_executions",
                event_kind = "row_retention_refused_nonpositive_days",
                retention_days,
                "module-execution row retention refused: retention_days must be positive \
                 (would delete every terminal parentless row on the first sweep)"
            );
            return Ok(RowRetentionStats::default());
        }
        if batch_size <= 0 {
            return Ok(RowRetentionStats::default());
        }
        let corpus_keep = corpus_keep.max(Self::REPLAY_REACH);

        // Measured ONCE per sweep, before the loop, so a `deleted_rows = 0`
        // reading is interpretable. Without it, "nothing is old enough" and
        // "plenty is old enough but every parent is still alive" are the same
        // number in the log, and an operator who enabled the flag and saw zero
        // has no way to tell a working sweep from a broken predicate. Errors are
        // non-fatal: this is a reporting field, not a gate, so a failed count
        // must not stop the sweep it is only annotating. But it degrades to
        // `None` rather than `0` — substituting 0 would put an unmeasured value
        // into the one field that exists to say whether a zero was measured.
        let retained_parent_alive = match sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM module_executions me \
             WHERE me.status = ANY($2) \
               AND me.created_at < NOW() - make_interval(days => $1::int) \
               AND EXISTS (SELECT 1 FROM workflow_executions we \
                           WHERE we.id = me.workflow_execution_id)",
        )
        .bind(retention_days)
        .bind(&Self::TERMINAL_STATUSES[..])
        .fetch_one(&self.db_pool)
        .await
        {
            Ok(n) => Some(n),
            Err(e) => {
                tracing::warn!(
                    target: "talos_module_executions",
                    event_kind = "row_retention_parent_alive_probe_failed",
                    error = %e,
                    "module-execution row retention: could not count rows skipped for a \
                     surviving parent; a deleted_rows=0 reading this tick is uninterpretable"
                );
                None
            }
        };

        let mut stats = RowRetentionStats {
            retained_parent_alive,
            ..Default::default()
        };

        // Bound the whole sweep, not just each batch: a first run against a
        // never-swept table must not hold the pool for an unbounded number of
        // rounds. Whatever is left is picked up on the next tick, because a
        // deleted row is self-excluding from the predicate. 20 x 5000 = 100,000
        // rows per tick, against the 9,018 currently eligible on the dev fleet
        // and a ~724 rows/day accrual — so steady state is one partial batch.
        const MAX_BATCHES_PER_SWEEP: u32 = 20;

        while stats.batches < MAX_BATCHES_PER_SWEEP {
            let deleted: Vec<(Uuid,)> = sqlx::query_as(
                r#"
                WITH corpus AS (
                    SELECT id FROM (
                        SELECT id,
                               row_number() OVER (
                                   PARTITION BY module_id, user_id
                                   ORDER BY completed_at DESC NULLS LAST, started_at DESC
                               ) AS rn
                        FROM module_executions
                        WHERE status = 'completed'
                    ) ranked
                    WHERE rn <= $2
                ),
                candidates AS (
                    SELECT me.id
                    FROM module_executions me
                    WHERE me.status = ANY($4)
                      AND me.created_at < NOW() - make_interval(days => $1::int)
                      AND NOT EXISTS (
                          SELECT 1 FROM workflow_executions we
                          WHERE we.id = me.workflow_execution_id
                      )
                      AND NOT EXISTS (SELECT 1 FROM corpus c WHERE c.id = me.id)
                    ORDER BY me.created_at
                    LIMIT $3
                )
                DELETE FROM module_executions m
                USING candidates c
                WHERE m.id = c.id
                  AND m.status = ANY($4)
                RETURNING m.id
                "#,
            )
            .bind(retention_days)
            .bind(corpus_keep)
            .bind(batch_size)
            .bind(&Self::TERMINAL_STATUSES[..])
            .fetch_all(&self.db_pool)
            .await
            .context("module-execution row retention sweep failed")?;

            let batch_len = deleted.len() as u64;
            stats.batches += 1;
            stats.deleted_rows += batch_len;
            if batch_len < batch_size as u64 {
                break; // last batch
            }
            // No inter-batch sleep, deliberately. The `workflow_executions`
            // retention DELETE in `controller/src/bootstrap/background.rs` has
            // a 100 ms one, but this crate has no `tokio` dependency and the
            // workspace `tokio` is built without the `time` feature — enabling
            // it here would widen feature unification for every crate in the
            // workspace to buy one sleep. `prune_terminal_payloads` directly
            // above, with the same batch size and the same 20-batch cap, does
            // not sleep either. Each batch is its own awaited round-trip, so
            // the pooled connection is returned between batches regardless, and
            // MAX_BATCHES_PER_SWEEP is the real bound on a single tick's work.
        }

        // Incremented at the chokepoint rather than at the call site, so a
        // future second caller cannot silently bypass it — the same reasoning as
        // `module_executions_swept_stuck_total` below. This is the ONLY durable
        // record that the sweep ran: unlike the payload sweep there is no
        // `payload_pruned_at` to count afterwards, because the rows that would
        // carry it are gone. `global()` is `None` when no registry is installed
        // (tests, tools), so this is best-effort and not a hard dependency.
        if stats.deleted_rows > 0 {
            if let Some(m) = talos_metrics::global() {
                m.module_executions_retention_deleted_total
                    .inc_by(stats.deleted_rows as f64);
            }
        }

        Ok(stats)
    }

    /// Mark executions stuck in `pending` or `running` state as `timeout`.
    ///
    /// If a worker crashes or is killed without reporting a result, the
    /// execution record is left in `running` indefinitely.  This method
    /// transitions those orphaned executions to `timeout` so that they do
    /// not pollute dashboards and metrics.
    ///
    /// `max_age_mins` controls how long an execution must be stuck before it
    /// is considered dead.  Default recommendation: 30 minutes.
    pub async fn cleanup_stuck_executions(&self, max_age_mins: i64) -> Result<u64> {
        // MCP-1062 (2026-05-15): refuse non-positive `max_age_mins`.
        // Sibling caller-supplied-negative class as MCP-997. With
        // `$1::int * INTERVAL '1 minute'` and a negative bind, the
        // predicate `started_at < NOW() - (-N * INTERVAL)` becomes
        // `started_at < NOW() + INTERVAL`, matching every pending /
        // running execution → 100-row batch of erroneous timeout
        // updates per sweep tick. Blast radius is LIMIT 100 per call
        // but a long-running sweep amplifies into total kill.
        if max_age_mins <= 0 {
            tracing::warn!(
                target: "talos_audit",
                max_age_mins,
                "stuck-executions cleanup refused: max_age_mins must be positive (would mark every pending/running execution as timeout)"
            );
            return Ok(0);
        }
        let result = sqlx::query(
            r#"
            UPDATE module_executions
            SET
                status = 'timeout',
                error_message = 'Execution timed out — worker did not report completion within the allowed window',
                error_type = 'stuck',
                completed_at = NOW(),
                updated_at = NOW()
            WHERE id IN (
                SELECT id FROM module_executions
                WHERE
                    status IN ('pending', 'running')
                    AND started_at < NOW() - ($1::int * INTERVAL '1 minute')
                LIMIT 100
                FOR UPDATE SKIP LOCKED
            )
            "#,
        )
        .bind(max_age_mins)
        .execute(&self.db_pool)
        .await
        .context("Failed to cleanup stuck executions")?;

        // The sweep's own count, made observable. Until 2026-08-12 the ONLY
        // consumer of this number was a `tracing::warn!` in the controller's
        // background loop — so a fleet where EVERY workflow node reached the
        // sweep (the single-node dispatch path never finalized its rows) was
        // indistinguishable from a healthy one to every alert and dashboard
        // this platform ships. The engine-side fix stops rows arriving here;
        // this counter is what would notice if anything ever redirects them
        // again, whatever the cause — a code change, a subscriber outage, a
        // transport that stops binding a reply inbox.
        //
        // Incremented at the chokepoint rather than at the single call site
        // so a future second caller cannot silently bypass it. `global()` is
        // `None` when no registry is installed (tests, tools), which is why
        // this is best-effort and not a hard dependency.
        let swept = result.rows_affected();
        if let Some(m) = talos_metrics::global() {
            m.module_executions_swept_stuck_total.inc_by(swept as f64);
        }

        Ok(swept)
    }
}
