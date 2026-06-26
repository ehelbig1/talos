use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use sqlx::PgPool;
use uuid::Uuid;

#[cfg(test)]
#[path = "module_executions_tests.rs"]
mod tests;

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
}

impl std::fmt::Display for ExecutionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Running => write!(f, "running"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
            Self::Timeout => write!(f, "timeout"),
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
        // create_execution populated.
        let (key_id, _input_enc, output_enc, _trigger_enc, payload_format) = self
            .encrypt_payload_bundle(execution_id, None, output_data.as_ref(), None)
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
    /// Returns Ok(()) even if rate limit is exceeded (fails silently to not block execution)
    pub async fn add_log(
        &self,
        execution_id: Uuid,
        level: LogLevel,
        message: String,
        metadata: Option<JsonValue>,
    ) -> Result<()> {
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
            Ok(_) => Ok(()),
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
                    Ok(())
                } else if error_msg.contains("violates foreign key constraint")
                    || error_msg.contains("is not present in table")
                {
                    // This happens for workflow/canvas node executions which don't have
                    // an entry in the module_executions table. We can safely ignore these logs in the DB.
                    tracing::trace!(
                        "Dropped log for canvas execution {} (no module_execution row)",
                        execution_id
                    );
                    Ok(())
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
                created_at, updated_at
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
        let pt_trigger: Option<JsonValue> = r.try_get("trigger_metadata").ok().flatten();
        let pt_input: Option<JsonValue> = r.try_get("input_data").ok().flatten();
        let pt_output: Option<JsonValue> = r.try_get("output_data").ok().flatten();
        let enc_trigger: Option<Vec<u8>> = r.try_get("trigger_metadata_enc").ok().flatten();
        let enc_input: Option<Vec<u8>> = r.try_get("input_data_enc").ok().flatten();
        let enc_output: Option<Vec<u8>> = r.try_get("output_data_enc").ok().flatten();
        let key_id: Option<Uuid> = r.try_get("payload_enc_key_id").ok().flatten();
        let payload_format: i16 = r.try_get("payload_format").unwrap_or(0);
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
            id: r.get("id"),
            module_id: r.get("module_id"),
            user_id: r.get("user_id"),
            status: r.get("status"),
            trigger_type: r.get("trigger_type"),
            trigger_metadata,
            input_data,
            output_data,
            started_at: r.get("started_at"),
            completed_at: r.try_get("completed_at").unwrap_or(None),
            duration_ms: r.try_get("duration_ms").unwrap_or(None),
            error_message: r.try_get("error_message").unwrap_or(None),
            error_type: r.try_get("error_type").unwrap_or(None),
            fuel_consumed: r.try_get("fuel_consumed").unwrap_or(None),
            memory_used_mb: r.try_get("memory_used_mb").unwrap_or(None),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
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
                created_at, updated_at
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
            let exec_id: Uuid = r.get("id");
            let pt_trigger: Option<JsonValue> = r.try_get("trigger_metadata").ok().flatten();
            let pt_input: Option<JsonValue> = r.try_get("input_data").ok().flatten();
            let pt_output: Option<JsonValue> = r.try_get("output_data").ok().flatten();
            let enc_trigger: Option<Vec<u8>> = r.try_get("trigger_metadata_enc").ok().flatten();
            let enc_input: Option<Vec<u8>> = r.try_get("input_data_enc").ok().flatten();
            let enc_output: Option<Vec<u8>> = r.try_get("output_data_enc").ok().flatten();
            let key_id: Option<Uuid> = r.try_get("payload_enc_key_id").ok().flatten();
            let payload_format: i16 = r.try_get("payload_format").unwrap_or(0);
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
                id: r.get("id"),
                module_id: r.get("module_id"),
                user_id: r.get("user_id"),
                status: r.get("status"),
                trigger_type: r.get("trigger_type"),
                trigger_metadata,
                input_data,
                output_data,
                started_at: r.get("started_at"),
                completed_at: r.try_get("completed_at").unwrap_or(None),
                duration_ms: r.try_get("duration_ms").unwrap_or(None),
                error_message: r.try_get("error_message").unwrap_or(None),
                error_type: r.try_get("error_type").unwrap_or(None),
                fuel_consumed: r.try_get("fuel_consumed").unwrap_or(None),
                memory_used_mb: r.try_get("memory_used_mb").unwrap_or(None),
                created_at: r.get("created_at"),
                updated_at: r.get("updated_at"),
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

    /// Add log entry (best effort - logs error on failure)
    pub async fn add_log_best_effort(
        &self,
        execution_id: Uuid,
        level: LogLevel,
        message: String,
        metadata: Option<JsonValue>,
    ) {
        if let Err(e) = self
            .add_log(execution_id, level, message.clone(), metadata)
            .await
        {
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
    pub async fn complete_execution_from_worker(
        &self,
        execution_id: Uuid,
        output_data: Option<JsonValue>,
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

        // $1 = output_data, $2 = execution_id
        sqlx::query(
            r#"
            UPDATE module_executions
            SET
                status = 'completed',
                output_data = $1,
                completed_at = NOW()
            WHERE id = $2 AND status IN ('pending', 'running')
            "#,
        )
        .bind(output_data)
        .bind(execution_id)
        .execute(&self.db_pool)
        .await
        .context("Failed to complete execution from worker result")?;

        tracing::debug!("Worker completed module execution {}", execution_id);
        Ok(())
    }

    /// Fail an execution from a trusted worker result (no user_id ownership check).
    ///
    /// Same trust model as `complete_execution_from_worker`.
    pub async fn fail_execution_from_worker(
        &self,
        execution_id: Uuid,
        error_message: String,
        error_type: Option<String>,
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

        // $1 = error_message, $2 = error_type, $3 = execution_id
        sqlx::query(
            r#"
            UPDATE module_executions
            SET
                status = 'failed',
                error_message = $1,
                error_type = $2,
                completed_at = NOW()
            WHERE id = $3 AND status IN ('pending', 'running')
            "#,
        )
        .bind(&error_message)
        .bind(error_type)
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

        Ok(result.rows_affected())
    }
}
