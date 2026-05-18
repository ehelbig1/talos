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

    pub fn new(db_pool: PgPool) -> Self {
        Self { db_pool }
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
    pub async fn create_execution(
        &self,
        module_id: Uuid,
        user_id: Uuid,
        trigger_type: TriggerType,
        trigger_metadata: Option<JsonValue>,
        input_data: Option<JsonValue>,
    ) -> Result<Uuid> {
        // Validate JSONB sizes before database insert (prevent bloat/DoS)
        Self::validate_jsonb_size(&trigger_metadata, "trigger_metadata")?;
        Self::validate_jsonb_size(&input_data, "input_data")?;

        let execution_id = Uuid::new_v4();

        sqlx::query!(
            r#"
            INSERT INTO module_executions (
                id, module_id, user_id, status, trigger_type, trigger_metadata, input_data
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
            execution_id,
            module_id,
            user_id,
            ExecutionStatus::Pending.to_string(),
            trigger_type.to_string(),
            trigger_metadata,
            input_data
        )
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
        // Validate output size before database update (prevent bloat/DoS)
        Self::validate_jsonb_size(&output_data, "output_data")?;

        let result = sqlx::query!(
            r#"
            UPDATE module_executions
            SET
                status = $1,
                completed_at = NOW(),
                output_data = $2,
                fuel_consumed = $3,
                memory_used_mb = $4
            WHERE id = $5 AND user_id = $6
            "#,
            ExecutionStatus::Completed.to_string(),
            output_data,
            fuel_consumed,
            memory_used_mb,
            execution_id,
            user_id
        )
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
        // Sanitize error message to prevent DB bloat
        let sanitized_message = Self::sanitize_error_message(error_message);

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

        // Validate metadata size (prevent bloat/DoS)
        Self::validate_jsonb_size(&metadata, "log metadata")?;

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
            metadata
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

    /// Get execution by ID (with authorization check)
    pub async fn get_execution(
        &self,
        execution_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<ModuleExecution>> {
        let record = sqlx::query_as!(
            ModuleExecution,
            r#"
            SELECT
                id, module_id, user_id,
                status as "status: ExecutionStatus",
                trigger_type as "trigger_type: TriggerType",
                trigger_metadata, input_data, output_data,
                started_at, completed_at, duration_ms,
                error_message, error_type,
                fuel_consumed, memory_used_mb,
                created_at, updated_at
            FROM module_executions
            WHERE id = $1 AND user_id = $2
            "#,
            execution_id,
            user_id
        )
        .fetch_optional(&self.db_pool)
        .await
        .context("Failed to fetch execution")?;

        Ok(record)
    }

    /// Get recent executions for a module (with authorization)
    pub async fn get_module_executions(
        &self,
        module_id: Uuid,
        user_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ModuleExecution>> {
        let records = sqlx::query_as!(
            ModuleExecution,
            r#"
            SELECT
                id, module_id, user_id,
                status as "status: ExecutionStatus",
                trigger_type as "trigger_type: TriggerType",
                trigger_metadata, input_data, output_data,
                started_at, completed_at, duration_ms,
                error_message, error_type,
                fuel_consumed, memory_used_mb,
                created_at, updated_at
            FROM module_executions
            WHERE module_id = $1 AND user_id = $2
            ORDER BY started_at DESC
            LIMIT $3 OFFSET $4
            "#,
            module_id,
            user_id,
            limit,
            offset
        )
        .fetch_all(&self.db_pool)
        .await
        .context("Failed to fetch module executions")?;

        Ok(records)
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
            tracing::warn!(
                "Failed to add log to execution {}: {} (message: {})",
                execution_id,
                e,
                message.chars().take(50).collect::<String>()
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
            tracing::warn!(
                "Failed to mark execution {} as failed: {} (original error: {})",
                execution_id,
                e,
                error_message.chars().take(50).collect::<String>()
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
        Self::validate_jsonb_size(&output_data, "output_data")?;

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
        let result = sqlx::query(
            r#"
            UPDATE module_executions
            SET
                status = 'timeout',
                error_message = 'Execution timed out — worker did not report completion within the allowed window',
                error_type = 'stuck',
                completed_at = NOW(),
                updated_at = NOW()
            WHERE
                status IN ('pending', 'running')
                AND started_at < NOW() - ($1::int * INTERVAL '1 minute')
            "#,
        )
        .bind(max_age_mins)
        .execute(&self.db_pool)
        .await
        .context("Failed to cleanup stuck executions")?;

        Ok(result.rows_affected())
    }
}
