//! ScheduleRepository — centralises SQL for the `workflow_schedules` table.
//! Handlers in `mcp/schedules.rs` should be thin wrappers over these methods.

use anyhow::Result;
use sqlx::{PgPool, Row};
use uuid::Uuid;

pub struct ScheduleRepository {
    db_pool: PgPool,
}

/// Schedule list row (joined with workflow name) returned by `list_for_user`.
#[derive(Debug)]
pub struct ScheduleListRow {
    pub id: Uuid,
    pub workflow_id: Uuid,
    pub workflow_name: String,
    pub cron_expression: String,
    pub timezone: Option<String>,
    pub is_enabled: bool,
    pub last_triggered_at: Option<chrono::DateTime<chrono::Utc>>,
    pub next_trigger_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Compact next-run projection for `get_schedule_next_runs`. Excludes
/// `last_triggered_at` (not surfaced) and pre-filters to enabled +
/// non-NULL next_trigger_at rows.
#[derive(Debug)]
pub struct ScheduleNextRunRow {
    pub id: Uuid,
    pub cron_expression: String,
    pub timezone: Option<String>,
    pub next_trigger_at: chrono::DateTime<chrono::Utc>,
    pub is_enabled: bool,
    pub workflow_name: String,
}

/// Health-check projection (joined with workflow). Includes the workflow's
/// id + name so the handler can use them for downstream stats lookups.
#[derive(Debug)]
pub struct ScheduleHealthRow {
    pub id: Uuid,
    pub cron_expression: String,
    pub timezone: String,
    pub is_enabled: bool,
    pub last_triggered_at: Option<chrono::DateTime<chrono::Utc>>,
    pub next_trigger_at: Option<chrono::DateTime<chrono::Utc>>,
    pub workflow_id: Uuid,
    pub workflow_name: String,
}

impl ScheduleRepository {
    pub fn new(db_pool: PgPool) -> Self {
        Self { db_pool }
    }

    /// Insert a new enabled workflow schedule. Surface the underlying
    /// `sqlx::Error` (not anyhow) so callers can pattern-match on
    /// `is_unique_violation()` to detect the
    /// `workflow_schedules_workflow_id_key` collision and produce a
    /// caller-friendly "schedule already exists" message.
    pub async fn create_schedule(
        &self,
        schedule_id: Uuid,
        workflow_id: Uuid,
        user_id: Uuid,
        cron_expression: &str,
        timezone: &str,
        next_trigger_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO workflow_schedules \
             (id, workflow_id, user_id, cron_expression, timezone, is_enabled, next_trigger_at, created_at) \
             VALUES ($1, $2, $3, $4, $5, true, $6, NOW())",
        )
        .bind(schedule_id)
        .bind(workflow_id)
        .bind(user_id)
        .bind(cron_expression)
        .bind(timezone)
        .bind(next_trigger_at)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    /// List a user's schedules joined with workflow name.
    pub async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<ScheduleListRow>> {
        let rows = sqlx::query(
            "SELECT ws.id, ws.workflow_id, ws.cron_expression, ws.timezone, ws.is_enabled, \
                    ws.last_triggered_at, ws.next_trigger_at, w.name AS workflow_name \
             FROM workflow_schedules ws \
             JOIN workflows w ON w.id = ws.workflow_id \
             WHERE ws.user_id = $1 \
             ORDER BY ws.created_at DESC",
        )
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;
        rows.iter()
            .map(|r| -> Result<ScheduleListRow> {
                Ok(ScheduleListRow {
                    id: r.get("id"),
                    workflow_id: r.get("workflow_id"),
                    workflow_name: r.get("workflow_name"),
                    cron_expression: r.get("cron_expression"),
                    timezone: r.try_get::<Option<_>, _>("timezone")?,
                    is_enabled: r.get("is_enabled"),
                    last_triggered_at: r.try_get::<Option<_>, _>("last_triggered_at")?,
                    next_trigger_at: r.try_get::<Option<_>, _>("next_trigger_at")?,
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    /// Toggle a schedule's `is_enabled` flag (handles both pause + resume).
    /// Returns rows affected (0 = not found / not owned).
    pub async fn set_enabled(
        &self,
        schedule_id: Uuid,
        user_id: Uuid,
        enabled: bool,
    ) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE workflow_schedules SET is_enabled = $1 WHERE id = $2 AND user_id = $3",
        )
        .bind(enabled)
        .bind(schedule_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Delete a schedule scoped to user.
    pub async fn delete(&self, schedule_id: Uuid, user_id: Uuid) -> Result<u64> {
        let result = sqlx::query("DELETE FROM workflow_schedules WHERE id = $1 AND user_id = $2")
            .bind(schedule_id)
            .bind(user_id)
            .execute(&self.db_pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// Upcoming scheduled runs for a user (enabled + non-NULL next_trigger_at).
    pub async fn list_next_runs(
        &self,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<ScheduleNextRunRow>> {
        let rows = sqlx::query(
            "SELECT ws.id, ws.cron_expression, ws.timezone, ws.next_trigger_at, ws.is_enabled, \
                    w.name AS workflow_name \
             FROM workflow_schedules ws \
             JOIN workflows w ON w.id = ws.workflow_id \
             WHERE ws.user_id = $1 AND ws.is_enabled = true AND ws.next_trigger_at IS NOT NULL \
             ORDER BY ws.next_trigger_at ASC LIMIT $2",
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        rows.iter()
            .map(|r| -> Result<ScheduleNextRunRow> {
                Ok(ScheduleNextRunRow {
                    id: r.get("id"),
                    cron_expression: r.get("cron_expression"),
                    timezone: r.try_get::<Option<_>, _>("timezone")?,
                    next_trigger_at: r.get("next_trigger_at"),
                    is_enabled: r.get("is_enabled"),
                    workflow_name: r.get("workflow_name"),
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    /// Health-check info: schedule fields + parent workflow id/name.
    pub async fn get_with_workflow_info(
        &self,
        schedule_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<ScheduleHealthRow>> {
        let row = sqlx::query(
            "SELECT ws.id, ws.cron_expression, ws.timezone, ws.is_enabled, \
                    ws.last_triggered_at, ws.next_trigger_at, \
                    w.id AS workflow_id, w.name AS workflow_name \
             FROM workflow_schedules ws \
             JOIN workflows w ON w.id = ws.workflow_id \
             WHERE ws.id = $1 AND ws.user_id = $2",
        )
        .bind(schedule_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        row.map(|r| -> Result<ScheduleHealthRow> {
            Ok(ScheduleHealthRow {
                id: r.get("id"),
                cron_expression: r.get("cron_expression"),
                timezone: r
                    .try_get::<Option<String>, _>("timezone")?
                    .unwrap_or_else(|| "UTC".to_string()),
                is_enabled: r.try_get::<Option<_>, _>("is_enabled")?.unwrap_or(false),
                last_triggered_at: r.try_get::<Option<_>, _>("last_triggered_at")?,
                next_trigger_at: r.try_get::<Option<_>, _>("next_trigger_at")?,
                workflow_id: r.get("workflow_id"),
                workflow_name: r.get("workflow_name"),
            })
        })
        .transpose()
    }
}
