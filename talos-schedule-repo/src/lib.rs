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

/// What [`ScheduleRepository::update_timing`] did.
#[derive(Debug)]
pub enum ScheduleTimingUpdate {
    /// The row was written.
    Updated(ScheduleTiming),
    /// No schedule with that id belongs to the caller. Nothing was written.
    NotFound,
    /// The merged cron and timezone have no next fire time. Nothing was
    /// written.
    NoNextTrigger,
}

/// A schedule's timing after [`ScheduleRepository::update_timing`], with what
/// it was before.
#[derive(Debug)]
pub struct ScheduleTiming {
    pub workflow_id: Uuid,
    pub previous_cron_expression: String,
    pub previous_timezone: String,
    pub cron_expression: String,
    pub timezone: String,
    pub is_enabled: bool,
    pub next_trigger_at: chrono::DateTime<chrono::Utc>,
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
    ///
    /// Takes a [`talos_schedule_spec::ScheduleSpec`]: its only constructor
    /// runs every cron and timezone check, so this write cannot store a
    /// schedule that skipped them, and it carries the first due time.
    pub async fn create_schedule(
        &self,
        schedule_id: Uuid,
        workflow_id: Uuid,
        user_id: Uuid,
        schedule: &talos_schedule_spec::ScheduleSpec,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO workflow_schedules \
             (id, workflow_id, user_id, cron_expression, timezone, is_enabled, next_trigger_at, created_at) \
             VALUES ($1, $2, $3, $4, $5, true, $6, NOW())",
        )
        .bind(schedule_id)
        .bind(workflow_id)
        .bind(user_id)
        .bind(schedule.cron_expression())
        .bind(schedule.timezone())
        .bind(schedule.next_trigger_at())
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
                    id: r.try_get("id")?,
                    workflow_id: r.try_get("workflow_id")?,
                    workflow_name: r.try_get("workflow_name")?,
                    cron_expression: r.try_get("cron_expression")?,
                    timezone: r.try_get::<Option<_>, _>("timezone")?,
                    is_enabled: r.try_get("is_enabled")?,
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

    /// Change WHEN an existing schedule fires: its cron expression, its
    /// timezone, or both. `None` keeps the stored value.
    ///
    /// One transaction: the row is read `FOR UPDATE` scoped to its owner, the
    /// new pair is merged with the stored one, `next_trigger` computes the
    /// next fire time for the merged pair, and the row is written. A tick of
    /// the scheduler cannot claim the row between the read and the write.
    ///
    /// `next_trigger` returning `None` means the merged pair has no next fire
    /// time. Nothing is written then ([`ScheduleTimingUpdate::NoNextTrigger`]):
    /// a schedule stored with a NULL `next_trigger_at` is one the due-claim
    /// query never selects, so it would be saved and never run.
    ///
    /// `is_enabled` and `last_triggered_at` are not touched. The next fire
    /// time is recomputed for a paused schedule too, so that resuming it does
    /// not fire at the old time.
    pub async fn update_timing<F>(
        &self,
        schedule_id: Uuid,
        user_id: Uuid,
        cron_expression: Option<&str>,
        timezone: Option<&str>,
        next_trigger: F,
    ) -> Result<ScheduleTimingUpdate>
    where
        F: FnOnce(&str, &str) -> Option<chrono::DateTime<chrono::Utc>>,
    {
        let mut tx = self.db_pool.begin().await?;
        let Some(row) = sqlx::query(
            "SELECT workflow_id, cron_expression, timezone, is_enabled \
             FROM workflow_schedules WHERE id = $1 AND user_id = $2 FOR UPDATE",
        )
        .bind(schedule_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?
        else {
            return Ok(ScheduleTimingUpdate::NotFound);
        };
        let stored_cron: String = row.try_get("cron_expression")?;
        let stored_timezone: Option<String> = row.try_get("timezone")?;
        let cron = cron_expression.unwrap_or(&stored_cron).to_string();
        let timezone = timezone
            .map(str::to_string)
            .or(stored_timezone.clone())
            .unwrap_or_else(|| "UTC".to_string());
        let Some(next_trigger_at) = next_trigger(&cron, &timezone) else {
            return Ok(ScheduleTimingUpdate::NoNextTrigger);
        };
        sqlx::query(
            "UPDATE workflow_schedules \
             SET cron_expression = $1, timezone = $2, next_trigger_at = $3, updated_at = NOW() \
             WHERE id = $4 AND user_id = $5",
        )
        .bind(&cron)
        .bind(&timezone)
        .bind(next_trigger_at)
        .bind(schedule_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(ScheduleTimingUpdate::Updated(ScheduleTiming {
            workflow_id: row.try_get("workflow_id")?,
            previous_cron_expression: stored_cron,
            previous_timezone: stored_timezone.unwrap_or_else(|| "UTC".to_string()),
            cron_expression: cron,
            timezone,
            is_enabled: row.try_get("is_enabled")?,
            next_trigger_at,
        }))
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
                    id: r.try_get("id")?,
                    cron_expression: r.try_get("cron_expression")?,
                    timezone: r.try_get::<Option<_>, _>("timezone")?,
                    next_trigger_at: r.try_get("next_trigger_at")?,
                    is_enabled: r.try_get("is_enabled")?,
                    workflow_name: r.try_get("workflow_name")?,
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
                id: r.try_get("id")?,
                cron_expression: r.try_get("cron_expression")?,
                timezone: r
                    .try_get::<Option<String>, _>("timezone")?
                    .unwrap_or_else(|| "UTC".to_string()),
                is_enabled: r.try_get::<Option<_>, _>("is_enabled")?.unwrap_or(false),
                last_triggered_at: r.try_get::<Option<_>, _>("last_triggered_at")?,
                next_trigger_at: r.try_get::<Option<_>, _>("next_trigger_at")?,
                workflow_id: r.try_get("workflow_id")?,
                workflow_name: r.try_get("workflow_name")?,
            })
        })
        .transpose()
    }
}
