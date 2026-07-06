//! Statistics aggregate: execution/schedule/queue stats projections.

use crate::*;

impl WorkflowRepository {
    // ── Execution statistics ───────────────────────────────────────────────

    /// Per-workflow execution stats for ALL of a user's workflows over the
    /// past `days` days (workflows with ≥1 execution in the window, worst
    /// failures first, capped at 50). Takes the caller's connection: the
    /// GraphQL `getAllWorkflowStats` query runs this on a
    /// `begin_user_scoped` tx so the workflows + workflow_executions RLS
    /// policies backstop the user-only read (RFC 0005 S3). Do NOT route
    /// through `self.db_pool`; that would silently drop the RLS backstop.
    pub async fn get_all_workflow_stats_scoped(
        &self,
        conn: &mut sqlx::PgConnection,
        user_id: Uuid,
        days: i32,
    ) -> Result<Vec<AllWorkflowStatsRow>> {
        let rows = sqlx::query_as::<_, AllWorkflowStatsRow>(
            r#"
            SELECT w.id, w.name,
                COUNT(*)::bigint AS total,
                COUNT(*) FILTER (WHERE we.status = 'completed')::bigint AS succeeded,
                COUNT(*) FILTER (WHERE we.status = 'failed')::bigint AS failed,
                (AVG(EXTRACT(EPOCH FROM (we.completed_at - we.started_at))) FILTER (WHERE we.completed_at IS NOT NULL))::float8 AS avg_duration_secs
            FROM workflows w
            LEFT JOIN workflow_executions we ON we.workflow_id = w.id AND we.started_at > NOW() - make_interval(days => $2::int)
            WHERE w.user_id = $1
            GROUP BY w.id, w.name
            HAVING COUNT(we.id) > 0
            ORDER BY COUNT(*) FILTER (WHERE we.status = 'failed') DESC, COUNT(*) DESC
            LIMIT 50
            "#,
        )
        .bind(user_id)
        .bind(days)
        .fetch_all(conn)
        .await?;
        Ok(rows)
    }

    /// Fetch aggregated execution stats for a workflow over the past N days.
    pub async fn get_workflow_execution_stats(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        days: i32,
    ) -> Result<WorkflowExecStats> {
        // avg_duration_secs is filtered to status='completed' so phantom-
        // duration outliers don't distort it. Stale-cleanup failures
        // (auto-marked failed after the timeout threshold) carry a
        // ~1h `completed_at - started_at`; a single one of these in a
        // 13-execution window pulled daily-brief's reported avg from
        // ~20s to ~300s in production. Keeping the average tied to
        // successful runs makes it usable for capacity planning;
        // operators who want failure-cost data should look at the
        // failed-execution log.
        let row = sqlx::query(
            "SELECT \
                COUNT(*)::bigint AS total, \
                COUNT(*) FILTER (WHERE status = 'completed')::bigint AS succeeded, \
                COUNT(*) FILTER (WHERE status = 'failed')::bigint AS failed, \
                COUNT(*) FILTER (WHERE status = 'running')::bigint AS running, \
                (AVG(EXTRACT(EPOCH FROM (completed_at - started_at))) \
                    FILTER (WHERE completed_at IS NOT NULL AND status = 'completed'))::float8 AS avg_duration_secs \
             FROM workflow_executions \
             WHERE workflow_id = $1 AND user_id = $2 \
               AND started_at > NOW() - make_interval(days => $3::int)",
        )
        .bind(workflow_id)
        .bind(user_id)
        .bind(days)
        .fetch_one(&self.db_pool)
        .await?;

        Ok(WorkflowExecStats {
            total: row.try_get::<Option<_>, _>("total")?.unwrap_or(0),
            succeeded: row.try_get::<Option<_>, _>("succeeded")?.unwrap_or(0),
            failed: row.try_get::<Option<_>, _>("failed")?.unwrap_or(0),
            running: row.try_get::<Option<_>, _>("running")?.unwrap_or(0),
            avg_duration_secs: row.try_get::<Option<_>, _>("avg_duration_secs")?,
        })
    }

    /// Batch sibling to [`get_workflow_execution_stats`]. Single
    /// `WHERE workflow_id = ANY($1) AND user_id = $2 GROUP BY workflow_id`
    /// query replaces the per-id loop used by the workflow-health handler
    /// when reporting on sub-workflow stats.
    ///
    /// Workflows with zero executions in the window simply don't appear
    /// in the result map — callers should `.get(id).copied()
    /// .unwrap_or_default()` (the empty stats shape). Empty input
    /// short-circuits without touching the DB.
    ///
    /// Security: same `AND user_id = $2` scoping as the per-id method.
    pub async fn get_workflow_execution_stats_for_ids(
        &self,
        workflow_ids: &[Uuid],
        user_id: Uuid,
        days: i32,
    ) -> Result<std::collections::HashMap<Uuid, WorkflowExecStats>> {
        if workflow_ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        // See `get_workflow_execution_stats` for the rationale on the
        // status='completed' AVG filter — same intent here.
        let rows = sqlx::query(
            "SELECT workflow_id, \
                    COUNT(*)::bigint AS total, \
                    COUNT(*) FILTER (WHERE status = 'completed')::bigint AS succeeded, \
                    COUNT(*) FILTER (WHERE status = 'failed')::bigint AS failed, \
                    COUNT(*) FILTER (WHERE status = 'running')::bigint AS running, \
                    (AVG(EXTRACT(EPOCH FROM (completed_at - started_at))) \
                        FILTER (WHERE completed_at IS NOT NULL AND status = 'completed'))::float8 AS avg_duration_secs \
             FROM workflow_executions \
             WHERE workflow_id = ANY($1) AND user_id = $2 \
               AND started_at > NOW() - make_interval(days => $3::int) \
             GROUP BY workflow_id",
        )
        .bind(workflow_ids)
        .bind(user_id)
        .bind(days)
        .fetch_all(&self.db_pool)
        .await?;
        rows.into_iter()
            .map(|row| -> Result<(Uuid, WorkflowExecStats)> {
                let id: Uuid = row
                    .try_get::<Option<_>, _>("workflow_id")?
                    .unwrap_or_default();
                let stats = WorkflowExecStats {
                    total: row.try_get::<Option<_>, _>("total")?.unwrap_or(0),
                    succeeded: row.try_get::<Option<_>, _>("succeeded")?.unwrap_or(0),
                    failed: row.try_get::<Option<_>, _>("failed")?.unwrap_or(0),
                    running: row.try_get::<Option<_>, _>("running")?.unwrap_or(0),
                    avg_duration_secs: row.try_get::<Option<_>, _>("avg_duration_secs")?,
                };
                Ok((id, stats))
            })
            .collect()
    }

    /// Count active schedules for a workflow.
    pub async fn get_workflow_schedule_count(&self, workflow_id: Uuid) -> Result<i64> {
        // The `workflow_schedules` table column is `is_enabled` (per
        // migration 20260309000200), NOT `is_active`. Pre-fix this
        // query referenced the non-existent column; handler
        // `unwrap_or(0)` swallowed the column-not-found error and
        // `get_workflow_summary` reported `active_schedules: 0` for
        // every workflow, including ones with active schedules. Same
        // class as the get_schedule_health zeros bug — discovered via
        // MCP probe 2026-05-06 (daily-brief shows is_enabled=true in
        // list_schedules but active_schedules=0 in summary).
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM workflow_schedules \
             WHERE workflow_id = $1 AND is_enabled = true",
        )
        .bind(workflow_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(count)
    }

    /// Count active webhook triggers for a set of module IDs owned by a user.
    pub async fn get_workflow_webhook_count(
        &self,
        module_ids: &[Uuid],
        user_id: Uuid,
    ) -> Result<i64> {
        if module_ids.is_empty() {
            return Ok(0);
        }
        // webhook_triggers column is `enabled` (initial schema +
        // never renamed). Same column-drift class as
        // get_workflow_schedule_count — pre-fix this query
        // referenced `is_active`, errored at runtime, and the
        // caller's unwrap_or(0) silently reported "0 active webhooks"
        // in get_workflow_summary.
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM webhook_triggers \
             WHERE module_id = ANY($1) AND enabled = true AND user_id = $2",
        )
        .bind(module_ids)
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(count)
    }

    // ── schedules.rs MCP-handler support ───────────────────────────────────

    /// 24-hour execution stats for a single workflow — total / succeeded /
    /// failed counts plus the last successful and last failed `started_at`.
    /// Used by `get_schedule_health`. Distinct from
    /// `get_workflow_queue_stats_24h` (which is user-scoped + queued/cancelled
    /// counts); this variant is workflow-only and tracks first-success /
    /// first-failure timestamps.
    pub async fn get_workflow_24h_execution_stats(
        &self,
        workflow_id: Uuid,
    ) -> Result<WorkflowHealthStats> {
        let row = sqlx::query(
            "SELECT \
                COUNT(*)::bigint AS total, \
                COUNT(*) FILTER (WHERE status = 'completed')::bigint AS succeeded, \
                COUNT(*) FILTER (WHERE status = 'failed')::bigint AS failed, \
                MAX(CASE WHEN status = 'completed' THEN started_at END) AS last_success_at, \
                MAX(CASE WHEN status = 'failed' THEN started_at END) AS last_failure_at \
             FROM workflow_executions \
             WHERE workflow_id = $1 AND started_at > NOW() - interval '24 hours'",
        )
        .bind(workflow_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(WorkflowHealthStats {
            total: row.try_get::<Option<_>, _>("total")?.unwrap_or(0),
            succeeded: row.try_get::<Option<_>, _>("succeeded")?.unwrap_or(0),
            failed: row.try_get::<Option<_>, _>("failed")?.unwrap_or(0),
            last_success_at: row.try_get::<Option<_>, _>("last_success_at")?,
            last_failure_at: row.try_get::<Option<_>, _>("last_failure_at")?,
        })
    }

    /// Like [`get_workflow_24h_execution_stats`] but filters to
    /// runs triggered by the scheduler. Used by `get_schedule_health`
    /// so manual `test_workflow` / `trigger_workflow` / webhook /
    /// approval-continuation runs don't pollute the schedule's
    /// success-rate and streak numbers.
    ///
    /// `workflow_executions` does NOT have a top-level `trigger_type`
    /// column (only `node_executions` does, per migration `012_node_executions.sql`).
    /// trigger_type lives in the `provenance` JSONB column —
    /// `provenance->>'trigger_type'` is the canonical projection,
    /// matching `ExecutionRepository::get_execution_base` line 1608.
    /// Pre-fix this query referenced the non-existent top-level
    /// column, errored at runtime, and the handler's `unwrap_or`
    /// returned zeros for every scheduled workflow.
    pub async fn get_scheduled_24h_execution_stats(
        &self,
        workflow_id: Uuid,
    ) -> Result<WorkflowHealthStats> {
        let row = sqlx::query(
            "SELECT \
                COUNT(*)::bigint AS total, \
                COUNT(*) FILTER (WHERE status = 'completed')::bigint AS succeeded, \
                COUNT(*) FILTER (WHERE status = 'failed')::bigint AS failed, \
                MAX(CASE WHEN status = 'completed' THEN started_at END) AS last_success_at, \
                MAX(CASE WHEN status = 'failed' THEN started_at END) AS last_failure_at \
             FROM workflow_executions \
             WHERE workflow_id = $1 \
               AND provenance->>'trigger_type' = 'scheduled' \
               AND started_at > NOW() - interval '24 hours'",
        )
        .bind(workflow_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(WorkflowHealthStats {
            total: row.try_get::<Option<_>, _>("total")?.unwrap_or(0),
            succeeded: row.try_get::<Option<_>, _>("succeeded")?.unwrap_or(0),
            failed: row.try_get::<Option<_>, _>("failed")?.unwrap_or(0),
            last_success_at: row.try_get::<Option<_>, _>("last_success_at")?,
            last_failure_at: row.try_get::<Option<_>, _>("last_failure_at")?,
        })
    }

    /// Recent execution statuses for a workflow (newest first), used by
    /// `get_schedule_health` to compute streak length and last-success-ago.
    pub async fn list_recent_workflow_execution_statuses(
        &self,
        workflow_id: Uuid,
        limit: i64,
    ) -> Result<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT status FROM workflow_executions \
             WHERE workflow_id = $1 ORDER BY started_at DESC LIMIT $2",
        )
        .bind(workflow_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows.into_iter().map(|(s,)| s).collect())
    }

    /// Schedule-scoped variant of
    /// [`list_recent_workflow_execution_statuses`]. Filters to
    /// scheduler-fired runs via `provenance->>'trigger_type'` so
    /// streak + last-success-ago reflect scheduled runs only. See
    /// the doc comment on `get_scheduled_24h_execution_stats` for
    /// why `provenance->>` rather than a top-level column.
    pub async fn list_recent_scheduled_execution_statuses(
        &self,
        workflow_id: Uuid,
        limit: i64,
    ) -> Result<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT status FROM workflow_executions \
             WHERE workflow_id = $1 AND provenance->>'trigger_type' = 'scheduled' \
             ORDER BY started_at DESC LIMIT $2",
        )
        .bind(workflow_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows.into_iter().map(|(s,)| s).collect())
    }

    /// Aggregated 24h queue stats for a workflow. Used by `get_queue_status`.
    pub async fn get_workflow_queue_stats_24h(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<WorkflowQueueStats> {
        let row = sqlx::query(
            "SELECT \
                COUNT(*) FILTER (WHERE status = 'queued')::bigint AS queued, \
                COUNT(*) FILTER (WHERE status = 'running')::bigint AS running, \
                COUNT(*) FILTER (WHERE status = 'completed')::bigint AS completed, \
                COUNT(*) FILTER (WHERE status = 'failed')::bigint AS failed, \
                COUNT(*) FILTER (WHERE status = 'cancelled')::bigint AS cancelled, \
                COUNT(*)::bigint AS total, \
                MIN(started_at) AS first_started, \
                MAX(completed_at) AS last_completed \
             FROM workflow_executions \
             WHERE workflow_id = $1 AND user_id = $2 AND started_at > NOW() - interval '24 hours'",
        )
        .bind(workflow_id)
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(WorkflowQueueStats {
            queued: row.get("queued"),
            running: row.get("running"),
            completed: row.get("completed"),
            failed: row.get("failed"),
            cancelled: row.get("cancelled"),
            total: row.get("total"),
            first_started: row.try_get::<Option<_>, _>("first_started")?,
            last_completed: row.try_get::<Option<_>, _>("last_completed")?,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Additional Row DTOs
// ─────────────────────────────────────────────────────────────────────────────

/// Per-workflow stats row returned by `get_all_workflow_stats_scoped`.
#[derive(Debug, sqlx::FromRow)]
pub struct AllWorkflowStatsRow {
    pub id: Uuid,
    pub name: String,
    pub total: i64,
    pub succeeded: i64,
    pub failed: i64,
    pub avg_duration_secs: Option<f64>,
}

#[derive(Debug)]
pub struct WorkflowExecStats {
    pub total: i64,
    pub succeeded: i64,
    pub failed: i64,
    pub running: i64,
    /// Average wall-clock duration of *successful* runs only — the
    /// underlying SQL filters on `status = 'completed'` so phantom
    /// durations from stale-cleanup failures don't distort capacity-
    /// planning consumers. `None` when no completed runs exist in the
    /// window.
    pub avg_duration_secs: Option<f64>,
}

impl WorkflowExecStats {
    /// Empty stats — handlers use this as the fall-back when the
    /// underlying query fails. Pulled into a constructor so the same
    /// `unwrap_or(...)` literal isn't pasted at every call site (the
    /// previous shape had this exact `{total:0, succeeded:0, ...}` block
    /// duplicated in `get_workflow_health` parent + child branches).
    pub fn empty() -> Self {
        Self {
            total: 0,
            succeeded: 0,
            failed: 0,
            running: 0,
            avg_duration_secs: None,
        }
    }

    /// Compute success rate as a percentage 0.0–100.0; zero if no runs.
    pub fn success_rate_percent(&self) -> f64 {
        if self.total > 0 {
            (self.succeeded as f64 / self.total as f64) * 100.0
        } else {
            0.0
        }
    }

    /// Project to the canonical JSON shape used by `get_workflow_health`
    /// (parent + sub-workflow entries) and `get_workflow_summary`.
    /// Caller supplies `period_days` so the same struct can be projected
    /// against different windows.
    ///
    /// MCP-19 (2026-05-07): success_rate_percent now emits a JSON number
    /// rounded to 1 decimal place. Pre-fix this projection used
    /// `format!("{:.1}", ...)`, while talos-analytics-repository's
    /// `format_percent` helper emits numbers — `get_workflow_health`
    /// kept emitting strings even after the round-4 fix because the
    /// projection lives here, not in the handler. Inlined the rounding
    /// (rather than adding a workspace dep on talos-analytics-repository
    /// for one tiny helper).
    pub fn to_json(&self, period_days: i32) -> serde_json::Value {
        let raw = self.success_rate_percent();
        let success_rate_percent = if raw.is_finite() {
            (raw * 10.0).round() / 10.0
        } else {
            0.0
        };
        // MCP-30 (2026-05-07): cap avg_duration_secs at 2 decimals.
        // Pre-fix the projection emitted the raw f64 from the SQL
        // EXTRACT(EPOCH FROM ...) which gave 6+ digits of precision —
        // operator-readable durations don't need sub-millisecond
        // precision. 2dp matches the existing `compute_units` /
        // `avg_node_time_ms` precision in get_execution_cost.
        let avg_duration_secs = self.avg_duration_secs.map(|v| {
            if v.is_finite() {
                (v * 100.0).round() / 100.0
            } else {
                0.0
            }
        });
        serde_json::json!({
            "period_days": period_days,
            "total_executions": self.total,
            "succeeded": self.succeeded,
            "failed": self.failed,
            "running": self.running,
            "success_rate_percent": success_rate_percent,
            "avg_duration_secs": avg_duration_secs,
        })
    }
}

/// 24h workflow execution stats for `get_schedule_health`.
#[derive(Debug)]
pub struct WorkflowHealthStats {
    pub total: i64,
    pub succeeded: i64,
    pub failed: i64,
    pub last_success_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_failure_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// 24-hour queue stats projection returned by `get_workflow_queue_stats_24h`.
#[derive(Debug)]
pub struct WorkflowQueueStats {
    pub queued: i64,
    pub running: i64,
    pub completed: i64,
    pub failed: i64,
    pub cancelled: i64,
    pub total: i64,
    pub first_started: Option<chrono::DateTime<chrono::Utc>>,
    pub last_completed: Option<chrono::DateTime<chrono::Utc>>,
}
