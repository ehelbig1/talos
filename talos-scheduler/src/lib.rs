use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::sync::Arc;
use talos_workflow_engine_core::WorkerSharedKey;
use uuid::Uuid;

use talos_engine::checkpoint_store::{load_checkpoint_for_full, ControllerCheckpointStore};
use talos_engine::events::{ExecutionEvent, ExecutionStatus};
use talos_module_executions::ModuleExecutionService;
use talos_registry::ModuleRegistry;
use talos_secrets_manager::SecretsManager;
use talos_worker_fleet::WorkerManager;

/// A scheduled trigger for a workflow, backed by a cron expression.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct WorkflowSchedule {
    pub id: Uuid,
    pub workflow_id: Uuid,
    pub user_id: Uuid,
    pub cron_expression: String,
    pub timezone: String,
    pub is_enabled: bool,
    pub last_triggered_at: Option<DateTime<Utc>>,
    pub next_trigger_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A workflow's schedule, gated on schedule ownership OR the parent
/// workflow's org access. Takes the caller's connection: the GraphQL
/// `workflowSchedule` query runs this on a `begin_tenant_read_scoped` tx
/// so the workflows RLS policy backstops the JOIN (workflow_schedules
/// has no policy of its own — RFC 0005 S3). Do NOT add a bare-pool
/// variant for that path.
pub async fn get_schedule_for_accessor_on_conn(
    conn: &mut sqlx::PgConnection,
    workflow_id: Uuid,
    user_id: Uuid,
    accessible_org_ids: &[Uuid],
) -> anyhow::Result<Option<WorkflowSchedule>> {
    let row = sqlx::query_as::<_, WorkflowSchedule>(
        r#"
        SELECT ws.id, ws.workflow_id, ws.user_id, ws.cron_expression, ws.timezone, ws.is_enabled,
               ws.last_triggered_at, ws.next_trigger_at, ws.created_at, ws.updated_at
        FROM workflow_schedules ws
        LEFT JOIN workflows w ON w.id = ws.workflow_id
        WHERE ws.workflow_id = $1 AND (ws.user_id = $2 OR w.org_id = ANY($3))
        "#,
    )
    .bind(workflow_id)
    .bind(user_id)
    .bind(accessible_org_ids)
    .fetch_optional(conn)
    .await?;
    Ok(row)
}

/// A user's own schedules, newest first with a unique `id DESC`
/// tiebreaker, paginated. Bare-pool read (strictly `user_id`-filtered;
/// backs the GraphQL `mySchedules` query).
pub async fn list_schedules_for_user(
    pool: &PgPool,
    user_id: Uuid,
    limit: i64,
    offset: i64,
) -> anyhow::Result<Vec<WorkflowSchedule>> {
    let rows = sqlx::query_as::<_, WorkflowSchedule>(
        r#"
        SELECT id, workflow_id, user_id, cron_expression, timezone, is_enabled,
               last_triggered_at, next_trigger_at, created_at, updated_at
        FROM workflow_schedules
        WHERE user_id = $1
        ORDER BY created_at DESC, id DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(user_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Upsert a workflow's schedule (INSERT or re-enable + rewrite on the
/// `workflow_id` UNIQUE conflict), returning the stored row. Takes the
/// caller's connection: the GraphQL `createSchedule` mutation runs the
/// workflow-access check and this upsert in ONE request-scoped
/// UnitOfWork (RFC 0005 S3). Do NOT add a bare-pool variant for that
/// path.
pub async fn upsert_schedule_on_conn(
    conn: &mut sqlx::PgConnection,
    workflow_id: Uuid,
    user_id: Uuid,
    cron_expression: &str,
    timezone: &str,
    next_trigger_at: DateTime<Utc>,
) -> anyhow::Result<WorkflowSchedule> {
    let row = sqlx::query_as::<_, WorkflowSchedule>(
        r#"
        INSERT INTO workflow_schedules (workflow_id, user_id, cron_expression, timezone, next_trigger_at)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (workflow_id) DO UPDATE SET
            cron_expression = EXCLUDED.cron_expression,
            timezone = EXCLUDED.timezone,
            next_trigger_at = EXCLUDED.next_trigger_at,
            is_enabled = true,
            updated_at = NOW()
        RETURNING id, workflow_id, user_id, cron_expression, timezone, is_enabled,
                  last_triggered_at, next_trigger_at, created_at, updated_at
        "#,
    )
    .bind(workflow_id)
    .bind(user_id)
    .bind(cron_expression)
    .bind(timezone)
    .bind(next_trigger_at)
    .fetch_one(conn)
    .await?;
    Ok(row)
}

/// Accessor-gated schedule read with a `FOR UPDATE OF ws` row lock so
/// the caller's read→merge→update is serialized against concurrent
/// updaters (lost-update window). Takes the caller's connection — the
/// lock only means anything inside the caller's transaction.
pub async fn get_schedule_for_update_on_conn(
    conn: &mut sqlx::PgConnection,
    workflow_id: Uuid,
    user_id: Uuid,
    accessible_org_ids: &[Uuid],
) -> anyhow::Result<Option<WorkflowSchedule>> {
    let row = sqlx::query_as::<_, WorkflowSchedule>(
        r#"
        SELECT ws.id, ws.workflow_id, ws.user_id, ws.cron_expression, ws.timezone, ws.is_enabled,
               ws.last_triggered_at, ws.next_trigger_at, ws.created_at, ws.updated_at
        FROM workflow_schedules ws
        LEFT JOIN workflows w ON w.id = ws.workflow_id
        WHERE ws.workflow_id = $1 AND (ws.user_id = $2 OR w.org_id = ANY($3))
        FOR UPDATE OF ws
        "#,
    )
    .bind(workflow_id)
    .bind(user_id)
    .bind(accessible_org_ids)
    .fetch_optional(conn)
    .await?;
    Ok(row)
}

/// Accessor-gated schedule rewrite (merged fields pre-computed by the
/// caller under the `get_schedule_for_update_on_conn` row lock),
/// returning the stored row. Takes the caller's connection — same
/// UnitOfWork as the locked read.
#[allow(clippy::too_many_arguments)]
pub async fn update_schedule_on_conn(
    conn: &mut sqlx::PgConnection,
    workflow_id: Uuid,
    user_id: Uuid,
    accessible_org_ids: &[Uuid],
    cron_expression: &str,
    timezone: &str,
    is_enabled: bool,
    next_trigger_at: Option<DateTime<Utc>>,
) -> anyhow::Result<WorkflowSchedule> {
    let row = sqlx::query_as::<_, WorkflowSchedule>(
        r#"
        UPDATE workflow_schedules ws
        SET cron_expression = $3,
            timezone = $4,
            is_enabled = $5,
            next_trigger_at = $6,
            updated_at = NOW()
        FROM workflows w
        WHERE ws.workflow_id = $1
          AND w.id = ws.workflow_id
          AND (ws.user_id = $2 OR w.org_id = ANY($7))
        RETURNING ws.id, ws.workflow_id, ws.user_id, ws.cron_expression, ws.timezone, ws.is_enabled,
                  ws.last_triggered_at, ws.next_trigger_at, ws.created_at, ws.updated_at
        "#,
    )
    .bind(workflow_id)
    .bind(user_id)
    .bind(cron_expression)
    .bind(timezone)
    .bind(is_enabled)
    .bind(next_trigger_at)
    .bind(accessible_org_ids)
    .fetch_one(conn)
    .await?;
    Ok(row)
}

/// Accessor-gated schedule delete. Takes the caller's connection (the
/// GraphQL `deleteSchedule` mutation shares one UnitOfWork with its
/// workflow-access check). Returns rows affected.
pub async fn delete_schedule_on_conn(
    conn: &mut sqlx::PgConnection,
    workflow_id: Uuid,
    user_id: Uuid,
    accessible_org_ids: &[Uuid],
) -> anyhow::Result<u64> {
    let result = sqlx::query(
        r#"
        DELETE FROM workflow_schedules ws
        USING workflows w
        WHERE ws.workflow_id = $1
          AND w.id = ws.workflow_id
          AND (ws.user_id = $2 OR w.org_id = ANY($3))
        "#,
    )
    .bind(workflow_id)
    .bind(user_id)
    .bind(accessible_org_ids)
    .execute(conn)
    .await?;
    Ok(result.rows_affected())
}

/// Calculate the next trigger time for a cron expression in the given timezone.
///
/// Returns `None` if the cron expression is invalid or no future occurrence can
/// be computed.
pub fn calculate_next_trigger(
    cron_expression: &str,
    timezone: &str,
) -> Result<DateTime<Utc>, String> {
    // MCP-959 (2026-05-15): delegate to the capped + reflection-
    // scrubbed timezone validator so this sibling-of-`validate_timezone`
    // entry point shares the same length cap and never echoes the
    // rejected value into the error message.
    let tz = parse_validated_timezone(timezone)?;

    // MCP-1020 (2026-05-15): delegate cron parse through the
    // length-capped + reflection-scrubbed helper, sibling pattern to
    // `parse_validated_timezone`.
    let cron = parse_validated_cron(cron_expression)?;

    let now_utc = Utc::now();
    let now_tz = now_utc.with_timezone(&tz);

    let next = cron
        .find_next_occurrence(&now_tz, false)
        .map_err(|e| format!("Failed to calculate next occurrence: {}", e))?;

    Ok(next.with_timezone(&Utc))
}

/// Validate that a cron expression is parseable.
pub fn validate_cron(cron_expression: &str) -> Result<(), String> {
    // MCP-1020 (2026-05-15): share the capped + scrubbed parse path so
    // future callers that bypass the boundary length cap still get the
    // defense-in-depth treatment. Same pattern as MCP-958/959 for
    // timezone validation.
    parse_validated_cron(cron_expression).map(|_| ())
}

/// Calculate the next `n` trigger occurrences in UTC. Useful for surfacing a
/// concrete preview of the schedule to the user (cron expressions like
/// `0 9 * * 1-5` are opaque to most readers; `Mon Apr 21 09:00 UTC, ...` is not).
///
/// Returns up to `n` occurrences. Stops early on iteration error rather than
/// returning a partial-then-failed Result, since this is a best-effort preview.
pub fn calculate_next_n_triggers(
    cron_expression: &str,
    timezone: &str,
    n: usize,
) -> Result<Vec<DateTime<Utc>>, String> {
    if n == 0 {
        return Ok(Vec::new());
    }
    // MCP-959 (2026-05-15): same delegation as `calculate_next_trigger`.
    let tz = parse_validated_timezone(timezone)?;
    // MCP-1020 (2026-05-15): sibling cron-parse helper.
    let cron = parse_validated_cron(cron_expression)?;

    let mut out = Vec::with_capacity(n);
    let mut cursor = Utc::now().with_timezone(&tz);
    for _ in 0..n {
        match cron.find_next_occurrence(&cursor, false) {
            Ok(next) => {
                out.push(next.with_timezone(&Utc));
                cursor = next;
            }
            Err(_) => break,
        }
    }
    Ok(out)
}

/// Validate that a cron expression fires no more frequently than `min_secs` apart.
///
/// Computes two consecutive occurrences from now and checks the gap.
/// Returns an error if the interval is shorter than `min_secs`.
pub fn validate_cron_min_interval(cron_expression: &str, min_secs: u64) -> Result<(), String> {
    // MCP-1020 (2026-05-15): sibling cron-parse helper.
    let cron = parse_validated_cron(cron_expression)?;

    let now = Utc::now();
    let next1 = cron
        .find_next_occurrence(&now, false)
        .map_err(|e| format!("Failed to calculate next occurrence: {}", e))?;
    let next2 = cron
        .find_next_occurrence(&next1, false)
        .map_err(|e| format!("Failed to calculate second occurrence: {}", e))?;

    let interval_secs = (next2 - next1).num_seconds();
    if interval_secs < min_secs as i64 {
        return Err(format!(
            "Schedule interval is too frequent ({} seconds). Minimum allowed interval is {} seconds.",
            interval_secs, min_secs
        ));
    }
    Ok(())
}

/// Validate that a timezone string is a valid IANA timezone.
///
/// MCP-958 (2026-05-15): cap caller-supplied length at 64 chars and
/// scrub the rejected value out of the error message. Pre-fix:
/// (1) `chrono_tz::Tz`'s `FromStr` impl walks ~600 IANA entries with
///     a memcmp per candidate; the early-exit on first-byte mismatch
///     keeps that bounded in practice, but there was no upstream
///     length cap so a multi-MB timezone string flowed through every
///     caller (MCP schedules.rs `validate_optional_string` and the
///     GraphQL `create_schedule` / `update_schedule` mutations both
///     forwarded raw caller input). MCP-414 / MCP-844 capped
///     `cron_expression` at 256 chars at the boundary for exactly
///     this DoS-by-unbounded-input class; this is the missing
///     timezone sibling.
/// (2) The error message echoed the rejected `timezone` value into
///     `format!("Invalid timezone: {}", timezone)`. An attacker could
///     reflect arbitrary content (up to the body cap) back through
///     the error response and the structured log — same reflection
///     class as the MCP-852/853/854 secrets-in-debug-print sweep,
///     just at the user-facing error surface. Now the error names
///     only the byte length, not the content.
///
/// 64 chars covers every IANA timezone identifier (longest legitimate
/// entry is `America/Argentina/ComodRivadavia` at 32 chars).
///
/// MCP-959 (2026-05-15): extracted the parse-or-reject body into
/// `parse_validated_timezone` so `calculate_next_trigger` and
/// `calculate_next_n_triggers` can share the same length cap +
/// scrubbed error path (both previously called `timezone.parse()`
/// directly with the un-scrubbed echo).
pub fn validate_timezone(timezone: &str) -> Result<(), String> {
    parse_validated_timezone(timezone).map(|_| ())
}

/// Length-cap + parse helper shared by `validate_timezone` and the
/// scheduler `calculate_next_*` helpers. Keeps the 64-char cap and
/// the reflection-scrub in a single place.
fn parse_validated_timezone(timezone: &str) -> Result<chrono_tz::Tz, String> {
    const MAX_TIMEZONE_LEN: usize = 64;
    if timezone.len() > MAX_TIMEZONE_LEN {
        return Err(format!(
            "Invalid timezone: input length {} exceeds {} char cap; \
             use an IANA timezone identifier like 'UTC' or 'America/New_York'",
            timezone.len(),
            MAX_TIMEZONE_LEN
        ));
    }
    timezone
        .parse::<chrono_tz::Tz>()
        .map_err(|_| format!("Invalid timezone: {}", timezone))
}

/// MCP-1020 (2026-05-15): length-cap + parse helper for cron
/// expressions, sibling to `parse_validated_timezone`. Pre-fix all four
/// public entry points (`validate_cron`, `validate_cron_min_interval`,
/// `calculate_next_trigger`, `calculate_next_n_triggers`) called
/// `croner::Cron::new(cron).parse()` directly. The four current callers
/// (talos-api create_schedule/update_schedule capping at 256, talos-mcp-
/// handlers schedules.rs / advanced.rs deploy_workflow / promote_workflow
/// capping at 200) all cap at the boundary, but the validator should
/// defend itself — any NEW caller that forgets the boundary cap would
/// flow multi-MB strings into the croner parser AND into a reflection-
/// shaped error message (`format!("Invalid cron expression: {}", e)`
/// where `e` may echo offending input). Same exact pattern MCP-958/959
/// closed for timezone validation. 256-char cap matches the canonical
/// GraphQL surface upper bound; longest legitimate cron is ~50 chars
/// (full vixie-cron 6-field with named day-of-week + months) so the
/// cap is operator-comfortable. Error message names byte length only
/// when cap is hit so the rejected value doesn't reflect through.
fn parse_validated_cron(cron_expression: &str) -> Result<croner::Cron, String> {
    const MAX_CRON_LEN: usize = 256;
    if cron_expression.len() > MAX_CRON_LEN {
        return Err(format!(
            "Invalid cron expression: input length {} exceeds {} char cap",
            cron_expression.len(),
            MAX_CRON_LEN
        ));
    }
    croner::Cron::new(cron_expression)
        .parse()
        .map_err(|e| format!("Invalid cron expression: {}", e))
}

/// Background service that polls for due schedules and triggers workflow
/// executions.
pub struct SchedulerService {
    db_pool: PgPool,
    event_sender: tokio::sync::broadcast::Sender<ExecutionEvent>,
    registry: Arc<ModuleRegistry>,
    secrets_manager: Arc<SecretsManager>,
    worker_manager: Arc<WorkerManager>,
    module_execution_service: Arc<ModuleExecutionService>,
    worker_shared_key: Option<WorkerSharedKey>,
    nats_client: Arc<async_nats::Client>,
    /// M6 (2026-05-28 review): bounds the number of scheduled executions
    /// running concurrently. After controller downtime or a clock catch-up a
    /// large batch of schedules comes due at once; pre-fix each was
    /// `tokio::spawn`ed with no ceiling, so the whole backlog thundered the
    /// engine / worker fleet / NATS simultaneously. Each spawned task now
    /// acquires a permit before running, so the backlog drains at a controlled
    /// rate. Sized from `SCHEDULER_MAX_CONCURRENT_EXECUTIONS` (default
    /// [`DEFAULT_SCHEDULER_MAX_CONCURRENT_EXECUTIONS`]).
    spawn_semaphore: Arc<tokio::sync::Semaphore>,
}

/// Default ceiling on concurrently-running scheduled executions (see
/// [`SchedulerService::spawn_semaphore`]). Override via
/// `SCHEDULER_MAX_CONCURRENT_EXECUTIONS`.
pub const DEFAULT_SCHEDULER_MAX_CONCURRENT_EXECUTIONS: usize = 16;

impl SchedulerService {
    pub fn new(
        db_pool: PgPool,
        event_sender: tokio::sync::broadcast::Sender<ExecutionEvent>,
        registry: Arc<ModuleRegistry>,
        secrets_manager: Arc<SecretsManager>,
        worker_manager: Arc<WorkerManager>,
        module_execution_service: Arc<ModuleExecutionService>,
        worker_shared_key: Option<WorkerSharedKey>,
        nats_client: Arc<async_nats::Client>,
    ) -> Self {
        // Resolved here (not a `new` param) so existing call sites are
        // unchanged. `positive_env_or_default` guards the `=0` footgun: a
        // zero-permit semaphore would park every scheduled execution forever.
        let max_concurrent: usize = talos_config::positive_env_or_default(
            "SCHEDULER_MAX_CONCURRENT_EXECUTIONS",
            DEFAULT_SCHEDULER_MAX_CONCURRENT_EXECUTIONS,
        );
        Self {
            db_pool,
            event_sender,
            registry,
            secrets_manager,
            worker_manager,
            module_execution_service,
            worker_shared_key,
            nats_client,
            spawn_semaphore: Arc::new(tokio::sync::Semaphore::new(max_concurrent)),
        }
    }

    /// Start the scheduler loop. This runs indefinitely, polling every 15
    /// seconds for schedules that are due.
    ///
    /// Pass a `tokio::sync::watch::Receiver<bool>` to drive a graceful
    /// shutdown: the loop exits cleanly the first time the watch flips
    /// to `true`. The previous bare-loop form remains available via
    /// [`run`] for callers that don't care about graceful shutdown
    /// (test code, ad-hoc invocations) — production should always use
    /// [`run_with_shutdown`] so the in-flight tick can drain instead
    /// of being aborted with the runtime.
    pub async fn run_with_shutdown(
        self: Arc<Self>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        // One-time backfill: compute next_trigger_at for any enabled schedules
        // that were created before this column was populated (i.e. next_trigger_at IS NULL).
        // Without this they are silently invisible to the scheduler's IS NOT NULL filter.
        self.backfill_null_trigger_times().await;

        let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(e) = self.poll_and_trigger().await {
                        tracing::error!("Scheduler poll error: {}", e);
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("Scheduler loop received shutdown signal");
                        break;
                    }
                }
            }
        }
    }

    /// Compatibility shim — runs forever with no shutdown awareness.
    /// Prefer [`run_with_shutdown`] for production paths.
    pub async fn run(self: Arc<Self>) {
        let (_tx, rx) = tokio::sync::watch::channel::<bool>(false);
        self.run_with_shutdown(rx).await
    }

    /// Compute and write next_trigger_at for all enabled schedules whose value is NULL.
    /// Called once at startup so pre-existing schedules (created before the column was
    /// populated at INSERT time) are picked up by the scheduler loop.
    ///
    /// MCP-516: pre-fix this fetched a single batch of 500 and stopped.
    /// If more than 500 schedules had NULL `next_trigger_at` (legacy data,
    /// migration drift, or a bug-introducing import), the residual rows
    /// stayed silently invisible to the polling loop's `IS NOT NULL`
    /// filter — for the full lifetime of the process. The cap on a
    /// one-time backfill is a hard data-loss bug. Page until the source
    /// is drained; the per-batch `LIMIT` still bounds peak memory.
    async fn backfill_null_trigger_times(&self) {
        #[derive(sqlx::FromRow)]
        struct NullSchedule {
            id: Uuid,
            cron_expression: String,
            timezone: String,
        }

        const BACKFILL_BATCH_SIZE: i64 = 500;
        // Hard outer bound so a row whose UPDATE keeps failing
        // (constraint violation, corrupted cron string) cannot wedge the
        // backfill into an infinite loop — the row reappears in the next
        // batch because next_trigger_at is still NULL. We log the
        // residual count and exit; the polling-loop's IS NOT NULL filter
        // still excludes the bad row, so production is no worse off than
        // the pre-fix single-batch behaviour.
        const BACKFILL_MAX_BATCHES: usize = 50;

        let mut total_processed: u64 = 0;
        for batch_no in 0..BACKFILL_MAX_BATCHES {
            let rows: Vec<NullSchedule> = match sqlx::query_as(
                "SELECT id, cron_expression, timezone \
                 FROM workflow_schedules \
                 WHERE is_enabled = true AND next_trigger_at IS NULL \
                 LIMIT $1",
            )
            .bind(BACKFILL_BATCH_SIZE)
            .fetch_all(&self.db_pool)
            .await
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(
                        batch = batch_no,
                        "Scheduler backfill: failed to fetch null-trigger schedules: {}",
                        e
                    );
                    return;
                }
            };

            if rows.is_empty() {
                if total_processed > 0 {
                    tracing::info!(total = total_processed, "Scheduler backfill: complete");
                }
                return;
            }

            tracing::info!(
                batch = batch_no,
                count = rows.len(),
                "Scheduler backfill: computing next_trigger_at for batch with NULL value"
            );

            let mut updated_in_batch: u64 = 0;
            for row in &rows {
                match calculate_next_trigger(&row.cron_expression, &row.timezone) {
                    Ok(next) => {
                        if let Err(e) = sqlx::query(
                            "UPDATE workflow_schedules SET next_trigger_at = $1, updated_at = NOW() WHERE id = $2",
                        )
                        .bind(next)
                        .bind(row.id)
                        .execute(&self.db_pool)
                        .await
                        {
                            tracing::warn!("Scheduler backfill: failed to update schedule {}: {}", row.id, e);
                        } else {
                            updated_in_batch += 1;
                            tracing::info!("Scheduler backfill: schedule {} next_trigger_at = {}", row.id, next);
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Scheduler backfill: could not compute next trigger for schedule {}: {}",
                            row.id, e
                        );
                    }
                }
            }

            total_processed += updated_in_batch;

            // No forward progress in this batch — every row is either
            // unparseable cron or its UPDATE failed. Looping would
            // re-process the same rows forever. Bail and let the polling
            // loop's filter drop them.
            if updated_in_batch == 0 {
                tracing::warn!(
                    batch = batch_no,
                    residual = rows.len(),
                    "Scheduler backfill: no rows updated in batch — residual NULL-trigger schedules \
                     will remain invisible to the polling loop until repaired"
                );
                return;
            }
        }

        tracing::warn!(
            total = total_processed,
            max_batches = BACKFILL_MAX_BATCHES,
            "Scheduler backfill: hit MAX_BATCHES cap with rows still pending — \
             review workflow_schedules for legacy NULL trigger rows"
        );
    }

    /// Single poll iteration: find due schedules and trigger them.
    async fn poll_and_trigger(&self) -> Result<(), String> {
        // Use a transaction with FOR UPDATE SKIP LOCKED to prevent
        // double-firing in multi-instance deployments.
        let mut tx = self
            .db_pool
            .begin()
            .await
            .map_err(|e| format!("Failed to begin transaction: {}", e))?;

        #[derive(sqlx::FromRow)]
        struct DueSchedule {
            id: Uuid,
            workflow_id: Uuid,
            user_id: Uuid,
            cron_expression: String,
            timezone: String,
        }

        let due_schedules: Vec<DueSchedule> = sqlx::query_as(
            r#"
            SELECT id, workflow_id, user_id, cron_expression, timezone
            FROM workflow_schedules
            WHERE is_enabled = true
              AND next_trigger_at IS NOT NULL
              AND next_trigger_at <= NOW()
            FOR UPDATE SKIP LOCKED
            LIMIT 50
            "#,
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| format!("Failed to fetch due schedules: {}", e))?;

        if due_schedules.is_empty() {
            // Commit the (empty) transaction to release locks.
            tx.commit()
                .await
                .map_err(|e| format!("Failed to commit transaction: {}", e))?;
            return Ok(());
        }

        tracing::info!("Scheduler found {} due schedule(s)", due_schedules.len());

        // MCP-539: defer execution-spawning until AFTER tx.commit() so a
        // commit failure can't leave us in the "tasks fired but
        // last_triggered_at + next_trigger_at rolled back" state.
        // Pre-fix: each schedule's `next_trigger_at` UPDATE landed inside
        // the tx, but `spawn_workflow_execution` was called inline before
        // commit. If commit failed (DB disconnect mid-loop, deadlock,
        // serialization), the UPDATEs rolled back AND the tasks already
        // fired — next poll pass found the same schedules still due (their
        // old `next_trigger_at` was still in the past) and triggered them
        // again. For non-idempotent workflows (notifications, emails) the
        // user sees duplicates on every DB hiccup.
        let mut to_spawn: Vec<(Uuid, Uuid, Uuid)> = Vec::with_capacity(due_schedules.len());

        for schedule in &due_schedules {
            // Calculate next trigger time before releasing the lock.
            let next_trigger = match calculate_next_trigger(
                &schedule.cron_expression,
                &schedule.timezone,
            ) {
                Ok(next) => Some(next),
                Err(e) => {
                    tracing::error!(
                        schedule_id = %schedule.id,
                        "Failed to calculate next trigger: {}. Disabling schedule.",
                        e
                    );
                    // Disable the schedule if we can't compute the next trigger.
                    //
                    // MCP-776 (2026-05-13): log UPDATE failures. Pre-fix
                    // `let _ = sqlx::query(...).await` swallowed DB errors
                    // on the disable path. A schedule with an unparseable
                    // cron would repeatedly appear in `due` (because the
                    // disable never landed), generating endless ERROR
                    // logs from the calculate_next_trigger arm with NO
                    // signal that the disable mutation was also failing.
                    // Same operator-visibility class as MCP-741
                    // (continuation-trigger cleanup swallowing) and
                    // MCP-733..743/745/774/775. WARN with stable
                    // `target: "talos_audit"` so the dual-failure
                    // pattern surfaces to dashboards.
                    if let Err(de) = sqlx::query(
                        "UPDATE workflow_schedules SET is_enabled = false, updated_at = NOW() WHERE id = $1",
                    )
                    .bind(schedule.id)
                    .execute(&mut *tx)
                    .await
                    {
                        tracing::warn!(
                            target: "talos_audit",
                            schedule_id = %schedule.id,
                            cron_error = %e,
                            disable_error = %de,
                            "Scheduler: failed to disable schedule with unparseable cron — schedule will reappear in next poll and re-fire this WARN until the underlying DB issue resolves"
                        );
                    }
                    continue;
                }
            };

            // Update last_triggered_at and next_trigger_at.
            if let Err(e) = sqlx::query(
                r#"
                UPDATE workflow_schedules
                SET last_triggered_at = NOW(),
                    next_trigger_at = $2,
                    updated_at = NOW()
                WHERE id = $1
                "#,
            )
            .bind(schedule.id)
            .bind(next_trigger)
            .execute(&mut *tx)
            .await
            {
                tracing::error!(
                    schedule_id = %schedule.id,
                    "Failed to update schedule timestamps: {}",
                    e
                );
                continue;
            }

            // MCP-539: stage the spawn, fire it only after commit succeeds.
            to_spawn.push((schedule.workflow_id, schedule.user_id, schedule.id));
        }

        tx.commit()
            .await
            .map_err(|e| format!("Failed to commit transaction: {}", e))?;

        // Commit succeeded — now safe to fire the executions. A crash
        // between commit and spawn would lose at most this batch's
        // triggers (no double-fire); the next poll sees them as already
        // "scheduled forward" because the UPDATE committed.
        for (workflow_id, user_id, schedule_id) in to_spawn {
            self.spawn_workflow_execution(workflow_id, user_id, schedule_id);
        }

        Ok(())
    }

    /// Trigger a workflow execution in the background, mirroring the pattern
    /// used by `trigger_workflow` in the GraphQL mutation.
    fn spawn_workflow_execution(&self, workflow_id: Uuid, user_id: Uuid, schedule_id: Uuid) {
        let db_pool = self.db_pool.clone();
        let db_pool_for_timeout = self.db_pool.clone();
        let sender = self.event_sender.clone();
        let registry = self.registry.clone();
        let secrets_manager = self.secrets_manager.clone();
        let worker_manager = self.worker_manager.clone();
        let module_execution_service = self.module_execution_service.clone();
        let worker_shared_key = self.worker_shared_key.clone();
        let nats_client = self.nats_client.clone();
        let spawn_semaphore = self.spawn_semaphore.clone();

        tokio::spawn(async move {
            // M6: bound concurrent scheduled executions. Acquire INSIDE the
            // spawned task (so the spawn itself stays non-blocking) — a
            // post-downtime backlog spawns many cheap parked tasks but only
            // `SCHEDULER_MAX_CONCURRENT_EXECUTIONS` run the execution at once,
            // draining at a controlled rate rather than stampeding the worker
            // fleet. The permit is held for the execution's lifetime and
            // released on drop. `acquire_owned` only errors if the semaphore is
            // closed, which never happens (the Arc lives as long as the
            // service); on the impossible error we skip rather than run
            // unbounded.
            let _permit = match spawn_semaphore.acquire_owned().await {
                Ok(p) => p,
                Err(_) => {
                    tracing::error!("Scheduler spawn semaphore closed — skipping execution");
                    return;
                }
            };
            let execution_id = Uuid::new_v4();

            tracing::info!(
                execution_id = %execution_id,
                workflow_id = %workflow_id,
                schedule_id = %schedule_id,
                "Scheduler triggering workflow execution"
            );

            // Maximum wall-clock time for a single scheduled execution.
            // Configurable via SCHEDULER_EXECUTION_TIMEOUT_SECS (default: 1 hour).
            //
            // MCP-689 (2026-05-13): route through `positive_env_or_default`
            // so `SCHEDULER_EXECUTION_TIMEOUT_SECS=0` doesn't degrade to
            // an immediate-timeout (`tokio::time::timeout(Duration::ZERO, ...)`
            // fires on the first poll). Same `=0` env footgun class as
            // MCP-665 (STALE_EXECUTION_MINUTES=0 → mass execution kill).
            // Pre-fix, an operator typo of `SCHEDULER_EXECUTION_TIMEOUT_SECS=0`
            // would cause every scheduled execution to time out before its
            // first NATS round-trip — the workflow would dispatch, the
            // worker would compute, then the controller-side timeout
            // wedge would orphan-and-fail every job.
            let timeout_secs: u64 =
                talos_config::positive_env_or_default("SCHEDULER_EXECUTION_TIMEOUT_SECS", 3600u64);
            let timeout_duration = std::time::Duration::from_secs(timeout_secs);

            if let Err(_elapsed) = tokio::time::timeout(
                timeout_duration,
                run_scheduled_execution(
                    execution_id,
                    workflow_id,
                    user_id,
                    schedule_id,
                    db_pool,
                    sender,
                    registry,
                    secrets_manager,
                    worker_manager,
                    module_execution_service,
                    worker_shared_key,
                    nats_client,
                ),
            )
            .await
            {
                tracing::error!(
                    execution_id = %execution_id,
                    workflow_id = %workflow_id,
                    schedule_id = %schedule_id,
                    timeout_secs = timeout_secs,
                    "Scheduled workflow execution timed out"
                );
                // MCP-776 (2026-05-13): log failure-marking UPDATE
                // failures. Pre-fix `let _ = ...await` swallowed errors;
                // a DB hiccup at this moment left the workflow_executions
                // row stuck in 'running' forever, indistinguishable from
                // a genuinely-running execution. Operators have NO signal
                // that the timeout was DETECTED but not persisted.
                // Same class as MCP-743 (talos-webhooks). WARN with
                // `target: "talos_audit"` for dashboard alerting.
                if let Err(ue) = sqlx::query(
                    "UPDATE workflow_executions SET status = 'failed', completed_at = NOW(), error_message = $2 WHERE id = $1 AND status NOT IN ('completed', 'failed', 'cancelled', 'resuming')",
                )
                .bind(execution_id)
                .bind(format!("Execution timed out after {} seconds", timeout_secs))
                .execute(&db_pool_for_timeout)
                .await
                {
                    tracing::warn!(
                        target: "talos_audit",
                        execution_id = %execution_id,
                        workflow_id = %workflow_id,
                        error = %ue,
                        "Scheduler: failed to mark timed-out execution as 'failed' — row will stay 'running' indefinitely until the underlying DB issue resolves"
                    );
                }
                // MCP-438: tokio::time::timeout drops the future on elapse, but
                // any in-flight NATS-dispatched module_executions are orphaned
                // — the drop doesn't propagate cancellation to remote workers,
                // so their rows sit in 'running' forever and skew per-actor /
                // per-workflow counts in get_actor_summary, get_workflow_health,
                // etc. The error-path inside run_scheduled_execution already
                // does this cancellation; mirror it here so timeout-path
                // parity holds.
                match sqlx::query(
                    "UPDATE module_executions \
                     SET status = 'cancelled', completed_at = NOW(), \
                         error_message = 'Workflow timed out — parallel sibling cancelled' \
                     WHERE workflow_execution_id = $1 AND status = 'running'",
                )
                .bind(execution_id)
                .execute(&db_pool_for_timeout)
                .await
                {
                    Ok(r) => tracing::info!(
                        execution_id = %execution_id,
                        cancelled = r.rows_affected(),
                        "timeout-path sibling cancellation UPDATE complete"
                    ),
                    Err(e) => tracing::warn!(
                        execution_id = %execution_id,
                        error = %e,
                        "timeout-path sibling cancellation UPDATE failed"
                    ),
                }
            }
        });
    }
}

/// Engine-entrypoint selection for a scheduled run.
///
/// Encodes the contract that prevents the regression class fixed in
/// r245: a fresh scheduled execution MUST drive through the
/// trigger-input path with a defined (non-null) JSON envelope so
/// workflows reading `{{__trigger_input__.X}}` resolve `.X` to `null`
/// rather than blowing up because no synthetic `__trigger__` node was
/// wired. Resume-from-checkpoint stays on the seed path because the
/// loaded `initial_results` already encodes the prior trigger
/// materialisation; introducing a second synthetic trigger would
/// double-seed the root nodes.
///
/// Selection is pure-functional and unit-tested below — the live
/// `run_scheduled_execution` site only consumes the variant.
#[derive(Debug)]
pub(crate) enum SchedulerDispatch {
    /// Fresh execution. Engine is invoked via
    /// `run_with_trigger_input_via_nats(&mut engine, ..., trigger_input, ...)`.
    Fresh { trigger_input: serde_json::Value },
    /// Resume from a prior checkpoint. Engine is invoked via
    /// `run_with_seed_via_nats(&engine, ..., initial_results, ...)`.
    Resume {
        initial_results: std::collections::HashMap<Uuid, serde_json::Value>,
    },
}

impl SchedulerDispatch {
    /// Decide which engine entrypoint a scheduled run should take based
    /// on whether a checkpoint was loaded. The trigger envelope on the
    /// `Fresh` variant is intentionally `serde_json::json!({})` — an
    /// empty *object* (not `null`) — so template substitution in root
    /// nodes (`{{__trigger_input__.X}}`) produces `null` for missing
    /// keys instead of failing the lookup outright.
    pub(crate) fn for_run(
        initial_results: std::collections::HashMap<Uuid, serde_json::Value>,
    ) -> Self {
        if initial_results.is_empty() {
            Self::Fresh {
                trigger_input: serde_json::json!({}),
            }
        } else {
            Self::Resume { initial_results }
        }
    }
}

/// Runs a single scheduled workflow execution to completion.
async fn run_scheduled_execution(
    execution_id: Uuid,
    workflow_id: Uuid,
    user_id: Uuid,
    schedule_id: Uuid,
    db_pool: PgPool,
    sender: tokio::sync::broadcast::Sender<ExecutionEvent>,
    registry: Arc<ModuleRegistry>,
    secrets_manager: Arc<SecretsManager>,
    _worker_manager: Arc<WorkerManager>,
    _module_execution_service: Arc<ModuleExecutionService>,
    worker_shared_key: Option<WorkerSharedKey>,
    nats_client: Arc<async_nats::Client>,
) {
    // 1. Fetch the workflow's graph + actor binding + description BEFORE
    //    inserting the execution row so the row carries the workflow's
    //    bound actor_id from the start. Pre-fix (MCP-21, 2026-05-07) the
    //    scheduler inserted with no actor_id and the binding never landed
    //    on the execution row, breaking `get_actor_summary.executions`
    //    counts and per-actor audit queries on scheduler-fired runs.
    #[derive(sqlx::FromRow)]
    struct WorkflowGraph {
        graph_json: String,
        actor_id: Option<uuid::Uuid>,
        description: Option<String>,
    }

    let workflow = match sqlx::query_as::<_, WorkflowGraph>(
        "SELECT graph_json, actor_id, description FROM workflows WHERE id = $1 AND user_id = $2",
    )
    .bind(workflow_id)
    .bind(user_id)
    .fetch_one(&db_pool)
    .await
    {
        Ok(w) => w,
        Err(e) => {
            tracing::error!(
                execution_id = %execution_id,
                workflow_id = %workflow_id,
                "Scheduler: failed to load workflow before INSERT: {}",
                e
            );
            return;
        }
    };

    // 1.5. MCP-708 (2026-05-13): upgraded from MCP-555's budget-only
    // `check_execution_allowed` to the full
    // `authorize_workflow_trigger` gate (status + budget +
    // capability-ceiling re-verification against the stored graph).
    // Same dispatch-path-authorization sweep as MCP-707 for
    // retry/replay — budget-only let operator-downgraded actor
    // ceilings drift open across scheduled fires.
    //
    // Pre-fix bypass scenario: actor A had `max_capability_world =
    // agent-node` at T0; user built workflow W with agent-node modules
    // and scheduled it cron. Operator at T1 downgrades A to
    // `http-node`. At every subsequent cron fire, the scheduler still
    // dispatched W's agent-node modules against the now-http-node-
    // ceilinged A. Scheduled workflows are particularly sensitive to
    // this because they fire repeatedly without any user-driven
    // re-trigger — the downgrade NEVER takes effect until the next
    // re-publish.
    //
    // Skip-with-warn semantics preserved per-rejection-class so
    // operators can distinguish budget vs ceiling vs actor-state.
    //
    // Phase D2 parity with `trigger.rs` (2026-07-10): the gate now runs
    // UNCONDITIONALLY and its resolved actor is captured. Pre-fix the
    // scheduler skipped the gate for unbound workflows ("no actor to
    // enforce") and built the engine with `with_effective_actor(None,
    // None)` — so an unbound scheduled workflow ran at the engine's
    // fail-safe Tier-1 default (local-egress-only: every external HTTP
    // call died as a generic `networkerror`) while the SAME workflow
    // triggered manually resolved the user's default actor (Tier-2) and
    // worked. Worse, the DB auto-stamp trigger recorded the default
    // actor on the execution row, so attribution said one actor while
    // the runtime tier came from none. The gate's Phase D1 fallback
    // (`get_or_create_default_actor`) is the single source of truth for
    // "who does an unbound workflow run as" — authorization,
    // attribution, and runtime tier now all use its answer.
    // Deny-arm log context: for an unbound workflow the actor being denied
    // is the gate's internally-resolved user-default actor, whose id the
    // error variants don't carry — `actor_id: None` alone is unactionable
    // (the operator can't tell WHICH actor to resume/fund). This field plus
    // `user_id` makes the denied principal recoverable in one lookup.
    let denied_actor_source = if workflow.actor_id.is_some() {
        "workflow-bound"
    } else {
        "user-default-actor"
    };
    let effective_actor_id: Option<Uuid> = {
        let workflow_repo_for_auth =
            talos_workflow_repository::WorkflowRepository::new(db_pool.clone());
        let actor_repo_for_auth = talos_actor_repository::ActorRepository::new(db_pool.clone());
        match talos_workflow_authorization::resolve_effective_actor(
            &workflow_repo_for_auth,
            &actor_repo_for_auth,
            &db_pool,
            workflow.actor_id,
            user_id,
            &workflow.graph_json,
        )
        .await
        {
            Ok(resolved) => resolved,
            Err(talos_workflow_authorization::TriggerAuthError::ActorArchived)
            | Err(talos_workflow_authorization::TriggerAuthError::ActorTerminated)
            | Err(talos_workflow_authorization::TriggerAuthError::ActorNotFoundOrInactive) => {
                tracing::warn!(
                    execution_id = %execution_id,
                    workflow_id = %workflow_id,
                    actor_id = ?workflow.actor_id,
                    %user_id,
                    denied_actor_source,
                    schedule_id = %schedule_id,
                    "MCP-708: scheduled fire denied — actor not in a runnable state"
                );
                return;
            }
            Err(talos_workflow_authorization::TriggerAuthError::ExecutionDenied(reason)) => {
                tracing::warn!(
                    execution_id = %execution_id,
                    workflow_id = %workflow_id,
                    actor_id = ?workflow.actor_id,
                    %user_id,
                    denied_actor_source,
                    schedule_id = %schedule_id,
                    reason = %reason,
                    "MCP-708: scheduled fire denied by actor budget/status gate — skipping dispatch"
                );
                return;
            }
            Err(talos_workflow_authorization::TriggerAuthError::CapabilityCeilingViolation {
                module_id,
                module_world,
                max_world,
                ..
            }) => {
                tracing::warn!(
                    execution_id = %execution_id,
                    workflow_id = %workflow_id,
                    actor_id = ?workflow.actor_id,
                    %user_id,
                    denied_actor_source,
                    schedule_id = %schedule_id,
                    %module_id,
                    %module_world,
                    %max_world,
                    "MCP-708: scheduled fire denied — node exceeds actor capability ceiling \
                     (drift since original create; downgrade actor ceiling or remove the node)"
                );
                return;
            }
            Err(talos_workflow_authorization::TriggerAuthError::Database(e)) => {
                // Fail-CLOSED on DB error. A transient lookup failure
                // must not let a downgraded ceiling slip through on
                // the next scheduled tick.
                tracing::warn!(
                    execution_id = %execution_id,
                    workflow_id = %workflow_id,
                    actor_id = ?workflow.actor_id,
                    %user_id,
                    denied_actor_source,
                    schedule_id = %schedule_id,
                    error = %e,
                    "MCP-708: scheduled fire denied — auth-gate DB error (fail-closed)"
                );
                return;
            }
        }
    };

    // 2. Create execution record via the canonical
    //    `WorkflowRepository::create_execution_with_lineage` helper so
    //    the row stamps both `provenance` (trigger_type='scheduled' +
    //    schedule_id) AND `actor_id` (the gate-resolved effective actor —
    //    see the Phase D2 note above) in one ownership-gated INSERT. This consolidates the scheduler onto
    //    the same write path used by `trigger_workflow` /
    //    `replay_execution`, so analytics queries that filter by
    //    `provenance->>'trigger_type' = 'scheduled'`
    //    (`get_scheduled_24h_execution_stats`) and per-actor counts
    //    (`get_actor_summary.executions`) both pick up scheduled runs.
    //
    //    Use status='running' + started_at NOW() because the scheduler
    //    executes immediately in-process. ('pending' was removed from
    //    the status CHECK constraint by 20260314001000_add_queued_status.sql)
    //
    //    allow-trigger-type-column: JSON object key in provenance literal,
    //    not a SQL column reference.
    let provenance = serde_json::json!({
        "trigger_type": "scheduled",
        "schedule_id": schedule_id.to_string(),
    });
    let workflow_repo = talos_workflow_repository::WorkflowRepository::new(db_pool.clone());
    // R3 (concurrency-cap fix): route through `create_execution_under_concurrency_limit`
    // — the SAME TOCTOU-safe gate (`SELECT max_concurrent_executions ... FOR
    // UPDATE` + running-count + INSERT in one tx) the manual trigger / webhook
    // paths use. Pre-fix the scheduler used `create_execution_with_lineage`,
    // which never reads `max_concurrent_executions`, so a frequent cron firing a
    // slow workflow piled up unbounded concurrent runs past a cap that manual
    // triggers correctly enforced. The ownership gate is now the tx's
    // `fetch_one ... WHERE id=$1 AND user_id=$2 FOR UPDATE` (a deleted/foreign
    // workflow returns Err here, replacing the old rows_affected==0 sentinel).
    let admission = match workflow_repo
        .create_execution_under_concurrency_limit(
            execution_id,
            workflow_id,
            user_id,
            None, // version_id — scheduler runs the draft graph
            None, // priority — defaults to "normal"
            // Phase D2: the gate-resolved actor (default-actor fallback
            // included) so the row's attribution matches the runtime tier
            // instead of relying on the DB auto-stamp trigger to fill NULL.
            effective_actor_id,
            Some(&provenance),
            None, // parent_execution_id — top-level run
            None, // root_execution_id — top-level run
            talos_workflow_repository::InitialExecutionStatus::Running,
        )
        .await
    {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(
                execution_id = %execution_id,
                workflow_id = %workflow_id,
                "Scheduler: failed to create execution record (workflow likely deleted mid-fire): {}",
                e
            );
            return;
        }
    };
    match admission {
        talos_workflow_repository::ConcurrencyAdmission::Created => {}
        talos_workflow_repository::ConcurrencyAdmission::LimitReached { limit, running } => {
            // Respect the per-workflow concurrency cap. `next_trigger_at` was
            // already advanced before this spawn (commit-before-dispatch), so a
            // skipped fire simply drops to the next occurrence — consistent with the
            // scheduler's skip-to-next philosophy (no catch-up storm) and the
            // MCP-708 auth-gate skip semantics already in this function.
            tracing::warn!(
                execution_id = %execution_id,
                workflow_id = %workflow_id,
                limit,
                running,
                "Scheduler: skipping fire — per-workflow max_concurrent_executions reached; \
                 the next scheduled occurrence will retry"
            );
            return;
        }
        talos_workflow_repository::ConcurrencyAdmission::ActorBudgetExceeded {
            kind,
            limit,
            count,
        } => {
            // The atomic backstop rolled back the INSERT — no execution row
            // exists. Pre-fix this arm fell through an `if let LimitReached`
            // and the engine ran anyway: a budget-bypassing ghost run whose
            // status/checkpoint writes all matched zero rows. The backstop
            // covers caps the gate's pre-check does not (per-minute, fuel/hr),
            // so this arm is reachable deterministically, not just via race.
            // Skip-to-next semantics, same as LimitReached; trigger.rs
            // rejects the same variant on the manual path.
            tracing::warn!(
                execution_id = %execution_id,
                workflow_id = %workflow_id,
                actor_id = ?effective_actor_id,
                schedule_id = %schedule_id,
                reason = %talos_workflow_repository::actor_budget_exceeded_message(
                    kind, limit, count
                ),
                "Scheduler: skipping fire — actor budget exceeded (atomic backstop); \
                 the next scheduled occurrence will retry"
            );
            return;
        }
    }

    // 3. Resolve actor memory context (independent of engine construction).
    //    Routes through the canonical `WorkflowRepository::get_relevant_actor_context`
    //    helper so this path inherits the same scratchpad-exclusion + graph-RAG
    //    + vector-similarity tiers that trigger_workflow / test_workflow use.
    //    Without this delegation the scheduler had its own raw SQL that ranked
    //    scratchpads last but still surfaced them when the actor's semantic+
    //    episodic count was below LIMIT — the recursive __actor_context__
    //    growth bug fixed for other dispatch paths in r221.
    //
    //    The workflow's description is forwarded as the relevance hint so
    //    graph RAG and vector similarity pick the most pertinent memories
    //    rather than just the most recent.
    let actor_context = if let Some(actor_id) = workflow.actor_id {
        let workflow_repo = talos_workflow_repository::WorkflowRepository::new(db_pool.clone());
        let context_hint = workflow.description.as_deref();
        match workflow_repo
            .get_relevant_actor_context(actor_id, 20, context_hint)
            .await
        {
            Ok(rows) if !rows.is_empty() => Some(talos_memory::actor_context::assemble_payload(
                actor_id, &rows,
            )),
            Ok(_) => None, // No memories — nothing to inject.
            Err(e) => {
                tracing::warn!(
                    %execution_id, %actor_id, error = %e,
                    "scheduler: failed to load actor context; running without __actor_context__"
                );
                None
            }
        }
    } else {
        None
    };

    // 4. Build the engine via the canonical builder. `TimeoutPolicy::Honor`
    //    is correct here: the engine reads the graph's `execution_timeout_secs`
    //    during `load_graph_from_json`, so any pre-load `set_execution_timeout_secs`
    //    is silently overwritten. The Honor variant lets the engine do its
    //    job; per-workflow timeout knobs continue to flow through the graph.
    let actor_repo = Arc::new(talos_actor_repository::ActorRepository::new(
        db_pool.clone(),
    ));
    let opts = talos_engine::builder::EngineOpts::for_run(workflow_id, workflow.graph_json.clone())
        // Phase D2: the gate-resolved actor (explicit → workflow → default
        // fallback already applied) so the engine tier matches the stamped
        // execution row. Pre-fix an unbound workflow passed (None, None)
        // here and silently ran at the engine's fail-safe Tier-1 while the
        // same workflow triggered manually ran Tier-2.
        .with_effective_actor(effective_actor_id, workflow.actor_id)
        .with_actor_context(actor_context);
    let mut engine = match talos_engine::builder::for_workflow(
        registry,
        secrets_manager.clone(),
        actor_repo,
        user_id,
        opts,
    )
    .await
    {
        Ok(e) => e,
        Err(e) => {
            // MCP-969 (2026-05-15): DLP-redact in parity with the
            // sibling site at line ~1119 (Scheduled workflow failed
            // arm). Engine build errors carry the same arbitrary-
            // upstream-text class as engine-execution errors.
            let redacted_e = talos_dlp_provider::redact_str(&e.to_string());
            let error_msg = format!("Scheduler: failed to build engine: {}", redacted_e);
            tracing::error!(execution_id = %execution_id, "{}", error_msg);
            // MCP-776 (2026-05-13): see timeout-arm above.
            if let Err(ue) = sqlx::query(
                "UPDATE workflow_executions SET status = 'failed', completed_at = NOW(), error_message = $2 WHERE id = $1 AND status NOT IN ('completed', 'failed', 'cancelled', 'resuming')",
            )
            .bind(execution_id)
            .bind(&error_msg)
            .execute(&db_pool)
            .await
            {
                tracing::warn!(
                    target: "talos_audit",
                    execution_id = %execution_id,
                    primary_error = %redacted_e,
                    update_error = %ue,
                    "Scheduler: engine-build failed AND failure-marking UPDATE failed — execution row stuck 'running'"
                );
            }
            return;
        }
    };

    // MCP-684 (2026-05-13): pass SecretsManager so the DEK-encrypted
    // `output_data_enc` is a usable resume fallback when
    // WORKER_SHARED_KEY is missing. Without this branch, a Phase A
    // deployment that hadn't wired WSK silently lost every
    // waiting-execution's prior results on resume — the engine
    // re-ran the workflow from scratch.
    let initial_results = load_checkpoint_for_full(
        &db_pool,
        worker_shared_key.as_ref().map(WorkerSharedKey::as_bytes),
        Some(secrets_manager.clone()),
        execution_id,
    )
    .await;

    let wsk_for_checkpoint = worker_shared_key.clone();

    // FU-1 fresh-run fence extended to the scheduler (the remaining-sites
    // follow-up): scheduled executions are long-lived `running` rows — the most
    // likely to outlast the stale window and be reclaimed by crash-recovery
    // while the scheduler is still dispatching, the exact split-brain the epoch
    // fence closes. Observe the row's ACTUAL current epoch — passing a wrong
    // value would abort a healthy run on the first heartbeat tick (a silent
    // lost execution); on an epoch-read failure we fall back to the unfenced
    // path (fencing is best-effort hardening, and the status-guarded terminal
    // writes still prevent corruption). Both the Fresh (trigger-input) and
    // Resume (seed) dispatches are fenced.
    let fence_epoch = talos_execution_repository::ExecutionRepository::new(db_pool.clone())
        .current_execution_epoch(execution_id)
        .await
        .ok()
        .flatten();
    if fence_epoch.is_none() {
        tracing::warn!(
            execution_id = %execution_id,
            "Scheduler: could not read epoch for fresh-run fence; running unfenced"
        );
    }

    // See `SchedulerDispatch` for the rationale that pins this decision.
    let run_result = match SchedulerDispatch::for_run(initial_results) {
        SchedulerDispatch::Fresh { trigger_input } => match fence_epoch {
            Some(epoch) => {
                talos_engine::fence::run_with_trigger_input_fenced(
                    &mut engine,
                    nats_client,
                    worker_shared_key,
                    trigger_input,
                    execution_id,
                    db_pool.clone(),
                    epoch,
                )
                .await
            }
            None => {
                talos_engine::nats_run::run_with_trigger_input_via_nats(
                    &mut engine,
                    nats_client,
                    worker_shared_key,
                    trigger_input,
                    execution_id,
                )
                .await
            }
        },
        SchedulerDispatch::Resume { initial_results } => match fence_epoch {
            Some(epoch) => {
                talos_engine::fence::run_with_seed_fenced(
                    &mut engine,
                    nats_client,
                    worker_shared_key,
                    initial_results,
                    execution_id,
                    db_pool.clone(),
                    epoch,
                )
                .await
            }
            None => {
                talos_engine::nats_run::run_with_seed_via_nats(
                    &engine,
                    nats_client,
                    worker_shared_key,
                    initial_results,
                    execution_id,
                )
                .await
            }
        },
    };
    match run_result {
        Ok(ctx) => {
            // Aggregate output data. Pre-fix the scheduler ONLY inserted
            // `ctx.results` keyed by node_id and skipped `ctx.node_timings`
            // entirely — so scheduled executions never had
            // `__node_timings__` in their stored output. Every downstream
            // tool that reads timings (`get_execution_cost`,
            // `get_execution_timeline`, `get_execution_waterfall`,
            // `get_workflow_performance_report`'s node_timing_breakdown)
            // showed 0 nodes / empty timings for scheduler-dispatched
            // runs. The MCP-driven dispatch paths (`bulk_trigger_workflow`,
            // `enqueue_workflow`, `trigger_workflow` via
            // `talos_execution_result_collector::collect_success_output`)
            // already stamp these. Bringing the scheduler into parity.
            // Keys for node outputs stay as `node_id.to_string()` for
            // back-compat with the watch-* workflows that read prior
            // outputs; only the engine-meta envelope keys change.
            let mut aggregated_output = serde_json::Map::new();
            for (node_id, output) in &ctx.results {
                aggregated_output.insert(node_id.to_string(), output.clone());
            }
            if !ctx.node_timings.is_empty() {
                aggregated_output.insert(
                    "__node_timings__".to_string(),
                    serde_json::to_value(&ctx.node_timings).unwrap_or_default(),
                );
            }
            let aggregated_json =
                talos_dlp_provider::redact_json(&serde_json::Value::Object(aggregated_output));

            // Route through the encryption-aware ExecutionRepository so
            // output_data is wrapped at rest (workflow_executions.output_data_enc).
            // The scheduler is one of three writer paths; the others are
            // mark_execution_completed_with_output (MCP-driven) and
            // ActorRepository::complete_execution (handoff). All three must
            // go through repos that hold a SecretsManager so encryption is
            // not bypassed.
            let exec_repo = talos_execution_repository::ExecutionRepository::with_encryption(
                db_pool.clone(),
                secrets_manager.clone(),
            );
            if ctx.waiting {
                if let Err(e) = exec_repo
                    .mark_execution_waiting(execution_id, &aggregated_json)
                    .await
                {
                    tracing::warn!(%execution_id, error = %e, "Failed to mark execution as waiting");
                }
                // Also persist an encrypted copy of the checkpoint.
                let store = ControllerCheckpointStore::new(
                    db_pool.clone(),
                    wsk_for_checkpoint.as_ref().map(|k| k.as_bytes().to_vec()),
                );
                // Monotonic seq = node-keyed snapshot cardinality (same scale
                // the engine's per-node saves use). This suspend-time write
                // carries the complete set of completed nodes, so its seq is
                // >= any racing interim per-node save and won't be rejected;
                // a later resume's saves continue above it.
                let checkpoint_seq =
                    aggregated_json.as_object().map(|o| o.len()).unwrap_or(0) as i64;
                if let Err(e) = talos_workflow_engine_core::CheckpointStore::save(
                    &store,
                    execution_id,
                    &aggregated_json,
                    checkpoint_seq,
                )
                .await
                {
                    tracing::warn!(
                        %execution_id,
                        error = %e,
                        "Failed to persist encrypted checkpoint — resume will rely on plain output_data fallback",
                    );
                }
            } else if let Err(e) = exec_repo
                .mark_execution_completed(execution_id, &aggregated_json)
                .await
            {
                tracing::warn!(%execution_id, error = %e, "Failed to mark execution as completed");
            }

            let _ = sender.send(ExecutionEvent {
                execution_id,
                node_id: None,
                status: ExecutionStatus::Completed,
                trace_id: ctx.trace_id,
                span_id: None,
                log_message: Some("Scheduled workflow finished successfully".to_string()),
                iteration_index: None,
                iteration_total: None,
                duration_ms: None,
                output: None,
            });

            tracing::info!(
                execution_id = %execution_id,
                schedule_id = %schedule_id,
                "Scheduled workflow execution completed"
            );
        }
        Err(e) if talos_engine::fence::was_fenced(&e) => {
            // FU-1 fence: a fence abort means crash-recovery reclaimed this
            // scheduled run (the row's epoch advanced) — it now belongs to the
            // resumer (or a reclaim already failed it). Do NOT mark it failed:
            // the status-guarded UPDATE below would no-op anyway, but bailing
            // here also skips the failure broadcast/alerts for a run this
            // controller no longer owns. Mirrors the trigger.rs / crash_recovery
            // `was_fenced` handling.
            tracing::warn!(
                execution_id = %execution_id,
                schedule_id = %schedule_id,
                "Scheduler: run fenced — superseded by a crash-recovery reclaim; \
                 leaving the row to its new owner"
            );
        }
        Err(e) => {
            // MCP-448: DLP-redact the engine error before persistence
            // and broadcast. Upstream API errors often carry tokens
            // ("HTTP 401: invalid token sk-proj-xxx", Bearer header
            // echoed back, ghp_* in a "Bad credentials" body). Pre-fix
            // these landed in workflow_executions.error_message AND
            // were broadcast over the ExecutionEvent channel to every
            // SSE/WebSocket subscriber. Same fix as MCP-447 in the
            // orchestration crate — keeps the scheduler-dispatched path
            // in parity with the trigger/replay/retry paths.
            let redacted_err = talos_dlp_provider::redact_str(&e.to_string());
            let error_msg = format!("Scheduled workflow failed: {}", redacted_err);
            // MCP-776 (2026-05-13): see timeout-arm earlier in this function.
            if let Err(ue) = sqlx::query(
                "UPDATE workflow_executions SET status = 'failed', completed_at = NOW(), error_message = $2 WHERE id = $1 AND status NOT IN ('completed', 'failed', 'cancelled', 'resuming')",
            )
            .bind(execution_id)
            .bind(&error_msg)
            .execute(&db_pool)
            .await
            {
                tracing::warn!(
                    target: "talos_audit",
                    execution_id = %execution_id,
                    primary_error = %redacted_err,
                    update_error = %ue,
                    "Scheduler: execution failed AND failure-marking UPDATE failed — execution row stuck 'running'"
                );
            }
            // Cancel any still-running sibling module_executions.
            match sqlx::query(
                "UPDATE module_executions \
                 SET status = 'cancelled', completed_at = NOW(), \
                     error_message = 'Workflow failed — parallel sibling cancelled' \
                 WHERE workflow_execution_id = $1 AND status = 'running'",
            )
            .bind(execution_id)
            .execute(&db_pool)
            .await
            {
                Ok(r) => tracing::info!(
                    execution_id = %execution_id,
                    cancelled = r.rows_affected(),
                    "sibling cancellation UPDATE complete"
                ),
                Err(e) => tracing::warn!(
                    execution_id = %execution_id,
                    error = %e,
                    "sibling cancellation UPDATE failed"
                ),
            }

            let _ = sender.send(ExecutionEvent {
                execution_id,
                node_id: None,
                status: ExecutionStatus::Failed,
                trace_id: None,
                span_id: None,
                log_message: Some(error_msg.clone()),
                iteration_index: None,
                iteration_total: None,
                duration_ms: None,
                output: None,
            });

            tracing::error!(
                execution_id = %execution_id,
                schedule_id = %schedule_id,
                "Scheduled workflow execution failed: {}",
                error_msg
            );
        }
    }
}

#[cfg(test)]
mod cron_validation_tests {
    //! MCP-1020: pins the length-cap + scrubbed-error invariants on
    //! the cron parse helper so future callers that bypass the
    //! boundary cap still get the defense-in-depth treatment.
    use super::*;

    #[test]
    fn accepts_canonical_cron_expressions() {
        assert!(validate_cron("0 9 * * *").is_ok());
        assert!(validate_cron("*/5 * * * *").is_ok());
        // Per-minute schedule
        assert!(validate_cron("* * * * *").is_ok());
    }

    #[test]
    fn rejects_oversized_cron_with_length_only_error() {
        let oversized = "* ".repeat(200) + "*";
        let err = validate_cron(&oversized).expect_err("oversized must reject");
        // Error message names byte length only; no reflection of input.
        assert!(
            err.contains("exceeds 256 char cap"),
            "expected length cap message, got: {err}"
        );
        // The rejected content must NOT appear in the error.
        assert!(
            !err.contains("* * * * * * * * * *"),
            "error must not echo rejected cron content: {err}"
        );
    }

    #[test]
    fn rejects_garbage_cron_with_natural_error() {
        // Short-but-invalid cron should still get a parser error
        // (natural croner error, bounded by the 256-char cap).
        let err = validate_cron("not a cron").expect_err("garbage must reject");
        assert!(
            err.starts_with("Invalid cron expression:"),
            "expected natural parse error prefix, got: {err}"
        );
    }

    #[test]
    fn calculate_next_trigger_rejects_oversized_cron() {
        let oversized = "* ".repeat(200) + "*";
        let err = calculate_next_trigger(&oversized, "UTC")
            .expect_err("oversized cron must reject in next_trigger path too");
        assert!(err.contains("exceeds 256 char cap"));
    }

    #[test]
    fn validate_cron_min_interval_rejects_oversized_cron() {
        let oversized = "* ".repeat(200) + "*";
        let err = validate_cron_min_interval(&oversized, 60)
            .expect_err("oversized cron must reject in min-interval path");
        assert!(err.contains("exceeds 256 char cap"));
    }

    #[test]
    fn calculate_next_n_triggers_rejects_oversized_cron() {
        let oversized = "* ".repeat(200) + "*";
        let err = calculate_next_n_triggers(&oversized, "UTC", 3)
            .expect_err("oversized cron must reject in next_n path");
        assert!(err.contains("exceeds 256 char cap"));
    }

    #[test]
    fn accepts_max_length_cron() {
        // Exactly at the cap: should reach the croner parser. The
        // parser will reject (it's a long stream of asterisks), but
        // via the natural "Invalid cron expression:" path, not the
        // length-cap path.
        let at_cap = "*".repeat(256);
        let err = validate_cron(&at_cap).expect_err("invalid cron content rejects");
        assert!(
            !err.contains("exceeds 256 char cap"),
            "at-cap input should reach parser, not length gate: {err}"
        );
    }
}

#[cfg(test)]
mod scheduler_dispatch_tests {
    //! Pure-logic tests for `SchedulerDispatch::for_run`.
    //!
    //! Background: the r245 prod incident (daily-brief 50% failure rate)
    //! was caused by `run_scheduled_execution` calling
    //! `run_with_seed_via_nats` with an empty checkpoint map. That path
    //! skips the synthetic `__trigger__` node the engine installs in
    //! the manual `trigger_workflow` path, so any workflow whose roots
    //! reference `{{__trigger_input__.X}}` evaluated against `null`.
    //!
    //! These tests pin the contract `SchedulerDispatch::for_run` now
    //! enforces, so a future refactor cannot reintroduce the bug
    //! without a failing test.
    use super::SchedulerDispatch;
    use std::collections::HashMap;
    use uuid::Uuid;

    #[test]
    fn empty_checkpoint_selects_fresh_with_object_trigger_input() {
        let dispatch = SchedulerDispatch::for_run(HashMap::new());
        match dispatch {
            SchedulerDispatch::Fresh { trigger_input } => {
                // The defining contract: the trigger envelope MUST be a
                // JSON object, never `null`. Template substitution
                // against `null.X` panics; against `{}.X` it resolves
                // to `null`, which is what root nodes expect for
                // missing-key reads on a fresh execution.
                assert!(
                    trigger_input.is_object(),
                    "trigger_input must be a JSON object so `__trigger_input__.X` resolves \
                     against an object (yields null for missing keys); got: {trigger_input:?}"
                );
                assert_eq!(
                    trigger_input,
                    serde_json::json!({}),
                    "fresh-execution trigger envelope must be the canonical empty object"
                );
            }
            SchedulerDispatch::Resume { .. } => {
                panic!("empty checkpoint must select Fresh, not Resume");
            }
        }
    }

    #[test]
    fn non_empty_checkpoint_selects_resume_and_passes_results_through() {
        let mut results = HashMap::new();
        let node_id = Uuid::new_v4();
        let payload = serde_json::json!({"some": "prior-output"});
        results.insert(node_id, payload.clone());

        let dispatch = SchedulerDispatch::for_run(results.clone());
        match dispatch {
            SchedulerDispatch::Resume { initial_results } => {
                assert_eq!(
                    initial_results, results,
                    "Resume must pass the loaded checkpoint map through verbatim — \
                     the engine relies on these per-node outputs to avoid double-seeding"
                );
            }
            SchedulerDispatch::Fresh { .. } => {
                panic!(
                    "non-empty checkpoint must select Resume so the engine doesn't \
                     re-trigger over the top of restored root outputs"
                );
            }
        }
    }

    #[test]
    fn fresh_trigger_input_is_never_null() {
        // Defense in depth: if a future refactor changes the trigger
        // envelope to something like `Value::Null` (treating "no input"
        // as null), `__trigger_input__.X` template substitution will
        // fail at runtime — the original r245 bug class. This test
        // pins the invariant in isolation so the failure reads as
        // a clear contract break, not a generic Fresh-variant test
        // regression.
        let SchedulerDispatch::Fresh { trigger_input } = SchedulerDispatch::for_run(HashMap::new())
        else {
            panic!("expected Fresh");
        };
        assert!(
            !trigger_input.is_null(),
            "fresh-execution trigger envelope must NEVER be JSON null \
             (would re-introduce the r245 daily-brief regression)"
        );
    }
}
