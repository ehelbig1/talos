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
    /// A SECOND, tighter ceiling applied only to the **startup backlog** —
    /// the schedules found due by the first poll after this process booted.
    ///
    /// The M6 semaphore above did not prevent the 2026-08-10 outage because
    /// its default (16) never bound: exactly 15 schedules came due at boot, so
    /// all fifteen ran at once. They started within 20 ms of each other, their
    /// WASM jobs opened ~16 simultaneous TLS connects to `gmail.googleapis.com`
    /// / `www.googleapis.com`, and the connects began failing
    /// (`tcp connect error: deadline has elapsed`, `Connection refused`).
    /// Five consecutive failures tripped the worker's per-host circuit
    /// breaker, after which every remaining workflow declaring that host
    /// failed instantly against an OPEN breaker — 8 of 19 runs, on a boot
    /// where Gmail itself was demonstrably healthy (HTTP 200 sixteen seconds
    /// earlier). Three more schedules were refused outright by the actor
    /// budget backstop, which the burst had exhausted; two of those are DAILY
    /// crons, so "the next scheduled occurrence will retry" meant tomorrow.
    ///
    /// Backlog executions acquire from BOTH semaphores, so startup
    /// concurrency is `min(startup, steady)`. This is admission control, not
    /// a delay: the first backlog run starts immediately, the rest queue
    /// behind permits and drain as those complete.
    startup_semaphore: Arc<tokio::sync::Semaphore>,
    /// Flips to `true` once the first poll has run, so the startup ceiling
    /// applies to exactly one batch — the accumulated backlog — and steady
    /// state is untouched.
    first_poll_done: Arc<std::sync::atomic::AtomicBool>,
    /// Consecutive polls held by the fleet-readiness barrier, and the latch
    /// that stops it holding once that count passes
    /// [`DEFAULT_SCHEDULER_READINESS_MAX_HOLDS`]. See
    /// [`SchedulerService::fleet_is_visible`] for why an empty fleet view is
    /// not proof that the fleet is absent, and therefore why the barrier must
    /// have a give-up point.
    consecutive_holds: Arc<std::sync::atomic::AtomicUsize>,
    readiness_degraded: Arc<std::sync::atomic::AtomicBool>,
}

/// Default ceiling on concurrently-running scheduled executions (see
/// [`SchedulerService::spawn_semaphore`]). Override via
/// `SCHEDULER_MAX_CONCURRENT_EXECUTIONS`.
pub const DEFAULT_SCHEDULER_MAX_CONCURRENT_EXECUTIONS: usize = 16;

/// Default ceiling on concurrently-running executions from the STARTUP
/// BACKLOG (see [`SchedulerService::startup_semaphore`]). Override via
/// `SCHEDULER_STARTUP_MAX_CONCURRENT`.
///
/// **This is a large reduction, not a proven-sufficient bound**, and saying so
/// is the point. The observed herd was 15 concurrent executions producing
/// ~16 simultaneous outbound connects; 4 is a ~4x reduction in concurrent
/// executions. It is NOT a hard cap on concurrent outbound connections — one
/// execution can still fan out across loop iterations and pipeline steps — so
/// the honest claim is "much smaller burst", not "burst impossible".
/// `talos_scheduler_dispatches_total{phase="startup",outcome="failed"}` and
/// the alert built on it are what tell us whether 4 was actually enough;
/// tuning belongs there, driven by that signal rather than by this comment.
pub const DEFAULT_SCHEDULER_STARTUP_MAX_CONCURRENT: usize = 4;

/// Default bound on how long the first poll waits for the worker fleet to
/// become visible before giving up on THAT poll. Override via
/// `SCHEDULER_READINESS_TIMEOUT_SECS`.
///
/// Sized from the heartbeat protocol, not guessed: NATS core delivery is not
/// retained, so a worker that booted BEFORE the controller subscribed loses its
/// first heartbeat entirely — not hypothetical, it is what happened on
/// 2026-08-10 (worker published at 13:45:27.71, the controller's listener
/// subscribed at 13:45:29.33). The controller therefore learns about such a
/// worker on its SECOND heartbeat, i.e. after two publish intervals.
///
/// **Derived from the largest interval a worker can be configured with, not
/// from the default.** This was `90` with the reasoning "2 x 30 s + a full
/// interval of margin", and that reasoning is only true at the DEFAULT
/// interval. `TALOS_WORKER_HEARTBEAT_INTERVAL_SECS` is operator-set and clamped
/// to [`WORKER_HEARTBEAT_MAX_INTERVAL_SECS`] (45 s), so at the clamped maximum
/// `2 x 45 = 90` — the bound EQUALLED two intervals and the claimed margin was
/// zero. Worse, the guard test asserted the property against a hardcoded local
/// `30`, so it was structurally incapable of seeing the configuration that
/// fails: #631's "security property as a number" pattern, in a liveness bound.
///
/// Three maximum intervals: two to reach the second heartbeat plus one full
/// interval of margin, at the WORST supported configuration. 135 s at today's
/// constants (4.5 intervals at the 30 s default). Overshooting is close to free
/// — the wait returns the instant a worker appears, and it delays only the
/// first poll of a controller that cannot see a fleet at all.
pub const DEFAULT_SCHEDULER_READINESS_TIMEOUT_SECS: u64 =
    3 * talos_workflow_job_protocol::WORKER_HEARTBEAT_MAX_INTERVAL_SECS;

/// How many CONSECUTIVE polls the readiness barrier may hold before it gives
/// up and dispatches anyway. Override via `SCHEDULER_READINESS_MAX_HOLDS`.
///
/// **This is the "must not block forever" bound, and it is not a formality.**
/// An empty fleet view is ambiguous, not proof of absence — the metric's own
/// description in `talos_metrics` says so — and one of the readings it covers
/// is a deployment where an operator set
/// `TALOS_WORKER_HEARTBEAT_INTERVAL_SECS=0`, which disables heartbeat
/// publishing entirely and is a supported configuration the worker logs as
/// such. A barrier that refused to dispatch until it saw a heartbeat would, on
/// that deployment, silently stop EVERY scheduled workflow forever on a
/// completely healthy fleet. That failure is strictly worse than the boot herd
/// this barrier exists to prevent, so the barrier degrades rather than wedges.
///
/// For that specific deployment the right answer is
/// `SCHEDULER_FLEET_READINESS_BARRIER=false` on the CONTROLLER (see
/// [`SchedulerService::readiness_barrier_enabled`]) — the controller cannot
/// detect the worker-side setting, and a barrier that can only hold, give up
/// and report degraded forever is worth nothing. This bound is the fail-safe
/// for the operator who has NOT set that switch.
///
/// 20 polls at the 15 s interval ≈ 5 minutes — comfortably longer than the
/// worst honest case (a missed first heartbeat costs one interval) and short
/// enough that a genuinely misconfigured fleet is not stalled for long.
/// Crossing it sets `talos_scheduler_readiness_degraded` to 1 and logs at WARN;
/// schedules run, but without the readiness guarantee, so a herd can recur.
/// The gauge returns to 0 as soon as any heartbeat is seen — see
/// [`SchedulerService::note_fleet_visible`] for why re-arming on that evidence
/// is safe and why the one-way latch it replaced was not.
pub const DEFAULT_SCHEDULER_READINESS_MAX_HOLDS: usize = 20;

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
            startup_semaphore: Arc::new(tokio::sync::Semaphore::new(
                talos_config::positive_env_or_default(
                    "SCHEDULER_STARTUP_MAX_CONCURRENT",
                    DEFAULT_SCHEDULER_STARTUP_MAX_CONCURRENT,
                ),
            )),
            first_poll_done: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            consecutive_holds: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            readiness_degraded: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Whether the controller can currently SEE a worker able to run what the
    /// scheduler is about to dispatch.
    ///
    /// Reads [`talos_worker_fleet::WorkerManager`] directly — the in-process
    /// view updated synchronously on each verified NATS heartbeat — and
    /// deliberately NOT the `talos_worker_fleet_live_workers` gauge, which is
    /// republished on a 60 s sweep and so lags the truth by up to a minute.
    /// On 2026-08-10 that distinction is the difference between learning about
    /// the worker at 13:45:57 and at 13:46:40.
    ///
    /// **What this does and does not certify.** It certifies that some process
    /// published a signed heartbeat recently — i.e. there is a fleet. It does
    /// NOT certify that a given third-party dependency is reachable, and it
    /// cannot: the per-host HTTP circuit breaker that actually failed those 8
    /// runs is a `static OnceLock` inside the WORKER process
    /// (`talos_worker_runtime::circuit_breaker`), invisible to the controller,
    /// with no signal on the wire. The controller must not synthesise one by
    /// probing Gmail either — that is a credentialed request storm against a
    /// third party. So this barrier is honestly scoped to the readiness it can
    /// observe, and the burst itself is defused by
    /// [`Self::startup_semaphore`] rather than by waiting on something
    /// unobservable.
    fn fleet_is_visible(&self) -> bool {
        self.worker_manager.worker_count() > 0
    }

    /// Wait, bounded, for the fleet to become visible before the first poll.
    ///
    /// Returns `true` if a worker became visible (dispatch may proceed) and
    /// `false` if the bound elapsed with an empty fleet, or shutdown fired.
    ///
    /// FAIL-SAFE DIRECTION. A `false` means the caller SKIPS the poll
    /// entirely — it never opens the transaction, so `last_triggered_at` /
    /// `next_trigger_at` are not advanced and every due schedule is still due
    /// on the next 15 s tick. Holding therefore cannot lose a run; it can only
    /// delay one.
    ///
    /// And it cannot wedge, in TWO separate senses, because one alone would
    /// not be enough:
    ///   * after this initial bounded wait the check is a cheap non-blocking
    ///     predicate re-evaluated every tick, so the backlog drains the moment
    ///     a worker appears; and
    ///   * holding itself is bounded — [`Self::hold_or_degrade`] gives up
    ///     after [`DEFAULT_SCHEDULER_READINESS_MAX_HOLDS`] consecutive polls
    ///     and dispatches anyway. Without that second bound, a deployment with
    ///     heartbeats disabled would have every scheduled workflow silently
    ///     stopped forever by a barrier that was supposed to protect it.
    async fn await_fleet_visible(&self, shutdown: &mut tokio::sync::watch::Receiver<bool>) -> bool {
        if self.fleet_is_visible() {
            return true;
        }
        let bound = std::time::Duration::from_secs(talos_config::positive_env_or_default(
            "SCHEDULER_READINESS_TIMEOUT_SECS",
            DEFAULT_SCHEDULER_READINESS_TIMEOUT_SECS,
        ));
        tracing::info!(
            target: "talos_scheduler",
            event_kind = "scheduler_awaiting_fleet",
            bound_secs = bound.as_secs(),
            "Scheduler: no worker visible in the NATS fleet heartbeat view yet — \
             holding the first dispatch. Nothing is lost while held: no schedule \
             state is advanced until a poll actually runs."
        );
        let deadline = tokio::time::Instant::now() + bound;
        // Poll the manager rather than awaiting a notification: the fleet view
        // has no change signal, and a 1 s probe against an in-memory DashMap
        // costs nothing next to the 15 s poll interval it gates.
        let mut probe = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = probe.tick() => {
                    if self.fleet_is_visible() {
                        return true;
                    }
                    if tokio::time::Instant::now() >= deadline {
                        return false;
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        return false;
                    }
                }
            }
        }
    }

    /// Decide whether this poll may dispatch, given that the fleet is not
    /// visible. Returns `true` to proceed anyway (degraded), `false` to hold.
    ///
    /// Holding is lossless — a held poll never opens its transaction, so no
    /// schedule state advances and everything is still due next tick — but it
    /// cannot be unbounded, because a zero fleet view is not proof of an
    /// absent fleet (see [`DEFAULT_SCHEDULER_READINESS_MAX_HOLDS`]). Past the
    /// bound this latches into a degraded mode that dispatches without the
    /// readiness evidence and reports that fact on
    /// `talos_scheduler_readiness_degraded`.
    fn hold_or_degrade(&self) -> bool {
        let max_holds = talos_config::positive_env_or_default(
            "SCHEDULER_READINESS_MAX_HOLDS",
            DEFAULT_SCHEDULER_READINESS_MAX_HOLDS,
        );

        let (holds, max_holds) =
            match decide_hold(&self.consecutive_holds, &self.readiness_degraded, max_holds) {
                // Already gave up; don't re-log or re-count every 15 s.
                HoldDecision::AlreadyDegraded => return true,
                HoldDecision::Hold { holds } => {
                    if let Some(m) = talos_metrics::global() {
                        m.scheduler_readiness_holds_total.inc();
                    }
                    tracing::warn!(
                        target: "talos_scheduler",
                        event_kind = "scheduler_dispatch_held_fleet_unready",
                        holds,
                        max_holds,
                        "Scheduler: holding dispatch — the controller's NATS fleet heartbeat \
                         view still contains no live worker. Due schedules are NOT advanced \
                         and NOT lost; they fire as soon as a worker becomes visible."
                    );
                    return false;
                }
                HoldDecision::Degrade { holds } => (holds, max_holds),
            };

        if let Some(m) = talos_metrics::global() {
            m.scheduler_readiness_degraded.set(1);
        }
        tracing::warn!(
            target: "talos_scheduler",
            event_kind = "scheduler_readiness_degraded",
            holds,
            max_holds,
            "Scheduler: no worker has become visible after {max_holds} consecutive \
             polls — dispatching WITHOUT fleet-readiness evidence until one is. A \
             zero fleet view is ambiguous (empty fleet, a build too old to publish \
             heartbeats, a broken subscription, or heartbeats disabled outright via \
             TALOS_WORKER_HEARTBEAT_INTERVAL_SECS=0), and refusing forever would \
             silently stop every scheduled workflow on a healthy fleet — which is \
             worse than the boot herd this barrier prevents. Schedules will run; the \
             startup-herd protection is weakened until heartbeats are seen, and \
             re-arms by itself the moment one is. If this deployment publishes no \
             heartbeats by design, set SCHEDULER_FLEET_READINESS_BARRIER=false \
             rather than leaving a permanently-degraded gauge."
        );
        true
    }

    /// Called on every poll that finds the fleet visible: clears the hold
    /// streak so a transient blip does not accumulate toward the give-up
    /// bound across an otherwise healthy day, and RE-ARMS the barrier if it
    /// had already given up.
    ///
    /// **Why re-arming is safe, and why the one-way latch it replaces was
    /// not.** The barrier's entire purpose is to hold dispatch while the fleet
    /// is invisible; a visible fleet is exactly the condition that should put
    /// it back in force. `readiness_degraded` never meant "this fleet is
    /// untrustworthy" — it meant "we have not seen a heartbeat yet, and we
    /// have stopped waiting". A seen heartbeat is strictly better evidence
    /// than that, so continuing to report degraded once one arrives asserts
    /// something no longer true.
    ///
    /// As a one-way latch it produced a permanently-firing alert on a HEALTHY
    /// fleet: a slow worker image pull outlasts the give-up bound, the worker
    /// then arrives and everything is fine — and `TalosSchedulerReadinessDegraded`
    /// (`== 1`, `for: 5m`) fires until the controller is restarted. A red that
    /// cannot go green teaches operators to ignore red, which is the same
    /// defect the barrier was added to avoid one level up.
    ///
    /// Re-arming cannot thrash: it is bounded by `consecutive_holds` climbing
    /// all the way back to `SCHEDULER_READINESS_MAX_HOLDS` (~5 min of
    /// continuous invisibility at the 15 s interval) before the gauge can
    /// return to 1, so a flapping fleet produces at most one transition per
    /// several minutes.
    fn note_fleet_visible(&self) {
        if clear_holds_and_rearm(&self.consecutive_holds, &self.readiness_degraded) {
            if let Some(m) = talos_metrics::global() {
                m.scheduler_readiness_degraded.set(0);
            }
            tracing::info!(
                target: "talos_scheduler",
                event_kind = "scheduler_readiness_rearmed",
                "Scheduler: a worker is visible in the NATS fleet heartbeat view again \
                 — the readiness barrier is back in force and \
                 talos_scheduler_readiness_degraded has returned to 0."
            );
        }
    }

    /// Whether the fleet-readiness barrier is engaged at all.
    ///
    /// **This exists for one deployment the controller cannot detect.**
    /// `TALOS_WORKER_HEARTBEAT_INTERVAL_SECS=0` on the WORKER disables
    /// heartbeat publishing outright — a supported configuration — and the
    /// controller has no way to see it: the setting lives in another process,
    /// and a fleet that never heartbeats is byte-identical to a fleet that is
    /// absent. On such a deployment the barrier holds for its bound, gives up,
    /// and pins `talos_scheduler_readiness_degraded` at 1 forever. The alert
    /// runbook used to say that firing was "expected for this deployment",
    /// which is not an acceptable resting state for an alert.
    ///
    /// Of the two available fixes — suppress the alert, or disable the barrier
    /// — this takes the second: an alert that is documented as ignorable in
    /// some configurations is an alert nobody reads in ANY configuration, and
    /// the barrier genuinely cannot do its job without heartbeats, so leaving
    /// it engaged buys nothing but a permanent hold-then-degrade cycle. It has
    /// to be an explicit operator switch rather than auto-detection precisely
    /// because the controller cannot observe the worker's env.
    ///
    /// Default ON. With it off, no readiness wait, no holds counted, and the
    /// degraded gauge stays 0 — the startup concurrency ceiling remains the
    /// herd protection in force, and it is the load-bearing one.
    fn readiness_barrier_enabled() -> bool {
        talos_config::bool_env_or_default("SCHEDULER_FLEET_READINESS_BARRIER", true)
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

        // READINESS BARRIER (bounded). `tokio::time::interval` fires its first
        // tick IMMEDIATELY, so without this the first poll runs ~1.7 s after
        // the controller starts and dispatches the entire accumulated backlog
        // into a fleet the controller cannot yet see. On 2026-08-10 that view
        // read ZERO live workers for the whole failure window — the herd fired
        // at 13:45:29.94 and the fleet did not become visible until 13:45:57.
        //
        // This wait happens ONCE, before the loop, and only when the fleet is
        // not already visible. On timeout we do not dispatch; the per-tick
        // check below re-evaluates cheaply, so the backlog is deferred, never
        // dropped.
        //
        // Resolved ONCE for the process rather than per tick: the switch is a
        // deployment posture, not something that changes under a running
        // controller, and one read means the pre-loop wait and the per-tick
        // check can never disagree.
        let barrier_enabled = Self::readiness_barrier_enabled();
        if !barrier_enabled {
            tracing::info!(
                target: "talos_scheduler",
                event_kind = "scheduler_readiness_barrier_disabled",
                "Scheduler: fleet-readiness barrier disabled by configuration \
                 (SCHEDULER_FLEET_READINESS_BARRIER). Dispatch will not wait on the \
                 NATS heartbeat view — set this only when the fleet genuinely does \
                 not publish heartbeats (TALOS_WORKER_HEARTBEAT_INTERVAL_SECS=0), \
                 where the barrier could otherwise only hold, give up, and report \
                 degraded forever. The startup concurrency ceiling still applies."
            );
        } else if self.await_fleet_visible(&mut shutdown).await {
            self.note_fleet_visible();
        }
        // `await_fleet_visible` consumes the shutdown notification via its own
        // `changed()`, and `watch::Receiver::changed()` only resolves on a
        // change the receiver has not yet seen. So the loop below would NOT
        // observe a shutdown that arrived during the barrier wait — it would
        // sit until the next tick and then dispatch, on a controller that is
        // going away. Re-read the current value instead of relying on a second
        // edge.
        if *shutdown.borrow() {
            tracing::info!("Scheduler received shutdown while awaiting fleet readiness");
            return;
        }
        // If it timed out we deliberately do NOTHING here and fall through: the
        // loop's first tick fires immediately and runs the same
        // `fleet_is_visible` / `hold_or_degrade` accounting every later tick
        // uses. Counting the hold here as well would inflate
        // `talos_scheduler_readiness_holds_total` by one on every boot that
        // waits, and the alert on it is threshold-based.

        let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Re-check every tick. Cheap (an in-memory count) and
                    // non-blocking: a poll held here advances no schedule
                    // state, so the same schedules are still due next tick.
                    //
                    // Skipped entirely when the barrier is off: no holds
                    // counted, no degraded latch set. A deployment that cannot
                    // produce the evidence must not be permanently reported as
                    // lacking it.
                    if barrier_enabled {
                        if self.fleet_is_visible() {
                            self.note_fleet_visible();
                        } else if !self.hold_or_degrade() {
                            continue;
                        }
                    }
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
        let (phase, to_spawn) =
            Self::select_due_and_advance(&self.db_pool, &self.first_poll_done).await?;

        if phase == talos_metrics::SCHEDULER_PHASE_STARTUP && !to_spawn.is_empty() {
            tracing::info!(
                target: "talos_scheduler",
                event_kind = "scheduler_startup_backlog",
                backlog = to_spawn.len(),
                "Scheduler: first poll after boot — draining the accumulated backlog \
                 under the startup concurrency ceiling rather than all at once"
            );
        }

        for (workflow_id, user_id, schedule_id) in to_spawn {
            self.spawn_workflow_execution(workflow_id, user_id, schedule_id, phase);
        }

        Ok(())
    }

    /// The DB half of one poll: classify the phase, claim the due batch,
    /// advance each schedule's trigger times, commit, and hand back the
    /// executions the caller should spawn now that the commit has landed.
    ///
    /// Split out of [`Self::poll_and_trigger`] — and taking its two inputs by
    /// reference rather than reading `self` — so the startup-phase lifecycle
    /// below can be driven against a real, deliberately unreachable pool in a
    /// unit test. Building a whole `SchedulerService` would need a live NATS
    /// connection, which is precisely the kind of setup cost that leaves an
    /// error path with no test at all.
    async fn select_due_and_advance(
        db_pool: &PgPool,
        first_poll_done: &std::sync::atomic::AtomicBool,
    ) -> Result<(&'static str, Vec<(Uuid, Uuid, Uuid)>), String> {
        // Classify the phase FIRST — before the query — but do NOT consume the
        // startup phase until this poll has actually reached a COMMIT.
        //
        // Consuming it on entry (a `swap(true, ..)` here, which is what this
        // did until the review of 6dde58b) disarms the ceiling on exactly the
        // condition it targets. Every error path below returns `Err` and the
        // caller only logs it: `begin()` against a Postgres that is still cold
        // at controller boot, the `fetch_all`, the `commit`. Nothing was
        // dispatched and no schedule advanced — so the next tick picks up the
        // whole backlog, now labelled `phase="steady"`, running under the
        // 16-wide steady semaphore that provably did not bind on a herd of 15,
        // and invisible to `TalosSchedulerStartupHerdNotAbsorbed`. A cold
        // Postgres at controller boot co-occurs with the cold-start herd by
        // construction; this is not a remote path.
        //
        // The EMPTY-BATCH case still consumes the phase, and that is deliberate
        // rather than an omission: a controller that restarts with nothing
        // overdue has no backlog at all, and the first `*/15` cron to come due
        // 15 s later must not be counted as startup — that would fire the herd
        // alert on an ordinary steady-state failure, and a detector that cries
        // wolf on the common case is how operators learn to ignore it. The
        // condition is "this poll reached a successful commit", not "this poll
        // found work".
        //
        // Plain load/store rather than a compare-exchange: `poll_and_trigger`
        // is driven from a single scheduler loop, one poll at a time, so there
        // is no concurrent second caller to race with.
        let is_startup_backlog = !first_poll_done.load(std::sync::atomic::Ordering::SeqCst);
        let phase = if is_startup_backlog {
            talos_metrics::SCHEDULER_PHASE_STARTUP
        } else {
            talos_metrics::SCHEDULER_PHASE_STEADY
        };

        // Use a transaction with FOR UPDATE SKIP LOCKED to prevent
        // double-firing in multi-instance deployments.
        let mut tx = db_pool
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
            // A boot with nothing overdue HAS consumed its startup phase — see
            // the classification comment above.
            first_poll_done.store(true, std::sync::atomic::Ordering::SeqCst);
            return Ok((phase, Vec::new()));
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

        // Commit succeeded — the startup phase is spent, and only now. A crash
        // between commit and spawn would lose at most this batch's
        // triggers (no double-fire); the next poll sees them as already
        // "scheduled forward" because the UPDATE committed.
        first_poll_done.store(true, std::sync::atomic::Ordering::SeqCst);

        Ok((phase, to_spawn))
    }

    /// Trigger a workflow execution in the background, mirroring the pattern
    /// used by `trigger_workflow` in the GraphQL mutation.
    fn spawn_workflow_execution(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        schedule_id: Uuid,
        phase: &'static str,
    ) {
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
        let startup_semaphore = self.startup_semaphore.clone();
        let is_startup = phase == talos_metrics::SCHEDULER_PHASE_STARTUP;

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
            // Startup-backlog runs take the tighter startup permit FIRST, then
            // the steady-state one, so the boot burst is `min(startup, steady)`
            // wide instead of "however many happened to come due".
            //
            // The order is load-bearing and is the opposite of the obvious one.
            // Taking the steady permit first would let all 15 parked backlog
            // tasks sit on steady permits while queueing for a startup permit,
            // leaving ~1 of 16 for anything else — so a `*/15` cron coming due
            // mid-drain would be starved by a backlog that is deliberately
            // draining slowly. This way at most `startup` backlog tasks hold a
            // steady permit at once and the rest of the steady pool stays
            // available.
            //
            // No deadlock: every backlog task acquires in the same order
            // (startup → steady) and steady-state tasks never touch the startup
            // semaphore at all, so there is no cycle. Both permits are held for
            // the execution's lifetime and released on drop. `acquire_owned`
            // only errors if the semaphore is closed, which never happens (the
            // Arc lives as long as the service); on the impossible error we skip
            // rather than run unbounded.
            //
            // Both impossible-error arms still record: "impossible" is a claim
            // about the code, and the counter's value is that it partitions
            // every spawned task without needing that claim to hold.
            let _startup_permit = if is_startup {
                match startup_semaphore.acquire_owned().await {
                    Ok(p) => Some(p),
                    Err(_) => {
                        record_dispatch(phase, talos_metrics::SCHEDULER_OUTCOME_FAILED);
                        tracing::error!("Scheduler startup semaphore closed — skipping execution");
                        return;
                    }
                }
            } else {
                None
            };
            let _permit = match spawn_semaphore.acquire_owned().await {
                Ok(p) => p,
                Err(_) => {
                    record_dispatch(phase, talos_metrics::SCHEDULER_OUTCOME_FAILED);
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
                    phase,
                ),
            )
            .await
            {
                // The timeout drops `run_scheduled_execution` mid-flight, so
                // its own terminal arms never run — count the failure here or
                // a timed-out scheduled run is invisible to the detector.
                record_dispatch(phase, talos_metrics::SCHEDULER_OUTCOME_FAILED);
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

/// What the readiness accounting decided for one poll.
#[derive(Debug, PartialEq, Eq)]
enum HoldDecision {
    /// Hold this poll; `holds` is the new consecutive count.
    Hold { holds: usize },
    /// This poll crosses the bound — give up and dispatch from now on.
    Degrade { holds: usize },
    /// An earlier poll already gave up; proceed without re-counting or
    /// re-logging every 15 s.
    AlreadyDegraded,
}

/// The state transition inside [`SchedulerService::hold_or_degrade`], split out
/// so the latch lifecycle — hold, give up, RE-ARM, hold again — can be driven
/// in a unit test against the production atomics instead of a copy that drifts
/// from them. The `&self` wrapper keeps the logging and the metric writes.
fn decide_hold(
    consecutive_holds: &std::sync::atomic::AtomicUsize,
    readiness_degraded: &std::sync::atomic::AtomicBool,
    max_holds: usize,
) -> HoldDecision {
    use std::sync::atomic::Ordering;

    if readiness_degraded.load(Ordering::SeqCst) {
        return HoldDecision::AlreadyDegraded;
    }
    let holds = consecutive_holds.fetch_add(1, Ordering::SeqCst) + 1;
    if holds <= max_holds {
        return HoldDecision::Hold { holds };
    }
    readiness_degraded.store(true, Ordering::SeqCst);
    HoldDecision::Degrade { holds }
}

/// Clear the hold streak and re-arm the barrier. Returns `true` if it had
/// actually given up, so the caller knows whether the transition is worth a log
/// line and a gauge write.
///
/// See [`SchedulerService::note_fleet_visible`] for why re-arming on a seen
/// heartbeat is safe, and why the one-way latch this replaced pinned
/// `talos_scheduler_readiness_degraded` at 1 on healthy fleets.
fn clear_holds_and_rearm(
    consecutive_holds: &std::sync::atomic::AtomicUsize,
    readiness_degraded: &std::sync::atomic::AtomicBool,
) -> bool {
    use std::sync::atomic::Ordering;

    consecutive_holds.store(0, Ordering::SeqCst);
    readiness_degraded.swap(false, Ordering::SeqCst)
}

/// Record one terminal scheduler dispatch outcome on
/// `talos_scheduler_dispatches_total{phase,outcome}`.
///
/// **The contract is EXACTLY ONE call per task spawned by
/// [`SchedulerService::spawn_workflow_execution`]**, on every path out —
/// including the ones that look like they do not matter. That is not tidiness:
/// `TalosSchedulerStartupHerdNotAbsorbed`'s runbook tells operators to
/// reconcile this counter against the boot backlog size logged by
/// `event_kind="scheduler_startup_backlog"`, and its expression divides the
/// failed/skipped count by the phase total. Both readings are wrong, silently,
/// for every terminal path that records nothing — which was nine of them
/// (workflow load, graph missing, graph error, actor not runnable, budget
/// pre-check, capability ceiling, auth-gate DB error, execution-row create,
/// engine build) plus the fence arm and the two semaphore-closed arms, until
/// the review of 6dde58b. `every_terminal_path_records_an_outcome` in this
/// crate's tests enumerates them.
///
/// Inert when metrics are not wired (unit tests, any process without
/// `set_global`) — never unwraps, per [`talos_metrics::global`]'s contract.
/// Both label values come from the `talos_metrics::SCHEDULER_*` constants that
/// the pre-seed loop iterates, so an emitted series is always a seeded one.
fn record_dispatch(phase: &'static str, outcome: &'static str) {
    if let Some(m) = talos_metrics::global() {
        m.scheduler_dispatches_total
            .with_label_values(&[phase, outcome])
            .inc();
    }
}

/// Runs a single scheduled workflow execution to completion.
#[allow(clippy::too_many_arguments)]
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
    // Which dispatch phase this run belongs to — `startup` for the backlog
    // drained by the first poll after boot, `steady` otherwise. Carried only
    // so the terminal outcome lands on the right series; it changes no
    // behaviour inside this function.
    phase: &'static str,
) {
    // 1. Fetch the workflow's actor binding + description BEFORE inserting the
    //    execution row so the row carries the workflow's bound actor_id from the
    //    start. Pre-fix (MCP-21, 2026-05-07) the scheduler inserted with no
    //    actor_id and the binding never landed on the execution row, breaking
    //    `get_actor_summary.executions` counts and per-actor audit queries on
    //    scheduler-fired runs. `actor_id` / `description` are workflow-level
    //    (not versioned), so they still come off the `workflows` row.
    #[derive(sqlx::FromRow)]
    struct WorkflowMeta {
        actor_id: Option<uuid::Uuid>,
        description: Option<String>,
    }

    let workflow = match sqlx::query_as::<_, WorkflowMeta>(
        "SELECT actor_id, description FROM workflows WHERE id = $1 AND user_id = $2",
    )
    .bind(workflow_id)
    .bind(user_id)
    .fetch_one(&db_pool)
    .await
    {
        Ok(w) => w,
        Err(e) => {
            record_dispatch(phase, talos_metrics::SCHEDULER_OUTCOME_FAILED);
            tracing::error!(
                execution_id = %execution_id,
                workflow_id = %workflow_id,
                "Scheduler: failed to load workflow before INSERT: {}",
                e
            );
            return;
        }
    };

    // 1.1. Resolve the graph to RUN the SAME way every manual/programmatic
    //      trigger does (`trigger.rs` + `call_workflow` both call
    //      `get_active_version_graph`): the ACTIVE PUBLISHED version, falling
    //      back to the draft `workflows.graph_json` only when the workflow has
    //      never been published.
    //
    //      Root cause (2026-07-20, pa-morning-dispatch fuel exhaustion): the
    //      scheduler previously ran the DRAFT graph unconditionally
    //      (`SELECT graph_json FROM workflows` + `version_id = None`), while
    //      manual triggers ran the published active version. A published
    //      workflow's scheduled fires therefore executed a DIFFERENT graph than
    //      its manual runs — ANY draft/published divergence (per-node `max_fuel`
    //      overrides, node configs, added/removed nodes) silently changed
    //      behavior between the two trigger sources. Here the published version
    //      carried the compose/send `max_fuel` overrides but the draft did not,
    //      so scheduled runs fell back to the too-low module-row default and
    //      exhausted fuel while manual runs honored the override. Aligning the
    //      graph source (and recording the resolved `version_id` below) makes a
    //      scheduled fire run exactly what was published — consistent with every
    //      other trigger path — and fixes the fuel divergence at the source.
    let workflow_repo = talos_workflow_repository::WorkflowRepository::new(db_pool.clone());
    let (graph_json, resolved_version_id): (String, Option<Uuid>) = match workflow_repo
        .get_active_version_graph(workflow_id, user_id)
        .await
    {
        Ok(Some(pair)) => pair,
        Ok(None) => {
            record_dispatch(phase, talos_metrics::SCHEDULER_OUTCOME_FAILED);
            tracing::error!(
                execution_id = %execution_id,
                workflow_id = %workflow_id,
                "Scheduler: no graph found for workflow (active version or draft) before INSERT"
            );
            return;
        }
        Err(e) => {
            record_dispatch(phase, talos_metrics::SCHEDULER_OUTCOME_FAILED);
            tracing::error!(
                execution_id = %execution_id,
                workflow_id = %workflow_id,
                "Scheduler: failed to resolve workflow graph before INSERT: {}",
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
        let actor_repo_for_auth = talos_actor_repository::ActorRepository::new(db_pool.clone());
        // Re-verify capability ceilings against the graph that will ACTUALLY run
        // (the resolved published/active graph above), not the draft.
        match talos_workflow_authorization::resolve_effective_actor(
            &workflow_repo,
            &actor_repo_for_auth,
            &db_pool,
            workflow.actor_id,
            user_id,
            &graph_json,
        )
        .await
        {
            Ok(resolved) => resolved,
            Err(talos_workflow_authorization::TriggerAuthError::ActorArchived)
            | Err(talos_workflow_authorization::TriggerAuthError::ActorTerminated)
            | Err(talos_workflow_authorization::TriggerAuthError::ActorNotFoundOrInactive) => {
                // `denied`, not `skipped`: an archived actor is a chronic
                // configuration state, unchanged by how many schedules came due
                // at once. Counting it as a herd symptom would fire
                // TalosSchedulerStartupHerdNotAbsorbed on every deploy with a
                // cause the number cannot support.
                record_dispatch(phase, talos_metrics::SCHEDULER_OUTCOME_DENIED);
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
                // `skipped`, matching this gate's own backstop sibling further
                // down (`ConcurrencyAdmission::ActorBudgetExceeded`). This is
                // the budget/status PRE-CHECK: it refuses for capacity, it is
                // exactly what the boot herd exhausts, and it must land on the
                // same series the backstop does or the two halves of one
                // mechanism report as two different things.
                record_dispatch(phase, talos_metrics::SCHEDULER_OUTCOME_SKIPPED);
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
                // `denied`: a ceiling violation is authorship/config drift, not
                // load. Same reasoning as the actor-state arm above.
                record_dispatch(phase, talos_metrics::SCHEDULER_OUTCOME_DENIED);
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
                //
                // `failed`, not `denied`: the refusal is the fail-closed
                // posture of an ERROR, and an operator reading `denied` would
                // go looking for an actor misconfiguration that does not exist.
                record_dispatch(phase, talos_metrics::SCHEDULER_OUTCOME_FAILED);
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
            resolved_version_id, // the active published version (or None when running the draft fallback)
            None,                // priority — defaults to "normal"
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
            record_dispatch(phase, talos_metrics::SCHEDULER_OUTCOME_FAILED);
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
            // skipped fire simply drops to the next occurrence — the same
            // skip semantics as the MCP-708 auth-gate arms above.
            //
            // This comment used to justify that by appealing to "the
            // scheduler's skip-to-next philosophy (no catch-up storm)". There
            // is no such philosophy in this code: the due query is
            // `next_trigger_at <= NOW()` with NO lower bound, so a schedule
            // that came due while the controller was down fires on the next
            // poll however stale it is — on 2026-08-10 `pa-read-later-digest`
            // (cron `0 9 * * 6`, Saturday) executed on a MONDAY, ~2 days late.
            // That IS a catch-up storm, and it is what the startup ceiling
            // exists to pace. Whether stale occurrences should be run at all,
            // dropped, or coalesced is an open operator decision (a staleness
            // policy), DEFERRED and deliberately not changed here — but the
            // comment must not claim the opposite of what the code does.
            record_dispatch(phase, talos_metrics::SCHEDULER_OUTCOME_SKIPPED);
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
            // The branch that silently cost two DAILY crons a full day on
            // 2026-08-10 (`pa-autonomy-digest` 0 6 * * *, `pa-inbox-triage`
            // 37 7 * * 1-5): the boot herd burned the actor's per-minute
            // budget, these were refused, and "the next scheduled occurrence
            // will retry" meant tomorrow. Counting it is what makes a skip
            // EXPLICITLY VISIBLE rather than a WARN nobody reads.
            record_dispatch(phase, talos_metrics::SCHEDULER_OUTCOME_SKIPPED);
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
    // INTENT (PR #461 review follow-up): context injection deliberately keys
    // on `workflow.actor_id`, NOT the gate-resolved `effective_actor_id`.
    // For an unbound workflow the effective actor is the user's SHARED
    // auto-provisioned Default actor — a fallback identity/budget bucket
    // whose memory pool accumulates writes from every unbound flow. Injecting
    // that pool as `__actor_context__` would cross-contaminate unrelated
    // workflows (and feed LLM nodes other flows' synthetic outputs — the
    // metadata.kind poisoning class). A workflow that wants its memory read
    // back on scheduled runs must be bound to its own actor
    // (`set_workflow_actor_id`); writes under the Default actor remain
    // reachable via explicit `agent_memory::get/search` calls.
    let actor_context = if !talos_config::actor_context_injection_enabled() {
        // Fleet-wide kill-switch: skip the graph-RAG/DB assembly entirely (the
        // dispatch chokepoints refuse injection regardless — this avoids the
        // wasted lookup on every scheduled fire).
        None
    } else if let Some(actor_id) = workflow.actor_id {
        let context_hint = workflow.description.as_deref();
        // Pass `Some(execution_id)` so the smart path records memory-rank
        // PROVENANCE for this scheduled run (which keys were packed + their
        // ranking-feature snapshot) when `ENABLE_MEMORY_RANK_PROVENANCE` is on.
        // The scheduler is the PRIMARY actor-bound context-injection path, so it
        // is the main training-data source for the learned ranker. The execution
        // row already exists here (created at `create_execution_under_concurrency_
        // limit` above), so provenance rows join cleanly to `judge_scores`.
        match workflow_repo
            .get_relevant_actor_context(
                actor_id,
                20,
                context_hint,
                Some(execution_id),
                // Auto-injection (scheduled actor-bound run) → curated (durable
                // semantic+episodic) scope; never surfaces transient `working`
                // memory into the execution trace by default.
                talos_workflow_repository::MemoryScope::Curated,
            )
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
    let opts = talos_engine::builder::EngineOpts::for_run(workflow_id, graph_json.clone())
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
            // This arm already writes status='failed' on the execution row, so
            // an uncounted return here made the counter disagree with the very
            // table the runbook asks operators to reconcile it against. Placed
            // adjacent to the `return` rather than at the top of the arm: the
            // structural guard below reads a bounded window above each terminal
            // return, and a long arm would otherwise need a window wide enough
            // for a neighbouring arm's call to vouch for this one.
            record_dispatch(phase, talos_metrics::SCHEDULER_OUTCOME_FAILED);
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

            record_dispatch(phase, talos_metrics::SCHEDULER_OUTCOME_COMPLETED);
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
            //
            // Its own outcome, deliberately: it is neither a success nor a
            // failure of THIS dispatch, and folding it into either would
            // misreport. Leaving it uncounted was the alternative, and an
            // uncounted terminal path is what stops the counter being the
            // partition the runbook reconciles against.
            record_dispatch(phase, talos_metrics::SCHEDULER_OUTCOME_FENCED);
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

            record_dispatch(phase, talos_metrics::SCHEDULER_OUTCOME_FAILED);
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
mod startup_herd_tests {
    //! Guards on the startup-herd fix (2026-08-10). The defect these exist
    //! for is not "the counter is wrong" — it is "the counter never moves",
    //! which is invisible to `cargo check` and to any behavioural test that
    //! only asserts the scheduler still runs.

    /// Check 58's stated blind spot is that a metric incremented ONLY through
    /// a wrapper reads as live even when nothing calls the wrapper. So drive
    /// the PRODUCTION function — `record_dispatch`, the exact one the four
    /// terminal arms call — against a real registry and assert the series
    /// actually moves, for every (phase, outcome) pair.
    ///
    /// This is the only test in the crate that installs the process-global
    /// metrics registry (`set_global` is one-shot per process); keep it that
    /// way or the others will silently observe each other's increments.
    #[test]
    fn record_dispatch_moves_every_seeded_series() {
        let m = talos_metrics::TalosMetrics::new().expect("metrics registry");
        talos_metrics::set_global(m.clone());

        for phase in talos_metrics::SCHEDULER_DISPATCH_PHASES {
            for outcome in talos_metrics::SCHEDULER_DISPATCH_OUTCOMES {
                let before = m
                    .scheduler_dispatches_total
                    .with_label_values(&[phase, outcome])
                    .get();
                super::record_dispatch(phase, outcome);
                let after = m
                    .scheduler_dispatches_total
                    .with_label_values(&[phase, outcome])
                    .get();
                assert_eq!(
                    after,
                    before + 1.0,
                    "record_dispatch({phase}, {outcome}) must move its own series — \
                     a wrapper whose call sites were deleted still looks 'live' to \
                     the dead-metric lint, so this assertion is the real guard"
                );
            }
        }
    }

    /// The label values the emitting sites use must be exactly the ones the
    /// pre-seed loop iterates. If they drift, the emitted series is a
    /// DIFFERENT, unseeded one — and an unseeded counter is absent, which
    /// every `increase(...) > 0` alert reads as "no match". The alert would
    /// then be silenced by precisely the failure it exists to catch.
    #[test]
    fn emitted_labels_are_the_seeded_labels() {
        assert!(talos_metrics::SCHEDULER_DISPATCH_PHASES
            .contains(&talos_metrics::SCHEDULER_PHASE_STARTUP));
        assert!(talos_metrics::SCHEDULER_DISPATCH_PHASES
            .contains(&talos_metrics::SCHEDULER_PHASE_STEADY));
        for outcome in [
            talos_metrics::SCHEDULER_OUTCOME_COMPLETED,
            talos_metrics::SCHEDULER_OUTCOME_FAILED,
            talos_metrics::SCHEDULER_OUTCOME_SKIPPED,
            talos_metrics::SCHEDULER_OUTCOME_DENIED,
            talos_metrics::SCHEDULER_OUTCOME_FENCED,
        ] {
            assert!(
                talos_metrics::SCHEDULER_DISPATCH_OUTCOMES.contains(&outcome),
                "{outcome} is emitted but not seeded"
            );
        }
        // The list above must not drift from the emitting sites either: every
        // outcome constant this crate can emit is one of the five, and the
        // partition claim in the metric's docs depends on the closed set
        // staying closed.
        assert_eq!(
            talos_metrics::SCHEDULER_DISPATCH_OUTCOMES.len(),
            5,
            "a new outcome must be added to this test, to the pre-seed loop, and \
             to the herd alert's outcome selector — an unseeded series is absent, \
             and every `increase(...)` idiom reads absent as 'no match'"
        );
    }

    /// The startup ceiling has to actually BIND on the herd that motivated
    /// it. The pre-existing M6 semaphore did not: its default was 16 and
    /// exactly 15 schedules came due, so every one of them ran at once and
    /// the mitigation was a no-op on the only sample we have. A default that
    /// does not bind is the same defect one level up.
    #[test]
    fn startup_ceiling_binds_on_the_observed_herd() {
        const OBSERVED_HERD: usize = 15;
        assert!(
            super::DEFAULT_SCHEDULER_STARTUP_MAX_CONCURRENT < OBSERVED_HERD,
            "the startup ceiling must be below the observed boot herd ({OBSERVED_HERD}); \
             at or above it the fix cannot have changed anything"
        );
        assert!(
            super::DEFAULT_SCHEDULER_MAX_CONCURRENT_EXECUTIONS >= OBSERVED_HERD,
            "documents WHY the pre-existing ceiling did not bind — if this ever \
             drops below the herd size, the comment above the startup semaphore \
             is stale and needs rewriting"
        );
    }

    /// The chart's alert file, read at COMPILE time so the threshold this test
    /// asserts against is the one operators are actually paged by.
    ///
    /// A hardcoded copy is a vacuous pin (#630): change the alert to `> 25` and
    /// a local `const ALERT_HOLDS_THRESHOLD: usize = 10` still passes while the
    /// invariant it names is silently broken. That is exactly what this test
    /// did until the review of 6dde58b.
    ///
    /// `include_str!` inside a `#[cfg(test)]` module is stripped before macro
    /// expansion in a non-test build, so this does NOT make `deploy/` a build
    /// dependency of the controller image — which matters, because
    /// `.dockerignore` excludes `deploy/` from the build context. Verified by
    /// mutation: pointing this at a nonexistent path still lets
    /// `cargo check -p talos-scheduler` (lib only) pass, and fails
    /// `--all-targets`.
    const CHART_ALERTS_YAML: &str = include_str!("../../deploy/helm/talos/files/alerts.yaml");

    /// Pull the numeric threshold out of the `TalosSchedulerDispatchHeldNoFleet`
    /// expression in the chart's alert file.
    fn alert_holds_threshold() -> usize {
        const NEEDLE: &str = "increase(talos_scheduler_readiness_holds_total[15m]) >";
        let tail = CHART_ALERTS_YAML.split(NEEDLE).nth(1).unwrap_or_else(|| {
            panic!(
                "TalosSchedulerDispatchHeldNoFleet's expression no longer contains \
                 `{NEEDLE}`. If the alert was rewritten, update this parser — do NOT \
                 replace it with a hardcoded number, which is what made this test \
                 vacuous in the first place."
            )
        });
        tail.split_whitespace()
            .next()
            .and_then(|t| t.trim().parse::<usize>().ok())
            .unwrap_or_else(|| panic!("could not parse a threshold after `{NEEDLE}`"))
    }

    /// The barrier must GIVE UP, and it must give up after the alert has had
    /// a chance to fire. This is the invariant that stops the fix from being
    /// worse than the bug: an empty fleet view is ambiguous, and one of the
    /// readings it covers is `TALOS_WORKER_HEARTBEAT_INTERVAL_SECS=0` — a
    /// supported setting that disables heartbeat publishing entirely. A
    /// barrier with no give-up point would, on such a deployment, stop every
    /// scheduled workflow forever on a perfectly healthy fleet.
    ///
    /// Residual risk of deriving the threshold from the chart file: it proves
    /// agreement with what the CHART ships, not with what a given cluster runs
    /// — a Prometheus loading a hand-edited copy of these rules is outside what
    /// any in-repo test can see.
    #[test]
    fn readiness_barrier_gives_up_after_the_alert_can_fire() {
        let threshold = alert_holds_threshold();
        assert!(
            super::DEFAULT_SCHEDULER_READINESS_MAX_HOLDS > threshold,
            "the barrier must not give up before the hold alert can fire \
             (give-up at {}, alert at >{threshold}) — an operator should hear that \
             dispatch is blocked while the guarantee is still in force, not after \
             it has been silently dropped",
            super::DEFAULT_SCHEDULER_READINESS_MAX_HOLDS
        );
        // And it must be finite. A `usize::MAX` "bound" is not a bound.
        assert!(
            super::DEFAULT_SCHEDULER_READINESS_MAX_HOLDS < 1_000,
            "the give-up bound must be a real bound: at the 15s poll interval \
             this is the number of polls scheduled work can be withheld for"
        );
    }

    /// The readiness bound must clear two heartbeat intervals **at the worst
    /// interval an operator can configure**, not at the default.
    ///
    /// A worker that boots before the controller subscribes loses its first
    /// heartbeat outright (NATS core delivery is not retained), so the
    /// controller can only learn about it on the second; a bound below 2x would
    /// time out on a perfectly healthy fleet and hold a dispatch for no reason.
    ///
    /// The previous version of this test hardcoded a local
    /// `DEFAULT_HEARTBEAT_SECS: u64 = 30`, so it asserted the property only at
    /// the default and was structurally blind to the failing case: at the
    /// clamped MAXIMUM interval (45 s) the old 90 s bound equalled exactly two
    /// intervals, with none of the "full interval of margin" it documented. A
    /// test that can only pass is not a guard — #631's "security property as a
    /// number", one axis over.
    #[test]
    fn readiness_bound_clears_two_of_the_slowest_configurable_heartbeats() {
        let max_interval = talos_workflow_job_protocol::WORKER_HEARTBEAT_MAX_INTERVAL_SECS;
        assert!(
            super::DEFAULT_SCHEDULER_READINESS_TIMEOUT_SECS > 2 * max_interval,
            "readiness bound ({}) must exceed two of the SLOWEST configurable \
             heartbeat intervals ({max_interval}s each) with real margin — deriving \
             it from the 30s default is what hid a zero-margin bound",
            super::DEFAULT_SCHEDULER_READINESS_TIMEOUT_SECS
        );
        // And the margin must be a whole interval, which is the claim the
        // constant's doc comment actually makes.
        assert!(
            super::DEFAULT_SCHEDULER_READINESS_TIMEOUT_SECS - 2 * max_interval >= max_interval,
            "the documented margin is a FULL interval; anything less means the \
             comment overstates the bound"
        );
    }

    /// FIX 1's guard: the startup phase must survive a poll that ERRORS.
    ///
    /// The flag used to be consumed by a `swap(true, ..)` on the first line of
    /// `poll_and_trigger`, before `db_pool.begin()`. Every error path after it
    /// returns `Err` and the caller only logs — so a cold Postgres at
    /// controller boot (which co-occurs with the cold-start herd by
    /// construction) spent the startup phase without dispatching anything, and
    /// the next tick released the whole backlog labelled `phase="steady"`:
    /// under the 16-wide steady semaphore that provably did not bind on a herd
    /// of 15, and invisible to the alert built to catch exactly this.
    ///
    /// Drives the production function against a real pool pointed at a closed
    /// port, so the failure is a genuine `begin()` error rather than a stub.
    #[tokio::test]
    async fn startup_phase_survives_a_poll_that_never_committed() {
        use std::sync::atomic::{AtomicBool, Ordering};

        // Port 1 is reserved and closed; connect_lazy defers the (failing)
        // connect to first use, which is `begin()` inside the function.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_millis(250))
            .connect_lazy("postgres://talos:talos@127.0.0.1:1/talos_does_not_exist")
            .expect("lazy pool construction does not connect");

        let first_poll_done = AtomicBool::new(false);

        for attempt in 1..=3 {
            let err = super::SchedulerService::select_due_and_advance(&pool, &first_poll_done)
                .await
                .expect_err("a poll against a closed port must fail");
            assert!(
                err.contains("Failed to begin transaction"),
                "attempt {attempt} failed for an unexpected reason: {err}"
            );
            assert!(
                !first_poll_done.load(Ordering::SeqCst),
                "attempt {attempt}: a poll that never reached a commit must NOT spend \
                 the startup phase — the backlog it did not dispatch is still a \
                 startup backlog on the next tick"
            );
        }
    }

    /// The other half of the same invariant, and the reason the fix is not
    /// simply "consume it later": an empty first poll DOES spend the phase.
    ///
    /// A controller that restarts with nothing overdue has no backlog, so the
    /// first `*/15` cron to come due 15 s later must be `steady`. Deciding on
    /// "found work" instead of "reached a commit" would fire the herd alert on
    /// an ordinary steady-state failure.
    ///
    /// Asserted on the code path rather than the DB: the empty branch and the
    /// non-empty branch both `store(true)` immediately after their own
    /// `tx.commit()`, and every `?` between entry and those two stores leaves
    /// the flag untouched — which is what the test above drives live.
    #[test]
    fn the_startup_phase_is_spent_by_a_commit_not_by_finding_work() {
        let src = include_str!("lib.rs");
        let body = src
            .split("async fn select_due_and_advance(")
            .nth(1)
            .expect("select_due_and_advance must exist")
            .split("\n    /// Trigger a workflow execution")
            .next()
            .expect("function body");

        assert!(
            !body.contains("first_poll_done\n            .swap(")
                && !body.contains("first_poll_done.swap("),
            "the startup flag must not be consumed by a swap-on-entry again — that \
             is the exact shape that disarmed the ceiling on a cold-DB boot"
        );
        let stores = body.matches("first_poll_done.store(true").count();
        assert_eq!(
            stores, 2,
            "expected exactly two consumption points, both immediately after a \
             successful commit (the empty batch and the dispatched batch); found \
             {stores}"
        );
        // Statement lines only — a prose mention of `tx.commit()` in a comment
        // is not a commit, and counting one as if it were is the same
        // text-matching sloppiness this test exists to guard against.
        let commits = body
            .lines()
            .filter(|l| l.trim_start().starts_with("tx.commit()"))
            .count();
        assert_eq!(
            commits, 2,
            "if the number of commits changed, re-check that every one of them is \
             paired with a store — this test's arithmetic is the pairing"
        );
    }

    /// FIX 2's guard: the degraded gauge must be a LEVEL, not a one-way latch.
    ///
    /// Realistic trigger for the latch version: a slow worker image pull
    /// outlasts the give-up bound, the worker then arrives, everything is
    /// healthy — and `TalosSchedulerReadinessDegraded` (`== 1`, `for: 5m`)
    /// fires until the controller restarts. A red that cannot go green trains
    /// operators to ignore red.
    ///
    /// Drives the production transition functions, not a copy of them.
    #[test]
    fn a_visible_fleet_rearms_the_barrier() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        let holds = AtomicUsize::new(0);
        let degraded = AtomicBool::new(false);
        const MAX: usize = 3;

        // Hold up to the bound...
        for expected in 1..=MAX {
            assert_eq!(
                super::decide_hold(&holds, &degraded, MAX),
                super::HoldDecision::Hold { holds: expected }
            );
        }
        // ...then give up, once.
        assert_eq!(
            super::decide_hold(&holds, &degraded, MAX),
            super::HoldDecision::Degrade { holds: MAX + 1 }
        );
        assert!(degraded.load(Ordering::SeqCst));
        assert_eq!(
            super::decide_hold(&holds, &degraded, MAX),
            super::HoldDecision::AlreadyDegraded,
            "a degraded barrier must not re-log or re-count every 15s"
        );

        // A single visible fleet re-arms it. This is the assertion the latch
        // version could not satisfy at all.
        assert!(
            super::clear_holds_and_rearm(&holds, &degraded),
            "re-arming from a degraded state must report the transition so the \
             gauge and the log line follow"
        );
        assert!(
            !degraded.load(Ordering::SeqCst),
            "a seen heartbeat is strictly better evidence than the latch, which \
             only ever meant 'we had not seen one yet'"
        );
        assert_eq!(holds.load(Ordering::SeqCst), 0);

        // Re-arming from a healthy state is a no-op, so a healthy controller
        // does not emit a transition log line every 15 s.
        assert!(!super::clear_holds_and_rearm(&holds, &degraded));

        // And the barrier is genuinely back in force: it can hold and degrade
        // again, which also bounds re-arm thrash — the gauge cannot return to 1
        // until MAX consecutive holds have accumulated afresh.
        for expected in 1..=MAX {
            assert_eq!(
                super::decide_hold(&holds, &degraded, MAX),
                super::HoldDecision::Hold { holds: expected }
            );
        }
        assert_eq!(
            super::decide_hold(&holds, &degraded, MAX),
            super::HoldDecision::Degrade { holds: MAX + 1 }
        );
    }

    /// FIX 3's guard: `talos_scheduler_dispatches_total` is documented as a
    /// PARTITION of dispatch attempts, and the alert runbook tells operators to
    /// reconcile it against the boot backlog size. Nine terminal `return;`
    /// paths recorded nothing, so those numbers could not reconcile.
    ///
    /// Structural, because there is no runtime hook that observes "this task
    /// returned without recording": every bare `return;` between
    /// `spawn_workflow_execution` and the tests must have a `record_dispatch(`
    /// within the preceding window.
    ///
    /// **Stated limits.** The window is a heuristic: a lookback long enough to
    /// clear the multi-field `tracing::warn!` calls in the auth-gate arms is
    /// also long enough that a `record_dispatch` in a NEIGHBOURING arm could
    /// vouch for a `return;` that has none. It catches the likely regression —
    /// a newly added early return with no instrumentation at all — and does not
    /// prove the mapping of path to outcome, which only review does.
    #[test]
    fn every_terminal_path_records_an_outcome() {
        const LOOKBACK: usize = 20;

        let src = include_str!("lib.rs");
        let region = src
            .split("    fn spawn_workflow_execution(")
            .nth(1)
            .expect("spawn_workflow_execution must exist")
            .split("mod startup_herd_tests")
            .next()
            .expect("the dispatch region ends at this crate's tests");

        let lines: Vec<&str> = region.lines().collect();
        let mut unrecorded = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            if line.trim() != "return;" {
                continue;
            }
            let start = i.saturating_sub(LOOKBACK);
            if !lines[start..i]
                .iter()
                .any(|l| l.contains("record_dispatch("))
            {
                unrecorded.push(i);
            }
        }
        assert!(
            unrecorded.is_empty(),
            "every terminal path out of a spawned scheduler task must record an \
             outcome — an uncounted one makes the counter stop being the partition \
             the runbook reconciles against. Unrecorded `return;` at region lines \
             {unrecorded:?}"
        );
        // The scan must actually be scanning something: an empty region would
        // make the assertion above vacuously true.
        assert!(
            lines.iter().filter(|l| l.trim() == "return;").count() >= 9,
            "the region scan found almost no terminal returns — the split markers \
             have probably drifted, which would make this test pass by looking at \
             nothing"
        );
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
