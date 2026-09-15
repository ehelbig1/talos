//! The deployment-wide execution pause must be SETTABLE and must STOP starts.
//!
//! Measured 2026-09-14 (package BF): neither was true. The writer bound a TEXT
//! parameter into the `jsonb` `system_settings.value` column, which Postgres
//! refuses, so `pause_executions` failed on every call and no row ever existed;
//! and the scheduler (67% of a week's runs), the webhook router and the Gmail
//! push branch (32%) never read the flag. These tests drive the one home
//! (`talos_execution_pause`), the row-creation chokepoint and the scheduler's
//! claim against a real clone.
//!
//! Every refusal test carries a CONTROL that the same start is admitted when
//! the flag is clear — a gate that refused everything would pass the refusal
//! half alone — and every "nothing was written" claim is read back from the
//! table, because a variant alone would pass on a transaction that committed.
//!
//! DB tests on the `common` harness (each gets a template clone of the
//! migrated DB), so they belong in CTRL_TESTS, not TC_TESTS (sub-leg 64b).

mod common;
// The real `McpState` + response helpers, one home (2026-09-08).
#[path = "common/mcp.rs"]
mod mcp_common;

use sqlx::{Pool, Postgres};
use std::sync::atomic::{AtomicBool, Ordering};
use talos_execution_pause::{ExecutionPause, PauseRefusal};
use talos_scheduler::SchedulerService;
use talos_workflow_repository::{ConcurrencyAdmission, InitialExecutionStatus, WorkflowRepository};
use uuid::Uuid;

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'pause test')",
    )
    .bind(id)
    .bind(format!("execution-pause-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

/// `workflow_executions.actor_id` is NOT NULL: every run is attributed.
async fn seed_actor(pool: &Pool<Postgres>, user_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name, status) VALUES ($1, $2, $3, 'active')")
        .bind(id)
        .bind(user_id)
        .bind(format!("pause-actor-{id}"))
        .execute(pool)
        .await
        .expect("seed actor");
    id
}

async fn execution_rows(pool: &Pool<Postgres>, workflow_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM workflow_executions WHERE workflow_id = $1")
        .bind(workflow_id)
        .fetch_one(pool)
        .await
        .expect("count execution rows")
}

async fn admit(
    repo: &WorkflowRepository,
    user: Uuid,
    actor: Uuid,
    workflow: Uuid,
) -> ConcurrencyAdmission {
    repo.create_execution_under_concurrency_limit(
        Uuid::new_v4(),
        workflow,
        user,
        None,
        talos_workflow_repository::ExecutionPriority::Normal,
        Some(actor),
        None,
        None,
        None,
        InitialExecutionStatus::Running,
    )
    .await
    .expect("admission query")
}

/// Write a raw stored value, bypassing the writer — the shape a hand edit or a
/// pre-fix writer that Postgres HAD accepted would leave behind.
async fn store_raw_flag(pool: &Pool<Postgres>, json_literal: &str) {
    sqlx::query(
        "INSERT INTO system_settings (key, value) VALUES ('execution_paused', $1::jsonb) \
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(json_literal)
    .execute(pool)
    .await
    .expect("store raw flag");
}

/// The writer the MCP pause/resume tools call. On main this statement could
/// not execute at all; here it must store a JSON boolean the reader sees.
#[tokio::test]
async fn the_pause_writer_stores_a_boolean_the_reader_classifies() {
    let (pool, _db) = common::isolated_db_pool().await;

    assert_eq!(
        talos_execution_pause::read_execution_pause(&pool)
            .await
            .unwrap(),
        ExecutionPause::Running,
        "no row is running"
    );

    talos_execution_pause::set_execution_paused(&pool, true)
        .await
        .expect("pausing must succeed — before package BF it never did");
    assert_eq!(
        talos_execution_pause::read_execution_pause(&pool)
            .await
            .unwrap(),
        ExecutionPause::Paused
    );
    let stored_type: String = sqlx::query_scalar(
        "SELECT jsonb_typeof(value) FROM system_settings WHERE key = 'execution_paused'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        stored_type, "boolean",
        "a JSON boolean, not the string \"true\""
    );

    talos_execution_pause::set_execution_paused(&pool, false)
        .await
        .expect("resuming must succeed");
    assert_eq!(
        talos_execution_pause::read_execution_pause(&pool)
            .await
            .unwrap(),
        ExecutionPause::Running,
        "resume overwrites the row (ON CONFLICT), it does not add a second one"
    );
}

/// The row-creation chokepoint: every scheduler, webhook, trigger, call, bulk
/// and as-actors start passes through it.
#[tokio::test]
async fn the_chokepoint_writes_no_row_while_paused_and_admits_after_resume() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let actor = seed_actor(&pool, user).await;
    let workflow = common::create_test_workflow(&pool, user, "pause-chokepoint").await;
    let repo = WorkflowRepository::new(pool.clone());

    talos_execution_pause::set_execution_paused(&pool, true)
        .await
        .unwrap();
    assert!(matches!(
        admit(&repo, user, actor, workflow).await,
        ConcurrencyAdmission::ExecutionsPaused(PauseRefusal::Paused)
    ));
    assert_eq!(execution_rows(&pool, workflow).await, 0);

    // CONTROL: the same start, flag cleared, is admitted and writes its row.
    talos_execution_pause::set_execution_paused(&pool, false)
        .await
        .unwrap();
    assert!(matches!(
        admit(&repo, user, actor, workflow).await,
        ConcurrencyAdmission::Created
    ));
    assert_eq!(execution_rows(&pool, workflow).await, 1);
}

/// A stored value that is not a JSON boolean REFUSES. The old reader was
/// `(value)::text = 'true'`, which read every such value as running.
#[tokio::test]
async fn an_unclassifiable_flag_refuses_rather_than_admits() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let actor = seed_actor(&pool, user).await;
    let workflow = common::create_test_workflow(&pool, user, "pause-garbage").await;
    let repo = WorkflowRepository::new(pool.clone());

    // The string "true" is what the pre-fix TEXT writer would have stored had
    // Postgres coerced it.
    store_raw_flag(&pool, r#""true""#).await;
    assert_eq!(
        talos_execution_pause::read_execution_pause(&pool)
            .await
            .unwrap(),
        ExecutionPause::Unreadable
    );
    assert!(matches!(
        admit(&repo, user, actor, workflow).await,
        ConcurrencyAdmission::ExecutionsPaused(PauseRefusal::Unreadable)
    ));
    assert_eq!(execution_rows(&pool, workflow).await, 0);

    // CONTROL: a JSON `false` written the same raw way admits.
    store_raw_flag(&pool, "false").await;
    assert!(matches!(
        admit(&repo, user, actor, workflow).await,
        ConcurrencyAdmission::Created
    ));
}

/// `enqueue_workflow`'s batch twin of the chokepoint.
#[tokio::test]
async fn the_batch_chokepoint_admits_nothing_while_paused() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let actor = seed_actor(&pool, user).await;
    let workflow = common::create_test_workflow(&pool, user, "pause-batch").await;
    let repo = WorkflowRepository::new(pool.clone());
    let ids = [Uuid::new_v4(), Uuid::new_v4()];

    talos_execution_pause::set_execution_paused(&pool, true)
        .await
        .unwrap();
    let paused = repo
        .create_executions_batch_under_concurrency_limit(&ids, workflow, user, None, Some(actor))
        .await
        .expect("batch admission");
    assert_eq!(paused.paused, Some(PauseRefusal::Paused));
    assert_eq!(paused.inserted, 0);
    assert_eq!(execution_rows(&pool, workflow).await, 0);

    talos_execution_pause::set_execution_paused(&pool, false)
        .await
        .unwrap();
    let running = repo
        .create_executions_batch_under_concurrency_limit(&ids, workflow, user, None, Some(actor))
        .await
        .expect("batch admission");
    assert_eq!(running.paused, None);
    assert_eq!(running.inserted, 2);
}

async fn quiesce_inherited_schedules(pool: &Pool<Postgres>) {
    sqlx::query("UPDATE workflow_schedules SET is_enabled = false")
        .execute(pool)
        .await
        .expect("disable inherited schedules");
}

async fn seed_schedule(pool: &Pool<Postgres>, user_id: Uuid, next_trigger: &str) -> Uuid {
    let workflow_id = common::create_test_workflow(pool, user_id, "pause-schedule").await;
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflow_schedules (id, workflow_id, user_id, cron_expression, timezone, is_enabled, next_trigger_at) \
         VALUES ($1, $2, $3, '*/15 * * * *', 'UTC', true, NOW() + $4::interval)",
    )
    .bind(id)
    .bind(workflow_id)
    .bind(user_id)
    .bind(next_trigger)
    .execute(pool)
    .await
    .expect("seed schedule");
    id
}

async fn is_due(pool: &Pool<Postgres>, schedule_id: Uuid) -> bool {
    sqlx::query_scalar("SELECT next_trigger_at <= NOW() FROM workflow_schedules WHERE id = $1")
        .bind(schedule_id)
        .fetch_one(pool)
        .await
        .expect("read next_trigger_at")
}

/// DEFER, DON'T DROP (the operator's decision): a paused poll claims nothing,
/// leaves the due row due, and does not spend the boot flag — so the first poll
/// after resume claims it, under the startup ceiling.
#[tokio::test]
async fn a_paused_scheduler_poll_defers_due_schedules_without_claiming_them() {
    let (pool, _db) = common::isolated_db_pool().await;
    quiesce_inherited_schedules(&pool).await;
    let user = seed_user(&pool).await;
    let schedule = seed_schedule(&pool, user, "-70 minutes").await;

    talos_execution_pause::set_execution_paused(&pool, true)
        .await
        .unwrap();
    let first_poll_done = AtomicBool::new(false);
    let deferred = SchedulerService::select_due_and_advance(&pool, &first_poll_done)
        .await
        .expect("paused poll");
    assert_eq!(deferred.deferred_by_pause, Some(PauseRefusal::Paused));
    assert!(deferred.to_spawn.is_empty(), "a paused poll claims nothing");
    assert!(
        is_due(&pool, schedule).await,
        "the schedule is still due — advancing it would DROP the fire"
    );
    assert!(
        !first_poll_done.load(Ordering::SeqCst),
        "a paused boot has not drained its backlog; the boot flag stays unspent"
    );

    // CONTROL + the resume half: the flag cleared, the same poll claims it.
    talos_execution_pause::set_execution_paused(&pool, false)
        .await
        .unwrap();
    let resumed = SchedulerService::select_due_and_advance(&pool, &first_poll_done)
        .await
        .expect("resumed poll");
    assert_eq!(resumed.deferred_by_pause, None);
    assert_eq!(resumed.to_spawn.len(), 1);
    assert_eq!(resumed.to_spawn[0].2, schedule);
    assert_eq!(
        resumed.phase,
        talos_metrics::SCHEDULER_PHASE_STARTUP,
        "the backlog a paused boot deferred still drains under the startup ceiling"
    );
    assert!(!is_due(&pool, schedule).await, "claimed and advanced");
}

/// A fire CLAIMED before the pause and refused at row creation: the claim had
/// already advanced `next_trigger_at`, so without the re-arm that fire is gone.
#[tokio::test]
async fn a_claimed_fire_refused_by_the_pause_is_rearmed_not_dropped() {
    let (pool, _db) = common::isolated_db_pool().await;
    quiesce_inherited_schedules(&pool).await;
    let user = seed_user(&pool).await;

    // The claim's post-state: advanced to the next occurrence.
    let claimed = seed_schedule(&pool, user, "15 minutes").await;
    assert!(!is_due(&pool, claimed).await);
    let rearmed = talos_scheduler::rearm_schedule_deferred_by_pause(&pool, claimed)
        .await
        .expect("re-arm");
    assert_eq!(rearmed, 1);
    assert!(
        is_due(&pool, claimed).await,
        "re-armed: due again, so the first poll after resume fires it"
    );

    // Never moves a time LATER: an already-due row is left exactly as it is.
    let already_due = seed_schedule(&pool, user, "-5 minutes").await;
    let before: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT next_trigger_at FROM workflow_schedules WHERE id = $1")
            .bind(already_due)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        talos_scheduler::rearm_schedule_deferred_by_pause(&pool, already_due)
            .await
            .unwrap(),
        0
    );
    let after: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT next_trigger_at FROM workflow_schedules WHERE id = $1")
            .bind(already_due)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(before, after);

    // Never revives a schedule someone disabled after the claim.
    let disabled = seed_schedule(&pool, user, "15 minutes").await;
    sqlx::query("UPDATE workflow_schedules SET is_enabled = false WHERE id = $1")
        .bind(disabled)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        talos_scheduler::rearm_schedule_deferred_by_pause(&pool, disabled)
            .await
            .unwrap(),
        0
    );
    assert!(!is_due(&pool, disabled).await);
}

/// The MCP handlers' shared entry gate (`trigger_workflow`'s MCP twins,
/// `call_workflow`, `bulk_trigger_workflow`, `trigger_workflow_as_actors`,
/// `enqueue_workflow`, `test_workflow`, `test_workflow_draft`). Before package
/// BF it read the flag through a repository copy that could never see a set
/// flag; it now reads the one home.
#[tokio::test]
async fn the_mcp_entry_gate_refuses_while_paused_and_admits_after_resume() {
    let (pool, _db) = common::isolated_db_pool().await;
    let repo = WorkflowRepository::new(pool.clone());

    talos_execution_pause::set_execution_paused(&pool, true)
        .await
        .unwrap();
    let refused = talos_mcp_handlers::utils::enforce_executions_not_paused(&repo, None)
        .await
        .expect_err("a paused deployment refuses the MCP start");
    let body = serde_json::to_string(&refused).unwrap();
    assert!(
        body.contains("Execution queue is paused"),
        "the operator-facing sentence clients already match on: {body}"
    );

    talos_execution_pause::set_execution_paused(&pool, false)
        .await
        .unwrap();
    assert!(
        talos_mcp_handlers::utils::enforce_executions_not_paused(&repo, None)
            .await
            .is_ok(),
        "CONTROL: cleared flag admits"
    );
}

fn watch_row(
    module_id: Option<Uuid>,
    workflow_id: Option<Uuid>,
) -> talos_gmail::watch::GmailWatchRow {
    talos_gmail::watch::GmailWatchRow {
        id: Uuid::new_v4(),
        integration_id: Uuid::new_v4(),
        email_address: "u@example.com".to_string(),
        topic_name: "projects/p/topics/t".to_string(),
        history_id: 42,
        label_ids: vec![],
        expiration_ms: 0,
        module_id,
        workflow_id,
        created_at_ms: 0,
        updated_at_ms: 0,
    }
}

/// The Gmail push decision (32% of a week's runs came through this path). A
/// deferred push is answered 503 BEFORE the history cursor moves; an unbound
/// watch is never deferred; a flag the database cannot return defers too.
#[tokio::test]
async fn a_bound_gmail_push_is_deferred_while_paused_and_an_unbound_one_is_not() {
    let (pool, _db) = common::isolated_db_pool().await;
    let bound = watch_row(None, Some(Uuid::new_v4()));
    let module_bound = watch_row(Some(Uuid::new_v4()), None);
    let unbound = watch_row(None, None);

    // CONTROL: running admits every push.
    assert!(!talos_gmail::dispatch::execution_pause_defers_push(&pool, &bound).await);

    talos_execution_pause::set_execution_paused(&pool, true)
        .await
        .unwrap();
    assert!(talos_gmail::dispatch::execution_pause_defers_push(&pool, &bound).await);
    assert!(talos_gmail::dispatch::execution_pause_defers_push(&pool, &module_bound).await);
    assert!(
        !talos_gmail::dispatch::execution_pause_defers_push(&pool, &unbound).await,
        "an unbound watch starts nothing — it keeps acking and advancing its cursor"
    );

    // Fail closed: a pool that cannot connect is not "running".
    let unreachable = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(200))
        .connect_lazy("postgres://nobody:nothing@127.0.0.1:1/none")
        .expect("lazy pool");
    assert!(talos_gmail::dispatch::execution_pause_defers_push(&unreachable, &bound).await);
}

// ───────────── package BG: the remaining start paths ─────────────

/// The ONE push rule every push integration calls (Gmail, Google Calendar,
/// GCP): a push that starts nothing is admitted even while paused; a bound one
/// is deferred while paused; a flag the database cannot return defers too.
#[tokio::test]
async fn the_shared_push_rule_defers_only_pushes_that_start_work() {
    use talos_execution_pause::{push_admission, PauseGatePath, PushAdmission};
    let (pool, _db) = common::isolated_db_pool().await;

    assert_eq!(
        push_admission(&pool, true, PauseGatePath::GcalPush).await,
        PushAdmission::Admit,
        "CONTROL: running admits a bound push"
    );
    talos_execution_pause::set_execution_paused(&pool, true)
        .await
        .unwrap();
    assert_eq!(
        push_admission(&pool, true, PauseGatePath::GcalPush).await,
        PushAdmission::Defer(PauseRefusal::Paused)
    );
    assert_eq!(
        push_admission(&pool, false, PauseGatePath::GcpPush).await,
        PushAdmission::Admit,
        "a push that starts nothing keeps acking and advancing its cursor"
    );
    let unreachable = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(200))
        .connect_lazy("postgres://nobody:nothing@127.0.0.1:1/none")
        .expect("lazy pool");
    assert_eq!(
        push_admission(&unreachable, true, PauseGatePath::GcpPush).await,
        PushAdmission::DeferReadFailed
    );
}

async fn seed_gate(
    pool: &Pool<Postgres>,
    user: Uuid,
    continuation: Option<Uuid>,
) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let token = format!(
        "{:032x}{:032x}",
        Uuid::new_v4().as_u128(),
        Uuid::new_v4().as_u128()
    );
    sqlx::query(
        "INSERT INTO workflow_approval_gates (id, user_id, title, token, continuation_workflow_id) \
         VALUES ($1, $2, 'pause gate', $3, $4)",
    )
    .bind(id)
    .bind(user)
    .bind(&token)
    .bind(continuation)
    .execute(pool)
    .await
    .expect("seed gate");
    (id, token)
}

async fn gate_status(pool: &Pool<Postgres>, id: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM workflow_approval_gates WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("gate status")
}

async fn seed_suspension(pool: &Pool<Postgres>, user: Uuid, continuation: Option<Uuid>) -> String {
    let correlation = format!(
        "{:032x}{:032x}",
        Uuid::new_v4().as_u128(),
        Uuid::new_v4().as_u128()
    );
    sqlx::query(
        "INSERT INTO workflow_suspensions (user_id, correlation_id, continuation_workflow_id, callback_url) \
         VALUES ($1, $2, $3, 'http://localhost/cb')",
    )
    .bind(user)
    .bind(&correlation)
    .bind(continuation)
    .execute(pool)
    .await
    .expect("seed suspension");
    correlation
}

async fn suspension_status(pool: &Pool<Postgres>, correlation: &str) -> String {
    sqlx::query_scalar("SELECT status FROM workflow_suspensions WHERE correlation_id = $1")
        .bind(correlation)
        .fetch_one(pool)
        .await
        .expect("suspension status")
}

async fn mcp_resolve(
    state: &controller::mcp::McpState,
    user: Uuid,
    gate: Uuid,
    resolution: &str,
) -> controller::mcp::types::JsonRpcResponse {
    controller::mcp::advanced::dispatch(
        "resolve_approval_gate",
        Some(serde_json::json!(1)),
        &serde_json::json!({"gate_id": gate, "resolution": resolution}),
        state,
        mcp_common::agent(user),
    )
    .await
    .expect("resolve_approval_gate is dispatched")
}

/// MCP `resolve_approval_gate`: an approval that would dispatch a continuation
/// is refused BEFORE the single-use resolve, so the gate stays pending and can
/// be approved after resume. A rejection starts nothing and is accepted.
#[tokio::test]
async fn a_paused_mcp_approval_leaves_the_gate_pending() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let continuation = common::create_test_workflow(&pool, user, "pause-continuation").await;
    let state = mcp_common::mcp_state(pool.clone()).await;

    let (gate, _) = seed_gate(&pool, user, Some(continuation)).await;
    talos_execution_pause::set_execution_paused(&pool, true)
        .await
        .unwrap();
    let refused = mcp_resolve(&state, user, gate, "approve").await;
    let msg = mcp_common::error_message(&refused);
    assert!(msg.contains("still pending"), "{msg}");
    assert_eq!(
        gate_status(&pool, gate).await,
        "pending",
        "nothing consumed"
    );

    // A rejection dispatches nothing: accepted while paused.
    let (rejected, _) = seed_gate(&pool, user, Some(continuation)).await;
    let _ = mcp_resolve(&state, user, rejected, "reject").await;
    assert_eq!(gate_status(&pool, rejected).await, "rejected");

    // CONTROL: resumed, the same approval resolves the gate.
    talos_execution_pause::set_execution_paused(&pool, false)
        .await
        .unwrap();
    let _ = mcp_resolve(&state, user, gate, "approve").await;
    assert_eq!(gate_status(&pool, gate).await, "approved");
}

/// MCP `resume_workflow_by_correlation_id`: refused BEFORE the claim.
#[tokio::test]
async fn a_paused_mcp_suspension_resume_consumes_nothing() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let continuation = common::create_test_workflow(&pool, user, "pause-suspension").await;
    let state = mcp_common::mcp_state(pool.clone()).await;
    let correlation = seed_suspension(&pool, user, Some(continuation)).await;
    let args = serde_json::json!({"correlation_id": correlation});
    let resume = || {
        controller::mcp::advanced::dispatch(
            "resume_workflow_by_correlation_id",
            Some(serde_json::json!(1)),
            &args,
            &state,
            mcp_common::agent(user),
        )
    };

    talos_execution_pause::set_execution_paused(&pool, true)
        .await
        .unwrap();
    let refused = resume().await.expect("dispatched");
    assert!(mcp_common::error_message(&refused).contains("still pending"));
    assert_eq!(suspension_status(&pool, &correlation).await, "waiting");

    talos_execution_pause::set_execution_paused(&pool, false)
        .await
        .unwrap();
    let _ = resume().await.expect("dispatched");
    assert_eq!(suspension_status(&pool, &correlation).await, "resumed");
}

fn registry(pool: &Pool<Postgres>) -> std::sync::Arc<talos_registry::ModuleRegistry> {
    std::sync::Arc::new(talos_registry::ModuleRegistry::new(pool.clone(), None))
}

/// The approve LINK (a capability URL, no session): 503 + the gate stays
/// pending while paused; resumed, the same link approves.
#[tokio::test]
async fn a_paused_approve_link_answers_503_and_consumes_nothing() {
    use axum::extract::{Extension, Path};
    use axum::response::IntoResponse;
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let continuation = common::create_test_workflow(&pool, user, "pause-link").await;
    let (gate, token) = seed_gate(&pool, user, Some(continuation)).await;
    let click = |token: String| {
        talos_webhooks::approval_gate_handler(
            Path((token, "approve".to_string())),
            Extension(pool.clone()),
            Extension(None::<std::sync::Arc<async_nats::Client>>),
            Extension(registry(&pool)),
            Extension(None),
        )
    };

    talos_execution_pause::set_execution_paused(&pool, true)
        .await
        .unwrap();
    let resp = click(token.clone()).await.into_response();
    assert_eq!(resp.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
    assert!(resp.headers().contains_key(axum::http::header::RETRY_AFTER));
    assert_eq!(gate_status(&pool, gate).await, "pending");

    talos_execution_pause::set_execution_paused(&pool, false)
        .await
        .unwrap();
    let _ = click(token).await.into_response();
    assert_eq!(gate_status(&pool, gate).await, "approved", "CONTROL");
}

/// The unauthenticated suspension callback: a live suspension with a
/// continuation is deferred (503, still waiting); an UNKNOWN id still gets 404
/// while paused (no "is the platform paused?" oracle without a capability); a
/// suspension with no continuation starts nothing and is resumed.
#[tokio::test]
async fn a_paused_suspension_callback_defers_only_a_live_continuation() {
    use axum::extract::{Extension, Path};
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let continuation = common::create_test_workflow(&pool, user, "pause-callback").await;
    let with_continuation = seed_suspension(&pool, user, Some(continuation)).await;
    let bare = seed_suspension(&pool, user, None).await;
    let call = |correlation: String| {
        talos_webhooks::suspension_callback_handler(
            Path(correlation),
            Extension(pool.clone()),
            Extension(registry(&pool)),
            Extension(None::<std::sync::Arc<async_nats::Client>>),
            Extension(None),
            axum::body::Bytes::new(),
        )
    };

    talos_execution_pause::set_execution_paused(&pool, true)
        .await
        .unwrap();
    let deferred = call(with_continuation.clone()).await;
    assert_eq!(
        deferred.status(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        suspension_status(&pool, &with_continuation).await,
        "waiting"
    );

    let unknown = call(format!("{:064x}", 7u8)).await;
    assert_eq!(
        unknown.status(),
        axum::http::StatusCode::NOT_FOUND,
        "without a live capability the caller learns nothing about the pause"
    );

    let _ = call(bare.clone()).await;
    assert_eq!(
        suspension_status(&pool, &bare).await,
        "resumed",
        "no continuation → starts nothing → not deferred"
    );

    talos_execution_pause::set_execution_paused(&pool, false)
        .await
        .unwrap();
    let _ = call(with_continuation.clone()).await;
    assert_eq!(
        suspension_status(&pool, &with_continuation).await,
        "resumed",
        "CONTROL"
    );
}
