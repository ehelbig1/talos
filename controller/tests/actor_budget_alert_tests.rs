//! `on_budget_exceeded = 'alert'` raises an alert (package CD, 2026-09-17).
//!
//! Until this package `alert` refused a start exactly as `block` did and
//! nothing alerted; a budget refusal was only a returned error string. These
//! tests drive the three places a refusal is decided — the atomic backstop at
//! row creation and the two pre-checks — against a real clone, and read the
//! counter and `ops_alerts` back. Every alert test has a `block` control that
//! must refuse identically and write no alert.
//!
//! `on_budget_exceeded = 'suspend'` raises one too (2026-10-06): the alert
//! that says the actor is suspended, raised by the start that suspended it
//! and closed by the resume. See the tests from
//! `a_budget_suspension_raises_one_alert_and_a_resume_closes_it` on.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use sqlx::{Pool, Postgres};
use talos_actor_repository::ActorRepository;
use talos_workflow_repository::{ConcurrencyAdmission, InitialExecutionStatus, WorkflowRepository};
use uuid::Uuid;

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'budget')",
    )
    .bind(id)
    .bind(format!("budget-alert-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

async fn seed_actor(pool: &Pool<Postgres>, user: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name, status) VALUES ($1, $2, $3, 'active')")
        .bind(id)
        .bind(user)
        .bind(format!("budget-actor-{id}"))
        .execute(pool)
        .await
        .expect("seed actor");
    id
}

async fn admit(
    repo: &WorkflowRepository,
    user: Uuid,
    actor: Uuid,
    wf: Uuid,
) -> ConcurrencyAdmission {
    repo.create_execution_under_concurrency_limit(
        Uuid::new_v4(),
        wf,
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

async fn set_policy(pool: &Pool<Postgres>, actor: Uuid, column: &str, cap: i64, mode: &str) {
    // `column` is a test constant, never input.
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "INSERT INTO actor_budget_policies (actor_id, {column}, on_budget_exceeded) VALUES ($1, $2, $3)"
    )))
    .bind(actor)
    .bind(cap)
    .bind(mode)
    .execute(pool)
    .await
    .expect("seed budget policy");
}

async fn budget_alerts(pool: &Pool<Postgres>, actor: Uuid) -> Vec<(String, Uuid, i32, String)> {
    sqlx::query_as(
        "SELECT dedup_key, user_id, occurrence_count, title FROM ops_alerts \
         WHERE dedup_key LIKE $1 ORDER BY dedup_key",
    )
    .bind(format!("talos/actor/{actor}/budget/%"))
    .fetch_all(pool)
    .await
    .expect("read ops_alerts")
}

fn refusals(cap: &str, mode: &str) -> f64 {
    talos_metrics::set_global(talos_metrics::TalosMetrics::new().expect("metrics"));
    talos_metrics::global()
        .expect("global metrics")
        .actor_budget_refusals_total
        .with_label_values(&[cap, mode])
        .get()
}

/// Every cap the backstop enforces: (policy column, cap label, count the
/// seeded usage produces).
const BACKSTOP_CAPS: [(&str, &str, i64); 5] = [
    ("max_workflows_per_minute", "per_minute", 1),
    ("max_executions_per_hour", "per_hour", 1),
    ("max_executions_total", "total", 1),
    ("max_fuel_per_hour", "fuel_per_hour", 5),
    ("max_llm_tokens_per_day", "llm_tokens_per_day", 5),
];

/// One admitted execution plus 5 fuel and 5 LLM tokens of usage, then a
/// policy capping `column` at 1 — so exactly that cap refuses the next start.
async fn actor_at_cap(pool: &Pool<Postgres>, column: &str, mode: &str) -> (Uuid, Uuid, Uuid) {
    let user = seed_user(pool).await;
    let actor = seed_actor(pool, user).await;
    let wf = common::create_test_workflow(pool, user, &format!("budget-wf-{actor}")).await;
    let repo = WorkflowRepository::new(pool.clone());
    assert!(matches!(
        admit(&repo, user, actor, wf).await,
        ConcurrencyAdmission::Created
    ));
    sqlx::query(
        "INSERT INTO execution_cost_rollup (actor_id, workflow_id, execution_id, node_id, fuel_consumed) \
         VALUES ($1, $2, $3, 'n', 5)",
    )
    .bind(actor)
    .bind(wf)
    .bind(Uuid::new_v4())
    .execute(pool)
    .await
    .expect("seed fuel");
    sqlx::query(
        "INSERT INTO llm_usage (actor_id, user_id, provider, model, prompt_tokens, completion_tokens) \
         VALUES ($1, $2, 'test', 'test', 3, 2)",
    )
    .bind(actor)
    .bind(user)
    .execute(pool)
    .await
    .expect("seed tokens");
    set_policy(pool, actor, column, 1, mode).await;
    (user, actor, wf)
}

#[tokio::test]
async fn the_backstop_raises_one_alert_per_actor_and_cap_in_alert_mode() {
    let (pool, _db) = common::isolated_db_pool().await;
    let repo = WorkflowRepository::new(pool.clone());
    for (column, cap, expected_count) in BACKSTOP_CAPS {
        let (user, actor, wf) = actor_at_cap(&pool, column, "alert").await;
        let before = refusals(cap, "alert");
        for _ in 0..3 {
            match admit(&repo, user, actor, wf).await {
                ConcurrencyAdmission::ActorBudgetExceeded { kind, limit, count } => {
                    assert_eq!((kind, limit, count), (cap, 1, expected_count));
                }
                other => panic!("{cap}: expected a budget refusal, got {other:?}"),
            }
        }
        assert!(
            refusals(cap, "alert") - before >= 3.0,
            "{cap}: every refusal is counted"
        );

        let alerts = budget_alerts(&pool, actor).await;
        assert_eq!(
            alerts.len(),
            1,
            "{cap}: one alert for the actor's cap: {alerts:?}"
        );
        let (key, owner, occurrences, title) = &alerts[0];
        assert_eq!(key, &format!("talos/actor/{actor}/budget/{cap}"));
        assert_eq!(*owner, user, "{cap}: scoped to the actor's owner");
        assert_eq!(
            *occurrences, 1,
            "{cap}: repeats inside the window are throttled, not re-written"
        );
        assert!(
            title.contains(&format!("({cap}): {expected_count} ")) && title.contains("limit 1"),
            "{title}"
        );
    }
}

#[tokio::test]
async fn block_mode_refuses_identically_and_raises_no_alert() {
    let (pool, _db) = common::isolated_db_pool().await;
    let (user, actor, wf) = actor_at_cap(&pool, "max_executions_per_hour", "block").await;
    let repo = WorkflowRepository::new(pool.clone());
    let before = refusals("per_hour", "block");
    assert!(matches!(
        admit(&repo, user, actor, wf).await,
        ConcurrencyAdmission::ActorBudgetExceeded {
            kind: "per_hour",
            ..
        }
    ));
    assert!(refusals("per_hour", "block") - before >= 1.0);
    assert!(
        budget_alerts(&pool, actor).await.is_empty(),
        "block raises no alert"
    );
}

#[tokio::test]
async fn the_actor_repository_precheck_raises_the_alert() {
    let (pool, _db) = common::isolated_db_pool().await;
    for (column, cap, needle) in [
        ("max_executions_per_hour", "per_hour", "last hour"),
        ("max_executions_total", "total", "total executions"),
    ] {
        let (_user, actor, _wf) = actor_at_cap(&pool, column, "alert").await;
        let err = ActorRepository::new(pool.clone())
            .check_execution_allowed(actor)
            .await
            .expect_err("the cap refuses");
        assert!(err.contains(needle), "{cap}: {err}");
        let alerts = budget_alerts(&pool, actor).await;
        assert_eq!(alerts.len(), 1, "{cap}: {alerts:?}");
        assert_eq!(alerts[0].0, format!("talos/actor/{actor}/budget/{cap}"));
    }
}

#[tokio::test]
async fn the_budget_precheck_raises_the_alert() {
    let (pool, _db) = common::isolated_db_pool().await;
    for (column, cap, needle) in [
        ("max_executions_per_hour", "per_hour", "last hour"),
        ("max_executions_total", "total", "lifetime cap"),
        ("max_llm_tokens_per_day", "llm_tokens_per_day", "LLM tokens"),
    ] {
        let (_user, actor, _wf) = actor_at_cap(&pool, column, "alert").await;
        let err = talos_actor_repository::budget_precheck::check_execution_allowed(&pool, actor)
            .await
            .expect_err("the cap refuses");
        assert!(err.contains(needle), "{cap}: {err}");
        let alerts = budget_alerts(&pool, actor).await;
        assert_eq!(alerts.len(), 1, "{cap}: {alerts:?}");
        assert_eq!(alerts[0].0, format!("talos/actor/{actor}/budget/{cap}"));
    }
}

/// (status, severity, occurrence_count, resolved_source, user_id) of the
/// actor's suspension alert, if it has one.
async fn suspension_alert(
    pool: &Pool<Postgres>,
    actor: Uuid,
) -> Option<(String, String, i32, Option<String>, Uuid)> {
    sqlx::query_as(
        "SELECT status, severity, occurrence_count, resolved_source, user_id FROM ops_alerts \
         WHERE dedup_key = $1",
    )
    .bind(format!("talos/actor/{actor}/suspended"))
    .fetch_optional(pool)
    .await
    .expect("read ops_alerts")
}

async fn actor_status(pool: &Pool<Postgres>, actor: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM actors WHERE id = $1")
        .bind(actor)
        .fetch_one(pool)
        .await
        .expect("read actor status")
}

/// `on_budget_exceeded = 'suspend'` at the hourly cap: the actor is
/// suspended AND an alert says so (2026-10-06). Until then the suspension was
/// a status column — measured, one stopped every workflow of an actor for
/// 1 h 45 min with nothing raised.
#[tokio::test]
async fn a_budget_suspension_raises_one_alert_and_a_resume_closes_it() {
    let (pool, _db) = common::isolated_db_pool().await;
    let (user, actor, _wf) = actor_at_cap(&pool, "max_executions_per_hour", "suspend").await;
    let repo = ActorRepository::new(pool.clone());

    let err = talos_actor_repository::budget_precheck::check_execution_allowed(&pool, actor)
        .await
        .expect_err("the cap refuses");
    assert!(err.contains("last hour"), "{err}");
    assert_eq!(actor_status(&pool, actor).await, "suspended");
    let (status, severity, occurrences, resolved_source, owner) =
        suspension_alert(&pool, actor).await.expect("one alert");
    assert_eq!(
        (
            status.as_str(),
            severity.as_str(),
            occurrences,
            resolved_source,
            owner
        ),
        ("new", "high", 1, None, user)
    );
    // It is a different row from a refusal alert, and `suspend` raises none.
    assert!(budget_alerts(&pool, actor).await.is_empty());

    // Further starts are refused by the status: the alert is not raised again.
    for _ in 0..3 {
        let err = talos_actor_repository::budget_precheck::check_execution_allowed(&pool, actor)
            .await
            .expect_err("a suspended actor refuses");
        assert!(err.contains("suspended"), "{err}");
    }
    assert_eq!(suspension_alert(&pool, actor).await.expect("alert").2, 1);

    // A status change that is not a resume leaves it open…
    assert_eq!(
        repo.update_actor_status(actor, user, "suspended")
            .await
            .expect("update"),
        1
    );
    assert_eq!(
        suspension_alert(&pool, actor).await.expect("alert").0,
        "new"
    );
    // …and so does another user's attempt, which changes nothing at all.
    let stranger = seed_user(&pool).await;
    assert_eq!(
        repo.update_actor_status(actor, stranger, "active")
            .await
            .expect("update"),
        0
    );
    assert_eq!(actor_status(&pool, actor).await, "suspended");
    assert_eq!(
        suspension_alert(&pool, actor).await.expect("alert").0,
        "new"
    );

    // The owner's resume closes it, as a signal (not an operator's verdict).
    assert_eq!(
        repo.update_actor_status(actor, user, "active")
            .await
            .expect("resume"),
        1
    );
    let (status, _, occurrences, resolved_source, _) =
        suspension_alert(&pool, actor).await.expect("alert");
    assert_eq!(
        (status.as_str(), occurrences, resolved_source.as_deref()),
        ("resolved", 1, Some("signal"))
    );

    // Still at its cap, it is suspended again by the next start: the SAME
    // row reopens, so the history of one actor is one alert.
    talos_actor_repository::budget_precheck::check_execution_allowed(&pool, actor)
        .await
        .expect_err("the cap refuses again");
    assert_eq!(actor_status(&pool, actor).await, "suspended");
    let (status, _, occurrences, _, _) = suspension_alert(&pool, actor).await.expect("alert");
    assert_eq!((status.as_str(), occurrences), ("new", 2));
}

/// Starts that reach the cap together all read the actor as `active`. One of
/// them suspends it; only that one raises the alert.
#[tokio::test]
async fn concurrent_starts_at_the_cap_raise_the_suspension_alert_once() {
    let (pool, _db) = common::isolated_db_pool().await;
    let (_user, actor, _wf) = actor_at_cap(&pool, "max_executions_per_hour", "suspend").await;
    let starts = (0..8).map(|_| {
        let pool = pool.clone();
        tokio::spawn(async move {
            talos_actor_repository::budget_precheck::check_execution_allowed(&pool, actor).await
        })
    });
    for start in starts.collect::<Vec<_>>() {
        start
            .await
            .expect("join")
            .expect_err("every start is refused");
    }
    assert_eq!(actor_status(&pool, actor).await, "suspended");
    assert_eq!(suspension_alert(&pool, actor).await.expect("alert").2, 1);
}

/// The resume the GraphQL mutation makes runs on the caller's connection,
/// inside its transaction: the alert closes with the commit and stays open
/// with a rollback.
#[tokio::test]
async fn a_resume_inside_a_transaction_closes_the_alert_with_the_commit() {
    let (pool, _db) = common::isolated_db_pool().await;
    let (user, actor, _wf) = actor_at_cap(&pool, "max_executions_per_hour", "suspend").await;
    let repo = ActorRepository::new(pool.clone());
    talos_actor_repository::budget_precheck::check_execution_allowed(&pool, actor)
        .await
        .expect_err("the cap refuses");
    assert_eq!(
        suspension_alert(&pool, actor).await.expect("alert").0,
        "new"
    );

    let mut tx = pool.begin().await.expect("begin");
    assert_eq!(
        repo.update_actor_status_scoped(&mut tx, actor, user, "active")
            .await
            .expect("resume"),
        1
    );
    tx.rollback().await.expect("rollback");
    assert_eq!(actor_status(&pool, actor).await, "suspended");
    assert_eq!(
        suspension_alert(&pool, actor).await.expect("alert").0,
        "new"
    );

    let mut tx = pool.begin().await.expect("begin");
    assert_eq!(
        repo.update_actor_status_scoped(&mut tx, actor, user, "active")
            .await
            .expect("resume"),
        1
    );
    tx.commit().await.expect("commit");
    assert_eq!(actor_status(&pool, actor).await, "active");
    let (status, _, _, resolved_source, _) = suspension_alert(&pool, actor).await.expect("alert");
    assert_eq!(
        (status.as_str(), resolved_source.as_deref()),
        ("resolved", Some("signal"))
    );
}

/// Closing the alert is scoped to the user it is closed for: another user's
/// row under the very same key is not touched, and a user with no such row
/// closes nothing. (An alert's key is only unique per user.)
#[tokio::test]
async fn closing_a_suspension_alert_touches_only_the_named_users_row() {
    let (pool, _db) = common::isolated_db_pool().await;
    let owner = seed_user(&pool).await;
    let other = seed_user(&pool).await;
    let stranger = seed_user(&pool).await;
    let actor = seed_actor(&pool, owner).await;
    let alerts = talos_ops_alerts_repository::OpsAlertRepository::new(pool.clone());
    for user in [owner, other] {
        alerts
            .ingest(
                user,
                None,
                talos_actor_budget_refusal::suspension_alert(
                    actor,
                    talos_actor_budget_refusal::BudgetCap::PerHour,
                    1,
                    1,
                ),
            )
            .await
            .expect("ingest");
    }
    let status_of = |user: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, String>(
                "SELECT status FROM ops_alerts WHERE user_id = $1 AND dedup_key = $2",
            )
            .bind(user)
            .bind(format!("talos/actor/{actor}/suspended"))
            .fetch_one(&pool)
            .await
            .expect("read alert")
        }
    };

    assert!(
        !talos_actor_budget_refusal::resolve_actor_suspension_alert(&pool, stranger, actor)
            .await
            .expect("resolve")
    );
    assert_eq!(status_of(owner).await, "new");
    assert_eq!(status_of(other).await, "new");

    assert!(
        talos_actor_budget_refusal::resolve_actor_suspension_alert(&pool, owner, actor)
            .await
            .expect("resolve")
    );
    assert_eq!(status_of(owner).await, "resolved");
    assert_eq!(status_of(other).await, "new");
    // Already closed: nothing to do, and it says so.
    assert!(
        !talos_actor_budget_refusal::resolve_actor_suspension_alert(&pool, owner, actor)
            .await
            .expect("resolve")
    );
}

/// The controls: `alert` and `block` refuse at the same cap, suspend nothing
/// and raise no suspension alert.
#[tokio::test]
async fn alert_and_block_modes_suspend_nothing_and_raise_no_suspension_alert() {
    let (pool, _db) = common::isolated_db_pool().await;
    for mode in ["alert", "block"] {
        let (_user, actor, _wf) = actor_at_cap(&pool, "max_executions_per_hour", mode).await;
        let err = talos_actor_repository::budget_precheck::check_execution_allowed(&pool, actor)
            .await
            .expect_err("the cap refuses");
        assert!(err.contains("last hour"), "{mode}: {err}");
        assert_eq!(actor_status(&pool, actor).await, "active", "{mode}");
        assert!(suspension_alert(&pool, actor).await.is_none(), "{mode}");
    }
}

/// The token cap's refusal message says tokens (it said "executions total").
#[test]
fn the_token_cap_message_names_tokens() {
    let msg =
        talos_workflow_repository::actor_budget_exceeded_message("llm_tokens_per_day", 1000, 1200);
    assert!(msg.contains("1200 tokens in the last 24 hours"), "{msg}");
    assert!(!msg.contains("executions"), "{msg}");
}
