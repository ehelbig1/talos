//! `on_budget_exceeded = 'alert'` raises an alert (package CD, 2026-09-17).
//!
//! Until this package `alert` refused a start exactly as `block` did and
//! nothing alerted; a budget refusal was only a returned error string. These
//! tests drive the three places a refusal is decided — the atomic backstop at
//! row creation and the two pre-checks — against a real clone, and read the
//! counter and `ops_alerts` back. Every alert test has a `block` control that
//! must refuse identically and write no alert.
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
    sqlx::query(&format!(
        "INSERT INTO actor_budget_policies (actor_id, {column}, on_budget_exceeded) VALUES ($1, $2, $3)"
    ))
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

/// The token cap's refusal message says tokens (it said "executions total").
#[test]
fn the_token_cap_message_names_tokens() {
    let msg =
        talos_workflow_repository::actor_budget_exceeded_message("llm_tokens_per_day", 1000, 1200);
    assert!(msg.contains("1200 tokens in the last 24 hours"), "{msg}");
    assert!(!msg.contains("executions"), "{msg}");
}
