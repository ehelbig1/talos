//! `list_workflows(runs: true)` lists the workflows that run, and
//! `session_start`'s two scheduled counts cannot contradict.
//!
//! Observed 2026-10-12: `list_workflows(status: "active")` returned 17
//! workflows while 27 had an enabled schedule, and `session_start` printed
//! `active_workflows: 17` beside `workflows_with_active_schedules: 27` under a
//! note calling the second a subset of the first. A draft with an enabled
//! schedule is dispatched from its draft graph, so `active` (published) was
//! never the question.
//!
//! Driven through the two repository methods the handlers call, against a
//! clone of the migrated schema.
//!
//! DB tests on the `common` harness.

mod common;

use sqlx::{Pool, Postgres};
use talos_advanced_repository::AdvancedRepository;
use talos_workflow_repository::WorkflowRepository;
use uuid::Uuid;

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'runs filter test')",
    )
    .bind(id)
    .bind(format!("runs-filter-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

/// A workflow with the given status and enabled flag.
async fn workflow(
    pool: &Pool<Postgres>,
    user: Uuid,
    name: &str,
    status: &str,
    enabled: bool,
) -> Uuid {
    let id = common::create_test_workflow(pool, user, name).await;
    sqlx::query("UPDATE workflows SET status = $2, is_enabled = $3 WHERE id = $1")
        .bind(id)
        .bind(status)
        .bind(enabled)
        .execute(pool)
        .await
        .expect("set status");
    id
}

async fn schedule(pool: &Pool<Postgres>, user: Uuid, workflow_id: Uuid, enabled: bool) {
    sqlx::query(
        "INSERT INTO workflow_schedules (id, workflow_id, user_id, cron_expression, timezone, is_enabled, next_trigger_at) \
         VALUES ($1, $2, $3, '0 9 * * *', 'UTC', $4, NOW() + interval '1 hour')",
    )
    .bind(Uuid::new_v4())
    .bind(workflow_id)
    .bind(user)
    .bind(enabled)
    .execute(pool)
    .await
    .expect("seed schedule");
}

async fn webhook(pool: &Pool<Postgres>, user: Uuid, workflow_id: Uuid, enabled: bool) {
    sqlx::query(
        "INSERT INTO webhook_triggers (id, name, verification_token_hash, enabled, user_id, workflow_id) \
         VALUES ($1, 'runs filter test', $2, $3, $4, $5)",
    )
    .bind(Uuid::new_v4())
    .bind(format!("made-up-{}", Uuid::new_v4().simple()))
    .bind(enabled)
    .bind(user)
    .bind(workflow_id)
    .execute(pool)
    .await
    .expect("seed webhook trigger");
}

/// One execution of `workflow_id`, started `ago` in the past.
/// `workflow_executions.actor_id` is NOT NULL: every run is attributed.
async fn execution(pool: &Pool<Postgres>, user: Uuid, workflow_id: Uuid, ago: &str) {
    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name, status) VALUES ($1, $2, $3, 'active')")
        .bind(actor)
        .bind(user)
        .bind(format!("runs-filter-actor-{actor}"))
        .execute(pool)
        .await
        .expect("seed actor");
    sqlx::query(
        "INSERT INTO workflow_executions (id, workflow_id, user_id, actor_id, status, started_at) \
         VALUES ($1, $2, $3, $4, 'completed', NOW() - $5::interval)",
    )
    .bind(Uuid::new_v4())
    .bind(workflow_id)
    .bind(user)
    .bind(actor)
    .bind(ago)
    .execute(pool)
    .await
    .expect("seed execution");
}

async fn names(
    repo: &WorkflowRepository,
    user: Uuid,
    status: Option<&str>,
    runs_only: bool,
) -> (Vec<String>, i64) {
    let (rows, total) = repo
        .list_workflows_paginated(user, status, None, None, runs_only, None, None, 200, 0)
        .await
        .expect("list");
    let mut names: Vec<String> = rows.into_iter().map(|w| w.name).collect();
    names.sort();
    (names, total)
}

#[tokio::test]
async fn runs_lists_what_runs_whatever_its_status() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let other = seed_user(&pool).await;

    // Runs: a published workflow on a schedule.
    let a = workflow(&pool, user, "a-active-scheduled", "active", true).await;
    schedule(&pool, user, a, true).await;
    // Runs: a DRAFT on a schedule. This is the population `status: "active"`
    // leaves out.
    let b = workflow(&pool, user, "b-draft-scheduled", "draft", true).await;
    schedule(&pool, user, b, true).await;
    // Runs: a webhook starts it.
    let c = workflow(&pool, user, "c-draft-webhook", "draft", true).await;
    webhook(&pool, user, c, true).await;
    // Runs: nothing of its own starts it, and it ran yesterday (a push
    // channel, an action link, another workflow).
    let d = workflow(&pool, user, "d-active-ran-yesterday", "active", true).await;
    execution(&pool, user, d, "1 day").await;

    // Does not run: published, and nothing starts it.
    workflow(&pool, user, "e-active-idle", "active", true).await;
    // Does not run: its last run was a month ago.
    let f = workflow(&pool, user, "f-active-ran-last-month", "active", true).await;
    execution(&pool, user, f, "30 days").await;
    // Does not run: its schedule is paused.
    let g = workflow(&pool, user, "g-active-schedule-paused", "active", true).await;
    schedule(&pool, user, g, false).await;
    // Does not run: its webhook is disabled.
    let h = workflow(&pool, user, "h-draft-webhook-disabled", "draft", true).await;
    webhook(&pool, user, h, false).await;
    // Does not run: archived, though its schedule row is still enabled.
    let i = workflow(&pool, user, "i-archived-scheduled", "archived", true).await;
    schedule(&pool, user, i, true).await;
    // Does not run: disabled, though scheduled.
    let j = workflow(&pool, user, "j-active-disabled-scheduled", "active", false).await;
    schedule(&pool, user, j, true).await;

    // Another user's scheduled workflow is never in this user's list.
    let z = workflow(&pool, other, "z-someone-elses", "active", true).await;
    schedule(&pool, other, z, true).await;

    let repo = WorkflowRepository::new(pool.clone());

    let (running, total) = names(&repo, user, None, true).await;
    assert_eq!(
        running,
        [
            "a-active-scheduled",
            "b-draft-scheduled",
            "c-draft-webhook",
            "d-active-ran-yesterday",
        ]
    );
    assert_eq!(total, 4, "the count uses the same filter as the page");

    // The defect: `status: "active"` is "published", and it both leaves out
    // the two drafts that run and includes four workflows that do not.
    let (active, _) = names(&repo, user, Some("active"), false).await;
    assert!(!active.contains(&"b-draft-scheduled".to_string()));
    assert!(!active.contains(&"c-draft-webhook".to_string()));
    assert!(active.contains(&"e-active-idle".to_string()));

    // The two filters combine: published AND running.
    let (active_running, _) = names(&repo, user, Some("active"), true).await;
    assert_eq!(
        active_running,
        ["a-active-scheduled", "d-active-ran-yesterday"]
    );

    // Without the filter the listing is what it was.
    let (all, total_all) = names(&repo, user, None, false).await;
    assert_eq!(all.len(), 10);
    assert_eq!(total_all, 10);
}

#[tokio::test]
async fn the_two_scheduled_counts_come_from_one_statement_and_reconcile() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;

    for n in 0..2 {
        let w = workflow(&pool, user, &format!("active-{n}"), "active", true).await;
        schedule(&pool, user, w, true).await;
    }
    for n in 0..3 {
        let w = workflow(&pool, user, &format!("draft-{n}"), "draft", true).await;
        schedule(&pool, user, w, true).await;
    }
    // Not counted: an active workflow with no schedule, one whose schedule is
    // paused, and an archived one that still has an enabled schedule row.
    workflow(&pool, user, "active-unscheduled", "active", true).await;
    let paused = workflow(&pool, user, "active-paused", "active", true).await;
    schedule(&pool, user, paused, false).await;
    let archived = workflow(&pool, user, "archived", "archived", true).await;
    schedule(&pool, user, archived, true).await;

    let repo = AdvancedRepository::new(pool.clone());
    let active_workflows = repo.get_active_workflow_count(user).await.expect("count");
    let scheduled = repo
        .get_active_workflows_with_schedule_count(user)
        .await
        .expect("count");

    assert_eq!(active_workflows, 4);
    assert_eq!(scheduled.not_archived, 5, "two active and three drafts");
    assert_eq!(scheduled.active, 2);
    // The subset really is one, and the larger number is allowed to be larger.
    assert!(scheduled.active <= active_workflows);
    assert!(scheduled.active <= scheduled.not_archived);
    assert!(scheduled.not_archived > active_workflows);
}

/// The name filters (2026-10-14): exact, and a case-insensitive substring in
/// which `%` and `_` are literal characters. Neither reaches another user's
/// workflows.
#[tokio::test]
async fn name_filters_find_one_workflow_by_name() {
    let (pool, _db) = common::isolated_db_pool().await;
    let repo = WorkflowRepository::new(pool.clone());
    let user = seed_user(&pool).await;
    let stranger = seed_user(&pool).await;
    for name in [
        "made-up-weekly-report",
        "made-up-100%-done",
        "Made-Up-Morning",
    ] {
        workflow(&pool, user, name, "draft", true).await;
    }
    workflow(&pool, stranger, "made-up-weekly-report", "draft", true).await;

    let names = |exact: Option<&'static str>, contains: Option<&'static str>| {
        let repo = &repo;
        async move {
            let (rows, total) = repo
                .list_workflows_paginated(user, None, None, None, false, exact, contains, 200, 0)
                .await
                .expect("list");
            let mut names: Vec<String> = rows.into_iter().map(|w| w.name).collect();
            names.sort();
            assert_eq!(total, names.len() as i64, "total counts the same filter");
            names
        }
    };

    assert_eq!(
        names(Some("made-up-weekly-report"), None).await,
        vec!["made-up-weekly-report"],
        "exact, and only the caller's"
    );
    assert!(
        names(Some("made-up-weekly"), None).await.is_empty(),
        "exact is exact"
    );
    assert!(
        names(Some("made-up-morning"), None).await.is_empty(),
        "exact is case-sensitive"
    );
    assert_eq!(
        names(None, Some("MORNING")).await,
        vec!["Made-Up-Morning"],
        "contains ignores case"
    );
    assert_eq!(
        names(None, Some("100%")).await,
        vec!["made-up-100%-done"],
        "`%` is a literal character, not a wildcard"
    );
    assert!(
        names(None, Some("_")).await.is_empty(),
        "`_` matches only an underscore"
    );
    assert_eq!(names(None, Some("made-up")).await.len(), 3);
}
