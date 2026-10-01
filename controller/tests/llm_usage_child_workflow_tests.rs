//! A sub-workflow child's LLM usage names the child workflow (2026-10-01).
//!
//! A child runs under an execution id of its own and writes no
//! `workflow_executions` row, so `record_llm_usage`'s join found nothing and
//! the row's `workflow_id` was NULL — every per-workflow usage query missed
//! every child run. The writer now falls back to the workflow the dispatching
//! engine ran, but only when the caller's user owns it.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use sqlx::{Pool, Postgres};
use talos_actor_repository::{ActorRepository, LlmUsageInsert};
use uuid::Uuid;

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'usage')")
        .bind(id)
        .bind(format!("usage-{id}@example.com"))
        .execute(pool)
        .await
        .expect("seed user");
    id
}

fn one_entry() -> Vec<LlmUsageInsert> {
    vec![LlmUsageInsert {
        provider: "test".to_string(),
        model: "test-model".to_string(),
        prompt_tokens: 7,
        completion_tokens: 3,
        calls: 1,
    }]
}

/// `(workflow_id, org_id, user_id)` of the single usage row for `execution`.
async fn usage_row(
    pool: &Pool<Postgres>,
    execution: Uuid,
) -> (Option<Uuid>, Option<Uuid>, Option<Uuid>) {
    sqlx::query_as("SELECT workflow_id, org_id, user_id FROM llm_usage WHERE execution_id = $1")
        .bind(execution)
        .fetch_one(pool)
        .await
        .expect("exactly one usage row")
}

async fn workflow_org(pool: &Pool<Postgres>, workflow: Uuid) -> Option<Uuid> {
    sqlx::query_scalar("SELECT org_id FROM workflows WHERE id = $1")
        .bind(workflow)
        .fetch_one(pool)
        .await
        .expect("workflow row")
}

#[tokio::test]
async fn a_child_run_with_no_execution_row_is_stamped_with_its_own_workflow() {
    let (pool, _db) = common::isolated_db_pool().await;
    let repo = ActorRepository::new(pool.clone());
    let user = seed_user(&pool).await;
    let child_wf = common::create_test_workflow(&pool, user, "usage-child").await;

    // The child's execution id: no `workflow_executions` row carries it.
    let child_execution = Uuid::new_v4();
    let written = repo
        .record_llm_usage(
            Some(child_execution),
            Some(child_wf),
            None,
            Some(user),
            &one_entry(),
        )
        .await
        .expect("record usage");
    assert_eq!(written, 1);

    let (workflow_id, org_id, user_id) = usage_row(&pool, child_execution).await;
    assert_eq!(workflow_id, Some(child_wf));
    assert_eq!(user_id, Some(user));
    assert_eq!(org_id, workflow_org(&pool, child_wf).await);
}

#[tokio::test]
async fn another_users_workflow_id_is_not_accepted() {
    let (pool, _db) = common::isolated_db_pool().await;
    let repo = ActorRepository::new(pool.clone());
    let owner = seed_user(&pool).await;
    let stranger = seed_user(&pool).await;
    let owners_wf = common::create_test_workflow(&pool, owner, "usage-owned").await;

    // The dispatch context names a workflow its own user does not own.
    let execution = Uuid::new_v4();
    repo.record_llm_usage(
        Some(execution),
        Some(owners_wf),
        None,
        Some(stranger),
        &one_entry(),
    )
    .await
    .expect("record usage");
    let (workflow_id, org_id, user_id) = usage_row(&pool, execution).await;
    assert_eq!(
        workflow_id, None,
        "a foreign workflow id must not be stamped"
    );
    assert_eq!(org_id, None);
    assert_eq!(user_id, Some(stranger));

    // With no user at all the fallback is not taken either.
    let execution = Uuid::new_v4();
    repo.record_llm_usage(Some(execution), Some(owners_wf), None, None, &one_entry())
        .await
        .expect("record usage");
    assert_eq!(usage_row(&pool, execution).await.0, None);
}

#[tokio::test]
async fn a_real_execution_row_still_wins_over_the_dispatch_workflow() {
    let (pool, _db) = common::isolated_db_pool().await;
    let repo = ActorRepository::new(pool.clone());
    let user = seed_user(&pool).await;
    let parent_wf = common::create_test_workflow(&pool, user, "usage-parent").await;
    let other_wf = common::create_test_workflow(&pool, user, "usage-other").await;

    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name, status) VALUES ($1, $2, $3, 'active')")
        .bind(actor)
        .bind(user)
        .bind(format!("usage-actor-{actor}"))
        .execute(&pool)
        .await
        .expect("seed actor");
    let execution = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflow_executions (id, workflow_id, user_id, actor_id, status) \
         VALUES ($1, $2, $3, $4, 'running')",
    )
    .bind(execution)
    .bind(parent_wf)
    .bind(user)
    .bind(actor)
    .execute(&pool)
    .await
    .expect("seed execution");

    // The controller's own execution row is the authority; a different
    // dispatch-context id does not override it.
    repo.record_llm_usage(
        Some(execution),
        Some(other_wf),
        None,
        Some(user),
        &one_entry(),
    )
    .await
    .expect("record usage");
    assert_eq!(usage_row(&pool, execution).await.0, Some(parent_wf));

    // Control: no dispatch workflow, no execution id — unchanged behaviour.
    repo.record_llm_usage(None, None, None, Some(user), &one_entry())
        .await
        .expect("record usage");
    let unattributed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM llm_usage WHERE user_id = $1 AND execution_id IS NULL \
         AND workflow_id IS NULL",
    )
    .bind(user)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(unattributed, 1);
}
