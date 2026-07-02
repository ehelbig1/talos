//! Regression test for the `queued -> running -> completed` execution
//! lifecycle on the GraphQL `trigger_workflow` path.
//!
//! `trigger_workflow` creates the execution row as `queued` and dispatches the
//! engine in a `tokio::spawn`. `mark_execution_completed` is guarded
//! `WHERE status = 'running'`, so if the spawned task does NOT promote the row
//! `queued -> running` first, completion silently no-ops and every successful
//! run sticks at `queued` forever (until the stuck-execution sweep force-fails
//! it). This was observed live: 0 executions ever reached `completed`.
//!
//! This test pins the contract at the repository layer (no engine/NATS needed):
//! completion no-ops while `queued`, and only takes effect after the
//! `mark_execution_running_from_queued` promotion.

mod common;

// Import from the canonical crate, not the controller's `pub(crate)`
// re-export shim (the shim was `pub` until the main.rs decomposition in
// #381 narrowed it; per the architectural mandate, external code — tests
// included — depends on `talos_*` crates directly).
use talos_workflow_repository::{ConcurrencyAdmission, InitialExecutionStatus, WorkflowRepository};
use uuid::Uuid;

async fn status(pool: &sqlx::Pool<sqlx::Postgres>, id: Uuid) -> String {
    sqlx::query_scalar::<_, String>("SELECT status FROM workflow_executions WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("fetch execution status")
}

#[tokio::test]
async fn queued_execution_requires_running_promotion_before_completion() {
    let ctx = common::setup_test_context().await;
    let user_id = common::create_test_user(&ctx.auth_service, "exec-status@example.com").await;
    let workflow_id = common::create_test_workflow(&ctx.db_pool, user_id, "exec-status-test").await;

    let repo = WorkflowRepository::new(ctx.db_pool.clone());
    let exec_id = Uuid::new_v4();

    // GraphQL trigger_workflow creates the row as `queued`.
    let admission = repo
        .create_execution_under_concurrency_limit(
            exec_id,
            workflow_id,
            user_id,
            None,
            Some("normal"),
            None,
            None,
            None,
            None,
            InitialExecutionStatus::Queued,
        )
        .await
        .expect("create queued execution");
    assert!(matches!(admission, ConcurrencyAdmission::Created));
    assert_eq!(status(&ctx.db_pool, exec_id).await, "queued");

    // The bug: completing while still `queued` no-ops (guard is
    // `WHERE status = 'running'`). The call returns Ok, but no row changes.
    repo.mark_execution_completed(exec_id, &serde_json::json!({"ok": true}))
        .await
        .expect("mark_execution_completed must not error even when it no-ops");
    assert_eq!(
        status(&ctx.db_pool, exec_id).await,
        "queued",
        "completion must no-op while queued — the promotion below is what fixes it",
    );

    // The fix: promote queued -> running, reporting that a row was updated.
    assert!(
        repo.mark_execution_running_from_queued(exec_id)
            .await
            .expect("promote queued -> running"),
        "promotion should report a row was updated",
    );
    assert_eq!(status(&ctx.db_pool, exec_id).await, "running");

    // Idempotent: a second promotion finds no `queued` row and reports false.
    assert!(
        !repo
            .mark_execution_running_from_queued(exec_id)
            .await
            .expect("second promotion"),
        "second promotion should no-op (row is no longer queued)",
    );

    // Now completion takes effect.
    repo.mark_execution_completed(exec_id, &serde_json::json!({"ok": true}))
        .await
        .expect("mark completed");
    assert_eq!(status(&ctx.db_pool, exec_id).await, "completed");
}
