//! Integration tests for workflow versioning (append-only publish & rollback).

mod common;

use controller::workflow_versions::WorkflowVersionService;

/// Helper: create a user and a workflow, returning (user_id, workflow_id).
async fn setup_user_and_workflow(
    ctx: &common::TestContext,
    email: &str,
) -> (uuid::Uuid, uuid::Uuid) {
    let user_id = common::create_test_user(&ctx.auth_service, email).await;
    let workflow_id = common::create_test_workflow(&ctx.db_pool, user_id, "version-test").await;
    (user_id, workflow_id)
}

/// Cleanup helper.
async fn teardown(ctx: &common::TestContext, user_id: uuid::Uuid, workflow_id: uuid::Uuid) {
    sqlx::query("DELETE FROM workflow_versions WHERE workflow_id = $1")
        .bind(workflow_id)
        .execute(&ctx.db_pool)
        .await
        .ok();
    sqlx::query("DELETE FROM workflows WHERE id = $1")
        .bind(workflow_id)
        .execute(&ctx.db_pool)
        .await
        .ok();
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&ctx.db_pool)
        .await
        .ok();
}

#[tokio::test]
async fn publish_version_creates_incrementing_version_numbers() {
    let ctx = common::setup_test_context().await;
    let (user_id, workflow_id) = setup_user_and_workflow(&ctx, "ver_incr@example.com").await;

    let (v1, _) = WorkflowVersionService::publish_version(
        &ctx.db_pool,
        workflow_id,
        user_id,
        Some("v1".to_string()),
        None,
    )
    .await
    .expect("publish v1");
    assert_eq!(v1.version_number, 1);

    let (v2, _) = WorkflowVersionService::publish_version(
        &ctx.db_pool,
        workflow_id,
        user_id,
        Some("v2".to_string()),
        None,
    )
    .await
    .expect("publish v2");
    assert_eq!(v2.version_number, 2);

    let (v3, _) =
        WorkflowVersionService::publish_version(&ctx.db_pool, workflow_id, user_id, None, None)
            .await
            .expect("publish v3");
    assert_eq!(v3.version_number, 3);

    teardown(&ctx, user_id, workflow_id).await;
}

#[tokio::test]
async fn publish_version_deactivates_previous_active() {
    let ctx = common::setup_test_context().await;
    let (user_id, workflow_id) = setup_user_and_workflow(&ctx, "ver_deact@example.com").await;

    let (v1, _) =
        WorkflowVersionService::publish_version(&ctx.db_pool, workflow_id, user_id, None, None)
            .await
            .expect("publish v1");
    assert!(v1.is_active);

    let (v2, _) =
        WorkflowVersionService::publish_version(&ctx.db_pool, workflow_id, user_id, None, None)
            .await
            .expect("publish v2");
    assert!(v2.is_active, "new version should be active");

    // Re-read v1 — it should now be inactive
    let v1_reloaded = WorkflowVersionService::get_version(&ctx.db_pool, v1.id)
        .await
        .expect("get v1")
        .expect("v1 should exist");
    assert!(
        !v1_reloaded.is_active,
        "previous version should be deactivated after new publish"
    );

    teardown(&ctx, user_id, workflow_id).await;
}

#[tokio::test]
async fn get_active_version_returns_latest_published() {
    let ctx = common::setup_test_context().await;
    let (user_id, workflow_id) = setup_user_and_workflow(&ctx, "ver_active@example.com").await;

    // No versions yet
    let none = WorkflowVersionService::get_active_version(&ctx.db_pool, workflow_id)
        .await
        .expect("get active");
    assert!(none.is_none(), "no active version before first publish");

    WorkflowVersionService::publish_version(&ctx.db_pool, workflow_id, user_id, None, None)
        .await
        .expect("publish v1");

    let (v2, _) = WorkflowVersionService::publish_version(
        &ctx.db_pool,
        workflow_id,
        user_id,
        Some("latest".to_string()),
        None,
    )
    .await
    .expect("publish v2");

    let active = WorkflowVersionService::get_active_version(&ctx.db_pool, workflow_id)
        .await
        .expect("get active version")
        .expect("should have active version");
    assert_eq!(active.id, v2.id);
    assert_eq!(active.version_number, 2);
    assert!(active.is_active);

    teardown(&ctx, user_id, workflow_id).await;
}

#[tokio::test]
async fn rollback_creates_new_version_with_target_graph() {
    let ctx = common::setup_test_context().await;
    let (user_id, workflow_id) = setup_user_and_workflow(&ctx, "ver_rollback@example.com").await;

    let (v1, _) = WorkflowVersionService::publish_version(
        &ctx.db_pool,
        workflow_id,
        user_id,
        Some("initial".to_string()),
        None,
    )
    .await
    .expect("publish v1");

    // Update workflow graph to something different
    sqlx::query("UPDATE workflows SET graph_json = '{\"nodes\":[{\"id\":\"n1\"}],\"edges\":[]}' WHERE id = $1")
        .bind(workflow_id)
        .execute(&ctx.db_pool)
        .await
        .expect("update graph");

    let (v2, _) = WorkflowVersionService::publish_version(
        &ctx.db_pool,
        workflow_id,
        user_id,
        Some("changed".to_string()),
        None,
    )
    .await
    .expect("publish v2");

    // Rollback to v1 should create v3 with v1's graph
    let v3 = WorkflowVersionService::rollback_to_version(&ctx.db_pool, workflow_id, v1.id, user_id)
        .await
        .expect("rollback to v1");

    assert_eq!(
        v3.version_number, 3,
        "rollback should be append-only (new version)"
    );
    assert!(v3.is_active, "rollback version should be active");
    assert_eq!(
        v3.graph_json, v1.graph_json,
        "rollback should copy the target version's graph_json"
    );
    assert!(
        v3.description.as_deref().unwrap_or("").contains("Rollback"),
        "description should mention rollback"
    );

    // v2 should now be inactive
    let v2_reloaded = WorkflowVersionService::get_version(&ctx.db_pool, v2.id)
        .await
        .expect("get v2")
        .expect("v2 should exist");
    assert!(!v2_reloaded.is_active);

    teardown(&ctx, user_id, workflow_id).await;
}

#[tokio::test]
async fn list_versions_returns_descending_order() {
    let ctx = common::setup_test_context().await;
    let (user_id, workflow_id) = setup_user_and_workflow(&ctx, "ver_list@example.com").await;

    for _ in 0..3 {
        WorkflowVersionService::publish_version(&ctx.db_pool, workflow_id, user_id, None, None)
            .await
            .expect("publish");
    }

    let versions = WorkflowVersionService::list_versions(&ctx.db_pool, workflow_id, 10, 0)
        .await
        .expect("list versions");

    assert_eq!(versions.len(), 3);
    assert_eq!(versions[0].version_number, 3, "first should be highest");
    assert_eq!(versions[1].version_number, 2);
    assert_eq!(versions[2].version_number, 1, "last should be lowest");

    teardown(&ctx, user_id, workflow_id).await;
}

#[tokio::test]
async fn ownership_verification_publish_rejects_other_user() {
    let ctx = common::setup_test_context().await;
    let (owner_id, workflow_id) = setup_user_and_workflow(&ctx, "ver_own@example.com").await;
    let intruder_id = common::create_test_user(&ctx.auth_service, "ver_intruder@example.com").await;

    let result =
        WorkflowVersionService::publish_version(&ctx.db_pool, workflow_id, intruder_id, None, None)
            .await;
    assert!(
        result.is_err(),
        "publishing another user's workflow should fail"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("not found") || err_msg.contains("access denied"),
        "error should mention access: {}",
        err_msg
    );

    teardown(&ctx, owner_id, workflow_id).await;
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(intruder_id)
        .execute(&ctx.db_pool)
        .await
        .ok();
}

#[tokio::test]
async fn ownership_verification_rollback_rejects_other_user() {
    let ctx = common::setup_test_context().await;
    let (owner_id, workflow_id) = setup_user_and_workflow(&ctx, "ver_ownrb@example.com").await;
    let intruder_id = common::create_test_user(&ctx.auth_service, "ver_intrb@example.com").await;

    let (v1, _) =
        WorkflowVersionService::publish_version(&ctx.db_pool, workflow_id, owner_id, None, None)
            .await
            .expect("publish");

    let result =
        WorkflowVersionService::rollback_to_version(&ctx.db_pool, workflow_id, v1.id, intruder_id)
            .await;
    assert!(result.is_err(), "rollback by non-owner should fail");

    teardown(&ctx, owner_id, workflow_id).await;
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(intruder_id)
        .execute(&ctx.db_pool)
        .await
        .ok();
}
