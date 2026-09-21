//! The dashboard's `deleteWorkflow` refuses what every other workflow delete
//! refuses. Until 2026-09-21 it carried the in-flight-execution guard only, so
//! the UI could delete a sub-workflow out from under an ENABLED parent while
//! MCP `delete_workflow` / `batch_delete_workflows` / `cleanup_workflows` all
//! refused the same request. Driven through the production GraphQL schema.
mod common;

use common::{
    add_user_to_organization, create_test_organization, create_test_user, setup_test_context,
    AuthenticatedClient,
};
use sqlx::{Pool, Postgres};
use talos_api_keys::ApiKeyScope;
use uuid::Uuid;

const BARE: &str = r#"{"nodes":[{"id":"n","type":"module","data":{}}],"edges":[]}"#;

fn parent_of(child: Uuid) -> String {
    format!(
        r#"{{"nodes":[{{"id":"g","type":"system:sub_workflow","data":{{"sub_workflow_id":"{child}"}}}}],"edges":[]}}"#
    )
}

async fn seed_workflow(
    pool: &Pool<Postgres>,
    user: Uuid,
    org: Option<Uuid>,
    name: &str,
    graph: &str,
    enabled: bool,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, org_id, name, graph_json, module_uri, status, is_enabled) \
         VALUES ($1, $2, $3, $4, $5, 'talos://t', 'active', $6)",
    )
    .bind(id)
    .bind(user)
    .bind(org)
    .bind(name)
    .bind(graph)
    .bind(enabled)
    .execute(pool)
    .await
    .expect("seed workflow");
    id
}

async fn exists(pool: &Pool<Postgres>, id: Uuid) -> bool {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM workflows WHERE id = $1)")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("exists")
}

async fn delete(client: &AuthenticatedClient, id: Uuid) -> async_graphql::Response {
    client
        .execute(&format!(r#"mutation {{ deleteWorkflow(id: "{id}") }}"#))
        .await
}

fn error_text(resp: &async_graphql::Response) -> String {
    resp.errors
        .iter()
        .map(|e| e.message.clone())
        .collect::<Vec<_>>()
        .join(" | ")
}

#[tokio::test]
async fn the_dashboard_delete_refuses_a_child_an_enabled_parent_dispatches_into() {
    let ctx = setup_test_context().await;
    let user = create_test_user(&ctx.auth_service, "delete-guard@example.com").await;
    let client = AuthenticatedClient::new(
        user,
        None,
        vec![ApiKeyScope::WorkflowsWrite],
        ctx.schema.clone(),
    );
    let pool = &ctx.db_pool;

    let child = seed_workflow(pool, user, None, "team-gather", BARE, true).await;
    let parent = seed_workflow(pool, user, None, "daily-briefing", &parent_of(child), true).await;
    let unrelated = seed_workflow(pool, user, None, "scratch", BARE, true).await;

    // CONTROL: an ordinary workflow deletes.
    let resp = delete(&client, unrelated).await;
    assert!(resp.errors.is_empty(), "{}", error_text(&resp));
    assert!(!exists(pool, unrelated).await);

    // The child is refused, the refusal names the parent, nothing is deleted.
    let resp = delete(&client, child).await;
    let text = error_text(&resp);
    assert!(
        !resp.errors.is_empty(),
        "deleting a live child must be refused"
    );
    assert!(
        text.contains("daily-briefing"),
        "the refusal must name the parent: {text}"
    );
    assert!(
        exists(pool, child).await,
        "the child was deleted out from under its parent"
    );
    assert!(exists(pool, parent).await);

    // Once the parent no longer dispatches (disabled), the same delete works —
    // so the refusal above is the parent's doing, not a broken delete.
    sqlx::query("UPDATE workflows SET is_enabled = false WHERE id = $1")
        .bind(parent)
        .execute(pool)
        .await
        .unwrap();
    let resp = delete(&client, child).await;
    assert!(resp.errors.is_empty(), "{}", error_text(&resp));
    assert!(!exists(pool, child).await);
}

/// The scan is keyed on the workflow's OWNER. An org colleague with write
/// access deleting someone else's child meets the refusal the owner would.
#[tokio::test]
async fn an_org_colleague_meets_the_same_refusal() {
    let ctx = setup_test_context().await;
    let pool = &ctx.db_pool;
    let owner = create_test_user(&ctx.auth_service, "delete-guard-owner@example.com").await;
    let colleague = create_test_user(&ctx.auth_service, "delete-guard-peer@example.com").await;
    let org = create_test_organization(pool, "delete-guard-org", owner).await;
    add_user_to_organization(pool, colleague, org, "member").await;
    // `None`, not `Some(org)`: the harness stores the org id as a bare `Uuid`
    // in the request data, which would REPLACE the user id of the same type.
    // The resolver derives the writable orgs from membership, not from it.
    let client = AuthenticatedClient::new(
        colleague,
        None,
        vec![ApiKeyScope::WorkflowsWrite],
        ctx.schema.clone(),
    );

    let child = seed_workflow(pool, owner, Some(org), "shared-child", BARE, true).await;
    let _parent = seed_workflow(
        pool,
        owner,
        Some(org),
        "shared-parent",
        &parent_of(child),
        true,
    )
    .await;
    let plain = seed_workflow(pool, owner, Some(org), "shared-plain", BARE, true).await;

    // CONTROL: the colleague really can delete the owner's org workflow.
    let resp = delete(&client, plain).await;
    assert!(resp.errors.is_empty(), "{}", error_text(&resp));
    assert!(!exists(pool, plain).await);

    let resp = delete(&client, child).await;
    assert!(
        error_text(&resp).contains("shared-parent"),
        "a colleague's delete must meet the owner's refusal: {}",
        error_text(&resp)
    );
    assert!(exists(pool, child).await);
}

/// The in-flight refusal still stands, and no longer points at a tool that
/// does not exist ("force-delete via MCP").
#[tokio::test]
async fn a_running_workflow_is_still_refused_with_advice_that_exists() {
    let ctx = setup_test_context().await;
    let pool = &ctx.db_pool;
    let user = create_test_user(&ctx.auth_service, "delete-guard-run@example.com").await;
    let client = AuthenticatedClient::new(
        user,
        None,
        vec![ApiKeyScope::WorkflowsWrite],
        ctx.schema.clone(),
    );
    let wf = seed_workflow(pool, user, None, "busy", BARE, true).await;
    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name) VALUES ($1, $2, 'delete-guard-actor')")
        .bind(actor)
        .bind(user)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO workflow_executions (id, workflow_id, user_id, actor_id, status) VALUES ($1, $2, $3, $4, 'running')",
    )
    .bind(Uuid::new_v4())
    .bind(wf)
    .bind(user)
    .bind(actor)
    .execute(pool)
    .await
    .unwrap();

    let resp = delete(&client, wf).await;
    let text = error_text(&resp);
    assert!(text.contains("running / queued / pending"), "{text}");
    assert!(
        !text.contains("force-delete"),
        "no such tool exists: {text}"
    );
    assert!(exists(pool, wf).await);
}

/// The refusal names parent workflows, so it must only ever be given to a
/// caller who may delete the workflow. A stranger gets "not found" — never the
/// name of somebody else's parent, and never a hint that the id exists.
#[tokio::test]
async fn a_stranger_learns_nothing_from_the_refusal() {
    let ctx = setup_test_context().await;
    let pool = &ctx.db_pool;
    let owner = create_test_user(&ctx.auth_service, "delete-guard-victim@example.com").await;
    let stranger = create_test_user(&ctx.auth_service, "delete-guard-stranger@example.com").await;
    let client = AuthenticatedClient::new(
        stranger,
        None,
        vec![ApiKeyScope::WorkflowsWrite],
        ctx.schema.clone(),
    );
    let child = seed_workflow(pool, owner, None, "private-child", BARE, true).await;
    let _parent = seed_workflow(
        pool,
        owner,
        None,
        "secret-parent-name",
        &parent_of(child),
        true,
    )
    .await;

    let text = error_text(&delete(&client, child).await);
    assert!(text.contains("not found"), "{text}");
    assert!(
        !text.contains("secret-parent-name"),
        "another tenant's parent name leaked: {text}"
    );
    assert!(exists(pool, child).await);
}

/// The access predicate on the owner read, on its own. Through the resolver
/// the tenant-scoped transaction's RLS policy also hides a stranger's row, so
/// that test cannot tell a dropped predicate from a present one (package BH's
/// second-guard shape). On an UNSCOPED connection nothing else stands between
/// a stranger and a refusal that names somebody else's parent workflow.
#[tokio::test]
async fn the_owner_read_is_access_scoped_without_help_from_rls() {
    let ctx = setup_test_context().await;
    let pool = &ctx.db_pool;
    let owner = create_test_user(&ctx.auth_service, "delete-guard-o2@example.com").await;
    let stranger = create_test_user(&ctx.auth_service, "delete-guard-s2@example.com").await;
    let child = seed_workflow(pool, owner, None, "o2-child", BARE, true).await;
    let _parent = seed_workflow(pool, owner, None, "o2-parent", &parent_of(child), true).await;
    let repo = talos_workflow_repository::WorkflowRepository::new(pool.clone());

    let mut conn = pool.acquire().await.expect("conn");
    let visible: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM workflows WHERE id = $1)")
        .bind(child)
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    assert!(visible, "CONTROL: this connection can see the owner's row");

    let as_stranger = repo
        .delete_workflow_guarded_scoped(&mut conn, child, stranger, &[])
        .await
        .expect("delete");
    assert!(
        matches!(
            as_stranger,
            talos_workflow_repository::ScopedWorkflowDelete::NotDeleted
        ),
        "a stranger must get NotDeleted, never the refusal that names parents: {as_stranger:?}"
    );
    // CONTROL: the owner, on the same connection, gets the refusal.
    let as_owner = repo
        .delete_workflow_guarded_scoped(&mut conn, child, owner, &[])
        .await
        .expect("delete");
    assert!(matches!(
        as_owner,
        talos_workflow_repository::ScopedWorkflowDelete::Referenced(_)
    ));
    assert!(exists(pool, child).await);
}
