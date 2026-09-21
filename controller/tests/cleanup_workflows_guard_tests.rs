//! `cleanup_workflows` (delete by prefix / delete all) carries the same two
//! guards as the single and batch deletes. Until 2026-09-21 it was a bare
//! `DELETE … WHERE user_id = $1 AND name LIKE $2`: reproduced on main, a prefix
//! cleanup deleted a workflow with a RUNNING execution (the CASCADE took the
//! execution with it) and a sub-workflow an enabled parent dispatches into.
mod common;

use sqlx::{Pool, Postgres};
use talos_workflow_repository::WorkflowRepository;
use uuid::Uuid;

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'cleanup test')",
    )
    .bind(id)
    .bind(format!("cleanup-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

async fn seed_workflow(pool: &Pool<Postgres>, user: Uuid, name: &str, graph: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, graph_json, module_uri, status, is_enabled) \
         VALUES ($1, $2, $3, $4, 'talos://t', 'active', true)",
    )
    .bind(id)
    .bind(user)
    .bind(name)
    .bind(graph)
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

const BARE: &str = r#"{"nodes":[{"id":"n","type":"module","data":{}}],"edges":[]}"#;

async fn seed_actor(pool: &Pool<Postgres>, user: Uuid) -> Uuid {
    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name) VALUES ($1, $2, $3)")
        .bind(actor)
        .bind(user)
        .bind(format!("cleanup-actor-{actor}"))
        .execute(pool)
        .await
        .expect("actor");
    actor
}

async fn seed_execution(
    pool: &Pool<Postgres>,
    wf: Uuid,
    user: Uuid,
    actor: Uuid,
    status: &str,
) -> Uuid {
    let exec = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflow_executions (id, workflow_id, user_id, actor_id, status) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(exec)
    .bind(wf)
    .bind(user)
    .bind(actor)
    .bind(status)
    .execute(pool)
    .await
    .expect("execution");
    exec
}

fn parent_of(child: Uuid) -> String {
    format!(
        r#"{{"nodes":[{{"id":"g","type":"system:sub_workflow","data":{{"sub_workflow_id":"{child}"}}}}],"edges":[]}}"#
    )
}

#[tokio::test]
async fn a_prefix_cleanup_refuses_what_the_other_deletes_refuse() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let actor = seed_actor(&pool, user).await;
    let stranger = seed_user(&pool).await;
    let repo = WorkflowRepository::new(pool.clone());

    let plain = seed_workflow(&pool, user, "tmp-plain", BARE).await;
    let finished = seed_workflow(&pool, user, "tmp-finished", BARE).await;
    seed_execution(&pool, finished, user, actor, "completed").await;
    let running = seed_workflow(&pool, user, "tmp-running", BARE).await;
    let exec = seed_execution(&pool, running, user, actor, "running").await;
    let child = seed_workflow(&pool, user, "tmp-child", BARE).await;
    let parent = seed_workflow(&pool, user, "prod-parent", &parent_of(child)).await;
    let other_prefix = seed_workflow(&pool, user, "keep-me", BARE).await;
    let strangers = seed_workflow(&pool, stranger, "tmp-not-yours", BARE).await;

    let cleanup = repo
        .cleanup_workflows(user, Some("tmp-"))
        .await
        .expect("cleanup");
    let mut deleted = cleanup.outcome.deleted.clone();
    deleted.sort_unstable();
    let mut expected = vec![plain, finished];
    expected.sort_unstable();
    assert_eq!(deleted, expected, "only the unguarded matches go");
    assert_eq!(cleanup.outcome.blocked_running, vec![running]);
    assert_eq!(cleanup.outcome.blocked_referenced.len(), 1);
    assert_eq!(cleanup.outcome.blocked_referenced[0].id, child);
    assert_eq!(
        cleanup.outcome.blocked_referenced[0].parents,
        vec!["prod-parent".to_string()]
    );
    assert!(!cleanup.truncated);

    assert!(
        exists(&pool, running).await,
        "a workflow with a RUNNING execution was deleted"
    );
    let exec_alive: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM workflow_executions WHERE id = $1)")
            .bind(exec)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(exec_alive, "the running execution was cascaded away");
    assert!(
        exists(&pool, child).await,
        "a child an enabled parent dispatches into was deleted"
    );
    for (id, why) in [
        (parent, "the parent"),
        (other_prefix, "another prefix"),
        (strangers, "another user's row"),
    ] {
        assert!(exists(&pool, id).await, "{why} must be untouched");
    }
}

/// The prefix is a LITERAL: `%` and `_` in it match themselves (MCP-719).
#[tokio::test]
async fn the_prefix_is_matched_literally() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = WorkflowRepository::new(pool.clone());
    let literal = seed_workflow(&pool, user, "a_%b-one", BARE).await;
    // Each bait is matched by exactly ONE unescaped wildcard.
    let percent_bait = seed_workflow(&pool, user, "a_ZZZb-two", BARE).await;
    let underscore_bait = seed_workflow(&pool, user, "aZ%b-three", BARE).await;
    let cleanup = repo
        .cleanup_workflows(user, Some("a_%b"))
        .await
        .expect("cleanup");
    assert_eq!(cleanup.outcome.deleted, vec![literal]);
    assert!(
        exists(&pool, percent_bait).await,
        "`%` in the prefix acted as a wildcard"
    );
    assert!(
        exists(&pool, underscore_bait).await,
        "`_` in the prefix acted as a wildcard"
    );
}

/// Delete-all: a parent inside the delete set is not a reason to refuse its
/// child, and the running guard still holds.
#[tokio::test]
async fn delete_all_takes_a_parent_with_its_child_and_still_spares_a_running_one() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let actor = seed_actor(&pool, user).await;
    let repo = WorkflowRepository::new(pool.clone());
    let child = seed_workflow(&pool, user, "child", BARE).await;
    let parent = seed_workflow(&pool, user, "parent", &parent_of(child)).await;
    let running = seed_workflow(&pool, user, "busy", BARE).await;
    seed_execution(&pool, running, user, actor, "queued").await;

    let cleanup = repo.cleanup_workflows(user, None).await.expect("cleanup");
    assert_eq!(cleanup.outcome.deleted.len(), 2);
    assert!(!exists(&pool, child).await && !exists(&pool, parent).await);
    assert_eq!(cleanup.outcome.blocked_running, vec![running]);
    assert!(cleanup.outcome.blocked_referenced.is_empty());
}

/// One call is bounded, says so, and a second call finishes the job.
#[tokio::test]
async fn one_call_is_bounded_and_says_when_more_matched() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = WorkflowRepository::new(pool.clone());
    let cap = talos_workflow_repository::CLEANUP_WORKFLOWS_MAX;
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, graph_json, module_uri, status, is_enabled) \
         SELECT gen_random_uuid(), $1, 'bulk-' || g, $2, 'talos://t', 'draft', true \
         FROM generate_series(1, $3::int) g",
    )
    .bind(user)
    .bind(BARE)
    .bind(i32::try_from(cap + 1).unwrap())
    .execute(&pool)
    .await
    .expect("bulk seed");

    // Another tenant's rows under the same prefix must not spend this
    // caller's cap, nor turn `truncated` on for a caller with five rows.
    let stranger = seed_user(&pool).await;
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, graph_json, module_uri, status, is_enabled) \
         SELECT gen_random_uuid(), $1, 'mix-' || g, $2, 'talos://t', 'draft', true \
         FROM generate_series(1, $3::int) g",
    )
    .bind(stranger)
    .bind(BARE)
    .bind(i32::try_from(cap + 1).unwrap())
    .execute(&pool)
    .await
    .expect("stranger bulk seed");
    for i in 0..5 {
        seed_workflow(&pool, user, &format!("mix-mine-{i}"), BARE).await;
    }
    let mixed = repo
        .cleanup_workflows(user, Some("mix-"))
        .await
        .expect("mixed");
    assert_eq!(mixed.outcome.deleted.len(), 5);
    assert!(
        !mixed.truncated,
        "another tenant's rows counted against this caller's cap"
    );

    let first = repo
        .cleanup_workflows(user, Some("bulk-"))
        .await
        .expect("first");
    assert_eq!(first.outcome.deleted.len() as i64, cap);
    assert!(first.truncated, "more matched than one call deletes");
    let second = repo
        .cleanup_workflows(user, Some("bulk-"))
        .await
        .expect("second");
    assert_eq!(second.outcome.deleted.len(), 1);
    assert!(!second.truncated);
}

/// The tenant predicate, on its own. On an UNSCOPED connection no RLS policy
/// narrows the read (unset GUC permits), so only `user_id = $1` stands between
/// one tenant's cleanup and another tenant's workflows.
#[tokio::test]
async fn the_id_resolution_is_tenant_scoped_without_help_from_rls() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let stranger = seed_user(&pool).await;
    let mine = seed_workflow(&pool, user, "shared-prefix-mine", BARE).await;
    let _theirs = seed_workflow(&pool, stranger, "shared-prefix-theirs", BARE).await;

    let mut conn = pool.acquire().await.expect("conn");
    let visible: i64 =
        sqlx::query_scalar("SELECT count(*) FROM workflows WHERE name LIKE 'shared-prefix-%'")
            .fetch_one(&mut *conn)
            .await
            .unwrap();
    assert_eq!(
        visible, 2,
        "CONTROL: this connection can see both tenants' rows"
    );

    let ids = WorkflowRepository::resolve_cleanup_ids(&mut conn, user, Some("shared-prefix-%"), 10)
        .await
        .expect("resolve");
    assert_eq!(ids, vec![mine]);
    let all = WorkflowRepository::resolve_cleanup_ids(&mut conn, user, None, 10)
        .await
        .expect("resolve all");
    assert_eq!(
        all,
        vec![mine],
        "delete-all is the caller's workflows, nobody else's"
    );
}
