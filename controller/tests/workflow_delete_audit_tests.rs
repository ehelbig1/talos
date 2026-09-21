//! A workflow delete and its `admin_event_log` record are one transaction.
//!
//! Until 2026-09-21 the three MCP deletes wrote their record from a detached
//! task AFTER the delete committed — a dropped task left an irreversible
//! delete with no record — and the record could not NAME what it deleted: the
//! name lives only on the row that is gone (all 21 live `workflow_deleted`
//! rows read "Workflow <uuid> deleted"). The dashboard's GraphQL delete and
//! hygiene `fix_all` recorded nothing at all.
mod common;

use serde_json::Value;
use sqlx::{Pool, Postgres, Row};
use talos_workflow_repository::{ScopedWorkflowDelete, WorkflowDeleteSurface, WorkflowRepository};
use uuid::Uuid;

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'delete audit')",
    )
    .bind(id)
    .bind(format!("delete-audit-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

async fn seed_workflow(pool: &Pool<Postgres>, user: Uuid, org: Option<Uuid>, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, org_id, name, graph_json, module_uri, status, is_enabled) \
         VALUES ($1, $2, $3, $4, '{\"nodes\":[],\"edges\":[]}', 'talos://t', 'active', true)",
    )
    .bind(id)
    .bind(user)
    .bind(org)
    .bind(name)
    .execute(pool)
    .await
    .expect("seed workflow");
    id
}

async fn seed_running_execution(pool: &Pool<Postgres>, wf: Uuid, user: Uuid) {
    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name) VALUES ($1, $2, $3)")
        .bind(actor)
        .bind(user)
        .bind(format!("delete-audit-actor-{actor}"))
        .execute(pool)
        .await
        .expect("actor");
    sqlx::query(
        "INSERT INTO workflow_executions (id, workflow_id, user_id, actor_id, status) \
         VALUES ($1, $2, $3, $4, 'running')",
    )
    .bind(Uuid::new_v4())
    .bind(wf)
    .bind(user)
    .bind(actor)
    .execute(pool)
    .await
    .expect("execution");
}

async fn exists(pool: &Pool<Postgres>, id: Uuid) -> bool {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM workflows WHERE id = $1)")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("exists")
}

struct Event {
    user_id: Option<Uuid>,
    event_type: String,
    resource_id: Option<Uuid>,
    summary: String,
    details: Value,
}

async fn workflow_events(pool: &Pool<Postgres>) -> Vec<Event> {
    sqlx::query(
        "SELECT user_id, event_type, resource_id, summary, details FROM admin_event_log \
         WHERE resource_type = 'workflow' ORDER BY created_at, id",
    )
    .fetch_all(pool)
    .await
    .expect("events")
    .into_iter()
    .map(|r| Event {
        user_id: r.try_get("user_id").unwrap(),
        event_type: r.try_get("event_type").unwrap(),
        resource_id: r.try_get("resource_id").unwrap(),
        summary: r.try_get("summary").unwrap(),
        details: r
            .try_get::<Option<Value>, _>("details")
            .unwrap()
            .unwrap_or(Value::Null),
    })
    .collect()
}

#[tokio::test]
async fn a_single_delete_records_the_workflow_by_name_and_a_miss_records_nothing() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = WorkflowRepository::new(pool.clone());
    let wf = seed_workflow(&pool, user, None, "quarterly-report").await;

    // A delete that removes nothing records nothing.
    let miss = repo
        .delete_workflows_checked(&[Uuid::new_v4()], user, WorkflowDeleteSurface::McpDelete)
        .await
        .expect("miss");
    assert!(miss.deleted.is_empty());
    assert!(workflow_events(&pool).await.is_empty());

    let outcome = repo
        .delete_workflows_checked(&[wf], user, WorkflowDeleteSurface::McpDelete)
        .await
        .expect("delete");
    assert_eq!(outcome.deleted, vec![wf]);
    assert!(!exists(&pool, wf).await);

    let events = workflow_events(&pool).await;
    assert_eq!(events.len(), 1, "exactly one record per deleted workflow");
    let e = &events[0];
    assert_eq!(e.event_type, "workflow_deleted");
    assert_eq!(e.user_id, Some(user));
    assert_eq!(e.resource_id, Some(wf));
    assert!(
        e.summary.contains("quarterly-report") && e.summary.contains("MCP delete_workflow"),
        "the summary names the workflow and the surface: {}",
        e.summary
    );
    assert_eq!(e.details["name"], "quarterly-report");
    assert_eq!(e.details["surface"], "mcp");
}

#[tokio::test]
async fn each_bulk_surface_writes_one_row_naming_every_workflow_removed() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = WorkflowRepository::new(pool.clone());

    // batch: two removed, one refused for a running execution.
    let a = seed_workflow(&pool, user, None, "batch-a").await;
    let b = seed_workflow(&pool, user, None, "batch-b").await;
    let busy = seed_workflow(&pool, user, None, "batch-busy").await;
    seed_running_execution(&pool, busy, user).await;
    // …and two refused because an enabled parent (outside the set) runs them.
    let child_a = seed_workflow(&pool, user, None, "batch-child-a").await;
    let child_b = seed_workflow(&pool, user, None, "batch-child-b").await;
    for child in [child_a, child_b] {
        let parent = seed_workflow(&pool, user, None, &format!("batch-parent-{child}")).await;
        sqlx::query("UPDATE workflows SET graph_json = $1 WHERE id = $2")
            .bind(format!(
                r#"{{"nodes":[{{"id":"g","type":"system:sub_workflow","data":{{"sub_workflow_id":"{child}"}}}}],"edges":[]}}"#
            ))
            .bind(parent)
            .execute(&pool)
            .await
            .expect("parent graph");
    }

    // A bulk call that removes nothing records nothing.
    let miss = repo
        .delete_workflows_checked(&[busy, child_a], user, WorkflowDeleteSurface::McpBatch)
        .await
        .expect("bulk miss");
    assert!(miss.deleted.is_empty());
    assert!(workflow_events(&pool).await.is_empty());

    let outcome = repo
        .delete_workflows_checked(
            &[a, b, busy, child_a, child_b],
            user,
            WorkflowDeleteSurface::McpBatch,
        )
        .await
        .expect("batch");
    assert_eq!(outcome.blocked_referenced.len(), 2);
    assert_eq!(outcome.deleted.len(), 2);
    assert_eq!(outcome.blocked_running, vec![busy]);
    assert!(exists(&pool, busy).await);

    // cleanup by prefix.
    seed_workflow(&pool, user, None, "tmp-one").await;
    let cleanup = repo
        .cleanup_workflows(user, Some("tmp-"))
        .await
        .expect("cleanup");
    assert_eq!(cleanup.outcome.deleted.len(), 1);

    // hygiene.
    let stale = seed_workflow(&pool, user, None, "stale-draft").await;
    repo.delete_workflows_checked(&[stale], user, WorkflowDeleteSurface::HygieneFixAll)
        .await
        .expect("hygiene");

    let events = workflow_events(&pool).await;
    let types: Vec<&str> = events.iter().map(|e| e.event_type.as_str()).collect();
    assert_eq!(
        types,
        vec![
            "workflows_bulk_deleted",
            "workflows_bulk_cleanup",
            "workflows_hygiene_deleted"
        ],
        "one row per CALL, per surface"
    );

    let batch = &events[0];
    assert_eq!(batch.user_id, Some(user));
    assert_eq!(batch.resource_id, None);
    assert_eq!(batch.details["deleted_count"], 2);
    assert_eq!(batch.details["refused_running"], 1);
    assert_eq!(batch.details["refused_referenced"], 2);
    let mut names: Vec<String> = batch.details["deleted_workflows"]
        .as_array()
        .expect("deleted_workflows")
        .iter()
        .map(|w| w["name"].as_str().unwrap().to_string())
        .collect();
    names.sort();
    assert_eq!(names, vec!["batch-a", "batch-b"]);
    let mut ids: Vec<String> = batch.details["deleted_workflow_ids"]
        .as_array()
        .expect("ids")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    ids.sort();
    let mut want = vec![a.to_string(), b.to_string()];
    want.sort();
    assert_eq!(ids, want);
    assert!(batch.summary.starts_with("2 workflow(s) deleted"));

    let cleanup_event = &events[1];
    assert_eq!(cleanup_event.details["prefix"], "tmp-");
    assert_eq!(
        cleanup_event.details["deleted_workflows"][0]["name"],
        "tmp-one"
    );
    // CONTROL: only the cleanup row carries a prefix.
    assert!(batch.details.get("prefix").is_none());

    assert_eq!(
        events[2].details["deleted_workflows"][0]["name"],
        "stale-draft"
    );
}

#[tokio::test]
async fn a_delete_that_cannot_be_recorded_does_not_happen() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = WorkflowRepository::new(pool.clone());
    let single = seed_workflow(&pool, user, None, "keep-single").await;
    let bulk = seed_workflow(&pool, user, None, "keep-bulk").await;
    let scoped = seed_workflow(&pool, user, None, "keep-scoped").await;

    sqlx::query("ALTER TABLE admin_event_log RENAME TO admin_event_log_away")
        .execute(&pool)
        .await
        .expect("rename");

    assert!(repo
        .delete_workflows_checked(&[single], user, WorkflowDeleteSurface::McpDelete)
        .await
        .is_err());
    assert!(repo
        .delete_workflows_checked(&[bulk], user, WorkflowDeleteSurface::McpBatch)
        .await
        .is_err());
    let mut tx = pool.begin().await.expect("tx");
    assert!(repo
        .delete_workflow_guarded_scoped(&mut tx, scoped, user, &[])
        .await
        .is_err());
    drop(tx);

    for (id, what) in [(single, "single"), (bulk, "bulk"), (scoped, "scoped")] {
        assert!(
            exists(&pool, id).await,
            "the {what} delete committed although its record could not be written"
        );
    }

    // CONTROL: with the table back, the same delete goes through.
    sqlx::query("ALTER TABLE admin_event_log_away RENAME TO admin_event_log")
        .execute(&pool)
        .await
        .expect("rename back");
    repo.delete_workflows_checked(&[single], user, WorkflowDeleteSurface::McpDelete)
        .await
        .expect("delete");
    assert!(!exists(&pool, single).await);
}

#[tokio::test]
async fn the_dashboard_delete_records_on_the_callers_transaction() {
    let (pool, _db) = common::isolated_db_pool().await;
    let owner = seed_user(&pool).await;
    let colleague = seed_user(&pool).await;
    let org = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO organizations (id, name, slug, owner_id) VALUES ($1, 'audit-org', $2, $3)",
    )
    .bind(org)
    .bind(format!("audit-org-{org}"))
    .bind(owner)
    .execute(&pool)
    .await
    .expect("org");
    let repo = WorkflowRepository::new(pool.clone());
    let rolled_back = seed_workflow(&pool, owner, None, "dash-rolled-back").await;
    let own = seed_workflow(&pool, owner, None, "dash-own").await;
    let shared = seed_workflow(&pool, owner, Some(org), "dash-shared").await;

    // A rolled-back caller transaction leaves neither the delete nor a record.
    let mut tx = pool.begin().await.expect("tx");
    let out = repo
        .delete_workflow_guarded_scoped(&mut tx, rolled_back, owner, &[])
        .await
        .expect("delete");
    assert!(matches!(out, ScopedWorkflowDelete::Deleted));
    tx.rollback().await.expect("rollback");
    assert!(exists(&pool, rolled_back).await);
    assert!(workflow_events(&pool).await.is_empty());

    // The owner's own delete.
    let mut tx = pool.begin().await.expect("tx");
    let out = repo
        .delete_workflow_guarded_scoped(&mut tx, own, owner, &[])
        .await
        .expect("delete");
    assert!(matches!(out, ScopedWorkflowDelete::Deleted));
    tx.commit().await.expect("commit");

    // An org colleague's delete of the owner's workflow.
    let mut tx = pool.begin().await.expect("tx");
    let out = repo
        .delete_workflow_guarded_scoped(&mut tx, shared, colleague, &[org])
        .await
        .expect("delete");
    assert!(matches!(out, ScopedWorkflowDelete::Deleted));
    tx.commit().await.expect("commit");

    // A stranger's attempt records nothing.
    let stranger = seed_user(&pool).await;
    let left = seed_workflow(&pool, owner, None, "dash-left").await;
    let mut tx = pool.begin().await.expect("tx");
    let out = repo
        .delete_workflow_guarded_scoped(&mut tx, left, stranger, &[])
        .await
        .expect("delete");
    assert!(matches!(out, ScopedWorkflowDelete::NotDeleted));
    tx.commit().await.expect("commit");

    let events = workflow_events(&pool).await;
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].event_type, "workflow_deleted");
    assert_eq!(events[0].user_id, Some(owner));
    assert_eq!(events[0].resource_id, Some(own));
    assert_eq!(events[0].details["name"], "dash-own");
    assert_eq!(events[0].details["surface"], "graphql");
    assert!(events[0].summary.contains("GraphQL deleteWorkflow"));
    assert!(
        events[0].details.get("owner_user_id").is_none(),
        "the owner's own delete names no second party"
    );

    assert_eq!(events[1].user_id, Some(colleague), "the ACTING user");
    assert_eq!(events[1].resource_id, Some(shared));
    assert_eq!(events[1].details["name"], "dash-shared");
    assert_eq!(events[1].details["owner_user_id"], owner.to_string());
}

/// TEXTUAL, and stated as such: no handler can be shown NOT to spawn a task by
/// driving it. The three MCP handlers and the hygiene service must not regrow
/// an out-of-transaction write for these event types.
#[test]
fn no_caller_regrows_a_detached_workflow_delete_record() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    for file in [
        "talos-mcp-handlers/src/workflows.rs",
        "talos-hygiene-service/src/lib.rs",
        "talos-api/src/schema/workflows/mutations.rs",
    ] {
        let src = std::fs::read_to_string(root.join(file)).expect(file);
        for event in [
            "\"workflow_deleted\"",
            "\"workflows_bulk_deleted\"",
            "\"workflows_bulk_cleanup\"",
            "\"workflows_hygiene_deleted\"",
        ] {
            assert!(
                !src.contains(event),
                "{file} names {event}: the repository records workflow deletes inside the delete's transaction"
            );
        }
    }
}

/// The refused-for-an-execution answer is owner-scoped on its own: another
/// user's busy workflow in the id list is in NEITHER set, so a caller cannot
/// learn that somebody else's id exists and is running.
#[tokio::test]
async fn another_users_busy_workflow_is_neither_deleted_nor_reported_blocked() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let other = seed_user(&pool).await;
    let repo = WorkflowRepository::new(pool.clone());
    let theirs = seed_workflow(&pool, other, None, "theirs-busy").await;
    seed_running_execution(&pool, theirs, other).await;
    let mine = seed_workflow(&pool, user, None, "mine-busy").await;
    seed_running_execution(&pool, mine, user).await;

    let outcome = repo
        .delete_workflows_checked(&[theirs, mine], user, WorkflowDeleteSurface::McpBatch)
        .await
        .expect("delete");
    assert!(outcome.deleted.is_empty());
    // CONTROL: the caller's own busy workflow IS reported.
    assert_eq!(outcome.blocked_running, vec![mine]);
    assert!(exists(&pool, theirs).await);
    assert!(workflow_events(&pool).await.is_empty());
}
