//! `delete_actor` (2026-09-30): the only path that deletes an actor, and it
//! records what it removes in the same transaction.
//!
//! Drives the PRODUCTION `ActorRepository::delete_actor_recorded` against a
//! real clone through every outcome. Each refusal is checked to have written
//! nothing; the delete is checked to have removed the actor and its cascades
//! and to have copied the actor's own audit trail into `admin_event_log`.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use sqlx::{Pool, Postgres};
use talos_actor_repository::{ActorDeletion, ActorRepository};
use uuid::Uuid;

async fn user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'del')")
        .bind(id)
        .bind(format!("delete-actor-{id}@example.com"))
        .execute(pool)
        .await
        .expect("seed user");
    id
}

async fn actor(
    pool: &Pool<Postgres>,
    owner: Uuid,
    name: &str,
    status: &str,
    is_default: bool,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO actors (id, user_id, name, status, is_default) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(owner)
    .bind(name)
    .bind(status)
    .bind(is_default)
    .execute(pool)
    .await
    .expect("seed actor");
    id
}

async fn exists(pool: &Pool<Postgres>, id: Uuid) -> bool {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM actors WHERE id = $1)")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("exists")
}

async fn audit_rows(pool: &Pool<Postgres>, id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM admin_event_log WHERE resource_id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("audit count")
}

#[tokio::test]
async fn every_refusal_writes_nothing() {
    let (pool, _db) = common::isolated_db_pool().await;
    let repo = ActorRepository::new(pool.clone());
    let me = user(&pool).await;
    let other = user(&pool).await;

    let foreign = actor(&pool, other, "theirs", "terminated", false).await;
    let default = actor(&pool, me, "my-default", "terminated", true).await;
    let active = actor(&pool, me, "still-running", "active", false).await;
    let bound = actor(&pool, me, "has-workflow", "terminated", false).await;
    let ran = actor(&pool, me, "has-history", "archived", false).await;
    let named = actor(&pool, me, "the-name", "terminated", false).await;

    let wf = common::create_test_workflow(&pool, me, "bound-to-actor").await;
    sqlx::query("UPDATE workflows SET actor_id = $2 WHERE id = $1")
        .bind(wf)
        .bind(bound)
        .execute(&pool)
        .await
        .expect("bind workflow");
    sqlx::query(
        "INSERT INTO workflow_executions (id, workflow_id, user_id, status, started_at, actor_id) \
         VALUES ($1, $2, $3, 'completed', NOW(), $4)",
    )
    .bind(Uuid::new_v4())
    .bind(common::create_test_workflow(&pool, me, "ran-once").await)
    .bind(me)
    .bind(ran)
    .execute(&pool)
    .await
    .expect("seed execution");

    let del = |id: Uuid, name: &'static str| repo.delete_actor_recorded(id, me, false, Some(name));
    assert_eq!(
        del(foreign, "theirs").await.unwrap(),
        ActorDeletion::NotFound,
        "no existence oracle"
    );
    assert_eq!(
        del(default, "my-default").await.unwrap(),
        ActorDeletion::DefaultActor
    );
    assert!(matches!(
        del(active, "still-running").await.unwrap(),
        ActorDeletion::NotFinal { .. }
    ));
    assert!(matches!(
        del(bound, "has-workflow").await.unwrap(),
        ActorDeletion::StillReferenced(r) if r.workflows == 1
    ));
    assert!(matches!(
        del(ran, "has-history").await.unwrap(),
        ActorDeletion::StillReferenced(r) if r.executions == 1
    ));
    assert_eq!(
        del(named, "wrong-name").await.unwrap(),
        ActorDeletion::NameMismatch
    );

    for id in [foreign, default, active, bound, ran, named] {
        assert!(
            exists(&pool, id).await,
            "a refused delete must leave the actor"
        );
        assert_eq!(
            audit_rows(&pool, id).await,
            0,
            "a refused delete must record nothing"
        );
    }
}

#[tokio::test]
async fn a_dry_run_writes_nothing_and_a_delete_records_what_it_removed() {
    let (pool, _db) = common::isolated_db_pool().await;
    let repo = ActorRepository::new(pool.clone());
    let me = user(&pool).await;
    let probe = actor(&pool, me, "probe", "terminated", false).await;
    for (kind, summary) in [
        ("created", "probe created"),
        ("terminated", "probe terminated"),
    ] {
        sqlx::query(
            "INSERT INTO actor_action_log (actor_id, action_type, summary) VALUES ($1, $2, $3)",
        )
        .bind(probe)
        .bind(kind)
        .bind(summary)
        .execute(&pool)
        .await
        .expect("seed action log");
    }
    sqlx::query("INSERT INTO actor_budget_policies (actor_id) VALUES ($1)")
        .bind(probe)
        .execute(&pool)
        .await
        .expect("seed budget policy");

    let preview = repo
        .delete_actor_recorded(probe, me, true, None)
        .await
        .unwrap();
    let ActorDeletion::WouldDelete { removed, .. } = preview else {
        panic!("dry run should pass: {preview:?}")
    };
    assert_eq!(
        (removed.action_log_entries, removed.budget_policies),
        (2, 1)
    );
    assert!(exists(&pool, probe).await, "dry run deletes nothing");
    assert_eq!(audit_rows(&pool, probe).await, 0, "dry run records nothing");

    let done = repo
        .delete_actor_recorded(probe, me, false, Some("probe"))
        .await
        .unwrap();
    assert!(matches!(done, ActorDeletion::Deleted { .. }), "{done:?}");
    assert!(!exists(&pool, probe).await);
    let left: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM actor_action_log WHERE actor_id = $1), \
                (SELECT COUNT(*) FROM actor_budget_policies WHERE actor_id = $1)",
    )
    .bind(probe)
    .fetch_one(&pool)
    .await
    .expect("cascades");
    assert_eq!(left, (0, 0), "the cascades ran");

    // The audit trail outlived the actor: one record, holding its action log.
    let (event, details): (String, serde_json::Value) =
        sqlx::query_as("SELECT event_type, details FROM admin_event_log WHERE resource_id = $1")
            .bind(probe)
            .fetch_one(&pool)
            .await
            .expect("exactly one audit record");
    assert_eq!(event, "actor_deleted");
    assert_eq!(details["removed"]["action_log_entries"], 2);
    assert_eq!(details["action_log"][1]["summary"], "probe terminated");
    assert_eq!(details["action_log_truncated"], false);

    // The name is free again.
    actor(&pool, me, "probe", "active", false).await;
}
