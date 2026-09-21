//! A module delete and its `admin_event_log` record are one transaction.
//!
//! Until 2026-09-21: `delete_module` and `cleanup_modules` recorded from a
//! detached task after the delete committed; `batch_delete_modules`,
//! `cleanup_module_versions` and hygiene `fix_all` recorded NOTHING; and no
//! record named a module — the cleanup row carried only a count, although its
//! own comment says it exists so a wiped module leaves a trace.
mod common;

use serde_json::Value;
use sqlx::{Pool, Postgres, Row};
use talos_module_repository::{ModuleDeleteSurface, ModuleRepository};
use uuid::Uuid;

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'module audit')",
    )
    .bind(id)
    .bind(format!("module-audit-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

/// `age_days` stamps `compiled_at` — `cleanup_modules` only takes old modules.
async fn seed_module(
    pool: &Pool<Postgres>,
    user: Uuid,
    name: &str,
    world: &str,
    age_days: i32,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO modules (id, user_id, name, kind, capability_world, compiled_at) \
         VALUES ($1, $2, $3, 'sandbox', $4, NOW() - make_interval(days => $5::int))",
    )
    .bind(id)
    .bind(user)
    .bind(name)
    .bind(world)
    .bind(age_days)
    .execute(pool)
    .await
    .expect("seed module");
    id
}

async fn exists(pool: &Pool<Postgres>, id: Uuid) -> bool {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM modules WHERE id = $1)")
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

async fn module_events(pool: &Pool<Postgres>) -> Vec<Event> {
    sqlx::query(
        "SELECT user_id, event_type, resource_id, summary, details FROM admin_event_log \
         WHERE resource_type = 'module' ORDER BY created_at, id",
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

fn listed_names(e: &Event) -> Vec<String> {
    let mut names: Vec<String> = e.details["deleted_modules"]
        .as_array()
        .expect("deleted_modules")
        .iter()
        .map(|m| m["name"].as_str().unwrap().to_string())
        .collect();
    names.sort();
    names
}

#[tokio::test]
async fn a_single_delete_records_name_world_and_force_and_a_miss_records_nothing() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let other = seed_user(&pool).await;
    let repo = ModuleRepository::new(pool.clone());
    let module = seed_module(&pool, user, "gmail-fetch", "http-node", 0).await;
    let theirs = seed_module(&pool, other, "not-yours", "minimal-node", 0).await;

    // Unknown id and another user's module: nothing removed, nothing recorded.
    assert_eq!(
        repo.delete_module(Uuid::new_v4(), user, false)
            .await
            .unwrap(),
        0
    );
    assert_eq!(repo.delete_module(theirs, user, true).await.unwrap(), 0);
    assert!(exists(&pool, theirs).await);
    assert!(module_events(&pool).await.is_empty());

    assert_eq!(repo.delete_module(module, user, true).await.unwrap(), 1);
    assert!(!exists(&pool, module).await);
    let events = module_events(&pool).await;
    assert_eq!(events.len(), 1);
    let e = &events[0];
    assert_eq!(e.event_type, "module_deleted");
    assert_eq!(e.user_id, Some(user));
    assert_eq!(e.resource_id, Some(module));
    assert!(e.summary.contains("gmail-fetch"), "{}", e.summary);
    assert_eq!(e.details["name"], "gmail-fetch");
    assert_eq!(e.details["capability_world"], "http-node");
    assert_eq!(e.details["force"], true);

    // CONTROL: an unforced delete says so.
    let plain = seed_module(&pool, user, "plain", "minimal-node", 0).await;
    repo.delete_module(plain, user, false).await.unwrap();
    assert_eq!(module_events(&pool).await[1].details["force"], false);
}

#[tokio::test]
async fn each_bulk_surface_writes_one_row_naming_every_module_removed() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let other = seed_user(&pool).await;
    let repo = ModuleRepository::new(pool.clone());

    // batch: two of the caller's, one of somebody else's (untouched).
    let a = seed_module(&pool, user, "batch-a", "http-node", 0).await;
    let b = seed_module(&pool, user, "batch-b", "agent-node", 0).await;
    let theirs = seed_module(&pool, other, "batch-theirs", "minimal-node", 0).await;
    // A bulk call that removes nothing records nothing.
    assert_eq!(
        repo.batch_delete_modules(&[theirs], user, ModuleDeleteSurface::McpBatch)
            .await
            .unwrap(),
        0
    );
    assert!(module_events(&pool).await.is_empty());
    assert_eq!(
        repo.batch_delete_modules(&[a, b, theirs], user, ModuleDeleteSurface::McpBatch)
            .await
            .unwrap(),
        2
    );
    assert!(exists(&pool, theirs).await);

    // version cleanup.
    let v1 = seed_module(&pool, user, "ver-1", "minimal-node", 0).await;
    let surface = ModuleDeleteSurface::McpCleanupVersions { prefix: "ver-" };
    assert_eq!(
        repo.batch_delete_modules(&[v1], user, surface)
            .await
            .unwrap(),
        1
    );

    // cleanup of unreferenced, old modules by prefix; a fresh one survives.
    seed_module(&pool, user, "tmp-old", "http-node", 40).await;
    let fresh = seed_module(&pool, user, "tmp-fresh", "http-node", 0).await;
    assert_eq!(
        repo.cleanup_unreferenced_modules(user, Some("tmp-"), 30)
            .await
            .unwrap(),
        1
    );
    assert!(exists(&pool, fresh).await);

    // hygiene.
    let orphan = seed_module(&pool, user, "orphan", "minimal-node", 0).await;
    assert_eq!(
        repo.delete_orphaned_modules(&[orphan], user).await.unwrap(),
        1
    );

    let events = module_events(&pool).await;
    let types: Vec<&str> = events.iter().map(|e| e.event_type.as_str()).collect();
    assert_eq!(
        types,
        vec![
            "modules_bulk_deleted",
            "module_versions_cleanup",
            "modules_bulk_cleanup",
            "modules_hygiene_deleted"
        ],
        "one row per CALL, per surface"
    );
    for e in &events {
        assert_eq!(e.user_id, Some(user));
        assert_eq!(e.resource_id, None);
        assert_eq!(e.details["listed_truncated"], false);
    }

    let batch = &events[0];
    assert_eq!(batch.details["deleted_count"], 2);
    assert_eq!(listed_names(batch), vec!["batch-a", "batch-b"]);
    let worlds: std::collections::BTreeSet<String> = batch.details["deleted_modules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["capability_world"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        worlds.into_iter().collect::<Vec<_>>(),
        vec!["agent-node", "http-node"]
    );
    assert!(batch.summary.starts_with("2 module(s) deleted"));
    assert!(
        batch.details.get("prefix").is_none(),
        "CONTROL: no prefix on a batch"
    );

    assert_eq!(events[1].details["prefix"], "ver-");
    assert_eq!(listed_names(&events[1]), vec!["ver-1"]);

    assert_eq!(events[2].details["prefix"], "tmp-");
    assert_eq!(events[2].details["older_than_days"], 30);
    assert_eq!(listed_names(&events[2]), vec!["tmp-old"]);

    assert_eq!(listed_names(&events[3]), vec!["orphan"]);
}

#[tokio::test]
async fn a_bulk_record_lists_at_most_a_thousand_and_says_so() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = ModuleRepository::new(pool.clone());
    sqlx::query(
        "INSERT INTO modules (id, user_id, name, kind, compiled_at) \
         SELECT gen_random_uuid(), $1, 'bulk-' || g, 'sandbox', NOW() - INTERVAL '40 days' \
         FROM generate_series(1, 1001) g",
    )
    .bind(user)
    .execute(&pool)
    .await
    .expect("seed 1001");

    assert_eq!(
        repo.cleanup_unreferenced_modules(user, Some("bulk-"), 30)
            .await
            .unwrap(),
        1001
    );
    let events = module_events(&pool).await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].details["deleted_count"], 1001, "the TRUE count");
    assert_eq!(
        events[0].details["deleted_modules"]
            .as_array()
            .unwrap()
            .len(),
        1000
    );
    assert_eq!(events[0].details["listed_truncated"], true);
}

#[tokio::test]
async fn a_module_delete_that_cannot_be_recorded_does_not_happen() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = ModuleRepository::new(pool.clone());
    let single = seed_module(&pool, user, "keep-single", "minimal-node", 0).await;
    let batch = seed_module(&pool, user, "keep-batch", "minimal-node", 0).await;
    let old = seed_module(&pool, user, "keep-old", "minimal-node", 40).await;
    let orphan = seed_module(&pool, user, "keep-orphan", "minimal-node", 0).await;

    sqlx::query("ALTER TABLE admin_event_log RENAME TO admin_event_log_away")
        .execute(&pool)
        .await
        .expect("rename");

    assert!(repo.delete_module(single, user, false).await.is_err());
    assert!(repo
        .batch_delete_modules(&[batch], user, ModuleDeleteSurface::McpBatch)
        .await
        .is_err());
    assert!(repo
        .cleanup_unreferenced_modules(user, Some("keep-"), 30)
        .await
        .is_err());
    assert!(repo.delete_orphaned_modules(&[orphan], user).await.is_err());
    for (id, what) in [
        (single, "single"),
        (batch, "batch"),
        (old, "cleanup"),
        (orphan, "hygiene"),
    ] {
        assert!(
            exists(&pool, id).await,
            "the {what} delete committed although its record could not be written"
        );
    }

    // CONTROL: with the table back the same delete goes through.
    sqlx::query("ALTER TABLE admin_event_log_away RENAME TO admin_event_log")
        .execute(&pool)
        .await
        .expect("rename back");
    assert_eq!(repo.delete_module(single, user, false).await.unwrap(), 1);
}

/// TEXTUAL, and stated as such: the handlers and the hygiene service must not
/// regrow an out-of-transaction write for these event types.
#[test]
fn no_caller_regrows_a_detached_module_delete_record() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    for file in [
        "talos-mcp-handlers/src/modules.rs",
        "talos-hygiene-service/src/lib.rs",
    ] {
        let src = std::fs::read_to_string(root.join(file)).expect(file);
        for event in [
            "\"module_deleted\"",
            "\"modules_bulk_deleted\"",
            "\"modules_bulk_cleanup\"",
            "\"module_versions_cleanup\"",
            "\"modules_hygiene_deleted\"",
        ] {
            assert!(
                !src.contains(event),
                "{file} names {event}: the repository records module deletes inside the delete's transaction"
            );
        }
    }
}
