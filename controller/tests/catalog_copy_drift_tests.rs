//! A user's installed catalog copies are classified against the catalog
//! (2026-09-29).
//!
//! The seeder refreshes the SYSTEM catalog row; a user's installed copy is a
//! frozen row that workflows run, so a catalog fix is not live in it until it
//! is reinstalled — and nothing reported that. This drives the PRODUCTION
//! `ModuleRepository::list_catalog_copy_drift` against a real clone, one copy
//! per state, because the statement is built with `format!` and check 88's
//! PREPARE probe cannot see it.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use sqlx::{Pool, Postgres};
use talos_module_repository::{CatalogCopyState, ModuleRepository};
use uuid::Uuid;

async fn user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'drift')")
        .bind(id)
        .bind(format!("catalog-drift-{id}@example.com"))
        .execute(pool)
        .await
        .expect("seed user");
    id
}

/// A system catalog row (`user_id` NULL) or a user copy.
async fn module(
    pool: &Pool<Postgres>,
    owner: Option<Uuid>,
    name: &str,
    slug: Option<&str>,
    source: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO modules (id, user_id, name, kind, catalog_slug, source_code) \
         VALUES ($1, $2, $3, 'catalog', $4, $5)",
    )
    .bind(id)
    .bind(owner)
    .bind(name)
    .bind(slug)
    .bind(source)
    .execute(pool)
    .await
    .expect("seed module");
    id
}

async fn workflow_using(pool: &Pool<Postgres>, owner: Uuid, module: Uuid, status: &str) {
    let wf = common::create_test_workflow(
        pool,
        owner,
        &format!("uses-{module}-{status}-{}", Uuid::new_v4()),
    )
    .await;
    sqlx::query("UPDATE workflows SET status = $2, graph_json = $3 WHERE id = $1")
        .bind(wf)
        .bind(status)
        .bind(
            serde_json::json!({"nodes": [{"id": "n", "type": module.to_string()}], "edges": []})
                .to_string(),
        )
        .execute(pool)
        .await
        .expect("point workflow at module");
}

#[tokio::test]
async fn every_copy_is_classified_and_counted_against_the_catalog() {
    let (pool, _db) = common::isolated_db_pool().await;
    let me = user(&pool).await;
    let someone_else = user(&pool).await;

    // The catalog: current source for each template, plus an OCI-style row
    // with no source at all.
    module(&pool, None, "Tmpl A", Some("tmpl-a"), "fn a_v2() {}").await;
    module(&pool, None, "Tmpl B", Some("tmpl-b"), "fn b_v2() {}").await;
    module(&pool, None, "Tmpl C", Some("tmpl-c"), "fn c_v2() {}").await;
    module(&pool, None, "Legacy Name", Some("legacy"), "fn l_v2() {}").await;
    module(&pool, None, "From Registry", Some("oci-tmpl"), "").await;

    let current = module(&pool, Some(me), "Tmpl A", Some("tmpl-a"), "fn a_v2() {}").await;
    let behind = module(&pool, Some(me), "Tmpl B", Some("tmpl-b"), "fn b_v1() {}").await;
    let edited = module(&pool, Some(me), "Tmpl C", Some("tmpl-c"), "fn c_mine() {}").await;
    sqlx::query(
        "INSERT INTO module_update_history (module_id, user_id, size_bytes, new_hash) VALUES ($1, $2, 1, 'h')",
    )
    .bind(edited)
    .bind(me)
    .execute(&pool)
    .await
    .expect("hot-update history");
    // Installed before `catalog_slug` existed: matched by name.
    let legacy = module(&pool, Some(me), "Legacy Name", None, "fn l_v1() {}").await;
    let registry = module(&pool, Some(me), "From Registry", Some("oci-tmpl"), "").await;
    let orphan = module(&pool, Some(me), "Gone", Some("removed-tmpl"), "fn g() {}").await;
    // Another user's copy is not in my report.
    module(
        &pool,
        Some(someone_else),
        "Tmpl B",
        Some("tmpl-b"),
        "fn b_v1() {}",
    )
    .await;

    // Workflow use: my active + draft count; my archived and someone else's do not.
    workflow_using(&pool, me, behind, "active").await;
    workflow_using(&pool, me, behind, "draft").await;
    workflow_using(&pool, me, behind, "archived").await;
    workflow_using(&pool, someone_else, behind, "active").await;

    let rows = ModuleRepository::new(pool.clone())
        .list_catalog_copy_drift(me)
        .await
        .expect("read drift");
    let state = |id: Uuid| {
        let r = rows
            .iter()
            .find(|r| r.module_id == id)
            .expect("copy listed");
        (CatalogCopyState::of(r), r.live_workflows)
    };
    assert_eq!(rows.len(), 6, "only my six copies");
    assert_eq!(state(current), (CatalogCopyState::Current, 0));
    assert_eq!(
        state(behind),
        (CatalogCopyState::Behind, 2),
        "archived + other user's not counted"
    );
    assert_eq!(state(edited).0, CatalogCopyState::Detached);
    assert_eq!(
        state(legacy).0,
        CatalogCopyState::Behind,
        "a slug-less copy is matched by name"
    );
    assert_eq!(
        state(registry).0,
        CatalogCopyState::Unknown,
        "no source is never 'current'"
    );
    assert_eq!(state(orphan).0, CatalogCopyState::NotInCatalog);
}
