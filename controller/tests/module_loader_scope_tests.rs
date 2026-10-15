//! The GraphQL `ModuleLoader` resolves a module only for a user who may see
//! it now (security review 2026-10-14, A-10 / D-9): their own, an org they
//! belong to, or the catalog. A member who ran an org-shared module and left
//! the org no longer reaches its current source.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use async_graphql::dataloader::Loader as _;
use controller::api::schema::{ModuleKey, ModuleLoader};
use uuid::Uuid;

async fn seed_user(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(id)
    .bind(format!("{id}@module-loader.test"))
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn seed_module(pool: &sqlx::PgPool, user: Option<Uuid>, org: Option<Uuid>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO modules (id, user_id, org_id, name, kind, capability_world, source_code) \
         VALUES ($1, $2, $3, $4, 'sandbox', 'minimal-node', 'fn current() {}')",
    )
    .bind(id)
    .bind(user)
    .bind(org)
    .bind(format!("loader-{}", &id.to_string()[..8]))
    .execute(pool)
    .await
    .unwrap();
    id
}

#[tokio::test]
async fn a_module_resolves_only_for_a_reader_who_may_see_it_now() {
    let (pool, _db) = common::isolated_db_pool().await;
    let owner = seed_user(&pool).await;
    let member = seed_user(&pool).await;
    let org: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (name, slug, owner_id, is_personal) \
         VALUES ($1, $1, $2, false) RETURNING id",
    )
    .bind(format!("loader-org-{}", Uuid::new_v4().simple()))
    .bind(owner)
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO organization_members (org_id, user_id, role) VALUES ($1, $2, 'member')",
    )
    .bind(org)
    .bind(member)
    .execute(&pool)
    .await
    .unwrap();
    let shared = seed_module(&pool, Some(owner), Some(org)).await;
    let own = seed_module(&pool, Some(member), None).await;
    let catalog = seed_module(&pool, None, None).await;
    let others = seed_module(&pool, Some(owner), None).await;

    let loader = ModuleLoader(pool.clone());
    let loader = &loader;
    let resolve = |ids: Vec<Uuid>| {
        let keys: Vec<ModuleKey> = ids
            .into_iter()
            .map(|module_id| ModuleKey {
                user_id: member,
                module_id,
            })
            .collect();
        async move {
            let mut found: Vec<Uuid> = loader
                .load(&keys)
                .await
                .expect("load")
                .into_keys()
                .map(|k| k.module_id)
                .collect();
            found.sort();
            found
        }
    };
    let mut want = vec![shared, own, catalog];
    want.sort();
    assert_eq!(resolve(vec![shared, own, catalog, others]).await, want);

    sqlx::query("DELETE FROM organization_members WHERE org_id = $1 AND user_id = $2")
        .bind(org)
        .bind(member)
        .execute(&pool)
        .await
        .unwrap();
    let mut want = vec![own, catalog];
    want.sort();
    assert_eq!(
        resolve(vec![shared, own, catalog, others]).await,
        want,
        "after leaving the org, the shared module no longer resolves"
    );
}
