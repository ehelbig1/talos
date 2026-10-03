//! The boot seed writes a shared catalog row's fuel limit (2026-10-03).
//!
//! Until then `upsert_catalog_template_by_slug` never wrote
//! `modules.max_fuel`: every shared row sat at the column default whatever
//! its template recommended, while an installed copy of the same template
//! carried the recommendation. Workflow nodes run directly on shared rows.
//!
//! Driven through the real row writer against a real clone. `common`
//! harness (a template clone per test), so the migrated-database job runs it.

mod common;

use serde_json::json;
use sqlx::{Pool, Postgres};
use talos_registry::reconcile::{
    upsert_catalog_template_by_slug, CatalogSource, CatalogUpsert, SHARED_CATALOG_DEFAULT_MAX_FUEL,
};
use uuid::Uuid;

async fn seed(pool: &Pool<Postgres>, slug: &str, name: &str, max_fuel: Option<i64>) -> Uuid {
    let schema = json!({"type": "object", "properties": {}});
    upsert_catalog_template_by_slug(
        pool,
        CatalogUpsert {
            name,
            category: "Network",
            description: "a made-up template",
            config_schema: &schema,
            source: CatalogSource::Disk {
                source_code: "pub fn run() {}",
            },
            allowed_hosts: &[],
            allowed_methods: &[],
            allowed_secrets: &[],
            requires_approval_for: &[],
            capability_world_long: "minimal-node",
            catalog_slug: slug,
            dependencies: None,
            max_fuel,
        },
    )
    .await
    .expect("the seed upsert")
    .id
}

async fn limit_of(pool: &Pool<Postgres>, id: Uuid) -> Option<i64> {
    sqlx::query_scalar("SELECT max_fuel FROM modules WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("the row")
}

#[tokio::test]
async fn a_new_shared_row_carries_the_limit_it_was_seeded_with() {
    let (pool, _db) = common::isolated_db_pool().await;
    let slug = format!("seed-fuel-{}", Uuid::new_v4());

    let id = seed(&pool, &slug, &format!("Seed Fuel {slug}"), Some(5_850_000)).await;
    assert_eq!(limit_of(&pool, id).await, Some(5_850_000));

    // The same template seeded again (every boot does) keeps tracking it:
    // raised, then lowered, then back to the default when it stops
    // recommending anything.
    for limit in [18_100_000, 1_000_000, SHARED_CATALOG_DEFAULT_MAX_FUEL] {
        let again = seed(&pool, &slug, &format!("Seed Fuel {slug}"), Some(limit)).await;
        assert_eq!(again, id, "the slug names one row");
        assert_eq!(limit_of(&pool, id).await, Some(limit));
    }
}

/// `None` is "the recommendation could not be read": it changes nothing.
#[tokio::test]
async fn an_unreadable_recommendation_leaves_the_limit_as_it_is() {
    let (pool, _db) = common::isolated_db_pool().await;
    let slug = format!("seed-fuel-{}", Uuid::new_v4());
    let name = format!("Seed Fuel {slug}");

    // A row that has never had a readable recommendation is at the default.
    let id = seed(&pool, &slug, &name, None).await;
    assert_eq!(
        limit_of(&pool, id).await,
        Some(SHARED_CATALOG_DEFAULT_MAX_FUEL)
    );

    seed(&pool, &slug, &name, Some(12_330_000)).await;
    seed(&pool, &slug, &name, None).await;
    assert_eq!(
        limit_of(&pool, id).await,
        Some(12_330_000),
        "an unreadable rule neither raises nor lowers the limit"
    );
}

/// The constant the seed writes for a template that recommends nothing is
/// the column's own default, so "declares nothing" and "never seeded with a
/// limit" are one state.
#[tokio::test]
async fn the_default_the_seed_writes_is_the_columns_default() {
    let (pool, _db) = common::isolated_db_pool().await;
    let default: String = sqlx::query_scalar(
        "SELECT column_default FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name = 'modules' AND column_name = 'max_fuel'",
    )
    .fetch_one(&pool)
    .await
    .expect("modules.max_fuel has a default");
    assert_eq!(default, SHARED_CATALOG_DEFAULT_MAX_FUEL.to_string());
}

/// The path a legacy row takes (no slug yet, matched by name): the limit is
/// written there too, and the slug is backfilled.
#[tokio::test]
async fn a_row_matched_by_name_gets_the_limit_too() {
    let (pool, _db) = common::isolated_db_pool().await;
    let slug = format!("seed-fuel-{}", Uuid::new_v4());
    let name = format!("Seed Fuel {slug}");
    let legacy: Uuid = sqlx::query_scalar(
        "INSERT INTO modules (user_id, name, kind, capability_world) \
         VALUES (NULL, $1, 'catalog', 'minimal-node') RETURNING id",
    )
    .bind(&name)
    .fetch_one(&pool)
    .await
    .expect("a legacy shared row with no slug");
    assert_eq!(
        limit_of(&pool, legacy).await,
        Some(SHARED_CATALOG_DEFAULT_MAX_FUEL)
    );

    let id = seed(&pool, &slug, &name, Some(9_894_000)).await;
    assert_eq!(id, legacy, "matched by name, not duplicated");
    assert_eq!(limit_of(&pool, id).await, Some(9_894_000));
    // …and `None` on that path keeps what is there.
    let other = format!("seed-fuel-{}", Uuid::new_v4());
    let other_name = format!("Seed Fuel {other}");
    let kept: Uuid = sqlx::query_scalar(
        "INSERT INTO modules (user_id, name, kind, capability_world, max_fuel) \
         VALUES (NULL, $1, 'catalog', 'minimal-node', 7000000) RETURNING id",
    )
    .bind(&other_name)
    .fetch_one(&pool)
    .await
    .expect("a second legacy row");
    assert_eq!(seed(&pool, &other, &other_name, None).await, kept);
    assert_eq!(limit_of(&pool, kept).await, Some(7_000_000));
}

/// A user's installed copy of the same template keeps its own limit: the
/// seed sizes the shared row only.
#[tokio::test]
async fn an_installed_copy_keeps_its_own_limit() {
    let (pool, _db) = common::isolated_db_pool().await;
    let slug = format!("seed-fuel-{}", Uuid::new_v4());
    let name = format!("Seed Fuel {slug}");
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'seed fuel')",
    )
    .bind(user)
    .bind(format!("seed-fuel-{user}@example.com"))
    .execute(&pool)
    .await
    .expect("a user");
    let copy: Uuid = sqlx::query_scalar(
        "INSERT INTO modules (user_id, name, kind, capability_world, catalog_slug, max_fuel) \
         VALUES ($1, $2, 'catalog', 'minimal-node', $3, 1404000) RETURNING id",
    )
    .bind(user)
    .bind(&name)
    .bind(&slug)
    .fetch_one(&pool)
    .await
    .expect("an installed copy");

    let shared = seed(&pool, &slug, &name, Some(9_894_000)).await;
    assert_ne!(shared, copy);
    assert_eq!(limit_of(&pool, shared).await, Some(9_894_000));
    assert_eq!(
        limit_of(&pool, copy).await,
        Some(1_404_000),
        "the operator's copy is not resized"
    );
}
