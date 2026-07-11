//! Tenancy isolation for the ML model registry (RFC 0011 P2c).
//!
//! The `talos.ml.predict` serving path and every MCP ml_* handler
//! resolve models through `ModelRegistry::{resolve_by_name,
//! resolve_by_id, list_models}`. Review 2026-07-11: isolation must NOT
//! rest on RLS alone — RLS enforces only under `TALOS_RLS_SET_ROLE` and
//! never on superuser pools (the common in-cluster deploy) — so the
//! resolvers carry an app-layer owner predicate. This is the
//! cross-tenant isolation test the platform-primitive checklist (§8)
//! requires for every new signed-RPC primitive: same-named models owned
//! by two users must never resolve across the boundary, foreign ids
//! must be indistinguishable from absent ones, and the promote path's
//! ownership gate (scoped resolve_by_id) must hold even for
//! dataset-less models.

mod common;

use talos_ml::ModelRegistry;
use uuid::Uuid;

async fn seed_user(pool: &sqlx::Pool<sqlx::Postgres>, id: Uuid, email: &str) {
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) \
         VALUES ($1, $2, 'not-a-real-hash', true) ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(email)
    .execute(pool)
    .await
    .expect("seed user");
}

/// Seed a personal model (org_id NULL). `dataset_id` stays NULL — the
/// promote-gate regression this guards involved exactly the
/// dataset-less state (`ON DELETE SET NULL`), where the old
/// dataset-ownership check was skipped entirely.
async fn seed_model(pool: &sqlx::Pool<sqlx::Postgres>, user_id: Uuid, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO ml_models (id, user_id, name, task_type, config_json) \
         VALUES ($1, $2, $3, 'classification', '{}'::jsonb)",
    )
    .bind(id)
    .bind(user_id)
    .bind(name)
    .execute(pool)
    .await
    .expect("seed model");
    id
}

#[tokio::test]
async fn same_named_models_never_resolve_across_tenants() {
    let (pool, _db) = common::isolated_db_pool().await;

    let user_a = Uuid::new_v4();
    let user_b = Uuid::new_v4();
    seed_user(&pool, user_a, "a@ml-tenancy.test").await;
    seed_user(&pool, user_b, "b@ml-tenancy.test").await;

    // The canonical collision: both tenants name their classifier the
    // same thing (per-scope unique index allows it).
    let model_a = seed_model(&pool, user_a, "inbox-classifier").await;
    let model_b = seed_model(&pool, user_b, "inbox-classifier").await;

    let mut conn = pool.acquire().await.expect("acquire");

    // Each caller resolves their OWN row — never the other tenant's,
    // regardless of id ordering (pre-fix, the unscoped ORDER BY … LIMIT 1
    // deterministically handed one tenant the other's model).
    let got_a = ModelRegistry::resolve_by_name(&mut conn, "inbox-classifier", user_a)
        .await
        .expect("resolve a")
        .expect("a sees a model");
    assert_eq!(got_a.model_id, model_a);
    let got_b = ModelRegistry::resolve_by_name(&mut conn, "inbox-classifier", user_b)
        .await
        .expect("resolve b")
        .expect("b sees a model");
    assert_eq!(got_b.model_id, model_b);

    // A user with no model of that name gets None — not a neighbor's.
    let stranger = Uuid::new_v4();
    seed_user(&pool, stranger, "c@ml-tenancy.test").await;
    assert!(
        ModelRegistry::resolve_by_name(&mut conn, "inbox-classifier", stranger)
            .await
            .expect("resolve stranger")
            .is_none()
    );
}

#[tokio::test]
async fn foreign_model_ids_are_indistinguishable_from_absent() {
    let (pool, _db) = common::isolated_db_pool().await;

    let owner = Uuid::new_v4();
    let intruder = Uuid::new_v4();
    seed_user(&pool, owner, "owner@ml-tenancy.test").await;
    seed_user(&pool, intruder, "intruder@ml-tenancy.test").await;
    let model_id = seed_model(&pool, owner, "private-model").await;

    let mut conn = pool.acquire().await.expect("acquire");

    // Owner resolves by id; the intruder gets None — the exact gate the
    // promote handler relies on for dataset-less models (a foreign id
    // must not be promotable, enumerable, or card-readable).
    assert!(ModelRegistry::resolve_by_id(&mut conn, model_id, owner)
        .await
        .expect("owner resolve")
        .is_some());
    assert!(ModelRegistry::resolve_by_id(&mut conn, model_id, intruder)
        .await
        .expect("intruder resolve")
        .is_none());

    // list_models is owner-scoped the same way.
    let owner_list = ModelRegistry::list_models(&mut conn, owner)
        .await
        .expect("owner list");
    assert_eq!(owner_list.len(), 1);
    let intruder_list = ModelRegistry::list_models(&mut conn, intruder)
        .await
        .expect("intruder list");
    assert!(intruder_list.is_empty());
}
