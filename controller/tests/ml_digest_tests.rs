//! RFC 0011 P2d disagreement-digest delivery against a real database:
//! a pending disagreement is decrypted and delivered to the model's
//! configured digest actor's memory, tenancy is enforced on the digest
//! actor, and the correction round-trip closes the loop.

mod common;

use std::sync::Arc;
use talos_ml::{run_digest_tick, LifecycleService};
use uuid::Uuid;

fn set_master_key() {
    std::env::set_var(
        "TALOS_MASTER_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
}

async fn seed_user(pool: &sqlx::Pool<sqlx::Postgres>, id: Uuid) {
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) \
         VALUES ($1, $2, 'not-a-real-hash', true) ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(format!("{id}@ml-digest.test"))
    .execute(pool)
    .await
    .expect("seed user");
}

async fn seed_actor(pool: &sqlx::Pool<sqlx::Postgres>, id: Uuid, user_id: Uuid) {
    sqlx::query("INSERT INTO actors (id, user_id, name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(user_id)
        .bind(format!("actor-{id}"))
        .execute(pool)
        .await
        .expect("seed actor");
}

/// Model with a policy + a `digest.actor_id` pointing at `digest_actor`.
async fn seed_model_with_digest(
    pool: &sqlx::Pool<sqlx::Postgres>,
    user_id: Uuid,
    dataset_id: Uuid,
    digest_actor: Uuid,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO ml_models (id, user_id, name, task_type, dataset_id, config_json, policy_json) \
         VALUES ($1, $2, $3, 'classification', $4, \
                 jsonb_build_object('digest', jsonb_build_object('actor_id', $5::text)), \
                 '{\"min_examples\": 1}'::jsonb)",
    )
    .bind(id)
    .bind(user_id)
    .bind(format!("m-{id}"))
    .bind(dataset_id)
    .bind(digest_actor.to_string())
    .execute(pool)
    .await
    .expect("seed model");
    id
}

async fn seed_dataset(pool: &sqlx::Pool<sqlx::Postgres>, user_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO ml_datasets (id, user_id, name, task_type) \
         VALUES ($1, $2, $3, 'classification')",
    )
    .bind(id)
    .bind(user_id)
    .bind(format!("ds-{id}"))
    .execute(pool)
    .await
    .expect("seed dataset");
    id
}

/// Initialized SecretsManager + the real memory-crypto hook installed
/// (idempotent OnceLock — first test wins), so both the disagreement
/// encryption and the actor_memory write path work.
async fn service(pool: &sqlx::Pool<sqlx::Postgres>) -> LifecycleService {
    set_master_key();
    let sm = Arc::new(controller::secrets::SecretsManager::new(pool.clone()).unwrap());
    sm.initialize().await.unwrap();
    talos_memory::register_memory_crypto_hook(Arc::new(
        talos_memory_crypto::SecretsManagerMemoryCrypto::new(sm.clone()),
    ));
    LifecycleService::new(sm)
}

#[tokio::test]
async fn digest_delivers_pending_disagreements_to_the_configured_owner_actor() {
    let (pool, _db) = common::isolated_db_pool().await;
    set_master_key();
    let user = Uuid::new_v4();
    seed_user(&pool, user).await;
    let digest_actor = Uuid::new_v4();
    seed_actor(&pool, digest_actor, user).await;
    let ds = seed_dataset(&pool, user).await;
    let model = seed_model_with_digest(&pool, user, ds, digest_actor).await;

    let svc = service(&pool).await;

    // A real (encrypted) divergence + a low-confidence sample.
    let mut conn = pool.acquire().await.unwrap();
    svc.record_disagreement(
        &mut conn,
        model,
        user,
        None,
        Some("msg-a"),
        "Subject: invoice overdue — can you approve?",
        Some(("archive", 0.55)),
        "follow_up",
        "divergence",
    )
    .await
    .unwrap();
    svc.record_disagreement(
        &mut conn,
        model,
        user,
        None,
        Some("msg-b"),
        "Subject: a totally novel sender the model has never seen",
        None,
        "to_read",
        "low_confidence",
    )
    .await
    .unwrap();
    drop(conn);

    // Run the digest tick (the scheduled task's kernel).
    let delivered = run_digest_tick(&pool, &svc).await.unwrap();
    assert_eq!(delivered, 1, "one model had a digest delivered");

    // The digest landed in the CONFIGURED actor's memory, keyed by
    // model_id, stamped ml_digest, and NOT embedded (scratchpad — the
    // decrypted email previews must not egress to an embedder).
    let (kind, mtype, embedded): (String, String, bool) = sqlx::query_as(
        "SELECT metadata->>'kind', memory_type, embedding IS NOT NULL \
         FROM actor_memory WHERE actor_id = $1 AND key = 'ml_digest/' || $2::text",
    )
    .bind(digest_actor)
    .bind(model)
    .fetch_one(&pool)
    .await
    .expect("digest memory row exists");
    assert_eq!(kind, "ml_digest");
    assert_eq!(mtype, "scratchpad", "digest must not be embedded");
    assert!(
        !embedded,
        "digest carries decrypted content; must not embed"
    );

    // Rotation cursor advanced (starvation guard).
    let stamped: bool =
        sqlx::query_scalar("SELECT last_digest_at IS NOT NULL FROM ml_models WHERE id = $1")
            .bind(model)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(stamped, "last_digest_at stamped on visit");
}

#[tokio::test]
async fn digest_refuses_an_actor_owned_by_another_user() {
    let (pool, _db) = common::isolated_db_pool().await;
    set_master_key();
    let owner = Uuid::new_v4();
    let stranger = Uuid::new_v4();
    seed_user(&pool, owner).await;
    seed_user(&pool, stranger).await;
    // Digest actor belongs to the STRANGER, not the model owner.
    let foreign_actor = Uuid::new_v4();
    seed_actor(&pool, foreign_actor, stranger).await;
    let ds = seed_dataset(&pool, owner).await;
    let model = seed_model_with_digest(&pool, owner, ds, foreign_actor).await;

    let svc = service(&pool).await;
    let mut conn = pool.acquire().await.unwrap();
    svc.record_disagreement(
        &mut conn,
        model,
        owner,
        None,
        Some("m1"),
        "Subject: leak me into the stranger's memory",
        None,
        "archive",
        "low_confidence",
    )
    .await
    .unwrap();
    drop(conn);

    // The tenancy gate must refuse: no cross-tenant delivery.
    let delivered = run_digest_tick(&pool, &svc).await.unwrap();
    assert_eq!(delivered, 0, "cross-owner digest actor is refused");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM actor_memory WHERE actor_id = $1")
        .bind(foreign_actor)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0, "nothing written to the foreign actor");
}
