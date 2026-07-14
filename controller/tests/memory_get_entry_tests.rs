//! DX-19 (2026-07-14): `talos_memory::recall_entry` — the read path behind
//! the additive `agent-memory::get-entry` WIT function. Proves that a memory
//! written through the canonical `persist_memory` fn reads back through
//! `recall_entry` with its value AND `created_at` metadata, and that an
//! absent key returns `Ok(None)` (never an error). Env-gated like the rest
//! of the controller suite (runs in quality.yml); uses the isolated-DB
//! harness (`common::isolated_db_pool`).

mod common;

use std::sync::Arc;
use uuid::Uuid;

fn set_master_key() {
    std::env::set_var(
        "TALOS_MASTER_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
}

async fn seed_actor_with_org(pool: &sqlx::Pool<sqlx::Postgres>) -> Uuid {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'h', true)",
    )
    .bind(user)
    .bind(format!("getentry-{user}@talos.test"))
    .execute(pool)
    .await
    .expect("seed user");
    let tag = Uuid::new_v4();
    let org: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (name, slug, owner_id, is_personal) \
         VALUES ($1, $2, $3, true) RETURNING id",
    )
    .bind(format!("getentryorg-{tag}"))
    .bind(format!("getentryorg-{tag}"))
    .bind(user)
    .fetch_one(pool)
    .await
    .expect("seed org");
    let actor = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO actors (id, user_id, name, org_id) VALUES ($1, $2, 'getentry-actor', $3)",
    )
    .bind(actor)
    .bind(user)
    .bind(org)
    .execute(pool)
    .await
    .expect("seed actor");
    actor
}

/// Register the REAL memory crypto hook so `persist_memory` encrypts and
/// `recall_entry` decrypts through the same versioned path as production.
async fn register_crypto(pool: &sqlx::Pool<sqlx::Postgres>) {
    let sm = Arc::new(controller::secrets::SecretsManager::new(pool.clone()).unwrap());
    sm.initialize().await.unwrap();
    // Idempotent OnceLock — first registration wins; safe across tests.
    talos_memory::register_memory_crypto_hook(Arc::new(
        talos_memory_crypto::SecretsManagerMemoryCrypto::new(sm),
    ));
}

#[tokio::test]
async fn recall_entry_returns_value_and_created_at() {
    set_master_key();
    let (pool, _db) = common::isolated_db_pool().await;
    register_crypto(&pool).await;

    let actor = seed_actor_with_org(&pool).await;

    // "scratchpad" skips the embedding provider (no Ollama in CI) while
    // exercising the identical encrypt + UPSERT path as any other type.
    let key = format!("daily_brief/{}", Uuid::new_v4());
    talos_memory::persist_memory(
        &pool,
        actor,
        &key,
        &serde_json::json!({ "summary": "todays brief" }),
        "scratchpad",
        None,
    )
    .await
    .expect("persist memory");

    let entry = talos_memory::recall_entry(&pool, actor, &key)
        .await
        .expect("recall_entry ok")
        .expect("entry present");

    assert_eq!(
        entry.value,
        serde_json::json!({ "summary": "todays brief" })
    );
    assert_eq!(entry.memory_type, "scratchpad");
    // created_at is a real, non-default timestamp populated by the DB.
    assert!(
        entry.created_at.timestamp() > 0,
        "created_at must be a real epoch timestamp, got {}",
        entry.created_at
    );
    // scratchpad carries a 24h default TTL → expiry present and in the future.
    let expires = entry.expires_at.expect("scratchpad entry has a 24h TTL");
    assert!(
        expires > entry.created_at,
        "expires_at ({expires}) must be after created_at ({})",
        entry.created_at
    );
}

#[tokio::test]
async fn recall_entry_absent_key_is_none_not_error() {
    set_master_key();
    let (pool, _db) = common::isolated_db_pool().await;
    register_crypto(&pool).await;

    let actor = seed_actor_with_org(&pool).await;

    let missing = format!("daily_brief/never-written-{}", Uuid::new_v4());
    let got = talos_memory::recall_entry(&pool, actor, &missing)
        .await
        .expect("recall_entry must not error on an absent key");
    assert!(got.is_none(), "absent key must be Ok(None), never an error");
}
