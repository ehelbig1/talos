//! The per-actor `actor_memory` row cap, driven through the REAL MCP dispatch
//! (2026-09-25).
//!
//! `MAX_MEMORIES_PER_ACTOR` moved from a check-then-insert in the MCP
//! `actor_remember` handler into the one persist statement every writer shares
//! (`talos_memory::PERSIST_MEMORY_ROW_SQL`). The statement itself is pinned by
//! `talos-memory/tests/integration.rs`; this binary pins the two MCP surfaces
//! whose BEHAVIOUR that move changed:
//!
//! * `compress_actor_context` — the tool whose purpose is to shrink an actor's
//!   memory. It used to write its replacements BEFORE retiring the originals,
//!   which is harmless without a cap and fatal with one: at the cap every
//!   replacement is a new key, so the tool would refuse for exactly the actor
//!   that most needs it. It now retires first, in the same transaction.
//! * `actor_remember` over an actor whose rows are partly EXPIRED — the
//!   handler's own pre-check counts live rows and passes; the chokepoint counts
//!   every row, refuses, reclaims this actor's expired rows and retries.
//!
//! # What this binary does NOT cover, stated rather than implied
//!
//! * `actor_remember`'s `QuotaExceeded` downcast arm is reached only when the
//!   handler's live-row pre-check passes AND the chokepoint still refuses after
//!   its reclaim — i.e. a concurrent writer takes the last slot between the two.
//!   That race is not reproduced here.
//! * The engine `__memory_write__` envelope and the signed memory RPC reach the
//!   same `persist_memory_with_metadata*` functions the talos-memory DB suite
//!   drives; they are not re-driven end to end here.

#[path = "common/mod.rs"]
mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use mcp_common::{agent, error_message, mcp_state, text_json};
use serde_json::Value;
use uuid::Uuid;

/// Register the actor-memory crypto hook. Process-global `OnceLock` bound to
/// THIS test's database (the hook's `SecretsManager` resolves DEKs from it),
/// so AT MOST ONE test per binary may call it — this binary has one test.
async fn register_crypto(pool: &sqlx::PgPool) {
    let sm = std::sync::Arc::new(
        controller::secrets::SecretsManager::new(pool.clone()).expect("secrets"),
    );
    sm.initialize().await.expect("initialize secrets");
    talos_memory::register_memory_crypto_hook(std::sync::Arc::new(
        talos_memory_crypto::SecretsManagerMemoryCrypto::new(sm),
    ));
}

async fn seed_user(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, created_at, updated_at) \
         VALUES ($1, $2, 'x', NOW(), NOW())",
    )
    .bind(id)
    .bind(format!("memcap-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

async fn seed_actor(pool: &sqlx::PgPool, user_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name, status) VALUES ($1, $2, $3, 'active')")
        .bind(id)
        .bind(user_id)
        .bind(format!("memcap-actor-{}", id.simple()))
        .execute(pool)
        .await
        .expect("seed actor");
    id
}

/// Fill the actor to exactly the cap in ONE statement, keys `cap/1..=cap`.
/// Dummy ciphertext under a real DEK id (the FK needs one); nothing here
/// decrypts a seeded row.
async fn seed_to_cap(pool: &sqlx::PgPool, actor_id: Uuid) {
    sqlx::query(
        "INSERT INTO actor_memory (actor_id, key, value_enc, value_key_id, value_format, memory_type) \
         SELECT $1, 'cap/' || g, '\\x00'::bytea, \
                (SELECT id FROM encryption_keys ORDER BY created_at LIMIT 1), 1, 'episodic' \
         FROM generate_series(1, $2::int) AS g",
    )
    .bind(actor_id)
    .bind(talos_memory::MAX_MEMORIES_PER_ACTOR as i32)
    .execute(pool)
    .await
    .expect("seed actor to the cap");
}

async fn row_count(pool: &sqlx::PgPool, actor_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM actor_memory WHERE actor_id = $1")
        .bind(actor_id)
        .fetch_one(pool)
        .await
        .expect("count rows")
}

async fn dispatch(
    state: &controller::mcp::McpState,
    user_id: Uuid,
    tool: &str,
    args: Value,
) -> controller::mcp::types::JsonRpcResponse {
    controller::mcp::actor::dispatch(
        tool,
        Some(serde_json::json!(1)),
        &args,
        state,
        agent(user_id),
    )
    .await
    .unwrap_or_else(|| panic!("{tool} is dispatched"))
}

#[tokio::test]
async fn compress_and_remember_work_at_the_cap_that_now_binds_every_writer() {
    let (pool, _db) = common::isolated_db_pool().await;
    register_crypto(&pool).await;
    let user_id = seed_user(&pool).await;
    let actor_id = seed_actor(&pool, user_id).await;
    let state = mcp_state(pool.clone()).await;
    seed_to_cap(&pool, actor_id).await;
    let cap = talos_memory::MAX_MEMORIES_PER_ACTOR;
    assert_eq!(row_count(&pool, actor_id).await, cap);

    // CONTROL: a plain new key at the cap is refused (the handler's own
    // pre-check answers first, with the count).
    let refused = dispatch(
        &state,
        user_id,
        "actor_remember",
        serde_json::json!({
            "actor_id": actor_id.to_string(),
            "key": "cap/new",
            "value": { "text": "one too many" },
        }),
    )
    .await;
    let msg = error_message(&refused);
    assert!(
        msg.contains("memory limit reached"),
        "a new key at the cap must be refused: {msg}"
    );
    assert_eq!(row_count(&pool, actor_id).await, cap);

    // 1. compress AT THE CAP: retire two, write one NEW key. The old order
    //    (write first) hit the cap before retiring anything and refused.
    let compressed = dispatch(
        &state,
        user_id,
        "compress_actor_context",
        serde_json::json!({
            "actor_id": actor_id.to_string(),
            "archive_keys": ["cap/1", "cap/2"],
            "replacement_entries": [{
                "key": "cap/condensed",
                "value": { "text": "the condensed replacement" },
                "memory_type": "episodic",
            }],
        }),
    )
    .await;
    let body = text_json(&compressed);
    assert_eq!(
        body.get("keys_retired").and_then(Value::as_u64),
        Some(2),
        "compress must work for an actor at the cap: {body}"
    );
    assert_eq!(row_count(&pool, actor_id).await, cap - 2 + 1);

    // 2. compress that adds MORE new keys than it retires is refused WHOLE:
    //    at cap-1, retiring one leaves cap-2, and three new keys need three
    //    slots. Nothing changes — not even the retirement.
    let before = row_count(&pool, actor_id).await;
    let over = dispatch(
        &state,
        user_id,
        "compress_actor_context",
        serde_json::json!({
            "actor_id": actor_id.to_string(),
            "archive_keys": ["cap/3"],
            "replacement_entries": [
                { "key": "cap/r1", "value": { "t": 1 }, "memory_type": "episodic" },
                { "key": "cap/r2", "value": { "t": 2 }, "memory_type": "episodic" },
                { "key": "cap/r3", "value": { "t": 3 }, "memory_type": "episodic" },
            ],
        }),
    )
    .await;
    let msg = error_message(&over);
    assert!(
        msg.contains("quota exceeded") && msg.contains("Nothing was changed"),
        "an over-cap compression must say so, not 'failed to write': {msg}"
    );
    assert_eq!(
        row_count(&pool, actor_id).await,
        before,
        "the refused compression rolled back"
    );
    let still_there: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM actor_memory WHERE actor_id = $1 AND key = 'cap/3'",
    )
    .bind(actor_id)
    .fetch_one(&pool)
    .await
    .expect("count archive key");
    assert_eq!(still_there, 1, "the retirement rolled back with the writes");

    // 3. actor_remember over EXPIRED rows. Fill back to the cap, then expire
    //    two rows: the handler's live-row pre-check passes (cap - 2 live), the
    //    chokepoint counts every row (cap), refuses, reclaims the two expired
    //    rows and retries — the write lands.
    let fill = cap - row_count(&pool, actor_id).await;
    assert_eq!(fill, 1);
    sqlx::query(
        "UPDATE actor_memory SET expires_at = now() - interval '1 minute' \
         WHERE actor_id = $1 AND key IN ('cap/4', 'cap/5')",
    )
    .bind(actor_id)
    .execute(&pool)
    .await
    .expect("expire two rows");
    sqlx::query(
        "INSERT INTO actor_memory (actor_id, key, value_enc, value_key_id, value_format, memory_type) \
         SELECT $1, 'cap/refill', '\\x00'::bytea, \
                (SELECT id FROM encryption_keys ORDER BY created_at LIMIT 1), 1, 'episodic'",
    )
    .bind(actor_id)
    .execute(&pool)
    .await
    .expect("refill to the cap");
    assert_eq!(row_count(&pool, actor_id).await, cap);
    let remembered = dispatch(
        &state,
        user_id,
        "actor_remember",
        serde_json::json!({
            "actor_id": actor_id.to_string(),
            "key": "cap/after-expiry",
            "value": { "text": "fits once the expired rows are reclaimed" },
        }),
    )
    .await;
    let body = text_json(&remembered);
    assert_eq!(
        body.get("success").and_then(Value::as_bool),
        Some(true),
        "{body}"
    );
    assert_eq!(
        row_count(&pool, actor_id).await,
        cap - 2 + 1,
        "two expired rows reclaimed, one written"
    );
}
