// Per-org root DEKs — actor_memory cutover (real crypto hook, end-to-end).
// Proves a memory write lands as format v4 under the ACTOR's org root DEK, is
// stamped with that org_id, and reads back through the versioned decrypt path.
// Env-gated like the rest of the controller suite (runs in quality.yml).

mod test_helpers;

use std::sync::Arc;
use uuid::Uuid;

fn set_master_key() {
    std::env::set_var(
        "TALOS_MASTER_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
}

async fn seed_actor_with_org(pool: &sqlx::Pool<sqlx::Postgres>) -> (Uuid, Uuid) {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'h', true)",
    )
    .bind(user)
    .bind(format!("mem-{user}@talos.test"))
    .execute(pool)
    .await
    .expect("seed user");
    let tag = Uuid::new_v4();
    let org: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (name, slug, owner_id, is_personal) VALUES ($1, $2, $3, true) RETURNING id",
    )
    .bind(format!("memorg-{tag}"))
    .bind(format!("memorg-{tag}"))
    .bind(user)
    .fetch_one(pool)
    .await
    .expect("seed org");
    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name, org_id) VALUES ($1, $2, 'mem-actor', $3)")
        .bind(actor)
        .bind(user)
        .bind(org)
        .execute(pool)
        .await
        .expect("seed actor");
    (actor, org)
}

#[tokio::test]
async fn actor_memory_writes_v4_under_actor_org_dek_and_reads_back() {
    set_master_key();
    let pool = test_helpers::get_test_db_pool().await;
    let sm = Arc::new(controller::secrets::SecretsManager::new(pool.clone()).unwrap());
    sm.initialize().await.unwrap();
    // Register the REAL memory crypto hook (idempotent OnceLock — first wins).
    talos_memory::register_memory_crypto_hook(Arc::new(
        talos_memory_crypto::SecretsManagerMemoryCrypto::new(sm.clone()),
    ));

    let (actor, org) = seed_actor_with_org(&pool).await;

    // "scratchpad" skips the embedding provider (no Ollama/HTTP dependency in CI)
    // while still exercising the identical encrypt + UPSERT path.
    let key = format!("dek/mem/{}", Uuid::new_v4());
    talos_memory::persist_memory(
        &pool,
        actor,
        &key,
        &serde_json::json!({ "v": "secret-mem" }),
        "scratchpad",
        None,
    )
    .await
    .unwrap();

    // Row is v4, stamped with the actor's org, keyed by that org's DEK.
    let (fmt, kid, row_org): (i16, Uuid, Option<Uuid>) = sqlx::query_as(
        "SELECT value_format, value_key_id, org_id FROM actor_memory WHERE actor_id=$1 AND key=$2",
    )
    .bind(actor)
    .bind(&key)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(fmt, 4, "actor_memory write must be format v4");
    assert_eq!(row_org, Some(org), "row org_id must be the actor's org");
    let org_dek = sm.get_active_dek_for_org(org).await.unwrap().unwrap();
    assert_eq!(kid, org_dek.id, "must use the actor's org DEK");

    // Reads back through the versioned decrypt path (v4 arm).
    let got = talos_memory::recall_exact(&pool, actor, &key)
        .await
        .unwrap()
        .expect("memory row present");
    assert_eq!(got.value, serde_json::json!({ "v": "secret-mem" }));
}
