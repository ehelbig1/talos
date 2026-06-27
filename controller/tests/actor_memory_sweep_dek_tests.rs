// Per-org root DEKs — actor_memory re-encrypt SWEEP (end-to-end).
// Migrates an existing v3-global memory row to v4 under the actor's org DEK.
// In its OWN test binary: the MemoryCryptoHook is an OnceLock whose captured
// SecretsManager pool must stay bound to a live tokio runtime — so the single
// hook-registering test here keeps that pool alive for the whole test (the
// cross-runtime-pool trap that bites a second hook test in the same binary).
// Env-gated (runs in quality.yml).

mod test_helpers;

use std::sync::Arc;
use uuid::Uuid;

#[tokio::test]
async fn re_encrypt_memories_to_org_migrates_v3_global_rows_to_v4() {
    std::env::set_var(
        "TALOS_MASTER_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
    let pool = test_helpers::get_test_db_pool().await;
    let sm = Arc::new(controller::secrets::SecretsManager::new(pool.clone()).unwrap());
    sm.initialize().await.unwrap();
    talos_memory::register_memory_crypto_hook(Arc::new(
        talos_memory_crypto::SecretsManagerMemoryCrypto::new(sm.clone()),
    ));

    // Seed an actor that HAS an org.
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'h', true)",
    )
    .bind(user)
    .bind(format!("memsweep-{user}@talos.test"))
    .execute(&pool)
    .await
    .unwrap();
    let tag = Uuid::new_v4();
    let org: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (name, slug, owner_id, is_personal) VALUES ($1, $2, $3, true) RETURNING id",
    )
    .bind(format!("memsweeporg-{tag}"))
    .bind(format!("memsweeporg-{tag}"))
    .bind(user)
    .fetch_one(&pool)
    .await
    .unwrap();
    let actor = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO actors (id, user_id, name, org_id) VALUES ($1, $2, 'sweep-actor', $3)",
    )
    .bind(actor)
    .bind(user)
    .bind(org)
    .execute(&pool)
    .await
    .unwrap();

    let key = format!("dek/sweep-mem/{}", Uuid::new_v4());
    let value = serde_json::json!({ "v": "legacy-mem" });

    // Craft a PRE-cutover row: v3 global ciphertext, org_id NULL.
    let aad = talos_memory::build_memory_aad(actor, &key);
    let (kid, ct, ver) = sm
        .encrypt_value_aad_v3(&serde_json::to_string(&value).unwrap(), &aad)
        .await
        .unwrap();
    assert_eq!(ver, 3);
    sqlx::query(
        "INSERT INTO actor_memory (actor_id, key, value_enc, value_key_id, value_format, memory_type, expires_at) \
         VALUES ($1, $2, $3, $4, 3, 'scratchpad', NULL)",
    )
    .bind(actor)
    .bind(&key)
    .bind(ct.as_slice())
    .bind(kid)
    .execute(&pool)
    .await
    .unwrap();

    // Sweep.
    let stats = talos_memory::re_encrypt_memories_to_org(&pool)
        .await
        .unwrap();
    assert!(
        stats.re_encrypted >= 1,
        "sweep must migrate at least our row"
    );
    assert_eq!(stats.failed, 0);

    // Now v4 under the actor's org DEK, org_id stamped, still decrypts.
    let (fmt, rkid, rorg): (i16, Uuid, Option<Uuid>) = sqlx::query_as(
        "SELECT value_format, value_key_id, org_id FROM actor_memory WHERE actor_id=$1 AND key=$2",
    )
    .bind(actor)
    .bind(&key)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(fmt, 4, "sweep must upgrade the row to v4");
    assert_eq!(rorg, Some(org), "sweep must stamp the actor's org_id");
    let org_dek = sm.get_active_dek_for_org(org).await.unwrap().unwrap();
    assert_eq!(rkid, org_dek.id, "row must now reference the org DEK");

    let got = talos_memory::recall_exact(&pool, actor, &key)
        .await
        .unwrap()
        .expect("row present");
    assert_eq!(got.value, value, "value must survive the sweep");
}
