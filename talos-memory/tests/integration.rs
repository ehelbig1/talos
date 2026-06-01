//! Integration tests against a live Postgres.
//!
//! Gated on `TALOS_TEST_DATABASE_URL` being set — without it, each
//! test prints a skip note and returns Ok. This keeps `cargo test`
//! green in CI without a database while still exercising the real
//! SQL when operators run it locally.
//!
//! ## Running
//!
//! ```sh
//! export TALOS_TEST_DATABASE_URL="postgres://talos:<pw>@localhost:5432/talos"
//! export TALOS_TEST_ACTOR_ID="7881fe57-df69-4151-ba67-984d1f4262d5"   # optional
//! cargo test -p talos-memory --test integration -- --nocapture
//! ```
//!
//! If `TALOS_TEST_ACTOR_ID` is omitted, a random UUID is used — the
//! tests only insert rows they own and clean them up on exit, so
//! there's no collision risk with real actors.

use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres};
use talos_memory as mem;
use uuid::Uuid;

/// A real AES-256-GCM `MemoryCryptoHook` for the test binary.
///
/// Phase B made the crypto hook mandatory — `persist_memory` fails closed
/// ("write attempted without crypto hook registered") if none is registered,
/// so this suite can't run without one. The production hook delegates to
/// `SecretsManager` (DEK envelope + master key + `encryption_keys` table),
/// which is far too heavy to stand up in a unit test. Instead we register a
/// self-contained AES-256-GCM hook with an ephemeral fixed key.
///
/// This is NOT a stub: it performs genuine authenticated encryption with the
/// same `(actor_id, key)` AAD binding the production hook uses, so the suite
/// exercises the real encrypt→store(`value_enc`/`value_key_id`/`value_format`)
/// →read→decrypt round trip — and, critically, the MCP-S2 AAD-binding
/// property (a cross-row ciphertext swap must fail tag verification), which
/// the in-process unit tests can't reach because they never touch the
/// ciphertext columns.
mod test_crypto {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use std::sync::Arc;
    use uuid::Uuid;

    // Fixed 256-bit key + key_id for the whole binary. Ephemeral — exists only
    // in test memory, never persisted, so a hardcoded value is fine here.
    const TEST_KEY: [u8; 32] = [0x7e; 32];

    /// The fixed `value_key_id` every test ciphertext references. Tests seed a
    /// matching `encryption_keys` row so the `actor_memory.value_key_id` FK
    /// resolves (the hook's actual key material is in-memory `TEST_KEY`, not the
    /// DB row — the FK is purely referential).
    pub fn key_id() -> Uuid {
        Uuid::from_u128(0x7e57_0000_0000_4000_8000_0000_0000_0001)
    }

    struct TestMemoryCrypto;

    impl talos_memory::MemoryCryptoHook for TestMemoryCrypto {
        fn encrypt(&self, plaintext: String, aad: Vec<u8>) -> talos_memory::EncryptFuture {
            Box::pin(async move {
                let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&TEST_KEY));
                // Random 12-byte nonce, prepended to the ciphertext so decrypt
                // can recover it. Same on-wire shape the production cipher uses.
                let mut nonce_bytes = [0u8; 12];
                rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
                let ct = cipher
                    .encrypt(
                        Nonce::from_slice(&nonce_bytes),
                        Payload {
                            msg: plaintext.as_bytes(),
                            aad: &aad,
                        },
                    )
                    .map_err(|_| anyhow::anyhow!("test encrypt failed"))?;
                let mut out = Vec::with_capacity(12 + ct.len());
                out.extend_from_slice(&nonce_bytes);
                out.extend_from_slice(&ct);
                // format_version 1 = AAD-bound (MCP-S2).
                Ok((key_id(), out, 1i16))
            })
        }

        fn decrypt(
            &self,
            _key_id: Uuid,
            ciphertext: Vec<u8>,
            aad: Vec<u8>,
            _format_version: i16,
        ) -> talos_memory::DecryptFuture {
            Box::pin(async move {
                if ciphertext.len() < 12 {
                    anyhow::bail!("test ciphertext too short");
                }
                let (nonce_bytes, ct) = ciphertext.split_at(12);
                let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&TEST_KEY));
                let pt = cipher
                    .decrypt(
                        Nonce::from_slice(nonce_bytes),
                        Payload { msg: ct, aad: &aad },
                    )
                    // A wrong AAD (cross-row swap) or tampered ciphertext lands
                    // here — AES-GCM tag verification fails. This is the MCP-S2
                    // property under test.
                    .map_err(|_| {
                        anyhow::anyhow!("test decrypt failed (AAD mismatch or tampered ciphertext)")
                    })?;
                let s = String::from_utf8(pt).map_err(|_| anyhow::anyhow!("decrypted bytes not UTF-8"))?;
                Ok(zeroize::Zeroizing::new(s))
            })
        }
    }

    /// Register the hook once per process. `register_memory_crypto_hook` is
    /// itself idempotent (`OnceLock::set`), so calling this from every test is
    /// safe under concurrent test execution.
    pub fn ensure_registered() {
        talos_memory::register_memory_crypto_hook(Arc::new(TestMemoryCrypto));
    }
}

async fn test_pool_or_skip() -> Option<(Pool<Postgres>, Uuid)> {
    let url = match std::env::var("TALOS_TEST_DATABASE_URL") {
        Ok(u) if !u.is_empty() => u,
        _ => {
            eprintln!(
                "SKIP: set TALOS_TEST_DATABASE_URL to run integration tests \
                 (see talos-memory/tests/integration.rs)"
            );
            return None;
        }
    };
    let actor_id = std::env::var("TALOS_TEST_ACTOR_ID")
        .ok()
        .and_then(|s| Uuid::parse_str(&s).ok())
        .unwrap_or_else(Uuid::new_v4);

    // Connect on the test's OWN runtime. The previous version built a nested
    // `tokio::runtime::Runtime` and `block_on`'d the connect, which panics with
    // "Cannot start a runtime from within a runtime" when called from a
    // `#[tokio::test]` async context — so this whole suite never actually ran.
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(&url)
        .await
        .expect("TALOS_TEST_DATABASE_URL connect");
    // Phase B: writers fail closed without a registered crypto hook. Register
    // the test AES-256-GCM hook before any test issues a memory write.
    test_crypto::ensure_registered();

    // Seed the FK parents: actor_memory.actor_id → actors(id) → users(id),
    // and actor_memory.value_key_id → encryption_keys(id). Without these,
    // every write fails a foreign-key constraint. Idempotent
    // (`ON CONFLICT DO NOTHING`) so concurrently-running tests don't collide.
    sqlx::query(
        "INSERT INTO encryption_keys (id, encrypted_key) VALUES ($1, $2) \
         ON CONFLICT DO NOTHING",
    )
    .bind(test_crypto::key_id())
    .bind(vec![0u8; 32]) // placeholder — the hook's real key is in-memory TEST_KEY
    .execute(&pool)
    .await
    .expect("seed encryption key");

    let user_id = Uuid::from_u128(0x7e57_0000_0000_4000_8000_0000_0000_00aa);
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) \
         VALUES ($1, $2, 'x', 'mem-it') ON CONFLICT DO NOTHING",
    )
    .bind(user_id)
    .bind(format!("mem-it-{user_id}@test.invalid"))
    .execute(&pool)
    .await
    .expect("seed user");
    // `name` carries actor_id: there's a UNIQUE(user_id, name) index, so a
    // fixed name would collide across tests that use distinct random actors.
    sqlx::query(
        "INSERT INTO actors (id, user_id, name) VALUES ($1, $2, $3) \
         ON CONFLICT DO NOTHING",
    )
    .bind(actor_id)
    .bind(user_id)
    .bind(format!("mem-it-{actor_id}"))
    .execute(&pool)
    .await
    .expect("seed actor");

    Some((pool, actor_id))
}

async fn cleanup_prefix(pool: &Pool<Postgres>, actor_id: Uuid, prefix: &str) {
    let _ = mem::forget_prefix(pool, actor_id, prefix).await;
}

#[tokio::test]
async fn persist_recall_forget_roundtrip() {
    let Some((pool, actor_id)) = test_pool_or_skip().await else {
        return;
    };
    let prefix = format!("talos-memory-test/{}/", Uuid::new_v4());
    cleanup_prefix(&pool, actor_id, &prefix).await;

    let key = format!("{}basic", prefix);
    let value = serde_json::json!({
        "text": "integration test payload",
        "tags": ["test", "integration"],
    });

    // Persist
    let outcome = mem::persist_memory(&pool, actor_id, &key, &value, "episodic", Some(1.0))
        .await
        .expect("persist_memory");
    // Embedding may or may not succeed depending on whether the
    // embedding provider is configured — assert only the write
    // landed, not the embedding.
    let _ = outcome.embedded;

    // Recall exact
    let row = mem::recall_exact(&pool, actor_id, &key)
        .await
        .expect("recall_exact")
        .expect("row found");
    assert_eq!(row.key, key);
    assert_eq!(row.memory_type, "episodic");
    assert_eq!(
        row.value.get("text").and_then(|v| v.as_str()),
        Some("integration test payload")
    );

    // List
    let list = mem::list_memories(&pool, actor_id, Some(&prefix), None, None)
        .await
        .expect("list_memories");
    assert!(list.iter().any(|m| m.key == key));

    // Forget (soft delete) — tombstone should remain
    let out = mem::forget(&pool, actor_id, &key).await.expect("forget");
    assert!(out.deleted);
    assert!(mem::key_exists_at_all(&pool, actor_id, &key)
        .await
        .expect("key_exists_at_all"));
    assert!(mem::recall_exact(&pool, actor_id, &key)
        .await
        .expect("recall_exact post-forget")
        .is_none());

    // Hard delete via prefix
    let n = mem::forget_prefix(&pool, actor_id, &prefix)
        .await
        .expect("forget_prefix");
    assert!(n >= 1);
    assert!(!mem::key_exists_at_all(&pool, actor_id, &key)
        .await
        .expect("key_exists_at_all post-prefix-forget"));
}

/// MCP-S2 regression: the at-rest ciphertext is bound to its `(actor_id, key)`
/// via AES-GCM AAD, so an attacker with raw DB write capability can't swap
/// `value_enc` between two rows that share a `value_key_id` to read another
/// row's plaintext. This is the end-to-end proof against real Postgres columns
/// — the in-process unit tests never exercise the ciphertext path.
#[tokio::test]
async fn aad_binding_blocks_cross_row_ciphertext_swap() {
    let Some((pool, actor_id)) = test_pool_or_skip().await else {
        return;
    };
    let prefix = format!("talos-memory-test/{}/", Uuid::new_v4());
    cleanup_prefix(&pool, actor_id, &prefix).await;

    let key_a = format!("{}row-a", prefix);
    let key_b = format!("{}row-b", prefix);
    let secret_a = serde_json::json!({ "secret": "value-A" });
    let secret_b = serde_json::json!({ "secret": "value-B" });

    mem::persist_memory(&pool, actor_id, &key_a, &secret_a, "episodic", None)
        .await
        .expect("persist row A");
    mem::persist_memory(&pool, actor_id, &key_b, &secret_b, "episodic", None)
        .await
        .expect("persist row B");

    // Sanity: before tampering, row A reads back as A's plaintext.
    let pre = mem::recall_exact(&pool, actor_id, &key_a)
        .await
        .expect("recall A pre-swap")
        .expect("row A present");
    assert_eq!(pre.value.get("secret").and_then(|v| v.as_str()), Some("value-A"));

    // Attacker overwrites row A's ciphertext columns with row B's. Both rows
    // were encrypted under the same test key (same value_key_id), so a naive
    // no-AAD scheme would now decrypt row A → "value-B" (cross-row leak).
    let swapped = sqlx::query(
        "UPDATE actor_memory a \
         SET value_enc = b.value_enc, \
             value_key_id = b.value_key_id, \
             value_format = b.value_format \
         FROM actor_memory b \
         WHERE a.actor_id = $1 AND a.key = $2 \
           AND b.actor_id = $1 AND b.key = $3",
    )
    .bind(actor_id)
    .bind(&key_a)
    .bind(&key_b)
    .execute(&pool)
    .await
    .expect("swap ciphertext");
    assert_eq!(swapped.rows_affected(), 1, "swap should touch exactly row A");

    // Reading the tampered row A must FAIL AES-GCM tag verification (its AAD is
    // derived from key_a, but the ciphertext was sealed under key_b's AAD) —
    // NOT silently return "value-B".
    let res = mem::recall_exact(&pool, actor_id, &key_a).await;
    assert!(
        res.is_err(),
        "cross-row ciphertext swap must fail decryption, got: {res:?}"
    );

    cleanup_prefix(&pool, actor_id, &prefix).await;
}

#[tokio::test]
async fn persist_rejects_oversized_value() {
    let Some((pool, actor_id)) = test_pool_or_skip().await else {
        return;
    };
    // A 70 KiB value — over the 64 KiB cap enforced by persist_memory.
    let oversized: String = "x".repeat(70 * 1024);
    let value = serde_json::json!({ "blob": oversized });
    let err = mem::persist_memory(&pool, actor_id, "oversized", &value, "working", None)
        .await
        .expect_err("should reject oversized");
    let msg = err.to_string();
    assert!(
        msg.contains("too large") && msg.contains("64 KiB"),
        "unexpected error: {msg}"
    );
}

#[tokio::test]
async fn persist_rejects_empty_key() {
    let Some((pool, actor_id)) = test_pool_or_skip().await else {
        return;
    };
    let err = mem::persist_memory(&pool, actor_id, "", &serde_json::json!({}), "working", None)
        .await
        .expect_err("should reject empty key");
    assert!(
        err.to_string().contains("non-empty"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn recall_semantic_filtered_excludes_by_metadata_kind() {
    let Some((pool, actor_id)) = test_pool_or_skip().await else {
        return;
    };
    let prefix = format!("talos-memory-test/{}/", Uuid::new_v4());
    cleanup_prefix(&pool, actor_id, &prefix).await;

    // Three rows whose KEYS share a substring so the keyword fallback can
    // match them all, plus distinct metadata.kind so we can verify the
    // filter SQL independently of embedding success.
    //
    // Phase B: the value column is encrypted, so the keyword fallback
    // substring-matches `key` only (not value). The shared term therefore
    // lives in the key, not the value text.
    let shared_word = "filterword";
    let k_synth = format!("{}{}-synth", prefix, shared_word);
    let k_qa = format!("{}{}-qa", prefix, shared_word);
    let k_plain = format!("{}{}-plain", prefix, shared_word); // NULL metadata

    mem::persist_memory_with_metadata(
        &pool,
        actor_id,
        &k_synth,
        &serde_json::json!({ "text": format!("{shared_word} one") }),
        Some(&serde_json::json!({ "kind": "meeting_prep" })),
        "episodic",
        Some(1.0),
    )
    .await
    .expect("persist synth");
    mem::persist_memory_with_metadata(
        &pool,
        actor_id,
        &k_qa,
        &serde_json::json!({ "text": format!("{shared_word} two") }),
        Some(&serde_json::json!({ "kind": "recall" })),
        "episodic",
        Some(1.0),
    )
    .await
    .expect("persist qa");
    mem::persist_memory_with_metadata(
        &pool,
        actor_id,
        &k_plain,
        &serde_json::json!({ "text": format!("{shared_word} three") }),
        None,
        "episodic",
        Some(1.0),
    )
    .await
    .expect("persist plain");

    // 1. Empty exclude — all three pass.
    let all = mem::recall_semantic_filtered(
        &pool,
        actor_id,
        shared_word,
        20,
        0.0,
        None,
        mem::SearchMethod::Direct,
        &[],
    )
    .await
    .expect("filtered empty");
    let keys: Vec<&str> = all.hits.iter().map(|h| h.key.as_str()).collect();
    assert!(keys.contains(&k_synth.as_str()));
    assert!(keys.contains(&k_qa.as_str()));
    assert!(keys.contains(&k_plain.as_str()));

    // 2. Single-kind exclusion drops matching row only.
    let drop_synth = mem::recall_semantic_filtered(
        &pool,
        actor_id,
        shared_word,
        20,
        0.0,
        None,
        mem::SearchMethod::Direct,
        &["meeting_prep".to_string()],
    )
    .await
    .expect("filtered drop synth");
    let keys: Vec<&str> = drop_synth.hits.iter().map(|h| h.key.as_str()).collect();
    assert!(
        !keys.contains(&k_synth.as_str()),
        "meeting_prep row should be excluded"
    );
    assert!(keys.contains(&k_qa.as_str()));
    assert!(
        keys.contains(&k_plain.as_str()),
        "NULL-metadata row must always pass"
    );

    // 3. Multi-kind composition.
    let drop_both = mem::recall_semantic_filtered(
        &pool,
        actor_id,
        shared_word,
        20,
        0.0,
        None,
        mem::SearchMethod::Direct,
        &["meeting_prep".to_string(), "recall".to_string()],
    )
    .await
    .expect("filtered drop both");
    let keys: Vec<&str> = drop_both.hits.iter().map(|h| h.key.as_str()).collect();
    assert!(!keys.contains(&k_synth.as_str()));
    assert!(!keys.contains(&k_qa.as_str()));
    assert!(
        keys.contains(&k_plain.as_str()),
        "NULL-metadata row passes even when multiple kinds excluded"
    );

    let _ = mem::forget_prefix(&pool, actor_id, &prefix).await;
}

#[tokio::test]
async fn recall_recent_by_types_filters_and_orders() {
    let Some((pool, actor_id)) = test_pool_or_skip().await else {
        return;
    };
    let prefix = format!("talos-memory-test/{}/", Uuid::new_v4());
    cleanup_prefix(&pool, actor_id, &prefix).await;

    let k_episodic = format!("{}ep", prefix);
    let k_working = format!("{}work", prefix);
    let k_scratch = format!("{}scratch", prefix);

    // Insert in reverse intended-recency order so we can verify that
    // ORDER BY updated_at DESC is the actual ordering, not insert order.
    mem::persist_memory(
        &pool,
        actor_id,
        &k_episodic,
        &serde_json::json!({"v": 1}),
        "episodic",
        Some(1.0),
    )
    .await
    .expect("persist episodic");
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    mem::persist_memory(
        &pool,
        actor_id,
        &k_working,
        &serde_json::json!({"v": 2}),
        "working",
        Some(1.0),
    )
    .await
    .expect("persist working");
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    mem::persist_memory(
        &pool,
        actor_id,
        &k_scratch,
        &serde_json::json!({"v": 3}),
        "scratchpad",
        Some(1.0),
    )
    .await
    .expect("persist scratchpad");

    // Filter to working+episodic only — scratchpad must NOT appear.
    let rows = mem::recall_recent_by_types(&pool, actor_id, &["working", "episodic"], 10)
        .await
        .expect("recall_recent_by_types");
    let returned_keys: Vec<&str> = rows.iter().map(|(k, _, _)| k.as_str()).collect();
    assert!(
        returned_keys.contains(&k_working.as_str()),
        "working included"
    );
    assert!(
        returned_keys.contains(&k_episodic.as_str()),
        "episodic included"
    );
    assert!(
        !returned_keys.contains(&k_scratch.as_str()),
        "scratchpad excluded by type filter"
    );

    // Recency: working was written most recently of the two matched
    // types, so it should come first.
    let working_pos = rows.iter().position(|(k, _, _)| k == &k_working);
    let episodic_pos = rows.iter().position(|(k, _, _)| k == &k_episodic);
    if let (Some(w), Some(e)) = (working_pos, episodic_pos) {
        assert!(
            w < e,
            "working (newer) must precede episodic (older) in recency-DESC sort"
        );
    }

    let _ = mem::forget_prefix(&pool, actor_id, &prefix).await;
}

#[tokio::test]
async fn recall_recent_excluding_types_drops_match_keeps_rest() {
    let Some((pool, actor_id)) = test_pool_or_skip().await else {
        return;
    };
    let prefix = format!("talos-memory-test/{}/", Uuid::new_v4());
    cleanup_prefix(&pool, actor_id, &prefix).await;

    let k_scratch = format!("{}scratch", prefix);
    let k_episodic = format!("{}ep", prefix);

    mem::persist_memory(
        &pool,
        actor_id,
        &k_scratch,
        &serde_json::json!({"v": 1}),
        "scratchpad",
        Some(1.0),
    )
    .await
    .expect("persist scratch");
    mem::persist_memory(
        &pool,
        actor_id,
        &k_episodic,
        &serde_json::json!({"v": 2}),
        "episodic",
        Some(1.0),
    )
    .await
    .expect("persist episodic");

    let rows = mem::recall_recent_excluding_types(&pool, actor_id, &["scratchpad"], 10)
        .await
        .expect("recall_recent_excluding_types");
    let returned: Vec<&str> = rows.iter().map(|(k, _, _)| k.as_str()).collect();
    assert!(
        returned.contains(&k_episodic.as_str()),
        "episodic preserved when only scratchpad excluded"
    );
    assert!(
        !returned.contains(&k_scratch.as_str()),
        "scratchpad excluded by NOT(type = ANY) filter"
    );

    // Empty exclude list returns everything — including scratchpad.
    let all = mem::recall_recent_excluding_types(&pool, actor_id, &[], 10)
        .await
        .expect("recall with empty exclude");
    let all_keys: Vec<&str> = all.iter().map(|(k, _, _)| k.as_str()).collect();
    assert!(
        all_keys.contains(&k_scratch.as_str()),
        "scratchpad included when exclude is empty"
    );

    let _ = mem::forget_prefix(&pool, actor_id, &prefix).await;
}

#[tokio::test]
async fn semantic_recall_returns_keyword_fallback_when_no_embedding() {
    let Some((pool, actor_id)) = test_pool_or_skip().await else {
        return;
    };
    let prefix = format!("talos-memory-test/{}/", Uuid::new_v4());
    cleanup_prefix(&pool, actor_id, &prefix).await;

    // Phase B: the keyword fallback substring-matches `key` only (the value
    // is encrypted at rest), so the searched term "review" must live in the
    // key for the fallback to surface this row.
    let key = format!("{}review-fall", prefix);
    let value = serde_json::json!({
        "text": "Remember to review PR #42",
    });
    let _ = mem::persist_memory(&pool, actor_id, &key, &value, "episodic", Some(1.0))
        .await
        .expect("persist");

    // Query contains literal "review" — will match even if the
    // embedding provider is down (falls back to keyword ILIKE on key).
    let outcome = mem::recall_semantic(
        &pool,
        actor_id,
        "review",
        5,
        0.0,
        None,
        mem::SearchMethod::Direct,
    )
    .await
    .expect("recall_semantic");
    assert!(
        !outcome.hits.is_empty(),
        "expected at least one hit (method={})",
        outcome.method
    );
    assert!(outcome.hits.iter().any(|h| h.key == key));

    let _ = mem::forget_prefix(&pool, actor_id, &prefix).await;
}
