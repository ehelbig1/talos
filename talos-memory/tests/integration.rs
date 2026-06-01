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
    assert!(err.to_string().contains("key cannot be empty"));
}

#[tokio::test]
async fn recall_semantic_filtered_excludes_by_metadata_kind() {
    let Some((pool, actor_id)) = test_pool_or_skip().await else {
        return;
    };
    let prefix = format!("talos-memory-test/{}/", Uuid::new_v4());
    cleanup_prefix(&pool, actor_id, &prefix).await;

    // Three rows with distinguishable text so the keyword fallback can
    // match them all via a shared substring, plus distinct metadata.kind
    // so we can verify the filter SQL independently of embedding success.
    let shared_word = "filterword";
    let k_synth = format!("{}synth", prefix);
    let k_qa = format!("{}qa", prefix);
    let k_plain = format!("{}plain", prefix); // NULL metadata

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

    let key = format!("{}fall", prefix);
    let value = serde_json::json!({
        "text": "Remember to review PR #42",
    });
    let _ = mem::persist_memory(&pool, actor_id, &key, &value, "episodic", Some(1.0))
        .await
        .expect("persist");

    // Query contains literal "review" — will match even if the
    // embedding provider is down (falls back to keyword ILIKE).
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
