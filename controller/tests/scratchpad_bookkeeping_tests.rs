//! A bookkeeping memory write is not embedded, not extracted, and not
//! returned by semantic recall (2026-10-14).
//!
//! A step counter written by a module (`work/log/<ticket>/<step>`, about 110
//! bytes of numbers, one write per step a person takes) was embedded and
//! queued for entity extraction by the local model on every write. Measured on
//! the dev stack: about 17 ms of embedding and 0.6 to 4.5 s of extraction per
//! tap, and the extractor invented a relationship from the counter.
//!
//! The platform already has the write for this: `memory_type: "scratchpad"`
//! is never embedded, never extracted, never backfilled and never put in
//! actor context, and an explicit `ttl_hours` makes it durable. What it did
//! not do was stay out of SEMANTIC recall: when the vector path came back
//! empty, the keyword fallback matched a scratchpad row by its key.
//!
//! Driven here end to end: a `__memory_write__` envelope through the engine's
//! real node hook, the real write path, a stand-in embedding provider that
//! counts requests (`talos-memory/tests/embedding_mock`) and a graph hook that
//! counts extractions, against a migrated Postgres.
//!
//! ONE test function: the embedding client reads its configuration once per
//! process, and the graph and crypto hooks register once.

mod common;
// The stand-in's other counters are for the memory crate's own tests.
#[allow(dead_code)]
#[path = "../../talos-memory/tests/embedding_mock/mod.rs"]
mod embedding_mock;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use uuid::Uuid;

const DIMS: usize = 1024;

/// Counts the extractions the write path hands it.
struct CountingGraphHook(Arc<AtomicUsize>);

impl talos_memory::GraphHook for CountingGraphHook {
    fn extract(
        &self,
        _actor_id: Uuid,
        _key: String,
        _value: serde_json::Value,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send>> {
        let count = self.0.clone();
        Box::pin(async move {
            count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }
}

async fn seed_actor(pool: &sqlx::PgPool) -> Uuid {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'h', true)",
    )
    .bind(user)
    .bind(format!("scratch-{user}@talos.test"))
    .execute(pool)
    .await
    .expect("seed user");
    let tag = Uuid::new_v4();
    let org: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (name, slug, owner_id, is_personal) \
         VALUES ($1, $2, $3, true) RETURNING id",
    )
    .bind(format!("scratch-{tag}"))
    .bind(format!("scratch-{tag}"))
    .bind(user)
    .fetch_one(pool)
    .await
    .expect("seed org");
    let actor = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO actors (id, user_id, name, org_id, max_write_ceiling) \
         VALUES ($1, $2, $3, $4, 'write')",
    )
    .bind(actor)
    .bind(user)
    .bind(format!("scratch-actor-{tag}"))
    .bind(org)
    .execute(pool)
    .await
    .expect("seed actor");
    actor
}

/// Write through the engine's own `__memory_write__` hook (it persists in a
/// spawned task) and wait for the row.
async fn envelope_write(pool: &sqlx::PgPool, actor: Uuid, envelope: serde_json::Value) {
    let key = envelope["key"].as_str().unwrap().to_string();
    talos_engine::node_hook::ControllerNodeHook::new(pool.clone()).persist_memory_write_if_present(
        Some(actor),
        &json!({ "__memory_write__": envelope }),
        talos_workflow_job_protocol::WriteCeiling::Write,
    );
    for _ in 0..100 {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM actor_memory WHERE actor_id = $1 AND key = $2",
        )
        .bind(actor)
        .bind(&key)
        .fetch_one(pool)
        .await
        .unwrap();
        if n > 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the envelope write of {key} never landed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bookkeeping_write_costs_no_embedding_or_extraction_and_stays_out_of_semantic_recall() {
    std::env::set_var(
        "TALOS_MASTER_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
    let mock = embedding_mock::start(Duration::from_millis(1), DIMS).await;
    embedding_mock::configure(&mock.url, DIMS, 5, None);
    let extractions = Arc::new(AtomicUsize::new(0));
    talos_memory::register_graph_hook(Arc::new(CountingGraphHook(extractions.clone())));

    let (pool, _db) = common::isolated_db_pool().await;
    let sm = Arc::new(controller::secrets::SecretsManager::new(pool.clone()).unwrap());
    sm.initialize().await.unwrap();
    talos_memory::register_memory_crypto_hook(Arc::new(
        talos_memory_crypto::SecretsManagerMemoryCrypto::new(sm.clone()),
    ));

    // ── A write as today: embedded and queued for extraction. ──────────────
    let indexed = seed_actor(&pool).await;
    envelope_write(
        &pool,
        indexed,
        json!({ "key": "notes/made-up-meeting", "value": { "said": "the release moves to Friday" } }),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let embeds_after_indexed = mock.received.load(Ordering::SeqCst);
    assert_eq!(
        embeds_after_indexed, 1,
        "an ordinary write is embedded once"
    );
    assert_eq!(
        extractions.load(Ordering::SeqCst),
        1,
        "an ordinary write is queued for extraction"
    );

    // ── A bookkeeping write: scratchpad, kept for a year. ──────────────────
    let tally = seed_actor(&pool).await;
    envelope_write(
        &pool,
        tally,
        json!({
            "key": "work/log/MADE-UP-1/start",
            "value": { "count": 3, "first": "2026-10-01T09:00:00Z", "last": "2026-10-14T08:00:00Z" },
            "memory_type": "scratchpad",
            "ttl_hours": 8760,
        }),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        mock.received.load(Ordering::SeqCst),
        embeds_after_indexed,
        "a scratchpad write makes no embedding call"
    );
    assert_eq!(
        extractions.load(Ordering::SeqCst),
        1,
        "a scratchpad write queues no extraction"
    );

    // Readable by key, and durable for the TTL it asked for.
    let entry = talos_memory::recall_entry(&pool, tally, "work/log/MADE-UP-1/start")
        .await
        .expect("read")
        .expect("the tally is readable by key");
    assert_eq!(entry.value["count"], 3);
    let expires_in_days = (entry.expires_at.expect("an expiry") - chrono::Utc::now()).num_days();
    assert!(
        expires_in_days >= 364,
        "kept for the year it asked: {expires_in_days} days"
    );
    let embedding_is_null: bool = sqlx::query_scalar(
        "SELECT embedding IS NULL FROM actor_memory WHERE actor_id = $1 AND key = $2",
    )
    .bind(tally)
    .bind("work/log/MADE-UP-1/start")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(embedding_is_null);

    // Absent from semantic recall: the vector path never returns it, and the
    // keyword fallback (the path taken here: this actor has no embedded row)
    // no longer matches it by key.
    //
    // MUTATION that turns it red: pass `false` for `semantic_fallback` in
    // `recall_semantic_filtered`'s fallback call.
    let outcome = talos_memory::recall_semantic_filtered(
        &pool,
        tally,
        "work log start",
        10,
        0.0,
        None,
        talos_memory::SearchMethod::Direct,
        &[],
    )
    .await
    .expect("recall");
    assert!(
        outcome
            .hits
            .iter()
            .all(|h| h.key != "work/log/MADE-UP-1/start"),
        "a bookkeeping row came back from semantic recall ({}): {:?}",
        outcome.method,
        outcome.hits.iter().map(|h| &h.key).collect::<Vec<_>>()
    );
    // An explicit keyword search still finds it: it is excluded from
    // SEMANTIC recall, not hidden.
    let by_keyword = talos_memory::recall_keyword(&pool, tally, "work log start", 10)
        .await
        .expect("keyword");
    assert!(by_keyword
        .iter()
        .any(|h| h.key == "work/log/MADE-UP-1/start"));

    // And the ordinary row is still found by semantic recall.
    let found = talos_memory::recall_semantic_filtered(
        &pool,
        indexed,
        "release friday",
        10,
        0.0,
        None,
        talos_memory::SearchMethod::Direct,
        &[],
    )
    .await
    .expect("recall");
    assert!(found.hits.iter().any(|h| h.key == "notes/made-up-meeting"));
}
