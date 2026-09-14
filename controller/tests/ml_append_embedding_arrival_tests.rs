//! The two embedding clauses of the example upsert's change predicate
//! (`EXAMPLE_UPSERT_CHANGES` in `talos-ml`): a re-append must REWRITE a row
//! whose stored embedding is NULL once the embedder can supply one, and a row
//! whose embedding was produced by a different model — and must stay a no-op
//! otherwise.
//!
//! A separate binary from `ml_append_noop_tests` on purpose: the embedding
//! client caches its configuration in a process-wide `OnceLock` and successful
//! vectors in an LRU, so a binary cannot switch between a dead provider and a
//! live one. This one serves its own local embedder (an axum listener on
//! 127.0.0.1) whose availability the test toggles, and runs ONE sequential
//! scenario so no parallel test can race the process-global configuration.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use talos_ml::{AppendExample, DatasetService, ExampleSource};
use uuid::Uuid;

const DIMS: usize = 1024;
const MOCK_MODEL: &str = "talos-test-mock-embedder";

/// A deterministic vector per input text, so equal text embeds equally — the
/// property measured on the live embedder that the no-op rule relies on.
fn vector_for(text: &str) -> Vec<f32> {
    let digest = <sha2::Sha256 as sha2::Digest>::digest(text.as_bytes());
    (0..DIMS)
        .map(|i| f32::from(digest[i % digest.len()]) / 255.0 + 0.001)
        .collect()
}

/// Serve an OpenAI-shaped `/v1/embeddings` that answers 503 while `up` is false.
async fn spawn_mock_embedder(up: Arc<AtomicBool>) -> std::net::SocketAddr {
    use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
    async fn embed(
        State(up): State<Arc<AtomicBool>>,
        Json(body): Json<serde_json::Value>,
    ) -> Result<Json<serde_json::Value>, StatusCode> {
        if !up.load(Ordering::SeqCst) {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        let text = body.get("input").and_then(|v| v.as_str()).unwrap_or("");
        Ok(Json(serde_json::json!({
            "data": [{ "index": 0, "embedding": vector_for(text) }],
            "model": MOCK_MODEL,
        })))
    }
    let app = Router::new()
        .route("/v1/embeddings", post(embed))
        .with_state(up);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock embedder");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("mock embedder");
    });
    addr
}

async fn seed_user(pool: &sqlx::PgPool, id: Uuid) {
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) \
         VALUES ($1, $2, 'x', true) ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(format!("{id}@ml-embed.test"))
    .execute(pool)
    .await
    .expect("seed user");
}

async fn seed_dataset(pool: &sqlx::PgPool, user_id: Uuid) -> Uuid {
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

async fn append(dsvc: &DatasetService, pool: &sqlx::PgPool, ds: Uuid) -> usize {
    let examples = ["disk full on db-1", "nightly backup ok"]
        .iter()
        .enumerate()
        .map(|(i, text)| AppendExample {
            features_text: (*text).to_string(),
            label: if i == 0 { "critical" } else { "noise" }.to_string(),
            source: ExampleSource::LlmProduction,
            example_key: Some(format!("k{i}")),
        })
        .collect();
    let mut conn = pool.acquire().await.unwrap();
    let tenancy = dsvc.dataset_tenancy(&mut conn, ds).await.unwrap();
    let prepared = dsvc.prepare_examples(ds, tenancy, examples).await.unwrap();
    dsvc.insert_prepared(&mut conn, ds, tenancy, prepared)
        .await
        .unwrap()
}

async fn embedded_rows(pool: &sqlx::PgPool, ds: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(embedding) FROM ml_examples WHERE dataset_id = $1")
        .bind(ds)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn embeddings_arriving_or_changing_model_rewrite_once_and_then_settle() {
    let up = Arc::new(AtomicBool::new(false));
    let addr = spawn_mock_embedder(up.clone()).await;
    // Before ANY embedding call: the client's configuration is cached once.
    std::env::set_var("EMBEDDING_API_URL", format!("http://{addr}/v1/embeddings"));
    std::env::set_var("EMBEDDING_MODEL", MOCK_MODEL);
    std::env::set_var("EMBEDDING_DIMENSIONS", DIMS.to_string());
    std::env::set_var(
        "TALOS_MASTER_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );

    let (pool, _db) = common::isolated_db_pool().await;
    let user = Uuid::new_v4();
    seed_user(&pool, user).await;
    let ds = seed_dataset(&pool, user).await;
    let sm = Arc::new(controller::secrets::SecretsManager::new(pool.clone()).unwrap());
    sm.initialize().await.unwrap();
    talos_memory::register_memory_crypto_hook(Arc::new(
        talos_memory_crypto::SecretsManagerMemoryCrypto::new(sm.clone()),
    ));
    let dsvc = DatasetService::new(sm);

    // 1. Embedder down: rows are stored WITHOUT vectors (backfillable).
    assert_eq!(append(&dsvc, &pool, ds).await, 2);
    assert_eq!(embedded_rows(&pool, ds).await, 0);

    // 2. Embedder back: the SAME re-append is a real change — the vectors
    //    arrive. Without this clause the rows would stay unusable to kNN
    //    until someone ran a backfill.
    up.store(true, Ordering::SeqCst);
    assert_eq!(append(&dsvc, &pool, ds).await, 2, "embeddings arrived");
    assert_eq!(embedded_rows(&pool, ds).await, 2);

    // 3. And then it settles.
    assert_eq!(append(&dsvc, &pool, ds).await, 0, "nothing changed since");

    // 4. A row embedded by a different model is rewritten into the current
    //    vector space — and only that row.
    sqlx::query(
        "UPDATE ml_examples SET embedding_model = 'talos-test-older-model' \
         WHERE dataset_id = $1 AND example_key = 'k0'",
    )
    .bind(ds)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(append(&dsvc, &pool, ds).await, 1, "embedding model moved");
    let model: String = sqlx::query_scalar(
        "SELECT embedding_model FROM ml_examples WHERE dataset_id = $1 AND example_key = 'k0'",
    )
    .bind(ds)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(model, MOCK_MODEL);
    assert_eq!(append(&dsvc, &pool, ds).await, 0);

    // 5. A row that lost its vector but KEPT its model name. No writer produces
    //    this today (every write binds the model only beside a vector; 0 such
    //    rows on the reference fleet, 2026-09-14), so in steps 1–2 the model
    //    clause alone would already have caught the arrival. This pins the
    //    arrival clause for the state a future writer could create — without
    //    it the missing vector would never be restored by a re-append.
    sqlx::query(
        "UPDATE ml_examples SET embedding = NULL \
         WHERE dataset_id = $1 AND example_key = 'k1'",
    )
    .bind(ds)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(embedded_rows(&pool, ds).await, 1);
    assert_eq!(
        append(&dsvc, &pool, ds).await,
        1,
        "the missing vector is restored"
    );
    assert_eq!(embedded_rows(&pool, ds).await, 2);
    assert_eq!(append(&dsvc, &pool, ds).await, 0);
}
