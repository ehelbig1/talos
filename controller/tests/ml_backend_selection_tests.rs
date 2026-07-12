//! RFC 0011 P3 — the eval harness as a BACKEND SELECTOR against a real DB.
//! Seeds a separable 3-class dataset with crafted embeddings, then runs
//! `run_backend_selection_eval` and asserts it evaluates BOTH backends on
//! one shared split, tags the parametric (`classical`) candidate with a
//! round-trippable artifact, and orders them best-macro-recall-first. The
//! parametric algorithm's minority-class advantage is proven separately in
//! the `talos-ml` unit tests; this proves the DB-wired selection +
//! persistence path.

mod common;

use std::sync::Arc;
use talos_ml::{AppendExample, DatasetService, ExampleSource, LinearModel};
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
         VALUES ($1, $2, 'x', true) ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(format!("{id}@ml-select.test"))
    .execute(pool)
    .await
    .expect("seed user");
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

async fn dataset_service(pool: &sqlx::Pool<sqlx::Postgres>) -> DatasetService {
    set_master_key();
    let sm = Arc::new(controller::secrets::SecretsManager::new(pool.clone()).unwrap());
    sm.initialize().await.unwrap();
    talos_memory::register_memory_crypto_hook(Arc::new(
        talos_memory_crypto::SecretsManagerMemoryCrypto::new(sm.clone()),
    ));
    DatasetService::new(sm)
}

/// A 1024-dim one-hot-ish embedding as a pgvector text literal (`[..]`),
/// so a class's rows cluster tightly and separably — no live embedder
/// needed. Dim must match the `vector(1024)` column.
fn embedding_literal(hot: usize) -> String {
    let mut parts = vec!["0"; 1024];
    parts[hot] = "1";
    format!("[{}]", parts.join(","))
}

#[tokio::test]
async fn selector_evaluates_both_backends_and_tags_linear_artifact() {
    let (pool, _db) = common::isolated_db_pool().await;
    set_master_key();
    let user = Uuid::new_v4();
    seed_user(&pool, user).await;
    let ds = seed_dataset(&pool, user).await;
    let dsvc = dataset_service(&pool).await;
    let tenancy = {
        let mut conn = pool.acquire().await.unwrap();
        dsvc.dataset_tenancy(&mut conn, ds).await.unwrap()
    };

    // 3 separable classes, 15 rows each. Insert with NULL embedding (no
    // live embedder), then stamp each class's crafted cluster embedding.
    for (label, hot) in [("alpha", 0usize), ("bravo", 1), ("charlie", 2)] {
        for i in 0..15 {
            let ex = AppendExample {
                features_text: format!("{label}-{i}"),
                label: label.to_string(),
                source: ExampleSource::LlmBootstrap,
                example_key: Some(format!("{label}-{i}")),
            };
            let prepared = dsvc.prepare_examples(ds, tenancy, vec![ex]).await.unwrap();
            let mut conn = pool.acquire().await.unwrap();
            dsvc.insert_prepared(&mut conn, ds, tenancy, prepared)
                .await
                .unwrap();
        }
        sqlx::query(
            "UPDATE ml_examples SET embedding = $1::vector \
             WHERE dataset_id = $2 AND label_json->>'label' = $3",
        )
        .bind(embedding_literal(hot))
        .bind(ds)
        .bind(label)
        .execute(&pool)
        .await
        .unwrap();
    }

    // Run the selector on one shared split.
    let mut conn = pool.acquire().await.unwrap();
    let candidates =
        talos_ml::run_backend_selection_eval(&dsvc, &mut conn, ds, 5, 0.2, Default::default())
            .await
            .expect("selection eval runs");

    // Both backends were evaluated on the SAME holdout.
    assert_eq!(candidates.len(), 2, "knn + linear both evaluated");
    let backends: Vec<&str> = candidates.iter().map(|c| c.backend).collect();
    assert!(backends.contains(&"knn-pgvector"));
    assert!(backends.contains(&"logistic-regression"));

    // Ordered by the selection score (macro-recall), best first.
    assert!(
        candidates[0].macro_recall >= candidates[1].macro_recall,
        "candidates must be sorted best-first by macro-recall"
    );

    // On cleanly separable data both backends do well.
    for c in &candidates {
        assert!(
            c.macro_recall > 0.8 && c.macro_f1 > 0.8,
            "{} scores too low on separable data (recall {}, f1 {})",
            c.backend,
            c.macro_recall,
            c.macro_f1
        );
    }

    // Only the parametric backend carries an artifact, and it round-trips
    // into a usable model that classifies its own cluster.
    let linear = candidates
        .iter()
        .find(|c| c.backend == "logistic-regression")
        .unwrap();
    let knn = candidates
        .iter()
        .find(|c| c.backend == "knn-pgvector")
        .unwrap();
    assert!(knn.artifact.is_none(), "knn is lazy — no artifact");
    let bytes = linear.artifact.as_ref().expect("linear has an artifact");
    let model = LinearModel::open(bytes).expect("artifact round-trips");
    let mut alpha = vec![0.0f32; 1024];
    alpha[0] = 1.0;
    let pred = model.predict(&alpha).expect("predicts");
    assert_eq!(pred.label, "alpha", "linear classifies its own cluster");
    assert!(pred.confidence > 0.5);
}
