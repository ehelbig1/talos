//! A user at the per-user example ceiling costs the shared embedder nothing
//! (security review 2026-10-15, I2-4): `DatasetService::prepare_examples`
//! asks the ceiling before it embeds, so an append that will be refused is
//! refused before any embedding request — the distill path, a correction and
//! a bootstrap page all prepare through it.
//!
//! The embedder is the counting loopback stand-in
//! (`talos-memory/tests/embedding_mock`); its settings are process-wide, so
//! this binary holds only this test.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;
// The stand-in's other counters are for the memory crate's own tests.
#[allow(dead_code)]
#[path = "../../talos-memory/tests/embedding_mock/mod.rs"]
mod embedding_mock;

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

const DIMS: usize = 8;

fn one_example(text: &str) -> Vec<talos_ml::AppendExample> {
    vec![talos_ml::AppendExample {
        features_text: text.to_string(),
        label: "made-up-class".to_string(),
        source: talos_ml::ExampleSource::LlmProduction,
        example_key: None,
        origin: None,
    }]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_user_at_the_example_ceiling_causes_zero_embedding_calls() {
    let mock = embedding_mock::start(Duration::from_millis(1), DIMS).await;
    embedding_mock::configure(&mock.url, DIMS, 5, None);
    let (pool, _db) = common::isolated_db_pool().await;
    let secrets =
        Arc::new(controller::secrets::SecretsManager::new(pool.clone()).expect("secrets"));
    secrets.initialize().await.expect("active DEK");
    let key_id: Uuid = sqlx::query_scalar("SELECT id FROM encryption_keys LIMIT 1")
        .fetch_one(&pool)
        .await
        .expect("a DEK");
    let service = talos_ml::DatasetService::new(secrets);

    let mut datasets = Vec::new();
    for name in ["under", "at"] {
        let user = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
        )
        .bind(user)
        .bind(format!("{user}@ml-ceiling.test"))
        .execute(&pool)
        .await
        .expect("seed user");
        let dataset = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO ml_datasets (id, user_id, name, task_type, schema_json) \
             VALUES ($1, $2, $3, 'classification', '{}'::jsonb)",
        )
        .bind(dataset)
        .bind(user)
        .bind(name)
        .execute(&pool)
        .await
        .expect("seed dataset");
        datasets.push((user, dataset));
    }
    let (_, under) = datasets[0];
    let (at_user, at) = datasets[1];
    sqlx::query(
        "INSERT INTO ml_examples (id, dataset_id, user_id, features_enc, features_key_id, \
                                  features_format, label_json, source) \
         SELECT gen_random_uuid(), $1, $2, '\\x00'::bytea, $3, 3, '\"x\"'::jsonb, 'llm_production' \
         FROM generate_series(1, $4) g",
    )
    .bind(at)
    .bind(at_user)
    .bind(key_id)
    .bind(talos_ml::MAX_EXAMPLES_PER_USER)
    .execute(&pool)
    .await
    .expect("seed the ceiling's worth of examples");

    // The stand-in is wired: a user under the ceiling is embedded.
    let mut conn = pool.acquire().await.expect("conn");
    let tenancy = service
        .dataset_tenancy(&mut conn, under)
        .await
        .expect("tenancy");
    service
        .prepare_examples(under, tenancy, one_example("a made-up message"))
        .await
        .expect("under the ceiling");
    let embedded = mock.received.load(Ordering::SeqCst);
    assert!(embedded >= 1, "the embedder stand-in answers");

    // At the ceiling: refused, and the embedder is not asked.
    let tenancy = service
        .dataset_tenancy(&mut conn, at)
        .await
        .expect("tenancy");
    let Err(refused) = service
        .prepare_examples(at, tenancy, one_example("another made-up message"))
        .await
    else {
        panic!("an append at the ceiling was prepared");
    };
    assert!(
        refused.to_string().contains("stored examples"),
        "{refused:#}"
    );
    assert_eq!(
        mock.received.load(Ordering::SeqCst),
        embedded,
        "no embedding call for an append that will be refused"
    );
}
