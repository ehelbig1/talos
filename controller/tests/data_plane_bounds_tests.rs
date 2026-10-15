//! The data plane's size and spend bounds (security review 2026-10-14,
//! package 13): the platform LLM key's daily ceiling (I-2, and every
//! vault-sourced client under it, I2-2), a dataset's
//! default growth cap and the per-user example ceiling (I-1), and the
//! cross-replica single flight (I-3).
//!
//! This binary sets `TALOS_PLATFORM_LLM_TOKENS_PER_DAY` itself (one setting
//! per binary).
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use std::time::Duration;
use uuid::Uuid;

const CEILING: i64 = 1_000;

fn small_platform_ceiling() {
    std::env::set_var("TALOS_PLATFORM_LLM_TOKENS_PER_DAY", CEILING.to_string());
}

async fn seed_user_and_actor(pool: &sqlx::PgPool) -> (Uuid, Uuid) {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(user)
    .bind(format!("{user}@data-plane.test"))
    .execute(pool)
    .await
    .expect("seed user");
    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name) VALUES ($1, $2, $3)")
        .bind(actor)
        .bind(user)
        .bind(format!("dp-{}", &actor.to_string()[..8]))
        .execute(pool)
        .await
        .expect("seed actor");
    (user, actor)
}

async fn spend(
    pool: &sqlx::PgPool,
    actor: Uuid,
    provider: &str,
    tokens: i64,
    with_execution: bool,
) {
    sqlx::query(
        "INSERT INTO llm_usage (actor_id, execution_id, provider, model, prompt_tokens, \
                                completion_tokens, calls) \
         VALUES ($1, CASE WHEN $2 THEN gen_random_uuid() END, $3, 'm', $4, 0, 1)",
    )
    .bind(actor)
    .bind(with_execution)
    .bind(provider)
    .bind(tokens)
    .execute(pool)
    .await
    .expect("record usage");
}

/// I-2: the platform key's ceiling counts the controller's own external
/// spend — every actor's — and nothing else; at the ceiling the external
/// call is refused, for an actor with no budget row of its own.
#[tokio::test]
async fn the_platform_key_has_a_daily_ceiling_across_every_actor() {
    small_platform_ceiling();
    let (pool, _db) = common::isolated_db_pool().await;
    let repo = talos_actor_repository::ActorRepository::new(pool.clone());
    let (_, a) = seed_user_and_actor(&pool).await;
    let (_, b) = seed_user_and_actor(&pool).await;
    assert!(
        !repo.external_llm_spend_refused(a).await,
        "nothing spent yet"
    );

    // Not the platform key's: local inference, and spend behind an execution.
    spend(&pool, b, "ollama", 5 * CEILING, false).await;
    spend(&pool, b, "anthropic", 5 * CEILING, true).await;
    assert!(!repo.external_llm_spend_refused(a).await);

    // Another actor's platform-key spend counts for everyone.
    spend(&pool, b, "anthropic", CEILING - 1, false).await;
    assert!(!repo.external_llm_spend_refused(a).await, "one under");
    spend(&pool, b, "anthropic", 1, false).await;
    assert!(repo.external_llm_spend_refused(a).await, "at the ceiling");
}

/// I2-2: every caller of a vault-sourced platform client is held to the same
/// ceiling — the shared controller client, the evaluation judge, consolidation
/// — because the gate is in the client's key resolution, not at two call
/// sites. At the ceiling the call is refused before a key is looked up — the
/// client below has none, so without the gate it would fail for that reason
/// and send nothing either way — and the refusal is the one callers recognise.
#[tokio::test]
async fn a_vault_sourced_llm_client_refuses_at_the_platform_ceiling() {
    small_platform_ceiling();
    let (pool, _db) = common::isolated_db_pool().await;
    let secrets = std::sync::Arc::new(
        controller::secrets::SecretsManager::new(pool.clone()).expect("secrets"),
    );
    let (_, actor) = seed_user_and_actor(&pool).await;
    spend(&pool, actor, "anthropic", CEILING, false).await;

    let client = talos_llm::LlmClient::with_vault(secrets, None);
    let err = client
        .generate_text("system", "user")
        .await
        .expect_err("refused at the ceiling");
    assert!(talos_llm::is_platform_ceiling(&err), "{err}");
}

/// I-1: a dataset that names no cap is held to the default one, an existing
/// dataset created before it included.
#[tokio::test]
async fn a_dataset_without_a_cap_is_held_to_the_default_one() {
    let (pool, _db) = common::isolated_db_pool().await;
    let secrets = std::sync::Arc::new(
        controller::secrets::SecretsManager::new(pool.clone()).expect("secrets"),
    );
    secrets.initialize().await.expect("active DEK");
    let key_id: Uuid = sqlx::query_scalar("SELECT id FROM encryption_keys LIMIT 1")
        .fetch_one(&pool)
        .await
        .expect("a DEK");
    let (user, _) = seed_user_and_actor(&pool).await;
    let dataset = Uuid::new_v4();
    // As a dataset made before the default existed: no cap in its schema.
    sqlx::query(
        "INSERT INTO ml_datasets (id, user_id, name, task_type, schema_json) \
         VALUES ($1, $2, 'uncapped', 'classification', '{}'::jsonb)",
    )
    .bind(dataset)
    .bind(user)
    .execute(&pool)
    .await
    .expect("seed dataset");
    let over = talos_ml::DEFAULT_MAX_EXAMPLES + 3;
    sqlx::query(
        "INSERT INTO ml_examples (id, dataset_id, user_id, features_enc, features_key_id, \
                                  features_format, label_json, source, created_at) \
         SELECT gen_random_uuid(), $1, $2, '\\x00'::bytea, $3, 3, '\"x\"'::jsonb, \
                'llm_production', now() - make_interval(secs => g) \
         FROM generate_series(1, $4) g",
    )
    .bind(dataset)
    .bind(user)
    .bind(key_id)
    .bind(over)
    .execute(&pool)
    .await
    .expect("seed examples");
    let service = talos_ml::DatasetService::new(secrets);
    let mut conn = pool.acquire().await.expect("conn");
    let evicted = service
        .enforce_growth_cap(&mut conn, dataset)
        .await
        .expect("cap");
    assert_eq!(evicted, 3, "the default cap applies to an uncapped dataset");

    // And a dataset created now records the default in its schema.
    let made = service
        .create_dataset(
            &mut conn,
            user,
            None,
            "made-now",
            "classification",
            &serde_json::json!({}),
        )
        .await
        .expect("create");
    let schema: serde_json::Value =
        sqlx::query_scalar("SELECT schema_json FROM ml_datasets WHERE id = $1")
            .bind(made)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(schema["max_examples"], talos_ml::DEFAULT_MAX_EXAMPLES);

    // I-1: the per-user ceiling counts every dataset.
    let held = over - 3;
    let room = (talos_ml::MAX_EXAMPLES_PER_USER - held) as usize;
    talos_ml::refuse_past_user_example_ceiling(&mut conn, user, room)
        .await
        .expect("up to the ceiling");
    assert!(
        talos_ml::refuse_past_user_example_ceiling(&mut conn, user, room + 1)
            .await
            .is_err()
    );
}

/// I-3: a named advisory lock is held by one holder across connections (as
/// across replicas); release hands it on, and a holder dropped without a
/// release frees it too.
#[tokio::test]
async fn a_named_advisory_lock_has_one_holder_at_a_time() {
    let (pool, _db) = common::isolated_db_pool().await;
    let other = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect_with((*pool.connect_options()).clone())
        .await
        .expect("a second pool, as another replica");
    let key = format!("graph_backfill:{}", Uuid::new_v4());
    let first = talos_db::try_named_advisory_lock(&pool, &key, Duration::ZERO)
        .await
        .expect("lock")
        .expect("free");
    assert!(
        talos_db::try_named_advisory_lock(&other, &key, Duration::ZERO)
            .await
            .expect("lock")
            .is_none(),
        "held elsewhere"
    );
    first.release().await;
    let second = talos_db::try_named_advisory_lock(&other, &key, Duration::from_secs(2))
        .await
        .expect("lock")
        .expect("released");
    drop(second);
    let third = talos_db::try_named_advisory_lock(&pool, &key, Duration::from_secs(5))
        .await
        .expect("lock");
    assert!(third.is_some(), "a dropped holder frees the lock");
}
