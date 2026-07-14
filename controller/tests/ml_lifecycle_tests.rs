//! RFC 0011 P2d lifecycle invariants against a real database:
//! CAS state transitions, shadow-stat accumulation, growth-cap
//! eviction with pinned corrections, and owner-scoped disagreement
//! round-trips (encrypt → digest read → resolve).

mod common;

use std::sync::Arc;
use talos_ml::{DatasetService, LifecycleService, LifecycleState};
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
         VALUES ($1, $2, 'not-a-real-hash', true) ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(format!("{id}@ml-lifecycle.test"))
    .execute(pool)
    .await
    .expect("seed user");
}

async fn seed_dataset(
    pool: &sqlx::Pool<sqlx::Postgres>,
    user_id: Uuid,
    schema_json: serde_json::Value,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO ml_datasets (id, user_id, name, task_type, schema_json) \
         VALUES ($1, $2, $3, 'classification', $4)",
    )
    .bind(id)
    .bind(user_id)
    .bind(format!("ds-{id}"))
    .bind(schema_json)
    .execute(pool)
    .await
    .expect("seed dataset");
    id
}

async fn seed_model(pool: &sqlx::Pool<sqlx::Postgres>, user_id: Uuid, dataset_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO ml_models (id, user_id, name, task_type, dataset_id, config_json) \
         VALUES ($1, $2, $3, 'classification', $4, '{}'::jsonb)",
    )
    .bind(id)
    .bind(user_id)
    .bind(format!("m-{id}"))
    .bind(dataset_id)
    .execute(pool)
    .await
    .expect("seed model");
    id
}

/// Direct example insert with dummy ciphertext (crypto is exercised by
/// the disagreement test; the growth cap only reads source/created_at).
async fn seed_example(
    pool: &sqlx::Pool<sqlx::Postgres>,
    dataset_id: Uuid,
    user_id: Uuid,
    source: &str,
    age_secs: i32,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO ml_examples (id, dataset_id, user_id, features_enc, features_key_id, \
         features_format, label_json, source, created_at) \
         VALUES ($1, $2, $3, '\\x00'::bytea, $4, 3, '{\"label\":\"x\"}'::jsonb, $5, \
                 NOW() - make_interval(secs => $6::int))",
    )
    .bind(id)
    .bind(dataset_id)
    .bind(user_id)
    .bind(Uuid::new_v4())
    .bind(source)
    .bind(age_secs)
    .execute(pool)
    .await
    .expect("seed example");
    id
}

fn lifecycle_service(pool: &sqlx::Pool<sqlx::Postgres>) -> LifecycleService {
    set_master_key();
    let sm = Arc::new(controller::secrets::SecretsManager::new(pool.clone()).unwrap());
    LifecycleService::new(sm)
}

#[tokio::test]
async fn cas_transitions_enforce_the_state_machine() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = Uuid::new_v4();
    seed_user(&pool, user).await;
    let ds = seed_dataset(&pool, user, serde_json::json!({})).await;
    let model = seed_model(&pool, user, ds).await;
    let svc = lifecycle_service(&pool);
    let mut conn = pool.acquire().await.unwrap();

    // Forward one step applies…
    assert!(svc
        .transition(
            &mut conn,
            model,
            user,
            LifecycleState::LlmOnly,
            LifecycleState::Shadow
        )
        .await
        .unwrap());
    // …a stale CAS (same from-state again) is a clean lost-race no-op…
    assert!(!svc
        .transition(
            &mut conn,
            model,
            user,
            LifecycleState::LlmOnly,
            LifecycleState::Shadow
        )
        .await
        .unwrap());
    // …skipping forward is structurally illegal…
    assert!(svc
        .transition(
            &mut conn,
            model,
            user,
            LifecycleState::Shadow,
            LifecycleState::FastPrimary
        )
        .await
        .is_err());
    // …a foreign user can't move the row (owner-scoped CAS)…
    let intruder = Uuid::new_v4();
    seed_user(&pool, intruder).await;
    assert!(!svc
        .transition(
            &mut conn,
            model,
            intruder,
            LifecycleState::Shadow,
            LifecycleState::Hybrid
        )
        .await
        .unwrap());
    // …and a multi-step demote is always legal (fail-safe).
    assert!(svc
        .transition(
            &mut conn,
            model,
            user,
            LifecycleState::Shadow,
            LifecycleState::Hybrid
        )
        .await
        .unwrap());
    assert!(svc
        .transition(
            &mut conn,
            model,
            user,
            LifecycleState::Hybrid,
            LifecycleState::LlmOnly
        )
        .await
        .unwrap());
}

#[tokio::test]
async fn shadow_stats_accumulate_per_band() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = Uuid::new_v4();
    seed_user(&pool, user).await;
    let ds = seed_dataset(&pool, user, serde_json::json!({})).await;
    let model = seed_model(&pool, user, ds).await;
    let svc = lifecycle_service(&pool);
    let mut conn = pool.acquire().await.unwrap();

    // Two agreements at 0.9, one miss at 0.9, one abstention.
    svc.record_shadow_outcome(&mut conn, model, user, None, Some(0.9), true)
        .await
        .unwrap();
    svc.record_shadow_outcome(&mut conn, model, user, None, Some(0.92), true)
        .await
        .unwrap();
    svc.record_shadow_outcome(&mut conn, model, user, None, Some(0.95), false)
        .await
        .unwrap();
    svc.record_shadow_outcome(&mut conn, model, user, None, None, false)
        .await
        .unwrap();

    // Overall (band >= 0): 2 agree / 4 total.
    let (agreement, total) = svc
        .shadow_agreement(&mut conn, model, 0)
        .await
        .unwrap()
        .expect("stats exist");
    assert_eq!(total, 4);
    assert!((agreement - 0.5).abs() < 1e-9);
    // High-confidence bands only (>= 9): 2 agree / 3 total.
    let (agreement, total) = svc
        .shadow_agreement(&mut conn, model, 9)
        .await
        .unwrap()
        .expect("stats exist");
    assert_eq!(total, 3);
    assert!((agreement - 2.0 / 3.0).abs() < 1e-9);
}

#[tokio::test]
async fn growth_cap_evicts_oldest_but_pins_corrections() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = Uuid::new_v4();
    seed_user(&pool, user).await;
    // Cap of 5 on the dataset policy.
    let ds = seed_dataset(&pool, user, serde_json::json!({"max_examples": 5})).await;

    // 3 corrections (oldest of all) + 5 bootstrap rows, newest last.
    let mut corrections = Vec::new();
    for i in 0..3 {
        corrections.push(seed_example(&pool, ds, user, "correction", 10_000 + i).await);
    }
    for i in 0..5 {
        seed_example(&pool, ds, user, "llm_bootstrap", 1_000 - i).await;
    }

    set_master_key();
    let sm = Arc::new(controller::secrets::SecretsManager::new(pool.clone()).unwrap());
    let dsvc = DatasetService::new(sm);
    let mut conn = pool.acquire().await.unwrap();
    dsvc.enforce_growth_cap(&mut conn, ds).await.unwrap();

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ml_examples WHERE dataset_id = $1")
        .bind(ds)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(total, 5, "capped to max_examples");
    // Every correction survived even though they were the OLDEST rows.
    let surviving_corrections: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM ml_examples WHERE dataset_id = $1 AND source = 'correction'",
    )
    .bind(ds)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(surviving_corrections, 3, "corrections are pinned");
}

#[tokio::test]
async fn disagreements_roundtrip_encrypted_and_owner_scoped() {
    let (pool, _db) = common::isolated_db_pool().await;
    set_master_key();
    let user = Uuid::new_v4();
    seed_user(&pool, user).await;
    let ds = seed_dataset(&pool, user, serde_json::json!({})).await;
    let model = seed_model(&pool, user, ds).await;

    let sm = Arc::new(controller::secrets::SecretsManager::new(pool.clone()).unwrap());
    sm.initialize().await.unwrap();
    let svc = LifecycleService::new(sm);
    let mut conn = pool.acquire().await.unwrap();

    let id = svc
        .record_disagreement(
            &mut conn,
            model,
            user,
            None,
            Some("msg-1"),
            "Subject: invoice overdue",
            Some(("archive", 0.61)),
            "follow_up",
            "divergence",
        )
        .await
        .unwrap();

    // Owner reads it decrypted; a stranger reads nothing.
    let pending = svc
        .pending_disagreements(&mut conn, model, user, 10)
        .await
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].features_text, "Subject: invoice overdue");
    assert_eq!(pending[0].fast_label.as_deref(), Some("archive"));
    let stranger = Uuid::new_v4();
    seed_user(&pool, stranger).await;
    assert!(svc
        .pending_disagreements(&mut conn, model, stranger, 10)
        .await
        .unwrap()
        .is_empty());
    // Stranger can't resolve it either; owner can, exactly once.
    assert!(!svc
        .set_disagreement_status(&mut conn, id, stranger, "dismissed")
        .await
        .unwrap());
    assert!(svc
        .set_disagreement_status(&mut conn, id, user, "resolved")
        .await
        .unwrap());
    assert!(!svc
        .set_disagreement_status(&mut conn, id, user, "resolved")
        .await
        .unwrap());
}

// ── Epoch-windowed shadow agreement (migration 20260714170000) ──────

/// The wrongful-demote regression pin: agreement accumulated in a prior
/// era (old teacher / old version / old state) must NOT feed the current
/// window. Pre-epoch, a model with bad early history was demoted the
/// moment it advanced — the guard read the stale aggregate, already past
/// min_shadow_total, before any fresh observation existed.
#[tokio::test]
async fn transition_rotates_shadow_window_and_stale_history_stays_out() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = Uuid::new_v4();
    seed_user(&pool, user).await;
    let ds = seed_dataset(&pool, user, serde_json::json!({})).await;
    let model = seed_model(&pool, user, ds).await;
    let svc = lifecycle_service(&pool);
    let mut conn = pool.acquire().await.unwrap();

    // Era 0: a bad run — five straight disagreements.
    for _ in 0..5 {
        svc.record_shadow_outcome(&mut conn, model, user, None, Some(0.9), false)
            .await
            .unwrap();
    }
    let (agreement, total) = svc
        .shadow_agreement(&mut conn, model, 0)
        .await
        .unwrap()
        .expect("era 0 has observations");
    assert_eq!((agreement, total), (0.0, 5));

    // Transition rotates the window (llm_only -> shadow).
    assert!(svc
        .transition(
            &mut conn,
            model,
            user,
            LifecycleState::LlmOnly,
            LifecycleState::Shadow
        )
        .await
        .unwrap());
    assert_eq!(talos_ml::shadow_epoch(&mut conn, model).await.unwrap(), 1);

    // Fresh era: NO observations — the drift guard has no data and
    // therefore no judgment (fail-safe), instead of inheriting 0%.
    assert!(svc
        .shadow_agreement(&mut conn, model, 0)
        .await
        .unwrap()
        .is_none());
    // History remains visible in the lifetime aggregate.
    let (lifetime_agreement, lifetime_total) = svc
        .shadow_agreement_lifetime(&mut conn, model, 0)
        .await
        .unwrap()
        .expect("lifetime keeps history");
    assert_eq!((lifetime_agreement, lifetime_total), (0.0, 5));

    // Fresh observations count from zero in the new era.
    for _ in 0..3 {
        svc.record_shadow_outcome(&mut conn, model, user, None, Some(0.9), true)
            .await
            .unwrap();
    }
    let (agreement, total) = svc
        .shadow_agreement(&mut conn, model, 0)
        .await
        .unwrap()
        .expect("era 1 has observations");
    assert_eq!((agreement, total), (1.0, 3));
    let (lifetime_agreement, lifetime_total) = svc
        .shadow_agreement_lifetime(&mut conn, model, 0)
        .await
        .unwrap()
        .expect("lifetime sums both eras");
    assert_eq!(lifetime_total, 8);
    assert!((lifetime_agreement - 3.0 / 8.0).abs() < 1e-9);
}

/// Promoting a new version is an era change too: the retired version's
/// agreement must not vouch for (or condemn) its successor.
#[tokio::test]
async fn promote_version_rotates_shadow_window() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = Uuid::new_v4();
    seed_user(&pool, user).await;
    let ds = seed_dataset(&pool, user, serde_json::json!({})).await;
    let model = seed_model(&pool, user, ds).await;
    let svc = lifecycle_service(&pool);
    let mut conn = pool.acquire().await.unwrap();

    svc.record_shadow_outcome(&mut conn, model, user, None, Some(0.8), true)
        .await
        .unwrap();

    let version = talos_ml::ModelRegistry::create_version(
        &mut conn,
        model,
        user,
        None,
        "knn-pgvector",
        None,
        &serde_json::json!({}),
    )
    .await
    .unwrap();
    talos_ml::ModelRegistry::promote_version(&mut conn, model, version.id)
        .await
        .unwrap();

    assert_eq!(talos_ml::shadow_epoch(&mut conn, model).await.unwrap(), 1);
    assert!(
        svc.shadow_agreement(&mut conn, model, 0)
            .await
            .unwrap()
            .is_none(),
        "the new version starts with an empty window"
    );
}

/// Old eras prune past the retention depth, so per-model counter rows
/// stay bounded no matter how many transitions a model goes through.
#[tokio::test]
async fn shadow_epoch_retention_prunes_old_eras() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = Uuid::new_v4();
    seed_user(&pool, user).await;
    let ds = seed_dataset(&pool, user, serde_json::json!({})).await;
    let model = seed_model(&pool, user, ds).await;
    let svc = lifecycle_service(&pool);
    let mut conn = pool.acquire().await.unwrap();

    // One observation per era across 7 eras (0..=6).
    for _ in 0..7 {
        svc.record_shadow_outcome(&mut conn, model, user, None, Some(0.7), true)
            .await
            .unwrap();
        talos_ml::bump_shadow_epoch(&mut conn, model).await.unwrap();
    }
    assert_eq!(talos_ml::shadow_epoch(&mut conn, model).await.unwrap(), 7);

    // Retention keeps the current era plus the last RETAINED (4): eras
    // below 7-4=3 are gone.
    let (min_epoch, eras): (i32, i64) = sqlx::query_as(
        "SELECT MIN(epoch), COUNT(DISTINCT epoch) FROM ml_shadow_stats WHERE model_id = $1",
    )
    .bind(model)
    .fetch_one(&mut *conn)
    .await
    .unwrap();
    assert_eq!(min_epoch, 3, "eras below current-4 pruned");
    assert_eq!(eras, 4, "eras 3..=6 hold data (7 is empty so far)");
    // Lifetime now reflects retained eras only — 4 observations.
    let (_, lifetime_total) = svc
        .shadow_agreement_lifetime(&mut conn, model, 0)
        .await
        .unwrap()
        .expect("retained history");
    assert_eq!(lifetime_total, 4);
}
