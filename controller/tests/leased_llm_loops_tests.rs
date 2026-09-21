//! The LLM / ML background loops run once per configured interval for the
//! FLEET — not once per controller replica, and not once per boot.
//!
//! Each test drives the PRODUCTION scheduler (`spawn_*`), whose first tick is
//! immediate, and reads the stamp that loop leaves on the rows it swept. A
//! second spawn on the same database is both "a second replica" and "the
//! controller restarted": before the lease it swept everything again.
mod common;

use std::sync::Arc;
use std::time::Duration;
use talos_task_supervision::BackgroundTask;
use uuid::Uuid;

type Pool = sqlx::Pool<sqlx::Postgres>;

async fn seed_actor(pool: &Pool) -> (Uuid, Uuid) {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(user)
    .bind(format!("{user}@leased-loops.test"))
    .execute(pool)
    .await
    .expect("user");
    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name, status) VALUES ($1, $2, $3, 'active')")
        .bind(actor)
        .bind(user)
        .bind(format!("actor-{actor}"))
        .execute(pool)
        .await
        .expect("actor");
    (user, actor)
}

/// Poll `stamp_sql` (one nullable timestamptz, bound to `id`) until it is
/// newer than `after`, or give up.
async fn wait_for_stamp(
    pool: &Pool,
    stamp_sql: &str,
    id: Uuid,
    after: Option<chrono::DateTime<chrono::Utc>>,
    within: Duration,
) -> Option<chrono::DateTime<chrono::Utc>> {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let stamp: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(stamp_sql)
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("read stamp");
        if let Some(s) = stamp {
            if after.is_none_or(|a| s > a) {
                return Some(s);
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn expire_lease(pool: &Pool, task: BackgroundTask) {
    let n = sqlx::query(
        "UPDATE background_task_leases SET leased_until = now() - interval '1 second' WHERE task = $1",
    )
    .bind(task.as_str())
    .execute(pool)
    .await
    .expect("expire")
    .rows_affected();
    assert_eq!(n, 1, "{} never took a lease", task.as_str());
}

/// The shape every leased loop must have. `spawn` starts one scheduler and
/// returns the sender that shuts it down.
async fn assert_runs_once_per_period<F>(
    pool: &Pool,
    task: BackgroundTask,
    stamp_sql: &str,
    id: Uuid,
    spawn: F,
) where
    F: Fn() -> tokio::sync::watch::Sender<bool>,
{
    // First process: its boot tick claims the period and sweeps.
    let first = spawn();
    let swept = wait_for_stamp(pool, stamp_sql, id, None, Duration::from_secs(20))
        .await
        .unwrap_or_else(|| panic!("{} never ran its first tick", task.as_str()));

    // A second replica / a restart: its boot tick must be refused.
    let second = spawn();
    assert!(
        wait_for_stamp(pool, stamp_sql, id, Some(swept), Duration::from_secs(2))
            .await
            .is_none(),
        "{} swept again inside its period",
        task.as_str()
    );
    let _ = first.send(true);
    let _ = second.send(true);

    // CONTROL: once the period is over, the next process's boot tick sweeps —
    // so the refusal above was the lease, not a scheduler that never runs twice.
    expire_lease(pool, task).await;
    let third = spawn();
    assert!(
        wait_for_stamp(pool, stamp_sql, id, Some(swept), Duration::from_secs(20))
            .await
            .is_some(),
        "{} did not run after its lease lapsed",
        task.as_str()
    );
    let _ = third.send(true);
}

fn secrets(pool: &Pool) -> Arc<controller::secrets::SecretsManager> {
    Arc::new(controller::secrets::SecretsManager::new(pool.clone()).expect("secrets manager"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn memory_consolidation_runs_once_per_period() {
    let (pool, _db) = common::isolated_db_pool().await;
    let (_user, actor) = seed_actor(&pool).await;
    let sm = secrets(&pool);
    assert_runs_once_per_period(
        &pool,
        BackgroundTask::MemoryConsolidationScheduler,
        "SELECT last_consolidated_at FROM actors WHERE id = $1",
        actor,
        || {
            let (tx, rx) = tokio::sync::watch::channel(false);
            talos_memory_consolidation::spawn_memory_consolidation_scheduler(
                pool.clone(),
                talos_actor_repository::ActorRepository::new(pool.clone()),
                None,
                sm.clone(),
                rx,
            );
            tx
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn memory_reflection_runs_once_per_period() {
    let (pool, _db) = common::isolated_db_pool().await;
    let (_user, actor) = seed_actor(&pool).await;
    let sm = secrets(&pool);
    assert_runs_once_per_period(
        &pool,
        BackgroundTask::MemoryReflectionScheduler,
        "SELECT last_reflected_at FROM actors WHERE id = $1",
        actor,
        || {
            let (tx, rx) = tokio::sync::watch::channel(false);
            talos_memory_consolidation::spawn_memory_reflection_scheduler(
                pool.clone(),
                talos_actor_repository::ActorRepository::new(pool.clone()),
                None,
                sm.clone(),
                rx,
            );
            tx
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rank_training_runs_once_per_period() {
    let (pool, _db) = common::isolated_db_pool().await;
    let (_user, actor) = seed_actor(&pool).await;
    assert_runs_once_per_period(
        &pool,
        BackgroundTask::RankTrainingScheduler,
        "SELECT last_rank_trained_at FROM actors WHERE id = $1",
        actor,
        || {
            let (tx, rx) = tokio::sync::watch::channel(false);
            talos_memory_ranking::spawn_rank_training_scheduler(
                pool.clone(),
                talos_actor_repository::ActorRepository::new(pool.clone()),
                rx,
            );
            tx
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_disagreement_digest_runs_once_per_period() {
    let (pool, _db) = common::isolated_db_pool().await;
    let (user, actor) = seed_actor(&pool).await;
    let model = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO ml_models (id, user_id, name, task_type, config_json, policy_json) \
         VALUES ($1, $2, $3, 'classification', $4, '{\"min_examples\": 1}'::jsonb)",
    )
    .bind(model)
    .bind(user)
    .bind(format!("m-{model}"))
    .bind(serde_json::json!({"digest": {"actor_id": actor}}))
    .execute(&pool)
    .await
    .expect("model");
    let lifecycle = Arc::new(talos_ml::lifecycle::LifecycleService::new(secrets(&pool)));
    assert_runs_once_per_period(
        &pool,
        BackgroundTask::MlDisagreementDigest,
        "SELECT last_digest_at FROM ml_models WHERE id = $1",
        model,
        || {
            let (tx, rx) = tokio::sync::watch::channel(false);
            talos_ml::digest::spawn_disagreement_digest(pool.clone(), lifecycle.clone(), rx);
            tx
        },
    )
    .await;
}

/// TEXTUAL, stated as such. The tests above prove a refused tick does not
/// sweep; they cannot see HOW OFTEN a loop asks. A daily loop whose ticker is
/// its period would, after being refused at boot, not ask again for a day —
/// and under frequent deploys its runs would drift up to two periods apart.
#[test]
fn every_leased_loop_re_asks_at_the_lease_crates_cadence() {
    for (src, loops) in [
        (
            include_str!("../../talos-memory-consolidation/src/lib.rs"),
            2,
        ),
        (include_str!("../../talos-memory-ranking/src/lib.rs"), 1),
        (include_str!("../../talos-ml/src/digest.rs"), 1),
    ] {
        let squashed: String = src.split_whitespace().collect();
        assert_eq!(
            squashed
                .matches("tokio::time::interval(talos_background_lease::tick_every(period))")
                .count(),
            loops
        );
        assert_eq!(
            squashed
                .matches("letperiod=std::time::Duration::from_secs(interval_secs);")
                .count(),
            loops,
            "the lease period must be the configured interval"
        );
        assert!(
            !squashed
                .contains("tokio::time::interval(std::time::Duration::from_secs(interval_secs))"),
            "a loop ticks at its full period again"
        );
    }
}
