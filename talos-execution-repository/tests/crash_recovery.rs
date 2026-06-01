//! Live-Postgres integration tests for the crash-recovery claim/fail/reclaim
//! repository methods (RFC 0003 durable execution). Proves the
//! safety-critical exactly-once claim, the stale-threshold gating, and the
//! terminal-exit guards.
//!
//! Gated on `TALOS_TEST_DATABASE_URL` (skips when unset):
//! ```sh
//! export TALOS_TEST_DATABASE_URL="postgres://postgres:talos@localhost:5433/talos"
//! cargo test -p talos-execution-repository --test crash_recovery
//! ```
//!
//! `claim_stuck_execution_for_resume` claims the GLOBALLY oldest stale
//! `running` row, so these tests (a) serialize via `SERIAL` and (b) refresh
//! every OTHER claimable row's `updated_at` so the seeded row is the only
//! claimable one — deterministic regardless of leftovers from prior runs.

use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres};
use std::sync::LazyLock;
use talos_execution_repository::ExecutionRepository;
use tokio::sync::Mutex;
use uuid::Uuid;

static SERIAL: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

fn db_url() -> Option<String> {
    std::env::var("TALOS_TEST_DATABASE_URL")
        .ok()
        .filter(|u| !u.is_empty())
}

async fn connect(url: &str) -> Pool<Postgres> {
    PgPoolOptions::new()
        .max_connections(8)
        .connect(url)
        .await
        .expect("connect")
}

async fn seed_running_exec(pool: &Pool<Postgres>, age_minutes: i64) -> (Uuid, Uuid, Uuid) {
    let user_id = Uuid::new_v4();
    let wf_id = Uuid::new_v4();
    let exec_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id,email,password_hash,name) VALUES ($1,$2,'x','cr')")
        .bind(user_id)
        .bind(format!("cr-{}@test.invalid", user_id.simple()))
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO workflows (id,user_id,name,module_uri,graph_json) \
         VALUES ($1,$2,'cr-wf','mod://x','{\"nodes\":[]}'::jsonb)",
    )
    .bind(wf_id)
    .bind(user_id)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO workflow_executions (id,workflow_id,user_id,status,started_at,updated_at) \
         VALUES ($1,$2,$3,'running', NOW() - make_interval(mins => $4::int), NOW() - make_interval(mins => $4::int))",
    )
    .bind(exec_id)
    .bind(wf_id)
    .bind(user_id)
    .bind(age_minutes)
    .execute(pool)
    .await
    .unwrap();
    (exec_id, wf_id, user_id)
}

/// Make `keep` the ONLY claimable row by refreshing every other running /
/// resuming row's `updated_at` to now (so they fall outside the staleness
/// window). Non-destructive.
async fn make_only_claimable(pool: &Pool<Postgres>, keep: Uuid) {
    sqlx::query(
        "UPDATE workflow_executions SET updated_at = NOW() \
         WHERE status IN ('running','resuming') AND id != $1",
    )
    .bind(keep)
    .execute(pool)
    .await
    .unwrap();
}

async fn status_of(pool: &Pool<Postgres>, id: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM workflow_executions WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn cleanup(pool: &Pool<Postgres>, user_id: Uuid, wf_id: Uuid) {
    let _ = sqlx::query("DELETE FROM workflow_executions WHERE workflow_id = $1")
        .bind(wf_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM workflows WHERE id = $1")
        .bind(wf_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await;
}

/// The safety-critical property: N concurrent claimers, one stale row →
/// EXACTLY ONE wins, the rest get None, and the row ends in `resuming`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn claim_is_exactly_once_under_concurrency() {
    let Some(url) = db_url() else { return };
    let _g = SERIAL.lock().await;
    let pool = connect(&url).await;
    let (exec_id, wf_id, user_id) = seed_running_exec(&pool, 60).await;
    make_only_claimable(&pool, exec_id).await;

    // 8 concurrent claims against the single stale row.
    let mut handles = Vec::new();
    for _ in 0..8 {
        let r = ExecutionRepository::new(pool.clone());
        handles.push(tokio::spawn(async move {
            r.claim_stuck_execution_for_resume(5).await.unwrap()
        }));
    }
    let mut won = 0usize;
    for h in handles {
        if let Some(row) = h.await.unwrap() {
            won += 1;
            assert_eq!(
                row.id, exec_id,
                "the only claimable row must be the seeded one"
            );
            assert_eq!(row.workflow_id, wf_id);
            assert!(
                row.graph_json.is_some(),
                "graph_json must come through the correlated subquery"
            );
        }
    }
    assert_eq!(
        won, 1,
        "exactly one concurrent claimer must win the single stale row"
    );
    assert_eq!(
        status_of(&pool, exec_id).await,
        "resuming",
        "claimed row must be in resuming"
    );

    // A second claim no longer finds it (no longer 'running').
    let repo = ExecutionRepository::new(pool.clone());
    let again = repo.claim_stuck_execution_for_resume(5).await.unwrap();
    assert!(again.map(|r| r.id) != Some(exec_id));

    cleanup(&pool, user_id, wf_id).await;
}

/// A FRESH running execution (recent updated_at) is not claimed; a
/// non-positive threshold is refused.
#[tokio::test]
async fn claim_respects_stale_threshold_and_refuses_nonpositive() {
    let Some(url) = db_url() else { return };
    let _g = SERIAL.lock().await;
    let pool = connect(&url).await;
    let (fresh_id, wf_id, user_id) = seed_running_exec(&pool, 0).await; // updated_at = now
    let repo = ExecutionRepository::new(pool.clone());

    // 5-min threshold: a fresh row is NOT claimed (it may claim some other
    // leftover, but never our fresh one).
    let claimed = repo.claim_stuck_execution_for_resume(5).await.unwrap();
    assert!(
        claimed.map(|r| r.id) != Some(fresh_id),
        "a fresh running execution must not be claimed under a 5-min threshold"
    );
    assert_eq!(status_of(&pool, fresh_id).await, "running");

    // Non-positive threshold is refused (would claim everything).
    assert!(repo
        .claim_stuck_execution_for_resume(0)
        .await
        .unwrap()
        .is_none());
    assert!(repo
        .claim_stuck_execution_for_resume(-5)
        .await
        .unwrap()
        .is_none());

    cleanup(&pool, user_id, wf_id).await;
}

/// fail_resuming only transitions a `resuming` row; reclaim_orphaned_resuming
/// fails stale `resuming` rows and leaves fresh ones.
#[tokio::test]
async fn fail_and_reclaim_are_status_guarded() {
    let Some(url) = db_url() else { return };
    let _g = SERIAL.lock().await;
    let pool = connect(&url).await;
    let (exec_id, wf_id, user_id) = seed_running_exec(&pool, 60).await;
    make_only_claimable(&pool, exec_id).await;
    let repo = ExecutionRepository::new(pool.clone());

    // fail_resuming on a 'running' row is a no-op (status guard).
    assert!(!repo.fail_resuming_execution(exec_id, "x").await.unwrap());
    assert_eq!(status_of(&pool, exec_id).await, "running");

    // Claim → resuming, then fail_resuming → failed.
    let claimed = repo.claim_stuck_execution_for_resume(5).await.unwrap();
    assert_eq!(claimed.unwrap().id, exec_id);
    assert!(repo
        .fail_resuming_execution(exec_id, "dispatch failed")
        .await
        .unwrap());
    assert_eq!(status_of(&pool, exec_id).await, "failed");

    // reclaim_orphaned_resuming: a stale 'resuming' row → failed. Seed it
    // directly via INSERT — a BEFORE-UPDATE trigger (which is what makes
    // updated_at a checkpoint heartbeat in production) would otherwise reset
    // updated_at to NOW() on an UPDATE, hiding the staleness.
    let (orphan, wf2, user2) = seed_running_exec(&pool, 60).await;
    sqlx::query("DELETE FROM workflow_executions WHERE id = $1")
        .bind(orphan)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO workflow_executions (id,workflow_id,user_id,status,started_at,updated_at) \
         VALUES ($1,$2,$3,'resuming', NOW()-make_interval(mins=>60), NOW()-make_interval(mins=>30))",
    )
    .bind(orphan).bind(wf2).bind(user2).execute(&pool).await.unwrap();
    let n = repo.reclaim_orphaned_resuming(10).await.unwrap();
    assert!(n >= 1);
    assert_eq!(status_of(&pool, orphan).await, "failed");
    // non-positive grace refused
    assert_eq!(repo.reclaim_orphaned_resuming(0).await.unwrap(), 0);

    cleanup(&pool, user_id, wf_id).await;
    cleanup(&pool, user2, wf2).await;
}
