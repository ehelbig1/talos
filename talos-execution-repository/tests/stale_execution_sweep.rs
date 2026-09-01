//! Live-Postgres integration tests for the attributed stale-execution sweep
//! (`talos_execution_repository::stale_sweep`).
//!
//! Gated on `TALOS_TEST_DATABASE_URL` (skips when unset):
//! ```sh
//! export TALOS_TEST_DATABASE_URL="postgres://talos:talos@localhost:5432/talos"
//! cargo test -p talos-execution-repository --test stale_execution_sweep
//! ```
//!
//! # What these pin, and why a unit test could not
//!
//! The property under test is a SQL property: "the last node that started and
//! never reported" is a `LATERAL` over `execution_events`, and "the row may
//! have finalized between the read and the write" is a status-guarded `UPDATE`.
//! Only a database can evaluate either.
//!
//! The wording itself is unit-tested in `src/stale_sweep.rs`. What is proved
//! HERE is that the evidence those words are built from is actually read off
//! disk correctly, and that the terminal row ends up carrying them.
//!
//! `list_stale_running_executions` is deliberately fleet-wide (the sweep is),
//! so each test neutralises every OTHER running row by moving its `started_at`
//! to now — the same non-destructive isolation `crash_recovery.rs` uses.

use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres};
use std::sync::LazyLock;
use talos_execution_repository::stale_sweep::{describe_stale_execution, STALE_SWEEP_BATCH};
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
        .max_connections(4)
        .connect(url)
        .await
        .expect("connect")
}

struct Seed {
    exec_id: Uuid,
    wf_id: Uuid,
    user_id: Uuid,
}

/// A `running` execution `age_minutes` old, owned by a workflow whose graph
/// declares one node with `label`. The node's graph id is a UUID string, so
/// `engine_node_uuid` maps it to itself — which lets the test write
/// `execution_events.node_id` directly without re-deriving the engine's
/// hashing (check 71: a private copy of that derivation fails silently).
async fn seed(pool: &Pool<Postgres>, age_minutes: i64, node: Uuid, label: &str) -> Seed {
    let user_id = Uuid::new_v4();
    let wf_id = Uuid::new_v4();
    let exec_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id,email,password_hash,name) VALUES ($1,$2,'x','ss')")
        .bind(user_id)
        .bind(format!("ss-{}@test.invalid", user_id.simple()))
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO actors (id,user_id,name,max_capability_world,is_default) \
         VALUES (gen_random_uuid(),$1,'Default','network-node',true)",
    )
    .bind(user_id)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO workflows (id,user_id,name,module_uri,graph_json) VALUES ($1,$2,'ss-wf','mod://x',$3)")
        .bind(wf_id)
        .bind(user_id)
        .bind(format!(
            r#"{{"nodes":[{{"id":"{node}","data":{{"label":"{label}"}}}}]}}"#
        ))
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
    Seed {
        exec_id,
        wf_id,
        user_id,
    }
}

/// Append one event `minutes_ago` in the past.
async fn event(pool: &Pool<Postgres>, exec: Uuid, kind: &str, node: Uuid, minutes_ago: i64) {
    sqlx::query(
        "INSERT INTO execution_events (execution_id,event_type,node_id,status,created_at) \
         VALUES ($1,$2,$3,'Running', NOW() - make_interval(mins => $4::int))",
    )
    .bind(exec)
    .bind(kind)
    .bind(node)
    .bind(minutes_ago)
    .execute(pool)
    .await
    .unwrap();
}

/// Make `keep` the only row the fleet-wide sweep can see.
async fn only_stale(pool: &Pool<Postgres>, keep: Uuid) {
    sqlx::query(
        "UPDATE workflow_executions SET started_at = NOW() WHERE status = 'running' AND id != $1",
    )
    .bind(keep)
    .execute(pool)
    .await
    .unwrap();
}

async fn row(pool: &Pool<Postgres>, id: Uuid) -> (String, Option<String>) {
    sqlx::query_as("SELECT status, error_message FROM workflow_executions WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn cleanup(pool: &Pool<Postgres>, s: &Seed) {
    let _ = sqlx::query("DELETE FROM execution_events WHERE execution_id = $1")
        .bind(s.exec_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM workflow_executions WHERE workflow_id = $1")
        .bind(s.wf_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM workflows WHERE id = $1")
        .bind(s.wf_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(s.user_id)
        .execute(pool)
        .await;
}

/// The 2026-08-31 `pa-inbox-organizer-work` shape, end to end.
///
/// A run whose third node started and never reported, whose controller process
/// then went away, closed an hour later by the sweep. The record it is left
/// with must say the run was ORPHANED — not that it "ran too long", which is
/// what the pre-2026-09 constant string said about an execution that had in
/// fact run for five seconds.
///
/// Red without the fix: the sweep wrote
/// `'Auto-cleaned: execution stale (running > configured threshold)'` for every
/// row, so `contains("Orphaned")` and `contains(label)` both fail.
#[tokio::test]
async fn an_execution_orphaned_by_a_restart_is_recorded_as_orphaned() {
    let Some(url) = db_url() else { return };
    let _g = SERIAL.lock().await;
    let pool = connect(&url).await;
    let node = Uuid::new_v4();
    let s = seed(&pool, 63, node, "classify_work").await;
    only_stale(&pool, s.exec_id).await;
    // Node started 63 minutes ago and never reported — the whole point.
    event(&pool, s.exec_id, "node_started", node, 63).await;

    let repo = ExecutionRepository::new(pool.clone());
    // The controller process took over the sweep AFTER that last activity.
    let sweep_epoch = repo.sweep_ownership_epoch().await.unwrap();

    let candidates = repo
        .list_stale_running_executions(60, STALE_SWEEP_BATCH)
        .await
        .unwrap();
    let ev = candidates
        .iter()
        .find(|c| c.id == s.exec_id)
        .expect("the stale row must be a sweep candidate");
    assert_eq!(ev.in_flight_node, Some(node));
    assert!(ev.in_flight_node_started_at.is_some());
    assert!(ev.last_event_at.is_some());
    assert!(
        ev.graph_json
            .as_deref()
            .is_some_and(|g| g.contains("classify_work")),
        "the graph must come back so the caller can resolve the node's label"
    );

    let msg = describe_stale_execution(ev, Some(sweep_epoch), Some("classify_work"));
    assert!(repo.fail_stale_execution(s.exec_id, &msg).await.unwrap());

    let (status, stored) = row(&pool, s.exec_id).await;
    let stored = stored.expect("a closed row must carry a reason");
    assert_eq!(status, "failed");
    assert!(
        stored.contains("Orphaned, not overrunning"),
        "the record must name the cause, not the sweep's own rule: {stored}"
    );
    assert!(
        stored.contains("Last node to start: classify_work"),
        "the record must name the node that was holding the run: {stored}"
    );
    assert!(
        stored.contains("execution stale"),
        "the downstream error classifier keys the `stale` class off this phrase: {stored}"
    );

    cleanup(&pool, &s).await;
}

/// The in-flight node is the LAST one to start, not the last one mentioned:
/// a node that started and completed must not be blamed.
#[tokio::test]
async fn the_named_node_is_the_one_that_never_reported() {
    let Some(url) = db_url() else { return };
    let _g = SERIAL.lock().await;
    let pool = connect(&url).await;
    let done = Uuid::new_v4();
    let stuck = Uuid::new_v4();
    let s = seed(&pool, 70, stuck, "llm").await;
    only_stale(&pool, s.exec_id).await;
    event(&pool, s.exec_id, "node_started", done, 70).await;
    event(&pool, s.exec_id, "node_completed", done, 69).await;
    event(&pool, s.exec_id, "node_started", stuck, 69).await;

    let repo = ExecutionRepository::new(pool.clone());
    let candidates = repo
        .list_stale_running_executions(60, STALE_SWEEP_BATCH)
        .await
        .unwrap();
    let ev = candidates.iter().find(|c| c.id == s.exec_id).unwrap();
    assert_eq!(ev.in_flight_node, Some(stuck));

    cleanup(&pool, &s).await;
}

/// A row that reached a real terminal status between the sweep's read and its
/// write keeps that outcome. The pre-2026-09 bulk `UPDATE` had no read and so
/// resolved this race by winning; the guarded per-row write resolves it the
/// other way, which is the correct direction — a genuine finalize beats the
/// janitor.
#[tokio::test]
async fn a_row_that_finalized_first_is_left_alone() {
    let Some(url) = db_url() else { return };
    let _g = SERIAL.lock().await;
    let pool = connect(&url).await;
    let node = Uuid::new_v4();
    let s = seed(&pool, 90, node, "compose").await;
    only_stale(&pool, s.exec_id).await;

    let repo = ExecutionRepository::new(pool.clone());
    let candidates = repo
        .list_stale_running_executions(60, STALE_SWEEP_BATCH)
        .await
        .unwrap();
    assert!(candidates.iter().any(|c| c.id == s.exec_id));

    // The engine finally returned, between the read and the write.
    sqlx::query(
        "UPDATE workflow_executions SET status = 'completed', completed_at = NOW() WHERE id = $1",
    )
    .bind(s.exec_id)
    .execute(&pool)
    .await
    .unwrap();

    assert!(
        !repo
            .fail_stale_execution(s.exec_id, "should not land")
            .await
            .unwrap(),
        "the guarded write must report that it did not apply"
    );
    let (status, msg) = row(&pool, s.exec_id).await;
    assert_eq!(status, "completed");
    assert!(msg.is_none(), "{msg:?}");

    cleanup(&pool, &s).await;
}

/// `make_interval(mins => -N)` flips the predicate to `started_at < NOW() +
/// INTERVAL`, which matches every running execution on the platform. Same
/// refusal as the user-scoped siblings — a `STALE_EXECUTION_MINUTES=0` typo is
/// the highest-blast-radius env footgun in this file's neighbourhood.
#[tokio::test]
async fn a_non_positive_threshold_sweeps_nothing() {
    let Some(url) = db_url() else { return };
    let _g = SERIAL.lock().await;
    let pool = connect(&url).await;
    let node = Uuid::new_v4();
    let s = seed(&pool, 90, node, "x").await;

    let repo = ExecutionRepository::new(pool.clone());
    for bad in [0i64, -1, -60] {
        assert!(
            repo.list_stale_running_executions(bad, STALE_SWEEP_BATCH)
                .await
                .unwrap()
                .is_empty(),
            "threshold {bad} must match nothing"
        );
    }
    assert_eq!(row(&pool, s.exec_id).await.0, "running");

    cleanup(&pool, &s).await;
}
