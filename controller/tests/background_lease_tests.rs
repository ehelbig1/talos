//! The fleet lease for periodic background loops (`talos-background-lease`),
//! against a real Postgres: the property under test is what TWO replicas —
//! two pools on one database — are told by one atomic statement.
mod common;

use std::time::Duration;
use talos_background_lease::{claim_tick, try_claim, LeaseOutcome};
use talos_task_supervision::BackgroundTask;

const PERIOD: Duration = Duration::from_secs(300);
const TASK: BackgroundTask = BackgroundTask::SlaBreachMonitor;

/// A second pool on the same database: the second controller replica.
async fn second_replica(pool: &sqlx::Pool<sqlx::Postgres>) -> sqlx::Pool<sqlx::Postgres> {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect_with((*pool.connect_options()).clone())
        .await
        .expect("second pool")
}

async fn expire(pool: &sqlx::Pool<sqlx::Postgres>, task: BackgroundTask) {
    sqlx::query("UPDATE background_task_leases SET leased_until = now() - interval '1 second' WHERE task = $1")
        .bind(task.as_str())
        .execute(pool)
        .await
        .expect("expire");
}

#[tokio::test]
async fn one_replica_holds_a_period_and_the_other_is_told_so() {
    let (a, _db) = common::isolated_db_pool().await;
    let b = second_replica(&a).await;

    assert_eq!(
        try_claim(&a, TASK, PERIOD).await.expect("a"),
        LeaseOutcome::Claimed
    );
    // The other replica ticks two minutes later, with no lock held by anyone:
    // it must still be refused. This is the case an advisory lock gets wrong.
    assert_eq!(
        try_claim(&b, TASK, PERIOD).await.expect("b"),
        LeaseOutcome::HeldElsewhere
    );
    // Nor may the holder run twice inside its own period.
    assert_eq!(
        try_claim(&a, TASK, PERIOD).await.expect("a again"),
        LeaseOutcome::HeldElsewhere
    );

    // Leases are per task.
    assert_eq!(
        try_claim(&b, BackgroundTask::SlaDegradationMonitor, PERIOD)
            .await
            .expect("other task"),
        LeaseOutcome::Claimed
    );
}

#[tokio::test]
async fn a_lease_that_ran_out_is_taken_over_by_whoever_ticks_next() {
    let (a, _db) = common::isolated_db_pool().await;
    let b = second_replica(&a).await;
    assert_eq!(
        try_claim(&a, TASK, PERIOD).await.expect("a"),
        LeaseOutcome::Claimed
    );
    let first_claimed_at: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT claimed_at FROM background_task_leases WHERE task = $1")
            .bind(TASK.as_str())
            .fetch_one(&a)
            .await
            .expect("claimed_at");

    // The holder died, or simply its period ended.
    expire(&a, TASK).await;
    assert_eq!(
        try_claim(&b, TASK, PERIOD).await.expect("b"),
        LeaseOutcome::Claimed
    );
    assert_eq!(
        try_claim(&a, TASK, PERIOD).await.expect("a"),
        LeaseOutcome::HeldElsewhere
    );

    let (rows, claimed_at): (i64, chrono::DateTime<chrono::Utc>) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM background_task_leases WHERE task = $1), claimed_at \
         FROM background_task_leases WHERE task = $1",
    )
    .bind(TASK.as_str())
    .fetch_one(&a)
    .await
    .expect("row");
    assert_eq!(rows, 1, "one row per task, taken over in place");
    assert!(
        claimed_at > first_claimed_at,
        "a takeover restamps claimed_at"
    );
}

#[tokio::test]
async fn the_lease_runs_on_the_database_clock_for_the_period_minus_its_slack() {
    let (a, _db) = common::isolated_db_pool().await;
    assert_eq!(
        try_claim(&a, TASK, PERIOD).await.expect("a"),
        LeaseOutcome::Claimed
    );
    let remaining: f64 = sqlx::query_scalar(
        "SELECT EXTRACT(EPOCH FROM (leased_until - now()))::float8 \
         FROM background_task_leases WHERE task = $1",
    )
    .bind(TASK.as_str())
    .fetch_one(&a)
    .await
    .expect("remaining");
    // 300 s period → 270 s lease; a few seconds of tolerance for the test itself.
    assert!(
        (260.0..=270.0).contains(&remaining),
        "remaining = {remaining}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sixteen_replicas_ticking_at_once_produce_exactly_one_holder() {
    let (a, _db) = common::isolated_db_pool().await;
    let b = second_replica(&a).await;
    let mut tasks = Vec::new();
    for i in 0..16 {
        let pool = if i % 2 == 0 { a.clone() } else { b.clone() };
        tasks.push(tokio::spawn(async move {
            try_claim(&pool, TASK, PERIOD).await.expect("claim")
        }));
    }
    let mut claimed = 0;
    for t in tasks {
        if t.await.expect("join") == LeaseOutcome::Claimed {
            claimed += 1;
        }
    }
    assert_eq!(claimed, 1);
}

fn claims(outcome: &str) -> f64 {
    prometheus::default_registry()
        .gather()
        .iter()
        .filter(|f| f.name() == "talos_background_lease_claims_total")
        .flat_map(|f| f.get_metric().iter())
        .filter(|m| {
            let has = |k: &str, v: &str| {
                m.get_label()
                    .iter()
                    .any(|l| l.name() == k && l.value() == v)
            };
            has("task", BackgroundTask::SlaDegradationMonitor.as_str()) && has("outcome", outcome)
        })
        .map(|m| m.get_counter().value())
        .sum()
}

/// The loop-side form. One test, because the counter is process-global.
#[tokio::test]
async fn a_tick_runs_only_on_a_claim_and_every_attempt_is_counted() {
    // Registered once per process; a duplicate registration is an Err we ignore.
    let _ = talos_background_lease::register_metrics(
        prometheus::default_registry(),
        &[BackgroundTask::SlaDegradationMonitor],
    );
    let task = BackgroundTask::SlaDegradationMonitor;
    let (a, _db) = common::isolated_db_pool().await;
    let b = second_replica(&a).await;
    let (c0, h0, e0) = (claims("claimed"), claims("held"), claims("error"));

    assert!(
        claim_tick(&a, task, PERIOD).await,
        "the first replica runs its tick"
    );
    assert!(
        !claim_tick(&b, task, PERIOD).await,
        "the second replica skips"
    );
    assert_eq!(
        (
            claims("claimed") - c0,
            claims("held") - h0,
            claims("error") - e0
        ),
        (1.0, 1.0, 0.0)
    );

    // A lease that cannot be read is NOT a claim: skipping is the safe
    // direction, because acting would be every replica acting at once.
    let dead = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(250))
        .connect_lazy("postgres://127.0.0.1:1/talos_never_connects")
        .expect("lazy pool");
    assert!(!claim_tick(&dead, task, PERIOD).await);
    assert_eq!(claims("error") - e0, 1.0);
    assert_eq!(
        claims("claimed") - c0,
        1.0,
        "an unreadable lease is not counted as a claim"
    );
}
