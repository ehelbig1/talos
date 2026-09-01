//! `execution_events.duration_ms` must mean what the emitter measured.
//!
//! The engine times every node dispatch with `std::time::Instant`
//! (CLOCK_MONOTONIC) — `run_scheduler_loop` parks one in `node_start_times`
//! before dispatch and reads `elapsed()` when the future resolves — and
//! `dispatch_subworkflow` does the same around a nested run. Neither value
//! reached this table: `compute_execution_event_duration()`, a BEFORE INSERT
//! trigger, derived `NEW.created_at - <matching node_started>.created_at`
//! instead, a WALL-CLOCK subtraction. On a host that suspends those are not
//! the same measurement. Measured on the live stack over the 2 378 executions
//! whose event count matches their cost-rollup count exactly: 24 319 076 ms of
//! wall clock against 8 707 280 ms of monotonic, 2.79x in aggregate and 17x on
//! the worst execution (5 618 304 ms recorded for 324 880 ms of work).
//!
//! These tests drive the REAL production writer (`PostgresEventSink`, the only
//! `EventSink` impl that writes this table) against a real Postgres carrying
//! the real trigger. A pure-Rust test cannot cover this: the discarding was
//! done by the DATABASE, so the only thing that can fail here is the round
//! trip.
//!
//! Three directions are pinned, because any one alone leaves a live defect:
//!
//! 1. A supplied duration must SURVIVE and be labelled `'monotonic'` — the bug.
//! 2. An unsupplied duration must still be DERIVED and labelled `'wallclock'`
//!    — `emit_node_lifecycle_events` (23 call sites, ~128 rows/day) and the
//!    four in-process evaluation paths measure nothing and would otherwise
//!    silently start writing NULL.
//! 3. The `0` UNKNOWN sentinel must NOT become a stored `0 ms`. This is the
//!    trap: `NodeCompletionContext::wall_time_ms` documents `0` as "the engine
//!    didn't record a start time", and a genuine sub-millisecond `0` is
//!    already reachable in this column (the trigger's `::bigint` cast
//!    truncates; 19 such rows existed when this was written, with real gaps of
//!    0.307–0.490 ms). A sentinel stored as a measurement would be
//!    indistinguishable from those.

mod common;

use talos_workflow_engine_core::{EventSink, NodeEventWrite};
use uuid::Uuid;

/// Seed the FK chain an `execution_events` row needs, then insert a
/// `node_started` row backdated by `age_secs`.
///
/// The backdating is what makes the two clocks disagree by a KNOWABLE amount:
/// the trigger's wall-clock derivation must land near `age_secs * 1000`, and a
/// monotonic value supplied by the emitter must be nowhere near it. Without it
/// both readings would be a few milliseconds and the test would pass against
/// the broken trigger too.
async fn seed_started_event(pool: &sqlx::Pool<sqlx::Postgres>, age_secs: i64) -> (Uuid, Uuid) {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) \
         VALUES ($1, $2, 'x', true)",
    )
    .bind(user)
    .bind(format!("{user}@ee-duration.test"))
    .execute(pool)
    .await
    .expect("seed user");

    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name) VALUES ($1, $2, $3)")
        .bind(actor)
        .bind(user)
        .bind(format!("actor-{actor}"))
        .execute(pool)
        .await
        .expect("seed actor");

    let workflow = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, module_uri, graph_json) \
         VALUES ($1, $2, $3, 'test://none', '{}'::jsonb)",
    )
    .bind(workflow)
    .bind(user)
    .bind(format!("wf-{workflow}"))
    .execute(pool)
    .await
    .expect("seed workflow");

    let exec = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflow_executions \
         (id, workflow_id, user_id, actor_id, status) \
         VALUES ($1, $2, $3, $4, 'running')",
    )
    .bind(exec)
    .bind(workflow)
    .bind(user)
    .bind(actor)
    .execute(pool)
    .await
    .expect("seed workflow_execution");

    // The `node_started` the trigger will look up. Backdated so the
    // wall-clock derivation is large and unmistakable.
    let node = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO execution_events \
         (execution_id, event_type, node_id, status, created_at) \
         VALUES ($1, 'node_started', $2, 'Running', \
                 NOW() - make_interval(secs => $3::float8))",
    )
    .bind(exec)
    .bind(node)
    .bind(age_secs as f64)
    .execute(pool)
    .await
    .expect("seed node_started event");

    (exec, node)
}

async fn read_completion(
    pool: &sqlx::Pool<sqlx::Postgres>,
    exec: Uuid,
    event_type: &str,
) -> (Option<i64>, Option<String>) {
    sqlx::query_as::<_, (Option<i64>, Option<String>)>(
        "SELECT duration_ms, duration_source FROM execution_events \
         WHERE execution_id = $1 AND event_type = $2",
    )
    .bind(exec)
    .bind(event_type)
    .fetch_one(pool)
    .await
    .expect("read back the completion event")
}

/// THE BUG. A monotonic duration supplied by the emitter must reach the column
/// intact, not be replaced by the trigger's wall-clock subtraction.
///
/// Mutation check: revert `compute_execution_event_duration` to its
/// unconditional form and this fails with the nap value (`3_600_000`-ish)
/// against the supplied `1234`.
#[tokio::test]
async fn a_supplied_monotonic_duration_survives_the_trigger() {
    let (pool, _db) = common::isolated_db_pool().await;
    let (exec, node) = seed_started_event(&pool, 3600).await;

    let sink = talos_engine::event_sink::PostgresEventSink::new(pool.clone());
    sink.emit(NodeEventWrite {
        execution_id: exec,
        event_type: "node_completed".to_string(),
        node_id: Some(node),
        status: "Completed".to_string(),
        log_message: None,
        iteration_index: None,
        error_class: None,
        duration_ms: NodeEventWrite::monotonic_ms(1234),
    })
    .await;

    let (duration, source) = read_completion(&pool, exec, "node_completed").await;
    assert_eq!(
        duration,
        Some(1234),
        "the emitter's monotonic measurement must survive; a value near \
         3_600_000 means the trigger overwrote it with the wall-clock gap"
    );
    assert_eq!(source.as_deref(), Some("monotonic"));
}

/// The failure path carries the same measurement and must be labelled too —
/// coverage is symmetric, not half. A node that fails after 110 s of retries
/// is a 110 s node.
#[tokio::test]
async fn a_supplied_duration_survives_on_the_failure_event_too() {
    let (pool, _db) = common::isolated_db_pool().await;
    let (exec, node) = seed_started_event(&pool, 3600).await;

    let sink = talos_engine::event_sink::PostgresEventSink::new(pool.clone());
    sink.emit(NodeEventWrite {
        execution_id: exec,
        event_type: "node_failed".to_string(),
        node_id: Some(node),
        status: "Failed".to_string(),
        log_message: Some("Job failed after 3 attempts".to_string()),
        iteration_index: None,
        error_class: None,
        duration_ms: NodeEventWrite::monotonic_ms(110_022),
    })
    .await;

    let (duration, source) = read_completion(&pool, exec, "node_failed").await;
    assert_eq!(duration, Some(110_022));
    assert_eq!(source.as_deref(), Some("monotonic"));
}

/// THE OTHER HALF OF CALLER-WINS. Emitters that measured nothing must keep the
/// derivation — `emit_node_lifecycle_events` writes ~128 rows/day this way and
/// would otherwise start writing NULL, which is a strictly worse trace than a
/// wall-clock number that labels itself.
#[tokio::test]
async fn an_unsupplied_duration_is_still_derived_and_labelled_wallclock() {
    let (pool, _db) = common::isolated_db_pool().await;
    let (exec, node) = seed_started_event(&pool, 3600).await;

    let sink = talos_engine::event_sink::PostgresEventSink::new(pool.clone());
    sink.emit(NodeEventWrite {
        execution_id: exec,
        event_type: "node_completed".to_string(),
        node_id: Some(node),
        status: "Completed".to_string(),
        log_message: Some("collected 2 branch outputs into items array".to_string()),
        iteration_index: None,
        error_class: None,
        duration_ms: None,
    })
    .await;

    let (duration, source) = read_completion(&pool, exec, "node_completed").await;
    let ms = duration.expect("the trigger must still derive a duration");
    assert!(
        (3_590_000..=3_610_000).contains(&ms),
        "expected the wall-clock gap (~3_600_000 ms), got {ms}"
    );
    assert_eq!(source.as_deref(), Some("wallclock"));
}

/// THE TRAP. The engine's `0` means "no start time was recorded", not
/// "instantaneous" — four sites pass it literally. It must fall through to the
/// derivation rather than being stored as a real-looking `0 ms`, which would
/// be indistinguishable from the genuine sub-millisecond zeros this column
/// already contains.
#[tokio::test]
async fn the_zero_sentinel_never_becomes_a_stored_measurement() {
    let (pool, _db) = common::isolated_db_pool().await;
    let (exec, node) = seed_started_event(&pool, 3600).await;

    let sink = talos_engine::event_sink::PostgresEventSink::new(pool.clone());
    sink.emit(NodeEventWrite {
        execution_id: exec,
        event_type: "node_completed".to_string(),
        node_id: Some(node),
        status: "Completed".to_string(),
        log_message: None,
        iteration_index: None,
        // Exactly what `handle_node_success` passes when the engine
        // recorded no start time for the node.
        duration_ms: NodeEventWrite::monotonic_ms(0),
        error_class: None,
    })
    .await;

    let (duration, source) = read_completion(&pool, exec, "node_completed").await;
    assert_ne!(
        duration,
        Some(0),
        "a 0 sentinel must never be stored as a 0 ms measurement — it is \
         indistinguishable from a genuine sub-millisecond duration"
    );
    assert_eq!(
        source.as_deref(),
        Some("wallclock"),
        "the unknown sentinel must be handed to the derivation, and the \
         derivation must say so"
    );
}

/// A completion with NO matching `node_started` must not be labelled at all.
/// The `SELECT ... INTO` leaves `duration_ms` NULL in that case, and stamping
/// `'wallclock'` beside a NULL would claim a measurement that does not exist.
///
/// This is reachable in production: `node_started` is emitted fire-and-forget
/// on several paths while `node_completed` is awaited, so the ordering can
/// invert under a slow sink, and the seeded scheduler can resume mid-graph.
#[tokio::test]
async fn a_completion_with_no_start_event_is_left_unlabelled() {
    let (pool, _db) = common::isolated_db_pool().await;
    let (exec, _node) = seed_started_event(&pool, 3600).await;

    // A DIFFERENT node id — nothing in the table opened a span for it.
    let orphan = Uuid::new_v4();
    let sink = talos_engine::event_sink::PostgresEventSink::new(pool.clone());
    sink.emit(NodeEventWrite {
        execution_id: exec,
        event_type: "node_completed".to_string(),
        node_id: Some(orphan),
        status: "Completed".to_string(),
        log_message: None,
        iteration_index: None,
        error_class: None,
        duration_ms: None,
    })
    .await;

    let (duration, source) = read_completion(&pool, exec, "node_completed").await;
    assert_eq!(duration, None, "no start event means no derivable duration");
    assert_eq!(
        source, None,
        "a NULL duration must carry a NULL source — labelling it 'wallclock' \
         would describe a measurement that was never made"
    );
}

/// The CHECK constraint is the backstop for the binding rule: the label is
/// bound from the same parameter as the value, so a third spelling can only
/// arrive from a future writer that ignored the rule.
#[tokio::test]
async fn an_unknown_duration_source_is_rejected_by_the_database() {
    let (pool, _db) = common::isolated_db_pool().await;
    let (exec, node) = seed_started_event(&pool, 60).await;

    let res = sqlx::query(
        "INSERT INTO execution_events \
         (execution_id, event_type, node_id, status, duration_ms, duration_source) \
         VALUES ($1, 'node_completed', $2, 'Completed', 5, 'guessed')",
    )
    .bind(exec)
    .bind(node)
    .execute(&pool)
    .await;

    assert!(
        res.is_err(),
        "duration_source must be constrained to the two known clocks"
    );
}
