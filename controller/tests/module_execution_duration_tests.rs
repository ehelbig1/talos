//! `module_executions.duration_ms` must mean what the writer measured.
//!
//! The engine times every node dispatch with `std::time::Instant`
//! (CLOCK_MONOTONIC) and binds the result into `record_completed`'s UPDATE.
//! `calculate_module_execution_duration()`, a BEFORE UPDATE trigger, used to
//! overwrite that unconditionally with `completed_at - started_at` — a
//! WALL-CLOCK interval. On a host that suspends the two are not the same
//! measurement: on the live stack a node recorded at 5 614 097 ms had consumed
//! 105 483 ms of monotonic time, the other 94 minutes being sleep.
//!
//! These tests drive the REAL production writer (`PostgresModuleExecutionStore`,
//! the only non-test `ModuleExecutionStore` impl in the workspace) against a
//! real Postgres carrying the real trigger. A pure-Rust test cannot cover this:
//! the discarding was done by the DATABASE, so the only thing that can fail
//! here is the round trip.
//!
//! Both directions are pinned, because either one alone leaves a live defect:
//! a supplied duration must SURVIVE (the bug), and an unsupplied one must still
//! be DERIVED (the twelve writers — the stuck-execution sweep, the six
//! sibling-cancellation sites, `ModuleExecutionService`'s complete/fail/timeout
//! paths — that pass no duration and would otherwise silently start writing
//! NULL).

mod common;

use talos_workflow_engine_core::ModuleExecutionStore;
use uuid::Uuid;

/// Seed the FK chain a `module_executions` row needs, and open one row in
/// `'running'` with `started_at` a fixed distance in the past. That backdating
/// is what makes the two clocks disagree by a knowable amount: the wall-clock
/// derivation must land near `age_secs * 1000`, and a monotonic value supplied
/// by the caller must be nowhere near it.
async fn seed_running_row(
    pool: &sqlx::Pool<sqlx::Postgres>,
    age_secs: i64,
) -> (Uuid, Uuid, Uuid, Uuid) {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) \
         VALUES ($1, $2, 'x', true)",
    )
    .bind(user)
    .bind(format!("{user}@me-duration.test"))
    .execute(pool)
    .await
    .expect("seed user");

    let module = Uuid::new_v4();
    sqlx::query("INSERT INTO modules (id, name, kind) VALUES ($1, $2, 'sandbox')")
        .bind(module)
        .bind(format!("m-{module}"))
        .execute(pool)
        .await
        .expect("seed module");

    // actor_id is NOT NULL post actor-universalization (#307–#317).
    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name) VALUES ($1, $2, $3)")
        .bind(actor)
        .bind(user)
        .bind(format!("actor-{actor}"))
        .execute(pool)
        .await
        .expect("seed actor");

    let exec = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO module_executions \
         (id, module_id, user_id, actor_id, status, trigger_type, started_at) \
         VALUES ($1, $2, $3, $4, 'running', 'manual', NOW() - make_interval(secs => $5::float8))",
    )
    .bind(exec)
    .bind(module)
    .bind(user)
    .bind(actor)
    .bind(age_secs as f64)
    .execute(pool)
    .await
    .expect("seed running module_execution");

    (user, module, actor, exec)
}

async fn read_duration(
    pool: &sqlx::Pool<sqlx::Postgres>,
    exec: Uuid,
) -> (Option<i32>, Option<String>) {
    sqlx::query_as::<_, (Option<i32>, Option<String>)>(
        "SELECT duration_ms, duration_source FROM module_executions WHERE id = $1",
    )
    .bind(exec)
    .fetch_one(pool)
    .await
    .expect("read back the finalized row")
}

/// THE REGRESSION. The engine measured 1 234 ms of monotonic work on a row
/// whose `started_at` is an hour in the past; the stored value must be 1 234,
/// not 3 600 000.
///
/// Pinning the exact value rather than a bound is deliberate: a trigger that
/// merely *clamped* the wall-clock derivation would satisfy any inequality
/// while still discarding the measurement.
#[tokio::test]
async fn a_caller_supplied_duration_survives_the_trigger() {
    let (pool, _db) = common::isolated_db_pool().await;
    let (_user, _module, _actor, exec) = seed_running_row(&pool, 3600).await;

    let store =
        talos_engine::module_execution_store::PostgresModuleExecutionStore::new(pool.clone());
    store
        .record_completed(
            exec,
            "completed",
            &serde_json::json!({"ok": true}),
            Some(1234),
            None,
        )
        .await
        .expect("record_completed");

    let (duration, source) = read_duration(&pool, exec).await;
    assert_eq!(
        duration,
        Some(1234),
        "the monotonic measurement the engine passed must be what is stored; \
         a value near 3_600_000 means the BEFORE UPDATE trigger overwrote it \
         with completed_at - started_at again"
    );
    assert_eq!(
        source.as_deref(),
        Some("monotonic"),
        "a surviving caller value must be LABELLED as such — an unlabelled row \
         is indistinguishable from the wall-clock rows the sweep writes"
    );
}

/// THE OTHER DIRECTION. A writer with no measurement passes `None`, and the
/// trigger must still derive one — otherwise narrowing it silently turns
/// `duration_ms` NULL for the stuck-execution sweep and every sibling-cancel
/// path, none of which supplies a duration.
#[tokio::test]
async fn an_unsupplied_duration_is_still_derived_and_labelled_wallclock() {
    let (pool, _db) = common::isolated_db_pool().await;
    let (_user, _module, _actor, exec) = seed_running_row(&pool, 120).await;

    let store =
        talos_engine::module_execution_store::PostgresModuleExecutionStore::new(pool.clone());
    store
        .record_completed(exec, "failed", &serde_json::Value::Null, None, Some("boom"))
        .await
        .expect("record_completed");

    let (duration, source) = read_duration(&pool, exec).await;
    let d = duration.expect("an unsupplied duration must still be derived, not left NULL");
    assert!(
        (110_000..=130_000).contains(&d),
        "expected ~120 000 ms derived from completed_at - started_at, got {d}"
    );
    assert_eq!(
        source.as_deref(),
        Some("wallclock"),
        "a derived duration must say so: it over-counts by any host suspend, \
         and a reader aggregating it alongside monotonic rows needs to know"
    );
}

/// Provenance is not decorative — it is the only thing that separates the two
/// meanings now living in one column, so it must be legible from SQL alone.
/// This is the query an operator asking "how long does this node normally
/// take" is expected to write.
#[tokio::test]
async fn monotonic_rows_are_selectable_apart_from_wallclock_rows() {
    let (pool, _db) = common::isolated_db_pool().await;
    let store =
        talos_engine::module_execution_store::PostgresModuleExecutionStore::new(pool.clone());

    let (_u1, _m1, _a1, measured) = seed_running_row(&pool, 7200).await;
    store
        .record_completed(
            measured,
            "completed",
            &serde_json::Value::Null,
            Some(42),
            None,
        )
        .await
        .expect("record measured");

    let (_u2, _m2, _a2, swept) = seed_running_row(&pool, 7200).await;
    store
        .record_completed(
            swept,
            "timeout",
            &serde_json::Value::Null,
            None,
            Some("stuck"),
        )
        .await
        .expect("record swept");

    let trustworthy: Vec<i32> = sqlx::query_scalar(
        "SELECT duration_ms FROM module_executions \
         WHERE duration_source = 'monotonic' ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .expect("select monotonic rows");

    assert_eq!(
        trustworthy,
        vec![42],
        "filtering on duration_source must yield exactly the measured row — \
         the swept row's 2-hour wall-clock number is the suspend artifact this \
         filter exists to exclude"
    );
}

/// The CHECK constraint is what stops a third, undocumented meaning appearing
/// in the column later. Without it `duration_source` is free text and the
/// filter above quietly stops matching.
#[tokio::test]
async fn duration_source_rejects_values_outside_the_documented_pair() {
    let (pool, _db) = common::isolated_db_pool().await;
    let (_user, _module, _actor, exec) = seed_running_row(&pool, 10).await;

    let err = sqlx::query("UPDATE module_executions SET duration_source = 'guess' WHERE id = $1")
        .bind(exec)
        .execute(&pool)
        .await
        .expect_err("an undocumented duration_source must be refused by the CHECK");
    assert!(
        err.to_string().contains("duration_source"),
        "expected the duration_source CHECK to name itself, got: {err}"
    );
}

/// A row open longer than `integer` can hold milliseconds (24.8 days) must
/// still be closable.
///
/// The pre-fix trigger computed `EXTRACT(EPOCH …) * 1000` unguarded into an
/// `integer` column, so it raised `integer out of range` INSIDE the trigger and
/// failed the whole UPDATE — the row could never be closed. That is not
/// hypothetical: measured on the live database on 2026-08-31 there were 7 open
/// rows, the oldest 43.3 days, and ONE already past the limit, so the next
/// `cleanup_stuck_executions` sweep to touch it would have errored.
///
/// The writers that depend on this derivation are exactly the ones that meet
/// such rows (the stuck-execution sweep, the sibling cancels, the scheduler
/// timeout path), which is why the clamp lives in the derivation branch rather
/// than being pushed onto callers.
#[tokio::test]
async fn a_row_open_past_the_integer_limit_is_still_closable() {
    let (pool, _db) = common::isolated_db_pool().await;
    // 60 days: comfortably past the 24.8-day integer ceiling.
    let (_user, _module, _actor, exec) = seed_running_row(&pool, 60 * 86_400).await;

    sqlx::query(
        "UPDATE module_executions SET status = 'failed', completed_at = NOW() WHERE id = $1",
    )
    .bind(exec)
    .execute(&pool)
    .await
    .expect("a 60-day-old row must still be closable");

    let (ms, src): (Option<i32>, Option<String>) =
        sqlx::query_as("SELECT duration_ms, duration_source FROM module_executions WHERE id = $1")
            .bind(exec)
            .fetch_one(&pool)
            .await
            .expect("read back");

    assert_eq!(
        ms,
        Some(i32::MAX),
        "the derived duration must saturate, not overflow"
    );
    assert_eq!(
        src.as_deref(),
        Some("wallclock"),
        "a saturated value is still a derived wall-clock one, and must say so"
    );
}
