//! A backlog that arrives WITHOUT a boot is still a backlog.
//!
//! The scheduler's tighter startup ceiling (`SCHEDULER_STARTUP_MAX_CONCURRENT`,
//! default 4) applied to exactly one batch: the one the FIRST poll after a
//! controller boot found due. The M6 comment above the steady semaphore names
//! the case that misses in its first sentence — "controller downtime OR a
//! clock catch-up" — and on 2026-09-10 the second one happened: the host was
//! suspended 10:56–12:06 UTC (every Prometheus job, Prometheus included, has
//! no samples in that window, and the dispatch counter climbed 17 → 28 with no
//! reset, so the process never restarted). The controller resumed with its
//! boot flag already spent, one poll claimed TEN schedules — daily crons 53
//! minutes late, a `*/15` cron 65 minutes late — labelled every one `steady`,
//! and drained them under the 16-wide steady ceiling that had not bound on the
//! 2026-08-10 herd of 15 either. Six carried LLM nodes into a single-slot
//! Ollama; two hit their 120 s node timeout queued behind the others. The herd
//! alert selected `phase="startup"` and saw a steady-state batch.
//!
//! The phase is now classified from the batch's own lateness as well as from
//! process age: a non-boot poll whose most overdue row is at least
//! `CATCHUP_OVERDUE_SECS` (six poll intervals) late is `catchup`, takes the
//! startup permit, and is selected by the alert. `classify_dispatch_phase` is
//! pure and unit-tested in `talos-scheduler`; what THESE tests add is the SQL —
//! the `overdue_secs` projection on the verbatim due-claim statement, computed
//! by the DATABASE clock — driven against a real clone, in both directions and
//! with the boot flag's precedence.
//!
//! Every test disables the clone's pre-existing schedules first: the harness
//! clones whatever template it is pointed at, and a template carrying live
//! rows with a past `next_trigger_at` would join the batch and make the phase
//! assertion depend on data the test did not write.
//!
//! DB tests on the `common` harness (each gets a template clone of the
//! migrated DB), so they belong in CTRL_TESTS, not TC_TESTS (64b).

mod common;

use sqlx::{Pool, Postgres};
use std::sync::atomic::{AtomicBool, Ordering};
use talos_scheduler::{SchedulerService, CATCHUP_OVERDUE_SECS};
use uuid::Uuid;

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'catchup phase test')",
    )
    .bind(id)
    .bind(format!("catchup-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

/// An enabled schedule whose `next_trigger_at` is `overdue` in the past, by
/// the database clock — the clock the claim query compares against.
async fn seed_due_schedule(pool: &Pool<Postgres>, user_id: Uuid, overdue: &str) -> Uuid {
    let workflow_id = common::create_test_workflow(pool, user_id, "catchup-phase").await;
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflow_schedules (id, workflow_id, user_id, cron_expression, timezone, is_enabled, next_trigger_at) \
         VALUES ($1, $2, $3, '*/15 * * * *', 'UTC', true, NOW() - $4::interval)",
    )
    .bind(id)
    .bind(workflow_id)
    .bind(user_id)
    .bind(overdue)
    .execute(pool)
    .await
    .expect("seed schedule");
    id
}

/// Anything the template shipped with must not be in the batch.
async fn quiesce_inherited_schedules(pool: &Pool<Postgres>) {
    sqlx::query("UPDATE workflow_schedules SET is_enabled = false")
        .execute(pool)
        .await
        .expect("disable inherited schedules");
}

async fn next_trigger_is_in_the_future(pool: &Pool<Postgres>, schedule_id: Uuid) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT next_trigger_at > NOW() FROM workflow_schedules WHERE id = $1",
    )
    .bind(schedule_id)
    .fetch_one(pool)
    .await
    .expect("read next_trigger_at")
}

/// The 2026-09-10 shape: the boot flag is spent, and a row is 70 minutes
/// overdue. Must be `catchup`, must be dispatched, must be advanced.
#[tokio::test]
async fn a_non_boot_poll_with_an_hour_overdue_row_is_a_catchup_batch() {
    let (pool, _db) = common::isolated_db_pool().await;
    quiesce_inherited_schedules(&pool).await;
    let user = seed_user(&pool).await;
    let schedule = seed_due_schedule(&pool, user, "70 minutes").await;

    let first_poll_done = AtomicBool::new(true);
    let batch = SchedulerService::select_due_and_advance(&pool, &first_poll_done)
        .await
        .expect("poll against a real clone");

    assert_eq!(batch.phase, talos_metrics::SCHEDULER_PHASE_CATCHUP);
    assert_eq!(batch.to_spawn.len(), 1, "the overdue row is claimed");
    assert_eq!(batch.to_spawn[0].2, schedule);
    let late = batch
        .max_overdue_secs
        .expect("a non-empty batch reports its lateness");
    assert!(
        (4100.0..4300.0).contains(&late),
        "lateness is read by the database clock: expected ~4200 s, got {late}"
    );
    assert!(
        late >= CATCHUP_OVERDUE_SECS,
        "the sample must clear the threshold, or this test proves nothing"
    );
    assert!(
        next_trigger_is_in_the_future(&pool, schedule).await,
        "a catch-up dispatch still advances the schedule — it is not a skip"
    );
}

/// CONTROL: a row five seconds overdue on a non-boot poll is ordinary
/// lateness — a `steady` batch. Without this the test above would pass on a
/// tree that labelled EVERY non-boot batch `catchup`.
#[tokio::test]
async fn a_non_boot_poll_with_an_on_time_row_is_steady() {
    let (pool, _db) = common::isolated_db_pool().await;
    quiesce_inherited_schedules(&pool).await;
    let user = seed_user(&pool).await;
    let schedule = seed_due_schedule(&pool, user, "5 seconds").await;

    let first_poll_done = AtomicBool::new(true);
    let batch = SchedulerService::select_due_and_advance(&pool, &first_poll_done)
        .await
        .expect("poll against a real clone");

    assert_eq!(batch.phase, talos_metrics::SCHEDULER_PHASE_STEADY);
    assert_eq!(batch.to_spawn.len(), 1);
    assert_eq!(batch.to_spawn[0].2, schedule);
    let late = batch.max_overdue_secs.expect("lateness reported");
    assert!((4.0..30.0).contains(&late), "expected ~5 s, got {late}");
}

/// The batch's lateness is its MOST overdue row: one hour-late daily cron
/// beside an on-time `*/15` is exactly the resume shape (both came due
/// during the gap; one is merely frequent). Both rows are claimed.
#[tokio::test]
async fn one_overdue_row_makes_the_whole_batch_catchup() {
    let (pool, _db) = common::isolated_db_pool().await;
    quiesce_inherited_schedules(&pool).await;
    let user = seed_user(&pool).await;
    let late_row = seed_due_schedule(&pool, user, "70 minutes").await;
    let on_time_row = seed_due_schedule(&pool, user, "5 seconds").await;

    let first_poll_done = AtomicBool::new(true);
    let batch = SchedulerService::select_due_and_advance(&pool, &first_poll_done)
        .await
        .expect("poll against a real clone");

    assert_eq!(batch.phase, talos_metrics::SCHEDULER_PHASE_CATCHUP);
    let mut claimed: Vec<Uuid> = batch.to_spawn.iter().map(|t| t.2).collect();
    claimed.sort();
    let mut expected = vec![late_row, on_time_row];
    expected.sort();
    assert_eq!(
        claimed, expected,
        "both rows are dispatched in the one batch"
    );
}

/// The boot flag wins: the same 70-minute-overdue row on the FIRST poll is
/// the boot backlog, `startup`, and the poll spends the flag.
#[tokio::test]
async fn the_first_poll_after_boot_is_startup_even_when_the_row_is_hours_late() {
    let (pool, _db) = common::isolated_db_pool().await;
    quiesce_inherited_schedules(&pool).await;
    let user = seed_user(&pool).await;
    seed_due_schedule(&pool, user, "70 minutes").await;

    let first_poll_done = AtomicBool::new(false);
    let batch = SchedulerService::select_due_and_advance(&pool, &first_poll_done)
        .await
        .expect("poll against a real clone");

    assert_eq!(batch.phase, talos_metrics::SCHEDULER_PHASE_STARTUP);
    assert_eq!(batch.to_spawn.len(), 1);
    assert!(
        first_poll_done.load(Ordering::SeqCst),
        "a committed first poll spends the boot flag"
    );

    // And the SECOND poll, now that everything is advanced, is an empty
    // steady batch — the flag is spent and nothing is late.
    let batch = SchedulerService::select_due_and_advance(&pool, &first_poll_done)
        .await
        .expect("second poll");
    assert_eq!(batch.phase, talos_metrics::SCHEDULER_PHASE_STEADY);
    assert!(batch.to_spawn.is_empty());
    assert_eq!(
        batch.max_overdue_secs, None,
        "an empty batch has no lateness"
    );
}
