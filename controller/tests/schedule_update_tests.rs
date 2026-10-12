//! `update_schedule` changes WHEN a schedule fires, in place, for its owner.
//!
//! Until 2026-10-12 there was create, delete, pause and resume. Moving a
//! schedule by ten minutes was delete-then-create: a window with no schedule,
//! and a "permanently delete" call for an edit.
//!
//! These drive `ScheduleRepository::update_timing` against a clone of the
//! migrated schema. The tenancy property is the first test: the statement is
//! scoped to the caller, and another user's schedule is neither changed nor
//! acknowledged.
//!
//! DB tests on the `common` harness (each gets a template clone of the
//! migrated DB).

mod common;

use chrono::{DateTime, Duration, Utc};
use sqlx::{Pool, Postgres, Row};
use talos_schedule_repo::{ScheduleRepository, ScheduleTimingUpdate};
use uuid::Uuid;

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'schedule update test')",
    )
    .bind(id)
    .bind(format!("schedule-update-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

/// A schedule at 09:00 UTC daily, with a next fire time an hour from now.
async fn seed_schedule(pool: &Pool<Postgres>, user_id: Uuid, enabled: bool) -> Uuid {
    let workflow_id = common::create_test_workflow(pool, user_id, "schedule-update").await;
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflow_schedules \
         (id, workflow_id, user_id, cron_expression, timezone, is_enabled, next_trigger_at, last_triggered_at) \
         VALUES ($1, $2, $3, '0 9 * * *', 'UTC', $4, NOW() + interval '1 hour', NOW() - interval '1 day')",
    )
    .bind(id)
    .bind(workflow_id)
    .bind(user_id)
    .bind(enabled)
    .execute(pool)
    .await
    .expect("seed schedule");
    id
}

struct Stored {
    cron: String,
    timezone: String,
    enabled: bool,
    next: Option<DateTime<Utc>>,
    last: Option<DateTime<Utc>>,
}

async fn stored(pool: &Pool<Postgres>, schedule_id: Uuid) -> Stored {
    let row = sqlx::query(
        "SELECT cron_expression, timezone, is_enabled, next_trigger_at, last_triggered_at \
         FROM workflow_schedules WHERE id = $1",
    )
    .bind(schedule_id)
    .fetch_one(pool)
    .await
    .expect("read schedule");
    Stored {
        cron: row.try_get("cron_expression").expect("cron"),
        timezone: row.try_get("timezone").expect("timezone"),
        enabled: row.try_get("is_enabled").expect("enabled"),
        next: row.try_get("next_trigger_at").expect("next"),
        last: row.try_get("last_triggered_at").expect("last"),
    }
}

/// The handler's own next-trigger function: the test stores what production
/// would compute.
fn next(cron: &str, timezone: &str) -> Option<DateTime<Utc>> {
    talos_scheduler::calculate_next_trigger(cron, timezone).ok()
}

#[tokio::test]
async fn another_users_schedule_is_neither_changed_nor_acknowledged() {
    let (pool, _db) = common::isolated_db_pool().await;
    let owner = seed_user(&pool).await;
    let stranger = seed_user(&pool).await;
    let schedule = seed_schedule(&pool, owner, true).await;
    let before = stored(&pool, schedule).await;
    let repo = ScheduleRepository::new(pool.clone());

    let outcome = repo
        .update_timing(
            schedule,
            stranger,
            Some("30 7 * * *"),
            Some("Europe/London"),
            next,
        )
        .await
        .expect("the statement runs");
    assert!(
        matches!(outcome, ScheduleTimingUpdate::NotFound),
        "a stranger was told about, or changed, another user's schedule: {outcome:?}"
    );
    let after = stored(&pool, schedule).await;
    assert_eq!(after.cron, before.cron);
    assert_eq!(after.timezone, before.timezone);
    assert_eq!(after.next, before.next);

    // A schedule that does not exist reads the same way.
    let outcome = repo
        .update_timing(Uuid::new_v4(), owner, Some("30 7 * * *"), None, next)
        .await
        .expect("the statement runs");
    assert!(matches!(outcome, ScheduleTimingUpdate::NotFound));
}

#[tokio::test]
async fn the_owner_moves_the_time_and_the_next_fire_follows() {
    let (pool, _db) = common::isolated_db_pool().await;
    let owner = seed_user(&pool).await;
    let schedule = seed_schedule(&pool, owner, true).await;
    let before = stored(&pool, schedule).await;
    let repo = ScheduleRepository::new(pool.clone());

    // Only the cron: the timezone keeps its stored value.
    let outcome = repo
        .update_timing(schedule, owner, Some("10 9 * * *"), None, next)
        .await
        .expect("the statement runs");
    let ScheduleTimingUpdate::Updated(timing) = outcome else {
        panic!("expected an update, got {outcome:?}");
    };
    assert_eq!(timing.previous_cron_expression, "0 9 * * *");
    assert_eq!(timing.previous_timezone, "UTC");
    assert_eq!(timing.cron_expression, "10 9 * * *");
    assert_eq!(timing.timezone, "UTC");
    assert!(timing.is_enabled);

    let after = stored(&pool, schedule).await;
    assert_eq!(after.cron, "10 9 * * *");
    assert_eq!(after.timezone, "UTC");
    assert!(after.enabled);
    assert_eq!(after.last, before.last, "the history is not touched");
    let next_fire = after.next.expect("a next fire time");
    assert_eq!(next_fire, timing.next_trigger_at);
    assert_eq!(next_fire.format("%H:%M").to_string(), "09:10");
    assert!(
        next_fire > Utc::now() && next_fire < Utc::now() + Duration::days(1) + Duration::minutes(1)
    );

    // Only the timezone: the cron keeps its value, and 09:10 in a zone five
    // or four hours behind UTC is 13:10 or 14:10 UTC.
    let outcome = repo
        .update_timing(schedule, owner, None, Some("America/New_York"), next)
        .await
        .expect("the statement runs");
    assert!(matches!(outcome, ScheduleTimingUpdate::Updated(_)));
    let after = stored(&pool, schedule).await;
    assert_eq!(after.cron, "10 9 * * *");
    assert_eq!(after.timezone, "America/New_York");
    let utc_time = after
        .next
        .expect("a next fire time")
        .format("%H:%M")
        .to_string();
    assert!(
        utc_time == "13:10" || utc_time == "14:10",
        "09:10 New York stored as {utc_time} UTC"
    );
}

#[tokio::test]
async fn a_paused_schedule_stays_paused_and_gets_its_new_time() {
    let (pool, _db) = common::isolated_db_pool().await;
    let owner = seed_user(&pool).await;
    let schedule = seed_schedule(&pool, owner, false).await;
    let repo = ScheduleRepository::new(pool.clone());

    let outcome = repo
        .update_timing(schedule, owner, Some("45 18 * * *"), None, next)
        .await
        .expect("the statement runs");
    let ScheduleTimingUpdate::Updated(timing) = outcome else {
        panic!("expected an update, got {outcome:?}");
    };
    assert!(
        !timing.is_enabled,
        "an edit must not resume a paused schedule"
    );
    let after = stored(&pool, schedule).await;
    assert!(!after.enabled);
    // Resuming later must not fire at the old time.
    assert_eq!(
        after
            .next
            .expect("a next fire time")
            .format("%H:%M")
            .to_string(),
        "18:45"
    );
}

#[tokio::test]
async fn a_pair_with_no_next_fire_time_writes_nothing() {
    let (pool, _db) = common::isolated_db_pool().await;
    let owner = seed_user(&pool).await;
    let schedule = seed_schedule(&pool, owner, true).await;
    let before = stored(&pool, schedule).await;
    let repo = ScheduleRepository::new(pool.clone());

    // A NULL next_trigger_at is a schedule the due-claim query never selects:
    // saved, and never run. Refused instead.
    let outcome = repo
        .update_timing(schedule, owner, Some("10 9 * * *"), None, |_, _| None)
        .await
        .expect("the statement runs");
    assert!(matches!(outcome, ScheduleTimingUpdate::NoNextTrigger));
    let after = stored(&pool, schedule).await;
    assert_eq!(after.cron, before.cron);
    assert_eq!(after.next, before.next);
}
