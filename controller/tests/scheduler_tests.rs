//! Integration tests for the scheduler module.
//!
//! Tests `calculate_next_trigger`, `validate_cron`, and `validate_timezone`
//! pure functions (no database required), plus SQL-level CRUD tests that
//! exercise `workflow_schedules` rows directly.

use chrono::Utc;
use controller::scheduler::{calculate_next_trigger, validate_cron, validate_timezone};

// ---------------------------------------------------------------------------
// calculate_next_trigger — valid inputs
// ---------------------------------------------------------------------------

#[test]
fn calculate_next_trigger_every_minute_utc() {
    let result = calculate_next_trigger("* * * * *", "UTC");
    assert!(result.is_ok(), "every-minute cron in UTC should succeed");
    let next = result.unwrap();
    assert!(next > Utc::now(), "next trigger must be in the future");
}

#[test]
fn calculate_next_trigger_daily_midnight_utc() {
    let result = calculate_next_trigger("0 0 * * *", "UTC");
    assert!(result.is_ok(), "daily-midnight cron should succeed");
    let next = result.unwrap();
    assert!(next > Utc::now());
}

#[test]
fn calculate_next_trigger_with_named_timezone() {
    let result = calculate_next_trigger("30 9 * * *", "America/New_York");
    assert!(
        result.is_ok(),
        "valid cron + IANA timezone should succeed: {:?}",
        result
    );
    let next = result.unwrap();
    assert!(next > Utc::now());
}

#[test]
fn calculate_next_trigger_with_europe_timezone() {
    let result = calculate_next_trigger("0 12 * * 1-5", "Europe/London");
    assert!(result.is_ok());
}

#[test]
fn calculate_next_trigger_with_asia_timezone() {
    let result = calculate_next_trigger("0 6 * * *", "Asia/Tokyo");
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// calculate_next_trigger — invalid inputs
// ---------------------------------------------------------------------------

#[test]
fn calculate_next_trigger_invalid_cron_expression() {
    let result = calculate_next_trigger("not a cron", "UTC");
    assert!(result.is_err(), "garbage cron should fail");
    assert!(
        result.unwrap_err().contains("Invalid cron"),
        "error should mention invalid cron"
    );
}

#[test]
fn calculate_next_trigger_invalid_timezone() {
    let result = calculate_next_trigger("* * * * *", "Fake/Zone");
    assert!(result.is_err(), "fake timezone should fail");
    assert!(
        result.unwrap_err().contains("Invalid timezone"),
        "error should mention invalid timezone"
    );
}

#[test]
fn calculate_next_trigger_empty_cron() {
    let result = calculate_next_trigger("", "UTC");
    assert!(result.is_err(), "empty cron should fail");
}

#[test]
fn calculate_next_trigger_empty_timezone() {
    let result = calculate_next_trigger("* * * * *", "");
    assert!(result.is_err(), "empty timezone should fail");
}

// ---------------------------------------------------------------------------
// validate_cron
// ---------------------------------------------------------------------------

#[test]
fn validate_cron_standard_five_field() {
    assert!(validate_cron("0 0 * * *").is_ok(), "standard 5-field cron");
    assert!(validate_cron("*/5 * * * *").is_ok(), "every 5 minutes");
    assert!(validate_cron("0 9 * * 1-5").is_ok(), "weekday mornings");
    assert!(validate_cron("0 0 1 1 *").is_ok(), "once a year");
}

#[test]
fn validate_cron_rejects_garbage() {
    assert!(validate_cron("hello world").is_err());
    assert!(validate_cron("").is_err());
    assert!(validate_cron("* *").is_err(), "too few fields");
}

#[test]
fn validate_cron_rejects_out_of_range() {
    assert!(validate_cron("61 * * * *").is_err(), "minute 61 is invalid");
    assert!(validate_cron("* 25 * * *").is_err(), "hour 25 is invalid");
}

// ---------------------------------------------------------------------------
// validate_timezone
// ---------------------------------------------------------------------------

#[test]
fn validate_timezone_accepts_utc() {
    assert!(validate_timezone("UTC").is_ok());
}

#[test]
fn validate_timezone_accepts_iana_names() {
    assert!(validate_timezone("America/New_York").is_ok());
    assert!(validate_timezone("Europe/London").is_ok());
    assert!(validate_timezone("Asia/Tokyo").is_ok());
    assert!(validate_timezone("Australia/Sydney").is_ok());
}

#[test]
fn validate_timezone_rejects_fake_zone() {
    let result = validate_timezone("Fake/Zone");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Invalid timezone"));
}

#[test]
fn validate_timezone_rejects_empty() {
    assert!(validate_timezone("").is_err());
}

#[test]
fn validate_timezone_rejects_offset_notation() {
    // chrono-tz does not accept raw UTC offsets like "+05:00"
    assert!(validate_timezone("+05:00").is_err());
}

// ---------------------------------------------------------------------------
// Schedule CRUD via direct SQL (requires a test database)
// ---------------------------------------------------------------------------

mod common;

#[tokio::test]
async fn schedule_crud_lifecycle() {
    let ctx = common::setup_test_context().await;
    let db = &ctx.db_pool;

    // Ensure the workflow_schedules table exists (migrations should have run).
    // Create a test user and workflow to satisfy foreign keys.
    let user_id = common::create_test_user(&ctx.auth_service, "sched_test@example.com").await;
    let workflow_id = common::create_test_workflow(db, user_id, "sched-test").await;

    let cron = "*/10 * * * *";
    let tz = "UTC";
    let next = calculate_next_trigger(cron, tz).expect("calculate next trigger");

    // CREATE
    let sched_id = uuid::Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO workflow_schedules
           (id, workflow_id, user_id, cron_expression, timezone, is_enabled, next_trigger_at)
           VALUES ($1, $2, $3, $4, $5, true, $6)"#,
    )
    .bind(sched_id)
    .bind(workflow_id)
    .bind(user_id)
    .bind(cron)
    .bind(tz)
    .bind(next)
    .execute(db)
    .await
    .expect("create schedule");

    // READ
    let row = sqlx::query_as::<_, (bool, String, String)>(
        "SELECT is_enabled, cron_expression, timezone FROM workflow_schedules WHERE id = $1",
    )
    .bind(sched_id)
    .fetch_one(db)
    .await
    .expect("read schedule");
    assert!(row.0, "schedule should be enabled");
    assert_eq!(row.1, cron);
    assert_eq!(row.2, tz);

    // Verify next_trigger_at is set and in the future
    let next_at = sqlx::query_scalar::<_, Option<chrono::DateTime<chrono::Utc>>>(
        "SELECT next_trigger_at FROM workflow_schedules WHERE id = $1",
    )
    .bind(sched_id)
    .fetch_one(db)
    .await
    .expect("read next_trigger_at");
    assert!(next_at.is_some(), "next_trigger_at should be set");
    assert!(
        next_at.unwrap() > chrono::Utc::now() - chrono::Duration::minutes(1),
        "next_trigger_at should be roughly in the future"
    );

    // UPDATE (change cron expression)
    sqlx::query("UPDATE workflow_schedules SET cron_expression = '0 0 * * *' WHERE id = $1")
        .bind(sched_id)
        .execute(db)
        .await
        .expect("update schedule");
    let updated_cron = sqlx::query_scalar::<_, String>(
        "SELECT cron_expression FROM workflow_schedules WHERE id = $1",
    )
    .bind(sched_id)
    .fetch_one(db)
    .await
    .expect("read updated cron");
    assert_eq!(updated_cron, "0 0 * * *");

    // DISABLE
    sqlx::query("UPDATE workflow_schedules SET is_enabled = false WHERE id = $1")
        .bind(sched_id)
        .execute(db)
        .await
        .expect("disable schedule");
    let is_enabled =
        sqlx::query_scalar::<_, bool>("SELECT is_enabled FROM workflow_schedules WHERE id = $1")
            .bind(sched_id)
            .fetch_one(db)
            .await
            .expect("read is_enabled");
    assert!(!is_enabled, "schedule should be disabled");

    // DELETE
    sqlx::query("DELETE FROM workflow_schedules WHERE id = $1")
        .bind(sched_id)
        .execute(db)
        .await
        .expect("delete schedule");
    let count =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM workflow_schedules WHERE id = $1")
            .bind(sched_id)
            .fetch_one(db)
            .await
            .expect("count after delete");
    assert_eq!(count, 0, "schedule should be deleted");

    // Cleanup
    sqlx::query("DELETE FROM workflows WHERE id = $1")
        .bind(workflow_id)
        .execute(db)
        .await
        .ok();
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(db)
        .await
        .ok();
}
