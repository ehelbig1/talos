//! Every `query_paginated` run is recorded (security review 2026-10-14, D-5):
//! the caller, the SHA-256 of the statement — never its text — the page and
//! the row count, in `admin_event_log`.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use uuid::Uuid;

#[tokio::test]
async fn a_run_is_recorded_by_the_statements_hash_not_its_text() {
    let (pool, _db) = common::isolated_db_pool().await;
    let admin = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(admin)
    .bind(format!("{admin}@admin-query.test"))
    .execute(&pool)
    .await
    .expect("seed user");
    let repo = talos_advanced_repository::AdvancedRepository::new(pool.clone());
    let statement = "SELECT id FROM workflows WHERE name = 'a literal worth hiding'";
    repo.record_admin_query(admin, statement, 2, 7)
        .await
        .expect("record");

    let (user_id, details): (Option<Uuid>, serde_json::Value) = sqlx::query_as(
        "SELECT user_id, details FROM admin_event_log \
         WHERE event_type = 'admin_query_paginated' ORDER BY created_at DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .expect("the record");
    assert_eq!(user_id, Some(admin));
    assert_eq!(
        details["statement_sha256"],
        talos_text_util::sha256_hex(statement)
    );
    assert_eq!(details["page"], 2);
    assert_eq!(details["row_count"], 7);
    assert!(
        !details.to_string().contains("literal worth hiding"),
        "the statement's text is not stored: {details}"
    );
}
