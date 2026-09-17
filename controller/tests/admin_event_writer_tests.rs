//! `admin_event_log` is written through ONE writer, and that writer bounds and
//! redacts what it stores.
//!
//! The table is append-only (its immutability triggers refuse UPDATE, DELETE
//! and TRUNCATE), so a row a writer puts there is what an auditor reads
//! forever — and every summary on this platform interpolates something a user
//! chose. Measured 2026-09-17 (package CH): of four production writers exactly
//! one truncated AND redacted; `talos-api-keys` redacted without truncating,
//! and the ML lifecycle job and the worker-provisioning writer did neither.
//!
//! These drive the shared writer and ONE real production caller of it against a
//! migrated clone. The other three call sites are held by structural check 94
//! (the statement may appear only in `talos-admin-event-log`), stated as a
//! textual guard: their own entry points are private (`audit_transition`) or
//! spawn a detached task (`log_key_event`).
//!
//! Runs in CI via `scripts/test-integration.sh` (CTRL_TESTS, `common`
//! harness — DATABASE_URL, per 64b).

mod common;

/// A secret shape `talos_dlp_provider` redacts, kept in one place so the
/// assertions below cannot drift from what is planted.
const PLANTED_SECRET: &str = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";

#[tokio::test]
async fn the_shared_writer_truncates_and_redacts_both_columns() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'h', true)",
    )
    .bind(user)
    .bind(format!("ch-{user}@example.com"))
    .execute(&pool)
    .await
    .unwrap();

    // A summary far past the cap, carrying a secret past the cut as well as
    // before it, and details carrying one too.
    let summary = format!("{PLANTED_SECRET} {} {PLANTED_SECRET}", "x".repeat(4000));
    let details = serde_json::json!({ "note": format!("pasted {PLANTED_SECRET}") });
    talos_admin_event_log::insert(
        &pool,
        Some(user),
        "ch_probe",
        "system",
        None,
        &summary,
        Some(&details),
    )
    .await
    .expect("the shared writer appends");

    let (stored_summary, stored_details): (String, Option<serde_json::Value>) = sqlx::query_as(
        "SELECT summary, details FROM admin_event_log WHERE event_type = 'ch_probe'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    assert!(
        stored_summary.len() <= 1000,
        "summary must be capped, got {} bytes",
        stored_summary.len()
    );
    assert!(
        !stored_summary.contains(PLANTED_SECRET),
        "summary must be redacted: {stored_summary}"
    );
    let details_text = stored_details.expect("details stored").to_string();
    assert!(
        !details_text.contains(PLANTED_SECRET),
        "details must be redacted: {details_text}"
    );
}

/// A REAL production caller — the operator CLI's provisioning-token audit,
/// which until package CH wrote its summary and details raw. It is also the one
/// writer with no platform user, so it pins that `user_id` stays NULL.
#[tokio::test]
async fn the_provisioning_token_writer_bounds_and_redacts_and_keeps_a_null_user() {
    let (pool, _db) = common::isolated_db_pool().await;
    let repo = talos_worker_identity_repository::WorkerIdentityRepository::new(pool.clone());
    let token_id = uuid::Uuid::new_v4();
    let summary = format!("minted for worker {} {PLANTED_SECRET}", "w".repeat(4000));
    let details = serde_json::json!({ "note": PLANTED_SECRET });

    repo.insert_provisioning_token_audit("ch_token_probe", token_id, &summary, Some(&details))
        .await
        .expect("audit event appends");

    let (user_id, stored_summary, stored_details): (
        Option<uuid::Uuid>,
        String,
        Option<serde_json::Value>,
    ) = sqlx::query_as(
        "SELECT user_id, summary, details FROM admin_event_log \
         WHERE event_type = 'ch_token_probe'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    assert!(
        user_id.is_none(),
        "the operator CLI writes no platform user"
    );
    assert!(stored_summary.len() <= 1000, "{}", stored_summary.len());
    assert!(!stored_summary.contains(PLANTED_SECRET), "{stored_summary}");
    assert!(
        !stored_details
            .expect("details")
            .to_string()
            .contains(PLANTED_SECRET),
        "details must be redacted"
    );
}
