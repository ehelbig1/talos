//! Audit-table immutability: UPDATE, DELETE **and TRUNCATE**.
//!
//! `prevent_audit_modification` was installed BEFORE DELETE OR UPDATE ... FOR
//! EACH ROW, and TRUNCATE fires no row trigger — so it emptied an audit table
//! with nothing raised (package CG, 2026-09-17). These tests drive the real
//! statements against a migrated clone, and pin the two catalog invariants that
//! outlive the current table list: every immutable table carries BOTH triggers,
//! and none of them carries an incoming FK with an enforced delete action (an
//! `ON DELETE CASCADE`/`SET NULL` into a table that refuses DELETE makes the
//! PARENT row undeletable — #264/#266, lint check 47).
//!
//! Runs in CI via `scripts/test-integration.sh` (CTRL_TESTS, `common`
//! harness — DATABASE_URL, per 64b).
//!
//! STATED LIMIT: a SUPERUSER bypasses every trigger with
//! `SET session_replication_role = replica`, and any owner can drop or disable
//! one. This is defence-in-depth against a stray TRUNCATE, not a bound on a
//! superuser, and `docs/THREAT_MODEL.md` says so.

mod common;

use std::collections::BTreeSet;

/// The tables that must refuse every destructive statement, each with an
/// INSERT that satisfies its own NOT NULL columns. A row is REQUIRED before the
/// DELETE/UPDATE arms mean anything: a row trigger fires per row, so on an
/// empty table both statements succeed with 0 rows affected and the assertion
/// passes over a table nothing protects (this test's own first draft did).
const IMMUTABLE_TABLES: [(&str, &str); 7] = [
    (
        "auth_audit_log",
        "INSERT INTO auth_audit_log (event_type, success) VALUES ('cg_probe', true)",
    ),
    (
        "secret_audit_log",
        "INSERT INTO secret_audit_log (action, actor_type, success) \
         VALUES ('cg_probe', 'system', true)",
    ),
    (
        "admin_event_log",
        "INSERT INTO admin_event_log (event_type, resource_type, summary) \
         VALUES ('cg_probe', 'system', 'probe')",
    ),
    (
        "schema_audit_log",
        "INSERT INTO schema_audit_log (command_tag, object_name) VALUES ('cg_probe', 'probe')",
    ),
    (
        "oauth_audit_log",
        "INSERT INTO oauth_audit_log (provider, event_type, success) \
         VALUES ('gmail', 'cg_probe', true)",
    ),
    (
        "gmail_integration_audit_log",
        "INSERT INTO gmail_integration_audit_log (event_type, success) VALUES ('cg_probe', true)",
    ),
    (
        "slack_integration_audit_log",
        "INSERT INTO slack_integration_audit_log (event_type, success) VALUES ('cg_probe', true)",
    ),
];

fn is_insufficient_privilege(e: &sqlx::Error) -> bool {
    e.as_database_error()
        .and_then(|d| d.code().map(|c| c.to_string()))
        .as_deref()
        == Some("42501")
}

#[tokio::test]
async fn every_immutable_audit_table_refuses_truncate_and_delete() {
    let (pool, _db) = common::isolated_db_pool().await;
    for (table, insert) in IMMUTABLE_TABLES {
        sqlx::query(insert)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("seed {table}: {e}"));
        // Each statement runs in its own transaction: a refusal aborts it, and
        // the next statement needs a clean one.
        for stmt in [
            format!("TRUNCATE {table}"),
            format!("DELETE FROM {table}"),
            format!("UPDATE {table} SET id = id"),
        ] {
            let mut tx = pool.begin().await.unwrap();
            let err = sqlx::query(&stmt)
                .execute(&mut *tx)
                .await
                .expect_err(&format!("{stmt} must be refused"));
            assert!(
                is_insufficient_privilege(&err),
                "{stmt} must raise 42501, got: {err}"
            );
            let _ = tx.rollback().await;
        }
    }
}

/// The CONTROL the refusals need: an ordinary INSERT still lands, so the
/// triggers did not make these tables write-only by accident.
#[tokio::test]
async fn an_append_still_works_on_an_immutable_table() {
    let (pool, _db) = common::isolated_db_pool().await;
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM admin_event_log")
        .fetch_one(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO admin_event_log (event_type, resource_type, summary) \
         VALUES ('cg_probe', 'system', 'append still works')",
    )
    .execute(&pool)
    .await
    .expect("an append-only table still appends");
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM admin_event_log")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(after, before + 1);
}

/// The invariant that outlives the list above: a table protected on UPDATE and
/// DELETE must also be protected on TRUNCATE, and vice versa. A new audit table
/// given one trigger and not the other fails here rather than at the first
/// TRUNCATE nobody meant to run.
#[tokio::test]
async fn every_immutable_table_carries_both_triggers() {
    let (pool, _db) = common::isolated_db_pool().await;
    let rows: Vec<(String, i16)> = sqlx::query_as(
        "SELECT c.relname::text, t.tgtype::int2 FROM pg_trigger t \
         JOIN pg_proc p ON p.oid = t.tgfoid JOIN pg_class c ON c.oid = t.tgrelid \
         WHERE p.proname = 'prevent_audit_modification' AND NOT t.tgisinternal",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(
        !rows.is_empty(),
        "no immutability trigger — the query is wrong"
    );

    // pg_trigger.tgtype bits: 1 = ROW, 4 = INSERT, 8 = DELETE, 16 = UPDATE,
    // 32 = TRUNCATE (a TRUNCATE trigger is statement-level, so bit 1 is clear).
    let mut row_guarded = BTreeSet::new();
    let mut truncate_guarded = BTreeSet::new();
    for (table, tgtype) in rows {
        if tgtype & 32 != 0 {
            truncate_guarded.insert(table.clone());
        }
        if tgtype & (8 | 16) != 0 {
            row_guarded.insert(table);
        }
    }
    let expected: BTreeSet<String> = IMMUTABLE_TABLES
        .iter()
        .map(|(t, _)| (*t).to_string())
        .collect();
    assert_eq!(row_guarded, expected, "UPDATE/DELETE guards");
    assert_eq!(
        truncate_guarded, expected,
        "TRUNCATE guards — a table guarded on rows only is emptied silently"
    );
}

/// #264/#266 as a live catalog check rather than a migration-text grep: an
/// enforced delete action into an immutable table makes the PARENT undeletable.
#[tokio::test]
async fn no_immutable_audit_table_has_an_enforced_delete_action() {
    let (pool, _db) = common::isolated_db_pool().await;
    let offenders: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT c.conrelid::regclass::text, c.conname::text, pg_get_constraintdef(c.oid) \
         FROM pg_constraint c \
         WHERE c.contype = 'f' AND c.confdeltype IN ('c', 'n') \
           AND EXISTS ( \
               SELECT 1 FROM pg_trigger t JOIN pg_proc p ON p.oid = t.tgfoid \
               WHERE t.tgrelid = c.conrelid AND p.proname = 'prevent_audit_modification' \
                 AND NOT t.tgisinternal \
           )",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(
        offenders.is_empty(),
        "an immutable audit table must not carry a CASCADE/SET NULL FK: {offenders:?}"
    );
}

/// Deleting the parent still works — the point of dropping those FKs — and the
/// audit row SURVIVES it, which is what an append-only record is for.
#[tokio::test]
async fn deleting_a_user_leaves_their_audit_rows_behind() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'h', true)",
    )
    .bind(user)
    .bind(format!("cg-{user}@example.com"))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO oauth_audit_log (user_id, provider, event_type, success) \
         VALUES ($1, 'gmail', 'connect', true)",
    )
    .bind(user)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user)
        .execute(&pool)
        .await
        .expect("an immutable audit row must not make its user undeletable");

    let kept: i64 = sqlx::query_scalar("SELECT count(*) FROM oauth_audit_log WHERE user_id = $1")
        .bind(user)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(kept, 1, "the audit row outlives the user it names");
}
