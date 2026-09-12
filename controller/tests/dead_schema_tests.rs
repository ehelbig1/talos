//! The schema carries no table that nothing reads or writes.
//!
//! Measured 2026-09-12 by sweeping every `public` table against every non-test
//! Rust file: eleven tables had no writer and no reader (or, for
//! `google_calendar_watch_channels`, readers that could never match a row —
//! it had no writer since gcal channels moved into `integration_state`). All
//! eleven held zero rows on the reference fleet and were dropped by migration
//! `20260912100000`. This binary pins that a migrated schema no longer carries
//! them, and that the two live tables the same sweep judged differently are
//! still there: `schema_audit_log` with its DDL event trigger (the SOC 2
//! collector now exports it), and the three audit tables with their
//! immutability triggers.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

const DROPPED: [&str; 11] = [
    "circuit_breaker_metrics",
    "compilation_cache",
    "feature_flags",
    "idempotency_keys",
    "key_rotation_events",
    "mcp_crate_allowlist",
    "secrets_rotation_log",
    "tenant_quotas",
    "webhook_processed_events",
    "workflow_nodes",
    "google_calendar_watch_channels",
];

#[tokio::test]
async fn the_eleven_untouched_tables_are_gone_and_the_live_ones_remain() {
    let (pool, _db) = common::isolated_db_pool().await;
    for t in DROPPED {
        let gone: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NULL")
            .bind(t)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(gone, "{t} must not exist on a migrated database");
    }
    // CONTROL: the DDL audit table the sweep deliberately KEPT, with the event
    // trigger that writes it.
    let present: bool = sqlx::query_scalar("SELECT to_regclass('schema_audit_log') IS NOT NULL")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(present, "schema_audit_log is live and must stay");
    let trg: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_event_trigger WHERE evtname = 'log_schema_changes' AND evtevent = 'ddl_command_end'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(trg, 1, "the DDL event trigger that writes schema_audit_log");
    // And the collector's export statement for it PREPAREs against the real
    // column (event_time — not created_at, the column the collector used to
    // assume for every table).
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM schema_audit_log WHERE event_time >= now() - interval '90 days'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(n >= 0);
    // The three audit tables keep their immutability trigger.
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_trigger WHERE tgname IN \
         ('trg_admin_event_log_immutable','trg_auth_audit_log_immutable','trg_secret_audit_log_immutable')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(n, 3);
}

/// Every table the SOC 2 collector exports must have the timestamp column the
/// collector names for it — the statement the collector runs, PREPAREd here
/// against the migrated schema. Until 2026-09-12 the collector assumed
/// `created_at` for every table and `secret_audit_log` (column `"timestamp"`)
/// exported an empty file on every run.
#[tokio::test]
async fn every_collector_export_statement_prepares() {
    let (pool, _db) = common::isolated_db_pool().await;
    for (table, ts) in [
        ("auth_audit_log", "created_at"),
        ("secret_audit_log", "\"timestamp\""),
        ("admin_event_log", "created_at"),
        ("schema_audit_log", "event_time"),
    ] {
        let sql = format!(
            "SELECT count(*) FROM {table} WHERE {ts} >= (now() - interval '90 days')::timestamptz"
        );
        let n: i64 = sqlx::query_scalar(&sql)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("collector export for {table} cannot run: {e}"));
        assert!(n >= 0);
    }
}
