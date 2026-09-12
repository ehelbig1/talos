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

use common::{create_test_user, create_test_workflow, setup_test_context};
use talos_workflow_repository::WorkflowRepository;
use uuid::Uuid;

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

/// The one reader `workflow_nodes` had was not a comment: the GraphQL
/// `actorWorkflows` resolver counted nodes with a subselect over it, executed
/// live six times in the two days before the table was dropped, and answered
/// "Request could not be completed" for every actor on the #822 deploy. The
/// count now comes from `graph_json`, so this pins both facts: the read
/// succeeds on a schema without the table, and the count is the REAL one
/// (it was always 0 before — the table never had a writer).
#[tokio::test]
async fn the_actor_workflows_read_counts_graph_nodes_without_workflow_nodes() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let user = create_test_user(&ctx.auth_service, "dead_schema_actor_wf@example.com").await;
    let actor_id = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name) VALUES ($1, $2, 'dead-schema-actor')")
        .bind(actor_id)
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    let wf = create_test_workflow(&pool, user, "dead-schema-actor-wf").await;
    sqlx::query(
        "UPDATE workflows SET actor_id = $2, \
         graph_json = '{\"nodes\":[{\"id\":\"a\"},{\"id\":\"b\"},{\"id\":\"c\"}],\"edges\":[]}' \
         WHERE id = $1",
    )
    .bind(wf)
    .bind(actor_id)
    .execute(&pool)
    .await
    .unwrap();
    // CONTROL: another actor's workflow stays out.
    let other_actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name) VALUES ($1, $2, 'dead-schema-other')")
        .bind(other_actor)
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    let other_wf = create_test_workflow(&pool, user, "dead-schema-other-wf").await;
    sqlx::query("UPDATE workflows SET actor_id = $2 WHERE id = $1")
        .bind(other_wf)
        .bind(other_actor)
        .execute(&pool)
        .await
        .unwrap();

    let repo = WorkflowRepository::new(pool.clone());
    let mut conn = pool.acquire().await.unwrap();
    let rows = repo
        .list_workflows_for_actor_scoped(&mut conn, actor_id, user, 10)
        .await
        .expect("the actor-workflows read must prepare on a schema without workflow_nodes");
    assert_eq!(rows.len(), 1, "only this actor's workflow");
    assert_eq!(rows[0].id, wf);
    assert_eq!(
        rows[0].node_count, 3,
        "the count is derived from graph_json"
    );
}
