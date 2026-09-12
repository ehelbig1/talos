//! `workflow_executions_archive`'s status CHECK must admit exactly what the
//! live table's does. The archive was created with March's status set and three
//! later widenings of the live constraint never reached it (migration
//! `20260912160000` aligns them). Column parity between the two tables is pinned
//! elsewhere (`ARCHIVED_EXECUTION_COLUMNS`); this pins the CONSTRAINT parity by
//! reading both definitions out of the catalog, so the next `ADD 'x' TO
//! status` on the live table fails here until the archive follows.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use std::collections::BTreeSet;

async fn allowed_statuses(pool: &sqlx::PgPool, table: &str) -> BTreeSet<String> {
    let def: String = sqlx::query_scalar(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid = $1::regclass AND contype = 'c' AND pg_get_constraintdef(oid) LIKE '%status%'",
    )
    .bind(table)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("{table} must carry exactly one status CHECK: {e}"));
    // CHECK ((status = ANY (ARRAY['a'::text, 'b'::text]))) → {a, b}
    def.split('\'')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .collect()
}

#[tokio::test]
async fn the_archive_admits_exactly_the_live_statuses() {
    let (pool, _db) = common::isolated_db_pool().await;
    let live = allowed_statuses(&pool, "workflow_executions").await;
    let archive = allowed_statuses(&pool, "workflow_executions_archive").await;
    assert!(
        !live.is_empty() && live.contains("resuming"),
        "live set parsed: {live:?}"
    );
    assert_eq!(
        archive, live,
        "archive status CHECK must equal the live table's"
    );
    assert!(
        !archive.contains("pending"),
        "`pending` left the live set in March and must not linger in the archive"
    );
}

#[tokio::test]
async fn the_archive_refuses_a_status_outside_the_set_and_admits_a_retired_run() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(user)
    .bind(format!("{user}@archive-check.test"))
    .execute(&pool)
    .await
    .unwrap();
    let org: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (name, slug, owner_id, is_personal) VALUES ($1, $1, $2, true) RETURNING id",
    )
    .bind(format!("arcchk-{user}"))
    .bind(user)
    .fetch_one(&pool)
    .await
    .unwrap();
    let workflow = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO workflows (id, user_id, org_id, name, module_uri, graph_json) VALUES ($1, $2, $3, $4, 'test://none', '{}'::jsonb)")
        .bind(workflow)
        .bind(user)
        .bind(org)
        .bind(format!("arcchk-{user}"))
        .execute(&pool)
        .await
        .unwrap();
    let actor = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name, org_id) VALUES ($1, $2, $3, $4)")
        .bind(actor)
        .bind(user)
        .bind(format!("arcchk-{user}"))
        .bind(org)
        .execute(&pool)
        .await
        .unwrap();
    let insert = |status: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query(
                "INSERT INTO workflow_executions_archive (id, workflow_id, user_id, actor_id, status, started_at, completed_at, archived_at) VALUES ($1, $2, $3, $4, $5, NOW() - interval '1 hour', NOW() - interval '59 minutes', NOW())",
            )
            .bind(uuid::Uuid::new_v4())
            .bind(workflow)
            .bind(user)
            .bind(actor)
            .bind(status)
            .execute(&pool)
            .await
        }
    };
    insert("cancelled")
        .await
        .expect("a terminal status the sweep moves must land");
    let err = insert("pending")
        .await
        .expect_err("the retired `pending` status must be refused");
    let code = err
        .as_database_error()
        .and_then(|e| e.code().map(|c| c.to_string()));
    assert_eq!(
        code.as_deref(),
        Some("23514"),
        "expected a CHECK violation, got {err}"
    );
}
