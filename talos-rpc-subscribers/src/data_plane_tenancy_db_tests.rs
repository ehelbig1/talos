//! A durable state write names a live run, and guest SQL carries its tenant
//! (security review 2026-10-14, B-3 and B-4/D-2), against the MIGRATED
//! database (CI: `scripts/test-integration.sh`, kind `lib-migrated`), as a
//! superuser. Skipped without `TALOS_TEST_DATABASE_URL`.
use crate::{
    execute_guest_query_within, execution_state_delete, execution_state_write, guest_reply,
    test_actor, GuestRoleSetting, StateWriteVerdict, GUEST_QUERY_FAILED,
};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::time::Duration;
use talos_memory::database_rpc::DatabaseRpcError;
use uuid::Uuid;

fn database_url() -> Option<String> {
    std::env::var("TALOS_TEST_DATABASE_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
}

async fn pool(url: &str) -> PgPool {
    PgPoolOptions::new()
        .max_connections(3)
        .connect(url)
        .await
        .expect("connect")
}

/// An execution row of `status` owned by a fresh user.
async fn execution(pool: &PgPool, status: &str) -> Uuid {
    let actor = test_actor(pool).await;
    let user: Uuid = sqlx::query_scalar("SELECT user_id FROM actors WHERE id = $1")
        .bind(actor)
        .fetch_one(pool)
        .await
        .unwrap();
    let workflow = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, graph_json, module_uri, status) \
         VALUES ($1, $2, $3, '{}', 'talos://test', 'draft')",
    )
    .bind(workflow)
    .bind(user)
    .bind(format!("state-{workflow}"))
    .execute(pool)
    .await
    .expect("seed workflow");
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflow_executions (id, workflow_id, user_id, actor_id, status, started_at) \
         VALUES ($1, $2, $3, $4, $5, now())",
    )
    .bind(id)
    .bind(workflow)
    .bind(user)
    .bind(actor)
    .bind(status)
    .execute(pool)
    .await
    .expect("seed execution");
    id
}

async fn state_rows(pool: &PgPool, execution_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM execution_state WHERE execution_id = $1")
        .bind(execution_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_state_write_for_an_execution_that_is_not_live_writes_nothing() {
    let Some(url) = database_url() else { return };
    let pool = pool(&url).await;
    let missing = Uuid::new_v4();
    assert_eq!(
        execution_state_write(&pool, missing, "k", "v")
            .await
            .unwrap(),
        StateWriteVerdict::NotLive
    );
    assert_eq!(state_rows(&pool, missing).await, 0);
    let ended = execution(&pool, "completed").await;
    assert_eq!(
        execution_state_write(&pool, ended, "k", "v").await.unwrap(),
        StateWriteVerdict::NotLive
    );
    assert_eq!(state_rows(&pool, ended).await, 0);
    assert_eq!(
        execution_state_delete(&pool, ended, "k").await.unwrap(),
        StateWriteVerdict::NotLive
    );

    let live = execution(&pool, "running").await;
    assert_eq!(
        execution_state_write(&pool, live, "k", "v").await.unwrap(),
        StateWriteVerdict::Written
    );
    // An overwrite of a held key is not a new key.
    assert_eq!(
        execution_state_write(&pool, live, "k", "v2").await.unwrap(),
        StateWriteVerdict::Written
    );
    assert_eq!(state_rows(&pool, live).await, 1);
    assert_eq!(
        execution_state_delete(&pool, live, "k").await.unwrap(),
        StateWriteVerdict::Written
    );
    assert_eq!(state_rows(&pool, live).await, 0);
}

#[tokio::test]
async fn a_state_write_past_the_executions_quota_is_refused() {
    use talos_memory::state_rpc::{MAX_STATE_BYTES_PER_EXECUTION, MAX_STATE_KEYS_PER_EXECUTION};
    let Some(url) = database_url() else { return };
    let pool = pool(&url).await;
    let live = execution(&pool, "running").await;
    sqlx::query(
        "INSERT INTO execution_state (execution_id, key, value) \
         SELECT $1, 'k' || g, 'v' FROM generate_series(1, $2) AS g",
    )
    .bind(live)
    .bind(MAX_STATE_KEYS_PER_EXECUTION)
    .execute(&pool)
    .await
    .expect("fill to the key quota");
    assert_eq!(
        execution_state_write(&pool, live, "one-more", "v")
            .await
            .unwrap(),
        StateWriteVerdict::OverQuota
    );
    assert_eq!(state_rows(&pool, live).await, MAX_STATE_KEYS_PER_EXECUTION);
    // A held key may still be overwritten.
    assert_eq!(
        execution_state_write(&pool, live, "k1", "w").await.unwrap(),
        StateWriteVerdict::Written
    );

    let bytes = execution(&pool, "running").await;
    let big = "x".repeat(usize::try_from(MAX_STATE_BYTES_PER_EXECUTION).unwrap());
    assert_eq!(
        execution_state_write(&pool, bytes, "big", &big)
            .await
            .unwrap(),
        StateWriteVerdict::Written
    );
    assert_eq!(
        execution_state_write(&pool, bytes, "small", "v")
            .await
            .unwrap(),
        StateWriteVerdict::OverQuota
    );
}

/// Guest SQL carries its tenant. The fixture table has the platform's
/// policy shape — `user_id` = `app.current_user_id`, and a permit-when-unset
/// arm — and is granted to `talos_guest`, which is exactly what an operator
/// granting a table to modules does. Without the tenant GUC the arm admits
/// every tenant's rows.
#[tokio::test]
async fn guest_sql_sees_only_its_actors_owners_rows() {
    let Some(url) = database_url() else { return };
    let pool = pool(&url).await;
    let table = format!(
        "guest_tenancy_{}",
        &Uuid::new_v4().simple().to_string()[..12]
    );
    let setup = format!(
        "CREATE TABLE {table} (user_id uuid NOT NULL, note text); \
         ALTER TABLE {table} ENABLE ROW LEVEL SECURITY; \
         CREATE POLICY {table}_tenant ON {table} USING ( \
             NULLIF(current_setting('app.current_user_id', true), '') IS NULL \
             OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid); \
         GRANT SELECT ON {table} TO talos_guest;"
    );
    // sql-safe: test-only DDL over a generated table name
    sqlx::raw_sql(sqlx::AssertSqlSafe(setup))
        .execute(&pool)
        .await
        .expect("fixture table");
    let a = test_actor(&pool).await;
    let b = test_actor(&pool).await;
    for actor in [a, b] {
        // sql-safe: test-only insert into a generated table name
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "INSERT INTO {table} SELECT user_id, 'row' FROM actors WHERE id = $1"
        )))
        .bind(actor)
        .execute(&pool)
        .await
        .unwrap();
    }
    let count_as = |actor: Uuid| {
        let pool = pool.clone();
        let sql = format!("SELECT count(*) AS n FROM {table}");
        async move {
            let res = execute_guest_query_within(
                &pool,
                &sql,
                &[],
                true,
                GuestRoleSetting::Role("talos_guest"),
                actor,
                Duration::from_secs(10),
            )
            .await
            .expect("guest count");
            let rows: serde_json::Value = serde_json::from_str(&res.rows_json).unwrap();
            rows[0]["n"].as_i64().unwrap()
        }
    };
    assert_eq!(
        count_as(a).await,
        1,
        "actor A's owner sees one row, its own"
    );
    assert_eq!(
        count_as(b).await,
        1,
        "actor B's owner sees one row, its own"
    );

    // An actor that does not exist has no tenant: refused.
    match execute_guest_query_within(
        &pool,
        "SELECT 1 AS one",
        &[],
        true,
        GuestRoleSetting::Role("talos_guest"),
        Uuid::new_v4(),
        Duration::from_secs(10),
    )
    .await
    {
        Err(DatabaseRpcError::Unauthorized) => {}
        other => panic!("an unknown actor must be refused, got {other:?}"),
    }
    // sql-safe: test-only cleanup of a generated table name
    let _ = sqlx::raw_sql(sqlx::AssertSqlSafe(format!("DROP TABLE {table}")))
        .execute(&pool)
        .await;
}

#[tokio::test]
async fn a_guest_query_error_reaches_the_guest_as_one_sentence() {
    let Some(url) = database_url() else { return };
    let pool = pool(&url).await;
    let actor = test_actor(&pool).await;
    let raw = execute_guest_query_within(
        &pool,
        "SELECT no_such_column FROM actors",
        &[],
        true,
        GuestRoleSetting::Unset,
        actor,
        Duration::from_secs(10),
    )
    .await;
    match &raw {
        Err(DatabaseRpcError::QueryError(class)) => {
            assert_eq!(class, "sqlstate=42703", "only the SQLSTATE is kept");
        }
        other => panic!("expected a query error, got {other:?}"),
    }
    match guest_reply(raw, actor) {
        Err(DatabaseRpcError::QueryError(said)) => assert_eq!(said, GUEST_QUERY_FAILED),
        other => panic!("expected the generic reply, got {other:?}"),
    }
}
