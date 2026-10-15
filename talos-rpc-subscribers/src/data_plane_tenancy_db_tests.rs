//! A durable state write names a live run, and guest SQL carries its tenant
//! (security review 2026-10-14, B-3 and B-4/D-2), against the MIGRATED
//! database (CI: `scripts/test-integration.sh`, kind `lib-migrated` — named
//! there since 2026-10-15, D2-2; before that the unit job ran it with no URL
//! and it returned green over zero assertions), as a superuser. Skipped
//! without `TALOS_TEST_DATABASE_URL`.
use crate::{
    apply_state_write, execute_guest_query_within, execution_state_delete, execution_state_write,
    guest_reply, test_actor, GuestRoleSetting, StateWriteVerdict, GUEST_CONNECTION_FAILED,
    GUEST_QUERY_FAILED,
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

/// A node's own `module_executions` row under `run`: the id a worker's
/// execution context holds as the job id.
async fn node_job(pool: &PgPool, run: Uuid) -> Uuid {
    let (user, actor): (Uuid, Uuid) =
        sqlx::query_as("SELECT user_id, actor_id FROM workflow_executions WHERE id = $1")
            .bind(run)
            .fetch_one(pool)
            .await
            .unwrap();
    let module = Uuid::new_v4();
    sqlx::query("INSERT INTO modules (id, name, kind, user_id) VALUES ($1, $2, 'sandbox', $3)")
        .bind(module)
        .bind(format!("state-node-{module}"))
        .bind(user)
        .execute(pool)
        .await
        .expect("seed module");
    let job = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO module_executions \
         (id, module_id, user_id, actor_id, status, trigger_type, workflow_execution_id) \
         VALUES ($1, $2, $3, $4, 'running', 'webhook', $5)",
    )
    .bind(job)
    .bind(module)
    .bind(user)
    .bind(actor)
    .bind(run)
    .execute(pool)
    .await
    .expect("seed module execution");
    job
}

/// The request is built exactly as the worker's `state::set` builds it, from
/// the two ids its execution context holds — the job's
/// `workflow_execution_id` and its `job_id` — and applied by the
/// subscriber's own function (security review 2026-10-15, B2-1: the worker
/// sent the job id, which names no run, and every honest write was refused).
#[tokio::test]
async fn a_state_write_built_as_the_worker_builds_it_lands_for_a_live_run() {
    use talos_memory::state_rpc::{StateWriteNotSent, StateWriteRequest};
    let Some(url) = database_url() else { return };
    let pool = pool(&url).await;
    talos_memory::rpc_auth::register_hmac_key(std::sync::Arc::new(vec![7u8; 32]));
    // The request a node of `run` sends, built from its context's two ids.
    let built = |run: Uuid, job: Uuid, actor: Uuid, value: Option<&str>| {
        StateWriteRequest::for_dispatch(
            &run.to_string(),
            &job.to_string(),
            actor,
            "talos://m:k",
            value,
        )
        .expect("a workflow node's write is sent")
    };
    let actor_of = |run: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Uuid>("SELECT actor_id FROM workflow_executions WHERE id = $1")
                .bind(run)
                .fetch_one(&pool)
                .await
                .unwrap()
        }
    };

    let run = execution(&pool, "running").await;
    let job = node_job(&pool, run).await;
    let actor = actor_of(run).await;
    let set = built(run, job, actor, Some("v"));
    set.verify().expect("the worker's request verifies");
    assert_eq!(
        apply_state_write(&pool, &set).await.unwrap(),
        StateWriteVerdict::Written
    );
    assert_eq!(state_rows(&pool, run).await, 1);
    assert_eq!(
        state_rows(&pool, job).await,
        0,
        "keyed on the run, not the job"
    );

    // The same request from a node of a run that has ended.
    let ended = execution(&pool, "completed").await;
    let ended_job = node_job(&pool, ended).await;
    let ended_actor = actor_of(ended).await;
    assert_eq!(
        apply_state_write(&pool, &built(ended, ended_job, ended_actor, Some("w")))
            .await
            .unwrap(),
        StateWriteVerdict::NotLive
    );
    assert_eq!(
        apply_state_write(&pool, &built(ended, ended_job, ended_actor, None))
            .await
            .unwrap(),
        StateWriteVerdict::NotLive
    );
    assert_eq!(
        state_rows(&pool, ended).await,
        0,
        "an ended run gains nothing"
    );

    // A module-bound dispatch names itself in both ids: it has no run and
    // sends nothing, so it never reaches the refusal counter.
    assert_eq!(
        StateWriteRequest::for_dispatch(
            &job.to_string(),
            &job.to_string(),
            actor,
            "talos://m:k",
            Some("v"),
        )
        .unwrap_err(),
        StateWriteNotSent::NoRun
    );
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

    // A guest role that does not exist: Postgres' refusal names the role,
    // and none of it reaches the guest (security review 2026-10-15, B2-5).
    let missing_role = format!(
        "no_such_guest_{}",
        &Uuid::new_v4().simple().to_string()[..8]
    );
    let raw = execute_guest_query_within(
        &pool,
        "SELECT 1 AS one",
        &[],
        true,
        GuestRoleSetting::Role(&missing_role),
        actor,
        Duration::from_secs(10),
    )
    .await;
    match &raw {
        Err(DatabaseRpcError::ConnectionFailed(detail)) => {
            assert!(
                detail.contains(&missing_role),
                "the detail names the role: {detail}"
            );
        }
        other => panic!("expected a connection failure, got {other:?}"),
    }
    match guest_reply(raw, actor) {
        Err(DatabaseRpcError::ConnectionFailed(said)) => {
            assert_eq!(said, GUEST_CONNECTION_FAILED);
        }
        other => panic!("expected the generic reply, got {other:?}"),
    }
}

/// Every row-security policy in `public` keys its reads on
/// `app.current_user_id` (security review 2026-10-15, D2-1). The guest
/// transaction sets the actor's owner there and an EMPTY org list; a policy
/// keyed only on the org list read that empty list as "unset" and admitted
/// every tenant's rows — `modules` and `webhook_triggers` did, so a
/// `GRANT SELECT ON modules TO talos_guest` showed every tenant's source and
/// grants. Asked of every policy, not only those on tables granted to
/// `talos_guest` today (none are, by default): a grant is one statement an
/// operator makes later.
#[tokio::test]
async fn every_row_security_policy_is_keyed_on_the_user() {
    let Some(url) = database_url() else { return };
    let pool = pool(&url).await;
    let unkeyed: Vec<(String, String)> = sqlx::query_as(
        "SELECT tablename::text, policyname::text FROM pg_policies \
         WHERE schemaname = 'public' \
           AND coalesce(qual, '') NOT LIKE '%app.current_user_id%' \
         ORDER BY 1, 2",
    )
    .fetch_all(&pool)
    .await
    .expect("pg_policies");
    assert!(
        unkeyed.is_empty(),
        "policies whose reads are not keyed on app.current_user_id: {unkeyed:?}"
    );
}

/// D2-1 driven through the guest path: two users each own a module, the
/// operator grants `modules` to the guest role, and each actor's query sees
/// its owner's module and the catalog's (decision D2-A: catalog rows are
/// public by design), never the other tenant's.
#[tokio::test]
async fn guest_sql_sees_only_its_owners_modules() {
    let Some(url) = database_url() else { return };
    let pool = pool(&url).await;
    let a = test_actor(&pool).await;
    let b = test_actor(&pool).await;
    let tag = Uuid::new_v4().simple().to_string();
    for actor in [a, b] {
        sqlx::query(
            "INSERT INTO modules (id, name, kind, user_id, source_code) \
             SELECT $1, $2, 'sandbox', user_id, 'fn secret() {}' FROM actors WHERE id = $3",
        )
        .bind(Uuid::new_v4())
        .bind(format!("guest-mod-{tag}-{actor}"))
        .bind(actor)
        .execute(&pool)
        .await
        .expect("seed module");
    }
    sqlx::query("INSERT INTO modules (id, name, kind) VALUES ($1, $2, 'catalog')")
        .bind(Uuid::new_v4())
        .bind(format!("guest-mod-{tag}-catalog"))
        .execute(&pool)
        .await
        .expect("seed catalog module");
    sqlx::raw_sql("GRANT SELECT ON modules TO talos_guest")
        .execute(&pool)
        .await
        .expect("grant");
    let names_as = |actor: Uuid| {
        let pool = pool.clone();
        let sql = format!("SELECT name FROM modules WHERE name LIKE 'guest-mod-{tag}-%'");
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
            .expect("guest read");
            let rows: serde_json::Value = serde_json::from_str(&res.rows_json).unwrap();
            let mut names = rows
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r["name"].as_str().unwrap().to_string())
                .collect::<Vec<_>>();
            names.sort();
            names
        }
    };
    let expected = |own: Uuid| {
        let mut v = vec![
            format!("guest-mod-{tag}-{own}"),
            format!("guest-mod-{tag}-catalog"),
        ];
        v.sort();
        v
    };
    let seen_a = names_as(a).await;
    let seen_b = names_as(b).await;
    let _ = sqlx::raw_sql("REVOKE SELECT ON modules FROM talos_guest")
        .execute(&pool)
        .await;
    assert_eq!(
        seen_a,
        expected(a),
        "A's owner sees its own module and the catalog's, not B's"
    );
    assert_eq!(
        seen_b,
        expected(b),
        "B's owner sees its own module and the catalog's, not A's"
    );
}
