//! Eleven RLS policies carried RFC 0004's transition arm `OR org_id IS NULL`
//! on tables whose `org_id` is never written (the M3 autostamp trigger was
//! scoped to four definition tables), so under `talos_app` they admitted every
//! row to every tenant. Migration `20260912140000` re-keys them on the tenant
//! column that IS written (`user_id`, plus a parent-derived arm). These tests
//! drive raw statements under `talos_app` — no app-layer predicate — so on
//! pristine main the isolation cases fail by assertion (count 1), and each has
//! an owner control beside it so `USING (false)` cannot pass.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use sqlx::Executor as _;
use uuid::Uuid;

struct Seeded {
    user: Uuid,
    workflow: Uuid,
    schedule: Uuid,
    module_exec: Uuid,
    credential: Uuid,
}

async fn seed_tenant(pool: &sqlx::PgPool) -> Seeded {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(user)
    .bind(format!("{user}@rls-arm.test"))
    .execute(pool)
    .await
    .expect("seed user");
    let tag = Uuid::new_v4();
    let org: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (name, slug, owner_id, is_personal) VALUES ($1, $2, $3, true) RETURNING id",
    )
    .bind(format!("armorg-{tag}"))
    .bind(format!("armorg-{tag}"))
    .bind(user)
    .fetch_one(pool)
    .await
    .expect("seed org");
    let workflow = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, org_id, name, module_uri, graph_json) VALUES ($1, $2, $3, $4, 'test://none', '{}'::jsonb)",
    )
    .bind(workflow)
    .bind(user)
    .bind(org)
    .bind(format!("armwf-{tag}"))
    .execute(pool)
    .await
    .expect("seed workflow");
    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name, org_id) VALUES ($1, $2, $3, $4)")
        .bind(actor)
        .bind(user)
        .bind(format!("armactor-{tag}"))
        .bind(org)
        .execute(pool)
        .await
        .expect("seed actor");
    let module: Uuid = sqlx::query_scalar(
        "INSERT INTO modules (name, kind, user_id) VALUES ($1, 'sandbox', $2) RETURNING id",
    )
    .bind(format!("armmod-{tag}"))
    .bind(user)
    .fetch_one(pool)
    .await
    .expect("seed module");
    // org_id deliberately left NULL on the three rows below — the shape of
    // every live row on the reference database.
    let schedule: Uuid = sqlx::query_scalar(
        "INSERT INTO workflow_schedules (workflow_id, user_id, cron_expression) VALUES ($1, $2, '0 * * * *') RETURNING id",
    )
    .bind(workflow)
    .bind(user)
    .fetch_one(pool)
    .await
    .expect("seed schedule");
    let module_exec: Uuid = sqlx::query_scalar(
        "INSERT INTO module_executions (module_id, user_id, status, trigger_type, actor_id) VALUES ($1, $2, 'completed', 'manual', $3) RETURNING id",
    )
    .bind(module)
    .bind(user)
    .bind(actor)
    .fetch_one(pool)
    .await
    .expect("seed module execution");
    let credential: Uuid = sqlx::query_scalar(
        "INSERT INTO integration_credentials (user_id, provider, provider_key) VALUES ($1, 'rls-probe', $2) RETURNING id",
    )
    .bind(user)
    .bind(format!("key-{tag}"))
    .fetch_one(pool)
    .await
    .expect("seed credential");
    Seeded {
        user,
        workflow,
        schedule,
        module_exec,
        credential,
    }
}

async fn as_user(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, user: Uuid) {
    (&mut **tx)
        .execute(
            format!(
                "SET LOCAL ROLE talos_app; SET LOCAL app.current_user_id = '{user}'; SET LOCAL app.current_org_ids = ''"
            )
            .as_str(),
        )
        .await
        .expect("set role + GUCs");
}

async fn count(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, sql: &str, id: Uuid) -> i64 {
    sqlx::query_scalar(sql)
        .bind(id)
        .fetch_one(&mut **tx)
        .await
        .expect("count")
}

const RETIRED: [&str; 11] = [
    "integration_credentials",
    "integration_state",
    "gmail_integrations",
    "google_calendar_integrations",
    "atlassian_integrations",
    "slack_integrations",
    "workflow_approval_gates",
    "workflow_schedules",
    "workflow_suspensions",
    "module_executions",
    "secret_audit_log",
];

/// The structural pin: every retired policy exists, its table is enabled and
/// forced, and neither its USING nor its WITH CHECK still carries the arm.
#[tokio::test]
async fn no_retired_policy_still_permits_a_null_org_id() {
    let (pool, _db) = common::isolated_db_pool().await;
    for table in RETIRED {
        let (enabled, forced): (bool, bool) = sqlx::query_as(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = $1::regclass",
        )
        .bind(table)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(enabled && forced, "{table}: RLS must be ENABLED and FORCED");
        let (qual, check): (String, Option<String>) = sqlx::query_as(
            "SELECT pg_get_expr(polqual, polrelid), pg_get_expr(polwithcheck, polrelid) FROM pg_policy WHERE polname = $1",
        )
        .bind(format!("{table}_tenant_isolation"))
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("{table}_tenant_isolation must exist: {e}"));
        assert!(
            !qual.contains("(org_id IS NULL)"),
            "{table}: USING still carries the permit arm: {qual}"
        );
        assert!(
            !check.as_deref().unwrap_or("").contains("(org_id IS NULL)"),
            "{table}: WITH CHECK still carries the permit arm"
        );
    }
}

/// Raw reads with NO app-layer predicate, under talos_app as user A, against
/// user B's org_id-NULL rows. Fails by assertion on pristine main (1 each).
#[tokio::test]
async fn another_tenants_null_org_rows_are_invisible_under_talos_app() {
    let (pool, _db) = common::isolated_db_pool().await;
    let a = seed_tenant(&pool).await;
    let b = seed_tenant(&pool).await;
    let mut tx = pool.begin().await.unwrap();
    as_user(&mut tx, a.user).await;
    assert_eq!(
        count(
            &mut tx,
            "SELECT COUNT(*) FROM workflow_schedules WHERE id = $1",
            b.schedule
        )
        .await,
        0,
        "schedule"
    );
    assert_eq!(
        count(
            &mut tx,
            "SELECT COUNT(*) FROM module_executions WHERE id = $1",
            b.module_exec
        )
        .await,
        0,
        "module execution"
    );
    assert_eq!(
        count(
            &mut tx,
            "SELECT COUNT(*) FROM integration_credentials WHERE id = $1",
            b.credential
        )
        .await,
        0,
        "credential"
    );
    // The production scoped reader, both layers in place: B's workflow id as A.
    let sched =
        talos_scheduler::get_schedule_for_accessor_on_conn(&mut tx, b.workflow, a.user, &[])
            .await
            .expect("scoped read");
    assert!(
        sched.is_none(),
        "user A must not read user B's schedule through the scoped reader"
    );
    tx.commit().await.unwrap();
}

/// CONTROL: the owner still reads every one of their own rows.
#[tokio::test]
async fn the_owner_still_reads_their_own_null_org_rows() {
    let (pool, _db) = common::isolated_db_pool().await;
    let a = seed_tenant(&pool).await;
    let mut tx = pool.begin().await.unwrap();
    as_user(&mut tx, a.user).await;
    assert_eq!(
        count(
            &mut tx,
            "SELECT COUNT(*) FROM workflow_schedules WHERE id = $1",
            a.schedule
        )
        .await,
        1
    );
    assert_eq!(
        count(
            &mut tx,
            "SELECT COUNT(*) FROM module_executions WHERE id = $1",
            a.module_exec
        )
        .await,
        1
    );
    assert_eq!(
        count(
            &mut tx,
            "SELECT COUNT(*) FROM integration_credentials WHERE id = $1",
            a.credential
        )
        .await,
        1
    );
    let sched =
        talos_scheduler::get_schedule_for_accessor_on_conn(&mut tx, a.workflow, a.user, &[])
            .await
            .expect("scoped read");
    assert_eq!(sched.map(|s| s.id), Some(a.schedule));
    tx.commit().await.unwrap();
}

/// The transition clause is kept: the scoped role with NO tenant GUC sees both
/// tenants' rows (engine / analytics posture).
#[tokio::test]
async fn the_scoped_role_without_a_tenant_guc_is_still_permitted_everything() {
    let (pool, _db) = common::isolated_db_pool().await;
    let a = seed_tenant(&pool).await;
    let b = seed_tenant(&pool).await;
    let mut tx = pool.begin().await.unwrap();
    (&mut *tx)
        .execute("SET LOCAL ROLE talos_app")
        .await
        .unwrap();
    for (sql, ids) in [
        (
            "SELECT COUNT(*) FROM workflow_schedules WHERE id = ANY($1)",
            [a.schedule, b.schedule],
        ),
        (
            "SELECT COUNT(*) FROM module_executions WHERE id = ANY($1)",
            [a.module_exec, b.module_exec],
        ),
        (
            "SELECT COUNT(*) FROM integration_credentials WHERE id = ANY($1)",
            [a.credential, b.credential],
        ),
    ] {
        let n: i64 = sqlx::query_scalar(sql)
            .bind(ids.to_vec())
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(n, 2, "{sql}");
    }
    tx.commit().await.unwrap();
}

/// WITH CHECK: a scoped upsert of a schedule under another tenant's workflow,
/// stamped with that tenant's user_id, is refused (42501); the owner's own lands.
#[tokio::test]
async fn a_scoped_schedule_write_is_bound_to_the_writer() {
    let (pool, _db) = common::isolated_db_pool().await;
    let a = seed_tenant(&pool).await;
    let b = seed_tenant(&pool).await;
    let mut tx = pool.begin().await.unwrap();
    as_user(&mut tx, a.user).await;
    sqlx::query("UPDATE workflow_schedules SET cron_expression = '5 * * * *' WHERE id = $1")
        .bind(a.schedule)
        .execute(&mut *tx)
        .await
        .expect("owner updates their own schedule");
    let err = sqlx::query(
        "INSERT INTO integration_credentials (user_id, provider, provider_key) VALUES ($1, 'rls-probe', 'forged')",
    )
    .bind(b.user)
    .execute(&mut *tx)
    .await
    .expect_err("a credential row minted for another user must be refused");
    let code = err
        .as_database_error()
        .and_then(|e| e.code().map(|c| c.to_string()));
    assert_eq!(
        code.as_deref(),
        Some("42501"),
        "expected an RLS WITH CHECK refusal, got {err}"
    );
    tx.rollback().await.unwrap();
}
