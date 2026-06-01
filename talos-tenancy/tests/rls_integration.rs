//! Postgres-backed integration test proving the `workflow_executions`
//! tenant-isolation RLS policy actually isolates orgs — the most critical
//! security property (a wrong policy is a cross-org data leak).
//!
//! It applies the REAL migration policy verbatim (`include_str!` of the
//! migration file, so the test can't drift from production), seeds executions
//! across two orgs, and verifies that under the read-scope GUCs a caller sees
//! ONLY their own + their org's executions — never the other org's. It also
//! confirms the permissive-when-unset rollout (no GUCs → all rows visible, the
//! engine/analytics path).
//!
//! Skipped (green) unless `TALOS_TEST_DATABASE_URL` points at a Postgres the
//! test may DROP/CREATE objects in. Run locally against a disposable PG:
//!
//! ```bash
//! docker run -d --rm -e POSTGRES_PASSWORD=test -e POSTGRES_DB=talos \
//!   -p 15433:5432 postgres:16-alpine
//! TALOS_TEST_DATABASE_URL=postgres://postgres:test@127.0.0.1:15433/talos \
//!   cargo test -p talos-tenancy --test rls_integration
//! ```

use sqlx::{Executor, PgPool, Row};
use talos_tenancy::{READ_ORGS_GUC, READ_USER_GUC};

/// The production RLS policy, verbatim — drift-proof.
const POLICY_MIGRATION: &str =
    include_str!("../../migrations/20260529200000_rls_workflow_executions_permissive.sql");

macro_rules! pool_or_skip {
    () => {
        match std::env::var("TALOS_TEST_DATABASE_URL") {
            Ok(url) => PgPool::connect(&url).await.expect("connect to test PG"),
            Err(_) => {
                eprintln!("skipping: TALOS_TEST_DATABASE_URL is not set");
                return;
            }
        }
    };
}

/// Fresh minimal schema + the real policy + a non-superuser role (RLS only
/// enforces for non-superusers / under SET ROLE). Returns (orgA, userA, exec_a,
/// orgB, userB, exec_b).
async fn setup(pool: &PgPool) -> (uuid::Uuid, uuid::Uuid, uuid::Uuid, uuid::Uuid, uuid::Uuid, uuid::Uuid) {
    // Idempotent teardown so reruns start clean.
    pool.execute(
        "DROP TABLE IF EXISTS workflow_executions CASCADE; \
         DROP TABLE IF EXISTS workflows CASCADE;",
    )
    .await
    .unwrap();

    // Minimal columns the policy touches.
    pool.execute(
        "CREATE TABLE workflows (id uuid PRIMARY KEY, org_id uuid, user_id uuid); \
         CREATE TABLE workflow_executions ( \
            id uuid PRIMARY KEY, workflow_id uuid, user_id uuid, org_id uuid);",
    )
    .await
    .unwrap();

    // Apply the REAL policy migration (multi-statement → simple protocol).
    sqlx::raw_sql(POLICY_MIGRATION).execute(pool).await.unwrap();

    // Non-superuser role for RLS enforcement (DROP first in case of a prior run).
    let _ = pool.execute("DROP OWNED BY rls_test_user; DROP ROLE IF EXISTS rls_test_user;").await;
    pool.execute(
        "CREATE ROLE rls_test_user NOSUPERUSER; \
         GRANT USAGE ON SCHEMA public TO rls_test_user; \
         GRANT SELECT ON workflows, workflow_executions TO rls_test_user;",
    )
    .await
    .unwrap();

    let (org_a, user_a, exec_a) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
    let (org_b, user_b, exec_b) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
    let wf_a = uuid::Uuid::new_v4();
    let wf_b = uuid::Uuid::new_v4();

    // Seeded as superuser (RLS bypassed for the writer).
    for (wf, org, user) in [(wf_a, org_a, user_a), (wf_b, org_b, user_b)] {
        sqlx::query("INSERT INTO workflows (id, org_id, user_id) VALUES ($1, $2, $3)")
            .bind(wf).bind(org).bind(user).execute(pool).await.unwrap();
    }
    for (exec, wf, user, org) in [(exec_a, wf_a, user_a, org_a), (exec_b, wf_b, user_b, org_b)] {
        sqlx::query(
            "INSERT INTO workflow_executions (id, workflow_id, user_id, org_id) VALUES ($1,$2,$3,$4)",
        )
        .bind(exec).bind(wf).bind(user).bind(org).execute(pool).await.unwrap();
    }

    (org_a, user_a, exec_a, org_b, user_b, exec_b)
}

/// Run a SELECT of all visible workflow_executions ids under the given read
/// scope, as the non-superuser role so RLS is enforced.
async fn visible_executions(
    pool: &PgPool,
    user_id: &str,
    org_ids: &str,
) -> Vec<uuid::Uuid> {
    // One connection/tx: set the read-scope GUCs, SET ROLE to the non-superuser
    // (RLS enforced), query, then unwind.
    let mut conn = pool.acquire().await.unwrap();
    conn.execute(format!("SET {READ_USER_GUC} = '{user_id}'").as_str()).await.unwrap();
    conn.execute(format!("SET {READ_ORGS_GUC} = '{org_ids}'").as_str()).await.unwrap();
    conn.execute("SET ROLE rls_test_user").await.unwrap();

    let rows = sqlx::query("SELECT id FROM workflow_executions ORDER BY id")
        .fetch_all(&mut *conn)
        .await
        .unwrap();

    conn.execute("RESET ROLE").await.unwrap();
    rows.into_iter().map(|r| r.get::<uuid::Uuid, _>("id")).collect()
}

#[tokio::test]
async fn rls_tenant_isolation_end_to_end() {
    let pool = pool_or_skip!();
    let (org_a, user_a, exec_a, org_b, _user_b, exec_b) = setup(&pool).await;

    // 1. Caller in org A sees ONLY org-A's execution — never org B's.
    let a = visible_executions(&pool, &user_a.to_string(), &org_a.to_string()).await;
    assert!(a.contains(&exec_a), "caller A must see their org's execution");
    assert!(
        !a.contains(&exec_b),
        "TENANT LEAK: caller A saw org B's execution {exec_b}"
    );
    assert_eq!(a.len(), 1, "caller A must see exactly their org's one execution");

    // 2. A caller scoped to org B sees ONLY org-B's execution (symmetry).
    let b = visible_executions(&pool, &uuid::Uuid::new_v4().to_string(), &org_b.to_string()).await;
    assert!(b.contains(&exec_b) && !b.contains(&exec_a), "TENANT LEAK across orgs");

    // 3. Permissive-when-unset: empty read scope (engine/analytics path) →
    //    the policy's `current_user_id IS NULL` clause makes it permissive, so
    //    ALL rows are visible (no false-hide of the internal cross-cutting reads).
    let all = visible_executions(&pool, "", "").await;
    assert!(
        all.contains(&exec_a) && all.contains(&exec_b),
        "permissive-when-unset path must see ALL rows, got {all:?}"
    );

    // Cleanup so the DB is reusable.
    let _ = pool
        .execute("DROP OWNED BY rls_test_user; DROP ROLE IF EXISTS rls_test_user;")
        .await;
}
