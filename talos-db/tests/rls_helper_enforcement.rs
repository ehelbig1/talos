//! Proves the PRODUCTION helper `talos_db::begin_tenant_read_scoped` (not a
//! hand-written `SET LOCAL ROLE`) ENFORCES the RFC 0004 RLS policies when
//! `TALOS_RLS_SET_ROLE=1` — even on a superuser connection (the in-cluster
//! Postgres default). This closes the loop between two facts proven
//! elsewhere:
//!   * lint check 25: every talos-api resolver runs RLS-table queries
//!     through a scoped-tx helper, never the bare pool;
//!   * rls_org_isolation.rs: the policies isolate by tenant.
//! What was untested until now is the LINK — that the helper resolvers
//! call actually activates the policies when the flag is on. It does so by
//! issuing `SET LOCAL ROLE talos_app`, which this test confirms directly
//! (`current_user` becomes `talos_app` inside the tx) and by effect
//! (another tenant's row is invisible).
//!
//! Lives in its OWN test binary so the flag's process-global `LazyLock`
//! captures `1` cleanly (set before the first helper call). Gated on
//! `TALOS_TEST_DATABASE_URL` (must be a superuser); skips when unset.

use sqlx::{postgres::PgPoolOptions, Executor, Pool, Postgres};
use talos_db::begin_tenant_read_scoped;
use talos_tenancy::TenantReadScope;
use uuid::Uuid;

fn superuser_url() -> Option<String> {
    std::env::var("TALOS_TEST_DATABASE_URL")
        .ok()
        .filter(|u| !u.is_empty())
}

async fn connect(url: &str) -> Pool<Postgres> {
    PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(url)
        .await
        .expect("connect")
}

#[tokio::test]
async fn begin_tenant_read_scoped_enforces_rls_when_flag_on() {
    let Some(su_url) = superuser_url() else {
        return;
    };
    // MUST precede the first helper call so the flag's LazyLock captures it.
    // Safe: single-threaded prologue, before any other thread touches env.
    std::env::set_var("TALOS_RLS_SET_ROLE", "1");

    let su = connect(&su_url).await;
    let user_a = Uuid::new_v4();
    let user_b = Uuid::new_v4();
    let wf = Uuid::new_v4();

    sqlx::query("INSERT INTO users (id, email, password_hash, name) VALUES ($1,$2,'x','ha')")
        .bind(user_a)
        .bind(format!("ha-{}@test.invalid", user_a.simple()))
        .execute(&su)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, module_uri, graph_json) \
         VALUES ($1, $2, 'h', 'mod://x', '{}'::jsonb)",
    )
    .bind(wf)
    .bind(user_a)
    .execute(&su)
    .await
    .unwrap();

    // Helper scoped to a DIFFERENT user (B) on the SUPERUSER pool. With the
    // flag on it issues `SET LOCAL ROLE talos_app`, so RLS enforces.
    let mut tx = begin_tenant_read_scoped(&su, &TenantReadScope::new(user_b, Vec::new()))
        .await
        .expect("scoped tx");
    // Direct confirmation the helper dropped the session role to talos_app.
    let role: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(
        role, "talos_app",
        "begin_tenant_read_scoped must SET LOCAL ROLE talos_app when TALOS_RLS_SET_ROLE is on"
    );
    let b_sees: i64 = sqlx::query_scalar("SELECT count(*) FROM workflows WHERE id = $1")
        .bind(wf)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        b_sees, 0,
        "the helper + flag must hide another tenant's workflow even on a superuser connection"
    );

    // Owner A sees it via the same helper (positive control).
    let mut tx = begin_tenant_read_scoped(&su, &TenantReadScope::new(user_a, Vec::new()))
        .await
        .unwrap();
    let a_sees: i64 = sqlx::query_scalar("SELECT count(*) FROM workflows WHERE id = $1")
        .bind(wf)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(a_sees, 1, "owner must see own workflow through the helper");

    let _ = sqlx::query("DELETE FROM workflows WHERE id = $1")
        .bind(wf)
        .execute(&su)
        .await;
    let _ = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_a)
        .execute(&su)
        .await;
}
