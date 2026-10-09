// ci-store: migrated — scripts/test-integration.sh runs this with that store (scripts/ci_test_targets.py)
//! What the ROLE a `query_paginated` statement runs as does, through the real
//! `AdvancedRepository::execute_paginated_select`, on the migrated schema
//! (`migrations/20261008200000_talos_admin_read_role.sql`):
//!
//! * a granted, row-secured table is read across tenants — every row, not the
//!   rows a tenant context would admit (without BYPASSRLS a role reads 0 of
//!   them, silently);
//! * a table the role is not granted is refused by Postgres, and the error
//!   says which;
//! * when the role cannot be used — missing, the pool's role not a member,
//!   lacking BYPASSRLS, a superuser — the call is refused and the caller's
//!   statement never runs as anyone.
//!
//! Gated on `TALOS_TEST_DATABASE_URL` pointing at a MIGRATED database, as a
//! superuser (the test creates roles).

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Executor, Pool, Postgres, Row};
use std::str::FromStr;
use talos_admin_query_gate::BLOCKED_TABLES_LIST;
use talos_advanced_repository::{
    ungranted_relation, AdvancedRepository, PaginatedSelectError, PaginationMode,
    QUERY_PAGINATED_ROLE,
};
use uuid::Uuid;

const OFFSET_0: PaginationMode<'static> = PaginationMode::Offset { offset: 0 };

/// Two GRANTs on one object from two sessions at once can fail one of them
/// ("tuple concurrently updated"); the tests that grant hold this.
static GRANTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn url() -> Option<String> {
    match std::env::var("TALOS_TEST_DATABASE_URL") {
        Ok(u) if !u.is_empty() => Some(u),
        _ => {
            eprintln!("SKIP: set TALOS_TEST_DATABASE_URL (migrated, superuser) to run paginated_select_role");
            None
        }
    }
}

async fn connect(url: &str) -> Pool<Postgres> {
    PgPoolOptions::new()
        .max_connections(2)
        .connect(url)
        .await
        .expect("connect")
}

fn tag() -> String {
    Uuid::new_v4().simple().to_string()[..12].to_string()
}

/// Two made-up users and one scratch session each, all under one marker.
async fn seed_two_tenants(admin: &Pool<Postgres>, marker: &str) -> [Uuid; 2] {
    let users = [Uuid::new_v4(), Uuid::new_v4()];
    for u in users {
        sqlx::query("INSERT INTO users (id, email, password_hash) VALUES ($1, $2, 'x')")
            .bind(u)
            .bind(format!("qp-{}@example.test", u.simple()))
            .execute(admin)
            .await
            .expect("user");
        sqlx::query("INSERT INTO scratch_sessions (user_id, name, code) VALUES ($1, $2, 'x')")
            .bind(u)
            .bind(marker)
            .execute(admin)
            .await
            .expect("scratch session");
    }
    users
}

async fn unseed(admin: &Pool<Postgres>, users: [Uuid; 2]) {
    let _ = sqlx::query("DELETE FROM scratch_sessions WHERE user_id = ANY($1)")
        .bind(&users[..])
        .execute(admin)
        .await;
    let _ = sqlx::query("DELETE FROM users WHERE id = ANY($1)")
        .bind(&users[..])
        .execute(admin)
        .await;
}

fn role_refusal(result: Result<Vec<sqlx::postgres::PgRow>, PaginatedSelectError>) -> String {
    match result {
        Err(PaginatedSelectError::RoleUnavailable { detail, .. }) => detail,
        Err(other) => panic!("expected the role refusal, got {other}"),
        Ok(rows) => panic!("expected the role refusal, got {} rows", rows.len()),
    }
}

/// `scratch_sessions` is row-secured and its policy admits nothing without a
/// tenant context. Under the tool's role both tenants' rows come back.
#[tokio::test]
async fn a_granted_row_secured_table_is_read_across_tenants() {
    let Some(url) = url() else { return };
    let admin = connect(&url).await;
    let marker = format!("qp-role-{}", tag());
    let users = seed_two_tenants(&admin, &marker).await;
    let repo = AdvancedRepository::new(connect(&url).await);

    let rows = repo
        .execute_paginated_select(
            &format!("SELECT user_id FROM scratch_sessions WHERE name = '{marker}'"),
            10,
            OFFSET_0,
        )
        .await
        .expect("a granted table");
    let mut read: Vec<Uuid> = rows
        .iter()
        .map(|r| r.try_get("user_id").expect("user_id"))
        .collect();
    read.sort();
    let mut expected = users.to_vec();
    expected.sort();
    assert_eq!(read, expected, "both tenants' rows, not a tenant's");

    let who: String = repo
        .execute_paginated_select("SELECT current_user::text AS who", 10, OFFSET_0)
        .await
        .expect("current_user")[0]
        .try_get("who")
        .expect("who");
    assert_eq!(who, QUERY_PAGINATED_ROLE);
    unseed(&admin, users).await;
}

/// A table the role holds no grant on is refused by Postgres's own privilege
/// check, whatever the gate in front of it admitted, and the refusal names it.
/// Every table `BLOCKED_TABLES_LIST` withholds that exists in the schema is
/// asked (some names are kept on the list after their table was dropped).
#[tokio::test]
async fn a_table_the_role_is_not_granted_is_refused_by_postgres() {
    let Some(url) = url() else { return };
    let admin = connect(&url).await;
    let repo = AdvancedRepository::new(connect(&url).await);
    let mut asked = 0;
    for table in BLOCKED_TABLES_LIST {
        let exists: bool = sqlx::query_scalar("SELECT to_regclass('public.' || $1) IS NOT NULL")
            .bind(table)
            .fetch_one(&admin)
            .await
            .expect("to_regclass");
        if !exists {
            continue;
        }
        asked += 1;
        let err = repo
            .execute_paginated_select(&format!("SELECT count(*) AS n FROM {table}"), 10, OFFSET_0)
            .await
            .expect_err(table);
        assert_eq!(ungranted_relation(&err).as_deref(), Some(*table), "{err}");
    }
    assert!(
        asked >= 15,
        "only {asked} withheld tables exist in the schema"
    );
    let err = repo
        .execute_paginated_select("SELECT count(*) AS n FROM pg_authid", 10, OFFSET_0)
        .await
        .expect_err("pg_authid");
    assert_eq!(ungranted_relation(&err).as_deref(), Some("pg_authid"));
}

#[tokio::test]
async fn the_call_is_refused_when_the_role_is_missing() {
    let Some(url) = url() else { return };
    let repo = AdvancedRepository::new(connect(&url).await);
    let absent = format!("qp_absent_{}", tag());
    let detail = role_refusal(
        repo.execute_paginated_select_as_role(&absent, "SELECT 1 AS one", 10, OFFSET_0)
            .await,
    );
    assert!(detail.contains("does not exist"), "{detail}");
}

/// A role that exists but lacks BYPASSRLS would read row-secured tables
/// short; a superuser role would be no boundary. Both are refused.
#[tokio::test]
async fn the_call_is_refused_as_a_role_without_bypassrls_or_a_superuser() {
    let Some(url) = url() else { return };
    let admin = connect(&url).await;
    let repo = AdvancedRepository::new(connect(&url).await);
    let _grants = GRANTS.lock().await;
    let plain = format!("qp_plain_{}", tag());
    let superuser = format!("qp_super_{}", tag());
    for sql in [
        format!("CREATE ROLE {plain} NOLOGIN NOINHERIT"),
        format!("GRANT SELECT ON scratch_sessions TO {plain}"),
        format!("CREATE ROLE {superuser} NOLOGIN SUPERUSER BYPASSRLS"),
    ] {
        admin
            .execute(sqlx::AssertSqlSafe(sql))
            .await
            .expect("role setup");
    }

    let detail = role_refusal(
        repo.execute_paginated_select_as_role(
            &plain,
            "SELECT count(*) AS n FROM scratch_sessions",
            10,
            OFFSET_0,
        )
        .await,
    );
    assert!(detail.contains("BYPASSRLS"), "{detail}");
    let detail = role_refusal(
        repo.execute_paginated_select_as_role(&superuser, "SELECT 1 AS one", 10, OFFSET_0)
            .await,
    );
    assert!(detail.contains("superuser"), "{detail}");

    for sql in [
        format!("REVOKE ALL ON scratch_sessions FROM {plain}"),
        format!("DROP ROLE {plain}"),
        format!("DROP ROLE {superuser}"),
    ] {
        let _ = admin.execute(sqlx::AssertSqlSafe(sql)).await;
    }
}

/// On a deployment whose pool connects as a role that is NOT a member of the
/// tool's role (a managed Postgres where the migration could not grant it),
/// the call is refused — it does not run as the pool's role instead.
#[tokio::test]
async fn the_call_is_refused_when_the_pool_role_is_not_a_member() {
    let Some(url) = url() else { return };
    let admin = connect(&url).await;
    let _grants = GRANTS.lock().await;
    let login = format!("qp_login_{}", tag());
    let password = format!("pw-{}", tag());
    for sql in [
        format!("CREATE ROLE {login} LOGIN PASSWORD '{password}'"),
        format!("GRANT SELECT ON scratch_sessions TO {login}"),
    ] {
        admin
            .execute(sqlx::AssertSqlSafe(sql))
            .await
            .expect("login role");
    }
    let options = PgConnectOptions::from_str(&url)
        .expect("url")
        .username(&login)
        .password(&password);
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("connect as the login role");
    let repo = AdvancedRepository::new(pool.clone());

    let detail = role_refusal(
        repo.execute_paginated_select("SELECT count(*) AS n FROM scratch_sessions", 10, OFFSET_0)
            .await,
    );
    assert!(detail.contains("permission denied"), "{detail}");
    pool.close().await;

    for sql in [
        format!("REVOKE ALL ON scratch_sessions FROM {login}"),
        format!("DROP ROLE {login}"),
    ] {
        let _ = admin.execute(sqlx::AssertSqlSafe(sql)).await;
    }
}
