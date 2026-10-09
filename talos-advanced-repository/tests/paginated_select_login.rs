// ci-store: migrated — scripts/test-integration.sh runs this with that store (scripts/ci_test_targets.py)
//! `query_paginated` on a database login of its own
//! (`TALOS_ADMIN_QUERY_DATABASE_URL`, `AdminQueryLogin`), through the real
//! `AdvancedRepository::execute_paginated_select` on the migrated schema:
//!
//! * the statement runs as `talos_admin_read` with the tool's login as the
//!   session user — not the pool's — under the configured statement timeout,
//!   on a connection that is gone afterwards;
//! * a login that cannot be used is refused, and the statement never runs on
//!   the pool instead: unreachable (a wrong password), the pool's own login, a
//!   superuser, a login with another attribute, a member of another role, one
//!   that owns something or holds a grant of its own, and a setting that is
//!   not a Postgres URL; a login that is not a member of the role is refused
//!   as the role's refusal.
//!
//! Gated on `TALOS_TEST_DATABASE_URL` pointing at a MIGRATED database, as a
//! superuser (the test creates login roles and connects as them over the URL's
//! host, so the server must accept password logins there).

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Executor, Pool, Postgres, Row};
use std::str::FromStr;
use talos_advanced_repository::{
    AdminQueryLogin, AdvancedRepository, LoginRefusal, PaginatedSelectError, PaginationMode,
    QUERY_PAGINATED_ROLE,
};
use uuid::Uuid;

const OFFSET_0: PaginationMode<'static> = PaginationMode::Offset { offset: 0 };

/// Two GRANTs on one object from two sessions at once can fail one of them
/// ("tuple concurrently updated"); every test here changes roles, so each
/// holds this.
static ROLES: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn url() -> Option<String> {
    match std::env::var("TALOS_TEST_DATABASE_URL") {
        Ok(u) if !u.is_empty() => Some(u),
        _ => {
            eprintln!("SKIP: set TALOS_TEST_DATABASE_URL (migrated, superuser) to run paginated_select_login");
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

async fn run(admin: &Pool<Postgres>, statements: &[String]) {
    for sql in statements {
        admin
            .execute(sqlx::AssertSqlSafe(sql.clone()))
            .await
            .unwrap_or_else(|e| panic!("{sql}: {e}"));
    }
}

/// A login made for the tool: LOGIN and nothing else, a member of its role.
/// `extra` is run after it is made, to give it what a test needs it to hold.
async fn make_login(admin: &Pool<Postgres>, extra: &[&str]) -> (String, String) {
    let login = format!("qp_door_{}", tag());
    let password = format!("pw-{}", tag());
    let mut statements = vec![
        format!(
            "CREATE ROLE {login} LOGIN PASSWORD '{password}' NOSUPERUSER NOCREATEDB \
             NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT"
        ),
        format!("GRANT {QUERY_PAGINATED_ROLE} TO {login}"),
    ];
    statements.extend(extra.iter().map(|sql| sql.replace("{login}", &login)));
    run(admin, &statements).await;
    (login, password)
}

async fn drop_login(admin: &Pool<Postgres>, login: &str) {
    for sql in [
        format!("DROP OWNED BY {login}"),
        format!("DROP ROLE {login}"),
    ] {
        let _ = admin.execute(sqlx::AssertSqlSafe(sql)).await;
    }
}

fn repo_on_login(
    pool: Pool<Postgres>,
    url: &str,
    login: &str,
    password: &str,
    statement_timeout_secs: u64,
) -> AdvancedRepository {
    let options = PgConnectOptions::from_str(url)
        .expect("url")
        .username(login)
        .password(password);
    AdvancedRepository::new(pool)
        .with_admin_query_login(AdminQueryLogin::dedicated(options, statement_timeout_secs))
}

fn login_refusal(result: Result<Vec<sqlx::postgres::PgRow>, PaginatedSelectError>) -> LoginRefusal {
    match result {
        Err(PaginatedSelectError::LoginUnavailable { refusal, .. }) => refusal,
        Err(other) => panic!("expected the login refusal, got {other}"),
        Ok(rows) => panic!("expected the login refusal, got {} rows", rows.len()),
    }
}

/// The statement every refusal test asks for: a read the role may make, so a
/// refusal is the login's and nothing else's.
const GRANTED_READ: &str = "SELECT count(*) AS n FROM scratch_sessions";

#[tokio::test]
async fn the_statement_runs_as_the_role_on_the_tools_own_login() {
    let Some(url) = url() else { return };
    let admin = connect(&url).await;
    let _roles = ROLES.lock().await;
    let (login, password) = make_login(&admin, &[]).await;

    // Two tenants' rows in a row-secured table: both come back.
    let marker = format!("qp-login-{}", tag());
    let users = [Uuid::new_v4(), Uuid::new_v4()];
    for u in users {
        sqlx::query("INSERT INTO users (id, email, password_hash) VALUES ($1, $2, 'x')")
            .bind(u)
            .bind(format!("qp-{}@example.test", u.simple()))
            .execute(&admin)
            .await
            .expect("user");
        sqlx::query("INSERT INTO scratch_sessions (user_id, name, code) VALUES ($1, $2, 'x')")
            .bind(u)
            .bind(&marker)
            .execute(&admin)
            .await
            .expect("scratch session");
    }

    let repo = repo_on_login(connect(&url).await, &url, &login, &password, 37);
    let rows = repo
        .execute_paginated_select(
            &format!("SELECT user_id FROM scratch_sessions WHERE name = '{marker}'"),
            10,
            OFFSET_0,
        )
        .await
        .expect("a granted table on the tool's own login");
    assert_eq!(rows.len(), 2, "both tenants' rows");

    let row = repo
        .execute_paginated_select(
            "SELECT session_user::text AS login, current_user::text AS role, \
             current_setting('application_name') AS app, \
             current_setting('statement_timeout') AS timeout, \
             current_setting('idle_in_transaction_session_timeout') AS idle, \
             current_setting('transaction_read_only') AS read_only",
            10,
            OFFSET_0,
        )
        .await
        .expect("session settings")
        .remove(0);
    let get = |column: &str| -> String { row.try_get(column).expect(column) };
    assert_eq!(get("login"), login, "the session is the tool's login");
    assert_eq!(get("role"), QUERY_PAGINATED_ROLE);
    assert_eq!(get("app"), "talos_admin_query");
    assert_eq!(get("timeout"), "37s");
    assert_eq!(get("idle"), "1min");
    assert_eq!(get("read_only"), "on");

    // The connection is closed after each call: no session of the login stays.
    let mut left = -1_i64;
    for _ in 0..40 {
        left = sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE usename = $1")
            .bind(&login)
            .fetch_one(&admin)
            .await
            .expect("pg_stat_activity");
        if left == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(left, 0, "the login's connection outlived the call");

    let _ = sqlx::query("DELETE FROM scratch_sessions WHERE user_id = ANY($1)")
        .bind(&users[..])
        .execute(&admin)
        .await;
    let _ = sqlx::query("DELETE FROM users WHERE id = ANY($1)")
        .bind(&users[..])
        .execute(&admin)
        .await;
    drop_login(&admin, &login).await;
}

/// The pool sets `statement_timeout` when it connects; the tool's own
/// connection sets it for its transaction, from the same setting.
#[tokio::test]
async fn the_statement_timeout_bounds_a_statement_on_the_tools_own_login() {
    let Some(url) = url() else { return };
    let admin = connect(&url).await;
    let _roles = ROLES.lock().await;
    let (login, password) = make_login(&admin, &[]).await;
    let repo = repo_on_login(connect(&url).await, &url, &login, &password, 1);

    let err = repo
        .execute_paginated_select("SELECT pg_sleep(3) AS slept", 10, OFFSET_0)
        .await
        .expect_err("a statement longer than the timeout");
    let PaginatedSelectError::Database(e) = &err else {
        panic!("expected the database's cancellation, got {err}");
    };
    assert_eq!(
        e.as_database_error().and_then(|d| d.code()).as_deref(),
        Some("57014"),
        "{err}"
    );
    drop_login(&admin, &login).await;
}

/// Each way the tool's own login can be unusable is refused for what it is,
/// and the statement does not run on the pool instead.
#[tokio::test]
async fn a_login_that_cannot_be_used_is_refused_and_the_pool_is_not_used() {
    let Some(url) = url() else { return };
    let admin = connect(&url).await;
    let _roles = ROLES.lock().await;

    // A wrong password: no connection.
    let (login, _) = make_login(&admin, &[]).await;
    let repo = repo_on_login(connect(&url).await, &url, &login, "not-the-password", 60);
    assert_eq!(
        login_refusal(
            repo.execute_paginated_select(GRANTED_READ, 10, OFFSET_0)
                .await
        ),
        LoginRefusal::Unreachable
    );
    drop_login(&admin, &login).await;

    // The pool's own login, by name (the test's superuser here).
    let options = PgConnectOptions::from_str(&url).expect("url");
    let repo = AdvancedRepository::new(connect(&url).await)
        .with_admin_query_login(AdminQueryLogin::dedicated(options, 60));
    assert_eq!(
        login_refusal(
            repo.execute_paginated_select(GRANTED_READ, 10, OFFSET_0)
                .await
        ),
        LoginRefusal::IsThePoolLogin
    );

    let cases: [(&[&str], LoginRefusal); 6] = [
        (&["ALTER ROLE {login} SUPERUSER"], LoginRefusal::Superuser),
        (
            &["ALTER ROLE {login} CREATEROLE"],
            LoginRefusal::ExtraAttributes,
        ),
        (
            &["ALTER ROLE {login} BYPASSRLS"],
            LoginRefusal::ExtraAttributes,
        ),
        (
            &["GRANT pg_read_all_data TO {login}"],
            LoginRefusal::OtherMemberships,
        ),
        (
            &["GRANT SELECT ON public.workflows TO {login}"],
            LoginRefusal::HoldsObjectsOrGrants,
        ),
        (
            // Ownership, kept out of `public` so a failed run leaves nothing
            // for the grants test to find there.
            &["CREATE SCHEMA qp_owned_{login} AUTHORIZATION {login}"],
            LoginRefusal::HoldsObjectsOrGrants,
        ),
    ];
    for (extra, expected) in cases {
        let (login, password) = make_login(&admin, extra).await;
        let repo = repo_on_login(connect(&url).await, &url, &login, &password, 60);
        assert_eq!(
            login_refusal(
                repo.execute_paginated_select(GRANTED_READ, 10, OFFSET_0)
                    .await
            ),
            expected,
            "{extra:?}"
        );
        drop_login(&admin, &login).await;
    }

    // A setting that names no Postgres login.
    let repo = AdvancedRepository::new(connect(&url).await).with_admin_query_login(
        AdminQueryLogin::from_url(Some("mysql://someone:pw@db/talos"), false, 60),
    );
    assert!(matches!(
        login_refusal(
            repo.execute_paginated_select(GRANTED_READ, 10, OFFSET_0)
                .await
        ),
        LoginRefusal::Misconfigured(_)
    ));
}

/// A login that is not a member of the tool's role cannot enter it: refused
/// as the role's refusal, not run as the login.
#[tokio::test]
async fn a_login_outside_the_role_is_refused_by_the_role() {
    let Some(url) = url() else { return };
    let admin = connect(&url).await;
    let _roles = ROLES.lock().await;
    let (login, password) = make_login(
        &admin,
        &[&format!("REVOKE {QUERY_PAGINATED_ROLE} FROM {{login}}")],
    )
    .await;
    let repo = repo_on_login(connect(&url).await, &url, &login, &password, 60);
    match repo
        .execute_paginated_select(GRANTED_READ, 10, OFFSET_0)
        .await
    {
        Err(PaginatedSelectError::RoleUnavailable { detail, .. }) => {
            assert!(detail.contains("permission denied"), "{detail}");
        }
        Err(other) => panic!("expected the role refusal, got {other}"),
        Ok(rows) => panic!("expected the role refusal, got {} rows", rows.len()),
    }
    drop_login(&admin, &login).await;
}
