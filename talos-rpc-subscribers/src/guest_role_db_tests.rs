//! The guest role (`TALOS_RPC_GUEST_ROLE`) on the real guest-SQL path,
//! `execute_guest_query_within`, against the MIGRATED database (CI:
//! `scripts/test-integration.sh`, kind `lib-migrated`), as a superuser:
//!
//! * with `talos_guest` the statement runs as it, and a table it holds no
//!   grant on is refused by Postgres;
//! * a setting that is not a role name refuses — it is not read as "no
//!   fence";
//! * a role that is a superuser or has BYPASSRLS refuses (it fences
//!   nothing), and so does one that does not exist or that the pool's user
//!   cannot enter;
//! * unset runs as the pool's user, the stated legacy posture.
use crate::{execute_guest_query_within, GuestRoleSetting};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Executor, PgPool};
use std::str::FromStr;
use std::time::Duration;
use talos_memory::database_rpc::{DatabaseResult, DatabaseRpcError};

const BUDGET: Duration = Duration::from_secs(10);

/// Role changes from two sessions at once can fail one of them ("tuple
/// concurrently updated"); the tests that make roles hold this.
static ROLES: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn database_url() -> Option<String> {
    std::env::var("TALOS_TEST_DATABASE_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
}

async fn pool(url: &str) -> PgPool {
    PgPoolOptions::new()
        .max_connections(2)
        .connect(url)
        .await
        .expect("connect")
}

fn tag() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..12].to_string()
}

async fn run(
    pool: &PgPool,
    sql: &str,
    role: GuestRoleSetting<'_>,
) -> Result<DatabaseResult, DatabaseRpcError> {
    execute_guest_query_within(pool, sql, &[], true, role, BUDGET).await
}

fn refused(result: Result<DatabaseResult, DatabaseRpcError>) -> String {
    match result {
        Err(DatabaseRpcError::ConnectionFailed(why)) => why,
        other => panic!("expected the guest role refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn guest_sql_runs_as_talos_guest_and_ungranted_tables_are_refused() {
    let Some(url) = database_url() else { return };
    let pool = pool(&url).await;
    let who = run(
        &pool,
        "SELECT current_user::text AS u",
        GuestRoleSetting::Role("talos_guest"),
    )
    .await
    .expect("a statement under the fence");
    assert!(
        who.rows_json.contains("\"talos_guest\""),
        "{}",
        who.rows_json
    );
    match run(
        &pool,
        "SELECT count(*) AS n FROM workflows",
        GuestRoleSetting::Role("talos_guest"),
    )
    .await
    {
        Err(DatabaseRpcError::QueryError(msg)) => {
            assert!(msg.contains("permission denied"), "{msg}")
        }
        other => panic!("an ungranted table must be refused, got {other:?}"),
    }
}

/// A set-but-invalid value refuses every query; until 2026-10-09 it ran
/// guest SQL as the app user.
#[tokio::test]
async fn an_invalid_setting_refuses_instead_of_running_unfenced() {
    let Some(url) = database_url() else { return };
    let pool = pool(&url).await;
    let setting = GuestRoleSetting::parse(Some("talos guest; DROP"));
    assert_eq!(setting, GuestRoleSetting::Invalid);
    let why = refused(run(&pool, "SELECT current_user::text AS u", setting).await);
    assert!(why.contains("not a valid role name"), "{why}");
}

#[tokio::test]
async fn a_role_that_fences_nothing_or_cannot_be_entered_refuses() {
    let Some(url) = database_url() else { return };
    let _roles = ROLES.lock().await;
    let pool = pool(&url).await;
    let superuser = format!("qp_guest_su_{}", tag());
    let bypass = format!("qp_guest_br_{}", tag());
    for sql in [
        format!("CREATE ROLE {superuser} NOLOGIN SUPERUSER"),
        format!("CREATE ROLE {bypass} NOLOGIN BYPASSRLS"),
    ] {
        pool.execute(sqlx::AssertSqlSafe(sql)).await.expect("role");
    }

    for role in [superuser.as_str(), bypass.as_str()] {
        let why = refused(
            run(
                &pool,
                "SELECT count(*) AS n FROM users",
                GuestRoleSetting::Role(role),
            )
            .await,
        );
        assert!(why.contains("superuser or has BYPASSRLS"), "{role}: {why}");
    }
    let missing = format!("qp_guest_absent_{}", tag());
    let why = refused(run(&pool, "SELECT 1 AS n", GuestRoleSetting::Role(&missing)).await);
    assert!(why.contains("does not exist"), "{why}");

    for role in [&superuser, &bypass] {
        let _ = pool
            .execute(sqlx::AssertSqlSafe(format!("DROP ROLE {role}")))
            .await;
    }
}

/// A pool whose user is not a member of the guest role cannot enter it:
/// refused, not run as that user.
#[tokio::test]
async fn a_pool_user_outside_the_guest_role_is_refused() {
    let Some(url) = database_url() else { return };
    let _roles = ROLES.lock().await;
    let admin = pool(&url).await;
    let login = format!("qp_guest_login_{}", tag());
    let password = format!("pw-{}", tag());
    admin
        .execute(sqlx::AssertSqlSafe(format!(
            "CREATE ROLE {login} LOGIN PASSWORD '{password}'"
        )))
        .await
        .expect("login");
    let options = PgConnectOptions::from_str(&url)
        .expect("url")
        .username(&login)
        .password(&password);
    let outsider = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("connect as the login");
    let why = refused(
        run(
            &outsider,
            "SELECT 1 AS n",
            GuestRoleSetting::Role("talos_guest"),
        )
        .await,
    );
    assert!(why.contains("permission denied"), "{why}");
    outsider.close().await;
    let _ = admin
        .execute(sqlx::AssertSqlSafe(format!("DROP ROLE {login}")))
        .await;
}

/// Unset is the legacy posture: the pool's user. Production refuses to boot
/// in it (`enforce_production_db_sandbox_posture`) unless acknowledged.
#[tokio::test]
async fn unset_runs_as_the_pool_user() {
    let Some(url) = database_url() else { return };
    let pool = pool(&url).await;
    let pool_user: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&pool)
        .await
        .expect("pool user");
    let who = run(
        &pool,
        "SELECT current_user::text AS u",
        GuestRoleSetting::Unset,
    )
    .await
    .expect("unset");
    assert!(
        who.rows_json.contains(&format!("\"{pool_user}\"")),
        "{}",
        who.rows_json
    );
}
