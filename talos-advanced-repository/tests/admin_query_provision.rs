// ci-store: migrated — scripts/test-integration.sh runs this with that store (scripts/ci_test_targets.py)
//! `admin_query_provision` — what `controller admin-query-login provision |
//! disable` does — against the migrated schema, as the superuser the test
//! connects as (the controller's role on the operator's deployment):
//!
//! * a new login is made with LOGIN and nothing else, a member of the tool's
//!   role, its password stored only as a SCRAM-SHA-256 verifier, and the URL
//!   returned connects and passes the tool's per-call checks;
//! * provisioning again gives it a new password: the old URL is refused, the
//!   new one works;
//! * a login that already exists with an attribute beyond LOGIN is put back
//!   to LOGIN only; one that holds something else (another membership) is
//!   reported as refused, not stripped;
//! * disabling takes LOGIN away.
//!
//! Gated on `TALOS_TEST_DATABASE_URL` pointing at a MIGRATED database, as a
//! superuser, reached over a connection that checks passwords (the URL's host
//! must not be one `pg_hba.conf` trusts, or a refused password would pass).

use sqlx::postgres::PgPoolOptions;
use sqlx::{Connection, Executor, PgConnection, Pool, Postgres};
use talos_advanced_repository::admin_query_provision::{
    disable_login, provision_login, ProvisionError,
};
use uuid::Uuid;

/// Role changes from two sessions at once can fail one of them ("tuple
/// concurrently updated"); every test here changes roles.
static ROLES: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn url() -> Option<String> {
    match std::env::var("TALOS_TEST_DATABASE_URL") {
        Ok(u) if !u.is_empty() => Some(u),
        _ => {
            eprintln!("SKIP: set TALOS_TEST_DATABASE_URL (migrated, superuser) to run admin_query_provision");
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

fn login_name() -> String {
    format!("qp_prov_{}", &Uuid::new_v4().simple().to_string()[..12])
}

async fn drop_login(admin: &Pool<Postgres>, login: &str) {
    for sql in [
        format!("DROP OWNED BY {login}"),
        format!("DROP ROLE {login}"),
    ] {
        let _ = admin.execute(sqlx::AssertSqlSafe(sql)).await;
    }
}

async fn can_log_in(url: &str) -> bool {
    match PgConnection::connect(url).await {
        Ok(conn) => {
            let _ = conn.close().await;
            true
        }
        Err(_) => false,
    }
}

#[tokio::test]
async fn a_new_login_is_made_with_login_only_and_its_url_works() {
    let Some(url) = url() else { return };
    let _roles = ROLES.lock().await;
    let admin = connect(&url).await;
    let login = login_name();

    let made = provision_login(&admin, &url, &login, false, 60)
        .await
        .expect("provision");
    assert!(made.created);
    assert!(
        made.url.contains(&format!("//{login}:")),
        "the URL names the login"
    );
    assert!(can_log_in(&made.url).await, "the URL connects");

    let (attrs, stored): (String, String) = sqlx::query_as(
        "SELECT concat_ws(',', rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, \
                rolreplication, rolbypassrls, rolinherit), rolpassword \
         FROM pg_authid WHERE rolname = $1",
    )
    .bind(&login)
    .fetch_one(&admin)
    .await
    .expect("pg_authid");
    assert_eq!(attrs, "t,f,f,f,f,f,f", "LOGIN and nothing else, NOINHERIT");
    assert!(stored.starts_with("SCRAM-SHA-256$4096:"), "{stored:.20}");
    let password = made
        .url
        .split_once(&format!("//{login}:"))
        .and_then(|(_, rest)| rest.split_once('@'))
        .map(|(p, _)| p.to_string())
        .expect("password in the URL");
    assert!(!stored.contains(&password), "only the verifier is stored");

    let member: bool = sqlx::query_scalar("SELECT pg_has_role($1, 'talos_admin_read', 'MEMBER')")
        .bind(&login)
        .fetch_one(&admin)
        .await
        .expect("membership");
    assert!(member);
    drop_login(&admin, &login).await;
}

#[tokio::test]
async fn provisioning_again_rotates_the_password() {
    let Some(url) = url() else { return };
    let _roles = ROLES.lock().await;
    let admin = connect(&url).await;
    let login = login_name();

    let first = provision_login(&admin, &url, &login, false, 60)
        .await
        .expect("first");
    let second = provision_login(&admin, &url, &login, false, 60)
        .await
        .expect("second");
    assert!(!second.created);
    assert_ne!(first.url.as_str(), second.url.as_str());
    assert!(!can_log_in(&first.url).await, "the old password is refused");
    assert!(can_log_in(&second.url).await, "the new password works");
    drop_login(&admin, &login).await;
}

/// An existing login with CREATEDB is put back to LOGIN only. One that
/// belongs to another role is not stripped: the tool's checks refuse it and
/// provisioning says so.
#[tokio::test]
async fn an_existing_login_is_normalised_but_not_stripped() {
    let Some(url) = url() else { return };
    let _roles = ROLES.lock().await;
    let admin = connect(&url).await;

    let login = login_name();
    admin
        .execute(sqlx::AssertSqlSafe(format!(
            "CREATE ROLE {login} LOGIN CREATEDB INHERIT"
        )))
        .await
        .expect("pre-existing login");
    let made = provision_login(&admin, &url, &login, false, 60)
        .await
        .expect("normalised");
    assert!(!made.created);
    let (createdb, inherit): (bool, bool) =
        sqlx::query_as("SELECT rolcreatedb, rolinherit FROM pg_roles WHERE rolname = $1")
            .bind(&login)
            .fetch_one(&admin)
            .await
            .expect("pg_roles");
    assert!(!createdb && !inherit);
    drop_login(&admin, &login).await;

    let login = login_name();
    for sql in [
        format!("CREATE ROLE {login} LOGIN"),
        format!("GRANT pg_read_all_data TO {login}"),
    ] {
        admin
            .execute(sqlx::AssertSqlSafe(sql))
            .await
            .expect("pre-existing login");
    }
    match provision_login(&admin, &url, &login, false, 60).await {
        Err(ProvisionError::Refused(why)) => {
            assert!(why.contains("belongs to a role other than"), "{why}");
        }
        other => panic!("expected the tool's refusal, got {other:?}"),
    }
    let still_member: bool =
        sqlx::query_scalar("SELECT pg_has_role($1, 'pg_read_all_data', 'MEMBER')")
            .bind(&login)
            .fetch_one(&admin)
            .await
            .expect("membership");
    assert!(still_member, "nothing the operator granted is removed");
    drop_login(&admin, &login).await;
}

#[tokio::test]
async fn production_refuses_a_url_without_tls_before_touching_the_database() {
    let Some(url) = url() else { return };
    let _roles = ROLES.lock().await;
    let admin = connect(&url).await;
    let login = login_name();
    if url.contains("sslmode=") {
        eprintln!("SKIP: the test URL pins an sslmode");
        return;
    }
    match provision_login(&admin, &url, &login, true, 60).await {
        Err(ProvisionError::Misconfigured(why)) => assert!(why.contains("sslmode"), "{why}"),
        other => panic!("expected the TLS refusal, got {other:?}"),
    }
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)")
            .bind(&login)
            .fetch_one(&admin)
            .await
            .expect("pg_roles");
    assert!(!exists, "nothing was made");
}

#[tokio::test]
async fn disabling_takes_login_away() {
    let Some(url) = url() else { return };
    let _roles = ROLES.lock().await;
    let admin = connect(&url).await;
    let login = login_name();

    let made = provision_login(&admin, &url, &login, false, 60)
        .await
        .expect("provision");
    assert!(disable_login(&admin, &login).await.expect("disable"));
    assert!(
        !can_log_in(&made.url).await,
        "a disabled login cannot connect"
    );
    let again = provision_login(&admin, &url, &login, false, 60)
        .await
        .expect("provision restores it");
    assert!(can_log_in(&again.url).await);
    drop_login(&admin, &login).await;
    assert!(!disable_login(&admin, &login).await.expect("absent"));
}
