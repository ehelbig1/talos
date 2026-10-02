//! A user-scoped secret delete must work when row security is ENFORCED
//! (`TALOS_RLS_SET_ROLE` on, so the transaction runs as `talos_app`).
//!
//! `secret_audit_log`'s policy (migration `20260912140000`) admits a row only
//! while its parent secret exists. Both delete paths wrote the audit row AFTER
//! the `DELETE`, so under `talos_app` the insert was refused, the transaction
//! rolled back, and the secret stayed. Seen live 2026-10-02: an OAuth disconnect
//! logged "revoke + vault cleanup" complete and left both token entries in the
//! vault.
//!
//! Every test turns the role switch on FIRST and proves it took effect, so a
//! run where row security is not enforced fails instead of passing on the
//! unscoped path.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use std::sync::Arc;

use chrono::{Duration, Utc};
use controller::secrets::SecretsManager;
use talos_oauth::OAuthCredentialService;
use uuid::Uuid;

/// Must run before the first scoped transaction: the switch is read once.
fn enforce_row_security() {
    std::env::set_var("TALOS_RLS_SET_ROLE", "1");
}

struct World {
    pool: sqlx::PgPool,
    secrets: Arc<SecretsManager>,
    _db: common::TestDb,
}

async fn world() -> World {
    enforce_row_security();
    let (pool, _db) = common::isolated_db_pool().await;
    let secrets = Arc::new(SecretsManager::new(pool.clone()).expect("secrets manager"));
    secrets.initialize().await.expect("active DEK");
    World { pool, secrets, _db }
}

async fn seed_user(pool: &sqlx::PgPool) -> Uuid {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(user)
    .bind(format!("{user}@secret-delete.test"))
    .execute(pool)
    .await
    .expect("seed user");
    user
}

/// The scoped transaction really runs as the restricted role. Without this a
/// run with the switch off would pass every case below on the unscoped path.
async fn assert_role_is_enforced(pool: &sqlx::PgPool, user: Uuid) {
    let mut tx = talos_db::begin_user_scoped(pool, user)
        .await
        .expect("scoped tx");
    let role: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&mut *tx)
        .await
        .expect("current_user");
    assert_eq!(
        role, "talos_app",
        "the scoped transaction must run as talos_app for this test to mean anything"
    );
}

async fn secret_count(pool: &sqlx::PgPool, key_path: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM secrets WHERE key_path = $1")
        .bind(key_path)
        .fetch_one(pool)
        .await
        .expect("count secrets")
}

async fn delete_audit_rows(pool: &sqlx::PgPool, secret_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM secret_audit_log WHERE secret_id = $1 AND action = 'delete'",
    )
    .bind(secret_id)
    .fetch_one(pool)
    .await
    .expect("count audit rows")
}

#[tokio::test]
async fn the_owner_can_delete_a_secret_by_path_and_the_delete_is_recorded() {
    let w = world().await;
    let user = seed_user(&w.pool).await;
    assert_role_is_enforced(&w.pool, user).await;
    let path = "rls-delete/by-path";
    let id = w
        .secrets
        .create_secret("by-path", path, "v", None, user, vec![], None)
        .await
        .expect("create");

    w.secrets
        .delete_secret(path, Some(user), &[])
        .await
        .expect("the owner's delete must succeed under talos_app");

    assert_eq!(secret_count(&w.pool, path).await, 0, "the secret is gone");
    assert_eq!(
        delete_audit_rows(&w.pool, id).await,
        1,
        "the delete is recorded exactly once"
    );
}

#[tokio::test]
async fn the_owner_can_delete_a_secret_by_id_and_the_delete_is_recorded() {
    let w = world().await;
    let user = seed_user(&w.pool).await;
    assert_role_is_enforced(&w.pool, user).await;
    let path = "rls-delete/by-id";
    let id = w
        .secrets
        .create_secret("by-id", path, "v", None, user, vec![], None)
        .await
        .expect("create");

    let deleted = w
        .secrets
        .delete_secret_by_id(user, id)
        .await
        .expect("the owner's delete must succeed under talos_app");

    assert!(deleted, "the row matched and was removed");
    assert_eq!(secret_count(&w.pool, path).await, 0, "the secret is gone");
    assert_eq!(delete_audit_rows(&w.pool, id).await, 1);
}

/// The control for both paths: the fix must not make someone else's secret
/// deletable, and a refused delete records nothing.
#[tokio::test]
async fn another_user_cannot_delete_it_and_nothing_is_recorded() {
    let w = world().await;
    let owner = seed_user(&w.pool).await;
    let stranger = seed_user(&w.pool).await;
    assert_role_is_enforced(&w.pool, stranger).await;
    let path = "rls-delete/not-yours";
    let id = w
        .secrets
        .create_secret("not-yours", path, "v", None, owner, vec![], None)
        .await
        .expect("create");

    assert!(
        w.secrets
            .delete_secret(path, Some(stranger), &[])
            .await
            .is_err(),
        "a stranger's delete by path is refused"
    );
    assert!(
        !w.secrets
            .delete_secret_if_present(path, Some(stranger), &[])
            .await
            .expect("a refused delete is not an error"),
        "to a stranger the secret is not there"
    );
    assert!(
        !w.secrets
            .delete_secret_by_id(stranger, id)
            .await
            .expect("a refused delete is not an error"),
        "a stranger's delete by id matches nothing"
    );

    assert_eq!(secret_count(&w.pool, path).await, 1, "the secret stays");
    assert_eq!(delete_audit_rows(&w.pool, id).await, 0);
}

#[tokio::test]
async fn deleting_a_path_that_is_not_there_is_false_not_an_error() {
    let w = world().await;
    let user = seed_user(&w.pool).await;
    assert_role_is_enforced(&w.pool, user).await;

    assert!(!w
        .secrets
        .delete_secret_if_present("rls-delete/never-created", Some(user), &[])
        .await
        .expect("absence is an answer, not a failure"));
    assert!(
        w.secrets
            .delete_secret("rls-delete/never-created", Some(user), &[])
            .await
            .is_err(),
        "delete_secret keeps its contract: a missing secret is an error"
    );
}

/// The path that failed live. `atlassian` has no revoke endpoint, so the
/// disconnect makes no network call and the vault cleanup is all that stands
/// between a disconnect and a live token left in the vault.
#[tokio::test]
async fn an_oauth_disconnect_removes_both_token_entries() {
    let w = world().await;
    let user = seed_user(&w.pool).await;
    assert_role_is_enforced(&w.pool, user).await;
    let creds = OAuthCredentialService::new(w.pool.clone(), w.secrets.clone());
    creds
        .store_credentials(
            user,
            "atlassian",
            "cloud-1",
            "access-value",
            Some("refresh-value"),
            Utc::now() + Duration::hours(1),
            "read",
            vec![],
        )
        .await
        .expect("store credentials");
    let prefix = format!("oauth/atlassian/{user}/cloud-1/%");
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM secrets WHERE key_path LIKE $1")
        .bind(&prefix)
        .fetch_one(&w.pool)
        .await
        .unwrap();
    assert_eq!(stored, 2, "the access and refresh entries were stored");

    creds
        .revoke_and_cleanup(user, "atlassian", "cloud-1")
        .await
        .expect("disconnect");

    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM secrets WHERE key_path LIKE $1")
        .bind(&prefix)
        .fetch_one(&w.pool)
        .await
        .unwrap();
    assert_eq!(left, 0, "a disconnect leaves no token in the vault");
    let active: bool = sqlx::query_scalar(
        "SELECT is_active FROM integration_credentials WHERE user_id = $1 AND provider = 'atlassian'",
    )
    .bind(user)
    .fetch_one(&w.pool)
    .await
    .unwrap();
    assert!(!active, "the credential row is retired");
}

/// When a token entry cannot be deleted the disconnect says so: the entry is
/// still there, the call is an error, and the rest of the cleanup has still
/// run. The failure is induced by refusing the delete's audit row.
#[tokio::test]
async fn a_disconnect_that_cannot_delete_a_token_reports_it() {
    let w = world().await;
    let user = seed_user(&w.pool).await;
    assert_role_is_enforced(&w.pool, user).await;
    let creds = OAuthCredentialService::new(w.pool.clone(), w.secrets.clone());
    creds
        .store_credentials(
            user,
            "atlassian",
            "cloud-2",
            "access-value",
            Some("refresh-value"),
            Utc::now() + Duration::hours(1),
            "read",
            vec![],
        )
        .await
        .expect("store credentials");
    sqlx::raw_sql(
        "CREATE FUNCTION refuse_delete_audit() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN RAISE EXCEPTION 'audit row refused (test)'; END $$; \
         CREATE TRIGGER refuse_delete_audit BEFORE INSERT ON secret_audit_log \
         FOR EACH ROW WHEN (NEW.action = 'delete') EXECUTE FUNCTION refuse_delete_audit();",
    )
    .execute(&w.pool)
    .await
    .expect("install the refusing trigger");

    let outcome = creds.revoke_and_cleanup(user, "atlassian", "cloud-2").await;

    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM secrets WHERE key_path LIKE $1")
        .bind(format!("oauth/atlassian/{user}/cloud-2/%"))
        .fetch_one(&w.pool)
        .await
        .unwrap();
    assert_eq!(left, 2, "an unrecordable delete does not happen");
    let err = outcome.expect_err("a token left in the vault is reported, not called complete");
    assert!(err.to_string().contains("2 token entries"), "{err}");
    let active: bool = sqlx::query_scalar(
        "SELECT is_active FROM integration_credentials WHERE user_id = $1 AND provider = 'atlassian'",
    )
    .bind(user)
    .fetch_one(&w.pool)
    .await
    .unwrap();
    assert!(!active, "the credential row is retired all the same");
}
