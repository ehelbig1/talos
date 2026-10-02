//! The ownership predicate on the two secret-delete statements, with row
//! security OUT of the picture.
//!
//! `secret_delete_under_rls_tests` runs as `talos_app`, where the `secrets`
//! policy hides another user's row before the statement's own predicate is
//! ever consulted — so dropping that predicate passes every test there. This
//! binary leaves the role switch off and connects as a role that bypasses row
//! security, so the predicate is the only thing refusing a stranger. A
//! deployment with `TALOS_RLS_SET_ROLE` off (the default) rests on it alone.
//!
//! A separate binary because the switch is read once per process. Each test
//! sets it OFF explicitly: a developer `.env` may turn it on, and the harness
//! loads that file.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use std::sync::Arc;

use controller::secrets::SecretsManager;
use uuid::Uuid;

/// Must run before the first scoped transaction: the switch is read once.
fn leave_row_security_unenforced() {
    std::env::set_var("TALOS_RLS_SET_ROLE", "0");
}

async fn seed_user(pool: &sqlx::PgPool) -> Uuid {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(user)
    .bind(format!("{user}@secret-predicate.test"))
    .execute(pool)
    .await
    .expect("seed user");
    user
}

/// The premise: inside a scoped transaction this connection still bypasses row
/// security. If it ever does not, this binary no longer pins the predicate and
/// must say so rather than pass.
async fn assert_row_security_is_bypassed(pool: &sqlx::PgPool, user: Uuid) {
    let mut tx = talos_db::begin_user_scoped(pool, user)
        .await
        .expect("scoped tx");
    let (role, bypasses): (String, bool) = sqlx::query_as(
        "SELECT rolname::text, rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("role attributes");
    assert!(
        bypasses,
        "this binary needs a connection that bypasses row security (and TALOS_RLS_SET_ROLE off); \
         the scoped transaction ran as `{role}`"
    );
}

#[tokio::test]
async fn a_stranger_cannot_delete_another_users_secret_by_path_or_by_id() {
    leave_row_security_unenforced();
    let (pool, _db) = common::isolated_db_pool().await;
    let secrets = Arc::new(SecretsManager::new(pool.clone()).expect("secrets manager"));
    secrets.initialize().await.expect("active DEK");
    let owner = seed_user(&pool).await;
    let stranger = seed_user(&pool).await;
    assert_row_security_is_bypassed(&pool, stranger).await;
    let path = "predicate/not-yours";
    let id = secrets
        .create_secret("not-yours", path, "v", None, owner, vec![], None)
        .await
        .expect("create");

    assert!(
        !secrets
            .delete_secret_if_present(path, Some(stranger), &[])
            .await
            .expect("a refused delete is not an error"),
        "by path: to a stranger the secret is not there"
    );
    assert!(
        !secrets
            .delete_secret_by_id(stranger, id)
            .await
            .expect("a refused delete is not an error"),
        "by id: a stranger's delete matches nothing"
    );

    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM secrets WHERE id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(left, 1, "the secret stays");
    let recorded: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM secret_audit_log WHERE secret_id = $1 AND action = 'delete'",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(recorded, 0, "a refused delete records nothing");
}

/// The control: the same two calls by the owner do delete, so the refusals
/// above are about WHO asked and not a statement that never matches.
#[tokio::test]
async fn the_owner_can_delete_by_path_and_by_id() {
    leave_row_security_unenforced();
    let (pool, _db) = common::isolated_db_pool().await;
    let secrets = Arc::new(SecretsManager::new(pool.clone()).expect("secrets manager"));
    secrets.initialize().await.expect("active DEK");
    let owner = seed_user(&pool).await;
    assert_row_security_is_bypassed(&pool, owner).await;
    let a = secrets
        .create_secret("a", "predicate/a", "v", None, owner, vec![], None)
        .await
        .expect("create");
    let b = secrets
        .create_secret("b", "predicate/b", "v", None, owner, vec![], None)
        .await
        .expect("create");

    assert!(secrets
        .delete_secret_if_present("predicate/a", Some(owner), &[])
        .await
        .expect("delete by path"));
    assert!(secrets
        .delete_secret_by_id(owner, b)
        .await
        .expect("delete by id"));

    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM secrets WHERE id = ANY($1)")
        .bind(vec![a, b])
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(left, 0);
}
