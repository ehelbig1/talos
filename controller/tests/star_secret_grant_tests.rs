//! A `*` secret grant grants nothing, and no row holds one (operator decision
//! D2-D, 2026-10-15; security review C-8). Until then `allowed_secrets: ["*"]`
//! delivered every secret the module's user could read — every OAuth access
//! token included — into each dispatch's envelope, and a second-factor
//! session could write it.
//!
//! * the repository writer refuses it for EVERY authority, with the sentence
//!   `SECRET_WILDCARD_RETIRED`; a `<prefix>/*` stays a session's to write;
//! * delivery fetches nothing for it;
//! * `modules_no_star_secret_grant` refuses a row that holds one, on either
//!   grant column, whoever writes it;
//! * the migration strips one from an existing row and keeps its other
//!   entries.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use talos_capability_world::{ChangeAuthority, SECRET_WILDCARD_RETIRED};
use uuid::Uuid;

const MIGRATION: &str =
    include_str!("../../migrations/20261015160000_modules_no_star_secret_grant.sql");

async fn seed_user(pool: &sqlx::PgPool) -> Uuid {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(user)
    .bind(format!("{user}@star-grant.test"))
    .execute(pool)
    .await
    .expect("seed user");
    user
}

async fn seed_module(pool: &sqlx::PgPool, user: Uuid, secrets: &[&str]) -> sqlx::Result<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO modules (id, user_id, name, kind, capability_world, allowed_secrets) \
         VALUES ($1, $2, $3, 'sandbox', 'http-node', $4)",
    )
    .bind(id)
    .bind(user)
    .bind(format!("star-probe-{}", &id.to_string()[..8]))
    .bind(secrets.iter().map(|s| (*s).to_string()).collect::<Vec<_>>())
    .execute(pool)
    .await?;
    Ok(id)
}

async fn grant(pool: &sqlx::PgPool, module: Uuid) -> Vec<String> {
    sqlx::query_scalar("SELECT allowed_secrets FROM modules WHERE id = $1")
        .bind(module)
        .fetch_one(pool)
        .await
        .expect("grant")
}

#[tokio::test]
async fn no_authority_writes_a_star_secret_grant() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let module = seed_module(&pool, user, &["svc/a"]).await.expect("seed");
    let repo = talos_module_repository::ModuleRepository::new(pool.clone());
    let keep = |_: &[String], new: &[String]| new.to_vec();
    let star = vec!["*".to_string()];
    for authority in [
        ChangeAuthority::SecondFactorSession,
        ChangeAuthority::BearerCredential,
    ] {
        let err = repo
            .update_module_allowed_secrets(module, user, &star, &keep, authority)
            .await
            .expect_err("refused");
        let refused = err
            .downcast_ref::<talos_module_repository::WildcardGrantRefused>()
            .expect("the grant refusal");
        assert_eq!(refused.0, SECRET_WILDCARD_RETIRED, "{authority:?}");
        assert_eq!(grant(&pool, module).await, vec!["svc/a"], "nothing written");
    }
    // A `<prefix>/*` is still a second-factor session's to write.
    let glob = vec!["svc/*".to_string()];
    repo.update_module_allowed_secrets(
        module,
        user,
        &glob,
        &keep,
        ChangeAuthority::SecondFactorSession,
    )
    .await
    .expect("written")
    .expect("owned");
    assert_eq!(grant(&pool, module).await, vec!["svc/*"]);
}

#[tokio::test]
async fn a_star_grant_delivers_nothing() {
    let (pool, _db) = common::isolated_db_pool().await;
    let sm = controller::secrets::SecretsManager::new(pool.clone()).expect("secrets");
    sm.initialize().await.expect("active DEK");
    let user = seed_user(&pool).await;
    for (name, path) in [
        ("a", "svc/a"),
        ("token", "oauth/gmail/made-up/access_token"),
    ] {
        sm.create_secret(name, path, "made-up-value", None, user, Vec::new(), None)
            .await
            .expect("secret");
    }
    let audit = talos_secrets_manager::PathReadAudit::NotRecorded;
    let star = sm
        .get_secrets_by_paths(&["*".to_string()], Some(user), audit)
        .await
        .expect("read");
    assert!(
        star.is_empty(),
        "a `*` grant fetched {} secret(s)",
        star.len()
    );
    let exact = sm
        .get_secrets_by_paths(&["svc/a".to_string()], Some(user), audit)
        .await
        .expect("read");
    assert_eq!(exact.len(), 1, "an exact path still delivers");
}

#[tokio::test]
async fn the_table_refuses_a_star_on_either_grant_column() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let err = seed_module(&pool, user, &["svc/a", "*"])
        .await
        .expect_err("refused by the table");
    assert!(
        err.to_string().contains("modules_no_star_secret_grant"),
        "{err}"
    );
    let module = seed_module(&pool, user, &["svc/*"])
        .await
        .expect("a glob is kept");
    let err = sqlx::query("UPDATE modules SET owner_added_secrets = ARRAY['*'] WHERE id = $1")
        .bind(module)
        .execute(&pool)
        .await
        .expect_err("refused by the table");
    assert!(
        err.to_string().contains("modules_no_star_secret_grant"),
        "{err}"
    );
}

/// The migration as shipped, run again over a row that holds `*` (the
/// constraint dropped first, as before the migration): the `*` goes, every
/// other entry stays, and the constraint is back.
#[tokio::test]
async fn the_migration_strips_a_star_and_keeps_the_rest() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    sqlx::query("ALTER TABLE modules DROP CONSTRAINT modules_no_star_secret_grant")
        .execute(&pool)
        .await
        .expect("drop");
    let module = seed_module(&pool, user, &["svc/a", "*", "oauth/gmail/*"])
        .await
        .expect("seed as before the migration");
    sqlx::query("UPDATE modules SET owner_added_secrets = ARRAY['*', 'svc/b'] WHERE id = $1")
        .bind(module)
        .execute(&pool)
        .await
        .expect("seed owner-added");
    sqlx::raw_sql(MIGRATION)
        .execute(&pool)
        .await
        .expect("migration");
    assert_eq!(grant(&pool, module).await, vec!["svc/a", "oauth/gmail/*"]);
    let owner_added: Vec<String> =
        sqlx::query_scalar("SELECT owner_added_secrets FROM modules WHERE id = $1")
            .bind(module)
            .fetch_one(&pool)
            .await
            .expect("owner-added");
    assert_eq!(owner_added, vec!["svc/b"]);
    assert!(
        seed_module(&pool, user, &["*"]).await.is_err(),
        "constraint back"
    );
}
