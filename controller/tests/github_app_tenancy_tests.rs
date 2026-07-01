//! Tenancy isolation for GitHub App installation-token resolution.
//!
//! `github_app:<owner>` secret paths mint an installation token via
//! `GithubAppInstallationRepository::get_active_by_account_for_user`, which is
//! scoped to the owning Talos user. This guards the boundary: a user must NOT be
//! able to resolve (and thus mint tokens against) another user's App install.
//! Before the per-user gate, resolution keyed on the GitHub owner login alone,
//! so any user who granted `github_app:<owner>` in a module's `allowed_secrets`
//! could mint a token against whichever user happened to own that install.

mod common;

use talos_github_repository::GithubAppInstallationRepository;
use uuid::Uuid;

async fn seed_user(pool: &sqlx::Pool<sqlx::Postgres>, id: Uuid, email: &str) {
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) \
         VALUES ($1, $2, 'not-a-real-hash', true) ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(email)
    .execute(pool)
    .await
    .expect("seed user");
}

#[tokio::test]
async fn github_app_installation_resolves_only_for_the_owning_user() {
    let (pool, _db) = common::isolated_db_pool().await;

    let owner_user = Uuid::new_v4();
    let other_user = Uuid::new_v4();
    seed_user(&pool, owner_user, "owner@tenancy.test").await;
    seed_user(&pool, other_user, "other@tenancy.test").await;

    let repo = GithubAppInstallationRepository::new(pool.clone());

    // `owner_user` installs the App on the GitHub org "acme-corp".
    repo.upsert(
        owner_user,
        987_654_321,
        "acme-corp",
        Some("Organization"),
        None,
        Some("all"),
    )
    .await
    .expect("seed installation");

    // The owning user resolves their own installation.
    let mine = repo
        .get_active_by_account_for_user("acme-corp", owner_user)
        .await
        .expect("lookup")
        .expect("owning user must resolve their own installation");
    assert_eq!(mine.user_id, owner_user);
    assert_eq!(mine.account_login, "acme-corp");

    // A DIFFERENT user must NOT resolve it — this is the tenancy boundary the
    // per-user gate enforces (pre-gate this returned the row and minted a token).
    let theirs = repo
        .get_active_by_account_for_user("acme-corp", other_user)
        .await
        .expect("lookup");
    assert!(
        theirs.is_none(),
        "a non-owning user must not resolve another user's github_app installation"
    );
}
