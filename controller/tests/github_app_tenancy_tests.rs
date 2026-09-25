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

use talos_github_repository::{
    ClaimTransition, GithubAppInstallationRepository, InstallationClaim, NewInstallationClaim,
};
use uuid::Uuid;

fn claim(user_id: Uuid, installation_id: i64, login: &str) -> NewInstallationClaim<'_> {
    NewInstallationClaim {
        user_id,
        installation_id,
        account_login: login,
        account_type: Some("Organization"),
        permissions: None,
        repository_selection: Some("all"),
    }
}

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
    let seeded = repo
        .claim_recorded(&claim(owner_user, 987_654_321, "acme-corp"))
        .await
        .expect("seed installation");
    assert!(matches!(seeded, InstallationClaim::Claimed { .. }));

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

async fn owner(pool: &sqlx::PgPool, installation_id: i64) -> (Uuid, bool) {
    sqlx::query_as(
        "SELECT user_id, is_active FROM github_app_installations WHERE installation_id = $1",
    )
    .bind(installation_id)
    .fetch_one(pool)
    .await
    .expect("installation row")
}

async fn claim_events(pool: &sqlx::PgPool) -> Vec<(Option<Uuid>, serde_json::Value)> {
    sqlx::query_as(
        "SELECT user_id, details FROM admin_event_log \
         WHERE event_type = 'github_installation_claimed' ORDER BY created_at, id",
    )
    .fetch_all(pool)
    .await
    .expect("admin events")
}

/// A second user cannot claim an installation another user actively holds —
/// the ownership half of the 2026-09-25 installation-takeover fix. Before it,
/// the claim was an upsert whose conflict arm set `user_id = EXCLUDED.user_id`
/// unconditionally, so this second claim MOVED the row (and `github_app:<owner>`
/// token minting) to the second user.
#[tokio::test]
async fn a_second_user_cannot_claim_an_existing_installation() {
    let (pool, _db) = common::isolated_db_pool().await;
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    seed_user(&pool, first, "first@claim.test").await;
    seed_user(&pool, second, "second@claim.test").await;
    let repo = GithubAppInstallationRepository::new(pool.clone());

    match repo
        .claim_recorded(&claim(first, 424_242, "acme-corp"))
        .await
        .unwrap()
    {
        InstallationClaim::Claimed { transition, .. } => {
            assert_eq!(transition, ClaimTransition::Created)
        }
        InstallationClaim::OwnedByAnotherUser => panic!("a first claim must succeed"),
    }

    // The takeover attempt.
    let second_try = repo
        .claim_recorded(&claim(second, 424_242, "renamed-by-attacker"))
        .await
        .unwrap();
    assert!(
        matches!(second_try, InstallationClaim::OwnedByAnotherUser),
        "an active installation owned by another user must not be reassigned"
    );
    assert_eq!(owner(&pool, 424_242).await, (first, true));
    let login: String = sqlx::query_scalar(
        "SELECT account_login FROM github_app_installations WHERE installation_id = $1",
    )
    .bind(424_242_i64)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        login, "acme-corp",
        "a refused claim must not rewrite the row's metadata either"
    );
    assert!(
        repo.get_active_by_account_for_user("acme-corp", second)
            .await
            .unwrap()
            .is_none(),
        "the second user must not be able to mint tokens against it"
    );
    assert_eq!(
        claim_events(&pool).await.len(),
        1,
        "a refused claim records nothing"
    );

    // The owner's own re-claim (re-install / permission change) still works.
    match repo
        .claim_recorded(&claim(first, 424_242, "acme-corp"))
        .await
        .unwrap()
    {
        InstallationClaim::Claimed { transition, .. } => {
            assert_eq!(transition, ClaimTransition::Refreshed)
        }
        InstallationClaim::OwnedByAnotherUser => panic!("the owner's own re-claim must succeed"),
    }

    // Once the owner disconnects, the installation is claimable again — the
    // only cross-user move, and it is recorded with the previous owner.
    assert_eq!(repo.deactivate(424_242, first).await.unwrap(), 1);
    match repo
        .claim_recorded(&claim(second, 424_242, "acme-corp"))
        .await
        .unwrap()
    {
        InstallationClaim::Claimed { transition, row } => {
            assert_eq!(transition, ClaimTransition::ReassignedFromInactive);
            assert_eq!(row.user_id, second);
        }
        InstallationClaim::OwnedByAnotherUser => {
            panic!("an INACTIVE installation may be claimed by a verified user")
        }
    }
    assert_eq!(owner(&pool, 424_242).await, (second, true));

    let events = claim_events(&pool).await;
    assert_eq!(
        events.len(),
        3,
        "created + refreshed + reassigned, each in its own transaction"
    );
    assert_eq!(events[2].0, Some(second));
    assert_eq!(events[2].1["transition"], "reassigned_from_inactive");
    assert_eq!(events[2].1["previous_user_id"], first.to_string());
    assert!(events[0].1["previous_user_id"].is_null());
}
