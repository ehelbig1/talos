//! A personal organization has exactly one member, its owner (security review
//! 2026-10-14, A-1). Every org-less resource a user creates is stamped with
//! their personal org, so a second member would see — and an Admin would
//! change — everything they own. The service refuses, and the database
//! refuses for any other writer.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use talos_organizations::{OrgRole, OrganizationService, PERSONAL_ORG_REFUSAL};
use uuid::Uuid;

async fn seed_user(pool: &sqlx::PgPool) -> Uuid {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(user)
    .bind(format!("{user}@personal-org.test"))
    .execute(pool)
    .await
    .expect("seed user");
    user
}

async fn members(pool: &sqlx::PgPool, org: Uuid) -> Vec<Uuid> {
    sqlx::query_scalar(
        "SELECT user_id FROM organization_members WHERE org_id = $1 ORDER BY user_id",
    )
    .bind(org)
    .fetch_all(pool)
    .await
    .expect("members")
}

#[tokio::test]
async fn nobody_joins_a_personal_organization() {
    let (pool, _db) = common::isolated_db_pool().await;
    let owner = seed_user(&pool).await;
    let other = seed_user(&pool).await;
    let personal = OrganizationService::create_personal_org(&pool, owner, None)
        .await
        .expect("personal org");
    assert_eq!(members(&pool, personal.id).await, vec![owner]);

    for role in [OrgRole::Member, OrgRole::Admin, OrgRole::Viewer] {
        let err = OrganizationService::add_member(&pool, personal.id, other, role, owner)
            .await
            .expect_err("a personal org takes no second member");
        assert!(err.to_string().contains(PERSONAL_ORG_REFUSAL), "{err}");
    }
    assert_eq!(
        members(&pool, personal.id).await,
        vec![owner],
        "nothing was added"
    );

    // Any other writer is refused by the database.
    let direct = sqlx::query(
        "INSERT INTO organization_members (org_id, user_id, role, invited_by) \
         VALUES ($1, $2, 'member', $3)",
    )
    .bind(personal.id)
    .bind(other)
    .bind(owner)
    .execute(&pool)
    .await;
    assert!(direct.is_err(), "the trigger refuses a direct insert");
    assert_eq!(members(&pool, personal.id).await, vec![owner]);
}

#[tokio::test]
async fn a_personal_organization_is_never_transferred() {
    let (pool, _db) = common::isolated_db_pool().await;
    let owner = seed_user(&pool).await;
    let other = seed_user(&pool).await;
    let personal = OrganizationService::create_personal_org(&pool, owner, None)
        .await
        .expect("personal org");
    let err = OrganizationService::transfer_ownership(&pool, personal.id, owner, other)
        .await
        .expect_err("refused");
    assert!(err.to_string().contains(PERSONAL_ORG_REFUSAL), "{err}");
    let direct = sqlx::query("UPDATE organizations SET owner_id = $2 WHERE id = $1")
        .bind(personal.id)
        .bind(other)
        .execute(&pool)
        .await;
    assert!(direct.is_err(), "the trigger refuses a direct owner change");
}

/// The control: a shared organization still takes members.
#[tokio::test]
async fn a_shared_organization_takes_members() {
    let (pool, _db) = common::isolated_db_pool().await;
    let owner = seed_user(&pool).await;
    let other = seed_user(&pool).await;
    let shared = OrganizationService::create_org(
        &pool,
        "Shared team",
        &format!("shared-{}", Uuid::new_v4().simple()),
        owner,
    )
    .await
    .expect("shared org");
    OrganizationService::add_member(&pool, shared.id, other, OrgRole::Member, owner)
        .await
        .expect("a shared org takes a member");
    assert_eq!(members(&pool, shared.id).await.len(), 2);
}
