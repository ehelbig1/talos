//! Integration tests for RFC 0004 personal-org + active-org resolution,
//! against a live Postgres with the full migration chain applied.
//!
//! Gated on `TALOS_TEST_DATABASE_URL` (skips with a note when unset), so
//! `cargo test` stays green in CI without a DB while still exercising the
//! real SQL locally:
//!
//! ```sh
//! export TALOS_TEST_DATABASE_URL="postgres://postgres:talos@localhost:5433/talos"
//! cargo test -p talos-organizations --test personal_org_resolution -- --nocapture
//! ```
//!
//! Each test creates its own users/orgs with random UUIDs and cleans
//! them up, so there is no collision with real data.

use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres};
use talos_organizations::{OrgRole, OrganizationService};
use uuid::Uuid;

async fn pool_or_skip() -> Option<Pool<Postgres>> {
    let url = match std::env::var("TALOS_TEST_DATABASE_URL") {
        Ok(u) if !u.is_empty() => u,
        _ => {
            eprintln!("SKIP: set TALOS_TEST_DATABASE_URL to run this integration test");
            return None;
        }
    };
    Some(
        PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect(&url)
            .await
            .expect("connect TALOS_TEST_DATABASE_URL"),
    )
}

async fn make_user(pool: &Pool<Postgres>, label: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', $3)")
        .bind(id)
        .bind(format!("{}-{}@test.invalid", label, id.simple()))
        .bind(label)
        .execute(pool)
        .await
        .expect("insert user");
    id
}

async fn cleanup(pool: &Pool<Postgres>, user_ids: &[Uuid]) {
    for uid in user_ids {
        // organization_members + organizations FK-cascade off users? Not
        // guaranteed — delete children explicitly, owned orgs first.
        let _ = sqlx::query(
            "DELETE FROM organization_members WHERE user_id = $1 \
             OR org_id IN (SELECT id FROM organizations WHERE owner_id = $1)",
        )
        .bind(uid)
        .execute(pool)
        .await;
        let _ = sqlx::query("DELETE FROM organizations WHERE owner_id = $1")
            .bind(uid)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(uid)
            .execute(pool)
            .await;
    }
}

#[tokio::test]
async fn create_personal_org_is_idempotent_and_owner_member() {
    let Some(pool) = pool_or_skip().await else { return };
    let uid = make_user(&pool, "carol").await;

    let org1 = OrganizationService::create_personal_org(&pool, uid, Some("Carol"))
        .await
        .expect("create personal org");
    // Second call returns the SAME org (idempotent), not a duplicate.
    let org2 = OrganizationService::create_personal_org(&pool, uid, Some("Carol"))
        .await
        .expect("idempotent create");
    assert_eq!(org1.id, org2.id, "personal org must be idempotent");
    assert_eq!(org1.owner_id, uid);
    assert_eq!(org1.slug, format!("user-{}", uid.simple()));

    // Owner membership exists.
    let role = OrganizationService::get_member_role(&pool, org1.id, uid)
        .await
        .expect("role lookup");
    assert!(role.is_some(), "creator must be an owner member of their personal org");

    cleanup(&pool, &[uid]).await;
}

#[tokio::test]
async fn resolve_active_org_honours_membership_else_falls_back_to_personal() {
    let Some(pool) = pool_or_skip().await else { return };
    let alice = make_user(&pool, "alice").await;
    let bob = make_user(&pool, "bob").await;

    let alice_personal = OrganizationService::create_personal_org(&pool, alice, None)
        .await
        .unwrap();
    // A shared org owned by Alice that Bob is NOT a member of.
    let _bob_personal = OrganizationService::create_personal_org(&pool, bob, None)
        .await
        .unwrap();
    let shared = OrganizationService::create_org(&pool, "Team", "team-rfc0004-test", alice)
        .await
        .unwrap();

    // None requested → Alice's personal org.
    let r_none = OrganizationService::resolve_active_org(&pool, alice, None)
        .await
        .unwrap();
    assert_eq!(r_none, alice_personal.id, "no claim → personal org");

    // Requested an org Alice IS a member of (she owns `shared`) → honoured.
    let r_member = OrganizationService::resolve_active_org(&pool, alice, Some(shared.id))
        .await
        .unwrap();
    assert_eq!(r_member, shared.id, "member of requested org → honoured");

    // Bob requests `shared` (NOT a member) → falls back to Bob's personal,
    // never Alice's shared org. This is the isolation-critical assertion.
    let r_nonmember = OrganizationService::resolve_active_org(&pool, bob, Some(shared.id))
        .await
        .unwrap();
    assert_ne!(r_nonmember, shared.id, "non-member must NOT resolve to requested org");
    let bob_personal = OrganizationService::create_personal_org(&pool, bob, None)
        .await
        .unwrap();
    assert_eq!(r_nonmember, bob_personal.id, "non-member → own personal org");

    // cleanup (shared org owned by alice is removed by alice's cleanup)
    let _ = sqlx::query("DELETE FROM organization_members WHERE org_id = $1")
        .bind(shared.id)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM organizations WHERE id = $1")
        .bind(shared.id)
        .execute(&pool)
        .await;
    cleanup(&pool, &[alice, bob]).await;
}

/// The writable-member gate that org-aware `create_workflow` relies on:
/// only Member+ (not Viewer) may create resources in a shared org.
#[tokio::test]
async fn org_write_access_excludes_viewers() {
    let Some(pool) = pool_or_skip().await else { return };
    let owner = make_user(&pool, "owner").await;
    let member = make_user(&pool, "member").await;
    let viewer = make_user(&pool, "viewer").await;

    let org = OrganizationService::create_org(&pool, "Team", "team-write-gate-test", owner)
        .await
        .unwrap();
    OrganizationService::add_member(&pool, org.id, member, OrgRole::Member, owner)
        .await
        .unwrap();
    OrganizationService::add_member(&pool, org.id, viewer, OrgRole::Viewer, owner)
        .await
        .unwrap();

    // Member+ gate (the exact check the create path applies before
    // stamping org_id on a workflow):
    assert!(
        OrganizationService::check_org_access(&pool, org.id, owner, OrgRole::Member)
            .await
            .is_ok(),
        "owner may create in the org"
    );
    assert!(
        OrganizationService::check_org_access(&pool, org.id, member, OrgRole::Member)
            .await
            .is_ok(),
        "member may create in the org"
    );
    assert!(
        OrganizationService::check_org_access(&pool, org.id, viewer, OrgRole::Member)
            .await
            .is_err(),
        "VIEWER must NOT be able to create resources in the org"
    );
    // A complete non-member is likewise refused.
    let outsider = make_user(&pool, "outsider").await;
    assert!(
        OrganizationService::check_org_access(&pool, org.id, outsider, OrgRole::Member)
            .await
            .is_err(),
        "non-member must be refused"
    );

    let _ = sqlx::query("DELETE FROM organization_members WHERE org_id = $1")
        .bind(org.id)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM organizations WHERE id = $1")
        .bind(org.id)
        .execute(&pool)
        .await;
    cleanup(&pool, &[owner, member, viewer, outsider]).await;
}
