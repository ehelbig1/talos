//! Integration tests for the organizations module.
//!
//! Tests that only exercise pure helper functions (role ordering, slug validation,
//! `can_access_resource` logic) run without a database. Tests that require a
//! live PostgreSQL connection use testcontainers for automatic provisioning.
//!
//!     cargo test --package controller --test organization_tests

mod test_helpers;

use controller::organizations::{can_access_resource, OrgRole, OrganizationService};
use uuid::Uuid;

// =========================================================================
// Pure logic tests (no database required)
// =========================================================================

#[test]
fn test_role_hierarchy_ordering() {
    // Owner > Admin > Member > Viewer
    assert!(OrgRole::Owner > OrgRole::Admin);
    assert!(OrgRole::Admin > OrgRole::Member);
    assert!(OrgRole::Member > OrgRole::Viewer);

    // Transitive: Owner > Viewer
    assert!(OrgRole::Owner > OrgRole::Viewer);

    // Equality
    assert_eq!(OrgRole::Admin, OrgRole::Admin);
    assert_ne!(OrgRole::Admin, OrgRole::Member);
}

#[test]
fn test_slug_validation() {
    // Helper that mirrors the slug check in OrganizationService::create_org.
    fn is_valid_slug(slug: &str) -> bool {
        slug.len() >= 3
            && slug.len() <= 100
            && slug
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    }

    // Valid slugs
    assert!(is_valid_slug("my-org"));
    assert!(is_valid_slug("org123"));
    assert!(is_valid_slug("a-b"));
    assert!(is_valid_slug("abc"));
    assert!(is_valid_slug("my-long-organization-slug-123"));

    // Invalid: too short
    assert!(!is_valid_slug("ab"));
    assert!(!is_valid_slug(""));

    // Invalid: uppercase
    assert!(!is_valid_slug("MyOrg"));
    assert!(!is_valid_slug("ORG"));

    // Invalid: spaces
    assert!(!is_valid_slug("my org"));

    // Invalid: special characters
    assert!(!is_valid_slug("my_org"));
    assert!(!is_valid_slug("my.org"));
    assert!(!is_valid_slug("org@name"));

    // Invalid: too long (101 chars)
    let long_slug: String = "a".repeat(101);
    assert!(!is_valid_slug(&long_slug));

    // Valid: exactly 100 chars
    let max_slug: String = "a".repeat(100);
    assert!(is_valid_slug(&max_slug));
}

#[tokio::test]
async fn test_can_access_resource_own_resource() {
    // A user can always access their own resources, regardless of org membership.
    let user_id = Uuid::new_v4();
    let resource_user_id = user_id; // same user

    // We need a DB pool for can_access_resource, but when user_id == resource_user_id
    // the function returns true immediately without touching the DB. Use a dummy pool
    // that will fail on any actual query — proving the fast path works.
    let pool = make_dummy_pool().await;

    let result = can_access_resource(&pool, user_id, resource_user_id, None, OrgRole::Viewer).await;
    assert!(
        result,
        "User should always be able to access their own resources"
    );

    // Even with an org_id set, own-resource check takes priority.
    let org_id = Uuid::new_v4();
    let result = can_access_resource(
        &pool,
        user_id,
        resource_user_id,
        Some(org_id),
        OrgRole::Admin,
    )
    .await;
    assert!(
        result,
        "Own-resource access should succeed even when org_id is present"
    );
}

#[tokio::test]
async fn test_can_access_resource_non_member_denied() {
    // When user_id != resource_user_id and there is no org_id, access is denied.
    let user_id = Uuid::new_v4();
    let resource_user_id = Uuid::new_v4();
    let pool = make_dummy_pool().await;

    let result = can_access_resource(&pool, user_id, resource_user_id, None, OrgRole::Viewer).await;
    assert!(!result, "Non-owner with no org should be denied access");
}

#[test]
fn test_org_role_permissions() {
    // can_read — all roles can read
    assert!(OrgRole::Owner.can_read());
    assert!(OrgRole::Admin.can_read());
    assert!(OrgRole::Member.can_read());
    assert!(OrgRole::Viewer.can_read());

    // can_write — Viewer cannot write
    assert!(OrgRole::Owner.can_write());
    assert!(OrgRole::Admin.can_write());
    assert!(OrgRole::Member.can_write());
    assert!(!OrgRole::Viewer.can_write());

    // can_manage_members — only Owner and Admin
    assert!(OrgRole::Owner.can_manage_members());
    assert!(OrgRole::Admin.can_manage_members());
    assert!(!OrgRole::Member.can_manage_members());
    assert!(!OrgRole::Viewer.can_manage_members());

    // can_delete — only Owner
    assert!(OrgRole::Owner.can_delete());
    assert!(!OrgRole::Admin.can_delete());
    assert!(!OrgRole::Member.can_delete());
    assert!(!OrgRole::Viewer.can_delete());
}

#[test]
fn test_viewer_cannot_write() {
    // Specifically verify the Viewer role is insufficient for write operations.
    let viewer = OrgRole::Viewer;
    assert!(viewer.can_read(), "Viewer should be able to read");
    assert!(!viewer.can_write(), "Viewer should NOT be able to write");
    assert!(
        !viewer.can_manage_members(),
        "Viewer should NOT be able to manage members"
    );
    assert!(!viewer.can_delete(), "Viewer should NOT be able to delete");
}

#[test]
fn test_role_from_str_roundtrip() {
    for role in [
        OrgRole::Viewer,
        OrgRole::Member,
        OrgRole::Admin,
        OrgRole::Owner,
    ] {
        let s = role.as_str();
        let parsed = OrgRole::from_str(s).expect("should parse valid role string");
        assert_eq!(parsed, role);
    }
}

#[test]
fn test_role_from_str_invalid() {
    assert!(OrgRole::from_str("superadmin").is_none());
    assert!(OrgRole::from_str("").is_none());
    assert!(OrgRole::from_str("OWNER").is_none()); // case-sensitive
    assert!(OrgRole::from_str("root").is_none());
}

#[test]
fn test_role_display() {
    assert_eq!(format!("{}", OrgRole::Owner), "owner");
    assert_eq!(format!("{}", OrgRole::Admin), "admin");
    assert_eq!(format!("{}", OrgRole::Member), "member");
    assert_eq!(format!("{}", OrgRole::Viewer), "viewer");
}

// =========================================================================
// Database-dependent tests (use testcontainers for PostgreSQL)
// =========================================================================

#[tokio::test]
async fn test_create_org_and_membership() {
    let pool = test_helpers::get_test_db_pool().await;
    let owner_id = ensure_test_user(&pool).await;

    let slug = format!("test-org-{}", Uuid::new_v4().as_simple());
    let slug = &slug[..slug.len().min(100)]; // Truncate to max 100 chars

    let org = OrganizationService::create_org(&pool, "Test Org", slug, owner_id)
        .await
        .expect("create_org should succeed");

    assert_eq!(org.name, "Test Org");
    assert_eq!(org.slug, slug);
    assert_eq!(org.owner_id, owner_id);

    // Owner should be a member with 'owner' role.
    let role = OrganizationService::get_member_role(&pool, org.id, owner_id)
        .await
        .expect("get_member_role should succeed")
        .expect("owner should be a member");
    assert_eq!(role, OrgRole::Owner);

    // Clean up
    sqlx::query("DELETE FROM organizations WHERE id = $1")
        .bind(org.id)
        .execute(&pool)
        .await
        .ok();
}

#[tokio::test]
async fn test_can_access_resource_org_member() {
    let pool = test_helpers::get_test_db_pool().await;
    let owner_id = ensure_test_user(&pool).await;
    let member_id = ensure_test_user(&pool).await;
    let resource_owner_id = ensure_test_user(&pool).await;

    let slug = format!("test-acc-{}", Uuid::new_v4().as_simple());
    let slug = &slug[..slug.len().min(100)];

    let org = OrganizationService::create_org(&pool, "Access Test Org", slug, owner_id)
        .await
        .expect("create_org should succeed");

    // Add member_id as a Member
    OrganizationService::add_member(&pool, org.id, member_id, OrgRole::Member, owner_id)
        .await
        .expect("add_member should succeed");

    // Member can access org resources with Viewer role requirement
    let access = can_access_resource(
        &pool,
        member_id,
        resource_owner_id,
        Some(org.id),
        OrgRole::Viewer,
    )
    .await;
    assert!(access, "Org member should be able to access org resources");

    // Member can access org resources with Member role requirement
    let access = can_access_resource(
        &pool,
        member_id,
        resource_owner_id,
        Some(org.id),
        OrgRole::Member,
    )
    .await;
    assert!(access, "Member role should satisfy Member requirement");

    // Member cannot access org resources with Admin role requirement
    let access = can_access_resource(
        &pool,
        member_id,
        resource_owner_id,
        Some(org.id),
        OrgRole::Admin,
    )
    .await;
    assert!(!access, "Member role should NOT satisfy Admin requirement");

    // Clean up
    sqlx::query("DELETE FROM organizations WHERE id = $1")
        .bind(org.id)
        .execute(&pool)
        .await
        .ok();
}

#[tokio::test]
async fn test_can_access_resource_non_member_denied_db() {
    let pool = test_helpers::get_test_db_pool().await;
    let owner_id = ensure_test_user(&pool).await;
    let outsider_id = ensure_test_user(&pool).await;
    let resource_owner_id = ensure_test_user(&pool).await;

    let slug = format!("test-deny-{}", Uuid::new_v4().as_simple());
    let slug = &slug[..slug.len().min(100)];

    let org = OrganizationService::create_org(&pool, "Deny Test Org", slug, owner_id)
        .await
        .expect("create_org should succeed");

    // outsider_id is NOT a member
    let access = can_access_resource(
        &pool,
        outsider_id,
        resource_owner_id,
        Some(org.id),
        OrgRole::Viewer,
    )
    .await;
    assert!(
        !access,
        "Non-member should be denied access to org resources"
    );

    // Clean up
    sqlx::query("DELETE FROM organizations WHERE id = $1")
        .bind(org.id)
        .execute(&pool)
        .await
        .ok();
}

#[tokio::test]
async fn test_can_access_resource_viewer_cannot_write_db() {
    let pool = test_helpers::get_test_db_pool().await;
    let owner_id = ensure_test_user(&pool).await;
    let viewer_id = ensure_test_user(&pool).await;
    let resource_owner_id = ensure_test_user(&pool).await;

    let slug = format!("test-view-{}", Uuid::new_v4().as_simple());
    let slug = &slug[..slug.len().min(100)];

    let org = OrganizationService::create_org(&pool, "Viewer Test Org", slug, owner_id)
        .await
        .expect("create_org should succeed");

    // Add viewer_id as a Viewer
    OrganizationService::add_member(&pool, org.id, viewer_id, OrgRole::Viewer, owner_id)
        .await
        .expect("add_member should succeed");

    // Viewer can read (Viewer requirement)
    let access = can_access_resource(
        &pool,
        viewer_id,
        resource_owner_id,
        Some(org.id),
        OrgRole::Viewer,
    )
    .await;
    assert!(access, "Viewer should satisfy Viewer requirement");

    // Viewer cannot write (Member requirement)
    let access = can_access_resource(
        &pool,
        viewer_id,
        resource_owner_id,
        Some(org.id),
        OrgRole::Member,
    )
    .await;
    assert!(
        !access,
        "Viewer role should NOT satisfy Member (write) requirement"
    );

    // Clean up
    sqlx::query("DELETE FROM organizations WHERE id = $1")
        .bind(org.id)
        .execute(&pool)
        .await
        .ok();
}

// =========================================================================
// Helpers
// =========================================================================

/// Create a dummy PgPool that will fail on any real query.
/// Used for tests where the fast-path avoids DB access.
async fn make_dummy_pool() -> sqlx::PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://dummy:dummy@localhost:1/dummy")
        .expect("lazy pool creation should not fail")
}

/// Insert a minimal test user and return its ID.
/// Uses the `users` table — assumes the standard Talos schema.
async fn ensure_test_user(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO users (id, email, password_hash, created_at, updated_at)
        VALUES ($1, $2, 'test-hash', NOW(), NOW())
        ON CONFLICT DO NOTHING
        "#,
    )
    .bind(id)
    .bind(format!("test-{}@example.com", id))
    .execute(pool)
    .await
    .expect("Failed to create test user");
    id
}
