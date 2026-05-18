//! Organization and team RBAC service.
//!
//! Provides organization management, membership, and role-based access control.
//! Resources (workflows, modules, secrets) can optionally belong to an organization,
//! enabling team collaboration while preserving single-user workflows.

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use sqlx::{Pool, Postgres};
use uuid::Uuid;

/// Organization record.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Organization {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub owner_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Organization member record.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct OrgMember {
    pub id: Uuid,
    pub org_id: Uuid,
    pub user_id: Uuid,
    pub role: String,
    pub invited_by: Option<Uuid>,
    pub joined_at: DateTime<Utc>,
}

/// Role within an organization, ordered by ascending privilege.
///
/// Pure-data enum lives in `talos-auth-types`; re-exported here so the
/// existing `crate::organizations::OrgRole` import path continues to work.
pub use talos_auth_types::OrgRole;

/// Service for organization CRUD and membership management.
pub struct OrganizationService;

impl OrganizationService {
    // ── Organization CRUD ──────────────────────────────────────────────

    /// Create a new organization and add the creator as the owner member.
    pub async fn create_org(
        db: &Pool<Postgres>,
        name: &str,
        slug: &str,
        owner_id: Uuid,
    ) -> Result<Organization> {
        // Validate slug format (lowercase alphanumeric + hyphens, 3-100 chars).
        if slug.len() < 3 || slug.len() > 100 {
            return Err(anyhow!("Slug must be between 3 and 100 characters"));
        }
        if !slug
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(anyhow!(
                "Slug must contain only lowercase letters, digits, and hyphens"
            ));
        }

        let mut tx = db.begin().await.context("Failed to begin transaction")?;

        let org = sqlx::query_as::<_, Organization>(
            r#"
            INSERT INTO organizations (name, slug, owner_id)
            VALUES ($1, $2, $3)
            RETURNING id, name, slug, owner_id, created_at, updated_at
            "#,
        )
        .bind(name)
        .bind(slug)
        .bind(owner_id)
        .fetch_one(&mut *tx)
        .await
        .context("Failed to create organization")?;

        // Add the creator as the owner member.
        sqlx::query(
            r#"
            INSERT INTO organization_members (org_id, user_id, role, invited_by)
            VALUES ($1, $2, 'owner', NULL)
            "#,
        )
        .bind(org.id)
        .bind(owner_id)
        .execute(&mut *tx)
        .await
        .context("Failed to add owner as member")?;

        tx.commit().await.context("Failed to commit transaction")?;

        Ok(org)
    }

    /// Get an organization by ID.
    pub async fn get_org(db: &Pool<Postgres>, org_id: Uuid) -> Result<Organization> {
        sqlx::query_as::<_, Organization>(
            "SELECT id, name, slug, owner_id, created_at, updated_at FROM organizations WHERE id = $1",
        )
        .bind(org_id)
        .fetch_optional(db)
        .await
        .context("Failed to query organization")?
        .ok_or_else(|| anyhow!("Organization not found"))
    }

    /// List all organizations the user belongs to.
    pub async fn list_user_orgs(db: &Pool<Postgres>, user_id: Uuid) -> Result<Vec<Organization>> {
        sqlx::query_as::<_, Organization>(
            r#"
            SELECT o.id, o.name, o.slug, o.owner_id, o.created_at, o.updated_at
            FROM organizations o
            INNER JOIN organization_members m ON m.org_id = o.id
            WHERE m.user_id = $1
            ORDER BY o.created_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(db)
        .await
        .context("Failed to list user organizations")
    }

    // ── Membership ─────────────────────────────────────────────────────

    /// Add a member to an organization. The inviter must have at least Admin role.
    pub async fn add_member(
        db: &Pool<Postgres>,
        org_id: Uuid,
        user_id: Uuid,
        role: OrgRole,
        invited_by: Uuid,
    ) -> Result<OrgMember> {
        // Verify inviter has permission.
        Self::check_org_access(db, org_id, invited_by, OrgRole::Admin).await?;

        // Cannot add someone as Owner through this method — use transfer_ownership.
        if role == OrgRole::Owner {
            return Err(anyhow!(
                "Cannot directly add a member as owner; use transfer_ownership instead"
            ));
        }

        let member = sqlx::query_as::<_, OrgMember>(
            r#"
            INSERT INTO organization_members (org_id, user_id, role, invited_by)
            VALUES ($1, $2, $3, $4)
            RETURNING id, org_id, user_id, role, invited_by, joined_at
            "#,
        )
        .bind(org_id)
        .bind(user_id)
        .bind(role.as_str())
        .bind(invited_by)
        .fetch_one(db)
        .await
        .context("Failed to add member (user may already be a member)")?;

        Ok(member)
    }

    /// Remove a member from an organization. Cannot remove the last owner.
    /// The caller must have at least Admin role to remove other members.
    pub async fn remove_member(
        db: &Pool<Postgres>,
        org_id: Uuid,
        user_id: Uuid,
        caller_id: Uuid,
    ) -> Result<bool> {
        // SECURITY: Verify the caller has at least Admin role.
        Self::check_org_access(db, org_id, caller_id, OrgRole::Admin).await?;

        // Use a transaction with FOR UPDATE to prevent TOCTOU races.
        let mut tx = db.begin().await.context("Failed to begin transaction")?;

        // Lock the relevant rows and count owners atomically.
        let owner_count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM organization_members WHERE org_id = $1 AND role = 'owner' FOR UPDATE",
        )
        .bind(org_id)
        .fetch_one(&mut *tx)
        .await
        .context("Failed to count owners")?;

        // Check the target member's role within the transaction.
        let member_role_str: Option<String> = sqlx::query_scalar(
            "SELECT role FROM organization_members WHERE org_id = $1 AND user_id = $2 FOR UPDATE",
        )
        .bind(org_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await
        .context("Failed to query member role")?;

        // MCP-996 (2026-05-15): rank-tiered access — caller's role must
        // be >= target's role. Pre-fix `check_org_access(Admin)` let
        // any Admin remove any member regardless of target's rank, so
        // an Admin could demote an Owner (as long as not the last)
        // and reduce org redundancy. The rule below preserves Admin's
        // ability to manage Members/Viewers AND Admin peers, while
        // requiring Owner-to-Owner removals to go through an Owner
        // caller. Same fix shape as `update_member_role` below.
        //
        // Read caller's role inside the same transaction so the role
        // pair is snapshotted together — otherwise a concurrent
        // demotion of the caller between check_org_access and this
        // point could open a brief escalation window.
        let caller_role_str: Option<String> = sqlx::query_scalar(
            "SELECT role FROM organization_members WHERE org_id = $1 AND user_id = $2 FOR UPDATE",
        )
        .bind(org_id)
        .bind(caller_id)
        .fetch_optional(&mut *tx)
        .await
        .context("Failed to query caller role")?;
        let caller_role = caller_role_str
            .as_deref()
            .and_then(OrgRole::from_str)
            .ok_or_else(|| anyhow!("Caller is not a member of this organization"))?;

        if let Some(ref role_str) = member_role_str {
            if let Some(target_role) = OrgRole::from_str(role_str) {
                if target_role > caller_role {
                    return Err(anyhow!(
                        "Insufficient permissions: cannot remove a member whose role \
                         ('{}') outranks yours ('{}')",
                        target_role,
                        caller_role
                    ));
                }
                if target_role == OrgRole::Owner && owner_count <= 1 {
                    return Err(anyhow!(
                        "Cannot remove the last owner; transfer ownership first"
                    ));
                }
            }
        }

        // Prevent a caller from removing themselves if they are the last owner.
        if caller_id == user_id {
            if let Some(ref role_str) = member_role_str {
                if OrgRole::from_str(role_str) == Some(OrgRole::Owner) && owner_count <= 1 {
                    return Err(anyhow!(
                        "Cannot remove yourself as the last owner; transfer ownership first"
                    ));
                }
            }
        }

        let result =
            sqlx::query("DELETE FROM organization_members WHERE org_id = $1 AND user_id = $2")
                .bind(org_id)
                .bind(user_id)
                .execute(&mut *tx)
                .await
                .context("Failed to remove member")?;

        tx.commit().await.context("Failed to commit transaction")?;

        Ok(result.rows_affected() > 0)
    }

    /// Update a member's role.
    /// Uses a transaction with row locking to prevent TOCTOU races when
    /// checking whether the last owner would be demoted.
    ///
    /// `caller_id` is the user making the request — used for the
    /// rank-tiered access check (MCP-996): an Admin cannot demote an
    /// Owner, only another Owner can.
    pub async fn update_member_role(
        db: &Pool<Postgres>,
        org_id: Uuid,
        user_id: Uuid,
        new_role: OrgRole,
        caller_id: Uuid,
    ) -> Result<OrgMember> {
        // Owner promotion must go through `transfer_ownership` — that path
        // verifies the caller is the current Owner and demotes them
        // atomically. Without this guard an Admin (the GraphQL caller-role
        // gate is Admin+) could call update_member_role(target, "owner")
        // and grant themselves or a confederate Owner-tier privileges,
        // bypassing the Owner-only restriction. add_member rejects the same
        // shape; keep the two methods symmetric.
        if new_role == OrgRole::Owner {
            return Err(anyhow!(
                "Cannot promote a member to owner via update_member_role; \
                 use transfer_ownership (Owner-only) instead"
            ));
        }

        let mut tx = db.begin().await.context("Failed to begin transaction")?;

        // MCP-996 (2026-05-15): rank-tiered access — caller's role must
        // be >= target's CURRENT role. Pre-fix any Admin could demote
        // any Owner (so long as not the last) since the function
        // gated only on `check_org_access(Admin)` at the GraphQL
        // layer. Reading caller_role inside this transaction
        // snapshots the caller/target role pair together; without
        // FOR UPDATE on the caller row, a concurrent demotion of
        // the caller mid-transaction could open a brief escalation
        // window. Sibling fix to `remove_member` above.
        let caller_role_str: Option<String> = sqlx::query_scalar(
            "SELECT role FROM organization_members WHERE org_id = $1 AND user_id = $2 FOR UPDATE",
        )
        .bind(org_id)
        .bind(caller_id)
        .fetch_optional(&mut *tx)
        .await
        .context("Failed to query caller role")?;
        let caller_role = caller_role_str
            .as_deref()
            .and_then(OrgRole::from_str)
            .ok_or_else(|| anyhow!("Caller is not a member of this organization"))?;

        // Prevent downgrading the last owner — check within the transaction with FOR UPDATE.
        if new_role != OrgRole::Owner {
            let current_role_str: Option<String> = sqlx::query_scalar(
                "SELECT role FROM organization_members WHERE org_id = $1 AND user_id = $2 FOR UPDATE",
            )
            .bind(org_id)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await
            .context("Failed to query member role")?;

            let current_role = current_role_str.and_then(|s| OrgRole::from_str(&s));
            if let Some(cr) = current_role {
                if cr > caller_role {
                    return Err(anyhow!(
                        "Insufficient permissions: cannot change the role of a member whose \
                         current role ('{}') outranks yours ('{}')",
                        cr,
                        caller_role
                    ));
                }
            }
            if current_role == Some(OrgRole::Owner) {
                let owner_count = sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM organization_members WHERE org_id = $1 AND role = 'owner' FOR UPDATE",
                )
                .bind(org_id)
                .fetch_one(&mut *tx)
                .await
                .context("Failed to count owners")?;

                if owner_count <= 1 {
                    return Err(anyhow!(
                        "Cannot change role of the last owner; transfer ownership first"
                    ));
                }
            }
        }

        let member = sqlx::query_as::<_, OrgMember>(
            r#"
            UPDATE organization_members
            SET role = $3
            WHERE org_id = $1 AND user_id = $2
            RETURNING id, org_id, user_id, role, invited_by, joined_at
            "#,
        )
        .bind(org_id)
        .bind(user_id)
        .bind(new_role.as_str())
        .fetch_optional(&mut *tx)
        .await
        .context("Failed to update member role")?
        .ok_or_else(|| anyhow!("Member not found in organization"))?;

        tx.commit().await.context("Failed to commit transaction")?;

        Ok(member)
    }

    /// Get a user's role in an organization (None if not a member).
    pub async fn get_member_role(
        db: &Pool<Postgres>,
        org_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<OrgRole>> {
        let role_str: Option<String> = sqlx::query_scalar(
            "SELECT role FROM organization_members WHERE org_id = $1 AND user_id = $2",
        )
        .bind(org_id)
        .bind(user_id)
        .fetch_optional(db)
        .await
        .context("Failed to query member role")?;

        Ok(role_str.and_then(|s| OrgRole::from_str(&s)))
    }

    /// Verify that a user has at least the required role in an organization.
    /// Returns an error if the user is not a member or lacks the required role.
    pub async fn check_org_access(
        db: &Pool<Postgres>,
        org_id: Uuid,
        user_id: Uuid,
        required_role: OrgRole,
    ) -> Result<()> {
        let role = Self::get_member_role(db, org_id, user_id)
            .await?
            .ok_or_else(|| anyhow!("User is not a member of this organization"))?;

        if role < required_role {
            return Err(anyhow!(
                "Insufficient permissions: requires at least '{}' role",
                required_role
            ));
        }

        Ok(())
    }

    /// List all members of an organization.
    pub async fn list_members(db: &Pool<Postgres>, org_id: Uuid) -> Result<Vec<OrgMember>> {
        sqlx::query_as::<_, OrgMember>(
            r#"
            SELECT id, org_id, user_id, role, invited_by, joined_at
            FROM organization_members
            WHERE org_id = $1
            ORDER BY joined_at ASC
            LIMIT 1000
            "#,
        )
        .bind(org_id)
        .fetch_all(db)
        .await
        .context("Failed to list organization members")
    }

    /// Transfer ownership to a new user. The new owner must already be a member.
    /// The caller must be the current owner.
    pub async fn transfer_ownership(
        db: &Pool<Postgres>,
        org_id: Uuid,
        current_owner_id: Uuid,
        new_owner_id: Uuid,
    ) -> Result<Organization> {
        let mut tx = db.begin().await.context("Failed to begin transaction")?;

        // Verify the caller is actually an owner (inside the transaction to
        // avoid TOCTOU races).
        let caller_role = sqlx::query_scalar::<_, String>(
            "SELECT role FROM organization_members WHERE org_id = $1 AND user_id = $2 FOR UPDATE",
        )
        .bind(org_id)
        .bind(current_owner_id)
        .fetch_optional(&mut *tx)
        .await
        .context("Failed to query caller role")?;

        match caller_role.as_deref().and_then(OrgRole::from_str) {
            Some(OrgRole::Owner) => {}
            Some(_) => {
                return Err(anyhow!(
                    "Insufficient permissions: requires at least 'owner' role"
                ))
            }
            None => return Err(anyhow!("User is not a member of this organization")),
        }

        // Verify the new owner is already a member (inside the transaction).
        let new_role_str = sqlx::query_scalar::<_, String>(
            "SELECT role FROM organization_members WHERE org_id = $1 AND user_id = $2 FOR UPDATE",
        )
        .bind(org_id)
        .bind(new_owner_id)
        .fetch_optional(&mut *tx)
        .await
        .context("Failed to query new owner role")?
        .ok_or_else(|| anyhow!("New owner must be an existing member of the organization"))?;

        let new_member_role = OrgRole::from_str(&new_role_str)
            .ok_or_else(|| anyhow!("Invalid role stored for new owner"))?;

        if new_member_role == OrgRole::Owner {
            return Err(anyhow!("User is already an owner"));
        }

        // Promote new owner.
        sqlx::query(
            "UPDATE organization_members SET role = 'owner' WHERE org_id = $1 AND user_id = $2",
        )
        .bind(org_id)
        .bind(new_owner_id)
        .execute(&mut *tx)
        .await
        .context("Failed to promote new owner")?;

        // Demote current owner to admin (they remain a member).
        sqlx::query(
            "UPDATE organization_members SET role = 'admin' WHERE org_id = $1 AND user_id = $2",
        )
        .bind(org_id)
        .bind(current_owner_id)
        .execute(&mut *tx)
        .await
        .context("Failed to demote current owner")?;

        // Update the org's owner_id column.
        let org = sqlx::query_as::<_, Organization>(
            r#"
            UPDATE organizations SET owner_id = $2, updated_at = NOW()
            WHERE id = $1
            RETURNING id, name, slug, owner_id, created_at, updated_at
            "#,
        )
        .bind(org_id)
        .bind(new_owner_id)
        .fetch_one(&mut *tx)
        .await
        .context("Failed to update organization owner")?;

        tx.commit().await.context("Failed to commit transaction")?;

        Ok(org)
    }
}

/// Check if a user can access a resource — either owns it directly or has org access.
pub async fn can_access_resource(
    db: &Pool<Postgres>,
    user_id: Uuid,
    resource_user_id: Uuid,
    resource_org_id: Option<Uuid>,
    min_role: OrgRole,
) -> bool {
    if user_id == resource_user_id {
        return true;
    }
    if let Some(org_id) = resource_org_id {
        return OrganizationService::check_org_access(db, org_id, user_id, min_role)
            .await
            .is_ok();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_ordering() {
        assert!(OrgRole::Owner > OrgRole::Admin);
        assert!(OrgRole::Admin > OrgRole::Member);
        assert!(OrgRole::Member > OrgRole::Viewer);
    }

    #[test]
    fn test_role_parse_roundtrip() {
        for role in [
            OrgRole::Viewer,
            OrgRole::Member,
            OrgRole::Admin,
            OrgRole::Owner,
        ] {
            let s = role.as_str();
            let parsed = OrgRole::from_str(s).unwrap();
            assert_eq!(parsed, role);
        }
    }

    #[test]
    fn test_role_permissions() {
        assert!(OrgRole::Owner.can_manage_members());
        assert!(OrgRole::Admin.can_manage_members());
        assert!(!OrgRole::Member.can_manage_members());
        assert!(!OrgRole::Viewer.can_manage_members());

        assert!(OrgRole::Owner.can_write());
        assert!(OrgRole::Admin.can_write());
        assert!(OrgRole::Member.can_write());
        assert!(!OrgRole::Viewer.can_write());

        assert!(OrgRole::Owner.can_read());
        assert!(OrgRole::Viewer.can_read());

        assert!(OrgRole::Owner.can_delete());
        assert!(!OrgRole::Admin.can_delete());
    }

    #[test]
    fn test_slug_validation_logic() {
        // Valid slugs
        assert!("my-org"
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'));
        assert!("org123"
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'));

        // Invalid: uppercase
        assert!(!"MyOrg"
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'));
        // Invalid: spaces
        assert!(!"my org"
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'));
    }

    #[test]
    fn test_role_from_invalid_str() {
        assert!(OrgRole::from_str("superadmin").is_none());
        assert!(OrgRole::from_str("").is_none());
    }
}
