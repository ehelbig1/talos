//! GraphQL Mutation resolvers (MutationRoot).

use async_graphql::{Context, Object, Result};
use uuid::Uuid;

use crate::schema::types::*;
use crate::schema::{require_2fa, SafeErrorExtensions};

#[derive(Default)]
pub struct OrganizationsMutations;

#[Object]
impl OrganizationsMutations {
    async fn create_organization(
        &self,
        ctx: &Context<'_>,
        name: String,
        slug: String,
    ) -> Result<OrganizationObj> {
        require_2fa(ctx)?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        // MCP-831 (2026-05-14): close two drift gaps on this mutation.
        // Name routed through the canonical `validate_display_name` helper
        // (introduced in MCP-832 — same focused subset that the inline
        // shape used here originally).
        let trimmed_name = crate::schema::validate_display_name("Organization name", &name, 255)
            .map_err(|e| e.extend_safe())?;
        let name = trimmed_name.to_string();

        // Slug gate previously said "1–100 characters" but the
        // service-layer `OrganizationService::create_org` enforces
        // `[3, 100]` AND lowercase-alphanum+dash charset. Pre-fix,
        // a caller passing `slug: "ab"` got "must be 1–100" from
        // GraphQL → passed → service rejected with "must be 3–100",
        // i.e. two contradictory messages. Pre-validate the lower
        // bound here so the caller sees ONE accurate message; the
        // service still owns the canonical charset enforcement.
        if slug.len() < 3 || slug.len() > 100 {
            return Err(
                async_graphql::Error::new("Organization slug must be 3–100 characters")
                    .extend_safe(),
            );
        }

        let org =
            talos_organizations::OrganizationService::create_org(db_pool, &name, &slug, user_id)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "Failed to create organization");
                    async_graphql::Error::new("Failed to create organization").extend_safe()
                })?;

        Ok(OrganizationObj::from(org))
    }

    async fn invite_member(
        &self,
        ctx: &Context<'_>,
        org_id: Uuid,
        target_user_id: Uuid,
        role: String,
    ) -> Result<OrgMemberObj> {
        require_2fa(ctx)?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        // MCP-818 (2026-05-14): align error message with actual
        // accepted set. Pre-fix the error said "must be one of
        // 'viewer', 'member', 'admin'" — accurate for what add_member
        // ACCEPTS but misleading because `OrgRole::from_str("owner")`
        // returns `Some(Owner)` and silently passes this gate. The
        // service layer (talos-organizations:144) then rejects with a
        // different message ("Cannot add someone as Owner through
        // this method"). Reject upstream with the precise message so
        // the user gets ONE error explaining the constraint AND the
        // remediation path (transfer_ownership) — instead of seeing
        // a misleading-allowlist error first and a different downstream
        // error second.
        let parsed_role = talos_organizations::OrgRole::from_str(&role).ok_or_else(|| {
            async_graphql::Error::new(
                "Invalid role: must be one of 'viewer', 'member', or 'admin' \
                 (use transfer_ownership for 'owner')",
            )
            .extend_safe()
        })?;
        if parsed_role == talos_organizations::OrgRole::Owner {
            return Err(async_graphql::Error::new(
                "Cannot add a member as 'owner' — use transfer_ownership instead",
            )
            .extend_safe());
        }

        let member = talos_organizations::OrganizationService::add_member(
            db_pool,
            org_id,
            target_user_id,
            parsed_role,
            user_id,
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to invite member");
            async_graphql::Error::new("Failed to invite member").extend_safe()
        })?;

        Ok(OrgMemberObj::from(member))
    }

    async fn remove_member(
        &self,
        ctx: &Context<'_>,
        org_id: Uuid,
        target_user_id: Uuid,
    ) -> Result<bool> {
        require_2fa(ctx)?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        // Verify caller has Admin+ access.
        talos_organizations::OrganizationService::check_org_access(
            db_pool,
            org_id,
            user_id,
            talos_organizations::OrgRole::Admin,
        )
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "Organization access denied for remove_member");
            async_graphql::Error::new("Insufficient permissions").extend_safe()
        })?;

        let removed = talos_organizations::OrganizationService::remove_member(
            db_pool,
            org_id,
            target_user_id,
            user_id,
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to remove member");
            async_graphql::Error::new("Failed to remove member").extend_safe()
        })?;

        Ok(removed)
    }

    async fn update_member_role(
        &self,
        ctx: &Context<'_>,
        org_id: Uuid,
        target_user_id: Uuid,
        role: String,
    ) -> Result<OrgMemberObj> {
        require_2fa(ctx)?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        // Verify caller has Admin+ access.
        talos_organizations::OrganizationService::check_org_access(
            db_pool,
            org_id,
            user_id,
            talos_organizations::OrgRole::Admin,
        )
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "Organization access denied for update_member_role");
            async_graphql::Error::new("Insufficient permissions").extend_safe()
        })?;

        // MCP-818 (2026-05-14): align error message with actual
        // accepted set + reject Owner upstream. Pre-fix the error
        // listed 'owner' as valid, but the service layer
        // (talos-organizations:251) rejects role==Owner with a
        // specific "use transfer_ownership" message — so a user
        // calling update_member_role(target, "owner") saw the
        // misleading "valid: owner" message NOT trigger and instead
        // got the downstream error. The actually-acceptable target
        // set for this mutation is {viewer, member, admin}; owner
        // promotion goes via transfer_ownership. Same misleading-
        // allowlist class as the add_member sibling above.
        let parsed_role = talos_organizations::OrgRole::from_str(&role).ok_or_else(|| {
            async_graphql::Error::new(
                "Invalid role: must be one of 'viewer', 'member', or 'admin' \
                 (use transfer_ownership for 'owner')",
            )
            .extend_safe()
        })?;
        if parsed_role == talos_organizations::OrgRole::Owner {
            return Err(async_graphql::Error::new(
                "Cannot promote a member to 'owner' via update_member_role — \
                 use transfer_ownership instead (Owner-only operation)",
            )
            .extend_safe());
        }

        let member = talos_organizations::OrganizationService::update_member_role(
            db_pool,
            org_id,
            target_user_id,
            parsed_role,
            user_id, // MCP-996: caller_id for rank-tiered access check
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to update member role");
            async_graphql::Error::new("Failed to update member role").extend_safe()
        })?;

        Ok(OrgMemberObj::from(member))
    }

    async fn transfer_ownership(
        &self,
        ctx: &Context<'_>,
        org_id: Uuid,
        new_owner_id: Uuid,
    ) -> Result<OrganizationObj> {
        require_2fa(ctx)?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        let org = talos_organizations::OrganizationService::transfer_ownership(
            db_pool,
            org_id,
            user_id,
            new_owner_id,
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to transfer ownership");
            async_graphql::Error::new("Failed to transfer ownership").extend_safe()
        })?;

        Ok(OrganizationObj::from(org))
    }
}
