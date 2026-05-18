//! GraphQL Query resolvers (QueryRoot).

use async_graphql::{Context, Result};
use uuid::Uuid;

use crate::schema::types::*;
use crate::schema::SafeErrorExtensions;
// use crate::schema::{require_scope, user_accessible_org_ids}; // unused
// use talos_compilation::CompilationService; // unused
// use talos_registry::ModuleRegistry; // unused
// use talos_workflow_versions::WorkflowVersionService; // unused
#[allow(unused_imports)]
use super::super::*;
#[allow(unused_imports)]
use crate::schema::types::*;

#[derive(Default)]
pub struct OrganizationsQueries;

#[async_graphql::Object]
impl OrganizationsQueries {
    async fn my_organizations(&self, ctx: &Context<'_>) -> Result<Vec<OrganizationObj>> {
        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        let orgs = talos_organizations::OrganizationService::list_user_orgs(db_pool, user_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to list user organizations");
                async_graphql::Error::new("Failed to list organizations").extend_safe()
            })?;

        Ok(orgs.into_iter().map(OrganizationObj::from).collect())
    }

    async fn organization(&self, ctx: &Context<'_>, org_id: Uuid) -> Result<OrganizationObj> {
        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        // Verify membership (any role).
        talos_organizations::OrganizationService::check_org_access(
            db_pool,
            org_id,
            user_id,
            talos_organizations::OrgRole::Viewer,
        )
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "Organization access denied");
            async_graphql::Error::new("Organization not found or access denied").extend_safe()
        })?;

        let org = talos_organizations::OrganizationService::get_org(db_pool, org_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to get organization");
                async_graphql::Error::new("Organization not found").extend_safe()
            })?;

        Ok(OrganizationObj::from(org))
    }

    async fn organization_members(
        &self,
        ctx: &Context<'_>,
        org_id: Uuid,
    ) -> Result<Vec<OrgMemberObj>> {
        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        // Verify membership (any role can list members).
        talos_organizations::OrganizationService::check_org_access(
            db_pool,
            org_id,
            user_id,
            talos_organizations::OrgRole::Viewer,
        )
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "Organization access denied");
            async_graphql::Error::new("Organization not found or access denied").extend_safe()
        })?;

        let members = talos_organizations::OrganizationService::list_members(db_pool, org_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to list organization members");
                async_graphql::Error::new("Failed to list members").extend_safe()
            })?;

        Ok(members.into_iter().map(OrgMemberObj::from).collect())
    }
}
