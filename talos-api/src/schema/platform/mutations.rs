//! GraphQL Mutation resolvers (MutationRoot).

use async_graphql::{Context, Result};
// use chrono::Utc; // unused
// use sha2::Digest; // unused
// use tracing::info; // unused
use uuid::Uuid;

use super::super::{require_2fa, require_scope, SafeErrorExtensions};
#[allow(unused_imports)]
use crate::schema::types::*;
#[derive(Default)]
pub struct PlatformMutations;

#[async_graphql::Object]
impl PlatformMutations {
    async fn set_concurrency_limit(
        &self,
        ctx: &Context<'_>,
        workflow_id: Uuid,
        max_concurrent: Option<i32>,
    ) -> Result<bool> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsWrite)?;

        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        // Validate range
        if let Some(val) = max_concurrent {
            if !(1..=100).contains(&val) {
                return Err(async_graphql::Error::new(
                    "max_concurrent must be between 1 and 100, or null to clear",
                )
                .extend_safe());
            }
        }

        // RFC 0005 S3: per-user scoped tx so the workflows RLS policy
        // backstops this UPDATE (USING-as-WITH-CHECK; the row stays owned
        // by the caller — only max_concurrent_executions changes). The repo
        // method executes on the tx we pass (see `set_max_concurrent_scoped`'s
        // doc warning); the resolver keeps owning begin + commit.
        let workflow_repo = talos_workflow_repository::WorkflowRepository::new(db_pool.clone());
        let mut tx = talos_db::begin_user_scoped(db_pool, user_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: tenant scope error");
                async_graphql::Error::new("Request scope error").extend_safe()
            })?;
        let rows_affected = workflow_repo
            .set_max_concurrent_scoped(&mut tx, workflow_id, user_id, max_concurrent)
            .await
            .map_err(|e| {
                tracing::error!("Failed to set concurrency limit: {}", e);
                async_graphql::Error::new("Failed to set concurrency limit").extend_safe()
            })?;
        tx.commit().await.map_err(|e| {
            tracing::error!(error = %e, "graphql: commit transaction error");
            async_graphql::Error::new("Request could not be completed").extend_safe()
        })?;

        if rows_affected == 0 {
            return Err(
                async_graphql::Error::new("Workflow not found or access denied").extend_safe(),
            );
        }

        tracing::info!(
            workflow_id = %workflow_id,
            max_concurrent = ?max_concurrent,
            "Updated workflow concurrency limit"
        );

        Ok(true)
    }

    async fn update_resource_quotas(
        &self,
        ctx: &Context<'_>,
        input: UpdateResourceQuotasInput,
    ) -> Result<ResourceQuota> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::Admin)?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        // Find the organization owned by the user
        let org_id =
            talos_organizations::OrganizationService::first_org_id_owned_by(db_pool, user_id)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "graphql: owned-org lookup failed");
                    async_graphql::Error::new("Request could not be completed").extend_safe()
                })?
                .ok_or_else(|| {
                    async_graphql::Error::new("No organization found to update quotas for")
                        .extend_safe()
                })?;

        let metrics = [
            ("cpu_cores", input.cpu_cores),
            ("memory_gb", input.memory_gb),
            ("storage_gb", input.storage_gb),
            ("concurrent_executions", input.concurrent_executions),
        ];

        for (metric, limit) in metrics {
            if let Some(val) = limit {
                talos_organizations::OrganizationService::upsert_org_quota_limit(
                    db_pool, org_id, metric, val,
                )
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, metric, "graphql: quota upsert failed");
                    async_graphql::Error::new("Request could not be completed").extend_safe()
                })?;
            }
        }

        // Fetch updated quotas
        let quotas =
            talos_organizations::OrganizationService::get_org_quota_limits(db_pool, org_id)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "graphql: quota limits read failed");
                    async_graphql::Error::new("Request could not be completed").extend_safe()
                })?;

        let mut result = ResourceQuota {
            cpu_cores: 1,
            used_cpu: 0,
            memory_gb: 2,
            used_memory: 0,
            storage_gb: 10,
            used_storage: 0,
            concurrent_executions: 5,
            active_executions: 0,
        };

        for q in quotas {
            match q.metric.as_str() {
                "cpu_cores" => result.cpu_cores = q.max_limit,
                "memory_gb" => result.memory_gb = q.max_limit,
                "storage_gb" => result.storage_gb = q.max_limit,
                "concurrent_executions" => result.concurrent_executions = q.max_limit,
                _ => {}
            }
        }

        Ok(result)
    }

    /// Grant a capability ceiling to a user. Cross-user grants require
    /// the designated `users.is_platform_admin` flag (M T6-1) — NOT
    /// "admin of any organisation." Self-grants stay open (no-op since
    /// you can't exceed your own ceiling). Granter's own ceiling must
    /// be >= the world being granted (enforced separately below).
    async fn grant_capability_ceiling(
        &self,
        ctx: &Context<'_>,
        input: GrantCapabilityCeilingInput,
    ) -> Result<bool> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::Admin)?;
        let granter_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        // Granting capability ceilings to OTHER users is platform-admin-class.
        // require_scope(Admin) session-bypasses, and the per-user
        // granter-ceiling check below only prevents elevation beyond
        // what the granter themselves holds. Without this gate, a user
        // who had been deliberately granted an elevated ceiling could
        // silently propagate it. Self-grant stays open (it's a no-op).
        //
        // M T6-1 audit fix (2026-05-06): delegate to the canonical
        // `ActorRepository::is_platform_admin` helper which queries the
        // dedicated `users.is_platform_admin` column. The MCP sibling
        // `handle_grant_capability_ceiling` already does this; the
        // pre-fix inline `EXISTS(... organization_members ... role IN
        // ('owner','admin'))` was the EXACT conflation M T6-1 was meant
        // to close — same drift class as r277/r289/r291/r292 that
        // `graphql_must_mirror_mcp_rbac_checks.md` flags.
        if input.user_id != granter_id {
            let actor_repo = talos_actor_repository::ActorRepository::new(db_pool.clone());
            let is_admin = actor_repo
                .is_platform_admin(granter_id)
                .await
                .map_err(|e| {
                    tracing::error!("grant_capability_ceiling admin check failed: {}", e);
                    async_graphql::Error::new("Database error").extend_safe()
                })?;
            if !is_admin {
                return Err(async_graphql::Error::new(
                    "Only platform admins can grant capability ceilings to other users",
                )
                .extend_safe());
            }
        }

        // Validate world name against the canonical list. Drift between
        // GraphQL and MCP is the same class as r292 — single source of
        // truth in talos-capability-world prevents one surface from
        // accepting a world the other refuses (or, worse, vice-versa).
        if !talos_capability_world::is_actor_ceiling_world(&input.max_capability_world) {
            return Err(async_graphql::Error::new(format!(
                "Invalid capability world. Valid values: {}",
                talos_capability_world::actor_ceiling_worlds_csv()
            ))
            .extend_safe());
        }

        // Validate notes length
        if let Some(ref notes) = input.notes {
            if notes.len() > 1000 {
                return Err(
                    async_graphql::Error::new("Notes must be 1000 characters or fewer")
                        .extend_safe(),
                );
            }
        }

        // Check granter's own ceiling
        let actor_repo = talos_actor_repository::ActorRepository::new(db_pool.clone());
        let granter_ceiling: String = actor_repo
            .get_user_max_capability_world(granter_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: granter ceiling read failed");
                async_graphql::Error::new("Request could not be completed").extend_safe()
            })?
            .unwrap_or_else(|| "http-node".to_string());

        // Lattice gate — NOT a linear rank comparison. You may only grant a
        // ceiling that is a SUBSET of your own. The previous local `rank`
        // closure mapped incomparable tier-3 siblings to the SAME rank
        // (governance == secrets == 3), so `rank(requested) > rank(granter)`
        // was false for the (governance-ceiling, grant-secrets) pair and let a
        // granter hand out a capability — vault access — they don't hold. This
        // is the exact lattice-bypass the 2026-05-28 review fixed on the actor
        // grant gates (actors/mutations.rs); the platform grant gate must use
        // the SAME canonical helper. `ceiling_permits` fails closed on any
        // unrecognised world.
        if !talos_capability_world::ceiling_permits(&granter_ceiling, &input.max_capability_world) {
            return Err(async_graphql::Error::new(format!(
                "Cannot grant '{}': your ceiling is '{}'. You cannot grant more than you have.",
                input.max_capability_world, granter_ceiling
            ))
            .extend_safe());
        }

        // Verify target user exists
        let user_exists = actor_repo.user_exists(input.user_id).await.map_err(|e| {
            tracing::error!(error = %e, "graphql: target user existence check failed");
            async_graphql::Error::new("Request could not be completed").extend_safe()
        })?;

        if !user_exists {
            return Err(async_graphql::Error::new("Target user not found").extend_safe());
        }

        // UPSERT the grant
        actor_repo
            .upsert_capability_grant(
                input.user_id,
                &input.max_capability_world,
                granter_id,
                input.notes.as_deref(),
            )
            .await
            .map_err(|e| {
                tracing::error!("grant_capability_ceiling failed: {}", e);
                async_graphql::Error::new("Failed to grant capability ceiling").extend_safe()
            })?;

        tracing::info!(
            granter = %granter_id,
            target = %input.user_id,
            world = %input.max_capability_world,
            "Capability ceiling granted via dashboard"
        );

        Ok(true)
    }

    /// Revoke a user's capability ceiling grant, reverting to the default (http-node).
    /// Admins can revoke any grant; users can revoke their own.
    async fn revoke_capability_ceiling(&self, ctx: &Context<'_>, user_id: Uuid) -> Result<bool> {
        require_2fa(ctx)?;
        let revoker_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        // Allow self-revoke, otherwise require platform admin.
        //
        // M T6-1 audit fix (2026-05-06): same drift class as the sibling
        // `grant_capability_ceiling` above — pre-fix this inlined the
        // OLD `organization_members ... role IN ('owner','admin')` check
        // that conflates "any org admin" with "platform admin." The
        // MCP sibling `handle_revoke_capability_ceiling` already uses
        // the canonical helper; this brings GraphQL into parity.
        if revoker_id != user_id {
            require_scope(ctx, talos_api_keys::ApiKeyScope::Admin)?;

            let actor_repo = talos_actor_repository::ActorRepository::new(db_pool.clone());
            let is_admin = actor_repo
                .is_platform_admin(revoker_id)
                .await
                .map_err(|e| {
                    tracing::error!("revoke_capability_ceiling admin check failed: {}", e);
                    async_graphql::Error::new("Database error").extend_safe()
                })?;

            if !is_admin {
                return Err(async_graphql::Error::new(
                    "Only platform admins can revoke another user's capability grant",
                )
                .extend_safe());
            }
        }

        let actor_repo = talos_actor_repository::ActorRepository::new(db_pool.clone());
        let rows_deleted = actor_repo
            .delete_capability_grant(user_id)
            .await
            .map_err(|e| {
                tracing::error!("revoke_capability_ceiling failed: {}", e);
                async_graphql::Error::new("Failed to revoke capability ceiling").extend_safe()
            })?;

        if rows_deleted == 0 {
            return Err(async_graphql::Error::new(
                "No grant found — user is already at the default ceiling",
            )
            .extend_safe());
        }

        tracing::info!(
            revoker = %revoker_id,
            target = %user_id,
            "Capability ceiling revoked via dashboard"
        );

        Ok(true)
    }

    async fn disconnect_service_integration(
        &self,
        ctx: &Context<'_>,
        id: Uuid,
        service: IntegrationService,
    ) -> Result<bool> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::Admin)?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        // Map the GraphQL enum variant to the serialized string for registry lookup.
        let service_str = match service {
            IntegrationService::GoogleCalendar => "GOOGLE_CALENDAR",
            IntegrationService::Gmail => "GMAIL",
            IntegrationService::Slack => "SLACK",
            IntegrationService::Jira => "JIRA",
        };

        let provider = talos_integrations::provider_config::PROVIDERS
            .iter()
            .find(|p| p.graphql_enum == service_str)
            .ok_or_else(|| {
                async_graphql::Error::new("Unknown integration service").extend_safe()
            })?;

        // Soft-delete vs hard-delete + the registry-driven table name live
        // in `talos_integrations::store::disconnect_user_integration`
        // (compile-time constants; only id and user_id are bound).
        let rows_affected =
            talos_integrations::store::disconnect_user_integration(db_pool, provider, id, *user_id)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "graphql: integration disconnect failed");
                    async_graphql::Error::new("Request could not be completed").extend_safe()
                })?;

        if rows_affected == 0 {
            return Err(
                async_graphql::Error::new("Integration not found or access denied").extend_safe(),
            );
        }

        Ok(true)
    }
}
