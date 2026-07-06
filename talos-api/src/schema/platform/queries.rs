use async_graphql::{Context, Result};
use uuid::Uuid;

#[allow(unused_imports)]
use super::super::*;
use crate::schema::types::*;

/// Human-readable description for each ceiling world. The world list
/// itself comes from `talos_capability_world::ACTOR_CEILING_WORLDS`
/// (single source of truth); only descriptions live here. If a new
/// world is added to the canonical list and this map is missing it,
/// the hierarchy query falls back to "" — caught in QA before any
/// security-sensitive divergence.
const WORLD_DESCRIPTIONS: &[(&str, &str)] = &[
    ("minimal-node", "Base sandbox — no network, no I/O"),
    ("http-node", "Outbound HTTP requests"),
    ("llm-node", "Native LLM host bindings (no vault)"),
    ("network-node", "Raw socket access"),
    ("secrets-node", "Vault access + LLM"),
    ("governance-node", "Human-approval gates"),
    ("messaging-node", "NATS pub/sub messaging"),
    ("filesystem-node", "File I/O access"),
    ("cache-node", "Redis cache access"),
    ("database-node", "Raw SQL database access"),
    (
        "agent-node",
        "LLM + secrets + memory + governance + orchestration",
    ),
    ("automation-node", "Full access — all interfaces"),
];

fn description_for(world: &str) -> &'static str {
    WORLD_DESCRIPTIONS
        .iter()
        .find(|(name, _)| *name == world)
        .map(|(_, desc)| *desc)
        .unwrap_or("")
}

/// Rank a world name. Delegates to `talos_capability_world::world_rank`
/// (single source of truth). Returns 7 for unknown worlds (safest default).
fn world_rank(world: &str) -> i32 {
    talos_capability_world::world_rank(world) as i32
}

#[derive(Default)]
pub struct PlatformQueries;

#[async_graphql::Object]
impl PlatformQueries {
    // allow-public-query: self-scoped per-user read of the caller's own
    // capability ceiling. WHERE user_id = $1 binds to the authenticated
    // caller — no cross-tenant disclosure surface, so the
    // grant/revoke_capability_ceiling Admin scope on the WRITE side
    // doesn't apply to this self-read.
    async fn my_capability_ceiling(&self, ctx: &Context<'_>) -> Result<String> {
        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        let actor_repo = talos_actor_repository::ActorRepository::new(db_pool.clone());
        let ceiling = actor_repo
            .get_user_max_capability_world(user_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: capability ceiling read failed");
                async_graphql::Error::new("Request could not be completed").extend_safe()
            })?;

        Ok(ceiling.unwrap_or_else(|| "http-node".to_string()))
    }

    /// Get detailed capability ceiling info for the current user.
    // allow-public-query: self-scoped per-user read; see my_capability_ceiling
    // above for the same rationale.
    async fn capability_ceiling_detail(
        &self,
        ctx: &Context<'_>,
    ) -> Result<CapabilityCeilingDetail> {
        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        let actor_repo = talos_actor_repository::ActorRepository::new(db_pool.clone());
        let grant = actor_repo
            .get_user_capability_grant(user_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: capability grant read failed");
                async_graphql::Error::new("Request could not be completed").extend_safe()
            })?;

        match grant {
            Some(g) => {
                let granter_email: Option<String> = match g.granted_by {
                    // Display-only enrichment — a failed email lookup degrades
                    // to None rather than failing the query (pre-extraction
                    // behavior).
                    Some(gid) => actor_repo.get_user_email(gid).await.unwrap_or(None),
                    None => None,
                };

                Ok(CapabilityCeilingDetail {
                    ceiling: g.max_capability_world,
                    source: "grant".to_string(),
                    granted_by_email: granter_email,
                    granted_at: Some(g.granted_at.to_rfc3339()),
                    notes: g.notes,
                })
            }
            None => Ok(CapabilityCeilingDetail {
                ceiling: "http-node".to_string(),
                source: "default".to_string(),
                granted_by_email: None,
                granted_at: None,
                notes: None,
            }),
        }
    }

    /// Return the full capability world hierarchy with ranks and descriptions.
    async fn capability_world_hierarchy(&self) -> Vec<CapabilityWorldInfo> {
        talos_capability_world::ACTOR_CEILING_WORLDS
            .iter()
            .map(|name| CapabilityWorldInfo {
                name: name.to_string(),
                rank: world_rank(name),
                description: description_for(name).to_string(),
            })
            .collect()
    }

    /// List all capability grants. Requires platform admin role.
    ///
    /// MCP-998 (2026-05-15): closes the QUERY sibling of the M T6-1
    /// drift fix that `grant_capability_ceiling` /
    /// `revoke_capability_ceiling` already received. Pre-fix this used
    /// the same inline `organization_members ... role IN
    /// ('owner','admin')` conflation that the mutations were
    /// audit-fixed away from — `require_scope(Admin)` session-bypasses,
    /// and the inline EXISTS check granted access to ANY user who was
    /// owner/admin of ANY organisation (their own tiny tenant counted).
    /// Information-disclosure class: the query returns ALL capability
    /// grants platform-wide (user_id, email, max_capability_world,
    /// granted_by, granted_at, notes — LIMIT 200), so a curious org
    /// admin on tenant A could enumerate every elevated user on
    /// tenants B/C/D, useful for targeted social engineering or
    /// reconnaissance ahead of an attempted privilege escalation.
    /// Fix delegates to the canonical `ActorRepository::
    /// is_platform_admin` helper that queries the dedicated
    /// `users.is_platform_admin` column. Same drift class as
    /// r277/r289/r291/r292 that `graphql_must_mirror_mcp_rbac_checks.md`
    /// flags — every NEW endpoint that touches cross-tenant data MUST
    /// either go through `require_platform_admin` or call
    /// `actor_repo.is_platform_admin` after a session check.
    async fn capability_grants(&self, ctx: &Context<'_>) -> Result<Vec<CapabilityGrant>> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::Admin)?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        let actor_repo = talos_actor_repository::ActorRepository::new(db_pool.clone());
        let is_admin = actor_repo.is_platform_admin(user_id).await.map_err(|e| {
            tracing::error!("capability_grants admin check failed: {}", e);
            async_graphql::Error::new("Database error").extend_safe()
        })?;

        if !is_admin {
            return Err(async_graphql::Error::new(
                "Only platform admins can list capability grants",
            )
            .extend_safe());
        }

        let rows = actor_repo.list_capability_grants().await.map_err(|e| {
            tracing::error!(error = %e, "graphql: capability grants list failed");
            async_graphql::Error::new("Request could not be completed").extend_safe()
        })?;

        Ok(rows
            .into_iter()
            .map(|r| CapabilityGrant {
                user_id: r.user_id,
                // INNER JOIN on users guarantees a row; email is NOT NULL,
                // so the Option only exists for the repo row's flexibility.
                email: r.email.unwrap_or_default(),
                max_capability_world: r.max_capability_world,
                granted_by: r.granted_by,
                granted_at: r.granted_at.to_rfc3339(),
                notes: r.notes,
            })
            .collect())
    }

    /// Verify the cryptographic audit chain for one execution (finding #2,
    /// on-demand forensic check). Platform admin only — it reads the WORM
    /// audit store across tenants, so it goes through the canonical
    /// `is_platform_admin` gate (NOT the org-admin conflation the MCP-998
    /// sweep removed). Returns the structured break list (sequence gaps,
    /// linkage/genesis mismatch, bad/missing HMAC); the inline ingest check
    /// and the continuous sweep cover the always-on side.
    async fn verify_audit_chain(
        &self,
        ctx: &Context<'_>,
        execution_id: Uuid,
    ) -> Result<AuditChainVerification> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::Admin)?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        let actor_repo = talos_actor_repository::ActorRepository::new(db_pool.clone());
        let is_admin = actor_repo.is_platform_admin(user_id).await.map_err(|e| {
            tracing::error!("verify_audit_chain admin check failed: {}", e);
            async_graphql::Error::new("Database error").extend_safe()
        })?;
        if !is_admin {
            return Err(
                async_graphql::Error::new("Only platform admins can verify audit chains")
                    .extend_safe(),
            );
        }

        // The chain genesis is bound to (workflow_id, execution_id), so we
        // need the owning workflow id. Deliberately cross-tenant: authz was
        // established upstream via is_platform_admin, and the repo method's
        // doc carries the full rationale (`get_workflow_id_any_user`).
        let exec_repo = talos_execution_repository::ExecutionRepository::new(db_pool.clone());
        let workflow_id = exec_repo
            .get_workflow_id_any_user(execution_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: audit-chain workflow lookup failed");
                async_graphql::Error::new("Request could not be completed").extend_safe()
            })?;
        let workflow_id = workflow_id
            .ok_or_else(|| async_graphql::Error::new("Execution not found").extend_safe())?;

        let report = talos_audit_ledger::verify_execution_chain_from_env(
            &workflow_id.to_string(),
            &execution_id.to_string(),
        )
        .await
        .map_err(|e| {
            // Generic client message; full detail (incl. "no S3 endpoint
            // configured") stays server-side per the no-leak rule.
            tracing::error!(
                target: "talos_audit",
                execution_id = %execution_id,
                "verify_audit_chain failed: {}", e
            );
            async_graphql::Error::new("Audit chain verification unavailable").extend_safe()
        })?;

        Ok(AuditChainVerification::from(report))
    }

    async fn resource_quotas(&self, ctx: &Context<'_>) -> Result<ResourceQuota> {
        // MCP-757 sibling: paired mutation `update_resource_quotas` is
        // `require_2fa` + Admin-scoped; this read surface had no scope
        // gate, so a non-Admin API key could discover the org's capacity
        // policy (cpu_cores, memory_gb, storage_gb, concurrent_executions).
        // Admin scope here matches the write surface; session-authenticated
        // callers (dashboard) pass through `require_scope` unchanged.
        crate::schema::require_scope(ctx, talos_api_keys::ApiKeyScope::Admin)?;

        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        let org_ids = talos_organizations::OrganizationService::list_user_org_ids(db_pool, user_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: org membership lookup failed");
                async_graphql::Error::new("Request could not be completed").extend_safe()
            })?;

        let org_id = match org_ids.first() {
            Some(o) => *o,
            None => {
                return Ok(ResourceQuota {
                    cpu_cores: 1,
                    used_cpu: 0,
                    memory_gb: 2,
                    used_memory: 0,
                    storage_gb: 10,
                    used_storage: 0,
                    concurrent_executions: 5,
                    active_executions: 0,
                });
            }
        };

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

    async fn service_integrations(&self, ctx: &Context<'_>) -> Result<Vec<ServiceIntegration>> {
        // MCP-757 sibling: paired mutation `disconnect_service_integration`
        // is `require_2fa` + Admin-scoped; this read surface had no scope
        // gate, so a non-Admin API key could enumerate every connected
        // provider for the user (id, account_identifier, connected_at).
        // Admin scope here matches the write surface; session-authenticated
        // callers (dashboard) pass through `require_scope` unchanged.
        crate::schema::require_scope(ctx, talos_api_keys::ApiKeyScope::Admin)?;

        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        // Helper: map a provider's graphql_enum string to the IntegrationService enum.
        fn resolve_service(graphql_enum: &str) -> IntegrationService {
            match graphql_enum {
                "GOOGLE_CALENDAR" => IntegrationService::GoogleCalendar,
                "GMAIL" => IntegrationService::Gmail,
                "SLACK" => IntegrationService::Slack,
                "JIRA" => IntegrationService::Jira,
                // Safety: PROVIDERS is a compile-time constant; unknown values should not appear.
                other => {
                    tracing::warn!(unknown_enum = other, "Unknown graphql_enum in PROVIDERS");
                    IntegrationService::Jira // fallback; will never happen with valid registry
                }
            }
        }

        // Single UNION-ALL round-trip across all registered providers
        // (2026-05-28 audit Perf#2); SQL builder + rationale live in
        // `talos_integrations::store::list_user_service_integrations`.
        let rows = talos_integrations::store::list_user_service_integrations(db_pool, *user_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: service integrations list failed");
                async_graphql::Error::new("Request could not be completed").extend_safe()
            })?;

        let integrations = rows
            .into_iter()
            .map(|row| ServiceIntegration {
                id: row.id,
                service: resolve_service(&row.service_tag),
                account_identifier: row.identifier,
                connected_at: row.created_at.to_rfc3339(),
                status: "active".to_string(),
            })
            .collect();

        Ok(integrations)
    }
}

#[cfg(test)]
mod world_description_parity_tests {
    use super::WORLD_DESCRIPTIONS;
    use talos_capability_world::ACTOR_CEILING_WORLDS;

    /// Every world in the canonical ACTOR_CEILING_WORLDS list must have a
    /// non-empty description in the local WORLD_DESCRIPTIONS map. Without
    /// this check, a new world added to talos-capability-world would
    /// silently surface in capability_world_hierarchy with an empty
    /// description string — invisible to UI consumers and confusing in
    /// docs / discovery flows.
    #[test]
    fn every_canonical_world_has_a_description() {
        let mut missing = Vec::new();
        for world in ACTOR_CEILING_WORLDS {
            let found = WORLD_DESCRIPTIONS
                .iter()
                .any(|(name, desc)| name == world && !desc.is_empty());
            if !found {
                missing.push(*world);
            }
        }
        assert!(
            missing.is_empty(),
            "WORLD_DESCRIPTIONS is missing entries for: {:?}. Add them to \
             talos-api/src/schema/platform/queries.rs to keep \
             capability_world_hierarchy in sync with talos-capability-world.",
            missing
        );
    }

    /// Conversely, no description should reference a world that no longer
    /// exists in ACTOR_CEILING_WORLDS — that means the canonical list was
    /// trimmed and the local map drifted. Treat as soft warning (panic in
    /// CI) so a planned removal can roll cleanly.
    #[test]
    fn no_description_for_removed_world() {
        let stale: Vec<&str> = WORLD_DESCRIPTIONS
            .iter()
            .filter(|(name, _)| !ACTOR_CEILING_WORLDS.contains(name))
            .map(|(name, _)| *name)
            .collect();
        assert!(
            stale.is_empty(),
            "WORLD_DESCRIPTIONS has entries for worlds no longer in \
             ACTOR_CEILING_WORLDS: {:?}. Remove them from \
             talos-api/src/schema/platform/queries.rs.",
            stale
        );
    }
}
