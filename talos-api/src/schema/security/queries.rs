//! GraphQL Query resolvers (QueryRoot).

use async_graphql::{Context, Result};
use std::sync::Arc;
use uuid::Uuid;

use crate::schema::types::*;
use crate::schema::{require_platform_admin, require_scope, SafeErrorExtensions};

/// Per-table per-org DEK migration status (one entry per encrypted table).
#[derive(async_graphql::SimpleObject)]
pub struct DekMigrationStatusEntry {
    /// Logical table/column label.
    pub table: String,
    /// True when a `reEncrypt…ToOrg` sweep drives `pending` to 0; false for the
    /// personal tables that migrate lazily on next write.
    pub has_sweep: bool,
    /// Rows still on the global DEK that have a resolvable org (remaining sweep
    /// work). 0 = migration complete for this table.
    pub pending: i64,
}
// use crate::schema::user_accessible_org_ids; // unused
// use talos_compilation::CompilationService; // unused
// use talos_registry::ModuleRegistry; // unused
// use talos_workflow_versions::WorkflowVersionService; // unused
#[allow(unused_imports)]
use super::super::*;
#[allow(unused_imports)]
use crate::schema::types::*;

#[derive(Default)]
pub struct SecurityQueries;

#[async_graphql::Object]
impl SecurityQueries {
    async fn audit_settings(&self, ctx: &Context<'_>) -> Result<Option<UserAuditSettings>> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::Admin)?;

        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        // user_audit_settings is user-keyed (not org-pinned RLS); bare-pool
        // read preserved through the pool-taking helper.
        let row = talos_audit_ledger::get_user_audit_settings(db_pool, user_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to fetch audit settings: {}", e);
                async_graphql::Error::new("Failed to fetch audit settings").extend_safe()
            })?;

        Ok(row.map(|r| UserAuditSettings {
            streaming_enabled: r.streaming_enabled,
            otlp_endpoint: r.otlp_endpoint,
            otlp_protocol: r.otlp_protocol,
            created_at: r.created_at.to_rfc3339(),
            updated_at: r.updated_at.to_rfc3339(),
        }))
    }

    /// Per-org DEK migration status — per encrypted table, how many rows still
    /// reference the global DEK but could be migrated to a per-org DEK (the
    /// remaining work for the `reEncrypt…ToOrg` sweeps). When every `pending` is
    /// 0, the global DEK is no longer load-bearing for migratable data.
    /// Platform-admin only (reveals system-wide counts across all orgs).
    async fn dek_migration_status(
        &self,
        ctx: &Context<'_>,
    ) -> Result<Vec<DekMigrationStatusEntry>> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::Admin)?;
        require_platform_admin(ctx).await?;

        let secrets_manager = ctx.data::<Arc<talos_secrets_manager::SecretsManager>>()?;
        let rows = secrets_manager.dek_migration_status().await.map_err(|e| {
            tracing::error!("dek_migration_status failed: {}", e);
            async_graphql::Error::new("Failed to read DEK migration status").extend_safe()
        })?;

        Ok(rows
            .into_iter()
            .map(|r| DekMigrationStatusEntry {
                table: r.table,
                has_sweep: r.has_sweep,
                pending: r.pending,
            })
            .collect())
    }

    async fn api_keys(
        &self,
        ctx: &Context<'_>,
        pagination: Option<PaginationInput>,
    ) -> Result<Vec<ApiKeyInfo>> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::Admin)?;

        let api_key_service = ctx.data::<Arc<talos_api_keys::ApiKeyService>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;

        // Get pagination parameters
        let pagination = pagination.unwrap_or(PaginationInput {
            limit: Some(100),
            offset: Some(0),
        });
        let limit = pagination.get_limit();
        let offset = pagination.get_offset();

        let keys = api_key_service
            .list_keys_paginated(*user_id, limit, offset)
            .await
            .map_err(|e| {
                tracing::error!("Failed to list API keys: {}", e);
                async_graphql::Error::new("Failed to list API keys").extend_safe()
            })?;

        Ok(keys
            .into_iter()
            .map(|k| ApiKeyInfo {
                id: k.id,
                name: k.name,
                key_prefix: k.key_prefix,
                scopes: k.scopes.iter().map(|s| s.to_string()).collect(),
                created_at: k.created_at.to_rfc3339(),
                expires_at: k.expires_at.map(|dt| dt.to_rfc3339()),
                last_used_at: k.last_used_at.map(|dt| dt.to_rfc3339()),
                is_active: k.is_active,
                usage_count: k.usage_count,
            })
            .collect())
    }
}
