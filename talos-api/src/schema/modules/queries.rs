//! GraphQL Query resolvers (QueryRoot).

use async_graphql::{Context, Result};
use std::sync::Arc;
use uuid::Uuid;

use crate::schema::types::*;
use crate::schema::{require_scope, user_accessible_org_ids, SafeErrorExtensions};
use talos_registry::ModuleRegistry;

#[derive(Default)]
pub struct ModulesQueries;

#[async_graphql::Object]
impl ModulesQueries {
    async fn module_execution_history(
        &self,
        ctx: &Context<'_>,
        module_id: Uuid,
        pagination: Option<PaginationInput>,
    ) -> Result<Vec<ModuleExecution>> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;

        let execution_service = ctx
            .data::<Arc<talos_module_executions::ModuleExecutionService>>()
            .map_err(|e| e.extend_safe())?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;

        // MCP-811 (2026-05-14): clamp(1, 1000) not min(1000). Caller
        // `Some(-1)` propagates to Postgres LIMIT -1 → 500. Sibling
        // fix class to MCP-767.
        let limit_val = pagination
            .as_ref()
            .and_then(|p| p.limit)
            .unwrap_or(50)
            .clamp(1, 1000) as i64;
        let offset_val = pagination
            .as_ref()
            .and_then(|p| p.offset)
            .unwrap_or(0)
            .max(0) as i64;

        let executions = execution_service
            .get_module_executions(module_id, *user_id, limit_val, offset_val)
            .await
            .map_err(|e| {
                tracing::error!("Failed to fetch execution history: {}", e);
                async_graphql::Error::new("Failed to fetch execution history").extend_safe()
            })?;

        Ok(executions.into_iter().map(Into::into).collect())
    }

    async fn module_execution_logs(
        &self,
        ctx: &Context<'_>,
        execution_id: Uuid,
    ) -> Result<Vec<ModuleExecutionLog>> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;

        let execution_service = ctx
            .data::<Arc<talos_module_executions::ModuleExecutionService>>()
            .map_err(|e| e.extend_safe())?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;

        // Explicit authorization check
        if execution_service
            .get_execution(execution_id, *user_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to verify execution access: {}", e);
                async_graphql::Error::new("Failed to verify execution access").extend_safe()
            })?
            .is_none()
        {
            return Err(async_graphql::Error::new("Not found or permission denied").extend_safe());
        }

        let logs = execution_service
            .get_execution_logs(execution_id, *user_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to fetch execution logs: {}", e);
                async_graphql::Error::new("Failed to fetch execution logs").extend_safe()
            })?;

        Ok(logs.into_iter().map(Into::into).collect())
    }

    async fn node_templates(
        &self,
        ctx: &Context<'_>,
        category: Option<String>,
        pagination: Option<PaginationInput>,
    ) -> Result<Vec<NodeTemplate>> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;

        let registry = ctx.data::<Arc<ModuleRegistry>>()?;

        // Get pagination parameters
        let pagination = pagination.unwrap_or(PaginationInput {
            limit: Some(100),
            offset: Some(0),
        });
        let limit = pagination.get_limit();
        let offset = pagination.get_offset();

        // MCP-794 (2026-05-14): user-scoped paginated template listing.
        // Pre-fix this called the unscoped `list_templates_paginated`
        // which executed `FROM modules` with no user_id filter — any
        // authenticated user could enumerate metadata (name,
        // description, config_schema, allowed_hosts) of every other
        // user's private templates by paging through the result.
        // Less severe than MCP-793 (1) which leaked source_code, but
        // same IDOR class as MCP-793 (2) `node_template` (singular)
        // and the one-line fix mirrors it: switch to the user-scoped
        // helper that gates `WHERE user_id IS NULL OR user_id = $X`.
        // Catalog templates (NULL owner) remain visible to everyone;
        // private templates resolve only for their owner.
        let user_id = ctx.data::<Uuid>()?;
        let templates: Vec<talos_registry::NodeTemplate> = registry
            .list_templates_paginated_for_user(category.as_deref(), *user_id, limit, offset)
            .await?;

        Ok(templates
            .into_iter()
            .map(|t| NodeTemplate {
                id: t.id,
                name: t.name,
                category: t.category,
                description: t.description,
                // Serialize the JSON schema; panic only on unexpected serialization failure.
                config_schema: serde_json::to_string(&t.config_schema)
                    .unwrap_or_else(|_| "{}".to_string()),
                icon: t.icon,
                allowed_hosts: t.allowed_hosts,
                capability_world: t.capability_world,
                requires_secrets: t.allowed_secrets,
                requires_approval_for: t.requires_approval_for,
            })
            .collect())
    }

    async fn node_template(&self, ctx: &Context<'_>, id: Uuid) -> Result<NodeTemplate> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;

        // MCP-793 (2026-05-14): user-scoped template lookup. Pre-fix this
        // called the unscoped `get_template(id)` which executed
        // `WHERE id = $1` with no user_id filter — letting any
        // authenticated user fetch name/description/config_schema/
        // allowed_hosts of any other user's private template by knowing
        // its UUID. Less severe than the sibling mutation
        // `create_module_from_template` (which also surfaces source_code
        // and lets the attacker COMPILE/USE the leaked module), but the
        // same IDOR class and the same one-line fix. The returned
        // `NodeTemplate` GraphQL type omits source_code, so the
        // unscoped call only ever exposed metadata — still a tenant-
        // isolation violation. `get_template_for_user(id, user_id)`
        // adds `AND (user_id IS NULL OR user_id = $2)`; catalog
        // templates (NULL owner) stay public, private templates
        // resolve only for their owner.
        let registry = ctx.data::<Arc<ModuleRegistry>>()?;
        let user_id = ctx.data::<Uuid>()?;
        let t = registry.get_template_for_user(id, *user_id).await?;

        Ok(NodeTemplate {
            id: t.id,
            name: t.name,
            category: t.category,
            description: t.description,
            config_schema: serde_json::to_string(&t.config_schema)
                .unwrap_or_else(|_| "{}".to_string()),
            icon: t.icon,
            allowed_hosts: t.allowed_hosts,
            capability_world: t.capability_world,
            requires_secrets: t.allowed_secrets,
            requires_approval_for: t.requires_approval_for,
        })
    }

    async fn wasm_modules(&self, ctx: &Context<'_>, ids: Vec<Uuid>) -> Result<Vec<WasmModule>> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;

        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        let org_ids: Vec<uuid::Uuid> = user_accessible_org_ids(ctx).await?;

        // Phase 5.1: unified `modules` table; bare-pool read preserved —
        // scoping is the explicit (user_id, org_ids) predicate in the repo.
        let repo = talos_module_repository::ModuleRepository::new(db_pool.clone());
        let modules = repo
            .get_modules_by_ids_scoped(&ids, *user_id, &org_ids)
            .await
            .map_err(|e| {
                tracing::error!("Failed to fetch modules: {}", e);
                async_graphql::Error::new("Failed to fetch modules").extend_safe()
            })?;

        Ok(modules
            .into_iter()
            .map(|m| WasmModule {
                id: m.id,
                name: m.name,
                size_bytes: m.size_bytes,
                content_hash: m.content_hash,
                compiled_at: m.compiled_at.to_rfc3339(),
                config: m
                    .config
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "{}".to_string()),
                config_schema: m.config_schema.map(|c| c.to_string()),
                catalog_slug: m.catalog_slug,
                capability_world: m.capability_world,
                imported_interfaces: m.imported_interfaces,
                source_code: m.source_code,
                language: m.language,
            })
            .collect())
    }

    async fn my_modules(
        &self,
        ctx: &Context<'_>,
        pagination: Option<PaginationInput>,
    ) -> Result<Vec<WasmModule>> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;

        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        // MCP-811 (2026-05-14): clamp(1, 1000) not min(1000) — see
        // module_executions above for the rationale.
        let limit_val = pagination
            .as_ref()
            .and_then(|p| p.limit)
            .unwrap_or(100)
            .clamp(1, 1000) as i64;
        let offset_val = pagination
            .as_ref()
            .and_then(|p| p.offset)
            .unwrap_or(0)
            .max(0) as i64;

        let org_ids: Vec<uuid::Uuid> = user_accessible_org_ids(ctx).await?;

        // Phase 5: unified `modules` table; bare-pool read preserved.
        // Scope stays on (user_id, org_id) — catalog rows have NULL
        // user_id and are excluded from "my modules".
        let repo = talos_module_repository::ModuleRepository::new(db_pool.clone());
        let modules = repo
            .list_modules_for_user_paginated(*user_id, &org_ids, limit_val, offset_val)
            .await
            .map_err(|e| {
                tracing::error!("Failed to fetch modules: {}", e);
                async_graphql::Error::new("Failed to fetch modules").extend_safe()
            })?;

        Ok(modules
            .into_iter()
            .map(|m| WasmModule {
                id: m.id,
                name: m.name,
                size_bytes: m.size_bytes,
                content_hash: m.content_hash,
                compiled_at: m.compiled_at.to_rfc3339(),
                config: m
                    .config
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "{}".to_string()),
                config_schema: m.config_schema.map(|c| c.to_string()),
                catalog_slug: m.catalog_slug,
                capability_world: m.capability_world,
                imported_interfaces: m.imported_interfaces,
                source_code: m.source_code,
                language: m.language,
            })
            .collect())
    }
}
