//! GraphQL Query resolvers (QueryRoot).

use async_graphql::{Context, Result};
use uuid::Uuid;

use crate::schema::types::*;
use crate::schema::{require_scope, SafeErrorExtensions};
// use crate::schema::user_accessible_org_ids; // unused
// use talos_compilation::CompilationService; // unused
// use talos_registry::ModuleRegistry; // unused
// use talos_workflow_versions::WorkflowVersionService; // unused
#[allow(unused_imports)]
use super::super::*;
#[allow(unused_imports)]
use crate::schema::types::*;

#[derive(Default)]
pub struct WebhooksQueries;

#[async_graphql::Object]
impl WebhooksQueries {
    async fn webhook_triggers(
        &self,
        ctx: &Context<'_>,
        pagination: Option<PaginationInput>,
    ) -> Result<Vec<WebhookTrigger>> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::WebhooksAccess)?;

        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;
        // MCP-631: empty-env hardening.
        let base_url = talos_config::get_base_url();

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        // Get pagination parameters
        let pagination = pagination.unwrap_or(PaginationInput {
            limit: Some(100),
            offset: Some(0),
        });
        let limit = pagination.get_limit();
        let offset = pagination.get_offset();

        // Bare-pool read preserved — webhook_triggers is user-scoped by
        // predicate, not org-pinned RLS.
        let repo = talos_webhook_repository::WebhookRepository::new(db_pool.clone());
        let listeners = repo
            .list_for_user_with_stats(*user_id, limit, offset)
            .await
            .map_err(|e| {
                tracing::error!("Failed to list webhook triggers: {}", e);
                async_graphql::Error::new("Failed to list webhook triggers").extend_safe()
            })?;

        Ok(listeners
            .into_iter()
            .map(|l| WebhookTrigger {
                id: l.id,
                module_id: l.module_id,
                name: l.name,
                webhook_url: format!("{}/webhooks/{}", base_url, l.id),
                verification_token: None, // Don't expose token in list queries
                enabled: l.enabled,
                max_requests_per_minute: l.max_requests_per_minute,
                trigger_count: l.trigger_count,
                success_count: l.success_count,
                error_count: l.error_count,
                last_triggered_at: l.last_triggered_at.map(|dt| dt.to_rfc3339()),
                event_filter: l.event_filter,
            })
            .collect())
    }

    async fn webhook_dead_letter_queue(&self, ctx: &Context<'_>) -> Result<Vec<WebhookDlqEntry>> {
        // MCP-757 (2026-05-13): scope-drift sibling to
        // `webhook_triggers` above which requires WebhooksAccess.
        // Pre-fix this query was reachable by any authenticated
        // caller — sessions ignore scope by design, but an API key
        // issued without WebhooksAccess could still enumerate the
        // user's webhook DLQ (trigger_id, source_ip, drop_reason,
        // headers, payload). Same per-file scope-drift class as
        // MCP-292 closed for actor mutations.
        require_scope(ctx, talos_api_keys::ApiKeyScope::WebhooksAccess)?;

        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        // Bare-pool read preserved — ownership is the JOIN on
        // webhook_triggers.user_id, not org-pinned RLS.
        let repo = talos_webhook_repository::WebhookRepository::new(db_pool.clone());
        let rows = repo.list_dlq_for_user(user_id, 200).await.map_err(|e| {
            tracing::error!("Failed to list webhook DLQ: {}", e);
            async_graphql::Error::new("Failed to list webhook DLQ").extend_safe()
        })?;

        Ok(rows
            .into_iter()
            .map(|row| WebhookDlqEntry {
                id: row.id,
                trigger_id: row.trigger_id,
                source_ip: row.source_ip,
                drop_reason: row.drop_reason,
                headers: row.headers,
                payload: row.payload,
                created_at: row.created_at.to_rfc3339(),
                replayed_at: row.replayed_at.map(|t| t.to_rfc3339()),
                replayed_by: row.replayed_by,
            })
            .collect())
    }

    async fn dead_letter_queue(&self, ctx: &Context<'_>) -> Result<Vec<DeadLetterEntry>> {
        // MCP-757 (2026-05-13): scope drift — this query reads workflow
        // DLQ entries (joins `workflows`), not webhook DLQ. The
        // semantically correct gate is `WorkflowsRead`, matching the
        // dataset returned (`workflow_id`, `execution_id`, `node_id`,
        // `error_message`, `payload`). Pre-fix any authenticated caller
        // could call this regardless of API key scope. Same per-file
        // scope-drift class as MCP-292.
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;

        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        // RFC 0005 S3: per-user scoped tx so the workflows RLS policy
        // backstops the ownership JOIN (dead_letter_queue has no policy of
        // its own; the gate is `w.user_id = $1` on the joined workflow).
        // The repo method takes the tx — executor preserved.
        let mut tx = talos_db::begin_user_scoped(db_pool, user_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: tenant scope error");
                async_graphql::Error::new("Request scope error").extend_safe()
            })?;
        let exec_repo = talos_execution_repository::ExecutionRepository::new(db_pool.clone());
        let rows = exec_repo
            .list_dead_letter_queue_scoped(&mut tx, user_id, 200)
            .await
            .map_err(|e| {
                tracing::error!("Failed to list dead letter queue: {}", e);
                async_graphql::Error::new("Failed to list dead letter queue").extend_safe()
            })?;
        tx.commit().await.map_err(|e| {
            tracing::error!(error = %e, "graphql: commit transaction error");
            async_graphql::Error::new("Request could not be completed").extend_safe()
        })?;

        Ok(rows
            .into_iter()
            .map(|row| DeadLetterEntry {
                id: row.id,
                workflow_id: row.workflow_id,
                execution_id: row.execution_id,
                node_id: row.node_id,
                error_message: row.error_message,
                payload: row.payload,
                created_at: row.created_at.to_rfc3339(),
                replayed_at: row.replayed_at.map(|t| t.to_rfc3339()),
                replayed_by: row.replayed_by,
            })
            .collect())
    }
}
