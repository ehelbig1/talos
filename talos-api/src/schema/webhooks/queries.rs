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

        let listeners = sqlx::query!(
            r#"
            SELECT id, name, module_id,
                   enabled as "enabled!",
                   max_requests_per_minute as "max_requests_per_minute!",
                   trigger_count as "trigger_count!",
                   success_count as "success_count!",
                   error_count as "error_count!",
                   last_triggered_at
            FROM webhook_triggers
            WHERE user_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
            user_id,
            limit,
            offset
        )
        .fetch_all(db_pool)
        .await?;

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

        use sqlx::Row;
        let rows = sqlx::query(
            r#"
            SELECT d.id, d.trigger_id, d.source_ip::text, d.drop_reason,
                   d.headers::text, d.payload::text, d.created_at,
                   d.replayed_at, d.replayed_by
            FROM webhook_dlq d
            JOIN webhook_triggers t ON t.id = d.trigger_id
            WHERE t.user_id = $1
            ORDER BY d.created_at DESC
            LIMIT 200
            "#,
        )
        .bind(user_id)
        .fetch_all(db_pool)
        .await
        .map_err(|e| e.extend_safe())?;

        Ok(rows
            .into_iter()
            .map(|row| WebhookDlqEntry {
                id: row.get("id"),
                trigger_id: row.get("trigger_id"),
                source_ip: row.get("source_ip"),
                drop_reason: row.get("drop_reason"),
                headers: row.get("headers"),
                payload: row.get("payload"),
                created_at: row
                    .get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                    .to_rfc3339(),
                replayed_at: row
                    .get::<Option<chrono::DateTime<chrono::Utc>>, _>("replayed_at")
                    .map(|t| t.to_rfc3339()),
                replayed_by: row.get("replayed_by"),
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

        use sqlx::Row;
        let rows = sqlx::query(
            r#"
            SELECT d.id, d.workflow_id, d.execution_id, d.node_id, d.error_message, d.payload::text,
                   d.created_at, d.replayed_at, d.replayed_by
            FROM dead_letter_queue d
            JOIN workflows w ON w.id = d.workflow_id
            WHERE w.user_id = $1
            ORDER BY d.created_at DESC
            LIMIT 200
            "#,
        )
        .bind(user_id)
        .fetch_all(db_pool)
        .await
        .map_err(|e| e.extend_safe())?;

        Ok(rows
            .into_iter()
            .map(|row| DeadLetterEntry {
                id: row.get("id"),
                workflow_id: row.get("workflow_id"),
                execution_id: row.get("execution_id"),
                node_id: row.get("node_id"),
                error_message: row.get("error_message"),
                payload: row.get("payload"),
                created_at: row
                    .get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                    .to_rfc3339(),
                replayed_at: row
                    .get::<Option<chrono::DateTime<chrono::Utc>>, _>("replayed_at")
                    .map(|t| t.to_rfc3339()),
                replayed_by: row.get("replayed_by"),
            })
            .collect())
    }
}
