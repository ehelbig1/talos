//! GraphQL Mutation resolvers (MutationRoot).

use async_graphql::{Context, Result};
use std::sync::Arc;
use uuid::Uuid;

use super::super::{require_2fa, require_scope, SafeErrorExtensions};
use crate::validation::validate_description_content;

#[derive(Default)]
pub struct ExecutionsMutations;

#[async_graphql::Object]
impl ExecutionsMutations {
    async fn retry_execution(&self, ctx: &Context<'_>, execution_id: Uuid) -> Result<Uuid> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsWrite)?;

        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;

        // MCP-827 (2026-05-14): collapsed ~250 lines of inline retry-
        // dispatch logic into a single call to the canonical
        // `ExecutionOrchestrationService::retry`. Pre-fix this handler
        // re-implemented the entire dispatch flow (load row + status
        // gate + actor authorization + graph load + execution-row reset
        // + spawn task + engine build + run + mark
        // completed/failed/failure-webhook + scratchpad trace), in
        // parallel with the same logic on the MCP-side handler
        // (`handle_retry_execution`). Same drift class as the MCP-825
        // / MCP-826 "GraphQL re-implements what the service already
        // does" pattern.
        //
        // Every bug-fix on the retry path had to land in BOTH places —
        // the historical comments scattered through the deleted block
        // (MCP-651, MCP-682, MCP-729, MCP-777) each required a sibling
        // fix on the service-side `talos-execution-orchestration::retry`
        // (MCP-557, MCP-707). Routing through the service collapses
        // that surface — future fixes land in one place.
        //
        // Cross-protocol parity is the explicit architectural mandate
        // (CLAUDE.md "GraphQL handlers must mirror MCP RBAC checks"
        // family — MCP-292). The service IS the mirror; using it makes
        // the parity load-bearing instead of aspirational.
        let orchestration_service = ctx
            .data::<Arc<talos_execution_orchestration::ExecutionOrchestrationService>>()
            .map_err(|_| {
                async_graphql::Error::new(
                    "Execution orchestration service unavailable — cannot retry",
                )
                .extend_safe()
            })?;

        let outcome = orchestration_service
            .retry(talos_execution_orchestration::RetryInput {
                execution_id,
                user_id,
            })
            .await
            .map_err(|e| {
                use talos_execution_orchestration::OrchestrationError;
                // Stable JSON-RPC-style code mapping mirrors the MCP
                // path so cross-protocol callers see consistent error
                // shapes. The user-facing message comes from the
                // typed error's Display impl (already operator-
                // friendly per the service-side comments).
                match &e {
                    OrchestrationError::InvalidArgument(_)
                    | OrchestrationError::ValidationFailed(_)
                    | OrchestrationError::WorkflowNotFound(_)
                    | OrchestrationError::ExecutionNotFound(_)
                    | OrchestrationError::ExecutionPaused
                    | OrchestrationError::WorkflowDisabled(_)
                    | OrchestrationError::StatusConflict(_)
                    | OrchestrationError::AuthorizationDenied(_)
                    | OrchestrationError::ConcurrencyLimitExceeded(_) => {
                        async_graphql::Error::new(e.to_string()).extend_safe()
                    }
                    OrchestrationError::DispatchFailed(_)
                    | OrchestrationError::Database(_)
                    | OrchestrationError::Internal(_) => {
                        tracing::error!(execution_id = %execution_id, "retry_execution: {}", e);
                        async_graphql::Error::new("Internal error during retry").extend_safe()
                    }
                }
            })?;

        Ok(outcome.execution_id)
    }

    async fn approve_execution(
        &self,
        ctx: &Context<'_>,
        id: Uuid,
        reason: Option<String>,
    ) -> Result<bool> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsWrite)?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        // MCP-867 (2026-05-14): trim + length-cap + control-char gate
        // on the audit-trail reason. Pre-fix the field bound directly
        // into the UPDATE: no trim (whitespace-only persisted, ragged
        // dashboards), no length cap (multi-MB strings into TEXT),
        // no `\0`/control-char rejection (embedded `\0` would crash
        // the UPDATE with an opaque "invalid input syntax for type
        // text"). Canonical helper from MCP-837 normalises here.
        let reason = match reason.as_deref() {
            Some(s) if !s.trim().is_empty() => {
                Some(validate_description_content("approval reason", s, 1000)?.to_string())
            }
            _ => None,
        };

        // RFC 0005 S3: per-user scoped tx so the workflows RLS policy
        // backstops the ownership JOIN (the gate is `w.user_id = $1` on
        // the joined workflow; execution_approvals has no policy itself).
        let mut tx = talos_db::begin_user_scoped(db_pool, user_id)
            .await
            .map_err(|e| async_graphql::Error::new(format!("tenant scope: {e}")).extend_safe())?;
        let result = sqlx::query!(
            "UPDATE execution_approvals \
             SET status = 'approved', decided_at = NOW(), decided_by = $1, reason = $2 \
             FROM workflows w \
             WHERE execution_approvals.id = $3 AND w.id = execution_approvals.workflow_id AND w.user_id = $1",
            user_id,
            reason,
            id
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| e.extend_safe())?;
        tx.commit()
            .await
            .map_err(|e| async_graphql::Error::new(format!("commit: {e}")).extend_safe())?;

        if result.rows_affected() == 0 {
            return Err(
                async_graphql::Error::new("Approval request not found or access denied")
                    .extend_safe(),
            );
        }

        Ok(true)
    }

    async fn deny_execution(
        &self,
        ctx: &Context<'_>,
        id: Uuid,
        reason: Option<String>,
    ) -> Result<bool> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsWrite)?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        // MCP-867 (2026-05-14): same content-discipline normalization
        // as approve_execution above. Sibling site.
        let reason = match reason.as_deref() {
            Some(s) if !s.trim().is_empty() => {
                Some(validate_description_content("denial reason", s, 1000)?.to_string())
            }
            _ => None,
        };

        // RFC 0005 S3: per-user scoped tx → workflows RLS backstops the
        // ownership JOIN (see approve_execution).
        let mut tx = talos_db::begin_user_scoped(db_pool, user_id)
            .await
            .map_err(|e| async_graphql::Error::new(format!("tenant scope: {e}")).extend_safe())?;
        let result = sqlx::query!(
            "UPDATE execution_approvals \
             SET status = 'denied', decided_at = NOW(), decided_by = $1, reason = $2 \
             FROM workflows w \
             WHERE execution_approvals.id = $3 AND w.id = execution_approvals.workflow_id AND w.user_id = $1",
            user_id,
            reason,
            id
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| e.extend_safe())?;
        tx.commit()
            .await
            .map_err(|e| async_graphql::Error::new(format!("commit: {e}")).extend_safe())?;

        if result.rows_affected() == 0 {
            return Err(
                async_graphql::Error::new("Approval request not found or access denied")
                    .extend_safe(),
            );
        }

        Ok(true)
    }
}
