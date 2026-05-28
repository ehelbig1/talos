//! GraphQL Query resolvers (QueryRoot).

use async_graphql::{Context, Object, Result};
use std::sync::Arc;
use uuid::Uuid;

use crate::schema::types::{PaginationInput, Secret, SecretAuditLog};
use crate::schema::{require_scope, user_accessible_org_ids, SafeErrorExtensions};

#[derive(Default)]
pub struct SecretsQueries;

#[Object]
impl SecretsQueries {
    async fn secrets(
        &self,
        ctx: &Context<'_>,
        pagination: Option<PaginationInput>,
    ) -> Result<Vec<Secret>> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::SecretsRead)?;

        let secrets_manager = ctx.data::<Arc<talos_secrets_manager::SecretsManager>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        // Get org IDs the user belongs to for org-level access
        let org_ids: Vec<uuid::Uuid> = user_accessible_org_ids(ctx).await?;

        // MCP-811 (2026-05-14): clamp(1, 1000) not min(1000). A caller-
        // supplied `pagination.limit = Some(-1)` (i32) propagates to
        // Postgres `LIMIT -1` → 500. Sibling fix class to MCP-767
        // (mcp-handlers/actor.rs) and MCP-724/725. PaginationInput's
        // own `get_limit()` helper already uses clamp; this inline
        // path had drifted.
        let capped_limit = pagination
            .as_ref()
            .and_then(|p| p.limit)
            .unwrap_or(100)
            .clamp(1, 1000) as i64;
        let offset_val = pagination
            .as_ref()
            .and_then(|p| p.offset)
            .unwrap_or(0)
            .max(0) as i64;

        let secrets: Vec<talos_secrets_manager::Secret> = secrets_manager
            .list_secrets_paginated(Some(*user_id), capped_limit, offset_val, &org_ids)
            .await?;

        Ok(secrets
            .into_iter()
            .map(|s: talos_secrets_manager::Secret| Secret {
                id: s.id,
                name: s.name,
                key_path: s.key_path,
                description: s.description,
                created_at: s.created_at.to_rfc3339(),
                last_accessed_at: s
                    .last_accessed_at
                    .map(|dt: chrono::DateTime<chrono::Utc>| dt.to_rfc3339()),
                access_count: s.access_count,
                expires_at: s
                    .expires_at
                    .map(|dt: chrono::DateTime<chrono::Utc>| dt.to_rfc3339()),
            })
            .collect())
    }

    async fn secret(&self, ctx: &Context<'_>, key_path: String) -> Result<Secret> {
        crate::schema::require_scope(ctx, talos_api_keys::ApiKeyScope::SecretsRead)?;

        // MCP-1003 sibling: the secret(key_path) READ surface must apply
        // the same canonical validation the create/update/delete mutations
        // enforce, or callers can probe rows with uppercase / `//` /
        // control-char / path-traversal-shaped key_paths that are
        // unreachable via the documented vault_path_permitted matcher.
        crate::validation::validate_vault_key_path(&key_path)?;

        let secrets_manager = ctx.data::<Arc<talos_secrets_manager::SecretsManager>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        // Get org IDs the user belongs to for cross-org secret visibility
        let org_ids: Vec<uuid::Uuid> = crate::schema::user_accessible_org_ids(ctx).await?;

        // L T2-1: ownership filter is now at the SQL layer inside
        // get_secret_metadata. Both the "row doesn't exist" and "row
        // exists but isn't accessible" cases produce the same Err and
        // the same client-facing message — no existence side-channel.
        // MCP-872 (2026-05-14): log the underlying secrets-manager
        // error before collapsing to "Secret not found" so a DB outage
        // / decryption failure / connection timeout is distinguishable
        // from a real not-found hit on the operator side. The
        // user-facing message stays generic (no existence
        // side-channel per the L T2-1 comment above).
        let internal_secret: talos_secrets_manager::Secret = secrets_manager
            .get_secret_metadata(&key_path, *user_id, &org_ids)
            .await
            .map_err(|e| {
                tracing::error!(
                    key_path = %key_path,
                    error = %e,
                    "get_secret_metadata failed"
                );
                // MCP-964: lowercase 'n' misses case-sensitive whitelist.
                async_graphql::Error::new("Secret not found").extend_safe()
            })?;

        Ok(Secret {
            id: internal_secret.id,
            name: internal_secret.name,
            key_path: internal_secret.key_path,
            description: internal_secret.description,
            created_at: internal_secret.created_at.to_rfc3339(),
            last_accessed_at: internal_secret
                .last_accessed_at
                .map(|dt: chrono::DateTime<chrono::Utc>| dt.to_rfc3339()),
            access_count: internal_secret.access_count,
            expires_at: internal_secret
                .expires_at
                .map(|dt: chrono::DateTime<chrono::Utc>| dt.to_rfc3339()),
        })
    }

    async fn secret_audit_log(
        &self,
        ctx: &Context<'_>,
        secret_id: Uuid,
        pagination: Option<PaginationInput>,
    ) -> Result<Vec<SecretAuditLog>> {
        crate::schema::require_scope(ctx, talos_api_keys::ApiKeyScope::SecretsRead)?;

        let secrets_manager = ctx.data::<Arc<talos_secrets_manager::SecretsManager>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        // MCP-811 (2026-05-14): clamp(1, 1000) not min(1000) — see
        // list_secrets above for the rationale.
        let capped_limit = pagination
            .as_ref()
            .and_then(|p| p.limit)
            .unwrap_or(100)
            .clamp(1, 1000) as i64;
        let offset_val = pagination
            .as_ref()
            .and_then(|p| p.offset)
            .unwrap_or(0)
            .max(0) as i64;

        let audit_entries: Vec<talos_secrets_manager::AuditLogEntry> = match secrets_manager
            .get_audit_log(secret_id, capped_limit, offset_val, Some(*user_id))
            .await
        {
            Ok(entries) => entries,
            Err(_) => {
                // MCP-918: .extend_safe() — generic outer message is
                // correct (underlying error logged server-side).
                return Err(
                    async_graphql::Error::new("Failed to fetch audit log").extend_safe(),
                );
            }
        };

        let logs: Vec<SecretAuditLog> = audit_entries
            .into_iter()
            .map(|l: talos_secrets_manager::AuditLogEntry| SecretAuditLog {
                id: l.id,
                action: l.action,
                actor_type: l.actor_type,
                success: l.success,
                timestamp: l.timestamp.to_rfc3339(),
                error_message: l.error_message,
            })
            .collect();

        Ok(logs)
    }
}
