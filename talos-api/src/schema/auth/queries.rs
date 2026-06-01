//! GraphQL Query resolvers (QueryRoot).

use async_graphql::{Context, Result};
use std::sync::Arc;
use uuid::Uuid;

use crate::schema::{types::*, IsTwoFactorVerified, SafeErrorExtensions};
// use crate::schema::user_accessible_org_ids; // unused
// use talos_compilation::CompilationService; // unused
// use talos_registry::ModuleRegistry; // unused
// use talos_workflow_versions::WorkflowVersionService; // unused
#[allow(unused_imports)]
use crate::schema::types::*;

#[derive(Default)]
pub struct AuthQueries;

#[async_graphql::Object]
impl AuthQueries {
    async fn me(&self, ctx: &Context<'_>) -> Result<UserInfo> {
        let auth_service = ctx
            .data::<Arc<talos_auth::AuthService>>()
            .map_err(|e| e.extend_safe())?;
        let totp_service = ctx
            .data::<Arc<talos_totp_2fa::TotpService>>()
            .map_err(|e| e.extend_safe())?;

        // Get user_id from context (set by auth middleware)
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Not authenticated").extend_safe())?;

        let user = auth_service.get_user(*user_id).await.map_err(|e| {
            tracing::error!("Failed to get user: {}", e);
            async_graphql::Error::new("Failed to get user").extend_safe()
        })?;

        // Check if 2FA is enabled.
        //
        // MCP-877 (2026-05-14): log the underlying error on the
        // `.unwrap_or(false)` fallback so operators see when the `me`
        // response silently lies about 2FA state. Pre-fix a DB error
        // on `users.totp_enabled` read collapsed to `false`, and the
        // downstream `is_two_factor_verified = !totp_enabled` fallback
        // (only fires when the auth middleware didn't set
        // `IsTwoFactorVerified`) then defaulted to `true`. Combined
        // failure mode: response says "no 2FA, all verified" while the
        // user might in reality have 2FA enrolled but un-verified —
        // misleading frontend gating + zero operator signal. Same
        // silent-lie observability gap as MCP-872/874/876.
        let totp_enabled = match totp_service.is_2fa_enabled(*user_id).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    user_id = %user_id,
                    error = %e,
                    "me query: is_2fa_enabled lookup failed — \
                     returning two_factor_enabled=false (the IsTwoFactorVerified \
                     middleware extension is the authoritative source for the \
                     verified flag, but this lie can still mislead frontend gating)"
                );
                false
            }
        };

        // Get 2FA verification status from context (set by auth middleware)
        let is_two_factor_verified = ctx
            .data_opt::<IsTwoFactorVerified>()
            .map(|v| v.0)
            .unwrap_or(!totp_enabled);

        Ok(UserInfo {
            id: user.id,
            email: user.email,
            name: user.name,
            created_at: user.created_at.to_rfc3339(),
            two_factor_enabled: totp_enabled,
            is_two_factor_verified,
        })
    }

    async fn oauth_login_url(&self, ctx: &Context<'_>, provider: String) -> Result<OAuthAuthUrl> {
        let oauth_service = ctx.data::<Arc<talos_oauth::OAuthService>>()?;

        let provider_enum = talos_oauth::OAuthProvider::from_str(&provider).map_err(|e| {
            tracing::error!("Invalid provider: {}", e);
            async_graphql::Error::new("Invalid provider").extend_safe()
        })?;

        if !oauth_service.is_provider_enabled(&provider_enum) {
            // MCP-918: .extend_safe() — operator needs to know which
            // provider is misconfigured, not "Internal server error".
            return Err(
                async_graphql::Error::new(format!("{} OAuth is not configured", provider))
                    .extend_safe(),
            );
        }

        let (auth_url, _csrf_token) = oauth_service
            .get_authorization_url(provider_enum, None)
            .await
            .map_err(|e| {
                tracing::error!("Failed to generate auth URL: {}", e);
                async_graphql::Error::new("Failed to generate auth URL").extend_safe()
            })?;

        Ok(OAuthAuthUrl { auth_url, provider })
    }

    async fn linked_oauth_accounts(&self, ctx: &Context<'_>) -> Result<Vec<OAuthAccount>> {
        // MCP-757 sibling: paired mutation `disconnect_service_integration`
        // is `require_2fa` + Admin-scoped; this read surface had no scope
        // gate, so a non-Admin API key (Memory-only / Webhooks-only) could
        // enumerate the user's full OAuth-linked-identity set (provider,
        // email, name, picture, timestamps) — recon useful for targeted
        // phishing. Admin scope here matches the write surface; session-
        // authenticated callers (dashboard) pass through `require_scope`
        // unchanged.
        crate::schema::require_scope(ctx, talos_api_keys::ApiKeyScope::Admin)?;

        let oauth_service = ctx.data::<Arc<talos_oauth::OAuthService>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;

        let accounts = oauth_service
            .get_user_oauth_accounts(*user_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to get OAuth accounts: {}", e);
                async_graphql::Error::new("Failed to get OAuth accounts").extend_safe()
            })?;

        Ok(accounts
            .into_iter()
            .map(|a| OAuthAccount {
                id: a.id,
                provider: a.provider,
                email: a.email,
                name: a.name,
                picture_url: a.picture_url,
                linked_at: a.created_at.map(|dt| dt.to_rfc3339()).unwrap_or_default(),
                last_login_at: a.last_login_at.map(|dt| dt.to_rfc3339()),
            })
            .collect())
    }
}
