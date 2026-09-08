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
        // MCP-877 (2026-05-14) LOGGED this collapse; 2026-09-08 REMOVES it.
        // The log was the right diagnosis and the wrong remedy, and MCP-877's
        // own text says why: a DB error on the `users.totp_enabled` read
        // collapsed to `false`, and `is_two_factor_verified`'s
        // `.unwrap_or(!totp_enabled)` fallback below then defaulted to `true`.
        // So ONE unreadable column flipped BOTH security-gating booleans to
        // their permissive reading — "no 2FA, and you are verified" — which is
        // the single most reassuring pair this resolver can emit and is exactly
        // what a frontend gate consumes. A warning in a log the browser cannot
        // read does not stop that; only refusing to answer does.
        //
        // `?`-propagation rather than a `Readings` ledger, and that is forced
        // rather than chosen: `UserInfo` is a typed `SimpleObject` with no
        // slot for a disclosure, and `talos-api` carries no `talos-measurement`
        // dependency. The house shape for an unanswerable read in this crate is
        // the one three statements above — `.map_err(|e| … .extend_safe())?`
        // with the cause logged server-side and a generic message on the wire.
        //
        // Refusing the WHOLE query, including `id`/`email`, is the deliberate
        // part: those fields are not what `me` is read for at the moment it
        // matters, and a partial `me` that omits only the 2FA pair would be
        // read by an existing consumer as the pair being false.
        let totp_enabled = totp_service.is_2fa_enabled(*user_id).await.map_err(|e| {
            tracing::error!(
                user_id = %user_id,
                error = %e,
                "me query: is_2fa_enabled lookup failed — REFUSING rather than \
                 reporting two_factor_enabled=false, which (with the \
                 is_two_factor_verified fallback below) would report an \
                 unreadable 2FA state as 'no 2FA, and verified'"
            );
            async_graphql::Error::new("Failed to read two-factor status").extend_safe()
        })?;

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

        let (auth_url, _csrf_token, session_nonce) = oauth_service
            .get_authorization_url(provider_enum, None)
            .await
            .map_err(|e| {
                tracing::error!("Failed to generate auth URL: {}", e);
                async_graphql::Error::new("Failed to generate auth URL").extend_safe()
            })?;

        // S1 (login-CSRF defense): bind the `state` nonce to this browser by
        // setting the session-binding cookie that the REST callback requires.
        // Without it, a GraphQL-initiated login would always hit the new
        // "missing binding cookie" rejection on callback. The Cookies jar is
        // injected into the GraphQL context (same path `set_session_cookies`
        // uses in the auth mutations). If absent (non-HTTP context), the
        // login falls back to a legacy unbound flow on the callback.
        if let Ok(cookies) = ctx.data::<tower_cookies::Cookies>() {
            super::set_oauth_session_binding_cookie(cookies, &session_nonce);
        } else {
            tracing::warn!(
                "oauth_login_url: no Cookies in context; state nonce not bound to session"
            );
        }

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
