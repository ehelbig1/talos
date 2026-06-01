//! GraphQL Mutation resolvers (MutationRoot).

use async_graphql::{Context, Result};
use std::sync::Arc;
use tower_cookies::Cookies;
use uuid::Uuid;

use crate::schema::types::*;
use crate::schema::{require_2fa, RequestMetadata, SafeErrorExtensions};

#[derive(Default)]
pub struct AuthMutations;

#[async_graphql::Object]
impl AuthMutations {
    async fn signup(&self, ctx: &Context<'_>, input: SignupInput) -> Result<AuthPayload> {
        // Distributed rate limiting for signup (same as login — prevents account enumeration spam)
        if let Ok(limiter) = ctx.data::<Arc<talos_rate_limit::DistributedRateLimiter>>() {
            let metadata = ctx.data_opt::<RequestMetadata>();
            let ip = metadata
                .and_then(|m| m.ip_address.as_deref())
                .unwrap_or("unknown");
            if !limiter.check(ip).await {
                return Err(async_graphql::Error::new(
                    "Too many signup attempts. Please try again later.",
                )
                .extend_safe());
            }
        }

        let auth_service = ctx.data::<Arc<talos_auth::AuthService>>()?;
        let metadata = ctx.data_opt::<RequestMetadata>();

        // Create user
        let user_id = auth_service
            .create_user(
                &input.email,
                &input.password,
                input.name.as_deref(),
                metadata.and_then(|m| m.ip_address.as_deref()),
                metadata.and_then(|m| m.user_agent.as_deref()),
            )
            .await
            .map_err(|e| {
                tracing::error!("Signup failed: {}", e);
                async_graphql::Error::new("Signup failed").extend_safe()
            })?;

        // Get user details
        let user = auth_service.get_user(user_id).await.map_err(|e| {
            tracing::error!("Failed to get user: {}", e);
            async_graphql::Error::new("Failed to get user").extend_safe()
        })?;

        // RFC 0004: every user gets a personal organization (their
        // org-as-tenant home). Best-effort — the user is already
        // committed, and `create_personal_org` is idempotent (the M1
        // backfill / a later call repairs a miss), so a transient failure
        // here must not fail an otherwise-successful signup. Once org_id
        // becomes required (M3) this moves into the same transaction.
        if let Ok(db_pool) = ctx.data::<sqlx::PgPool>() {
            if let Err(e) = talos_organizations::OrganizationService::create_personal_org(
                db_pool,
                user_id,
                user.name.as_deref(),
            )
            .await
            {
                tracing::error!(user_id = %user_id, "Failed to create personal org at signup (will be repaired): {e}");
            }
        }

        // Generate access token (short-lived: 15 minutes)
        // New users don't have 2FA enabled yet, so they are verified
        let access_token = auth_service
            .generate_access_token(&user, true)
            .map_err(|e| {
                tracing::error!("Failed to generate access token: {}", e);
                async_graphql::Error::new("Failed to generate access token").extend_safe()
            })?;

        // Generate refresh token (long-lived: 7 days)
        let refresh_token = auth_service
            .generate_refresh_token(user_id, true)
            .await
            .map_err(|e| {
                tracing::error!("Failed to generate refresh token: {}", e);
                async_graphql::Error::new("Failed to generate refresh token").extend_safe()
            })?;

        // Set httpOnly cookies if Cookies extension is available
        if let Ok(cookies) = ctx.data::<Cookies>() {
            // MCP-1040: canonical session-cookie installer.
            super::set_session_cookies(cookies, &access_token, &refresh_token);
        }

        Ok(AuthPayload {
            user: UserInfo {
                id: user.id,
                email: user.email,
                name: user.name,
                created_at: user.created_at.to_rfc3339(),
                two_factor_enabled: user.totp_enabled.unwrap_or(false),
                is_two_factor_verified: true,
            },
        })
    }

    async fn login(&self, ctx: &Context<'_>, input: LoginInput) -> Result<AuthPayload> {
        // Distributed rate limiting for auth endpoints (Redis-backed, falls back to in-memory)
        if let Ok(limiter) = ctx.data::<Arc<talos_rate_limit::DistributedRateLimiter>>() {
            let metadata = ctx.data_opt::<RequestMetadata>();
            let ip = metadata
                .and_then(|m| m.ip_address.as_deref())
                .unwrap_or("unknown");
            if !limiter.check(ip).await {
                return Err(async_graphql::Error::new(
                    "Too many login attempts. Please try again later.",
                )
                .extend_safe());
            }
        }

        let auth_service = ctx.data::<Arc<talos_auth::AuthService>>()?;
        let metadata = ctx.data_opt::<RequestMetadata>();

        // Authenticate user and get both access token and refresh token
        let (access_token, refresh_token, user) = auth_service
            .login(
                &input.email,
                &input.password,
                metadata.and_then(|m| m.ip_address.as_deref()),
                metadata.and_then(|m| m.user_agent.as_deref()),
            )
            .await
            .map_err(|e| {
                tracing::error!("Login failed: {}", e);
                async_graphql::Error::new("Login failed").extend_safe()
            })?;

        // Set httpOnly cookies if Cookies extension is available
        if let Ok(cookies) = ctx.data::<Cookies>() {
            // MCP-1040: canonical session-cookie installer.
            super::set_session_cookies(cookies, &access_token, &refresh_token);
        }

        let two_factor_enabled = user.totp_enabled.unwrap_or(false);
        Ok(AuthPayload {
            user: UserInfo {
                id: user.id,
                email: user.email,
                name: user.name,
                created_at: user.created_at.to_rfc3339(),
                two_factor_enabled,
                is_two_factor_verified: !two_factor_enabled,
            },
        })
    }

    async fn refresh_token(&self, ctx: &Context<'_>) -> Result<AuthPayload> {
        // Rate-limit token refresh to mitigate token exhaustion / flooding attacks.
        // Single-use rotation already invalidates stolen tokens, but rate limiting
        // prevents high-frequency hammering that could race the rotation window.
        if let Ok(limiter) = ctx.data::<Arc<talos_rate_limit::DistributedRateLimiter>>() {
            let metadata = ctx.data_opt::<RequestMetadata>();
            let ip = metadata
                .and_then(|m| m.ip_address.as_deref())
                .unwrap_or("unknown");
            if !limiter.check(ip).await {
                return Err(async_graphql::Error::new(
                    "Too many requests. Please try again later.",
                )
                .extend_safe());
            }
        }

        let auth_service = ctx.data::<Arc<talos_auth::AuthService>>()?;

        // Get refresh token from httpOnly cookie
        let cookies = ctx.data::<Cookies>()?;
        let refresh_token = cookies
            .get("talos_refresh_token")
            .ok_or_else(|| {
                async_graphql::Error::new("No refresh token found in cookies").extend_safe()
            })?
            .value()
            .to_string();

        // Validate old refresh token, generate new access token, and rotate refresh token.
        let (access_token, new_refresh_token, user, is_2fa_verified) = auth_service
            .refresh_access_token(&refresh_token)
            .await
            .map_err(|e| {
                tracing::error!("Token refresh failed: {}", e);
                async_graphql::Error::new("Token refresh failed").extend_safe()
            })?;

        // MCP-1040: canonical session-cookie installer. Rotates BOTH
        // cookies — overwriting `talos_refresh_token` with the new
        // value is what makes the rotation policy hold.
        super::set_session_cookies(cookies, &access_token, &new_refresh_token);

        Ok(AuthPayload {
            user: UserInfo {
                id: user.id,
                email: user.email,
                name: user.name,
                created_at: user.created_at.to_rfc3339(),
                two_factor_enabled: user.totp_enabled.unwrap_or(false),
                is_two_factor_verified: is_2fa_verified,
            },
        })
    }

    async fn logout(&self, ctx: &Context<'_>) -> Result<bool> {
        let auth_service = ctx.data::<Arc<talos_auth::AuthService>>()?;

        // Get refresh token from httpOnly cookie
        let cookies = ctx.data::<Cookies>()?;
        let refresh_token = cookies
            .get("talos_refresh_token")
            .ok_or_else(|| {
                async_graphql::Error::new("No refresh token found in cookies").extend_safe()
            })?
            .value()
            .to_string();

        auth_service
            .revoke_refresh_token(&refresh_token)
            .await
            .map_err(|e| {
                tracing::error!("Logout failed: {}", e);
                async_graphql::Error::new("Logout failed").extend_safe()
            })?;

        // MCP-1041: canonical session-cookie remover (path-aware).
        super::clear_session_cookies(cookies);

        Ok(true)
    }

    /// Revoke ALL active sessions for the authenticated user across all devices.
    /// Use this after a suspected account compromise or when a user wants to
    /// sign out everywhere. Clears the current device's cookies as well.
    async fn logout_all_sessions(&self, ctx: &Context<'_>) -> Result<bool> {
        let auth_service = ctx.data::<Arc<talos_auth::AuthService>>()?;
        let cookies = ctx.data::<Cookies>()?;

        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;

        auth_service
            .revoke_all_sessions(*user_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to revoke all sessions: {}", e);
                async_graphql::Error::new("Failed to revoke sessions").extend_safe()
            })?;

        // MCP-1041: canonical session-cookie remover. Clears the
        // current device's cookies in addition to revoking server-side
        // refresh-token rows above; without this the user appears
        // logged-in client-side after a successful logout_all_sessions
        // call until the access-token JWT expires on its own.
        super::clear_session_cookies(cookies);

        Ok(true)
    }

    async fn setup_two_factor(&self, ctx: &Context<'_>) -> Result<TwoFactorSetup> {
        // MCP-649 (2026-05-13): require_2fa for symmetry with
        // `disable_two_factor` (line 381) — every 2FA-management
        // endpoint should require an `is_2fa_verified=true` token.
        //
        // For a user WITHOUT 2FA enabled: their login token carries
        // `is_2fa_verified=true` (the OAuth-bypass fix: `is_2fa_verified
        // = !totp_enabled` initially), so enrolment self-service works.
        //
        // For a user WITH 2FA enabled: their login token carries
        // `is_2fa_verified=false` until `verify_two_factor` succeeds.
        // Without this gate, an attacker holding a stolen partial-2FA
        // token (post-password, pre-TOTP) could call setup_two_factor
        // to harvest a new secret. The atomic-overwrite refusal in
        // `TotpService::enable_2fa` already blocks the re-enrol path,
        // so this is defense-in-depth — but the asymmetry vs.
        // disable_two_factor is the kind of fragility that grows into
        // a real bypass when a future endpoint moves around.
        require_2fa(ctx)?;
        let totp_service = ctx.data::<Arc<talos_totp_2fa::TotpService>>()?;
        let auth_service = ctx.data::<Arc<talos_auth::AuthService>>()?;

        // Get authenticated user
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;

        let user = auth_service.get_user(*user_id).await.map_err(|e| {
            tracing::error!("Failed to get user: {}", e);
            async_graphql::Error::new("Failed to get user").extend_safe()
        })?;

        // Generate secret
        let secret = totp_service.generate_secret();

        // Generate QR code URL and PNG
        let qr_code_url = totp_service
            .generate_qr_code_url(&secret, &user.email)
            .map_err(|e| {
                tracing::error!("Failed to generate QR URL: {}", e);
                async_graphql::Error::new("Failed to generate QR URL").extend_safe()
            })?;

        let qr_code_png = totp_service
            .generate_qr_code_png(&secret, &user.email)
            .map_err(|e| {
                tracing::error!("Failed to generate QR code: {}", e);
                async_graphql::Error::new("Failed to generate QR code").extend_safe()
            })?;

        Ok(TwoFactorSetup {
            secret,
            qr_code_url,
            qr_code_png,
        })
    }

    async fn enable_two_factor(
        &self,
        ctx: &Context<'_>,
        input: Enable2FAInput,
    ) -> Result<TwoFactorEnrollment> {
        // MCP-649: matches setup_two_factor — require_2fa for
        // symmetry with disable_two_factor. See setup_two_factor for
        // the full rationale (defense-in-depth on top of the atomic
        // `WHERE totp_enabled IS NOT TRUE` overwrite-refusal in
        // TotpService::enable_2fa).
        require_2fa(ctx)?;
        let totp_service = ctx.data::<Arc<talos_totp_2fa::TotpService>>()?;
        let auth_service = ctx.data::<Arc<talos_auth::AuthService>>()?;

        // Get authenticated user
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;

        let user = auth_service.get_user(*user_id).await.map_err(|e| {
            tracing::error!("Failed to get user: {}", e);
            async_graphql::Error::new("Failed to get user").extend_safe()
        })?;

        // Enable 2FA (verifies code and generates backup codes)
        let backup_codes = totp_service
            .enable_2fa(*user_id, &input.secret, &input.code, &user.email)
            .await
            .map_err(|e| {
                tracing::error!("Failed to enable 2FA: {}", e);
                async_graphql::Error::new("Failed to enable 2FA").extend_safe()
            })?;

        let db_pool = ctx.data::<sqlx::PgPool>()?.clone();
        talos_actor_repository::spawn_log_admin_event(
            db_pool,
            *user_id,
            "2fa_enabled",
            "user",
            Some(*user_id),
            "Two-factor authentication enabled".to_string(),
            None,
        );

        Ok(TwoFactorEnrollment { backup_codes })
    }

    async fn disable_two_factor(&self, ctx: &Context<'_>) -> Result<bool> {
        require_2fa(ctx)?;
        let totp_service = ctx.data::<Arc<talos_totp_2fa::TotpService>>()?;

        // Get authenticated user
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;

        totp_service.disable_2fa(*user_id).await.map_err(|e| {
            tracing::error!("Failed to disable 2FA: {}", e);
            async_graphql::Error::new("Failed to disable 2FA").extend_safe()
        })?;

        let db_pool = ctx.data::<sqlx::PgPool>()?.clone();
        talos_actor_repository::spawn_log_admin_event(
            db_pool,
            *user_id,
            "2fa_disabled",
            "user",
            Some(*user_id),
            "Two-factor authentication disabled".to_string(),
            None,
        );

        Ok(true)
    }

    async fn verify_two_factor(
        &self,
        ctx: &Context<'_>,
        input: Verify2FAInput,
    ) -> Result<AuthPayload> {
        // IP-level rate limit (same pattern as login/signup).
        if let Ok(limiter) = ctx.data::<Arc<talos_rate_limit::DistributedRateLimiter>>() {
            let metadata = ctx.data_opt::<RequestMetadata>();
            let ip = metadata
                .and_then(|m| m.ip_address.as_deref())
                .unwrap_or("unknown");
            if !limiter.check(ip).await {
                // MCP-916 cont.: .extend_safe() — rate-limit message must
                // reach the client so the user knows to back off; scrubbed
                // to "Internal server error" was actively misleading.
                return Err(async_graphql::Error::new(
                    "Too many 2FA attempts. Please try again later.",
                )
                .extend_safe());
            }
        }

        let totp_service = ctx.data::<Arc<talos_totp_2fa::TotpService>>()?;
        let auth_service = ctx.data::<Arc<talos_auth::AuthService>>()?;

        // Get authenticated user (they've already passed password check)
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;

        let user = auth_service.get_user(*user_id).await.map_err(|e| {
            tracing::error!("Failed to get user: {}", e);
            async_graphql::Error::new("Failed to get user").extend_safe()
        })?;

        // Verify 2FA code
        let valid = totp_service
            .verify_2fa_login(*user_id, &input.code, &user.email)
            .await
            .map_err(|e| {
                tracing::error!("2FA verification failed: {}", e);
                async_graphql::Error::new("2FA verification failed").extend_safe()
            })?;

        if !valid {
            return Err(async_graphql::Error::new("Invalid 2FA code").extend_safe());
        }

        // Generate new tokens
        let access_token = auth_service
            .generate_access_token(&user, true)
            .map_err(|e| {
                tracing::error!("Failed to generate token: {}", e);
                async_graphql::Error::new("Failed to generate token").extend_safe()
            })?;

        let refresh_token = auth_service
            .generate_refresh_token(*user_id, true)
            .await
            .map_err(|e| {
                tracing::error!("Failed to generate refresh token: {}", e);
                async_graphql::Error::new("Failed to generate refresh token").extend_safe()
            })?;

        // Revoke all pre-2FA sessions — they were created with is_2fa_verified=false at
        // initial login and are now superseded by the fully-verified session we just created.
        // Non-fatal: if this fails the user is still logged in; stale sessions expire in 7 days.
        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;
        if let Err(e) =
            sqlx::query("DELETE FROM user_sessions WHERE user_id = $1 AND is_2fa_verified = false")
                .bind(*user_id)
                .execute(db_pool)
                .await
        {
            tracing::warn!(
                user_id = %user_id,
                "Failed to revoke pre-2FA sessions after 2FA completion (non-fatal): {}",
                e
            );
        }

        // Set httpOnly cookies if available
        if let Ok(cookies) = ctx.data::<Cookies>() {
            // MCP-1040: canonical session-cookie installer.
            super::set_session_cookies(cookies, &access_token, &refresh_token);
        }

        Ok(AuthPayload {
            user: UserInfo {
                id: user.id,
                email: user.email,
                name: user.name,
                created_at: user.created_at.to_rfc3339(),
                two_factor_enabled: true,
                is_two_factor_verified: true,
            },
        })
    }

    async fn unlink_oauth_account(&self, ctx: &Context<'_>, provider: String) -> Result<bool> {
        // Require 2FA — unlinking OAuth removes a recovery path, and we
        // don't want a partial-2FA session (post-password, pre-TOTP) to
        // be able to remove the user's Google/Okta login as part of an
        // account-takeover squat.
        require_2fa(ctx)?;
        let oauth_service = ctx.data::<Arc<talos_oauth::OAuthService>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;

        let provider_enum = talos_oauth::OAuthProvider::from_str(&provider).map_err(|e| {
            tracing::error!("Invalid provider: {}", e);
            async_graphql::Error::new("Invalid provider").extend_safe()
        })?;

        oauth_service
            .unlink_oauth_account(*user_id, provider_enum)
            .await
            .map_err(|e| {
                tracing::error!("Failed to unlink OAuth account: {}", e);
                async_graphql::Error::new("Failed to unlink OAuth account").extend_safe()
            })?;

        Ok(true)
    }
}
