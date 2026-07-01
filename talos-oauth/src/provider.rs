//! The uniform contract an OAuth integration implements so the shared drivers
//! run authorize + callback with the CSRF / PKCE / single-use / tenancy handling
//! **guaranteed** — a provider supplies its config and its provider-specific
//! exchange+store, and literally cannot skip the security-critical state consume.
//!
//! ```ignore
//! #[async_trait]
//! impl OAuthIntegration for MyIntegrationService {
//!     type Connected = MyIntegration;
//!     fn provider(&self) -> &'static str { "myprovider" }
//!     fn authorize_request(&self) -> Result<AuthorizeRequest<'static>> { /* config from env */ }
//!     async fn complete_callback(&self, pool, code, consumed) -> Result<MyIntegration> {
//!         // consumed.user_id + consumed.pkce_verifier are already validated.
//!         // Exchange `code`, derive the provider key, store the row +
//!         // credentials against consumed.user_id, return the record.
//!     }
//! }
//! // public API delegates to the drivers:
//! pub async fn get_authorization_url(&self, uid: Uuid) -> Result<(String, String)> {
//!     talos_oauth::authorization_url(&self.db_pool, self, uid).await
//! }
//! pub async fn handle_callback(&self, code: String, state: String) -> Result<MyIntegration> {
//!     talos_oauth::handle_oauth_callback(&self.db_pool, self, &code, &state).await
//! }
//! ```

use anyhow::Result;
use async_trait::async_trait;
use uuid::Uuid;

use crate::flow::{
    begin_oauth_authorization, consume_oauth_state, AuthorizeRequest, ConsumedOAuthState,
};

/// The contract for an OAuth 2.0 authorization-code + PKCE integration.
///
/// Implement the three provider-specific pieces; drive the flow with
/// [`authorization_url`] + [`handle_oauth_callback`]. Everything security-
/// critical and uniform (CSRF single-use consume, PKCE, format gate,
/// state-bound `user_id`) lives in the drivers, not the impl.
#[async_trait]
pub trait OAuthIntegration: Sync {
    /// The record produced on a successful connection (e.g. `SlackIntegration`).
    type Connected: Send;

    /// Stable provider key (`"slack"`, `"gmail"`, …) — stored in
    /// `oauth_state_tokens.provider` and matched on consume. MUST equal the
    /// `provider` field of [`authorize_request`](Self::authorize_request).
    fn provider(&self) -> &'static str;

    /// Build the authorize config: auth/token URLs, client creds (typically from
    /// env, validated here), scopes, and any provider-specific extra params.
    /// Return an error if the integration isn't configured.
    fn authorize_request(&self) -> Result<AuthorizeRequest<'static>>;

    /// Provider-specific token exchange + post-processing. `consumed` carries the
    /// ALREADY-VALIDATED, state-bound `user_id` and the PKCE verifier — exchange
    /// `code`, derive the provider key, and persist the integration row +
    /// credentials **against `consumed.user_id`** (never a session identity).
    /// This is where Slack's team lookup / Atlassian's cloud-site discovery /
    /// Gmail's userinfo lookup live.
    async fn complete_callback(
        &self,
        pool: &sqlx::PgPool,
        code: &str,
        consumed: ConsumedOAuthState,
    ) -> Result<Self::Connected>;
}

/// Drive the authorize step: build the PKCE + CSRF authorize URL and persist the
/// state token bound to `user_id`. Returns `(auth_url, state)`.
pub async fn authorization_url<P: OAuthIntegration + ?Sized>(
    pool: &sqlx::PgPool,
    provider: &P,
    user_id: Uuid,
) -> Result<(String, String)> {
    begin_oauth_authorization(pool, &provider.authorize_request()?, user_id).await
}

/// Drive the callback: **consume + validate** the state token (CSRF / single-use
/// / format / tenancy — via [`consume_oauth_state`], unskippable) and only then
/// hand the validated `ConsumedOAuthState` to the provider's exchange. This
/// ordering is the whole point of the trait: a new integration cannot exchange a
/// `code` without first passing the security-critical consume.
pub async fn handle_oauth_callback<P: OAuthIntegration + ?Sized>(
    pool: &sqlx::PgPool,
    provider: &P,
    code: &str,
    state: &str,
) -> Result<P::Connected> {
    let consumed = consume_oauth_state(pool, provider.provider(), state).await?;
    provider.complete_callback(pool, code, consumed).await
}
