//! Shared OAuth 2.0 authorization-code + PKCE flow scaffolding.
//!
//! Every OAuth integration (`talos-slack`, `talos-atlassian`, `talos-gmail`)
//! re-implemented the same two security-critical steps: build a PKCE + CSRF
//! authorize URL and persist a state token bound to the initiating user, then on
//! callback validate + single-use-consume that state token and recover the
//! bound `user_id`. Getting either wrong is a real vulnerability class:
//!
//! * **CSRF / account-linking** — if the callback trusted the session cookie
//!   instead of the state token, an attacker who completes consent on THEIR
//!   account could hand a victim a callback URL and attach the attacker's
//!   workspace/mailbox to the victim's Talos account. The `user_id` MUST come
//!   from the state token set at authorize time.
//! * **Replay** — the consume MUST be atomic single-use (`UPDATE … used=true …
//!   WHERE used=false … RETURNING`), or a captured `code`+`state` replays.
//!
//! Centralizing them here means a NEW integration gets the CSRF/PKCE/replay/
//! tenancy handling correct by construction — it supplies its provider config
//! and does its own token exchange + post-processing (which genuinely varies:
//! Slack's non-standard response, Atlassian's cloud-site discovery, Gmail's
//! userinfo lookup). The exchange is intentionally NOT centralized.

use anyhow::{anyhow, Context, Result};
use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl,
    Scope, TokenUrl,
};
use uuid::Uuid;

use crate::validate_oauth_state_token_format;

/// Provider inputs for [`begin_oauth_authorization`]. All borrowed — the caller
/// owns the config (typically from env vars validated at service construction).
pub struct AuthorizeRequest<'a> {
    /// Stable provider key stored in `oauth_state_tokens.provider` and matched on
    /// consume (e.g. `"slack"`, `"atlassian"`, `"gmail"`). MUST match the value
    /// passed to [`consume_oauth_state`] on the callback.
    pub provider: &'a str,
    pub auth_url: &'a str,
    pub token_url: &'a str,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scopes: &'a [&'a str],
    /// Provider-specific extra query params on the authorize URL — e.g.
    /// Google's `access_type=offline` / `prompt=consent`, Atlassian's
    /// `audience`, Slack's `user_scope`.
    pub extra_params: &'a [(&'a str, &'a str)],
}

/// Build the PKCE + CSRF authorize URL and persist a single-use state token
/// bound to `user_id`. Returns `(auth_url, state)`.
///
/// The `state` binding to `user_id` is the tenancy anchor — [`consume_oauth_state`]
/// recovers `user_id` from it on the callback, never from a session cookie.
pub async fn begin_oauth_authorization(
    pool: &sqlx::PgPool,
    req: &AuthorizeRequest<'_>,
    user_id: Uuid,
) -> Result<(String, String)> {
    let client = BasicClient::new(
        ClientId::new(req.client_id.clone()),
        Some(ClientSecret::new(req.client_secret.clone())),
        AuthUrl::new(req.auth_url.to_string()).context("invalid OAuth auth_url")?,
        Some(TokenUrl::new(req.token_url.to_string()).context("invalid OAuth token_url")?),
    )
    .set_redirect_uri(
        RedirectUrl::new(req.redirect_uri.clone()).context("invalid OAuth redirect_uri")?,
    );

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let mut auth = client.authorize_url(CsrfToken::new_random);
    for scope in req.scopes {
        auth = auth.add_scope(Scope::new((*scope).to_string()));
    }
    for (k, v) in req.extra_params {
        auth = auth.add_extra_param(*k, *v);
    }
    let (auth_url, csrf_token) = auth.set_pkce_challenge(pkce_challenge).url();

    let state_secret = csrf_token.secret().to_string();

    sqlx::query(
        "INSERT INTO oauth_state_tokens (state_token, provider, pkce_verifier, user_id) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(&state_secret)
    .bind(req.provider)
    .bind(pkce_verifier.secret())
    .bind(user_id)
    .execute(pool)
    .await
    .with_context(|| format!("Failed to store {} OAuth state token", req.provider))?;

    Ok((auth_url.to_string(), state_secret))
}

/// The state recovered from a validated, single-use-consumed callback.
pub struct ConsumedOAuthState {
    /// The user who INITIATED the flow (bound at authorize time). Tenancy anchor
    /// — the integration + credentials MUST be stored against this user, not the
    /// callback request's session identity.
    pub user_id: Uuid,
    /// PKCE `code_verifier` to include in the provider's token exchange, if PKCE
    /// was used (it always is for flows started via [`begin_oauth_authorization`]).
    pub pkce_verifier: Option<String>,
}

/// Peek the `provider` bound to a live (unused, unexpired) state token WITHOUT
/// consuming it.
///
/// Purpose: a provider family that shares ONE registered redirect URI across
/// multiple consent tiers (e.g. `google_cloud` read-only vs `google_cloud_write`
/// provisioning) needs to know which service should handle the callback before
/// calling [`consume_oauth_state`]. This is routing metadata only — every
/// security property (CSRF single-use consume, provider match, expiry, PKCE)
/// is still enforced by the subsequent consume; a peek→consume race is
/// harmless because the consume is atomic. Returns `Ok(None)` for an unknown /
/// used / expired state so the caller falls through to its default provider
/// and lets `consume_oauth_state` produce the canonical CSRF-safe error.
pub async fn peek_state_provider(pool: &sqlx::PgPool, state: &str) -> Result<Option<String>> {
    // Same format-gate as consume (MCP-1171): don't let a multi-KB state
    // reach the DB.
    if validate_oauth_state_token_format(state).is_err() {
        return Ok(None);
    }

    let row: Option<(String,)> = sqlx::query_as(
        "SELECT provider FROM oauth_state_tokens \
         WHERE state_token = $1 AND used = false AND expires_at > NOW()",
    )
    .bind(state)
    .fetch_optional(pool)
    .await
    .context("Failed to peek OAuth state token provider")?;

    Ok(row.map(|(provider,)| provider))
}

/// Validate + atomically single-use-consume the callback `state` for `provider`,
/// returning the bound `user_id` + PKCE verifier.
///
/// Fails closed with a generic CSRF-safe error on an invalid, expired, replayed,
/// or wrong-provider state — a new integration MUST call this rather than
/// re-implement the consume, so the CSRF/replay/tenancy guarantees can't drift.
pub async fn consume_oauth_state(
    pool: &sqlx::PgPool,
    provider: &str,
    state: &str,
) -> Result<ConsumedOAuthState> {
    // Format-gate before the DB touch (MCP-1171): `$1` binding already isolates
    // injection, but this closes the store/validate asymmetry + a multi-KB-state
    // DoS-amplification on consume.
    validate_oauth_state_token_format(state)?;

    // Atomic single-use consume: only an unused, unexpired token for THIS
    // provider flips to `used` and returns its bound pkce_verifier + user_id. A
    // replayed or foreign state matches zero rows.
    let row = sqlx::query_as::<_, (Uuid, Option<String>, Option<Uuid>)>(
        "UPDATE oauth_state_tokens SET used = true \
         WHERE state_token = $1 AND provider = $2 AND used = false AND expires_at > NOW() \
         RETURNING id, pkce_verifier, user_id",
    )
    .bind(state)
    .bind(provider)
    .fetch_optional(pool)
    .await
    .with_context(|| format!("Failed to validate {provider} OAuth state token"))?;

    let (state_id, pkce_verifier, user_id_opt) = row.ok_or_else(|| {
        anyhow!("Invalid or expired OAuth state token. This may indicate a CSRF attack.")
    })?;

    // Best-effort PKCE scrub post-consume (MCP-1096): the verifier is already in
    // memory for the exchange; if this fails the 10-min TTL sweep gets it. Guards
    // a read-only DB compromise during the in-flight + post-consume window.
    if let Err(e) = sqlx::query("UPDATE oauth_state_tokens SET pkce_verifier = NULL WHERE id = $1")
        .bind(state_id)
        .execute(pool)
        .await
    {
        tracing::warn!(
            state_id = %state_id,
            provider,
            "Failed to scrub pkce_verifier after OAuth consume: {}",
            e
        );
    }

    let user_id = user_id_opt.ok_or_else(|| {
        anyhow!("State token missing user_id — cannot identify the initiating user")
    })?;

    Ok(ConsumedOAuthState {
        user_id,
        pkce_verifier,
    })
}
