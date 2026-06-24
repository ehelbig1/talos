pub mod credentials;
pub mod refresh_task;
pub mod resolver;
pub use credentials::OAuthCredentialService;
pub use resolver::ControllerSecretsResolver;

/// Compute an OAuth token's `expires_at` from a provider-supplied
/// `expires_in` (seconds, optional). Safe under three failure modes
/// that the canonical `Utc::now() + Duration::seconds(expires_in as i64)`
/// idiom hit silently:
///
/// 1. **Negative cast wrap.** `Option<u64>::unwrap_or(3600) as i64`
///    wraps for `expires_in > i64::MAX` (~9.2e18 sec). Result: a
///    negative duration → `expires_at` in the past → token treated as
///    immediately-expired on every read → refresh-loop hammers the
///    provider.
///
/// 2. **`chrono::Duration::seconds` panic.** Chrono represents
///    durations internally as i64 milliseconds. For
///    `seconds > i64::MAX / 1_000` (~9.2e15), the constructor
///    overflows and **panics**, killing the refresh task entirely
///    with no graceful fallback.
///
/// 3. **None / zero / negative `expires_in`.** Providers occasionally
///    return `expires_in: 0` (or omit the field); the canonical
///    idiom defaulted to 3600s.
///
/// Defense matches MCP-997 (caller-supplied destructive interval
/// clamp at function entry) and the MCP-960..962 integer-cast sweep.
/// Clamps to 24h max (an OAuth refresh-token TTL longer than a day
/// is unusual; capping defends against a misbehaving provider).
/// Minimum 60s so a `expires_in: 1` doesn't immediately invalidate.
pub fn oauth_expires_at(expires_in_seconds: Option<u64>) -> chrono::DateTime<chrono::Utc> {
    /// Provider-suggested default when `expires_in` is missing. Matches
    /// the canonical OAuth2 RFC 6749 §4.2.2 default and what every
    /// pre-fix call site used.
    const DEFAULT_EXPIRES_IN_SECS: u64 = 3600;
    /// Minimum acceptable token TTL. A provider returning 1s would
    /// otherwise cause immediate refresh-storm; floor to 60s.
    const MIN_EXPIRES_IN_SECS: u64 = 60;
    /// Maximum acceptable TTL — 90 days. Cap defends against a
    /// buggy/hostile provider returning u64::MAX while accommodating
    /// long-lived legitimate tokens: Google service-account JWTs
    /// (≤1h typical, but signed JWTs can carry a longer `exp` claim),
    /// Microsoft Graph service-principal tokens (24h–60d), and any
    /// future provider whose access token TTL exceeds the prior 24h
    /// ceiling. The proactive-refresh task fires
    /// `REFRESH_THRESHOLD_MINUTES` (10 min) ahead of expiry regardless
    /// of TTL, so a long-lived legitimate token is still refreshed on
    /// the correct cadence. 90 days × 86_400 = 7_776_000 sec, well
    /// under `i64::MAX / 1000` so chrono::Duration::seconds is safe.
    /// 2026-05-28 audit Perf#8: raised from 24h after the audit
    /// flagged the prior cap as a footgun for future integrations
    /// that ship long-lived tokens.
    const MAX_EXPIRES_IN_SECS: u64 = 90 * 24 * 60 * 60;

    let raw = expires_in_seconds.unwrap_or(DEFAULT_EXPIRES_IN_SECS);
    let clamped = raw.clamp(MIN_EXPIRES_IN_SECS, MAX_EXPIRES_IN_SECS);
    // u64 → i64 safe: clamped <= 7_776_000 << i64::MAX.
    // `try_seconds` for fail-closed safety; the clamp guarantees Some,
    // but defending against future mis-use is cheap.
    let dur = chrono::Duration::try_seconds(clamped as i64)
        .unwrap_or_else(|| chrono::Duration::seconds(DEFAULT_EXPIRES_IN_SECS as i64));
    chrono::Utc::now() + dur
}

/// How far ahead of token expiry we start refreshing (minutes).
///
/// INVARIANT: the proactive refresh task's SQL query window (`refresh_task.rs`)
/// must use this exact value. A mismatch creates a dead zone where the task
/// finds a token expiring within its window but the inner `refresh_if_needed`
/// check refuses to refresh it. See the 2026-04-11 gmail/follow-up-detector
/// incident for the real-world consequence.
pub const REFRESH_THRESHOLD_MINUTES: i64 = 10;

use anyhow::{anyhow, Context, Result};

/// Build a reqwest HTTP client with conservative timeouts for OAuth provider calls.
/// Using a bare `Client::default()` has no timeout, risking indefinite hangs
/// if the OAuth provider is slow or unresponsive (thread pool exhaustion under attack).
///
/// MCP-459: pre-fix the build-failure fallback was
/// `unwrap_or_else(|_| oauth_http_client())` — a recursive call to
/// THIS function. If `Client::builder().build()` ever failed (rare:
/// TLS init failure on a system without crypto support), the
/// "recovery" path infinite-recursed until stack overflow. The
/// underlying failure path also affects `Client::new()`, so replace
/// with `expect()` — a clear panic message beats a cryptic stack
/// overflow under TLS init failure.
///
/// MCP-571 (2026-05-12): disable redirect following. This client
/// carries credential-bearing requests on every call:
///   * `revoke_at_provider` — token in POST form body (Google) or
///     `Bearer` header (Slack).
///   * `OAuthService::exchange_code_*` — client_secret +
///     authorization_code in form body.
///   * `OAuthService::fetch_*_user_info` — `Bearer` access_token.
///
/// Same Mode-B credential-leak surface that MCP-533 closed for
/// talos-atlassian and talos-oauth/credentials.rs. A compromised
/// provider endpoint returning a 302 to attacker.com would
/// re-POST credentials (Google form revoke) or surface the bearer
/// (Slack revoke / user-info) — reqwest strips
/// Authorization/Cookie/Proxy-Authorization on CROSS-origin
/// redirects by default, but body content is preserved and
/// same-origin redirects still carry the bearer. Fail-closed at
/// the policy layer rather than rely on reqwest's strip heuristics.
fn oauth_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .connect_timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("oauth_http_client: reqwest builder failed (TLS init?)")
}
/// Revoke an OAuth token at the provider (best-effort).
///
/// Returns `Ok(true)` when the provider acknowledges revocation,
/// `Ok(false)` when the provider has no public revoke endpoint (Atlassian),
/// `Err` on network/HTTP failure. Caller decides whether to log+continue.
///
/// SECURITY: response bodies may echo client-side context but should NOT be
/// logged at INFO+ level — they may contain the original token or related
/// material. Caller logs body LENGTH only.
///
/// Token is sent via the standardised RFC 7009 form-encoded `token` parameter
/// for Google; via bearer auth for Slack's `auth.revoke`. We deliberately
/// avoid SDK abstractions here — every revoke endpoint has its own quirks
/// and we want the wire shape to be reviewable.
pub(crate) async fn revoke_at_provider(provider: &str, token: &str) -> Result<bool> {
    let client = oauth_http_client();

    match provider {
        // Google: RFC 7009-style endpoint accepting form-encoded token.
        // Revoking a refresh_token also revokes every access_token issued
        // under that grant. 200 OK = revoked. 400 = token already invalid
        // (treat as success — the user-facing intent is "make it dead").
        "gmail" | "google_calendar" => {
            let resp = client
                .post("https://oauth2.googleapis.com/revoke")
                .form(&[("token", token)])
                .send()
                .await
                .context("Google revoke request failed")?;
            let status = resp.status();
            if status.is_success() || status == reqwest::StatusCode::BAD_REQUEST {
                Ok(true)
            } else {
                let body_len = talos_http_body::read_error_text_capped(resp).await.len();
                anyhow::bail!(
                    "Google revoke returned HTTP {} (body_len={})",
                    status,
                    body_len
                );
            }
        }
        // Slack: auth.revoke is a Web API method using bearer auth. It returns
        // {ok:true,revoked:true} on success. Empty/expired tokens return
        // {ok:false,error:"invalid_auth"} with HTTP 200 — we count those as
        // already-revoked rather than failing the disconnect.
        "slack" => {
            let resp = client
                .post("https://slack.com/api/auth.revoke")
                .bearer_auth(token)
                .send()
                .await
                .context("Slack revoke request failed")?;
            let status = resp.status();
            if !status.is_success() {
                let body_len = talos_http_body::read_error_text_capped(resp).await.len();
                anyhow::bail!(
                    "Slack revoke returned HTTP {} (body_len={})",
                    status,
                    body_len
                );
            }
            // Best-effort parse: tolerate non-JSON bodies (network proxy injecting HTML, etc).
            let body: serde_json::Value =
                talos_http_body::read_json_capped::<serde_json::Value>(resp)
                    .await
                    .unwrap_or_default();
            let ok = body.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
            // Slack returns {ok:false,error:"invalid_auth"} when token is already dead — accept that.
            let already_dead = !ok
                && body
                    .get("error")
                    .and_then(|v| v.as_str())
                    .map(|s| s == "invalid_auth" || s == "token_revoked" || s == "not_authed")
                    .unwrap_or(false);
            Ok(ok || already_dead)
        }
        // Atlassian does not expose a public token-revoke endpoint
        // (https://developer.atlassian.com/cloud/jira/platform/oauth-2-3lo-apps/).
        // The customer-facing revocation path is the user's account
        // settings page or Atlassian admin console. Local cleanup
        // (vault delete + soft-delete) still proceeds.
        "atlassian" => Ok(false),
        // Unknown provider — caller should not have called us, but treat as no-op.
        _ => Ok(false),
    }
}

// NOTE: We deliberately avoid the `openidconnect` crate to prevent pulling the
// vulnerable `rsa` dependency (RUSTSEC‑2023‑0071). All token verification is
// performed with constant‑time primitives from the `ring` crate via the custom
// `OAuthService` implementation.
use chrono::{DateTime, Utc};
use oauth2::reqwest::async_http_client;
use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};
use uuid::Uuid;

/// OAuth provider enum
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OAuthProvider {
    Google,
    Okta,
    Snyk,
}

impl OAuthProvider {
    pub fn as_str(&self) -> &str {
        match self {
            OAuthProvider::Google => "google",
            OAuthProvider::Okta => "okta",
            OAuthProvider::Snyk => "snyk",
        }
    }

    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "google" => Ok(OAuthProvider::Google),
            "okta" => Ok(OAuthProvider::Okta),
            "snyk" => Ok(OAuthProvider::Snyk),
            _ => Err(anyhow!("Unsupported OAuth provider: {}", s)),
        }
    }
}

/// OAuth account record
#[derive(Debug, Clone)]
pub struct OAuthAccount {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider: String,
    pub provider_user_id: String,
    pub email: String,
    pub name: Option<String>,
    pub picture_url: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub last_login_at: Option<DateTime<Utc>>,
}

/// User info from OAuth provider
#[derive(Clone, Serialize, Deserialize)]
pub struct OAuthUserInfo {
    pub provider_user_id: String,
    pub email: String,
    pub email_verified: bool,
    pub name: Option<String>,
    pub picture: Option<String>,
    // Optional tokens for service integrations (e.g., Google Calendar, Gmail)
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_in: Option<i64>,
    pub scope: Option<String>,
}

/// Custom `Debug` redacts `access_token` / `refresh_token` so an
/// accidental `tracing::debug!("{:?}", user_info)` in any caller
/// can't dump live OAuth credentials into logs. Mirrors the
/// `User` struct's Debug pattern in `talos_auth`. Both auto-derive
/// would have been a footgun.
impl std::fmt::Debug for OAuthUserInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthUserInfo")
            .field("provider_user_id", &self.provider_user_id)
            .field("email", &self.email)
            .field("email_verified", &self.email_verified)
            .field("name", &self.name)
            .field("picture", &self.picture)
            .field(
                "access_token",
                &self.access_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .finish()
    }
}

/// MCP-1157 (2026-05-16): validate `OKTA_DOMAIN` at read time.
///
/// The env value is interpolated into FIVE outbound OAuth URLs via
/// `format!("https://{domain}/oauth2/v1/{authorize|token|userinfo}")`
/// (see `get_okta_auth_url` and `handle_okta_callback` below). With no
/// validation, an operator misconfig like `OKTA_DOMAIN=attacker.com/x`
/// produces `https://attacker.com/x/oauth2/v1/authorize` — a fully
/// resolvable attacker URL that Okta-trusting users redirect to and
/// enter credentials into. Same env-var-misconfig-as-silent-bypass
/// class as MCP-1000 (`FRONTEND_URL`) and MCP-1155 (`BASE_URL`):
/// validate at the env-var read site, not at every interpolation.
///
/// Valid Okta domain: an RFC 1123 hostname — labels of
/// `[a-zA-Z0-9-]` separated by `.`, 1-63 chars per label, no
/// leading/trailing hyphen, total ≤ 253 chars. No scheme, no path,
/// no port, no userinfo. Custom Okta domains (`auth.acme.com`) and
/// standard ones (`acme.okta.com`, `acme.oktapreview.com`) both pass.
fn is_valid_okta_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

/// OAuth service for handling Google, Okta, and Snyk authentication
pub struct OAuthService {
    db_pool: Pool<Postgres>,
    google_client_id: Option<String>,
    google_client_secret: Option<String>,
    google_redirect_uri: Option<String>,
    okta_domain: Option<String>,
    okta_client_id: Option<String>,
    okta_client_secret: Option<String>,
    okta_redirect_uri: Option<String>,
    snyk_client_id: Option<String>,
    snyk_client_secret: Option<String>,
    snyk_redirect_uri: Option<String>,
    redis_client: Option<std::sync::Arc<redis::Client>>,
}

/// MCP-1171 (2026-05-17): canonical state-token format validator.
///
/// Shared between `store_state_token` (write path) and
/// `validate_state_token` (callback verification path). Pre-fix only
/// the write path enforced 1-255 chars + ASCII alphanumeric/-_.
/// charset; the callback validator took the raw query-param value and
/// fed it straight into the Redis Lua-script key
/// (`format!("oauth_nonce:{}", state_token)`) AND the DB `WHERE
/// state_token = $1` predicate. Postgres `$1` binding + Redis-EVAL
/// argv-binding both isolate against injection — but an attacker
/// spamming the callback with multi-KB state values amplified Redis
/// key allocation + DB string-comparison work per request, AND the
/// asymmetry meant the validator accepted shapes the writer would
/// have rejected (defense-rule inconsistency). Single source of truth
/// closes both gaps.
///
/// `pub` so the per-provider integration callbacks
/// (`talos-gmail`/`talos-slack`/`talos-atlassian` `handle_callback`) apply the
/// same pre-DB format gate as the login flow — extending the MCP-1171
/// symmetry to every `oauth_state_tokens` consume path.
pub fn validate_oauth_state_token_format(state_token: &str) -> Result<()> {
    if state_token.is_empty() || state_token.len() > 255 {
        anyhow::bail!("OAuth state token must be 1-255 characters");
    }
    if !state_token
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        anyhow::bail!("OAuth state token contains invalid characters");
    }
    Ok(())
}

/// S1 (login-CSRF / session-fixation): browser-session binding for the
/// **pre-auth SSO LOGIN** flow.
///
/// The `state` nonce alone proves only "Talos issued this authorize
/// URL", NOT "issued to THIS browser". Without a per-browser binding an
/// attacker can run the consent flow against their *own* provider
/// account, capture the resulting `code` + `state`, and feed the victim
/// the callback URL — logging the victim's browser in as the attacker
/// (classic login-CSRF / session fixation). The account-LINK flows
/// (`talos-slack`/`talos-gmail`/`talos-atlassian`) bind the *already
/// authenticated* `user_id`; the login flow has no user yet, so it
/// binds an opaque browser-session nonce instead.
///
/// We generate a high-entropy nonce, hand the **plaintext** to the
/// caller to set as an HttpOnly+Secure+SameSite=Lax cookie, and persist
/// only its **SHA-256 hash** in the state row. Storing the hash (not the
/// raw value) means a read-only DB compromise during the ≤10-min row
/// lifetime never yields a usable cookie value — same `token_hash`
/// discipline the approval-gate handler uses (lint check 41). On
/// callback we recompute the hash from the cookie and constant-time
/// compare it against the stored hash.
///
/// `Lax` (not `Strict`) is required: the callback arrives via a
/// top-level cross-site redirect from the provider, and `Strict` would
/// withhold the cookie on that navigation, breaking every login.
/// Returns `(plaintext_nonce, sha256_hex_hash)`.
pub fn generate_oauth_session_binding() -> (String, String) {
    // ~244 bits of entropy from two v4 UUIDs (122 bits each), hex-
    // encoded so the value passes `validate_oauth_state_token_format`'s
    // charset rules and is a safe cookie value. No new RNG dependency:
    // `uuid` is already a direct dep and v4 draws from the OS CSPRNG.
    let nonce = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let hash = hash_oauth_session_binding(&nonce);
    (nonce, hash)
}

/// SHA-256 (hex) of a session-binding nonce. The hex digest is what's
/// persisted in `oauth_state_tokens.session_binding_hash` and what's
/// recomputed-and-compared on callback.
pub fn hash_oauth_session_binding(nonce: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(nonce.as_bytes());
    hex::encode(hasher.finalize())
}

/// Constant-time equality over two hex-encoded SHA-256 digests.
///
/// The compared values are hashes (not raw secrets), but the comparison
/// still gates an auth decision, so we avoid the early-return timing
/// oracle of `==`/`str::eq` per the CLAUDE.md "constant-time compare for
/// security-sensitive values" rule. `subtle` is not a workspace dep, so
/// this is the canonical no-dep XOR-accumulate form. A length mismatch
/// is folded into the accumulator (rather than short-circuited) so the
/// caller can't distinguish "wrong length" from "wrong value" by timing.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff: u8 = (a.len() ^ b.len()) as u8;
    // Walk the longer of the two so the loop count depends only on the
    // (public) digest length, never on where the first mismatch is.
    let len = a.len().max(b.len());
    for i in 0..len {
        let ab = a.get(i).copied().unwrap_or(0);
        let bb = b.get(i).copied().unwrap_or(0);
        diff |= ab ^ bb;
    }
    diff == 0
}

impl OAuthService {
    pub fn new(
        db_pool: Pool<Postgres>,
        redis_client: Option<std::sync::Arc<redis::Client>>,
    ) -> Result<Self> {
        Ok(Self {
            db_pool,
            // MCP-710 (2026-05-13): treat empty env as unset across
            // all three OAuth providers. Pre-fix the helm placeholder
            // `googleClientId: ""` (and equivalents for Okta, Snyk)
            // would yield `Some("")`, making `is_provider_enabled()`
            // return true (line ~280) — but every authorize URL the
            // service generates carries empty client_id/domain.
            // Providers return cryptic "Missing parameter" errors that
            // misdirect operator debugging. Same empty-env class as
            // MCP-590/591/592/653/etc. — sibling to the GmailIntegration
            // / SlackIntegration / AtlassianIntegration trio fixed in
            // the same commit.
            google_client_id: std::env::var("GOOGLE_CLIENT_ID").ok().filter(|v| !v.is_empty()),
            google_client_secret: std::env::var("GOOGLE_CLIENT_SECRET").ok().filter(|v| !v.is_empty()),
            google_redirect_uri: std::env::var("GOOGLE_REDIRECT_URI").ok().filter(|v| !v.is_empty()),
            // MCP-1157 (2026-05-16): also drop OKTA_DOMAIN values that
            // don't pass `is_valid_okta_domain` — see the predicate
            // comment for why a path/scheme-laden misconfig is a
            // phishing vector. Log at WARN so the operator notices the
            // provider is disabled (`is_provider_enabled` falls to
            // false when okta_domain is None).
            okta_domain: std::env::var("OKTA_DOMAIN")
                .ok()
                .filter(|v| !v.is_empty())
                .and_then(|v| {
                    if is_valid_okta_domain(&v) {
                        Some(v)
                    } else {
                        tracing::warn!(
                            target: "talos_audit",
                            event_kind = "okta_domain_invalid_format",
                            "OKTA_DOMAIN env value rejected — not an RFC 1123 hostname; provider disabled"
                        );
                        None
                    }
                }),
            okta_client_id: std::env::var("OKTA_CLIENT_ID").ok().filter(|v| !v.is_empty()),
            okta_client_secret: std::env::var("OKTA_CLIENT_SECRET").ok().filter(|v| !v.is_empty()),
            okta_redirect_uri: std::env::var("OKTA_REDIRECT_URI").ok().filter(|v| !v.is_empty()),
            snyk_client_id: std::env::var("SNYK_CLIENT_ID").ok().filter(|v| !v.is_empty()),
            snyk_client_secret: std::env::var("SNYK_CLIENT_SECRET").ok().filter(|v| !v.is_empty()),
            snyk_redirect_uri: std::env::var("SNYK_REDIRECT_URI").ok().filter(|v| !v.is_empty()),
            redis_client,
        })
    }

    /// Check if a provider is configured
    pub fn is_provider_enabled(&self, provider: &OAuthProvider) -> bool {
        match provider {
            OAuthProvider::Google => {
                self.google_client_id.is_some()
                    && self.google_client_secret.is_some()
                    && self.google_redirect_uri.is_some()
            }
            OAuthProvider::Okta => {
                self.okta_domain.is_some()
                    && self.okta_client_id.is_some()
                    && self.okta_client_secret.is_some()
                    && self.okta_redirect_uri.is_some()
            }
            OAuthProvider::Snyk => {
                self.snyk_client_id.is_some()
                    && self.snyk_client_secret.is_some()
                    && self.snyk_redirect_uri.is_some()
            }
        }
    }

    /// Store a CSRF state token in the database.
    ///
    /// `provider` is a free-form string (e.g. "google", "gmail", "slack") stored in the
    /// `oauth_state_tokens.provider` column.  Using `&str` instead of `&OAuthProvider`
    /// allows integration-specific providers ("gmail") that are separate from the main
    /// authentication provider enum.
    /// `session_binding_hash` is the SHA-256 hex of the per-browser
    /// session nonce (see `generate_oauth_session_binding`). `None` is
    /// accepted only for legacy / non-login callers; the login flow
    /// (`get_authorization_url`) always supplies it so `validate_state_token`
    /// can require a matching cookie on callback (S1 login-CSRF fix).
    pub async fn store_state_token(
        &self,
        state_token: &str,
        provider: &str,
        pkce_verifier: Option<&str>,
        session_binding_hash: Option<&str>,
    ) -> Result<()> {
        // Validate state token format to prevent storage of malformed values.
        // State tokens must be non-empty, within a reasonable length, and
        // contain only URL-safe characters (hex, base64url, or UUID format).
        validate_oauth_state_token_format(state_token)?;

        sqlx::query(
            "INSERT INTO oauth_state_tokens (state_token, provider, pkce_verifier, session_binding_hash) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(state_token)
        .bind(provider)
        .bind(pkce_verifier)
        .bind(session_binding_hash)
        .execute(&self.db_pool)
        .await
        .context("Failed to store OAuth state token")?;

        Ok(())
    }

    /// Retrieve the PKCE code_verifier stored with a state token.
    /// Called during callback before validate_state_token consumes the token.
    async fn get_pkce_verifier(&self, state_token: &str) -> Result<Option<String>> {
        let verifier = sqlx::query_scalar::<_, Option<String>>(
            "SELECT pkce_verifier FROM oauth_state_tokens WHERE state_token = $1",
        )
        .bind(state_token)
        .fetch_optional(&self.db_pool)
        .await
        .context("Failed to retrieve PKCE verifier")?;
        Ok(verifier.flatten())
    }

    /// Validate and consume a CSRF state token (atomic — sets `used = true`).
    ///
    /// `provider` must match the value used in `store_state_token`.  Returns an error
    /// if the token is unknown, already used, or expired (10-minute TTL).
    ///
    /// Defence-in-depth: Uses atomic Redis Lua script for replay prevention when
    /// Redis is available, preventing race conditions in multi-instance deployments.
    /// Falls back to DB-only validation if Redis is unavailable.
    ///
    /// All OAuth flows must have a valid, unexpired, unconsumed state token in the
    /// database. Previous code skipped validation for JSON-shaped state values
    /// (e.g. `{"source":"google-calendar"}`); that bypass has been removed because
    /// any caller could craft a `{…}` string to circumvent CSRF protection.
    ///
    /// `session_binding` is the plaintext browser-session nonce read from
    /// the callback request's `talos_oauth_session` cookie (S1 login-CSRF
    /// fix). When the consumed state row carries a `session_binding_hash`
    /// (every row written by the login flow does), the cookie is REQUIRED
    /// and its SHA-256 must match the stored hash — a missing or
    /// mismatched cookie is rejected with the generic CSRF error. Rows
    /// with a NULL hash (legacy / non-login callers) skip the check, so
    /// this is backward compatible.
    pub async fn validate_state_token(
        &self,
        state_token: &str,
        provider: &str,
        session_binding: Option<&str>,
    ) -> Result<()> {
        // MCP-1171 (2026-05-17): format-validate at the START of the
        // callback path, before the expensive Redis EVAL + DB UPDATE
        // ops. Pre-fix this validator accepted any caller-supplied
        // state value — see `validate_oauth_state_token_format` doc
        // for why that's the defense-asymmetry concern. The error
        // surface uses the same generic "Invalid or expired OAuth
        // state token. This may indicate a CSRF attack." message
        // the DB-miss path returns at line ~520, so the validator
        // doesn't reveal format requirements to attackers probing
        // the callback (the legitimate caller flow always produces a
        // canonical token via `store_state_token` → it never hits
        // the rejection path).
        if validate_oauth_state_token_format(state_token).is_err() {
            return Err(anyhow!(
                "Invalid or expired OAuth state token. This may indicate a CSRF attack."
            ));
        }
        let redis_nonce_key = format!("oauth_nonce:{}", state_token);

        // Step 1: Atomic Redis check-and-set using Lua script
        // This prevents race conditions where two requests check Redis simultaneously
        // before either updates it.
        if let Some(redis) = &self.redis_client {
            match redis.get_multiplexed_tokio_connection().await {
                Ok(mut con) => {
                    // Lua script: Check if key exists, if not set it with TTL and return 1
                    // If key exists, return 0 (replay detected)
                    let lua_script = r#"
                        if redis.call("exists", KEYS[1]) == 1 then
                            return 0
                        else
                            redis.call("setex", KEYS[1], ARGV[1], "consumed")
                            return 1
                        end
                    "#;

                    let result: Result<i32, _> = redis::cmd("EVAL")
                        .arg(lua_script)
                        .arg(1) // Number of keys
                        .arg(&redis_nonce_key)
                        .arg(600) // 10 minute TTL
                        .query_async(&mut con)
                        .await;

                    match result {
                        Ok(0) => {
                            // Key already exists — replay detected
                            return Err(anyhow!(
                                "OAuth state token has already been consumed (replay detected)."
                            ));
                        }
                        Ok(1) => {
                            // Successfully marked as consumed in Redis
                            tracing::debug!("OAuth nonce marked as consumed in Redis");
                        }
                        Ok(_) => {
                            // Unexpected return value from Lua script, log and continue
                            tracing::warn!("Redis Lua script returned unexpected value");
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "Redis Lua script failed — proceeding with DB-only validation"
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "Redis unavailable for OAuth nonce check — proceeding with DB-only validation"
                    );
                }
            }
        }

        // Step 2: DB-level atomic consumption
        //
        // MCP-1096 (2026-05-16): NULL out `pkce_verifier` on consume.
        // The verifier is short-lived (10-min row TTL) but credential-
        // class — combined with an intercepted authorization code it
        // completes the OAuth exchange. Pre-fix consumed rows kept
        // the verifier in DB until `cleanup_expired_state_tokens`
        // swept them at the 10-minute mark. A read-only DB compromise
        // during that window exposed live (used=false, not expired)
        // AND just-consumed (used=true, not expired) verifiers; the
        // just-consumed ones have no exploit value on their own (the
        // `code` is single-use at the provider), but defense-in-depth
        // says scrub credential-class fields the moment they stop
        // being needed. Same persistence-boundary discipline as
        // MCP-1002 (oauth_state_tokens added to query_paginated
        // blocklist). Caller already retrieved the verifier via
        // `get_pkce_verifier` before this UPDATE fires; setting it to
        // NULL here is safe.
        let result = sqlx::query_as::<_, (Uuid, Option<String>)>(
            "UPDATE oauth_state_tokens
             SET used = true, pkce_verifier = NULL
             WHERE state_token = $1 AND provider = $2 AND used = false AND expires_at > NOW()
             RETURNING id, session_binding_hash",
        )
        .bind(state_token)
        .bind(provider)
        .fetch_optional(&self.db_pool)
        .await
        .context("Failed to validate OAuth state token")?;

        let (_id, stored_binding_hash) = match result {
            Some(row) => row,
            None => {
                return Err(anyhow!(
                    "Invalid or expired OAuth state token. This may indicate a CSRF attack."
                ));
            }
        };

        // S1 (login-CSRF / session-fixation): if the row was written with
        // a browser-session binding, the callback MUST present the
        // matching cookie. The row is already consumed atomically above
        // (single-use preserved) — we reject AFTER the consume so a
        // failed binding check still burns the token, denying an attacker
        // any retry against the same `state`. The compare is over SHA-256
        // hex digests, constant-time so it can't be used as a timing
        // oracle to recover the cookie. Never log either value.
        if let Some(expected_hash) = stored_binding_hash {
            let provided_hash = match session_binding {
                Some(nonce) => hash_oauth_session_binding(nonce),
                None => {
                    tracing::warn!(
                        provider = %provider,
                        "OAuth callback missing session-binding cookie for a bound state token (possible login-CSRF)"
                    );
                    return Err(anyhow!(
                        "Invalid or expired OAuth state token. This may indicate a CSRF attack."
                    ));
                }
            };
            if !constant_time_eq(expected_hash.as_bytes(), provided_hash.as_bytes()) {
                tracing::warn!(
                    provider = %provider,
                    "OAuth callback session-binding mismatch (possible login-CSRF)"
                );
                return Err(anyhow!(
                    "Invalid or expired OAuth state token. This may indicate a CSRF attack."
                ));
            }
        }

        Ok(())
    }

    /// Clean up expired OAuth state tokens
    /// This should be called periodically (e.g., hourly) to prevent database bloat
    /// and ensure that expired tokens cannot be replayed
    pub async fn cleanup_expired_state_tokens(&self) -> Result<u64> {
        let result = sqlx::query!("DELETE FROM oauth_state_tokens WHERE expires_at < NOW()")
            .execute(&self.db_pool)
            .await
            .context("Failed to cleanup expired OAuth state tokens")?;

        let deleted_count = result.rows_affected();
        if deleted_count > 0 {
            tracing::info!("Cleaned up {} expired OAuth state tokens", deleted_count);
        }

        Ok(deleted_count)
    }

    /// Generate OAuth authorization URL.
    ///
    /// Returns `(auth_url, state_token, session_binding_nonce)`.
    ///
    /// S1 (login-CSRF / session-fixation): `session_binding_nonce` is an
    /// opaque per-browser secret. The CALLER MUST set it on the browser
    /// as an HttpOnly + Secure + SameSite=Lax cookie (suggested name
    /// `talos_oauth_session`) and pass the cookie value back into
    /// `handle_callback` on the provider redirect. Only the SHA-256 of
    /// the nonce is persisted server-side; the plaintext lives only in
    /// the cookie. This binds the `state` nonce to THIS browser, not just
    /// "Talos issued it". NEVER log the returned nonce.
    pub async fn get_authorization_url(
        &self,
        provider: OAuthProvider,
        extra_scopes: Option<Vec<String>>,
    ) -> Result<(String, String, String)> {
        if !self.is_provider_enabled(&provider) {
            return Err(anyhow!(
                "{} OAuth is not configured. Set environment variables.",
                provider.as_str()
            ));
        }

        let (auth_url, csrf_token, pkce_verifier) = match provider {
            OAuthProvider::Google => self.get_google_auth_url(extra_scopes).await,
            OAuthProvider::Okta => self.get_okta_auth_url().await,
            OAuthProvider::Snyk => self.get_snyk_auth_url().await,
        }?;

        // Generate a browser-session binding; persist only its hash.
        let (session_nonce, session_binding_hash) = generate_oauth_session_binding();

        // Store state token + PKCE verifier + session binding for CSRF,
        // code-interception, and login-CSRF protection.
        self.store_state_token(
            &csrf_token,
            provider.as_str(),
            Some(pkce_verifier.secret()),
            Some(&session_binding_hash),
        )
        .await?;

        Ok((auth_url, csrf_token, session_nonce))
    }

    /// Google OAuth authorization URL
    async fn get_google_auth_url(
        &self,
        extra_scopes: Option<Vec<String>>,
    ) -> Result<(String, String, PkceCodeVerifier)> {
        // `client` is not used after creation; rename to `_client` to avoid dead_code warning.
        let _client = BasicClient::new(
            ClientId::new(
                self.google_client_id
                    .clone()
                    .ok_or_else(|| anyhow!("Google client ID not configured"))?,
            ),
            Some(ClientSecret::new(
                self.google_client_secret
                    .clone()
                    .ok_or_else(|| anyhow!("Google client secret not configured"))?,
            )),
            AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())?,
            Some(TokenUrl::new(
                "https://oauth2.googleapis.com/token".to_string(),
            )?),
        )
        // The redirect URI must match the one used in the auth request.
        .set_redirect_uri(RedirectUrl::new(
            self.google_redirect_uri
                .clone()
                .ok_or_else(|| anyhow!("Google redirect URI not configured"))?,
        )?);

        // PKCE: generate S256 challenge to prevent authorization code interception.
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let mut req = _client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .set_pkce_challenge(pkce_challenge);

        if let Some(scopes) = extra_scopes {
            for scope in scopes {
                req = req.add_scope(Scope::new(scope));
            }
            req = req.add_extra_param("access_type", "offline");
            req = req.add_extra_param("prompt", "consent");
        }
        let (auth_url, csrf_token) = req.url();

        Ok((
            auth_url.to_string(),
            csrf_token.secret().to_string(),
            pkce_verifier,
        ))
    }

    /// Okta OIDC authorization URL
    async fn get_okta_auth_url(&self) -> Result<(String, String, PkceCodeVerifier)> {
        // Build Okta URLs manually – Okta follows the standard OAuth2 endpoints.
        let domain = self
            .okta_domain
            .clone()
            .ok_or_else(|| anyhow!("Okta domain not configured"))?;
        let auth_endpoint = format!("https://{domain}/oauth2/v1/authorize");
        let token_endpoint = format!("https://{domain}/oauth2/v1/token");

        let _client = BasicClient::new(
            ClientId::new(
                self.okta_client_id
                    .clone()
                    .ok_or_else(|| anyhow!("Okta client ID not configured"))?,
            ),
            Some(ClientSecret::new(
                self.okta_client_secret
                    .clone()
                    .ok_or_else(|| anyhow!("Okta client secret not configured"))?,
            )),
            AuthUrl::new(auth_endpoint)?,
            Some(TokenUrl::new(token_endpoint)?),
        )
        .set_redirect_uri(RedirectUrl::new(
            self.okta_redirect_uri
                .clone()
                .ok_or_else(|| anyhow!("Okta redirect URI not configured"))?,
        )?);

        // PKCE: generate S256 challenge to prevent authorization code interception.
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let (auth_url, csrf_token) = _client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .set_pkce_challenge(pkce_challenge)
            .url();

        Ok((
            auth_url.to_string(),
            csrf_token.secret().to_string(),
            pkce_verifier,
        ))
    }

    /// Snyk OAuth authorization URL
    async fn get_snyk_auth_url(&self) -> Result<(String, String, PkceCodeVerifier)> {
        let _client = BasicClient::new(
            ClientId::new(
                self.snyk_client_id
                    .clone()
                    .ok_or_else(|| anyhow!("Snyk client ID not configured"))?,
            ),
            Some(ClientSecret::new(
                self.snyk_client_secret
                    .clone()
                    .ok_or_else(|| anyhow!("Snyk client secret not configured"))?,
            )),
            AuthUrl::new("https://app.snyk.io/oauth2/authorize".to_string())?,
            Some(TokenUrl::new(
                "https://api.snyk.io/oauth2/token".to_string(),
            )?),
        )
        .set_redirect_uri(RedirectUrl::new(
            self.snyk_redirect_uri
                .clone()
                .ok_or_else(|| anyhow!("Snyk redirect URI not configured"))?,
        )?);

        // PKCE: generate S256 challenge to prevent authorization code interception.
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let (auth_url, csrf_token) = _client
            .authorize_url(CsrfToken::new_random)
            // Snyk scopes: offline.access for refresh tokens, plus API access scopes
            .add_scope(Scope::new("offline.access".to_string()))
            .add_scope(Scope::new("org.read".to_string()))
            .add_scope(Scope::new("org.project.read".to_string()))
            .add_scope(Scope::new("org.report.read".to_string()))
            .set_pkce_challenge(pkce_challenge)
            .url();

        Ok((
            auth_url.to_string(),
            csrf_token.secret().to_string(),
            pkce_verifier,
        ))
    }

    /// Handle OAuth callback and get user info
    /// `session_binding` is the plaintext value of the browser's
    /// `talos_oauth_session` cookie (set by the caller at
    /// `get_authorization_url` time). The caller MUST read it from the
    /// callback request's cookies and pass it here so the S1 login-CSRF
    /// binding can be enforced. Passing `None` when the consumed state row
    /// carries a binding hash is rejected as a CSRF attempt.
    pub async fn handle_callback(
        &self,
        provider: OAuthProvider,
        code: String,
        state_token: Option<String>,
        session_binding: Option<&str>,
    ) -> Result<OAuthUserInfo> {
        // Validate CSRF state token
        let state = state_token.ok_or_else(|| {
            anyhow!("Missing OAuth state parameter. CSRF protection requires state token.")
        })?;

        // Retrieve PKCE verifier before consuming the state token (validate_state_token
        // marks the row as used but does not delete it, so order is flexible here;
        // fetching first is safer against any future row-deletion changes).
        let pkce_verifier = self.get_pkce_verifier(&state).await?;

        self.validate_state_token(&state, provider.as_str(), session_binding)
            .await?;

        match provider {
            OAuthProvider::Google => self.handle_google_callback(code, pkce_verifier).await,
            OAuthProvider::Okta => self.handle_okta_callback(code, pkce_verifier).await,
            OAuthProvider::Snyk => self.handle_snyk_callback(code, pkce_verifier).await,
        }
    }

    /// Handle Google OAuth callback
    async fn handle_google_callback(
        &self,
        code: String,
        pkce_verifier: Option<String>,
    ) -> Result<OAuthUserInfo> {
        // Construct OAuth client; not used directly in this flow.
        let _client = BasicClient::new(
            ClientId::new(
                self.google_client_id
                    .clone()
                    .ok_or_else(|| anyhow!("Google client ID not configured"))?,
            ),
            Some(ClientSecret::new(
                self.google_client_secret
                    .clone()
                    .ok_or_else(|| anyhow!("Google client secret not configured"))?,
            )),
            AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())?,
            Some(TokenUrl::new(
                "https://oauth2.googleapis.com/token".to_string(),
            )?),
        )
        .set_redirect_uri(RedirectUrl::new(
            self.google_redirect_uri
                .clone()
                .ok_or_else(|| anyhow!("Google redirect URI not configured"))?,
        )?);

        // Exchange code for token – Google requires client credentials in the request body
        // rather than HTTP Basic auth, which the `oauth2` crate defaults to. To ensure
        // compatibility we perform a manual POST request mirroring the original implementation.
        let token_endpoint = "https://oauth2.googleapis.com/token";
        let client_id = self
            .google_client_id
            .as_deref()
            .ok_or_else(|| anyhow!("Google client ID not configured"))?;
        let client_secret = self
            .google_client_secret
            .as_deref()
            .ok_or_else(|| anyhow!("Google client secret not configured"))?;
        let redirect_uri = self
            .google_redirect_uri
            .as_deref()
            .ok_or_else(|| anyhow!("Google redirect URI not configured"))?;

        // Build params dynamically to include PKCE code_verifier when present.
        let mut params: Vec<(&str, &str)> = vec![
            ("code", code.as_str()),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("redirect_uri", redirect_uri),
            ("grant_type", "authorization_code"),
        ];
        // PKCE: include code_verifier so Google can verify the S256 challenge.
        if let Some(ref verifier) = pkce_verifier {
            params.push(("code_verifier", verifier.as_str()));
        }

        let token_resp = oauth_http_client()
            .post(token_endpoint)
            .form(&params)
            .send()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to request token endpoint");
                anyhow!("Failed to exchange authorization code for token: {}", e)
            })?;
        let token_response =
            talos_http_body::read_json_capped::<oauth2::basic::BasicTokenResponse>(token_resp)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "Failed to parse token response");
                    anyhow!("Failed to parse token response: {}", e)
                })?;

        // Get user info from Google
        let user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo";
        let resp = oauth_http_client()
            .get(user_info_url)
            .bearer_auth(token_response.access_token().secret())
            .send()
            .await?;
        let user_info: serde_json::Value = talos_http_body::read_json_capped(resp).await?;

        Ok(OAuthUserInfo {
            provider_user_id: user_info["id"]
                .as_str()
                .ok_or_else(|| anyhow!("Missing user ID"))?
                .to_string(),
            email: user_info["email"]
                .as_str()
                .ok_or_else(|| anyhow!("Missing email"))?
                .to_string(),
            email_verified: user_info["verified_email"]
                .as_bool()
                .ok_or_else(|| anyhow!("Missing verified_email field in Google user info"))?,
            name: user_info["name"].as_str().map(|s| s.to_string()),
            picture: user_info["picture"].as_str().map(|s| s.to_string()),
            // Include tokens for Google Calendar/Gmail integrations
            access_token: Some(token_response.access_token().secret().to_string()),
            refresh_token: token_response
                .refresh_token()
                .map(|t| t.secret().to_string()),
            // Saturate the u64→i64 conversion (MCP-960..962 integer-cast class):
            // a malicious/buggy provider returning an absurd `expires_in` would
            // otherwise wrap to a negative i64 and corrupt downstream expiry math.
            expires_in: token_response
                .expires_in()
                .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX)),
            // `scopes()` returns an Option<&[Scope]>. Annotate the slice type so Rust can infer
            // the closure parameter.
            // `scopes()` returns `Option<&Vec<Scope>>`; map over the Vec reference.
            scope: token_response.scopes().map(|scopes| {
                scopes
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(" ")
            }),
        })
    }

    /// Handle Okta OIDC callback
    async fn handle_okta_callback(
        &self,
        code: String,
        pkce_verifier: Option<String>,
    ) -> Result<OAuthUserInfo> {
        // Build Okta client (same as get_okta_auth_url)
        let domain = self
            .okta_domain
            .clone()
            .ok_or_else(|| anyhow!("Okta domain not configured"))?;
        let auth_endpoint = format!("https://{domain}/oauth2/v1/authorize");
        let token_endpoint = format!("https://{domain}/oauth2/v1/token");

        let client = BasicClient::new(
            ClientId::new(
                self.okta_client_id
                    .clone()
                    .ok_or_else(|| anyhow!("Okta client ID not configured"))?,
            ),
            Some(ClientSecret::new(
                self.okta_client_secret
                    .clone()
                    .ok_or_else(|| anyhow!("Okta client secret not configured"))?,
            )),
            AuthUrl::new(auth_endpoint)?,
            Some(TokenUrl::new(token_endpoint)?),
        )
        .set_redirect_uri(RedirectUrl::new(
            self.okta_redirect_uri
                .clone()
                .ok_or_else(|| anyhow!("Okta redirect URI not configured"))?,
        )?);

        // Exchange code for token, including PKCE verifier when present.
        let mut exchange = client.exchange_code(AuthorizationCode::new(code));
        if let Some(verifier) = pkce_verifier {
            exchange = exchange.set_pkce_verifier(PkceCodeVerifier::new(verifier));
        }
        let token_response = exchange
            .request_async(async_http_client)
            .await
            .context("Failed to exchange authorization code for token")?;

        // Retrieve userinfo via Okta's userinfo endpoint
        let userinfo_endpoint = format!("https://{domain}/oauth2/v1/userinfo");
        let resp = oauth_http_client()
            .get(&userinfo_endpoint)
            .bearer_auth(token_response.access_token().secret())
            .send()
            .await?;
        let user_info: serde_json::Value = talos_http_body::read_json_capped(resp).await?;

        Ok(OAuthUserInfo {
            provider_user_id: user_info["sub"]
                .as_str()
                .ok_or_else(|| anyhow!("Missing user ID"))?
                .to_string(),
            email: user_info["email"]
                .as_str()
                .ok_or_else(|| anyhow!("Missing email"))?
                .to_string(),
            email_verified: user_info["email_verified"]
                .as_bool()
                .ok_or_else(|| anyhow!("Missing email_verified field in Okta user info"))?,
            name: user_info["name"].as_str().map(|s| s.to_string()),
            picture: user_info["picture"].as_str().map(|s| s.to_string()),
            // Okta is for authentication only; token data is not persisted.
            access_token: None,
            refresh_token: None,
            expires_in: None,
            scope: None,
        })
    }

    /// Handle Snyk OAuth callback
    async fn handle_snyk_callback(
        &self,
        code: String,
        pkce_verifier: Option<String>,
    ) -> Result<OAuthUserInfo> {
        let client = BasicClient::new(
            ClientId::new(
                self.snyk_client_id
                    .clone()
                    .ok_or_else(|| anyhow!("Snyk client ID not configured"))?,
            ),
            Some(ClientSecret::new(
                self.snyk_client_secret
                    .clone()
                    .ok_or_else(|| anyhow!("Snyk client secret not configured"))?,
            )),
            AuthUrl::new("https://app.snyk.io/oauth2/authorize".to_string())?,
            Some(TokenUrl::new(
                "https://api.snyk.io/oauth2/token".to_string(),
            )?),
        )
        .set_redirect_uri(RedirectUrl::new(
            self.snyk_redirect_uri
                .clone()
                .ok_or_else(|| anyhow!("Snyk redirect URI not configured"))?,
        )?);

        // Exchange code for token, including PKCE verifier when present.
        let mut exchange = client.exchange_code(AuthorizationCode::new(code));
        if let Some(verifier) = pkce_verifier {
            exchange = exchange.set_pkce_verifier(PkceCodeVerifier::new(verifier));
        }
        let token_response = exchange
            .request_async(async_http_client)
            .await
            .context("Failed to exchange authorization code for Snyk token")?;

        // Get user info from Snyk API
        let user_info_url = "https://api.snyk.io/rest/self?version=2024-01-04";
        let resp = oauth_http_client()
            .get(user_info_url)
            .bearer_auth(token_response.access_token().secret())
            .send()
            .await?;
        let user_info: serde_json::Value = talos_http_body::read_json_capped(resp).await?;

        // Snyk API returns: { "data": { "id": "...", "attributes": { "email": "...", "name": "...", "username": "..." } } }
        let data = user_info["data"]
            .as_object()
            .ok_or_else(|| anyhow!("Invalid Snyk user info response"))?;
        let attrs = data["attributes"]
            .as_object()
            .ok_or_else(|| anyhow!("Missing attributes in Snyk response"))?;

        Ok(OAuthUserInfo {
            provider_user_id: data["id"]
                .as_str()
                .ok_or_else(|| anyhow!("Missing user ID in Snyk response"))?
                .to_string(),
            email: attrs["email"]
                .as_str()
                .ok_or_else(|| anyhow!("Missing email in Snyk response"))?
                .to_string(),
            email_verified: true, // Snyk doesn't provide this, assume verified
            name: attrs["name"].as_str().map(|s| s.to_string()),
            picture: None, // Snyk doesn't provide avatar URLs
            // Include tokens for Snyk API integrations
            access_token: Some(token_response.access_token().secret().to_string()),
            refresh_token: token_response
                .refresh_token()
                .map(|t| t.secret().to_string()),
            // Saturate the u64→i64 conversion (MCP-960..962 integer-cast class):
            // a malicious/buggy provider returning an absurd `expires_in` would
            // otherwise wrap to a negative i64 and corrupt downstream expiry math.
            expires_in: token_response
                .expires_in()
                .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX)),
            // Annotate slice type for `scopes()` as above.
            // Convert the list of scopes into a space‑separated string.
            scope: token_response.scopes().map(|scopes| {
                scopes
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(" ")
            }),
        })
    }

    /// Link OAuth account to existing user or create new user
    pub async fn link_or_create_user(
        &self,
        provider: OAuthProvider,
        user_info: OAuthUserInfo,
        existing_user_id: Option<Uuid>,
    ) -> Result<(Uuid, bool)> {
        // Require a verified email address before allowing account creation or linking.
        // Accepting unverified emails could allow an attacker to claim another user's
        // account by registering with that email at a permissive OAuth provider.
        if !user_info.email_verified {
            anyhow::bail!(
                "OAuth login rejected: email address '{}' is not verified by the provider. \
                 Please verify your email with {} before signing in.",
                user_info.email,
                provider.as_str()
            );
        }

        // Check if OAuth account already exists
        if let Some(existing) = self
            .get_oauth_account(&provider, &user_info.provider_user_id)
            .await?
        {
            // Update last login
            sqlx::query!(
                "UPDATE oauth_accounts SET last_login_at = NOW() WHERE id = $1",
                existing.id
            )
            .execute(&self.db_pool)
            .await?;

            return Ok((existing.user_id, false)); // existing user
        }

        // If linking to existing user (explicit intent — user is already authenticated)
        if let Some(user_id) = existing_user_id {
            self.link_oauth_account(user_id, provider, user_info)
                .await?;
            return Ok((user_id, false));
        }

        // Check if user exists by email. Dynamic query (not the `query!`
        // macro) so we don't need to add the new column projection to the
        // sqlx offline cache.
        //
        // MCP-659: case-insensitive email match for sibling parity with the
        // signup/login normalization in talos-auth. Pre-fix the case-
        // sensitive WHERE missed legacy `Alice@Gmail.com` rows when the
        // OAuth provider returned `alice@gmail.com`; the flow then created
        // a DUPLICATE row in `users` for the same person. The auto-link
        // refusal further down still applies — case-insensitive match just
        // ensures the security policy fires consistently regardless of
        // upstream provider casing. LIMIT 1 defends against legacy
        // duplicate rows that may already exist from before this fix.
        let normalized_email = user_info.email.trim().to_lowercase();
        let existing_user: Option<(Uuid, String)> = sqlx::query_as::<_, (Uuid, String)>(
            "SELECT id, password_hash FROM users \
             WHERE LOWER(email) = $1 AND is_active = true \
             LIMIT 1",
        )
        .bind(&normalized_email)
        .fetch_optional(&self.db_pool)
        .await?;

        let is_new_user = existing_user.is_none();
        let user_id = if let Some((existing_user_id, _password_hash)) = existing_user {
            // SECURITY: refuse to auto-link an OAuth login to ANY existing
            // account on a callback-only flow. Auto-linking by email is
            // unsafe regardless of whether the existing account is
            // password-based or OAuth-only:
            //
            //   - PASSWORD ACCOUNT: a malicious/permissive OAuth provider
            //     issuing a token with a target's email + email_verified=true
            //     would inherit the password-protected account.
            //
            //   - OAUTH-ONLY ACCOUNT: cross-provider hijack. alice signs up
            //     via Google with alice@x.com; later, an attacker who controls
            //     alice@x.com on a different configured provider (Slack
            //     workspace owner, Atlassian custom-domain admin, repurposed
            //     domain owner) authenticates via that provider and gets
            //     auto-linked into alice's existing Talos account.
            //
            // Either case requires explicit authenticated linking: pass
            // `existing_user_id` (the current user is already logged in),
            // or expose a 2FA-gated "connect provider" mutation. The
            // callback path with `existing_user_id = None` should only ever
            // create new users or reattach to a same-(provider, provider_user_id)
            // OAuth account — both already handled above.
            tracing::warn!(
                user_id = %existing_user_id,
                provider = %provider.as_str(),
                "Refusing OAuth auto-link to existing account on email match"
            );
            anyhow::bail!(
                "An account with this email already exists. \
                 Please sign in with your existing method and link your {} account from settings.",
                provider.as_str()
            );
        } else {
            // Create new user.
            // SECURITY: OAuth accounts have no password. Store a bcrypt hash of a
            // fixed sentinel string so that password verification always fails for
            // these accounts (bcrypt::verify returns false, never true).
            // Using "" would work in practice but is ambiguous and error-prone.
            //
            // MCP-659: persist the normalized (trim+lowercase) email, matching
            // the signup-side normalization in talos_auth::create_user. This
            // keeps the case-insensitive lookup above consistent with the
            // stored row casing.
            //
            // MCP-1083 (2026-05-16): use the SAME bcrypt cost as real password
            // hashes, not the previous hardcoded cost 4. Pre-fix the sentinel
            // had cost-4 baked into the stored hash, so `bcrypt::verify` on
            // OAuth-only accounts ran ~5ms vs ~100-400ms for real-password
            // accounts (cost 10-14). Timing diff was a side-channel oracle:
            // an attacker calling `POST /auth/login` with an OAuth-only email
            // could ENUMERATE which accounts are OAuth-only just by measuring
            // response latency, then pivot to OAuth-provider attacks (phishing
            // the IdP login page, exploiting account-linking flaws, etc.).
            //
            // Reads `BCRYPT_COST` directly so timing matches the AuthService's
            // password hashes byte-for-byte. Falls back to `bcrypt::DEFAULT_COST`
            // if the env var is unset or out of bcrypt's valid range — the
            // controller validates BCRYPT_COST at startup (MCP-1077) so a
            // bad value already aborts boot before any signup runs, making
            // this fallback effectively unreachable in production.
            //
            // One-time cost: signup is now ~100ms instead of ~10ms for OAuth
            // users. Login (where the timing oracle lives) is unaffected for
            // legitimate users since they don't hit password-verify; the cost
            // is only paid when an attacker probes.
            let sentinel_cost = std::env::var("BCRYPT_COST")
                .ok()
                .and_then(|v| v.parse::<u32>().ok())
                .filter(|c| (4..=31).contains(c))
                .unwrap_or(bcrypt::DEFAULT_COST);
            let sentinel_hash = bcrypt::hash("__talos_oauth_account_no_password__", sentinel_cost)
                .map_err(|e| anyhow::anyhow!("Failed to create sentinel hash: {}", e))?;
            // MCP-1004 (2026-05-15): sanitize provider-supplied display
            // name before persistence. Pre-fix `user_info.name` was bound
            // verbatim — providers occasionally return names with embedded
            // control characters (some Slack workspaces, some Atlassian
            // sites with admin-edited profiles), or `null` / whitespace-
            // only fallbacks; the existing canonical-name-discipline
            // sweep (MCP-186 / MCP-218 / MCP-262 / MCP-321 / MCP-431 /
            // MCP-769) closed every other named-resource surface but the
            // OAuth user.name persistence was missed.
            //
            // OAuth-side policy diverges from `create_user` (signup):
            // signup REJECTS malformed names (operator typo deserves a
            // clear error), but OAuth SANITIZES-to-None instead (the
            // provider's data quality is not under user control — don't
            // bounce a legitimate login because Slack returned a name
            // with a stray BEL). Same shape as the talos-auth helper but
            // wraps the `Err` branch as None.
            let sanitized_name: Option<String> = user_info.name.as_deref().and_then(|raw| {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    return None;
                }
                if trimmed.len() > 255 {
                    return None;
                }
                if raw.contains('\0') || raw.chars().any(|c| c.is_control() && c != '\t') {
                    return None;
                }
                Some(trimmed.to_string())
            });
            let new_user_id = sqlx::query_scalar!(
                "INSERT INTO users (email, password_hash, name, is_active)
                 VALUES ($1, $2, $3, true)
                 RETURNING id",
                normalized_email,
                sentinel_hash,
                sanitized_name
            )
            .fetch_one(&self.db_pool)
            .await?;

            // Link OAuth account
            self.link_oauth_account(new_user_id, provider, user_info)
                .await?;

            new_user_id
        };

        Ok((user_id, is_new_user)) // return true if new user created
    }

    /// Link OAuth account to user
    async fn link_oauth_account(
        &self,
        user_id: Uuid,
        provider: OAuthProvider,
        user_info: OAuthUserInfo,
    ) -> Result<Uuid> {
        let account_id = sqlx::query_scalar!(
            r#"
            INSERT INTO oauth_accounts (
                user_id, provider, provider_user_id, email, name, picture_url, last_login_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, NOW())
            ON CONFLICT (user_id, provider)
            DO UPDATE SET
                provider_user_id = EXCLUDED.provider_user_id,
                email = EXCLUDED.email,
                name = EXCLUDED.name,
                picture_url = EXCLUDED.picture_url,
                last_login_at = NOW(),
                updated_at = NOW()
            RETURNING id
            "#,
            user_id,
            provider.as_str(),
            user_info.provider_user_id,
            user_info.email,
            user_info.name,
            user_info.picture
        )
        .fetch_one(&self.db_pool)
        .await
        .context("Failed to link OAuth account")?;

        Ok(account_id)
    }

    /// Get OAuth account by provider and provider user ID
    async fn get_oauth_account(
        &self,
        provider: &OAuthProvider,
        provider_user_id: &str,
    ) -> Result<Option<OAuthAccount>> {
        let account = sqlx::query_as!(
            OAuthAccount,
            r#"
            SELECT id, user_id, provider, provider_user_id, email, name, picture_url,
                   metadata, created_at, updated_at, last_login_at
            FROM oauth_accounts
            WHERE provider = $1 AND provider_user_id = $2
            "#,
            provider.as_str(),
            provider_user_id
        )
        .fetch_optional(&self.db_pool)
        .await?;

        Ok(account)
    }

    /// Get all OAuth accounts for a user
    pub async fn get_user_oauth_accounts(&self, user_id: Uuid) -> Result<Vec<OAuthAccount>> {
        let accounts = sqlx::query_as!(
            OAuthAccount,
            r#"
            SELECT id, user_id, provider, provider_user_id, email, name, picture_url,
                   metadata, created_at, updated_at, last_login_at
            FROM oauth_accounts
            WHERE user_id = $1
            "#,
            user_id
        )
        .fetch_all(&self.db_pool)
        .await?;

        Ok(accounts)
    }

    /// Unlink OAuth account
    pub async fn unlink_oauth_account(&self, user_id: Uuid, provider: OAuthProvider) -> Result<()> {
        let result = sqlx::query!(
            "DELETE FROM oauth_accounts WHERE user_id = $1 AND provider = $2",
            user_id,
            provider.as_str()
        )
        .execute(&self.db_pool)
        .await?;

        if result.rows_affected() == 0 {
            anyhow::bail!("OAuth account not found or access denied");
        }

        Ok(())
    }

    /// Log OAuth event
    pub async fn log_oauth_event(
        &self,
        user_id: Option<Uuid>,
        provider: &OAuthProvider,
        event_type: &str,
        success: bool,
        error_message: Option<&str>,
    ) -> Result<()> {
        // MCP-482: DLP-scrub the OAuth audit error_message before
        // persisting. Live call sites pass `&e.to_string()` from
        // `oauth_service.handle_callback(...)` — errors there can
        // include parts of an OAuth provider's response body
        // (e.g. an `invalid_client` error that quotes `client_id` or
        // `client_secret` parameter values for diagnostic purposes,
        // a misconfigured proxy that echoes the access_token / Bearer
        // header back, etc.). The `oauth_audit_log` table is queryable
        // by operators via admin tooling; matches the persistence-
        // boundary DLP rule the platform applies to DLQ (MCP-466) and
        // worker logs (MCP-481).
        //
        // MCP-1028 (2026-05-15): truncate-then-redact discipline,
        // sibling-parity with MCP-1012 (auth_audit_log) and MCP-1018
        // (webhook_request_log user_agent). OAuth provider error
        // bodies are usually under 500 chars but a verbose provider
        // (or buggy proxy) could ship multi-KB; redacting the full
        // payload before truncating wastes the regex pass. 1024
        // chars covers every legitimate OAuth error.
        let scrubbed = error_message.map(|e| {
            let truncated: &str = if e.len() > 1024 {
                talos_text_util::truncate_at_char_boundary(e, 1024)
            } else {
                e
            };
            talos_dlp_provider::redact_str(truncated)
        });
        let scrubbed_ref = scrubbed.as_deref();
        sqlx::query!(
            r#"
            INSERT INTO oauth_audit_log (user_id, provider, event_type, success, error_message)
            VALUES ($1, $2, $3, $4, $5)
            "#,
            user_id,
            provider.as_str(),
            event_type,
            success,
            scrubbed_ref
        )
        .execute(&self.db_pool)
        .await
        .ok(); // Don't fail if logging fails

        Ok(())
    }
}

#[cfg(test)]
mod session_binding_tests {
    use super::*;

    /// The verification predicate as it runs inside `validate_state_token`
    /// after the row is consumed: a stored `Option<hash>` plus the
    /// plaintext cookie value yields accept/reject. Kept as a free fn so
    /// the decision logic is exercised by real production code (the same
    /// `hash_oauth_session_binding` + `constant_time_eq` the handler uses)
    /// without standing up Postgres.
    fn binding_accepts(stored_hash: Option<&str>, provided_cookie: Option<&str>) -> bool {
        match stored_hash {
            // NULL hash (legacy / non-login row) → no binding required.
            None => true,
            Some(expected) => match provided_cookie {
                None => false,
                Some(nonce) => {
                    let provided = hash_oauth_session_binding(nonce);
                    constant_time_eq(expected.as_bytes(), provided.as_bytes())
                }
            },
        }
    }

    #[test]
    fn binding_is_written_as_hash_not_plaintext() {
        let (nonce, hash) = generate_oauth_session_binding();
        // What gets persisted must be the hash, never the cookie value.
        assert_ne!(
            nonce, hash,
            "stored value must differ from cookie plaintext"
        );
        assert_eq!(hash.len(), 64, "sha256 hex digest is 64 chars");
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        // The hash is reproducible from the nonce (callback recompute path).
        assert_eq!(hash, hash_oauth_session_binding(&nonce));
        // The nonce itself passes the state-token charset gate so it's a
        // safe cookie value.
        assert!(validate_oauth_state_token_format(&nonce).is_ok());
    }

    #[test]
    fn nonce_is_high_entropy_and_unique() {
        let (a, _) = generate_oauth_session_binding();
        let (b, _) = generate_oauth_session_binding();
        assert_ne!(a, b, "two generated nonces must not collide");
        // 2 × 32 hex chars (two v4 UUIDs, hyphenless).
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn happy_path_accepts_matching_cookie() {
        let (nonce, hash) = generate_oauth_session_binding();
        assert!(binding_accepts(Some(&hash), Some(&nonce)));
    }

    #[test]
    fn mismatched_cookie_rejected() {
        let (_nonce_a, hash_a) = generate_oauth_session_binding();
        let (nonce_b, _hash_b) = generate_oauth_session_binding();
        // Attacker presents a cookie for a different (their own) session.
        assert!(!binding_accepts(Some(&hash_a), Some(&nonce_b)));
    }

    #[test]
    fn missing_cookie_rejected_when_binding_present() {
        let (_nonce, hash) = generate_oauth_session_binding();
        // Victim's browser hits the attacker-supplied callback URL with no
        // matching session cookie → must be refused.
        assert!(!binding_accepts(Some(&hash), None));
    }

    #[test]
    fn null_hash_row_skips_binding_check() {
        // Legacy / non-login rows (NULL hash) accept regardless of cookie,
        // preserving backward compatibility.
        assert!(binding_accepts(None, None));
        assert!(binding_accepts(None, Some("anything")));
    }

    #[test]
    fn constant_time_eq_matches_semantics_of_equality() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        // Length mismatch is a rejection, not a panic or a short-circuit.
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"", b"x"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn empty_cookie_does_not_match_a_real_binding() {
        let (_nonce, hash) = generate_oauth_session_binding();
        // An empty-string cookie hashes to the SHA-256 of "" which is not
        // the stored hash → rejected.
        assert!(!binding_accepts(Some(&hash), Some("")));
    }
}

#[cfg(test)]
mod redaction_tests {
    use super::*;

    /// Pins the contract that `OAuthUserInfo`'s `Debug` redacts both
    /// tokens. If a future refactor reverts to `#[derive(Debug)]` this
    /// test fails — protects every caller from accidentally dumping
    /// live OAuth credentials via `tracing::*!("{:?}", info)`.
    #[test]
    fn debug_redacts_tokens() {
        let info = OAuthUserInfo {
            provider_user_id: "uid-123".into(),
            email: "alice@example.com".into(),
            email_verified: true,
            name: Some("Alice".into()),
            picture: None,
            access_token: Some("ya29.LIVE_ACCESS_TOKEN_ABCDEF".into()),
            refresh_token: Some("1//LIVE_REFRESH_TOKEN_XYZ".into()),
            expires_in: Some(3600),
            scope: Some("email profile".into()),
        };
        let dbg = format!("{:?}", info);
        assert!(
            !dbg.contains("ya29.LIVE_ACCESS_TOKEN_ABCDEF"),
            "access_token leaked: {dbg}"
        );
        assert!(
            !dbg.contains("LIVE_REFRESH_TOKEN_XYZ"),
            "refresh_token leaked: {dbg}"
        );
        assert!(
            dbg.contains("[REDACTED]"),
            "redaction marker missing: {dbg}"
        );
        // Non-secret fields still visible — the point is targeted
        // redaction, not blackboxing the whole struct.
        assert!(dbg.contains("alice@example.com"), "email lost: {dbg}");
        assert!(dbg.contains("uid-123"), "provider_user_id lost: {dbg}");
    }

    #[test]
    fn debug_keeps_none_distinguishable_from_some() {
        let info = OAuthUserInfo {
            provider_user_id: "uid".into(),
            email: "a@b.c".into(),
            email_verified: false,
            name: None,
            picture: None,
            access_token: None,
            refresh_token: None,
            expires_in: None,
            scope: None,
        };
        let dbg = format!("{:?}", info);
        // None tokens print as `None`, NOT as `Some("[REDACTED]")` —
        // observers can still tell whether a token was present.
        assert!(dbg.contains("access_token: None"), "None lost: {dbg}");
        assert!(dbg.contains("refresh_token: None"), "None lost: {dbg}");
    }
}

#[cfg(test)]
mod okta_domain_validation_tests {
    use super::is_valid_okta_domain;

    #[test]
    fn accepts_canonical_okta_domains() {
        assert!(is_valid_okta_domain("acme.okta.com"));
        assert!(is_valid_okta_domain("acme.oktapreview.com"));
        assert!(is_valid_okta_domain("acme.okta-emea.com"));
    }

    #[test]
    fn accepts_custom_okta_domains() {
        assert!(is_valid_okta_domain("auth.mycompany.com"));
        assert!(is_valid_okta_domain("sso.example.io"));
    }

    #[test]
    fn rejects_empty_or_too_long() {
        assert!(!is_valid_okta_domain(""));
        let long = "a".repeat(254);
        assert!(!is_valid_okta_domain(&long));
    }

    #[test]
    fn rejects_path_traversal_misconfig() {
        // The MCP-1157 phishing-vector cases: scheme/path/query/fragment in domain.
        assert!(!is_valid_okta_domain("attacker.com/x"));
        assert!(!is_valid_okta_domain("attacker.com?x=1"));
        assert!(!is_valid_okta_domain("attacker.com#x"));
        assert!(!is_valid_okta_domain("https://attacker.com"));
        assert!(!is_valid_okta_domain("acme.okta.com/oauth2"));
    }

    #[test]
    fn rejects_userinfo_and_port() {
        assert!(!is_valid_okta_domain("user@acme.okta.com"));
        assert!(!is_valid_okta_domain("acme.okta.com:8080"));
    }

    #[test]
    fn rejects_invalid_label_shapes() {
        assert!(!is_valid_okta_domain("acme..okta.com")); // empty label
        assert!(!is_valid_okta_domain("-acme.okta.com")); // leading hyphen on label
        assert!(!is_valid_okta_domain("acme-.okta.com")); // trailing hyphen on label
        assert!(!is_valid_okta_domain(".acme.okta.com")); // empty leading label
        assert!(!is_valid_okta_domain("acme.okta.com.")); // empty trailing label
        let long_label = format!("{}.okta.com", "a".repeat(64));
        assert!(!is_valid_okta_domain(&long_label));
    }

    #[test]
    fn rejects_control_and_whitespace() {
        assert!(!is_valid_okta_domain("acme okta.com"));
        assert!(!is_valid_okta_domain("acme.\nokta.com"));
        assert!(!is_valid_okta_domain("acme.\tokta.com"));
        assert!(!is_valid_okta_domain("acme.okta.com\0"));
    }
}

#[cfg(test)]
mod oauth_expires_at_tests {
    use super::oauth_expires_at;
    use chrono::Utc;

    #[test]
    fn default_for_none() {
        let now = Utc::now();
        let exp = oauth_expires_at(None);
        let delta = exp - now;
        // 3600s default, allow 5s skew for test execution.
        assert!(
            (3595..=3605).contains(&delta.num_seconds()),
            "expected ~3600s delta, got {}",
            delta.num_seconds()
        );
    }

    #[test]
    fn clamps_floor() {
        // expires_in=1 would invalidate the token within a tick;
        // floor to 60s so the refresh loop doesn't storm the provider.
        let now = Utc::now();
        let exp = oauth_expires_at(Some(1));
        let delta = exp - now;
        assert!(
            delta.num_seconds() >= 55,
            "floor should kick in: got {}s",
            delta.num_seconds()
        );
    }

    #[test]
    fn clamps_ceiling() {
        // 90-day cap defends against a provider returning huge /
        // u64::MAX. Pre-Perf#8 the cap was 24h, which silently
        // truncated long-lived legitimate tokens (Microsoft Graph
        // service principals, etc.).
        let now = Utc::now();
        let exp = oauth_expires_at(Some(u64::MAX));
        let delta = exp - now;
        // 90 days × 86_400 = 7_776_000 sec. Allow 5s skew.
        assert!(
            (7_775_995..=7_776_005).contains(&delta.num_seconds()),
            "ceiling cap should clamp to 90 days, got {}s",
            delta.num_seconds()
        );
    }

    #[test]
    fn does_not_panic_on_i64_overflow_inputs() {
        // Pre-fix: `chrono::Duration::seconds(u64::MAX as i64)` —
        // u64::MAX as i64 wraps to -1, the resulting "Duration of -1s"
        // produced expires_at in the past → immediate refresh storm.
        // For sufficiently large multiples (>i64::MAX/1000)
        // Duration::seconds panics internally. With the clamp, both
        // paths are safe.
        for v in [
            i64::MAX as u64 + 1,
            (i64::MAX / 1000) as u64 + 1,
            u64::MAX - 1,
            u64::MAX,
        ] {
            let exp = oauth_expires_at(Some(v));
            // Result must be in the FUTURE, not the past.
            assert!(
                exp > Utc::now() - chrono::Duration::seconds(5),
                "expires_at must be in the future for input {v}, got {exp}"
            );
        }
    }

    #[test]
    fn default_when_zero() {
        // expires_in=0 floors to 60s.
        let now = Utc::now();
        let exp = oauth_expires_at(Some(0));
        let delta = exp - now;
        assert!(delta.num_seconds() >= 55);
    }
}
