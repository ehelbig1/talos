//! Google Calendar (add events) connection: the OAuth consent that lets ONE
//! kind of module put an event on a calendar the owner owns.
//!
//! This is a second connection to Google Calendar, beside the read-only one
//! in `talos-google-calendar`. They are kept apart on purpose:
//!
//! * the read connection (`oauth/google_calendar/…`) is granted to every
//!   module that reads a calendar, and its scopes cannot change an event;
//! * this one (`oauth/google_calendar_write/…`) carries the one write scope,
//!   `calendar.events.owned`, in its own vault namespace. A module granted
//!   the read connection cannot name these tokens, so adding a write does
//!   not turn every calendar reader into a calendar writer.
//!
//! The scope is the narrowest Google offers that can add an event to the
//! owner's own calendar: events on calendars the account OWNS. It is not
//! `calendar.events` (every calendar the account can see, shared ones
//! included) and not `calendar` (sharing and deletion of calendars). The
//! scope still permits changing and deleting an owned event; what a module
//! may do with the token is narrowed further by its `allowed_methods` — a
//! module that only adds events declares `POST` and the worker refuses the
//! rest.
//!
//! OAuth only — no push channel, no webhook, no API client of its own. The
//! write is done by a sandboxed module with a
//! `vault://oauth/google_calendar_write/...` reference; this crate exists so
//! that token can be obtained, refreshed and revoked.
//!
//! * Tokens live in the unified credential store; the table here holds
//!   metadata.
//! * The consent is issued under the SHARED Google client
//!   ([`talos_oauth::shared_google_client`]) — the same resolution the token
//!   refresh uses, because a token cannot be refreshed by a different client.
//! * The flow is `talos_oauth`'s: state bound to the user and to the browser
//!   that started it, single-use, PKCE. Nothing here re-implements it.

pub mod handlers;

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use sqlx::{Pool, Postgres};
use std::sync::{Arc, LazyLock};
use uuid::Uuid;

use talos_oauth::OAuthCredentialService;

/// Provider string: the state-token match key and the vault-path segment.
pub const PROVIDER: &str = "google_calendar_write";

/// The one scope this connection exists for: events on calendars the
/// account owns.
pub const WRITE_SCOPE: &str = "https://www.googleapis.com/auth/calendar.events.owned";

/// What the consent asks for. `openid` + `userinfo.email` identify the
/// connected account (its id keys the vault path, its address labels the
/// settings card).
pub const SCOPES: &[&str] = &[
    WRITE_SCOPE,
    "https://www.googleapis.com/auth/userinfo.email",
    "openid",
];

const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const USERINFO_URL: &str = "https://www.googleapis.com/oauth2/v2/userinfo";
/// Where Google sends the browser back when no redirect is configured (the
/// development stack).
const DEFAULT_REDIRECT_URI: &str = "http://localhost:8000/api/google-calendar-write/callback";

/// One hardened client for the token exchange and the account lookup
/// (redirects off, connect and total timeouts — lint 49).
static HTTP: LazyLock<reqwest::Client> = LazyLock::new(|| {
    talos_http_utils::trusted_client::build_integration_client(std::time::Duration::from_secs(15))
});

/// A connected Google Calendar (add events) account. Metadata only — no token is ever here.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct GoogleCalendarWriteIntegration {
    pub id: Uuid,
    pub user_id: Uuid,
    /// Stable per-account key, derived from Google's immutable account id;
    /// the vault-path segment.
    pub provider_key: Uuid,
    pub account_email: Option<String>,
    pub token_expires_at: Option<DateTime<Utc>>,
    pub scope: Option<String>,
    pub is_active: bool,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

/// The connect flow for Google Calendar (add events).
pub struct GoogleCalendarWriteService {
    db_pool: Pool<Postgres>,
    client_id: Option<String>,
    client_secret: Option<String>,
    redirect_uri: String,
    credentials_service: Option<Arc<OAuthCredentialService>>,
    token_url: String,
    userinfo_url: String,
}

/// Hand-written so a stray `{:?}` never prints the client secret (lint 37).
impl std::fmt::Debug for GoogleCalendarWriteService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GoogleCalendarWriteService")
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("redirect_uri", &self.redirect_uri)
            .field(
                "has_credentials_service",
                &self.credentials_service.is_some(),
            )
            .finish()
    }
}

impl GoogleCalendarWriteService {
    pub fn new(db_pool: Pool<Postgres>) -> Self {
        let (client_id, client_secret) = talos_oauth::shared_google_client();
        Self {
            db_pool,
            client_id,
            client_secret,
            // Empty is unset (a helm placeholder must not become the redirect).
            redirect_uri: std::env::var("GOOGLE_CALENDAR_WRITE_REDIRECT_URI")
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| DEFAULT_REDIRECT_URI.to_string()),
            credentials_service: None,
            token_url: TOKEN_URL.to_string(),
            userinfo_url: USERINFO_URL.to_string(),
        }
    }

    /// Attach the unified credential service. Without it a callback is
    /// refused: there is nowhere safe to put the tokens.
    pub fn with_credentials_service(mut self, svc: Arc<OAuthCredentialService>) -> Self {
        self.credentials_service = Some(svc);
        self
    }

    /// A service with the given client and endpoints. For tests, which stand
    /// a loopback server in for Google; deliberately not reachable from
    /// configuration, so a deployment cannot be pointed at another token
    /// endpoint.
    #[doc(hidden)]
    pub fn for_tests(
        db_pool: Pool<Postgres>,
        client: Option<(&str, &str)>,
        token_url: &str,
        userinfo_url: &str,
    ) -> Self {
        Self {
            db_pool,
            client_id: client.map(|(id, _)| id.to_string()),
            client_secret: client.map(|(_, secret)| secret.to_string()),
            redirect_uri: DEFAULT_REDIRECT_URI.to_string(),
            credentials_service: None,
            token_url: token_url.to_string(),
            userinfo_url: userinfo_url.to_string(),
        }
    }

    /// Whether the shared Google client is configured.
    pub fn is_configured(&self) -> bool {
        self.client_id.is_some() && self.client_secret.is_some()
    }

    /// The authorize URL for `user_id`, with the state bound to that user and
    /// to the browser `binding` belongs to. Returns `(url, state)`.
    pub async fn get_authorization_url(
        &self,
        user_id: Uuid,
        binding: &talos_oauth::BrowserBinding,
    ) -> Result<(String, String)> {
        talos_oauth::authorization_url(&self.db_pool, self, user_id, binding).await
    }

    /// Complete the connect. The user comes from the state token, never from
    /// a session; the state is consumed before the code is exchanged.
    pub async fn handle_callback(
        &self,
        code: String,
        state: String,
        presented_binding: Option<&str>,
    ) -> Result<GoogleCalendarWriteIntegration> {
        talos_oauth::handle_oauth_callback(&self.db_pool, self, &code, &state, presented_binding)
            .await
    }

    /// Insert the account's row, or bring a disconnected one back.
    ///
    /// `updated_at` is left to the table's trigger.
    async fn upsert_integration(
        &self,
        user_id: Uuid,
        provider_key: Uuid,
        account_email: Option<&str>,
        token_expires_at: DateTime<Utc>,
        scope: &str,
    ) -> Result<GoogleCalendarWriteIntegration> {
        sqlx::query_as::<_, GoogleCalendarWriteIntegration>(
            r#"
            INSERT INTO google_calendar_write_integrations (
                user_id, provider_key, account_email, token_expires_at, scope
            )
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (user_id, provider_key)
            DO UPDATE SET
                account_email = EXCLUDED.account_email,
                token_expires_at = EXCLUDED.token_expires_at,
                scope = EXCLUDED.scope,
                is_active = TRUE
            RETURNING id, user_id, provider_key, account_email, token_expires_at, scope,
                      is_active, created_at, updated_at
            "#,
        )
        .bind(user_id)
        .bind(provider_key)
        .bind(account_email)
        .bind(token_expires_at)
        .bind(scope)
        .fetch_one(&self.db_pool)
        .await
        .context("Failed to upsert Google Calendar (add events) integration")
    }
}

/// The stable per-account key: `Uuid::from_bytes(Sha256(google_account_id)[..16])`,
/// the derivation the other Google integrations use, so reconnecting one
/// account updates its row instead of adding a second.
pub fn derive_provider_key(google_account_id: &str) -> Uuid {
    // allow-adhoc-node-uuid: this is the GOOGLE-ACCOUNT-id derivation, not the
    // graph-node-id one. It shares the arithmetic by coincidence, keys a
    // different column (`provider_key`), and must stay pinned to Google's
    // account id.
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(google_account_id.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    Uuid::from_bytes(bytes)
}

#[async_trait::async_trait]
impl talos_oauth::OAuthIntegration for GoogleCalendarWriteService {
    type Connected = GoogleCalendarWriteIntegration;

    fn provider(&self) -> &'static str {
        PROVIDER
    }

    fn authorize_request(&self) -> Result<talos_oauth::AuthorizeRequest<'static>> {
        Ok(talos_oauth::AuthorizeRequest {
            provider: PROVIDER,
            auth_url: AUTH_URL,
            token_url: TOKEN_URL,
            client_id: self
                .client_id
                .clone()
                .ok_or_else(|| anyhow!("GOOGLE_CLIENT_ID is not set"))?,
            client_secret: self
                .client_secret
                .clone()
                .ok_or_else(|| anyhow!("GOOGLE_CLIENT_SECRET is not set"))?,
            redirect_uri: self.redirect_uri.clone(),
            scopes: SCOPES,
            // Offline access for a refresh token; forced consent so one is
            // issued on a reconnect too.
            extra_params: &[("access_type", "offline"), ("prompt", "consent")],
        })
    }

    async fn complete_callback(
        &self,
        _pool: &sqlx::PgPool,
        code: &str,
        consumed: talos_oauth::ConsumedOAuthState,
    ) -> Result<GoogleCalendarWriteIntegration> {
        // The user is the one the state was minted for. The state has already
        // been consumed and its browser binding checked by the shared driver.
        let user_id = consumed.user_id;
        let cred_svc = self.credentials_service.as_ref().ok_or_else(|| {
            anyhow!("Credential service not configured — cannot store Google Calendar (add events) tokens")
        })?;
        let client_id = self
            .client_id
            .clone()
            .ok_or_else(|| anyhow!("GOOGLE_CLIENT_ID is not set"))?;
        let client_secret = self
            .client_secret
            .clone()
            .ok_or_else(|| anyhow!("GOOGLE_CLIENT_SECRET is not set"))?;

        // ---- 1. Exchange the code ----------------------------------------
        let mut form = vec![
            ("grant_type", "authorization_code".to_string()),
            ("code", code.to_string()),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("redirect_uri", self.redirect_uri.clone()),
        ];
        if let Some(verifier) = consumed.pkce_verifier {
            form.push(("code_verifier", verifier));
        }
        let resp = HTTP
            .post(&self.token_url)
            .form(&form)
            .send()
            .await
            .context("Failed to reach Google token endpoint")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = talos_http_body::read_error_text_capped(resp).await;
            let preview = talos_text_util::truncate_at_char_boundary(&body, 500);
            tracing::error!(
                status = %status,
                body_len = body.len(),
                body_preview = %talos_dlp_provider::redact_str(preview),
                "Google Calendar (add events) token exchange failed"
            );
            return Err(anyhow!(
                "Google Calendar (add events) token exchange failed (HTTP {status})"
            ));
        }

        #[derive(serde::Deserialize)]
        struct TokenResponse {
            access_token: String,
            refresh_token: Option<String>,
            expires_in: Option<u64>,
            scope: Option<String>,
        }
        let tokens: TokenResponse = talos_http_body::read_json_capped(resp)
            .await
            .context("Failed to parse Google token response")?;
        // Without a refresh token the connection would die in an hour and
        // look healthy until then.
        let refresh_token = tokens
            .refresh_token
            .filter(|t| !t.is_empty())
            .ok_or_else(|| {
                anyhow!(
                    "Google did not return a refresh_token — reconnect and grant offline access"
                )
            })?;
        let granted = tokens.scope.unwrap_or_default();
        // The owner can untick a scope on the consent screen. A connection
        // that cannot add an event is refused here, where it can be said,
        // rather than stored and discovered as a 403 at the first tap.
        //
        // The grant just issued is NOT revoked on this or the refusals below.
        // A Google revoke ends the account's whole grant to the OAuth client
        // (tested live 2026-10-02 — see `talos_oauth::google_grant`), which
        // would end its Gmail and Calendar connections too. The tokens are
        // dropped, unstored, and the owner can remove the grant at Google.
        if !granted_write_scope(&granted) {
            return Err(anyhow!(ConnectRefusal::NoWriteScope));
        }
        let token_expires_at = talos_oauth::oauth_expires_at(tokens.expires_in);

        // ---- 2. Which account is this -----------------------------------
        let resp = HTTP
            .get(&self.userinfo_url)
            .bearer_auth(&tokens.access_token)
            .send()
            .await
            .context("Google userinfo request failed")?;
        if !resp.status().is_success() {
            return Err(anyhow!(
                "Google userinfo request failed (HTTP {})",
                resp.status()
            ));
        }
        #[derive(serde::Deserialize)]
        struct UserInfo {
            id: String,
            email: Option<String>,
        }
        let userinfo: UserInfo = talos_http_body::read_json_capped(resp)
            .await
            .context("Failed to parse Google userinfo response")?;
        if userinfo.id.trim().is_empty() {
            return Err(anyhow!("Google userinfo carried no account id"));
        }
        let provider_key = derive_provider_key(&userinfo.id);

        // ---- 3. The row, then the tokens -----------------------------------
        // A token with no row would be refreshed every hour with no card to
        // disconnect it from. So the row is written first; if the tokens then
        // cannot be stored, the row is hidden again. (A row with no token
        // behind it needs both this store AND that compensation to fail, and
        // shows itself at the first read.)
        let integration = self
            .upsert_integration(
                user_id,
                provider_key,
                userinfo.email.as_deref(),
                token_expires_at,
                &granted,
            )
            .await?;
        if let Err(e) = cred_svc
            .store_credentials(
                user_id,
                PROVIDER,
                &provider_key.to_string(),
                &tokens.access_token,
                Some(refresh_token.as_str()),
                token_expires_at,
                &granted,
                vec![],
            )
            .await
        {
            if let Err(hide) = sqlx::query(
                "UPDATE google_calendar_write_integrations SET is_active = FALSE WHERE id = $1 AND user_id = $2",
            )
            .bind(integration.id)
            .bind(user_id)
            .execute(&self.db_pool)
            .await
            {
                tracing::error!(
                    integration_id = %integration.id,
                    error = %hide,
                    "Google Calendar (add events) tokens could not be stored and the connection row could not be hidden again"
                );
            }
            return Err(e.context("Failed to store Google Calendar (add events) credentials"));
        }

        // A grant to write to a calendar is worth a line an operator can
        // find. The account address is not logged.
        tracing::info!(
            target: "talos_audit",
            event_kind = "google_calendar_write_connected",
            user_id = %user_id,
            integration_id = %integration.id,
            "Google Calendar (add events) connected"
        );
        Ok(integration)
    }
}

/// Why a callback that reached Google and got tokens is still refused.
#[derive(Debug, PartialEq, Eq)]
pub enum ConnectRefusal {
    /// The consent was completed with the calendar scope unticked.
    NoWriteScope,
}
impl std::fmt::Display for ConnectRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoWriteScope => f.write_str("the consent did not grant the calendar scope"),
        }
    }
}
impl std::error::Error for ConnectRefusal {}

/// Whether `granted` (Google returns the granted scopes space-separated)
/// holds the scope this connection exists for. A broader calendar scope is
/// NOT accepted in its place: this crate asks for one scope, and a grant that
/// names another is not the grant it asked for.
fn granted_write_scope(granted: &str) -> bool {
    granted.split([' ', ',']).any(|scope| scope == WRITE_SCOPE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use talos_oauth::OAuthIntegration;

    fn service(client: Option<(&str, &str)>) -> GoogleCalendarWriteService {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused@127.0.0.1:1/unused")
            .expect("lazy pool");
        GoogleCalendarWriteService::for_tests(pool, client, TOKEN_URL, USERINFO_URL)
    }

    #[tokio::test]
    async fn the_consent_asks_for_one_narrow_write_scope_under_its_own_provider() {
        let svc = service(Some(("client-id", "client-secret")));
        let req = svc.authorize_request().expect("configured");
        // Its own provider string: the vault namespace the read connection's
        // grants cannot name.
        assert_eq!(
            (req.provider, svc.provider()),
            ("google_calendar_write", "google_calendar_write")
        );
        assert_ne!(req.provider, "google_calendar");
        assert_eq!(req.auth_url, "https://accounts.google.com/o/oauth2/v2/auth");
        assert_eq!(req.token_url, "https://oauth2.googleapis.com/token");
        assert_eq!(
            req.redirect_uri,
            "http://localhost:8000/api/google-calendar-write/callback"
        );
        // Exactly one calendar scope, and it is the owned-events one: not
        // every calendar the account can see, and not calendar management.
        let calendar: Vec<&&str> = req
            .scopes
            .iter()
            .filter(|s| s.contains("/auth/calendar"))
            .collect();
        assert_eq!(
            calendar,
            vec![&"https://www.googleapis.com/auth/calendar.events.owned"]
        );
        for scope in req.scopes {
            assert!(
                *scope == WRITE_SCOPE
                    || *scope == "openid"
                    || scope.ends_with("/auth/userinfo.email"),
                "{scope}"
            );
        }
        assert!(
            req.extra_params.contains(&("access_type", "offline"))
                && req.extra_params.contains(&("prompt", "consent"))
        );
    }

    #[tokio::test]
    async fn an_unconfigured_client_cannot_start_a_connect() {
        let svc = service(None);
        assert!(!svc.is_configured());
        assert!(svc.authorize_request().is_err());
        assert!(service(Some(("id", "secret"))).is_configured());
    }

    #[tokio::test]
    async fn the_client_secret_is_not_in_debug_output() {
        let shown = format!("{:?}", service(Some(("client-id", "s3cr3t-value"))));
        assert!(
            shown.contains("[REDACTED]") && !shown.contains("s3cr3t-value"),
            "{shown}"
        );
    }

    #[test]
    fn a_consent_without_the_calendar_scope_is_told_apart() {
        assert!(granted_write_scope(&SCOPES.join(" ")));
        assert!(granted_write_scope(
            "openid https://www.googleapis.com/auth/calendar.events.owned"
        ));
        assert!(!granted_write_scope(
            "openid https://www.googleapis.com/auth/userinfo.email"
        ));
        assert!(!granted_write_scope(""));
        // Neither a read scope nor a broader write scope stands in for it,
        // and a scope that merely starts with it is a different scope.
        for other in [
            "https://www.googleapis.com/auth/calendar.events.owned.readonly",
            "https://www.googleapis.com/auth/calendar.events",
            "https://www.googleapis.com/auth/calendar",
            "https://www.googleapis.com/auth/calendar.readonly",
        ] {
            assert!(!granted_write_scope(other), "{other}");
        }
    }

    #[test]
    fn one_account_always_gets_the_same_key() {
        assert_eq!(
            derive_provider_key("1234567890"),
            derive_provider_key("1234567890")
        );
        assert_ne!(
            derive_provider_key("1234567890"),
            derive_provider_key("1234567891")
        );
    }
}
