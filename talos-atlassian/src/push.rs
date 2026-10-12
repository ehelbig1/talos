//! Jira (Atlassian Cloud) dynamic webhooks: registering one for a connection,
//! keeping it alive, binding the workflow a delivery starts, and listing what
//! exists.
//!
//! The receiver is in [`crate::push_receiver`]; the refresh loop in
//! [`crate::push_scheduler`]. Setup and constraints: `docs/jira-push-setup.md`.
//!
//! # Whose webhook is it
//!
//! Atlassian allows one webhook URL per app, so the URL cannot say whose a
//! delivery is. A registration row does: it is created for one of the
//! caller's OWN connections (`atlassian_integrations` read with
//! `user_id = $caller`), it records Atlassian's webhook id, and the receiver
//! maps a delivery to its owner through that id and nothing the request
//! supplies. Every function here that takes a `user_id` names it in its SQL.
//!
//! # What is asked of Atlassian
//!
//! `POST|PUT|DELETE|GET https://api.atlassian.com/ex/jira/{cloudId}/rest/api/3/webhook`
//! with the connection's own OAuth token (scopes `read:jira-work` and
//! `manage:jira-webhook`). A webhook expires 30 days after it is created or
//! refreshed.

use chrono::{DateTime, Utc};
use serde::Deserialize;
use talos_integration_helpers::audit::{
    insert_channel_audit, truncate_and_redact_error, ChannelAuditEvent,
};
use talos_push_channel_inventory::{
    BindWorkflowRefusal, ModuleBinding, ProvisionRefusal, ProvisionRefusalKind, ProvisionedChannel,
    PushChannelFailure, PushChannelInventory, PushChannelProvisioner, PushChannelRow,
};
use uuid::Uuid;

use crate::integration::{AtlassianIntegrationService, REFRESH_HTTP_CLIENT};

/// The name this integration's channels are listed and bound under.
pub const INTEGRATION_NAME: &str = "atlassian";

/// The one path Atlassian delivers to. The receiver's route and the URL a
/// registration names are both built from it.
pub const WEBHOOK_PATH: &str = "/api/atlassian/webhook";

/// The address Atlassian is told to deliver to, when it is not the
/// deployment's general public address. Atlassian requires the webhook URL to
/// share the base URL the app is registered with.
pub const WEBHOOK_BASE_URL_ENV: &str = "ATLASSIAN_WEBHOOK_BASE_URL";

/// The scope a connection must hold before a webhook can be registered.
pub const WEBHOOK_SCOPE: &str = "manage:jira-webhook";

/// A webhook's lifetime at Atlassian, from its creation or its last refresh.
pub const WEBHOOK_LIFETIME_DAYS: i64 = 30;

/// A registration is refreshed once it is within this many days of expiring:
/// twenty days of hourly attempts before a webhook is lost.
pub const REFRESH_WINDOW_DAYS: i32 = 10;

/// A registration whose webhook expired this many days ago is no longer
/// refreshed: Atlassian has deleted the webhook, so every further attempt is
/// the same failure, hourly, forever. The channel stays listed, marked as
/// expired, until its owner deletes it and creates it again.
pub const GIVE_UP_AFTER_EXPIRY_DAYS: i32 = 7;

/// What `list_push_channels` says about a registration whose webhook has
/// expired and has no refresh failure of its own recorded (the controller was
/// not running while it could still have been refreshed).
pub const EXPIRED_WEBHOOK_MESSAGE: &str =
    "the webhook expired at Atlassian; delete this channel and create it again";

/// How long a handled delivery id is remembered. Atlassian retries a delivery
/// at most five times, in minutes; a week is far past any retry.
pub const DELIVERY_RETENTION_DAYS: i32 = 7;

/// The Jira events a registration asks for, and the fields whose change
/// counts as an update. The workflow re-reads Jira, so this only decides how
/// often it is woken.
const WEBHOOK_EVENTS: [&str; 2] = ["jira:issue_created", "jira:issue_updated"];
const WEBHOOK_FIELD_IDS: [&str; 4] = ["status", "assignee", "priority", "duedate"];

/// One registered webhook, as stored. No token, no ticket content.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct JiraPushRegistration {
    pub id: Uuid,
    pub user_id: Uuid,
    pub cloud_id: String,
    pub webhook_id: i64,
    pub url: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub workflow_id: Option<Uuid>,
    pub last_delivery_at: Option<DateTime<Utc>>,
    pub refresh_failed_at: Option<DateTime<Utc>>,
    pub refresh_error: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// How a call to Atlassian failed. The KIND is kept, because what to do next
/// depends on it: a refused credential needs a reconnect, a blip needs
/// another attempt, a refused request needs a different request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamFailure {
    /// The request never got an answer (connect failure, timeout).
    Unreachable { timed_out: bool },
    /// 401 or 403: the token, or a scope it lacks.
    Unauthorized { status: u16 },
    /// 429.
    RateLimited,
    /// 5xx, or one of the statuses Atlassian itself treats as retryable.
    Server { status: u16 },
    /// Any other non-2xx: the request is wrong and repeating it will not help.
    Refused { status: u16 },
    /// 2xx whose body said the webhook was not created.
    Rejected,
    /// 2xx whose body could not be read as what the API documents.
    Malformed,
}

impl UpstreamFailure {
    /// Classify a non-2xx status.
    #[must_use]
    pub fn from_status(status: u16) -> Self {
        match status {
            401 | 403 => Self::Unauthorized { status },
            429 => Self::RateLimited,
            408 | 409 | 425 | 500..=599 => Self::Server { status },
            _ => Self::Refused { status },
        }
    }

    /// Whether the same request may succeed later without anyone acting.
    #[must_use]
    pub fn is_transient(self) -> bool {
        matches!(
            self,
            Self::Unreachable { .. } | Self::RateLimited | Self::Server { .. }
        )
    }
}

impl std::fmt::Display for UpstreamFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable { timed_out: true } => f.write_str("request timed out"),
            Self::Unreachable { timed_out: false } => f.write_str("request could not be sent"),
            Self::Unauthorized { status } => write!(f, "HTTP {status} unauthorized"),
            Self::RateLimited => f.write_str("HTTP 429 rate limited"),
            Self::Server { status } => write!(f, "HTTP {status} server error"),
            Self::Refused { status } => write!(f, "HTTP {status} request refused"),
            Self::Rejected => f.write_str("the webhook was not accepted"),
            Self::Malformed => f.write_str("the response could not be read"),
        }
    }
}

/// Why a connection cannot register a webhook until it is connected again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconnectReason {
    /// The connection predates the `manage:jira-webhook` request.
    MissingWebhookScope,
    /// No Jira account id was recorded at connect time (or it is not one).
    MissingAccountId,
    /// The stored token could not be read or refreshed.
    CredentialUnavailable,
}

/// Why a registration call did not do what was asked.
#[derive(Debug, thiserror::Error)]
pub enum JiraPushError {
    #[error("Atlassian OAuth is not configured")]
    NotConfigured,
    #[error("the webhook address is not usable: {0}")]
    WebhookUrlNotUsable(&'static str),
    #[error("no such Jira connection for this user")]
    ConnectionNotFound,
    #[error("more than one Jira connection; a cloud_id is needed")]
    ConnectionAmbiguous,
    #[error("the Jira connection must be reconnected ({0:?})")]
    NeedsReconnect(ReconnectReason),
    #[error("no such Jira push channel for this user")]
    RegistrationNotFound,
    #[error("the webhook no longer exists at Atlassian")]
    WebhookGone,
    #[error("Jira webhook {what}: {failure}")]
    Upstream {
        what: &'static str,
        failure: UpstreamFailure,
    },
    #[error("database: {0}")]
    Database(#[from] sqlx::Error),
}

impl JiraPushError {
    /// What the caller is told. Names what to do; never an upstream body, a
    /// token, a query or another user's existence.
    #[must_use]
    pub fn user_facing_message(&self) -> String {
        match self {
            Self::NotConfigured => "Jira is not configured on this deployment \
                 (ATLASSIAN_CLIENT_ID, ATLASSIAN_CLIENT_SECRET and ATLASSIAN_REDIRECT_URI)."
                .to_string(),
            Self::WebhookUrlNotUsable(reason) => format!(
                "Jira cannot deliver to this deployment's address ({reason}). Set \
                 {WEBHOOK_BASE_URL_ENV} to the https:// address this deployment is reached at \
                 from the internet (the same base address as the Atlassian app's callback URL), \
                 restart the controller, and try again."
            ),
            Self::ConnectionNotFound => "No such Jira connection.".to_string(),
            Self::ConnectionAmbiguous => "You have more than one Jira connection. Name the site \
                 to watch with cloud_id."
                .to_string(),
            Self::NeedsReconnect(ReconnectReason::MissingWebhookScope) => format!(
                "This Jira connection was made before Talos asked for permission to manage \
                 webhooks ({WEBHOOK_SCOPE}). Disconnect Jira in Settings, connect it again, and \
                 try again."
            ),
            Self::NeedsReconnect(ReconnectReason::MissingAccountId) => "This Jira connection has \
                 no usable Jira account id recorded. Disconnect Jira in Settings, connect it \
                 again, and try again."
                .to_string(),
            Self::NeedsReconnect(ReconnectReason::CredentialUnavailable) => "The stored Jira \
                 credential could not be used. Disconnect Jira in Settings, connect it again, \
                 and try again."
                .to_string(),
            Self::RegistrationNotFound => {
                "No such Jira push channel. list_push_channels shows yours.".to_string()
            }
            Self::WebhookGone => "The webhook no longer exists at Atlassian. Delete this channel \
                 and create it again."
                .to_string(),
            Self::Upstream { failure, .. } => match failure {
                UpstreamFailure::Unauthorized { .. } => format!(
                    "Jira refused this connection's credentials or it lacks {WEBHOOK_SCOPE}. \
                     Check that the scope is enabled on the Atlassian app, then disconnect and \
                     connect Jira again."
                ),
                f if f.is_transient() => format!("Jira did not answer ({f}). Try again."),
                f => format!("Jira did not accept the request ({f})."),
            },
            Self::Database(_) => "The request could not be completed. Try again.".to_string(),
        }
    }

    /// The protocol-level kind a tool reports this as.
    #[must_use]
    pub fn refusal_kind(&self) -> ProvisionRefusalKind {
        match self {
            Self::ConnectionNotFound | Self::RegistrationNotFound => ProvisionRefusalKind::NotFound,
            Self::Database(_) => ProvisionRefusalKind::Unavailable,
            Self::Upstream { failure, .. } if failure.is_transient() => {
                ProvisionRefusalKind::Unavailable
            }
            _ => ProvisionRefusalKind::Refused,
        }
    }
}

impl From<JiraPushError> for ProvisionRefusal {
    fn from(e: JiraPushError) -> Self {
        Self::new(e.refusal_kind(), e.user_facing_message())
    }
}

/// The webhook URL built from a public base address, or why that address
/// cannot receive a delivery. Pure.
///
/// Atlassian delivers over the internet to an `https://` URL, so a plain-http
/// or loopback address is refused HERE, before an API call is spent on a
/// registration that could never be delivered to.
pub fn webhook_url_from_base(base: &str) -> Result<String, JiraPushError> {
    let base = base.trim().trim_end_matches('/');
    if !talos_config::is_valid_frontend_url(base) {
        return Err(JiraPushError::WebhookUrlNotUsable(
            "it is not a scheme and host with no path",
        ));
    }
    let Some(authority) = base.strip_prefix("https://") else {
        return Err(JiraPushError::WebhookUrlNotUsable("it is not https://"));
    };
    let host = if let Some(rest) = authority.strip_prefix('[') {
        rest.split(']').next().unwrap_or_default()
    } else {
        authority.split(':').next().unwrap_or_default()
    }
    .to_ascii_lowercase();
    let loopback = host == "localhost"
        || host.ends_with(".localhost")
        || host == "0.0.0.0"
        || host == "::1"
        || host == "::"
        || host.starts_with("127.");
    if host.is_empty() || loopback {
        return Err(JiraPushError::WebhookUrlNotUsable(
            "it is this machine's own address",
        ));
    }
    Ok(format!("{base}{WEBHOOK_PATH}"))
}

/// A Jira account id as it may be written into a JQL string: Atlassian's are
/// letters, digits, `:`, `-` and `_`. Anything else is refused rather than
/// escaped.
#[must_use]
pub fn account_id_is_plain(account_id: &str) -> bool {
    !account_id.is_empty()
        && account_id.len() <= 128
        && account_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'-' | b'_'))
}

/// A cloud id as it may be written into a request path: Atlassian's are
/// UUIDs. Anything that is not letters, digits and `-` is refused.
#[must_use]
pub fn cloud_id_is_plain(cloud_id: &str) -> bool {
    !cloud_id.is_empty()
        && cloud_id.len() <= 64
        && cloud_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// The registration request for one user's issues on one site.
///
/// `jqlFilter` supports only a handful of clauses; `assignee = "<account id>"`
/// is one of them. The account id has been checked by
/// [`account_id_is_plain`], so it cannot close the string it is written into.
#[must_use]
pub fn registration_body(webhook_url: &str, account_id: &str) -> serde_json::Value {
    serde_json::json!({
        "url": webhook_url,
        "webhooks": [{
            "events": WEBHOOK_EVENTS,
            "jqlFilter": format!("assignee = \"{account_id}\""),
            "fieldIdsFilter": WEBHOOK_FIELD_IDS,
        }],
    })
}

/// Atlassian's `expirationDate`, which the API description types as an
/// integer and the examples show as a date string. Both are accepted; a
/// number is epoch milliseconds when it is too large to be seconds.
#[must_use]
pub fn parse_expiration(value: &serde_json::Value) -> Option<DateTime<Utc>> {
    match value {
        serde_json::Value::Number(n) => {
            let raw = n.as_i64()?;
            if raw <= 0 {
                return None;
            }
            if raw >= 100_000_000_000 {
                DateTime::<Utc>::from_timestamp_millis(raw)
            } else {
                DateTime::<Utc>::from_timestamp(raw, 0)
            }
        }
        serde_json::Value::String(s) => {
            let s = s.trim();
            DateTime::parse_from_rfc3339(s)
                .or_else(|_| DateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f%z"))
                .ok()
                .map(|d| d.with_timezone(&Utc))
        }
        _ => None,
    }
}

#[derive(Deserialize)]
struct RegisterResponse {
    #[serde(rename = "webhookRegistrationResult", default)]
    results: Vec<RegisterResult>,
}

#[derive(Deserialize)]
struct RegisterResult {
    #[serde(rename = "createdWebhookId", default)]
    created_webhook_id: Option<i64>,
    #[serde(default)]
    errors: Vec<String>,
}

#[derive(Deserialize)]
struct RefreshResponse {
    #[serde(rename = "expirationDate", default)]
    expiration_date: serde_json::Value,
}

#[derive(Deserialize)]
struct WebhookPage {
    #[serde(default)]
    values: Vec<WebhookEntry>,
    #[serde(rename = "isLast", default)]
    is_last: Option<bool>,
}

#[derive(Deserialize)]
struct WebhookEntry {
    id: i64,
    #[serde(rename = "expirationDate", default)]
    expiration_date: serde_json::Value,
}

/// Whether Atlassian still lists a webhook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemotePresence {
    Present(Option<DateTime<Utc>>),
    Absent,
    /// The listing did not answer, or was longer than is read.
    Unknown,
}

/// A connection as registration needs it: only the caller's own rows are
/// ever loaded into one.
#[derive(sqlx::FromRow)]
struct Connection {
    cloud_id: String,
    scope: Option<String>,
    account_id: Option<String>,
}

/// Pages of the webhook listing read when confirming a refresh. An app may
/// hold 5 webhooks per user per site, so one page is the whole list; the cap
/// only bounds a listing that is not what the documentation describes.
const MAX_LIST_PAGES: usize = 5;
const LIST_PAGE_SIZE: usize = 100;

impl AtlassianIntegrationService {
    /// The public base address a registration's URL is built from:
    /// `ATLASSIAN_WEBHOOK_BASE_URL` when set (used as given, and refused if
    /// it is not usable; it is never silently replaced), otherwise the
    /// deployment's public address.
    fn webhook_base(&self) -> String {
        if let Some(base) = self.webhook_base_url.get() {
            return base.clone();
        }
        std::env::var(WEBHOOK_BASE_URL_ENV)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| talos_public_url::public_base_url_or(talos_config::get_base_url))
    }

    /// The URL Atlassian is told to deliver to, or why it cannot be one.
    pub fn webhook_url(&self) -> Result<String, JiraPushError> {
        webhook_url_from_base(&self.webhook_base())
    }

    fn api_base(&self) -> &str {
        self.api_base_url
            .get()
            .map_or("https://api.atlassian.com", String::as_str)
    }

    /// One request to a site's webhook API, with the connection's own token.
    ///
    /// A 401 is answered ONCE by refreshing the token and repeating the
    /// request: the stored token is whatever the last refresh left, and
    /// Atlassian's access tokens last an hour. Anything else that is not 2xx
    /// is returned as its kind. The error body is read (bounded) only so its
    /// length can be logged; its text is not, because an error body can echo
    /// what was sent.
    async fn webhook_api(
        &self,
        user_id: Uuid,
        cloud_id: &str,
        method: reqwest::Method,
        suffix: &str,
        body: Option<&serde_json::Value>,
        what: &'static str,
    ) -> Result<reqwest::Response, JiraPushError> {
        if !cloud_id_is_plain(cloud_id) {
            return Err(JiraPushError::ConnectionNotFound);
        }
        let url = format!(
            "{}/ex/jira/{}/rest/api/3/webhook{}",
            self.api_base(),
            cloud_id,
            suffix
        );
        let mut token = self.get_access_token(user_id, cloud_id).await.map_err(|e| {
            tracing::warn!(%user_id, what, error = %e, "Jira webhook call: no usable access token");
            JiraPushError::NeedsReconnect(ReconnectReason::CredentialUnavailable)
        })?;
        let mut refreshed = false;
        loop {
            let mut request = REFRESH_HTTP_CLIENT
                .request(method.clone(), &url)
                .bearer_auth(&token)
                .header(reqwest::header::ACCEPT, "application/json");
            if let Some(body) = body {
                request = request.json(body);
            }
            let response = request.send().await.map_err(|e| {
                tracing::warn!(
                    %user_id,
                    what,
                    error = %talos_http_utils::trusted_client::error_chain(&e),
                    "Jira webhook call could not be sent"
                );
                JiraPushError::Upstream {
                    what,
                    failure: UpstreamFailure::Unreachable {
                        timed_out: e.is_timeout(),
                    },
                }
            })?;
            let status = response.status();
            if status.is_success() {
                return Ok(response);
            }
            if status.as_u16() == 401 && !refreshed {
                refreshed = true;
                if let Some(fresh) = self.force_refresh_access_token(user_id, cloud_id).await {
                    token = fresh;
                    continue;
                }
            }
            let body_len = talos_http_body::read_error_text_capped(response)
                .await
                .len();
            let failure = UpstreamFailure::from_status(status.as_u16());
            tracing::warn!(%user_id, what, %failure, body_len, "Jira webhook call refused");
            return Err(JiraPushError::Upstream { what, failure });
        }
    }

    /// Refresh the connection's token after a 401 and return the new one, or
    /// `None` when nothing new was stored (the grant is gone, the provider
    /// did not answer). Goes through the credential service's own refresh, so
    /// there is still one token-endpoint call site.
    async fn force_refresh_access_token(&self, user_id: Uuid, cloud_id: &str) -> Option<String> {
        let creds = self.credentials_service.as_ref()?;
        let path =
            talos_oauth::credentials::access_token_vault_path("atlassian", user_id, cloud_id);
        match creds.refresh_oauth_token_forced(&path).await {
            Ok(true) => creds
                .get_valid_access_token(user_id, "atlassian", cloud_id)
                .await
                .ok(),
            Ok(false) => None,
            Err(e) => {
                tracing::warn!(%user_id, error = %e, "Jira token refresh after a 401 failed");
                None
            }
        }
    }

    /// The caller's own connection to register for.
    ///
    /// THE ownership rule for a registration: the row is read with
    /// `user_id = $caller`, so a cloud id that is another user's connection
    /// is the same answer as one that does not exist.
    async fn own_connection(
        &self,
        user_id: Uuid,
        cloud_id: Option<&str>,
    ) -> Result<Connection, JiraPushError> {
        let mut rows: Vec<Connection> = match cloud_id {
            Some(cloud_id) => {
                sqlx::query_as(
                    "SELECT cloud_id, scope, account_id FROM atlassian_integrations \
                     WHERE user_id = $1 AND cloud_id = $2 AND is_active = true",
                )
                .bind(user_id)
                .bind(cloud_id)
                .fetch_all(&self.db_pool)
                .await?
            }
            None => {
                sqlx::query_as(
                    "SELECT cloud_id, scope, account_id FROM atlassian_integrations \
                     WHERE user_id = $1 AND is_active = true ORDER BY created_at LIMIT 2",
                )
                .bind(user_id)
                .fetch_all(&self.db_pool)
                .await?
            }
        };
        match rows.len() {
            0 => Err(JiraPushError::ConnectionNotFound),
            1 => Ok(rows.remove(0)),
            _ => Err(JiraPushError::ConnectionAmbiguous),
        }
    }

    /// One of the caller's own registrations, by id.
    async fn own_registration(
        &self,
        user_id: Uuid,
        registration_id: Uuid,
    ) -> Result<JiraPushRegistration, JiraPushError> {
        sqlx::query_as(
            "SELECT id, user_id, cloud_id, webhook_id, url, expires_at, workflow_id, \
                    last_delivery_at, refresh_failed_at, refresh_error, created_at \
             FROM atlassian_webhook_registrations WHERE id = $1 AND user_id = $2",
        )
        .bind(registration_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?
        .ok_or(JiraPushError::RegistrationNotFound)
    }

    async fn registration_for_connection(
        &self,
        user_id: Uuid,
        cloud_id: &str,
    ) -> Result<Option<JiraPushRegistration>, sqlx::Error> {
        sqlx::query_as(
            "SELECT id, user_id, cloud_id, webhook_id, url, expires_at, workflow_id, \
                    last_delivery_at, refresh_failed_at, refresh_error, created_at \
             FROM atlassian_webhook_registrations WHERE user_id = $1 AND cloud_id = $2",
        )
        .bind(user_id)
        .bind(cloud_id)
        .fetch_optional(&self.db_pool)
        .await
    }

    /// Register a webhook for one of the caller's own Jira connections, or
    /// return the one it already has (`created: false`).
    ///
    /// Everything that can be refused without Atlassian is refused first: the
    /// deployment's address, the connection's ownership, its scope and its
    /// account id. The Atlassian call and the row write happen under a lock
    /// every controller replica shares, and the "is there one already?"
    /// question is asked again under it — a second registration is a second
    /// webhook, and each user may hold five per site.
    pub async fn register_push_channel(
        &self,
        user_id: Uuid,
        cloud_id: Option<&str>,
    ) -> Result<(JiraPushRegistration, bool), JiraPushError> {
        if !self.is_configured() {
            return Err(JiraPushError::NotConfigured);
        }
        let webhook_url = self.webhook_url()?;
        let connection = self.own_connection(user_id, cloud_id).await?;
        let has_scope = connection
            .scope
            .as_deref()
            .is_some_and(|granted| granted.split_whitespace().any(|s| s == WEBHOOK_SCOPE));
        if !has_scope {
            return Err(JiraPushError::NeedsReconnect(
                ReconnectReason::MissingWebhookScope,
            ));
        }
        let account_id = connection
            .account_id
            .as_deref()
            .filter(|id| account_id_is_plain(id))
            .ok_or(JiraPushError::NeedsReconnect(
                ReconnectReason::MissingAccountId,
            ))?;
        let cloud_id = connection.cloud_id.as_str();

        let _guard = self
            .push_locks
            .acquire_fleet(
                &self.db_pool,
                (user_id, cloud_id.to_string()),
                &format!("atlassian-push:{user_id}:{cloud_id}"),
            )
            .await?;
        if let Some(existing) = self.registration_for_connection(user_id, cloud_id).await? {
            return Ok((existing, false));
        }

        let response = self
            .webhook_api(
                user_id,
                cloud_id,
                reqwest::Method::POST,
                "",
                Some(&registration_body(&webhook_url, account_id)),
                "register",
            )
            .await?;
        let parsed: RegisterResponse =
            talos_http_body::read_json_capped(response)
                .await
                .map_err(|_| JiraPushError::Upstream {
                    what: "register",
                    failure: UpstreamFailure::Malformed,
                })?;
        let Some(result) = parsed.results.into_iter().next() else {
            return Err(JiraPushError::Upstream {
                what: "register",
                failure: UpstreamFailure::Malformed,
            });
        };
        let Some(webhook_id) = result.created_webhook_id else {
            // Atlassian's reasons are about the request Talos built (the
            // filter, the address, the limit of five). They go to the log,
            // scrubbed; the caller is told the webhook was not accepted.
            tracing::warn!(
                %user_id,
                errors = result.errors.len(),
                first = %truncate_and_redact_error(result.errors.first().map_or("", String::as_str)),
                "Jira did not create the webhook"
            );
            return Err(JiraPushError::Upstream {
                what: "register",
                failure: UpstreamFailure::Rejected,
            });
        };

        let expires_at = Utc::now() + chrono::Duration::days(WEBHOOK_LIFETIME_DAYS);
        let inserted: Result<JiraPushRegistration, sqlx::Error> = sqlx::query_as(
            "INSERT INTO atlassian_webhook_registrations \
                 (user_id, cloud_id, webhook_id, url, expires_at) \
             VALUES ($1, $2, $3, $4, $5) \
             RETURNING id, user_id, cloud_id, webhook_id, url, expires_at, workflow_id, \
                       last_delivery_at, refresh_failed_at, refresh_error, created_at",
        )
        .bind(user_id)
        .bind(cloud_id)
        .bind(webhook_id)
        .bind(&webhook_url)
        .bind(expires_at)
        .fetch_one(&self.db_pool)
        .await;
        let registration = match inserted {
            Ok(row) => row,
            Err(e) => {
                // A webhook nothing here records would deliver for thirty days
                // to a receiver that maps it to nobody. Take it back.
                let undone = self
                    .delete_remote_webhook(user_id, cloud_id, webhook_id)
                    .await;
                tracing::error!(
                    %user_id,
                    webhook_id,
                    removed_at_atlassian = undone.is_ok(),
                    error = %e,
                    "Jira webhook was created but could not be recorded"
                );
                return Err(JiraPushError::Database(e));
            }
        };

        self.audit(
            &registration,
            "jira_webhook_registered",
            true,
            None,
            serde_json::json!({}),
        )
        .await;
        tracing::info!(
            %user_id,
            registration = %registration.id,
            webhook_id,
            "Jira webhook registered"
        );
        Ok((registration, true))
    }

    async fn delete_remote_webhook(
        &self,
        user_id: Uuid,
        cloud_id: &str,
        webhook_id: i64,
    ) -> Result<(), JiraPushError> {
        self.webhook_api(
            user_id,
            cloud_id,
            reqwest::Method::DELETE,
            "",
            Some(&serde_json::json!({ "webhookIds": [webhook_id] })),
            "delete",
        )
        .await
        .map(|_| ())
    }

    /// Delete one of the caller's own registrations: at Atlassian (best
    /// effort) and here. Returns whether Atlassian confirmed the delete; a
    /// webhook that could not be deleted there expires on its own, and its
    /// deliveries match no row.
    pub async fn delete_push_channel(
        &self,
        user_id: Uuid,
        registration_id: Uuid,
    ) -> Result<bool, JiraPushError> {
        let registration = self.own_registration(user_id, registration_id).await?;
        let removed_remotely = self.remove_registration(&registration).await?;
        Ok(removed_remotely)
    }

    /// Delete every registration of one connection. Called when the
    /// connection is disconnected, BEFORE its token is removed from the
    /// vault: the delete at Atlassian needs that token.
    pub async fn remove_push_registrations_for_connection(
        &self,
        user_id: Uuid,
        cloud_id: &str,
    ) -> Result<usize, JiraPushError> {
        let rows: Vec<JiraPushRegistration> = sqlx::query_as(
            "SELECT id, user_id, cloud_id, webhook_id, url, expires_at, workflow_id, \
                    last_delivery_at, refresh_failed_at, refresh_error, created_at \
             FROM atlassian_webhook_registrations WHERE user_id = $1 AND cloud_id = $2",
        )
        .bind(user_id)
        .bind(cloud_id)
        .fetch_all(&self.db_pool)
        .await?;
        for registration in &rows {
            self.remove_registration(registration).await?;
        }
        Ok(rows.len())
    }

    async fn remove_registration(
        &self,
        registration: &JiraPushRegistration,
    ) -> Result<bool, JiraPushError> {
        let remote = self
            .delete_remote_webhook(
                registration.user_id,
                &registration.cloud_id,
                registration.webhook_id,
            )
            .await;
        if let Err(e) = &remote {
            tracing::warn!(
                user_id = %registration.user_id,
                registration = %registration.id,
                webhook_id = registration.webhook_id,
                error = %e,
                "Jira webhook could not be deleted at Atlassian; removing it here anyway \
                 (it expires there on its own)"
            );
        }
        sqlx::query("DELETE FROM atlassian_webhook_registrations WHERE id = $1 AND user_id = $2")
            .bind(registration.id)
            .bind(registration.user_id)
            .execute(&self.db_pool)
            .await?;
        self.audit(
            registration,
            "jira_webhook_deleted",
            true,
            None,
            serde_json::json!({ "removed_at_atlassian": remote.is_ok() }),
        )
        .await;
        Ok(remote.is_ok())
    }

    /// Whether Atlassian still lists `webhook_id` for this connection.
    async fn remote_presence(
        &self,
        user_id: Uuid,
        cloud_id: &str,
        webhook_id: i64,
    ) -> RemotePresence {
        for page in 0..MAX_LIST_PAGES {
            let suffix = format!(
                "?startAt={}&maxResults={}",
                page * LIST_PAGE_SIZE,
                LIST_PAGE_SIZE
            );
            let Ok(response) = self
                .webhook_api(
                    user_id,
                    cloud_id,
                    reqwest::Method::GET,
                    &suffix,
                    None,
                    "list",
                )
                .await
            else {
                return RemotePresence::Unknown;
            };
            let Ok(listing) = talos_http_body::read_json_capped::<WebhookPage>(response).await
            else {
                return RemotePresence::Unknown;
            };
            if let Some(entry) = listing.values.iter().find(|w| w.id == webhook_id) {
                return RemotePresence::Present(parse_expiration(&entry.expiration_date));
            }
            // Only an explicit last page is the end of the list. A page that
            // says nothing about being last is not evidence of absence.
            match listing.is_last {
                Some(true) => return RemotePresence::Absent,
                _ if listing.values.is_empty() => return RemotePresence::Unknown,
                _ => {}
            }
        }
        RemotePresence::Unknown
    }

    /// Refresh one of the caller's own registrations and record the outcome
    /// on its row: the new expiry on success, the failure (scrubbed) when it
    /// could not be refreshed. Both are also written to the shared audit log.
    ///
    /// Atlassian's refresh ignores a webhook id it does not know, so a refresh
    /// that "succeeds" says nothing about a webhook that has already expired
    /// or been deleted. The listing is therefore read afterwards, and a
    /// webhook Atlassian no longer lists is a FAILURE, said in words the
    /// owner can act on. A listing that cannot be read is not evidence either
    /// way and leaves the refresh's own answer standing.
    pub async fn refresh_push_channel(
        &self,
        user_id: Uuid,
        registration_id: Uuid,
    ) -> Result<DateTime<Utc>, JiraPushError> {
        let registration = self.own_registration(user_id, registration_id).await?;
        match self.refresh_at_atlassian(&registration).await {
            Ok(expires_at) => {
                sqlx::query(
                    "UPDATE atlassian_webhook_registrations \
                     SET expires_at = $3, refresh_failed_at = NULL, refresh_error = NULL \
                     WHERE id = $1 AND user_id = $2",
                )
                .bind(registration.id)
                .bind(user_id)
                .bind(expires_at)
                .execute(&self.db_pool)
                .await?;
                self.audit(
                    &registration,
                    "jira_webhook_refreshed",
                    true,
                    None,
                    serde_json::json!({ "expires_at": expires_at }),
                )
                .await;
                Ok(expires_at)
            }
            Err(e) => {
                let scrubbed = truncate_and_redact_error(&e.to_string());
                // The failure's own record. If THIS cannot be written the
                // caller still gets the original error, and says so loudly.
                if let Err(db) = sqlx::query(
                    "UPDATE atlassian_webhook_registrations \
                     SET refresh_failed_at = now(), refresh_error = $3 \
                     WHERE id = $1 AND user_id = $2",
                )
                .bind(registration.id)
                .bind(user_id)
                .bind(&scrubbed)
                .execute(&self.db_pool)
                .await
                {
                    tracing::error!(
                        registration = %registration.id,
                        error = %db,
                        "a failed Jira webhook refresh could not be recorded on its row"
                    );
                }
                self.audit(
                    &registration,
                    "jira_webhook_refresh_failed",
                    false,
                    Some(&scrubbed),
                    serde_json::json!({}),
                )
                .await;
                Err(e)
            }
        }
    }

    async fn refresh_at_atlassian(
        &self,
        registration: &JiraPushRegistration,
    ) -> Result<DateTime<Utc>, JiraPushError> {
        let response = self
            .webhook_api(
                registration.user_id,
                &registration.cloud_id,
                reqwest::Method::PUT,
                "/refresh",
                Some(&serde_json::json!({ "webhookIds": [registration.webhook_id] })),
                "renewal",
            )
            .await?;
        let refreshed: RefreshResponse = talos_http_body::read_json_capped(response)
            .await
            .map_err(|_| JiraPushError::Upstream {
                what: "renewal",
                failure: UpstreamFailure::Malformed,
            })?;
        let listed = match self
            .remote_presence(
                registration.user_id,
                &registration.cloud_id,
                registration.webhook_id,
            )
            .await
        {
            RemotePresence::Absent => return Err(JiraPushError::WebhookGone),
            RemotePresence::Present(expiry) => expiry,
            RemotePresence::Unknown => None,
        };
        Ok(parse_expiration(&refreshed.expiration_date)
            .or(listed)
            .unwrap_or_else(|| Utc::now() + chrono::Duration::days(WEBHOOK_LIFETIME_DAYS)))
    }

    /// Registrations that expire within [`REFRESH_WINDOW_DAYS`], with their
    /// owners, soonest first. A row with no recorded expiry is due. One that
    /// expired more than [`GIVE_UP_AFTER_EXPIRY_DAYS`] ago is not: its webhook
    /// is gone, and the inventory shows it as expired instead.
    pub async fn registrations_needing_refresh(
        &self,
    ) -> Result<Vec<JiraPushRegistration>, sqlx::Error> {
        sqlx::query_as(
            "SELECT id, user_id, cloud_id, webhook_id, url, expires_at, workflow_id, \
                    last_delivery_at, refresh_failed_at, refresh_error, created_at \
             FROM atlassian_webhook_registrations \
             WHERE expires_at IS NULL \
                OR (expires_at < now() + make_interval(days => $1::int) \
                    AND expires_at > now() - make_interval(days => $2::int)) \
             ORDER BY expires_at NULLS FIRST, id LIMIT 500",
        )
        .bind(REFRESH_WINDOW_DAYS)
        .bind(GIVE_UP_AFTER_EXPIRY_DAYS)
        .fetch_all(&self.db_pool)
        .await
    }

    /// Forget handled delivery ids older than [`DELIVERY_RETENTION_DAYS`].
    pub async fn sweep_handled_deliveries(&self) -> Result<u64, sqlx::Error> {
        sqlx::query(
            "DELETE FROM atlassian_webhook_deliveries \
             WHERE received_at < now() - make_interval(days => $1::int)",
        )
        .bind(DELIVERY_RETENTION_DAYS)
        .execute(&self.db_pool)
        .await
        .map(|done| done.rows_affected())
    }

    /// Drop idle entries from the registration lock map.
    pub fn cleanup_push_locks(&self) {
        self.push_locks.cleanup();
    }

    /// One row in the shared integration-events log. Losing it is a loss of
    /// visibility, not of correctness, so it never fails its caller.
    async fn audit(
        &self,
        registration: &JiraPushRegistration,
        event_type: &'static str,
        success: bool,
        error_message: Option<&str>,
        mut metadata: serde_json::Value,
    ) {
        if let Some(map) = metadata.as_object_mut() {
            map.insert("registration_id".into(), serde_json::json!(registration.id));
            map.insert(
                "webhook_id".into(),
                serde_json::json!(registration.webhook_id),
            );
        }
        if let Err(e) = insert_channel_audit(
            &self.db_pool,
            ChannelAuditEvent {
                integration_id: None,
                user_id: registration.user_id,
                event_type,
                target: Some(&registration.cloud_id),
                success,
                error_message,
                metadata,
            },
        )
        .await
        {
            tracing::warn!(registration = %registration.id, event_type, error = %e, "Jira webhook audit log insert failed");
        }
    }
}

/// Bind the workflow a delivery on one of the caller's own registrations
/// starts, or clear the binding (`None`).
///
/// The same two rules as a calendar channel's binding, asked in the same
/// order: the workflow must be one `user_id` owns — the read the trigger
/// itself uses, so "bindable" and "this user may start it" cannot drift, and
/// "no such workflow" and "not yours" are one answer — and the registration
/// must be the caller's, which the UPDATE's own `user_id` predicate decides.
/// A refusal changes nothing.
pub async fn bind_registration_workflow(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    registration_id: Uuid,
    workflow_id: Option<Uuid>,
) -> Result<(), BindWorkflowRefusal> {
    if let Some(workflow_id) = workflow_id {
        let repo = talos_workflow_repository::WorkflowRepository::new(pool.clone());
        match repo.get_workflow(workflow_id, user_id).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                tracing::warn!(
                    target: "talos_audit",
                    event_kind = "jira_push_workflow_binding_refused",
                    %user_id,
                    %workflow_id,
                    "refusing to bind a Jira push channel to a workflow this user does not own"
                );
                return Err(BindWorkflowRefusal::WorkflowNotBindable);
            }
            Err(e) => {
                tracing::error!(%user_id, %workflow_id, error = %e, "Jira push binding: workflow read failed");
                return Err(BindWorkflowRefusal::Unreadable);
            }
        }
    }

    let bound: Option<(String, i64)> = sqlx::query_as(
        "UPDATE atlassian_webhook_registrations SET workflow_id = $3 \
         WHERE id = $1 AND user_id = $2 RETURNING cloud_id, webhook_id",
    )
    .bind(registration_id)
    .bind(user_id)
    .bind(workflow_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        tracing::error!(%user_id, registration = %registration_id, error = %e, "Jira push binding: update failed");
        BindWorkflowRefusal::Unreadable
    })?;
    let Some((cloud_id, webhook_id)) = bound else {
        return Err(BindWorkflowRefusal::ChannelNotFound);
    };

    if let Err(e) = insert_channel_audit(
        pool,
        ChannelAuditEvent {
            integration_id: None,
            user_id,
            event_type: if workflow_id.is_some() {
                "jira_workflow_bound"
            } else {
                "jira_workflow_unbound"
            },
            target: Some(&cloud_id),
            success: true,
            error_message: None,
            metadata: serde_json::json!({
                "registration_id": registration_id,
                "webhook_id": webhook_id,
                "workflow_id": workflow_id,
            }),
        },
    )
    .await
    {
        tracing::warn!(registration = %registration_id, error = %e, "Jira workflow binding audit log insert failed");
    }
    Ok(())
}

/// The operator view of this user's Jira registrations. Holds a pool and
/// nothing else, so it can be built whether or not Atlassian is configured
/// and cannot register anything.
pub struct JiraPushChannelInventory {
    pool: sqlx::PgPool,
}

impl JiraPushChannelInventory {
    #[must_use]
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct InventoryRow {
    id: Uuid,
    cloud_id: String,
    site_label: Option<String>,
    workflow_id: Option<Uuid>,
    last_delivery_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    refresh_failed_at: Option<DateTime<Utc>>,
    refresh_error: Option<String>,
    created_at: DateTime<Utc>,
}

/// What an operator is shown as wrong with a registration, if anything: the
/// last refresh that failed, or — with none recorded — that the webhook's
/// expiry has passed. An expired webhook delivers nothing, and without this a
/// channel that expired while the controller was down would look healthy.
fn registration_failure(
    refresh_failed_at: Option<DateTime<Utc>>,
    refresh_error: Option<String>,
    expires_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Option<PushChannelFailure> {
    if let Some(failed_at) = refresh_failed_at {
        let error_message =
            refresh_error.unwrap_or_else(|| "the webhook could not be refreshed".to_string());
        return Some(PushChannelFailure {
            likely_oauth_failure: talos_integration_helpers::looks_like_oauth_failure(
                &error_message,
            ),
            error_message,
            failed_at,
        });
    }
    expires_at
        .filter(|expiry| *expiry < now)
        .map(|expiry| PushChannelFailure {
            error_message: EXPIRED_WEBHOOK_MESSAGE.to_string(),
            failed_at: expiry,
            likely_oauth_failure: false,
        })
}

#[async_trait::async_trait]
impl PushChannelInventory for JiraPushChannelInventory {
    fn integration_name(&self) -> &'static str {
        INTEGRATION_NAME
    }

    async fn list_channels(&self, user_id: Uuid) -> anyhow::Result<Vec<PushChannelRow>> {
        // The site's NAME is the label (never its URL, and never the webhook
        // address); the cloud id stands in when no name was recorded.
        let rows: Vec<InventoryRow> = sqlx::query_as(
            "SELECT r.id, r.cloud_id, NULLIF(i.display_name, '') AS site_label, r.workflow_id, \
                    r.last_delivery_at, r.expires_at, r.refresh_failed_at, r.refresh_error, \
                    r.created_at \
             FROM atlassian_webhook_registrations r \
             LEFT JOIN atlassian_integrations i \
               ON i.user_id = r.user_id AND i.cloud_id = r.cloud_id \
             WHERE r.user_id = $1 ORDER BY r.created_at, r.id LIMIT 500",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        let now = Utc::now();
        Ok(rows
            .into_iter()
            .map(|r| PushChannelRow {
                integration: INTEGRATION_NAME,
                channel_id: r.id,
                display_name: r.site_label.unwrap_or(r.cloud_id),
                // A Jira registration runs no module: a delivery only starts
                // the bound workflow.
                module_id: None,
                module_name: None,
                module_binding: ModuleBinding::None,
                workflow_id: r.workflow_id,
                created_at: Some(r.created_at),
                last_event_at: r.last_delivery_at,
                recent_failure: registration_failure(
                    r.refresh_failed_at,
                    r.refresh_error,
                    r.expires_at,
                    now,
                ),
            })
            .collect())
    }

    async fn bind_workflow(
        &self,
        user_id: Uuid,
        channel_id: Uuid,
        workflow_id: Option<Uuid>,
    ) -> Result<(), BindWorkflowRefusal> {
        bind_registration_workflow(&self.pool, user_id, channel_id, workflow_id).await
    }
}

/// Creates and deletes Jira registrations for the tools that reach them
/// through the push-channel set. Holds the integration service, so it is
/// wired only where that service is.
pub struct JiraPushProvisioner {
    service: std::sync::Arc<AtlassianIntegrationService>,
}

impl JiraPushProvisioner {
    #[must_use]
    pub fn new(service: std::sync::Arc<AtlassianIntegrationService>) -> Self {
        Self { service }
    }
}

#[async_trait::async_trait]
impl PushChannelProvisioner for JiraPushProvisioner {
    fn integration_name(&self) -> &'static str {
        INTEGRATION_NAME
    }

    async fn create_channel(
        &self,
        user_id: Uuid,
        target: Option<&str>,
    ) -> Result<ProvisionedChannel, ProvisionRefusal> {
        let (registration, created) = self
            .service
            .register_push_channel(user_id, target)
            .await
            .map_err(|e| {
                tracing::warn!(%user_id, error = %e, "Jira push channel was not created");
                ProvisionRefusal::from(e)
            })?;
        Ok(ProvisionedChannel {
            integration: INTEGRATION_NAME,
            channel_id: registration.id,
            display_name: registration.cloud_id,
            expires_at: registration.expires_at,
            created,
        })
    }

    async fn delete_channel(
        &self,
        user_id: Uuid,
        channel_id: Uuid,
    ) -> Result<(), ProvisionRefusal> {
        self.service
            .delete_push_channel(user_id, channel_id)
            .await
            .map(|_| ())
            .map_err(|e| {
                tracing::warn!(%user_id, error = %e, "Jira push channel was not deleted");
                ProvisionRefusal::from(e)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_webhook_url_is_the_one_path_on_an_https_public_address() {
        assert_eq!(
            webhook_url_from_base("https://talos.example.com").unwrap(),
            "https://talos.example.com/api/atlassian/webhook"
        );
        assert_eq!(
            webhook_url_from_base(" https://talos.example.com:8443/ ").unwrap(),
            "https://talos.example.com:8443/api/atlassian/webhook"
        );
    }

    /// Atlassian delivers over the internet to https. Each of these would be
    /// a registration that could never be delivered to, so each is refused
    /// before an API call, with a message that names the variable to set.
    #[test]
    fn an_address_atlassian_cannot_deliver_to_is_refused_and_says_what_to_set() {
        for base in [
            "http://talos.example.com",
            "http://localhost:8000",
            "https://localhost",
            "https://localhost:8000",
            "https://app.localhost",
            "https://127.0.0.1",
            "https://127.0.0.1:8000",
            "https://[::1]:8000",
            "https://0.0.0.0",
            "https://talos.example.com/prefix",
            "https://talos.example.com?x=1",
            "talos.example.com",
            "ftp://talos.example.com",
            "",
        ] {
            let err = webhook_url_from_base(base).expect_err(base);
            assert!(
                matches!(err, JiraPushError::WebhookUrlNotUsable(_)),
                "{base}: {err}"
            );
            let said = err.user_facing_message();
            assert!(said.contains(WEBHOOK_BASE_URL_ENV), "{said}");
            assert!(said.contains("https://"), "{said}");
            assert_eq!(err.refusal_kind(), ProvisionRefusalKind::Refused);
        }
    }

    #[test]
    fn only_a_plain_account_id_is_written_into_a_filter() {
        for good in [
            "5b10ac8d82e05b22cc7d4ef5",
            "557058:f58131cb-b67d-43c7-b30d-6b58d40bd077",
            "qm:example_id-1",
        ] {
            assert!(account_id_is_plain(good), "{good}");
        }
        for bad in [
            "",
            "abc\" OR project = SECRET",
            "abc def",
            "abc'",
            "abc\\",
            "abc)",
            "ünï",
            &"a".repeat(129),
        ] {
            assert!(!account_id_is_plain(bad), "{bad}");
        }
    }

    #[test]
    fn only_a_plain_cloud_id_is_written_into_a_path() {
        assert!(cloud_id_is_plain("11111111-2222-3333-4444-555555555555"));
        for bad in ["", "a/b", "..", "a?b", "a b", "a%2Fb", &"a".repeat(65)] {
            assert!(!cloud_id_is_plain(bad), "{bad}");
        }
    }

    /// The request names the caller's own issues, the two events, and the
    /// fields whose change counts. The filter is exactly one assignee clause.
    #[test]
    fn the_registration_asks_for_the_users_own_issues_and_nothing_else() {
        let body = registration_body(
            "https://talos.example.com/api/atlassian/webhook",
            "557058:f58131cb-b67d-43c7-b30d-6b58d40bd077",
        );
        assert_eq!(
            body,
            serde_json::json!({
                "url": "https://talos.example.com/api/atlassian/webhook",
                "webhooks": [{
                    "events": ["jira:issue_created", "jira:issue_updated"],
                    "jqlFilter": "assignee = \"557058:f58131cb-b67d-43c7-b30d-6b58d40bd077\"",
                    "fieldIdsFilter": ["status", "assignee", "priority", "duedate"],
                }],
            })
        );
    }

    #[test]
    fn an_expiration_is_read_as_a_number_or_a_date() {
        let expected = DateTime::parse_from_rfc3339("2026-11-11T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        for value in [
            serde_json::json!(expected.timestamp_millis()),
            serde_json::json!(expected.timestamp()),
            serde_json::json!("2026-11-11T12:00:00Z"),
            serde_json::json!("2026-11-11T12:00:00.000+0000"),
            serde_json::json!("2026-11-11T07:00:00.000-0500"),
        ] {
            assert_eq!(parse_expiration(&value), Some(expected), "{value}");
        }
        for value in [
            serde_json::json!(null),
            serde_json::json!(0),
            serde_json::json!(-5),
            serde_json::json!("soon"),
            serde_json::json!({}),
            serde_json::json!(1.5),
        ] {
            assert_eq!(parse_expiration(&value), None, "{value}");
        }
    }

    /// The kind of an HTTP failure survives into the error, and decides what
    /// the caller is told to do.
    #[test]
    fn an_upstream_failure_keeps_its_kind() {
        use UpstreamFailure as F;
        assert_eq!(F::from_status(401), F::Unauthorized { status: 401 });
        assert_eq!(F::from_status(403), F::Unauthorized { status: 403 });
        assert_eq!(F::from_status(429), F::RateLimited);
        assert_eq!(F::from_status(503), F::Server { status: 503 });
        assert_eq!(F::from_status(408), F::Server { status: 408 });
        assert_eq!(F::from_status(400), F::Refused { status: 400 });
        assert_eq!(F::from_status(404), F::Refused { status: 404 });

        for (failure, transient) in [
            (F::Unreachable { timed_out: true }, true),
            (F::Unreachable { timed_out: false }, true),
            (F::RateLimited, true),
            (F::Server { status: 502 }, true),
            (F::Unauthorized { status: 401 }, false),
            (F::Refused { status: 400 }, false),
            (F::Rejected, false),
            (F::Malformed, false),
        ] {
            assert_eq!(failure.is_transient(), transient, "{failure}");
            let err = JiraPushError::Upstream {
                what: "renewal",
                failure,
            };
            assert_eq!(
                err.refusal_kind() == ProvisionRefusalKind::Unavailable,
                transient,
                "{failure}"
            );
        }
        // The recorded text names the status, so a reader (and the shared
        // "does this look like a dead credential" heuristic) can tell a 401
        // from a blip. The operation is called "renewal" in an error for
        // that reason: the heuristic reads the word "refresh" as a dead
        // credential, and a 503 during one is not.
        let dead = JiraPushError::Upstream {
            what: "renewal",
            failure: F::Unauthorized { status: 401 },
        }
        .to_string();
        assert_eq!(dead, "Jira webhook renewal: HTTP 401 unauthorized");
        assert!(talos_integration_helpers::looks_like_oauth_failure(&dead));
        let blip = JiraPushError::Upstream {
            what: "renewal",
            failure: F::Server { status: 503 },
        }
        .to_string();
        assert!(!talos_integration_helpers::looks_like_oauth_failure(&blip));
    }

    /// A failed refresh is what is shown; with none recorded, an expiry that
    /// has passed is. A healthy registration shows nothing.
    #[test]
    fn a_registration_shows_its_failed_refresh_or_that_it_expired() {
        let now = Utc::now();
        let ago = |days| now - chrono::Duration::days(days);
        assert_eq!(registration_failure(None, None, Some(ago(-20)), now), None);
        assert_eq!(registration_failure(None, None, None, now), None);

        let expired = registration_failure(None, None, Some(ago(3)), now).expect("expired");
        assert_eq!(expired.error_message, EXPIRED_WEBHOOK_MESSAGE);
        assert_eq!(expired.failed_at, ago(3));
        assert!(!expired.likely_oauth_failure);

        // A recorded failure is the more specific statement and wins.
        let dead = registration_failure(
            Some(ago(1)),
            Some("Jira webhook renewal: HTTP 401 unauthorized".into()),
            Some(ago(3)),
            now,
        )
        .expect("failed");
        assert!(dead.error_message.contains("401"));
        assert!(dead.likely_oauth_failure);
        assert_eq!(dead.failed_at, ago(1));
    }

    /// "Not yours" and "no such" are one answer, and neither names anything.
    #[test]
    fn a_missing_connection_or_channel_is_one_plain_answer() {
        for err in [
            JiraPushError::ConnectionNotFound,
            JiraPushError::RegistrationNotFound,
        ] {
            assert_eq!(err.refusal_kind(), ProvisionRefusalKind::NotFound);
            assert!(!err.user_facing_message().contains("another"));
        }
        let hidden = JiraPushError::Database(sqlx::Error::PoolTimedOut).user_facing_message();
        assert!(!hidden.to_lowercase().contains("pool"), "{hidden}");
    }
}
