//! Connecting a bank account through Plaid Link, and disconnecting it.
//!
//! The browser runs Plaid Link (Plaid's own sign-in window; the bank password
//! goes to Plaid and the bank, never here). Talos does two things around it:
//!
//! 1. [`PlaidConnectService::link_token`] starts a Link session for the
//!    signed-in user.
//! 2. [`PlaidConnectService::connect`] takes the short-lived `public_token`
//!    Link returns, exchanges it server-side for the Item's long-lived access
//!    token, and stores that token in the vault at
//!    `plaid/access_token/{item_id}` — owned by the user, readable by a module
//!    only through a `vault://` reference under its `plaid/*` grant. The token
//!    never reaches the browser.
//!
//! [`PlaidConnectService::remove_item`] ends a connection: at Plaid (so it
//! stops counting against the plan's Item limit) and in the vault. The
//! Settings page reaches it through the generic disconnect path, which first
//! hides the `plaid_items` row.

pub mod handlers;

use std::sync::Arc;

use talos_plaid::link::{access_token_path, PLAID_CLIENT_ID_PATH, PLAID_SECRET_PATH};
use talos_plaid::{AccessToken, LinkToken, PlaidClient, PlaidConfig, PublicToken};
use talos_secrets_manager::{SecretRequestor, SecretsManager};
use uuid::Uuid;

/// The longest `public_token` accepted. Plaid's are well under this; the cap
/// only stops an arbitrary string being sent on to Plaid.
const MAX_PUBLIC_TOKEN_CHARS: usize = 256;

/// The longest institution name or id kept. They are display labels from the
/// browser, not trusted for anything.
const MAX_LABEL_CHARS: usize = 200;

/// The bank as Plaid Link described it to the browser. Display only.
#[derive(Debug, Clone, Default)]
pub struct Institution {
    pub id: Option<String>,
    pub name: Option<String>,
}

/// What a completed connection reports to the person who made it.
#[derive(Debug, Clone)]
pub struct ConnectedItem {
    pub item_id: String,
    pub institution_name: Option<String>,
    /// Accounts the connection covers; `None` when Plaid could not say.
    pub accounts: Option<usize>,
}

/// Why a connection was not made. Each is one closed caller-facing sentence:
/// the detail goes to the log, never to the browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectRefusal {
    /// `PLAID_CLIENT_ID` / `PLAID_SECRET` / `PLAID_ENV` are not set.
    NotConfigured,
    /// The token from the browser was missing or malformed.
    BadPublicToken,
    /// Plaid refused the exchange (expired, already used, wrong environment).
    Exchange,
    /// The connection was made at Plaid but could not be stored here; it has
    /// been removed at Plaid again.
    Store,
    /// Plaid refused to start a sign-in session.
    LinkToken,
}

impl ConnectRefusal {
    #[must_use]
    pub fn message(self) -> &'static str {
        match self {
            Self::NotConfigured => "Plaid is not configured on this server",
            Self::BadPublicToken => "The bank sign-in did not return a usable token",
            Self::Exchange => "Plaid did not accept the bank sign-in; try connecting again",
            Self::Store => "The bank was connected at Plaid but could not be saved here, so the connection was undone; try again",
            Self::LinkToken => "Plaid could not start a bank sign-in; try again",
        }
    }
}

/// Keep only printable characters and bound the length.
fn label(raw: Option<&str>) -> Option<String> {
    let cleaned: String = raw?
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_LABEL_CHARS)
        .collect();
    let trimmed = cleaned.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// The display name of a bank's access-token entry in the vault.
fn access_token_name(institution_name: Option<&str>) -> String {
    match institution_name {
        Some(bank) => format!("Plaid access token ({bank})"),
        None => "Plaid access token".to_string(),
    }
}

/// Where a disconnect can end a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RemovalAt {
    /// At Plaid, with this server's credentials.
    Plaid,
    /// Only here: the connection was made in another Plaid environment, whose
    /// host and app secret this server does not have. Sending its token to
    /// the configured environment would only be refused.
    HereOnly { connected_in: String },
}

/// `row_environment` is the environment recorded when the bank was connected;
/// `None` (no row, or the row could not be read) leaves the decision to Plaid.
fn removal_at(row_environment: Option<&str>, configured: &str) -> RemovalAt {
    match row_environment {
        Some(env) if env != configured => RemovalAt::HereOnly {
            connected_in: env.to_string(),
        },
        _ => RemovalAt::Plaid,
    }
}

/// A `public_token` worth sending to Plaid: present, bounded, the shape Plaid
/// issues (`public-<env>-<uuid>`), no whitespace or control characters.
fn check_public_token(raw: &str) -> Result<PublicToken, ConnectRefusal> {
    let t = raw.trim();
    let shaped = t.starts_with("public-")
        && t.len() <= MAX_PUBLIC_TOKEN_CHARS
        && t.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    if shaped {
        Ok(PublicToken::new(t.to_string()))
    } else {
        Err(ConnectRefusal::BadPublicToken)
    }
}

pub struct PlaidConnectService {
    pool: sqlx::PgPool,
    secrets: Arc<SecretsManager>,
    client: Option<PlaidClient>,
}

impl PlaidConnectService {
    /// Reads Plaid's settings from the environment. Not configured (or
    /// misconfigured — the boot log says which) is a service that refuses
    /// every request with [`ConnectRefusal::NotConfigured`].
    #[must_use]
    pub fn new(pool: sqlx::PgPool, secrets: Arc<SecretsManager>) -> Self {
        let client = PlaidConfig::from_env().ok().flatten().map(PlaidClient::new);
        Self {
            pool,
            secrets,
            client,
        }
    }

    /// A service around a given client (one pointed at a stand-in for Plaid).
    #[doc(hidden)]
    #[must_use]
    pub fn for_tests(
        pool: sqlx::PgPool,
        secrets: Arc<SecretsManager>,
        client: PlaidClient,
    ) -> Self {
        Self {
            pool,
            secrets,
            client: Some(client),
        }
    }

    #[must_use]
    pub fn is_configured(&self) -> bool {
        self.client.is_some()
    }

    fn client(&self) -> Result<&PlaidClient, ConnectRefusal> {
        self.client.as_ref().ok_or(ConnectRefusal::NotConfigured)
    }

    /// Start a Plaid Link session for `user_id`.
    pub async fn link_token(&self, user_id: Uuid) -> Result<LinkToken, ConnectRefusal> {
        let client = self.client()?;
        client
            .create_link_token(&user_id.to_string())
            .await
            .map_err(|e| {
                tracing::warn!(target: "talos_plaid", %user_id, error = %e, "Plaid link token not created");
                ConnectRefusal::LinkToken
            })
    }

    /// Finish a bank sign-in: exchange the browser's `public_token`, store the
    /// access token for `user_id`, record the connection.
    ///
    /// Once the exchange succeeds a live connection exists at Plaid, so every
    /// later failure undoes it there ([`ConnectRefusal::Store`]): a connection
    /// this server cannot use would still count against the plan's limit.
    pub async fn connect(
        &self,
        user_id: Uuid,
        public_token: &str,
        institution: Institution,
    ) -> Result<ConnectedItem, ConnectRefusal> {
        let client = self.client()?;
        let public = check_public_token(public_token)?;
        let (access, item_id) = client.exchange_public_token(&public).await.map_err(|e| {
            tracing::warn!(target: "talos_plaid", %user_id, error = %e, "Plaid public token not exchanged");
            ConnectRefusal::Exchange
        })?;
        let institution_name = label(institution.name.as_deref());
        let institution_id = label(institution.id.as_deref());

        match self
            .store(
                user_id,
                &item_id,
                &access,
                institution_id.as_deref(),
                institution_name.as_deref(),
            )
            .await
        {
            Ok(()) => {}
            Err(e) => {
                tracing::error!(
                    target: "talos_plaid",
                    %user_id,
                    item_id = %item_id,
                    error = %e,
                    "Plaid connection made but not stored — undoing it at Plaid"
                );
                self.undo(user_id, &item_id, &access).await;
                return Err(ConnectRefusal::Store);
            }
        }
        let accounts = client.accounts(&access).await.map(|a| a.len()).ok();
        tracing::info!(
            target: "talos_audit",
            event_kind = "plaid_item_connected",
            %user_id,
            item_id = %item_id,
            institution = institution_name.as_deref().unwrap_or("unknown"),
            accounts = ?accounts,
            env = client.config().env.as_str(),
            "bank connected through Plaid"
        );
        Ok(ConnectedItem {
            item_id,
            institution_name,
            accounts,
        })
    }

    /// The row, then the vault entries. The app's own Plaid credentials are
    /// written too, so a reader module always has the ones for the environment
    /// this connection was made in.
    async fn store(
        &self,
        user_id: Uuid,
        item_id: &str,
        access: &AccessToken,
        institution_id: Option<&str>,
        institution_name: Option<&str>,
    ) -> anyhow::Result<()> {
        let client = self.client().map_err(|r| anyhow::anyhow!(r.message()))?;
        let token_path = access_token_path(item_id).map_err(|e| anyhow::anyhow!(e))?;
        let org_id = talos_organizations::OrganizationService::create_personal_org(
            &self.pool, user_id, None,
        )
        .await?
        .id;
        sqlx::query(
            "INSERT INTO plaid_items (user_id, item_id, institution_id, institution_name, environment) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (user_id, item_id) DO UPDATE SET \
                institution_id = EXCLUDED.institution_id, \
                institution_name = EXCLUDED.institution_name, \
                environment = EXCLUDED.environment, \
                is_active = TRUE",
        )
        .bind(user_id)
        .bind(item_id)
        .bind(institution_id)
        .bind(institution_name)
        .bind(client.config().env.as_str())
        .execute(&self.pool)
        .await?;
        let config = client.config();
        // The token's name says which bank it is, so the entry can be told
        // from the others wherever secrets are listed.
        let token_name = access_token_name(institution_name);
        for (name, path, value) in [
            (
                "Plaid client id",
                PLAID_CLIENT_ID_PATH,
                config.client_id.as_str(),
            ),
            ("Plaid app secret", PLAID_SECRET_PATH, config.secret()),
            (token_name.as_str(), token_path.as_str(), access.as_str()),
        ] {
            self.secrets
                .upsert_secret(
                    name,
                    path,
                    value,
                    "default",
                    Some("written by the Plaid connect flow; read by a module through vault://"),
                    user_id,
                    Vec::new(),
                    Some(org_id),
                )
                .await?;
        }
        Ok(())
    }

    /// Undo a connection that could not be stored: hide the row, drop any
    /// token entry written, and remove the Item at Plaid. Best effort; each
    /// failure is logged.
    async fn undo(&self, user_id: Uuid, item_id: &str, access: &AccessToken) {
        if let Err(e) = sqlx::query(
            "UPDATE plaid_items SET is_active = FALSE WHERE user_id = $1 AND item_id = $2",
        )
        .bind(user_id)
        .bind(item_id)
        .execute(&self.pool)
        .await
        {
            tracing::warn!(target: "talos_plaid", %user_id, error = %e, "could not hide the unstored Plaid row");
        }
        if let Ok(path) = access_token_path(item_id) {
            if let Err(e) = self
                .secrets
                .delete_secret_if_present(&path, Some(user_id), &[])
                .await
            {
                tracing::warn!(target: "talos_plaid", %user_id, error = %e, "could not delete the unstored Plaid token");
            }
        }
        if let Ok(client) = self.client() {
            if let Err(e) = client.remove_item(access).await {
                tracing::error!(
                    target: "talos_plaid",
                    %user_id,
                    item_id = %item_id,
                    error = %e,
                    "could not remove the unstored connection at Plaid — remove it in the Plaid dashboard"
                );
            }
        }
    }

    /// End a connection: at Plaid, then in the vault. Called after the
    /// Settings disconnect has hidden the `plaid_items` row.
    ///
    /// A Plaid failure is logged and the vault entry is deleted anyway (no
    /// one here can use the connection after that). `Err` only when the token
    /// is still in the vault afterwards.
    ///
    /// A connection made in the other Plaid environment (a sandbox bank left
    /// over after the switch to production) is not sent to Plaid at all: see
    /// [`RemovalAt::HereOnly`].
    pub async fn remove_item(&self, user_id: Uuid, item_id: &str) -> anyhow::Result<()> {
        let path = access_token_path(item_id).map_err(|e| anyhow::anyhow!(e))?;
        let row_environment: Option<String> = match sqlx::query_scalar::<_, String>(
            "SELECT environment FROM plaid_items WHERE user_id = $1 AND item_id = $2",
        )
        .bind(user_id)
        .bind(item_id)
        .fetch_optional(&self.pool)
        .await
        {
            Ok(env) => env,
            Err(e) => {
                tracing::warn!(target: "talos_plaid", %user_id, error = %e, "could not read the connection's environment; asking Plaid to remove it");
                None
            }
        };
        let mut removed_at_plaid = false;
        let org_ids = match talos_organizations::OrganizationService::create_personal_org(
            &self.pool, user_id, None,
        )
        .await
        {
            Ok(org) => vec![org.id],
            Err(_) => Vec::new(),
        };
        match self
            .secrets
            .get_secret(&path, SecretRequestor::User(user_id), &org_ids)
            .await
        {
            Ok(raw) => match self.client() {
                Ok(client) => {
                    match removal_at(row_environment.as_deref(), client.config().env.as_str()) {
                        RemovalAt::Plaid => {
                            match client.remove_item(&AccessToken::new(raw)).await {
                                Ok(()) => removed_at_plaid = true,
                                Err(e) => tracing::warn!(
                                    target: "talos_plaid",
                                    %user_id,
                                    item_id = %item_id,
                                    error = %e,
                                    "Plaid did not confirm the removal; the token is deleted here regardless"
                                ),
                            }
                        }
                        RemovalAt::HereOnly { connected_in } => tracing::warn!(
                            target: "talos_plaid",
                            %user_id,
                            item_id = %item_id,
                            connected_in = %connected_in,
                            configured = client.config().env.as_str(),
                            "this connection was made in another Plaid environment, so it was not removed at Plaid; \
                             the token is deleted here. A production connection left this way still counts against \
                             the plan until it is removed in the Plaid dashboard"
                        ),
                    }
                }
                Err(_) => tracing::warn!(
                    target: "talos_plaid",
                    %user_id,
                    item_id = %item_id,
                    "Plaid is not configured, so the connection was not removed at Plaid; remove it in the Plaid dashboard"
                ),
            },
            Err(e) => {
                tracing::debug!(target: "talos_plaid", %user_id, error = %e, "no stored Plaid token to remove")
            }
        }
        self.secrets
            .delete_secret_if_present(&path, Some(user_id), &org_ids)
            .await
            .map(|_| ())?;
        tracing::info!(
            target: "talos_audit",
            event_kind = "plaid_item_disconnected",
            %user_id,
            item_id = %item_id,
            removed_at_plaid,
            "bank disconnected"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_public_token_must_have_plaids_shape() {
        assert!(check_public_token("public-sandbox-1b2c3d4e-0000-4000-8000-000000000000").is_ok());
        assert!(check_public_token("  public-production-abc-123  ").is_ok());
        for bad in [
            "",
            "access-sandbox-abc",
            "public-abc def",
            "public-a\nb",
            "public-a/../b",
            &format!("public-{}", "a".repeat(300)),
        ] {
            assert_eq!(
                check_public_token(bad).err(),
                Some(ConnectRefusal::BadPublicToken),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_connection_from_another_environment_is_ended_here_only() {
        assert_eq!(
            removal_at(Some("production"), "production"),
            RemovalAt::Plaid
        );
        assert_eq!(removal_at(Some("sandbox"), "sandbox"), RemovalAt::Plaid);
        assert_eq!(
            removal_at(Some("sandbox"), "production"),
            RemovalAt::HereOnly {
                connected_in: "sandbox".into()
            }
        );
        assert_eq!(
            removal_at(Some("production"), "sandbox"),
            RemovalAt::HereOnly {
                connected_in: "production".into()
            }
        );
        // No row to say otherwise: Plaid decides.
        assert_eq!(removal_at(None, "production"), RemovalAt::Plaid);
    }

    #[test]
    fn the_token_entry_is_named_for_its_bank() {
        assert_eq!(
            access_token_name(Some("Wells Fargo")),
            "Plaid access token (Wells Fargo)"
        );
        assert_eq!(access_token_name(None), "Plaid access token");
    }

    #[test]
    fn labels_are_printable_bounded_and_blank_is_none() {
        assert_eq!(label(Some("  Wells Fargo ")), Some("Wells Fargo".into()));
        assert_eq!(label(Some("Ally\u{0}\nBank")), Some("AllyBank".into()));
        assert_eq!(label(Some("   ")), None);
        assert_eq!(label(None), None);
        assert_eq!(
            label(Some(&"x".repeat(500))).map(|s| s.len()),
            Some(MAX_LABEL_CHARS)
        );
    }

    #[test]
    fn every_refusal_has_a_sentence_and_none_names_a_token() {
        for r in [
            ConnectRefusal::NotConfigured,
            ConnectRefusal::BadPublicToken,
            ConnectRefusal::Exchange,
            ConnectRefusal::Store,
            ConnectRefusal::LinkToken,
        ] {
            assert!(!r.message().is_empty());
            assert!(!r.message().contains("public-") && !r.message().contains("access-"));
        }
    }
}
