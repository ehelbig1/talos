//! GitHub App connect/install orchestration (RFC 0008 B2b).
//!
//! The initiate step is session-authenticated; the two callbacks are cross-site
//! redirects from github.com that carry no session (the auth cookie is
//! `SameSite=Strict`), so they recover the user from single-use state tokens —
//! and every state is bound to the initiating BROWSER as well as the user
//! (`talos_oauth::BrowserBinding`), so a URL minted by one person cannot be
//! completed in another person's browser.
//!
//! **Why two hops (2026-09-25).** GitHub documents that the Setup-URL redirect's
//! `installation_id` can be spoofed, and this flow used to trust it: any user
//! could open `/api/github/setup?installation_id=<someone else's>&state=<their
//! own>` and the upsert moved that installation — and `github_app:<owner>` token
//! minting — to them. Now:
//!
//! 1. `/api/github/connect` → a `github_app` state + the install URL.
//! 2. `/api/github/setup` consumes it and, instead of writing anything, starts
//!    GitHub's user-authorization web flow with a second state
//!    (`github_app_user`, PKCE) that carries the named installation id
//!    server-side (`bound_subject`).
//! 3. `/api/github/authorized` consumes that, exchanges the code for a
//!    short-lived user token, and claims the installation ONLY if GitHub lists
//!    it among that user's installations (`GET /user/installations`) — and the
//!    claim itself refuses to move an active row another Talos user owns.
//!
//! The App must NOT enable "Request user authorization (OAuth) during
//! installation": that mode sends GitHub's post-install redirect to the Callback
//! URL instead of the Setup URL, which step 2 depends on.

use anyhow::{anyhow, Context, Result};
use sqlx::PgPool;
use uuid::Uuid;

use talos_github::{
    install_url, parse_setup_callback, GithubAppClient, GithubAppConfig, GithubUserAuthClient,
    InstallationAccess,
};
use talos_github_repository::{
    GithubAppInstallationRepository, InstallationClaim, NewInstallationClaim,
};
use talos_oauth::{AuthorizeRequest, BrowserBinding};

/// `oauth_state_tokens.provider` for the install redirect's state.
const PROVIDER: &str = "github_app";
/// `oauth_state_tokens.provider` for the user-authorization hop's state.
const USER_AUTH_PROVIDER: &str = "github_app_user";

/// Outcome of a completed connect (for the success redirect).
pub struct SetupOutcome {
    pub account_login: String,
}

/// Why a verified callback still did not connect the installation. These are
/// decisions, not failures, and each gets its own caller-facing code: the user
/// has already proven (via GitHub) who they are, so naming the reason discloses
/// nothing they could not see on GitHub.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimRefusal {
    /// GitHub does not list the installation among the authorizing user's.
    NotAccessible,
    /// The user's installation list is too long to read in full.
    Unverifiable,
    /// The installation is actively connected to a different Talos account.
    OwnedByAnotherUser,
}

impl ClaimRefusal {
    /// The `github_error` query value the settings page renders.
    pub fn error_code(self) -> &'static str {
        match self {
            Self::NotAccessible => "installation_not_accessible",
            Self::Unverifiable => "installation_not_verifiable",
            Self::OwnedByAnotherUser => "installation_connected_to_another_account",
        }
    }
}

/// The result of the user-authorization callback.
#[must_use]
pub enum AuthorizedOutcome {
    Connected(SetupOutcome),
    Refused(ClaimRefusal),
}

/// A connected installation, surfaced to the UI so the Integrations page can
/// show that GitHub is linked (and to which account).
#[derive(serde::Serialize)]
pub struct InstallationSummary {
    pub installation_id: i64,
    pub account_login: String,
    pub account_type: Option<String>,
    pub repository_selection: Option<String>,
}

struct ConfiguredApp {
    client: GithubAppClient,
    app_slug: String,
    user_auth: GithubUserAuthClient,
}

/// Connect service. Holds the configured App (client + slug + user-authorization
/// client) when the connect flow is enabled; otherwise [`is_configured`] is false
/// and the handlers return 503.
///
/// [`is_configured`]: GithubConnectService::is_configured
pub struct GithubConnectService {
    db_pool: PgPool,
    app: Option<ConfiguredApp>,
}

impl GithubConnectService {
    /// Build from the resolved platform config (`None` = App not configured).
    ///
    /// The connect flow needs the App's user-authorization credentials
    /// (`GITHUB_APP_CLIENT_ID` / `_SECRET` / `_REDIRECT_URI`) to prove the
    /// connecting user can access an installation. Without them the flow is
    /// DISABLED (503) rather than run unverified; installation tokens for
    /// already-connected installations are minted elsewhere and keep working.
    pub fn new(db_pool: PgPool, config: Option<GithubAppConfig>) -> Self {
        let app = config.and_then(|c| {
            let Some(user_auth_cfg) = c.user_auth().cloned() else {
                tracing::warn!(
                    "GitHub App connect flow DISABLED: GITHUB_APP_CLIENT_ID / \
                     GITHUB_APP_CLIENT_SECRET / GITHUB_APP_REDIRECT_URI are unset, so \
                     installation ownership cannot be verified; existing installations \
                     still mint tokens"
                );
                return None;
            };
            let client = match c.client() {
                Ok(client) => client,
                Err(e) => {
                    tracing::error!(error = %e, "GitHub App configured but client build failed; disabling connect flow");
                    return None;
                }
            };
            let user_auth = match GithubUserAuthClient::new(user_auth_cfg) {
                Ok(u) => u,
                Err(e) => {
                    tracing::error!(error = %e, "GitHub App user-authorization client build failed; disabling connect flow");
                    return None;
                }
            };
            Some(ConfiguredApp {
                client,
                app_slug: c.app_slug.clone(),
                user_auth,
            })
        });
        Self { db_pool, app }
    }

    /// Build with explicit clients. Tests point both at a loopback GitHub;
    /// deliberately NOT reachable from configuration.
    #[doc(hidden)]
    pub fn with_clients(
        db_pool: PgPool,
        client: GithubAppClient,
        app_slug: String,
        user_auth: GithubUserAuthClient,
    ) -> Self {
        Self {
            db_pool,
            app: Some(ConfiguredApp {
                client,
                app_slug,
                user_auth,
            }),
        }
    }

    pub fn is_configured(&self) -> bool {
        self.app.is_some()
    }

    /// List the user's ACTIVE installations (for the Integrations UI). This is a
    /// plain DB read, so it works even if the App client isn't configured — a
    /// previously-connected installation should still be visible.
    pub async fn list_installations(&self, user_id: Uuid) -> Result<Vec<InstallationSummary>> {
        let repo = GithubAppInstallationRepository::new(self.db_pool.clone());
        let rows = repo
            .list_for_user(user_id)
            .await
            .context("list GitHub App installations")?;
        Ok(rows
            .into_iter()
            .filter(|r| r.is_active)
            .map(|r| InstallationSummary {
                installation_id: r.installation_id,
                account_login: r.account_login,
                account_type: r.account_type,
                repository_selection: r.repository_selection,
            })
            .collect())
    }

    fn app(&self) -> Result<&ConfiguredApp> {
        self.app
            .as_ref()
            .ok_or_else(|| anyhow!("GitHub App is not configured on this server"))
    }

    /// Step 1: persist a single-use state bound to `user_id` AND `binding`, and
    /// return the GitHub install URL. The caller sets `binding`'s cookie on the
    /// response.
    pub async fn begin_install(&self, user_id: Uuid, binding: &BrowserBinding) -> Result<String> {
        let app = self.app()?;
        let state = talos_oauth::issue_bound_state(&self.db_pool, PROVIDER, user_id, binding)
            .await
            .context("store GitHub App install state token")?;
        install_url(&app.app_slug, &state).map_err(|e| anyhow!("{e}"))
    }

    /// Step 2 — the Setup-URL callback. Consumes the install state (single-use,
    /// this browser only) and returns the GitHub user-authorization URL to
    /// redirect to. **Writes no installation row**: the `installation_id` here
    /// is untrusted and is only carried, server-side, to step 3.
    pub async fn handle_setup(
        &self,
        installation_id_raw: Option<&str>,
        setup_action: Option<&str>,
        state: &str,
        binding: &BrowserBinding,
        presented_binding: Option<&str>,
    ) -> Result<String> {
        let app = self.app()?;

        // Validate untrusted callback params (positive installation_id, known action).
        let cb =
            parse_setup_callback(installation_id_raw, setup_action).map_err(|e| anyhow!("{e}"))?;

        let consumed =
            talos_oauth::consume_oauth_state(&self.db_pool, PROVIDER, state, presented_binding)
                .await?;

        let auth_url = app.user_auth.authorize_url();
        let token_url = app.user_auth.token_url();
        let cfg = app.user_auth.config();
        let req = AuthorizeRequest {
            provider: USER_AUTH_PROVIDER,
            auth_url: &auth_url,
            token_url: &token_url,
            client_id: cfg.client_id.clone(),
            client_secret: cfg.client_secret().to_string(),
            redirect_uri: cfg.redirect_uri.clone(),
            // A GitHub App's user token carries the App's permissions, not scopes.
            scopes: &[],
            extra_params: &[],
        };
        let (url, _state) = talos_oauth::begin_oauth_authorization_with_subject(
            &self.db_pool,
            &req,
            consumed.user_id,
            binding,
            Some(&cb.installation_id.to_string()),
        )
        .await
        .context("start GitHub user authorization")?;
        Ok(url)
    }

    /// Step 3 — the user-authorization callback. Claims the installation only if
    /// the GitHub user who just authorized can access it, and only if no other
    /// Talos account actively holds it.
    pub async fn handle_authorized(
        &self,
        code: &str,
        state: &str,
        presented_binding: Option<&str>,
    ) -> Result<AuthorizedOutcome> {
        let app = self.app()?;

        let consumed = talos_oauth::consume_oauth_state(
            &self.db_pool,
            USER_AUTH_PROVIDER,
            state,
            presented_binding,
        )
        .await?;
        let installation_id: i64 = consumed
            .bound_subject
            .as_deref()
            .and_then(|s| s.parse().ok())
            .filter(|id: &i64| *id > 0)
            .ok_or_else(|| anyhow!("user-authorization state carries no installation id"))?;
        let user_id = consumed.user_id;

        // Ownership proof: does GitHub list this installation for the user who
        // just authorized? The token lives only for this block.
        let access = {
            let token = app
                .user_auth
                .exchange_code(code, consumed.pkce_verifier.as_deref())
                .await
                .context("exchange GitHub user-authorization code")?;
            app.user_auth
                .user_can_access_installation(&token, installation_id)
                .await
                .context("list the authorizing user's GitHub installations")?
        };
        let refusal = match access {
            InstallationAccess::Accessible => None,
            InstallationAccess::NotAccessible => Some(ClaimRefusal::NotAccessible),
            InstallationAccess::TooManyToVerify => Some(ClaimRefusal::Unverifiable),
        };
        if let Some(r) = refusal {
            log_refusal(user_id, installation_id, r);
            return Ok(AuthorizedOutcome::Refused(r));
        }

        let now = chrono::Utc::now().timestamp();
        let info = app
            .client
            .get_installation(installation_id, now)
            .await
            .context("fetch GitHub installation metadata")?;

        let repo = GithubAppInstallationRepository::new(self.db_pool.clone());
        let claim = repo
            .claim_recorded(&NewInstallationClaim {
                user_id,
                installation_id,
                account_login: &info.account_login,
                account_type: info.account_type.as_deref(),
                permissions: Some(&info.permissions),
                repository_selection: info.repository_selection.as_deref(),
            })
            .await
            .context("persist GitHub installation")?;
        match claim {
            InstallationClaim::Claimed { row, .. } => {
                Ok(AuthorizedOutcome::Connected(SetupOutcome {
                    account_login: row.account_login,
                }))
            }
            InstallationClaim::OwnedByAnotherUser => {
                log_refusal(user_id, installation_id, ClaimRefusal::OwnedByAnotherUser);
                Ok(AuthorizedOutcome::Refused(ClaimRefusal::OwnedByAnotherUser))
            }
        }
    }
}

/// A refused claim writes nothing, so it has no `admin_event_log` row; it is a
/// `talos_audit` line instead (ids only — no token, no GitHub response).
fn log_refusal(user_id: Uuid, installation_id: i64, refusal: ClaimRefusal) {
    tracing::warn!(
        target: "talos_audit",
        event_kind = "github_installation_claim_refused",
        user_id = %user_id,
        installation_id,
        reason = refusal.error_code(),
        "GitHub App installation claim refused"
    );
}
