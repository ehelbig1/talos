//! GitHub App connect/install orchestration (RFC 0008 B2b).
//!
//! Mirrors the `talos-gmail` / `talos-atlassian` connect pattern: the initiate
//! step is session-authenticated and stores the connecting `user_id` in
//! `oauth_state_tokens`; the install **callback is a cross-site redirect from
//! github.com**, so it carries no session auth (a `SameSite=Strict` auth cookie
//! isn't sent) and recovers `user_id` from the single-use state token instead.

use anyhow::{anyhow, Context, Result};
use sqlx::PgPool;
use uuid::Uuid;

use talos_github::{install_url, parse_setup_callback, GithubAppClient, GithubAppConfig};
use talos_github_repository::GithubAppInstallationRepository;

/// `oauth_state_tokens.provider` discriminator for this flow.
const PROVIDER: &str = "github_app";

/// Outcome of a completed setup callback (for the success redirect).
pub struct SetupOutcome {
    pub account_login: String,
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
}

/// Connect service. Holds the configured App (client + slug) when GitHub App
/// support is enabled; otherwise [`is_configured`] is false and the handlers
/// return 503.
///
/// [`is_configured`]: GithubConnectService::is_configured
pub struct GithubConnectService {
    db_pool: PgPool,
    app: Option<ConfiguredApp>,
}

impl GithubConnectService {
    /// Build from the resolved platform config (`None` = App not configured).
    /// A client-build failure (shouldn't happen — the key is validated at config
    /// load) is logged and downgraded to "not configured" so the controller
    /// still boots.
    pub fn new(db_pool: PgPool, config: Option<GithubAppConfig>) -> Self {
        let app = config.and_then(|c| match c.client() {
            Ok(client) => Some(ConfiguredApp {
                client,
                app_slug: c.app_slug.clone(),
            }),
            Err(e) => {
                tracing::error!(error = %e, "GitHub App configured but client build failed; disabling connect flow");
                None
            }
        });
        Self { db_pool, app }
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

    /// Initiate the install flow: persist a single-use CSRF state token bound to
    /// `user_id`, and return the GitHub install-redirect URL. `user_id` comes
    /// from the authenticated session (the route is auth-gated).
    pub async fn begin_install(&self, user_id: Uuid) -> Result<String> {
        let app = self.app()?;

        // ~244 bits from two v4 UUIDs, hex-encoded — passes
        // `validate_oauth_state_token_format`'s charset rules (same shape as
        // talos-oauth's `generate_oauth_session_binding`).
        let state = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());

        sqlx::query(
            "INSERT INTO oauth_state_tokens (state_token, provider, user_id) VALUES ($1, $2, $3)",
        )
        .bind(&state)
        .bind(PROVIDER)
        .bind(user_id)
        .execute(&self.db_pool)
        .await
        .context("store GitHub App install state token")?;

        install_url(&app.app_slug, &state).map_err(|e| anyhow!("{e}"))
    }

    /// Complete the install callback. Validates + single-use-consumes the state
    /// token (recovering the initiating `user_id`), fetches installation
    /// metadata from GitHub, and upserts the installation row.
    ///
    /// `installation_id_raw` / `setup_action` are GitHub's untrusted query
    /// params; `state` is the CSRF token echoed back.
    pub async fn handle_setup(
        &self,
        installation_id_raw: Option<&str>,
        setup_action: Option<&str>,
        state: &str,
    ) -> Result<SetupOutcome> {
        let app = self.app()?;

        // Validate untrusted callback params (positive installation_id, known action).
        let cb =
            parse_setup_callback(installation_id_raw, setup_action).map_err(|e| anyhow!("{e}"))?;

        // Format-gate state before the DB consume (defense-asymmetry / DoS guard),
        // matching the gmail/atlassian connect callbacks.
        talos_oauth::validate_oauth_state_token_format(state)
            .map_err(|_| anyhow!("Invalid or expired state token (possible CSRF)"))?;

        // Atomic single-use consume; recover the initiating user_id.
        let row = sqlx::query_as::<_, (Uuid, Option<Uuid>)>(
            "UPDATE oauth_state_tokens \
             SET used = true \
             WHERE state_token = $1 AND provider = $2 AND used = false AND expires_at > NOW() \
             RETURNING id, user_id",
        )
        .bind(state)
        .bind(PROVIDER)
        .fetch_optional(&self.db_pool)
        .await
        .context("validate GitHub App install state token")?;

        let (_state_id, user_id_opt) = row.ok_or_else(|| {
            anyhow!("Invalid or expired state token. This may indicate a CSRF attempt.")
        })?;
        let user_id = user_id_opt
            .ok_or_else(|| anyhow!("state token missing user_id — cannot identify the user"))?;

        // Fetch installation metadata (account login/type, permissions) from GitHub.
        let now = chrono::Utc::now().timestamp();
        let info = app
            .client
            .get_installation(cb.installation_id, now)
            .await
            .context("fetch GitHub installation metadata")?;

        let repo = GithubAppInstallationRepository::new(self.db_pool.clone());
        let stored = repo
            .upsert(
                user_id,
                cb.installation_id,
                &info.account_login,
                info.account_type.as_deref(),
                Some(&info.permissions),
                info.repository_selection.as_deref(),
            )
            .await
            .context("persist GitHub installation")?;

        Ok(SetupOutcome {
            account_login: stored.account_login,
        })
    }
}
