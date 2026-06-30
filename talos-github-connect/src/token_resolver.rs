//! Outbound GitHub App token resolution for modules (RFC 0008 B4).
//!
//! GitHub modules (e.g. `github-pr-reviewer`) authenticate by reading a secret
//! path (`GITHUB_TOKEN_SECRET`) and sending `Authorization: Bearer <value>`. B4
//! lets that value be a **short-lived App installation token** instead of a
//! long-lived PAT, chosen explicitly per module via a secret-path scheme:
//!
//! * `github_app:<owner>` → the controller mints an installation token for the
//!   GitHub account `<owner>` (D6 "prefer the App token for the repo's owner").
//! * any other path → unchanged (the PAT / vault secret).
//!
//! This module provides the resolver ([`GithubTokenResolver`]) and the
//! path-scheme parser ([`parse_github_app_secret_path`]). **B4-wiring** — calling
//! the resolver from the controller's per-module secret prefetch
//! (`build_encrypted_secrets`) and injecting the token under the module's
//! token-secret key — is the remaining step (it touches the security-critical
//! secret-prefetch path and is best validated against a live workflow run).

use anyhow::{anyhow, Context, Result};
use sqlx::PgPool;
use zeroize::Zeroizing;

use talos_github::{GithubAppConfig, InstallationTokenCache};
use talos_github_repository::GithubAppInstallationRepository;

/// The secret-path scheme that opts a module into App-token auth.
pub const GITHUB_APP_SCHEME: &str = "github_app:";

/// If `secret_path` uses the App-token scheme (`github_app:<owner>`), return the
/// `<owner>` login; otherwise `None` (a normal PAT / vault path, left untouched).
///
/// The owner must be a non-empty GitHub login (ASCII alphanumeric + hyphen) so a
/// malformed path can't smuggle arbitrary text into the lookup.
pub fn parse_github_app_secret_path(secret_path: &str) -> Option<&str> {
    secret_path.strip_prefix(GITHUB_APP_SCHEME).filter(|owner| {
        !owner.is_empty()
            && owner
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

/// Resolves App installation tokens for a repo owner, composing the installation
/// registry (B2a) with the minting cache (B3).
pub struct GithubTokenResolver {
    repo: GithubAppInstallationRepository,
    // `None` when GitHub App support isn't configured → resolution always yields
    // `None` so callers fall back to the PAT.
    cache: Option<InstallationTokenCache>,
}

impl GithubTokenResolver {
    /// Build from the resolved platform config (`None` = App not configured).
    pub fn new(db_pool: PgPool, config: Option<GithubAppConfig>) -> Self {
        let cache = config.and_then(|c| match c.client() {
            Ok(client) => Some(InstallationTokenCache::new(client)),
            Err(e) => {
                tracing::error!(error = %e, "GitHub App configured but client build failed; token resolution disabled");
                None
            }
        });
        Self {
            repo: GithubAppInstallationRepository::new(db_pool),
            cache,
        }
    }

    pub fn is_configured(&self) -> bool {
        self.cache.is_some()
    }

    /// Resolve an installation token for a GitHub account `owner`.
    ///
    /// * `Ok(None)` — App not configured, or no active installation for `owner`
    ///   → the caller should fall back to the PAT (D6).
    /// * `Ok(Some(token))` — a fresh (cached / re-minted) installation token.
    /// * `Err` — an active installation exists but minting failed (don't silently
    ///   fall back: surface it so a broken App config is visible, rather than
    ///   masquerading as "no installation").
    pub async fn token_for_owner(&self, owner: &str) -> Result<Option<Zeroizing<String>>> {
        let Some(cache) = self.cache.as_ref() else {
            return Ok(None);
        };
        let Some(installation) = self
            .repo
            .get_active_by_account(owner)
            .await
            .with_context(|| format!("look up GitHub App installation for {owner}"))?
        else {
            return Ok(None);
        };

        let now = chrono::Utc::now().timestamp();
        let token = cache
            .get_token(installation.installation_id, now)
            .await
            .map_err(|e| anyhow!("mint installation token for {owner}: {e:#}"))?;
        Ok(Some(token))
    }
}

/// Bridge to the engine's secret-resolution path (B4-wiring): a module secret
/// path `github_app:<owner>` resolves to an installation token. The provider
/// trait lives in `talos-workflow-engine-core` so the resolver crate can hold a
/// `dyn` reference without depending on this crate (no cycle).
#[async_trait::async_trait]
impl talos_workflow_engine_core::GithubInstallationTokenProvider for GithubTokenResolver {
    async fn installation_token(
        &self,
        owner: &str,
    ) -> Result<Option<String>, talos_workflow_engine_core::BoxError> {
        match self.token_for_owner(owner).await {
            // Deref the zeroizing buffer to a plaintext String — same pattern as
            // ControllerSecretsResolver::resolve_llm_keys. It lives only until the
            // engine seals it into the job's encrypted_secrets (microseconds).
            Ok(Some(token)) => Ok(Some(token.as_str().to_string())),
            Ok(None) => Ok(None),
            Err(e) => Err(format!("{e:#}").into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_app_scheme() {
        assert_eq!(
            parse_github_app_secret_path("github_app:ehelbig1"),
            Some("ehelbig1")
        );
        assert_eq!(
            parse_github_app_secret_path("github_app:my-org"),
            Some("my-org")
        );
    }

    #[test]
    fn ignores_non_app_paths() {
        assert_eq!(parse_github_app_secret_path("github/token"), None);
        assert_eq!(parse_github_app_secret_path("llm/api_key"), None);
        assert_eq!(parse_github_app_secret_path("vault://github/token"), None);
    }

    #[test]
    fn rejects_malformed_owner() {
        assert_eq!(parse_github_app_secret_path("github_app:"), None);
        assert_eq!(parse_github_app_secret_path("github_app:has spaces"), None);
        assert_eq!(parse_github_app_secret_path("github_app:owner/repo"), None);
        assert_eq!(parse_github_app_secret_path("github_app:../etc"), None);
    }
}
