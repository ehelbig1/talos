//! Controller-side adapter implementing [`talos_workflow_engine_core::SecretsResolver`].
//!
//! Wraps [`SecretsManager`] and owns the lazy construction of an
//! [`OAuthCredentialService`] that refreshes short-lived tokens before
//! vault-path resolution. Keeping this here — rather than inside
//! `SecretsManager` or inside the workflow engine — means:
//!
//! * `SecretsManager` stays a pure storage concern.
//! * The workflow engine no longer depends on `SecretsManager`,
//!   `OAuthCredentialService`, or `talos_workflow_job_protocol` LLM-path constants; it
//!   only talks to the trait.
//! * Consumers outside Talos can implement the same trait with a
//!   completely different backing store (HashiCorp Vault, static test
//!   map, etc.) without touching this file.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use talos_workflow_engine_core::{BoxError, GithubInstallationTokenProvider, SecretsResolver};
use uuid::Uuid;

use crate::OAuthCredentialService;
use talos_secrets_manager::SecretsManager;

/// Secret-path scheme that resolves to a GitHub App installation token
/// (RFC 0008 B4): `github_app:<owner>`.
const GITHUB_APP_SCHEME: &str = "github_app:";

/// Process-wide GitHub App installation-token provider, injected once at
/// controller startup via [`set_github_installation_token_provider`]. The App is
/// a deployment singleton (one App config), so a set-once global is the
/// least-invasive injection — threading a `dyn` through every engine-builder
/// call site would touch the whole dispatch tree. Unset (tests, App disabled) →
/// `github_app:` paths simply aren't resolved (fail-safe).
static GITHUB_PROVIDER: OnceLock<Arc<dyn GithubInstallationTokenProvider>> = OnceLock::new();

/// Inject the GitHub App installation-token provider (RFC 0008 B4). Idempotent:
/// the first call wins; later calls are ignored.
pub fn set_github_installation_token_provider(provider: Arc<dyn GithubInstallationTokenProvider>) {
    let _ = GITHUB_PROVIDER.set(provider);
}

/// Adapter exposing [`SecretsManager`] through the
/// [`SecretsResolver`] trait.
///
/// OAuth refresh is performed lazily on first use: construction is
/// cheap, and callers that never touch vault paths never pay the cost
/// of building an [`OAuthCredentialService`]. Once constructed, the
/// service is reused for the lifetime of this resolver.
pub struct ControllerSecretsResolver {
    sm: Arc<SecretsManager>,
    oauth: OnceLock<Arc<OAuthCredentialService>>,
}

impl ControllerSecretsResolver {
    /// Build a resolver that will lazily construct its own OAuth
    /// credential service from the [`SecretsManager`]'s backing pool.
    #[must_use]
    pub fn new(sm: Arc<SecretsManager>) -> Self {
        Self {
            sm,
            oauth: OnceLock::new(),
        }
    }

    /// Build a resolver backed by a caller-supplied OAuth service.
    ///
    /// Prefer this over [`new`](Self::new) when the caller already has
    /// an [`OAuthCredentialService`] in hand — it avoids duplicating
    /// that service's internal per-credential locks.
    #[must_use]
    pub fn with_oauth(sm: Arc<SecretsManager>, oauth: Arc<OAuthCredentialService>) -> Self {
        let lock = OnceLock::new();
        // Ignore: set() only fails if already set, which is impossible for a freshly constructed lock.
        let _ = lock.set(oauth);
        Self { sm, oauth: lock }
    }

    fn oauth_service(&self) -> Arc<OAuthCredentialService> {
        if let Some(oc) = self.oauth.get() {
            return oc.clone();
        }
        let svc = Arc::new(OAuthCredentialService::new(
            self.sm.db_pool().clone(),
            self.sm.clone(),
        ));
        // If another thread raced us, keep whichever value won so both
        // threads end up using the same service instance.
        let _ = self.oauth.set(svc.clone());
        self.oauth.get().cloned().unwrap_or(svc)
    }
}

fn boxed(err: impl std::fmt::Display) -> BoxError {
    err.to_string().into()
}

#[async_trait]
impl SecretsResolver for ControllerSecretsResolver {
    async fn resolve_module_secrets(
        &self,
        node_id: Uuid,
    ) -> Result<HashMap<String, String>, BoxError> {
        self.sm.get_module_secrets(node_id).await.map_err(boxed)
    }

    async fn resolve_by_paths(
        &self,
        paths: &[String],
        user_id: Option<Uuid>,
    ) -> Result<HashMap<String, String>, BoxError> {
        // RFC 0008 B4: split `github_app:<owner>` paths from ordinary vault
        // paths. The App tokens are minted on demand; everything else resolves
        // through SecretsManager exactly as before.
        let (github_paths, vault_paths): (Vec<String>, Vec<String>) = paths
            .iter()
            .cloned()
            .partition(|p| p.starts_with(GITHUB_APP_SCHEME));

        let mut out = if vault_paths.is_empty() {
            HashMap::new()
        } else {
            self.sm
                .get_secrets_by_paths(&vault_paths, user_id)
                .await
                .map_err(boxed)?
        };

        if !github_paths.is_empty() {
            // App tokens are a PER-USER credential: only mint for installations
            // the execution's own user set up. Without a `user_id` we cannot
            // verify ownership, so fail closed (don't inject) rather than mint a
            // token against whichever user happens to own the matching install.
            match (GITHUB_PROVIDER.get(), user_id) {
                (Some(provider), Some(uid)) => {
                    for path in github_paths {
                        let owner = &path[GITHUB_APP_SCHEME.len()..];
                        match provider.installation_token(owner, uid).await {
                            // Key by the full `github_app:<owner>` path: that's
                            // what the module reads via get_secret(...).
                            Ok(Some(token)) => {
                                out.insert(path.clone(), token);
                            }
                            Ok(None) => tracing::warn!(
                                %owner,
                                "no active GitHub App installation owned by this user; github_app secret not injected (module will fail closed)"
                            ),
                            Err(e) => tracing::error!(
                                %owner,
                                error = %e,
                                "GitHub App installation-token mint failed"
                            ),
                        }
                    }
                }
                (Some(_), None) => tracing::warn!(
                    count = github_paths.len(),
                    "github_app:<owner> secret requested without a user context; not injected (fail closed — App tokens are per-user)"
                ),
                (None, _) => tracing::warn!(
                    count = github_paths.len(),
                    "github_app:<owner> secret requested but no GitHub App provider is configured"
                ),
            }
        }

        Ok(out)
    }

    async fn resolve_llm_keys(
        &self,
        user_id: Option<Uuid>,
    ) -> Result<HashMap<String, String>, BoxError> {
        // SecretsManager returns Zeroizing<String> values for the cache; the
        // SecretsResolver trait is defined in the open-source workflow engine
        // crate and cannot depend on the zeroize crate, so we deref-clone here.
        // The cache copy stays zeroized; the returned plaintext lives only as
        // long as the engine's `encrypt_into_job` consumes it (microseconds).
        let zeroizing_map = self.sm.get_llm_vault_keys(user_id).await.map_err(boxed)?;
        Ok(zeroizing_map
            .into_iter()
            .map(|(k, v)| (k, v.as_str().to_string()))
            .collect())
    }

    async fn refresh_vault_paths(&self, paths: &[String]) {
        if paths.is_empty() {
            return;
        }
        self.oauth_service()
            .refresh_oauth_tokens_in_batch(paths)
            .await;
    }
}
