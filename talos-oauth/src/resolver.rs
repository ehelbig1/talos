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
use talos_workflow_engine_core::{
    BoxError, GcpImpersonationTokenProvider, GithubInstallationTokenProvider, SecretsResolver,
};
use uuid::Uuid;

use crate::OAuthCredentialService;
use talos_secrets_manager::SecretsManager;

/// Secret-path scheme that resolves to a GitHub App installation token
/// (RFC 0008 B4): `github_app:<owner>`.
const GITHUB_APP_SCHEME: &str = "github_app:";

/// Secret-path prefix that resolves to a minted GCP impersonated
/// service-account access token (Phase D):
/// `gcp/impersonated/<service_account_email>/access_token`.
const GCP_IMPERSONATED_PREFIX: &str = "gcp/impersonated/";
/// Required suffix — only `.../access_token` is a mint target (guards a
/// typo'd path from being silently treated as a mintable secret).
const GCP_IMPERSONATED_SUFFIX: &str = "/access_token";

/// Process-wide GitHub App installation-token provider, injected once at
/// controller startup via [`set_github_installation_token_provider`]. The App is
/// a deployment singleton (one App config), so a set-once global is the
/// least-invasive injection — threading a `dyn` through every engine-builder
/// call site would touch the whole dispatch tree. Unset (tests, App disabled) →
/// `github_app:` paths simply aren't resolved (fail-safe).
static GITHUB_PROVIDER: OnceLock<Arc<dyn GithubInstallationTokenProvider>> = OnceLock::new();

/// Process-wide GCP impersonation-token provider (Phase D), injected once at
/// controller startup via [`set_gcp_impersonation_token_provider`]. Same
/// set-once-global rationale as [`GITHUB_PROVIDER`]: the broad consent + IAM
/// Credentials client are a deployment singleton. Unset (tests, GCP not
/// configured) → `gcp/impersonated/*` paths simply aren't resolved (fail-safe:
/// the module fails closed on the missing secret).
static GCP_IMPERSONATION_PROVIDER: OnceLock<Arc<dyn GcpImpersonationTokenProvider>> =
    OnceLock::new();

/// Inject the GitHub App installation-token provider (RFC 0008 B4). Idempotent:
/// the first call wins; later calls are ignored.
pub fn set_github_installation_token_provider(provider: Arc<dyn GithubInstallationTokenProvider>) {
    let _ = GITHUB_PROVIDER.set(provider);
}

/// Inject the GCP impersonation-token provider (Phase D). Idempotent: the
/// first call wins; later calls are ignored.
pub fn set_gcp_impersonation_token_provider(provider: Arc<dyn GcpImpersonationTokenProvider>) {
    let _ = GCP_IMPERSONATION_PROVIDER.set(provider);
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

/// Extract the impersonation target (service-account email) from a
/// `gcp/impersonated/<sa_email>/access_token` path, or `None` if the path
/// isn't a well-formed mint target. SA emails never contain `/`, so the
/// segment between the fixed prefix and suffix is exactly the target; a `/`
/// inside it (extra path segments) or an empty target is rejected so a
/// malformed path can never be silently treated as a mintable secret.
fn parse_impersonation_target(path: &str) -> Option<&str> {
    let inner = path
        .strip_prefix(GCP_IMPERSONATED_PREFIX)?
        .strip_suffix(GCP_IMPERSONATED_SUFFIX)?;
    if inner.is_empty() || inner.contains('/') {
        return None;
    }
    Some(inner)
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
        // Mint-on-dispatch schemes are partitioned OUT of the vault lookup:
        // they have nothing stored to fetch. Everything else resolves through
        // SecretsManager exactly as before.
        //   - `github_app:<owner>`                    (RFC 0008 B4)
        //   - `gcp/impersonated/<sa>/access_token`    (Phase D)
        let mut github_paths: Vec<String> = Vec::new();
        let mut gcp_impersonated_paths: Vec<String> = Vec::new();
        let mut vault_paths: Vec<String> = Vec::new();
        for p in paths {
            if p.starts_with(GITHUB_APP_SCHEME) {
                github_paths.push(p.clone());
            } else if p.starts_with(GCP_IMPERSONATED_PREFIX) && p.ends_with(GCP_IMPERSONATED_SUFFIX)
            {
                gcp_impersonated_paths.push(p.clone());
            } else {
                vault_paths.push(p.clone());
            }
        }

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

        if !gcp_impersonated_paths.is_empty() {
            // Impersonated tokens are minted from the requesting user's broad
            // `google_cloud_full` consent, so they are a PER-USER credential.
            // Without a `user_id` we cannot identify whose consent to mint
            // from — fail closed (don't inject) rather than mint against
            // whichever user happens to own a full-tier consent.
            match (GCP_IMPERSONATION_PROVIDER.get(), user_id) {
                (Some(provider), Some(uid)) => {
                    for path in gcp_impersonated_paths {
                        let Some(sa_email) = parse_impersonation_target(&path) else {
                            tracing::warn!(
                                "malformed gcp/impersonated path; not injected (fail closed)"
                            );
                            continue;
                        };
                        match provider.impersonated_token(sa_email, uid).await {
                            // Key by the full requested path: that's what the
                            // module reads via get_secret(...), and what its
                            // `gcp/impersonated/*` allowed_secrets grant covers.
                            Ok(Some(token)) => {
                                out.insert(path.clone(), token);
                            }
                            Ok(None) => tracing::warn!(
                                "no google_cloud_full consent / impersonation not permitted for this user; gcp impersonated token not injected (module fails closed)"
                            ),
                            Err(e) => tracing::error!(
                                error = %e,
                                "GCP impersonated-token mint failed"
                            ),
                        }
                    }
                }
                (Some(_), None) => tracing::warn!(
                    count = gcp_impersonated_paths.len(),
                    "gcp/impersonated secret requested without a user context; not injected (fail closed — impersonated tokens are per-user)"
                ),
                (None, _) => tracing::warn!(
                    count = gcp_impersonated_paths.len(),
                    "gcp/impersonated secret requested but no GCP impersonation provider is configured"
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

#[cfg(test)]
mod impersonation_path_tests {
    use super::parse_impersonation_target;

    #[test]
    fn extracts_well_formed_sa_email() {
        assert_eq!(
            parse_impersonation_target(
                "gcp/impersonated/talos-runner@sandbox.iam.gserviceaccount.com/access_token"
            ),
            Some("talos-runner@sandbox.iam.gserviceaccount.com")
        );
    }

    #[test]
    fn rejects_malformed_targets() {
        // Empty target.
        assert_eq!(
            parse_impersonation_target("gcp/impersonated//access_token"),
            None
        );
        // Extra path segments (a `/` inside the "email") — never a real SA,
        // and would let a crafted path smuggle structure into the mint call.
        assert_eq!(
            parse_impersonation_target("gcp/impersonated/a/b/access_token"),
            None
        );
        // Wrong suffix — only `.../access_token` is a mint target.
        assert_eq!(
            parse_impersonation_target("gcp/impersonated/sa@x.com/refresh_token"),
            None
        );
        // Not the impersonation namespace at all.
        assert_eq!(
            parse_impersonation_target("oauth/google_cloud_full/u/k/access_token"),
            None
        );
    }
}
