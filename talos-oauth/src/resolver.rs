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
// The `gcp/impersonated/...` mint path (Phase D) has ONE home for its two
// forms; this file only asks it what a path means.
use talos_workflow_engine_core::MintReadiness;
use talos_workflow_job_protocol::{dispatch_mint, DispatchMint, MintScheme};

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

/// What can be said about a mint path without minting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MintCheck {
    /// The path is taken as a mint path but is not a form the minter reads.
    /// Nothing is minted for it and nothing stored at it is read.
    Malformed(MintScheme),
    /// The provider's answer.
    Answered(MintScheme, MintReadiness),
    /// The provider could not be asked (its read failed). Not evidence of
    /// anything; the failure is logged here.
    Unreadable(MintScheme),
}

impl MintCheck {
    /// Would a dispatch have a connection to mint this path from? `false`
    /// for an unreadable check: an unknown is not a pass.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Answered(_, MintReadiness::Ready))
    }

    /// Which mint the path belongs to.
    #[must_use]
    pub fn scheme(&self) -> MintScheme {
        match self {
            Self::Malformed(s) | Self::Answered(s, _) | Self::Unreadable(s) => *s,
        }
    }
}

/// For a diagnostic: could `path` be minted for `user_id` at dispatch?
///
/// `None` when `path` is not a mint path at all (an ordinary stored secret:
/// ask the vault). Otherwise the answer of the provider that would mint it,
/// asked through the same process-wide provider the dispatch uses.
///
/// This never mints, refreshes or reads a token, and makes no outbound call.
/// Tenancy is the provider's: it is asked about `user_id` only, and a
/// connection key that is not that user's reads exactly as one that does not
/// exist ([`MintReadiness::NamedConnectionNotUsable`]).
pub async fn check_mint(path: &str, user_id: Uuid) -> Option<MintCheck> {
    let mint = dispatch_mint(path)?;
    let scheme = mint.scheme();
    let answered = match mint {
        DispatchMint::Malformed(_) => return Some(MintCheck::Malformed(scheme)),
        DispatchMint::GithubApp { owner } => match GITHUB_PROVIDER.get() {
            Some(provider) => provider.mint_readiness(owner, user_id).await,
            None => Ok(MintReadiness::NotConfigured),
        },
        DispatchMint::GcpImpersonated(target) => match GCP_IMPERSONATION_PROVIDER.get() {
            Some(provider) => provider.mint_readiness(target.connection, user_id).await,
            None => Ok(MintReadiness::NotConfigured),
        },
    };
    Some(match answered {
        Ok(readiness) => MintCheck::Answered(scheme, readiness),
        Err(e) => {
            // The path is not logged: it names a service account or an owner.
            tracing::warn!(error = %e, ?scheme, "mint readiness could not be read");
            MintCheck::Unreadable(scheme)
        }
    })
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
        module_id: Uuid,
        user_id: Option<Uuid>,
    ) -> Result<talos_workflow_engine_core::SecretMap, BoxError> {
        self.sm
            .get_module_secrets_for(module_id, user_id)
            .await
            .map_err(boxed)
    }

    async fn resolve_by_paths(
        &self,
        paths: &[String],
        user_id: Option<Uuid>,
    ) -> Result<talos_workflow_engine_core::SecretMap, BoxError> {
        // Mint-on-dispatch schemes are partitioned OUT of the vault lookup:
        // they have nothing stored to fetch. Everything else resolves through
        // SecretsManager exactly as before.
        //   - `github_app:<owner>`                    (RFC 0008 B4)
        //   - `gcp/impersonated/<sa>/access_token`    (Phase D)
        let mut github_paths: Vec<String> = Vec::new();
        let mut gcp_impersonated_paths: Vec<String> = Vec::new();
        let mut vault_paths: Vec<String> = Vec::new();
        // Which paths are mints is asked of the ONE recogniser
        // (`dispatch_mint`), the same one the diagnostic tools ask, so a tool
        // can never call a path "stored" that this function will not look up.
        for p in paths {
            match dispatch_mint(p).map(|m| m.scheme()) {
                Some(MintScheme::GithubApp) => github_paths.push(p.clone()),
                Some(MintScheme::GcpImpersonated) => gcp_impersonated_paths.push(p.clone()),
                None => vault_paths.push(p.clone()),
            }
        }

        let mut out = if vault_paths.is_empty() {
            HashMap::new()
        } else {
            self.sm
                .get_secrets_by_paths(
                    &vault_paths,
                    user_id,
                    talos_secrets_manager::PathReadAudit::Dispatch,
                )
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
                        let Some(DispatchMint::GithubApp { owner }) = dispatch_mint(&path) else {
                            // `github_app:` with no owner.
                            tracing::warn!(
                                "malformed github_app path; not injected (fail closed)"
                            );
                            continue;
                        };
                        match provider.installation_token(owner, uid).await {
                            // Key by the full `github_app:<owner>` path: that's
                            // what the module reads via get_secret(...).
                            Ok(Some(token)) => {
                                out.insert(path.clone(), zeroize::Zeroizing::new(token));
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
                        let Some(DispatchMint::GcpImpersonated(target)) = dispatch_mint(&path)
                        else {
                            tracing::warn!(
                                "malformed gcp/impersonated path; not injected (fail closed)"
                            );
                            continue;
                        };
                        match provider
                            .impersonated_token(
                                target.service_account_email,
                                target.connection,
                                uid,
                            )
                            .await
                        {
                            // Key by the full requested path: that's what the
                            // module reads via get_secret(...), and what its
                            // `gcp/impersonated/*` allowed_secrets grant covers.
                            Ok(Some(token)) => {
                                out.insert(path.clone(), zeroize::Zeroizing::new(token));
                            }
                            Ok(None) => tracing::warn!(
                                named_connection = target.connection.is_some(),
                                "no single google_cloud_full consent to mint from for this user (none, several with none named, or the named one is not theirs); gcp impersonated token not injected (module fails closed)"
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
    ) -> Result<talos_workflow_engine_core::SecretMap, BoxError> {
        // The cache's `Zeroizing` values, handed on unchanged (C2-4): no
        // plain copy of a provider key is made between the store and the seal.
        self.sm.get_llm_vault_keys(user_id).await.map_err(boxed)
    }

    async fn refresh_vault_paths(&self, paths: &[String]) {
        if paths.is_empty() {
            return;
        }
        self.oauth_service()
            .refresh_oauth_tokens_in_batch(paths)
            .await;
    }

    async fn force_refresh_vault_paths(
        &self,
        paths: &[String],
    ) -> talos_workflow_engine_core::ForcedRefresh {
        if paths.is_empty() {
            return talos_workflow_engine_core::ForcedRefresh::NothingToRefresh;
        }
        // Routed through the SAME `OAuthCredentialService` as the predictive
        // path, so a reactive repair is still a vault write on the audited
        // credential path — it does not get its own token-endpoint call site
        // or its own way into the secrets table.
        self.oauth_service()
            .force_refresh_oauth_tokens_in_batch(paths)
            .await
    }
}

#[cfg(test)]
mod check_mint_tests {
    use super::{check_mint, MintCheck};
    use talos_workflow_engine_core::MintReadiness;
    use talos_workflow_job_protocol::MintScheme;
    use uuid::Uuid;

    /// No provider is injected in this test binary, which is the state of a
    /// deployment with neither integration configured.
    #[tokio::test]
    async fn a_stored_path_is_not_checked_and_a_mint_path_never_reads_as_stored() {
        let user = Uuid::from_u128(1);

        // An ordinary path: not a mint, so the caller asks the vault.
        for path in ["jira/api_token", "gcp/impersonated/someone/refresh_token"] {
            assert_eq!(check_mint(path, user).await, None, "{path}");
        }

        // A mint path the minter cannot read.
        let malformed = check_mint("gcp/impersonated//access_token", user)
            .await
            .expect("a mint path");
        assert_eq!(malformed, MintCheck::Malformed(MintScheme::GcpImpersonated));
        assert!(!malformed.is_ready());

        // A well-formed one with nothing configured to mint it.
        for (path, scheme) in [
            (
                "gcp/impersonated/runner@example-project.iam.gserviceaccount.com/access_token",
                MintScheme::GcpImpersonated,
            ),
            ("github_app:example-org", MintScheme::GithubApp),
        ] {
            let check = check_mint(path, user).await.expect("a mint path");
            assert_eq!(
                check,
                MintCheck::Answered(scheme, MintReadiness::NotConfigured),
                "{path}"
            );
            assert!(!check.is_ready());
            assert_eq!(check.scheme(), scheme);
        }
    }
}

/// The paths a module run OUTSIDE a workflow may have resolved for it:
/// `test_module`, `run_sandbox`, a module replay.
///
/// `wanted` is everything the run would like (its grant list plus any
/// `vault://` reference found in its payload). `granted` is the grant the run
/// is ENTITLED to: the module's own `allowed_secrets`, or for inline code the
/// list its caller declared. Two rules:
///
/// * a STORED path is returned as it was asked for. These surfaces have
///   always fetched a referenced stored secret for the caller's own user,
///   and what the guest may then do with it is decided where it runs, by
///   the grant list in its security context;
/// * a MINT path ([`dispatch_mint`]) is kept only when `granted` covers it.
///   A mint is an outbound call that creates a credential, so it needs the
///   grant a real dispatch of the module would need. A `vault://` reference
///   typed into a test's config is not a grant.
///
/// Order is kept and duplicates are dropped. Pure, so the rule is tested
/// without a database.
#[must_use]
pub fn standalone_run_paths(granted: &[String], wanted: &[String]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    wanted
        .iter()
        .filter(|path| {
            dispatch_mint(path).is_none()
                || talos_workflow_job_protocol::vault_path_permitted(granted, path)
        })
        .filter(|path| seen.insert(path.as_str()))
        .cloned()
        .collect()
}

/// A resolved map handed to the in-process runtime, whose secret provider
/// holds plain `String`s: the ONE place a standalone run's values leave the
/// zeroizing [`talos_workflow_engine_core::SecretMap`] (security review
/// 2026-10-14, C-10). A dispatch never does this — its map is sealed.
#[must_use]
pub fn into_runtime_secrets(map: talos_workflow_engine_core::SecretMap) -> HashMap<String, String> {
    map.into_iter().map(|(k, v)| (k, v.to_string())).collect()
}

/// Resolve the secrets of a module run outside a workflow, the way a
/// dispatch resolves them: stored paths from the vault, mint paths minted.
///
/// Until 2026-10-13 these surfaces asked the vault directly, so a module
/// that authenticates with a minted token (an impersonated Google Cloud
/// service account, a GitHub App installation) could not be rehearsed or
/// replayed on its own: nothing is stored at a mint path, the vault returned
/// nothing, and the run failed on a missing secret.
///
/// This is [`ControllerSecretsResolver::resolve_by_paths`] over
/// [`standalone_run_paths`]. So the tenancy is the dispatch's own: a mint is
/// made only for `user_id`, from that user's own connection, and with no
/// `user_id` nothing is minted at all.
///
/// # Errors
/// When the vault cannot be read. A mint that is refused or fails is not an
/// error: the path is simply absent from the map, as on a dispatch.
pub async fn resolve_for_standalone_run(
    sm: Arc<SecretsManager>,
    granted: &[String],
    wanted: &[String],
    user_id: Option<Uuid>,
) -> Result<talos_workflow_engine_core::SecretMap, BoxError> {
    let paths = standalone_run_paths(granted, wanted);
    if paths.is_empty() {
        return Ok(HashMap::new());
    }
    ControllerSecretsResolver::new(sm)
        .resolve_by_paths(&paths, user_id)
        .await
}

#[cfg(test)]
mod standalone_run_paths_tests {
    use super::standalone_run_paths;

    const SA: &str = "runner@example-project.iam.gserviceaccount.com";

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_string()).collect()
    }

    /// A stored path is fetched as before, granted or not: these tools have
    /// always resolved a referenced stored secret for the caller's own user.
    #[test]
    fn stored_paths_are_unchanged() {
        let wanted = s(&[
            "jira/api_token",
            "oauth/gmail/abc/access_token",
            "jira/api_token",
        ]);
        assert_eq!(
            standalone_run_paths(&[], &wanted),
            s(&["jira/api_token", "oauth/gmail/abc/access_token"]),
            "order kept, duplicates dropped, nothing withheld"
        );
    }

    /// A mint needs the grant a dispatch would need. A `vault://` reference
    /// in a test's config puts the path in `wanted`; it does not grant it.
    #[test]
    fn a_mint_path_is_resolved_only_when_the_grant_covers_it() {
        let plain = format!("gcp/impersonated/{SA}/access_token");
        let named =
            format!("gcp/impersonated/{SA}/as/0b7b0f0e-4c1d-4a57-9d2e-3f6a1c2b9e10/access_token");
        let other =
            "gcp/impersonated/someone-else@example-project.iam.gserviceaccount.com/access_token"
                .to_string();
        let github = "github_app:example-org".to_string();
        let wanted = vec![
            "jira/api_token".to_string(),
            plain.clone(),
            named.clone(),
            other.clone(),
            github.clone(),
        ];

        // No grant: only the stored path.
        assert_eq!(standalone_run_paths(&[], &wanted), s(&["jira/api_token"]));

        // The exact path: that one mint, and no other.
        assert_eq!(
            standalone_run_paths(&s(&[&plain]), &wanted),
            vec!["jira/api_token".to_string(), plain.clone()]
        );

        // A grant on one service account does not reach another's token, and
        // a Google grant does not reach a GitHub one.
        let one_account = s(&[&format!("gcp/impersonated/{SA}")]);
        assert_eq!(
            standalone_run_paths(&one_account, &wanted),
            vec!["jira/api_token".to_string(), plain.clone(), named.clone()]
        );

        // The namespace, and the GitHub scheme by its exact entry.
        let both = s(&["gcp/impersonated/*", "github_app:example-org"]);
        assert_eq!(standalone_run_paths(&both, &wanted), wanted);
        assert_eq!(
            standalone_run_paths(&s(&["github_app:another-org"]), &wanted),
            s(&["jira/api_token"])
        );
    }
}
