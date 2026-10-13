//! Pluggable secret resolution for node dispatch.
//!
//! The executor does not talk to a vault, a database, or an OAuth
//! provider. It delegates every secret lookup to a [`SecretsResolver`]
//! implementation supplied by the consumer. This lets a single engine
//! crate serve a production deployment (where secrets live in an
//! envelope-encrypted Postgres column and OAuth tokens need refreshing
//! before use) and a test harness (where an `InMemorySecrets` impl
//! returns a hardcoded map) without the engine learning about either.

use std::collections::HashMap;

use async_trait::async_trait;
use uuid::Uuid;

/// Type-erased error returned by [`SecretsResolver`] methods.
///
/// The trait is agnostic about the concrete error type an implementation
/// uses — a boxed `std::error::Error` lets impls propagate their own
/// error types (`sqlx::Error`, OAuth errors, etc.) without the trait
/// crate having to know about them.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// What a reactive credential refresh
/// ([`SecretsResolver::force_refresh_vault_paths`]) amounted to.
///
/// Only [`Refreshed`](Self::Refreshed) authorises a retry. The others are
/// separate because they ask different things of an operator: a refusal
/// means a person has to re-authorise the connection; an unreachable
/// provider means nothing is wrong with the connection and the next run will
/// try again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForcedRefresh {
    /// At least one path now holds a NEW credential.
    Refreshed,
    /// The provider REFUSED the refresh: the grant is revoked or expired.
    /// The connection must be re-authorised by a person.
    RefusedByProvider,
    /// The provider's token endpoint could not be reached, or answered with
    /// a server-side error. The connection is not at fault.
    ProviderUnreachable,
    /// The refresh was attempted and failed in some other way (a credential
    /// row that could not be read, a response that could not be parsed).
    Failed,
    /// There was nothing refreshable among the paths: not an OAuth access
    /// token, or a provider with no refresh endpoint.
    NothingToRefresh,
}

impl ForcedRefresh {
    /// Whether a NEW credential was stored, i.e. whether a retry is
    /// authorised.
    #[must_use]
    pub const fn refreshed(self) -> bool {
        matches!(self, Self::Refreshed)
    }

    /// The outcome of refreshing SEVERAL credentials, from each one's own.
    ///
    /// One new credential is enough to retry. Otherwise the outcome that
    /// asks the most of a person wins: a refusal over an unreachable
    /// provider over another failure.
    #[must_use]
    pub fn of_all(outcomes: impl IntoIterator<Item = Self>) -> Self {
        let rank = |outcome: Self| match outcome {
            Self::Refreshed => 4,
            Self::RefusedByProvider => 3,
            Self::ProviderUnreachable => 2,
            Self::Failed => 1,
            Self::NothingToRefresh => 0,
        };
        outcomes
            .into_iter()
            .max_by_key(|outcome| rank(*outcome))
            .unwrap_or(Self::NothingToRefresh)
    }

    /// What to tell the operator when the refresh did not produce a new
    /// credential, as a clause that follows "the OAuth credential could not
    /// be refreshed: ". `None` for [`Refreshed`](Self::Refreshed).
    ///
    /// No provider or account is named: for some providers the vault path's
    /// key IS the user's e-mail address, and this text is stored on the
    /// execution.
    #[must_use]
    pub const fn operator_note(self) -> Option<&'static str> {
        match self {
            Self::Refreshed => None,
            Self::RefusedByProvider => Some(
                "the provider refused it, so the grant is revoked or expired; \
                 re-authorise the integration. Not retried",
            ),
            Self::ProviderUnreachable => Some(
                "the provider's token endpoint could not be reached, so nothing is wrong with \
                 the integration itself and it does NOT need re-authorising; the next run will \
                 try again. Not retried",
            ),
            Self::Failed => Some(
                "the refresh failed before the provider gave an answer (the reason is in the \
                 controller log, target talos_oauth_refresh). Not retried",
            ),
            Self::NothingToRefresh => Some(
                "this credential has no refresh path, so the rejection is not a stale token. \
                 Not retried",
            ),
        }
    }
}

/// Resolves the secrets needed to dispatch a workflow node.
///
/// # Method breakdown
///
/// - [`resolve_module_secrets`](Self::resolve_module_secrets) returns
///   secrets explicitly granted to a single node (e.g. via an
///   `allowed_secrets` ACL).
/// - [`resolve_by_paths`](Self::resolve_by_paths) resolves arbitrary
///   vault-style paths referenced by a node's configuration (e.g.
///   `vault://service/token` expressions in HTTP-header templates).
/// - [`resolve_llm_keys`](Self::resolve_llm_keys) returns canonical
///   LLM-provider API keys that the executor injects into every job
///   automatically.
/// - [`refresh_vault_paths`](Self::refresh_vault_paths) is an
///   optional hook invoked before path resolution, giving impls a
///   chance to refresh short-lived credentials (OAuth access tokens,
///   etc.) before they are read.
///
/// # Semantics
///
/// Methods that return `HashMap` return plaintext values. Any envelope
/// encryption for wire transmission is a concern of the dispatcher, not
/// of the resolver. Impls should treat failures per-category: a
/// resolver error on `resolve_module_secrets` does not necessarily
/// imply `resolve_by_paths` would also fail.
#[async_trait]
pub trait SecretsResolver: Send + Sync {
    /// Return the secrets explicitly granted to the node identified by
    /// `node_id` (for example, secrets listed in its `allowed_secrets`
    /// grant). Returns an empty map when the node has no grants.
    async fn resolve_module_secrets(
        &self,
        node_id: Uuid,
    ) -> Result<HashMap<String, String>, BoxError>;

    /// Resolve a batch of vault paths for a given user. `user_id` is
    /// `None` for system-scoped or actor-scoped lookups; impls may
    /// reject or silently filter such cases as they see fit.
    async fn resolve_by_paths(
        &self,
        paths: &[String],
        user_id: Option<Uuid>,
    ) -> Result<HashMap<String, String>, BoxError>;

    /// Return the canonical set of LLM-provider API keys for `user_id`.
    ///
    /// Impls propagate backing-store errors through the `Err` arm; the
    /// executor decides the policy (a common choice is to swallow and
    /// log so a missing or broken LLM-key vault doesn't fail unrelated
    /// nodes). Returning an empty `Ok(HashMap)` is correct when the
    /// user has no LLM keys configured.
    ///
    /// The default body returns an empty map — useful for consumers
    /// running with `default-features = false` (no `llm-primitives`)
    /// and for in-process executors that don't orchestrate LLM
    /// workflows at all. Override when the resolver backs onto an
    /// LLM-key store.
    async fn resolve_llm_keys(
        &self,
        _user_id: Option<Uuid>,
    ) -> Result<HashMap<String, String>, BoxError> {
        Ok(HashMap::new())
    }

    /// Optional pre-fetch hook invoked with the vault paths about to be
    /// resolved. Impls can use this to refresh short-lived credentials
    /// (e.g. OAuth access tokens) before the paths are read.
    ///
    /// The default implementation is a no-op, which is correct for any
    /// resolver whose backing store holds only long-lived secrets. Impls
    /// backed by short-lived tokens **must** override this; the engine
    /// guarantees it is awaited before
    /// [`resolve_by_paths`](Self::resolve_by_paths), so a refresh here
    /// is observable by the subsequent read.
    ///
    /// Errors are intentionally swallowed at this layer — a failed
    /// refresh should not fail the node before `resolve_by_paths` has
    /// had a chance to return the last-known-good value. Impls should
    /// log internally.
    async fn refresh_vault_paths(&self, _paths: &[String]) {}

    /// Optional **reactive** repair hook, invoked only after a dispatched job
    /// has already failed with what looks like an authentication failure on a
    /// credential this resolver owns.
    ///
    /// This is a different axis from
    /// [`refresh_vault_paths`](Self::refresh_vault_paths). That one is
    /// PREDICTIVE — it asks "is this credential near its recorded expiry?" and
    /// is a no-op when the recorded expiry says the token is fine. A token can
    /// nevertheless be rejected by the provider while the recorded expiry is
    /// still in the future (the refresh that should have run failed
    /// transiently, or the provider invalidated the token early). Only an
    /// error-driven refresh recovers those, so this hook deliberately skips
    /// the expiry predicate.
    ///
    /// Returns [`ForcedRefresh::Refreshed`] **only when at least one path now
    /// holds a NEW credential**. That is the caller's whole retry
    /// authorisation: a fresh credential was stored, retrying can succeed,
    /// and re-resolving the paths is guaranteed to read the new value rather
    /// than replay the one that just failed.
    ///
    /// Every other outcome means nothing was refreshed and the caller **must
    /// not** retry: re-sending the same rejected credential is a guaranteed
    /// second failure and doubles load on the provider. They are told apart
    /// because they ask different things of the operator: see
    /// [`ForcedRefresh`]. Until 2026-10-12 this returned `bool`, and a token
    /// endpoint that could not be reached read the same as a revoked grant.
    ///
    /// Because a revoked grant can never produce `Refreshed`, a caller that
    /// honours this contract cannot loop on one.
    ///
    /// The default implementation refreshes nothing and returns
    /// [`ForcedRefresh::NothingToRefresh`], which is the correct fail-safe
    /// for any resolver whose backing store holds only long-lived secrets.
    async fn force_refresh_vault_paths(&self, _paths: &[String]) -> ForcedRefresh {
        ForcedRefresh::NothingToRefresh
    }
}

/// Whether a token COULD be minted for a user, decided without minting one.
///
/// A diagnostic asks this instead of "is a secret stored at this path":
/// nothing is ever stored at a mint path. It reads the same rows the mint
/// reads, under the same user id, and makes no outbound call. `Ready` means
/// there is ONE connection to mint from; it does not mean the provider will
/// issue the token (that is only known by asking it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MintReadiness {
    /// There is one connection of the user's to mint from.
    Ready,
    /// The user has nothing of this kind connected.
    NoConnection,
    /// The path names a connection that is not a usable one of this user's.
    /// Another user's, a disconnected one and one that never existed are
    /// ONE answer: a caller must not learn which.
    NamedConnectionNotUsable,
    /// The user has several and the path names none, so nothing is minted.
    SeveralAndNoneNamed,
    /// This kind of mint is not configured in this deployment.
    NotConfigured,
}

/// Resolves a GitHub App installation token for a repo owner (RFC 0008 B4).
///
/// Injected into a [`SecretsResolver`] so a module secret path of the form
/// `github_app:<owner>` resolves to a freshly-minted, short-lived installation
/// token instead of a static vault secret. It lives in this low-level crate
/// (rather than the GitHub crates) so the resolver crate can hold a `dyn`
/// reference to it without a dependency cycle.
#[async_trait]
pub trait GithubInstallationTokenProvider: Send + Sync {
    /// Mint an installation token for `owner`, but ONLY if `user_id` owns an
    /// active installation for that GitHub account. `user_id` is the Talos user
    /// the execution runs as — passing it makes the App token a per-user
    /// credential (tenancy isolation), so one user's workflow can't mint tokens
    /// against another user's GitHub App installation.
    ///
    /// * `Ok(Some(token))` — `user_id` owns an active installation for `owner`;
    ///   a fresh (cached / re-minted) installation token.
    /// * `Ok(None)` — no installation owned by `user_id` for `owner` (or App
    ///   disabled); the secret is simply not injected, so the module fails
    ///   closed on the missing secret.
    /// * `Err` — an installation exists but minting failed.
    async fn installation_token(
        &self,
        owner: &str,
        user_id: Uuid,
    ) -> Result<Option<String>, BoxError>;

    /// Whether [`Self::installation_token`] has an installation to mint from
    /// for `owner` and `user_id`, WITHOUT minting. Same tenancy as the mint:
    /// only an installation `user_id` owns counts.
    ///
    /// `Err` when the installation could not be looked up: "could not look"
    /// is never "there is none".
    async fn mint_readiness(&self, owner: &str, user_id: Uuid) -> Result<MintReadiness, BoxError>;
}

/// Mints a short-lived impersonated GCP service-account access token
/// (Phase D — dynamic secret minting).
///
/// Injected into a [`SecretsResolver`] so a module secret path of the form
/// `gcp/impersonated/<service_account_email>/access_token` (or
/// `.../<service_account_email>/as/<connection key>/access_token`, which
/// names the Google Cloud connection to mint from) resolves to a
/// freshly-minted ~10-minute impersonated token instead of a static vault
/// secret. Like [`GithubInstallationTokenProvider`], it lives in this
/// low-level crate so the resolver can hold a `dyn` reference without a
/// dependency cycle on the GCP crates.
///
/// The token is minted by the controller from the requesting user's broad
/// `google_cloud_full` consent (host-reserved, never guest-visible) via
/// `iamcredentials.generateAccessToken`. The guest only ever receives the
/// scoped-down, short-lived impersonated token — never the broad grant.
#[async_trait]
pub trait GcpImpersonationTokenProvider: Send + Sync {
    /// Mint an impersonated access token for `service_account_email`, using
    /// the broad GCP credential owned by `user_id`. Passing `user_id` makes
    /// the minted token a per-user credential (tenancy isolation): one
    /// user's workflow can never mint against another user's consent.
    ///
    /// * `Ok(Some(token))` — `user_id` has a `google_cloud_full` consent AND
    ///   Google permits it to impersonate `service_account_email` (the
    ///   caller holds `iam.serviceAccountTokenCreator` on that SA); a fresh
    ///   short-lived token.
    /// * `Ok(None)` — there is no ONE consent to mint from: `user_id` owns no
    ///   full-tier consent, owns several and `connection` names none, or
    ///   `connection` names one that is not an active consent of `user_id`.
    ///   The secret is simply not injected, so the module fails closed on
    ///   the missing secret.
    /// * `Err` — a consent exists but the mint call itself failed.
    ///
    /// `connection` is the key of the Google Cloud connection to mint from.
    /// An implementation must never choose between several consents itself:
    /// a token minted from the wrong account acts as the wrong person.
    async fn impersonated_token(
        &self,
        service_account_email: &str,
        connection: Option<Uuid>,
        user_id: Uuid,
    ) -> Result<Option<String>, BoxError>;

    /// Whether [`Self::impersonated_token`] has ONE consent to mint from for
    /// `connection` and `user_id`, WITHOUT minting and without any outbound
    /// call. An implementation decides it with the same function the mint
    /// uses, from the same list read under `user_id`.
    ///
    /// `Err` when the consents could not be read: "could not look" is never
    /// "there is none".
    async fn mint_readiness(
        &self,
        connection: Option<Uuid>,
        user_id: Uuid,
    ) -> Result<MintReadiness, BoxError>;
}

#[cfg(test)]
mod forced_refresh_tests {
    use super::ForcedRefresh as F;

    #[test]
    fn only_a_new_credential_authorises_a_retry() {
        assert!(F::Refreshed.refreshed());
        for outcome in [
            F::RefusedByProvider,
            F::ProviderUnreachable,
            F::Failed,
            F::NothingToRefresh,
        ] {
            assert!(!outcome.refreshed(), "{outcome:?}");
            assert!(outcome.operator_note().is_some(), "{outcome:?}");
        }
        assert_eq!(F::Refreshed.operator_note(), None);
    }

    #[test]
    fn several_credentials_one_new_one_is_enough_and_a_refusal_outranks_a_blip() {
        assert_eq!(F::of_all([]), F::NothingToRefresh);
        assert_eq!(
            F::of_all([F::ProviderUnreachable, F::Refreshed]),
            F::Refreshed
        );
        assert_eq!(
            F::of_all([F::ProviderUnreachable, F::RefusedByProvider, F::Failed]),
            F::RefusedByProvider
        );
        assert_eq!(F::of_all([F::NothingToRefresh, F::Failed]), F::Failed);
        assert_eq!(
            F::of_all([F::Failed, F::ProviderUnreachable]),
            F::ProviderUnreachable
        );
    }

    /// The two sentences an operator acts on must not say each other's
    /// thing: until 2026-10-11 an unreachable token endpoint was reported as
    /// "refused, most likely needs to be re-authorised".
    #[test]
    fn an_unreachable_provider_is_not_described_as_needing_reauthorisation() {
        let unreachable = F::ProviderUnreachable.operator_note().unwrap();
        assert!(
            unreachable.contains("does NOT need re-authorising"),
            "{unreachable}"
        );
        assert!(!unreachable.contains("refused"), "{unreachable}");
        let refused = F::RefusedByProvider.operator_note().unwrap();
        assert!(
            refused.contains("re-authorise the integration"),
            "{refused}"
        );
        assert!(!refused.contains("could not be reached"), "{refused}");
    }
}
