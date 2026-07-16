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
}

/// Mints a short-lived impersonated GCP service-account access token
/// (Phase D — dynamic secret minting).
///
/// Injected into a [`SecretsResolver`] so a module secret path of the form
/// `gcp/impersonated/<service_account_email>/access_token` resolves to a
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
    /// * `Ok(None)` — no full-tier consent owned by `user_id`, or minting is
    ///   not permitted; the secret is simply not injected, so the module
    ///   fails closed on the missing secret.
    /// * `Err` — a consent exists but the mint call itself failed.
    async fn impersonated_token(
        &self,
        service_account_email: &str,
        user_id: Uuid,
    ) -> Result<Option<String>, BoxError>;
}
