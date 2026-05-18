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
use talos_workflow_engine_core::{BoxError, SecretsResolver};
use uuid::Uuid;

use crate::OAuthCredentialService;
use talos_secrets_manager::SecretsManager;

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
        self.sm
            .get_secrets_by_paths(paths, user_id)
            .await
            .map_err(boxed)
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
