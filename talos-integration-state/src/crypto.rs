//! Encrypt-at-rest for `integration_state.value`.
//!
//! The primitive is advertised for durable "OAuth tokens + watch secrets", so
//! `value` must be encrypted at rest. Encryption needs the org/DEK machinery in
//! `SecretsManager`, but `execute_op` is called from many places (the RPC
//! subscriber for worker-originated writes; gmail/gcal directly for watch
//! management) that don't hold a `SecretsManager`. Rather than re-plumb every
//! call site, we mirror the [`GithubInstallationTokenProvider`] pattern: a
//! process-global encryptor installed once at controller startup.
//!
//! Unset (unit tests, or before wiring) → values are stored/read as plaintext
//! (the pre-encryption behavior), so nothing breaks in a crypto-less context.
//!
//! [`GithubInstallationTokenProvider`]: talos_workflow_engine_core::GithubInstallationTokenProvider

use std::sync::{Arc, OnceLock};

use anyhow::Result;
use async_trait::async_trait;
use uuid::Uuid;

/// The encrypt/decrypt operations `execute_op` needs, kept as a trait so
/// `talos-integration-state` doesn't depend on `SecretsManager`. Implemented by
/// `SecretsManager` (in `talos-secrets-manager`) over its per-context AEAD.
#[async_trait]
pub trait IntegrationStateCrypto: Send + Sync {
    /// Encrypt `value` (a UTF-8 JSON string) for `user_id`, bound to `aad`.
    /// Returns `(key_id, ciphertext, format_version)` — bind the RETURNED format,
    /// never a hardcoded one (a v4 row mislabeled v3 fails to decrypt).
    async fn encrypt(&self, value: &str, user_id: Uuid, aad: &[u8])
        -> Result<(Uuid, Vec<u8>, i16)>;

    /// Decrypt back to the original UTF-8 JSON string. `aad` must match the value
    /// passed to [`encrypt`](Self::encrypt) exactly, or decryption fails closed.
    async fn decrypt(
        &self,
        key_id: Uuid,
        ciphertext: &[u8],
        aad: &[u8],
        format: i16,
    ) -> Result<String>;
}

static CRYPTO: OnceLock<Arc<dyn IntegrationStateCrypto>> = OnceLock::new();

/// Install the process-wide `integration_state` value encryptor. Call once at
/// controller startup (idempotent — first call wins). When unset, values are
/// stored + read as plaintext.
pub fn set_integration_state_crypto(crypto: Arc<dyn IntegrationStateCrypto>) {
    let _ = CRYPTO.set(crypto);
}

/// The installed encryptor, if any.
pub(crate) fn integration_state_crypto() -> Option<Arc<dyn IntegrationStateCrypto>> {
    CRYPTO.get().cloned()
}

/// Additional authenticated data binding a `value` ciphertext to its exact
/// `(integration_name, user_id, key)` slot, so a ciphertext can't be lifted into
/// another row (different user / integration / key) and still decrypt. Fixed
/// domain prefix + fixed-width `user_id` + NUL separators; the surrounding
/// fields are trusted, length-bounded, integration-authored strings (not raw
/// user input).
pub(crate) fn integration_state_aad(integration_name: &str, user_id: Uuid, key: &str) -> Vec<u8> {
    let mut aad =
        Vec::with_capacity(b"integration_state\0".len() + integration_name.len() + 18 + key.len());
    aad.extend_from_slice(b"integration_state\0");
    aad.extend_from_slice(integration_name.as_bytes());
    aad.push(0);
    aad.extend_from_slice(user_id.as_bytes());
    aad.push(0);
    aad.extend_from_slice(key.as_bytes());
    aad
}
