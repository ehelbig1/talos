use crate::provider::{SecretProvider, SlotHandle};

/// Decorator that adds structured audit logging around every `SecretProvider` call.
///
/// Usage:
/// ```ignore
/// let provider = AuditingProvider::new(TalosVaultProvider::from_resolved(secrets));
/// ```
///
/// `resolve` logs the key path at INFO with the OAuth provider key hashed
/// (`talos_workflow_job_protocol::redact_vault_path_for_log`) — never the raw
/// `oauth/gmail/<user>/<email>/…` form.
///
/// All plaintext exit points (`into_auth_header`, `sign`, `decrypt`) are logged
/// at `DEBUG` level with handle ID and context so that access can be audited with:
/// ```text
/// grep -rn "secret.expose_for_header\|secret.sign\|secret.decrypt" worker/logs/
/// ```
pub struct AuditingProvider<P: SecretProvider> {
    inner: P,
}

impl<P: SecretProvider> AuditingProvider<P> {
    pub fn new(inner: P) -> Self {
        Self { inner }
    }
}

#[async_trait::async_trait]
impl<P: SecretProvider> SecretProvider for AuditingProvider<P> {
    async fn resolve(&self, path: &str, execution_id: uuid::Uuid) -> anyhow::Result<SlotHandle> {
        // The path is rendered through the shared redactor: an OAuth path
        // carries the account's provider key (for gmail, the user's email)
        // in its fourth segment, and this line fires on every secret a
        // module resolves — structural check 91. The field is `key_path`
        // (was `path`) so the check can see it by name; grep the message.
        let key_path = talos_workflow_job_protocol::redact_vault_path_for_log(path);
        tracing::info!(key_path = %key_path, %execution_id, "secret.resolve");
        let result = self.inner.resolve(path, execution_id).await;
        if let Err(ref e) = result {
            tracing::warn!(key_path = %key_path, %execution_id, error = %e, "secret.resolve.failed");
        }
        result
    }

    fn into_auth_header(
        &self,
        handle: SlotHandle,
        header_name: &str,
    ) -> anyhow::Result<zeroize::Zeroizing<String>> {
        tracing::debug!(handle = handle.0, header_name, "secret.expose_for_header");
        self.inner.into_auth_header(handle, header_name)
    }

    fn sign(&self, handle: SlotHandle, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
        tracing::debug!(
            handle = handle.0,
            payload_len = payload.len(),
            "secret.sign"
        );
        self.inner.sign(handle, payload)
    }

    fn decrypt(
        &self,
        handle: SlotHandle,
        ciphertext: &[u8],
    ) -> anyhow::Result<zeroize::Zeroizing<Vec<u8>>> {
        tracing::debug!(handle = handle.0, "secret.decrypt");
        self.inner.decrypt(handle, ciphertext)
    }

    async fn release(&self, handle: SlotHandle) -> anyhow::Result<()> {
        tracing::debug!(handle = handle.0, "secret.release");
        self.inner.release(handle).await
    }

    async fn health_check(&self) -> anyhow::Result<()> {
        self.inner.health_check().await
    }
}

#[cfg(test)]
#[path = "auditing_tests.rs"]
mod tests;
