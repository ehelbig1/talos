/// Opaque handle to a materialized secret slot.
/// This u64 is the ONLY thing that ever crosses the WASM boundary.
/// Plaintext lives inside the provider's slot registry and is exposed only
/// through the explicit `into_auth_header` / `sign` / `decrypt` methods,
/// each of which is auditable via `AuditingProvider`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SlotHandle(pub u64);

#[async_trait::async_trait]
pub trait SecretProvider: Send + Sync {
    /// Resolve a vault path to a slot handle. Materializes the secret value
    /// inside the provider's DashMap; the caller receives an opaque handle,
    /// never plaintext. Multiple calls for the same path create independent slots.
    async fn resolve(&self, path: &str, execution_id: uuid::Uuid) -> anyhow::Result<SlotHandle>;

    /// Read the slot's value as an HTTP header value string.
    /// This is ONE of the auditable plaintext exit points — call sites are
    /// grep-able: `grep -rn "into_auth_header" worker/src/`
    ///
    /// L-4: returns `Zeroizing<String>` so the plaintext is wiped from
    /// heap on drop. Callers that need to pass the value to reqwest's
    /// header builder can pass `&str` (deref) or `.to_string()` for an
    /// owned copy — but the owned-copy path defeats the wipe and should
    /// be avoided. Production paths (`worker/src/host_impl.rs`) hand the
    /// `&Zeroizing<String>` directly into reqwest's `HeaderValue::from_str`
    /// which copies into HeaderValue's own buffer; the Zeroizing wrapper
    /// then drops + wipes when the binding goes out of scope.
    // The `into_` prefix is intentional: it names the security audit grep target.
    #[allow(clippy::wrong_self_convention)]
    fn into_auth_header(
        &self,
        handle: SlotHandle,
        header_name: &str,
    ) -> anyhow::Result<zeroize::Zeroizing<String>>;

    /// HMAC-sign a payload using the key held in the slot.
    /// Returns `Err` if the backend does not support this operation.
    fn sign(&self, handle: SlotHandle, payload: &[u8]) -> anyhow::Result<Vec<u8>>;

    /// Decrypt ciphertext using the key held in the slot.
    /// Returns `Err` if the backend does not support this operation.
    fn decrypt(
        &self,
        handle: SlotHandle,
        ciphertext: &[u8],
    ) -> anyhow::Result<zeroize::Zeroizing<Vec<u8>>>;

    /// Release a slot — drops the `Zeroizing<String>`, zeroing memory.
    async fn release(&self, handle: SlotHandle) -> anyhow::Result<()>;

    /// Provider liveness check (used at startup and health endpoints).
    async fn health_check(&self) -> anyhow::Result<()>;
}

#[cfg(test)]
#[path = "provider_tests.rs"]
mod tests;
