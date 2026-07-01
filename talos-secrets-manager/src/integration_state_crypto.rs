//! `SecretsManager`'s implementation of `talos_integration_state::IntegrationStateCrypto`.
//!
//! Bridges the `integration_state` value encrypt-at-rest hook onto the same
//! per-context AEAD (per-org DEK v4, global-DEK v3 fallback) used for secrets /
//! actor_memory / module payloads. Wired into the process-global slot at
//! controller startup via `set_integration_state_crypto`.

use anyhow::Result;
use async_trait::async_trait;
use uuid::Uuid;

use crate::SecretsManager;

#[async_trait]
impl talos_integration_state::IntegrationStateCrypto for SecretsManager {
    async fn encrypt(
        &self,
        value: &str,
        user_id: Uuid,
        aad: &[u8],
    ) -> Result<(Uuid, Vec<u8>, i16)> {
        // Per-user → resolves the user's personal org DEK (v4), falling back to
        // the global DEK (v3) for org-less contexts. Returns (key_id, ct, format);
        // the caller binds the RETURNED format, never a hardcoded one.
        self.encrypt_value_aad_v4_for_user(value, user_id, aad)
            .await
    }

    async fn decrypt(
        &self,
        key_id: Uuid,
        ciphertext: &[u8],
        aad: &[u8],
        format: i16,
    ) -> Result<String> {
        let plaintext = self
            .decrypt_versioned(key_id, ciphertext, aad, format)
            .await?;
        // The value is returned to the caller (RPC subscriber → worker, or the
        // controller-side integration) as plaintext anyway, so the Zeroizing
        // guarantee ends here regardless.
        Ok(plaintext.as_str().to_string())
    }
}
