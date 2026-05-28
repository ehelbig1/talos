//! `MemoryCryptoHook` impl for the controller. Wraps `SecretsManager`'s
//! envelope-encryption primitives so `talos_memory::*` writers/readers
//! can transparently encrypt `actor_memory.value_enc` at rest.
//!
//! See `docs/security/agent-memory-encryption-plan.md` for the full design.
//!
//! MCP-S2: writes always use v1 AAD-bound encryption with AAD =
//! `build_memory_aad(actor_id, key)` so an attacker with DB write
//! capability can't swap ciphertexts between actor_memory rows that
//! share `value_key_id`. Reads dispatch on the per-row `value_format`
//! column: v0 (legacy) uses empty AAD; v1 requires the same AAD bytes
//! as the writer.

use std::pin::Pin;
use std::sync::Arc;

use anyhow::Result;
use uuid::Uuid;

// `talos_secrets_manager::SecretsManager` resolves to whichever copy of the
// `secrets` module is in scope: the lib-side one when this file is built
// as part of the `controller` lib crate, and main.rs's `mod secrets`
// copy when built as part of the `controller` binary. Both compile to
// identical code from the same source.
use talos_secrets_manager::SecretsManager;

/// Adapter from `talos_memory::MemoryCryptoHook` to `SecretsManager`.
/// Delegates `encrypt` to `SecretsManager::encrypt_value_aad_v1`
/// (returns `(key_id, ciphertext, version)`) and `decrypt` to
/// `SecretsManager::decrypt_versioned`.
pub struct SecretsManagerMemoryCrypto {
    secrets: Arc<SecretsManager>,
}

impl SecretsManagerMemoryCrypto {
    #[must_use]
    pub fn new(secrets: Arc<SecretsManager>) -> Self {
        Self { secrets }
    }
}

impl talos_memory::MemoryCryptoHook for SecretsManagerMemoryCrypto {
    fn encrypt(
        &self,
        plaintext: String,
        aad: Vec<u8>,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(Uuid, Vec<u8>, i16)>> + Send>>
    {
        let secrets = self.secrets.clone();
        Box::pin(async move { secrets.encrypt_value_aad_v1(&plaintext, &aad).await })
    }

    fn decrypt(
        &self,
        key_id: Uuid,
        ciphertext: Vec<u8>,
        aad: Vec<u8>,
        format_version: i16,
    ) -> Pin<
        Box<dyn std::future::Future<Output = Result<zeroize::Zeroizing<String>>> + Send>,
    > {
        let secrets = self.secrets.clone();
        Box::pin(async move {
            secrets
                .decrypt_versioned(key_id, &ciphertext, &aad, format_version)
                .await
        })
    }
}
