//! KEK (Key-Encryption-Key) provider abstraction.
//!
//! The KEK sits at the root of the encryption tree — every DEK in
//! `encryption_keys` is wrapped with it; every secret value, every
//! `oauth_token`, every `actor_memory.value_enc` ultimately depends on
//! the KEK being available to unwrap its DEK.
//!
//! Historically the KEK has been a 32-byte AES key loaded from
//! `TALOS_MASTER_KEY` (env var or Docker secret). That works but the
//! key sits in the controller process's memory and in any environment
//! dump — anyone with shell access reads everything. Step 1 toward
//! moving the KEK into a real KMS (HashiCorp Vault transit, AWS KMS,
//! GCP KMS) is to put a trait between `SecretsManager` and the wrap /
//! unwrap primitives, so the swap is a one-line constructor change
//! instead of a code rewrite.
//!
//! Design notes:
//!
//! - **Wire format is opaque.** The wrapped bytes that come out of
//!   `wrap_dek` and go back into `unwrap_dek` are an implementation
//!   detail of the provider — `EnvKekProvider` uses `nonce || ciphertext`
//!   AES-256-GCM, Vault transit returns `vault:v1:<base64>`, AWS KMS
//!   returns its own blob. Callers MUST round-trip without inspection.
//!
//! - **Async-only.** Future KMS providers issue network calls. The
//!   `EnvKekProvider` is logically sync but exposes async methods so the
//!   trait stays uniform.
//!
//! - **Box-future, not async-trait.** Object-safe (`dyn KekProvider`)
//!   without pulling in `async-trait`. Mirrors the
//!   `talos_memory::MemoryCryptoHook` pattern.
//!
//! - **Failure mode is fail-closed.** Wrap/unwrap errors surface as
//!   `anyhow::Error`; `SecretsManager` propagates them. The KMS network
//!   path will translate transport errors into the same shape.

use std::pin::Pin;
use std::sync::Arc;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use anyhow::{anyhow, Context, Result};
use rand::RngCore;
use zeroize::Zeroizing;

/// Pluggable wrap / unwrap surface for the KEK that protects DEKs.
///
/// Implementations: [`EnvKekProvider`] (current path — local AES with
/// `TALOS_MASTER_KEY`), `VaultTransitProvider` (Phase 2), `AwsKmsProvider`
/// (deferred), `GcpKmsProvider` (deferred).
pub trait KekProvider: Send + Sync + 'static {
    /// Wrap a 32-byte DEK. Returns provider-defined opaque bytes.
    fn wrap_dek(
        &self,
        dek: &[u8; 32],
    ) -> Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>>> + Send + '_>>;

    /// Unwrap previously-wrapped bytes back to a 32-byte DEK.
    /// Returned via `Zeroizing` so the plaintext key is wiped on drop.
    fn unwrap_dek(
        &self,
        wrapped: &[u8],
    ) -> Pin<Box<dyn std::future::Future<Output = Result<Zeroizing<Vec<u8>>>> + Send + '_>>;

    /// Identifier reported in startup logs / health checks (`env`,
    /// `vault://transit/keys/talos-kek`, etc.). Must NOT include the
    /// key material itself.
    fn name(&self) -> &str;
}

/// Local-AES KEK provider — backwards-compatible path matching the
/// pre-refactor `TALOS_MASTER_KEY` behavior exactly. Same ciphertext
/// format (`12-byte nonce || GCM ciphertext`), same algorithm
/// (AES-256-GCM), same key length (32 bytes).
///
/// Suitable for development and single-host deployments. Production
/// deployments should migrate to a real KMS via `VaultTransitProvider`
/// (Phase 2).
pub struct EnvKekProvider {
    master_key: Zeroizing<Vec<u8>>,
}

impl EnvKekProvider {
    /// Build from a hex-encoded 32-byte key (the value of
    /// `TALOS_MASTER_KEY`). Validates length + hex shape; never logs
    /// the decoded bytes.
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes =
            hex::decode(hex_str.trim()).context("TALOS_MASTER_KEY must be a valid hex string")?;
        if bytes.len() != 32 {
            return Err(anyhow!(
                "TALOS_MASTER_KEY must be 32 bytes (64 hex chars), got {} bytes",
                bytes.len()
            ));
        }
        Ok(Self {
            master_key: Zeroizing::new(bytes),
        })
    }

    /// Build directly from raw bytes — used by the test stub. Caller
    /// guarantees the length is exactly 32.
    #[cfg(test)]
    pub fn from_raw_bytes(bytes: Vec<u8>) -> Self {
        debug_assert_eq!(bytes.len(), 32);
        Self {
            master_key: Zeroizing::new(bytes),
        }
    }

    /// Build from raw bytes with length validation. Used by
    /// `rotate_master_key` to construct a provider from operator-supplied
    /// rotation input. Returns Err on wrong length so the rotation API
    /// can surface a clear validation error instead of constructing a
    /// silently-broken provider.
    pub fn from_raw_bytes_owned(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(anyhow!(
                "EnvKekProvider requires a 32-byte key, got {} bytes",
                bytes.len()
            ));
        }
        Ok(Self {
            master_key: Zeroizing::new(bytes),
        })
    }

    /// All-zeros stub for cache-layer tests that don't actually
    /// wrap/unwrap anything. Mirrors `SecretsManager::test_stub_for_cache`.
    #[cfg(test)]
    pub fn test_stub() -> Self {
        Self::from_raw_bytes(vec![0u8; 32])
    }
}

impl KekProvider for EnvKekProvider {
    fn wrap_dek(
        &self,
        dek: &[u8; 32],
    ) -> Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>>> + Send + '_>> {
        let dek = *dek;
        Box::pin(async move {
            let cipher = Aes256Gcm::new_from_slice(&self.master_key)
                .context("Failed to construct master cipher")?;
            let mut nonce_bytes = [0u8; 12];
            rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
            let ciphertext = cipher
                .encrypt(Nonce::from_slice(&nonce_bytes), dek.as_ref())
                .map_err(|e| anyhow!("Failed to wrap DEK: {}", e))?;
            // Wire format: nonce (12 bytes) || ciphertext (variable).
            // Matches the pre-refactor on-disk layout exactly so existing
            // rows in `encryption_keys.encrypted_key` still decrypt.
            let mut out = nonce_bytes.to_vec();
            out.extend_from_slice(&ciphertext);
            Ok(out)
        })
    }

    fn unwrap_dek(
        &self,
        wrapped: &[u8],
    ) -> Pin<Box<dyn std::future::Future<Output = Result<Zeroizing<Vec<u8>>>> + Send + '_>> {
        let wrapped = wrapped.to_vec();
        Box::pin(async move {
            if wrapped.len() < 12 {
                return Err(anyhow!(
                    "Invalid wrapped DEK: too short ({} bytes)",
                    wrapped.len()
                ));
            }
            let cipher = Aes256Gcm::new_from_slice(&self.master_key)
                .context("Failed to construct master cipher")?;
            let nonce = Nonce::from_slice(&wrapped[..12]);
            let ciphertext = &wrapped[12..];
            let plaintext = cipher
                .decrypt(nonce, ciphertext)
                .map_err(|e| anyhow!("Failed to unwrap DEK: {}", e))?;
            Ok(Zeroizing::new(plaintext))
        })
    }

    fn name(&self) -> &str {
        "env"
    }
}

/// Convenience constructor that reads the env var (or
/// `TALOS_MASTER_KEY_FILE` for Docker secrets) and validates.
/// Returns `Arc<dyn KekProvider>` so callers can hand it straight to
/// `SecretsManager::with_kek_provider`.
pub fn env_kek_provider_from_environment() -> Result<Arc<dyn KekProvider>> {
    let hex = talos_config::read_env_or_file("TALOS_MASTER_KEY").ok_or_else(|| {
        anyhow!(
            "TALOS_MASTER_KEY environment variable must be set (or \
             TALOS_MASTER_KEY_FILE for Docker secrets). Generate with: \
             openssl rand -hex 32"
        )
    })?;
    Ok(Arc::new(EnvKekProvider::from_hex(&hex)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn env_kek_round_trip() {
        let kek = EnvKekProvider::from_raw_bytes(vec![1u8; 32]);
        let dek = [42u8; 32];
        let wrapped = kek.wrap_dek(&dek).await.unwrap();
        // Wire format guarantee: 12-byte nonce + ≥16-byte GCM tag = ≥28 bytes.
        assert!(wrapped.len() >= 12 + 32 + 16);
        let unwrapped = kek.unwrap_dek(&wrapped).await.unwrap();
        assert_eq!(unwrapped.as_slice(), &dek);
    }

    #[tokio::test]
    async fn env_kek_distinct_nonces_per_wrap() {
        // GCM is catastrophically broken under nonce reuse — verify each
        // wrap call emits a fresh random nonce by wrapping twice and
        // checking the leading 12 bytes differ.
        let kek = EnvKekProvider::from_raw_bytes(vec![7u8; 32]);
        let dek = [9u8; 32];
        let a = kek.wrap_dek(&dek).await.unwrap();
        let b = kek.wrap_dek(&dek).await.unwrap();
        assert_ne!(a[..12], b[..12], "GCM nonce was reused across wraps");
    }

    #[tokio::test]
    async fn env_kek_rejects_truncated_wrapped() {
        let kek = EnvKekProvider::from_raw_bytes(vec![3u8; 32]);
        assert!(kek.unwrap_dek(b"short").await.is_err());
    }

    #[tokio::test]
    async fn env_kek_rejects_corrupted_ciphertext() {
        let kek = EnvKekProvider::from_raw_bytes(vec![5u8; 32]);
        let dek = [11u8; 32];
        let mut wrapped = kek.wrap_dek(&dek).await.unwrap();
        let last = wrapped.len() - 1;
        wrapped[last] ^= 0xff;
        // GCM auth-tag check must fail closed on tampered ciphertext.
        assert!(kek.unwrap_dek(&wrapped).await.is_err());
    }

    #[test]
    fn from_hex_rejects_wrong_length() {
        assert!(EnvKekProvider::from_hex("deadbeef").is_err());
    }

    #[test]
    fn from_hex_rejects_non_hex() {
        assert!(EnvKekProvider::from_hex(&"z".repeat(64)).is_err());
    }
}
