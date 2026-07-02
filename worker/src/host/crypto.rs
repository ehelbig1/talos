//! `crypto` host interface (hash / HMAC / encoding with input caps).

use super::*;

// ============================================================================
// Crypto
// ============================================================================

/// Maximum input size for hash/HMAC operations (100 MiB).
/// Prevents a WASM guest from triggering multi-second CPU stalls on the host.
const MAX_HASH_INPUT_BYTES: usize = 100 * 1024 * 1024;

/// Maximum HMAC key size (1 MiB).
/// HMAC keys beyond one block are hashed by the algorithm anyway; this cap
/// prevents host memory pressure from oversized keys.
const MAX_HMAC_KEY_BYTES: usize = 1024 * 1024;

impl wit_crypto::Host for TalosContext {
    async fn hash(&mut self, algorithm: wit_crypto::HashAlgorithm, data: Vec<u8>) -> Vec<u8> {
        // Check if crypto budget is already exhausted.
        if self
            .crypto_budget_us
            .load(std::sync::atomic::Ordering::Relaxed)
            == 0
        {
            tracing::warn!(
                "hash() called but crypto time budget is exhausted — returning empty vec"
            );
            return vec![];
        }
        // Guard against DoS via oversized input.
        if data.len() > MAX_HASH_INPUT_BYTES {
            tracing::warn!(
                data_len = data.len(),
                limit = MAX_HASH_INPUT_BYTES,
                "hash() input exceeds size limit — returning empty vec"
            );
            return vec![];
        }
        use sha2::Digest;
        let start = std::time::Instant::now();
        let result = match algorithm {
            wit_crypto::HashAlgorithm::Sha256 => sha2::Sha256::digest(&data).to_vec(),
            wit_crypto::HashAlgorithm::Sha512 => sha2::Sha512::digest(&data).to_vec(),
            wit_crypto::HashAlgorithm::Md5 => {
                tracing::warn!(
                    module_id = ?self.module_id,
                    "MD5 hash is cryptographically broken — use SHA-256 or SHA-512 instead"
                );
                md5::compute(&data).to_vec()
            }
        };
        let elapsed_us = start.elapsed().as_micros() as u64;
        if !self.deduct_crypto_budget(elapsed_us) {
            tracing::warn!(
                elapsed_us,
                "hash() exhausted crypto time budget — subsequent crypto calls will be rejected"
            );
        }
        result
    }

    async fn hmac(
        &mut self,
        algorithm: wit_crypto::HashAlgorithm,
        key: Vec<u8>,
        data: Vec<u8>,
    ) -> Vec<u8> {
        // Check if crypto budget is already exhausted.
        if self
            .crypto_budget_us
            .load(std::sync::atomic::Ordering::Relaxed)
            == 0
        {
            tracing::warn!(
                "hmac() called but crypto time budget is exhausted — returning empty vec"
            );
            return vec![];
        }
        // Guard against DoS via oversized key or data.
        if key.len() > MAX_HMAC_KEY_BYTES || data.len() > MAX_HASH_INPUT_BYTES {
            tracing::warn!(
                key_len = key.len(),
                data_len = data.len(),
                "hmac() key or data exceeds size limit — returning empty vec"
            );
            return vec![];
        }
        use hmac::{Hmac, Mac};
        let start = std::time::Instant::now();
        // new_from_slice() accepts any key length for HMAC (unlike block ciphers), so
        // the error branch is unreachable in practice, but we handle it to avoid panics.
        let result = match algorithm {
            wit_crypto::HashAlgorithm::Sha256 => match Hmac::<sha2::Sha256>::new_from_slice(&key) {
                Ok(mut mac) => {
                    mac.update(&data);
                    mac.finalize().into_bytes().to_vec()
                }
                Err(_) => {
                    tracing::warn!("hmac() failed to build HMAC instance");
                    vec![]
                }
            },
            wit_crypto::HashAlgorithm::Sha512 => match Hmac::<sha2::Sha512>::new_from_slice(&key) {
                Ok(mut mac) => {
                    mac.update(&data);
                    mac.finalize().into_bytes().to_vec()
                }
                Err(_) => {
                    tracing::warn!("hmac() failed to build HMAC instance");
                    vec![]
                }
            },
            wit_crypto::HashAlgorithm::Md5 => {
                // HMAC-MD5 is cryptographically weak; fall back to HMAC-SHA256.
                // The md5 0.7 crate is not digest 0.10 compatible, so we cannot
                // construct Hmac::<md5::Md5> directly.  Returning HMAC-SHA256 keeps
                // the interface functional while steering callers away from MD5.
                match Hmac::<sha2::Sha256>::new_from_slice(&key) {
                    Ok(mut mac) => {
                        mac.update(&data);
                        mac.finalize().into_bytes().to_vec()
                    }
                    Err(_) => {
                        tracing::warn!("hmac() fallback HMAC-SHA256 failed");
                        vec![]
                    }
                }
            }
        };
        let elapsed_us = start.elapsed().as_micros() as u64;
        if !self.deduct_crypto_budget(elapsed_us) {
            tracing::warn!(
                elapsed_us,
                "hmac() exhausted crypto time budget — subsequent crypto calls will be rejected"
            );
        }
        result
    }

    async fn encode(&mut self, encoding: wit_crypto::Encoding, data: Vec<u8>) -> String {
        match encoding {
            wit_crypto::Encoding::Hex => hex::encode(&data),
            wit_crypto::Encoding::Base64 => {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(&data)
            }
            wit_crypto::Encoding::Base64url => {
                use base64::Engine;
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&data)
            }
        }
    }

    async fn decode(
        &mut self,
        encoding: wit_crypto::Encoding,
        data: String,
    ) -> Result<Vec<u8>, wit_crypto::Error> {
        match encoding {
            wit_crypto::Encoding::Hex => {
                hex::decode(&data).map_err(|_| wit_crypto::Error::Invalidinput)
            }
            wit_crypto::Encoding::Base64 => {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD
                    .decode(&data)
                    .map_err(|_| wit_crypto::Error::Invalidinput)
            }
            wit_crypto::Encoding::Base64url => {
                use base64::Engine;
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(&data)
                    .map_err(|_| wit_crypto::Error::Invalidinput)
            }
        }
    }

    async fn random_bytes(&mut self, length: u32) -> Vec<u8> {
        use rand::RngCore;
        const MAX_RANDOM_BYTES: u32 = 1_000_000; // 1 MB — prevents host memory exhaustion
        if length > MAX_RANDOM_BYTES {
            tracing::warn!(
                "random_bytes() requested {} bytes, exceeds limit of {}; returning empty",
                length,
                MAX_RANDOM_BYTES
            );
            return vec![];
        }
        let mut bytes = vec![0u8; length as usize];
        // MCP-1085 (2026-05-16): use `OsRng` (always CSPRNG-grade per
        // platform syscall — /dev/urandom on Linux, getrandom(2),
        // BCryptGenRandom on Windows) instead of `rand::thread_rng()`.
        // Pre-fix `thread_rng()` returns a ChaCha-based PRNG that IS
        // CSPRNG-grade in current `rand` versions, but the rand crate
        // docs explicitly recommend `OsRng` for cryptographic use AND
        // a future rand-crate change could weaken thread_rng (e.g.,
        // switch to a faster PRNG for general use). Guest modules
        // calling `random_bytes()` may use the output for session
        // tokens, nonces, key material — defense-in-depth requires
        // explicit OsRng so the CSPRNG guarantee survives any crate
        // upgrade. Matches the convention already established in
        // talos-auth (refresh tokens) and talos-csrf (CSRF tokens) /
        // talos-api (mcp agent tokens).
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        bytes
    }

    async fn uuid(&mut self) -> String {
        uuid::Uuid::new_v4().to_string()
    }
}
