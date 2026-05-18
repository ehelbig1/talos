//! Postgres-backed implementation of [`CheckpointStore`].
//!
//! Owns the AES-256-GCM encrypt/decrypt path (formerly free functions on
//! the engine) plus the query the engine used to carry on its
//! `load_checkpoint` method.

use std::collections::HashMap;
use std::fmt;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use async_trait::async_trait;
use rand::RngCore;
use serde_json::Value as JsonValue;
use sqlx::{Pool, Postgres};
use talos_workflow_engine_core::{BoxError, CheckpointStore};
use uuid::Uuid;

/// Minimum key length for AES-256-GCM. Keys longer than this are
/// truncated to the first 32 bytes.
const AES_KEY_LEN: usize = 32;

/// AES-GCM nonce length used by the `aes_gcm` crate's default.
const NONCE_LEN: usize = 12;

/// Postgres-backed checkpoint store.
///
/// `load` transparently handles three storage shapes, tried in order:
/// (1) legacy plain-JSON checkpoints in `output_data`; (2)
/// WSK-encrypted checkpoints in `checkpoint_encrypted` +
/// `checkpoint_nonce`; (3) DEK-encrypted Phase A output bytes in
/// `output_data_enc` + `output_enc_key_id` (MCP-684, fall-back when
/// `WORKER_SHARED_KEY` is missing but `SecretsManager` is wired —
/// the scheduler / GraphQL trigger paths write the same
/// `aggregated_json` to BOTH the DEK column AND the WSK column, so
/// either is sufficient to resume).
///
/// When both `worker_shared_key` AND `secrets_manager` are `None`,
/// `load` only ever sees plaintext rows — the correct behavior for
/// test harnesses and CI.
pub struct ControllerCheckpointStore {
    pool: Pool<Postgres>,
    worker_shared_key: Option<Vec<u8>>,
    /// MCP-684 (2026-05-13): optional SecretsManager so `load` can
    /// fall back to decrypting `output_data_enc` (the DEK-encrypted
    /// `mark_execution_waiting` output) when no WSK is configured.
    /// Pre-fix, a Phase A deployment without `WORKER_SHARED_KEY`
    /// silently lost every waiting workflow's resume state — the
    /// `save()` path no-ops without a key and the `load()` path
    /// returned an empty map, so the engine resumed from scratch.
    secrets_manager: Option<std::sync::Arc<talos_secrets_manager::SecretsManager>>,
}

impl fmt::Debug for ControllerCheckpointStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never format the key bytes — even a debug-only leak would land
        // material into `tracing` output verbatim. Report length only.
        f.debug_struct("ControllerCheckpointStore")
            .field("pool", &self.pool)
            .field(
                "worker_shared_key",
                &self
                    .worker_shared_key
                    .as_ref()
                    .map(|k| format!("<redacted; len={}>", k.len()))
                    .unwrap_or_else(|| "None".to_string()),
            )
            .field(
                "secrets_manager",
                &self.secrets_manager.as_ref().map(|_| "<wired>").unwrap_or("None"),
            )
            .finish()
    }
}

impl ControllerCheckpointStore {
    /// Build a store bound to `pool`. When `worker_shared_key` is
    /// `None`, `load` falls back to the DEK column (MCP-684) if a
    /// SecretsManager is also wired via `with_secrets_manager`.
    #[must_use]
    pub fn new(pool: Pool<Postgres>, worker_shared_key: Option<Vec<u8>>) -> Self {
        Self {
            pool,
            worker_shared_key,
            secrets_manager: None,
        }
    }

    /// MCP-684: attach a SecretsManager so `load` can decrypt
    /// `output_data_enc` when no WSK is available.
    #[must_use]
    pub fn with_secrets_manager(
        mut self,
        sm: std::sync::Arc<talos_secrets_manager::SecretsManager>,
    ) -> Self {
        self.secrets_manager = Some(sm);
        self
    }
}

/// Caller-side one-shot helper: build a [`ControllerCheckpointStore`]
/// and call [`load`](CheckpointStore::load), returning an empty map on
/// any error. This is what most call sites actually want — they don't
/// hold a store between calls, they just want to hydrate a resume run.
///
/// Saves callers from repeating the `Arc<Vec<u8>>` → `Vec<u8>` clone
/// dance and from having to `use talos_workflow_engine_core::CheckpointStore`
/// at every site just to reach `load`.
pub async fn load_checkpoint_for(
    pool: &Pool<Postgres>,
    worker_shared_key: Option<&[u8]>,
    execution_id: Uuid,
) -> HashMap<Uuid, JsonValue> {
    load_checkpoint_for_full(pool, worker_shared_key, None, execution_id).await
}

/// MCP-684 (2026-05-13): variant that also threads a SecretsManager so
/// the DEK-encrypted `output_data_enc` fallback can light up when the
/// operator hasn't wired `WORKER_SHARED_KEY`. Same return shape as
/// `load_checkpoint_for`; callers that don't have an `Arc<SecretsManager>`
/// handy should keep using the original helper.
pub async fn load_checkpoint_for_full(
    pool: &Pool<Postgres>,
    worker_shared_key: Option<&[u8]>,
    secrets_manager: Option<std::sync::Arc<talos_secrets_manager::SecretsManager>>,
    execution_id: Uuid,
) -> HashMap<Uuid, JsonValue> {
    let mut store =
        ControllerCheckpointStore::new(pool.clone(), worker_shared_key.map(<[u8]>::to_vec));
    if let Some(sm) = secrets_manager {
        store = store.with_secrets_manager(sm);
    }
    match store.load(execution_id).await {
        Ok(map) => map,
        Err(e) => {
            tracing::warn!(
                %execution_id,
                error = %e,
                "Failed to load checkpoint — treating as fresh run"
            );
            HashMap::new()
        }
    }
}

#[async_trait]
impl CheckpointStore for ControllerCheckpointStore {
    async fn save(&self, execution_id: Uuid, snapshot: &JsonValue) -> Result<(), BoxError> {
        // Silently no-op when no key is configured. Save paths run on
        // happy-path workflow completion; aborting the workflow because
        // the operator hasn't wired up `WORKER_SHARED_KEY` would be a
        // worse user experience than a missing encrypted checkpoint,
        // and `load` already tolerates the absence at resume time.
        let Some(key) = self.worker_shared_key.as_deref() else {
            return Ok(());
        };
        let (ciphertext, nonce) =
            encrypt_checkpoint(snapshot, key).map_err(|e| -> BoxError { e.into() })?;
        sqlx::query(
            "UPDATE workflow_executions \
             SET checkpoint_encrypted = $1, checkpoint_nonce = $2 \
             WHERE id = $3",
        )
        .bind(&ciphertext)
        .bind(&nonce)
        .bind(execution_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn load(&self, execution_id: Uuid) -> Result<HashMap<Uuid, JsonValue>, BoxError> {
        // Plain-JSON fast path: older executions and ones written with no key.
        let row: Option<(Option<JsonValue>,)> = sqlx::query_as(
            "SELECT output_data FROM workflow_executions \
             WHERE id = $1 AND status = 'waiting'",
        )
        .bind(execution_id)
        .fetch_optional(&self.pool)
        .await?;

        if let Some((Some(output_data),)) = row {
            if let Some(obj) = output_data.as_object() {
                let results = uuid_keyed_map(obj);
                if !results.is_empty() {
                    return Ok(results);
                }
            }
        }

        // WSK-encrypted checkpoint path. When a worker_shared_key is
        // available, prefer this — it was the dedicated checkpoint
        // storage column populated by `save()` above.
        if let Some(key) = self.worker_shared_key.as_deref() {
            let enc_row: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
                "SELECT checkpoint_encrypted, checkpoint_nonce FROM workflow_executions \
                 WHERE id = $1 AND status = 'waiting' AND checkpoint_encrypted IS NOT NULL",
            )
            .bind(execution_id)
            .fetch_optional(&self.pool)
            .await?;

            if let Some((ciphertext, nonce)) = enc_row {
                let decrypted = decrypt_checkpoint(&ciphertext, &nonce, key)
                    .map_err(|e| -> BoxError { e.into() })?;
                return Ok(decrypted
                    .as_object()
                    .map(uuid_keyed_map)
                    .unwrap_or_default());
            }
        }

        // MCP-684 (2026-05-13): DEK-encrypted fallback via
        // `output_data_enc`. The scheduler / GraphQL trigger /
        // continuation-trigger paths write the SAME aggregated_json to
        // BOTH `output_data_enc` (via mark_execution_waiting) AND
        // `checkpoint_encrypted` (via save()) — the two encryptions use
        // different keys. Pre-fix, a Phase A deployment without
        // WORKER_SHARED_KEY had no resume path: save() no-opped, the
        // WSK-decrypt branch above bailed on `None`, and we returned an
        // empty map → the engine treated the resume as a fresh run.
        // This branch decrypts `output_data_enc` via SecretsManager so
        // the resume succeeds whenever ANY encryption is wired.
        let Some(sm) = self.secrets_manager.as_ref() else {
            return Ok(HashMap::new());
        };

        let dek_row: Option<(Option<Vec<u8>>, Option<Uuid>)> = sqlx::query_as(
            "SELECT output_data_enc, output_enc_key_id FROM workflow_executions \
             WHERE id = $1 AND status = 'waiting' AND output_data_enc IS NOT NULL",
        )
        .bind(execution_id)
        .fetch_optional(&self.pool)
        .await?;

        let Some((Some(enc_bytes), Some(key_id))) = dek_row else {
            return Ok(HashMap::new());
        };

        // Decrypt-failure is logged + treated as "no checkpoint" —
        // safer than panicking the resume thread. The engine then
        // re-runs from scratch which is a worse UX than a clean
        // resume but better than a crash loop.
        let plain = match sm.decrypt_value_by_key(key_id, &enc_bytes).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    %execution_id,
                    error = %e,
                    "MCP-684: DEK-decrypt of output_data_enc failed during checkpoint load — \
                     treating as fresh run"
                );
                return Ok(HashMap::new());
            }
        };
        let parsed: JsonValue = match serde_json::from_str(plain.as_str()) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    %execution_id,
                    error = %e,
                    "MCP-684: decrypted output_data_enc not valid JSON — treating as fresh run"
                );
                return Ok(HashMap::new());
            }
        };
        Ok(parsed.as_object().map(uuid_keyed_map).unwrap_or_default())
    }
}

fn uuid_keyed_map(obj: &serde_json::Map<String, JsonValue>) -> HashMap<Uuid, JsonValue> {
    obj.iter()
        .filter_map(|(k, v)| Uuid::parse_str(k).ok().map(|u| (u, v.clone())))
        .collect()
}

/// Encrypt a checkpoint snapshot with AES-256-GCM and a random nonce.
/// Returns `(ciphertext, nonce)`. Private; callers go through the
/// [`CheckpointStore::save`] trait method, which owns the SQL write.
///
/// M-11: requires the key to be exactly [`AES_KEY_LEN`] bytes. The previous
/// `key.len() < AES_KEY_LEN` check accepted longer keys and silently
/// truncated to the first 32 bytes, which masked operator-error key
/// configurations (hex-encoded keys interpreted as raw bytes,
/// prepend-rotation accidentally using stale material).
fn encrypt_checkpoint(data: &JsonValue, key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    if key.len() != AES_KEY_LEN {
        return Err(format!(
            "Encryption key must be exactly {AES_KEY_LEN} bytes; got {}",
            key.len()
        ));
    }
    let plaintext =
        serde_json::to_vec(data).map_err(|e| format!("Failed to serialize checkpoint: {e}"))?;
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| format!("Failed to create cipher: {e}"))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| format!("Encryption failed: {e}"))?;
    Ok((ciphertext, nonce_bytes.to_vec()))
}

/// Decrypt an AES-256-GCM checkpoint. Returns an opaque error string on
/// any failure (wrong key, corrupted ciphertext, malformed JSON).
///
/// M-11: requires the key to be exactly [`AES_KEY_LEN`] bytes (mirrors
/// `encrypt_checkpoint`).
fn decrypt_checkpoint(ciphertext: &[u8], nonce: &[u8], key: &[u8]) -> Result<JsonValue, String> {
    if key.len() != AES_KEY_LEN {
        return Err(format!(
            "Decryption key must be exactly {AES_KEY_LEN} bytes; got {}",
            key.len()
        ));
    }
    if nonce.len() != NONCE_LEN {
        return Err(format!(
            "Nonce must be exactly {NONCE_LEN} bytes; got {}",
            nonce.len()
        ));
    }
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| format!("Failed to create cipher: {e}"))?;
    let nonce = Nonce::from_slice(nonce);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Checkpoint decryption failed — wrong key or corrupted data".to_string())?;
    serde_json::from_slice(&plaintext).map_err(|e| format!("Failed to deserialize checkpoint: {e}"))
}

#[cfg(test)]
mod m11_key_length_tests {
    use super::*;

    fn k(n: usize) -> Vec<u8> {
        vec![0x42u8; n]
    }

    #[test]
    fn encrypt_rejects_short_key() {
        let v = serde_json::json!({});
        let err = encrypt_checkpoint(&v, &k(31)).unwrap_err();
        assert!(err.contains("exactly 32 bytes"), "got {err}");
    }

    #[test]
    fn encrypt_rejects_long_key() {
        // M-11: previously accepted; silently truncated to first 32 bytes.
        let v = serde_json::json!({});
        let err = encrypt_checkpoint(&v, &k(33)).unwrap_err();
        assert!(err.contains("exactly 32 bytes"), "got {err}");
    }

    #[test]
    fn encrypt_accepts_exact_key() {
        let v = serde_json::json!({"x": 1});
        assert!(encrypt_checkpoint(&v, &k(32)).is_ok());
    }

    #[test]
    fn decrypt_rejects_long_key() {
        let err = decrypt_checkpoint(&[], &[0u8; NONCE_LEN], &k(64)).unwrap_err();
        assert!(err.contains("exactly 32 bytes"), "got {err}");
    }

    #[test]
    fn decrypt_rejects_wrong_nonce_length() {
        let err = decrypt_checkpoint(&[], &[0u8; 11], &k(32)).unwrap_err();
        assert!(err.contains("Nonce must be exactly"), "got {err}");
    }
}
