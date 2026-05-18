//! Shared payload encryption for `module_executions.{input,output,trigger_metadata}_enc`.
//!
//! Multiple writer paths exist (canonical `ModuleExecutionService`, the
//! engine's `PostgresModuleExecutionStore`, webhook trigger handler).
//! This module is the single source of truth for the wire format so
//! they all produce identical-shaped ciphertext under the same DEK.
//!
//! The three payload columns share one DEK because they're co-written
//! per row — `payload_enc_key_id` is the FK to that DEK.
//!
//! Wire format mirrors `actor_memory.value_enc`: opaque BYTEA produced
//! by `SecretsManager.encrypt_value`, decrypted via
//! `SecretsManager.decrypt_value_by_key(payload_enc_key_id, bytes)`.

use anyhow::{Context, Result};
use serde_json::Value as JsonValue;
use std::sync::Arc;
use uuid::Uuid;

/// Result of encrypting a payload bundle. Each `Option<Vec<u8>>` is `Some`
/// iff the corresponding plaintext input was `Some`. `key_id` is `Some`
/// iff at least one of the three plaintexts was non-`None` AND the
/// SecretsManager was provided.
#[derive(Default, Debug)]
pub struct EncryptedPayloadBundle {
    pub key_id: Option<Uuid>,
    pub input_enc: Option<Vec<u8>>,
    pub output_enc: Option<Vec<u8>>,
    pub trigger_enc: Option<Vec<u8>>,
}

impl EncryptedPayloadBundle {
    /// True when encryption ran (caller writes `*_enc` + NULL plaintext columns).
    /// False when no SecretsManager was wired or all inputs were None
    /// (caller writes plaintext columns as-is).
    pub fn encrypting(&self) -> bool {
        self.key_id.is_some()
    }
}

/// Encrypt a payload bundle through the configured SecretsManager.
/// Returns an empty bundle (no-op) when `secrets_manager` is `None` so
/// callers can write plaintext columns unchanged. Returns an empty bundle
/// when all three plaintexts are `None` (nothing to encrypt).
pub async fn encrypt_payload_bundle(
    secrets_manager: Option<&Arc<talos_secrets_manager::SecretsManager>>,
    input: Option<&JsonValue>,
    output: Option<&JsonValue>,
    trigger: Option<&JsonValue>,
) -> Result<EncryptedPayloadBundle> {
    let Some(sm) = secrets_manager else {
        return Ok(EncryptedPayloadBundle::default());
    };
    if input.is_none() && output.is_none() && trigger.is_none() {
        return Ok(EncryptedPayloadBundle::default());
    }

    let mut bundle = EncryptedPayloadBundle::default();
    for (slot, value) in [
        (PayloadSlot::Input, input),
        (PayloadSlot::Output, output),
        (PayloadSlot::Trigger, trigger),
    ] {
        let Some(v) = value else { continue };
        let plain = serde_json::to_string(v)
            .with_context(|| format!("payload_encryption: serialize {slot:?}"))?;
        let (kid, ciphertext) = sm
            .encrypt_value(&plain)
            .await
            .with_context(|| format!("payload_encryption: encrypt {slot:?}"))?;
        if let Some(prev) = bundle.key_id {
            // M-3: a single bundle write must reuse the same DEK across
            // columns. If the active DEK rotated mid-write the bundle
            // would have mixed key_ids — earlier ciphertexts referencing
            // the OLD DEK become unrecoverable when `bundle.key_id` is
            // overwritten with the NEW one. Previously this used
            // `debug_assert_eq!` which only fires in dev builds; in
            // release the silent overwrite class of bug shipped.
            //
            // Fail-closed in release too: bail and let the caller retry
            // — the next attempt will see a stable active DEK across all
            // bundle slots.
            if prev != kid {
                anyhow::bail!(
                    "payload_encryption: DEK rotated mid-bundle write (prev={prev}, current={kid}); \
                     retry the write so all slots reference one DEK"
                );
            }
        }
        bundle.key_id = Some(kid);
        match slot {
            PayloadSlot::Input => bundle.input_enc = Some(ciphertext),
            PayloadSlot::Output => bundle.output_enc = Some(ciphertext),
            PayloadSlot::Trigger => bundle.trigger_enc = Some(ciphertext),
        }
    }
    Ok(bundle)
}

#[derive(Debug, Clone, Copy)]
enum PayloadSlot {
    Input,
    Output,
    Trigger,
}
