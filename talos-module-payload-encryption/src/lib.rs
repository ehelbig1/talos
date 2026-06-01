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
/// SecretsManager was provided. `format_version` records the AAD
/// version used; v0 = legacy no-AAD (no longer produced by this helper),
/// v1 = AAD-bound to `module_execution_id` (MCP-S2).
#[derive(Default, Debug)]
pub struct EncryptedPayloadBundle {
    pub key_id: Option<Uuid>,
    pub input_enc: Option<Vec<u8>>,
    pub output_enc: Option<Vec<u8>>,
    pub trigger_enc: Option<Vec<u8>>,
    /// MCP-S2: AAD version persisted to `module_executions.payload_format`.
    /// Set to v1 when encryption runs; 0 when bundle is empty (matches
    /// the default for pre-fix legacy rows that never had a column).
    pub format_version: i16,
}

impl EncryptedPayloadBundle {
    /// True when encryption ran (caller writes `*_enc` + NULL plaintext columns).
    /// False when no SecretsManager was wired or all inputs were None
    /// (caller writes plaintext columns as-is).
    pub fn encrypting(&self) -> bool {
        self.key_id.is_some()
    }
}

/// Which logical payload column a ciphertext belongs to. The variant is
/// folded into the AAD (v2+) so input/output/trigger ciphertexts in one row
/// can no longer be swapped for one another by a DB-write attacker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadSlot {
    Input,
    Output,
    Trigger,
}

impl PayloadSlot {
    /// Stable byte tag folded into the v2 AAD. MUST NOT change once rows are
    /// written with it — a changed tag fails decryption of existing v2 rows.
    #[must_use]
    pub const fn aad_tag(self) -> &'static [u8] {
        match self {
            PayloadSlot::Input => b"input",
            PayloadSlot::Output => b"output",
            PayloadSlot::Trigger => b"trigger",
        }
    }
}

/// Canonical AAD builder for a module-payload slot at a given format version.
/// **Both the writer (`encrypt_payload_bundle`) and every reader MUST build
/// the AAD through this one function** so the two sides can never drift.
///
/// * v0 / v1 (legacy rows): AAD = `module_execution_id` bytes only — the
///   row-id binding that blocks cross-row swaps. All three slots share it,
///   so within-row swaps are NOT detected (the gap v2 closes).
/// * v2+: AAD = `module_execution_id` bytes ‖ `0x00` ‖ slot tag. The `0x00`
///   separator is unambiguous because a UUID is a fixed 16 bytes, so the
///   slot tag can never be confused with row-id bytes.
#[must_use]
pub fn payload_slot_aad(
    module_execution_id: Uuid,
    slot: PayloadSlot,
    format_version: i16,
) -> Vec<u8> {
    let mut aad = module_execution_id.as_bytes().to_vec();
    if format_version >= talos_secrets_manager::SecretsManager::AAD_FORMAT_V2 {
        aad.push(0x00);
        aad.extend_from_slice(slot.aad_tag());
    }
    aad
}

/// Decrypt one module-payload slot, reconstructing the version+slot-bound AAD
/// via [`payload_slot_aad`]. Every `module_executions` payload read site MUST
/// route through this helper instead of calling `decrypt_versioned` with a
/// hand-built AAD — that is what keeps readers in lockstep with the writer
/// across the v1→v2 slot-binding change.
pub async fn decrypt_payload_slot(
    secrets_manager: &talos_secrets_manager::SecretsManager,
    key_id: Uuid,
    encrypted: &[u8],
    module_execution_id: Uuid,
    slot: PayloadSlot,
    format_version: i16,
) -> Result<zeroize::Zeroizing<String>> {
    let aad = payload_slot_aad(module_execution_id, slot, format_version);
    secrets_manager
        .decrypt_versioned(key_id, encrypted, &aad, format_version)
        .await
        .with_context(|| format!("payload_encryption: decrypt {slot:?}"))
}

/// Encrypt a payload bundle through the configured SecretsManager.
/// Returns an empty bundle (no-op) when `secrets_manager` is `None` so
/// callers can write plaintext columns unchanged. Returns an empty bundle
/// when all three plaintexts are `None` (nothing to encrypt).
///
/// MCP-S2: `module_execution_id` is bound as AAD so an attacker with DB write
/// capability cannot swap (input|output|trigger)_enc between two
/// `module_executions` rows that share an `encryption_key_id`.
///
/// 2026-05-28 review (low): v2 additionally folds a per-slot tag into the AAD
/// (see [`payload_slot_aad`]). Pre-fix all three slots authenticated under the
/// identical row-id AAD + the same DEK, so a DB-write attacker could swap
/// input_enc ↔ output_enc *within one row* and both still verified — execution
/// input would surface as its output in dashboards/audit/replay. v2 binds each
/// ciphertext to its column so a within-row swap now fails tag verification.
/// Existing v1 rows stay readable (readers dispatch on the per-row
/// `payload_format`).
pub async fn encrypt_payload_bundle(
    secrets_manager: Option<&Arc<talos_secrets_manager::SecretsManager>>,
    module_execution_id: Uuid,
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
    let format_version = talos_secrets_manager::SecretsManager::AAD_FORMAT_V2;
    bundle.format_version = format_version;
    for (slot, value) in [
        (PayloadSlot::Input, input),
        (PayloadSlot::Output, output),
        (PayloadSlot::Trigger, trigger),
    ] {
        let Some(v) = value else { continue };
        let plain = serde_json::to_string(v)
            .with_context(|| format!("payload_encryption: serialize {slot:?}"))?;
        let aad = payload_slot_aad(module_execution_id, slot, format_version);
        let (kid, ciphertext) = sm
            .encrypt_value_with_aad(&plain, &aad)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_aad_v1_is_row_id_only_for_every_slot() {
        let id = Uuid::from_u128(0x1234_5678_9abc_def0_1122_3344_5566_7788);
        let v1 = talos_secrets_manager::SecretsManager::AAD_FORMAT_V1;
        for slot in [
            PayloadSlot::Input,
            PayloadSlot::Output,
            PayloadSlot::Trigger,
        ] {
            assert_eq!(payload_slot_aad(id, slot, v1), id.as_bytes().to_vec());
        }
        // v0 (legacy) behaves like v1: row-id only.
        assert_eq!(
            payload_slot_aad(id, PayloadSlot::Output, 0),
            id.as_bytes().to_vec()
        );
    }

    #[test]
    fn slot_aad_v2_binds_distinct_aad_per_slot() {
        let id = Uuid::from_u128(0xdead_beef_dead_beef_dead_beef_dead_beef);
        let v2 = talos_secrets_manager::SecretsManager::AAD_FORMAT_V2;
        let input = payload_slot_aad(id, PayloadSlot::Input, v2);
        let output = payload_slot_aad(id, PayloadSlot::Output, v2);
        let trigger = payload_slot_aad(id, PayloadSlot::Trigger, v2);
        // All three differ — a within-row swap now changes the AAD, so
        // AES-GCM tag verification fails on a swapped ciphertext.
        assert_ne!(input, output);
        assert_ne!(output, trigger);
        assert_ne!(input, trigger);
        // Each is row-id ‖ 0x00 ‖ tag, and the v2 AAD differs from the v1 AAD.
        assert_eq!(&input[..16], id.as_bytes());
        assert_eq!(input[16], 0x00);
        assert_eq!(&input[17..], b"input");
        assert_ne!(input, payload_slot_aad(id, PayloadSlot::Input, v2 - 1));
    }
}
