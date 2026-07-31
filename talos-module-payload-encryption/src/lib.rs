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

    /// Prometheus `stage` label for
    /// `talos_module_payload_encryption_failures_total`. Deliberately NOT
    /// derived from [`Self::aad_tag`]: the AAD tag is `trigger` (a wire
    /// constant that can never change without breaking existing rows) while
    /// the metric label — and the `TalosModulePayloadEncryptionFailures`
    /// alert annotation, and the crypto Grafana panel's `sum by (op, stage)`
    /// — say `trigger_metadata`, after the DB column. Two different
    /// contracts; keep them separate.
    #[must_use]
    pub const fn metric_stage(self) -> &'static str {
        match self {
            PayloadSlot::Input => "input",
            PayloadSlot::Output => "output",
            PayloadSlot::Trigger => "trigger_metadata",
        }
    }
}

/// Count one `module_executions` payload crypto failure on
/// `talos_module_payload_encryption_failures_total{op,stage}`.
///
/// This crate is the single chokepoint both directions pass through
/// ([`encrypt_payload_bundle`] has 5 caller sites across 3 crates,
/// [`decrypt_payload_slot`] has 9 across 3 more), and it is the only place
/// with the failing SLOT in scope — `ModuleExecutionService` encrypts input
/// and trigger_metadata in ONE call, so a caller-side handler could not
/// attribute `stage` at all.
///
/// Both labels are `&'static str` from the closed sets `{encrypt, decrypt}`
/// × [`PayloadSlot::metric_stage`], so cardinality is fixed at 6 series. No
/// identifier, ciphertext, key id, or error text reaches a label — the error
/// keeps carrying that detail to the logs via `with_context`.
///
/// Inert (never unwraps) when `talos_metrics::set_global` has not run, per
/// the `talos_metrics::global` contract.
fn inc_payload_crypto_failure(op: &'static str, stage: &'static str) {
    if let Some(m) = talos_metrics::global() {
        m.module_payload_encryption_failures_total
            .with_label_values(&[op, stage])
            .inc();
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
        .inspect_err(|_| inc_payload_crypto_failure("decrypt", slot.metric_stage()))
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
/// Resolve the org a module-execution's payloads encrypt under — the execution's
/// TENANT org = the workflow's org (matching workflow-output crypto, #326). Prefer
/// the caller-supplied `workflow_execution_id` (available at record_started);
/// otherwise fall back to the existing `module_executions` row (record_completed,
/// where the row exists but the parent id isn't in scope). `None` (standalone /
/// webhook / org-less) → the global DEK. Because both the started and completed
/// writes of one row resolve the SAME org, the shared `payload_enc_key_id` stays
/// consistent across slots. Best-effort: a DB error degrades to None (global)
/// rather than failing the encrypt.
async fn resolve_workflow_org(
    sm: &talos_secrets_manager::SecretsManager,
    workflow_execution_id: Option<Uuid>,
    module_execution_id: Uuid,
) -> Option<Uuid> {
    let pool = sm.db_pool();
    let row: std::result::Result<Option<Option<Uuid>>, sqlx::Error> = match workflow_execution_id {
        Some(wei) => {
            sqlx::query_scalar(
                "SELECT w.org_id FROM workflow_executions we \
                 JOIN workflows w ON w.id = we.workflow_id WHERE we.id = $1",
            )
            .bind(wei)
            .fetch_optional(pool)
            .await
        }
        None => {
            sqlx::query_scalar(
                "SELECT w.org_id FROM module_executions me \
                 JOIN workflow_executions we ON we.id = me.workflow_execution_id \
                 JOIN workflows w ON w.id = we.workflow_id WHERE me.id = $1",
            )
            .bind(module_execution_id)
            .fetch_optional(pool)
            .await
        }
    };
    row.ok().flatten().flatten()
}

pub async fn encrypt_payload_bundle(
    secrets_manager: Option<&Arc<talos_secrets_manager::SecretsManager>>,
    module_execution_id: Uuid,
    workflow_execution_id: Option<Uuid>,
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
    // Per-org DEK arc: encrypt under the execution's tenant org (the workflow's
    // org, resolved below); org-less / standalone payloads stay on the global DEK.
    // v3/v4 share the same per-slot AAD (`payload_slot_aad` includes the slot tag
    // for any format >= V2) and the per-context-derived key — v4 only differs in
    // using the org's root DEK as IKM. Readers dispatch on the per-row
    // `payload_format`, so existing v0/v1/v2/v3 rows stay readable.
    let org_id = resolve_workflow_org(sm, workflow_execution_id, module_execution_id).await;
    let format_version = if org_id.is_some() {
        talos_secrets_manager::SecretsManager::AAD_FORMAT_V4_ORG_DERIVED
    } else {
        talos_secrets_manager::SecretsManager::AAD_FORMAT_V3_DERIVED
    };
    bundle.format_version = format_version;
    for (slot, value) in [
        (PayloadSlot::Input, input),
        (PayloadSlot::Output, output),
        (PayloadSlot::Trigger, trigger),
    ] {
        let Some(v) = value else { continue };
        let stage = slot.metric_stage();
        let plain = serde_json::to_string(v)
            .inspect_err(|_| inc_payload_crypto_failure("encrypt", stage))
            .with_context(|| format!("payload_encryption: serialize {slot:?}"))?;
        let aad = payload_slot_aad(module_execution_id, slot, format_version);
        let (kid, ciphertext, _version) = sm
            .encrypt_value_aad_v4_or_global(&plain, org_id, &aad)
            .await
            .inspect_err(|_| inc_payload_crypto_failure("encrypt", stage))
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
                inc_payload_crypto_failure("encrypt", stage);
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

    /// The slot AAD tags are wire-format constants: rows are written with
    /// these exact bytes folded into the GCM tag, so ANY change fails
    /// decryption of every existing v2+ row. Locked byte-for-byte.
    #[test]
    fn slot_aad_tags_are_frozen_wire_constants() {
        assert_eq!(PayloadSlot::Input.aad_tag(), b"input");
        assert_eq!(PayloadSlot::Output.aad_tag(), b"output");
        assert_eq!(PayloadSlot::Trigger.aad_tag(), b"trigger");
    }

    /// v3 and v4 reconstruct the SAME AAD bytes as v2 (the `>= V2` branch):
    /// the org-derived formats differ only in WHICH key is the HKDF IKM,
    /// never in the AAD. A drift here would break decryption of every
    /// v3/v4 row, since readers rebuild the AAD from the version column.
    #[test]
    fn slot_aad_v3_v4_identical_to_v2() {
        let id = Uuid::from_u128(0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10);
        let v2 = talos_secrets_manager::SecretsManager::AAD_FORMAT_V2;
        let v3 = talos_secrets_manager::SecretsManager::AAD_FORMAT_V3_DERIVED;
        let v4 = talos_secrets_manager::SecretsManager::AAD_FORMAT_V4_ORG_DERIVED;
        for slot in [
            PayloadSlot::Input,
            PayloadSlot::Output,
            PayloadSlot::Trigger,
        ] {
            let aad_v2 = payload_slot_aad(id, slot, v2);
            assert_eq!(payload_slot_aad(id, slot, v3), aad_v2, "{slot:?} v3 == v2");
            assert_eq!(payload_slot_aad(id, slot, v4), aad_v2, "{slot:?} v4 == v2");
        }
    }

    /// The AAD is deterministic (encrypt and decrypt sides must derive the
    /// identical bytes) and distinct across rows (the cross-row swap
    /// protection: two rows sharing a DEK never share an AAD).
    #[test]
    fn slot_aad_deterministic_and_distinct_across_rows() {
        let row_a = Uuid::new_v4();
        let row_b = Uuid::new_v4();
        for version in [
            0,
            talos_secrets_manager::SecretsManager::AAD_FORMAT_V1,
            talos_secrets_manager::SecretsManager::AAD_FORMAT_V2,
            talos_secrets_manager::SecretsManager::AAD_FORMAT_V3_DERIVED,
            talos_secrets_manager::SecretsManager::AAD_FORMAT_V4_ORG_DERIVED,
        ] {
            assert_eq!(
                payload_slot_aad(row_a, PayloadSlot::Output, version),
                payload_slot_aad(row_a, PayloadSlot::Output, version),
                "AAD must be deterministic at v{version}"
            );
            assert_ne!(
                payload_slot_aad(row_a, PayloadSlot::Output, version),
                payload_slot_aad(row_b, PayloadSlot::Output, version),
                "distinct rows must yield distinct AADs at v{version} (cross-row swap defense)"
            );
            // The row id always leads the AAD, at every version.
            assert_eq!(
                &payload_slot_aad(row_a, PayloadSlot::Output, version)[..16],
                row_a.as_bytes()
            );
        }
    }

    /// Default bundle is the "not encrypting" sentinel the callers branch on:
    /// no key id, no ciphertexts, and format_version 0 (the pre-fix legacy
    /// default) — so plaintext-column writes stay byte-identical.
    #[test]
    fn default_bundle_is_non_encrypting_with_legacy_format() {
        let bundle = EncryptedPayloadBundle::default();
        assert!(!bundle.encrypting());
        assert!(bundle.key_id.is_none());
        assert!(bundle.input_enc.is_none());
        assert!(bundle.output_enc.is_none());
        assert!(bundle.trigger_enc.is_none());
        assert_eq!(bundle.format_version, 0);
    }
}

/// Async tests for the no-DB-reachable paths of the encrypt/decrypt entry
/// points. Follows the repo's stub-constructor pattern (see
/// `SecretsManager::test_stub_for_cache`): a REAL `SecretsManager` over a lazy
/// pool that is never connected — every test here exercises only branches that
/// return before any query, so a DB touch fails the test loudly instead of
/// passing vacuously.
///
/// The full ciphertext round-trip (per-version encrypt→decrypt, wrong-AAD
/// rejection, nonce uniqueness) requires a provisioned DEK, which is DB-backed
/// (`encryption_keys`); that coverage lives with the crypto itself in
/// `talos-secrets-manager` (v3 derive/AEAD tests) and the DB-backed
/// integration suite — it cannot run as a unit test from this crate without a
/// Postgres instance.
#[cfg(test)]
mod stub_sm_tests {
    use super::*;
    use serde_json::json;

    /// `talos_module_payload_encryption_failures_total` is process-global
    /// while these tests run concurrently in one binary, so any test that
    /// drives a crypto FAILURE (i.e. bumps the counter) must hold this while
    /// it does, or the delta-assert below sees sibling traffic. Held by every
    /// counter-moving test in this module — add new ones to the list.
    /// `into_inner` on poison: a sibling panic must not cascade into an
    /// unrelated failure here.
    static METRIC_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn metric_guard() -> std::sync::MutexGuard<'static, ()> {
        METRIC_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Real SecretsManager over a never-connected lazy pool + a real (non-zero)
    /// env KEK. Any code path that touches the pool errors on connect — which
    /// is exactly what these tests rely on NOT happening.
    fn stub_sm() -> Arc<talos_secrets_manager::SecretsManager> {
        let lazy_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://127.0.0.1:1/talos_never_connects")
            .expect("lazy pool build");
        let kek = Arc::new(
            talos_secrets_manager::kek_provider::EnvKekProvider::from_hex(&"ab".repeat(32))
                .expect("stub KEK"),
        );
        Arc::new(
            talos_secrets_manager::SecretsManager::with_kek_provider(lazy_pool, kek)
                .expect("stub SecretsManager"),
        )
    }

    /// No SecretsManager wired → empty bundle even with plaintexts present,
    /// so callers write the plaintext columns unchanged (the encryption-off
    /// deployment posture).
    #[tokio::test]
    async fn no_secrets_manager_yields_empty_bundle() {
        let bundle = encrypt_payload_bundle(
            None,
            Uuid::new_v4(),
            Some(Uuid::new_v4()),
            Some(&json!({"in": 1})),
            Some(&json!({"out": 2})),
            Some(&json!({"trig": 3})),
        )
        .await
        .expect("no-op path succeeds");
        assert!(!bundle.encrypting());
        assert!(bundle.input_enc.is_none());
        assert!(bundle.output_enc.is_none());
        assert!(bundle.trigger_enc.is_none());
        assert_eq!(bundle.format_version, 0);
    }

    /// All three plaintexts `None` → empty bundle WITHOUT touching the DB
    /// (the early return precedes org resolution). A regression that moves
    /// the org lookup ahead of the emptiness check fails here with a
    /// connection error against the never-connected pool.
    #[tokio::test]
    async fn all_none_inputs_yield_empty_bundle_without_db_access() {
        let sm = stub_sm();
        let bundle = encrypt_payload_bundle(Some(&sm), Uuid::new_v4(), None, None, None, None)
            .await
            .expect("nothing-to-encrypt path must not hit the DB");
        assert!(!bundle.encrypting());
        assert_eq!(bundle.format_version, 0);
    }

    /// Unknown format versions fail CLOSED at the decrypt dispatcher —
    /// before any key lookup — instead of guessing an AAD scheme. Covers a
    /// future v5 row read by this (older) reader, and corrupted/negative
    /// version columns.
    #[tokio::test]
    async fn decrypt_unknown_format_fails_closed_without_db_access() {
        let _g = metric_guard();
        let sm = stub_sm();
        let row = Uuid::new_v4();
        // Plausible ciphertext length (nonce + tag + payload) so the failure
        // can only come from the version dispatch, not a length check.
        let ciphertext = vec![0u8; 12 + 16 + 32];
        for bad_version in [5i16, 99, -1, i16::MAX, i16::MIN] {
            let err = decrypt_payload_slot(
                &sm,
                Uuid::new_v4(),
                &ciphertext,
                row,
                PayloadSlot::Output,
                bad_version,
            )
            .await
            .expect_err("unknown format must fail closed");
            // The context wrapper names the slot for triage without leaking
            // key material or AAD bytes.
            assert!(
                format!("{err:#}").contains("payload_encryption: decrypt Output"),
                "error context names the failing slot: {err:#}"
            );
        }
    }

    /// A v3/v4 blob shorter than the 12-byte nonce prefix is structurally
    /// invalid and must be rejected before any DEK lookup (fail-closed on
    /// malformed rows, no DB dependency).
    #[tokio::test]
    async fn decrypt_derived_format_rejects_truncated_ciphertext() {
        let _g = metric_guard();
        let sm = stub_sm();
        let row = Uuid::new_v4();
        for version in [
            talos_secrets_manager::SecretsManager::AAD_FORMAT_V3_DERIVED,
            talos_secrets_manager::SecretsManager::AAD_FORMAT_V4_ORG_DERIVED,
        ] {
            for truncated in [&[][..], &[0u8; 1][..], &[0u8; 11][..]] {
                assert!(
                    decrypt_payload_slot(
                        &sm,
                        Uuid::new_v4(),
                        truncated,
                        row,
                        PayloadSlot::Input,
                        version,
                    )
                    .await
                    .is_err(),
                    "v{version} blob of {} bytes must be rejected",
                    truncated.len()
                );
            }
        }
    }

    /// D3 pin for `talos_module_payload_encryption_failures_total`.
    ///
    /// Drives the REAL production `decrypt_payload_slot` /
    /// `encrypt_payload_bundle` into their real failure edges and asserts the
    /// counter moved — deliberately NOT a `render_prometheus` shape test.
    /// A metrics-render test is exactly what made this metric look alive for
    /// months while every one of its production paths was silent, and what
    /// made check 58 report it as instrumented.
    ///
    /// Deltas, never absolutes: `set_global` is a process-wide one-shot
    /// `OnceLock`, so sibling tests in this binary share the registry and may
    /// run concurrently. Read back through `talos_metrics::global()` rather
    /// than the local `Arc` for the same reason — another test may have won
    /// the `set_global` race.
    #[tokio::test]
    async fn payload_crypto_failures_are_counted_on_the_production_path() {
        let _g = metric_guard();
        talos_metrics::set_global(talos_metrics::TalosMetrics::new().expect("metrics"));
        let m = talos_metrics::global().expect("global installed");
        let read = |op: &str, stage: &str| {
            m.module_payload_encryption_failures_total
                .with_label_values(&[op, stage])
                .get()
        };

        // ── decrypt: unknown format version, fails closed with no DB touch.
        let before = read("decrypt", "output");
        decrypt_payload_slot(
            &stub_sm(),
            Uuid::new_v4(),
            &vec![0u8; 12 + 16 + 32],
            Uuid::new_v4(),
            PayloadSlot::Output,
            99,
        )
        .await
        .expect_err("unknown format must fail closed");
        assert_eq!(
            read("decrypt", "output") - before,
            1.0,
            "decrypt failure must bump {{op=decrypt,stage=output}}"
        );

        // ── decrypt: the Trigger slot reports stage `trigger_metadata` (the
        // DB column / alert-annotation spelling), NOT the `trigger` AAD wire
        // tag. An alert or Grafana panel selecting on the wrong spelling is
        // the same false assurance as a dead counter.
        let before = read("decrypt", "trigger_metadata");
        decrypt_payload_slot(
            &stub_sm(),
            Uuid::new_v4(),
            &vec![0u8; 60],
            Uuid::new_v4(),
            PayloadSlot::Trigger,
            99,
        )
        .await
        .expect_err("unknown format must fail closed");
        assert_eq!(read("decrypt", "trigger_metadata") - before, 1.0);
        assert_eq!(
            m.module_payload_encryption_failures_total
                .with_label_values(&["decrypt", "trigger"])
                .get(),
            0.0,
            "stage label must be trigger_metadata, not the AAD tag"
        );

        // ── encrypt: a real bundle write whose DEK lookup cannot reach
        // Postgres. Own pool (not stub_sm) so the refused connection fails in
        // ~250ms instead of on sqlx's 30s default acquire timeout.
        let fast_fail_sm = {
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                .acquire_timeout(std::time::Duration::from_millis(250))
                .connect_lazy("postgres://127.0.0.1:1/talos_never_connects")
                .expect("lazy pool build");
            let kek = Arc::new(
                talos_secrets_manager::kek_provider::EnvKekProvider::from_hex(&"cd".repeat(32))
                    .expect("stub KEK"),
            );
            Arc::new(
                talos_secrets_manager::SecretsManager::with_kek_provider(pool, kek)
                    .expect("stub SecretsManager"),
            )
        };
        let before = read("encrypt", "input");
        encrypt_payload_bundle(
            Some(&fast_fail_sm),
            Uuid::new_v4(),
            None,
            Some(&json!({"in": 1})),
            None,
            None,
        )
        .await
        .expect_err("DEK resolution must fail against a dead pool");
        assert_eq!(
            read("encrypt", "input") - before,
            1.0,
            "encrypt failure must bump {{op=encrypt,stage=input}}"
        );
    }

    /// The `stage` label set is fixed at three values and is NOT derived from
    /// the AAD wire tag — two contracts that must not be collapsed (the AAD
    /// tag can never change without breaking existing rows; the label follows
    /// the DB column name the alert annotation prints).
    #[test]
    fn metric_stage_labels_are_the_documented_closed_set() {
        assert_eq!(PayloadSlot::Input.metric_stage(), "input");
        assert_eq!(PayloadSlot::Output.metric_stage(), "output");
        assert_eq!(PayloadSlot::Trigger.metric_stage(), "trigger_metadata");
        assert_eq!(PayloadSlot::Trigger.aad_tag(), b"trigger");
    }
}
