//! Postgres-backed implementation of [`CheckpointStore`].
//!
//! Owns the AES-256-GCM encrypt/decrypt path (formerly free functions on
//! the engine) plus the query the engine used to carry on its
//! `load_checkpoint` method.

use std::collections::HashMap;
use std::fmt;

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use async_trait::async_trait;
use hkdf::Hkdf;
use rand::RngCore;
use serde_json::Value as JsonValue;
use sha2::Sha256;
use sqlx::{Pool, Postgres};
use talos_workflow_engine_core::{BoxError, CheckpointStore};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Minimum key length for AES-256-GCM. Keys longer than this are
/// truncated to the first 32 bytes.
const AES_KEY_LEN: usize = 32;

/// AES-GCM nonce length used by the `aes_gcm` crate's default.
const NONCE_LEN: usize = 12;

/// HKDF-SHA256 domain-separation label for the checkpoint AEAD subkey.
///
/// `WORKER_SHARED_KEY` is the root for several primitives (rpc_auth /
/// JobRequest / JobResult HMAC signing, and the secret-envelope AES-GCM
/// subkey in `talos-workflow-job-protocol`). Encrypting checkpoints with
/// the RAW root reused it as an AEAD key across primitives. We instead
/// derive a dedicated 32-byte subkey via HKDF with this UNIQUE label —
/// distinct from the envelope label (`.../envelope-aead/v1`) so the two
/// subkeys never collide. Bumping the `v1` suffix forces a clean
/// fleet-wide re-key (same operational cost as rotating the root).
///
/// NOTE (migration): this change moves checkpoints off the raw root and
/// adds `execution_id` AAD binding. Checkpoints written under the OLD
/// scheme (raw key, no AAD) will NO LONGER decrypt and fail closed with
/// a clear error — the same constraint the envelope HKDF change (5eedad8)
/// accepted. Checkpoints are transient execution-resume state, so a fleet
/// restart that re-runs in-flight waiting workflows from scratch is an
/// acceptable one-time cost.
const CHECKPOINT_AEAD_KEY_LABEL: &[u8] = b"talos/worker-shared-key/checkpoint-aead/v1";

/// v2 label (finding #1): the per-execution checkpoint subkey folds the
/// `execution_id` into the HKDF `info` so each execution gets its OWN AES
/// key. The AES-GCM random-nonce birthday budget is then consumed per
/// execution (at most the node-checkpoint writes of one workflow run)
/// instead of globally across every checkpoint the fleet ever writes
/// under one `WORKER_SHARED_KEY`. Distinct from the v1 label so a v2
/// subkey can never collide with the legacy static one.
const CHECKPOINT_AEAD_KEY_LABEL_V2: &[u8] =
    b"talos/worker-shared-key/checkpoint-aead/v2-per-execution";

/// v1 (legacy) derivation: a single static subkey per root, used by every
/// checkpoint regardless of execution. Retained ONLY as a decrypt
/// fallback so in-flight checkpoints written before the v2 rollout still
/// resume during the migration window. New writes use [`derive_checkpoint_aead_key`].
fn derive_checkpoint_aead_key_legacy_v1(root: &[u8]) -> Zeroizing<[u8; AES_KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(None, root);
    let mut subkey = Zeroizing::new([0u8; AES_KEY_LEN]);
    hk.expand(CHECKPOINT_AEAD_KEY_LABEL, subkey.as_mut())
        .expect("HKDF-SHA256 expand to 32 bytes is always a valid length");
    subkey
}

/// Expand the root `WORKER_SHARED_KEY` into the per-execution 32-byte
/// AES-256-GCM subkey for execution checkpoints (v2). The `execution_id`
/// bytes are the HKDF `info`, so the subkey is unique per execution.
/// Pure and deterministic; encrypt and decrypt derive it identically.
/// Mirrors `derive_envelope_aead_key` in `talos-workflow-job-protocol`
/// but with a distinct domain-separation label + per-execution info.
fn derive_checkpoint_aead_key(root: &[u8], execution_aad: &[u8]) -> Zeroizing<[u8; AES_KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(Some(CHECKPOINT_AEAD_KEY_LABEL_V2), root);
    let mut subkey = Zeroizing::new([0u8; AES_KEY_LEN]);
    hk.expand(execution_aad, subkey.as_mut())
        .expect("HKDF-SHA256 expand to 32 bytes is always a valid length");
    subkey
}

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
    /// Previous `WORKER_SHARED_KEY` roots accepted for checkpoint *decryption*
    /// only (the decrypt-ring). Empty in steady state. During a rolling
    /// `WORKER_SHARED_KEY` rotation, the operator stages the old root here so a
    /// checkpoint written under the old key still resumes — closing the
    /// "checkpoint present but failed to decrypt → re-run from scratch" window
    /// the `load` path otherwise logs loudly. `save` never uses these: new
    /// checkpoints are always written under the current `worker_shared_key`.
    /// See [`with_previous_worker_shared_keys`](Self::with_previous_worker_shared_keys).
    previous_worker_shared_keys: Vec<Vec<u8>>,
    /// Execution statuses `load` will read a checkpoint from. Defaults to
    /// `["waiting"]` (the suspend/approval-gate resume path). Crash recovery
    /// sets this to `["waiting", "resuming"]` via [`with_resume_statuses`]
    /// (`ControllerCheckpointStore::with_resume_statuses`) so a claimed
    /// (`resuming`) orphaned execution actually hydrates its checkpoint —
    /// without it, all three `load` branches filter `status='waiting'` and a
    /// `resuming` row silently loads empty → re-runs from scratch.
    load_statuses: Vec<String>,
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
                &self
                    .secrets_manager
                    .as_ref()
                    .map(|_| "<wired>")
                    .unwrap_or("None"),
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
        // Auto-populate the decrypt-ring from WORKER_SHARED_KEY_PREVIOUS so a
        // checkpoint written under the old root still resumes during a rolling
        // rotation — every construction path (load helpers, scheduler, builder,
        // crash recovery) inherits it without call-site churn. Empty when the
        // env var is unset (tests/CI), so behavior is unchanged off-rotation.
        // Use `with_previous_worker_shared_keys` to override explicitly.
        let previous_worker_shared_keys =
            talos_workflow_job_protocol::load_worker_shared_key_previous()
                .unwrap_or_default()
                .into_iter()
                .map(|k| k.as_bytes().to_vec())
                .collect();
        Self {
            pool,
            worker_shared_key,
            secrets_manager: None,
            previous_worker_shared_keys,
            load_statuses: vec!["waiting".to_string()],
        }
    }

    /// Stage previous `WORKER_SHARED_KEY` roots for the checkpoint
    /// decrypt-ring. `load` tries the current key first, then each of these in
    /// turn; the loud "stranded checkpoint" error only fires when *every* key
    /// fails. `save` is unaffected — new checkpoints always use the current
    /// key. Pass the bytes of each previous 32-byte root (e.g. from
    /// `WorkerKeyRing::verify_keys()` minus the signing key).
    #[must_use]
    pub fn with_previous_worker_shared_keys(mut self, previous: Vec<Vec<u8>>) -> Self {
        self.previous_worker_shared_keys = previous;
        self
    }

    /// Crash recovery (RFC 0003): also read a checkpoint from `resuming`
    /// rows (the claimed-orphan state), not just `waiting`. Without this the
    /// startup resume sweep would load an empty checkpoint for every claimed
    /// execution and re-run it from scratch.
    #[must_use]
    pub fn with_resume_statuses(mut self) -> Self {
        self.load_statuses = vec!["waiting".to_string(), "resuming".to_string()];
        self
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

/// Crash-recovery variant of [`load_checkpoint_for_full`] that also reads a
/// checkpoint from `resuming` rows (the claimed-orphan state), not just
/// `waiting`. The startup resume sweep MUST use this — `load_checkpoint_for_full`
/// would return an empty map for a `resuming` row (all three branches filter
/// `status='waiting'`), silently re-running the workflow from scratch.
pub async fn load_checkpoint_for_resume(
    pool: &Pool<Postgres>,
    worker_shared_key: Option<&[u8]>,
    secrets_manager: Option<std::sync::Arc<talos_secrets_manager::SecretsManager>>,
    execution_id: Uuid,
) -> HashMap<Uuid, JsonValue> {
    let mut store =
        ControllerCheckpointStore::new(pool.clone(), worker_shared_key.map(<[u8]>::to_vec))
            .with_resume_statuses();
    if let Some(sm) = secrets_manager {
        store = store.with_secrets_manager(sm);
    }
    match store.load(execution_id).await {
        Ok(map) => map,
        Err(e) => {
            tracing::warn!(
                %execution_id,
                error = %e,
                "Failed to load checkpoint for resume — treating as fresh run"
            );
            HashMap::new()
        }
    }
}

#[async_trait]
impl CheckpointStore for ControllerCheckpointStore {
    async fn save(
        &self,
        execution_id: Uuid,
        snapshot: &JsonValue,
        seq: i64,
    ) -> Result<(), BoxError> {
        // Silently no-op when no key is configured. Save paths run on
        // happy-path workflow completion; aborting the workflow because
        // the operator hasn't wired up `WORKER_SHARED_KEY` would be a
        // worse user experience than a missing encrypted checkpoint,
        // and `load` already tolerates the absence at resume time.
        let Some(key) = self.worker_shared_key.as_deref() else {
            return Ok(());
        };
        // AAD binds the ciphertext to this execution_id so a DB-write
        // attacker can't transpose a checkpoint blob from one execution
        // into another and have it decrypt cleanly.
        let (ciphertext, nonce) = encrypt_checkpoint(snapshot, key, execution_id.as_bytes())
            .map_err(|e| -> BoxError { e.into() })?;
        // Two WHERE guards on the fire-and-forget per-node save:
        //
        // 1. Status: never write a checkpoint to a TERMINAL execution. A
        //    save spawned just before the execution is marked
        //    completed/failed/cancelled could otherwise land afterward and
        //    leave stale resume material on a finished row. (`load` also
        //    filters to waiting/resuming, so this is defence in depth.)
        //
        // 2. Monotonicity (`$4 >= checkpoint_seq`): saves race — a write
        //    capturing N completed nodes can land AFTER one capturing N+k.
        //    `seq` is the snapshot's node count (monotone over the
        //    execution's life, continuing across a resume because the
        //    resumed engine re-seeds its result map from the loaded
        //    checkpoint). Dropping a strictly-smaller seq means a reordered
        //    stale snapshot can never clobber a newer one and lose progress.
        //    Equal seq is idempotent (same node set ⇒ same snapshot).
        sqlx::query(
            "UPDATE workflow_executions \
             SET checkpoint_encrypted = $1, checkpoint_nonce = $2, checkpoint_seq = $4 \
             WHERE id = $3 AND status NOT IN ('completed', 'failed', 'cancelled') \
               AND $4 >= checkpoint_seq",
        )
        .bind(&ciphertext)
        .bind(&nonce)
        .bind(execution_id)
        .bind(seq)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn load(&self, execution_id: Uuid) -> Result<HashMap<Uuid, JsonValue>, BoxError> {
        // Plain-JSON fast path: older executions and ones written with no key.
        let row: Option<(Option<JsonValue>,)> = sqlx::query_as(
            "SELECT output_data FROM workflow_executions \
             WHERE id = $1 AND status = ANY($2)",
        )
        .bind(execution_id)
        .bind(&self.load_statuses)
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
                 WHERE id = $1 AND status = ANY($2) AND checkpoint_encrypted IS NOT NULL",
            )
            .bind(execution_id)
            .bind(&self.load_statuses)
            .fetch_optional(&self.pool)
            .await?;

            if let Some((ciphertext, nonce)) = enc_row {
                match decrypt_checkpoint_ring(
                    &ciphertext,
                    &nonce,
                    key,
                    &self.previous_worker_shared_keys,
                    execution_id.as_bytes(),
                ) {
                    Ok(decrypted) => {
                        return Ok(decrypted
                            .as_object()
                            .map(uuid_keyed_map)
                            .unwrap_or_default());
                    }
                    Err(e) => {
                        // A checkpoint blob is PRESENT but won't decrypt under
                        // the current WORKER_SHARED_KEY. The dominant cause is
                        // a WSK rotation: the checkpoint AEAD key is derived
                        // from the WSK, so rotating it strands every in-flight
                        // checkpoint. Surface this LOUDLY and specifically —
                        // without it the only signal is a generic "treating as
                        // fresh run" warning, indistinguishable from a clean
                        // no-checkpoint resume, and operators silently lose
                        // mid-execution progress (re-running already-completed
                        // side-effecting nodes, at-least-once) on every
                        // rotation. Mitigation: drain in-flight executions
                        // before rotating WORKER_SHARED_KEY. The error carries
                        // no plaintext (decrypt failed) so it is safe to log.
                        tracing::error!(
                            %execution_id,
                            error = %e,
                            previous_key_count = self.previous_worker_shared_keys.len(),
                            "CRASH-RECOVERY: checkpoint present but failed to decrypt under \
                             the current key OR any staged previous key — almost certainly a \
                             WORKER_SHARED_KEY rotation stranded it. This execution will \
                             resume FROM SCRATCH, re-running any already-completed \
                             side-effecting nodes (at-least-once). When rotating \
                             WORKER_SHARED_KEY, stage the old root in WORKER_SHARED_KEY_PREVIOUS \
                             (the decrypt-ring) and/or drain in-flight executions first."
                        );
                        return Err(e.into());
                    }
                }
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

        // MCP-S2: `output_data_enc` is written AAD-bound to the execution
        // `id` (`encrypt_value_aad_v1`), so the read MUST dispatch on
        // `output_data_format` and supply the same AAD via
        // `decrypt_versioned`. A bare `decrypt_value_by_key` (empty AAD)
        // tag-fails every v1 row, silently dropping the resume seed back to
        // a fresh run on encrypted deploys.
        let dek_row: Option<(Option<Vec<u8>>, Option<Uuid>, i16)> = sqlx::query_as(
            "SELECT output_data_enc, output_enc_key_id, output_data_format FROM workflow_executions \
             WHERE id = $1 AND status = ANY($2) AND output_data_enc IS NOT NULL",
        )
        .bind(execution_id)
        .bind(&self.load_statuses)
        .fetch_optional(&self.pool)
        .await?;

        let Some((Some(enc_bytes), Some(key_id), output_format)) = dek_row else {
            return Ok(HashMap::new());
        };

        // Decrypt-failure is logged + treated as "no checkpoint" —
        // safer than panicking the resume thread. The engine then
        // re-runs from scratch which is a worse UX than a clean
        // resume but better than a crash loop.
        let plain = match sm
            .decrypt_versioned(key_id, &enc_bytes, execution_id.as_bytes(), output_format)
            .await
        {
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
/// The AES-GCM key is an HKDF subkey of `key` (the root
/// `WORKER_SHARED_KEY`), NEVER the raw root — the root is also the HMAC
/// signing key for rpc_auth / JobRequest / JobResult, so reusing it as an
/// AEAD key crosses primitive boundaries. `derive_checkpoint_aead_key`
/// uses a domain-separation label distinct from the secret-envelope label.
///
/// `aad` (the execution_id bytes) is bound into the GCM tag so a blob
/// transposed to a different execution fails the tag check on decrypt.
///
/// M-11: requires the key to be exactly [`AES_KEY_LEN`] bytes. The previous
/// `key.len() < AES_KEY_LEN` check accepted longer keys and silently
/// truncated to the first 32 bytes, which masked operator-error key
/// configurations (hex-encoded keys interpreted as raw bytes,
/// prepend-rotation accidentally using stale material).
fn encrypt_checkpoint(
    data: &JsonValue,
    key: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    if key.len() != AES_KEY_LEN {
        return Err(format!(
            "Encryption key must be exactly {AES_KEY_LEN} bytes; got {}",
            key.len()
        ));
    }
    // Checkpoint plaintext is the serialized node-output JSON, which can
    // carry sensitive workflow data — keep it in Zeroizing so the buffer
    // is wiped on drop.
    let plaintext: Zeroizing<Vec<u8>> = Zeroizing::new(
        serde_json::to_vec(data).map_err(|e| format!("Failed to serialize checkpoint: {e}"))?,
    );
    // v2: per-execution key derivation — `aad` is the execution_id, folded
    // into the HKDF info so the random-nonce budget is per-execution.
    let aead_key = derive_checkpoint_aead_key(key, aad);
    let cipher = Aes256Gcm::new_from_slice(aead_key.as_slice())
        .map_err(|e| format!("Failed to create cipher: {e}"))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext.as_slice(),
                aad,
            },
        )
        .map_err(|e| format!("Encryption failed: {e}"))?;
    Ok((ciphertext, nonce_bytes.to_vec()))
}

/// Decrypt an AES-256-GCM checkpoint. Returns an opaque error string on
/// any failure (wrong key, corrupted ciphertext, malformed JSON, or AAD
/// mismatch). Like `encrypt_checkpoint`, derives the AEAD key via HKDF
/// from the root and binds `aad` (the execution_id bytes) into the tag.
///
/// Fails closed on any mismatch. Checkpoints written under the pre-HKDF
/// scheme (raw root key, no AAD) will NOT decrypt here and surface the
/// standard "wrong key or corrupted data" error — accepted migration cost
/// (transient resume state; see [`CHECKPOINT_AEAD_KEY_LABEL`]).
///
/// M-11: requires the key to be exactly [`AES_KEY_LEN`] bytes (mirrors
/// `encrypt_checkpoint`).
fn decrypt_checkpoint(
    ciphertext: &[u8],
    nonce: &[u8],
    key: &[u8],
    aad: &[u8],
) -> Result<JsonValue, String> {
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
    let nonce = Nonce::from_slice(nonce);

    // Try the v2 per-execution key first (the steady-state hit), then the
    // legacy v1 static key. AES-GCM's tag makes the fallback unambiguous:
    // a v2 ciphertext can NOT pass under the v1 key and vice versa, so the
    // extra attempt never yields a false-accept — it only lets in-flight
    // checkpoints written before the v2 rollout still resume during the
    // migration window. Both attempts bind `aad` (execution_id) in the tag.
    let v2_key = derive_checkpoint_aead_key(key, aad);
    let v1_key = derive_checkpoint_aead_key_legacy_v1(key);
    // Wipe the decrypted node-output bytes on drop, including the
    // deserialize-error branch below.
    let mut plaintext: Option<Zeroizing<Vec<u8>>> = None;
    for candidate in [v2_key, v1_key] {
        let cipher = Aes256Gcm::new_from_slice(candidate.as_slice())
            .map_err(|e| format!("Failed to create cipher: {e}"))?;
        if let Ok(pt) = cipher.decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        ) {
            plaintext = Some(Zeroizing::new(pt));
            break;
        }
    }
    let plaintext = plaintext
        .ok_or_else(|| "Checkpoint decryption failed — wrong key or corrupted data".to_string())?;
    serde_json::from_slice(&plaintext).map_err(|e| format!("Failed to deserialize checkpoint: {e}"))
}

/// Decrypt a checkpoint against a **decrypt-ring**: try `current` first (the
/// steady-state hit), then each `previous` root in turn. Returns the first
/// success; if every key fails, returns the *current*-key error (the most
/// useful diagnostic — `previous` keys are expected to miss for any
/// checkpoint written after the rotation).
///
/// AES-256-GCM's authentication tag makes this safe and unambiguous: a wrong
/// key cannot produce a passing tag, so trying multiple keys never yields a
/// false-accept — at most it costs one extra GCM verification per staged key
/// (the ring is 1–2 entries in practice). This is the AEAD analogue of the
/// `rpc_auth` HMAC verify-ring: encrypt under one key, accept several.
fn decrypt_checkpoint_ring(
    ciphertext: &[u8],
    nonce: &[u8],
    current: &[u8],
    previous: &[Vec<u8>],
    aad: &[u8],
) -> Result<JsonValue, String> {
    let current_err = match decrypt_checkpoint(ciphertext, nonce, current, aad) {
        Ok(v) => return Ok(v),
        Err(e) => e,
    };
    for prev in previous {
        if let Ok(v) = decrypt_checkpoint(ciphertext, nonce, prev, aad) {
            return Ok(v);
        }
    }
    Err(current_err)
}

#[cfg(test)]
mod decrypt_ring_tests {
    use super::*;

    fn root(byte: u8) -> Vec<u8> {
        vec![byte; AES_KEY_LEN]
    }

    #[test]
    fn current_key_decrypts_without_consulting_previous() {
        let cur = root(0x01);
        let snapshot = serde_json::json!({"node": 1});
        let (ct, nonce) = encrypt_checkpoint(&snapshot, &cur, b"exec-a").unwrap();
        // No previous keys needed.
        let got = decrypt_checkpoint_ring(&ct, &nonce, &cur, &[], b"exec-a").unwrap();
        assert_eq!(got, snapshot);
    }

    #[test]
    fn previous_key_decrypts_after_rotation() {
        // Checkpoint written under the OLD root; the process has since rotated
        // so `current` is the NEW root and OLD is staged as previous.
        let old = root(0x0A);
        let new = root(0x0B);
        let snapshot = serde_json::json!({"node": 2, "state": "mid"});
        let (ct, nonce) = encrypt_checkpoint(&snapshot, &old, b"exec-b").unwrap();

        // Current key alone fails (this is the pre-ring "stranded" case)...
        assert!(decrypt_checkpoint(&ct, &nonce, &new, b"exec-b").is_err());
        // ...but the ring recovers it via the staged previous key.
        let got = decrypt_checkpoint_ring(&ct, &nonce, &new, &[old], b"exec-b").unwrap();
        assert_eq!(got, snapshot);
    }

    #[test]
    fn all_keys_failing_returns_current_key_error() {
        let cur = root(0x01);
        let snapshot = serde_json::json!({"node": 3});
        let (ct, nonce) = encrypt_checkpoint(&snapshot, &root(0xFF), b"exec-c").unwrap();
        // Neither current nor the staged previous can decrypt a blob written
        // under a third, unknown key.
        let err = decrypt_checkpoint_ring(&ct, &nonce, &cur, &[root(0x02)], b"exec-c").unwrap_err();
        assert!(err.contains("wrong key or corrupted data"), "got {err}");
    }

    #[test]
    fn wrong_aad_is_not_rescued_by_the_ring() {
        // AAD binding still holds across the ring — a checkpoint for exec-d
        // can't be transposed onto exec-e under any key.
        let cur = root(0x01);
        let snapshot = serde_json::json!({"node": 4});
        let (ct, nonce) = encrypt_checkpoint(&snapshot, &cur, b"exec-d").unwrap();
        let err = decrypt_checkpoint_ring(&ct, &nonce, &cur, &[root(0x02)], b"exec-e").unwrap_err();
        assert!(err.contains("wrong key or corrupted data"), "got {err}");
    }
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
        let err = encrypt_checkpoint(&v, &k(31), b"exec").unwrap_err();
        assert!(err.contains("exactly 32 bytes"), "got {err}");
    }

    #[test]
    fn encrypt_rejects_long_key() {
        // M-11: previously accepted; silently truncated to first 32 bytes.
        let v = serde_json::json!({});
        let err = encrypt_checkpoint(&v, &k(33), b"exec").unwrap_err();
        assert!(err.contains("exactly 32 bytes"), "got {err}");
    }

    #[test]
    fn encrypt_accepts_exact_key() {
        let v = serde_json::json!({"x": 1});
        assert!(encrypt_checkpoint(&v, &k(32), b"exec").is_ok());
    }

    #[test]
    fn decrypt_rejects_long_key() {
        let err = decrypt_checkpoint(&[], &[0u8; NONCE_LEN], &k(64), b"exec").unwrap_err();
        assert!(err.contains("exactly 32 bytes"), "got {err}");
    }

    #[test]
    fn decrypt_rejects_wrong_nonce_length() {
        let err = decrypt_checkpoint(&[], &[0u8; 11], &k(32), b"exec").unwrap_err();
        assert!(err.contains("Nonce must be exactly"), "got {err}");
    }
}

#[cfg(test)]
mod checkpoint_aead_tests {
    use super::*;

    fn k(n: usize) -> Vec<u8> {
        vec![0x42u8; n]
    }

    #[test]
    fn round_trip_with_matching_execution_id_succeeds() {
        let key = k(AES_KEY_LEN);
        let exec = Uuid::new_v4();
        let snapshot = serde_json::json!({"node": "a", "value": 42});

        let (ct, nonce) = encrypt_checkpoint(&snapshot, &key, exec.as_bytes()).unwrap();
        let decrypted = decrypt_checkpoint(&ct, &nonce, &key, exec.as_bytes()).unwrap();

        assert_eq!(decrypted, snapshot);
    }

    #[test]
    fn decrypt_with_different_execution_id_fails_aad_mismatch() {
        let key = k(AES_KEY_LEN);
        let exec = Uuid::new_v4();
        let other = Uuid::new_v4();
        assert_ne!(exec, other);
        let snapshot = serde_json::json!({"node": "a"});

        let (ct, nonce) = encrypt_checkpoint(&snapshot, &key, exec.as_bytes()).unwrap();
        // Transposing the blob to a different execution_id must fail closed.
        let err = decrypt_checkpoint(&ct, &nonce, &key, other.as_bytes()).unwrap_err();
        assert!(
            err.contains("wrong key or corrupted data"),
            "expected fail-closed AAD mismatch, got {err}"
        );
    }

    #[test]
    fn derived_subkey_differs_from_raw_input_key() {
        // The AEAD key must be the HKDF subkey, never the raw root (which
        // is also the HMAC signing key for rpc_auth / JobRequest / JobResult).
        let root = k(AES_KEY_LEN);
        let exec = Uuid::new_v4();
        let subkey = derive_checkpoint_aead_key(&root, exec.as_bytes());
        assert_ne!(
            &subkey[..],
            &root[..],
            "derived checkpoint AEAD subkey must differ from the raw root key"
        );
        // Deterministic across calls for the same (root, execution).
        assert_eq!(subkey, derive_checkpoint_aead_key(&root, exec.as_bytes()));
    }

    #[test]
    fn distinct_executions_derive_distinct_subkeys() {
        // Finding #1: per-execution partition — each execution_id yields a
        // different checkpoint key, bounding the random-nonce budget to one
        // execution's writes.
        let root = k(AES_KEY_LEN);
        let a = derive_checkpoint_aead_key(&root, Uuid::new_v4().as_bytes());
        let b = derive_checkpoint_aead_key(&root, Uuid::new_v4().as_bytes());
        assert_ne!(&*a, &*b, "different executions must derive different keys");
        // And the v2 per-execution key must differ from the legacy static one.
        let legacy = derive_checkpoint_aead_key_legacy_v1(&root);
        assert_ne!(
            &*a, &*legacy,
            "v2 per-execution key must differ from the v1 static key"
        );
    }

    #[test]
    fn legacy_v1_ciphertext_still_decrypts_during_migration() {
        // A checkpoint written under the old static-key scheme (v1) must
        // still resume after the v2 rollout, via the decrypt fallback.
        let root = k(AES_KEY_LEN);
        let exec = Uuid::new_v4();
        let snapshot = serde_json::json!({"node": "legacy", "value": 7});

        // Hand-roll a v1 ciphertext: static legacy key + execution_id AAD.
        let v1_key = derive_checkpoint_aead_key_legacy_v1(&root);
        let cipher = Aes256Gcm::new_from_slice(v1_key.as_slice()).unwrap();
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let pt = serde_json::to_vec(&snapshot).unwrap();
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: pt.as_ref(),
                    aad: exec.as_bytes(),
                },
            )
            .unwrap();

        // The v2-first decrypt path must fall back to v1 and succeed.
        let decrypted = decrypt_checkpoint(&ct, &nonce_bytes, &root, exec.as_bytes()).unwrap();
        assert_eq!(decrypted, snapshot);
    }
}
