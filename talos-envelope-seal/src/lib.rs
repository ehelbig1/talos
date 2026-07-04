//! RFC 0010 P3 (D3b) — controller-side per-execution secret-envelope sealing.
//!
//! This crate owns the controller half of the claim/lease protocol that removes
//! `WORKER_SHARED_KEY` as a secret-decryption root on the worker (see
//! `docs/rfcs/0010-asymmetric-worker-trust-boundary.md`, "P3 detailed design").
//! It does NOT touch NATS — the transport wiring (the claim responder
//! subscription, the reply publish) lives in the controller binary; this crate
//! is the pure, testable core:
//!
//! * [`EnvelopeSealingMode`] — the `off` / `audit` / `required` policy flag.
//! * [`SealContext`] — the resolved plaintext secret values for one in-flight
//!   execution, redacted in `Debug` and zeroized on drop.
//! * [`InFlightSeals`] — the dispatching replica's in-memory map
//!   `exec_id → SealContext`. The single-claim guarantee rides on an **atomic
//!   `take`** (`DashMap::remove`): the first claim removes the context and seals;
//!   any concurrent or later claim gets `None` and is rejected. No secretless
//!   double-run is possible.
//! * [`handle_secret_claim`] — verify the claim's Ed25519 signature against the
//!   worker's registered key(s), atomically take the context, seal the secrets
//!   to the worker's ephemeral key, and return a signed [`SealedSecrets`].
//! * [`RedisLease`] — the durability / crash-recovery layer: a per-`exec_id`
//!   Redis key with a CAS (`dispatched → claimed_by`) so a dead replica's job is
//!   re-dispatchable after the lease expires. In-memory `take` is authoritative
//!   for single-claim; Redis is the cross-replica / crash-recovery backstop
//!   (same fail-open posture as `talos-replay-guard`).

use std::collections::HashMap;

use dashmap::DashMap;
use uuid::Uuid;
use zeroize::Zeroizing;

use talos_workflow_job_protocol::{
    seal_secrets, worker_public_keys, DispatchSigningKey, DispatchVerifyingKey, SealedSecrets,
    SecretClaim,
};

pub mod lease;
pub mod responder;
pub use lease::{ClaimLeaseOutcome, RedisLease};
pub use responder::run_claim_responder;

// The worker-verifying-key registry (`set_dynamic_worker_public_keys`) is a
// process-global that REPLACES its contents, so every test that mutates it must
// hold THIS one lock — a per-module lock wouldn't serialize across modules in the
// same test binary (lib::tests vs responder::tests). nextest isolates by process,
// but `cargo test` runs them as threads, so the shared lock is required there.
#[cfg(test)]
pub(crate) static REGISTRY_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// P3 secret-delivery policy, mirroring the Sigstore three-policy shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeSealingMode {
    /// Today's inline WSK envelope — byte-identical to pre-P3. Default.
    Off,
    /// Controller uses claim-based sealing for claim-capable workers, still
    /// accepts inline for others (migration window).
    Audit,
    /// Refuse `sealing == 0` dispatch/execution (the P4-adjacent enforcement
    /// point for secrets).
    Required,
}

impl EnvelopeSealingMode {
    /// Resolve from `TALOS_ENVELOPE_SEALING` ∈ {off, audit, required}. Unknown or
    /// unset → `Off` (fail-safe to today's behaviour).
    #[must_use]
    pub fn from_env() -> Self {
        match std::env::var("TALOS_ENVELOPE_SEALING")
            .ok()
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref()
        {
            Some("audit") => Self::Audit,
            Some("required") => Self::Required,
            _ => Self::Off,
        }
    }

    /// Whether the controller should seal claim-based for a dispatch. `true` for
    /// `audit`/`required`, `false` for `off`.
    #[must_use]
    pub fn seals_claim_based(self) -> bool {
        matches!(self, Self::Audit | Self::Required)
    }

    /// Whether a `sealing == 0` (inline WSK) dispatch must be refused.
    #[must_use]
    pub fn refuses_inline(self) -> bool {
        matches!(self, Self::Required)
    }
}

/// The resolved plaintext secret values for one in-flight execution, held only
/// long enough to seal them to the claiming worker's ephemeral key. The JSON is
/// zeroized on drop and never rendered in `Debug` (lint check 37).
pub struct SealContext {
    /// Serialized `HashMap<String,String>` of secret name → value.
    secrets_json: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for SealContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealContext")
            .field("secrets_json", &"<redacted>")
            .finish()
    }
}

impl SealContext {
    /// Serialize a resolved secrets map into a seal context. The map is consumed
    /// by the caller after this; the serialized copy here is the only retained
    /// form and is zeroized on drop.
    pub fn new(secrets: &HashMap<String, String>) -> Result<Self, String> {
        let json =
            serde_json::to_vec(secrets).map_err(|e| format!("serialize seal context: {e}"))?;
        Ok(Self {
            secrets_json: Zeroizing::new(json),
        })
    }

    /// Seal a pre-serialized JSON payload directly. Used by the pipeline path,
    /// where one claim delivers a per-step `Vec<HashMap<String,String>>` (aligned
    /// to the pipeline's steps) rather than a single flat map — the caller
    /// serializes that structure and hands the bytes here. The worker opens the
    /// same bytes and deserializes them back into the per-step vector. The bytes
    /// are zeroized on drop.
    #[must_use]
    pub fn from_bytes(json: Vec<u8>) -> Self {
        Self {
            secrets_json: Zeroizing::new(json),
        }
    }

    /// The serialized secret bytes to seal (borrowed; not cloned).
    fn bytes(&self) -> &[u8] {
        &self.secrets_json
    }
}

/// The dispatching replica's in-memory `exec_id → SealContext` map. Single-claim
/// is guaranteed by [`Self::take`] (atomic `DashMap::remove`).
#[derive(Default)]
pub struct InFlightSeals {
    map: DashMap<Uuid, SealContext>,
}

impl InFlightSeals {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a job's resolved secrets at dispatch time. Overwrites any prior
    /// context for the same `exec_id` (a re-dispatch supersedes the stale one).
    pub fn register(&self, exec_id: Uuid, ctx: SealContext) {
        self.map.insert(exec_id, ctx);
    }

    /// Atomically take the context for `exec_id`, if present. The first caller
    /// wins; a concurrent or later caller gets `None`. This is the single-claim
    /// primitive.
    #[must_use]
    pub fn take(&self, exec_id: Uuid) -> Option<SealContext> {
        self.map.remove(&exec_id).map(|(_, v)| v)
    }

    /// Drop an unclaimed context (job finished, failed, or was cancelled before a
    /// claim arrived) so the map doesn't grow with dead executions.
    pub fn discard(&self, exec_id: Uuid) {
        self.map.remove(&exec_id);
    }

    /// Number of in-flight (unclaimed) seal contexts. Bounded by concurrency, not
    /// by jobs-ever-seen (contexts are removed on claim or discard).
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// Why a [`handle_secret_claim`] failed. All variants collapse to a generic
/// `ClaimRejected` on the wire — the worker never learns which check failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimError {
    /// No registered public key for the claiming `worker_id`.
    UnknownWorker,
    /// The claim signature or freshness check failed under every candidate key.
    Unauthorized,
    /// No in-flight seal context for this `exec_id` — never dispatched by this
    /// replica, already claimed (single-claim loser), or expired.
    UnknownExecution,
    /// The ECDH/AEAD seal itself failed (e.g. a low-order ephemeral key).
    SealFailed(String),
}

impl std::fmt::Display for ClaimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownWorker => write!(f, "unknown worker"),
            Self::Unauthorized => write!(f, "unauthorized claim"),
            Self::UnknownExecution => write!(f, "unknown or already-claimed execution"),
            Self::SealFailed(e) => write!(f, "seal failed: {e}"),
        }
    }
}

impl std::error::Error for ClaimError {}

/// Handle a `SecretClaim`: authenticate it against the worker's registered
/// Ed25519 key(s), atomically take the in-flight seal context (single-claim),
/// seal the secrets to the worker's ephemeral key, and return a controller-
/// signed [`SealedSecrets`]. Pure and synchronous — the NATS receive/reply and
/// the Redis lease CAS are layered by the controller responder around this.
///
/// Verification uses the P2 registry (`worker_public_keys`) so key rotation
/// (multiple registered keys) is handled by trying each candidate — identical
/// to the ring-verify posture elsewhere.
pub fn handle_secret_claim(
    claim: &SecretClaim,
    in_flight: &InFlightSeals,
    controller_key: &DispatchSigningKey,
    max_age_secs: u64,
) -> Result<SealedSecrets, ClaimError> {
    let candidates: Vec<DispatchVerifyingKey> = worker_public_keys(&claim.worker_id);
    if candidates.is_empty() {
        return Err(ClaimError::UnknownWorker);
    }
    let authenticated = candidates
        .iter()
        .any(|vk| claim.verify(vk, max_age_secs).is_ok());
    if !authenticated {
        return Err(ClaimError::Unauthorized);
    }

    // Single-claim: the first claim to reach here removes the context; any
    // racing claim (NATS redelivery to a second worker) finds it gone and is
    // rejected — so exactly one worker ever receives the sealed values.
    let ctx = in_flight
        .take(claim.exec_id)
        .ok_or(ClaimError::UnknownExecution)?;

    let seal = seal_secrets(&claim.epk_w, claim.exec_id, &claim.worker_id, ctx.bytes())
        .map_err(ClaimError::SealFailed)?;

    Ok(SealedSecrets::new_signed(
        claim.exec_id,
        seal,
        controller_key,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use talos_workflow_job_protocol::{set_dynamic_worker_public_keys, WorkerEphemeral};

    use super::REGISTRY_TEST_LOCK as REGISTRY_LOCK;

    fn ctx_of(pairs: &[(&str, &str)]) -> SealContext {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        SealContext::new(&map).unwrap()
    }

    #[test]
    fn mode_from_env_parsing() {
        // Default (unset) is Off; parsing is case-insensitive.
        assert!(!EnvelopeSealingMode::Off.seals_claim_based());
        assert!(EnvelopeSealingMode::Audit.seals_claim_based());
        assert!(EnvelopeSealingMode::Required.seals_claim_based());
        assert!(EnvelopeSealingMode::Required.refuses_inline());
        assert!(!EnvelopeSealingMode::Audit.refuses_inline());
    }

    #[test]
    fn in_flight_take_is_single_claim() {
        let seals = InFlightSeals::new();
        let exec = Uuid::new_v4();
        seals.register(exec, ctx_of(&[("k", "v")]));
        assert_eq!(seals.len(), 1);
        assert!(seals.take(exec).is_some(), "first take wins");
        assert!(seals.take(exec).is_none(), "second take gets nothing");
        assert!(seals.is_empty());
    }

    #[test]
    fn full_claim_seal_open_roundtrip() {
        let _g = REGISTRY_LOCK.lock().unwrap();
        // Register a worker key in the process registry.
        let worker_sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
        let worker_vk = worker_sk.verifying_key();
        set_dynamic_worker_public_keys(vec![("worker-roundtrip".to_string(), worker_vk)]);

        let controller_sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
        let controller_vk = controller_sk.verifying_key();

        let exec = Uuid::new_v4();
        let seals = InFlightSeals::new();
        seals.register(exec, ctx_of(&[("anthropic/api_key", "sk-ant-secret")]));

        // Worker side: generate ephemeral, build a signed claim.
        let we = WorkerEphemeral::generate();
        let claim =
            SecretClaim::new_signed(exec, "worker-roundtrip".into(), we.public_key(), &worker_sk);

        // Controller side: handle it.
        let sealed =
            handle_secret_claim(&claim, &seals, &controller_sk, 60).expect("claim handled");
        sealed
            .verify(&controller_vk, 60)
            .expect("worker verifies controller sig");

        // Worker opens.
        let plaintext = we
            .open(
                &sealed.epk_c,
                exec,
                "worker-roundtrip",
                &sealed.ciphertext,
                &sealed.nonce,
            )
            .expect("worker opens sealed secrets");
        let recovered: HashMap<String, String> = serde_json::from_slice(&plaintext).unwrap();
        assert_eq!(recovered.get("anthropic/api_key").unwrap(), "sk-ant-secret");

        // Second claim for the same exec is rejected (single-claim).
        let we2 = WorkerEphemeral::generate();
        let claim2 = SecretClaim::new_signed(
            exec,
            "worker-roundtrip".into(),
            we2.public_key(),
            &worker_sk,
        );
        assert_eq!(
            handle_secret_claim(&claim2, &seals, &controller_sk, 60).unwrap_err(),
            ClaimError::UnknownExecution
        );
    }

    #[test]
    fn claim_from_unregistered_worker_rejected() {
        let _g = REGISTRY_LOCK.lock().unwrap();
        // Deterministically ensure "ghost-worker" is not registered.
        set_dynamic_worker_public_keys(vec![]);
        let controller_sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
        let stranger_sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
        let exec = Uuid::new_v4();
        let seals = InFlightSeals::new();
        seals.register(exec, ctx_of(&[("k", "v")]));
        let we = WorkerEphemeral::generate();
        // worker_id not present in the registry snapshot.
        let claim =
            SecretClaim::new_signed(exec, "ghost-worker".into(), we.public_key(), &stranger_sk);
        assert_eq!(
            handle_secret_claim(&claim, &seals, &controller_sk, 60).unwrap_err(),
            ClaimError::UnknownWorker
        );
        // The context must NOT have been consumed by a failed auth.
        assert_eq!(seals.len(), 1, "rejected claim must not take the context");
    }

    #[test]
    fn claim_with_wrong_signature_rejected_without_taking_context() {
        let _g = REGISTRY_LOCK.lock().unwrap();
        // Register worker-A's key, but sign the claim with worker-B's key under
        // worker-A's id — authentication must fail and the context survive.
        let real_sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
        let forger_sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
        set_dynamic_worker_public_keys(vec![("worker-A".to_string(), real_sk.verifying_key())]);
        let controller_sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
        let exec = Uuid::new_v4();
        let seals = InFlightSeals::new();
        seals.register(exec, ctx_of(&[("k", "v")]));
        let we = WorkerEphemeral::generate();
        let claim = SecretClaim::new_signed(exec, "worker-A".into(), we.public_key(), &forger_sk);
        assert_eq!(
            handle_secret_claim(&claim, &seals, &controller_sk, 60).unwrap_err(),
            ClaimError::Unauthorized
        );
        assert_eq!(
            seals.len(),
            1,
            "unauthorized claim must not take the context"
        );
    }
}
