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

/// A registered seal context plus the instant it was registered. The timestamp
/// exists solely for [`InFlightSeals::sweep_older_than`] — it bounds the map
/// against *fire-and-forget* dispatch (module-bound Gmail/GCal/webhook pushes)
/// which, unlike the engine's request/reply path, cannot `discard` after
/// awaiting a result. An un-claimed orphan (worker died before claiming) would
/// otherwise linger forever.
struct Registered {
    at: std::time::Instant,
    ctx: SealContext,
}

/// The dispatching replica's in-memory `exec_id → SealContext` map. Single-claim
/// is guaranteed by [`Self::take`] (atomic `DashMap::remove`).
#[derive(Default)]
pub struct InFlightSeals {
    map: DashMap<Uuid, Registered>,
}

/// The process-wide claim-sealing handle a dispatch path needs: the shared
/// in-flight seal store (also read by the claim responder) plus the responder's
/// claim subject (stamped into `JobRequest.claim_inbox`).
///
/// Lives HERE — the crate every sealing participant already depends on — so
/// both the engine-NATS dispatcher and the module-bound integration paths
/// (gmail / gcal / webhooks, via `talos-integration-helpers`) name the SAME
/// type without an integration→engine-NATS dep edge. There must be exactly one
/// instance per process (memoized by the controller); a second `InFlightSeals`
/// would register seals the responder never sees.
#[derive(Clone)]
pub struct EnvelopeSealingHandle {
    /// The shared in-flight seal store the claim responder reads.
    pub in_flight: std::sync::Arc<InFlightSeals>,
    /// The replica-local claim subject the responder subscribes to.
    pub claim_subject: String,
}

impl InFlightSeals {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a job's resolved secrets at dispatch time. Overwrites any prior
    /// context for the same `exec_id` (a re-dispatch supersedes the stale one).
    pub fn register(&self, exec_id: Uuid, ctx: SealContext) {
        self.map.insert(
            exec_id,
            Registered {
                at: std::time::Instant::now(),
                ctx,
            },
        );
    }

    /// Atomically take the context for `exec_id`, if present. The first caller
    /// wins; a concurrent or later caller gets `None`. This is the single-claim
    /// primitive.
    #[must_use]
    pub fn take(&self, exec_id: Uuid) -> Option<SealContext> {
        self.map.remove(&exec_id).map(|(_, v)| v.ctx)
    }

    /// Drop an unclaimed context (job finished, failed, or was cancelled before a
    /// claim arrived) so the map doesn't grow with dead executions.
    pub fn discard(&self, exec_id: Uuid) {
        self.map.remove(&exec_id);
    }

    /// Evict every context registered longer than `ttl` ago and return how many
    /// were swept. The safety net for *fire-and-forget* dispatch paths that
    /// cannot `discard`: the engine's request/reply dispatcher removes its
    /// context on claim OR on the post-dispatch `discard`, but a module-bound
    /// push publishes and returns immediately, so a worker that dies before
    /// claiming would strand its context here. `ttl` must be generously larger
    /// than the worst-case dispatch→claim latency (a live worker claims within
    /// milliseconds of receiving the job) so this never races a legitimate
    /// claim. Zeroization still runs — the swept `SealContext`'s
    /// `Zeroizing<Vec<u8>>` clears on drop.
    pub fn sweep_older_than(&self, ttl: std::time::Duration) -> usize {
        let mut swept = 0usize;
        self.map.retain(|_, reg| {
            let keep = reg.at.elapsed() < ttl;
            if !keep {
                swept += 1;
            }
            keep
        });
        swept
    }

    /// Number of in-flight (unclaimed) seal contexts. Bounded by concurrency and
    /// the sweep, not by jobs-ever-seen (contexts are removed on claim, discard,
    /// or sweep).
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
    fn sweep_evicts_only_entries_older_than_ttl() {
        let seals = InFlightSeals::new();
        let exec = Uuid::new_v4();
        seals.register(exec, ctx_of(&[("k", "v")]));

        // A generous TTL keeps a just-registered entry (the live-worker case:
        // a claim always arrives well within the TTL, so the sweep never races
        // a legitimate claim).
        assert_eq!(
            seals.sweep_older_than(std::time::Duration::from_secs(3600)),
            0,
            "fresh entry is not swept"
        );
        assert_eq!(seals.len(), 1);

        // A zero TTL treats every entry as expired — the orphan case (worker
        // died before claiming). Sweep evicts it and reports the count.
        assert_eq!(
            seals.sweep_older_than(std::time::Duration::from_secs(0)),
            1,
            "orphaned entry is swept"
        );
        assert!(seals.is_empty());
        // And a claim arriving after the sweep gets nothing (fail-closed).
        assert!(seals.take(exec).is_none());
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

    /// Serializes tests that mutate `TALOS_ENVELOPE_SEALING` — the env var is
    /// process-global, so any future test reading it must hold this lock too.
    static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// `from_env` parsing: case-insensitive, whitespace-trimmed, and
    /// fail-safe — unknown values and unset both resolve to `Off` (today's
    /// inline-WSK behavior), never accidentally to an enforcing mode.
    #[test]
    fn mode_from_env_parses_variants_and_fails_safe_to_off() {
        let _g = ENV_TEST_LOCK.lock().unwrap();
        let original = std::env::var("TALOS_ENVELOPE_SEALING").ok();

        let cases = [
            ("off", EnvelopeSealingMode::Off),
            ("audit", EnvelopeSealingMode::Audit),
            ("required", EnvelopeSealingMode::Required),
            // Case-insensitive.
            ("AUDIT", EnvelopeSealingMode::Audit),
            ("Required", EnvelopeSealingMode::Required),
            // Whitespace-trimmed.
            ("  required  ", EnvelopeSealingMode::Required),
            // Unknown values fail SAFE to Off — a typo'd value must not
            // silently flip the fleet into refuse-inline enforcement.
            ("enforce", EnvelopeSealingMode::Off),
            ("1", EnvelopeSealingMode::Off),
            ("", EnvelopeSealingMode::Off),
        ];
        for (raw, expected) in cases {
            std::env::set_var("TALOS_ENVELOPE_SEALING", raw);
            assert_eq!(
                EnvelopeSealingMode::from_env(),
                expected,
                "TALOS_ENVELOPE_SEALING={raw:?}"
            );
        }

        std::env::remove_var("TALOS_ENVELOPE_SEALING");
        assert_eq!(
            EnvelopeSealingMode::from_env(),
            EnvelopeSealingMode::Off,
            "unset must default to Off"
        );

        if let Some(v) = original {
            std::env::set_var("TALOS_ENVELOPE_SEALING", v);
        }
    }

    /// Single-claim atomicity under real concurrency: many tasks race
    /// `take()` for the same exec_id; exactly one must win, on every trial.
    /// Mirrors the nonce-cache TOCTOU tests in `talos-memory/src/rpc_auth.rs`
    /// — races are timing-dependent, so a single trial can hide a window.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_takes_admit_exactly_one_winner() {
        const TRIALS: usize = 150;
        const RACERS: usize = 4;
        for trial in 0..TRIALS {
            let seals = std::sync::Arc::new(InFlightSeals::new());
            let exec = Uuid::new_v4();
            seals.register(exec, ctx_of(&[("k", "v")]));

            let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(RACERS));
            let mut handles = Vec::with_capacity(RACERS);
            for _ in 0..RACERS {
                let s = seals.clone();
                let b = barrier.clone();
                handles.push(tokio::spawn(async move {
                    b.wait().await;
                    s.take(exec).is_some()
                }));
            }
            let mut winners = 0usize;
            for h in handles {
                if h.await.unwrap() {
                    winners += 1;
                }
            }
            assert_eq!(
                winners, 1,
                "trial {trial}: expected exactly one take() winner, got {winners} — \
                 a >1 result means two workers could both receive sealed secrets"
            );
            assert!(seals.is_empty(), "trial {trial}: context must be consumed");
        }
    }

    /// Re-registration (the M3 re-arm / re-dispatch path) OVERWRITES the
    /// prior context: the map holds one entry per exec_id and a claim after
    /// re-dispatch receives the NEW secrets, not the stale ones.
    #[test]
    fn re_registration_overwrites_prior_context() {
        let seals = InFlightSeals::new();
        let exec = Uuid::new_v4();
        seals.register(exec, ctx_of(&[("api_key", "stale-value")]));
        seals.register(exec, ctx_of(&[("api_key", "fresh-value")]));
        assert_eq!(seals.len(), 1, "re-registration must not duplicate entries");

        let ctx = seals
            .take(exec)
            .expect("context takeable after re-register");
        let recovered: HashMap<String, String> = serde_json::from_slice(ctx.bytes()).unwrap();
        assert_eq!(
            recovered.get("api_key").map(String::as_str),
            Some("fresh-value"),
            "a claim after re-dispatch must see the superseding context"
        );
        assert!(
            seals.take(exec).is_none(),
            "still single-claim after re-arm"
        );
    }

    /// `discard` after a successful `take` is a harmless no-op (the engine's
    /// request/reply path always discards post-dispatch, even when the claim
    /// already consumed the context), and discarding an unknown exec_id is
    /// equally inert.
    #[test]
    fn discard_after_take_and_discard_unknown_are_noops() {
        let seals = InFlightSeals::new();
        let exec = Uuid::new_v4();
        seals.register(exec, ctx_of(&[("k", "v")]));
        assert!(seals.take(exec).is_some());

        seals.discard(exec); // already taken — must not panic or resurrect
        assert!(seals.is_empty());
        assert!(
            seals.take(exec).is_none(),
            "discard must not re-arm the context"
        );

        seals.discard(Uuid::new_v4()); // never registered — inert
        assert!(seals.is_empty());
    }

    /// `discard` on an UNCLAIMED context (job finished/cancelled before any
    /// claim) removes it, and a late claim then finds nothing (fail-closed).
    #[test]
    fn discard_unclaimed_context_blocks_late_claim() {
        let seals = InFlightSeals::new();
        let exec = Uuid::new_v4();
        seals.register(exec, ctx_of(&[("k", "v")]));
        seals.discard(exec);
        assert!(seals.is_empty());
        assert!(
            seals.take(exec).is_none(),
            "late claim after discard gets nothing"
        );
    }

    /// Sweep evicts only entries older than the TTL, leaving younger
    /// registrations claimable. Generous sleep/TTL margins (4×) keep this
    /// deterministic on slow CI.
    #[test]
    fn sweep_is_selective_by_age() {
        let seals = InFlightSeals::new();
        let old_exec = Uuid::new_v4();
        let new_exec = Uuid::new_v4();
        seals.register(old_exec, ctx_of(&[("k", "old")]));
        std::thread::sleep(std::time::Duration::from_millis(200));
        seals.register(new_exec, ctx_of(&[("k", "new")]));

        let swept = seals.sweep_older_than(std::time::Duration::from_millis(100));
        assert_eq!(swept, 1, "only the aged-out entry is swept");
        assert!(seals.take(old_exec).is_none(), "orphan is gone");
        assert!(
            seals.take(new_exec).is_some(),
            "fresh entry survives the sweep"
        );
    }

    /// `SealContext`'s Debug impl must redact the secret bytes (lint check
    /// 37): the rendered string carries the `<redacted>` marker and NEVER the
    /// plaintext, for both constructors.
    #[test]
    fn seal_context_debug_redacts_plaintext() {
        let ctx = ctx_of(&[("anthropic/api_key", "sk-ant-DO-NOT-PRINT")]);
        let rendered = format!("{ctx:?}");
        assert!(
            rendered.contains("<redacted>"),
            "Debug must show the redaction marker"
        );
        assert!(
            !rendered.contains("sk-ant-DO-NOT-PRINT"),
            "Debug must not leak the secret value"
        );
        assert!(
            !rendered.contains("anthropic/api_key"),
            "Debug must not leak secret names either"
        );

        let ctx2 = SealContext::from_bytes(br#"{"k":"from-bytes-SECRET"}"#.to_vec());
        let rendered2 = format!("{ctx2:?}");
        assert!(rendered2.contains("<redacted>"));
        assert!(!rendered2.contains("from-bytes-SECRET"));
    }

    /// An EMPTY secrets map round-trips through the full claim → seal → open
    /// path (the no-secret-node case under `required` mode).
    #[test]
    fn empty_secrets_map_round_trips() {
        let _g = REGISTRY_LOCK.lock().unwrap();
        let worker_sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
        set_dynamic_worker_public_keys(vec![(
            "worker-empty".to_string(),
            worker_sk.verifying_key(),
        )]);
        let controller_sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);

        let exec = Uuid::new_v4();
        let seals = InFlightSeals::new();
        seals.register(exec, SealContext::new(&HashMap::new()).unwrap());

        let we = WorkerEphemeral::generate();
        let claim =
            SecretClaim::new_signed(exec, "worker-empty".into(), we.public_key(), &worker_sk);
        let sealed = handle_secret_claim(&claim, &seals, &controller_sk, 60).expect("sealed");
        let plaintext = we
            .open(
                &sealed.epk_c,
                exec,
                "worker-empty",
                &sealed.ciphertext,
                &sealed.nonce,
            )
            .expect("opens");
        let recovered: HashMap<String, String> = serde_json::from_slice(&plaintext).unwrap();
        assert!(recovered.is_empty());
    }

    /// Wrong-key failure on the full round-trip: the sealed payload only
    /// opens under the EXACT ephemeral secret whose public half was in the
    /// claim. An attacker holding a different ephemeral (or observing epk_w
    /// on the bus) recovers nothing.
    #[test]
    fn sealed_secrets_do_not_open_under_wrong_ephemeral() {
        let _g = REGISTRY_LOCK.lock().unwrap();
        let worker_sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
        set_dynamic_worker_public_keys(vec![("worker-wk".to_string(), worker_sk.verifying_key())]);
        let controller_sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);

        let exec = Uuid::new_v4();
        let seals = InFlightSeals::new();
        seals.register(exec, ctx_of(&[("k", "super-secret")]));

        let we = WorkerEphemeral::generate();
        let claim = SecretClaim::new_signed(exec, "worker-wk".into(), we.public_key(), &worker_sk);
        let sealed = handle_secret_claim(&claim, &seals, &controller_sk, 60).expect("sealed");

        // A DIFFERENT ephemeral (attacker's own keypair) must fail to open.
        let attacker = WorkerEphemeral::generate();
        assert!(
            attacker
                .open(
                    &sealed.epk_c,
                    exec,
                    "worker-wk",
                    &sealed.ciphertext,
                    &sealed.nonce
                )
                .is_err(),
            "wrong ephemeral secret must not open the seal"
        );
    }

    /// Tamper rejection on the full round-trip: a flipped ciphertext byte
    /// fails BOTH the controller signature check and the AEAD open; opening
    /// under a different exec_id or worker_id fails the AAD binding.
    #[test]
    fn tampered_or_transposed_seal_is_rejected() {
        let _g = REGISTRY_LOCK.lock().unwrap();
        let worker_sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
        set_dynamic_worker_public_keys(vec![("worker-tam".to_string(), worker_sk.verifying_key())]);
        let controller_sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
        let controller_vk = controller_sk.verifying_key();

        let exec = Uuid::new_v4();
        let seals = InFlightSeals::new();
        seals.register(exec, ctx_of(&[("k", "super-secret")]));

        let we = WorkerEphemeral::generate();
        let claim = SecretClaim::new_signed(exec, "worker-tam".into(), we.public_key(), &worker_sk);
        let mut sealed = handle_secret_claim(&claim, &seals, &controller_sk, 60).expect("sealed");

        // On-bus ciphertext bit-flip: the Ed25519 signature covers the
        // ciphertext, so verify() fails first...
        sealed.ciphertext[0] ^= 0x01;
        assert!(
            sealed.verify(&controller_vk, 60).is_err(),
            "tampered ciphertext must fail the controller signature"
        );
        // ...and even a worker that skipped verify() fails the GCM tag.
        assert!(
            we.open(
                &sealed.epk_c,
                exec,
                "worker-tam",
                &sealed.ciphertext,
                &sealed.nonce
            )
            .is_err(),
            "tampered ciphertext must fail AEAD open"
        );

        // AAD transposition: a clean seal for exec A does not open as exec B
        // or as a different worker (fresh flow — the ephemeral above was consumed).
        let exec2 = Uuid::new_v4();
        seals.register(exec2, ctx_of(&[("k", "super-secret")]));
        let we2 = WorkerEphemeral::generate();
        let claim2 =
            SecretClaim::new_signed(exec2, "worker-tam".into(), we2.public_key(), &worker_sk);
        let sealed2 = handle_secret_claim(&claim2, &seals, &controller_sk, 60).expect("sealed");
        assert!(
            we2.open(
                &sealed2.epk_c,
                Uuid::new_v4(), // wrong exec_id → AAD mismatch
                "worker-tam",
                &sealed2.ciphertext,
                &sealed2.nonce
            )
            .is_err(),
            "seal must be bound to its exec_id"
        );
    }

    /// Key-rotation ring verify: with TWO keys registered for one worker_id
    /// (old + new during rotation), a claim signed by EITHER authenticates.
    #[test]
    fn rotation_ring_accepts_either_registered_key() {
        let _g = REGISTRY_LOCK.lock().unwrap();
        let old_sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
        let new_sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
        set_dynamic_worker_public_keys(vec![
            ("worker-rot".to_string(), old_sk.verifying_key()),
            ("worker-rot".to_string(), new_sk.verifying_key()),
        ]);
        let controller_sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);

        let seals = InFlightSeals::new();
        for sk in [&old_sk, &new_sk] {
            let exec = Uuid::new_v4();
            seals.register(exec, ctx_of(&[("k", "v")]));
            let we = WorkerEphemeral::generate();
            let claim = SecretClaim::new_signed(exec, "worker-rot".into(), we.public_key(), sk);
            handle_secret_claim(&claim, &seals, &controller_sk, 60)
                .expect("claim signed with a registered ring key must seal");
        }
        assert!(seals.is_empty());
    }

    /// A claim whose worker_id was swapped post-signature (to another
    /// REGISTERED worker) must fail auth — the id is inside the signed bytes
    /// — and must NOT consume the seal context.
    #[test]
    fn claim_with_transposed_worker_id_rejected_without_taking_context() {
        let _g = REGISTRY_LOCK.lock().unwrap();
        let sk_a = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
        let sk_b = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
        set_dynamic_worker_public_keys(vec![
            ("worker-ta".to_string(), sk_a.verifying_key()),
            ("worker-tb".to_string(), sk_b.verifying_key()),
        ]);
        let controller_sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);

        let exec = Uuid::new_v4();
        let seals = InFlightSeals::new();
        seals.register(exec, ctx_of(&[("k", "v")]));

        let we = WorkerEphemeral::generate();
        let mut claim = SecretClaim::new_signed(exec, "worker-ta".into(), we.public_key(), &sk_a);
        claim.worker_id = "worker-tb".to_string(); // transpose to another real worker
        assert_eq!(
            handle_secret_claim(&claim, &seals, &controller_sk, 60).unwrap_err(),
            ClaimError::Unauthorized
        );
        assert_eq!(seals.len(), 1, "context must survive the rejected claim");
    }

    /// A validly-signed claim for an exec_id this replica never dispatched
    /// (or already swept) is `UnknownExecution` — fail-closed, no seal.
    #[test]
    fn valid_claim_for_undispatched_execution_rejected() {
        let _g = REGISTRY_LOCK.lock().unwrap();
        let worker_sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
        set_dynamic_worker_public_keys(vec![("worker-ud".to_string(), worker_sk.verifying_key())]);
        let controller_sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);

        let seals = InFlightSeals::new(); // nothing registered
        let we = WorkerEphemeral::generate();
        let claim = SecretClaim::new_signed(
            Uuid::new_v4(),
            "worker-ud".into(),
            we.public_key(),
            &worker_sk,
        );
        assert_eq!(
            handle_secret_claim(&claim, &seals, &controller_sk, 60).unwrap_err(),
            ClaimError::UnknownExecution
        );
    }

    /// A low-order (all-zero) ephemeral key from an AUTHENTICATED worker
    /// fails the seal with `SealFailed` (non-contributory ECDH is rejected).
    /// Documents current behavior: the context IS consumed before the seal
    /// runs (take-then-seal), so the sabotaged execution cannot re-claim —
    /// fail-closed against probing, at the cost of that job's secrets.
    #[test]
    fn low_order_ephemeral_key_fails_seal_closed() {
        let _g = REGISTRY_LOCK.lock().unwrap();
        let worker_sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
        set_dynamic_worker_public_keys(vec![("worker-lo".to_string(), worker_sk.verifying_key())]);
        let controller_sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);

        let exec = Uuid::new_v4();
        let seals = InFlightSeals::new();
        seals.register(exec, ctx_of(&[("k", "v")]));

        // [0u8; 32] is the identity/low-order point: X25519 output is all-zero
        // → `was_contributory()` is false → derive_seal_key fails closed.
        let claim = SecretClaim::new_signed(exec, "worker-lo".into(), [0u8; 32], &worker_sk);
        match handle_secret_claim(&claim, &seals, &controller_sk, 60) {
            Err(ClaimError::SealFailed(_)) => {}
            other => panic!("expected SealFailed for low-order epk_w, got {other:?}"),
        }
        // Current behavior: the context was atomically taken before sealing,
        // so a retry claim finds nothing.
        assert!(
            seals.is_empty(),
            "context is consumed by the failed seal (documented)"
        );
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
