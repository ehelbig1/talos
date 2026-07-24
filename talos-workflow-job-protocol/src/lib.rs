//! Shared job protocol between Controller and Workers.
//!
//! Security model:
//! - Secrets are AES-256-GCM encrypted before transmission over NATS.
//! - Every JobRequest is HMAC-SHA256 signed using a pre-shared key
//!   (WORKER_SHARED_KEY) to prevent injection of malicious jobs.
//! - A `job_nonce` (timestamp + random hex) is included to prevent replay attacks.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use uuid::Uuid;

/// Canonical NATS subject registry — one authoritative name per `talos.*`
/// subject shared across process boundaries.
pub mod subjects;

/// RFC 0010 P3 (D3b) — per-execution ephemeral secret-envelope sealing.
pub mod envelope_seal;
pub use envelope_seal::{
    seal_secrets, ClaimResponse, SealOutput, SealedSecrets, SecretClaim, WorkerEphemeral,
};

type HmacSha256 = Hmac<Sha256>;

/// RFC 0010 P3 secret-delivery scheme carried by `JobRequest` /
/// `PipelineJobRequest`. `0` = legacy inline WSK envelope (today, default);
/// `1` = claim-based ECIES sealing (D3b). Security-relevant (an attacker must
/// not downgrade `1`→`0` to force a WSK envelope), so it is bound into the
/// dispatch signing payload — but ONLY when non-zero, so a scheme-`0` message's
/// signed bytes stay byte-identical to the pre-P3 wire format.
pub const SEALING_INLINE_WSK: u8 = 0;
/// See [`SEALING_INLINE_WSK`]. Claim-based ephemeral ECIES sealing.
pub const SEALING_CLAIM_ECIES: u8 = 1;

/// `skip_serializing_if` predicate: omit `sealing` from the wire JSON when it is
/// the legacy default, so a scheme-0 (inline-WSK) message serializes
/// byte-identically to the pre-P3 format. Signature is fixed by serde (`&T`).
#[allow(clippy::trivially_copy_pass_by_ref)]
fn sealing_is_default(v: &u8) -> bool {
    *v == SEALING_INLINE_WSK
}

/// HKDF-SHA256 `info` label for the secret-envelope AES-256-GCM subkey.
///
/// The 32-byte `WORKER_SHARED_KEY` is the *root*; the envelope cipher
/// uses a subkey expanded from it under this label, so the encryption
/// key is domain-separated from the HMAC signing key — historically the
/// two were the same raw bytes. Both the controller (seal) and the
/// worker (open) derive the identical subkey, so the round-trip is
/// consistent by construction. Bumping the `v1` suffix forces a clean
/// fleet-wide re-key (restart controller + workers together, same as
/// rotating `WORKER_SHARED_KEY` itself).
const ENVELOPE_AEAD_KEY_LABEL: &[u8] = b"talos/worker-shared-key/envelope-aead/v1";

/// v2 label (finding #1): the per-job envelope subkey folds the job's AAD
/// (the execution context bytes) into the HKDF `info`, so each job gets
/// its OWN AES key. The AES-GCM random-nonce birthday budget is then
/// per-job rather than shared across every envelope the fleet seals under
/// one `WORKER_SHARED_KEY`. Distinct label from v1 so the two subkeys
/// never collide.
const ENVELOPE_AEAD_KEY_LABEL_V2: &[u8] = b"talos/worker-shared-key/envelope-aead/v2-per-job";

/// v1 (legacy) envelope subkey: a single static subkey per root, shared by
/// every envelope. Used for the no-AAD wrappers (`encrypt`/`decrypt`) and
/// as the decrypt fallback for envelopes sealed before the v2 rollout.
fn derive_envelope_aead_key_v1(root: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, root);
    let mut subkey = [0u8; 32];
    hk.expand(ENVELOPE_AEAD_KEY_LABEL, &mut subkey)
        .expect("HKDF-SHA256 expand to 32 bytes is always a valid length");
    subkey
}

/// v2 per-job envelope subkey: `aad` (the job/execution context) is the
/// HKDF `info`, so the subkey is unique per job. Pure and deterministic;
/// controller (seal) and worker (open) derive it identically.
fn derive_envelope_aead_key_v2(root: &[u8], aad: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(ENVELOPE_AEAD_KEY_LABEL_V2), root);
    let mut subkey = [0u8; 32];
    hk.expand(aad, &mut subkey)
        .expect("HKDF-SHA256 expand to 32 bytes is always a valid length");
    subkey
}

/// Select the envelope AES key for an AAD context. A non-empty `aad` (the
/// production per-job path) uses the v2 per-job derivation; an empty `aad`
/// (the legacy no-AAD `encrypt`/`decrypt` wrappers) preserves the exact v1
/// static behavior so those byte-for-byte round-trips are unchanged.
fn envelope_seal_key(root: &[u8], aad: &[u8]) -> [u8; 32] {
    if aad.is_empty() {
        derive_envelope_aead_key_v1(root)
    } else {
        derive_envelope_aead_key_v2(root, aad)
    }
}

/// HKDF-SHA256 `info` label for the per-worker HMAC signing subkey (codebase
/// review 2026-07-03, item #1). Distinct from the envelope-AEAD labels so the
/// signing subkey is domain-separated from every encryption subkey derived from
/// the same `WORKER_SHARED_KEY` root.
const WORKER_SIGNING_KEY_LABEL: &[u8] = b"talos/worker-shared-key/per-worker-signing/v1";

/// Derive a **per-worker** HMAC signing subkey from the fleet root
/// (`WORKER_SHARED_KEY`) bound to a specific `worker_id`.
///
/// `key = HKDF-SHA256(ikm = root, salt = WORKER_SIGNING_KEY_LABEL, info = worker_id)`
///
/// # Status: building block only — NOT a standalone mitigation
///
/// This is a domain-separated per-identity KDF, kept as a foundation for a
/// future asymmetric worker-trust redesign. It is **inert** (no sign/verify path
/// calls it) and, on its own, does **not** reduce the blast radius of a worker
/// compromise.
///
/// Why not: under the current *symmetric*-HMAC architecture the worker must hold
/// the fleet root anyway — to verify the controller's `JobRequest` (with HMAC,
/// verify-capability == forge-capability) and to decrypt the per-job secret
/// envelope. A wasmtime sandbox escape therefore recovers the root regardless of
/// how `JobResult` is signed, and with the root the attacker can derive *any*
/// worker's key from this very function. Signing `JobResult` per-worker while the
/// root is still resident is security theater. The genuine fix removes
/// root-equivalent material from the worker, which requires asymmetric crypto
/// (Ed25519 for controller→worker verification; per-worker keypairs for
/// worker→controller; an ECIES/per-execution scheme for the secret envelope).
/// See `docs/reviews/security-hardening-followups-2026-07-03.md` (corrected
/// Finding #1) for the analysis and the RFC-scoped plan.
///
/// Pure and deterministic: worker (sign) and controller (verify) derive it
/// identically. `worker_id` should already be [`validate_worker_id`]-clean at
/// the call site; the derivation itself is defined for any byte string.
pub fn derive_worker_signing_key(root: &[u8], worker_id: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(WORKER_SIGNING_KEY_LABEL), root);
    let mut subkey = [0u8; 32];
    hk.expand(worker_id.as_bytes(), &mut subkey)
        .expect("HKDF-SHA256 expand to 32 bytes is always a valid length");
    subkey
}

/// Length-prefix a variable-width string segment for a canonical signing
/// payload: `"<byte-len>:<value>"`. Prefixing makes the boundary against the
/// next segment unambiguous, so two adjacent free-form fields can't be shifted
/// to forge an identical concatenation (the payload-collision class the
/// `JobRequest` / `PipelineJobRequest` signing payloads guard against). Shared
/// by both `signing_payload` impls so the discipline can't drift between them.
fn lp(s: &str) -> String {
    format!("{}:{}", s.len(), s)
}

/// Maximum future-skew tolerance for nonce timestamps (seconds).
///
/// Controller and worker sit on the same NATS cluster and should be
/// within a few seconds via NTP. A larger tolerance would extend the
/// effective replay window (a future-dated signature stays valid for
/// `FUTURE_SKEW + max_age_secs` total). A 5 s ≈ 5000 ms asymmetric
/// window is a common choice for signed-NATS RPC.
const MAX_FUTURE_SKEW_SECS: u64 = 5;

// ============================================================================
// Verifier role marker (L-4, 2026-05-22)
// ============================================================================
//
// Pre-r300/r301 the controller had two consumers of every JobResult —
// the primary inline dispatcher AND a background audit subscriber —
// and BOTH called `verify()`, which inserts the result nonce into the
// process-local `JOB_NONCE_CACHE`. The second verifier always lost
// the race with "result_nonce already seen", failing every workflow.
// The fix was twofold: (a) the worker single-publishes each result
// to one subject; (b) the split `verify` / `verify_no_replay` API.
//
// `verify` / `verify_no_replay` are still correct, but the choice
// between them is encoded only in the method name — a future caller
// can grep for one and copy-paste it into the wrong role. The
// `Verifier` enum forces the caller to declare intent at the type
// level, and `verify_as` dispatches on it. New code should prefer
// this API; the bare `verify` / `verify_no_replay` are kept for
// existing callers and tests.

/// L-4 marker that selects which verification flavour a caller wants.
///
/// Declaring intent at the type level prevents the regression class
/// behind the r300 incident: an audit subscriber accidentally calling
/// `verify()` instead of `verify_no_replay()` and racing the primary
/// verifier into "result_nonce already seen" errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verifier {
    /// **Primary** verifier: the single inline consumer that converts
    /// the signed result into a durable side effect (DB write, reply
    /// to a NATS request inbox, return to a webhook caller). Records
    /// the nonce in the process-local replay cache so the same
    /// signed result cannot be applied twice. There must be EXACTLY
    /// ONE primary verifier per result per controller process.
    Primary,
    /// **Observer** verifier: a passive consumer (audit subscriber,
    /// metrics emitter) whose only side effect is idempotent under
    /// replay. HMAC + freshness are checked; the nonce is NOT
    /// inserted into the replay cache. Use this whenever the same
    /// signed result might reach another consumer that already runs
    /// as the [`Primary`](Self::Primary).
    Observer,
}

// ============================================================================
// Replay-resistant nonce cache (single-use within freshness window)
// ============================================================================
//
// The freshness check on its own (now - ts <= max_age_secs) is necessary
// but not sufficient — within that window, an attacker who captures a
// signed JobRequest from NATS can replay it any number of times. The
// nonce cache turns that into a single-use guarantee: each (nonce, ts)
// pair is admitted exactly once; subsequent attempts return a "replay
// detected" error.
//
// Implementation: std-only (`Mutex<HashMap<String, u64>>`) keyed on the
// nonce string with the timestamp as value. On each insert we sweep
// entries older than `2 × max_age_secs` (some slack for clock skew),
// which keeps memory bounded at `rate × 2 × max_age_secs`. With
// max_age_secs = 300 and 100 verify/sec that's ~60k entries — small.
// A hard cap of 200k entries triggers a more aggressive sweep under
// abnormal load to keep the worker from OOMing.
//
// Workspace consistency: this mirrors the two-generation pattern in
// `talos-memory::rpc_auth` but uses a single Mutex<HashMap> rather than
// rotating DashMaps because (a) this crate is published to crates.io
// and we don't want to add `dashmap` + `arc-swap` as required deps,
// and (b) under realistic load (sub-millisecond Mutex contention) the
// simpler form is performant enough. Revisit if profiling shows the
// Mutex becoming a hot spot.

const NONCE_CACHE_HARD_CAP: usize = 200_000;

struct JobNonceCache {
    seen: std::sync::Mutex<HashMap<String, u64>>,
}

impl JobNonceCache {
    fn new() -> Self {
        Self {
            seen: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Returns `true` if the nonce is fresh (and atomically records it),
    /// `false` if it's a replay within the freshness window.
    fn check_and_record(&self, nonce: &str, ts: u64, max_age_secs: u64) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(ts);
        // Poison-tolerant: rebuild the lock state on poison rather than
        // hard-failing every subsequent call. A poisoned mutex here only
        // means a previous panic happened mid-update; the data itself is
        // a HashMap that's safe to keep using.
        let mut g = match self.seen.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        // Sweep entries older than 2× max_age_secs. The 2× slack absorbs
        // clock skew and avoids an admitting-then-rejecting race when
        // (now, ts) straddle the boundary.
        let cutoff = now.saturating_sub(max_age_secs.saturating_mul(2));
        if g.len() > 1024 {
            // Skip the sweep at small sizes — pure overhead. Above 1k
            // entries it's worth it.
            g.retain(|_, t| *t > cutoff);
        }
        if g.contains_key(nonce) {
            return false;
        }
        // Hard cap: if rate × 2× max_age_secs exceeds 200k entries,
        // we're under abnormal load (or a flood). Drop everything older
        // than the strict freshness window to free space.
        if g.len() >= NONCE_CACHE_HARD_CAP {
            let aggressive_cutoff = now.saturating_sub(max_age_secs);
            g.retain(|_, t| *t > aggressive_cutoff);
        }
        g.insert(nonce.to_string(), ts);
        true
    }
}

static JOB_NONCE_CACHE: std::sync::LazyLock<JobNonceCache> =
    std::sync::LazyLock::new(JobNonceCache::new);

/// Check whether `nonce` (with stamped timestamp `ts`) has been seen
/// within the freshness window. Returns `true` on first observation
/// (and atomically records it), `false` on replay. Used by every
/// `verify()` impl in this crate after HMAC verification succeeds.
fn check_and_record_job_nonce(nonce: &str, ts: u64, max_age_secs: u64) -> bool {
    JOB_NONCE_CACHE.check_and_record(nonce, ts, max_age_secs)
}

/// Current entry count of the process-local job-nonce replay cache.
///
/// Surfaced for `/health` / metrics endpoints so operators can correlate
/// "approaching `NONCE_CACHE_HARD_CAP`" (200k) with upstream traffic
/// rate. Sustained near-cap usage suggests either legitimate high
/// throughput (raise the cap) or a replay flood (gate at the NATS
/// subject level upstream).
///
/// Reading the cache size takes the same mutex as
/// `check_and_record_job_nonce`. The lock is held only long enough to
/// call `.len()`; the contention impact at typical query rates is
/// negligible (microseconds).
///
/// Returns `0` if the cache lock is currently poisoned (which only
/// happens if a previous panic occurred mid-mutation). The
/// `check_and_record` path itself is poison-tolerant so the cache
/// remains functional — this accessor errs on the side of "0" rather
/// than panic-on-read.
pub fn job_nonce_cache_size() -> usize {
    JOB_NONCE_CACHE.seen.lock().map(|g| g.len()).unwrap_or(0)
}

/// Maximum length of a `worker_id` in bytes. Pod names and host names
/// in practice fit well under 64 bytes (Kubernetes' RFC-1123 label cap
/// is 63 chars); 128 leaves slack for synthetic prefixes/suffixes.
pub const MAX_WORKER_ID_LEN: usize = 128;

/// Validate a self-reported worker identity before binding it into a
/// HMAC-signed result. The charset (`A-Z`, `a-z`, `0-9`, `.`, `-`, `_`)
/// is restricted so the colon-delimited signing-payload format stays
/// unambiguous — without this, a worker_id containing `:` could shift
/// the field boundary and let the same HMAC verify under a different
/// interpretation of the payload.
///
/// An empty `worker_id` is permitted (the back-compat `sign()` wrapper
/// passes the empty string) and renders as `""` in the signing payload.
/// Production worker code is expected to supply a non-empty value.
pub fn validate_worker_id(worker_id: &str) -> Result<(), String> {
    if worker_id.len() > MAX_WORKER_ID_LEN {
        return Err(format!(
            "worker_id too long: {} bytes (max {MAX_WORKER_ID_LEN})",
            worker_id.len()
        ));
    }
    if !worker_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return Err("worker_id contains invalid chars (allowed: A-Z a-z 0-9 . - _)".into());
    }
    Ok(())
}

#[cfg(test)]
mod worker_id_validation_tests {
    use super::validate_worker_id;

    #[test]
    fn accepts_empty() {
        validate_worker_id("").unwrap();
    }

    #[test]
    fn accepts_typical_pod_name() {
        validate_worker_id("talos-worker-abc-12345").unwrap();
    }

    #[test]
    fn accepts_uuid_style() {
        validate_worker_id("ab12cd34-ef56-7890-1234-567890abcdef").unwrap();
    }

    #[test]
    fn rejects_colon() {
        // The signing payload is colon-delimited; embedded `:` would
        // shift the field boundary.
        assert!(validate_worker_id("worker:1").is_err());
    }

    #[test]
    fn rejects_whitespace() {
        assert!(validate_worker_id("worker 1").is_err());
        assert!(validate_worker_id("worker\n1").is_err());
    }

    #[test]
    fn rejects_null_byte() {
        assert!(validate_worker_id("worker\0").is_err());
    }

    #[test]
    fn rejects_overlong() {
        let big = "a".repeat(super::MAX_WORKER_ID_LEN + 1);
        assert!(validate_worker_id(&big).is_err());
    }

    #[test]
    fn accepts_max_length() {
        let max = "a".repeat(super::MAX_WORKER_ID_LEN);
        validate_worker_id(&max).unwrap();
    }
}

// ============================================================================
// Shared sign/verify core — `SignedMessage`
// ============================================================================
//
// Every signed NATS message type in this crate (`JobRequest`, `JobResult`,
// `PipelineJobRequest`, `PipelineJobResult`, `WorkerHeartbeat`) shares the
// exact same HMAC / nonce-freshness / replay-cache / key-ring machinery.
// Historically each type carried its own hand-rolled copy of that logic
// (~5 near-identical families) — a drift surface for subtle security code
// (this crate carries the r300/r301 dual-verify incident history). The
// crate-private trait below holds the logic ONCE; each type supplies only
// its canonical `signing_payload()` bytes (untouched — wire-format-stable),
// its nonce/signature field accessors, and the nonce field's name for the
// byte-for-byte-stable error strings.
//
// The public API is unchanged: the inherent `sign` / `verify` /
// `verify_no_replay` / `*_with_ring` methods on each type are thin wrappers
// over these defaults, so worker/controller/engine callers need no changes
// and the verify() vs verify_no_replay() split (CLAUDE.md "Verify-once
// rule") is preserved exactly — `verify_core` is the ONLY path that inserts
// into `JOB_NONCE_CACHE`; `verify_no_replay_core` never touches it.

// ============================================================================
// RFC 0010 P1 — Ed25519 controller→worker dispatch signature scheme
// ============================================================================
//
// The `WORKER_SHARED_KEY` HMAC path (crypto scheme 0) is symmetric: a worker
// that can verify a `JobRequest` can also forge one. Because the worker runs
// untrusted WASM, a sandbox escape recovers the shared key and can mint
// dispatches for any actor/tenant. Ed25519 (scheme 1) breaks that symmetry: the
// controller signs with its private key and the worker holds only the *public*
// key, so a compromised worker can verify dispatches but cannot forge them.
//
// Rollout safety (see RFC 0010 P1):
// - `crypto_scheme` is an unsigned dispatch hint. It is NOT bound into the HMAC
//   payload, so the scheme-0 `signing_payload()` bytes stay byte-identical to
//   the pre-P1 wire format — no coordinated restart is needed for the HMAC path.
// - Downgrade is still prevented: the two schemes sign DIFFERENT bytes (Ed25519
//   signs `ed25519_signing_input`, which appends a domain tag), and the verifier
//   dispatches on `crypto_scheme`. Flipping the hint routes the message to the
//   wrong verify method, where the signature (which the attacker cannot forge
//   for the other scheme) fails. Turning HMAC acceptance off entirely (P4) is
//   the flag on the worker's dispatch call, not a payload change.

/// Signature scheme tag carried by `JobRequest` / `PipelineJobRequest`.
/// Scheme 0 = legacy `WORKER_SHARED_KEY` HMAC-SHA256; scheme 1 = Ed25519.
pub const CRYPTO_SCHEME_HMAC: u8 = 0;
/// See [`CRYPTO_SCHEME_HMAC`].
pub const CRYPTO_SCHEME_ED25519: u8 = 1;

/// Domain-separation suffix appended to the canonical payload before Ed25519
/// signing/verification. Keeps an Ed25519 dispatch signature from ever being
/// confused with an HMAC over "the same" message, and versions the scheme so a
/// future format can bump the tag for a clean re-key.
const ED25519_DISPATCH_DOMAIN_TAG: &[u8] = b":talos-dispatch-ed25519-v1";

/// Re-exported so the controller (sign) and worker (verify) name the dispatch
/// key types without pinning the `ed25519-dalek` version in their own manifests.
pub use ed25519_dalek::{SigningKey as DispatchSigningKey, VerifyingKey as DispatchVerifyingKey};

/// Parse a 32-byte Ed25519 **public** (verifying) key from lowercase/uppercase
/// hex. Used by the worker to load `TALOS_CONTROLLER_PUBLIC_KEY`. Fails closed on
/// wrong length or non-canonical encoding.
pub fn parse_ed25519_verifying_key_hex(hex_str: &str) -> Result<DispatchVerifyingKey, String> {
    let bytes = hex::decode(hex_str.trim())
        .map_err(|_| "controller public key: invalid hex".to_string())?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "controller public key: must be 32 bytes".to_string())?;
    DispatchVerifyingKey::from_bytes(&arr)
        .map_err(|_| "controller public key: not a valid Ed25519 point".to_string())
}

/// Parse a 32-byte Ed25519 **public** (verifying) key from raw bytes. Used by the
/// controller's RFC 0010 P2 inc.4 refresh task to turn a `worker_identities`
/// `bytea` column into a verifying key before merging it into the dynamic
/// overlay. Fails closed on a non-canonical point — a bad row is skipped rather
/// than poisoning the snapshot. Keeps callers off a direct `ed25519-dalek` dep.
pub fn parse_ed25519_verifying_key_bytes(bytes: &[u8; 32]) -> Result<DispatchVerifyingKey, String> {
    DispatchVerifyingKey::from_bytes(bytes)
        .map_err(|_| "worker public key: not a valid Ed25519 point".to_string())
}

/// Domain-separation prefix for the worker-registration proof-of-possession
/// message (RFC 0010 P2 inc.4). A version bump invalidates every older proof.
const WORKER_REGISTRATION_POP_DOMAIN: &[u8] = b"talos/worker-key-registration/v1";

/// Build the canonical proof-of-possession message a worker signs to prove it
/// holds the private key for `public_key` when self-registering over the network.
/// Length-prefixed, domain-separated, fixed-little-endian so two distinct field
/// tuples can never collide onto the same bytes. Pure and deterministic.
#[must_use]
pub fn worker_registration_pop_message(
    worker_id: &str,
    public_key: &[u8; 32],
    supports_sealing: bool,
    issued_at_ms: u64,
    nonce: &str,
) -> Vec<u8> {
    let wid = worker_id.as_bytes();
    let non = nonce.as_bytes();
    let mut msg = Vec::with_capacity(
        WORKER_REGISTRATION_POP_DOMAIN.len() + 8 + wid.len() + 32 + 1 + 8 + 8 + non.len(),
    );
    msg.extend_from_slice(WORKER_REGISTRATION_POP_DOMAIN);
    msg.extend_from_slice(&(wid.len() as u64).to_le_bytes());
    msg.extend_from_slice(wid);
    msg.extend_from_slice(public_key);
    msg.push(u8::from(supports_sealing));
    msg.extend_from_slice(&issued_at_ms.to_le_bytes());
    msg.extend_from_slice(&(non.len() as u64).to_le_bytes());
    msg.extend_from_slice(non);
    msg
}

/// Sign a worker-registration proof-of-possession with the worker's Ed25519
/// signing key; returns the 64-byte signature. Used by the worker's boot-time
/// self-registration client. The controller checks it with
/// [`verify_worker_registration_proof`].
#[must_use]
pub fn sign_worker_registration_proof(
    signing_key: &DispatchSigningKey,
    worker_id: &str,
    public_key: &[u8; 32],
    supports_sealing: bool,
    issued_at_ms: u64,
    nonce: &str,
) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let msg = worker_registration_pop_message(
        worker_id,
        public_key,
        supports_sealing,
        issued_at_ms,
        nonce,
    );
    signing_key.sign(&msg).to_bytes().to_vec()
}

/// Verify a worker-registration proof-of-possession: `proof` MUST be a valid
/// Ed25519 signature by `public_key` over the canonical message for these exact
/// fields. Proves the registrant holds the private key for the key it registers,
/// so it cannot register a public key it does not control, nor alter any signed
/// field without invalidating the proof. Uses `verify_strict` (rejects
/// small-order keys and signature malleability). Fails closed on a malformed
/// signature or any field mismatch. Does NOT check freshness or caller
/// authorization — the endpoint layers a bearer-token gate and a freshness
/// window on top.
pub fn verify_worker_registration_proof(
    public_key: &[u8; 32],
    worker_id: &str,
    supports_sealing: bool,
    issued_at_ms: u64,
    nonce: &str,
    proof: &[u8],
) -> Result<(), String> {
    let vk = DispatchVerifyingKey::from_bytes(public_key)
        .map_err(|_| "registration proof: public_key is not a valid Ed25519 point".to_string())?;
    let sig_bytes: [u8; 64] = proof
        .try_into()
        .map_err(|_| "registration proof: signature must be 64 bytes".to_string())?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    let msg = worker_registration_pop_message(
        worker_id,
        public_key,
        supports_sealing,
        issued_at_ms,
        nonce,
    );
    vk.verify_strict(&msg, &sig)
        .map_err(|_| "registration proof: signature verification failed".to_string())
}

/// Parse a 32-byte Ed25519 **private** (signing) key seed from hex. Used by the
/// controller to load its dispatch signing key. The seed is secret — callers
/// must source it from a Secret / KMS, never a plaintext config committed to
/// the repo. Fails closed on wrong length.
pub fn parse_ed25519_signing_key_hex(hex_str: &str) -> Result<DispatchSigningKey, String> {
    let bytes = hex::decode(hex_str.trim())
        .map_err(|_| "controller signing key: invalid hex".to_string())?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "controller signing key: must be a 32-byte seed".to_string())?;
    Ok(DispatchSigningKey::from_bytes(&arr))
}

/// Generate a fresh Ed25519 keypair for the RFC 0010 worker-trust boundary,
/// returned as `(signing_seed_hex, verifying_key_hex)` — both 64-char lowercase
/// hex, in the exact shape [`parse_ed25519_signing_key_hex`] /
/// [`parse_ed25519_verifying_key_hex`] accept. The seed is SECRET (store it in a
/// Secret / KMS and hand it to exactly one process); the verifying key is public
/// and is what the peer configures. Backs the `controller
/// generate-worker-trust-keypair` operator subcommand — the ONE supported way
/// to mint keys for `TALOS_{CONTROLLER,WORKER}_SIGNING_KEY` +
/// `TALOS_{CONTROLLER_PUBLIC_KEY,WORKER_PUBLIC_KEYS}`.
#[must_use]
pub fn generate_ed25519_keypair_hex() -> (String, String) {
    let sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
    let vk = sk.verifying_key();
    (hex::encode(sk.to_bytes()), hex::encode(vk.to_bytes()))
}

/// The controller's dispatch-signing choice, constructed once at boot from
/// config and used at every `JobRequest` / `PipelineJobRequest` sign site so the
/// scheme lives in ONE place. `Hmac` keeps the legacy `WORKER_SHARED_KEY` path;
/// `Ed25519` signs with the controller's private key (RFC 0010 P1).
#[derive(Clone)]
pub enum DispatchSigner {
    /// Scheme 0 — symmetric HMAC-SHA256 under the pre-shared key.
    Hmac(std::sync::Arc<Vec<u8>>),
    /// Scheme 1 — Ed25519 under the controller's private key.
    Ed25519(std::sync::Arc<DispatchSigningKey>),
}

// Redacted Debug (lint check 37): never render key material.
impl std::fmt::Debug for DispatchSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Hmac(_) => f.write_str("DispatchSigner::Hmac(<redacted>)"),
            Self::Ed25519(_) => f.write_str("DispatchSigner::Ed25519(<redacted>)"),
        }
    }
}

impl DispatchSigner {
    /// The wire `crypto_scheme` this signer stamps.
    #[must_use]
    pub fn scheme(&self) -> u8 {
        match self {
            Self::Hmac(_) => CRYPTO_SCHEME_HMAC,
            Self::Ed25519(_) => CRYPTO_SCHEME_ED25519,
        }
    }

    /// Sign a `JobRequest` under this signer's scheme (sets nonce + signature +
    /// `crypto_scheme`).
    pub fn sign_job(&self, req: &mut JobRequest) -> Result<(), String> {
        match self {
            Self::Hmac(k) => req.sign(k),
            Self::Ed25519(sk) => req.sign_ed25519(sk),
        }
    }

    /// Sign a `PipelineJobRequest` under this signer's scheme.
    pub fn sign_pipeline(&self, req: &mut PipelineJobRequest) -> Result<(), String> {
        match self {
            Self::Hmac(k) => req.sign(k),
            Self::Ed25519(sk) => req.sign_ed25519(sk),
        }
    }
}

/// The process-wide Ed25519 dispatch signer, resolved once from env, or `None`
/// when Ed25519 dispatch is not configured (the default) — in which case every
/// sign site keeps its legacy HMAC path. `Some` is returned only when
/// `TALOS_DISPATCH_SCHEME=ed25519` AND a valid 32-byte-hex-seed
/// `TALOS_CONTROLLER_SIGNING_KEY` is present. A requested-but-misconfigured
/// setup logs an error and returns `None` (fall back to HMAC, which the
/// dual-verify worker still accepts, so a bad key can't strand dispatch during
/// rollout). Single source of truth for ALL controller sign sites (engine
/// dispatcher, retry re-sign, module-push paths) so the scheme can't diverge
/// between them.
///
/// Reads env like the sibling `load_worker_key_ring` / `load_worker_shared_key_previous`
/// helpers; cached in a `OnceLock` so the key is parsed once.
#[must_use]
pub fn configured_dispatch_signer() -> Option<DispatchSigner> {
    static CACHE: std::sync::OnceLock<Option<DispatchSigner>> = std::sync::OnceLock::new();
    CACHE
        .get_or_init(|| {
            let scheme = std::env::var("TALOS_DISPATCH_SCHEME").unwrap_or_default();
            if !scheme.eq_ignore_ascii_case("ed25519") {
                return None;
            }
            let Ok(hex_seed) = std::env::var("TALOS_CONTROLLER_SIGNING_KEY") else {
                // NB: this crate has no `tracing` dep by design; the controller's
                // `talos-engine` wrapper logs the same condition loudly at boot.
                return None;
            };
            parse_ed25519_signing_key_hex(&hex_seed)
                .ok()
                .map(|sk| DispatchSigner::Ed25519(std::sync::Arc::new(sk)))
        })
        .clone()
}

/// Per-worker Ed25519 **result-verifying** key registry, parsed once from
/// `TALOS_WORKER_PUBLIC_KEYS` (RFC 0010 P2). Format: comma-separated
/// `worker_id=hex32` pairs; a `worker_id` MAY repeat to publish several keys
/// (rotation / blue-green rollout), and every key registered for that id is
/// tried at verify time. Malformed or empty entries are skipped (that entry
/// fails closed) rather than poisoning the whole registry — one bad line can't
/// strand the fleet. An unknown `worker_id` yields an empty slice, so
/// `verify_dispatch` fails closed because no key matches.
///
/// The controller holds only worker *public* keys, so it can verify a
/// worker-signed result but cannot forge one — the asymmetric half of the
/// result-path trust boundary, mirroring the worker holding only the
/// controller's public key on the dispatch path.
type WorkerKeyMap = std::collections::HashMap<String, Vec<DispatchVerifyingKey>>;

/// The env-parsed base registry (`TALOS_WORKER_PUBLIC_KEYS`), parsed exactly
/// once. Immutable; the dynamic (DB-backed, RFC 0010 P2 inc.4) overlay is merged
/// on top of a clone of this by [`set_dynamic_worker_public_keys`].
fn env_worker_public_key_registry() -> &'static WorkerKeyMap {
    static ENV: std::sync::OnceLock<WorkerKeyMap> = std::sync::OnceLock::new();
    ENV.get_or_init(|| {
        std::env::var("TALOS_WORKER_PUBLIC_KEYS")
            .map(|raw| parse_worker_public_keys(&raw))
            .unwrap_or_default()
    })
}

/// The live verifying-key snapshot readers hit on the hot `verify_dispatch` path.
/// Seeded lazily from the env registry — so a worker (which never installs a
/// dynamic overlay) keeps pure env-only behaviour — and atomically replaced by
/// the controller's refresh task via [`set_dynamic_worker_public_keys`].
///
/// `ArcSwap` gives lock-free O(1) reads on the verify hot path and an atomic
/// pointer swap on refresh (no reader ever blocks on a writer), the same shape
/// `rpc_auth` uses for its rotating nonce cache.
fn worker_public_key_snapshot() -> &'static arc_swap::ArcSwap<WorkerKeyMap> {
    static SNAP: std::sync::OnceLock<arc_swap::ArcSwap<WorkerKeyMap>> = std::sync::OnceLock::new();
    SNAP.get_or_init(|| arc_swap::ArcSwap::from_pointee(env_worker_public_key_registry().clone()))
}

/// **Controller-only.** Replace the dynamic worker-key overlay with `dynamic`,
/// rebuilding the live snapshot as `union(env static registry, dynamic)` and
/// atomically swapping it in. Full-replacement (NOT additive): each call rebuilds
/// from the immutable env base, so a key that was deactivated in the DB and hence
/// dropped from `dynamic` disappears from the snapshot on the next refresh — the
/// controller's refresh task passes the complete active DB set every interval.
///
/// Env-registered keys always survive (they are the operator-pinned base);
/// dynamic keys byte-identical to an env key are de-duplicated so a worker whose
/// key is in both places is not verified against twice. The worker never calls
/// this, so its behaviour is unchanged. Idempotent and safe to call repeatedly.
pub fn set_dynamic_worker_public_keys(
    dynamic: impl IntoIterator<Item = (String, DispatchVerifyingKey)>,
) {
    let mut merged = env_worker_public_key_registry().clone();
    for (worker_id, vk) in dynamic {
        let slot = merged.entry(worker_id).or_default();
        if !slot
            .iter()
            .any(|existing| existing.to_bytes() == vk.to_bytes())
        {
            slot.push(vk);
        }
    }
    worker_public_key_snapshot().store(std::sync::Arc::new(merged));
}

/// Pure parser for the `TALOS_WORKER_PUBLIC_KEYS` value — extracted from
/// [`worker_public_key_registry`] so the skip-malformed / repeat-id-for-rotation
/// behaviour is unit-testable without mutating process env. See that function
/// for the format and fail-closed semantics.
fn parse_worker_public_keys(
    raw: &str,
) -> std::collections::HashMap<String, Vec<DispatchVerifyingKey>> {
    let mut map: std::collections::HashMap<String, Vec<DispatchVerifyingKey>> =
        std::collections::HashMap::new();
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let Some((wid, hexk)) = entry.split_once('=') else {
            continue;
        };
        let wid = wid.trim();
        if wid.is_empty() {
            continue;
        }
        let Ok(vk) = parse_ed25519_verifying_key_hex(hexk) else {
            continue;
        };
        map.entry(wid.to_string()).or_default().push(vk);
    }
    map
}

/// Ed25519 result-verifying key(s) registered for `worker_id` (possibly several,
/// for rotation). Reads the live snapshot = `union(env registry, dynamic DB
/// overlay)`. Empty when the worker is unknown or no key is registered anywhere —
/// `JobResult::verify_dispatch` then fails closed on an Ed25519-scheme result.
/// Lock-free; see [`worker_public_key_snapshot`] / [`set_dynamic_worker_public_keys`].
#[must_use]
pub fn worker_public_keys(worker_id: &str) -> Vec<DispatchVerifyingKey> {
    worker_public_key_snapshot()
        .load()
        .get(worker_id)
        .cloned()
        .unwrap_or_default()
}

/// Whether the controller still accepts legacy-HMAC-signed job/pipeline results.
/// Default `true` (accept — the rollout posture while workers migrate to
/// per-worker Ed25519). `TALOS_RESULT_REQUIRE_ED25519` ∈ {`1`,`true`,`yes`,`on`}
/// flips it to `false`: the RFC 0010 P4 enforcement flip that refuses HMAC
/// results once every worker signs Ed25519. Cached; single source of truth for
/// the `accept_legacy_hmac` argument at every controller result-verify site.
#[must_use]
pub fn result_accept_legacy_hmac() -> bool {
    static CACHE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *CACHE.get_or_init(|| {
        !matches!(
            std::env::var("TALOS_RESULT_REQUIRE_ED25519")
                .ok()
                .as_deref(),
            Some("1" | "true" | "yes" | "on")
        )
    })
}

/// Crate-private core shared by every signed NATS message type.
///
/// Implementors provide the canonical signing payload plus nonce/signature
/// field access; the provided methods implement sign, HMAC+freshness
/// verification, replay-cache recording, and key-ring rotation support
/// exactly once for all five message types.
trait SignedMessage {
    /// The nonce field's name as it appears in every error string
    /// (`"job_nonce"` / `"result_nonce"` / `"heartbeat_nonce"`).
    /// Error messages are byte-for-byte stable — callers and tests
    /// match on them (e.g. `"result_nonce already seen"`).
    const NONCE_LABEL: &'static str;

    /// Canonical byte string signed / verified by HMAC-SHA256. Forwards to
    /// the type's inherent `signing_payload()` — the append-only,
    /// wire-format-stable payload construction stays per-type and untouched.
    fn payload_bytes(&self) -> Vec<u8>;

    /// The nonce field (`"{unix_secs}:{random_hex}"`).
    fn nonce(&self) -> &str;

    /// Set the nonce field (called by [`Self::sign_core`]).
    fn set_nonce(&mut self, nonce: String);

    /// The HMAC-SHA256 signature field.
    fn signature(&self) -> &[u8];

    /// Set the signature field (called by [`Self::sign_core`]).
    fn set_signature(&mut self, signature: Vec<u8>);

    /// Shared signing core: build a fresh nonce
    /// (`"<unix_seconds>:<16 random hex bytes>"`), then HMAC-SHA256 the
    /// canonical payload with the pre-shared `key`. Sets both fields.
    fn sign_core(&mut self, key: &[u8]) -> Result<(), String> {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("system time error: {e}"))?
            .as_secs();
        let rand_bytes: [u8; 16] = rand::thread_rng().gen();
        self.set_nonce(format!("{}:{}", ts, hex::encode(rand_bytes)));

        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(key).map_err(|e| format!("HMAC key error: {e}"))?;
        mac.update(&self.payload_bytes());
        self.set_signature(mac.finalize().into_bytes().to_vec());
        Ok(())
    }

    /// Nonce parse + freshness window (past `max_age_secs`, future
    /// `MAX_FUTURE_SKEW_SECS`). Signature-scheme-independent, so BOTH the HMAC
    /// and the Ed25519 verify paths build on it — the replay/freshness discipline
    /// is identical across schemes; only the signature primitive differs.
    /// Returns the parsed nonce timestamp on success.
    ///
    /// Check order is timestamp-parse before hex-validation. (Pre-refactor
    /// `PipelineJobResult` alone checked hex first — accidental drift; the
    /// orders are otherwise equivalent, differing only in WHICH error
    /// string is returned for a nonce malformed in both ways at once.)
    fn check_freshness_window(&self, max_age_secs: u64) -> Result<u64, String> {
        let parts: Vec<&str> = self.nonce().splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(format!("malformed {}", Self::NONCE_LABEL));
        }
        let ts: u64 = parts[0]
            .parse()
            .map_err(|_| format!("invalid timestamp in {}", Self::NONCE_LABEL))?;
        if hex::decode(parts[1]).is_err() {
            return Err(format!("invalid hex in {}", Self::NONCE_LABEL));
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if now.saturating_sub(ts) > max_age_secs {
            return Err(format!(
                "{} is too old ({} s, max {})",
                Self::NONCE_LABEL,
                now.saturating_sub(ts),
                max_age_secs
            ));
        }
        if ts.saturating_sub(now) > MAX_FUTURE_SKEW_SECS {
            return Err(format!(
                "{} is in the future ({} s ahead, max {})",
                Self::NONCE_LABEL,
                ts.saturating_sub(now),
                MAX_FUTURE_SKEW_SECS
            ));
        }
        Ok(ts)
    }

    /// Shared verify-without-replay-recording core: freshness window +
    /// constant-time HMAC. **Never touches the replay cache** — this is the
    /// observer half of the verify-once split. Returns the parsed nonce
    /// timestamp on success.
    fn verify_no_replay_core(&self, key: &[u8], max_age_secs: u64) -> Result<u64, String> {
        let ts = self.check_freshness_window(max_age_secs)?;

        // Constant-time HMAC verification.
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(key).map_err(|e| format!("HMAC key error: {e}"))?;
        mac.update(&self.payload_bytes());
        mac.verify_slice(self.signature())
            .map_err(|_| "HMAC signature verification failed".to_string())?;

        Ok(ts)
    }

    /// Canonical bytes signed / verified under the Ed25519 dispatch scheme: the
    /// type's HMAC `payload_bytes()` plus [`ED25519_DISPATCH_DOMAIN_TAG`]. The
    /// domain tag means an Ed25519 signature and an HMAC over "the same" message
    /// commit to different bytes — no cross-scheme confusion — and binds the
    /// scheme/version.
    fn ed25519_signing_input(&self) -> Vec<u8> {
        let mut v = self.payload_bytes();
        v.extend_from_slice(ED25519_DISPATCH_DOMAIN_TAG);
        v
    }

    /// Ed25519 signing core: fresh nonce + Ed25519 signature over
    /// [`Self::ed25519_signing_input`] with the controller's private key. Sets
    /// both the nonce and the (64-byte) signature field. The nonce is set FIRST
    /// so it is covered by the signature (it is part of `payload_bytes`).
    fn sign_core_ed25519(&mut self, signing_key: &DispatchSigningKey) -> Result<(), String> {
        use ed25519_dalek::Signer;
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("system time error: {e}"))?
            .as_secs();
        let rand_bytes: [u8; 16] = rand::thread_rng().gen();
        self.set_nonce(format!("{}:{}", ts, hex::encode(rand_bytes)));
        let sig = signing_key.sign(&self.ed25519_signing_input());
        self.set_signature(sig.to_bytes().to_vec());
        Ok(())
    }

    /// Ed25519 verify-without-replay: freshness window + Ed25519 signature check
    /// against each provided controller public key (first match wins, so a
    /// rotated controller key with an overlap window verifies). Uses
    /// `verify_strict` (rejects non-canonical `R`/small-order points). Touches
    /// no replay cache. Returns the parsed nonce timestamp on success.
    fn verify_no_replay_ed25519_core(
        &self,
        keys: &[DispatchVerifyingKey],
        max_age_secs: u64,
    ) -> Result<u64, String> {
        let ts = self.check_freshness_window(max_age_secs)?;
        if keys.is_empty() {
            return Err("no controller Ed25519 verifying key configured".to_string());
        }
        let sig = ed25519_dalek::Signature::from_slice(self.signature())
            .map_err(|_| "malformed Ed25519 signature".to_string())?;
        let input = self.ed25519_signing_input();
        for k in keys {
            if k.verify_strict(&input, &sig).is_ok() {
                return Ok(ts);
            }
        }
        Err("Ed25519 signature verification failed".to_string())
    }

    /// Ed25519 primary-verifier core: [`Self::verify_no_replay_ed25519_core`]
    /// plus replay-cache recording (verify-once). Records the nonce exactly once,
    /// only after a key matches.
    fn verify_ed25519_core(
        &self,
        keys: &[DispatchVerifyingKey],
        max_age_secs: u64,
    ) -> Result<(), String> {
        let ts = self.verify_no_replay_ed25519_core(keys, max_age_secs)?;
        self.record_nonce_or_replay_err(ts, max_age_secs)
    }

    /// Record the (already HMAC+freshness-verified) nonce in the
    /// process-local replay cache, or fail with the byte-stable
    /// `"<nonce> already seen"` replay error. This is the ONLY place the
    /// shared core inserts into `JOB_NONCE_CACHE`.
    fn record_nonce_or_replay_err(&self, ts: u64, max_age_secs: u64) -> Result<(), String> {
        // Replay protection: refuse a nonce we have seen before within
        // the freshness window. HMAC alone catches forgery; without
        // this check, anyone with NATS-publish access can capture a
        // signed message and re-fire it any number of times until
        // ts + max_age_secs expires.
        if !check_and_record_job_nonce(self.nonce(), ts, max_age_secs) {
            return Err(format!(
                "{} already seen (replay attempt within {}-second window)",
                Self::NONCE_LABEL,
                max_age_secs
            ));
        }
        Ok(())
    }

    /// Shared primary-verifier core: [`Self::verify_no_replay_core`] plus
    /// replay-cache recording. Exactly one primary caller per signed
    /// message per process (verify-once rule).
    fn verify_core(&self, key: &[u8], max_age_secs: u64) -> Result<(), String> {
        let ts = self.verify_no_replay_core(key, max_age_secs)?;
        self.record_nonce_or_replay_err(ts, max_age_secs)
    }

    /// Ring variant of [`Self::verify_no_replay_core`]: HMAC+freshness
    /// against the signing key first, then each staged previous key; first
    /// match wins. Returns the signing-key error if all fail. Touches no
    /// replay cache — which is what makes the multi-key loop safe (a naive
    /// `for k { self.verify(k) }` would insert the nonce on the first
    /// attempt and spuriously fail the second key as a replay).
    fn verify_no_replay_with_ring_core(
        &self,
        ring: &talos_workflow_engine_core::WorkerKeyRing,
        max_age_secs: u64,
    ) -> Result<u64, String> {
        let mut keys = ring.verify_keys().iter();
        let signing = keys.next().expect("WorkerKeyRing is never empty");
        let signing_err = match self.verify_no_replay_core(signing.as_bytes(), max_age_secs) {
            Ok(ts) => return Ok(ts),
            Err(e) => e,
        };
        for prev in keys {
            if let Ok(ts) = self.verify_no_replay_core(prev.as_bytes(), max_age_secs) {
                return Ok(ts);
            }
        }
        Err(signing_err)
    }

    /// Ring variant of [`Self::verify_core`]: the nonce is recorded exactly
    /// once, only after a ring member matches.
    fn verify_with_ring_core(
        &self,
        ring: &talos_workflow_engine_core::WorkerKeyRing,
        max_age_secs: u64,
    ) -> Result<(), String> {
        let ts = self.verify_no_replay_with_ring_core(ring, max_age_secs)?;
        self.record_nonce_or_replay_err(ts, max_age_secs)
    }
}

/// Hard cap for the job-nonce replay cache.
///
/// Exposed so health endpoints can report the headroom (`size / cap`)
/// alongside the raw size. The constant lives in this crate to keep a
/// single source of truth.
pub const JOB_NONCE_CACHE_CAPACITY: usize = NONCE_CACHE_HARD_CAP;

#[cfg(test)]
#[allow(dead_code)] // helper for future tests that exercise replay protection
fn clear_job_nonce_cache_for_test() {
    if let Ok(mut g) = JOB_NONCE_CACHE.seen.lock() {
        g.clear();
    }
}

/// `skip_serializing_if` helpers for zero-default numeric fields —
/// keeps default-valued wire messages byte-identical to the
/// pre-field format (the wire-format stability rule).
fn is_default_u32(v: &u32) -> bool {
    *v == 0
}
fn is_default_u64(v: &u64) -> bool {
    *v == 0
}

fn default_priority() -> u8 {
    100
}

#[cfg(test)]
mod per_worker_signing_key_tests {
    use super::{derive_envelope_aead_key_v1, derive_worker_signing_key, WORKER_SIGNING_KEY_LABEL};

    const ROOT: &[u8] = b"0123456789abcdef0123456789abcdef"; // 32 bytes

    #[test]
    fn deterministic_for_same_inputs() {
        // Worker (sign) and controller (verify) must derive byte-identical keys.
        assert_eq!(
            derive_worker_signing_key(ROOT, "talos-worker-abc-12345"),
            derive_worker_signing_key(ROOT, "talos-worker-abc-12345"),
        );
    }

    #[test]
    fn distinct_per_worker_id() {
        // The whole point: worker-A's key cannot sign as worker-B. Different
        // worker_id ⇒ different key, so a compromised worker holding only its
        // own derived key can't forge worker-B's signatures.
        let a = derive_worker_signing_key(ROOT, "worker-a");
        let b = derive_worker_signing_key(ROOT, "worker-b");
        assert_ne!(a, b, "distinct worker_ids must yield distinct signing keys");
    }

    #[test]
    fn distinct_per_root() {
        // A different fleet root ⇒ different key for the same worker_id.
        let root2: &[u8] = b"ffffffffffffffffffffffffffffffff";
        assert_ne!(
            derive_worker_signing_key(ROOT, "worker-a"),
            derive_worker_signing_key(root2, "worker-a"),
        );
    }

    #[test]
    fn domain_separated_from_envelope_key() {
        // The signing subkey must not collide with the envelope-AEAD subkey
        // derived from the same root — distinct HKDF labels guarantee it. A
        // collision would let an envelope key be used as a signing key or vice
        // versa. (Empty worker_id vs. the v1 envelope's no-info derivation is
        // the closest-adjacent pair; assert they differ.)
        assert_ne!(
            derive_worker_signing_key(ROOT, ""),
            derive_envelope_aead_key_v1(ROOT),
        );
    }

    #[test]
    fn label_is_stable() {
        // The label is part of the wire contract: changing it silently breaks
        // verification fleet-wide (worker signs under new label, controller
        // verifies under old). Pin it so a bump is a deliberate, reviewed change.
        assert_eq!(
            WORKER_SIGNING_KEY_LABEL,
            b"talos/worker-shared-key/per-worker-signing/v1"
        );
    }

    #[test]
    fn empty_worker_id_is_defined() {
        // The back-compat `sign()` wrapper uses an empty worker_id; derivation
        // must be well-defined (not panic) for it even though production uses a
        // real id.
        let k = derive_worker_signing_key(ROOT, "");
        assert_eq!(k.len(), 32);
    }
}

// ============================================================================
// Reserved host vault paths — LLM provider API keys
// ============================================================================
//
// These paths name the canonical LLM provider API keys that the controller
// pre-fetches into every worker job's secrets map so the host-side `llm::*`
// functions can resolve them. THE LIST HAS SECURITY IMPLICATIONS:
//
// - Controller-side (`engine::parallel::prefetch_llm_vault_keys` +
//   `secrets::SecretsManager::get_llm_vault_keys`): every job gets a snapshot
//   of these paths injected so LLM host calls can find them without the
//   module declaring them in `allowed_secrets`.
// - Worker-side (`host_impl::check_secret_allowlist`): guest-reachable
//   secret resolution MUST deny these paths even when a module has
//   `allowed_secrets: ["*"]` — otherwise a wildcard-grant module could
//   exfiltrate the user's LLM API keys via `secrets::get_secret` or a
//   `vault://anthropic/api_key` header interpolation.
//
// The list lives here, not per-crate, so adding a provider happens in one
// place and the controller prefetch + cache-invalidation + worker deny-list
// stay in lockstep. If you're adding a new provider (say, Mistral), update
// this constant and the corresponding branch in `worker::host_impl::llm_key_lookup_paths`.
//
// Rules for the list:
// - Entries are literal, case-sensitive vault paths.
// - The worker does a case-sensitive exact match; casing/prefix games can't
//   bypass the deny-list.
// - Add only paths that are genuinely host-only. User-facing secrets
//   (OAuth tokens, per-integration keys) do NOT belong here.
pub const LLM_PROVIDER_VAULT_PATHS: &[&str] =
    &["anthropic/api_key", "openai/api_key", "gemini/api_key"];

/// True iff `path` is one of the canonical LLM provider vault paths that
/// are reserved for host-internal consumption. Consumers use this as:
/// - worker: deny `secrets::get_secret` from returning these to WASM
/// - controller: trigger cache invalidation when the key is rotated
pub fn is_llm_provider_vault_path(path: &str) -> bool {
    LLM_PROVIDER_VAULT_PATHS.contains(&path)
}

/// Re-export so controller + worker can `use talos_workflow_job_protocol::LlmTier`
/// without pulling engine-core directly. The underlying type lives in
/// engine-core because `DispatchJob` carries it through the dispatch
/// pipeline and engine-core sits below job-protocol in the dep graph.
pub use talos_workflow_engine_core::EgressScope;
pub use talos_workflow_engine_core::LlmTier;
pub use talos_workflow_engine_core::WriteCeiling;

/// Map a provider name (case-insensitive) to its data-egress tier.
/// Anthropic / OpenAI / Gemini = Tier 2 (external). Ollama = Tier 1
/// (local). Unknown providers default to Tier 2 (treat as external
/// until proven local) — fail-closed against future providers that
/// haven't been classified yet.
///
/// NB: classification ≠ an implemented client. `talos-llm` currently ships
/// Anthropic (Tier 2) and Ollama (Tier 1) clients only; OpenAI/Gemini are
/// classified here (and in [`EXTERNAL_LLM_HOSTS`]) purely so the Tier-1 egress
/// gate denies them ahead of any client existing.
pub fn provider_tier(provider_name: &str) -> LlmTier {
    // The explicit Tier2 arm is intentional: it documents which
    // providers we have classified. Unknown providers also fall
    // through to Tier2 (fail-closed against unclassified entries).
    // Removing the explicit arm would lose that documentation.
    #[allow(clippy::match_same_arms)]
    match provider_name.to_ascii_lowercase().as_str() {
        "ollama" => LlmTier::Tier1,
        "anthropic" | "openai" | "gemini" => LlmTier::Tier2,
        _ => LlmTier::Tier2,
    }
}

/// DNS hostnames that belong to external LLM providers. Tier-1 actors
/// must not be allowed to reach these even via the generic
/// `wit_http::fetch` host function — otherwise the `llm::*`-level
/// refusal is trivially bypassed by a guest that writes its own
/// `POST https://api.anthropic.com/v1/messages` + `vault://anthropic/api_key`
/// header.
///
/// Matching is case-insensitive exact-match on the host portion of
/// the URL + suffix match to catch region-specific subdomains (e.g.
/// `generativelanguage.googleapis.com` → also `*.generativelanguage.googleapis.com`).
///
/// Extend this list whenever `LLM_PROVIDER_VAULT_PATHS` grows; the
/// two are parallel (vault-path side deny-lists the key, host-side
/// deny-lists the destination).
pub const EXTERNAL_LLM_HOSTS: &[&str] = &[
    // Anthropic — API endpoint.
    "api.anthropic.com",
    // OpenAI — primary + Azure mirror.
    "api.openai.com",
    // Google Gemini — current + legacy names.
    "generativelanguage.googleapis.com",
    "aiplatform.googleapis.com",
];

/// True iff `host` (already lowercased) matches one of the reserved
/// external LLM hostnames. Uses exact + suffix match so region
/// subdomains (`eu.api.openai.com`) also trigger.
///
/// **Trailing-dot normalisation.** `url::Url::parse("https://api.anthropic.com./...")`
/// returns `"api.anthropic.com."` (the FQDN trailing dot is preserved per
/// RFC 1738 / RFC 3986). DNS resolution treats the trailing dot as
/// equivalent to the dotless form — the same A/AAAA record is returned —
/// so leaving the deny-list strict would let a guest reach
/// `api.anthropic.com.` while the matcher silently passed. We strip the
/// trailing dot defensively at the matcher entry so every one of the five
/// worker enforcement surfaces (`fetch`, `fetch_all`, `graphql::execute`,
/// `webhook::send`, `http_stream::connect`) inherits the fix from one
/// place. Repeating the strip at every call site would be brittle.
pub fn is_external_llm_host(host_lower: &str) -> bool {
    // Defense in depth — callers are documented to pass an already-lowercased
    // host but we normalise here too: an upstream regression that forwards a
    // mixed-case or trailing-dot value shouldn't silently bypass the gate.
    let normalised = host_lower.trim_end_matches('.').to_ascii_lowercase();
    EXTERNAL_LLM_HOSTS
        .iter()
        .any(|reserved| *reserved == normalised || normalised.ends_with(&format!(".{reserved}")))
}

/// True iff `vault_path` references a Tier-2 LLM provider's credentials.
/// Used to block `vault://anthropic/api_key` substitution in HTTP headers
/// for Tier-1 jobs — the tier gate on `llm::*` host fns doesn't help if
/// the guest fetches directly and interpolates the key through
/// `resolve_vault_header`.
pub fn is_tier2_llm_vault_path(vault_path: &str) -> bool {
    is_llm_provider_vault_path(vault_path)
}

/// Postgres function names that WASM modules must never invoke from
/// `database::execute_query`. Canonical single-source-of-truth for both
/// the worker (`worker::sql_validator`) and the controller's database-RPC
/// re-parse path (`talos-rpc-subscribers`).
///
/// **Why a function deny-list is needed.** The statement-level deny-list
/// blocks `COPY`, `SET ROLE`, `PREPARE`, etc. — but a benign-looking
/// `SELECT pg_read_server_files('/etc/passwd')` parses as a Query and
/// passes every other gate. The validator must walk `Expr::Function`
/// nodes inside SELECT bodies and refuse any whose unqualified name (or
/// `pg_catalog.*` qualified form) appears below.
///
/// **Three risk classes:**
///
/// 1. **Filesystem read.** `pg_read_server_files` / `pg_read_file` /
///    `pg_read_binary_file` / `pg_ls_dir` / `pg_stat_file` /
///    `pg_ls_logdir` / `pg_ls_waldir` / `pg_ls_archive_statusdir` /
///    `pg_ls_tmpdir` — read arbitrary files on the database host. The
///    `talos_guest` role wrap (M-2) revokes EXECUTE where possible, but
///    PUBLIC keeps the default grant on many of these in stock
///    PostgreSQL — relying on the role alone is fragile. Block AST-side
///    for defense in depth.
///
/// 2. **Sleep / budget burn.** `pg_sleep` / `pg_sleep_for` /
///    `pg_sleep_until` — consume the full `statement_timeout` (60 s
///    default) without releasing the controller-side semaphore permit
///    (`MAX_IN_FLIGHT = 8`). 8 concurrent sleeping queries from a
///    malicious actor stalls every other actor's DB RPC for the
///    timeout window. Combined with the 500 queries-per-execution
///    cap, the validator catches the DoS vector at parse time.
///
/// 3. **Backend / config manipulation.** `pg_terminate_backend` /
///    `pg_cancel_backend` — kill arbitrary Postgres sessions belonging
///    to other tenants. `pg_reload_conf` / `pg_rotate_logfile` —
///    operator-only maintenance ops. `lo_import` / `lo_export` —
///    large-object FS I/O (the LO equivalent of `COPY FROM/TO`).
///
/// **Match rules:**
///
/// - Case-insensitive (Postgres normalises identifier case to lower for
///   unquoted identifiers; `PG_SLEEP(1)` is the same call as `pg_sleep(1)`).
/// - Matches both bare (`pg_sleep`) and schema-qualified (`pg_catalog.pg_sleep`)
///   forms — the visitor handles the schema strip before consulting this
///   list.
/// - Does NOT match user-defined functions with the same name. User code
///   that defines a `public.pg_sleep` is a footgun on its own (search_path
///   shadowing) and the validator can't disambiguate from the AST alone;
///   the role-wrap (M-2) is the fence for that case.
///
/// **Extending the list.** Adding a new entry requires updating both the
/// worker tests (`worker/src/sql_validator.rs`) and the controller-side
/// mirror tests (`talos-rpc-subscribers`). The deliberate-duplication
/// comment in the subscriber documents why both sides exist.
pub const DISALLOWED_SQL_FUNCTIONS: &[&str] = &[
    // ── Filesystem read ─────────────────────────────────────────────────
    "pg_read_server_files",
    "pg_read_file",
    "pg_read_binary_file",
    "pg_ls_dir",
    "pg_stat_file",
    "pg_ls_logdir",
    "pg_ls_waldir",
    "pg_ls_archive_statusdir",
    "pg_ls_tmpdir",
    // ── Sleep / budget burn ─────────────────────────────────────────────
    "pg_sleep",
    "pg_sleep_for",
    "pg_sleep_until",
    // ── Backend control ─────────────────────────────────────────────────
    "pg_terminate_backend",
    "pg_cancel_backend",
    // ── Config / maintenance ────────────────────────────────────────────
    "pg_reload_conf",
    "pg_rotate_logfile",
    "pg_promote",
    // ── Large object FS I/O (lo_import / lo_export) ─────────────────────
    "lo_import",
    "lo_export",
    // ── adminpack filesystem write/delete ───────────────────────────────
    // The read side (pg_read_file/…) is covered above; adminpack adds the
    // MUTATION side, which is strictly worse. Typically not installed, but
    // denied in the same fail-closed spirit as dblink / plperlu below.
    "pg_file_write",
    "pg_file_read",
    "pg_file_unlink",
    "pg_file_rename",
    "pg_file_sync",
    "pg_logfile_rotate",
    "pg_logdir_ls",
    // ── dblink — bypass network egress controls via PG-side connection ──
    "dblink",
    "dblink_exec",
    "dblink_connect",
    // dblink_connect_u is the UNRESTRICTED variant — it lets a non-superuser
    // use any libpq auth method, the explicit privilege-bypass of
    // dblink_connect. Denying dblink_connect without it left the bypass open.
    "dblink_connect_u",
    "dblink_disconnect",
    "dblink_send_query",
    "dblink_open",
    "dblink_close",
    "dblink_fetch",
    "dblink_get_result",
    "dblink_get_connections",
    "dblink_cancel_query",
    "dblink_error_message",
    "dblink_is_busy",
    "dblink_get_notify",
    // ── PL/perl / PL/python untrusted variants — RCE via stored proc ────
    // These are typically not installed but if they ARE installed in the
    // operator's cluster, calling them from guest SQL is RCE.
    "plperlu_call_handler",
    "plpythonu_call_handler",
    "plpython3u_call_handler",
    // ── Session-state mutation — the FUNCTION form of the blocked SET ────
    // The statement-level deny-list blocks `SET` / `SET ROLE` /
    // `SET search_path` because (per its own rationale) they are
    // "session-level state mutation that can pivot privileges or change
    // query semantics for the rest of the connection". `set_config(name,
    // value, is_local)` is the FUNCTION equivalent — `SELECT
    // set_config('search_path', …, false)` / `set_config('role', …, false)`
    // / `set_config('statement_timeout', '0', false)` reach the exact state
    // the SET block prevents, but slip past it as a plain function call in a
    // SELECT. A WASM data query has no legitimate need to mutate session
    // config, so deny it fail-closed (the bare AND `pg_catalog.set_config`
    // forms are both caught by the matcher). `current_setting` (read-only)
    // is intentionally NOT blocked — it mutates nothing.
    "set_config",
    // ── Inter-session side channel — the FUNCTION form of blocked NOTIFY ─
    // The statement-level deny-list blocks `LISTEN` / `NOTIFY` / `UNLISTEN`
    // because they are inter-session side channels (a guest could signal or
    // exfiltrate to another connection out-of-band). `pg_notify(channel,
    // payload)` is the FUNCTION equivalent of the `NOTIFY` statement —
    // `SELECT pg_notify('chan', 'secret')` delivers the same async
    // notification, slipping past the statement gate as a plain function
    // call. Same parity gap as set_config↔SET (PR #114). There is no function
    // form of LISTEN/UNLISTEN to receive, but a one-way emit is still the
    // side channel the NOTIFY block exists to close. Denied fail-closed; a
    // WASM data query has no legitimate need to emit NOTIFY traffic.
    "pg_notify",
];

/// True iff `name` (case-insensitive, schema component already stripped)
/// appears in [`DISALLOWED_SQL_FUNCTIONS`]. The schema strip is the
/// caller's responsibility — the AST visitor walks `ObjectName` and
/// passes the trailing identifier here, also re-checking the `pg_catalog`
/// qualified form because user code may write `pg_catalog.pg_sleep` to
/// bypass search-path tricks.
///
/// Constant-time match isn't needed — function names are not secrets and
/// the entire deny-list is public. The linear scan over ~25 short strings
/// is faster than the hash-table setup cost.
pub fn is_disallowed_sql_function(name: &str) -> bool {
    // Lowercase comparison. PG normalises unquoted identifiers to lower
    // at parse time, but sqlparser preserves the original case so we
    // normalise here for the comparison.
    let lower = name.to_ascii_lowercase();
    DISALLOWED_SQL_FUNCTIONS.contains(&lower.as_str())
}

/// True iff `path` is consumed by a controller-internal subsystem (LLM
/// client cache, OAuth refresh loop) rather than by any WASM module's
/// `allowed_secrets` grant. Used by the orphaned-secrets hygiene check
/// to suppress false positives — these paths are by-design absent from
/// every module's grant list.
///
/// Recognized patterns:
/// - LLM provider keys: every entry of [`LLM_PROVIDER_VAULT_PATHS`]
/// - OAuth refresh tokens:
///   `oauth/<provider>/<user_id>/<provider_key>/refresh_token`.
///   Access tokens are NOT considered host-internal because workflow
///   modules legitimately read them via `vault://` in node config.
/// - The GCP `google_cloud_full` consent tier: ALL of its tokens
///   (access AND refresh) are host-only. This tier holds a broad
///   `cloud-platform` token used solely CONTROLLER-SIDE to mint
///   short-lived impersonated service-account tokens (Phase D). It is
///   deliberately never handed to a guest — the whole point of
///   impersonation is that a module receives a 10-minute, single-SA
///   token (`gcp/impersonated/<sa>/access_token`, which is NOT reserved),
///   never the broad grant it was minted from.
///
/// Hygiene checks must use this rather than `is_llm_provider_vault_path`
/// alone — flagging an OAuth refresh_token as orphan would suggest an
/// operator delete it, silently breaking the next refresh cycle.
pub fn is_controller_internal_vault_path(path: &str) -> bool {
    if is_llm_provider_vault_path(path) {
        return true;
    }
    // The full-tier GCP consent is host-only in its ENTIRETY (access +
    // refresh). Unlike ordinary providers whose access_token is
    // module-readable via `vault://`, a `cloud-platform` access token is
    // too broad to ever cross to a guest — it exists only to call
    // iamcredentials.generateAccessToken controller-side. Reserve the whole
    // subtree. The minted `gcp/impersonated/*` tokens are a SEPARATE,
    // non-reserved namespace, so this does not block them.
    if path.starts_with("oauth/google_cloud_full/") {
        return true;
    }
    // Defensive: refuse to match shapes like "oauth/refresh_token" that
    // lack the {provider}/{user}/{key} segments — those wouldn't be
    // produced by the canonical refresh_token_path() builder, so they'd
    // be a genuine orphan worth surfacing.
    if let Some(rest) = path.strip_prefix("oauth/") {
        if let Some(prefix) = rest.strip_suffix("/refresh_token") {
            // Require at least three intermediate segments (provider /
            // user_id / provider_key) before the refresh_token suffix.
            if prefix.split('/').filter(|s| !s.is_empty()).count() >= 3 {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod llm_provider_path_tests {
    use super::{
        is_controller_internal_vault_path, is_external_llm_host, is_llm_provider_vault_path,
        EXTERNAL_LLM_HOSTS, LLM_PROVIDER_VAULT_PATHS,
    };

    #[test]
    fn canonical_paths_are_recognised() {
        for p in LLM_PROVIDER_VAULT_PATHS {
            assert!(
                is_llm_provider_vault_path(p),
                "canonical path {} not recognised",
                p
            );
        }
    }

    /// Tier-1 (local-Ollama-only) actors are blocked from external LLM egress
    /// by the worker's HTTP-host gate, which keys on `EXTERNAL_LLM_HOSTS`. Key
    /// resolution keys on `LLM_PROVIDER_VAULT_PATHS`. If a provider is added to
    /// the latter but its API host(s) are NOT added to the former, a tier-1
    /// actor can reach the new provider by raw host and exfiltrate data — the
    /// drift CLAUDE.md warns about under "Adding a new LLM provider".
    ///
    /// This is the forcing function: a new provider must be mapped here AND its
    /// host(s) must be present in `EXTERNAL_LLM_HOSTS`, or this test fails at PR
    /// time instead of the gap shipping silently.
    #[test]
    fn every_llm_provider_has_its_egress_host_in_the_deny_list() {
        // provider segment -> API host(s) the provider's traffic uses.
        let provider_hosts: &[(&str, &[&str])] = &[
            ("anthropic", &["api.anthropic.com"]),
            ("openai", &["api.openai.com"]),
            (
                "gemini",
                &[
                    "generativelanguage.googleapis.com",
                    "aiplatform.googleapis.com",
                ],
            ),
        ];

        // 1. Every vault-path provider must be mapped above.
        for path in LLM_PROVIDER_VAULT_PATHS {
            let provider = path
                .split('/')
                .next()
                .expect("vault path has a provider segment");
            assert!(
                provider_hosts.iter().any(|(p, _)| *p == provider),
                "LLM provider `{provider}` (in LLM_PROVIDER_VAULT_PATHS) is unmapped here — add it \
                 + its API host(s) to EXTERNAL_LLM_HOSTS, else a tier-1 actor can reach it by raw \
                 host (CLAUDE.md tier-1 egress invariant)."
            );
        }

        // 2. Every mapped host must be in the tier-1 egress deny-list AND
        //    recognised by the matcher the worker gate actually calls.
        for (provider, hosts) in provider_hosts {
            for host in *hosts {
                assert!(
                    EXTERNAL_LLM_HOSTS.contains(host),
                    "egress host `{host}` for provider `{provider}` is missing from \
                     EXTERNAL_LLM_HOSTS — the tier-1 HTTP-host gate won't deny it."
                );
                assert!(
                    is_external_llm_host(host),
                    "is_external_llm_host(`{host}`) is false despite the deny-list entry."
                );
            }
        }
    }

    #[test]
    fn non_llm_paths_are_not_recognised() {
        assert!(!is_llm_provider_vault_path(""));
        assert!(!is_llm_provider_vault_path("github/pat"));
        assert!(!is_llm_provider_vault_path("oauth/gmail/access_token"));
    }

    #[test]
    fn casing_and_nesting_do_not_bypass() {
        // Case-sensitive exact match only — attackers can't wrap the path
        // in a subpath or alter casing to bypass.
        assert!(!is_llm_provider_vault_path("ANTHROPIC/API_KEY"));
        assert!(!is_llm_provider_vault_path("anthropic/api_key/child"));
        assert!(!is_llm_provider_vault_path("prefix/anthropic/api_key"));
    }

    #[test]
    fn controller_internal_recognises_llm_keys() {
        for p in LLM_PROVIDER_VAULT_PATHS {
            assert!(is_controller_internal_vault_path(p));
        }
    }

    #[test]
    fn controller_internal_recognises_oauth_refresh_tokens() {
        // Canonical shape from oauth/credentials.rs::refresh_token_path:
        // oauth/{provider}/{user_id}/{provider_key}/refresh_token
        assert!(is_controller_internal_vault_path(
            "oauth/google_calendar/1a361562-e551-41aa-9cb4-6f8988b035f7/primary/refresh_token"
        ));
        assert!(is_controller_internal_vault_path(
            "oauth/atlassian/abc123/site/refresh_token"
        ));
    }

    #[test]
    fn controller_internal_rejects_oauth_access_tokens() {
        // Access tokens are consumed by sandbox modules via vault:// in node
        // config (e.g. pa-meeting-fetch). Including them would suppress
        // legitimate orphan warnings.
        assert!(!is_controller_internal_vault_path(
            "oauth/google_calendar/1a361562-e551-41aa-9cb4-6f8988b035f7/primary/access_token"
        ));
    }

    #[test]
    fn controller_internal_rejects_malformed_oauth_paths() {
        // Missing intermediate segments — these wouldn't be produced by the
        // canonical builder, so they're genuine orphans worth surfacing.
        assert!(!is_controller_internal_vault_path("oauth/refresh_token"));
        assert!(!is_controller_internal_vault_path(
            "oauth/provider/refresh_token"
        ));
        assert!(!is_controller_internal_vault_path(
            "oauth/provider/user/refresh_token"
        ));
        // Wrong prefix.
        assert!(!is_controller_internal_vault_path(
            "auth/google/user/key/refresh_token"
        ));
        // Misleading suffix.
        assert!(!is_controller_internal_vault_path(
            "oauth/google/user/key/refresh_token_backup"
        ));
    }

    #[test]
    fn controller_internal_rejects_unrelated_paths() {
        assert!(!is_controller_internal_vault_path(""));
        assert!(!is_controller_internal_vault_path("github/pat"));
        assert!(!is_controller_internal_vault_path("custom/secret"));
    }
}

// ============================================================================
// Wasm-security review 2026-05-23: is_external_llm_host normalisation tests
// ============================================================================
//
// Threat model. The five worker call sites that gate Tier-1 LLM egress —
// `wit_http::fetch` / `fetch_all`, `wit_graphql::execute`,
// `wit_webhook::send`, `wit_http_stream::connect` — feed `host_str()` from a
// `url::Url` into `is_external_llm_host`. `url::Url::parse` preserves the
// trailing dot on an FQDN, so a Tier-1 actor could write
// `https://api.anthropic.com./v1/messages` and the strict equality check
// would silently pass: DNS resolves the trailing-dot form to the same
// record. These tests pin the defensive normalisation at the matcher entry.
#[cfg(test)]
mod external_llm_host_normalisation_tests {
    use super::is_external_llm_host;

    #[test]
    fn bare_host_matches() {
        assert!(is_external_llm_host("api.anthropic.com"));
        assert!(is_external_llm_host("api.openai.com"));
        assert!(is_external_llm_host("generativelanguage.googleapis.com"));
    }

    #[test]
    fn trailing_dot_does_not_bypass() {
        // The exploit shape: `https://api.anthropic.com./v1/messages` —
        // `url::Url::host_str()` returns the trailing-dot form. Pre-fix the
        // matcher returned false; post-fix the strip normalises before
        // compare.
        assert!(is_external_llm_host("api.anthropic.com."));
        assert!(is_external_llm_host("api.openai.com."));
        assert!(is_external_llm_host("generativelanguage.googleapis.com."));
    }

    #[test]
    fn trailing_dot_on_subdomain_does_not_bypass() {
        // Suffix-match limb must also normalise — region subdomains are
        // the documented suffix-match motivator.
        assert!(is_external_llm_host("eu.api.openai.com."));
        assert!(is_external_llm_host("us-east-1.api.anthropic.com."));
    }

    #[test]
    fn mixed_case_does_not_bypass() {
        // Documented as caller-responsibility, but defense-in-depth at the
        // matcher entry guards against an upstream regression that forgets
        // to lowercase. The normalisation must apply BOTH lowercasing AND
        // trailing-dot strip — neither alone is sufficient.
        assert!(is_external_llm_host("API.ANTHROPIC.COM"));
        assert!(is_external_llm_host("API.ANTHROPIC.COM."));
        assert!(is_external_llm_host("Eu.Api.OpenAI.com."));
    }

    #[test]
    fn unrelated_hosts_still_do_not_match() {
        // Negative path — the strip must not be so aggressive that it
        // matches dot-suffixed lookalikes.
        assert!(!is_external_llm_host("example.com"));
        assert!(!is_external_llm_host("example.com."));
        assert!(!is_external_llm_host("anthropic.com")); // bare apex is NOT in deny list
        assert!(!is_external_llm_host("badanthropic.com."));
        assert!(!is_external_llm_host("api.anthropic.com.attacker.example"));
    }

    #[test]
    fn empty_and_dot_only_do_not_match() {
        // Edge cases that the trim could theoretically corrupt — confirm
        // they remain non-matches.
        assert!(!is_external_llm_host(""));
        assert!(!is_external_llm_host("."));
        assert!(!is_external_llm_host(".."));
    }
}

// ============================================================================
// Wasm-security review 2026-05-22 (MEDIUM-1): SQL function deny-list tests
// ============================================================================
#[cfg(test)]
mod disallowed_sql_function_tests {
    use super::{is_disallowed_sql_function, DISALLOWED_SQL_FUNCTIONS};

    #[test]
    fn every_canonical_entry_is_matched() {
        // Tripwire: if the const and the matcher ever drift the matcher
        // would silently miss entries the operator THOUGHT were blocked.
        for f in DISALLOWED_SQL_FUNCTIONS {
            assert!(
                is_disallowed_sql_function(f),
                "canonical deny-list entry `{f}` is not matched by is_disallowed_sql_function"
            );
        }
    }

    #[test]
    fn match_is_case_insensitive() {
        // PG normalises unquoted identifiers to lower; `PG_SLEEP(1)`,
        // `Pg_Sleep(1)`, and `pg_sleep(1)` are the same call. The
        // sqlparser AST may preserve original case, so the matcher
        // must normalise.
        assert!(is_disallowed_sql_function("PG_SLEEP"));
        assert!(is_disallowed_sql_function("Pg_Sleep"));
        assert!(is_disallowed_sql_function("pg_sleep"));
        assert!(is_disallowed_sql_function("PG_READ_SERVER_FILES"));
        assert!(is_disallowed_sql_function("LO_IMPORT"));
    }

    #[test]
    fn unrelated_function_names_not_matched() {
        // Tripwire against an overly-broad refactor (e.g. switching to
        // a `starts_with("pg_")` check that would block legitimate
        // user functions like `pg_my_custom_func`).
        for f in [
            "count",
            "sum",
            "now",
            "current_user",
            "json_agg",
            "row_number",
            "version",   // Note: version() is allowed (read-only info)
            "pg_typeof", // diagnostic, no escalation
            "pg_my_custom_business_func",
        ] {
            assert!(
                !is_disallowed_sql_function(f),
                "benign function `{f}` must NOT be matched by the deny-list"
            );
        }
    }

    #[test]
    fn empty_string_not_matched() {
        // Edge case: empty function name (shouldn't happen from the
        // parser, but defensively).
        assert!(!is_disallowed_sql_function(""));
    }

    #[test]
    fn deny_list_covers_three_risk_classes() {
        // Pin the categorical coverage so a future refactor that drops
        // any class (e.g. "let's only block filesystem reads") shows up
        // as a failing test rather than a silent policy regression.

        // Filesystem read
        for f in [
            "pg_read_server_files",
            "pg_read_file",
            "pg_read_binary_file",
            "pg_ls_dir",
            "pg_stat_file",
        ] {
            assert!(
                is_disallowed_sql_function(f),
                "filesystem-read `{f}` must be denied"
            );
        }

        // Sleep / budget burn
        for f in ["pg_sleep", "pg_sleep_for", "pg_sleep_until"] {
            assert!(is_disallowed_sql_function(f), "sleep `{f}` must be denied");
        }

        // Backend control / config
        for f in [
            "pg_terminate_backend",
            "pg_cancel_backend",
            "pg_reload_conf",
            "pg_rotate_logfile",
        ] {
            assert!(
                is_disallowed_sql_function(f),
                "backend-control `{f}` must be denied"
            );
        }

        // Large-object I/O + dblink network bypass
        for f in ["lo_import", "lo_export", "dblink", "dblink_connect"] {
            assert!(
                is_disallowed_sql_function(f),
                "io/dblink `{f}` must be denied"
            );
        }
    }
}

// ============================================================================
// Vault path allowlist matcher — shared between controller and worker
// ============================================================================

/// Returns true if `key_path` is permitted by this module's `allowed_secrets` grant.
///
/// This is the single source of truth for vault path matching semantics. Both
/// the controller (static validation, hygiene reports, engine dispatch) and
/// the worker (runtime enforcement in `secrets::get_secret()`) call this
/// function so they agree on exactly which paths a module can access.
///
/// Semantics:
///   - `[]` (empty)  → deny all (no secret is permitted)
///   - `["*"]`       → allow any key (wildcard)
///   - `["prefix"]`  → allow exactly `"prefix"` and any `"prefix/<child>"` subpath
///   - `["pfx/*"]`   → explicit glob form, equivalent to the plain prefix form above
///
/// The separator must be `/` — `["stripe"]` grants `"stripe"` and `"stripe/key"`
/// but NOT `"stripe-live/key"` (different separator).
pub fn vault_path_permitted(allowed: &[String], key_path: &str) -> bool {
    if allowed.is_empty() {
        return false;
    }
    allowed.iter().any(|s| {
        s == "*"
            || s.as_str() == key_path
            || key_path.starts_with(&format!("{}/", s))
            || (s.ends_with("/*") && key_path.starts_with(&s[..s.len() - 1]))
    })
}

#[cfg(test)]
mod vault_matcher_tests {
    use super::vault_path_permitted;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn empty_list_denies_everything() {
        assert!(!vault_path_permitted(&[], "anthropic/api_key"));
        assert!(!vault_path_permitted(&[], ""));
    }

    #[test]
    fn wildcard_allows_anything() {
        assert!(vault_path_permitted(&s(&["*"]), "anthropic/api_key"));
        assert!(vault_path_permitted(&s(&["*"]), "oauth/gmail/user/access"));
    }

    #[test]
    fn exact_match_allowed() {
        assert!(vault_path_permitted(
            &s(&["anthropic/api_key"]),
            "anthropic/api_key"
        ));
    }

    #[test]
    fn prefix_match_allowed() {
        assert!(vault_path_permitted(
            &s(&["oauth/gmail"]),
            "oauth/gmail/user/access"
        ));
        assert!(vault_path_permitted(&s(&["oauth/gmail"]), "oauth/gmail"));
    }

    #[test]
    fn glob_suffix_allowed() {
        assert!(vault_path_permitted(
            &s(&["oauth/gmail/*"]),
            "oauth/gmail/user/access"
        ));
    }

    #[test]
    fn different_separator_denied() {
        // `stripe` should NOT match `stripe-live/key` — separator must be `/`
        assert!(!vault_path_permitted(&s(&["stripe"]), "stripe-live/key"));
    }

    #[test]
    fn partial_prefix_denied() {
        assert!(!vault_path_permitted(
            &s(&["oauth/gmail"]),
            "oauth/atlassian/token"
        ));
    }

    /// SECURITY INVARIANT (GCP Phase C): a read-tier grant must never match
    /// the write-tier namespace. `oauth/google_cloud/*` and bare
    /// `oauth/google_cloud` grants must NOT resolve
    /// `oauth/google_cloud_write/...` — the distinct provider segment is the
    /// structural boundary keeping the provisioning token out of read-only
    /// modules. Both the glob arm (which strips only the `*`, keeping the
    /// `/`) and the prefix arm (which appends `/` before matching) are
    /// segment-boundary-safe; this test pins that a refactor to raw string
    /// prefixes fails loudly.
    #[test]
    fn read_tier_grant_cannot_name_write_tier_paths() {
        for grant in ["oauth/google_cloud/*", "oauth/google_cloud"] {
            assert!(
                !vault_path_permitted(
                    &s(&[grant]),
                    "oauth/google_cloud_write/1a361562/9c4d/access_token"
                ),
                "grant {grant} must not cross into the write tier"
            );
        }
        // And the write grant still matches its own namespace.
        assert!(vault_path_permitted(
            &s(&["oauth/google_cloud_write/*"]),
            "oauth/google_cloud_write/1a361562/9c4d/access_token"
        ));
    }
}

#[cfg(test)]
mod full_tier_reservation_tests {
    use super::{is_controller_internal_vault_path, vault_path_permitted};

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    /// SECURITY INVARIANT (GCP Phase D): the `google_cloud_full` consent
    /// tier holds a broad `cloud-platform` token used only to mint
    /// impersonated tokens controller-side. BOTH its access AND refresh
    /// tokens must be host-reserved — a `cloud-platform` access token is
    /// far too broad to ever reach a guest (unlike ordinary access tokens,
    /// which are module-readable). This is what the worker's
    /// `check_secret_allowlist` and the controller's `retain_wire_safe_secrets`
    /// backstop both inherit from one predicate.
    #[test]
    fn full_tier_tokens_are_entirely_host_reserved() {
        assert!(is_controller_internal_vault_path(
            "oauth/google_cloud_full/1a361562/9c4d/refresh_token"
        ));
        // The distinguishing case: full-tier ACCESS tokens are reserved too,
        // where every other provider's access token is NOT.
        assert!(is_controller_internal_vault_path(
            "oauth/google_cloud_full/1a361562/9c4d/access_token"
        ));
    }

    /// The read/write tiers stay module-readable on their access tokens —
    /// the full-tier reservation must not have widened to them.
    #[test]
    fn read_and_write_tier_access_tokens_stay_module_readable() {
        assert!(!is_controller_internal_vault_path(
            "oauth/google_cloud/1a361562/9c4d/access_token"
        ));
        assert!(!is_controller_internal_vault_path(
            "oauth/google_cloud_write/1a361562/9c4d/access_token"
        ));
    }

    /// The MINTED impersonated token lives in a separate, NON-reserved
    /// namespace so a module's `gcp/impersonated/*` grant can name it —
    /// that's the whole delivery mechanism. It must NOT be swept up by the
    /// full-tier reservation.
    #[test]
    fn minted_impersonated_token_is_not_reserved_and_is_grantable() {
        let minted = "gcp/impersonated/talos-runner@sandbox.iam.gserviceaccount.com/access_token";
        assert!(
            !is_controller_internal_vault_path(minted),
            "minted impersonated token must be deliverable to the guest"
        );
        assert!(
            vault_path_permitted(&s(&["gcp/impersonated/*"]), minted),
            "a gcp/impersonated/* module grant must cover the minted token"
        );
        // And a full-tier grant string must NOT reach the minted namespace
        // (nor vice-versa) — they are unrelated prefixes.
        assert!(!vault_path_permitted(
            &s(&["gcp/impersonated/*"]),
            "oauth/google_cloud_full/1a361562/9c4d/access_token"
        ));
    }
}

// ============================================================================
// Encrypted secrets transport
// ============================================================================

/// Encrypted secret store for transit over untrusted channels (e.g. NATS).
///
/// The plaintext is JSON-serialized `HashMap<String, String>` encrypted
/// with AES-256-GCM using the pre-shared `WORKER_SHARED_KEY`.
///
/// **Intentionally NOT `Default`.** An empty `EncryptedSecrets` is a
/// legitimate value (a job with no secrets), but it must be constructed
/// via the explicitly-named [`EncryptedSecrets::empty`] so it can never
/// arise by *accident* — e.g. `encrypted_secrets: talos_workflow_job_protocol::EncryptedSecrets::empty()` in
/// a dispatch path that should have called `build_encrypted_secrets()`,
/// which silently strips a module's secret access (the real loop-node
/// bug, 2026-04-16). This makes lint check 17 a compiler guarantee: the
/// empty case now costs a deliberate `::empty()` at the call site.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptedSecrets {
    /// AES-256-GCM ciphertext.
    pub ciphertext: Vec<u8>,
    /// 12-byte random nonce (unique per encryption).
    pub nonce: Vec<u8>,
}

impl EncryptedSecrets {
    /// The empty secret store — a job that legitimately carries no
    /// secrets. Deliberately named (not `Default`) so choosing "no
    /// secrets" is always an explicit decision at the call site. If a
    /// module is *expected* to have secrets, do NOT use this — go through
    /// the engine's `build_encrypted_secrets()` prefetch instead.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            ciphertext: Vec::new(),
            nonce: Vec::new(),
        }
    }
}

/// Reference [`SecretEnvelope`] impl backing the workspace's default
/// dispatch path. Seals the plaintext secrets map with AES-256-GCM,
/// using a caller-supplied 32-byte key as the AEAD key and a fresh
/// random 12-byte nonce per call. The AEAD tag authenticates the
/// ciphertext in-place, so callers do not need to add an outer MAC.
///
/// Construct as `AesGcmSecretEnvelope` (unit struct — no state). The
/// engine holds an `Arc<dyn SecretEnvelope>` and calls
/// [`SecretEnvelope::seal`] once per dispatch.
///
/// # Security properties
///
/// * Fresh 96-bit nonce per call (`rand::thread_rng`).
/// * Authenticated (AES-GCM's GMAC covers the ciphertext).
/// * Key length is validated — a non-32-byte key returns an error
///   rather than silently truncating.
///
/// [`SecretEnvelope`]: talos_workflow_engine_core::SecretEnvelope
/// [`SecretEnvelope::seal`]: talos_workflow_engine_core::SecretEnvelope::seal
#[derive(Debug, Clone, Copy, Default)]
pub struct AesGcmSecretEnvelope;

#[async_trait::async_trait]
impl talos_workflow_engine_core::SecretEnvelope for AesGcmSecretEnvelope {
    async fn seal(
        &self,
        secrets: &HashMap<String, String>,
        shared_key: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), talos_workflow_engine_core::BoxError> {
        // Empty map is a valid input — return the sentinel (empty
        // ciphertext + empty nonce) so the engine can short-circuit
        // without running AES on nothing.
        if secrets.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        let enc = EncryptedSecrets::encrypt(secrets, shared_key)
            .map_err(|e| -> talos_workflow_engine_core::BoxError { e.into() })?;
        Ok((enc.ciphertext, enc.nonce))
    }

    /// L-1: override the default to actually bind `aad` into the
    /// AES-GCM tag.
    async fn seal_with_aad(
        &self,
        secrets: &HashMap<String, String>,
        shared_key: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), talos_workflow_engine_core::BoxError> {
        if secrets.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        let enc = EncryptedSecrets::encrypt_with_aad(secrets, shared_key, aad)
            .map_err(|e| -> talos_workflow_engine_core::BoxError { e.into() })?;
        Ok((enc.ciphertext, enc.nonce))
    }
}

impl EncryptedSecrets {
    /// Encrypt a secrets map using AES-256-GCM.
    ///
    /// `key` must be exactly 32 bytes (256 bits).
    ///
    /// L-1 (2026-05-22): backwards-compatible no-AAD wrapper. New
    /// call sites should prefer [`Self::encrypt_with_aad`] passing
    /// `workflow_execution_id.as_bytes()` as the AAD — that ties the
    /// AES-GCM authentication tag to the specific execution and makes
    /// a transposed ciphertext (lifted from one execution into another
    /// with the same shared key) fail to decrypt rather than relying
    /// solely on the wider JobRequest HMAC to catch the tamper.
    pub fn encrypt(secrets: &HashMap<String, String>, key: &[u8]) -> Result<Self, String> {
        Self::encrypt_with_aad(secrets, key, &[])
    }

    /// L-1: Encrypt a secrets map with `aad` bound into the AES-GCM
    /// authentication tag.
    ///
    /// `key` is the 32-byte root `WORKER_SHARED_KEY`. It is **not** used
    /// as the AES-GCM key directly: the cipher key is HKDF-SHA256-expanded
    /// from it (see [`ENVELOPE_AEAD_KEY_LABEL`]) so the encryption key is
    /// domain-separated from the HMAC signing key. [`Self::decrypt_with_aad`]
    /// performs the identical derivation.
    ///
    /// The `aad` is the dispatching workflow execution id (e.g.
    /// `workflow_execution_id.as_bytes()`) — that produces an
    /// in-protocol binding between the ciphertext and the execution
    /// it travels in.
    /// Decryption MUST be done with the same `aad` via
    /// [`Self::decrypt_with_aad`]; otherwise the tag will not
    /// validate and decryption will fail closed.
    ///
    /// Empty `aad` is equivalent to [`Self::encrypt`] — the
    /// AES-GCM construction degenerates to "no AAD" and ciphertext
    /// is byte-identical to the no-AAD path (assuming the same
    /// nonce, which is randomly generated per call).
    pub fn encrypt_with_aad(
        secrets: &HashMap<String, String>,
        key: &[u8],
        aad: &[u8],
    ) -> Result<Self, String> {
        if key.len() != 32 {
            return Err(format!(
                "WORKER_SHARED_KEY must be 32 bytes, got {}",
                key.len()
            ));
        }

        let plaintext =
            serde_json::to_vec(secrets).map_err(|e| format!("serialize secrets: {e}"))?;

        // The AES-GCM key is an HKDF subkey of the root, never the raw
        // root (which is also the HMAC signing key). v2: a non-empty `aad`
        // folds the per-job context into the subkey so the random-nonce
        // budget is per-job. Encrypt and decrypt derive it identically, so
        // the round-trip stays symmetric.
        let aead_key = envelope_seal_key(key, aad);
        let cipher =
            Aes256Gcm::new_from_slice(&aead_key).map_err(|e| format!("create cipher: {e}"))?;

        // OsRng (CSPRNG via getrandom) for nonce parity with the rest of
        // the Talos signing surface — see talos-memory/src/rpc_auth.rs's
        // random_nonce. thread_rng() (ChaCha-12) is practically safe at
        // the per-message scale we hit, but using the same source
        // workspace-wide makes audit easier and removes the ChaCha-12
        // birthday-bound footnote from this primitive.
        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext.as_ref(),
                    aad,
                },
            )
            .map_err(|e| format!("encrypt secrets: {e}"))?;

        Ok(Self {
            ciphertext,
            nonce: nonce_bytes.to_vec(),
        })
    }

    /// Decrypt back into a secrets map.
    ///
    /// `key` must be the same 32-byte key used for encryption.
    /// Backwards-compatible no-AAD wrapper — passes empty AAD.
    /// Use [`Self::decrypt_with_aad`] for new call sites.
    pub fn decrypt(&self, key: &[u8]) -> Result<HashMap<String, String>, String> {
        self.decrypt_with_aad(key, &[])
    }

    /// L-1: Decrypt with `aad` bound into the AES-GCM tag check.
    ///
    /// The AAD passed here MUST byte-equal the AAD used at encrypt
    /// time. If they differ, the tag will not validate and this
    /// method returns the standard "wrong key or tampered ciphertext"
    /// error — same fail-closed surface as a bit-flipped ciphertext.
    pub fn decrypt_with_aad(
        &self,
        key: &[u8],
        aad: &[u8],
    ) -> Result<HashMap<String, String>, String> {
        if key.len() != 32 {
            return Err(format!(
                "WORKER_SHARED_KEY must be 32 bytes, got {}",
                key.len()
            ));
        }
        if self.nonce.len() != 12 {
            return Err("invalid nonce length".to_string());
        }

        let nonce = Nonce::from_slice(&self.nonce);

        // The AES-GCM key is an HKDF subkey of the root, never the raw root
        // (which is also the HMAC signing key). For a non-empty `aad` (the
        // production per-job path) try the v2 per-job key first, then fall
        // back to the v1 static key so envelopes sealed by a not-yet-rolled
        // controller still open during the rolling deploy. (Roll workers
        // first/together: a worker that only knows v1 cannot open a v2
        // envelope.) For an empty `aad` there is only the v1 key. AES-GCM's
        // tag makes the extra attempt safe — a wrong key cannot forge a
        // passing tag. `aad` is bound into the tag on every attempt.
        let candidates: Vec<[u8; 32]> = if aad.is_empty() {
            vec![derive_envelope_aead_key_v1(key)]
        } else {
            vec![
                derive_envelope_aead_key_v2(key, aad),
                derive_envelope_aead_key_v1(key),
            ]
        };

        for aead_key in candidates {
            let cipher =
                Aes256Gcm::new_from_slice(&aead_key).map_err(|e| format!("create cipher: {e}"))?;
            if let Ok(plaintext) = cipher.decrypt(
                nonce,
                Payload {
                    msg: self.ciphertext.as_ref(),
                    aad,
                },
            ) {
                return serde_json::from_slice(&plaintext)
                    .map_err(|e| format!("deserialize secrets: {e}"));
            }
        }
        Err("decryption failed — wrong key or tampered ciphertext".to_string())
    }

    /// Decrypt against a [`WorkerKeyRing`] (the decrypt-ring), trying the
    /// signing key first then each staged previous key. Returns the first
    /// success; if all fail, returns the signing-key error.
    ///
    /// This is what the worker should call to decrypt `encrypted_secrets`
    /// during a rolling `WORKER_SHARED_KEY` rotation: the controller may have
    /// already flipped to encrypting under the new root while a not-yet-rolled
    /// worker still treats the old root as current (or vice-versa). Because
    /// the encryptor (controller) and decryptor (worker) are different
    /// processes, rotation is a **two-phase** operator procedure — see
    /// [`WorkerKeyRing`]'s rotation note: first deploy the incoming key as an
    /// *accepted* (previous) key everywhere, then flip the signing key.
    ///
    /// AES-256-GCM's tag makes trial-decryption safe: a wrong key cannot forge
    /// a passing tag, so the worst case is one extra GCM verification per
    /// staged key. AAD binding is preserved across every attempt.
    ///
    /// [`WorkerKeyRing`]: talos_workflow_engine_core::WorkerKeyRing
    pub fn decrypt_with_ring(
        &self,
        ring: &talos_workflow_engine_core::WorkerKeyRing,
        aad: &[u8],
    ) -> Result<HashMap<String, String>, String> {
        let mut keys = ring.verify_keys().iter();
        // INVARIANT: a ring is never empty, so `signing` is always present.
        let signing = keys.next().expect("WorkerKeyRing is never empty");
        let signing_err = match self.decrypt_with_aad(signing.as_bytes(), aad) {
            Ok(map) => return Ok(map),
            Err(e) => e,
        };
        for prev in keys {
            if let Ok(map) = self.decrypt_with_aad(prev.as_bytes(), aad) {
                return Ok(map);
            }
        }
        Err(signing_err)
    }

    /// Returns `true` if no secrets are stored.
    pub fn is_empty(&self) -> bool {
        self.ciphertext.is_empty()
    }
}

// ============================================================================
// Job request / result
// ============================================================================

/// A job dispatched by the Controller to a Worker via NATS.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JobRequest {
    pub job_id: Uuid,
    pub workflow_execution_id: Uuid,
    pub module_uri: String,
    pub input_payload: serde_json::Value,

    /// AES-256-GCM encrypted `HashMap<String, String>` of secret values.
    /// Encrypted with the pre-shared `WORKER_SHARED_KEY`.
    /// Never log or expose directly.
    // `default = "…::empty"` (not bare `#[serde(default)]`) because
    // EncryptedSecrets is intentionally non-Default; the produced value
    // (empty ciphertext) is byte-identical to the old Default, so the
    // wire format is unchanged.
    #[serde(default = "EncryptedSecrets::empty")]
    pub encrypted_secrets: EncryptedSecrets,

    pub timeout_ms: u64,

    /// Job priority (0 = lowest, 255 = highest). Default: 100.
    /// Higher-priority jobs are dequeued before lower-priority ones.
    #[serde(default = "default_priority")]
    pub priority: u8,

    /// Absolute deadline as Unix timestamp (seconds). If set, the job MUST
    /// complete before this time or be treated as failed.  0 = no deadline.
    #[serde(default)]
    pub deadline_unix_secs: u64,

    /// Opaque cancellation token.  If set, the worker checks this token
    /// periodically and aborts execution if the token is revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancellation_token: Option<String>,

    pub allowed_hosts: Vec<String>,
    /// HTTP method allowlist. Empty = allow all methods. Non-empty = restrict to listed methods.
    #[serde(default)]
    pub allowed_methods: Vec<String>,
    /// Secret allowlist. Empty = deny all. `["*"]` = allow all. Otherwise explicit secret names.
    #[serde(default)]
    pub allowed_secrets: Vec<String>,
    /// SQL operation allowlist. Empty = allow all. Otherwise explicit types (SELECT, INSERT, etc.).
    #[serde(default)]
    pub allowed_sql_operations: Vec<String>,
    /// When true, the module may call `expose_secret` (Tier-2) to receive
    /// raw secret plaintext in WASM guest memory. Default: false (blocked).
    #[serde(default)]
    pub allow_tier2_exposure: bool,

    /// HMAC-SHA256 over the canonical job fields (see [`JobRequest::sign`]).
    pub signature: Vec<u8>,

    /// Nonce used for replay-attack prevention: `"{unix_secs}:{random_hex}"`.
    pub job_nonce: String,

    /// Actor ID that owns this execution. When set, the worker routes
    /// WIT agent-memory get/set/search calls to the persistent actor_memory
    /// Postgres table instead of the ephemeral in-memory HashMap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Uuid>,

    /// Optional WASM module bytes.  When present the worker uses these
    /// directly instead of reading from `module_uri`, avoiding file-system
    /// coupling and improving performance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wasm_bytes: Option<Vec<u8>>,

    /// Capability world hint for the worker's tiered linker selection.
    ///
    /// When present and not "unknown", the worker uses this instead of
    /// re-inspecting the WASM binary.  This is critical for sandbox modules
    /// (stored in `node_templates.precompiled_wasm`) whose world name may
    /// not survive the Wizer snapshot step.
    ///
    /// Accepts both bare names ("minimal") and WIT world names ("minimal-node",
    /// "automation-node").
    ///
    /// H-3 (2026-05-23): NOW HMAC-bound at the end of the signing payload.
    /// The previous "performance hint, linker enforces real security at
    /// instantiation time" disclaimer was only true when the worker
    /// re-derived the world from the WASM binary; for precompiled (Wizer)
    /// modules whose embedded world name doesn't survive, the controller's
    /// hint IS the policy decision. Binding it into the signature closes
    /// the tampering path where an attacker on the NATS subject would flip
    /// `minimal-node` → `automation-node` and trick the worker into
    /// selecting a wider tiered linker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_world: Option<String>,

    /// Integration name this module was compiled under, if any. When set,
    /// the module can call integration-scoped host functions (e.g. an
    /// `integration-state::*` WIT interface) and the worker signs every
    /// downstream RPC request with this value. When None, the host
    /// function returns `unauthorized` — non-integration modules cannot
    /// write to the shared integration-state table.
    ///
    /// Populated by the engine from `wasm_modules.integration_name` /
    /// `node_templates.integration_name`. Guest code has no way to
    /// supply or change this value — the worker reads it from the
    /// request, never from WIT arguments.
    ///
    /// Not part of the HMAC commitment (it's not a capability, just a
    /// scoping identifier); the RPC layer signs it separately.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integration_name: Option<String>,

    /// Expected SHA-256 hex digest of the WASM binary loaded from `module_uri`.
    ///
    /// Set by the controller from `wasm_modules.content_hash` (recorded at
    /// compile/registration time).  When present and `wasm_bytes` is absent
    /// (i.e. the worker will load the binary from the registry or Redis), the
    /// worker MUST verify that `sha256(loaded_bytes) == expected_wasm_hash`
    /// before execution.  A mismatch indicates tampering in the storage layer.
    ///
    /// Included in the HMAC signing payload so the commitment is tamper-evident.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_wasm_hash: Option<String>,

    /// Maximum fuel (WASM instructions) for this job.
    ///
    /// Set by the controller from the node's `max_fuel` config key or the
    /// module's stored `max_fuel` column.  When non-zero the worker SHOULD use
    /// this value instead of its global `WASM_FUEL_LIMIT` default.
    /// Capped at 50_000_000 (50M) by the controller to prevent abuse.
    /// Zero means "use the worker's default fuel limit".
    #[serde(default)]
    pub max_fuel: u64,

    /// User ID that owns this execution — used for ownership-scoped
    /// resources (integration_state writes, per-user rate limiting,
    /// audit trails). Populated by the controller from the workflow
    /// owner's user_id. Nil UUID indicates 'no user context' (system
    /// executions); integration_state host fns reject those.
    ///
    /// Added to JobRequest alongside `actor_id` so host fns that need
    /// user scoping (integration_state::{set,get,...}) don't have to
    /// conflate it with actor_id.
    #[serde(default)]
    pub user_id: Uuid,

    /// Maximum LLM data-egress tier this job is allowed to reach.
    /// Sourced from `actors.max_llm_tier` for actor-bound executions,
    /// `Tier2` (no restriction) for system jobs and pre-actor workflows.
    ///
    /// Worker enforcement: when this is `Tier1`, the worker's
    /// `get_llm_api_key` refuses to resolve keys for Anthropic / OpenAI
    /// / Gemini and the job fails closed with a clear "actor X is
    /// tier-1, provider Y forbidden" error.
    ///
    /// HMAC-bound: included in the signing payload so an on-wire
    /// attacker can't downgrade a tier-1 ceiling to tier-2 to redirect
    /// a sensitive actor's data to an external provider.
    #[serde(default)]
    pub max_llm_tier: LlmTier,

    /// Data-mutation ceiling this job is allowed to exercise. Sourced from
    /// `actors.max_write_ceiling` for actor-bound executions; `Write` (no
    /// restriction) for trusted system / actor-less jobs and — via
    /// `#[serde(default)]` — for legacy wire messages that predate this field.
    ///
    /// Worker enforcement (gated by `TALOS_WRITE_CEILING_ENFORCED`): when
    /// this is `ReadOnly`, every data-mutating host surface (actor-memory
    /// writes, DB DML, non-GET HTTP, webhook/email/messaging/object-storage/
    /// integration-state writes, GraphQL execute) is refused, failing closed.
    ///
    /// HMAC-bound: included in the signing payload so an on-wire attacker
    /// can't upgrade a `readonly` job to `write` and make a read-only actor
    /// mutate data.
    #[serde(default)]
    pub max_write_ceiling: WriteCeiling,

    /// Blanket network-egress scope — a security axis INDEPENDENT of
    /// `max_llm_tier`. `None` (the default, and every legacy/existing actor)
    /// falls back to the tier-derived default (`Tier1` ⇒ local, `Tier2` ⇒
    /// public). `Some(Local)` denies all public egress; `Some(Public)` permits
    /// it (subject to `allowed_hosts` + SSRF filtering) even for a `Tier1`
    /// actor whose LLM stays hard-gated local. See [`EgressScope`].
    ///
    /// HMAC-bound ONLY when `Some` (see `signing_payload`): a `None` value
    /// appends nothing, keeping every pre-existing signature byte-identical, so
    /// the field ships inert. An on-wire attacker cannot flip `Public`→`Local`
    /// (or vice-versa) without invalidating the signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_scope: Option<EgressScope>,

    /// When true, non-GET HTTP requests are mocked (returns 200 with dry_run metadata).
    /// GET requests execute normally for data fetching.
    #[serde(default)]
    pub dry_run: bool,

    /// H-1: signed reply-inbox commitment.
    ///
    /// When `Some(subject)`, the worker MUST publish its `JobResult`
    /// to exactly this NATS subject — regardless of what arrives in
    /// the unsigned `msg.reply` NATS header. Pre-fix, an on-wire
    /// attacker (or anyone with NATS publish rights) could substitute
    /// `msg.reply` with an arbitrary subject (e.g. `talos.admin.*`)
    /// and the worker would happily publish a legitimately-signed
    /// JobResult there, leaking execution output.
    ///
    /// Populated by the dispatcher when the transport supports
    /// inbox pre-allocation (`JobTransport::new_reply_inbox`).
    /// `None` falls back to the legacy "trust msg.reply" path for
    /// backward compatibility with older controllers / transports.
    ///
    /// HMAC-bound via the signing payload (appended at end per the
    /// wire-format stability rule).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_topic: Option<String>,

    /// RFC 0010 P1: signature scheme this request was signed under.
    /// [`CRYPTO_SCHEME_HMAC`] (0, default) = legacy `WORKER_SHARED_KEY`
    /// HMAC-SHA256; [`CRYPTO_SCHEME_ED25519`] (1) = Ed25519 with the controller's
    /// private key. An unsigned dispatch hint: the verifier routes on it, and a
    /// flip only sends the message to the wrong verify method (where the
    /// scheme-specific signature the attacker can't forge fails). NOT part of the
    /// HMAC `signing_payload()`, so scheme-0 bytes stay identical to pre-P1.
    #[serde(default)]
    pub crypto_scheme: u8,

    /// RFC 0010 P3 (D3b): secret-delivery scheme. [`SEALING_INLINE_WSK`] (0,
    /// default) = the inline WSK envelope in `encrypted_secrets` (today);
    /// [`SEALING_CLAIM_ECIES`] (1) = claim-based ephemeral sealing — the worker
    /// claims the job with an ephemeral key and the controller seals to it.
    /// Bound into `signing_payload()` ONLY when non-zero (so scheme-0 bytes are
    /// unchanged), which makes a `1`→`0` downgrade invalidate the signature.
    /// Omitted from the wire JSON when 0 so a legacy message is byte-identical.
    #[serde(default, skip_serializing_if = "sealing_is_default")]
    pub sealing: u8,

    /// RFC 0010 P3: the vault paths this job is permitted to resolve, sent in
    /// the clear (paths are not secrets; values are). Populated ONLY when
    /// `sealing == SEALING_CLAIM_ECIES`; the controller resolves + seals the
    /// *values* on claim, reusing the existing per-module allowlist so the claim
    /// cannot widen scope. When `sealing == 1`, `encrypted_secrets` is empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secret_paths: Vec<String>,

    /// RFC 0010 P3 (D3b): the NATS subject the worker sends its `SecretClaim` to.
    /// Set by the dispatcher (to the dispatching replica's per-process claim
    /// responder inbox) ONLY when `sealing == SEALING_CLAIM_ECIES`. Bound into
    /// `signing_payload()` when sealing is non-zero — same reasoning as
    /// `reply_topic`: an on-wire attacker must not redirect the claim (which
    /// carries the worker's ephemeral public key) to a subject they control and
    /// have the controller seal the secrets straight to them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_inbox: Option<String>,

    /// Opt-in idempotency key for a SEND node (webhook / HTTP POST / messaging).
    ///
    /// When the workflow author declares idempotency on a node (config key
    /// `__idempotency_key__`), the engine stamps a STABLE key here — stable
    /// across retry attempts of the same dispatch, unique per logical send. The
    /// worker emits it as an `Idempotency-Key` HTTP header on MUTATING outbound
    /// requests (`fetch` / `webhook::send`) so a retried send is deduplicated at
    /// the destination (the Stripe / RFC-draft industry pattern). Its presence is
    /// ALSO what lets the engine's method-aware retry default grant retries to an
    /// otherwise-non-idempotent send world — see
    /// `talos_workflow_engine_core::default_max_retries_for_module`.
    ///
    /// HMAC-bound ONLY when `Some` (see [`Self::signing_payload`]): a `None`
    /// value (every non-declaring node, and every legacy wire message) appends
    /// NOTHING, so pre-existing signatures stay byte-identical and the field
    /// ships inert. When `Some`, the `:idem=<key>` suffix is bound so an on-wire
    /// attacker cannot strip the key (forcing a duplicate on retry) or swap it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

impl JobRequest {
    /// Canonical byte string signed / verified by HMAC-SHA256.
    ///
    /// All security-sensitive fields are covered so that an attacker cannot
    /// substitute `input_payload`, secrets, WASM bytes, timeout, or allowed
    /// hosts without invalidating the signature.
    ///
    /// Format:
    /// `job_id:wex_id:module_uri:job_nonce:sha256(input):sha256(secrets_ciphertext):timeout_ms:sorted_hosts:sorted_methods:sha256(wasm_bytes)|expected_wasm_hash|none`
    ///
    /// When `wasm_bytes` is inline, the field is `sha256(wasm_bytes)`.
    /// When `wasm_bytes` is absent but `expected_wasm_hash` is set, the field is that hash
    /// (tamper-evident commitment to the content the worker will load from `module_uri`).
    /// Otherwise the sentinel "none" is used.
    #[allow(clippy::too_many_lines)] // canonical signing payload — one linear format!
    fn signing_payload(&self) -> Vec<u8> {
        use sha2::Digest;

        // Hash large/variable fields to fixed-size hex representations.
        // This prevents payload-substitution attacks where an attacker could
        // replace input_payload, secrets, or wasm_bytes with malicious content.
        let input_hash = hex::encode(Sha256::digest(self.input_payload.to_string().as_bytes()));
        let secrets_hash = hex::encode(Sha256::digest(&self.encrypted_secrets.ciphertext));

        // Sort allowed_hosts so the signature is stable regardless of array order.
        let mut hosts = self.allowed_hosts.clone();
        hosts.sort_unstable();
        let hosts_str = hosts.join(",");

        // Sort allowed_methods for the same reason: order must not matter.
        let mut methods = self.allowed_methods.clone();
        methods.sort_unstable();
        let methods_str = methods.join(",");

        // Wasm integrity commitment:
        // - Inline bytes → sha256(bytes) (already covers the content)
        // - No inline bytes + expected hash → that hash (tamper-evident URI-content binding)
        // - Neither → "none"
        let wasm_hash = if let Some(b) = self.wasm_bytes.as_deref() {
            hex::encode(Sha256::digest(b))
        } else if let Some(ref h) = self.expected_wasm_hash {
            h.clone()
        } else {
            "none".to_string()
        };

        // integration_name is part of the module's identity for
        // integration-state scoping — a NATS-channel tampering attacker
        // could otherwise swap "gcal" → "gmail" in flight and redirect
        // a module's writes into a different integration's namespace
        // without invalidating the signature. The sentinel "-" is used
        // for modules that aren't integrations so an absent value is
        // still tamper-evident (distinct from the empty string).
        //
        // Wire-format stability rule: this field is appended at the END
        // of the format string — adding it here is safe during a
        // coordinated controller+worker restart; reordering the
        // existing positions would break every deployed signature.
        let integration_name = self.integration_name.as_deref().unwrap_or("-");

        // M-4: actor_id bound. Pre-fix, an on-wire attacker could
        // change A→B without invalidating the signature; the worker
        // would then sign every downstream MemoryRpcRequest with the
        // tampered actor_id and the controller would accept it
        // (correctly signed by the worker key with the wrong actor_id).
        // Sentinel "-" for None so absence is tamper-evident.
        let actor_id_str = self
            .actor_id
            .map(|u| u.to_string())
            .unwrap_or_else(|| "-".to_string());

        // M-5: capability-grant fields bound (defense-in-depth). Even
        // though the encrypted_secrets blob and worker host-internal
        // deny-list together prevent any unauthorised secret read,
        // capability claims should be self-consistent with the signed
        // message. Pre-fix, allowed_secrets / allowed_sql_operations /
        // allow_tier2_exposure could be tampered without invalidating
        // the signature.
        let mut allowed_secrets_sorted = self.allowed_secrets.clone();
        allowed_secrets_sorted.sort_unstable();
        let allowed_secrets_str = allowed_secrets_sorted.join(",");
        let mut allowed_sql_sorted = self.allowed_sql_operations.clone();
        allowed_sql_sorted.sort_unstable();
        let allowed_sql_str = allowed_sql_sorted.join(",");

        // L-9: every variable-length field is now length-prefixed in
        // its hashed/encoded form. Field-internal `:` characters can no
        // longer cause a collision between two semantically-different
        // payloads. The legacy fixed-width fields (UUIDs, hex digests,
        // numbers, sentinel "-") use unambiguous formats so a `:`
        // delimiter remains safe. The user-controlled string fields
        // (module_uri, hosts_str, methods_str, integration_name,
        // allowed_secrets_str, allowed_sql_str, actor_id_str) are
        // emitted as `<len>:<bytes>` to remove the ambiguity.
        //
        // Defense-in-depth: today the existing fixed-width-prefix
        // header already disambiguates, but an extension that adds a
        // new free-form string field could re-introduce the collision
        // class. The length-prefix discipline is forward-safe.
        // (`lp` is the module-level length-prefix helper.)

        // H-1: reply_topic. Sentinel `-` for None so absence is
        // tamper-evident (an attacker can't strip the field to
        // downgrade verification). Length-prefixed because the inbox
        // subject is variable-length and contains `.` separators (so
        // it could collide against adjacent fields under naive
        // concatenation).
        let reply_topic_str = self.reply_topic.as_deref().unwrap_or("-");

        // Wasm-security review 2026-05-23 (H-3, H-7): bind the remaining
        // policy-controlling fields. Each was previously unsigned, which
        // gave anyone with NATS-publish rights on the job subject a
        // tamper window:
        //
        // - `capability_world` (H-3). Pre-fix doc described it as a
        //   performance hint, "linker enforces real security at
        //   instantiation time." That's only true if the worker
        //   ALWAYS re-derives the world from the WASM binary. For
        //   `precompiled_wasm` (Wizer-snapshotted) the world name may
        //   not survive — in which case the controller's hint IS the
        //   policy. An attacker who flips `minimal-node` → `automation-node`
        //   on the wire could select a wider tiered linker that resolves
        //   host fns the module would otherwise lack. Sentinel `-` for
        //   None.
        // - `dry_run` (H-7). Tamperer flips `true → false` to convert
        //   planning-mode into a real-side-effect run (real HTTP POSTs,
        //   real webhooks, real DB writes).
        // - `priority` (H-7). Queue-jumping / starving — a NATS-publish
        //   attacker can promote arbitrary jobs to drown out legitimate
        //   high-priority work.
        // - `deadline_unix_secs` (H-7). Tamperer sets a past timestamp
        //   to force premature failure; reading the field is one of
        //   the worker's loop conditions.
        // - `cancellation_token` (H-7). Stripping the token leaves an
        //   in-flight job uncancellable — resource hog / cost overrun.
        let capability_world_str = self.capability_world.as_deref().unwrap_or("-");
        let cancellation_token_str = self.cancellation_token.as_deref().unwrap_or("-");

        let mut payload = format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
            self.job_id,
            self.workflow_execution_id,
            lp(&self.module_uri),
            self.job_nonce,
            input_hash,
            secrets_hash,
            self.timeout_ms,
            lp(&hosts_str),
            lp(&methods_str),
            wasm_hash,
            lp(integration_name),
            // Appended AT THE END per the wire-format stability rule —
            // inserting in the middle would break every deployed
            // signature. user_id bound so an on-wire attacker can't
            // redirect a module's writes to a different user's
            // integration-state namespace.
            self.user_id,
            // Appended AT THE END for the same reason. Tier-ceiling
            // bound so an attacker can't downgrade a tier-1 actor's
            // ceiling on the wire to redirect data to an external LLM.
            self.max_llm_tier.as_signing_str(),
            // M-4: actor_id appended AT THE END.
            lp(&actor_id_str),
            // M-5: capability grants appended AT THE END.
            lp(&allowed_secrets_str),
            lp(&allowed_sql_str),
            self.allow_tier2_exposure,
            // H-1: reply_topic appended AT THE END so an on-wire
            // attacker can't redirect a worker's signed JobResult to
            // an attacker-controlled subject via the unsigned
            // msg.reply NATS header.
            lp(reply_topic_str),
            // H-3 (2026-05-23): capability_world appended AT THE END.
            lp(capability_world_str),
            // H-7 (2026-05-23): dry_run appended AT THE END.
            self.dry_run,
            // H-7 (2026-05-23): priority appended AT THE END.
            self.priority,
            // H-7 (2026-05-23): deadline_unix_secs appended AT THE END.
            self.deadline_unix_secs,
            // H-7 (2026-05-23): cancellation_token appended AT THE END.
            lp(cancellation_token_str),
            // Write-ceiling appended AT THE END (after all prior fields, before
            // the conditional sealing block) per the wire-format stability rule.
            // HMAC-bound so an on-wire attacker can't upgrade a `readonly` job to
            // `write` and make a read-only actor mutate data. As a new signed
            // field this needs a coordinated controller+worker restart, same as
            // `max_llm_tier` before it.
            self.max_write_ceiling.as_signing_str(),
        );

        // Egress-scope override appended AT THE END, ONLY when `Some`, per the
        // wire-format stability rule. A `None` (the default + every legacy /
        // existing actor) appends NOTHING, so pre-existing signatures stay
        // byte-identical and the field ships inert — no coordinated restart for
        // the default path. When `Some`, the `:egress=<scope>` suffix is
        // HMAC-bound so an on-wire attacker can't flip `public`↔`local` (e.g.
        // downgrade an air-gapped actor to public egress, or strip a
        // local-only actor's exfiltration block). Bound AFTER `max_write_ceiling`
        // and BEFORE the conditional sealing block.
        if let Some(scope) = self.egress_scope {
            use std::fmt::Write as _;
            let _ = write!(payload, ":egress={}", scope.as_signing_str());
        }

        // RFC 0010 P3 (D3b): bind `sealing` + `secret_paths` ONLY when a
        // non-legacy sealing scheme is in effect. For `sealing == 0` (today's
        // inline WSK envelope) nothing is appended, so the signed bytes are
        // byte-identical to the pre-P3 wire format — no coordinated restart for
        // the legacy path. When `sealing == 1`, appending the marker + sorted
        // paths makes a `1`→`0` downgrade (or a widened `secret_paths`) fail
        // verification, because the two produce different signed bytes.
        if self.sealing != 0 {
            use std::fmt::Write as _;
            let mut paths = self.secret_paths.clone();
            paths.sort_unstable();
            // claim_inbox bound with a `-` sentinel for None so its absence is
            // tamper-evident (an attacker can't strip it to redirect the claim).
            let claim_inbox = self.claim_inbox.as_deref().unwrap_or("-");
            let _ = write!(
                payload,
                ":{}:{}:{}",
                self.sealing,
                lp(&paths.join(",")),
                lp(claim_inbox)
            );
        }

        // Idempotency key appended AT THE END, ONLY when `Some`, per the
        // wire-format stability rule — a `None` (every non-declaring node +
        // every legacy message) appends nothing, so pre-existing signatures are
        // byte-identical and the field ships inert. When `Some`, binding the key
        // stops an on-wire attacker from stripping it (which would let a retried
        // send re-fire un-deduped) or swapping it for a colliding value.
        // Length-prefixed because a user-supplied key is free-form.
        if let Some(ref idem) = self.idempotency_key {
            use std::fmt::Write as _;
            let _ = write!(payload, ":idem={}", lp(idem));
        }

        payload.into_bytes()
    }

    /// Diagnostic snapshot of the per-field hashes that
    /// [`Self::signing_payload`] consumes for `input_payload` and
    /// `encrypted_secrets.ciphertext`, plus the input's serialized byte
    /// length. Surfaced by the dispatcher's `signature_diag` WARN log
    /// (controller side) and the worker's `signature verification failed`
    /// `output_payload.diag` (worker side) so operators can field-by-field
    /// compare what the two sides hashed when verification mismatched.
    /// Cheap to compute; safe to call on production traffic. Not
    /// security-sensitive (the same hashes already go into the signature).
    pub fn diag_hashes(&self) -> (String, String, usize) {
        use sha2::Digest;
        let input_str = self.input_payload.to_string();
        let input_hash = hex::encode(Sha256::digest(input_str.as_bytes()));
        let secrets_hash = hex::encode(Sha256::digest(&self.encrypted_secrets.ciphertext));
        (input_hash, secrets_hash, input_str.len())
    }

    /// Sign the request using the pre-shared `key`.
    ///
    /// Sets `self.signature` and `self.job_nonce` (timestamp + random hex).
    /// Call this after all other fields have been populated.
    pub fn sign(&mut self, key: &[u8]) -> Result<(), String> {
        self.sign_core(key)
    }

    /// Verify the HMAC signature and nonce freshness, *and* record the
    /// nonce in the process-local replay cache. Subsequent `verify()`
    /// calls against the same nonce within the freshness window will
    /// fail with `"job_nonce already seen"`.
    ///
    /// Use this at the **primary action point** for the request — the
    /// place where the message is converted into a worker dispatch.
    /// There must be EXACTLY ONE primary verifier per `JobRequest`
    /// per worker process. Passive observers (metrics, audit
    /// subscribers) MUST call [`verify_no_replay`](Self::verify_no_replay)
    /// instead — calling `verify()` from two consumers of the same
    /// signed request causes the second one to fail with a spurious
    /// replay error. See CLAUDE.md "Verify-once rule for signed NATS
    /// messages" for the architectural mandate.
    ///
    /// Returns `Err` if the signature is invalid or the nonce is older than
    /// `max_age_secs` (default recommendation: 300 s / 5 minutes).
    pub fn verify(&self, key: &[u8], max_age_secs: u64) -> Result<(), String> {
        self.verify_core(key, max_age_secs)
    }

    /// Verify against a [`WorkerKeyRing`] (decrypt/verify-ring), recording the
    /// nonce exactly once. HMAC+freshness is tried per ring member via
    /// [`Self::verify_no_replay`] — which never touches the replay cache — so
    /// the nonce is recorded only after a key matches. This avoids the
    /// multi-key nonce-cache hazard a naive `for k { self.verify(k) }` loop
    /// would create. The worker uses this to verify dispatched jobs during a
    /// rolling `WORKER_SHARED_KEY` rotation.
    ///
    /// [`WorkerKeyRing`]: talos_workflow_engine_core::WorkerKeyRing
    pub fn verify_with_ring(
        &self,
        ring: &talos_workflow_engine_core::WorkerKeyRing,
        max_age_secs: u64,
    ) -> Result<(), String> {
        self.verify_with_ring_core(ring, max_age_secs)
    }

    /// Ring variant of [`Self::verify_no_replay`]: HMAC+freshness against the
    /// signing key first, then each staged previous key; first match wins.
    /// Returns the signing-key error if all fail. Touches no replay cache.
    pub fn verify_no_replay_with_ring(
        &self,
        ring: &talos_workflow_engine_core::WorkerKeyRing,
        max_age_secs: u64,
    ) -> Result<u64, String> {
        self.verify_no_replay_with_ring_core(ring, max_age_secs)
    }

    /// Verify HMAC signature and nonce freshness **without** recording
    /// the nonce in the replay cache. Returns the parsed timestamp on
    /// success.
    ///
    /// 2026-05-28 audit F5: per CLAUDE.md "Verify-once rule for signed
    /// NATS messages — Adding a new signed message type? Add both
    /// verify() and verify_no_replay() together up front; the
    /// prophylactic split is cheap, the regression is total (every
    /// job fails)." Pre-fix `JobRequest` had only `verify()`; today
    /// only one consumer verifies so no dual-cache bug, but the
    /// architectural mandate is to add the split BEFORE the second
    /// consumer lands, not after.
    ///
    /// Use at passive observers (metrics/audit subscribers downstream
    /// of a primary `verify()` caller). HMAC continues to gate
    /// forgery and the freshness window continues to gate stale-replay;
    /// replay protection is the responsibility of the primary verifier.
    pub fn verify_no_replay(&self, key: &[u8], max_age_secs: u64) -> Result<u64, String> {
        self.verify_no_replay_core(key, max_age_secs)
    }

    // ── RFC 0010 P1: Ed25519 dispatch scheme ──────────────────────────────

    /// Sign under the Ed25519 dispatch scheme with the controller's private key.
    /// Sets `crypto_scheme = CRYPTO_SCHEME_ED25519`, a fresh `job_nonce`, and the
    /// 64-byte signature. Call after all other fields are populated.
    pub fn sign_ed25519(&mut self, signing_key: &DispatchSigningKey) -> Result<(), String> {
        self.crypto_scheme = CRYPTO_SCHEME_ED25519;
        self.sign_core_ed25519(signing_key)
    }

    /// **Primary** Ed25519 verify: freshness + signature against the controller
    /// public key(s), then record the nonce (verify-once). `keys` may carry a
    /// rotated-out previous controller key for an overlap window.
    pub fn verify_ed25519(
        &self,
        keys: &[DispatchVerifyingKey],
        max_age_secs: u64,
    ) -> Result<(), String> {
        self.verify_ed25519_core(keys, max_age_secs)
    }

    /// Observer Ed25519 verify: freshness + signature only, no replay-cache
    /// write. Returns the parsed nonce timestamp.
    pub fn verify_no_replay_ed25519(
        &self,
        keys: &[DispatchVerifyingKey],
        max_age_secs: u64,
    ) -> Result<u64, String> {
        self.verify_no_replay_ed25519_core(keys, max_age_secs)
    }

    /// Scheme-dispatching **primary** verify for the worker. Routes on
    /// `self.crypto_scheme`:
    /// - [`CRYPTO_SCHEME_ED25519`] → verify against `ed_keys`.
    /// - [`CRYPTO_SCHEME_HMAC`] → verify against the `hmac_ring`, but ONLY if
    ///   `accept_legacy_hmac` is true. Setting it false is the RFC 0010 P4
    ///   enforcement flip: the worker refuses legacy-HMAC dispatches once the
    ///   fleet is fully on Ed25519.
    /// - any other value → reject (unknown scheme).
    ///
    /// Records the nonce exactly once on success (verify-once rule preserved
    /// across both schemes).
    pub fn verify_dispatch(
        &self,
        hmac_ring: &talos_workflow_engine_core::WorkerKeyRing,
        ed_keys: &[DispatchVerifyingKey],
        max_age_secs: u64,
        accept_legacy_hmac: bool,
    ) -> Result<(), String> {
        match self.crypto_scheme {
            CRYPTO_SCHEME_ED25519 => self.verify_ed25519(ed_keys, max_age_secs),
            CRYPTO_SCHEME_HMAC => {
                if !accept_legacy_hmac {
                    return Err(
                        "legacy HMAC dispatch refused (Ed25519-only enforcement enabled)"
                            .to_string(),
                    );
                }
                self.verify_with_ring(hmac_ring, max_age_secs)
            }
            other => Err(format!("unknown dispatch crypto_scheme: {other}")),
        }
    }
}

impl SignedMessage for JobRequest {
    const NONCE_LABEL: &'static str = "job_nonce";

    fn payload_bytes(&self) -> Vec<u8> {
        self.signing_payload()
    }
    fn nonce(&self) -> &str {
        &self.job_nonce
    }
    fn set_nonce(&mut self, nonce: String) {
        self.job_nonce = nonce;
    }
    fn signature(&self) -> &[u8] {
        &self.signature
    }
    fn set_signature(&mut self, signature: Vec<u8>) {
        self.signature = signature;
    }
}

/// Job status reported by a Worker.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum JobStatus {
    Success,
    Failed,
    TimedOut,
}

/// Upper bound on the number of [`LlmUsageEntry`] rows a single result may
/// carry. The worker aggregates provider token usage per `(provider, model)`
/// before draining into the result, so this is a bound on *distinct model
/// combinations used in one job*, not on the call count. Truncating keeps the
/// signed payload small and prevents a runaway module (looping over many
/// model names) from bloating every result message. See
/// [`aggregate_llm_usage`].
pub const MAX_LLM_USAGE_ENTRIES: usize = 16;

/// Per-`(provider, model)` LLM token usage observed by the worker during a
/// single job, surfaced to the controller inside the SIGNED
/// [`JobResult`] / [`PipelineJobResult`] (workers are credential-free and
/// DB-free — usage cannot be written to the DB from the worker; it rides the
/// signed result instead).
///
/// Aggregated per provider+model (NOT per call) so the vec is bounded by the
/// number of distinct models a job touches. `calls` records how many
/// individual completions folded into this row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmUsageEntry {
    pub provider: String,
    pub model: String,
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub calls: u32,
}

impl LlmUsageEntry {
    /// Canonical single-line form for the signing digest. Fixed-shape,
    /// pipe-delimited; neither `provider` nor `model` may contain `|` in
    /// practice (provider is a fixed enum-ish string, model is a
    /// provider-issued identifier), and even if they did the collision is
    /// only a hash pre-image concern the SHA-256 absorbs.
    fn canonical_line(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            self.provider, self.model, self.prompt_tokens, self.completion_tokens, self.calls
        )
    }
}

/// Fold raw per-call `(provider, model, prompt_tokens, completion_tokens)`
/// observations into a bounded, order-independent `Vec<LlmUsageEntry>`
/// aggregated per `(provider, model)`.
///
/// PURE — no I/O, deterministic. Both the worker's usage-drain path and the
/// unit tests call this exact function so the merge logic can't drift. Token
/// counts accumulate with saturating `u32` arithmetic (a single call can't
/// realistically exceed `u32::MAX` tokens, but saturating keeps it total).
/// The result is sorted by `(provider, model)` and truncated to
/// [`MAX_LLM_USAGE_ENTRIES`] so the signing digest and wire size are bounded.
pub fn aggregate_llm_usage(
    raw: impl IntoIterator<Item = (String, String, u32, u32)>,
) -> Vec<LlmUsageEntry> {
    use std::collections::BTreeMap;
    let mut acc: BTreeMap<(String, String), (u32, u32, u32)> = BTreeMap::new();
    for (provider, model, prompt, completion) in raw {
        let slot = acc.entry((provider, model)).or_insert((0, 0, 0));
        slot.0 = slot.0.saturating_add(prompt);
        slot.1 = slot.1.saturating_add(completion);
        slot.2 = slot.2.saturating_add(1);
    }
    acc.into_iter()
        .map(|((provider, model), (p, c, calls))| LlmUsageEntry {
            provider,
            model,
            prompt_tokens: p,
            completion_tokens: c,
            calls,
        })
        .take(MAX_LLM_USAGE_ENTRIES)
        .collect()
}

/// Bind an `llm_usage` vec into a signing payload: returns `Some(hex_sha256)`
/// of the canonical, sorted, newline-joined entry lines when non-empty, or
/// `None` when the vec is empty (so an empty vec appends NOTHING to the
/// signing payload and old messages verify byte-identically).
///
/// Entries are sorted before hashing so the digest is order-independent —
/// two results with the same usage in a different vec order sign the same.
fn llm_usage_signing_hash(entries: &[LlmUsageEntry]) -> Option<String> {
    use sha2::Digest;
    if entries.is_empty() {
        return None;
    }
    let mut lines: Vec<String> = entries.iter().map(LlmUsageEntry::canonical_line).collect();
    lines.sort_unstable();
    Some(hex::encode(Sha256::digest(lines.join("\n").as_bytes())))
}

/// Result returned by a Worker to the Controller via NATS.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JobResult {
    pub job_id: Uuid,
    pub status: JobStatus,
    pub output_payload: serde_json::Value,
    pub logs: Vec<String>,
    pub execution_time_ms: u64,
    /// HMAC-SHA256 signature over canonical result fields (see [`JobResult::sign`]).
    /// Allows the controller to verify the result came from a legitimate worker.
    #[serde(default)]
    pub signature: Vec<u8>,
    /// Nonce for replay prevention: `"{unix_secs}:{random_hex}"`.
    #[serde(default)]
    pub result_nonce: String,
    /// Self-reported worker identity, HMAC-bound by [`JobResult::sign_with_worker_id`].
    ///
    /// Plain pre-shared HMAC keys cannot distinguish results from worker-A vs.
    /// worker-B — any process holding `WORKER_SHARED_KEY` can sign for any
    /// `job_id`. Binding the worker's own id into the signed payload gives the
    /// controller forensic visibility (which pod produced which result) and
    /// opens the path to per-worker HKDF subkeys in a future rev.
    ///
    /// Charset is restricted (`[A-Za-z0-9._-]{0,128}`) so the colon-delimited
    /// signing payload format stays unambiguous. Empty string is permitted for
    /// the [`JobResult::sign`] back-compat wrapper; production worker code uses
    /// [`JobResult::sign_with_worker_id`].
    #[serde(default)]
    pub worker_id: String,

    /// RFC 0010 P2: signature scheme this result was signed under.
    /// [`CRYPTO_SCHEME_HMAC`] (0, default) = legacy `WORKER_SHARED_KEY` HMAC;
    /// [`CRYPTO_SCHEME_ED25519`] (1) = the worker's own Ed25519 private key
    /// (verified by the controller against the worker's registered public key,
    /// keyed by `worker_id`). Unsigned dispatch hint — a flip routes to the wrong
    /// verify method where the scheme-specific signature fails. NOT part of the
    /// HMAC `signing_payload()`, so scheme-0 bytes stay identical to pre-P2.
    #[serde(default)]
    pub crypto_scheme: u8,

    /// Per-`(provider, model)` LLM token usage observed during this job.
    /// Empty for jobs that made no LLM calls. Bound into
    /// [`Self::signing_payload`] ONLY when non-empty (append-at-end, so old
    /// messages with no usage sign byte-identically — no coordinated restart
    /// for the no-LLM path). The controller attributes these tokens to the
    /// execution's actor/user from ITS OWN records; the worker-supplied
    /// provider/model/counts are advisory metrics, not an identity claim.
    /// Capped at [`MAX_LLM_USAGE_ENTRIES`] by the worker.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub llm_usage: Vec<LlmUsageEntry>,
}

impl JobResult {
    /// Canonical byte string signed / verified by HMAC-SHA256.
    ///
    /// Format:
    /// `job_id:status:result_nonce:sha256(output_payload):execution_time_ms:sha256(logs_canonical)`
    ///
    /// L-10: `logs` is now part of the signing payload via a SHA-256 of
    /// the canonical newline-joined form. Pre-fix, an attacker tampering
    /// with the logs field in flight could inject misleading log lines
    /// without invalidating the signature. No capability impact, but
    /// audit-trail integrity matters for incident response.
    ///
    /// L-11 (2026-05-22): `worker_id` is appended at the end of the
    /// signing payload so a result captured from one worker can't be
    /// re-published as if it came from another. The charset is enforced
    /// by [`validate_worker_id`] so the colon-delimited format stays
    /// unambiguous (no `:` smuggling). Empty `worker_id` is permitted
    /// (renders as `""`) — the [`JobResult::sign`] back-compat wrapper
    /// leaves it empty; production worker code calls
    /// [`JobResult::sign_with_worker_id`].
    fn signing_payload(&self) -> Vec<u8> {
        use sha2::Digest;
        let status_str = match self.status {
            JobStatus::Success => "success",
            JobStatus::Failed => "failed",
            JobStatus::TimedOut => "timedout",
        };
        let output_hash = hex::encode(Sha256::digest(self.output_payload.to_string().as_bytes()));
        // Canonicalise logs by joining with `\n` (a stable separator
        // that no individual log line can contain — Vec<String> elements
        // are pre-split on newlines by the worker). Hash to a fixed
        // 64-char hex digest so the signing payload size is bounded.
        let logs_hash = hex::encode(Sha256::digest(self.logs.join("\n").as_bytes()));
        let mut payload = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            self.job_id,
            status_str,
            self.result_nonce,
            output_hash,
            self.execution_time_ms,
            // L-10: appended AT THE END per the wire-format stability rule.
            logs_hash,
            // L-11: appended AT THE END (after L-10) per the same rule.
            self.worker_id,
        );
        // R2 token ledger (2026-07-20): bind `llm_usage` ONLY when non-empty,
        // mirroring the `sealing != 0` conditional-append precedent on
        // JobRequest. A result with no LLM usage signs byte-identically to the
        // pre-R2 format (old workers / old messages verify unchanged); a
        // result that DOES carry usage commits to the sorted canonical entry
        // digest, so an on-wire tamperer can't inflate/deflate another
        // actor's token attribution without invalidating the signature.
        if let Some(usage_hash) = llm_usage_signing_hash(&self.llm_usage) {
            use std::fmt::Write as _;
            let _ = write!(payload, ":llm_usage:{usage_hash}");
        }
        payload.into_bytes()
    }

    /// Sign the result using the pre-shared `key`. **Back-compat wrapper —
    /// production worker code should call
    /// [`JobResult::sign_with_worker_id`] so the worker identity is bound
    /// into the signature.**
    ///
    /// Sets `self.signature` and `self.result_nonce`. The `worker_id`
    /// field is left untouched (empty by default), so the signed payload
    /// commits to an empty identity. Test fixtures that don't care about
    /// per-worker attribution use this path; the worker process must use
    /// `sign_with_worker_id`. A `lint-structural.sh` check rejects raw
    /// `.sign(` in the `worker/` tree to prevent regressions.
    pub fn sign(&mut self, key: &[u8]) -> Result<(), String> {
        self.sign_with_worker_id(key, "")
    }

    /// Sign the result and bind the worker's self-reported identity.
    ///
    /// `worker_id` is validated by [`validate_worker_id`] (charset
    /// `[A-Za-z0-9._-]{0,128}`); invalid ids fail closed before any HMAC
    /// is computed so a misconfigured worker can't accidentally publish a
    /// malformed-but-signed result.
    pub fn sign_with_worker_id(&mut self, key: &[u8], worker_id: &str) -> Result<(), String> {
        validate_worker_id(worker_id)?;
        self.worker_id = worker_id.to_string();
        self.sign_core(key)
    }

    /// Verify the HMAC signature and nonce freshness, *and* record the
    /// nonce in the process-local replay cache. Subsequent `verify()`
    /// calls against the same nonce within the freshness window will
    /// fail with `"result_nonce already seen"`.
    ///
    /// Use this at the **primary action point** for a result — the
    /// place where the message is converted into a side effect that
    /// would be wrong to apply twice. There must be EXACTLY ONE
    /// primary verifier per `JobResult` per controller process.
    /// Passive observers (e.g. an audit/DB-update subscriber that
    /// already runs downstream of the primary) MUST call
    /// [`verify_no_replay`](Self::verify_no_replay) instead — calling
    /// `verify()` from two consumers of the same signed result causes
    /// the second one to fail with a spurious replay error.
    pub fn verify(&self, key: &[u8], max_age_secs: u64) -> Result<(), String> {
        self.verify_core(key, max_age_secs)
    }

    /// L-4 typed verifier: dispatches to [`Self::verify`] for
    /// [`Verifier::Primary`] and [`Self::verify_no_replay`] for
    /// [`Verifier::Observer`]. New code should prefer this method —
    /// the role becomes explicit at the call site instead of being
    /// encoded only in the method name.
    pub fn verify_as(&self, key: &[u8], max_age_secs: u64, role: Verifier) -> Result<(), String> {
        match role {
            Verifier::Primary => self.verify(key, max_age_secs),
            Verifier::Observer => self.verify_no_replay(key, max_age_secs).map(|_| ()),
        }
    }

    /// Ring variant of [`Self::verify_as`]. The controller verifies worker
    /// results here; carrying the verify-ring lets a result signed under a
    /// staged previous key validate during a rolling `WORKER_SHARED_KEY`
    /// rotation. `Primary` records the nonce exactly once (after a key
    /// matches, via [`Self::verify_with_ring`]); `Observer` never touches the
    /// replay cache.
    pub fn verify_as_with_ring(
        &self,
        ring: &talos_workflow_engine_core::WorkerKeyRing,
        max_age_secs: u64,
        role: Verifier,
    ) -> Result<(), String> {
        match role {
            Verifier::Primary => self.verify_with_ring(ring, max_age_secs),
            Verifier::Observer => self
                .verify_no_replay_with_ring(ring, max_age_secs)
                .map(|_| ()),
        }
    }

    /// Ring variant of [`Self::verify`]: HMAC+freshness per ring member,
    /// nonce recorded exactly once after a match. See
    /// [`JobRequest::verify_with_ring`] for why this is loop-safe.
    pub fn verify_with_ring(
        &self,
        ring: &talos_workflow_engine_core::WorkerKeyRing,
        max_age_secs: u64,
    ) -> Result<(), String> {
        self.verify_with_ring_core(ring, max_age_secs)
    }

    /// Ring variant of [`Self::verify_no_replay`]: signing key first, then
    /// each staged previous key; first match wins, signing-key error if all
    /// fail. Touches no replay cache.
    pub fn verify_no_replay_with_ring(
        &self,
        ring: &talos_workflow_engine_core::WorkerKeyRing,
        max_age_secs: u64,
    ) -> Result<u64, String> {
        self.verify_no_replay_with_ring_core(ring, max_age_secs)
    }

    /// Verify HMAC signature and nonce freshness **without** recording
    /// the nonce in the replay cache. Returns the parsed timestamp on
    /// success, allowing the caller to chain a manual cache update if
    /// desired.
    ///
    /// Use this at **passive observer** call sites that consume a
    /// signed result already verified-with-replay-protection by some
    /// other primary verifier in the same process — e.g. a
    /// `talos.results.*` audit subscriber whose only side effect is an
    /// idempotent DB write. HMAC continues to gate forgery and the
    /// freshness window continues to gate stale-replay; replay
    /// protection is the responsibility of the primary verifier.
    ///
    /// **Security invariant**: there must be at least one primary
    /// `verify()` caller in the chain for any given result. If you're
    /// adding a NEW result-consumer and it's the only verifier in its
    /// chain, use `verify()` (not this method).
    pub fn verify_no_replay(&self, key: &[u8], max_age_secs: u64) -> Result<u64, String> {
        self.verify_no_replay_core(key, max_age_secs)
    }

    // ── RFC 0010 P2: per-worker Ed25519 result signing ────────────────────

    /// Sign under the worker's Ed25519 key (scheme 1) and bind `worker_id`.
    /// The controller verifies against the public key registered for that
    /// `worker_id`, so a compromised worker holding only its own private key can
    /// sign results only as itself. `worker_id` is validated (charset) and MUST
    /// be non-empty under Ed25519 — an empty id has no registered key to verify
    /// against.
    pub fn sign_ed25519_with_worker_id(
        &mut self,
        signing_key: &DispatchSigningKey,
        worker_id: &str,
    ) -> Result<(), String> {
        validate_worker_id(worker_id)?;
        if worker_id.is_empty() {
            return Err("Ed25519 result signing requires a non-empty worker_id".to_string());
        }
        self.worker_id = worker_id.to_string();
        self.crypto_scheme = CRYPTO_SCHEME_ED25519;
        self.sign_core_ed25519(signing_key)
    }

    /// **Primary** Ed25519 result verify (controller): freshness + signature
    /// against the worker's public key(s), then record the nonce (verify-once).
    pub fn verify_ed25519(
        &self,
        keys: &[DispatchVerifyingKey],
        max_age_secs: u64,
    ) -> Result<(), String> {
        self.verify_ed25519_core(keys, max_age_secs)
    }

    /// Observer Ed25519 result verify: freshness + signature only, no replay
    /// write. For passive audit subscribers (see the verify-once rule).
    pub fn verify_no_replay_ed25519(
        &self,
        keys: &[DispatchVerifyingKey],
        max_age_secs: u64,
    ) -> Result<u64, String> {
        self.verify_no_replay_ed25519_core(keys, max_age_secs)
    }

    /// Scheme-dispatching **primary** verify for the controller. Routes on
    /// `self.crypto_scheme`: Ed25519 against `worker_ed_keys` (the keys
    /// registered for `self.worker_id`), or legacy HMAC against `hmac_ring` when
    /// `accept_legacy_hmac` (the P4 flip refuses HMAC once the fleet is on
    /// Ed25519). Records the nonce exactly once. Use [`Verifier`] semantics via
    /// [`Self::verify_as`] for the HMAC path when you need Observer.
    pub fn verify_dispatch(
        &self,
        hmac_ring: &talos_workflow_engine_core::WorkerKeyRing,
        worker_ed_keys: &[DispatchVerifyingKey],
        max_age_secs: u64,
        accept_legacy_hmac: bool,
    ) -> Result<(), String> {
        match self.crypto_scheme {
            CRYPTO_SCHEME_ED25519 => self.verify_ed25519(worker_ed_keys, max_age_secs),
            CRYPTO_SCHEME_HMAC => {
                if !accept_legacy_hmac {
                    return Err(
                        "legacy HMAC result refused (Ed25519-only enforcement enabled)".to_string(),
                    );
                }
                self.verify_with_ring(hmac_ring, max_age_secs)
            }
            other => Err(format!("unknown result crypto_scheme: {other}")),
        }
    }

    /// Scheme-dispatching **Observer** verify (passive audit subscribers on
    /// `talos.results.*`): freshness + signature only, NEVER touching the
    /// process-local replay cache. Routes on `self.crypto_scheme` exactly like
    /// [`Self::verify_dispatch`] but uses the no-replay primitive on both arms,
    /// honouring the verify-once rule (the request-reply dispatcher is the sole
    /// Primary verifier). Use this at any site whose only side effect is an
    /// idempotent DB write.
    pub fn verify_no_replay_dispatch(
        &self,
        hmac_ring: &talos_workflow_engine_core::WorkerKeyRing,
        worker_ed_keys: &[DispatchVerifyingKey],
        max_age_secs: u64,
        accept_legacy_hmac: bool,
    ) -> Result<(), String> {
        match self.crypto_scheme {
            CRYPTO_SCHEME_ED25519 => self
                .verify_no_replay_ed25519(worker_ed_keys, max_age_secs)
                .map(|_| ()),
            CRYPTO_SCHEME_HMAC => {
                if !accept_legacy_hmac {
                    return Err(
                        "legacy HMAC result refused (Ed25519-only enforcement enabled)".to_string(),
                    );
                }
                self.verify_as_with_ring(hmac_ring, max_age_secs, Verifier::Observer)
            }
            other => Err(format!("unknown result crypto_scheme: {other}")),
        }
    }
}

impl SignedMessage for JobResult {
    const NONCE_LABEL: &'static str = "result_nonce";

    fn payload_bytes(&self) -> Vec<u8> {
        self.signing_payload()
    }
    fn nonce(&self) -> &str {
        &self.result_nonce
    }
    fn set_nonce(&mut self, nonce: String) {
        self.result_nonce = nonce;
    }
    fn signature(&self) -> &[u8] {
        &self.signature
    }
    fn set_signature(&mut self, signature: Vec<u8>) {
        self.signature = signature;
    }
}

// ============================================================================
// Pipeline job protocol
// ============================================================================

/// A single step in a pipeline job dispatched via NATS.
///
/// **Security invariant: no per-step LLM tier override.** The tier
/// ceiling applies uniformly to every step in a pipeline and is sourced
/// from `PipelineJobRequest::max_llm_tier`. Do NOT add a
/// `max_llm_tier` field here. Per-step tier granularity is precisely
/// the surface area we don't want — it would create a path where a
/// subtle refactor accidentally sets one step to Tier2 inside an
/// otherwise-Tier1 pipeline, leaking the data the pipeline was supposed
/// to keep local.
///
/// If a future requirement genuinely needs per-step tiering (e.g.
/// "step 1 enriches with public data via Anthropic, step 2 processes
/// private data locally"), the right shape is to split into two
/// pipelines with explicit hand-off — not to widen this struct. The
/// worker stamps `PipelineJobRequest::max_llm_tier` uniformly onto
/// every step's `TalosContext` (see `Runtime::execute_pipeline` at the
/// `context.max_llm_tier = max_llm_tier` line); a per-step override
/// would have to land there too, and breaking that single stamp is
/// where any tier-leak regression would show up.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineStep {
    pub module_id: Uuid,
    /// URI for the module (e.g. "redis:wasm:uuid" or "file://...")
    pub module_uri: String,
    /// Optional WASM module bytes for this step (overrides module_uri if provided).
    pub wasm_bytes: Option<Vec<u8>>,
    /// Module configuration (merged into input as `{"config": ..., "input": ...}`).
    pub config: serde_json::Value,
    pub allowed_hosts: Vec<String>,
    pub allowed_methods: Vec<String>,
    /// Secret allowlist. Empty = deny all. `["*"]` = allow all.
    #[serde(default)]
    pub allowed_secrets: Vec<String>,
    /// SQL operation allowlist. Empty = allow all.
    #[serde(default)]
    pub allowed_sql_operations: Vec<String>,
    /// When true, expose_secret (Tier-2) is allowed. Default: false.
    #[serde(default)]
    pub allow_tier2_exposure: bool,
    /// AES-256-GCM encrypted secret map for this step.
    pub encrypted_secrets: EncryptedSecrets,
    /// Maximum fuel (WASM instructions) for this step.
    pub max_fuel: u64,
    pub max_memory_mb: usize,
    /// Per-step timeout in milliseconds.
    pub timeout_ms: u64,

    /// Step priority (inherited from JobRequest if not set). Default: 100.
    #[serde(default = "default_priority")]
    pub priority: u8,

    /// Cancellation token for this step. Checked by the worker during execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancellation_token: Option<String>,

    /// Expected SHA-256 hex digest of the WASM binary at `module_uri`.
    ///
    /// Set by the controller from `wasm_modules.content_hash`.  When present
    /// and `wasm_bytes` is absent, the worker verifies the loaded bytes match
    /// before execution.  Included in the pipeline HMAC signing payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_wasm_hash: Option<String>,

    /// Integration this step's module belongs to. Same semantics as
    /// `JobRequest::integration_name`. Pipeline steps may belong to
    /// different integrations within one pipeline (rare but valid),
    /// so it's per-step rather than at the pipeline level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integration_name: Option<String>,

    /// Per-step retry ceiling for TRANSIENT application failures,
    /// executed IN-WORKER by `execute_pipeline`'s step loop (the
    /// pipeline claims its sealed secrets once per dispatch; in-worker
    /// step retries reuse the already-claimed material, so no re-claim
    /// races). 0 = no retries — the historical behavior and the serde
    /// default, so legacy senders/readers are unaffected. The worker's
    /// transient-error classifier still gates every retry on top of
    /// this ceiling (auth/fuel/validation failures never re-run).
    /// HMAC-bound via the conditional `:retries=` signing segment.
    #[serde(default, skip_serializing_if = "is_default_u32")]
    pub max_retries: u32,
    /// Base backoff between step retry attempts in milliseconds
    /// (exponential growth + jitter applied by the worker). 0 = use
    /// the worker's default. Signed alongside `max_retries`.
    #[serde(default, skip_serializing_if = "is_default_u64")]
    pub retry_backoff_ms: u64,
}

/// A pipeline job dispatched by the Controller to a Worker via NATS.
///
/// The signing payload covers the job identity, step count, WASM integrity hashes,
/// and nonce — making it impossible for an attacker to add/remove/replace steps
/// without invalidating the signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineJobRequest {
    pub job_id: Uuid,
    pub workflow_execution_id: Uuid,
    pub steps: Vec<PipelineStep>,
    /// Total timeout for the entire pipeline in milliseconds.
    pub total_timeout_ms: u64,
    /// If true, all steps share a single ephemeral filesystem sandbox.
    pub share_sandbox: bool,
    /// HMAC-SHA256 signature over the canonical pipeline fields.
    pub signature: Vec<u8>,
    /// Nonce for replay-attack prevention: `"{unix_secs}:{random_hex}"`.
    pub job_nonce: String,
    /// User ID for global rate limiting and audit logging.
    pub user_id: Uuid,

    /// LLM data-egress ceiling — MUST match the owning workflow's
    /// actor's `max_llm_tier`. Worker stamps this into every step's
    /// `TalosContext` before execution so each pipeline step enforces
    /// the same tier gate as a single-node JobRequest.
    ///
    /// HMAC-bound via the signing payload (appended at end per the
    /// wire-format stability rule). `#[serde(default)]` for backward
    /// compat with older controllers — deserialized as Tier2 which
    /// matches pre-feature behavior for unrestricted actors.
    #[serde(default)]
    pub max_llm_tier: LlmTier,

    /// Data-mutation ceiling — MUST match the owning workflow's actor's
    /// `max_write_ceiling`. The worker stamps this into every step's
    /// `TalosContext` so each pipeline step enforces the same write gate as
    /// a single-node JobRequest. HMAC-bound (appended at end). `Write`
    /// default for backward compat with older controllers.
    #[serde(default)]
    pub max_write_ceiling: WriteCeiling,

    /// Blanket network-egress scope override, stamped uniformly onto every
    /// pipeline step (mirrors `max_llm_tier` / `max_write_ceiling`). `None`
    /// (default) falls back to the tier-derived default. HMAC-bound only when
    /// `Some` so default messages stay byte-identical. See [`EgressScope`] and
    /// [`JobRequest::egress_scope`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_scope: Option<EgressScope>,

    /// H-1: signed reply-inbox commitment. Same semantics as
    /// [`JobRequest::reply_topic`] — the worker MUST publish its
    /// `PipelineJobResult` to this exact NATS subject when set,
    /// regardless of `msg.reply`. `None` falls back to the legacy
    /// trust-msg.reply path. HMAC-bound at the end of the signing
    /// payload (wire-format stability rule).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_topic: Option<String>,

    /// RFC 0010 P1: signature scheme (see [`JobRequest::crypto_scheme`]).
    /// [`CRYPTO_SCHEME_HMAC`] (0, default) or [`CRYPTO_SCHEME_ED25519`] (1).
    #[serde(default)]
    pub crypto_scheme: u8,

    /// RFC 0010 P3 (D3b): secret-delivery scheme (see [`JobRequest::sealing`]).
    /// Bound into `signing_payload()` only when non-zero; omitted from wire JSON
    /// when 0 so a legacy pipeline message is byte-identical.
    #[serde(default, skip_serializing_if = "sealing_is_default")]
    pub sealing: u8,

    /// RFC 0010 P3: vault paths this pipeline is permitted to resolve when
    /// `sealing == SEALING_CLAIM_ECIES`. See [`JobRequest::secret_paths`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secret_paths: Vec<String>,

    /// RFC 0010 P3 (D3b): the subject the worker sends its `SecretClaim` to
    /// (the controller replica's claim-responder inbox) when
    /// `sealing == SEALING_CLAIM_ECIES`. The claim delivers ONE sealed payload —
    /// a per-step `Vec<HashMap<String,String>>` aligned to `steps` — so the whole
    /// pipeline is a single claim round-trip. Bound into `signing_payload()` when
    /// sealing is non-zero (same reasoning as [`JobRequest::claim_inbox`]); omitted
    /// from wire JSON when `None` so a legacy pipeline message is byte-identical.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_inbox: Option<String>,
}

impl PipelineJobRequest {
    /// Canonical signing payload.
    ///
    /// Format:
    /// `pipeline:{job_id}:{wex_id}:{nonce}:{total_timeout_ms}:{share_sandbox}:
    ///  {num_steps}:{user_id}:{sha256(step0_wasm)}:{sha256(step1_wasm)}:...`
    #[allow(clippy::too_many_lines)] // canonical signing payload — one linear format!
    fn signing_payload(&self) -> Vec<u8> {
        use sha2::Digest;

        let step_hashes: Vec<String> = self
            .steps
            .iter()
            .map(|s| {
                if let Some(b) = s.wasm_bytes.as_deref() {
                    // Inline bytes: hash the actual content.
                    hex::encode(Sha256::digest(b))
                } else if let Some(ref h) = s.expected_wasm_hash {
                    // No inline bytes but controller committed to a content hash.
                    h.clone()
                } else {
                    // No hash commitment: fall back to URI (unchanged legacy behavior).
                    hex::encode(Sha256::digest(s.module_uri.as_bytes()))
                }
            })
            .collect();

        // Per-step integration_name commitment. Same reasoning as
        // JobRequest::signing_payload — a NATS-channel tamperer could
        // otherwise swap a step's integration_name and redirect that
        // step's integration_state writes into a different namespace.
        // Sentinel "-" for non-integration steps (distinct from empty).
        //
        // Wire-format stability: appended at the END of the format
        // string — safe during coordinated deploys; reordering would
        // break every deployed pipeline signature.
        let step_integrations: Vec<&str> = self
            .steps
            .iter()
            .map(|s| s.integration_name.as_deref().unwrap_or("-"))
            .collect();

        // M-5 (pipeline): per-step capability grants. Each step can
        // carry its own allowlists; bind all of them so a NATS-channel
        // attacker can't widen `allowed_secrets` or flip
        // `allow_tier2_exposure` on a single step without invalidating
        // the whole pipeline signature.
        //
        // Encoded as `step0_secrets|step0_sql|step0_tier2 ;; step1_…`
        // with length-prefixed segments so concatenation can't collide
        // across step boundaries.
        let step_caps: Vec<String> = self
            .steps
            .iter()
            .map(|s| {
                let mut secrets = s.allowed_secrets.clone();
                secrets.sort_unstable();
                let secrets_str = secrets.join(",");
                let mut sql = s.allowed_sql_operations.clone();
                sql.sort_unstable();
                let sql_str = sql.join(",");
                format!(
                    "{}:{}|{}:{}|{}",
                    secrets_str.len(),
                    secrets_str,
                    sql_str.len(),
                    sql_str,
                    s.allow_tier2_exposure,
                )
            })
            .collect();
        let step_caps_str = step_caps.join(";;");

        // L-9 (pipeline): length-prefix the user-controlled string
        // segments so internal `:` / `,` characters can't cause
        // payload-collisions. Existing fixed-width fields stay
        // unchanged. (`lp` is the module-level length-prefix helper.)
        let step_hashes_joined = step_hashes.join(":");
        let step_integrations_joined = step_integrations.join(",");

        // H-1 (pipeline): reply_topic — same semantics as JobRequest.
        let reply_topic_str = self.reply_topic.as_deref().unwrap_or("-");

        // C-2 (2026-05-23, critical fix): per-step policy commitment.
        //
        // Pre-fix `PipelineJobRequest::signing_payload` bound the
        // wasm-integrity hash + integration_name + capability grants per
        // step, plus job-level fields (user, tier, reply_topic). It did
        // NOT bind any of `config` (the step input!), `allowed_hosts`,
        // `allowed_methods`, `encrypted_secrets.{ciphertext,nonce}`,
        // `max_fuel`, `max_memory_mb`, `timeout_ms`, `priority`,
        // `cancellation_token`. Anyone with NATS publish on the pipeline
        // subject could:
        //   - rewrite a step's config — the signed-and-attested module
        //     executes attacker-supplied input under signed secrets;
        //   - widen `allowed_hosts` / `allowed_methods` to exfiltrate
        //     via attacker-controlled URL + still-signed `vault://`
        //     header;
        //   - swap one step's `encrypted_secrets.ciphertext` for
        //     another's (engine.rs uses `workflow_execution_id` as AAD,
        //     which is shared across steps — both blobs are decryptable
        //     by the worker for this pipeline);
        //   - inflate `max_fuel` / `max_memory_mb` / `timeout_ms` for
        //     resource exhaustion;
        //   - strip `cancellation_token` to keep an in-flight pipeline
        //     uncancellable;
        //   - promote `priority` for queue-jumping.
        //
        // The fix mirrors the single-node `JobRequest::signing_payload`
        // shape: hash each variable-length field (input / secrets) to
        // fixed-width hex, length-prefix the string-valued segments
        // (sorted hosts / methods, cancellation_token), and encode the
        // u8/u64 numerics as decimal. Steps are separated by `;;` (the
        // same separator already used by `step_caps_str`) and each
        // intra-step field by `|`.
        let step_policies: Vec<String> = self
            .steps
            .iter()
            .map(|s| {
                let config_hash = hex::encode(Sha256::digest(s.config.to_string().as_bytes()));
                let secrets_ct_hash = hex::encode(Sha256::digest(&s.encrypted_secrets.ciphertext));
                let mut hosts = s.allowed_hosts.clone();
                hosts.sort_unstable();
                let hosts_str = hosts.join(",");
                let mut methods = s.allowed_methods.clone();
                methods.sort_unstable();
                let methods_str = methods.join(",");
                let cancellation_token_str = s.cancellation_token.as_deref().unwrap_or("-");
                // Length-prefix every user-controlled string so a `|`
                // or `;;` inside a field cannot collide with the inter-
                // field / inter-step separator.
                //
                // Field order (positional, do not reorder — this is
                // wire-format-stable from this revision forward):
                //   1. config_hash               (64-char hex)
                //   2. secrets_ct_hash           (64-char hex)
                //   3. lp(hosts_str)             (length-prefixed)
                //   4. lp(methods_str)           (length-prefixed)
                //   5. max_fuel                  (u64 decimal)
                //   6. max_memory_mb             (usize decimal)
                //   7. timeout_ms                (u64 decimal)
                //   8. priority                  (u8 decimal)
                //   9. lp(cancellation_token)    (length-prefixed)
                format!(
                    "{}|{}|{}|{}|{}|{}|{}|{}|{}",
                    config_hash,
                    secrets_ct_hash,
                    lp(&hosts_str),
                    lp(&methods_str),
                    s.max_fuel,
                    s.max_memory_mb,
                    s.timeout_ms,
                    s.priority,
                    lp(cancellation_token_str),
                )
            })
            .collect();
        let step_policies_str = step_policies.join(";;");

        let mut payload = format!(
            "pipeline:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
            self.job_id,
            self.workflow_execution_id,
            self.job_nonce,
            self.total_timeout_ms,
            self.share_sandbox,
            self.steps.len(),
            self.user_id,
            // step_hashes is fixed-width hex per element joined by `:`,
            // length-prefix the joined form so the boundary against the
            // next segment is unambiguous.
            lp(&step_hashes_joined),
            lp(&step_integrations_joined),
            // Appended AT THE END per the wire-format stability rule
            // (same reasoning as `JobRequest::signing_payload`). A
            // tamperer on the wire can't downgrade a tier-1 pipeline
            // to tier-2 without invalidating the signature.
            self.max_llm_tier.as_signing_str(),
            // M-5 (pipeline): per-step capability grants appended AT THE END.
            lp(&step_caps_str),
            // H-1 (pipeline): reply_topic appended AT THE END.
            lp(reply_topic_str),
            // C-2 (2026-05-23): per-step policy (config, hosts, methods,
            // secrets ciphertext, fuel/mem/timeout, priority,
            // cancellation_token) appended AT THE END per the
            // wire-format stability rule.
            lp(&step_policies_str),
            // Write-ceiling appended AT THE END (same reasoning as
            // `JobRequest::signing_payload`). A tamperer can't upgrade a
            // `readonly` pipeline to `write` without invalidating the signature.
            self.max_write_ceiling.as_signing_str(),
        );

        // Egress-scope override appended AT THE END, ONLY when `Some`, per the
        // wire-format stability rule — `None` appends nothing so default
        // messages stay byte-identical. HMAC-bound against `public`↔`local`
        // tampering. Mirrors `JobRequest::signing_payload`.
        if let Some(scope) = self.egress_scope {
            use std::fmt::Write as _;
            let _ = write!(payload, ":egress={}", scope.as_signing_str());
        }

        // RFC 0010 P3 (D3b): bind `sealing` + `secret_paths` ONLY when a
        // non-legacy sealing scheme is in effect, so `sealing == 0` bytes stay
        // byte-identical to the pre-P3 wire format. See
        // `JobRequest::signing_payload` for the downgrade-resistance reasoning.
        if self.sealing != 0 {
            use std::fmt::Write as _;
            let mut paths = self.secret_paths.clone();
            paths.sort_unstable();
            // Bind claim_inbox too (the worker sends its ephemeral-key-bearing
            // claim here — a tamperer must not redirect it). Appended after
            // sealing/secret_paths, still inside the `sealing != 0` guard so
            // legacy bytes are unchanged.
            let _ = write!(
                payload,
                ":{}:{}:{}",
                self.sealing,
                lp(&paths.join(",")),
                lp(self.claim_inbox.as_deref().unwrap_or("-")),
            );
        }

        // Per-step retry policy (2026-07-24) appended AT THE END, ONLY when
        // any step carries a non-zero value, so all-zero (legacy) pipelines
        // stay byte-identical. Binding matters in both directions: a
        // tamperer bumping `max_retries` amplifies side-effect re-fires and
        // worker load; zeroing it silently strips an operator's declared
        // resilience. Fixed-width decimals joined per step — no
        // length-prefix needed for pure numerics.
        if self
            .steps
            .iter()
            .any(|s| s.max_retries != 0 || s.retry_backoff_ms != 0)
        {
            use std::fmt::Write as _;
            let step_retries: Vec<String> = self
                .steps
                .iter()
                .map(|s| format!("{}|{}", s.max_retries, s.retry_backoff_ms))
                .collect();
            let _ = write!(payload, ":retries={}", step_retries.join(";;"));
        }

        payload.into_bytes()
    }

    /// Sign the pipeline request using the pre-shared `key`.
    pub fn sign(&mut self, key: &[u8]) -> Result<(), String> {
        self.sign_core(key)
    }

    /// Verify the HMAC signature and nonce freshness, *and* record the
    /// nonce in the process-local replay cache. See `JobRequest::verify`
    /// for the architectural-mandate rationale (CLAUDE.md "Verify-once
    /// rule"). Pair with [`verify_no_replay`](Self::verify_no_replay)
    /// for passive observers.
    pub fn verify(&self, key: &[u8], max_age_secs: u64) -> Result<(), String> {
        self.verify_core(key, max_age_secs)
    }

    /// Ring variant of [`Self::verify`]: HMAC+freshness per ring member,
    /// `job_nonce` recorded exactly once after a match. See
    /// [`JobRequest::verify_with_ring`] for the loop-safety rationale.
    pub fn verify_with_ring(
        &self,
        ring: &talos_workflow_engine_core::WorkerKeyRing,
        max_age_secs: u64,
    ) -> Result<(), String> {
        self.verify_with_ring_core(ring, max_age_secs)
    }

    /// Ring variant of [`Self::verify_no_replay`]: signing key first, then
    /// each staged previous key; first match wins. Touches no replay cache.
    pub fn verify_no_replay_with_ring(
        &self,
        ring: &talos_workflow_engine_core::WorkerKeyRing,
        max_age_secs: u64,
    ) -> Result<u64, String> {
        self.verify_no_replay_with_ring_core(ring, max_age_secs)
    }

    /// Verify HMAC + freshness WITHOUT touching the replay cache.
    /// 2026-05-28 audit F5 sibling of `JobRequest::verify_no_replay` —
    /// passive observers (metrics, audit subscribers) MUST use this
    /// to avoid dual-cache-insert deadlocks.
    pub fn verify_no_replay(&self, key: &[u8], max_age_secs: u64) -> Result<u64, String> {
        self.verify_no_replay_core(key, max_age_secs)
    }

    // ── RFC 0010 P1: Ed25519 dispatch scheme (mirror of JobRequest) ────────

    /// Sign under the Ed25519 dispatch scheme. See [`JobRequest::sign_ed25519`].
    pub fn sign_ed25519(&mut self, signing_key: &DispatchSigningKey) -> Result<(), String> {
        self.crypto_scheme = CRYPTO_SCHEME_ED25519;
        self.sign_core_ed25519(signing_key)
    }

    /// Primary Ed25519 verify. See [`JobRequest::verify_ed25519`].
    pub fn verify_ed25519(
        &self,
        keys: &[DispatchVerifyingKey],
        max_age_secs: u64,
    ) -> Result<(), String> {
        self.verify_ed25519_core(keys, max_age_secs)
    }

    /// Observer Ed25519 verify. See [`JobRequest::verify_no_replay_ed25519`].
    pub fn verify_no_replay_ed25519(
        &self,
        keys: &[DispatchVerifyingKey],
        max_age_secs: u64,
    ) -> Result<u64, String> {
        self.verify_no_replay_ed25519_core(keys, max_age_secs)
    }

    /// Scheme-dispatching primary verify. See [`JobRequest::verify_dispatch`].
    pub fn verify_dispatch(
        &self,
        hmac_ring: &talos_workflow_engine_core::WorkerKeyRing,
        ed_keys: &[DispatchVerifyingKey],
        max_age_secs: u64,
        accept_legacy_hmac: bool,
    ) -> Result<(), String> {
        match self.crypto_scheme {
            CRYPTO_SCHEME_ED25519 => self.verify_ed25519(ed_keys, max_age_secs),
            CRYPTO_SCHEME_HMAC => {
                if !accept_legacy_hmac {
                    return Err(
                        "legacy HMAC dispatch refused (Ed25519-only enforcement enabled)"
                            .to_string(),
                    );
                }
                self.verify_with_ring(hmac_ring, max_age_secs)
            }
            other => Err(format!("unknown dispatch crypto_scheme: {other}")),
        }
    }
}

impl SignedMessage for PipelineJobRequest {
    const NONCE_LABEL: &'static str = "job_nonce";

    fn payload_bytes(&self) -> Vec<u8> {
        self.signing_payload()
    }
    fn nonce(&self) -> &str {
        &self.job_nonce
    }
    fn set_nonce(&mut self, nonce: String) {
        self.job_nonce = nonce;
    }
    fn signature(&self) -> &[u8] {
        &self.signature
    }
    fn set_signature(&mut self, signature: Vec<u8>) {
        self.signature = signature;
    }
}

/// Per-step result within a `PipelineJobResult`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineStepResult {
    pub module_id: Uuid,
    pub status: JobStatus,
    pub output: serde_json::Value,
    pub execution_time_ms: u64,
    pub error: Option<String>,
}

/// Result of a pipeline job returned by the Worker via NATS.
///
/// **Verify-once invariant** (mirrors [`JobResult`]). A signed
/// `PipelineJobResult` MUST be `verify()`-ed exactly once per
/// controller process at its **primary action point** — the site
/// where the result becomes a durable side effect that would be
/// wrong to apply twice (the dispatcher's result-handling path).
/// Any passive observer (audit subscriber, metrics emitter,
/// idempotent-DB-write subscriber, etc.) MUST use
/// [`verify_no_replay`](Self::verify_no_replay) instead.
///
/// Reason: `verify()` mutates the process-local `JOB_NONCE_CACHE` to
/// reject the same nonce on subsequent calls. Two `verify()` calls
/// against the same signed message land in the same shared cache —
/// the second deterministically fails with
/// `"result_nonce already seen"`. This is the same regression class
/// that broke `JobResult` in r300/r301 (see CLAUDE.md "Verify-once
/// rule for signed NATS messages"); adding the split API to
/// `PipelineJobResult` up front is the prophylactic — cheap when the
/// type is born, total when a second subscriber slips in later.
///
/// The worker MUST single-publish each `PipelineJobResult` to ONE
/// NATS subject (reply inbox OR audit topic, branched on `reply_topic`
/// presence). Dual-publishing primes the cache race even when both
/// consumers correctly use the split API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineJobResult {
    pub job_id: Uuid,
    pub overall_status: JobStatus,
    pub step_results: Vec<PipelineStepResult>,
    pub final_output: serde_json::Value,
    pub total_time_ms: u64,
    /// HMAC-SHA256 signature over the canonical result fields.
    pub signature: Vec<u8>,
    /// Nonce for replay prevention.
    pub result_nonce: String,
    /// Self-reported worker identity, HMAC-bound by
    /// [`PipelineJobResult::sign_with_worker_id`]. See [`JobResult::worker_id`]
    /// for the security rationale — same model for both result types.
    #[serde(default)]
    pub worker_id: String,

    /// RFC 0010 P2: signature scheme (see [`JobResult::crypto_scheme`]).
    #[serde(default)]
    pub crypto_scheme: u8,

    /// Per-`(provider, model)` LLM token usage for the WHOLE pipeline
    /// (accumulated across steps). Same contract as [`JobResult::llm_usage`]:
    /// empty when no LLM calls happened, bound into the signing payload only
    /// when non-empty (append-at-end), capped at [`MAX_LLM_USAGE_ENTRIES`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub llm_usage: Vec<LlmUsageEntry>,
}

impl PipelineJobResult {
    /// Canonical signing payload.
    ///
    /// Format:
    /// `pipeline_result:{job_id}:{overall_status}:{result_nonce}:
    ///  {total_time_ms}:{sha256(final_output_json)}:{sha256(canonical_step_results)}`
    ///
    /// L-10 (analog): per-step results are now bound. Pre-fix only the
    /// final_output was hashed; an attacker tampering with step outputs
    /// or error strings could mislead audit/error-reporting without
    /// invalidating the signature. Each step contributes
    /// `module_id|status|sha256(output_json)|sha256(error)` (sentinel
    /// "none" for missing error). Joined with `\n` then SHA-256'd to
    /// keep the payload size bounded regardless of step count.
    fn signing_payload(&self) -> Vec<u8> {
        use sha2::Digest;
        let status_str = match self.overall_status {
            JobStatus::Success => "success",
            JobStatus::Failed => "failed",
            JobStatus::TimedOut => "timedout",
        };
        let output_hash = hex::encode(Sha256::digest(self.final_output.to_string().as_bytes()));

        // Canonical per-step digest: each step contributes a fixed-shape
        // line; the complete sequence is hashed once.
        let step_digests: Vec<String> = self
            .step_results
            .iter()
            .map(|s| {
                let s_status = match s.status {
                    JobStatus::Success => "success",
                    JobStatus::Failed => "failed",
                    JobStatus::TimedOut => "timedout",
                };
                let s_output = hex::encode(Sha256::digest(s.output.to_string().as_bytes()));
                let s_error = match s.error.as_deref() {
                    Some(e) => hex::encode(Sha256::digest(e.as_bytes())),
                    None => "none".to_string(),
                };
                format!("{}|{}|{}|{}", s.module_id, s_status, s_output, s_error)
            })
            .collect();
        let step_results_hash = hex::encode(Sha256::digest(step_digests.join("\n").as_bytes()));

        let mut payload = format!(
            "pipeline_result:{}:{}:{}:{}:{}:{}:{}",
            self.job_id,
            status_str,
            self.result_nonce,
            self.total_time_ms,
            output_hash,
            // Appended AT THE END per the wire-format stability rule.
            step_results_hash,
            // L-11 (2026-05-22): worker_id appended AT THE END (after the
            // step-results hash) per the same rule. See
            // [`JobResult::signing_payload`] for the full rationale.
            self.worker_id,
        );
        // R2 token ledger (2026-07-20): conditional append-at-end, mirroring
        // [`JobResult::signing_payload`]. Empty usage = pre-R2 bytes.
        if let Some(usage_hash) = llm_usage_signing_hash(&self.llm_usage) {
            use std::fmt::Write as _;
            let _ = write!(payload, ":llm_usage:{usage_hash}");
        }
        payload.into_bytes()
    }

    /// Sign the pipeline result using the pre-shared `key`. **Back-compat
    /// wrapper — production worker code should call
    /// [`PipelineJobResult::sign_with_worker_id`] so the worker identity
    /// is bound into the signature.** See [`JobResult::sign`] for the
    /// matching contract on single-node results.
    pub fn sign(&mut self, key: &[u8]) -> Result<(), String> {
        self.sign_with_worker_id(key, "")
    }

    /// Sign the pipeline result and bind the worker's self-reported
    /// identity. Mirror of [`JobResult::sign_with_worker_id`] — same
    /// charset validation, same fail-closed-on-invalid-id contract.
    pub fn sign_with_worker_id(&mut self, key: &[u8], worker_id: &str) -> Result<(), String> {
        validate_worker_id(worker_id)?;
        self.worker_id = worker_id.to_string();
        self.sign_core(key)
    }

    /// Verify the HMAC signature, nonce freshness, *and* record the
    /// nonce in the process-local replay cache.
    ///
    /// See [`JobResult::verify`] for the full primary/observer
    /// contract — same rules apply: exactly one primary verifier per
    /// `PipelineJobResult` per controller process. Passive observers
    /// (audit subscribers, metrics emitters) MUST use
    /// [`PipelineJobResult::verify_no_replay`] to avoid the
    /// dual-verify race that broke `JobResult` pre-r300. Today
    /// pipeline results have only one verifier (the engine
    /// dispatcher), so the bug is latent — this API split makes the
    /// safe option available BEFORE a future second consumer is
    /// added, not after the same regression hits production.
    pub fn verify(&self, key: &[u8], max_age_secs: u64) -> Result<(), String> {
        self.verify_core(key, max_age_secs)
    }

    /// L-4 typed verifier — same dispatch as
    /// [`JobResult::verify_as`]. Use this method in new code.
    pub fn verify_as(&self, key: &[u8], max_age_secs: u64, role: Verifier) -> Result<(), String> {
        match role {
            Verifier::Primary => self.verify(key, max_age_secs),
            Verifier::Observer => self.verify_no_replay(key, max_age_secs).map(|_| ()),
        }
    }

    /// Ring variant of [`Self::verify_as`] — see
    /// [`JobResult::verify_as_with_ring`]. Lets a pipeline result signed
    /// under a staged previous key validate during a rolling rotation.
    pub fn verify_as_with_ring(
        &self,
        ring: &talos_workflow_engine_core::WorkerKeyRing,
        max_age_secs: u64,
        role: Verifier,
    ) -> Result<(), String> {
        match role {
            Verifier::Primary => self.verify_with_ring(ring, max_age_secs),
            Verifier::Observer => self
                .verify_no_replay_with_ring(ring, max_age_secs)
                .map(|_| ()),
        }
    }

    /// Ring variant of [`Self::verify`]: `result_nonce` recorded exactly once
    /// after a ring member matches.
    pub fn verify_with_ring(
        &self,
        ring: &talos_workflow_engine_core::WorkerKeyRing,
        max_age_secs: u64,
    ) -> Result<(), String> {
        self.verify_with_ring_core(ring, max_age_secs)
    }

    /// Ring variant of [`Self::verify_no_replay`]: signing key first, then
    /// each staged previous key. Touches no replay cache.
    pub fn verify_no_replay_with_ring(
        &self,
        ring: &talos_workflow_engine_core::WorkerKeyRing,
        max_age_secs: u64,
    ) -> Result<u64, String> {
        self.verify_no_replay_with_ring_core(ring, max_age_secs)
    }

    /// Verify HMAC signature and nonce freshness without recording the
    /// nonce in the replay cache. Returns the parsed timestamp on
    /// success.
    ///
    /// See [`JobResult::verify_no_replay`] for the security contract.
    /// HMAC continues to gate forgery; freshness continues to gate
    /// stale-replay; within-window-replay protection is the
    /// responsibility of the primary `verify()` caller.
    ///
    /// (Historical note: pre-refactor this type alone validated the
    /// nonce's hex component before parsing its timestamp; the shared
    /// core now checks timestamp-first like every other message type.
    /// Only the error-string *selection* for a nonce malformed in both
    /// ways at once differs — every accept/reject outcome is identical.)
    pub fn verify_no_replay(&self, key: &[u8], max_age_secs: u64) -> Result<u64, String> {
        self.verify_no_replay_core(key, max_age_secs)
    }

    // ── RFC 0010 P2: per-worker Ed25519 result signing (mirror of JobResult) ──

    /// Sign under the worker's Ed25519 key + bind `worker_id`. See
    /// [`JobResult::sign_ed25519_with_worker_id`].
    pub fn sign_ed25519_with_worker_id(
        &mut self,
        signing_key: &DispatchSigningKey,
        worker_id: &str,
    ) -> Result<(), String> {
        validate_worker_id(worker_id)?;
        if worker_id.is_empty() {
            return Err("Ed25519 result signing requires a non-empty worker_id".to_string());
        }
        self.worker_id = worker_id.to_string();
        self.crypto_scheme = CRYPTO_SCHEME_ED25519;
        self.sign_core_ed25519(signing_key)
    }

    /// Primary Ed25519 result verify. See [`JobResult::verify_ed25519`].
    pub fn verify_ed25519(
        &self,
        keys: &[DispatchVerifyingKey],
        max_age_secs: u64,
    ) -> Result<(), String> {
        self.verify_ed25519_core(keys, max_age_secs)
    }

    /// Observer Ed25519 result verify. See [`JobResult::verify_no_replay_ed25519`].
    pub fn verify_no_replay_ed25519(
        &self,
        keys: &[DispatchVerifyingKey],
        max_age_secs: u64,
    ) -> Result<u64, String> {
        self.verify_no_replay_ed25519_core(keys, max_age_secs)
    }

    /// Scheme-dispatching primary verify. See [`JobResult::verify_dispatch`].
    pub fn verify_dispatch(
        &self,
        hmac_ring: &talos_workflow_engine_core::WorkerKeyRing,
        worker_ed_keys: &[DispatchVerifyingKey],
        max_age_secs: u64,
        accept_legacy_hmac: bool,
    ) -> Result<(), String> {
        match self.crypto_scheme {
            CRYPTO_SCHEME_ED25519 => self.verify_ed25519(worker_ed_keys, max_age_secs),
            CRYPTO_SCHEME_HMAC => {
                if !accept_legacy_hmac {
                    return Err(
                        "legacy HMAC result refused (Ed25519-only enforcement enabled)".to_string(),
                    );
                }
                self.verify_with_ring(hmac_ring, max_age_secs)
            }
            other => Err(format!("unknown result crypto_scheme: {other}")),
        }
    }
}

impl SignedMessage for PipelineJobResult {
    const NONCE_LABEL: &'static str = "result_nonce";

    fn payload_bytes(&self) -> Vec<u8> {
        self.signing_payload()
    }
    fn nonce(&self) -> &str {
        &self.result_nonce
    }
    fn set_nonce(&mut self, nonce: String) {
        self.result_nonce = nonce;
    }
    fn signature(&self) -> &[u8] {
        &self.signature
    }
    fn set_signature(&mut self, signature: Vec<u8>) {
        self.signature = signature;
    }
}

// ============================================================================
// Worker heartbeat
// ============================================================================

/// Heartbeat message published by workers so the controller can track fleet health.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerHeartbeat {
    pub worker_id: Uuid,
    /// Self-reported capabilities (e.g. ["wasm", "gpu", "network"]).
    pub capabilities: Vec<String>,
    /// Current CPU usage as a percentage (0.0 – 100.0).
    pub cpu_usage_pct: f32,
    /// HMAC-SHA256 signature for tamper detection.
    #[serde(default)]
    pub signature: Vec<u8>,
    /// Nonce for replay prevention: `"{unix_secs}:{random_hex}"`.
    #[serde(default)]
    pub heartbeat_nonce: String,
}

impl WorkerHeartbeat {
    /// Canonical signing payload — includes capabilities to prevent forgery.
    fn signing_payload(&self) -> Vec<u8> {
        format!(
            "heartbeat:{}:{}:{}:{}",
            self.worker_id,
            self.heartbeat_nonce,
            self.cpu_usage_pct,
            self.capabilities.join(","),
        )
        .into_bytes()
    }

    /// Sign the heartbeat using the pre-shared `key`.
    pub fn sign(&mut self, key: &[u8]) -> Result<(), String> {
        self.sign_core(key)
    }

    /// Verify the HMAC signature and nonce freshness, *and* record
    /// the nonce in the process-local replay cache. See
    /// `JobRequest::verify` for the architectural-mandate rationale
    /// (CLAUDE.md "Verify-once rule"). Pair with
    /// [`verify_no_replay`](Self::verify_no_replay) for passive observers.
    pub fn verify(&self, key: &[u8], max_age_secs: u64) -> Result<(), String> {
        self.verify_core(key, max_age_secs)
    }

    /// Verify HMAC + freshness WITHOUT touching the replay cache.
    /// 2026-05-28 audit F5 sibling of `JobRequest::verify_no_replay`.
    pub fn verify_no_replay(&self, key: &[u8], max_age_secs: u64) -> Result<u64, String> {
        self.verify_no_replay_core(key, max_age_secs)
    }
}

impl SignedMessage for WorkerHeartbeat {
    const NONCE_LABEL: &'static str = "heartbeat_nonce";

    fn payload_bytes(&self) -> Vec<u8> {
        self.signing_payload()
    }
    fn nonce(&self) -> &str {
        &self.heartbeat_nonce
    }
    fn set_nonce(&mut self, nonce: String) {
        self.heartbeat_nonce = nonce;
    }
    fn signature(&self) -> &[u8] {
        &self.signature
    }
    fn set_signature(&mut self, signature: Vec<u8>) {
        self.signature = signature;
    }
}

// ============================================================================
// Shared-key helper
// ============================================================================

/// Decode the `WORKER_SHARED_KEY` environment variable (64 hex chars → 32 bytes)
/// and return it wrapped in a [`WorkerSharedKey`].
///
/// Both the controller and the worker must call this at startup and fail-fast
/// if the key is absent or malformed.
///
/// # Key rotation
///
/// This returns only the **signing** key. For restart-free rotation, prefer
/// [`load_worker_key_ring`], which additionally loads `WORKER_SHARED_KEY_PREVIOUS`
/// and accepts signatures made under previous keys during a rolling restart.
/// `load_worker_shared_key` is retained for call sites that only ever *sign*
/// (they always use the current key) and for backward compatibility.
///
/// Historically this loader documented that rotation *required a simultaneous
/// restart*, because a bare single-key `OnceLock` rejects every signature made
/// under a different key. See [`WorkerKeyRing`] for why a verify-ring lifts
/// that constraint without a wire-format change or key-ID negotiation.
///
/// [`WorkerSharedKey`]: talos_workflow_engine_core::WorkerSharedKey
/// [`WorkerKeyRing`]: talos_workflow_engine_core::WorkerKeyRing
pub fn load_worker_shared_key() -> Result<talos_workflow_engine_core::WorkerSharedKey, String> {
    // Support Docker secrets via WORKER_SHARED_KEY_FILE in addition to direct env var
    let hex_key = std::env::var("WORKER_SHARED_KEY")
        .ok()
        .or_else(|| {
            std::env::var("WORKER_SHARED_KEY_FILE").ok().and_then(|path| {
                std::fs::read_to_string(&path)
                    .map(|s| s.trim_end_matches('\n').trim_end_matches('\r').to_string())
                    .ok()
                    .filter(|s| !s.is_empty())
            })
        })
        .ok_or_else(|| {
            "WORKER_SHARED_KEY environment variable is not set (or WORKER_SHARED_KEY_FILE for Docker secrets). \
             Generate with: openssl rand -hex 32"
                .to_string()
        })?;

    let key = hex::decode(hex_key.trim())
        .map_err(|e| format!("WORKER_SHARED_KEY is not valid hex: {e}"))?;

    if key.len() != 32 {
        return Err(format!(
            "WORKER_SHARED_KEY must be 32 bytes (64 hex chars), got {} bytes",
            key.len()
        ));
    }

    Ok(talos_workflow_engine_core::WorkerSharedKey::new(key))
}

/// Decode one 64-hex-char (`32`-byte) shared key from a raw string, applying
/// the same length + hex validation as [`load_worker_shared_key`]. Used by
/// [`load_worker_key_ring`] to parse each comma-separated previous key.
fn decode_shared_key_hex(
    hex_key: &str,
    label: &str,
) -> Result<talos_workflow_engine_core::WorkerSharedKey, String> {
    let key = hex::decode(hex_key.trim()).map_err(|e| format!("{label} is not valid hex: {e}"))?;
    if key.len() != 32 {
        return Err(format!(
            "{label} must be 32 bytes (64 hex chars), got {} bytes",
            key.len()
        ));
    }
    Ok(talos_workflow_engine_core::WorkerSharedKey::new(key))
}

/// Load the worker-shared **key ring** for restart-free signing-key rotation.
///
/// * `WORKER_SHARED_KEY` (or `WORKER_SHARED_KEY_FILE`) — the current signing
///   key. Required; fail-fast if absent or malformed (delegates to
///   [`load_worker_shared_key`]).
/// * `WORKER_SHARED_KEY_PREVIOUS` — optional, comma-separated list of previous
///   64-hex-char keys accepted **for verification only**. Empty / unset means
///   a single-key ring identical to the old behavior.
///
/// New messages are signed under the current key; inbound messages signed
/// under any ring member verify successfully. See [`WorkerKeyRing`] for the
/// rotation workflow and the security rationale (no wire change, no key-ID
/// negotiation, explicit + freshness-bounded acceptance).
///
/// At startup the caller should log [`worker_key_fingerprint`] for each ring
/// member so an operator can confirm the controller and worker fleet agree —
/// the same drift-detection pattern the AOT key ring uses.
///
/// [`WorkerKeyRing`]: talos_workflow_engine_core::WorkerKeyRing
pub fn load_worker_key_ring() -> Result<talos_workflow_engine_core::WorkerKeyRing, String> {
    let signing = load_worker_shared_key()?;
    let previous = load_worker_shared_key_previous()?;
    Ok(talos_workflow_engine_core::WorkerKeyRing::new(
        signing, previous,
    ))
}

/// Load just the previous (verify/decrypt-only) keys from
/// `WORKER_SHARED_KEY_PREVIOUS` — the comma-separated list staged during a
/// rolling rotation. Empty when unset. Factored out of [`load_worker_key_ring`]
/// so a consumer that already holds the current signing key (e.g. the engine's
/// `build_nats_dispatcher`) can build the verify-ring without re-reading
/// `WORKER_SHARED_KEY`.
pub fn load_worker_shared_key_previous(
) -> Result<Vec<talos_workflow_engine_core::WorkerSharedKey>, String> {
    let mut previous = Vec::new();
    if let Ok(prev) = std::env::var("WORKER_SHARED_KEY_PREVIOUS") {
        for (idx, raw) in prev.split(',').enumerate() {
            let raw = raw.trim();
            if raw.is_empty() {
                continue;
            }
            // Label each entry so a bad previous key points at the right slot
            // without echoing the (secret) value.
            previous.push(decode_shared_key_hex(
                raw,
                &format!("WORKER_SHARED_KEY_PREVIOUS[{idx}]"),
            )?);
        }
    }
    Ok(previous)
}

/// Stable, non-secret fingerprint of a shared key for drift-detection logging.
///
/// Returns the first 8 hex chars of `HMAC-SHA256(key, "talos-worker-shared-key-fingerprint-v1")`.
/// Using an HMAC (rather than a bare hash of the key) keeps the key bytes one
/// pre-image away from the log line; 32 bits is enough to spot a controller↔
/// worker mismatch while revealing nothing usable about the key.
#[must_use]
pub fn worker_key_fingerprint(key: &[u8]) -> String {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC-SHA256 accepts a key of any length");
    mac.update(b"talos-worker-shared-key-fingerprint-v1");
    let tag = mac.finalize().into_bytes();
    hex::encode(&tag[..4])
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod decrypt_ring_tests {
    use super::*;
    use talos_workflow_engine_core::{WorkerKeyRing, WorkerSharedKey};

    fn secrets() -> HashMap<String, String> {
        HashMap::from([("api_key".to_string(), "s3cr3t".to_string())])
    }

    #[test]
    fn ring_decrypts_with_current_key() {
        let cur = vec![0x01u8; 32];
        let enc = EncryptedSecrets::encrypt_with_aad(&secrets(), &cur, b"exec").unwrap();
        let ring = WorkerKeyRing::single(WorkerSharedKey::new(cur));
        assert_eq!(enc.decrypt_with_ring(&ring, b"exec").unwrap(), secrets());
    }

    #[test]
    fn ring_decrypts_secrets_sealed_under_previous_key() {
        // Controller (not yet flipped) sealed under OLD; this worker's current
        // key is NEW, OLD staged as previous.
        let old = vec![0x0Au8; 32];
        let new = vec![0x0Bu8; 32];
        let enc = EncryptedSecrets::encrypt_with_aad(&secrets(), &old, b"exec").unwrap();

        let new_only = WorkerKeyRing::single(WorkerSharedKey::new(new.clone()));
        assert!(enc.decrypt_with_ring(&new_only, b"exec").is_err());

        let ring = WorkerKeyRing::new(WorkerSharedKey::new(new), [WorkerSharedKey::new(old)]);
        assert_eq!(enc.decrypt_with_ring(&ring, b"exec").unwrap(), secrets());
    }

    #[test]
    fn ring_preserves_aad_binding() {
        let cur = vec![0x01u8; 32];
        let enc = EncryptedSecrets::encrypt_with_aad(&secrets(), &cur, b"exec-a").unwrap();
        let ring = WorkerKeyRing::new(
            WorkerSharedKey::new(cur),
            [WorkerSharedKey::new(vec![0x02u8; 32])],
        );
        // Right key, wrong AAD — no ring member rescues a transposed ciphertext.
        assert!(enc.decrypt_with_ring(&ring, b"exec-b").is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> Vec<u8> {
        vec![0x42u8; 32] // 32-byte test key
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = test_key();
        let mut secrets = HashMap::new();
        secrets.insert("slack/token".to_string(), "xoxb-secret".to_string());
        secrets.insert("api/key".to_string(), "sk-12345".to_string());

        let encrypted = EncryptedSecrets::encrypt(&secrets, &key).unwrap();
        assert!(!encrypted.ciphertext.is_empty());
        assert_eq!(encrypted.nonce.len(), 12);

        let decrypted = encrypted.decrypt(&key).unwrap();
        assert_eq!(decrypted, secrets);
    }

    #[test]
    fn test_wrong_key_fails_decryption() {
        let key1 = test_key();
        let key2 = vec![0xFFu8; 32];
        let mut secrets = HashMap::new();
        secrets.insert("key".to_string(), "value".to_string());

        let encrypted = EncryptedSecrets::encrypt(&secrets, &key1).unwrap();
        let result = encrypted.decrypt(&key2);
        assert!(result.is_err());
    }

    /// L-1: AAD round-trip — encrypt with AAD, decrypt with the same
    /// AAD, get the original plaintext back.
    #[test]
    fn aad_round_trip_succeeds() {
        let key = test_key();
        let mut secrets = HashMap::new();
        secrets.insert("anthropic/api_key".to_string(), "sk-xyz".to_string());
        let aad = b"job:abc-123";
        let enc = EncryptedSecrets::encrypt_with_aad(&secrets, &key, aad).unwrap();
        let dec = enc.decrypt_with_aad(&key, aad).unwrap();
        assert_eq!(dec, secrets);
    }

    /// L-1: decrypting with a DIFFERENT AAD must fail. This is the
    /// core anti-transposition property — an attacker who lifts an
    /// EncryptedSecrets blob from one JobRequest into another (under
    /// the same shared key) cannot decrypt the lifted ciphertext if
    /// the new JobRequest's AAD differs from the original.
    #[test]
    fn aad_mismatch_fails_decryption() {
        let key = test_key();
        let mut secrets = HashMap::new();
        secrets.insert("anthropic/api_key".to_string(), "sk-xyz".to_string());
        let enc = EncryptedSecrets::encrypt_with_aad(&secrets, &key, b"job:abc").unwrap();
        // Same key, same ciphertext — but different AAD context.
        let bad = enc.decrypt_with_aad(&key, b"job:zzz");
        assert!(
            bad.is_err(),
            "decrypt with different AAD must fail (anti-transposition gate)"
        );
        let msg = bad.unwrap_err();
        assert!(
            msg.contains("decryption failed"),
            "expected GCM tag error, got: {msg}"
        );
    }

    /// The envelope cipher key is an HKDF subkey of the root, not the
    /// root itself — so it is distinct from the HMAC signing key, which
    /// uses the root bytes directly. Derivation is deterministic so the
    /// controller (seal) and worker (open) compute the same subkey.
    #[test]
    fn envelope_subkey_is_domain_separated_and_deterministic() {
        let root = [7u8; 32];
        let subkey = derive_envelope_aead_key_v1(&root);
        assert_ne!(
            &subkey[..],
            &root[..],
            "envelope subkey must differ from the root (== the signing key)"
        );
        assert_eq!(
            subkey,
            derive_envelope_aead_key_v1(&root),
            "derivation must be deterministic across processes"
        );
        // v2 per-job derivation: distinct jobs derive distinct keys, and
        // each differs from the v1 static key (finding #1).
        let k_a = derive_envelope_aead_key_v2(&root, b"job:aaa");
        let k_b = derive_envelope_aead_key_v2(&root, b"job:bbb");
        assert_ne!(
            k_a, k_b,
            "different jobs must derive different envelope keys"
        );
        assert_ne!(
            k_a, subkey,
            "v2 per-job key must differ from the v1 static key"
        );
        assert_eq!(
            k_a,
            derive_envelope_aead_key_v2(&root, b"job:aaa"),
            "v2 derivation must be deterministic across processes"
        );
    }

    /// Migration: an envelope sealed under the legacy v1 static key (a
    /// not-yet-rolled controller) must still open via the v2-first decrypt
    /// fallback once the worker is on the new code.
    #[test]
    fn legacy_v1_envelope_opens_via_fallback() {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        use aes_gcm::{Aes256Gcm, Nonce};
        let key = test_key();
        let mut secrets = HashMap::new();
        secrets.insert("anthropic/api_key".to_string(), "sk-legacy".to_string());
        let aad = b"job:legacy-1";

        // Hand-seal a v1 envelope: static key + aad bound in the tag.
        let v1_key = derive_envelope_aead_key_v1(&key);
        let cipher = Aes256Gcm::new_from_slice(&v1_key).unwrap();
        let nonce_bytes = [3u8; 12];
        let plaintext = serde_json::to_vec(&secrets).unwrap();
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext.as_ref(),
                    aad,
                },
            )
            .unwrap();
        let env = EncryptedSecrets {
            ciphertext,
            nonce: nonce_bytes.to_vec(),
        };
        // v2-first decrypt must fall back to v1 and recover the secrets.
        assert_eq!(env.decrypt_with_aad(&key, aad).unwrap(), secrets);
    }

    /// The strongest proof the slice does what Part 2 claims: a sealed
    /// envelope must NOT open under the raw root key (which is also the
    /// HMAC signing key), only under the derived subkey that
    /// `decrypt_with_aad` reconstructs.
    #[test]
    fn envelope_does_not_open_under_the_raw_signing_key() {
        use aes_gcm::{
            aead::{Aead, KeyInit, Payload},
            Aes256Gcm, Nonce,
        };
        let root = [9u8; 32];
        let mut secrets = HashMap::new();
        secrets.insert("api_key".to_string(), "sk-xyz".to_string());
        let aad = b"exec-123";

        let env = EncryptedSecrets::encrypt_with_aad(&secrets, &root, aad).unwrap();

        // Opens via the normal path (which derives the subkey).
        assert_eq!(env.decrypt_with_aad(&root, aad).unwrap(), secrets);

        // Must NOT open if you treat the raw root as the AES-GCM key.
        let raw_cipher = Aes256Gcm::new_from_slice(&root).unwrap();
        let nonce = Nonce::from_slice(&env.nonce);
        let opened_raw = raw_cipher.decrypt(
            nonce,
            Payload {
                msg: env.ciphertext.as_ref(),
                aad,
            },
        );
        assert!(
            opened_raw.is_err(),
            "ciphertext must not open under the raw signing key"
        );
    }

    /// L-1: backwards compatibility — `encrypt`/`decrypt` (no AAD)
    /// continue to interoperate with each other. Critical so
    /// existing dispatch paths that haven't migrated to the AAD form
    /// keep working.
    #[test]
    fn no_aad_round_trip_still_works() {
        let key = test_key();
        let mut secrets = HashMap::new();
        secrets.insert("k".to_string(), "v".to_string());
        let enc = EncryptedSecrets::encrypt(&secrets, &key).unwrap();
        let dec = enc.decrypt(&key).unwrap();
        assert_eq!(dec, secrets);
    }

    /// L-1: encrypt-no-AAD + decrypt-with-AAD must fail. Confirms the
    /// AES-GCM tag binding is one-way — there's no "matches when one
    /// side is empty" silent-success path.
    #[test]
    fn mixed_aad_modes_fail_decryption() {
        let key = test_key();
        let mut secrets = HashMap::new();
        secrets.insert("k".to_string(), "v".to_string());
        let enc = EncryptedSecrets::encrypt(&secrets, &key).unwrap();
        // Encrypted with empty AAD; decrypt with non-empty AAD.
        let bad = enc.decrypt_with_aad(&key, b"any");
        assert!(bad.is_err());

        let enc2 = EncryptedSecrets::encrypt_with_aad(&secrets, &key, b"any").unwrap();
        // Encrypted with AAD; decrypt with empty (legacy `decrypt`).
        let bad2 = enc2.decrypt(&key);
        assert!(bad2.is_err());
    }

    #[test]
    fn test_replay_within_window_is_rejected() {
        // Sign a request, verify it once (admitted), then verify the
        // same bytes again — the nonce cache should reject the second
        // verify as a replay even though HMAC + freshness still pass.
        let key = test_key();
        let mut req = JobRequest {
            crypto_scheme: 0,
            sealing: 0,
            secret_paths: Vec::new(),
            claim_inbox: None,
            job_id: Uuid::new_v4(),
            workflow_execution_id: Uuid::new_v4(),
            module_uri: "wasm://module/v1".to_string(),
            input_payload: serde_json::json!({"replay_test": true}),
            encrypted_secrets: EncryptedSecrets::empty(),
            timeout_ms: 30000,
            priority: 100,
            deadline_unix_secs: 0,
            cancellation_token: None,
            allowed_hosts: vec![],
            allowed_methods: vec![],
            allowed_secrets: vec![],
            allowed_sql_operations: vec![],
            allow_tier2_exposure: false,
            signature: vec![],
            max_llm_tier: LlmTier::default(),
            max_write_ceiling: WriteCeiling::default(),
            egress_scope: None,
            job_nonce: String::new(),
            actor_id: None,
            wasm_bytes: None,
            capability_world: None,
            integration_name: None,
            user_id: Uuid::nil(),
            expected_wasm_hash: None,
            max_fuel: 0,
            dry_run: false,
            reply_topic: None,
            idempotency_key: None,
        };
        req.sign(&key).unwrap();

        // First verification admits the nonce.
        req.verify(&key, 300).expect("first verify should succeed");

        // Second verification of the same JobRequest must now fail —
        // the nonce was already recorded. Error message should mention
        // replay so operators can correlate logs.
        let err = req
            .verify(&key, 300)
            .expect_err("second verify should be rejected as replay");
        assert!(
            err.contains("replay"),
            "replay rejection message should contain 'replay'; got: {err}"
        );
    }

    #[test]
    fn test_sign_and_verify() {
        let key = test_key();
        let mut req = JobRequest {
            crypto_scheme: 0,
            sealing: 0,
            secret_paths: Vec::new(),
            claim_inbox: None,
            job_id: Uuid::new_v4(),
            workflow_execution_id: Uuid::new_v4(),
            module_uri: "wasm://module/v1".to_string(),
            input_payload: serde_json::json!({}),
            encrypted_secrets: EncryptedSecrets::empty(),
            timeout_ms: 30000,
            priority: 100,
            deadline_unix_secs: 0,
            cancellation_token: None,
            allowed_hosts: vec![],
            allowed_methods: vec![],
            allowed_secrets: vec![],
            allowed_sql_operations: vec![],
            allow_tier2_exposure: false,
            signature: vec![],
            max_llm_tier: LlmTier::default(),
            max_write_ceiling: WriteCeiling::default(),
            egress_scope: None,
            job_nonce: String::new(),
            actor_id: None,
            wasm_bytes: None,
            capability_world: None,
            integration_name: None,
            user_id: Uuid::nil(),
            expected_wasm_hash: None,
            max_fuel: 0,
            dry_run: false,
            reply_topic: None,
            idempotency_key: None,
        };

        req.sign(&key).unwrap();
        assert!(!req.signature.is_empty());
        assert!(!req.job_nonce.is_empty());

        // Verification should pass
        req.verify(&key, 300).unwrap();
    }

    #[test]
    fn test_tampered_signature_fails() {
        let key = test_key();
        let mut req = JobRequest {
            crypto_scheme: 0,
            sealing: 0,
            secret_paths: Vec::new(),
            claim_inbox: None,
            job_id: Uuid::new_v4(),
            workflow_execution_id: Uuid::new_v4(),
            module_uri: "wasm://module/v1".to_string(),
            input_payload: serde_json::json!({}),
            encrypted_secrets: EncryptedSecrets::empty(),
            timeout_ms: 30000,
            priority: 100,
            deadline_unix_secs: 0,
            cancellation_token: None,
            allowed_hosts: vec![],
            allowed_methods: vec![],
            allowed_secrets: vec![],
            allowed_sql_operations: vec![],
            allow_tier2_exposure: false,
            signature: vec![],
            max_llm_tier: LlmTier::default(),
            max_write_ceiling: WriteCeiling::default(),
            egress_scope: None,
            job_nonce: String::new(),
            actor_id: None,
            wasm_bytes: None,
            capability_world: None,
            integration_name: None,
            user_id: Uuid::nil(),
            expected_wasm_hash: None,
            max_fuel: 0,
            dry_run: false,
            reply_topic: None,
            idempotency_key: None,
        };
        req.sign(&key).unwrap();
        req.module_uri = "wasm://evil-module/v1".to_string(); // tamper
        let result = req.verify(&key, 300);
        assert!(result.is_err());
    }

    #[test]
    fn test_job_result_sign_and_verify() {
        let key = test_key();
        let mut result = JobResult {
            llm_usage: vec![],
            crypto_scheme: 0,
            job_id: Uuid::new_v4(),
            status: JobStatus::Success,
            output_payload: serde_json::json!({"answer": 42}),
            logs: vec![],
            execution_time_ms: 150,
            signature: vec![],
            result_nonce: String::new(),
            worker_id: String::new(),
        };

        result.sign(&key).unwrap();
        assert!(!result.signature.is_empty());
        assert!(!result.result_nonce.is_empty());

        result.verify(&key, 300).unwrap();
    }

    #[test]
    fn test_job_result_tampered_fails() {
        let key = test_key();
        let mut result = JobResult {
            llm_usage: vec![],
            crypto_scheme: 0,
            job_id: Uuid::new_v4(),
            status: JobStatus::Success,
            output_payload: serde_json::json!({"answer": 42}),
            logs: vec![],
            execution_time_ms: 150,
            signature: vec![],
            result_nonce: String::new(),
            worker_id: String::new(),
        };
        result.sign(&key).unwrap();
        result.output_payload = serde_json::json!({"answer": 99}); // tamper
        assert!(result.verify(&key, 300).is_err());
    }

    /// L-4: `verify_as(Verifier::Primary)` matches `verify()` exactly —
    /// records the nonce, so a second `Primary` call against the same
    /// result trips the replay cache. `verify_as(Verifier::Observer)`
    /// matches `verify_no_replay()` — no cache mutation, so repeated
    /// `Observer` calls succeed and an `Observer` followed by a
    /// `Primary` also succeeds (the primary records the nonce on its
    /// first call).
    #[test]
    fn verifier_primary_records_replay_observer_does_not() {
        let key = test_key();
        let mut a = JobResult {
            llm_usage: vec![],
            crypto_scheme: 0,
            job_id: Uuid::new_v4(),
            status: JobStatus::Success,
            output_payload: serde_json::json!({}),
            logs: vec![],
            execution_time_ms: 1,
            signature: vec![],
            result_nonce: String::new(),
            worker_id: String::new(),
        };
        a.sign(&key).unwrap();

        // Observer is idempotent — repeated calls succeed.
        a.verify_as(&key, 300, Verifier::Observer).unwrap();
        a.verify_as(&key, 300, Verifier::Observer).unwrap();

        // Primary records the nonce — second Primary call must fail.
        a.verify_as(&key, 300, Verifier::Primary).unwrap();
        let second = a.verify_as(&key, 300, Verifier::Primary);
        assert!(
            second.is_err(),
            "second Primary verify must trip the replay cache"
        );
        let msg = second.unwrap_err();
        assert!(
            msg.contains("already seen"),
            "expected replay-cache error, got: {msg}"
        );
    }

    /// L-4: an Observer-first-then-Primary sequence is the canonical
    /// production pattern (audit subscriber runs concurrently with
    /// the primary). Both must succeed; only the second Primary
    /// would fail (covered by the test above).
    #[test]
    fn verifier_observer_then_primary_both_succeed() {
        let key = test_key();
        let mut a = JobResult {
            llm_usage: vec![],
            crypto_scheme: 0,
            job_id: Uuid::new_v4(),
            status: JobStatus::Success,
            output_payload: serde_json::json!({}),
            logs: vec![],
            execution_time_ms: 1,
            signature: vec![],
            result_nonce: String::new(),
            worker_id: String::new(),
        };
        a.sign(&key).unwrap();
        a.verify_as(&key, 300, Verifier::Observer).unwrap();
        a.verify_as(&key, 300, Verifier::Primary).unwrap();
    }

    /// L-4: tampering still gates both roles via the HMAC check.
    #[test]
    fn verifier_rejects_tampered_signature_in_both_roles() {
        let key = test_key();
        let mut a = JobResult {
            llm_usage: vec![],
            crypto_scheme: 0,
            job_id: Uuid::new_v4(),
            status: JobStatus::Success,
            output_payload: serde_json::json!({"answer": 42}),
            logs: vec![],
            execution_time_ms: 1,
            signature: vec![],
            result_nonce: String::new(),
            worker_id: String::new(),
        };
        a.sign(&key).unwrap();
        a.output_payload = serde_json::json!({"answer": 99});
        assert!(a.verify_as(&key, 300, Verifier::Observer).is_err());
        assert!(a.verify_as(&key, 300, Verifier::Primary).is_err());
    }

    #[test]
    fn test_tampered_allowed_methods_fails() {
        let key = test_key();
        let mut req = JobRequest {
            crypto_scheme: 0,
            sealing: 0,
            secret_paths: Vec::new(),
            claim_inbox: None,
            job_id: Uuid::new_v4(),
            workflow_execution_id: Uuid::new_v4(),
            module_uri: "wasm://module/v1".to_string(),
            input_payload: serde_json::json!({}),
            encrypted_secrets: EncryptedSecrets::empty(),
            timeout_ms: 30000,
            priority: 100,
            deadline_unix_secs: 0,
            cancellation_token: None,
            allowed_hosts: vec!["api.example.com".to_string()],
            allowed_methods: vec!["GET".to_string()],
            allowed_secrets: vec![],
            allowed_sql_operations: vec![],
            allow_tier2_exposure: false,
            signature: vec![],
            max_llm_tier: LlmTier::default(),
            max_write_ceiling: WriteCeiling::default(),
            egress_scope: None,
            job_nonce: String::new(),
            actor_id: None,
            wasm_bytes: None,
            capability_world: None,
            integration_name: None,
            user_id: Uuid::nil(),
            expected_wasm_hash: None,
            max_fuel: 0,
            dry_run: false,
            reply_topic: None,
            idempotency_key: None,
        };
        req.sign(&key).unwrap();
        // An attacker cannot escalate from GET-only to POST by modifying the field.
        req.allowed_methods = vec!["GET".to_string(), "POST".to_string()];
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered allowed_methods must fail verification"
        );
    }

    #[test]
    fn test_allowed_methods_order_independent() {
        let key = test_key();
        let mut req = JobRequest {
            crypto_scheme: 0,
            sealing: 0,
            secret_paths: Vec::new(),
            claim_inbox: None,
            job_id: Uuid::new_v4(),
            workflow_execution_id: Uuid::new_v4(),
            module_uri: "wasm://module/v1".to_string(),
            input_payload: serde_json::json!({}),
            encrypted_secrets: EncryptedSecrets::empty(),
            timeout_ms: 30000,
            priority: 100,
            deadline_unix_secs: 0,
            cancellation_token: None,
            allowed_hosts: vec![],
            allowed_methods: vec!["POST".to_string(), "GET".to_string()],
            allowed_secrets: vec![],
            allowed_sql_operations: vec![],
            allow_tier2_exposure: false,
            signature: vec![],
            max_llm_tier: LlmTier::default(),
            max_write_ceiling: WriteCeiling::default(),
            egress_scope: None,
            job_nonce: String::new(),
            actor_id: None,
            wasm_bytes: None,
            capability_world: None,
            integration_name: None,
            user_id: Uuid::nil(),
            expected_wasm_hash: None,
            max_fuel: 0,
            dry_run: false,
            reply_topic: None,
            idempotency_key: None,
        };
        req.sign(&key).unwrap();
        // Reordering must not affect verification (sorted before hashing).
        req.allowed_methods = vec!["GET".to_string(), "POST".to_string()];
        req.verify(&key, 300)
            .expect("order-independent allowed_methods must still verify");
    }

    #[test]
    fn test_job_result_unsigned_fails() {
        let key = test_key();
        let result = JobResult {
            llm_usage: vec![],
            crypto_scheme: 0,
            job_id: Uuid::new_v4(),
            status: JobStatus::Success,
            output_payload: serde_json::json!({}),
            logs: vec![],
            execution_time_ms: 0,
            signature: vec![],
            result_nonce: String::new(),
            worker_id: String::new(),
        };
        assert!(result.verify(&key, 300).is_err());
    }

    /// Helper for the new wire-format binding tests below: build a
    /// minimal JobRequest with the named overrides applied. Callers
    /// `.sign()` themselves before tampering / re-verifying.
    fn make_test_request(actor_id: Option<Uuid>) -> JobRequest {
        JobRequest {
            crypto_scheme: 0,
            sealing: 0,
            secret_paths: Vec::new(),
            claim_inbox: None,
            job_id: Uuid::new_v4(),
            workflow_execution_id: Uuid::new_v4(),
            module_uri: "wasm://m/v1".to_string(),
            input_payload: serde_json::json!({}),
            encrypted_secrets: EncryptedSecrets::empty(),
            timeout_ms: 30000,
            priority: 100,
            deadline_unix_secs: 0,
            cancellation_token: None,
            allowed_hosts: vec![],
            allowed_methods: vec![],
            allowed_secrets: vec!["slack/token".to_string()],
            allowed_sql_operations: vec!["SELECT".to_string()],
            allow_tier2_exposure: false,
            signature: vec![],
            max_llm_tier: LlmTier::default(),
            max_write_ceiling: WriteCeiling::default(),
            egress_scope: None,
            job_nonce: String::new(),
            actor_id,
            wasm_bytes: None,
            capability_world: None,
            integration_name: None,
            user_id: Uuid::nil(),
            expected_wasm_hash: None,
            max_fuel: 0,
            dry_run: false,
            reply_topic: None,
            idempotency_key: None,
        }
    }

    // ── RFC 0010 P1: Ed25519 dispatch scheme tests ────────────────────────

    fn ed_keypair() -> DispatchSigningKey {
        DispatchSigningKey::generate(&mut rand::rngs::OsRng)
    }

    fn hmac_ring(key: &[u8]) -> talos_workflow_engine_core::WorkerKeyRing {
        talos_workflow_engine_core::WorkerKeyRing::single(
            talos_workflow_engine_core::WorkerSharedKey::new(key.to_vec()),
        )
    }

    fn make_test_result() -> JobResult {
        JobResult {
            llm_usage: vec![],
            crypto_scheme: 0,
            job_id: Uuid::new_v4(),
            status: JobStatus::Success,
            output_payload: serde_json::json!({"ok": true}),
            logs: vec![],
            execution_time_ms: 12,
            signature: vec![],
            result_nonce: String::new(),
            worker_id: String::new(),
        }
    }

    // ── RFC 0010 P2: per-worker Ed25519 RESULT signing tests ──────────────

    #[test]
    fn result_ed25519_sign_verify_roundtrip() {
        let worker_sk = ed_keypair();
        let worker_pk = worker_sk.verifying_key();
        let mut r = make_test_result();
        r.sign_ed25519_with_worker_id(&worker_sk, "talos-worker-7")
            .unwrap();
        assert_eq!(r.crypto_scheme, CRYPTO_SCHEME_ED25519);
        assert_eq!(r.worker_id, "talos-worker-7");
        r.verify_no_replay_ed25519(&[worker_pk], 300)
            .expect("controller verifies against the worker's public key");
    }

    #[test]
    fn result_ed25519_requires_worker_id() {
        let worker_sk = ed_keypair();
        let mut r = make_test_result();
        assert!(
            r.sign_ed25519_with_worker_id(&worker_sk, "").is_err(),
            "empty worker_id has no registered key to verify against"
        );
    }

    #[test]
    fn result_ed25519_wrong_worker_key_fails() {
        // A result signed by worker-A's key does not verify against worker-B's
        // key — a compromised worker can only sign results as itself.
        let a = ed_keypair();
        let b_pk = ed_keypair().verifying_key();
        let mut r = make_test_result();
        r.sign_ed25519_with_worker_id(&a, "worker-a").unwrap();
        assert!(r.verify_no_replay_ed25519(&[b_pk], 300).is_err());
    }

    #[test]
    fn result_ed25519_tampered_output_fails() {
        let sk = ed_keypair();
        let pk = sk.verifying_key();
        let mut r = make_test_result();
        r.sign_ed25519_with_worker_id(&sk, "worker-a").unwrap();
        r.output_payload = serde_json::json!({"ok": false});
        assert!(r.verify_no_replay_ed25519(&[pk], 300).is_err());
    }

    #[test]
    fn result_verify_dispatch_routes_and_enforces_p4() {
        let key = test_key();
        let ring = hmac_ring(&key);
        let sk = ed_keypair();
        let pk = sk.verifying_key();

        // HMAC result: accepted during rollout, refused under enforcement.
        let mut hmac_r = make_test_result();
        hmac_r.sign_with_worker_id(&key, "worker-a").unwrap();
        hmac_r
            .verify_dispatch(&ring, &[pk], 300, true)
            .expect("HMAC result accepted during rollout");
        let mut hmac_r2 = make_test_result();
        hmac_r2.sign_with_worker_id(&key, "worker-a").unwrap();
        assert!(
            hmac_r2.verify_dispatch(&ring, &[pk], 300, false).is_err(),
            "P4: HMAC result refused under Ed25519-only enforcement"
        );

        // Ed25519 result: accepted regardless of the legacy flag.
        let mut ed_r = make_test_result();
        ed_r.sign_ed25519_with_worker_id(&sk, "worker-a").unwrap();
        ed_r.verify_dispatch(&ring, &[pk], 300, false)
            .expect("Ed25519 result accepted under enforcement");
    }

    #[test]
    fn result_downgrade_flip_rejected() {
        let key = test_key();
        let ring = hmac_ring(&key);
        let sk = ed_keypair();
        let mut r = make_test_result();
        r.sign_ed25519_with_worker_id(&sk, "worker-a").unwrap();
        r.crypto_scheme = CRYPTO_SCHEME_HMAC; // tamper the hint
        assert!(r
            .verify_dispatch(&ring, &[sk.verifying_key()], 300, true)
            .is_err());
    }

    #[test]
    fn worker_public_key_registry_parses_and_verifies() {
        // Two workers, plus a rotated-in second key for worker-a — the exact
        // shape the controller loads from TALOS_WORKER_PUBLIC_KEYS.
        let a_old = ed_keypair();
        let a_new = ed_keypair();
        let b = ed_keypair();
        let raw = format!(
            "worker-a={},worker-b={},worker-a={}",
            hex::encode(a_old.verifying_key().to_bytes()),
            hex::encode(b.verifying_key().to_bytes()),
            hex::encode(a_new.verifying_key().to_bytes()),
        );
        let reg = parse_worker_public_keys(&raw);

        // worker-a carries BOTH keys (rotation overlap); worker-b carries one.
        assert_eq!(reg.get("worker-a").map(Vec::len), Some(2));
        assert_eq!(reg.get("worker-b").map(Vec::len), Some(1));
        assert!(reg.get("worker-c").is_none());

        // A result signed under either of worker-a's keys verifies against the
        // registered set (first match wins).
        let mut r = make_test_result();
        r.sign_ed25519_with_worker_id(&a_new, "worker-a").unwrap();
        r.verify_no_replay_ed25519(reg.get("worker-a").unwrap(), 300)
            .expect("rotated-in worker key must verify");
    }

    #[test]
    fn worker_public_key_registry_skips_malformed_entries() {
        let good = ed_keypair();
        // Garbage, a keyless bareword, an empty worker_id, and trailing commas
        // are all skipped without poisoning the one valid pair.
        let raw = format!(
            "  , notanentry , =deadbeef , worker-x=zzzz , worker-ok={} ,,",
            hex::encode(good.verifying_key().to_bytes()),
        );
        let reg = parse_worker_public_keys(&raw);
        assert_eq!(reg.len(), 1, "only the one well-formed pair survives");
        assert_eq!(reg.get("worker-ok").map(Vec::len), Some(1));
    }

    #[test]
    fn worker_public_keys_empty_input_is_empty() {
        assert!(parse_worker_public_keys("").is_empty());
        assert!(parse_worker_public_keys("   ,  , ").is_empty());
    }

    // RFC 0010 P2 inc.4: the DB-backed dynamic overlay. Uses a worker_id no other
    // test references and no TALOS_WORKER_PUBLIC_KEYS env (unset in the test proc),
    // so the env base is empty and this test owns its slice of the global snapshot.
    #[test]
    fn dynamic_worker_public_keys_overlay_union_dedup_and_replace() {
        let a = ed_keypair();
        let b = ed_keypair();
        let wid = "inc4-dynamic-worker";

        // Install two keys for the worker (rotation overlap): both resolve.
        set_dynamic_worker_public_keys([
            (wid.to_string(), a.verifying_key()),
            (wid.to_string(), b.verifying_key()),
        ]);
        let keys = worker_public_keys(wid);
        assert_eq!(keys.len(), 2, "both dynamic keys present");

        // Dedup: re-installing with a byte-identical repeat does not double it.
        set_dynamic_worker_public_keys([
            (wid.to_string(), a.verifying_key()),
            (wid.to_string(), a.verifying_key()),
        ]);
        assert_eq!(
            worker_public_keys(wid).len(),
            1,
            "byte-identical keys dedup"
        );
        assert_eq!(
            worker_public_keys(wid)[0].to_bytes(),
            a.verifying_key().to_bytes()
        );

        // Full-replacement: an empty overlay drops the worker entirely (models a
        // worker whose every key was deactivated in the DB).
        set_dynamic_worker_public_keys(std::iter::empty());
        assert!(
            worker_public_keys(wid).is_empty(),
            "empty refresh clears the dynamic overlay for this worker"
        );

        // A result signed by the worker verifies only while its key is installed.
        set_dynamic_worker_public_keys([(wid.to_string(), a.verifying_key())]);
        let mut r = make_test_result();
        r.sign_ed25519_with_worker_id(&a, wid).unwrap();
        r.verify_no_replay_ed25519(&worker_public_keys(wid), 300)
            .expect("installed dynamic key verifies the worker's result");
        // Reset the global so we don't leak state into other tests.
        set_dynamic_worker_public_keys(std::iter::empty());
    }

    #[test]
    fn ed25519_sign_verify_roundtrip() {
        let sk = ed_keypair();
        let pk = sk.verifying_key();
        let mut req = make_test_request(Some(Uuid::new_v4()));
        req.sign_ed25519(&sk).unwrap();
        assert_eq!(req.crypto_scheme, CRYPTO_SCHEME_ED25519);
        assert_eq!(req.signature.len(), 64, "Ed25519 signatures are 64 bytes");
        req.verify_no_replay_ed25519(&[pk], 300)
            .expect("valid Ed25519 signature must verify");
    }

    #[test]
    fn ed25519_tampered_payload_fails() {
        let sk = ed_keypair();
        let pk = sk.verifying_key();
        let mut req = make_test_request(Some(Uuid::new_v4()));
        req.sign_ed25519(&sk).unwrap();
        // Tamper a signed field.
        req.max_llm_tier = LlmTier::Tier1;
        assert!(
            req.verify_no_replay_ed25519(&[pk], 300).is_err(),
            "tampered payload must fail Ed25519 verification"
        );
    }

    #[test]
    fn ed25519_wrong_key_fails() {
        let sk = ed_keypair();
        let other_pk = ed_keypair().verifying_key();
        let mut req = make_test_request(None);
        req.sign_ed25519(&sk).unwrap();
        assert!(
            req.verify_no_replay_ed25519(&[other_pk], 300).is_err(),
            "a different controller key must not verify"
        );
    }

    #[test]
    fn ed25519_empty_keyset_rejects() {
        let sk = ed_keypair();
        let mut req = make_test_request(None);
        req.sign_ed25519(&sk).unwrap();
        assert!(
            req.verify_no_replay_ed25519(&[], 300).is_err(),
            "no configured key must fail closed, not pass"
        );
    }

    #[test]
    fn ed25519_key_rotation_overlap() {
        // Signed under the CURRENT key; a verifier carrying [rotated_in, old]
        // still validates (first match wins), so a controller-key rotation with
        // an overlap window doesn't drop in-flight dispatches.
        let old = ed_keypair();
        let new = ed_keypair();
        let mut req = make_test_request(None);
        req.sign_ed25519(&old).unwrap();
        req.verify_no_replay_ed25519(&[new.verifying_key(), old.verifying_key()], 300)
            .expect("previous-key overlap must verify");
    }

    #[test]
    fn schemes_do_not_cross_validate() {
        let key = test_key();
        let sk = ed_keypair();
        let pk = sk.verifying_key();

        // HMAC-signed request must not verify as Ed25519.
        let mut hmac_req = make_test_request(None);
        hmac_req.sign(&key).unwrap();
        assert!(hmac_req.verify_no_replay_ed25519(&[pk], 300).is_err());

        // Ed25519-signed request must not verify as HMAC (domain-separated
        // input + a 64-byte non-HMAC signature).
        let mut ed_req = make_test_request(None);
        ed_req.sign_ed25519(&sk).unwrap();
        assert!(ed_req.verify_no_replay(&key, 300).is_err());
    }

    #[test]
    fn verify_dispatch_routes_by_scheme_and_enforces_p4() {
        let key = test_key();
        let ring = hmac_ring(&key);
        let sk = ed_keypair();
        let pk = sk.verifying_key();

        // HMAC request: admitted while legacy HMAC is accepted (rollout window).
        let mut hmac_req = make_test_request(None);
        hmac_req.sign(&key).unwrap();
        hmac_req
            .verify_dispatch(&ring, &[pk], 300, true)
            .expect("HMAC dispatch accepted during rollout");

        // Same HMAC request REFUSED once Ed25519-only enforcement is on (P4).
        let mut hmac_req2 = make_test_request(None);
        hmac_req2.sign(&key).unwrap();
        assert!(
            hmac_req2.verify_dispatch(&ring, &[pk], 300, false).is_err(),
            "P4: legacy HMAC dispatch must be refused when enforcement is on"
        );

        // Ed25519 request: admitted regardless of the legacy flag.
        let mut ed_req = make_test_request(None);
        ed_req.sign_ed25519(&sk).unwrap();
        ed_req
            .verify_dispatch(&ring, &[pk], 300, false)
            .expect("Ed25519 dispatch accepted under enforcement");
    }

    #[test]
    fn downgrade_flip_is_rejected() {
        // An on-wire attacker flips a valid Ed25519 request's scheme hint to 0
        // to force the HMAC path. Without the HMAC key they cannot produce a
        // valid HMAC, so verify_dispatch fails.
        let key = test_key();
        let ring = hmac_ring(&key);
        let sk = ed_keypair();
        let mut req = make_test_request(None);
        req.sign_ed25519(&sk).unwrap();
        req.crypto_scheme = CRYPTO_SCHEME_HMAC; // tamper the hint
        assert!(
            req.verify_dispatch(&ring, &[sk.verifying_key()], 300, true)
                .is_err(),
            "scheme downgrade must fail (no valid HMAC for the payload)"
        );
    }

    #[test]
    fn unknown_scheme_is_rejected() {
        let key = test_key();
        let ring = hmac_ring(&key);
        let sk = ed_keypair();
        let mut req = make_test_request(None);
        req.sign_ed25519(&sk).unwrap();
        req.crypto_scheme = 200; // unknown
        assert!(req
            .verify_dispatch(&ring, &[sk.verifying_key()], 300, true)
            .is_err());
    }

    #[test]
    fn ed25519_primary_verify_records_replay() {
        let sk = ed_keypair();
        let pk = sk.verifying_key();
        let mut req = make_test_request(None);
        req.sign_ed25519(&sk).unwrap();
        // Primary verify records the nonce…
        req.verify_ed25519(&[pk], 300).expect("first verify ok");
        // …so a second primary verify of the same nonce is a replay.
        assert!(
            req.verify_ed25519(&[pk], 300).is_err(),
            "replayed Ed25519 dispatch must be rejected"
        );
    }

    #[test]
    fn ed25519_key_hex_parse_roundtrip() {
        let sk = ed_keypair();
        let pk = sk.verifying_key();
        let pk_hex = hex::encode(pk.to_bytes());
        let parsed = parse_ed25519_verifying_key_hex(&pk_hex).expect("parse pubkey");
        assert_eq!(parsed.to_bytes(), pk.to_bytes());
        let sk_hex = hex::encode(sk.to_bytes());
        let parsed_sk = parse_ed25519_signing_key_hex(&sk_hex).expect("parse signkey");
        assert_eq!(parsed_sk.to_bytes(), sk.to_bytes());
        // Wrong lengths fail closed.
        assert!(parse_ed25519_verifying_key_hex("deadbeef").is_err());
        assert!(parse_ed25519_signing_key_hex("").is_err());
    }

    #[test]
    fn worker_registration_proof_roundtrip_and_field_binding() {
        let sk = ed_keypair();
        let pk = sk.verifying_key().to_bytes();
        let (wid, sealing, ts, nonce) = ("worker-9", true, 1_700_000_000_000u64, "nonce-abc");

        let proof = sign_worker_registration_proof(&sk, wid, &pk, sealing, ts, nonce);
        assert_eq!(proof.len(), 64, "Ed25519 signature is 64 bytes");
        verify_worker_registration_proof(&pk, wid, sealing, ts, nonce, &proof)
            .expect("a faithfully-signed proof verifies");

        // EVERY signed field is bound — flipping any one breaks verification.
        assert!(
            verify_worker_registration_proof(&pk, "worker-8", sealing, ts, nonce, &proof).is_err()
        );
        assert!(verify_worker_registration_proof(&pk, wid, !sealing, ts, nonce, &proof).is_err());
        assert!(
            verify_worker_registration_proof(&pk, wid, sealing, ts + 1, nonce, &proof).is_err()
        );
        assert!(
            verify_worker_registration_proof(&pk, wid, sealing, ts, "nonce-xyz", &proof).is_err()
        );

        // A proof for a DIFFERENT key does not verify against this key — the
        // registrant can only prove possession of a key it actually holds, so it
        // cannot register another party's (or another worker's) public key.
        let other_pk = ed_keypair().verifying_key().to_bytes();
        assert!(
            verify_worker_registration_proof(&other_pk, wid, sealing, ts, nonce, &proof).is_err()
        );

        // Tampered / malformed signatures fail closed.
        let mut bad = proof.clone();
        bad[0] ^= 0x01;
        assert!(verify_worker_registration_proof(&pk, wid, sealing, ts, nonce, &bad).is_err());
        assert!(
            verify_worker_registration_proof(&pk, wid, sealing, ts, nonce, &proof[..63]).is_err()
        );
        // A non-point public_key is rejected before any verify.
        assert!(
            verify_worker_registration_proof(&[2u8; 32], wid, sealing, ts, nonce, &proof).is_err()
        );
    }

    #[test]
    fn worker_registration_pop_message_is_unambiguous() {
        // Length-prefixing prevents a field-boundary collision: moving a byte
        // from the end of worker_id to the start of nonce must change the bytes.
        let pk = [7u8; 32];
        let a = worker_registration_pop_message("ab", &pk, false, 1, "cd");
        let b = worker_registration_pop_message("abc", &pk, false, 1, "d");
        assert_ne!(a, b, "ambiguous concatenation would make these equal");
    }

    #[test]
    fn verifying_key_from_bytes_roundtrips_and_rejects_noncanonical() {
        // The bytes path (used by the inc.4 DB-overlay refresh) agrees with the
        // hex path and with the key's own encoding.
        let pk = ed_keypair().verifying_key();
        let bytes = pk.to_bytes();
        let parsed = parse_ed25519_verifying_key_bytes(&bytes).expect("canonical point parses");
        assert_eq!(parsed.to_bytes(), bytes);
        // A value that is not a valid curve point fails closed rather than
        // yielding a key that would silently never verify. (`[2u8; 32]` does not
        // decompress to an Edwards point.)
        assert!(parse_ed25519_verifying_key_bytes(&[2u8; 32]).is_err());
    }

    #[test]
    fn generated_keypair_hex_roundtrips_and_matches() {
        let (seed_hex, pub_hex) = generate_ed25519_keypair_hex();
        assert_eq!(seed_hex.len(), 64, "seed is 32 bytes = 64 hex chars");
        assert_eq!(pub_hex.len(), 64, "public key is 32 bytes = 64 hex chars");
        // Both parse in the exact shape the env loaders accept.
        let sk = parse_ed25519_signing_key_hex(&seed_hex).expect("seed parses");
        let pk = parse_ed25519_verifying_key_hex(&pub_hex).expect("pubkey parses");
        // The emitted public key is the one derived from the emitted seed —
        // an operator pasting the two halves into peer processes gets a
        // matching pair, and a signature made with the seed verifies under it.
        assert_eq!(sk.verifying_key().to_bytes(), pk.to_bytes());
        let mut req = make_test_request(None);
        req.sign_ed25519(&sk).unwrap();
        req.verify_no_replay_ed25519(&[pk], 300)
            .expect("seed-signed request verifies under the emitted public key");
        // Two calls yield distinct keys (not a constant).
        let (seed2, _) = generate_ed25519_keypair_hex();
        assert_ne!(seed_hex, seed2, "keygen must be random per call");
    }

    /// RFC 0010 end-to-end: the exact hex strings the
    /// `generate-worker-trust-keypair` subcommand prints, fed through the SAME
    /// pure loaders the controller and worker read env with, must compose across
    /// BOTH trust directions — controller→worker dispatch (P1) and
    /// worker→controller results (P2) — using ONE per-worker keypair (the same
    /// key the RPC path uses). This is the "did we ship something an operator can
    /// actually turn on" check: it fails if the keygen output format drifts from
    /// what `parse_ed25519_*` / `parse_worker_public_keys` accept, or if the two
    /// verify paths diverge.
    #[test]
    fn operator_keygen_config_composes_both_directions() {
        // --- what the operator generates + pastes into env ---
        // `--role controller`: seed on controller, pub on every worker.
        let (ctrl_seed_hex, ctrl_pub_hex) = generate_ed25519_keypair_hex();
        // `--role worker --worker-id worker-1`: seed on the worker, the
        // `worker_id=pub` pair appended to the controller's registry string.
        let (w1_seed_hex, w1_pub_hex) = generate_ed25519_keypair_hex();
        let worker_public_keys_env = format!("worker-1={w1_pub_hex}");

        // === P1 dispatch: controller signs, worker verifies ===
        // Controller side — build the signer exactly as configured_dispatch_signer.
        let ctrl_signer = DispatchSigner::Ed25519(std::sync::Arc::new(
            parse_ed25519_signing_key_hex(&ctrl_seed_hex).expect("controller seed parses"),
        ));
        let mut req = make_test_request(Some(Uuid::new_v4()));
        ctrl_signer
            .sign_job(&mut req)
            .expect("controller signs dispatch");
        assert_eq!(req.crypto_scheme, CRYPTO_SCHEME_ED25519);
        // Worker side — parse TALOS_CONTROLLER_PUBLIC_KEY and verify. The ring
        // holds only an unrelated dummy key: the Ed25519 path never touches the
        // symmetric ring, and accept_legacy_hmac=false proves it holds under P4
        // enforcement (a signature forged under the dummy HMAC key is refused).
        let ctrl_pub = parse_ed25519_verifying_key_hex(&ctrl_pub_hex).expect("ctrl pub parses");
        let unrelated_ring = hmac_ring(b"unrelated-hmac-key-never-touched-on-ed25519-path");
        req.verify_dispatch(&unrelated_ring, &[ctrl_pub], 300, false)
            .expect("worker verifies the controller-signed dispatch");

        // === P2 result: worker signs, controller verifies via the registry ===
        let w1_sk = parse_ed25519_signing_key_hex(&w1_seed_hex).expect("worker seed parses");
        let mut result = make_test_result();
        result
            .sign_ed25519_with_worker_id(&w1_sk, "worker-1")
            .expect("worker signs its result");
        // Controller side — resolve the verifying key(s) for worker-1 out of the
        // parsed TALOS_WORKER_PUBLIC_KEYS registry, then verify.
        let registry = parse_worker_public_keys(&worker_public_keys_env);
        let w1_keys = registry.get("worker-1").expect("worker-1 is registered");
        result
            .verify_dispatch(&unrelated_ring, w1_keys, 300, false)
            .expect("controller verifies the worker-signed result");

        // === Core security property, driven through the config path ===
        // A result claiming to be worker-1 but signed by a DIFFERENT key (a
        // compromised/rogue worker impersonating worker-1) fails against the
        // registered key. The asymmetric boundary means holding a valid worker
        // key never lets you forge as another worker_id.
        let (rogue_seed_hex, _) = generate_ed25519_keypair_hex();
        let rogue_sk = parse_ed25519_signing_key_hex(&rogue_seed_hex).unwrap();
        let mut forged = make_test_result();
        forged
            .sign_ed25519_with_worker_id(&rogue_sk, "worker-1")
            .unwrap();
        assert!(
            forged
                .verify_dispatch(&unrelated_ring, w1_keys, 300, false)
                .is_err(),
            "a rogue key claiming worker-1 must not verify against worker-1's registered key"
        );
    }

    /// M-4: tampering with `actor_id` MUST invalidate the signature.
    /// Pre-fix the field was excluded from the signing payload, so a
    /// NATS-channel attacker could redirect the worker's downstream
    /// `MemoryRpcRequest` writes to a different actor's memory namespace.
    #[test]
    fn tampered_actor_id_fails_verification() {
        let key = test_key();
        let actor_a = Uuid::new_v4();
        let actor_b = Uuid::new_v4();
        let mut req = make_test_request(Some(actor_a));
        req.sign(&key).unwrap();

        // Tamper: swap actor_a → actor_b. Pre-fix this passed.
        req.actor_id = Some(actor_b);
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered actor_id must fail verification (M-4)"
        );
    }

    /// M-4: actor_id None → Some MUST also be tamper-evident.
    #[test]
    fn actor_id_none_to_some_fails_verification() {
        let key = test_key();
        let mut req = make_test_request(None);
        req.sign(&key).unwrap();

        req.actor_id = Some(Uuid::new_v4());
        assert!(
            req.verify(&key, 300).is_err(),
            "swapping actor_id from None to Some must fail (M-4)"
        );
    }

    /// M-5: tampering with `allowed_secrets` MUST invalidate signature.
    /// Even though encrypted_secrets is the active enforcement layer,
    /// capability claims should be self-consistent with the signed
    /// message.
    #[test]
    fn tampered_allowed_secrets_fails_verification() {
        let key = test_key();
        let mut req = make_test_request(None);
        req.sign(&key).unwrap();

        req.allowed_secrets = vec!["openai/api_key".to_string(), "*".to_string()];
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered allowed_secrets must fail verification (M-5)"
        );
    }

    /// M-5: tampering with `allow_tier2_exposure` MUST invalidate.
    /// Pre-fix an attacker could flip the tier-2 bit on the wire,
    /// granting the module Tier-2 capability the operator never
    /// intended.
    #[test]
    fn tampered_allow_tier2_fails_verification() {
        let key = test_key();
        let mut req = make_test_request(None);
        req.allow_tier2_exposure = false;
        req.sign(&key).unwrap();

        req.allow_tier2_exposure = true;
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered allow_tier2_exposure must fail verification (M-5)"
        );
    }

    /// M-5: tampering with `allowed_sql_operations` MUST invalidate.
    #[test]
    fn tampered_allowed_sql_operations_fails_verification() {
        let key = test_key();
        let mut req = make_test_request(None);
        req.sign(&key).unwrap();

        req.allowed_sql_operations = vec![
            "SELECT".to_string(),
            "INSERT".to_string(),
            "DELETE".to_string(),
        ];
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered allowed_sql_operations must fail verification (M-5)"
        );
    }

    /// M-5: order-independence — re-ordering allowed_secrets must NOT
    /// invalidate. Same property as `test_allowed_methods_order_independent`
    /// but for the new fields.
    #[test]
    fn allowed_secrets_order_independent() {
        let key = test_key();
        let mut req = make_test_request(None);
        req.allowed_secrets = vec!["b".to_string(), "a".to_string(), "c".to_string()];
        req.sign(&key).unwrap();

        req.allowed_secrets = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        req.verify(&key, 300)
            .expect("order-independent allowed_secrets must still verify (M-5)");
    }

    /// L-9: payload-collision regression guard. Two semantically-distinct
    /// requests whose `module_uri` + `job_nonce` could collide under the
    /// pre-length-prefix scheme MUST produce different signatures.
    /// Pre-fix the colon delimiter could collide between
    /// `(module_uri="a", job_nonce="b:c")` and `(module_uri="a:b", job_nonce="c")`
    /// — same signing-payload bytes. The length-prefix on module_uri
    /// disambiguates.
    #[test]
    fn length_prefix_prevents_module_uri_collision() {
        let key = test_key();
        let mut req_a = make_test_request(None);
        req_a.module_uri = "a".to_string();
        req_a.sign(&key).unwrap();

        let mut req_b = make_test_request(None);
        // Try to construct a colliding payload by stuffing bytes into
        // module_uri that, under the pre-fix concatenation, would have
        // matched req_a's bytes. With length-prefixing the byte counts
        // differ so no collision is possible.
        req_b.module_uri = "a:b".to_string();
        req_b.job_id = req_a.job_id;
        req_b.workflow_execution_id = req_a.workflow_execution_id;
        req_b.job_nonce = req_a.job_nonce.clone();
        // Sign req_b with its own values but check that the resulting
        // signing_payload bytes differ from req_a's even under
        // adversarial field choices. (Direct inspection of the payload
        // bytes — we don't need to actually swap signatures.)
        let payload_a = req_a.signing_payload();
        let payload_b = req_b.signing_payload();
        assert_ne!(
            payload_a, payload_b,
            "length-prefixed module_uri must prevent collision between adversarially-chosen field values (L-9)"
        );
    }

    /// L-10: tampering with `JobResult.logs` MUST invalidate the
    /// signature. Pre-fix the logs field was unsigned; an attacker
    /// could inject misleading audit-trail entries in flight.
    #[test]
    fn tampered_job_result_logs_fails_verification() {
        let key = test_key();
        let mut result = JobResult {
            llm_usage: vec![],
            crypto_scheme: 0,
            job_id: Uuid::new_v4(),
            status: JobStatus::Success,
            output_payload: serde_json::json!({"answer": 42}),
            logs: vec!["legit log line".to_string()],
            execution_time_ms: 100,
            signature: vec![],
            result_nonce: String::new(),
            worker_id: String::new(),
        };
        result.sign(&key).unwrap();

        // Tamper: append a misleading log line.
        result
            .logs
            .push("FAKE: user authorized critical action".to_string());
        assert!(
            result.verify(&key, 300).is_err(),
            "tampered logs must fail verification (L-10)"
        );
    }

    /// H-1: tampering with `reply_topic` MUST invalidate the signature.
    /// Pre-fix the field was excluded from the signing payload, so a
    /// NATS-channel attacker could redirect the worker's signed
    /// JobResult to an attacker-controlled subject.
    #[test]
    fn tampered_reply_topic_fails_verification() {
        let key = test_key();
        let mut req = make_test_request(None);
        req.reply_topic = Some("_INBOX.legit.abc123".to_string());
        req.sign(&key).unwrap();

        // Tamper: swap to a malicious subject.
        req.reply_topic = Some("talos.admin.commands".to_string());
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered reply_topic must fail verification (H-1)"
        );
    }

    /// H-1: reply_topic None → Some MUST also be tamper-evident
    /// (sentinel `-` differs from a real subject).
    #[test]
    fn reply_topic_none_to_some_fails_verification() {
        let key = test_key();
        let mut req = make_test_request(None);
        req.sign(&key).unwrap();
        req.reply_topic = Some("talos.admin.commands".to_string());
        assert!(
            req.verify(&key, 300).is_err(),
            "injecting reply_topic must fail verification (H-1)"
        );
    }

    /// H-1: reply_topic Some → None MUST also be tamper-evident
    /// (stripping the field shouldn't downgrade verification to the
    /// legacy "trust msg.reply" path).
    #[test]
    fn reply_topic_some_to_none_fails_verification() {
        let key = test_key();
        let mut req = make_test_request(None);
        req.reply_topic = Some("_INBOX.legit.abc123".to_string());
        req.sign(&key).unwrap();
        req.reply_topic = None;
        assert!(
            req.verify(&key, 300).is_err(),
            "stripping reply_topic must fail verification (H-1)"
        );
    }

    /// H-1: tampering at the pipeline level — same property as
    /// JobRequest. PipelineJobRequest tampering is per-pipeline,
    /// not per-step, so we tamper the field at the root.
    #[test]
    fn tampered_pipeline_reply_topic_fails_verification() {
        let key = test_key();
        let mut req = PipelineJobRequest {
            crypto_scheme: 0,
            sealing: 0,
            secret_paths: Vec::new(),
            claim_inbox: None,
            job_id: Uuid::new_v4(),
            workflow_execution_id: Uuid::new_v4(),
            steps: vec![],
            total_timeout_ms: 60_000,
            share_sandbox: false,
            signature: vec![],
            job_nonce: String::new(),
            user_id: Uuid::nil(),
            max_llm_tier: LlmTier::default(),
            max_write_ceiling: WriteCeiling::default(),
            egress_scope: None,
            reply_topic: Some("_INBOX.legit.xyz".to_string()),
        };
        req.sign(&key).unwrap();
        req.reply_topic = Some("talos.admin.commands".to_string());
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered pipeline reply_topic must fail verification (H-1)"
        );
    }

    /// L-10: empty-logs case — signature must round-trip correctly.
    #[test]
    fn job_result_with_empty_logs_round_trips() {
        let key = test_key();
        let mut result = JobResult {
            llm_usage: vec![],
            crypto_scheme: 0,
            job_id: Uuid::new_v4(),
            status: JobStatus::Success,
            output_payload: serde_json::json!({}),
            logs: vec![],
            execution_time_ms: 0,
            signature: vec![],
            result_nonce: String::new(),
            worker_id: String::new(),
        };
        result.sign(&key).unwrap();
        result
            .verify(&key, 300)
            .expect("empty-logs result should verify");
    }

    // ========================================================================
    // Wasm-security review 2026-05-23: tampering tests for the H-3 / H-7 / C-2
    // signing-payload extensions.
    // ========================================================================
    //
    // Each `tampered_<field>_fails_verification` test follows the same shape:
    // 1. Build a clean request and sign it.
    // 2. Mutate exactly one field that USED to be unsigned.
    // 3. Re-verify and assert failure.
    //
    // Pre-fix, every one of these mutations would have passed verification —
    // anyone with NATS publish on the job subject could perform the mutation
    // in flight without the worker detecting it.

    /// H-3: `capability_world` is now HMAC-bound. Pre-fix an attacker could
    /// flip `minimal-node` → `automation-node` to trick the worker into
    /// selecting a wider tiered linker (important for precompiled WASM
    /// where the embedded world name may not survive Wizer).
    #[test]
    fn tampered_capability_world_fails_verification() {
        let key = test_key();
        let mut req = make_test_request(None);
        req.capability_world = Some("minimal-node".to_string());
        req.sign(&key).unwrap();

        req.capability_world = Some("automation-node".to_string());
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered capability_world must fail verification (H-3)"
        );
    }

    /// H-3: stripping the `capability_world` (Some → None) must also be
    /// tamper-evident — the sentinel `-` for None makes the absence
    /// signed.
    #[test]
    fn capability_world_some_to_none_fails_verification() {
        let key = test_key();
        let mut req = make_test_request(None);
        req.capability_world = Some("minimal-node".to_string());
        req.sign(&key).unwrap();

        req.capability_world = None;
        assert!(
            req.verify(&key, 300).is_err(),
            "stripping capability_world must fail verification (H-3)"
        );
    }

    /// H-7: `dry_run` is now HMAC-bound. Pre-fix an attacker could flip
    /// `true → false` to convert a planning-mode run into a real one
    /// (real HTTP POSTs, real webhooks).
    #[test]
    fn tampered_dry_run_fails_verification() {
        let key = test_key();
        let mut req = make_test_request(None);
        req.dry_run = true;
        req.sign(&key).unwrap();

        req.dry_run = false;
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered dry_run must fail verification (H-7)"
        );
    }

    /// H-7: `priority` is now HMAC-bound. Pre-fix an attacker could
    /// promote arbitrary jobs to starve legitimate high-priority work.
    #[test]
    fn tampered_priority_fails_verification() {
        let key = test_key();
        let mut req = make_test_request(None);
        req.priority = 100;
        req.sign(&key).unwrap();

        req.priority = 1;
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered priority must fail verification (H-7)"
        );
    }

    /// H-7: `deadline_unix_secs` is now HMAC-bound. Pre-fix an attacker
    /// could set a past timestamp to force premature failure.
    #[test]
    fn tampered_deadline_fails_verification() {
        let key = test_key();
        let mut req = make_test_request(None);
        req.deadline_unix_secs = 0;
        req.sign(&key).unwrap();

        req.deadline_unix_secs = 1;
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered deadline_unix_secs must fail verification (H-7)"
        );
    }

    /// H-7: `cancellation_token` is now HMAC-bound. Pre-fix an attacker
    /// could strip the token, leaving an in-flight job uncancellable.
    #[test]
    fn tampered_cancellation_token_fails_verification() {
        let key = test_key();
        let mut req = make_test_request(None);
        req.cancellation_token = Some("token-abc".to_string());
        req.sign(&key).unwrap();

        req.cancellation_token = None;
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered cancellation_token must fail verification (H-7)"
        );
    }

    /// H-3 + H-7 (combined positive case): a clean round-trip with all
    /// the newly-bound fields populated must verify.
    #[test]
    fn newly_bound_fields_round_trip() {
        let key = test_key();
        let mut req = make_test_request(None);
        req.capability_world = Some("automation-node".to_string());
        req.dry_run = true;
        req.priority = 200;
        req.deadline_unix_secs = 1_700_000_000;
        req.cancellation_token = Some("abc-123".to_string());
        req.sign(&key).unwrap();

        req.verify(&key, 300)
            .expect("clean request with newly-bound H-3/H-7 fields must verify");
    }

    // ========================================================================
    // C-2: PipelineJobRequest::signing_payload extension tests.
    // ========================================================================
    //
    // Pre-fix the pipeline signing payload bound only step_hashes,
    // step_integrations, step_caps (allowed_secrets / sql / tier2),
    // max_llm_tier, reply_topic, and the job-level fields — it did NOT
    // bind per-step config, allowed_hosts, allowed_methods, encrypted
    // secrets ciphertext, max_fuel, max_memory_mb, timeout_ms, priority,
    // or cancellation_token. Each of the tests below mutates exactly
    // one of those fields and asserts the signature no longer verifies.

    fn make_test_pipeline_step() -> PipelineStep {
        PipelineStep {
            module_id: Uuid::new_v4(),
            module_uri: "wasm://m/v1".to_string(),
            wasm_bytes: None,
            config: serde_json::json!({"input": "original"}),
            allowed_hosts: vec!["api.example.com".to_string()],
            allowed_methods: vec!["GET".to_string()],
            allowed_secrets: vec!["slack/token".to_string()],
            allowed_sql_operations: vec!["SELECT".to_string()],
            allow_tier2_exposure: false,
            encrypted_secrets: EncryptedSecrets::empty(),
            max_fuel: 1_000_000,
            max_memory_mb: 64,
            timeout_ms: 30_000,
            priority: 100,
            cancellation_token: None,
            expected_wasm_hash: None,
            integration_name: None,
            max_retries: 0,
            retry_backoff_ms: 0,
        }
    }

    fn make_test_pipeline(steps: Vec<PipelineStep>) -> PipelineJobRequest {
        PipelineJobRequest {
            crypto_scheme: 0,
            sealing: 0,
            secret_paths: Vec::new(),
            claim_inbox: None,
            job_id: Uuid::new_v4(),
            workflow_execution_id: Uuid::new_v4(),
            steps,
            total_timeout_ms: 60_000,
            share_sandbox: false,
            signature: vec![],
            job_nonce: String::new(),
            user_id: Uuid::nil(),
            max_llm_tier: LlmTier::default(),
            max_write_ceiling: WriteCeiling::default(),
            egress_scope: None,
            reply_topic: None,
        }
    }

    /// C-2: pipeline `config` is now HMAC-bound. Pre-fix the worker
    /// would execute the signed-and-attested module against
    /// attacker-supplied config under the signed secrets blob.
    #[test]
    fn pipeline_tampered_step_config_fails_verification() {
        let key = test_key();
        let mut req = make_test_pipeline(vec![make_test_pipeline_step()]);
        req.sign(&key).unwrap();

        req.steps[0].config = serde_json::json!({"input": "tampered"});
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered pipeline step config must fail verification (C-2)"
        );
    }

    /// C-2: pipeline `allowed_hosts` is now HMAC-bound. Pre-fix an
    /// attacker could widen the allowlist to exfiltrate via
    /// attacker-controlled URL + signed `vault://` header.
    #[test]
    fn pipeline_tampered_step_hosts_fails_verification() {
        let key = test_key();
        let mut req = make_test_pipeline(vec![make_test_pipeline_step()]);
        req.sign(&key).unwrap();

        req.steps[0]
            .allowed_hosts
            .push("attacker.example".to_string());
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered pipeline allowed_hosts must fail verification (C-2)"
        );
    }

    /// C-2: pipeline `allowed_methods` is now HMAC-bound.
    #[test]
    fn pipeline_tampered_step_methods_fails_verification() {
        let key = test_key();
        let mut req = make_test_pipeline(vec![make_test_pipeline_step()]);
        req.sign(&key).unwrap();

        req.steps[0].allowed_methods.push("DELETE".to_string());
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered pipeline allowed_methods must fail verification (C-2)"
        );
    }

    /// C-2: pipeline `encrypted_secrets.ciphertext` is now HMAC-bound.
    /// Pre-fix the AAD (workflow_execution_id) was shared across all
    /// steps in one pipeline, so an attacker could swap one step's
    /// ciphertext for another's and the worker would happily decrypt.
    #[test]
    fn pipeline_tampered_step_secrets_fails_verification() {
        let key = test_key();
        let mut req = make_test_pipeline(vec![make_test_pipeline_step()]);
        req.sign(&key).unwrap();

        req.steps[0].encrypted_secrets.ciphertext = vec![0xff; 32];
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered pipeline encrypted_secrets must fail verification (C-2)"
        );
    }

    /// C-2: pipeline `max_fuel` / `max_memory_mb` / `timeout_ms` are now
    /// HMAC-bound. Pre-fix an attacker could inflate any of them for
    /// resource exhaustion / cost overrun.
    #[test]
    fn pipeline_tampered_step_resource_caps_fail_verification() {
        let key = test_key();
        let mut req = make_test_pipeline(vec![make_test_pipeline_step()]);
        req.sign(&key).unwrap();

        // Inflate fuel.
        req.steps[0].max_fuel = 1_000_000_000;
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered pipeline max_fuel must fail (C-2)"
        );
        req.steps[0].max_fuel = 1_000_000;
        req.signature = vec![]; // resign baseline
        req.sign(&key).unwrap();

        // Inflate memory.
        req.steps[0].max_memory_mb = 4096;
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered pipeline max_memory_mb must fail (C-2)"
        );
        req.steps[0].max_memory_mb = 64;
        req.signature = vec![];
        req.sign(&key).unwrap();

        // Inflate timeout.
        req.steps[0].timeout_ms = 600_000;
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered pipeline timeout_ms must fail (C-2)"
        );
    }

    /// C-2: pipeline `priority` is now HMAC-bound.
    #[test]
    fn pipeline_tampered_step_priority_fails_verification() {
        let key = test_key();
        let mut req = make_test_pipeline(vec![make_test_pipeline_step()]);
        req.sign(&key).unwrap();

        req.steps[0].priority = 1;
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered pipeline priority must fail verification (C-2)"
        );
    }

    /// C-2: pipeline `cancellation_token` is now HMAC-bound. None → Some
    /// and Some → None must both fail.
    #[test]
    fn pipeline_tampered_step_cancellation_token_fails_verification() {
        let key = test_key();
        let mut req = make_test_pipeline(vec![make_test_pipeline_step()]);
        req.steps[0].cancellation_token = Some("tok-1".to_string());
        req.sign(&key).unwrap();

        req.steps[0].cancellation_token = None;
        assert!(
            req.verify(&key, 300).is_err(),
            "stripping pipeline cancellation_token must fail (C-2)"
        );
    }

    /// C-2: clean round-trip — a pipeline with all the C-2 fields
    /// populated must verify successfully.
    #[test]
    fn pipeline_signing_round_trip() {
        let key = test_key();
        let mut step = make_test_pipeline_step();
        step.config = serde_json::json!({"k": "v", "n": 42});
        step.cancellation_token = Some("tok-xyz".to_string());
        let mut req = make_test_pipeline(vec![step]);
        req.sign(&key).unwrap();

        req.verify(&key, 300)
            .expect("clean pipeline with C-2 fields populated must verify");
    }

    /// C-2: per-step independence — mutating step 1 must invalidate the
    /// whole signature even though step 0 is untouched.
    #[test]
    fn pipeline_tampered_second_step_config_fails() {
        let key = test_key();
        let s0 = make_test_pipeline_step();
        let mut s1 = make_test_pipeline_step();
        s1.config = serde_json::json!({"step": 1});
        let mut req = make_test_pipeline(vec![s0, s1]);
        req.sign(&key).unwrap();

        // Tamper the SECOND step's config.
        req.steps[1].config = serde_json::json!({"step": "tampered"});
        assert!(
            req.verify(&key, 300).is_err(),
            "tampering a non-first step's config must still fail (C-2)"
        );
    }

    /// C-2: order-independence — re-ordering `allowed_hosts` within a
    /// step must NOT invalidate. Mirrors the existing
    /// `test_allowed_methods_order_independent` invariant.
    #[test]
    fn pipeline_step_hosts_order_independent() {
        let key = test_key();
        let mut step = make_test_pipeline_step();
        step.allowed_hosts = vec!["b.com".to_string(), "a.com".to_string()];
        let mut req = make_test_pipeline(vec![step]);
        req.sign(&key).unwrap();

        req.steps[0].allowed_hosts = vec!["a.com".to_string(), "b.com".to_string()];
        req.verify(&key, 300)
            .expect("re-ordered allowed_hosts must still verify");
    }

    // ────────────────────────────────────────────────────────────────
    // 2026-05-28 audit F5: verify_no_replay parity tests
    //
    // CLAUDE.md "Verify-once rule for signed NATS messages": every
    // signed message type MUST have BOTH `verify()` (records to nonce
    // cache) AND `verify_no_replay()` (HMAC + freshness only). Pre-fix
    // JobRequest, PipelineJobRequest, WorkerHeartbeat had only
    // `verify()` — today only one consumer per type so no dual-cache
    // bug, but adding the split BEFORE the second consumer lands is
    // the architectural mandate. Tests pin the split's three core
    // properties:
    //   1. verify_no_replay accepts a valid signed message.
    //   2. verify_no_replay does NOT poison the cache (subsequent
    //      `verify()` on the same nonce still succeeds).
    //   3. verify_no_replay rejects forgery / freshness violations.
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn job_request_verify_no_replay_accepts_valid_signature() {
        let key = test_key();
        let mut req = make_test_request(None);
        req.sign(&key).unwrap();
        let ts = req
            .verify_no_replay(&key, 300)
            .expect("verify_no_replay must accept a valid signature");
        assert!(ts > 0, "parsed timestamp should be > 0");
    }

    #[test]
    fn job_request_verify_no_replay_does_not_poison_cache() {
        // The key invariant: an observer's verify_no_replay must NOT
        // record the nonce. Otherwise the primary verify() on the
        // same message would fail with "already seen" — the dual-
        // consumer regression the architectural mandate exists to
        // prevent.
        let key = test_key();
        let mut req = make_test_request(None);
        req.sign(&key).unwrap();
        req.verify_no_replay(&key, 300)
            .expect("observer call succeeds");
        // Primary consumer's verify must STILL succeed.
        req.verify(&key, 300)
            .expect("primary verify must not collide with observer's verify_no_replay");
        // And THIS verify() should have recorded the nonce, so the
        // next verify() on the same signature must fail.
        assert!(
            req.verify(&key, 300).is_err(),
            "second verify() on the same nonce must fail (replay protection)"
        );
    }

    #[test]
    fn job_request_verify_no_replay_rejects_forgery() {
        let key = test_key();
        let mut req = make_test_request(None);
        req.sign(&key).unwrap();
        // Tamper with the signature.
        req.signature[0] ^= 0xff;
        assert!(
            req.verify_no_replay(&key, 300).is_err(),
            "tampered signature must fail in verify_no_replay too"
        );
    }

    #[test]
    fn job_request_verify_no_replay_rejects_stale_nonce() {
        let key = test_key();
        let mut req = make_test_request(None);
        req.sign(&key).unwrap();
        // Rewrite the nonce timestamp to be 1 hour in the past so the
        // freshness window check trips deterministically (same-second
        // sign+verify would otherwise pass with `max_age_secs=0`).
        // The signature will no longer match (we replaced part of the
        // signing input) but verify_no_replay must reject on the
        // freshness check BEFORE reaching HMAC — that's the contract.
        let stale_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 3600;
        let parts: Vec<&str> = req.job_nonce.splitn(2, ':').collect();
        req.job_nonce = format!("{}:{}", stale_ts, parts[1]);
        let err = req.verify_no_replay(&key, 300).unwrap_err();
        assert!(
            err.contains("too old"),
            "verify_no_replay must reject stale nonce before HMAC; got: {err}"
        );
    }

    #[test]
    fn pipeline_job_request_verify_no_replay_does_not_poison_cache() {
        let key = test_key();
        let step = make_test_pipeline_step();
        let mut req = make_test_pipeline(vec![step]);
        req.sign(&key).unwrap();
        req.verify_no_replay(&key, 300)
            .expect("observer call succeeds");
        req.verify(&key, 300)
            .expect("primary verify must not collide with observer");
        assert!(
            req.verify(&key, 300).is_err(),
            "second primary verify on the same nonce must fail (replay protection)"
        );
    }

    fn make_test_heartbeat() -> WorkerHeartbeat {
        WorkerHeartbeat {
            worker_id: Uuid::new_v4(),
            capabilities: vec!["wasm".to_string()],
            cpu_usage_pct: 25.0,
            heartbeat_nonce: String::new(),
            signature: vec![],
        }
    }

    #[test]
    fn worker_heartbeat_verify_no_replay_does_not_poison_cache() {
        let key = test_key();
        let mut hb = make_test_heartbeat();
        hb.sign(&key).unwrap();
        hb.verify_no_replay(&key, 300)
            .expect("observer call succeeds");
        hb.verify(&key, 300)
            .expect("primary verify must not collide with observer");
        assert!(
            hb.verify(&key, 300).is_err(),
            "second primary verify on the same nonce must fail (replay protection)"
        );
    }

    #[test]
    fn worker_heartbeat_verify_no_replay_rejects_forgery() {
        let key = test_key();
        let mut hb = make_test_heartbeat();
        hb.sign(&key).unwrap();
        hb.signature[0] ^= 0xff;
        assert!(
            hb.verify_no_replay(&key, 300).is_err(),
            "tampered heartbeat signature must fail in verify_no_replay"
        );
    }

    // ------------------------------------------------------------------
    // R2 token ledger: llm_usage wire-format + aggregation tests.
    // ------------------------------------------------------------------

    fn usage_entries() -> Vec<LlmUsageEntry> {
        vec![
            LlmUsageEntry {
                provider: "anthropic".into(),
                model: "claude-sonnet-4-5".into(),
                prompt_tokens: 1200,
                completion_tokens: 340,
                calls: 2,
            },
            LlmUsageEntry {
                provider: "ollama".into(),
                model: "qwen3:6b".into(),
                prompt_tokens: 900,
                completion_tokens: 210,
                calls: 5,
            },
        ]
    }

    /// A result signed WITHOUT llm_usage (the pre-R2 shape) must verify
    /// unchanged — the empty vec appends nothing to the signing payload,
    /// so old messages from old workers keep verifying byte-identically.
    #[test]
    fn llm_usage_empty_signs_byte_identical_to_pre_r2() {
        let key = test_key();
        let mut result = make_test_result();
        let pre_r2_payload = {
            // Simulate the pre-R2 payload by construction: empty usage.
            assert!(result.llm_usage.is_empty());
            result.sign(&key).unwrap();
            result.clone()
        };
        pre_r2_payload.verify_no_replay(&key, 300).unwrap();

        // Round-trip through the wire (serde) and verify again — the
        // field is skip_serializing_if-omitted, deserializes to empty via
        // serde(default), and the payload bytes still match.
        let wire = serde_json::to_string(&pre_r2_payload).unwrap();
        assert!(
            !wire.contains("llm_usage"),
            "empty llm_usage must be omitted from wire JSON"
        );
        let back: JobResult = serde_json::from_str(&wire).unwrap();
        back.verify_no_replay(&key, 300).unwrap();
    }

    /// Old-message JSON (captured shape with NO llm_usage key at all)
    /// deserializes and verifies against a signature produced before the
    /// field existed.
    #[test]
    fn llm_usage_old_wire_json_still_verifies() {
        let key = test_key();
        let mut result = make_test_result();
        result.sign(&key).unwrap();
        let mut wire: serde_json::Value = serde_json::to_value(&result).unwrap();
        // Assert the key truly isn't on the wire, then re-parse as if the
        // JSON came from an old worker.
        assert!(wire.get("llm_usage").is_none());
        // Belt-and-braces: explicitly remove in case a future serde change
        // starts emitting it.
        wire.as_object_mut().unwrap().remove("llm_usage");
        let back: JobResult = serde_json::from_value(wire).unwrap();
        back.verify_no_replay(&key, 300).unwrap();
    }

    /// A result carrying usage round-trips (field survives serde) and
    /// verifies; tampering with any usage number invalidates the signature.
    #[test]
    fn llm_usage_round_trip_and_tamper_detection() {
        let key = test_key();
        let mut result = make_test_result();
        result.llm_usage = usage_entries();
        result.sign(&key).unwrap();

        let wire = serde_json::to_string(&result).unwrap();
        assert!(wire.contains("llm_usage"));
        let back: JobResult = serde_json::from_str(&wire).unwrap();
        assert_eq!(back.llm_usage, usage_entries());
        back.verify_no_replay(&key, 300).unwrap();

        // Tamper: inflate the completion tokens.
        let mut tampered = back.clone();
        tampered.llm_usage[0].completion_tokens += 1;
        assert!(
            tampered.verify_no_replay(&key, 300).is_err(),
            "tampered token count must invalidate the signature"
        );

        // Tamper: strip the usage entirely (deflation attack).
        let mut stripped = back;
        stripped.llm_usage.clear();
        assert!(
            stripped.verify_no_replay(&key, 300).is_err(),
            "stripping llm_usage from a signed result must fail verification"
        );
    }

    /// The usage digest is order-independent: same entries in a different
    /// vec order produce the same signed bytes.
    #[test]
    fn llm_usage_signing_is_order_independent() {
        let mut a = make_test_result();
        a.llm_usage = usage_entries();
        let mut b = make_test_result();
        b.job_id = a.job_id;
        let mut rev = usage_entries();
        rev.reverse();
        b.llm_usage = rev;
        assert_eq!(a.signing_payload(), b.signing_payload());
    }

    /// PipelineJobResult mirrors the same contract.
    #[test]
    fn pipeline_llm_usage_round_trip_and_compat() {
        let key = test_key();
        let mut result = PipelineJobResult {
            llm_usage: vec![],
            crypto_scheme: 0,
            job_id: Uuid::new_v4(),
            overall_status: JobStatus::Success,
            step_results: vec![],
            final_output: serde_json::json!({"ok": true}),
            total_time_ms: 5,
            signature: vec![],
            result_nonce: String::new(),
            worker_id: String::new(),
        };
        // Empty usage: omitted from wire, verifies (pre-R2 compat).
        result.sign(&key).unwrap();
        let wire = serde_json::to_string(&result).unwrap();
        assert!(!wire.contains("llm_usage"));
        let back: PipelineJobResult = serde_json::from_str(&wire).unwrap();
        back.verify_no_replay(&key, 300).unwrap();

        // Non-empty usage: bound + tamper-evident.
        result.llm_usage = usage_entries();
        result.sign(&key).unwrap();
        let back: PipelineJobResult =
            serde_json::from_str(&serde_json::to_string(&result).unwrap()).unwrap();
        back.verify_no_replay(&key, 300).unwrap();
        let mut tampered = back;
        tampered.llm_usage[1].prompt_tokens = 0;
        assert!(tampered.verify_no_replay(&key, 300).is_err());
    }

    /// aggregate_llm_usage folds per-call observations per (provider, model),
    /// counts calls, saturates, and caps the output length.
    #[test]
    fn aggregate_llm_usage_merges_counts_and_caps() {
        let raw = vec![
            ("anthropic".to_string(), "m1".to_string(), 100u32, 20u32),
            ("anthropic".to_string(), "m1".to_string(), 50, 10),
            ("ollama".to_string(), "m2".to_string(), 7, 3),
        ];
        let agg = aggregate_llm_usage(raw);
        assert_eq!(agg.len(), 2);
        let a = agg.iter().find(|e| e.model == "m1").unwrap();
        assert_eq!(
            (a.prompt_tokens, a.completion_tokens, a.calls),
            (150, 30, 2)
        );
        let o = agg.iter().find(|e| e.model == "m2").unwrap();
        assert_eq!((o.prompt_tokens, o.completion_tokens, o.calls), (7, 3, 1));

        // Saturating add: near-max counts don't wrap.
        let sat = aggregate_llm_usage(vec![
            ("p".to_string(), "m".to_string(), u32::MAX - 1, u32::MAX - 1),
            ("p".to_string(), "m".to_string(), 100, 100),
        ]);
        assert_eq!(sat[0].prompt_tokens, u32::MAX);
        assert_eq!(sat[0].completion_tokens, u32::MAX);

        // Cap: more than MAX_LLM_USAGE_ENTRIES distinct models truncates.
        let many: Vec<_> = (0..MAX_LLM_USAGE_ENTRIES + 8)
            .map(|i| ("p".to_string(), format!("model-{i:03}"), 1u32, 1u32))
            .collect();
        assert_eq!(aggregate_llm_usage(many).len(), MAX_LLM_USAGE_ENTRIES);
    }
}
