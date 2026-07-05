//! RFC 0010 P3 (D3b) — per-execution ephemeral secret-envelope sealing.
//!
//! This module removes `WORKER_SHARED_KEY` (WSK) as a *secret-decryption root*
//! on the worker. Instead of the controller pre-sealing a job's secrets under a
//! fleet-wide WSK subkey and embedding the ciphertext in the `JobRequest`, the
//! worker claims the dispatched job with a **fresh ephemeral X25519 public key**
//! and the controller seals the secret values to *that* key. Both ends
//! contribute an ephemeral key, so a later compromise of either long-term
//! Ed25519 identity does not decrypt any captured past `SealedSecrets`
//! (forward secrecy). Worker identity is authenticated out-of-band by the
//! Ed25519 signature on the `SecretClaim` (clean separation: **Ed25519
//! authenticates *who*, X25519 provides *confidentiality + forward secrecy***).
//!
//! Message flow (see the RFC's "Message flow" section):
//! ```text
//!   1. Controller  --JobDispatch(sealing=1, secret_paths, no secrets)-->  Worker
//!   2. Worker      --SecretClaim{exec_id, worker_id, epk_w, nonce, sig}-->  Controller
//!   3. Controller  --SealedSecrets{exec_id, epk_c, ciphertext, nonce, sig}-->  Worker
//!   4. Worker      --JobResult (unchanged P2 path)-->  Controller
//! ```
//!
//! ## Cryptographic construction (the seal)
//! ```text
//!   worker:      (esk_w, epk_w) = X25519::generate()   # per execution, zeroized after open
//!   controller:  (esk_c, epk_c) = X25519::generate()   # per seal
//!   shared:      ss  = X25519(esk_c, epk_w) == X25519(esk_w, epk_c)
//!                key = HKDF-SHA256(ikm=ss, salt=exec_id, info=b"talos/envelope-seal/v3-ecies")
//!                aad = exec_id || len(worker_id) || worker_id || epk_w
//!                ct  = AES-256-GCM(key, random-96-bit-nonce, plaintext=secrets_json, aad)
//! ```
//! `ss` is rejected if non-contributory (all-zero output for a low-order point),
//! failing closed. The AAD binds the ciphertext to the exact
//! `(execution, worker, ephemeral key)` so a `SealedSecrets` cannot be replayed
//! against a different execution or a different claim.

// `esk_*` / `epk_*` (ephemeral secret / public key) are the standard ECDH names;
// clippy's `similar_names` heuristic flags the pair but renaming would obscure
// the cryptographic convention.
#![allow(clippy::similar_names)]

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use zeroize::Zeroize;

use crate::{DispatchSigningKey, DispatchVerifyingKey, CRYPTO_SCHEME_ED25519};

/// HKDF `info` string — versioned so a future construction can bump it for a
/// clean re-key without ever colliding with v3 output.
const ENVELOPE_SEAL_INFO: &[u8] = b"talos/envelope-seal/v3-ecies";

/// Domain-separation prefixes for the two signed control messages. A version
/// bump invalidates every older signature.
const SECRET_CLAIM_DOMAIN: &[u8] = b"talos/secret-claim/v1";
const SEALED_SECRETS_DOMAIN: &[u8] = b"talos/sealed-secrets/v1";

/// Future-dated tolerance for the freshness check on the two control messages
/// (clock skew). Mirrors `rpc_auth`'s asymmetric window: generous past
/// (`max_age_secs`, caller-supplied), tight future.
const FUTURE_SKEW_MS: u64 = 5_000;

/// Length-prefix a byte slice: `u64-LE length || bytes`. Keeps two distinct
/// field tuples from ever colliding onto the same signed/AAD bytes.
fn lp_into(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    buf.extend_from_slice(bytes);
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

/// Freshness gate shared by both control messages: reject a message older than
/// `max_age_secs` in the past or more than `FUTURE_SKEW_MS` in the future.
fn check_freshness(issued_at_ms: u64, max_age_secs: u64) -> Result<(), String> {
    let now = now_ms();
    if issued_at_ms > now.saturating_add(FUTURE_SKEW_MS) {
        return Err("message issued_at is in the future".to_string());
    }
    if issued_at_ms.saturating_add(max_age_secs.saturating_mul(1000)) < now {
        return Err("message is stale (past freshness window)".to_string());
    }
    Ok(())
}

// ===================================================================
// Seal construction (pure crypto)
// ===================================================================

/// Build the AEAD additional-authenticated-data: `exec_id || lp(worker_id) ||
/// epk_w`. Length-prefixing `worker_id` makes the binding transposition-proof
/// (no boundary ambiguity between `worker_id` and the fixed-width `epk_w`).
fn seal_aad(exec_id: Uuid, worker_id: &str, epk_w: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16 + 8 + worker_id.len() + 32);
    aad.extend_from_slice(exec_id.as_bytes());
    lp_into(&mut aad, worker_id.as_bytes());
    aad.extend_from_slice(epk_w);
    aad
}

/// Derive the 32-byte AES key from the ECDH shared secret. Fails closed if the
/// shared secret is non-contributory (low-order `epk`, all-zero output).
fn derive_seal_key(ss: &SharedSecret, exec_id: Uuid) -> Result<[u8; 32], String> {
    if !ss.was_contributory() {
        return Err("non-contributory ECDH shared secret (low-order ephemeral key)".to_string());
    }
    let hk = Hkdf::<Sha256>::new(Some(exec_id.as_bytes()), ss.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(ENVELOPE_SEAL_INFO, &mut okm)
        .map_err(|_| "HKDF expand failed".to_string())?;
    Ok(okm)
}

/// Output of a successful [`seal_secrets`] — the controller's per-seal ephemeral
/// public key plus the AES-256-GCM ciphertext and nonce.
#[derive(Debug, Clone)]
pub struct SealOutput {
    pub epk_c: [u8; 32],
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
}

/// **Controller side.** Seal `plaintext` (the JSON-encoded secrets map) to the
/// worker's ephemeral public key `epk_w`, binding the ciphertext to
/// `(exec_id, worker_id, epk_w)`. Generates a fresh controller ephemeral per
/// call (forward secrecy on the controller's side too). Returns the ephemeral
/// public key, ciphertext, and nonce for the `SealedSecrets` reply.
pub fn seal_secrets(
    epk_w: &[u8; 32],
    exec_id: Uuid,
    worker_id: &str,
    plaintext: &[u8],
) -> Result<SealOutput, String> {
    let esk_c = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let epk_c = PublicKey::from(&esk_c).to_bytes();
    let peer = PublicKey::from(*epk_w);
    let ss = esk_c.diffie_hellman(&peer);
    let mut key = derive_seal_key(&ss, exec_id)?;

    let aad = seal_aad(exec_id, worker_id, epk_w);
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| "invalid AES key".to_string())?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| "AES-GCM seal failed".to_string())?;
    key.zeroize();

    Ok(SealOutput {
        epk_c,
        ciphertext,
        nonce: nonce_bytes,
    })
}

/// A worker's per-execution ephemeral X25519 keypair. The secret is
/// **single-use** (X25519 `EphemeralSecret` is consumed by [`Self::open`] and
/// zeroized on drop), giving forward secrecy: once the job is opened the secret
/// is gone and no later key compromise recovers it. NOT `Clone` / `Serialize` —
/// the secret must never leave the worker process.
pub struct WorkerEphemeral {
    secret: EphemeralSecret,
    /// The public half, sent in the `SecretClaim`.
    public: [u8; 32],
}

impl std::fmt::Debug for WorkerEphemeral {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the secret; the public key is safe.
        f.debug_struct("WorkerEphemeral")
            .field("public", &hex::encode(self.public))
            .field("secret", &"<zeroized-on-drop>")
            .finish()
    }
}

impl WorkerEphemeral {
    /// Generate a fresh per-execution ephemeral keypair.
    #[must_use]
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let public = PublicKey::from(&secret).to_bytes();
        Self { secret, public }
    }

    /// The ephemeral public key `epk_w` to place in the `SecretClaim`.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }

    /// **Worker side.** Consume the ephemeral secret to open a `SealedSecrets`
    /// returned by the controller. Recomputes the ECDH shared secret from the
    /// controller's `epk_c`, re-derives the AES key, and AEAD-opens the
    /// ciphertext under the same `(exec_id, worker_id, epk_w)` AAD. The
    /// ephemeral secret is consumed (single-use → forward secrecy). Returns the
    /// plaintext secrets JSON. Fails closed on a non-contributory shared secret,
    /// a wrong `epk_c`, or any AAD mismatch (wrong execution/worker/key).
    pub fn open(
        self,
        epk_c: &[u8; 32],
        exec_id: Uuid,
        worker_id: &str,
        ciphertext: &[u8],
        nonce: &[u8; 12],
    ) -> Result<Vec<u8>, String> {
        let peer = PublicKey::from(*epk_c);
        let ss = self.secret.diffie_hellman(&peer);
        let mut key = derive_seal_key(&ss, exec_id)?;

        let aad = seal_aad(exec_id, worker_id, &self.public);
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| "invalid AES key".to_string())?;
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| "AES-GCM open failed (wrong key or tampered ciphertext)".to_string());
        key.zeroize();
        plaintext
    }
}

// ===================================================================
// SecretClaim (worker → controller), Ed25519-signed with the long-term key
// ===================================================================

/// Worker → controller claim for a dispatched job's secrets. Signed with the
/// worker's **long-term** registered Ed25519 key (P2 inc.2/inc.4) — this is
/// what authenticates *who* is claiming. The ephemeral `epk_w` provides only
/// confidentiality; binding it inside a signature by the long-term key is the
/// property that stops an on-bus attacker from substituting its own ephemeral
/// key and having the controller seal straight to it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretClaim {
    pub exec_id: Uuid,
    pub worker_id: String,
    /// Worker per-execution ephemeral X25519 public key.
    pub epk_w: [u8; 32],
    pub claim_nonce: String,
    pub issued_at_ms: u64,
    /// Signature scheme (only [`CRYPTO_SCHEME_ED25519`] defined today).
    #[serde(default)]
    pub crypto_scheme: u8,
    /// Ed25519 signature by the worker's long-term key over the canonical bytes.
    #[serde(default)]
    pub signature: Vec<u8>,
}

fn secret_claim_signing_bytes(
    exec_id: Uuid,
    worker_id: &str,
    epk_w: &[u8; 32],
    claim_nonce: &str,
    issued_at_ms: u64,
    crypto_scheme: u8,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(
        SECRET_CLAIM_DOMAIN.len() + 16 + 8 + worker_id.len() + 32 + 8 + claim_nonce.len() + 8 + 1,
    );
    msg.extend_from_slice(SECRET_CLAIM_DOMAIN);
    msg.extend_from_slice(exec_id.as_bytes());
    lp_into(&mut msg, worker_id.as_bytes());
    msg.extend_from_slice(epk_w);
    lp_into(&mut msg, claim_nonce.as_bytes());
    msg.extend_from_slice(&issued_at_ms.to_le_bytes());
    msg.push(crypto_scheme);
    msg
}

impl SecretClaim {
    /// Construct + sign a claim with the worker's long-term signing key. Stamps
    /// a fresh nonce + `issued_at_ms` and `crypto_scheme = Ed25519`.
    pub fn new_signed(
        exec_id: Uuid,
        worker_id: String,
        epk_w: [u8; 32],
        signing_key: &DispatchSigningKey,
    ) -> Self {
        use ed25519_dalek::Signer;
        let mut nonce_raw = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce_raw);
        let claim_nonce = hex::encode(nonce_raw);
        let issued_at_ms = now_ms();
        let bytes = secret_claim_signing_bytes(
            exec_id,
            &worker_id,
            &epk_w,
            &claim_nonce,
            issued_at_ms,
            CRYPTO_SCHEME_ED25519,
        );
        let signature = signing_key.sign(&bytes).to_bytes().to_vec();
        Self {
            exec_id,
            worker_id,
            epk_w,
            claim_nonce,
            issued_at_ms,
            crypto_scheme: CRYPTO_SCHEME_ED25519,
            signature,
        }
    }

    /// Signature + freshness verification (the controller's claim handler is the
    /// single primary caller). `verifying_key` is resolved from the worker's
    /// registered long-term key via `job_protocol::worker_public_keys`. The
    /// single-claim / anti-replay guarantee is the Redis lease CAS at the
    /// handler (see [`Self::verify_no_replay`] for the note).
    pub fn verify(
        &self,
        verifying_key: &DispatchVerifyingKey,
        max_age_secs: u64,
    ) -> Result<(), String> {
        check_freshness(self.issued_at_ms, max_age_secs)?;
        self.verify_no_replay(verifying_key, max_age_secs)
    }

    /// Signature + freshness ONLY — identical crypto to [`Self::verify`]. These
    /// types carry no process-local nonce cache (unlike `JobResult`, whose
    /// dual-`verify()` bug the r300/r301 rule addresses): a replayed claim is
    /// caught by the exec-scoped Redis lease CAS (a second claim for an already
    /// `claimed_by` exec_id is rejected), not a per-message cache. Provided as
    /// the twin per the "add both up front" discipline so a future passive
    /// observer has a non-cache-touching entry point.
    pub fn verify_no_replay(
        &self,
        verifying_key: &DispatchVerifyingKey,
        max_age_secs: u64,
    ) -> Result<(), String> {
        check_freshness(self.issued_at_ms, max_age_secs)?;
        if self.crypto_scheme != CRYPTO_SCHEME_ED25519 {
            return Err(format!(
                "unknown SecretClaim crypto_scheme: {}",
                self.crypto_scheme
            ));
        }
        let sig_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| "SecretClaim signature must be 64 bytes".to_string())?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        let bytes = secret_claim_signing_bytes(
            self.exec_id,
            &self.worker_id,
            &self.epk_w,
            &self.claim_nonce,
            self.issued_at_ms,
            self.crypto_scheme,
        );
        verifying_key
            .verify_strict(&bytes, &sig)
            .map_err(|_| "SecretClaim signature verification failed".to_string())
    }
}

// ===================================================================
// SealedSecrets (controller → worker), Ed25519-signed with the controller key
// ===================================================================

/// Controller → worker sealed secret envelope. Signed with the controller's P1
/// dispatch Ed25519 key; the worker verifies with the same
/// `TALOS_CONTROLLER_PUBLIC_KEY` already pinned for dispatch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedSecrets {
    pub exec_id: Uuid,
    /// Controller per-seal ephemeral X25519 public key.
    pub epk_c: [u8; 32],
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub issued_at_ms: u64,
    #[serde(default)]
    pub signature: Vec<u8>,
}

fn sealed_secrets_signing_bytes(
    exec_id: Uuid,
    epk_c: &[u8; 32],
    ciphertext: &[u8],
    nonce: &[u8; 12],
    issued_at_ms: u64,
) -> Vec<u8> {
    let mut msg =
        Vec::with_capacity(SEALED_SECRETS_DOMAIN.len() + 16 + 32 + 8 + ciphertext.len() + 12 + 8);
    msg.extend_from_slice(SEALED_SECRETS_DOMAIN);
    msg.extend_from_slice(exec_id.as_bytes());
    msg.extend_from_slice(epk_c);
    lp_into(&mut msg, ciphertext);
    msg.extend_from_slice(nonce);
    msg.extend_from_slice(&issued_at_ms.to_le_bytes());
    msg
}

impl SealedSecrets {
    /// Wrap a [`SealOutput`] into a signed `SealedSecrets` for `exec_id`.
    pub fn new_signed(exec_id: Uuid, seal: SealOutput, signing_key: &DispatchSigningKey) -> Self {
        use ed25519_dalek::Signer;
        let issued_at_ms = now_ms();
        let bytes = sealed_secrets_signing_bytes(
            exec_id,
            &seal.epk_c,
            &seal.ciphertext,
            &seal.nonce,
            issued_at_ms,
        );
        let signature = signing_key.sign(&bytes).to_bytes().to_vec();
        Self {
            exec_id,
            epk_c: seal.epk_c,
            ciphertext: seal.ciphertext,
            nonce: seal.nonce,
            issued_at_ms,
            signature,
        }
    }

    /// Signature + freshness verification (the worker is the single primary
    /// caller). `verifying_key` is the controller's pinned dispatch public key.
    pub fn verify(
        &self,
        verifying_key: &DispatchVerifyingKey,
        max_age_secs: u64,
    ) -> Result<(), String> {
        self.verify_no_replay(verifying_key, max_age_secs)
    }

    /// Signature + freshness ONLY. A replayed `SealedSecrets` is inert: it opens
    /// only under the matching per-execution ephemeral secret (already consumed
    /// after the first open) and its AAD binds the exact `exec_id`/`epk_w`, so
    /// there is no process-local cache to protect. Twin provided per discipline.
    pub fn verify_no_replay(
        &self,
        verifying_key: &DispatchVerifyingKey,
        max_age_secs: u64,
    ) -> Result<(), String> {
        check_freshness(self.issued_at_ms, max_age_secs)?;
        let sig_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| "SealedSecrets signature must be 64 bytes".to_string())?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        let bytes = sealed_secrets_signing_bytes(
            self.exec_id,
            &self.epk_c,
            &self.ciphertext,
            &self.nonce,
            self.issued_at_ms,
        );
        verifying_key
            .verify_strict(&bytes, &sig)
            .map_err(|_| "SealedSecrets signature verification failed".to_string())
    }
}

/// The controller's reply to a `SecretClaim` on the claim inbox: either the
/// sealed secrets, or a generic rejection (unknown/already-claimed execution,
/// unauthorized claim, seal failure — all collapsed so the worker learns
/// nothing about which check failed). The worker drops the job without running
/// on `Rejected`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClaimResponse {
    Sealed(SealedSecrets),
    Rejected { reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kp() -> (DispatchSigningKey, DispatchVerifyingKey) {
        let sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    #[test]
    fn seal_open_roundtrip() {
        let exec_id = Uuid::new_v4();
        let worker_id = "worker-1";
        let we = WorkerEphemeral::generate();
        let epk_w = we.public_key();
        let secret = br#"{"anthropic/api_key":"sk-ant-xxx"}"#;

        let sealed = seal_secrets(&epk_w, exec_id, worker_id, secret).unwrap();
        let opened = we
            .open(
                &sealed.epk_c,
                exec_id,
                worker_id,
                &sealed.ciphertext,
                &sealed.nonce,
            )
            .unwrap();
        assert_eq!(opened, secret);
    }

    #[test]
    fn open_fails_with_wrong_epk_c() {
        let exec_id = Uuid::new_v4();
        let we = WorkerEphemeral::generate();
        let epk_w = we.public_key();
        let sealed = seal_secrets(&epk_w, exec_id, "w", b"payload").unwrap();
        // Substitute a different controller ephemeral public key.
        let other = WorkerEphemeral::generate().public_key();
        let err = we.open(&other, exec_id, "w", &sealed.ciphertext, &sealed.nonce);
        assert!(err.is_err(), "wrong epk_c must not open");
    }

    #[test]
    fn aad_transposition_fails() {
        // A seal made for (exec_A, worker) must not open under exec_B, and a
        // seal for worker-A must not open for worker-B — the AAD binds both.
        let exec_a = Uuid::new_v4();
        let exec_b = Uuid::new_v4();
        let we = WorkerEphemeral::generate();
        let epk_w = we.public_key();
        let sealed = seal_secrets(&epk_w, exec_a, "worker-A", b"top-secret").unwrap();

        // Re-generate the ephemeral is impossible (consumed on open); make two.
        let we2 = WorkerEphemeral::generate();
        // Build a fresh seal to worker-A/exec-A but try to open as exec-B.
        let sealed2 = seal_secrets(&we2.public_key(), exec_a, "worker-A", b"top-secret").unwrap();
        let wrong_exec = we2.open(
            &sealed2.epk_c,
            exec_b,
            "worker-A",
            &sealed2.ciphertext,
            &sealed2.nonce,
        );
        assert!(wrong_exec.is_err(), "wrong exec_id AAD must fail");

        let we3 = WorkerEphemeral::generate();
        let sealed3 = seal_secrets(&we3.public_key(), exec_a, "worker-A", b"top-secret").unwrap();
        let wrong_worker = we3.open(
            &sealed3.epk_c,
            exec_a,
            "worker-B",
            &sealed3.ciphertext,
            &sealed3.nonce,
        );
        assert!(wrong_worker.is_err(), "wrong worker_id AAD must fail");
        let _ = sealed; // silence unused in some cfgs
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let exec_id = Uuid::new_v4();
        let we = WorkerEphemeral::generate();
        let mut sealed = seal_secrets(&we.public_key(), exec_id, "w", b"payload").unwrap();
        sealed.ciphertext[0] ^= 0xff;
        let err = we.open(
            &sealed.epk_c,
            exec_id,
            "w",
            &sealed.ciphertext,
            &sealed.nonce,
        );
        assert!(err.is_err(), "tampered ciphertext must fail the GCM tag");
    }

    #[test]
    fn secret_claim_sign_verify_roundtrip() {
        let (sk, vk) = kp();
        let claim = SecretClaim::new_signed(Uuid::new_v4(), "worker-9".into(), [7u8; 32], &sk);
        claim
            .verify(&vk, 60)
            .expect("fresh, correctly signed claim verifies");
    }

    #[test]
    fn secret_claim_wrong_key_fails() {
        let (sk, _vk) = kp();
        let (_sk2, vk2) = kp();
        let claim = SecretClaim::new_signed(Uuid::new_v4(), "worker-9".into(), [7u8; 32], &sk);
        // Verifying under a DIFFERENT key (a claim not signed by the registered
        // long-term key) must fail — this is the ephemeral-key authenticity
        // property.
        assert!(claim.verify(&vk2, 60).is_err());
    }

    #[test]
    fn secret_claim_tampered_epk_fails() {
        let (sk, vk) = kp();
        let mut claim = SecretClaim::new_signed(Uuid::new_v4(), "worker-9".into(), [7u8; 32], &sk);
        claim.epk_w = [8u8; 32]; // attacker substitutes its own ephemeral key
        assert!(
            claim.verify(&vk, 60).is_err(),
            "substituted epk_w must invalidate the claim"
        );
    }

    #[test]
    fn secret_claim_stale_fails() {
        let (sk, vk) = kp();
        let mut claim = SecretClaim::new_signed(Uuid::new_v4(), "w".into(), [7u8; 32], &sk);
        claim.issued_at_ms = 1; // ancient
                                // Re-sign so the signature is valid but the timestamp is stale.
        let bytes = secret_claim_signing_bytes(
            claim.exec_id,
            &claim.worker_id,
            &claim.epk_w,
            &claim.claim_nonce,
            claim.issued_at_ms,
            claim.crypto_scheme,
        );
        use ed25519_dalek::Signer;
        claim.signature = sk.sign(&bytes).to_bytes().to_vec();
        assert!(
            claim.verify(&vk, 60).is_err(),
            "stale claim must be rejected by freshness"
        );
    }

    #[test]
    fn sealed_secrets_sign_verify_roundtrip() {
        let (sk, vk) = kp();
        let exec_id = Uuid::new_v4();
        let we = WorkerEphemeral::generate();
        let seal = seal_secrets(&we.public_key(), exec_id, "w", b"data").unwrap();
        let ss = SealedSecrets::new_signed(exec_id, seal, &sk);
        ss.verify(&vk, 60)
            .expect("controller-signed SealedSecrets verifies");
    }

    #[test]
    fn sealed_secrets_wrong_key_fails() {
        let (sk, _vk) = kp();
        let (_sk2, vk2) = kp();
        let exec_id = Uuid::new_v4();
        let we = WorkerEphemeral::generate();
        let seal = seal_secrets(&we.public_key(), exec_id, "w", b"data").unwrap();
        let ss = SealedSecrets::new_signed(exec_id, seal, &sk);
        assert!(ss.verify(&vk2, 60).is_err());
    }

    #[test]
    fn sealed_secrets_tampered_ciphertext_fails_signature() {
        let (sk, vk) = kp();
        let exec_id = Uuid::new_v4();
        let we = WorkerEphemeral::generate();
        let seal = seal_secrets(&we.public_key(), exec_id, "w", b"data").unwrap();
        let mut ss = SealedSecrets::new_signed(exec_id, seal, &sk);
        ss.ciphertext.push(0x00);
        assert!(
            ss.verify(&vk, 60).is_err(),
            "ciphertext is signed; tamper must fail verify"
        );
    }
}
