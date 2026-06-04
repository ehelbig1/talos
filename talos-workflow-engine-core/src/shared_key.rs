//! Shared HMAC signing key for engine↔worker authentication.
//!
//! [`WorkerSharedKey`] is the opaque newtype every engine public-API entry
//! point takes in place of a raw `Arc<Vec<u8>>` / `&[u8]`. It exists for
//! three reasons:
//!
//! * **Cheap to share.** The inner representation is `Arc<[u8]>` (single
//!   indirection, no `Vec` overhead), so the engine can clone it into the
//!   many spawned dispatch tasks a single run produces without copying the
//!   key bytes.
//! * **Semantic.** A `WorkerSharedKey` at the type level says "this is an
//!   HMAC signing key the worker fleet shares," which an
//!   `Option<Arc<Vec<u8>>>` cannot. Callers can't accidentally swap in an
//!   unrelated byte buffer.
//! * **Redacted by default.** The `Debug` impl never prints the key bytes,
//!   so a stray `tracing::debug!(?key, ...)` at a call site cannot leak the
//!   secret into logs.

use std::sync::Arc;

/// Shared HMAC-SHA256 signing key used to authenticate job dispatch between
/// the workflow engine and its worker pool.
///
/// The engine itself never inspects these bytes — it forwards them to the
/// pluggable [`NodeDispatcher`](crate::NodeDispatcher) impl, which signs
/// the wire envelope and seals per-dispatch secrets under them. Consumers
/// typically source the key from an environment variable or secrets
/// manager at startup (see `talos_workflow_job_protocol::load_worker_shared_key`).
///
/// # Cloning
///
/// `Clone` is a single atomic refcount bump on the inner `Arc<[u8]>`; the
/// key bytes are shared, not copied. This makes it safe to pass into the
/// many spawned dispatch tasks a single engine run produces.
///
/// # Debug
///
/// The `Debug` impl deliberately does not print the key bytes. It reports
/// only the byte length, so logging a `WorkerSharedKey` via `?key` cannot
/// leak the secret.
///
/// # Example
///
/// ```
/// use talos_workflow_engine_core::WorkerSharedKey;
///
/// // From raw bytes (e.g. `openssl rand -hex 32` decoded).
/// let key = WorkerSharedKey::new(vec![0u8; 32]);
/// assert_eq!(key.as_bytes().len(), 32);
///
/// // Cheap to clone — shares the Arc<[u8]> under the hood.
/// let _ = key.clone();
///
/// // Debug output never reveals the key bytes.
/// let debug_str = format!("{:?}", key);
/// assert!(debug_str.contains("redacted"));
/// ```
#[derive(Clone)]
pub struct WorkerSharedKey(Arc<[u8]>);

impl WorkerSharedKey {
    /// Wrap raw key bytes.
    ///
    /// Accepts any `Into<Arc<[u8]>>` — `Vec<u8>`, `&[u8]`, `Box<[u8]>`, or
    /// an existing `Arc<[u8]>`. The conversion is zero-copy for types that
    /// already own their bytes heap-allocated.
    #[must_use]
    pub fn new(bytes: impl Into<Arc<[u8]>>) -> Self {
        Self(bytes.into())
    }

    /// Borrow the key bytes for signing / sealing use.
    ///
    /// The returned slice is valid for the lifetime of the borrow; the
    /// underlying `Arc` keeps the bytes alive.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Key length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// `true` iff the key has zero bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for WorkerSharedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("WorkerSharedKey")
            .field(&format_args!("<redacted; {} bytes>", self.0.len()))
            .finish()
    }
}

impl AsRef<[u8]> for WorkerSharedKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// An ordered set of [`WorkerSharedKey`]s enabling **restart-free rotation**
/// of the shared HMAC signing key.
///
/// `keys[0]` (the *signing key*) signs every new outbound message; **all**
/// elements (signing + previous) are accepted candidates when *verifying* an
/// inbound signature. Holding more than one key is the entire mechanism: it
/// lets the new key be deployed while signatures made under the old key are
/// still accepted, so a rolling restart no longer opens a window where every
/// signed NATS RPC is rejected.
///
/// # Relationship to the loader's "intentional" note
///
/// The shared-key loader historically documented that rotation *requires a
/// simultaneous restart*, on two grounds: (1) a "key-ID negotiation protocol
/// is hard to get right", and (2) "a botched live rotation is a silent
/// signature bypass." A verify-ring answers both:
///
/// * **No negotiation, no wire change.** Verification simply tries each
///   candidate key. Nothing on the wire carries a key ID; the message format
///   is byte-for-byte unchanged. This is exactly what the worker's
///   `AotKeyRing` already does for AOT-blob integrity — a *higher*-stakes key
///   (its compromise yields native code execution via `Component::deserialize`).
/// * **Not silent.** Accepting a previous key is explicit, fingerprint-logged
///   at startup, time-bounded by the operator (remove `*_PREVIOUS` after
///   rollout), and — for the freshness-gated RPC/job messages — additionally
///   bounded by the ~60 s replay window. The failure mode of forgetting to
///   remove the previous key is "an old, deliberately-staged key keeps
///   working for a while", not "any key passes".
///
/// # Rotation workflow
///
/// 1. Set `WORKER_SHARED_KEY=<new>` and `WORKER_SHARED_KEY_PREVIOUS=<old>` on
///    the controller and every worker.
/// 2. Rolling restart. New messages sign under `<new>`; in-flight messages
///    signed under `<old>` still verify.
/// 3. Once the freshness window has elapsed (and, for at-rest material such as
///    checkpoints, once old-key-encrypted rows have drained — see the separate
///    decrypt-ring work), remove `WORKER_SHARED_KEY_PREVIOUS`.
///
/// # Invariant
///
/// A `WorkerKeyRing` is **never empty**; `signing_key()` and `verify_keys()`
/// therefore never panic and never return an empty slice.
#[derive(Clone)]
pub struct WorkerKeyRing {
    // INVARIANT: non-empty; `keys[0]` is the signing key, the remainder are
    // verify-only previous keys in the order they were supplied.
    keys: Vec<WorkerSharedKey>,
}

impl WorkerKeyRing {
    /// Build a ring from a signing key plus zero or more previous
    /// (verify-only) keys. The signing key is always `verify_keys()[0]`.
    #[must_use]
    pub fn new(
        signing: WorkerSharedKey,
        previous: impl IntoIterator<Item = WorkerSharedKey>,
    ) -> Self {
        let mut keys = Vec::with_capacity(1);
        keys.push(signing);
        keys.extend(previous);
        Self { keys }
    }

    /// A ring with a single key — both the signer and the only accepted
    /// verifier. The common steady-state (no rotation in progress) and the
    /// drop-in replacement for a bare `WorkerSharedKey`.
    #[must_use]
    pub fn single(signing: WorkerSharedKey) -> Self {
        Self {
            keys: vec![signing],
        }
    }

    /// The key used to sign new outbound messages.
    #[must_use]
    pub fn signing_key(&self) -> &WorkerSharedKey {
        &self.keys[0] // INVARIANT: non-empty
    }

    /// All keys accepted when verifying an inbound signature, signing key
    /// first. Callers verify by trying each in turn (constant-time per
    /// candidate) and accepting on the first match.
    #[must_use]
    pub fn verify_keys(&self) -> &[WorkerSharedKey] {
        &self.keys
    }

    /// Number of keys in the ring (always ≥ 1).
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Always `false` — a ring is never empty. Present to satisfy clippy's
    /// `len_without_is_empty`; the invariant makes the answer constant.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }
}

impl std::fmt::Debug for WorkerKeyRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key bytes; report only the shape so a stray `?ring`
        // can't leak a secret. Mirrors `WorkerSharedKey`'s redaction.
        f.debug_struct("WorkerKeyRing")
            .field(
                "keys",
                &format_args!("<{} redacted key(s)>", self.keys.len()),
            )
            .finish()
    }
}

impl From<WorkerSharedKey> for WorkerKeyRing {
    fn from(signing: WorkerSharedKey) -> Self {
        Self::single(signing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_from_vec_preserves_bytes() {
        let key = WorkerSharedKey::new(vec![0xAB; 32]);
        assert_eq!(key.len(), 32);
        assert_eq!(key.as_bytes(), &[0xAB; 32]);
        assert!(!key.is_empty());
    }

    #[test]
    fn new_from_slice_preserves_bytes() {
        let bytes: &[u8] = &[1, 2, 3, 4];
        let key = WorkerSharedKey::new(bytes);
        assert_eq!(key.as_bytes(), bytes);
    }

    #[test]
    fn empty_key_reports_empty() {
        let key = WorkerSharedKey::new(Vec::new());
        assert_eq!(key.len(), 0);
        assert!(key.is_empty());
    }

    #[test]
    fn clone_shares_bytes_without_copy() {
        let key = WorkerSharedKey::new(vec![7u8; 32]);
        let cloned = key.clone();
        // Same backing allocation — checked via Arc pointer equality.
        assert!(Arc::ptr_eq(&key.0, &cloned.0));
    }

    #[test]
    fn debug_redacts_bytes_but_reports_length() {
        let key = WorkerSharedKey::new(vec![0xFFu8; 32]);
        let s = format!("{key:?}");
        assert!(s.contains("redacted"));
        assert!(s.contains("32"));
        // Ensure the actual byte representation is not present.
        assert!(!s.contains("FF"));
        assert!(!s.contains("255"));
    }

    #[test]
    fn as_ref_returns_same_slice_as_as_bytes() {
        let key = WorkerSharedKey::new(vec![9u8; 8]);
        let via_as_ref: &[u8] = key.as_ref();
        assert_eq!(via_as_ref, key.as_bytes());
    }

    #[test]
    fn ring_single_has_one_key_that_is_both_signer_and_verifier() {
        let ring = WorkerKeyRing::single(WorkerSharedKey::new(vec![0xABu8; 32]));
        assert_eq!(ring.len(), 1);
        assert!(!ring.is_empty());
        assert_eq!(ring.signing_key().as_bytes(), &[0xABu8; 32]);
        assert_eq!(ring.verify_keys().len(), 1);
        assert_eq!(ring.verify_keys()[0].as_bytes(), &[0xABu8; 32]);
    }

    #[test]
    fn ring_signs_with_first_key_and_verifies_against_all() {
        let signing = WorkerSharedKey::new(vec![1u8; 32]);
        let prev_a = WorkerSharedKey::new(vec![2u8; 32]);
        let prev_b = WorkerSharedKey::new(vec![3u8; 32]);
        let ring = WorkerKeyRing::new(signing, [prev_a, prev_b]);

        assert_eq!(ring.len(), 3);
        // Signing key is always the first verify candidate.
        assert_eq!(ring.signing_key().as_bytes(), &[1u8; 32]);
        let verify: Vec<&[u8]> = ring.verify_keys().iter().map(|k| k.as_bytes()).collect();
        assert_eq!(verify, vec![&[1u8; 32][..], &[2u8; 32][..], &[3u8; 32][..]]);
    }

    #[test]
    fn ring_from_single_key_matches_single_constructor() {
        let key = WorkerSharedKey::new(vec![7u8; 32]);
        let ring: WorkerKeyRing = key.clone().into();
        assert_eq!(ring.len(), 1);
        assert_eq!(ring.signing_key().as_bytes(), key.as_bytes());
    }

    #[test]
    fn ring_debug_redacts_bytes_but_reports_count() {
        let ring = WorkerKeyRing::new(
            WorkerSharedKey::new(vec![0xFFu8; 32]),
            [WorkerSharedKey::new(vec![0xEEu8; 32])],
        );
        let s = format!("{ring:?}");
        assert!(s.contains("redacted"));
        assert!(s.contains('2')); // two keys
        assert!(!s.contains("FF"));
        assert!(!s.contains("255"));
    }
}
