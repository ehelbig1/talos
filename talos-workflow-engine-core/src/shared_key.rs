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
}
