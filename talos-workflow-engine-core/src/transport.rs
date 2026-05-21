//! Pluggable transport for dispatching serialized jobs to a worker pool.
//!
//! The engine builds a `JobRequest`-shaped payload (opaque to this
//! trait), signs it, and hands the bytes to the transport. The
//! transport sends them to a worker pool identified by `topic` and
//! returns the raw response bytes back to the engine for parsing.
//!
//! This is the engine's only outbound I/O dependency for job
//! execution. Typical impls:
//!
//! * A NATS `request()` call for a distributed worker pool — the
//!   reference production default, shipped in the sibling
//!   `talos-workflow-engine-nats` crate.
//! * An in-process Tokio channel for tests — sidesteps the need for a
//!   running broker.
//! * An HTTP round-trip for simpler single-worker deployments.
//!
//! # Timeout handling — caller responsibility
//!
//! The trait deliberately does **not** take a timeout parameter. Impls
//! are free to block as long as the underlying transport takes (or, in
//! a buggy impl, forever); **callers MUST wrap every `request` call
//! in `tokio::time::timeout` (or an equivalent cancellation
//! mechanism)**. Keeping timeout at the caller lets the retry loop
//! distinguish "timed out" from "transport failure" — they have
//! different retry semantics (timeouts should not be retried, since
//! the job may still be running worker-side and a retry would
//! duplicate it).
//!
//! The engine's retry helpers already do this. If you write a new
//! caller from scratch, the pattern looks like:
//!
//! ```text
//! let result = tokio::time::timeout(
//!     Duration::from_secs(30),
//!     transport.request(topic, payload),
//! )
//! .await;
//!
//! match result {
//!     Ok(Ok(response)) => { /* success */ }
//!     Ok(Err(e))       => { /* retryable transport failure */ }
//!     Err(_elapsed)    => { /* timeout — do NOT retry */ }
//! }
//! ```

use async_trait::async_trait;

use crate::BoxError;

/// Send one serialized job to a worker and await its response.
///
/// # Contract
///
/// * `topic` identifies the destination worker pool. The shape is
///   transport-specific (NATS subject, HTTP path, etc.); the engine
///   composes it according to the policy the transport documents.
/// * `payload` is already serialized and signed by the engine. The
///   transport treats it as opaque bytes.
/// * Returns the raw response bytes on success. Parsing (into a
///   `JobResult`-shaped value) is the engine's responsibility.
///
/// # Error handling
///
/// Transport errors — connection failures, broker rejections,
/// worker-side decode errors — surface as `Err(BoxError)`. The engine
/// classifies the error and decides whether to retry; the transport
/// does not retry internally and does not own a timeout budget. See
/// the module docs for the timeout rationale.
#[async_trait]
pub trait JobTransport: Send + Sync {
    /// Send `payload` to the worker pool at `topic` and await a reply.
    /// See the trait-level docs for the full contract.
    async fn request(&self, topic: &str, payload: Vec<u8>) -> Result<Vec<u8>, BoxError>;

    /// H-1: Pre-allocate a unique reply-inbox subject for the next
    /// [`request_with_reply_inbox`] call.
    ///
    /// When `Some(inbox)`, the dispatcher binds the inbox subject
    /// into the JobRequest's signed `reply_topic` field, so the
    /// worker can verify the wire `msg.reply` against the
    /// HMAC-protected value and refuse to publish results to an
    /// attacker-redirected subject.
    ///
    /// `None` (default) signals that the transport does not support
    /// inbox pre-allocation. Callers fall back to the legacy
    /// [`request`] flow, which trusts the unsigned wire `msg.reply`.
    /// Test transports and stub impls can stay on the default.
    fn new_reply_inbox(&self) -> Option<String> {
        None
    }

    /// H-1: Publish `payload` to `topic` with `reply_inbox` as the
    /// reply-subject and await one reply on that inbox. The caller
    /// is responsible for having bound `reply_inbox` into the
    /// signed payload via [`new_reply_inbox`] first.
    ///
    /// The default implementation delegates to [`request`] (ignoring
    /// the inbox) so transports that don't override are still
    /// usable — they just don't get the reply-topic binding
    /// guarantee. Callers MUST check [`new_reply_inbox`] first to
    /// know whether this method has a useful implementation; the
    /// dispatcher does exactly that.
    ///
    /// [`request`]: Self::request
    /// [`new_reply_inbox`]: Self::new_reply_inbox
    async fn request_with_reply_inbox(
        &self,
        topic: &str,
        _reply_inbox: &str,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, BoxError> {
        self.request(topic, payload).await
    }
}
