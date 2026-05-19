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
}
