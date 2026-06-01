//! [`JobTransport`] implementation backed by NATS.
//!
//! Thin newtype wrapper around [`async_nats::Client`] so the orphan
//! rule permits the trait impl (both `JobTransport` and the client
//! live in foreign crates). Production code holds
//! `Arc<NatsTransport>` and passes it where `Arc<dyn JobTransport>`
//! is expected — the unsized coercion covers the cast at call sites.
//!
//! This is the only place in the crate where the engine's transport
//! abstraction meets the concrete NATS client. Timeout handling is
//! the caller's responsibility per the trait contract; the engine's
//! retry helpers wrap each `request` call in `tokio::time::timeout`
//! so a stuck broker never blocks the dispatch loop.

use std::sync::Arc;

use async_trait::async_trait;
use futures::StreamExt;
use talos_workflow_engine_core::{BoxError, JobTransport};

/// Newtype wrapper around `async_nats::Client` that implements
/// [`JobTransport`]. Construct once at startup from a shared
/// `Arc<async_nats::Client>` and pass the resulting
/// `Arc<NatsTransport>` into `run` / `run_with_seed` (or through an
/// `Arc<dyn JobTransport>` coercion).
pub struct NatsTransport {
    client: Arc<async_nats::Client>,
}

impl NatsTransport {
    /// Build a transport around an existing client.
    #[must_use]
    pub fn new(client: Arc<async_nats::Client>) -> Self {
        Self { client }
    }

    /// Convenience: wrap a shared NATS client into an
    /// `Arc<dyn JobTransport>` ready to pass into engine entry points.
    /// Saves callers from the `Arc::new(NatsTransport::new(...))` dance
    /// at every dispatch site.
    #[must_use]
    pub fn shared(client: Arc<async_nats::Client>) -> Arc<dyn JobTransport> {
        Arc::new(Self::new(client))
    }
}

impl std::fmt::Debug for NatsTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NatsTransport").finish_non_exhaustive()
    }
}

#[async_trait]
impl JobTransport for NatsTransport {
    async fn request(&self, topic: &str, payload: Vec<u8>) -> Result<Vec<u8>, BoxError> {
        let reply = self
            .client
            .request(topic.to_string(), payload.into())
            .await
            .map_err(|e| -> BoxError { e.to_string().into() })?;
        Ok(reply.payload.to_vec())
    }

    /// H-1: pre-allocate a unique NATS inbox subject via
    /// [`async_nats::Client::new_inbox`]. The returned string is
    /// safe to bind into the JobRequest's `reply_topic` and then
    /// hand back to [`request_with_reply_inbox`].
    fn new_reply_inbox(&self) -> Option<String> {
        Some(self.client.new_inbox())
    }

    /// H-1: subscribe to `reply_inbox` BEFORE publishing so we don't
    /// race the worker's reply, then publish with reply set to the
    /// same inbox, and await exactly one message on the subscription.
    ///
    /// Lifetime contract:
    /// - The subscription is dropped at function return (via the
    ///   `_sub` guard going out of scope). NATS auto-unsubscribes
    ///   when the local `Subscriber` is dropped, so we don't leak
    ///   subscriptions on broker or timeout failures.
    /// - The caller wraps this in `tokio::time::timeout` per the
    ///   trait-level contract; a malicious worker that never
    ///   replies cannot block this method forever.
    async fn request_with_reply_inbox(
        &self,
        topic: &str,
        reply_inbox: &str,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, BoxError> {
        let mut sub = self
            .client
            .subscribe(reply_inbox.to_string())
            .await
            .map_err(|e| -> BoxError { format!("inbox subscribe: {e}").into() })?;
        self.client
            .publish_with_reply(topic.to_string(), reply_inbox.to_string(), payload.into())
            .await
            .map_err(|e| -> BoxError { format!("publish_with_reply: {e}").into() })?;
        // Best-effort flush so the publish doesn't sit in the local
        // outbox while we wait for a reply. Errors here are not fatal
        // — `next()` will simply time out if the broker disconnects.
        let _ = self.client.flush().await;
        match sub.next().await {
            Some(msg) => Ok(msg.payload.to_vec()),
            None => Err("inbox subscription closed before reply arrived".into()),
        }
    }
}
