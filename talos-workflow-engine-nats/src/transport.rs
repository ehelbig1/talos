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
        // Inject the current W3C trace context so the worker can link its
        // job span to the controller's `workflow` span. Empty (no-op) when no
        // span/propagator is active — never an error.
        let mut headers = async_nats::HeaderMap::new();
        talos_trace_nats::inject_trace_context(&mut headers);
        let reply = self
            .client
            .send_request(
                topic.to_string(),
                async_nats::Request::new()
                    .headers(headers)
                    .payload(payload.into()),
            )
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
        // Inject the current W3C trace context (controller `workflow` span) into
        // the job headers so the worker links its job span to it. The HMAC is
        // over the JobRequest payload, not NATS headers, so this does not affect
        // signature verification. No-op when no span/propagator is active.
        let mut headers = async_nats::HeaderMap::new();
        talos_trace_nats::inject_trace_context(&mut headers);
        self.client
            .publish_with_reply_and_headers(
                topic.to_string(),
                reply_inbox.to_string(),
                headers,
                payload.into(),
            )
            .await
            .map_err(|e| -> BoxError { format!("publish_with_reply: {e}").into() })?;
        // Best-effort flush so the publish doesn't sit in the local
        // outbox while we wait for a reply. Errors here are not fatal
        // — `next()` will simply time out if the broker disconnects.
        let _ = self.client.flush().await;
        match sub.next().await {
            Some(msg) => {
                // A NATS `503 No Responders` control message is a REPLY with
                // an EMPTY body, not an error — see
                // `no_responders_error_for` for why this check has to be
                // here and what it cost to be missing.
                if let Some(e) = no_responders_error_for(msg.status, topic) {
                    return Err(e);
                }
                Ok(msg.payload.to_vec())
            }
            None => Err("inbox subscription closed before reply arrived".into()),
        }
    }
}

/// Translate a NATS reply `status` into a delivery error when it is
/// `503 No Responders`, i.e. the server had ZERO subscribers on the job
/// subject at publish time and synthesised a reply so the requester would not
/// hang.
///
/// # Why this is not free plumbing
///
/// `async_nats::Client::request()` performs exactly this check internally
/// (`client.rs`, `if message.status == Some(StatusCode::NO_RESPONDERS)` →
/// `RequestErrorKind::NoResponders`), and every other NATS request/reply in
/// this workspace goes through it. This module is the one place that
/// hand-rolls request/reply — H-1 requires the reply inbox to be allocated
/// BEFORE the payload is signed, so the inbox can be HMAC-bound — and in
/// doing so it dropped the status check.
///
/// The 503 body is empty, so without this the empty payload flowed into
/// `serde_json::from_slice::<JobResult>` and surfaced as
/// **"Failed to parse job result: EOF while parsing a value at line 1
/// column 0"** — a message that blames the worker's output when in fact no
/// worker existed. It cost two production workflow failures (2026-07-29,
/// 2026-08-19), each an isolated dispatch with healthy neighbours either
/// side: the signature of a sub-second reconnect window, not a fleet outage.
///
/// Returning `Err` also re-arms machinery that already exists:
/// `dispatch_with_retry` retries delivery errors with backoff, but a 503
/// arrived as `Ok(Ok(response))` and returned immediately. A 503 is the
/// safest thing in the system to retry — zero subscribers means the message
/// reached nobody, so a retry cannot double-execute a non-idempotent module.
/// (The retry is still gated by the caller's `max_retries`; this does not
/// widen it.)
///
/// Pure so the branch is testable without a broker.
pub(crate) fn no_responders_error_for(
    status: Option<async_nats::StatusCode>,
    topic: &str,
) -> Option<BoxError> {
    if status == Some(async_nats::StatusCode::NO_RESPONDERS) {
        return Some(
            format!(
                "no responders on '{topic}': no worker was subscribed when the \
                 job was published (NATS 503). The job was delivered to nobody, \
                 so it is safe to retry."
            )
            .into(),
        );
    }
    None
}

#[cfg(test)]
mod no_responders_tests {
    use super::*;

    #[test]
    fn no_responders_status_becomes_a_delivery_error() {
        let e = no_responders_error_for(Some(async_nats::StatusCode::NO_RESPONDERS), "talos.jobs")
            .expect("503 must map to an error, not an empty payload");
        let msg = e.to_string();
        // The operator-visible attribution is the whole point of the fix: it
        // must name the fleet, not the payload.
        assert!(msg.contains("no responders"), "got: {msg}");
        assert!(msg.contains("talos.jobs"), "subject must be named: {msg}");
        assert!(
            !msg.contains("parse"),
            "must not blame the result payload: {msg}"
        );
    }

    #[test]
    fn ordinary_replies_pass_through() {
        assert!(no_responders_error_for(None, "talos.jobs").is_none());
        assert!(no_responders_error_for(Some(async_nats::StatusCode::OK), "talos.jobs").is_none());
    }

    /// Drives the CALL SITE, not just the pure helper above.
    ///
    /// This test exists because the pure-function test cannot fail if someone
    /// deletes the `no_responders_error_for(...)` call from
    /// `request_with_reply_inbox` — the "wrapper is wired but nothing calls
    /// it" gap that structural check 58's own documentation names as the hole
    /// a grep cannot close. Here the assertion runs through the real
    /// `JobTransport` impl against a real broker.
    ///
    /// GATED, and honestly so: without `TALOS_TEST_NATS_URL` it returns
    /// without asserting anything, exactly like the two live-NATS tests in
    /// `dispatcher.rs`. A skip is not a pass; the guard for that is running it
    /// against the dev stack, which is how this fix was validated.
    #[tokio::test]
    async fn call_site_converts_a_real_503_into_an_error() {
        let Ok(url) = std::env::var("TALOS_TEST_NATS_URL") else {
            eprintln!("skipping: set TALOS_TEST_NATS_URL to run");
            return;
        };
        if url.is_empty() {
            eprintln!("skipping: TALOS_TEST_NATS_URL is empty");
            return;
        }
        // Credentials may be supplied out-of-band for brokers that require
        // auth (the dev stack does); a bare URL is still the common case.
        let client = Arc::new(
            match (
                std::env::var("TALOS_TEST_NATS_USER"),
                std::env::var("TALOS_TEST_NATS_PASSWORD"),
            ) {
                (Ok(u), Ok(pw)) if !u.is_empty() => {
                    async_nats::ConnectOptions::with_user_and_password(u, pw)
                        .connect(&url)
                        .await
                        .expect("connect nats (user/password)")
                }
                _ => async_nats::connect(&url).await.expect("connect nats"),
            },
        );
        let transport = NatsTransport::new(client.clone());
        let inbox = client.new_inbox();

        // A subject with ZERO subscribers — the production condition.
        let err = transport
            .request_with_reply_inbox(
                "talos.jobs.nobody.is.listening.here",
                &inbox,
                b"{}".to_vec(),
            )
            .await
            .expect_err("a 503 must surface as an error, not an empty payload");

        let msg = err.to_string();
        assert!(
            msg.contains("no responders"),
            "the call site must attribute this to the fleet, got: {msg}"
        );
    }

    /// The exact production symptom, pinned: an EMPTY body — which is what a
    /// 503 carries — parses as `Eof`. This is the byte-for-byte string that
    /// appeared in `workflow_executions.error_message` on both occurrences,
    /// and it is what the status check above now prevents anyone from seeing.
    #[test]
    fn empty_payload_is_the_eof_parse_error_we_observed() {
        let err = serde_json::from_slice::<serde_json::Value>(b"")
            .expect_err("an empty payload cannot parse");
        assert_eq!(
            err.to_string(),
            "EOF while parsing a value at line 1 column 0"
        );
    }
}
