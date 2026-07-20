// MCP-946 (2026-05-15): kept `#![allow(dead_code)]` deliberately.
// The crate carries several pre-existing dead items audited in this
// sweep but not removable in a one-shot doc-style sweep:
//   * `DLQ_MAX_PENDING` const + `enqueue_webhook_dlq` function:
//     vestigial OLD-DLQ surface superseded by `DlqService` (stored
//     on WebhookRouter at line ~245). The old function does
//     DLP-aware header sanitization that no caller reaches.
//   * `event_sender: tokio::sync::broadcast::Sender<ExecutionEvent>`
//     field on WebhookRouter: stored in the constructor but never
//     read. Either the broadcast logic was supposed to wire up
//     and didn't, or the field is leftover from a refactor.
//   * `allow` method in src/rate_limiter.rs: dead implementation
//     (the WebhookRouter uses the IpRateLimiter via different
//     plumbing).
// Each needs careful surgical removal (constructor signature
// changes ripple to main.rs + tests for event_sender; the DLQ
// helpers contain non-trivial security logic worth verifying isn't
// the new path's de-facto contract). Tracked as cleanup follow-ups.
#![allow(dead_code)]
//! Webhook router manages incoming webhook requests with security features
//! including circuit breakers, rate limiting, HMAC verification, and DLQ support.

mod approval;

/// Minimal HTML escape for dynamic content embedded in the public
/// token-authenticated pages (approval gates, correction links). ONE
/// copy for the whole crate — these pages render externally-influenced
/// text (gate titles, alert titles from email/GCP payloads) on
/// unauthenticated endpoints, so a hardening fix must never land in
/// one page's private escaper and miss another's.
pub(crate) fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
mod correction;
mod dlq;
#[allow(
    clippy::needless_borrow,
    clippy::needless_borrows_for_generic_args,
    clippy::option_as_ref_deref,
    clippy::too_many_arguments,
    clippy::unused_async
)]
mod rate_limiter;
mod router;
mod suspension;
mod types;

pub use rate_limiter::CircuitBreaker;
pub use rate_limiter::CircuitBreakerFailureType;

pub use approval::{
    approval_gate_handler, approval_gate_preview, approval_handler, ApprovalPayload,
};
pub use correction::{correction_apply, correction_preview};
pub use dlq::{DlqMetrics, DlqService};
pub use router::{webhook_handler, WebhookRouter};
pub use suspension::suspension_callback_handler;
pub use types::{validate_event_filter, WebhookTrigger};
