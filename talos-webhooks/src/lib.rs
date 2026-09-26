//! Webhook router manages incoming webhook requests with security features
//! including circuit breakers, rate limiting, HMAC verification, and DLQ support.

mod approval;
mod approval_actions;

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
mod dispatch_failure;
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
mod signature;
mod suspension;
mod types;

pub use rate_limiter::CircuitBreaker;
pub use rate_limiter::CircuitBreakerFailureType;

pub use approval::{
    approval_gate_handler, approval_gate_preview, approval_handler, ApprovalPayload,
};
pub use approval_actions::{approval_action_apply, approval_action_preview};
pub use correction::{correction_apply, correction_preview};
pub use dispatch_failure::{drop_reason as dlq_drop_reason, ModuleDispatchFailure};
pub use dlq::{
    dlq_entry_was_authenticated, DlqMetrics, DlqService, ReplayRefused, DLQ_AUTHENTICATED_KEY,
};
pub use router::{insert_webhook_module_execution, webhook_handler, WebhookRouter};
pub use signature::{
    body_fingerprint, dedup_fingerprint, header_is_sensitive, VerifiedSignatureFormat,
    WebhookAuthOutcome,
};
pub use suspension::{suspension_callback_handler, SUSPENSION_CALLBACK_MAX_BODY_BYTES};
pub use types::{validate_event_filter, WebhookTrigger};
