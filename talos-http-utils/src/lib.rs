//! Small axum-layer utilities used by every Talos HTTP service.
//!
//! Three modules:
//! * [`request_id`] — middleware that generates / propagates an
//!   `X-Request-ID` header for distributed tracing and audit log
//!   correlation. Reads upstream value if present, otherwise mints
//!   a new UUID.
//! * [`sanitization`] — input sanitisation helpers for preventing log
//!   injection (control characters, ANSI escapes) and basic safe
//!   truncation. Use at API boundaries before logging or persisting.
//! * [`ssrf`] — outbound URL validator (SSRF guard). Use AT FIRE TIME
//!   for any URL that originated from caller input — webhooks, approval
//!   notifications, SLA alerts. Write-time validation alone leaves a
//!   gap when SSRF rules tighten between write and fire.
//!
//! All three are re-exported at the crate root so existing call sites
//! continue to resolve through thin shims.

pub mod request_id;
pub mod sanitization;
pub mod ssrf;
