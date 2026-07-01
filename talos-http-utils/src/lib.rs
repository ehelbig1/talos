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
//! * [`outbound`] — SSRF-safe outbound reqwest client builder. The
//!   connect-time DNS-rebinding resolver that complements the call-time
//!   [`ssrf`] check; every controller outbound-webhook fire site builds
//!   its client here so the resolver is reachable from every crate.

pub mod outbound;
pub mod request_id;
pub mod sanitization;
pub mod ssrf;
pub mod trusted_client;
