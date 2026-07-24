//! Cryptographic audit events moved to the shared `talos-audit-event` crate
//! so the controller-side WORM persister and the offline chain verifier run
//! the SAME canonical hashing/signing code as this producer (no drift).
//! `crate::audit::{AuditEvent, ExecutionLedger}` paths keep resolving via
//! this re-export.
// Re-export only what the worker (producer) names. The consumer-side
// verification API (`audit_verify_keys`, `verify_chain`, …) is imported
// straight from `talos_audit_event` by the controller-side crate.
// `AuditEvent` is named only in `audit_tests.rs`, hence allow(unused) for
// non-test builds.
#[allow(unused_imports)]
pub use talos_audit_event::{AuditEvent, ExecutionLedger};

#[cfg(test)]
#[path = "audit_tests.rs"]
// The included file wraps its content in its own `mod tests` —
// latent clippy::module_inception surfaced by `--all-targets`.
#[allow(clippy::module_inception)]
mod tests;
