//! Re-export shim for the extracted `talos-webhooks` crate.
//!
//! `WebhookRouter`, the inbound handler chain (HMAC verification,
//! IP allowlisting, dedup, rate-limit, payload encryption,
//! workflow / module dispatch, approval-gate resolution via the
//! shared `talos-continuation-trigger` crate), `CircuitBreaker`,
//! and the rate_limiter sub-module all live in `talos-webhooks`.
//! This shim preserves the existing `crate::webhooks::*` import
//! path used by `controller::main` for service construction and
//! route wiring under `/webhooks/*`, plus the GraphQL mutations in
//! `api/schema/webhooks/mutations.rs` and the MCP wiring in
//! `mcp/mod.rs`.

#![allow(unused_imports)]

pub use talos_webhooks::*;
