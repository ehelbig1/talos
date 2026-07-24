//! Talos worker runtime library — the wasmtime WASM host.
//!
//! Extracted from the `worker` crate (July 2026) so controller-side
//! consumers (talos-api, talos-mcp-handlers, talos-replay-service,
//! talos-google-calendar, controller) depend on a library crate instead
//! of the deployable worker binary. The `worker` bin crate keeps a thin
//! re-export shim (`worker/src/lib.rs`) so `worker::runtime::TalosRuntime`
//! style paths remain valid; bin-only modules (`main.rs`, `self_register`,
//! `metrics_server`, `secret_claim`) stay in `worker/`.

pub mod audit;
pub mod bindings;
pub mod circuit_breaker;
pub mod context;
pub mod error_sanitize;
pub mod expose_fallback;
pub mod host;
pub mod host_impl;
pub mod job_idempotency;
pub mod job_span;
pub mod metrics;
pub mod module_fetcher;
pub mod runtime;
pub mod s3_signer;
pub mod sql_validator;
pub mod ssrf_resolver;
pub mod trace_nats;
pub mod tracing;
pub mod wit_inspector;
pub mod worker_identity;

pub use runtime::TalosRuntime;
pub use wit_inspector::{
    inspect_component, validate_capability_level, CapabilityWorld, ComponentInspection,
};
pub use worker_identity::worker_identity;
