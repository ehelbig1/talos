//! Talos worker library exposing the runtime and host implementations.
//!
//! The `worker` binary (`main.rs`) consumes this library crate (`use
//! worker::…`) rather than re-declaring the same modules — one module
//! tree, compiled once.

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
pub mod metrics_server;
pub mod module_fetcher;
pub mod runtime;
pub mod s3_signer;
pub mod self_register;
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
