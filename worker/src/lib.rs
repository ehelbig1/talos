//! Talos worker library exposing the runtime and host implementations.
#![allow(dead_code, unused_imports)]

pub mod audit;
pub mod bindings;
pub mod circuit_breaker;
pub mod context;
pub mod expose_fallback;
pub mod host_impl;
pub mod metrics;
pub mod metrics_server;
pub mod runtime;
pub mod s3_signer;
pub mod sql_validator;
pub mod ssrf_resolver;
pub mod tracing;
pub mod wit_inspector;
pub mod worker_identity;

pub use runtime::TalosRuntime;
pub use wit_inspector::{
    inspect_component, validate_capability_level, CapabilityWorld, ComponentInspection,
};
pub use worker_identity::worker_identity;
