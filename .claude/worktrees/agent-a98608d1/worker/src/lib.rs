//! Talos worker library exposing the runtime and host implementations.
#![allow(dead_code, unused_imports)]

pub mod audit;
pub mod bindings;
pub mod context;
pub mod host_impl;
pub mod metrics;
pub mod metrics_server;
pub mod runtime;
pub mod tracing;
pub mod wit_inspector;

pub use runtime::TalosRuntime;
pub use wit_inspector::{
    inspect_component, validate_capability_level, CapabilityWorld, ComponentInspection,
};
