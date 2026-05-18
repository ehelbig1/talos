//! Re-export shim for the extracted `talos-wit-inspector` crate.
//!
//! Inspector logic moved to `talos-wit-inspector` so the controller's
//! `talos-compilation` crate can call `inspect_component` without
//! depending on this worker bin/lib (which would invert the dependency
//! direction — worker is the WASM runtime executor, the compiler is
//! upstream of it). All public symbols (`CapabilityWorld`,
//! `ComponentInspection`, `inspect_component`, `validate_capability_level`)
//! continue to resolve via `crate::wit_inspector::*` for runtime.rs and
//! lib.rs callers.

#![allow(unused_imports)]

pub use talos_wit_inspector::*;
