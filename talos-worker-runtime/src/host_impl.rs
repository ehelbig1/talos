//! Re-export shim — the host function implementations moved to the
//! per-interface modules under [`crate::host`] (see `host/mod.rs`).
//!
//! Kept so every existing `crate::host_impl::<item>` path keeps
//! resolving, mirroring the controller's re-export-shim convention.

pub use crate::host::*;
