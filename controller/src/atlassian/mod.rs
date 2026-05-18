//! Re-export shim for the extracted `talos-atlassian` crate.
//!
//! Both submodules (`handlers`, `integration`) plus the top-level
//! re-exports (`AtlassianIntegrationService`, `AtlassianIntegrationInfo`,
//! and the four `*_handler` axum endpoints) live in `talos-atlassian`.
//! This shim preserves the existing `crate::atlassian::*` import path
//! used by `controller::main` for service construction and route wiring
//! under `/api/atlassian/*`.

#![allow(unused_imports)]

pub use talos_atlassian::*;

pub mod handlers {
    pub use talos_atlassian::handlers::*;
}
pub mod integration {
    pub use talos_atlassian::integration::*;
}
