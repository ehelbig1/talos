//! Re-export shim for the extracted `talos-slack` crate.
//!
//! Submodules (`integration`, `handlers`) plus the top-level
//! `SlackApiClient`, `SlackIntegration`, `SlackIntegrationInfo`,
//! `SlackIntegrationService`, and the six axum handlers all live in
//! `talos-slack`. The shim preserves the existing `crate::slack::*`
//! import path used by `controller::main` for service construction
//! and route wiring under `/api/slack/*`.

#![allow(unused_imports)]

pub use talos_slack::*;

pub mod handlers {
    pub use talos_slack::handlers::*;
}
pub mod integration {
    pub use talos_slack::integration::*;
}
