//! Re-export shim for the extracted `talos-google-cloud` crate.
//!
//! The sub-modules (`api`, `handlers`, `integration`, plus the Phase-B
//! push stack `watch` / `dispatch` / `watch_channel_service` / `admin`)
//! and the top-level `GoogleCloudIntegration*` types + axum handlers all
//! live in `talos-google-cloud`. This shim preserves the
//! `crate::google_cloud::*` import path used by `controller::main` for
//! service construction and route wiring under `/api/gcp/*`.

#![allow(unused_imports)]

pub use talos_google_cloud::*;

pub mod api {
    pub use talos_google_cloud::api::*;
}
pub mod handlers {
    pub use talos_google_cloud::handlers::*;
}
pub mod integration {
    pub use talos_google_cloud::integration::*;
}
pub mod watch {
    pub use talos_google_cloud::watch::*;
}
pub mod dispatch {
    pub use talos_google_cloud::dispatch::*;
}
pub mod watch_channel_service {
    pub use talos_google_cloud::watch_channel_service::*;
}
pub mod admin {
    pub use talos_google_cloud::admin::*;
}
