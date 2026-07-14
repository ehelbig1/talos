//! Re-export shim for the extracted `talos-google-cloud` crate.
//!
//! Three sub-modules (`api`, `handlers`, `integration`) plus the top-level
//! `GoogleCloudIntegration`, `GoogleCloudIntegrationInfo`,
//! `GoogleCloudIntegrationService`, and the axum handlers all live in
//! `talos-google-cloud`. This shim preserves the `crate::google_cloud::*`
//! import path used by `controller::main` for service construction and route
//! wiring under `/api/gcp/*`.

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
