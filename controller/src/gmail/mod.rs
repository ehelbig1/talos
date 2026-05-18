//! Re-export shim for the extracted `talos-gmail` crate.
//!
//! Nine sub-modules (`admin`, `api`, `dispatch`, `handlers`,
//! `integration`, `pubsub_jwt`, `scheduler`, `watch`,
//! `watch_channel_service`) plus the top-level `GmailApiClient`,
//! `GmailIntegration`, `GmailIntegrationInfo`, `GmailIntegrationService`,
//! and the five axum handlers all live in `talos-gmail`. This shim
//! preserves the existing `crate::gmail::*` import path used by
//! `controller::main` for service construction and route wiring under
//! `/api/gmail/*`, plus the Pub/Sub push endpoint and renewal
//! background task.

#![allow(unused_imports)]

pub use talos_gmail::*;

pub mod admin {
    pub use talos_gmail::admin::*;
}
pub mod api {
    pub use talos_gmail::api::*;
}
pub mod dispatch {
    pub use talos_gmail::dispatch::*;
}
pub mod handlers {
    pub use talos_gmail::handlers::*;
}
pub mod integration {
    pub use talos_gmail::integration::*;
}
pub mod pubsub_jwt {
    pub use talos_gmail::pubsub_jwt::*;
}
pub mod scheduler {
    pub use talos_gmail::scheduler::*;
}
pub mod watch {
    pub use talos_gmail::watch::*;
}
pub mod watch_channel_service {
    pub use talos_gmail::watch_channel_service::*;
}
