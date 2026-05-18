//! Re-export shim for the extracted `talos-google-calendar` crate.
//!
//! Eight sub-modules (`admin`, `api`, `handlers`, `scheduler`,
//! `watch`, `watch_channel_service`, `webhook_token`, plus the
//! orphaned `tests` source file) plus the top-level
//! `GoogleCalendarService`, `GoogleCalendarIntegration`, `WatchChannel`,
//! `CalendarEvent`, etc. all live in `talos-google-calendar`. This
//! shim preserves the existing `crate::google_calendar::*` import path
//! used by `controller::main` for service construction and route
//! wiring under `/api/google-calendar/*`, plus the cross-tree call
//! from `api/schema/modules/mutations.rs`.

#![allow(unused_imports)]

pub use talos_google_calendar::*;

pub mod admin {
    pub use talos_google_calendar::admin::*;
}
pub mod api {
    pub use talos_google_calendar::api::*;
}
pub mod handlers {
    pub use talos_google_calendar::handlers::*;
}
pub mod scheduler {
    pub use talos_google_calendar::scheduler::*;
}
pub mod watch {
    pub use talos_google_calendar::watch::*;
}
pub mod watch_channel_service {
    pub use talos_google_calendar::watch_channel_service::*;
}
pub mod webhook_token {
    pub use talos_google_calendar::webhook_token::*;
}
