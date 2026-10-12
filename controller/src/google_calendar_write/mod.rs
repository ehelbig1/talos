//! Re-export shim for the `talos-google-calendar-write` crate, preserving the
//! `crate::google_calendar_write::*` path used for service construction and route wiring
//! under `/api/google-calendar-write/*`.

#![allow(unused_imports)]

pub use talos_google_calendar_write::*;

pub mod handlers {
    pub use talos_google_calendar_write::handlers::*;
}
