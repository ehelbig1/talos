//! Re-export shim for the `talos-google-health` crate, preserving the
//! `crate::google_health::*` path used for service construction and route
//! wiring under `/api/google-health/*`.

#![allow(unused_imports)]

pub use talos_google_health::*;

pub mod handlers {
    pub use talos_google_health::handlers::*;
}
