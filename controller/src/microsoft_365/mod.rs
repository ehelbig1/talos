//! Re-export shim for the `talos-microsoft-365` crate, preserving the
//! `crate::microsoft_365::*` path used for service construction and route wiring
//! under `/api/microsoft-365/*`.

#![allow(unused_imports)]

pub use talos_microsoft_365::*;

pub mod handlers {
    pub use talos_microsoft_365::handlers::*;
}
