//! Re-export shim for the extracted `talos-oauth` crate.
//!
//! `OAuthCredentialService` and the proactive refresh task moved to
//! `talos-oauth`. This shim preserves existing
//! `crate::oauth::*`, `crate::oauth::credentials::*`, and
//! `crate::oauth::refresh_task::*` import paths.

#![allow(unused_imports)]

pub use talos_oauth::*;

pub mod credentials {
    pub use talos_oauth::credentials::*;
}

pub mod refresh_task {
    pub use talos_oauth::refresh_task::*;
}
