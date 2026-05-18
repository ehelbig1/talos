//! Re-export shim for the extracted `talos-ws-auth` crate.
//!
//! GraphQL-over-WebSocket auth + handshake handler moved to
//! `talos-ws-auth`. This shim preserves the existing
//! `crate::ws_auth::*` import path used by `controller::main` for
//! the `/ws` route wiring.

#![allow(unused_imports)]

pub use talos_ws_auth::*;
