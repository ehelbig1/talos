//! Re-export shim for the extracted `talos-api-docs` crate.
//!
//! GraphQL Playground HTML, GraphQL SDL export, and the
//! REST/JSON API documentation router moved to `talos-api-docs`.
//! This shim preserves the existing `crate::api_docs::*` import
//! path used by `controller::main` for `/docs` + `/docs.json` +
//! `/graphql/sdl` + `/graphql/playground` route wiring.

#![allow(unused_imports)]

pub use talos_api_docs::*;
