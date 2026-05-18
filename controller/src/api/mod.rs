//! Re-export shim for the extracted `talos-api` crate.
//!
//! The entire GraphQL surface — `QueryRoot`, `MutationRoot`,
//! `SubscriptionRoot`, dataloaders, validators, and the per-domain
//! `schema/{actors,auth,executions,modules,organizations,platform,
//! secrets,security,webhooks,workflows}/{queries,mutations}.rs`
//! tree — lives in `talos-api`. This shim preserves the existing
//! `crate::api::*` import path used by `controller::main` (schema
//! construction + axum handler wiring at `/graphql` and `/ws`),
//! `controller::ws_auth`, and `controller::schema_alias`.

#![allow(unused_imports)]

pub use talos_api::*;

pub mod dataloaders {
    pub use talos_api::dataloaders::*;
}
pub mod schema {
    pub use talos_api::schema::*;
}
pub mod validation {
    pub use talos_api::validation::*;
}
