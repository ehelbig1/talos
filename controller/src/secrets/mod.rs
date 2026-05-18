//! Re-export shim for the extracted `talos-secrets-manager` crate.
//!
//! The transport-free SecretsManager core (envelope encryption, KEK
//! providers, DEK cache, master-key rotation) lives in
//! `talos-secrets-manager`. The OAuth-aware `ControllerSecretsResolver`
//! moved with `OAuthCredentialService` into `talos-oauth` and is
//! re-exported under its historical path here. Only [`handlers`] (axum
//! HTTP handlers) stays in the controller — it pulls in axum + the
//! request/response plumbing the core crate intentionally avoids.
//!
//! `vault_resolver` (`vault://` reference substitution helpers) has lived in
//! `talos-workflow-engine` since the engine extraction; we re-export it here
//! so existing `crate::secrets::vault_resolver::*` imports keep working.

#![allow(unused_imports)]

pub use talos_secrets_manager::*;

// Re-export submodules so call-sites that path through the module name
// (`crate::secrets::kek_provider::KekProvider`,
// `crate::secrets::vault_kek_provider::VaultTransitProvider::from_env`)
// keep compiling unchanged.
pub mod kek_provider {
    pub use talos_secrets_manager::kek_provider::*;
}
pub mod kek_rewrap {
    pub use talos_secrets_manager::kek_rewrap::*;
}
pub mod provider {
    pub use talos_secrets_manager::provider::*;
}
pub mod vault_kek_provider {
    pub use talos_secrets_manager::vault_kek_provider::*;
}

pub mod handlers;

/// OAuth-aware secrets resolver re-exported from `talos-oauth`.
pub mod resolver {
    pub use talos_oauth::resolver::*;
}

/// `vault_resolver` lives in the workflow engine crate. Re-export so existing
/// `crate::secrets::vault_resolver::*` imports keep working.
pub mod vault_resolver {
    pub use talos_workflow_engine::vault_resolver::*;
}
