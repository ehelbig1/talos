//! Google Cloud Platform integration for Talos.
//!
//! Phase A: OAuth connect flow (authorize + callback), credential storage
//! via the unified `OAuthCredentialService` (vault path
//! `oauth/google_cloud/{user_id}/{provider_key}/access_token`), and a
//! read-only Cloud Resource Manager API client for listing GCP projects.
//!
//! `talos-slack` is the canonical `OAuthIntegration` reference; the
//! provider_key derivation mirrors `talos-google-calendar` (stable UUID
//! from `Sha256(google_account_id)[..16]`).

pub mod admin;
pub mod api;
pub mod dispatch;
pub mod integration;
pub mod watch;
pub mod watch_channel_service;
#[allow(unused_imports)]
pub use integration::{
    GcpTier, GoogleCloudIntegration, GoogleCloudIntegrationInfo, GoogleCloudIntegrationService,
};

pub mod handlers;
pub use handlers::{
    connect_gcp_handler, disconnect_integration_handler, gcp_callback_handler,
    get_integration_handler, list_integrations_handler, list_projects_handler, GcpOAuthServices,
};
