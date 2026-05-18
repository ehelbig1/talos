//! Atlassian (Jira / Confluence) OAuth integration service.
//!
//! Extracted from `controller/src/atlassian/`. Owns:
//! - `AtlassianIntegrationService` — OAuth code-exchange, accessible-
//!   resources discovery, refresh-on-expiry token retrieval, integration
//!   list/disconnect.
//! - HTTP handlers (`connect`, `callback`, `list_integrations`,
//!   `disconnect_integration`) wired in `controller::main` under
//!   `/api/atlassian/*`.
//!
//! Shared trust boundary with the rest of the OAuth stack: token storage
//! goes through `talos_oauth::OAuthCredentialService`, which envelope-
//! encrypts via `SecretsManager` so plaintext tokens never hit disk.

pub mod handlers;
pub mod integration;

pub use handlers::{
    callback_handler, connect_handler, disconnect_integration_handler, list_integrations_handler,
};
pub use integration::{AtlassianIntegrationInfo, AtlassianIntegrationService};
