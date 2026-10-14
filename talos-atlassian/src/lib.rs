//! Atlassian (Jira / Confluence) OAuth integration service.
//!
//! Extracted from `controller/src/atlassian/`. Owns:
//! - `AtlassianIntegrationService` — OAuth code-exchange, accessible-
//!   resources discovery, refresh-on-expiry token retrieval, integration
//!   list/disconnect.
//! - HTTP handlers (`connect`, `callback`, `list_integrations`,
//!   `disconnect_integration`) wired in `controller::main` under
//!   `/api/atlassian/*`.
//! - Jira push (2026-10-12): the dynamic webhook a connection registers
//!   ([`push`]), the public receiver for its deliveries ([`push_receiver`],
//!   authenticated by [`push_jwt`]) and the task that keeps it alive
//!   ([`push_scheduler`]). See `docs/jira-push-setup.md`.
//!
//! Shared trust boundary with the rest of the OAuth stack: token storage
//! goes through `talos_oauth::OAuthCredentialService`, which envelope-
//! encrypts via `SecretsManager` so plaintext tokens never hit disk.

pub mod handlers;
pub mod integration;
pub mod push;
pub mod push_jwt;
pub mod push_receiver;
pub mod push_replay;
pub mod push_scheduler;

pub use handlers::{
    callback_handler, connect_handler, disconnect_integration_handler, list_integrations_handler,
};
pub use integration::{AtlassianIntegrationInfo, AtlassianIntegrationService};
