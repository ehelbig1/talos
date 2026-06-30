//! `talos-github-connect` — the GitHub App connect/install flow (RFC 0008 B2b).
//!
//! Service + axum handlers, mirroring the `talos-gmail` connect pattern. The
//! controller (B2b-3) constructs [`GithubConnectService`] from
//! `talos_github::GithubAppConfig::from_env()`, registers the two routes, and
//! provides the auth middleware that injects the connecting user's id.
//!
//! Security shape:
//! * Initiate (`/api/github/connect`) is session-authenticated; the `user_id` is
//!   stored in the single-use `oauth_state_tokens` row.
//! * The Setup-URL callback (`/api/github/setup`) is a cross-site redirect from
//!   github.com — no session auth — so it recovers `user_id` from the state
//!   token (atomic single-use consume), validates the untrusted params, then
//!   fetches + persists the installation.

mod handlers;
mod service;
mod token_resolver;

pub use handlers::{
    connect_github_handler, github_setup_callback_handler, list_github_installations_handler,
    SetupParams,
};
pub use service::{GithubConnectService, InstallationSummary, SetupOutcome};
pub use token_resolver::{parse_github_app_secret_path, GithubTokenResolver, GITHUB_APP_SCHEME};
