//! `talos-github-connect` — the GitHub App connect/install flow (RFC 0008 B2b).
//!
//! Service + axum handlers, mirroring the `talos-gmail` connect pattern. The
//! controller (B2b-3) constructs [`GithubConnectService`] from
//! `talos_github::GithubAppConfig::from_env()`, registers the two routes, and
//! provides the auth middleware that injects the connecting user's id.
//!
//! Security shape (see `service.rs` for the full rationale):
//! * Initiate (`/api/github/connect`) is session-authenticated; the `user_id` is
//!   stored in a single-use `oauth_state_tokens` row bound to this browser.
//! * The Setup-URL callback (`/api/github/setup`) trusts nothing it is handed:
//!   it consumes the state and starts GitHub's user authorization.
//! * The Callback-URL (`/api/github/authorized`) claims the installation only
//!   if the authorizing GitHub user can access it, and never moves an active
//!   installation another Talos user holds.

mod handlers;
mod service;
mod token_resolver;

pub use handlers::{
    connect_github_handler, github_authorized_callback_handler, github_setup_callback_handler,
    list_github_installations_handler, AuthorizedParams, SetupParams,
};
pub use service::{
    AuthorizedOutcome, ClaimRefusal, GithubConnectService, InstallationSummary, SetupOutcome,
};
pub use token_resolver::{parse_github_app_secret_path, GithubTokenResolver, GITHUB_APP_SCHEME};
