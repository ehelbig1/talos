//! Read-side port for the running user's connected services.
//!
//! The `connections` system node executes CONTROLLER-side — which services
//! a user has connected, and where each credential is stored, are
//! controller data (workers stay credential-free) — so the engine reaches
//! them through an injected trait object, like [`crate::OpsAlertsReader`].
//! The Postgres impl lives in `talos-engine`.
//!
//! ## What the node is for
//!
//! A workflow that reads "my banks" or "my calendars" had one hand-wired
//! node per account, so an account connected later was not read until
//! someone edited the graph, and nothing said so. This node gives a
//! workflow the list, so a composer can at least say what it did not read.
//!
//! ## What it deliberately does not do
//!
//! It emits each connection's `vault://` REFERENCE (a string naming where
//! the credential is), never a credential. And a reference arriving in a
//! node's INPUT is not resolved at dispatch — the engine ships a secret only
//! for a reference in the node's own configuration — so this node's output
//! does not, by itself, let a downstream module use a credential its author
//! did not name.

use async_trait::async_trait;
use serde_json::Value as JsonValue;
use uuid::Uuid;

/// Whether `provider` has the shape of a service id (`plaid`,
/// `google-calendar`): 1 to 40 lowercase letters, digits, `-` or `_`.
///
/// The graph parser reads a value that fails this as "no filter", so the
/// authoring tool refuses one rather than letting a typo widen the listing.
#[must_use]
pub fn provider_id_usable(provider: &str) -> bool {
    !provider.is_empty()
        && provider.len() <= 40
        && provider
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// Fetch the caller's connections.
#[async_trait]
pub trait ConnectionsReader: Send + Sync {
    /// Returns a JSON object shaped:
    /// `{ "count": N, "truncated": bool, "stored_checked": bool,
    ///    "connections": [ {service, name, account, connected_at,
    ///    vault_reference, allowed_secrets, stored, module_readable, …} ] }`.
    ///
    /// `user_id` is the TENANT scope — impls MUST filter every query by it
    /// (it comes from the execution's resolved identity, never from node
    /// config). `provider` keeps one service's connections; `None` keeps
    /// all.
    async fn connections(
        &self,
        user_id: Uuid,
        provider: Option<&str>,
    ) -> Result<JsonValue, crate::BoxError>;
}
