//! Read-side port for pending human approvals (`execution_approvals`).
//!
//! The `pending_approvals` system node executes CONTROLLER-side — the
//! approvals store and the capability-token minter are both controller
//! data planes (workers stay credential-free), so the engine reaches
//! them through an injected trait object exactly like
//! [`crate::OpsAlertsReader`]. The Postgres impl lives in `talos-engine`
//! (wired by the controller engine builder); this crate stays
//! persistence-free.
//!
//! ## Why a node at all
//!
//! One-click approve/reject capability URLs can only be minted AFTER an
//! execution is actually suspended at its approval gate — a token minted
//! at compose time would bind an execution that has not paused yet (and
//! may never pause, if a conditional edge skips the gate). So the
//! approval-request email cannot carry its own links. The shape that
//! works is notify-AFTER-pause: a separate notifier workflow reads the
//! pending set (URLs minted at read time, when the pause is a fact) and
//! sends the actionable message. This port is that read surface.

use async_trait::async_trait;
use serde_json::Value as JsonValue;
use uuid::Uuid;

/// Fetch the caller's currently-pending approvals plus freshly-minted
/// one-click approve/reject capability URLs.
#[async_trait]
pub trait PendingApprovalsReader: Send + Sync {
    /// Returns a JSON object shaped:
    /// `{ "approvals": [ {execution_id, workflow_id, workflow_name,
    ///    node_id, requested_at, waiting_seconds, required_for,
    ///    approve_url, reject_url} ], "count": N }`.
    ///
    /// `user_id` is the TENANT scope — impls MUST filter every query by
    /// it (it comes from the execution's resolved identity, never from
    /// node config). `limit` is caller-clamped but impls should
    /// defensively clamp again.
    ///
    /// URL minting is best-effort: an approval whose links could not be
    /// minted MUST still be emitted, with `approve_url` / `reject_url`
    /// as `null`.
    async fn pending(&self, user_id: Uuid, limit: u32) -> Result<JsonValue, crate::BoxError>;
}
