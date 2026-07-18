//! Read-side port for the ops-alerts triage store (`ops_alerts` domain).
//!
//! The `ops_alerts_digest` system node executes CONTROLLER-side — the
//! store is deliberately a controller-only data plane (no worker RPC,
//! workers stay credential-free), so the engine reaches it the same way
//! it reaches approvals: through an injected trait object
//! ([`crate::ApprovalGate`] is the structural precedent). The Postgres
//! impl lives in `talos-engine` (wired by the controller engine
//! builder); this crate stays persistence-free.

use async_trait::async_trait;
use serde_json::Value as JsonValue;
use uuid::Uuid;

/// Fetch a triage snapshot for one user: digest counts over the active
/// set plus the top-N active alerts (severity-ordered).
#[async_trait]
pub trait OpsAlertsReader: Send + Sync {
    /// Returns a JSON object shaped:
    /// `{ "digest": { active_by_severity, active_by_source, new_last_24h,
    ///    reopened_active }, "top_active": [ {title, severity, source,
    ///    status, occurrence_count, corrected, ...} ] }`.
    ///
    /// `user_id` is the TENANT scope — impls MUST filter every query by
    /// it (it comes from the execution's resolved identity, never from
    /// node config). `top_limit` is caller-clamped but impls should
    /// defensively clamp again.
    async fn snapshot(&self, user_id: Uuid, top_limit: u32) -> Result<JsonValue, crate::BoxError>;
}
