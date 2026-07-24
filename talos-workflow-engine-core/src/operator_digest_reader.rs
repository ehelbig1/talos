//! Read-side port for the autonomy cockpit (`operator_digest` system node).
//! Same architecture as [`crate::AssistantReportReader`]: the node executes
//! CONTROLLER-side through an injected trait object; the Postgres impl lives in
//! `talos-engine`, delegating to the `talos-operator-digest` service so SQL
//! ownership stays with each domain crate.

use async_trait::async_trait;
use serde_json::Value as JsonValue;
use uuid::Uuid;

/// Fetch the three-panel operator digest for one user over a trailing window:
/// what the autonomous machinery RAN (executions by `trigger_type` + schedules),
/// LEARNED (memory writes by kind, rank-weight fits, ML loop health), and
/// NEEDS the operator to decide (unified approvals + ops-alert corrections +
/// autonomous failures).
#[async_trait]
pub trait OperatorDigestReader: Send + Sync {
    /// `user_id` is the TENANT scope — impls MUST filter every query by it
    /// (from the execution's resolved identity, never node config). `days` is
    /// caller-clamped but impls should defensively clamp.
    async fn snapshot(&self, user_id: Uuid, days: u32) -> Result<JsonValue, crate::BoxError>;
}
