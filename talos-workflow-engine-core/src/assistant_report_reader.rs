//! Read-side port for the weekly assistant report (`assistant_report`
//! system node). Same architecture as [`crate::OpsAlertsReader`]: the
//! node executes CONTROLLER-side through an injected trait object; the
//! Postgres impl lives in `talos-engine`, composed from the domain
//! repositories (executions, ops-alerts, ml) so SQL ownership stays
//! with each domain crate.

use async_trait::async_trait;
use serde_json::Value as JsonValue;
use uuid::Uuid;

/// Fetch a trailing-N-days activity + learning-health snapshot for one
/// user: per-workflow execution stats, fuel totals, ops-alerts week
/// stats with correction candidates, and ML loop health (lifecycle,
/// gold accuracy, shadow agreement, corrections banked).
#[async_trait]
pub trait AssistantReportReader: Send + Sync {
    /// `user_id` is the TENANT scope — impls MUST filter every query by
    /// it (from the execution's resolved identity, never node config).
    /// `days` is caller-clamped but impls should defensively clamp.
    async fn snapshot(&self, user_id: Uuid, days: u32) -> Result<JsonValue, crate::BoxError>;
}
