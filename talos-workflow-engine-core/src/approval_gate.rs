//! Pluggable human-in-the-loop approval gate for dispatch.
//!
//! When a module declares `requires_approval_for: [...]` (e.g.
//! `["send_email"]` or `["transfer_funds"]`), the engine must check
//! whether a human has approved the current execution BEFORE
//! dispatching. If no approval exists, the engine creates a pending
//! request row (idempotent) and pauses the workflow at that node.
//!
//! Concrete storage (Postgres `execution_approvals` table, an S3
//! approval log, an in-memory set for tests) is the impl's choice.

use async_trait::async_trait;
use uuid::Uuid;

/// Outcome of an approval check.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ApprovalStatus {
    /// A human has approved this execution's node — dispatch proceeds.
    Approved,
    /// No approval exists (or the pending one hasn't been actioned);
    /// the gate has idempotently created / reused a pending request.
    /// Engine should pause the workflow at this node.
    Pending,
    /// A human has explicitly denied the request — dispatch must not
    /// proceed. The attached `reason` is surfaced in the workflow
    /// error message.
    Denied {
        /// Human-readable reason surfaced into the workflow-level error.
        reason: String,
    },
}

/// Check + request human approval for a dispatched node.
#[async_trait]
pub trait ApprovalGate: Send + Sync {
    /// Check whether `(execution_id, node_id)` has been approved.
    /// If an approval already exists, returns [`ApprovalStatus::Approved`]
    /// or [`ApprovalStatus::Denied`]. If no approval exists, the impl
    /// atomically creates a pending-request record and returns
    /// [`ApprovalStatus::Pending`].
    ///
    /// `required_for` is the list of operation tags declared in the
    /// module's `requires_approval_for` field (e.g. `["send_email",
    /// "delete_file"]`). Stored with the request so reviewers can see
    /// what they're being asked to approve.
    ///
    /// `notification_webhook` is an optional URL the impl should POST
    /// to on the transition from no-record to pending (i.e. only on
    /// initial creation, not when reusing an existing pending row).
    /// Fire-and-forget — a failing webhook should be logged, not
    /// propagated as an error.
    async fn check_or_request(
        &self,
        execution_id: Uuid,
        node_id: Uuid,
        required_for: &[String],
        notification_webhook: Option<&str>,
    ) -> Result<ApprovalStatus, crate::BoxError>;
}
