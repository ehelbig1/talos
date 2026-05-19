//! Constant-outcome [`ApprovalGate`] implementations.
//!
//! Use these in tests that exercise a node's approval-gated code path
//! without needing a real approval UI or persistence.
//!
//! [`ApprovalGate`]: talos_workflow_engine_core::ApprovalGate

use async_trait::async_trait;
use talos_workflow_engine_core::{ApprovalGate, ApprovalStatus, BoxError};
use uuid::Uuid;

/// [`ApprovalGate`] that returns [`ApprovalStatus::Approved`] for
/// every call. Use when testing the happy-path dispatch of a module
/// that declares `requires_approval_for`.
#[derive(Clone, Debug, Default)]
pub struct AlwaysApproveGate;

impl AlwaysApproveGate {
    /// Build a new instance.
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ApprovalGate for AlwaysApproveGate {
    async fn check_or_request(
        &self,
        _execution_id: Uuid,
        _node_id: Uuid,
        _required_for: &[String],
        _notification_webhook: Option<&str>,
    ) -> Result<ApprovalStatus, BoxError> {
        Ok(ApprovalStatus::Approved)
    }
}

/// [`ApprovalGate`] that returns [`ApprovalStatus::Pending`] for every
/// call. Use when testing the "execution paused, awaiting approval"
/// branch.
#[derive(Clone, Debug, Default)]
pub struct AlwaysPendingGate;

impl AlwaysPendingGate {
    /// Build a new instance.
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ApprovalGate for AlwaysPendingGate {
    async fn check_or_request(
        &self,
        _execution_id: Uuid,
        _node_id: Uuid,
        _required_for: &[String],
        _notification_webhook: Option<&str>,
    ) -> Result<ApprovalStatus, BoxError> {
        Ok(ApprovalStatus::Pending)
    }
}

/// [`ApprovalGate`] that returns [`ApprovalStatus::Denied`] with a
/// configurable reason. Use when testing failure paths.
#[derive(Clone, Debug)]
pub struct AlwaysDenyGate {
    reason: String,
}

impl AlwaysDenyGate {
    /// Build a gate that denies with `reason`.
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl Default for AlwaysDenyGate {
    fn default() -> Self {
        Self::new("denied by test gate")
    }
}

#[async_trait]
impl ApprovalGate for AlwaysDenyGate {
    async fn check_or_request(
        &self,
        _execution_id: Uuid,
        _node_id: Uuid,
        _required_for: &[String],
        _notification_webhook: Option<&str>,
    ) -> Result<ApprovalStatus, BoxError> {
        Ok(ApprovalStatus::Denied {
            reason: self.reason.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn always_approve() {
        let g = AlwaysApproveGate::new();
        let got = g
            .check_or_request(Uuid::nil(), Uuid::nil(), &[], None)
            .await
            .unwrap();
        assert_eq!(got, ApprovalStatus::Approved);
    }

    #[tokio::test]
    async fn always_pending() {
        let g = AlwaysPendingGate::new();
        let got = g
            .check_or_request(Uuid::nil(), Uuid::nil(), &[], None)
            .await
            .unwrap();
        assert_eq!(got, ApprovalStatus::Pending);
    }

    #[tokio::test]
    async fn always_deny_carries_reason() {
        let g = AlwaysDenyGate::new("unit test denial");
        let got = g
            .check_or_request(Uuid::nil(), Uuid::nil(), &[], None)
            .await
            .unwrap();
        assert_eq!(
            got,
            ApprovalStatus::Denied {
                reason: "unit test denial".into()
            }
        );
    }
}
