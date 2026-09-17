//! Types exchanged across the actor-policy subsystem boundaries.
//!
//! `TriggerCondition` is the typed form of the string stored in
//! `actor_approval_policies.trigger_condition`. Strings are parsed at
//! cache-load time (not per-evaluation) so the hot path never re-parses.
//!
//! `PolicyEvent` is what call sites emit. Every new trigger-able action
//! in the platform adds a variant here and a matching detector.
//!
//! `PolicyVerdict` is what `PolicyEvaluator::evaluate` returns. Callers
//! short-circuit on `Blocked`; `Allow` records the side effects that
//! *did* fire (log rows written, approvers notified) so handlers can
//! surface provenance without re-querying.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Storage-level discriminant for `approval_mode`. Stored as lowercase
/// string in the DB; parsed here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMode {
    Log,
    Notify,
    Block,
}

impl PolicyMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "log" => Some(PolicyMode::Log),
            "notify" => Some(PolicyMode::Notify),
            "block" => Some(PolicyMode::Block),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            PolicyMode::Log => "log",
            PolicyMode::Notify => "notify",
            PolicyMode::Block => "block",
        }
    }
}

/// Typed form of `actor_approval_policies.trigger_condition`. Known
/// built-in names are promoted to their own variants; anything else is
/// assumed to be a Rhai expression and parsed into `Custom`.
///
/// Phase 1 status:
/// - `FirstWorkflowDeploy` — **enforced** at `publish_version` time.
/// - `Custom(..)` — **enforced** at every call site that emits a
///   `PolicyEvent` (currently only `PublishVersion`).
/// - All others — parsed but detectors return `Inapplicable`; the
///   policy persists but has no runtime effect. See
///   `detectors/mod.rs` for the Phase 2 TODO map.
#[derive(Debug, Clone)]
pub enum TriggerCondition {
    FirstWorkflowDeploy,
    NewExternalHost,
    DatabaseWrite,
    EmailSend,
    NewSecretAccess,
    /// Raw Rhai source. The evaluator compiles once at cache-load
    /// time; see `rhai_eval::compile_expression`.
    Custom(String),
}

impl TriggerCondition {
    pub fn parse(raw: &str) -> Self {
        match raw {
            "first_workflow_deploy" => TriggerCondition::FirstWorkflowDeploy,
            "new_external_host" => TriggerCondition::NewExternalHost,
            "database_write" => TriggerCondition::DatabaseWrite,
            "email_send" => TriggerCondition::EmailSend,
            "new_secret_access" => TriggerCondition::NewSecretAccess,
            other => TriggerCondition::Custom(other.to_string()),
        }
    }

    /// Human-readable label for tool responses + telemetry.
    pub fn label(&self) -> &str {
        match self {
            TriggerCondition::FirstWorkflowDeploy => "first_workflow_deploy",
            TriggerCondition::NewExternalHost => "new_external_host",
            TriggerCondition::DatabaseWrite => "database_write",
            TriggerCondition::EmailSend => "email_send",
            TriggerCondition::NewSecretAccess => "new_secret_access",
            TriggerCondition::Custom(s) => s.as_str(),
        }
    }

    /// Whether this condition will actually fire at any call site in
    /// Phase 1. Used by the MCP tool response to set `enforcement`:
    /// "enabled" / "enabled_for_publish_version_only" / "disabled".
    pub fn phase1_enforcement_status(&self) -> EnforcementStatus {
        match self {
            TriggerCondition::FirstWorkflowDeploy => EnforcementStatus::Enabled,
            TriggerCondition::Custom(_) => EnforcementStatus::PublishVersionOnly,
            TriggerCondition::NewExternalHost
            | TriggerCondition::DatabaseWrite
            | TriggerCondition::EmailSend
            | TriggerCondition::NewSecretAccess => EnforcementStatus::Disabled,
        }
    }
}

impl TriggerCondition {
    /// Why a policy with this trigger may not be created, or `None` when it
    /// may. Package CC (2026-09-17): a trigger nothing evaluates is REFUSED at
    /// creation. Until then `new_external_host`, `database_write`,
    /// `email_send` and `new_secret_access` were accepted and stored — the
    /// response carried `enforcement: "disabled"` and a warning — and the
    /// policy then had no effect: an operator configuring oversight on email
    /// sends got none. One home for the rule: a condition whose status is
    /// [`EnforcementStatus::Disabled`] is refused, so wiring a detector (and
    /// moving its status) re-admits the name with no second edit.
    #[must_use]
    pub fn creation_refusal(&self) -> Option<String> {
        match self.phase1_enforcement_status() {
            EnforcementStatus::Disabled => Some(format!(
                "trigger_condition '{}' is not evaluated anywhere yet (no call site emits \
                 its event), so a policy on it would have no effect and is refused. \
                 Enforced today: 'first_workflow_deploy' and custom Rhai expressions \
                 (evaluated at publish_version). For gating inside a workflow, use \
                 create_approval_gate.",
                self.label()
            )),
            EnforcementStatus::Enabled | EnforcementStatus::PublishVersionOnly => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementStatus {
    /// Fires at all relevant call sites in Phase 1.
    Enabled,
    /// Custom Rhai — evaluated only where PolicyEvent emitters exist.
    /// Today that's just `publish_version`.
    PublishVersionOnly,
    /// Parsed and persisted but no call site emits an event for this
    /// condition yet.
    Disabled,
}

impl EnforcementStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            EnforcementStatus::Enabled => "enabled",
            EnforcementStatus::PublishVersionOnly => "enabled_for_publish_version_only",
            EnforcementStatus::Disabled => "disabled",
        }
    }
}

/// Every call site that wants policy evaluation emits one of these.
/// Detectors match against `PolicyEvent` variants + `TriggerCondition`
/// variants in a single 2D switch (see `evaluator::matches_trigger`).
#[derive(Debug, Clone)]
pub enum PolicyEvent {
    /// Emitted from `WorkflowVersionService::publish_version` when an
    /// actor is resolved for the workflow being published.
    PublishVersion {
        actor_id: Uuid,
        workflow_id: Uuid,
        user_id: Uuid,
    },
    // Phase 2 variants land here. Each new variant requires:
    //   1. Enum addition here
    //   2. Matching detector(s) in `detectors/`
    //   3. A call site that emits it
    //   4. Update the `enforcement` mapping in `TriggerCondition::phase1_enforcement_status`
}

impl PolicyEvent {
    pub fn actor_id(&self) -> Uuid {
        match self {
            PolicyEvent::PublishVersion { actor_id, .. } => *actor_id,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            PolicyEvent::PublishVersion { .. } => "publish_version",
        }
    }

    /// Build the JSON context that custom Rhai expressions evaluate
    /// against. The event kind is always present under `event`.
    pub fn to_rhai_context(&self) -> serde_json::Value {
        match self {
            PolicyEvent::PublishVersion {
                actor_id,
                workflow_id,
                user_id,
            } => serde_json::json!({
                "event": "publish_version",
                "actor_id": actor_id.to_string(),
                "workflow_id": workflow_id.to_string(),
                "user_id": user_id.to_string(),
            }),
        }
    }
}

/// The fire-and-forget record of what happened, keyed by policy row.
/// Returned as part of `PolicyVerdict::Allow` so handlers can surface
/// what ran without an extra DB query.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyFiredRecord {
    pub policy_id: Uuid,
    pub mode: PolicyMode,
    pub trigger_label: String,
}

/// The evaluator's verdict. Callers must halt on `Blocked`.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum PolicyVerdict {
    /// Proceed. `fired` records every policy that matched and the
    /// side-effect it produced (log row / notification). May be empty
    /// when no policies matched (common case).
    Allow { fired: Vec<PolicyFiredRecord> },
    /// Caller must halt. Carries the approval-gate a human can resolve
    /// to unblock the caller's next retry. Only the *first* matching
    /// block policy is surfaced — iteration order is `created_at ASC`
    /// to match `list_actor_approval_policies`.
    Blocked {
        policy_id: Uuid,
        gate_id: Uuid,
        approve_url: String,
        reject_url: String,
        trigger_label: String,
        approvers: Vec<String>,
        reason: String,
        /// Side effects that DID fire (earlier-in-order log/notify
        /// policies) before the block short-circuit.
        fired: Vec<PolicyFiredRecord>,
    },
}

#[cfg(test)]
mod creation_refusal_tests {
    use super::{EnforcementStatus, TriggerCondition};

    /// Every built-in name, the refused four, and the two admitted shapes.
    #[test]
    fn exactly_the_unevaluated_triggers_are_refused() {
        for name in [
            "new_external_host",
            "database_write",
            "email_send",
            "new_secret_access",
        ] {
            let t = TriggerCondition::parse(name);
            let msg = t
                .creation_refusal()
                .unwrap_or_else(|| panic!("{name} must be refused"));
            assert!(msg.contains(name), "{msg}");
            assert!(msg.contains("first_workflow_deploy"), "{msg}");
        }
        assert!(TriggerCondition::parse("first_workflow_deploy")
            .creation_refusal()
            .is_none());
        assert!(TriggerCondition::parse("actor_id != \"\"")
            .creation_refusal()
            .is_none());
    }

    /// The refusal is the enforcement status, not a second list: every
    /// condition is refused exactly when its status is `Disabled`.
    #[test]
    fn refusal_follows_the_enforcement_status() {
        for name in [
            "first_workflow_deploy",
            "new_external_host",
            "database_write",
            "email_send",
            "new_secret_access",
            "true",
        ] {
            let t = TriggerCondition::parse(name);
            assert_eq!(
                t.creation_refusal().is_some(),
                t.phase1_enforcement_status() == EnforcementStatus::Disabled,
                "{name}"
            );
        }
    }
}
