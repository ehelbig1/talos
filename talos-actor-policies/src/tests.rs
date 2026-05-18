//! Tests that exercise the non-DB parts of the policy framework.
//!
//! Evaluator + detector tests that need a live Postgres connection
//! belong in an integration suite (future `tests/policy_enforcement.rs`),
//! not here. This file covers parsing + enforcement-status mapping —
//! the bits that encode our UX contracts.

use super::types::{EnforcementStatus, PolicyEvent, PolicyMode, TriggerCondition};
use uuid::Uuid;

#[test]
fn policy_mode_round_trips() {
    for m in [PolicyMode::Log, PolicyMode::Notify, PolicyMode::Block] {
        assert_eq!(PolicyMode::parse(m.as_str()), Some(m));
    }
    assert!(PolicyMode::parse("nonsense").is_none());
}

#[test]
fn trigger_condition_built_ins_parse_to_typed_variants() {
    assert!(matches!(
        TriggerCondition::parse("first_workflow_deploy"),
        TriggerCondition::FirstWorkflowDeploy
    ));
    assert!(matches!(
        TriggerCondition::parse("new_external_host"),
        TriggerCondition::NewExternalHost
    ));
    assert!(matches!(
        TriggerCondition::parse("database_write"),
        TriggerCondition::DatabaseWrite
    ));
    assert!(matches!(
        TriggerCondition::parse("email_send"),
        TriggerCondition::EmailSend
    ));
    assert!(matches!(
        TriggerCondition::parse("new_secret_access"),
        TriggerCondition::NewSecretAccess
    ));
}

#[test]
fn trigger_condition_anything_else_parses_as_custom() {
    let cond = TriggerCondition::parse("event == \"publish_version\"");
    match cond {
        TriggerCondition::Custom(src) => {
            assert_eq!(src, "event == \"publish_version\"");
        }
        other => panic!("expected Custom, got {:?}", other),
    }
}

#[test]
fn enforcement_matrix_matches_phase1_contract() {
    // Phase 1 — these MUST be enforced end-to-end. Breaking this
    // assertion means the tool doc lied again.
    assert_eq!(
        TriggerCondition::FirstWorkflowDeploy.phase1_enforcement_status(),
        EnforcementStatus::Enabled
    );
    assert_eq!(
        TriggerCondition::Custom("true".into()).phase1_enforcement_status(),
        EnforcementStatus::PublishVersionOnly
    );
    // Phase 2 — disabled until a call site emits a matching event.
    assert_eq!(
        TriggerCondition::NewExternalHost.phase1_enforcement_status(),
        EnforcementStatus::Disabled
    );
    assert_eq!(
        TriggerCondition::DatabaseWrite.phase1_enforcement_status(),
        EnforcementStatus::Disabled
    );
    assert_eq!(
        TriggerCondition::EmailSend.phase1_enforcement_status(),
        EnforcementStatus::Disabled
    );
    assert_eq!(
        TriggerCondition::NewSecretAccess.phase1_enforcement_status(),
        EnforcementStatus::Disabled
    );
}

#[test]
fn enforcement_status_as_str_matches_tool_response_values() {
    // The MCP handler surfaces `enforcement.as_str()` directly in the
    // response. These strings are part of the public API — a silent
    // rename here would be a breaking change for clients that branch
    // on them.
    assert_eq!(EnforcementStatus::Enabled.as_str(), "enabled");
    assert_eq!(
        EnforcementStatus::PublishVersionOnly.as_str(),
        "enabled_for_publish_version_only"
    );
    assert_eq!(EnforcementStatus::Disabled.as_str(), "disabled");
}

#[test]
fn policy_event_kind_is_stable() {
    let e = PolicyEvent::PublishVersion {
        actor_id: Uuid::new_v4(),
        workflow_id: Uuid::new_v4(),
        user_id: Uuid::new_v4(),
    };
    assert_eq!(e.kind(), "publish_version");
}

#[test]
fn policy_event_rhai_context_includes_all_ids() {
    let actor_id = Uuid::new_v4();
    let workflow_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let e = PolicyEvent::PublishVersion {
        actor_id,
        workflow_id,
        user_id,
    };
    let ctx = e.to_rhai_context();
    assert_eq!(ctx["event"], "publish_version");
    assert_eq!(ctx["actor_id"], actor_id.to_string());
    assert_eq!(ctx["workflow_id"], workflow_id.to_string());
    assert_eq!(ctx["user_id"], user_id.to_string());
}
