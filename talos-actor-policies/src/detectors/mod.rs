//! Built-in trigger-condition detectors.
//!
//! Each detector answers one question: "given this event and an actor,
//! should this specific trigger condition be considered matched?"
//!
//! The signature is intentionally narrow: every detector takes an
//! `sqlx::Transaction` so it can run DB-level checks (advisory locks,
//! `NOT EXISTS` probes) inside the caller's transaction — this is how
//! we get race-safety for "first time ever" conditions without a second
//! round-trip.
//!
//! # Phase 2 backlog
//!
//! Each unimplemented built-in condition maps to a detector stub that
//! returns `DetectionResult::Inapplicable`. Wiring a detector up
//! requires three things:
//!
//! 1. A new `PolicyEvent` variant in `super::types` with the fields the
//!    detector needs.
//! 2. A call site that emits that event (e.g. the worker host's HTTP
//!    egress path for `new_external_host`).
//! 3. The detector's `detect` body replaces `Inapplicable` with real
//!    logic, typically a per-actor memoization table lookup.
//!
//! See individual `TODO(phase2-*)` markers below.

pub mod first_workflow_deploy;

use super::types::{PolicyEvent, TriggerCondition};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionResult {
    /// Trigger condition matches; policy should fire.
    Match,
    /// Trigger condition does not match; policy should NOT fire.
    NoMatch,
    /// This (event, condition) pair has no detector implementation.
    /// Caller skips the policy and increments the phase-2-stub metric.
    Inapplicable,
}

/// Dispatch table: given a trigger condition + event, run the right
/// detector. Built-in conditions map to detector modules; `Custom`
/// Rhai is handled by the evaluator directly (not here) because it
/// doesn't need DB access.
///
/// The `tx` is threaded in so detectors can run inside the caller's
/// transaction for race-free "first time" checks.
pub async fn detect(
    condition: &TriggerCondition,
    event: &PolicyEvent,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> anyhow::Result<DetectionResult> {
    match (condition, event) {
        (TriggerCondition::FirstWorkflowDeploy, PolicyEvent::PublishVersion { actor_id, .. }) => {
            first_workflow_deploy::detect(*actor_id, tx).await
        }

        // TODO(phase2-new-external-host): match against PolicyEvent::OutboundHost
        // — needs a call site in worker egress + a per-actor
        // `actor_seen_hosts` memoization table.
        (TriggerCondition::NewExternalHost, _) => Ok(DetectionResult::Inapplicable),

        // TODO(phase2-database-write): match against PolicyEvent::DatabaseWrite
        // — needs worker-side hook on `database::execute` for non-SELECT SQL.
        (TriggerCondition::DatabaseWrite, _) => Ok(DetectionResult::Inapplicable),

        // TODO(phase2-email-send): match against PolicyEvent::EmailSend
        // — needs a call site in catalog email modules (Gmail, SMTP).
        (TriggerCondition::EmailSend, _) => Ok(DetectionResult::Inapplicable),

        // TODO(phase2-new-secret-access): match against PolicyEvent::SecretAccessed
        // — needs a call site in `secrets::resolver` + `actor_seen_secrets` table.
        (TriggerCondition::NewSecretAccess, _) => Ok(DetectionResult::Inapplicable),

        // Custom Rhai is handled at the evaluator layer (rhai_eval.rs)
        // — not here — because it operates on the JSON context only
        // and doesn't need DB access.
        (TriggerCondition::Custom(_), _) => Ok(DetectionResult::Inapplicable),
    }
}
