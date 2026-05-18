//! Pure-data types for Talos actor metadata + approval policies.
//!
//! Extracted from `controller::actor_scaffold_service` (the controller's
//! local copy of `LlmTier`) and `controller::actor_policies::types`.
//!
//! What lives here:
//! - [`LlmTier`] — data-egress ceiling (`Tier1` local-only / `Tier2`
//!   external providers allowed). Mirrors `talos_workflow_job_protocol::LlmTier`
//!   so the controller request layer stays decoupled from the wire-protocol crate
//!   for callers that only care about the type, not the conversion.
//! - [`PolicyMode`], [`EnforcementStatus`], [`TriggerCondition`],
//!   [`PolicyEvent`], [`PolicyFiredRecord`], [`PolicyVerdict`] — types
//!   exchanged across the actor-policy subsystem boundaries.
//!
//! What does **not** live here: the policy evaluator, cache, detectors,
//! and any code that needs `sqlx`, `rhai`, or async — those stay in
//! `controller::actor_policies`.

mod llm_tier;
mod policy;

pub use llm_tier::LlmTier;
pub use policy::{
    EnforcementStatus, PolicyEvent, PolicyFiredRecord, PolicyMode, PolicyVerdict, TriggerCondition,
};
