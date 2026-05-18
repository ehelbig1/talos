//! Actor-level approval policy enforcement.
//!
//! See `docs/actor-policies.md` (and the `actor_policies::types` module
//! docs) for the high-level architecture. Phase 1 enforces
//! `first_workflow_deploy` at `publish_version` time plus custom Rhai
//! expressions at the same call site; other built-in conditions are
//! parsed/persisted but not yet wired (see `detectors::mod`).

pub mod cache;
pub mod detectors;
pub mod evaluator;
pub mod rhai_eval;
pub mod types;

#[cfg(test)]
mod tests;

pub use evaluator::{PolicyEvaluator, PublishVersionPolicyHook};
pub use types::{EnforcementStatus, TriggerCondition};

// Maintained for API stability so out-of-tree callers can keep using
// `crate::{PolicyPrePublishHook, PolicyVerdict}` paths.
#[allow(unused_imports)]
pub use evaluator::PolicyPrePublishHook;
#[allow(unused_imports)]
pub use types::PolicyVerdict;
