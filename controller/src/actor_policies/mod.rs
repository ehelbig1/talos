//! Re-export shim for the extracted `talos-actor-policies` crate.
//!
//! All five sub-modules (cache, detectors/, evaluator, rhai_eval, types)
//! plus the top-level re-exports (PolicyEvaluator, PolicyPrePublishHook,
//! PolicyVerdict, EnforcementStatus, etc.) live in `talos-actor-policies`.
//! This shim preserves the existing `crate::actor_policies::*` import
//! path for the 3 caller files in controller (mcp/{mod, actor, versions}).

#![allow(unused_imports)]

pub use talos_actor_policies::*;

pub mod cache {
    pub use talos_actor_policies::cache::*;
}
pub mod detectors {
    pub use talos_actor_policies::detectors::*;
}
pub mod evaluator {
    pub use talos_actor_policies::evaluator::*;
}
pub mod rhai_eval {
    pub use talos_actor_policies::rhai_eval::*;
}
pub mod types {
    pub use talos_actor_policies::types::*;
}
