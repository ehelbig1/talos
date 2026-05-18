//! Re-export of the canonical actor-policy types.
//!
//! Pure-data enums and structs live in `talos-actor-types`; this module
//! preserves the existing `crate::types::*` import path
//! so call sites elsewhere in the controller don't need to change.
pub use talos_actor_types::{
    EnforcementStatus, PolicyEvent, PolicyFiredRecord, PolicyMode, PolicyVerdict, TriggerCondition,
};
