// Capability-world enumeration helpers moved to talos-capability-world
// (next to the CapabilityWorld type itself). This shim preserves the
// existing `crate::capability_worlds::*` import path for
// MCP-handler call-sites in this crate.
#![allow(unused_imports)]
pub use talos_capability_world::{
    actor_ceiling_worlds_csv, compilable_worlds, compilable_worlds_csv, is_actor_ceiling_world,
    is_compilable_world, ACTOR_CEILING_WORLDS,
};
