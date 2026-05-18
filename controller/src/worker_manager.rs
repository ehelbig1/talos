// Worker fleet tracking moved to the `talos-worker-fleet` workspace crate.
// Re-export so existing `use crate::worker_manager::*` imports keep working.
pub use talos_worker_fleet::*;
