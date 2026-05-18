// Env-config helpers moved to the `talos-config` workspace crate.
// Re-export so existing `use crate::config::*` imports keep working.
pub use talos_config::*;
