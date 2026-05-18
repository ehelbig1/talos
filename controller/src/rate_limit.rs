// Rate-limiting primitives moved to the `talos-rate-limit` workspace crate.
// Re-export the entire surface so existing `use crate::rate_limit::*` imports
// keep working — call sites do not have to change.
pub use talos_rate_limit::*;
