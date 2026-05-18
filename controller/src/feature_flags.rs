// Feature flag service moved to the `talos-feature-flags` workspace crate.
// Re-export so existing `use crate::feature_flags::*` imports keep working.
// MCP-705: the underlying crate's `load_flag` is a placeholder that
// always returns `Ok(None)`, so `is_enabled` always returns `false`.
// Allow unused so the re-export doesn't trigger an `unused_imports`
// warning now that the lone main.rs allocation has been removed; future
// real consumers can drop the allow.
#[allow(unused_imports)]
pub use talos_feature_flags::*;
