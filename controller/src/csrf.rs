// CSRF protection moved to the `talos-csrf` workspace crate.
// Re-export so existing `use crate::csrf::*` imports keep working.
pub use talos_csrf::*;
