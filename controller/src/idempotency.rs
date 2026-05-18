// Idempotency key service moved to the `talos-idempotency` workspace crate.
// Re-export so existing `use crate::idempotency::*` imports keep working.
pub use talos_idempotency::*;
