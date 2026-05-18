// AuthService and friends now live in the `talos-auth` workspace crate.
// Re-export the entire surface so existing `use controller::auth::*`
// imports keep working — call sites don't have to change as part of
// the extraction.
pub use talos_auth::*;
