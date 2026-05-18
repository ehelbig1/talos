// Module registry (ModuleRegistry + OCI sync + admin handlers) moved to
// the `talos-registry` workspace crate.
#![allow(unused_imports)]
pub use talos_registry::*;

pub mod api {
    pub use talos_registry::api::*;
}
pub mod sync {
    pub use talos_registry::sync::*;
}
