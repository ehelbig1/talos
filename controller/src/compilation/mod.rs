//! Re-export shim for the extracted `talos-compilation` crate.
//!
//! Five sub-modules (`analyze` private, `container`, `js_templates`,
//! `scaffold`, plus the new `dependency_allowlist`) and the public
//! `CompilationService` / `CompilationError` plus
//! `validate_dependencies` / `get_allowed_dependencies` helpers all
//! live in `talos-compilation`. This shim preserves the existing
//! `crate::compilation::*` import path used by `controller::main`,
//! the MCP layer (sandbox, modules, workflows), and the GraphQL API.

#![allow(unused_imports)]

pub use talos_compilation::*;

pub mod container {
    pub use talos_compilation::container::*;
}
pub mod js_templates {
    pub use talos_compilation::js_templates::*;
}
pub mod scaffold {
    pub use talos_compilation::scaffold::*;
}
pub mod dependency_allowlist {
    pub use talos_compilation::dependency_allowlist::*;
}
