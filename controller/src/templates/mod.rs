//! Re-export shim for the extracted `talos-templates` crate.
//!
//! No callers in `controller/src/*` reference this path today (the
//! `templates::` module is unused dead code in the controller tree),
//! but we keep the shim for parity with every other extraction so a
//! future re-introduction of templated code-gen has a stable import
//! path.

#![allow(unused_imports)]

pub use talos_templates::*;

pub mod generator {
    pub use talos_templates::generator::*;
}
