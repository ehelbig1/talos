//! Handlebars-based code-generation helper for Talos WASM module templates.
//!
//! Extracted from `controller/src/templates/` so any crate that needs to
//! render `wit_bindgen!` / `talos_module!` scaffolding can depend on it
//! without pulling in the controller binary.

pub mod generator;

pub use generator::TemplateGenerator;
