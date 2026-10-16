//! A native stand-in for the host bindings a Talos module is compiled against,
//! so a module's own `#[cfg(test)]` tests run with `cargo test`.
//!
//! A module is written against `talos::core::*` (generated from
//! `wit/talos.wit` when it is built for the sandbox) and the
//! `#[talos_module]` attribute. Neither exists on the host. This crate gives:
//!
//! * [`talos`] — the same paths, types and function signatures, answered from
//!   state a test sets up through [`host`] (HTTP responses, actor memory,
//!   secrets, the clock, a model's reply). Nothing here touches a network.
//! * [`build`] — for a `build.rs`: copies each module source with the two
//!   SDK-macro lines removed and writes one `pub mod` per module to include.
//! * [`source`] — the gates over a module's source text (`talos-module-source`):
//!   the hosts it addresses against its grant, the config keys it reads
//!   against its schema, and the static lint that refuses a compile. The
//!   catalog's tests and an authoring lane's run the same functions.
//! * [`recorded_run`] — a module's `fixtures/` kept from one of its tests,
//!   for the catalog's layout (`module-templates/<slug>/talos.json`) and an
//!   authoring lane's (`modules/<name>/module.json`).
//!
//! # Using it
//!
//! ```text
//! // build.rs
//! talos_module_testkit::build::generate(&modules, &out_dir)?;
//!
//! // src/lib.rs
//! pub use talos_module_testkit::talos;   // modules may say `crate::talos`
//! include!(concat!(env!("OUT_DIR"), "/modules.rs"));
//! ```
//!
//! Each module's tests then run as `cargo test`. State is per test thread, so
//! tests do not see each other's setup and need no reset.
//!
//! # What this does and does not prove
//!
//! It proves the module's LOGIC. It does not prove the module builds for the
//! sandbox: these types are a hand-written mirror of the generated ones, and
//! `scripts/check-catalog.sh` is the gate that compiles every catalog template
//! against the real bindings. `tests::every_mirrored_function_is_in_the_wit`
//! holds the function NAMES here to `wit/talos.wit`; argument and field types
//! are not checked against it.

pub mod build;
pub mod host;
pub mod recorded_run;
pub use talos_module_source as source;
pub mod talos;

#[cfg(test)]
mod tests;
