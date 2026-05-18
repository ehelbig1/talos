// `ModuleFetcher` impl for `ModuleRegistry` moved to the `talos-registry`
// crate -- the impl lives next to the type to satisfy the orphan rule and
// keep the registry self-contained. `wasm_module_to_artifact` is also
// re-exported so the prefetch warmer in this controller crate can keep
// using it under the historical path.
#![allow(unused_imports)]
pub use talos_registry::module_fetcher::*;
