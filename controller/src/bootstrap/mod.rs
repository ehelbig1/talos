//! Bootstrap-local modules for the controller binary (2026-07 decomposition
//! of `main.rs`). Bin-private by design: these are the bodies of `main()`'s
//! startup phases, not reusable library surface — anything that graduates to
//! cross-crate use belongs in a `talos-*` workspace crate instead.
pub(crate) mod background;
pub(crate) mod router;
pub(crate) mod services;
