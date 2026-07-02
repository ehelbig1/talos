//! Distributed-tracing support for the worker.
//!
//! This module was historically a byte-for-byte copy of the `talos-trace`
//! workspace crate (the controller consumes the same code via `talos_trace`).
//! Maintaining two copies meant they drifted — so the implementation now lives
//! solely in `talos-trace` and this module is a thin re-export. Everything the
//! worker referenced (`init_tracing`, `shutdown_tracing`, `ExecutionSpan`
//! incl. `new_with_parent`, `SpanGuard`, `extract_trace_id`,
//! `create_trace_context`) is re-exported unchanged.
//!
//! See `talos-trace/src/lib.rs` for the documented API and doctests.
pub use talos_trace::*;

#[cfg(test)]
#[path = "tracing_tests.rs"]
// The included file wraps its content in its own `mod tests` —
// latent clippy::module_inception surfaced by `--all-targets`.
#[allow(clippy::module_inception)]
mod tests;
