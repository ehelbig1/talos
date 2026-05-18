// Prometheus metrics moved to the `talos-metrics` workspace crate.
// Re-export so existing `use crate::metrics::*` imports keep working.
pub use talos_metrics::*;
