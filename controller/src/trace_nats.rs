// W3C TraceContext propagation over NATS headers moved to the
// `talos-trace-nats` workspace crate. Both controller (inject) and worker
// (extract) sides live there; this is now a thin re-export shim.
#[allow(unused_imports)]
pub use talos_trace_nats::*;
