//! Thin re-export shim over [`talos_worker_runtime`].
//!
//! The worker's library half (the entire wasmtime WASM host: runtime,
//! context, host/ modules, module_fetcher, sql_validator, wit_inspector, …)
//! moved to the `talos-worker-runtime` workspace crate in July 2026 so
//! controller-side consumers depend on a library crate instead of this
//! deployable binary. This shim keeps `worker::…` paths resolving for the
//! bin (`main.rs`), the integration tests, and anything not yet migrated —
//! same pattern as the `controller/src/*` re-export shims.
//!
//! Only genuinely bin-only modules remain declared here:
//! `metrics_server` (worker-process Prometheus endpoint), `secret_claim`
//! (worker-side envelope-seal claim client), `self_register`
//! (boot-time worker-identity registration), `liveness` (the periodic
//! proof-of-possession ping that bounds how long this worker's key stays in
//! the controller's trusted verify ring after the process departs), and
//! `heartbeat` (the periodic NATS fleet heartbeat — an observability signal
//! under the FLEET-SHARED key, deliberately weaker than `liveness` and
//! forbidden from touching the trust boundary). New runtime logic goes in
//! `talos-worker-runtime`, not here.

pub use talos_worker_runtime::*;

pub mod heartbeat;
pub mod liveness;
pub mod metrics_server;
pub mod secret_claim;
pub mod self_register;
