//! Pluggable per-module rate-limit counter.
//!
//! The engine's per-module rate-limit guard ([`check_rate_limit` in
//! the executor crate]) defaults to a process-global `DashMap`-backed
//! counter. That's correct for single-process deployments but resets
//! on every restart — a rolling deploy effectively voids the limit
//! for the ~window-length grace period after each replica comes up,
//! and a sharded fleet can trivially exceed any per-module cap by
//! spreading dispatches across instances.
//!
//! [`RateLimitStore`] is the abstraction that lets a production
//! deployment back the counter with shared state (Redis, a database,
//! a centralized rate-limit service) so the cap holds across restarts
//! and instances.
//!
//! [`check_rate_limit` in the executor crate]: https://docs.rs/talos-workflow-engine/0.2/talos_workflow_engine/struct.ParallelWorkflowEngine.html
//!
//! # Failure semantics
//!
//! The trait method returns `Result<u32, BoxError>` so impls can
//! signal a transport failure. The engine's policy on store-side
//! errors is **fail-open** — a Redis network blip should not block
//! dispatch. The engine logs a warning and proceeds as if the limit
//! had not been exceeded. Adopters who need fail-closed semantics
//! must enforce that at the transport / dispatcher layer instead;
//! this is the documented contract.
//!
//! # Window semantics
//!
//! The engine passes `window_secs` (currently 60). Impls own the
//! rollover logic: when the first call lands in a new window, the
//! counter resets to 1. The trait does not impose any particular
//! algorithm — fixed window, sliding window, token bucket are all
//! valid as long as the post-increment count is monotonic within a
//! window and resets on the boundary.

use async_trait::async_trait;
use uuid::Uuid;

use crate::BoxError;

/// Atomic per-module rate-limit counter.
///
/// One method: increment the counter for a module within the current
/// window and return the post-increment count. The engine compares
/// the returned count against the per-module cap loaded at graph
/// init time; impls don't see the cap and don't make the
/// allow/deny decision.
///
/// See the module-level docs for the failure-mode and window
/// contracts.
#[async_trait]
pub trait RateLimitStore: Send + Sync {
    /// Atomically:
    ///
    /// 1. If `module_id`'s window has expired, reset its counter to
    ///    `0`.
    /// 2. Increment the counter by 1.
    /// 3. Return the post-increment count.
    ///
    /// `window_secs` is the window length the engine is operating
    /// against; impls treat it as the "if no record, or record older
    /// than this, start a new window" boundary.
    ///
    /// Returning `Err` triggers the engine's fail-open path —
    /// the dispatch is allowed and a `tracing::warn!` is emitted.
    /// Impls SHOULD distinguish "transport down" (return `Err`) from
    /// "this module's counter is now N" (return `Ok(n)`).
    async fn record_and_count(&self, module_id: Uuid, window_secs: u64) -> Result<u32, BoxError>;
}
