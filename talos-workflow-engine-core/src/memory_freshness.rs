//! Optional adapter for measuring the AGE of the actor-memory keys a node
//! declares via [`crate::reserved_keys::REQUIRES_FRESH`].
//!
//! # Why this exists
//!
//! A workflow that reads actor memory and reports on it cannot tell that its
//! inputs are stale. If the upstream writer failed — or simply hasn't run yet —
//! the reader synthesizes yesterday's data and presents it as today's, with no
//! signal anywhere in the pipeline. This was observed live (2026-07-25) on the
//! cross-domain briefing workflow: 32-hour-old `meeting_prep/today` rendered as
//! "Heavy Meeting Day" *for today*, and the shape-checking judge passed it.
//!
//! Measuring key age needs to reach into the consumer's actor-memory datastore,
//! which is outside the engine's concern — hence a port, exactly like
//! [`crate::SubworkflowActorContextResolver`]. Consumers without an
//! actor-memory layer (test harnesses, the in-memory runtime, embedded shells)
//! opt out implicitly by not wiring a resolver: nodes then get an
//! explicitly-`verified: false` report rather than a silent pass.
//!
//! # Cost
//!
//! The engine calls this ONLY for a node that actually declares
//! `requires_fresh`, so a graph with no freshness contracts issues zero extra
//! queries. Implementations SHOULD answer the whole key set in one round-trip
//! (`talos_memory::key_freshness` binds `key = ANY($2)`), because the call sits
//! on the per-node dispatch path.
//!
//! # Security contract
//!
//! Ages are scoped to the `actor_id` the engine passes — the node's own bound
//! actor. Implementations MUST NOT widen that scope: leaking the existence or
//! write-time of another actor's keys is a cross-tenant metadata disclosure.
//! Freshness is a TRUST signal, not a security boundary, so an implementation
//! that cannot answer should return `None` (reported as unverified) rather than
//! guessing.

use async_trait::async_trait;
use std::collections::HashMap;
use uuid::Uuid;

/// Resolve the age, in hours, of actor-memory keys.
#[async_trait]
pub trait MemoryFreshnessResolver: Send + Sync {
    /// Ages in HOURS for the keys that are PRESENT and live (an expired row is
    /// absent, matching what a reader could actually recall). A key missing
    /// from the returned map is treated as not-fresh by
    /// [`crate::reserved_keys::build_staleness_report`].
    ///
    /// Returning `None` means "could not determine" (store error, no backend) —
    /// the engine then injects an explicitly unverified report instead of
    /// asserting freshness it did not check.
    async fn resolve_ages_hours(
        &self,
        actor_id: Uuid,
        keys: &[String],
    ) -> Option<HashMap<String, f64>>;
}
