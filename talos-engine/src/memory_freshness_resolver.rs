//! Controller implementation of [`MemoryFreshnessResolver`].
//!
//! Answers "how old is each of these actor-memory keys?" for the per-node
//! `requires_fresh` contract, via ONE batched metadata-only query
//! (`talos_memory::key_freshness` → `key = ANY($2)`), so a multi-key contract
//! is a single round-trip on the dispatch path.
//!
//! Scoped strictly to the `actor_id` the engine passes — the node's own bound
//! actor (which, after the 2026-07 sub-workflow identity rebind, is the
//! sub-workflow's actor inside a sub-engine). No widening: reporting the
//! existence or write-time of another actor's keys would be a cross-tenant
//! metadata disclosure.
//!
//! Fail-soft by design: a store error returns `None`, which the engine reports
//! as `verified: false` rather than asserting freshness it did not check.
//! Freshness is a trust signal, not a security boundary, so a transient DB blip
//! must not take a pipeline down.

use async_trait::async_trait;
use std::collections::HashMap;
use talos_workflow_engine_core::MemoryFreshnessResolver;
use uuid::Uuid;

pub struct ControllerMemoryFreshnessResolver {
    db_pool: sqlx::Pool<sqlx::Postgres>,
}

impl ControllerMemoryFreshnessResolver {
    pub fn from_pool(db_pool: sqlx::Pool<sqlx::Postgres>) -> Self {
        Self { db_pool }
    }
}

#[async_trait]
impl MemoryFreshnessResolver for ControllerMemoryFreshnessResolver {
    async fn resolve_ages_hours(
        &self,
        actor_id: Uuid,
        keys: &[String],
    ) -> Option<HashMap<String, f64>> {
        match talos_memory::key_freshness(&self.db_pool, actor_id, keys).await {
            Ok(rows) => {
                let now = chrono::Utc::now();
                Some(
                    rows.into_iter()
                        .map(|(key, updated_at)| {
                            // A clock skew / future timestamp clamps to 0 rather
                            // than reporting a negative age (which would read as
                            // "impossibly fresh").
                            let hours =
                                (now - updated_at).num_milliseconds() as f64 / 3_600_000.0_f64;
                            (key, hours.max(0.0))
                        })
                        .collect(),
                )
            }
            Err(e) => {
                tracing::warn!(
                    target: "talos_freshness",
                    %actor_id,
                    error = %e,
                    "key_freshness lookup failed; reporting unverified"
                );
                None
            }
        }
    }
}
