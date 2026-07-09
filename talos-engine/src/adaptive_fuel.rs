//! Adaptive fuel (Phase 2): learn a per-node `max_fuel` ceiling from observed
//! consumption so a node never silently under-provisions.
//!
//! GUARD MODE — the learned ceiling is applied by the engine as a FLOOR
//! (`max(configured_baseline, learned)`; see
//! [`ParallelWorkflowEngine::resolve_node_max_fuel`]). So adaptation can only
//! ever RAISE a node's ceiling to cover real demand — it never lowers a
//! deliberately-set value and therefore can never introduce a fuel-exhaustion
//! failure that the static ceiling wouldn't already have had. Kill switch:
//! `TALOS_ADAPTIVE_FUEL=0`.
//!
//! Ceilings are computed once per engine build from `execution_cost_rollup`
//! history (p95/max × headroom, tenant-scoped by `workflow_id`) and cached with
//! a short TTL so repeated executions of the same workflow don't re-query. The
//! path is fail-open: any error yields an empty map (static ceilings), never a
//! failed build.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use sqlx::PgPool;
use uuid::Uuid;

use talos_analytics_repository::AnalyticsRepository;
use talos_compilation::scaffold::adaptive_ceiling;

/// How long a workflow's computed ceilings stay cached before recomputation.
const CACHE_TTL: Duration = Duration::from_secs(120);
/// Aggregation window for the percentile — recent enough to track payload
/// growth, wide enough to gather samples.
const WINDOW_DAYS: i32 = 30;
/// Minimum completed samples per node before a learned ceiling is trusted.
const MIN_SAMPLES: i64 = 5;
/// Upper bound on distinct workflows held in the cache. Bounds memory; on
/// overflow the whole cache is dropped (entries are tiny and cheap to rebuild).
const MAX_CACHED_WORKFLOWS: usize = 4096;

struct Entry {
    computed_at: Instant,
    ceilings: HashMap<String, u64>,
}

fn cache() -> &'static Mutex<HashMap<Uuid, Entry>> {
    static CACHE: OnceLock<Mutex<HashMap<Uuid, Entry>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Whether adaptive fuel is active. ON by default (guard mode is strictly safe);
/// set `TALOS_ADAPTIVE_FUEL` to `0` / `false` / `off` to disable.
pub fn adaptive_fuel_enabled() -> bool {
    !matches!(
        std::env::var("TALOS_ADAPTIVE_FUEL").ok().as_deref(),
        Some("0") | Some("false") | Some("off")
    )
}

/// Learned per-node fuel ceilings for a workflow, keyed by node label (matching
/// the engine's `node_labels`, i.e. `execution_cost_rollup.node_id`).
///
/// Returns an empty map — the "no adaptation" case, byte-for-byte the old
/// static behaviour — when adaptive is disabled, no node has enough samples, or
/// the query fails. Never errors: adaptive is an enhancement, not a hard
/// dependency of dispatch.
pub async fn learned_fuel_ceilings(pool: &PgPool, workflow_id: Uuid) -> HashMap<String, u64> {
    if !adaptive_fuel_enabled() {
        return HashMap::new();
    }

    // Read-path cache hit.
    if let Ok(guard) = cache().lock() {
        if let Some(e) = guard.get(&workflow_id) {
            if e.computed_at.elapsed() < CACHE_TTL {
                return e.ceilings.clone();
            }
        }
    }

    // Miss / expired: recompute from history and apply the guard-mode headroom.
    let repo = AnalyticsRepository::new(pool.clone());
    let ceilings: HashMap<String, u64> = match repo
        .get_workflow_node_fuel_stats(workflow_id, WINDOW_DAYS, MIN_SAMPLES)
        .await
    {
        Ok(stats) => stats
            .into_iter()
            .map(|s| (s.node_label, adaptive_ceiling(s.fuel_p95, s.fuel_max)))
            .collect(),
        Err(e) => {
            // Fail-open: fall back to static ceilings, retry after the TTL.
            tracing::warn!(
                error = %e,
                %workflow_id,
                "adaptive fuel: node fuel-stats query failed; using static ceilings"
            );
            HashMap::new()
        }
    };

    if let Ok(mut guard) = cache().lock() {
        // Sweep expired entries on every (infrequent, once-per-TTL-per-workflow)
        // insert, and hard-bound the map so a churn of distinct workflow ids
        // can't grow it without limit.
        guard.retain(|_, e| e.computed_at.elapsed() < CACHE_TTL);
        if guard.len() >= MAX_CACHED_WORKFLOWS {
            guard.clear();
        }
        guard.insert(
            workflow_id,
            Entry {
                computed_at: Instant::now(),
                ceilings: ceilings.clone(),
            },
        );
    }

    ceilings
}
