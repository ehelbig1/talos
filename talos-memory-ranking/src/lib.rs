//! # Adaptive per-actor memory ranking — Phase 2 (the learned ranker)
//!
//! Phase 1 (`talos_memory::fetch_rank_training_examples` + the
//! `execution_memory_context` provenance table) records, for every memory that
//! was injected into an actor's `__actor_context__`, its ranking-feature
//! snapshot joined to the execution OUTCOME. Phase 2 LEARNS a per-actor set of
//! fused-ranking weights from that corpus, replacing the global
//! `SMART_MEMORY_CONTEXT_W_*` constants with weights adapted to which memories
//! actually preceded good outcomes for THAT actor.
//!
//! ## Shape
//! * [`model`] — the tiny per-actor weighted logistic regression
//!   ([`fit_rank_weights`]) over the four recorded features
//!   `[relevance, recency, importance, access_boost]`, the [`RankWeights`]
//!   artifact stored in `actors.metadata.rank_weights`, and the
//!   coefficient → fused-weight mapping ([`rank_weights_to_fused`]).
//! * [`spawn_rank_training_scheduler`] — the default-OFF background fit job.
//! * [`load_serving_weights`] — the serving-side read that the ranker seam in
//!   `talos-workflow-repository` calls when `ENABLE_ADAPTIVE_RANK` is on.
//!
//! ## Safety invariants
//! * **Default-OFF** on both flags (`ENABLE_ADAPTIVE_RANK` serving /
//!   `ENABLE_ADAPTIVE_RANK_TRAINING` training). Flag-off ⇒ byte-identical
//!   ranking to today AND no training task spawned.
//! * **Per-actor isolation** — training reads only `WHERE actor_id = $1`
//!   examples (Phase-1 query) and writes only that actor's `metadata`
//!   (`get`/`set_actor_rank_weights` key strictly on `actor_id`). One actor's
//!   outcomes can NEVER move another's weights.
//! * **Bounded / clamped** — mapped fused weights are non-negative and capped
//!   ([`FUSED_WEIGHT_MAX`]); access weight is `[0,1]`; the fit fails closed to
//!   `None` (→ global defaults) on non-finite output.
//! * **Cold-start-safe** — below the min-examples gate or single-class ⇒ no
//!   model written and serving falls back to global weights.
//! * **No LLM / no tier gate** — the fit is a PURE numeric computation over the
//!   Phase-1 numeric signals only (memory KEYS + feature scalars); it reads no
//!   memory VALUES and makes no external call, so there is zero data egress and
//!   thus (unlike consolidation/reflection) no `max_llm_tier` gate is needed.

pub mod model;

pub use model::{
    build_training_set, example_label, example_to_features, fit_rank_weights,
    rank_weights_to_fused, RankWeights, FUSED_WEIGHT_MAX, N_FEATURES,
};

use sqlx::PgPool;
use talos_actor_repository::ActorRepository;
use tokio::sync::watch;
use uuid::Uuid;

/// Upper bound on the per-actor training fetch, so one degenerate actor can't
/// pull an unbounded scan. The Phase-1 query additionally clamps its own limit.
const TRAINING_FETCH_CAP: i64 = 20_000;

/// Serving-side load of an actor's learned fused weights, for the ranker seam.
///
/// Returns `Some((weights, access_weight))` ONLY when a learned model exists,
/// parses, is backed by at least [`talos_config::adaptive_rank_min_examples`]
/// examples, and maps to at least one non-zero base weight. Every other case —
/// no row, unparseable, too-few examples, an all-zero (fully-degenerate)
/// mapping, or any DB error — returns `None`, and the caller falls back to the
/// exact global-config behaviour (cold-start / flag-off parity). Errors are
/// non-fatal and logged at debug; this is a cheap single indexed SELECT by
/// `actor_id`.
///
/// Note: this does NOT check `ENABLE_ADAPTIVE_RANK` — the caller gates on the
/// flag so a flag-off path skips the read entirely.
pub async fn load_serving_weights(
    pool: &PgPool,
    actor_id: Uuid,
) -> Option<(talos_memory::actor_context::Weights, f64)> {
    let actor_repo = ActorRepository::new(pool.clone());
    let raw = match actor_repo.get_actor_rank_weights(actor_id).await {
        Ok(Some(v)) => v,
        Ok(None) => return None, // cold-start: no learned weights yet
        Err(e) => {
            tracing::debug!(target: "talos_memory_ranking", %actor_id, error = %e, "rank-weights read failed; using global defaults");
            return None;
        }
    };
    let rw: RankWeights = match serde_json::from_value(raw) {
        Ok(rw) => rw,
        Err(e) => {
            tracing::debug!(target: "talos_memory_ranking", %actor_id, error = %e, "rank-weights parse failed; using global defaults");
            return None;
        }
    };
    // Below the trust threshold → global defaults (a stale under-trained row
    // must never serve).
    if rw.n_examples < talos_config::adaptive_rank_min_examples() {
        return None;
    }
    let (weights, access_weight) = rank_weights_to_fused(&rw);
    // Fully-degenerate mapping (every base coefficient non-positive) would zero
    // the fused score and collapse ranking to tie-break order — fall back to
    // global weights instead.
    if weights.relevance <= 0.0 && weights.recency <= 0.0 && weights.importance <= 0.0 {
        tracing::debug!(target: "talos_memory_ranking", %actor_id, "learned weights all non-positive; using global defaults");
        return None;
    }
    Some((weights, access_weight))
}

/// Spawn the per-actor rank-training scheduler. Default-OFF: when
/// [`talos_config::adaptive_rank_training_enabled`] is false, logs once and
/// returns WITHOUT spawning a task (zero background overhead).
///
/// `actor_repo` need only carry the DB pool — the scan/read/write are plain
/// `actors` reads/writes. No LLM, no secrets, no tier gate (pure numeric fit;
/// see the crate doc).
pub fn spawn_rank_training_scheduler(
    pool: PgPool,
    actor_repo: ActorRepository,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    if !talos_config::adaptive_rank_training_enabled() {
        tracing::info!(
            target: "talos_memory_ranking",
            "adaptive rank training disabled (ENABLE_ADAPTIVE_RANK_TRAINING unset); scheduler not spawned"
        );
        return;
    }

    let interval_secs = talos_config::adaptive_rank_training_interval_secs();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tracing::info!(
            target: "talos_memory_ranking",
            interval_secs,
            "adaptive rank training scheduler active"
        );
        loop {
            tokio::select! {
                biased;
                _ = shutdown_rx.changed() => {
                    tracing::info!(target: "talos_memory_ranking", "adaptive rank training scheduler shutting down");
                    break;
                }
                _ = interval.tick() => {
                    if let Err(e) = run_rank_training_tick(&pool, &actor_repo).await {
                        tracing::warn!(target: "talos_memory_ranking", error = %e, "rank training tick failed; retrying next interval");
                    }
                }
            }
        }
    });
}

/// One training pass over the fleet. Scans up to
/// `adaptive_rank_max_actors_per_tick` active actors; for each, fetches its
/// Phase-1 examples within the lookback window, builds the labeled training set,
/// fits, and — only when the fit yields a model — persists it to that actor's
/// `metadata.rank_weights`. Every per-actor error logs and continues; a `None`
/// fit (too few / single-class) skips the actor at debug, leaving it on global
/// defaults. Bounded per-tick work (`max_actors` × `TRAINING_FETCH_CAP`).
async fn run_rank_training_tick(pool: &PgPool, actor_repo: &ActorRepository) -> anyhow::Result<()> {
    let max_actors = talos_config::adaptive_rank_max_actors_per_tick();
    let lookback_days = talos_config::adaptive_rank_lookback_days();
    let since = chrono::Utc::now() - chrono::Duration::days(lookback_days);

    let actor_ids = actor_repo.scan_actors_for_rank_training(max_actors).await?;
    tracing::debug!(
        target: "talos_memory_ranking",
        actor_count = actor_ids.len(),
        lookback_days,
        "rank training tick scanning actors"
    );

    for &actor_id in &actor_ids {
        // Phase-1 fetch is actor-scoped (`WHERE emc.actor_id = $1`): a fit for
        // this actor consumes ONLY this actor's provenance rows.
        let examples = match talos_memory::fetch_rank_training_examples(
            pool,
            actor_id,
            since,
            TRAINING_FETCH_CAP,
        )
        .await
        {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(target: "talos_memory_ranking", %actor_id, error = %e, "training-example fetch failed; skipping actor");
                continue;
            }
        };

        let train = model::build_training_set(&examples);
        match model::fit_rank_weights(&train) {
            Some(rw) => {
                let json = match serde_json::to_value(&rw) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(target: "talos_memory_ranking", %actor_id, error = %e, "rank-weights serialize failed; skipping actor");
                        continue;
                    }
                };
                // Keyed strictly on `actor_id` — writes ONLY this actor's row.
                match actor_repo.set_actor_rank_weights(actor_id, &json).await {
                    Ok(updated) => tracing::info!(
                        target: "talos_memory_ranking",
                        %actor_id,
                        updated,
                        n_examples = rw.n_examples,
                        w_relevance = rw.w_relevance,
                        w_recency = rw.w_recency,
                        w_importance = rw.w_importance,
                        w_access = rw.w_access,
                        "fit per-actor rank weights"
                    ),
                    Err(e) => {
                        tracing::warn!(target: "talos_memory_ranking", %actor_id, error = %e, "rank-weights write failed")
                    }
                }
            }
            None => tracing::debug!(
                target: "talos_memory_ranking",
                %actor_id,
                usable_examples = train.len(),
                "insufficient / single-class training data; keeping global defaults"
            ),
        }
    }

    // Advance the rotation cursor for every actor this tick examined (fit or
    // skipped) so the next tick moves on to the least-recently-trained actors —
    // fair fleet coverage. Best-effort; a failure only means a repeat next tick.
    if let Err(e) = actor_repo.mark_actors_rank_trained(&actor_ids).await {
        tracing::warn!(target: "talos_memory_ranking", error = %e, "failed to advance rank-training rotation cursor");
    }
    Ok(())
}
