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
pub mod recall;

pub use model::{
    build_training_set, example_label, example_to_features, fit_rank_weights,
    rank_weights_to_fused, FetchProvenance, RankWeights, FUSED_WEIGHT_MAX,
    INERT_LOOKBACK_MIN_SHORTFALL_DAYS, N_FEATURES,
};
pub use recall::recall_semantic_ranked;

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};
use std::time::{Duration, Instant};

use sqlx::PgPool;
use talos_actor_repository::ActorRepository;
use tokio::sync::watch;
use uuid::Uuid;

/// Upper bound on the per-actor training fetch, so one degenerate actor can't
/// pull an unbounded scan. The Phase-1 query additionally clamps its own limit
/// (`talos_memory::RANK_TRAINING_EXAMPLE_MAX`, 50 000 — a second, higher ceiling
/// on the same path).
///
/// The fetch orders `created_at DESC`, so when this binds the fit sees the
/// NEWEST rows of the lookback window and the older remainder is never read.
/// That is defensible as recency bias for a ranker — but it is NOT defensible
/// for the fit to then report `n_examples` as if it were the population, so the
/// training tick measures the window and records a
/// [`model::FetchProvenance`] with every model. It binds today:
/// `personal-assistant` had 55 179 rows in a 30-day window on 2026-08-19.
///
/// Changing this value is a PERFORMANCE decision (it bounds per-tick work as
/// `max_actors × TRAINING_FETCH_CAP`), and belongs to the operator.
///
/// **It is deliberately NOT a knob, and cost is not the reason** (decided
/// 2026-09-09). This cap binds before `ADAPTIVE_RANK_LOOKBACK_DAYS`, whose
/// documented range is `[1, 3650]` days — measured on the reference fleet, the
/// configured 30 days was a fitted 6.56 and every value from 7 to 3650 produced
/// a bit-identical model. Making the cap tunable would NOT restore that range,
/// because two further ceilings bind above it:
/// `talos_memory::RANK_TRAINING_EXAMPLE_MAX` (50 000, ~17 days) and, decisively,
/// execution ARCHIVAL at `ARCHIVE_AFTER_DAYS` (default 30) — past which a
/// provenance row's `LEFT JOIN workflow_executions` finds nothing, so it arrives
/// UNLABELED and `build_training_set` drops it. Measured: rows with a live
/// execution saturate at 72 712 from 30 days on while the raw count climbs to
/// 110 812 at 60. A knob that still could not reach its documented range would
/// be this same defect with an extra step.
///
/// Cost was measured rather than assumed, so it cannot be cited as the reason:
/// the production fetch is ~18 ms at 20 000 rows and ~59 ms at 50 000
/// (`EXPLAIN ANALYZE`, three runs each), on a six-hourly tick over ≤50 actors.
///
/// Consequently **training on recent outcomes is a DECISION here, not a side
/// effect of the `ORDER BY`** — and the load-bearing half is the label horizon,
/// not this cap: past ~30 days the corpus has no labels at all, so a
/// recency-weighted fit is the only thing it can support.
const TRAINING_FETCH_CAP: i64 = 20_000;

/// Milliseconds in a day, for turning a `chrono::Duration` into the fractional
/// days the disclosure reports. `num_days()` truncates toward zero, which would
/// render a 6.56-day effective window as "6" and a 0.9-day one as "0".
const MILLIS_PER_DAY: f64 = 86_400_000.0;

// ── Serving-weights cache (F3) ──────────────────────────────────────────────
//
// `load_serving_weights` is called on EVERY grounded recall through the ranker
// seam. Uncached, each call did one indexed `actors` SELECT (+ built a throwaway
// `ActorRepository`). Learned weights change only once per training tick (daily
// by default), so a short-TTL read-through cache turns the steady state into a
// pure in-memory lookup. Both POSITIVE (learned weights) and NEGATIVE
// (cold-start `None`) results are cached — cold-start actors would otherwise hit
// the DB every recall too.
//
// Freshness: the training tick calls `invalidate_serving_weights(actor)` right
// after it writes new weights, so on the writing controller a fresh fit serves
// IMMEDIATELY. On OTHER controllers in a multi-replica deployment the TTL is the
// propagation bound (fine for daily-cadence weights). The TTL also bounds entry
// lifetime for actors whose recall traffic goes quiet.
//
// Growth is bounded WITHOUT a background task: an insert that finds the map at
// or above `SERVING_WEIGHTS_SWEEP_THRESHOLD` first reaps expired entries
// (read-path eviction handles active actors; this amortized sweep handles ones
// that went dark), and a hard `SERVING_WEIGHTS_MAX_ENTRIES` backstop clears the
// map if the live set is still pathologically large (cheap — it self-refills).
const SERVING_WEIGHTS_TTL: Duration = Duration::from_secs(300);
const SERVING_WEIGHTS_SWEEP_THRESHOLD: usize = 4_096;
const SERVING_WEIGHTS_MAX_ENTRIES: usize = 50_000;

struct ServingWeightsEntry {
    /// `None` = cold-start (no usable learned weights) — cached so cold-start
    /// actors don't re-hit the DB every recall.
    value: Option<(talos_memory::actor_context::Weights, f64)>,
    expires_at: Instant,
}

fn serving_weights_cache() -> &'static RwLock<HashMap<Uuid, ServingWeightsEntry>> {
    static CACHE: OnceLock<RwLock<HashMap<Uuid, ServingWeightsEntry>>> = OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Drop any cached serving weights for `actor_id` so the next recall re-reads
/// from the DB. Called by the training tick immediately after it writes new
/// weights (scoped write-path invalidation — see the cache patterns in
/// CLAUDE.md). Poison-tolerant: a poisoned lock still yields the map.
pub fn invalidate_serving_weights(actor_id: Uuid) {
    serving_weights_cache()
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(&actor_id);
}

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
///
/// Backed by a short-TTL process-local cache (see the module constants): a hit
/// returns without touching the DB; a miss loads via [`load_serving_weights_db`]
/// and populates the cache. The training tick invalidates on write.
pub async fn load_serving_weights(
    pool: &PgPool,
    actor_id: Uuid,
) -> Option<(talos_memory::actor_context::Weights, f64)> {
    // Fast path: cache hit that hasn't expired.
    {
        let cache = serving_weights_cache()
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(entry) = cache.get(&actor_id) {
            if entry.expires_at > Instant::now() {
                return entry.value;
            }
        }
    }

    // Miss (or expired): load from DB and populate the cache (positive AND
    // negative results are cached).
    let value = load_serving_weights_db(pool, actor_id).await;
    let entry = ServingWeightsEntry {
        value,
        expires_at: Instant::now() + SERVING_WEIGHTS_TTL,
    };
    {
        let mut cache = serving_weights_cache()
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Amortized sweep: when the map grows past the threshold, reap expired
        // entries (handles actors that went dark); if the live set is still
        // pathological, hard-clear (self-refills). Bounds growth with no task.
        if cache.len() >= SERVING_WEIGHTS_SWEEP_THRESHOLD {
            let now = Instant::now();
            cache.retain(|_, e| e.expires_at > now);
            if cache.len() >= SERVING_WEIGHTS_MAX_ENTRIES {
                cache.clear();
            }
        }
        cache.insert(actor_id, entry);
    }
    value
}

/// Uncached DB read of an actor's learned fused weights. See
/// [`load_serving_weights`] for the contract; this is the miss path.
async fn load_serving_weights_db(
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
    // Supervised: the shutdown arm `break`s, so a clean stop is real and
    // was previously invisible.
    talos_task_supervision::spawn_supervised(
        talos_task_supervision::BackgroundTask::RankTrainingScheduler,
        async move {
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
                        break talos_task_supervision::TaskExit::ShuttingDown;
                    }
                    _ = interval.tick() => {
                        if let Err(e) = run_rank_training_tick(&pool, &actor_repo).await {
                            tracing::warn!(target: "talos_memory_ranking", error = %e, "rank training tick failed; retrying next interval");
                        }
                    }
                }
            }
        },
    );
}

/// Per-tick accounting for the TRAINING WINDOW — the half of the truncation
/// disclosure denominated in DAYS rather than rows.
///
/// It exists as a type rather than two loose statements for the reason #654
/// made `FetchProvenance` a required argument of [`model::fit_rank_weights`]:
/// [`Self::observe`] is the tick's ONLY source of a `FetchProvenance`, and the
/// fit cannot run without one, so the coverage counter cannot be forgotten
/// without the fit failing to compile. The gauge's [`Self::publish`] is an
/// ordinary call site and is NOT protected that way — see the stated limits on
/// `window_accounting_tests`.
#[derive(Debug, Default)]
struct TickWindowAccounting {
    /// Widest gap, in days, between the CONFIGURED window and the one a single
    /// fit actually saw. Starts at "nothing fell short" and only ever widens.
    worst_shortfall_days: f64,
}

impl TickWindowAccounting {
    /// Classify one actor's fetch, move the coverage counter, and fold its
    /// shortfall into the tick's worst case.
    ///
    /// `examples` is the fetch's own result, still ordered `created_at DESC`, so
    /// its LAST element is the oldest row the fit could see — the far edge of
    /// the window that was actually read. Free: the rows are already in memory,
    /// so the days half of this disclosure costs no query even when the cap
    /// binds (the row half's `count(*)` is issued by the caller, and only when
    /// it must be).
    fn observe(
        &mut self,
        examples: &[talos_memory::RankTrainingExample],
        n_fetched: i64,
        n_available: Option<i64>,
        lookback_days: i64,
        now: chrono::DateTime<chrono::Utc>,
    ) -> model::FetchProvenance {
        let oldest_fetched_age_days = examples
            .last()
            .map(|e| (now - e.created_at).num_milliseconds() as f64 / MILLIS_PER_DAY);
        let fetch = model::FetchProvenance::new(
            n_fetched,
            TRAINING_FETCH_CAP,
            n_available,
            Some(lookback_days),
            oldest_fetched_age_days,
        );
        // `coverage` is a closed compile-time set and carries NO actor id —
        // that is caller-influenced and stays a log FIELD. One classification
        // per fetch, so the two series partition the actors this tick examined.
        talos_metrics::record_rank_training_fetch(if fetch.truncated() {
            talos_metrics::RANK_TRAINING_COVERAGE_TRUNCATED
        } else {
            talos_metrics::RANK_TRAINING_COVERAGE_COMPLETE
        });
        if let Some(shortfall) = fetch.lookback_shortfall_days() {
            self.worst_shortfall_days = self.worst_shortfall_days.max(shortfall);
        }
        fetch
    }

    /// Publish the tick's worst shortfall. Called ONCE, after every actor has
    /// been classified, so the gauge is a completed measurement rather than a
    /// value that walks up through the loop.
    ///
    /// WORST case across the tick because `actor_id` cannot be a label; the
    /// paired counter says how many fits were affected, and is what
    /// distinguishes this gauge's 0 ("nothing fell short") from a controller
    /// that has not ticked yet.
    fn publish(&self) {
        talos_metrics::set_rank_training_lookback_shortfall_days(self.worst_shortfall_days);
    }
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
    // ONE clock for the whole tick. `since` and every `oldest_fetched_age_days`
    // must be read against the same instant, or the shortfall between the
    // configured and the effective window carries the tick's own duration.
    let now = chrono::Utc::now();
    let since = now - chrono::Duration::days(lookback_days);
    // Per-tick window accounting: the coverage counter, and the worst shortfall
    // seen across the fleet for the label-free gauge.
    let mut window = TickWindowAccounting::default();

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

        // Instrument for the order-free label rule: an execution whose scored
        // judges disagreed contributes NO judge label (it falls through to the
        // weaker status label). That withdrawal must be visible — a silently
        // shrinking labeled set is the same defect one level up.
        let disputed = examples.iter().filter(|e| e.judge_disputed).count();
        if disputed > 0 {
            tracing::info!(
                target: "talos_memory_ranking",
                %actor_id,
                disputed_examples = disputed,
                total_examples = examples.len(),
                "provenance rows whose execution's judges disagreed — labeled by \
                 execution status instead of a judge verdict"
            );
        }

        // ── Fetch accounting (the disclosure) ──────────────────────────────
        //
        // `TRAINING_FETCH_CAP` takes the NEWEST rows in the lookback window and
        // drops the rest. The fit then reports `n_examples`, which without this
        // block equals the cap and reads as "trained on everything available" —
        // a measurement of the limit presented as a measurement of the
        // population. Observed live 2026-08-19: `personal-assistant` had 55 179
        // rows in its 30-day window, the fetch returned 20 000, and the stored
        // artifact said `n_examples: 20000` and nothing else.
        //
        // The population count is issued ONLY when the cap actually bound. An
        // unbound fetch has already read every row in the window, so its own
        // length IS the denominator and the extra scan would buy nothing. A
        // fleet with no truncating actor therefore pays zero additional queries.
        let n_fetched = examples.len() as i64;
        let fetch_bound = n_fetched >= TRAINING_FETCH_CAP;
        let n_available = if fetch_bound {
            match talos_memory::count_rank_training_examples(pool, actor_id, since).await {
                Ok(n) => Some(n),
                // A failed count leaves the population UNKNOWN. It must not
                // degrade to `Some(n_fetched)` — that would assert "nothing was
                // dropped" about the one case where something certainly was.
                Err(e) => {
                    tracing::warn!(
                        target: "talos_memory_ranking",
                        %actor_id,
                        error = %e,
                        "training-window population count failed; the fit will \
                         record its fetch as truncated with an unknown denominator"
                    );
                    None
                }
            }
        } else {
            Some(n_fetched)
        };
        // The provenance is minted HERE, through the tick's accounting, which
        // is what makes the machine-readable half structural rather than a call
        // site someone can delete: `fit_rank_weights` REQUIRES a
        // `FetchProvenance` (#654's rule), and this is the tick's only way to
        // obtain one — so a fit cannot be produced without the coverage counter
        // having moved and the shortfall having been folded in.
        let fetch = window.observe(&examples, n_fetched, n_available, lookback_days, now);

        if fetch.truncated() {
            // WARN, and say which direction the truncation runs. Unlike the
            // fuel-headroom sweep — whose `ORDER BY utilisation DESC` keeps the
            // numerator complete so only a denominator under-reports — this
            // fetch orders by `created_at DESC`, so what is dropped is the OLDER
            // half of the window. That is a recency bias, not a missing tail.
            tracing::warn!(
                target: "talos_memory_ranking",
                %actor_id,
                event_kind = "rank_training_truncated",
                cap = TRAINING_FETCH_CAP,
                n_fetched,
                n_available = n_available.unwrap_or(-1),
                n_dropped = fetch.n_dropped().unwrap_or(-1),
                lookback_days,
                // The three fields that put the row accounting into the unit the
                // operator configured. Without them a reader learns that rows
                // were dropped and still cannot tell that raising the knob would
                // change nothing.
                effective_lookback_days = fetch.effective_lookback_days().unwrap_or(-1.0),
                lookback_shortfall_days = fetch.lookback_shortfall_days().unwrap_or(-1.0),
                lookback_inert = fetch.lookback_inert(),
                "rank-training fetch hit its row cap; the fit sees only the \
                 NEWEST rows of the lookback window and the model's n_examples \
                 measures the cap, not the window. ADAPTIVE_RANK_LOOKBACK_DAYS \
                 is effective DOWNWARD ONLY here: raising it past \
                 effective_lookback_days adds no rows to the fit, it only \
                 widens the population this line reports as dropped \
                 (-1 = unmeasured)"
            );
        }

        let train = model::build_training_set(&examples);
        match model::fit_rank_weights(&train, fetch) {
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
                    Ok(updated) => {
                        // Scoped write-path invalidation: drop this actor's
                        // cached serving weights so the fresh fit serves on the
                        // very next recall (no waiting out the TTL on the
                        // writing controller).
                        invalidate_serving_weights(actor_id);
                        tracing::info!(
                            target: "talos_memory_ranking",
                            %actor_id,
                            updated,
                            n_examples = rw.n_examples,
                            n_fetched,
                            fetch_truncated = fetch.truncated(),
                            n_available = n_available.unwrap_or(-1),
                            w_relevance = rw.w_relevance,
                            w_recency = rw.w_recency,
                            w_importance = rw.w_importance,
                            w_access = rw.w_access,
                            "fit per-actor rank weights"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(target: "talos_memory_ranking", %actor_id, error = %e, "rank-weights write failed")
                    }
                }
            }
            // INFO (not DEBUG): this per-actor-per-tick line is how an operator
            // sees WHICH actors aren't learning yet and WHY (too few / one-class
            // examples). At DEBUG it was invisible under the prod INFO level, so
            // "training is on but nothing is being learned" looked like silence.
            // Low-frequency (bounded per tick, daily cadence) — no spam risk,
            // unlike the per-recall serving-side fallbacks which stay DEBUG.
            None => tracing::info!(
                target: "talos_memory_ranking",
                %actor_id,
                usable_examples = train.len(),
                n_fetched,
                fetch_truncated = fetch.truncated(),
                disputed_examples = disputed,
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

    window.publish();
    Ok(())
}

#[cfg(test)]
mod serving_cache_tests {
    use super::*;

    fn sample() -> (talos_memory::actor_context::Weights, f64) {
        (
            talos_memory::actor_context::Weights {
                relevance: 0.5,
                recency: 0.3,
                importance: 0.2,
                recency_halflife_days: 30.0,
            },
            0.1,
        )
    }

    fn insert(
        actor_id: Uuid,
        value: Option<(talos_memory::actor_context::Weights, f64)>,
        ttl: Duration,
    ) {
        serving_weights_cache()
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                actor_id,
                ServingWeightsEntry {
                    value,
                    expires_at: Instant::now() + ttl,
                },
            );
    }

    fn peek(actor_id: Uuid) -> Option<Option<(talos_memory::actor_context::Weights, f64)>> {
        let cache = serving_weights_cache()
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cache
            .get(&actor_id)
            .and_then(|e| (e.expires_at > Instant::now()).then_some(e.value))
    }

    #[test]
    fn invalidate_removes_cached_entry() {
        let actor = Uuid::new_v4();
        insert(actor, Some(sample()), SERVING_WEIGHTS_TTL);
        assert!(
            peek(actor).is_some(),
            "entry should be present before invalidation"
        );
        invalidate_serving_weights(actor);
        assert!(
            peek(actor).is_none(),
            "invalidation must drop the entry so the next recall re-reads the DB"
        );
    }

    #[test]
    fn expired_entry_is_not_served() {
        let actor = Uuid::new_v4();
        // Already-expired TTL → the read-path freshness check must reject it.
        insert(actor, Some(sample()), Duration::from_millis(0));
        assert!(
            peek(actor).is_none(),
            "an expired entry must not be served (read-path eviction)"
        );
        invalidate_serving_weights(actor);
    }

    #[test]
    fn negative_result_is_cacheable() {
        // Cold-start `None` is cached too, so cold-start actors don't re-hit the
        // DB every recall.
        let actor = Uuid::new_v4();
        insert(actor, None, SERVING_WEIGHTS_TTL);
        // `Weights` isn't `PartialEq`, so match the shape rather than `assert_eq!`.
        assert!(
            matches!(peek(actor), Some(None)),
            "None must round-trip through the cache (fresh entry, value == None)"
        );
        invalidate_serving_weights(actor);
    }
}

/// **The wiring nothing else can see.** The adaptive rank-training scheduler goes through
/// `talos_task_supervision::spawn_supervised`; reverting that site to a
/// bare `tokio::spawn` is behaviourally identical on a healthy process
/// and completely silent on a dead one — no metric moves, no log line
/// appears, and every operator surface keeps reporting the subsystem as
/// configured. Structural lint check 58 cannot see it either: it asks
/// whether a metric has an increment SITE, not whether anything reaches
/// one.
///
/// No other spawn site exists in this crate.
///
/// The counting rule lives in `talos_task_supervision` so the pins in
/// the eight crates that carry one cannot drift; its stated limits
/// (textual, per-file, blind to WHICH task is named) apply here.
#[cfg(test)]
mod task_supervision_pin {
    #[test]
    fn the_long_lived_loop_is_supervised() {
        let (supervised, bare) =
            talos_task_supervision::production_spawn_counts(include_str!("lib.rs"));
        assert_eq!(
            supervised, 1,
            "The adaptive rank-training scheduler must still go through spawn_supervised"
        );
        assert_eq!(
            bare, 0,
            "the set of deliberately-unsupervised one-shot spawns in this file changed"
        );
    }
}

/// The DAYS half of the truncation disclosure, driven through the same
/// [`TickWindowAccounting`] the production tick uses.
///
/// **Why this exists at all.** `ADAPTIVE_RANK_LOOKBACK_DAYS` is documented as a
/// training window clamped to `[1, 3650]` days; [`TRAINING_FETCH_CAP`] binds
/// first, and on the reference fleet the configured 30 days was a fitted 6.56
/// with every value from 7 to 3650 producing a bit-identical model. The
/// pre-existing disclosure is denominated in ROWS, and its row counts MOVE when
/// the inert knob is turned — raising 30 → 90 grew `window_rows_dropped` from
/// 52 642 to 90 805 while the fitted coefficients did not change a bit, which
/// reads as the change taking effect. These assertions are about the number
/// that cannot do that.
///
/// **Stated limits, so the coverage is not overstated.**
/// * [`TickWindowAccounting::observe`] is protected STRUCTURALLY — it is the
///   tick's only source of the `FetchProvenance` that [`model::fit_rank_weights`]
///   requires, so deleting the counter means deleting the fit. [`
///   TickWindowAccounting::publish`] is an ordinary call site: a tick that
///   computes the shortfall correctly and never publishes it survives every
///   test here, which is checks 74b/79b's stated limit and is why the call sits
///   at the tick's single exit.
/// * The WARN's own fields are not asserted (a `tracing` line is not readable
///   in-process); every one of them is `fetch.<method>()`, and those methods
///   are asserted in `model::tests`.
/// * Nothing here proves the tick passes the fetch's REAL rows — that needs a
///   database, and this crate has no DB harness. It is the same residual
///   #654 carried.
#[cfg(test)]
mod window_accounting_tests {
    use super::*;
    use talos_memory::RankTrainingExample;

    /// The one accessor, never a second installer.
    ///
    /// `talos_metrics::set_global` is a one-shot `OnceLock`, so a test that
    /// installs its OWN registry and asserts against that local `Arc` is
    /// correct only if it wins the race — every production site writes through
    /// `talos_metrics::global()`. Returning the INSTALLED one makes the
    /// assertions order-independent, and every caller must read DELTAS.
    fn installed_test_metrics() -> std::sync::Arc<talos_metrics::TalosMetrics> {
        if let Some(m) = talos_metrics::global() {
            return m.clone();
        }
        let m = talos_metrics::TalosMetrics::new().expect("metrics registry");
        talos_metrics::set_global(m);
        talos_metrics::global()
            .cloned()
            .expect("a global registry is installed by now")
    }

    fn row(age_days: f64, now: chrono::DateTime<chrono::Utc>) -> RankTrainingExample {
        RankTrainingExample {
            memory_key: "k".to_string(),
            relevance: 0.5,
            recency: 0.5,
            importance: 0.5,
            access_boost: None,
            fused_score: 0.0,
            rank: 0,
            judge_score: None,
            judge_passed: Some(true),
            judge_disputed: false,
            execution_status: Some("completed".to_string()),
            created_at: now - chrono::Duration::milliseconds((age_days * MILLIS_PER_DAY) as i64),
        }
    }

    /// `created_at DESC`, newest first — the order the Phase-1 fetch returns.
    fn window_of(ages: &[f64], now: chrono::DateTime<chrono::Utc>) -> Vec<RankTrainingExample> {
        ages.iter().map(|&a| row(a, now)).collect()
    }

    #[test]
    fn a_capped_fetch_reports_the_window_it_actually_saw_not_the_one_configured() {
        let now = chrono::Utc::now();
        let mut w = TickWindowAccounting::default();
        // The live shape: a 30-day knob, a fetch that stopped at the cap, and
        // an oldest row 6.5 days back.
        let rows = window_of(&[0.1, 3.0, 6.5], now);
        let fetch = w.observe(&rows, TRAINING_FETCH_CAP, Some(72_642), 30, now);

        assert!(fetch.truncated(), "n_fetched == cap must read as truncated");
        let effective = fetch
            .effective_lookback_days()
            .expect("a dated oldest row makes the effective window measurable");
        assert!(
            (effective - 6.5).abs() < 0.01,
            "the effective window is the age of the OLDEST row read, got {effective}"
        );
        assert!(
            (fetch.lookback_shortfall_days().unwrap() - 23.5).abs() < 0.01,
            "30 configured minus 6.5 seen is a 23.5-day shortfall"
        );
        assert!(
            fetch.lookback_inert(),
            "a 23.5-day shortfall means raising ADAPTIVE_RANK_LOOKBACK_DAYS \
             changes nothing — that is the whole finding"
        );
    }

    /// **The control half.** Without it the assertion above passes on a build
    /// that calls EVERY fit truncated, which is the disclosure crying wolf —
    /// and a disclosure nobody believes is worth no more than none.
    #[test]
    fn an_unbound_fetch_reports_the_configured_window_and_no_shortfall() {
        let now = chrono::Utc::now();
        let mut w = TickWindowAccounting::default();
        // Fewer rows than the cap, and the oldest is only 2 days back — the
        // window simply had nothing older in it.
        let rows = window_of(&[0.1, 2.0], now);
        let fetch = w.observe(&rows, 2, Some(2), 30, now);

        assert!(!fetch.truncated(), "a short fetch is not a truncated one");
        assert_eq!(
            fetch.effective_lookback_days(),
            Some(30.0),
            "an unbound fetch SEARCHED the whole configured window; reporting \
             the oldest surviving row here would report an empty tail as a \
             narrower window"
        );
        assert_eq!(fetch.lookback_shortfall_days(), Some(0.0));
        assert!(
            !fetch.lookback_inert(),
            "the knob is doing exactly what it says on this actor"
        );
    }

    /// A sub-day gap is measurement noise, not an inert knob: the configured
    /// window comes from the `since` the tick computed and the effective one
    /// from a clock read after the fetch returned.
    #[test]
    fn a_sub_day_gap_is_not_called_inert() {
        let now = chrono::Utc::now();
        let mut w = TickWindowAccounting::default();
        let rows = window_of(&[0.0, 29.4], now);
        let fetch = w.observe(&rows, TRAINING_FETCH_CAP, Some(99_999), 30, now);
        assert!(fetch.truncated());
        assert!(
            fetch.lookback_shortfall_days().unwrap() < INERT_LOOKBACK_MIN_SHORTFALL_DAYS,
            "0.6 days is below the threshold"
        );
        assert!(!fetch.lookback_inert(), "a 0.6-day gap must not cry wolf");
    }

    /// An EMPTY fetch has no oldest row, so its window is UNKNOWN — never the
    /// configured one, and never zero. It also cannot be truncated, so the
    /// unbound arm applies and the configured window is the honest answer;
    /// the assertion is that `oldest_fetched_age_days` stays absent rather than
    /// being manufactured.
    #[test]
    fn an_empty_fetch_dates_nothing() {
        let now = chrono::Utc::now();
        let mut w = TickWindowAccounting::default();
        let fetch = w.observe(&[], 0, Some(0), 30, now);
        assert_eq!(fetch.oldest_fetched_age_days, None);
        assert!(!fetch.truncated());
    }

    /// A truncated fetch whose oldest row could not be dated leaves the window
    /// UNKNOWN. `None`, never a number — the same rule `n_available` follows.
    #[test]
    fn a_truncated_fetch_with_no_dated_row_is_unknown_not_configured() {
        let fetch = model::FetchProvenance::new(
            TRAINING_FETCH_CAP,
            TRAINING_FETCH_CAP,
            None,
            Some(30),
            None,
        );
        assert!(fetch.truncated());
        assert_eq!(
            fetch.effective_lookback_days(),
            None,
            "an unmeasurable window must not degrade to the configured one — \
             that would assert the knob worked about the one case where it \
             certainly may not have"
        );
        assert_eq!(fetch.lookback_shortfall_days(), None);
        assert!(
            !fetch.lookback_inert(),
            "'inert' drives a sentence telling the operator their knob does \
             nothing; asserting that from an unmeasured fit is the determinate \
             negative this disclosure exists to remove"
        );
    }

    /// The series must MOVE — not merely have an increment site (check 58's
    /// stated limit). DELTAS, because `installed_test_metrics` returns the
    /// process-global registry that sibling tests also write to.
    #[test]
    fn observing_a_fetch_moves_its_coverage_series_and_publish_moves_the_gauge() {
        let m = installed_test_metrics();
        let now = chrono::Utc::now();
        let read = |coverage: &str| {
            m.rank_training_fetches_total
                .with_label_values(&[coverage])
                .get()
        };

        let trunc_before = read(talos_metrics::RANK_TRAINING_COVERAGE_TRUNCATED);
        let complete_before = read(talos_metrics::RANK_TRAINING_COVERAGE_COMPLETE);

        let mut w = TickWindowAccounting::default();
        w.observe(
            &window_of(&[0.0, 6.5], now),
            TRAINING_FETCH_CAP,
            Some(72_642),
            30,
            now,
        );
        assert_eq!(
            read(talos_metrics::RANK_TRAINING_COVERAGE_TRUNCATED),
            trunc_before + 1.0,
            "a capped fetch must move coverage=truncated"
        );
        assert_eq!(
            read(talos_metrics::RANK_TRAINING_COVERAGE_COMPLETE),
            complete_before,
            "and must NOT move coverage=complete — the two labels partition \
             every fetch, so a build that moved both would double-count the \
             fleet"
        );

        // The control: an unbound fetch moves the OTHER series.
        w.observe(&window_of(&[0.0, 1.0], now), 2, Some(2), 30, now);
        assert_eq!(
            read(talos_metrics::RANK_TRAINING_COVERAGE_COMPLETE),
            complete_before + 1.0,
        );
        assert_eq!(
            read(talos_metrics::RANK_TRAINING_COVERAGE_TRUNCATED),
            trunc_before + 1.0,
        );

        // The gauge carries the WORST shortfall across the tick — the 23.5-day
        // one, not the second observation's 0.
        w.publish();
        let gauge = m.rank_training_lookback_shortfall_days.get();
        assert!(
            (gauge - 23.5).abs() < 0.01,
            "publish() must report the tick's worst shortfall, got {gauge}"
        );
    }

    /// A tick in which nothing truncated must publish a real ZERO, not leave
    /// the previous tick's shortfall standing. Without this the gauge is a
    /// high-water mark that never comes down, and an operator who fixed the
    /// condition would keep reading the old number.
    #[test]
    fn a_clean_tick_publishes_zero() {
        let m = installed_test_metrics();
        let now = chrono::Utc::now();
        // Leave a non-zero value behind first, so the assertion is about the
        // reset rather than about an untouched gauge.
        let mut dirty = TickWindowAccounting::default();
        dirty.observe(
            &window_of(&[0.0, 5.0], now),
            TRAINING_FETCH_CAP,
            Some(99_999),
            30,
            now,
        );
        dirty.publish();
        assert!(m.rank_training_lookback_shortfall_days.get() > 1.0);

        let mut clean = TickWindowAccounting::default();
        clean.observe(&window_of(&[0.0, 1.0], now), 2, Some(2), 30, now);
        clean.publish();
        assert_eq!(
            m.rank_training_lookback_shortfall_days.get(),
            0.0,
            "a tick with no shortfall must say so, not inherit the last one"
        );
    }
}
