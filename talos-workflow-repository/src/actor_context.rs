//! Actor context + scratchpad access for workflow execution.
//!
//! NOTE (known domain leakage, follow-up from the crate review):
//! these methods reach into `talos-memory` (recall/persist) and
//! `talos-graph-rag` (`GRAPH_SERVICE`) rather than staying pure
//! workflow SQL. Kept verbatim in this split; extracting them to a
//! context service is the tracked follow-up.

use crate::*;

// `ActorMemory` struct removed alongside its sole consumer
// `get_actor_memories` (read from non-existent `actor_memories`
// plural table). For live reads use `talos_memory::list_memories`.

/// Which memory types are eligible for injection into `__actor_context__`.
///
/// The distinction is a SECURITY control: `working` memory is short-lived
/// scratch where a workflow might stash a transient token, so grounding-BY-
/// DEFAULT must not surface it into an execution trace. `Curated` is therefore
/// the default for auto-injection; `Full` is reserved for callers who pass
/// `inject_memory_context=true` deliberately (the trigger tool docs warn that
/// working/episodic memory can carry sensitive values that land in traces).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum MemoryScope {
    /// Durable, curated memory only: `semantic` + `episodic` (persona, daily
    /// briefs, meeting prep, consolidated facts). Excludes `working` (and
    /// `scratchpad`, which the retriever already drops). The secure default.
    #[default]
    Curated,
    /// All live memory types, including `working`. Deliberate opt-in.
    Full,
}

/// Drop memory rows outside the [`MemoryScope`]. `Curated` removes `working`
/// rows (`scratchpad` is already excluded upstream by the retriever); `Full`
/// is a no-op. Pure so the scope boundary is unit-testable.
pub(crate) fn apply_memory_scope(
    mut rows: Vec<(String, serde_json::Value, String)>,
    scope: MemoryScope,
) -> Vec<(String, serde_json::Value, String)> {
    if scope == MemoryScope::Curated {
        rows.retain(|(_, _, memory_type)| memory_type != "working");
    }
    rows
}

impl WorkflowRepository {
    // ── Actor memory (actor_memory table with memory_type) ─────────────────

    /// Fetch recent working/episodic memories for an actor (for context injection).
    pub async fn get_recent_actor_context(
        &self,
        actor_id: Uuid,
    ) -> Result<Vec<(String, serde_json::Value, String)>> {
        talos_memory::recall_recent_by_types(&self.db_pool, actor_id, &["working", "episodic"], 10)
            .await
    }

    /// Fetch relevant actor memories + graph context for injection.
    ///
    /// Three-layer retrieval:
    /// 1. **Graph RAG**: if Neo4j is connected and context_hint is provided,
    ///    traverse the knowledge graph to find related entities (people,
    ///    tickets, projects) and include them as structured context.
    /// 2. **Vector similarity**: embed the context_hint and find the most
    ///    semantically similar memories via pgvector cosine distance.
    /// 3. **Recency fallback**: if no embeddings or hint, return the most
    ///    recently updated memories across all types.
    ///
    /// The graph context is prepended as a special `__graph_context__`
    /// entry so the LLM sees entity relationships alongside memory values.
    ///
    /// `execution_id` is the execution this context is being packed for, used
    /// ONLY by the smart path to record memory-rank PROVENANCE (which keys +
    /// their ranking-feature snapshot) when `ENABLE_MEMORY_RANK_PROVENANCE` is
    /// on. `None` (draft/test/scheduler/sub-workflow paths) skips provenance —
    /// the ranking output is unaffected either way.
    ///
    /// `scope` bounds which memory TYPES are eligible (see [`MemoryScope`]):
    /// auto-injection passes `Curated` (durable semantic+episodic only, the
    /// secure default), while an explicit caller opt-in passes `Full`.
    pub async fn get_relevant_actor_context(
        &self,
        actor_id: Uuid,
        limit: usize,
        context_hint: Option<&str>,
        execution_id: Option<Uuid>,
        scope: MemoryScope,
    ) -> Result<Vec<(String, serde_json::Value, String)>> {
        let rows = self
            .get_relevant_actor_context_unscoped(actor_id, limit, context_hint, execution_id)
            .await?;
        Ok(apply_memory_scope(rows, scope))
    }

    /// Inner retriever, scope-unaware. See [`Self::get_relevant_actor_context`].
    async fn get_relevant_actor_context_unscoped(
        &self,
        actor_id: Uuid,
        limit: usize,
        context_hint: Option<&str>,
        execution_id: Option<Uuid>,
    ) -> Result<Vec<(String, serde_json::Value, String)>> {
        // Smart path (default-OFF): kind-filtered, min-score-floored,
        // byte-budgeted assembly. When the flag is OFF the legacy body
        // below runs unchanged — byte-identical output.
        if talos_config::smart_memory_context_enabled() {
            return self
                .get_relevant_actor_context_smart(actor_id, limit, context_hint, execution_id)
                .await;
        }

        let mut results: Vec<(String, serde_json::Value, String)> = Vec::new();

        // Layer 1: Graph RAG — traverse entity relationships.
        if let Some(hint) = context_hint {
            if let Some(graph) = talos_graph_rag::GRAPH_SERVICE.get() {
                match graph.get_graph_context(actor_id, hint, 2, 20).await {
                    Ok(ctx) => {
                        let entity_count = ctx
                            .get("entity_count")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        if entity_count > 0 {
                            results.push((
                                "__graph_context__".to_string(),
                                ctx,
                                "graph".to_string(),
                            ));
                        }
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "Graph context retrieval failed (non-fatal)");
                    }
                }
            }
        }

        // Layer 2: Vector similarity from pgvector.
        let vector_limit = if results.is_empty() {
            limit
        } else {
            limit.saturating_sub(1) // Reserve 1 slot for graph context
        };

        if let Some(hint) = context_hint {
            // Overfetch by 2x so we still hit `vector_limit` distinct
            // non-scratchpad neighbors after the filter below. Without the
            // pad, an actor with mostly engine-trace memories would see its
            // semantic context starved and fall through to Layer 3 every run.
            let vector_fetch_limit = vector_limit.saturating_mul(2).max(vector_limit + 5);
            let outcome = talos_memory::recall_semantic(
                &self.db_pool,
                actor_id,
                hint,
                vector_fetch_limit as i64,
                0.0,
                None,
                talos_memory::SearchMethod::Direct,
            )
            .await?;
            if outcome.method == "vector_cosine" && !outcome.hits.is_empty() {
                // Drop scratchpad engine-trace rows — they're per-execution
                // bookkeeping (key prefix `execution/<id>/trace`, type
                // `scratchpad`) whose JSON value embeds the previous run's
                // `__trigger_input__` which itself embeds `__actor_context__`.
                // Including them would make context injection grow recursively
                // by the entire prior call tree on every run, blowing fuel
                // budgets within a few iterations.
                let filtered: Vec<_> = outcome
                    .hits
                    .into_iter()
                    .filter(|h| h.memory_type != "scratchpad")
                    .take(vector_limit)
                    .map(|h| (h.key, h.value, h.memory_type))
                    .collect();
                if !filtered.is_empty() {
                    results.extend(filtered);
                    return Ok(results);
                }
                // All vector hits were scratchpad — fall through to Layer 3.
            }
        }

        // Layer 3: Recency fallback across non-scratchpad types. The
        // scratchpad exclusion mirrors Layer 2 — see comment above for
        // the recursive-context-growth rationale.
        let extra = talos_memory::recall_recent_excluding_types(
            &self.db_pool,
            actor_id,
            &["scratchpad"],
            limit as i64,
        )
        .await?;
        results.extend(extra);
        Ok(results)
    }

    /// Smart actor-context retriever — the ON branch of
    /// [`Self::get_relevant_actor_context`], gated by
    /// `talos_config::smart_memory_context_enabled()`.
    ///
    /// Improvements over the legacy path, all preserving the same
    /// tenancy/crypto invariants (only ever queries the bound `actor_id`,
    /// always through `talos_memory`'s decrypt-correct, tier-1-embed-gated
    /// recall APIs — no hand-rolled SQL/decrypt):
    /// 1. **Kind filter** — every layer excludes synthetic self-outputs
    ///    ([`talos_memory::SYNTHETIC_MEMORY_KINDS`]) so the LLM never
    ///    grounds on its own prior briefs/verdicts.
    /// 2. **Min-score floor** — semantic recall uses
    ///    `smart_memory_context_min_score()` instead of `0.0`, dropping
    ///    weak neighbours.
    /// 3. **Merge + dedup** — graph + semantic + recency layers are all
    ///    gathered (not early-returned) and de-duplicated by key, keeping the
    ///    highest-relevance instance of each.
    /// 4. **Fused ranking (Phase 2)** — the merged candidates are scored by a
    ///    weighted blend of relevance + recency-decay + importance
    ///    (`talos_memory::actor_context::fused_score`, weights from
    ///    `smart_memory_context_w_*`) and packed in fused-score order rather
    ///    than raw retrieval order.
    /// 5. **HyDE toggle (Phase 2)** — when `smart_memory_hyde_enabled()` is
    ///    ON the semantic layer embeds a HyDE-rewritten query
    ///    (`SearchMethod::HyDE`) instead of the raw hint; the same
    ///    `min_score` + `exclude_kinds` filters and the tier-1 embed gate
    ///    apply either way.
    /// 6. **Byte budget** — the ranked candidates are packed under
    ///    `smart_memory_context_byte_budget()` with a per-memory cap, so a
    ///    few large memories can't balloon a node's parse-fuel.
    async fn get_relevant_actor_context_smart(
        &self,
        actor_id: Uuid,
        limit: usize,
        context_hint: Option<&str>,
        execution_id: Option<Uuid>,
    ) -> Result<Vec<(String, serde_json::Value, String)>> {
        let byte_budget = talos_config::smart_memory_context_byte_budget();
        let per_memory_cap = talos_config::smart_memory_context_per_memory_cap();
        let min_score = talos_config::smart_memory_context_min_score();
        let exclude_kinds = talos_memory::synthetic_memory_kinds();

        // Layer 1: Graph RAG — entity relationships. Not a synthetic
        // self-output (no `metadata.kind`), so it is kept as-is; the
        // per-memory cap in the packer bounds its size like any other row.
        let mut graph_candidate: Option<(String, serde_json::Value, String)> = None;
        if let Some(hint) = context_hint {
            if let Some(graph) = talos_graph_rag::GRAPH_SERVICE.get() {
                match graph.get_graph_context(actor_id, hint, 2, 20).await {
                    Ok(ctx) => {
                        let entity_count = ctx
                            .get("entity_count")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        if entity_count > 0 {
                            graph_candidate =
                                Some(("__graph_context__".to_string(), ctx, "graph".to_string()));
                        }
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "Graph context retrieval failed (non-fatal)");
                    }
                }
            }
        }

        // Layer 2: Vector similarity — kind-filtered + min-score-floored.
        // Over-fetch 3x the count budget so we still have enough distinct
        // candidates after dedup + the byte-budget pack. `recall_semantic_filtered`
        // clamps the limit to [1, 50] internally and applies the
        // `metadata.kind != ALL(...)` + `>= min_score` predicates at the DB
        // layer (only ever scoped to the bound `actor_id`).
        //
        // Phase 2: the search METHOD is HyDE-toggled. Direct embeds the raw
        // hint; HyDE embeds a hypothetical-answer rewrite. Same filter/floor
        // args and the same tier-1 embed gate apply either way — we route
        // through `recall_semantic_filtered` (not the exclude-kinds-less
        // `recall_hyde` wrapper) precisely so the synthetic-kind filter is
        // preserved under HyDE.
        let search_method = if talos_config::smart_memory_hyde_enabled() {
            talos_memory::SearchMethod::HyDE
        } else {
            talos_memory::SearchMethod::Direct
        };
        let semantic_hits = if let Some(hint) = context_hint {
            let fetch = limit.saturating_mul(3).max(limit + 5) as i64;
            talos_memory::recall_semantic_filtered(
                &self.db_pool,
                actor_id,
                hint,
                fetch,
                min_score,
                None,
                search_method,
                &exclude_kinds,
            )
            .await?
            .hits
        } else {
            Vec::new()
        };

        // Layer 3: Recency — non-scratchpad, kind-filtered. Unlike the
        // legacy path (which only falls back here when semantic returned
        // nothing), the smart path always folds recency in and lets the
        // fused rank + byte budget decide what survives. The `_ts` variant
        // also projects `updated_at` so the recency signal survives into the
        // fused scorer (same decrypt column set + AAD path as the non-`_ts`
        // sibling — only `updated_at` is added).
        // Fetch recency at 1× the limit (not 2×). Recency rows enter the fused
        // rank at only the `recency_baseline` relevance and rarely out-score a
        // real semantic hit, so `limit` recent rows are ample headroom for the
        // final packed set — while every extra fetched row costs an AES-GCM
        // decrypt (per-row HKDF subkey) on this per-execution hot path. The 3×
        // semantic over-fetch already supplies the dedup/ranking headroom.
        let recency = talos_memory::recall_recent_excluding_types_and_kinds_ts(
            &self.db_pool,
            actor_id,
            &["scratchpad"],
            &exclude_kinds,
            limit as i64,
        )
        .await?;

        // Merge + dedup + scratchpad/floor selection (pure, tested), threading
        // the per-layer relevance/recency/importance signals into Candidates.
        let candidates = talos_memory::actor_context::select_candidates(
            graph_candidate,
            semantic_hits,
            recency,
            min_score,
            talos_config::smart_memory_context_graph_baseline(),
            talos_config::smart_memory_context_recency_baseline(),
        );

        // Fused multi-signal rank (relevance + recency-decay + importance),
        // then deterministically bound the assembled payload to the byte
        // budget in fused-score order. `now` is injected once here so the
        // production path uses the real clock while tests stay deterministic.
        // Fused-ranking weights. DEFAULT: the global `SMART_MEMORY_CONTEXT_W_*`
        // constants. When `ENABLE_ADAPTIVE_RANK` is on AND this actor has a
        // TRUSTED learned model (Phase 2), use its per-actor LEARNED weights
        // instead. Flag-off / no model / parse-fail / too-few-examples /
        // degenerate mapping ALL fall back here to the EXACT global-config
        // weights — so flag-off (or cold-start) ranking is byte-identical to
        // today. The learned weights only change the fused SCORE ORDER; the
        // recency half-life stays global (only the 3 blend weights + access are
        // learned) and `pack_within_budget` + everything downstream is
        // unchanged.
        let global_weights = talos_memory::actor_context::Weights {
            relevance: talos_config::smart_memory_context_w_relevance(),
            recency: talos_config::smart_memory_context_w_recency(),
            importance: talos_config::smart_memory_context_w_importance(),
            recency_halflife_days: talos_config::smart_memory_context_recency_halflife_days(),
        };
        let global_access_weight = talos_config::smart_memory_context_access_weight();
        let (weights, access_weight) = if talos_config::adaptive_rank_enabled() {
            // Keyed on the bound `actor_id` — reads only this actor's learned
            // weights (per-actor isolation). Non-fatal: any miss → global.
            talos_memory_ranking::load_serving_weights(&self.db_pool, actor_id)
                .await
                .unwrap_or((global_weights, global_access_weight))
        } else {
            (global_weights, global_access_weight)
        };
        let now = chrono::Utc::now();
        let ranked =
            talos_memory::actor_context::rank_candidates(candidates, &weights, now, access_weight);

        // Phase 1 (adaptive memory ranking): snapshot each ranked candidate's
        // per-memory ranking features BEFORE `candidates_into_rows` drops them,
        // keyed by memory key. Only built when provenance is ON and there is a
        // real execution to key it to — otherwise this stays empty and the hot
        // path is byte-identical to today (no clones, no work). Cheap: numeric
        // signals only, no memory-value clone. The features mirror EXACTLY what
        // the fused ranker used (same `now`/`weights`/`access_weight`).
        let record_provenance =
            execution_id.is_some() && talos_config::memory_rank_provenance_enabled();
        let feature_snapshots: std::collections::HashMap<
            String,
            (f64, f64, f64, Option<f64>, f64),
        > = if record_provenance {
            ranked
                .iter()
                .map(|c| {
                    let relevance = c.relevance;
                    let recency = talos_memory::actor_context::recency_component(
                        c,
                        now,
                        weights.recency_halflife_days,
                    );
                    let importance = talos_memory::actor_context::importance(c, access_weight);
                    let fused =
                        talos_memory::actor_context::fused_score(c, &weights, now, access_weight);
                    (
                        c.key.clone(),
                        (relevance, recency, importance, c.access_boost, fused),
                    )
                })
                .collect()
        } else {
            std::collections::HashMap::new()
        };

        let rows = talos_memory::actor_context::candidates_into_rows(ranked);
        let packed = talos_memory::actor_context::pack_within_budget(
            actor_id,
            rows,
            byte_budget,
            per_memory_cap,
        );

        // Phase 3a: bump the durable access signal for exactly the rows that
        // survived into the injected set — FIRE-AND-FORGET so this first-ever
        // recall-path mutation never adds latency to context assembly. ONE
        // batched UPDATE, best-effort: log at debug on error, never propagate.
        // Only fires on the flag-ON smart path (this method). The
        // `__graph_context__` synthetic key harmlessly matches no row.
        let bump_keys: Vec<String> = packed.iter().map(|(k, _, _)| k.clone()).collect();
        if !bump_keys.is_empty() {
            let pool = self.db_pool.clone();
            tokio::spawn(async move {
                if let Err(e) = talos_memory::bump_access(&pool, actor_id, &bump_keys).await {
                    tracing::debug!(
                        %actor_id,
                        error = %e,
                        "actor-context access bump failed (non-fatal)"
                    );
                }
            });
        }

        // Phase 1 (adaptive memory ranking): record the per-memory ranking
        // features of the packed set keyed by execution — the training
        // substrate a later phase joins to execution OUTCOME. FIRE-AND-FORGET
        // (like `bump_access`): never on the latency path, never propagates.
        // Gated on the flag AND a real execution id (both folded into
        // `record_provenance` / the presence of `feature_snapshots`). Stores
        // memory KEYS + numeric signals ONLY — never memory values.
        if record_provenance {
            if let Some(execution_id) = execution_id {
                let prov_rows: Vec<talos_memory::MemoryContextProvenanceRow> = packed
                    .iter()
                    .enumerate()
                    .filter_map(|(rank, (key, _, _))| {
                        feature_snapshots.get(key).map(
                            |&(relevance, recency, importance, access_boost, fused_score)| {
                                talos_memory::MemoryContextProvenanceRow {
                                    memory_key: key.clone(),
                                    relevance,
                                    recency,
                                    importance,
                                    access_boost,
                                    fused_score,
                                    rank: rank as i32,
                                }
                            },
                        )
                    })
                    .collect();
                if !prov_rows.is_empty() {
                    let pool = self.db_pool.clone();
                    tokio::spawn(async move {
                        if let Err(e) = talos_memory::record_execution_memory_context(
                            &pool,
                            execution_id,
                            actor_id,
                            &prov_rows,
                        )
                        .await
                        {
                            tracing::debug!(
                                %actor_id,
                                %execution_id,
                                error = %e,
                                "memory-rank provenance write failed (non-fatal)"
                            );
                        }
                    });
                }
            }
        }

        Ok(packed)
    }

    /// Fetch recent working/episodic memories for an actor with a configurable limit.
    /// (Legacy — callers should prefer get_relevant_actor_context.)
    pub async fn get_recent_actor_context_limited(
        &self,
        actor_id: Uuid,
        limit: usize,
    ) -> Result<Vec<(String, serde_json::Value, String)>> {
        // Legacy helper explicitly about working/episodic memory → Full scope.
        self.get_relevant_actor_context(actor_id, limit, None, None, MemoryScope::Full)
            .await
    }

    /// Upsert a scratchpad execution trace. Delegates to the canonical
    /// memory service so scratchpad writes obey the same TTL and
    /// (non-)embedding rules as every other code path.
    pub async fn upsert_scratchpad_trace(
        &self,
        actor_id: Uuid,
        key: &str,
        value: &serde_json::Value,
    ) -> Result<()> {
        talos_memory::persist_memory(&self.db_pool, actor_id, key, value, "scratchpad", None)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod memory_scope_tests {
    use super::{apply_memory_scope, MemoryScope};
    use serde_json::json;

    fn rows() -> Vec<(String, serde_json::Value, String)> {
        vec![
            ("persona".into(), json!({}), "semantic".into()),
            ("daily_brief/latest".into(), json!({}), "episodic".into()),
            ("scratch_token".into(), json!({}), "working".into()),
        ]
    }

    #[test]
    fn curated_drops_working_keeps_semantic_and_episodic() {
        let out = apply_memory_scope(rows(), MemoryScope::Curated);
        let types: Vec<&str> = out.iter().map(|(_, _, t)| t.as_str()).collect();
        assert!(types.contains(&"semantic"));
        assert!(types.contains(&"episodic"));
        assert!(
            !types.contains(&"working"),
            "working must be dropped in Curated"
        );
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn full_keeps_everything() {
        let out = apply_memory_scope(rows(), MemoryScope::Full);
        assert_eq!(out.len(), 3);
        assert!(out.iter().any(|(_, _, t)| t == "working"));
    }

    #[test]
    fn default_is_curated() {
        assert_eq!(MemoryScope::default(), MemoryScope::Curated);
    }
}
