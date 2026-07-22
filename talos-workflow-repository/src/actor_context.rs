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
    pub async fn get_relevant_actor_context(
        &self,
        actor_id: Uuid,
        limit: usize,
        context_hint: Option<&str>,
    ) -> Result<Vec<(String, serde_json::Value, String)>> {
        // Smart path (default-OFF): kind-filtered, min-score-floored,
        // byte-budgeted assembly. When the flag is OFF the legacy body
        // below runs unchanged — byte-identical output.
        if talos_config::smart_memory_context_enabled() {
            return self
                .get_relevant_actor_context_smart(actor_id, limit, context_hint)
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
        let recency = talos_memory::recall_recent_excluding_types_and_kinds_ts(
            &self.db_pool,
            actor_id,
            &["scratchpad"],
            &exclude_kinds,
            limit.saturating_mul(2) as i64,
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
        let weights = talos_memory::actor_context::Weights {
            relevance: talos_config::smart_memory_context_w_relevance(),
            recency: talos_config::smart_memory_context_w_recency(),
            importance: talos_config::smart_memory_context_w_importance(),
            recency_halflife_days: talos_config::smart_memory_context_recency_halflife_days(),
        };
        let ranked = talos_memory::actor_context::rank_candidates(
            candidates,
            &weights,
            chrono::Utc::now(),
            talos_config::smart_memory_context_access_weight(),
        );
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

        Ok(packed)
    }

    /// Fetch recent working/episodic memories for an actor with a configurable limit.
    /// (Legacy — callers should prefer get_relevant_actor_context.)
    pub async fn get_recent_actor_context_limited(
        &self,
        actor_id: Uuid,
        limit: usize,
    ) -> Result<Vec<(String, serde_json::Value, String)>> {
        self.get_relevant_actor_context(actor_id, limit, None).await
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
