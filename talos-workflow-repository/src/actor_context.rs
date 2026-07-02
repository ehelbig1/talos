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
