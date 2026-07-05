//! Discovery aggregate: semantic execution cache, tags, embeddings,
//! search text, and the vector / trigram / ILIKE search paths.

use crate::*;

// ── Semantic execution cache repository methods ──────────────────────────────

impl WorkflowRepository {
    /// Exact hash lookup in the semantic execution cache.
    pub async fn get_exact_cache_hit(
        &self,
        workflow_id: Uuid,
        input_hash: &str,
    ) -> Option<serde_json::Value> {
        sqlx::query_scalar(
            "SELECT output_json FROM semantic_execution_cache \
             WHERE workflow_id = $1 AND input_hash = $2 \
               AND (expires_at IS NULL OR expires_at > now()) \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(workflow_id)
        .bind(input_hash)
        .fetch_optional(&self.db_pool)
        .await
        .ok()
        .flatten()
    }

    /// Increment the hit count for a cache entry (fire-and-forget).
    ///
    /// L T5-1: persistent UPDATE failures used to be discarded via
    /// `let _ = ...`, so a backed-up DB or schema-migration window
    /// silently produced zero increments — operator dashboards would
    /// show "0 cache hits" while the cache was actually serving
    /// heavily. We still spawn (don't block the read path) but log
    /// the error so the outage is visible.
    pub fn increment_cache_hit_count(&self, workflow_id: Uuid, input_hash: String) {
        let pool = self.db_pool.clone();
        tokio::spawn(async move {
            if let Err(e) = sqlx::query(
                "UPDATE semantic_execution_cache SET hit_count = hit_count + 1 \
                 WHERE workflow_id = $1 AND input_hash = $2",
            )
            .bind(workflow_id)
            .bind(&input_hash)
            .execute(&pool)
            .await
            {
                tracing::warn!(
                    target: "talos_workflow_repo",
                    event_kind = "cache_hit_increment_failed",
                    %workflow_id,
                    error = %e,
                    "increment_cache_hit_count: best-effort UPDATE failed"
                );
            }
        });
    }

    /// Semantic similarity lookup in the execution cache using pgvector.
    pub async fn get_semantic_cache_hit(
        &self,
        workflow_id: Uuid,
        embedding_str: &str,
        threshold: f64,
    ) -> Option<(serde_json::Value, f64)> {
        sqlx::query_as(
            "SELECT output_json, (1.0 - (input_embedding <=> $2::vector)) AS score \
             FROM semantic_execution_cache \
             WHERE workflow_id = $1 \
               AND input_embedding IS NOT NULL \
               AND (expires_at IS NULL OR expires_at > now()) \
               AND (1.0 - (input_embedding <=> $2::vector)) >= $3 \
             ORDER BY input_embedding <=> $2::vector \
             LIMIT 1",
        )
        .bind(workflow_id)
        .bind(embedding_str)
        .bind(threshold)
        .fetch_optional(&self.db_pool)
        .await
        .ok()
        .flatten()
    }

    /// Write or update a semantic cache entry. Returns the row ID.
    pub async fn upsert_cache_entry(
        &self,
        workflow_id: Uuid,
        input_hash: &str,
        input: &serde_json::Value,
        output: &serde_json::Value,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Uuid> {
        let id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO semantic_execution_cache \
             (workflow_id, input_hash, input_json, output_json, expires_at) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (workflow_id, input_hash) DO UPDATE \
               SET output_json = EXCLUDED.output_json, \
                   expires_at  = EXCLUDED.expires_at, \
                   hit_count   = 0 \
             RETURNING id",
        )
        .bind(workflow_id)
        .bind(input_hash)
        .bind(input)
        .bind(output)
        .bind(expires_at)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(id)
    }

    /// Asynchronously update the embedding vector for a cache entry.
    pub fn update_cache_embedding(&self, row_id: Uuid, embedding_str: String) {
        let pool = self.db_pool.clone();
        tokio::spawn(async move {
            if let Err(e) = sqlx::query(
                "UPDATE semantic_execution_cache \
                 SET input_embedding = $1::vector \
                 WHERE id = $2",
            )
            .bind(&embedding_str)
            .bind(row_id)
            .execute(&pool)
            .await
            {
                tracing::warn!(row_id = %row_id, "Cache embedding update failed: {}", e);
            }
        });
    }

    // ── Tagging ───────────────────────────────────────────────────────────

    /// Get the current tag count for a workflow.
    pub async fn get_tag_count(&self, workflow_id: Uuid, user_id: Uuid) -> Result<i64> {
        let count: i64 = sqlx::query_scalar(
            "SELECT coalesce(array_length(tags, 1), 0) FROM workflows WHERE id = $1 AND user_id = $2",
        )
        .bind(workflow_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?
        .unwrap_or(0);
        Ok(count)
    }

    /// Add a tag to a workflow (idempotent — skips if already present). Returns rows affected.
    pub async fn add_tag(&self, workflow_id: Uuid, user_id: Uuid, tag: &str) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE workflows SET tags = array_append(tags, $1) \
             WHERE id = $2 AND user_id = $3 AND NOT ($1 = ANY(tags))",
        )
        .bind(tag)
        .bind(workflow_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Remove a tag from a workflow. Returns rows affected.
    pub async fn remove_tag(&self, workflow_id: Uuid, user_id: Uuid, tag: &str) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE workflows SET tags = array_remove(tags, $1) \
             WHERE id = $2 AND user_id = $3",
        )
        .bind(tag)
        .bind(workflow_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Batch-add a tag to multiple workflows. Returns total rows affected.
    pub async fn bulk_add_tag(
        &self,
        workflow_ids: &[Uuid],
        user_id: Uuid,
        tag: &str,
    ) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE workflows SET tags = array_append(tags, $1) \
             WHERE id = ANY($2) AND user_id = $3 AND NOT ($1 = ANY(tags))",
        )
        .bind(tag)
        .bind(workflow_ids)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// MCP-152 (2026-05-08): Count how many of the supplied workflow ids are
    /// actually owned by `user_id`. Pairs with `bulk_add_tag` so callers can
    /// disambiguate not-found / not-owned from already-tagged: previously the
    /// bulk tag handler reported `already_tagged_count = total - tagged`,
    /// which silently swallowed nonexistent UUIDs as "already tagged" and
    /// hid typos in operator input.
    pub async fn count_owned_workflows_in_set(
        &self,
        workflow_ids: &[Uuid],
        user_id: Uuid,
    ) -> Result<u64> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM workflows \
             WHERE id = ANY($1) AND user_id = $2",
        )
        .bind(workflow_ids)
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(row.0.max(0) as u64)
    }

    /// Set the embedding vector for a workflow.
    pub async fn set_workflow_embedding(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        embedding: &[f64],
    ) -> Result<bool> {
        let emb_str = format!(
            "[{}]",
            embedding
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
        let result = sqlx::query(
            "UPDATE workflows SET embedding = $1::vector, updated_at = NOW() \
             WHERE id = $2 AND user_id = $3",
        )
        .bind(&emb_str)
        .bind(workflow_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    // ── utils.rs MCP-handler support (search_text rebuild) ────────────────

    /// Source columns for `update_workflow_search_text` — name + the four
    /// inputs that get joined into the search text. Distinct from
    /// `WorkflowEmbeddingSource` which omits graph_json (the embedding text
    /// only uses node names indirectly via capabilities).
    pub async fn get_workflow_for_search_text_rebuild(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<WorkflowSearchTextSource>> {
        let row = sqlx::query(
            "SELECT name, description, intent, capabilities, graph_json \
             FROM workflows WHERE id = $1 AND user_id = $2",
        )
        .bind(workflow_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        row.map(|r| -> Result<WorkflowSearchTextSource> {
            Ok(WorkflowSearchTextSource {
                name: r.get("name"),
                description: r.try_get::<Option<_>, _>("description")?,
                intent: r.try_get::<Option<_>, _>("intent")?,
                capabilities: r
                    .try_get::<Option<_>, _>("capabilities")?
                    .unwrap_or_default(),
                graph_json: r.try_get::<Option<_>, _>("graph_json")?,
            })
        })
        .transpose()
    }

    /// Update the `search_text` column on a workflow (best-effort).
    /// No user_id scope — caller has already verified ownership via the
    /// preceding `get_workflow_for_search_text_rebuild` lookup.
    pub async fn set_workflow_search_text(&self, workflow_id: Uuid, text: &str) -> Result<()> {
        sqlx::query("UPDATE workflows SET search_text = $1 WHERE id = $2")
            .bind(text)
            .bind(workflow_id)
            .execute(&self.db_pool)
            .await?;
        Ok(())
    }

    /// Find workflows whose `capabilities` array is a superset of the given
    /// list — matches the engine's runtime capability-dispatch SQL exactly
    /// (parallel.rs:2715-2718). Used by `preview_capability_dispatch`.
    pub async fn find_workflows_for_capability_dispatch_preview(
        &self,
        user_id: Uuid,
        required_caps: &[String],
        limit: i64,
    ) -> Result<Vec<CapabilityDispatchPreviewRow>> {
        let rows = sqlx::query(
            "SELECT id, name, capabilities, readiness_score, status, updated_at \
             FROM workflows \
             WHERE user_id = $1 \
               AND capabilities @> $2 \
             ORDER BY updated_at DESC \
             LIMIT $3",
        )
        .bind(user_id)
        .bind(required_caps)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        rows.iter()
            .map(|r| -> Result<CapabilityDispatchPreviewRow> {
                Ok(CapabilityDispatchPreviewRow {
                    id: r.try_get::<Option<_>, _>("id")?.unwrap_or_default(),
                    name: r.try_get::<Option<_>, _>("name")?.unwrap_or_default(),
                    capabilities: r
                        .try_get::<Option<_>, _>("capabilities")?
                        .unwrap_or_default(),
                    readiness_score: r.try_get::<Option<_>, _>("readiness_score")?,
                    status: r.try_get::<Option<_>, _>("status")?.unwrap_or_default(),
                    updated_at: r.try_get::<Option<_>, _>("updated_at")?,
                })
            })
            .collect()
    }

    /// Top N workflows by readiness_score (NULLS LAST). Used by
    /// `get_session_context` to surface the user's most production-ready
    /// workflows first.
    pub async fn list_top_workflows_by_readiness(
        &self,
        user_id: Uuid,
        limit: i32,
    ) -> Result<Vec<SessionContextWorkflowRow>> {
        let rows = sqlx::query(
            "SELECT id, name, capabilities, readiness_score, graph_json \
             FROM workflows WHERE user_id = $1 \
             ORDER BY readiness_score DESC NULLS LAST \
             LIMIT $2",
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        rows.iter()
            .map(|r| -> Result<SessionContextWorkflowRow> {
                Ok(SessionContextWorkflowRow {
                    id: r.get("id"),
                    name: r.get("name"),
                    capabilities: r
                        .try_get::<Option<_>, _>("capabilities")?
                        .unwrap_or_default(),
                    readiness_score: r.try_get::<Option<_>, _>("readiness_score")?,
                    graph_json: r.try_get::<Option<_>, _>("graph_json")?.unwrap_or_default(),
                })
            })
            .collect()
    }

    /// Most-recently-used workflows for a user via `workflow_reuse_events`.
    /// DISTINCT ON keeps only the latest reuse per workflow.
    pub async fn list_recently_used_workflows(
        &self,
        user_id: Uuid,
        limit: i32,
    ) -> Result<Vec<RecentlyUsedWorkflowRow>> {
        let rows = sqlx::query(
            "SELECT DISTINCT ON (r.workflow_id) r.workflow_id, w.name, w.capabilities \
             FROM workflow_reuse_events r \
             JOIN workflows w ON w.id = r.workflow_id AND w.user_id = $1 \
             ORDER BY r.workflow_id, r.created_at DESC \
             LIMIT $2",
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        rows.iter()
            .map(|r| -> Result<RecentlyUsedWorkflowRow> {
                Ok(RecentlyUsedWorkflowRow {
                    workflow_id: r.get("workflow_id"),
                    name: r.try_get::<Option<_>, _>("name")?.unwrap_or_default(),
                    capabilities: r
                        .try_get::<Option<_>, _>("capabilities")?
                        .unwrap_or_default(),
                })
            })
            .collect()
    }

    /// Keyword-match workflows by ILIKE on name/description/capabilities. Used
    /// by `get_session_context` task-description matching.
    pub async fn match_workflows_by_keyword(
        &self,
        user_id: Uuid,
        ilike_pattern: &str,
        limit: i32,
    ) -> Result<Vec<RecentlyUsedWorkflowRow>> {
        let rows = sqlx::query(
            "SELECT id, name, capabilities FROM workflows \
             WHERE user_id = $1 \
               AND (name ILIKE $2 OR description ILIKE $2 OR array_to_string(capabilities, ' ') ILIKE $2) \
             LIMIT $3",
        )
        .bind(user_id)
        .bind(ilike_pattern)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        rows.iter()
            .map(|r| -> Result<RecentlyUsedWorkflowRow> {
                Ok(RecentlyUsedWorkflowRow {
                    workflow_id: r.get("id"),
                    name: r.try_get::<Option<_>, _>("name")?.unwrap_or_default(),
                    capabilities: r
                        .try_get::<Option<_>, _>("capabilities")?
                        .unwrap_or_default(),
                })
            })
            .collect()
    }

    // ── search.rs MCP-handler support ──────────────────────────────────────

    /// Fetch the embedding-source columns for a workflow. Used by
    /// `auto_embed_workflow` to compute the embedding text from
    /// `(name, description, capabilities, intent)`.
    pub async fn get_workflow_embedding_source(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<WorkflowEmbeddingSource>> {
        let row = sqlx::query(
            "SELECT name, description, capabilities, intent FROM workflows \
             WHERE id = $1 AND user_id = $2",
        )
        .bind(workflow_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        row.map(|r| -> Result<WorkflowEmbeddingSource> {
            Ok(WorkflowEmbeddingSource {
                name: r.try_get::<Option<_>, _>("name")?.unwrap_or_default(),
                description: r.try_get::<Option<_>, _>("description")?,
                capabilities: r
                    .try_get::<Option<_>, _>("capabilities")?
                    .unwrap_or_default(),
                intent: r.try_get::<Option<_>, _>("intent")?,
            })
        })
        .transpose()
    }

    /// Set the embedding column from a pre-formatted pgvector literal string
    /// (`"[0.1,0.2,...]"`). The `auto_embed_workflow` and
    /// `generate_workflow_embeddings` paths share this; the typed
    /// `set_workflow_embedding` (above) builds the string for them.
    pub async fn set_workflow_embedding_from_str(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        embedding_str: &str,
    ) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE workflows SET embedding = $1::vector WHERE id = $2 AND user_id = $3",
        )
        .bind(embedding_str)
        .bind(workflow_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Batch sibling to [`set_workflow_embedding_from_str`]. Single
    /// `UPDATE … FROM UNNEST(...)` round-trip applies all (workflow_id,
    /// embedding) pairs in one statement, replacing the per-workflow
    /// loop used by `handle_generate_workflow_embeddings` (up to 200
    /// round-trips per call → 1).
    ///
    /// Returns the number of rows actually updated. A row that no longer
    /// exists for `user_id` simply doesn't update and isn't counted —
    /// matching the per-row method's "0 rows affected" semantics for a
    /// missing target. Empty input short-circuits without touching the DB.
    ///
    /// Security: same user-bound scoping as the per-row method
    /// (`AND w.user_id = $3`) — an attacker passing a workflow_id they
    /// don't own contributes 0 to rows_affected, identical to the prior
    /// per-row behaviour.
    pub async fn bulk_set_workflow_embeddings_from_str(
        &self,
        pairs: &[(Uuid, String)],
        user_id: Uuid,
    ) -> Result<u64> {
        if pairs.is_empty() {
            return Ok(0);
        }
        let ids: Vec<Uuid> = pairs.iter().map(|(id, _)| *id).collect();
        let embs: Vec<String> = pairs.iter().map(|(_, e)| e.clone()).collect();
        let result = sqlx::query(
            "UPDATE workflows w \
             SET embedding = u.emb::vector \
             FROM UNNEST($1::uuid[], $2::text[]) AS u(id, emb) \
             WHERE w.id = u.id AND w.user_id = $3",
        )
        .bind(&ids)
        .bind(&embs)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Keyword search by `name ILIKE` with optional `tag` filter and
    /// `include_archived` flag. Used by `handle_search_workflows`.
    pub async fn search_workflows_by_name_ilike(
        &self,
        user_id: Uuid,
        ilike_pattern: &str,
        tag_filter: Option<&str>,
        include_archived: bool,
        limit: i64,
    ) -> Result<Vec<WorkflowSearchRow>> {
        let rows = if let Some(tag) = tag_filter {
            sqlx::query(
                "SELECT id, name, description, tags, status, created_at, updated_at \
                 FROM workflows WHERE user_id = $1 AND name ILIKE $2 AND $3 = ANY(tags) \
                 AND ($4 OR COALESCE(status, '') != 'archived') \
                 ORDER BY updated_at DESC LIMIT $5",
            )
            .bind(user_id)
            .bind(ilike_pattern)
            .bind(tag)
            .bind(include_archived)
            .bind(limit)
            .fetch_all(&self.db_pool)
            .await?
        } else {
            sqlx::query(
                "SELECT id, name, description, tags, status, created_at, updated_at \
                 FROM workflows WHERE user_id = $1 AND name ILIKE $2 \
                 AND ($3 OR COALESCE(status, '') != 'archived') \
                 ORDER BY updated_at DESC LIMIT $4",
            )
            .bind(user_id)
            .bind(ilike_pattern)
            .bind(include_archived)
            .bind(limit)
            .fetch_all(&self.db_pool)
            .await?
        };
        rows.iter()
            .map(|r| -> Result<WorkflowSearchRow> {
                Ok(WorkflowSearchRow {
                    id: r.get("id"),
                    name: r.get("name"),
                    description: r.try_get::<Option<_>, _>("description")?,
                    tags: r.try_get::<Option<_>, _>("tags")?.unwrap_or_default(),
                    status: r.try_get::<Option<_>, _>("status")?,
                    created_at: r.get("created_at"),
                    updated_at: r.get("updated_at"),
                })
            })
            .collect()
    }

    /// Fetch the source-workflow graph_json string for `find_similar_workflows`.
    /// Returns Ok(None) when the workflow doesn't exist or isn't owned.
    pub async fn get_workflow_graph_for_similarity(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<String>> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT graph_json FROM workflows WHERE id = $1 AND user_id = $2")
                .bind(workflow_id)
                .bind(user_id)
                .fetch_optional(&self.db_pool)
                .await?;
        Ok(row.map(|(g,)| g))
    }

    /// List the user's other workflows for module-overlap similarity scoring.
    /// Caps at 200 rows (heuristic similarity scan, not a paginated view).
    pub async fn list_workflows_for_similarity(
        &self,
        user_id: Uuid,
        exclude_id: Uuid,
        limit: i64,
    ) -> Result<Vec<WorkflowGraphRow>> {
        let rows = sqlx::query(
            "SELECT id, name, graph_json FROM workflows WHERE user_id = $1 AND id != $2 \
             AND (status IS NULL OR status != 'archived') LIMIT $3",
        )
        .bind(user_id)
        .bind(exclude_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| WorkflowGraphRow {
                id: r.get("id"),
                name: r.get("name"),
                graph_json: r.get("graph_json"),
            })
            .collect())
    }

    /// Vector cosine search over the workflows.embedding column.
    /// `embedding_str` must be in pgvector literal form.
    ///
    /// N T5-N2: `include_archived: bool` is a typed boolean, not a SQL
    /// fragment. Pre-fix the parameter was `archived_clause: &str`
    /// interpolated into the SQL via `format!()` — safe today because
    /// the only caller branched on a closed boolean, but a future
    /// caller forwarding user input could trip the SQL-fragment
    /// injection footgun. The bool is now bound via `$N` like every
    /// other parameter and the SQL string is fully parameterised.
    pub async fn search_workflows_by_embedding(
        &self,
        user_id: Uuid,
        embedding_str: &str,
        tag_filter: Option<&str>,
        include_archived: bool,
        limit: i32,
    ) -> Result<Vec<WorkflowSemanticVectorRow>, sqlx::Error> {
        let rows = if let Some(tag) = tag_filter {
            sqlx::query(
                "SELECT id, name, description, capabilities, readiness_score, \
                        1 - (embedding <=> $2::vector) AS match_score \
                 FROM workflows WHERE user_id = $1 AND embedding IS NOT NULL \
                    AND ($5 OR COALESCE(status, '') != 'archived') \
                    AND $4 = ANY(tags) \
                 ORDER BY embedding <=> $2::vector \
                 LIMIT $3",
            )
            .bind(user_id)
            .bind(embedding_str)
            .bind(limit)
            .bind(tag)
            .bind(include_archived)
            .fetch_all(&self.db_pool)
            .await?
        } else {
            sqlx::query(
                "SELECT id, name, description, capabilities, readiness_score, \
                        1 - (embedding <=> $2::vector) AS match_score \
                 FROM workflows WHERE user_id = $1 AND embedding IS NOT NULL \
                    AND ($4 OR COALESCE(status, '') != 'archived') \
                 ORDER BY embedding <=> $2::vector \
                 LIMIT $3",
            )
            .bind(user_id)
            .bind(embedding_str)
            .bind(limit)
            .bind(include_archived)
            .fetch_all(&self.db_pool)
            .await?
        };
        rows.iter()
            .map(|r| -> Result<WorkflowSemanticVectorRow, sqlx::Error> {
                Ok(WorkflowSemanticVectorRow {
                    id: r.get("id"),
                    name: r.get("name"),
                    description: r.get("description"),
                    capabilities: r.get("capabilities"),
                    readiness_score: r.get("readiness_score"),
                    match_score: r.try_get::<Option<_>, _>("match_score")?.unwrap_or(0.0),
                })
            })
            .collect()
    }

    /// pg_trgm fuzzy keyword search with ILIKE fallback OR. Returns
    /// `(id, name, description, capabilities, intent, readiness_score, match_score)`.
    ///
    /// N T5-N2: `include_archived: bool` (typed parameter, not SQL
    /// fragment) — same fix as `search_workflows_by_embedding`.
    pub async fn search_workflows_trgm(
        &self,
        user_id: Uuid,
        query_str: &str,
        ilike_pattern: &str,
        tag_filter: Option<&str>,
        include_archived: bool,
        limit: i32,
    ) -> Result<Vec<WorkflowSemanticTrgmRow>, sqlx::Error> {
        let rows = if let Some(tag) = tag_filter {
            sqlx::query(
                "SELECT id, name, description, capabilities, intent, readiness_score, \
                    GREATEST( \
                        similarity(name, $2), \
                        similarity(COALESCE(description, ''), $2), \
                        similarity(array_to_string(capabilities, ' '), $2), \
                        similarity(COALESCE(search_text, ''), $2) \
                    ) AS match_score \
                 FROM workflows WHERE user_id = $1 \
                    AND ($6 OR COALESCE(status, '') != 'archived') \
                    AND $5 = ANY(tags) \
                    AND (similarity(name, $2) > 0.1 OR similarity(COALESCE(description, ''), $2) > 0.1 \
                         OR similarity(COALESCE(search_text, ''), $2) > 0.1 \
                         OR name ILIKE $3 OR COALESCE(description, '') ILIKE $3 OR COALESCE(search_text, '') ILIKE $3) \
                 ORDER BY match_score DESC LIMIT $4",
            )
            .bind(user_id)
            .bind(query_str)
            .bind(ilike_pattern)
            .bind(limit)
            .bind(tag)
            .bind(include_archived)
            .fetch_all(&self.db_pool)
            .await?
        } else {
            sqlx::query(
                "SELECT id, name, description, capabilities, intent, readiness_score, \
                    GREATEST( \
                        similarity(name, $2), \
                        similarity(COALESCE(description, ''), $2), \
                        similarity(array_to_string(capabilities, ' '), $2), \
                        similarity(COALESCE(search_text, ''), $2) \
                    ) AS match_score \
                 FROM workflows WHERE user_id = $1 \
                    AND ($5 OR COALESCE(status, '') != 'archived') \
                    AND (similarity(name, $2) > 0.1 OR similarity(COALESCE(description, ''), $2) > 0.1 \
                         OR similarity(COALESCE(search_text, ''), $2) > 0.1 \
                         OR name ILIKE $3 OR COALESCE(description, '') ILIKE $3 OR COALESCE(search_text, '') ILIKE $3) \
                 ORDER BY match_score DESC LIMIT $4",
            )
            .bind(user_id)
            .bind(query_str)
            .bind(ilike_pattern)
            .bind(limit)
            .bind(include_archived)
            .fetch_all(&self.db_pool)
            .await?
        };
        rows.iter()
            .map(|r| -> Result<WorkflowSemanticTrgmRow, sqlx::Error> {
                Ok(WorkflowSemanticTrgmRow {
                    id: r.get("id"),
                    name: r.get("name"),
                    description: r.try_get::<Option<_>, _>("description")?,
                    capabilities: r
                        .try_get::<Option<_>, _>("capabilities")?
                        .unwrap_or_default(),
                    intent: r.try_get::<Option<_>, _>("intent")?,
                    readiness_score: r.try_get::<Option<_>, _>("readiness_score")?,
                    match_score: r
                        .try_get::<Option<f32>, _>("match_score")
                        .ok()
                        .flatten()
                        .map(|f| f as f64),
                })
            })
            .collect()
    }

    /// ILIKE-only fallback for `search_workflows_trgm` when pg_trgm is
    /// unavailable. Same projection minus the `match_score` (keyword fallback
    /// has none).
    ///
    /// N T5-N2: `include_archived: bool` (typed parameter, not SQL
    /// fragment) — same fix as `search_workflows_by_embedding`.
    pub async fn search_workflows_ilike_fallback(
        &self,
        user_id: Uuid,
        ilike_pattern: &str,
        tag_filter: Option<&str>,
        include_archived: bool,
        limit: i32,
    ) -> Result<Vec<WorkflowSemanticTrgmRow>, sqlx::Error> {
        let rows = if let Some(tag) = tag_filter {
            sqlx::query(
                "SELECT id, name, description, capabilities, intent, readiness_score \
                 FROM workflows WHERE user_id = $1 \
                    AND ($5 OR COALESCE(status, '') != 'archived') \
                    AND $4 = ANY(tags) \
                    AND (name ILIKE $2 OR description ILIKE $2 OR array_to_string(capabilities, ' ') ILIKE $2 OR intent::text ILIKE $2 OR COALESCE(search_text, '') ILIKE $2) \
                 ORDER BY readiness_score DESC NULLS LAST \
                 LIMIT $3",
            )
            .bind(user_id)
            .bind(ilike_pattern)
            .bind(limit)
            .bind(tag)
            .bind(include_archived)
            .fetch_all(&self.db_pool)
            .await?
        } else {
            sqlx::query(
                "SELECT id, name, description, capabilities, intent, readiness_score \
                 FROM workflows WHERE user_id = $1 \
                    AND ($4 OR COALESCE(status, '') != 'archived') \
                    AND (name ILIKE $2 OR description ILIKE $2 OR array_to_string(capabilities, ' ') ILIKE $2 OR intent::text ILIKE $2 OR COALESCE(search_text, '') ILIKE $2) \
                 ORDER BY readiness_score DESC NULLS LAST \
                 LIMIT $3",
            )
            .bind(user_id)
            .bind(ilike_pattern)
            .bind(limit)
            .bind(include_archived)
            .fetch_all(&self.db_pool)
            .await?
        };
        rows.iter()
            .map(|r| -> Result<WorkflowSemanticTrgmRow, sqlx::Error> {
                Ok(WorkflowSemanticTrgmRow {
                    id: r.get("id"),
                    name: r.get("name"),
                    description: r.try_get::<Option<_>, _>("description")?,
                    capabilities: r
                        .try_get::<Option<_>, _>("capabilities")?
                        .unwrap_or_default(),
                    intent: r.try_get::<Option<_>, _>("intent")?,
                    readiness_score: r.try_get::<Option<_>, _>("readiness_score")?,
                    match_score: None,
                })
            })
            .collect()
    }

    /// Workflows that need embedding regeneration. When `force_refresh` is
    /// true, returns all rows; otherwise only rows where `embedding IS NULL`.
    pub async fn list_workflows_for_embedding_generation(
        &self,
        user_id: Uuid,
        force_refresh: bool,
        limit: i32,
    ) -> Result<Vec<WorkflowEmbeddingCandidate>> {
        let rows = if force_refresh {
            sqlx::query(
                "SELECT id, name, description, capabilities, intent \
                 FROM workflows WHERE user_id = $1 \
                 ORDER BY updated_at DESC LIMIT $2",
            )
            .bind(user_id)
            .bind(limit)
            .fetch_all(&self.db_pool)
            .await?
        } else {
            sqlx::query(
                "SELECT id, name, description, capabilities, intent \
                 FROM workflows WHERE user_id = $1 AND embedding IS NULL \
                 ORDER BY updated_at DESC LIMIT $2",
            )
            .bind(user_id)
            .bind(limit)
            .fetch_all(&self.db_pool)
            .await?
        };
        rows.iter()
            .map(|r| -> Result<WorkflowEmbeddingCandidate> {
                Ok(WorkflowEmbeddingCandidate {
                    id: r.try_get::<Option<_>, _>("id")?.unwrap_or_default(),
                    name: r.try_get::<Option<_>, _>("name")?.unwrap_or_default(),
                    description: r.try_get::<Option<_>, _>("description")?,
                    capabilities: r
                        .try_get::<Option<_>, _>("capabilities")?
                        .unwrap_or_default(),
                    intent: r.try_get::<Option<_>, _>("intent")?,
                })
            })
            .collect()
    }
}

/// Source projection for `update_workflow_search_text`. Includes the raw
/// graph_json string — the helper extracts node labels from it before
/// composing the final search text.
#[derive(Debug)]
pub struct WorkflowSearchTextSource {
    pub name: String,
    pub description: Option<String>,
    pub intent: Option<serde_json::Value>,
    pub capabilities: Vec<String>,
    pub graph_json: Option<String>,
}

/// Row returned by `find_workflows_for_capability_dispatch_preview`.
#[derive(Debug)]
pub struct CapabilityDispatchPreviewRow {
    pub id: Uuid,
    pub name: String,
    pub capabilities: Vec<String>,
    pub readiness_score: Option<i32>,
    pub status: String,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Top-readiness row for `get_session_context`.
#[derive(Debug)]
pub struct SessionContextWorkflowRow {
    pub id: Uuid,
    pub name: String,
    pub capabilities: Vec<String>,
    pub readiness_score: Option<i32>,
    pub graph_json: String,
}

/// Recently-used / keyword-matched row for `get_session_context`.
#[derive(Debug)]
pub struct RecentlyUsedWorkflowRow {
    pub workflow_id: Uuid,
    pub name: String,
    pub capabilities: Vec<String>,
}

/// Source columns for `auto_embed_workflow` — name + the three free-text
/// inputs that get joined into the embedding text.
#[derive(Debug)]
pub struct WorkflowEmbeddingSource {
    pub name: String,
    pub description: Option<String>,
    pub capabilities: Vec<String>,
    pub intent: Option<serde_json::Value>,
}

/// Search row returned by `search_workflows_by_name_ilike`.
#[derive(Debug)]
pub struct WorkflowSearchRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub status: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Compact row for `list_workflows_for_similarity` — just enough to compute
/// module-overlap scores.
#[derive(Debug)]
pub struct WorkflowGraphRow {
    pub id: Uuid,
    pub name: String,
    pub graph_json: String,
}

/// Vector-search projection for `search_workflows_by_embedding`.
#[derive(Debug)]
pub struct WorkflowSemanticVectorRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub capabilities: Vec<String>,
    pub readiness_score: Option<i32>,
    pub match_score: f64,
}

/// pg_trgm/ILIKE projection for `search_workflows_trgm` and the
/// `search_workflows_ilike_fallback` fallback (which returns
/// `match_score = None`).
#[derive(Debug)]
pub struct WorkflowSemanticTrgmRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub capabilities: Vec<String>,
    pub intent: Option<serde_json::Value>,
    pub readiness_score: Option<i32>,
    pub match_score: Option<f64>,
}

/// Embedding-generation candidate row.
#[derive(Debug)]
pub struct WorkflowEmbeddingCandidate {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub capabilities: Vec<String>,
    pub intent: Option<serde_json::Value>,
}

/// Format an embedding vector as a pgvector literal (`"[v1,v2,…]"`).
///
/// pgvector accepts string literals via the `::vector` cast; this is the
/// canonical wire format used by `search_workflows_by_embedding`.
pub fn format_pgvector_literal(emb: &[f64]) -> String {
    let parts: Vec<String> = emb.iter().map(|v| v.to_string()).collect();
    format!("[{}]", parts.join(","))
}

/// Compute an ILIKE-fallback match score for a candidate row given a list of
/// `%word%`-pattern search words. Score weights:
///   * name contains the word → +3
///   * description contains the word → +2
///   * any capability contains the word → +2
///   * intent JSON contains the word → +1
///
/// `words` is the same shape the handler builds:
/// `format!("%{}%", escape_like(&w.to_lowercase()))` — the `%` markers are
/// trimmed before substring matching.
pub fn compute_keyword_match_score(
    name: &str,
    description: Option<&str>,
    capabilities: &[String],
    intent: Option<&serde_json::Value>,
    words: &[String],
) -> i32 {
    let name_lower = name.to_lowercase();
    let desc_lower = description.unwrap_or("").to_lowercase();
    let caps_str = capabilities.join(" ").to_lowercase();
    let intent_str = intent
        .map(|v| v.to_string().to_lowercase())
        .unwrap_or_default();

    let mut score = 0i32;
    for word in words {
        let w = word.trim_matches('%');
        if name_lower.contains(w) {
            score += 3;
        }
        if desc_lower.contains(w) {
            score += 2;
        }
        if caps_str.contains(w) {
            score += 2;
        }
        if intent_str.contains(w) {
            score += 1;
        }
    }
    score
}
