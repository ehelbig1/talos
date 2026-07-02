//! Core workflow aggregate: CRUD, metadata, versions, duplication,
//! publish/import support, schedules, and the
//! [`talos_workflow_engine_core::WorkflowGraphStore`] impl.

use crate::*;

// ─────────────────────────────────────────────────────────────────────────────
// Row DTOs
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct WorkflowSummary {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    /// Raw JSON string — the handler parses it for node/edge counts.
    pub graph_json: String,
    pub tags: Vec<String>,
    pub last_status: Option<String>,
    pub last_exec_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub status: Option<String>,
    pub workflow_type: Option<String>,
}

#[derive(Debug)]
pub struct WorkflowRecord {
    pub id: Uuid,
    pub name: String,
    pub graph_json: String,
    pub tags: Vec<String>,
    pub description: Option<String>,
    pub max_concurrent_executions: Option<i32>,
    pub is_enabled: bool,
    pub capabilities: Vec<String>,
    pub intent: Option<serde_json::Value>,
    pub readiness_score: Option<i32>,
    pub actor_id: Option<Uuid>,
    pub status: Option<String>,
    pub workflow_type: Option<String>,
    pub timeout_seconds: Option<i32>,
    pub input_schema: Option<serde_json::Value>,
}

impl WorkflowRepository {
    /// Open a write transaction scoped to the creator's **personal org**
    /// (RFC 0006 org-pin / RFC 0005 S3). Resolves that org in Rust so the
    /// caller can BOTH bind it as the new row's `org_id` AND have the
    /// org-pin RLS `WITH CHECK` enforce (`org_id = app.current_org_id`)
    /// once the fail-closed flip is on — the bound org and the scoped org
    /// match by construction. Returns `(tx, personal_org)`; the caller MUST
    /// bind `personal_org` as the row's `org_id` and commit the tx. Falls
    /// back to a user-scoped tx + `None` org when the personal org is absent
    /// (the policy's `org_id IS NULL → permit` clause applies). Latent while
    /// `TALOS_RLS_SET_ROLE` is off (sets the GUCs, no role switch).
    async fn begin_personal_org_write(
        &self,
        user_id: Uuid,
    ) -> Result<(sqlx::Transaction<'_, sqlx::Postgres>, Option<Uuid>)> {
        let personal_org: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM organizations WHERE owner_id = $1 AND is_personal")
                .bind(user_id)
                .fetch_optional(&self.db_pool)
                .await?;
        let tx = match personal_org {
            Some(org) => {
                talos_db::begin_org_scoped(
                    &self.db_pool,
                    &talos_tenancy::OrgScope::new(org, user_id),
                )
                .await?
            }
            None => talos_db::begin_user_scoped(&self.db_pool, user_id).await?,
        };
        Ok((tx, personal_org))
    }

    // ── Listing & retrieval ────────────────────────────────────────────────

    /// List workflows for a user, optionally filtered by tag. Returns up to 50.
    pub async fn list_workflows(
        &self,
        user_id: Uuid,
        tag_filter: Option<&str>,
    ) -> Result<Vec<WorkflowSummary>> {
        // RFC 0005 S3: self-scope (see get_workflow). Both branches + the
        // LATERAL workflow_executions join run under one per-user tx.
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let rows = if let Some(tag) = tag_filter {
            sqlx::query(
                "SELECT w.id, w.name, w.description, w.graph_json, w.created_at, w.updated_at, \
                        w.tags, latest.status AS last_status, latest.started_at AS last_exec_at \
                 FROM workflows w \
                 LEFT JOIN LATERAL ( \
                     SELECT status, started_at FROM workflow_executions \
                     WHERE workflow_id = w.id ORDER BY started_at DESC LIMIT 1 \
                 ) latest ON true \
                 WHERE w.user_id = $1 AND $2 = ANY(w.tags) \
                 ORDER BY w.updated_at DESC LIMIT 50",
            )
            .bind(user_id)
            .bind(tag)
            .fetch_all(&mut *tx)
            .await?
        } else {
            sqlx::query(
                "SELECT w.id, w.name, w.description, w.graph_json, w.created_at, w.updated_at, \
                        w.tags, latest.status AS last_status, latest.started_at AS last_exec_at \
                 FROM workflows w \
                 LEFT JOIN LATERAL ( \
                     SELECT status, started_at FROM workflow_executions \
                     WHERE workflow_id = w.id ORDER BY started_at DESC LIMIT 1 \
                 ) latest ON true \
                 WHERE w.user_id = $1 \
                 ORDER BY w.updated_at DESC LIMIT 50",
            )
            .bind(user_id)
            .fetch_all(&mut *tx)
            .await?
        };
        tx.commit().await?;

        let summaries = rows
            .into_iter()
            .map(|row| WorkflowSummary {
                id: row.get("id"),
                name: row.get("name"),
                description: row.try_get("description").ok().flatten(),
                graph_json: row.get("graph_json"),
                tags: row.try_get("tags").ok().unwrap_or_default(),
                last_status: row.try_get("last_status").ok().flatten(),
                last_exec_at: row.try_get("last_exec_at").ok().flatten(),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
                status: row.try_get("status").ok().flatten(),
                workflow_type: row.try_get("workflow_type").ok().flatten(),
            })
            .collect();

        Ok(summaries)
    }

    /// Paginated workflow listing with status + type filters.
    pub async fn list_workflows_paginated(
        &self,
        user_id: Uuid,
        status_filter: Option<&str>,
        type_filter: Option<&str>,
        tag_filter: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<WorkflowSummary>, i64)> {
        let base_select =
            "SELECT w.id, w.name, w.description, w.graph_json, w.created_at, w.updated_at, \
                           w.tags, w.status, w.workflow_type, \
                           latest.status AS last_status, latest.started_at AS last_exec_at";
        let from_clause = "FROM workflows w \
                           LEFT JOIN LATERAL ( \
                               SELECT status, started_at FROM workflow_executions \
                               WHERE workflow_id = w.id ORDER BY started_at DESC LIMIT 1 \
                           ) latest ON true";

        // SECURITY: Build WHERE clause dynamically using ONLY parameterized binds.
        // The format! macro is used ONLY to construct SQL structure ($N placeholders),
        // never for user values. All user-provided values are bound separately via .bind().
        // This prevents SQL injection while allowing dynamic query construction.
        let mut conditions = vec!["w.user_id = $1"];
        let mut param_idx = 2usize;

        let status_clause = status_filter.map(|_| {
            let c = format!("w.status = ${}", param_idx);
            param_idx += 1;
            c
        });
        let type_clause = type_filter.map(|_| {
            let c = format!("w.workflow_type = ${}", param_idx);
            param_idx += 1;
            c
        });
        let tag_clause = tag_filter.map(|_| {
            let c = format!("${} = ANY(w.tags)", param_idx);
            param_idx += 1;
            c
        });
        let limit_param = param_idx;
        param_idx += 1;
        let offset_param = param_idx;

        if let Some(ref c) = status_clause {
            conditions.push(c);
        }
        if let Some(ref c) = type_clause {
            conditions.push(c);
        }
        if let Some(ref c) = tag_clause {
            conditions.push(c);
        }

        let where_str = conditions.join(" AND ");
        let data_sql = format!(
            "{base_select} {from_clause} WHERE {where_str} ORDER BY w.updated_at DESC, w.id DESC LIMIT ${limit_param} OFFSET ${offset_param}"
        );
        let count_sql = format!("SELECT COUNT(*) FROM workflows w WHERE {where_str}");

        let mut data_q = sqlx::query(&data_sql).bind(user_id);
        let mut count_q = sqlx::query_scalar::<_, i64>(&count_sql).bind(user_id);
        if let Some(s) = status_filter {
            data_q = data_q.bind(s);
            count_q = count_q.bind(s);
        }
        if let Some(t) = type_filter {
            data_q = data_q.bind(t);
            count_q = count_q.bind(t);
        }
        if let Some(tg) = tag_filter {
            data_q = data_q.bind(tg);
            count_q = count_q.bind(tg);
        }
        data_q = data_q.bind(limit).bind(offset);

        // RFC 0005 S3: self-scope (see get_workflow). The data + count
        // queries share ONE per-user tx, so they run sequentially rather
        // than the prior concurrent try_join — a single scoped transaction
        // can't be borrowed by two concurrent queries. Both are bounded
        // (LIMIT / COUNT), so the latency cost is small.
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let rows = data_q.fetch_all(&mut *tx).await?;
        let total = count_q.fetch_one(&mut *tx).await?;
        tx.commit().await?;

        let summaries = rows
            .into_iter()
            .map(|row| WorkflowSummary {
                id: row.get("id"),
                name: row.get("name"),
                description: row.try_get("description").ok().flatten(),
                graph_json: row.get("graph_json"),
                tags: row.try_get("tags").ok().unwrap_or_default(),
                last_status: row.try_get("last_status").ok().flatten(),
                last_exec_at: row.try_get("last_exec_at").ok().flatten(),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
                status: row.try_get("status").ok().flatten(),
                workflow_type: row.try_get("workflow_type").ok().flatten(),
            })
            .collect();

        Ok((summaries, total))
    }

    /// Fetch a full workflow record by id + user_id (ownership check). Returns None if not found.
    pub async fn get_workflow(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<WorkflowRecord>> {
        // RFC 0005 S3: self-scope on a per-user tx so the workflows RLS
        // policy backstops the read for ALL callers (the MCP workflow
        // handlers), no per-caller change. The query filters
        // `user_id = $2`; the scope's user-clause mirrors it.
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let row = sqlx::query(
            "SELECT id, name, graph_json, tags, description, max_concurrent_executions, \
                    is_enabled, capabilities, intent, readiness_score, actor_id, status, \
                    workflow_type, timeout_seconds, input_schema \
             FROM workflows WHERE id = $1 AND user_id = $2",
        )
        .bind(workflow_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok(row.map(|r| WorkflowRecord {
            id: r.get("id"),
            name: r.get("name"),
            graph_json: r.get("graph_json"),
            tags: r.try_get("tags").unwrap_or_default(),
            description: r.try_get("description").unwrap_or(None),
            max_concurrent_executions: r.try_get("max_concurrent_executions").unwrap_or(None),
            is_enabled: r.try_get("is_enabled").unwrap_or(true),
            capabilities: r.try_get("capabilities").unwrap_or_default(),
            intent: r.try_get("intent").unwrap_or(None),
            readiness_score: r.try_get("readiness_score").unwrap_or(None),
            actor_id: r.try_get("actor_id").unwrap_or(None),
            status: r.try_get("status").unwrap_or(None),
            workflow_type: r.try_get("workflow_type").unwrap_or(None),
            timeout_seconds: r.try_get("timeout_seconds").unwrap_or(None),
            input_schema: r.try_get("input_schema").unwrap_or(None),
        }))
    }

    /// Fetch `graph_json` for `workflow_id` scoped to `user_id`. Returns
    /// `Ok(None)` when the workflow does not exist or is not visible.
    ///
    /// The `::text` cast is a no-op today (`workflows.graph_json` is TEXT
    /// in the migration) but is kept for consistency with
    /// [`get_workflow_graph_unchecked`](Self::get_workflow_graph_unchecked)
    /// and [`get_workflow_graphs`](Self::get_workflow_graphs); if the
    /// column is ever migrated to JSONB, all three paths continue to
    /// decode into `String` the same way.
    pub async fn get_workflow_graph(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<String>> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT graph_json::text FROM workflows WHERE id = $1 AND user_id = $2")
                .bind(workflow_id)
                .bind(user_id)
                .fetch_optional(&self.db_pool)
                .await?;

        Ok(row.map(|(gj,)| gj))
    }

    /// Batch variant of [`get_workflow_graph`] — fetches `graph_json` for
    /// every id in `ids` that belongs to `user_id`, in a single query.
    ///
    /// Ids that do not resolve (wrong user or missing workflow) are
    /// simply absent from the returned map. The query projects
    /// `graph_json::text` so JSONB columns are returned as strings, not
    /// parsed `Value`s, matching the caller's expectations.
    pub async fn get_workflow_graphs(
        &self,
        ids: &[Uuid],
        user_id: Uuid,
    ) -> Result<HashMap<Uuid, String>> {
        if ids.is_empty() {
            return Ok(HashMap::new());
        }
        let rows: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT id, graph_json::text FROM workflows \
             WHERE id = ANY($1) AND user_id = $2",
        )
        .bind(ids)
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows.into_iter().collect())
    }

    /// Fetch `(name, graph_json)` for `workflow_id` scoped to `user_id`.
    /// Used by callers that need to display a workflow's name alongside its
    /// graph (e.g. the rotate-secret verification path that test-runs each
    /// dependent workflow and reports results by name).
    pub async fn get_workflow_name_and_graph(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<(String, String)>> {
        let row: Option<(String, String)> = sqlx::query_as(
            "SELECT name, graph_json::text FROM workflows WHERE id = $1 AND user_id = $2",
        )
        .bind(workflow_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(row)
    }

    /// Fetch graph_json without ownership check (used by graph mutation handlers
    /// that have already verified ownership earlier in the call, e.g. system-node builders).
    pub async fn get_workflow_graph_unchecked(&self, workflow_id: Uuid) -> Result<Option<String>> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT graph_json::text FROM workflows WHERE id = $1")
                .bind(workflow_id)
                .fetch_optional(&self.db_pool)
                .await?;
        Ok(row.map(|(gj,)| gj))
    }

    /// Fetch the actor_id for a workflow — used at authoring time to enforce capability ceilings.
    /// Returns `Ok(None)` when the workflow has no actor_id or the workflow does not belong
    /// to `user_id`. Returns `Err` only on a real database failure.
    pub async fn get_workflow_actor_id(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<Uuid>> {
        let actor_id: Option<Option<Uuid>> =
            sqlx::query_scalar("SELECT actor_id FROM workflows WHERE id = $1 AND user_id = $2")
                .bind(workflow_id)
                .bind(user_id)
                .fetch_optional(&self.db_pool)
                .await?;
        Ok(actor_id.flatten())
    }

    /// Fetch the active version's graph_json and version id. Falls back to the draft if no
    /// active version exists. Returns None if the workflow is not found.
    pub async fn get_active_version_graph(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<(String, Option<Uuid>)>> {
        // Try active published version first. Scoped by user_id via JOIN on
        // workflows so the SQL itself enforces ownership — defense in depth
        // even if an upstream caller forgets to verify. Without this, a
        // future refactor that loads the active version by workflow_id alone
        // could silently expose another user's published graph.
        let version_row: Option<(Uuid, String)> = sqlx::query_as(
            "SELECT v.id, v.graph_json::text \
             FROM workflow_versions v \
             JOIN workflows w ON w.id = v.workflow_id \
             WHERE v.workflow_id = $1 AND v.is_active = true AND w.user_id = $2",
        )
        .bind(workflow_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;

        if let Some((vid, gj)) = version_row {
            return Ok(Some((gj, Some(vid))));
        }

        // Fall back to draft.
        let draft: Option<(String,)> =
            sqlx::query_as("SELECT graph_json FROM workflows WHERE id = $1 AND user_id = $2")
                .bind(workflow_id)
                .bind(user_id)
                .fetch_optional(&self.db_pool)
                .await?;

        Ok(draft.map(|(gj,)| (gj, None)))
    }

    /// Check whether a workflow name is already taken for a user (ignoring archived).
    pub async fn find_workflow_by_name(&self, user_id: Uuid, name: &str) -> Result<Option<Uuid>> {
        // RFC 0005 S3: self-scope (see get_workflow).
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let id: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM workflows \
             WHERE user_id = $1 AND name = $2 \
             AND (status IS NULL OR status != 'archived') \
             LIMIT 1",
        )
        .bind(user_id)
        .bind(name)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Fetch the declared input_schema for a workflow. Returns None if not set.
    pub async fn get_workflow_input_schema(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<serde_json::Value>> {
        // RFC 0005 S3: self-scope (see get_workflow).
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let schema: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT input_schema FROM workflows WHERE id = $1 AND user_id = $2")
                .bind(workflow_id)
                .bind(user_id)
                .fetch_optional(&mut *tx)
                .await?
                .flatten();
        tx.commit().await?;
        Ok(schema)
    }

    // ── Mutation ───────────────────────────────────────────────────────────

    /// Insert a new workflow row. Returns the new workflow's UUID.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_workflow(
        &self,
        user_id: Uuid,
        name: &str,
        graph_json: &str,
        description: Option<&str>,
        tags: &[String],
        capabilities: &[String],
        intent: Option<&serde_json::Value>,
        max_concurrent: Option<i32>,
        timeout_secs: Option<i32>,
        actor_id: Option<Uuid>,
    ) -> Result<Uuid> {
        let wf_id = Uuid::new_v4();

        // RFC 0004: stamp org_id = the creator's personal org. RFC 0006 /
        // RFC 0005 S3: scope the write to that org so the org-pin RLS WITH
        // CHECK enforces (see `begin_personal_org_write`). The resolved org
        // is bound as `org_id` ($12) so the row's org matches the scope.
        let (mut tx, personal_org) = self.begin_personal_org_write(user_id).await?;

        sqlx::query(
            "INSERT INTO workflows \
             (id, user_id, name, module_uri, graph_json, description, tags, capabilities, \
              intent, max_concurrent_executions, timeout_seconds, actor_id, readiness_score, \
              created_at, updated_at, org_id) \
             VALUES ($1, $2, $3, '', $4, $5, $6, $7, $8, $9, $10, $11, 0, NOW(), NOW(), $12)",
        )
        .bind(wf_id)
        .bind(user_id)
        .bind(name)
        .bind(graph_json)
        .bind(description)
        .bind(tags)
        .bind(capabilities)
        .bind(intent)
        .bind(max_concurrent)
        .bind(timeout_secs)
        .bind(actor_id)
        .bind(personal_org)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(wf_id)
    }

    /// Update only graph_json (and bump updated_at). Returns true if a row was affected.
    pub async fn update_workflow_graph(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        graph_json: &str,
    ) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE workflows SET graph_json = $1, updated_at = NOW() \
             WHERE id = $2 AND user_id = $3",
        )
        .bind(graph_json)
        .bind(workflow_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Update graph_json without the user_id ownership check (used by graph mutation handlers
    /// that have already verified ownership earlier in the call).
    pub async fn update_workflow_graph_unchecked(
        &self,
        workflow_id: Uuid,
        graph_json: &str,
    ) -> Result<bool> {
        let result =
            sqlx::query("UPDATE workflows SET graph_json = $1, updated_at = NOW() WHERE id = $2")
                .bind(graph_json)
                .bind(workflow_id)
                .execute(&self.db_pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Update workflow metadata fields selectively. Returns true if a row was affected.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_workflow_metadata(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        name: Option<&str>,
        description: Option<&str>,
        tags: Option<&[String]>,
        capabilities: Option<&[String]>,
        intent: Option<&serde_json::Value>,
        max_concurrent: Option<i32>,
    ) -> Result<bool> {
        // Build a dynamic SET clause. We always touch updated_at.
        // param_count tracks the number of bound parameters ($1, $2, ...) separately
        // from set_parts.len() because set_parts[0] is "updated_at = NOW()" which
        // has no corresponding bind parameter — mixing the two caused a $N off-by-one
        // that made PostgreSQL see more parameter slots than sqlx actually binds.
        let mut set_parts: Vec<String> = vec!["updated_at = NOW()".to_string()];
        let mut param_count = 0usize;
        if name.is_some() {
            param_count += 1;
            set_parts.push(format!("name = ${}", param_count));
        }
        if description.is_some() {
            param_count += 1;
            set_parts.push(format!("description = ${}", param_count));
        }
        if tags.is_some() {
            param_count += 1;
            set_parts.push(format!("tags = ${}", param_count));
        }
        if capabilities.is_some() {
            param_count += 1;
            set_parts.push(format!("capabilities = ${}", param_count));
        }
        if intent.is_some() {
            param_count += 1;
            set_parts.push(format!("intent = ${}", param_count));
        }
        if max_concurrent.is_some() {
            param_count += 1;
            set_parts.push(format!("max_concurrent_executions = ${}", param_count));
        }

        let where_id_pos = param_count + 1;
        let where_uid_pos = param_count + 2;

        let sql = format!(
            "UPDATE workflows SET {} WHERE id = ${} AND user_id = ${}",
            set_parts.join(", "),
            where_id_pos,
            where_uid_pos
        );

        let mut q = sqlx::query(&sql);
        if let Some(n) = name {
            q = q.bind(n);
        }
        if let Some(d) = description {
            q = q.bind(d);
        }
        if let Some(t) = tags {
            q = q.bind(t);
        }
        if let Some(c) = capabilities {
            q = q.bind(c);
        }
        if let Some(i) = intent {
            q = q.bind(i);
        }
        if let Some(m) = max_concurrent {
            q = q.bind(m);
        }
        q = q.bind(workflow_id).bind(user_id);

        let result = q.execute(&self.db_pool).await?;
        Ok(result.rows_affected() > 0)
    }

    /// Delete workflows by ID list (ownership checked). Skips any that have running executions.
    /// Returns `(deleted_ids, blocked_ids)`.
    /// `blocked_ids` — workflows that exist, are owned by user, but have running/queued
    ///   executions preventing deletion.
    /// Ids that don't exist or belong to another user appear in neither list; callers
    /// compute `not_found = requested - deleted - blocked`.
    pub async fn delete_workflows(
        &self,
        ids: &[Uuid],
        user_id: Uuid,
    ) -> Result<(Vec<Uuid>, Vec<Uuid>)> {
        if ids.is_empty() {
            return Ok((vec![], vec![]));
        }
        let deleted_ids: Vec<Uuid> = sqlx::query_scalar(
            "DELETE FROM workflows WHERE id = ANY($1) AND user_id = $2 \
             AND NOT EXISTS ( \
                 SELECT 1 FROM workflow_executions \
                 WHERE workflow_id = workflows.id AND status IN ('running', 'queued', 'pending', 'resuming') \
             ) \
             RETURNING id",
        )
        .bind(ids)
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;

        // Only include ids in `blocked` when the workflow EXISTS and is owned by
        // this user but has active executions preventing deletion.  Ids that don't
        // exist (or belong to another user) must NOT appear in `blocked` — the
        // handler uses blocked.is_empty() to distinguish "blocked" from "not found".
        let blocked: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM workflows WHERE id = ANY($1) AND user_id = $2 \
             AND EXISTS ( \
                 SELECT 1 FROM workflow_executions \
                 WHERE workflow_id = workflows.id AND status IN ('running', 'queued', 'pending', 'resuming') \
             )",
        )
        .bind(ids)
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await
        .unwrap_or_default();

        Ok((deleted_ids, blocked))
    }

    /// Enable or disable a workflow. Returns true if a row was affected.
    pub async fn set_workflow_enabled(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        enabled: bool,
    ) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE workflows SET is_enabled = $1, updated_at = NOW() \
             WHERE id = $2 AND user_id = $3",
        )
        .bind(enabled)
        .bind(workflow_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Update the full-text search vector for a workflow (best-effort).
    pub async fn update_workflow_search_text(&self, workflow_id: Uuid, text: &str) -> Result<()> {
        sqlx::query("UPDATE workflows SET search_text = to_tsvector('english', $1) WHERE id = $2")
            .bind(text)
            .bind(workflow_id)
            .execute(&self.db_pool)
            .await?;
        Ok(())
    }

    // ── Workflow cleanup & archiving ──────────────────────────────────────

    /// Delete all workflows for a user, optionally filtered by name prefix.
    /// Returns the number of rows deleted.
    ///
    /// MCP-719 (2026-05-13): added `ESCAPE '\\'` and inline LIKE-escape
    /// on the prefix so a caller-supplied `%` / `_` is matched literally
    /// instead of as a wildcard. Pre-fix a forgotten escape at the
    /// caller (or a deliberately-malformed prefix like `"%"`) would
    /// DELETE every workflow for the user, since `LIKE '%%'` matches
    /// everything. The user-scope (`WHERE user_id = $1`) keeps the
    /// blast radius bounded to the caller's own data, but
    /// "accidentally nuke all my workflows" is a footgun worth closing
    /// at the repo level rather than relying on every caller to
    /// escape. The function body mirrors
    /// `talos_search_service::escape_like` (cannot import directly —
    /// search-service depends on this crate, so taking the reverse
    /// edge would cycle); replacement order matters (backslash MUST be
    /// doubled first so the `%` / `_` escapes don't get re-doubled).
    pub async fn cleanup_workflows(&self, user_id: Uuid, prefix: Option<&str>) -> Result<u64> {
        let result = if let Some(pfx) = prefix {
            let escaped: String = pfx
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_");
            sqlx::query("DELETE FROM workflows WHERE user_id = $1 AND name LIKE $2 ESCAPE '\\'")
                .bind(user_id)
                .bind(format!("{}%", escaped))
                .execute(&self.db_pool)
                .await?
        } else {
            sqlx::query("DELETE FROM workflows WHERE user_id = $1")
                .bind(user_id)
                .execute(&self.db_pool)
                .await?
        };
        Ok(result.rows_affected())
    }

    /// Find non-archived workflows whose names match a LIKE pattern.
    /// Returns `(id, name)` pairs. Capped at 500 results.
    pub async fn find_workflows_by_prefix(
        &self,
        user_id: Uuid,
        like_pattern: &str,
    ) -> Result<Vec<(Uuid, String)>> {
        // RFC 0005 S3: self-scope (see get_workflow).
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let rows: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT id, name FROM workflows \
             WHERE user_id = $1 AND name LIKE $2 ESCAPE '\\' \
               AND (status IS NULL OR status != 'archived') \
             ORDER BY name LIMIT 500",
        )
        .bind(user_id)
        .bind(like_pattern)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows)
    }

    /// Archive a set of workflows by ID, optionally stamping a workflow_type.
    /// Returns the number of rows updated.
    pub async fn archive_workflows_by_ids(
        &self,
        ids: &[Uuid],
        user_id: Uuid,
        wf_type: Option<&str>,
    ) -> Result<u64> {
        if ids.is_empty() {
            return Ok(0);
        }
        let result = if let Some(t) = wf_type {
            sqlx::query(
                "UPDATE workflows SET status = 'archived', workflow_type = $3, updated_at = NOW() \
                 WHERE id = ANY($1) AND user_id = $2 \
                   AND (status IS NULL OR status != 'archived')",
            )
            .bind(ids)
            .bind(user_id)
            .bind(t)
            .execute(&self.db_pool)
            .await?
        } else {
            sqlx::query(
                "UPDATE workflows SET status = 'archived', updated_at = NOW() \
                 WHERE id = ANY($1) AND user_id = $2 \
                   AND (status IS NULL OR status != 'archived')",
            )
            .bind(ids)
            .bind(user_id)
            .execute(&self.db_pool)
            .await?
        };
        Ok(result.rows_affected())
    }

    // ── Simple single-field workflow updates ──────────────────────────────

    /// Set the input_schema for a workflow. Returns true if a row was updated.
    pub async fn set_workflow_input_schema(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        schema: &serde_json::Value,
    ) -> Result<bool> {
        let result =
            sqlx::query("UPDATE workflows SET input_schema = $1 WHERE id = $2 AND user_id = $3")
                .bind(schema)
                .bind(workflow_id)
                .bind(user_id)
                .execute(&self.db_pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Set the workflow_type column. Returns true if a row was updated.
    pub async fn set_workflow_type(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        wf_type: &str,
    ) -> Result<bool> {
        let result =
            sqlx::query("UPDATE workflows SET workflow_type = $1 WHERE id = $2 AND user_id = $3")
                .bind(wf_type)
                .bind(workflow_id)
                .bind(user_id)
                .execute(&self.db_pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Update the description of a workflow. Returns true if a row was updated.
    pub async fn set_workflow_description(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        description: &str,
    ) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE workflows SET description = $1, updated_at = NOW() \
             WHERE id = $2 AND user_id = $3",
        )
        .bind(description)
        .bind(workflow_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Bind or unbind the default actor on a workflow. Returns true if a
    /// row was updated. `actor_id = None` clears the binding (the workflow
    /// becomes "shared mode" — every caller must pass actor_id explicitly,
    /// otherwise __memory_write__ envelopes silently drop).
    ///
    /// Caller MUST pre-validate that:
    ///   1. The workflow is owned by `user_id` (this query enforces that).
    ///   2. When `actor_id` is `Some(_)`, the actor exists, is non-archived,
    ///      and is owned by the same `user_id` (cross-user actor binding
    ///      would let user A's workflow stamp user B's actor on every
    ///      execution — defense in depth lives in the caller per the
    ///      service-layer pattern; this repo method does NOT re-check the
    ///      actor side).
    pub async fn set_workflow_actor_id(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        actor_id: Option<Uuid>,
    ) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE workflows SET actor_id = $1, updated_at = NOW() \
             WHERE id = $2 AND user_id = $3",
        )
        .bind(actor_id)
        .bind(workflow_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Batch fetch of `(workflow_id, name)` pairs scoped to `user_id`.
    /// Used by the workflow-health handler to resolve sub-workflow names
    /// without paying for a full `get_workflow` round-trip per child.
    /// Workflows the caller doesn't own are excluded from the result;
    /// callers reading "does this id resolve" should use `.contains_key`.
    /// Empty input short-circuits without touching the DB.
    pub async fn get_workflow_names_by_ids(
        &self,
        workflow_ids: &[Uuid],
        user_id: Uuid,
    ) -> Result<std::collections::HashMap<Uuid, String>> {
        if workflow_ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let rows: Vec<(Uuid, String)> =
            sqlx::query_as("SELECT id, name FROM workflows WHERE id = ANY($1) AND user_id = $2")
                .bind(workflow_ids)
                .bind(user_id)
                .fetch_all(&self.db_pool)
                .await?;
        Ok(rows.into_iter().collect())
    }

    /// Fetch version metadata for a workflow (count, latest version number, last published).
    pub async fn get_workflow_version_info(
        &self,
        workflow_id: Uuid,
    ) -> Result<WorkflowVersionInfo> {
        let row = sqlx::query(
            "SELECT COUNT(*)::bigint AS total_versions, \
                    MAX(version_number) AS latest_version, \
                    MAX(published_at) AS last_published \
             FROM workflow_versions WHERE workflow_id = $1",
        )
        .bind(workflow_id)
        .fetch_one(&self.db_pool)
        .await?;

        Ok(WorkflowVersionInfo {
            total_versions: row.try_get("total_versions").unwrap_or(0),
            latest_version: row.try_get("latest_version").unwrap_or(None),
            last_published: row.try_get("last_published").unwrap_or(None),
        })
    }

    /// Count active (non-archived) workflows owned by `user_id` whose name
    /// matches `name` but whose id differs from `exclude_id`.  Used to surface
    /// a soft name-collision warning after LLM scaffolding.
    pub async fn count_workflow_name_collision(
        &self,
        user_id: Uuid,
        name: &str,
        exclude_id: Uuid,
    ) -> Result<i64> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM workflows \
             WHERE user_id = $1 AND name = $2 AND id != $3 \
             AND (status IS NULL OR status != 'archived')",
        )
        .bind(user_id)
        .bind(name)
        .bind(exclude_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(count)
    }

    /// Check if a workflow exists and is owned by the given user.
    ///
    /// MCP-876 (2026-05-14): log the underlying sqlx error on failure
    /// before collapsing to `false`. Pre-fix `.unwrap_or(false)`
    /// silently treated DB errors (connection-pool exhausted, query
    /// timeout, FK violation) identically to "row missing or wrong
    /// owner" — fail-closed is correct here (every caller routes
    /// `false` to "Workflow not found"), but operators investigating
    /// a flood of "workflow not found" reports had no signal whether
    /// to look at user mistakes vs DB infrastructure. Now the WARN
    /// log lets the audit team correlate.
    ///
    /// Note: API-shape follow-up worth doing — return `Result<bool>`
    /// so the 10+ MCP callers can distinguish the two outcomes in
    /// their user-facing error messages (separate "we have a DB
    /// issue, retry" path from "this workflow really isn't yours").
    /// Out of scope for this fix; the telemetry below covers the
    /// silent-incident case.
    pub async fn workflow_exists(&self, workflow_id: Uuid, user_id: Uuid) -> bool {
        // RFC 0005 S3: self-scope (see get_workflow). A begin failure
        // folds into the same fail-closed `false` the query-error arm
        // returns (callers surface it as "Workflow not found").
        let mut tx = match talos_db::begin_user_scoped(&self.db_pool, user_id).await {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(workflow_id = %workflow_id, user_id = %user_id, error = %e,
                    "workflow_exists: tenant-scope begin failed — returning false (fail-closed)");
                return false;
            }
        };
        match sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM workflows WHERE id = $1 AND user_id = $2)",
        )
        .bind(workflow_id)
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await
        {
            Ok(exists) => {
                let _ = tx.commit().await;
                exists
            }
            Err(e) => {
                tracing::warn!(
                    workflow_id = %workflow_id,
                    user_id = %user_id,
                    error = %e,
                    "workflow_exists query failed — returning false (fail-closed); \
                     callers will surface this as 'Workflow not found' to the user"
                );
                false
            }
        }
    }

    // ── workflows.rs MCP-handler support ───────────────────────────────────

    /// Insert a published, internal-type workflow with an actor_id. Used by
    /// `plan_and_execute_workflow` for both subtask workflows and the
    /// orchestrator workflow. `graph_json` is bound as text and cast to JSONB.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_published_internal_workflow(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        actor_id: Option<Uuid>,
        name: &str,
        description: &str,
        graph_json: &str,
    ) -> Result<()> {
        // RFC 0006 / RFC 0005 S3: scope to the creator's personal org so the
        // org-pin WITH CHECK enforces; bind the resolved org as `org_id` ($7).
        let (mut tx, personal_org) = self.begin_personal_org_write(user_id).await?;
        sqlx::query(
            "INSERT INTO workflows (id, user_id, actor_id, name, description, graph_json, status, workflow_type, org_id) \
             VALUES ($1, $2, $3, $4, $5, $6::jsonb, 'published', 'internal', $7)",
        )
        .bind(workflow_id)
        .bind(user_id)
        .bind(actor_id)
        .bind(name)
        .bind(description)
        .bind(graph_json)
        .bind(personal_org)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Insert a workflow created from a YAML import. Distinct from
    /// `create_workflow_basic` because this variant carries
    /// `capabilities` + a placeholder `module_uri` and sets `is_enabled = true`.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_yaml_imported_workflow(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        name: &str,
        description: &str,
        graph_json: &str,
        capabilities: &[String],
        module_uri: &str,
    ) -> Result<()> {
        // RFC 0006 / RFC 0005 S3: scope to the creator's personal org so the
        // org-pin WITH CHECK enforces; bind the resolved org as `org_id` ($8).
        let (mut tx, personal_org) = self.begin_personal_org_write(user_id).await?;
        sqlx::query(
            "INSERT INTO workflows (id, user_id, name, description, graph_json, is_enabled, capabilities, module_uri, org_id) \
             VALUES ($1, $2, $3, $4, $5, true, $6, $7, $8)",
        )
        .bind(workflow_id)
        .bind(user_id)
        .bind(name)
        .bind(description)
        .bind(graph_json)
        .bind(capabilities)
        .bind(module_uri)
        .bind(personal_org)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    // ── versions.rs MCP-handler support ────────────────────────────────────

    /// Optionally update `intent` and/or `capabilities` on a workflow.
    /// COALESCE-based so passing `None` preserves the existing column value.
    /// Sidecar bools (`update_intent`, `update_capabilities`) distinguish
    /// "caller did not pass" from "caller cleared to NULL"; same idiom
    /// `update_actor_name_description` uses for description.
    pub async fn update_workflow_intent_and_capabilities(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        intent: Option<&serde_json::Value>,
        capabilities: Option<&[String]>,
    ) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE workflows SET \
                intent = CASE WHEN $3::bool THEN $4 ELSE intent END, \
                capabilities = CASE WHEN $5::bool THEN $6 ELSE capabilities END \
             WHERE id = $1 AND user_id = $2",
        )
        .bind(workflow_id)
        .bind(user_id)
        .bind(intent.is_some())
        .bind(intent)
        .bind(capabilities.is_some())
        .bind(capabilities)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Update the `status` column on a workflow (e.g. "active", "archived").
    pub async fn set_workflow_status(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        status: &str,
    ) -> Result<u64> {
        let result = sqlx::query("UPDATE workflows SET status = $1 WHERE id = $2 AND user_id = $3")
            .bind(status)
            .bind(workflow_id)
            .bind(user_id)
            .execute(&self.db_pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// Fetch `(version_id, graph_json::text)` for a (workflow_id, version_number)
    /// pair, scoped to the caller. Used by `rollback_workflow`.
    ///
    /// Defense-in-depth: the JOIN on `workflows.user_id` makes this fail
    /// closed if a future caller forgets the upstream ownership check —
    /// matches the r274 pattern for `get_active_version_graph`.
    pub async fn get_version_by_number(
        &self,
        workflow_id: Uuid,
        version_number: i32,
        user_id: Uuid,
    ) -> Result<Option<(Uuid, String)>> {
        let row: Option<(Uuid, String)> = sqlx::query_as(
            "SELECT v.id, v.graph_json::text \
             FROM workflow_versions v \
             JOIN workflows w ON w.id = v.workflow_id \
             WHERE v.workflow_id = $1 AND v.version_number = $2 AND w.user_id = $3",
        )
        .bind(workflow_id)
        .bind(version_number)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(row)
    }

    /// Fetch just the `graph_json::text` for a (workflow_id, version_number)
    /// pair, scoped to the caller. Used by `diff_versions`.
    pub async fn get_version_graph_text_by_number(
        &self,
        workflow_id: Uuid,
        version_number: i32,
        user_id: Uuid,
    ) -> Result<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT v.graph_json::text \
             FROM workflow_versions v \
             JOIN workflows w ON w.id = v.workflow_id \
             WHERE v.workflow_id = $1 AND v.version_number = $2 AND w.user_id = $3",
        )
        .bind(workflow_id)
        .bind(version_number)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(row.map(|(g,)| g))
    }

    /// Fetch the `graph_json::text` for the currently-active published
    /// version. Used by `get_version_diff_summary` to compare draft vs.
    /// published. Returns Ok(None) when no version is active yet.
    pub async fn get_active_version_graph_text(&self, workflow_id: Uuid) -> Result<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT graph_json::text FROM workflow_versions \
             WHERE workflow_id = $1 AND is_active = true",
        )
        .bind(workflow_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(row.map(|(g,)| g))
    }

    // ── graph.rs MCP-handler support ───────────────────────────────────────

    /// Returns true if the workflow has an active published version. Used
    /// 4× by graph mutation handlers as a gate for the auto-publish sync.
    pub async fn workflow_has_active_version(&self, workflow_id: Uuid) -> Result<bool> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM workflow_versions WHERE workflow_id = $1 AND is_active = true)",
        )
        .bind(workflow_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(exists)
    }

    /// Source-workflow projection for `duplicate_workflow` — name, raw
    /// graph_json text, and tags only.
    pub async fn get_workflow_for_duplicate(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<WorkflowDuplicateSource>> {
        let row = sqlx::query(
            "SELECT name, graph_json, tags FROM workflows WHERE id = $1 AND user_id = $2",
        )
        .bind(workflow_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(row.map(|r| WorkflowDuplicateSource {
            name: r.try_get("name").unwrap_or_default(),
            graph_json: r.try_get("graph_json").unwrap_or_else(|_| "{}".to_string()),
            tags: r.try_get("tags").unwrap_or_default(),
        }))
    }

    /// Insert a duplicated workflow row. Returns the DB error so callers
    /// can decide between "duplicate-name" and generic-failure messaging.
    pub async fn insert_duplicated_workflow(
        &self,
        new_id: Uuid,
        user_id: Uuid,
        new_name: &str,
        graph_json: &str,
        tags: &[String],
    ) -> Result<()> {
        // RFC 0006 / RFC 0005 S3: scope to the creator's personal org so the
        // org-pin WITH CHECK enforces; bind the resolved org as `org_id` ($6).
        let (mut tx, personal_org) = self.begin_personal_org_write(user_id).await?;
        sqlx::query(
            "INSERT INTO workflows (id, user_id, name, module_uri, graph_json, tags, created_at, updated_at, org_id) \
             VALUES ($1, $2, $3, '', $4, $5, NOW(), NOW(), $6)",
        )
        .bind(new_id)
        .bind(user_id)
        .bind(new_name)
        .bind(graph_json)
        .bind(tags)
        .bind(personal_org)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Copy `input_schema` from one workflow to another (caller already
    /// verified ownership of both). Best-effort — returns Err on DB failure
    /// but the duplicate-workflow handler swallows it as non-fatal.
    pub async fn copy_input_schema(
        &self,
        source_workflow_id: Uuid,
        target_workflow_id: Uuid,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE workflows SET input_schema = (SELECT input_schema FROM workflows WHERE id = $1) \
             WHERE id = $2",
        )
        .bind(source_workflow_id)
        .bind(target_workflow_id)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    /// Get a workflow's name by id, NOT scoped to user. Used by the
    /// `get_workflow_graph` sub-workflow label resolver — sub-workflow names
    /// are visible from a workflow that already passed ownership check.
    pub async fn get_workflow_name_by_id(&self, workflow_id: Uuid) -> Result<Option<String>> {
        let name: Option<String> = sqlx::query_scalar("SELECT name FROM workflows WHERE id = $1")
            .bind(workflow_id)
            .fetch_optional(&self.db_pool)
            .await?;
        Ok(name)
    }

    /// Update the raw `graph_json` column for a workflow scoped to user.
    /// Used by handlers that mutate the JSON in-Rust then write it back
    /// (e.g. `set_workflow_priority`).
    pub async fn update_workflow_graph_json(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        graph_json: &str,
    ) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE workflows SET graph_json = $1, updated_at = NOW() \
             WHERE id = $2 AND user_id = $3",
        )
        .bind(graph_json)
        .bind(workflow_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Just the workflow's name for ownership check — used by
    /// `get_workflow_input_schema` to verify ownership before scanning
    /// execution outputs.
    pub async fn get_workflow_name_for_user(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<String>> {
        // RFC 0005 S3: self-scope (see get_workflow).
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let row: Option<(String,)> =
            sqlx::query_as("SELECT name FROM workflows WHERE id = $1 AND user_id = $2")
                .bind(workflow_id)
                .bind(user_id)
                .fetch_optional(&mut *tx)
                .await?;
        tx.commit().await?;
        Ok(row.map(|(n,)| n))
    }

    /// Update the `intent` JSONB column on a workflow.
    pub async fn set_workflow_intent_field(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        intent: &serde_json::Value,
    ) -> Result<u64> {
        let result = sqlx::query("UPDATE workflows SET intent = $1 WHERE id = $2 AND user_id = $3")
            .bind(intent)
            .bind(workflow_id)
            .bind(user_id)
            .execute(&self.db_pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// Full identity row for `get_workflow_identity`.
    pub async fn get_workflow_identity_row(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<WorkflowIdentityRow>> {
        let row = sqlx::query(
            "SELECT id, name, description, capabilities, intent, readiness_score, readiness_computed_at, graph_json, input_schema \
             FROM workflows WHERE id = $1 AND user_id = $2",
        )
        .bind(workflow_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(row.map(|r| WorkflowIdentityRow {
            name: r.get("name"),
            description: r.try_get("description").unwrap_or(None),
            capabilities: r.try_get("capabilities").unwrap_or_default(),
            intent: r.try_get("intent").unwrap_or(None),
            readiness_score: r.try_get("readiness_score").unwrap_or(None),
            readiness_computed_at: r.try_get("readiness_computed_at").unwrap_or(None),
            graph_json: r.try_get("graph_json").unwrap_or_default(),
            input_schema: r.try_get("input_schema").unwrap_or(None),
        }))
    }

    // ── platform.rs MCP-handler support ────────────────────────────────────

    /// Update the failure_webhook_url column on a workflow. Pass `None` to clear.
    /// Returns rows affected (0 = workflow not found / not owned).
    /// Distinct from the `workflow_webhooks` table — this is a single-column
    /// shortcut for the legacy MCP `set_failure_notification` tool.
    pub async fn set_failure_webhook_url_column(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        url: Option<&str>,
    ) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE workflows SET failure_webhook_url = $1 WHERE id = $2 AND user_id = $3",
        )
        .bind(url)
        .bind(workflow_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Fetch the legacy `workflows.failure_webhook_url` column. Outer Option
    /// = workflow found vs. not found; inner = column NULL vs. set.
    /// Distinct from `get_failure_webhook_url`, which queries the newer
    /// `workflow_webhooks` event-type table.
    pub async fn get_failure_webhook_url_column(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<Option<String>>> {
        let row: Option<(Option<String>,)> = sqlx::query_as(
            "SELECT failure_webhook_url FROM workflows WHERE id = $1 AND user_id = $2",
        )
        .bind(workflow_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(row.map(|(u,)| u))
    }

    /// Set or clear the per-workflow concurrency cap.
    pub async fn set_max_concurrent_executions(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        max_concurrent: Option<i32>,
    ) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE workflows SET max_concurrent_executions = $1 WHERE id = $2 AND user_id = $3",
        )
        .bind(max_concurrent)
        .bind(workflow_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// List all workflows for a user with their optional schedule joined in.
    /// Used by `export_platform_state` to build the manifest. Returns rows
    /// including raw `graph_json` text for the caller to parse.
    pub async fn list_user_workflows_with_schedule(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<WorkflowExportRow>> {
        let rows = sqlx::query(
            "SELECT w.id, w.name, w.graph_json, w.is_enabled, \
                    ws.cron_expression, ws.timezone, ws.is_enabled AS schedule_enabled \
             FROM workflows w \
             LEFT JOIN workflow_schedules ws ON ws.workflow_id = w.id \
             WHERE w.user_id = $1 \
             ORDER BY w.created_at ASC",
        )
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| WorkflowExportRow {
                id: r.get("id"),
                name: r.get("name"),
                graph_json: r.get("graph_json"),
                is_enabled: r.try_get("is_enabled").unwrap_or(true),
                cron_expression: r.try_get("cron_expression").unwrap_or(None),
                timezone: r
                    .try_get::<Option<String>, _>("timezone")
                    .unwrap_or(None)
                    .unwrap_or_else(|| "UTC".to_string()),
                schedule_enabled: r.try_get("schedule_enabled").unwrap_or(true),
            })
            .collect())
    }

    /// Find a workflow by exact name match (regardless of status). Used by
    /// the `import_platform_state` upsert path which intentionally re-imports
    /// over archived workflows too.
    pub async fn find_workflow_id_by_name_any_status(
        &self,
        user_id: Uuid,
        name: &str,
    ) -> Result<Option<Uuid>> {
        let id: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM workflows WHERE user_id = $1 AND name = $2 LIMIT 1")
                .bind(user_id)
                .bind(name)
                .fetch_optional(&self.db_pool)
                .await?;
        Ok(id)
    }

    /// Batch sibling to [`find_workflow_id_by_name_any_status`]. Replaces
    /// the per-name round-trip used by `import_platform_state`'s dry-run
    /// preview with a single `WHERE name = ANY($2)` lookup. Returns a
    /// `name → id` map; callers reading whether a name exists should
    /// use `.contains_key(name)` rather than zipping.
    ///
    /// Why this exists: a 5,000-workflow manifest's dry-run cost
    /// 5,001 round-trips pre-batch. Empty input short-circuits to an
    /// empty map without touching the DB.
    pub async fn find_workflow_ids_by_names_any_status(
        &self,
        user_id: Uuid,
        names: &[String],
    ) -> Result<std::collections::HashMap<String, Uuid>> {
        if names.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let rows: Vec<(String, Uuid)> =
            sqlx::query_as("SELECT name, id FROM workflows WHERE user_id = $1 AND name = ANY($2)")
                .bind(user_id)
                .bind(names)
                .fetch_all(&self.db_pool)
                .await?;
        Ok(rows.into_iter().collect())
    }

    /// Insert-or-update a workflow's graph_json by (user_id, name). Returns
    /// the workflow id (existing or newly minted).
    pub async fn upsert_workflow_graph_by_name(
        &self,
        user_id: Uuid,
        name: &str,
        graph_json: &str,
        existing_id: Option<Uuid>,
    ) -> Result<Uuid> {
        let id: Uuid = if let Some(eid) = existing_id {
            // Defense-in-depth: scope the UPDATE by user_id even though the
            // caller resolved `existing_id` from a user-scoped lookup.
            // Failing closed (no row returned) protects against future
            // callers that forget the upstream check or accept an
            // attacker-supplied id.
            sqlx::query_scalar(
                "UPDATE workflows SET graph_json = $1, updated_at = NOW() \
                 WHERE id = $2 AND user_id = $3 RETURNING id",
            )
            .bind(graph_json)
            .bind(eid)
            .bind(user_id)
            .fetch_optional(&self.db_pool)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Workflow not found or not owned by caller"))?
        } else {
            // RFC 0006 / RFC 0005 S3: scope the INSERT to the creator's
            // personal org so the org-pin WITH CHECK enforces; bind the
            // resolved org as `org_id` ($4). (The UPDATE branch above doesn't
            // move org_id, so it stays unscoped — permit-via-unset.)
            let (mut tx, personal_org) = self.begin_personal_org_write(user_id).await?;
            let new_id: Uuid = sqlx::query_scalar(
                "INSERT INTO workflows (user_id, name, module_uri, graph_json, created_at, updated_at, org_id) \
                 VALUES ($1, $2, '', $3, NOW(), NOW(), $4) \
                 RETURNING id",
            )
            .bind(user_id)
            .bind(name)
            .bind(graph_json)
            .bind(personal_org)
            .fetch_one(&mut *tx)
            .await?;
            tx.commit().await?;
            new_id
        };
        Ok(id)
    }

    /// Upsert a workflow_schedules row for a workflow (one schedule per workflow).
    ///
    /// Defense-in-depth: the INSERT...SELECT predicate on `workflows.user_id`
    /// fails closed if the workflow doesn't belong to the caller — even if a
    /// future caller bypasses upstream ownership checks. We then verify rows
    /// were actually written and surface an error rather than silently no-op'ing.
    pub async fn upsert_workflow_schedule(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        cron: &str,
        timezone: &str,
        is_enabled: bool,
    ) -> Result<()> {
        let result = sqlx::query(
            "INSERT INTO workflow_schedules (workflow_id, user_id, cron_expression, timezone, is_enabled, created_at, updated_at) \
             SELECT $1, $2, $3, $4, $5, NOW(), NOW() \
             FROM workflows \
             WHERE id = $1 AND user_id = $2 \
             ON CONFLICT (workflow_id) DO UPDATE SET \
               cron_expression = EXCLUDED.cron_expression, \
               timezone = EXCLUDED.timezone, \
               is_enabled = EXCLUDED.is_enabled, \
               updated_at = NOW()",
        )
        .bind(workflow_id)
        .bind(user_id)
        .bind(cron)
        .bind(timezone)
        .bind(is_enabled)
        .execute(&self.db_pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(anyhow::anyhow!("Workflow not found or not owned by caller"));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct WorkflowVersionInfo {
    pub total_versions: i64,
    pub latest_version: Option<i32>,
    pub last_published: Option<chrono::DateTime<chrono::Utc>>,
}

/// Source-workflow row for `duplicate_workflow`.
#[derive(Debug)]
pub struct WorkflowDuplicateSource {
    pub name: String,
    pub graph_json: String,
    pub tags: Vec<String>,
}

/// Identity projection for `get_workflow_identity`.
#[derive(Debug)]
pub struct WorkflowIdentityRow {
    pub name: String,
    pub description: Option<String>,
    pub capabilities: Vec<String>,
    pub intent: Option<serde_json::Value>,
    pub readiness_score: Option<i32>,
    pub readiness_computed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub graph_json: String,
    pub input_schema: Option<serde_json::Value>,
}

// ─────────────────────────────────────────────────────────────────────────────
// WorkflowGraphStore impl — lets the workflow executor fetch sub-workflow
// graphs through a trait without having to know about this repository or
// its Postgres pool.
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl talos_workflow_engine_core::WorkflowGraphStore for WorkflowRepository {
    async fn get_graph(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<serde_json::Value>, talos_workflow_engine_core::BoxError> {
        // `workflows.graph_json` is stored as TEXT (per the schema), not JSONB.
        // Decoding directly into `serde_json::Value` fails with a typed-decode
        // error and the engine treats the lookup as "graph not found" — which
        // breaks every sub-workflow / capability-dispatch / judge / ensemble
        // node with a misleading "Sub-workflow workflow X not found" error
        // message even though the row exists. Decode as String and parse.
        let row: Option<(String,)> =
            sqlx::query_as("SELECT graph_json FROM workflows WHERE id = $1 AND user_id = $2")
                .bind(workflow_id)
                .bind(user_id)
                .fetch_optional(&self.db_pool)
                .await?;
        match row {
            None => Ok(None),
            Some((s,)) => {
                let v = serde_json::from_str(&s).map_err(
                    |e| -> talos_workflow_engine_core::BoxError {
                        format!("graph_json parse error for {}: {}", workflow_id, e).into()
                    },
                )?;
                Ok(Some(v))
            }
        }
    }

    async fn get_graphs(
        &self,
        ids: &[Uuid],
        user_id: Uuid,
    ) -> Result<HashMap<Uuid, serde_json::Value>, talos_workflow_engine_core::BoxError> {
        if ids.is_empty() {
            return Ok(HashMap::new());
        }
        // Same TEXT-not-JSONB story as `get_graph`. The batch path was the
        // primary symptom: `populate_sub_workflow_cache` swallowed the decode
        // error with a WARN and fell back to per-node `get_graph` queries —
        // which then ALSO failed with the same decode bug, so every
        // sub-workflow node returned GraphNotFound.
        let rows: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT id, graph_json FROM workflows \
             WHERE id = ANY($1) AND user_id = $2",
        )
        .bind(ids)
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;
        let mut out = HashMap::with_capacity(rows.len());
        for (id, s) in rows {
            match serde_json::from_str::<serde_json::Value>(&s) {
                Ok(v) => {
                    out.insert(id, v);
                }
                Err(e) => {
                    tracing::warn!(
                        workflow_id = %id,
                        error = %e,
                        "Skipping workflow with malformed graph_json — sub-workflow \
                         dispatch will see GraphNotFound for this id"
                    );
                }
            }
        }
        Ok(out)
    }

    async fn resolve_by_name(
        &self,
        name: &str,
        user_id: Uuid,
    ) -> Result<Option<Uuid>, talos_workflow_engine_core::BoxError> {
        let row: Option<(Uuid,)> =
            sqlx::query_as("SELECT id FROM workflows WHERE name = $1 AND user_id = $2 LIMIT 1")
                .bind(name)
                .bind(user_id)
                .fetch_optional(&self.db_pool)
                .await?;
        Ok(row.map(|(id,)| id))
    }

    async fn resolve_by_capabilities(
        &self,
        required_capabilities: &[String],
        user_id: Uuid,
    ) -> Result<Option<(Uuid, String)>, talos_workflow_engine_core::BoxError> {
        let row: Option<(Uuid, String)> = sqlx::query_as(
            "SELECT id, name FROM workflows \
             WHERE user_id = $1 AND capabilities @> $2 \
             ORDER BY updated_at DESC LIMIT 1",
        )
        .bind(user_id)
        .bind(required_capabilities)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(row)
    }
}
