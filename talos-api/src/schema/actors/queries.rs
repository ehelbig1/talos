use async_graphql::{Context, Result};
use uuid::Uuid;

use crate::schema::types::*;
use crate::schema::{require_scope, SafeErrorExtensions};

#[derive(Default)]
pub struct ActorsQueries;

#[async_graphql::Object]
impl ActorsQueries {
    async fn actors(&self, ctx: &Context<'_>) -> Result<Vec<ActorSummary>> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;

        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        use sqlx::Row;

        let rows = sqlx::query(
            r#"SELECT
                a.id, a.name, a.description, a.status, a.max_capability_world,
                a.created_at, a.updated_at,
                (SELECT COUNT(*) FROM workflows w WHERE w.actor_id = a.id) as workflow_count,
                (SELECT COUNT(*) FROM workflow_executions we
                 JOIN workflows w ON w.id = we.workflow_id
                 WHERE w.actor_id = a.id) as execution_count
             FROM actors a
             WHERE a.user_id = $1
             ORDER BY a.created_at DESC"#,
        )
        .bind(user_id)
        .fetch_all(db_pool)
        .await
        .map_err(|e| e.extend_safe())?;

        let actors = rows
            .into_iter()
            .map(|row| ActorSummary {
                id: row.get("id"),
                name: row.get("name"),
                description: row.get("description"),
                status: row.get("status"),
                max_capability_world: row.get("max_capability_world"),
                workflow_count: row.get("workflow_count"),
                execution_count: row.get("execution_count"),
                total_budget_usd: None,
                spent_budget_usd: 0.0,
                created_at: row
                    .get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                    .to_rfc3339(),
                updated_at: row
                    .get::<chrono::DateTime<chrono::Utc>, _>("updated_at")
                    .to_rfc3339(),
            })
            .collect();

        Ok(actors)
    }

    #[graphql(name = "actor")]

    async fn actor(&self, ctx: &Context<'_>, id: Uuid) -> Result<Option<ActorDetails>> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;

        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        use sqlx::Row;

        let row = sqlx::query(
            r#"SELECT
                a.id, a.name, a.description, a.status, a.max_capability_world, a.metadata,
                a.created_at, a.updated_at,
                (SELECT COUNT(*) FROM workflows w WHERE w.actor_id = a.id) as workflow_count,
                (SELECT COUNT(*) FROM workflow_executions we
                 WHERE we.actor_id = a.id) as execution_count,
                (SELECT MAX(we.started_at) FROM workflow_executions we
                 WHERE we.actor_id = a.id) as last_active_at
             FROM actors a
             WHERE a.id = $1 AND a.user_id = $2"#,
        )
        .bind(id)
        .bind(user_id)
        .fetch_optional(db_pool)
        .await
        .map_err(|e: sqlx::Error| e.extend_safe())?;

        Ok(row.map(|r| {
            let metadata: Option<String> = r
                .get::<'_, Option<serde_json::Value>, _>("metadata")
                .map(|v| v.to_string());
            let last_active_at: Option<String> = r
                .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("last_active_at")
                .ok()
                .flatten()
                .map(|d| d.to_rfc3339());

            ActorDetails {
                id: r.get("id"),
                name: r.get("name"),
                description: r.get("description"),
                status: r.get("status"),
                max_capability_world: r.get("max_capability_world"),
                metadata,
                workflow_count: r.get("workflow_count"),
                execution_count: r.get("execution_count"),
                total_budget_usd: None,
                spent_budget_usd: 0.0,
                mcp_token: None,
                rate_limit: None,
                last_active_at,
                created_at: r
                    .get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                    .to_rfc3339(),
                updated_at: r
                    .get::<chrono::DateTime<chrono::Utc>, _>("updated_at")
                    .to_rfc3339(),
            }
        }))
    }

    async fn actor_executions_summary(
        &self,
        ctx: &Context<'_>,
        actor_id: Uuid,
    ) -> Result<ActorExecutionsSummary> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        use sqlx::Row;

        let actor_exists: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM actors WHERE id = $1 AND user_id = $2")
                .bind(actor_id)
                .bind(user_id)
                .fetch_optional(db_pool)
                .await
                .map_err(|e| e.extend_safe())?;

        if actor_exists.is_none() {
            return Err(async_graphql::Error::new("Actor not found").extend_safe());
        }

        let stats = sqlx::query(
            "SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE status = 'completed') AS successful,
                COUNT(*) FILTER (WHERE status = 'failed') AS failed,
                COUNT(*) FILTER (WHERE status IN ('pending', 'running')) AS active
             FROM workflow_executions WHERE actor_id = $1",
        )
        .bind(actor_id)
        .fetch_one(db_pool)
        .await
        .map_err(|e| e.extend_safe())?;

        Ok(ActorExecutionsSummary {
            total_executions: stats.get("total"),
            successful_executions: stats.get("successful"),
            failed_executions: stats.get("failed"),
            active_executions: stats.get("active"),
        })
    }

    async fn actor_workflows_summary(
        &self,
        ctx: &Context<'_>,
        actor_id: Uuid,
    ) -> Result<ActorWorkflowsSummary> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        use sqlx::Row;

        let actor_exists: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM actors WHERE id = $1 AND user_id = $2")
                .bind(actor_id)
                .bind(user_id)
                .fetch_optional(db_pool)
                .await
                .map_err(|e| e.extend_safe())?;

        if actor_exists.is_none() {
            return Err(async_graphql::Error::new("Actor not found").extend_safe());
        }

        let stats = sqlx::query(
            "SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE status != 'archived' OR status IS NULL) AS active
             FROM workflows WHERE actor_id = $1",
        )
        .bind(actor_id)
        .fetch_one(db_pool)
        .await
        .map_err(|e| e.extend_safe())?;

        Ok(ActorWorkflowsSummary {
            total_workflows: stats.get("total"),
            active_workflows: stats.get("active"),
        })
    }

    async fn actor_action_log(
        &self,
        ctx: &Context<'_>,
        actor_id: Uuid,
        limit: Option<i64>,
    ) -> Result<Vec<ActorActionLogEntry>> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        use sqlx::Row;

        let actor_exists: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM actors WHERE id = $1 AND user_id = $2")
                .bind(actor_id)
                .bind(user_id)
                .fetch_optional(db_pool)
                .await
                .map_err(|e| e.extend_safe())?;

        if actor_exists.is_none() {
            return Err(async_graphql::Error::new("Actor not found").extend_safe());
        }

        let limit = limit.unwrap_or(50).clamp(1, 200);

        let rows = sqlx::query(
            r#"SELECT id, action_type, summary, timestamp, workflow_id, execution_id
               FROM actor_action_log
               WHERE actor_id = $1
               ORDER BY timestamp DESC
               LIMIT $2"#,
        )
        .bind(actor_id)
        .bind(limit)
        .fetch_all(db_pool)
        .await
        .map_err(|e| e.extend_safe())?;

        Ok(rows
            .into_iter()
            .map(|row| ActorActionLogEntry {
                id: row.get("id"),
                action_type: row.get("action_type"),
                summary: row.get("summary"),
                timestamp: row
                    .get::<chrono::DateTime<chrono::Utc>, _>("timestamp")
                    .to_rfc3339(),
                workflow_id: row.get("workflow_id"),
                execution_id: row.get("execution_id"),
            })
            .collect())
    }

    /// MCP-1189 (2026-05-17): `limit` arg added with default 1000 and
    /// hard cap of 1000. Pre-fix the query did `fetch_all` on workflows
    /// with NO LIMIT, AND each row carried the full `graph_json` blob
    /// (capped at MAX_PAYLOAD_SIZE = 10 MiB per row, talos-api/src/
    /// validation.rs:31). Theoretical worst case for a malicious /
    /// pathological user who created thousands of workflows linked to
    /// one actor: rows × 10 MiB per `graph_json` = tens of GiB
    /// allocated on the controller per request. Frontend
    /// `getActorWorkflows` (graphqlClient.ts:922) explicitly requests
    /// `graphJson` so the full blob comes back per row — caller can't
    /// opt out via projection. Sibling fix to MCP-1188 (actor_memories
    /// 1000-row cap).
    async fn actor_workflows(
        &self,
        ctx: &Context<'_>,
        actor_id: Uuid,
        #[graphql(desc = "Max rows to return (default 1000, max 1000)")]
        limit: Option<i32>,
    ) -> Result<Vec<ActorWorkflowItem>> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        use sqlx::Row;

        let actor_exists: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM actors WHERE id = $1 AND user_id = $2")
                .bind(actor_id)
                .bind(user_id)
                .fetch_optional(db_pool)
                .await
                .map_err(|e| e.extend_safe())?;

        if actor_exists.is_none() {
            return Err(async_graphql::Error::new("Actor not found").extend_safe());
        }

        // MCP-1189: cap at 1000 even if caller passes a larger value.
        // Negatives / zero clamp up to 1. Canonical `unwrap_or(N)
        // .clamp(1, MAX)` shape used throughout the workspace.
        let limit_val: i64 = i64::from(limit.unwrap_or(1000).clamp(1, 1000));

        let rows = sqlx::query(
            r#"SELECT
                w.id, w.name, w.status, w.graph_json, w.created_at, w.updated_at,
                COALESCE(
                    (SELECT COUNT(*) FROM workflow_nodes wn WHERE wn.workflow_id = w.id),
                    0
                ) AS node_count
               FROM workflows w
               WHERE w.actor_id = $1 AND w.user_id = $2
               ORDER BY w.updated_at DESC
               LIMIT $3"#,
        )
        .bind(actor_id)
        .bind(user_id)
        .bind(limit_val)
        .fetch_all(db_pool)
        .await
        .map_err(|e| e.extend_safe())?;

        Ok(rows
            .into_iter()
            .map(|row| ActorWorkflowItem {
                id: row.get("id"),
                name: row.get("name"),
                status: row.get("status"),
                node_count: row.get::<i64, _>("node_count"),
                graph_json: row.get("graph_json"),
                created_at: row
                    .get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                    .to_rfc3339(),
                updated_at: row
                    .get::<chrono::DateTime<chrono::Utc>, _>("updated_at")
                    .to_rfc3339(),
            })
            .collect())
    }

    /// List non-expired memory entries for an actor the current user owns.
    ///
    /// MCP-1188 (2026-05-17): `limit` arg added with default 1000 and a
    /// hard cap of 1000. Pre-fix the query did `fetch_all` with no
    /// LIMIT — a user's actor can hold up to MAX_MEMORIES_PER_ACTOR =
    /// 10_000 rows (talos-memory:48), each carrying a decrypted value
    /// up to MAX_VALUE_BYTES = 64 KiB → worst-case ~640 MB allocation
    /// per request, AND a per-row AES-GCM decrypt. A user with a
    /// memory-heavy actor could trash the controller on repeated calls
    /// via the dashboard. The MCP sibling `handle_list_actor_memories`
    /// has always had a 200-row cap; this query was the holdout.
    async fn actor_memories(
        &self,
        ctx: &Context<'_>,
        actor_id: Uuid,
        #[graphql(desc = "Filter by type: working | episodic | semantic | scratchpad")]
        memory_type: Option<String>,
        #[graphql(desc = "Max rows to return (default 1000, max 1000)")]
        limit: Option<i32>,
    ) -> Result<Vec<ActorMemoryEntry>> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        // Verify ownership
        let owned: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM actors WHERE id = $1 AND user_id = $2)",
        )
        .bind(actor_id)
        .bind(user_id)
        .fetch_one(db_pool)
        .await
        .map_err(|e| e.extend_safe())?;

        if !owned {
            return Err(
                async_graphql::Error::new("Actor not found or access denied").extend_safe(),
            );
        }

        // MCP-1188: cap at 1000 even if caller passes a larger value.
        // 1000 rows × 64 KiB worst-case value = ~64 MiB per request,
        // which is bounded enough for the controller to absorb under
        // concurrent dashboard loads. Negatives / zero clamp up to 1.
        let limit_val: i64 = i64::from(limit.unwrap_or(1000).clamp(1, 1000));

        use sqlx::Row as _;
        // Phase B: every row carries ciphertext (value_enc + value_key_id);
        // the legacy plaintext `value` column is dropped. decrypt_row_value
        // reads value_enc + value_key_id and routes through the registered
        // crypto hook.
        let rows = sqlx::query(
            "SELECT key, value_enc, value_key_id, memory_type, expires_at, updated_at \
             FROM actor_memory \
             WHERE actor_id = $1 \
               AND ($2::text IS NULL OR memory_type = $2) \
               AND (expires_at IS NULL OR expires_at > NOW()) \
             ORDER BY memory_type, key ASC \
             LIMIT $3",
        )
        .bind(actor_id)
        .bind(memory_type.as_deref())
        .bind(limit_val)
        .fetch_all(db_pool)
        .await
        .map_err(|e| e.extend_safe())?;

        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            let value = talos_memory::decrypt_row_value(r).await.map_err(|e| {
                // Log the underlying decrypt error server-side. The
                // chain may include KEK provider URLs, transit-key
                // names, DEK UUIDs, and aead::Error from AES-GCM
                // — all server internals that should not cross the
                // GraphQL boundary. Return a generic safe message.
                tracing::error!(
                    actor_id = %actor_id,
                    "actor_memories: row decrypt failed: {:#}",
                    e
                );
                async_graphql::Error::new("Failed to decrypt actor memory").extend_safe()
            })?;
            out.push(ActorMemoryEntry {
                key: r.get("key"),
                value: value.to_string(),
                memory_type: r.get("memory_type"),
                expires_at: r
                    .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("expires_at")
                    .ok()
                    .flatten()
                    .map(|d| d.to_rfc3339()),
                updated_at: r
                    .get::<chrono::DateTime<chrono::Utc>, _>("updated_at")
                    .to_rfc3339(),
            });
        }
        Ok(out)
    }

    /// MCP-1190 (2026-05-17): `limit` arg added with default 100 and
    /// hard cap of 1000. Pre-fix the query did `fetch_all` on
    /// mcp_agents with NO LIMIT — no formal per-user MCP-agent cap
    /// exists at registration time, so an admin who accidentally /
    /// maliciously creates thousands of agents trashes controller
    /// heap on every dashboard `mcpAgents` call. Same unbounded-
    /// fetch-all audit class as MCP-1188 / MCP-1189; here per-row
    /// size is small (Uuid + name + two timestamps) so the worst-
    /// case is dominated by row count rather than per-row weight.
    async fn mcp_agents(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "Max rows to return (default 100, max 1000)")]
        limit: Option<i32>,
    ) -> Result<Vec<McpAgent>> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        // MCP-1190: clamp 1..=1000, default 100. Per-row size is
        // small (~100 bytes) so 1000 rows = ~100 KiB, bounded.
        let limit_val: i64 = i64::from(limit.unwrap_or(100).clamp(1, 1000));

        #[derive(sqlx::FromRow)]
        struct McpAgentRow {
            id: Uuid,
            name: String,
            created_at: chrono::DateTime<chrono::Utc>,
            last_used_at: Option<chrono::DateTime<chrono::Utc>>,
        }

        let rows = sqlx::query_as::<_, McpAgentRow>(
            r#"
            SELECT id, name, created_at, last_connected_at AS last_used_at
            FROM mcp_agents
            WHERE user_id = $1
            ORDER BY created_at DESC
            LIMIT $2
            "#,
        )
        .bind(user_id)
        .bind(limit_val)
        .fetch_all(db_pool)
        .await
        .map_err(|e| e.extend_safe())?;

        Ok(rows
            .into_iter()
            .map(|r| McpAgent {
                id: r.id,
                name: r.name,
                created_at: r.created_at.to_rfc3339(),
                last_used_at: r
                    .last_used_at
                    .map(|dt: chrono::DateTime<chrono::Utc>| dt.to_rfc3339()),
            })
            .collect())
    }
}
