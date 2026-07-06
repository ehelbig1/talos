use async_graphql::{Context, Result};
use uuid::Uuid;

use crate::schema::types::*;
use crate::schema::{require_scope, user_accessible_org_ids, SafeErrorExtensions};

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

        // RFC 0004/0005 S2: run on a tenant-scoped tx so the actors RLS
        // policy backstops the app-layer `user_id` filter. Actors are
        // personal (the policy only ever matches the owner clause), but
        // we pass the user's real accessible orgs so the workflow /
        // workflow_executions COUNT subqueries — both RLS-enabled — stay
        // permissive enough to count a teammate's executions on this
        // actor's org-shared workflows (preserving the pre-RLS counts; an
        // empty org list would undercount them). The repo method executes
        // on the tx we pass (`list_actor_summaries_scoped`).
        let actor_repo = talos_actor_repository::ActorRepository::new(db_pool.clone());
        let org_ids: Vec<uuid::Uuid> = crate::schema::user_accessible_org_ids(ctx).await?;
        let scope = talos_tenancy::TenantReadScope::new(user_id, org_ids);
        let mut tx = talos_db::begin_tenant_read_scoped(db_pool, &scope)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: tenant scope error");
                async_graphql::Error::new("Request scope error").extend_safe()
            })?;
        let rows = actor_repo
            .list_actor_summaries_scoped(&mut tx, user_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: actors list failed");
                async_graphql::Error::new("Request could not be completed").extend_safe()
            })?;
        tx.commit()
            .await
            .map_err(|e: sqlx::Error| e.extend_safe())?;

        let actors = rows
            .into_iter()
            .map(|row| ActorSummary {
                id: row.id,
                name: row.name,
                description: row.description,
                status: row.status,
                max_capability_world: row.max_capability_world,
                workflow_count: row.workflow_count,
                execution_count: row.execution_count,
                total_budget_usd: None,
                spent_budget_usd: 0.0,
                created_at: row.created_at.to_rfc3339(),
                updated_at: row.updated_at.to_rfc3339(),
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

        // RFC 0004/0005 S2: tenant-scoped tx → actors RLS backstops the
        // app-layer `user_id` filter; real org_ids keep the RLS-enabled
        // COUNT subqueries non-regressing (see sibling list resolver).
        // Repo method executes on the tx we pass.
        let actor_repo = talos_actor_repository::ActorRepository::new(db_pool.clone());
        let org_ids: Vec<uuid::Uuid> = crate::schema::user_accessible_org_ids(ctx).await?;
        let scope = talos_tenancy::TenantReadScope::new(user_id, org_ids);
        let mut tx = talos_db::begin_tenant_read_scoped(db_pool, &scope)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: tenant scope error");
                async_graphql::Error::new("Request scope error").extend_safe()
            })?;
        let row = actor_repo
            .get_actor_details_scoped(&mut tx, id, user_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: actor detail read failed");
                async_graphql::Error::new("Request could not be completed").extend_safe()
            })?;
        tx.commit()
            .await
            .map_err(|e: sqlx::Error| e.extend_safe())?;

        Ok(row.map(|r| ActorDetails {
            id: r.id,
            name: r.name,
            description: r.description,
            status: r.status,
            max_capability_world: r.max_capability_world,
            metadata: r.metadata.map(|v| v.to_string()),
            workflow_count: r.workflow_count,
            execution_count: r.execution_count,
            total_budget_usd: None,
            spent_budget_usd: 0.0,
            mcp_token: None,
            rate_limit: None,
            last_active_at: r.last_active_at.map(|d| d.to_rfc3339()),
            created_at: r.created_at.to_rfc3339(),
            updated_at: r.updated_at.to_rfc3339(),
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

        // RFC 0005 S3: one request-scoped unit of work — the ownership
        // check and the stats aggregate share ONE tenant-scoped tx (role +
        // GUC set once), so they see a consistent snapshot and the
        // actors / workflow_executions RLS policies backstop both. Real
        // org ids keep the executions count non-regressing (a teammate's
        // executions on the actor's org-shared workflows still count).
        // Repo methods execute on the UoW's connection.
        let actor_repo = talos_actor_repository::ActorRepository::new(db_pool.clone());
        let org_ids: Vec<uuid::Uuid> = user_accessible_org_ids(ctx).await?;
        let scope = talos_tenancy::TenantReadScope::new(user_id, org_ids);
        let mut uow = talos_db::UnitOfWork::begin(db_pool, &scope)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: tenant scope error");
                async_graphql::Error::new("Request scope error").extend_safe()
            })?;

        let actor_exists = actor_repo
            .actor_owned_by_user_scoped(uow.conn(), actor_id, user_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: actor ownership check failed");
                async_graphql::Error::new("Request could not be completed").extend_safe()
            })?;

        if !actor_exists {
            return Err(async_graphql::Error::new("Actor not found").extend_safe());
        }

        let stats = actor_repo
            .get_actor_execution_counts_scoped(uow.conn(), actor_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: actor execution stats failed");
                async_graphql::Error::new("Request could not be completed").extend_safe()
            })?;
        uow.commit().await.map_err(|e| {
            tracing::error!(error = %e, "graphql: commit transaction error");
            async_graphql::Error::new("Request could not be completed").extend_safe()
        })?;

        Ok(ActorExecutionsSummary {
            total_executions: stats.total,
            successful_executions: stats.successful,
            failed_executions: stats.failed,
            active_executions: stats.active,
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

        // RFC 0005 S3: shared unit of work (see actor_executions_summary).
        // Ownership check + workflows aggregate in one tenant-scoped tx.
        let actor_repo = talos_actor_repository::ActorRepository::new(db_pool.clone());
        let org_ids: Vec<uuid::Uuid> = user_accessible_org_ids(ctx).await?;
        let scope = talos_tenancy::TenantReadScope::new(user_id, org_ids);
        let mut uow = talos_db::UnitOfWork::begin(db_pool, &scope)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: tenant scope error");
                async_graphql::Error::new("Request scope error").extend_safe()
            })?;

        let actor_exists = actor_repo
            .actor_owned_by_user_scoped(uow.conn(), actor_id, user_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: actor ownership check failed");
                async_graphql::Error::new("Request could not be completed").extend_safe()
            })?;

        if !actor_exists {
            return Err(async_graphql::Error::new("Actor not found").extend_safe());
        }

        let stats = actor_repo
            .get_actor_workflow_counts_scoped(uow.conn(), actor_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: actor workflow stats failed");
                async_graphql::Error::new("Request could not be completed").extend_safe()
            })?;
        uow.commit().await.map_err(|e| {
            tracing::error!(error = %e, "graphql: commit transaction error");
            async_graphql::Error::new("Request could not be completed").extend_safe()
        })?;

        Ok(ActorWorkflowsSummary {
            total_workflows: stats.total,
            active_workflows: stats.active,
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

        let limit = limit.unwrap_or(50).clamp(1, 200);

        // RFC 0005 S3: ownership check + action-log read in ONE per-user
        // unit of work (actors are personal — the actor's log is the
        // user's), so the actors ownership read gets the RLS backstop.
        let actor_repo = talos_actor_repository::ActorRepository::new(db_pool.clone());
        let mut uow = talos_db::UnitOfWork::begin_user(db_pool, user_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: tenant scope error");
                async_graphql::Error::new("Request scope error").extend_safe()
            })?;

        let actor_exists = actor_repo
            .actor_owned_by_user_scoped(uow.conn(), actor_id, user_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: actor ownership check failed");
                async_graphql::Error::new("Request could not be completed").extend_safe()
            })?;

        if !actor_exists {
            return Err(async_graphql::Error::new("Actor not found").extend_safe());
        }

        let rows = actor_repo
            .list_action_log_scoped(uow.conn(), actor_id, limit)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: action log read failed");
                async_graphql::Error::new("Request could not be completed").extend_safe()
            })?;
        uow.commit().await.map_err(|e| {
            tracing::error!(error = %e, "graphql: commit transaction error");
            async_graphql::Error::new("Request could not be completed").extend_safe()
        })?;

        Ok(rows
            .into_iter()
            .map(|row| ActorActionLogEntry {
                id: row.id,
                action_type: row.action_type,
                summary: row.summary,
                timestamp: row.timestamp.to_rfc3339(),
                workflow_id: row.workflow_id,
                execution_id: row.execution_id,
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
        #[graphql(desc = "Max rows to return (default 1000, max 1000)")] limit: Option<i32>,
    ) -> Result<Vec<ActorWorkflowItem>> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        // MCP-1189: cap at 1000 even if caller passes a larger value.
        // Negatives / zero clamp up to 1. Canonical `unwrap_or(N)
        // .clamp(1, MAX)` shape used throughout the workspace.
        let limit_val: i64 = i64::from(limit.unwrap_or(1000).clamp(1, 1000));

        // RFC 0005 S3: ownership check + the actor's-workflows read in ONE
        // per-user unit of work — both `actors` and `workflows` (the read
        // is `w.user_id = $2`, strictly the user's own) get the RLS
        // backstop. Repo methods execute on the UoW's connection.
        let actor_repo = talos_actor_repository::ActorRepository::new(db_pool.clone());
        let workflow_repo = talos_workflow_repository::WorkflowRepository::new(db_pool.clone());
        let mut uow = talos_db::UnitOfWork::begin_user(db_pool, user_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: tenant scope error");
                async_graphql::Error::new("Request scope error").extend_safe()
            })?;

        let actor_exists = actor_repo
            .actor_owned_by_user_scoped(uow.conn(), actor_id, user_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: actor ownership check failed");
                async_graphql::Error::new("Request could not be completed").extend_safe()
            })?;

        if !actor_exists {
            return Err(async_graphql::Error::new("Actor not found").extend_safe());
        }

        let rows = workflow_repo
            .list_workflows_for_actor_scoped(uow.conn(), actor_id, user_id, limit_val)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: actor workflows read failed");
                async_graphql::Error::new("Request could not be completed").extend_safe()
            })?;
        uow.commit().await.map_err(|e| {
            tracing::error!(error = %e, "graphql: commit transaction error");
            async_graphql::Error::new("Request could not be completed").extend_safe()
        })?;

        Ok(rows
            .into_iter()
            .map(|row| ActorWorkflowItem {
                id: row.id,
                name: row.name,
                status: row.status,
                node_count: row.node_count,
                graph_json: row.graph_json,
                created_at: row.created_at.to_rfc3339(),
                updated_at: row.updated_at.to_rfc3339(),
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
        #[graphql(desc = "Max rows to return (default 1000, max 1000)")] limit: Option<i32>,
    ) -> Result<Vec<ActorMemoryEntry>> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        // MCP-1188: cap at 1000 even if caller passes a larger value.
        // 1000 rows × 64 KiB worst-case value = ~64 MiB per request,
        // which is bounded enough for the controller to absorb under
        // concurrent dashboard loads. Negatives / zero clamp up to 1.
        let limit_val: i64 = i64::from(limit.unwrap_or(1000).clamp(1, 1000));

        // RFC 0005 S3: ownership check + memory read in ONE per-user unit
        // of work (actors are personal), so the actors ownership read gets
        // the RLS backstop. Commit before the (connection-free) per-row
        // decrypt loop below.
        let actor_repo = talos_actor_repository::ActorRepository::new(db_pool.clone());
        let mut uow = talos_db::UnitOfWork::begin_user(db_pool, user_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: tenant scope error");
                async_graphql::Error::new("Request scope error").extend_safe()
            })?;

        // Verify ownership
        let owned = actor_repo
            .actor_owned_by_user_scoped(uow.conn(), actor_id, user_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: actor ownership check failed");
                async_graphql::Error::new("Request could not be completed").extend_safe()
            })?;

        if !owned {
            return Err(
                async_graphql::Error::new("Actor not found or access denied").extend_safe(),
            );
        }

        // Phase B: every row carries ciphertext (value_enc + value_key_id).
        // The canonical talos-memory listing projects the MCP-S2 columns
        // (actor_id, value_format) that AAD-bound decryption requires —
        // the pre-extraction inline SELECT omitted both, so decrypt failed
        // loudly ("must project `actor_id`") for every populated actor.
        let rows = talos_memory::list_memories_with_ciphertext_scoped(
            uow.conn(),
            actor_id,
            memory_type.as_deref(),
            limit_val,
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "graphql: actor memories read failed");
            async_graphql::Error::new("Request could not be completed").extend_safe()
        })?;
        uow.commit().await.map_err(|e| {
            tracing::error!(error = %e, "graphql: commit transaction error");
            async_graphql::Error::new("Request could not be completed").extend_safe()
        })?;

        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            let value = talos_memory::decrypt_memory_list_row(r)
                .await
                .map_err(|e| {
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
                key: r.key.clone(),
                value: value.to_string(),
                memory_type: r.memory_type.clone(),
                expires_at: r.expires_at.map(|d| d.to_rfc3339()),
                updated_at: r.updated_at.to_rfc3339(),
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
        #[graphql(desc = "Max rows to return (default 100, max 1000)")] limit: Option<i32>,
    ) -> Result<Vec<McpAgent>> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        // MCP-1190: clamp 1..=1000, default 100. Per-row size is
        // small (~100 bytes) so 1000 rows = ~100 KiB, bounded.
        let limit_val: i64 = i64::from(limit.unwrap_or(100).clamp(1, 1000));

        let system_repo = talos_system_repo::SystemRepository::new(db_pool.clone());
        let rows = system_repo
            .list_agents_for_user(*user_id, limit_val)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: mcp agents list failed");
                async_graphql::Error::new("Request could not be completed").extend_safe()
            })?;

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
