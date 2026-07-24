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

    /// Per-actor LLM token spend (R2 token ledger) — the daily-ceiling
    /// usage bar plus a trailing-window per-model/provider breakdown.
    /// Read-only visibility surface; mirrors the MCP `get_actor_budget`
    /// tool's `current_usage`/`policy` numbers so the two protocol
    /// surfaces agree. `days` defaults to 7, clamped 1..=90 by the
    /// repository method (mirrors `llm_usage_by_user_window`).
    async fn llm_usage_summary(
        &self,
        ctx: &Context<'_>,
        actor_id: Uuid,
        days: Option<i32>,
    ) -> Result<LlmUsageSummary> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        // RFC 0005 S3: ownership check on a per-user unit of work (actors
        // are personal) so the `actors` RLS policy backstops the app-layer
        // predicate — same shape as actor_executions_summary /
        // actor_workflows_summary above. The llm_usage / budget-policy
        // reads that follow run on the bare pool afterward (llm_usage
        // isn't an RLS-enabled table; ownership is already established).
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
        uow.commit().await.map_err(|e| {
            tracing::error!(error = %e, "graphql: commit transaction error");
            async_graphql::Error::new("Request could not be completed").extend_safe()
        })?;

        let policy = actor_repo
            .get_actor_budget_policy(actor_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: actor budget policy read failed");
                async_graphql::Error::new("Request could not be completed").extend_safe()
            })?;
        let tokens_last_24h = actor_repo
            .sum_llm_tokens_last_24h(actor_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: llm token sum failed");
                async_graphql::Error::new("Request could not be completed").extend_safe()
            })?;
        let by_model = actor_repo
            .llm_usage_by_actor_window(actor_id, days.unwrap_or(7))
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: llm usage window read failed");
                async_graphql::Error::new("Request could not be completed").extend_safe()
            })?;

        Ok(LlmUsageSummary {
            actor_id,
            tokens_last_24h,
            max_llm_tokens_per_day: policy.and_then(|p| p.max_llm_tokens_per_day),
            by_model: by_model
                .into_iter()
                .map(|r| LlmUsageModelRow {
                    provider: r.provider,
                    model: r.model,
                    prompt_tokens: r.prompt_tokens,
                    completion_tokens: r.completion_tokens,
                    calls: r.calls,
                })
                .collect(),
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

    /// Batched sibling of `actorMemories`: one request returns the
    /// memories of MANY owned actors, grouped per actor.
    ///
    /// N+1 this closes: the Briefings page fanned out one
    /// `actorMemories(actorId)` GraphQL round-trip PER actor after
    /// `actors` (1 + N requests, each opening its own tenant-scoped tx
    /// and ownership check). This resolver serves the same data in ONE
    /// request: one per-user unit of work, ONE batched ownership read
    /// (`actor_ids_owned_by_user_scoped`), then ONE batched listing
    /// (`list_memories_with_ciphertext_batched_scoped`, a single
    /// `actor_id = ANY($1)` window-capped scan) on the same
    /// connection/snapshot. The prior residual — a per-actor listing
    /// loop inside this one tx, because a crypto-aware `= ANY($1)` read
    /// had to live in `talos-memory` (all actor_memory access MUST go
    /// through `talos_memory::*`) — is now closed, so the whole page is
    /// two queries (ownership + listing) regardless of actor count.
    ///
    /// Tenancy: ids that are unknown or another tenant's are silently
    /// skipped (no group), so absence is indistinguishable from
    /// non-existence. Duplicated ids collapse to one group.
    async fn actors_memories(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "Actors to read (max 100 ids)")] actor_ids: Vec<Uuid>,
        #[graphql(desc = "Filter by type: working | episodic | semantic | scratchpad")]
        memory_type: Option<String>,
        #[graphql(desc = "Max rows PER ACTOR (default 1000, max 1000)")] limit_per_actor: Option<
            i32,
        >,
    ) -> Result<Vec<ActorMemoryGroup>> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        if actor_ids.is_empty() {
            return Ok(vec![]);
        }
        // Mirror `latestWorkflowExecutions`' explicit arg cap: refuse
        // oversized batches loudly instead of truncating silently.
        if actor_ids.len() > 100 {
            return Err(
                async_graphql::Error::new("actor_ids must contain at most 100 entries")
                    .extend_safe(),
            );
        }

        // MCP-1188 sibling: cap PER-ACTOR rows at 1000 even if the
        // caller passes a larger value; negatives / zero clamp up to 1.
        let limit_val: i64 = i64::from(limit_per_actor.unwrap_or(1000).clamp(1, 1000));

        // RFC 0005 S3: batched ownership check + memory reads in ONE
        // per-user unit of work (actors are personal), so every read
        // gets the RLS backstop on a single snapshot. Commit before the
        // (connection-free) decrypt loop below.
        let actor_repo = talos_actor_repository::ActorRepository::new(db_pool.clone());
        let mut uow = talos_db::UnitOfWork::begin_user(db_pool, user_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: tenant scope error");
                async_graphql::Error::new("Request scope error").extend_safe()
            })?;

        let owned = actor_repo
            .actor_ids_owned_by_user_scoped(uow.conn(), &actor_ids, user_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: batched actor ownership check failed");
                async_graphql::Error::new("Request could not be completed").extend_safe()
            })?;
        let ordered = filter_owned_preserving_order(&actor_ids, &owned);

        // ONE batched, window-capped `actor_id = ANY($1)` scan (the SQL
        // lives in talos-memory — the crypto-aware access path — so this
        // resolver stays raw-sqlx-free, lint check 50). Actors that
        // returned no rows are re-materialized as empty groups below so
        // the output shape matches the pre-batch per-actor loop.
        let flat_rows = talos_memory::list_memories_with_ciphertext_batched_scoped(
            uow.conn(),
            &ordered,
            memory_type.as_deref(),
            limit_val,
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "graphql: batched actor memories read failed");
            async_graphql::Error::new("Request could not be completed").extend_safe()
        })?;
        uow.commit().await.map_err(|e| {
            tracing::error!(error = %e, "graphql: commit transaction error");
            async_graphql::Error::new("Request could not be completed").extend_safe()
        })?;

        let per_actor_rows = talos_memory::group_memory_list_rows_by_actor(&ordered, flat_rows);

        let mut groups = Vec::with_capacity(per_actor_rows.len());
        for (actor_id, rows) in per_actor_rows {
            let mut memories = Vec::with_capacity(rows.len());
            for r in &rows {
                let value = talos_memory::decrypt_memory_list_row(r)
                    .await
                    .map_err(|e| {
                        // Same redaction contract as `actorMemories`: the
                        // chain may include KEK provider URLs, transit-key
                        // names, DEK UUIDs, and aead::Error — server
                        // internals that must not cross the GraphQL
                        // boundary.
                        tracing::error!(
                            actor_id = %actor_id,
                            "actors_memories: row decrypt failed: {:#}",
                            e
                        );
                        async_graphql::Error::new("Failed to decrypt actor memory").extend_safe()
                    })?;
                memories.push(ActorMemoryEntry {
                    key: r.key.clone(),
                    value: value.to_string(),
                    memory_type: r.memory_type.clone(),
                    expires_at: r.expires_at.map(|d| d.to_rfc3339()),
                    updated_at: r.updated_at.to_rfc3339(),
                });
            }
            groups.push(ActorMemoryGroup { actor_id, memories });
        }
        Ok(groups)
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

/// Tenancy + shape filter for the batched `actorsMemories` read: keep
/// only requested ids that survived the batched ownership check, in the
/// caller's original order, with duplicates collapsed to their first
/// occurrence. Pure so the unit tests below exercise the exact
/// production logic (see the "unit tests exercise real production code"
/// testing convention).
fn filter_owned_preserving_order(requested: &[Uuid], owned: &[Uuid]) -> Vec<Uuid> {
    let owned_set: std::collections::HashSet<Uuid> = owned.iter().copied().collect();
    let mut seen = std::collections::HashSet::new();
    requested
        .iter()
        .copied()
        .filter(|id| owned_set.contains(id) && seen.insert(*id))
        .collect()
}

#[cfg(test)]
mod actors_memories_tests {
    use super::filter_owned_preserving_order;
    use uuid::Uuid;

    fn ids(n: usize) -> Vec<Uuid> {
        (0..n).map(|_| Uuid::new_v4()).collect()
    }

    #[test]
    fn non_owned_ids_are_silently_dropped() {
        let all = ids(3);
        let owned = vec![all[0], all[2]];
        assert_eq!(
            filter_owned_preserving_order(&all, &owned),
            vec![all[0], all[2]],
            "the id missing from the ownership result must produce no group — \
             a cross-tenant or unknown id is indistinguishable from absence"
        );
    }

    #[test]
    fn caller_order_is_preserved_regardless_of_ownership_result_order() {
        let all = ids(3);
        // Ownership check returns rows in arbitrary (DB) order.
        let owned = vec![all[2], all[0], all[1]];
        assert_eq!(filter_owned_preserving_order(&all, &owned), all);
    }

    #[test]
    fn duplicate_ids_collapse_to_first_occurrence() {
        let all = ids(2);
        let requested = vec![all[0], all[1], all[0], all[1], all[0]];
        assert_eq!(
            filter_owned_preserving_order(&requested, &all),
            vec![all[0], all[1]],
            "duplicated ids must not multiply the per-actor listing work"
        );
    }

    #[test]
    fn empty_ownership_result_yields_no_groups() {
        let all = ids(2);
        assert!(filter_owned_preserving_order(&all, &[]).is_empty());
    }
}
