use async_graphql::{Context, Result};
use std::sync::Arc;
use uuid::Uuid;

use crate::schema::types::*;
use crate::schema::{
    compute_graph_diff, require_scope, user_accessible_org_ids, SafeErrorExtensions,
};
use talos_compilation::CompilationService;
use talos_workflow_versions::WorkflowVersionService;

#[derive(Default)]
pub struct WorkflowsQueries;

#[async_graphql::Object]
impl WorkflowsQueries {
    async fn latest_workflow_executions(
        &self,
        ctx: &Context<'_>,
        workflow_ids: Vec<Uuid>,
    ) -> Result<Vec<WorkflowExecution>> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;

        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        if workflow_ids.is_empty() {
            return Ok(vec![]);
        }

        if workflow_ids.len() > 200 {
            return Err(
                async_graphql::Error::new("workflow_ids must contain at most 200 entries")
                    .extend_safe(),
            );
        }

        let org_ids: Vec<uuid::Uuid> = user_accessible_org_ids(ctx).await?;

        // RFC 0004/0005 S2: run on a tenant-scoped tx so the
        // workflow_executions RLS policy backstops the app-layer
        // ownership/org filter. The scope carries the same (user,
        // accessible orgs) the WHERE clause uses; the policy mirrors the
        // `we.user_id = $2 OR w.org_id = ANY(...)` predicate (EXISTS on
        // the parent workflow's org — see the migration for why we.org_id
        // is not the tenant key here). The repo method executes on the tx
        // we pass.
        let exec_repo = talos_execution_repository::ExecutionRepository::new(db_pool.clone());
        let scope = talos_tenancy::TenantReadScope::new(user_id, org_ids);
        let mut tx = talos_db::begin_tenant_read_scoped(db_pool, &scope)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: tenant scope error");
                async_graphql::Error::new("Request scope error").extend_safe()
            })?;
        let rows = exec_repo
            .list_latest_executions_for_workflows_scoped(
                &mut tx,
                &workflow_ids,
                user_id,
                &scope.accessible_org_ids,
            )
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: latest executions read failed");
                async_graphql::Error::new("Request could not be completed").extend_safe()
            })?;
        tx.commit()
            .await
            .map_err(|e: sqlx::Error| e.extend_safe())?;

        Ok(rows
            .into_iter()
            .map(|r| WorkflowExecution {
                id: r.id,
                workflow_id: r.workflow_id,
                status: r.status,
                started_at: r.started_at.to_rfc3339(),
                completed_at: r
                    .completed_at
                    .map(|d: chrono::DateTime<chrono::Utc>| d.to_rfc3339()),
                error_message: r.error_message,
                created_at: r.created_at.to_rfc3339(),
                duration_ms: None,
                output_data: None,
                trigger_type: None,
                actor_id: None,
            })
            .collect())
    }

    async fn workflow_execution_history(
        &self,
        ctx: &Context<'_>,
        workflow_id: Uuid,
        pagination: Option<PaginationInput>,
    ) -> Result<Vec<WorkflowExecution>> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;

        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        // MCP-811 (2026-05-14): clamp(1, 1000) not min(1000). Caller
        // `Some(-1)` propagates to Postgres LIMIT -1 → 500. Sibling
        // fix class to MCP-767.
        let limit_val = pagination
            .as_ref()
            .and_then(|p| p.limit)
            .unwrap_or(50)
            .clamp(1, 1000) as i64;
        let offset_val = pagination
            .as_ref()
            .and_then(|p| p.offset)
            .unwrap_or(0)
            .max(0) as i64;

        let org_ids: Vec<uuid::Uuid> = user_accessible_org_ids(ctx).await?;

        // N T6-N2 note: `latest_workflow_executions` above uses
        // `DISTINCT ON (we.workflow_id)` because it semantically wants
        // "one row per workflow"; the history read intentionally omits
        // DISTINCT (every execution IS a distinct audit event). The
        // trigger_type projection backstory lives on the repo method
        // (`list_execution_history_scoped`).
        // RFC 0004/0005 S2: tenant-scoped tx → workflow_executions RLS
        // backstops the app-layer ownership/org filter (see sibling
        // resolver above + the migration). The repo method executes on
        // the tx we pass.
        let exec_repo = talos_execution_repository::ExecutionRepository::new(db_pool.clone());
        let scope = talos_tenancy::TenantReadScope::new(user_id, org_ids);
        let mut tx = talos_db::begin_tenant_read_scoped(db_pool, &scope)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: tenant scope error");
                async_graphql::Error::new("Request scope error").extend_safe()
            })?;
        let rows = exec_repo
            .list_execution_history_scoped(
                &mut tx,
                workflow_id,
                user_id,
                &scope.accessible_org_ids,
                limit_val,
                offset_val,
            )
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: execution history read failed");
                async_graphql::Error::new("Request could not be completed").extend_safe()
            })?;
        tx.commit()
            .await
            .map_err(|e: sqlx::Error| e.extend_safe())?;

        Ok(rows
            .into_iter()
            .map(|r| {
                // MCP-960 (2026-05-15): saturate to i32 instead of
                // wrapping. Pre-fix `num_milliseconds() as i32`
                // truncated silently — an execution running longer
                // than 2^31 ms (~24.8 days) wrapped into a wrong (often
                // negative) duration that the UI would render as
                // garbage. Also defends against negative durations
                // from completed_at < started_at clock-skew rows by
                // clamping to 0. The GraphQL schema field is i32 so
                // changing the type would be a wider breaking change;
                // saturating preserves the schema contract while
                // making the value truthful at the extremes. Sibling
                // sites in MCP handlers either already `.max(0)` or
                // use `i64`; this was the only unscoped `as i32`.
                let duration_ms = r.completed_at.map(|completed| {
                    let ms_i64 = (completed - r.started_at).num_milliseconds().max(0);
                    i32::try_from(ms_i64).unwrap_or(i32::MAX)
                });

                WorkflowExecution {
                    id: r.id,
                    workflow_id: r.workflow_id,
                    status: r.status,
                    started_at: r.started_at.to_rfc3339(),
                    completed_at: r
                        .completed_at
                        .map(|d: chrono::DateTime<chrono::Utc>| d.to_rfc3339()),
                    error_message: r.error_message,
                    created_at: r.created_at.to_rfc3339(),
                    duration_ms,
                    output_data: r.output_data,
                    trigger_type: r.trigger_type,
                    actor_id: r.actor_id,
                }
            })
            .collect())
    }

    async fn workflow(&self, ctx: &Context<'_>, id: Uuid) -> Result<Workflow> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;

        let db_pool = ctx
            .data::<sqlx::Pool<sqlx::Postgres>>()
            .map_err(|e| e.extend_safe())?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;

        let org_ids: Vec<uuid::Uuid> = user_accessible_org_ids(ctx).await?;

        // RFC 0004 M4: run on a tenant-scoped tx so the workflows RLS
        // policy backstops the app-layer ownership/org filter. The scope
        // carries the same (user, accessible orgs) the WHERE clause uses.
        // The repo method executes on the tx we pass.
        let workflow_repo = talos_workflow_repository::WorkflowRepository::new(db_pool.clone());
        let scope = talos_tenancy::TenantReadScope::new(*user_id, org_ids);
        let mut tx = talos_db::begin_tenant_read_scoped(db_pool, &scope)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: tenant scope error");
                async_graphql::Error::new("Request scope error").extend_safe()
            })?;
        let found = workflow_repo
            .get_workflow_for_accessor_scoped(&mut tx, id, *user_id, &scope.accessible_org_ids)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: workflow read failed");
                async_graphql::Error::new("Request could not be completed").extend_safe()
            })?;
        tx.commit()
            .await
            .map_err(|e: sqlx::Error| e.extend_safe())?;
        let workflow = found.ok_or_else(|| {
            async_graphql::Error::new("Workflow not found or access denied").extend_safe()
        })?;

        Ok(Workflow {
            id: workflow.id,
            name: workflow.name,
            graph_json: workflow.graph_json,
            max_concurrent_executions: workflow.max_concurrent_executions,
            intent: workflow.intent,
            actor_id: workflow.actor_id,
        })
    }

    async fn workflows(
        &self,
        ctx: &Context<'_>,
        pagination: Option<PaginationInput>,
    ) -> Result<Vec<Workflow>> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;

        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        // MCP-811 (2026-05-14): clamp(1, 1000) not min(1000) — see
        // workflow_executions above for the rationale.
        let limit_val = pagination
            .as_ref()
            .and_then(|p| p.limit)
            .unwrap_or(100)
            .clamp(1, 1000) as i64;
        let offset_val = pagination
            .as_ref()
            .and_then(|p| p.offset)
            .unwrap_or(0)
            .max(0) as i64;

        let org_ids: Vec<uuid::Uuid> = user_accessible_org_ids(ctx).await?;

        // RFC 0004 M4: scoped tx so the workflows RLS policy backstops the
        // app-layer union filter. The repo method executes on the tx we pass.
        let workflow_repo = talos_workflow_repository::WorkflowRepository::new(db_pool.clone());
        let scope = talos_tenancy::TenantReadScope::new(*user_id, org_ids);
        let mut tx = talos_db::begin_tenant_read_scoped(db_pool, &scope)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: tenant scope error");
                async_graphql::Error::new("Request scope error").extend_safe()
            })?;
        let workflows = workflow_repo
            .list_workflows_for_accessor_scoped(
                &mut tx,
                *user_id,
                &scope.accessible_org_ids,
                limit_val,
                offset_val,
            )
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: workflows list failed");
                async_graphql::Error::new("Request could not be completed").extend_safe()
            })?;
        tx.commit()
            .await
            .map_err(|e: sqlx::Error| e.extend_safe())?;

        Ok(workflows
            .into_iter()
            .map(|w| Workflow {
                id: w.id,
                name: w.name,
                graph_json: w.graph_json,
                max_concurrent_executions: w.max_concurrent_executions,
                intent: w.intent,
                actor_id: w.actor_id,
            })
            .collect())
    }

    async fn analyze_rhai(
        &self,
        ctx: &Context<'_>,
        input: AnalyzeRhaiInput,
    ) -> Result<AnalyzeCustomModuleResult> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;

        let compiler = ctx.data::<Arc<CompilationService>>()?;

        if input.script.len() > 100_000 {
            return Err(async_graphql::Error::new("Script exceeds 100 KB limit").extend_safe());
        }
        let raw_errors = compiler
            .analyze_code("rhai_analysis", &input.script)
            .await?;

        let errors = raw_errors
            .into_iter()
            .map(|e| CompilationErrorObj {
                line: e.line,
                column: e.column,
                end_line: e.end_line,
                end_column: e.end_column,
                message: e.message,
                severity: e.severity,
            })
            .collect::<Vec<_>>();

        Ok(AnalyzeCustomModuleResult {
            success: errors.is_empty(),
            errors,
        })
    }

    async fn test_rhai_expression(
        &self,
        ctx: &Context<'_>,
        input: TestRhaiExpressionInput,
    ) -> Result<TestRhaiExpressionResult> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;

        const MAX_RHAI_SCRIPT_BYTES: usize = 100_000; // 100 KB
        const MAX_RHAI_CONTEXT_BYTES: usize = 1_000_000; // 1 MB
        if input.script.len() > MAX_RHAI_SCRIPT_BYTES {
            return Err(async_graphql::Error::new("Script exceeds 100 KB limit").extend_safe());
        }
        if input.mock_context.len() > MAX_RHAI_CONTEXT_BYTES {
            return Err(async_graphql::Error::new("Mock context exceeds 1 MB limit").extend_safe());
        }

        let mock_context: serde_json::Value =
            serde_json::from_str(&input.mock_context).map_err(|e: serde_json::Error| {
                async_graphql::Error::new(format!("Invalid mock context JSON: {}", e))
            })?;

        let mut engine = rhai::Engine::new();
        engine.set_max_operations(1000);
        engine.set_max_array_size(500);
        engine.set_max_call_levels(16);
        engine.set_max_string_size(65536);
        engine.disable_symbol("eval");
        engine.set_module_resolver(rhai::module_resolvers::DummyModuleResolver);

        let mut scope = rhai::Scope::new();

        // Map JSON fields into script scope
        if let serde_json::Value::Object(map) = &mock_context {
            for (key, val) in map {
                if let Ok(dynamic) = rhai::serde::to_dynamic(val) {
                    scope.push_dynamic(key, dynamic);
                }
            }
        }

        if let Ok(ctx_dynamic) = rhai::serde::to_dynamic(&mock_context) {
            scope.push_dynamic("ctx", ctx_dynamic.clone());
            scope.push_dynamic("inputs", ctx_dynamic);
        }

        match engine.eval_with_scope::<rhai::Dynamic>(&mut scope, &input.script) {
            Ok(result) => {
                let json_result: serde_json::Value =
                    rhai::serde::from_dynamic(&result).unwrap_or(serde_json::Value::Null);
                Ok(TestRhaiExpressionResult {
                    success: true,
                    output: Some(json_result.to_string()),
                    error: None,
                })
            }
            Err(e) => Ok(TestRhaiExpressionResult {
                success: false,
                output: None,
                error: Some(e.to_string()),
            }),
        }
    }

    async fn workflow_versions(
        &self,
        ctx: &Context<'_>,
        workflow_id: Uuid,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<Vec<WorkflowVersion>> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;

        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        // RFC 0005 S3: the ownership check + the versions read share ONE
        // request-scoped unit of work (one tenant-scoped tx + snapshot,
        // role/GUC set once, RLS backstop on both). `user_accessible_org_ids`
        // sources the scope so it necessarily precedes the tx.
        let org_ids: Vec<uuid::Uuid> = user_accessible_org_ids(ctx).await?;
        let scope = talos_tenancy::TenantReadScope::new(user_id, org_ids);
        let mut uow = talos_db::UnitOfWork::begin(db_pool, &scope)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: tenant scope error");
                async_graphql::Error::new("Request scope error").extend_safe()
            })?;

        let owns = crate::access_check::workflow_accessible_for_user_on_conn(
            uow.conn(),
            workflow_id,
            user_id,
            &scope.accessible_org_ids,
        )
        .await
        .map_err(|e: sqlx::Error| e.extend_safe())?;

        if !owns {
            return Err(
                async_graphql::Error::new("Workflow not found or access denied").extend_safe(),
            );
        }

        let limit_val = limit.unwrap_or(50).clamp(1, 1000) as i64;
        let offset_val = offset.unwrap_or(0).max(0) as i64;

        let versions = WorkflowVersionService::list_versions_on_conn(
            uow.conn(),
            workflow_id,
            limit_val,
            offset_val,
        )
        .await
        .map_err(|e: anyhow::Error| {
            tracing::error!("Failed to list workflow versions: {}", e);
            async_graphql::Error::new("Failed to list workflow versions").extend_safe()
        })?;
        uow.commit().await.map_err(|e| {
            tracing::error!(error = %e, "graphql: commit transaction error");
            async_graphql::Error::new("Request could not be completed").extend_safe()
        })?;

        Ok(versions.into_iter().map(Into::into).collect())
    }

    async fn workflow_version(
        &self,
        ctx: &Context<'_>,
        id: Uuid,
    ) -> Result<Option<WorkflowVersion>> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;

        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;
        let org_ids: Vec<uuid::Uuid> = user_accessible_org_ids(ctx).await?;

        // SECURITY: Join through workflows to enforce ownership check.
        // Without this, any authenticated user could read any workflow version by ID.
        // RFC 0005 S3: run on a tenant-scoped tx so the workflows RLS
        // policy backstops the join — workflow_versions has no policy of
        // its own, so this scoping is the only RLS protection a version
        // read gets (if RLS hides the parent workflow, the join yields
        // nothing).
        let scope = talos_tenancy::TenantReadScope::new(user_id, org_ids);
        let mut tx = talos_db::begin_tenant_read_scoped(db_pool, &scope)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: tenant scope error");
                async_graphql::Error::new("Request scope error").extend_safe()
            })?;
        let version = WorkflowVersionService::get_version_for_accessor_on_conn(
            &mut tx,
            id,
            user_id,
            &scope.accessible_org_ids,
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "graphql: workflow version read failed");
            async_graphql::Error::new("Request could not be completed").extend_safe()
        })?;
        tx.commit()
            .await
            .map_err(|e: sqlx::Error| e.extend_safe())?;

        Ok(version.map(|v| v.into()))
    }

    async fn active_workflow_version(
        &self,
        ctx: &Context<'_>,
        workflow_id: Uuid,
    ) -> Result<Option<WorkflowVersion>> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;

        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        // RFC 0005 S3: ownership check + active-version read in ONE
        // request-scoped unit of work (see workflow_versions above).
        let org_ids: Vec<uuid::Uuid> = user_accessible_org_ids(ctx).await?;
        let scope = talos_tenancy::TenantReadScope::new(user_id, org_ids);
        let mut uow = talos_db::UnitOfWork::begin(db_pool, &scope)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: tenant scope error");
                async_graphql::Error::new("Request scope error").extend_safe()
            })?;

        let owns = crate::access_check::workflow_accessible_for_user_on_conn(
            uow.conn(),
            workflow_id,
            user_id,
            &scope.accessible_org_ids,
        )
        .await
        .map_err(|e: sqlx::Error| e.extend_safe())?;

        if !owns {
            return Err(
                async_graphql::Error::new("Workflow not found or access denied").extend_safe(),
            );
        }

        let version: Option<talos_workflow_versions::WorkflowVersion> =
            WorkflowVersionService::get_active_version_on_conn(uow.conn(), workflow_id)
                .await
                .map_err(|e: anyhow::Error| {
                    tracing::error!("Failed to get active workflow version: {}", e);
                    async_graphql::Error::new("Failed to get active workflow version").extend_safe()
                })?;
        uow.commit().await.map_err(|e| {
            tracing::error!(error = %e, "graphql: commit transaction error");
            async_graphql::Error::new("Request could not be completed").extend_safe()
        })?;

        Ok(version.map(Into::into))
    }

    async fn workflow_schedule(
        &self,
        ctx: &Context<'_>,
        workflow_id: Uuid,
    ) -> Result<Option<WorkflowScheduleObj>> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;

        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        let org_ids: Vec<uuid::Uuid> = user_accessible_org_ids(ctx).await?;

        // RFC 0005 S3: tenant-scoped tx so the workflows RLS policy
        // backstops the join (workflow_schedules has no policy of its own;
        // an org-shared schedule is reachable via the parent workflow's
        // org, the `ws.user_id` clause covers the personal case).
        let scope = talos_tenancy::TenantReadScope::new(user_id, org_ids);
        let mut tx = talos_db::begin_tenant_read_scoped(db_pool, &scope)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: tenant scope error");
                async_graphql::Error::new("Request scope error").extend_safe()
            })?;
        let row = talos_scheduler::get_schedule_for_accessor_on_conn(
            &mut tx,
            workflow_id,
            user_id,
            &scope.accessible_org_ids,
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "graphql: workflow schedule read failed");
            async_graphql::Error::new("Request could not be completed").extend_safe()
        })?;
        tx.commit()
            .await
            .map_err(|e: sqlx::Error| e.extend_safe())?;

        Ok(row.map(|s| WorkflowScheduleObj {
            id: s.id,
            workflow_id: s.workflow_id,
            cron_expression: s.cron_expression,
            timezone: s.timezone,
            is_enabled: s.is_enabled,
            last_triggered_at: s.last_triggered_at.map(|d| d.to_rfc3339()),
            next_trigger_at: s.next_trigger_at.map(|d| d.to_rfc3339()),
            created_at: s.created_at.to_rfc3339(),
            updated_at: s.updated_at.to_rfc3339(),
        }))
    }

    async fn my_schedules(
        &self,
        ctx: &Context<'_>,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<Vec<WorkflowScheduleObj>> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;

        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        let limit_val = limit.unwrap_or(100).clamp(1, 1000) as i64;
        let offset_val = offset.unwrap_or(0).max(0) as i64;

        let rows =
            talos_scheduler::list_schedules_for_user(db_pool, user_id, limit_val, offset_val)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "graphql: schedules list failed");
                    async_graphql::Error::new("Request could not be completed").extend_safe()
                })?;

        Ok(rows
            .into_iter()
            .map(|s| WorkflowScheduleObj {
                id: s.id,
                workflow_id: s.workflow_id,
                cron_expression: s.cron_expression,
                timezone: s.timezone,
                is_enabled: s.is_enabled,
                last_triggered_at: s.last_triggered_at.map(|d| d.to_rfc3339()),
                next_trigger_at: s.next_trigger_at.map(|d| d.to_rfc3339()),
                created_at: s.created_at.to_rfc3339(),
                updated_at: s.updated_at.to_rfc3339(),
            })
            .collect())
    }

    // ── Organization queries ───────────────────────────────────────────

    async fn get_all_workflow_stats(
        &self,
        ctx: &Context<'_>,
        days: Option<i32>,
    ) -> Result<Vec<WorkflowStats>> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;

        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        let days_val = days.unwrap_or(7).clamp(1, 90);

        // RFC 0005 S3: per-user tenant-scoped tx so the workflows +
        // workflow_executions RLS policies backstop this user-only stats
        // read (both tables are RLS-enabled; the query filters w.user_id).
        // The repo method executes on the tx we pass.
        let workflow_repo = talos_workflow_repository::WorkflowRepository::new(db_pool.clone());
        let mut tx = talos_db::begin_user_scoped(db_pool, user_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: tenant scope error");
                async_graphql::Error::new("Request scope error").extend_safe()
            })?;
        let rows = workflow_repo
            .get_all_workflow_stats_scoped(&mut tx, user_id, days_val)
            .await
            .map_err(|e| {
                tracing::error!("Failed to fetch workflow stats: {}", e);
                async_graphql::Error::new("Failed to fetch workflow stats").extend_safe()
            })?;
        tx.commit().await.map_err(|e| {
            tracing::error!(error = %e, "graphql: commit transaction error");
            async_graphql::Error::new("Request could not be completed").extend_safe()
        })?;

        Ok(rows
            .into_iter()
            .map(|r| WorkflowStats {
                id: r.id,
                name: r.name,
                total: r.total,
                succeeded: r.succeeded,
                failed: r.failed,
                avg_duration_secs: r.avg_duration_secs,
            })
            .collect())
    }

    async fn get_version_diff_summary(
        &self,
        ctx: &Context<'_>,
        workflow_id: Uuid,
    ) -> Result<VersionDiffSummary> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;

        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        // RFC 0005 S3: the ownership read (workflows.graph_json doubles as
        // the access check) + the published-version read share ONE
        // request-scoped unit of work — consistent snapshot, both RLS
        // tables backstopped. user_accessible_org_ids sources the scope.
        let org_ids: Vec<uuid::Uuid> = user_accessible_org_ids(ctx).await?;
        let scope = talos_tenancy::TenantReadScope::new(user_id, org_ids);
        let mut uow = talos_db::UnitOfWork::begin(db_pool, &scope)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: tenant scope error");
                async_graphql::Error::new("Request scope error").extend_safe()
            })?;

        let workflow_repo = talos_workflow_repository::WorkflowRepository::new(db_pool.clone());
        let draft_json = workflow_repo
            .get_graph_json_for_accessor_scoped(
                uow.conn(),
                workflow_id,
                user_id,
                &scope.accessible_org_ids,
            )
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: workflow graph read failed");
                async_graphql::Error::new("Request could not be completed").extend_safe()
            })?;

        let draft_json = draft_json.ok_or_else(|| {
            async_graphql::Error::new("Workflow not found or access denied").extend_safe()
        })?;

        // Get active published version
        let published_json =
            WorkflowVersionService::get_active_graph_json_on_conn(uow.conn(), workflow_id)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "graphql: active version read failed");
                    async_graphql::Error::new("Request could not be completed").extend_safe()
                })?;
        uow.commit().await.map_err(|e| {
            tracing::error!(error = %e, "graphql: commit transaction error");
            async_graphql::Error::new("Request could not be completed").extend_safe()
        })?;

        let published_json = match published_json {
            Some(pj) => pj,
            None => {
                return Ok(VersionDiffSummary {
                    summary: "No published version — all changes are new".to_string(),
                    nodes_added: 0,
                    nodes_removed: 0,
                    nodes_changed: 0,
                    edges_added: 0,
                    edges_removed: 0,
                    has_published_version: false,
                });
            }
        };

        let diff = compute_graph_diff(&published_json, &draft_json);
        let mut parts = Vec::new();
        if diff.nodes_added > 0 {
            parts.push(format!("{} node(s) added", diff.nodes_added));
        }
        if diff.nodes_removed > 0 {
            parts.push(format!("{} node(s) removed", diff.nodes_removed));
        }
        if diff.nodes_changed > 0 {
            parts.push(format!("{} node(s) changed", diff.nodes_changed));
        }
        if diff.edges_added > 0 {
            parts.push(format!("{} edge(s) added", diff.edges_added));
        }
        if diff.edges_removed > 0 {
            parts.push(format!("{} edge(s) removed", diff.edges_removed));
        }
        let summary = if parts.is_empty() {
            "No changes from published version".to_string()
        } else {
            parts.join(", ")
        };

        Ok(VersionDiffSummary {
            summary,
            nodes_added: diff.nodes_added,
            nodes_removed: diff.nodes_removed,
            nodes_changed: diff.nodes_changed,
            edges_added: diff.edges_added,
            edges_removed: diff.edges_removed,
            has_published_version: true,
        })
    }

    async fn get_workflow_changelog(
        &self,
        ctx: &Context<'_>,
        workflow_id: Uuid,
        limit: Option<i32>,
    ) -> Result<Vec<ChangelogEntry>> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;

        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        let limit_val = limit.unwrap_or(10).clamp(1, 100) as i64;

        // RFC 0005 S3: ownership check + versions read in ONE request-scoped
        // unit of work (mirrors workflow_versions). user_accessible_org_ids
        // sources the scope.
        let org_ids: Vec<uuid::Uuid> = user_accessible_org_ids(ctx).await?;
        let scope = talos_tenancy::TenantReadScope::new(user_id, org_ids);
        let mut uow = talos_db::UnitOfWork::begin(db_pool, &scope)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: tenant scope error");
                async_graphql::Error::new("Request scope error").extend_safe()
            })?;

        let owns = crate::access_check::workflow_accessible_for_user_on_conn(
            uow.conn(),
            workflow_id,
            user_id,
            &scope.accessible_org_ids,
        )
        .await
        .map_err(|e: sqlx::Error| e.extend_safe())?;

        if !owns {
            return Err(
                async_graphql::Error::new("Workflow not found or access denied").extend_safe(),
            );
        }

        // Fetch one extra version so we can diff the oldest requested version against its predecessor
        let versions = WorkflowVersionService::list_versions_on_conn(
            uow.conn(),
            workflow_id,
            limit_val + 1,
            0,
        )
        .await
        .map_err(|e: anyhow::Error| {
            tracing::error!("Failed to list workflow versions: {}", e);
            async_graphql::Error::new("Failed to list workflow versions").extend_safe()
        })?;
        uow.commit().await.map_err(|e| {
            tracing::error!(error = %e, "graphql: commit transaction error");
            async_graphql::Error::new("Request could not be completed").extend_safe()
        })?;

        let mut entries = Vec::new();
        for (i, version) in versions.iter().enumerate() {
            if i as i64 >= limit_val {
                break;
            }

            let summary = if version.version_number == 1 {
                "Initial version".to_string()
            } else if let Some(prev) = versions.get(i + 1) {
                let diff = compute_graph_diff(
                    &prev.graph_json.to_string(),
                    &version.graph_json.to_string(),
                );
                let mut parts = Vec::new();
                if diff.nodes_added > 0 {
                    parts.push(format!("Added {} node(s)", diff.nodes_added));
                }
                if diff.nodes_removed > 0 {
                    parts.push(format!("Removed {} node(s)", diff.nodes_removed));
                }
                if diff.nodes_changed > 0 {
                    parts.push(format!("Changed {} node(s)", diff.nodes_changed));
                }
                if diff.edges_added > 0 {
                    parts.push(format!("Added {} edge(s)", diff.edges_added));
                }
                if diff.edges_removed > 0 {
                    parts.push(format!("Removed {} edge(s)", diff.edges_removed));
                }
                if parts.is_empty() {
                    "No structural changes".to_string()
                } else {
                    parts.join(", ")
                }
            } else {
                // No previous version available for diff
                "Changes unknown (predecessor not loaded)".to_string()
            };

            entries.push(ChangelogEntry {
                version_number: version.version_number,
                published_at: version.published_at.to_rfc3339(),
                description: version.description.clone(),
                summary,
            });
        }

        Ok(entries)
    }

    /// MCP-1190 (2026-05-17): `limit` arg added with default 20 and
    /// hard cap of 100, matching the canonical MCP sibling at
    /// `handle_list_pending_approvals` (executions.rs:6063) which has
    /// enforced 1..=100 since MCP-179. Pre-fix this GraphQL query did
    /// `fetch_all` with NO LIMIT — a user with a misconfigured
    /// approval workflow accumulating thousands of pending gates would
    /// get a huge response on every dashboard `pendingApprovals` call;
    /// repeated polls trash controller heap. Same cross-protocol
    /// GraphQL-must-mirror-MCP class as MCP-1188/1189.
    async fn pending_approvals(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "Max rows to return (default 20, max 100)")] limit: Option<i32>,
    ) -> Result<Vec<ExecutionApproval>> {
        // MCP-757 (2026-05-13): the sole query in this file missing
        // `require_scope(WorkflowsRead)`. Every sibling query (14 of them
        // — latest_workflow_executions through get_workflow_changelog)
        // gates on the same scope; pending_approvals drifted at some
        // earlier point. Sessions bypass scope checks (per
        // require_scope_session_bypass.md memory note) so dashboard
        // users are unaffected, but an API key issued WITHOUT
        // WorkflowsRead — e.g. a Memory-scoped or Webhooks-scoped key —
        // could call pending_approvals and read workflow-internal
        // execution metadata (workflow_id, execution_id, node_id,
        // required_for, reason) for the owning user's pending
        // approvals. Same per-file scope-drift class that MCP-292
        // closed for actor-ceiling enforcement; the SQL filter
        // `WHERE w.user_id = $1` bounds blast radius but the scope
        // gate is the documented API contract.
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;

        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        // MCP-1190: clamp 1..=100 matching MCP canonical, default 20.
        let limit_val: i64 = i64::from(limit.unwrap_or(20).clamp(1, 100));

        // RFC 0005 S3: per-user tenant-scoped tx so the workflows RLS
        // policy backstops the ownership JOIN (execution_approvals has no
        // policy of its own; the gate is `w.user_id = $1` on the joined
        // workflow). The repo method executes on the tx we pass.
        let exec_repo = talos_execution_repository::ExecutionRepository::new(db_pool.clone());
        let mut tx = talos_db::begin_user_scoped(db_pool, user_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: tenant scope error");
                async_graphql::Error::new("Request scope error").extend_safe()
            })?;
        let rows = exec_repo
            .list_pending_approvals_scoped(&mut tx, user_id, limit_val)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: pending approvals read failed");
                async_graphql::Error::new("Request could not be completed").extend_safe()
            })?;
        tx.commit().await.map_err(|e| {
            tracing::error!(error = %e, "graphql: commit transaction error");
            async_graphql::Error::new("Request could not be completed").extend_safe()
        })?;

        Ok(rows
            .into_iter()
            .map(|row| ExecutionApproval {
                id: row.id,
                workflow_id: row.workflow_id,
                execution_id: row.execution_id,
                node_id: row.node_id,
                required_for: row.required_for,
                status: row.status,
                requested_at: row.requested_at.to_rfc3339(),
                decided_at: row.decided_at.map(|t| t.to_rfc3339()),
                decided_by: row.decided_by,
                reason: row.reason,
            })
            .collect())
    }
}
