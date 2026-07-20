use async_graphql::{Context, Result};
use chrono::Utc;
use std::sync::Arc;
// MCP-853 (2026-05-14): `tracing::info` removed; the only previous user
// was the per-event debug log in the trigger_workflow `store_and_send!`
// macro which leaked log_message via Debug format. Surrounding code uses
// the qualified `tracing::info!` path where structured logging is needed.
use uuid::Uuid;

use crate::schema::types::*;
use crate::schema::{
    require_2fa, require_scope, sync_workflow_module_refs, validate_max_concurrent_executions,
    validate_payload_size, validate_resource_name, SafeErrorExtensions,
};
use talos_engine::events::{ExecutionEvent, ExecutionStatus};
use talos_registry::ModuleRegistry;
use talos_workflow_engine_core::WorkerSharedKey;
use talos_workflow_versions::WorkflowVersionService;

#[derive(Default)]
pub struct WorkflowsMutations;

#[async_graphql::Object]
impl WorkflowsMutations {
    async fn trigger_workflow(
        &self,
        ctx: &Context<'_>,
        workflow_id: Uuid,
        #[graphql(
            desc = "Optional actor to run as. When set, the execution is tagged with this actor's ID and the actor's budget is enforced."
        )]
        actor_id: Option<Uuid>,
    ) -> Result<WorkflowExecution> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsWrite)?;

        // Get authenticated user
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;

        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?.clone();

        // Triggering a workflow is a write — it consumes LLM/fuel budget,
        // may write to actor memory, fires external HTTP calls. A Viewer
        // must not be able to trigger an org-shared workflow.
        let org_ids = crate::schema::user_writable_org_ids(ctx).await?;
        let workflow_exists = crate::access_check::workflow_accessible_for_user(
            &db_pool,
            workflow_id,
            *user_id,
            &org_ids,
        )
        .await
        .map_err(|e: sqlx::Error| {
            tracing::error!("Failed to fetch workflow: {}", e);
            async_graphql::Error::new("Failed to check workflow").extend_safe()
        })?;

        if !workflow_exists {
            // MCP-918: .extend_safe() — lowercase "not found" doesn't
            // match the case-sensitive scrubber whitelist "Not found".
            return Err(
                async_graphql::Error::new("Workflow not found or access denied").extend_safe(),
            );
        }

        // Cross-protocol unification (2026-07-01): route through the shared
        // ExecutionOrchestrationService — the SAME Arc the MCP
        // trigger_workflow handler consumes — instead of the ~690-line
        // inline reimplementation this resolver carried since before r295.
        // The inline copy was kept in sync with the MCP path by comments
        // (r292, MCP-853, MCP-916, MCP-918 were all drift fixes); the
        // service makes the parity load-bearing. What the service adds
        // that the inline path lacked: platform-pause gate, is_enabled
        // check, input-schema validation, actor-context injection hooks,
        // audit log, reuse analytics, failure alert + failure webhook,
        // scratchpad trace, the F4 fresh-run fence, and the atomic
        // actor-budget backstop. What moved INTO the service to avoid
        // regressions: terminal executionUpdates event emission
        // (broadcast + execution_events persistence — see
        // talos-execution-orchestration/src/terminal_event.rs), which now
        // fires for MCP-triggered executions too.
        //
        // Deliberate semantic changes vs. the inline path (documented in
        // docs/engine-builder-refactor-plan.md "Open questions" #3):
        // - actor binding now falls back to the workflow's default actor
        //   and then the user's default actor (MCP parity) instead of
        //   caller-arg-only.
        // - the row is created as 'running' with the epoch fence instead
        //   of 'queued' + advisory-lock promotion; the returned status
        //   string is therefore "running" (was "pending").
        let orchestration_service = ctx
            .data::<Arc<talos_execution_orchestration::ExecutionOrchestrationService>>()
            .map_err(|_| {
                async_graphql::Error::new(
                    "Execution orchestration service unavailable — cannot trigger",
                )
                .extend_safe()
            })?;

        let outcome = orchestration_service
            .trigger(talos_execution_orchestration::TriggerInput {
                workflow_id,
                user_id: *user_id,
                trigger_input: serde_json::json!({}),
                trigger_agent_id: actor_id,
                inject_memory_context: false,
                dry_run: false,
                wait_ms: None,
            })
            .await
            .map_err(|e| {
                use talos_execution_orchestration::OrchestrationError;
                // Same mapping as retry_execution above: actionable
                // variants surface their typed Display verbatim (the
                // service owns the canonical user-facing strings, shared
                // with MCP); internal variants collapse to a generic
                // message after server-side logging.
                match &e {
                    OrchestrationError::InvalidArgument(_)
                    | OrchestrationError::ValidationFailed(_)
                    | OrchestrationError::WorkflowNotFound(_)
                    | OrchestrationError::ExecutionNotFound(_)
                    | OrchestrationError::ExecutionPaused
                    | OrchestrationError::WorkflowDisabled(_)
                    | OrchestrationError::StatusConflict(_)
                    | OrchestrationError::AuthorizationDenied(_)
                    | OrchestrationError::ConcurrencyLimitExceeded(_)
                    | OrchestrationError::GraphLoadFailed(_) => {
                        async_graphql::Error::new(e.to_string()).extend_safe()
                    }
                    OrchestrationError::DispatchFailed(_)
                    | OrchestrationError::Database(_)
                    | OrchestrationError::Internal(_) => {
                        tracing::error!(workflow_id = %workflow_id, "trigger_workflow: {}", e);
                        async_graphql::Error::new("Internal error during trigger").extend_safe()
                    }
                }
            })?;

        let dispatched = match outcome {
            talos_execution_orchestration::TriggerOutcome::Dispatched(o) => o,
            // Unreachable with dry_run: false — defensive arm.
            talos_execution_orchestration::TriggerOutcome::DryRun(_) => {
                tracing::error!(
                    workflow_id = %workflow_id,
                    "trigger_workflow: service returned DryRun for a non-dry-run trigger"
                );
                return Err(
                    async_graphql::Error::new("Internal error during trigger").extend_safe()
                );
            }
        };

        let now = Utc::now().to_rfc3339();
        Ok(WorkflowExecution {
            id: dispatched.execution_id,
            workflow_id,
            status: "running".to_string(),
            started_at: now.clone(),
            completed_at: None,
            error_message: None,
            created_at: now,
            duration_ms: None,
            output_data: None,
            trigger_type: Some("manual".to_string()),
            actor_id: dispatched.metadata.actor_id,
        })
    }

    async fn resume_workflow(&self, ctx: &Context<'_>, execution_id: Uuid) -> Result<bool> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsWrite)?;

        // Get authenticated user
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;

        // Org-aware write scoping: org members with a WRITE role may
        // resume org-owned executions (role-filtered — a Viewer cannot).
        let org_ids = crate::schema::user_writable_org_ids(ctx).await?;

        // Delegate to the shared resume service (the same
        // `ExecutionOrchestrationService::resume_waiting_execution` behind
        // MCP `submit_workflow_approval`): org/ownership advisory read,
        // full trigger-authorization gate (actor status, budget,
        // capability-ceiling drift — the MCP-726/MCP-652 shape this
        // mutation previously inlined), atomic `waiting -> 'resuming'`
        // claim with epoch fence, checkpoint reload and fenced re-run.
        //
        // HISTORY: the previous ~550-line bespoke implementation here
        // flipped the row to 'pending' — a status the
        // `workflow_executions_status_check` constraint has FORBIDDEN
        // since migration 20260530000000 — so every call failed at the
        // claim ("Failed to resume execution") and all the resume code
        // behind it was unreachable. One resume path for both protocols
        // means they cannot drift again.
        let orchestration = ctx
            .data::<Arc<talos_execution_orchestration::ExecutionOrchestrationService>>()
            .map_err(|_| {
                async_graphql::Error::new("Orchestration service unavailable").extend_safe()
            })?;
        match orchestration
            .resume_waiting_execution(execution_id, *user_id, &org_ids)
            .await
        {
            Ok(talos_execution_orchestration::WaitingResumeOutcome::Resumed) => Ok(true),
            Ok(talos_execution_orchestration::WaitingResumeOutcome::NotWaiting) => {
                Err(async_graphql::Error::new(
                    "Execution is not in 'waiting' status (already resumed, finished, or \
                     claimed by another resume)",
                )
                .extend_safe())
            }
            Err(talos_execution_orchestration::OrchestrationError::ExecutionNotFound(_))
            | Err(talos_execution_orchestration::OrchestrationError::WorkflowNotFound(_)) => {
                Err(async_graphql::Error::new("Execution not found or access denied").extend_safe())
            }
            Err(talos_execution_orchestration::OrchestrationError::AuthorizationDenied(msg)) => {
                // Operator-facing by design (actor archived / budget /
                // ceiling drift) — same surfacing as the MCP path.
                Err(async_graphql::Error::new(msg).extend_safe())
            }
            Err(e) => {
                // Full detail server-side only; generic message out.
                tracing::error!(
                    execution_id = %execution_id,
                    error = %e,
                    "resume_workflow: shared resume service failed"
                );
                Err(async_graphql::Error::new("Failed to resume execution").extend_safe())
            }
        }
    }

    async fn create_workflow(
        &self,
        ctx: &Context<'_>,
        input: CreateWorkflowInput,
    ) -> Result<Workflow> {
        crate::schema::require_2fa(ctx)?;
        crate::schema::require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsWrite)?;

        // SECURITY: Validate workflow name to prevent injection attacks
        validate_resource_name(&input.name)?;
        validate_payload_size("graph_json", &input.graph_json)?;
        // MCP-1216 (2026-05-18): cap graph-level execution_timeout_secs
        // at MAX_WORKFLOW_EXECUTION_TIMEOUT_SECS. Pre-fix the engine
        // honored any u64 from graph_json's top-level
        // `execution_timeout_secs` field; a caller could submit 86400
        // (24 h) and pin a worker slot for the full day per execution,
        // × up to 100 concurrent executions per workflow. Sibling to
        // MCP-584 (HTTP), MCP-1215 (LLM streaming) wall-clock caps.
        crate::validation::validate_workflow_execution_timeout(&input.graph_json)?;
        // MCP-1182: enforce 1-100 cap on max_concurrent_executions
        // (sibling to MCP `set_concurrency_limit` / GraphQL
        // `set_concurrency_limit` mutation). Pre-fix create_workflow
        // bound input.max_concurrent_executions straight into the
        // INSERT — a caller could set i32::MAX (no cap; bypasses the
        // per-workflow throttle that protects the shared worker fleet
        // from a runaway dispatch loop) or 0 / negative (admit_count
        // helper collapses non-positive to 0 → self-DoS).
        validate_max_concurrent_executions(input.max_concurrent_executions)?;
        // 2026-05-28 review (low): validate `intent` through the canonical
        // `validate_intent` helper — the same one the MCP `set_workflow_intent`
        // path uses — so the GraphQL surface enforces unknown-field rejection,
        // the ≤500-char/field cap, null-byte/control-char rejection, and the
        // 10K serialized cap. Pre-fix `intent` was bound raw into the JSONB
        // column with no per-field validation (cross-protocol parity drift).
        if let Some(ref intent) = input.intent {
            talos_workflow_creation_helpers::validate_intent(intent)
                .map_err(|e| async_graphql::Error::new(e).extend_safe())?;
        }
        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;

        // RFC 0004: resolve the OWNING ORG. An explicit org must be one
        // the caller can write to (Member+, via user_writable_org_ids —
        // a Viewer can't create resources in an org); omitting it
        // defaults to the caller's personal org, so every workflow has a
        // non-null owning org going forward (sets up the eventual
        // `org_id SET NOT NULL`). Stamping org_id is what makes the
        // org-union read path actually surface team-shared workflows —
        // previously org_id was never written, so sharing was read-ready
        // but write-incomplete.
        let org_id: Uuid = match input.organization_id {
            Some(org) => {
                let writable = crate::schema::user_writable_org_ids(ctx).await?;
                if !writable.contains(&org) {
                    return Err(async_graphql::Error::new(
                        "You do not have write access to that organization",
                    )
                    .extend_safe());
                }
                org
            }
            None => {
                talos_organizations::OrganizationService::create_personal_org(db_pool, *user_id, None)
                    .await
                    .map_err(|e| {
                        tracing::error!(user_id = %user_id, "create_workflow: resolve personal org failed: {e}");
                        async_graphql::Error::new("Failed to resolve your personal organization")
                            .extend_safe()
                    })?
                    .id
            }
        };

        // RFC 0006 / RFC 0005 S3: insert on an ORG-scoped tx so the
        // workflows RLS WITH CHECK (org pin — `org_id = app.current_org_id`)
        // actually ENFORCES once the fail-closed flip is on. The owning
        // `org_id` resolved above is both bound into the row AND set as the
        // scope's active org, so they match by construction; a write that
        // tried to land the row in any other org would be rejected (42501).
        // `begin_org_scoped` also sets `app.current_user_id`, which the
        // org-pinned workflows policy simply ignores. Latent while
        // `TALOS_RLS_SET_ROLE` is off (sets the GUCs, no role switch).
        let workflow_repo = talos_workflow_repository::WorkflowRepository::new(db_pool.clone());
        let mut tx =
            talos_db::begin_org_scoped(db_pool, &talos_tenancy::OrgScope::new(org_id, *user_id))
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "graphql: tenant scope error");
                    async_graphql::Error::new("Request scope error").extend_safe()
                })?;
        let workflow_id = workflow_repo
            .insert_workflow_scoped(
                &mut tx,
                &input.name,
                &input.graph_json,
                *user_id,
                input.max_concurrent_executions,
                input.intent.as_ref(),
                org_id,
            )
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: workflow insert failed");
                async_graphql::Error::new("Request could not be completed").extend_safe()
            })?;
        tx.commit()
            .await
            .map_err(|e: sqlx::Error| e.extend_safe())?;

        // Maintain workflow_module_refs junction table.
        sync_workflow_module_refs(db_pool, workflow_id, &input.graph_json).await;

        Ok(Workflow {
            id: workflow_id,
            name: input.name,
            graph_json: input.graph_json,
            max_concurrent_executions: input.max_concurrent_executions,
            intent: input.intent,
            actor_id: None,
        })
    }

    /// AI-scaffolded workflow creation from a natural-language
    /// description. Backed by the same `WorkflowCreationService`
    /// that powers the MCP `create_workflow_from_description` tool —
    /// a single source of truth for scaffold semantics across both
    /// surfaces.
    ///
    /// Both success cases (LLM-scaffolded, explicit-modules) and all
    /// soft-failure cases (LLM unavailable, LLM rate-limited, etc.)
    /// return a populated `CreateWorkflowFromDescriptionResult` —
    /// hard failures (DB unavailable, etc.) flow as a GraphQL Error.
    async fn create_workflow_from_description(
        &self,
        ctx: &Context<'_>,
        input: CreateWorkflowFromDescriptionInput,
    ) -> Result<CreateWorkflowFromDescriptionResult> {
        crate::schema::require_2fa(ctx)?;
        crate::schema::require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsWrite)?;

        validate_payload_size("description", &input.description)?;

        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;

        let service = ctx
            .data::<Arc<talos_workflow_creation::WorkflowCreationService>>()
            .map_err(|_| {
                async_graphql::Error::new("WorkflowCreationService not available").extend_safe()
            })?;

        // Validate input shape using the service's own validator —
        // single source of truth for rules like description length.
        if let Err(e) = talos_workflow_creation::validate_input(Some(&input.description)) {
            // MCP-918: .extend_safe() — InputError Display is user-safe
            // (fixed-format strings: "Missing or empty 'description'" /
            // "Description too long (max N chars)").
            return Err(async_graphql::Error::new(format!("{}", e)).extend_safe());
        }

        let modules = input.modules.unwrap_or_default();
        let outcome = service
            .create_from_description(talos_workflow_creation::CreateFromDescriptionRequest {
                description: &input.description,
                explicit_modules: &modules,
                user_id,
            })
            .await
            .map_err(|e| {
                tracing::error!("create_workflow_from_description: service error: {:#}", e);
                async_graphql::Error::new("Failed to create workflow").extend_safe()
            })?;

        Ok(map_create_outcome(outcome))
    }

    async fn update_workflow(
        &self,
        ctx: &Context<'_>,
        id: Uuid,
        input: CreateWorkflowInput,
    ) -> Result<Workflow> {
        crate::schema::require_2fa(ctx)?;
        crate::schema::require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsWrite)?;

        // MCP-830 (2026-05-14): mirror the per-field validation that
        // `create_workflow` has run since MCP-751. Pre-fix `update_workflow`
        // skipped BOTH checks, so the validation that the create-path
        // enforces (name length / forbidden chars / control chars /
        // hidden-file prefix / reserved Windows names, plus 10 MB cap
        // on graph_json) could be bypassed by writing a workflow with
        // a clean name then immediately PATCHing it to e.g. `../../etc/passwd`,
        // a 1 GiB graph_json, or a name containing `\0`. Same
        // create/update sibling-divergence class as MCP-829
        // (update_secret whitespace-only) and the broader GraphQL-
        // content-discipline drift (MCP-186/373/431/747-751/769/829).
        validate_resource_name(&input.name)?;
        validate_payload_size("graph_json", &input.graph_json)?;
        // MCP-1216 (2026-05-18): cap graph-level execution_timeout_secs.
        // Mirror of create_workflow validation above — exact MCP-1182
        // sibling-drift class. Without this, a caller could create a
        // clean workflow and PATCH execution_timeout_secs to 86400 via
        // update_workflow to bypass the create-time cap.
        crate::validation::validate_workflow_execution_timeout(&input.graph_json)?;
        // MCP-1182: enforce 1-100 cap on max_concurrent_executions
        // here too. update_workflow took CreateWorkflowInput so the
        // gap was symmetrical with create_workflow above. Without
        // this, a caller could create a clean workflow and then
        // PATCH max_concurrent_executions to i32::MAX or -1 to
        // bypass / DoS the per-workflow throttle.
        validate_max_concurrent_executions(input.max_concurrent_executions)?;
        // 2026-05-28 review (low): mirror create_workflow's intent validation
        // (canonical `validate_intent`) so a clean workflow can't be PATCHed to
        // an oversized / unknown-field / null-byte-bearing intent.
        if let Some(ref intent) = input.intent {
            talos_workflow_creation_helpers::validate_intent(intent)
                .map_err(|e| async_graphql::Error::new(e).extend_safe())?;
        }

        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;

        // Update workflow (ensure ownership or org membership with write access).
        // Use the role-filtered helper — a Viewer must NOT be able to UPDATE
        // an org-shared workflow even though they can SELECT it.
        let org_ids: Vec<uuid::Uuid> = crate::schema::user_writable_org_ids(ctx).await?;
        // RFC 0004 M4: scoped tx (user + writable orgs) so the workflows
        // RLS USING matches the same rows as the app-layer WHERE.
        let scope = talos_tenancy::TenantReadScope::new(*user_id, org_ids);
        let mut tx = talos_db::begin_tenant_read_scoped(db_pool, &scope)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: tenant scope error");
                async_graphql::Error::new("Request scope error").extend_safe()
            })?;
        let workflow_repo = talos_workflow_repository::WorkflowRepository::new(db_pool.clone());
        let rows_affected = workflow_repo
            .update_workflow_scoped(
                &mut tx,
                id,
                *user_id,
                &scope.accessible_org_ids,
                &input.name,
                &input.graph_json,
                input.max_concurrent_executions,
                input.intent.as_ref(),
            )
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: workflow update failed");
                async_graphql::Error::new("Request could not be completed").extend_safe()
            })?;
        tx.commit()
            .await
            .map_err(|e: sqlx::Error| e.extend_safe())?;

        if rows_affected == 0 {
            // MCP-918: .extend_safe()
            return Err(async_graphql::Error::new(
                "Workflow not found or you don't have permission to update it",
            )
            .extend_safe());
        }

        // Maintain workflow_module_refs junction table.
        sync_workflow_module_refs(db_pool, id, &input.graph_json).await;

        Ok(Workflow {
            id,
            name: input.name,
            graph_json: input.graph_json,
            max_concurrent_executions: input.max_concurrent_executions,
            intent: input.intent,
            actor_id: None,
        })
    }

    async fn delete_workflow(&self, ctx: &Context<'_>, id: Uuid) -> Result<bool> {
        crate::schema::require_2fa(ctx)?;
        crate::schema::require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsWrite)?;

        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;

        // Delete workflow — Viewers must not be able to DELETE org-shared
        // workflows even though they can SELECT them. Use the role-filtered
        // helper that requires Member+ for org membership.
        let org_ids: Vec<uuid::Uuid> = crate::schema::user_writable_org_ids(ctx).await?;

        // MCP-650 (2026-05-13): mirror the MCP-side
        // `WorkflowRepository::delete_workflows` running-execution guard.
        // Pre-fix the GraphQL path did a plain DELETE which CASCADE-
        // deleted every `workflow_executions` row referencing this
        // workflow (the FK is `ON DELETE CASCADE` per migration 009).
        // Consequences:
        //   * Running / queued / pending executions silently disappear
        //     mid-flight — workers that finish after the delete write
        //     the result row to a now-missing FK target and fail
        //     loudly, but the audit trail is gone.
        //   * Approval gates, suspensions, schedules also cascade.
        //   * Operator dashboard shows "execution completed" while
        //     the persisted row was already gone.
        // The MCP path returned a structured (deleted, blocked) split
        // so operators saw which workflows had in-flight work. Mirror
        // the guard at the SQL layer so the GraphQL dashboard can't
        // silently nuke running executions. Cross-protocol parity per
        // MCP-292 / MCP-647 / MCP-648.
        // RFC 0004 M4: scoped tx (user + writable orgs) so the workflows
        // RLS USING matches the app-layer WHERE. The workflow_executions
        // subquery is unaffected (that table isn't RLS-enabled). Clone —
        // org_ids is reused by the refusal-path diagnostic SELECT below.
        let scope = talos_tenancy::TenantReadScope::new(*user_id, org_ids.clone());
        let mut tx = talos_db::begin_tenant_read_scoped(db_pool, &scope)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: tenant scope error");
                async_graphql::Error::new("Request scope error").extend_safe()
            })?;
        let workflow_repo = talos_workflow_repository::WorkflowRepository::new(db_pool.clone());
        let rows_affected = workflow_repo
            .delete_workflow_guarded_scoped(&mut tx, id, *user_id, &scope.accessible_org_ids)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: workflow delete failed");
                async_graphql::Error::new("Request could not be completed").extend_safe()
            })?;
        tx.commit()
            .await
            .map_err(|e: sqlx::Error| e.extend_safe())?;

        if rows_affected == 0 {
            // Distinguish "not found / access denied" from "blocked by
            // in-flight executions" so the operator gets actionable
            // feedback. Run a second SELECT to determine which case
            // applies. The check is read-only and runs only on the
            // refusal path, so the cost is acceptable.
            //
            // MCP-838 (2026-05-14): handle the SELECT error explicitly
            // instead of `.ok().flatten()`. Pre-fix any DB hiccup
            // collapsed `blocked` to None and the handler fell through
            // to "Workflow not found or you don't have permission" —
            // misleading the operator twice: (a) they assume their
            // workflow is already deleted (it isn't), and (b) if the
            // real cause was running executions, they never see the
            // "cancel them first" guidance and try to redeploy on top
            // of a still-running workflow. Fail closed with a
            // retry-after-DB diagnostic so the operator knows the
            // delete state is undetermined.
            // RFC 0005 S3: run the diagnostic on a tenant-scoped tx so the
            // workflows + workflow_executions RLS policies backstop it. A
            // begin/commit failure maps to sqlx::Error and lands in the
            // Err arm below — which already means "delete state
            // undetermined", the correct outcome when the scope can't even
            // be established.
            let blocked: anyhow::Result<Option<bool>> = async {
                let mut dtx = talos_db::begin_tenant_read_scoped(db_pool, &scope)
                    .await
                    .map_err(|e| anyhow::anyhow!("tenant scope: {e}"))?;
                let b = workflow_repo
                    .workflow_delete_blocked_scoped(
                        &mut dtx,
                        id,
                        *user_id,
                        &scope.accessible_org_ids,
                    )
                    .await?;
                dtx.commit().await?;
                Ok(b)
            }
            .await;
            match blocked {
                Ok(Some(true)) => {
                    // MCP-916 cont.: .extend_safe() — operator needs the
                    // actionable "cancel running executions" guidance,
                    // not "Internal server error".
                    return Err(async_graphql::Error::new(
                        "Workflow has running / queued / pending executions. \
                         Cancel them before deleting, or use force-delete via MCP.",
                    )
                    .extend_safe());
                }
                Ok(_) => {
                    return Err(async_graphql::Error::new(
                        "Workflow not found or you don't have permission to delete it",
                    )
                    .extend_safe());
                }
                Err(e) => {
                    tracing::error!(workflow_id = %id, error = %e, "delete_workflow: blocked-state probe failed");
                    return Err(async_graphql::Error::new(
                        "Database hiccup while determining delete state. The workflow may or may not have been deleted — refresh and retry.",
                    )
                    .extend_safe());
                }
            }
        }

        Ok(true)
    }

    async fn generate_code(
        &self,
        ctx: &Context<'_>,
        input: GenerateCodeInput,
    ) -> Result<GenerateCodeResult> {
        // Auth gate — generate_code calls Anthropic and burns credits; without
        // these checks an unauthenticated client could drain the LLM budget.
        // require_2fa + WorkflowsWrite scope mirrors create_workflow's posture.
        crate::schema::require_2fa(ctx)?;
        crate::schema::require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsWrite)?;
        let _user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;

        let llm_client = ctx.data::<talos_llm::LlmClient>().map_err(|_| {
            async_graphql::Error::new("AI generation is not configured. Please set the ANTHROPIC_API_KEY environment variable on the server.").extend_safe()
        })?;

        let prompt_redacted = talos_dlp_provider::redact_str(&input.prompt);
        // R2 token ledger: attribute this call's token usage to the
        // requesting user via the talos-llm task-local scope.
        let code = talos_llm::usage::scoped_user(
            *_user_id,
            llm_client.generate_code(
                &prompt_redacted,
                &input.current_code,
                &input.capability_world,
            ),
        )
        .await
        .map_err(|e: anyhow::Error| {
            // Added type annotation
            tracing::error!("Internal error: {}", e);
            async_graphql::Error::new("An internal error occurred").extend_safe()
        })?;

        Ok(GenerateCodeResult { code })
    }

    async fn publish_workflow_version(
        &self,
        ctx: &Context<'_>,
        workflow_id: Uuid,
        description: Option<String>,
    ) -> Result<WorkflowVersion> {
        crate::schema::require_2fa(ctx)?;
        crate::schema::require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsWrite)?;

        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        // MCP-747: mirror MCP `handle_publish_version` content discipline
        // (cap 2000, trim, reject whitespace-only / control chars / `\0`).
        // Note the 2000 cap vs actor's 5000 — version descriptions are
        // changelog-style and the immutable workflow_versions table
        // holds many rows per workflow, so the smaller cap bounds
        // cumulative storage. MCP-837 (2026-05-14): canonical helper.
        let description = match description {
            None => None,
            Some(d) if d.is_empty() => None,
            Some(d) => Some(
                crate::schema::validate_description_content("description", &d, 2000)
                    .map_err(|e| e.extend_safe())?
                    .to_string(),
            ),
        };

        let publish_result = WorkflowVersionService::publish_version(
            db_pool,
            workflow_id,
            user_id,
            description,
            None,
        )
        .await;
        let (version, _warnings) = publish_result.map_err(|e: anyhow::Error| {
            tracing::error!("Failed to publish workflow version: {}", e);
            async_graphql::Error::new("Internal error").extend_safe()
        })?;

        Ok(version.into())
    }

    async fn rollback_workflow_version(
        &self,
        ctx: &Context<'_>,
        workflow_id: Uuid,
        version_id: Uuid,
    ) -> Result<WorkflowVersion> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsWrite)?;

        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        let version =
            WorkflowVersionService::rollback_to_version(db_pool, workflow_id, version_id, user_id)
                .await
                .map_err(|e: anyhow::Error| {
                    // Added type annotation
                    tracing::error!("Failed to rollback workflow version: {}", e);
                    async_graphql::Error::new("Failed to rollback workflow version").extend_safe()
                })?;

        Ok(version.into())
    }

    async fn create_schedule(
        &self,
        ctx: &Context<'_>,
        workflow_id: Uuid,
        cron_expression: String,
        timezone: Option<String>,
    ) -> Result<WorkflowScheduleObj> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsWrite)?;

        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        let tz = timezone.unwrap_or_else(|| "UTC".to_string());

        // MCP-844 (2026-05-14): mirror MCP-414's length cap + trim at
        // the boundary. Pre-fix the GraphQL surface accepted multi-MB
        // cron strings (forcing validate_cron to scan all of it) and
        // persisted leading/trailing whitespace from copy-pasted
        // runbook snippets, producing ragged dashboard displays and
        // potential parse-tolerance drift with downstream consumers.
        // 256-char cap covers every legitimate cron expression; trim
        // ensures the stored value matches what readers see.
        if cron_expression.len() > 256 {
            return Err(
                async_graphql::Error::new("cron_expression must be ≤ 256 characters").extend_safe(),
            );
        }
        let cron_expression = cron_expression.trim().to_string();
        if cron_expression.is_empty() {
            return Err(async_graphql::Error::new(
                "cron_expression cannot be empty or whitespace-only",
            )
            .extend_safe());
        }

        // MCP-843 (2026-05-14): mirror the MCP `handle_create_schedule`
        // fast-fail field-count gate (talos-mcp-handlers/src/schedules.rs:207).
        // Pre-fix wrong-field-count cron expressions reached
        // `validate_cron` (the croner parse) which produces a parser-
        // shape error message that's harder for an operator to act on
        // than the explicit "must have 5 or 6 space-separated fields"
        // diagnostic. Same UX-parity class as MCP-292
        // ("GraphQL must mirror MCP").
        let field_count = cron_expression.split_whitespace().count();
        if !(5..=6).contains(&field_count) {
            return Err(async_graphql::Error::new(
                "Invalid cron expression: must have 5 or 6 space-separated fields",
            )
            .extend_safe());
        }

        // Validate cron expression
        talos_scheduler::validate_cron(&cron_expression)
            .map_err(|e| async_graphql::Error::new(e).extend_safe())?;
        // Enforce minimum 1-minute interval to prevent runaway scheduler load
        talos_scheduler::validate_cron_min_interval(&cron_expression, 60)
            .map_err(|e| async_graphql::Error::new(e).extend_safe())?;

        // Validate timezone
        talos_scheduler::validate_timezone(&tz)
            .map_err(|e| async_graphql::Error::new(e).extend_safe())?;

        // Calculate next trigger time (pure — compute before opening the
        // tx so the unit of work stays scoped to the two DB ops).
        let next_trigger = talos_scheduler::calculate_next_trigger(&cron_expression, &tz)
            .map_err(|e| async_graphql::Error::new(e).extend_safe())?;

        // RFC 0005 S3: the org-WRITE-access check + the upsert share ONE
        // request-scoped unit of work — the ownership read gets the
        // workflows RLS backstop, and both run in one transaction.
        // user_writable_org_ids (Viewer must not create schedules on
        // org-shared workflows) sources the scope, so it precedes the tx.
        let org_ids: Vec<uuid::Uuid> = crate::schema::user_writable_org_ids(ctx).await?;
        let scope = talos_tenancy::TenantReadScope::new(user_id, org_ids);
        let mut uow = talos_db::UnitOfWork::begin(db_pool, &scope)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: tenant scope error");
                async_graphql::Error::new("Request scope error").extend_safe()
            })?;

        let workflow_exists = crate::access_check::workflow_accessible_for_user_on_conn(
            uow.conn(),
            workflow_id,
            user_id,
            &scope.accessible_org_ids,
        )
        .await
        .map_err(|e: sqlx::Error| e.extend_safe())?;

        if !workflow_exists {
            return Err(
                async_graphql::Error::new("Workflow not found or access denied").extend_safe(),
            );
        }

        // Upsert: insert or update on conflict (workflow_id is UNIQUE)
        let row = talos_scheduler::upsert_schedule_on_conn(
            uow.conn(),
            workflow_id,
            user_id,
            &cron_expression,
            &tz,
            next_trigger,
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "graphql: schedule upsert failed");
            async_graphql::Error::new("Request could not be completed").extend_safe()
        })?;
        uow.commit().await.map_err(|e| {
            tracing::error!(error = %e, "graphql: commit transaction error");
            async_graphql::Error::new("Request could not be completed").extend_safe()
        })?;

        Ok(WorkflowScheduleObj {
            id: row.id,
            workflow_id: row.workflow_id,
            cron_expression: row.cron_expression,
            timezone: row.timezone,
            is_enabled: row.is_enabled,
            last_triggered_at: row.last_triggered_at.map(|d| d.to_rfc3339()),
            next_trigger_at: row.next_trigger_at.map(|d| d.to_rfc3339()),
            created_at: row.created_at.to_rfc3339(),
            updated_at: row.updated_at.to_rfc3339(),
        })
    }

    async fn update_schedule(
        &self,
        ctx: &Context<'_>,
        workflow_id: Uuid,
        cron_expression: Option<String>,
        timezone: Option<String>,
        is_enabled: Option<bool>,
    ) -> Result<WorkflowScheduleObj> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsWrite)?;

        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        // RFC 0005 S3: ownership check + read-merge-write all in ONE
        // request-scoped unit of work. Beyond the snapshot/RLS-backstop
        // win, the shared tx lets the existing-row SELECT take a
        // `FOR UPDATE` row lock so the read→merge→update is atomic —
        // closing the lost-update window where two concurrent updates each
        // merging different fields off a stale snapshot would clobber each
        // other. update_schedule is a write, so the scope uses the
        // WRITABLE org set (Viewer must not change an org-shared schedule).
        let org_ids: Vec<uuid::Uuid> = crate::schema::user_writable_org_ids(ctx).await?;
        let scope = talos_tenancy::TenantReadScope::new(user_id, org_ids);
        let mut uow = talos_db::UnitOfWork::begin(db_pool, &scope)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: tenant scope error");
                async_graphql::Error::new("Request scope error").extend_safe()
            })?;

        let workflow_exists = crate::access_check::workflow_accessible_for_user_on_conn(
            uow.conn(),
            workflow_id,
            user_id,
            &scope.accessible_org_ids,
        )
        .await
        .map_err(|e: sqlx::Error| e.extend_safe())?;

        if !workflow_exists {
            return Err(
                async_graphql::Error::new("Workflow not found or access denied").extend_safe(),
            );
        }

        // Fetch existing schedule, locking the row (`FOR UPDATE OF ws`) so
        // the merge-then-update below is serialized against concurrent
        // updaters.
        let existing = talos_scheduler::get_schedule_for_update_on_conn(
            uow.conn(),
            workflow_id,
            user_id,
            &scope.accessible_org_ids,
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "graphql: schedule locked read failed");
            async_graphql::Error::new("Request could not be completed").extend_safe()
        })?
        .ok_or_else(|| async_graphql::Error::new("Schedule not found").extend_safe())?;

        let new_cron = cron_expression.unwrap_or(existing.cron_expression);
        let new_tz = timezone.unwrap_or(existing.timezone);
        let new_enabled = is_enabled.unwrap_or(existing.is_enabled);

        // MCP-844 (2026-05-14): length cap + trim parity with
        // create_schedule above. Stored cron from `existing` will
        // already be trimmed if it was written post-fix; the trim is
        // a no-op then. Caller-supplied new value gets the same
        // boundary normalization.
        if new_cron.len() > 256 {
            return Err(
                async_graphql::Error::new("cron_expression must be ≤ 256 characters").extend_safe(),
            );
        }
        let new_cron = new_cron.trim().to_string();
        if new_cron.is_empty() {
            return Err(async_graphql::Error::new(
                "cron_expression cannot be empty or whitespace-only",
            )
            .extend_safe());
        }

        // MCP-843 (2026-05-14): same fast-fail field-count gate as
        // create_schedule above. The existing row's cron_expression
        // already passed this gate at create time, but if the caller
        // supplies a new cron_expression here it must too.
        let field_count = new_cron.split_whitespace().count();
        if !(5..=6).contains(&field_count) {
            return Err(async_graphql::Error::new(
                "Invalid cron expression: must have 5 or 6 space-separated fields",
            )
            .extend_safe());
        }

        // Validate cron expression
        talos_scheduler::validate_cron(&new_cron)
            .map_err(|e| async_graphql::Error::new(e).extend_safe())?;
        // Enforce minimum 1-minute interval to prevent runaway scheduler load
        talos_scheduler::validate_cron_min_interval(&new_cron, 60)
            .map_err(|e| async_graphql::Error::new(e).extend_safe())?;

        // Validate timezone
        talos_scheduler::validate_timezone(&new_tz)
            .map_err(|e| async_graphql::Error::new(e).extend_safe())?;

        // Calculate next trigger time (only when enabled)
        let next_trigger = if new_enabled {
            Some(
                talos_scheduler::calculate_next_trigger(&new_cron, &new_tz)
                    .map_err(|e| async_graphql::Error::new(e).extend_safe())?,
            )
        } else {
            None
        };

        let row = talos_scheduler::update_schedule_on_conn(
            uow.conn(),
            workflow_id,
            user_id,
            &scope.accessible_org_ids,
            &new_cron,
            &new_tz,
            new_enabled,
            next_trigger,
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "graphql: schedule update failed");
            async_graphql::Error::new("Request could not be completed").extend_safe()
        })?;
        uow.commit().await.map_err(|e| {
            tracing::error!(error = %e, "graphql: commit transaction error");
            async_graphql::Error::new("Request could not be completed").extend_safe()
        })?;

        Ok(WorkflowScheduleObj {
            id: row.id,
            workflow_id: row.workflow_id,
            cron_expression: row.cron_expression,
            timezone: row.timezone,
            is_enabled: row.is_enabled,
            last_triggered_at: row.last_triggered_at.map(|d| d.to_rfc3339()),
            next_trigger_at: row.next_trigger_at.map(|d| d.to_rfc3339()),
            created_at: row.created_at.to_rfc3339(),
            updated_at: row.updated_at.to_rfc3339(),
        })
    }

    async fn delete_schedule(&self, ctx: &Context<'_>, workflow_id: Uuid) -> Result<bool> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsWrite)?;

        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        // delete_schedule is a write — Viewer must not be able to detach
        // a schedule from an org-shared workflow.
        // RFC 0005 S3: ownership check + DELETE share ONE request-scoped
        // unit of work (completes the schedule trio with create/update,
        // PR #29). The workflows-USING join gets the RLS backstop; the
        // scope uses the WRITABLE org set (write op).
        let org_ids: Vec<uuid::Uuid> = crate::schema::user_writable_org_ids(ctx).await?;
        let scope = talos_tenancy::TenantReadScope::new(user_id, org_ids);
        let mut uow = talos_db::UnitOfWork::begin(db_pool, &scope)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "graphql: tenant scope error");
                async_graphql::Error::new("Request scope error").extend_safe()
            })?;

        let workflow_exists = crate::access_check::workflow_accessible_for_user_on_conn(
            uow.conn(),
            workflow_id,
            user_id,
            &scope.accessible_org_ids,
        )
        .await
        .map_err(|e: sqlx::Error| e.extend_safe())?;

        if !workflow_exists {
            return Err(
                async_graphql::Error::new("Workflow not found or access denied").extend_safe(),
            );
        }

        let rows_affected = talos_scheduler::delete_schedule_on_conn(
            uow.conn(),
            workflow_id,
            user_id,
            &scope.accessible_org_ids,
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "graphql: schedule delete failed");
            async_graphql::Error::new("Request could not be completed").extend_safe()
        })?;
        uow.commit().await.map_err(|e| {
            tracing::error!(error = %e, "graphql: commit transaction error");
            async_graphql::Error::new("Request could not be completed").extend_safe()
        })?;

        Ok(rows_affected > 0)
    }

    // ── Workflow Testing ────────────────────────────────────────────────

    async fn test_workflow(
        &self,
        ctx: &Context<'_>,
        workflow_id: Uuid,
        // Mock JSON input data to inject as the first node's output.
        mock_inputs: Option<String>,
    ) -> Result<TestWorkflowResult> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsWrite)?;

        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;

        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?.clone();
        let nats_client = ctx
            .data_opt::<Option<Arc<async_nats::Client>>>()
            .cloned()
            .flatten()
            .ok_or_else(|| {
                async_graphql::Error::new(
                    "NATS client not available — test execution requires NATS",
                )
                .extend_safe()
            })?;
        let worker_shared_key = ctx.data_opt::<Option<WorkerSharedKey>>().cloned().flatten();
        let registry = ctx.data::<Arc<ModuleRegistry>>().ok().cloned();
        let redis_client = ctx
            .data_opt::<Option<Arc<redis::Client>>>()
            .cloned()
            .flatten();
        let secrets_manager = ctx
            .data::<Arc<talos_secrets_manager::SecretsManager>>()
            .ok()
            .cloned();
        // Live-event broadcast sender — the detached run below emits
        // start / terminal ExecutionEvents here so the existing
        // `executionUpdates` GraphQL subscription streams a test run's
        // progress exactly like a real execution (per-node events flow
        // via the engine's PostgresEventSink → execution_events replay).
        let sender = ctx
            .data::<tokio::sync::broadcast::Sender<ExecutionEvent>>()?
            .clone();
        // test_workflow runs the full graph (real LLM/HTTP/secret access);
        // it's a write — Viewer must not be able to test-trigger an
        // org-shared workflow.
        let org_ids: Vec<uuid::Uuid> = crate::schema::user_writable_org_ids(ctx).await?;
        let workflow_exists = crate::access_check::workflow_accessible_for_user(
            &db_pool,
            workflow_id,
            user_id,
            &org_ids,
        )
        .await
        .map_err(|e: sqlx::Error| {
            tracing::error!("Failed to fetch workflow: {}", e);
            async_graphql::Error::new("Failed to fetch workflow").extend_safe()
        })?;

        if !workflow_exists {
            return Err(
                async_graphql::Error::new("Workflow not found or access denied").extend_safe(),
            );
        }

        // MCP-672 (2026-05-13): fetch workflow.actor_id alongside graph_json
        // so the budget/status gate below can run. Pre-fix the SQL pulled
        // only `graph_json`, so test_workflow could spin a full real-LLM
        // /real-HTTP/real-secret execution even when the bound actor was
        // suspended, deactivated, or over its rolling-hour cap. Same
        // dispatch-path-gate rule that closed MCP-555 (scheduler),
        // MCP-557/651 (retry), MCP-564 (continuation-trigger),
        // MCP-565 (webhook), MCP-652 (resume). test_workflow was the
        // last GraphQL execution-creating surface without the gate.
        // See `memory/dispatch_path_authorization_sweep.md`.
        let test_workflow_repo =
            talos_workflow_repository::WorkflowRepository::new(db_pool.clone());
        let wf_for_test = test_workflow_repo
            .get_graph_and_actor_unchecked(workflow_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to load workflow for test: {}", e);
                async_graphql::Error::new("Internal database error").extend_safe()
            })?;
        let graph_json = wf_for_test.graph_json;

        // MCP-672 + MCP-730 (2026-05-13): actor budget + capability-
        // ceiling gate. test_workflow exercises the full graph (real
        // LLM/HTTP/secret access — see the comment 20 lines up) so the
        // cost-control budget applies (MCP-672 added the budget check).
        // Only fires when the workflow has an actor binding; unbound
        // workflows have no budget to enforce. Gates BEFORE creating
        // the test-execution row so a denied test leaves no orphan
        // 'running'-status workflow_executions entry.
        //
        // MCP-730 upgrade: full `authorize_workflow_trigger`. Same
        // capability-ceiling-drift bypass class as MCP-707/726/729 —
        // an operator who downgraded the actor's ceiling between
        // workflow authoring and `test_workflow` invocation would
        // otherwise see the test execution dispatch at the previously-
        // elevated ceiling. Budget-only was INSUFFICIENT; full gate
        // also re-verifies every module in the graph against the
        // actor's current ceiling. The graph_json variable above
        // already holds the workflow's current graph.
        if let Some(actor_id) = wf_for_test.actor_id {
            let workflow_repo = talos_workflow_repository::WorkflowRepository::new(db_pool.clone());
            let actor_repo_for_gate = talos_actor_repository::ActorRepository::new(db_pool.clone());
            if let Err(e) = talos_workflow_authorization::authorize_workflow_trigger(
                &workflow_repo,
                &actor_repo_for_gate,
                &db_pool,
                Some(actor_id),
                user_id,
                &graph_json,
            )
            .await
            {
                use talos_workflow_authorization::TriggerAuthError;
                let msg = match e {
                    TriggerAuthError::ActorArchived => {
                        "Cannot test — owning actor is archived".to_string()
                    }
                    TriggerAuthError::ActorTerminated => {
                        "Cannot test — owning actor is terminated".to_string()
                    }
                    TriggerAuthError::ActorNotFoundOrInactive => {
                        "Cannot test — owning actor not found, not active, or belongs to a different user".to_string()
                    }
                    TriggerAuthError::ExecutionDenied(s) => s,
                    TriggerAuthError::CapabilityCeilingViolation {
                        module_id,
                        module_world,
                        max_world,
                        ..
                    } => {
                        tracing::warn!(
                            workflow_id = %workflow_id,
                            actor_id = %actor_id,
                            module_id = %module_id,
                            module_world = %module_world,
                            max_world = %max_world,
                            "test_workflow: BLOCKED — capability ceiling violation (likely ceiling-drift since workflow authored)"
                        );
                        format!(
                            "Cannot test — module {} requires '{}' but actor ceiling is '{}'. \
                             The actor's capability ceiling was likely downgraded since this workflow was authored.",
                            module_id, module_world, max_world
                        )
                    }
                    TriggerAuthError::Database(db_err) => {
                        tracing::error!(
                            workflow_id = %workflow_id,
                            error = %db_err,
                            "test_workflow: authorization DB error"
                        );
                        "Database error during authorization".to_string()
                    }
                };
                return Err(async_graphql::Error::new(msg).extend_safe());
            }
        }

        let execution_id = Uuid::new_v4();

        // Phase C3 of "every execution gets an actor": resolve the effective
        // actor for this test run — the workflow's own actor if it has one,
        // else the user's default actor — so the test execution row is
        // attributed and the engine below runs at the actor's tier. Fail OPEN
        // to actor-less (today's behaviour) if resolution errors, so a DB
        // hiccup never blocks a test. Note: this does NOT add budget/ceiling
        // enforcement for previously-unbound workflows — that gate (above)
        // still only fires for `wf_for_test.actor_id`; Phase D universalizes it.
        let test_effective_actor = talos_actor_repository::ActorRepository::new(db_pool.clone())
            .resolve_effective_actor(user_id, wf_for_test.actor_id)
            .await
            .ok();

        // Create a test execution record (marked as test)
        talos_execution_repository::ExecutionRepository::new(db_pool.clone())
            .insert_test_execution_row(execution_id, workflow_id, user_id, test_effective_actor)
            .await
            .map_err(|e| {
                tracing::error!("Failed to create test execution: {}", e);
                async_graphql::Error::new("Failed to create test execution").extend_safe()
            })?;

        // Parse mock_inputs → trigger_input BEFORE spawning so a malformed
        // payload returns a proper synchronous GraphQL error rather than a
        // silent async failure.
        //
        // MCP-666 (2026-05-13): align with `TRIGGER_INPUT_MAX_BYTES`
        // (1_000_000 bytes / 1 MB decimal) in talos-execution-orchestration.
        // Pre-fix this gate used 1_048_576 (1 MiB binary), so test_workflow
        // accepted ~5% larger inputs than the trigger path it's supposed
        // to simulate. The error message said "1 MB limit" while actually
        // enforcing 1 MiB — minor inconsistency that a dev test could
        // pass and the prod trigger then reject. Use the same constant
        // shape (1_000_000) and the same operator-facing wording.
        let trigger_input = if let Some(ref mock_json) = mock_inputs {
            const TEST_INPUT_MAX_BYTES: usize = 1_000_000;
            if mock_json.len() > TEST_INPUT_MAX_BYTES {
                return Err(async_graphql::Error::new(format!(
                    "mock_inputs must be ≤ {} bytes when serialised (got {})",
                    TEST_INPUT_MAX_BYTES,
                    mock_json.len()
                ))
                .extend_safe());
            }
            serde_json::from_str(mock_json).map_err(|e: serde_json::Error| {
                async_graphql::Error::new(format!("Invalid mock_inputs JSON: {}", e)).extend_safe()
            })?
        } else {
            serde_json::Value::Null
        };

        // Detached execution — mirror trigger_workflow (see the `tokio::spawn`
        // at the top of this file). Pre-fix (the "stuck running" bug) the run
        // was awaited INLINE here, wrapped in `tokio::time::timeout(30s)`. A
        // client that aborts the request (browser / graphql-ws, ~15 s) dropped
        // the whole resolver future — cancelling the in-flight worker dispatch
        // (reply inbox torn down, JobResult lost) AND skipping finalization, so
        // the test-execution row sat `running` until the 30-min stale sweep. It
        // also capped legitimately-slow local-Ollama tests at 30 s server-side
        // even when the graph allowed longer.
        //
        // Now the run + finalize live in a detached `tokio::spawn` that OWNS the
        // engine, so a client disconnect can't cancel it: the task runs to
        // completion (bounded by the engine's own `execution_timeout_secs` via
        // `for_run`'s Honor policy — no request-lifetime coupling), finalizes
        // the row (status-guarded), and broadcasts terminal events. The
        // resolver returns immediately with status `"running"`; the frontend
        // subscribes to `executionUpdates(executionId)` for live progress +
        // final result.
        tokio::spawn(async move {
            // allow-secrets-manager-new: defensive fallback (same rationale as
            // the trigger/resume sites above). Production context always
            // supplies the shared instance.
            let secrets_manager = match secrets_manager {
                Some(sm) => sm,
                None => match talos_secrets_manager::SecretsManager::new(db_pool.clone()) {
                    Ok(sm) => Arc::new(sm),
                    Err(e) => {
                        tracing::error!(
                            execution_id = %execution_id,
                            "test_workflow: failed to create SecretsManager: {}",
                            e
                        );
                        mark_test_execution_failed(
                            &db_pool,
                            &sender,
                            execution_id,
                            "Secrets service unavailable",
                        )
                        .await;
                        return;
                    }
                },
            };
            let sm_for_persist = secrets_manager.clone();

            let test_actor_repo = Arc::new(talos_actor_repository::ActorRepository::new(
                db_pool.clone(),
            ));
            let resolved_test_registry = registry
                .unwrap_or_else(|| Arc::new(ModuleRegistry::new(db_pool.clone(), redis_client)));

            // Phase C3: build the engine at the resolved actor's tier (builder
            // calls apply_actor_to_engine, fail-closed to Tier-1 on error). The
            // graph's `execution_timeout_secs` is now the ONLY wall-clock cap.
            let mut engine = match talos_engine::builder::for_workflow(
                resolved_test_registry,
                secrets_manager,
                test_actor_repo,
                user_id,
                talos_engine::builder::EngineOpts::for_run(workflow_id, graph_json.clone())
                    .with_effective_actor(test_effective_actor, None),
            )
            .await
            {
                Ok(e) => e,
                Err(e) => {
                    tracing::error!(
                        execution_id = %execution_id,
                        "test_workflow: invalid workflow graph: {}",
                        e
                    );
                    mark_test_execution_failed(
                        &db_pool,
                        &sender,
                        execution_id,
                        "Invalid workflow graph",
                    )
                    .await;
                    return;
                }
            };

            // Emit a "started" event so subscribers see the run begin
            // (per-node events flow via the engine's PostgresEventSink →
            // execution_events, replayed by the subscription on connect).
            persist_and_broadcast_test_event(
                &db_pool,
                &sender,
                ExecutionEvent {
                    execution_id,
                    node_id: None,
                    status: ExecutionStatus::Running,
                    trace_id: None,
                    span_id: None,
                    log_message: None,
                    iteration_index: None,
                    iteration_total: None,
                    duration_ms: None,
                    output: None,
                },
            )
            .await;

            match talos_engine::nats_run::run_with_trigger_input_via_nats(
                &mut engine,
                nats_client,
                worker_shared_key,
                trigger_input,
                execution_id,
            )
            .await
            {
                Ok(ctx) => {
                    // Aggregate per-node outputs, DLP-redact, size-cap, and
                    // persist encryption-aware — same discipline as
                    // trigger_workflow so the frontend can fetch final outputs
                    // after completion.
                    let mut aggregated_output = serde_json::Map::new();
                    for (node_id, output) in &ctx.results {
                        aggregated_output.insert(node_id.to_string(), output.clone());
                    }
                    let aggregated_json = talos_dlp_provider::redact_json(
                        &serde_json::Value::Object(aggregated_output),
                    );

                    const MAX_AGGREGATED_OUTPUT_BYTES: usize = 50 * 1024 * 1024; // 50 MB
                    if let Ok(json_str) = serde_json::to_string(&aggregated_json) {
                        if json_str.len() > MAX_AGGREGATED_OUTPUT_BYTES {
                            tracing::error!(
                                execution_id = %execution_id,
                                output_bytes = json_str.len(),
                                "test_workflow: output exceeds 50 MB limit"
                            );
                            mark_test_execution_failed(
                                &db_pool,
                                &sender,
                                execution_id,
                                "Workflow output exceeds size limit",
                            )
                            .await;
                            return;
                        }
                    }

                    // MCP-682: encryption-aware repository write so Phase A
                    // deployments persist ciphertext, not plaintext.
                    let wf_repo =
                        talos_workflow_repository::WorkflowRepository::new(db_pool.clone())
                            .with_encryption(sm_for_persist.clone());
                    let (final_status, mark_res) = if ctx.waiting {
                        (
                            ExecutionStatus::Waiting,
                            wf_repo
                                .mark_execution_waiting(execution_id, &aggregated_json)
                                .await,
                        )
                    } else {
                        (
                            ExecutionStatus::Completed,
                            wf_repo
                                .mark_execution_completed(execution_id, &aggregated_json)
                                .await,
                        )
                    };
                    if let Err(db_err) = mark_res {
                        tracing::error!(
                            execution_id = %execution_id,
                            "test_workflow: failed to finalize execution: {}",
                            db_err
                        );
                    }

                    // Carry the (already DLP-redacted) per-node aggregated
                    // output on the terminal event so the test modal can show
                    // each node's result live — the async model streams status
                    // but the engine doesn't broadcast per-node output, and the
                    // persisted copy is encrypted (a read-back would need a
                    // decrypting query). We already hold the plaintext here.
                    // Cap it so a large payload can't bloat the bounded
                    // broadcast channel; the full output is still persisted.
                    // Suppress on the waiting path (partial output is misleading).
                    const MAX_EVENT_OUTPUT_BYTES: usize = 256 * 1024;
                    let event_output = if ctx.waiting {
                        None
                    } else {
                        match serde_json::to_string(&aggregated_json) {
                            Ok(s) if s.len() <= MAX_EVENT_OUTPUT_BYTES => {
                                Some(aggregated_json.clone())
                            }
                            _ => None,
                        }
                    };

                    persist_and_broadcast_test_event(
                        &db_pool,
                        &sender,
                        ExecutionEvent {
                            execution_id,
                            node_id: None,
                            status: final_status,
                            trace_id: ctx.trace_id,
                            span_id: None,
                            log_message: Some(if ctx.waiting {
                                "Test run suspended (awaiting continuation)".to_string()
                            } else {
                                "Test run finished successfully".to_string()
                            }),
                            iteration_index: None,
                            iteration_total: None,
                            duration_ms: None,
                            output: event_output,
                        },
                    )
                    .await;
                }
                Err(e) => {
                    // MCP-969-class: DLP-redact the engine error before it
                    // reaches the DB / broadcast — `e.to_string()` carries
                    // arbitrary node-emitted text (HTTP bodies, upstream
                    // exceptions echoing Authorization headers).
                    let redacted = talos_dlp_provider::redact_str(&e.to_string());
                    let error_msg = format!("Test run failed: {}", redacted);
                    mark_test_execution_failed(&db_pool, &sender, execution_id, &error_msg).await;
                }
            }
        });

        // Return immediately — the run is detached. The frontend subscribes to
        // executionUpdates(executionId) for live progress + final status.
        Ok(TestWorkflowResult {
            execution_id,
            status: "running".to_string(),
            node_traces: Vec::new(),
            schema_warnings: Vec::new(),
            duration_ms: 0,
            error: None,
        })
    }

    /// Bind (or unbind, with a null `actorId`) a workflow's default actor —
    /// the tenancy principal its executions run under. Required for a Smart
    /// Classifier node: model serving + distillation resolve the model owner
    /// from this actor. Mirrors the MCP `set_workflow_actor_id` tool.
    async fn set_workflow_actor_id(
        &self,
        ctx: &Context<'_>,
        workflow_id: Uuid,
        actor_id: Option<Uuid>,
    ) -> Result<bool> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsWrite)?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;

        // Validate the actor belongs to the caller + is active before binding
        // (the repo UPDATE only gates workflow ownership). Mirrors the MCP
        // handler's service-layer check.
        if let Some(aid) = actor_id {
            let actor_repo = talos_actor_repository::ActorRepository::new(db_pool.clone());
            match actor_repo.get_actor_basic_info(aid, user_id).await {
                Ok(Some(info)) if info.status != "archived" && info.status != "terminated" => {}
                Ok(Some(_)) => {
                    return Err(async_graphql::Error::new(
                        "That actor is archived or terminated — reactivate it first",
                    )
                    .extend_safe());
                }
                Ok(None) => {
                    return Err(
                        async_graphql::Error::new("Actor not found or not owned by you")
                            .extend_safe(),
                    );
                }
                Err(e) => {
                    tracing::error!(target: "talos_api", error = %e, "set_workflow_actor_id actor lookup");
                    return Err(
                        async_graphql::Error::new("Could not verify the actor").extend_safe()
                    );
                }
            }
        }

        let workflow_repo = talos_workflow_repository::WorkflowRepository::new(db_pool.clone());
        let updated = workflow_repo
            .set_workflow_actor_id(workflow_id, user_id, actor_id)
            .await
            .map_err(|e| {
                tracing::error!(target: "talos_api", error = %e, "set_workflow_actor_id failed");
                async_graphql::Error::new("Could not bind the actor").extend_safe()
            })?;
        if !updated {
            return Err(
                async_graphql::Error::new("Workflow not found or not owned by you").extend_safe(),
            );
        }

        // MCP-396 parity: the binding decides which actor's tier ceiling,
        // budget, and approval policies govern every subsequent run — a flip
        // to a permissive actor (or to unbound/shared mode) must leave a
        // persistent trace on THIS surface too, exactly as the MCP handler
        // records it. Same event shape so forensics join on one event_type.
        talos_actor_repository::spawn_log_admin_event(
            db_pool.clone(),
            user_id,
            "workflow_actor_binding_changed",
            "workflow",
            Some(workflow_id),
            match actor_id {
                Some(aid) => format!("Workflow {workflow_id} bound to actor {aid}"),
                None => format!("Workflow {workflow_id} actor binding cleared (shared mode)"),
            },
            Some(serde_json::json!({
                "new_actor_id": actor_id.map(|a| a.to_string()),
                "shared_mode": actor_id.is_none(),
                "surface": "graphql",
            })),
        );
        Ok(true)
    }

    // ── Organization mutations ─────────────────────────────────────────
}

/// Broadcast a test-run execution event to live subscribers AND persist it to
/// `execution_events` so the `executionUpdates` connect-replay can recover it.
///
/// test_workflow runs detached and can finish in a few ms — faster than the
/// browser can open its WebSocket subscription after the mutation returns. A
/// broadcast-only terminal event would be sent before anyone is listening and
/// never seen, leaving the modal hung on "running". Persisting it (exactly as
/// trigger_workflow's `store_and_send!` does for real runs) makes it durable:
/// a late subscriber's replay reads the terminal row from `execution_events`.
/// `log_message` is DLP-redacted + capped (8 KiB) before persistence — it can
/// carry arbitrary node output. (The `output` field is live-only; it has no
/// `execution_events` column, so a sub-second run's per-node output is best-
/// effort — status + error message are what's made durable here.)
async fn persist_and_broadcast_test_event(
    db_pool: &sqlx::Pool<sqlx::Postgres>,
    sender: &tokio::sync::broadcast::Sender<ExecutionEvent>,
    event: ExecutionEvent,
) {
    // Broadcast first so live subscribers get it even if persistence fails.
    let _ = sender.send(event.clone());

    let event_type = match (&event.node_id, &event.status) {
        (None, ExecutionStatus::Running) => "started",
        (None, ExecutionStatus::Completed) => "completed",
        (None, ExecutionStatus::Failed) => "failed",
        (None, ExecutionStatus::Waiting) => "waiting",
        _ => "node_event",
    };
    let redacted_log_message = event.log_message.as_deref().map(|m| {
        let truncated: &str = if m.len() > 8192 {
            talos_text_util::truncate_at_char_boundary(m, 8192)
        } else {
            m
        };
        talos_dlp_provider::redact_str(truncated)
    });
    // Bare pool by design: execution_id is owned by the authenticated user
    // via the test row test_workflow INSERTed before this detached task ran.
    if let Err(db_err) = talos_execution_repository::ExecutionRepository::new(db_pool.clone())
        .insert_execution_event(
            event.execution_id,
            event_type,
            event.node_id,
            &format!("{:?}", event.status),
            redacted_log_message.as_deref(),
            None,
            None,
        )
        .await
    {
        tracing::error!(
            execution_id = %event.execution_id,
            error = %db_err,
            "test_workflow: failed to persist execution event"
        );
    }
}

/// Finalize a test execution as `failed` (status-guarded) and broadcast +
/// persist a terminal Failed event. Used by `test_workflow`'s detached run so a
/// build or run error can never leave the row stuck in `running` (the bug this
/// refactor closes). `message` MUST already be DLP-redacted if it derives from
/// engine / node output — callers redact before invoking; static strings are safe.
async fn mark_test_execution_failed(
    db_pool: &sqlx::Pool<sqlx::Postgres>,
    sender: &tokio::sync::broadcast::Sender<ExecutionEvent>,
    execution_id: Uuid,
    message: &str,
) {
    // Bare pool by design: execution_id was INSERTed under the authenticated
    // user_id by test_workflow before this detached task ran, for a workflow
    // gated by workflow_accessible_for_user; revisit on RLS SET-ROLE rollout.
    // The repo method carries the terminal-status guard (check 39).
    if let Err(db_err) = talos_execution_repository::ExecutionRepository::new(db_pool.clone())
        .fail_execution_unless_terminal(execution_id, message, true)
        .await
    {
        tracing::error!(
            execution_id = %execution_id,
            error = %db_err,
            "test_workflow: failed to mark execution failed"
        );
    }
    persist_and_broadcast_test_event(
        db_pool,
        sender,
        ExecutionEvent {
            execution_id,
            node_id: None,
            status: ExecutionStatus::Failed,
            trace_id: None,
            span_id: None,
            log_message: Some(message.to_string()),
            iteration_index: None,
            iteration_total: None,
            duration_ms: None,
            output: None,
        },
    )
    .await;
}

// `release_advisory_lock` moved to `talos_db::release_advisory_lock`
// (check-50 extraction) — the MCP-702 detach-on-unlock-failure rationale
// lives on the canonical helper.

/// Project the typed `CreateFromDescriptionOutcome` from the workflow
/// creation service into the GraphQL response shape. The MCP handler
/// projects the same enum into JSON-RPC text; this projection lives
/// here because GraphQL has stronger typing requirements (every
/// field is on the result schema). Pure function — no I/O.
fn map_create_outcome(
    outcome: talos_workflow_creation::CreateFromDescriptionOutcome,
) -> CreateWorkflowFromDescriptionResult {
    use talos_workflow_creation::CreateFromDescriptionOutcome as O;

    let empty = CreateWorkflowFromDescriptionResult {
        success: false,
        workflow_id: None,
        scaffolded_by: "none".to_string(),
        name: None,
        reasoning: None,
        unresolved_modules: None,
        modules_not_compiled: None,
        suggested_schedule: None,
        error_class: None,
        error_message: None,
        llm_error_class: None,
    };

    match outcome {
        O::LlmScaffold(boxed) => {
            // Deref the Box once so we can move fields out of the
            // owned LlmScaffoldOutcome below. The variant is boxed
            // (clippy::large_enum_variant) because it carries 13
            // fields totaling ~344 bytes.
            let s = *boxed;
            CreateWorkflowFromDescriptionResult {
                success: true,
                workflow_id: Some(s.workflow_id),
                scaffolded_by: "llm".to_string(),
                name: Some(s.suggested_name),
                reasoning: Some(s.reasoning),
                unresolved_modules: if s.unresolved_modules.is_empty() {
                    None
                } else {
                    Some(s.unresolved_modules)
                },
                modules_not_compiled: if s.modules_not_compiled.is_empty() {
                    None
                } else {
                    Some(s.modules_not_compiled)
                },
                suggested_schedule: s.suggested_schedule,
                ..empty
            }
        }
        O::ExplicitModuleScaffold(e) => CreateWorkflowFromDescriptionResult {
            success: true,
            workflow_id: Some(e.workflow_id),
            scaffolded_by: "explicit_modules".to_string(),
            name: Some(e.workflow_name),
            ..empty
        },
        O::LlmIncomplete => CreateWorkflowFromDescriptionResult {
            error_class: Some("llm_incomplete".to_string()),
            error_message: Some(
                "LLM scaffold returned an incomplete response. Try again with a more specific description."
                    .to_string(),
            ),
            ..empty
        },
        O::LlmInvalidJson { .. } => CreateWorkflowFromDescriptionResult {
            error_class: Some("llm_invalid_json".to_string()),
            error_message: Some(
                "LLM scaffold returned an unparseable response. Try again, or simplify your description."
                    .to_string(),
            ),
            ..empty
        },
        O::LlmCallFailed { class, detail } => CreateWorkflowFromDescriptionResult {
            error_class: Some("llm_failed".to_string()),
            llm_error_class: Some(class.tag().to_string()),
            error_message: Some(detail),
            ..empty
        },
        O::NoLlmAndNoExplicit => CreateWorkflowFromDescriptionResult {
            error_class: Some("no_llm_and_no_explicit".to_string()),
            error_message: Some(
                "AI-powered scaffolding requires ANTHROPIC_API_KEY, or pass explicit module IDs."
                    .to_string(),
            ),
            ..empty
        },
        O::NoMatchedModules {
            available_template_count,
        } => CreateWorkflowFromDescriptionResult {
            error_class: Some("no_matched_modules".to_string()),
            error_message: Some(format!(
                "None of the provided module_ids were found in the catalog ({} templates available).",
                available_template_count
            )),
            ..empty
        },
    }
}

#[cfg(test)]
mod create_outcome_projection_tests {
    //! Defends the GraphQL projection against drift. Every variant
    //! of `CreateFromDescriptionOutcome` must map to a populated
    //! `CreateWorkflowFromDescriptionResult` whose `success` flag,
    //! `scaffolded_by` tag, and (where applicable) `error_class` are
    //! the values agents and the UI branch on. If a future variant
    //! is added to the service enum, the exhaustive match in
    //! `map_create_outcome` becomes a compile error here too — so
    //! these tests double as a "did you forget to update the
    //! projection" canary.

    use super::*;
    use talos_workflow_creation::{
        CreateFromDescriptionOutcome, ExplicitModuleOutcome, LlmErrorClass, LlmScaffoldOutcome,
        ResolvedNode,
    };

    fn fake_llm_outcome() -> LlmScaffoldOutcome {
        LlmScaffoldOutcome {
            workflow_id: Uuid::new_v4(),
            suggested_name: "n".into(),
            reasoning: "r".into(),
            suggested_schedule: Some("0 9 * * *".into()),
            suggested_error_handling: serde_json::json!([]),
            resolved_nodes: vec![ResolvedNode {
                label: "L".into(),
                template_id: Uuid::new_v4(),
                module_name: "m".into(),
            }],
            unresolved_modules: vec!["foo".into()],
            modules_not_compiled: vec!["bar".into()],
            graph_nodes: vec![],
            graph_edges: vec![],
            entry_node_warnings: vec![],
            node_configs_needed: vec![],
            schema_map: Default::default(),
            name_collision_count: 0,
        }
    }

    #[test]
    fn llm_scaffold_maps_to_success() {
        let r = map_create_outcome(CreateFromDescriptionOutcome::LlmScaffold(Box::new(
            fake_llm_outcome(),
        )));
        assert!(r.success);
        assert_eq!(r.scaffolded_by, "llm");
        assert!(r.workflow_id.is_some());
        assert_eq!(
            r.unresolved_modules.as_deref(),
            Some(&["foo".to_string()][..])
        );
        assert_eq!(r.suggested_schedule.as_deref(), Some("0 9 * * *"));
        assert!(r.error_class.is_none());
    }

    #[test]
    fn llm_scaffold_with_no_unresolved_omits_field() {
        let mut s = fake_llm_outcome();
        s.unresolved_modules = vec![];
        s.modules_not_compiled = vec![];
        let r = map_create_outcome(CreateFromDescriptionOutcome::LlmScaffold(Box::new(s)));
        assert!(r.unresolved_modules.is_none());
        assert!(r.modules_not_compiled.is_none());
    }

    #[test]
    fn explicit_module_maps_to_success() {
        let wf_id = Uuid::new_v4();
        let r = map_create_outcome(CreateFromDescriptionOutcome::ExplicitModuleScaffold(
            ExplicitModuleOutcome {
                workflow_id: wf_id,
                workflow_name: "name".into(),
                matched_templates: vec![],
                ready_to_run: true,
                missing_config: vec![],
                required_secrets: vec![],
            },
        ));
        assert!(r.success);
        assert_eq!(r.scaffolded_by, "explicit_modules");
        assert_eq!(r.workflow_id, Some(wf_id));
    }

    #[test]
    fn llm_incomplete_maps_to_error_class() {
        let r = map_create_outcome(CreateFromDescriptionOutcome::LlmIncomplete);
        assert!(!r.success);
        assert_eq!(r.error_class.as_deref(), Some("llm_incomplete"));
        assert!(r.workflow_id.is_none());
    }

    #[test]
    fn llm_invalid_json_maps_to_error_class() {
        let r = map_create_outcome(CreateFromDescriptionOutcome::LlmInvalidJson {
            detail: "oops".into(),
        });
        assert_eq!(r.error_class.as_deref(), Some("llm_invalid_json"));
    }

    #[test]
    fn llm_call_failed_carries_subclass() {
        let r = map_create_outcome(CreateFromDescriptionOutcome::LlmCallFailed {
            class: LlmErrorClass::RateLimited,
            detail: "429".into(),
        });
        assert_eq!(r.error_class.as_deref(), Some("llm_failed"));
        assert_eq!(r.llm_error_class.as_deref(), Some("rate_limited"));
        assert_eq!(r.error_message.as_deref(), Some("429"));
    }

    #[test]
    fn no_llm_and_no_explicit_maps_to_error_class() {
        let r = map_create_outcome(CreateFromDescriptionOutcome::NoLlmAndNoExplicit);
        assert_eq!(r.error_class.as_deref(), Some("no_llm_and_no_explicit"));
    }

    #[test]
    fn no_matched_modules_includes_count_in_message() {
        let r = map_create_outcome(CreateFromDescriptionOutcome::NoMatchedModules {
            available_template_count: 17,
        });
        assert_eq!(r.error_class.as_deref(), Some("no_matched_modules"));
        assert!(r.error_message.unwrap().contains("17 templates"));
    }
}
