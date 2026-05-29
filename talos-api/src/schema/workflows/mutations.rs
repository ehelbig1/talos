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
    require_2fa, require_scope, sync_workflow_module_refs,
    validate_max_concurrent_executions, validate_payload_size, validate_resource_name,
    SafeErrorExtensions,
};
use talos_engine::checkpoint_store::{
    load_checkpoint_for_full, ControllerCheckpointStore,
};
use talos_engine::events::{ExecutionEvent, ExecutionStatus};
use talos_registry::ModuleRegistry;
use talos_workflow_engine_core::WorkerSharedKey;
use talos_workflow_versions::WorkflowVersionService;
use worker::runtime::TalosRuntime;

/// Saturating u32→i32 conversion for `execution_events.iteration_index`
/// / `iteration_total` columns (Postgres `int4`). Defense in depth on
/// the WRITE boundary — the read boundary already saturates with
/// `.max(0) as u32` (MCP-961). Source is `Option<u32>` from
/// `talos_engine_events::NodeEventWrite`; the engine is internal and
/// emits non-pathological counters today, but a future producer (or a
/// manual row-write) exceeding `i32::MAX` (~2.1B) would silently land
/// as a negative iteration index. Saturate to MAX so the dashboard
/// renders an operator-recognisably absurd value rather than a
/// nonsensical negative counter.
fn saturating_u32_to_i32(v: u32) -> i32 {
    i32::try_from(v).unwrap_or(i32::MAX)
}

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
        let execution_id = Uuid::new_v4();
        let sender = ctx
            .data::<tokio::sync::broadcast::Sender<ExecutionEvent>>()?
            .clone();
        let nats_client = ctx
            .data_opt::<Option<Arc<async_nats::Client>>>()
            .cloned()
            .flatten()
            .ok_or_else(|| async_graphql::Error::new("NATS client not available").extend_safe())?;
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
        let _runtime = ctx.data::<Arc<TalosRuntime>>()?.clone();

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
            return Err(async_graphql::Error::new(
                "Workflow not found or access denied",
            ).extend_safe());
        }

        // Pre-load the graph_json synchronously so trigger-time
        // authorization can re-verify the actor's capability ceiling
        // against the actual modules in the graph (post-create graph
        // edits would otherwise slip past the create-time gate). This
        // also lets `authorize_workflow_trigger` run before the
        // concurrency-limit transaction below — failing fast on auth
        // errors before any execution row is created.
        let pre_loaded_graph: Option<(String, Option<Uuid>)> =
            match WorkflowVersionService::get_active_version(&db_pool, workflow_id).await {
                Ok(Some(version)) => Some((version.graph_json.to_string(), Some(version.id))),
                _ => match sqlx::query_scalar::<_, String>(
                    "SELECT graph_json FROM workflows WHERE id = $1",
                )
                .bind(workflow_id)
                .fetch_optional(&db_pool)
                .await
                {
                    Ok(Some(g)) => Some((g, None)),
                    Ok(None) => None,
                    Err(e) => {
                        tracing::error!("Failed to load workflow graph for auth: {}", e);
                        return Err(
                            async_graphql::Error::new("Failed to check workflow").extend_safe()
                        );
                    }
                },
            };

        // Trigger-time authorization. Mirrors the MCP `trigger_workflow`
        // path (see CLAUDE.md "GraphQL handlers must mirror MCP RBAC
        // checks"): the inline `SELECT status FROM actors WHERE
        // id = $1 AND user_id = $2` probe was insufficient — it caught
        // ownership + terminal state but skipped (a) suspended-via-budget
        // gating and (b) capability-ceiling re-verification against the
        // graph's modules. r292 closed the same drift on a different
        // surface; this is the trigger-side parity fix.
        if let Some((ref graph_json_for_auth, _version_id)) = pre_loaded_graph {
            use talos_workflow_authorization::{authorize_workflow_trigger, TriggerAuthError};
            let workflow_repo =
                talos_workflow_repository::WorkflowRepository::new(db_pool.clone());
            let actor_repo_for_auth =
                talos_actor_repository::ActorRepository::new(db_pool.clone());
            match authorize_workflow_trigger(
                &workflow_repo,
                &actor_repo_for_auth,
                &db_pool,
                actor_id,
                *user_id,
                graph_json_for_auth,
            )
            .await
            {
                Ok(_) => {}
                // MCP-916 (2026-05-14): every actionable TriggerAuthError
                // variant marked `.extend_safe()` so the production error
                // scrubber doesn't replace them with "Internal server
                // error". "Actor is archived/terminated" and the
                // capability-ceiling diagnostic have no overlap with the
                // production-mode substring whitelist (Authentication /
                // Access denied / Not found / Invalid / Validation /
                // Unauthorized — see controller/main.rs:4999) — without
                // the explicit safe-marker, operators triggering a
                // workflow with an archived actor saw "Internal server
                // error" with no clue why. Database variant intentionally
                // stays unmarked: the inner sqlx::Error is logged
                // server-side and the generic outer message is correct
                // for the client.
                Err(TriggerAuthError::ActorNotFoundOrInactive) => {
                    return Err(async_graphql::Error::new(
                        "Actor not found or access denied",
                    ).extend_safe());
                }
                Err(TriggerAuthError::ActorArchived) => {
                    return Err(async_graphql::Error::new(
                        "Actor is archived — terminal state, cannot dispatch executions.",
                    ).extend_safe());
                }
                Err(TriggerAuthError::ActorTerminated) => {
                    return Err(async_graphql::Error::new(
                        "Actor is terminated — terminal state, cannot dispatch executions.",
                    ).extend_safe());
                }
                Err(TriggerAuthError::ExecutionDenied(msg)) => {
                    // user-facing message from check_execution_allowed
                    // (budget/status). Surface verbatim — same as MCP.
                    return Err(async_graphql::Error::new(msg).extend_safe());
                }
                Err(TriggerAuthError::CapabilityCeilingViolation {
                    module_world,
                    max_world,
                    ..
                }) => {
                    return Err(async_graphql::Error::new(format!(
                        "Workflow contains a module that exceeds the actor's capability \
                         ceiling: module requires `{module_world}`, actor max is `{max_world}`. \
                         Lower the workflow's capability requirement or grant the actor a \
                         higher ceiling via `grant_capability_ceiling`."
                    )).extend_safe());
                }
                Err(TriggerAuthError::Database(e)) => {
                    tracing::error!("Trigger authorization DB error: {}", e);
                    return Err(
                        async_graphql::Error::new("Internal database error").extend_safe()
                    );
                }
            }
        }

        // Per-workflow concurrency limit check + execution INSERT via the
        // canonical TOCTOU-safe entry point in `talos_workflow_repository`.
        // L T6-1: pre-extraction this resolver duplicated the `SELECT …
        // FOR UPDATE` + COUNT + INSERT block inline; the canonical method
        // also gates on `(workflow_id, user_id)` ownership and on
        // `parent_execution_id` lineage when supplied (defense-in-depth
        // T5-N3 / T7-N1). The asymmetry vs MCP — `'queued'` instead of
        // `'running'` — is preserved via the typed `InitialExecutionStatus`
        // enum: GraphQL spawns dispatch in a `tokio::spawn` so the row
        // must not advertise `'running'` until the engine actually
        // receives the JobRequest.
        let workflow_repo = talos_workflow_repository::WorkflowRepository::new(db_pool.clone());
        match workflow_repo
            .create_execution_under_concurrency_limit(
                execution_id,
                workflow_id,
                *user_id,
                None,
                None,
                actor_id,
                None,
                None,
                None,
                talos_workflow_repository::InitialExecutionStatus::Queued,
            )
            .await
        {
            Ok(talos_workflow_repository::ConcurrencyAdmission::Created) => {}
            Ok(talos_workflow_repository::ConcurrencyAdmission::LimitReached {
                limit,
                running,
            }) => {
                return Err(async_graphql::Error::new(format!(
                    "Workflow has reached its concurrency limit ({running} running, max {limit}). \
                     Wait for running executions to complete or increase the limit."
                ))
                .extend_safe());
            }
            Err(e) => {
                tracing::error!("Failed to create execution: {}", e);
                return Err(
                    async_graphql::Error::new("Internal database error").extend_safe()
                );
            }
        }

        let user_id = *user_id;
        tokio::spawn(async move {
            // Distributed lock at the start of the background task
            let mut conn = match db_pool.acquire().await {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!("Failed to acquire DB connection for locking: {}", e);
                    return;
                }
            };

            // Use hash of workflow_id for advisory lock so concurrent executions of the
            // same workflow are serialized (not execution_id which is unique per run).
            let lock_id = (workflow_id.as_u128() % (i64::MAX as u128)) as i64;

            // Try to acquire the lock
            let locked: bool =
                match sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_lock($1)")
                    .bind(lock_id)
                    .fetch_one(&mut *conn)
                    .await
                {
                    Ok(l) => l,
                    Err(e) => {
                        tracing::error!("Failed to acquire advisory lock: {}", e);
                        false
                    }
                };

            if !locked {
                tracing::warn!(execution_id = %execution_id, "Execution already in progress, skipping duplicate trigger");
                return;
            }

            // Create secrets_manager with proper error handling.
            // allow-secrets-manager-new: defensive fallback. Production
            // GraphQL context always supplies the shared instance via
            // schema.data::<Arc<SecretsManager>>(); this branch only
            // fires in dev/test paths that don't wire it. Carries the
            // KEK-mismatch risk documented on subworkflow_contract_service
            // — if it ever fires in production, that's the bug.
            let secrets_manager = match secrets_manager {
                Some(sm) => sm,
                None => match talos_secrets_manager::SecretsManager::new(db_pool.clone()) {
                    Ok(sm) => Arc::new(sm),
                    Err(e) => {
                        tracing::error!("Failed to create SecretsManager: {}", e);
                        return;
                    }
                },
            };

            // The engine is built AFTER the graph fetch below. Pre-r227 it
            // was built here and then load_graph_from_json was called later
            // — but that pattern dropped the graph's execution_timeout_secs
            // (same regression class r225 fixed for the scheduler). Routing
            // through `for_workflow` requires the graph_json upfront, so the
            // build moves down. Materialise the inputs here so the move
            // doesn't change behavior beyond the timeout fix.
            let resolved_registry = registry
                .unwrap_or_else(|| Arc::new(ModuleRegistry::new(db_pool.clone(), redis_client)));

            // Load checkpoint if exists. MCP-684 (2026-05-13): also pass
            // a SecretsManager clone so a Phase A deployment without
            // WORKER_SHARED_KEY can still resume by decrypting
            // `output_data_enc` (the mark_execution_waiting payload).
            let initial_results = load_checkpoint_for_full(
                &db_pool,
                worker_shared_key.as_ref().map(WorkerSharedKey::as_bytes),
                Some(secrets_manager.clone()),
                execution_id,
            )
            .await;

            // Helper macro to store event in database AND broadcast
            macro_rules! store_and_send {
                ($event:expr) => {{
                    let event = $event;
                    // Store in database for audit trail and replay
                    let event_type = match (&event.node_id, &event.status) {
                        (None, ExecutionStatus::Running) => "started",
                        (Some(_), ExecutionStatus::Running) => "node_started",
                        (Some(_), ExecutionStatus::Completed) => "node_completed",
                        (Some(_), ExecutionStatus::Failed) => "node_failed",
                        (Some(_), ExecutionStatus::Skipped) => "node_skipped",
                        (None, ExecutionStatus::Completed) => "completed",
                        (None, ExecutionStatus::Failed) => "failed",
                        (None, ExecutionStatus::Pending) => "pending",
                        (Some(_), ExecutionStatus::Pending) => "pending",
                        (None, ExecutionStatus::Skipped) => "skipped",
                        (Some(_), ExecutionStatus::Waiting) => "node_waiting",
                        (None, ExecutionStatus::Waiting) => "waiting",
                        (_, ExecutionStatus::OutputReady) => "output_ready",
                    };

                    // Broadcast to subscriptions FIRST so live subscribers get the event
                    // even if the database persistence fails.
                    //
                    // MCP-853 (2026-05-14): trigger_workflow sibling of
                    // MCP-852. Pre-fix this site fired
                    // `info!("sending event: {:?}", event)` for EVERY
                    // event broadcast (node_started / node_completed /
                    // node_failed / ...). Same PII concern: the
                    // `log_message` field on ExecutionEvent is arbitrary
                    // workflow-node output (HTTP response bodies, raw
                    // error text, partial user input) with NO DLP
                    // redaction at log time. The sibling resume_workflow
                    // macro (~line 911) already omits this debug log;
                    // bringing trigger_workflow in line. If a future
                    // operator needs per-event tracing, use the
                    // structured `tracing::trace!` shape MCP-852
                    // adopted in the subscription resolver.
                    let _ = sender.send(event.clone());

                    // MCP-965 (2026-05-15): DLP-redact log_message
                    // before persistence. Pre-fix `event.log_message`
                    // (arbitrary node-emitted text — HTTP response
                    // bodies, error strings echoing Authorization
                    // headers, partial outputs from misconfigured
                    // workflows) was bound directly into INSERT, so
                    // secrets matching the canonical patterns (`sk-*`,
                    // `ghp_*`, Bearer tokens) leaked into the DB.
                    // The sibling output-data redaction pattern lives
                    // at line ~550 (`talos_dlp_provider::redact_json`
                    // on `aggregated_output`); this is the matching
                    // event-side redaction. Same scope as MCP-466 /
                    // MCP-481-484 persistence-boundary DLP sweep.
                    //
                    // MCP-1194 (2026-05-17): truncate-then-redact
                    // discipline. Sibling holdout to MCP-1165 which
                    // closed the same gap on the engine-side
                    // `event_sink.rs` execution_events writer. The
                    // engine-emitted `log_message: Option<String>` is
                    // unbounded — node errors echo HTTP response
                    // bodies (multi-MB possible), retry reasons echo
                    // wasmtime traces. Pre-fix the regex pass walked
                    // the entire string AND the unbounded result
                    // landed in `execution_events.log_message` with
                    // no DB-side length cap. 8 KiB matches the
                    // canonical MCP-1165 cap.
                    let redacted_log_message = event.log_message.as_deref().map(|m| {
                        let truncated: &str = if m.len() > 8192 {
                            talos_text_util::truncate_at_char_boundary(m, 8192)
                        } else {
                            m
                        };
                        talos_dlp_provider::redact_str(truncated)
                    });
                    // Then persist for replay
                    if let Err(db_err) = sqlx::query(
                        r#"
                        INSERT INTO execution_events (execution_id, event_type, node_id, status, log_message, iteration_index, iteration_total)
                        VALUES ($1, $2, $3, $4, $5, $6, $7)
                        "#
                    )
                    .bind(event.execution_id)
                    .bind(event_type)
                    .bind(event.node_id)
                    .bind(format!("{:?}", event.status))
                    .bind(&redacted_log_message)
                    .bind(event.iteration_index.map(saturating_u32_to_i32))
                    .bind(event.iteration_total.map(saturating_u32_to_i32))
                    .execute(&db_pool)
                    .await {
                        tracing::error!("Failed to persist execution event: {}", db_err);
                    }
                }};
            }

            // Fetch workflow definition: prefer active published version, fall back to draft
            #[derive(sqlx::FromRow)]
            struct WorkflowGraph {
                graph_json: String,
            }

            // Check for an active published version first
            let (graph_json_str, version_id) = match WorkflowVersionService::get_active_version(
                &db_pool,
                workflow_id,
            )
            .await
            {
                Ok(Some(version)) => {
                    tracing::info!(
                        workflow_id = %workflow_id,
                        version = version.version_number,
                        "Using published version for execution"
                    );
                    (version.graph_json.to_string(), Some(version.id))
                }
                _ => {
                    // Fall back to draft graph_json from workflows table
                    match sqlx::query_as::<_, WorkflowGraph>(
                        "SELECT graph_json FROM workflows WHERE id = $1 AND user_id = $2",
                    )
                    .bind(workflow_id)
                    .bind(user_id)
                    .fetch_one(&db_pool)
                    .await
                    {
                        Ok(w) => (w.graph_json, None),
                        Err(e) => {
                            tracing::error!(execution_id = %execution_id, "Failed to load workflow: {}", e);
                            let error_msg = "Workflow execution failed".to_string();
                            if let Err(db_err) = sqlx::query(
                                "UPDATE workflow_executions SET status = 'failed', completed_at = NOW(), error_message = $2 WHERE id = $1"
                            )
                            .bind(execution_id)
                            .bind(&error_msg)
                            .execute(&db_pool)
                            .await {
                                tracing::error!("Database operation failed in schema: {}", db_err);
                            }

                            let event = ExecutionEvent {
                                execution_id,
                                node_id: None,
                                status: ExecutionStatus::Failed,
                                trace_id: None,
                                span_id: None,
                                log_message: Some(error_msg),
                                iteration_index: None,
                                iteration_total: None,
                                duration_ms: None,
                                output: None,
                            };
                            store_and_send!(event);
                            release_advisory_lock(conn, lock_id).await;
                            return;
                        }
                    }
                }
            };

            // Store the workflow_version_id on the execution record (best-effort)
            if let Some(vid) = version_id {
                if let Err(db_err) = sqlx::query(
                    "UPDATE workflow_executions SET workflow_version_id = $2 WHERE id = $1",
                )
                .bind(execution_id)
                .bind(vid)
                .execute(&db_pool)
                .await
                {
                    tracing::warn!(
                        "Failed to store workflow_version_id on execution: {}",
                        db_err
                    );
                }
            }

            // Build the engine via the canonical builder. TimeoutPolicy::Honor
            // closes a latent bug: pre-r227 this site never set
            // execution_timeout_secs at all, so a workflow with
            // `execution_timeout_secs: 60` in graph_json was silently using
            // the engine compile-time default (300 s) when triggered via
            // GraphQL — same regression class r225 fixed for the scheduler.
            //
            // Actor-binding semantic preserved: this path uses the
            // caller-supplied `actor_id` arg only and does NOT fall back
            // to the workflow's default (asymmetric vs MCP trigger_workflow,
            // see docs/engine-builder-refactor-plan.md "Open questions" #3).
            let actor_repo = Arc::new(talos_actor_repository::ActorRepository::new(
                db_pool.clone(),
            ));
            let mut opts = talos_engine::builder::EngineOpts::for_run(workflow_id, graph_json_str);
            if let Some(aid) = actor_id {
                opts = opts.with_actor_id(aid);
            }
            // MCP-682 (2026-05-13): retain a SecretsManager clone for the
            // post-run persistence step. Pre-fix the engine consumed the
            // Arc at builder time, and the final UPDATE statement wrote
            // plaintext `output_data = $2` via raw SQL — bypassing
            // Phase A encryption for every GraphQL-triggered workflow.
            // Route the completion/waiting writes through
            // `WorkflowRepository::mark_execution_{completed,waiting}`
            // so the encryption-aware branch (output_data NULL +
            // output_data_enc filled) fires on production deployments.
            let sm_for_persist = secrets_manager.clone();
            let engine = match talos_engine::builder::for_workflow(
                resolved_registry,
                secrets_manager,
                actor_repo,
                user_id,
                opts,
            )
            .await
            {
                Ok(e) => e,
                Err(e) => {
                    tracing::error!(execution_id = %execution_id, "Failed to build engine: {}", e);
                    let error_msg = "Workflow execution failed".to_string();
                    if let Err(db_err) = sqlx::query(
                        "UPDATE workflow_executions SET status = 'failed', completed_at = NOW(), error_message = $2 WHERE id = $1"
                    )
                    .bind(execution_id)
                    .bind(&error_msg)
                    .execute(&db_pool)
                    .await
                    {
                        tracing::error!("Database operation failed in schema: {}", db_err);
                    }

                    let event = ExecutionEvent {
                        execution_id,
                        node_id: None,
                        status: ExecutionStatus::Failed,
                        trace_id: None,
                        span_id: None,
                        log_message: Some(error_msg),
                        iteration_index: None,
                        iteration_total: None,
                        duration_ms: None,
                        output: None,
                    };
                    store_and_send!(event);
                    release_advisory_lock(conn, lock_id).await;
                    return;
                }
            };

            // Execute workflow
            let wsk_for_checkpoint = worker_shared_key.clone();
            match talos_engine::nats_run::run_with_seed_via_nats(
                &engine,
                nats_client.clone(),
                worker_shared_key,
                initial_results,
                execution_id,
            )
            .await
            {
                Ok(ctx) => {
                    // Convert entire ctx.results hashmap to JSON to save on the workflow_execution
                    let mut aggregated_output = serde_json::Map::new();
                    for (node_id, output) in &ctx.results {
                        aggregated_output.insert(node_id.to_string(), output.clone());
                    }
                    let aggregated_json = talos_dlp_provider::redact_json(
                        &serde_json::Value::Object(aggregated_output),
                    );

                    // Enforce output size limit to prevent DoS via unbounded DB writes
                    const MAX_AGGREGATED_OUTPUT_BYTES: usize = 50 * 1024 * 1024; // 50 MB
                    match serde_json::to_string(&aggregated_json) {
                        Ok(json_str) if json_str.len() > MAX_AGGREGATED_OUTPUT_BYTES => {
                            tracing::error!(
                                execution_id = %execution_id,
                                output_bytes = json_str.len(),
                                "Workflow output exceeds 50 MB limit"
                            );
                            if let Err(e) = sqlx::query(
                                "UPDATE workflow_executions SET status = 'failed', completed_at = NOW(), error_message = $2 WHERE id = $1"
                            )
                            .bind(execution_id)
                            .bind("Workflow output exceeds size limit")
                            .execute(&db_pool)
                            .await {
                                tracing::error!(
                                    execution_id = %execution_id,
                                    error = %e,
                                    "Failed to mark execution as failed (size-limit path) — \
                                     execution will appear stuck in 'running' state"
                                );
                            }
                            return;
                        }
                        Err(e) => {
                            tracing::error!(execution_id = %execution_id, "Failed to serialize workflow output: {}", e);
                        }
                        Ok(_) => {}
                    }

                    // Update execution status. MCP-682: encryption-aware
                    // repository writes so Phase A deployments persist
                    // ciphertext, not plaintext.
                    let wf_repo =
                        talos_workflow_repository::WorkflowRepository::new(db_pool.clone())
                            .with_encryption(sm_for_persist.clone());
                    if ctx.waiting {
                        if let Err(db_err) = wf_repo
                            .mark_execution_waiting(execution_id, &aggregated_json)
                            .await
                        {
                            tracing::error!("Database operation failed in schema: {}", db_err);
                        }
                        // Also persist an encrypted copy of the checkpoint for defense-in-depth.
                        let store = ControllerCheckpointStore::new(
                            db_pool.clone(),
                            wsk_for_checkpoint.as_ref().map(|k| k.as_bytes().to_vec()),
                        );
                        if let Err(e) = talos_workflow_engine_core::CheckpointStore::save(
                            &store,
                            execution_id,
                            &aggregated_json,
                        )
                        .await
                        {
                            tracing::warn!(
                                %execution_id,
                                error = %e,
                                "Failed to persist encrypted checkpoint — resume will rely on plain output_data fallback",
                            );
                        }
                    } else if let Err(db_err) = wf_repo
                        .mark_execution_completed(execution_id, &aggregated_json)
                        .await
                    {
                        tracing::error!("Database operation failed in schema: {}", db_err);
                    }

                    let event = ExecutionEvent {
                        execution_id,
                        node_id: None,
                        status: ExecutionStatus::Completed,
                        trace_id: ctx.trace_id,
                        span_id: None,
                        log_message: Some("Workflow finished successfully".to_string()),
                        iteration_index: None,
                        iteration_total: None,
                        duration_ms: None,
                        output: None,
                    };
                    store_and_send!(event);
                }
                Err(e) => {
                    // MCP-969 (2026-05-15): DLP-redact the engine
                    // error before formatting it into the UPDATE
                    // bind. Engine `e.to_string()` carries arbitrary
                    // node-emitted text (HTTP response bodies, upstream
                    // exception messages echoing Authorization headers).
                    // Sibling-class to MCP-967/968 on the
                    // mark_execution_failed paths; matches the
                    // already-correct talos-scheduler:1119 pattern.
                    let redacted_e = talos_dlp_provider::redact_str(&e.to_string());
                    let error_msg = format!("Workflow failed: {}", redacted_e);
                    if let Err(db_err) = sqlx::query(
                        "UPDATE workflow_executions SET status = 'failed', completed_at = NOW(), error_message = $2 WHERE id = $1"
                    )
                    .bind(execution_id)
                    .bind(&error_msg)
                    .execute(&db_pool)
                    .await {
    tracing::error!("Database operation failed in schema: {}", db_err);
}

                    // Note: sending node_id=None signals to the frontend that the *entire workflow* has failed.
                    let event = ExecutionEvent {
                        execution_id,
                        node_id: None,
                        status: ExecutionStatus::Failed,
                        trace_id: None,
                        span_id: None,
                        log_message: Some(error_msg),
                        iteration_index: None,
                        iteration_total: None,
                        duration_ms: None,
                        output: None,
                    };
                    store_and_send!(event);
                }
            }

            // Release the advisory lock on the SAME connection where it was acquired.
            release_advisory_lock(conn, lock_id).await;
        });

        let now = Utc::now().to_rfc3339();
        Ok(WorkflowExecution {
            id: execution_id,
            workflow_id,
            status: "pending".to_string(),
            started_at: now.clone(),
            completed_at: None,
            error_message: None,
            created_at: now,
            duration_ms: None,
            output_data: None,
            trigger_type: Some("manual".to_string()),
            actor_id: None,
        })
    }

    async fn resume_workflow(&self, ctx: &Context<'_>, execution_id: Uuid) -> Result<bool> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsWrite)?;

        // Get authenticated user
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;

        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?.clone();
        let sender = ctx
            .data::<tokio::sync::broadcast::Sender<ExecutionEvent>>()?
            .clone();
        let nats_client = ctx
            .data_opt::<Option<Arc<async_nats::Client>>>()
            .cloned()
            .flatten()
            .ok_or_else(|| async_graphql::Error::new("NATS client not available").extend_safe())?;
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
        // 1. Verify user owns the execution and it is currently 'waiting'.
        // MCP-652: also pull `actor_id` so the budget/status gate below
        // can run. Pre-fix this tuple was {workflow_id, status} only —
        // resume bypassed the actor-budget enforcement that
        // continuation-trigger (MCP-564) and retry (MCP-557/MCP-651)
        // both honour. The sibling MCP path `resume_workflow_by_correlation_id`
        // gates via `trigger_continuation_workflow` → `check_execution_allowed`;
        // GraphQL's `resume_workflow(execution_id)` is unique to this
        // surface so the gap had no MCP mirror to compare against.
        #[derive(sqlx::FromRow)]
        struct ExecInfo {
            workflow_id: Uuid,
            status: String,
            actor_id: Option<Uuid>,
        }

        // Include org-owned executions via the parent workflow's org_id.
        // Resume is a write — use role-filtered helper so a Viewer can't
        // resume someone else's suspended execution.
        let org_ids = crate::schema::user_writable_org_ids(ctx).await?;
        let exec_info = sqlx::query_as::<_, ExecInfo>(
            r#"SELECT we.workflow_id, we.status, we.actor_id FROM workflow_executions we
               LEFT JOIN workflows w ON w.id = we.workflow_id
               WHERE we.id = $1 AND (we.user_id = $2 OR w.org_id = ANY($3))"#,
        )
        .bind(execution_id)
        .bind(user_id)
        .bind(&org_ids)
        .fetch_optional(&db_pool)
        .await
        .map_err(|e: sqlx::Error| {
            // Added type annotation
            tracing::error!("Failed to check execution: {}", e);
            // MCP-964: extend_safe so "Execution not found or access
            // denied" survives the scrubber (lowercase 'n' misses
            // case-sensitive whitelist).
            async_graphql::Error::new("Failed to check execution").extend_safe()
        })?
        .ok_or_else(|| {
            async_graphql::Error::new("Execution not found or access denied").extend_safe()
        })?;

        if exec_info.status != "waiting" {
            // MCP-916 cont.: .extend_safe() so the resume-status mismatch
            // surfaces verbatim instead of being scrubbed.
            return Err(async_graphql::Error::new(format!(
                "Execution is in status '{}', not 'waiting'",
                exec_info.status
            )).extend_safe());
        }

        // MCP-652: actor-status/budget gate. While the execution was
        // paused, the operator may have suspended or terminated the
        // bound actor (or its rolling-hour cap may have flipped via
        // other dispatches). Resuming dispatches new engine work — fuel
        // burn, external HTTP, LLM spend — that the actor should not
        // accrue if it is no longer eligible. Gates BEFORE the status
        // transition so a denied resume leaves the execution in
        // 'waiting' (recoverable by un-suspending the actor and re-calling
        // resume), not stuck in 'pending' with no dispatcher behind it.
        //
        // MCP-726 (2026-05-13): upgrade budget-only `check_execution_allowed`
        // to full `authorize_workflow_trigger`. Same capability-ceiling-
        // drift bypass class as MCP-707 (retry/replay) and MCP-708
        // (scheduler/chain-dispatch/continuation-trigger): an operator
        // who downgraded the actor's `max_capability_world` between
        // suspension and resume would otherwise see the resume dispatch
        // proceed with the previously-elevated ceiling. Budget-only is
        // INSUFFICIENT — the canonical full gate also re-checks every
        // module in the graph against the actor's current ceiling.
        //
        // Order matches MCP-707's pattern in replay.rs: load graph
        // FIRST so we have something to gate against, then run the
        // auth gate BEFORE the status UPDATE so a denied resume leaves
        // the row in 'waiting' (recoverable). The full-gate variant
        // returns rich error types; we map them to user-facing strings
        // matching the existing GraphQL convention.
        if let Some(actor_id) = exec_info.actor_id {
            let workflow_repo =
                talos_workflow_repository::WorkflowRepository::new(db_pool.clone());
            let actor_repo_for_gate =
                talos_actor_repository::ActorRepository::new(db_pool.clone());

            let graph_json = match workflow_repo
                .get_active_version_graph(exec_info.workflow_id, *user_id)
                .await
            {
                Ok(Some((g, _version_id))) => g,
                Ok(None) => {
                    return Err(async_graphql::Error::new(
                        "Workflow graph not found for execution",
                    )
                    .extend_safe());
                }
                Err(e) => {
                    tracing::error!(
                        execution_id = %execution_id,
                        error = %e,
                        "resume_workflow: graph load failed"
                    );
                    return Err(async_graphql::Error::new("Database error").extend_safe());
                }
            };

            match talos_workflow_authorization::authorize_workflow_trigger(
                &workflow_repo,
                &actor_repo_for_gate,
                &db_pool,
                Some(actor_id),
                *user_id,
                &graph_json,
            )
            .await
            {
                Ok(_) => {}
                Err(talos_workflow_authorization::TriggerAuthError::ActorArchived) => {
                    return Err(async_graphql::Error::new(
                        "Cannot resume — owning actor is archived",
                    )
                    .extend_safe());
                }
                Err(talos_workflow_authorization::TriggerAuthError::ActorTerminated) => {
                    return Err(async_graphql::Error::new(
                        "Cannot resume — owning actor is terminated",
                    )
                    .extend_safe());
                }
                Err(talos_workflow_authorization::TriggerAuthError::ActorNotFoundOrInactive) => {
                    return Err(async_graphql::Error::new(
                        "Cannot resume — owning actor not found, not active, or belongs to a different user",
                    )
                    .extend_safe());
                }
                Err(talos_workflow_authorization::TriggerAuthError::ExecutionDenied(msg)) => {
                    return Err(async_graphql::Error::new(msg).extend_safe());
                }
                Err(talos_workflow_authorization::TriggerAuthError::CapabilityCeilingViolation {
                    module_id,
                    module_world,
                    max_world,
                    ..
                }) => {
                    tracing::warn!(
                        execution_id = %execution_id,
                        actor_id = %actor_id,
                        module_id = %module_id,
                        module_world = %module_world,
                        max_world = %max_world,
                        "resume_workflow: BLOCKED — capability ceiling violation (likely ceiling-drift since suspension)"
                    );
                    return Err(async_graphql::Error::new(format!(
                        "Cannot resume — module {} requires '{}' but actor ceiling is '{}'. The actor's capability ceiling was likely downgraded while this execution was suspended.",
                        module_id, module_world, max_world
                    ))
                    .extend_safe());
                }
                Err(talos_workflow_authorization::TriggerAuthError::Database(e)) => {
                    tracing::error!(
                        execution_id = %execution_id,
                        error = %e,
                        "resume_workflow: authorization DB error"
                    );
                    return Err(async_graphql::Error::new("Database error").extend_safe());
                }
            }
        }

        // 2. Update status to 'pending' to allow resumption
        sqlx::query("UPDATE workflow_executions SET status = 'pending' WHERE id = $1")
            .bind(execution_id)
            .execute(&db_pool)
            .await
            .map_err(|e: sqlx::Error| {
                // Added type annotation
                tracing::error!("Failed to update execution status: {}", e);
                async_graphql::Error::new("Failed to resume execution").extend_safe()
            })?;

        // 3. Spawn background resumption (similar to trigger_workflow)
        let user_id = *user_id;
        let workflow_id = exec_info.workflow_id;
        tokio::spawn(async move {
            // Distributed lock
            let mut conn = match db_pool.acquire().await {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!("Failed to acquire DB connection for locking: {}", e);
                    return;
                }
            };
            let lock_id = (execution_id.as_u128() % (i64::MAX as u128)) as i64;
            let locked: bool =
                match sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_lock($1)")
                    .bind(lock_id)
                    .fetch_one(&mut *conn)
                    .await
                {
                    Ok(l) => l,
                    Err(e) => {
                        tracing::error!("Failed to acquire advisory lock: {}", e);
                        false
                    }
                };
            if !locked {
                tracing::warn!(execution_id = %execution_id, "Execution already in progress, skipping duplicate resume");
                return;
            }

            // Create secrets_manager with proper error handling.
            // allow-secrets-manager-new: defensive fallback. Production
            // GraphQL context always supplies the shared instance via
            // schema.data::<Arc<SecretsManager>>(); this branch only
            // fires in dev/test paths that don't wire it. Carries the
            // KEK-mismatch risk documented on subworkflow_contract_service
            // — if it ever fires in production, that's the bug.
            let secrets_manager = match secrets_manager {
                Some(sm) => sm,
                None => match talos_secrets_manager::SecretsManager::new(db_pool.clone()) {
                    Ok(sm) => Arc::new(sm),
                    Err(e) => {
                        tracing::error!("Failed to create SecretsManager: {}", e);
                        return;
                    }
                },
            };

            // Engine is built AFTER graph fetch via for_workflow so the
            // graph's execution_timeout_secs is honored. Pre-r227 the resume
            // path stripped every setter — no actor, no timeout, no
            // actor_context. We preserve the no-actor + no-context posture
            // (worth a separate decision per the refactor plan's open
            // questions) but Honor the graph's timeout, which is the bug-fix
            // theme of PR 3.
            let resume_resolved_registry = registry
                .unwrap_or_else(|| Arc::new(ModuleRegistry::new(db_pool.clone(), redis_client)));

            macro_rules! store_and_send {
                ($event:expr) => {{
                    let event = $event;
                    let event_type = match (&event.node_id, &event.status) {
                        (None, ExecutionStatus::Running) => "started",
                        (Some(_), ExecutionStatus::Running) => "node_started",
                        (Some(_), ExecutionStatus::Completed) => "node_completed",
                        (Some(_), ExecutionStatus::Failed) => "node_failed",
                        (Some(_), ExecutionStatus::Skipped) => "node_skipped",
                        (Some(_), ExecutionStatus::Waiting) => "node_waiting",
                        (None, ExecutionStatus::Completed) => "completed",
                        (None, ExecutionStatus::Failed) => "failed",
                        (None, ExecutionStatus::Waiting) => "waiting",
                        (None, ExecutionStatus::Pending) => "pending",
                        (Some(_), ExecutionStatus::Pending) => "pending",
                        (None, ExecutionStatus::Skipped) => "skipped",
                        (_, ExecutionStatus::OutputReady) => "output_ready",
                    };

                    // Broadcast FIRST so live subscribers get the event
                    let _ = sender.send(event.clone());

                    // MCP-965 (2026-05-15): sibling site to the
                    // trigger_workflow event-persist DLP fix above.
                    // Same redaction discipline applied here so the
                    // resume_workflow path doesn't bypass redaction
                    // when the engine emits sensitive log_message
                    // content during a resumed run.
                    //
                    // MCP-1194 (2026-05-17): truncate-then-redact
                    // discipline applied to the resume_workflow event
                    // writer too. See the trigger_workflow site above
                    // for the full rationale; both sites bind into
                    // the same `execution_events.log_message` column
                    // and need the same 8 KiB ceiling matching the
                    // canonical MCP-1165 fix in engine event_sink.rs.
                    let redacted_log_message = event.log_message.as_deref().map(|m| {
                        let truncated: &str = if m.len() > 8192 {
                            talos_text_util::truncate_at_char_boundary(m, 8192)
                        } else {
                            m
                        };
                        talos_dlp_provider::redact_str(truncated)
                    });
                    if let Err(db_err) = sqlx::query(
                        "INSERT INTO execution_events (execution_id, event_type, node_id, status, log_message, iteration_index, iteration_total) VALUES ($1, $2, $3, $4, $5, $6, $7)"
                    )
                    .bind(event.execution_id)
                    .bind(event_type)
                    .bind(event.node_id)
                    .bind(format!("{:?}", event.status))
                    .bind(&redacted_log_message)
                    .bind(event.iteration_index.map(saturating_u32_to_i32))
                    .bind(event.iteration_total.map(saturating_u32_to_i32))
                    .execute(&db_pool)
                    .await {
                        tracing::error!("Failed to persist execution event: {}", db_err);
                    }
                }};
            }

            // Load checkpoint. MCP-684: DEK-fallback for Phase A
            // deployments without WORKER_SHARED_KEY (same as the
            // triggerWorkflow callsite above).
            let initial_results = load_checkpoint_for_full(
                &db_pool,
                worker_shared_key.as_ref().map(WorkerSharedKey::as_bytes),
                Some(secrets_manager.clone()),
                execution_id,
            )
            .await;

            // Load workflow definition: use the version pinned to this execution,
            // or fall back to active version, then draft
            #[derive(sqlx::FromRow)]
            struct WorkflowGraph {
                graph_json: String,
            }

            // First try to load the version pinned to this execution record.
            //
            // MCP-839 (2026-05-14): propagate the DB error explicitly.
            // Pre-fix `.ok().flatten()` collapsed every failure into
            // None and the next block fell through to the unpinned
            // branch, which loads the ACTIVE version or the DRAFT
            // graph_json. For an execution that WAS pinned at trigger
            // time, that means resuming on a DIFFERENT graph topology
            // than the one the checkpoint references — nodes may have
            // been added/removed, edges rewired. The engine resumes
            // from a checkpoint that points at nodes that don't exist
            // in the loaded graph and either errors opaquely partway
            // through or worse, attributes results to the wrong node.
            // Same graph-topology-drift class as MCP-435. Fail closed
            // on DB error (mark execution failed + return) — the
            // operator can retry once the DB recovers. The execution
            // row already exists at this point (verified above), so
            // sqlx::Error::RowNotFound cannot fire here; this match
            // only handles real connection-level failures.
            let pinned_version_id = match sqlx::query_scalar::<_, Option<Uuid>>(
                "SELECT workflow_version_id FROM workflow_executions WHERE id = $1",
            )
            .bind(execution_id)
            .fetch_one(&db_pool)
            .await
            {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(
                        execution_id = %execution_id,
                        error = %e,
                        "resume_workflow: failed to load pinned workflow_version_id — refusing to fall back to draft graph (would drift execution topology)"
                    );
                    if let Err(db_err) = sqlx::query(
                        "UPDATE workflow_executions SET status = 'failed', error_message = $2 WHERE id = $1"
                    )
                    .bind(execution_id)
                    .bind("Workflow execution failed")
                    .execute(&db_pool)
                    .await
                    {
                        tracing::error!(
                            execution_id = %execution_id,
                            error = %db_err,
                            "Failed to mark execution as failed; execution will appear stuck"
                        );
                    }
                    release_advisory_lock(conn, lock_id).await;
                    return;
                }
            };

            let graph_json_str = if let Some(vid) = pinned_version_id {
                match WorkflowVersionService::get_version(&db_pool, vid).await {
                    Ok(Some(v)) => v.graph_json.to_string(),
                    _ => {
                        match sqlx::query_as::<_, WorkflowGraph>(
                            "SELECT graph_json FROM workflows WHERE id = $1",
                        )
                        .bind(workflow_id)
                        .fetch_one(&db_pool)
                        .await
                        {
                            Ok(w) => w.graph_json,
                            Err(e) => {
                                tracing::error!(execution_id = %execution_id, "Failed to load workflow: {}", e);
                                if let Err(db_err) = sqlx::query("UPDATE workflow_executions SET status = 'failed', error_message = $2 WHERE id = $1")
                                    .bind(execution_id).bind("Workflow execution failed").execute(&db_pool).await {
                                    tracing::error!(
                                        execution_id = %execution_id,
                                        error = %db_err,
                                        "Failed to mark execution as failed; execution will appear stuck"
                                    );
                                }
                                release_advisory_lock(conn, lock_id).await;
                                return;
                            }
                        }
                    }
                }
            } else {
                match WorkflowVersionService::get_active_version(&db_pool, workflow_id).await {
                    Ok(Some(version)) => version.graph_json.to_string(),
                    _ => {
                        match sqlx::query_as::<_, WorkflowGraph>(
                            "SELECT graph_json FROM workflows WHERE id = $1",
                        )
                        .bind(workflow_id)
                        .fetch_one(&db_pool)
                        .await
                        {
                            Ok(w) => w.graph_json,
                            Err(e) => {
                                tracing::error!(execution_id = %execution_id, "Failed to load workflow: {}", e);
                                if let Err(db_err) = sqlx::query("UPDATE workflow_executions SET status = 'failed', error_message = $2 WHERE id = $1")
                                    .bind(execution_id).bind("Workflow execution failed").execute(&db_pool).await {
                                    tracing::error!(
                                        execution_id = %execution_id,
                                        error = %db_err,
                                        "Failed to mark execution as failed; execution will appear stuck"
                                    );
                                }
                                release_advisory_lock(conn, lock_id).await;
                                return;
                            }
                        }
                    }
                }
            };

            // Build the engine via the canonical builder.
            let resume_actor_repo = Arc::new(talos_actor_repository::ActorRepository::new(
                db_pool.clone(),
            ));
            let resume_opts =
                talos_engine::builder::EngineOpts::for_run(workflow_id, graph_json_str);
            // MCP-682 (2026-05-13): preserve a SecretsManager handle for
            // the post-run persistence. Same fix-shape as the
            // triggerWorkflow path above: raw SQL `output_data = $2`
            // bypasses Phase A encryption.
            let resume_sm_for_persist = secrets_manager.clone();
            let engine = match talos_engine::builder::for_workflow(
                resume_resolved_registry,
                secrets_manager,
                resume_actor_repo,
                user_id,
                resume_opts,
            )
            .await
            {
                Ok(e) => e,
                Err(e) => {
                    tracing::error!(execution_id = %execution_id, "Failed to build engine for resume: {}", e);
                    if let Err(db_err) = sqlx::query("UPDATE workflow_executions SET status = 'failed', error_message = $2 WHERE id = $1")
                        .bind(execution_id).bind("Workflow execution failed").execute(&db_pool).await {
                        tracing::error!(
                            execution_id = %execution_id,
                            error = %db_err,
                            "Failed to mark execution as failed (engine-build path); execution will appear stuck"
                        );
                    }
                    release_advisory_lock(conn, lock_id).await;
                    return;
                }
            };

            // Emit resumption event
            store_and_send!(ExecutionEvent {
                execution_id,
                node_id: None,
                status: ExecutionStatus::Running,
                trace_id: None,
                span_id: None,
                log_message: Some("Execution resumed from checkpoint".to_string()),
                iteration_index: None,
                iteration_total: None,
                duration_ms: None,
                output: None,
            });

            // Run engine
            let wsk_for_checkpoint = worker_shared_key.clone();
            match talos_engine::nats_run::run_with_seed_via_nats(
                &engine,
                nats_client,
                worker_shared_key,
                initial_results,
                execution_id,
            )
            .await
            {
                Ok(ctx) => {
                    let mut aggregated_output = serde_json::Map::new();
                    for (node_id, output) in &ctx.results {
                        aggregated_output.insert(node_id.to_string(), output.clone());
                    }
                    let aggregated_json = talos_dlp_provider::redact_json(
                        &serde_json::Value::Object(aggregated_output),
                    );

                    // MCP-682: encryption-aware persistence path.
                    let resume_wf_repo =
                        talos_workflow_repository::WorkflowRepository::new(db_pool.clone())
                            .with_encryption(resume_sm_for_persist.clone());
                    if ctx.waiting {
                        if let Err(db_err) = resume_wf_repo
                            .mark_execution_waiting(execution_id, &aggregated_json)
                            .await
                        {
                            tracing::error!(
                                "Database operation failed in resume_workflow: {}",
                                db_err
                            );
                        }
                        // Also persist an encrypted copy of the checkpoint.
                        let store = ControllerCheckpointStore::new(
                            db_pool.clone(),
                            wsk_for_checkpoint.as_ref().map(|k| k.as_bytes().to_vec()),
                        );
                        if let Err(e) = talos_workflow_engine_core::CheckpointStore::save(
                            &store,
                            execution_id,
                            &aggregated_json,
                        )
                        .await
                        {
                            tracing::warn!(
                                %execution_id,
                                error = %e,
                                "Failed to persist encrypted checkpoint — resume will rely on plain output_data fallback",
                            );
                        }
                    } else {
                        if let Err(db_err) = resume_wf_repo
                            .mark_execution_completed(execution_id, &aggregated_json)
                            .await
                        {
                            tracing::error!(
                                "Database operation failed in resume_workflow: {}",
                                db_err
                            );
                        }

                        store_and_send!(ExecutionEvent {
                            execution_id,
                            node_id: None,
                            status: ExecutionStatus::Completed,
                            trace_id: ctx.trace_id,
                            span_id: None,
                            log_message: Some("Workflow finished successfully".to_string()),
                            iteration_index: None,
                            iteration_total: None,
                            duration_ms: None,
                            output: None,
                        });
                    }
                }
                Err(e) => {
                    // MCP-969 (2026-05-15): see sibling redact at the
                    // trigger_workflow Err arm above. Same engine-error
                    // bind path on the resume side.
                    let redacted_e = talos_dlp_provider::redact_str(&e.to_string());
                    let error_msg = format!("Resumed workflow failed: {}", redacted_e);
                    if let Err(db_err) = sqlx::query("UPDATE workflow_executions SET status = 'failed', completed_at = NOW(), error_message = $2 WHERE id = $1")
                        .bind(execution_id).bind(&error_msg).execute(&db_pool).await {
                        tracing::error!(
                            execution_id = %execution_id,
                            error = %db_err,
                            "Failed to mark resumed execution as failed; execution will appear stuck"
                        );
                    }
                    store_and_send!(ExecutionEvent {
                        execution_id,
                        node_id: None,
                        status: ExecutionStatus::Failed,
                        trace_id: None,
                        span_id: None,
                        log_message: Some(error_msg),
                        iteration_index: None,
                        iteration_total: None,
                        duration_ms: None,
                        output: None,
                    });
                }
            }

            // Release the advisory lock on the SAME connection where it was acquired.
            release_advisory_lock(conn, lock_id).await;
        });

        Ok(true)
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

        // Insert or update workflow
        let workflow_id = sqlx::query_scalar::<_, Uuid>(
            r#"
            INSERT INTO workflows (name, module_uri, graph_json, user_id, max_concurrent_executions, intent)
            VALUES ($1, '', $2, $3, $4, $5)
            RETURNING id
            "#,
        )
        .bind(&input.name)
        .bind(&input.graph_json)
        .bind(user_id)
        .bind(input.max_concurrent_executions)
        .bind(&input.intent)
        .fetch_one(db_pool)
        .await?;

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
            .map_err(|_| async_graphql::Error::new("WorkflowCreationService not available").extend_safe())?;

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
        let result = sqlx::query(
            r#"
            UPDATE workflows
            SET name = $1, graph_json = $2, max_concurrent_executions = $3, intent = $4, updated_at = NOW()
            WHERE id = $5 AND (user_id = $6 OR org_id = ANY($7))
            "#,
        )
        .bind(&input.name)
        .bind(&input.graph_json)
        .bind(input.max_concurrent_executions)
        .bind(&input.intent)
        .bind(id)
        .bind(user_id)
        .bind(&org_ids)
        .execute(db_pool)
        .await?;

        if result.rows_affected() == 0 {
            // MCP-918: .extend_safe()
            return Err(async_graphql::Error::new(
                "Workflow not found or you don't have permission to update it",
            ).extend_safe());
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
        let result = sqlx::query(
            "DELETE FROM workflows \
             WHERE id = $1 \
               AND (user_id = $2 OR org_id = ANY($3)) \
               AND NOT EXISTS ( \
                   SELECT 1 FROM workflow_executions \
                   WHERE workflow_id = workflows.id \
                     AND status IN ('running', 'queued', 'pending') \
               )",
        )
        .bind(id)
        .bind(user_id)
        .bind(&org_ids)
        .execute(db_pool)
        .await?;

        if result.rows_affected() == 0 {
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
            let blocked = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS ( \
                     SELECT 1 FROM workflows w \
                     WHERE w.id = $1 \
                       AND (w.user_id = $2 OR w.org_id = ANY($3)) \
                       AND EXISTS ( \
                           SELECT 1 FROM workflow_executions \
                           WHERE workflow_id = w.id \
                             AND status IN ('running', 'queued', 'pending') \
                       ) \
                 )",
            )
            .bind(id)
            .bind(user_id)
            .bind(&org_ids)
            .fetch_optional(db_pool)
            .await;
            match blocked {
                Ok(Some(true)) => {
                    // MCP-916 cont.: .extend_safe() — operator needs the
                    // actionable "cancel running executions" guidance,
                    // not "Internal server error".
                    return Err(async_graphql::Error::new(
                        "Workflow has running / queued / pending executions. \
                         Cancel them before deleting, or use force-delete via MCP.",
                    ).extend_safe());
                }
                Ok(_) => {
                    return Err(async_graphql::Error::new(
                        "Workflow not found or you don't have permission to delete it",
                    ).extend_safe());
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
        let code = llm_client
            .generate_code(
                &prompt_redacted,
                &input.current_code,
                &input.capability_world,
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
            return Err(async_graphql::Error::new(
                "cron_expression must be ≤ 256 characters",
            )
            .extend_safe());
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

        // Verify user owns the workflow or has org write access (creating
        // schedules is a write — Viewer must not create schedules on
        // org-shared workflows).
        let org_ids: Vec<uuid::Uuid> = crate::schema::user_writable_org_ids(ctx).await?;
        let workflow_exists = crate::access_check::workflow_accessible_for_user(
            db_pool,
            workflow_id,
            user_id,
            &org_ids,
        )
        .await
        .map_err(|e: sqlx::Error| e.extend_safe())?;

        if !workflow_exists {
            return Err(
                async_graphql::Error::new("Workflow not found or access denied").extend_safe(),
            );
        }

        // Calculate next trigger time
        let next_trigger = talos_scheduler::calculate_next_trigger(&cron_expression, &tz)
            .map_err(|e| async_graphql::Error::new(e).extend_safe())?;

        // Upsert: insert or update on conflict (workflow_id is UNIQUE)
        let row = sqlx::query_as::<_, talos_scheduler::WorkflowSchedule>(
            r#"
            INSERT INTO workflow_schedules (workflow_id, user_id, cron_expression, timezone, next_trigger_at)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (workflow_id) DO UPDATE SET
                cron_expression = EXCLUDED.cron_expression,
                timezone = EXCLUDED.timezone,
                next_trigger_at = EXCLUDED.next_trigger_at,
                is_enabled = true,
                updated_at = NOW()
            RETURNING id, workflow_id, user_id, cron_expression, timezone, is_enabled,
                      last_triggered_at, next_trigger_at, created_at, updated_at
            "#,
        )
        .bind(workflow_id)
        .bind(user_id)
        .bind(&cron_expression)
        .bind(&tz)
        .bind(next_trigger)
        .fetch_one(db_pool)
        .await
        .map_err(|e: sqlx::Error| e.extend_safe())?; // Added type annotation

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

        // update_schedule is a write — Viewer must not be able to change
        // the cron of an org-shared workflow.
        let org_ids: Vec<uuid::Uuid> = crate::schema::user_writable_org_ids(ctx).await?;
        let workflow_exists = crate::access_check::workflow_accessible_for_user(
            db_pool,
            workflow_id,
            user_id,
            &org_ids,
        )
        .await
        .map_err(|e: sqlx::Error| e.extend_safe())?;

        if !workflow_exists {
            return Err(
                async_graphql::Error::new("Workflow not found or access denied").extend_safe(),
            );
        }

        // Fetch existing schedule
        let existing = sqlx::query_as::<_, talos_scheduler::WorkflowSchedule>(
            r#"
            SELECT ws.id, ws.workflow_id, ws.user_id, ws.cron_expression, ws.timezone, ws.is_enabled,
                   ws.last_triggered_at, ws.next_trigger_at, ws.created_at, ws.updated_at
            FROM workflow_schedules ws
            LEFT JOIN workflows w ON w.id = ws.workflow_id
            WHERE ws.workflow_id = $1 AND (ws.user_id = $2 OR w.org_id = ANY($3))
            "#,
        )
        .bind(workflow_id)
        .bind(user_id)
        .bind(&org_ids)
        .fetch_optional(db_pool)
        .await
        .map_err(|e: sqlx::Error| e.extend_safe())? // Added type annotation
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
            return Err(async_graphql::Error::new(
                "cron_expression must be ≤ 256 characters",
            )
            .extend_safe());
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

        let row = sqlx::query_as::<_, talos_scheduler::WorkflowSchedule>(
            r#"
            UPDATE workflow_schedules ws
            SET cron_expression = $3,
                timezone = $4,
                is_enabled = $5,
                next_trigger_at = $6,
                updated_at = NOW()
            FROM workflows w
            WHERE ws.workflow_id = $1
              AND w.id = ws.workflow_id
              AND (ws.user_id = $2 OR w.org_id = ANY($7))
            RETURNING ws.id, ws.workflow_id, ws.user_id, ws.cron_expression, ws.timezone, ws.is_enabled,
                      ws.last_triggered_at, ws.next_trigger_at, ws.created_at, ws.updated_at
            "#,
        )
        .bind(workflow_id)
        .bind(user_id)
        .bind(&new_cron)
        .bind(&new_tz)
        .bind(new_enabled)
        .bind(next_trigger)
        .bind(&org_ids)
        .fetch_one(db_pool)
        .await
        .map_err(|e: sqlx::Error| e.extend_safe())?; // Added type annotation

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
        let org_ids: Vec<uuid::Uuid> = crate::schema::user_writable_org_ids(ctx).await?;
        let workflow_exists = crate::access_check::workflow_accessible_for_user(
            db_pool,
            workflow_id,
            user_id,
            &org_ids,
        )
        .await
        .map_err(|e: sqlx::Error| e.extend_safe())?;

        if !workflow_exists {
            return Err(
                async_graphql::Error::new("Workflow not found or access denied").extend_safe(),
            );
        }

        let result = sqlx::query(
            r#"
            DELETE FROM workflow_schedules ws
            USING workflows w
            WHERE ws.workflow_id = $1
              AND w.id = ws.workflow_id
              AND (ws.user_id = $2 OR w.org_id = ANY($3))
            "#,
        )
        .bind(workflow_id)
        .bind(user_id)
        .bind(&org_ids)
        .execute(db_pool)
        .await
        .map_err(|e: sqlx::Error| e.extend_safe())?; // Added type annotation

        Ok(result.rows_affected() > 0)
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
        #[derive(sqlx::FromRow)]
        struct WorkflowForTest {
            graph_json: String,
            actor_id: Option<Uuid>,
        }
        let wf_for_test = sqlx::query_as::<_, WorkflowForTest>(
            "SELECT graph_json, actor_id FROM workflows WHERE id = $1",
        )
        .bind(workflow_id)
        .fetch_one(&db_pool)
        .await
        .map_err(|e: sqlx::Error| {
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
            let workflow_repo =
                talos_workflow_repository::WorkflowRepository::new(db_pool.clone());
            let actor_repo_for_gate =
                talos_actor_repository::ActorRepository::new(db_pool.clone());
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

        // Create a test execution record (marked as test)
        sqlx::query(
            "INSERT INTO workflow_executions (id, workflow_id, user_id, status, is_test_execution) VALUES ($1, $2, $3, 'running', true)"
        )
        .bind(execution_id)
        .bind(workflow_id)
        .bind(user_id)
        .execute(&db_pool)
        .await
        .map_err(|e: sqlx::Error| {
            tracing::error!("Failed to create test execution: {}", e);
            async_graphql::Error::new("Failed to create test execution").extend_safe()
        })?;

        // Build engine with proper error handling for SecretsManager.
        // allow-secrets-manager-new: defensive fallback (same rationale
        // as the trigger/resume sites above).
        let secrets_manager = match secrets_manager {
            Some(sm) => sm,
            None => Arc::new(
                talos_secrets_manager::SecretsManager::new(db_pool.clone()).map_err(|e| {
                    tracing::error!("Failed to create SecretsManager: {}", e);
                    async_graphql::Error::new("Secrets service unavailable").extend_safe()
                })?,
            ),
        };

        // Build the engine via the canonical builder.
        // Note: this path is wrapped in `tokio::time::timeout(Duration::from_secs(30))`
        // below as a hard wall-clock cap. TimeoutPolicy::Honor means the engine
        // ALSO respects the graph's `execution_timeout_secs` if set — if a
        // workflow declares a tighter ceiling (e.g. 10 s), the engine's
        // internal timeout fires first; if it declares a looser one, tokio's
        // 30 s wins. That matches author intent and is a behavior change
        // from pre-r227 (engine never honored the graph's timeout here).
        let test_actor_repo = Arc::new(talos_actor_repository::ActorRepository::new(
            db_pool.clone(),
        ));
        let resolved_test_registry = registry
            .unwrap_or_else(|| Arc::new(ModuleRegistry::new(db_pool.clone(), redis_client)));
        let mut engine = match talos_engine::builder::for_workflow(
            resolved_test_registry,
            secrets_manager,
            test_actor_repo,
            user_id,
            talos_engine::builder::EngineOpts::for_run(workflow_id, graph_json.clone()),
        )
        .await
        {
            Ok(e) => e,
            Err(e) => {
                return Err(
                    async_graphql::Error::new(format!("Invalid workflow graph: {}", e))
                        .extend_safe(),
                );
            }
        };

        // If mock_inputs provided, use them as trigger input for the engine.
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

        // Run with a 30-second timeout
        let start = std::time::Instant::now();
        let run_result = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            talos_engine::nats_run::run_with_trigger_input_via_nats(
                &mut engine,
                nats_client,
                worker_shared_key,
                trigger_input,
                execution_id,
            ),
        )
        .await;

        let duration_ms = start.elapsed().as_millis() as u64;

        // Build the response
        let (status_str, error_msg, ctx_results) = match run_result {
            Ok(Ok(ctx)) => ("completed".to_string(), None, ctx.results),
            Ok(Err(e)) => (
                "failed".to_string(),
                Some(e.to_string()),
                std::collections::HashMap::new(),
            ),
            Err(_) => (
                "failed".to_string(),
                Some("Test execution timed out after 30 seconds".to_string()),
                std::collections::HashMap::new(),
            ),
        };

        // Build per-node traces from the checkpoint/results
        let mut node_traces = Vec::new();
        for &node_id in engine.node_map().keys() {
            let output = ctx_results.get(&node_id);
            let node_status = if output.is_some() {
                "completed"
            } else {
                "skipped"
            };
            node_traces.push(TestNodeTrace {
                node_id,
                input: "{}".to_string(), // Input data is ephemeral in the engine
                output: output.map(|v| v.to_string()),
                status: node_status.to_string(),
                error: None,
            });
        }

        // Mark execution as complete (best-effort — the test harness has
        // already gathered node_traces, so a stale row in `running` state
        // is observability noise rather than a correctness bug).
        if let Err(e) = sqlx::query(
            "UPDATE workflow_executions SET status = $2, completed_at = NOW() WHERE id = $1",
        )
        .bind(execution_id)
        .bind(&status_str)
        .execute(&db_pool)
        .await
        {
            tracing::warn!(
                execution_id = %execution_id,
                error = %e,
                "test_workflow: failed to mark execution complete (results still returned)"
            );
        }

        Ok(TestWorkflowResult {
            execution_id,
            status: status_str,
            node_traces,
            schema_warnings: Vec::new(),
            duration_ms,
            error: error_msg,
        })
    }

    // ── Organization mutations ─────────────────────────────────────────
}

async fn release_advisory_lock(
    mut conn: sqlx::pool::PoolConnection<sqlx::Postgres>,
    lock_id: i64,
) {
    // MCP-702 (2026-05-13): the pre-fix design took `&mut conn` and
    // commented "Advisory locks auto-release on connection close, so a
    // failure here is recoverable." That assumption is wrong for sqlx
    // pool connections — they are NOT closed when `PoolConnection` is
    // dropped, they're returned to the pool and the Postgres TCP
    // session persists. A session-level `pg_advisory_lock` therefore
    // LEAKS to whatever pool consumer reuses that connection next,
    // stalling future `pg_advisory_xact_lock(same_key)` attempts
    // indefinitely. Same class as MCP-701 (rotate_master_key).
    //
    // Take `conn` by value so we can `detach()` it on unlock failure:
    // detach converts the PoolConnection into a raw `PgConnection`
    // that closes on Drop instead of returning to the pool, ending
    // the Postgres session and freeing the lock. Without the detach,
    // a transient unlock failure (network glitch, query timeout) would
    // permanently retain the lock until sqlx's idle-timeout
    // maintenance reaps the connection — which can take hours on a
    // busy pool.
    //
    // **Remaining caller-side hazard**: tokio::spawn panics. If the
    // spawned task panics between `pg_try_advisory_lock` and this
    // function call, the PoolConnection drops without unlocking; the
    // lock leaks. Refactoring the spawned-task bodies to use the
    // MCP-701 IIFE pattern (wrap critical section in
    // `async {}.await`, run unlock in the outer scope regardless of
    // inner Result) would close this. Not yet applied because the
    // spawned-task bodies are ~600 LoC each.
    match sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(lock_id)
        .execute(&mut *conn)
        .await
    {
        Ok(_) => {
            // Happy path — lock released, conn returns to pool on drop.
        }
        Err(e) => {
            tracing::warn!(
                lock_id,
                error = %e,
                "Failed to release pg advisory lock — detaching connection from pool \
                 so the lock doesn't leak to the next consumer"
            );
            // Force-close the underlying connection so the session
            // ends and the lock releases server-side. The detached
            // connection drops at end of this expression.
            let _detached = conn.detach();
            // _detached is a PgConnection; Drop closes the TCP session
            // and Postgres releases all advisory locks held by it.
        }
    }
}

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

#[cfg(test)]
mod saturating_u32_to_i32_tests {
    //! MCP-961 sibling: defend the `execution_events.iteration_index` /
    //! `iteration_total` write boundary against u32→i32 wraparound.
    //! Pre-fix `event.iteration_index.map(|i| i as i32)` silently
    //! wrapped any u32 > i32::MAX (~2.1B) to a negative iteration
    //! index. The read boundary already saturates with `.max(0) as u32`
    //! (MCP-961); the write boundary is defense-in-depth.
    use super::saturating_u32_to_i32;

    #[test]
    fn passes_through_when_in_range() {
        assert_eq!(saturating_u32_to_i32(0), 0);
        assert_eq!(saturating_u32_to_i32(1_000_000), 1_000_000);
        assert_eq!(saturating_u32_to_i32(i32::MAX as u32), i32::MAX);
    }

    #[test]
    fn saturates_at_i32_max_for_excess_u32() {
        // u32::MAX = 4_294_967_295; i32::MAX = 2_147_483_647. The
        // pre-fix `as i32` would wrap negative; saturation surfaces a
        // positive operator-recognisably-absurd ceiling.
        assert_eq!(saturating_u32_to_i32(u32::MAX), i32::MAX);
        assert_eq!(saturating_u32_to_i32(3_000_000_000), i32::MAX);
        assert_eq!(saturating_u32_to_i32(i32::MAX as u32 + 1), i32::MAX);
    }

    #[test]
    fn never_returns_negative() {
        // Crisp invariant: an iteration index/total is a non-negative
        // counter; saturate-to-MAX preserves that semantic.
        for v in [0u32, 1, u32::MAX / 2, u32::MAX - 1, u32::MAX] {
            assert!(
                saturating_u32_to_i32(v) >= 0,
                "iteration counter must be non-negative; got {} for {v}",
                saturating_u32_to_i32(v)
            );
        }
    }
}
