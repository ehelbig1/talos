//! Gmail → WASM dispatch.
//!
//! Mirrors `google_calendar::handlers::process_webhook_events` in
//! shape, adapted for Gmail's history shape:
//!
//!   * Input: a slice of `HistoryEntry` (messagesAdded only — we
//!     ignore labelsAdded/messagesDeleted for now).
//!   * For each added message, optionally dedup against Redis,
//!     build a signed `JobRequest`, publish to NATS.
//!
//! We do NOT pre-fetch full message content. The dispatch payload
//! carries the message id + thread id + label ids + the mailbox
//! email + the current historyId + the module's config. WASM
//! modules that need the message body call Gmail's API themselves
//! using the vault-resolved access token injected into the
//! payload.
//!
//! This keeps the controller's Gmail API quota footprint at 1
//! history.list per push, not N (one per message) — critical for
//! high-volume mailboxes.

use super::api::HistoryEntry;
use super::watch::GmailWatchRow;
use anyhow::{bail, Context, Result};
use redis::AsyncCommands;
use std::sync::Arc;
use talos_module_executions::{LogLevel, ModuleExecutionService, TriggerType};
use talos_registry::ModuleRegistry;
use talos_secrets_manager::SecretsManager;
use talos_workflow_engine_core::WorkerSharedKey;
use talos_workflow_job_protocol::JobRequest;
use uuid::Uuid;

/// Every service the dispatch path needs. Constructed once at
/// controller startup and Arc-cloned into the handler state.
#[derive(Clone)]
pub struct GmailDispatchContext {
    pub registry: Arc<ModuleRegistry>,
    pub execution_service: Arc<ModuleExecutionService>,
    pub nats: Arc<async_nats::Client>,
    pub worker_shared_key: WorkerSharedKey,
    pub redis: Option<Arc<redis::Client>>,
    pub db_pool: sqlx::PgPool,
    /// Optional because dev/bootstrap setups may run without a fully
    /// configured secrets manager. When `None`, dispatched jobs ship
    /// with empty `encrypted_secrets` — vault:// header substitution
    /// and `talos::core::llm::*` host calls will then fail in the
    /// worker, but the dispatch path itself stays alive (parity with
    /// the previous `Default::default()` behaviour, which silently
    /// dropped ALL secrets even in production).
    pub secrets_manager: Option<Arc<SecretsManager>>,
}

/// Dispatch one WASM job per newly-added message in the history
/// entries. Returns `Ok(())` even when individual messages fail
/// to dispatch — per-message errors are logged + execution rows
/// marked failed, but don't abort the whole push (that would
/// cause Pub/Sub to retry the entire batch, producing duplicate
/// jobs for messages that DID dispatch successfully).
pub(crate) async fn dispatch_history_entries(
    ctx: &GmailDispatchContext,
    user_id: Uuid,
    row: &GmailWatchRow,
    entries: &[HistoryEntry],
) -> Result<()> {
    // Early outs — cheap checks before any module load.
    let module_id = match row.module_id {
        Some(id) => id,
        None => {
            tracing::debug!(
                channel_uuid = %row.id,
                "gmail dispatch: no module bound — cursor advanced but nothing to dispatch"
            );
            return Ok(());
        }
    };

    let messages: Vec<&super::api::HistoryMessageRef> = entries
        .iter()
        .flat_map(|e| e.messages_added.iter().map(|ma| &ma.message))
        .collect();
    if messages.is_empty() {
        return Ok(());
    }

    // Load the module ONCE — hoisted outside the per-message loop
    // to avoid N+1 registry reads. Scoped to user_id enforces
    // ownership; a module belonging to another user returns Err.
    let exec_info = ctx
        .registry
        .get_execution_info(module_id, user_id)
        .await
        .context("load module for dispatch")?;
    let config = exec_info
        .config
        .clone()
        .unwrap_or_else(|| serde_json::json!({}));

    // Optional Redis dedup — same `gmail:processed:{email}:{message_id}`
    // key pattern works because Gmail message IDs are globally unique
    // per mailbox. When Redis is unavailable we log + dispatch
    // everything (better to duplicate than drop).
    let to_dispatch: Vec<&super::api::HistoryMessageRef> = if let Some(ref redis) = ctx.redis {
        match deduplicate_messages(redis, &messages, &row.email_address).await {
            Ok(fresh) => {
                if fresh.len() < messages.len() {
                    tracing::info!(
                        seen_before = messages.len() - fresh.len(),
                        to_dispatch = fresh.len(),
                        "gmail dispatch: dedup filtered"
                    );
                }
                fresh
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "gmail dispatch: Redis dedup failed; dispatching all (may duplicate)"
                );
                messages
            }
        }
    } else {
        messages
    };

    if to_dispatch.is_empty() {
        return Ok(());
    }

    // Resolve the vault path for the access token so WASM modules
    // can fetch message bodies themselves without the controller
    // prefetching. Gmail's vault key is provider_key = email_address
    // (matching what OAuthCredentialService wrote at connect time).
    let vault_path = format!(
        "vault://oauth/gmail/{}/{}/access_token",
        user_id, row.email_address
    );

    for msg in to_dispatch {
        if let Err(e) = dispatch_single_message(
            ctx,
            user_id,
            row,
            module_id,
            &exec_info,
            &config,
            &vault_path,
            msg,
        )
        .await
        {
            tracing::warn!(
                message_id = %msg.id,
                error = %e,
                "gmail dispatch: failed to publish job; continuing with next message"
            );
        }
    }

    Ok(())
}

async fn dispatch_single_message(
    ctx: &GmailDispatchContext,
    user_id: Uuid,
    row: &GmailWatchRow,
    module_id: Uuid,
    exec_info: &talos_registry::ModuleExecutionInfo,
    config: &serde_json::Value,
    vault_path: &str,
    msg: &super::api::HistoryMessageRef,
) -> Result<()> {
    // Build the per-message payload. `config` is the module's
    // node-config JSON; `data` is the message envelope. ACCESS_TOKEN
    // is a vault:// reference the worker resolves at execution
    // time — plaintext never crosses the controller → NATS boundary.
    let mut enriched_config = config.clone();
    if let Some(obj) = enriched_config.as_object_mut() {
        obj.insert("ACCESS_TOKEN".to_string(), serde_json::json!(vault_path));
    }
    let data = serde_json::json!({
        "message_id": msg.id,
        "thread_id": msg.thread_id,
        "label_ids": msg.label_ids,
        "email_address": row.email_address,
        "history_id": row.history_id,
    });
    let input_payload = serde_json::json!({
        "config": enriched_config,
        "data": data,
    });

    // Create execution record before publishing so a dispatch
    // failure has a row to attach the error to.
    let trigger_metadata = serde_json::json!({
        "channel_uuid": row.id.to_string(),
        "email_address": row.email_address,
        "message_id": msg.id,
        "thread_id": msg.thread_id,
        "history_id": row.history_id,
    });
    // Phase C of "every execution gets an actor": resolve an owning actor for
    // this push dispatch. Gmail watches carry no actor, so this is the user's
    // default actor; its `max_llm_tier` then travels with the job below. Fail
    // OPEN to actor-less Tier-2 (today's behaviour) on any resolution error so
    // a transient DB hiccup never drops an inbound message.
    let actor_repo = talos_actor_repository::ActorRepository::new(ctx.db_pool.clone());
    let (resolved_actor, actor_tier) = match actor_repo.resolve_effective_actor(user_id, None).await
    {
        Ok(aid) => {
            let tier = actor_repo
                .get_actor_max_llm_tier(aid)
                .await
                .ok()
                .flatten()
                .unwrap_or(talos_workflow_job_protocol::LlmTier::Tier2);
            (Some(aid), tier)
        }
        Err(e) => {
            tracing::warn!(
                %user_id, error = %e,
                "gmail dispatch: default-actor resolution failed; dispatching actor-less (Tier-2)"
            );
            (None, talos_workflow_job_protocol::LlmTier::default())
        }
    };

    let execution_id = ctx
        .execution_service
        .create_execution(
            module_id,
            user_id,
            Uuid::new_v4(),
            TriggerType::Webhook,
            Some(data.clone()),
            Some(trigger_metadata),
            None,
            resolved_actor,
        )
        .await
        .context("create execution record for gmail message")?;

    ctx.execution_service
        .add_log_best_effort(
            execution_id,
            LogLevel::Info,
            format!("Job queued for gmail message {}", msg.id),
            Some(serde_json::json!({
                "message_id": msg.id,
                "thread_id": msg.thread_id,
            })),
        )
        .await;

    // Encrypted secrets combine the MODULE's declared
    // allowed_secrets PLUS the host-reserved LLM provider keys.
    // Without this, vault:// header substitution returns NotFound
    // and llm::* host calls fail with NotConfigured. Mirrors
    // ParallelWorkflowEngine::build_encrypted_secrets and the
    // talos-webhooks dispatch path; see CLAUDE.md "Secret Handling
    // Rules" for the canonical pattern.
    let encrypted_secrets = talos_integration_helpers::build_dispatch_encrypted_secrets(
        ctx.secrets_manager.as_ref(),
        module_id,
        user_id,
        // L-1: AAD = execution_id. This dispatch sets
        // `JobRequest.workflow_execution_id = execution_id` (and
        // also `job_id = execution_id`), so the worker decrypts with
        // the same AAD.
        execution_id,
    )
    .await;

    let mut job_request = JobRequest {
        job_id: execution_id,
        workflow_execution_id: execution_id,
        module_uri: exec_info.module_uri.clone(),
        input_payload,
        encrypted_secrets,
        timeout_ms: 30_000,
        allowed_hosts: exec_info.allowed_hosts.clone(),
        allowed_methods: exec_info.allowed_methods.clone(),
        allowed_secrets: exec_info.allowed_secrets.clone(),
        allowed_sql_operations: vec![],
        allow_tier2_exposure: false,
        priority: 100,
        deadline_unix_secs: 0,
        cancellation_token: None,
        signature: vec![],
        job_nonce: String::new(),
        // Phase C: the resolved actor's tier travels with the job. Defaults to
        // Tier-2 (the user's default actor is Tier-2), so this is non-breaking;
        // an operator who sets their default actor to `tier1` now gets
        // data-egress control for inbound-mail processing without the
        // wrap-in-a-workflow workaround.
        max_llm_tier: actor_tier,
        wasm_bytes: None,
        capability_world: None,
        integration_name: exec_info.integration_name.clone(),
        expected_wasm_hash: Some(exec_info.content_hash.clone()),
        // MCP-1089 (2026-05-16): propagate per-module `max_fuel` from
        // `wasm_modules.max_fuel` (via `ModuleExecutionInfo.max_fuel`).
        // Pre-fix this site hardcoded 0 (= "use worker default"), so an
        // operator who tuned the module's fuel budget via DB (or the
        // hot-update flow) had the bump silently ignored on
        // gmail-triggered dispatches. The worker honours 0 as "use
        // WASM_FUEL_LIMIT default" so the prior behaviour was safe but
        // operationally surprising. Sibling-parity with engine
        // dispatch which already plumbs per-module fuel.
        max_fuel: exec_info.max_fuel,
        dry_run: false,
        reply_topic: None,
        actor_id: resolved_actor,
        user_id,
    };

    // Signing is mandatory. An unsigned JobRequest is rejected by
    // the worker at HMAC verify anyway, so publishing it would just
    // burn NATS bandwidth — bail early with a clear error.
    if let Err(e) = job_request.sign(ctx.worker_shared_key.as_bytes()) {
        let err_msg = format!("failed to sign gmail job: {e}");
        ctx.execution_service
            .fail_execution_best_effort(
                execution_id,
                user_id,
                err_msg.clone(),
                Some("signing_error".into()),
            )
            .await;
        bail!(err_msg);
    }

    let payload = serde_json::to_vec(&job_request).context("serialize gmail job")?;

    // Edge routing (if enabled) matches gcal's pattern: per-user
    // topic when ENABLE_EDGE_ROUTING=true, else shared talos.jobs.
    // MCP-1065 (2026-05-15): routed through
    // `talos_config::edge_routing_enabled()` so all four dispatch
    // sites (gmail / gcal / webhooks request-reply / webhooks DLQ
    // replay) agree on truthy-token semantics.
    let topic = if talos_config::edge_routing_enabled() {
        format!("talos.jobs.{}", user_id)
    } else {
        "talos.jobs".to_string()
    };

    let mut headers = async_nats::HeaderMap::new();
    talos_trace_nats::inject_trace_context(&mut headers);
    match ctx
        .nats
        .publish_with_headers(topic, headers, payload.into())
        .await
    {
        Ok(_) => {
            tracing::info!(
                message_id = %msg.id,
                job_id = %execution_id,
                "✅ gmail job published to worker"
            );
            // Mark as processed AFTER successful publish. A crash
            // between publish + mark causes one duplicate on the
            // next push; missing the mark for a message that's
            // IN-FLIGHT would under-dispatch, which is worse.
            if let Some(ref redis) = ctx.redis {
                if let Err(e) = mark_message_processed(redis, &msg.id, &row.email_address).await {
                    tracing::warn!(error = %e, "gmail dispatch: mark-processed failed");
                }
            }
            Ok(())
        }
        Err(e) => {
            let err_msg = format!("NATS publish failed: {e}");
            ctx.execution_service
                .fail_execution_best_effort(
                    execution_id,
                    user_id,
                    err_msg.clone(),
                    Some("nats_publish".into()),
                )
                .await;
            bail!(err_msg);
        }
    }
}

/// Filter `messages` down to those not already seen in Redis. Uses
/// SETNX with a 24-hour TTL — long enough that a Pub/Sub retry
/// within Google's max retry window (7 days) wouldn't re-dispatch,
/// but bounded so idle keys don't accumulate.
async fn deduplicate_messages<'a>(
    client: &Arc<redis::Client>,
    messages: &[&'a super::api::HistoryMessageRef],
    email: &str,
) -> Result<Vec<&'a super::api::HistoryMessageRef>> {
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .context("redis connection")?;
    let mut fresh = Vec::with_capacity(messages.len());
    for msg in messages {
        let key = format!("gmail:processed:{}:{}", email, msg.id);
        let was_new: bool = conn
            .set_options(
                &key,
                "1",
                redis::SetOptions::default()
                    .conditional_set(redis::ExistenceCheck::NX)
                    .with_expiration(redis::SetExpiry::EX(24 * 3600)),
            )
            .await
            .context("redis SET NX EX")?;
        if was_new {
            fresh.push(*msg);
        }
    }
    Ok(fresh)
}

async fn mark_message_processed(
    client: &Arc<redis::Client>,
    message_id: &str,
    email: &str,
) -> Result<()> {
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .context("redis connection")?;
    let key = format!("gmail:processed:{}:{}", email, message_id);
    // Explicit EX in case dedup path took the NX branch but we got
    // here via non-dedup path somehow. Idempotent.
    let _: () = conn
        .set_ex::<_, _, ()>(&key, "1", 24 * 3600)
        .await
        .context("redis SET EX")?;
    Ok(())
}
