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
use talos_continuation_trigger::{trigger_continuation_workflow, TriggerSourceKind};
use talos_module_executions::{LogLevel, ModuleExecutionService, TriggerType};
use talos_registry::ModuleRegistry;
use talos_secrets_manager::SecretsManager;
use talos_workflow_engine_core::WorkerSharedKey;
use talos_workflow_job_protocol::JobRequest;
use uuid::Uuid;

/// What an inbound Gmail push should dispatch to, decided from the
/// watch row's bindings. Pure selection — no I/O — so the precedence
/// rule is unit-testable without NATS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DispatchTarget {
    /// A full workflow execution (`workflow_id` bound).
    Workflow(Uuid),
    /// A single WASM module job per message (`module_id` bound).
    Module(Uuid),
    /// Nothing bound — the cursor still advances, but no job fires.
    None,
}

/// Precedence rule: **`workflow_id` wins when both are set.** A workflow
/// is the strictly more capable target (it can itself dispatch modules,
/// run the authorization gate, resolve an effective actor), so a mailbox
/// carrying both bindings is treated as workflow-bound. When only one is
/// set it selects that; when neither is set the push no-ops (cursor still
/// advances upstream).
pub(crate) fn select_dispatch_target(row: &GmailWatchRow) -> DispatchTarget {
    match (row.workflow_id, row.module_id) {
        (Some(workflow_id), _) => DispatchTarget::Workflow(workflow_id),
        (None, Some(module_id)) => DispatchTarget::Module(module_id),
        (None, None) => DispatchTarget::None,
    }
}

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
    /// RFC 0010 P3 (M4): the shared claim-based-sealing handle, injected by
    /// the controller when `TALOS_ENVELOPE_SEALING` is on (audit/required) and
    /// an Ed25519 signing key is configured. When `Some` and the module has
    /// secrets, dispatch registers the plaintext for a worker claim
    /// (`sealing = SEALING_CLAIM_ECIES`) instead of shipping a WSK envelope —
    /// which the worker refuses under `required`. `None` keeps the inline
    /// envelope path (byte-identical to pre-M4).
    pub sealing_handle: Option<talos_integration_helpers::ModuleSealingHandle>,
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
    // Branch selection — workflow_id wins over module_id (see
    // `select_dispatch_target`). Cheap, no I/O, before any module load.
    let module_id = match select_dispatch_target(row) {
        DispatchTarget::Workflow(workflow_id) => {
            return dispatch_to_workflow(ctx, user_id, row, workflow_id, entries).await;
        }
        DispatchTarget::Module(id) => id,
        DispatchTarget::None => {
            tracing::debug!(
                channel_uuid = %row.id,
                "gmail dispatch: no module/workflow bound — cursor advanced but nothing to dispatch"
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

/// Trigger one full workflow execution for a push whose watch row is
/// workflow-bound. Unlike the module path (one job per message), this
/// fires the workflow ONCE per history page carrying new messages — the
/// workflow re-fetches its own mail, so the trigger input is minimal
/// (`{source, email_address, history_id}`) and carries no message bodies.
///
/// Dispatch goes through `trigger_continuation_workflow`, which runs the
/// workflow-authorization gate + effective-actor resolution, creates the
/// execution row, builds the engine (with the resolved actor's tier), and
/// dispatches over NATS. Errors here never abort the push — the caller
/// logs and still advances the cursor, exactly as for the module path.
async fn dispatch_to_workflow(
    ctx: &GmailDispatchContext,
    user_id: Uuid,
    row: &GmailWatchRow,
    workflow_id: Uuid,
    entries: &[HistoryEntry],
) -> Result<()> {
    // Collect the newly-added messages on this page (same source the module
    // path uses). No new messages (e.g. a label-only change) → advance the
    // cursor without spinning up a run.
    let messages: Vec<&super::api::HistoryMessageRef> = entries
        .iter()
        .flat_map(|e| e.messages_added.iter().map(|ma| &ma.message))
        .collect();
    if messages.is_empty() {
        return Ok(());
    }

    // Redelivery guard. Pub/Sub is at-least-once, and two concurrent
    // deliveries of the same push both read the pre-advance cursor — so
    // advancing the cursor alone does NOT prevent a duplicate trigger.
    // Reuse the module path's atomic SETNX dedup: it claims each message_id
    // (24h TTL) and returns only the freshly-claimed ones, so at most one
    // delivery fires the workflow for a given message set. When Redis is
    // unavailable we trigger anyway (better to duplicate than drop —
    // matching the module path); the target workflow re-fetches its own
    // mail and should be idempotent (e.g. fetch-unread-then-archive).
    if let Some(ref redis) = ctx.redis {
        match deduplicate_messages(redis, &messages, &row.email_address).await {
            Ok(fresh) if fresh.is_empty() => {
                tracing::debug!(
                    channel_uuid = %row.id,
                    workflow_id = %workflow_id,
                    "gmail dispatch: all messages already seen (redelivery); skipping workflow trigger"
                );
                return Ok(());
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    channel_uuid = %row.id,
                    "gmail dispatch: Redis dedup failed; triggering workflow anyway (may duplicate)"
                );
            }
        }
    }

    // `trigger_continuation_workflow` builds a real engine, which needs a
    // SecretsManager. The dispatch context makes it optional (dev/bootstrap
    // stacks). When absent we log + no-op rather than run a workflow with no
    // secret access; the cursor still advances upstream.
    let secrets_manager = match ctx.secrets_manager.clone() {
        Some(sm) => sm,
        None => {
            tracing::warn!(
                channel_uuid = %row.id,
                workflow_id = %workflow_id,
                "gmail dispatch: workflow trigger requires a SecretsManager (none configured); skipping — cursor still advances"
            );
            return Ok(());
        }
    };

    // Precedence visibility: if BOTH bindings are present, make it obvious in
    // the logs why the module was skipped in favour of the workflow.
    if row.module_id.is_some() {
        tracing::info!(
            channel_uuid = %row.id,
            workflow_id = %workflow_id,
            module_id = ?row.module_id,
            "gmail dispatch: both workflow_id and module_id bound — workflow_id takes precedence"
        );
    }

    // Minimal trigger input. The workflow re-fetches its own mail via the
    // gmail catalog modules, so no message ids/bodies are needed here.
    let payload = serde_json::json!({
        "source": "gmail_push",
        "email_address": row.email_address,
        "history_id": row.history_id,
    });

    tracing::info!(
        channel_uuid = %row.id,
        workflow_id = %workflow_id,
        history_id = %row.history_id,
        "gmail dispatch: triggering workflow for inbound push"
    );

    // `source_id` = the watch channel UUID; surfaces in the workflow's
    // trigger input as `gmail_channel_id` with `triggered_by: "gmail_push"`.
    match trigger_continuation_workflow(
        &ctx.db_pool,
        ctx.registry.clone(),
        Some(ctx.nats.clone()),
        secrets_manager,
        user_id,
        workflow_id,
        &payload,
        row.id,
        TriggerSourceKind::GmailPush,
    )
    .await
    {
        Some(execution_id) => {
            tracing::info!(
                channel_uuid = %row.id,
                workflow_id = %workflow_id,
                execution_id = %execution_id,
                "✅ gmail push triggered workflow execution"
            );
            Ok(())
        }
        None => {
            // trigger_continuation_workflow fails CLOSED (auth-gate denial,
            // actor not runnable, missing workflow, DB error) and logs the
            // specific reason internally. Surface a generic marker here;
            // don't abort the push — the cursor still advances.
            tracing::warn!(
                channel_uuid = %row.id,
                workflow_id = %workflow_id,
                "gmail dispatch: workflow trigger produced no execution (denied by auth gate or setup failure)"
            );
            Ok(())
        }
    }
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
    let (resolved_actor, actor_tier, actor_write_ceiling, actor_egress) = match actor_repo
        .resolve_effective_actor(user_id, None)
        .await
    {
        Ok(aid) => {
            let tier = actor_repo
                .get_actor_max_llm_tier(aid)
                .await
                .ok()
                .flatten()
                .unwrap_or(talos_workflow_job_protocol::LlmTier::Tier2);
            let write_ceiling = actor_repo
                .get_actor_max_write_ceiling(aid)
                .await
                .ok()
                .flatten()
                .unwrap_or(talos_workflow_job_protocol::WriteCeiling::Write);
            // Egress override travels too (air-gapped actor stays air-gapped);
            // fail OPEN to None (tier-derived default) on error.
            let egress = actor_repo
                .get_actor_egress_scope(aid)
                .await
                .ok()
                .flatten()
                .flatten();
            (Some(aid), tier, write_ceiling, egress)
        }
        Err(e) => {
            tracing::warn!(
                %user_id, error = %e,
                "gmail dispatch: default-actor resolution failed; dispatching actor-less (Tier-2)"
            );
            (
                None,
                talos_workflow_job_protocol::LlmTier::default(),
                talos_workflow_job_protocol::WriteCeiling::default(),
                None,
            )
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

    // Secret delivery combines the MODULE's declared allowed_secrets
    // PLUS the host-reserved LLM provider keys. Without this, vault://
    // header substitution returns NotFound and llm::* host calls fail
    // with NotConfigured. Mirrors ParallelWorkflowEngine::build_encrypted_secrets
    // and the talos-webhooks dispatch path; see CLAUDE.md "Secret Handling
    // Rules" for the canonical pattern.
    //
    // RFC 0010 P3 (M4): under claim-based sealing (`sealing_handle` is Some)
    // this registers the plaintext for a worker claim and stamps
    // `sealing = SEALING_CLAIM_ECIES`; otherwise it builds the inline WSK
    // envelope (L-1: AAD = execution_id — this dispatch sets both `job_id`
    // and `workflow_execution_id` to `execution_id`, so the worker decrypts
    // with the same AAD).
    let delivery = talos_integration_helpers::prepare_module_dispatch_secrets(
        ctx.secrets_manager.as_ref(),
        module_id,
        user_id,
        execution_id,
        ctx.sealing_handle.as_ref(),
    )
    .await;

    // Placeholder secret-delivery fields; `delivery.apply_to` below writes all
    // four in one drift-proof mapping (a hand-spread per site risks a future
    // copy that forgets one — check-17's `Default::default()` class).
    let mut job_request = JobRequest {
        crypto_scheme: 0,
        sealing: 0,
        secret_paths: Vec::new(),
        claim_inbox: None,
        job_id: execution_id,
        workflow_execution_id: execution_id,
        module_uri: exec_info.module_uri.clone(),
        input_payload,
        encrypted_secrets: talos_workflow_job_protocol::EncryptedSecrets::empty(),
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
        max_write_ceiling: actor_write_ceiling,
        egress_scope: actor_egress,
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
    delivery.apply_to(&mut job_request);

    // Signing is mandatory. An unsigned JobRequest is rejected by the worker at
    // verify anyway, so publishing it would just burn NATS bandwidth — bail
    // early with a clear error. RFC 0010 P1: prefer the configured Ed25519
    // dispatch signer; else the legacy HMAC path.
    let sign_result = match talos_workflow_job_protocol::configured_dispatch_signer() {
        Some(signer) => signer.sign_job(&mut job_request),
        None => job_request.sign(ctx.worker_shared_key.as_bytes()),
    };
    if let Err(e) = sign_result {
        // RFC 0010 P3 (M4): the seal was registered before signing; reclaim it
        // now rather than leaving it for the TTL sweep (this dispatch is dead).
        if let Some(h) = &ctx.sealing_handle {
            h.in_flight.discard(execution_id);
        }
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

    let payload = match serde_json::to_vec(&job_request) {
        Ok(p) => p,
        Err(e) => {
            // RFC 0010 P3 (M4): reclaim the seal on this (practically
            // unreachable) serialize failure too, for parity with the
            // sign/publish discards above/below.
            if let Some(h) = &ctx.sealing_handle {
                h.in_flight.discard(execution_id);
            }
            return Err(anyhow::Error::new(e).context("serialize gmail job"));
        }
    };

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
            // RFC 0010 P3 (M4): publish failed — the worker will never claim,
            // so reclaim the registered seal immediately (belt-and-braces with
            // the TTL sweep).
            if let Some(h) = &ctx.sealing_handle {
                h.in_flight.discard(execution_id);
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A watch row with the given bindings; other fields are inert for
    /// selection.
    fn row_with(module_id: Option<Uuid>, workflow_id: Option<Uuid>) -> GmailWatchRow {
        GmailWatchRow {
            id: Uuid::new_v4(),
            integration_id: Uuid::new_v4(),
            email_address: "u@example.com".to_string(),
            topic_name: "projects/p/topics/t".to_string(),
            history_id: 42,
            label_ids: vec!["INBOX".to_string()],
            expiration_ms: 0,
            module_id,
            workflow_id,
            created_at_ms: 0,
            updated_at_ms: 0,
        }
    }

    #[test]
    fn selects_module_when_only_module_bound() {
        let m = Uuid::new_v4();
        assert_eq!(
            select_dispatch_target(&row_with(Some(m), None)),
            DispatchTarget::Module(m)
        );
    }

    #[test]
    fn selects_workflow_when_only_workflow_bound() {
        let w = Uuid::new_v4();
        assert_eq!(
            select_dispatch_target(&row_with(None, Some(w))),
            DispatchTarget::Workflow(w)
        );
    }

    #[test]
    fn none_when_neither_bound() {
        assert_eq!(
            select_dispatch_target(&row_with(None, None)),
            DispatchTarget::None
        );
    }

    #[test]
    fn workflow_wins_when_both_bound() {
        let m = Uuid::new_v4();
        let w = Uuid::new_v4();
        // Precedence rule: workflow_id takes priority over module_id.
        assert_eq!(
            select_dispatch_target(&row_with(Some(m), Some(w))),
            DispatchTarget::Workflow(w)
        );
    }

    /// A pre-existing watch row serialized before `workflow_id` existed
    /// must still decode (serde default => None), so old rows keep their
    /// module-dispatch behaviour after this change ships.
    #[test]
    fn legacy_row_without_workflow_id_decodes_to_module() {
        let m = Uuid::new_v4();
        let legacy = serde_json::json!({
            "id": Uuid::new_v4(),
            "integration_id": Uuid::new_v4(),
            "email_address": "u@example.com",
            "topic_name": "projects/p/topics/t",
            "history_id": 7,
            "label_ids": ["INBOX"],
            "expiration_ms": 0,
            "module_id": m,
            "created_at_ms": 0,
            "updated_at_ms": 0
        });
        let row: GmailWatchRow = serde_json::from_value(legacy).expect("legacy row decodes");
        assert_eq!(row.workflow_id, None);
        assert_eq!(select_dispatch_target(&row), DispatchTarget::Module(m));
    }
}
