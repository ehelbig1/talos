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
use talos_execution_orchestration::{
    ExecutionOrchestrationService, ExecutionOrigin, TriggerInput, TriggerOutcome,
    PUSH_REFUSAL_TRIGGER_FAILED, PUSH_REFUSAL_TRIGGER_SERVICE_NOT_WIRED,
};
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

/// Whether a push for this watch row would START work — a workflow run or a
/// module job. Only such a push consults the deployment-wide execution pause:
/// an unbound watch starts nothing, so it keeps acking and advancing its cursor
/// while paused. Pure, so the rule is testable without a push.
pub(crate) fn push_starts_work(row: &GmailWatchRow) -> bool {
    !matches!(select_dispatch_target(row), DispatchTarget::None)
}

/// Whether the deployment-wide execution pause DEFERS this push — `true` means
/// the handler answers 503 so Pub/Sub redelivers, BEFORE the task that advances
/// the history cursor runs. An unbound watch starts nothing and is never
/// deferred. A flag the database could not return is deferred too: a start
/// whose kill-switch could not be read is not admitted, and 503 is the
/// retryable answer. Extracted from the handler so the decision is driven by a
/// DB test (`controller/tests/execution_pause_tests`); the one-line call site
/// in `pubsub_push_handler` is pinned textually.
pub async fn execution_pause_defers_push(pool: &sqlx::PgPool, row: &GmailWatchRow) -> bool {
    let admission = talos_execution_pause::push_admission(
        pool,
        push_starts_work(row),
        talos_execution_pause::PauseGatePath::GmailPush,
    )
    .await;
    if admission.defers() {
        tracing::info!(
            channel_uuid = %row.id,
            admission = ?admission,
            "gmail pubsub: deferred by the execution pause; 503 so Pub/Sub redelivers"
        );
    }
    admission.defers()
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
    /// The trigger service a watch's bound WORKFLOW is started through, as
    /// the watch's own user. `None` in a process that wired none: a bound
    /// workflow is then not started, and the audit log says why.
    pub orchestration: Option<Arc<ExecutionOrchestrationService>>,
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

/// At most this many message ids travel in one trigger input.
const MAX_PUSH_MESSAGE_IDS: usize = 50;

/// What a workflow bound to a Gmail watch is started with: WHICH mailbox
/// changed and the ids of the new messages. No sender, subject, snippet or
/// label — a trigger input is stored with its execution, and the workflow
/// reads the mail itself with its own grants (which is also what lets the
/// same workflow run from a schedule as a catch-up). The same shape as
/// `calendar_push`.
///
/// An id is taken only when it looks like one (Gmail's are short hex
/// strings): the ids come from Google's reply, and a stored trigger input is
/// not somewhere for an arbitrary string to land.
pub(crate) fn gmail_push_trigger_input(
    integration_id: Uuid,
    channel_uuid: Uuid,
    email_address: &str,
    message_ids: &[&str],
) -> serde_json::Value {
    let plain =
        |id: &&&str| (1..=128).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric());
    let ids: Vec<&&str> = message_ids.iter().filter(plain).collect();
    serde_json::json!({
        "gmail_push": {
            "integration_id": integration_id,
            "channel_id": channel_uuid,
            "email_address": email_address,
            "changed": message_ids.len(),
            "message_ids": ids.iter().take(MAX_PUSH_MESSAGE_IDS).collect::<Vec<_>>(),
            "truncated": ids.len() > MAX_PUSH_MESSAGE_IDS || ids.len() < message_ids.len(),
        }
    })
}

/// What became of the workflow a push's watch is bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundWorkflowStart {
    /// The trigger service created this execution.
    Started(Uuid),
    /// Nothing was started; the word is one of the trigger service's closed
    /// set (`OrchestrationError::push_refusal_reason`) and is what the audit
    /// row carries.
    NotStarted(&'static str),
}

/// Start the workflow a Gmail watch is bound to, as the watch's own user,
/// through the trigger service — so ownership, liveness, the execution pause,
/// the actor's budget and ceilings, the input schema and the concurrency
/// limit all apply, exactly as for a start the owner makes by hand.
///
/// A start that is refused is RECORDED and not retried: the history cursor
/// advances whatever happens here, so these messages will not start the
/// workflow again. One WARN under `talos_audit` and one row in the channel
/// audit log (`workflow_not_started`) with the reason; the error's own text
/// goes to the server log only. A successful start writes no audit row — it
/// is an execution.
///
/// `pub` so the path is driven by a database test without a dispatch bus.
pub async fn start_bound_workflow(
    pool: &sqlx::PgPool,
    orchestration: Option<&Arc<ExecutionOrchestrationService>>,
    user_id: Uuid,
    row: &GmailWatchRow,
    workflow_id: Uuid,
    message_ids: &[&str],
) -> BoundWorkflowStart {
    let outcome = match orchestration {
        None => Err(PUSH_REFUSAL_TRIGGER_SERVICE_NOT_WIRED),
        Some(service) => match service
            .trigger(TriggerInput {
                workflow_id,
                user_id,
                trigger_input: gmail_push_trigger_input(
                    row.integration_id,
                    row.id,
                    &row.email_address,
                    message_ids,
                ),
                trigger_agent_id: None,
                inject_memory_context: false,
                origin: ExecutionOrigin::PushChannel {
                    integration: super::watch::GMAIL_INTEGRATION_NAME,
                    channel_id: row.id,
                },
                validate_only: false,
                dry_run: false,
                wait_ms: None,
            })
            .await
        {
            Ok(TriggerOutcome::Dispatched(started)) => Ok(started.execution_id),
            // Not reachable with `validate_only: false`; named so it is never read as a start.
            Ok(TriggerOutcome::ValidatedOnly(_)) => Err(PUSH_REFUSAL_TRIGGER_FAILED),
            Err(e) => {
                tracing::warn!(
                    channel_uuid = %row.id,
                    %workflow_id,
                    %user_id,
                    error = %e,
                    "gmail push: the bound workflow was not started"
                );
                Err(e.push_refusal_reason())
            }
        },
    };
    match outcome {
        Ok(execution_id) => {
            tracing::info!(
                event_kind = "gmail_push_started_workflow",
                channel_uuid = %row.id,
                %workflow_id,
                %execution_id,
                changed = message_ids.len(),
                "gmail push started its bound workflow"
            );
            BoundWorkflowStart::Started(execution_id)
        }
        Err(reason) => {
            tracing::warn!(
                target: "talos_audit",
                event_kind = "gmail_push_workflow_not_started",
                channel_uuid = %row.id,
                %workflow_id,
                %user_id,
                reason,
                "gmail push: bound workflow not started; these messages will not start it again"
            );
            if let Err(e) = talos_integration_helpers::audit::insert_channel_audit(
                pool,
                talos_integration_helpers::audit::ChannelAuditEvent {
                    integration_id: Some(row.integration_id),
                    user_id,
                    event_type: "workflow_not_started",
                    target: Some(&row.email_address),
                    success: false,
                    error_message: Some(reason),
                    metadata: serde_json::json!({
                        "channel_uuid": row.id.to_string(),
                        "workflow_id": workflow_id,
                        "changed": message_ids.len(),
                    }),
                },
            )
            .await
            {
                tracing::warn!(channel_uuid = %row.id, error = %e, "gmail workflow_not_started audit log insert failed");
            }
            BoundWorkflowStart::NotStarted(reason)
        }
    }
}

/// A push whose watch row is workflow-bound starts that workflow ONCE per
/// history page carrying new messages (the module path dispatches one job per
/// message). Errors here never abort the push — the caller still advances the
/// cursor, exactly as for the module path.
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
    // advancing the cursor alone does NOT prevent a duplicate start. Reuse
    // the module path's atomic SETNX dedup: it claims each message_id (24h
    // TTL) and returns only the freshly-claimed ones, so at most one delivery
    // starts the workflow for a given message, and the trigger names only the
    // messages no earlier delivery named. When Redis is unavailable we start
    // anyway with every message on the page (better to duplicate than drop —
    // matching the module path); the workflow reads its own mail and should
    // be safe to run twice.
    let fresh: Vec<&super::api::HistoryMessageRef> = match ctx.redis {
        Some(ref redis) => match deduplicate_messages(redis, &messages, &row.email_address).await {
            Ok(fresh) if fresh.is_empty() => {
                tracing::debug!(
                    channel_uuid = %row.id,
                    workflow_id = %workflow_id,
                    "gmail dispatch: all messages already seen (redelivery); not starting the workflow"
                );
                return Ok(());
            }
            Ok(fresh) => fresh,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    channel_uuid = %row.id,
                    "gmail dispatch: Redis dedup failed; starting the workflow anyway (may duplicate)"
                );
                messages
            }
        },
        None => messages,
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

    let ids: Vec<&str> = fresh.iter().map(|m| m.id.as_str()).collect();
    start_bound_workflow(
        &ctx.db_pool,
        ctx.orchestration.as_ref(),
        user_id,
        row,
        workflow_id,
        &ids,
    )
    .await;
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
    let (resolved_actor, actor_tier, actor_write_ceiling, actor_egress, actor_http_verb_ceiling) =
        match actor_repo.resolve_effective_actor(user_id, None).await {
            Ok(aid) => {
                // #736: one joined SELECT, CLASSIFIED rather than collapsed.
                //
                // The parenthetical this comment used to carry — "air-gapped actor
                // stays air-gapped via the egress override" — was FALSE, and the
                // measurement is worth keeping: the old fallback passed `None` for
                // egress, and `resolve_local_egress_only` reads
                // `None => matches!(max_llm_tier, Tier1)`, so `(Tier2, _, None)`
                // derives PUBLIC egress. Three live tier-1 actors rely on exactly
                // that tier-derived default (`egress_scope IS NULL`). The claim
                // would hold only for an actor with an EXPLICIT
                // `egress_scope='local'`, and there are none.
                //
                // The old collapse was VACUOUS rather than exploitable, and still
                // is: all five call sites resolve the DEFAULT actor via
                // `resolve_effective_actor(_, None)`, and that actor is
                // tier2/write, so the fallback granted what it already had. It
                // becomes live the moment the default actor is tier-1.
                //
                // The decision this used to defer, now taken: refusing is NOT
                // available on this path. `dispatch_history_entries` swallows a
                // per-message error to avoid a whole-batch Pub/Sub retry, its
                // caller advances the history cursor regardless, the handler
                // already returned 200, `deduplicate_messages` claimed a 24 h SETNX
                // key before dispatch, and there is no polling fallback — so an
                // error here loses the message permanently. The choice is
                // grant-vs-restrict, and we restrict.
                // `GmailMessage` is an `EventRecovery::Lost` site, so this is
                // infallible by construction — but it is still spelled as a
                // `match` rather than an `unwrap`, so that flipping the site's
                // recovery classification is a compile-time conversation.
                let (tier, write_ceiling, egress, actor_http_verb_ceiling) = match actor_repo
                    .read_module_bound_ceilings(aid)
                    .await
                    .resolve_for(aid, talos_actor_repository::DispatchSite::GmailMessage)
                {
                    Ok(triple) => triple,
                    Err(refusal) => return Err(anyhow::anyhow!("{refusal}")),
                };
                (
                    Some(aid),
                    tier,
                    write_ceiling,
                    egress,
                    actor_http_verb_ceiling,
                )
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
                    // No actor → no override. The ceiling beside it is the
                    // permissive wire default, which is this actor-less posture's
                    // documented shape; `None` here INHERITS it rather than
                    // inventing a second opinion.
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
        // Send-side construction: fixes the wire text this dispatch signs.
        input_payload: input_payload.into(),
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
        http_verb_ceiling: actor_http_verb_ceiling,
        egress_scope: actor_egress,
        wasm_bytes: None,
        capability_world: Some(exec_info.capability_world.as_str().to_string()),
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
        idempotency_key: None,
        dispatch_attempt: 0,
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
        talos_workflow_job_protocol::subjects::jobs_for(user_id)
    } else {
        talos_workflow_job_protocol::subjects::JOBS.to_string()
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
    let mut conn = talos_redis::multiplexed(client)
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
    let mut conn = talos_redis::multiplexed(client)
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
            renewed_from: None,
        }
    }

    /// A workflow is started with WHICH mailbox changed and the ids of the
    /// new messages, and nothing else: fifty at most, and only strings that
    /// look like a Gmail id.
    #[test]
    fn the_trigger_names_the_mailbox_and_message_ids_and_nothing_else() {
        let (integration, channel) = (Uuid::new_v4(), Uuid::new_v4());
        let input = gmail_push_trigger_input(
            integration,
            channel,
            "u@example.com",
            &["18c2f3a4b5d6e7f8", "18c2f3a4b5d6e7f9"],
        );
        assert_eq!(
            input,
            serde_json::json!({
                "gmail_push": {
                    "integration_id": integration,
                    "channel_id": channel,
                    "email_address": "u@example.com",
                    "changed": 2,
                    "message_ids": ["18c2f3a4b5d6e7f8", "18c2f3a4b5d6e7f9"],
                    "truncated": false,
                }
            })
        );

        // Not an id: dropped, and the trigger says it is not the whole set.
        let odd = gmail_push_trigger_input(
            integration,
            channel,
            "u@example.com",
            &["18c2f3a4b5d6e7f8", "Subject: quarterly numbers", "", "a b"],
        );
        assert_eq!(
            odd["gmail_push"]["message_ids"],
            serde_json::json!(["18c2f3a4b5d6e7f8"])
        );
        assert_eq!(odd["gmail_push"]["changed"], 4);
        assert_eq!(odd["gmail_push"]["truncated"], true);

        // Fifty at most, and it says so.
        let many: Vec<String> = (0..60).map(|i| format!("18c2f3a4b5d6e{i:03}")).collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        let capped = gmail_push_trigger_input(integration, channel, "u@example.com", &many);
        assert_eq!(
            capped["gmail_push"]["message_ids"]
                .as_array()
                .unwrap()
                .len(),
            MAX_PUSH_MESSAGE_IDS
        );
        assert_eq!(capped["gmail_push"]["changed"], 60);
        assert_eq!(capped["gmail_push"]["truncated"], true);
        let exactly: Vec<&str> = many[..MAX_PUSH_MESSAGE_IDS].to_vec();
        assert_eq!(
            gmail_push_trigger_input(integration, channel, "u@example.com", &exactly)["gmail_push"]
                ["truncated"],
            false
        );
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
    fn only_a_bound_watch_consults_the_execution_pause() {
        assert!(push_starts_work(&row_with(Some(Uuid::new_v4()), None)));
        assert!(push_starts_work(&row_with(None, Some(Uuid::new_v4()))));
        assert!(push_starts_work(&row_with(
            Some(Uuid::new_v4()),
            Some(Uuid::new_v4())
        )));
        assert!(!push_starts_work(&row_with(None, None)));
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
