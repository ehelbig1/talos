//! Google Cloud (Cloud Monitoring incident) → WASM dispatch.
//!
//! Mirrors `talos_gmail::dispatch` in shape, adapted for Cloud
//! Monitoring's per-incident push model:
//!
//!   * Input: ONE incident per push (Monitoring publishes a notification
//!     per incident/state-transition, unlike Gmail's history batch).
//!   * Optionally dedup against Redis, build a signed `JobRequest`,
//!     publish to NATS.
//!
//! We do NOT pre-fetch anything from GCP. The dispatch payload carries
//! the incident envelope + a vault:// reference to the connected
//! account's access token; a WASM module that needs to call back into
//! GCP (e.g. to fetch resource metadata) resolves the token itself at
//! execution time. Plaintext tokens never cross controller → NATS.

use super::watch::{GcpWatchRow, GOOGLE_CLOUD_INTEGRATION_NAME};
use super::GoogleCloudIntegrationService;
use anyhow::{bail, Context, Result};
use redis::AsyncCommands;
use serde_json::Value as JsonValue;
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

/// Every service the dispatch path needs. Constructed once at
/// controller startup and Arc-cloned into the handler state.
#[derive(Clone)]
pub struct GcpDispatchContext {
    pub registry: Arc<ModuleRegistry>,
    pub execution_service: Arc<ModuleExecutionService>,
    pub nats: Arc<async_nats::Client>,
    pub worker_shared_key: WorkerSharedKey,
    pub redis: Option<Arc<redis::Client>>,
    pub db_pool: sqlx::PgPool,
    /// Resolves an integration's `provider_key` for the vault-path
    /// (`oauth/google_cloud/{user}/{provider_key}/access_token`) that
    /// the worker substitutes at execution time.
    pub integrations: Arc<GoogleCloudIntegrationService>,
    /// Optional (dev/bootstrap). When `None`, dispatched jobs ship with
    /// empty `encrypted_secrets` — vault:// header substitution and
    /// `talos::core::llm::*` host calls then fail in the worker, but the
    /// dispatch path stays alive (parity with the previous
    /// `Default::default()` behaviour that silently dropped ALL
    /// secrets).
    pub secrets_manager: Option<Arc<SecretsManager>>,
    /// RFC 0010 P3 (M4): the shared claim-based-sealing handle, injected by
    /// controller-main like the gmail/gcal/webhook siblings. When Some, a
    /// secret-carrying dispatch registers the plaintext for a worker claim
    /// (`sealing = SEALING_CLAIM_ECIES`) instead of shipping a WSK envelope.
    /// This path was the ONE sibling the original M4 sweep missed — found
    /// live 2026-07-17 when the first real Pub/Sub push was refused with
    /// "envelope sealing required; inline dispatch refused" under `required`.
    pub sealing_handle: Option<talos_integration_helpers::ModuleSealingHandle>,
}

/// The three fields a Cloud Monitoring push carries that we need to
/// dedup + route: the inner incident object, its id, and its state.
pub(crate) struct ParsedIncident {
    pub incident: JsonValue,
    pub incident_id: String,
    pub state: String,
}

/// Parse a Cloud Monitoring push payload. The realistic shape is
/// `{"version":"1.2","incident":{"incident_id":"...","state":"open",…}}`;
/// we tolerate the incident object being at the top level too, and
/// tolerate `incident_id` arriving as a string OR a number (Google's
/// client libraries differ). Missing fields become empty strings —
/// the caller falls back to the Pub/Sub `messageId` for dedup when
/// `incident_id` is empty.
pub(crate) fn parse_monitoring_incident(payload: &JsonValue) -> ParsedIncident {
    let incident = payload
        .get("incident")
        .cloned()
        .unwrap_or_else(|| payload.clone());
    let incident_id = str_or_num(&incident, "incident_id");
    let state = str_or_num(&incident, "state");
    ParsedIncident {
        incident,
        incident_id,
        state,
    }
}

fn str_or_num(obj: &JsonValue, key: &str) -> String {
    match obj.get(key) {
        Some(JsonValue::String(s)) => s.clone(),
        Some(JsonValue::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

/// Redis dedup key for one incident/state transition on one watch.
/// Uses `incident_id` when present, else the Pub/Sub `messageId` (so a
/// malformed incident without an id still dedups on retry). Keyed by
/// the watch uuid so two watches on the same account don't cross-dedup.
fn dedup_key(watch_uuid: Uuid, incident_id: &str, state: &str, pubsub_message_id: &str) -> String {
    let dedup_id = if incident_id.is_empty() {
        pubsub_message_id
    } else {
        incident_id
    };
    format!("gcp:processed:{}:{}:{}", watch_uuid, dedup_id, state)
}

/// Redis key that lets ONE delivery of an incident/state transition start
/// the channel's bound workflow. A key of its own, so the module dispatch's
/// claim on the same transition does not stop the workflow or the reverse.
fn workflow_dedup_key(
    watch_uuid: Uuid,
    incident_id: &str,
    state: &str,
    pubsub_message_id: &str,
) -> String {
    let dedup_id = if incident_id.is_empty() {
        pubsub_message_id
    } else {
        incident_id
    };
    format!("gcp:workflow-started:{}:{}:{}", watch_uuid, dedup_id, state)
}

/// An identifier as it may travel in a stored trigger input: short, and made
/// only of the characters Google's own ids and resource names use. Anything
/// else is left out rather than carried — the fields come from a push body.
fn plain_id<'a>(value: &'a str, max: usize, extra: &[u8]) -> Option<&'a str> {
    (!value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || extra.contains(&b)))
    .then_some(value)
}

/// What a workflow bound to a Google Cloud push channel is started with:
/// WHICH incident changed and to what state, as identifiers. No policy name,
/// summary, documentation, metric value or resource label — a trigger input
/// is stored with its execution. `condition_name` is the condition's resource
/// path (`projects/…/alertPolicies/…/conditions/…`), which names the alert
/// policy the workflow can read with its own grants. Each field is present
/// only when it is a plain identifier. The same shape as `calendar_push` and
/// `gmail_push`.
pub(crate) fn gcp_push_trigger_input(
    integration_id: Uuid,
    channel_uuid: Uuid,
    incident: &JsonValue,
    incident_id: &str,
    state: &str,
    pubsub_message_id: &str,
) -> JsonValue {
    let project_id = str_or_num(incident, "scoping_project_id");
    let condition_name = incident
        .get("condition")
        .map(|c| str_or_num(c, "name"))
        .unwrap_or_default();
    let mut push = serde_json::json!({
        "integration_id": integration_id,
        "channel_id": channel_uuid,
    });
    if let Some(obj) = push.as_object_mut() {
        for (key, value) in [
            ("incident_id", plain_id(incident_id, 128, b"._-")),
            ("state", plain_id(state, 32, b"_")),
            ("project_id", plain_id(&project_id, 64, b"-")),
            ("condition_name", plain_id(&condition_name, 256, b"/_-")),
            ("message_id", plain_id(pubsub_message_id, 128, b"_-")),
        ] {
            if let Some(value) = value {
                obj.insert(key.to_string(), JsonValue::String(value.to_string()));
            }
        }
    }
    serde_json::json!({ "gcp_push": push })
}

/// What became of the workflow a push's channel is bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundWorkflowStart {
    /// The trigger service created this execution.
    Started(Uuid),
    /// Another delivery of the same incident/state transition already
    /// started it. Nothing was attempted and nothing is recorded.
    AlreadyStarted,
    /// Nothing was started; the word is one of the trigger service's closed
    /// set (`OrchestrationError::push_refusal_reason`) and is what the audit
    /// row carries.
    NotStarted(&'static str),
}

/// What a push says, for the bound-workflow start.
pub struct PushedIncident<'a> {
    pub incident: &'a JsonValue,
    pub incident_id: &'a str,
    pub state: &'a str,
    pub pubsub_message_id: &'a str,
}

/// Start the workflow a Google Cloud push channel is bound to, as the
/// channel's own user, through the trigger service — so ownership, liveness,
/// the execution pause, the actor's budget and ceilings, the input schema and
/// the concurrency limit all apply, exactly as for a start the owner makes by
/// hand.
///
/// Pub/Sub delivers at least once, so one delivery claims the transition in
/// Redis first; with no Redis, or when it does not answer, the workflow is
/// started anyway (a second run beats a dropped incident, as on the module
/// path). A start that is refused is RECORDED and not retried: the push has
/// been acknowledged. One WARN under `talos_audit` and one row in the channel
/// audit log (`workflow_not_started`) with the reason; the error's own text
/// goes to the server log only. A successful start writes no audit row — it
/// is an execution.
///
/// `pub` so the path is driven by a database test without a dispatch bus.
pub async fn start_bound_workflow(
    pool: &sqlx::PgPool,
    orchestration: Option<&Arc<ExecutionOrchestrationService>>,
    redis: Option<&Arc<redis::Client>>,
    user_id: Uuid,
    row: &GcpWatchRow,
    workflow_id: Uuid,
    pushed: &PushedIncident<'_>,
) -> BoundWorkflowStart {
    if let Some(redis) = redis {
        let key = workflow_dedup_key(
            row.id,
            pushed.incident_id,
            pushed.state,
            pushed.pubsub_message_id,
        );
        match reserve_dedup(redis, &key).await {
            Ok(true) => {}
            Ok(false) => {
                tracing::info!(
                    channel_uuid = %row.id,
                    %workflow_id,
                    "gcp push: this incident transition already started the bound workflow; acking"
                );
                return BoundWorkflowStart::AlreadyStarted;
            }
            Err(e) => tracing::warn!(
                error = %e,
                channel_uuid = %row.id,
                "gcp push: Redis dedup failed; starting the workflow anyway (may duplicate)"
            ),
        }
    }

    let outcome = match orchestration {
        None => Err(PUSH_REFUSAL_TRIGGER_SERVICE_NOT_WIRED),
        Some(service) => match service
            .trigger(TriggerInput {
                workflow_id,
                user_id,
                trigger_input: gcp_push_trigger_input(
                    row.integration_id,
                    row.id,
                    pushed.incident,
                    pushed.incident_id,
                    pushed.state,
                    pushed.pubsub_message_id,
                ),
                trigger_agent_id: None,
                inject_memory_context: false,
                origin: ExecutionOrigin::PushChannel {
                    integration: GOOGLE_CLOUD_INTEGRATION_NAME,
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
                    "gcp push: the bound workflow was not started"
                );
                Err(e.push_refusal_reason())
            }
        },
    };
    match outcome {
        Ok(execution_id) => {
            tracing::info!(
                event_kind = "gcp_push_started_workflow",
                channel_uuid = %row.id,
                %workflow_id,
                %execution_id,
                "gcp push started its bound workflow"
            );
            BoundWorkflowStart::Started(execution_id)
        }
        Err(reason) => {
            tracing::warn!(
                target: "talos_audit",
                event_kind = "gcp_push_workflow_not_started",
                channel_uuid = %row.id,
                %workflow_id,
                %user_id,
                reason,
                "gcp push: bound workflow not started; this incident transition will not start it again"
            );
            if let Err(e) = talos_integration_helpers::audit::insert_channel_audit(
                pool,
                talos_integration_helpers::audit::ChannelAuditEvent {
                    integration_id: Some(row.integration_id),
                    user_id,
                    event_type: "workflow_not_started",
                    target: Some(&row.expected_sa_email),
                    success: false,
                    error_message: Some(reason),
                    metadata: serde_json::json!({
                        "channel_uuid": row.id.to_string(),
                        "workflow_id": workflow_id,
                    }),
                },
            )
            .await
            {
                tracing::warn!(channel_uuid = %row.id, error = %e, "gcp workflow_not_started audit log insert failed");
            }
            BoundWorkflowStart::NotStarted(reason)
        }
    }
}

/// Dispatch ONE Cloud Monitoring incident to the watch's bound module.
/// Returns `Ok(())` on a clean ack (no module bound / already
/// processed) as well as on a successful publish; only a hard failure
/// (module load, signing, NATS publish) returns `Err`.
///
/// **Every failure exit writes ONE `gcp_dispatch_failed` audit row, and
/// that is what this wrapper is for.** Measured 2026-09-07: the inner
/// function has six failure exits and only TWO of them — the signing
/// failure and the NATS publish failure — wrote the row, so the four
/// that fire in practice (module load, module-bound ceiling refusal,
/// execution-row create, job serialise) recorded nothing anywhere. On
/// this fleet the module-load exit had fired on every push since the
/// channel was created and `google_calendar_audit_log` held ZERO
/// `gcp_dispatch_failed` rows, so `watch_channel_service`'s
/// `recent_failure` — the surface designed to show exactly this — was
/// dark because its input had never been produced. A helper called at
/// each exit is one forgotten call site away from that state; a wrapper
/// over the whole body cannot be forgotten.
pub(crate) async fn dispatch_monitoring_incident(
    ctx: &GcpDispatchContext,
    user_id: Uuid,
    row: &GcpWatchRow,
    incident: &JsonValue,
    incident_id: &str,
    incident_state: &str,
    pubsub_message_id: &str,
) -> Result<()> {
    let outcome = dispatch_monitoring_incident_inner(
        ctx,
        user_id,
        row,
        incident,
        incident_id,
        incident_state,
        pubsub_message_id,
    )
    .await;
    if let Err(ref e) = outcome {
        // `{:#}` — the whole anyhow chain. `Display` on an `anyhow::Error`
        // prints the OUTERMOST context only, which is how four identical
        // "load module for gcp dispatch" lines said nothing about the
        // "Module not found or access denied" underneath them.
        audit_dispatch_failed(ctx, user_id, row, &format!("{e:#}")).await;
    }
    outcome
}

async fn dispatch_monitoring_incident_inner(
    ctx: &GcpDispatchContext,
    user_id: Uuid,
    row: &GcpWatchRow,
    incident: &JsonValue,
    incident_id: &str,
    incident_state: &str,
    pubsub_message_id: &str,
) -> Result<()> {
    // Early out — cheap check before any module load / Redis call.
    let module_id = match row.module_id {
        Some(id) => id,
        None => {
            tracing::debug!(
                channel_uuid = %row.id,
                "gcp dispatch: no module bound — incident acked, nothing to dispatch"
            );
            return Ok(());
        }
    };

    // Optional Redis dedup. Pub/Sub retries non-2xx for up to 7 days;
    // the SETNX (24h TTL) guards against re-dispatch on retries/replays.
    // On a Redis error we dispatch anyway — a duplicate WASM run beats a
    // dropped incident.
    let dkey = dedup_key(row.id, incident_id, incident_state, pubsub_message_id);
    if let Some(ref redis) = ctx.redis {
        match reserve_dedup(redis, &dkey).await {
            Ok(true) => {} // fresh — proceed
            Ok(false) => {
                tracing::info!(
                    channel_uuid = %row.id,
                    "gcp dispatch: incident already processed (dedup hit); acking"
                );
                return Ok(());
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "gcp dispatch: Redis dedup failed; dispatching anyway (may duplicate)"
                );
            }
        }
    }

    // Load the module ONCE. Scoped to user_id enforces ownership.
    // The `module_id` belongs in the CONTEXT, not only in a log field:
    // this error is rendered into the audit row and into the handler's
    // WARN, and on a healthy database the only failure `get_module` has
    // is "Module not found or access denied" — i.e. the binding names a
    // module that does not exist for this user. Without the id an
    // operator cannot tell which module to re-create or re-bind.
    let exec_info = ctx
        .registry
        .get_execution_info(module_id, user_id)
        .await
        .with_context(|| {
            format!(
                "load module for gcp dispatch (channel {}, module {module_id})",
                row.id
            )
        })?;
    let config = exec_info
        .config
        .clone()
        .unwrap_or_else(|| serde_json::json!({}));

    // Inject the vault:// access-token reference so a module can call
    // back into GCP without the controller pre-fetching the token.
    // Best-effort: if the integration was disconnected we still dispatch
    // the incident (the module just can't call GCP APIs).
    let mut enriched_config = config.clone();
    if let Some(obj) = enriched_config.as_object_mut() {
        match ctx
            .integrations
            .get_integration(row.integration_id, user_id)
            .await
        {
            Ok(Some(integ)) => {
                let vault_path = format!(
                    "vault://oauth/google_cloud/{}/{}/access_token",
                    user_id, integ.provider_key
                );
                obj.insert("ACCESS_TOKEN".to_string(), serde_json::json!(vault_path));
            }
            _ => {
                tracing::warn!(
                    channel_uuid = %row.id,
                    "gcp dispatch: integration not resolvable; dispatching without ACCESS_TOKEN"
                );
            }
        }
    }

    let received_at = chrono::Utc::now().timestamp_millis();
    let data = serde_json::json!({
        "incident": incident,
        "incident_id": incident_id,
        "state": incident_state,
        "watch_uuid": row.id.to_string(),
        "received_at": received_at,
    });
    let input_payload = serde_json::json!({
        "config": enriched_config,
        "data": data,
    });

    let trigger_metadata = serde_json::json!({
        "channel_uuid": row.id.to_string(),
        "incident_id": incident_id,
        "state": incident_state,
        "pubsub_message_id": pubsub_message_id,
    });

    // Every-execution-gets-an-actor: resolve an owning actor for this
    // push dispatch (the user's default actor — a GCP watch carries
    // none). Its `max_llm_tier` / write ceiling travel with the job.
    // Fail OPEN to actor-less Tier-2 on any resolution error so a
    // transient DB hiccup never drops an inbound incident.
    let actor_repo = talos_actor_repository::ActorRepository::new(ctx.db_pool.clone());
    let (resolved_actor, actor_tier, actor_write_ceiling, actor_egress, actor_http_verb_ceiling) =
        match actor_repo.resolve_effective_actor(user_id, None).await {
            Ok(aid) => {
                // #736: one joined SELECT, CLASSIFIED rather than collapsed.
                //
                // The parenthetical this comment used to carry — "a module
                // bound to an air-gapped (egress=local) actor stays air-gapped
                // via the egress override" — was FALSE, and the measurement is
                // worth keeping: the old fallback passed `None` for egress and
                // `resolve_local_egress_only` reads
                // `None => matches!(max_llm_tier, Tier1)`, so `(Tier2, _, None)`
                // derives PUBLIC egress. The claim would have held only for an
                // actor with an EXPLICIT `egress_scope = 'local'`.
                //
                // Refusing is NOT available here: `pubsub_push_handler` has
                // already returned 200 (this runs in a detached `tokio::spawn`)
                // and `reserve_dedup` claimed a 24 h SETNX key above, so an
                // error would lose the incident permanently AND block a manual
                // re-push. So the choice is grant-vs-restrict, and we restrict.
                let (tier, write_ceiling, egress, actor_http_verb_ceiling) = match actor_repo
                    .read_module_bound_ceilings(aid)
                    .await
                    .resolve_for(
                        aid,
                        talos_actor_repository::DispatchSite::GcpMonitoringIncident,
                    ) {
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
                    "gcp dispatch: default-actor resolution failed; dispatching actor-less (Tier-2)"
                );
                (
                    None,
                    talos_workflow_job_protocol::LlmTier::default(),
                    talos_workflow_job_protocol::WriteCeiling::default(),
                    None,
                    // No actor → no override; `None` INHERITS the permissive wire
                    // default beside it rather than inventing a second opinion.
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
        .context("create execution record for gcp incident")?;

    ctx.execution_service
        .add_log_best_effort(
            execution_id,
            LogLevel::Info,
            format!("Job queued for GCP incident {incident_id}"),
            Some(serde_json::json!({
                "incident_id": incident_id,
                "state": incident_state,
            })),
        )
        .await;

    // Module-declared allowed_secrets + host-reserved LLM keys. RFC 0010
    // P3 (M4): under claim-based sealing (`sealing_handle` is Some) this
    // registers the plaintext for a worker claim and stamps
    // `sealing = SEALING_CLAIM_ECIES`; otherwise it builds the inline WSK
    // envelope with AAD = execution_id (worker decrypts with the same AAD
    // pulled from JobRequest.workflow_execution_id). Mirrors the
    // gmail/gcal/webhook siblings.
    let delivery = talos_integration_helpers::prepare_module_dispatch_secrets(
        ctx.secrets_manager.as_ref(),
        module_id,
        user_id,
        execution_id,
        ctx.sealing_handle.as_ref(),
    )
    .await;

    // Placeholder secret-delivery fields; `delivery.apply_to` below writes
    // all four in one drift-proof mapping.
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
        max_llm_tier: actor_tier,
        max_write_ceiling: actor_write_ceiling,
        http_verb_ceiling: actor_http_verb_ceiling,
        egress_scope: actor_egress,
        wasm_bytes: None,
        capability_world: Some(exec_info.capability_world.as_str().to_string()),
        integration_name: exec_info.integration_name.clone(),
        expected_wasm_hash: Some(exec_info.content_hash.clone()),
        max_fuel: exec_info.max_fuel,
        dry_run: false,
        reply_topic: None,
        idempotency_key: None,
        dispatch_attempt: 0,
        actor_id: resolved_actor,
        user_id,
    };

    delivery.apply_to(&mut job_request);

    // Signing is mandatory — an unsigned JobRequest is rejected by the
    // worker at verify anyway. RFC 0010 P1: prefer the configured
    // Ed25519 dispatch signer; else the legacy HMAC path.
    let sign_result = match talos_workflow_job_protocol::configured_dispatch_signer() {
        Some(signer) => signer.sign_job(&mut job_request),
        None => job_request.sign(ctx.worker_shared_key.as_bytes()),
    };
    if let Err(e) = sign_result {
        // RFC 0010 P3 (M4): the seal was registered before signing; reclaim
        // it now rather than leaving it for the TTL sweep.
        if let Some(h) = &ctx.sealing_handle {
            h.in_flight.discard(execution_id);
        }
        let err_msg = format!("failed to sign gcp job: {e}");
        ctx.execution_service
            .fail_execution_best_effort(
                execution_id,
                user_id,
                err_msg.clone(),
                Some("signing_error".into()),
            )
            .await;
        // No inline audit call: the wrapper writes exactly one row per
        // failure, for every exit.
        bail!(err_msg);
    }

    let payload = match serde_json::to_vec(&job_request) {
        Ok(p) => p,
        Err(e) => {
            // RFC 0010 P3 (M4): reclaim the seal on this (practically
            // unreachable) serialize failure, for parity with the
            // sign/publish discards.
            if let Some(h) = &ctx.sealing_handle {
                h.in_flight.discard(execution_id);
            }
            return Err(anyhow::Error::new(e).context("serialize gcp job"));
        }
    };

    // Edge routing (per-user topic) when enabled, else shared talos.jobs.
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
                incident_id = %incident_id,
                job_id = %execution_id,
                "✅ gcp job published to worker"
            );
            // Mark processed AFTER successful publish (idempotent
            // re-affirm of the SETNX reservation). A crash between
            // publish + mark costs at most one duplicate on the next
            // push; under-dispatching an in-flight incident is worse.
            if let Some(ref redis) = ctx.redis {
                if let Err(e) = mark_processed(redis, &dkey).await {
                    tracing::warn!(error = %e, "gcp dispatch: mark-processed failed");
                }
            }
            Ok(())
        }
        Err(e) => {
            // RFC 0010 P3 (M4): publish failed — the worker will never
            // claim, so reclaim the registered seal immediately
            // (belt-and-braces with the TTL sweep).
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
            // No inline audit call: the wrapper writes exactly one row
            // per failure, for every exit.
            bail!(err_msg);
        }
    }
}

/// Best-effort `gcp_dispatch_failed` audit row. Surfaced by
/// `watch_channel_service`'s `recent_failure` enrichment so the UI can
/// flag a watch whose module dispatch is failing. The error is
/// truncate-then-DLP-scrubbed before persisting (upstream/error chains
/// can echo token bytes). Non-fatal on failure.
async fn audit_dispatch_failed(
    ctx: &GcpDispatchContext,
    user_id: Uuid,
    row: &GcpWatchRow,
    err: &str,
) {
    let scrubbed = talos_integration_helpers::audit::truncate_and_redact_error(err);
    if let Err(e) = talos_integration_helpers::audit::insert_channel_audit(
        &ctx.db_pool,
        talos_integration_helpers::audit::ChannelAuditEvent {
            integration_id: Some(row.integration_id),
            user_id,
            event_type: "gcp_dispatch_failed",
            target: Some(&row.expected_sa_email),
            success: false,
            error_message: Some(&scrubbed),
            metadata: serde_json::json!({ "channel_uuid": row.id.to_string() }),
        },
    )
    .await
    {
        tracing::warn!(error = %e, "gcp dispatch_failed audit log insert failed");
    }
}

/// SETNX with a 24-hour TTL. Returns `true` when the key was newly
/// created (this incident is fresh), `false` when it already existed
/// (duplicate).
async fn reserve_dedup(client: &Arc<redis::Client>, key: &str) -> Result<bool> {
    let mut conn = talos_redis::multiplexed(client)
        .await
        .context("redis connection")?;
    let was_new: bool = conn
        .set_options(
            key,
            "1",
            redis::SetOptions::default()
                .conditional_set(redis::ExistenceCheck::NX)
                .with_expiration(redis::SetExpiry::EX(24 * 3600)),
        )
        .await
        .context("redis SET NX EX")?;
    Ok(was_new)
}

async fn mark_processed(client: &Arc<redis::Client>, key: &str) -> Result<()> {
    let mut conn = talos_redis::multiplexed(client)
        .await
        .context("redis connection")?;
    let _: () = conn
        .set_ex::<_, _, ()>(key, "1", 24 * 3600)
        .await
        .context("redis SET EX")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn dedup_key_uses_incident_id_when_present() {
        let wu = Uuid::nil();
        let k = dedup_key(wu, "inc-42", "open", "msg-99");
        assert_eq!(
            k,
            format!("gcp:processed:{}:inc-42:open", wu),
            "incident_id should be preferred over messageId"
        );
    }

    #[test]
    fn dedup_key_falls_back_to_message_id_when_incident_id_empty() {
        let wu = Uuid::nil();
        let k = dedup_key(wu, "", "closed", "msg-99");
        assert_eq!(k, format!("gcp:processed:{}:msg-99:closed", wu));
    }

    /// The workflow's claim on an incident transition is not the module's:
    /// a channel with both starts both.
    #[test]
    fn the_workflow_claim_is_a_key_of_its_own() {
        let wu = Uuid::nil();
        assert_eq!(
            workflow_dedup_key(wu, "inc-42", "open", "msg-99"),
            format!("gcp:workflow-started:{wu}:inc-42:open")
        );
        assert_eq!(
            workflow_dedup_key(wu, "", "closed", "msg-99"),
            format!("gcp:workflow-started:{wu}:msg-99:closed")
        );
        assert_ne!(
            workflow_dedup_key(wu, "inc-42", "open", "msg-99"),
            dedup_key(wu, "inc-42", "open", "msg-99")
        );
    }

    /// A workflow is started with WHICH incident changed and to what state,
    /// as identifiers, and with nothing the incident says.
    #[test]
    fn the_trigger_names_the_incident_and_carries_nothing_it_says() {
        let (integration, channel) = (Uuid::new_v4(), Uuid::new_v4());
        let incident = json!({
            "incident_id": "0.abc123def456",
            "state": "open",
            "scoping_project_id": "example-project-1",
            "policy_name": "Checkout latency over budget",
            "summary": "p99 latency for checkout is above 2s",
            "documentation": { "content": "page the payments on-call" },
            "resource": { "labels": { "instance_id": "1234567890" } },
            "condition": {
                "name": "projects/example-project-1/alertPolicies/111/conditions/222",
                "displayName": "p99 above 2s"
            },
            "url": "https://console.cloud.google.com/monitoring/alerting/incidents/0.abc123def456"
        });
        let input = gcp_push_trigger_input(
            integration,
            channel,
            &incident,
            "0.abc123def456",
            "open",
            "9876543210",
        );
        assert_eq!(
            input,
            json!({
                "gcp_push": {
                    "integration_id": integration,
                    "channel_id": channel,
                    "incident_id": "0.abc123def456",
                    "state": "open",
                    "project_id": "example-project-1",
                    "condition_name": "projects/example-project-1/alertPolicies/111/conditions/222",
                    "message_id": "9876543210",
                }
            })
        );
        let text = input.to_string();
        for said in ["latency", "payments", "instance_id", "console.cloud", "p99"] {
            assert!(!text.contains(said), "the trigger carries `{said}`: {text}");
        }
    }

    /// A field that is not a plain identifier is left out, not carried.
    #[test]
    fn a_field_that_is_not_an_identifier_is_left_out() {
        let incident = json!({
            "scoping_project_id": "a project with spaces",
            "condition": { "name": "projects/p/alertPolicies/1/conditions/2?x=<script>" }
        });
        let input = gcp_push_trigger_input(
            Uuid::nil(),
            Uuid::nil(),
            &incident,
            "an incident: with text",
            &"x".repeat(33),
            "",
        );
        assert_eq!(
            input,
            json!({ "gcp_push": { "integration_id": Uuid::nil(), "channel_id": Uuid::nil() } })
        );
        assert_eq!(plain_id("open", 32, b"_"), Some("open"));
        assert_eq!(
            plain_id(&"x".repeat(32), 32, b"_"),
            Some("x".repeat(32).as_str())
        );
        assert_eq!(plain_id("", 32, b"_"), None);
    }

    #[test]
    fn parses_realistic_monitoring_payload() {
        let payload = json!({
            "version": "1.2",
            "incident": {
                "incident_id": "0.abc123",
                "state": "open",
                "policy_name": "High CPU",
                "resource_name": "vm-1",
            }
        });
        let parsed = parse_monitoring_incident(&payload);
        assert_eq!(parsed.incident_id, "0.abc123");
        assert_eq!(parsed.state, "open");
        // The inner incident object is what dispatch forwards to the module.
        assert_eq!(
            parsed.incident.get("policy_name").and_then(|v| v.as_str()),
            Some("High CPU")
        );
    }

    #[test]
    fn parses_incident_id_as_number() {
        // Some Google client paths emit incident_id as a JSON number.
        let payload = json!({
            "incident": { "incident_id": 123456789, "state": "closed" }
        });
        let parsed = parse_monitoring_incident(&payload);
        assert_eq!(parsed.incident_id, "123456789");
        assert_eq!(parsed.state, "closed");
    }

    #[test]
    fn tolerates_top_level_incident_and_missing_fields() {
        // No wrapping "incident" key + no id → empty id (caller falls
        // back to the Pub/Sub messageId for dedup).
        let payload = json!({ "state": "open" });
        let parsed = parse_monitoring_incident(&payload);
        assert_eq!(parsed.incident_id, "");
        assert_eq!(parsed.state, "open");
    }

    /// **Exactly one `gcp_dispatch_failed` row per failed dispatch, and
    /// the wrapper is the only thing that writes it.**
    ///
    /// Structural, and the reason is a measurement rather than a
    /// preference: driving `dispatch_monitoring_incident` needs a
    /// `GcpDispatchContext`, whose `nats` field is a non-optional
    /// `Arc<async_nats::Client>` — there is no offline constructor — so
    /// no test in this workspace can exercise the module-load exit that
    /// fired four times on the live fleet on 2026-09-07. What CAN be
    /// pinned is the shape that made those four failures leave no trace:
    /// an audit helper called at each exit, where two exits called it and
    /// four did not.
    ///
    /// Two directions, because either alone is trivially defeated: the
    /// WRAPPER must still call the helper (delete that and every failure
    /// goes silent again), and the INNER function must not (re-add an
    /// inline call and a failure writes two rows, which
    /// `attach_recent_failures`' `DISTINCT ON` hides while the table
    /// grows).
    ///
    /// **Stated limits**: it is TEXTUAL and split-anchored, so a rename
    /// of either function misleads it — in the LOUD direction, since the
    /// split then fails outright; and it proves the call is PRESENT, never
    /// that it sits on the failure branch. The honest guard for that is
    /// the live read of `google_calendar_audit_log` after deploy.
    #[test]
    fn exactly_one_audit_write_and_it_is_in_the_wrapper() {
        let src = include_str!("dispatch.rs");
        let after_wrapper = src
            .split("pub(crate) async fn dispatch_monitoring_incident(")
            .nth(1)
            .expect("the wrapper must exist");
        let wrapper_body = after_wrapper
            .split("async fn dispatch_monitoring_incident_inner(")
            .next()
            .expect("the inner function must follow the wrapper");
        let inner_body = after_wrapper
            .split("async fn dispatch_monitoring_incident_inner(")
            .nth(1)
            .expect("the inner function must exist")
            .split("async fn audit_dispatch_failed(")
            .next()
            .expect("the audit helper follows the inner function");

        assert_eq!(
            wrapper_body.matches("audit_dispatch_failed(").count(),
            1,
            "the wrapper must write exactly one audit row on failure — it is \
             the ONLY thing that covers all six of the inner function's \
             failure exits"
        );
        assert_eq!(
            inner_body.matches("audit_dispatch_failed(").count(),
            0,
            "the inner function must NOT write an audit row: the wrapper \
             already does, so an inline call is a duplicate row per failure"
        );
        // The split must be splitting something (checks 64/65).
        assert!(
            inner_body.len() > 1000 && wrapper_body.contains("dispatch_monitoring_incident_inner("),
            "the function-name anchors have drifted; this test would then be \
             asserting over the wrong region"
        );
    }
}
