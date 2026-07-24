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

use super::watch::GcpWatchRow;
use super::GoogleCloudIntegrationService;
use anyhow::{bail, Context, Result};
use redis::AsyncCommands;
use serde_json::Value as JsonValue;
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

/// Dispatch ONE Cloud Monitoring incident to the watch's bound module.
/// Returns `Ok(())` on a clean ack (no module bound / already
/// processed) as well as on a successful publish; only a hard failure
/// (module load, signing, NATS publish) returns `Err`.
pub(crate) async fn dispatch_monitoring_incident(
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
    let exec_info = ctx
        .registry
        .get_execution_info(module_id, user_id)
        .await
        .context("load module for gcp dispatch")?;
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
    let (resolved_actor, actor_tier, actor_write_ceiling, actor_egress) =
        match actor_repo.resolve_effective_actor(user_id, None).await {
            Ok(aid) => {
                // One joined SELECT, fail-OPEN to actor-less Tier-2 on any
                // error (a module bound to an air-gapped (egress=local) actor
                // stays air-gapped via the egress override), matching the
                // Tier-2 fail-open posture of this inbound-incident path.
                let (tier, write_ceiling, egress) = actor_repo.get_module_bound_ceilings(aid).await;
                (Some(aid), tier, write_ceiling, egress)
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
        max_llm_tier: actor_tier,
        max_write_ceiling: actor_write_ceiling,
        egress_scope: actor_egress,
        wasm_bytes: None,
        capability_world: None,
        integration_name: exec_info.integration_name.clone(),
        expected_wasm_hash: Some(exec_info.content_hash.clone()),
        max_fuel: exec_info.max_fuel,
        dry_run: false,
        reply_topic: None,
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
        audit_dispatch_failed(ctx, user_id, row, &err_msg).await;
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
            audit_dispatch_failed(ctx, user_id, row, &err_msg).await;
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
    let mut conn = client
        .get_multiplexed_async_connection()
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
    let mut conn = client
        .get_multiplexed_async_connection()
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
}
