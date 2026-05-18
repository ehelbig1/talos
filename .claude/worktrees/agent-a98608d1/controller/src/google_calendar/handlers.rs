use super::GoogleCalendarService;
use crate::google_calendar::api::GoogleCalendarApiClient;
use crate::module_executions::{LogLevel, ModuleExecutionService, TriggerType};
use crate::registry::ModuleRegistry;
use crate::secrets::SecretsManager;
use anyhow::{Context, Result};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    Extension,
};
use job_protocol::JobRequest;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use std::sync::Arc;
use uuid::Uuid;
use worker::runtime::TalosRuntime;

#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

#[derive(Serialize)]
pub struct GoogleCalendarIntegrationInfo {
    pub id: Uuid,
    pub user_id: Uuid,
    pub oauth_account_id: Uuid,
    pub email: Option<String>,
    pub scope: String,
    pub is_active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// List user's Google Calendar integrations
pub async fn list_integrations_handler(
    State(service): State<Arc<GoogleCalendarService>>,
    Extension(user_id): Extension<Uuid>,
) -> impl IntoResponse {
    match service.list_integrations(user_id).await {
        Ok(integrations) => {
            let mut infos = Vec::new();
            for i in integrations {
                let email: Option<String> = sqlx::query_scalar::<_, String>(
                    "SELECT email FROM oauth_accounts WHERE id = $1",
                )
                .bind(i.oauth_account_id)
                .fetch_optional(&service.db_pool)
                .await
                .ok()
                .flatten();

                infos.push(GoogleCalendarIntegrationInfo {
                    id: i.id,
                    user_id: i.user_id,
                    oauth_account_id: i.oauth_account_id,
                    email,
                    scope: i.scope,
                    is_active: i.is_active,
                    created_at: i.created_at,
                    updated_at: i.updated_at,
                });
            }

            Json(ApiResponse {
                success: true,
                data: Some(infos),
                error: None,
            })
        }
        Err(e) => Json(ApiResponse {
            success: false,
            data: None::<Vec<GoogleCalendarIntegrationInfo>>,
            error: Some(e.to_string()),
        }),
    }
}

/// Get a specific integration
pub async fn get_integration_handler(
    State(service): State<Arc<GoogleCalendarService>>,
    Extension(user_id): Extension<Uuid>,
    Path(integration_id): Path<Uuid>,
) -> impl IntoResponse {
    match service.get_integration(user_id, integration_id).await {
        Ok(Some(integration)) => {
            let email: Option<String> =
                sqlx::query_scalar::<_, String>("SELECT email FROM oauth_accounts WHERE id = $1")
                    .bind(integration.oauth_account_id)
                    .fetch_optional(&service.db_pool)
                    .await
                    .ok()
                    .flatten();

            let info = GoogleCalendarIntegrationInfo {
                id: integration.id,
                user_id: integration.user_id,
                oauth_account_id: integration.oauth_account_id,
                email,
                scope: integration.scope,
                is_active: integration.is_active,
                created_at: integration.created_at,
                updated_at: integration.updated_at,
            };

            Json(ApiResponse {
                success: true,
                data: Some(info),
                error: None,
            })
            .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiResponse {
                success: false,
                data: None::<GoogleCalendarIntegrationInfo>,
                error: Some("Integration not found".to_string()),
            }),
        )
            .into_response(),
        Err(e) => Json(ApiResponse {
            success: false,
            data: None::<GoogleCalendarIntegrationInfo>,
            error: Some(e.to_string()),
        })
        .into_response(),
    }
}

/// List calendars for an integration
#[derive(Serialize)]
struct CalendarInfo {
    id: String,
    summary: String,
    description: Option<String>,
    time_zone: Option<String>,
    access_role: String,
    primary: Option<bool>,
}

pub async fn list_calendars_handler(
    State(service): State<Arc<GoogleCalendarService>>,
    Extension(user_id): Extension<Uuid>,
    Path(integration_id): Path<Uuid>,
) -> impl IntoResponse {
    match service.get_integration(user_id, integration_id).await {
        Ok(Some(mut integration)) => {
            // Refresh token if needed
            if let Err(e) = service.refresh_token_if_needed(&mut integration).await {
                return Json(ApiResponse {
                    success: false,
                    data: None::<Vec<CalendarInfo>>,
                    error: Some(format!("Failed to refresh token: {}", e)),
                })
                .into_response();
            }

            // List calendars
            let api_client = GoogleCalendarApiClient::new();
            match api_client.list_calendars(&integration.access_token).await {
                Ok(calendars) => {
                    let calendar_info: Vec<CalendarInfo> = calendars
                        .into_iter()
                        .map(|c| CalendarInfo {
                            id: c.id,
                            summary: c.summary,
                            description: c.description,
                            time_zone: c.time_zone,
                            access_role: c.access_role,
                            primary: c.primary,
                        })
                        .collect();

                    Json(ApiResponse {
                        success: true,
                        data: Some(calendar_info),
                        error: None,
                    })
                    .into_response()
                }
                Err(e) => Json(ApiResponse {
                    success: false,
                    data: None::<Vec<CalendarInfo>>,
                    error: Some(e.to_string()),
                })
                .into_response(),
            }
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiResponse {
                success: false,
                data: None::<Vec<CalendarInfo>>,
                error: Some("Integration not found".to_string()),
            }),
        )
            .into_response(),
        Err(e) => Json(ApiResponse {
            success: false,
            data: None::<Vec<CalendarInfo>>,
            error: Some(e.to_string()),
        })
        .into_response(),
    }
}

/// Create a watch channel
#[derive(Deserialize)]
pub struct CreateWatchRequest {
    pub integration_id: Uuid,
    pub calendar_id: String,
    pub webhook_url: Option<String>,
}

pub async fn create_watch_handler(
    State(service): State<Arc<GoogleCalendarService>>,
    Extension(user_id): Extension<Uuid>,
    Json(req): Json<CreateWatchRequest>,
) -> impl IntoResponse {
    // Verify user owns the integration
    match service.get_integration(user_id, req.integration_id).await {
        Ok(Some(_)) => {
            // Auto-generate webhook URL if not provided
            let webhook_url = req.webhook_url.unwrap_or_else(|| {
                let base_url = std::env::var("BASE_URL")
                    .unwrap_or_else(|_| "http://localhost:8000".to_string());
                format!("{}/api/google-calendar/webhook", base_url)
            });

            match service
                .create_watch_channel(req.integration_id, &req.calendar_id, &webhook_url, None)
                .await
            {
                Ok(mut channel) => {
                    // Never expose the verification token to clients — it is a server-side
                    // secret used to authenticate incoming webhook notifications from Google.
                    channel.verification_token = "***".to_string();
                    Json(ApiResponse {
                        success: true,
                        data: Some(channel),
                        error: None,
                    })
                    .into_response()
                }
                Err(e) => Json(ApiResponse {
                    success: false,
                    data: None::<super::WatchChannel>,
                    error: Some(e.to_string()),
                })
                .into_response(),
            }
        }
        Ok(None) => (
            StatusCode::FORBIDDEN,
            Json(ApiResponse {
                success: false,
                data: None::<super::WatchChannel>,
                error: Some("Integration not found or not owned by user".to_string()),
            }),
        )
            .into_response(),
        Err(e) => Json(ApiResponse {
            success: false,
            data: None::<super::WatchChannel>,
            error: Some(e.to_string()),
        })
        .into_response(),
    }
}

/// Handle webhook notification from Google
#[derive(Debug)]
pub struct WebhookHeaders {
    pub channel_id: Option<String>,
    pub resource_id: Option<String>,
    pub resource_state: Option<String>,
    pub message_number: Option<String>,
}

pub async fn webhook_notification_handler(
    State(service): State<Arc<GoogleCalendarService>>,
    Extension(redis_client): Extension<Option<Arc<redis::Client>>>,
    Extension(execution_service): Extension<Option<Arc<ModuleExecutionService>>>,
    Extension(nats_client): Extension<Option<Arc<async_nats::Client>>>,
    Extension(worker_shared_key): Extension<Option<Arc<Vec<u8>>>>,
    Extension(runtime): Extension<Option<Arc<TalosRuntime>>>,
    Extension(secrets_manager): Extension<Option<Arc<SecretsManager>>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    // Explicitly annotate types to help compiler
    let execution_service: Option<Arc<ModuleExecutionService>> = execution_service;
    let nats_client: Option<Arc<async_nats::Client>> = nats_client;

    // Extract Google notification headers
    let channel_id = headers
        .get("X-Goog-Channel-ID")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let resource_state = headers
        .get("X-Goog-Resource-State")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let channel_token = headers
        .get("X-Goog-Channel-Token")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let message_number = headers
        .get("X-Goog-Message-Number")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<i64>().ok());

    tracing::debug!(
        "📬 Google Calendar webhook - Channel: {:?}, State: {:?}, Msg: {:?}",
        channel_id,
        resource_state,
        message_number
    );

    // Find channel by channel_id and verify token
    if let Some(ch_id) = channel_id {
        // Per-channel rate limit (IP-based limiting is insufficient because Google
        // sends notifications from a shared IP pool).
        if !service.allow_webhook_channel(&ch_id) {
            tracing::warn!(
                channel_id = %ch_id,
                "Google Calendar webhook rate limit exceeded for channel — notification dropped"
            );
            // Return 200 OK to Google so it doesn't back-off-and-retry; the
            // notification is deduplicated by Google on their end anyway.
            return StatusCode::OK;
        }
        let channel_result = sqlx::query_as::<_, (Uuid, String, i64, Option<Uuid>, Uuid)>(
            "SELECT w.id, w.verification_token, w.last_message_number, w.module_id, i.user_id
             FROM google_calendar_watch_channels w
             JOIN google_calendar_integrations i ON w.integration_id = i.id
             WHERE w.channel_id = $1 AND w.is_active = true",
        )
        .bind(&ch_id)
        .fetch_optional(&service.db_pool)
        .await;

        match channel_result {
            // `last_msg_num` is currently unused; prefix with underscore to silence warnings.
            Ok(Some((channel_uuid, expected_token, _last_msg_num, module_id, channel_user_id))) => {
                // SECURITY: Verify the token matches using constant-time comparison
                // to prevent timing attacks that could leak token information
                if let Some(token) = channel_token {
                    if !constant_time_eq::constant_time_eq(
                        token.as_bytes(),
                        expected_token.as_bytes(),
                    ) {
                        tracing::warn!(
                            "🚨 SECURITY: Invalid token for channel {}. Rejecting webhook.",
                            ch_id
                        );
                        return StatusCode::FORBIDDEN;
                    }
                } else {
                    tracing::warn!(
                        "🚨 SECURITY: Missing X-Goog-Channel-Token header for channel {}",
                        ch_id
                    );
                    return StatusCode::FORBIDDEN;
                }

                // DEDUPLICATION: Atomically advance the message number.
                // The WHERE clause ensures we skip duplicates and out-of-order deliveries
                // without a separate read — eliminating the TOCTOU race condition that
                // would occur with a check-then-update pattern under concurrent requests.
                if let Some(msg_num) = message_number {
                    match sqlx::query(
                        "UPDATE google_calendar_watch_channels
                         SET last_message_number = $1
                         WHERE id = $2 AND last_message_number < $1",
                    )
                    .bind(msg_num)
                    .bind(channel_uuid)
                    .execute(&service.db_pool)
                    .await
                    {
                        Ok(result) if result.rows_affected() == 0 => {
                            tracing::info!(
                                "⏭️ Duplicate or out-of-order message {} for channel {} — skipping.",
                                msg_num, ch_id
                            );
                            return StatusCode::OK;
                        }
                        Ok(_) => {}
                        Err(e) => {
                            tracing::error!(
                                "❌ CRITICAL: Failed to update message number for channel {} (msg {}): {}. Database error!",
                                channel_uuid, msg_num, e
                            );
                            // Return 500 so Google retries later. Processing now without recording the message
                            // number could lead to duplicate executions if we process it again later.
                            return StatusCode::INTERNAL_SERVER_ERROR;
                        }
                    }
                }

                // Process events in background (don't block webhook response).
                //
                // Google sends X-Goog-Resource-State: "sync" immediately after a watch
                // channel is registered — it is a handshake, not a real change. We must
                // perform an initial full sync to obtain the sync token, but we must NOT
                // dispatch any jobs; that would execute every historical calendar event.
                //
                // Subsequent notifications use state "exists" and carry only the delta
                // since the stored sync token, so those are safe to dispatch.
                let is_initial_sync = resource_state.as_deref() == Some("sync");

                let service_clone = Arc::clone(&service);
                let redis_clone = redis_client.clone();
                let exec_service_clone = execution_service.as_ref().map(|s| Arc::clone(s));
                let nats_clone = nats_client.clone();
                let key_clone = worker_shared_key.clone();
                let runtime_clone = runtime.clone();
                let secrets_clone = secrets_manager.clone();

                tokio::spawn(async move {
                    if is_initial_sync {
                        // Establish sync token without dispatching any jobs.
                        tracing::info!(
                            "🔄 Initial sync handshake for channel {} — establishing sync token, no jobs dispatched",
                            channel_uuid
                        );
                        if let Err(e) = service_clone.sync_channel_events(channel_uuid).await {
                            tracing::error!(
                                "❌ Failed to establish sync token for channel {}: {}",
                                channel_uuid,
                                e
                            );
                        } else {
                            tracing::info!(
                                "✅ Sync token established for channel {}",
                                channel_uuid
                            );
                        }
                    } else if let Err(e) = process_webhook_events(
                        service_clone,
                        channel_uuid,
                        module_id,
                        channel_user_id,
                        redis_clone,
                        exec_service_clone,
                        nats_clone,
                        key_clone,
                        runtime_clone,
                        secrets_clone,
                    )
                    .await
                    {
                        tracing::error!(
                            "❌ Failed to process webhook events for channel {}: {}",
                            channel_uuid,
                            e
                        );
                    }
                });
            }
            Ok(None) => {
                // This is expected when a watch channel was registered in Google's system
                // but is no longer tracked in the database (e.g., after a DB reset or
                // schema migration).  Google will stop sending notifications once the
                // channel's 7-day TTL expires.  No action required.
                tracing::warn!(
                    "⚠️ Webhook for unrecognised channel {} — likely a stale channel \
                     from before a DB reset; will expire automatically within 7 days.",
                    ch_id
                );
            }
            Err(e) => {
                tracing::error!("❌ Database error looking up channel {}: {}", ch_id, e);
            }
        }
    }

    // Always return 200 OK to acknowledge receipt (Google requires this)
    StatusCode::OK
}

/// Disconnect integration
pub async fn disconnect_integration_handler(
    State(service): State<Arc<GoogleCalendarService>>,
    Extension(user_id): Extension<Uuid>,
    Path(integration_id): Path<Uuid>,
) -> impl IntoResponse {
    match service
        .deactivate_integration(user_id, integration_id)
        .await
    {
        Ok(_) => Json(ApiResponse {
            success: true,
            data: Some("Integration disconnected"),
            error: None,
        }),
        Err(e) => Json(ApiResponse {
            success: false,
            data: None::<&str>,
            error: Some(e.to_string()),
        }),
    }
}

#[derive(Serialize)]
pub struct ClientConfig {
    client_id: String,
    redirect_uri: String,
    is_configured: bool,
}

/// Get Google OAuth client configuration for frontend
pub async fn client_config_handler(
    State(service): State<Arc<GoogleCalendarService>>,
) -> impl IntoResponse {
    Json(ApiResponse {
        success: true,
        data: Some(ClientConfig {
            client_id: service.client_id.clone(),
            redirect_uri: service.redirect_uri.clone(),
            is_configured: service.is_configured(),
        }),
        error: None,
    })
}

/// Process webhook events: sync, filter, deduplicate, and publish jobs to worker
pub async fn process_webhook_events(
    service: Arc<GoogleCalendarService>,
    channel_uuid: Uuid,
    module_id: Option<Uuid>,
    user_id: Uuid,
    redis_client: Option<Arc<redis::Client>>,
    execution_service: Option<Arc<ModuleExecutionService>>,
    nats_client: Option<Arc<async_nats::Client>>,
    worker_shared_key: Option<Arc<Vec<u8>>>,
    runtime: Option<Arc<TalosRuntime>>,
    secrets_manager: Option<Arc<SecretsManager>>,
) -> Result<()> {
    tracing::debug!("🔄 Processing webhook events for channel {}", channel_uuid);

    // 1. Sync events from Google Calendar API
    let events = service
        .sync_channel_events(channel_uuid)
        .await
        .context("Failed to sync events")?;

    if events.is_empty() {
        tracing::debug!("No new events to process for channel {}", channel_uuid);
        return Ok(());
    }

    tracing::info!(
        "✅ Synced {} events for channel {}",
        events.len(),
        channel_uuid
    );

    // 2. If no module_id, we're done (just synced for audit/history)
    let module_uuid = match module_id {
        Some(id) => id,
        None => {
            tracing::debug!(
                "No module linked to channel {} - events synced but not executed",
                channel_uuid
            );
            return Ok(());
        }
    };

    // 3. DEDUPLICATION: Filter out events that were already processed
    // This prevents duplicate execution when multiple watch channels exist for the same calendar
    let deduplicated_events = if let Some(ref redis) = redis_client {
        match deduplicate_events(redis, &events, channel_uuid).await {
            Ok(deduped) => {
                let removed = events.len().saturating_sub(deduped.len());
                if removed > 0 {
                    tracing::info!(
                        "🔍 Deduplication: {} events already processed, {} new events to process",
                        removed,
                        deduped.len()
                    );
                }
                deduped
            }
            Err(e) => {
                tracing::warn!(
                    "⚠️ Redis deduplication failed: {}. Processing all events (may cause duplicates)",
                    e
                );
                events.clone() // Fallback: process all events if Redis fails
            }
        }
    } else {
        tracing::debug!("Redis not available - deduplication disabled (may process duplicates)");
        events.clone()
    };

    if deduplicated_events.is_empty() {
        tracing::debug!(
            "All {} events were already processed (duplicates)",
            events.len()
        );
        return Ok(());
    }

    // 4. Load WASM module and config (user_id enforces ownership)
    let registry = Arc::new(ModuleRegistry::new(
        service.db_pool.clone(),
        redis_client.clone(),
    ));

    let exec_info = registry
        .get_execution_info(module_uuid, user_id)
        .await
        .context("Failed to prepare WASM module for execution")?;

    let config = exec_info.config.unwrap_or_else(|| serde_json::json!({}));

    tracing::debug!(
        "Loaded module {} with config for event filtering",
        module_uuid
    );

    // 5. Apply filters to deduplicated events
    let filtered_events = filter_events(&deduplicated_events, &config);

    if filtered_events.is_empty() {
        tracing::debug!(
            "All {} events filtered out by user configuration",
            deduplicated_events.len()
        );
        return Ok(());
    }

    tracing::info!(
        "📊 Filtered {} → {} events (filters applied: EVENT_TYPES, keywords, etc.)",
        deduplicated_events.len(),
        filtered_events.len()
    );

    // 7. Check NATS availability
    let nats = match nats_client {
        Some(ref client) => client.clone(),
        None => {
            tracing::error!("❌ NATS client not available - cannot publish jobs to worker");
            anyhow::bail!("NATS client not configured");
        }
    };

    // 7.5. Fetch the OAuth access token for this channel ONCE to avoid N+1 queries
    let mut channel_access_token: Option<String> = None;
    match sqlx::query_scalar::<_, String>(
        "SELECT i.access_token 
         FROM google_calendar_integrations i
         JOIN google_calendar_watch_channels c ON c.integration_id = i.id
         WHERE c.id = $1",
    )
    .bind(channel_uuid)
    .fetch_one(&service.db_pool)
    .await
    {
        Ok(token) => {
            tracing::info!(
                "✅ Successfully retrieved Google Calendar access token for channel {}",
                channel_uuid
            );
            channel_access_token = Some(token);
        }
        Err(e) => {
            tracing::error!(
                "❌ Failed to fetch Google Calendar access token for channel {}: {}",
                channel_uuid,
                e
            );
        }
    }

    // 8. Publish jobs to worker via NATS for each filtered event
    for (index, event) in filtered_events.iter().enumerate() {
        let event_id = event
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let event_summary = event
            .get("summary")
            .and_then(|v| v.as_str())
            .unwrap_or("(no title)");

        // Create execution record
        let execution_id = if let Some(exec_service) = execution_service.as_ref() {
            let trigger_metadata = serde_json::json!({
                "channel_id": channel_uuid.to_string(),
                "event_id": event_id,
                "event_summary": event_summary,
                "calendar_event_index": index + 1,
                "total_events": filtered_events.len(),
            });

            match exec_service
                .create_execution(
                    module_uuid,
                    user_id,
                    TriggerType::Webhook,
                    Some(trigger_metadata),
                    Some(event.clone()),
                )
                .await
            {
                Ok(id) => {
                    // Mark as queued (will be picked up by worker)
                    exec_service
                        .add_log_best_effort(
                            id,
                            LogLevel::Info,
                            format!("Job queued for calendar event: {}", event_summary),
                            Some(serde_json::json!({
                                "event_id": event_id,
                                "index": index + 1,
                                "total": filtered_events.len(),
                                "execution_location": "worker"
                            })),
                        )
                        .await;

                    Some(id)
                }
                Err(e) => {
                    tracing::warn!("Failed to create execution record: {}", e);
                    None
                }
            }
        } else {
            None
        };

        let job_id = execution_id.unwrap_or_else(|| Uuid::new_v4());

        tracing::debug!(
            "📤 Publishing job to worker for event {}/{}: {} ({})",
            index + 1,
            filtered_events.len(),
            event_summary,
            event_id
        );

        // Extract event status to determine type
        let event_status = event.get("status").and_then(|v| v.as_str()).unwrap_or("");
        let event_type = match event_status {
            "cancelled" => "deleted",
            "confirmed" | "tentative" => "updated", // Can't easily tell created vs updated without state
            _ => "unknown",
        };

        // Prepare job payload with config and event data, injecting the event_type
        let mut event_clone = event.clone();
        if let Some(obj) = event_clone.as_object_mut() {
            obj.insert("type".to_string(), serde_json::json!(event_type));
            obj.insert("event_type".to_string(), serde_json::json!(event_type));
        }

        // Inject Google Calendar ACCESS_TOKEN if available
        let mut enriched_config = config.clone();

        if let Some(ref token) = channel_access_token {
            if let Some(obj) = enriched_config.as_object_mut() {
                obj.insert("ACCESS_TOKEN".to_string(), serde_json::json!(token));
            }
        }

        let input_payload = serde_json::json!({
            "config": enriched_config,
            "data": event_clone
        });

        // Create job request for worker
        let mut job_request = JobRequest {
            job_id,
            workflow_execution_id: job_id, // Single node execution, use same ID
            module_uri: exec_info.module_uri.clone(),
            input_payload,
            encrypted_secrets: Default::default(), // Google Calendar webhooks don't dispatch user secrets
            timeout_ms: 30_000,                    // 30 second timeout
            allowed_hosts: exec_info.allowed_hosts.clone(),
            allowed_methods: exec_info.allowed_methods.clone(),
            signature: vec![],
            job_nonce: String::new(),
            wasm_bytes: None, // PERFORMANCE: Include bytes directly (avoids file I/O)
        };

        // Sign the job request with the shared key for integrity and replay protection.
        // If the key is unavailable the job is skipped — an unsigned job would be
        // rejected by the worker anyway, so publishing it is pointless.
        // If an execution record was already created, mark it as failed so it is
        // not orphaned indefinitely in the database.
        let sign_result = match &worker_shared_key {
            Some(key) => job_request.sign(key).map_err(|e| {
                format!(
                    "Failed to sign job {} for event '{}': {}",
                    job_id, event_summary, e
                )
            }),
            None => Err(format!(
                "WORKER_SHARED_KEY not configured — cannot sign job {} for event '{}'",
                job_id, event_summary
            )),
        };

        if let Err(sign_err) = sign_result {
            tracing::error!("❌ {sign_err}. Skipping event.");
            // Mark the execution record as failed so it doesn't stay orphaned.
            if let (Some(svc), Some(eid)) = (execution_service.as_ref(), execution_id) {
                if let Err(e) = svc
                    .fail_execution(
                        eid,
                        user_id,
                        sign_err.clone(),
                        Some("signing_error".to_string()),
                    )
                    .await
                {
                    tracing::warn!("Failed to mark execution {} as failed: {}", eid, e);
                }
            }
            if let (Some(_rt), Some(sm), Some(nats_clone)) = (
                runtime.clone(),
                secrets_manager.clone(),
                nats_client.clone(),
            ) {
                let db_pool = service.db_pool.clone();
                let event_data = event.clone();
                let worker_shared_key_clone = worker_shared_key.clone();
                let redis_client_clone = redis_client.clone();
                tokio::spawn(async move {
                    crate::engine::workflow_chains::run_workflow_chains(
                        nats_clone,
                        sm,
                        &db_pool,
                        worker_shared_key_clone,
                        redis_client_clone,
                        module_uuid,
                        user_id,
                        event_data,
                        channel_uuid,
                        execution_id.unwrap_or(Uuid::new_v4()),
                        Some(sign_err),
                    )
                    .await;
                });
            }
            continue; // Skip event, don't return Ok(()) completely
        }

        let job_payload =
            serde_json::to_vec(&job_request).context("Failed to serialize job request")?;

        // Fallback to standard topic for generic deployments,
        // or route dynamically via edge node env var
        let edge_routing_enabled =
            std::env::var("ENABLE_EDGE_ROUTING").unwrap_or_else(|_| "false".to_string()) == "true";
        let nats_topic = if edge_routing_enabled {
            format!("talos.jobs.{}", user_id)
        } else {
            "talos.jobs".to_string()
        };

        match nats
            .publish_with_headers(
                nats_topic,
                {
                    let mut headers = async_nats::HeaderMap::new();
                    crate::trace_nats::inject_trace_context(&mut headers);
                    headers
                },
                job_payload.into(),
            )
            .await
        {
            Ok(_) => {
                tracing::info!(
                    "✅ Job published to worker: {} for event '{}'",
                    job_id,
                    event_summary
                );

                // Mark event as processed in Redis to prevent duplicate execution
                if let Some(ref redis) = redis_client {
                    if let Err(e) = mark_event_processed(redis, event, channel_uuid).await {
                        tracing::warn!(
                            "⚠️ Failed to mark event {} as processed in Redis: {}",
                            event_id,
                            e
                        );
                    }
                }

                // Chain to downstream workflow nodes in-process — fire and forget so
                // the event loop is not blocked waiting for downstream execution.
                if let (Some(_rt), Some(sm), Some(nats_clone)) = (
                    runtime.clone(),
                    secrets_manager.clone(),
                    nats_client.clone(),
                ) {
                    let db_pool = service.db_pool.clone();
                    let event_data = event.clone();
                    let worker_shared_key_clone = worker_shared_key.clone();
                    let redis_client_clone = redis_client.clone();
                    tokio::spawn(async move {
                        crate::engine::workflow_chains::run_workflow_chains(
                            nats_clone,
                            sm,
                            &db_pool,
                            worker_shared_key_clone,
                            redis_client_clone,
                            module_uuid,
                            user_id,
                            event_data,
                            channel_uuid,
                            execution_id.unwrap_or(Uuid::new_v4()),
                            None, // Google calendar only runs chains on success
                        )
                        .await;
                    });
                }
            }
            Err(e) => {
                tracing::error!("❌ Failed to publish job {} to NATS: {}", job_id, e);
                let err_str = format!("Failed to publish job to worker: {}", e);

                // Mark execution as failed
                if let (Some(exec_service), Some(exec_id)) =
                    (execution_service.as_ref(), execution_id)
                {
                    exec_service
                        .fail_execution_best_effort(
                            exec_id,
                            user_id,
                            err_str.clone(),
                            Some("nats_publish".to_string()),
                        )
                        .await;
                }

                if let (Some(_rt), Some(sm), Some(nats_clone)) = (
                    runtime.clone(),
                    secrets_manager.clone(),
                    nats_client.clone(),
                ) {
                    let db_pool = service.db_pool.clone();
                    let event_data = event.clone();
                    let worker_shared_key_clone = worker_shared_key.clone();
                    let redis_client_clone = redis_client.clone();
                    tokio::spawn(async move {
                        crate::engine::workflow_chains::run_workflow_chains(
                            nats_clone,
                            sm,
                            &db_pool,
                            worker_shared_key_clone,
                            redis_client_clone,
                            module_uuid,
                            user_id,
                            event_data,
                            channel_uuid,
                            execution_id.unwrap_or(Uuid::new_v4()),
                            Some(err_str),
                        )
                        .await;
                    });
                }
            }
        }
    }

    tracing::info!(
        "🎉 Webhook processing complete: {} events executed for module {}",
        filtered_events.len(),
        module_uuid
    );

    Ok(())
}

/// Generate a unique cache key for event deduplication
/// Format: "gcal:processed:{calendar_id}:{event_id}:{updated_timestamp}"
/// This ensures we process the same event only once, even with multiple watch channels
fn generate_event_cache_key(event: &Value, _channel_uuid: Uuid) -> Result<String> {
    let event_id = event
        .get("id")
        .and_then(|v| v.as_str())
        .context("Event missing id field")?;

    let updated = event
        .get("updated")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    // Include channel in key to support per-channel processing if needed in future
    // For now, we deduplicate globally across all channels for the same calendar
    let calendar_id = event
        .get("organizer")
        .and_then(|v| v.get("email"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    // Use event_id + updated timestamp as unique identifier
    // This ensures we re-process events if they're updated
    Ok(format!(
        "gcal:processed:{}:{}:{}",
        calendar_id, event_id, updated
    ))
}

/// Check if events were already processed (deduplication)
/// Returns only events that haven't been processed yet
async fn deduplicate_events(
    redis: &Arc<redis::Client>,
    events: &[Value],
    channel_uuid: Uuid,
) -> Result<Vec<Value>> {
    if events.is_empty() {
        return Ok(Vec::new());
    }

    // Get async connection
    let mut conn = redis
        .get_multiplexed_async_connection()
        .await
        .context("Failed to connect to Redis for deduplication")?;

    let mut new_events = Vec::new();

    // Check each event against Redis cache
    // PERFORMANCE: Could batch this with MGET if performance becomes an issue
    for event in events {
        let cache_key = match generate_event_cache_key(event, channel_uuid) {
            Ok(key) => key,
            Err(e) => {
                tracing::warn!(
                    "⚠️ Failed to generate cache key for event: {}. Including event.",
                    e
                );
                new_events.push(event.clone());
                continue;
            }
        };

        // Check if event was already processed
        match conn.exists::<&str, bool>(&cache_key).await {
            Ok(exists) => {
                if !exists {
                    new_events.push(event.clone());
                } else {
                    let event_id = event
                        .get("id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    tracing::debug!("⏭️ Event {} already processed, skipping", event_id);
                }
            }
            Err(e) => {
                tracing::warn!(
                    "⚠️ Redis EXISTS check failed for {}: {}. Including event to avoid missing it.",
                    cache_key,
                    e
                );
                new_events.push(event.clone());
            }
        }
    }

    Ok(new_events)
}

/// Mark an event as processed in Redis cache
/// TTL: 24 hours (events older than 24 hours are automatically cleaned up)
async fn mark_event_processed(
    redis: &Arc<redis::Client>,
    event: &Value,
    channel_uuid: Uuid,
) -> Result<()> {
    let cache_key = generate_event_cache_key(event, channel_uuid)?;

    let mut conn = redis
        .get_multiplexed_async_connection()
        .await
        .context("Failed to connect to Redis")?;

    // Store with 24-hour TTL (86400 seconds)
    // Value is just "1" - we only care about key existence
    const TTL_SECONDS: u64 = 86400;

    conn.set_ex::<&str, &str, ()>(&cache_key, "1", TTL_SECONDS)
        .await
        .context("Failed to set processed flag in Redis")?;

    tracing::debug!("✅ Marked event as processed: {} (TTL: 24h)", cache_key);

    Ok(())
}

/// Filter events based on user configuration
fn filter_events(events: &[Value], config: &Value) -> Vec<Value> {
    events
        .iter()
        .filter(|event| {
            // Filter by EVENT_TYPES (created, updated, deleted)
            if let Some(event_types) = config.get("EVENT_TYPES").and_then(|v| v.as_array()) {
                let event_status = event.get("status").and_then(|v| v.as_str()).unwrap_or("");

                // Map Google Calendar status to our event types
                let event_type = match event_status {
                    "cancelled" => "deleted",
                    "confirmed" | "tentative" => {
                        // Check if event was created or updated
                        // For now, consider all confirmed/tentative as "updated"
                        // (true "created" detection would require comparing timestamps)
                        "updated"
                    }
                    _ => "unknown",
                };

                let event_types_str: Vec<&str> =
                    event_types.iter().filter_map(|v| v.as_str()).collect();

                if !event_types_str.contains(&event_type) && event_type != "unknown" {
                    return false; // Event type not in filter
                }
            }

            // Filter by FILTER_TITLE_KEYWORDS
            if let Some(keywords) = config
                .get("FILTER_TITLE_KEYWORDS")
                .and_then(|v| v.as_array())
            {
                if !keywords.is_empty() {
                    let summary = event.get("summary").and_then(|v| v.as_str()).unwrap_or("");
                    let summary_lower = summary.to_lowercase();

                    let has_keyword = keywords.iter().any(|kw| {
                        if let Some(kw_str) = kw.as_str() {
                            summary_lower.contains(&kw_str.to_lowercase())
                        } else {
                            false
                        }
                    });

                    if !has_keyword {
                        return false; // No matching keywords
                    }
                }
            }

            // Filter by EXCLUDE_ALL_DAY_EVENTS
            if let Some(true) = config
                .get("EXCLUDE_ALL_DAY_EVENTS")
                .and_then(|v| v.as_bool())
            {
                let is_all_day = event.get("start").and_then(|v| v.get("date")).is_some(); // All-day events have "date" instead of "dateTime"

                if is_all_day {
                    return false;
                }
            }

            // Filter by ONLY_WITH_ATTENDEES
            if let Some(true) = config.get("ONLY_WITH_ATTENDEES").and_then(|v| v.as_bool()) {
                let has_attendees = event
                    .get("attendees")
                    .and_then(|v| v.as_array())
                    .map(|a| !a.is_empty())
                    .unwrap_or(false);

                if !has_attendees {
                    return false;
                }
            }

            // Filter by FILTER_ATTENDEE_EMAILS
            if let Some(email_patterns) = config
                .get("FILTER_ATTENDEE_EMAILS")
                .and_then(|v| v.as_array())
            {
                if !email_patterns.is_empty() {
                    let attendees = event.get("attendees").and_then(|v| v.as_array());

                    if let Some(attendees) = attendees {
                        let has_matching_attendee = attendees.iter().any(|attendee| {
                            let email =
                                attendee.get("email").and_then(|v| v.as_str()).unwrap_or("");
                            email_patterns.iter().any(|pattern| {
                                if let Some(pattern_str) = pattern.as_str() {
                                    email.contains(pattern_str)
                                } else {
                                    false
                                }
                            })
                        });

                        if !has_matching_attendee {
                            return false;
                        }
                    } else {
                        return false; // No attendees but filter requires them
                    }
                }
            }

            // Filter by MIN_DURATION_MINUTES
            if let Some(min_duration) = config.get("MIN_DURATION_MINUTES").and_then(|v| v.as_i64())
            {
                if min_duration > 0 {
                    let start = event
                        .get("start")
                        .and_then(|v| v.get("dateTime"))
                        .and_then(|v| v.as_str());
                    let end = event
                        .get("end")
                        .and_then(|v| v.get("dateTime"))
                        .and_then(|v| v.as_str());

                    if let (Some(start_str), Some(end_str)) = (start, end) {
                        if let (Ok(start_time), Ok(end_time)) = (
                            chrono::DateTime::parse_from_rfc3339(start_str),
                            chrono::DateTime::parse_from_rfc3339(end_str),
                        ) {
                            let duration_minutes = (end_time - start_time).num_minutes();
                            if duration_minutes < min_duration {
                                return false;
                            }
                        }
                    }
                }
            }

            // Filter by EXCLUDE_DECLINED_EVENTS
            if let Some(true) = config
                .get("EXCLUDE_DECLINED_EVENTS")
                .and_then(|v| v.as_bool())
            {
                let attendees = event.get("attendees").and_then(|v| v.as_array());

                if let Some(attendees) = attendees {
                    // Check if the current user (based on organizer or self) has declined
                    let has_declined_self = attendees.iter().any(|attendee| {
                        attendee
                            .get("self")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false)
                            && attendee.get("responseStatus").and_then(|v| v.as_str())
                                == Some("declined")
                    });

                    if has_declined_self {
                        return false;
                    }
                }
            }

            true // Event passed all filters
        })
        .cloned()
        .collect()
}
