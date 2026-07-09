use super::GoogleCalendarService;
use crate::api::GoogleCalendarApiClient;
use anyhow::{Context, Result};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    Extension,
};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use talos_module_executions::{LogLevel, ModuleExecutionService, TriggerType};
use talos_registry::ModuleRegistry;
use talos_secrets_manager::SecretsManager;
use talos_worker_fleet::WorkerManager;
use talos_workflow_engine_core::WorkerSharedKey;
use talos_workflow_job_protocol::JobRequest;

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
            // MCP-930 (2026-05-14): batch the oauth_accounts email
            // lookup. Pre-fix this loop issued one `SELECT email FROM
            // oauth_accounts WHERE id = $1` per integration — classic
            // N+1. A user with 10 integrations triggered 11 DB
            // queries to render the integrations grid. CLAUDE.md
            // performance rule: "NEVER use N+1 query patterns. Batch
            // with `WHERE id = ANY($1)` when processing collections."
            // The same `ParsedMsg` + prefetch HashMap shape audit
            // ledger uses (MCP-808) — collect distinct ids, one
            // round-trip, build a map, lookup per row in O(1).
            let account_ids: Vec<Uuid> = integrations
                .iter()
                .map(|i| i.oauth_account_id)
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();
            let mut email_by_account: std::collections::HashMap<Uuid, String> =
                std::collections::HashMap::new();
            if !account_ids.is_empty() {
                match sqlx::query_as::<_, (Uuid, String)>(
                    "SELECT id, email FROM oauth_accounts WHERE id = ANY($1)",
                )
                .bind(&account_ids)
                .fetch_all(&service.db_pool)
                .await
                {
                    Ok(rows) => {
                        for (id, email) in rows {
                            email_by_account.insert(id, email);
                        }
                    }
                    Err(e) => {
                        // Same posture as the per-row `.ok().flatten()`
                        // — log and continue with empty map so each
                        // integration's `email` falls back to None.
                        tracing::warn!(
                            user_id = %user_id,
                            error = %e,
                            "list_integrations: batch oauth_accounts email lookup failed; email fields will be None"
                        );
                    }
                }
            }

            // Prefer the dedicated-flow `account_email` label (migration
            // 20260708210000) over the legacy `oauth_accounts` lookup, which
            // misses for decoupled rows (oauth_account_id is no longer an FK
            // into oauth_accounts). One batched query, keyed by integration id.
            let integration_ids: Vec<Uuid> = integrations.iter().map(|i| i.id).collect();
            let mut email_by_integration: std::collections::HashMap<Uuid, String> =
                std::collections::HashMap::new();
            if !integration_ids.is_empty() {
                match sqlx::query_as::<_, (Uuid, Option<String>)>(
                    "SELECT id, account_email FROM google_calendar_integrations WHERE id = ANY($1)",
                )
                .bind(&integration_ids)
                .fetch_all(&service.db_pool)
                .await
                {
                    Ok(rows) => {
                        for (id, email) in rows {
                            if let Some(e) = email {
                                email_by_integration.insert(id, e);
                            }
                        }
                    }
                    Err(e) => tracing::warn!(
                        user_id = %user_id,
                        error = %e,
                        "list_integrations: account_email lookup failed; falling back to oauth_accounts email"
                    ),
                }
            }

            let infos: Vec<GoogleCalendarIntegrationInfo> = integrations
                .into_iter()
                .map(|i| GoogleCalendarIntegrationInfo {
                    id: i.id,
                    user_id: i.user_id,
                    email: email_by_integration
                        .get(&i.id)
                        .cloned()
                        .or_else(|| email_by_account.get(&i.oauth_account_id).cloned()),
                    oauth_account_id: i.oauth_account_id,
                    scope: i.scope,
                    is_active: i.is_active,
                    created_at: i.created_at,
                    updated_at: i.updated_at,
                })
                .collect();

            Json(ApiResponse {
                success: true,
                data: Some(infos),
                error: None,
            })
        }
        Err(e) => {
            // MCP-925 (2026-05-14): log full error server-side, return
            // generic message to client. Sweep completes the
            // MCP-923/924 pattern across the third integration crate.
            // gcal's `disconnect_integration_handler` was already
            // canonical (via MCP-581) and `renew_watch_channel_handler`
            // (via MCP-764); the other 11 sites in this file drifted.
            // Surface area is identical: full `anyhow::Error` chains
            // can leak sqlx schema/query detail, vault paths from the
            // unified credentials service, Google API error bodies,
            // and reqwest connect-error specifics.
            tracing::error!(
                user_id = %user_id,
                error = %e,
                "Failed to list Google Calendar integrations"
            );
            Json(ApiResponse {
                success: false,
                data: None::<Vec<GoogleCalendarIntegrationInfo>>,
                error: Some("Failed to list integrations".to_string()),
            })
        }
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
        Err(e) => {
            // MCP-925: log server-side, generic to client.
            tracing::error!(
                user_id = %user_id,
                integration_id = %integration_id,
                error = %e,
                "Failed to get Google Calendar integration"
            );
            Json(ApiResponse {
                success: false,
                data: None::<GoogleCalendarIntegrationInfo>,
                error: Some("Failed to get integration".to_string()),
            })
            .into_response()
        }
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
        Ok(Some(integration)) => {
            // Get fresh access token via centralized credential service.
            let access_token = match service.get_access_token(&integration).await {
                Ok(t) => t,
                Err(e) => {
                    // MCP-581: log full error server-side; return
                    // generic to client. The inner error can include
                    // vault paths (`oauth/google_calendar/...`) and
                    // sqlx error fragments. Anyhow chains propagate
                    // upstream provider response bodies too. Same
                    // "NEVER return internal error details" rule from
                    // CLAUDE.md security section.
                    tracing::error!(
                        user_id = %user_id,
                        integration_id = %integration_id,
                        error = %e,
                        "list_calendars: failed to resolve access token"
                    );
                    return Json(ApiResponse {
                        success: false,
                        data: None::<Vec<CalendarInfo>>,
                        error: Some(
                            "Failed to resolve access token — reconnect the integration"
                                .to_string(),
                        ),
                    })
                    .into_response();
                }
            };

            // List calendars
            let api_client = GoogleCalendarApiClient::new();
            match api_client.list_calendars(&access_token).await {
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
                Err(e) => {
                    // MCP-925: Google API list_calendars failure — log
                    // full error server-side, generic to client.
                    // anyhow chains carry upstream Google response
                    // bodies (quota detail, invalid_grant cause text).
                    tracing::error!(
                        user_id = %user_id,
                        integration_id = %integration_id,
                        error = %e,
                        "Failed to list Google calendars via API"
                    );
                    Json(ApiResponse {
                        success: false,
                        data: None::<Vec<CalendarInfo>>,
                        error: Some("Failed to list calendars".to_string()),
                    })
                    .into_response()
                }
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
        Err(e) => {
            // MCP-925: integration lookup failure — log, return generic.
            tracing::error!(
                user_id = %user_id,
                integration_id = %integration_id,
                error = %e,
                "list_calendars: failed to look up integration"
            );
            Json(ApiResponse {
                success: false,
                data: None::<Vec<CalendarInfo>>,
                error: Some("Failed to look up integration".to_string()),
            })
            .into_response()
        }
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
            // Auto-generate webhook URL if not provided.
            // MCP-765 (2026-05-13): match the empty-env-hardened pattern
            // already used by the sibling sites at `admin.rs:143` (which
            // explicitly cites MCP-630/631) and `talos-actor-policies::
            // evaluator.rs:101`. Pre-fix `BASE_URL=""` (helm placeholder)
            // returned `Ok("")` from `std::env::var`, the `unwrap_or_else`
            // didn't fire, and `webhook_url` became
            // `"/api/google-calendar/webhook"` — a relative URL that
            // Google rejects at watch-channel creation with an opaque
            // "invalid resource" error. Sibling drift class as
            // MCP-590/591/653/710/752/753/762; the third
            // gcal-webhook-URL constructor needs the same fix.
            // MCP-1155: canonical `get_base_url()` (empty-env + open-
            // redirect-misconfig defense in one helper).
            let webhook_url = req.webhook_url.unwrap_or_else(|| {
                format!(
                    "{}/api/google-calendar/webhook",
                    talos_config::get_base_url()
                )
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
                Err(e) => {
                    // MCP-925: create_watch_channel failure — log full,
                    // generic to client.
                    tracing::error!(
                        user_id = %user_id,
                        integration_id = %req.integration_id,
                        calendar_id = %req.calendar_id,
                        error = %e,
                        "Failed to create Google Calendar watch channel"
                    );
                    Json(ApiResponse {
                        success: false,
                        data: None::<super::WatchChannel>,
                        error: Some("Failed to create watch channel".to_string()),
                    })
                    .into_response()
                }
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
        Err(e) => {
            // MCP-925: ownership-check failure — log full, generic to client.
            tracing::error!(
                user_id = %user_id,
                integration_id = %req.integration_id,
                error = %e,
                "create_watch: integration ownership lookup failed"
            );
            Json(ApiResponse {
                success: false,
                data: None::<super::WatchChannel>,
                error: Some("Failed to verify integration ownership".to_string()),
            })
            .into_response()
        }
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
    Extension(worker_shared_key): Extension<Option<WorkerSharedKey>>,
    Extension(runtime): Extension<Option<Arc<TalosRuntime>>>,
    Extension(secrets_manager): Extension<Option<Arc<SecretsManager>>>,
    Extension(worker_manager): Extension<Option<Arc<WorkerManager>>>,
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

    // -----------------------------------------------------------------
    // Webhook verification pipeline
    //
    // Order matters, from cheapest to most expensive so a flood of
    // malformed / unauthorised webhooks never reaches the database:
    //
    //   1. Header presence (channel_id, channel_token)
    //   2. Per-channel rate-limit (in-memory DashMap; no I/O)
    //   3. Signed-token verify (constant-time HMAC, no I/O) — also
    //      recovers the bound user_id without any lookup.
    //   4. integration_state lookup scoped to (gcal, user_id).
    //   5. Dedup of X-Goog-Message-Number (read-modify-write).
    //   6. Dispatch in a spawned task.
    //
    // Any verification failure returns 403, logged with the channel id
    // but NEVER the token itself (it's a bearer secret).
    // -----------------------------------------------------------------
    let Some(ch_id) = channel_id else {
        // Missing channel id means we can't route; 200 so Google doesn't
        // retry (nothing to retry toward).
        return StatusCode::OK;
    };

    if !service.allow_webhook_channel(&ch_id) {
        tracing::warn!(
            channel_id = %ch_id,
            "Google Calendar webhook rate limit exceeded — notification dropped"
        );
        return StatusCode::OK;
    }

    // Signed-token verification happens BEFORE any database work. The
    // HMAC key must be present at this point (wired at startup).
    let Some(token_str) = channel_token else {
        tracing::warn!(channel_id = %ch_id, "🚨 Missing X-Goog-Channel-Token");
        return StatusCode::FORBIDDEN;
    };
    let Some(ref shared_key_bytes) = worker_shared_key else {
        tracing::error!("WORKER_SHARED_KEY not configured; cannot verify gcal webhook tokens");
        return StatusCode::INTERNAL_SERVER_ERROR;
    };
    let Some(user_id) =
        crate::webhook_token::verify_channel_token(&token_str, &ch_id, shared_key_bytes.as_bytes())
    else {
        tracing::warn!(
            channel_id = %ch_id,
            "🚨 Invalid gcal webhook token (HMAC mismatch)"
        );
        return StatusCode::FORBIDDEN;
    };

    // Look up the channel in integration_state scoped to the user the
    // token attested to. `None` means the row has been renewed/deleted
    // while Google still had the old channel_id in flight — transient,
    // treat as a stale webhook.
    let watch = match service.find_channel_by_google_id(user_id, &ch_id).await {
        Ok(Some(w)) => w,
        Ok(None) => {
            tracing::warn!(
                channel_id = %ch_id,
                user_id = %user_id,
                "⚠️ Webhook for unknown/expired channel — ignoring"
            );
            return StatusCode::OK;
        }
        Err(e) => {
            tracing::error!(
                channel_id = %ch_id,
                error = %e,
                "integration_state lookup failed"
            );
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    };

    let channel_uuid = watch.id;
    let module_id = watch.module_id;
    let integration_uuid = watch.integration_id;

    // Deduplicate by X-Goog-Message-Number. integration_state has no
    // per-row conditional update; the service method reads + compares +
    // writes. Concurrent duplicates in the same millisecond are rare
    // enough to accept the small TOCTOU window; event-level dedup in
    // Redis is the belt to this suspender.
    if let Some(msg_num) = message_number {
        match service
            .advance_message_number(user_id, channel_uuid, msg_num)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                tracing::info!(
                    msg_num,
                    channel = %ch_id,
                    "⏭️ Duplicate or out-of-order gcal message — skipping"
                );
                return StatusCode::OK;
            }
            Err(e) => {
                tracing::error!(
                    channel = %ch_id,
                    msg_num,
                    error = %e,
                    "advance_message_number failed"
                );
                return StatusCode::INTERNAL_SERVER_ERROR;
            }
        }
    }

    // Dispatch in a background task so the webhook response returns
    // immediately (Google requires a quick 200).
    let is_initial_sync = resource_state.as_deref() == Some("sync");
    let service_clone = Arc::clone(&service);
    let redis_clone = redis_client.clone();
    let exec_service_clone = execution_service.as_ref().map(Arc::clone);
    let nats_clone = nats_client.clone();
    let key_clone = worker_shared_key.clone();
    let runtime_clone = runtime.clone();
    let secrets_clone = secrets_manager.clone();
    let worker_mgr_clone = worker_manager.clone();

    tokio::spawn(async move {
        if is_initial_sync {
            tracing::info!(
                channel = %channel_uuid,
                "🔄 Initial sync handshake — establishing sync token, no jobs dispatched"
            );
            if let Err(e) = service_clone
                .sync_channel_events(user_id, channel_uuid)
                .await
            {
                tracing::error!(
                    channel = %channel_uuid,
                    error = %e,
                    "Failed to establish sync token"
                );
            }
        } else if let Err(e) = process_webhook_events(
            service_clone,
            channel_uuid,
            integration_uuid,
            module_id,
            user_id,
            redis_clone,
            exec_service_clone,
            nats_clone,
            key_clone,
            runtime_clone,
            secrets_clone,
            worker_mgr_clone,
        )
        .await
        {
            tracing::error!(
                channel = %channel_uuid,
                error = %e,
                "Failed to process gcal webhook events"
            );
        }
    });

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
        Err(e) => {
            // MCP-581: log full error server-side, return a generic
            // message to the client. Pre-fix `e.to_string()` was
            // echoed verbatim — sqlx errors can include schema and
            // query fragments; the integration-services layer's
            // anyhow chains can include vault paths or upstream
            // provider response bodies. Parity with talos-atlassian's
            // `disconnect_integration_handler` which already follows
            // this pattern. Same threat-model as the general
            // "NEVER return internal error details to API clients"
            // CLAUDE.md security rule.
            tracing::error!(
                user_id = %user_id,
                integration_id = %integration_id,
                error = %e,
                "Failed to disconnect Google Calendar integration"
            );
            Json(ApiResponse {
                success: false,
                data: None::<&str>,
                error: Some("Failed to disconnect integration".to_string()),
            })
        }
    }
}

#[derive(Serialize)]
pub struct ClientConfig {
    client_id: String,
    redirect_uri: String,
    is_configured: bool,
}

// ---------------------------------------------------------------------------
// Watch-channel management endpoints (authenticated, user-scoped)
// ---------------------------------------------------------------------------

// WatchChannelSummary lives in the watch_channel_service module so
// the service and the handler share one canonical shape.
use super::watch_channel_service::WatchChannelService;
pub use super::watch_channel_service::WatchChannelSummary;

/// GET /api/google-calendar/watch-channels
/// Returns every active watch channel for the authenticated user.
pub async fn list_watch_channels_handler(
    State(service): State<Arc<GoogleCalendarService>>,
    Extension(user_id): Extension<Uuid>,
) -> impl IntoResponse {
    match WatchChannelService::new(&service)
        .list_for_user(user_id)
        .await
    {
        Ok(summaries) => Json(ApiResponse {
            success: true,
            data: Some(summaries),
            error: None,
        })
        .into_response(),
        Err(e) => {
            // MCP-925: log server-side, generic to client.
            tracing::error!(
                user_id = %user_id,
                error = %e,
                "Failed to list Google Calendar watch channels"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<Vec<WatchChannelSummary>> {
                    success: false,
                    data: None,
                    error: Some("Failed to list watch channels".to_string()),
                }),
            )
                .into_response()
        }
    }
}

/// POST /api/google-calendar/watch-channels/:channel_uuid/renew
/// Forces the renewal scheduler's logic to run for this one channel.
/// Authz: integration_state is scoped per user_id, so a wrong user
/// gets back "not found" (never sees another user's channel).
pub async fn renew_watch_channel_handler(
    State(service): State<Arc<GoogleCalendarService>>,
    Extension(user_id): Extension<Uuid>,
    Path(channel_uuid): Path<Uuid>,
) -> impl IntoResponse {
    match service.renew_watch_channel(user_id, channel_uuid).await {
        Ok(ch) => Json(ApiResponse {
            success: true,
            data: Some(serde_json::json!({
                "channel_uuid": ch.id,
                "google_channel_id": ch.channel_id,
                "calendar_id": ch.calendar_id,
                "expiration": ch.expiration,
            })),
            error: None,
        })
        .into_response(),
        Err(e) => {
            // MCP-764 (2026-05-13): log full error server-side, return
            // generic message. Same MCP-581 pattern this file already
            // uses for `disconnect_integration_handler` (line ~543).
            // Google Calendar API renewal can return error bodies that
            // include token detail; sqlx errors carry schema/table
            // names; integration-state RPC errors include vault paths.
            // Sibling MCP-764 fix applied to talos-gmail's renewal
            // handler in the same commit.
            tracing::warn!(
                user_id = %user_id,
                channel_uuid = %channel_uuid,
                error = %e,
                "Failed to renew Google Calendar watch channel"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<serde_json::Value> {
                    success: false,
                    data: None,
                    error: Some("Failed to renew watch channel".to_string()),
                }),
            )
                .into_response()
        }
    }
}

/// POST /api/google-calendar/watch-channels/:channel_uuid/test
///
/// Read-only probe of the channel's integration. Verifies the OAuth
/// token still authenticates, the Google API is reachable, and the
/// user still has permission on the calendar list. Intentionally
/// does NOT call `sync_events` — that would advance the stored
/// sync_token and silently consume events that a real webhook
/// delivery would otherwise dispatch to WASM. `list_calendars` is a
/// GET against `/users/me/calendarList` with no server-side state
/// mutation.
pub async fn test_watch_channel_handler(
    State(service): State<Arc<GoogleCalendarService>>,
    Extension(user_id): Extension<Uuid>,
    Path(channel_uuid): Path<Uuid>,
) -> impl IntoResponse {
    let start = std::time::Instant::now();

    // 1. Resolve the channel row (also enforces authz: scoped to user_id).
    let row = match service.find_channel_by_id_raw(user_id, channel_uuid).await {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ApiResponse::<serde_json::Value> {
                    success: false,
                    data: None,
                    error: Some("Watch channel not found".into()),
                }),
            )
                .into_response();
        }
    };

    // 2. Fetch an access token via the unified credential service.
    let integration = match service.get_integration(user_id, row.integration_id).await {
        Ok(Some(i)) => i,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ApiResponse::<serde_json::Value> {
                    success: false,
                    data: None,
                    error: Some("Integration not found".into()),
                }),
            )
                .into_response();
        }
        Err(e) => {
            // MCP-925: test_watch — integration lookup failure.
            tracing::error!(
                user_id = %user_id,
                channel_uuid = %channel_uuid,
                error = %e,
                "test_watch: integration lookup failed"
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<serde_json::Value> {
                    success: false,
                    data: None,
                    error: Some("Failed to look up integration".to_string()),
                }),
            )
                .into_response();
        }
    };
    let access_token = match service.get_access_token(&integration).await {
        Ok(t) => t,
        Err(e) => {
            // MCP-925: test_watch — access-token resolution failure.
            // anyhow chain can include vault paths.
            tracing::error!(
                user_id = %user_id,
                channel_uuid = %channel_uuid,
                error = %e,
                "test_watch: failed to resolve access token"
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<serde_json::Value> {
                    success: false,
                    data: None,
                    error: Some(
                        "Failed to resolve access token — reconnect the integration".to_string(),
                    ),
                }),
            )
                .into_response();
        }
    };

    // 3. Read-only probe: list calendars. No side effects.
    let api = crate::api::GoogleCalendarApiClient::new();
    match api.list_calendars(&access_token).await {
        Ok(calendars) => {
            let target_present = calendars.iter().any(|c| c.id == row.calendar_id);
            Json(ApiResponse {
                success: true,
                data: Some(serde_json::json!({
                    "oauth_ok": true,
                    "calendar_still_accessible": target_present,
                    "calendars_visible": calendars.len(),
                    "duration_ms": start.elapsed().as_millis() as u64,
                    "note": "read-only probe — sync_token unchanged",
                })),
                error: None,
            })
            .into_response()
        }
        Err(e) => {
            // MCP-925: test_watch — Google API probe failed. anyhow
            // chain can carry upstream Google response bodies (auth
            // failure detail, quota error text).
            tracing::error!(
                user_id = %user_id,
                channel_uuid = %channel_uuid,
                error = %e,
                "test_watch: Google Calendar probe failed"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<serde_json::Value> {
                    success: false,
                    data: None,
                    error: Some("Google Calendar probe failed".to_string()),
                }),
            )
                .into_response()
        }
    }
}

/// DELETE /api/google-calendar/watch-channels/:channel_uuid
/// Stops the channel on Google's side and removes the row. Idempotent.
pub async fn stop_watch_channel_handler(
    State(service): State<Arc<GoogleCalendarService>>,
    Extension(user_id): Extension<Uuid>,
    Path(channel_uuid): Path<Uuid>,
) -> impl IntoResponse {
    match service.stop_watch_channel(user_id, channel_uuid).await {
        Ok(_) => Json(ApiResponse {
            success: true,
            data: Some("Channel stopped"),
            error: None,
        }),
        Err(e) => {
            // MCP-925: stop_watch_channel chains errors from the
            // Google channels.stop API, integration-state RPC, and
            // sqlx — log full, generic to client.
            tracing::error!(
                user_id = %user_id,
                channel_uuid = %channel_uuid,
                error = %e,
                "Failed to stop Google Calendar watch channel"
            );
            Json(ApiResponse {
                success: false,
                data: None::<&str>,
                error: Some("Failed to stop watch channel".to_string()),
            })
        }
    }
}

/// Query params for the dedicated Calendar OAuth callback.
#[derive(Deserialize)]
pub struct CalendarOAuthCallbackParams {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

#[derive(Serialize)]
struct OAuthUrlResponse {
    authorization_url: String,
    csrf_token: String,
}

/// `GET /api/google-calendar/connect` — start the DEDICATED Calendar OAuth flow.
///
/// Authenticated (the caller must be a logged-in user). Returns the Google
/// authorization URL to open; `user_id` is bound into the CSRF state token so
/// the callback recovers identity from the token, not a session cookie. This
/// replaces the old SSO-login piggyback that 500s for existing password accounts.
pub async fn connect_calendar_handler(
    State(service): State<Arc<GoogleCalendarService>>,
    Extension(user_id): Extension<Uuid>,
) -> impl IntoResponse {
    if !service.is_configured() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiResponse::<OAuthUrlResponse> {
                success: false,
                data: None,
                error: Some("Google Calendar OAuth is not configured on this server".to_string()),
            }),
        )
            .into_response();
    }

    match service.get_authorization_url(user_id).await {
        Ok((url, csrf_token)) => Json(ApiResponse {
            success: true,
            data: Some(OAuthUrlResponse {
                authorization_url: url,
                csrf_token,
            }),
            error: None,
        })
        .into_response(),
        Err(e) => {
            // Log server-side, generic to client (MCP-923/924 posture).
            tracing::error!(
                user_id = %user_id,
                error = %e,
                "Failed to generate Google Calendar auth URL"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<OAuthUrlResponse> {
                    success: false,
                    data: None,
                    error: Some("Failed to initiate OAuth flow".to_string()),
                }),
            )
                .into_response()
        }
    }
}

/// `GET /api/google-calendar/callback` — dedicated Calendar OAuth callback.
///
/// NOT session-authenticated: cross-site redirects from Google don't carry the
/// SameSite session cookie. The user is identified via the single-use CSRF state
/// token bound at connect time (`handle_callback` → shared driver consume). On
/// success/failure it redirects back to the settings page with a status param.
pub async fn calendar_callback_handler(
    axum::extract::Query(params): axum::extract::Query<CalendarOAuthCallbackParams>,
    State(service): State<Arc<GoogleCalendarService>>,
) -> impl IntoResponse {
    use axum::response::Redirect;
    let frontend_url = talos_config::get_frontend_url();

    // Provider-reported error (user denied consent, etc.).
    if let Some(err) = params.error.as_deref() {
        tracing::warn!(provider_error = %err, "Google Calendar OAuth callback returned provider error");
        return Redirect::to(&format!(
            "{}/settings?google_calendar_error=access_denied#integrations",
            frontend_url
        ));
    }

    let (code, state) = match (params.code, params.state) {
        (Some(c), Some(s)) if !c.is_empty() && !s.is_empty() => (c, s),
        _ => {
            return Redirect::to(&format!(
                "{}/settings?google_calendar_error=missing_code_or_state#integrations",
                frontend_url
            ));
        }
    };

    match service.handle_callback(code, state).await {
        Ok(_integration) => Redirect::to(&format!(
            "{}/settings?google_calendar_connected=1#integrations",
            frontend_url
        )),
        Err(e) => {
            // Log the full cause server-side; the query param stays generic so
            // no internal detail leaks into the browser URL / history.
            tracing::error!(error = %e, "Google Calendar OAuth callback failed");
            Redirect::to(&format!(
                "{}/settings?google_calendar_error=connect_failed#integrations",
                frontend_url
            ))
        }
    }
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
    integration_uuid: Uuid,
    module_id: Option<Uuid>,
    user_id: Uuid,
    redis_client: Option<Arc<redis::Client>>,
    execution_service: Option<Arc<ModuleExecutionService>>,
    nats_client: Option<Arc<async_nats::Client>>,
    worker_shared_key: Option<WorkerSharedKey>,
    runtime: Option<Arc<TalosRuntime>>,
    secrets_manager: Option<Arc<SecretsManager>>,
    worker_manager: Option<Arc<WorkerManager>>,
) -> Result<()> {
    tracing::debug!("🔄 Processing webhook events for channel {}", channel_uuid);

    // 1. Sync events from Google Calendar API
    let events = service
        .sync_channel_events(user_id, channel_uuid)
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

    // Phase C of "every execution gets an actor": resolve an owning actor ONCE
    // for this batch of events. Calendar watches carry no actor, so this is the
    // user's default actor; its `max_llm_tier` then travels with each job. Fail
    // OPEN to actor-less Tier-2 (today's behaviour) on any resolution error so a
    // transient DB hiccup never drops inbound calendar events.
    let actor_repo = talos_actor_repository::ActorRepository::new(service.db_pool.clone());
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
                "gcal dispatch: default-actor resolution failed; dispatching actor-less (Tier-2)"
            );
            (None, talos_workflow_job_protocol::LlmTier::default())
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

    // 7.5. Resolve oauth_account_id + token presence in a single query.
    // The caller already passed in integration_uuid (from the outer
    // handler's WatchChannel lookup), saving us one round-trip.
    // integration_credentials.provider_key for google_calendar is the
    // oauth_account_id — matches what OAuthCredentialService wrote.
    // MCP-535: distinguish "no row" from "DB error". Pre-fix the
    // `.unwrap_or(None)` collapsed both into None, which silently
    // disabled vault-path injection — the worker module then failed
    // with an opaque "missing ACCESS_TOKEN" error while the underlying
    // Postgres failure left no trace. Behaviour is unchanged (None →
    // skip injection) but operators now get a structured error log to
    // drive availability alerts.
    let oauth_account_id: Option<uuid::Uuid> = match sqlx::query_scalar::<_, uuid::Uuid>(
        "SELECT g.oauth_account_id \
         FROM google_calendar_integrations g \
         WHERE g.id = $1 AND g.user_id = $2 AND g.is_active = true \
           AND EXISTS (\
             SELECT 1 FROM integration_credentials c \
             WHERE c.user_id = g.user_id \
               AND c.provider = 'google_calendar' \
               AND c.provider_key = g.oauth_account_id::text \
               AND c.access_token_secret_path IS NOT NULL \
               AND c.is_active = true)",
    )
    .bind(integration_uuid)
    .bind(user_id)
    .fetch_optional(&service.db_pool)
    .await
    {
        Ok(row) => row,
        Err(e) => {
            tracing::error!(
                user_id = %user_id,
                integration_id = %integration_uuid,
                error = %e,
                "process_webhook_events: oauth_account_id lookup failed; \
                 ACCESS_TOKEN vault path will not be injected"
            );
            None
        }
    };
    let channel_has_token: bool = oauth_account_id.is_some();
    let channel_access_token: Option<String> = if channel_has_token {
        Some("vault-ref".into())
    } else {
        None
    };

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
                    Uuid::new_v4(),
                    TriggerType::Webhook,
                    Some(event.clone()),
                    Some(trigger_metadata),
                    None,
                    resolved_actor,
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

        let job_id = execution_id.unwrap_or_else(Uuid::new_v4);

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

        // Inject Google Calendar ACCESS_TOKEN via vault reference — never
        // embed the plaintext token in the job payload (it's persisted to
        // module_executions.input_data and transmitted over NATS).
        let mut enriched_config = config.clone();

        if channel_access_token.is_some() {
            if let Some(obj) = enriched_config.as_object_mut() {
                // The worker resolves vault:// paths at execution time via the
                // secrets provider, so the plaintext token never leaves the
                // controller or appears in job payloads / audit logs.
                //
                // Vault path format (migration 019): oauth/{provider}/
                // {user_id}/{provider_key}/access_token. provider_key for
                // google_calendar is the oauth_account_id, NOT the
                // google_calendar_integrations.id. Using the wrong id
                // was a pre-existing bug fixed here as part of the
                // integration_state cutover.
                if let Some(acct) = oauth_account_id {
                    let vault_path = format!(
                        "vault://oauth/google_calendar/{}/{}/access_token",
                        user_id, acct
                    );
                    obj.insert("ACCESS_TOKEN".to_string(), serde_json::json!(vault_path));
                }
            }
        }

        let input_payload = serde_json::json!({
            "config": enriched_config,
            "data": event_clone
        });

        // Encrypted secrets combine the MODULE's declared
        // allowed_secrets PLUS the host-reserved LLM provider keys.
        // Without this, modules using talos::core::llm::* fail with
        // NotConfigured and vault:// header substitution returns
        // NotFound. Mirrors the canonical pattern in
        // talos-webhooks::handle_inbound_webhook and the engine's
        // build_encrypted_secrets helper. (Was previously
        // Default::default() — fixed alongside gmail dispatch.)
        let encrypted_secrets = talos_integration_helpers::build_dispatch_encrypted_secrets(
            secrets_manager.as_ref(),
            module_uuid,
            user_id,
            // L-1: AAD = execution_id (= job_id for single-node
            // dispatches). The JobRequest below sets
            // `workflow_execution_id = job_id`, matching the worker
            // decrypt AAD.
            job_id,
        )
        .await;

        // Create job request for worker
        let mut job_request = JobRequest {
            crypto_scheme: 0,
            sealing: 0,
            secret_paths: Vec::new(),
            claim_inbox: None,
            job_id,
            workflow_execution_id: job_id, // Single node execution, use same ID
            module_uri: exec_info.module_uri.clone(),
            input_payload,
            encrypted_secrets,
            timeout_ms: 30_000, // 30 second timeout
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
            // Phase C: the resolved actor's tier travels with the job. Defaults
            // to Tier-2 (the default actor is Tier-2) so it's non-breaking; an
            // operator who sets their default actor to `tier1` now gets tier
            // enforcement on calendar-triggered processing without the
            // wrap-in-a-workflow workaround.
            max_llm_tier: actor_tier,
            wasm_bytes: None, // PERFORMANCE: Include bytes directly (avoids file I/O)
            capability_world: None,
            // MCP-1090 (2026-05-16): propagate per-module integration_name
            // from `ModuleExecutionInfo.integration_name`. Pre-fix this site
            // hardcoded None — but gcal-triggered modules ARE part of the
            // google_calendar integration and need integration_state access
            // for OAuth tokens / watch metadata. The worker's
            // `integration_state_ctx_owned()` returns `Unauthorized` when
            // `integration_name` is None or empty, so the prior behaviour
            // failed every integration_state WIT call from gcal-triggered
            // modules. Sibling of MCP-1089 (max_fuel propagation) on the
            // same field-drop class. The gmail dispatch path already
            // propagates this correctly.
            integration_name: exec_info.integration_name.clone(),
            expected_wasm_hash: Some(exec_info.content_hash.clone()),
            // MCP-1089: propagate per-module max_fuel from ModuleExecutionInfo.
            // See talos-gmail/src/dispatch.rs for rationale.
            max_fuel: exec_info.max_fuel,
            dry_run: false,
            reply_topic: None,
            actor_id: resolved_actor,
            user_id,
        };

        // Sign the job request with the shared key for integrity and replay protection.
        // If the key is unavailable the job is skipped — an unsigned job would be
        // rejected by the worker anyway, so publishing it is pointless.
        // If an execution record was already created, mark it as failed so it is
        // not orphaned indefinitely in the database.
        // RFC 0010 P1: prefer the configured Ed25519 dispatch signer; else the
        // legacy HMAC path (unsigned jobs are rejected by the worker, so a
        // missing key is a hard error here).
        let sign_result =
            if let Some(signer) = talos_workflow_job_protocol::configured_dispatch_signer() {
                signer.sign_job(&mut job_request).map_err(|e| {
                    format!(
                        "Failed to sign job {} for event '{}': {}",
                        job_id, event_summary, e
                    )
                })
            } else {
                match &worker_shared_key {
                    Some(key) => job_request.sign(key.as_bytes()).map_err(|e| {
                        format!(
                            "Failed to sign job {} for event '{}': {}",
                            job_id, event_summary, e
                        )
                    }),
                    None => Err(format!(
                        "WORKER_SHARED_KEY not configured — cannot sign job {} for event '{}'",
                        job_id, event_summary
                    )),
                }
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
                let worker_mgr_clone = worker_manager.clone();
                let exec_svc_clone = execution_service.clone();
                tokio::spawn(async move {
                    if let Err(e) = talos_engine::workflow_chains::run_workflow_chains(
                        nats_clone,
                        sm,
                        &db_pool,
                        worker_shared_key_clone,
                        redis_client_clone,
                        worker_mgr_clone,
                        exec_svc_clone,
                        module_uuid,
                        user_id,
                        event_data,
                        channel_uuid,
                        execution_id.unwrap_or(Uuid::new_v4()),
                        Some(sign_err),
                    )
                    .await
                    {
                        tracing::warn!(
                            "Failed to run workflow chains for channel {}: {}",
                            channel_uuid,
                            e
                        );
                    }
                });
            }
            continue; // Skip event, don't return Ok(()) completely
        }

        let job_payload =
            serde_json::to_vec(&job_request).context("Failed to serialize job request")?;

        // Fallback to standard topic for generic deployments,
        // or route dynamically via edge node env var.
        // MCP-1065 (2026-05-15): canonical edge-routing resolver.
        let nats_topic = if talos_config::edge_routing_enabled() {
            format!("talos.jobs.{}", user_id)
        } else {
            "talos.jobs".to_string()
        };

        match nats
            .publish_with_headers(
                nats_topic,
                {
                    let mut headers = async_nats::HeaderMap::new();
                    talos_trace_nats::inject_trace_context(&mut headers);
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
                    let worker_mgr_clone = worker_manager.clone();
                    let exec_svc_clone = execution_service.clone();
                    tokio::spawn(async move {
                        if let Err(e) = talos_engine::workflow_chains::run_workflow_chains(
                            nats_clone,
                            sm,
                            &db_pool,
                            worker_shared_key_clone,
                            redis_client_clone,
                            worker_mgr_clone,
                            exec_svc_clone,
                            module_uuid,
                            user_id,
                            event_data,
                            channel_uuid,
                            execution_id.unwrap_or(Uuid::new_v4()),
                            None, // Google calendar only runs chains on success
                        )
                        .await
                        {
                            tracing::warn!(
                                "Failed to run workflow chains for channel {}: {}",
                                channel_uuid,
                                e
                            );
                        }
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
                    let worker_mgr_clone = worker_manager.clone();
                    let exec_svc_clone = execution_service.clone();
                    tokio::spawn(async move {
                        if let Err(e) = talos_engine::workflow_chains::run_workflow_chains(
                            nats_clone,
                            sm,
                            &db_pool,
                            worker_shared_key_clone,
                            redis_client_clone,
                            worker_mgr_clone,
                            exec_svc_clone,
                            module_uuid,
                            user_id,
                            event_data,
                            channel_uuid,
                            execution_id.unwrap_or(Uuid::new_v4()),
                            Some(err_str),
                        )
                        .await
                        {
                            tracing::warn!(
                                "Failed to run workflow chains for channel {}: {}",
                                channel_uuid,
                                e
                            );
                        }
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
