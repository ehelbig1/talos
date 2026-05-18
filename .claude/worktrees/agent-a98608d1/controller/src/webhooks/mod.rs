// Webhook router contains functionality not exercised by the current test suite.
#![allow(dead_code, unused_imports, unused_mut, unused_variables)]
use anyhow::{Context, Result};
use axum::{
    body::Bytes,
    extract::Path,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension,
};
use sqlx::{Pool, Postgres, Row};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;

use crate::module_executions::ExecutionStatus;
use crate::registry::ModuleRegistry;
use crate::secrets::SecretsManager;

// Suppress a collection of clippy warnings that surface in this module but are not
// critical for functionality.
// Suppress selected clippy warnings for this module.
#[allow(
    clippy::needless_borrow,
    clippy::needless_borrows_for_generic_args,
    clippy::option_as_ref_deref,
    clippy::too_many_arguments,
    clippy::unused_async
)]
mod rate_limiter;
use rate_limiter::RateLimiter;

/// Webhook router manages incoming webhook requests
#[derive(Clone)]
pub struct WebhookRouter {
    db_pool: Pool<Postgres>,
    registry: Arc<ModuleRegistry>,
    secrets_manager: Arc<SecretsManager>,
    rate_limiter: Arc<RateLimiter>, // No RwLock needed - DashMap is lock-free
    nats_client: Arc<async_nats::Client>,
    worker_shared_key: Option<Arc<Vec<u8>>>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct WebhookTrigger {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub module_id: Uuid,
    pub verification_token: Option<String>,
    pub signing_secret: Option<String>,
    pub allowed_ips: Option<Vec<String>>,
    pub enabled: bool,
    pub auto_respond: bool,
    pub queue_events: bool,
    pub max_requests_per_minute: i32,
}

impl WebhookRouter {
    /// Creates a new `WebhookRouter`. Returns an error if the WASM runtime cannot be initialized.
    pub fn new(
        db_pool: Pool<Postgres>,
        registry: Arc<ModuleRegistry>,
        secrets_manager: Arc<SecretsManager>,
        nats_client: Arc<async_nats::Client>,
        worker_shared_key: Option<Arc<Vec<u8>>>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            db_pool,
            registry,
            secrets_manager,
            rate_limiter: Arc::new(RateLimiter::new()), // No RwLock - DashMap is lock‑free
            nats_client,
            worker_shared_key,
        })
    }

    /// Handle an incoming webhook request
    pub async fn handle_webhook(
        &self,
        trigger_id: Uuid,
        headers: &HeaderMap,
        body: Bytes,
        source_ip: Option<IpAddr>,
    ) -> Result<Response> {
        let start_time = Instant::now();

        // 1. Lookup trigger configuration
        let trigger = self.get_trigger(trigger_id).await?;

        if !trigger.enabled {
            tracing::warn!(
                trigger_id = %trigger_id,
                "Webhook trigger is disabled"
            );
            return Ok((StatusCode::NOT_FOUND, "Not found").into_response());
        }

        // 2. Check rate limit (lock-free with DashMap)
        if !self
            .rate_limiter
            .allow(trigger_id, trigger.max_requests_per_minute as usize)
        {
            tracing::warn!(
                trigger_id = %trigger_id,
                "Rate limit exceeded"
            );
            self.log_request(
                trigger_id,
                headers,
                &body,
                source_ip,
                StatusCode::TOO_MANY_REQUESTS.as_u16() as i32,
                None,
                0,
                0,
                false,
                Some("Rate limit exceeded"),
            )
            .await;
            return Ok((StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded").into_response());
        }

        // 3. Check IP allowlist
        if let Some(allowed_ips) = &trigger.allowed_ips {
            if !allowed_ips.is_empty() {
                if let Some(ip) = source_ip {
                    // Parse stored strings to IpAddr before comparing — string equality
                    // fails for equivalent addresses with different representations
                    // (e.g. "::ffff:1.2.3.4" vs "1.2.3.4", or leading zeros).
                    // Invalid entries are logged as an operator error and treated as
                    // non-matching (deny by default), but should not reach this path
                    // since create_webhook_trigger validates IPs at insertion time.
                    let mut allowed = false;
                    for stored in allowed_ips {
                        if let Ok(network) = stored.parse::<ipnetwork::IpNetwork>() {
                            if network.contains(ip) {
                                allowed = true;
                                break;
                            }
                        } else if let Ok(a) = stored.parse::<std::net::IpAddr>() {
                            if a == ip {
                                allowed = true;
                                break;
                            }
                        } else {
                            tracing::error!(
                                trigger_id = %trigger_id,
                                invalid_ip = %stored,
                                "Malformed IP/CIDR in allowed_ips list — failing immediately"
                            );
                            self.log_request(
                                trigger_id,
                                headers,
                                &body,
                                source_ip,
                                StatusCode::INTERNAL_SERVER_ERROR.as_u16() as i32,
                                None,
                                0,
                                0,
                                false,
                                Some("Invalid IP/CIDR configuration"),
                            )
                            .await;
                            return Ok((
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "Invalid IP/CIDR configuration",
                            )
                                .into_response());
                        }
                    }
                    if !allowed {
                        tracing::warn!(
                            trigger_id = %trigger_id,
                            ip = %ip,
                            "IP not in allowlist"
                        );
                        self.log_request(
                            trigger_id,
                            headers,
                            &body,
                            source_ip,
                            StatusCode::FORBIDDEN.as_u16() as i32,
                            None,
                            0,
                            0,
                            false,
                            Some("IP not allowed"),
                        )
                        .await;
                        return Ok((StatusCode::FORBIDDEN, "Forbidden").into_response());
                    }
                }
            }
        }

        // 4. Verify HMAC signature if signing_secret is configured
        if let Some(signing_secret) = &trigger.signing_secret {
            if !self.verify_hmac_signature(headers, &body, signing_secret) {
                tracing::warn!(
                    trigger_id = %trigger_id,
                    "HMAC signature verification failed"
                );
                self.log_request(
                    trigger_id,
                    headers,
                    &body,
                    source_ip,
                    StatusCode::UNAUTHORIZED.as_u16() as i32,
                    None,
                    0,
                    0,
                    false,
                    Some("Invalid signature"),
                )
                .await;
                return Ok((StatusCode::UNAUTHORIZED, "Invalid signature").into_response());
            }
        }

        // 5. Load WASM module (pass user_id to enforce ownership)
        let module_bytes = match self
            .registry
            .get_module_bytes(trigger.module_id, trigger.user_id)
            .await
        {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::error!(
                    trigger_id = %trigger_id,
                    module_id = %trigger.module_id,
                    error = %e,
                    "Failed to load WASM module"
                );
                self.log_request(
                    trigger_id,
                    headers,
                    &body,
                    source_ip,
                    StatusCode::INTERNAL_SERVER_ERROR.as_u16() as i32,
                    None,
                    0,
                    0,
                    false,
                    Some(&format!("Failed to load module: {}", e)),
                )
                .await;
                return Ok(
                    (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
                );
            }
        };

        // 6. Get module config and resolve secrets (pass user_id to enforce ownership)
        let module_config = match self
            .registry
            .get_module_config(trigger.module_id, trigger.user_id)
            .await
        {
            Ok(Some(config)) => config,
            Ok(None) => serde_json::json!({}),
            Err(e) => {
                tracing::error!(
                    trigger_id = %trigger_id,
                    error = %e,
                    "Failed to get module config"
                );
                self.log_request(
                    trigger_id,
                    headers,
                    &body,
                    source_ip,
                    StatusCode::INTERNAL_SERVER_ERROR.as_u16() as i32,
                    None,
                    0,
                    0,
                    false,
                    Some(&format!("Failed to get module config: {}", e)),
                )
                .await;
                return Ok(
                    (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
                );
            }
        };

        // 7. Parse raw body into JSON (or keep as string) and wrap with config.
        //    Slack enrichment (user profiles, channel info, thread context, mention
        //    resolution) and per-channel rate limiting are now handled inside the
        //    slack-webhook-listener WASM template via the `http` and `state` interfaces.
        // Require valid UTF-8; reject bodies with invalid byte sequences rather
        // than silently replacing them, which could mask injection attempts.
        let body_str = match std::str::from_utf8(&body) {
            Ok(s) => s.to_string(),
            Err(_) => {
                tracing::warn!(
                    trigger_id = %trigger_id,
                    "Webhook body contains invalid UTF-8; rejecting request"
                );
                return Ok(
                    (StatusCode::BAD_REQUEST, "Invalid UTF-8 in request body").into_response()
                );
            }
        };
        let payload_value = serde_json::from_str::<serde_json::Value>(&body_str)
            .unwrap_or(serde_json::Value::String(body_str.clone()));

        // Wrap webhook payload with config
        let wrapped_input = serde_json::json!({
            "config": module_config,
            "input": payload_value
        });
        let input_str = wrapped_input.to_string();

        // 9. Execute WASM module (async — execute_module_with_timeout is now async)
        let wasm_start = Instant::now();
        let job_id = Uuid::new_v4();

        if let Err(e) = sqlx::query(
            "INSERT INTO module_executions (id, module_id, user_id, status, input_data, workflow_execution_id, trigger_type, started_at)
             VALUES ($1, $2, $3, 'running', $4, $5, 'webhook', NOW())
             ON CONFLICT DO NOTHING"
        )
        .bind(job_id)
        .bind(trigger.module_id)
        .bind(trigger.user_id)
        .bind(&payload_value)
        .bind(None::<Uuid>)
        .execute(&self.db_pool)
        .await {
            tracing::error!("Failed to insert module_execution for webhook: {}", e);
        }

        let worker_shared_key_clone = self.worker_shared_key.clone();
        let result = tokio::spawn({
            let registry = self.registry.clone();
            let nats = self.nats_client.clone();
            let secrets_manager = self.secrets_manager.clone();
            let module_id = trigger.module_id;
            let user_id = trigger.user_id;
            let input_value = payload_value.clone();
            let job_id = job_id;

            async move {
                let exec_info = match registry.get_execution_info(module_id, user_id).await {
                    Ok(info) => info,
                    Err(e) => {
                        tracing::error!(
                            "Failed to prepare webhook module {} for execution: {}",
                            module_id,
                            e
                        );
                        return Err(anyhow::anyhow!("Module not available"));
                    }
                };

                let mut req = job_protocol::JobRequest {
                    job_id,
                    workflow_execution_id: job_id, // Standalone webhook uses same ID
                    module_uri: exec_info.module_uri,
                    input_payload: input_value,
                    encrypted_secrets: {
                        let mut es = Default::default();
                        if let Ok(key) = job_protocol::load_worker_shared_key() {
                            if let Ok(secrets_map) =
                                secrets_manager.get_module_secrets(module_id).await
                            {
                                if let Ok(encrypted) =
                                    job_protocol::EncryptedSecrets::encrypt(&secrets_map, &key)
                                {
                                    es = encrypted;
                                }
                            }
                        }
                        es
                    },
                    timeout_ms: 3_000,
                    allowed_hosts: exec_info.allowed_hosts,
                    allowed_methods: exec_info.allowed_methods,
                    signature: vec![],
                    job_nonce: String::new(),
                    wasm_bytes: None,
                };

                if let Some(key) = &worker_shared_key_clone {
                    req.sign(key)
                        .map_err(|e| anyhow::anyhow!("Failed to sign job request: {}", e))?;
                }
                let payload = serde_json::to_vec(&req).map_err(|e| anyhow::anyhow!(e))?;

                // Request-reply pattern via NATS
                let topic = format!("talos.jobs.{}", user_id);
                let fallback_topic = "talos.jobs".to_string();
                let topic_to_use = if std::env::var("ENABLE_EDGE_ROUTING")
                    .unwrap_or_else(|_| "false".to_string())
                    == "true"
                {
                    topic
                } else {
                    fallback_topic
                };

                let response = tokio::time::timeout(
                    std::time::Duration::from_secs(3),
                    nats.request(topic_to_use, payload.into()),
                )
                .await
                .map_err(|_| anyhow::anyhow!("WASM execution timed out after 3s"))??;

                let result: job_protocol::JobResult =
                    serde_json::from_slice(&response.payload).map_err(|e| anyhow::anyhow!(e))?;

                match result.status {
                    job_protocol::JobStatus::Success => Ok(result.output_payload.to_string()),
                    _ => Err(anyhow::anyhow!(
                        "Execution failed: {}",
                        result.output_payload
                    )),
                }
            }
        })
        .await;

        let wasm_duration_ms = wasm_start.elapsed().as_millis() as i32;

        let (response_body, success, error_msg) = match result {
            Ok(Ok(output)) => (output, true, None),
            Ok(Err(e)) => {
                tracing::error!(
                    trigger_id = %trigger_id,
                    error = %e,
                    "WASM execution failed"
                );
                (String::new(), false, Some(e.to_string()))
            }
            Err(e) => {
                tracing::error!(
                    trigger_id = %trigger_id,
                    error = %e,
                    "WASM task panicked"
                );
                (String::new(), false, Some(format!("Task panicked: {}", e)))
            }
        };

        let total_duration_ms = start_time.elapsed().as_millis() as i32;

        // ------------------------------------------------------------
        // Decoupled Write Path (Phase 2): Async Logging & State Updates
        // ------------------------------------------------------------
        // Update statistics, log the request, and record the workflow execution
        // in a background task so the HTTP response can return immediately.
        let status_code = if success {
            StatusCode::OK
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        };
        let response_body_clone = response_body.clone();
        let error_msg_clone = error_msg.clone();
        let headers_clone = headers.clone();
        let body_clone = body.clone();
        let router_clone = self.clone();
        let trigger_user_id = trigger.user_id;
        let module_id = trigger.module_id;

        tokio::spawn(async move {
            // 10. Update statistics (scoped to trigger owner via user_id)
            router_clone
                .update_trigger_stats(trigger_id, trigger_user_id, success, total_duration_ms)
                .await;

            // 11. Log request
            router_clone
                .log_request(
                    trigger_id,
                    &headers_clone,
                    &body_clone,
                    source_ip,
                    status_code.as_u16() as i32,
                    if success {
                        Some(&response_body_clone)
                    } else {
                        None
                    },
                    total_duration_ms,
                    wasm_duration_ms,
                    success,
                    error_msg_clone.as_deref(),
                )
                .await;
        });

        // 12. Chain to downstream workflow nodes — fire and forget so the
        //     HTTP response is returned immediately (webhook callers time out fast).
        let output_value = serde_json::from_str::<serde_json::Value>(&response_body)
            .unwrap_or(serde_json::Value::String(response_body.clone()));
        let nats = self.nats_client.clone();
        let secrets_manager = self.secrets_manager.clone();
        let db_pool = self.db_pool.clone();
        let worker_shared_key_for_chain = self.worker_shared_key.clone();
        let redis_client = self.registry.redis_client.clone();
        let module_id = trigger.module_id;
        let user_id = trigger.user_id;
        let trigger_error = error_msg.clone();
        tokio::spawn(async move {
            crate::engine::workflow_chains::run_workflow_chains(
                nats,
                secrets_manager,
                &db_pool,
                worker_shared_key_for_chain,
                redis_client,
                module_id,
                user_id,
                output_value,
                trigger_id,
                job_id,
                trigger_error,
            )
            .await;
        });

        // 13. Return response
        if trigger.auto_respond {
            if success {
                Ok((status_code, response_body).into_response())
            } else {
                Ok((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error_msg.unwrap_or_else(|| "Internal server error".to_string()),
                )
                    .into_response())
            }
        } else {
            Ok((StatusCode::OK, "OK").into_response())
        }
    }

    async fn get_trigger(&self, trigger_id: Uuid) -> Result<WebhookTrigger> {
        sqlx::query_as::<_, WebhookTrigger>(
            r#"
            SELECT id, user_id, name, module_id,
                   verification_token, signing_secret, allowed_ips,
                   enabled, auto_respond, queue_events, max_requests_per_minute
            FROM webhook_triggers
            WHERE id = $1
            "#,
        )
        .bind(trigger_id)
        .fetch_one(&self.db_pool)
        .await
        .context("Webhook trigger not found")
    }

    /// Verify HMAC signature from webhook request
    /// Supports multiple header formats (Slack, GitHub, etc.)
    // Made public to enable external testing of HMAC verification logic.
    #[must_use]
    pub fn verify_hmac_signature(
        &self,
        headers: &HeaderMap,
        body: &Bytes,
        signing_secret: &str,
    ) -> bool {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        use subtle::ConstantTimeEq;

        // Try Slack signature format first (X-Slack-Signature)
        if let Some(signature) = headers.get("x-slack-signature") {
            if let Ok(sig_str) = signature.to_str() {
                // Slack format: v0=<hash>
                if let Some(hash_hex) = sig_str.strip_prefix("v0=") {
                    if let Some(timestamp) = headers.get("x-slack-request-timestamp") {
                        if let Ok(ts_str) = timestamp.to_str() {
                            // Enforce timestamp freshness (±5 minutes) to prevent replay attacks.
                            // Slack's own documentation recommends this check.
                            if let Ok(ts_secs) = ts_str.parse::<i64>() {
                                let now_secs = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_secs() as i64)
                                    .unwrap_or(0);
                                if (now_secs - ts_secs).abs() > 300 {
                                    tracing::warn!(
                                        timestamp = ts_secs,
                                        now = now_secs,
                                        "Slack request timestamp is outside the ±5 minute window — replay attack?"
                                    );
                                    return false;
                                }
                            } else {
                                tracing::warn!(
                                    "Slack X-Slack-Request-Timestamp is not a valid integer"
                                );
                                return false;
                            }

                            // Create basestring: version:timestamp:body
                            let base_string = format!("v0:{}:", ts_str);
                            let mut full_message = base_string.into_bytes();
                            full_message.extend_from_slice(&body);

                            // Compute HMAC
                            let mut mac =
                                match Hmac::<Sha256>::new_from_slice(signing_secret.as_bytes()) {
                                    Ok(m) => m,
                                    Err(_) => {
                                        tracing::error!("Invalid HMAC secret size");
                                        return false;
                                    }
                                };
                            mac.update(&full_message);
                            let result = mac.finalize();
                            let expected = hex::encode(result.into_bytes());

                            return expected.as_bytes().ct_eq(hash_hex.as_bytes()).unwrap_u8() == 1;
                        }
                    }
                }
            }
        }

        // Try GitHub signature format (X-Hub-Signature-256)
        if let Some(signature) = headers.get("x-hub-signature-256") {
            if let Ok(sig_str) = signature.to_str() {
                if let Some(hash_hex) = sig_str.strip_prefix("sha256=") {
                    let mut mac = match Hmac::<Sha256>::new_from_slice(signing_secret.as_bytes()) {
                        Ok(m) => m,
                        Err(_) => {
                            tracing::error!("Invalid HMAC secret size");
                            return false;
                        }
                    };
                    mac.update(body);
                    let result = mac.finalize();
                    let expected = hex::encode(result.into_bytes());

                    return expected.as_bytes().ct_eq(hash_hex.as_bytes()).unwrap_u8() == 1;
                }
            }
        }

        // Try generic X-Signature header
        if let Some(signature) = headers.get("x-signature") {
            if let Ok(sig_str) = signature.to_str() {
                let mut mac = match Hmac::<Sha256>::new_from_slice(signing_secret.as_bytes()) {
                    Ok(m) => m,
                    Err(_) => {
                        tracing::error!("Invalid HMAC secret size");
                        return false;
                    }
                };
                mac.update(body);
                let result = mac.finalize();
                let expected = hex::encode(result.into_bytes());

                return expected.as_bytes().ct_eq(sig_str.as_bytes()).unwrap_u8() == 1;
            }
        }

        // No recognized signature header found
        tracing::warn!("No recognized signature header found in request");
        false
    }

    async fn update_trigger_stats(
        &self,
        trigger_id: Uuid,
        user_id: Uuid,
        success: bool,
        response_time_ms: i32,
    ) {
        let result = if success {
            sqlx::query(
                r#"
                UPDATE webhook_triggers
                SET last_triggered_at = NOW(),
                    trigger_count = trigger_count + 1,
                    success_count = success_count + 1,
                    avg_response_ms = COALESCE(
                        (avg_response_ms * success_count + $3::float) / (success_count + 1),
                        $3::float
                    )
                WHERE id = $1 AND user_id = $2
                "#,
            )
            .bind(trigger_id)
            .bind(user_id)
            .bind(response_time_ms as f64)
            .execute(&self.db_pool)
            .await
        } else {
            sqlx::query(
                r#"
                UPDATE webhook_triggers
                SET last_triggered_at = NOW(),
                    trigger_count = trigger_count + 1,
                    error_count = error_count + 1
                WHERE id = $1 AND user_id = $2
                "#,
            )
            .bind(trigger_id)
            .bind(user_id)
            .execute(&self.db_pool)
            .await
        };

        if let Err(e) = result {
            tracing::error!(
                trigger_id = %trigger_id,
                error = %e,
                "Failed to update trigger stats"
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn log_request(
        &self,
        trigger_id: Uuid,
        headers: &HeaderMap,
        body: &Bytes,
        source_ip: Option<IpAddr>,
        status_code: i32,
        response_body: Option<&str>,
        response_time_ms: i32,
        wasm_execution_ms: i32,
        success: bool,
        error_message: Option<&str>,
    ) {
        // Convert headers to JSON
        let headers_json: HashMap<String, String> = headers
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_string(),
                    v.to_str().unwrap_or("[binary]").to_string(),
                )
            })
            .collect();

        let user_agent = headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let ip_str = source_ip.map(|ip| ip.to_string());

        // Convert body bytes to string (or use placeholder for binary data).
        // Strip ASCII control characters (except \t, \n, \r) to prevent log injection.
        let body_str_owned: String;
        let body_str = match std::str::from_utf8(body.as_ref()) {
            Ok(s) => {
                body_str_owned = s
                    .chars()
                    .filter(|c| !c.is_ascii_control() || matches!(c, '\t' | '\n' | '\r'))
                    .take(65_535) // cap logged body at 64 KiB
                    .collect();
                body_str_owned.as_str()
            }
            Err(_) => "[binary data]",
        };

        let result = sqlx::query!(
            r#"
            INSERT INTO webhook_request_log (
                trigger_id, method, headers, body, source_ip, user_agent,
                status_code, response_body, response_time_ms, wasm_execution_ms,
                success, error_message
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            "#,
            trigger_id,
            "POST",
            serde_json::to_value(&headers_json).ok(),
            body_str,
            ip_str.as_deref(),
            user_agent.as_deref(),
            status_code,
            response_body,
            response_time_ms,
            wasm_execution_ms,
            success,
            error_message
        )
        .execute(&self.db_pool)
        .await;

        if let Err(e) = result {
            tracing::error!(
                trigger_id = %trigger_id,
                error = %e,
                "Failed to log webhook request"
            );
        }
    }

    /// Evict idle token-bucket entries from the in-memory webhook rate limiter.
    ///
    /// Call periodically from a background task to prevent unbounded memory
    /// growth when many unique webhook tokens are hit over the lifetime of the
    /// process.  Buckets inactive for more than `max_idle` are removed.
    pub fn cleanup_rate_limiter(&self) {
        self.rate_limiter
            .cleanup(std::time::Duration::from_secs(600)); // evict buckets idle > 10 min
    }

    /// Clean up old webhook request logs (default retention: 90 days)
    pub async fn cleanup_request_logs(&self, retention_days: i64) -> Result<u64> {
        let result = sqlx::query(
            "DELETE FROM webhook_request_log WHERE created_at < NOW() - INTERVAL '1 day' * $1",
        )
        .bind(retention_days)
        .execute(&self.db_pool)
        .await?;

        Ok(result.rows_affected())
    }
}

/// Axum handler for webhook requests
pub async fn webhook_handler(
    Path(trigger_id): Path<Uuid>,
    headers: HeaderMap,
    Extension(webhook_router): Extension<Arc<WebhookRouter>>,
    body: Bytes,
) -> Response {
    // Extract source IP from headers using the same CIDR-based trusted proxy
    // model as the rate limiter (TRUSTED_PROXY_CIDRS env var). This replaces the
    // previous permissive `TRUSTED_PROXY=true` boolean approach.
    //
    // The webhook handler does not have ConnectInfo (direct peer IP), so we
    // only trust X-Forwarded-For when TRUSTED_PROXY_CIDRS is explicitly set by
    // the operator — indicating they have configured a reverse proxy.
    let source_ip = if std::env::var("TRUSTED_PROXY_CIDRS").is_ok() {
        headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .and_then(|s| s.trim().parse().ok())
    } else {
        None
    };

    match webhook_router
        .handle_webhook(trigger_id, &headers, body, source_ip)
        .await
    {
        Ok(response) => response,
        Err(e) => {
            tracing::error!(
                trigger_id = %trigger_id,
                error = %e,
                "Webhook handler error"
            );
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
        }
    }
}

use serde::Deserialize;

#[derive(Deserialize)]
pub struct ApprovalPayload {
    pub approved: bool,
}

pub async fn approval_handler(
    Path(execution_id): Path<String>,
    Extension(user_id): Extension<uuid::Uuid>,
    Extension(redis_client): Extension<Option<std::sync::Arc<redis::Client>>>,
    Extension(nats_client): Extension<Option<std::sync::Arc<async_nats::Client>>>,
    axum::Json(payload): axum::Json<ApprovalPayload>,
) -> impl IntoResponse {
    tracing::info!(
        "User {} is resolving approval for execution {}",
        user_id,
        execution_id
    );
    let redis = match redis_client {
        Some(r) => r,
        None => return (StatusCode::INTERNAL_SERVER_ERROR, "Redis not available").into_response(),
    };
    let nats = match nats_client {
        Some(n) => n,
        None => return (StatusCode::INTERNAL_SERVER_ERROR, "NATS not available").into_response(),
    };

    let mut con = match redis.get_multiplexed_tokio_connection().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to get Redis connection: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Redis error").into_response();
        }
    };

    // The frontend UI calls this webhook with the workflow_execution_id, not the specific node's execution_id.
    let redis_key = format!("approval:{}", execution_id);
    let reply_topic: Option<String> = redis::cmd("GET")
        .arg(&redis_key)
        .query_async(&mut con)
        .await
        .unwrap_or(None);

    let topic = match reply_topic {
        Some(t) => t,
        None => {
            return (
                StatusCode::NOT_FOUND,
                "Approval request not found or expired",
            )
                .into_response()
        }
    };

    let response_str = if payload.approved { "true" } else { "false" };

    if let Err(e) = nats.publish(topic, response_str.into()).await {
        tracing::error!("Failed to publish approval to NATS: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to send approval").into_response();
    }

    (StatusCode::OK, "Approval processed").into_response()
}
