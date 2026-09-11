use anyhow::{Context, Result};
use axum::{
    body::Bytes,
    extract::Path,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension,
};
use sqlx::{Pool, Postgres};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;

use talos_engine::events::ExecutionEvent;
use talos_module_executions::ModuleExecutionService;
use talos_registry::ModuleRegistry;

use crate::dispatch_failure::{self, ModuleDispatchFailure};
use talos_secrets_manager::SecretsManager;
use talos_worker_fleet::WorkerManager;
use talos_workflow_engine_core::WorkerSharedKey;

use crate::dlq::{self, DlqEntry, DlqService};
use crate::rate_limiter;
use crate::rate_limiter::RateLimiter;
use crate::signature::{self, WebhookAuthOutcome};
use crate::types::{
    build_module_dispatch_payload, build_webhook_trigger_payload, event_filter_matches,
    webhook_must_fail_closed_on_hmac, WebhookTrigger,
};
use crate::{CircuitBreaker, CircuitBreakerFailureType};

// ============================================================================

/// Maximum webhook payload size (1 MB) to prevent memory exhaustion attacks.
const MAX_WEBHOOK_PAYLOAD_SIZE: usize = 1024 * 1024;

/// Insert the `module_executions` tracking row for a bare-module webhook
/// dispatch — the ONE implementation shared by the live delivery path and the
/// DLQ replay path.
///
/// Why it must run before every such dispatch: `wasm.log.{job_id}` routing is
/// `WHERE EXISTS`-guarded on this table, so a job dispatched under an id with
/// no row here has its logs discarded, never reaches a terminal status, and is
/// invisible to `get_execution_logs`. The DLQ replay path had no INSERT at all
/// — 100% of replayed webhook module deliveries were orphaned that way, which
/// is the worst possible moment to lose the logs (an operator replays a DLQ
/// entry *because* they are debugging it).
///
/// Both encrypt branches are preserved deliberately:
/// * `encrypt_payload_bundle` OK → `pt_payload` stays `None` and only the
///   ciphertext lands in `input_data_enc` (MCP-S2: AAD = `job_id`, binding the
///   ciphertext to this row). No org context on a standalone webhook dispatch →
///   global DEK (v3).
/// * encryption FAILS (KMS outage, DEK rotation race, wiring gap) → fall back
///   to plaintext in `input_data`, but DLP-redacted first (MCP-987). Webhook
///   bodies routinely carry secrets — provider callbacks echo bearer tokens,
///   signing signatures land in the JSON itself — so an unredacted fallback
///   would land secret-shaped values in a queryable column. An encryption
///   failure is NOT fatal to the dispatch; only the INSERT failing is.
///
/// `ON CONFLICT DO NOTHING` is load-bearing: replay may re-run against a
/// `job_id` that already has a row.
///
/// `org_id` / `actor_id` NOT-NULLs are filled by `trg_set_default_actor`.
///
/// Free function (rather than a `&self` method) so the family harness in
/// `controller/tests/wasm_log_routing_tests.rs` can drive the REAL statement
/// against a real Postgres — the `WHERE EXISTS` interaction is the thing under
/// test and a mock cannot fail the way the real statement failed.
#[allow(clippy::too_many_arguments)]
pub async fn insert_webhook_module_execution(
    db_pool: &Pool<Postgres>,
    secrets_manager: &Arc<SecretsManager>,
    job_id: Uuid,
    module_id: Uuid,
    user_id: Uuid,
    payload: &serde_json::Value,
    actor_id: Option<Uuid>,
) -> Result<(), sqlx::Error> {
    let payload_bundle = match talos_module_payload_encryption::encrypt_payload_bundle(
        Some(secrets_manager),
        job_id,
        // Standalone webhook module dispatch — no parent workflow
        // execution, so no org to scope to → global DEK (v3).
        None,
        Some(payload),
        None,
        None,
    )
    .await
    {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("Failed to encrypt webhook payload: {}", e);
            talos_module_payload_encryption::EncryptedPayloadBundle::default()
        }
    };
    let redacted_pt_payload = if payload_bundle.encrypting() {
        None
    } else {
        Some(talos_dlp_provider::redact_json(payload))
    };

    sqlx::query(
        "INSERT INTO module_executions (id, module_id, user_id, status, \
          input_data, input_data_enc, payload_enc_key_id, payload_format, \
          workflow_execution_id, actor_id, trigger_type, started_at)
         VALUES ($1, $2, $3, 'running', $4, $5, $6, $7, $8, $9, 'webhook', NOW())
         ON CONFLICT DO NOTHING",
    )
    .bind(job_id)
    .bind(module_id)
    .bind(user_id)
    .bind(redacted_pt_payload.as_ref())
    .bind(payload_bundle.input_enc.as_deref())
    .bind(payload_bundle.key_id)
    .bind(payload_bundle.format_version)
    .bind(None::<Uuid>)
    .bind(actor_id)
    .execute(db_pool)
    .await
    .map(|_| ())
}

/// The inbound request material a post-auth DLQ capture needs
/// (`WebhookRouter::capture_post_auth_drop`). Borrowed from `handle_webhook`
/// and threaded into `trigger_workflow_execution` so its pre-dispatch exits
/// can record a replayable row; the DLQ replay path passes `None`.
pub struct DlqCapture<'a> {
    pub headers: &'a axum::http::HeaderMap,
    pub body: &'a axum::body::Bytes,
    pub source_ip: Option<std::net::IpAddr>,
}

/// Webhook router manages incoming webhook requests
#[derive(Clone)]
pub struct WebhookRouter {
    db_pool: Pool<Postgres>,
    registry: Arc<ModuleRegistry>,
    secrets_manager: Arc<SecretsManager>,
    rate_limiter: Arc<RateLimiter>, // No RwLock needed - DashMap is lock-free
    circuit_breaker: Arc<CircuitBreaker>,
    nats_client: Arc<async_nats::Client>,
    worker_shared_key: Option<WorkerSharedKey>,
    worker_manager: Option<Arc<WorkerManager>>,
    module_execution_service: Option<Arc<ModuleExecutionService>>,
    event_sender: tokio::sync::broadcast::Sender<ExecutionEvent>,
    dlq_service: DlqService,
    /// Optional Redis-backed deduplication. When present, identical webhook deliveries
    /// (same trigger + same payload fingerprint) within the 1-hour window are suppressed.
    dedup: Option<std::sync::Arc<talos_idempotency::WebhookDeduplication>>,
    /// RFC 0010 P3 (M4): the shared claim-based-sealing handle, injected by the
    /// controller when `TALOS_ENVELOPE_SEALING` is on (audit/required) and an
    /// Ed25519 signing key is configured. `Some` drives both dispatch sites
    /// (request-reply + DLQ replay) to register plaintext for a worker claim
    /// instead of shipping a WSK envelope that `required` refuses. `None` keeps
    /// the inline envelope path (byte-identical to pre-M4).
    sealing_handle: Option<talos_integration_helpers::ModuleSealingHandle>,
}

impl WebhookRouter {
    /// MCP-1131 (2026-05-16): signal the DLQ batch processor to flush
    /// its in-memory batch and exit before tokio aborts the task.
    /// Called by the controller's graceful_shutdown callback. Closes
    /// the explicit "DLQ messages in-flight" concern from MCP-667.
    pub fn shutdown_dlq(&self) {
        self.dlq_service.shutdown();
    }

    /// Creates a new `WebhookRouter`. Returns an error if the WASM runtime cannot be initialized.
    pub fn new(
        db_pool: Pool<Postgres>,
        registry: Arc<ModuleRegistry>,
        secrets_manager: Arc<SecretsManager>,
        nats_client: Arc<async_nats::Client>,
        worker_shared_key: Option<WorkerSharedKey>,
        circuit_breaker: Arc<CircuitBreaker>,
        worker_manager: Option<Arc<WorkerManager>>,
        module_execution_service: Option<Arc<ModuleExecutionService>>,
        event_sender: tokio::sync::broadcast::Sender<ExecutionEvent>,
        dlq_event_sender: tokio::sync::broadcast::Sender<talos_engine::events::DlqEvent>,
        dedup: Option<std::sync::Arc<talos_idempotency::WebhookDeduplication>>,
        sealing_handle: Option<talos_integration_helpers::ModuleSealingHandle>,
    ) -> anyhow::Result<Self> {
        let dlq_service = DlqService::new(db_pool.clone(), dlq_event_sender);
        Ok(Self {
            db_pool,
            registry,
            secrets_manager,
            rate_limiter: Arc::new(RateLimiter::new()), // No RwLock - DashMap is lock‑free
            circuit_breaker,
            nats_client,
            worker_shared_key,
            worker_manager,
            module_execution_service,
            event_sender,
            dlq_service,
            dedup,
            sealing_handle,
        })
    }

    /// Enqueue a dropped webhook payload into the dead-letter queue.
    /// Uses the bounded DLQ service with backpressure — never blocks the response path.
    ///
    /// `authenticated` records whether the request had passed the auth gate
    /// (HMAC / verification token / IP allowlist) when it was dropped. It is
    /// stamped into the stored header map under
    /// [`dlq::DLQ_AUTHENTICATED_KEY`] and read back by `dispatch_replay`,
    /// which REFUSES to re-dispatch an unauthenticated entry (F2).
    ///
    /// The DLQ therefore holds TWO classes of row (see `dispatch_failure`):
    /// * pre-auth DROPS — the circuit-breaker and rate-limit sites, ABOVE the
    ///   gate, pass `false`. A record, never replayable.
    /// * post-auth DISPATCH FAILURES — every site below the gate where the
    ///   module or engine never observed the delivery (registry read, tracking
    ///   row, signing, publish, reply window) passes `true` via
    ///   `capture_post_auth_drop`. These are what replay is for. A module that
    ///   RAN and returned an error is deliberately NOT captured — that is an
    ///   execution failure `module_executions` already records, and a replay
    ///   would double its side effects.
    fn enqueue_dlq(
        &self,
        trigger_id: Option<Uuid>,
        source_ip: Option<std::net::IpAddr>,
        drop_reason: &'static str,
        headers: &axum::http::HeaderMap,
        body: &axum::body::Bytes,
        authenticated: bool,
    ) {
        // Build a sanitized header map (strip auth material). The classifier
        // is shared with `log_request` — see `signature::header_is_sensitive`.
        let mut header_map = serde_json::Map::new();
        for (name, value) in headers.iter() {
            if signature::header_is_sensitive(name.as_str()) {
                // Record presence but not value, so the DLQ entry is debuggable without leaking secrets.
                header_map.insert(
                    name.to_string(),
                    serde_json::Value::String("[redacted]".to_string()),
                );
                continue;
            }
            if let Ok(v) = value.to_str() {
                // MCP-974 (2026-05-15): DLP-redact non-sensitive
                // header VALUES too. The name-based `header_is_sensitive`
                // filter catches canonical auth headers (cookie, Bearer,
                // signature, etc.) but a misconfigured client can stash
                // a secret in any custom header — `X-Trace-Id`,
                // `X-Customer-Ref`, etc. — and operators can't enumerate
                // every third-party convention. The sibling
                // `enqueue_webhook_dlq` site (line ~2877) already runs
                // `redact_str` on each non-sensitive header value; this
                // brings the entry-level DLQ path in line.
                let scrubbed = talos_dlp_provider::redact_str(v);
                header_map.insert(name.to_string(), serde_json::Value::String(scrubbed));
            }
        }
        // Stamped LAST so a sender-supplied header of the same name (header
        // tokens may contain `_`) is overwritten by the engine's verdict, and
        // stored as a JSON bool so a string "true" from such a header can
        // never satisfy the strict `Value::Bool(true)` check on replay.
        header_map.insert(
            dlq::DLQ_AUTHENTICATED_KEY.to_string(),
            serde_json::Value::Bool(authenticated),
        );
        let headers_json = serde_json::Value::Object(header_map);

        // Parse and DLP-scrub the payload
        let payload_json =
            serde_json::from_slice::<serde_json::Value>(body).unwrap_or(serde_json::Value::Null);

        // Skip null payloads (parse failure on empty bodies)
        if payload_json.is_null() {
            self.dlq_service
                .metrics
                .dropped_null_payload
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // MCP-567: mirror to Prometheus. Null-payload drops are
            // counted under the generic `dlq_drops_total` (same as
            // queue-full drops) so operators can alert on "any DLQ
            // drop" without enumerating reasons.
            if let Some(m) = talos_metrics::global() {
                m.dlq_drops_total.inc();
            }
            return;
        }

        let scrubbed_payload = talos_dlp_provider::redact_json(&payload_json);

        let entry = DlqEntry {
            trigger_id,
            source_ip: source_ip.map(|ip| ip.to_string()),
            drop_reason: drop_reason.to_string(),
            headers: headers_json,
            payload: scrubbed_payload,
        };

        // Try to enqueue — may drop if channel is full (backpressure)
        if !self.dlq_service.try_enqueue(entry) {
            tracing::warn!(
                trigger_id = ?trigger_id,
                drop_reason = drop_reason,
                "DLQ entry dropped due to channel capacity"
            );
        }
    }

    /// Record a POST-AUTH dispatch failure in the DLQ as a REPLAYABLE row.
    ///
    /// The request had already passed the auth gate, so the row is stamped
    /// `authenticated: true` and `dispatch_replay` will accept it. Call this
    /// ONLY at a site where the module / engine never observed the delivery
    /// (`dispatch_failure` names the partition); `drop_reason` should be one
    /// of `dispatch_failure::drop_reason::*` so the DLQ list says where the
    /// platform failed. `capture` is `None` on the replay path itself, which
    /// has no inbound request to record — a replay that fails is reported to
    /// the operator directly and its row stays unreplayed.
    fn capture_post_auth_drop(
        &self,
        trigger_id: Uuid,
        capture: Option<&DlqCapture<'_>>,
        drop_reason: &'static str,
    ) {
        if let Some(c) = capture {
            self.enqueue_dlq(
                Some(trigger_id),
                c.source_ip,
                drop_reason,
                c.headers,
                c.body,
                true,
            );
        }
    }

    /// Release a webhook dedup claim taken at arrival (R2-4 begin/abandon).
    ///
    /// `is_duplicate` atomically records the dedup key when the delivery
    /// arrives (which correctly blocks two *concurrent* deliveries of the same
    /// event from both running). But if processing then fails with a transient,
    /// retryable error BEFORE the module/workflow actually runs, the sender's
    /// redelivery would otherwise be suppressed as a "duplicate" and the
    /// delivery silently lost for the whole window. Callers invoke this ONLY on
    /// pre-execution failures so the claim is abandoned and the retry honored.
    /// A claim for an event that actually ran is left recorded. Best-effort:
    /// a release error is logged, not propagated (worst case reverts to the
    /// pre-fix suppress-on-retry behavior).
    async fn release_dedup_claim(&self, trigger_id: Uuid, claim: &Option<String>) {
        if let (Some(dedup), Some(event_id)) = (&self.dedup, claim) {
            if let Err(e) = dedup.release(trigger_id, event_id).await {
                tracing::warn!(
                    trigger_id = %trigger_id,
                    "Failed to release webhook dedup claim after a pre-execution \
                     failure; the sender's redelivery may be suppressed: {e}"
                );
            }
        }
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

        // SECURITY: Validate content type to prevent MIME-confusion attacks.
        // Browsers allow cross-origin POST with text/plain (no preflight), so accepting
        // text/plain would enable CSRF attacks where a victim's browser sends a
        // text/plain body that happens to parse as JSON. Only accept true JSON types.
        // application/x-www-form-urlencoded is kept for legacy webhook senders.
        // text/plain and application/octet-stream are intentionally excluded.
        if let Some(content_type) = headers.get("content-type").and_then(|v| v.to_str().ok()) {
            let content_type_lower = content_type.to_lowercase();
            let allowed_types = ["application/json", "application/x-www-form-urlencoded"];
            if !allowed_types
                .iter()
                .any(|&t| content_type_lower.starts_with(t))
            {
                tracing::warn!(
                    trigger_id = %trigger_id,
                    content_type = %content_type,
                    "Rejected webhook with disallowed content type"
                );
                return Ok((
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "Unsupported content type",
                )
                    .into_response());
            }
        }

        // SECURITY: Validate payload size (already limited by middleware, but double-check)
        if body.len() > MAX_WEBHOOK_PAYLOAD_SIZE {
            tracing::warn!(
                trigger_id = %trigger_id,
                size = body.len(),
                max = MAX_WEBHOOK_PAYLOAD_SIZE,
                "Rejected webhook with oversized payload"
            );
            return Ok((StatusCode::PAYLOAD_TOO_LARGE, "Payload too large").into_response());
        }

        // 0. Circuit breaker check — cheapest gate, runs before any DB query or HMAC.
        if let Some(ip) = source_ip {
            if self.circuit_breaker.is_blocked(ip) {
                tracing::warn!(
                    trigger_id = %trigger_id,
                    ip = %ip,
                    "Circuit breaker open: blocking request from repeatedly-failing IP"
                );
                // Persist to DLQ as a record of the drop. This is ABOVE the
                // auth gate, so the entry is stamped unauthenticated and
                // `dispatch_replay` will refuse to re-dispatch it (F2).
                if !body.is_empty() {
                    self.enqueue_dlq(
                        Some(trigger_id),
                        source_ip,
                        "circuit_breaker",
                        headers,
                        &body,
                        false,
                    );
                }
                return Ok((StatusCode::TOO_MANY_REQUESTS, "Too many requests").into_response());
            }
        }

        // 1. Lookup trigger configuration
        let trigger = self.get_trigger(trigger_id).await?;

        if !trigger.enabled {
            tracing::warn!(
                trigger_id = %trigger_id,
                "Webhook trigger is disabled"
            );
            // F3: a disabled trigger is NOT an authentication failure and is
            // deliberately NOT counted toward the circuit breaker. The
            // breaker is keyed by source IP, and GitHub / Slack deliver every
            // tenant's webhooks from one shared IP range — an operator
            // pausing a trigger that its sender keeps posting to would trip
            // the breaker for every other tenant behind that IP.
            // `record_failure_with_type` also refuses non-auth types itself.
            // Same status AND body as the trigger-not-found path so a caller
            // can't distinguish "disabled" from "never existed" (trims the
            // existence/enabled-state oracle; sibling of the MCP-1102
            // approval-gate fix). Enumeration is already infeasible — the
            // trigger id is a 122-bit UUID — this closes the residual leak
            // for an id an attacker already holds.
            return Ok((StatusCode::NOT_FOUND, "Webhook not found").into_response());
        }

        // 2. Check rate limit (lock-free with DashMap).
        // Two limits are checked: per-trigger (operator-configured) and per-user
        // aggregate (TALOS_WEBHOOK_USER_RPM, default 300). Both must pass.
        // This prevents a user from registering N triggers to bypass per-trigger limits.
        let user_max_rpm = rate_limiter::configured_user_webhook_rpm();
        // MCP-813 (2026-05-14): defense-in-depth read-side clamp. MCP-812
        // closed the write-time path (GraphQL `create_webhook_trigger`
        // now rejects max_requests_per_minute outside [1, 10000]), but
        // the column type is `INTEGER` (signed i32) and legacy rows or
        // direct-SQL inserts can still carry negative or zero values.
        // Pre-fix `trigger.max_requests_per_minute as usize` on 64-bit
        // platforms underflows `-1i32 as usize` to 18446744073709551615,
        // which the token-bucket treats as "unlimited burst". Mirror
        // the write-time bounds [1, 10000] at the cast site so a
        // misconfigured row caps at sane per-trigger throughput rather
        // than effectively disabling the per-trigger limit. The
        // aggregate per-user limit at the second bucket still applies.
        // Sibling defense to MCP-811 / MCP-767 (the read-side
        // counterpart to the write-side bounds).
        let trigger_rpm = trigger.max_requests_per_minute.clamp(1, 10_000) as usize;
        let (trigger_ok, user_ok) = self.rate_limiter.allow_for_trigger(
            trigger_id,
            trigger_rpm,
            trigger.user_id,
            user_max_rpm,
        );
        if !trigger_ok || !user_ok {
            if !trigger_ok {
                tracing::warn!(trigger_id = %trigger_id, "Webhook per-trigger rate limit exceeded");
            } else {
                tracing::warn!(
                    trigger_id = %trigger_id,
                    user_id = %trigger.user_id,
                    "Webhook per-user aggregate rate limit exceeded"
                );
            }
            // F3: a rate-limit hit is NOT an authentication failure and is
            // deliberately NOT counted toward the IP-keyed circuit breaker —
            // the per-trigger / per-user limits are already the throttle, and
            // a shared sender IP (GitHub, Slack) exceeding ONE tenant's
            // per-trigger limit must not open the breaker for every tenant.
            // Persist to DLQ as a record of the drop. Pre-auth ⇒ stamped
            // unauthenticated ⇒ not replayable (F2).
            if !body.is_empty() {
                self.enqueue_dlq(
                    Some(trigger_id),
                    source_ip,
                    "rate_limit",
                    headers,
                    &body,
                    false,
                );
            }
            talos_metrics::record_rate_limit_hit(talos_metrics::RateLimitKind::Webhook);
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
                        // IP allowlist rejection counts as auth failure for CB tracking
                        self.circuit_breaker
                            .record_failure_with_type(ip, CircuitBreakerFailureType::IpNotAllowed);
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

        // 4. Verify request authenticity.
        //
        //    Priority: HMAC signing_secret (strongest) → verification_token (static fallback).
        //    If neither is configured the webhook is open (no authentication).
        //
        //    The signing secret is stored encrypted (AES-256-GCM via SecretsManager).
        //    It is decrypted in-memory here and never written to any log.
        // L T2-3: SecretsManager::decrypt_value_by_key returns
        // Zeroizing<String> so the HMAC signing secret is wiped from
        // the heap on drop. The HMAC verifier takes `&str`; the deref
        // path works transparently.
        //
        // MEDIUM (auth downgrade): distinguish "HMAC was CONFIGURED" from
        // "HMAC secret RESOLVED". The presence of a stored encrypted
        // signing secret (`signing_secret_enc`) is the operator's intent
        // to require HMAC; the operator-facing create_webhook contract
        // guarantees the static-token fallback is PERMANENTLY off once a
        // signing secret is set. `decrypted_signing_secret` becomes None
        // not only when no secret is configured, but ALSO when decryption
        // FAILS (key rotation, DEK/KMS outage, corrupted ciphertext,
        // AAD/format mismatch). Without tracking the configured-flag
        // separately, a transient decrypt failure would silently fall
        // through to the verification_token branch below — re-enabling a
        // long-lived static UUID token the operator believes is off. We
        // fail closed instead: configured-but-unresolved => 401.
        let hmac_configured = trigger.signing_secret_enc.is_some();
        let decrypted_signing_secret: Option<zeroize::Zeroizing<String>> = match (
            &trigger.signing_secret_enc,
            trigger.signing_key_id,
        ) {
            (Some(enc), Some(key_id)) => {
                // MCP-S2: dispatch on the per-row format version. v0 rows
                // (existing pre-fix) decrypt with empty AAD; v1 rows
                // decrypt with AAD = trigger.id bytes. A swapped
                // ciphertext (attacker DB-write) fails AES-GCM tag
                // verification on v1 rows and is logged as a decryption
                // failure — the webhook then falls back to
                // verification_token (or rejects, depending on policy).
                match self
                    .secrets_manager
                    .decrypt_versioned(
                        key_id,
                        enc,
                        trigger.id.as_bytes(),
                        trigger.signing_secret_format,
                    )
                    .await
                {
                    Ok(s) => Some(s),
                    Err(e) => {
                        // Do NOT leak the internal error detail (or any
                        // secret/ciphertext) to the response — log it at
                        // WARN with only the trigger id so operators can
                        // correlate to a DEK/rotation/KMS outage. The
                        // caller gets a generic 401 from the fail-closed
                        // branch below (hmac_configured && None).
                        tracing::warn!(
                            trigger_id = %trigger_id,
                            "Failed to decrypt webhook signing secret — HMAC is configured but the \
                             secret could not be resolved (DEK/KMS outage, key rotation, corrupted \
                             ciphertext, or AAD/format mismatch); failing closed: {}",
                            e
                        );
                        None
                    }
                }
            }
            _ => None,
        };
        // F1: the outcome of this gate — WHICH format verified, or that none
        // was checked — is what the dedup fingerprint below is derived from.
        // Every failure arm returns, so the chain's value is the outcome.
        let auth_outcome: WebhookAuthOutcome = if let Some(ref signing_secret) =
            decrypted_signing_secret
        {
            // MCP-1100 (2026-05-16): GitHub-format webhooks include no
            // timestamp header, so their HMAC signature is replayable
            // indefinitely without the deduplication store. Slack
            // (`x-slack-signature`) and the generic format
            // (`x-signature` + `x-webhook-timestamp`) both bind a
            // timestamp into the signed material with a ±5-minute
            // freshness window — replays past that window fail. GitHub
            // (`x-hub-signature-256`) signs the body alone, and the
            // ONLY replay defense is the dedup-store lookup later in
            // this handler. If dedup is unavailable (production
            // deployment without REDIS_URL, or Redis hard-down between
            // boot and the request), a captured GitHub webhook can be
            // replayed against the controller indefinitely with a
            // valid signature.
            //
            // Refuse the GitHub format up front when dedup isn't
            // available — caller sees the same Unauthorized response
            // as a signature-mismatch, so no information disclosure
            // about the deployment state. Slack / generic flows are
            // unaffected (their timestamp check still binds replays).
            if headers.contains_key("x-hub-signature-256") && self.dedup.is_none() {
                tracing::warn!(
                    trigger_id = %trigger_id,
                    "GitHub-format webhook received but webhook deduplication is not configured — \
                     refusing to authenticate without replay protection. Configure REDIS_URL so \
                     WebhookDeduplication is wired up."
                );
                if let Some(ip) = source_ip {
                    self.circuit_breaker
                        .record_failure_with_type(ip, CircuitBreakerFailureType::InvalidSignature);
                }
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
            // HMAC path — verifies integrity and authenticity of the full payload,
            // and reports WHICH format did so.
            match signature::verify_hmac_signature(headers, &body, signing_secret) {
                Some(format) => WebhookAuthOutcome::Hmac(format),
                None => {
                    tracing::warn!(
                        trigger_id = %trigger_id,
                        "HMAC signature verification failed"
                    );
                    if let Some(ip) = source_ip {
                        self.circuit_breaker.record_failure_with_type(
                            ip,
                            CircuitBreakerFailureType::InvalidSignature,
                        );
                    }
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
        } else if webhook_must_fail_closed_on_hmac(
            hmac_configured,
            decrypted_signing_secret.is_some(),
        ) {
            // FAIL CLOSED: HMAC was configured on this trigger
            // (`signing_secret_enc` is present) but the secret could not
            // be decrypted (see the WARN logged at the decrypt site).
            // Falling through to the static-token branch here would be a
            // silent HMAC -> static-token auth DOWNGRADE: the
            // verification_token is a long-lived UUID the operator was
            // told is permanently disabled once a signing secret is set.
            // A transient DEK/KMS/rotation outage must NEVER re-enable it.
            // Mirror the GitHub-format `dedup.is_none()` fail-closed shape
            // above — generic 401, no internal detail in the response.
            tracing::warn!(
                trigger_id = %trigger_id,
                "Webhook has an HMAC signing secret configured but it could not be resolved — \
                 refusing to fall back to the static verification token (auth-downgrade guard). \
                 Check for a DEK/KMS outage or in-progress key rotation."
            );
            if let Some(ip) = source_ip {
                self.circuit_breaker
                    .record_failure_with_type(ip, CircuitBreakerFailureType::InvalidSignature);
            }
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
        } else if let Some(expected_token) = &trigger.verification_token {
            // Static token fallback — used when the caller cannot compute HMAC
            // (e.g. simple webhook forwarders).  The caller must supply the token
            // in the X-Verification-Token header.  Comparison is constant-time to
            // prevent timing side-channels.
            use subtle::ConstantTimeEq;
            let provided = headers
                .get("x-verification-token")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            // MCP-629 (2026-05-12): empty-string ct_eq bypass class. The
            // storage path always sets `verification_token` to a fresh
            // `Uuid::new_v4()` (36 chars), so an empty stored token is
            // impossible via the documented surface. But defense-in-depth
            // requires the verify path to reject empty values: pre-fix,
            // a stored `expected_token = ""` combined with a request
            // missing the X-Verification-Token header (so
            // `provided = ""`) would have produced
            // `ct_eq(&[], &[]) == 1` and authenticated. Same auth-bypass
            // class as MCP-590/591/592/628 — auth gates must reject
            // empty values before constant-time compare.
            if expected_token.is_empty() || provided.is_empty() {
                tracing::warn!(
                    trigger_id = %trigger_id,
                    expected_empty = expected_token.is_empty(),
                    provided_empty = provided.is_empty(),
                    "Verification token rejected: empty value (storage path enforces UUID; \
                     either header missing or stored token bypassed validation)"
                );
                if let Some(ip) = source_ip {
                    self.circuit_breaker.record_failure_with_type(
                        ip,
                        CircuitBreakerFailureType::InvalidVerificationToken,
                    );
                }
                return Ok((StatusCode::UNAUTHORIZED, "Invalid verification token").into_response());
            }
            if expected_token
                .as_bytes()
                .ct_eq(provided.as_bytes())
                .unwrap_u8()
                != 1
            {
                tracing::warn!(
                    trigger_id = %trigger_id,
                    "Verification token check failed"
                );
                if let Some(ip) = source_ip {
                    self.circuit_breaker.record_failure_with_type(
                        ip,
                        CircuitBreakerFailureType::InvalidVerificationToken,
                    );
                }
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
                    Some("Invalid verification token"),
                )
                .await;
                return Ok((StatusCode::UNAUTHORIZED, "Invalid verification token").into_response());
            }
            WebhookAuthOutcome::StaticToken
        } else {
            // Neither a signing secret nor a verification token: the webhook
            // is open (documented at the top of step 4).
            WebhookAuthOutcome::Open
        };

        // 4b. RFC 0007 event filter. Evaluated AFTER all signature / verification-
        //     token auth (so unverified input never reaches filter logic) and
        //     BEFORE dedup/dispatch. A non-matching delivery is ACKNOWLEDGED with
        //     200 and NO workflow execution — GitHub (and most senders) retry
        //     non-2xx, so an intentionally-ignored event must not 4xx, and it must
        //     not burn an execution's budget/audit row. The skip is still
        //     `log_request`-recorded (observable) and rate-limiting already applied.
        if let Some(ref filter) = trigger.event_filter {
            let parsed_body: serde_json::Value =
                serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
            let header_value = filter
                .get("header")
                .and_then(|h| h.as_str())
                .and_then(|name| headers.get(name))
                .and_then(|v| v.to_str().ok());
            if !event_filter_matches(filter, header_value, &parsed_body) {
                tracing::debug!(
                    trigger_id = %trigger_id,
                    "event_filter: delivery did not match; acknowledging 200 without dispatch"
                );
                self.log_request(
                    trigger_id,
                    headers,
                    &body,
                    source_ip,
                    StatusCode::OK.as_u16() as i32,
                    None,
                    0,
                    0,
                    true,
                    Some("event filtered (no dispatch)"),
                )
                .await;
                return Ok((StatusCode::OK, "Event ignored (filtered)").into_response());
            }
        }

        // 5. Deduplication: suppress re-delivery of the same webhook within the window.
        //    Event fingerprint = the VERIFIED format's own signature value, else
        //    SHA-256 of the body (F1). It used to be the first recognisable
        //    header in a fixed precedence list starting with `x-signature`, so a
        //    captured GitHub delivery replayed with a fresh random `X-Signature`
        //    verified via the GitHub branch and deduplicated on the attacker's
        //    header — every replay a "new" event, against the one format whose
        //    ONLY replay defence is this lookup. `signature::dedup_fingerprint`
        //    can only name a header the verifier actually checked.
        //
        // R2-4: `Some(event_id)` once we've taken (recorded) a dedup claim, so a
        // PRE-EXECUTION failure below can release it (begin/abandon) and let the
        // sender retry instead of being suppressed as a duplicate. Stays `None`
        // when no dedup backend is configured or the claim wasn't taken.
        let mut dedup_claim: Option<String> = None;
        if let Some(ref dedup) = self.dedup {
            let raw_event_id: String = signature::dedup_fingerprint(auth_outcome, headers, &body);

            // MCP-1101 (2026-05-16): bound the Redis key length by
            // hashing oversized event_ids. Legitimate signature/delivery
            // headers are ≤128 chars (GitHub UUID = 36, Slack `v0=…` =
            // 67, GitHub `sha256=…` = 71, generic `X-Signature` 64-128
            // hex chars). HTTP headers themselves can carry ~64KB —
            // pre-fix a malicious sender could ship a 64KB event_id and
            // get the controller to write a 64KB Redis key in the
            // `webhook:processed:<trigger>:` namespace per request. At
            // the trigger's max-requests-per-minute (default 60), that's
            // ~4MB of Redis memory burned per attacker-controlled
            // trigger per minute. Also bounds the log line size
            // downstream (event_id = %event_id at line ~840). 512 covers
            // any legitimate format with comfortable headroom.
            const MAX_EVENT_ID_LEN: usize = 512;
            let event_id: String = if raw_event_id.len() > MAX_EVENT_ID_LEN {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(raw_event_id.as_bytes());
                tracing::warn!(
                    trigger_id = %trigger_id,
                    raw_len = raw_event_id.len(),
                    "Oversized webhook event-id header — hashing to bound Redis key size"
                );
                hex::encode(hasher.finalize())
            } else {
                raw_event_id
            };

            match dedup.is_duplicate(trigger_id, &event_id).await {
                Ok(true) => {
                    tracing::info!(
                        trigger_id = %trigger_id,
                        event_id = %event_id,
                        "Suppressed duplicate webhook delivery"
                    );
                    // Return 200 so the sender does not retry; log at INFO not
                    // WARN. The body SAYS it was suppressed — a bare "OK" made
                    // manual testing look like a dropped delivery (2026-07-17:
                    // an identical re-POST during live validation produced no
                    // execution and nothing to explain why without docker
                    // logs). Machine-readable so scripted callers can branch.
                    return Ok((
                        StatusCode::OK,
                        axum::Json(serde_json::json!({
                            "status": "duplicate_suppressed",
                            "detail": "identical payload already processed within the dedup window; no execution dispatched",
                        })),
                    )
                        .into_response());
                }
                Ok(false) => {
                    // Claim recorded — track it so a pre-execution failure can
                    // abandon it (R2-4).
                    dedup_claim = Some(event_id.clone());
                }
                Err(e) => {
                    // Dedup backend errored (e.g. Redis down). For GitHub-format
                    // webhooks this is NOT safe to continue through: the GitHub
                    // HMAC signs the body only — no timestamp is bound, so there
                    // is no freshness window and dedup is the *sole* replay
                    // defense. Continuing would let a captured valid delivery be
                    // replayed for the whole outage (the exact gap the MCP-1100
                    // `dedup.is_none()` guard above closes for the not-configured
                    // case). Fail closed (401) so GitHub re-delivers once dedup
                    // recovers. We do NOT record a circuit-breaker failure here —
                    // this is our infra outage, not the sender's bad signature,
                    // and penalising legitimate senders would mass-trip the
                    // breaker across a Redis blip. Slack/generic bind a timestamp
                    // into the HMAC (±5-min window), so continuing is safe there.
                    if headers.contains_key("x-hub-signature-256") {
                        tracing::warn!(
                            trigger_id = %trigger_id,
                            "GitHub-format webhook: deduplication backend unavailable ({e}) — \
                             failing closed (body-only HMAC has no replay window without dedup)"
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
                    tracing::warn!(
                        trigger_id = %trigger_id,
                        "Webhook deduplication check failed (non-fatal): {}",
                        e
                    );
                }
            }
        }

        // 6. Handle Trigger (Module or Workflow)
        if let Some(module_id) = trigger.module_id {
            // Load WASM module (pass user_id to enforce ownership)
            let _module_bytes = match self
                .registry
                .get_module_bytes(module_id, trigger.user_id)
                .await
            {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::error!(
                        trigger_id = %trigger_id,
                        module_id = %module_id,
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
                    // R2-4: transient pre-execution failure — the module never
                    // ran, so abandon the dedup claim and let the sender retry.
                    // Post-auth dispatch failure: the module never ran, so this
                    // delivery is REPLAYABLE (`dispatch_failure` partition).
                    self.capture_post_auth_drop(
                        trigger_id,
                        Some(&DlqCapture {
                            headers,
                            body: &body,
                            source_ip,
                        }),
                        dispatch_failure::drop_reason::MODULE_LOAD_FAILED,
                    );
                    self.release_dedup_claim(trigger_id, &dedup_claim).await;
                    return Ok((StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
                        .into_response());
                }
            };

            // 6. Get module config and resolve secrets (pass user_id to enforce ownership)
            let module_config = match self
                .registry
                .get_module_config(module_id, trigger.user_id)
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
                    // R2-4: transient pre-execution failure — the module never
                    // ran, so abandon the dedup claim and let the sender retry.
                    // Post-auth dispatch failure: the module never ran, so this
                    // delivery is REPLAYABLE (`dispatch_failure` partition).
                    self.capture_post_auth_drop(
                        trigger_id,
                        Some(&DlqCapture {
                            headers,
                            body: &body,
                            source_ip,
                        }),
                        dispatch_failure::drop_reason::MODULE_CONFIG_FAILED,
                    );
                    self.release_dedup_claim(trigger_id, &dedup_claim).await;
                    return Ok((StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
                        .into_response());
                }
            };

            // 7. Parse raw body into JSON (or keep as string) and wrap with config.
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
            // RFC 0007 D5: surface inbound event metadata (event type + delivery
            // id from headers, body `action`) as a reserved `__webhook__` key so
            // both `input` and `__trigger_input__` below carry it. Shared with
            // the DLQ replay path so the two payload shapes cannot drift.
            let payload_value =
                build_webhook_trigger_payload(&body_str, headers, trigger.event_filter.as_ref());

            // Wrap webhook payload with config (shared builder — see
            // `build_module_dispatch_payload` for the `__trigger_input__`
            // contract).
            let wrapped_input = build_module_dispatch_payload(&module_config, &payload_value);

            // 8. Execute WASM module
            let wasm_start = Instant::now();
            let job_id = Uuid::new_v4();

            // Phase C of "every execution gets an actor": resolve an owning
            // actor for this bare-module webhook dispatch. Webhook triggers
            // carry no actor → the user's default actor; its max_llm_tier then
            // travels with the job below. Fail OPEN to actor-less Tier-2
            // (today's behaviour) on any resolution error so a transient DB
            // hiccup never drops an inbound webhook.
            let (resolved_actor, actor_tier, actor_write_ceiling, actor_egress) = {
                let actor_repo = talos_actor_repository::ActorRepository::new(self.db_pool.clone());
                match actor_repo
                    .resolve_effective_actor(trigger.user_id, None)
                    .await
                {
                    Ok(aid) => {
                        // #736: one joined SELECT, CLASSIFIED rather than
                        // collapsed. The pre-#736 `_` arm mapped BOTH a missing
                        // row and a FAILED READ to `(Tier2, Write, None)` — the
                        // most permissive triple on all three axes — so a read
                        // that told us nothing about this actor's authority
                        // granted external-LLM egress, writes, and (via
                        // `resolve_local_egress_only(None, Tier2)`) public
                        // egress, on a job stamped `resolved_actor = Some(aid)`.
                        //
                        // Unlike the three Google push paths, refusing IS safe
                        // here: `handle_webhook` is synchronous, so the error
                        // reaches `webhook_handler` and becomes a 500 the sender
                        // retries. The one thing that must not be forgotten is
                        // the dedup claim — a bare `?` would leave it held and
                        // the retry would be swallowed as a duplicate, turning a
                        // deferral back into a loss. Same shape as the R2-4
                        // transient-failure branch below.
                        let (tier, write_ceiling, egress) =
                            match actor_repo
                                .read_module_bound_ceilings(aid)
                                .await
                                .resolve_for(
                                    aid,
                                    talos_actor_repository::DispatchSite::WebhookModuleDispatch,
                                ) {
                                Ok(triple) => triple,
                                Err(refusal) => {
                                    tracing::error!(
                                        trigger_id = %trigger_id,
                                        actor_id = %aid,
                                        error = %refusal,
                                        "webhook dispatch: refusing rather than dispatching at a \
                                         posture we never read"
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
                                        Some("Failed to resolve actor ceilings"),
                                    )
                                    .await;
                                    // R2-4: the module never ran, so abandon the
                                    // dedup claim and let the sender retry.
                                    // Post-auth dispatch failure: the module never ran, so this
                                    // delivery is REPLAYABLE (`dispatch_failure` partition).
                                    self.capture_post_auth_drop(
                                    trigger_id,
                                    Some(&DlqCapture { headers, body: &body, source_ip }),
                                    dispatch_failure::drop_reason::MODULE_ACTOR_CEILINGS_UNREADABLE,
                                );
                                    self.release_dedup_claim(trigger_id, &dedup_claim).await;
                                    return Ok((
                                        StatusCode::INTERNAL_SERVER_ERROR,
                                        "Internal server error",
                                    )
                                        .into_response());
                                }
                            };
                        (Some(aid), tier, write_ceiling, egress)
                    }
                    Err(e) => {
                        tracing::warn!(
                            user_id = %trigger.user_id, error = %e,
                            "webhook dispatch: default-actor resolution failed; dispatching actor-less (Tier-2)"
                        );
                        (
                            None,
                            talos_workflow_job_protocol::LlmTier::default(),
                            talos_workflow_job_protocol::WriteCeiling::default(),
                            None,
                        )
                    }
                }
            };

            // The tracking row MUST exist before the job is dispatched under
            // `job_id`: every `wasm.log.{job_id}` line the worker publishes is
            // routed by a `WHERE EXISTS` guard on this table, so a dispatch
            // whose row is missing produces an execution with no logs, no
            // status, and no way for an operator to find it. Pre-fix this was
            // `tracing::error!` only and the dispatch proceeded anyway — a
            // single DB blip silently produced an invisible execution.
            // Fail CLOSED instead: the module has not run yet, so this is a
            // transient pre-execution failure of exactly the same class as the
            // module-load / module-config failures above — abandon the dedup
            // claim and let the sender retry.
            //
            // Two honest costs, both accepted:
            //  * At-least-once. If the INSERT commits but the call still
            //    reports an error (connection reset after commit), the released
            //    claim lets the sender's retry run the module a second time
            //    under a NEW `job_id`. Pre-fix that delivery would have
            //    dispatched once and returned 200. Webhook delivery is
            //    at-least-once by contract and both pre-existing 500 branches
            //    above have the same shape.
            //  * Not every failure here is transient. `module_executions
            //    .actor_id` is NOT NULL and `trg_set_default_actor` can only
            //    stamp it for a user who HAS a default actor, so a user with
            //    none makes this INSERT fail permanently and the sender retries
            //    into a wall. Every user has had one since the Phase-B backfill
            //    (`20260626180000`), and a permanently-refused delivery is
            //    still better than a permanently-invisible one.
            if let Err(e) = insert_webhook_module_execution(
                &self.db_pool,
                &self.secrets_manager,
                job_id,
                module_id,
                trigger.user_id,
                &payload_value,
                resolved_actor,
            )
            .await
            {
                tracing::error!(
                    trigger_id = %trigger_id,
                    job_id = %job_id,
                    error = %e,
                    "Failed to insert module_execution for webhook; refusing to dispatch an \
                     untrackable job"
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
                    Some("Failed to record module execution"),
                )
                .await;
                // R2-4: transient pre-execution failure — the module never
                // ran, so abandon the dedup claim and let the sender retry.
                // Post-auth dispatch failure: the module never ran, so this
                // delivery is REPLAYABLE (`dispatch_failure` partition).
                self.capture_post_auth_drop(
                    trigger_id,
                    Some(&DlqCapture {
                        headers,
                        body: &body,
                        source_ip,
                    }),
                    dispatch_failure::drop_reason::MODULE_EXECUTION_ROW_FAILED,
                );
                self.release_dedup_claim(trigger_id, &dedup_claim).await;
                return Ok(
                    (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
                );
            }

            let registry = self.registry.clone();
            let nats = self.nats_client.clone();
            let secrets_manager = self.secrets_manager.clone();
            // RFC 0010 P3 (M4): claim-based sealing handle for this dispatch.
            let sealing_handle = self.sealing_handle.clone();
            let worker_shared_key_clone = self.worker_shared_key.clone();
            // Result verify-ring (current + staged WORKER_SHARED_KEY_PREVIOUS)
            // so this webhook reply-inbox primary verifier accepts a result
            // signed under a previous key during a rolling rotation. Signing
            // (below) still uses the current key only.
            let worker_key_ring_clone = worker_shared_key_clone.clone().map(|signing| {
                talos_workflow_engine_core::WorkerKeyRing::new(
                    signing,
                    talos_workflow_job_protocol::load_worker_shared_key_previous()
                        .unwrap_or_default(),
                )
            });
            let user_id = trigger.user_id;
            // R2 token ledger: pool handle for recording the verified
            // result's LLM usage inside the dispatch task below.
            let usage_pool = self.db_pool.clone();

            let result = tokio::spawn({
                let input_payload = wrapped_input.clone();
                async move {
                    let exec_info = match registry.get_execution_info(module_id, user_id).await {
                        Ok(info) => info,
                        Err(e) => {
                            tracing::error!(
                                "Failed to prepare webhook module {} for execution: {}",
                                module_id,
                                e
                            );
                            return Err(ModuleDispatchFailure::NotDispatched {
                                drop_reason: dispatch_failure::drop_reason::MODULE_EXEC_INFO_FAILED,
                                detail: "Module not available".to_string(),
                            });
                        }
                    };

                    // MCP-1144 (2026-05-16): route through the canonical
                    // helper `talos_integration_helpers::prepare_module_dispatch_secrets`.
                    // Pre-fix this site inlined ~50 lines duplicating the
                    // composition logic that already lived in the helper
                    // — module-declared secrets via `get_module_secrets_for_user`
                    // (MCP-589 user-scoped) PLUS host-reserved LLM keys
                    // via `get_llm_vault_keys(Some(user_id))`. The
                    // MCP-1143 DLQ replay fix already mirrored this logic;
                    // collapsing both into the helper kills the future-drift
                    // hazard. Same logging discipline as the helper
                    // (DEBUG on common-case missing LLM keys, WARN on
                    // shared-key or encryption failure).
                    // RFC 0010 P3 (M4): under claim-based sealing register the
                    // plaintext for a worker claim (`sealing = SEALING_CLAIM_ECIES`);
                    // otherwise build the inline WSK envelope. L-1: AAD = job_id
                    // (= workflow_execution_id below) on the inline path.
                    let delivery = talos_integration_helpers::prepare_module_dispatch_secrets(
                        Some(&secrets_manager),
                        module_id,
                        user_id,
                        job_id,
                        sealing_handle.as_ref(),
                    )
                    .await;
                    // Reply inbox allocated BEFORE the request is built so it
                    // is bound into the signature (H-1 parity, see
                    // `reply_topic` below).
                    let reply_inbox = nats.new_inbox();
                    // Placeholder secret-delivery fields; `delivery.apply_to`
                    // below writes all four in one drift-proof mapping.
                    let mut req = talos_workflow_job_protocol::JobRequest {
                        crypto_scheme: 0,
                        sealing: 0,
                        secret_paths: Vec::new(),
                        claim_inbox: None,
                        job_id,
                        workflow_execution_id: job_id, // Standalone webhook uses same ID
                        module_uri: exec_info.module_uri,
                        // Send-side construction: fixes the wire text this dispatch signs.
                        input_payload: input_payload.into(),
                        encrypted_secrets: talos_workflow_job_protocol::EncryptedSecrets::empty(),
                        timeout_ms: 3_000,
                        allowed_hosts: exec_info.allowed_hosts,
                        allowed_methods: exec_info.allowed_methods,
                        allowed_secrets: exec_info.allowed_secrets,
                        allowed_sql_operations: vec![],
                        allow_tier2_exposure: false,
                        priority: 100,
                        deadline_unix_secs: 0,
                        cancellation_token: None,
                        signature: vec![],
                        // Phase C: the resolved actor's tier travels with the
                        // job. Defaults to Tier-2 (the default actor is Tier-2)
                        // so it's non-breaking; an operator who sets their
                        // default actor to `tier1` now gets tier enforcement on
                        // webhook-triggered module dispatch without the
                        // wrap-in-a-workflow workaround.
                        max_llm_tier: actor_tier,
                        max_write_ceiling: actor_write_ceiling,
                        egress_scope: actor_egress,
                        job_nonce: String::new(),
                        wasm_bytes: None,
                        capability_world: None,
                        // MCP-1090: propagate per-module integration_name.
                        // Modules belonging to integrations (e.g., GitHub
                        // webhook → GitHub integration module) need
                        // integration_state access for OAuth tokens and
                        // watch metadata. Hardcoded None silently broke
                        // every integration_state call from such modules.
                        integration_name: exec_info.integration_name.clone(),
                        expected_wasm_hash: Some(exec_info.content_hash.clone()),
                        // MCP-1089: propagate per-module max_fuel.
                        max_fuel: exec_info.max_fuel,
                        dry_run: false,
                        // 2026-09-10 review (H-1 parity): this was the LAST
                        // request/reply dispatcher that sent `reply_topic:
                        // None` and relied on the UNSIGNED NATS wire reply
                        // header — the one arm the worker still honoured "for
                        // backward compat". The engine dispatcher has signed
                        // its inbox since H-1; a bus participant could replay
                        // a captured webhook job to a sibling worker with its
                        // OWN reply header and receive the signed module
                        // output. The inbox is allocated here so it is bound
                        // into the signature below, and the worker now ignores
                        // the wire header whenever the signed field is absent.
                        reply_topic: Some(reply_inbox.clone()),
                        idempotency_key: None,
                        dispatch_attempt: 0,
                        actor_id: resolved_actor,
                        user_id,
                    };
                    delivery.apply_to(&mut req);

                    // RFC 0010 P1: prefer the configured Ed25519 dispatch signer;
                    // else the legacy HMAC path.
                    if let Some(signer) = talos_workflow_job_protocol::configured_dispatch_signer()
                    {
                        signer.sign_job(&mut req).map_err(|e| {
                            ModuleDispatchFailure::NotDispatched {
                                drop_reason: dispatch_failure::drop_reason::MODULE_SIGN_FAILED,
                                detail: format!("Failed to sign job request: {}", e),
                            }
                        })?;
                    } else if let Some(key) = &worker_shared_key_clone {
                        req.sign(key.as_bytes()).map_err(|e| {
                            ModuleDispatchFailure::NotDispatched {
                                drop_reason: dispatch_failure::drop_reason::MODULE_SIGN_FAILED,
                                detail: format!("Failed to sign job request: {}", e),
                            }
                        })?;
                    }
                    let payload = serde_json::to_vec(&req).map_err(|e| {
                        ModuleDispatchFailure::NotDispatched {
                            drop_reason:
                                dispatch_failure::drop_reason::MODULE_REQUEST_ENCODE_FAILED,
                            detail: e.to_string(),
                        }
                    })?;

                    // Request-reply pattern via NATS, on the SIGNED inbox:
                    // subscribe first, then publish with that inbox as the
                    // wire reply (the worker publishes to the signed field,
                    // which equals the wire header here, so either reading
                    // lands on this subscription).
                    // MCP-1065 (2026-05-15): canonical edge-routing resolver.
                    let topic_to_use = if talos_config::edge_routing_enabled() {
                        talos_workflow_job_protocol::subjects::jobs_for(user_id)
                    } else {
                        talos_workflow_job_protocol::subjects::JOBS.to_string()
                    };

                    // Every failure from here to the reply is TYPED
                    // (`dispatch_failure`): before the publish the worker saw
                    // nothing (`NotDispatched`); a silent reply window is
                    // `ReplyLost`; anything the worker actually answered is
                    // `Answered`. The caller captures the first two classes
                    // into the DLQ as replayable rows and never the third.
                    let mut reply_sub = nats.subscribe(reply_inbox.clone()).await.map_err(|e| {
                        ModuleDispatchFailure::NotDispatched {
                            drop_reason:
                                dispatch_failure::drop_reason::MODULE_REPLY_SUBSCRIBE_FAILED,
                            detail: format!("reply inbox subscribe failed: {}", e),
                        }
                    })?;
                    nats.publish_with_reply(topic_to_use, reply_inbox.clone(), payload.into())
                        .await
                        .map_err(|e| ModuleDispatchFailure::NotDispatched {
                            drop_reason: dispatch_failure::drop_reason::MODULE_PUBLISH_FAILED,
                            detail: format!("job publish failed: {}", e),
                        })?;
                    // Best-effort flush so the publish does not sit in the
                    // local outbox while we wait; a failure here surfaces as
                    // the timeout below.
                    let _flushed = nats.flush().await;
                    let response = tokio::time::timeout(
                        std::time::Duration::from_secs(3),
                        futures::StreamExt::next(&mut reply_sub),
                    )
                    .await
                    .map_err(|_| ModuleDispatchFailure::ReplyLost {
                        drop_reason: dispatch_failure::drop_reason::MODULE_REPLY_TIMEOUT,
                        detail: "WASM execution timed out after 3s".to_string(),
                    })?
                    .ok_or_else(|| ModuleDispatchFailure::ReplyLost {
                        drop_reason: dispatch_failure::drop_reason::MODULE_REPLY_INBOX_CLOSED,
                        detail: "reply inbox closed before a result arrived".to_string(),
                    })?;

                    // From here on the worker (or something on the bus) has
                    // ANSWERED — nothing below is replayable.
                    let result: talos_workflow_job_protocol::JobResult =
                        serde_json::from_slice(&response.payload).map_err(|e| {
                            ModuleDispatchFailure::Answered {
                                detail: e.to_string(),
                            }
                        })?;

                    // SECURITY: Verify the JobResult HMAC signature before
                    // treating its `output_payload` as authoritative. Without
                    // this gate, an attacker who can publish to NATS could
                    // forge a `JobResult { status: Success, output_payload:
                    // <attacker-controlled> }` to this reply inbox and the
                    // webhook handler would return the forged bytes as the
                    // HTTP response.
                    //
                    // This handler is the SOLE in-process consumer of this
                    // reply (worker single-publishes to either reply_topic
                    // XOR `talos.results.{job_id}` per CLAUDE.md verify-once
                    // rule, and we use NATS request-reply with an
                    // auto-generated inbox subject — the controller's
                    // `talos.results.*` subscriber does not see this
                    // payload). L-4: `Verifier::Primary` makes the role
                    // explicit at the call site — this is the canonical
                    // primary verifier for results on this reply inbox.
                    if let Some(ring) = &worker_key_ring_clone {
                        // RFC 0010 P2: scheme-routing Primary verify — Ed25519
                        // against the keys registered for this worker_id, or
                        // legacy HMAC against the ring while
                        // `result_accept_legacy_hmac()`. Canonical Primary
                        // verifier for results on this reply inbox (records the
                        // nonce exactly once).
                        let worker_ed_keys =
                            talos_workflow_job_protocol::worker_public_keys(&result.worker_id);
                        if let Err(e) = result.verify_dispatch(
                            ring,
                            &worker_ed_keys,
                            300,
                            talos_workflow_job_protocol::result_accept_legacy_hmac(),
                        ) {
                            // Split liveness from tampering: a stale result means
                            // the fleet or a clock stalled, NOT that someone forged
                            // a reply. Rejected either way.
                            tracing::warn!(
                                target: "talos_security",
                                trigger_id = %trigger_id,
                                failure_kind = e.kind().label(),
                                liveness = e.is_liveness(),
                                age_secs = e.age_secs(),
                                "{}",
                                talos_workflow_job_protocol::describe_verify_failure(
                                    "Webhook job result",
                                    &e,
                                )
                            );
                            return Err(ModuleDispatchFailure::Answered {
                                detail: talos_workflow_job_protocol::describe_verify_failure(
                                    "Job result",
                                    &e,
                                ),
                            });
                        }
                    }

                    // R2 token ledger: record the VERIFIED result's LLM usage.
                    // Module-bound webhook dispatch is the one primary-verify
                    // site outside the engine dispatcher, so it records
                    // directly (identity from the controller-resolved
                    // actor/user above, never the worker result). Spawned +
                    // best-effort: accounting must not delay or fail the
                    // webhook response.
                    if !result.llm_usage.is_empty() {
                        let repo = talos_actor_repository::ActorRepository::new(usage_pool.clone());
                        let entries: Vec<talos_actor_repository::LlmUsageInsert> = result
                            .llm_usage
                            .iter()
                            .map(|u| talos_actor_repository::LlmUsageInsert {
                                provider: u.provider.clone(),
                                model: u.model.clone(),
                                prompt_tokens: i64::from(u.prompt_tokens),
                                completion_tokens: i64::from(u.completion_tokens),
                                calls: i64::from(u.calls).try_into().unwrap_or(i32::MAX),
                            })
                            .collect();
                        tokio::spawn(async move {
                            if let Err(e) = repo
                                .record_llm_usage(
                                    Some(job_id),
                                    resolved_actor,
                                    Some(user_id),
                                    &entries,
                                )
                                .await
                            {
                                tracing::warn!(
                                    job_id = %job_id,
                                    error = %e,
                                    "failed to record webhook module LLM usage"
                                );
                            }
                        });
                    }

                    match result.status {
                        talos_workflow_job_protocol::JobStatus::Success => {
                            Ok(result.output_payload.value().to_string())
                        }
                        _ => Err(ModuleDispatchFailure::Answered {
                            detail: format!("Execution failed: {}", result.output_payload.value()),
                        }),
                    }
                }
            })
            .await;

            // RFC 0010 P3 (M4): this path is request/reply — the worker claimed
            // its sealed secrets DURING the request above. `discard` after the
            // join reclaims the entry on any outcome where the worker never
            // claimed (timeout / publish error / task panic); it's a no-op when
            // the claim already took it. Belt-and-braces with the TTL sweep.
            if let Some(h) = &self.sealing_handle {
                h.in_flight.discard(job_id);
            }

            // MCP-961 sibling: saturating u128→i32 conversion. Pre-fix
            // `as i32` wrapped for durations > i32::MAX ms (~24.8 days).
            // The webhook timeout bounds practical exposure, but the
            // column type is i32 — saturating keeps the column
            // monotonic under any future timeout policy change.
            let wasm_duration_ms =
                i32::try_from(wasm_start.elapsed().as_millis()).unwrap_or(i32::MAX);

            let (response_body, success, error_msg) = match result {
                Ok(Ok(output)) => {
                    // Auth passed and execution succeeded — clear any CB failures for this IP.
                    if let Some(ip) = source_ip {
                        self.circuit_breaker.record_success(ip);
                    }
                    (output, true, None)
                }
                Ok(Err(e)) => {
                    tracing::error!(
                        trigger_id = %trigger_id,
                        error = %e,
                        replayable = e.worker_never_saw_job(),
                        "WASM execution failed"
                    );
                    // Post-auth DLQ capture, decided by TYPE: a publish
                    // failure or a silent reply window leaves a REPLAYABLE
                    // row; a module that ran and reported an error does not
                    // (`module_executions` already records it, and a replay
                    // would double its side effects).
                    if let Some(reason) = e.dlq_drop_reason() {
                        self.capture_post_auth_drop(
                            trigger_id,
                            Some(&DlqCapture {
                                headers,
                                body: &body,
                                source_ip,
                            }),
                            reason,
                        );
                    }
                    // R2-4 invariant extended one step: when the job never
                    // reached NATS the module never ran, so the dedup claim
                    // is abandoned and the sender's redelivery is honoured.
                    // Pre-fix this arm held the claim for EVERY task error, so
                    // a publish failure suppressed the retry as a "duplicate"
                    // for the whole window. `ReplyLost` deliberately keeps the
                    // claim — the worker may still be executing.
                    if matches!(e, ModuleDispatchFailure::NotDispatched { .. }) {
                        self.release_dedup_claim(trigger_id, &dedup_claim).await;
                    }
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

            // Finalize the `module_executions` row INSERTed as `running` above.
            // Without this the webhook-fired module's tracking row sticks at
            // `running` forever — even on success — because the webhook path
            // consumes the worker JobResult inline (request/reply) and there is
            // no result-subscriber to finalize it (the workflow-dispatch path
            // finalizes via the engine's module_execution_store). Best-effort:
            // a finalize failure must not change the webhook response.
            //
            // MONOTONIC: `wasm_duration_ms` is `wasm_start.elapsed()`, an
            // `Instant` — so it survives a host suspend, which is the whole
            // point of supplying it. Before this it was computed, written to
            // the webhook request log, and then DISCARDED here, leaving the
            // `calculate_module_execution_duration()` trigger to derive
            // `completed_at - started_at` instead: the exact defect #707 fixed
            // on the engine path, on a path #707 did not sweep. On the live
            // stack wall and monotonic have diverged by 8.1 hours, so the
            // derived value is a nap length, not a duration.
            //
            // The span is the CONTROLLER-SIDE dispatch — the same class the
            // engine's `record_completed` rows carry (`dispatch_started`), so
            // webhook rows stay comparable with engine rows. It is a little
            // WIDER than the trigger's derivation would have been: `wasm_start`
            // is taken before the actor resolution and payload encryption that
            // precede the row's own INSERT. That is deliberate and matches the
            // engine path's own reasoning — the dispatch really did take that
            // long, and the alternative is a number from the wrong clock.
            //
            // Deliberately NOT the worker's self-reported
            // `JobResult::execution_time_ms`: that is a strictly narrower,
            // WORKER-side span (it excludes the NATS round trip and any queue
            // wait), so it would put a second span class under one label.
            // Measured on 12 paired jobs 2026-08-31 the two differ by 5-14 ms
            // (median 7) on an idle worker, but the gap is unbounded under
            // queue backlog or a dispatcher retry.
            if let Some(svc) = &self.module_execution_service {
                let finalize = if success {
                    svc.complete_execution_from_worker(
                        job_id,
                        serde_json::from_str::<serde_json::Value>(&response_body).ok(),
                        Some(wasm_duration_ms),
                    )
                    .await
                } else {
                    // `error_type` — the CAUSE, derived from the SAME text
                    // bound into `error_message` one argument up.
                    //
                    // #744 gave `module_executions.error_type` a derivation at
                    // the ENGINE's finalizer (`record_completed`) and left the
                    // two `fail_execution_from_worker` callers passing `None`.
                    // This is one of them, and it is the one with no engine in
                    // its path at all: a MODULE-bound webhook dispatches the
                    // module directly, so nothing else ever closes this row and
                    // every such failure stored NULL — the exact gap #744
                    // closed one path over. Same single home
                    // (`talos_engine::module_error_type`), same vocabulary, so
                    // the stored column and `analyze_execution_failure` cannot
                    // give one cause two names.
                    //
                    // Stated limit: this derives from the PRE-redaction text,
                    // because `fail_execution_from_worker` redacts inside the
                    // callee and the vocabulary lives in a crate that callee
                    // cannot reach (the dependency edge runs
                    // webhooks -> engine -> module-executions). #744's own
                    // engine site derives from the redacted string for exactly
                    // the "cannot drift from what an operator reads" reason;
                    // here that is unavailable without inverting an edge.
                    let msg = error_msg
                        .clone()
                        .unwrap_or_else(|| "webhook module execution failed".to_string());
                    let error_type =
                        talos_engine::module_error_type::derive_error_type("failed", Some(&msg))
                            .map(str::to_string);
                    svc.fail_execution_from_worker(job_id, msg, error_type, Some(wasm_duration_ms))
                        .await
                };
                if let Err(e) = finalize {
                    tracing::warn!(
                        trigger_id = %trigger_id,
                        job_id = %job_id,
                        error = %e,
                        "failed to finalize webhook module_executions row (left at 'running')"
                    );
                }
            }

            // MCP-961 sibling: see wasm_duration_ms above — saturating
            // u128→i32 conversion bounds the column under any future
            // timeout policy change.
            let total_duration_ms =
                i32::try_from(start_time.elapsed().as_millis()).unwrap_or(i32::MAX);

            // Decoupled Write Path: Async Logging & State Updates
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

            tokio::spawn(async move {
                // 10. Update statistics
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

            // 12. Chain to downstream workflow nodes
            let output_value = serde_json::from_str::<serde_json::Value>(&response_body)
                .unwrap_or(serde_json::Value::String(response_body.clone()));
            let nats = self.nats_client.clone();
            let secrets_manager = self.secrets_manager.clone();
            let db_pool = self.db_pool.clone();
            let worker_shared_key_for_chain = self.worker_shared_key.clone();
            let redis_client = self.registry.redis_client.clone();
            let trigger_error = error_msg.clone();
            let router_for_chain = self.clone();
            tokio::spawn(async move {
                if let Err(e) = talos_engine::workflow_chains::run_workflow_chains(
                    nats,
                    secrets_manager,
                    &db_pool,
                    worker_shared_key_for_chain,
                    redis_client,
                    router_for_chain.worker_manager.clone(),
                    router_for_chain.module_execution_service.clone(),
                    module_id,
                    user_id,
                    output_value,
                    trigger_id,
                    job_id,
                    trigger_error,
                )
                .await
                {
                    tracing::error!("Failed to run workflow chains: {}", e);
                }
            });

            // 13. Return response
            if trigger.auto_respond {
                if success {
                    Ok((status_code, response_body).into_response())
                } else {
                    // MCP-926 (2026-05-14): always return generic
                    // "Internal server error" to the webhook caller on
                    // failure. Pre-fix `error_msg.unwrap_or_else(...)`
                    // looked defensive but was effectively
                    // `error_msg.unwrap()` — `error_msg` is set to
                    // `Some(e.to_string())` on EVERY failure branch
                    // (WASM-error at ~line 1116, task-panic at ~line
                    // 1124), so the fallback never fired. The webhook
                    // response body always carried the full
                    // `anyhow::Error` chain (sqlx detail, workflow
                    // node internals, panic-message stack frames) to
                    // whoever hit the URL — and webhook URLs are
                    // public-facing by design. Same class as
                    // MCP-923/924/925 but on the public webhook
                    // surface instead of the user-authed integration
                    // REST handlers. Full error is already captured
                    // server-side via `tracing::error!` at the WASM/
                    // panic branches AND stored in
                    // `webhook_request_log` via `log_request` —
                    // operators and the trigger owner have full
                    // detail through both paths.
                    Ok(
                        (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
                            .into_response(),
                    )
                }
            } else {
                Ok((StatusCode::OK, "OK").into_response())
            }
        } else if let Some(workflow_id) = trigger.workflow_id {
            // Workflow Trigger Path
            //
            // FU-3: the dedup claim is threaded in so `trigger_workflow_execution`
            // can release it on its TRANSIENT pre-dispatch failures only (it
            // knows exactly which exits are above the run/spawn boundary). A
            // status-based release HERE would be unsafe — sync mode returns
            // 5xx/504 AFTER the engine ran — so the decision lives inside the
            // method where pre- vs post-dispatch is unambiguous.
            let body_str = std::str::from_utf8(&body).unwrap_or("");

            // RFC 0007 D5: surface inbound event metadata to the workflow as a
            // reserved `__webhook__` key inside the trigger seed (the workflow
            // reads `{{__trigger_input__.__webhook__.event}}`). Same shared
            // builder as the module path and the DLQ replay path.
            let input_payload =
                build_webhook_trigger_payload(body_str, headers, trigger.event_filter.as_ref());

            self.trigger_workflow_execution(
                workflow_id,
                trigger.user_id,
                input_payload,
                trigger_id,
                trigger.auto_respond,
                trigger.sync_timeout_secs,
                &dedup_claim,
                // Post-auth: the three pre-dispatch exits inside record a
                // REPLAYABLE DLQ row (`dispatch_failure::drop_reason::WORKFLOW_*`).
                Some(&DlqCapture {
                    headers,
                    body: &body,
                    source_ip,
                }),
            )
            .await
        } else {
            Ok((
                StatusCode::BAD_REQUEST,
                "Webhook trigger has no module or workflow associated",
            )
                .into_response())
        }
    }

    /// Triggers a workflow execution directly from a webhook.
    ///
    /// Behaviour split by `auto_respond`:
    /// * `false` (async, default): spawn the engine, return 202 + queued
    ///   `execution_id` immediately. Caller polls.
    /// * `true` (synchronous): run the engine inline under a
    ///   `tokio::time::timeout(sync_timeout_secs, ...)`, collect the
    ///   per-node output, return 200 + JSON inline. On timeout the
    ///   engine continues in the background — caller gets 504 + the
    ///   `execution_id` so they can poll later.
    ///
    /// Both paths use `run_with_trigger_input_via_nats` (the canonical
    /// trigger-seed entry — wires the synthetic `__trigger__` node
    /// correctly). The previous implementation seeded with a random
    /// UUID, which silently produced workflows that never saw the
    /// webhook input.
    /// `dedup_claim` (FU-3): the webhook dedup claim taken at arrival, or `None`
    /// (DLQ replay / no dedup backend). On a TRANSIENT pre-dispatch failure —
    /// one that happens BEFORE the engine starts and could succeed on a retry
    /// (auth DB error, execution-row create failure, concurrency limit, engine
    /// build failure) — the claim is released so the sender's redelivery isn't
    /// suppressed as a duplicate. It is NOT released on permanent denials
    /// (workflow-not-found / actor / capability — retrying is futile, so leaving
    /// the duplicate suppressed is correct) and NOT on any POST-dispatch outcome
    /// (the engine already ran; releasing would risk a double-run). The
    /// invariant: any release MUST be at an exit ABOVE the run/spawn boundary.
    async fn trigger_workflow_execution(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        input_payload: serde_json::Value,
        trigger_id: Uuid,
        auto_respond: bool,
        sync_timeout_secs: i32,
        dedup_claim: &Option<String>,
        dlq_capture: Option<&DlqCapture<'_>>,
    ) -> Result<Response> {
        let execution_id = Uuid::new_v4();

        // 1. Fetch the workflow's graph + actor binding BEFORE creating
        //    the execution row so the row carries the workflow's bound
        //    actor_id and provenance.trigger_type='webhook' from the
        //    start. Pre-fix (MCP-20/21, 2026-05-07) the webhook path
        //    INSERTed with no provenance and no actor_id — same bug
        //    class as the scheduler — so analytics queries that filter
        //    by `provenance->>'trigger_type'` and per-actor counts both
        //    missed webhook-triggered runs.
        #[derive(sqlx::FromRow)]
        struct WorkflowDispatchRow {
            graph_json: String,
            actor_id: Option<Uuid>,
        }
        let wf_row = match sqlx::query_as::<_, WorkflowDispatchRow>(
            "SELECT graph_json, actor_id FROM workflows WHERE id = $1 AND user_id = $2",
        )
        .bind(workflow_id)
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(
                    workflow_id = %workflow_id,
                    error = %e,
                    "Failed to fetch workflow graph from database"
                );
                return Ok((StatusCode::NOT_FOUND, "Workflow not found").into_response());
            }
        };
        let graph_json = wf_row.graph_json;

        // MCP-565: trigger-time authorization (budget + status +
        // capability-ceiling re-verify). Mirrors the GraphQL +
        // execution-orchestration trigger paths — see the comment on
        // `authorize_workflow_trigger`. Pre-fix the webhook path
        // bypassed:
        //   * actor-suspended check (operator could resume actor's
        //     workflows by webhook even after `update_actor_status`),
        //   * hourly + lifetime budget caps (a misbehaving upstream
        //     could fire continuously past `max_executions_per_hour`),
        //   * capability-ceiling re-verification (a post-create graph
        //     edit that escalated a node's world wouldn't be re-checked
        //     against the actor's `max_capability_world`).
        // The MCP-555 / MCP-557 / MCP-564 sweep covered scheduler /
        // chains / retry / continuation; this closes the last surface.
        //
        // Phase D2 parity (PR #461 follow-up): the gate now runs
        // UNCONDITIONALLY and its resolved actor is captured for the row
        // stamp + engine binding below. Pre-fix, an unbound workflow's
        // webhook dispatch skipped the gate AND left the engine unbound —
        // running at the engine's fail-safe Tier-1 (external-LLM calls
        // denied, `__memory_write__` dropped) while the SAME workflow
        // triggered manually resolved the user's default actor (Tier-2).
        let denied_actor_source = if wf_row.actor_id.is_some() {
            "workflow-bound"
        } else {
            "user-default-actor"
        };
        let effective_actor_id: Option<uuid::Uuid> = {
            use talos_workflow_authorization::TriggerAuthError;
            let workflow_repo_for_auth =
                talos_workflow_repository::WorkflowRepository::new(self.db_pool.clone());
            let actor_repo_for_auth =
                talos_actor_repository::ActorRepository::new(self.db_pool.clone());
            match talos_workflow_authorization::resolve_effective_actor(
                &workflow_repo_for_auth,
                &actor_repo_for_auth,
                &self.db_pool,
                wf_row.actor_id,
                user_id,
                &graph_json,
            )
            .await
            {
                Ok(resolved) => resolved,
                Err(TriggerAuthError::ActorNotFoundOrInactive)
                | Err(TriggerAuthError::ActorArchived)
                | Err(TriggerAuthError::ActorTerminated) => {
                    tracing::warn!(
                        target: "talos_webhooks",
                        event_kind = "webhook_dispatch_denied_actor_state",
                        workflow_id = %workflow_id,
                        trigger_id = %trigger_id,
                        %user_id,
                        denied_actor_source,
                        "MCP-565: webhook dispatch denied — actor not in a runnable state"
                    );
                    return Ok((StatusCode::FORBIDDEN, "Actor not runnable").into_response());
                }
                Err(TriggerAuthError::ExecutionDenied(reason)) => {
                    tracing::warn!(
                        target: "talos_webhooks",
                        event_kind = "webhook_dispatch_denied_by_budget",
                        workflow_id = %workflow_id,
                        trigger_id = %trigger_id,
                        %user_id,
                        denied_actor_source,
                        reason = %reason,
                        "MCP-565: webhook dispatch denied by actor budget/status gate"
                    );
                    return Ok(
                        (StatusCode::TOO_MANY_REQUESTS, "Actor budget exceeded").into_response()
                    );
                }
                Err(TriggerAuthError::CapabilityCeilingViolation { .. }) => {
                    tracing::warn!(
                        target: "talos_webhooks",
                        event_kind = "webhook_dispatch_denied_capability_ceiling",
                        workflow_id = %workflow_id,
                        trigger_id = %trigger_id,
                        %user_id,
                        denied_actor_source,
                        "MCP-565: webhook dispatch denied — workflow exceeds actor capability ceiling"
                    );
                    return Ok((
                        StatusCode::FORBIDDEN,
                        "Workflow capability exceeds actor ceiling",
                    )
                        .into_response());
                }
                Err(TriggerAuthError::Database(e)) => {
                    tracing::error!(
                        target: "talos_webhooks",
                        event_kind = "webhook_dispatch_auth_db_error",
                        workflow_id = %workflow_id,
                        %user_id,
                        denied_actor_source,
                        error = %e,
                        "MCP-565: webhook dispatch authorization DB error — failing closed"
                    );
                    // FU-3: transient pre-dispatch failure — engine never ran;
                    // release the dedup claim so the sender's retry is honored.
                    self.release_dedup_claim(trigger_id, dedup_claim).await;
                    self.capture_post_auth_drop(
                        trigger_id,
                        dlq_capture,
                        dispatch_failure::drop_reason::WORKFLOW_AUTH_DB_ERROR,
                    );
                    return Err(anyhow::anyhow!("Internal authorization error"));
                }
            }
        };

        // 2. Create the execution row via the canonical
        //    `create_execution_under_concurrency_limit` helper. This
        //    consolidates webhook-triggered runs onto the same write
        //    path used by trigger_workflow / scheduler, with:
        //      • TOCTOU-safe concurrency gate (SELECT FOR UPDATE on
        //        the workflows row + COUNT + INSERT in one tx),
        //      • actor_id stamped on the row (MCP-21),
        //      • provenance.trigger_type='webhook' + trigger_id stamped
        //        for analytics filters (MCP-20).
        //
        //    allow-trigger-type-column: JSON object key in provenance literal,
        //    not a SQL column reference.
        let provenance = serde_json::json!({
            "trigger_type": "webhook",
            "trigger_id": trigger_id.to_string(),
        });
        let workflow_repo =
            talos_workflow_repository::WorkflowRepository::new(self.db_pool.clone());
        let admission = match workflow_repo
            .create_execution_under_concurrency_limit(
                execution_id,
                workflow_id,
                user_id,
                None, // version_id — webhook runs the active graph
                // The priority the graph declares (was `None` → `normal` until
                // 2026-09-10, disagreeing with the manual-trigger path).
                talos_workflow_repository::ExecutionPriority::declared_in_graph_json(&graph_json),
                // Phase D2: the gate-resolved actor so row attribution
                // matches the engine binding below.
                effective_actor_id,
                Some(&provenance),
                None, // parent_execution_id
                None, // root_execution_id
                talos_workflow_repository::InitialExecutionStatus::Queued,
            )
            .await
        {
            Ok(a) => a,
            Err(e) => {
                tracing::error!("Failed to create execution record: {}", e);
                // FU-3: transient pre-dispatch failure — engine never ran.
                self.release_dedup_claim(trigger_id, dedup_claim).await;
                self.capture_post_auth_drop(
                    trigger_id,
                    dlq_capture,
                    dispatch_failure::drop_reason::WORKFLOW_EXECUTION_ROW_FAILED,
                );
                return Err(anyhow::anyhow!("Internal server error"));
            }
        };
        match admission {
            talos_workflow_repository::ConcurrencyAdmission::Created => {}
            talos_workflow_repository::ConcurrencyAdmission::WorkflowArchived => {
                // The NARROW lifecycle gate (2026-09-07).
                //
                // The CALLER is told exactly what it is told about a workflow
                // that is not there — the same 404 and the same four words as
                // the load at the top of this function. That is deliberate and
                // it is the one place in this change where a refusal is
                // rendered as an absence ON PURPOSE: an inbound webhook caller
                // is unauthenticated with respect to the workflow, and a reply
                // that distinguishes "archived" from "no such workflow" is an
                // existence oracle for anyone who can guess a trigger id. Same
                // argument as `caller_facing_unauthorized` and #754's
                // collapsed `write_ceiling_unreadable` reply.
                //
                // There is no paused-workflow response to mirror, and that was
                // MEASURED rather than assumed: this path consults
                // `workflows.is_enabled` nowhere, in SQL or in Rust, so a
                // disabled workflow still fires by webhook today. The narrow
                // gate does not change that — it is the other column.
                //
                // The OPERATOR keeps the distinction, in the counter and in a
                // WARN. WARN rather than the scheduler's DEBUG because this is
                // not a recurring tick: a webhook refusal is one inbound
                // request, so the line cannot become the permanent noise
                // check 69 exists for, and an upstream that keeps posting to a
                // retired workflow is worth seeing.
                //
                // The dedup claim is NOT released, matching the "Workflow not
                // found" exit above: releasing invites a retry, and this
                // refusal cannot be repaired by retrying.
                talos_metrics::record_dispatch_refusal(
                    talos_workflow_liveness::dispatch::DispatchPath::Webhook,
                );
                tracing::warn!(
                    target: talos_workflow_liveness::dispatch::REFUSAL_TARGET,
                    event_kind = talos_workflow_liveness::dispatch::REFUSAL_EVENT_KIND,
                    path = talos_workflow_liveness::dispatch::DispatchPath::Webhook.as_str(),
                    workflow_id = %workflow_id,
                    trigger_id = %trigger_id,
                    "Webhook fired at an archived workflow; refusing. The caller \
                     is told only 'Workflow not found'."
                );
                return Ok((StatusCode::NOT_FOUND, "Workflow not found").into_response());
            }
            talos_workflow_repository::ConcurrencyAdmission::LimitReached { limit, .. } => {
                // FU-3: transient pre-dispatch failure — a concurrency slot may free
                // up, so a later retry can succeed; release the dedup claim.
                self.release_dedup_claim(trigger_id, dedup_claim).await;
                return Ok((
                    StatusCode::TOO_MANY_REQUESTS,
                    format!("Concurrency limit reached: {}", limit),
                )
                    .into_response());
            }
            talos_workflow_repository::ConcurrencyAdmission::ActorBudgetExceeded {
                kind,
                limit,
                count,
            } => {
                // The atomic backstop rolled back the INSERT — no execution
                // row exists. Pre-fix this arm fell through an `if let
                // LimitReached` and the engine ran anyway (budget-bypassing
                // ghost run) — same defect the PR #461 review confirmed in
                // the scheduler. Budget windows refill, so release the dedup
                // claim and 429 like LimitReached.
                self.release_dedup_claim(trigger_id, dedup_claim).await;
                return Ok((
                    StatusCode::TOO_MANY_REQUESTS,
                    talos_workflow_repository::actor_budget_exceeded_message(kind, limit, count),
                )
                    .into_response());
            }
        }

        // Canonical engine builder. TimeoutPolicy::Honor closes a latent
        // bug: pre-r227, this site never set execution_timeout_secs at all,
        // so a workflow with `execution_timeout_secs: 60` in its graph_json
        // was silently using the engine compile-time default (300 s) when
        // triggered via webhook — the same regression class r225 fixed for
        // the scheduler. The for_workflow path goes through
        // load_graph_from_json which now correctly populates the field
        // from the JSON.
        //
        // Phase D2: bind the gate-resolved actor (explicit → workflow →
        // default fallback already applied inside the gate) so the engine
        // tier matches the stamped execution row. Pre-fix an unbound
        // workflow left the engine actorless here and it ran at the
        // Tier-1 fail-safe while the same workflow triggered manually ran
        // Tier-2 under the default actor. Bound workflows behave exactly
        // as before (the gate returns their own actor).
        let actor_repo = std::sync::Arc::new(talos_actor_repository::ActorRepository::new(
            self.db_pool.clone(),
        ));
        let opts = talos_engine::builder::EngineOpts::for_run(workflow_id, graph_json.clone())
            .with_effective_actor(effective_actor_id, wf_row.actor_id);
        let mut engine = match talos_engine::builder::for_workflow(
            self.registry.clone(),
            self.secrets_manager.clone(),
            actor_repo,
            user_id,
            opts,
        )
        .await
        {
            Ok(e) => e,
            Err(e) => {
                // MCP-993 (2026-05-15): DLP-redact the error in the
                // operator-log surface too. Builder errors can wrap
                // registry / secrets-manager failures whose anyhow
                // context strings include caller-supplied identifiers
                // (vault paths, module IDs as substrings of upstream
                // API error bodies). Sibling MCP-989/990 — operator
                // logs containing worker/WASM-adjacent error chains
                // need the same DLP discipline as the persistence
                // path that follows (MCP-449 line ~1534).
                let redacted_for_log = talos_dlp_provider::redact_str(&format!("{:?}", e));
                tracing::error!(
                    workflow_id = %workflow_id,
                    error = %redacted_for_log,
                    "Failed to build engine for webhook trigger"
                );
                // MCP-449: DLP-redact the engine error before it lands
                // in the DB row. Same secret-leak class as MCP-447.
                let redacted = talos_dlp_provider::redact_str(&format!("{:?}", e));
                // MCP-743 (2026-05-13): log the UPDATE result. Pre-fix
                // `let _ = sqlx::query(...).await` discarded the result;
                // if the DB UPDATE itself failed (pool exhaustion,
                // deadlock, etc.) the execution row was left in its
                // initial 'queued' state with no recorded failure
                // reason — operator dashboards saw an execution that
                // never moved past queued and no log signal explaining
                // why. Same operator-visibility class as MCP-733..742.
                if let Err(db_err) = sqlx::query(
                    "UPDATE workflow_executions SET status = 'failed', error_message = $2, completed_at = NOW() WHERE id = $1 AND status NOT IN ('completed', 'failed', 'cancelled', 'resuming')",
                )
                .bind(execution_id)
                .bind(format!("Failed to load graph: {}", redacted))
                .execute(&self.db_pool)
                .await
                {
                    tracing::warn!(
                        target: "talos_rpc",
                        execution_id = %execution_id,
                        workflow_id = %workflow_id,
                        error = %db_err,
                        "Failed to mark webhook execution failed after graph-load error — execution row left in queued state",
                    );
                }
                // FU-3: transient pre-dispatch failure (registry/secrets/graph
                // build hiccup) — engine never ran; release the dedup claim.
                self.release_dedup_claim(trigger_id, dedup_claim).await;
                self.capture_post_auth_drop(
                    trigger_id,
                    dlq_capture,
                    dispatch_failure::drop_reason::WORKFLOW_GRAPH_LOAD_FAILED,
                );
                return Ok((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to load workflow graph",
                )
                    .into_response());
            }
        };

        let nats = self.nats_client.clone();
        let worker_shared_key = self.worker_shared_key.clone();

        // Stats update (fire-and-forget) — same in both modes.
        let router_clone = self.clone();
        tokio::spawn(async move {
            router_clone
                .update_trigger_stats(trigger_id, user_id, true, 0)
                .await;
        });

        if auto_respond {
            // Synchronous mode: wait inline up to sync_timeout_secs for the
            // engine to complete and return per-node output as the HTTP body.
            // MCP-1091: clamp at the read boundary to defend against legacy
            // / direct-DB-written rows outside the MCP creation validator's
            // 1..=120 range. Pre-fix a stored `sync_timeout_secs = -1` cast
            // straight to `u64::MAX`, giving an effectively-infinite timeout
            // that pinned a worker connection indefinitely. Sibling class to
            // MCP-767/811/812/997 (caller-supplied-negative clamp lint).
            let timeout_secs = sync_timeout_secs.clamp(1, 120) as u64;
            let timeout = std::time::Duration::from_secs(timeout_secs);
            let _trigger_input_for_storage = input_payload.clone();
            let db_pool = self.db_pool.clone();

            // We move `engine` into the run; capture node_labels first.
            // After completion node_labels is still valid since engine is borrowed.
            let run_fut = talos_engine::nats_run::run_with_trigger_input_via_nats(
                &mut engine,
                nats,
                worker_shared_key,
                input_payload,
                execution_id,
            );

            match tokio::time::timeout(timeout, run_fut).await {
                Ok(Ok(ctx)) => {
                    let node_labels = engine.node_labels();
                    let mut output = serde_json::Map::new();
                    for (nid, result) in &ctx.results {
                        let key = node_labels
                            .get(nid)
                            .cloned()
                            .unwrap_or_else(|| nid.to_string());
                        if key == "__trigger__" {
                            continue;
                        }
                        if result
                            .get("__skipped")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false)
                        {
                            continue;
                        }
                        let clean =
                            talos_workflow_engine::ParallelWorkflowEngine::unwrap_output(result)
                                .clone();
                        output.insert(key, clean);
                    }
                    let output_value = serde_json::Value::Object(output);
                    // Persist the SCRUBBED output to workflow_executions, return
                    // the UNSCRUBBED output to the caller — they triggered the
                    // request and own the data; the audit log is what gets DLP.
                    let scrubbed_for_storage = talos_dlp_provider::redact_json(&output_value);
                    // MCP-682 (2026-05-13): route through encryption-aware
                    // repository so sync-response webhook completions land
                    // in `output_data_enc` on Phase A deployments. Pre-fix
                    // the raw UPDATE wrote plaintext only, bypassing the
                    // encryption-at-rest guarantee.
                    let wf_repo =
                        talos_workflow_repository::WorkflowRepository::new(db_pool.clone())
                            .with_encryption(self.secrets_manager.clone());
                    // PR #423 sibling: a wait/confidence-gate pause is NOT
                    // completed — persist status='waiting' so the row stays
                    // resumable, and tell the webhook caller "waiting" so
                    // they don't treat the paused run as terminal.
                    let is_waiting = ctx.waiting;
                    if is_waiting {
                        if let Err(e) = wf_repo
                            .mark_execution_waiting(execution_id, &scrubbed_for_storage)
                            .await
                        {
                            tracing::error!(
                                execution_id = %execution_id,
                                error = %e,
                                "Failed to mark webhook execution waiting"
                            );
                        }
                    } else if let Err(e) = wf_repo
                        .mark_execution_completed(execution_id, &scrubbed_for_storage)
                        .await
                    {
                        tracing::error!(
                            execution_id = %execution_id,
                            error = %e,
                            "Failed to mark webhook execution completed"
                        );
                    }

                    let body = serde_json::json!({
                        "execution_id": execution_id,
                        "status": if is_waiting { "waiting" } else { "completed" },
                        "output": output_value,
                    })
                    .to_string();
                    Ok((
                        StatusCode::OK,
                        [(axum::http::header::CONTENT_TYPE, "application/json")],
                        body,
                    )
                        .into_response())
                }
                Ok(Err(e)) => {
                    // MCP-449 + MCP-993: DLP-redact the engine error.
                    // CRITICAL on this path because `err_msg` is fanned
                    // out to THREE surfaces:
                    //   - The operator-log line below (MCP-993 — workflow
                    //     execution errors regularly wrap upstream API
                    //     bodies / module output strings that contain
                    //     secret-shaped values).
                    //   - The DB row (MCP-449 — error_message column).
                    //   - The HTTP response body returned to the webhook
                    //     caller (external system: Slack, GitHub, etc.).
                    //     The external caller would otherwise see any
                    //     token echoed back by a failing upstream call.
                    let err_msg = talos_dlp_provider::redact_str(&format!("{:?}", e));
                    tracing::error!(
                        execution_id = %execution_id,
                        error = %err_msg,
                        "Workflow sync execution failed"
                    );
                    // MCP-743 (2026-05-13): log the failure-UPDATE result
                    // — see the matching site above for the operator-
                    // visibility rationale. The execution row would
                    // otherwise be stuck in 'queued' even though the
                    // caller saw 500 + the redacted error in the body.
                    if let Err(db_err) = sqlx::query(
                        "UPDATE workflow_executions SET status = 'failed', error_message = $2, completed_at = NOW() WHERE id = $1 AND status NOT IN ('completed', 'failed', 'cancelled', 'resuming')",
                    )
                    .bind(execution_id)
                    .bind(&err_msg)
                    .execute(&db_pool)
                    .await
                    {
                        tracing::warn!(
                            target: "talos_rpc",
                            execution_id = %execution_id,
                            error = %db_err,
                            "Failed to mark webhook execution failed after sync run error — execution row left in queued state",
                        );
                    }
                    let body = serde_json::json!({
                        "execution_id": execution_id,
                        "status": "failed",
                        "error": err_msg,
                    })
                    .to_string();
                    Ok((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        [(axum::http::header::CONTENT_TYPE, "application/json")],
                        body,
                    )
                        .into_response())
                }
                Err(_elapsed) => {
                    // Timeout: the engine future was dropped on timeout, so
                    // the workflow is NOT actually still running. Mark the
                    // execution failed with a clear timeout reason and
                    // return 504 + execution_id so the caller can find the
                    // record in their history.
                    tracing::warn!(
                        execution_id = %execution_id,
                        sync_timeout_secs = timeout_secs,
                        "Sync webhook execution exceeded sync_timeout_secs",
                    );
                    let err_msg = format!(
                        "Synchronous webhook execution exceeded sync_timeout_secs={}s. \
                         Reduce workflow complexity, raise sync_timeout_secs (max 120), \
                         or set auto_respond=false to use async dispatch.",
                        timeout_secs
                    );
                    // MCP-743 (2026-05-13): log the failure-UPDATE
                    // result on the sync-timeout path. Without this,
                    // a DB hiccup at the exact moment a sync webhook
                    // times out leaves the execution row in 'queued'
                    // forever AND the caller receives 504 — operator
                    // sees an indefinitely-queued execution with no
                    // explanation, indistinguishable from a stuck
                    // dispatcher.
                    if let Err(db_err) = sqlx::query(
                        "UPDATE workflow_executions SET status = 'failed', error_message = $2, completed_at = NOW() WHERE id = $1 AND status NOT IN ('completed', 'failed', 'cancelled', 'resuming')",
                    )
                    .bind(execution_id)
                    .bind(&err_msg)
                    .execute(&db_pool)
                    .await
                    {
                        tracing::warn!(
                            target: "talos_rpc",
                            execution_id = %execution_id,
                            sync_timeout_secs = timeout_secs,
                            error = %db_err,
                            "Failed to mark webhook execution failed after sync timeout — execution row left in queued state",
                        );
                    }
                    let body = serde_json::json!({
                        "execution_id": execution_id,
                        "status": "timeout",
                        "error": err_msg,
                    })
                    .to_string();
                    Ok((
                        StatusCode::GATEWAY_TIMEOUT,
                        [(axum::http::header::CONTENT_TYPE, "application/json")],
                        body,
                    )
                        .into_response())
                }
            }
        } else {
            // Async mode: spawn engine, return 202 immediately.
            //
            // NOT epoch-fenced (self-review correction): an earlier change wired
            // the FU-1 fence here, but it was inert AND unnecessary. The webhook
            // async path creates the execution row as `Queued` and nothing
            // transitions it to `running` before the engine writes its terminal
            // status (only the MCP enqueue path calls
            // mark_execution_running_from_queued). Crash recovery
            // (`claim_stuck_execution_for_resume`) only reclaims `running` rows,
            // so a `queued` webhook run is NEVER reclaimed → there is never a
            // resumer → there is no split-brain for a fence to close. The fence
            // therefore protected against nothing (and cost a per-run heartbeat
            // task). Wiring it in would only have meaning if we ALSO marked the
            // row `running` — i.e. made webhook runs crash-recoverable — which is
            // a separate deliberate change, not something to bolt on to justify a
            // fence. Left unfenced; the run's terminal write is status-guarded.
            tokio::spawn(async move {
                if let Err(e) = talos_engine::nats_run::run_with_trigger_input_via_nats(
                    &mut engine,
                    nats,
                    worker_shared_key,
                    input_payload,
                    execution_id,
                )
                .await
                {
                    tracing::error!(
                        execution_id = %execution_id,
                        workflow_id = %workflow_id,
                        error = ?e,
                        "Workflow execution failed (async)"
                    );
                }
            });

            let body = serde_json::json!({
                "execution_id": execution_id,
                "status": "queued",
            })
            .to_string();
            Ok((
                StatusCode::ACCEPTED,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                body,
            )
                .into_response())
        }
    }

    async fn get_trigger(&self, trigger_id: Uuid) -> Result<WebhookTrigger> {
        sqlx::query_as::<_, WebhookTrigger>(
            r#"
            SELECT id, user_id, name, module_id, workflow_id,
                   verification_token,
                   signing_secret_enc, signing_key_id, signing_secret_format,
                   allowed_ips, enabled, auto_respond, queue_events, max_requests_per_minute,
                   COALESCE(sync_response, false) as sync_response,
                   COALESCE(sync_timeout_secs, 30) as sync_timeout_secs,
                   event_filter
            FROM webhook_triggers
            WHERE id = $1
            "#,
        )
        .bind(trigger_id)
        // fetch_optional, NOT fetch_one + .context("not found"): the latter
        // stamped "not found" onto EVERY error including transient DB failures
        // (pool exhaustion, connection drop), which `webhook_handler` then
        // substring-matched to a 404 — masking a real outage as a missing
        // trigger (a legit webhook silently 404s during a DB blip) and muddying
        // the existence oracle. Now a genuine miss → Ok(None) → "not found"
        // (404); a DB error → Err (no "not found" substring) → 500 + logged.
        .fetch_optional(&self.db_pool)
        .await
        .context("get_trigger query failed")?
        .ok_or_else(|| anyhow::anyhow!("Webhook trigger not found"))
    }

    /// Verify HMAC signature from webhook request.
    /// Supports multiple header formats (Slack, GitHub, generic).
    ///
    /// Thin `bool` wrapper kept for external callers
    /// (`controller/tests/webhooks_hmac_test.rs`). The live auth gate calls
    /// `signature::verify_hmac_signature` directly because it needs to know
    /// WHICH format verified — the dedup fingerprint is derived from that
    /// format's own header (F1). A caller that only wants yes/no gets it here.
    #[must_use]
    pub fn verify_hmac_signature(
        &self,
        headers: &HeaderMap,
        body: &Bytes,
        signing_secret: &str,
    ) -> bool {
        signature::verify_hmac_signature(headers, body, signing_secret).is_some()
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
        // Convert headers to JSON. F7d: credential-bearing headers
        // (`X-Verification-Token`, every signature header, Authorization,
        // cookies, API keys — `signature::header_is_sensitive`, the SAME
        // classifier `enqueue_dlq` uses) are recorded as PRESENT but never
        // by value. Pre-fix this map landed the static verification token and
        // the HMAC signatures in plaintext in `webhook_request_log.headers`,
        // queryable via `webhookRequestLog`; the DLP pass below is value-shape
        // based and does not recognise a bare UUID token or a hex signature.
        let headers_json: HashMap<String, String> = headers
            .iter()
            .map(|(k, v)| {
                let value = if signature::header_is_sensitive(k.as_str()) {
                    "[redacted]".to_string()
                } else {
                    v.to_str().unwrap_or("[binary]").to_string()
                };
                (k.as_str().to_string(), value)
            })
            .collect();

        // MCP-1018 (2026-05-15): truncate the User-Agent to 1 KB at a
        // UTF-8 char boundary BEFORE the DLP scan. Sibling-parity to
        // talos-auth's auth_audit_log writer (MCP-478 truncation +
        // MCP-1012 redact). HTTP allows ~64 KB header values; a
        // 64 KB UA fed straight to `redact_str` pays O(N × pattern_count)
        // regex work per webhook request, and lands a 64 KB string
        // in `webhook_request_log.user_agent` queryable via
        // `webhookRequestLog`. Walk backwards from byte 1024 to the
        // nearest char boundary so a multi-byte UTF-8 sequence
        // (localised UAs do this in practice) isn't truncated
        // mid-codepoint and panic.
        //
        // MCP-1050 (2026-05-15): route through canonical
        // `talos_text_util::truncate_at_char_boundary` — the inline
        // walk-back was an exact reimplementation of the helper.
        let user_agent = headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(|ua| {
                talos_dlp_provider::redact_str(talos_text_util::truncate_at_char_boundary(ua, 1024))
            });
        // MCP-977 (2026-05-15): redact the standalone user_agent
        // column. The full header map is already redacted via
        // `redact_json` on `scrubbed_headers` below, but the
        // `user_agent` column is extracted out separately and was
        // bound raw — sibling drift to MCP-974 (entry-level DLQ
        // header drift). A misbehaving / malicious webhook source
        // could stash a secret in the User-Agent header
        // ("python-requests/2.31 (token=sk-...)"), and the bare
        // column would land unscrubbed even while the header map
        // copy was scrubbed.

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

        // MCP-484: DLP-scrub every caller-controlled field before
        // persisting to `webhook_request_log`. Inbound webhooks
        // routinely carry secrets in headers (`Authorization: Bearer
        // ...`, `X-Api-Key: sk-...`) and in bodies (e.g. provider
        // callbacks that echo a token in the JSON payload for
        // diagnostic purposes). Pre-fix every webhook request landed
        // raw — operator's debug tool was also a long-lived
        // secret-leak surface queryable via `webhook_request_log_view`
        // and the GraphQL `webhookRequestLog` connection.
        //
        // `redact_str` handles the body / response_body / error
        // strings; `redact_json` recursively scrubs the header
        // JSONB blob so individual header values get scanned for
        // secret-shaped substrings independently. Same persistence-
        // boundary rule as MCP-481/482/483.
        let scrubbed_body = talos_dlp_provider::redact_str(body_str);
        let scrubbed_headers = serde_json::to_value(&headers_json)
            .ok()
            .as_ref()
            .map(talos_dlp_provider::redact_json);
        // MCP-1160 (2026-05-17): truncate-then-redact for response_body
        // + error_message. Pre-fix both fields ran `redact_str` on the
        // RAW caller-supplied string. `response_body` is the WASM
        // module's output (`output` at the `result` match above); WASM
        // outputs are unbounded by default while the inbound webhook
        // body is already capped at 1 MiB by the route layer
        // (MCP-1158/1159 sweep) AND truncated to 64 KiB before logging
        // (line ~2253 `take(65_535)`). `error_message` is a
        // wasmtime error trace (`e.to_string()` lines ~1265/1273) which
        // can include multi-KB stack info. Without a cap, the DLP
        // regex pass walked the full string per row — sibling drift
        // class to MCP-1012/1018/1027/1028 (auth_audit_log /
        // webhook_request_log user_agent / oauth_audit_log /
        // slack+gmail integration_audit_log) where truncate-first
        // bounds the regex-pass cost AND the persisted row size.
        // 64 KiB ceiling on `response_body` matches the body_str
        // truncation on the inbound side; 4 KiB on `error_message`
        // matches the talos-engine/sandbox wasmtime trace ceiling
        // (4 KiB covers every legitimate trace plus headroom).
        let scrubbed_response = response_body.map(|r| {
            let truncated: &str = if r.len() > 65_536 {
                talos_text_util::truncate_at_char_boundary(r, 65_536)
            } else {
                r
            };
            talos_dlp_provider::redact_str(truncated)
        });
        let scrubbed_response_ref = scrubbed_response.as_deref();
        let scrubbed_err = error_message.map(|e| {
            let truncated: &str = if e.len() > 4096 {
                talos_text_util::truncate_at_char_boundary(e, 4096)
            } else {
                e
            };
            talos_dlp_provider::redact_str(truncated)
        });
        let scrubbed_err_ref = scrubbed_err.as_deref();
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
            scrubbed_headers,
            scrubbed_body,
            ip_str.as_deref(),
            user_agent.as_deref(),
            status_code,
            scrubbed_response_ref,
            response_time_ms,
            wasm_execution_ms,
            success,
            scrubbed_err_ref
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

    /// Evict stale circuit-breaker records (IPs quiet for more than `max_age`).
    /// Call periodically alongside `cleanup_rate_limiter`.
    pub fn cleanup_circuit_breaker(&self) {
        self.circuit_breaker
            .cleanup(std::time::Duration::from_secs(600)); // evict records idle > 10 min
    }

    /// Expose a reference to the circuit breaker for MCP tools and tests.
    pub fn circuit_breaker(&self) -> &Arc<CircuitBreaker> {
        &self.circuit_breaker
    }

    /// Re-dispatch a DLQ payload directly to the workflow/module execution path.
    /// Bypasses circuit-breaker, rate-limiter, IP allowlist, and HMAC verification —
    /// which is exactly why it must be handed the entry's stored header map:
    /// the ONLY thing standing between an attacker's unsigned POST and an
    /// execution is the [`dlq::DLQ_AUTHENTICATED_KEY`] stamp `enqueue_dlq`
    /// wrote when the request was dropped (F2).
    ///
    /// The DLQ holds two classes of row and only one is replayable (see the
    /// `dispatch_failure` module doc). PRE-AUTH DROPS — the circuit-breaker
    /// and rate-limit sites, which sit ABOVE the auth gate — carry
    /// `authenticated: false`: nothing ever checked their signature or token,
    /// so a caller who could reach a rate-limited trigger's URL could park an
    /// arbitrary body in the DLQ and wait for an operator to replay it as the
    /// trigger's owner. POST-AUTH DISPATCH FAILURES — a registry read, the
    /// tracking-row INSERT, signing, the NATS publish or a silent reply
    /// window, at every site where the module / engine never observed the
    /// delivery — carry `authenticated: true` and are what this method is
    /// for. Until 2026-09-10 only the first class was ever written, so the
    /// former doc comment ("the payload was already authenticated when first
    /// received") described rows that did not exist.
    ///
    /// Two gates, both refusals with a caller-readable reason and NO force
    /// flag: (1) the entry must carry `authenticated: true` — a legacy row
    /// (no marker) is treated as unauthenticated, which is also what it was;
    /// (2) the trigger must be `enabled`, the check the live path has at step
    /// 1 and replay lacked.
    pub async fn dispatch_replay(
        &self,
        trigger_id: Uuid,
        body: Vec<u8>,
        dlq_headers: Option<&serde_json::Value>,
    ) -> Result<()> {
        if !dlq::dlq_entry_was_authenticated(dlq_headers) {
            return Err(anyhow::Error::new(dlq::ReplayRefused::Unauthenticated));
        }

        let trigger = self.get_trigger(trigger_id).await?;

        if !trigger.enabled {
            return Err(anyhow::Error::new(dlq::ReplayRefused::TriggerDisabled));
        }

        let body_str = std::str::from_utf8(&body).unwrap_or("");

        // Build the payload through the SAME helper the live path uses, so a
        // replayed delivery is structurally identical to the original. Pre-fix
        // BOTH replay branches skipped the `__webhook__` injection entirely, so
        // a replayed delivery carried no `__webhook__` key at all while the
        // original did — and the module branch additionally omitted
        // `__trigger_input__` (below), so every module using the documented
        // `data["__trigger_input__"]` escape hatch read `null` on replay.
        //
        // ONE deliberate difference remains, and it is a data limitation rather
        // than a choice: replay has no request headers. The DLQ row does store a
        // redacted header map, but `dispatch_replay` is handed only the body
        // (`WebhookRepository::get_dlq_entry_for_replay` selects `trigger_id,
        // payload, replayed_at`), so the two header-derived fields come back
        // `null`: `__webhook__.event` and `__webhook__.delivery`. `action` is
        // read from the body and IS faithful. Null-but-present is the documented
        // shape of an absent field here — strictly closer to the original than
        // omitting the key — but a module that ROUTES on `__webhook__.event`
        // still takes its no-event branch on replay. Plumbing the stored headers
        // through is the follow-up if that ever bites.
        let replay_headers = HeaderMap::new();
        let payload_value =
            build_webhook_trigger_payload(body_str, &replay_headers, trigger.event_filter.as_ref());

        if let Some(workflow_id) = trigger.workflow_id {
            // Replay path is fire-and-forget — never returns the result inline.
            // Force async mode regardless of trigger.auto_respond so the replayer
            // doesn't block on a long-running workflow.
            self.trigger_workflow_execution(
                workflow_id,
                trigger.user_id,
                payload_value,
                trigger_id,
                false, // auto_respond: replay never waits inline
                trigger.sync_timeout_secs,
                // DLQ replay has no inbound dedup claim to release.
                &None,
                // …and no inbound request to re-capture: a failed replay is
                // reported to the operator and the row stays unreplayed.
                None,
            )
            .await?;
        } else if let Some(module_id) = trigger.module_id {
            let module_config = self
                .registry
                .get_module_config(module_id, trigger.user_id)
                .await?
                .unwrap_or(serde_json::json!({}));

            // Same envelope builder as the live module path — `{config, input,
            // __trigger_input__}`, not the `{config, input}` this used to build.
            let wrapped_input = build_module_dispatch_payload(&module_config, &payload_value);

            let job_id = Uuid::new_v4();
            let registry = self.registry.clone();
            let nats = self.nats_client.clone();
            let secrets_manager = self.secrets_manager.clone();
            // RFC 0010 P3 (M4): claim-based sealing handle for this DLQ replay.
            let sealing_handle = self.sealing_handle.clone();
            let worker_shared_key_clone = self.worker_shared_key.clone();
            let user_id = trigger.user_id;
            // Now that the replay records a tracking row, the dispatch task's
            // own bail-outs (module load / sign / serialize / publish) must
            // finalize it — a row stuck at 'running' forever is its own
            // misleading state.
            //
            // The SUCCESS path needs nothing here: this dispatch sets
            // `reply_topic: None` and publishes with no wire reply, so the
            // worker sends its `JobResult` to `talos.results.{job_id}`, where
            // the controller's audit subscriber
            // (`bootstrap/background.rs`, `RESULTS_WILDCARD`) calls
            // `complete_execution_from_worker` / `fail_execution_from_worker`
            // on that same id. What it does NOT cover is the four bail-outs
            // below — those happen before the worker ever sees the job, so no
            // result is ever published and nothing else would move the row off
            // 'running'.
            let exec_service = self.module_execution_service.clone();

            // Phase C: resolve an owning actor for the DLQ replay (same shape as
            // the live webhook path above). Webhook triggers carry no actor →
            // the user's default actor; its tier travels with the re-dispatched
            // job. Fail OPEN to actor-less Tier-2 on any resolution error.
            let (resolved_actor, actor_tier, actor_write_ceiling, actor_egress) = {
                let actor_repo = talos_actor_repository::ActorRepository::new(self.db_pool.clone());
                match actor_repo.resolve_effective_actor(user_id, None).await {
                    Ok(aid) => {
                        // #736: one joined SELECT, CLASSIFIED rather than
                        // collapsed. The parenthetical this comment used to
                        // carry — "egress override travels so an air-gapped
                        // actor stays air-gapped" — was FALSE on the fallback
                        // path it described: it passed `None` for egress, and
                        // `resolve_local_egress_only` reads
                        // `None => matches!(max_llm_tier, Tier1)`, so
                        // `(Tier2, _, None)` derives PUBLIC egress.
                        //
                        // Refusing is FREE on this path — the cheapest of the
                        // five. This is an operator-initiated
                        // `replayWebhookDeadLetterEntry`, and the caller stamps
                        // `replayed_at` only AFTER this returns `Ok`, so a
                        // refusal surfaces to the operator and leaves the entry
                        // replayable. Nothing is lost and nothing is granted.
                        let (tier, write_ceiling, egress) = actor_repo
                            .read_module_bound_ceilings(aid)
                            .await
                            .resolve_for(
                                aid,
                                talos_actor_repository::DispatchSite::WebhookDlqReplay,
                            )
                            .map_err(|refusal| {
                                anyhow::anyhow!("{refusal} (the entry remains replayable)")
                            })?;
                        (Some(aid), tier, write_ceiling, egress)
                    }
                    Err(e) => {
                        tracing::warn!(
                            %user_id, error = %e,
                            "DLQ replay: default-actor resolution failed; dispatching actor-less (Tier-2)"
                        );
                        (
                            None,
                            talos_workflow_job_protocol::LlmTier::default(),
                            talos_workflow_job_protocol::WriteCeiling::default(),
                            None,
                        )
                    }
                }
            };

            // Record the tracking row BEFORE dispatching, exactly as the live
            // path does and through the same helper. Without it every
            // `wasm.log.{job_id}` line from the replayed run is discarded by
            // the log router's `WHERE EXISTS` guard and the run never reaches a
            // terminal status — a 100%-deterministic orphan on the one path an
            // operator reaches for *because* they are debugging. Fail closed:
            // an untrackable replay is worse than a refused one, and the caller
            // (`replayWebhookDeadLetterEntry`) surfaces the error and leaves
            // `replayed_at` unset so the entry can be replayed again.
            insert_webhook_module_execution(
                &self.db_pool,
                &self.secrets_manager,
                job_id,
                module_id,
                user_id,
                &payload_value,
                resolved_actor,
            )
            .await
            .with_context(|| {
                format!("DLQ replay: failed to record module_execution row for job {job_id}")
            })?;

            tokio::spawn(async move {
                // Finalize the tracking row inserted above when this task bails
                // out before the worker ever sees the job.
                let fail_row = |reason: String| {
                    let svc = exec_service.clone();
                    async move {
                        if let Some(svc) = svc {
                            svc.fail_execution_best_effort(
                                job_id,
                                user_id,
                                reason,
                                Some("dlq_replay_dispatch".to_string()),
                            )
                            .await;
                        }
                    }
                };

                let exec_info = match registry.get_execution_info(module_id, user_id).await {
                    Ok(info) => info,
                    Err(e) => {
                        tracing::error!(
                            trigger_id = %trigger_id,
                            "DLQ replay: failed to load execution info: {}",
                            e
                        );
                        fail_row("DLQ replay: failed to load execution info".to_string()).await;
                        return;
                    }
                };

                // RFC 0010 P3 (M4): under claim-based sealing register the
                // plaintext for a worker claim; otherwise the inline WSK
                // envelope (L-1: AAD = job_id = workflow_execution_id). Same
                // helper both dispatch sites share, so they can't drift.
                let delivery = talos_integration_helpers::prepare_module_dispatch_secrets(
                    Some(&secrets_manager),
                    module_id,
                    user_id,
                    job_id,
                    sealing_handle.as_ref(),
                )
                .await;

                // Placeholder secret-delivery fields; `delivery.apply_to`
                // below writes all four in one drift-proof mapping.
                let mut req = talos_workflow_job_protocol::JobRequest {
                    crypto_scheme: 0,
                    sealing: 0,
                    secret_paths: Vec::new(),
                    claim_inbox: None,
                    job_id,
                    workflow_execution_id: job_id,
                    module_uri: exec_info.module_uri,
                    input_payload: wrapped_input.into(),
                    encrypted_secrets: talos_workflow_job_protocol::EncryptedSecrets::empty(),
                    timeout_ms: 3_000,
                    allowed_hosts: exec_info.allowed_hosts,
                    allowed_methods: exec_info.allowed_methods,
                    allowed_secrets: exec_info.allowed_secrets,
                    allowed_sql_operations: vec![],
                    allow_tier2_exposure: false,
                    priority: 100,
                    deadline_unix_secs: 0,
                    cancellation_token: None,
                    signature: vec![],
                    job_nonce: String::new(),
                    // Phase C: the resolved actor's tier travels with the
                    // re-dispatched job (Tier-2 default → non-breaking; the
                    // user's default actor at tier1 gives egress control).
                    max_llm_tier: actor_tier,
                    max_write_ceiling: actor_write_ceiling,
                    egress_scope: actor_egress,
                    wasm_bytes: None,
                    capability_world: None,
                    // MCP-1090: propagate integration_name (DLQ replay).
                    integration_name: exec_info.integration_name.clone(),
                    expected_wasm_hash: Some(exec_info.content_hash.clone()),
                    // MCP-1089: propagate per-module max_fuel (DLQ replay path).
                    max_fuel: exec_info.max_fuel,
                    dry_run: false,
                    reply_topic: None,
                    idempotency_key: None,
                    dispatch_attempt: 0,
                    actor_id: resolved_actor,
                    user_id,
                };
                delivery.apply_to(&mut req);

                // RFC 0010 P1: prefer the configured Ed25519 dispatch signer.
                let sign_result = match talos_workflow_job_protocol::configured_dispatch_signer() {
                    Some(signer) => Some(signer.sign_job(&mut req)),
                    None => worker_shared_key_clone
                        .as_ref()
                        .map(|key| req.sign(key.as_bytes())),
                };
                if let Some(Err(e)) = sign_result {
                    // RFC 0010 P3 (M4): reclaim the registered seal — dead dispatch.
                    if let Some(h) = &sealing_handle {
                        h.in_flight.discard(job_id);
                    }
                    tracing::error!(trigger_id = %trigger_id, "DLQ replay: sign failed: {}", e);
                    fail_row("DLQ replay: job signing failed".to_string()).await;
                    return;
                }

                let payload = match serde_json::to_vec(&req) {
                    Ok(p) => p,
                    Err(e) => {
                        if let Some(h) = &sealing_handle {
                            h.in_flight.discard(job_id);
                        }
                        tracing::error!(trigger_id = %trigger_id, "DLQ replay: serialize failed: {}", e);
                        fail_row("DLQ replay: job serialization failed".to_string()).await;
                        return;
                    }
                };

                // MCP-1065 (2026-05-15): canonical edge-routing resolver.
                let topic = if talos_config::edge_routing_enabled() {
                    talos_workflow_job_protocol::subjects::jobs_for(user_id)
                } else {
                    talos_workflow_job_protocol::subjects::JOBS.to_string()
                };

                if let Err(e) = nats.publish(topic, payload.into()).await {
                    // RFC 0010 P3 (M4): fire-and-forget publish failed — the
                    // worker never received the job, so reclaim the seal now
                    // (belt-and-braces with the TTL sweep).
                    if let Some(h) = &sealing_handle {
                        h.in_flight.discard(job_id);
                    }
                    tracing::error!(trigger_id = %trigger_id, "DLQ replay: NATS publish failed: {}", e);
                    fail_row("DLQ replay: NATS publish failed".to_string()).await;
                } else {
                    tracing::info!(trigger_id = %trigger_id, job_id = %job_id, "DLQ replay dispatched");
                }
            });
        } else {
            return Err(anyhow::anyhow!(
                "Trigger {} has no module or workflow associated",
                trigger_id
            ));
        }

        Ok(())
    }

    /// Clean up old webhook request logs (default retention: 90 days)
    /// MCP-997 (2026-05-15): refuse non-positive `retention_days`.
    /// Sibling caller-supplied-negative class as MCP-767/811/812 — a
    /// negative value would convert `NOW() - INTERVAL '1 day' * -N`
    /// into `NOW() + INTERVAL`, matching every row and purging the
    /// entire webhook request log table.
    pub async fn cleanup_request_logs(&self, retention_days: i64) -> Result<u64> {
        if retention_days <= 0 {
            tracing::warn!(
                target: "talos_audit",
                retention_days,
                "webhook-request-log cleanup refused: retention_days must be positive (would purge entire log)"
            );
            return Ok(0);
        }
        let result = sqlx::query(
            "DELETE FROM webhook_request_log WHERE created_at < NOW() - INTERVAL '1 day' * $1",
        )
        .bind(retention_days)
        .execute(&self.db_pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Clean up old dead-letter-queue rows (default retention: 90 days).
    ///
    /// `webhook_dlq` stores the (DLP-redacted) payload + headers of every
    /// request dropped by the circuit breaker or rate limiter, so a sustained
    /// flood against a known trigger — easy to trigger, no auth required —
    /// accumulates rows indefinitely without this sweep, an unbounded
    /// storage-exhaustion vector on the shared Postgres instance. The
    /// in-memory channel is bounded (backpressure-drops past
    /// `DLQ_CHANNEL_CAPACITY`), but flushed rows previously lived forever.
    /// Mirrors [`cleanup_request_logs`] — same non-positive-`retention_days`
    /// guard (MCP-997 caller-supplied-negative class: a negative value flips
    /// `NOW() - INTERVAL '1 day' * -N` into `NOW() + INTERVAL`, matching every
    /// row and purging the whole table).
    pub async fn cleanup_dlq(&self, retention_days: i64) -> Result<u64> {
        if retention_days <= 0 {
            tracing::warn!(
                target: "talos_audit",
                retention_days,
                "webhook-DLQ cleanup refused: retention_days must be positive (would purge the entire DLQ)"
            );
            return Ok(0);
        }
        let result =
            sqlx::query("DELETE FROM webhook_dlq WHERE created_at < NOW() - INTERVAL '1 day' * $1")
                .bind(retention_days)
                .execute(&self.db_pool)
                .await?;

        Ok(result.rows_affected())
    }
}

/// Axum handler for webhook requests
pub async fn webhook_handler(
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Path(trigger_id): Path<Uuid>,
    headers: HeaderMap,
    Extension(webhook_router): Extension<Arc<WebhookRouter>>,
    Extension(trusted_proxies): Extension<Arc<talos_rate_limit::TrustedProxies>>,
    body: Bytes,
) -> Response {
    // Use the canonical RFC 7239 §5.2 right-to-left XFF walk
    // (`rate_limit::extract_client_ip`). The previous leftmost read was
    // exploitable: a client behind a trusted proxy could prepend `X-Forwarded-For:
    // <preferred-ip>` and Traefik would append the real client to the right,
    // leaving `<preferred-ip>, real_client_ip` in the header. Reading leftmost
    // would let the attacker spoof their `source_ip` for both rate-limit
    // accounting and the per-trigger `allowed_ips` allowlist gate.
    //
    // The right-to-left walk skips trusted-proxy entries from the right and
    // returns the first non-trusted entry — the actual original client.
    let direct_ip = addr.ip();
    let source_ip = Some(talos_rate_limit::extract_client_ip(
        direct_ip,
        &headers,
        &trusted_proxies,
    ));

    match webhook_router
        .handle_webhook(trigger_id, &headers, body, source_ip)
        .await
    {
        Ok(response) => response,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("not found") {
                (StatusCode::NOT_FOUND, "Webhook not found").into_response()
            } else if msg.contains("rate limit") || msg.contains("Rate limit") {
                (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded").into_response()
            } else if msg.contains("IP") || msg.contains("not allowed") {
                (StatusCode::FORBIDDEN, "Forbidden").into_response()
            } else {
                tracing::error!(
                    trigger_id = %trigger_id,
                    error = %e,
                    "Webhook handler error"
                );
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
            }
        }
    }
}
