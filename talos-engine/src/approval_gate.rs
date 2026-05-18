//! Postgres-backed [`ApprovalGate`] adapter.
//!
//! Wraps the `execution_approvals` table + the HTTP notification
//! webhook fire-and-forget. The engine previously called the free
//! function `engine::parallel::check_or_request_approval` against a
//! raw `&sqlx::PgPool`; this adapter hides both the pool and the
//! table name behind the abstract trait.

use async_trait::async_trait;
use sqlx::{Pool, Postgres};
use std::sync::LazyLock;
use std::time::Duration;
use talos_workflow_engine_core::{ApprovalGate, ApprovalStatus, BoxError};
use uuid::Uuid;

/// MCP-1116 (2026-05-16): cache the approval-gate notification
/// webhook HTTP client at module scope so `check_or_request`
/// doesn't rebuild it per call. Fourth site in the MCP-1110/1111/
/// 1112 per-call-client sweep — same anti-pattern in adjacent
/// crate.
///
/// Hot path: fires on EVERY approval-gate creation that has a
/// `notification_webhook` configured. Approval-heavy workflows
/// (review queues, multi-step automation with manual gates,
/// bulk import flows) fan out many gate creations; pre-fix every
/// fire rebuilt the TLS context + connection pool, defeating
/// keep-alive reuse to the operator-facing alert target
/// (PagerDuty / Slack / OpsGenie / custom incident-mgmt API).
///
/// MCP-1058 timeout(10s) + connect_timeout(5s) preserved exactly.
/// MCP-469 redirect=none preserved — `check_outbound_url_no_ssrf`
/// gates the literal URL but a 30x from the validated host to an
/// internal IP would pivot beneath the gate without this policy.
///
/// `.expect()` on TLS-init failure matches the sibling MCP-1110/
/// 1111/1112 pattern. Pre-fix `Err(e) => warn+return` silently
/// dropped EVERY approval notification for the pod's lifetime on
/// TLS-init failure with no operator-visible signal that the
/// notification fire was broken; loud first-call panic is the
/// better failure mode for a deployment-time TLS issue.
static APPROVAL_WEBHOOK_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("talos-engine: failed to build approval-gate webhook HTTP client (TLS init)")
});

/// Default Talos impl backed by Postgres.
pub struct PostgresApprovalGate {
    pool: Pool<Postgres>,
}

impl PostgresApprovalGate {
    /// Build a gate bound to `pool`.
    #[must_use]
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

impl std::fmt::Debug for PostgresApprovalGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresApprovalGate")
            .field("pool", &self.pool)
            .finish()
    }
}

#[async_trait]
impl ApprovalGate for PostgresApprovalGate {
    async fn check_or_request(
        &self,
        execution_id: Uuid,
        node_id: Uuid,
        required_for: &[String],
        notification_webhook: Option<&str>,
    ) -> Result<ApprovalStatus, BoxError> {
        // Fast path: check for an existing approval.
        let status: Option<String> = sqlx::query_scalar(
            "SELECT status FROM execution_approvals \
             WHERE execution_id = $1 AND node_id = $2 \
             ORDER BY requested_at DESC LIMIT 1",
        )
        .bind(execution_id)
        .bind(node_id)
        .fetch_optional(&self.pool)
        .await?;

        match status.as_deref() {
            Some("approved") => return Ok(ApprovalStatus::Approved),
            Some("denied") => {
                return Ok(ApprovalStatus::Denied {
                    reason: format!("Execution denied: module {} approval was denied", node_id),
                })
            }
            Some("pending") => return Ok(ApprovalStatus::Pending),
            _ => { /* No record — create one */ }
        }

        // Insert a pending approval request (idempotent).
        // Uses execution_id in both workflow_id and execution_id slots
        // to match the pre-extraction behavior — the real workflow_id
        // is not always threaded through at this call site; mismatched
        // slots would break downstream approval queries that join on
        // (workflow_id, execution_id).
        let insert_result = sqlx::query(
            "INSERT INTO execution_approvals (workflow_id, execution_id, node_id, required_for) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT DO NOTHING",
        )
        .bind(execution_id)
        .bind(execution_id)
        .bind(node_id)
        .bind(required_for)
        .execute(&self.pool)
        .await?;

        tracing::info!(
            execution_id = %execution_id,
            node_id = %node_id,
            required_for = ?required_for,
            "Approval gate: created pending approval request",
        );

        // Fire NOTIFICATION_WEBHOOK on initial creation only
        // (rows_affected == 1 means we actually inserted; == 0 means
        // a concurrent request won the race). Best-effort spawn.
        //
        // SSRF re-validation at FIRE TIME (not just write time) — webhook
        // URLs persisted before SSRF rules tightened (r285 obfuscated-IPv4,
        // r287 webhook re-validation) bypass write-time gates otherwise.
        // `redirect::Policy::none()` blocks 30x to internal hosts: the
        // SSRF check covers the literal URL, redirects pivot beneath it.
        if insert_result.rows_affected() == 1 {
            if let Some(url) = notification_webhook {
                let url = url.to_string();
                if let Err(reason) = talos_http_utils::ssrf::check_outbound_url_no_ssrf(&url) {
                    tracing::warn!(
                        execution_id = %execution_id,
                        node_id = %node_id,
                        reason,
                        "Approval gate notification webhook URL rejected by SSRF guard; \
                         skipping fire (the approval is still recorded in DB)",
                    );
                } else {
                    let required_for_clone: Vec<String> = required_for.to_vec();
                    tokio::spawn(async move {
                        let payload = serde_json::json!({
                            "event": "approval_requested",
                            "execution_id": execution_id,
                            "node_id": node_id,
                            "required_for": required_for_clone,
                        });
                        // MCP-1116: shared once-built client (see
                        // APPROVAL_WEBHOOK_CLIENT module-scope LazyLock
                        // above). One TLS context + one connection
                        // pool process-wide; keep-alive stays warm
                        // across approval-gate fires. MCP-1058 timeout
                        // + connect_timeout and MCP-469 redirect=none
                        // preserved in the builder up there.
                        let client: &reqwest::Client = &APPROVAL_WEBHOOK_CLIENT;
                        // MCP-810 (2026-05-14): canonical 3-arm match.
                        // Pre-fix this fire only logged on Err — an
                        // operator-supplied approval webhook returning
                        // 4xx/5xx (PagerDuty rate-limit, Slack 503,
                        // OpsGenie 502, custom-app 401 on stale token)
                        // was silently swallowed. The approval IS still
                        // recorded in DB (the comment above documents
                        // this), so the operator can poll for it, but
                        // when an operator explicitly configures a
                        // notification webhook they expect to be paged —
                        // a silently-undelivered approval can stall a
                        // critical workflow for hours before someone
                        // notices the missing alert. Same misleading-
                        // success class as MCP-737/738/800/801/809.
                        // WARN+target talos_rpc so dashboards correlate
                        // delivery-failure rate to controller health.
                        match client.post(&url).json(&payload).send().await {
                            Ok(resp) if resp.status().is_success() => {
                                tracing::debug!(
                                    url = %url,
                                    status = resp.status().as_u16(),
                                    "Approval gate notification webhook delivered"
                                );
                            }
                            Ok(resp) => {
                                tracing::warn!(
                                    target: "talos_rpc",
                                    url = %url,
                                    status = resp.status().as_u16(),
                                    "Approval gate notification webhook returned non-success status — operator notification may not have reached its destination (approval is still recorded in DB)"
                                );
                            }
                            Err(e) => {
                                tracing::warn!(
                                    target: "talos_rpc",
                                    url = %url,
                                    error = %e,
                                    "Approval gate notification webhook POST failed — operator notification undelivered (approval is still recorded in DB)"
                                );
                            }
                        }
                    });
                }
            }
        }

        Ok(ApprovalStatus::Pending)
    }
}
