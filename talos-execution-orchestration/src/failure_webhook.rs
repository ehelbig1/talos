//! Workflow-failure webhook dispatch.
//!
//! Fires the URL stored on the workflow row when an execution fails.
//! Re-validates the URL against the SSRF allowlist at fire time —
//! write-time validation isn't sufficient because rule changes
//! (e.g. r285's non-canonical-IPv4 rejection) need to apply
//! retroactively to URLs stored before the rule change.
//!
//! Best-effort: failures (network, SSRF, timeout) are logged but
//! never propagate to the caller. The execution row is already
//! marked failed by the time this is called; webhook delivery is
//! supplementary alerting.

use std::sync::LazyLock;
use std::time::Duration;
use uuid::Uuid;

use talos_http_utils::ssrf::check_outbound_url_no_ssrf;
use talos_workflow_repository::WorkflowRepository;

const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(5);

/// ONE hardened failure-webhook client per process (MCP-1112: the per-call
/// build discarded keep-alive exactly when failures spike). Built via the
/// shared SSRF-safe builder: redirect(none) (MCP-469) + the connect-time
/// `ControllerSsrfResolver`, which closes the DNS-rebinding TOCTOU the
/// fire-time `check_outbound_url_no_ssrf` cannot — the URL is user-supplied.
///
/// `None` when TLS init failed: every fire then logs an ERROR naming it. This
/// dispatcher runs inside detached tasks (the trigger path and MCP
/// `call_workflow`), where a first-use panic would lose the task's result
/// rather than surface the broken alerting any louder.
static FAILURE_WEBHOOK_CLIENT: LazyLock<Option<reqwest::Client>> = LazyLock::new(|| {
    talos_http_utils::outbound::build_outbound_webhook_client_with_timeout(
        "talos-failure-webhook/1.0",
        WEBHOOK_TIMEOUT,
    )
    .map_err(|e| tracing::error!(error = %e, "failure-webhook HTTP client build failed"))
    .ok()
});

/// Fire the workflow's stored failure webhook for `execution_id`: fire-time
/// SSRF re-validation, the shared SSRF-safe client, never an error to the
/// caller. `pub` so other crates reuse this one dispatcher instead of a copy.
pub async fn dispatch_failure_webhook(
    workflow_repo: &WorkflowRepository,
    workflow_id: Uuid,
    execution_id: Uuid,
    error: &str,
) {
    let url = match workflow_repo
        .get_workflow_failure_webhook(workflow_id)
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => return,
        // A failed read is not "no webhook configured": say the operator
        // notification was skipped.
        Err(e) => {
            tracing::warn!(
                target: "talos_rpc",
                workflow_id = %workflow_id,
                execution_id = %execution_id,
                error = %e,
                "failure_webhook URL unreadable — operator notification skipped"
            );
            return;
        }
    };
    if check_outbound_url_no_ssrf(&url).is_err() {
        tracing::warn!(
            workflow_id = %workflow_id,
            "skipping failure webhook: stored URL failed SSRF validation"
        );
        return;
    }
    let alert_payload = serde_json::json!({
        "event": "workflow_failed",
        "workflow_id": workflow_id,
        "execution_id": execution_id,
        "error": error,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });
    let Some(client) = FAILURE_WEBHOOK_CLIENT.as_ref() else {
        tracing::error!(
            workflow_id = %workflow_id,
            execution_id = %execution_id,
            "failure_webhook HTTP client unavailable (TLS init failed) — operator notification undelivered"
        );
        return;
    };
    // MCP-742 (2026-05-13): log POST failures. The failure-webhook is
    // typically wired to operator alerting (PagerDuty, Slack,
    // incident-mgmt). Pre-fix `let _ = client.post(...).await`
    // discarded the result entirely; if the webhook URL was
    // unreachable (DNS / TLS / 5xx / network partition), workflow
    // failures went UNDELIVERED to the operator's notification
    // channel with zero signal in the controller logs that the
    // delivery itself failed. The operator would only notice when
    // monitoring graphs eventually flagged sustained failure rates.
    // Same MCP-733..741 operator-visibility class — WARN with
    // stable `target: "talos_rpc"` so dashboards can correlate
    // "failure-webhook delivery rate" with controller health.
    match client.post(&url).json(&alert_payload).send().await {
        Ok(resp) if resp.status().is_success() => {
            tracing::debug!(
                workflow_id = %workflow_id,
                status = resp.status().as_u16(),
                "failure_webhook delivered"
            );
        }
        Ok(resp) => {
            tracing::warn!(
                target: "talos_rpc",
                workflow_id = %workflow_id,
                execution_id = %execution_id,
                status = resp.status().as_u16(),
                "failure_webhook returned non-success status — operator notification may not have reached its destination"
            );
        }
        Err(e) => {
            tracing::warn!(
                target: "talos_rpc",
                workflow_id = %workflow_id,
                execution_id = %execution_id,
                error = %e,
                "failure_webhook POST failed — operator notification undelivered"
            );
        }
    }
}
