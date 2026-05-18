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

/// MCP-1112 (2026-05-16): cache the hardened failure-webhook HTTP
/// client at module scope so `dispatch_failure_webhook` doesn't
/// rebuild it per call. Sibling sweep of MCP-1110 (talos-search-
/// service) and MCP-1111 (talos-memory) — third copy of the
/// per-call `Client::builder().build()` anti-pattern.
///
/// Hot path: fires on EVERY workflow execution failure. In a
/// degraded state (provider outage, mis-deployed module, network
/// partition) failure rates spike — the prior code rebuilt the
/// full TLS context + per-call connection pool on every fire,
/// guaranteeing zero keep-alive reuse to the operator-facing
/// alert target (PagerDuty / Slack webhook / Opsgenie / internal
/// incident-mgmt API). Each fresh handshake adds ~50-200ms of
/// connect latency PLUS amplifies provider-side rate-limit
/// accounting (fresh connections count harder than warm pool
/// reuse on most provider tiers — exactly when the operator is
/// most acutely waiting for the alert).
///
/// MCP-469 redirect=none preserved exactly — the SSRF gate at
/// `check_outbound_url_no_ssrf` covers the literal URL but a 302
/// from a validated host to an internal IP would pivot beneath
/// the gate without `.redirect(Policy::none())`. MCP-1034 explicit
/// connect_timeout(2s) preserved so a black-holed endpoint fails
/// fast on TCP-handshake instead of burning the full 5s budget.
///
/// `.expect()` on TLS-init failure matches the sibling MCP-1110/
/// 1111 pattern — TLS init failing is a deployment issue (broken
/// system roots / OS misconfiguration), not a request-time
/// recoverable error. Pre-fix `Err(e) => log+return` silently
/// dropped EVERY failure webhook for the pod's lifetime with no
/// signal to operators that alerting itself was broken; loud
/// first-call panic is the better failure mode.
static FAILURE_WEBHOOK_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(WEBHOOK_TIMEOUT)
        .connect_timeout(Duration::from_secs(2))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("talos-execution-orchestration: failed to build failure-webhook HTTP client (TLS init)")
});

pub(crate) async fn dispatch_failure_webhook(
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
        _ => return,
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
    // MCP-1112: shared once-built client (see FAILURE_WEBHOOK_CLIENT
    // module-scope LazyLock above). One TLS context + one
    // connection pool process-wide. MCP-469 redirect=none policy
    // and MCP-1034 explicit connect_timeout preserved in the
    // builder up there.
    let client: &reqwest::Client = &FAILURE_WEBHOOK_CLIENT;
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
