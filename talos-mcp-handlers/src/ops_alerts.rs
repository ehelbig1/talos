//! Ops-alerts triage surface — the operator side of the alert-triage
//! pipeline (`ops_alerts` domain; ingest happens via the `__ops_alert__`
//! engine hook, never through this surface).
//!
//! Thin handlers per the architectural mandate: parse/validate →
//! `talos_ops_alerts_repository::OpsAlertRepository` → format. The one
//! semantically-loaded tool is `correct_ops_alert_severity`: human
//! corrections are the distillation gold set (they outrank classifier
//! labels and survive dedup bumps), mirroring the inbox-organizer
//! correction→few-shot loop.

use super::types::JsonRpcResponse;
use super::utils::{mcp_error, mcp_text};
use super::{auth, McpState};
use std::sync::Arc;
use talos_ops_alerts_repository::{OpsAlertFilter, OpsAlertRepository, ASSIGNABLE_SEVERITIES};
use uuid::Uuid;

pub fn tool_schemas() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "name": "list_ops_alerts",
            "description": "List normalized operational alerts (Snyk/AWS-Health/ServiceNow email alerts, GCP Monitoring, webhooks) ingested via the __ops_alert__ pipeline. Defaults to active (non-resolved) alerts, newest activity first.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "status": { "type": "string", "enum": ["new", "acked", "resolved"], "description": "Filter by lifecycle status (omit for all)" },
                    "severity": { "type": "string", "enum": ["critical", "high", "medium", "low", "info", "noise", "unclassified"], "description": "Filter by triaged severity" },
                    "source": { "type": "string", "description": "Filter by source label (e.g. 'snyk-email')" },
                    "since_hours": { "type": "number", "description": "Only alerts with activity in the last N hours (max 720)" },
                    "limit": { "type": "number", "description": "Max rows (default 50, max 200)" }
                }
            }
        }),
        serde_json::json!({
            "name": "set_ops_alert_status",
            "description": "Advance an ops-alert through its lifecycle: 'acked' (only from new) or 'resolved' (from new/acked). A re-fired resolved alert automatically reopens to new.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "alert_id": { "type": "string", "description": "UUID of the alert" },
                    "status": { "type": "string", "enum": ["acked", "resolved"] }
                },
                "required": ["alert_id", "status"]
            }
        }),
        serde_json::json!({
            "name": "correct_ops_alert_severity",
            "description": "Record a HUMAN severity correction on an ops-alert. Corrections are the triage gold signal: they overwrite classifier labels, are never overwritten by future classifier runs, and survive dedup bumps — they feed the classifier's few-shot/distillation loop.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "alert_id": { "type": "string", "description": "UUID of the alert" },
                    "severity": { "type": "string", "enum": ["critical", "high", "medium", "low", "info", "noise"] }
                },
                "required": ["alert_id", "severity"]
            }
        }),
        serde_json::json!({
            "name": "get_ops_alerts_digest",
            "description": "Rollup of the active ops-alert set: counts by severity and source, new-in-last-24h, and reopened (re-fired after resolve) counts. Feed for the morning dispatch.",
            "inputSchema": { "type": "object", "properties": {} }
        }),
        serde_json::json!({
            "name": "cleanup_ops_alerts",
            "description": "Delete RESOLVED ops-alerts older than a threshold (housekeeping; active alerts are never touched).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "older_than_days": { "type": "number", "description": "Delete resolved alerts older than this many days (default 30, min 7)" }
                }
            }
        }),
    ]
}

pub async fn dispatch(
    name: &str,
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> Option<JsonRpcResponse> {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    match name {
        "list_ops_alerts" => Some(handle_list(req_id, args, state, user_id).await),
        "set_ops_alert_status" => Some(handle_set_status(req_id, args, state, user_id).await),
        "correct_ops_alert_severity" => Some(handle_correct(req_id, args, state, user_id).await),
        "get_ops_alerts_digest" => Some(handle_digest(req_id, state, user_id).await),
        "cleanup_ops_alerts" => Some(handle_cleanup(req_id, args, state, user_id).await),
        _ => None,
    }
}

fn repo(state: &McpState) -> OpsAlertRepository {
    OpsAlertRepository::new(state.db_pool.clone())
}

fn parse_alert_id(
    args: &serde_json::Value,
    req_id: &Option<serde_json::Value>,
) -> Result<Uuid, JsonRpcResponse> {
    args.get("alert_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| {
            mcp_error(
                req_id.clone(),
                -32602,
                "Missing or invalid required field: alert_id (UUID)",
            )
        })
}

async fn handle_list(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let limit = match crate::utils::validate_range_i64(args, "limit", 1, 200, 50, &req_id) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let since_hours =
        match crate::utils::validate_range_i64(args, "since_hours", 1, 720, 720, &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    // `since` only constrains when the caller supplied it explicitly.
    let since = args
        .get("since_hours")
        .is_some()
        .then(|| chrono::Utc::now() - chrono::Duration::hours(since_hours));
    let opt_str = |k: &str| {
        args.get(k)
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    let filter = OpsAlertFilter {
        status: opt_str("status"),
        severity: opt_str("severity"),
        source: opt_str("source"),
        since,
        limit: Some(limit),
    };
    match repo(state).list(user_id, filter).await {
        Ok(rows) => {
            let alerts: Vec<serde_json::Value> = rows
                .iter()
                .map(|a| {
                    serde_json::json!({
                        "id": a.id,
                        "source": a.source,
                        "external_id": a.external_id,
                        "title": a.title,
                        "resource": a.resource,
                        "severity": a.severity,
                        "severity_raw": a.severity_raw,
                        "triage_source": a.triage_source,
                        "triage_confidence": a.triage_confidence,
                        "corrected": a.corrected_severity.is_some(),
                        "status": a.status,
                        "occurrence_count": a.occurrence_count,
                        "first_seen": a.first_seen.to_rfc3339(),
                        "last_seen": a.last_seen.to_rfc3339(),
                        "reopened_at": a.reopened_at.map(|t| t.to_rfc3339()),
                    })
                })
                .collect();
            mcp_text(
                req_id,
                &serde_json::json!({ "count": alerts.len(), "alerts": alerts }).to_string(),
            )
        }
        Err(e) => {
            tracing::error!("list_ops_alerts failed: {:#}", e);
            crate::utils::database_error(req_id)
        }
    }
}

async fn handle_set_status(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let alert_id = match parse_alert_id(args, &req_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let status = args.get("status").and_then(|v| v.as_str()).unwrap_or("");
    let result = match status {
        "acked" => repo(state).ack(user_id, alert_id).await,
        "resolved" => repo(state).resolve(user_id, alert_id).await,
        other => {
            return mcp_error(
                req_id,
                -32602,
                &format!("Invalid status '{other}' — expected 'acked' or 'resolved'"),
            )
        }
    };
    match result {
        Ok(true) => mcp_text(
            req_id,
            &serde_json::json!({ "alert_id": alert_id, "status": status }).to_string(),
        ),
        Ok(false) => mcp_error(
            req_id,
            -32000,
            "Alert not found, not yours, or not in a state that allows this transition \
             (acked requires 'new'; resolved requires 'new' or 'acked')",
        ),
        Err(e) => {
            tracing::error!("set_ops_alert_status failed: {:#}", e);
            crate::utils::database_error(req_id)
        }
    }
}

async fn handle_correct(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let alert_id = match parse_alert_id(args, &req_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let severity = args.get("severity").and_then(|v| v.as_str()).unwrap_or("");
    if talos_ops_alerts_repository::validate_severity(severity).is_err() {
        return mcp_error(
            req_id,
            -32602,
            &format!("Invalid severity '{severity}' — expected one of {ASSIGNABLE_SEVERITIES:?}"),
        );
    }
    match repo(state)
        .correct_severity(user_id, alert_id, severity)
        .await
    {
        Ok(true) => mcp_text(
            req_id,
            &serde_json::json!({
                "alert_id": alert_id,
                "severity": severity,
                "corrected": true,
                "note": "Correction recorded — outranks classifier labels and survives dedup bumps."
            })
            .to_string(),
        ),
        Ok(false) => mcp_error(req_id, -32000, "Alert not found or not yours"),
        Err(e) => {
            tracing::error!("correct_ops_alert_severity failed: {:#}", e);
            crate::utils::database_error(req_id)
        }
    }
}

async fn handle_digest(
    req_id: Option<serde_json::Value>,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    match repo(state).digest(user_id).await {
        Ok(d) => mcp_text(
            req_id,
            &serde_json::json!({
                "active_by_severity": d.active_by_severity
                    .iter().map(|(s, n)| serde_json::json!({"severity": s, "count": n})).collect::<Vec<_>>(),
                "active_by_source": d.active_by_source
                    .iter().map(|(s, n)| serde_json::json!({"source": s, "count": n})).collect::<Vec<_>>(),
                "new_last_24h": d.new_last_24h,
                "reopened_active": d.reopened_active,
            })
            .to_string(),
        ),
        Err(e) => {
            tracing::error!("get_ops_alerts_digest failed: {:#}", e);
            crate::utils::database_error(req_id)
        }
    }
}

async fn handle_cleanup(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // Min 7 mirrors cleanup_old_alerts: a small-but-positive floor so a
    // typo can't purge yesterday's audit trail (MCP-997 class).
    let days = match crate::utils::validate_range_i64(args, "older_than_days", 7, 3650, 30, &req_id)
    {
        Ok(v) => v as i32,
        Err(resp) => return resp,
    };
    match repo(state).delete_resolved_older_than(user_id, days).await {
        Ok(n) => mcp_text(
            req_id,
            &serde_json::json!({ "deleted": n, "older_than_days": days }).to_string(),
        ),
        Err(e) => {
            tracing::error!("cleanup_ops_alerts failed: {:#}", e);
            crate::utils::database_error(req_id)
        }
    }
}
