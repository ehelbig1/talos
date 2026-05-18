use super::types::JsonRpcResponse;
use super::utils::{mcp_error, mcp_text};
use super::{auth, McpState};
use std::sync::Arc;
use uuid::Uuid;

pub fn tool_schemas() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "name": "list_alerts",
            "description": "List workflow failure alerts. By default shows only unacknowledged alerts.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "acknowledged": { "type": "boolean", "description": "Filter by acknowledged status (default: false = unacked only)" },
                    "limit": { "type": "number", "description": "Maximum number of alerts to return (default: 20, max: 100)" }
                },
            }
        }),
        serde_json::json!({
            "name": "acknowledge_alert",
            "description": "Acknowledge (dismiss) a single workflow alert by ID.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "alert_id": { "type": "string", "description": "UUID of the alert to acknowledge" }
                },
                "required": ["alert_id"]
            }
        }),
        serde_json::json!({
            "name": "acknowledge_all_alerts",
            "description": "Acknowledge all unacknowledged workflow alerts for the current user.",
            "inputSchema": {
                "type": "object",
                "properties": {},
            }
        }),
        serde_json::json!({
            "name": "get_recent_alerts_summary",
            "description": "Quick overview of recent workflow alerts. Returns both literal alerts and a fingerprint-grouped 'groups' rollup that collapses near-duplicate messages (UUIDs/timestamps/numeric tails/long quoted strings normalized).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "hours": { "type": "number", "description": "Look back this many hours (default: 24, max: 168)" }
                },
            }
        }),
        serde_json::json!({
            "name": "cleanup_old_alerts",
            "description": "Delete acknowledged alerts older than a threshold. Housekeeping for the workflow_alerts table.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "older_than_days": { "type": "number", "description": "Delete acknowledged alerts older than this many days (default: 30, min: 7)" }
                },
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
        "list_alerts" => Some(handle_list_alerts(req_id, args, state, user_id).await),
        "acknowledge_alert" => Some(handle_acknowledge_alert(req_id, args, state, user_id).await),
        "acknowledge_all_alerts" => {
            Some(handle_acknowledge_all_alerts(req_id, state, user_id).await)
        }
        "get_recent_alerts_summary" => {
            Some(handle_get_recent_alerts_summary(req_id, args, state, user_id).await)
        }
        "cleanup_old_alerts" => Some(handle_cleanup_old_alerts(req_id, args, state, user_id).await),
        _ => None,
    }
}

async fn handle_list_alerts(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // MCP-245 (2026-05-08): pre-fix `acknowledged: "yes"` (string)
    // silently became `false` via the as_bool-then-unwrap_or chain —
    // a real probe got back the unacked-only list with no signal that
    // the filter was malformed. Confirmed by probe. Same MCP-189 /
    // MCP-229 family. Use validate_optional_bool which rejects
    // wrong-type loudly.
    let acknowledged = match crate::utils::validate_optional_bool(args, "acknowledged", false, &req_id) {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    let limit = match crate::utils::validate_range_i64(args, "limit", 1, 100, 20, &req_id) {
        Ok(v) => v as i32,
        Err(resp) => return resp,
    };

    match state
        .analytics_repo
        .list_alerts_for_user(user_id, acknowledged, limit)
        .await
    {
        Ok(rows) => {
            // MCP-40 (2026-05-07): surface execution_archived so
            // operators can tell which alerts have dead execution_id
            // pointers (FK target archived). Pre-fix the alerts list
            // continued to surface old execution_ids that
            // get_execution_status would 404 on, with no signal at the
            // alert layer. The flag lets dashboards filter or
            // bulk-acknowledge orphan alerts.
            let alerts: Vec<serde_json::Value> = rows
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "id": r.id,
                        "workflow_id": r.workflow_id,
                        "workflow_name": r.workflow_name,
                        "execution_id": r.execution_id,
                        "execution_archived": r.execution_archived,
                        "alert_type": r.alert_type,
                        "message": r.message,
                        "created_at": r.created_at.to_rfc3339(),
                        "occurrence_count": r.occurrence_count,
                        "last_occurred_at": r.last_occurred_at.to_rfc3339(),
                    })
                })
                .collect();
            // MCP-45 (2026-05-07): emit a structured envelope so this
            // surface matches list_approval_gates / list_workflow_suspensions
            // / list_actors etc. Pre-fix this returned a bare array which
            // forced operators to type-test before .length / .filter calls.
            //
            // MCP-78 (2026-05-07): reuse build_fingerprint_groups so the
            // operator audit experience is consistent with
            // get_recent_alerts_summary. WorkflowAlertRow projects cleanly
            // onto RecentAlertSummaryRow for the fingerprint pass.
            let summary_rows: Vec<talos_analytics_repository::RecentAlertSummaryRow> = rows
                .iter()
                .map(|r| talos_analytics_repository::RecentAlertSummaryRow {
                    workflow_name: r.workflow_name.clone(),
                    message: r.message.clone(),
                    occurrence_count: r.occurrence_count,
                    last_occurred_at: r.last_occurred_at,
                    acknowledged,
                })
                .collect();
            let groups = build_fingerprint_groups(&summary_rows);
            let envelope = serde_json::json!({
                "count": alerts.len(),
                "alerts": alerts,
                "groups": groups,
                "groups_note": "Alerts collapsed by fingerprint (UUIDs, timestamps, numeric tails, and long quoted strings normalized). Use 'alerts' for literal messages.",
            });
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&envelope).unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("list_alerts query failed: {:#}", e);
            mcp_error(req_id, -32000, "Failed to list alerts")
        }
    }
}

async fn handle_acknowledge_alert(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let alert_id: uuid::Uuid = match args
        .get("alert_id")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
    {
        Some(id) => id,
        None => {
            return mcp_error(
                req_id,
                -32602,
                "Invalid or missing 'alert_id' (must be a UUID)",
            )
        }
    };

    use talos_analytics_repository::AckOutcome;
    // N-M (2026-05-06): surface fresh-vs-no-op so callers can tell
    // whether their action did anything. Pre-fix, repeating an ack
    // returned the same "Alert X acknowledged" message as a fresh ack.
    match state
        .analytics_repo
        .acknowledge_alert(alert_id, user_id)
        .await
    {
        Ok(AckOutcome::Acknowledged) => mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "alert_id": alert_id,
                "acknowledged": true,
                "was_already_acknowledged": false,
                "message": format!("Alert {} acknowledged.", alert_id),
            }))
            .unwrap_or_default(),
        ),
        Ok(AckOutcome::AlreadyAcknowledged) => mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "alert_id": alert_id,
                "acknowledged": true,
                "was_already_acknowledged": true,
                "message": format!("Alert {} was already acknowledged — no state change.", alert_id),
            }))
            .unwrap_or_default(),
        ),
        Ok(AckOutcome::NotFound) => {
            mcp_error(req_id, -32000, "Alert not found or access denied")
        }
        Err(e) => {
            tracing::error!("acknowledge_alert failed: {:#}", e);
            mcp_error(req_id, -32000, "Failed to acknowledge alert")
        }
    }
}

async fn handle_acknowledge_all_alerts(
    req_id: Option<serde_json::Value>,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    match state.analytics_repo.acknowledge_all_alerts(user_id).await {
        Ok(rows) => mcp_text(req_id, &format!("{} alert(s) acknowledged.", rows)),
        Err(e) => {
            tracing::error!("acknowledge_all_alerts failed: {:#}", e);
            mcp_error(req_id, -32000, "Failed to acknowledge alerts")
        }
    }
}

async fn handle_get_recent_alerts_summary(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let hours: f64 =
        match crate::utils::validate_range_f64(args, "hours", 1.0, 168.0, 24.0, &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    let hours_i32 = hours as i32;

    match state
        .analytics_repo
        .list_recent_alerts_summary(user_id, hours_i32)
        .await
    {
        Ok(rows) => {
            let alerts: Vec<serde_json::Value> = rows
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "workflow_name": r.workflow_name,
                        "message": r.message,
                        "occurrence_count": r.occurrence_count,
                        "last_occurred_at": r.last_occurred_at.to_rfc3339(),
                        "acknowledged": r.acknowledged,
                    })
                })
                .collect();

            // MCP-7: fingerprint-grouped rollup. Operators auditing recent
            // alerts saw near-duplicate noise (e.g. one-character differences
            // inside a quoted prose preview). Reusing `fingerprint_error_message`
            // — the same helper used by `get_workflow_stats` and
            // `get_error_report` — collapses the literal differences while
            // preserving every literal alert in the `alerts` array above.
            let groups = build_fingerprint_groups(&rows);

            let result = serde_json::json!({
                "hours": hours_i32,
                "count": alerts.len(),
                "alert_count": alerts.len(),
                "alerts": alerts,
                "groups": groups,
                "groups_note": "Alerts collapsed by fingerprint (UUIDs, timestamps, numeric tails, and long quoted strings normalized). Use 'alerts' for literal messages.",
            });
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&result).unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("get_recent_alerts_summary query failed: {:#}", e);
            mcp_error(req_id, -32000, "Failed to query alerts summary")
        }
    }
}

/// MCP-7: collapse alert messages by `fingerprint_error_message` so that
/// near-duplicates (e.g. `"untrusted data"` vs `"untrusted_data"` inside
/// a quoted prose preview) roll up into one group with summed occurrence
/// counts. Iteration order is the input order, so the most-recent alert
/// in a fingerprint determines `first_message` (the canonical literal we
/// surface alongside the normalized fingerprint).
fn build_fingerprint_groups(
    rows: &[talos_analytics_repository::RecentAlertSummaryRow],
) -> Vec<serde_json::Value> {
    use std::collections::HashMap;
    struct GroupAcc {
        fingerprint: String,
        first_message: String,
        workflow_names: std::collections::BTreeSet<String>,
        occurrence_count: i64,
        alert_count: i64,
        last_occurred_at: chrono::DateTime<chrono::Utc>,
        acknowledged_count: i64,
    }
    let mut groups: HashMap<String, GroupAcc> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    for r in rows {
        let fp = talos_analytics_repository::fingerprint_error_message(&r.message);
        let entry = groups.entry(fp.clone()).or_insert_with(|| {
            order.push(fp.clone());
            GroupAcc {
                fingerprint: fp.clone(),
                first_message: r.message.clone(),
                workflow_names: std::collections::BTreeSet::new(),
                occurrence_count: 0,
                alert_count: 0,
                last_occurred_at: r.last_occurred_at,
                acknowledged_count: 0,
            }
        });
        entry.workflow_names.insert(r.workflow_name.clone());
        entry.occurrence_count += r.occurrence_count as i64;
        entry.alert_count += 1;
        if r.last_occurred_at > entry.last_occurred_at {
            entry.last_occurred_at = r.last_occurred_at;
        }
        if r.acknowledged {
            entry.acknowledged_count += 1;
        }
    }
    let mut out: Vec<serde_json::Value> = order
        .into_iter()
        .map(|fp| {
            let g = groups.remove(&fp).expect("present by construction");
            serde_json::json!({
                "fingerprint": g.fingerprint,
                "first_message": g.first_message,
                "workflow_names": g.workflow_names.into_iter().collect::<Vec<_>>(),
                "alert_count": g.alert_count,
                "occurrence_count": g.occurrence_count,
                "last_occurred_at": g.last_occurred_at.to_rfc3339(),
                "fully_acknowledged": g.acknowledged_count == g.alert_count,
            })
        })
        .collect();
    // Most-impactful first (sum of occurrences across the group).
    out.sort_by(|a, b| {
        b.get("occurrence_count")
            .and_then(|v| v.as_i64())
            .unwrap_or(0)
            .cmp(&a.get("occurrence_count").and_then(|v| v.as_i64()).unwrap_or(0))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::build_fingerprint_groups;
    use chrono::{TimeZone, Utc};
    use talos_analytics_repository::RecentAlertSummaryRow;

    fn row(workflow: &str, message: &str, occ: i32, acked: bool, secs_ago: i64) -> RecentAlertSummaryRow {
        RecentAlertSummaryRow {
            workflow_name: workflow.to_string(),
            message: message.to_string(),
            occurrence_count: occ,
            last_occurred_at: Utc.timestamp_opt(1_700_000_000 - secs_ago, 0).unwrap(),
            acknowledged: acked,
        }
    }

    #[test]
    fn collapses_fingerprint_dupes() {
        // The fingerprint regex normalizes quoted strings of 16+ chars to
        // <QUOTED>, so two messages whose only difference is inside a long
        // quoted preview collapse to the same fingerprint.
        let rows = vec![
            row(
                "alpha",
                "OUTPUT_SCHEMA rejected: \"the model returned untrusted data not in allowlist\"",
                3,
                false,
                100,
            ),
            row(
                "alpha",
                "OUTPUT_SCHEMA rejected: \"the model returned untrusted_data not in allowlist\"",
                5,
                false,
                50,
            ),
            row(
                "beta",
                "execution 11111111-2222-3333-4444-555555555555 failed",
                1,
                true,
                0,
            ),
        ];
        let groups = build_fingerprint_groups(&rows);
        assert_eq!(
            groups.len(),
            2,
            "the two near-identical schema rejections collapse"
        );
        let top = &groups[0];
        assert_eq!(top["alert_count"].as_i64().unwrap(), 2);
        assert_eq!(top["occurrence_count"].as_i64().unwrap(), 8);
        assert_eq!(top["fully_acknowledged"].as_bool().unwrap(), false);
    }

    #[test]
    fn fully_acknowledged_only_when_every_alert_acked() {
        let rows = vec![
            row("alpha", "timeout after 30", 1, true, 0),
            row("alpha", "timeout after 60", 1, false, 5),
        ];
        let groups = build_fingerprint_groups(&rows);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0]["fully_acknowledged"].as_bool().unwrap(), false);

        let rows_all_acked = vec![
            row("alpha", "timeout after 30", 1, true, 0),
            row("alpha", "timeout after 60", 1, true, 5),
        ];
        let groups_all = build_fingerprint_groups(&rows_all_acked);
        assert_eq!(groups_all[0]["fully_acknowledged"].as_bool().unwrap(), true);
    }

    #[test]
    fn distinct_workflow_names_aggregate() {
        let rows = vec![
            row("alpha", "execution aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee failed", 1, false, 0),
            row("beta", "execution 11111111-2222-3333-4444-555555555555 failed", 2, false, 5),
        ];
        let groups = build_fingerprint_groups(&rows);
        assert_eq!(groups.len(), 1);
        let names: Vec<String> = groups[0]["workflow_names"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert_eq!(names, vec!["alpha", "beta"]);
        assert_eq!(groups[0]["occurrence_count"].as_i64().unwrap(), 3);
    }

    #[test]
    fn empty_input_returns_empty() {
        let rows: Vec<RecentAlertSummaryRow> = vec![];
        assert!(build_fingerprint_groups(&rows).is_empty());
    }

    #[test]
    fn sort_is_by_total_occurrence_desc() {
        let rows = vec![
            row("alpha", "msg one", 1, false, 0),
            row("beta", "msg two", 5, false, 5),
            row("gamma", "msg three", 3, false, 10),
        ];
        let groups = build_fingerprint_groups(&rows);
        let counts: Vec<i64> = groups
            .iter()
            .map(|g| g["occurrence_count"].as_i64().unwrap())
            .collect();
        assert_eq!(counts, vec![5, 3, 1]);
    }
}

async fn handle_cleanup_old_alerts(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // MCP-176 (2026-05-08): replace silent-clamp with explicit range
    // validation. Pre-fix `unwrap_or(30).max(7)` silently rewrote
    // -1 → 7 and 3 → 7 with no warning to the caller. Operator could
    // not tell whether the value they passed was honoured. Same
    // pattern as MCP-160 (add_loop_node max_iterations).
    let older_than_days =
        match crate::utils::validate_range_i64(args, "older_than_days", 7, 365, 30, &req_id) {
            Ok(v) => v as i32,
            Err(resp) => return resp,
        };

    let deleted = state
        .analytics_repo
        .cleanup_old_alerts(user_id, older_than_days)
        .await;

    match deleted {
        Ok(count) => {
            let result = serde_json::json!({
                "deleted_count": count,
                "older_than_days": older_than_days,
            });
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&result).unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("cleanup_old_alerts query failed: {}", e);
            mcp_error(req_id, -32000, "Failed to cleanup alerts")
        }
    }
}
