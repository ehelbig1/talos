use super::types::JsonRpcResponse;
use super::utils::{mcp_error, mcp_text};
use super::{auth, McpState};
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

/// Best-effort human description of a 5-field cron expression. Doesn't attempt
/// to handle every conceivable expression — just calls out the common shapes
/// so the response is self-evident for typical schedules. Falls back to the
/// raw expression for anything unusual; callers always have the cron string +
/// next_triggers preview to disambiguate.
fn describe_cron(expr: &str) -> String {
    let parts: Vec<&str> = expr.split_whitespace().collect();
    if parts.len() != 5 {
        return format!("Cron: {}", expr);
    }
    let (min, hour, dom, mon, dow) = (parts[0], parts[1], parts[2], parts[3], parts[4]);
    // Patterns we recognize; everything else falls back to the raw string.
    match (min, hour, dom, mon, dow) {
        ("*", "*", "*", "*", "*") => "Every minute".into(),
        ("*/5", "*", "*", "*", "*") => "Every 5 minutes".into(),
        ("*/10", "*", "*", "*", "*") => "Every 10 minutes".into(),
        ("*/15", "*", "*", "*", "*") => "Every 15 minutes".into(),
        ("*/30", "*", "*", "*", "*") => "Every 30 minutes".into(),
        ("0", "*", "*", "*", "*") => "At the top of every hour".into(),
        ("0", h, "*", "*", "*") if h.parse::<u8>().is_ok() => {
            format!("Daily at {:0>2}:00", h)
        }
        ("0", h, "*", "*", "1-5") if h.parse::<u8>().is_ok() => {
            format!("Weekdays (Mon-Fri) at {:0>2}:00", h)
        }
        ("0", h, "*", "*", "0,6") if h.parse::<u8>().is_ok() => {
            format!("Weekends (Sat & Sun) at {:0>2}:00", h)
        }
        ("0", h, "*", "*", "1") if h.parse::<u8>().is_ok() => {
            format!("Mondays at {:0>2}:00", h)
        }
        ("0", h, "1", "*", "*") if h.parse::<u8>().is_ok() => {
            format!("First day of every month at {:0>2}:00", h)
        }
        _ => format!("Cron: {}", expr),
    }
}

pub fn tool_schemas() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "name": "create_schedule",
            "description": "Create a cron schedule for a workflow. The workflow will be triggered automatically according to the cron expression. \
                CONSTRAINT: each workflow can have at most one schedule. If the workflow already has one, this call returns an error — call list_schedules + delete_schedule first to replace it.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to schedule" },
                    "cron_expression": { "type": "string", "description": "Cron expression (5 or 6 space-separated fields, e.g. '0 9 * * 1-5' for weekdays at 9am)" },
                    "timezone": { "type": "string", "description": "IANA timezone (default: UTC)" }
                },
                "required": ["workflow_id", "cron_expression"]
            }
        }),
        serde_json::json!({
            "name": "list_schedules",
            "description": "List all workflow schedules for the current user.",
            "inputSchema": {
                "type": "object",
                "properties": {},
            }
        }),
        serde_json::json!({
            "name": "pause_schedule",
            "description": "Pause an active workflow schedule.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "schedule_id": { "type": "string", "description": "UUID of the schedule to pause" }
                },
                "required": ["schedule_id"]
            }
        }),
        serde_json::json!({
            "name": "resume_schedule",
            "description": "Resume a paused workflow schedule.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "schedule_id": { "type": "string", "description": "UUID of the schedule to resume" }
                },
                "required": ["schedule_id"]
            }
        }),
        serde_json::json!({
            "name": "delete_schedule",
            "description": "Permanently delete a workflow schedule.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "schedule_id": { "type": "string", "description": "UUID of the schedule to delete" }
                },
                "required": ["schedule_id"]
            }
        }),
        serde_json::json!({
            "name": "get_schedule_next_runs",
            "description": "Show upcoming scheduled workflow executions sorted by next trigger time.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": { "type": "number", "description": "Max results (default: 10, max: 50)" }
                },
            }
        }),
        serde_json::json!({
            "name": "get_schedule_health",
            "description": "Get health and observability data for a scheduled workflow: schedule info, last 24h execution stats, current success/failure streak, and rolling success rate.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "schedule_id": { "type": "string", "description": "UUID of the workflow schedule" }
                },
                "required": ["schedule_id"]
            }
        }),
    ]
}

pub async fn dispatch(
    name: &str,
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> Option<JsonRpcResponse> {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    match name {
        "create_schedule" => Some(handle_create_schedule(req_id, args, state, user_id).await),
        "list_schedules" => Some(handle_list_schedules(req_id, args, state, user_id).await),
        "pause_schedule" => Some(handle_pause_schedule(req_id, args, state, user_id).await),
        "resume_schedule" => Some(handle_resume_schedule(req_id, args, state, user_id).await),
        "delete_schedule" => Some(handle_delete_schedule(req_id, args, state, user_id).await),
        "get_schedule_next_runs" => {
            Some(handle_get_schedule_next_runs(req_id, args, state, user_id).await)
        }
        "get_schedule_health" => {
            Some(handle_get_schedule_health(req_id, args, state, user_id).await)
        }
        _ => None,
    }
}

async fn handle_create_schedule(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let workflow_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    // MCP-414 (2026-05-11): bound + trim cron_expression at the
    // boundary. Pre-fix:
    //   (1) no length cap — a multi-MB string with 6 whitespace-
    //       separated tokens (1 huge token + 5 small) would pass the
    //       field-count gate and reach talos_scheduler::validate_cron
    //       which then has to parse the entire string before
    //       rejecting it. Same DoS-by-unbounded-input class as
    //       MCP-411 / MCP-413.
    //   (2) untrimmed — `cron_expression: "  * * * * *  "` (operator
    //       paste from a runbook) was persisted WITH the surrounding
    //       whitespace; downstream displays show ragged output and
    //       parse-on-load consumers may differ from validate_cron's
    //       tolerance. Trim at the boundary so the persisted value
    //       matches what every consumer sees.
    // 256 chars covers every legitimate cron expression — even
    // 6-field expressions with extended ranges and lists rarely
    // exceed 80 chars.
    let cron_expression = match args.get("cron_expression").and_then(|v| v.as_str()) {
        Some(c) if c.len() > 256 => {
            return mcp_error(
                req_id,
                -32602,
                "cron_expression must be ≤ 256 characters",
            )
        }
        Some(c) if !c.trim().is_empty() => c.trim().to_string(),
        _ => return mcp_error(req_id, -32602, "Missing or empty 'cron_expression'"),
    };
    // MCP-347 (2026-05-11): pre-fix `as_str().unwrap_or("UTC")`
    // collapsed wrong-type into UTC. An operator passing
    // `timezone: 7` (number) wanted some specific zone and silently
    // got UTC — the scheduled workflow then fired at the wrong local
    // time, off by up to 12 hours depending on the operator's actual
    // intent. The chrono-tz `parse()` below would catch invalid
    // STRINGS, but wrong-type bypassed it entirely. Same MCP-346
    // family applied to a scheduler-timing surface.
    let timezone =
        match crate::utils::validate_optional_string(args, "timezone", "UTC", None, &req_id) {
            Ok(s) => s,
            Err(resp) => return resp,
        };

    // Validate cron expression — parse with the same croner library the scheduler uses
    // so storage and execution agree on validity. Field-count pre-check is kept as a
    // fast first gate; parse validation catches semantic errors (invalid ranges, etc.).
    let field_count = cron_expression.split_whitespace().count();
    if !(5..=6).contains(&field_count) {
        return mcp_error(
            req_id,
            -32602,
            "Invalid cron expression: must have 5 or 6 space-separated fields",
        );
    }

    if let Err(e) = talos_scheduler::validate_cron(&cron_expression) {
        return mcp_error(req_id, -32602, &e);
    }

    // MCP-195 (2026-05-08): validate timezone against the IANA database
    // before persisting. Pre-fix the handler accepted any string
    // (e.g. "Mars/Olympus_Mons"), persisted the schedule, and
    // `calculate_next_trigger` returned None when the chrono_tz parse
    // failed — which the scheduler loop interprets as "never run". The
    // operator saw a success response but the schedule silently never
    // fired. The validate_timezone helper has lived in talos-scheduler
    // since the crate was extracted; this just calls it. Mirrors the
    // existing validate_cron call above.
    if let Err(e) = talos_scheduler::validate_timezone(&timezone) {
        return mcp_error(
            req_id,
            -32602,
            &format!(
                "{e}. Use an IANA timezone identifier like 'UTC', 'America/New_York', or 'Europe/London'."
            ),
        );
    }

    // Enforce a minimum schedule interval of 60 seconds (one trigger per minute at most).
    // This prevents resource exhaustion from expressions like `* * * * * *` (every second)
    // or `* * * * *` (every minute) across many workflows simultaneously.
    const MIN_INTERVAL_SECS: u64 = 60;
    if let Err(e) = talos_scheduler::validate_cron_min_interval(&cron_expression, MIN_INTERVAL_SECS)
    {
        return mcp_error(req_id, -32602, &e);
    }

    // Verify workflow ownership
    let wf_exists: bool = state
        .workflow_repo
        .workflow_exists(workflow_id, user_id)
        .await;

    if !wf_exists {
        return crate::utils::workflow_not_found_error(req_id);
    }

    // Compute next_trigger_at now so the scheduler loop picks this schedule up
    // on its first tick. Without this, the WHERE next_trigger_at IS NOT NULL filter
    // in the scheduler would silently ignore newly created schedules forever.
    let next_trigger_at = talos_scheduler::calculate_next_trigger(&cron_expression, &timezone).ok();

    let schedule_id = Uuid::new_v4();
    let sched_repo = talos_schedule_repo::ScheduleRepository::new(state.db_pool.clone());
    match sched_repo
        .create_schedule(
            schedule_id,
            workflow_id,
            user_id,
            &cron_expression,
            &timezone,
            next_trigger_at,
        )
        .await
    {
        Ok(_) => {
            // Compute the next 3 trigger times so the human caller can sanity-check
            // the schedule without having to mentally evaluate the cron string.
            let upcoming: Vec<String> =
                talos_scheduler::calculate_next_n_triggers(&cron_expression, &timezone, 3)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|t| t.to_rfc3339())
                    .collect();
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "schedule_id": schedule_id.to_string(),
                    "workflow_id": workflow_id.to_string(),
                    "cron_expression": cron_expression,
                    "cron_description": describe_cron(&cron_expression),
                    "timezone": timezone,
                    "enabled": true,
                    "next_trigger_at": next_trigger_at.map(|t: chrono::DateTime<chrono::Utc>| t.to_rfc3339()),
                    "upcoming_triggers": upcoming,
                }))
                .unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("create_schedule failed: {}", e);
            // Surface the most common 4xx-style error — the
            // `workflow_schedules_workflow_id_key` UNIQUE constraint means each
            // workflow can have at most one schedule. The DB error text is
            // operator-facing; the MCP response should tell the CALLER what to
            // do instead. Pattern-match on the sqlx error KIND (not the
            // message string) so Postgres-message-text changes don't regress
            // the branch.
            if let Some(db_err) = e.as_database_error() {
                if db_err.is_unique_violation() {
                    return mcp_error(
                        req_id,
                        -32602,
                        &format!(
                            "A schedule already exists for workflow {}. Each workflow can have \
                             at most one schedule. Call list_schedules to find the existing one, \
                             then delete_schedule to remove it before creating a new one (or \
                             update the cron_expression via the scheduler UI).",
                            workflow_id
                        ),
                    );
                }
            }
            mcp_error(req_id, -32000, "Failed to create schedule")
        }
    }
}

async fn handle_list_schedules(
    req_id: Option<serde_json::Value>,
    _args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let sched_repo = talos_schedule_repo::ScheduleRepository::new(state.db_pool.clone());
    match sched_repo.list_for_user(user_id).await {
        Ok(rows) => {
            let schedules: Vec<serde_json::Value> = rows
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "id": r.id,
                        "workflow_id": r.workflow_id,
                        "workflow_name": r.workflow_name,
                        "cron_expression": r.cron_expression,
                        "timezone": r.timezone,
                        "is_enabled": r.is_enabled,
                        "last_triggered_at": r.last_triggered_at.map(|t| t.to_rfc3339()),
                        "next_trigger_at": r.next_trigger_at.map(|t| t.to_rfc3339()),
                    })
                })
                .collect();
            // MCP-45 (2026-05-07): structured envelope (count + items).
            let envelope = serde_json::json!({
                "count": schedules.len(),
                "schedules": schedules,
            });
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&envelope).unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("list_schedules failed: {:#}", e);
            mcp_error(req_id, -32000, "Failed to list schedules")
        }
    }
}

async fn handle_pause_schedule(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let schedule_id = match crate::utils::require_uuid(args, "schedule_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let sched_repo = talos_schedule_repo::ScheduleRepository::new(state.db_pool.clone());
    match sched_repo.set_enabled(schedule_id, user_id, false).await {
        Ok(rows) if rows > 0 => mcp_text(req_id, &format!("Schedule {} paused.", schedule_id)),
        Ok(_) => mcp_error(req_id, -32000, "Schedule not found or access denied"),
        Err(e) => {
            tracing::error!("pause_schedule failed: {:#}", e);
            mcp_error(req_id, -32000, "Failed to pause schedule")
        }
    }
}

async fn handle_resume_schedule(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let schedule_id = match crate::utils::require_uuid(args, "schedule_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let sched_repo = talos_schedule_repo::ScheduleRepository::new(state.db_pool.clone());
    match sched_repo.set_enabled(schedule_id, user_id, true).await {
        Ok(rows) if rows > 0 => mcp_text(req_id, &format!("Schedule {} resumed.", schedule_id)),
        Ok(_) => mcp_error(req_id, -32000, "Schedule not found or access denied"),
        Err(e) => {
            tracing::error!("resume_schedule failed: {:#}", e);
            mcp_error(req_id, -32000, "Failed to resume schedule")
        }
    }
}

async fn handle_delete_schedule(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let schedule_id = match crate::utils::require_uuid(args, "schedule_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let sched_repo = talos_schedule_repo::ScheduleRepository::new(state.db_pool.clone());
    match sched_repo.delete(schedule_id, user_id).await {
        Ok(rows) if rows > 0 => mcp_text(req_id, &format!("Schedule {} deleted.", schedule_id)),
        Ok(_) => mcp_error(req_id, -32000, "Schedule not found or access denied"),
        Err(e) => {
            tracing::error!("delete_schedule failed: {:#}", e);
            mcp_error(req_id, -32000, "Failed to delete schedule")
        }
    }
}

async fn handle_get_schedule_next_runs(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let limit: i64 = match crate::utils::validate_range_i64(args, "limit", 1, 50, 10, &req_id) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let sched_repo = talos_schedule_repo::ScheduleRepository::new(state.db_pool.clone());
    match sched_repo.list_next_runs(user_id, limit).await {
        Ok(rows) => {
            let schedules: Vec<serde_json::Value> = rows
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "schedule_id": r.id,
                        "workflow_name": r.workflow_name,
                        "cron_expression": r.cron_expression,
                        "timezone": r.timezone,
                        "next_trigger_at": r.next_trigger_at.to_rfc3339(),
                        "is_enabled": r.is_enabled,
                    })
                })
                .collect();

            let result = serde_json::json!({
                "count": schedules.len(),
                "schedule_count": schedules.len(),
                "schedules": schedules,
            });
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&result).unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("get_schedule_next_runs query failed: {:#}", e);
            mcp_error(req_id, -32000, "Failed to query schedule next runs")
        }
    }
}

async fn handle_get_schedule_health(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let schedule_id = match crate::utils::require_uuid(args, "schedule_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // Get schedule info
    let sched_repo = talos_schedule_repo::ScheduleRepository::new(state.db_pool.clone());
    let sched = match sched_repo
        .get_with_workflow_info(schedule_id, user_id)
        .await
        .unwrap_or(None)
    {
        Some(r) => r,
        None => return mcp_error(req_id, -32000, "Schedule not found or access denied"),
    };

    let workflow_id = sched.workflow_id;
    let workflow_name = sched.workflow_name;
    let cron_expression = sched.cron_expression;
    let timezone = sched.timezone;
    let is_enabled = sched.is_enabled;
    let last_triggered_at = sched.last_triggered_at;
    let next_trigger_at = sched.next_trigger_at;

    // Get last 24h execution stats. We track whether each repo call
    // actually succeeded — the previous shape (`unwrap_or_else(|e|
    // Default)`) returned `total: 0` indistinguishably from "no
    // executions yet," which masked the 2026-05-06 broken-query bug
    // where `get_scheduled_24h_execution_stats` referenced a non-
    // existent `trigger_type` column. Now any DB error stamps a
    // `data_warning` on the response so the operator has a signal.
    let mut data_warnings: Vec<String> = Vec::new();
    let stats = match state
        .workflow_repo
        .get_scheduled_24h_execution_stats(workflow_id)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                target: "talos_schedules",
                event_kind = "schedule_health_stats_failed",
                workflow_id = %workflow_id,
                error = %e,
                "get_scheduled_24h_execution_stats query failed"
            );
            data_warnings.push(format!(
                "stats_24h unavailable: {} (zeros below are not authoritative)",
                e
            ));
            talos_workflow_repository::WorkflowHealthStats {
                total: 0,
                succeeded: 0,
                failed: 0,
                last_success_at: None,
                last_failure_at: None,
            }
        }
    };
    let total = stats.total;
    let succeeded = stats.succeeded;
    let failed = stats.failed;
    let last_success_at = stats.last_success_at;
    let last_failure_at = stats.last_failure_at;

    // Compute streak from recent executions (schedule-scoped only).
    let statuses = match state
        .workflow_repo
        .list_recent_scheduled_execution_statuses(workflow_id, 20)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                target: "talos_schedules",
                event_kind = "schedule_health_statuses_failed",
                workflow_id = %workflow_id,
                error = %e,
                "list_recent_scheduled_execution_statuses query failed"
            );
            // MCP-351 (2026-05-11): pre-fix the DB error string was
            // pushed verbatim into the operator-visible `data_warnings`.
            // sqlx errors include table / column / constraint names —
            // info-disclosure to the API surface. Full error stays in
            // the tracing event above for server-side debugging; the
            // operator sees only that the streak is unavailable.
            data_warnings.push("streak unavailable: query failed (see server logs)".to_string());
            Vec::new()
        }
    };

    let (streak_type, streak_count) = if let Some(first) = statuses.first() {
        let count = statuses.iter().take_while(|s| *s == first).count();
        (first.clone(), count)
    } else {
        ("none".to_string(), 0)
    };

    // MCP-29 (2026-05-07): emit last_success_ago as a structured
    // {available, runs_ago, label} envelope rather than a magic string
    // ("no executions" / "last run" / "N runs ago"). Pre-fix the field
    // mixed three different shapes — operators feeding it into a
    // duration parser got NaN. The envelope keeps the human-readable
    // label for terminal output but lets programmatic consumers branch
    // on `available` and use `runs_ago` for arithmetic without parsing.
    let last_success_ago = if statuses.is_empty() {
        serde_json::json!({
            "available": false,
            "runs_ago": null,
            "label": "no executions in window"
        })
    } else if let Some(pos) = statuses.iter().position(|s| s == "completed") {
        let label = if pos == 0 {
            "last run".to_string()
        } else {
            format!("{} runs ago", pos)
        };
        serde_json::json!({
            "available": true,
            "runs_ago": pos,
            "label": label
        })
    } else {
        serde_json::json!({
            "available": false,
            "runs_ago": null,
            "label": format!("no successes in last {} runs", statuses.len())
        })
    };

    let rolling_success_rate_24h = if total > 0 {
        (succeeded as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    let mut result = serde_json::json!({
        "schedule": {
            "id": schedule_id.to_string(),
            "cron_expression": cron_expression,
            "timezone": timezone,
            "is_enabled": is_enabled,
            "last_triggered_at": last_triggered_at.map(|t| t.to_rfc3339()),
            "next_trigger_at": next_trigger_at.map(|t| t.to_rfc3339()),
        },
        "workflow": {
            "id": workflow_id.to_string(),
            "name": workflow_name,
        },
        "stats_24h": {
            "total": total,
            "succeeded": succeeded,
            "failed": failed,
            "rolling_success_rate_pct": talos_analytics_repository::format_percent(rolling_success_rate_24h),
            "last_success_at": last_success_at.map(|t| t.to_rfc3339()),
            "last_failure_at": last_failure_at.map(|t| t.to_rfc3339()),
        },
        "streak": {
            "type": streak_type,
            "count": streak_count,
        },
        "last_success_ago": last_success_ago,
    });
    if !data_warnings.is_empty() {
        result["data_warnings"] = serde_json::json!(data_warnings);
    }

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

#[cfg(test)]
mod tests {
    use super::describe_cron;

    #[test]
    fn common_patterns_get_friendly_descriptions() {
        assert_eq!(describe_cron("0 9 * * 1-5"), "Weekdays (Mon-Fri) at 09:00");
        assert_eq!(describe_cron("0 8 * * *"), "Daily at 08:00");
        assert_eq!(describe_cron("*/15 * * * *"), "Every 15 minutes");
        assert_eq!(describe_cron("0 * * * *"), "At the top of every hour");
        assert_eq!(
            describe_cron("0 9 1 * *"),
            "First day of every month at 09:00"
        );
        assert_eq!(describe_cron("0 9 * * 1"), "Mondays at 09:00");
    }

    #[test]
    fn unrecognised_patterns_fall_through_to_raw_expression() {
        // Custom complex expressions don't get a friendly mapping —
        // we surface the raw cron so the caller can still read it.
        let weird = "7 4,16 * 1,7 *";
        let out = describe_cron(weird);
        assert_eq!(out, "Cron: 7 4,16 * 1,7 *");
    }

    #[test]
    fn malformed_field_count_falls_through() {
        // 4-field input (missing dow) — should not panic, should not be
        // mistakenly matched against a 5-field pattern.
        let out = describe_cron("0 9 * *");
        assert_eq!(out, "Cron: 0 9 * *");
    }
}
