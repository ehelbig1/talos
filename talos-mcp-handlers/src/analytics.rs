use super::types::JsonRpcResponse;
use super::utils::{compute_mcp_graph_diff, mcp_error, mcp_text, update_workflow_search_text};
use super::{auth, McpState};
use std::sync::Arc;
use uuid::Uuid;

/// Derive capability tag suggestions from a workflow's graph JSON.
/// Pure computation: parse graph → extract module_ids → DB queries → return tags.
async fn compute_capability_suggestions(graph_json: &str, pool: &sqlx::PgPool) -> Vec<String> {
    let repo = talos_analytics_repository::AnalyticsRepository::new(pool.clone());
    let graph: serde_json::Value =
        serde_json::from_str(graph_json).unwrap_or(serde_json::json!({"nodes":[],"edges":[]}));

    let nodes = graph.get("nodes").and_then(|n| n.as_array());
    let edges = graph.get("edges").and_then(|e| e.as_array());

    let module_ids: Vec<Uuid> = nodes
        .map(|ns| {
            ns.iter()
                .filter_map(|n| {
                    n.get("type")
                        .and_then(|v| v.as_str())
                        .and_then(|s| s.parse().ok())
                })
                .collect()
        })
        .unwrap_or_default();

    let mut suggestions: Vec<String> = Vec::new();

    if !module_ids.is_empty() {
        let world_rows = repo
            .get_capability_worlds_for_modules(&module_ids)
            .await
            .unwrap_or_default();

        for world in &world_rows {
            let w = talos_capability_world::world_short(world);
            // Always surface the world short-name as a tag — gives capability-based
            // search a deterministic handle even for worlds without a flavor mapping
            // (e.g. "minimal" and arbitrary future worlds). Without this, sub-workflows
            // built from `minimal-node` modules (a very common case for pure-Rust
            // helpers, judges, reflection nodes) would derive zero tags and get
            // skipped by auto_tag_capabilities.
            suggestions.push(format!("world-{}", w));

            match w {
                "http" | "network" => {
                    suggestions.push("http".to_string());
                    suggestions.push("fetch".to_string());
                }
                "database" => suggestions.push("database".to_string()),
                "secrets" => suggestions.push("uses-secrets".to_string()),
                "filesystem" => suggestions.push("filesystem".to_string()),
                "cache" => suggestions.push("caching".to_string()),
                "messaging" => suggestions.push("messaging".to_string()),
                "agent" => suggestions.push("agentic".to_string()),
                "governance" => suggestions.push("governance".to_string()),
                "automation" | "trusted" => suggestions.push("automation".to_string()),
                "minimal" => suggestions.push("computational".to_string()),
                _ => {}
            }
        }

        let tmpl_cats = repo
            .get_template_categories_lower(&module_ids)
            .await
            .unwrap_or_default();

        for cat in &tmpl_cats {
            match cat.as_str() {
                "network" | "http" if !suggestions.iter().any(|s| s == "http") => {
                    suggestions.push("http".to_string());
                }
                "data" | "database" if !suggestions.iter().any(|s| s == "database") => {
                    suggestions.push("database".to_string());
                }
                _ => {}
            }
        }
    }

    // Graph-structure hints
    if let (Some(ns), Some(es)) = (nodes, edges) {
        let n_count = ns.len();
        let e_count = es.len();

        // Single-node, no-edges shape is the canonical sub-workflow template
        // (judge / reflection / classifier / synth fragments invoked from a
        // parent via add_judge_node / add_reflective_retry_node / etc.). Tag
        // accordingly so capability-based discovery surfaces them as composable
        // building blocks rather than leaf workflows.
        if n_count == 1 && e_count == 0 {
            suggestions.push("sub-workflow".to_string());
        }

        if n_count > 2 {
            let mut incoming: std::collections::HashMap<&str, usize> = Default::default();
            for e in es {
                if let Some(t) = e.get("target").and_then(|v| v.as_str()) {
                    *incoming.entry(t).or_insert(0) += 1;
                }
            }
            if incoming.values().any(|&c| c > 1) {
                suggestions.push("parallel".to_string());
            }
        }
    }

    suggestions.sort();
    suggestions.dedup();
    suggestions
}

/// Best-effort: derive capability tags from a workflow's graph and apply them if none are set.
/// Runs in a background tokio::spawn — never panics.
pub(crate) async fn auto_suggest_capabilities(
    workflow_id: Uuid,
    user_id: Uuid,
    pool: &sqlx::PgPool,
) {
    let repo = talos_analytics_repository::AnalyticsRepository::new(pool.clone());

    // Only apply if capabilities are currently empty
    let gc = match repo
        .get_workflow_graph_and_capabilities(workflow_id, user_id)
        .await
    {
        Ok(Some(pair)) => pair,
        _ => return,
    };

    let (graph_json_str, caps) = gc;
    if !caps.is_empty() {
        return; // Don't overwrite explicit user-set capabilities
    }

    let suggestions = compute_capability_suggestions(&graph_json_str, pool).await;

    if suggestions.is_empty() {
        return;
    }

    let _ = repo
        .set_capabilities_if_empty(workflow_id, user_id, &suggestions)
        .await;
}

pub fn tool_schemas() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "name": "get_workflow_stats",
            "description": "Get execution statistics for a workflow over a time period. Returns success/failure counts, avg duration, and top error fingerprints.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" },
                    "days": { "type": "number", "description": "Number of days to look back (default 7, max 90)" }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "get_system_status",
            "description": "Get a count of all major platform resources for the current user.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
        serde_json::json!({
            "name": "get_health_dashboard",
            "description": "Overview of workflow health: failing workflows, long-running executions, and summary counts.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
        serde_json::json!({
            "name": "get_workflow_dependencies",
            "description": "List all external dependencies of a workflow: modules, secrets, webhooks, and schedules.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "get_workflow_changelog",
            "description": "Human-readable changelog from version history. Shows diffs between consecutive versions as a formatted list.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" },
                    "limit": { "type": "number", "description": "Max entries to return (default 10, max 100)" }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "validate_all_workflows",
            "description": "Batch-validate all workflows for the current user: checks module existence and cycle detection for each.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
        serde_json::json!({
            "name": "get_system_health",
            "description": "ADMIN-ONLY. Comprehensive platform health check: database connectivity, resource counts, stale executions, recent failure rate, and disk usage estimate. Non-admin callers receive an Unauthorized error. Non-admin users should call get_health_dashboard or session_start for the subset of health signals available at user-level privileges.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
        serde_json::json!({
            "name": "get_workflow_audit_trail",
            "description": "Unified audit timeline for a workflow: version publishes, execution triggers, and configuration changes.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to audit" },
                    "limit": { "type": "number", "description": "Maximum number of events to return (default: 20, max: 100)" }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "get_workflow_sla_report",
            "description": "SLA compliance report for a workflow. Compares actual success rate and latency percentiles (p50/p95/p99) against configurable targets.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" },
                    "target_success_rate": { "type": "number", "description": "Target success rate percentage (default: 99.0)" },
                    "target_max_duration_ms": { "type": "number", "description": "Target maximum execution duration in milliseconds (default: 5000)" },
                    "days": { "type": "number", "description": "Number of days to look back (default: 30, max: 90)" }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "list_workflow_triggers",
            "description": "Show all trigger sources for a workflow: schedules, webhooks, parent workflows that invoke it as a sub-workflow, and whether it is manual-only.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "get_workflow_call_tree",
            "description": "Show the full call tree across sub-workflows — which workflows call which. Detects circular references.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the root workflow" },
                    "max_depth": { "type": "number", "description": "Maximum recursion depth (default 3, max 5)" }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "get_all_workflow_stats",
            "description": "Aggregate dashboard across all workflows. Returns per-workflow stats (total, succeeded, failed, avg duration) for the top 50 most active workflows sorted by failure count.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "days": { "type": "number", "description": "Number of days to look back (default 7, max 90)" }
                }
            }
        }),
        serde_json::json!({
            "name": "get_error_report",
            "description": "Comprehensive error analysis for a workflow: total failures, error fingerprints, node-level failure breakdown, and time-of-day failure patterns.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to analyze" },
                    "days": { "type": "number", "description": "Number of days to look back (default: 7, max: 90)" }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "suggest_retry_config",
            "description": "Analyze past execution failures and suggest optimal retry settings (retry_count, backoff, conditions) with reasoning.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to analyze" }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "get_workflow_topology",
            "description": "DAG analysis for a workflow: longest path length, parallel width, critical path nodes, and bottleneck fan-in points.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to analyze" }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "get_node_failure_breakdown",
            "description": "Node-level failure analysis with human-readable labels. Resolves node UUIDs from execution_events back to the workflow graph labels.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to analyze" },
                    "days": { "type": "number", "description": "Number of days to look back (default: 7, max: 90)" }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "get_workflow_dependency_map",
            "description": "Visualize cross-workflow module dependencies. Shows which modules are shared across which workflows.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
        serde_json::json!({
            "name": "get_workflow_performance_report",
            "description": "Detailed performance analysis for a workflow: p50/p95/p99 latency, per-node timing breakdown, slowest/fastest executions, and performance trend (improving/degrading/stable). Response includes a see_also hint pointing to get_execution_waterfall for a visual parallel-timeline chart of a specific execution.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" },
                    "days": { "type": "number", "description": "Number of days to analyze (default: 7, max: 90)" }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "get_workflow_risk_assessment",
            "description": "Identify potential issues in a workflow: missing retry configs on HTTP nodes, no timeout, high-failure sub-workflows, stale modules, expiring secrets, missing error edges, and nodes with continue_on_error that silently swallow failures.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to assess" }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "get_daily_digest",
            "description": "Summary of the last 24 hours across all your workflows: execution counts by status, top active workflows, top failing workflows, and upcoming schedules.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
        serde_json::json!({
            "name": "set_workflow_capabilities",
            "description": "Set structured capability tags on a workflow (e.g., 'http-fetch', 'data-transform'). Capabilities enable semantic discovery.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" },
                    "capabilities": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Array of capability tags (lowercase alphanumeric + hyphens, max 50 chars each, max 20 total)"
                    }
                },
                "required": ["workflow_id", "capabilities"]
            }
        }),
        serde_json::json!({
            "name": "get_workflows_by_capability",
            "description": "Find workflows that have ALL of the specified capabilities. Returns workflows with success rates and readiness scores.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "capabilities": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Array of required capability tags (all must match)"
                    }
                },
                "required": ["capabilities"]
            }
        }),
        serde_json::json!({
            "name": "get_workflow_reuse_stats",
            "description": "Get reuse analytics across workflows: invocation counts, unique sessions, repeat-use ratio, and estimated token savings.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "days": { "type": "number", "description": "Lookback period in days (default: 30)" }
                }
            }
        }),
        serde_json::json!({
            "name": "suggest_capabilities",
            "description": "Auto-suggest capability tags for a workflow by analyzing its graph structure and module types.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "get_fuel_usage_report",
            "description": "Aggregate fuel (computation) consumption across recent workflow executions. Shows top fuel-intensive modules with p50, p95, max stats and flags modules near the fuel limit.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "days": { "type": "number", "description": "Number of days to look back (default: 7, max: 30)" }
                }
            }
        }),
        serde_json::json!({
            "name": "get_platform_hygiene_report",
            "description": "One-call platform hygiene audit. Surfaces: undescribed published workflows, \
                workflows missing capabilities (invisible to capability-based search), workflows missing embeddings \
                (invisible to semantic search), orphaned compiled modules, stale stuck executions, dormant workflows, \
                idle agents, orphaned secrets (not referenced by any module), and API token secrets missing expiry dates. \
                internal/test workflow types are suppressed from readiness warnings. \
                Use this as the single daily operator check to keep the registry and vault clean.\n\n\
                fix_all mode: set fix_all=true to see a dry-run preview of auto-fixable items (stale draft workflows, \
                stuck executions, orphaned modules). Add confirm=true to execute the fixes.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "fix_all": {
                        "type": "boolean",
                        "description": "If true, generate a fix_all preview block listing auto-fixable issues (stale draft workflows, stuck executions, orphaned modules). Combine with confirm=true to apply fixes. Default: false."
                    },
                    "confirm": {
                        "type": "boolean",
                        "description": "When fix_all=true: if confirm=true, execute the auto-fixes. If confirm=false (default), return a dry-run preview without mutating any state."
                    }
                }
            }
        }),
        serde_json::json!({
            "name": "get_readiness_breakdown",
            "description": "Explain the readiness_score for a workflow by decomposing it into its four weighted components: \
                reliability (50% — success rate × run count, saturates at 10 runs), documentation (20% — description + node descriptions + capabilities), \
                freshness (20% — recency of last execution), and risk (10% — timeout, error edges, expiring secrets). \
                Shows current value and maximum for each component, plus specific actions to improve the score. \
                Also persists the computed score to the workflow record so other tools (hygiene report, semantic search) can read it.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to explain" }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "get_all_readiness_scores",
            "description": "Batch readiness audit for all your workflows. Returns readiness_score, key component indicators, and the top improvement action for each workflow sorted ascending (worst first). Replaces N sequential get_readiness_breakdown calls. Uses cached scores — call get_readiness_breakdown on specific workflows to recalculate. Archived workflows are excluded by default (status='archived'); set include_archived: true to include them. Each entry may include a 'note' field (string) when score_state is 'unscored' — the note prompts calling get_readiness_breakdown to compute the initial score.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_ids": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Optional list of workflow UUIDs to assess. Omit to assess all your workflows (max 50, worst-first)."
                    },
                    "max_score": {
                        "type": "number",
                        "description": "Only return workflows with readiness_score at or below this value. Useful for finding only underperforming workflows (e.g. max_score: 50)."
                    },
                    "include_archived": {
                        "type": "boolean",
                        "description": "Include archived workflows (status='archived') in results. Default false — archived workflows are excluded to prevent them from inflating below_50_count."
                    }
                }
            }
        }),
        serde_json::json!({
            "name": "auto_tag_capabilities",
            "description": "Derive and apply capability tags to untagged workflows by inspecting each workflow's graph structure: \
                WASM module capability worlds, node types (loop, sub_workflow, collect), edge conditions, and topology. \
                Workflows with no WASM module nodes (e.g. empty scaffolding or QA fixtures) will be skipped with \
                skip_reason: 'no_graph_signals' — use set_workflow_capabilities to tag those manually. \
                Returns a per-workflow summary. Idempotent — already-tagged workflows are skipped. \
                Provide workflow_ids to restrict to specific workflows; omit to process all untagged (max 200).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_ids": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Optional list of workflow UUIDs to tag. When provided, only these workflows are processed (still skips already-tagged). Omit to process all untagged workflows (max 200)."
                    }
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
    let is_admin = agent.is_admin();
    match name {
        "get_workflow_stats" => Some(handle_get_workflow_stats(req_id, args, state, user_id).await),
        "get_system_status" => Some(handle_get_system_status(req_id, state, user_id).await),
        "get_health_dashboard" => Some(handle_get_health_dashboard(req_id, state, user_id).await),
        "get_workflow_dependencies" => {
            Some(handle_get_workflow_dependencies(req_id, args, state, user_id).await)
        }
        "get_workflow_changelog" => {
            Some(handle_get_workflow_changelog(req_id, args, state, user_id).await)
        }
        "validate_all_workflows" => {
            Some(handle_validate_all_workflows(req_id, state, user_id).await)
        }
        "get_system_health" => {
            Some(handle_get_system_health(req_id, state, user_id, is_admin).await)
        }
        "get_workflow_audit_trail" => {
            Some(handle_get_workflow_audit_trail(req_id, args, state, user_id).await)
        }
        "get_workflow_sla_report" => {
            Some(handle_get_workflow_sla_report(req_id, args, state, user_id).await)
        }
        "list_workflow_triggers" => {
            Some(handle_list_workflow_triggers(req_id, args, state, user_id).await)
        }
        "get_workflow_call_tree" => {
            Some(handle_get_workflow_call_tree(req_id, args, state, user_id).await)
        }
        "get_all_workflow_stats" => {
            Some(handle_get_all_workflow_stats(req_id, args, state, user_id).await)
        }
        "get_error_report" => Some(handle_get_error_report(req_id, args, state, user_id).await),
        "suggest_retry_config" => {
            Some(handle_suggest_retry_config(req_id, args, state, user_id).await)
        }
        "get_workflow_topology" => {
            Some(handle_get_workflow_topology(req_id, args, state, user_id).await)
        }
        "get_node_failure_breakdown" => {
            Some(handle_get_node_failure_breakdown(req_id, args, state, user_id).await)
        }
        "get_workflow_dependency_map" => {
            Some(handle_get_workflow_dependency_map(req_id, args, state, user_id).await)
        }
        "get_workflow_performance_report" => {
            Some(handle_get_workflow_performance_report(req_id, args, state, user_id).await)
        }
        "get_workflow_risk_assessment" => {
            Some(handle_get_workflow_risk_assessment(req_id, args, state, user_id).await)
        }
        "get_daily_digest" => Some(handle_get_daily_digest(req_id, args, state, user_id).await),
        "set_workflow_capabilities" => {
            Some(handle_set_workflow_capabilities(req_id, args, state, user_id).await)
        }
        "get_workflows_by_capability" => {
            Some(handle_get_workflows_by_capability(req_id, args, state, user_id).await)
        }
        "get_workflow_reuse_stats" => {
            Some(handle_get_workflow_reuse_stats(req_id, args, state, user_id).await)
        }
        "suggest_capabilities" => {
            Some(handle_suggest_capabilities(req_id, args, state, user_id).await)
        }
        "get_fuel_usage_report" => {
            Some(handle_get_fuel_usage_report(req_id, args, state, user_id).await)
        }
        "get_platform_hygiene_report" => {
            Some(handle_get_platform_hygiene_report(req_id, args, state, user_id).await)
        }
        "auto_tag_capabilities" => {
            Some(handle_bulk_tag_workflows(req_id, args, state, user_id).await)
        }
        "get_readiness_breakdown" => {
            Some(handle_get_readiness_breakdown(req_id, args, state, user_id).await)
        }
        "get_all_readiness_scores" => {
            Some(handle_get_all_readiness_scores(req_id, args, state, user_id).await)
        }
        _ => None,
    }
}

async fn handle_get_workflow_stats(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // MCP-170 (2026-05-08): pre-check workflow ownership. Pre-fix the
    // handler ran the SELECT-COUNT-by-user_id query directly, so a
    // non-existent / cross-tenant workflow_id returned a successful
    // {total: 0, succeeded: 0, ...} envelope — silent-not-found.
    // Sister handlers (get_workflow_performance_report,
    // get_workflow_call_tree, get_node_failure_breakdown, etc.) already
    // do this; bring this one in line.
    if !state.workflow_repo.workflow_exists(wf_id, user_id).await {
        return crate::utils::workflow_not_found_error(req_id);
    }

    let days: i32 = match crate::utils::validate_range_i64(args, "days", 1, 90, 7, &req_id) {
        Ok(v) => v as i32,
        Err(resp) => return resp,
    };

    let stats = match state
        .analytics_repo
        .get_exec_stats(wf_id, user_id, days)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("get_workflow_stats query failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to fetch workflow stats");
        }
    };

    let (total, succeeded, failed, running, avg_duration_secs) = (
        stats.total,
        stats.succeeded,
        stats.failed,
        stats.running,
        stats.avg_duration_secs,
    );

    // Error fingerprints
    let error_msgs = state
        .analytics_repo
        .get_error_messages(wf_id, user_id, days, 100)
        .await
        .unwrap_or_default();

    let mut fp_map: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for msg in &error_msgs {
        let fp = talos_analytics_repository::fingerprint_error_message(msg);
        *fp_map.entry(fp).or_insert(0) += 1;
    }
    let mut fp_list: Vec<serde_json::Value> = fp_map
        .into_iter()
        .map(|(fp, count)| serde_json::json!({"fingerprint": fp, "count": count}))
        .collect();
    fp_list.sort_by(|a, b| {
        let ca = a.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        let cb = b.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        cb.cmp(&ca)
    });
    fp_list.truncate(5);

    let success_rate = stats.success_rate_percent();

    let result = serde_json::json!({
        "workflow_id": wf_id.to_string(),
        "period_days": days,
        "total": total,
        "succeeded": succeeded,
        "failed": failed,
        "running": running,
        "success_rate_percent": talos_analytics_repository::format_percent(success_rate),
        "avg_duration_secs": avg_duration_secs,
        "top_error_fingerprints": fp_list,
    });

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

async fn handle_get_system_status(
    req_id: Option<serde_json::Value>,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    match state.analytics_repo.get_system_status_counts(user_id).await {
        Ok(counts) => {
            let result = serde_json::json!({
                "workflows": counts.workflows,
                "executions": counts.executions,
                "modules": counts.modules,
                "templates": counts.templates,
                "secrets": counts.secrets,
                "schedules": counts.schedules,
                "webhooks": counts.webhooks,
            });
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&result).unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("get_system_status query failed: {}", e);
            mcp_error(req_id, -32000, "Failed to fetch system status")
        }
    }
}

async fn handle_get_health_dashboard(
    req_id: Option<serde_json::Value>,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let failing_rows = state
        .analytics_repo
        .get_failing_workflows(user_id, 1)
        .await
        .unwrap_or_default();

    let failing: Vec<serde_json::Value> = failing_rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "workflow_id": r.id.to_string(),
                "name": r.name,
                "failures_24h": r.fail_count,
                "total_24h": r.total_count,
            })
        })
        .collect();

    let long_running_rows = state
        .analytics_repo
        .get_long_running_executions(user_id)
        .await
        .unwrap_or_default();

    let long_running: Vec<serde_json::Value> = long_running_rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "execution_id": r.id.to_string(),
                "workflow_name": r.name,
                "running_seconds": r.running_secs,
            })
        })
        .collect();

    // MCP-1211 (2026-05-18): workflows whose recent executions hit a loop
    // node's max_iterations safety cap. Surfaced alongside failures +
    // long-runners because "completed but burning fuel on dead iterations"
    // is the third class of silent-broken workflow that doesn't show up
    // in any other dashboard. Routed through ExecutionRepository because
    // PG 16 stores output_data encrypted (`output_data_enc`) — a plain
    // JSONB-path query can't see the bytes; we must decrypt + filter in
    // Rust. See `find_loop_capped_workflows_24h`.
    let loop_capped_rows = match state
        .execution_repo
        .find_loop_capped_workflows_24h(user_id)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "find_loop_capped_workflows_24h returned error");
            Vec::new()
        }
    };

    let loop_capped: Vec<serde_json::Value> = loop_capped_rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "workflow_id": r.workflow_id.to_string(),
                "name": r.workflow_name,
                "occurrence_count_24h": r.occurrence_count,
                "last_seen": r.last_seen.map(|t| t.to_rfc3339()),
            })
        })
        .collect();

    let summary = match state
        .analytics_repo
        .get_health_summary_counts(user_id)
        .await
    {
        Ok(s) => s,
        Err(_) => return mcp_error(req_id, -32000, "Failed to fetch health dashboard"),
    };

    // MCP-63 (2026-05-07): mirror array lengths into summary so callers
    // can answer "is anything broken right now" from a single object
    // instead of length-checking two separate top-level arrays.
    let result = serde_json::json!({
        "summary": {
            "currently_running": summary.running,
            "failed_last_24h": summary.failed_24h,
            "completed_last_24h": summary.completed_24h,
            "failing_workflow_count": failing.len(),
            "long_running_execution_count": long_running.len(),
            "loop_capped_workflow_count": loop_capped.len(),
        },
        "failing_workflows": failing,
        "long_running_executions": long_running,
        "loop_capped_workflows": loop_capped,
    });

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

async fn handle_get_workflow_dependencies(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let graph_json_str = match state
        .analytics_repo
        .get_workflow_graph_json(wf_id, user_id)
        .await
    {
        Ok(Some(gj)) => gj,
        Ok(None) => return mcp_error(req_id, -32000, "Workflow not found or access denied"),
        Err(e) => {
            tracing::error!("get_workflow_dependencies graph query failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to fetch workflow");
        }
    };

    let graph: serde_json::Value =
        serde_json::from_str(&graph_json_str).unwrap_or(serde_json::json!({"nodes":[],"edges":[]}));

    let nodes = graph
        .get("nodes")
        .and_then(|n| n.as_array())
        .cloned()
        .unwrap_or_default();

    // Extract module IDs
    let module_ids: Vec<uuid::Uuid> = nodes
        .iter()
        .filter_map(|n| {
            n.get("type")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
        })
        .collect();

    // Resolve module names
    let module_names: std::collections::HashMap<uuid::Uuid, String> = if !module_ids.is_empty() {
        state
            .analytics_repo
            .list_module_and_template_names(&module_ids)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|r| (r.id, r.name))
            .collect()
    } else {
        std::collections::HashMap::new()
    };

    let modules: Vec<serde_json::Value> = module_ids
        .iter()
        .map(|id| {
            serde_json::json!({
                "module_id": id.to_string(),
                "name": module_names.get(id).cloned().unwrap_or_else(|| "unknown".to_string()),
            })
        })
        .collect();

    // Secrets referenced in graph
    let secrets_referenced: Vec<String> = nodes
        .iter()
        .flat_map(|n| {
            n.get("data")
                .map(|d| crate::utils::json_string_array_field(d, "allowed_secrets"))
                .unwrap_or_default()
        })
        .collect();

    let schedule_rows = state
        .analytics_repo
        .list_workflow_schedules(wf_id)
        .await
        .unwrap_or_default();
    let schedules: Vec<serde_json::Value> = schedule_rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "cron_expression": r.cron_expression,
                "is_enabled": r.is_enabled,
            })
        })
        .collect();

    let webhook_rows = state
        .analytics_repo
        .list_workflow_webhooks(wf_id)
        .await
        .unwrap_or_default();
    let webhooks: Vec<serde_json::Value> = webhook_rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "webhook_id": r.id.to_string(),
                "endpoint_path": r.endpoint_path,
                "is_enabled": r.is_enabled,
            })
        })
        .collect();

    // MCP-108 (2026-05-08): per-array counts + total_dependencies so a
    // caller can answer "what's this workflow's external surface area"
    // from one object lookup. Same MCP-83 pattern.
    let result = serde_json::json!({
        "workflow_id": wf_id.to_string(),
        "module_count": modules.len(),
        "secret_count": secrets_referenced.len(),
        "schedule_count": schedules.len(),
        "webhook_count": webhooks.len(),
        "total_dependencies": modules.len()
            + secrets_referenced.len()
            + schedules.len()
            + webhooks.len(),
        "modules": modules,
        "secrets": secrets_referenced,
        "schedules": schedules,
        "webhooks": webhooks,
    });

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

async fn handle_get_workflow_changelog(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let limit: i64 = match crate::utils::validate_range_i64(args, "limit", 1, 100, 10, &req_id) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // Verify ownership
    let wf = state
        .analytics_repo
        .get_workflow_for_analytics(wf_id, user_id)
        .await
        .unwrap_or(None);
    if wf.is_none() {
        return crate::utils::workflow_not_found_error(req_id);
    }

    let rows = match state
        .analytics_repo
        .list_workflow_versions_changelog(wf_id, limit)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("get_workflow_changelog query failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to fetch version history");
        }
    };

    if rows.is_empty() {
        // Return a structured envelope (matching the populated branch's shape)
        // so callers can `.changelog.length === 0` instead of having to
        // string-match a free-form message. The note field carries the
        // human-readable hint for ops dashboards.
        let result = serde_json::json!({
            "workflow_id": wf_id.to_string(),
            "count": 0,
            "changelog": [],
            "note": "No published versions found for this workflow.",
        });
        return mcp_text(
            req_id,
            &serde_json::to_string_pretty(&result).unwrap_or_default(),
        );
    }

    let mut changelog_entries: Vec<serde_json::Value> = Vec::new();

    // MCP-47 (2026-05-07): synthesize an "Initial publish" entry for
    // version 1 — pre-fix the loop started at index 1 and skipped the
    // very first version, so a workflow with one published version
    // returned an empty changelog even when v1 had a meaningful
    // description. Now operators always see something for v1.
    if let Some(first) = rows.first() {
        let first_version: i32 = first.version_number.unwrap_or(0);
        let first_desc: Option<String> = first.description.clone();
        let first_published_at = first.published_at.unwrap_or_default();
        changelog_entries.push(serde_json::json!({
            "version": first_version,
            "published_at": first_published_at.to_rfc3339(),
            "description": first_desc,
            "diff": null,
            "change_type": "initial_publish",
        }));
    }

    for i in 1..rows.len() {
        let prev = &rows[i - 1];
        let curr = &rows[i];

        let prev_graph: String = prev.graph_json.clone().unwrap_or_default();
        let curr_graph: String = curr.graph_json.clone().unwrap_or_default();
        let curr_version: i32 = curr.version_number.unwrap_or(0);
        let curr_desc: Option<String> = curr.description.clone();
        let curr_published_at = curr.published_at.unwrap_or_default();

        let diff = compute_mcp_graph_diff(&prev_graph, &curr_graph);

        changelog_entries.push(serde_json::json!({
            "version": curr_version,
            "published_at": curr_published_at.to_rfc3339(),
            "description": curr_desc,
            "diff": diff,
            "change_type": "version_diff",
        }));
    }

    changelog_entries.reverse();

    // MCP-88 (2026-05-07): emit canonical `count` field. Sibling list
    // tools all carry it post-MCP-45.
    let result = serde_json::json!({
        "workflow_id": wf_id.to_string(),
        "count": changelog_entries.len(),
        "changelog": changelog_entries,
    });

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

async fn handle_validate_all_workflows(
    req_id: Option<serde_json::Value>,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let workflows = match state
        .analytics_repo
        .list_workflows_with_graphs(user_id)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!("validate_all_workflows query failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to load workflows");
        }
    };

    let mut valid_count = 0u32;
    let mut invalid_count = 0u32;
    let mut issues_list: Vec<serde_json::Value> = Vec::new();

    // Pre-load secret grants for all modules across all workflows in one batch
    // to avoid N+1 queries. Collect ALL distinct module IDs from ALL workflows upfront.
    let all_module_ids: Vec<uuid::Uuid> = {
        let mut ids = std::collections::HashSet::new();
        for wf_row in &workflows {
            let g: serde_json::Value =
                serde_json::from_str(&wf_row.graph_json.clone().unwrap_or_default())
                    .unwrap_or(serde_json::json!({"nodes":[]}));
            if let Some(ns) = g.get("nodes").and_then(|n| n.as_array()) {
                for n in ns {
                    if let Some(id) = n
                        .get("type")
                        .and_then(|v| v.as_str())
                        .and_then(|s| s.parse::<uuid::Uuid>().ok())
                    {
                        ids.insert(id);
                    }
                }
            }
        }
        ids.into_iter().collect()
    };

    // Batch-load effective allowed_secrets:
    // installed_secrets = wasm_modules (authoritative per-install override)
    // template_secrets  = node_templates (fallback when no wasm_modules entry exists)
    //
    // MCP-402 (2026-05-11): batch ALSO the existence checks. Pre-fix
    // `check_template_ids_exist` and `check_module_ids_exist` were
    // called INSIDE the per-workflow loop below, so a user with 500
    // workflows incurred 2 * 500 = 1000 extra DB roundtrips on
    // every `validate_all_workflows` call — even though the entire
    // set of module ids is already aggregated in `all_module_ids`
    // (see lines 1054-1073). The N+1 sat next to existing batching
    // for installed_secrets / template_secrets and was easy to miss.
    // Hoist both existence queries out of the loop so they each run
    // once; build a single `existing_modules` HashSet that the
    // per-workflow loop consults. Pure win — fewer queries, same
    // per-workflow validation logic.
    let (installed_secrets_batch, template_secrets_batch, existing_templates, existing_wasm) =
        if !all_module_ids.is_empty() {
            tokio::join!(
                state
                    .workflow_repo
                    .get_installed_secrets_by_template_ids(&all_module_ids, user_id),
                state.workflow_repo.get_templates_by_ids(&all_module_ids),
                state
                    .analytics_repo
                    .check_template_ids_exist(&all_module_ids),
                state.analytics_repo.check_module_ids_exist(&all_module_ids),
            )
        } else {
            (
                Ok(std::collections::HashMap::new()),
                Ok(vec![]),
                Ok(vec![]),
                Ok(vec![]),
            )
        };
    let installed_secrets_batch = installed_secrets_batch.unwrap_or_default();
    let template_secrets_batch: std::collections::HashMap<uuid::Uuid, Vec<String>> =
        template_secrets_batch
            .unwrap_or_default()
            .into_iter()
            .map(|r| (r.id, r.allowed_secrets))
            .collect();
    let existing_modules: std::collections::HashSet<uuid::Uuid> = existing_templates
        .unwrap_or_default()
        .into_iter()
        .chain(existing_wasm.unwrap_or_default())
        .collect();

    for wf_row in &workflows {
        let wf_id = wf_row.id;
        let wf_name = wf_row.name.clone();
        let graph_json_str: String = wf_row.graph_json.clone().unwrap_or_default();

        let graph: serde_json::Value = serde_json::from_str(&graph_json_str)
            .unwrap_or(serde_json::json!({"nodes":[],"edges":[]}));

        let mut wf_issues: Vec<String> = Vec::new();

        let nodes = graph
            .get("nodes")
            .and_then(|n| n.as_array())
            .cloned()
            .unwrap_or_default();
        let edges = graph
            .get("edges")
            .and_then(|e| e.as_array())
            .cloned()
            .unwrap_or_default();

        // Check module existence
        let module_ids: Vec<uuid::Uuid> = nodes
            .iter()
            .filter_map(|n| {
                n.get("type")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse().ok())
            })
            .collect();

        if !module_ids.is_empty() {
            // MCP-402: consult the pre-batched existence set.
            for mid in &module_ids {
                if !existing_modules.contains(mid) {
                    wf_issues.push(format!("Module '{}' not found", mid));
                }
            }
        }

        // Cycle detection using petgraph
        let node_ids: Vec<&str> = nodes
            .iter()
            .filter_map(|n| n.get("id").and_then(|v| v.as_str()))
            .collect();

        let node_index_map: std::collections::HashMap<&str, usize> = node_ids
            .iter()
            .enumerate()
            .map(|(i, id)| (*id, i))
            .collect();

        let mut digraph = petgraph::graph::DiGraph::<&str, ()>::new();
        let graph_indices: Vec<petgraph::graph::NodeIndex> =
            node_ids.iter().map(|id| digraph.add_node(id)).collect();

        for edge in &edges {
            let src = edge.get("source").and_then(|v| v.as_str()).unwrap_or("");
            let tgt = edge.get("target").and_then(|v| v.as_str()).unwrap_or("");
            if let (Some(&si), Some(&ti)) = (node_index_map.get(src), node_index_map.get(tgt)) {
                digraph.add_edge(graph_indices[si], graph_indices[ti], ());
            }
        }

        if petgraph::algo::is_cyclic_directed(&digraph) {
            wf_issues.push("Graph contains a cycle".to_string());
        }

        // Check for orphaned edges
        let node_id_set: std::collections::HashSet<&str> = node_ids.iter().copied().collect();
        for edge in &edges {
            let src = edge.get("source").and_then(|v| v.as_str()).unwrap_or("");
            let tgt = edge.get("target").and_then(|v| v.as_str()).unwrap_or("");
            if !node_id_set.contains(src) {
                wf_issues.push(format!("Edge source '{}' does not match any node", src));
            }
            if !node_id_set.contains(tgt) {
                wf_issues.push(format!("Edge target '{}' does not match any node", tgt));
            }
        }

        // Reachability analysis — detect nodes unreachable from any root.
        // Skip if a cycle was already found (the cycle itself is the structural problem).
        if !wf_issues.iter().any(|i| i.contains("cycle")) && nodes.len() > 1 {
            let mut reachable: std::collections::HashSet<petgraph::graph::NodeIndex> =
                std::collections::HashSet::new();
            for (&idx, _) in graph_indices.iter().zip(node_ids.iter()) {
                if digraph
                    .edges_directed(idx, petgraph::Direction::Incoming)
                    .next()
                    .is_none()
                {
                    let mut dfs = petgraph::visit::Dfs::new(&digraph, idx);
                    while let Some(visited) = dfs.next(&digraph) {
                        reachable.insert(visited);
                    }
                }
            }
            let unreachable: Vec<&str> = graph_indices
                .iter()
                .zip(node_ids.iter())
                .filter_map(|(&idx, &id)| {
                    if !reachable.contains(&idx) {
                        Some(id)
                    } else {
                        None
                    }
                })
                .collect();
            if !unreachable.is_empty() {
                wf_issues.push(format!(
                    "Unreachable node(s): [{}] — remove with update_workflow action:remove_node",
                    unreachable.join(", ")
                ));
            }
        }

        // Vault path × allowed_secrets checks using pre-loaded batch maps.
        // Detects: (1) malformed vault:// paths, (2) paths blocked by allowed_secrets.
        for node in &nodes {
            let node_id = node.get("id").and_then(|v| v.as_str()).unwrap_or("?");
            let Ok(mid) = node
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .parse::<uuid::Uuid>()
            else {
                continue;
            };

            // Prefer wasm_modules entry (operator override); fall back to node_templates default.
            let effective_secrets: Option<&Vec<String>> = installed_secrets_batch
                .get(&mid)
                .or_else(|| template_secrets_batch.get(&mid));
            let Some(allowed_secrets) = effective_secrets else {
                continue;
            };

            let has_wildcard = allowed_secrets.iter().any(|s| s == "*");

            let node_data = node.get("data").cloned().unwrap_or(serde_json::json!({}));
            let node_config = node_data
                .get("config")
                .cloned()
                .unwrap_or_else(|| node_data.clone());

            if let Some(cfg_obj) = node_config.as_object() {
                for (field_key, field_val) in cfg_obj {
                    if let Some(val_str) = field_val.as_str() {
                        if let Some(path) = val_str.strip_prefix("vault://") {
                            if path.is_empty() {
                                wf_issues.push(format!(
                                    "Node '{}' config field '{}' has empty vault:// reference \
                                     ('vault://'). Must be 'vault://path/to/key'.",
                                    node_id, field_key
                                ));
                                continue;
                            }
                            if path.starts_with("vault://") {
                                wf_issues.push(format!(
                                    "Node '{}' config field '{}' has nested vault:// prefix \
                                     ('{}'). Use single prefix: 'vault://path/to/key'.",
                                    node_id, field_key, val_str
                                ));
                                continue;
                            }
                            if !has_wildcard
                                && !crate::workflows::vault_path_permitted(path, allowed_secrets)
                            {
                                wf_issues.push(format!(
                                    "Node '{}' config field '{}' references vault path '{}' \
                                     blocked by allowed_secrets [{}]. Will fail with \
                                     'unauthorized' at runtime. Reinstall module with path \
                                     added to allowed_secrets.",
                                    node_id,
                                    field_key,
                                    path,
                                    if allowed_secrets.is_empty() {
                                        "deny-all".to_string()
                                    } else {
                                        allowed_secrets.join(", ")
                                    }
                                ));
                            }
                        }
                    }
                }
            }
        }

        if wf_issues.is_empty() {
            valid_count += 1;
        } else {
            invalid_count += 1;
            issues_list.push(serde_json::json!({
                "workflow_id": wf_id.to_string(),
                "workflow_name": wf_name,
                "issues": wf_issues,
            }));
        }
    }

    // MCP-110 (2026-05-08): emit canonical `count` alongside legacy
    // `total` for envelope consistency with list_workflows / list_executions.
    let total_workflows = valid_count + invalid_count;
    let result = serde_json::json!({
        "valid_count": valid_count,
        "invalid_count": invalid_count,
        "count": total_workflows,
        "total": total_workflows,
        "issues": issues_list,
    });

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

async fn handle_get_system_health(
    req_id: Option<serde_json::Value>,
    state: &McpState,
    user_id: Uuid,
    is_admin: bool,
) -> JsonRpcResponse {
    if !is_admin {
        return mcp_error(
            req_id,
            -32003,
            "Unauthorized: get_system_health requires admin capability",
        );
    }

    // Use a simple repo call as DB connectivity check
    let db_ok = state
        .analytics_repo
        .get_system_status_counts(user_id)
        .await
        .is_ok();

    let counts = match state.analytics_repo.get_system_status_counts(user_id).await {
        Ok(c) => c,
        Err(_) => return mcp_error(req_id, -32000, "Failed to fetch system health"),
    };

    let active_schedules = state
        .analytics_repo
        .count_active_schedules_for_user(user_id)
        .await
        .unwrap_or(0);
    let active_webhooks = state
        .analytics_repo
        .count_active_webhooks_for_user(user_id)
        .await
        .unwrap_or(0);
    let stale_executions = state
        .analytics_repo
        .count_stale_running_executions(user_id)
        .await
        .unwrap_or(0);
    let unack_alerts = state
        .analytics_repo
        .count_unacknowledged_alerts(user_id)
        .await
        .unwrap_or(0);

    let (hour_total, hour_failed) = state
        .analytics_repo
        .get_recent_exec_error_rate(user_id)
        .await
        .unwrap_or((0, 0));
    let failure_rate_pct = if hour_total > 0 {
        (hour_failed as f64 / hour_total as f64 * 100.0).round()
    } else {
        0.0
    };

    let (wasm_bytes, template_bytes) = state
        .analytics_repo
        .get_storage_bytes(user_id)
        .await
        .unwrap_or((0, 0));
    let total_wasm_bytes = wasm_bytes + template_bytes;
    let wasm_size_mb = total_wasm_bytes as f64 / (1024.0 * 1024.0);

    let result = serde_json::json!({
        "database_connected": db_ok,
        "total_workflows": counts.workflows,
        "total_modules": counts.modules + counts.templates,
        "total_executions": counts.executions,
        "active_schedules": active_schedules,
        "active_webhooks": active_webhooks,
        "stale_executions": stale_executions,
        "unacknowledged_alerts": unack_alerts,
        "recent_failure_rate": {
            "period": "last_hour",
            "total_executions": hour_total,
            "failed_executions": hour_failed,
            "failure_rate_pct": failure_rate_pct,
        },
        "disk_usage": {
            "total_wasm_bytes": total_wasm_bytes,
            "total_wasm_mb": format!("{:.2}", wasm_size_mb),
        },
    });

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

/// MCP-68: clean error truncation for the audit-trail prose preview.
/// Cuts at the last sentence boundary (`. `, `: `, `; `) within `max_chars`,
/// falling back to the last whitespace, then to the char-boundary cut. The
/// goal is to never end mid-word like "Job failed af...".
fn clean_truncate_error(error: &str, max_chars: usize) -> String {
    // talos_text_util::truncate_at_char_boundary is char-boundary safe but
    // doesn't respect word/sentence boundaries — wrap it.
    if error.chars().count() <= max_chars {
        return error.to_string();
    }
    let cut = talos_text_util::truncate_at_char_boundary(error, max_chars);
    // Look for clause boundaries first — they're the most natural cut.
    if let Some(idx) = cut
        .rfind(". ")
        .or_else(|| cut.rfind(": "))
        .or_else(|| cut.rfind("; "))
    {
        // Include the punctuation, drop the trailing space, append ellipsis.
        return format!("{}…", &cut[..idx + 1]);
    }
    // Fall back to the last whitespace boundary so we don't split a word.
    if let Some(idx) = cut.rfind(char::is_whitespace) {
        if idx > max_chars / 2 {
            return format!("{}…", &cut[..idx]);
        }
    }
    format!("{}…", cut)
}

async fn handle_get_workflow_audit_trail(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let limit: i64 = match crate::utils::validate_range_i64(args, "limit", 1, 100, 20, &req_id) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let wf_graph = match state
        .analytics_repo
        .get_workflow_for_analytics(wf_id, user_id)
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return mcp_error(req_id, -32000, "Workflow not found or access denied"),
        Err(e) => {
            tracing::error!("get_workflow_audit_trail: {}", e);
            return mcp_error(req_id, -32000, "Failed to fetch workflow");
        }
    };

    let wf_name = wf_graph.name.clone();
    let wf_created_at = wf_graph.created_at.unwrap_or_default();
    let wf_updated_at = wf_graph.updated_at.unwrap_or_default();

    let mut events: Vec<serde_json::Value> = Vec::new();

    events.push(serde_json::json!({
        "event_type": "workflow_created",
        "timestamp": wf_created_at.to_rfc3339(),
        "details": format!("Workflow '{}' created", wf_name),
    }));

    let version_rows = state
        .analytics_repo
        .list_workflow_versions_audit(wf_id, limit)
        .await
        .unwrap_or_default();

    for row in &version_rows {
        let version_number = row.version_number.unwrap_or(0);
        let description = row.description.clone();
        let published_at = row.published_at.unwrap_or_default();
        let is_active = row.is_active;

        events.push(serde_json::json!({
            "event_type": "version_published",
            "timestamp": published_at.to_rfc3339(),
            "details": format!(
                "Version {} published{}{}",
                version_number,
                if is_active { " (active)" } else { "" },
                description.map(|d| format!(": {}", d)).unwrap_or_default()
            ),
            "version_number": version_number,
        }));
    }

    let exec_rows = state
        .analytics_repo
        .list_executions_for_audit(wf_id, user_id, limit)
        .await
        .unwrap_or_default();

    for row in &exec_rows {
        let exec_id = row.id;
        let status = row.status.clone();
        let started_at = row.started_at.unwrap_or_default();
        let trigger_type = row.trigger_type.clone();
        let error_message = row.error_message.clone();

        // MCP-68 (2026-05-07): truncate the error preview at clause / word
        // boundaries instead of mid-character. Operators get a clean cut
        // ("Job failed after 2 attempts" → readable) and the structured
        // `error_preview` field surfaces alongside the prose `details` so
        // tooling can choose either. `execution_id` remains the canonical
        // way to drill into the full error via get_execution_logs.
        let trigger_label = trigger_type
            .as_ref()
            .map(|t| format!(", trigger: {}", t))
            .unwrap_or_default();
        let error_preview = error_message.as_ref().map(|e| clean_truncate_error(e, 140));

        let detail = match &error_preview {
            Some(p) => format!(
                "Execution {} ({}){}, error: {}",
                &exec_id.to_string()[..8],
                status,
                trigger_label,
                p,
            ),
            None => format!(
                "Execution {} ({}){}",
                &exec_id.to_string()[..8],
                status,
                trigger_label,
            ),
        };

        let mut event = serde_json::json!({
            "event_type": "execution_triggered",
            "timestamp": started_at.to_rfc3339(),
            "details": detail,
            "execution_id": exec_id.to_string(),
            "status": status,
        });
        if let Some(p) = error_preview {
            if let Some(map) = event.as_object_mut() {
                map.insert("error_preview".to_string(), serde_json::Value::String(p));
            }
        }
        events.push(event);
    }

    if wf_updated_at != wf_created_at {
        events.push(serde_json::json!({
            "event_type": "workflow_updated",
            "timestamp": wf_updated_at.to_rfc3339(),
            "details": "Workflow configuration last modified",
        }));
    }

    events.sort_by(|a, b| {
        let ta = a.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        let tb = b.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        tb.cmp(ta)
    });

    events.truncate(limit as usize);

    let result = serde_json::json!({
        "workflow_id": wf_id.to_string(),
        "workflow_name": wf_name,
        "count": events.len(),
        "event_count": events.len(),
        "events": events,
    });

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

async fn handle_get_workflow_sla_report(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let target_success_rate: f64 = match crate::utils::validate_range_f64(
        args,
        "target_success_rate",
        0.0,
        100.0,
        99.0,
        &req_id,
    ) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // target_max_duration_ms is open-ended on the upper side (very long-running
    // workflows are legitimate), but reject negative / zero values explicitly.
    //
    // MCP-333 (2026-05-11): pre-fix the `.and_then(|v| v.as_f64())` chain
    // collapsed wrong-type into None, which then fell back to 5000.0 ms.
    // A caller passing `target_max_duration_ms: "10000"` (string,
    // intending to override) silently got the 5s default — the SLA
    // violations_count below reports against the WRONG threshold, no
    // signal. Same MCP-318 wrong-type-silent-default family. Distinguish
    // absent / null (legitimate default) from wrong-type (loud reject).
    let target_max_duration_ms: f64 = match args.get("target_max_duration_ms") {
        None | Some(serde_json::Value::Null) => 5000.0,
        Some(v) => {
            match v.as_f64() {
                Some(n) if !n.is_finite() || n < 1.0 => {
                    return mcp_error(
                    req_id,
                    -32602,
                    &format!("Invalid 'target_max_duration_ms' value {n}: must be a finite number ≥ 1.0"),
                );
                }
                Some(n) => n,
                None => {
                    let kind = crate::utils::json_type_name(v);
                    return mcp_error(
                        req_id,
                        -32602,
                        &format!("target_max_duration_ms must be a number ≥ 1.0, got {kind}"),
                    );
                }
            }
        }
    };

    let days: i32 = match crate::utils::validate_range_i64(args, "days", 1, 90, 30, &req_id) {
        Ok(v) => v as i32,
        Err(resp) => return resp,
    };

    let wf = state
        .analytics_repo
        .get_workflow_for_analytics(wf_id, user_id)
        .await
        .unwrap_or(None);
    if wf.is_none() {
        return crate::utils::workflow_not_found_error(req_id);
    }

    let stats = match state
        .analytics_repo
        .get_exec_stats(wf_id, user_id, days)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("get_workflow_sla_report count query failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to fetch SLA data");
        }
    };

    let total = stats.total;
    let succeeded = stats.succeeded;

    let actual_success_rate = if total > 0 {
        (succeeded as f64 / total as f64) * 100.0
    } else {
        100.0
    };

    let lat = match state
        .analytics_repo
        .get_latency_percentiles_ms(wf_id, user_id, days)
        .await
    {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("get_workflow_sla_report percentile query failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to fetch SLA latency data");
        }
    };

    let (p50_ms, p95_ms, p99_ms) = (lat.p50_ms, lat.p95_ms, lat.p99_ms);

    // Count completed executions whose duration exceeded the target.
    // Pre-fix this was hardcoded to 0, which made the SLA report
    // misleading: p95/p99 could be 100x the target while
    // violations_count stayed at 0. Errors degrade to 0 with a
    // structured tracing event so operators can see the failure mode
    // rather than getting silent zeros.
    let violations_count: i64 = match state
        .analytics_repo
        .count_sla_duration_violations(wf_id, user_id, i64::from(days), target_max_duration_ms)
        .await
    {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(
                target: "talos_analytics",
                event_kind = "sla_violations_count_failed",
                workflow_id = %wf_id,
                error = %e,
                "count_sla_duration_violations failed; reporting 0"
            );
            0
        }
    };

    let success_rate_met = actual_success_rate >= target_success_rate;
    let duration_met = p99_ms.unwrap_or(0.0) <= target_max_duration_ms;
    let in_compliance = success_rate_met && duration_met;

    // MCP-4: warn when total_executions is too small for the target_success_rate
    // to be statistically meaningful. With N=13 samples, a single failure is
    // ~7.7% — a 99% target is statistically unmeetable in that regime, so the
    // resulting "compliance failure" is non-actionable.
    //
    // Math: smallest non-zero failure rate is 1/N. For the target to be
    // distinguishable from "one bad run", we need N ≥ 1/(1 - target/100).
    //   target=99 → need N ≥ 100
    //   target=95 → need N ≥ 20
    //   target=99.9 → need N ≥ 1000
    let min_n_for_target = if target_success_rate < 100.0 && target_success_rate > 0.0 {
        (1.0 / (1.0 - target_success_rate / 100.0)).ceil() as i64
    } else {
        0
    };
    // MCP-92 (2026-05-07): round percentile millis to 1 decimal so the
    // f64-conversion artifacts (e.g. 22205.164099999998 → 22205.2) don't
    // leak. Operates on Option<f64> (the percentile lookup returns None
    // when there are no completed executions in the window).
    let round_1dp_opt = |v: Option<f64>| -> Option<f64> {
        v.and_then(|f| {
            if f.is_finite() {
                Some((f * 10.0).round() / 10.0)
            } else {
                None
            }
        })
    };
    let mut result = serde_json::json!({
        "in_compliance": in_compliance,
        "success_rate": {
            "target": target_success_rate,
            "actual": talos_analytics_repository::format_percent(actual_success_rate),
            "met": success_rate_met,
        },
        "duration": {
            "target_ms": target_max_duration_ms,
            "p50": round_1dp_opt(p50_ms),
            "p95": round_1dp_opt(p95_ms),
            "p99": round_1dp_opt(p99_ms),
            "violations_count": violations_count,
        },
        "period_days": days,
        "total_executions": total,
    });
    if min_n_for_target > 0 && total < min_n_for_target {
        result["sample_size_warning"] = serde_json::json!(format!(
            "Sample size ({total}) is below the threshold ({min_n_for_target}) needed for a {target_success_rate}% target to be statistically meaningful. A single failure is {failure_pct:.1}% of {total} runs — verdict may not be actionable. Consider lowering target_success_rate, extending the days window, or accepting the verdict as advisory.",
            total = total,
            min_n_for_target = min_n_for_target,
            target_success_rate = target_success_rate,
            failure_pct = if total > 0 { 100.0 / total as f64 } else { 0.0 },
        ));
        result["min_n_for_meaningful_target"] = serde_json::json!(min_n_for_target);
    }

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

async fn handle_list_workflow_triggers(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // Verify ownership
    let wf = state
        .analytics_repo
        .get_workflow_for_analytics(wf_id, user_id)
        .await
        .unwrap_or(None);
    if wf.is_none() {
        return crate::utils::workflow_not_found_error(req_id);
    }

    // 1. Schedules
    let schedule_rows = state
        .analytics_repo
        .list_workflow_schedules(wf_id)
        .await
        .unwrap_or_default();
    // MCP-35 (2026-05-07): emit schedule_id + timezone +
    // last_triggered_at + next_trigger_at so callers chaining
    // list_workflow_triggers → get_schedule_health don't need a
    // separate list_schedules round-trip just to get schedule_id.
    let schedules: Vec<serde_json::Value> = schedule_rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "schedule_id": r.id.to_string(),
                "cron_expression": r.cron_expression,
                "is_enabled": r.is_enabled,
                "timezone": r.timezone,
                "last_triggered_at": r.last_triggered_at.map(|t| t.to_rfc3339()),
                "next_trigger_at": r.next_trigger_at.map(|t| t.to_rfc3339()),
            })
        })
        .collect();

    // 2. Webhooks: find module_ids in graph, then look up webhook_triggers
    let graph_json = state
        .analytics_repo
        .get_workflow_graph_json(wf_id, user_id)
        .await
        .unwrap_or(None);

    let mut webhook_module_ids: Vec<uuid::Uuid> = Vec::new();
    if let Some(ref gj) = graph_json {
        if let Ok(graph) = serde_json::from_str::<serde_json::Value>(gj) {
            if let Some(nodes) = graph.get("nodes").and_then(|n| n.as_array()) {
                for node in nodes {
                    if let Some(module_id_str) = node
                        .get("data")
                        .and_then(|d| d.get("module_id"))
                        .and_then(|v| v.as_str())
                    {
                        if let Ok(mid) = uuid::Uuid::parse_str(module_id_str) {
                            webhook_module_ids.push(mid);
                        }
                    }
                }
            }
        }
    }

    let webhooks: Vec<serde_json::Value> = if !webhook_module_ids.is_empty() {
        let webhook_rows = state
            .analytics_repo
            .list_webhooks_for_modules(&webhook_module_ids, wf_id)
            .await
            .unwrap_or_default();
        webhook_rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "webhook_id": r.id.to_string(),
                    "endpoint_path": r.endpoint_path,
                    "is_enabled": r.is_enabled,
                })
            })
            .collect()
    } else {
        Vec::new()
    };

    // 3. Parent workflows that reference this one as a sub_workflow.
    //
    // MCP-435 (2026-05-11): SQL-side LIKE filter via
    // `find_workflows_referencing_workflow_id`. Pre-fix this path
    // called `list_workflows_with_graphs(user_id)` (cap 500) and
    // substring-scanned all graph_json blobs in Rust — typical
    // result set 25MB+ for a user with 500 workflows, then 500-row
    // JSON deserialisation just to filter to ~20 matches. The
    // SQL-side LIKE with LIMIT 20 is a sequential scan but
    // PostgreSQL stops after 20 hits, returning only the matching
    // {id, name} pairs (~5KB total).
    let wf_id_str = wf_id.to_string();
    let parent_rows = state
        .analytics_repo
        .find_workflows_referencing_workflow_id(user_id, wf_id, &wf_id_str, 20)
        .await
        .unwrap_or_default();
    let parent_workflows: Vec<serde_json::Value> = parent_rows
        .iter()
        .map(|(id, name)| {
            serde_json::json!({
                "workflow_id": id.to_string(),
                "name": name,
            })
        })
        .collect();

    let manual_only = schedules.is_empty() && webhooks.is_empty() && parent_workflows.is_empty();

    // MCP-83 (2026-05-07): emit per-array counts + a derived
    // total_trigger_count so callers can answer "is this workflow
    // trigger-only / manual / multi-source" from one object lookup.
    // manual_only is preserved as a derived flag (and remains
    // consistent with total_trigger_count == 0 by definition).
    let result = serde_json::json!({
        "schedule_count": schedules.len(),
        "webhook_count": webhooks.len(),
        "parent_workflow_count": parent_workflows.len(),
        "total_trigger_count": schedules.len() + webhooks.len() + parent_workflows.len(),
        "schedules": schedules,
        "webhooks": webhooks,
        "parent_workflows": parent_workflows,
        "manual_only": manual_only,
    });

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

async fn handle_get_workflow_call_tree(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let root_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    // MCP-38 (2026-05-07): N-J validation matches the schema-declared
    // bound. Pre-fix the silent `.min(5)` clamp accepted out-of-range
    // values and silently truncated, hiding caller typos.
    let max_depth = match crate::utils::validate_range_u64(args, "max_depth", 1, 5, 3, &req_id) {
        Ok(v) => v as usize,
        Err(resp) => return resp,
    };

    // Recursive function to build call tree
    async fn build_call_tree(
        repo: &talos_analytics_repository::AnalyticsRepository,
        workflow_id: uuid::Uuid,
        user_id: uuid::Uuid,
        depth: usize,
        max_depth: usize,
        visited: &mut std::collections::HashSet<uuid::Uuid>,
    ) -> serde_json::Value {
        if visited.contains(&workflow_id) {
            return serde_json::json!({
                "id": workflow_id.to_string(),
                "circular_reference": true
            });
        }
        visited.insert(workflow_id);

        let row = repo
            .get_workflow_for_analytics(workflow_id, user_id)
            .await
            .unwrap_or(None);

        let (name, graph_json): (String, Option<String>) = match row {
            Some(r) => (r.name, r.graph_json),
            None => {
                return serde_json::json!({
                    "id": workflow_id.to_string(),
                    "error": "Workflow not found or access denied"
                })
            }
        };

        let mut nodes_count = 0usize;
        let mut sub_workflows = Vec::new();

        if let Some(ref gj) = graph_json {
            if let Ok(graph) = serde_json::from_str::<serde_json::Value>(gj) {
                if let Some(nodes) = graph.get("nodes").and_then(|n| n.as_array()) {
                    nodes_count = nodes.len();
                    if depth < max_depth {
                        for node in nodes {
                            let kind = node.get("kind").and_then(|k| k.as_str()).unwrap_or("");
                            if kind == "sub_workflow" {
                                if let Some(sub_id_str) = node
                                    .get("data")
                                    .and_then(|d| d.get("sub_workflow_id"))
                                    .and_then(|v| v.as_str())
                                {
                                    if let Ok(sub_id) = sub_id_str.parse::<uuid::Uuid>() {
                                        let child = Box::pin(build_call_tree(
                                            repo,
                                            sub_id,
                                            user_id,
                                            depth + 1,
                                            max_depth,
                                            visited,
                                        ))
                                        .await;
                                        sub_workflows.push(child);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        visited.remove(&workflow_id);

        // MCP-74 (2026-05-07): emit canonical `node_count` alongside the
        // legacy `nodes_count` (drift from `list_workflows`,
        // `find_similar_workflows`, etc., which use the singular form).
        serde_json::json!({
            "id": workflow_id.to_string(),
            "name": name,
            "node_count": nodes_count,
            "nodes_count": nodes_count,
            "sub_workflows": sub_workflows,
        })
    }

    let mut visited = std::collections::HashSet::new();
    let tree = build_call_tree(
        &state.analytics_repo,
        root_id,
        user_id,
        0,
        max_depth,
        &mut visited,
    )
    .await;
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&tree).unwrap_or_default(),
    )
}

async fn handle_get_all_workflow_stats(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let days: i32 = match crate::utils::validate_range_i64(args, "days", 1, 90, 7, &req_id) {
        Ok(v) => v as i32,
        Err(resp) => return resp,
    };

    match state
        .analytics_repo
        .list_workflow_stat_summaries(user_id, days, 50)
        .await
    {
        Ok(rows) => {
            // MCP-101 (2026-05-08): round avg_duration_secs to 2 decimals
            // (same round_2dp pattern as MCP-30 / MCP-79). Pre-fix this
            // emitted raw f64 from the SQL EXTRACT(EPOCH FROM ...) divide,
            // producing 16-digit drift like 20.367137142857143.
            let stats: Vec<serde_json::Value> = rows
                .iter()
                .map(|r| {
                    let avg = r.avg_duration_secs.unwrap_or(0.0);
                    let avg_rounded = if avg.is_finite() {
                        (avg * 100.0).round() / 100.0
                    } else {
                        0.0
                    };
                    serde_json::json!({
                        "workflow_id": r.id.to_string(),
                        "name": r.name,
                        "total": r.total,
                        "succeeded": r.succeeded,
                        "failed": r.failed,
                        "avg_duration_secs": avg_rounded,
                    })
                })
                .collect();
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "days": days,
                    "count": stats.len(),
                    "workflow_count": stats.len(),
                    "workflows": stats,
                }))
                .unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("Failed to fetch workflow stats: {}", e);
            mcp_error(req_id, -32000, "Failed to fetch workflow stats")
        }
    }
}

async fn handle_get_error_report(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // MCP-170 (2026-05-08): pre-check workflow ownership. Same
    // silent-not-found pattern as get_workflow_stats — pre-fix the
    // handler returned a synthetic {total_failures: 0, ...} envelope
    // for cross-tenant / unknown workflow_ids.
    if !state.workflow_repo.workflow_exists(wf_id, user_id).await {
        return crate::utils::workflow_not_found_error(req_id);
    }

    let days = match crate::utils::validate_range_i64(args, "days", 1, 90, 7, &req_id) {
        Ok(v) => v as i32,
        Err(resp) => return resp,
    };

    // Total failures in period
    let stats = state
        .analytics_repo
        .get_exec_stats(wf_id, user_id, days)
        .await
        .unwrap_or(talos_analytics_repository::ExecStats {
            total: 0,
            succeeded: 0,
            failed: 0,
            running: 0,
            avg_duration_secs: None,
        });
    let total_failures = stats.failed;

    // MCP-99 (2026-05-08): error fingerprints now carry `latest_at` so
    // operators can tell whether a fingerprint is fresh or stale.
    // Source rows are ordered by started_at DESC, so the FIRST row seen
    // for a fingerprint is the most recent occurrence. The fuel-bump
    // detector below still wants Vec<String>, so we keep both views.
    let error_rows = state
        .analytics_repo
        .get_error_messages_with_started_at(wf_id, user_id, days, 200)
        .await
        .unwrap_or_default();
    let error_msgs: Vec<String> = error_rows.iter().map(|(m, _)| m.clone()).collect();

    // HashMap<fingerprint, (count, latest_message, latest_at)> — keeping
    // the most-recent timestamp + message means the first row encountered
    // (rows are DESC-sorted) wins, and later rows just bump count.
    let mut fingerprint_groups: std::collections::HashMap<
        String,
        (usize, String, chrono::DateTime<chrono::Utc>),
    > = std::collections::HashMap::new();
    for (msg, started_at) in &error_rows {
        let fp = talos_analytics_repository::fingerprint_error_message(msg);
        match fingerprint_groups.get_mut(&fp) {
            Some(entry) => {
                entry.0 += 1;
                if *started_at > entry.2 {
                    entry.2 = *started_at;
                    entry.1 = msg.clone();
                }
            }
            None => {
                fingerprint_groups.insert(fp, (1, msg.clone(), *started_at));
            }
        }
    }

    let mut error_fingerprints: Vec<serde_json::Value> = fingerprint_groups
        .into_iter()
        .map(|(fp, (count, latest_msg, latest_at))| {
            serde_json::json!({
                "fingerprint": fp,
                "count": count,
                "latest_message": latest_msg,
                "latest_at": latest_at.to_rfc3339(),
            })
        })
        .collect();
    error_fingerprints.sort_by(|a, b| {
        let ca = a.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        let cb = b.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        cb.cmp(&ca)
    });
    error_fingerprints.truncate(10);

    // Node-level failure breakdown from execution_events
    let node_failures = state
        .analytics_repo
        .get_node_failure_counts(wf_id, user_id, days)
        .await
        .unwrap_or_default();

    // MCP-99 (2026-05-08): resolve node UUIDs to labels via the workflow
    // graph. Pre-fix this surface emitted bare synthetic UUIDs
    // (sha256-derived) which forced operators to cross-reference
    // get_workflow_graph manually. Sister tool `get_node_failure_breakdown`
    // already does the same resolution (per MCP-65); now this surface
    // matches.
    let graph_json_str = state
        .analytics_repo
        .get_workflow_graph_json(wf_id, user_id)
        .await
        .unwrap_or(None);
    let mut uuid_to_label: std::collections::HashMap<uuid::Uuid, String> =
        std::collections::HashMap::new();
    if let Some(gj) = graph_json_str {
        if let Ok(graph) = serde_json::from_str::<serde_json::Value>(&gj) {
            if let Some(nodes) = graph.get("nodes").and_then(|n| n.as_array()) {
                for node in nodes {
                    if let Some(node_id_str) = node.get("id").and_then(|v| v.as_str()) {
                        let node_uuid = uuid::Uuid::parse_str(node_id_str).unwrap_or_else(|_| {
                            use sha2::{Digest, Sha256};
                            let hash = Sha256::digest(node_id_str.as_bytes());
                            let mut bytes = [0u8; 16];
                            bytes.copy_from_slice(&hash[..16]);
                            uuid::Uuid::from_bytes(bytes)
                        });
                        let label = node
                            .get("data")
                            .and_then(|d| d.get("label"))
                            .and_then(|l| l.as_str())
                            .unwrap_or(node_id_str);
                        uuid_to_label.insert(node_uuid, label.to_string());
                    }
                }
            }
        }
    }

    let node_breakdown: Vec<serde_json::Value> = node_failures
        .iter()
        .map(|row| {
            let node_label = uuid_to_label
                .get(&row.node_id)
                .cloned()
                .unwrap_or_else(|| row.node_id.to_string());
            serde_json::json!({
                "node_id": row.node_id.to_string(),
                "node_label": node_label,
                "failure_count": row.fail_count,
            })
        })
        .collect();

    // Fuel-bump anti-pattern detection.
    //
    // Signal: a node fails with "WASM fuel exhausted" at *multiple distinct
    // limit values* across recent executions. This pattern means an operator
    // has been raising WASM_FUEL_LIMIT / max_fuel as a band-aid without fixing
    // the underlying code. Raising fuel on a node that consistently hits the
    // ceiling just postpones the failure — the correct fix is to optimize
    // module-side parsing (typed structs vs Value), split the work across
    // nodes, or reduce upstream payload size.
    //
    // Detection:
    //   - error matches "fuel exhausted" AND carries "Current fuel limit: N"
    //   - group by node label (extracted from "node 'X' failed" prefix)
    //   - flag nodes with ≥ 2 distinct limits (at least one bump) as WARN,
    //     ≥ 3 distinct limits as a strong anti-pattern signal
    let fuel_bump_antipatterns = detect_fuel_bump_antipattern(&error_msgs);

    // Time-of-day pattern: failures grouped by hour
    let hourly_rows = state
        .analytics_repo
        .get_hourly_failure_breakdown(wf_id, user_id, days)
        .await
        .unwrap_or_default();

    let hourly_pattern: Vec<serde_json::Value> = hourly_rows
        .iter()
        .map(|row| serde_json::json!({ "hour": row.hour, "failure_count": row.fail_count }))
        .collect();

    let mut result = serde_json::json!({
        "workflow_id": wf_id.to_string(),
        "period_days": days,
        "total_failures": total_failures,
        "error_fingerprints": error_fingerprints,
        "node_failure_breakdown": node_breakdown,
        "hourly_failure_pattern": hourly_pattern,
    });
    if !fuel_bump_antipatterns.is_empty() {
        result["fuel_bump_antipatterns"] = serde_json::Value::Array(fuel_bump_antipatterns);
    }

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

/// Detect the "fuel-bump band-aid" anti-pattern from raw error messages.
///
/// A single node failing repeatedly with `WASM fuel exhausted ... Current fuel
/// limit: N` at 2+ distinct limit values indicates an operator has been
/// raising the ceiling without fixing the root cause. Returns a list of
/// actionable findings — one per affected node — ordered by severity.
fn detect_fuel_bump_antipattern(error_msgs: &[String]) -> Vec<serde_json::Value> {
    static RE_FUEL_LIMIT: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"Current fuel limit:\s*(\d+)").expect("valid fuel limit regex")
    });
    static RE_NODE_LABEL: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"node '([^']+)' failed").expect("valid node label regex")
    });

    // node_label -> set of distinct fuel limits seen
    let mut per_node: std::collections::HashMap<String, std::collections::BTreeSet<u64>> =
        std::collections::HashMap::new();

    for msg in error_msgs {
        if !msg.contains("fuel exhausted") {
            continue;
        }
        let limit = match RE_FUEL_LIMIT
            .captures(msg)
            .and_then(|c| c.get(1))
            .and_then(|m| m.as_str().parse::<u64>().ok())
        {
            Some(n) => n,
            None => continue,
        };
        let label = RE_NODE_LABEL
            .captures(msg)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| "<unknown>".to_string());
        per_node.entry(label).or_default().insert(limit);
    }

    let mut findings: Vec<serde_json::Value> = per_node
        .into_iter()
        .filter(|(_, limits)| limits.len() >= 2)
        .map(|(node_label, limits)| {
            let limit_ladder: Vec<u64> = limits.iter().copied().collect();
            let severity = if limit_ladder.len() >= 3 {
                "high"
            } else {
                "medium"
            };
            let max_limit = limit_ladder.last().copied().unwrap_or(0);
            serde_json::json!({
                "node_label": node_label,
                "severity": severity,
                "distinct_fuel_limits": limit_ladder,
                "max_limit_reached": max_limit,
                "finding": "Fuel limit has been raised across multiple executions but the node still exhausts it.",
                "recommendation": "Raising fuel is a band-aid — the node consistently hits the ceiling. \
                                   Fix the root cause: (1) replace serde_json::Value with typed #[derive(Deserialize)] structs \
                                   (3–10× fuel reduction), (2) cap upstream input size, \
                                   (3) split the work across multiple nodes, or \
                                   (4) reduce payload via metadata-only API calls (e.g. Gmail format=metadata)."
            })
        })
        .collect();

    // Highest severity + biggest ladder first.
    findings.sort_by(|a, b| {
        let sa = a.get("severity").and_then(|v| v.as_str()).unwrap_or("");
        let sb = b.get("severity").and_then(|v| v.as_str()).unwrap_or("");
        let la = a
            .get("distinct_fuel_limits")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        let lb = b
            .get("distinct_fuel_limits")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        sb.cmp(sa).then_with(|| lb.cmp(&la))
    });
    findings
}

#[cfg(test)]
mod fuel_bump_tests {
    use super::detect_fuel_bump_antipattern;

    fn msg(node: &str, limit: u64) -> String {
        format!(
            "node '{}' failed: Job failed after 1 attempts: execution failure: WASM fuel exhausted after {} instructions. Your module ran out of computation budget. Current fuel limit: {} (configurable via WASM_FUEL_LIMIT).",
            node, limit, limit
        )
    }

    #[test]
    fn single_limit_is_not_antipattern() {
        let msgs = vec![
            msg("fetch-threads", 10_000_000),
            msg("fetch-threads", 10_000_000),
        ];
        assert!(detect_fuel_bump_antipattern(&msgs).is_empty());
    }

    #[test]
    fn two_distinct_limits_flagged_medium() {
        let msgs = vec![
            msg("fetch-threads", 10_000_000),
            msg("fetch-threads", 30_000_000),
        ];
        let out = detect_fuel_bump_antipattern(&msgs);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["severity"], "medium");
        assert_eq!(
            out[0]["distinct_fuel_limits"],
            serde_json::json!([10_000_000, 30_000_000])
        );
    }

    #[test]
    fn three_distinct_limits_flagged_high() {
        let msgs = vec![
            msg("fetch-threads", 1_000_000),
            msg("fetch-threads", 10_000_000),
            msg("fetch-threads", 30_000_000),
        ];
        let out = detect_fuel_bump_antipattern(&msgs);
        assert_eq!(out[0]["severity"], "high");
        assert_eq!(out[0]["max_limit_reached"], 30_000_000);
    }

    #[test]
    fn per_node_grouping() {
        let msgs = vec![
            msg("fetch-threads", 10_000_000),
            msg("fetch-threads", 30_000_000),
            msg("other-node", 5_000_000),
        ];
        // fetch-threads has 2 distinct limits (flagged); other-node has 1 (not flagged)
        let out = detect_fuel_bump_antipattern(&msgs);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["node_label"], "fetch-threads");
    }

    #[test]
    fn ignores_non_fuel_errors() {
        let msgs = vec![
            "node 'fetch-threads' failed: Gmail 401: token expired".to_string(),
            "node 'draft-replies' failed: Anthropic API error (HTTP 429)".to_string(),
        ];
        assert!(detect_fuel_bump_antipattern(&msgs).is_empty());
    }
}

/// Classify a lowercased error message as deterministic — i.e.
/// retrying with the SAME inputs will fail the SAME way and burn
/// LLM / compute budget for zero outcome. Used by
/// `suggest_retry_config` to flip the recommendation to no-retry
/// once ≥70% of failures fall in this bucket.
///
/// The original list (not found / invalid / unauthorized / forbidden)
/// missed the most common modern failure shapes: OUTPUT_SCHEMA
/// prompt-validation failures, WASM fuel exhaustion, compile errors,
/// and stale-cleanup ghosts. Each entry below ties to a real prod
/// observation; the unit tests below pin the patterns.
pub(crate) fn is_deterministic_failure(lower_msg: &str) -> bool {
    lower_msg.contains("output_schema enforcement fired")
        || (lower_msg.contains("required keys") && lower_msg.contains("got prose"))
        || lower_msg.contains("wasm fuel exhausted")
        || lower_msg.contains("fuel exhausted")
        || lower_msg.contains("compilation failed")
        || lower_msg.contains("compile error")
        || lower_msg.contains("auto-cleaned: execution stale")
        || lower_msg.contains("missing field")
        || lower_msg.contains("required field")
        || lower_msg.contains("not found")
        || lower_msg.contains("invalid")
        || lower_msg.contains("unauthorized")
        || lower_msg.contains("forbidden")
}

async fn handle_suggest_retry_config(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // MCP-199 (2026-05-08): pre-check workflow ownership. Pre-fix the
    // handler ran the user-scoped retry-history query directly, so a
    // non-existent / cross-tenant workflow_id returned a synthetic
    // "no execution history — module-type defaults" suggestion. Same
    // silent-not-found pattern as MCP-170.
    if !state.workflow_repo.workflow_exists(wf_id, user_id).await {
        return crate::utils::workflow_not_found_error(req_id);
    }

    // Load recent executions (last 30 days) via retry_config_executions
    let exec_rows = state
        .analytics_repo
        .get_retry_config_executions(wf_id, user_id)
        .await
        .unwrap_or_default();

    if exec_rows.is_empty() {
        // Cold-start path: no execution history yet. Infer defaults from module types.
        //
        // MCP-418 (2026-05-11): pre-fix this path called
        // `list_workflows_with_graphs(user_id)` (default cap 500) and
        // then `.find(|r| r.id == wf_id)` — loading up to 500 full
        // graph_json blobs (10-50MB result set typical) just to pick
        // the ONE we already authenticated above. Switch to the
        // single-row helper `get_workflow_graph_for_similarity` that
        // `find_similar_workflows` already uses (same user-scoped
        // ownership gate, exactly the field we need). Big perf win
        // on a path operators hit when asking "what retry config
        // should I use for this fresh workflow".
        let graph_str = state
            .workflow_repo
            .get_workflow_graph_for_similarity(wf_id, user_id)
            .await
            .unwrap_or(None);

        let module_ids: Vec<uuid::Uuid> = graph_str
            .as_deref()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
            .and_then(|g| g.get("nodes").and_then(|n| n.as_array()).cloned())
            .unwrap_or_default()
            .iter()
            .filter_map(|n| {
                n.get("type")
                    .and_then(|t| t.as_str())
                    .and_then(|s| s.parse().ok())
            })
            .collect();

        let module_names = state
            .analytics_repo
            .list_module_and_template_names(&module_ids)
            .await
            .unwrap_or_default();
        let name_lower_set: Vec<String> =
            module_names.iter().map(|m| m.name.to_lowercase()).collect();

        let has_llm = name_lower_set.iter().any(|n: &String| {
            n.contains("llm")
                || n.contains("claude")
                || n.contains("openai")
                || n.contains("gemini")
                || n.contains("inference")
        });
        let has_http = name_lower_set.iter().any(|n: &String| {
            n.contains("http")
                || n.contains("request")
                || n.contains("webhook")
                || n.contains("slack")
                || n.contains("github")
        });
        let has_db = name_lower_set.iter().any(|n: &String| {
            n.contains("database")
                || n.contains("postgres")
                || n.contains("sql")
                || n.contains("mysql")
        });
        let has_queue = name_lower_set.iter().any(|n: &String| {
            n.contains("queue")
                || n.contains("nats")
                || n.contains("messaging")
                || n.contains("kafka")
        });

        let (suggested_retry_count, suggested_backoff_ms, strategy, reasoning) = if has_llm {
            (3u32, 5000u64, "exponential_jitter", "LLM APIs are rate-limited (429) and occasionally overloaded — 3 retries with 5s base and jitter avoids retry storms.")
        } else if has_http {
            (3u32, 2000u64, "exponential", "HTTP services return transient 429/5xx — 3 retries with 2s exponential backoff is a safe default.")
        } else if has_db {
            (2u32, 500u64, "linear", "Database connection errors are usually transient — 2 retries with 500ms linear backoff avoids long delays.")
        } else if has_queue {
            (5u32, 1000u64, "exponential", "Message queue publish failures can be retried aggressively — 5 retries with 1s exponential backoff.")
        } else {
            (2u32, 1000u64, "linear", "No execution history available. 2 retries with 1s linear backoff is a conservative general default.")
        };

        return mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "workflow_id": wf_id.to_string(),
                "basis": "module_type_defaults",
                "note": "No execution history found — these are module-type-based defaults, not data-driven recommendations. Re-run after a few executions for a calibrated suggestion.",
                "detected_module_types": {
                    "llm": has_llm,
                    "http": has_http,
                    "database": has_db,
                    "queue": has_queue,
                },
                "suggested_retry_count": suggested_retry_count,
                "suggested_backoff_ms": suggested_backoff_ms,
                "suggested_strategy": strategy,
                "reasoning": reasoning,
                "apply_with": {
                    "tool": "update_node_config",
                    "hint": "Set retry_count and retry_backoff_ms on each node via update_node_config."
                }
            }))
            .unwrap_or_default(),
        );
    }

    let total = exec_rows.len();
    let mut failed = 0usize;
    let mut succeeded = 0usize;
    let mut timeout_errors = 0usize;
    let mut rate_limit_errors = 0usize;
    let mut deterministic_errors = 0usize;
    let mut error_messages: Vec<String> = Vec::new();

    for (status, error_msg) in &exec_rows {
        match status.as_str() {
            "completed" => succeeded += 1,
            "failed" => {
                failed += 1;
                if let Some(ref msg) = error_msg {
                    let lower = msg.to_lowercase();
                    if lower.contains("timeout")
                        || lower.contains("429")
                        || lower.contains("rate limit")
                    {
                        timeout_errors += 1;
                    }
                    if lower.contains("429")
                        || lower.contains("rate limit")
                        || lower.contains("too many")
                    {
                        rate_limit_errors += 1;
                    }
                    if is_deterministic_failure(&lower) {
                        deterministic_errors += 1;
                    }
                    error_messages.push(msg.clone());
                }
            }
            _ => {}
        }
    }

    let failure_rate = if total > 0 {
        failed as f64 / total as f64
    } else {
        0.0
    };
    let is_intermittent = succeeded > 0 && failed > 0;

    // MCP-58 (2026-05-07): the legacy `retry_condition` strings mixed
    // structured tokens with prose ("none - deterministic failures",
    // "on_any_failure - but investigate root cause"). Programmatic
    // consumers couldn't parse these without substring tricks. Split
    // into:
    //   `retry_condition` — one of a small enum
    //     ("none", "on_timeout_or_rate_limit", "on_any_failure")
    //   `retry_advisory` — optional human prose explaining the choice
    //   `error_class` — the dominant error category that drove the
    //     suggestion ("deterministic", "timeout_or_rate_limit",
    //     "intermittent", "all_failed", "all_succeeded")
    let mut reasoning = Vec::new();
    let mut suggested_retry_count: u32 = 0;
    let mut suggested_backoff_ms: u32 = 0;
    let mut retry_condition = "none";
    let mut retry_advisory: Option<&str> = None;
    let mut error_class = "all_succeeded";

    if deterministic_errors > 0 && deterministic_errors as f64 / failed.max(1) as f64 > 0.7 {
        reasoning.push(format!(
            "{} of {} failures appear deterministic (output_schema_violation, fuel_exhausted, compile_error, missing_field, not_found, invalid, unauthorized, or stale-cleanup). Retrying with the same inputs will fail the same way and burn LLM / compute budget. Fix the upstream cause first — see analyze_execution_failure for class-specific remediation.",
            deterministic_errors, failed
        ));
        suggested_retry_count = 0;
        retry_condition = "none";
        retry_advisory = Some(
            "Failures appear deterministic — retrying will not help. Fix the upstream cause first.",
        );
        error_class = "deterministic";
    } else if timeout_errors > 0 || rate_limit_errors > 0 {
        reasoning.push(format!(
            "Detected {} timeout/rate-limit errors out of {} failures. Exponential backoff recommended.",
            timeout_errors + rate_limit_errors, failed
        ));
        suggested_retry_count = 3;
        suggested_backoff_ms = if rate_limit_errors > timeout_errors {
            5000
        } else {
            2000
        };
        retry_condition = "on_timeout_or_rate_limit";
        error_class = "timeout_or_rate_limit";
    } else if is_intermittent {
        reasoning.push(format!(
            "Intermittent failures: {} succeeded, {} failed out of {} total ({:.0}% failure rate). Retry recommended.",
            succeeded, failed, total, failure_rate * 100.0
        ));
        suggested_retry_count = 3;
        suggested_backoff_ms = 1000;
        retry_condition = "on_any_failure";
        error_class = "intermittent";
    } else if failed == total {
        reasoning.push(format!(
            "All {} recent executions failed. This may be a systemic issue requiring investigation rather than retry.",
            total
        ));
        suggested_retry_count = 1;
        suggested_backoff_ms = 5000;
        retry_condition = "on_any_failure";
        retry_advisory = Some("Every recent run failed — likely systemic. Investigate root cause before relying on retry.");
        error_class = "all_failed";
    }

    if reasoning.is_empty() {
        reasoning.push(format!(
            "All {} recent executions succeeded. No retry needed.",
            total
        ));
    }

    let mut suggestion = serde_json::json!({
        "retry_count": suggested_retry_count,
        "retry_backoff_ms": suggested_backoff_ms,
        "retry_condition": retry_condition,
    });
    if let (Some(adv), Some(map)) = (retry_advisory, suggestion.as_object_mut()) {
        map.insert(
            "retry_advisory".to_string(),
            serde_json::Value::String(adv.to_string()),
        );
    }

    let result = serde_json::json!({
        "workflow_id": wf_id.to_string(),
        "analysis_period": "30 days",
        "total_executions": total,
        "succeeded": succeeded,
        "failed": failed,
        "failure_rate_percent": talos_analytics_repository::format_percent(failure_rate * 100.0),
        "error_class": error_class,
        "suggestion": suggestion,
        "reasoning": reasoning,
        "retry_condition_legend": {
            "none": "Disable retry. Use when failures are deterministic (same input → same outcome).",
            "on_timeout_or_rate_limit": "Retry only when the engine classifies the failure as a timeout or rate limit. Use exponential backoff.",
            "on_any_failure": "Retry on every failure regardless of class. Use only when failures are confirmed transient/intermittent.",
        },
    });

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

async fn handle_get_workflow_topology(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let graph_str = match state
        .analytics_repo
        .get_workflow_graph_json(wf_id, user_id)
        .await
    {
        Ok(Some(gj)) => gj,
        Ok(None) => return mcp_error(req_id, -32000, "Workflow not found or access denied"),
        Err(e) => {
            tracing::error!("get_workflow_topology query failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to fetch workflow");
        }
    };

    let graph: serde_json::Value =
        serde_json::from_str(&graph_str).unwrap_or(serde_json::json!({"nodes":[],"edges":[]}));

    let edges = graph
        .get("edges")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default();

    // Build adjacency list and in-degree map
    let node_ids = talos_workflow_repository::extract_node_id_strings(&graph);

    let mut adj: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    let mut in_degree: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    for id in &node_ids {
        adj.entry(id.clone()).or_default();
        in_degree.entry(id.clone()).or_insert(0);
    }

    for edge in &edges {
        let src = edge.get("source").and_then(|v| v.as_str()).unwrap_or("");
        let tgt = edge.get("target").and_then(|v| v.as_str()).unwrap_or("");
        if !src.is_empty() && !tgt.is_empty() {
            adj.entry(src.to_string())
                .or_default()
                .push(tgt.to_string());
            *in_degree.entry(tgt.to_string()).or_insert(0) += 1;
        }
    }

    // Topological sort with depth tracking (BFS / Kahn's algorithm)
    let mut queue: std::collections::VecDeque<(String, usize)> = std::collections::VecDeque::new();
    let mut depth_map: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    for (id, deg) in &in_degree {
        if *deg == 0 {
            queue.push_back((id.clone(), 0));
            depth_map.insert(id.clone(), 0);
        }
    }

    let mut max_depth: usize = 0;
    let mut processed = 0usize;

    while let Some((node, depth)) = queue.pop_front() {
        processed += 1;
        if depth > max_depth {
            max_depth = depth;
        }
        if let Some(neighbors) = adj.get(&node) {
            for neighbor in neighbors {
                let new_depth = depth + 1;
                // Use max depth for this neighbor (longest path)
                let current = depth_map.get(neighbor).copied().unwrap_or(0);
                if new_depth > current {
                    depth_map.insert(neighbor.clone(), new_depth);
                }
                let should_enqueue = if let Some(entry) = in_degree.get_mut(neighbor) {
                    *entry -= 1;
                    *entry == 0
                } else {
                    false
                };
                if should_enqueue {
                    let final_depth = depth_map.get(neighbor).copied().unwrap_or(new_depth);
                    queue.push_back((neighbor.clone(), final_depth));
                }
            }
        }
    }

    // Recalculate max_depth from depth_map
    max_depth = depth_map.values().copied().max().unwrap_or(0);
    let longest_path_length = max_depth;

    // Parallel width: max nodes at same depth
    let mut depth_counts: std::collections::HashMap<usize, usize> =
        std::collections::HashMap::new();
    for depth in depth_map.values() {
        *depth_counts.entry(*depth).or_insert(0) += 1;
    }
    let parallel_width = depth_counts.values().copied().max().unwrap_or(0);

    // Critical path: trace back from deepest nodes
    let mut critical_path: Vec<String> = Vec::new();
    {
        // Find node(s) at max depth, then trace backwards through predecessors at each depth
        let mut current_depth = max_depth;
        loop {
            let nodes_at_depth: Vec<String> = depth_map
                .iter()
                .filter(|(_, d)| **d == current_depth)
                .map(|(id, _)| id.clone())
                .collect();
            if let Some(node) = nodes_at_depth.first() {
                critical_path.push(node.clone());
            }
            if current_depth == 0 {
                break;
            }
            current_depth -= 1;
        }
        critical_path.reverse();
    }

    // Bottleneck potential: nodes with most incoming edges (fan-in)
    let mut fan_in: Vec<(String, usize)> = edges
        .iter()
        .filter_map(|e| crate::utils::json_optional_string(e, "target"))
        .fold(
            std::collections::HashMap::<String, usize>::new(),
            |mut acc, tgt| {
                *acc.entry(tgt).or_insert(0) += 1;
                acc
            },
        )
        .into_iter()
        .filter(|(_, count)| *count > 1)
        .collect();
    fan_in.sort_by_key(|b| std::cmp::Reverse(b.1));
    fan_in.truncate(10);

    // MCP-37 (2026-05-07): tag each fan-in point with whether the
    // target is a Collect node (the desired aggregation pattern) or a
    // regular node (the actual problem case). Pre-fix the response
    // labelled ALL fan-in points "bottleneck" — including legitimate
    // Collect targets, which is the desired pattern, not a problem.
    // Operators couldn't tell which entries were genuine warnings.
    let nodes_array = graph
        .get("nodes")
        .and_then(|n| n.as_array())
        .cloned()
        .unwrap_or_default();
    let is_collect_node = |id: &str| -> bool {
        nodes_array.iter().any(|n| {
            let matches = n.get("id").and_then(|v| v.as_str()) == Some(id);
            if !matches {
                return false;
            }
            let node_type = n.get("type").and_then(|v| v.as_str()).unwrap_or("");
            // system:collect is the engine built-in; catalog Collect nodes
            // have a UUID `type` and the name "Collect" in their template.
            node_type == "system:collect" || node_type.eq_ignore_ascii_case("collect")
        })
    };

    let fan_in_points: Vec<serde_json::Value> = fan_in
        .iter()
        .map(|(id, count)| {
            let has_collect = is_collect_node(id);
            serde_json::json!({
                "node_id": id,
                "incoming_edge_count": count,
                "has_collect_aggregator": has_collect,
                "is_potential_problem": !has_collect,
            })
        })
        .collect();

    let has_cycle = processed < node_ids.len();

    // MCP-37: surface BOTH the legacy `longest_path_length` (edge
    // count) AND the more-explicit `longest_path_edges` /
    // `longest_path_node_count` so callers don't have to guess which
    // unit "length" referred to. critical_path's len === node_count.
    // bottleneck_fan_in_points is preserved as a deprecated alias of
    // fan_in_points for back-compat.
    // MCP-84 (2026-05-07): surface the deprecated aliases explicitly so
    // operators reading the response can see what's legacy and migrate.
    // bottleneck_fan_in_points is byte-identical to fan_in_points (same
    // reason: pre-MCP-37 the structured field was bottleneck_*).
    // longest_path_length is the legacy edge count; longest_path_edges
    // is the canonical name post-MCP-37. All retained for back-compat.
    let result = serde_json::json!({
        "workflow_id": wf_id.to_string(),
        "total_nodes": node_ids.len(),
        "total_edges": edges.len(),
        "longest_path_length": longest_path_length,
        "longest_path_edges": longest_path_length,
        "longest_path_node_count": critical_path.len(),
        "parallel_width": parallel_width,
        "critical_path": critical_path,
        "fan_in_points": fan_in_points.clone(),
        "bottleneck_fan_in_points": fan_in_points,
        "has_cycle": has_cycle,
        "_deprecated_aliases": {
            "bottleneck_fan_in_points": "Renamed to fan_in_points in MCP-37. Both fields emit byte-identical data — prefer fan_in_points in new code; bottleneck_fan_in_points may be removed in a future release.",
            "longest_path_length": "Renamed to longest_path_edges in MCP-37 to disambiguate edge count from node count. longest_path_node_count is the per-MCP-37 sibling. Prefer the new names in new code.",
        },
    });

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

async fn handle_get_node_failure_breakdown(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let days = match crate::utils::validate_range_i64(args, "days", 1, 90, 7, &req_id) {
        Ok(v) => v as i32,
        Err(resp) => return resp,
    };

    // Load workflow graph_json to build UUID -> label mapping
    let graph_json_str = match state
        .analytics_repo
        .get_workflow_graph_json(wf_id, user_id)
        .await
    {
        Ok(Some(gj)) => gj,
        Ok(None) => return mcp_error(req_id, -32000, "Workflow not found or access denied"),
        Err(e) => {
            tracing::error!("get_node_failure_breakdown graph query failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to fetch workflow");
        }
    };

    // Build UUID -> label mapping using SHA-256 derivation (same as engine)
    let mut uuid_to_label: std::collections::HashMap<uuid::Uuid, String> =
        std::collections::HashMap::new();
    if let Ok(graph) = serde_json::from_str::<serde_json::Value>(&graph_json_str) {
        if let Some(nodes) = graph.get("nodes").and_then(|n| n.as_array()) {
            for node in nodes {
                if let Some(node_id_str) = node.get("id").and_then(|v| v.as_str()) {
                    let node_uuid = uuid::Uuid::parse_str(node_id_str).unwrap_or_else(|_| {
                        use sha2::{Digest, Sha256};
                        let hash = Sha256::digest(node_id_str.as_bytes());
                        let mut bytes = [0u8; 16];
                        bytes.copy_from_slice(&hash[..16]);
                        uuid::Uuid::from_bytes(bytes)
                    });
                    let label = node
                        .get("data")
                        .and_then(|d| d.get("label"))
                        .and_then(|l| l.as_str())
                        .unwrap_or(node_id_str);
                    uuid_to_label.insert(node_uuid, label.to_string());
                }
            }
        }
    }

    match state
        .analytics_repo
        .get_node_failure_details(wf_id, user_id, days)
        .await
    {
        Ok(rows) => {
            let breakdown: Vec<serde_json::Value> = rows
                .iter()
                .map(|row| {
                    let node_label = uuid_to_label
                        .get(&row.node_id)
                        .cloned()
                        .unwrap_or_else(|| row.node_id.to_string());
                    serde_json::json!({
                        "node_label": node_label,
                        "failure_count": row.fail_count,
                        "latest_error": row.latest_error,
                        "latest_at": row.latest_at.map(|t| t.to_rfc3339()),
                    })
                })
                .collect();

            // MCP-65 (2026-05-07): collapse repeat-error rows by fingerprint
            // so an operator looking at this surface sees "3 of 4 failures
            // share the same root cause" at a glance instead of reading 4×
            // 400-char error strings. Same fingerprint helper used in
            // alerts.rs::build_fingerprint_groups (MCP-7).
            let groups = build_node_failure_fingerprint_groups(&rows, &uuid_to_label);
            let total_failures: i64 = rows.iter().map(|r| r.fail_count).sum();

            let result = serde_json::json!({
                "workflow_id": wf_id.to_string(),
                "period_days": days,
                "affected_node_count": breakdown.len(),
                "total_failure_count": total_failures,
                "node_failures": breakdown,
                "groups": groups,
                "groups_note": "node_failures collapsed by fingerprint (UUIDs, timestamps, numeric tails, and long quoted strings normalized).",
            });
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&result).unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("get_node_failure_breakdown query failed: {}", e);
            mcp_error(req_id, -32000, "Failed to query node failure breakdown")
        }
    }
}

/// MCP-65: collapse `node_failures` rows by error-message fingerprint so
/// near-duplicate errors (only differing in UUIDs / timestamps / numeric
/// tails) are grouped. Same approach as `alerts::build_fingerprint_groups`.
fn build_node_failure_fingerprint_groups(
    rows: &[talos_analytics_repository::NodeFailureDetailRow],
    uuid_to_label: &std::collections::HashMap<uuid::Uuid, String>,
) -> Vec<serde_json::Value> {
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct Acc {
        node_count: usize,
        total_failures: i64,
        sample_node_label: String,
        sample_error: String,
        latest_at: Option<chrono::DateTime<chrono::Utc>>,
    }

    let mut by_fp: BTreeMap<String, Acc> = BTreeMap::new();
    for r in rows {
        let err = r.latest_error.as_deref().unwrap_or("");
        let fp = talos_analytics_repository::fingerprint_error_message(err);
        let label = uuid_to_label
            .get(&r.node_id)
            .cloned()
            .unwrap_or_else(|| r.node_id.to_string());
        let entry = by_fp.entry(fp).or_default();
        entry.node_count += 1;
        entry.total_failures += r.fail_count;
        if entry.sample_node_label.is_empty() {
            entry.sample_node_label = label;
            entry.sample_error = err.to_string();
        }
        match (entry.latest_at, r.latest_at) {
            (None, Some(t)) => entry.latest_at = Some(t),
            (Some(prev), Some(t)) if t > prev => entry.latest_at = Some(t),
            _ => {}
        }
    }

    let mut groups: Vec<serde_json::Value> = by_fp
        .into_iter()
        .map(|(fp, acc)| {
            serde_json::json!({
                "fingerprint": fp,
                "node_count": acc.node_count,
                "total_failure_count": acc.total_failures,
                "sample_node_label": acc.sample_node_label,
                "sample_error": acc.sample_error,
                "latest_at": acc.latest_at.map(|t| t.to_rfc3339()),
            })
        })
        .collect();
    // Most-impactful group first (by total failures, then node count).
    groups.sort_by(|a, b| {
        let af = a
            .get("total_failure_count")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let bf = b
            .get("total_failure_count")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        bf.cmp(&af).then_with(|| {
            let an = a.get("node_count").and_then(|v| v.as_i64()).unwrap_or(0);
            let bn = b.get("node_count").and_then(|v| v.as_i64()).unwrap_or(0);
            bn.cmp(&an)
        })
    });
    groups
}

async fn handle_get_workflow_dependency_map(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let _ = args;
    let rows = match state
        .analytics_repo
        .list_workflows_with_graphs(user_id)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("get_workflow_dependency_map query failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to load workflows");
        }
    };

    // MCP-66 (2026-05-07): collect workflow names + module ids per workflow
    // first; emit cross-references as `[{id, name}, ...]` in BOTH directions
    // so callers don't have to do the lookup roundtrip themselves.
    let mut module_usage: std::collections::HashMap<String, Vec<(String, String)>> =
        std::collections::HashMap::new();
    let mut workflow_module_links: Vec<(uuid::Uuid, String, Vec<String>)> = Vec::new();

    for row in &rows {
        let wf_id = row.id;
        let wf_name = row.name.clone();
        let graph_json: Option<&String> = row.graph_json.as_ref();

        let mut module_ids = Vec::new();
        if let Some(gj) = graph_json {
            if let Ok(graph) = serde_json::from_str::<serde_json::Value>(gj) {
                if let Some(nodes) = graph.get("nodes").and_then(|n| n.as_array()) {
                    for node in nodes {
                        let module_id_str = node
                            .get("type")
                            .and_then(|v| v.as_str())
                            .filter(|s| uuid::Uuid::parse_str(s).is_ok())
                            .or_else(|| {
                                node.get("data")
                                    .and_then(|d| d.get("moduleId"))
                                    .and_then(|v| v.as_str())
                            });
                        if let Some(mid) = module_id_str {
                            if !module_ids.contains(&mid.to_string()) {
                                module_ids.push(mid.to_string());
                            }
                            module_usage
                                .entry(mid.to_string())
                                .or_default()
                                .push((wf_id.to_string(), wf_name.clone()));
                        }
                    }
                }
            }
        }

        workflow_module_links.push((wf_id, wf_name, module_ids));
    }

    // Resolve module names in one batch
    let module_ids_flat: Vec<uuid::Uuid> = module_usage
        .keys()
        .filter_map(|id| id.parse().ok())
        .collect();

    let mut module_names: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    if !module_ids_flat.is_empty() {
        let name_rows = state
            .analytics_repo
            .list_module_and_template_names(&module_ids_flat)
            .await
            .unwrap_or_default();
        for nr in &name_rows {
            module_names.insert(nr.id.to_string(), nr.name.clone());
        }
    }

    // Render workflows with hydrated module references.
    let workflows_list: Vec<serde_json::Value> = workflow_module_links
        .iter()
        .map(|(wf_id, wf_name, mids)| {
            let uses: Vec<serde_json::Value> = mids
                .iter()
                .map(|mid| {
                    serde_json::json!({
                        "id": mid,
                        "name": module_names.get(mid).cloned().unwrap_or_else(|| "unknown".to_string()),
                    })
                })
                .collect();
            serde_json::json!({
                "id": wf_id.to_string(),
                "name": wf_name,
                "uses_modules": uses,
            })
        })
        .collect();

    let modules_list: Vec<serde_json::Value> = module_usage
        .iter()
        .map(|(mid, wf_links)| {
            // De-dupe used_by_workflows entries (a workflow can reference
            // a module via multiple nodes; we want one row per workflow).
            let mut seen = std::collections::HashSet::new();
            let used_by: Vec<serde_json::Value> = wf_links
                .iter()
                .filter(|(wid, _)| seen.insert(wid.clone()))
                .map(|(wid, wname)| serde_json::json!({ "id": wid, "name": wname }))
                .collect();
            serde_json::json!({
                "id": mid,
                "name": module_names.get(mid).cloned().unwrap_or_else(|| "unknown".to_string()),
                "used_by_workflows": used_by,
            })
        })
        .collect();

    let result = serde_json::json!({
        "module_count": modules_list.len(),
        "workflow_count": workflows_list.len(),
        "modules": modules_list,
        "workflows": workflows_list,
    });
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

async fn handle_get_workflow_performance_report(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let days: i32 = match crate::utils::validate_range_i64(args, "days", 1, 90, 7, &req_id) {
        Ok(v) => v as i32,
        Err(resp) => return resp,
    };

    // Verify workflow ownership and capture graph for node filtering
    let wf_row = match state
        .analytics_repo
        .get_workflow_for_analytics(wf_id, user_id)
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return mcp_error(req_id, -32000, "Workflow not found or access denied"),
        Err(e) => {
            tracing::error!(
                "get_workflow_performance_report workflow lookup failed: {}",
                e
            );
            return mcp_error(req_id, -32000, "Failed to fetch workflow");
        }
    };
    let wf_name = wf_row.name.clone();

    // Build set of node IDs from this workflow's graph to filter out sub-workflow node IDs
    let wf_node_ids: std::collections::HashSet<String> = wf_row
        .graph_json
        .as_deref()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
        .map(|g| {
            talos_workflow_repository::extract_node_id_strings(&g)
                .into_iter()
                .collect()
        })
        .unwrap_or_default();

    // p50/p95/p99 latency
    let perf = match state
        .analytics_repo
        .get_performance_metrics(wf_id, user_id, days)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(
                "get_workflow_performance_report percentile query failed: {}",
                e
            );
            return mcp_error(req_id, -32000, "Failed to fetch performance data");
        }
    };
    let total = perf.total;
    // MCP-49 (2026-05-07): cap latency precision at 2 decimals — pre-fix
    // p95_ms emitted f64 from SQL percentile_cont with values like
    // 22205.164099999998 (12 decimals). Same shape as MCP-30 +
    // get_execution_cost.avg_node_time_ms.
    let round_2dp = |v: Option<f64>| {
        v.map(|x| {
            if x.is_finite() {
                (x * 100.0).round() / 100.0
            } else {
                0.0
            }
        })
    };
    let p50_ms = round_2dp(perf.p50_ms);
    let p95_ms = round_2dp(perf.p95_ms);
    let p99_ms = round_2dp(perf.p99_ms);
    let avg_ms = round_2dp(perf.avg_ms);

    // Per-node timing breakdown from output_data containing __node_timings__.
    // IMPORTANT: scoped to wf_id so node data from other workflows cannot pollute this report.
    let timing_rows = state
        .analytics_repo
        .get_completed_executions_output(wf_id, user_id, days, 50)
        .await
        .unwrap_or_default();

    let mut node_timing_sums: std::collections::HashMap<String, (f64, usize)> =
        std::collections::HashMap::new();
    for output_val in &timing_rows {
        if let Some(timings) = output_val
            .get("__node_timings__")
            .and_then(|t| t.as_object())
        {
            for (node_id, timing_val) in timings {
                // Skip node IDs from sub-workflows that leaked into __node_timings__
                if !wf_node_ids.is_empty() && !wf_node_ids.contains(node_id) {
                    continue;
                }
                if let Some(ms) = timing_val.as_f64() {
                    let entry = node_timing_sums.entry(node_id.clone()).or_insert((0.0, 0));
                    entry.0 += ms;
                    entry.1 += 1;
                }
            }
        }
    }

    let mut node_breakdown: Vec<serde_json::Value> = {
        let mut items: Vec<(String, f64)> = node_timing_sums
            .iter()
            .map(|(node_id, (sum, count))| (node_id.clone(), sum / *count as f64))
            .collect();
        items.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        items
            .into_iter()
            .map(|(node_id, avg_ms)| {
                // MCP-49: avg_duration_ms emits a JSON number, not
                // a quoted string (matches latency.* and
                // total_node_time_ms in get_execution_cost).
                let rounded = if avg_ms.is_finite() {
                    (avg_ms * 100.0).round() / 100.0
                } else {
                    0.0
                };
                serde_json::json!({
                    "node_id": node_id,
                    "avg_duration_ms": rounded,
                })
            })
            .collect()
    };

    // MCP-50 (2026-05-07): when output_data.__node_timings__ is
    // empty (engine path not stamping it — the daily-brief case)
    // fall back to execution_cost_rollup which is the canonical
    // per-node timing record. Pre-fix node_timing_breakdown
    // returned [] for any workflow whose engine didn't emit
    // __node_timings__ even when execution_cost_rollup had every
    // node populated.
    if node_breakdown.is_empty() {
        if let Ok(rollup_rows) = state
            .analytics_repo
            .get_workflow_node_timing_breakdown(wf_id, user_id, days)
            .await
        {
            node_breakdown = rollup_rows
                .into_iter()
                .map(|(node_label, avg_ms, sample_count)| {
                    let rounded = if avg_ms.is_finite() {
                        (avg_ms * 100.0).round() / 100.0
                    } else {
                        0.0
                    };
                    serde_json::json!({
                        "node_id": node_label,
                        "avg_duration_ms": rounded,
                        "sample_count": sample_count,
                        "source": "execution_cost_rollup",
                    })
                })
                .collect();
        }
    }

    // Slowest + fastest completed executions in the period. Pre-fix
    // these were hardcoded `None` with a "not available via repo"
    // comment, which made the response misleading: the docstring
    // promised the fields, the handler always returned null. Now
    // sourced from `AnalyticsRepository::get_extreme_executions`.
    let (slowest, fastest) = match state
        .analytics_repo
        .get_extreme_executions(wf_id, user_id, i64::from(days))
        .await
    {
        Ok((s, f)) => {
            let to_json = |e: talos_analytics_repository::ExtremeExecution| {
                serde_json::json!({
                    "execution_id": e.id.to_string(),
                    "started_at": e.started_at.to_rfc3339(),
                    "duration_ms": e.duration_ms.round() as i64,
                })
            };
            (s.map(to_json), f.map(to_json))
        }
        Err(e) => {
            tracing::warn!(
                target: "talos_analytics",
                event_kind = "performance_extremes_failed",
                workflow_id = %wf_id,
                error = %e,
                "get_extreme_executions failed; slowest/fastest will be null"
            );
            (None, None)
        }
    };

    // Performance trend: compare last 24h avg to previous 24h avg
    let trend = match state
        .analytics_repo
        .get_performance_trend(wf_id, user_id)
        .await
    {
        Ok((recent, previous)) => match (recent, previous) {
            (Some(r), Some(p)) if p > 0.0 => {
                let change_pct = ((r - p) / p) * 100.0;
                if change_pct < -10.0 {
                    "improving"
                } else if change_pct > 10.0 {
                    "degrading"
                } else {
                    "stable"
                }
            }
            _ => "insufficient_data",
        },
        Err(_) => "insufficient_data",
    };

    let result = serde_json::json!({
        "workflow_name": wf_name,
        "period_days": days,
        "total_completed_executions": total,
        "latency": {
            "p50_ms": p50_ms,
            "p95_ms": p95_ms,
            "p99_ms": p99_ms,
            "avg_ms": avg_ms,
        },
        "node_timing_breakdown": node_breakdown,
        "slowest_execution": slowest,
        "fastest_execution": fastest,
        "performance_trend": trend,
        "see_also": "For a visual text-based waterfall chart showing parallel execution timing, use get_execution_waterfall(execution_id: <id>) on a recent execution.",
    });

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

async fn handle_get_workflow_risk_assessment(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // Load workflow graph + metadata for documentation checks
    let wf_full = match state.analytics_repo.get_workflow_full(wf_id, user_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return mcp_error(req_id, -32000, "Workflow not found or access denied"),
        Err(e) => {
            tracing::error!("get_workflow_risk_assessment workflow lookup failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to fetch workflow");
        }
    };
    let wf_name: String = wf_full.name;
    let graph_json_str: String = wf_full.graph_json.unwrap_or_default();
    let wf_description: Option<String> = wf_full.description;
    let wf_capabilities: Option<Vec<String>> = wf_full.capabilities;
    let wf_intent: Option<serde_json::Value> =
        wf_full.intent.and_then(|s| serde_json::from_str(&s).ok());

    let graph: serde_json::Value =
        serde_json::from_str(&graph_json_str).unwrap_or(serde_json::json!({"nodes":[],"edges":[]}));

    let nodes = graph
        .get("nodes")
        .and_then(|n| n.as_array())
        .cloned()
        .unwrap_or_default();
    let edges = graph
        .get("edges")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default();

    let mut risks: Vec<serde_json::Value> = Vec::new();

    // Check: No timeout configured
    let has_timeout = graph
        .get("execution_timeout_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
        > 0;
    if !has_timeout {
        risks.push(serde_json::json!({
            "risk_level": "medium",
            "category": "timeout",
            "description": "Workflow has no execution timeout configured",
            "recommendation": "Set execution_timeout_secs to prevent runaway executions. Use update_node_config or recreate the workflow with a timeout."
        }));
    }

    // Check: Nodes without retry config
    // Get template names/categories for nodes to identify HTTP-calling nodes
    let module_ids: Vec<uuid::Uuid> = nodes
        .iter()
        .filter_map(|n| {
            n.get("type")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
        })
        .collect();

    // Load module metadata in parallel:
    // - template_info: name + category (from node_templates) for retry/HTTP checks
    // - installed_secrets: per-install wasm_modules.allowed_secrets (authoritative override)
    // - template_rows: node_templates.allowed_secrets (fallback when no wasm_modules entry)
    //
    // Both installed_secrets and template_rows are needed because wasm_modules may not have
    // an entry (e.g. if the wasm_modules insert failed silently, or if user_id was NULL at
    // install time). Using node_templates as a fallback matches validate_workflow's behavior.
    let (template_info_vec, installed_secrets_res, template_rows_res) = if !module_ids.is_empty() {
        tokio::join!(
            state.analytics_repo.get_risk_module_categories(&module_ids),
            state
                .workflow_repo
                .get_installed_secrets_by_template_ids(&module_ids, user_id),
            state.workflow_repo.get_templates_by_ids(&module_ids),
        )
    } else {
        (Ok(vec![]), Ok(std::collections::HashMap::new()), Ok(vec![]))
    };

    let template_info: std::collections::HashMap<uuid::Uuid, (String, String)> = template_info_vec
        .unwrap_or_default()
        .into_iter()
        .map(|(id, name, cat)| (id, (name, cat.unwrap_or_else(|| "unknown".to_string()))))
        .collect();

    let installed_secrets = installed_secrets_res.unwrap_or_default();

    // Build fallback map: template_id → allowed_secrets from node_templates.
    // Prefer installed_secrets (wasm_modules) over this fallback.
    let template_secrets: std::collections::HashMap<uuid::Uuid, Vec<String>> = template_rows_res
        .unwrap_or_default()
        .into_iter()
        .map(|r| (r.id, r.allowed_secrets))
        .collect();

    for node in &nodes {
        let node_id = node.get("id").and_then(|v| v.as_str()).unwrap_or("?");
        let module_id_str = node.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let has_retry = node
            .get("retry_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
            > 0;

        if let Ok(mid) = module_id_str.parse::<uuid::Uuid>() {
            if let Some((tmpl_name, tmpl_cat)) = template_info.get(&mid) {
                // MCP-1142 (2026-05-16): hoist the `tmpl_name.to_lowercase()`
                // clone out of the boolean chain. Pre-fix called
                // `.to_lowercase()` THREE times in succession on the same
                // input — same anti-pattern as MCP-1139 (rhai bare-string
                // heuristic, two clones) and MCP-1140 (placeholder warning
                // helper, three clones). `tmpl_name` is bounded by template-
                // name validation so absolute cost is small, but the shape
                // recurs workspace-wide and is part of the running sweep.
                // Per-call: 3 heap clones + 3 case-walk passes → 1 clone +
                // 1 walk + 3 substring scans on the cached lowercase form.
                let tmpl_name_lower = tmpl_name.to_lowercase();
                let is_http = tmpl_cat.contains("http")
                    || tmpl_name_lower.contains("http")
                    || tmpl_name_lower.contains("api")
                    || tmpl_name_lower.contains("request")
                    || tmpl_cat.contains("network");
                if is_http && !has_retry {
                    risks.push(serde_json::json!({
                        "risk_level": "high",
                        "category": "missing_retry",
                        "description": format!("Node '{}' uses HTTP module '{}' but has no retry config", node_id, tmpl_name),
                        "recommendation": "Add retry_count and retry_backoff_ms using update_node_config to handle transient network failures."
                    }));
                }
            }
        }
    }

    // Check: Missing error edges (nodes with no outgoing error edge)
    let error_edge_sources: std::collections::HashSet<String> = edges
        .iter()
        .filter(|e| {
            e.get("edge_type").and_then(|v| v.as_str()) == Some("error")
                || e.get("condition")
                    .and_then(|v| v.as_str())
                    .map(|c| c.contains("error") || c.contains("fail"))
                    .unwrap_or(false)
        })
        .filter_map(|e| crate::utils::json_optional_string(e, "source"))
        .collect();

    for node in &nodes {
        let node_id = node.get("id").and_then(|v| v.as_str()).unwrap_or("?");
        // Skip terminal nodes (no outgoing edges at all is fine if it's the last node)
        let has_outgoing = edges
            .iter()
            .any(|e| e.get("source").and_then(|v| v.as_str()) == Some(node_id));
        if has_outgoing && !error_edge_sources.contains(node_id) {
            risks.push(serde_json::json!({
                "risk_level": "low",
                "category": "missing_error_edge",
                "description": format!("Node '{}' has outgoing edges but no error handling path", node_id),
                "recommendation": "Add an error edge to handle failures gracefully instead of failing the entire workflow."
            }));
        }
    }

    // Check: continue_on_error nodes (failures silently swallowed)
    for node in &nodes {
        let node_id = node.get("id").and_then(|v| v.as_str()).unwrap_or("?");
        let coe = node
            .get("continue_on_error")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
            || node
                .get("data")
                .and_then(|d| d.get("continue_on_error"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
        if coe {
            risks.push(serde_json::json!({
                "risk_level": "low",
                "category": "continue_on_error",
                "node_id": node_id,
                "description": format!("Node '{}' has continue_on_error: true — failures are silently swallowed and execution continues", node_id),
                "recommendation": "Verify downstream nodes handle error input correctly. Consider using an error edge instead for explicit failure routing."
            }));
        }
    }

    // Check: Modules not updated in >90 days
    if !module_ids.is_empty() {
        let stale_ids = state
            .analytics_repo
            .get_risk_stale_templates(&module_ids)
            .await
            .unwrap_or_default();
        // template_info already loaded: use it to map stale ids to names
        for stale_id in &stale_ids {
            let name = template_info
                .get(stale_id)
                .map(|(n, _)| n.as_str())
                .unwrap_or("unknown");
            risks.push(serde_json::json!({
                "risk_level": "medium",
                "category": "stale_module",
                "description": format!("Module '{}' has not been updated in over 90 days", name),
                "recommendation": "Review and update the module to ensure it still works correctly with current APIs."
            }));
        }
    }

    // Check: Secrets expiring within 30 days
    let expiring_secrets = state
        .analytics_repo
        .get_risk_expiring_secrets(user_id)
        .await
        .unwrap_or_default();
    for (name, expires_at) in &expiring_secrets {
        risks.push(serde_json::json!({
            "risk_level": "high",
            "category": "expiring_secret",
            "description": format!("Secret '{}' expires on {}", name, expires_at.format("%Y-%m-%d")),
            "recommendation": "Rotate the secret before it expires to avoid workflow failures."
        }));
    }

    // Check: Sub-workflow failure rates.
    //
    // Pre-collect every sub-workflow ID referenced by node.data.workflow_id,
    // then batch-fetch 7-day exec counts in a single query. Replaces the
    // prior per-node `get_risk_exec_counts` round-trip — N+1 → 1+1 — and
    // adds user_id scoping so the lookup can't indirectly leak counts for
    // a workflow that doesn't belong to the caller.
    let sub_wf_ids: Vec<uuid::Uuid> = nodes
        .iter()
        .filter_map(|node| {
            node.get("data")
                .and_then(|d| d.as_object())
                .and_then(|data| data.get("workflow_id"))
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<uuid::Uuid>().ok())
        })
        .collect::<std::collections::HashSet<_>>() // de-dupe before fetch
        .into_iter()
        .collect();
    let exec_counts = state
        .analytics_repo
        .get_risk_exec_counts_for_ids(&sub_wf_ids, user_id)
        .await
        .unwrap_or_default();
    for sub_wf_id in &sub_wf_ids {
        let (failed, total) = match exec_counts.get(sub_wf_id) {
            Some(t) => *t,
            None => continue, // no executions in window or not user-owned
        };
        if total <= 0 {
            continue;
        }
        let fail_rate = (failed as f64 / total as f64) * 100.0;
        if fail_rate > 20.0 {
            risks.push(serde_json::json!({
                "risk_level": "high",
                "category": "high_failure_sub_workflow",
                "description": format!(
                    "Sub-workflow {} has {:.0}% failure rate ({}/{} in last 7 days)",
                    sub_wf_id, fail_rate, failed, total
                ),
                "recommendation": "Investigate and fix the sub-workflow before it causes cascading failures."
            }));
        }
    }

    // Check: No workflow description
    if wf_description.as_deref().unwrap_or("").trim().is_empty() {
        risks.push(serde_json::json!({
            "risk_level": "medium",
            "category": "no_description",
            "description": "Workflow has no description set",
            "recommendation": "Add a description with set_workflow_description"
        }));
    }

    // Check: No capability tags
    let has_capabilities = wf_capabilities
        .as_ref()
        .map(|c| !c.is_empty())
        .unwrap_or(false);
    if !has_capabilities {
        risks.push(serde_json::json!({
            "risk_level": "low",
            "category": "no_capabilities",
            "description": "Workflow has no capability tags set",
            "recommendation": "Run suggest_capabilities then set_workflow_capabilities"
        }));
    }

    // Check: No intent registered
    let has_intent = wf_intent
        .as_ref()
        .map(|i| !i.is_null() && i != &serde_json::json!({}))
        .unwrap_or(false);
    if !has_intent {
        // Check if workflow is published
        let is_published: bool = state
            .analytics_repo
            .check_has_active_version(wf_id)
            .await
            .unwrap_or(false);

        let risk_level = if is_published { "medium" } else { "low" };
        risks.push(serde_json::json!({
            "risk_level": risk_level,
            "category": "no_intent",
            "description": format!("Workflow has no intent registered{}", if is_published { " (published workflow)" } else { "" }),
            "recommendation": "Register an intent to describe what this workflow does and when it should be used"
        }));
    }

    // Check: Secrets without expiry referenced by workflow modules
    if !module_ids.is_empty() {
        // Find secrets that modules in this workflow might reference and that have no expiry
        let secrets_no_expiry = state
            .analytics_repo
            .get_risk_no_expiry_secrets(user_id)
            .await
            .unwrap_or_default();
        let graph_str_lower = graph_json_str.to_lowercase();
        for secret_name in &secrets_no_expiry {
            // Check if any node in the graph references this secret
            if graph_str_lower.contains(&secret_name.to_lowercase()) {
                risks.push(serde_json::json!({
                    "risk_level": "medium",
                    "category": "secret_no_expiry",
                    "description": format!("Secret '{}' is referenced by this workflow but has no expiry set", secret_name),
                    "recommendation": "Set an expiry on this secret to ensure it gets rotated periodically"
                }));
            }
        }
    }

    // Check: Nodes backed by user-authored sandbox modules.
    // Sandbox modules are compiled from user-written source, may have been built
    // against an older WIT interface, and have no automated update path — making
    // them inherently higher risk than catalog modules which are platform-managed.
    if !module_ids.is_empty() {
        let sandbox_modules = state
            .analytics_repo
            .get_risk_sandbox_modules(&module_ids)
            .await
            .unwrap_or_default();
        if !sandbox_modules.is_empty() {
            let sandbox_id_set: std::collections::HashSet<uuid::Uuid> =
                sandbox_modules.iter().map(|(id, _)| *id).collect();
            let sandbox_name_map: std::collections::HashMap<uuid::Uuid, &str> = sandbox_modules
                .iter()
                .map(|(id, n)| (*id, n.as_str()))
                .collect();
            // Collect node IDs that use sandbox modules
            let node_refs: Vec<String> = nodes
                .iter()
                .filter_map(|n| {
                    let mid: uuid::Uuid = n
                        .get("type")
                        .and_then(|v| v.as_str())
                        .and_then(|s| s.parse().ok())?;
                    if sandbox_id_set.contains(&mid) {
                        let node_id = n.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                        let mod_name = sandbox_name_map.get(&mid).copied().unwrap_or("unknown");
                        Some(format!("{} ({})", node_id, mod_name))
                    } else {
                        None
                    }
                })
                .collect();
            if !node_refs.is_empty() {
                risks.push(serde_json::json!({
                    "risk_level": "medium",
                    "category": "sandbox_modules",
                    "description": format!(
                        "{} node(s) use user-authored sandbox modules: {}",
                        node_refs.len(),
                        node_refs.join(", ")
                    ),
                    "recommendation": "Sandbox modules are user-authored and may have been compiled \
                        against an older WIT version. Inspect source with get_workflow_dependencies \
                        and recompile via compile_custom_sandbox if the platform WIT has been updated."
                }));
            }
        }
    }

    // Check: Secret access grant risks — wildcard grants and always-failing configs.
    //
    // Uses installed_secrets (wasm_modules, loaded above in parallel) with fallback to
    // template_secrets (node_templates) when no wasm_modules entry exists. This mirrors
    // validate_workflow's two-layer approach and catches risks regardless of which table
    // has the authoritative record for this installation.
    if !module_ids.is_empty() {
        for node in &nodes {
            let node_id = node.get("id").and_then(|v| v.as_str()).unwrap_or("?");
            let Ok(mid) = node
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .parse::<uuid::Uuid>()
            else {
                continue;
            };

            // Prefer wasm_modules entry (operator-applied override); fall back to
            // node_templates default. If neither has a record (e.g. trigger/condition
            // nodes that don't access secrets), skip secret risk checks for this node.
            let effective_secrets: Option<&Vec<String>> = installed_secrets
                .get(&mid)
                .or_else(|| template_secrets.get(&mid));

            let tmpl_name = template_info
                .get(&mid)
                .map(|(n, _)| n.as_str())
                .unwrap_or("unknown");

            let Some(secrets) = effective_secrets else {
                continue;
            };

            // Risk A: wildcard grant — module can read any vault path.
            if secrets.iter().any(|s| s == "*") {
                risks.push(serde_json::json!({
                    "risk_level": "medium",
                    "category": "wildcard_secret_grant",
                    "node_id": node_id,
                    "description": format!(
                        "Node '{}' (module: '{}') has wildcard secret access \
                         (allowed_secrets: [\"*\"]) — can read any vault path. \
                         Blast radius: all secrets in the vault.",
                        node_id, tmpl_name
                    ),
                    "recommendation": "Reinstall the module with explicit allowed_secrets paths \
                        to restrict access to only the secrets it needs."
                }));
                // Wildcard covers everything — no need for vault_path_blocked check.
                continue;
            }

            // Risk B: empty grant — only flag when the node's config actually
            // references vault:// paths. An empty allowed_secrets on a module that
            // doesn't use secrets (e.g. memory-writer, classifiers) is correct and
            // shouldn't produce noise.
            let node_data = node.get("data").cloned().unwrap_or(serde_json::json!({}));
            let node_config = node_data
                .get("config")
                .cloned()
                .unwrap_or_else(|| node_data.clone());
            let has_vault_refs = node_config
                .as_object()
                .map(|cfg| {
                    cfg.values().any(|v| {
                        v.as_str()
                            .map(|s| s.starts_with("vault://"))
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false);

            if secrets.is_empty() && has_vault_refs {
                risks.push(serde_json::json!({
                    "risk_level": "high",
                    "category": "empty_secret_grant",
                    "node_id": node_id,
                    "description": format!(
                        "Node '{}' (module: '{}') has no secret grant (allowed_secrets: []) \
                         but its config references vault:// paths. \
                         Every execution will fail with 'unauthorized'.",
                        node_id, tmpl_name
                    ),
                    "recommendation": "Reinstall the module with allowed_secrets: [\"path/to/key\"] \
                        or [\"*\"] to enable secret access."
                }));
            }

            // Risk C: vault:// config value blocked by effective allowed_secrets.
            // Catches mismatches between what's in the node config and what the grant permits.
            // Also fires for empty-grant nodes (every vault:// ref is blocked).
            if let Some(cfg_obj) = node_config.as_object() {
                for (field_key, field_val) in cfg_obj {
                    if let Some(val_str) = field_val.as_str() {
                        if let Some(path) = val_str.strip_prefix("vault://") {
                            if !crate::workflows::vault_path_permitted(path, secrets) {
                                risks.push(serde_json::json!({
                                    "risk_level": "high",
                                    "category": "vault_path_blocked",
                                    "node_id": node_id,
                                    "config_field": field_key,
                                    "vault_path": path,
                                    "description": format!(
                                        "Node '{}' config field '{}' references vault path '{}' \
                                         which is not permitted by the module's allowed_secrets \
                                         ({}). Every execution will fail with 'unauthorized'.",
                                        node_id,
                                        field_key,
                                        path,
                                        if secrets.is_empty() {
                                            "deny-all — no secrets granted".to_string()
                                        } else {
                                            format!("[{}]", secrets.join(", "))
                                        }
                                    ),
                                    "recommendation": "Reinstall the module with the vault path \
                                        added to allowed_secrets, or update the config to use \
                                        a permitted path."
                                }));
                            }
                        }
                    }
                }
            }
        }
    }

    // Check: Recent execution failures with 'unauthorized'/'access denied' errors.
    // Cross-references the live execution history to surface recurring secret failures
    // that indicate a vault_path_blocked or empty_secret_grant config issue in production.
    {
        let recent_auth_failures = state
            .analytics_repo
            .count_recent_auth_failures(wf_id, 7)
            .await
            .unwrap_or(None);

        if let Some((count, last_failure)) = recent_auth_failures {
            if count > 0 {
                risks.push(serde_json::json!({
                    "risk_level": "high",
                    "category": "repeated_auth_failures",
                    "description": format!(
                        "This workflow has failed {} time(s) in the last 7 days with \
                         'unauthorized' or 'access-denied' errors (most recent: {}). \
                         This strongly indicates a vault path blocked by allowed_secrets \
                         or a missing secret grant.",
                        count,
                        last_failure
                    ),
                    "recommendation": "Run validate_workflow to identify which node config fields \
                        reference vault paths blocked by the module's allowed_secrets. \
                        Then reinstall the affected module with the correct paths added.",
                    "failure_count": count,
                }));
            }
        }
    }

    // Sort risks by severity
    risks.sort_by(|a, b| {
        let level_order = |v: &serde_json::Value| match v.get("risk_level").and_then(|l| l.as_str())
        {
            Some("high") => 0,
            Some("medium") => 1,
            Some("low") => 2,
            _ => 3,
        };
        level_order(a).cmp(&level_order(b))
    });

    let result = serde_json::json!({
        "workflow_name": wf_name,
        "workflow_id": wf_id.to_string(),
        "total_risks": risks.len(),
        "high": risks.iter().filter(|r| r.get("risk_level").and_then(|l| l.as_str()) == Some("high")).count(),
        "medium": risks.iter().filter(|r| r.get("risk_level").and_then(|l| l.as_str()) == Some("medium")).count(),
        "low": risks.iter().filter(|r| r.get("risk_level").and_then(|l| l.as_str()) == Some("low")).count(),
        "risks": risks,
    });

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

async fn handle_get_daily_digest(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let _ = args;

    // Total executions in last 24h by status
    let summary_row = match state.analytics_repo.get_daily_exec_summary(user_id).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("get_daily_digest status query failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to fetch daily digest");
        }
    };
    let total = summary_row.total;
    let succeeded = summary_row.succeeded;
    let failed = summary_row.failed;
    let cancelled = summary_row.cancelled;
    let running = summary_row.running;

    // Top 3 most active workflows
    let active_rows = state
        .analytics_repo
        .get_top_active_workflows_24h(user_id)
        .await
        .unwrap_or_default();
    let top_active: Vec<serde_json::Value> = active_rows.iter().map(|r| {
        serde_json::json!({"workflow_id": r.id.to_string(), "name": r.name, "executions": r.exec_count})
    }).collect();

    // Top 3 failing workflows
    let failing_rows = state
        .analytics_repo
        .get_top_failing_workflows_24h(user_id)
        .await
        .unwrap_or_default();
    let top_failing: Vec<serde_json::Value> = failing_rows
        .iter()
        .map(|r| {
            let fail_rate = if r.total_count > 0 {
                (r.fail_count as f64 / r.total_count as f64) * 100.0
            } else {
                0.0
            };
            serde_json::json!({
                "workflow_id": r.id.to_string(),
                "name": r.name,
                "failures": r.fail_count,
                "total": r.total_count,
                "failure_rate": format!("{:.1}%", fail_rate),
            })
        })
        .collect();

    // Upcoming schedules (next 24h)
    let schedule_rows = state
        .analytics_repo
        .get_upcoming_schedules_for_user(user_id)
        .await
        .unwrap_or_default();
    let schedules: Vec<serde_json::Value> = schedule_rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "workflow_id": r.workflow_id.to_string(),
                "workflow_name": r.workflow_name,
                "cron": r.cron_expression,
                "timezone": r.timezone.as_deref().unwrap_or("UTC"),
            })
        })
        .collect();

    // Build human-readable summary
    let mut summary = format!(
        "Daily Digest (last 24 hours)\n\
         =============================\n\n\
         Executions: {} total ({} succeeded, {} failed, {} cancelled, {} running)\n",
        total, succeeded, failed, cancelled, running
    );

    if !top_active.is_empty() {
        summary.push_str("\nMost Active Workflows:\n");
        for (i, wf) in top_active.iter().enumerate() {
            summary.push_str(&format!(
                "  {}. {} - {} executions\n",
                i + 1,
                wf.get("name").and_then(|v| v.as_str()).unwrap_or("?"),
                wf.get("executions").and_then(|v| v.as_i64()).unwrap_or(0),
            ));
        }
    }

    if !top_failing.is_empty() {
        summary.push_str("\nTop Failing Workflows:\n");
        for (i, wf) in top_failing.iter().enumerate() {
            summary.push_str(&format!(
                "  {}. {} - {} failures ({} failure rate)\n",
                i + 1,
                wf.get("name").and_then(|v| v.as_str()).unwrap_or("?"),
                wf.get("failures").and_then(|v| v.as_i64()).unwrap_or(0),
                wf.get("failure_rate")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?"),
            ));
        }
    }

    if !schedules.is_empty() {
        summary.push_str("\nUpcoming Schedules:\n");
        for sched in &schedules {
            summary.push_str(&format!(
                "  - {} ({}): {} ({})\n",
                sched
                    .get("workflow_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?"),
                sched
                    .get("workflow_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?"),
                sched.get("cron").and_then(|v| v.as_str()).unwrap_or("?"),
                sched
                    .get("timezone")
                    .and_then(|v| v.as_str())
                    .unwrap_or("UTC"),
            ));
        }
    }

    let result = serde_json::json!({
        "summary": summary,
        "data": {
            "executions": {
                "total": total,
                "succeeded": succeeded,
                "failed": failed,
                "cancelled": cancelled,
                "running": running,
            },
            "top_active_workflows": top_active,
            "top_failing_workflows": top_failing,
            "upcoming_schedules": schedules,
        }
    });

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

async fn handle_set_workflow_capabilities(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    // MCP-285 (2026-05-10): pre-fix `filter_map(|v| v.as_str()...)`
    // silently dropped non-string entries — `["http", 42, "secrets"]`
    // became `["http", "secrets"]`, the regex below passed, and the
    // operator's deliberate 3-cap intent became 2 with no signal.
    // Reject malformed entries upfront. Same MCP-274 family.
    let capabilities: Vec<String> = match args.get("capabilities").and_then(|v| v.as_array()) {
        Some(arr) => {
            let mut out: Vec<String> = Vec::with_capacity(arr.len());
            for (i, v) in arr.iter().enumerate() {
                match v.as_str() {
                    Some(s) => out.push(s.to_string()),
                    None => {
                        let kind = crate::utils::json_type_name(v);
                        return mcp_error(
                            req_id,
                            -32602,
                            &format!("capabilities[{i}] must be a string, got {kind}"),
                        );
                    }
                }
            }
            out
        }
        None => return mcp_error(req_id, -32602, "Missing 'capabilities' array"),
    };
    if capabilities.len() > 20 {
        return mcp_error(req_id, -32602, "Maximum 20 capabilities allowed");
    }
    // MCP-1052: route through canonical `is_valid_capability_name`
    // (talos-workflow-creation-helpers).
    for cap in &capabilities {
        if !talos_workflow_creation_helpers::is_valid_capability_name(cap) {
            return mcp_error(
                req_id,
                -32602,
                &format!(
                "Invalid capability '{}'. Must be lowercase alphanumeric + hyphens, 1-50 chars.",
                talos_text_util::bounded_preview(cap, 64)
            ),
            );
        }
    }
    match state
        .analytics_repo
        .set_workflow_capabilities(wf_id, user_id, &capabilities)
        .await
    {
        Ok(true) => {
            // Best-effort: update search_text
            let pool = state.db_pool.clone();
            let uid = user_id;
            tokio::spawn(async move {
                update_workflow_search_text(&pool, wf_id, uid).await;
            });
            mcp_text(
                req_id,
                &format!(
                    "Capabilities set on workflow {}:\n{}",
                    wf_id,
                    capabilities.join(", ")
                ),
            )
        }
        Ok(false) => crate::utils::workflow_not_found_error(req_id),
        Err(e) => {
            tracing::error!(workflow_id = %wf_id, "set_workflow_capabilities failed: {}", e);
            mcp_error(req_id, -32000, "Failed to update capabilities")
        }
    }
}

async fn handle_get_workflows_by_capability(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // MCP-285 (2026-05-10): same strict-parse pattern as
    // set_workflow_capabilities — reject non-string entries instead of
    // silently dropping them.
    let capabilities: Vec<String> = match args.get("capabilities").and_then(|v| v.as_array()) {
        Some(arr) => {
            let mut out: Vec<String> = Vec::with_capacity(arr.len());
            for (i, v) in arr.iter().enumerate() {
                match v.as_str() {
                    Some(s) => out.push(s.to_string()),
                    None => {
                        let kind = crate::utils::json_type_name(v);
                        return mcp_error(
                            req_id,
                            -32602,
                            &format!("capabilities[{i}] must be a string, got {kind}"),
                        );
                    }
                }
            }
            out
        }
        None => return mcp_error(req_id, -32602, "Missing 'capabilities' array"),
    };
    if capabilities.is_empty() {
        return mcp_error(req_id, -32602, "At least one capability required");
    }

    match state
        .analytics_repo
        .get_workflows_by_capability(user_id, &capabilities)
        .await
    {
        Ok(rows) => {
            // MCP-86 (2026-05-07): four fixes in one:
            //   * emit `workflow_id` alongside legacy `id` (MCP-31 class).
            //   * convert `success_rate_30d` from raw 0.0–1.0 fraction
            //     (16-digit precision leak) to a 1-decimal percentage
            //     via `format_percent`. Renamed to
            //     `success_rate_30d_percent` to mirror MCP-19 naming.
            //     Legacy `success_rate_30d` retained as a rounded
            //     fraction for back-compat (4dp cap so the 16-digit
            //     leak is gone either way).
            //   * wrap in `{count, capabilities_filter, workflows}`
            //     envelope so the surface matches MCP-45 sweep.
            let results: Vec<serde_json::Value> = rows
                .iter()
                .map(|row| {
                    // success_rate is Option<f64>: None when total = 0.
                    // Emit the legacy fraction rounded to 4dp; the new
                    // _percent field is only meaningful when the fraction
                    // exists. None → null on both fields so callers can
                    // distinguish "no executions yet" from "ran and 0%".
                    let frac_opt: Option<f64> = row.success_rate;
                    let frac_4dp: Option<f64> = frac_opt.and_then(|f| {
                        if f.is_finite() {
                            Some((f * 10000.0).round() / 10000.0)
                        } else {
                            None
                        }
                    });
                    let percent_value: serde_json::Value = match frac_opt {
                        Some(f) if f.is_finite() => {
                            serde_json::json!(talos_analytics_repository::format_percent(f * 100.0))
                        }
                        _ => serde_json::Value::Null,
                    };
                    serde_json::json!({
                        "id": row.id,
                        "workflow_id": row.id,
                        "name": row.name,
                        "description": row.description,
                        "capabilities": row.capabilities,
                        "readiness_score": row.readiness_score,
                        "success_rate_30d": frac_4dp,
                        "success_rate_30d_percent": percent_value,
                    })
                })
                .collect();
            let envelope = serde_json::json!({
                "count": results.len(),
                "capabilities_filter": capabilities,
                "workflows": results,
            });
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&envelope).unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("get_workflows_by_capability failed: {}", e);
            mcp_error(req_id, -32000, "Failed to query workflows")
        }
    }
}

async fn handle_get_workflow_reuse_stats(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let days = match crate::utils::validate_range_i64(args, "days", 1, 365, 30, &req_id) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    match state
        .analytics_repo
        .get_workflow_reuse_stats(user_id, days as i32)
        .await
    {
        Ok(rows) => {
            let stats: Vec<serde_json::Value> = rows
                .iter()
                .map(|row| {
                    let total = row.total_invocations;
                    let unique = row.unique_days;
                    let node_count = row
                        .graph_json
                        .as_deref()
                        .and_then(|gj| serde_json::from_str::<serde_json::Value>(gj).ok())
                        .and_then(|g| g.get("nodes").and_then(|n| n.as_array()).map(|a| a.len()))
                        .unwrap_or(0);
                    let repeat_ratio = if unique > 0 {
                        total as f64 / unique as f64
                    } else {
                        0.0
                    };
                    // MCP-67 (2026-05-07): the savings number is a rough
                    // heuristic, not measured. The factor 50 represents
                    // average tokens saved per reused node (workflow
                    // scaffolding the LLM would otherwise re-explain). The
                    // formula is documented in the response `note`.
                    const TOKENS_PER_NODE_ESTIMATE: i64 = 50;
                    let estimated_token_savings =
                        node_count as i64 * TOKENS_PER_NODE_ESTIMATE * total;

                    serde_json::json!({
                        "workflow_id": row.workflow_id,
                        "name": row.name,
                        "total_invocations": total,
                        "unique_active_days": unique,
                        "executions_per_active_day": (repeat_ratio * 100.0).round() / 100.0,
                        "estimated_token_savings": estimated_token_savings,
                        "node_count": node_count,
                    })
                })
                .collect();
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "period_days": days,
                    "count": stats.len(),
                    "workflow_count": stats.len(),
                    "workflows": stats,
                    "note": "Counts all executions in workflow_executions. unique_active_days = distinct calendar days with at least one run. estimated_token_savings = total_invocations × node_count × 50 (rough per-node scaffolding heuristic; not measured per-execution — treat as a relative-magnitude signal, not a calibrated cost number).",
                }))
                .unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("get_workflow_reuse_stats failed: {}", e);
            mcp_error(req_id, -32000, "Failed to query reuse stats")
        }
    }
}

async fn handle_suggest_capabilities(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // Load graph_json
    let graph_json_str = match state
        .analytics_repo
        .get_workflow_graph_json(wf_id, user_id)
        .await
    {
        Ok(Some(gj)) => gj,
        Ok(None) => return mcp_error(req_id, -32000, "Workflow not found or access denied"),
        Err(e) => {
            tracing::error!("suggest_capabilities graph lookup failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to fetch workflow");
        }
    };

    let graph: serde_json::Value =
        serde_json::from_str(&graph_json_str).unwrap_or(serde_json::json!({"nodes":[],"edges":[]}));

    let nodes = graph.get("nodes").and_then(|n| n.as_array());
    let edges = graph.get("edges").and_then(|e| e.as_array());

    let mut suggestions: Vec<String> = Vec::new();

    // Extract module IDs to look up capability_worlds
    let module_ids: Vec<uuid::Uuid> = nodes
        .map(|ns| {
            ns.iter()
                .filter_map(|n| {
                    n.get("type")
                        .and_then(|v| v.as_str())
                        .and_then(|s| s.parse().ok())
                })
                .collect()
        })
        .unwrap_or_default();

    if !module_ids.is_empty() {
        // Check wasm_modules by both id and template_id
        let world_rows = state
            .analytics_repo
            .get_capability_worlds_for_modules(&module_ids)
            .await
            .unwrap_or_default();

        for world in &world_rows {
            let w = talos_capability_world::world_short(world);
            match w {
                "http" | "network" => {
                    suggestions.push("http".to_string());
                    suggestions.push("fetch".to_string());
                }
                "database" => suggestions.push("database".to_string()),
                "secrets" => suggestions.push("uses-secrets".to_string()),
                "filesystem" => suggestions.push("filesystem".to_string()),
                "cache" => suggestions.push("caching".to_string()),
                "messaging" => suggestions.push("messaging".to_string()),
                "agent" => suggestions.push("agentic".to_string()),
                "governance" => suggestions.push("governance".to_string()),
                "automation" | "trusted" => suggestions.push("automation".to_string()),
                "minimal" => {}
                _ => {}
            }
        }

        // Also check node_templates for modules that might not be in wasm_modules
        let tmpl_names = state
            .analytics_repo
            .get_template_categories_lower(&module_ids)
            .await
            .unwrap_or_default();

        for cat in &tmpl_names {
            match cat.as_str() {
                "data" if !suggestions.iter().any(|s| s == "database") => {
                    suggestions.push("database".to_string());
                }
                "network" | "http" if !suggestions.iter().any(|s| s == "http") => {
                    suggestions.push("http".to_string());
                }
                _ => {}
            }
        }
    }

    // Check for system nodes
    if let Some(ns) = nodes {
        for n in ns {
            let node_type = n.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let node_kind = n.get("kind").and_then(|v| v.as_str()).unwrap_or("");

            // Check for loop nodes
            if (node_kind == "loop" || node_type.contains("loop"))
                && !suggestions.contains(&"loop".to_string())
            {
                suggestions.push("loop".to_string());
                suggestions.push("paginate".to_string());
            }
            // Check for sub_workflow / call nodes
            if (node_kind == "sub_workflow" || node_type.contains("sub_workflow"))
                && !suggestions.contains(&"composition".to_string())
            {
                suggestions.push("composition".to_string());
            }
            // Check for collect / aggregate nodes
            if (node_kind == "collect" || node_type.contains("collect"))
                && !suggestions.contains(&"aggregate".to_string())
            {
                suggestions.push("aggregate".to_string());
            }
            // Check for retry config (stored at node level or in data)
            if (n.get("retry_count").is_some()
                || n.get("data").and_then(|d| d.get("retry_count")).is_some())
                && !suggestions.contains(&"retryable".to_string())
            {
                suggestions.push("retryable".to_string());
            }
        }
    }

    // Check edges for conditional and error types
    if let Some(es) = edges {
        for e in es {
            let edge_type = e
                .get("edge_type")
                .and_then(|v| v.as_str())
                .unwrap_or("default");
            match edge_type {
                "conditional" if !suggestions.contains(&"conditional".to_string()) => {
                    suggestions.push("conditional".to_string());
                }
                "error" if !suggestions.contains(&"has-error-handling".to_string()) => {
                    suggestions.push("has-error-handling".to_string());
                }
                _ => {}
            }
            // Also check condition field on edges
            if e.get("condition")
                .and_then(|v| v.as_str())
                .map(|s| !s.is_empty())
                .unwrap_or(false)
                && !suggestions.contains(&"conditional".to_string())
            {
                suggestions.push("conditional".to_string());
            }
        }
    }

    // Check for timeout
    if graph.get("execution_timeout_secs").is_some() {
        suggestions.push("has-timeout".to_string());
    }

    // Infer composition type from graph structure
    if let (Some(ns), Some(es)) = (nodes, edges) {
        let node_count = ns.len();
        if node_count > 2 {
            // Check if any node has multiple incoming edges (fan-in = parallel)
            let mut incoming_counts: std::collections::HashMap<&str, usize> =
                std::collections::HashMap::new();
            for e in es {
                if let Some(tgt) = e.get("target").and_then(|v| v.as_str()) {
                    *incoming_counts.entry(tgt).or_insert(0) += 1;
                }
            }
            if incoming_counts.values().any(|&c| c > 1) {
                suggestions.push("parallel".to_string());
            }
            if node_count == es.len() + 1 {
                suggestions.push("sequential".to_string());
            }
        }
    }

    // Deduplicate
    suggestions.sort();
    suggestions.dedup();

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "workflow_id": wf_id,
            "suggested_capabilities": suggestions,
            "note": "Use set_workflow_capabilities to apply these suggestions."
        }))
        .unwrap_or_default(),
    )
}

/// Inverse of `compilation::scaffold::compute_max_fuel_with_llm_output`'s
/// safety multiplier: pick a budget that absorbs p95 with ~30% headroom,
/// clamped to the same [1M, 50M] band the formula uses. Keeping the
/// clamp here prevents recommendations the engine would itself reject.
fn recommend_budget_from_p95(p95: i64) -> i64 {
    const MIN_FUEL: i64 = 1_000_000;
    const MAX_FUEL: i64 = 50_000_000;
    if p95 <= 0 {
        return MIN_FUEL;
    }
    // Round up to nearest 100k so recommendations are easier to eyeball
    // and stable under tiny p95 jitter between reports.
    let raw = (p95 as f64 / 0.70).ceil() as i64;
    let rounded = ((raw + 99_999) / 100_000) * 100_000;
    rounded.clamp(MIN_FUEL, MAX_FUEL)
}

async fn handle_get_fuel_usage_report(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let days: i32 = match crate::utils::validate_range_i64(args, "days", 1, 30, 7, &req_id) {
        Ok(v) => v as i32,
        Err(resp) => return resp,
    };
    let limit: i32 = match crate::utils::validate_range_i64(args, "limit", 1, 100, 20, &req_id) {
        Ok(v) => v as i32,
        Err(resp) => return resp,
    };
    let min_executions: i64 =
        match crate::utils::validate_range_i64(args, "min_executions", 1, 1000, 3, &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };

    // execution_cost_rollup is the structured per-node fuel source —
    // unlike the previous output_data parse, this attributes fuel to the
    // module that ran (not the node label), reflects the current
    // modules.max_fuel ceiling for utilization math, and skips nodes
    // without a tunable budget.
    let stats = match state
        .analytics_repo
        .get_per_module_fuel_stats(user_id, days, min_executions, limit)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            // M-F (2026-05-06): log the underlying error AND categorise it
            // so the operator gets actionable signal without leaking
            // internal SQL details. Pre-fix the bare "Failed to fetch
            // fuel stats" wrapper hid an `AVG(bigint)` decode mismatch
            // for months — the operator had no way to self-diagnose.
            tracing::error!(
                target: "talos_analytics",
                event_kind = "fuel_report_failed",
                error = %e,
                "get_fuel_usage_report query failed"
            );
            let lower = e.to_string().to_ascii_lowercase();
            let hint = if lower.contains("mismatched types") || lower.contains("convert") {
                "Failed to fetch fuel stats: a column type returned by the analytics query \
                 doesn't match the decoder. Check controller logs for the underlying SQL error \
                 (target: talos_analytics, event_kind: fuel_report_failed) and verify the \
                 execution_cost_rollup schema is in sync with this build."
            } else if lower.contains("relation") && lower.contains("does not exist") {
                "Failed to fetch fuel stats: the execution_cost_rollup table is missing. \
                 Confirm migration 20260410000003_cost_attribution.sql ran."
            } else {
                "Failed to fetch fuel stats: see controller logs (target: talos_analytics, \
                 event_kind: fuel_report_failed) for the underlying error."
            };
            return mcp_error(req_id, -32000, hint);
        }
    };

    let mut at_risk: Vec<serde_json::Value> = Vec::new();
    let mut over_provisioned: Vec<serde_json::Value> = Vec::new();
    let mut well_tuned: Vec<serde_json::Value> = Vec::new();

    let mut modules: Vec<serde_json::Value> = Vec::with_capacity(stats.len());
    for s in &stats {
        let ceiling = s.current_max_fuel.max(1);
        let utilization_pct = (s.fuel_p95 as f64 / ceiling as f64) * 100.0;
        let recommended = recommend_budget_from_p95(s.fuel_p95);

        // Classification thresholds:
        //   at_risk:          p95 > 67% of ceiling (1.5× headroom)
        //   over_provisioned: p95 < 33% of ceiling (3× headroom) AND
        //                     enough samples to trust the percentile AND
        //                     recommendation cuts ≥30% from current
        //   well_tuned:       everything in between
        let class = if utilization_pct > 67.0 {
            "at_risk"
        } else if utilization_pct < 33.0
            && s.executions >= 10
            && (s.current_max_fuel - recommended) * 100 / s.current_max_fuel.max(1) >= 30
        {
            "over_provisioned"
        } else {
            "well_tuned"
        };

        let entry = serde_json::json!({
            "module_id": s.module_id,
            "module_name": s.module_name,
            "kind": s.kind,
            "executions": s.executions,
            "current_max_fuel": s.current_max_fuel,
            "fuel_p50": s.fuel_p50,
            "fuel_p95": s.fuel_p95,
            "fuel_max": s.fuel_max,
            "fuel_avg": s.fuel_avg,
            "wall_time_p50_ms": s.wall_time_p50_ms,
            "wall_time_p95_ms": s.wall_time_p95_ms,
            "utilization_p95_pct": talos_analytics_repository::format_percent(utilization_pct),
            "recommendation": class,
            "recommended_max_fuel": recommended,
        });

        match class {
            "at_risk" => at_risk.push(entry.clone()),
            "over_provisioned" => over_provisioned.push(entry.clone()),
            _ => well_tuned.push(entry.clone()),
        }
        modules.push(entry);
    }

    let result = serde_json::json!({
        "period_days": days,
        "modules_analyzed": stats.len(),
        "summary": {
            "at_risk": at_risk.len(),
            "over_provisioned": over_provisioned.len(),
            "well_tuned": well_tuned.len(),
        },
        "at_risk": at_risk,
        "over_provisioned": over_provisioned,
        "modules": modules,
        "note": "Apply recommendations via hot_update_module(name, fuel_budget=recommended_max_fuel) — bumps modules.max_fuel without recompiling source.",
    });

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

async fn handle_get_readiness_breakdown(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // Load workflow metadata
    let wf_full = match state.analytics_repo.get_workflow_full(wf_id, user_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return mcp_error(req_id, -32000, "Workflow not found or access denied"),
        Err(e) => {
            tracing::error!("get_readiness_breakdown: {}", e);
            return mcp_error(req_id, -32000, "Failed to fetch workflow");
        }
    };

    let name: String = wf_full.name;
    let description: Option<String> = wf_full.description;
    let caps: Vec<String> = wf_full.capabilities.unwrap_or_default();
    let graph_json_str: String = wf_full.graph_json.unwrap_or_default();
    let wf_analytics = state
        .analytics_repo
        .get_workflow_for_analytics(wf_id, user_id)
        .await
        .unwrap_or(None);
    let workflow_type: String = wf_analytics
        .and_then(|r| r.workflow_type)
        .unwrap_or_else(|| "production".into());

    let graph: serde_json::Value =
        serde_json::from_str(&graph_json_str).unwrap_or(serde_json::json!({"nodes":[],"edges":[]}));

    // ── Reliability (50%) ──────────────────────────────────────────────────
    // Acknowledged failures (acknowledge_execution_failure) are excluded so that
    // known-historical out-of-band events don't penalise the current score.
    // Saturates at 20 runs — a workflow with 20 successful executions is
    // considered fully reliable; requiring 100 runs was overly punitive.
    let exec_data = state
        .analytics_repo
        .get_readiness_exec_data(wf_id)
        .await
        .unwrap_or(talos_analytics_repository::ReadinessExecData {
            success_rate: None,
            total_count: 0,
        });
    let (success_rate, exec_count) = (exec_data.success_rate, exec_data.total_count);
    // Saturation at 10 runs: 5 perfect runs → 50% of reliability credit (not alarming).
    // Linear ramp 0→10 runs, then capped at 1.0. Shared with validate_workflow.
    let reliability =
        talos_analytics_repository::compute_reliability_score(success_rate, exec_count);

    // ── Documentation (20%) ───────────────────────────────────────────────
    // Reduced from 30% — documentation is valuable but should not dominate
    // over execution health. A well-running undocumented workflow scores better
    // than a documented workflow that never runs.
    let has_desc = description.as_ref().map(|d| !d.is_empty()).unwrap_or(false);
    let has_node_desc = graph
        .get("nodes")
        .and_then(|n| n.as_array())
        .map(|nodes| {
            nodes.iter().any(|n| {
                n.get("description")
                    .and_then(|d| d.as_str())
                    .map(|s| !s.is_empty())
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false);
    let has_caps = !caps.is_empty();
    // has_desc: 10, has_node_desc: 5, has_caps: 5 = max 20 — shared with validate_workflow.
    let documentation =
        talos_analytics_repository::compute_documentation_score(has_desc, has_node_desc, has_caps);

    // ── Freshness (20%) ───────────────────────────────────────────────────
    let last_exec_at = state
        .analytics_repo
        .get_max_execution_started_at(wf_id)
        .await
        .unwrap_or(None);
    let days_since_last =
        last_exec_at.map(|t| chrono::Utc::now().signed_duration_since(t).num_days());
    let freshness = talos_analytics_repository::compute_freshness_score(days_since_last);

    // ── Retry configuration check (for deterministic failure warning) ─────
    let has_retries_configured = graph
        .get("nodes")
        .and_then(|n| n.as_array())
        .map(|nodes| {
            nodes.iter().any(|n| {
                // retry_count may live directly on the node or inside its config object
                let top = n.get("retry_count").and_then(|v| v.as_i64()).unwrap_or(0);
                let nested = n
                    .get("config")
                    .and_then(|c| c.get("retry_count"))
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                top > 0 || nested > 0
            })
        })
        .unwrap_or(false);

    // ── Risk (10%) ────────────────────────────────────────────────────────
    let has_timeout = graph.get("execution_timeout_secs").is_some();
    let has_error_edges = graph
        .get("edges")
        .and_then(|e| e.as_array())
        .map(|edges| {
            edges
                .iter()
                .any(|e| e.get("edge_type").and_then(|t| t.as_str()) == Some("error"))
        })
        .unwrap_or(false);
    let expiring_secrets: i64 = state
        .analytics_repo
        .count_expiring_secrets(user_id)
        .await
        .unwrap_or(0);

    let risk = talos_analytics_repository::compute_risk_score(
        has_timeout,
        has_error_edges,
        expiring_secrets,
    );

    let computed_score = (reliability + documentation + freshness + risk).round() as i32;

    // ── Build actionable improvement suggestions ───────────────────────────
    let mut improvements: Vec<serde_json::Value> = Vec::new();
    if !has_desc {
        improvements.push(serde_json::json!({"action": "set_workflow_description — also improves semantic search quality", "points_available": 10, "component": "documentation"}));
    }
    if !has_node_desc {
        improvements.push(serde_json::json!({"action": "Add descriptions to nodes in the graph", "points_available": 5, "component": "documentation"}));
    }
    if !has_caps {
        improvements.push(serde_json::json!({"action": "set_workflow_capabilities or auto_tag_capabilities", "points_available": 5, "component": "documentation"}));
    }
    if !has_timeout {
        improvements.push(serde_json::json!({"action": "Set execution_timeout_secs on the workflow graph", "points_available": 3, "component": "risk"}));
    }
    if !has_error_edges {
        improvements.push(serde_json::json!({
            "action": "Add error handler",
            "detail": "add_error_handler(workflow_id: X, handler_module_id: Y) wires error edges from ALL at-risk nodes in one call",
            "tool": "add_error_handler",
            "points_available": 3,
            "component": "risk"
        }));
    }
    if exec_count == 0 {
        improvements.push(serde_json::json!({"action": "Execute the workflow at least once to establish reliability baseline", "points_available": 50, "component": "reliability"}));
    } else if exec_count < 10 {
        let remaining = (50.0 * (1.0 - exec_count as f64 / 10.0)) as i32;
        improvements.push(serde_json::json!({"action": format!("Run {} more times to reach full reliability credit (currently {}/10 runs)", 10 - exec_count, exec_count), "points_available": remaining, "component": "reliability"}));
    } else if success_rate.unwrap_or(0.0) < 0.95 {
        improvements.push(serde_json::json!({"action": "Improve success rate — currently below 95%", "points_available": (50.0 * (1.0 - success_rate.unwrap_or(0.0))) as i32, "component": "reliability"}));
    }
    if freshness == 0.0 {
        improvements.push(serde_json::json!({"action": "Execute within the last 30 days to restore freshness score", "points_available": 10, "component": "freshness"}));
    }

    // Retry warning: retries configured but failures appear deterministic (≠ transient)
    let retry_warning: Option<&str> = if has_retries_configured
        && exec_count > 0
        && success_rate.unwrap_or(1.0) < 1.0
    {
        Some("Retries are configured but some failures appear deterministic. Run suggest_retry_config — if failures are auth/not-found/validation errors, retries waste fuel and mask root cause.")
    } else {
        None
    };
    if let Some(msg) = retry_warning {
        improvements.push(serde_json::json!({
            "action": msg,
            "points_available": 0,
            "component": "risk",
            "type": "warning",
        }));
    }

    // Sort by most impactful first (warnings with points_available: 0 sort last)
    improvements.sort_by(|a, b| {
        b.get("points_available")
            .and_then(|v| v.as_i64())
            .unwrap_or(0)
            .cmp(
                &a.get("points_available")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0),
            )
    });

    let total_points_available: i64 = improvements
        .iter()
        .filter_map(|i| i.get("points_available").and_then(|v| v.as_i64()))
        .sum();

    // Persist the computed score back to the workflow row so the hygiene report,
    // semantic search, and any other tool that reads readiness_score get a fresh
    // value without needing to recompute. Best-effort: log on failure, never fail
    // the caller.
    //
    // MCP-1211 (2026-05-18): pre-fix this was TWO separate UPDATEs — score
    // first, then `readiness_scored_at = NOW()`. A transient DB error
    // between them left the row with a score but no timestamp, which
    // `classify_readiness_state` then had to paper over as "unscored". The
    // single-statement repository method writes both columns atomically.
    if let Err(e) = state
        .analytics_repo
        .set_workflow_readiness_score(wf_id, user_id, computed_score)
        .await
    {
        tracing::warn!(wf_id = %wf_id, score = computed_score, error = %e, "readiness_score write-back failed");
    }

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "workflow_id": wf_id.to_string(),
            "name": name,
            "workflow_type": workflow_type,
            "score": {
                "current": computed_score,
                "stored": computed_score,  // write-back completed above
                "max_possible": 100,
            },
            "components": {
                "reliability": {
                    "score": reliability.round() as i32,
                    "max": 50,
                    "weight": "50%",
                    "detail": {
                        "executions_30d": exec_count,
                        // MCP-111 (2026-05-08): replace ad-hoc rounding
                        // with the canonical `format_percent` helper used
                        // platform-wide post-MCP-19. The input is a 0-1
                        // fraction, so multiply by 100 first.
                        "success_rate": success_rate
                            .map(|r| talos_analytics_repository::format_percent(r * 100.0)),
                        "saturation_runs": 10,
                    }
                },
                "documentation": {
                    "score": documentation.round() as i32,
                    "max": 20,
                    "weight": "20%",
                    "detail": {
                        "has_description": has_desc,
                        "has_node_descriptions": has_node_desc,
                        "has_capabilities": has_caps,
                        "capabilities": caps,
                    }
                },
                "freshness": {
                    "score": freshness.round() as i32,
                    "max": 20,
                    "weight": "20%",
                    "detail": {
                        "last_executed": last_exec_at.map(|t| t.to_rfc3339()),
                        "days_since_last_execution": days_since_last,
                    }
                },
                "risk": {
                    "score": risk.round() as i32,
                    "max": 10,
                    "weight": "10%",
                    "detail": {
                        "has_timeout": has_timeout,
                        "has_error_edges": has_error_edges,
                        "expiring_secrets": expiring_secrets,
                        "retry_warning": retry_warning,
                    }
                },
            },
            "improvements": improvements,
            "total_points_available": total_points_available,
        }))
        .unwrap_or_default(),
    )
}

// ── get_all_readiness_scores ──────────────────────────────────────────────────

/// Classify a readiness row into `(is_unscored, score_state_label)`
/// from the two columns the DB returns: `readiness_score` (nullable
/// i32) and `readiness_scored_at` (nullable timestamp).
///
/// `scored_at` is the single authoritative "has been scored"
/// indicator. The two columns can drift — a workflow can have a
/// non-null `readiness_score` (e.g. 22 from an initial insert)
/// while `readiness_scored_at` is still NULL — so anchoring on
/// `raw_score.is_none()` (the original buggy predicate) would
/// classify those rows as "scored" while the per-row label called
/// them "unscored". Returning a single `(is_unscored, label)`
/// pair forces both consumers (the row's `score_state` field AND
/// the summary's `unscored_count`) onto the same predicate.
pub(crate) fn classify_readiness_state(
    raw_score: Option<i32>,
    scored_at: Option<chrono::DateTime<chrono::Utc>>,
) -> (bool, &'static str) {
    let is_unscored = scored_at.is_none();
    let score = raw_score.unwrap_or(0);
    let label = if is_unscored {
        "unscored"
    } else if score == 0 {
        "scored_zero" // scored, genuinely zero — needs improvement
    } else {
        "scored" // scored, non-zero
    };
    (is_unscored, label)
}

async fn handle_get_all_readiness_scores(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // MCP-275 (2026-05-10): pre-fix `filter_map` silently dropped any
    // entry that wasn't a valid UUID — user passes
    // `workflow_ids: ["abc", <valid_uuid>]` and gets readiness scores
    // for ONE workflow instead of an error. Same MCP-249 / MCP-274
    // family. Reject malformed entries loudly with the bad index.
    let filter_ids: Option<Vec<uuid::Uuid>> = match args.get("workflow_ids") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::Array(arr)) => {
            if arr.is_empty() {
                None
            } else {
                let mut ids: Vec<uuid::Uuid> = Vec::with_capacity(arr.len());
                for (i, item) in arr.iter().enumerate() {
                    match item.as_str().and_then(|s| s.parse::<uuid::Uuid>().ok()) {
                        Some(id) => ids.push(id),
                        None => {
                            return mcp_error(
                                req_id,
                                -32602,
                                &format!(
                                    "workflow_ids[{i}] is not a valid UUID; bulk parse rejects malformed entries instead of silently dropping them"
                                ),
                            )
                        }
                    }
                }
                Some(ids)
            }
        }
        Some(v) => {
            let kind = crate::utils::json_type_name(v);
            return mcp_error(
                req_id,
                -32602,
                &format!("workflow_ids must be an array of UUID strings, got {kind}"),
            );
        }
    };

    // MCP-275 (2026-05-10): pre-fix `as_f64().map(|f| f as i32)`
    // silently truncated large values (`max_score: 1e10` wrapped) and
    // collapsed wrong-type into None. Bound to readiness-score range
    // [0, 100] explicitly.
    let max_score: Option<i32> = match args.get("max_score") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => match v.as_f64() {
            Some(f) if !f.is_finite() => {
                return mcp_error(req_id, -32602, "max_score must be a finite number")
            }
            Some(f) if !(0.0..=100.0).contains(&f) => {
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("max_score must be in [0, 100], got {f}"),
                )
            }
            Some(f) => Some(f as i32),
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("max_score must be a number, got {kind}"),
                );
            }
        },
    };

    // MCP-267 (2026-05-10): direction-class wrong-type rejection.
    let include_archived =
        match crate::utils::validate_optional_bool(args, "include_archived", false, &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };

    let rows = state
        .analytics_repo
        .list_readiness_scores(user_id, filter_ids.as_deref(), max_score, include_archived)
        .await
        .unwrap_or_default();

    let mut below_50_count: i64 = 0;
    let mut unscored_count: i64 = 0;
    let mut score_sum: i64 = 0;

    let workflows: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            let raw_score = r.readiness_score;
            let score = raw_score.unwrap_or(0);
            let scored_at = r.readiness_scored_at;
            let score_age_hours: Option<i64> =
                scored_at.map(|t| (chrono::Utc::now() - t).num_hours());

            // Single authoritative "has been scored" indicator —
            // shared by the per-row state label AND the aggregate
            // counter so they can never diverge again. See
            // `classify_readiness_state` for the full rationale.
            let (is_unscored, score_state) = classify_readiness_state(raw_score, scored_at);

            score_sum += score as i64;
            if score < 50 {
                below_50_count += 1;
            }
            if is_unscored {
                unscored_count += 1;
            }

            let mut entry = serde_json::json!({
                "workflow_id": r.id.to_string(),
                "name": r.name,
                "readiness_score": score,
                "score_state": score_state,
                "has_description": r.has_description,
                "has_capabilities": r.has_capabilities,
                "scored_at": scored_at.map(|t| t.to_rfc3339()),
                "score_age_hours": score_age_hours,
            });
            if is_unscored {
                entry["note"] = serde_json::json!("Call get_readiness_breakdown to compute score");
            }
            entry
        })
        .collect();

    let total = workflows.len();
    let avg_score = if total > 0 {
        score_sum / total as i64
    } else {
        0
    };

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "total": total,
            "summary": {
                "avg_score": avg_score,
                "below_50_count": below_50_count,
                "unscored_count": unscored_count,
            },
            "workflows": workflows,
        }))
        .unwrap_or_default(),
    )
}

async fn handle_bulk_tag_workflows(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // MCP-286 (2026-05-10): pre-fix `filter_map(|v| v.as_str()?.parse().ok())`
    // silently dropped any entry that wasn't a parseable UUID — operator
    // sending `workflow_ids: ["abc", <valid>]` to auto_tag_capabilities
    // would get tagging applied to ONE workflow with no signal that
    // their typo'd entry was rejected. Same MCP-274 / MCP-285 family.
    let filter_ids: Vec<uuid::Uuid> = match args.get("workflow_ids") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(serde_json::Value::Array(arr)) => {
            let mut ids: Vec<uuid::Uuid> = Vec::with_capacity(arr.len());
            for (i, item) in arr.iter().enumerate() {
                match item.as_str().and_then(|s| s.parse::<uuid::Uuid>().ok()) {
                    Some(id) => ids.push(id),
                    None => {
                        return mcp_error(
                            req_id,
                            -32602,
                            &format!(
                                "workflow_ids[{i}] is not a valid UUID; bulk parse rejects malformed entries instead of silently dropping them"
                            ),
                        )
                    }
                }
            }
            ids
        }
        Some(v) => {
            let kind = crate::utils::json_type_name(v);
            return mcp_error(
                req_id,
                -32602,
                &format!("workflow_ids must be an array of UUID strings, got {kind}"),
            );
        }
    };

    // Fetch untagged workflows. When filter_ids is provided, restrict via ANY($2).
    let filter_ids_opt: Option<&[uuid::Uuid]> = if filter_ids.is_empty() {
        None
    } else {
        Some(&filter_ids)
    };
    let rows = match state
        .analytics_repo
        .get_untagged_workflows(user_id, filter_ids_opt)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("bulk_tag_workflows query failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to query untagged workflows");
        }
    };

    let mut tagged = 0usize;
    let mut skipped = 0usize;
    let mut results: Vec<serde_json::Value> = Vec::new();

    for row in &rows {
        let wf_id = row.id;
        let name = row.name.clone();
        let graph_json: String = row.graph_json.clone().unwrap_or_default();

        let suggestions = compute_capability_suggestions(&graph_json, &state.db_pool).await;

        if suggestions.is_empty() {
            // Graph has no WASM nodes / edges we can derive tags from (e.g. empty scaffold or QA fixture).
            // Caller should use set_workflow_capabilities to tag these manually.
            skipped += 1;
            results.push(serde_json::json!({
                "workflow_id": wf_id.to_string(),
                "name": name,
                "tags_applied": [],
                "skipped": true,
                "skip_reason": "no_graph_signals",
            }));
            continue;
        }

        match state
            .analytics_repo
            .set_workflow_capabilities_if_empty(wf_id, user_id, &suggestions)
            .await
        {
            Ok(_) => {
                tagged += 1;
                results.push(serde_json::json!({
                    "workflow_id": wf_id.to_string(),
                    "name": name,
                    "tags_applied": suggestions,
                    "skipped": false,
                }));
            }
            Err(e) => {
                tracing::warn!("bulk_tag_workflows: failed to update {}: {}", wf_id, e);
                skipped += 1;
                results.push(serde_json::json!({
                    "workflow_id": wf_id.to_string(),
                    "name": name,
                    "tags_applied": [],
                    "skipped": true,
                    "skip_reason": "update_failed",
                }));
            }
        }
    }

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "tagged": tagged,
            "skipped": skipped,
            "results": results,
            "note": if skipped > 0 && tagged == 0 {
                "All workflows were skipped. Workflows with skip_reason 'no_graph_signals' have no \
                 WASM module nodes — tag them manually with set_workflow_capabilities."
            } else {
                ""
            },
        }))
        .unwrap_or_default(),
    )
}

async fn handle_get_platform_hygiene_report(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let h = match state.analytics_repo.get_hygiene_report(user_id).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("get_platform_hygiene_report failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to generate hygiene report");
        }
    };

    // Auto-classify workflows whose names start with known QA/test prefixes.
    // These should be classified as workflow_type='test' but often aren't — exclude
    // them from readiness warnings and surface them as a separate recommendation.
    let test_name_prefixes = [
        "QA-", "qa-", "QA_", "qa_", "test-", "test_", "Test-", "Test_", "TEST-", "TEST_",
    ];
    let is_test_like = |name: &str| test_name_prefixes.iter().any(|p| name.starts_with(p));

    let auto_classified_count = h
        .undescribed
        .iter()
        .chain(h.uncapabilized.iter())
        .filter(|r| is_test_like(&r.name))
        .map(|r| r.id)
        .collect::<std::collections::HashSet<_>>()
        .len();

    let undescribed: Vec<serde_json::Value> = h
        .undescribed
        .iter()
        .filter(|r| !is_test_like(&r.name))
        .map(|r| {
            serde_json::json!({
                "id": r.id.to_string(),
                "name": r.name,
                "readiness_score": r.readiness_score,
                "created_at": r.created_at.to_rfc3339(),
            })
        })
        .collect();

    let uncapabilized: Vec<serde_json::Value> = h
        .uncapabilized
        .iter()
        .filter(|r| !is_test_like(&r.name))
        .map(|r| {
            serde_json::json!({
                "id": r.id.to_string(),
                "name": r.name,
                "description": r.description,
                "readiness_score": r.readiness_score,
                "created_at": r.created_at.to_rfc3339(),
            })
        })
        .collect();

    let suppressed_count = h.suppressed_count;
    let suppressed_low_score_count = h.suppressed_low_score_count;
    let unembedded_count = h.unembedded_count;
    let total_workflow_count = h.total_workflow_count;

    // --- 4. Orphaned compiled modules ---
    let orphaned_modules: Vec<serde_json::Value> = h
        .orphaned_modules
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id.to_string(),
                "name": r.name,
                "size_bytes": r.size_bytes,
                "compiled_at": r.compiled_at.to_rfc3339(),
            })
        })
        .collect();

    // --- 5. Stale stuck executions ---
    let stale_executions: Vec<serde_json::Value> = h
        .stale_executions
        .iter()
        .map(|r| {
            let hours_stuck = chrono::Utc::now()
                .signed_duration_since(r.started_at)
                .num_minutes() as f64
                / 60.0;
            serde_json::json!({
                "id": r.id.to_string(),
                "workflow_id": r.workflow_id.to_string(),
                "workflow_name": r.workflow_name,
                "status": r.status,
                "started_at": r.started_at.to_rfc3339(),
                "hours_stuck": format!("{:.1}", hours_stuck),
            })
        })
        .collect();

    // --- 6. Dormant enabled workflows ---
    let dormant_workflows: Vec<serde_json::Value> = h
        .dormant_workflows
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id.to_string(),
                "name": r.name,
                "created_at": r.created_at.to_rfc3339(),
                "last_execution": r.last_execution.map(|t| t.to_rfc3339()),
            })
        })
        .collect();

    let stale_draft_workflows: Vec<serde_json::Value> = h
        .stale_draft_workflows
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id.to_string(),
                "name": r.name,
                "created_at": r.created_at.to_rfc3339(),
            })
        })
        .collect();

    let idle_actors: Vec<serde_json::Value> = h
        .idle_actors
        .iter()
        .map(|r| {
            // MCP-6: emit a string-typed `last_active_label` ("never" or
            // RFC3339) alongside the raw `last_active` Option. Keeps the
            // semantic-correct null for programmatic null-check while
            // giving ops dashboards a label that's always renderable
            // without "missing field" confusion.
            let last_active_label = match r.last_active {
                Some(ref t) => t.to_rfc3339(),
                None => "never".to_string(),
            };
            serde_json::json!({
                "actor_id": r.id.to_string(),
                "name": r.name,
                "status": r.status,
                "last_active": r.last_active.map(|t| t.to_rfc3339()),
                "last_active_label": last_active_label,
                "total_executions": r.total_executions,
            })
        })
        .collect();

    // --- 10. Orphaned secrets ---
    let orphaned_secrets: Vec<serde_json::Value> = if h.has_wildcard_module {
        Vec::new()
    } else {
        h.orphaned_secrets
            .iter()
            .map(|r| {
                serde_json::json!({
                    "name": r.name,
                    "key_path": r.key_path,
                    "namespace": r.namespace.as_deref().unwrap_or("default"),
                    "created_at": r.created_at.to_rfc3339(),
                    "has_expiry": r.expires_at.is_some(),
                })
            })
            .collect()
    };

    // --- 11. Secrets missing expiry ---
    let secrets_without_expiry: Vec<serde_json::Value> = h
        .secrets_without_expiry
        .iter()
        .map(|r| {
            serde_json::json!({
                "name": r.name,
                "key_path": r.key_path,
                "created_at": r.created_at.to_rfc3339(),
            })
        })
        .collect();

    // --- Actor memories expiring within 24 hours ---
    let expiring_actor_memories: Vec<serde_json::Value> = h
        .expiring_actor_memories
        .iter()
        .map(|r| {
            serde_json::json!({
                "actor_id": r.actor_id.to_string(),
                "actor_name": r.actor_name,
                "key": r.key,
                "memory_type": r.memory_type,
                "expires_at": r.expires_at.to_rfc3339(),
            })
        })
        .collect();

    // --- Production workflows needing input_schema ---
    let workflows_needing_schema: Vec<serde_json::Value> = h
        .workflows_needing_schema
        .iter()
        .map(|r| {
            serde_json::json!({
                "workflow_id": r.id.to_string(),
                "name": r.name,
                "execution_count": r.execution_count,
                "last_run": r.last_run.map(|t| t.to_rfc3339()).unwrap_or_default(),
            })
        })
        .collect();

    // --- Build summary and recommendations ---
    let mut recommendations: Vec<serde_json::Value> = Vec::new();

    if !undescribed.is_empty() {
        recommendations.push(serde_json::json!({
            "priority": "high",
            "category": "documentation",
            "action": format!("Add descriptions to {} published workflow(s) using set_workflow_description. Undescribed workflows score poorly in readiness and are hard for agents to discover.", undescribed.len()),
            "affected_count": undescribed.len(),
        }));
    }

    if !uncapabilized.is_empty() {
        recommendations.push(serde_json::json!({
            "priority": "high",
            "category": "discoverability",
            "action": format!("Add capabilities to {} workflow(s) using set_workflow_capabilities or suggest_capabilities. Workflows without capabilities cannot be found by get_workflows_by_capability.", uncapabilized.len()),
            "affected_count": uncapabilized.len(),
        }));
    }

    if unembedded_count > 0 {
        let pct = if total_workflow_count > 0 {
            unembedded_count * 100 / total_workflow_count
        } else {
            0
        };
        recommendations.push(serde_json::json!({
            "priority": "medium",
            "category": "semantic_search",
            "action": format!("{} of {} workflows ({pct}%) lack embeddings — semantic search falls back to keyword matching for these. Run generate_workflow_embeddings to index them for true vector search.", unembedded_count, total_workflow_count),
            "affected_count": unembedded_count,
        }));
    }

    if !orphaned_modules.is_empty() {
        let total_size: i64 = orphaned_modules
            .iter()
            .filter_map(|m| m.get("size_bytes").and_then(|v| v.as_i64()))
            .sum();
        recommendations.push(serde_json::json!({
            "priority": "low",
            "category": "cleanup",
            "action": format!("{} compiled module(s) are not used by any workflow ({}KB total). Use cleanup_modules to reclaim storage.", orphaned_modules.len(), total_size / 1024),
            "affected_count": orphaned_modules.len(),
        }));
    }

    if !stale_executions.is_empty() {
        recommendations.push(serde_json::json!({
            "priority": "critical",
            "category": "operations",
            "action": format!("{} execution(s) have been stuck in running/queued state for more than 2 hours. Use cleanup_stale_executions or cancel them individually.", stale_executions.len()),
            "affected_count": stale_executions.len(),
        }));
    }

    if !dormant_workflows.is_empty() {
        recommendations.push(serde_json::json!({
            "priority": "low",
            "category": "cleanup",
            "action": format!("{} enabled workflow(s) have had no executions in 30+ days. Consider disabling or deleting them with batch_delete_workflows to reduce registry noise.", dormant_workflows.len()),
            "affected_count": dormant_workflows.len(),
        }));
    }

    if !stale_draft_workflows.is_empty() {
        recommendations.push(serde_json::json!({
            "priority": "low",
            "category": "cleanup",
            "action": format!("{} draft workflow(s) have never been published or executed in 7+ days — likely scaffolding leftovers. Review with get_workflow_quickstart then publish_version or delete with batch_delete_workflows.", stale_draft_workflows.len()),
            "affected_count": stale_draft_workflows.len(),
        }));
    }

    if !idle_actors.is_empty() {
        recommendations.push(serde_json::json!({
            "priority": "low",
            "category": "cleanup",
            "action": format!("Terminate or archive {} idle actor(s) to reduce attack surface and noise in list_actors. Use archive_actor to preserve history or terminate_actor for full cleanup.", idle_actors.len()),
            "affected_count": idle_actors.len(),
        }));
    }

    // MCP-1208 (2026-05-17): recommendation text routes operators to
    // the dashboard for both deletion and expiry-set actions. The
    // previous text referenced the `delete_secret` / `set_secret` MCP
    // tools that MCP-1201 removed — operators following the old text
    // would call a tool that no longer exists. Same docs-drift class
    // closed by MCP-1202 (CLAUDE.md + docs/*) but the hygiene-report
    // recommendation generator was missed in that sweep.
    if !orphaned_secrets.is_empty() {
        recommendations.push(serde_json::json!({
            "priority": "medium",
            "category": "security",
            "action": format!("{} secret(s) are not referenced by any module's allowed_secrets list. Delete them in the dashboard (Settings → Secrets) to reduce vault clutter and limit credential exposure — secret writes require 2FA and aren't available through MCP.", orphaned_secrets.len()),
            "affected_count": orphaned_secrets.len(),
        }));
    }

    if !secrets_without_expiry.is_empty() {
        recommendations.push(serde_json::json!({
            "priority": "medium",
            "category": "security",
            "action": format!("{} API key/token secret(s) have no expiry date set. Set an expiry in the dashboard (Settings → Secrets) to enforce rotation cadence — secret writes require 2FA and aren't available through MCP.", secrets_without_expiry.len()),
            "affected_count": secrets_without_expiry.len(),
        }));
    }

    // Wildcard secret grant: at least one installed module can read any vault path.
    // This is a security risk — a single compromised workflow can exfiltrate the entire vault.
    // Note: orphaned_secrets is suppressed when has_wildcard_module=true (every secret
    // might be referenced), so this recommendation surfaces in that scenario.
    if h.has_wildcard_module {
        let names_str = if h.wildcard_module_names.is_empty() {
            "unknown".to_string()
        } else {
            h.wildcard_module_names
                .iter()
                .map(|n| format!("'{}'", n))
                .collect::<Vec<_>>()
                .join(", ")
        };
        recommendations.push(serde_json::json!({
            "priority": "medium",
            "category": "security",
            "wildcard_modules": h.wildcard_module_names,
            "action": format!(
                "{} module(s) have wildcard secret access (allowed_secrets: [\"*\"]): {}. \
                 Each can read every secret in your vault — a single compromised or misbehaving \
                 workflow can exfiltrate all credentials. Reinstall with explicit allowed_secrets \
                 paths to limit blast radius. Use get_workflow_risk_assessment on workflows \
                 containing these modules to identify affected nodes.",
                h.wildcard_module_names.len(),
                names_str
            ),
            "affected_count": h.wildcard_module_names.len(),
        }));
    }

    if !expiring_actor_memories.is_empty() {
        let keys_preview: Vec<&str> = expiring_actor_memories
            .iter()
            .take(3)
            .filter_map(|m| m.get("key").and_then(|k| k.as_str()))
            .collect();
        recommendations.push(serde_json::json!({
            "priority": "high",
            "category": "actor_memory",
            "action": format!(
                "{} actor memory key(s) expire within 24 hours (e.g. {}). Use refresh_memory_ttl to extend TTL, or let them expire if the data is no longer needed.",
                expiring_actor_memories.len(),
                keys_preview.join(", ")
            ),
            "affected_count": expiring_actor_memories.len(),
        }));
    }

    if !workflows_needing_schema.is_empty() {
        let names_preview: Vec<&str> = workflows_needing_schema
            .iter()
            .take(3)
            .filter_map(|w| w.get("name").and_then(|n| n.as_str()))
            .collect();
        recommendations.push(serde_json::json!({
            "priority": "medium",
            "category": "input_schema",
            "action": format!(
                "{} published workflow(s) have execution history but no input_schema (e.g. {}). Run infer_workflow_input_schema on each, then set_workflow_input_schema to lock the contract and enable input validation.",
                workflows_needing_schema.len(),
                names_preview.join(", ")
            ),
            "affected_count": workflows_needing_schema.len(),
        }));
    }

    if auto_classified_count > 0 {
        recommendations.push(serde_json::json!({
            "priority": "low",
            "category": "classification",
            "action": format!(
                "{} workflow(s) have test-like name prefixes (QA-, test-, Test-) but are classified as production type — excluded from readiness warnings automatically. Use set_workflow_type with type='test' to formally classify them and keep your production metrics clean.",
                auto_classified_count
            ),
            "affected_count": auto_classified_count,
        }));
    }

    // Untyped serde_json::Value parsing is a wasmtime fuel anti-pattern.
    // Flag user modules whose source uses it and emit a ready-to-paste
    // generate_typed_scaffold fix command per module, seeded with the real
    // module_id so the capture path can pull a scrubbed sample from the
    // most recent completed execution. This turns the lint into a
    // one-click remediation: copy the command, review the generated
    // structs, fill in the run body, compile.
    if !h.untyped_value_modules.is_empty() {
        let names_preview = h
            .untyped_value_modules
            .iter()
            .take(5)
            .map(|m| format!("'{}'", m.name))
            .collect::<Vec<_>>()
            .join(", ");
        let suffix = if h.untyped_value_modules.len() > 5 {
            format!(" and {} more", h.untyped_value_modules.len() - 5)
        } else {
            String::new()
        };
        // Emit a fix command per flagged module. The commands are plain
        // JSON-RPC-style argument blocks the operator can copy-paste into
        // any MCP client; they reference source_module_id so the scaffold
        // generator pulls real captured samples via the DLP-scrubbed path
        // shipped in commit 1355e86 — no hand-crafted JSON required.
        let fix_commands: Vec<serde_json::Value> = h
            .untyped_value_modules
            .iter()
            .map(|m| {
                serde_json::json!({
                    "module_name": m.name,
                    "module_id": m.id.to_string(),
                    "tool": "generate_typed_scaffold",
                    "arguments": {
                        "name": format!("{}-typed", m.name),
                        "source_module_id": m.id.to_string(),
                    },
                    "next": "Review generated structs, fill in run body, then call compile_custom_sandbox with a fuel_budget derived from expected payload shape, then hot_update_module on the original to swap the implementation.",
                })
            })
            .collect();
        // Serialize the HygieneReport struct's module list into a compact
        // {id,name} array for the recommendation payload. Keeping the id
        // surfaced makes the recommendation self-contained.
        let flagged_modules: Vec<serde_json::Value> = h
            .untyped_value_modules
            .iter()
            .map(|m| serde_json::json!({ "id": m.id.to_string(), "name": m.name }))
            .collect();
        recommendations.push(serde_json::json!({
            "priority": "medium",
            "category": "performance",
            "untyped_value_modules": flagged_modules,
            "fix_commands": fix_commands,
            "action": format!(
                "{} module(s) parse input via untyped serde_json::Value: {}{}. \
                 Value parsing allocates HashMap<String, Value> per JSON object and dominates \
                 wasmtime fuel on large payloads — 3–10× more expensive than typed #[derive(Deserialize)] \
                 structs. Each flagged module has a ready-to-paste fix command in `fix_commands` that \
                 calls generate_typed_scaffold with source_module_id pre-filled — the tool will pull a \
                 real captured sample from the module's most recent completed execution (DLP-scrubbed) \
                 and emit typed Deserialize structs for review. Reference incident: smart-email-drafts \
                 fetch-threads exhausted 30M fuel on Value parsing; typed rewrite dropped it below 1M.",
                h.untyped_value_modules.len(),
                names_preview,
                suffix
            ),
            "affected_count": h.untyped_value_modules.len(),
        }));
    }

    let secret_issues = orphaned_secrets.len()
        + secrets_without_expiry.len()
        + if h.has_wildcard_module { 1 } else { 0 };
    let issues_found = undescribed.len()
        + uncapabilized.len()
        + stale_executions.len()
        + orphaned_modules.len()
        + dormant_workflows.len()
        + stale_draft_workflows.len()
        + idle_actors.len()
        + secret_issues
        + expiring_actor_memories.len()
        + workflows_needing_schema.len()
        + if unembedded_count > 0 { 1 } else { 0 };

    let note = {
        let base = match (suppressed_count, auto_classified_count as i64) {
            (0, 0) => String::new(),
            (s, 0) => format!("{} internal/test workflow(s) excluded from readiness warnings (workflow_type=test/internal). Use set_workflow_type to classify QA fixtures.", s),
            (0, a) => format!("{} workflow(s) auto-excluded: test-like name prefix (QA-/test-) but no formal type set. Use set_workflow_type with type='test' to classify them.", a),
            (s, a) => format!("{} internal/test workflow(s) formally suppressed; {} more auto-excluded via name-prefix heuristic. Use set_workflow_type to normalize all test fixtures.", s, a),
        };
        if suppressed_low_score_count > 0 {
            format!("{}{}{} draft(s) with readiness_score<10 suppressed from documentation recommendations.", base, if base.is_empty() { "" } else { " " }, suppressed_low_score_count)
        } else {
            base
        }
    };

    // MCP-76 (2026-05-07): sort recommendations by priority desc so that
    // medium / high / critical entries appear above low-priority cleanup
    // items in the rendered output. Pre-fix, the order was insertion order
    // and a medium-severity "API key without expiry" landed below
    // low-priority "draft workflows" cleanup. Operators triaging would
    // miss security-class gaps unless they manually re-sorted.
    fn priority_rank(s: &str) -> u8 {
        match s {
            "critical" => 0,
            "high" => 1,
            "medium" => 2,
            "low" => 3,
            _ => 4,
        }
    }
    recommendations.sort_by(|a, b| {
        let ap = a.get("priority").and_then(|v| v.as_str()).unwrap_or("");
        let bp = b.get("priority").and_then(|v| v.as_str()).unwrap_or("");
        priority_rank(ap).cmp(&priority_rank(bp))
    });

    let report = serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "summary": {
            "total_issues": issues_found,
            "critical": stale_executions.len(),
            "high": undescribed.len() + uncapabilized.len() + expiring_actor_memories.len(),
            "medium": (if unembedded_count > 0 { 1 } else { 0 }) + secret_issues + workflows_needing_schema.len(),
            "low": orphaned_modules.len() + dormant_workflows.len() + stale_draft_workflows.len() + idle_actors.len(),
            "total_workflows": total_workflow_count,
            "idle_actors_count": idle_actors.len(),
            "wildcard_secret_grant": h.has_wildcard_module,
            "orphaned_secrets_count": orphaned_secrets.len(),
            "secrets_without_expiry_count": secrets_without_expiry.len(),
            "expiring_memories_count": expiring_actor_memories.len(),
            "workflows_needing_schema_count": workflows_needing_schema.len(),
            "suppressed_internal_test_workflows": suppressed_count,
            "suppressed_low_score_count": suppressed_low_score_count,
            "auto_classified_test_like_workflows": auto_classified_count,
            "embedding_coverage_percent": if total_workflow_count > 0 {
                (total_workflow_count - unembedded_count) * 100 / total_workflow_count
            } else { 100 },
            "note": note,
        },
        "stale_executions": stale_executions,
        "undescribed_workflows": undescribed,
        "uncapabilized_workflows": uncapabilized,
        "unembedded_workflow_count": unembedded_count,
        "orphaned_modules": orphaned_modules,
        "dormant_workflows": dormant_workflows,
        "stale_draft_workflows": stale_draft_workflows,
        "idle_actors": idle_actors,
        "orphaned_secrets": orphaned_secrets,
        "secrets_without_expiry": secrets_without_expiry,
        "expiring_actor_memories": expiring_actor_memories,
        "workflows_needing_schema": workflows_needing_schema,
        "recommendations": recommendations,
    });

    // ── fix_all mode ──────────────────────────────────────────────────────────
    // When fix_all=true, return a dry-run preview of what would be cleaned up.
    // When fix_all=true AND confirm=true, execute the cleanups and return results.
    // MCP-267 (2026-05-10): direction-class wrong-type rejection.
    // Pre-fix `confirm: "true"` (string) silently fell back to false
    // — the operator's confirmation was lost and the fix-mode silently
    // turned into another preview. Same for fix_all.
    let fix_all = match crate::utils::validate_optional_bool(args, "fix_all", false, &req_id) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if !fix_all {
        return mcp_text(
            req_id,
            &serde_json::to_string_pretty(&report).unwrap_or_default(),
        );
    }

    let confirm = match crate::utils::validate_optional_bool(args, "confirm", false, &req_id) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // Build the list of actionable fixes.
    //
    // M-I (2026-05-06): partition stale_draft_workflows into
    // auto-deletable vs substantive_skipped via the shared
    // `crate::advanced::is_substantive_workflow` predicate. Pre-fix,
    // ALL stale drafts went into `stale_draft_workflows_to_delete` —
    // including drafts that `session_start` simultaneously surfaced as
    // "ready for publish_version" (the unpublished_substantive_drafts
    // list). An operator running `fix_all confirm=true` after seeing
    // session_start's "5 substantive draft(s) ready to publish"
    // message would have nuked exactly the workflows they were about
    // to ship. Now: substantive drafts appear in `substantive_drafts_skipped`
    // (informational; surfaces the safety net to the operator) and
    // are EXCLUDED from auto-delete.
    let (substantive_drafts_skipped, auto_deletable_drafts): (Vec<_>, Vec<_>) = h
        .stale_draft_workflows
        .iter()
        .partition(|r| crate::advanced::is_substantive_workflow(r.graph_json.as_deref()));
    let draft_ids: Vec<uuid::Uuid> = auto_deletable_drafts.iter().map(|r| r.id).collect();
    let stale_exec_ids: Vec<uuid::Uuid> = h.stale_executions.iter().map(|r| r.id).collect();
    let orphaned_module_ids: Vec<uuid::Uuid> = h.orphaned_modules.iter().map(|r| r.id).collect();

    let fix_preview = serde_json::json!({
        "stale_draft_workflows_to_delete": auto_deletable_drafts.iter().map(|r| serde_json::json!({
            "id": r.id.to_string(), "name": r.name,
        })).collect::<Vec<_>>(),
        "substantive_drafts_skipped": substantive_drafts_skipped.iter().map(|r| serde_json::json!({
            "id": r.id.to_string(),
            "name": r.name,
            "reason": "Has SYSTEM_PROMPT/OUTPUT_SCHEMA/retry/description markers — auto-delete refused. \
                      Use publish_version, or delete explicitly via batch_delete_workflows.",
        })).collect::<Vec<_>>(),
        "stale_executions_to_cancel": h.stale_executions.iter().map(|r| serde_json::json!({
            "id": r.id.to_string(),
            "workflow_name": r.workflow_name,
            "status": r.status,
        })).collect::<Vec<_>>(),
        "orphaned_modules_to_delete": h.orphaned_modules.iter().map(|r| serde_json::json!({
            "id": r.id.to_string(), "name": r.name,
        })).collect::<Vec<_>>(),
        "total_fixable": draft_ids.len() + stale_exec_ids.len() + orphaned_module_ids.len(),
    });

    if !confirm {
        // Dry-run: return the hygiene report + preview, no mutations.
        let mut report_with_preview = report;
        report_with_preview["fix_all"] = serde_json::json!({
            "dry_run": true,
            "preview": fix_preview,
            "note": "Set confirm: true to execute these fixes. Items not listed (undescribed workflows, missing capabilities, expiring secrets) require manual attention.",
        });
        return mcp_text(
            req_id,
            &serde_json::to_string_pretty(&report_with_preview).unwrap_or_default(),
        );
    }

    // ── Execute fixes ──────────────────────────────────────────────────────────
    let mut fix_results = serde_json::json!({});

    // 1. Delete stale draft workflows
    if !draft_ids.is_empty() {
        let (deleted, blocked) = state
            .workflow_repo
            .delete_workflows(&draft_ids, user_id)
            .await
            .unwrap_or((vec![], vec![]));
        tracing::warn!(
            user_id = %user_id,
            deleted = deleted.len(),
            blocked = blocked.len(),
            "hygiene fix: deleted stale draft workflows"
        );
        fix_results["stale_drafts_deleted"] = serde_json::json!(deleted.len());
        fix_results["stale_drafts_blocked"] = serde_json::json!(blocked.len());
    }

    // 2. Cancel/fail stale executions (mark as failed after >120 min stuck)
    if !stale_exec_ids.is_empty() {
        let cancelled = state
            .execution_repo
            .cleanup_stale_executions(120, user_id)
            .await
            .unwrap_or(0);
        fix_results["stale_executions_cancelled"] = serde_json::json!(cancelled);
    }

    // 3. Delete orphaned compiled modules (not referenced by any workflow)
    if !orphaned_module_ids.is_empty() {
        let deleted_modules = state
            .module_repo
            .delete_orphaned_modules(&orphaned_module_ids, user_id)
            .await
            .unwrap_or(0);
        tracing::warn!(
            user_id = %user_id,
            deleted = deleted_modules,
            "hygiene fix: deleted orphaned modules"
        );
        fix_results["orphaned_modules_deleted"] = serde_json::json!(deleted_modules);
    }

    let mut report_with_results = report;
    report_with_results["fix_all"] = serde_json::json!({
        "dry_run": false,
        "executed": true,
        "preview": fix_preview,
        "results": fix_results,
        "note": "Fixes applied. Re-run get_platform_hygiene_report to verify the updated state.",
    });
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&report_with_results).unwrap_or_default(),
    )
}

#[cfg(test)]
mod retry_classifier_tests {
    use super::is_deterministic_failure;

    fn lower(s: &str) -> String {
        s.to_lowercase()
    }

    #[test]
    fn output_schema_violation_is_deterministic() {
        // Real prod failure: daily-brief synthesize node — same prompt
        // produces same prose-vs-JSON output every time. Retrying
        // 3x burns 3x LLM cost for zero outcome.
        let msg = lower(
            r#"Job failed after 2 attempts: execution failure: Component returned error: OUTPUT_SCHEMA enforcement fired: response is not valid JSON. Required keys: ["brief", "__memory_write__"]. Got prose: "I notice the untrusted data block contains what appears to b...". Fix the SYSTEM_PROMPT to instruct strict JSON output (no markdown, no prose)."#,
        );
        assert!(is_deterministic_failure(&msg));
    }

    #[test]
    fn fuel_exhausted_is_deterministic() {
        let msg = lower(
            "WASM fuel exhausted after 1710000 instructions. Your module ran out of computation budget.",
        );
        assert!(is_deterministic_failure(&msg));
    }

    #[test]
    fn compile_error_is_deterministic() {
        assert!(is_deterministic_failure(
            "compilation failed: error[E0308] mismatched types"
        ));
        assert!(is_deterministic_failure("compile error in module foo"));
    }

    #[test]
    fn stale_cleanup_is_deterministic() {
        // Auto-cleaned executions are aborted at the timeout
        // threshold; retrying the same workload hits the same wall.
        assert!(is_deterministic_failure(
            "auto-cleaned: execution stale (running > configured threshold)"
        ));
    }

    #[test]
    fn rate_limit_is_NOT_deterministic() {
        // Rate limits are transient — backoff + retry is exactly
        // the right strategy. Must NOT be flagged as deterministic.
        assert!(!is_deterministic_failure(
            "http 429 too many requests; rate limit exceeded"
        ));
    }

    #[test]
    fn network_timeout_is_NOT_deterministic() {
        // Network connection timeouts are usually transient.
        assert!(!is_deterministic_failure("connection refused by upstream"));
    }

    #[test]
    fn legacy_patterns_still_caught() {
        // Don't regress the original deterministic classes.
        assert!(is_deterministic_failure("resource not found"));
        assert!(is_deterministic_failure("invalid input"));
        assert!(is_deterministic_failure("unauthorized: missing token"));
        assert!(is_deterministic_failure("forbidden: insufficient scope"));
    }
}

#[cfg(test)]
mod readiness_classification_tests {
    use super::classify_readiness_state;

    fn t(year: i32, month: u32, day: u32) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_naive_utc_and_offset(
            chrono::NaiveDate::from_ymd_opt(year, month, day)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap(),
            chrono::Utc,
        )
    }

    #[test]
    fn null_scored_at_is_unscored_regardless_of_score_value() {
        // The exact bug `unscored_count: 0 vs 17 actually-unscored`
        // was triggered by this case: readiness_score populated
        // (e.g. 22 from initial insert) while scored_at NULL. The
        // old buggy predicate `raw_score.is_none()` would say
        // "scored" — wrong. The fix anchors on scored_at only.
        let (is_unscored, label) = classify_readiness_state(Some(22), None);
        assert!(is_unscored);
        assert_eq!(label, "unscored");
    }

    #[test]
    fn null_score_with_null_scored_at_is_unscored() {
        let (is_unscored, label) = classify_readiness_state(None, None);
        assert!(is_unscored);
        assert_eq!(label, "unscored");
    }

    #[test]
    fn scored_zero_when_scored_at_present_and_score_zero() {
        let (is_unscored, label) = classify_readiness_state(Some(0), Some(t(2026, 5, 7)));
        assert!(!is_unscored);
        assert_eq!(label, "scored_zero");
    }

    #[test]
    fn scored_when_both_present_and_nonzero() {
        let (is_unscored, label) = classify_readiness_state(Some(85), Some(t(2026, 5, 7)));
        assert!(!is_unscored);
        assert_eq!(label, "scored");
    }

    #[test]
    fn null_score_with_scored_at_is_scored_zero_not_unscored() {
        // Inverse drift: timestamp written but score not yet —
        // classify as "scored_zero" so operators know the scoring
        // pipeline at least ran. Either way, the per-row label and
        // the aggregate counter MUST agree.
        let (is_unscored, label) = classify_readiness_state(None, Some(t(2026, 5, 7)));
        assert!(!is_unscored);
        assert_eq!(label, "scored_zero");
    }

    #[test]
    fn aggregate_invariant_holds_across_drift_combos() {
        // Property test: across all four (score-present-or-not) ×
        // (scored_at-present-or-not) combinations, the
        // is_unscored boolean always agrees with `label == "unscored"`.
        // If the two ever drift, summary.unscored_count would
        // contradict the per-row entries — the original prod bug.
        let combos = [
            (None, None),
            (Some(0), None),
            (Some(50), None),
            (None, Some(t(2026, 5, 7))),
            (Some(0), Some(t(2026, 5, 7))),
            (Some(50), Some(t(2026, 5, 7))),
        ];
        for (s, ts) in combos {
            let (is_unscored, label) = classify_readiness_state(s, ts);
            assert_eq!(
                is_unscored,
                label == "unscored",
                "drift detected for (score={:?}, scored_at={:?})",
                s,
                ts
            );
        }
    }
}
