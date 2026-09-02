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

    if let Err(e) = repo
        .set_capabilities_if_empty(workflow_id, user_id, &suggestions)
        .await
    {
        tracing::warn!(
            %workflow_id,
            error = %e,
            "auto_suggest_capabilities: capability write failed; the workflow stays untagged for capability search"
        );
    }
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
            "description": "Overview of workflow health: failing workflows, long-running executions, and summary counts. The summary includes failure_rate_24h_pct (failed/(failed+completed) over 24h, null when no executions), and top_failures_24h lists up to 10 workflows grouped by 24h failure count with last_failed_at and a truncated representative error_message — this surfaces mass transient outages that the currently-failing heuristic misses.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
        serde_json::json!({
            "name": "get_workflow_dependencies",
            "description": "Canonical dependency-read tool — the `view` parameter selects the output shape. view='list' (default): all external dependencies of one workflow — modules, secrets, webhooks, and schedules (requires workflow_id). view='map': cross-workflow module-dependency map showing which modules are shared across which workflows, across ALL your workflows (no workflow_id needed; replaces the deprecated get_workflow_dependency_map). view='call_tree': the full call tree across sub-workflows — which workflows call which, with circular-reference detection (requires workflow_id; optional max_depth; replaces the deprecated get_workflow_call_tree). Each view emits the same JSON its legacy tool produced; the deprecated names still dispatch with a deprecation notice.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "view": { "type": "string", "enum": ["list", "map", "call_tree"], "description": "Output shape (default: 'list'). list/call_tree operate on one workflow (workflow_id required); map spans all your workflows (workflow_id ignored)." },
                    "workflow_id": { "type": "string", "description": "UUID of the workflow (required for views 'list' and 'call_tree'; ignored for 'map')" },
                    "max_depth": { "type": "number", "description": "view='call_tree' only. Maximum recursion depth (default 3, max 5)" }
                },
                "required": []
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
            "description": "Batch-validate every workflow for the current user, running the SAME checks validate_workflow runs. Returns errors (which make a workflow invalid) and warnings (which do NOT) separately: valid_count/invalid_count count workflows by ERROR only, while warning_count/workflows_with_warnings are independent. Detail lists are capped — `truncated` names exactly what was omitted, and the counts are always exact. `history` reports how many workflows the execution-history checks could actually see.",
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
            "description": "Comprehensive error analysis. With workflow_id: per-workflow report — total failures, error fingerprints, node-level failure breakdown, and time-of-day failure patterns. Without workflow_id: platform-wide rollup across all your workflows — total failures, error fingerprints grouped across workflows, and per-workflow failure counts. Useful after a mass/transient outage where no single workflow is the culprit.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to analyze. Omit for a platform-wide (user-scoped) rollup across all workflows." },
                    "days": { "type": "number", "description": "Number of days to look back (default: 7, max: 90)" },
                    "limit": { "type": "number", "description": "Global mode only: max workflows in the per-workflow failure breakdown (default: 20, max: 100)" }
                }
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
            "name": "get_operator_digest",
            "description": "Autonomy cockpit: a time-windowed view of what your AUTONOMOUS machinery did, learned, and needs you to decide. RAN — executions grouped by trigger_type (scheduled/webhook/actor_dispatch runs shown apart from manual ones), per-workflow stats, and schedule health (with overdue flags). LEARNED — what the loops produced: memory writes by kind (briefs/reflections/consolidations/CRM), per-actor rank-weight fits, ML loop health, judge scores (ONE ENTRY PER JUDGE NODE, not per workflow — a workflow running a rubric judge beside a coverage judge emits two entries with the SAME name, so key them on the workflow_id+node_id pair, which is also what probe_inline_judge takes). NEEDS_ME — the unified decision inbox: pending approvals + ops-alert corrections + ml_decisions + autonomous failures + active alert backlog, with a single total (ml_decisions are ML lifecycle gates the platform has parked: a satisfied policy with auto_advance off, or a stored verdict that predates banked evidence — each names the model, the version it judged and the stored unmet reasons verbatim; one item per model, capped). MIXED DENOMINATOR: total sums three ITEM counts (approvals, corrections, ml_decisions) plus autonomous_failures, which counts failed EXECUTIONS — one workflow failing thirty times moves total by thirty. needs_me.total_note states this in the payload; ops_backlog is not summed. Superset of get_daily_digest / assistant_report focused on autonomy oversight.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "days": { "type": "integer", "description": "Trailing window in days (1-31, default 1 = overnight)." }
                }
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
            "description": "Find workflows that have ALL of the specified capabilities. Returns workflows with success rates and readiness scores. POPULATION: success_rate_30d covers every execution ROW created in the trailing 30 days, in ANY status (a queued, still-running or cancelled execution is in the denominator but not the numerator); runs_30d is that exact denominator and is on every row. A rate over fewer than 20 runs is labeled sample_size=\"insufficient\": below 20, one failure moves the rate by 5+ points, so ranking two candidates by it is noise — prefer readiness_score or gather more runs.",
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
            // Deprecated alias (2026-07 consolidation) — identical output to
            // get_workflow_dependencies view='call_tree', with a deprecation
            // notice injected. Removed from tool_schemas; dispatch-only.
            let resp = handle_get_workflow_call_tree(req_id.clone(), args, state, user_id).await;
            Some(crate::actor::inject_deprecation_pub(
                resp,
                "get_workflow_call_tree",
                "get_workflow_dependencies (view: 'call_tree')",
            ))
        }
        "get_all_workflow_stats" => {
            Some(handle_get_all_workflow_stats(req_id, args, state, user_id).await)
        }
        "get_error_report" => Some(handle_get_error_report(req_id, args, state, user_id).await),
        "suggest_retry_config" => {
            Some(handle_suggest_retry_config(req_id, args, state, user_id).await)
        }
        "get_workflow_topology" => {
            // Deprecated alias (2026-07 consolidation) — identical output to
            // get_workflow_graph view='topology', with a deprecation notice
            // injected. Removed from tool_schemas; dispatch-only.
            let resp = handle_get_workflow_topology(req_id.clone(), args, state, user_id).await;
            Some(crate::actor::inject_deprecation_pub(
                resp,
                "get_workflow_topology",
                "get_workflow_graph (view: 'topology')",
            ))
        }
        "get_node_failure_breakdown" => {
            Some(handle_get_node_failure_breakdown(req_id, args, state, user_id).await)
        }
        "get_workflow_dependency_map" => {
            // Deprecated alias (2026-07 consolidation) — identical output to
            // get_workflow_dependencies view='map', with a deprecation notice
            // injected. Removed from tool_schemas; dispatch-only.
            let resp =
                handle_get_workflow_dependency_map(req_id.clone(), args, state, user_id).await;
            Some(crate::actor::inject_deprecation_pub(
                resp,
                "get_workflow_dependency_map",
                "get_workflow_dependencies (view: 'map')",
            ))
        }
        "get_workflow_performance_report" => {
            Some(handle_get_workflow_performance_report(req_id, args, state, user_id).await)
        }
        "get_workflow_risk_assessment" => {
            Some(handle_get_workflow_risk_assessment(req_id, args, state, user_id).await)
        }
        "get_daily_digest" => Some(handle_get_daily_digest(req_id, args, state, user_id).await),
        "get_operator_digest" => {
            Some(handle_get_operator_digest(req_id, args, state, user_id).await)
        }
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
    // All four list reads below are DISCLOSED. Pre-fix two swallowed the error
    // silently and two logged it and substituted `Vec::new()` — but a log is
    // invisible to the operator holding this output, and an empty list here
    // renders as "nothing is failing, nothing is stuck". The `*_count` fields
    // are the sharp edge: `failing_workflow_count: 0` is the single number a
    // dashboard or alert reads, and it is exactly the number the 2026-07-24
    // mass-outage incident (see `top_failures_24h` below) proved must not lie.
    let mut readings = talos_measurement::Readings::new();

    let failing_rows = readings.record_rows(
        "failing_workflows",
        state.analytics_repo.get_failing_workflows(user_id, 1).await,
    );

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

    let long_running_rows = readings.record_rows(
        "long_running_executions",
        state
            .analytics_repo
            .get_long_running_executions(user_id)
            .await,
    );

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
    let loop_capped_rows = readings.record_rows(
        "loop_capped_workflows",
        state
            .execution_repo
            .find_loop_capped_workflows_24h(user_id)
            .await,
    );

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

    // 2026-07-24: grouped 24h failure rollup. The `failing_workflows`
    // heuristic above only surfaces workflows that are CURRENTLY failing,
    // so a mass transient outage (many workflows each failing a few times,
    // then recovering) showed `failing_workflow_count: 0` while the raw
    // failed/completed counts said ~34% of runs died. `top_failures_24h`
    // + `failure_rate_24h_pct` make that class of incident visible.
    let top_failure_rows = readings.record_rows(
        "top_failures_24h",
        state.analytics_repo.get_top_failures_24h(user_id).await,
    );

    let top_failures: Vec<serde_json::Value> = top_failure_rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "workflow_id": r.workflow_id.to_string(),
                "workflow_name": r.workflow_name,
                "failed_count": r.failed_count,
                "last_failed_at": r.last_failed_at.map(|t| t.to_rfc3339()),
                "error_message": r
                    .latest_error_message
                    .as_deref()
                    .map(truncate_error_message),
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
    // A count derived from a list we could not read is null, not 0. Otherwise
    // the disclosure sits next to a `0` that still reads as an all-clear.
    let count_of = |field: &str, rendered: &[serde_json::Value]| -> Option<usize> {
        if readings.not_measured().contains(&field) {
            None
        } else {
            Some(rendered.len())
        }
    };

    let mut result = serde_json::json!({
        "summary": {
            "currently_running": summary.running,
            "failed_last_24h": summary.failed_24h,
            "completed_last_24h": summary.completed_24h,
            "failure_rate_24h_pct": failure_rate_pct(summary.failed_24h, summary.completed_24h),
            "failing_workflow_count": count_of("failing_workflows", &failing),
            "long_running_execution_count": count_of("long_running_executions", &long_running),
            "loop_capped_workflow_count": count_of("loop_capped_workflows", &loop_capped),
        },
        "failing_workflows": failing,
        "long_running_executions": long_running,
        "loop_capped_workflows": loop_capped,
        "top_failures_24h": top_failures,
    });
    readings.attach(&mut result);

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

/// Pure: 24h failure rate as failed/(failed+completed) percent, rounded
/// to 1 decimal. `None` (serialized as JSON null) when the window has no
/// terminal executions at all — a rate over zero runs is meaningless and
/// `0.0` would falsely read as "healthy".
pub(crate) fn failure_rate_pct(failed: i64, completed: i64) -> Option<f64> {
    let total = failed + completed;
    if total <= 0 || failed < 0 || completed < 0 {
        return None;
    }
    Some(((failed as f64 / total as f64) * 1000.0).round() / 10.0)
}

/// Representative error messages on the dashboard are previews, not full
/// payloads — cap at ~200 bytes on a char boundary (delegates to
/// `talos_text_util::bounded_preview`, which appends an ellipsis marker
/// when it truncates).
pub(crate) fn truncate_error_message(msg: &str) -> String {
    talos_text_util::bounded_preview(msg, 200).into_owned()
}

#[cfg(test)]
mod health_dashboard_summary_tests {
    use super::{failure_rate_pct, truncate_error_message};

    #[test]
    fn failure_rate_none_when_no_executions() {
        assert_eq!(failure_rate_pct(0, 0), None);
    }

    #[test]
    fn failure_rate_zero_when_all_completed() {
        assert_eq!(failure_rate_pct(0, 245), Some(0.0));
    }

    #[test]
    fn failure_rate_hundred_when_all_failed() {
        assert_eq!(failure_rate_pct(125, 0), Some(100.0));
    }

    #[test]
    fn failure_rate_rounds_to_one_decimal() {
        // The motivating incident: 125 failed / 245 completed → 33.8%.
        assert_eq!(failure_rate_pct(125, 245), Some(33.8));
        // 1/3 → 33.333... → 33.3
        assert_eq!(failure_rate_pct(1, 2), Some(33.3));
        // 2/3 → 66.666... → 66.7
        assert_eq!(failure_rate_pct(2, 1), Some(66.7));
    }

    #[test]
    fn failure_rate_negative_counts_are_null_not_garbage() {
        // Defensive: COUNT(*) can't go negative, but a future refactor
        // feeding a delta here shouldn't produce a nonsense percentage.
        assert_eq!(failure_rate_pct(-1, 10), None);
        assert_eq!(failure_rate_pct(10, -1), None);
    }

    #[test]
    fn truncation_passes_short_messages_through() {
        let msg = "connection refused by upstream";
        assert_eq!(truncate_error_message(msg), msg);
    }

    #[test]
    fn truncation_caps_long_messages() {
        let msg = "x".repeat(1000);
        let out = truncate_error_message(&msg);
        assert!(out.len() <= 200, "expected <= 200 bytes, got {}", out.len());
        assert!(out.ends_with('…'), "truncated preview carries a marker");
    }

    #[test]
    fn truncation_respects_char_boundaries() {
        // 4-byte scalar values: naive byte slicing at 200 would panic.
        let msg = "🦀".repeat(100); // 400 bytes
        let out = truncate_error_message(&msg);
        assert!(out.len() <= 200);
        // Must still be valid UTF-8 (implied by String) and non-empty.
        assert!(!out.is_empty());
    }
}

/// The three output shapes of the consolidated `get_workflow_dependencies`
/// tool (2026-07 workflow-read consolidation). `List` is the historical
/// `get_workflow_dependencies` body; the other two emit JSON byte-identical
/// to the deprecated tools they absorbed (`get_workflow_dependency_map` /
/// `get_workflow_call_tree`, still dispatchable as aliases).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DependencyView {
    List,
    Map,
    CallTree,
}

/// Parse the optional `view` argument. Absent / null → `List`
/// (back-compat: pre-consolidation calls carry no `view`). Unknown values
/// and wrong types reject loudly (-32602 at the handler) with the valid
/// list + per-view argument hints — never silently default.
fn parse_dependency_view(args: &serde_json::Value) -> Result<DependencyView, String> {
    match args.get("view") {
        None | Some(serde_json::Value::Null) => Ok(DependencyView::List),
        Some(serde_json::Value::String(s)) => match s.as_str() {
            "list" => Ok(DependencyView::List),
            "map" => Ok(DependencyView::Map),
            "call_tree" => Ok(DependencyView::CallTree),
            other => Err(format!(
                "Invalid 'view' value '{other}': must be one of 'list', 'map', \
                 'call_tree'. list (default) shows one workflow's external \
                 dependencies — modules, secrets, webhooks, schedules \
                 (workflow_id required); map shows cross-workflow module sharing \
                 across ALL your workflows (workflow_id ignored); call_tree walks \
                 sub-workflow calls from a root workflow (workflow_id required, \
                 optional max_depth 1-5)."
            )),
        },
        Some(v) => Err(format!(
            "'view' must be a string, got {}",
            crate::utils::json_type_name(v)
        )),
    }
}

/// Canonical dependency-read entry point: route on `view` to the
/// shape-specific implementation. Each implementation's output is
/// byte-identical to the tool it previously backed.
async fn handle_get_workflow_dependencies(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let view = match parse_dependency_view(args) {
        Ok(v) => v,
        Err(msg) => return mcp_error(req_id, -32602, &msg),
    };
    match view {
        DependencyView::List => {
            handle_get_workflow_dependencies_list(req_id, args, state, user_id).await
        }
        DependencyView::Map => {
            handle_get_workflow_dependency_map(req_id, args, state, user_id).await
        }
        DependencyView::CallTree => {
            handle_get_workflow_call_tree(req_id, args, state, user_id).await
        }
    }
}

async fn handle_get_workflow_dependencies_list(
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
/// Cap on the workflows rendered into `issues` / `warnings`.
///
/// The COUNTS are always exact and always over every workflow — only the
/// per-workflow detail lists are bounded. A truncated list that reads as
/// complete is the defect this whole change is about, so the response says
/// exactly what it dropped under `truncated`.
const FLEET_MAX_DETAIL_WORKFLOWS: usize = 50;

/// Cap on findings rendered per workflow, per severity.
///
/// Measured on the live fleet (2026-09-01): 86 warnings across 28 workflows,
/// max 7 on one. At 500 workflows the uncapped body would be megabytes.
const FLEET_MAX_FINDINGS_PER_WORKFLOW: usize = 10;

/// Accumulates one `ValidationResult` per workflow into the
/// `validate_all_workflows` response.
///
/// A separate type, driven from a test, because the COUNT SEMANTICS are the
/// part of this response most easily got wrong and least easily noticed:
///
/// * `valid_count` / `invalid_count` partition workflows by **Error only**. A
///   workflow with warnings and no errors is VALID. Letting a warning quietly
///   start counting as invalid would be the same class of silent redefinition
///   that this whole change exists to undo.
/// * `error_count` / `warning_count` / `workflows_with_warnings` are EXACT
///   over every workflow, and are computed before any cap applies. A cap may
///   shorten the detail lists; it may never move a count.
/// * `truncated` states what the caps dropped. A truncated list that reads as
///   complete is precisely the defect this repository keeps paying for, so it
///   is reported rather than inferred from a length.
#[derive(Default)]
pub(crate) struct FleetValidationTally {
    valid_count: u32,
    invalid_count: u32,
    error_count: usize,
    warning_count: usize,
    workflows_with_warnings: u32,
    history_consulted: u32,
    history_empty: u32,
    history_unavailable: u32,
    issues_list: Vec<serde_json::Value>,
    warnings_list: Vec<serde_json::Value>,
    issue_workflows_omitted: u32,
    warning_workflows_omitted: u32,
    findings_omitted: usize,
}

impl FleetValidationTally {
    pub(crate) fn record(
        &mut self,
        workflow_id: Uuid,
        workflow_name: &str,
        result: &talos_workflow_validation::ValidationResult,
    ) {
        use talos_workflow_validation::HistoryCoverage;

        match &result.history {
            HistoryCoverage::Observed { .. } => self.history_consulted += 1,
            HistoryCoverage::Empty { .. } => self.history_empty += 1,
            HistoryCoverage::Unavailable => self.history_unavailable += 1,
        }

        let errors = result.errors();
        let warnings = result.warnings();

        // Counts first, and unconditionally — before any cap can be reached.
        self.error_count += errors.len();
        self.warning_count += warnings.len();
        if errors.is_empty() {
            self.valid_count += 1;
        } else {
            self.invalid_count += 1;
        }
        if !warnings.is_empty() {
            self.workflows_with_warnings += 1;
        }
        debug_assert_eq!(
            errors.len() + warnings.len(),
            result.issues.len(),
            "ValidationSeverity gained a variant neither bucket counts"
        );

        Self::push(
            &mut self.issues_list,
            &mut self.issue_workflows_omitted,
            &mut self.findings_omitted,
            workflow_id,
            workflow_name,
            &errors,
            "issues",
        );
        Self::push(
            &mut self.warnings_list,
            &mut self.warning_workflows_omitted,
            &mut self.findings_omitted,
            workflow_id,
            workflow_name,
            &warnings,
            "warnings",
        );
    }

    fn push(
        bucket: &mut Vec<serde_json::Value>,
        omitted_workflows: &mut u32,
        findings_omitted: &mut usize,
        workflow_id: Uuid,
        workflow_name: &str,
        findings: &[&talos_workflow_validation::ValidationIssue],
        key: &str,
    ) {
        if findings.is_empty() {
            return;
        }
        if bucket.len() >= FLEET_MAX_DETAIL_WORKFLOWS {
            *omitted_workflows += 1;
            *findings_omitted += findings.len();
            return;
        }
        let shown = findings.len().min(FLEET_MAX_FINDINGS_PER_WORKFLOW);
        *findings_omitted += findings.len() - shown;
        bucket.push(serde_json::json!({
            "workflow_id": workflow_id.to_string(),
            "workflow_name": workflow_name,
            key: findings[..shown]
                .iter()
                .map(|i| i.message.clone())
                .collect::<Vec<_>>(),
            // Present even when nothing was dropped, so a reader never has to
            // infer completeness from a list length.
            "total_for_workflow": findings.len(),
        }));
    }

    pub(crate) fn render(self, window_days: i32) -> serde_json::Value {
        // MCP-110 (2026-05-08): emit canonical `count` alongside legacy
        // `total` for envelope consistency with list_workflows / list_executions.
        let total_workflows = self.valid_count + self.invalid_count;
        serde_json::json!({
            "valid_count": self.valid_count,
            "invalid_count": self.invalid_count,
            "count": total_workflows,
            "total": total_workflows,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "workflows_with_warnings": self.workflows_with_warnings,
            "issues": self.issues_list,
            "warnings": self.warnings_list,
            "truncated": {
                "issue_workflows_omitted": self.issue_workflows_omitted,
                "warning_workflows_omitted": self.warning_workflows_omitted,
                "findings_omitted": self.findings_omitted,
                "max_detail_workflows": FLEET_MAX_DETAIL_WORKFLOWS,
                "max_findings_per_workflow": FLEET_MAX_FINDINGS_PER_WORKFLOW,
            },
            // What the history-based checks could actually see. An empty
            // `warnings` list is not evidence of health when history was
            // unavailable — this says which it was.
            "history": {
                "window_days": window_days,
                "consulted": self.history_consulted,
                "empty": self.history_empty,
                "unavailable": self.history_unavailable,
            },
        })
    }
}

/// Fleet-wide validation.
///
/// **ONE checker.** This runs `talos_workflow_validation::validate_prepared`
/// — the same function `validate_workflow` runs — over inputs batch-loaded
/// once for every workflow. It does NOT carry its own copy of any check.
///
/// # Why it used to, and what that cost
///
/// This handler previously re-implemented validation inline, because calling
/// `WorkflowValidationService::validate` in a loop issues five queries per
/// workflow and the sweep already batch-loaded the same rows across all of
/// them (MCP-402 had removed exactly that N+1 from the existence checks). The
/// duplicate then drifted, as a duplicate does. Measured against the live
/// fleet on 2026-09-01, the inline copy reported **28 workflows, 1 invalid**
/// where the shared validator finds **2 invalid and 86 warnings**:
///
/// * It missed an **ERROR**, not just warnings: `stress-04-security`'s
///   `AUTH_HEADER` references `vault://anthropic/api_key` against a module
///   whose `allowed_secrets` is empty (deny-all). The inline vault check
///   matched `vault://` as a bare PREFIX via `strip_prefix`, and **all 39
///   vault references on the fleet are embedded** (`Bearer vault://…`) — so
///   its only security check had **0/39 recall** and was dead code on the
///   entire live corpus.
/// * It reported unreachable nodes as an ERROR where the shared validator
///   grades them a Warning, so the two surfaces disagreed on `valid` in the
///   other direction too.
/// * Every check added to `talos-workflow-validation` since — retry
///   envelopes, fuel sizing, observed failure history, disabled retries,
///   at-least-once durability — was invisible fleet-wide. The retry-envelope
///   check has a production incident behind it.
///
/// # How this stays out of the N+1
///
/// Five batched loads, ONE round trip each, regardless of workflow count:
/// module existence, template rows, installed secret grants, actor bindings,
/// and execution history (`node_run_history_batch`'s `LATERAL`, which keeps
/// the per-workflow `LIMIT` that a flat `ANY($1)` would collapse). Then a
/// pure, I/O-free `validate_prepared` per workflow.
async fn handle_validate_all_workflows(
    req_id: Option<serde_json::Value>,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    use talos_workflow_validation::{
        graph_module_ids, validate_prepared, PreparedValidation, HISTORY_MAX_EXECUTIONS,
    };

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

    // Parse each graph ONCE. `validate_prepared` re-parses from the same
    // string with the same malformed-graph fallback, so the two never
    // disagree about what the graph is; this copy only resolves module ids.
    let workflow_ids: Vec<uuid::Uuid> = workflows.iter().map(|w| w.id).collect();
    let per_workflow_modules: Vec<Vec<uuid::Uuid>> = workflows
        .iter()
        .map(|w| {
            let graph: serde_json::Value =
                serde_json::from_str(w.graph_json.as_deref().unwrap_or(""))
                    .unwrap_or_else(|_| serde_json::json!({"nodes": [], "edges": []}));
            graph_module_ids(&graph)
        })
        .collect();

    let all_module_ids: Vec<uuid::Uuid> = {
        let mut seen = std::collections::HashSet::new();
        per_workflow_modules
            .iter()
            .flatten()
            .copied()
            .filter(|id| seen.insert(*id))
            .collect()
    };

    // ── The five batched loads ────────────────────────────────────────────
    // Each is ONE query for the WHOLE fleet. This is the constraint that
    // made the inline duplicate exist; it is met here rather than worked
    // around. `tokio::join!` so they overlap on the wire too.
    let window_days = talos_workflow_validation::history_window_days();
    let (existing, templates, installed_secrets, bound_actors, history) = tokio::join!(
        state.workflow_repo.modules_exist(&all_module_ids),
        state.workflow_repo.get_templates_by_ids(&all_module_ids),
        state
            .workflow_repo
            .get_installed_secrets_by_template_ids(&all_module_ids, user_id),
        state
            .workflow_repo
            .workflows_with_bound_actor(&workflow_ids, user_id),
        state.workflow_repo.node_run_history_batch(
            &workflow_ids,
            user_id,
            window_days,
            HISTORY_MAX_EXECUTIONS,
        ),
    );

    let existing_modules: std::collections::HashSet<uuid::Uuid> =
        existing.unwrap_or_default().into_iter().collect();
    let templates_by_id: std::collections::HashMap<uuid::Uuid, _> = templates
        .unwrap_or_default()
        .into_iter()
        .map(|r| (r.id, r))
        .collect();
    let installed_secrets = installed_secrets.unwrap_or_default();
    let bound_actors = bound_actors.unwrap_or_default();
    // A FAILED batch history read must not read as "no history" for all 28
    // workflows — that is the error-as-absence shape `HistoryCoverage` exists
    // to prevent. The message is carried into every workflow's result, which
    // renders it as `history.unavailable`.
    let history = match history {
        Ok(map) => Ok(map),
        Err(e) => {
            tracing::error!(
                target: "talos_validation",
                error = %e,
                event_kind = "fleet_validation_history_read_failed",
                "validate_all_workflows: batched execution-history read failed — \
                 history checks did not run for ANY workflow"
            );
            Err(e.to_string())
        }
    };

    let mut tally = FleetValidationTally::default();

    for (wf_row, module_ids) in workflows.iter().zip(per_workflow_modules.iter()) {
        // Narrow every fleet-wide map to the modules THIS workflow dispatches
        // before handing it over. Two reasons, and the second is the load-
        // bearing one:
        //
        // 1. Cost: this is O(this workflow's nodes), where cloning the whole
        //    fleet map per workflow would be O(workflows x fleet modules).
        // 2. Correctness: `validate_prepared` builds its side-effecting-node
        //    list and its durability advisory by SCANNING the template rows,
        //    so a superset would attribute another workflow's modules to this
        //    one. It re-narrows defensively; this is the primary narrowing.
        let existing: std::collections::HashSet<uuid::Uuid> = module_ids
            .iter()
            .copied()
            .filter(|id| existing_modules.contains(id))
            .collect();
        let templates: Vec<_> = module_ids
            .iter()
            .filter_map(|id| templates_by_id.get(id).cloned())
            .collect();
        let installed: std::collections::HashMap<uuid::Uuid, Vec<String>> = module_ids
            .iter()
            .filter_map(|id| installed_secrets.get(id).map(|v| (*id, v.clone())))
            .collect();

        let wf_history = match &history {
            // An id absent from a SUCCESSFUL batch means the workflow has no
            // executions in the window — a real empty slice, not a failed
            // read. `node_run_history_batch` returns a row for every id it was
            // asked about, so this is belt-and-braces.
            Ok(map) => Ok(map.get(&wf_row.id).cloned().unwrap_or(
                talos_workflow_repository::NodeRunHistory {
                    executions_scanned: 0,
                    window_days,
                    nodes: Vec::new(),
                },
            )),
            Err(e) => Err(e.clone()),
        };

        let result = validate_prepared(PreparedValidation {
            workflow_id: wf_row.id,
            graph_json: wf_row.graph_json.clone().unwrap_or_default(),
            existing_modules: existing,
            templates,
            installed_secrets: installed,
            has_actor: bound_actors.contains(&wf_row.id),
            history: wf_history,
        });

        tally.record(wf_row.id, &wf_row.name, &result);
    }

    let result = tally.render(window_days);

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

    // Every read below is DISCLOSED, not defaulted. Pre-fix each one ended
    // `.unwrap_or(0)`, so a database problem rendered this tool's output as a
    // maximally healthy system: no stuck executions, no unacknowledged alerts,
    // no errors in the last hour — which is exactly what an operator opens this
    // tool to check during an incident. `Readings` nulls the field and names it
    // under `measurement.not_measured`; see `talos_measurement::Readings` for
    // the class and its two prior local repairs (#699, #702).
    let mut readings = talos_measurement::Readings::new();

    let active_schedules = readings.record(
        "active_schedules",
        state
            .analytics_repo
            .count_active_schedules_for_user(user_id)
            .await,
    );
    let active_webhooks = readings.record(
        "active_webhooks",
        state
            .analytics_repo
            .count_active_webhooks_for_user(user_id)
            .await,
    );
    let stale_executions = readings.record(
        "stale_executions",
        state
            .analytics_repo
            .count_stale_running_executions(user_id)
            .await,
    );
    let unack_alerts = readings.record(
        "unacknowledged_alerts",
        state
            .analytics_repo
            .count_unacknowledged_alerts(user_id)
            .await,
    );

    let error_rate = readings.record(
        "recent_failure_rate",
        state
            .analytics_repo
            .get_recent_exec_error_rate(user_id)
            .await,
    );
    let storage = readings.record(
        "disk_usage",
        state.analytics_repo.get_storage_bytes(user_id).await,
    );

    let result = render_system_health(
        db_ok,
        &SystemHealthReads {
            total_workflows: counts.workflows,
            total_modules: counts.modules + counts.templates,
            total_executions: counts.executions,
            active_schedules,
            active_webhooks,
            stale_executions,
            unacknowledged_alerts: unack_alerts,
            error_rate,
            storage,
        },
        &readings,
    );

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

/// The six DB-backed readings behind `get_system_health`, each already
/// resolved to `Some(measured)` / `None(could not measure)`.
///
/// A struct rather than nine positional arguments so the renderer can be driven
/// from a test without a database — the query-failed case is the entire point
/// of the fix, and it must be pinned against the code that actually ships, not
/// against a test-local copy of it.
pub(crate) struct SystemHealthReads {
    pub total_workflows: i64,
    pub total_modules: i64,
    pub total_executions: i64,
    pub active_schedules: Option<i64>,
    pub active_webhooks: Option<i64>,
    pub stale_executions: Option<i64>,
    pub unacknowledged_alerts: Option<i64>,
    /// `(total, failed)` executions in the last hour.
    pub error_rate: Option<(i64, i64)>,
    /// `(wasm_bytes, template_bytes)`.
    pub storage: Option<(i64, i64)>,
}

/// Pure: render the `get_system_health` response.
///
/// Every derived number stays `None` when its input was not measured. A rate
/// over an unmeasured denominator is not 0% — it is nothing — and a megabyte
/// figure computed from an unmeasured byte count is not "0.00 MB".
pub(crate) fn render_system_health(
    db_ok: bool,
    reads: &SystemHealthReads,
    readings: &talos_measurement::Readings,
) -> serde_json::Value {
    let hour_total = reads.error_rate.map(|(t, _)| t);
    let hour_failed = reads.error_rate.map(|(_, f)| f);
    let failure_rate_pct = reads.error_rate.map(|(total, failed)| {
        if total > 0 {
            (failed as f64 / total as f64 * 100.0).round()
        } else {
            0.0
        }
    });

    let total_wasm_bytes = reads.storage.map(|(wasm, template)| wasm + template);
    let wasm_size_mb = total_wasm_bytes.map(|b| format!("{:.2}", b as f64 / (1024.0 * 1024.0)));

    let mut result = serde_json::json!({
        "database_connected": db_ok,
        "total_workflows": reads.total_workflows,
        "total_modules": reads.total_modules,
        "total_executions": reads.total_executions,
        "active_schedules": reads.active_schedules,
        "active_webhooks": reads.active_webhooks,
        "stale_executions": reads.stale_executions,
        "unacknowledged_alerts": reads.unacknowledged_alerts,
        "recent_failure_rate": {
            "period": "last_hour",
            "total_executions": hour_total,
            "failed_executions": hour_failed,
            "failure_rate_pct": failure_rate_pct,
        },
        "disk_usage": {
            "total_wasm_bytes": total_wasm_bytes,
            "total_wasm_mb": wasm_size_mb,
        },
    });
    readings.attach(&mut result);
    result
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
    //
    // 2026-07-28: lifted verbatim into `talos_measurement::min_n_for_rate_target`
    // (which takes a FRACTION, not a percentage) so the model card and the
    // capability router judge sample size by the same rule. The old inline
    // version returned a 0 sentinel where there is no threshold; the shared
    // one returns None, which is the same branch below.
    let min_n_for_target: Option<u64> =
        talos_measurement::min_n_for_rate_target(target_success_rate / 100.0);
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
    // `total` is a row count (>= 0); the saturating conversion keeps a
    // hypothetical negative from wrapping into a huge u64 and suppressing the
    // warning (check 21).
    let total_u = u64::try_from(total).unwrap_or(0);
    if let Some(min_n_for_target) = min_n_for_target.filter(|m| total_u < *m) {
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

/// Which report `get_error_report` should produce, derived from the
/// (now-optional) `workflow_id` argument.
///
/// Kept as a pure parse step so the two modes' argument handling is unit-
/// testable without a DB: absent/null → `Global`; a valid UUID →
/// `PerWorkflow`; a malformed value is an ERROR (via
/// `parse_optional_uuid_strict`), never a silent fall-through to the
/// global rollup — a typo'd workflow_id silently widening the report to
/// every workflow would be the same silent-drop class MCP-309 fixed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ErrorReportMode {
    Global,
    PerWorkflow(Uuid),
}

pub(crate) fn parse_error_report_mode(
    args: &serde_json::Value,
    req_id: &Option<serde_json::Value>,
) -> Result<ErrorReportMode, JsonRpcResponse> {
    Ok(
        match crate::utils::parse_optional_uuid_strict(args, "workflow_id", req_id)? {
            Some(id) => ErrorReportMode::PerWorkflow(id),
            None => ErrorReportMode::Global,
        },
    )
}

/// Pure: group raw `(error_message, started_at)` rows (most-recent first)
/// into fingerprint buckets and return the top-`top_k` as JSON objects
/// `{fingerprint, count, latest_message, latest_at}`.
///
/// Shared by BOTH `get_error_report` modes (per-workflow and global) so
/// the fingerprinting behavior can never drift between them — this is the
/// logic that previously lived inline in the per-workflow handler.
/// Ordered by count desc with the fingerprint string as a deterministic
/// tiebreaker (the inline version iterated a HashMap, so tie order was
/// nondeterministic across runs).
pub(crate) fn group_error_fingerprints(
    error_rows: &[(String, chrono::DateTime<chrono::Utc>)],
    top_k: usize,
) -> Vec<serde_json::Value> {
    // HashMap<fingerprint, (count, latest_message, latest_at)> — keeping
    // the most-recent timestamp + message means the first row encountered
    // (rows are DESC-sorted) wins, and later rows just bump count.
    let mut fingerprint_groups: std::collections::HashMap<
        String,
        (usize, String, chrono::DateTime<chrono::Utc>),
    > = std::collections::HashMap::new();
    for (msg, started_at) in error_rows {
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

    let mut groups: Vec<(String, usize, String, chrono::DateTime<chrono::Utc>)> =
        fingerprint_groups
            .into_iter()
            .map(|(fp, (count, latest_msg, latest_at))| (fp, count, latest_msg, latest_at))
            .collect();
    groups.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    groups.truncate(top_k);
    groups
        .into_iter()
        .map(|(fp, count, latest_msg, latest_at)| {
            serde_json::json!({
                "fingerprint": fp,
                "count": count,
                "latest_message": latest_msg,
                "latest_at": latest_at.to_rfc3339(),
            })
        })
        .collect()
}

/// Source-row cap for the GLOBAL fingerprint rollup. Higher than the
/// per-workflow 200 because it spans every workflow the user owns; still
/// a hard bound so a pathological failure storm can't make the handler
/// pull unbounded rows.
const GLOBAL_ERROR_ROWS_CAP: i64 = 500;

async fn handle_get_error_report(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let wf_id = match parse_error_report_mode(args, &req_id) {
        Ok(ErrorReportMode::PerWorkflow(id)) => id,
        Ok(ErrorReportMode::Global) => {
            return handle_error_report_global(req_id, args, state, user_id).await;
        }
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

    // `total_failures: 0` is the headline of this tool, and pre-fix a failed
    // stats query produced it from a hand-written zeroed struct — the tool
    // that answers "what is breaking" answering "nothing is breaking" because
    // it could not ask.
    let mut readings = talos_measurement::Readings::new();
    let total_failures = readings
        .record(
            "total_failures",
            state
                .analytics_repo
                .get_exec_stats(wf_id, user_id, days)
                .await,
        )
        .map(|stats| stats.failed);

    // MCP-99 (2026-05-08): error fingerprints now carry `latest_at` so
    // operators can tell whether a fingerprint is fresh or stale.
    // Source rows are ordered by started_at DESC, so the FIRST row seen
    // for a fingerprint is the most recent occurrence. The fuel-bump
    // detector below still wants Vec<String>, so we keep both views.
    let error_rows = readings.record_rows(
        "error_fingerprints",
        state
            .analytics_repo
            .get_error_messages_with_started_at(wf_id, user_id, days, 200)
            .await,
    );
    let error_msgs: Vec<String> = error_rows.iter().map(|(m, _)| m.clone()).collect();

    // Fingerprint grouping shared with the global mode — see
    // `group_error_fingerprints`.
    let error_fingerprints = group_error_fingerprints(&error_rows, 10);

    // Node-level failure breakdown from execution_events
    let node_failures = readings.record_rows(
        "node_failure_breakdown",
        state
            .analytics_repo
            .get_node_failure_counts(wf_id, user_id, days)
            .await,
    );

    // MCP-99 (2026-05-08): resolve node UUIDs to labels via the workflow
    // graph. Pre-fix this surface emitted bare synthetic UUIDs
    // (sha256-derived) which forced operators to cross-reference
    // get_workflow_graph manually. Sister tool `get_node_failure_breakdown`
    // already does the same resolution (per MCP-65); now this surface
    // matches.
    // Decorative only — this graph read exists solely to
    // resolve node UUIDs to human labels below. On failure every entry in
    // `node_failure_breakdown` falls back to its bare UUID (see the
    // `unwrap_or_else` in the map), so the failure COUNTS are untouched and the
    // degradation is visible in the output rather than hidden by it. Nothing
    // here makes a claim about system state.
    let graph_json_str = state
        .analytics_repo
        .get_workflow_graph_json(wf_id, user_id)
        // allow-benign-default: label prettification only; see the note above.
        .await
        .unwrap_or(None);
    let mut uuid_to_label: std::collections::HashMap<uuid::Uuid, String> =
        std::collections::HashMap::new();
    if let Some(gj) = graph_json_str {
        if let Ok(graph) = serde_json::from_str::<serde_json::Value>(&gj) {
            if let Some(nodes) = graph.get("nodes").and_then(|n| n.as_array()) {
                for node in nodes {
                    if let Some(node_id_str) = node.get("id").and_then(|v| v.as_str()) {
                        let node_uuid = talos_workflow_engine_core::engine_node_uuid(node_id_str);
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
    let hourly_rows = readings.record_rows(
        "hourly_failure_pattern",
        state
            .analytics_repo
            .get_hourly_failure_breakdown(wf_id, user_id, days)
            .await,
    );

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
    readings.attach(&mut result);

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

/// Global (no `workflow_id`) mode of `get_error_report`: a user-scoped,
/// platform-wide failure rollup for the window. Motivated by the same
/// 2026-07-24 incident as `top_failures_24h` — a mass transient outage
/// had no single workflow to point `get_error_report` at, and the
/// per-workflow requirement forced operators to iterate every workflow
/// by hand to see the blast radius.
///
/// Shares `group_error_fingerprints` with the per-workflow path so the
/// fingerprinting semantics are identical in both modes.
async fn handle_error_report_global(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let days = match crate::utils::validate_range_i64(args, "days", 1, 90, 7, &req_id) {
        Ok(v) => v as i32,
        Err(resp) => return resp,
    };
    // Caller-clamped breadth of the per-workflow breakdown (lint check 12
    // discipline — validated range, never a raw caller value into LIMIT).
    let limit = match crate::utils::validate_range_i64(args, "limit", 1, 100, 20, &req_id) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // Total failures across all the user's workflows in the window.
    // Pre-fix this logged and substituted an empty ExecStats, so the response
    // could self-contradict: `total_failures: 0` sitting directly above a
    // populated `error_fingerprints` list. The other two reads in this handler
    // already refuse to guess (they return `mcp_error`); this one now nulls and
    // discloses instead, because a rollup missing one of three sections is
    // still worth serving.
    let mut readings = talos_measurement::Readings::new();
    let total_failures = readings
        .record(
            "total_failures",
            state
                .analytics_repo
                .get_exec_stats_global(user_id, days)
                .await,
        )
        .map(|stats| stats.failed);

    let error_rows = match state
        .analytics_repo
        .get_error_messages_with_started_at_global(user_id, days, GLOBAL_ERROR_ROWS_CAP)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = %e, "global error-message query failed");
            return mcp_error(req_id, -32000, "Failed to fetch error report");
        }
    };
    let error_fingerprints = group_error_fingerprints(&error_rows, 10);

    let per_workflow_rows = match state
        .analytics_repo
        .get_per_workflow_failure_counts(user_id, days, limit)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = %e, "per-workflow failure-count query failed");
            return mcp_error(req_id, -32000, "Failed to fetch error report");
        }
    };
    let workflow_failure_counts: Vec<serde_json::Value> = per_workflow_rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "workflow_id": r.workflow_id.to_string(),
                "workflow_name": r.workflow_name,
                "failed_count": r.failed_count,
                "last_failed_at": r.last_failed_at.map(|t| t.to_rfc3339()),
            })
        })
        .collect();

    let mut result = serde_json::json!({
        "scope": "global",
        "period_days": days,
        "total_failures": total_failures,
        "error_fingerprints": error_fingerprints,
        "workflow_failure_counts": workflow_failure_counts,
    });
    readings.attach(&mut result);

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

#[cfg(test)]
mod error_report_mode_tests {
    use super::{group_error_fingerprints, parse_error_report_mode, ErrorReportMode};
    use chrono::{Duration, TimeZone, Utc};

    // -- argument parsing: the two modes -------------------------------

    #[test]
    fn missing_workflow_id_selects_global_mode() {
        let args = serde_json::json!({});
        assert_eq!(
            parse_error_report_mode(&args, &None).unwrap(),
            ErrorReportMode::Global
        );
    }

    #[test]
    fn null_workflow_id_selects_global_mode() {
        let args = serde_json::json!({ "workflow_id": null });
        assert_eq!(
            parse_error_report_mode(&args, &None).unwrap(),
            ErrorReportMode::Global
        );
    }

    #[test]
    fn valid_workflow_id_selects_per_workflow_mode() {
        let id = uuid::Uuid::new_v4();
        let args = serde_json::json!({ "workflow_id": id.to_string() });
        assert_eq!(
            parse_error_report_mode(&args, &None).unwrap(),
            ErrorReportMode::PerWorkflow(id)
        );
    }

    #[test]
    fn malformed_workflow_id_is_an_error_not_global_fallthrough() {
        // A typo'd workflow_id must NOT silently widen the report to
        // every workflow (silent-drop class, MCP-309).
        let args = serde_json::json!({ "workflow_id": "not-a-uuid" });
        assert!(parse_error_report_mode(&args, &None).is_err());
    }

    #[test]
    fn wrong_type_workflow_id_is_an_error() {
        let args = serde_json::json!({ "workflow_id": 42 });
        assert!(parse_error_report_mode(&args, &None).is_err());
    }

    // -- fingerprint grouping (shared by both modes) --------------------

    fn ts(offset_secs: i64) -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 24, 12, 0, 0).unwrap() + Duration::seconds(offset_secs)
    }

    #[test]
    fn groups_equivalent_messages_under_one_fingerprint() {
        let rows = vec![
            ("timeout after 91".to_string(), ts(2)),
            ("timeout after 32".to_string(), ts(1)),
        ];
        let out = group_error_fingerprints(&rows, 10);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["count"], 2);
        // Most recent occurrence wins as the representative message.
        assert_eq!(out[0]["latest_message"], "timeout after 91");
        assert_eq!(out[0]["latest_at"], ts(2).to_rfc3339());
    }

    #[test]
    fn orders_by_count_desc_with_fingerprint_tiebreaker() {
        let rows = vec![
            ("aaa distinct error".to_string(), ts(0)),
            ("zzz frequent error".to_string(), ts(1)),
            ("zzz frequent error".to_string(), ts(2)),
            ("bbb distinct error".to_string(), ts(3)),
        ];
        let out = group_error_fingerprints(&rows, 10);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0]["fingerprint"], "zzz frequent error");
        // Count ties break on fingerprint string, deterministically.
        assert_eq!(out[1]["fingerprint"], "aaa distinct error");
        assert_eq!(out[2]["fingerprint"], "bbb distinct error");
    }

    #[test]
    fn truncates_to_top_k() {
        let rows: Vec<(String, chrono::DateTime<Utc>)> = (0..15)
            .map(|i| (format!("unique error kind {i} occurred"), ts(i)))
            .collect();
        let out = group_error_fingerprints(&rows, 10);
        assert_eq!(out.len(), 10);
    }

    #[test]
    fn empty_rows_produce_empty_fingerprints() {
        assert!(group_error_fingerprints(&[], 10).is_empty());
    }
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

    /// Build the fixture from the REAL producer
    /// (`talos_worker_runtime::runtime::fuel_exhausted_message`) rather than a
    /// hand-typed copy of it, wrapped in the engine/dispatcher prefixes the
    /// controller adds on the way to `workflow_executions.error_message`.
    ///
    /// The hand-typed version drifted the moment the worker's message was
    /// reworded (2026-08): these tests kept passing against a string production
    /// no longer emitted, so they proved the regex worked on a museum piece.
    /// Binding to the producer means a future reword that drops
    /// `Current fuel limit: N` fails HERE, in the detector's own suite.
    ///
    /// Limitation worth stating: this binds the SHAPE, not the call sites. A
    /// worker path that stops calling `fuel_exhausted_message` altogether is
    /// still invisible to this test.
    fn msg(node: &str, limit: u64) -> String {
        format!(
            "node '{}' failed: Job failed after 1 attempts: execution failure: {}",
            node,
            talos_worker_runtime::runtime::fuel_exhausted_message(Some(limit), limit, None)
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

/// Render the per-node half of `suggest_retry_config`'s answer, and the largest
/// single count that is safe for every advised node.
///
/// **Every retry-safety judgement here is DELEGATED, not reimplemented.**
/// `WorkflowValidationService::retry_advice` loads the same rows
/// `validate_workflow` loads and runs `retry_advice_prepared`, which consumes
/// `retry_envelope_overrun`, `retry_headroom`, `disabled_retry_protection` and
/// `module_is_side_effecting` — the same functions `validate_prepared` calls.
/// This function only formats. That split is the point of #721: the advisor
/// used to answer a retry question with no view of the checks the validator was
/// already running, and returned `retry_count: 3` for a workflow whose nodes
/// the validator had flagged as overrunning at 2. Re-deriving any of it here
/// would recreate exactly the drift #720 removed from the fleet sweep.
///
/// Returns `(block, blanket_safe_retries)`. `blanket_safe_retries` is `None`
/// when the advice could not be produced — the caller must then say its
/// suggestion is UNBOUNDED rather than silently emit an unchecked number.
async fn build_retry_advice_block(
    state: &McpState,
    wf_id: Uuid,
    user_id: Uuid,
    desired_retries: Option<u32>,
) -> (serde_json::Value, Option<u32>) {
    let advice = match talos_workflow_validation::WorkflowValidationService::retry_advice(
        &state.workflow_repo,
        wf_id,
        user_id,
        desired_retries,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(%wf_id, error = %e, "suggest_retry_config: retry advice unavailable");
            return (
                serde_json::json!({
                    "available": false,
                    "note": "Per-node retry advice could NOT be produced (the graph, module rows \
                             or execution history could not be read). The workflow-level \
                             suggestion below is therefore UNBOUNDED: it has not been checked \
                             against any node's retry envelope, workflow budget, or ability to \
                             change state at an external destination. Run validate_workflow \
                             before applying it.",
                }),
                None,
            );
        }
    };

    let nodes: Vec<serde_json::Value> = advice
        .nodes
        .iter()
        .map(|n| {
            let mut obj = serde_json::json!({
                "node_id": n.node_id,
                "action": n.action(),
                "current_retry_count": n.current_retries,
                "recommended_retry_count": n.recommended_retries,
                "retry_count_source": if n.retries_declared {
                    "declared on the node (an explicit value always wins over the module default)"
                } else {
                    "module method-aware default (the node declares no retry_count)"
                },
                "per_attempt_timeout_secs": n.per_attempt_secs,
                "retry_backoff_ms": n.backoff_ms,
                "current_envelope_secs": n.current_envelope_secs,
                "recommended_envelope_secs": n.recommended_envelope_secs,
                "workflow_budget_secs": n.budget_secs,
                "budget_ceiling_retry_count": n.budget_ceiling,
                "module_default_retry_count": n.world_default_retries,
                "safe_max_retry_count": n.safe_max_retries,
                "state_changing": n.state_changing,
                "currently_overruns_budget": n.currently_overruns,
                "bounded_by": n.bounds.iter().map(describe_retry_bound).collect::<Vec<_>>(),
                "notes": n.notes,
            });
            if let Some(map) = obj.as_object_mut() {
                if let Some(prov) = n.provenance_note() {
                    map.insert("provenance".into(), serde_json::Value::String(prov.into()));
                }
                if n.changes_current() {
                    map.insert(
                        "apply_with".into(),
                        serde_json::Value::String(format!(
                            "update_node_config(workflow_id: '{}', node_id: '{}', retry_count: {})",
                            wf_id, n.node_id, n.recommended_retries
                        )),
                    );
                }
            }
            obj
        })
        .collect();

    let blanket = advice.blanket_safe_retries();
    let changed = advice.nodes.iter().filter(|n| n.changes_current()).count();
    let overrunning = advice.overrunning_nodes().len();
    let total_graph_nodes = advice.nodes.len() + advice.skipped.len();

    let block = serde_json::json!({
        "available": true,
        // Every count states its population — an unlabelled "4" here would be
        // read as "4 of the workflow's nodes" when it is 4 of the
        // module-dispatched ones.
        "population": format!(
            "{} module-dispatched node(s) advised of {} graph node(s); {} skipped (see \
             `skipped`). Counts below are over the ADVISED nodes only.",
            advice.nodes.len(), total_graph_nodes, advice.skipped.len()
        ),
        "workflow_budget_secs": advice.budget_secs,
        "workflow_budget_source": advice.budget_source,
        "workflow_has_bound_actor": advice.has_actor,
        "history_coverage": advice.history.note(),
        "nodes_recommended_to_change": changed,
        "nodes_currently_overrunning_budget": overrunning,
        "blanket_safe_retry_count": blanket,
        "nodes": nodes,
        "skipped": advice.skipped.iter().map(|s| serde_json::json!({
            "node_id": s.node_id,
            "reason": s.reason,
        })).collect::<Vec<_>>(),
    });

    (block, blanket)
}

/// Render one `RetryAdviceBound` for the response.
fn describe_retry_bound(bound: &talos_workflow_validation::RetryAdviceBound) -> serde_json::Value {
    match bound {
        talos_workflow_validation::RetryAdviceBound::Budget {
            max_retries,
            budget_secs,
            proposed_envelope_secs,
        } => serde_json::json!({
            "bound": "workflow_budget",
            "max_retry_count": max_retries,
            "workflow_budget_secs": budget_secs,
            "rejected_envelope_secs": proposed_envelope_secs,
            "reason": "A higher count's worst-case envelope exceeds the workflow's enforced \
                       wall-clock budget. The retry loop has no view of that deadline, so it \
                       starts an attempt that cannot finish; when the budget expires the whole \
                       execution is dropped, discarding every sibling node that had already \
                       completed.",
        }),
        talos_workflow_validation::RetryAdviceBound::ModuleDefault {
            cap_retries,
            current_retries,
            world_default_retries,
            capability_world,
            allowed_methods,
        } => serde_json::json!({
            "bound": "author_or_module_default",
            "max_retry_count": cap_retries,
            "current_retry_count": current_retries,
            "module_default_retry_count": world_default_retries,
            "capability_world": capability_world,
            "allowed_methods": allowed_methods,
            "reason": "The recommendation is never raised above the HIGHER of what the node \
                       already declares and what its module's own method-aware default grants, \
                       because that default is the platform's idempotency judgement: \
                       governance, messaging, database, unknown worlds and state-changing HTTP \
                       fail closed to 0 precisely so a blind retry cannot re-fire a \
                       non-idempotent send. Granting more than both would be on nobody's \
                       authority.",
        }),
    }
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

    // Load recent executions (last 30 days) via retry_config_executions.
    //
    // A FAILED read is not an empty history. Pre-#721 this was
    // `.unwrap_or_default()`, so a Postgres blip routed the request into the
    // cold-start branch below, which announces "No execution history found" —
    // a database error rendered as a confident statement about the workflow's
    // operational record, and the basis for a recommendation. That is the
    // benign-default class lint check 74 exists for. The branch is now taken
    // only on a genuinely empty window, and the error is named in the output.
    let exec_read = state
        .analytics_repo
        .get_retry_config_executions(wf_id, user_id)
        .await;
    let history_read_failed = exec_read.is_err();
    if let Err(ref e) = exec_read {
        tracing::error!(
            %wf_id,
            error = %e,
            "suggest_retry_config: execution-history read failed — advice is static-only"
        );
    }
    let exec_rows = exec_read.unwrap_or_default();

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

        // Bound the module-type default the same way the history path is
        // bounded. A fresh workflow is exactly where a blanket number does the
        // most damage: it has no observed record to contradict it, and its
        // nodes still have real budgets and real send semantics.
        let (advice_block, blanket) =
            build_retry_advice_block(state, wf_id, user_id, Some(suggested_retry_count)).await;
        let bounded_retry_count = blanket
            .map(|b| suggested_retry_count.min(b))
            .unwrap_or(suggested_retry_count);

        return mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "workflow_id": wf_id.to_string(),
                "basis": "module_type_defaults",
                "note": if history_read_failed {
                    "The execution-history read FAILED — this is NOT a statement that the \
                     workflow has no history. These are module-type-based defaults. Re-run once \
                     the history query succeeds."
                } else {
                    "No execution history found in the analysis window — these are \
                     module-type-based defaults, not data-driven recommendations. Re-run after a \
                     few executions for a calibrated suggestion."
                },
                "history_read_failed": history_read_failed,
                "detected_module_types": {
                    "llm": has_llm,
                    "http": has_http,
                    "database": has_db,
                    "queue": has_queue,
                },
                "suggested_retry_count": bounded_retry_count,
                "unbounded_module_type_retry_count": suggested_retry_count,
                "suggested_backoff_ms": suggested_backoff_ms,
                "suggested_strategy": strategy,
                "reasoning": reasoning,
                "per_node": advice_block,
                "apply_with": {
                    "tool": "update_node_config",
                    "hint": "Apply the PER-NODE recommendations in `per_node.nodes`, not this \
                             single number. `suggested_retry_count` is the largest value that is \
                             safe for every advised node, which is by construction too low for \
                             some of them."
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

    // ── Bound the class-derived number against what the platform would warn
    // about, per node (#721).
    //
    // `suggested_retry_count` above is derived from the workflow's failure
    // MIX. That is a real signal and it is kept — but it is a statement about
    // error classes, not about whether any particular node can afford another
    // attempt. On one live workflow it produced `retry_count: 3` for a
    // workflow whose gmail_work and organize_work nodes already overran their
    // 300 s budget at 2, and one of which the platform separately flags as
    // making state-changing external calls. The number was not wrong about the
    // failures; it was answering a question it could not see the constraints
    // for.
    //
    // The bound is `blanket_safe_retry_count` — the minimum over every advised
    // node of that node's own `safe_max_retries`, which the validation crate
    // computes from `max_retries_within_budget` (the inverse of
    // `retry_envelope_overrun`) and `default_max_retries_for_module`. Nothing
    // about that judgement is restated here.
    //
    // A class-derived count of ZERO is passed as `None`, not as `Some(0)`. The
    // deterministic-failure and all-succeeded branches both leave
    // `suggested_retry_count` at 0, and that is a statement about the retry
    // CONDITION ("retries are not the lever for these failures"), never an
    // instruction to strip the retries every node already has. `Some(0)` would
    // propose lowering every node in the workflow to zero — advice to disable
    // working retry protection, issued because nothing had failed.
    let (advice_block, blanket) = build_retry_advice_block(
        state,
        wf_id,
        user_id,
        (suggested_retry_count > 0).then_some(suggested_retry_count),
    )
    .await;
    let unbounded_retry_count = suggested_retry_count;
    let bounded_retry_count = blanket
        .map(|b| suggested_retry_count.min(b))
        .unwrap_or(suggested_retry_count);
    if bounded_retry_count < unbounded_retry_count {
        reasoning.push(format!(
            "The failure mix alone would suggest retry_count {unbounded_retry_count}, but that \
             value is not safe for every node in this workflow: the largest count that fits \
             every advised node's retry envelope inside the workflow budget — and that never \
             raises a node above the retries its module's own method-aware default grants — is \
             {bounded_retry_count}. Apply the per-node recommendations instead; a single \
             workflow-wide number is the instrument that produced the contradiction."
        ));
    }
    if blanket.is_none() {
        reasoning.push(
            "Per-node advice could NOT be produced, so this suggestion is UNBOUNDED — it has \
             not been checked against any node's retry envelope, the workflow budget, or any \
             node's ability to change state at an external destination. Run validate_workflow \
             before applying it."
                .to_string(),
        );
    }

    let mut suggestion = serde_json::json!({
        "retry_count": bounded_retry_count,
        "retry_backoff_ms": suggested_backoff_ms,
        "retry_condition": retry_condition,
        // The class-derived value BEFORE the per-node bound, kept so nothing
        // is hidden and the two can be compared.
        "unbounded_retry_count": unbounded_retry_count,
        "bounded_by_node_constraints": blanket.is_some(),
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
        // Every count states its population: these are WORKFLOW EXECUTIONS in
        // the window, not node attempts, and `per_node.population` names its
        // own separately.
        "population": format!(
            "{total} workflow execution(s) in the analysis window (cancelled and test runs \
             excluded). Per-node advice is scoped separately — see per_node.population."
        ),
        "total_executions": total,
        "succeeded": succeeded,
        "failed": failed,
        "failure_rate_percent": talos_analytics_repository::format_percent(failure_rate * 100.0),
        "error_class": error_class,
        "suggestion": suggestion,
        "per_node": advice_block,
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

/// `pub(crate)`: also the view='topology' arm of the consolidated
/// `get_workflow_graph` tool (dispatched from `configuration.rs`).
pub(crate) async fn handle_get_workflow_topology(
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

    // Build UUID -> label mapping via `engine_node_uuid` — the SAME function the
    // executor used to write these `execution_events.node_id` values. A private
    // copy of the arithmetic that drifts keys the map on UUIDs no row carries,
    // and every label falls back to the raw UUID with no error.
    let mut uuid_to_label: std::collections::HashMap<uuid::Uuid, String> =
        std::collections::HashMap::new();
    if let Ok(graph) = serde_json::from_str::<serde_json::Value>(&graph_json_str) {
        if let Some(nodes) = graph.get("nodes").and_then(|n| n.as_array()) {
            for node in nodes {
                if let Some(node_id_str) = node.get("id").and_then(|v| v.as_str()) {
                    let node_uuid = talos_workflow_engine_core::engine_node_uuid(node_id_str);
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

/// `source` value for a node-timing row averaged from the engine's
/// `output_data.__node_timings__` stamp.
pub(crate) const NODE_TIMING_SOURCE_OUTPUT: &str = "execution_output.__node_timings__";

/// `source` value for a node-timing row averaged from `execution_cost_rollup`.
pub(crate) const NODE_TIMING_SOURCE_ROLLUP: &str = "execution_cost_rollup";

/// How to read `node_timing_breakdown` — stated ONCE beside the list rather
/// than implied per row.
pub(crate) const NODE_TIMING_BREAKDOWN_NOTE: &str =
    "avg_duration_ms is a mean over sample_count observations from ONE source, and every row in \
     this list shares that source. source=execution_output.__node_timings__ means the mean is \
     over per-node timings stamped on the last 50 completed executions in the window (one \
     observation per node per execution); source=execution_cost_rollup means the engine did not \
     stamp those timings and the mean is over execution_cost_rollup rows for the whole window. \
     The two populations are NOT interchangeable — compare rows within one report, not across \
     reports with different sources. An empty list means the stamped timings were absent AND the \
     rollup fallback produced nothing — either it had no rows or its query failed, which this \
     surface does not distinguish; treat an empty list as NO DATA, never as zero time spent.";

/// Build one `node_timing_breakdown` row.
///
/// D2 (2026-07-29): ONE builder for BOTH sources. Pre-fix the primary
/// (`__node_timings__`) path emitted `{node_id, avg_duration_ms}` and the
/// rollup fallback emitted `{node_id, avg_duration_ms, sample_count, source}`,
/// so a reader could not tell a mean over ONE observation from a mean over
/// fifty, and could not tell which of the two populations they were looking
/// at — the shape itself was the only clue, and only if you had seen both.
/// A shared builder makes the asymmetry unrepresentable.
///
/// `avg_ms` is rounded to 2 decimals and emitted as a JSON number (MCP-49:
/// matches `latency.*` and `get_execution_cost.total_node_time_ms`); a
/// non-finite mean renders as `0.0`, preserving the pre-D2 behavior of both
/// paths.
#[must_use]
pub(crate) fn node_timing_entry(
    node_id: &str,
    avg_ms: f64,
    sample_count: i64,
    source: &str,
) -> serde_json::Value {
    let rounded = if avg_ms.is_finite() {
        (avg_ms * 100.0).round() / 100.0
    } else {
        0.0
    };
    serde_json::json!({
        "node_id": node_id,
        "avg_duration_ms": rounded,
        "sample_count": sample_count,
        "source": source,
    })
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
        let mut items: Vec<(String, f64, usize)> = node_timing_sums
            .iter()
            .map(|(node_id, (sum, count))| (node_id.clone(), sum / *count as f64, *count))
            .collect();
        items.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        items
            .into_iter()
            .map(|(node_id, avg_ms, count)| {
                node_timing_entry(&node_id, avg_ms, count as i64, NODE_TIMING_SOURCE_OUTPUT)
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
                    node_timing_entry(&node_label, avg_ms, sample_count, NODE_TIMING_SOURCE_ROLLUP)
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
        "node_timing_breakdown_note": NODE_TIMING_BREAKDOWN_NOTE,
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
    // A risk assessment that could not run one of its probes must say so: an
    // absent finding and an unaskable question look identical in `risks: []`.
    let mut readings = talos_measurement::Readings::new();

    // Check: workflow-level wall-clock cap DISABLED.
    //
    // This finding used to fire whenever `execution_timeout_secs` did not
    // resolve to a positive number — which folded "the graph says nothing"
    // together with "the graph says 0". Those are opposites. An absent field
    // leaves the engine's constructor default in place
    // (DEFAULT_WORKFLOW_EXECUTION_TIMEOUT_SECS = 300 s), so the workflow runs
    // under a real cap and the reported "has no execution timeout configured"
    // was simply false; measured against the live fleet on 2026-08-28 that was
    // 23 of 30 workflows, every one of them the absent case and every one of
    // them wrong. An explicit `0` is the engine's documented sentinel for "no
    // wall-clock cap", which is the genuine exposure this finding was for, and
    // there were zero of those. Both cases are now classified by
    // `talos_workflow_validation::workflow_timeout_posture`.
    if talos_workflow_validation::workflow_timeout_posture(&graph)
        == talos_workflow_validation::WorkflowTimeoutPosture::ExplicitlyDisabled
    {
        risks.push(serde_json::json!({
            "risk_level": "medium",
            "category": "timeout",
            "description": "Workflow sets execution_timeout_secs to 0, which DISABLES the \
                            workflow-level wall-clock cap. Per-node timeouts are the only thing \
                            bounding a runaway execution.",
            "recommendation": "Set execution_timeout_secs to a positive number of seconds, or \
                               remove the field to fall back to the engine default of 300s. If \
                               the 0 is deliberate, confirm every node carries a timeout_secs."
        }));
    }

    // Check: nodes that explicitly disable the retries their module's world grants.
    let module_ids: Vec<uuid::Uuid> = nodes
        .iter()
        .filter_map(|n| {
            n.get("type")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
        })
        .collect();

    // Load module metadata in parallel:
    // - module_facts: name / category / capability_world / allowed_methods
    // - installed_secrets: per-install wasm_modules.allowed_secrets (authoritative override)
    // - template_rows: node_templates.allowed_secrets (fallback when no wasm_modules entry)
    //
    // Both installed_secrets and template_rows are needed because wasm_modules may not have
    // an entry (e.g. if the wasm_modules insert failed silently, or if user_id was NULL at
    // install time). Using node_templates as a fallback matches validate_workflow's behavior.
    let (module_facts_vec, installed_secrets_res, template_rows_res) = if !module_ids.is_empty() {
        tokio::join!(
            state.analytics_repo.get_risk_module_facts(&module_ids),
            state
                .workflow_repo
                .get_installed_secrets_by_template_ids(&module_ids, user_id),
            state.workflow_repo.get_templates_by_ids(&module_ids),
        )
    } else {
        (Ok(vec![]), Ok(std::collections::HashMap::new()), Ok(vec![]))
    };

    let module_facts: std::collections::HashMap<
        uuid::Uuid,
        talos_analytics_repository::RiskModuleFacts,
    > = module_facts_vec
        .unwrap_or_default()
        .into_iter()
        .map(|f| (f.id, f))
        .collect();

    let installed_secrets = installed_secrets_res.unwrap_or_default();

    // Build fallback map: template_id → allowed_secrets from node_templates.
    // Prefer installed_secrets (wasm_modules) over this fallback.
    let template_secrets: std::collections::HashMap<uuid::Uuid, Vec<String>> = template_rows_res
        .unwrap_or_default()
        .into_iter()
        .map(|r| (r.id, r.allowed_secrets))
        .collect();

    // Every `vault://` reference this graph actually carries, extracted ONCE
    // through the canonical extractor and shared by all four secret findings
    // below (`empty_secret_grant`, `vault_path_blocked`, `expiring_secret`,
    // `secret_no_expiry`).
    //
    // `talos_workflow_engine::vault_resolver::extract_vault_refs` is the same
    // function the controller uses to decide which secrets to prefetch into a
    // job, and it is kept byte-compatible with the worker's
    // `resolve_vault_header`: a reference is matched ANYWHERE in a config
    // value and its path runs to the first whitespace. The risk checks used
    // `val.starts_with("vault://")` instead, which only matches a bare prefix.
    // Every catalog integration module carries its reference inside a header
    // template — `AUTH_HEADER = "Bearer vault://oauth/gmail/<uid>/<email>/
    // access_token"` — so the prefix test matched none of them. Measured on
    // the live fleet 2026-08-28: 0 bare-prefix references against 45 embedded
    // ones, i.e. both HIGH-severity grant findings had zero recall over the
    // whole fleet while the worker was enforcing exactly the grant they claim
    // to predict.
    let node_vault_refs: Vec<(String, uuid::Uuid, Vec<(String, String)>)> = nodes
        .iter()
        .filter_map(|node| {
            let node_id = node.get("id").and_then(|v| v.as_str()).unwrap_or("?");
            let mid = node
                .get("type")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<uuid::Uuid>().ok())?;
            let node_data = node.get("data").cloned().unwrap_or(serde_json::json!({}));
            let node_config = node_data
                .get("config")
                .cloned()
                .unwrap_or_else(|| node_data.clone());
            Some((
                node_id.to_string(),
                mid,
                talos_workflow_engine::vault_resolver::extract_vault_refs(&node_config),
            ))
        })
        .collect();

    // `missing_retry`, rebuilt on the engine's own retry rule.
    //
    // What this finding used to do: decide "is this an HTTP module" by
    // substring-matching the module's display NAME and CATEGORY against
    // {"http", "api", "request", "network"}, then recommend adding retries to
    // every match that carried no top-level `retry_count`. Both halves were
    // wrong, and the first was wrong in the dangerous direction. Measured
    // against the live catalog on 2026-08-28 the name/category predicate
    // matched exactly two modules — `HTTP Request` and `HTTP Request with
    // Retry`, both `http-node` declaring {GET,POST,PUT,PATCH,DELETE} — for
    // which `default_max_retries_for_module` resolves 0 ON PURPOSE, because a
    // blind retry of a state-changing send re-fires it. So the finding told an
    // operator, at HIGH severity, to add retries to precisely the nodes the
    // engine fails closed for: a double-charge / duplicate-message
    // recommendation. In the same measurement its recall was 0 of the 63
    // catalog modules whose world DOES grant transient retries, so it also
    // never fired where retries were the right answer.
    //
    // What it does now: delegate to
    // `talos_workflow_validation::disabled_retry_protection`, added by #696,
    // which calls `default_max_retries_for_module` rather than restating it
    // and fires only on the case that is actually a configuration hazard — a
    // node whose EXPLICIT `retry_count: 0` overrides a world default of > 0.
    // That preserves #696's distinction between an explicit 0 (a deliberate
    // choice, which this reports without calling wrong) and an absent one (the
    // healthy case, where the default applies). It also picks up
    // `data.retry_count`, which the old top-level-only read missed, via the
    // same dual-shape accessor the engine uses.
    //
    // Severity is medium, not high: an explicit 0 has legitimate uses on
    // metered work, so this is a decision to surface, not a defect to alarm on.
    for node in &nodes {
        let node_id = node.get("id").and_then(|v| v.as_str()).unwrap_or("?");
        let Some(mid) = node
            .get("type")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<uuid::Uuid>().ok())
        else {
            continue;
        };
        let Some(facts) = module_facts.get(&mid) else {
            continue;
        };
        let Some(finding) = talos_workflow_validation::disabled_retry_protection(
            node,
            &facts.allowed_methods,
            facts.capability_world.as_deref(),
        ) else {
            continue;
        };
        // The value this finding invites the operator to apply has to fit the
        // budget it would run inside. Measured 2026-09-01, 33 of the 35 fleet
        // nodes this fires on would have tripped the retry-envelope warning on
        // following the un-budgeted form. Resolved through the SAME budget
        // posture classifier the timeout finding above uses, and the same
        // ceiling function the validator and the retry advisor use.
        let budget_ceiling = talos_workflow_validation::node_budget_retry_ceiling(
            node,
            match talos_workflow_validation::workflow_timeout_posture(&graph) {
                talos_workflow_validation::WorkflowTimeoutPosture::Declared(s) => s,
                talos_workflow_validation::WorkflowTimeoutPosture::EngineDefault(s) => s,
                talos_workflow_validation::WorkflowTimeoutPosture::ExplicitlyDisabled => 0,
            },
            talos_workflow_engine_core::default_node_timeout_secs(),
        );
        let applied_retry_count = budget_ceiling.map_or(finding.world_default_retries, |c| {
            c.min(finding.world_default_retries)
        });
        risks.push(serde_json::json!({
            "risk_level": "medium",
            "category": "missing_retry",
            "node_id": node_id,
            "description": talos_workflow_validation::describe_disabled_retry_protection(
                &finding, node_id, None, None, 0, 0, budget_ceiling,
            ),
            // The description (rendered by the shared #696 formatter) already
            // states both branches of the decision and the value to use. This
            // names the tool that applies it rather than restating them.
            "recommendation": if applied_retry_count == 0 {
                format!(
                    "If the 0 is not deliberate: no retry count fits this workflow's budget at \
                     node '{node_id}'s per-attempt timeout — raise execution_timeout_secs or \
                     lower the node's timeout_secs first."
                )
            } else {
                format!(
                    "If the 0 is not deliberate: update_node_config(node_id: '{node_id}', \
                     retry_count: {applied_retry_count})."
                )
            },
        }));
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
        let stale_ids = readings.record_rows(
            "stale_module",
            state
                .analytics_repo
                .get_risk_stale_templates(&module_ids)
                .await,
        );
        // module_facts already loaded: use it to map stale ids to names
        for stale_id in &stale_ids {
            let name = module_facts
                .get(stale_id)
                .map(|f| f.name.as_str())
                .unwrap_or("unknown");
            risks.push(serde_json::json!({
                "risk_level": "medium",
                "category": "stale_module",
                "description": format!("Module '{}' has not been updated in over 90 days", name),
                "recommendation": "Review and update the module to ensure it still works correctly with current APIs."
            }));
        }
    }

    // Checks: expiry posture of the secrets THIS workflow references.
    //
    // Both findings previously answered a different question than the one they
    // reported. `expiring_secret` listed every secret of the caller's expiring
    // inside 30 days and attributed all of them to whichever workflow was
    // being assessed — no link between the secret and the graph was ever
    // tested, so on an account with one expiring credential every workflow
    // reported the same HIGH finding whether it used the credential or not.
    // `secret_no_expiry` tested whether a secret's display NAME appeared as a
    // case-insensitive substring anywhere in the raw `graph_json` text, which
    // matches node labels, descriptions and URLs as readily as a real
    // reference — a secret named "gmail" would have fired on every workflow
    // mentioning Gmail.
    //
    // Both are answerable exactly: the path inside a `vault://` reference IS
    // `secrets.key_path`, so the references extracted above join straight onto
    // the secrets table. A path with no matching row is deliberately silent
    // here — that is `vault_path_blocked`'s and the engine's `SecretNotResolved`
    // territory, not an expiry question.
    let referenced_vault_paths: Vec<String> = node_vault_refs
        .iter()
        .flat_map(|(_, _, refs)| refs.iter().map(|(_, path)| path.clone()))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let referenced_secrets = readings.record_rows(
        "expiring_secret",
        state
            .analytics_repo
            .get_risk_secret_expiry_for_paths(user_id, &referenced_vault_paths)
            .await,
    );
    // An ALREADY-expired secret is reported too. The retired query bounded its
    // window with `expires_at > NOW()`, so a credential that had already lapsed
    // — the state in which the workflow is broken right now rather than about
    // to be — dropped out of the report entirely.
    let now = chrono::Utc::now();
    let expiry_horizon = now + chrono::Duration::days(30);
    for secret in &referenced_secrets {
        match secret.expires_at {
            Some(expires_at) if expires_at <= expiry_horizon => {
                let (verb, day) = if expires_at <= now {
                    ("expired on", expires_at)
                } else {
                    ("expires on", expires_at)
                };
                risks.push(serde_json::json!({
                    "risk_level": "high",
                    "category": "expiring_secret",
                    "vault_path": secret.key_path,
                    "description": format!(
                        "Secret '{}' (vault path '{}') is referenced by this workflow and \
                         {} {}.",
                        secret.name,
                        secret.key_path,
                        verb,
                        day.format("%Y-%m-%d")
                    ),
                    "recommendation": "Rotate the secret before it expires to avoid workflow failures."
                }));
            }
            None => {
                risks.push(serde_json::json!({
                    "risk_level": "medium",
                    "category": "secret_no_expiry",
                    "vault_path": secret.key_path,
                    "description": format!(
                        "Secret '{}' (vault path '{}') is referenced by this workflow but has \
                         no expiry set.",
                        secret.name, secret.key_path
                    ),
                    "recommendation": "Set an expiry on this secret to ensure it gets rotated periodically"
                }));
            }
            Some(_) => {}
        }
    }

    // Check: Sub-workflow failure rates.
    //
    // Pre-collect every workflow this graph dispatches into, then batch-fetch
    // 7-day exec counts in a single query. The batch keeps the N+1 → 1+1 shape
    // and the user_id scoping (so the lookup can't indirectly leak counts for
    // a workflow that doesn't belong to the caller).
    //
    // The reference key was WRONG: this read `node.data.workflow_id`, which is
    // not a key the engine dispatches on. `talos-workflow-engine`'s
    // `graph_parser.rs` names a sub-workflow through one of seven distinct
    // `*_workflow_id` keys — `sub_workflow_id` for a sub_workflow node,
    // `judge_workflow_id` for judge / ensemble, `child_workflow_id`,
    // `body_workflow_id`, `fallback_workflow_id`, `reflection_workflow_id`,
    // `classifier_workflow_id` — and `workflow_id` is none of them. Measured
    // on the live fleet 2026-08-28: 0 nodes carried `workflow_id`, while 2
    // carried `sub_workflow_id` and 3 `judge_workflow_id`. The check was dead
    // — a HIGH-severity cascading-failure warning that could not fire on any
    // real sub-workflow. `collect_subworkflow_references` matches the shared
    // `*_workflow_id` convention instead.
    let sub_wf_ids: Vec<uuid::Uuid> = nodes
        .iter()
        .flat_map(talos_workflow_validation::collect_subworkflow_references)
        .map(|(_key, id)| id)
        .collect::<std::collections::HashSet<_>>() // de-dupe before fetch
        .into_iter()
        .collect();
    let exec_counts = readings
        .record(
            "high_failure_sub_workflow",
            state
                .analytics_repo
                .get_risk_exec_counts_for_ids(&sub_wf_ids, user_id)
                .await,
        )
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
        // The only benign-default site in this handler that does NOT hide a
        // finding — the `no_intent` risk is pushed either way, and a failure
        // merely downgrades its severity from medium to low. Disclosed rather
        // than silently accepted, because a downgraded severity is still a
        // softer claim than the evidence supports.
        let is_published: bool = readings
            .record(
                "no_intent.risk_level",
                state.analytics_repo.check_has_active_version(wf_id).await,
            )
            .unwrap_or(false);

        let risk_level = if is_published { "medium" } else { "low" };
        risks.push(serde_json::json!({
            "risk_level": risk_level,
            "category": "no_intent",
            "description": format!("Workflow has no intent registered{}", if is_published { " (published workflow)" } else { "" }),
            "recommendation": "Register an intent to describe what this workflow does and when it should be used"
        }));
    }

    // `secret_no_expiry` moved up to the vault-path-scoped block alongside
    // `expiring_secret` — the two ask the same question of the same rows, and
    // both now resolve the workflow's extracted `vault://` paths against
    // `secrets.key_path` instead of substring-matching a display name against
    // the raw graph document.

    // Check: Nodes backed by user-authored sandbox modules.
    // Sandbox modules are compiled from user-written source, may have been built
    // against an older WIT interface, and have no automated update path — making
    // them inherently higher risk than catalog modules which are platform-managed.
    if !module_ids.is_empty() {
        let sandbox_modules = readings.record_rows(
            "sandbox_module",
            state
                .analytics_repo
                .get_risk_sandbox_modules(&module_ids)
                .await,
        );
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

            let tmpl_name = module_facts
                .get(&mid)
                .map(|f| f.name.as_str())
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
            //
            // The reference set comes from `node_vault_refs`, extracted once
            // above through the canonical `extract_vault_refs`. The prior
            // `starts_with("vault://")` prefix test matched no real reference
            // in the fleet — see the note on `node_vault_refs`.
            let vault_refs: &[(String, String)] = node_vault_refs
                .iter()
                .find(|(nid, _, _)| nid == node_id)
                .map(|(_, _, refs)| refs.as_slice())
                .unwrap_or(&[]);

            if secrets.is_empty() && !vault_refs.is_empty() {
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
            for (field_key, path) in vault_refs {
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

    // Check: Recent execution failures with 'unauthorized'/'access denied' errors.
    // Cross-references the live execution history to surface recurring secret failures
    // that indicate a vault_path_blocked or empty_secret_grant config issue in production.
    {
        // `.unwrap_or(None)` here made a DB error indistinguishable from "this
        // workflow has had no auth failures", so a HIGH-severity finding
        // vanished from the risk list without a trace. `None` and `Err` are two
        // different sentences and only one of them is a clean bill of health.
        let recent_auth_failures = readings.record(
            "repeated_auth_failures",
            state
                .analytics_repo
                .count_recent_auth_failures(wf_id, 7)
                .await,
        );

        // `count == 0` is the "no auth failures" signal, not an absent row: the
        // repository's query is an UNGROUPED aggregate, so it always returns
        // exactly one row. The old `Some(Some(..))` match implied a reachable
        // "no row" case that Postgres can never produce, and its inner
        // `String` decode of a NULL `MAX(started_at)` is what made every
        // no-failure workflow read as a failed measurement.
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
                        // `count > 0` implies at least one matching row and
                        // `started_at` is NOT NULL, so this is `Some` in
                        // practice — but a MAX has no meaningful zero, so the
                        // absent case gets a word rather than a fabricated
                        // timestamp.
                        last_failure.as_deref().unwrap_or("unknown")
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

    let mut result = serde_json::json!({
        "workflow_name": wf_name,
        "workflow_id": wf_id.to_string(),
        "total_risks": risks.len(),
        "high": risks.iter().filter(|r| r.get("risk_level").and_then(|l| l.as_str()) == Some("high")).count(),
        "medium": risks.iter().filter(|r| r.get("risk_level").and_then(|l| l.as_str()) == Some("medium")).count(),
        "low": risks.iter().filter(|r| r.get("risk_level").and_then(|l| l.as_str()) == Some("low")).count(),
        "risks": risks,
    });
    readings.attach(&mut result);

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

/// Autonomy cockpit — the three-panel operator digest (ran / learned /
/// needs_me) over a trailing window. Thin wrapper: parse `days`, call the
/// shared `OperatorDigestService`, return the JSON. Tenancy is the
/// authenticated `user_id`.
async fn handle_get_operator_digest(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let days = args
        .get("days")
        .and_then(serde_json::Value::as_u64)
        .map(|d| d.clamp(1, 31) as u32)
        .unwrap_or(1);

    let service = talos_operator_digest::OperatorDigestService::new(state.db_pool.clone());
    match service.snapshot(user_id, days).await {
        Ok(digest) => mcp_text(
            req_id,
            &serde_json::to_string_pretty(&digest).unwrap_or_default(),
        ),
        Err(e) => {
            tracing::error!("get_operator_digest failed: {}", e);
            mcp_error(req_id, -32000, "Failed to build operator digest")
        }
    }
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
    // This handler renders a HUMAN-READABLE `summary` that is emailed by the
    // autonomy digest, and its section headings are emitted only when their
    // list is non-empty. A failed query therefore did not merely zero a
    // number — it silently DELETED the "Top Failing Workflows" section from a
    // digest a human reads as complete. The disclosure is appended to the prose
    // as well as to the JSON for exactly that reason.
    let mut readings = talos_measurement::Readings::new();
    let active_rows = readings.record_rows(
        "top_active_workflows",
        state
            .analytics_repo
            .get_top_active_workflows_24h(user_id)
            .await,
    );
    let top_active: Vec<serde_json::Value> = active_rows.iter().map(|r| {
        serde_json::json!({"workflow_id": r.id.to_string(), "name": r.name, "executions": r.exec_count})
    }).collect();

    // Top 3 failing workflows
    let failing_rows = readings.record_rows(
        "top_failing_workflows",
        state
            .analytics_repo
            .get_top_failing_workflows_24h(user_id)
            .await,
    );
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
    let schedule_rows = readings.record_rows(
        "upcoming_schedules",
        state
            .analytics_repo
            .get_upcoming_schedules_for_user(user_id)
            .await,
    );
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

    if !readings.complete() {
        summary.push_str("\n⚠ INCOMPLETE DIGEST\n");
        summary.push_str(&format!("  {}\n", readings.note()));
    }

    let mut result = serde_json::json!({
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
    readings.attach(&mut result);

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

/// Population disclosure for `get_workflows_by_capability` rows.
///
/// Grounded against the actual SQL in
/// `talos_analytics_repository::get_workflows_by_capability`: the denominator
/// is `COUNT(*)` over `workflow_executions` with `started_at` inside the
/// window — every status, not just completed+failed — and the numerator is
/// `COUNT(*) FILTER (WHERE status = 'completed')`.
///
/// Phase-2 review: `started_at` is `NOT NULL DEFAULT NOW()` (migration
/// `009_workflow_executions`), i.e. stamped when the ROW is created, not when
/// execution begins — so queued executions that never ran are in the
/// denominator too, and the note must not imply a "started" filter that the
/// column does not express.
pub(crate) const CAPABILITY_ROW_POPULATION_NOTE: &str =
    "success_rate_30d = completed / EVERY execution row of the workflow created in the \
     trailing 30 days (started_at is stamped at row creation, so queued, running, \
     cancelled and failed executions are all in the denominator); \
     runs_30d is that denominator. success_rate_30d_ci95 is a Wilson binomial interval \
     over runs_30d — it assumes independent runs, which bursty failures violate, so it is \
     a width to compare candidates by, not a guarantee. Rates below the sample-size floor \
     are labeled sample_size=\"insufficient\" and must not be used to rank candidates.";

/// Sample-size floor below which a 30-day success rate is not usable for
/// RANKING two candidate workflows against each other.
///
/// Grounded in the same convention as the SLA report's MCP-4 warning
/// (`talos_measurement::min_n_for_rate_target`): the smallest observable
/// failure rate in `n` runs is `1/n`, so distinguishing a 95%-class workflow
/// from a lucky one needs `n >= 1/(1 - 0.95) = 20`. Below that a single
/// failure swings the rate by five points or more and the ordering between
/// two candidates is noise.
const CAPABILITY_RANKING_TARGET_RATE: f64 = 0.95;

/// Render one capability row: the legacy fields byte-for-byte as before, plus
/// the sample size, the Wilson interval and the sufficiency label.
///
/// Extracted as a pure function (2026-07-28) so the shape is unit-testable
/// against real production code rather than a test-local re-implementation —
/// and so dropping `runs_30d` fails a test instead of silently shipping.
pub(crate) fn capability_row_json(
    row: &talos_analytics_repository::WorkflowCapabilityRow,
) -> serde_json::Value {
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
    let runs = u64::try_from(row.runs_30d).unwrap_or(0);
    // `Measurement::from_fraction` refuses n = 0 and non-finite fractions, so
    // "never ran" can never render as a healthy-looking 0.0 with a [0,0]
    // interval — it renders as no interval at all.
    let ci95: serde_json::Value = frac_opt
        .and_then(|f| talos_measurement::Measurement::from_fraction(f, runs))
        .and_then(|m| m.ci95)
        .map_or(serde_json::Value::Null, |ci| serde_json::json!(ci));
    let floor = talos_measurement::min_n_for_rate_target(CAPABILITY_RANKING_TARGET_RATE)
        .unwrap_or(u64::MAX);
    let sufficiency = talos_measurement::Sufficiency::judge(runs, floor);
    serde_json::json!({
        "id": row.id,
        "workflow_id": row.id,
        "name": row.name,
        "description": row.description,
        "capabilities": row.capabilities,
        "readiness_score": row.readiness_score,
        "success_rate_30d": frac_4dp,
        "success_rate_30d_percent": percent_value,
        // The n. Its absence is the whole S1 defect: without it, 1-for-1 and
        // 400-for-400 both render "100.0%" and routing picks either.
        "runs_30d": row.runs_30d,
        "success_rate_30d_ci95": ci95,
        "sample_size": sufficiency.label(),
        "sample_size_note": sufficiency.to_string(),
    })
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
            let results: Vec<serde_json::Value> = rows.iter().map(capability_row_json).collect();
            let envelope = serde_json::json!({
                "count": results.len(),
                "capabilities_filter": capabilities,
                "population_note": CAPABILITY_ROW_POPULATION_NOTE,
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
        // THE DENOMINATOR IS THE ENFORCED CEILING, NOT THE MODULE ROW.
        //
        // This used to be `fuel_p95 / modules.max_fuel`, which is not the
        // limit a run is killed at whenever a node carries a `max_fuel`
        // override — so it reported utilisation ABOVE 100% for runs that
        // completed, and `at_risk` is a verdict about exhaustion, i.e. a claim
        // about the ENFORCED limit. Measured on the live database 2026-08-18:
        // 11 of 12 `at_risk` verdicts were false (cos_groundedness 566.5%,
        // LLM Inference 425.5%), and `Gmail: Get Message` understated its
        // utilisation 4× in the direction that HIDES risk. See
        // `ModuleFuelStats` for the full derivation and why this is a p95 of
        // per-row ratios rather than a ratio of aggregates.
        let utilization_pct = s.utilisation_p95 * 100.0;
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
            // Disambiguation rather than a rename: `current_max_fuel` keeps its
            // meaning for back-compat, and the two numbers that were silently
            // collapsed into it are now both named. `module_row_max_fuel` is
            // what `hot_update_module(fuel_budget=…)` writes; the enforced
            // range is what runs are actually measured against. A spread here
            // means the module row governs only some of this module's nodes,
            // so bumping it will not move the ones that override it.
            "module_row_max_fuel": s.current_max_fuel,
            "enforced_ceiling_min": s.enforced_ceiling_min,
            "enforced_ceiling_max": s.enforced_ceiling_max,
            "executions_with_enforced_ceiling": s.rows_with_enforced_ceiling,
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

    // ── Per-NODE high-utilisation nodes ─────────────────────────────────
    //
    // A DIFFERENT QUESTION FROM EVERYTHING ABOVE, and the difference is why
    // `pa-read-later-digest/digest` was invisible here for 16 days at 96.9% of
    // its budget. The per-module report aggregates by MODULE against the
    // SHARED `modules.max_fuel`, uses p95, and hides anything below
    // `min_executions` (default 3). `digest` had a node-scoped ceiling, a
    // peak rather than a percentile, and TWO runs — it failed all three
    // filters at once.
    //
    // So this section is per (workflow, node), peak-not-percentile, against
    // the ceiling a worker actually enforced, and has NO sample floor. It is
    // the operator-facing half of `talos_fuel_high_utilisation_nodes`, which
    // carries the count but cannot carry the names (node labels are
    // author-supplied and unbounded, i.e. unbounded metric cardinality).
    //
    // Owner-scoped here, fleet-wide for the gauge. Failure is non-fatal: the
    // per-module report above is still worth returning, and a missing section
    // is reported as such rather than as an empty one — an empty array would
    // read as "no node is at risk".
    const HIGH_UTILISATION_THRESHOLD: f64 = 0.80;
    let (high_utilisation_nodes, high_utilisation_error) = match state
        .analytics_repo
        .get_node_fuel_headroom(Some(user_id), 30, 200)
        .await
    {
        Ok(rows) => (
            rows.iter()
                .filter(|r| r.utilisation() >= HIGH_UTILISATION_THRESHOLD)
                .map(|r| {
                    serde_json::json!({
                        "workflow_id": r.workflow_id,
                        "workflow_name": r.workflow_name,
                        "node": r.node_label,
                        "samples": r.samples,
                        "peak_fuel": r.peak_fuel,
                        "enforced_ceiling": r.current_ceiling,
                        "utilization_pct": talos_analytics_repository::format_percent(
                            r.utilisation() * 100.0,
                        ),
                    })
                })
                .collect::<Vec<_>>(),
            None,
        ),
        Err(e) => {
            tracing::error!(
                target: "talos_analytics",
                event_kind = "fuel_headroom_query_failed",
                error = %e,
                "get_fuel_usage_report: per-node headroom query failed"
            );
            (
                Vec::new(),
                Some(
                    "per-node headroom unavailable (see controller logs, target: \
                     talos_analytics, event_kind: fuel_headroom_query_failed) — the empty \
                     list below is NOT evidence that no node is at risk",
                ),
            )
        }
    };

    let result = serde_json::json!({
        "period_days": days,
        "modules_analyzed": stats.len(),
        "summary": {
            "at_risk": at_risk.len(),
            "over_provisioned": over_provisioned.len(),
            "well_tuned": well_tuned.len(),
            "high_utilisation_nodes": high_utilisation_nodes.len(),
        },
        "at_risk": at_risk,
        "over_provisioned": over_provisioned,
        "modules": modules,
        "high_utilisation_nodes": high_utilisation_nodes,
        "high_utilisation_error": high_utilisation_error,
        "high_utilisation_note": "Per (workflow, node) over a fixed 30-day window, test \
             executions excluded: PEAK fuel_consumed against the ceiling a worker most \
             recently ENFORCED, flagged at >=80%. Independent of `period_days` and \
             `min_executions` above, and deliberately UNFLOORED on sample count — a node \
             with one or two runs is exactly the case the per-module section cannot see. \
             Backs the TalosFuelHeadroomLow alert.",
        "utilization_basis": "utilization_p95_pct is the p95 of the PER-EXECUTION ratio \
             fuel_consumed / the ceiling that execution actually ran under \
             (execution_cost_rollup.max_fuel — the worker's own __fuel_limit__ stamp — \
             falling back to modules.max_fuel for rows written before that column \
             existed). It is NOT fuel_p95 / module_row_max_fuel: a node-level max_fuel \
             override means the module row is not the limit anything is killed at, and \
             dividing by it produced impossible >100% figures. Because each execution \
             consumed at most the ceiling enforced for it, this value cannot exceed \
             100% for completed runs. The high_utilisation_nodes section below uses the \
             same ENFORCED basis, per (workflow, node) and peak-not-percentile — so the \
             two sections now agree on what the denominator means.",
        "note": "Apply recommendations via hot_update_module(name, fuel_budget=recommended_max_fuel) — bumps modules.max_fuel without recompiling source. If enforced_ceiling_min/max differ from module_row_max_fuel, some nodes override the module budget and bumping the row will not change what they enforce.",
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
    // Every DB-backed input to the readiness SCORE is disclosed. A score is a
    // single number an operator reads as a verdict, so a component computed
    // from a defaulted input has to say which input it did not have.
    let mut readings = talos_measurement::Readings::new();
    let wf_analytics = readings
        .record(
            "workflow_type",
            state
                .analytics_repo
                .get_workflow_for_analytics(wf_id, user_id)
                .await,
        )
        .flatten();
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
    let exec_data = readings.record(
        "reliability.executions",
        state.analytics_repo.get_readiness_exec_data(wf_id).await,
    );
    if exec_data.is_none() {
        readings.mark_derived("readiness_score");
    }
    let exec_data = exec_data.unwrap_or(talos_analytics_repository::ReadinessExecData {
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
    let last_exec_at = readings
        .record(
            "freshness.last_execution_at",
            state
                .analytics_repo
                .get_max_execution_started_at(wf_id)
                .await,
        )
        .flatten();
    if readings
        .not_measured()
        .contains(&"freshness.last_execution_at")
    {
        readings.mark_derived("readiness_score");
    }
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
    // `.unwrap_or(0)` fed a defaulted "no secrets are expiring" straight into
    // the risk component of the readiness score, INFLATING it — the failure
    // direction that makes a workflow look more production-ready than it is.
    // The score is still emitted (nulling it would break every consumer), but
    // both the input and the score it fed are disclosed, and the score is then
    // an UPPER bound rather than a measurement.
    let expiring_measured = readings.record(
        "expiring_secrets",
        state.analytics_repo.count_expiring_secrets(user_id).await,
    );
    if expiring_measured.is_none() {
        readings.mark_derived("readiness_score");
    }
    let expiring_secrets: i64 = expiring_measured.unwrap_or(0);

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

    let mut result = serde_json::json!({
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
    });
    readings.attach(&mut result);

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
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

/// Build the `summary` block for `get_all_readiness_scores` from the POPULATION
/// aggregate — never from the returned page.
///
/// Pure so the contract is testable without Postgres. The contract has two
/// halves and the second is the one that matters:
///
/// 1. When the population is known, the figures are population-wide and
///    `avg_score` keeps one decimal (the pre-2026-08-19 code used integer
///    division, rendering 75.59 as 75).
/// 2. When the population query FAILED, every figure is `null` and the note says
///    so. It deliberately does NOT fall back to accumulating over the page: the
///    page is `ORDER BY readiness_score ASC LIMIT 50`, so its mean is a
///    worst-50 mean, and emitting that under the name `avg_score` is the exact
///    defect this function exists to remove. A null is a missing answer; a
///    biased sample under a population name is a wrong one.
pub(crate) fn readiness_summary_json(
    population: Option<&talos_analytics_repository::ReadinessPopulation>,
) -> serde_json::Value {
    match population {
        Some(p) => serde_json::json!({
            "avg_score": p.avg_score.map(|a| (a * 10.0).round() / 10.0),
            "below_50_count": p.below_50,
            "unscored_count": p.unscored,
            "population": "all workflows matching the request filters, uncapped",
        }),
        None => serde_json::json!({
            "avg_score": serde_json::Value::Null,
            "below_50_count": serde_json::Value::Null,
            "unscored_count": serde_json::Value::Null,
            "population": "unavailable: the population aggregate query failed. These are NULL \
                           rather than computed over the returned page, because the page is the \
                           lowest-scoring workflows and its mean is not a fleet average.",
        }),
    }
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

    // An empty list here reads as "you have no workflows below this score" —
    // the all-clear — and every summary count below is derived from its length.
    let mut readings = talos_measurement::Readings::new();
    let rows = readings.record_rows(
        "workflows",
        state
            .analytics_repo
            .list_readiness_scores(user_id, filter_ids.as_deref(), max_score, include_archived)
            .await,
    );

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

    // 2026-08-19: `summary` now describes the POPULATION, not the page.
    //
    // Every one of these four numbers used to be accumulated over the rows
    // returned by `list_readiness_scores`, which is `ORDER BY
    // COALESCE(readiness_score, 0) ASC LIMIT 50` — the 50 LOWEST scorers. That
    // is a biased sample sold as a fleet statistic, and no `truncated: true`
    // flag repairs it: pinned to the worst tail, `avg_score` is monotonically
    // non-increasing in fleet quality, so a fleet that IMPROVES reports a
    // falling average, and `below_50_count` saturates at exactly 50 forever.
    // The `workflows` array below is unchanged — a "worst 50, fix these first"
    // list is what that query is genuinely good for.
    let population = state
        .analytics_repo
        .readiness_population(user_id, filter_ids.as_deref(), max_score, include_archived)
        .await
        .ok();

    let page_len = i64::try_from(workflows.len()).unwrap_or(i64::MAX);
    // `total` keeps meaning what its name says. When the population query
    // failed we fall back to the page length AND say so, rather than silently
    // reporting a page size under a population name — which is the defect.
    let coverage = match &population {
        Some(p) => talos_measurement::Coverage::new(
            page_len,
            talos_analytics_repository::READINESS_PAGE_LIMIT,
        )
        .with_available(p.total),
        None => talos_measurement::Coverage::new(
            page_len,
            talos_analytics_repository::READINESS_PAGE_LIMIT,
        ),
    };

    let summary = readiness_summary_json(population.as_ref());

    let mut result = serde_json::json!({
        "total": population.map_or(page_len, |p| p.total),
        "summary": summary,
        "workflows_coverage": coverage.to_json(),
        "workflows_note": "`workflows` is the LOWEST-scoring page (ORDER BY readiness_score \
                           ASC), not a sample of the fleet. Read `summary` for fleet-wide \
                           figures and this list for what to fix first.",
        "workflows": workflows,
    });
    readings.attach(&mut result);

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
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

/// Thin wrapper (architectural-mandate extraction, 2026-07): parse the
/// `fix_all` / `confirm` booleans, call `talos-hygiene-service`, format.
/// Report assembly, the fix-candidate partition, and the fix mutations
/// all live in `HygieneService` — output JSON is byte-identical to the
/// pre-extraction handler.
async fn handle_get_platform_hygiene_report(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let outcome = match state
        .hygiene_service
        .generate(talos_hygiene_service::HygieneReportInput { user_id })
        .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::error!("get_platform_hygiene_report failed: {}", e);
            return mcp_error(req_id, e.jsonrpc_code(), &e.user_facing_message());
        }
    };
    let mut report = outcome.report;

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

    report["fix_all"] = if confirm {
        state
            .hygiene_service
            .apply_fixes(user_id, &outcome.fix_candidates)
            .await
    } else {
        // Dry-run: return the hygiene report + preview, no mutations.
        talos_hygiene_service::HygieneService::dry_run_envelope(&outcome.fix_candidates)
    };
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&report).unwrap_or_default(),
    )
}

/// S1 (measurement envelope, 2026-07-28): the capability-routing row must
/// carry the denominator of its own success rate.
#[cfg(test)]
mod capability_row_measurement_tests {
    use super::{capability_row_json, CAPABILITY_ROW_POPULATION_NOTE};
    use talos_analytics_repository::WorkflowCapabilityRow;
    use uuid::Uuid;

    fn row(rate: Option<f64>, runs: i64) -> WorkflowCapabilityRow {
        WorkflowCapabilityRow {
            id: Uuid::nil(),
            name: "wf".to_string(),
            description: None,
            capabilities: Some(vec!["http-fetch".to_string()]),
            readiness_score: Some(70),
            success_rate: rate,
            runs_30d: runs,
        }
    }

    /// The defect verbatim: 1-for-1 and 400-for-400 are both "100.0%".
    /// The rendered rows must be distinguishable.
    #[test]
    fn identical_rates_over_different_samples_are_distinguishable() {
        let lucky = capability_row_json(&row(Some(1.0), 1));
        let proven = capability_row_json(&row(Some(1.0), 400));
        // The legacy fields are, by design, identical — that IS the bug.
        assert_eq!(lucky["success_rate_30d"], proven["success_rate_30d"]);
        assert_eq!(
            lucky["success_rate_30d_percent"],
            proven["success_rate_30d_percent"]
        );
        // …so the row must differ somewhere a reader will see.
        assert_ne!(lucky, proven, "rows over 1 and 400 runs render identically");
        assert_eq!(lucky["runs_30d"], 1);
        assert_eq!(proven["runs_30d"], 400);
        assert_eq!(lucky["sample_size"], "insufficient");
        assert_eq!(proven["sample_size"], "sufficient");
        // The interval is what makes the difference legible: 1/1 spans most
        // of the range, 400/400 barely moves off 1.0.
        let lucky_lo = lucky["success_rate_30d_ci95"][0].as_f64().unwrap();
        let proven_lo = proven["success_rate_30d_ci95"][0].as_f64().unwrap();
        assert!(lucky_lo < 0.3, "1-for-1 lower bound was {lucky_lo}");
        assert!(proven_lo > 0.98, "400-for-400 lower bound was {proven_lo}");
    }

    /// Mutation guard (8b): dropping `runs_30d` from the row must fail here.
    #[test]
    fn every_row_carries_its_sample_size() {
        for (rate, runs) in [
            (Some(1.0), 1i64),
            (Some(0.0), 5),
            (Some(0.75), 40),
            (None, 0),
        ] {
            let v = capability_row_json(&row(rate, runs));
            let obj = v.as_object().expect("row is an object");
            assert!(
                obj.contains_key("runs_30d"),
                "runs_30d missing for ({rate:?}, {runs})"
            );
            assert_eq!(v["runs_30d"], runs);
            assert!(obj.contains_key("sample_size"));
        }
    }

    /// The floor is 20, grounded in `min_n_for_rate_target(0.95)`. Pin the
    /// boundary so a silent change to the routing floor is visible.
    #[test]
    fn insufficient_label_flips_exactly_at_the_floor() {
        assert_eq!(
            talos_measurement::min_n_for_rate_target(super::CAPABILITY_RANKING_TARGET_RATE),
            Some(20)
        );
        assert_eq!(
            capability_row_json(&row(Some(0.9), 19))["sample_size"],
            "insufficient"
        );
        assert_eq!(
            capability_row_json(&row(Some(0.9), 20))["sample_size"],
            "sufficient"
        );
        // The note names the n and the floor, so "insufficient" is actionable.
        let note = capability_row_json(&row(Some(0.9), 19))["sample_size_note"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(note.contains("n=19") && note.contains("20"), "{note}");
    }

    /// n = 0 must never render as a healthy 0.0 with a [0,0] interval.
    #[test]
    fn a_workflow_that_never_ran_reports_no_rate_and_no_interval() {
        let v = capability_row_json(&row(None, 0));
        assert!(v["success_rate_30d"].is_null());
        assert!(v["success_rate_30d_percent"].is_null());
        assert!(
            v["success_rate_30d_ci95"].is_null(),
            "n=0 must not produce an interval"
        );
        assert_eq!(v["runs_30d"], 0);
        assert_eq!(v["sample_size"], "insufficient");
    }

    /// The population string must describe the SQL that produced the number:
    /// the denominator is every execution started in the window, not just
    /// completed+failed.
    #[test]
    fn population_note_matches_the_actual_denominator() {
        assert!(CAPABILITY_ROW_POPULATION_NOTE.contains("created in the trailing 30 days"));
        assert!(
            CAPABILITY_ROW_POPULATION_NOTE.contains("queued, running, cancelled and failed"),
            "the denominator includes queued and other non-terminal statuses; say so"
        );
        assert!(CAPABILITY_ROW_POPULATION_NOTE.contains("runs_30d is that denominator"));
        // Phase-2: the interval must not read as an exact bound.
        assert!(
            CAPABILITY_ROW_POPULATION_NOTE.contains("Wilson binomial interval"),
            "name the interval's model"
        );
        assert!(
            CAPABILITY_ROW_POPULATION_NOTE.contains("not a guarantee"),
            "a ci95 field is read as a bound unless told otherwise"
        );
    }
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
        // Real producer, not a retyped copy — see `fuel_bump_tests::msg`.
        let msg = lower(&talos_worker_runtime::runtime::fuel_exhausted_message(
            Some(1_710_000),
            1_710_000,
            None,
        ));
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
    #[allow(non_snake_case)] // NOT-emphasis is intentional in the test name
    fn rate_limit_is_NOT_deterministic() {
        // Rate limits are transient — backoff + retry is exactly
        // the right strategy. Must NOT be flagged as deterministic.
        assert!(!is_deterministic_failure(
            "http 429 too many requests; rate limit exceeded"
        ));
    }

    #[test]
    #[allow(non_snake_case)] // NOT-emphasis is intentional in the test name
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

#[cfg(test)]
mod dependency_view_tests {
    use super::{parse_dependency_view, DependencyView};
    use serde_json::json;

    #[test]
    fn absent_view_defaults_to_list() {
        // Back-compat: every pre-consolidation get_workflow_dependencies
        // call carries no `view` and must keep producing the per-workflow
        // dependency list.
        assert_eq!(
            parse_dependency_view(&json!({"workflow_id": "x"})),
            Ok(DependencyView::List)
        );
    }

    #[test]
    fn null_view_defaults_to_list() {
        assert_eq!(
            parse_dependency_view(&json!({"view": null})),
            Ok(DependencyView::List)
        );
    }

    #[test]
    fn each_known_view_parses() {
        for (name, expected) in [
            ("list", DependencyView::List),
            ("map", DependencyView::Map),
            ("call_tree", DependencyView::CallTree),
        ] {
            assert_eq!(
                parse_dependency_view(&json!({ "view": name })),
                Ok(expected)
            );
        }
    }

    #[test]
    fn unknown_view_is_rejected_with_helpful_message() {
        let err = parse_dependency_view(&json!({"view": "tree"})).unwrap_err();
        // The handler maps this Err to -32602; the message must echo the
        // bad value AND enumerate every valid view with its argument hint.
        assert!(err.contains("Invalid 'view' value 'tree'"), "{err}");
        for valid in ["'list'", "'map'", "'call_tree'"] {
            assert!(err.contains(valid), "message missing {valid}: {err}");
        }
        assert!(err.contains("workflow_id"), "{err}");
        assert!(err.contains("max_depth"), "{err}");
    }

    #[test]
    fn wrong_type_view_is_rejected_loudly() {
        // Direction-class rule (MCP-267 family): a wrong-typed opt-in must
        // reject, not silently collapse to the default view.
        let err = parse_dependency_view(&json!({"view": 3})).unwrap_err();
        assert!(err.contains("'view' must be a string"), "{err}");
        assert!(err.contains("number"), "{err}");
    }
}

#[cfg(test)]
mod node_timing_shape_tests {
    use super::{
        node_timing_entry, NODE_TIMING_BREAKDOWN_NOTE, NODE_TIMING_SOURCE_OUTPUT,
        NODE_TIMING_SOURCE_ROLLUP,
    };

    /// D2's whole point: a reader must be able to tell "n=1" from "n=50",
    /// and must be able to tell WHICH population a row came from. Both keys
    /// are mandatory on BOTH sources.
    #[test]
    fn both_sources_emit_sample_count_and_source() {
        for source in [NODE_TIMING_SOURCE_OUTPUT, NODE_TIMING_SOURCE_ROLLUP] {
            let v = node_timing_entry("compose", 1234.5678, 7, source);
            let obj = v.as_object().expect("object row");
            for key in ["node_id", "avg_duration_ms", "sample_count", "source"] {
                assert!(obj.contains_key(key), "{source} row is missing {key}: {v}");
            }
            assert_eq!(obj.len(), 4, "unexpected extra keys: {v}");
            assert_eq!(v["node_id"], "compose");
            assert_eq!(v["sample_count"], 7);
            assert_eq!(v["source"], source);
        }
    }

    /// The two sources are distinguishable — a single shared `source` string
    /// would make the field decorative.
    #[test]
    fn the_two_source_labels_differ_and_name_their_origin() {
        assert_ne!(NODE_TIMING_SOURCE_OUTPUT, NODE_TIMING_SOURCE_ROLLUP);
        assert!(NODE_TIMING_SOURCE_OUTPUT.contains("__node_timings__"));
        assert!(NODE_TIMING_SOURCE_ROLLUP.contains("execution_cost_rollup"));
    }

    /// Rounding + the non-finite fallback are unchanged from the pre-D2
    /// per-path copies (MCP-49's 2-decimal JSON-number contract).
    #[test]
    fn rounding_matches_the_pre_unification_behaviour() {
        let v = node_timing_entry("n", 22_205.164_099_999_998, 3, NODE_TIMING_SOURCE_OUTPUT);
        assert_eq!(v["avg_duration_ms"], 22_205.16);
        assert!(v["avg_duration_ms"].is_number(), "must not be a string");
        // A non-finite mean (empty divisor upstream) renders 0.0, not null
        // and not NaN — serde_json cannot encode NaN at all.
        let v = node_timing_entry("n", f64::NAN, 0, NODE_TIMING_SOURCE_ROLLUP);
        assert_eq!(v["avg_duration_ms"], 0.0);
        let v = node_timing_entry("n", f64::INFINITY, 0, NODE_TIMING_SOURCE_ROLLUP);
        assert_eq!(v["avg_duration_ms"], 0.0);
    }

    /// The population is stated ONCE, and states both sources plus what an
    /// empty list means.
    #[test]
    fn the_note_states_both_populations_once() {
        let n = NODE_TIMING_BREAKDOWN_NOTE;
        assert!(n.contains(NODE_TIMING_SOURCE_OUTPUT), "{n}");
        assert!(n.contains(NODE_TIMING_SOURCE_ROLLUP), "{n}");
        assert!(n.contains("sample_count"), "{n}");
        assert!(n.contains("empty list"), "{n}");
        // The fallback's error is swallowed (`if let Ok(..)`), so the note
        // must not promise that an empty list proves both sources were empty.
        assert!(n.contains("its query failed"), "{n}");
    }
}

#[cfg(test)]
mod readiness_population_pins {
    //! `get_all_readiness_scores`' summary must describe the FLEET, not the page.
    //!
    //! The page is `ORDER BY COALESCE(readiness_score, 0) ASC LIMIT 50` — the 50
    //! LOWEST scorers. Accumulating a mean over it and calling it `avg_score` is
    //! not a truncation (which a `truncated: true` flag would answer); it is an
    //! inverted statistic. Pinned rather than disclosed for that reason.
    use super::readiness_summary_json;
    use talos_analytics_repository::ReadinessPopulation;

    fn pop(total: i64, avg: Option<f64>, below: i64, unscored: i64) -> ReadinessPopulation {
        ReadinessPopulation {
            total,
            avg_score: avg,
            below_50: below,
            unscored,
        }
    }

    #[test]
    fn summary_reports_population_figures_not_page_figures() {
        // The live reference deployment: 22 non-archived workflows, true mean
        // 75.59. The pre-fix handler emitted 75 (integer division).
        let v = readiness_summary_json(Some(&pop(22, Some(75.59), 3, 21)));
        assert_eq!(v["avg_score"], serde_json::json!(75.6));
        assert_eq!(v["below_50_count"], serde_json::json!(3));
        assert_eq!(v["unscored_count"], serde_json::json!(21));
        assert!(v["population"].as_str().unwrap().contains("uncapped"));
    }

    #[test]
    fn a_failed_population_query_nulls_the_summary_rather_than_falling_back_to_the_page() {
        // This is the whole point. A fallback to page-derived figures would be
        // silently WRONG (a worst-50 mean under a fleet-average name); a null is
        // merely absent. If someone "helpfully" restores a fallback, this fails.
        let v = readiness_summary_json(None);
        assert_eq!(v["avg_score"], serde_json::Value::Null);
        assert_eq!(v["below_50_count"], serde_json::Value::Null);
        assert_eq!(v["unscored_count"], serde_json::Value::Null);
        assert!(
            v["population"].as_str().unwrap().contains("unavailable"),
            "the note must say the figures are missing, not imply they are zero"
        );
    }

    #[test]
    fn an_empty_fleet_yields_a_null_mean_not_a_zero_one() {
        // AVG() over zero rows is SQL NULL. Rendering that as 0 would report an
        // empty account as "every workflow scores zero" — the same
        // absent-is-not-zero rule the alerting layer learned in #625.
        let v = readiness_summary_json(Some(&pop(0, None, 0, 0)));
        assert_eq!(v["avg_score"], serde_json::Value::Null);
        assert_eq!(v["below_50_count"], serde_json::json!(0));
    }
}

#[cfg(test)]
mod system_health_disclosure_tests {
    use super::{render_system_health, SystemHealthReads};
    use talos_measurement::Readings;

    /// Every field measured. Nothing is nulled and no `measurement` block is
    /// added — the healthy response must be byte-identical to the pre-fix one,
    /// or every dashboard reading this tool moves for no reason.
    #[test]
    fn a_fully_measured_report_is_unchanged_and_carries_no_disclosure() {
        let readings = Readings::new();
        let out = render_system_health(
            true,
            &SystemHealthReads {
                total_workflows: 30,
                total_modules: 91,
                total_executions: 5000,
                active_schedules: Some(12),
                active_webhooks: Some(3),
                stale_executions: Some(0),
                unacknowledged_alerts: Some(0),
                error_rate: Some((100, 7)),
                storage: Some((1024 * 1024, 0)),
            },
            &readings,
        );

        assert_eq!(out["stale_executions"], 0);
        assert_eq!(out["unacknowledged_alerts"], 0);
        assert_eq!(out["recent_failure_rate"]["failure_rate_pct"], 7.0);
        assert_eq!(out["disk_usage"]["total_wasm_mb"], "1.00");
        assert!(
            out.get("measurement").is_none(),
            "a clean run must not grow a disclosure block: {out}"
        );
    }

    /// THE regression. The two fields an operator opens this tool for during an
    /// incident are `stale_executions` and `unacknowledged_alerts`. Pre-fix a
    /// failed query rendered both as `0` — "no stuck executions, no
    /// unacknowledged alerts" — which is the most reassuring output the tool
    /// can produce, emitted precisely because the database was unreachable.
    #[test]
    fn a_query_failure_is_null_and_disclosed_never_a_reassuring_zero() {
        let mut readings = Readings::new();
        // Drive the REAL recorder with the real error type shape, rather than
        // hand-constructing a not-measured list.
        let stale = readings.record(
            "stale_executions",
            Err::<i64, _>(anyhow::anyhow!("connection reset by peer")),
        );
        let unack = readings.record(
            "unacknowledged_alerts",
            Err::<i64, _>(anyhow::anyhow!("connection reset by peer")),
        );
        let rate = readings.record(
            "recent_failure_rate",
            Err::<(i64, i64), _>(anyhow::anyhow!("connection reset by peer")),
        );

        let out = render_system_health(
            true,
            &SystemHealthReads {
                total_workflows: 30,
                total_modules: 91,
                total_executions: 5000,
                active_schedules: Some(12),
                active_webhooks: Some(3),
                stale_executions: stale,
                unacknowledged_alerts: unack,
                error_rate: rate,
                storage: Some((0, 0)),
            },
            &readings,
        );

        assert!(out["stale_executions"].is_null(), "{out}");
        assert!(out["unacknowledged_alerts"].is_null(), "{out}");
        assert_ne!(out["stale_executions"], 0);
        assert_ne!(out["unacknowledged_alerts"], 0);

        // The derived rate must not survive its inputs. `0%` failures is the
        // benign reading, and it is unreachable from an unmeasured denominator.
        assert!(
            out["recent_failure_rate"]["failure_rate_pct"].is_null(),
            "{out}"
        );
        assert!(
            out["recent_failure_rate"]["total_executions"].is_null(),
            "{out}"
        );

        // Measured fields are untouched by a sibling's failure.
        assert_eq!(out["active_schedules"], 12);

        // And the degradation travels with the data, not only in the log.
        assert_eq!(out["measurement"]["complete"], false);
        let named = out["measurement"]["not_measured"].as_array().unwrap();
        assert_eq!(named.len(), 3, "{out}");
        assert!(named.iter().any(|v| v == "stale_executions"));
        assert!(named.iter().any(|v| v == "unacknowledged_alerts"));
    }

    /// A measured zero and an unmeasurable field must never serialize the same.
    /// This is the whole class in one assertion.
    #[test]
    fn measured_zero_and_could_not_measure_are_distinguishable_in_the_wire_shape() {
        let clean = Readings::new();
        let measured = render_system_health(
            true,
            &SystemHealthReads {
                total_workflows: 0,
                total_modules: 0,
                total_executions: 0,
                active_schedules: Some(0),
                active_webhooks: Some(0),
                stale_executions: Some(0),
                unacknowledged_alerts: Some(0),
                error_rate: Some((0, 0)),
                storage: Some((0, 0)),
            },
            &clean,
        );

        let mut broken_readings = Readings::new();
        for field in [
            "active_schedules",
            "active_webhooks",
            "stale_executions",
            "unacknowledged_alerts",
            "recent_failure_rate",
            "disk_usage",
        ] {
            let _: Option<i64> =
                broken_readings.record(field, Err::<i64, _>(anyhow::anyhow!("db down")));
        }
        let unmeasured = render_system_health(
            true,
            &SystemHealthReads {
                total_workflows: 0,
                total_modules: 0,
                total_executions: 0,
                active_schedules: None,
                active_webhooks: None,
                stale_executions: None,
                unacknowledged_alerts: None,
                error_rate: None,
                storage: None,
            },
            &broken_readings,
        );

        assert_ne!(
            measured, unmeasured,
            "an all-zero system and an unreachable database rendered identically"
        );
    }
}

/// The `validate_all_workflows` output contract.
///
/// Every test drives the REAL [`FleetValidationTally`] the handler drives —
/// the counts and the truncation disclosure are pinned against shipping code,
/// not a test-local restatement of it.
#[cfg(test)]
mod fleet_validation_tally_tests {
    use super::{
        FleetValidationTally, FLEET_MAX_DETAIL_WORKFLOWS, FLEET_MAX_FINDINGS_PER_WORKFLOW,
    };
    use talos_workflow_validation::{
        HistoryCoverage, ValidationIssue, ValidationResult, ValidationSeverity,
    };
    use uuid::Uuid;

    fn issue(severity: ValidationSeverity, message: &str) -> ValidationIssue {
        ValidationIssue {
            severity,
            message: message.to_string(),
            node_id: None,
            category: "test".into(),
        }
    }

    fn result(issues: Vec<ValidationIssue>, history: HistoryCoverage) -> ValidationResult {
        ValidationResult {
            valid: !issues
                .iter()
                .any(|i| i.severity == ValidationSeverity::Error),
            issues,
            history,
        }
    }

    fn observed() -> HistoryCoverage {
        HistoryCoverage::Observed {
            executions: 5,
            window_days: 30,
        }
    }

    /// The count contract, stated as a test because a warning silently
    /// becoming "invalid" is the regression this response shape invites.
    #[test]
    fn warnings_never_make_a_workflow_invalid() {
        let mut t = FleetValidationTally::default();
        t.record(
            Uuid::from_u128(1),
            "warns-a-lot",
            &result(
                vec![
                    issue(ValidationSeverity::Warning, "w1"),
                    issue(ValidationSeverity::Warning, "w2"),
                    issue(ValidationSeverity::Warning, "w3"),
                ],
                observed(),
            ),
        );
        let out = t.render(30);
        assert_eq!(out["valid_count"], 1);
        assert_eq!(out["invalid_count"], 0);
        assert_eq!(out["warning_count"], 3);
        assert_eq!(out["error_count"], 0);
        assert_eq!(out["workflows_with_warnings"], 1);
        // A valid workflow with warnings appears in `warnings` and NOT in `issues`.
        assert_eq!(out["issues"].as_array().unwrap().len(), 0);
        assert_eq!(out["warnings"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn one_error_makes_a_workflow_invalid_regardless_of_warnings() {
        let mut t = FleetValidationTally::default();
        t.record(
            Uuid::from_u128(1),
            "broken",
            &result(
                vec![
                    issue(ValidationSeverity::Error, "cycle"),
                    issue(ValidationSeverity::Warning, "w"),
                ],
                observed(),
            ),
        );
        let out = t.render(30);
        assert_eq!(out["valid_count"], 0);
        assert_eq!(out["invalid_count"], 1);
        assert_eq!(out["error_count"], 1);
        assert_eq!(out["warning_count"], 1);
        // The SAME workflow appears in both lists, once per severity.
        assert_eq!(out["issues"].as_array().unwrap().len(), 1);
        assert_eq!(out["warnings"].as_array().unwrap().len(), 1);
    }

    /// `count` / `total` count WORKFLOWS. `error_count` / `warning_count`
    /// count FINDINGS. Conflating them is how a fleet report starts claiming
    /// more broken workflows than exist.
    #[test]
    fn workflow_counts_and_finding_counts_are_different_numbers() {
        let mut t = FleetValidationTally::default();
        for i in 0..3u128 {
            t.record(
                Uuid::from_u128(i),
                "wf",
                &result(
                    vec![
                        issue(ValidationSeverity::Warning, "a"),
                        issue(ValidationSeverity::Warning, "b"),
                    ],
                    observed(),
                ),
            );
        }
        let out = t.render(30);
        assert_eq!(out["count"], 3, "three workflows");
        assert_eq!(out["total"], 3);
        assert_eq!(out["warning_count"], 6, "six findings");
        assert_eq!(out["workflows_with_warnings"], 3);
    }

    /// A cap may shorten a list. It may NEVER move a count.
    #[test]
    fn truncation_shortens_the_list_but_never_the_counts() {
        let mut t = FleetValidationTally::default();
        let over = FLEET_MAX_FINDINGS_PER_WORKFLOW + 4;
        t.record(
            Uuid::from_u128(1),
            "noisy",
            &result(
                (0..over)
                    .map(|i| issue(ValidationSeverity::Warning, &format!("w{i}")))
                    .collect(),
                observed(),
            ),
        );
        let out = t.render(30);
        assert_eq!(
            out["warning_count"], over,
            "the count is over EVERY finding"
        );
        let entry = &out["warnings"][0];
        assert_eq!(
            entry["warnings"].as_array().unwrap().len(),
            FLEET_MAX_FINDINGS_PER_WORKFLOW
        );
        assert_eq!(
            entry["total_for_workflow"], over,
            "each entry states its own true total"
        );
        assert_eq!(out["truncated"]["findings_omitted"], 4);
    }

    #[test]
    fn a_workflow_past_the_detail_cap_is_counted_and_disclosed_not_silently_dropped() {
        let mut t = FleetValidationTally::default();
        let n = FLEET_MAX_DETAIL_WORKFLOWS + 3;
        for i in 0..n as u128 {
            t.record(
                Uuid::from_u128(i),
                "wf",
                &result(vec![issue(ValidationSeverity::Warning, "w")], observed()),
            );
        }
        let out = t.render(30);
        assert_eq!(out["count"], n as u64, "every workflow is counted");
        assert_eq!(out["warning_count"], n, "every finding is counted");
        assert_eq!(out["workflows_with_warnings"], n as u64);
        assert_eq!(
            out["warnings"].as_array().unwrap().len(),
            FLEET_MAX_DETAIL_WORKFLOWS
        );
        assert_eq!(out["truncated"]["warning_workflows_omitted"], 3);
        assert_eq!(out["truncated"]["findings_omitted"], 3);
    }

    #[test]
    fn nothing_omitted_reports_zero_rather_than_omitting_the_disclosure() {
        let mut t = FleetValidationTally::default();
        t.record(
            Uuid::from_u128(1),
            "fine",
            &result(vec![issue(ValidationSeverity::Warning, "w")], observed()),
        );
        let out = t.render(30);
        assert_eq!(out["truncated"]["findings_omitted"], 0);
        assert_eq!(out["truncated"]["warning_workflows_omitted"], 0);
        assert_eq!(out["truncated"]["issue_workflows_omitted"], 0);
        // The caps themselves are reported, so a reader can tell a full list
        // from one that merely happens to sit at the limit.
        assert_eq!(
            out["truncated"]["max_findings_per_workflow"],
            FLEET_MAX_FINDINGS_PER_WORKFLOW
        );
    }

    /// An empty `warnings` list means something different depending on
    /// whether history could be read. The response says which.
    #[test]
    fn history_coverage_is_reported_per_state() {
        let mut t = FleetValidationTally::default();
        t.record(Uuid::from_u128(1), "a", &result(vec![], observed()));
        t.record(
            Uuid::from_u128(2),
            "b",
            &result(vec![], HistoryCoverage::Empty { window_days: 30 }),
        );
        t.record(
            Uuid::from_u128(3),
            "c",
            &result(vec![], HistoryCoverage::Unavailable),
        );
        let out = t.render(30);
        assert_eq!(out["history"]["consulted"], 1);
        assert_eq!(out["history"]["empty"], 1);
        assert_eq!(out["history"]["unavailable"], 1);
        assert_eq!(out["history"]["window_days"], 30);
        // All three are still VALID workflows — history coverage is a
        // statement about what was examined, never a verdict.
        assert_eq!(out["valid_count"], 3);
    }

    /// A clean fleet must be legible as clean: zeros everywhere, empty lists,
    /// and the pre-existing `valid_count`/`invalid_count`/`count`/`total`
    /// keys unchanged in name and meaning for existing callers.
    #[test]
    fn the_legacy_keys_survive_unchanged_for_existing_callers() {
        let mut t = FleetValidationTally::default();
        t.record(Uuid::from_u128(1), "clean", &result(vec![], observed()));
        let out = t.render(30);
        for key in ["valid_count", "invalid_count", "count", "total", "issues"] {
            assert!(out.get(key).is_some(), "legacy key `{key}` disappeared");
        }
        assert_eq!(out["valid_count"], 1);
        assert_eq!(out["invalid_count"], 0);
        assert_eq!(out["issues"].as_array().unwrap().len(), 0);
    }
}

/// The rendering half of `suggest_retry_config`'s per-node advice (#721).
///
/// The DECISIONS are tested in `talos-workflow-validation` against the same
/// functions `validate_workflow` calls — that is the whole point of the split.
/// What is testable here is that the handler does not lose or misname them on
/// the way out, which is where the previous version's confident number came
/// from.
#[cfg(test)]
mod retry_advice_rendering_tests {
    use super::describe_retry_bound;
    use talos_workflow_validation::RetryAdviceBound;

    #[test]
    fn a_budget_bound_names_the_ceiling_and_the_rejected_envelope() {
        let v = describe_retry_bound(&RetryAdviceBound::Budget {
            max_retries: 1,
            budget_secs: 300,
            proposed_envelope_secs: 369,
        });
        assert_eq!(v["bound"], "workflow_budget");
        assert_eq!(v["max_retry_count"], 1);
        assert_eq!(v["workflow_budget_secs"], 300);
        assert_eq!(v["rejected_envelope_secs"], 369);
        assert!(v["reason"]
            .as_str()
            .unwrap()
            .contains("discarding every sibling node"));
    }

    /// The cap reported must be the one that APPLIED, not the module default —
    /// on `organize_work` those are 2 and 0 and reporting the default would
    /// tell an operator their state-changing node is capped at 0 when the
    /// engine will make three attempts.
    #[test]
    fn a_cap_bound_reports_the_value_that_applied_not_the_module_default() {
        let v = describe_retry_bound(&RetryAdviceBound::ModuleDefault {
            cap_retries: 2,
            current_retries: 2,
            world_default_retries: 0,
            capability_world: Some("http-node".into()),
            allowed_methods: vec!["GET".into(), "POST".into()],
        });
        assert_eq!(v["bound"], "author_or_module_default");
        assert_eq!(v["max_retry_count"], 2);
        assert_eq!(v["current_retry_count"], 2);
        assert_eq!(v["module_default_retry_count"], 0);
        assert_eq!(v["capability_world"], "http-node");
        assert!(v["reason"].as_str().unwrap().contains("HIGHER of"));
    }
}
