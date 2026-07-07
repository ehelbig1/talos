use super::types::JsonRpcResponse;
use super::utils::{mcp_error, mcp_text};
use super::{auth, McpState};
use serde_json::Value;
use std::fmt::Write as FmtWrite;
use std::sync::Arc;
use uuid::Uuid;

pub fn tool_schemas() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "name": "get_execution_status",
            "description": "Check the status and results of a workflow execution. Pass detail: true (default) to get the full per-node trace including status, duration, output, and retries for every node.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "execution_id": { "type": "string", "description": "UUID of the execution to check" },
                    "detail": { "type": "boolean", "description": "If true, return full per-node trace (status, duration, output, retries) instead of the summary. Default: true. Set false for lightweight polling loops where only the status string is needed." }
                },
                "required": ["execution_id"]
            }
        }),
        serde_json::json!({
            "name": "list_executions",
            "description": "List recent executions for a workflow with status, time, and error info.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string" },
                    "limit": { "type": "number", "description": "Max results (default 60)" },
                    "offset": { "type": "number", "description": "Skip this many results (default 0)" }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "list_recent_executions",
            "description": "List recent workflow executions across all workflows for the current user, with optional status filter.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": { "type": "number", "description": "Max results (default 20, max 100)" },
                    "status": { "type": "string", "description": "Filter by status (e.g. 'completed', 'failed', 'running')" }
                },
            }
        }),
        serde_json::json!({
            "name": "replay_execution",
            "description": "Re-run a previous workflow execution using the same trigger input. Returns a new execution ID.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "execution_id": { "type": "string", "description": "UUID of the execution to replay" }
                },
                "required": ["execution_id"]
            }
        }),
        serde_json::json!({
            "name": "replay_execution_with_input",
            "description": "Re-run a previous workflow execution with the original trigger input deep-merged with the provided overrides. Useful for retrying with corrected parameters without modifying the workflow.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "execution_id": { "type": "string", "description": "UUID of the execution to replay" },
                    "input_overrides": { "type": "object", "description": "Key-value overrides to deep-merge into the original trigger input" }
                },
                "required": ["execution_id", "input_overrides"]
            }
        }),
        serde_json::json!({
            "name": "cancel_execution",
            "description": "Cancel a running workflow execution.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "execution_id": { "type": "string", "description": "UUID of the execution to cancel" }
                },
                "required": ["execution_id"]
            }
        }),
        serde_json::json!({
            "name": "cleanup_stale_executions",
            "description": "Clean up executions stuck in 'running' state (from crashes, timeouts, or orphaned processes). Marks them as failed.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "older_than_minutes": { "type": "number", "description": "Only clean up executions running longer than this many minutes (default: 60, minimum: 5)" }
                },
            }
        }),
        serde_json::json!({
            "name": "get_execution_logs",
            "description": "Get the event timeline (WASM module logs) for an execution, including node statuses, log messages, and timestamps.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "execution_id": { "type": "string", "description": "UUID of the execution" }
                },
                "required": ["execution_id"]
            }
        }),
        serde_json::json!({
            "name": "tail_worker_logs",
            "description": "Stream the per-line log output from worker WASM modules for a workflow execution. Returns ascending-time-ordered entries with level/message/node_id/metadata. Pairs with analyze_failure: when a node fails with an opaque error, tail_worker_logs surfaces the structured `gate=...` and other tracing events the worker emitted during the run.\n\nDifference vs get_execution_logs: that returns the engine's own node-state event stream (node_started, node_completed, etc.); this returns the WASM module's stdout/structured-log output. Use both together for a full debugging picture.\n\nOnly accepts workflow_execution IDs (the common case for trigger_workflow / call_workflow / scheduled runs). For standalone module_executions (test_module / webhook), use get_execution_logs.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "execution_id": { "type": "string", "description": "UUID of the workflow execution" },
                    "node_id": { "type": "string", "description": "Optional UUID of a specific node — when set, only logs from that node are returned" },
                    "min_level": {
                        "type": "string",
                        "enum": ["DEBUG", "INFO", "WARN", "ERROR"],
                        "description": "Minimum log level to include (default: INFO)"
                    },
                    "since": { "type": "string", "description": "RFC3339 timestamp — only logs at or after this time. Useful for tailing live runs without re-fetching old lines." },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 5000, "description": "Max entries to return (default: 500, max: 5000)" }
                },
                "required": ["execution_id"]
            }
        }),
        serde_json::json!({
            "name": "get_node_output",
            "description": "Get the output of a specific node from an execution (instead of the entire workflow output).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "execution_id": { "type": "string", "description": "UUID of the execution" },
                    "node_id": { "type": "string", "description": "Node ID (label) to retrieve output for" }
                },
                "required": ["execution_id", "node_id"]
            }
        }),
        serde_json::json!({
            "name": "compare_executions",
            "description": "Compare two workflow executions side-by-side. Shows per-node output differences, timing, and status. Per-value byte cap defaults to 8 KiB to keep responses under MCP-client request timeouts; set max_bytes_per_value to override (max 65536). Truncated values are replaced with a {__truncated, original_byte_size, preview} envelope; truncated_value_count reports how many fired.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "execution_id_a": { "type": "string", "description": "UUID of the first execution" },
                    "execution_id_b": { "type": "string", "description": "UUID of the second execution" },
                    "max_bytes_per_value": { "type": "number", "description": "Per-value cap for inline value_a/value_b in the response (default 8192, max 65536, min 1024). Values exceeding this are replaced with a truncation envelope." }
                },
                "required": ["execution_id_a", "execution_id_b"]
            }
        }),
        serde_json::json!({
            "name": "get_execution_timeline",
            "description": "Rich execution visualization: combines events, per-node timings, and output into a unified human-readable timeline.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "execution_id": { "type": "string", "description": "UUID of the execution" }
                },
                "required": ["execution_id"]
            }
        }),
        serde_json::json!({
            "name": "pin_execution",
            "description": "Mark an execution as pinned/important for easy reference later.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "execution_id": { "type": "string", "description": "UUID of the execution to pin" },
                    "note": { "type": "string", "description": "Optional note explaining why this execution is pinned" }
                },
                "required": ["execution_id"]
            }
        }),
        serde_json::json!({
            "name": "unpin_execution",
            "description": "Remove the pinned flag from an execution.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "execution_id": { "type": "string", "description": "UUID of the execution to unpin" }
                },
                "required": ["execution_id"]
            }
        }),
        serde_json::json!({
            "name": "list_pinned_executions",
            "description": "List all pinned (important) executions for the current user, ordered by most recent first.",
            "inputSchema": {
                "type": "object",
                "properties": {},
            }
        }),
        serde_json::json!({
            "name": "acknowledge_execution_failure",
            "description": "Mark a failed execution as acknowledged so it is excluded from the workflow's reliability score in get_readiness_breakdown. \
                Use for known-historical failures that do not reflect the workflow's current quality — for example, deliberate test failures, \
                infra incidents, or config experiments. The execution remains in history for audit purposes. \
                Only failed executions can be acknowledged.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "execution_id": {
                        "type": "string",
                        "description": "UUID of the failed execution to acknowledge"
                    },
                    "reason": {
                        "type": "string",
                        "description": "Human-readable explanation of why this failure is acknowledged (e.g. 'infra incident 2026-03-15', 'known flaky dependency — ticket #4821')"
                    }
                },
                "required": ["execution_id", "reason"]
            }
        }),
        serde_json::json!({
            "name": "pause_executions",
            "description": "(Admin only) Pause the execution queue. New workflow triggers will be rejected until resumed. Requires admin privileges — returns an error for non-admin agents.",
            "inputSchema": {
                "type": "object",
                "properties": {},
            }
        }),
        serde_json::json!({
            "name": "resume_executions",
            "description": "(Admin only) Resume the execution queue after it has been paused. Requires admin privileges — returns an error for non-admin agents.",
            "inputSchema": {
                "type": "object",
                "properties": {},
            }
        }),
        serde_json::json!({
            "name": "enqueue_workflow",
            "description": "Enqueue a large batch of workflow executions with rate limiting. Unlike bulk_trigger_workflow (max 20), this has no cap on total inputs but rate-limits execution dispatch. Execution records are created upfront with 'queued' status.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to execute" },
                    "inputs": {
                        "type": "array",
                        "items": { "type": "object" },
                        "description": "Array of input objects. Each becomes a separate execution."
                    },
                    "rate_per_second": { "type": "number", "description": "Executions per second (default: 5, max: 20)" }
                },
                "required": ["workflow_id", "inputs"]
            }
        }),
        serde_json::json!({
            "name": "cancel_queued_executions",
            "description": "Cancel all queued (not yet started) executions for a workflow. Use this to drain a batch that was enqueued with incorrect inputs or that is no longer needed. Only affects executions in 'queued' status — running executions are not interrupted. Returns the count and IDs of cancelled executions.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow whose queued executions should be cancelled" },
                    "limit": { "type": "number", "description": "Maximum number of queued executions to cancel in one call (default: 1000, max: 10000). Use for incremental draining of very large queues." }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "get_sub_workflow_output",
            "description": "Get the output of a sub-workflow node from a parent execution. Returns the child workflow's per-node results.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "execution_id": { "type": "string", "description": "UUID of the parent execution" },
                    "node_id": { "type": "string", "description": "Node ID of the sub-workflow node in the parent workflow" }
                },
                "required": ["execution_id", "node_id"]
            }
        }),
        serde_json::json!({
            "name": "watch_execution",
            "description": "Poll execution progress. Returns current status, new events since a given timestamp, and elapsed time. Designed for efficient polling: pass since = last event timestamp to get only new events. Accepts execution_id (direct) or workflow_id (resolves to the latest execution for that workflow).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "execution_id": { "type": "string", "description": "UUID of the execution to watch. Either this or workflow_id is required." },
                    "workflow_id": { "type": "string", "description": "UUID of the workflow — resolves to its most recent execution. Use when you don't have the execution_id handy." },
                    "since": { "type": "string", "description": "ISO 8601 timestamp — only return events after this time. Omit to get all events." }
                }
            }
        }),
        serde_json::json!({
            "name": "retry_execution",
            "description": "Retry a failed or cancelled execution by resetting its status and re-running it in-place. Unlike replay_execution, this updates the SAME execution record.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "execution_id": { "type": "string", "description": "UUID of the failed/cancelled execution to retry" }
                },
                "required": ["execution_id"]
            }
        }),
        serde_json::json!({
            "name": "get_execution_output",
            "description": "Get the complete, untruncated output_data JSON for a workflow execution. Unlike get_execution_status (which truncates large outputs), this returns the full raw output.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "execution_id": { "type": "string", "description": "UUID of the execution" }
                },
                "required": ["execution_id"]
            }
        }),
        serde_json::json!({
            "name": "get_execution_diff",
            "description": "Compare outputs of two executions with detailed field-level diffs per node. Shows which fields were added, removed, or changed (with both values). More detailed than compare_executions. Per-value byte cap defaults to 8 KiB to keep responses under MCP-client request timeouts; set max_bytes_per_value to override (max 65536).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "execution_id_a": { "type": "string", "description": "UUID of the first execution" },
                    "execution_id_b": { "type": "string", "description": "UUID of the second execution" },
                    "node_id": { "type": "string", "description": "Optional: focus diff on a specific node. Use the graph node_id string (e.g. 'fetch', 'validate-input') as defined when the node was added — NOT the module display label and NOT a UUID. Find node IDs via get_workflow_graph." },
                    "max_bytes_per_value": { "type": "number", "description": "Per-value cap for inline value_a/value_b in the response (default 8192, max 65536, min 1024). Values exceeding this are replaced with a truncation envelope." }
                },
                "required": ["execution_id_a", "execution_id_b"]
            }
        }),
        serde_json::json!({
            "name": "get_node_execution_history",
            "description": "Get execution history for a specific node across multiple workflow runs. Shows which executions the node succeeded/failed in.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" },
                    "node_label": { "type": "string", "description": "Identifies the node in the workflow graph. Accepts (1) the rf_id (e.g. 'synthesize', 'fetch-data' — the value in the 'id' column of get_workflow_graph), (2) the module display name (e.g. 'LLM Inference'), or (3) the explicit data.label set in the editor. Resolution preference is rf_id → module name → data.label; the response's resolved_via field reports which path matched." },
                    "limit": { "type": "number", "description": "Max events to return (default: 20, max: 100)" }
                },
                "required": ["workflow_id", "node_label"]
            }
        }),
        serde_json::json!({
            "name": "get_execution_cost",
            "description": "Track and expose resource consumption for a specific execution. Returns total duration, node count, per-node timings, and estimated compute units.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "execution_id": { "type": "string", "description": "UUID of the execution to analyze" }
                },
                "required": ["execution_id"]
            }
        }),
        serde_json::json!({
            "name": "get_execution_waterfall",
            "description": "Visual text-based waterfall chart showing parallel execution timing for each node in a workflow execution.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "execution_id": { "type": "string", "description": "UUID of the execution to visualize" }
                },
                "required": ["execution_id"]
            }
        }),
        serde_json::json!({
            "name": "get_execution_replay_chain",
            "description": "Trace replay lineage for an execution. Finds other executions on the same workflow with matching input data, indicating replays.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "execution_id": { "type": "string", "description": "UUID of the execution to trace" }
                },
                "required": ["execution_id"]
            }
        }),
        serde_json::json!({
            "name": "get_execution_comparison_report",
            "description": "Compare multiple executions side-by-side: status, duration, output keys, and divergences. Useful for debugging flaky workflows.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "execution_ids": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Array of execution UUIDs to compare (max 10)"
                    }
                },
                "required": ["execution_ids"]
            }
        }),
        serde_json::json!({
            "name": "get_execution_delta",
            "description": "Show what changed in node outputs across the last N executions of a workflow. Fetches up to N recent completed/failed executions, then computes a field-level diff between each consecutive pair (run K vs run K+1). Returns per-node change summaries, identical-count, and a stability rating. Useful for spotting regressions or intermittent failures without manually comparing individual executions.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to inspect" },
                    "n": { "type": "number", "description": "Number of recent executions to compare (default: 5, min: 2, max: 10)" },
                    "node_label": { "type": "string", "description": "Optional: focus delta on a single node's output. Matched against the node's display label (module name), NOT its node_id string — passing an actual node_id UUID will match nothing. Use get_workflow_graph to see node labels." }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "analyze_execution_failure",
            "description": "Diagnose why a failed workflow execution failed. Fetches failed-node events, classifies error type (output_schema_violation / host_not_allowed / module_compile_error / json_parse / missing_secret / rate_limit / fuel_exhausted / wasm_trap / timeout / network_error / config_error / http_401 / http_403 / http_404 / http_5xx / auth_error / database_error / runtime_error), and returns numbered remediation steps. Call this immediately after an execution fails to get actionable next steps. When apply_fix=true and a config_error is detected with an extractable field, automatically patches the workflow graph.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "execution_id": { "type": "string", "description": "UUID of the failed execution to analyze" },
                    "apply_fix": { "type": "boolean", "description": "When true and failure_class is config_error with an extractable field name, automatically patches the workflow graph. Default: false." },
                    "auto_retry": { "type": "boolean", "description": "When true and apply_fix succeeds, automatically retries the execution. Only meaningful with apply_fix=true. Default: false." }
                },
                "required": ["execution_id"]
            }
        }),
        serde_json::json!({
            "name": "get_execution_lineage",
            "description": "Trace the full parent–child execution tree for any execution. Shows all ancestor and descendant executions linked via parent_execution_id, giving a unified view of how a single user action (trigger, handoff, or sub-workflow dispatch) spawned multiple executions across actors and workflows. Useful for debugging complex agentic scenarios where one intent fans out into many runs.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "execution_id": { "type": "string", "description": "UUID of any execution in the lineage — root, leaf, or intermediate. The tool walks up to the root then expands all descendants." }
                },
                "required": ["execution_id"]
            }
        }),
        serde_json::json!({
            "name": "list_pending_approvals",
            "description": "List execution-level approvals — workflow executions paused at an approval node, waiting for human action. Shows the execution ID, workflow name, node that requested approval, the approval reason, and how long it has been waiting. Use submit_workflow_approval to approve or reject. NOTE: list_approval_gates is the broader actor-policy surface (gate creation history, all statuses, audit). list_pending_approvals is the operator-action surface (only pending, only execution-blocking). Pick this one when 'what do I need to act on right now?' is the question.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": { "type": "number", "description": "Max results (default 20, max 100)" }
                }
            }
        }),
        serde_json::json!({
            "name": "submit_workflow_approval",
            "description": "Approve or reject a workflow execution that is paused waiting for human review. Pass the execution_id from list_pending_approvals and set approved=true to allow execution to continue or approved=false to reject it. An optional reason string is recorded in the audit log.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "execution_id": { "type": "string", "description": "UUID of the workflow execution waiting for approval (from list_pending_approvals)" },
                    "approved": { "type": "boolean", "description": "true to approve and allow execution to continue; false to reject and fail the execution" },
                    "reason": { "type": "string", "description": "Optional human-readable reason for the decision, stored in the audit log" }
                },
                "required": ["execution_id", "approved"]
            }
        }),
        serde_json::json!({
            "name": "get_execution_trace",
            "description": "Get the full per-node execution trace for a workflow execution. Returns each node's label, status, start/finish times, duration, retry count, error messages, and output data. Same data as get_execution_status with detail: true, but as a dedicated tool for when you already know you want the full trace.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "execution_id": { "type": "string", "description": "UUID of the execution to trace" }
                },
                "required": ["execution_id"]
            }
        }),
        serde_json::json!({
            "name": "get_node_io",
            "description": "Get the input and output for a specific node in a workflow execution. Useful for debugging data flow between nodes.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "execution_id": { "type": "string", "description": "UUID of the execution" },
                    "node_id": { "type": "string", "description": "Node label (e.g. 'fetch-jira', 'summarize')" }
                },
                "required": ["execution_id", "node_id"]
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
    let is_admin = agent.is_admin();
    match name {
        "get_execution_status" => {
            Some(handle_get_execution_status(req_id, args, state, user_id).await)
        }
        "list_executions" => Some(handle_list_executions(req_id, args, state, user_id).await),
        "list_recent_executions" => {
            Some(handle_list_recent_executions(req_id, args, state, user_id).await)
        }
        "replay_execution" => Some(handle_replay_execution(req_id, args, state, user_id).await),
        "replay_execution_with_input" => {
            Some(handle_replay_execution_with_input(req_id, args, state, user_id).await)
        }
        "cancel_execution" => Some(handle_cancel_execution(req_id, args, state, user_id).await),
        "cleanup_stale_executions" => {
            Some(handle_cleanup_stale_executions(req_id, args, state, user_id).await)
        }
        "get_execution_logs" => Some(handle_get_execution_logs(req_id, args, state, user_id).await),
        "tail_worker_logs" => Some(handle_tail_worker_logs(req_id, args, state, user_id).await),
        "get_node_output" => Some(handle_get_node_output(req_id, args, state, user_id).await),
        "compare_executions" => Some(handle_compare_executions(req_id, args, state, user_id).await),
        "get_execution_timeline" => {
            Some(handle_get_execution_timeline(req_id, args, state, user_id).await)
        }
        "pin_execution" => Some(handle_pin_execution(req_id, args, state, user_id).await),
        "unpin_execution" => Some(handle_unpin_execution(req_id, args, state, user_id).await),
        "list_pinned_executions" => {
            Some(handle_list_pinned_executions(req_id, args, state, user_id).await)
        }
        "pause_executions" => {
            Some(handle_pause_executions(req_id, args, state, user_id, is_admin).await)
        }
        "resume_executions" => {
            Some(handle_resume_executions(req_id, args, state, user_id, is_admin).await)
        }
        "enqueue_workflow" => Some(handle_enqueue_workflow(req_id, args, state, user_id).await),
        "get_sub_workflow_output" => {
            Some(handle_get_sub_workflow_output(req_id, args, state, user_id).await)
        }
        "watch_execution" => Some(handle_watch_execution(req_id, args, state, user_id).await),
        "retry_execution" => Some(handle_retry_execution(req_id, args, state, user_id).await),
        "get_execution_output" => {
            Some(handle_get_execution_output(req_id, args, state, user_id).await)
        }
        "get_execution_diff" => Some(handle_get_execution_diff(req_id, args, state, user_id).await),
        "get_node_execution_history" => {
            Some(handle_get_node_execution_history(req_id, args, state, user_id).await)
        }
        "get_execution_cost" => Some(handle_get_execution_cost(req_id, args, state, user_id).await),
        "get_execution_waterfall" => {
            Some(handle_get_execution_waterfall(req_id, args, state, user_id).await)
        }
        "get_execution_replay_chain" => {
            Some(handle_get_execution_replay_chain(req_id, args, state, user_id).await)
        }
        "get_execution_comparison_report" => {
            Some(handle_get_execution_comparison_report(req_id, args, state, user_id).await)
        }
        "get_execution_trace" => {
            Some(handle_get_execution_trace(req_id, args, state, user_id).await)
        }
        "get_execution_delta" => {
            Some(handle_get_execution_delta(req_id, args, state, user_id).await)
        }
        "analyze_execution_failure" => {
            Some(handle_analyze_execution_failure(req_id, args, state, user_id).await)
        }
        "acknowledge_execution_failure" => {
            Some(handle_acknowledge_execution_failure(req_id, args, state, user_id).await)
        }
        "cancel_queued_executions" => {
            Some(handle_cancel_queued_executions(req_id, args, state, user_id).await)
        }
        "get_execution_lineage" => {
            Some(handle_get_execution_lineage(req_id, args, state, user_id).await)
        }
        "get_node_io" => Some(handle_get_node_io(req_id, args, state, user_id).await),
        "list_pending_approvals" => {
            Some(handle_list_pending_approvals(req_id, args, state, user_id).await)
        }
        "submit_workflow_approval" => {
            Some(handle_submit_workflow_approval(req_id, args, state, user_id).await)
        }
        _ => None,
    }
}

/// Build a HashMap from node UUID → node id string (label) using the graph_json.
/// The engine stores SHA256-derived UUIDs in execution_events.node_id.
/// This helper reproduces the same derivation so events can show human-readable names.
fn build_node_label_map(
    graph_str: Option<String>,
) -> std::collections::HashMap<uuid::Uuid, String> {
    let mut map = std::collections::HashMap::new();
    if let Some(gj) = graph_str {
        if let Ok(graph) = serde_json::from_str::<serde_json::Value>(&gj) {
            if let Some(nodes) = graph.get("nodes").and_then(|n| n.as_array()) {
                for node in nodes {
                    if let Some(rf_id) = node.get("id").and_then(|v| v.as_str()) {
                        let node_uuid = uuid::Uuid::parse_str(rf_id).unwrap_or_else(|_| {
                            use sha2::{Digest, Sha256};
                            let hash = Sha256::digest(rf_id.as_bytes());
                            let mut bytes = [0u8; 16];
                            bytes.copy_from_slice(&hash[..16]);
                            uuid::Uuid::from_bytes(bytes)
                        });
                        map.insert(node_uuid, rf_id.to_string());
                    }
                }
            }
        }
    }
    map
}

/// Same as build_node_label_map but also extracts the display label from
/// node.data.label. Canonical home is the failure-analysis service crate
/// (moved with the handle_analyze_execution_failure extraction); re-imported
/// here for the two execution-trace call sites below.
use talos_failure_analysis_service::build_node_display_label_map;

async fn handle_get_execution_status(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let exec_id = match crate::utils::require_uuid(args, "execution_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // MCP-252 (2026-05-10): pre-fix `detail: "false"` (string) silently
    // returned the heavy detail trace. Operators using detail=false as
    // a "lightweight polling loop" path got the full trace + bandwidth
    // they were trying to avoid. Wrong-type rejection makes the typo
    // visible. Same family as MCP-251.
    let detail = match crate::utils::validate_optional_bool(args, "detail", true, &req_id) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if detail {
        return match build_execution_trace_json(exec_id, user_id, state).await {
            Ok(trace) => mcp_text(req_id, &trace),
            Err(msg) => mcp_error(req_id, -32000, &msg),
        };
    }

    let exec = match state.execution_repo.get_execution(exec_id, user_id).await {
        Ok(Some(e)) => e,
        Ok(None) => return mcp_error(req_id, -32000, "Execution not found or access denied"),
        Err(e) => {
            tracing::error!(execution_id = %exec_id, "get_execution_status query failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to query execution");
        }
    };

    // MCP-91 (2026-05-07): the description sells `detail=false` as a
    // "lightweight polling loop" path, but pre-fix this branch dumped the
    // full output_data (truncated at 4 KiB) on every call — every poll
    // paid that bandwidth. The summary now drops output_data entirely:
    // emit only execution_id, status, started_at, completed_at,
    // duration_ms (when both timestamps exist), error_message, and the
    // tier-2 exposure flag. Callers needing the output should call
    // get_execution_output (linked in the response so polling code can
    // discover the next step). Pinned/note are kept since they're tiny
    // metadata; node_timings + output_data go behind detail=true.
    let duration_ms = match (exec.started_at, exec.completed_at) {
        (Some(s), Some(c)) => Some((c - s).num_milliseconds()),
        _ => None,
    };
    let tier2_exposed = exec
        .output_data
        .as_ref()
        .and_then(|out| out.get("__secret_tier2_exposed__"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let has_output = exec.output_data.is_some();

    let mut summary = serde_json::json!({
        "execution_id": exec_id.to_string(),
        "status": exec.status,
        "started_at": exec.started_at.map(|t| t.to_rfc3339()),
        "completed_at": exec.completed_at.map(|t| t.to_rfc3339()),
        "duration_ms": duration_ms,
        "has_output": has_output,
    });
    if let Some(map) = summary.as_object_mut() {
        if exec.is_pinned {
            map.insert("is_pinned".to_string(), serde_json::Value::Bool(true));
            if let Some(ref note) = exec.pin_note {
                map.insert(
                    "pin_note".to_string(),
                    serde_json::Value::String(note.clone()),
                );
            }
        }
        if let Some(ref err) = exec.error_message {
            map.insert(
                "error_message".to_string(),
                serde_json::Value::String(err.clone()),
            );
        }
        if tier2_exposed {
            // Same Tier-2 plaintext-crossed-WASM warning as the legacy
            // text path; preserved as a structured field so polling
            // dashboards can flag it cleanly.
            map.insert(
                "secret_tier2_exposed".to_string(),
                serde_json::Value::Bool(true),
            );
            map.insert(
                "secret_tier2_warning".to_string(),
                serde_json::Value::String(
                    "Module called expose-secret() — plaintext crossed the WASM boundary. \
                     Prefer hmac-sign / fetch-with-bearer (Tier 1) to keep keys host-side."
                        .to_string(),
                ),
            );
        }
        if has_output {
            map.insert(
                "output_hint".to_string(),
                serde_json::Value::String(format!(
                    "Output omitted in summary mode. Call get_execution_output(execution_id: \"{}\") for full payload, or get_execution_status(execution_id: \"{}\", detail: true) for a per-node trace.",
                    exec_id, exec_id
                )),
            );
        }
    }
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&summary).unwrap_or_default(),
    )
}

async fn handle_list_executions(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // Validate the workflow exists *for this user*. Using a cross-user existence check
    // would let a caller distinguish "wrong UUID" from "another user's workflow" via the
    // error message, leaking existence. user-scoped check makes both states return the
    // same response.
    if !state.workflow_repo.workflow_exists(wf_id, user_id).await {
        return mcp_error(req_id, -32000, "Workflow not found or access denied");
    }

    let limit = match crate::utils::validate_range_i64(args, "limit", 1, 200, 60, &req_id) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    // MCP-209 (2026-05-08): pre-fix `args.get("offset").and_then(|v|
    // v.as_i64())` returned None for both "absent" AND "wrong type"
    // (e.g. `offset: "10"`, `offset: 5.7`), silently falling through
    // to 0 — same MCP-187 wrong-type confusion. There was also no
    // upper bound, so `offset: 999999999999` would generate a slow
    // table scan. Use `validate_range_i64` for upfront wrong-type
    // rejection and an explicit cap of 1_000_000 (well past any
    // realistic pagination need given the 200-row LIMIT).
    let offset = match crate::utils::validate_range_i64(args, "offset", 0, 1_000_000, 0, &req_id) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let rows = match state
        .execution_repo
        .list_executions(wf_id, user_id, limit, offset)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(workflow_id = %wf_id, "list_executions query failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to list executions");
        }
    };

    // Parallel count for the pagination envelope. `has_more` lets callers
    // page without a second "did I get everything?" round-trip.
    let total = state
        .execution_repo
        .count_executions(wf_id, user_id)
        .await
        .unwrap_or(rows.len() as i64);

    let executions: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            // Duration is derivable from the two timestamps when both are
            // present — cheaper for callers than computing client-side, and
            // the typical use case is "how long did each run take?".
            let duration_ms: Option<i64> = match (r.started_at, r.completed_at) {
                (Some(s), Some(c)) => Some((c - s).num_milliseconds().max(0)),
                _ => None,
            };
            // MCP-31: emit `execution_id` as the canonical name; keep
            // `id` as a legacy alias so existing callers continue to
            // resolve. Sibling tools (get_execution_status,
            // get_execution_lineage, get_workflow_audit_trail) all use
            // `execution_id` and operators chaining list_executions →
            // get_execution_status no longer need to remap.
            let mut obj = serde_json::json!({
                "execution_id": r.id,
                "id": r.id,
                "workflow_id": r.workflow_id,
                "status": r.status,
                "started_at": r.started_at.map(|t| t.to_rfc3339()),
            });
            if let Some(map) = obj.as_object_mut() {
                if let Some(ref c) = r.completed_at {
                    map.insert(
                        "completed_at".to_string(),
                        serde_json::json!(c.to_rfc3339()),
                    );
                }
                if let Some(ref e) = r.error_message {
                    map.insert("error_message".to_string(), serde_json::json!(e));
                }
                if let Some(d) = duration_ms {
                    map.insert("duration_ms".to_string(), serde_json::json!(d));
                }
                if r.is_pinned {
                    map.insert("is_pinned".to_string(), serde_json::json!(true));
                    if let Some(ref n) = r.pin_note {
                        map.insert("pin_note".to_string(), serde_json::json!(n));
                    }
                }
            }
            obj
        })
        .collect();

    // Envelope shape mirrors `list_workflows` for consistency. Callers that
    // previously parsed a bare array can read `.executions`; the extra
    // `total` / `has_more` fields help them page without re-querying.
    //
    // MCP-103 (2026-05-08): emit canonical `count` alongside legacy
    // `total` so envelope tooling that keys on `count` reads this
    // surface uniformly.
    let has_more = offset + (executions.len() as i64) < total;
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "executions": executions,
            "count": executions.len(),
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": has_more,
        }))
        .unwrap_or_default(),
    )
}

async fn handle_list_recent_executions(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let limit = match crate::utils::validate_range_i64(args, "limit", 1, 100, 20, &req_id) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let status_filter: Option<String> = args
        .get("status")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    // MCP-145 (2026-05-08): reject unknown status filters instead of
    // passing them through and returning an empty list. Status values
    // come from the workflow_executions.status enum.
    if let Some(ref s) = status_filter {
        // MCP-820 (2026-05-14): added `waiting` and `timed_out` to the
        // accepted filter set. Pre-fix the filter rejected both even
        // though they're legitimate stored values:
        //   - `waiting`: written by
        //     `talos-execution-repository::pause_execution_with_output`
        //     at lib.rs:1131 when an execution suspends at an approval
        //     gate. Operators querying "what's blocked on approval?"
        //     had no way to surface them via this list filter.
        //   - `timed_out`: returned by
        //     `talos_execution_orchestration::ExecutionStatus::TimedOut.as_str()`
        //     and parsed in trigger.rs:624. Marks dispatches that
        //     exceeded the per-execution timeout.
        // `suspended` is retained for backwards compat with operators
        // who may script against it, but it's a dead value at the
        // execution layer (suspension is `waiting`; `suspended` is
        // actor-level state). Same drift-class as MCP-815/816/817/819
        // — error-message allowlist not aligned with the actual
        // accepted/stored set.
        if !matches!(
            s.as_str(),
            "queued"
                | "running"
                | "completed"
                | "failed"
                | "cancelled"
                | "waiting"
                | "timed_out"
                | "suspended"
        ) {
            // MCP-1030: cap reflected status at 64 chars.
            let preview = talos_text_util::bounded_preview(s.as_str(), 64);
            return mcp_error(
                req_id,
                -32602,
                &format!(
                    "Invalid status filter '{preview}'. Valid values: queued, running, completed, failed, cancelled, waiting, timed_out",
                ),
            );
        }
    }

    let rows = match state
        .execution_repo
        .list_recent_executions(user_id, limit, status_filter.as_deref())
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("list_recent_executions query failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to list executions");
        }
    };

    let executions: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            // MCP-53 (2026-05-07): emit `execution_id` as the canonical
            // name; keep `id` as a legacy alias so existing callers
            // continue to resolve. Sibling tools (get_execution_status /
            // get_execution_lineage / list_executions) all use
            // execution_id.
            let mut obj = serde_json::json!({
                "execution_id": r.id,
                "id": r.id,
                "status": r.status,
                "workflow_name": r.workflow_name,
                "started_at": r.started_at.map(|t| t.to_rfc3339()),
                "priority": r.priority,
            });
            if let Some(ref c) = r.completed_at {
                if let Some(map) = obj.as_object_mut() {
                    map.insert(
                        "completed_at".to_string(),
                        serde_json::json!(c.to_rfc3339()),
                    );
                }
            }
            if let Some(ref e) = r.error_message {
                if let Some(map) = obj.as_object_mut() {
                    map.insert("error_message".to_string(), serde_json::json!(e));
                }
            }
            obj
        })
        .collect();
    // MCP-45 (2026-05-07): structured envelope (count + items).
    let envelope = serde_json::json!({
        "count": executions.len(),
        "executions": executions,
    });
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&envelope).unwrap_or_default(),
    )
}

async fn handle_replay_execution(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let original_execution_id =
        match crate::utils::require_uuid(args, "execution_id", req_id.clone()) {
            Ok(id) => id,
            Err(resp) => return resp,
        };
    match state
        .execution_orchestration_service
        .replay(talos_execution_orchestration::ReplayInput {
            original_execution_id,
            user_id,
            replay_agent_id: None,
        })
        .await
    {
        Ok(outcome) => mcp_text(
            req_id,
            &format!(
                "Replaying execution {} as new execution {}.\nWorkflow: {}\nStatus: running\n\nUse get_execution_status to check results.",
                original_execution_id, outcome.execution_id, outcome.metadata.workflow_id
            ),
        ),
        Err(err) => crate::utils::orchestration_error_to_response(err, req_id),
    }
}

async fn handle_cancel_execution(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let exec_id = match crate::utils::require_uuid(args, "execution_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    match state
        .execution_repo
        .mark_execution_cancelled(exec_id, user_id)
        .await
    {
        Ok(true) => mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "execution_id": exec_id.to_string(),
                "status": "cancelled",
                "message": "Execution cancelled successfully"
            }))
            .unwrap_or_default(),
        ),
        Ok(false) => {
            // rows_affected = 0: either the ID doesn't exist or already in terminal state.
            // Do a follow-up read so we can give an actionable message.
            match state.execution_repo.get_execution(exec_id, user_id).await {
                // MCP-57 (2026-05-07): align error wording with the
                // canonical "current status: X" phrasing used by the
                // orchestration service (see retry_execution / replay_*
                // via OrchestrationError::StatusConflict). Pre-fix the
                // cancel path used "already in terminal state" while
                // sibling action tools used "current status" — same
                // class of error, two different operator-facing strings.
                Ok(Some(exec)) => mcp_error(
                    req_id,
                    -32000,
                    &format!(
                        "Cannot cancel execution: current status '{}'. \
                         Only executions with status 'running', 'queued', or 'pending' can be cancelled.",
                        exec.status
                    ),
                ),
                Ok(None) => {
                    mcp_error(req_id, -32000, "Execution not found or access denied")
                }
                Err(e) => {
                    tracing::error!(execution_id = %exec_id, "cancel_execution post-check fetch failed: {}", e);
                    mcp_error(req_id, -32000, "Execution not found or access denied")
                }
            }
        }
        Err(e) => {
            tracing::error!("cancel_execution failed: {}", e);
            mcp_error(req_id, -32000, "Failed to cancel execution")
        }
    }
}

async fn handle_cleanup_stale_executions(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // MCP-182 (2026-05-08): replace the silent max-clamp with
    // explicit range validation. Pre-fix the min check (>=5) was
    // loud but the max was silent — `older_than_minutes=99999`
    // became 1440 with no warning. The resulting SQL ran with the
    // wrong window, indistinguishable to the caller from "no
    // executions cleaned up". Range [5, 1440] keeps the existing
    // 24h ceiling but rejects out-of-range loudly.
    let older_than_minutes =
        match crate::utils::validate_range_i64(args, "older_than_minutes", 5, 1440, 60, &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };

    match state
        .execution_repo
        .cleanup_stale_executions(older_than_minutes, user_id)
        .await
    {
        Ok(count) => {
            // MCP-400 (2026-05-11): audit-erasure protection. This
            // path HARD-DELETEs rows from workflow_executions —
            // unlike archive_executions which preserves them in an
            // archive table. Pre-fix an attacker who wanted to erase
            // a specific suspicious execution could call
            // cleanup_stale_executions with a tight time window
            // covering the target row's timestamp, and the row would
            // be permanently gone with no trace anywhere.
            // admin_event_log is append-only — once the cleanup is
            // recorded here, the deletion itself becomes
            // un-deniable even if the underlying rows are gone. This
            // is the strictest audit-gap-closure of the session
            // because it specifically prevents the use of the
            // platform's own tools to launder its audit trail.
            if count > 0 {
                crate::actor::spawn_log_admin_event(
                    state.db_pool.clone(),
                    user_id,
                    "executions_stale_cleanup",
                    "execution",
                    None,
                    format!(
                        "{} stale execution(s) hard-deleted (older than {} minutes)",
                        count, older_than_minutes
                    ),
                    Some(serde_json::json!({
                        "deleted_count": count,
                        "older_than_minutes": older_than_minutes,
                    })),
                );
            }
            mcp_text(
                req_id,
                &format!(
                    "Cleaned up {} stale execution(s) older than {} minutes.",
                    count, older_than_minutes
                ),
            )
        }
        Err(e) => {
            tracing::error!("cleanup_stale_executions failed: {}", e);
            mcp_error(req_id, -32000, "Failed to clean up stale executions")
        }
    }
}

async fn handle_get_execution_logs(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let exec_id = match crate::utils::require_uuid(args, "execution_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // Verify the execution belongs to this user and get workflow_id for label resolution
    let exec = match state.execution_repo.get_execution(exec_id, user_id).await {
        Ok(Some(e)) => e,
        Ok(None) => return mcp_error(req_id, -32000, "Execution not found or access denied"),
        Err(e) => {
            tracing::error!(execution_id = %exec_id, "get_execution_logs: load failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to load execution");
        }
    };
    let workflow_id = exec.workflow_id;

    // Build UUID → label mapping from graph_json for readable node names
    let node_label_map = build_node_label_map(
        state
            .execution_repo
            .get_workflow_graph_for_user(workflow_id, user_id)
            .await
            .ok()
            .flatten(),
    );

    let events = match state.execution_repo.list_execution_events(exec_id).await {
        Ok(e) => e,
        Err(e) => {
            tracing::error!("get_execution_logs query failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to fetch execution logs");
        }
    };

    // Return `[]` for empty rather than a bare prose message — matches the
    // populated branch's array shape so callers can `.length === 0` instead
    // of having to type-test the response. (Prose lived here as a UX
    // convenience but breaks programmatic consumers.)

    let event_list: Vec<serde_json::Value> = events
        .iter()
        .map(|ev| {
            let mut obj = serde_json::json!({ "event_type": ev.event_type });
            let map = match obj.as_object_mut() {
                Some(m) => m,
                None => return obj, // Should never happen with json!({})
            };
            if let Some(nid) = ev.node_id {
                let label = node_label_map
                    .get(&nid)
                    .cloned()
                    .unwrap_or_else(|| nid.to_string());
                map.insert("node_id".to_string(), serde_json::json!(label));
            }
            if let Some(ref s) = ev.status {
                map.insert("status".to_string(), serde_json::json!(s));
            }
            if let Some(ref m) = ev.log_message {
                // MCP-41: redact actor_context memory values so this
                // surface doesn't leak what list_actor_memories
                // deliberately hides. The structure (memory keys,
                // count, types) is preserved so debugging stays
                // useful; only the value bodies are blanked.
                let redacted = redact_actor_context_in_log(m);
                map.insert("log_message".to_string(), serde_json::json!(redacted));
            }
            // Machine-readable failure class from the engine v0.2 — see
            // handle_watch_execution for the same surfacing.
            if let Some(ref ec) = ev.error_class {
                map.insert("error_class".to_string(), serde_json::json!(ec));
            }
            map.insert(
                "created_at".to_string(),
                serde_json::json!(ev.created_at.to_rfc3339()),
            );
            obj
        })
        .collect();

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&event_list).unwrap_or_default(),
    )
}

/// MCP-41: redact actor_context memory values inside an execution
/// log_message before it leaves the controller.
///
/// `node_input` events are written by the engine as JSON-stringified
/// node configs that may contain a fully-resolved `__actor_context__`
/// payload (see `talos_memory::actor_context::assemble_payload`). The
/// payload includes every memory's plaintext value — the same data
/// that `list_actor_memories` deliberately omits (only metadata).
/// Without this redaction, `get_execution_logs` was a clean bypass
/// for any caller who knew an execution_id.
///
/// Strategy:
///   1. Try to parse the log_message as JSON. If parsing fails, return
///      the message unchanged (it's not a structured payload, so it
///      can't carry an actor_context).
///   2. Walk the parsed value with `redact_in_place`, replacing the
///      `value` field of every entry under `__actor_context__.memories`
///      with the string `"[REDACTED]"`. Memory key, type, expires_at
///      etc. stay visible so debugging still works.
///   3. Re-serialize. On serialize failure (shouldn't happen — we only
///      mutate value fields), return the original.
///
/// Pure function so the redaction is unit-testable without DB or NATS.
pub(crate) fn redact_actor_context_in_log(log_message: &str) -> String {
    let Ok(mut parsed) = serde_json::from_str::<serde_json::Value>(log_message) else {
        // MCP-94 (2026-05-07): the truncated_preview fallback path of
        // get_node_io passes raw mid-truncated JSON in. JSON-parse fails,
        // and pre-fix this function returned the input unchanged — so
        // __actor_context__ memory content leaked verbatim. When the
        // string is unparseable but contains the actor_context marker,
        // fall through to a substring-level scrub that elides the
        // memory `value` fields. Same fail-closed posture as the parsed
        // path: privacy is the invariant; partial preview is sacrificed.
        return scrub_actor_context_in_raw_string(log_message);
    };
    let redacted = redact_actor_context_in_place(&mut parsed);
    if !redacted {
        return log_message.to_string();
    }
    serde_json::to_string(&parsed).unwrap_or_else(|_| log_message.to_string())
}

/// MCP-94: substring-level scrub for the unparseable-JSON case. If the
/// string contains the `"__actor_context__"` marker, return a sanitized
/// placeholder rather than risking a leak via raw passthrough. Operators
/// losing the preview content is the right trade against an actor_context
/// memory `value` field reaching the wire. JSON-parseable inputs go
/// through the structured path above and are unaffected.
fn scrub_actor_context_in_raw_string(s: &str) -> String {
    if s.contains("\"__actor_context__\"") {
        // Preserve the front of the payload (config keys, model, etc.)
        // up to the marker; replace the rest with a sentinel so a caller
        // can still see what kind of node-input this was without seeing
        // injected memory content.
        if let Some(idx) = s.find("\"__actor_context__\"") {
            let mut out = String::with_capacity(idx + 64);
            out.push_str(&s[..idx]);
            out.push_str(
                "\"__actor_context__\":\"[REDACTED — truncated payload contained actor memory; full content suppressed for privacy]\"",
            );
            return out;
        }
    }
    s.to_string()
}

/// Recursively walk a JSON value looking for `__actor_context__.memories[*]`
/// and blank each entry's `value` field. Returns true iff at least one
/// redaction fired (so the caller can skip re-serialisation cost when
/// nothing changed). Operates in-place on `&mut Value`.
fn redact_actor_context_in_place(v: &mut serde_json::Value) -> bool {
    let mut redacted = false;
    if let Some(map) = v.as_object_mut() {
        if let Some(ctx) = map.get_mut("__actor_context__") {
            if let Some(memories) = ctx.get_mut("memories").and_then(|m| m.as_array_mut()) {
                for mem in memories.iter_mut() {
                    if let Some(mem_map) = mem.as_object_mut() {
                        if mem_map.contains_key("value") {
                            mem_map.insert(
                                "value".to_string(),
                                serde_json::Value::String("[REDACTED]".to_string()),
                            );
                            redacted = true;
                        }
                    }
                }
            }
        }
        // Walk other fields too — actor_context can nest under any
        // node-config key in node_input events.
        for (_, child) in map.iter_mut() {
            if redact_actor_context_in_place(child) {
                redacted = true;
            }
        }
    } else if let Some(arr) = v.as_array_mut() {
        for child in arr.iter_mut() {
            if redact_actor_context_in_place(child) {
                redacted = true;
            }
        }
    }
    redacted
}

// ── tail_worker_logs ────────────────────────────────────────────────────────
//
// Returns ascending-time-ordered log lines from `workflow_execution_logs`,
// the table the wasm-log subscriber writes worker stdout/structured-log
// output into for workflow-execution IDs. Different from get_execution_logs
// (engine event timeline). Authorized via workflow ownership.

async fn handle_tail_worker_logs(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let exec_id = match crate::utils::require_uuid(args, "execution_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    // MCP-387 (2026-05-11): strict-parse so a wrong-type `node_id`
    // doesn't silently drop the filter and return ALL log lines for
    // the execution. Pre-fix `optional_uuid` collapsed wrong-type /
    // invalid-UUID into None — operator's typed-wrong filter became
    // "no filter", returning a far larger log payload than they asked
    // for (potentially hitting the response cap and getting their
    // logs truncated). Same MCP-386 family applied to a log-tailing
    // surface where the silent drop quietly inflates the response.
    let node_id: Option<Uuid> =
        match crate::utils::parse_optional_uuid_strict(args, "node_id", &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    // MCP-356 (2026-05-11): pre-fix `as_str().map(uppercase).filter(allowlist).unwrap_or("INFO")`
    // collapsed BOTH wrong-type AND invalid-string into "INFO". Operator
    // passing `min_level: 4` (number — common confusion since some tools
    // use numeric levels) or `min_level: "DEBUUG"` (typo) silently got
    // INFO-level filtering, hiding the DEBUG entries they were hunting.
    // Direction-class on a diagnostic surface. Open-coded because the
    // allowlist is case-insensitive (we accept "debug" / "DEBUG" both),
    // which the case-sensitive `validate_optional_string` helper
    // doesn't support.
    let min_level: String = match args.get("min_level") {
        None | Some(serde_json::Value::Null) => "INFO".to_string(),
        Some(v) => match v.as_str() {
            Some(s) => {
                let upper = s.to_uppercase();
                match upper.as_str() {
                    "DEBUG" | "INFO" | "WARN" | "ERROR" => upper,
                    _ => {
                        return mcp_error(
                            req_id,
                            -32602,
                            &format!(
                                "min_level must be one of [DEBUG, INFO, WARN, ERROR] (case-insensitive), got '{}'",
                                talos_text_util::bounded_preview(s, 64)
                            ),
                        )
                    }
                }
            }
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("min_level must be a string, got {kind}"),
                );
            }
        },
    };
    // MCP-248 (2026-05-08): pre-fix `since: "not-a-timestamp"` silently
    // parsed-as-None and returned the unfiltered event list. Same
    // silent-drop class as MCP-224 (get_actor_action_log).
    //
    // MCP-356 (2026-05-11): the MCP-248 fix caught the invalid-string
    // case but the inner `.and_then(|v| v.as_str())` still silently
    // collapsed wrong-type (`since: 42` number) into None — operator's
    // typed-wrong timestamp silently returned the full unfiltered event
    // list. Pull the outer args.get() out so the wrong-type branch can
    // reject loudly.
    let since: Option<chrono::DateTime<chrono::Utc>> = match args.get("since") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => match v.as_str() {
            Some(s) => match chrono::DateTime::parse_from_rfc3339(s) {
                Ok(dt) => Some(dt.with_timezone(&chrono::Utc)),
                Err(_) => {
                    return mcp_error(
                        req_id,
                        -32602,
                        "since must be an RFC 3339 timestamp (e.g. '2026-05-08T00:00:00Z')",
                    )
                }
            },
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("since must be an RFC 3339 timestamp string, got {kind}"),
                );
            }
        },
    };
    let limit: i64 = match crate::utils::validate_range_i64(args, "limit", 1, 5000, 500, &req_id) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // Authorization: workflow_execution must be owned by this user.
    // Both branches (no row, or owned by another user) collapse to the same
    // canonical message — distinguishing them would leak existence across users.
    // The hint about standalone module runs is generic, so it's safe to surface
    // for unauthorised callers too.
    match state
        .execution_repo
        .get_workflow_execution_owner(exec_id)
        .await
    {
        Ok(Some(owner)) if owner == user_id => {}
        Ok(_) => {
            return mcp_error(
                req_id,
                -32000,
                "Execution not found or access denied. tail_worker_logs only supports \
                 workflow executions; for standalone module runs use get_execution_logs.",
            );
        }
        Err(e) => {
            tracing::error!(execution_id = %exec_id, "tail_worker_logs ownership check failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to verify execution ownership");
        }
    }

    let rows = match state
        .execution_repo
        .tail_workflow_logs(exec_id, node_id, Some(&min_level), since, limit)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(execution_id = %exec_id, "tail_workflow_logs query failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to fetch worker logs");
        }
    };

    // 2026-05-28 review (low): apply the same __actor_context__ redaction the
    // sibling readers (get_execution_logs, get_node_io) use — blank the
    // plaintext `value` fields of any injected actor-memory so this read
    // surface honours the MCP-41 privacy invariant uniformly. The write-path
    // DLP only strips token-shaped secrets, not arbitrary actor-memory content,
    // so a module that logs its own input would otherwise leak it here in the
    // clear while every other read path redacts the identical bytes.
    let entries: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            let mut obj = serde_json::json!({
                "ts": r.created_at.to_rfc3339(),
                "level": r.level,
                "message": redact_actor_context_in_log(&r.message),
            });
            if let Some(nid) = r.node_id {
                if let Some(m) = obj.as_object_mut() {
                    m.insert("node_id".to_string(), serde_json::json!(nid));
                }
            }
            if let Some(ref md) = r.metadata {
                if let Some(m) = obj.as_object_mut() {
                    let mut md = md.clone();
                    redact_actor_context_in_place(&mut md);
                    m.insert("metadata".to_string(), md);
                }
            }
            obj
        })
        .collect();

    let returned = entries.len();
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "execution_id": exec_id,
            "filter": {
                "min_level": min_level,
                "node_id": node_id,
                "since": since.map(|dt| dt.to_rfc3339()),
                "limit": limit,
            },
            "entries": entries,
            "returned": returned,
            "truncated": returned as i64 == limit,
            "tip": if returned == 0 {
                "No worker logs captured. Either the execution emitted no log_event/tracing calls, or it pre-dates the workflow_execution_logs migration."
            } else {
                "Use since=<last entry's ts> to tail incrementally. Use min_level=ERROR to focus on failures."
            },
        }))
        .unwrap_or_default(),
    )
}

async fn handle_get_node_output(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let exec_id = match crate::utils::require_uuid(args, "execution_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    // MCP-226 (2026-05-08): trim node_id at the boundary.
    let node_id = match args.get("node_id").and_then(|v| v.as_str()) {
        Some(id) if !id.trim().is_empty() => id.trim(),
        _ => return mcp_error(req_id, -32602, "Missing or empty node_id"),
    };

    let exec = match state.execution_repo.get_execution(exec_id, user_id).await {
        Ok(Some(e)) => e,
        Ok(None) => return mcp_error(req_id, -32000, "Execution not found or access denied"),
        Err(e) => {
            tracing::error!("get_node_output query failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to fetch execution output");
        }
    };

    let data = match exec.output_data {
        Some(d) => d,
        None => return mcp_error(req_id, -32000, "Execution has no output data yet"),
    };

    // MCP-109 (2026-05-08): apply the same UUID-resolution path that
    // `get_node_io` uses (`compute_node_uuid_from_rf_id`). The engine
    // emits output_data keyed by `node_id` UUID — either the rf_id
    // verbatim if it parses as a UUID, or `sha256(rf_id)[:16]` if it
    // doesn't. Pre-fix this handler only checked the raw input string,
    // so passing a label like "synthesize" hit the unhelpful fallback
    // listing synthetic UUIDs. Now: try the input as-is, then try the
    // SHA-256-derived UUID, then walk the workflow graph to resolve
    // `data.label` -> rf_id, then walk nested `nodes`/`results` shapes.
    let try_keys = [
        // 1. Input as-is (handles UUID input AND label-as-key when the
        //    output uses labels — see test_workflow's collapsed shape).
        node_id.to_string(),
        // 2. SHA-256-derived UUID for the rf_id case.
        compute_node_uuid_from_rf_id(node_id).to_string(),
    ];
    for key in &try_keys {
        if let Some(node_output) = data.get(key) {
            return mcp_text(
                req_id,
                &serde_json::to_string_pretty(node_output).unwrap_or_default(),
            );
        }
        if let Some(nodes_obj) = data.get("nodes").or_else(|| data.get("results")) {
            if let Some(node_output) = nodes_obj.get(key) {
                return mcp_text(
                    req_id,
                    &serde_json::to_string_pretty(node_output).unwrap_or_default(),
                );
            }
        }
    }

    // 3. Fall back to graph-driven resolution: find a node whose
    //    `data.label` matches the input, then look up that node's id /
    //    sha256-derived UUID. Same path as
    //    `resolve_rf_id_from_label` in get_node_execution_history.
    if let Some((rf_id, _)) =
        resolve_rf_id_from_label(state, exec.workflow_id, user_id, node_id).await
    {
        let alt_uuid = compute_node_uuid_from_rf_id(&rf_id).to_string();
        for key in [&rf_id, &alt_uuid] {
            if let Some(node_output) = data.get(key) {
                return mcp_text(
                    req_id,
                    &serde_json::to_string_pretty(node_output).unwrap_or_default(),
                );
            }
        }
    }

    // 4. Not found — render a label-resolved key list so the operator
    //    sees friendly names instead of synthetic UUIDs. Pre-fix this
    //    listed `03823045-...` and `6fb0ab0f-...` (sha256-derived)
    //    which forced the operator to cross-reference get_workflow_graph.
    let label_map = build_node_label_map(
        state
            .execution_repo
            .get_workflow_graph_for_user(exec.workflow_id, user_id)
            .await
            .ok()
            .flatten(),
    );
    let labeled_keys: Vec<String> = data
        .as_object()
        .map(|o| {
            o.keys()
                .filter(|k| k.as_str() != "__node_timings__")
                .map(|k| {
                    uuid::Uuid::parse_str(k)
                        .ok()
                        .and_then(|u| label_map.get(&u).cloned())
                        .unwrap_or_else(|| k.clone())
                })
                .collect()
        })
        .unwrap_or_default();
    mcp_error(
        req_id,
        -32000,
        &format!(
            "Node '{}' not found in execution output. Resolved node labels available: [{}]. \
             Note: this surface accepts the rf_id (the 'id' column from get_workflow_graph) \
             OR the data.label set in the editor — both resolve to the same output entry.",
            node_id,
            labeled_keys.join(", "),
        ),
    )
}

/// Default per-value cap used by compare_executions and get_execution_diff
/// when embedding `value_a` / `value_b` inline. Beyond this, the value is
/// replaced with a `{__truncated, original_byte_size, preview, tip}` envelope
/// to keep MCP-transport response payloads under the client request-timeout.
const DEFAULT_INLINE_VALUE_CAP_BYTES: usize = 8 * 1024;
const MAX_INLINE_VALUE_CAP_BYTES: usize = 64 * 1024;

/// Read `max_bytes_per_value` from `args`. MCP-10: convert silent clamp
/// to N-J explicit -32602 — out-of-range values now fail fast rather
/// than silently coercing to the boundary.
fn parse_inline_value_cap(args: &Value, req_id: &Option<Value>) -> Result<usize, JsonRpcResponse> {
    let v = crate::utils::validate_range_u64(
        args,
        "max_bytes_per_value",
        1024,
        MAX_INLINE_VALUE_CAP_BYTES as u64,
        DEFAULT_INLINE_VALUE_CAP_BYTES as u64,
        req_id,
    )?;
    Ok(v as usize)
}

/// If `v` serializes to ≤ `max_bytes`, returns it unchanged. Otherwise
/// returns a small JSON envelope describing the size and showing a head
/// preview. Used so massive node outputs (LLM bodies, scraped HTML) don't
/// inflate compare/diff responses past the MCP-client request timeout.
fn cap_value_for_inline_response(v: &Value, max_bytes: usize) -> (Value, bool) {
    let serialized = serde_json::to_string(v).unwrap_or_default();
    if serialized.len() <= max_bytes {
        return (v.clone(), false);
    }
    // MCP-1047 (2026-05-15): byte-aware preview. Pre-fix `preview_len`
    // was computed as a byte target (`max_bytes / 4`) but used as a
    // codepoint count via `.chars().take(preview_len)` — for multi-byte
    // serialised JSON (CJK strings, emoji, escaped Unicode) the resulting
    // preview could be up to 4× the intended byte cap, defeating the
    // "small inline preview" intent of this function. Same byte-vs-chars
    // class as MCP-1046 (wit_logging) and MCP-478/1012/1018 (audit-log
    // persistence-boundary truncate-then-redact).
    let preview_len = (max_bytes / 4).max(512).min(serialized.len());
    let preview = talos_text_util::truncate_at_char_boundary(&serialized, preview_len).to_string();
    (
        serde_json::json!({
            "__truncated": true,
            "original_byte_size": serialized.len(),
            "preview": preview,
            "tip": "Output too large to embed inline. Use focus_node / node_id to narrow the diff, raise max_bytes_per_value (max 65536), or fetch the full value via get_node_io.",
        }),
        true,
    )
}

async fn handle_compare_executions(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let exec_id_a = match crate::utils::require_uuid(args, "execution_id_a", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let exec_id_b = match crate::utils::require_uuid(args, "execution_id_b", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let inline_cap = match parse_inline_value_cap(args, &req_id) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // Single round-trip via batch fetch — replaces two sequential `get_execution`
    // calls (each of which used to await the same DEK fetch separately).
    let mut rows = match state
        .execution_repo
        .get_executions_by_ids(&[exec_id_a, exec_id_b], user_id)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("compare_executions batch fetch failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to load executions");
        }
    };

    // get_executions_by_ids returns rows in DB-default order, not input
    // order — re-bind by id so exec_a / exec_b stay deterministic.
    let exec_a = rows
        .iter()
        .position(|r| r.id == exec_id_a)
        .map(|i| rows.swap_remove(i));
    let exec_b = rows
        .iter()
        .position(|r| r.id == exec_id_b)
        .map(|i| rows.swap_remove(i));
    let (exec_a, exec_b) = match (exec_a, exec_b) {
        (Some(a), Some(b)) => (a, b),
        _ => {
            return mcp_error(
                req_id,
                -32000,
                "One or both executions not found or access denied",
            )
        }
    };

    let duration_a = match (exec_a.started_at, exec_a.completed_at) {
        (Some(s), Some(c)) => Some((c - s).num_milliseconds()),
        _ => None,
    };
    let duration_b = match (exec_b.started_at, exec_b.completed_at) {
        (Some(s), Some(c)) => Some((c - s).num_milliseconds()),
        _ => None,
    };

    // Compare per-node outputs
    let output_a = exec_a
        .output_data
        .as_ref()
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let output_b = exec_b
        .output_data
        .as_ref()
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();

    let all_keys: std::collections::BTreeSet<&String> =
        output_a.keys().chain(output_b.keys()).collect();

    // Build a UUID → graph-id label map so the diff is operator-readable.
    // Only resolve when both executions are from the same workflow; cross-workflow
    // diffs would need TWO maps and the comparison rarely makes sense anyway.
    // Same pattern as get_node_io / get_node_failure_breakdown / get_node_execution_history.
    let label_map = if exec_a.workflow_id == exec_b.workflow_id {
        let graph = state
            .workflow_repo
            .get_workflow_graph(exec_a.workflow_id, user_id)
            .await
            .ok()
            .flatten();
        build_node_label_map(graph)
    } else {
        std::collections::HashMap::new()
    };

    let mut truncated_count: usize = 0;
    let mut node_diffs: Vec<serde_json::Value> = Vec::new();
    for key in &all_keys {
        let val_a = output_a.get(*key);
        let val_b = output_b.get(*key);
        let cmp_status = match (val_a, val_b) {
            (Some(a), Some(b)) if a == b => "identical",
            (Some(_), Some(_)) => "different",
            (Some(_), None) => "only_in_a",
            (None, Some(_)) => "only_in_b",
            (None, None) => "missing",
        };
        let (capped_a, t_a) = match val_a {
            Some(v) => {
                let (capped, t) = cap_value_for_inline_response(v, inline_cap);
                (Some(capped), t)
            }
            None => (None, false),
        };
        let (capped_b, t_b) = match val_b {
            Some(v) => {
                let (capped, t) = cap_value_for_inline_response(v, inline_cap);
                (Some(capped), t)
            }
            None => (None, false),
        };
        if t_a {
            truncated_count += 1;
        }
        if t_b {
            truncated_count += 1;
        }
        let node_label = uuid::Uuid::parse_str(key.as_str())
            .ok()
            .and_then(|u| label_map.get(&u).cloned());

        // MCP-18: skip synthetic engine-internal trace placeholders. They have
        // per-execution UUIDs that don't resolve to a graph node label, AND
        // their values are empty objects on both sides (no diff signal). Their
        // presence is pure noise after the label resolver lights up the real
        // nodes. Only suppress when the UUID is unresolvable AND the only
        // signal would be "{} != null" or "null != {}" — that's how
        // engine-emitted placeholders manifest. A real node with empty output
        // would still resolve to a label and pass the filter.
        let is_synthetic_placeholder = node_label.is_none()
            && match (val_a, val_b) {
                (Some(serde_json::Value::Object(a)), None) => a.is_empty(),
                (None, Some(serde_json::Value::Object(b))) => b.is_empty(),
                (Some(serde_json::Value::Object(a)), Some(serde_json::Value::Object(b))) => {
                    a.is_empty() && b.is_empty()
                }
                _ => false,
            };
        if is_synthetic_placeholder {
            continue;
        }

        // MCP-96 (2026-05-07): drop the raw `node` (synthetic UUID) field
        // when `node_label` resolved cleanly — operators reading this
        // surface don't need both. Same MCP-22/25 family ("synthetic
        // UUID hidden when label is available"). The synthetic UUID is
        // kept ONLY when label resolution failed (legacy fallback path).
        //
        // MCP-115 (2026-05-08): only emit `synthetic_node_id` when the
        // key is UUID-shaped AND the label_map lookup missed. Non-UUID
        // keys (already-friendly rf_ids) are themselves the readable
        // label — tagging them synthetic was misleading.
        let label_string = node_label.clone().unwrap_or_else(|| key.to_string());
        let mut entry = serde_json::json!({
            "node_label": label_string,
            "comparison": cmp_status,
            "value_a": capped_a,
            "value_b": capped_b,
        });
        if node_label.is_none() && uuid::Uuid::parse_str(key).is_ok() {
            if let Some(map) = entry.as_object_mut() {
                map.insert(
                    "synthetic_node_id".to_string(),
                    serde_json::Value::String(key.to_string()),
                );
            }
        }
        node_diffs.push(entry);
    }

    let response = serde_json::json!({
        "execution_a": {
            "id": exec_id_a,
            "status": exec_a.status,
            "duration_ms": duration_a,
            "workflow_id": exec_a.workflow_id,
        },
        "execution_b": {
            "id": exec_id_b,
            "status": exec_b.status,
            "duration_ms": duration_b,
            "workflow_id": exec_b.workflow_id,
        },
        "same_workflow": exec_a.workflow_id == exec_b.workflow_id,
        "count": node_diffs.len(),
        "node_comparisons": node_diffs,
        "inline_value_cap_bytes": inline_cap,
        "truncated_value_count": truncated_count,
    });
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&response).unwrap_or_default(),
    )
}

async fn handle_get_execution_timeline(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let exec_id = match crate::utils::require_uuid(args, "execution_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // Load execution record
    let exec = match state.execution_repo.get_execution(exec_id, user_id).await {
        Ok(Some(e)) => e,
        Ok(None) => return mcp_error(req_id, -32000, "Execution not found or access denied"),
        Err(e) => {
            tracing::error!(execution_id = %exec_id, "get_execution_timeline: load failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to load execution");
        }
    };
    let status = exec.status.clone();
    let started_at = exec.started_at;
    let completed_at = exec.completed_at;
    let error_message = exec.error_message.clone();
    let output_data = exec.output_data.clone();
    let workflow_id = exec.workflow_id;

    // Build UUID → label mapping from graph_json
    let node_label_map = build_node_label_map(
        state
            .execution_repo
            .get_workflow_graph_for_user(workflow_id, user_id)
            .await
            .ok()
            .flatten(),
    );

    // Load events
    let event_rows = state
        .execution_repo
        .list_execution_events(exec_id)
        .await
        .unwrap_or_default();

    // Build timeline text
    let mut timeline = String::new();
    let _ = writeln!(timeline, "=== Execution Timeline: {} ===", exec_id);
    let _ = writeln!(timeline, "Status: {}", status);
    if let Some(ref sa) = started_at {
        let _ = writeln!(timeline, "Started: {}", sa.to_rfc3339());
    }
    if let Some(ref ca) = completed_at {
        let _ = writeln!(timeline, "Completed: {}", ca.to_rfc3339());
        if let Some(ref sa) = started_at {
            let duration = (*ca - *sa).num_milliseconds();
            let _ = writeln!(timeline, "Total Duration: {}ms", duration);
        }
    }
    if let Some(ref err) = error_message {
        let _ = writeln!(timeline, "Error: {}", err);
    }
    timeline.push_str("\n--- Event Sequence ---\n");

    for (i, ev) in event_rows.iter().enumerate() {
        let node_label = ev
            .node_id
            .and_then(|nid| node_label_map.get(&nid).cloned())
            .unwrap_or_else(|| {
                ev.node_id
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "(workflow)".to_string())
            });

        let _ = write!(
            timeline,
            "  [{}] {} | {} | {}",
            i + 1,
            ev.created_at.to_rfc3339(),
            ev.event_type,
            node_label
        );
        if let Some(ref s) = ev.status {
            let _ = write!(timeline, " | {}", s);
        }
        if let Some(ref msg) = ev.log_message {
            // MCP-89 (2026-05-07): apply MCP-41 redaction before truncation
            // so __actor_context__ payloads don't leak through this surface.
            // Same helper used by get_execution_logs / get_node_io.
            let redacted = redact_actor_context_in_log(msg);
            let truncated = if redacted.len() > 200 {
                format!(
                    "{}...",
                    talos_text_util::truncate_at_char_boundary(&redacted, 200)
                )
            } else {
                redacted
            };
            let _ = write!(timeline, " | {}", truncated);
        }
        timeline.push('\n');
    }

    // Node timings from output_data
    if let Some(ref out) = output_data {
        if let Some(timings) = out.get("__node_timings__") {
            timeline.push_str("\n--- Per-Node Timings ---\n");
            if let Some(obj) = timings.as_object() {
                for (node, timing) in obj {
                    let _ = writeln!(timeline, "  {}: {}", node, timing);
                }
            } else {
                let _ = writeln!(
                    timeline,
                    "  {}",
                    serde_json::to_string_pretty(timings).unwrap_or_default()
                );
            }
        }

        // Expand sub-workflow node outputs: show child node names
        if let Some(obj) = out.as_object() {
            // Standard template output keys — if a node's output contains these,
            // it is a regular module result, not a sub-workflow envelope.
            const STANDARD_OUTPUT_KEYS: &[&str] = &[
                "success",
                "rows",
                "error",
                "status",
                "result",
                "data",
                "message",
                "body",
                "response",
                "output",
                "ok",
                "count",
                "url",
                "headers",
                "status_code",
            ];

            for (node_key, node_val) in obj {
                if node_key.starts_with("__") {
                    continue;
                }
                // Detect sub-workflow outputs: they are objects with nested node results
                if let Some(sub_obj) = node_val.as_object() {
                    // Skip expansion for outputs that have standard template keys
                    let has_standard_keys = sub_obj
                        .keys()
                        .any(|k| STANDARD_OUTPUT_KEYS.contains(&k.as_str()));
                    if has_standard_keys {
                        continue;
                    }

                    // Heuristic: if the value is an object containing keys that look like
                    // node outputs (with their own objects/strings), and there are no
                    // simple scalar top-level values, this is likely a sub-workflow output
                    let has_child_timings = sub_obj.contains_key("__node_timings__");
                    // Sub-workflow outputs have ALL non-__ values as objects (node results).
                    // Regular outputs have at least one scalar/array value.
                    let non_meta_values: Vec<_> = sub_obj
                        .iter()
                        .filter(|(k, _)| !k.starts_with("__"))
                        .collect();
                    let all_values_are_objects = !non_meta_values.is_empty()
                        && non_meta_values.iter().all(|(_, v)| v.is_object());
                    if has_child_timings || (all_values_are_objects && non_meta_values.len() >= 2) {
                        let _ = write!(timeline, "\n--- Sub-workflow: {} ---\n", node_key);
                        for (child_node, child_output) in sub_obj {
                            if child_node.starts_with("__") {
                                continue;
                            }
                            let output_preview =
                                serde_json::to_string(child_output).unwrap_or_default();
                            let truncated = if output_preview.len() > 200 {
                                format!(
                                    "{}...",
                                    talos_text_util::truncate_at_char_boundary(
                                        &output_preview,
                                        200
                                    )
                                )
                            } else {
                                output_preview
                            };
                            let _ = writeln!(timeline, "  [{}]: {}", child_node, truncated);
                        }
                        if let Some(child_timings) = sub_obj.get("__node_timings__") {
                            timeline.push_str("  Child Timings:\n");
                            if let Some(ct_obj) = child_timings.as_object() {
                                for (cn, ct) in ct_obj {
                                    let _ = writeln!(timeline, "    {}: {}", cn, ct);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    mcp_text(req_id, &timeline)
}

async fn handle_pin_execution(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let exec_id = match crate::utils::require_uuid(args, "execution_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    // MCP-264 (2026-05-10): reject whitespace-only pin notes — they
    // surface in pinned-execution listings and pollute the operator's
    // audit trail without conveying anything. Same MCP-186 family;
    // mirrors resolve_approval_gate.note (advanced.rs:3670) and the
    // actor consolidation notes (actor.rs:5108 / 5259).
    //
    // MCP-374 (2026-05-11): pre-fix passed the UNTRIMMED note through
    // to `pin_execution`. Pinned-execution listings rendered notes
    // with surrounding padding, and the post-success format!() echoed
    // the padding back at the operator. Trim post-check; re-validate
    // length on the trimmed value.
    let note: Option<&str> = match args.get("note").and_then(|v| v.as_str()) {
        None => None,
        Some(n) if n.trim().is_empty() => {
            return mcp_error(
                req_id,
                -32602,
                "Pin note must be non-empty and non-whitespace when provided. Omit the field to leave it blank.",
            );
        }
        Some(n) if n.trim().len() > 500 => {
            return mcp_error(req_id, -32602, "Pin note must be 500 characters or fewer");
        }
        Some(n) => Some(n.trim()),
    };

    match state
        .execution_repo
        .pin_execution(exec_id, user_id, note)
        .await
    {
        Ok(true) => {
            // MCP-146 (2026-05-08): JSON envelope on success.
            let msg = if let Some(n) = note {
                format!("Execution {} pinned with note: {}", exec_id, n)
            } else {
                format!("Execution {} pinned.", exec_id)
            };
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "success": true,
                    "execution_id": exec_id.to_string(),
                    "note": note,
                    "message": msg,
                }))
                .unwrap_or_default(),
            )
        }
        Ok(false) => crate::utils::execution_not_found_error(req_id),
        Err(e) => {
            tracing::error!("pin_execution failed: {}", e);
            mcp_error(req_id, -32000, "Failed to pin execution")
        }
    }
}

async fn handle_unpin_execution(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let exec_id = match crate::utils::require_uuid(args, "execution_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    match state.execution_repo.unpin_execution(exec_id, user_id).await {
        // MCP-146 (2026-05-08): JSON envelope on success.
        Ok(true) => mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "execution_id": exec_id.to_string(),
                "message": format!("Execution {} unpinned.", exec_id),
            }))
            .unwrap_or_default(),
        ),
        Ok(false) => crate::utils::execution_not_found_error(req_id),
        Err(e) => {
            tracing::error!("unpin_execution failed: {}", e);
            mcp_error(req_id, -32000, "Failed to unpin execution")
        }
    }
}

async fn handle_list_pinned_executions(
    req_id: Option<serde_json::Value>,
    _args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let rows = match state.execution_repo.list_pinned_executions(user_id).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("list_pinned_executions query failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to list pinned executions");
        }
    };

    // `[]` for empty (matches the populated array shape) — see e6e0f05.

    let executions: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            let mut obj = serde_json::json!({
                "execution_id": r.id,
                "workflow_id": r.workflow_id,
                "workflow_name": r.workflow_name,
                "status": r.status,
                "started_at": r.started_at.map(|t| t.to_rfc3339()),
            });
            let map = match obj.as_object_mut() {
                Some(m) => m,
                None => return obj,
            };
            if let Some(ref ca) = r.completed_at {
                map.insert(
                    "completed_at".to_string(),
                    serde_json::json!(ca.to_rfc3339()),
                );
            }
            if let Some(ref err) = r.error_message {
                map.insert("error".to_string(), serde_json::json!(err));
            }
            if let Some(ref note) = r.pin_note {
                map.insert("pin_note".to_string(), serde_json::json!(note));
            }
            obj
        })
        .collect();

    // MCP-45 (2026-05-07): structured envelope (count + items).
    let envelope = serde_json::json!({
        "count": executions.len(),
        "executions": executions,
    });
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&envelope).unwrap_or_default(),
    )
}

async fn handle_pause_executions(
    req_id: Option<serde_json::Value>,
    _args: &Value,
    state: &McpState,
    user_id: Uuid,
    _is_admin: bool,
) -> JsonRpcResponse {
    // MCP-323 (2026-05-11): `set_execution_paused` writes to the
    // `system_settings` table — a single row that gates EVERY tenant's
    // workflow dispatch. Pre-fix the gate was the agent-level
    // `is_admin` capability, which is the per-tenant admin role. So an
    // organization-scoped admin agent in a multi-tenant SaaS could
    // flip the global execution_paused flag and DoS every other
    // tenant's workflows. Same require_platform_admin family the
    // security memory file flags. Use the `users.is_platform_admin`
    // column instead — the deployment-wide flag set on operator users
    // only (handle_grant_capability_ceiling / handle_revoke_capability_
    // ceiling already do this).
    let is_platform_admin = state
        .actor_repo
        .is_platform_admin(user_id)
        .await
        .unwrap_or(false);
    if !is_platform_admin {
        return mcp_error(
            req_id,
            -32601,
            "pause_executions requires platform-admin privileges. \
             The execution-paused flag is deployment-wide state that affects every tenant.",
        );
    }
    match state.execution_repo.set_execution_paused(true).await {
        Ok(_) => {
            // MCP-398 (2026-05-11): persistent audit on a deployment-
            // wide DoS gate. The auth gate from MCP-323 prevents
            // per-tenant admins from flipping the flag, but a
            // compromised platform-admin token could pause → exploit
            // (e.g. modify infrastructure under cover of the
            // queue-quiet window) → resume, with nothing in
            // admin_event_log to mark the cycle. The append-only
            // trigger on admin_event_log makes the pause/resume
            // round-trip permanent. resource_id is None — the
            // execution_paused flag is global, not per-resource.
            crate::actor::spawn_log_admin_event(
                state.db_pool.clone(),
                user_id,
                "executions_paused",
                "system",
                None,
                "Execution queue paused (deployment-wide)".to_string(),
                None,
            );
            mcp_text(
                req_id,
                "Execution queue paused. New workflow triggers will be rejected until resumed.",
            )
        }
        Err(e) => {
            tracing::error!("pause_executions failed: {}", e);
            mcp_error(req_id, -32000, "Failed to pause executions")
        }
    }
}

async fn handle_resume_executions(
    req_id: Option<serde_json::Value>,
    _args: &Value,
    state: &McpState,
    user_id: Uuid,
    _is_admin: bool,
) -> JsonRpcResponse {
    // MCP-323 (2026-05-11): see handle_pause_executions above for the
    // platform-admin rationale. Resuming a paused queue is the inverse
    // operation but the cross-tenant blast-radius is identical (one
    // tenant's admin re-opening execution dispatch when the platform
    // operator paused it for an incident).
    let is_platform_admin = state
        .actor_repo
        .is_platform_admin(user_id)
        .await
        .unwrap_or(false);
    if !is_platform_admin {
        return mcp_error(
            req_id,
            -32601,
            "resume_executions requires platform-admin privileges. \
             The execution-paused flag is deployment-wide state that affects every tenant.",
        );
    }
    match state.execution_repo.set_execution_paused(false).await {
        Ok(_) => {
            // MCP-398 (2026-05-11): paired audit to pause_executions
            // above. Without the resume event, an attacker who paused
            // the queue could exit cleanly with only the pause row
            // visible — operators investigating would see "paused
            // 10:00, resumed (no row)" and not know who restored
            // service. Pairing both events makes the round-trip
            // intent-reconstructable from admin_event_log alone.
            crate::actor::spawn_log_admin_event(
                state.db_pool.clone(),
                user_id,
                "executions_resumed",
                "system",
                None,
                "Execution queue resumed (deployment-wide)".to_string(),
                None,
            );
            mcp_text(
                req_id,
                "Execution queue resumed. Workflow triggers are now accepted.",
            )
        }
        Err(e) => {
            tracing::error!("resume_executions failed: {}", e);
            mcp_error(req_id, -32000, "Failed to resume executions")
        }
    }
}

async fn handle_enqueue_workflow(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // MCP-610 (2026-05-12): use the canonical `enforce_executions_not_paused`
    // helper so a DB error fails CLOSED. Pre-fix `unwrap_or(false)` silently
    // let the enqueue path through on any Postgres hiccup — meaning a
    // platform-admin "pause executions" gate could be defeated by a brief
    // DB outage. The orchestration paths (trigger.rs:159 / replay.rs:97)
    // already use `?` to propagate the error; the MCP enqueue handler was
    // the lone divergent caller. Same class as MCP-323 (cross-tenant
    // pause-flag privilege gate) — when admin gates exist, they must
    // fail closed on infrastructure faults.
    if let Err(resp) =
        crate::utils::enforce_executions_not_paused(&state.workflow_repo, req_id.clone()).await
    {
        return resp;
    }

    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let inputs = match args.get("inputs").and_then(|v| v.as_array()) {
        Some(arr) => arr.clone(),
        None => return mcp_error(req_id, -32602, "Missing or invalid 'inputs' array"),
    };

    if inputs.is_empty() {
        return mcp_error(req_id, -32602, "inputs array must not be empty");
    }
    if inputs.len() > 10_000 {
        return mcp_error(req_id, -32602, "inputs array cannot exceed 10,000 items");
    }
    for (i, item) in inputs.iter().enumerate() {
        let item_len = serde_json::to_string(item).map(|s| s.len()).unwrap_or(0);
        if item_len > 500_000 {
            return mcp_error(
                req_id,
                -32602,
                &format!("inputs[{}] exceeds 500 KB per-item limit", i),
            );
        }
    }

    let rate_per_second: f64 = if let Some(raw) = args.get("rate_per_second") {
        let f = match raw.as_f64() {
            Some(f) => f,
            None => return mcp_error(req_id, -32602, "rate_per_second must be a number"),
        };
        if f.fract() != 0.0 {
            return mcp_error(
                req_id,
                -32602,
                &format!("rate_per_second must be a whole number (1–20), got {f}"),
            );
        }
        if !(1.0..=20.0).contains(&f) {
            return mcp_error(
                req_id,
                -32602,
                &format!("rate_per_second must be between 1 and 20, got {}", f as i64),
            );
        }
        f
    } else {
        5.0 // platform default: 5 executions per second
    };

    // Validate workflow exists and belongs to user
    let wf_graph = match state
        .execution_repo
        .get_workflow_graph_for_user(wf_id, user_id)
        .await
        .unwrap_or(None)
    {
        Some(g) => g,
        None => return mcp_error(req_id, -32000, "Workflow not found or access denied"),
    };

    // Try active published version first, fall back to draft graph
    let (graph_json, version_id) = match state
        .execution_repo
        .get_active_version_graph(wf_id, user_id)
        .await
        .unwrap_or(None)
    {
        Some((vid, gj)) => (gj, Some(vid)),
        None => (wf_graph, None),
    };

    let nats = match &state.nats_client {
        Some(nc) => nc.clone(),
        None => return mcp_error(req_id, -32000, "NATS client not available"),
    };

    // Actor ownership + status + capability-ceiling enforcement via the
    // canonical full gate. MCP-728 (2026-05-13): upgrade from manual
    // archived/terminated/suspended + `check_execution_allowed_for_batch`
    // to `authorize_workflow_trigger` + batch-aware budget. Same drift
    // class as MCP-707 (retry/replay), MCP-708 (scheduler/chain/
    // continuation), MCP-726 (resume), MCP-727 (handoff). Without
    // ceiling enforcement, an actor whose `max_capability_world` was
    // downgraded after a workflow was authored could enqueue
    // executions of agent-node-tier workflows under their now-
    // restricted http-node ceiling — the dispatched executions would
    // ignore the downgrade and run at the workflow's authored level.
    //
    // `authorize_workflow_trigger` covers identity + ownership +
    // terminal-state + batch_size=1 budget + capability ceiling. We
    // call `check_execution_allowed_for_batch` AFTER for batch-size=N
    // budget (MCP-566) — the full gate's budget check is implicitly
    // batch_size=1 which is insufficient for bulk enqueue. Both
    // checks are intentional: ceiling + batch-aware budget.
    let enqueue_agent_id: Option<uuid::Uuid> = crate::utils::parse_optional_actor_id(args);
    if let Some(agent_id) = enqueue_agent_id {
        if let Err(e) = talos_workflow_authorization::authorize_workflow_trigger(
            &state.workflow_repo,
            &state.actor_repo,
            &state.db_pool,
            Some(agent_id),
            user_id,
            &graph_json,
        )
        .await
        {
            use talos_workflow_authorization::TriggerAuthError;
            let msg = match e {
                TriggerAuthError::ActorArchived => {
                    "Actor is archived — cannot dispatch executions. \
                     Use update_actor_status to reactivate first."
                        .to_string()
                }
                TriggerAuthError::ActorTerminated => {
                    "Actor is terminated — cannot dispatch executions. \
                     Use update_actor_status to reactivate first."
                        .to_string()
                }
                TriggerAuthError::ActorNotFoundOrInactive => {
                    "Actor not found or access denied".to_string()
                }
                TriggerAuthError::ExecutionDenied(s) => s,
                TriggerAuthError::CapabilityCeilingViolation {
                    module_id,
                    module_world,
                    max_world,
                    ..
                } => {
                    tracing::warn!(
                        actor_id = %agent_id,
                        workflow_id = %wf_id,
                        module_id = %module_id,
                        module_world = %module_world,
                        max_world = %max_world,
                        "enqueue_workflow: BLOCKED — capability ceiling violation (likely ceiling-drift since workflow authored)"
                    );
                    format!(
                        "Cannot enqueue: module {} requires capability '{}' but actor ceiling is '{}'. \
                         The actor's capability ceiling may have been downgraded since this workflow was authored.",
                        module_id, module_world, max_world
                    )
                }
                TriggerAuthError::Database(db_err) => {
                    tracing::error!(
                        actor_id = %agent_id,
                        workflow_id = %wf_id,
                        error = %db_err,
                        "enqueue_workflow: authorization DB error"
                    );
                    "Database error during authorization".to_string()
                }
            };
            return mcp_error(req_id, -32000, &msg);
        }

        // MCP-566: batch-aware budget gate. Pre-fix the per-batch check
        // used `check_execution_allowed` (batch_size=1 semantics), so an
        // actor with `max_executions_per_hour = N` could be enqueued with
        // a batch of size > N as long as the current hourly count was
        // below N. Now passes `inputs.len()` so the gate refuses any
        // batch that would push the count past the cap. Reject-whole
        // semantics — the workflow-level concurrency cap already does
        // partial admission via `create_executions_batch_under_concurrency_limit`;
        // having TWO partial-admit caps stacked would make the response
        // shape ambiguous.
        //
        // This check stacks WITH the full gate above: the full gate's
        // implicit batch_size=1 budget check passes for an actor with
        // 1 unit of remaining quota, but the batch may need N > 1.
        let batch_size = inputs.len() as i64;
        if let Err(msg) =
            crate::actor::check_execution_allowed_for_batch(&state.db_pool, agent_id, batch_size)
                .await
        {
            return mcp_error(req_id, -32000, &msg);
        }
    }

    // Create execution records upfront with 'queued' status. The
    // cap-aware admission helper enforces `max_concurrent_executions`
    // — without it, this batch silently bypassed the cap. Because
    // `'queued'` rows are counted by the cap query
    // (status IN ('running','queued','pending','resuming')), an unbounded enqueue
    // against a workflow at its limit starved every other dispatch
    // path (`trigger_workflow`, `bulk_trigger_workflow`) for the
    // duration of the drain. The helper's transaction locks the
    // workflows row, counts in-flight, and inserts only the prefix
    // that fits under the cap; suffix is reported as `throttled`.
    //
    // Single-batched INSERT also fixes a latent bug from the prior
    // per-input loop: the loop pushed exec_ids only on success but
    // the background processor indexed `inputs` and `exec_ids` by
    // the same `idx`. One per-row failure would shift exec_ids out
    // of alignment and silently drop the suffix. Batched INSERT is
    // all-or-nothing for the admitted prefix.
    let exec_ids: Vec<uuid::Uuid> = (0..inputs.len()).map(|_| uuid::Uuid::new_v4()).collect();
    let mut results = Vec::with_capacity(inputs.len());

    let admission = match state
        .workflow_repo
        .create_executions_batch_under_concurrency_limit(
            &exec_ids,
            wf_id,
            user_id,
            version_id,
            enqueue_agent_id,
        )
        .await
    {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(
                workflow_id = %wf_id,
                input_count = inputs.len(),
                "enqueue_workflow: batch admission failed: {}", e
            );
            for idx in 0..inputs.len() {
                results.push(serde_json::json!({
                    "input_index": idx,
                    "execution_id": serde_json::Value::Null,
                    "status": "error",
                    "error": "Failed to create execution records (transaction rolled back; no inputs were queued)"
                }));
            }
            return mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "queued": 0,
                    "rate_per_second": rate_per_second,
                    "executions": results,
                    "monitor_with": null
                }))
                .unwrap_or_default(),
            );
        }
    };

    let admitted = admission.inserted;
    let throttled = inputs.len() - admitted;

    for (idx, exec_id) in exec_ids.iter().take(admitted).enumerate() {
        results.push(serde_json::json!({
            "input_index": idx,
            "execution_id": exec_id.to_string(),
            "status": "queued"
        }));
    }
    let throttle_reason = match admission.limit {
        Some(limit) => format!(
            "max_concurrent_executions reached: {} in-flight (limit: {}); only {} of {} admitted",
            admission.running,
            limit,
            admitted,
            inputs.len()
        ),
        None => "throttled".to_string(),
    };
    for idx in admitted..inputs.len() {
        results.push(serde_json::json!({
            "input_index": idx,
            "execution_id": serde_json::Value::Null,
            "status": "throttled",
            "error": throttle_reason,
        }));
    }

    // Truncate inputs/exec_ids to the admitted prefix so the dispatch
    // loop only operates on rows that actually exist. Without this,
    // mark_execution_running_from_queued would no-op against missing
    // ids and the engine would still be invoked.
    let admitted_inputs: Vec<serde_json::Value> = inputs.into_iter().take(admitted).collect();
    let admitted_exec_ids: Vec<uuid::Uuid> = exec_ids.into_iter().take(admitted).collect();
    let inputs = admitted_inputs;
    let exec_ids = admitted_exec_ids;

    // Spawn background task to process at the specified rate. Capture the
    // shared SecretsManager + ActorRepository Arcs so each iteration reuses
    // one initialized instance instead of constructing+initializing per
    // execution. Cloning Arcs BEFORE the spawn (rather than borrowing
    // through `state`) is required because `tokio::spawn` needs 'static.
    let repo = state.execution_repo.clone();
    let registry = state.registry.clone();
    let secrets_manager = state.secrets_manager.clone();
    let actor_repo = state.actor_repo.clone();
    let delay_ms = (1000.0 / rate_per_second) as u64;
    let queued_count = exec_ids.len();

    tokio::spawn(async move {
        // Pair input with its execution_id structurally — pre-batch this
        // loop indexed `inputs` and `exec_ids` separately and guarded with
        // `if idx >= exec_ids.len() { break; }`, which silently truncated
        // the suffix when the per-row insert loop hit any failure. The
        // batch INSERT guarantees `exec_ids.len() == inputs.len()` at
        // this point, so `zip` enforces the invariant in the type system.
        for (idx, (input_payload, &exec_id)) in inputs.iter().zip(exec_ids.iter()).enumerate() {
            // Update status to running
            if let Err(e) = repo.mark_execution_running_from_queued(exec_id).await {
                tracing::error!(execution_id = %exec_id, "Failed to update execution status: {}", e);
            }

            // Canonical builder; TimeoutPolicy::Honor (engine reads timeout
            // from graph during load — pre-load extraction was redundant).
            let mut engine = match talos_engine::builder::for_workflow(
                registry.clone(),
                secrets_manager.clone(),
                actor_repo.clone(),
                user_id,
                talos_engine::builder::EngineOpts::for_run(wf_id, graph_json.clone()),
            )
            .await
            {
                Ok(e) => e,
                Err(e) => {
                    // MCP-450: DLP-redact engine build error before
                    // persistence. Same secret-leak class as MCP-447.
                    let redacted = talos_dlp_provider::redact_str(&e.to_string());
                    let _ = repo.mark_execution_failed(exec_id, &redacted, None).await;
                    if idx + 1 < inputs.len() {
                        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                    }
                    continue;
                }
            };

            let worker_key = crate::utils::load_worker_shared_key_logged(file!());
            match talos_engine::nats_run::run_with_trigger_input_via_nats(
                &mut engine,
                nats.clone(),
                worker_key,
                input_payload.clone(),
                exec_id,
            )
            .await
            {
                Ok(ctx) => {
                    let output_data = talos_dlp_provider::redact_json(
                        &serde_json::to_value(&ctx.results).unwrap_or(serde_json::json!({})),
                    );
                    // MCP-802 (2026-05-14): log mark_execution_completed
                    // failures. Pre-fix `let _ = ...await` discarded the
                    // Result, so a transient DB UPDATE failure (pool
                    // exhaustion, encryption error, network blip) left
                    // the execution row stuck in 'running' forever even
                    // though the engine completed successfully. Child
                    // module_executions rows orphan; downstream
                    // dependents that wait on a not-yet-terminal status
                    // block indefinitely. Same operator-visibility class
                    // as MCP-741 (continuation-trigger cleanup) and
                    // MCP-776 (scheduler failure-marking). WARN with
                    // `target: "talos_audit"` so dashboards can
                    // correlate "stuck running" reports to DB health.
                    if let Err(ue) = repo.mark_execution_completed(exec_id, &output_data).await {
                        tracing::warn!(
                            target: "talos_audit",
                            execution_id = %exec_id,
                            workflow_id = %wf_id,
                            error = %ue,
                            "enqueue_workflow: mark_execution_completed UPDATE failed — execution row may stay in 'running' state"
                        );
                    }
                }
                Err(e) => {
                    // MCP-450: DLP-redact engine run error before
                    // persistence. Mirrors the success-path
                    // redact_json above.
                    let redacted = talos_dlp_provider::redact_str(&e.to_string());
                    // MCP-802 sibling: log mark_execution_failed UPDATE
                    // failures. Higher operator stakes than the Ok arm
                    // — the engine ALREADY failed, and if the
                    // failure-marking UPDATE also fails the row sits in
                    // 'running' state masking the real failure. Same
                    // WARN+target shape as above.
                    if let Err(ue) = repo.mark_execution_failed(exec_id, &redacted, None).await {
                        tracing::warn!(
                            target: "talos_audit",
                            execution_id = %exec_id,
                            workflow_id = %wf_id,
                            primary_error = %e,
                            update_error = %ue,
                            "enqueue_workflow: mark_execution_failed UPDATE failed — execution row may mask the real engine failure as 'running'"
                        );
                    }
                }
            }

            // Rate limit
            if idx + 1 < inputs.len() {
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            }
        }
        tracing::info!(workflow_id = %wf_id, count = exec_ids.len(), "enqueue_workflow batch complete");
    });

    let response = serde_json::json!({
        "queued": queued_count,
        "throttled": throttled,
        "rate_per_second": rate_per_second,
        "executions": results,
        "monitor_with": {
            "tool": "get_queue_status",
            "args": { "workflow_id": wf_id.to_string() },
            "note": "Call get_queue_status(workflow_id) to track batch progress."
        }
    });
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&response).unwrap_or_default(),
    )
}

async fn handle_get_sub_workflow_output(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let exec_id = match crate::utils::require_uuid(args, "execution_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    // MCP-226 (2026-05-08): trim node_id at the boundary.
    let node_id = match args.get("node_id").and_then(|v| v.as_str()) {
        Some(n) if !n.trim().is_empty() => n.trim(),
        _ => return mcp_error(req_id, -32602, "Missing or empty 'node_id' parameter"),
    };

    // Load the parent execution's output_data
    let exec = match state.execution_repo.get_execution(exec_id, user_id).await {
        Ok(Some(e)) => e,
        Ok(None) => return mcp_error(req_id, -32000, "Execution not found or access denied"),
        Err(e) => {
            tracing::error!("get_sub_workflow_output: load failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to load execution");
        }
    };

    match exec.output_data {
        Some(output_data) => {
            // Sub-workflow outputs are stored under the node_id key in output_data
            if let Some(sub_output) = output_data.get(node_id) {
                let mut formatted = String::new();
                formatted.push_str(&format!(
                    "=== Sub-workflow output for node '{}' ===\n",
                    node_id
                ));

                // If the sub-output contains per-node results, expand them
                if let Some(obj) = sub_output.as_object() {
                    for (child_node, child_output) in obj {
                        if child_node.starts_with("__") {
                            continue;
                        }
                        formatted.push_str(&format!("\n  [{}]:\n", child_node));
                        let output_str =
                            serde_json::to_string_pretty(child_output).unwrap_or_default();
                        for line in output_str.lines() {
                            formatted.push_str(&format!("    {}\n", line));
                        }
                    }
                    // Show timing info if present
                    if let Some(timings) = obj.get("__node_timings__") {
                        formatted.push_str("\n  --- Child Node Timings ---\n");
                        formatted.push_str(&format!(
                            "    {}\n",
                            serde_json::to_string_pretty(timings).unwrap_or_default()
                        ));
                    }
                } else {
                    formatted
                        .push_str(&serde_json::to_string_pretty(sub_output).unwrap_or_default());
                }

                mcp_text(req_id, &formatted)
            } else {
                // List available node IDs for guidance
                let available: Vec<&str> = output_data
                    .as_object()
                    .map(|o| {
                        o.keys()
                            .map(|k| k.as_str())
                            .filter(|k| !k.starts_with("__"))
                            .collect()
                    })
                    .unwrap_or_default();
                mcp_error(
                    req_id,
                    -32000,
                    &format!(
                        "Node '{}' not found in execution output. Available nodes: {:?}",
                        node_id, available
                    ),
                )
            }
        }
        None => mcp_error(
            req_id,
            -32000,
            "Execution has no output data (may still be running)",
        ),
    }
}

async fn handle_watch_execution(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // Accept either execution_id (direct) or workflow_id (resolves to latest execution).
    let exec = if let Some(exec_id) = args
        .get("execution_id")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<uuid::Uuid>().ok())
    {
        match state.execution_repo.get_execution(exec_id, user_id).await {
            Ok(Some(e)) => e,
            Ok(None) => return mcp_error(req_id, -32000, "Execution not found or access denied"),
            Err(e) => {
                tracing::error!("watch_execution failed: {}", e);
                return mcp_error(req_id, -32000, "Failed to load execution");
            }
        }
    } else if let Some(wf_id) = args
        .get("workflow_id")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<uuid::Uuid>().ok())
    {
        match state
            .execution_repo
            .get_latest_execution_for_workflow(wf_id, user_id)
            .await
        {
            Ok(Some(e)) => e,
            Ok(None) => return mcp_error(req_id, -32000, "No executions found for this workflow"),
            Err(e) => {
                tracing::error!("watch_execution (by workflow_id) failed: {}", e);
                return mcp_error(req_id, -32000, "Failed to load latest execution");
            }
        }
    } else {
        return mcp_error(
            req_id,
            -32602,
            "Provide either 'execution_id' or 'workflow_id'",
        );
    };
    let exec_id = exec.id;
    // MCP-248 (2026-05-08): pre-fix `since: "not-a-timestamp"` silently
    // parsed-as-None and returned the unfiltered event list.
    //
    // MCP-356 (2026-05-11): MCP-248's fix caught invalid-strings but
    // wrong-type (`since: 42` number) still silently bypassed the
    // filter via the inner `.and_then(|v| v.as_str())`. Sibling fix to
    // handle_tail_worker_logs's `since` field above; same shape.
    let since: Option<chrono::DateTime<chrono::Utc>> = match args.get("since") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => match v.as_str() {
            Some(s) => match chrono::DateTime::parse_from_rfc3339(s) {
                Ok(dt) => Some(dt.with_timezone(&chrono::Utc)),
                Err(_) => {
                    return mcp_error(
                        req_id,
                        -32602,
                        "since must be an RFC 3339 timestamp (e.g. '2026-05-08T00:00:00Z')",
                    )
                }
            },
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("since must be an RFC 3339 timestamp string, got {kind}"),
                );
            }
        },
    };

    let status = exec.status.clone();
    let started_at = exec.started_at;
    let completed_at = exec.completed_at;
    let workflow_id = exec.workflow_id;
    let is_complete = status == "completed" || status == "failed" || status == "cancelled";

    let elapsed_ms = started_at
        .map(|s| {
            let end = completed_at.unwrap_or_else(chrono::Utc::now);
            (end - s).num_milliseconds().max(0) as u64
        })
        .unwrap_or(0);

    // Build UUID → label mapping and UUID → redacted config mapping from graph_json.
    let graph_json_opt = state
        .execution_repo
        .get_workflow_graph_for_user(workflow_id, user_id)
        .await
        .ok()
        .flatten();
    let node_label_map = build_node_label_map(graph_json_opt.clone());
    // Build a per-node config map for error context, with credential fields redacted.
    // Build a per-node config map for error context, with credential fields redacted.
    // Node IDs in graph JSON are arbitrary strings (React Flow IDs like "node_1") — the
    // engine derives execution_events.node_id via SHA256, so we must apply the same
    // derivation to match events to graph nodes.
    let node_config_map: std::collections::HashMap<uuid::Uuid, serde_json::Value> = {
        use sha2::{Digest, Sha256};
        graph_json_opt
            .as_deref()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
            .and_then(|g| g.get("nodes").and_then(|n| n.as_array()).cloned())
            .unwrap_or_default()
            .iter()
            .filter_map(|node| {
                let id_str = node.get("id").and_then(|v| v.as_str())?;
                // Mirror the UUID derivation used by the execution engine.
                let node_uuid = uuid::Uuid::parse_str(id_str).unwrap_or_else(|_| {
                    let hash = Sha256::digest(id_str.as_bytes());
                    let mut bytes = [0u8; 16];
                    bytes.copy_from_slice(&hash[..16]);
                    uuid::Uuid::from_bytes(bytes)
                });
                let data = node.get("data").cloned().unwrap_or(serde_json::json!({}));
                let cfg = data.get("config").cloned().unwrap_or_else(|| data.clone());
                let redacted = if let Some(obj) = cfg.as_object() {
                    let mut out = serde_json::Map::new();
                    for (k, v) in obj {
                        let klower = k.to_lowercase();
                        if klower.contains("key")
                            || klower.contains("secret")
                            || klower.contains("token")
                            || klower.contains("password")
                            || klower.contains("auth")
                            || klower.contains("credential")
                        {
                            out.insert(k.clone(), serde_json::json!("[REDACTED]"));
                        } else {
                            out.insert(k.clone(), v.clone());
                        }
                    }
                    serde_json::Value::Object(out)
                } else {
                    cfg
                };
                Some((node_uuid, redacted))
            })
            .collect()
    };

    // Load events since the given timestamp (or all events)
    let events = match since {
        Some(since_ts) => state
            .execution_repo
            .list_execution_events_since(exec_id, since_ts)
            .await
            .unwrap_or_default(),
        None => state
            .execution_repo
            .list_execution_events(exec_id)
            .await
            .unwrap_or_default(),
    };

    // First pass: count retry events per node so node_error events can show
    // "attempt 3/3 — retries exhausted" vs "attempt 1/3 — first failure".
    let mut node_retry_counts: std::collections::HashMap<uuid::Uuid, i32> =
        std::collections::HashMap::new();
    for ev in &events {
        if ev.event_type == "node_retrying" {
            if let Some(nid) = ev.node_id {
                *node_retry_counts.entry(nid).or_insert(0) += 1;
            }
        }
    }

    let event_list: Vec<serde_json::Value> = events.iter().map(|ev| {
        let mut obj = serde_json::json!({ "event_type": ev.event_type });
        let map = match obj.as_object_mut() {
            Some(m) => m,
            None => return obj, // Should never happen with json!({})
        };
        if let Some(nid) = ev.node_id {
            let label = node_label_map.get(&nid).cloned().unwrap_or_else(|| nid.to_string());
            map.insert("node_id".to_string(), serde_json::json!(label));
        }
        if let Some(ref s) = ev.status {
            map.insert("status".to_string(), serde_json::json!(s));
        }
        if let Some(ref m) = ev.log_message {
            map.insert("log_message".to_string(), serde_json::json!(m));
        }
        // Surface the engine-stamped machine-readable failure class
        // (populated on `node_failed` and `retry_skipped` events per
        // talos-workflow-engine v0.2). Lets callers correlate
        // retry_skipped → node_failed without regex-matching log_message.
        if let Some(ref ec) = ev.error_class {
            map.insert("error_class".to_string(), serde_json::json!(ec));
        }
        map.insert("created_at".to_string(), serde_json::json!(ev.created_at.to_rfc3339()));
        // For node_retrying events, surface the retry attempt number explicitly
        if ev.event_type == "node_retrying" {
            if let Some(idx) = ev.iteration_index {
                map.insert("retry_number".to_string(), serde_json::json!(idx));
            }
        }
        // For node_error events, annotate with retry context so callers know whether
        // this was a first-attempt failure or retries-exhausted — these need different fixes.
        // Also include the node's (redacted) config so callers can see misconfigured fields.
        if ev.event_type == "node_error" {
            if let Some(nid) = ev.node_id {
                let retries = node_retry_counts.get(&nid).copied().unwrap_or(0);
                let total_attempts = retries + 1;
                if retries > 0 {
                    map.insert("retries_exhausted".to_string(), serde_json::json!(true));
                    map.insert("total_attempts".to_string(), serde_json::json!(total_attempts));
                    map.insert("attempt_context".to_string(), serde_json::json!(
                        format!("attempt {}/{} — retries exhausted (transient error; check network/timeout)", total_attempts, total_attempts)
                    ));
                } else {
                    map.insert("retries_exhausted".to_string(), serde_json::json!(false));
                    map.insert("total_attempts".to_string(), serde_json::json!(1));
                    map.insert("attempt_context".to_string(), serde_json::json!(
                        "attempt 1 — first-attempt failure (immediate error; check config/code)"
                    ));
                }
                // Include redacted node config for debugging (credentials replaced with "[REDACTED]").
                if let Some(cfg) = node_config_map.get(&nid) {
                    if !cfg.as_object().map(|m| m.is_empty()).unwrap_or(true) {
                        map.insert("node_config".to_string(), cfg.clone());
                    }
                }
            }
        }
        obj
    }).collect();

    let response = serde_json::json!({
        "execution_id": exec_id.to_string(),
        "current_status": status,
        "is_complete": is_complete,
        "elapsed_ms": elapsed_ms,
        "events_count": event_list.len(),
        "events": event_list,
    });
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&response).unwrap_or_default(),
    )
}

async fn handle_retry_execution(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let execution_id = match crate::utils::require_uuid(args, "execution_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    match state
        .execution_orchestration_service
        .retry(talos_execution_orchestration::RetryInput {
            execution_id,
            user_id,
        })
        .await
    {
        Ok(_outcome) => mcp_text(
            req_id,
            &serde_json::json!({
                "execution_id": execution_id.to_string(),
                "status": "retrying",
                "message": "Execution has been reset and is re-running."
            })
            .to_string(),
        ),
        Err(err) => crate::utils::orchestration_error_to_response(err, req_id),
    }
}

async fn handle_get_execution_output(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let exec_id = match crate::utils::require_uuid(args, "execution_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let exec = match state.execution_repo.get_execution(exec_id, user_id).await {
        Ok(Some(e)) => e,
        Ok(None) => return mcp_error(req_id, -32000, "Execution not found or access denied"),
        Err(e) => {
            tracing::error!("get_execution_output: load failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to fetch execution");
        }
    };

    let Some(output) = exec.output_data else {
        return mcp_text(
            req_id,
            "Execution has no output data (may still be running).",
        );
    };

    // MCP-23 + MCP-24: build a UUID → label map from the workflow graph
    // so we can both attach human-readable labels and filter out
    // synthetic engine-internal trace nodes whose UUIDs don't appear
    // in the graph (per the same is_synthetic_placeholder logic in
    // compare_executions / get_execution_diff).
    let node_label_map = build_node_label_map(
        state
            .execution_repo
            .get_workflow_graph_for_user(exec.workflow_id, user_id)
            .await
            .ok()
            .flatten(),
    );

    let nodes_array = if let Some(map) = output.as_object() {
        let mut nodes = Vec::with_capacity(map.len());
        for (key, value) in map {
            // Engine-internal keys at top-level (e.g. `__trigger_input__`)
            // pass through with no label resolution.
            if key.starts_with("__") {
                nodes.push(serde_json::json!({
                    "node": key,
                    "node_label": null,
                    "output": value,
                }));
                continue;
            }
            // Try to resolve the key as a node UUID. If it parses AND
            // doesn't appear in the graph, treat it as a synthetic
            // placeholder (per MCP-18 logic). The empty-object check is
            // a secondary heuristic — synthetic trace nodes carry no
            // user-facing output.
            let key_uuid = key.parse::<Uuid>().ok();
            let label = key_uuid.and_then(|u| node_label_map.get(&u).cloned());
            let is_unknown_uuid = key_uuid.is_some() && label.is_none();
            let is_empty_object = value.as_object().map(|o| o.is_empty()).unwrap_or(false);
            if is_unknown_uuid && is_empty_object {
                continue;
            }
            nodes.push(serde_json::json!({
                "node": key,
                "node_label": label,
                "output": value,
            }));
        }
        nodes
    } else {
        // Non-object output_data (e.g. a top-level array or scalar).
        // Surface unchanged under a single envelope.
        vec![serde_json::json!({
            "node": null,
            "node_label": null,
            "output": output.clone(),
        })]
    };

    let body = serde_json::json!({
        "execution_id": exec_id.to_string(),
        "workflow_id": exec.workflow_id.to_string(),
        "nodes": nodes_array,
        "note": "Each entry surfaces both the per-execution node UUID (`node`) and the human-readable graph label (`node_label`, null when the node was removed from the graph or for engine-internal keys). Synthetic engine-internal trace nodes are filtered.",
    });
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&body).unwrap_or_default(),
    )
}

async fn handle_get_execution_diff(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let exec_id_a = match crate::utils::require_uuid(args, "execution_id_a", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let exec_id_b = match crate::utils::require_uuid(args, "execution_id_b", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let focus_node_id = args
        .get("node_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let inline_cap = match parse_inline_value_cap(args, &req_id) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // Single round-trip via batch fetch.
    let mut rows = match state
        .execution_repo
        .get_executions_by_ids(&[exec_id_a, exec_id_b], user_id)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("get_execution_diff batch fetch failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to load executions");
        }
    };
    let exec_a = rows
        .iter()
        .position(|r| r.id == exec_id_a)
        .map(|i| rows.swap_remove(i));
    let exec_b = rows
        .iter()
        .position(|r| r.id == exec_id_b)
        .map(|i| rows.swap_remove(i));
    let (exec_a, exec_b) = match (exec_a, exec_b) {
        (Some(a), Some(b)) => (a, b),
        _ => {
            return mcp_error(
                req_id,
                -32000,
                "One or both executions not found or access denied",
            )
        }
    };

    let output_a = exec_a
        .output_data
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();
    let output_b = exec_b
        .output_data
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();

    // Collect all node keys (optionally filtered)
    let all_keys: std::collections::BTreeSet<String> = if let Some(ref nid) = focus_node_id {
        let mut s = std::collections::BTreeSet::new();
        s.insert(nid.clone());
        s
    } else {
        output_a.keys().chain(output_b.keys()).cloned().collect()
    };

    // Filter out internal keys
    let all_keys: std::collections::BTreeSet<String> = all_keys
        .into_iter()
        .filter(|k| !k.starts_with("__"))
        .collect();

    // Same label-resolver pattern as compare_executions — make the diff
    // operator-readable instead of forcing a manual UUID→label lookup.
    let label_map = if exec_a.workflow_id == exec_b.workflow_id {
        let graph = state
            .workflow_repo
            .get_workflow_graph(exec_a.workflow_id, user_id)
            .await
            .ok()
            .flatten();
        build_node_label_map(graph)
    } else {
        std::collections::HashMap::new()
    };
    let resolve_label = |key: &str| -> Option<String> {
        uuid::Uuid::parse_str(key)
            .ok()
            .and_then(|u| label_map.get(&u).cloned())
    };

    // MCP-112 (2026-05-08): build a node-row entry with the same shape
    // MCP-96 introduced for compare_executions — drop the synthetic
    // `node` UUID when the label resolves cleanly, expose it as
    // `synthetic_node_id` only when label resolution falls back to the
    // raw key. Operators don't need both identifiers when one resolves.
    //
    // MCP-115 (2026-05-08): only emit `synthetic_node_id` when the key
    // is UUID-shaped AND the label_map lookup missed. Non-UUID keys
    // (already-friendly rf_ids like "compute-context") are themselves
    // the operator-readable label — tagging them as synthetic was
    // misleading.
    let make_diff_entry =
        |key: &str, extra: serde_json::Map<String, serde_json::Value>| -> serde_json::Value {
            let label = resolve_label(key);
            let label_string = label.clone().unwrap_or_else(|| key.to_string());
            let mut obj = serde_json::Map::new();
            obj.insert(
                "node_label".to_string(),
                serde_json::Value::String(label_string),
            );
            if label.is_none() && uuid::Uuid::parse_str(key).is_ok() {
                obj.insert(
                    "synthetic_node_id".to_string(),
                    serde_json::Value::String(key.to_string()),
                );
            }
            for (k, v) in extra {
                obj.insert(k, v);
            }
            serde_json::Value::Object(obj)
        };

    // MCP-18: same synthetic-placeholder filter as compare_executions.
    // Skip rows whose UUID doesn't resolve AND whose values are empty
    // objects — those are engine-internal trace placeholders, not real nodes.
    let is_synthetic_placeholder =
        |key: &str, va: Option<&serde_json::Value>, vb: Option<&serde_json::Value>| -> bool {
            if resolve_label(key).is_some() {
                return false;
            }
            match (va, vb) {
                (Some(serde_json::Value::Object(a)), None) => a.is_empty(),
                (None, Some(serde_json::Value::Object(b))) => b.is_empty(),
                (Some(serde_json::Value::Object(a)), Some(serde_json::Value::Object(b))) => {
                    a.is_empty() && b.is_empty()
                }
                _ => false,
            }
        };

    let mut node_diffs: Vec<serde_json::Value> = Vec::new();
    let mut truncated_count: usize = 0;
    for key in &all_keys {
        let val_a = output_a.get(key);
        let val_b = output_b.get(key);

        if is_synthetic_placeholder(key, val_a, val_b) {
            continue;
        }

        match (val_a, val_b) {
            (None, None) => continue,
            (Some(va), None) => {
                let (capped, t) = cap_value_for_inline_response(va, inline_cap);
                if t {
                    truncated_count += 1;
                }
                let mut extra = serde_json::Map::new();
                extra.insert(
                    "status".to_string(),
                    serde_json::Value::String("only_in_a".to_string()),
                );
                extra.insert("value_a".to_string(), capped);
                node_diffs.push(make_diff_entry(key, extra));
            }
            (None, Some(vb)) => {
                let (capped, t) = cap_value_for_inline_response(vb, inline_cap);
                if t {
                    truncated_count += 1;
                }
                let mut extra = serde_json::Map::new();
                extra.insert(
                    "status".to_string(),
                    serde_json::Value::String("only_in_b".to_string()),
                );
                extra.insert("value_b".to_string(), capped);
                node_diffs.push(make_diff_entry(key, extra));
            }
            (Some(a), Some(b)) if a == b => {
                let mut extra = serde_json::Map::new();
                extra.insert(
                    "status".to_string(),
                    serde_json::Value::String("identical".to_string()),
                );
                node_diffs.push(make_diff_entry(key, extra));
            }
            (Some(a), Some(b)) => {
                // Compute field-level diff for this node
                let obj_a = a.as_object();
                let obj_b = b.as_object();

                if let (Some(fields_a), Some(fields_b)) = (obj_a, obj_b) {
                    let all_fields: std::collections::BTreeSet<&String> =
                        fields_a.keys().chain(fields_b.keys()).collect();
                    let mut field_diffs: Vec<serde_json::Value> = Vec::new();

                    for field in all_fields {
                        let fa = fields_a.get(field);
                        let fb = fields_b.get(field);
                        match (fa, fb) {
                            (Some(va), Some(vb)) if va == vb => {} // identical field, skip
                            (Some(va), Some(vb)) => {
                                let (capped_a, t_a) = cap_value_for_inline_response(va, inline_cap);
                                let (capped_b, t_b) = cap_value_for_inline_response(vb, inline_cap);
                                if t_a {
                                    truncated_count += 1;
                                }
                                if t_b {
                                    truncated_count += 1;
                                }
                                field_diffs.push(serde_json::json!({
                                    "field": field,
                                    "change": "modified",
                                    "value_a": capped_a,
                                    "value_b": capped_b,
                                }));
                            }
                            (Some(va), None) => {
                                let (capped, t) = cap_value_for_inline_response(va, inline_cap);
                                if t {
                                    truncated_count += 1;
                                }
                                field_diffs.push(serde_json::json!({
                                    "field": field,
                                    "change": "removed",
                                    "value_a": capped,
                                }));
                            }
                            (None, Some(vb)) => {
                                let (capped, t) = cap_value_for_inline_response(vb, inline_cap);
                                if t {
                                    truncated_count += 1;
                                }
                                field_diffs.push(serde_json::json!({
                                    "field": field,
                                    "change": "added",
                                    "value_b": capped,
                                }));
                            }
                            (None, None) => {}
                        }
                    }

                    let mut extra = serde_json::Map::new();
                    extra.insert(
                        "status".to_string(),
                        serde_json::Value::String("different".to_string()),
                    );
                    extra.insert(
                        "field_diffs".to_string(),
                        serde_json::Value::Array(field_diffs),
                    );
                    node_diffs.push(make_diff_entry(key, extra));
                } else {
                    // Not both objects — show whole value diff
                    let (capped_a, t_a) = cap_value_for_inline_response(a, inline_cap);
                    let (capped_b, t_b) = cap_value_for_inline_response(b, inline_cap);
                    if t_a {
                        truncated_count += 1;
                    }
                    if t_b {
                        truncated_count += 1;
                    }
                    let mut extra = serde_json::Map::new();
                    extra.insert(
                        "status".to_string(),
                        serde_json::Value::String("different".to_string()),
                    );
                    extra.insert("value_a".to_string(), capped_a);
                    extra.insert("value_b".to_string(), capped_b);
                    node_diffs.push(make_diff_entry(key, extra));
                }
            }
        }
    }

    // MCP-112 (2026-05-08): canonical `count` envelope alongside node_diffs
    // for parity with sister surfaces.
    let response = serde_json::json!({
        "execution_a": exec_id_a.to_string(),
        "execution_b": exec_id_b.to_string(),
        "focus_node": focus_node_id,
        "count": node_diffs.len(),
        "node_diffs": node_diffs,
        "inline_value_cap_bytes": inline_cap,
        "truncated_value_count": truncated_count,
    });
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&response).unwrap_or_default(),
    )
}

async fn handle_get_execution_delta(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let n: i64 = match crate::utils::validate_range_i64(args, "n", 2, 10, 5, &req_id) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    // MCP-225 (2026-05-08): trim node_label filter so whitespace-only
    // values fall through to "no filter" instead of matching nothing
    // and silently producing a delta where every node-diff is empty.
    // A real probe with `node_label: "   "` returned 4 deltas with
    // nodes_changed: 0 and nodes_identical: 0 (filter matched no node;
    // every diff was vacuous). Same family as MCP-221 / MCP-222 / MCP-223.
    let focus_node = args
        .get("node_label")
        .or_else(|| args.get("node_id")) // legacy alias
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let executions = match state
        .execution_repo
        .list_executions_with_output(wf_id, user_id, n)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!("get_execution_delta db error: {:?}", e);
            return mcp_error(req_id, -32000, "Failed to fetch executions");
        }
    };

    if executions.len() < 2 {
        let response = serde_json::json!({
            "workflow_id": wf_id.to_string(),
            "execution_count": executions.len(),
            "deltas": [],
            "note": "At least 2 completed/failed executions are required to compute a delta."
        });
        return mcp_text(
            req_id,
            &serde_json::to_string_pretty(&response).unwrap_or_default(),
        );
    }

    // executions are newest-first; reverse so index 0 = oldest in the window
    let mut sorted = executions;
    sorted.reverse();

    // Build per-pair deltas
    let mut deltas: Vec<serde_json::Value> = Vec::new();

    for window in sorted.windows(2) {
        let a = &window[0];
        let b = &window[1];

        let out_a = a
            .output_data
            .as_ref()
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        let out_b = b
            .output_data
            .as_ref()
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();

        // Collect node keys (optionally filtered, always skip __ internals)
        let all_keys: std::collections::BTreeSet<String> = if let Some(ref nid) = focus_node {
            let mut s = std::collections::BTreeSet::new();
            s.insert(nid.clone());
            s
        } else {
            out_a
                .keys()
                .chain(out_b.keys())
                .filter(|k| !k.starts_with("__"))
                .cloned()
                .collect()
        };

        let mut node_diffs: Vec<serde_json::Value> = Vec::new();
        let mut identical_count: usize = 0;
        let mut changed_count: usize = 0;

        for key in &all_keys {
            let va = out_a.get(key);
            let vb = out_b.get(key);

            match (va, vb) {
                (Some(a_val), Some(b_val)) if a_val == b_val => {
                    identical_count += 1;
                    // Only emit identical entries when focus_node is set (to give full context)
                    if focus_node.is_some() {
                        node_diffs.push(serde_json::json!({ "node": key, "status": "identical" }));
                    }
                }
                (Some(a_val), Some(b_val)) => {
                    changed_count += 1;
                    // Field-level diff if both sides are objects
                    if let (Some(fa), Some(fb)) = (a_val.as_object(), b_val.as_object()) {
                        let all_fields: std::collections::BTreeSet<&String> =
                            fa.keys().chain(fb.keys()).collect();
                        let mut field_diffs: Vec<serde_json::Value> = Vec::new();
                        for field in all_fields {
                            match (fa.get(field), fb.get(field)) {
                                (Some(fva), Some(fvb)) if fva == fvb => {}
                                (Some(fva), Some(fvb)) => {
                                    field_diffs.push(serde_json::json!({ "field": field, "change": "modified", "from": fva, "to": fvb }));
                                }
                                (Some(fva), None) => {
                                    field_diffs.push(serde_json::json!({ "field": field, "change": "removed", "from": fva }));
                                }
                                (None, Some(fvb)) => {
                                    field_diffs.push(serde_json::json!({ "field": field, "change": "added", "to": fvb }));
                                }
                                (None, None) => {}
                            }
                        }
                        node_diffs.push(serde_json::json!({ "node": key, "status": "changed", "field_diffs": field_diffs }));
                    } else {
                        node_diffs.push(serde_json::json!({ "node": key, "status": "changed", "from": a_val, "to": b_val }));
                    }
                }
                (None, Some(b_val)) => {
                    changed_count += 1;
                    node_diffs.push(
                        serde_json::json!({ "node": key, "status": "added_in_b", "value": b_val }),
                    );
                }
                (Some(a_val), None) => {
                    changed_count += 1;
                    node_diffs.push(serde_json::json!({ "node": key, "status": "removed_in_b", "value": a_val }));
                }
                (None, None) => {}
            }
        }

        let dur_a = a
            .started_at
            .zip(a.completed_at)
            .map(|(s, c)| (c - s).num_milliseconds());
        let dur_b = b
            .started_at
            .zip(b.completed_at)
            .map(|(s, c)| (c - s).num_milliseconds());

        deltas.push(serde_json::json!({
            "from_execution": {
                "id": a.id.to_string(),
                "status": a.status,
                "started_at": a.started_at.map(|t| t.to_rfc3339()),
                "duration_ms": dur_a,
            },
            "to_execution": {
                "id": b.id.to_string(),
                "status": b.status,
                "started_at": b.started_at.map(|t| t.to_rfc3339()),
                "duration_ms": dur_b,
            },
            "nodes_changed": changed_count,
            "nodes_identical": identical_count,
            "node_diffs": node_diffs,
        }));
    }

    // Overall stability: fraction of consecutive pairs with zero changes
    let stable_pairs = deltas
        .iter()
        .filter(|d| d["nodes_changed"].as_u64().unwrap_or(1) == 0)
        .count();
    let stability_pct = (stable_pairs * 100) / (sorted.len() - 1).max(1);
    let stability_label = match stability_pct {
        90..=100 => "stable",
        60..=89 => "mostly_stable",
        30..=59 => "intermittent",
        _ => "volatile",
    };

    let response = serde_json::json!({
        "workflow_id": wf_id.to_string(),
        "focus_node": focus_node,
        "executions_compared": sorted.len(),
        "stability": stability_label,
        "stable_pairs_pct": stability_pct,
        "deltas": deltas,
    });
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&response).unwrap_or_default(),
    )
}

async fn handle_get_node_execution_history(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    // MCP-170 (2026-05-08): pre-check workflow ownership. Pre-fix the
    // handler ran the user-scoped node-history SQL directly, so a
    // cross-tenant / unknown workflow_id produced a synthetic
    // {count: 0, events: []} envelope — silent-not-found. The
    // node_label resolution path also queries the workflow graph, so
    // failing fast here saves an extra SQL round-trip on the miss path.
    if !state.workflow_repo.workflow_exists(wf_id, user_id).await {
        return crate::utils::workflow_not_found_error(req_id);
    }
    // MCP-170 (2026-05-08): reject whitespace-only node_label. Pre-fix
    // `!s.is_empty()` accepted "                " — the handler then
    // computed SHA-256 over the whitespace, missed in the events
    // table, fell through to module-name resolution, missed there too,
    // and returned an empty-but-successful envelope. Same family as
    // MCP-161/163.
    let node_id_str = match args
        .get("node_label")
        .or_else(|| args.get("node_id")) // legacy alias
        .and_then(|v| v.as_str())
    {
        Some(s) if !s.trim().is_empty() => s,
        _ => return mcp_error(req_id, -32602, "Missing or empty node_label"),
    };
    let limit: i64 = match crate::utils::validate_range_i64(args, "limit", 1, 100, 20, &req_id) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // Engine emits `node_id = SHA256(rf_id)[:16]` into `execution_events` (or
    // the rf_id verbatim when it's already a UUID). To stay friendly to
    // callers who don't know the rf_id by heart, we accept three input
    // forms and resolve in this order:
    //   1. SHA-256 of the input string (works if caller passes the rf_id).
    //   2. Resolved rf_id when the input matches a node's module display
    //      name in the workflow graph (e.g. "LLM Inference" → "synthesize").
    //   3. Resolved rf_id when the input matches `data.label` on a node.
    let direct_uuid = compute_node_uuid_from_rf_id(node_id_str);
    let mut resolution = "rf_id_or_uuid";

    let mut rows = match state
        .execution_repo
        .list_node_execution_history(wf_id, user_id, direct_uuid, limit)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("get_node_execution_history query failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to query node execution history");
        }
    };

    let mut resolved_rf_id: Option<String> = None;
    if rows.is_empty() {
        if let Some((rf_id, kind)) =
            resolve_rf_id_from_label(state, wf_id, user_id, node_id_str).await
        {
            let alt_uuid = compute_node_uuid_from_rf_id(&rf_id);
            if alt_uuid != direct_uuid {
                match state
                    .execution_repo
                    .list_node_execution_history(wf_id, user_id, alt_uuid, limit)
                    .await
                {
                    Ok(r) if !r.is_empty() => {
                        rows = r;
                        resolution = kind;
                        resolved_rf_id = Some(rf_id);
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::error!("get_node_execution_history retry query failed: {}", e);
                    }
                }
            }
        }
    }

    // MCP-90 (2026-05-07): apply MCP-41 redaction + length cap to log_message.
    // Pre-fix, node_input events leaked __actor_context__ payloads, and a
    // 20-event default limit could yield 30KB+ responses (full system prompts
    // per node_input event). Truncate at ~500 chars on a char boundary and
    // surface log_message_truncated to flag the cap.
    const NODE_HISTORY_LOG_CAP: usize = 500;
    let events: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            let (log_value, was_truncated) = match r.log_message.as_deref() {
                Some(msg) => {
                    let redacted = redact_actor_context_in_log(msg);
                    if redacted.chars().count() > NODE_HISTORY_LOG_CAP {
                        let cut = talos_text_util::truncate_at_char_boundary(
                            &redacted,
                            NODE_HISTORY_LOG_CAP,
                        );
                        (serde_json::Value::String(format!("{}...", cut)), true)
                    } else {
                        (serde_json::Value::String(redacted), false)
                    }
                }
                None => (serde_json::Value::Null, false),
            };
            let mut entry = serde_json::json!({
                "execution_id": r.execution_id,
                "event_type": r.event_type,
                "status": r.status,
                "log_message": log_value,
                "created_at": r.created_at.to_rfc3339(),
                "execution_started_at": r.execution_started_at.map(|t| t.to_rfc3339()),
            });
            if was_truncated {
                if let Some(map) = entry.as_object_mut() {
                    map.insert(
                        "log_message_truncated".to_string(),
                        serde_json::Value::Bool(true),
                    );
                }
            }
            entry
        })
        .collect();

    let mut result = serde_json::json!({
        "node_id": node_id_str,
        "workflow_id": wf_id,
        "count": events.len(),
        "event_count": events.len(),
        "events": events,
        "resolved_via": resolution,
    });
    if let Some(rf) = resolved_rf_id {
        result["resolved_rf_id"] = serde_json::Value::String(rf);
    }
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

/// Engine encoding of `node_id` in `execution_events`: SHA-256 of the
/// rf_id's first 16 bytes, OR the rf_id verbatim when it parses as a
/// UUID. Mirrors `talos_workflow_engine::engine::build_graph_from_json`.
fn compute_node_uuid_from_rf_id(rf_id: &str) -> uuid::Uuid {
    if let Ok(u) = rf_id.parse::<uuid::Uuid>() {
        return u;
    }
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(rf_id.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash[..16]);
    uuid::Uuid::from_bytes(bytes)
}

/// Look up an rf_id in the workflow graph from a user-supplied label
/// (case-insensitive). Tries module display names first, then explicit
/// `data.label` strings. Returns `(rf_id, resolution_kind)`.
async fn resolve_rf_id_from_label(
    state: &McpState,
    wf_id: uuid::Uuid,
    user_id: uuid::Uuid,
    input: &str,
) -> Option<(String, &'static str)> {
    let row = state
        .workflow_repo
        .get_workflow_name_and_graph(wf_id, user_id)
        .await
        .ok()
        .flatten()?;
    let graph: serde_json::Value = serde_json::from_str(&row.1).ok()?;
    let nodes = graph.get("nodes").and_then(|n| n.as_array())?;

    let needle = input.trim().to_ascii_lowercase();

    // Pass 1: data.label exact match (what the editor stamps).
    for n in nodes {
        let lbl = n
            .get("data")
            .and_then(|d| d.get("label"))
            .and_then(|v| v.as_str())
            .or_else(|| n.get("label").and_then(|v| v.as_str()));
        if let Some(lbl) = lbl {
            if lbl.trim().to_ascii_lowercase() == needle {
                if let Some(id) = n.get("id").and_then(|v| v.as_str()) {
                    return Some((id.to_string(), "data_label"));
                }
            }
        }
    }

    // Pass 2: resolve module name via batched module-id lookup.
    let module_ids: Vec<uuid::Uuid> = nodes
        .iter()
        .filter_map(|n| {
            n.get("type")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<uuid::Uuid>().ok())
        })
        .collect();
    if module_ids.is_empty() {
        return None;
    }
    let mut module_names: std::collections::HashMap<uuid::Uuid, String> =
        std::collections::HashMap::new();
    if let Ok(rows) = state
        .module_repo
        .list_template_names_by_ids(&module_ids)
        .await
    {
        module_names.extend(rows);
    }
    if let Ok(rows) = state
        .workflow_repo
        .list_wasm_module_names_by_ids_unscoped(&module_ids)
        .await
    {
        for (id, name) in rows {
            module_names.entry(id).or_insert(name);
        }
    }

    for n in nodes {
        let module_id: Option<uuid::Uuid> = n
            .get("type")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok());
        if let Some(mid) = module_id {
            if let Some(name) = module_names.get(&mid) {
                if name.trim().to_ascii_lowercase() == needle {
                    if let Some(id) = n.get("id").and_then(|v| v.as_str()) {
                        return Some((id.to_string(), "module_name"));
                    }
                }
            }
        }
    }

    None
}

async fn handle_get_execution_cost(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let exec_id = match crate::utils::require_uuid(args, "execution_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let exec = match state.execution_repo.get_execution(exec_id, user_id).await {
        Ok(Some(e)) => e,
        Ok(None) => return mcp_error(req_id, -32000, "Execution not found or access denied"),
        Err(e) => {
            tracing::error!("get_execution_cost query failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to fetch execution");
        }
    };

    let started_at = exec.started_at;
    let completed_at = exec.completed_at;
    let workflow_id = exec.workflow_id;
    let output_json: serde_json::Value = exec.output_data.unwrap_or(serde_json::json!({}));

    let total_duration_ms = match (started_at, completed_at) {
        (Some(s), Some(c)) => Some((c - s).num_milliseconds()),
        _ => None,
    };

    // Two timing sources, in order of preference:
    //   1. `output_data.__node_timings__` — written by the result
    //      collector when ctx.node_timings is non-empty. Fast path.
    //   2. `execution_events` — node_started + node_completed/node_failed
    //      pairs let us reconstruct durations event-by-event. Slower
    //      but always available for any execution that emitted lifecycle
    //      events. Critical for executions that ran BEFORE the scheduler
    //      `__node_timings__` stamping landed (commit 0085b3d) — those
    //      have no `__node_timings__` key, but the events still exist,
    //      so we should never report `node_count: 0` for them.
    let mut per_node: Vec<serde_json::Value> = output_json
        .get("__node_timings__")
        .and_then(|v| v.as_object())
        .map(|t| {
            t.iter()
                .map(|(k, v)| serde_json::json!({ "node": k, "duration_ms": v }))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut timing_source = "node_timings_stamp";

    if per_node.is_empty() {
        // Event fallback — reconstruct durations from execution_events.
        let events = state
            .execution_repo
            .list_execution_events(exec_id)
            .await
            .unwrap_or_default();
        let graph_str = state
            .execution_repo
            .get_workflow_graph_for_user(workflow_id, user_id)
            .await
            .ok()
            .flatten();
        let uuid_to_label = build_node_display_label_map(graph_str);
        let mut node_starts: std::collections::HashMap<uuid::Uuid, chrono::DateTime<chrono::Utc>> =
            std::collections::HashMap::new();
        for ev in &events {
            if let Some(nid) = ev.node_id {
                match ev.event_type.as_str() {
                    "node_started" => {
                        node_starts.insert(nid, ev.created_at);
                    }
                    "node_completed" | "node_failed" => {
                        if let Some(start_ts) = node_starts.remove(&nid) {
                            let dur = (ev.created_at - start_ts).num_milliseconds().max(1);
                            let label = uuid_to_label
                                .get(&nid)
                                .cloned()
                                .unwrap_or_else(|| nid.to_string());
                            per_node.push(serde_json::json!({
                                "node": label,
                                "duration_ms": dur,
                            }));
                        }
                    }
                    _ => {}
                }
            }
        }
        if !per_node.is_empty() {
            timing_source = "execution_events";
        } else {
            timing_source = "unavailable";
        }
    }

    let node_count = per_node.len();
    let total_node_time_ms: f64 = per_node
        .iter()
        .filter_map(|n| n.get("duration_ms").and_then(|v| v.as_f64()))
        .sum();
    let avg_node_time_ms = if node_count > 0 {
        total_node_time_ms / node_count as f64
    } else {
        0.0
    };

    // MCP-42 (2026-05-07): pull total fuel consumed from the
    // execution_cost_rollup table — this is the actual platform-cost
    // metric (WASM instructions executed) rather than wall time.
    // Pre-fix `compute_units = node_count * avg_node_time_ms` was
    // mathematically identical to `total_node_time_ms` (the average
    // is total/count) — emitting both was redundant and misleading
    // operators about what compute_units measured.
    let total_fuel_consumed: i64 = state
        .analytics_repo
        .get_execution_node_fuel(exec_id, user_id)
        .await
        .ok()
        .map(|rows| rows.iter().map(|(_, _, fuel, _, _)| *fuel).sum())
        .unwrap_or(0);

    // MCP-19: emit numeric values directly rather than format!-strings.
    // Round to 2 decimals via the same shape format_percent uses (×100 for
    // 2-decimal precision).
    let round_2dp = |v: f64| {
        if v.is_finite() {
            (v * 100.0).round() / 100.0
        } else {
            0.0
        }
    };
    let result = serde_json::json!({
        "execution_id": exec_id.to_string(),
        "total_duration_ms": total_duration_ms,
        "node_count": node_count,
        "total_node_time_ms": total_node_time_ms,
        "avg_node_time_ms": round_2dp(avg_node_time_ms),
        "total_fuel_consumed": total_fuel_consumed,
        "compute_units": total_fuel_consumed,
        "compute_units_unit": "wasm_instructions",
        "per_node_timings": per_node,
        "timing_source": timing_source,
    });

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

async fn handle_get_execution_waterfall(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let exec_id = match crate::utils::require_uuid(args, "execution_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // Load execution record
    let exec = match state.execution_repo.get_execution(exec_id, user_id).await {
        Ok(Some(e)) => e,
        Ok(None) => return mcp_error(req_id, -32000, "Execution not found or access denied"),
        Err(e) => {
            tracing::error!(execution_id = %exec_id, "get_execution_waterfall fetch failed: {}", e);
            return mcp_error(req_id, -32000, "Database error fetching execution");
        }
    };

    let status = exec.status.clone();
    let started_at = exec.started_at;
    let completed_at = exec.completed_at;
    let output_data = exec.output_data.clone();
    let workflow_id = exec.workflow_id;

    let wf_start = match started_at {
        Some(t) => t,
        None => return mcp_error(req_id, -32000, "Execution has no start time"),
    };

    // Load execution events to get per-node start/complete timestamps
    let events = state
        .execution_repo
        .list_execution_events(exec_id)
        .await
        .unwrap_or_default();

    // Build UUID -> display label mapping from graph_json
    let graph_str = state
        .execution_repo
        .get_workflow_graph_for_user(workflow_id, user_id)
        .await
        .ok()
        .flatten();
    let uuid_to_label = build_node_display_label_map(graph_str);

    // Track per-node timing from events: node_started -> node_completed/node_failed
    struct NodeTiming {
        label: String,
        start_ms: i64,
        duration_ms: i64,
    }

    let mut node_starts: std::collections::HashMap<uuid::Uuid, chrono::DateTime<chrono::Utc>> =
        std::collections::HashMap::new();
    let mut timings: Vec<NodeTiming> = Vec::new();

    for ev in &events {
        if let Some(nid) = ev.node_id {
            let ts = ev.created_at;
            match ev.event_type.as_str() {
                "node_started" => {
                    node_starts.insert(nid, ts);
                }
                "node_completed" | "node_failed" => {
                    let start_ts = node_starts.remove(&nid).unwrap_or(ts);
                    let start_ms = (start_ts - wf_start).num_milliseconds().max(0);
                    let duration_ms = (ts - start_ts).num_milliseconds().max(1);
                    let label = uuid_to_label
                        .get(&nid)
                        .cloned()
                        .unwrap_or_else(|| nid.to_string());
                    timings.push(NodeTiming {
                        label,
                        start_ms,
                        duration_ms,
                    });
                }
                _ => {}
            }
        }
    }

    // If no event-based timings, fall back to __node_timings__ from output_data
    if timings.is_empty() {
        if let Some(ref out) = output_data {
            if let Some(obj) = out.get("__node_timings__").and_then(|v| v.as_object()) {
                // Without start offsets we place them sequentially for visualization
                let mut offset: i64 = 0;
                for (label, duration_val) in obj {
                    let dur: i64 = duration_val.as_u64().unwrap_or(0).try_into().unwrap_or(0);
                    timings.push(NodeTiming {
                        label: label.clone(),
                        start_ms: offset,
                        duration_ms: dur.max(1),
                    });
                    offset += dur;
                }
            }
        }
    }

    if timings.is_empty() {
        return mcp_text(req_id, "No node timing data available for this execution.");
    }

    // Sort by start time
    timings.sort_by_key(|t| t.start_ms);

    let total_ms = completed_at
        .map(|c| (c - wf_start).num_milliseconds().max(1))
        .unwrap_or_else(|| {
            timings
                .iter()
                .map(|t| t.start_ms + t.duration_ms)
                .max()
                .unwrap_or(1)
        });

    // Build waterfall chart
    let chart_width: usize = 50; // characters for the bar area
    let max_label_len = timings
        .iter()
        .map(|t| t.label.len())
        .max()
        .unwrap_or(10)
        .min(30);

    // Header with time scale
    let time_step = total_ms / 5;
    let mut header_nums = format!("{:<width$}", "", width = max_label_len + 2);
    for i in 0..=5 {
        let ms = i * time_step;
        let label = if ms >= 1000 {
            format!("{:.1}s", ms as f64 / 1000.0)
        } else {
            format!("{}ms", ms)
        };
        if i < 5 {
            let segment_width = chart_width / 5;
            header_nums.push_str(&format!("{:<width$}", label, width = segment_width));
        } else {
            header_nums.push_str(&label);
        }
    }

    let mut header_line = format!("{:<width$}", "", width = max_label_len + 2);
    for _ in 0..=5 {
        let segment_width = chart_width / 5;
        header_line.push('|');
        for _ in 1..segment_width {
            header_line.push('-');
        }
    }

    let mut waterfall = String::new();
    waterfall.push_str(&format!("=== Execution Waterfall: {} ===\n", exec_id));
    waterfall.push_str(&format!("Status: {} | Total: {}ms\n\n", status, total_ms));
    waterfall.push_str(&header_nums);
    waterfall.push('\n');
    waterfall.push_str(&header_line);
    waterfall.push('\n');

    for t in &timings {
        let truncated_label = if t.label.len() > max_label_len {
            format!("{}...", &t.label[..max_label_len - 3])
        } else {
            t.label.clone()
        };

        let bar_start = ((t.start_ms as f64 / total_ms as f64) * chart_width as f64) as usize;
        let bar_len =
            ((t.duration_ms as f64 / total_ms as f64) * chart_width as f64).ceil() as usize;
        let bar_start = bar_start.min(chart_width);
        let bar_len = bar_len.clamp(1, chart_width - bar_start);

        let mut bar = String::new();
        for _ in 0..bar_start {
            bar.push('\u{2591}'); // light shade for idle
        }
        for _ in 0..bar_len {
            bar.push('\u{2588}'); // full block for active
        }
        let remaining = chart_width.saturating_sub(bar_start + bar_len);
        for _ in 0..remaining {
            bar.push('\u{2591}');
        }

        waterfall.push_str(&format!(
            "{:<width$}  {}  ({}ms, started at {}ms)\n",
            truncated_label,
            bar,
            t.duration_ms,
            t.start_ms,
            width = max_label_len
        ));
    }

    mcp_text(req_id, &waterfall)
}

async fn handle_get_execution_replay_chain(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let exec_id = match crate::utils::require_uuid(args, "execution_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // Fetch the base execution record (user-scoped)
    let exec = match state.execution_repo.get_execution(exec_id, user_id).await {
        Ok(Some(e)) => e,
        Ok(None) => return mcp_error(req_id, -32000, "Execution not found or access denied"),
        Err(e) => {
            tracing::error!(execution_id = %exec_id, "get_execution_replay_chain fetch failed: {}", e);
            return mcp_error(req_id, -32000, "Database error fetching execution");
        }
    };

    let workflow_id = exec.workflow_id;
    let replayed_from_id = exec.replayed_from_id;

    // Walk backward: use repo chain (walks ancestors via replayed_from_id)
    let ancestor_chain = state
        .execution_repo
        .get_execution_replay_chain(exec_id, user_id, 20)
        .await
        .unwrap_or_default();
    // ancestor_chain is oldest→newest; exclude the execution itself (last element)
    let ancestors: Vec<String> = ancestor_chain
        .iter()
        .filter(|e| e.id != exec_id)
        .map(|e| e.id.to_string())
        .collect();

    // Walk forward: find descendants
    let descendants = state
        .execution_repo
        .list_execution_descendants(exec_id, user_id)
        .await
        .unwrap_or_default();

    let result = serde_json::json!({
        "execution_id": exec_id.to_string(),
        "workflow_id": workflow_id.to_string(),
        "replayed_from": replayed_from_id.map(|id| id.to_string()),
        "ancestors": ancestors,
        "descendants": descendants.iter().map(|id| id.to_string()).collect::<Vec<_>>(),
    });

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

async fn handle_get_execution_comparison_report(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // MCP-274 (2026-05-10): pre-fix `filter_map` silently dropped any
    // entry that wasn't a parseable UUID, so a mixed array like
    // `["abc", "def", "<valid>"]` produced a comparison report on
    // ONE execution with no signal that two of the operator's inputs
    // were rejected. Reject the malformed entry loudly with -32602
    // identifying the bad index — same MCP-249/250 family.
    let execution_ids: Vec<uuid::Uuid> = match args.get("execution_ids").and_then(|v| v.as_array())
    {
        Some(arr) => {
            if arr.is_empty() {
                return mcp_error(req_id, -32602, "execution_ids array must not be empty");
            }
            if arr.len() > 10 {
                return mcp_error(req_id, -32602, "Maximum 10 execution IDs allowed");
            }
            let mut parsed: Vec<uuid::Uuid> = Vec::with_capacity(arr.len());
            for (i, item) in arr.iter().enumerate() {
                match item.as_str().and_then(|s| s.parse::<uuid::Uuid>().ok()) {
                    Some(id) => parsed.push(id),
                    None => {
                        return mcp_error(
                            req_id,
                            -32602,
                            &format!(
                                "execution_ids[{i}] is not a valid UUID; bulk parse rejects malformed entries instead of silently dropping them"
                            ),
                        )
                    }
                }
            }
            parsed
        }
        None => return mcp_error(req_id, -32602, "Missing 'execution_ids' array"),
    };

    let mut executions: Vec<serde_json::Value> = Vec::new();
    let mut all_output_keys: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut per_execution_keys: Vec<std::collections::HashSet<String>> = Vec::new();
    let mut durations: Vec<f64> = Vec::new();
    let mut statuses: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    // Batched fetch — single round-trip via WHERE id = ANY($1) replaces the
    // prior per-id `get_execution` loop. The not-found-or-not-owned filter
    // is preserved (rows excluded by the user_id scope simply don't appear
    // in the map). Input ordering is preserved by indexing the map below.
    let exec_map: std::collections::HashMap<uuid::Uuid, talos_execution_repository::ExecutionRow> =
        match state
            .execution_repo
            .get_executions_by_ids(&execution_ids, user_id)
            .await
        {
            Ok(rows) => rows.into_iter().map(|r| (r.id, r)).collect(),
            Err(e) => {
                tracing::error!("get_execution_comparison_report batch fetch failed: {}", e);
                std::collections::HashMap::new()
            }
        };

    // MCP-355 (2026-05-11): pre-fix the inner `continue` silently
    // dropped any execution_id that wasn't found / wasn't owned / failed
    // the batch fetch. So an operator asking to compare 5 executions
    // where 3 were theirs and 2 were typos / unowned saw a comparison
    // report on 3 with NO signal about the missing 2. Worse, the
    // `common_output_keys` and `divergent_output_keys` sets below
    // become misleading — keys that appear in all 3 visible executions
    // are reported as "common" even though the operator's intended
    // 5-execution comparison might have had divergent keys among the
    // missing 2. Same family as MCP-149 (update_node_positions
    // unknown_node_ids surface) and batch_delete_workflows
    // not_found surface. Track and surface explicitly.
    let mut not_found_ids: Vec<String> = Vec::new();
    for eid in &execution_ids {
        let exec = match exec_map.get(eid) {
            Some(e) => e,
            None => {
                not_found_ids.push(eid.to_string());
                continue;
            }
        };

        let duration_ms: Option<f64> = match (exec.started_at, exec.completed_at) {
            (Some(s), Some(c)) => Some((c - s).num_milliseconds() as f64),
            _ => None,
        };

        *statuses.entry(exec.status.clone()).or_insert(0) += 1;
        if let Some(d) = duration_ms {
            durations.push(d);
        }

        let output_data = exec.output_data.clone().unwrap_or(serde_json::json!({}));
        let mut output_keys: std::collections::HashSet<String> = std::collections::HashSet::new();
        if let Some(obj) = output_data.as_object() {
            for key in obj.keys() {
                all_output_keys.insert(key.clone());
                output_keys.insert(key.clone());
            }
        }
        per_execution_keys.push(output_keys.clone());

        executions.push(serde_json::json!({
            "execution_id": exec.id.to_string(),
            "workflow_id": exec.workflow_id.to_string(),
            "status": exec.status,
            "error_message": exec.error_message,
            "started_at": exec.started_at.map(|t| t.to_rfc3339()),
            "completed_at": exec.completed_at.map(|t| t.to_rfc3339()),
            "duration_ms": duration_ms,
            "output_keys": output_keys.into_iter().collect::<Vec<_>>(),
        }));
    }

    if executions.is_empty() {
        return mcp_text(
            req_id,
            "No matching executions found (check IDs and ownership).",
        );
    }

    // Compute common and divergent output keys
    let common_keys: Vec<String> = all_output_keys
        .iter()
        .filter(|k| per_execution_keys.iter().all(|eks| eks.contains(*k)))
        .cloned()
        .collect();
    let divergent_keys: Vec<String> = all_output_keys
        .iter()
        .filter(|k| !per_execution_keys.iter().all(|eks| eks.contains(*k)))
        .cloned()
        .collect();

    // Duration statistics
    let (min_dur, max_dur, avg_dur) = if durations.is_empty() {
        (None, None, None)
    } else {
        let min = durations.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = durations.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let avg = durations.iter().sum::<f64>() / durations.len() as f64;
        (Some(min), Some(max), Some(avg))
    };

    // MCP-355: surface unmatched IDs so the operator can audit ownership
    // / typos. `total_requested` mirrors what they asked for, vs
    // `total_compared` for what actually rolled into the stats. When the
    // two differ, callers know to interpret `common_output_keys` with a
    // pinch of salt — the "common" set is across the visible subset.
    let result = serde_json::json!({
        "executions": executions,
        "summary": {
            "total_requested": execution_ids.len(),
            "total_compared": executions.len(),
            "not_found_ids": not_found_ids,
            "status_breakdown": statuses,
            "duration_spread": {
                // MCP-19: emit numbers, rounded to 1 decimal — not format!-strings.
                "min_ms": min_dur.map(|d| (d * 10.0).round() / 10.0),
                "max_ms": max_dur.map(|d| (d * 10.0).round() / 10.0),
                "avg_ms": avg_dur.map(|d| (d * 10.0).round() / 10.0),
            },
            "common_output_keys": common_keys,
            "divergent_output_keys": divergent_keys,
        },
    });

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

// ── shared trace builder ─────────────────────────────────────────────────────

/// Builds the full per-node trace JSON string for an execution.
/// Called by get_execution_trace, get_execution_status(detail: true), and trigger_workflow(wait_ms).
pub async fn build_execution_trace_json(
    exec_id: Uuid,
    user_id: Uuid,
    state: &McpState,
) -> Result<String, String> {
    let exec = match state.execution_repo.get_execution(exec_id, user_id).await {
        Ok(Some(e)) => e,
        Ok(None) => return Err("Execution not found or access denied".to_string()),
        Err(e) => {
            tracing::error!(execution_id = %exec_id, "build_execution_trace_json fetch failed: {}", e);
            return Err("Database error fetching execution".to_string());
        }
    };

    let status = exec.status.clone();
    let started_at = exec.started_at;
    let completed_at = exec.completed_at;
    let error_message = exec.error_message.clone();
    let output_data = exec.output_data.clone();
    let workflow_id = exec.workflow_id;
    let actor_id = exec.actor_id;
    let provenance = exec.provenance.clone();

    let graph_str = state
        .execution_repo
        .get_workflow_graph_for_user(workflow_id, user_id)
        .await
        .ok()
        .flatten();
    let node_label_map = build_node_label_map(graph_str);

    let event_rows = state
        .execution_repo
        .list_execution_events(exec_id)
        .await
        .unwrap_or_default();

    struct NodeTrace {
        order: usize,
        label: String,
        first_started_at: Option<chrono::DateTime<chrono::Utc>>,
        finished_at: Option<chrono::DateTime<chrono::Utc>>,
        start_count: u32,
        final_status: String,
        error: Option<String>,
    }

    let mut node_order: Vec<Uuid> = Vec::new();
    let mut node_traces: std::collections::HashMap<Uuid, NodeTrace> =
        std::collections::HashMap::new();

    for ev in &event_rows {
        let node_id = match ev.node_id {
            Some(id) => id,
            None => continue,
        };
        let created_at = ev.created_at;
        let label = node_label_map
            .get(&node_id)
            .cloned()
            .unwrap_or_else(|| node_id.to_string());

        match ev.event_type.as_str() {
            "node_started" => {
                node_traces.entry(node_id).or_insert_with(|| {
                    let order = node_order.len() + 1;
                    node_order.push(node_id);
                    NodeTrace {
                        order,
                        label,
                        first_started_at: Some(created_at),
                        finished_at: None,
                        start_count: 1,
                        final_status: "running".to_string(),
                        error: None,
                    }
                });
            }
            "node_retrying" => {
                if let Some(entry) = node_traces.get_mut(&node_id) {
                    entry.start_count += 1;
                    entry.finished_at = None;
                    entry.final_status = "running".to_string();
                }
            }
            "node_completed" => {
                if let Some(entry) = node_traces.get_mut(&node_id) {
                    entry.finished_at = Some(created_at);
                    entry.final_status = "completed".to_string();
                    entry.error = None;
                }
            }
            "node_failed" => {
                if let Some(entry) = node_traces.get_mut(&node_id) {
                    entry.finished_at = Some(created_at);
                    entry.final_status = "failed".to_string();
                    entry.error = ev.log_message.clone();
                }
            }
            "node_skipped" => {
                if let std::collections::hash_map::Entry::Vacant(e) = node_traces.entry(node_id) {
                    let order = node_order.len() + 1;
                    node_order.push(node_id);
                    e.insert(NodeTrace {
                        order,
                        label,
                        first_started_at: None,
                        finished_at: Some(created_at),
                        start_count: 0,
                        final_status: "skipped".to_string(),
                        error: None,
                    });
                } else if let Some(entry) = node_traces.get_mut(&node_id) {
                    entry.final_status = "skipped".to_string();
                }
            }
            _ => {}
        }
    }

    let output_by_label: std::collections::HashMap<String, serde_json::Value> = output_data
        .as_ref()
        .and_then(|v| v.as_object())
        .map(|obj| {
            obj.iter()
                .filter(|(k, _)| !k.starts_with("__"))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        })
        .unwrap_or_default();

    // Per-node fuel + ceiling from `execution_cost_rollup`. The hook
    // records the node *label* (not the UUID) in `node_id`, so we key by
    // label to match `node_traces` entries. `effective_max_fuel` is the
    // limit the dispatch actually enforced — `COALESCE(rollup.max_fuel,
    // modules.max_fuel)`: the worker-stamped `__fuel_limit__` when present
    // (includes node-config overrides + engine clamp), the module default
    // for pre-stamp rows. 0 for raw rust_code nodes that never landed in
    // the modules table.
    struct NodeFuel {
        module_id: Option<Uuid>,
        fuel_consumed: i64,
        wall_time_ms: i64,
        effective_max_fuel: i64,
    }
    let fuel_by_label: std::collections::HashMap<String, NodeFuel> = state
        .analytics_repo
        .get_execution_node_fuel(exec_id, user_id)
        .await
        .ok()
        .unwrap_or_default()
        .into_iter()
        .map(|(label, mid, fuel, wall, ceiling)| {
            (
                label,
                NodeFuel {
                    module_id: mid,
                    fuel_consumed: fuel,
                    wall_time_ms: wall,
                    effective_max_fuel: ceiling.unwrap_or(0),
                },
            )
        })
        .collect();

    let nodes_json: Vec<serde_json::Value> = node_order
        .iter()
        .filter_map(|nid| node_traces.get(nid).map(|t| (nid, t)))
        .map(|(nid, t)| {
            let duration_ms = match (t.first_started_at, t.finished_at) {
                (Some(s), Some(f)) => Some((f - s).num_milliseconds()),
                _ => None,
            };
            // MCP-22 + MCP-24 fix: output_data is keyed by per-execution
            // node UUID, not label. Pre-fix the lookup used `t.label` and
            // missed every entry, surfacing `output: null` for nodes that
            // actually produced output. Try UUID first, fall back to
            // label for paths that key by label. When neither matches,
            // emit a sentinel rather than null so operators don't read
            // "no output" when it actually exists in the row.
            let nid_str = nid.to_string();
            let output_value = output_by_label
                .get(&nid_str)
                .cloned()
                .or_else(|| output_by_label.get(&t.label).cloned());
            let output_field = match output_value {
                Some(v) => v,
                None if output_data
                    .as_ref()
                    .and_then(|d| d.as_object())
                    .is_some_and(|m| !m.is_empty()) =>
                {
                    serde_json::json!({
                        "available": false,
                        "fetch_via": "get_execution_output",
                        "note": "Per-node output is in the execution row but not surfaced here (truncation/projection skip). Call get_execution_output for the full payload."
                    })
                }
                None => serde_json::Value::Null,
            };
            let fuel_info = fuel_by_label.get(&t.label).map(|f| {
                // MCP-25: utilization_pct is a JSON number (1 decimal,
                // matched to format_percent's contract). Pre-fix this
                // was a quoted string `"1.8"` — same wire-format
                // inconsistency MCP-19 already swept across percentage
                // fields.
                let utilization_pct = if f.effective_max_fuel > 0 {
                    Some(talos_analytics_repository::format_percent(
                        (f.fuel_consumed as f64 / f.effective_max_fuel as f64) * 100.0,
                    ))
                } else {
                    None
                };
                serde_json::json!({
                    "module_id": f.module_id.map(|m| m.to_string()),
                    "fuel_consumed": f.fuel_consumed,
                    "wall_time_ms": f.wall_time_ms,
                    "current_max_fuel": if f.effective_max_fuel > 0 { Some(f.effective_max_fuel) } else { None },
                    "utilization_pct": utilization_pct,
                })
            });
            serde_json::json!({
                "order": t.order,
                "node_id": nid.to_string(),
                "label": t.label,
                "status": t.final_status,
                "started_at": t.first_started_at.map(|d| d.to_rfc3339()),
                "duration_ms": duration_ms,
                "retries_attempted": t.start_count.saturating_sub(1),
                "output": output_field,
                "fuel": fuel_info,
                "error": t.error,
            })
        })
        .collect();

    let total_nodes = nodes_json.len();
    let completed = nodes_json
        .iter()
        .filter(|n| n.get("status").and_then(|v| v.as_str()) == Some("completed"))
        .count();
    let failed = nodes_json
        .iter()
        .filter(|n| n.get("status").and_then(|v| v.as_str()) == Some("failed"))
        .count();
    let skipped = nodes_json
        .iter()
        .filter(|n| n.get("status").and_then(|v| v.as_str()) == Some("skipped"))
        .count();

    // MCP-1211 (2026-05-18): surface loop nodes that bailed via the
    // max_iterations safety cap as warnings. Pre-fix the execution
    // completed silently — no signal in the trace, no flag in the status
    // string, no entry in get_health_dashboard. The daily-brief workflow
    // ran a misconfigured `while: true` probe-loop on 19 consecutive
    // executions before the gap was noticed. Surfacing here gives
    // operators a per-execution view; the health dashboard adds the
    // aggregate view via get_loop_capped_workflows_24h.
    //
    // We scan `output_data` directly (not `nodes_json`) because
    // system-loop nodes don't always emit node_started/node_completed
    // events — they appear in output_data but not in event_rows. The
    // shape is `{ "<node_id>": { "termination_reason": "...", "iterations": N, ... }, ... }`.
    let mut warnings: Vec<serde_json::Value> = Vec::new();
    if let Some(obj) = output_data.as_ref().and_then(|d| d.as_object()) {
        for (key, val) in obj {
            // Skip engine-internal trace keys (`__node_timings__`, etc.).
            if key.starts_with("__") {
                continue;
            }
            let termination_reason = val.get("termination_reason").and_then(|v| v.as_str());
            if termination_reason != Some("max_iterations") {
                continue;
            }
            let iterations = val.get("iterations").and_then(|v| v.as_i64());
            // Try to resolve a friendly label from the graph's node-label
            // map (keyed by Uuid). The output_data key is normally the
            // per-execution node UUID; for graph nodes whose id is a
            // human label rather than a UUID, the key itself is the label.
            let (label, node_id_str) = match key.parse::<Uuid>() {
                Ok(uid) => (
                    node_label_map
                        .get(&uid)
                        .cloned()
                        .unwrap_or_else(|| key.clone()),
                    key.clone(),
                ),
                Err(_) => (key.clone(), key.clone()),
            };
            warnings.push(serde_json::json!({
                "kind": "loop_max_iterations",
                "node_id": node_id_str,
                "label": label,
                "iterations": iterations,
                "message": format!(
                    "Loop node '{}' terminated via max_iterations safety cap — likely a \
                     misconfigured exit condition. Run validate_workflow to check the loop's \
                     condition expression.",
                    label
                ),
            }));
        }
    }

    let total_duration_ms = match (started_at, completed_at) {
        (Some(s), Some(c)) => Some((c - s).num_milliseconds()),
        _ => None,
    };

    // Sub-execution timing — pain point #2 from aegix_dev_pain_points.md.
    // Pre-r234, sub_workflow dispatch nodes (judge / ensemble / reflective_retry
    // / llm_dispatch / sub_workflow) showed up as ~1s LABEL nodes in the parent
    // trace because the long-pole LLM latency lived in the *child* execution
    // and was invisible from the parent's vantage point. Surfacing the child
    // executions inline (linked via workflow_executions.parent_execution_id)
    // lets a reader correlate "the gap before label X started_at" with the
    // matching child duration without an extra get_execution_lineage call.
    //
    // Bounded: list_child_executions caps at 64 rows. Cheap join over an
    // indexed column; no unbounded scan even for fan-out-heavy parents.
    let sub_executions: Vec<serde_json::Value> = state
        .execution_repo
        .list_child_executions(exec_id, user_id)
        .await
        .ok()
        .unwrap_or_default()
        .into_iter()
        .map(|c| {
            let duration_ms = match (c.started_at, c.completed_at) {
                (Some(s), Some(e)) => Some((e - s).num_milliseconds()),
                _ => None,
            };
            serde_json::json!({
                "execution_id": c.execution_id.to_string(),
                "workflow_id": c.workflow_id.to_string(),
                "workflow_name": c.workflow_name,
                "status": c.status,
                "started_at": c.started_at.map(|d| d.to_rfc3339()),
                "completed_at": c.completed_at.map(|d| d.to_rfc3339()),
                "duration_ms": duration_ms,
                "error_message": c.error_message,
            })
        })
        .collect();
    let sub_execution_count = sub_executions.len();

    let warning_count = warnings.len();
    let result = serde_json::json!({
        "execution_id": exec_id.to_string(),
        "workflow_id": workflow_id.to_string(),
        "actor_id": actor_id.map(|id| id.to_string()),
        "provenance": provenance,
        "status": status,
        "started_at": started_at.map(|d| d.to_rfc3339()),
        "completed_at": completed_at.map(|d| d.to_rfc3339()),
        "total_duration_ms": total_duration_ms,
        "error": error_message,
        "nodes": nodes_json,
        "sub_executions": sub_executions,
        "warnings": warnings,
        "summary": {
            "total_nodes": total_nodes,
            "completed": completed,
            "failed": failed,
            "skipped": skipped,
            "sub_execution_count": sub_execution_count,
            "warning_count": warning_count,
        }
    });

    Ok(serde_json::to_string_pretty(&result).unwrap_or_default())
}

// ── get_execution_trace ──────────────────────────────────────────────────────

async fn handle_get_execution_trace(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let exec_id = match crate::utils::require_uuid(args, "execution_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    match build_execution_trace_json(exec_id, user_id, state).await {
        Ok(trace) => mcp_text(req_id, &trace),
        Err(msg) => mcp_error(req_id, -32000, &msg),
    }
}

async fn handle_analyze_execution_failure(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let exec_id = match crate::utils::require_uuid(args, "execution_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // MCP-267 (2026-05-10): direction-class wrong-type rejection.
    // Pre-fix `apply_fix: "true"` (string) silently fell back to false
    // — operator's intent to apply the auto-fix was lost; same for
    // auto_retry. analyze_execution_failure is interactive enough
    // that wrong-type as a typo should fail loudly. Same family as
    // MCP-251 / MCP-252.
    let apply_fix = match crate::utils::validate_optional_bool(args, "apply_fix", false, &req_id) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let auto_retry = match crate::utils::validate_optional_bool(args, "auto_retry", false, &req_id)
    {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // Classification, remediation playbooks, and the config-field
    // auto-fix all live in `talos-failure-analysis-service` — report
    // shape and error strings preserved byte-for-byte from the
    // pre-extraction handler.
    match state
        .failure_analysis_service
        .analyze(talos_failure_analysis_service::AnalyzeFailureInput {
            execution_id: exec_id,
            user_id,
            apply_fix,
            auto_retry,
        })
        .await
    {
        Ok(outcome) => mcp_text(
            req_id,
            &serde_json::to_string_pretty(&outcome.report).unwrap_or_default(),
        ),
        Err(e) => mcp_error(req_id, e.jsonrpc_code(), &e.user_facing_message()),
    }
}

// ── replay_execution_with_input ──────────────────────────────────────────────
//
// Pre-extraction this handler had its own inline `deep_merge`; it was
// lifted into `talos_execution_orchestration::deep_merge` and is now
// called from the service layer's `replay_with_input` method.

async fn handle_replay_execution_with_input(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let original_execution_id =
        match crate::utils::require_uuid(args, "execution_id", req_id.clone()) {
            Ok(id) => id,
            Err(resp) => return resp,
        };
    let input_overrides = args
        .get("input_overrides")
        .cloned()
        .unwrap_or(serde_json::json!({}));
    match state
        .execution_orchestration_service
        .replay_with_input(talos_execution_orchestration::ReplayWithInputInput {
            original_execution_id,
            user_id,
            replay_agent_id: None,
            input_overrides,
        })
        .await
    {
        Ok(outcome) => mcp_text(
            req_id,
            &format!(
                "Replay (with input overrides) started.\nOriginal execution: {}\nNew execution ID: {}\nStatus: running",
                original_execution_id, outcome.execution_id
            ),
        ),
        Err(err) => crate::utils::orchestration_error_to_response(err, req_id),
    }
}

async fn handle_acknowledge_execution_failure(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let exec_id = match args
        .get("execution_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        Some(id) => id,
        None => return mcp_error(req_id, -32602, "Missing or invalid execution_id"),
    };
    // MCP-205 (2026-05-08): reject whitespace-only reasons. The
    // reason is persisted to the action log AND surfaces in the
    // workflow's reliability-score acknowledgement audit. Pre-fix
    // a 16-space reason got persisted verbatim. Same family as
    // MCP-186.
    //
    // MCP-374 (2026-05-11): pre-fix `Some(r) => r.to_string()` persisted
    // UNTRIMMED. Audit-log search across the acknowledgement trail
    // missed the trimmed query. Trim post-emptiness-check; re-validate
    // length on the trimmed value so padding can't bypass the 2000-char
    // cap.
    let reason = match args.get("reason").and_then(|v| v.as_str()) {
        None => return mcp_error(req_id, -32602, "Missing required argument: reason"),
        Some(r) if r.trim().is_empty() => {
            return mcp_error(
                req_id,
                -32602,
                "reason must be a non-empty, non-whitespace string explaining why this failure is acknowledged",
            )
        }
        Some(r) if r.trim().len() > 2000 => {
            return mcp_error(req_id, -32602, "reason must be ≤ 2000 characters")
        }
        Some(r) => r.trim().to_string(),
    };

    // Verify the execution exists, belongs to user, and is in a failed state.
    let exec = match state.execution_repo.get_execution(exec_id, user_id).await {
        Ok(Some(e)) => e,
        Ok(None) => return mcp_error(req_id, -32000, "Execution not found or access denied"),
        Err(e) => {
            tracing::error!(execution_id = %exec_id, "acknowledge_execution_failure fetch failed: {}", e);
            return mcp_error(req_id, -32000, "Database error fetching execution");
        }
    };

    if exec.status != "failed" {
        return mcp_error(
            req_id,
            -32000,
            &format!(
                "Only failed executions can be acknowledged (current status: {})",
                exec.status
            ),
        );
    }

    // Idempotency guard — acknowledgements are immutable for audit integrity.
    // A second call with a different reason could silently overwrite the audit trail.
    if let Some(ref ack_at) = exec.acknowledged_at {
        return mcp_error(
            req_id,
            -32000,
            &format!(
                "Execution {} is already acknowledged (acknowledged_at: {}, reason: '{}').\
                 \nAcknowledgements are immutable for audit integrity — the original reason cannot be overwritten.\
                 \nUse list_executions to view the stored acknowledgement.",
                exec_id,
                ack_at.to_rfc3339(),
                exec.acknowledgement_reason.as_deref().unwrap_or("(none)")
            ),
        );
    }

    match state.execution_repo.acknowledge_execution_failure(exec_id, user_id, &reason).await {
        Ok(_) => mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "acknowledged": true,
                "execution_id": exec_id.to_string(),
                "reason": reason,
                "effect": "This failure will be excluded from the workflow's reliability score in get_readiness_breakdown. It remains in execution history.",
            }))
            .unwrap_or_default(),
        ),
        Err(e) => {
            tracing::error!(execution_id = %exec_id, "acknowledge_execution_failure DB error: {}", e);
            mcp_error(req_id, -32000, "Failed to acknowledge execution")
        }
    }
}

// ── cancel_queued_executions ─────────────────────────────────────────────────

async fn handle_cancel_queued_executions(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    // Validate limit: must be absent (→ default 1000) or a whole number in [1, 10000].
    // Non-integer JSON numbers (floats) fail as_i64() and are rejected as well.
    let limit = if let Some(limit_val) = args.get("limit") {
        match limit_val.as_i64() {
            Some(l) if (1..=10000).contains(&l) => l,
            _ => return mcp_error(req_id, -32602, "limit must be a positive integer (1–10000)"),
        }
    } else {
        1000
    };

    match state
        .execution_repo
        .cancel_queued_executions_for_workflow(wf_id, user_id, limit)
        .await
    {
        Ok(ids) => {
            let count = ids.len();
            tracing::info!(
                workflow_id = %wf_id,
                user_id = %user_id,
                count,
                "cancel_queued_executions: cancelled {} queued executions",
                count
            );
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "cancelled_count": count,
                    "workflow_id": wf_id.to_string(),
                    "cancelled_execution_ids": ids.iter().map(|id| id.to_string()).collect::<Vec<_>>(),
                    "note": if limit as usize == count {
                        format!("Cancelled {} executions (limit reached). Call again to continue draining.", count)
                    } else {
                        format!("Cancelled {} queued execution(s). Queue is now empty.", count)
                    }
                }))
                .unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!(workflow_id = %wf_id, "cancel_queued_executions failed: {}", e);
            mcp_error(req_id, -32000, "Failed to cancel queued executions")
        }
    }
}

// ── get_execution_lineage ────────────────────────────────────────────────────

async fn handle_get_execution_lineage(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let exec_id = match crate::utils::require_uuid(args, "execution_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // Step 1: Verify the execution exists using stable columns (no lineage columns).
    // Fails loudly with a proper error — never swallows DB errors silently.
    let base = match state
        .execution_repo
        .get_execution_base(exec_id, user_id)
        .await
    {
        Ok(row) => row,
        Err(e) => {
            tracing::error!(execution_id = %exec_id, "get_execution_lineage: DB error: {}", e);
            return mcp_error(req_id, -32000, "Database error looking up execution");
        }
    };

    let (status, wf_id_str, actor_id_str, trigger_type) = match base {
        None => return mcp_error(req_id, -32000, "Execution not found or access denied"),
        Some(row) => row,
    };

    // Step 2: Determine the tree root using lineage columns (added in migration 20260326000002).
    // These columns are plain UUID DEFAULT NULL — no FK constraints. If the migration has not yet
    // been applied, the query fails; we fall back to standalone view.
    let lineage_root: Uuid = match state
        .execution_repo
        .get_execution_lineage_root(exec_id, user_id)
        .await
    {
        Ok(Some((Some(root), _))) => root, // has an explicit root → use it
        Ok(Some((None, Some(parent)))) => parent, // parent is the root (no root set on it)
        Ok(Some((None, None))) | Ok(None) => exec_id, // standalone or not found
        Err(e) => {
            // Lineage columns likely don't exist yet — fall back to standalone view
            tracing::warn!(execution_id = %exec_id, "get_execution_lineage: lineage columns unavailable ({}), returning standalone view", e);
            exec_id
        }
    };

    // Step 3: Fetch the entire tree in a single flat query.
    // root: found by id = lineage_root; children: found by root_execution_id = lineage_root.
    // If lineage columns don't exist, fall back to returning just this execution.
    let tree = match state
        .execution_repo
        .get_execution_lineage_tree(lineage_root, user_id)
        .await
    {
        Ok(rows) if !rows.is_empty() => rows,
        Ok(_) | Err(_) => {
            // Fallback: return just this execution as a standalone entry.
            vec![(
                exec_id,
                None,
                None,
                status,
                wf_id_str,
                trigger_type,
                actor_id_str,
            )]
        }
    };

    let nodes: Vec<serde_json::Value> = tree
        .iter()
        .map(|(id, parent, root, exec_status, wf_id, trigger, actor)| {
            serde_json::json!({
                "execution_id": id.to_string(),
                "parent_execution_id": parent.map(|p| p.to_string()),
                "root_execution_id": root.map(|r| r.to_string()),
                "workflow_id": wf_id,
                "status": exec_status,
                "trigger_type": trigger,
                "actor_id": actor,
                "is_requested_execution": *id == exec_id,
                "is_root": parent.is_none(),
            })
        })
        .collect();

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "root_execution_id": lineage_root.to_string(),
            "requested_execution_id": exec_id.to_string(),
            "total_executions_in_lineage": nodes.len(),
            "lineage": nodes,
            "note": if nodes.len() == 1 {
                "This execution has no parent or child executions — it is a standalone run."
            } else {
                "Lineage includes all executions linked via root_execution_id."
            }
        }))
        .unwrap_or_default(),
    )
}

async fn handle_list_pending_approvals(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // MCP-179 (2026-05-08): replace silent-clamp with explicit
    // validation. Pre-fix `unwrap_or(20).min(100)` silently rewrote
    // 99999 → 100 with no signal to the caller.
    let limit = match crate::utils::validate_range_u64(args, "limit", 1, 100, 20, &req_id) {
        Ok(v) => v as i64,
        Err(resp) => return resp,
    };

    // execution_approvals.workflow_id is stored as execution_id (limitation in parallel.rs),
    // so the join goes via workflow_executions.id = execution_id for ownership + workflow name.
    let rows = state
        .execution_repo
        .list_pending_approvals_for_user(user_id, limit)
        .await;

    match rows {
        Ok(rows) => {
            let items: Vec<serde_json::Value> = rows
                .iter()
                .map(|r| {
                    let elapsed_secs = r.requested_at
                        .map(|t| (chrono::Utc::now() - t).num_seconds())
                        .unwrap_or(0);
                    serde_json::json!({
                        "execution_id": r.execution_id.to_string(),
                        "workflow_id": r.workflow_id.map(|id| id.to_string()),
                        "workflow_name": r.workflow_name,
                        "node_id": r.node_id.to_string(),
                        "required_for": r.required_for,
                        "requested_at": r.requested_at.map(|t| t.to_rfc3339()),
                        "waiting_seconds": elapsed_secs,
                        "action": "Call submit_workflow_approval with this execution_id to approve or reject"
                    })
                })
                .collect();

            // MCP-93 (2026-05-07): emit canonical `count` alongside legacy
            // `pending_count` so envelope tooling that keys on `count`
            // reads this surface uniformly.
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "count": items.len(),
                    "pending_count": items.len(),
                    "pending_approvals": items
                }))
                .unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("list_pending_approvals query failed: {}", e);
            mcp_error(req_id, -32000, "Failed to list pending approvals")
        }
    }
}

async fn handle_submit_workflow_approval(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let execution_id_str = match args.get("execution_id").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return mcp_error(req_id, -32602, "execution_id is required"),
    };
    let exec_id = match Uuid::parse_str(execution_id_str) {
        Ok(u) => u,
        Err(_) => return mcp_error(req_id, -32602, "Invalid execution_id UUID"),
    };
    // MCP-369 (2026-05-11): pre-fix `.and_then(|v| v.as_bool())` collapsed
    // wrong-type AND absent into the same None branch → "approved
    // (boolean) is required". Critical on this governance surface: an
    // operator passing `approved: "false"` (string, meaning "reject")
    // got told the field was missing. They might retry with
    // `approved: true` (correct shape) intending to "fix the format",
    // and accidentally APPROVE the action they wanted to REJECT.
    // Distinguish loudly so the operator knows the shape was wrong,
    // not the value.
    let approved = match args.get("approved") {
        None => return mcp_error(req_id, -32602, "approved (boolean) is required"),
        Some(v) => match v.as_bool() {
            Some(b) => b,
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!(
                        "approved must be a boolean (true or false), got {kind}. Note: JSON booleans are first-class — pass `true` or `false`, not `\"true\"` / `\"false\"` strings."
                    ),
                );
            }
        },
    };
    // MCP-1222 (2026-05-18): trim + length-cap + control-char gate on
    // the audit-trail reason. Pre-fix the field bound directly into
    // `update_execution_approval_decision` AND echoed back in the MCP
    // response: no trim (whitespace-only persisted, ragged dashboards),
    // no length cap (multi-MB strings into TEXT — DB write + response
    // amplification), no `\0`/control-char rejection (embedded `\0`
    // crashed the UPDATE with an opaque "invalid input syntax for type
    // text"). Sibling drift to MCP-867 (2026-05-14) which closed the
    // same gap on the GraphQL `approve_execution` / `deny_execution`
    // mutations via `validate_description_content("approval reason", s,
    // 1000)`. The MCP `submit_workflow_approval` handler was the
    // missed cross-protocol sibling. 1000-char cap matches GraphQL.
    let reason_opt_owned = match crate::utils::validate_multiline_description(
        "reason",
        args.get("reason").and_then(|v| v.as_str()),
        1000,
        "Omit the field entirely to record no reason.",
        req_id.clone(),
    ) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let reason = reason_opt_owned.clone().unwrap_or_default();

    // SECURITY: verify the authenticated user owns this execution before allowing
    // them to approve/reject it.
    let owner = state
        .execution_repo
        .get_workflow_execution_owner(exec_id)
        .await
        .unwrap_or(None);

    match owner {
        Some(owner_id) if owner_id == user_id => {} // authorised
        Some(_) => {
            // Log distinct telemetry server-side, but never differentiate this from
            // "no such execution" in the response — distinguishing them would leak
            // existence of other users' executions.
            tracing::warn!(
                %user_id,
                %exec_id,
                "submit_workflow_approval: execution belongs to a different user"
            );
            return mcp_error(req_id, -32000, "Execution not found or access denied");
        }
        None => {
            return mcp_error(req_id, -32000, "Execution not found or access denied");
        }
    }

    // --- Inline Human_Approval_Gate via Redis + NATS ---
    // The Human_Approval_Gate WASM module stores key "approval:{exec_id}" in Redis
    // containing the NATS reply topic.  Publishing "true"/"false" unblocks the waiting WASM.
    let mut nats_published = false;
    if let Some(ref redis) = state.registry.redis_client {
        match redis.get_multiplexed_tokio_connection().await {
            Ok(mut con) => {
                let redis_key = format!("approval:{}", exec_id);
                // MCP-999 (2026-05-15): MCP-535 sibling on Redis side.
                // Pre-fix `.unwrap_or(None)` collapsed Err(redis_error)
                // into "no key" → fell through to the DB-backed approval
                // path silently. Operators saw approvals seemingly
                // succeed via the DB branch even when Redis-side
                // inline-approval signalling was failing — masking
                // partial outages where ongoing WASM
                // Human_Approval_Gate executions stop receiving NATS
                // signal but the gate row updates normally. Log the
                // Redis error explicitly; behaviour (fall through to
                // DB) is unchanged. Sibling at
                // talos-webhooks/src/lib.rs::approval_handler in the
                // same commit.
                let reply_topic: Option<String> = match redis::cmd("GET")
                    .arg(&redis_key)
                    .query_async::<Option<String>>(&mut con)
                    .await
                {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::error!(
                            %exec_id,
                            error = %e,
                            "submit_workflow_approval: Redis GET for approval reply-topic failed; \
                             falling through to DB-backed approval path"
                        );
                        None
                    }
                };

                if let Some(topic) = reply_topic {
                    // SECURITY: validate the topic before publishing. The topic is stored in Redis
                    // by a WASM module. Reject wildcards and non-printable ASCII to prevent NATS
                    // subject injection.
                    let topic_safe = !topic.is_empty()
                        && topic.len() <= 512
                        && topic
                            .bytes()
                            .all(|b| b.is_ascii() && b >= 0x20 && b != b'*' && b != b'>');
                    if !topic_safe {
                        tracing::error!(%exec_id, "SECURITY: approval reply topic from Redis failed validation");
                        return mcp_error(req_id, -32000, "Invalid approval routing data");
                    }
                    if let Some(ref nats) = state.nats_client {
                        let response_str = if approved { "true" } else { "false" };
                        match nats.publish(topic.clone(), response_str.into()).await {
                            Ok(_) => {
                                // Best-effort cleanup of the Redis key
                                let _: redis::RedisResult<()> = redis::cmd("DEL")
                                    .arg(&redis_key)
                                    .query_async(&mut con)
                                    .await;
                                nats_published = true;
                                tracing::info!(
                                    %exec_id,
                                    approved,
                                    topic,
                                    "submit_workflow_approval: published inline approval to NATS"
                                );
                            }
                            Err(e) => {
                                tracing::error!(%exec_id, "Failed to publish approval to NATS: {}", e);
                                return mcp_error(req_id, -32000, "Failed to send approval signal");
                            }
                        }
                    } else {
                        return mcp_error(
                            req_id,
                            -32000,
                            "NATS not available — cannot deliver approval",
                        );
                    }
                }
                // No Redis key means this is not an inline Human_Approval_Gate execution —
                // fall through to the DB-backed approval update below.
            }
            Err(e) => {
                tracing::error!("submit_workflow_approval: Redis connection failed: {}", e);
                // Don't fail hard — maybe it's a DB-only gate, try DB path
            }
        }
    }

    // --- DB-backed approval gates (execution_approvals table) ---
    // Updates any pending row for this execution to approved/denied with reason and actor.
    let status_val = if approved { "approved" } else { "denied" };
    let reason_opt: Option<&str> = if reason.is_empty() {
        None
    } else {
        Some(&reason)
    };
    let db_rows_updated = match state
        .execution_repo
        .update_execution_approval_decision(exec_id, status_val, user_id, reason_opt)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(%exec_id, "submit_workflow_approval: DB update failed: {:#}", e);
            0
        }
    };

    if !nats_published && db_rows_updated == 0 {
        return mcp_error(
            req_id,
            -32000,
            "No pending approval found for this execution. It may have already been decided, timed out, or the execution is not waiting for approval.",
        );
    }

    tracing::info!(
        %exec_id,
        %user_id,
        approved,
        db_rows_updated,
        nats_published,
        "submit_workflow_approval: decision recorded"
    );

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "execution_id": exec_id.to_string(),
            "decision": if approved { "approved" } else { "rejected" },
            "reason": reason,
            "inline_signal_sent": nats_published,
            "db_rows_updated": db_rows_updated,
            "message": if approved {
                "Execution approved — it will continue processing."
            } else {
                "Execution rejected — it will fail with an approval denied error."
            }
        }))
        .unwrap_or_default(),
    )
}

/// Get the input and output for a specific node in a workflow execution.
async fn handle_get_node_io(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let exec_id = match crate::utils::require_uuid(args, "execution_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    // MCP-226 (2026-05-08): trim node_id at the boundary.
    let node_id_str = match args.get("node_id").and_then(|v| v.as_str()) {
        Some(id) if !id.trim().is_empty() => id.trim(),
        _ => return mcp_error(req_id, -32602, "Missing or empty node_id"),
    };

    // Load execution (ownership check)
    let exec = match state.execution_repo.get_execution(exec_id, user_id).await {
        Ok(Some(e)) => e,
        Ok(None) => return mcp_error(req_id, -32000, "Execution not found or access denied"),
        Err(e) => {
            tracing::error!(execution_id = %exec_id, "get_node_io: load failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to load execution");
        }
    };
    let workflow_id = exec.workflow_id;

    // Build UUID -> label mapping from graph_json
    let graph_json_opt = state
        .execution_repo
        .get_workflow_graph_for_user(workflow_id, user_id)
        .await
        .ok()
        .flatten();
    let node_label_map = build_node_label_map(graph_json_opt);

    // Resolve the user-provided label to a node UUID
    let node_uuid = node_label_map
        .iter()
        .find(|(_, label)| label.as_str() == node_id_str)
        .map(|(uuid, _)| *uuid)
        .unwrap_or_else(|| {
            // Fall back: try parsing as UUID directly, or SHA256-derive it
            node_id_str.parse::<Uuid>().unwrap_or_else(|_| {
                use sha2::{Digest, Sha256};
                let hash = Sha256::digest(node_id_str.as_bytes());
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(&hash[..16]);
                Uuid::from_bytes(bytes)
            })
        });

    // Query execution_events for node_input event
    let node_input = match state
        .execution_repo
        .get_latest_node_input_event(exec_id, node_uuid)
        .await
    {
        Ok(opt) => opt,
        Err(e) => {
            tracing::warn!(error = %e, "get_node_io: failed to query node_input events");
            None
        }
    };

    // Parse input as JSON if possible, otherwise return as string.
    //
    // MCP-32: the engine truncates oversized node_input previews with
    // a literal "...(truncated)" suffix, which makes the stored
    // log_message an invalid-JSON tail of a valid-JSON head. Strip
    // the suffix before parsing so the structured object operators
    // expect comes back; on failure (genuinely-bad JSON) fall back to
    // the wrapped-string shape with a `truncated_preview` flag so the
    // operator knows the structure couldn't be recovered.
    //
    // MCP-41: redact any `__actor_context__` memory values before
    // returning. Same security invariant as get_execution_logs:
    // node-input projections must not leak what list_actor_memories
    // hides.
    let input_value = match &node_input {
        Some(s) => {
            let redacted_str = redact_actor_context_in_log(s);
            const TRUNCATION_SUFFIX: &str = "...(truncated)";
            let parse_target = redacted_str
                .strip_suffix(TRUNCATION_SUFFIX)
                .unwrap_or(&redacted_str);
            match serde_json::from_str::<serde_json::Value>(parse_target) {
                Ok(v) => v,
                Err(_) => serde_json::json!({
                    "truncated_preview": redacted_str,
                    "note": "log_message could not be parsed as JSON (likely truncated mid-structure). The value is the raw stored preview."
                }),
            }
        }
        None => serde_json::Value::Null,
    };

    // Extract node output from execution output_data. The engine's
    // canonical output map is keyed by node UUID (the SHA-256-derived
    // form OR the rf_id verbatim when it parsed as a UUID), so the
    // resolved `node_uuid` is the primary lookup. Fall back to the raw
    // rf_id and to nested "nodes"/"results" objects to stay friendly to
    // legacy / alternate-shape outputs.
    let node_uuid_str = node_uuid.to_string();
    let output_value = exec
        .output_data
        .as_ref()
        .and_then(|data| {
            data.get(&node_uuid_str)
                .or_else(|| data.get(node_id_str))
                .or_else(|| {
                    data.get("nodes")
                        .or_else(|| data.get("results"))
                        .and_then(|n| n.get(&node_uuid_str).or_else(|| n.get(node_id_str)))
                })
                .cloned()
        })
        .unwrap_or(serde_json::Value::Null);

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "node_id": node_id_str,
            "input": input_value,
            "output": output_value,
        }))
        .unwrap_or_default(),
    )
}

#[cfg(test)]
mod redact_actor_context_tests {
    use super::redact_actor_context_in_log;
    use serde_json::json;

    #[test]
    fn redacts_actor_context_memory_values() {
        let payload = json!({
            "__actor_context__": {
                "actor_id": "c1362f85-1a2c-4a61-8b4b-7b99b7653c03",
                "memories": [
                    {"key": "daily_brief/2026-05-07", "type": "episodic", "value": {"brief": "secret content here"}},
                    {"key": "daily_brief/2026-05-06", "type": "episodic", "value": "more secret"}
                ]
            },
            "MAX_TOKENS": 2048
        });
        let s = serde_json::to_string(&payload).unwrap();
        let redacted = redact_actor_context_in_log(&s);
        assert!(redacted.contains("[REDACTED]"));
        assert!(!redacted.contains("secret content here"));
        assert!(!redacted.contains("more secret"));
        // Structure preserved for debugging.
        assert!(redacted.contains("daily_brief/2026-05-07"));
        assert!(redacted.contains("daily_brief/2026-05-06"));
        assert!(redacted.contains("episodic"));
        // Other fields untouched.
        assert!(redacted.contains("\"MAX_TOKENS\":2048"));
    }

    #[test]
    fn no_actor_context_returns_unchanged() {
        let payload = json!({"MAX_TOKENS": 2048, "MODEL": "claude-sonnet-4-6"});
        let s = serde_json::to_string(&payload).unwrap();
        let out = redact_actor_context_in_log(&s);
        assert_eq!(out, s);
    }

    #[test]
    fn invalid_json_passes_through() {
        let s = "not actually json";
        let out = redact_actor_context_in_log(s);
        assert_eq!(out, s);
    }

    #[test]
    fn handles_actor_context_with_no_memories() {
        let payload = json!({"__actor_context__": {"actor_id": "x", "memories": []}});
        let s = serde_json::to_string(&payload).unwrap();
        let out = redact_actor_context_in_log(&s);
        assert_eq!(out, s);
    }

    #[test]
    fn redacts_nested_actor_context() {
        // Some node configs nest the inject under data.config.__actor_context__
        let payload = json!({
            "data": {
                "config": {
                    "__actor_context__": {
                        "memories": [{"key": "k", "value": "secret"}]
                    }
                }
            }
        });
        let s = serde_json::to_string(&payload).unwrap();
        let out = redact_actor_context_in_log(&s);
        assert!(out.contains("[REDACTED]"));
        assert!(!out.contains("\"secret\""));
    }

    #[test]
    fn memory_without_value_field_is_safe() {
        // Defensive: redactor must not panic if a memory entry has no "value" field.
        let payload = json!({
            "__actor_context__": {"memories": [{"key": "k", "type": "episodic"}]}
        });
        let s = serde_json::to_string(&payload).unwrap();
        let out = redact_actor_context_in_log(&s);
        assert_eq!(out, s);
    }
}
