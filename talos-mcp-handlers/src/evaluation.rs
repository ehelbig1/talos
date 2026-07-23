//! Memory-grounding evaluation MCP surface.
//!
//! Thin handlers per the architectural mandate: parse → validate → service →
//! format. All logic lives in `talos-evaluation`.
//!
//! - `run_memory_ab_eval` — the controlled causal experiment: run each task
//!   twice (memory grounding ON vs OFF), judge both with a TIER-GATED judge
//!   (tier-1 actors judged on local Ollama only), aggregate the paired lift.
//!   SYNCHRONOUS: keep the task set small (each task = 2 workflow executions +
//!   2 judge calls); it returns the full summary inline.
//! - `memory_grounding_report` — the cheap OBSERVATIONAL signal from accrued
//!   provenance (correlation of memory relevance with judge outcome). Read-only.

use super::types::JsonRpcResponse;
use super::utils::{mcp_error, mcp_text};
use super::McpState;
use serde_json::Value;
use std::sync::Arc;
use talos_evaluation::{EvalRunInput, EvalTask, EvaluationError, EvaluationService};
use uuid::Uuid;

pub fn tool_schemas() -> Vec<Value> {
    vec![
        serde_json::json!({
            "name": "run_memory_ab_eval",
            "description": "CONTROLLED A/B: measure whether MEMORY GROUNDING makes an actor's responses better. Runs each task twice — memory ON vs OFF (the inject_memory_context toggle) — judges each output with a tier-gated LLM judge (tier-1 actors judged on LOCAL Ollama only; the actor's private data never reaches an external provider), and aggregates the paired lift: mean score delta, per-arm pass rates, win/loss/tie tally, a two-sided sign-test p-value, and a verdict (improves/regresses/inconclusive). SYNCHRONOUS and expensive: each task = 2 workflow executions + 2 judge calls, so keep the task set small (2-5). Returns the full summary + per-task detail inline.",
            "inputSchema": { "type": "object", "properties": {
                "actor_id": { "type": "string", "description": "The actor whose memory grounding is under test (also the trigger agent, so its memory is injected on the ON arm)" },
                "tasks": {
                    "type": "array",
                    "description": "The eval set — each task is replayed under both arms",
                    "items": { "type": "object", "properties": {
                        "label": { "type": "string", "description": "Human label for this task" },
                        "workflow_id": { "type": "string", "description": "The actor-bound workflow to run" },
                        "trigger_input": { "description": "The workflow's __trigger__ input (any JSON; default {})" }
                    }, "required": ["label", "workflow_id"] }
                },
                "judge_model": { "type": "string", "description": "Local judge model override for the tier-1 path (default qwen3.6)" },
                "wait_ms": { "type": "integer", "description": "Per-arm synchronous wait in ms (default 120000; clamped 1000-300000)" }
            }, "required": ["actor_id", "tasks"] }
        }),
        serde_json::json!({
            "name": "memory_grounding_report",
            "description": "OBSERVATIONAL memory-grounding signal from already-accrued provenance (execution_memory_context joined to judge_scores). Within executions that carried memory, does higher mean relevance track a better judge outcome? Reports point-biserial correlations (relevance→pass, count→pass), a median-split pass-rate comparison, and overall pass rate. Correlational ONLY — it cannot prove ON-vs-OFF causation (memory-OFF runs leave no provenance); use run_memory_ab_eval for the causal answer. Read-only, instant.",
            "inputSchema": { "type": "object", "properties": {
                "actor_id": { "type": "string", "description": "The actor to analyze" },
                "since_days": { "type": "integer", "description": "Lookback window in days (default 30, clamped 1-365)" }
            }, "required": ["actor_id"] }
        }),
    ]
}

pub async fn dispatch(
    tool_name: &str,
    req_id: Option<Value>,
    args: &Value,
    state: &McpState,
    agent: Arc<super::auth::AgentIdentity>,
) -> Option<JsonRpcResponse> {
    if tool_name != "run_memory_ab_eval" && tool_name != "memory_grounding_report" {
        return None;
    }
    let Some(user_id) = agent.user_id else {
        return Some(mcp_error(
            req_id,
            -32000,
            "memory evaluation tools require a user-bound agent identity",
        ));
    };
    match tool_name {
        "run_memory_ab_eval" => Some(handle_run_ab_eval(req_id, args, state, user_id).await),
        "memory_grounding_report" => {
            Some(handle_grounding_report(req_id, args, state, user_id).await)
        }
        _ => None,
    }
}

/// Build the service from `McpState` (cheap — all `Arc`/pool clones).
fn eval_service(state: &McpState) -> EvaluationService {
    EvaluationService::new(
        state.execution_orchestration_service.clone(),
        state.execution_repo.clone(),
        state.actor_repo.clone(),
        state.secrets_manager.clone(),
        state.ollama_client.clone(),
        state.db_pool.clone(),
    )
}

/// Tenancy gate: the actor must be owned by the calling user. Both eval tools
/// read/act on actor-scoped data, so a foreign `actor_id` must be refused
/// (defense in depth alongside the user-scoped execution reads). A single
/// not-found/foreign message avoids enumerating other tenants' actor ids.
async fn ensure_actor_owner(state: &McpState, actor_id: Uuid, user_id: Uuid) -> Result<(), String> {
    match state.actor_repo.get_actor_owner_user_id(actor_id).await {
        Ok(Some(owner)) if owner == user_id => Ok(()),
        Ok(_) => Err("actor not found or not owned by you".to_string()),
        Err(_) => Err("actor ownership check failed".to_string()),
    }
}

fn parse_uuid_field(v: &Value, key: &str) -> Result<Uuid, String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("missing or non-string '{key}'"))
        .and_then(|s| Uuid::parse_str(s).map_err(|_| format!("'{key}' is not a valid UUID")))
}

/// Map a service error to the JSON-RPC surface with its stable code + a
/// user-safe message (Internal is already collapsed by `user_facing_message`).
fn eval_err(req_id: Option<Value>, e: &EvaluationError) -> JsonRpcResponse {
    if let EvaluationError::Internal(inner) = e {
        tracing::error!(target: "talos_evaluation", error = %inner, "memory eval failed");
    }
    mcp_error(req_id, e.jsonrpc_code(), &e.user_facing_message())
}

async fn handle_run_ab_eval(
    req_id: Option<Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let actor_id = match parse_uuid_field(args, "actor_id") {
        Ok(v) => v,
        Err(m) => return mcp_error(req_id, -32602, &m),
    };
    if let Err(m) = ensure_actor_owner(state, actor_id, user_id).await {
        return mcp_error(req_id, -32004, &m);
    }
    let Some(task_vals) = args.get("tasks").and_then(|v| v.as_array()) else {
        return mcp_error(req_id, -32602, "missing 'tasks' array");
    };
    let mut tasks = Vec::with_capacity(task_vals.len());
    for (i, tv) in task_vals.iter().enumerate() {
        let workflow_id = match parse_uuid_field(tv, "workflow_id") {
            Ok(v) => v,
            Err(m) => return mcp_error(req_id, -32602, &format!("task[{i}]: {m}")),
        };
        let label = tv
            .get("label")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| format!("task-{i}"));
        let trigger_input = tv.get("trigger_input").cloned().unwrap_or(Value::Null);
        tasks.push(EvalTask {
            label,
            workflow_id,
            trigger_input,
        });
    }
    let judge_model = args
        .get("judge_model")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let wait_ms = args
        .get("wait_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(120_000);

    let svc = eval_service(state);
    match svc
        .run_ab_eval(EvalRunInput {
            actor_id,
            user_id,
            tasks,
            judge_model,
            wait_ms,
        })
        .await
    {
        Ok(outcome) => mcp_text(
            req_id,
            &serde_json::to_string_pretty(&outcome).unwrap_or_default(),
        ),
        Err(e) => eval_err(req_id, &e),
    }
}

async fn handle_grounding_report(
    req_id: Option<Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let actor_id = match parse_uuid_field(args, "actor_id") {
        Ok(v) => v,
        Err(m) => return mcp_error(req_id, -32602, &m),
    };
    if let Err(m) = ensure_actor_owner(state, actor_id, user_id).await {
        return mcp_error(req_id, -32004, &m);
    }
    let since_days = args
        .get("since_days")
        .and_then(|v| v.as_i64())
        .unwrap_or(30);

    let svc = eval_service(state);
    match svc.observational_report(actor_id, since_days).await {
        Ok(report) => mcp_text(
            req_id,
            &serde_json::to_string_pretty(&report).unwrap_or_default(),
        ),
        Err(e) => eval_err(req_id, &e),
    }
}
