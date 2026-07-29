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
            "description": "CONTROLLED A/B: measure whether MEMORY GROUNDING makes an actor's responses better. Runs each task twice — memory ON vs OFF (the inject_memory_context toggle) — judges each output with a tier-gated LLM judge (tier-1 actors judged on LOCAL Ollama only; the actor's private data never reaches an external provider), and aggregates the paired lift: mean score delta, per-arm pass rates, win/loss/tie tally, a two-sided sign-test p-value, and a verdict (improves/regresses/inconclusive). SYNCHRONOUS and expensive: each task = 2 workflow executions + 2 judge calls (polled to true completion up to wait_ms), so keep the task set small (2-5, hard max 10). Eval workflows should be READ-ONLY — the ON arm runs against LIVE actor memory, so a workflow that writes memory (__memory_write__) would mutate state mid-run and make results non-reproducible. Returns the full summary + per-task detail inline.",
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
        Ok(report) => mcp_text(req_id, &render_grounding_report(&report, since_days)),
        Err(e) => eval_err(req_id, &e),
    }
}

/// The window disclosure the report itself cannot carry: `since_days` is a
/// caller argument that the pure stats kernel never sees, so before this the
/// handler silently DROPPED it and a 7-day report rendered identically to a
/// 365-day one (S3, 2026-07-28). Additive: every existing field is untouched.
///
/// Pure + `pub(crate)` so the echo is unit-tested against real production code.
pub(crate) fn render_grounding_report(
    report: &talos_evaluation::stats::ObservationalReport,
    since_days: i64,
) -> String {
    let mut body = serde_json::to_value(report).unwrap_or_default();
    if let Some(obj) = body.as_object_mut() {
        // The EFFECTIVE window, not the requested one: the service clamps to
        // [1, 365], so echoing the raw argument would render
        // "trailing 5000 days" over a 365-day query — the defect this change
        // exists to remove, reintroduced by the fix for it.
        let effective = talos_evaluation::effective_since_days(since_days);
        obj.insert("since_days".into(), serde_json::json!(effective));
        obj.insert(
            "window".into(),
            serde_json::json!(format!("trailing {effective} days")),
        );
        if effective != since_days {
            obj.insert("since_days_requested".into(), serde_json::json!(since_days));
            obj.insert(
                "since_days_note".into(),
                serde_json::json!(format!(
                    "requested since_days={since_days} was clamped to {effective} \
                     (allowed range 1-365); every number below covers the clamped window"
                )),
            );
        }
        obj.insert(
            "population_note".into(),
            serde_json::json!(format!(
                "POPULATION: only executions of this actor that had MEMORY CONTEXT INJECTED are \
                 eligible at all (rows come from execution_memory_context, and the window is on \
                 that provenance row's timestamp, not on the execution's own clock); an execution \
                 that ran without memory is invisible here. At most the {cap} most recent eligible \
                 executions in the window are read — a busier actor gets a silently partial \
                 window. n_labeled counts those executions that ALSO carry a judge verdict; \
                 abstentions are not verdicts and are excluded at the source \
                 (judge_scores NOT not_applicable). Every statistic below is over n_labeled, \
                 never over all executions, and overall_pass_rate is a bare 0.0 when \
                 n_labeled = 0 — read n_labeled first. mean_judge_score is over \
                 n_scored (labeled executions that also carry a numeric score), NOT n_labeled. \
                 pass_rate_high/low_relevance are over n_high/n_low, the two halves of a median \
                 split on mean relevance; ties land in the high half, so the halves can be \
                 lopsided and n_high/n_low are the only way to see that. \
                 corr_*_ci95 are Fisher-z intervals and APPROXIMATE here: the judge pass is a 0/1 \
                 outcome, not a normal one, so coverage degrades as the pass rate approaches 0 or \
                 1 — read an interval as \"could this be zero?\", never as an exact bound. \
                 Correlations are OBSERVATIONAL — memory-OFF runs leave \
                 no provenance, so nothing here is causal.",
                cap = talos_evaluation::OBSERVATIONAL_ROW_CAP,
            )),
        );
    }
    serde_json::to_string_pretty(&body).unwrap_or_default()
}

/// S3 (measurement envelope, 2026-07-28): the handler owns `since_days` and
/// used to drop it, so a 7-day report rendered identically to a 365-day one.
#[cfg(test)]
mod grounding_report_window_tests {
    use super::render_grounding_report;
    use talos_evaluation::stats::{analyze_observational, ObservationalRow};

    fn report(n: usize) -> talos_evaluation::stats::ObservationalReport {
        let rows: Vec<ObservationalRow> = (0..n)
            .map(|i| ObservationalRow {
                mean_fused: if i % 2 == 0 { 0.8 } else { 0.2 },
                mem_count: i as i64,
                judge_passed: Some(i % 3 != 0),
                judge_score: Some(0.5),
            })
            .collect();
        analyze_observational(&rows)
    }

    #[test]
    fn since_days_is_echoed_and_the_window_is_named() {
        let r = report(10);
        let v: serde_json::Value = serde_json::from_str(&render_grounding_report(&r, 7)).unwrap();
        assert_eq!(v["since_days"], 7);
        assert_eq!(v["window"], "trailing 7 days");
        // Two different windows must not produce identical output.
        let other: serde_json::Value =
            serde_json::from_str(&render_grounding_report(&r, 365)).unwrap();
        assert_ne!(v, other, "the window must be visible in the output");
        assert_eq!(other["since_days"], 365);
    }

    #[test]
    fn every_report_field_survives_the_wrapping() {
        let r = report(10);
        let v: serde_json::Value = serde_json::from_str(&render_grounding_report(&r, 30)).unwrap();
        for k in [
            "n_labeled",
            "overall_pass_rate",
            "corr_relevance_pass",
            "corr_relevance_pass_ci95",
            "corr_count_pass",
            "corr_count_pass_ci95",
            "pass_rate_high_relevance",
            "pass_rate_low_relevance",
            "n_high",
            "n_low",
            "mean_judge_score",
            "n_scored",
        ] {
            assert!(
                v.as_object().unwrap().contains_key(k),
                "{k} missing from the rendered report"
            );
        }
        assert_eq!(v["n_labeled"], 10);
        assert_eq!(v["n_scored"], 10);
    }

    /// Phase-2 finding: the echo must be the window the QUERY used, not the
    /// caller's raw argument — `observational_report` clamps to [1, 365], so
    /// echoing 5000 would have reintroduced the exact defect being fixed.
    #[test]
    fn an_out_of_range_window_echoes_the_clamped_value_and_says_it_clamped() {
        let r = report(10);
        let v: serde_json::Value =
            serde_json::from_str(&render_grounding_report(&r, 5000)).unwrap();
        assert_eq!(v["since_days"], 365, "the echo must be the clamped window");
        assert_eq!(v["window"], "trailing 365 days");
        assert_eq!(v["since_days_requested"], 5000);
        let note = v["since_days_note"].as_str().unwrap();
        assert!(note.contains("clamped to 365"), "{note}");
        // The low end clamps too (0 or negative → 1).
        let z: serde_json::Value = serde_json::from_str(&render_grounding_report(&r, 0)).unwrap();
        assert_eq!(z["since_days"], 1);
        assert_eq!(z["window"], "trailing 1 days");
        // An in-range window carries no clamp noise.
        let ok: serde_json::Value = serde_json::from_str(&render_grounding_report(&r, 30)).unwrap();
        let obj = ok.as_object().unwrap();
        assert!(!obj.contains_key("since_days_requested"));
        assert!(!obj.contains_key("since_days_note"));
    }

    /// Phase-2 finding: the note must disclose that the population is
    /// memory-context rows (not all executions), that it is capped, and that
    /// the correlation intervals are approximate for a 0/1 outcome.
    #[test]
    fn population_note_discloses_eligibility_the_cap_and_the_ci_caveat() {
        let v: serde_json::Value =
            serde_json::from_str(&render_grounding_report(&report(10), 30)).unwrap();
        let note = v["population_note"].as_str().unwrap();
        assert!(note.contains("MEMORY CONTEXT INJECTED"), "{note}");
        assert!(note.contains("execution_memory_context"), "{note}");
        assert!(
            note.contains(&talos_evaluation::OBSERVATIONAL_ROW_CAP.to_string()),
            "the row cap must be stated and must track the constant: {note}"
        );
        assert!(note.contains("APPROXIMATE"), "{note}");
        assert!(
            note.contains("never as an exact bound"),
            "a Fisher-z interval on a 0/1 outcome must not read as exact: {note}"
        );
        assert!(
            note.contains("overall_pass_rate is a bare 0.0 when"),
            "a rate over a zero denominator must be disclosed: {note}"
        );
    }

    #[test]
    fn population_note_names_each_denominator() {
        let v: serde_json::Value =
            serde_json::from_str(&render_grounding_report(&report(10), 30)).unwrap();
        let note = v["population_note"].as_str().unwrap();
        assert!(note.contains("n_scored"), "{note}");
        assert!(note.contains("NOT n_labeled"), "{note}");
        assert!(note.contains("n_high/n_low"), "{note}");
        assert!(
            note.contains("nothing here is causal"),
            "an observational correlation must say so: {note}"
        );
    }
}
