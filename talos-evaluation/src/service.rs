//! [`EvaluationService`] — the controlled A/B + observational orchestration.

use std::sync::Arc;

use chrono::{Duration, Utc};
use serde::Serialize;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

use talos_actor_repository::{ActorRepository, LlmTierDecision};
use talos_execution_orchestration::{
    ExecutionOrchestrationService, OrchestrationError, TriggerInput, TriggerOutcome,
};
use talos_execution_repository::ExecutionRepository;
use talos_llm::{LlmClient, OllamaClient};
use talos_secrets_manager::SecretsManager;

use crate::error::EvaluationError;
use crate::stats::{aggregate_paired, analyze_observational, EvalSummary, PairedResult};

/// Max eval tasks per run (each costs 2 workflow executions + 2 judge calls).
const MAX_TASKS: usize = 50;
/// Clamp for the per-arm synchronous wait.
const MAX_WAIT_MS: u64 = 300_000;
const MIN_WAIT_MS: u64 = 1_000;
/// Judge output token budget — a score + one-sentence reason is small.
const JUDGE_MAX_TOKENS: u32 = 512;
/// Byte caps so a large workflow output / task input can't blow the judge prompt.
const OUTPUT_CAP: usize = 8_000;
const INPUT_CAP: usize = 2_000;
/// Default local judge model (tier-1). Overridable per run.
const DEFAULT_JUDGE_MODEL: &str = "qwen3.6";

/// The judge rubric. Deliberately rewards GROUNDING/personalization — the thing
/// memory provides — so a fluent-but-generic answer cannot score as well as a
/// specific, context-grounded one. The judge is BLIND to which arm (memory ON
/// vs OFF) produced the response; it only ever sees the task + the response.
const JUDGE_SYSTEM: &str = "You are a strict evaluator of an AI personal assistant's response. \
You are given the TASK the assistant was asked to do and its RESPONSE. Rate how well the response is \
GROUNDED IN and PERSONALIZED TO the specific user's real context — their people, projects, commitments, \
history, and preferences. Reward responses that surface concrete, specific, plausibly-correct personal \
details relevant to the task. Penalize generic, vague, or hedging answers, and answers that claim to lack \
information when the task clearly concerns the user's own context. Judge ONLY response quality for THIS \
user and task; do not reward verbosity. Return JSON {\"score\": 0.0-1.0, \"passed\": boolean, \
\"reasoning\": one short sentence}. Set passed=true when score >= 0.6.";

/// JSON Schema for the judge's structured verdict — feeds both the local
/// (Ollama `format`) and external (Anthropic tool `input_schema`) paths.
fn judge_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "score": { "type": "number", "description": "Quality in [0,1]." },
            "passed": { "type": "boolean" },
            "reasoning": { "type": "string", "description": "One short sentence." }
        },
        "required": ["score", "passed", "reasoning"]
    })
}

/// One eval task: a workflow + the trigger input to replay under both arms.
#[derive(Clone, Debug)]
pub struct EvalTask {
    pub label: String,
    pub workflow_id: Uuid,
    pub trigger_input: Value,
}

/// Input to a controlled A/B run.
pub struct EvalRunInput {
    /// The actor whose memory grounding is under test (also the trigger agent,
    /// so its memory is the one injected on the ON arm).
    pub actor_id: Uuid,
    /// Tenancy — every execution + output read is scoped to this user.
    pub user_id: Uuid,
    pub tasks: Vec<EvalTask>,
    /// Local judge model override (tier-1 path). `None` → [`DEFAULT_JUDGE_MODEL`].
    pub judge_model: Option<String>,
    /// Per-arm synchronous wait, clamped to `[MIN_WAIT_MS, MAX_WAIT_MS]`.
    pub wait_ms: u64,
}

/// One arm's outcome.
#[derive(Clone, Debug, Serialize)]
pub struct ArmResult {
    pub execution_id: Uuid,
    pub status: String,
    pub score: f64,
    pub passed: bool,
    pub reasoning: String,
}

/// A task evaluated under both arms.
#[derive(Clone, Debug, Serialize)]
pub struct EvalTaskResult {
    pub label: String,
    pub on: ArmResult,
    pub off: ArmResult,
}

/// A task that could not be evaluated (dispatch or judge failure) — recorded
/// rather than aborting the whole run, so the pair set stays balanced.
#[derive(Clone, Debug, Serialize)]
pub struct SkippedTask {
    pub label: String,
    pub reason: String,
}

/// Full controlled-A/B outcome.
#[derive(Clone, Debug, Serialize)]
pub struct EvalRunOutcome {
    pub summary: EvalSummary,
    pub per_task: Vec<EvalTaskResult>,
    pub skipped: Vec<SkippedTask>,
    /// "local" (tier-1 Ollama) or "external" (tier-2) — which judge ran.
    pub judge_backend: String,
    pub judge_model: String,
}

/// Which judge backend the actor's tier permits.
enum JudgeBackend {
    /// Tier-1 — judge on local Ollama only.
    Local(String),
    /// Tier-2 — judge on the external provider.
    External,
}

impl JudgeBackend {
    fn label(&self) -> &'static str {
        match self {
            JudgeBackend::Local(_) => "local",
            JudgeBackend::External => "external",
        }
    }
    fn model(&self) -> String {
        match self {
            JudgeBackend::Local(m) => m.clone(),
            JudgeBackend::External => "claude-haiku-4-5".to_string(),
        }
    }
}

/// Stateless bundle of the deps the two eval methods need. Cheap to construct
/// per call from `McpState` fields (all `Arc`/pool clones); cross-protocol
/// ready if a GraphQL consumer ever wants the same `Arc`.
#[derive(Clone)]
pub struct EvaluationService {
    orchestration: Arc<ExecutionOrchestrationService>,
    execution_repo: Arc<ExecutionRepository>,
    actor_repo: Arc<ActorRepository>,
    secrets_manager: Arc<SecretsManager>,
    ollama: Option<Arc<OllamaClient>>,
    pool: PgPool,
}

impl EvaluationService {
    pub fn new(
        orchestration: Arc<ExecutionOrchestrationService>,
        execution_repo: Arc<ExecutionRepository>,
        actor_repo: Arc<ActorRepository>,
        secrets_manager: Arc<SecretsManager>,
        ollama: Option<Arc<OllamaClient>>,
        pool: PgPool,
    ) -> Self {
        Self {
            orchestration,
            execution_repo,
            actor_repo,
            secrets_manager,
            ollama,
            pool,
        }
    }

    /// Controlled A/B: run every task under memory-ON and memory-OFF, judge
    /// each output with the tier-appropriate judge, aggregate the paired deltas.
    pub async fn run_ab_eval(
        &self,
        input: EvalRunInput,
    ) -> Result<EvalRunOutcome, EvaluationError> {
        if input.tasks.is_empty() {
            return Err(EvaluationError::InvalidArgument(
                "no eval tasks provided".into(),
            ));
        }
        if input.tasks.len() > MAX_TASKS {
            return Err(EvaluationError::InvalidArgument(format!(
                "too many tasks ({}, max {MAX_TASKS})",
                input.tasks.len()
            )));
        }
        let wait_ms = input.wait_ms.clamp(MIN_WAIT_MS, MAX_WAIT_MS);

        // Resolve the judge tier ONCE. `tier1_local_ok = true` is always safe
        // here: a tier-1 actor resolves to LocalOnly (judge on Ollama) and NEVER
        // to External, so its memory-derived output never reaches an external
        // provider. `ollama_available` gates the tier-1 path — no local judge
        // ⇒ Skip ⇒ TierSkip error (fail closed).
        let decision = self
            .actor_repo
            .resolve_llm_tier_decision(input.actor_id, true, self.ollama.is_some())
            .await;
        let backend = match decision {
            LlmTierDecision::External => JudgeBackend::External,
            LlmTierDecision::LocalOnly => JudgeBackend::Local(
                input
                    .judge_model
                    .clone()
                    .unwrap_or_else(|| DEFAULT_JUDGE_MODEL.to_string()),
            ),
            LlmTierDecision::Skip => return Err(EvaluationError::TierSkip),
        };

        let mut per_task = Vec::new();
        let mut skipped = Vec::new();
        for task in &input.tasks {
            match self.run_task(&input, task, &backend, wait_ms).await {
                Ok(tr) => per_task.push(tr),
                Err(e) => skipped.push(SkippedTask {
                    label: task.label.clone(),
                    reason: e.user_facing_message(),
                }),
            }
        }

        let paired: Vec<PairedResult> = per_task
            .iter()
            .map(|t| PairedResult {
                task_label: t.label.clone(),
                score_on: t.on.score,
                score_off: t.off.score,
                passed_on: t.on.passed,
                passed_off: t.off.passed,
            })
            .collect();
        let summary = aggregate_paired(&paired);

        Ok(EvalRunOutcome {
            summary,
            per_task,
            skipped,
            judge_backend: backend.label().to_string(),
            judge_model: backend.model(),
        })
    }

    /// Run ONE task under both arms and judge each.
    async fn run_task(
        &self,
        input: &EvalRunInput,
        task: &EvalTask,
        backend: &JudgeBackend,
        wait_ms: u64,
    ) -> Result<EvalTaskResult, EvaluationError> {
        // ON first, then OFF — sequential to avoid overloading a shared local
        // Ollama (the judge + tier-1 workflow LLM calls share it).
        let on = self.run_arm(input, task, true, backend, wait_ms).await?;
        let off = self.run_arm(input, task, false, backend, wait_ms).await?;
        Ok(EvalTaskResult {
            label: task.label.clone(),
            on,
            off,
        })
    }

    /// Trigger one arm, fetch its decrypted output, judge it.
    async fn run_arm(
        &self,
        input: &EvalRunInput,
        task: &EvalTask,
        inject_memory: bool,
        backend: &JudgeBackend,
        wait_ms: u64,
    ) -> Result<ArmResult, EvaluationError> {
        let ti = TriggerInput {
            workflow_id: task.workflow_id,
            user_id: input.user_id,
            trigger_input: task.trigger_input.clone(),
            // Bind the run to THIS actor so (a) its memory is injected on the ON
            // arm and (b) its budget/ceiling govern the run.
            trigger_agent_id: Some(input.actor_id),
            inject_memory_context: inject_memory,
            dry_run: false,
            wait_ms: Some(wait_ms),
        };
        let outcome = self
            .orchestration
            .trigger(ti)
            .await
            .map_err(|e| EvaluationError::Orchestration(safe_orch(&e)))?;
        let exec = match outcome {
            TriggerOutcome::Dispatched(o) => o,
            TriggerOutcome::DryRun(_) => {
                return Err(EvaluationError::Orchestration(
                    "unexpected dry-run outcome".into(),
                ))
            }
        };
        let exec_id = exec.execution_id;

        // Decrypted final output (user-scoped read — RLS-backstopped).
        let row = self
            .execution_repo
            .get_execution(exec_id, input.user_id)
            .await
            .map_err(EvaluationError::Internal)?;
        let (output, status) = match row {
            Some(r) => (r.output_data, r.status),
            None => (None, "unknown".to_string()),
        };

        let (score, passed, reasoning) = match &output {
            Some(v) => self.judge(backend, task, v).await?,
            // No output (failed / crashed arm) is the worst outcome: score 0.
            None => (0.0, false, format!("no output (status={status})")),
        };

        Ok(ArmResult {
            execution_id: exec_id,
            status,
            score,
            passed,
            reasoning,
        })
    }

    /// Judge one output with the tier-appropriate backend + structured output.
    async fn judge(
        &self,
        backend: &JudgeBackend,
        task: &EvalTask,
        output: &Value,
    ) -> Result<(f64, bool, String), EvaluationError> {
        let user = build_judge_user(&task.label, &task.trigger_input, output);
        let raw = match backend {
            JudgeBackend::Local(model) => {
                let ollama = self.ollama.as_ref().ok_or(EvaluationError::TierSkip)?;
                ollama
                    .complete_with_schema(
                        model,
                        JUDGE_SYSTEM,
                        &user,
                        JUDGE_MAX_TOKENS,
                        &judge_schema(),
                    )
                    .await
                    .map_err(|_| EvaluationError::Judge)?
            }
            JudgeBackend::External => {
                let client = LlmClient::with_vault(self.secrets_manager.clone(), None);
                client
                    .generate_with_schema(JUDGE_SYSTEM, &user, &judge_schema(), "record_judgment")
                    .await
                    .map_err(|_| EvaluationError::Judge)?
            }
        };
        parse_judgment(&raw).ok_or(EvaluationError::Judge)
    }

    /// Observational report: within executions that carried memory, does higher
    /// mean relevance track a better judge outcome? Correlational only.
    pub async fn observational_report(
        &self,
        actor_id: Uuid,
        since_days: i64,
    ) -> Result<crate::stats::ObservationalReport, EvaluationError> {
        let since = Utc::now() - Duration::days(since_days.clamp(1, 365));
        let rows =
            talos_memory::fetch_execution_memory_outcomes(&self.pool, actor_id, since, 10_000)
                .await
                .map_err(EvaluationError::Internal)?;
        let obs: Vec<crate::stats::ObservationalRow> = rows
            .iter()
            .map(|r| crate::stats::ObservationalRow {
                mean_fused: r.mean_fused,
                mem_count: r.mem_count,
                judge_passed: r.judge_passed,
                judge_score: r.judge_score,
            })
            .collect();
        Ok(analyze_observational(&obs))
    }
}

/// Build the judge's user prompt: task label + input + response, each byte-capped
/// at a UTF-8 boundary so a large payload can't blow the prompt.
fn build_judge_user(label: &str, input: &Value, output: &Value) -> String {
    let input_s = cap_utf8(&input.to_string(), INPUT_CAP);
    let output_s = cap_utf8(&output.to_string(), OUTPUT_CAP);
    format!("TASK: {label}\nINPUT: {input_s}\n\nRESPONSE:\n{output_s}")
}

/// Truncate to at most `max` bytes on a char boundary.
fn cap_utf8(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Parse the judge's structured verdict. Tolerant: direct parse, else the
/// outermost `{...}` slice (behind the structured-output guarantee this is
/// belt-and-suspenders). `passed` defaults to `score >= 0.6` when absent;
/// `score` is clamped to [0,1]. Returns `None` when no score can be recovered.
fn parse_judgment(raw: &str) -> Option<(f64, bool, String)> {
    let val = parse_object(raw)?;
    let score = val.get("score").and_then(|v| v.as_f64())?.clamp(0.0, 1.0);
    let passed = val
        .get("passed")
        .and_then(|v| v.as_bool())
        .unwrap_or(score >= 0.6);
    let reasoning = val
        .get("reasoning")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    Some((score, passed, reasoning))
}

fn parse_object(raw: &str) -> Option<Value> {
    let t = raw.trim();
    if let Ok(v) = serde_json::from_str::<Value>(t) {
        if v.is_object() {
            return Some(v);
        }
    }
    let (start, end) = (t.find('{')?, t.rfind('}')?);
    if end > start {
        if let Ok(v) = serde_json::from_str::<Value>(&t[start..=end]) {
            if v.is_object() {
                return Some(v);
            }
        }
    }
    None
}

/// Map an `OrchestrationError` to an operator-safe string, collapsing any
/// variant that could carry internal DB/dispatch detail.
fn safe_orch(e: &OrchestrationError) -> String {
    use OrchestrationError as E;
    match e {
        E::InvalidArgument(s) | E::ValidationFailed(s) | E::GraphLoadFailed(s) => {
            format!("invalid task: {s}")
        }
        E::WorkflowNotFound(id) => format!("workflow {id} not found"),
        E::ExecutionNotFound(id) => format!("execution {id} not found"),
        E::ExecutionPaused => "execution paused".into(),
        E::WorkflowDisabled(id) => format!("workflow {id} disabled"),
        E::StatusConflict(s) => format!("status conflict: {s}"),
        E::AuthorizationDenied(_) => "authorization denied".into(),
        E::ConcurrencyLimitExceeded(_) => "concurrency limit exceeded".into(),
        // Collapse anything that could leak internal detail.
        _ => "execution dispatch failed".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_judgment_direct() {
        let (s, p, r) =
            parse_judgment(r#"{"score":0.8,"passed":true,"reasoning":"grounded"}"#).unwrap();
        assert!((s - 0.8).abs() < 1e-9);
        assert!(p);
        assert_eq!(r, "grounded");
    }

    #[test]
    fn parse_judgment_derives_passed_and_clamps() {
        // passed absent → derived from score; score >1 clamped.
        let (s, p, _) = parse_judgment(r#"{"score":1.5,"reasoning":"x"}"#).unwrap();
        assert_eq!(s, 1.0);
        assert!(p);
        let (s2, p2, _) = parse_judgment(r#"{"score":0.3}"#).unwrap();
        assert_eq!(s2, 0.3);
        assert!(!p2);
    }

    #[test]
    fn parse_judgment_recovers_fenced() {
        let (s, _, _) =
            parse_judgment("```json\n{\"score\":0.5,\"passed\":false,\"reasoning\":\"meh\"}\n```")
                .unwrap();
        assert!((s - 0.5).abs() < 1e-9);
    }

    #[test]
    fn parse_judgment_no_score_is_none() {
        assert!(parse_judgment(r#"{"reasoning":"no score here"}"#).is_none());
        assert!(parse_judgment("not json at all").is_none());
    }

    #[test]
    fn cap_utf8_respects_boundary() {
        let s = "héllo wörld"; // multibyte
        let capped = cap_utf8(s, 3);
        assert!(s.starts_with(&capped));
        assert!(capped.len() <= 3);
    }
}
