//! Sub-workflow contract testing — application service.
//!
//! Backing logic for the `test_subworkflow_contract` MCP tool. The tool
//! lets authors simulate how a parent system-node (judge, reflection,
//! llm-dispatch classifier, reflective-retry child, sub_workflow) will see
//! a sub-workflow's output, by running the sub-workflow through the
//! exact same engine helpers the real parent uses and then interpreting
//! the collapsed output per the parent's contract.
//!
//! Architectural fit: follows the mandate that MCP handlers stay thin —
//! handlers do arg-parse → service call → response formatting; the
//! service owns engine construction, timeout plumbing, and per-contract
//! interpretation. Consistent with `ModuleExecutionService`,
//! `CompilationService`, and the other application services.

use serde_json::{json, Value as JsonValue};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use talos_workflow_engine::{JudgeVerdict, SubflowError};

/// Narrow dependency container for [`run_contract_test`]. Replaces the
/// pre-extraction `&McpState` parameter so this crate doesn't have to
/// pull in controller's full service-locator type. Construct from
/// McpState fields at the call-site (`controller::mcp::workflows::
/// handle_test_subworkflow_contract`):
///
/// ```ignore
/// ContractServiceDeps {
///     nats_client: deps.nats_client.clone(),
///     secrets_manager: deps.secrets_manager.clone(),
///     registry: deps.registry.clone(),
///     actor_repo: deps.actor_repo.clone(),
/// }
/// ```
#[derive(Clone)]
pub struct ContractServiceDeps {
    pub nats_client: Option<Arc<async_nats::Client>>,
    pub secrets_manager: Arc<talos_secrets_manager::SecretsManager>,
    pub registry: Arc<talos_registry::ModuleRegistry>,
    pub actor_repo: Arc<talos_actor_repository::ActorRepository>,
}

/// Which parent system-node contract to simulate.
///
/// Strings map 1:1 with the `contract` MCP argument. Using an enum (vs
/// matching strings inside the service) lets the handler validate up-front
/// and return a clean error before any engine work begins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractKind {
    /// Parent is a Judge node; post-run we parse a `JudgeVerdict`.
    Judge,
    /// Parent is a reflection step inside reflective-retry.
    Reflection,
    /// Parent is an LLM-dispatch classifier; post-run we look for
    /// `class` / `output` / `result`.
    Classifier,
    /// Parent is a reflective-retry child.
    Child,
    /// Generic `sub_workflow` node.
    Subworkflow,
}

impl ContractKind {
    /// Parse from the string MCP argument. Returns `Err` with a caller-
    /// friendly message when the value isn't a known contract.
    pub fn from_arg(s: &str) -> Result<Self, String> {
        match s {
            "judge" => Ok(Self::Judge),
            "reflection" => Ok(Self::Reflection),
            "classifier" => Ok(Self::Classifier),
            "child" => Ok(Self::Child),
            "subworkflow" => Ok(Self::Subworkflow),
            other => Err(format!(
                "'contract' must be one of judge|reflection|classifier|child|subworkflow (got '{}')",
                talos_text_util::bounded_preview(other, 64)
            )),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Judge => "judge",
            Self::Reflection => "reflection",
            Self::Classifier => "classifier",
            Self::Child => "child",
            Self::Subworkflow => "subworkflow",
        }
    }
}

/// Outcome of a contract-test run. Always populated; the handler
/// serializes it verbatim into the MCP tool result.
#[derive(Debug, Clone)]
pub struct ContractTestOutcome {
    pub workflow_id: Uuid,
    pub contract: ContractKind,
    /// True iff the sub-workflow output satisfies the contract's schema.
    /// Specifically: for `judge`, no malformed verdict fields; for
    /// `classifier`, a non-empty class string was present; for the
    /// remaining contracts, the output has no `__error: true` envelope.
    pub passed: bool,
    /// The collapsed output as `execute_subworkflow_graph` returned it —
    /// the exact value the real parent node would receive.
    pub collapsed_output: JsonValue,
    /// Populated for `ContractKind::Judge` with the parsed verdict.
    pub judge_verdict: Option<JudgeVerdict>,
    /// Populated for `ContractKind::Classifier` with the extracted class
    /// string (or `None` if none of `class`/`output`/`result` held a string).
    pub classifier_class: Option<String>,
}

impl ContractTestOutcome {
    /// Serialize to the JSON body the MCP tool returns. The format is
    /// stable — downstream docs + clients rely on these key names.
    pub fn to_tool_body(&self) -> JsonValue {
        let mut body = json!({
            "workflow_id": self.workflow_id.to_string(),
            "contract": self.contract.label(),
            "passed": self.passed,
            "collapsed_output": self.collapsed_output,
        });
        if let Some(v) = &self.judge_verdict {
            // NOTE: `JudgeVerdict` now derives `serde::Serialize` (engine
            // changelog, Added). We still build the envelope by hand to
            // preserve the stable MCP field name `malformed_fields`, which
            // diverges from the engine's internal `malformed_field_count`.
            // Switching to `serde_json::to_value(v)` would silently change
            // the tool's wire format. Keep hand-written unless we're also
            // bumping the MCP contract.
            body["judge_verdict"] = json!({
                "score": v.score,
                "passed": v.passed,
                "reasoning": v.reasoning,
                "feedback": v.feedback,
                "malformed_fields": v.malformed_field_count,
            });
        }
        if self.contract == ContractKind::Classifier {
            body["classifier_class"] = match &self.classifier_class {
                Some(s) => JsonValue::String(s.clone()),
                None => JsonValue::Null,
            };
        }
        body
    }
}

/// Failure modes returned to the MCP handler. The handler maps these
/// to HTTP/JSON-RPC shapes; the service stays transport-agnostic.
#[derive(Debug)]
pub enum ContractTestError {
    /// `deps.nats_client` was unset — can't reach workers.
    NatsUnavailable,
    /// `SecretsManager` construction failed at the dispatch site.
    SecretsManagerUnavailable(String),
    /// Sub-workflow execution failed before completing. Payload is the
    /// engine's own error envelope — safe to forward to the caller.
    ExecutionFailed(JsonValue),
    /// Wall-clock timeout fired. Includes the requested timeout_secs.
    Timeout { timeout_secs: u64 },
}

/// Run a sub-workflow under the contract-testing harness.
///
/// Steps:
/// 1. Build an isolated `ParallelWorkflowEngine` scoped to `user_id`,
///    reusing the canonical shared `SecretsManager` from `McpState`.
///    See the secrets-sharing rationale on `deps.secrets_manager` below.
/// 2. Dispatch the sub-workflow via `execute_subworkflow_graph` inside a
///    `tokio::time::timeout` window. When the timeout fires, the future
///    drops; in-flight NATS awaits abort, and any sandbox already running
///    on a worker completes under its own per-node timeout (no leak).
/// 3. Collapse + interpret per-contract.
///
/// Panic safety: no unwraps on operator-controlled input. Every failure
/// path maps to `ContractTestError`.
pub async fn run_contract_test(
    deps: &ContractServiceDeps,
    user_id: Uuid,
    workflow_id: Uuid,
    contract: ContractKind,
    input: JsonValue,
    timeout_secs: u64,
) -> Result<ContractTestOutcome, ContractTestError> {
    // Reuse the canonical SecretsManager from McpState rather than
    // constructing a fresh one per call.
    //
    // Pre-r233 this site built a fresh SecretsManager from the db_pool
    // every call (see check 4 in scripts/lint-structural.sh for the
    // pattern this lint guards against). That was wrong on three axes:
    //
    //   1. **Correctness (the actual bug we're fixing).** The fresh
    //      manager loaded its KEK via `env_kek_provider_from_environment()`.
    //      In a deployment using a Vault-backed or KMS-backed KEK provider
    //      for the global manager (the production posture), the env-provider
    //      KEK and the production KEK can differ. Per-row DEK unwrap then
    //      fails with `Failed to get DEK for secret …` at WARN level inside
    //      `get_secrets_by_paths` (the loop logs and continues per-row), so
    //      `resolve_llm_keys` returns an EMPTY map. The job dispatched with
    //      no anthropic/openai/gemini key, the worker had no env fallback,
    //      and `llm::complete` failed with "LLM provider 'anthropic' is not
    //      configured." Symptom-as-observed on r232 prior to this fix.
    //
    //   2. **Performance.** Each fresh manager has cold DEK / LLM-keys
    //      caches; every contract test paid 3 DB roundtrips to repopulate
    //      LLM keys plus N DEK fetches. The shared manager is already warm
    //      and amortises across all dispatch sites in the controller.
    //
    //   3. **Consistency.** Every other dispatch site (scheduler, MCP
    //      triggers, GraphQL mutations, webhooks, replay/retry) takes
    //      `deps.secrets_manager` from McpState. The contract test was
    //      the lone outlier, which is exactly the drift class the
    //      EngineBuilder refactor exists to prevent.
    //
    // Arc clone is a refcount bump (cheap); the Arc lives as long as the
    // controller process so the prior "might outlive the pool" worry is
    // moot.
    let secrets_manager = deps.secrets_manager.clone();

    let nats_client = deps
        .nats_client
        .clone()
        .ok_or(ContractTestError::NatsUnavailable)?;
    let worker_shared_key = talos_workflow_job_protocol::load_worker_shared_key().ok();

    // Build via the canonical EngineBuilder. `for_skip_load` because
    // execute_subworkflow_graph resolves the graph itself via the engine's
    // WorkflowGraphStore — we don't want load_graph_from_json fired here.
    // Contract testing is intentionally anonymous (no actor binding); the
    // sub-workflow runs under whatever actor it's bound to in its own graph
    // when the engine resolves it.
    let opts = talos_engine::builder::EngineOpts::for_skip_load(workflow_id);
    let engine = talos_engine::builder::for_workflow(
        deps.registry.clone(),
        secrets_manager,
        deps.actor_repo.clone(),
        user_id,
        opts,
    )
    .await
    .map_err(|talos_engine::builder::BuildError::GraphLoad(engine_err)| {
        // Defensive: GraphSource::SkipLoad means load_graph_from_json never
        // runs, so this branch is unreachable today. Map it to BuildFailed
        // (closest existing SubflowError variant) for forward-compat in case
        // future builder steps grow their own failure modes.
        ContractTestError::ExecutionFailed(into_subflow_envelope(
            SubflowError::BuildFailed(engine_err.to_string()),
            "Sub-workflow contract test (engine build)",
        ))
    })?;

    // Cancellation: `tokio::time::timeout` drops the future on expiry.
    // Pending NATS/DB awaits release; a worker-side sandbox that was
    // mid-flight completes under its per-node timeout (bounded). No
    // controller-side resource leak.
    let dispatcher = talos_engine::nats_run::build_nats_dispatcher(
        &engine,
        nats_client,
        worker_shared_key.clone(),
    );
    let fut = engine.execute_subworkflow_graph(workflow_id, input, dispatcher, worker_shared_key);
    let exec_result = tokio::time::timeout(Duration::from_secs(timeout_secs), fut).await;

    let collapsed = match exec_result {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            return Err(ContractTestError::ExecutionFailed(into_subflow_envelope(
                e,
                "Sub-workflow contract test",
            )));
        }
        Err(_) => {
            tracing::info!(
                target: "talos_engine",
                event_kind = "contract_test_timeout",
                %workflow_id,
                contract = contract.label(),
                timeout_secs,
                "test_subworkflow_contract: timeout — controller-side awaits dropped; \
                 any in-flight sandbox on a worker will complete under its per-node timeout"
            );
            return Err(ContractTestError::Timeout { timeout_secs });
        }
    };

    Ok(interpret(&collapsed, contract, workflow_id))
}

/// Contract-specific interpretation of a collapsed sub-workflow output.
///
/// Pure function — no I/O — so callers can unit-test all 5 contract
/// branches without spinning up an engine or DB.
pub fn interpret(
    collapsed: &JsonValue,
    contract: ContractKind,
    workflow_id: Uuid,
) -> ContractTestOutcome {
    let (passed, judge_verdict, classifier_class) = match contract {
        ContractKind::Judge => {
            let v = JudgeVerdict::from_collapsed(collapsed);
            let passed = v.malformed_field_count == 0;
            (passed, Some(v), None)
        }
        ContractKind::Classifier => {
            let class = collapsed
                .get("class")
                .or_else(|| collapsed.get("output"))
                .or_else(|| collapsed.get("result"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let passed = class.as_ref().map(|s| !s.is_empty()).unwrap_or(false);
            (passed, None, class)
        }
        ContractKind::Reflection | ContractKind::Child | ContractKind::Subworkflow => {
            let errored = collapsed
                .get("__error")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            (!errored, None, None)
        }
    };
    ContractTestOutcome {
        workflow_id,
        contract,
        passed,
        collapsed_output: collapsed.clone(),
        judge_verdict,
        classifier_class,
    }
}

fn into_subflow_envelope(err: SubflowError, context: &str) -> JsonValue {
    err.into_error_envelope(context)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wf() -> Uuid {
        Uuid::new_v4()
    }

    #[test]
    fn contract_kind_from_arg_known_values() {
        assert_eq!(
            ContractKind::from_arg("judge").unwrap(),
            ContractKind::Judge
        );
        assert_eq!(
            ContractKind::from_arg("classifier").unwrap(),
            ContractKind::Classifier
        );
        assert_eq!(
            ContractKind::from_arg("child").unwrap(),
            ContractKind::Child
        );
    }

    #[test]
    fn contract_kind_from_arg_unknown() {
        let err = ContractKind::from_arg("ensemble").unwrap_err();
        assert!(err.contains("'contract' must be one of"));
        assert!(err.contains("ensemble"));
    }

    #[test]
    fn interpret_judge_happy_path() {
        let collapsed = json!({
            "score": 0.9,
            "passed": true,
            "reasoning": "ok",
            "feedback": "good",
        });
        let out = interpret(&collapsed, ContractKind::Judge, wf());
        assert!(out.passed, "well-shaped judge verdict must pass");
        let v = out.judge_verdict.unwrap();
        assert_eq!(v.malformed_field_count, 0);
        assert!((v.score - 0.9).abs() < 1e-9);
    }

    #[test]
    fn interpret_judge_malformed_fails() {
        // Missing `feedback` and wrong-typed `score`.
        let collapsed = json!({
            "score": "nine-tenths",
            "passed": true,
            "reasoning": "ok",
        });
        let out = interpret(&collapsed, ContractKind::Judge, wf());
        assert!(!out.passed, "malformed judge must fail the contract");
        assert!(out.judge_verdict.unwrap().malformed_field_count > 0);
    }

    #[test]
    fn interpret_classifier_reads_class_first() {
        let collapsed = json!({ "class": "urgent", "output": "ignored" });
        let out = interpret(&collapsed, ContractKind::Classifier, wf());
        assert!(out.passed);
        assert_eq!(out.classifier_class.as_deref(), Some("urgent"));
    }

    #[test]
    fn interpret_classifier_falls_through_to_output_then_result() {
        let out = interpret(&json!({ "output": "x" }), ContractKind::Classifier, wf());
        assert_eq!(out.classifier_class.as_deref(), Some("x"));
        let out = interpret(&json!({ "result": "y" }), ContractKind::Classifier, wf());
        assert_eq!(out.classifier_class.as_deref(), Some("y"));
    }

    #[test]
    fn interpret_classifier_empty_fails() {
        let out = interpret(&json!({ "class": "" }), ContractKind::Classifier, wf());
        assert!(!out.passed);
    }

    #[test]
    fn interpret_classifier_missing_returns_null() {
        let out = interpret(&json!({ "noise": 1 }), ContractKind::Classifier, wf());
        assert!(!out.passed);
        assert!(out.classifier_class.is_none());
    }

    #[test]
    fn interpret_reflection_child_subworkflow_gate_on_error_envelope() {
        for k in [
            ContractKind::Reflection,
            ContractKind::Child,
            ContractKind::Subworkflow,
        ] {
            let ok = interpret(&json!({ "answer": "42" }), k, wf());
            assert!(ok.passed, "no __error means pass for {:?}", k);
            let err = interpret(
                &json!({ "__error": true, "error_message": "nope" }),
                k,
                wf(),
            );
            assert!(!err.passed, "__error:true means fail for {:?}", k);
        }
    }

    #[test]
    fn to_tool_body_includes_judge_block_only_for_judge() {
        let judge_body = interpret(
            &json!({"score": 1.0, "passed": true, "reasoning": "", "feedback": ""}),
            ContractKind::Judge,
            wf(),
        )
        .to_tool_body();
        assert!(judge_body.get("judge_verdict").is_some());

        let child_body =
            interpret(&json!({"answer": "ok"}), ContractKind::Child, wf()).to_tool_body();
        assert!(child_body.get("judge_verdict").is_none());
    }

    #[test]
    fn to_tool_body_includes_classifier_class_only_for_classifier() {
        let cls = interpret(&json!({"class": "x"}), ContractKind::Classifier, wf()).to_tool_body();
        assert!(cls.get("classifier_class").is_some());

        let jud = interpret(
            &json!({"score": 1.0, "passed": true, "reasoning": "", "feedback": ""}),
            ContractKind::Judge,
            wf(),
        )
        .to_tool_body();
        assert!(jud.get("classifier_class").is_none());
    }
}
