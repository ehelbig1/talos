//! Sub-workflow-family dispatch handlers — extracted from engine.rs.
//!
//! Hosts the parent-node handlers that run a child workflow graph:
//! `dispatch_judge` / `dispatch_inline_judge`, `dispatch_ensemble`,
//! `dispatch_reflective_retry`, `dispatch_llm_dispatch`, and
//! `dispatch_subworkflow`, plus the shared invocation kernel they all
//! route through (`execute_subworkflow_graph`,
//! `collapse_subworkflow_output`, sub-actor identity rebind + ceiling
//! narrowing via `resolve_subworkflow_binding` /
//! `bind_subengine_actor_and_ceilings`) and
//! the engine-side judge glue ([`JudgeVerdict`], [`SubflowError`],
//! `record_judge_score`). Pure code movement from the previous
//! engine.rs location — no behaviour change. Lifted out so the
//! sub-workflow dispatch path stays auditable in isolation alongside
//! `engine_dispatch_single` and `engine_dispatch_pipeline`.

use std::collections::HashMap;
use std::sync::Arc;

use futures::stream::StreamExt;
use petgraph::graph::NodeIndex;
use petgraph::Direction;
use serde_json::Value as JsonValue;
use uuid::Uuid;

use crate::engine::{ParallelWorkflowEngine, MAX_CONCURRENT_NODE_DISPATCH};

/// Structured errors from [`ParallelWorkflowEngine::execute_subworkflow_graph`].
/// Callers convert these into their own error envelopes via
/// [`SubflowError::into_error_envelope`] so each system-node kind can keep its
/// own context-specific messages ("Judge workflow X not found", etc).
///
/// Marked [`#[non_exhaustive]`] so the engine can promote new failure modes
/// (invalid ownership, schema-version mismatch, ...) into their own variants
/// without breaking downstream `match` arms. Consumers should always include
/// a wildcard arm.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SubflowError {
    /// Engine has no registry configured — sub-workflow execution impossible.
    NoRegistry,
    /// Engine has no `user_id` — all sub-workflow execution requires it.
    NoUserId,
    /// Secrets resolver not attached — sub-workflow modules couldn't fetch secrets.
    NoSecretsResolver,
    /// No workflow matching `sub_wf_id` exists (or not visible to `user_id`).
    ///
    /// Typically means the referenced workflow was deleted after the
    /// parent graph was authored, or the parent and sub-workflow are
    /// owned by different users. Carries the missing ID so callers can
    /// surface a precise diagnostic (e.g. "judge workflow X was
    /// deleted; edit the parent to reference a valid judge").
    GraphNotFound(Uuid),
    /// `build_engine_from_graph_json_with_resolver` failed — usually a module resolution issue.
    BuildFailed(String),
    /// `run_with_seed` returned an error — execution actually ran and failed.
    ExecutionFailed(String),
}

impl SubflowError {
    /// Canonical `{__error, error_message}` envelope with a caller-provided
    /// context label (e.g. "Judge", "Ensemble child", "Sub-workflow").
    pub fn into_error_envelope(self, context: &str) -> JsonValue {
        let msg = match self {
            SubflowError::NoRegistry => {
                format!("Registry not available for {} node", context)
            }
            SubflowError::NoUserId => "user_id required for sub-workflow execution".to_string(),
            SubflowError::NoSecretsResolver => {
                format!("secrets resolver unavailable for {} execution", context)
            }
            SubflowError::GraphNotFound(id) => {
                format!("{} workflow {} not found", context, id)
            }
            SubflowError::BuildFailed(e) => {
                format!("Failed to build {} workflow engine: {}", context, e)
            }
            SubflowError::ExecutionFailed(e) => {
                format!("{} workflow execution failed: {}", context, e)
            }
        };
        serde_json::json!({ "__error": true, "error_message": msg })
    }

    /// Returns the missing sub-workflow id when this error is
    /// [`GraphNotFound`](Self::GraphNotFound), else `None`.
    ///
    /// Callers that need to branch on "missing sub-workflow" without
    /// exhaustively matching every variant (e.g. to surface a
    /// structured `{kind: "sub_workflow_not_found", id}` response in
    /// their API layer) can pattern-match on this accessor instead.
    pub fn missing_sub_workflow_id(&self) -> Option<Uuid> {
        match self {
            SubflowError::GraphNotFound(id) => Some(*id),
            _ => None,
        }
    }
}

/// Structured judge verdict parsed from a collapsed sub-workflow output.
///
/// Downstream consumers (`judge_node`, ensemble `best_of_n`) want the same 4 fields;
/// this struct centralizes parsing and logs when fields are missing so malformed
/// judge workflows fail loudly rather than silently scoring 0.0.
///
/// # Using outside the engine's own dispatch paths
///
/// Third-party call sites (HTTP handlers, CLI tools, contract tests) that
/// need to score a sub-workflow's output should construct one of these via
/// [`from_collapsed`](Self::from_collapsed) rather than hand-parsing the
/// JSON — otherwise the parse logic drifts from what the engine itself
/// uses to score judge nodes, and malformed-verdict warnings stop firing.
///
/// ```no_run
/// use serde_json::json;
/// use talos_workflow_engine::JudgeVerdict;
///
/// let collapsed = json!({
///     "score": 0.82,
///     "passed": true,
///     "reasoning": "meets the rubric",
///     "feedback": "tighten the closing line",
/// });
/// let verdict = JudgeVerdict::from_collapsed(&collapsed);
/// assert!(verdict.passed);
/// assert_eq!(verdict.malformed_field_count, 0);
/// ```
///
/// `Serialize` / `Deserialize` are implemented so the verdict can be
/// shipped over an API without an intermediate conversion.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JudgeVerdict {
    /// Verdict score in `0.0..=1.0`. Higher = better. Sub-workflow
    /// outputs missing this field default to `0.0`.
    pub score: f64,
    /// Did the upstream output pass the rubric? Sub-workflow outputs
    /// missing this field default to `false`.
    pub passed: bool,
    /// Human-readable explanation of the verdict. Used for audit
    /// trails and downstream context.
    pub reasoning: String,
    /// Suggested correction or improvement that downstream nodes
    /// (e.g. `ReflectiveRetry`) can feed back into the next attempt.
    pub feedback: String,
    /// Number of expected fields that were missing or wrong-typed in the
    /// sub-workflow output (0..=4). Non-zero indicates a malformed judge workflow.
    pub malformed_field_count: u8,
}

impl JudgeVerdict {
    /// Parse a verdict from a collapsed sub-workflow output. Missing/mistyped
    /// fields fall back to defaults and increment `malformed_field_count` so
    /// callers can surface the issue. Always returns a value — judge extraction
    /// must never panic at runtime.
    pub fn from_collapsed(verdict: &JsonValue) -> Self {
        let mut malformed = 0u8;
        let score = match verdict.get("score").and_then(|v| v.as_f64()) {
            Some(v) => v,
            None => {
                malformed += 1;
                0.0
            }
        };
        let passed = match verdict.get("passed").and_then(|v| v.as_bool()) {
            Some(v) => v,
            None => {
                malformed += 1;
                false
            }
        };
        let reasoning = match verdict.get("reasoning").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => {
                malformed += 1;
                String::new()
            }
        };
        let feedback = match verdict.get("feedback").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => {
                malformed += 1;
                String::new()
            }
        };
        if malformed > 0 {
            tracing::warn!(
                malformed_fields = malformed,
                "Judge sub-workflow returned malformed verdict — missing or wrong-typed fields. \
                 Expected {{score: f64, passed: bool, reasoning: string, feedback: string}}."
            );
        }
        Self {
            score,
            passed,
            reasoning,
            feedback,
            malformed_field_count: malformed,
        }
    }
}

/// Pull the observe-only `(score, passed)` pair out of a judge node's
/// enriched output envelope, for the `JudgeScoreRecorder` hook. Returns
/// `None` when the output carries no `__judge_score__` (not a judge
/// verdict) — the score is the gate, `__judge_passed__` defaults to
/// `false` when absent. Kept pure (no engine state) so it is unit-tested
/// without a runtime. DLP: intentionally reads only the score + pass
/// boolean, never the reasoning/feedback text.
pub(crate) fn extract_judge_score(output: &JsonValue) -> Option<(f64, bool)> {
    let score = output.get("__judge_score__").and_then(|v| v.as_f64())?;
    let passed = output
        .get("__judge_passed__")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    Some((score, passed))
}

impl ParallelWorkflowEngine {
    /// Unwrap engine wrapper from node output if present.
    /// Templates receive `{"config": ..., "input": ...}` and many echo it back.
    /// For inter-node data flow, we want the raw payload, not the engine wrapper.
    /// Collapse a completed sub-workflow's per-node results into a single output value.
    ///
    /// All sub-workflow invocation sites (judge, reflective-retry, ensemble, `sub_workflow`)
    /// need the same semantics; authoring a sub-workflow whose output is a shaped record
    /// (e.g. judge returning `{score, passed, reasoning, feedback}`) should "just work"
    /// regardless of how the sub-workflow graph is wired internally.
    ///
    /// Rules:
    /// - Nodes marked `__skipped` are dropped.
    /// - The synthetic `__trigger__` node is dropped.
    /// - Each remaining output is passed through `unwrap_output` to strip the engine
    ///   `{input, config, ...}` envelope.
    /// - If exactly one **terminal** node remains (a node with no outgoing edges inside
    ///   the sub-graph), its unwrapped output IS the collapsed value. Callers see the
    ///   record shape their sub-workflow returns, not a `{node_label: {...}}` wrap.
    /// - Otherwise (zero terminals, which means the graph is cyclic or empty, or
    ///   multiple terminals — a diamond without an explicit aggregator), fall back to a
    ///   label-keyed map so callers can still reach individual branches via
    ///   `output[label]`. Node-label collisions are deterministically resolved by
    ///   preferring terminal nodes (so shadowing a non-terminal is explicit).
    /// One-shot dispatch of an Ensemble system node.
    ///
    /// Runs `child_wf_id` `run_count` times with the same input, then applies
    /// the consensus strategy to pick a winner:
    /// - `first_pass`: first non-error result.
    /// - `best_of_n`: requires `judge_wf_id_opt`; scores each candidate via the
    ///   judge workflow and picks the highest score.
    /// - anything else ("`majority_vote`" / default): most common value at
    ///   `result`/`output` key (with an 8 KiB vote-key cap to bound memory).
    ///
    /// Output is enriched with `__ensemble_method__` and `__ensemble_size__`.
    pub async fn dispatch_ensemble(
        &self,
        inputs: JsonValue,
        child_wf_id: Uuid,
        run_count: u32,
        consensus_strategy: String,
        judge_wf_id_opt: Option<Uuid>,
        dispatcher: Arc<dyn talos_workflow_engine_core::NodeDispatcher>,
        worker_shared_key: Option<talos_workflow_engine_core::WorkerSharedKey>,
    ) -> JsonValue {
        let clean_input = if let Some(obj) = inputs.as_object() {
            let mut cleaned = obj.clone();
            cleaned.retain(|k, _| !k.starts_with("__"));
            serde_json::Value::Object(cleaned)
        } else {
            inputs
        };

        // 1. Run the child workflow N times. M6 (2026-05-28 review): the N runs
        // are INDEPENDENT (identical input), so run them CONCURRENTLY instead of
        // sequentially — pre-fix wall-clock was run_count × child-latency (a
        // 5-run ensemble of a 10s child took ~50s instead of ~10s). `buffered`
        // preserves run order so `first_pass` (picks the first non-error) and
        // the recorded metadata stay deterministic, and bounds concurrency at
        // MAX_CONCURRENT_NODE_DISPATCH so a large run_count (or nested
        // ensembles) can't stampede the worker fleet. The sibling `sub_workflow`
        // fan-out path was already parallel; ensemble had been missed.
        let candidate_futs = (0..run_count).map(|_i| {
            let input = clean_input.clone();
            let dispatcher = dispatcher.clone();
            let wsk = worker_shared_key.clone();
            async move {
                match self
                    .execute_subworkflow_graph(child_wf_id, input, dispatcher, wsk)
                    .await
                {
                    Ok(v) => v,
                    Err(e) => e.into_error_envelope("Ensemble child"),
                }
            }
        });
        let all_results: Vec<JsonValue> = futures::stream::iter(candidate_futs)
            .buffered(*MAX_CONCURRENT_NODE_DISPATCH)
            .collect()
            .await;

        // 2. Pick a winner via the consensus strategy.
        let consensus_output: JsonValue = match consensus_strategy.as_str() {
            "first_pass" => all_results
                .iter()
                .find(|r| !r.get("__error").and_then(|v| v.as_bool()).unwrap_or(false))
                .cloned()
                .unwrap_or_else(|| {
                    all_results.first().cloned().unwrap_or_else(|| {
                        serde_json::json!({
                            "__error": true,
                            "error_message": "All ensemble runs failed"
                        })
                    })
                }),
            "best_of_n" if judge_wf_id_opt.is_some() => {
                let judge_wf_id = judge_wf_id_opt.unwrap();
                // P6: the judge sub-workflows are INDEPENDENT (each scores one
                // candidate in isolation), so run them CONCURRENTLY instead of
                // sequentially — pre-fix wall-clock was non_error_count ×
                // judge-latency (5 candidates × ~10s judge ≈ 50s instead of
                // ~10s). `buffered` PRESERVES candidate order, so the
                // score→candidate selection below is byte-for-byte equivalent
                // to the old sequential `for` loop: error candidates are still
                // skipped (and never eligible to win), a judge that errors
                // still yields `None` and is skipped from scoring, and the
                // strict `>` comparison still keeps the FIRST candidate that
                // attains the max score on a tie. Bounded at
                // MAX_CONCURRENT_NODE_DISPATCH to match the candidate-generation
                // fan-out and not stampede the worker fleet.
                // Own the scored candidates (Vec<JsonValue>, not
                // Vec<&JsonValue>) so NOTHING borrows `all_results` across the
                // judge `.await` below. The enclosing `run_inner` future is
                // boxed as `dyn Future + Send + '_`, so its only across-await
                // borrow may be `&self` (HRTB lifetime); any *second* live
                // borrow — `all_results` via a `&JsonValue`, or a lazy
                // `.map()` iterator that borrows a local — makes the future
                // fail the "Send is not general enough" check. This mirrors the
                // working `candidate_futs` fan-out above, which captures only
                // owned data plus `&self`.
                let scored_candidates: Vec<JsonValue> = all_results
                    .iter()
                    .filter(|candidate| {
                        !candidate
                            .get("__error")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false)
                    })
                    .cloned()
                    .collect();
                // Eagerly materialize the futures into an owned Vec so
                // `stream::iter` owns them (no borrow of `scored_candidates`
                // held across the await); each future owns its candidate clone.
                let judge_futs: Vec<_> = scored_candidates
                    .iter()
                    .map(|candidate| {
                        let dispatcher = dispatcher.clone();
                        let wsk = worker_shared_key.clone();
                        let candidate = candidate.clone();
                        async move {
                            let judge_input =
                                serde_json::json!({ "content": candidate, "rubric": "" });
                            match self
                                .execute_subworkflow_graph(
                                    judge_wf_id,
                                    judge_input,
                                    dispatcher,
                                    wsk,
                                )
                                .await
                            {
                                Ok(collapsed) => {
                                    Some(JudgeVerdict::from_collapsed(&collapsed).score)
                                }
                                // Judge dispatch failed — preserve the old loop's
                                // behavior of skipping this candidate from scoring.
                                Err(_) => None,
                            }
                        }
                    })
                    .collect();
                let judge_scores: Vec<Option<f64>> = futures::stream::iter(judge_futs)
                    .buffered(*MAX_CONCURRENT_NODE_DISPATCH)
                    .collect()
                    .await;

                let mut best_result: Option<JsonValue> = None;
                let mut best_score = f64::NEG_INFINITY;
                for (candidate, score) in scored_candidates.iter().zip(judge_scores.iter()) {
                    if let Some(score) = score {
                        if *score > best_score {
                            best_score = *score;
                            // `candidate: &JsonValue` (iter over owned
                            // Vec<JsonValue>); clone the owned candidate value.
                            best_result = Some(candidate.clone());
                        }
                    }
                }
                let chosen = best_result.unwrap_or_else(|| {
                    all_results.first().cloned().unwrap_or_else(|| {
                        serde_json::json!({
                            "__error": true,
                            "error_message": "All best_of_n candidates failed"
                        })
                    })
                });
                Self::emit_quality_gate_event(
                    "ensemble_best_of_n",
                    best_score > f64::NEG_INFINITY,
                    if best_score > f64::NEG_INFINITY {
                        Some(best_score)
                    } else {
                        None
                    },
                    Some(run_count),
                    None,
                );
                chosen
            }
            _ => {
                // majority_vote: find most common value at result["result"] or result["output"].
                // Vote-key is capped at 8 KiB to bound memory when candidates are huge.
                let mut vote_counts: std::collections::HashMap<String, (usize, JsonValue)> =
                    std::collections::HashMap::new();
                const MAX_VOTE_KEY_BYTES: usize = 8_192;
                for r in &all_results {
                    if r.get("__error").and_then(|v| v.as_bool()).unwrap_or(false) {
                        continue;
                    }
                    let key_val = {
                        let s = r
                            .get("result")
                            .or_else(|| r.get("output"))
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| r.to_string());
                        if s.len() > MAX_VOTE_KEY_BYTES {
                            s[..MAX_VOTE_KEY_BYTES].to_string()
                        } else {
                            s
                        }
                    };
                    let entry = vote_counts.entry(key_val).or_insert((0, r.clone()));
                    entry.0 += 1;
                }
                vote_counts
                    .into_iter()
                    .max_by_key(|(_, (count, _))| *count)
                    .map(|(_, (_, best))| best)
                    .unwrap_or_else(|| {
                        all_results.first().cloned().unwrap_or_else(|| {
                            serde_json::json!({
                                "__error": true,
                                "error_message": "Ensemble majority_vote: all runs failed"
                            })
                        })
                    })
            }
        };

        // 3. Annotate with ensemble metadata.
        let mut out = if let Some(obj) = consensus_output.as_object() {
            obj.clone()
        } else {
            serde_json::Map::new()
        };
        out.insert(
            "__ensemble_method__".to_string(),
            serde_json::json!(consensus_strategy),
        );
        out.insert(
            "__ensemble_size__".to_string(),
            serde_json::json!(run_count),
        );
        serde_json::Value::Object(out)
    }

    /// One-shot dispatch of a `LlmDispatch` system node.
    ///
    /// Flow:
    /// 1. Run `classifier_wf_id` with the inbound inputs (stripped of `__*`).
    /// 2. Extract a class string from the classifier output (top-level
    ///    `class`, `output`, or `result` keys — whichever is present).
    /// 3. If the class matches a key in `routes`, run that route's workflow
    ///    with the same input. Otherwise run `fallback_wf_id` (if set),
    ///    passing the unmatched class as `__unmatched_class__`.
    ///
    /// The returned output always carries `__dispatched_class__` and
    /// `__dispatched_workflow_id__` for trace observability.
    pub async fn dispatch_llm_dispatch(
        &self,
        inputs: JsonValue,
        classifier_wf_id: Uuid,
        routes: std::collections::HashMap<String, Uuid>,
        fallback_wf_id: Option<Uuid>,
        dispatcher: Arc<dyn talos_workflow_engine_core::NodeDispatcher>,
        worker_shared_key: Option<talos_workflow_engine_core::WorkerSharedKey>,
    ) -> JsonValue {
        let clean_input = if let Some(obj) = inputs.as_object() {
            let mut cleaned = obj.clone();
            cleaned.retain(|k, _| !k.starts_with("__"));
            serde_json::Value::Object(cleaned)
        } else {
            inputs
        };

        // 1. Run classifier. Distinguish 3 failure modes rather than
        // collapsing them into a single "empty class" message:
        //   a) classifier sub-workflow itself failed (DB, build, exec error)
        //   b) classifier ran but returned no recognised class field
        //   c) classifier ran and returned an empty string
        let class_str = match self
            .execute_subworkflow_graph(
                classifier_wf_id,
                clean_input.clone(),
                dispatcher.clone(),
                worker_shared_key.clone(),
            )
            .await
        {
            Ok(out) => {
                let raw = out
                    .get("class")
                    .or_else(|| out.get("output"))
                    .or_else(|| out.get("result"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                match raw {
                    None => {
                        let keys: Vec<&String> = out
                            .as_object()
                            .map(|m| m.keys().collect())
                            .unwrap_or_default();
                        return serde_json::json!({
                            "__error": true,
                            "error_message": format!(
                                "LlmDispatch classifier output had no 'class', 'output', or 'result' \
                                 string field (saw keys: {:?}). The classifier sub-workflow must return \
                                 a string class label.",
                                keys
                            ),
                        });
                    }
                    Some(s) if s.is_empty() => {
                        return serde_json::json!({
                            "__error": true,
                            "error_message":
                                "LlmDispatch classifier returned an empty class string — \
                                 the classifier must produce a non-empty label.",
                        });
                    }
                    Some(s) => s,
                }
            }
            Err(e) => {
                // Preserve the classifier sub-workflow error detail under a
                // context-specific label so the caller can tell the difference
                // between "classifier failed" and "classifier returned bad data".
                return e.into_error_envelope("LlmDispatch classifier");
            }
        };

        // 2. Resolve the target workflow from routes or fallback.
        let (target_wf_id, input_for_target, is_fallback) = match routes.get(&class_str) {
            Some(&target) => (target, clean_input, false),
            None => match fallback_wf_id {
                Some(fb) => {
                    let mut fb_input = if let Some(obj) = clean_input.as_object() {
                        obj.clone()
                    } else {
                        serde_json::Map::new()
                    };
                    fb_input.insert(
                        "__unmatched_class__".to_string(),
                        serde_json::json!(class_str),
                    );
                    (fb, serde_json::Value::Object(fb_input), true)
                }
                None => {
                    let route_keys: Vec<&String> = routes.keys().collect();
                    return serde_json::json!({
                        "__error": true,
                        "error_message": format!(
                            "LLM dispatch: class '{}' not in routes {:?}",
                            class_str, route_keys
                        )
                    });
                }
            },
        };

        // 3. Execute the target workflow and annotate the result.
        let context_label = if is_fallback {
            "LlmDispatch fallback"
        } else {
            "LlmDispatch target"
        };
        match self
            .execute_subworkflow_graph(
                target_wf_id,
                input_for_target,
                dispatcher,
                worker_shared_key,
            )
            .await
        {
            Ok(target_out) => {
                let mut out = if let Some(obj) = target_out.as_object() {
                    obj.clone()
                } else {
                    let mut m = serde_json::Map::new();
                    m.insert("output".to_string(), target_out);
                    m
                };
                out.insert(
                    "__dispatched_class__".to_string(),
                    serde_json::json!(class_str),
                );
                out.insert(
                    "__dispatched_workflow_id__".to_string(),
                    serde_json::json!(target_wf_id.to_string()),
                );
                // Unified observability fields (parity with capability_dispatch
                // / expression_dispatch) — readers can pivot on these without
                // having to know the dispatcher kind ahead of time.
                out.insert(
                    "__dispatched_by".to_string(),
                    serde_json::json!("llm_dispatch"),
                );
                out.insert(
                    "__dispatch_branch__".to_string(),
                    serde_json::json!(class_str),
                );
                if is_fallback {
                    out.insert(
                        "__llm_dispatch_fallback".to_string(),
                        serde_json::json!(true),
                    );
                }
                serde_json::Value::Object(out)
            }
            Err(e) => e.into_error_envelope(context_label),
        }
    }

    /// One-shot dispatch of a `ReflectiveRetry` system node.
    ///
    /// Runs `child_wf_id` up to `max_retries` times. After each failure,
    /// invokes `reflection_wf_id` with `{input, error, attempt}`. The
    /// reflection workflow's returned fields are merged (non-`__` keys only)
    /// back into the child's input for the next attempt — the child adapts
    /// instead of blindly re-running identical input.
    ///
    /// Returns the child's collapsed terminal output enriched with
    /// `__reflective_retry_attempts__` on success, or an error envelope on
    /// exhaustion.
    #[tracing::instrument(
        level = "info",
        name = "reflective_retry",
        skip_all,
        fields(
            child_workflow_id = %child_wf_id,
            reflection_workflow_id = %reflection_wf_id,
            max_retries,
        ),
    )]
    pub async fn dispatch_reflective_retry(
        &self,
        initial_input: JsonValue,
        child_wf_id: Uuid,
        reflection_wf_id: Uuid,
        max_retries: u32,
        dispatcher: Arc<dyn talos_workflow_engine_core::NodeDispatcher>,
        worker_shared_key: Option<talos_workflow_engine_core::WorkerSharedKey>,
    ) -> JsonValue {
        let mut current_input = initial_input;
        let mut last_error = String::new();

        for attempt in 1..=max_retries {
            let clean_input = if let Some(obj) = current_input.as_object() {
                let mut c = obj.clone();
                c.retain(|k, _| !k.starts_with("__"));
                serde_json::Value::Object(c)
            } else {
                current_input.clone()
            };

            let child_out = match self
                .execute_subworkflow_graph(
                    child_wf_id,
                    clean_input.clone(),
                    dispatcher.clone(),
                    worker_shared_key.clone(),
                )
                .await
            {
                Ok(v) => v,
                Err(e) => e.into_error_envelope("ReflectiveRetry child"),
            };

            if !child_out
                .get("__error")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                Self::emit_quality_gate_event("reflective_retry", true, None, Some(attempt), None);
                let mut out = if let Some(obj) = child_out.as_object() {
                    obj.clone()
                } else {
                    let mut m = serde_json::Map::new();
                    m.insert("output".to_string(), child_out.clone());
                    m
                };
                out.insert(
                    "__reflective_retry_attempts__".to_string(),
                    serde_json::json!(attempt),
                );
                return serde_json::Value::Object(out);
            }

            last_error = child_out
                .get("error_message")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error")
                .to_string();

            if attempt < max_retries {
                let reflect_input = serde_json::json!({
                    "input": clean_input,
                    "error": last_error,
                    "attempt": attempt,
                });
                if let Ok(reflection_out) = self
                    .execute_subworkflow_graph(
                        reflection_wf_id,
                        reflect_input,
                        dispatcher.clone(),
                        worker_shared_key.clone(),
                    )
                    .await
                {
                    let mut merged = if let Some(obj) = current_input.as_object() {
                        obj.clone()
                    } else {
                        serde_json::Map::new()
                    };
                    if let Some(obj) = reflection_out.as_object() {
                        for (k, v) in obj {
                            if !k.starts_with("__") {
                                merged.insert(k.clone(), v.clone());
                            }
                        }
                    }
                    current_input = serde_json::Value::Object(merged);
                }
            }
        }

        Self::emit_quality_gate_event(
            "reflective_retry",
            false,
            None,
            Some(max_retries),
            Some("exhausted"),
        );
        serde_json::json!({
            "__error": true,
            "error_message": format!(
                "Reflective retry exhausted {} attempts. Last error: {}",
                max_retries, last_error
            ),
        })
    }

    /// One-shot dispatch of a `SubWorkflow` system node.
    ///
    /// Strips engine metadata (`__*`) from the inbound parent inputs before
    /// passing as the sub-workflow trigger, then returns the collapsed
    /// terminal output (single-terminal workflows flatten to their leaf
    /// output; multi-terminal fall back to label-keyed map).
    pub async fn dispatch_subworkflow(
        &self,
        inputs: JsonValue,
        sub_wf_id: Uuid,
        dispatcher: Arc<dyn talos_workflow_engine_core::NodeDispatcher>,
        worker_shared_key: Option<talos_workflow_engine_core::WorkerSharedKey>,
    ) -> JsonValue {
        // Strip internal metadata keys so sub-workflow input doesn't carry
        // engine internals (`__trigger_input__`, `__fuel_consumed__`, …).
        let clean_input = if let Some(obj) = inputs.as_object() {
            let mut cleaned = obj.clone();
            cleaned.retain(|k, _| !k.starts_with("__"));
            serde_json::Value::Object(cleaned)
        } else {
            inputs
        };
        match self
            .execute_subworkflow_graph(sub_wf_id, clean_input, dispatcher, worker_shared_key)
            .await
        {
            Ok(collapsed) => collapsed,
            Err(e) => {
                tracing::error!(sub_workflow_id = %sub_wf_id, error = ?e, "Sub-workflow execution failed");
                e.into_error_envelope("Sub-workflow")
            }
        }
    }

    /// Emit a `target: "talos_workflow_engine"` event for a quality-gate outcome.
    ///
    /// Structured telemetry for judge / reflective-retry / ensemble so operators
    /// can answer "what's our judge pass rate?" and "how often does reflection
    /// rescue a failing child?" without plumbing custom metrics per-workflow.
    fn emit_quality_gate_event(
        kind: &'static str,
        passed: bool,
        score: Option<f64>,
        attempts: Option<u32>,
        extra: Option<&str>,
    ) {
        tracing::info!(
            target: "talos_workflow_engine",
            event_kind = "quality_gate",
            gate = kind,
            passed = passed,
            score = score,
            attempts = attempts,
            extra = extra,
            "quality gate completed"
        );
    }

    /// Best-effort record of an observe-only judge verdict for the weekly
    /// `assistant_report` node. Extracts `(score, passed)` from the judge
    /// node's enriched output and hands it to the injected
    /// [`JudgeScoreRecorder`](talos_workflow_engine_core::JudgeScoreRecorder)
    /// off the hot path via `tokio::spawn`. No recorder wired, no workflow
    /// id, or no `__judge_score__` in the output → silent no-op. The
    /// recorder swallows its own DB errors, so this can NEVER fail the
    /// workflow — same discipline as the `__ops_alert__` / DLQ hooks.
    pub(crate) fn record_judge_score(&self, node_id: Uuid, execution_id: Uuid, output: &JsonValue) {
        let Some(recorder) = self.judge_score_recorder.as_ref() else {
            return;
        };
        let Some(workflow_id) = self.workflow_id else {
            return;
        };
        let Some((score, passed)) = extract_judge_score(output) else {
            return;
        };
        let recorder = Arc::clone(recorder);
        tokio::spawn(async move {
            recorder
                .record(workflow_id, node_id, execution_id, score, passed)
                .await;
        });
    }

    /// One-shot dispatch of a Judge system node. Builds the judge input from
    /// `parent_inputs`, runs the judge sub-workflow, parses the verdict, and
    /// returns the final output envelope that the outer loop will insert into
    /// the results map.
    ///
    /// # When to call this directly
    ///
    /// Most consumers don't — putting a [`SystemNodeKind::Judge`] node
    /// in the workflow graph and letting the scheduler call this method
    /// is the supported path. This method is also `pub` so embedders
    /// who want a one-off judge invocation outside any graph (e.g. an
    /// MCP handler that scores a single LLM output, a CLI tool, an
    /// HTTP endpoint that takes content + rubric and returns a
    /// verdict) can call it directly without authoring a wrapper
    /// graph. Same `JudgeVerdict` shape, same sub-workflow lookup
    /// path, same envelope. See
    /// [`docs/sub-workflow-composition.md`](https://github.com/aegix-dev/talos-workflow-engine/blob/main/docs/sub-workflow-composition.md)
    /// for the verdict-shape contract.
    ///
    /// Shared by the `run` and `run_with_seed` dispatch loops — both previously
    /// inlined ~100 lines of near-identical logic here.
    //
    // `skip_all` is load-bearing: `parent_inputs` may carry plaintext
    // post-template-interpolation secrets; never forward it to a tracing
    // sink. Identifying fields are explicit so production debugging can
    // correlate without UUID hand-tracing.
    #[tracing::instrument(
        level = "info",
        name = "judge",
        skip_all,
        fields(
            judge_workflow_id = %judge_wf_id,
            pass_threshold = ?pass_threshold,
        ),
    )]
    pub async fn dispatch_judge(
        &self,
        parent_inputs: JsonValue,
        judge_wf_id: Uuid,
        rubric: String,
        pass_threshold: Option<f64>,
        on_failure: &str,
        dispatcher: Arc<dyn talos_workflow_engine_core::NodeDispatcher>,
        worker_shared_key: Option<talos_workflow_engine_core::WorkerSharedKey>,
    ) -> JsonValue {
        let judge_input = serde_json::json!({
            "content": &parent_inputs,
            "rubric": rubric,
        });
        match self
            .execute_subworkflow_graph(judge_wf_id, judge_input, dispatcher, worker_shared_key)
            .await
        {
            Ok(collapsed) => {
                let verdict = JudgeVerdict::from_collapsed(&collapsed);
                let JudgeVerdict {
                    score,
                    passed: passed_raw,
                    reasoning,
                    feedback,
                    malformed_field_count,
                } = verdict;
                let passed = if let Some(threshold) = pass_threshold {
                    passed_raw && score >= threshold
                } else {
                    passed_raw
                };
                Self::emit_quality_gate_event(
                    "judge",
                    passed,
                    Some(score),
                    None,
                    if malformed_field_count > 0 {
                        Some("malformed_verdict")
                    } else {
                        None
                    },
                );
                if passed {
                    let mut out = if let Some(obj) = parent_inputs.as_object() {
                        obj.clone()
                    } else {
                        serde_json::Map::new()
                    };
                    out.insert("__judge_score__".to_string(), serde_json::json!(score));
                    out.insert("__judge_passed__".to_string(), serde_json::json!(true));
                    out.insert(
                        "__judge_reasoning__".to_string(),
                        serde_json::json!(reasoning),
                    );
                    out.insert(
                        "__judge_feedback__".to_string(),
                        serde_json::json!(feedback),
                    );
                    serde_json::Value::Object(out)
                } else if on_failure == "passthrough" {
                    // Forward the parent output enriched with the rejection
                    // envelope. Downstream edges can conditional-route on
                    // `__judge_passed__ == false` without tripping the error
                    // path — same semantics as `verify` with
                    // `on_failure: passthrough`.
                    let mut out = if let Some(obj) = parent_inputs.as_object() {
                        obj.clone()
                    } else {
                        serde_json::Map::new()
                    };
                    out.insert("__judge_score__".to_string(), serde_json::json!(score));
                    out.insert("__judge_passed__".to_string(), serde_json::json!(false));
                    out.insert("__judge_rejected__".to_string(), serde_json::json!(true));
                    out.insert(
                        "__judge_reasoning__".to_string(),
                        serde_json::json!(reasoning),
                    );
                    out.insert(
                        "__judge_feedback__".to_string(),
                        serde_json::json!(feedback),
                    );
                    serde_json::Value::Object(out)
                } else {
                    serde_json::json!({
                        "__error": true,
                        "error_message": format!("Judge rejected output: {} (score: {:.2})", reasoning, score),
                        "__judge_score__": score,
                        "__judge_passed__": false,
                        "__judge_feedback__": feedback,
                    })
                }
            }
            Err(e) => e.into_error_envelope("Judge"),
        }
    }

    /// Inline-expression judge — evaluate `verdict_expr` against the
    /// gathered parent inputs via the configured
    /// [`ExpressionEvaluator`](talos_workflow_engine_core::ExpressionEvaluator),
    /// parse the result as a [`JudgeVerdict`], and produce the same
    /// pass / reject envelope shape as the sub-workflow
    /// [`dispatch_judge`](Self::dispatch_judge) path.
    ///
    /// Synchronous because it does no I/O — purely an expression
    /// evaluation. Useful when the verdict reduces to a one-line
    /// scoring function and the cost of authoring + dispatching a
    /// separate sub-workflow isn't justified. Promote to a full
    /// `Judge` once the rubric grows its own model call or branching.
    ///
    /// On evaluator failure (no evaluator wired, expression error,
    /// non-object output) the function emits an error envelope rather
    /// than panicking — the engine already treats `__error: true` as
    /// a node-level failure routable through `ErrorHandler` edges.
    ///
    /// # When to call this directly
    ///
    /// Same shape as
    /// [`dispatch_judge`](Self::dispatch_judge): the supported path
    /// is to author a [`SystemNodeKind::InlineJudge`] in the graph
    /// and let the scheduler dispatch it. Embedders who want to
    /// score a single value outside any graph (e.g. a CLI checking
    /// quality of a one-off LLM output, an HTTP handler that scores
    /// content + verdict-expr and returns a verdict) can call this
    /// method directly. Synchronous — no `await` required at the
    /// call site.
    //
    // `skip_all` keeps `parent_inputs` and the expression text out of
    // the span — both can carry plaintext secrets after caller-side
    // template interpolation.
    #[cfg(feature = "llm-primitives")]
    #[tracing::instrument(
        level = "info",
        name = "inline_judge",
        skip_all,
        fields(pass_threshold = ?pass_threshold),
    )]
    pub fn dispatch_inline_judge(
        &self,
        parent_inputs: JsonValue,
        verdict_expr: &str,
        pass_threshold: Option<f64>,
        on_failure: &str,
    ) -> JsonValue {
        let raw_verdict = match self.eval_json(verdict_expr, &parent_inputs) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "InlineJudge: verdict expression failed to evaluate",
                );
                return serde_json::json!({
                    "__error": true,
                    "error_message": format!("InlineJudge expression failed: {e}"),
                });
            }
        };
        let verdict = JudgeVerdict::from_collapsed(&raw_verdict);
        let JudgeVerdict {
            score,
            passed: passed_raw,
            reasoning,
            feedback,
            malformed_field_count,
        } = verdict;
        let passed = if let Some(threshold) = pass_threshold {
            passed_raw && score >= threshold
        } else {
            passed_raw
        };
        Self::emit_quality_gate_event(
            "inline_judge",
            passed,
            Some(score),
            None,
            if malformed_field_count > 0 {
                Some("malformed_verdict")
            } else {
                None
            },
        );
        if passed {
            let mut out = if let Some(obj) = parent_inputs.as_object() {
                obj.clone()
            } else {
                serde_json::Map::new()
            };
            out.insert("__judge_score__".to_string(), serde_json::json!(score));
            out.insert("__judge_passed__".to_string(), serde_json::json!(true));
            out.insert(
                "__judge_reasoning__".to_string(),
                serde_json::json!(reasoning),
            );
            out.insert(
                "__judge_feedback__".to_string(),
                serde_json::json!(feedback),
            );
            serde_json::Value::Object(out)
        } else if on_failure == "passthrough" {
            let mut out = if let Some(obj) = parent_inputs.as_object() {
                obj.clone()
            } else {
                serde_json::Map::new()
            };
            out.insert("__judge_score__".to_string(), serde_json::json!(score));
            out.insert("__judge_passed__".to_string(), serde_json::json!(false));
            out.insert("__judge_rejected__".to_string(), serde_json::json!(true));
            out.insert(
                "__judge_reasoning__".to_string(),
                serde_json::json!(reasoning),
            );
            out.insert(
                "__judge_feedback__".to_string(),
                serde_json::json!(feedback),
            );
            serde_json::Value::Object(out)
        } else {
            serde_json::json!({
                "__error": true,
                "error_message": format!(
                    "InlineJudge rejected output: {} (score: {:.2})",
                    reasoning, score
                ),
                "__judge_score__": score,
                "__judge_passed__": false,
                "__judge_feedback__": feedback,
            })
        }
    }

    /// Execute a sub-workflow by ID with the given trigger input, and return
    /// the collapsed terminal output.
    ///
    /// This is the canonical sub-workflow invocation path. It encapsulates what
    /// was previously duplicated at ~10 call sites (judge, ensemble, reflective-
    /// retry, `sub_workflow`, llm-dispatch) across two dispatch loops:
    ///
    /// 1. Load the sub-workflow graph from the DB (via the registry's `db_pool`).
    /// 2. Build an engine, register a synthetic `__trigger__` node, wire it to
    ///    every root so root nodes execute instead of being pre-seeded.
    /// 3. `run_with_seed` with `trigger_input` as the trigger's output.
    /// 4. Call [`Self::collapse_subworkflow_output`] to flatten the
    ///    results into the shape callers expect (single-terminal → its
    ///    unwrapped output).
    ///
    /// Returns `Ok(JsonValue)` with the collapsed output, or [`SubflowError`]
    /// which each caller converts into their own error envelope via
    /// [`SubflowError::into_error_envelope`].
    ///
    /// # Durability limitation (by design)
    ///
    /// The sub-engine built here is **not** given a `CheckpointStore`, so a
    /// sub-workflow does not checkpoint its own progress. If the controller
    /// crashes mid-sub-workflow, crash-recovery resumes the PARENT execution
    /// from its last checkpoint and the sub-workflow re-runs from the start —
    /// it is not resumed mid-flight the way a top-level execution is. This is
    /// an intentional cost/complexity trade-off (per-sub-workflow durable state
    /// would multiply checkpoint volume), but callers whose sub-workflows have
    /// non-idempotent side effects must make those steps idempotent themselves;
    /// the engine will not dedupe a re-run sub-workflow's effects.
    #[tracing::instrument(
        level = "info",
        name = "subworkflow",
        skip_all,
        fields(sub_workflow_id = %sub_wf_id),
    )]
    pub async fn execute_subworkflow_graph(
        &self,
        sub_wf_id: Uuid,
        trigger_input: JsonValue,
        dispatcher: Arc<dyn talos_workflow_engine_core::NodeDispatcher>,
        worker_shared_key: Option<talos_workflow_engine_core::WorkerSharedKey>,
    ) -> Result<JsonValue, SubflowError> {
        self.module_fetcher
            .as_ref()
            .ok_or(SubflowError::NoRegistry)?;
        let user_id = self.user_id.ok_or(SubflowError::NoUserId)?;
        self.secrets_resolver
            .as_ref()
            .ok_or(SubflowError::NoSecretsResolver)?;

        let graph_json = self
            .get_sub_workflow_graph(sub_wf_id, user_id)
            .await
            .ok_or_else(|| SubflowError::GraphNotFound(sub_wf_id))?;

        // Reuse the parent's adapter Arcs (Arc::clone is a refcount
        // bump per trait object — cheap). Use the *guarded* path
        // (`into_engine_with_graph`) so the recursion-depth check
        // fires here — without it, a self-referential workflow
        // would stack-overflow the reactor instead of returning a
        // typed error.
        let mut sub_engine = self
            .adapter_set()
            .into_engine_with_graph(&graph_json)
            .map_err(|e| SubflowError::BuildFailed(e.to_string()))?;

        // The sub-workflow runs under a synthetic execution id with no
        // `workflow_executions` row (see the `run_with_seed_with_transport`
        // call below, seeded with `Uuid::new_v4()`). The parent's
        // `PostgresEventSink` FKs every event's `execution_id` to
        // `workflow_executions`, so leaving it attached logs a WARN and
        // drops every inner node event — noise plus a wasted DB round-trip.
        // Detach it (fuel + memory writes are unaffected — see
        // `clear_event_sink`).
        sub_engine.clear_event_sink();

        // Cross-actor isolation: when a parent dispatches a sub-workflow
        // bound to a *different* actor, hydrate the sub-engine with that
        // actor's `__actor_context__` so downstream LLM nodes with
        // INJECT_CONTEXT=true see the sub-workflow's intended persona,
        // not nothing. Without this hook, the freshly-built sub-engine
        // has `actor_context = None` regardless of the sub-workflow's
        // bound actor — which silently degrades cross-actor patterns
        // (e.g. CEO calls VPE) to "second LLM call with the same parent
        // context" instead of real cross-actor consultation. Returning
        // `None` from the resolver keeps the pre-hook behaviour exactly.
        if let Some(resolver) = self.sub_actor_context_resolver.as_ref() {
            if let Some(ctx) = resolver.resolve(sub_wf_id, user_id).await {
                sub_engine.set_actor_context(ctx);
            }
        }

        // Bind the sub-engine to the sub-workflow's OWN actor identity
        // (so direct agent_memory RPCs resolve against the sub-workflow's
        // actor, matching the __actor_context__ injection above) AND narrow
        // each ceiling to the most-restrictive of (parent, sub-actor) so a
        // sub-workflow bound to a stricter actor can't inherit the parent's
        // looser ceiling. See `bind_subengine_actor_and_ceilings`.
        self.bind_subengine_actor_and_ceilings(&mut sub_engine, sub_wf_id, user_id)
            .await;

        // Synthetic trigger node: seeded with the caller's input,
        // wired to every root so root-level modules actually execute.
        // Delegates to the shared helper so this path and the public
        // `run_with_trigger_input_transport` can't drift.
        let trigger_node_id = sub_engine.ensure_trigger_node_wired_to_roots();
        let mut initial_results = HashMap::new();
        initial_results.insert(trigger_node_id, trigger_input);

        let ctx = sub_engine
            .run_with_seed_with_transport(
                dispatcher,
                worker_shared_key,
                initial_results,
                Uuid::new_v4(),
            )
            .await
            .map_err(|e| SubflowError::ExecutionFailed(e.to_string()))?;

        Ok(Self::collapse_subworkflow_output(&ctx.results, &sub_engine))
    }

    /// Resolve the binding a sub-workflow should run under: its OWN actor
    /// identity (memory scope + action attribution) plus the ceilings, where
    /// each ceiling is the most-restrictive of `(this engine's ceiling, the
    /// sub-workflow actor's ceiling)` on each axis (`max_llm_tier`,
    /// `max_write_ceiling`, `egress_scope`).
    ///
    /// **Identity: adopt the sub-actor.** `AdapterSet` copies the PARENT's
    /// `actor_id` verbatim into a freshly-built sub-engine, so without this a
    /// sub-workflow's direct `agent_memory::get/set` RPCs resolve against the
    /// PARENT's memory even though the sub-workflow is bound to a different
    /// actor — silently disagreeing with the `__actor_context__` injection
    /// path (which already uses the sub-actor) and writing memory into the
    /// wrong actor. We pass the sub-actor's `actor_id` straight through
    /// (identity is not a lattice — it's simply adopted); the executor sets
    /// it. This is not an escalation: the resolver only answers for a
    /// workflow visible to `user_id` bound to an actor owned by `user_id`.
    ///
    /// **Ceilings: fail-closed, narrow-only composition.** Without this, a
    /// sub-workflow bound to a MORE restrictive actor (e.g. a Tier-1,
    /// read-only persona) would silently inherit the parent's looser
    /// ceiling — a privilege escalation across the sub-workflow boundary.
    /// The composition can only ever *tighten*: a looser sub-actor ceiling
    /// has no widening effect.
    ///
    /// `None` (no resolver, or no distinct sub-actor binding) means "keep the
    /// inherited parent identity + ceilings" — safe, since the parent bound
    /// is already the caller's authorized one.
    pub(crate) async fn resolve_subworkflow_binding(
        &self,
        sub_wf_id: Uuid,
        user_id: Uuid,
    ) -> Option<talos_workflow_engine_core::SubworkflowBinding> {
        let resolver = self.sub_actor_context_resolver.as_ref()?;
        let sub = resolver.resolve_binding(sub_wf_id, user_id).await?;
        // Egress narrows one-directionally (explicit Local wins), but — unlike
        // the concrete tier/write axes — the override is an `Option` where
        // `None` means "tier-derived default". Resolve BOTH sides to their
        // EFFECTIVE concrete scope FIRST so a sub-actor air-gapped only by its
        // tier default (egress column NULL, e.g. every pre-feature Tier-1
        // actor) is NOT silently widened to a `Public` parent's scope across
        // the sub-workflow boundary. Without this, `narrow(Some(Public), None)`
        // would defer to the parent and drop the sub-actor's air-gap.
        let parent_egress = talos_workflow_engine_core::EgressScope::effective(
            self.egress_scope,
            self.max_llm_tier,
        );
        let sub_egress_eff =
            talos_workflow_engine_core::EgressScope::effective(sub.egress_scope, sub.max_llm_tier);
        Some(talos_workflow_engine_core::SubworkflowBinding {
            // Identity is adopted verbatim (see doc) — no narrowing.
            actor_id: sub.actor_id,
            max_llm_tier: self.max_llm_tier.most_restrictive(sub.max_llm_tier),
            max_write_ceiling: self
                .max_write_ceiling
                .most_restrictive(sub.max_write_ceiling),
            egress_scope: talos_workflow_engine_core::EgressScope::narrow(
                Some(parent_egress),
                Some(sub_egress_eff),
            ),
        })
    }

    /// Apply a resolved [`talos_workflow_engine_core::SubworkflowBinding`] to a
    /// freshly-built sub-engine: adopt the sub-workflow's own actor identity
    /// (when known) and stamp the fail-closed narrowed ceilings.
    ///
    /// Identity and the tier ceiling are stamped **together** here — the same
    /// invariant lint check 29 enforces for the top-level
    /// `apply_actor_to_engine` path (never set `actor_id` without stamping the
    /// tier, or a Tier-1 actor silently runs Tier-2). This call site is inside
    /// `talos-workflow-engine`, where the setter legitimately lives, so the
    /// bare `set_actor_id` is exempt by design.
    pub(crate) fn apply_subworkflow_binding(
        sub_engine: &mut ParallelWorkflowEngine,
        binding: &talos_workflow_engine_core::SubworkflowBinding,
    ) {
        // `None` = identity couldn't be resolved (fail-closed DB error); keep
        // the parent's already-authorized identity rather than guess a scope.
        if let Some(actor_id) = binding.actor_id {
            sub_engine.set_actor_id(actor_id);
        }
        sub_engine.set_max_llm_tier(binding.max_llm_tier);
        sub_engine.set_max_write_ceiling(binding.max_write_ceiling);
        sub_engine.set_egress_scope(binding.egress_scope);
    }

    /// Apply [`Self::resolve_subworkflow_binding`] to a freshly-built
    /// sub-engine. Call this on EVERY sub-engine built via
    /// `adapter_set().into_engine_with_graph(...)` before running it —
    /// `execute_subworkflow_graph`, dynamic/capability dispatch, and the
    /// agent-loop body all go through here so the identity rebind AND the
    /// fail-closed ceiling narrowing can't be forgotten on one path (the
    /// escalation gap H2 closed; the identity axis added 2026-07).
    pub(crate) async fn bind_subengine_actor_and_ceilings(
        &self,
        sub_engine: &mut ParallelWorkflowEngine,
        sub_wf_id: Uuid,
        user_id: Uuid,
    ) {
        if let Some(binding) = self.resolve_subworkflow_binding(sub_wf_id, user_id).await {
            Self::apply_subworkflow_binding(sub_engine, &binding);
        }
    }

    /// Reduce a sub-workflow's `results` map into the single value
    /// the parent dispatch site sees as "the sub-workflow's output."
    ///
    /// Two cases:
    ///
    /// * **One terminal node.** Returns that node's output unwrapped.
    ///   This is the canonical case — `Judge`, `Ensemble`, and
    ///   `ReflectiveRetry` all rely on it for their structured-shape
    ///   parsing.
    /// * **Multiple terminal nodes (or a complex shape).** Falls back
    ///   to a label-keyed map so the parent retains every terminal's
    ///   output by its node label.
    ///
    /// Skipped nodes (`{"__skipped": true}`) and the synthetic
    /// `__trigger__` node added by sub-workflow dispatch are filtered
    /// out before collapse.
    pub fn collapse_subworkflow_output(
        ctx_results: &HashMap<Uuid, JsonValue>,
        sub_engine: &ParallelWorkflowEngine,
    ) -> JsonValue {
        // Index uuid -> NodeIndex once (O(V)) so per-node lookups stay O(1).
        let mut uuid_to_idx: HashMap<Uuid, NodeIndex> =
            HashMap::with_capacity(sub_engine.graph.node_count());
        for idx in sub_engine.graph.node_indices() {
            uuid_to_idx.insert(sub_engine.graph[idx], idx);
        }

        // Partition node outputs into (terminal, non_terminal) while stripping
        // skipped + trigger + engine envelope.
        let mut terminals: Vec<(String, JsonValue)> = Vec::new();
        let mut non_terminals: Vec<(String, JsonValue)> = Vec::new();
        for (nid, output) in ctx_results {
            if output
                .get("__skipped")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                continue;
            }
            let label = sub_engine
                .node_labels
                .get(nid)
                .cloned()
                .unwrap_or_else(|| nid.to_string());
            if label == "__trigger__" {
                continue;
            }
            let unwrapped = Self::unwrap_output(output).clone();
            let is_terminal = match uuid_to_idx.get(nid) {
                Some(idx) => {
                    sub_engine
                        .graph
                        .neighbors_directed(*idx, Direction::Outgoing)
                        .count()
                        == 0
                }
                // Node present in results but not in the graph — treat as non-terminal
                // so it can't accidentally shadow the real leaf.
                None => false,
            };
            if is_terminal {
                terminals.push((label, unwrapped));
            } else {
                non_terminals.push((label, unwrapped));
            }
        }

        // Canonical path: exactly one terminal → its output IS the sub-workflow output.
        if terminals.len() == 1 {
            return terminals.into_iter().next().unwrap().1;
        }

        // Fallback: label-keyed map. Insert non-terminals first, then terminals,
        // so a terminal's label wins any collision (stable, predictable ordering).
        let mut map = serde_json::Map::with_capacity(non_terminals.len() + terminals.len());
        for (label, output) in non_terminals {
            map.insert(label, output);
        }
        for (label, output) in terminals {
            map.insert(label, output);
        }
        JsonValue::Object(map)
    }

    /// Resolve the workflow's original trigger input from the completed-
    /// results map. Returns `None` when the synthetic `__trigger__` node
    /// hasn't emitted yet (should never happen on the main dispatch
    /// path, but the reactor may call this before seed hydration under
    /// some edge cases).
    ///
    /// Behaviour for nested cases:
    ///
    /// * When the parent workflow was itself invoked as a sub-workflow,
    ///   its `results[__trigger__]` is a wrapper blob shaped like
    ///   `{..upstream, "__trigger_input__": <root-user-trigger>}`. We
    ///   unwrap one level so callers downstream see the **original
    ///   user-facing trigger** — which is the whole point of the
    ///   `__trigger_input__` key (survive sub-workflow boundaries).
    /// * When no wrapper is present (top-level workflow), the trigger
    ///   blob IS the trigger input — returned as-is.
    ///
    /// This keeps the scaffold's "`__trigger_input__` is always preserved"
    /// contract honest even for 2+ level deep composition. Single source
    /// of truth — all three callers (loop body dispatcher, single-node
    /// dispatcher, sub-workflow dispatcher) use this helper.
    pub(crate) fn extract_trigger_input(
        &self,
        results: &HashMap<Uuid, JsonValue>,
    ) -> Option<JsonValue> {
        let trigger_blob = self
            .node_labels
            .iter()
            .find(|(_, label)| label.as_str() == "__trigger__")
            .and_then(|(uuid, _)| results.get(uuid))
            .cloned()?;
        // Nested case: we're a sub-workflow whose trigger carries the
        // outer user trigger under `__trigger_input__`. Unwrap one level.
        if let Some(obj) = trigger_blob.as_object() {
            if let Some(inner) = obj.get("__trigger_input__") {
                return Some(inner.clone());
            }
        }
        Some(trigger_blob)
    }

    /// Strip the engine's wrapping envelope from a node output if
    /// present. Workers sometimes return `{"input": <real>, "score":
    /// ..., "passed": ...}` where the real payload is under `"input"`
    /// and the outer keys are duplicated for convenience; this helper
    /// returns a reference to the unwrapped inner value when that
    /// wrapper is detected, otherwise to `output` unchanged.
    pub fn unwrap_output(output: &JsonValue) -> &JsonValue {
        // If output is a JSON string that contains JSON, try to parse it
        if let JsonValue::String(_s) = output {
            // String output from WASM — try to parse as JSON
            // (handled at a higher level, just return as-is here)
            return output;
        }
        // If output looks like the engine wrapper, strip it down to clean payload.
        if let Some(obj) = output.as_object() {
            // Case 1: {"config": {...}, "input": {...}, ...fields} — extract input
            if obj.contains_key("input") {
                if let Some(inner) = obj.get("input") {
                    if let Some(inner_obj) = inner.as_object() {
                        let is_wrapper = inner_obj.keys().all(|k| obj.contains_key(k));
                        if is_wrapper && !inner_obj.is_empty() {
                            return inner;
                        }
                    }
                }
            }
            // Case 2: {"config": {...}, "input": null} — extract config (direct tool with no input)
            if obj.contains_key("config") && obj.get("input").map(|v| v.is_null()).unwrap_or(false)
            {
                if let Some(config) = obj.get("config") {
                    if config.is_object()
                        && !config.as_object().map(|m| m.is_empty()).unwrap_or(true)
                    {
                        return config;
                    }
                }
                // config is also empty — return empty object
                if obj.len() == 2 {
                    return &JsonValue::Null;
                }
            }
        }
        output
    }
}

#[cfg(test)]
mod identity_binding_tests {
    //! Unit coverage for the sub-workflow identity rebind + fail-closed
    //! ceiling narrowing (`resolve_subworkflow_binding` /
    //! `apply_subworkflow_binding`). These exercise the real production
    //! composition — a mock resolver stands in for the DB lookup, but the
    //! narrowing math and the identity-adoption rule are the shipping code.

    use super::ParallelWorkflowEngine;
    use async_trait::async_trait;
    use serde_json::Value as JsonValue;
    use std::sync::Arc;
    use talos_workflow_engine_core::{
        EgressScope, LlmTier, SubworkflowActorContextResolver, SubworkflowBinding, WriteCeiling,
    };
    use uuid::Uuid;

    /// A resolver that returns a fixed binding (or `None`), standing in for
    /// the DB-backed `ControllerSubActorContextResolver`.
    struct MockResolver(Option<SubworkflowBinding>);

    #[async_trait]
    impl SubworkflowActorContextResolver for MockResolver {
        async fn resolve(&self, _workflow_id: Uuid, _user_id: Uuid) -> Option<JsonValue> {
            None
        }
        async fn resolve_binding(
            &self,
            _workflow_id: Uuid,
            _user_id: Uuid,
        ) -> Option<SubworkflowBinding> {
            self.0
        }
    }

    fn engine_with_binding(
        parent_tier: LlmTier,
        parent_write: WriteCeiling,
        parent_egress: Option<EgressScope>,
        sub: Option<SubworkflowBinding>,
    ) -> ParallelWorkflowEngine {
        let mut e = ParallelWorkflowEngine::new();
        e.set_max_llm_tier(parent_tier);
        e.set_max_write_ceiling(parent_write);
        e.set_egress_scope(parent_egress);
        e.set_sub_actor_context_resolver(Arc::new(MockResolver(sub)));
        e
    }

    #[tokio::test]
    async fn resolve_binding_adopts_sub_actor_and_narrows_ceilings() {
        let sub_actor = Uuid::new_v4();
        // Parent is loose (Tier2 / Write / Public); sub-actor is strict
        // (Tier1 / ReadOnly / egress NULL → tier-derived Local).
        let e = engine_with_binding(
            LlmTier::Tier2,
            WriteCeiling::Write,
            Some(EgressScope::Public),
            Some(SubworkflowBinding {
                actor_id: Some(sub_actor),
                max_llm_tier: LlmTier::Tier1,
                max_write_ceiling: WriteCeiling::ReadOnly,
                egress_scope: None,
            }),
        );

        let binding = e
            .resolve_subworkflow_binding(Uuid::new_v4(), Uuid::new_v4())
            .await
            .expect("resolver returns a binding");

        // Identity: the sub-workflow's own actor is adopted verbatim.
        assert_eq!(binding.actor_id, Some(sub_actor));
        // Ceilings: narrowed to the stricter sub-actor on every axis.
        assert_eq!(binding.max_llm_tier, LlmTier::Tier1);
        assert_eq!(binding.max_write_ceiling, WriteCeiling::ReadOnly);
        // Tier1 sub-actor with NULL egress → effective Local; narrow(Public, Local) = Local.
        assert_eq!(binding.egress_scope, Some(EgressScope::Local));
    }

    #[tokio::test]
    async fn resolve_binding_looser_sub_actor_never_widens_but_identity_still_adopted() {
        let sub_actor = Uuid::new_v4();
        // Parent is strict (Tier1 / ReadOnly / Local); sub-actor is loose.
        let e = engine_with_binding(
            LlmTier::Tier1,
            WriteCeiling::ReadOnly,
            Some(EgressScope::Local),
            Some(SubworkflowBinding {
                actor_id: Some(sub_actor),
                max_llm_tier: LlmTier::Tier2,
                max_write_ceiling: WriteCeiling::Write,
                egress_scope: Some(EgressScope::Public),
            }),
        );

        let binding = e
            .resolve_subworkflow_binding(Uuid::new_v4(), Uuid::new_v4())
            .await
            .expect("resolver returns a binding");

        // Identity is adopted even when the sub-actor is LOOSER — identity is
        // not a lattice; only ceilings narrow.
        assert_eq!(binding.actor_id, Some(sub_actor));
        // Every ceiling stays at the stricter parent value (no widening).
        assert_eq!(binding.max_llm_tier, LlmTier::Tier1);
        assert_eq!(binding.max_write_ceiling, WriteCeiling::ReadOnly);
        assert_eq!(binding.egress_scope, Some(EgressScope::Local));
    }

    #[tokio::test]
    async fn resolve_binding_no_resolver_returns_none() {
        // No resolver wired → keep the parent's inherited identity + ceilings.
        let e = ParallelWorkflowEngine::new();
        assert!(e
            .resolve_subworkflow_binding(Uuid::new_v4(), Uuid::new_v4())
            .await
            .is_none());
    }

    #[test]
    fn apply_binding_some_actor_rebinds_identity_and_stamps_ceilings() {
        let parent_actor = Uuid::new_v4();
        let sub_actor = Uuid::new_v4();
        let mut e = ParallelWorkflowEngine::new();
        e.set_actor_id(parent_actor);

        ParallelWorkflowEngine::apply_subworkflow_binding(
            &mut e,
            &SubworkflowBinding {
                actor_id: Some(sub_actor),
                max_llm_tier: LlmTier::Tier1,
                max_write_ceiling: WriteCeiling::ReadOnly,
                egress_scope: Some(EgressScope::Local),
            },
        );

        // The sub-actor identity replaces the parent's — direct agent_memory
        // RPCs in the sub-workflow now resolve against the sub-actor.
        assert_eq!(e.actor_id, Some(sub_actor));
        assert_eq!(e.max_llm_tier, LlmTier::Tier1);
        assert_eq!(e.max_write_ceiling, WriteCeiling::ReadOnly);
        assert_eq!(e.egress_scope, Some(EgressScope::Local));
    }

    #[test]
    fn apply_binding_none_actor_keeps_parent_identity() {
        let parent_actor = Uuid::new_v4();
        let mut e = ParallelWorkflowEngine::new();
        e.set_actor_id(parent_actor);

        // actor_id: None models the fail-closed DB-error path — ceilings still
        // apply (fail-closed), but the parent's authorized identity is kept
        // rather than guessing a scope.
        ParallelWorkflowEngine::apply_subworkflow_binding(
            &mut e,
            &SubworkflowBinding {
                actor_id: None,
                max_llm_tier: LlmTier::Tier1,
                max_write_ceiling: WriteCeiling::ReadOnly,
                egress_scope: Some(EgressScope::Local),
            },
        );

        assert_eq!(e.actor_id, Some(parent_actor));
        // Fail-closed ceilings were still stamped.
        assert_eq!(e.max_llm_tier, LlmTier::Tier1);
        assert_eq!(e.max_write_ceiling, WriteCeiling::ReadOnly);
        assert_eq!(e.egress_scope, Some(EgressScope::Local));
    }
}
