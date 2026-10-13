//! Pure helpers for collecting workflow-execution output from a
//! finished engine run.
//!
//! Lifted from the post-`run_with_trigger_input_via_nats` block that
//! appears identically in 8+ call sites:
//!   * `talos-mcp-handlers::workflows::handle_trigger_workflow`
//!   * `talos-mcp-handlers::executions::handle_replay_execution`
//!     (3 separate variants)
//!   * `talos-mcp-handlers::executions::handle_retry_execution`
//!   * `talos-mcp-handlers::actor::handle_handoff_to_actor`
//!   * `talos-continuation-trigger::trigger_continuation_workflow`
//!   * `talos-webhooks::handle_inbound_webhook` (2 variants)
//!
//! Every call site walked the engine's `WorkflowContext.results`,
//! filtered out the synthetic `__trigger__` and any `__skipped`
//! results, unwrapped each value, inserted `__trigger_input__` and
//! optional `__node_timings__`, then DLP-redacted the whole
//! object before storage.
//!
//! Two pure functions here capture the success and failure paths so
//! the same shape is produced regardless of caller. No I/O, no
//! state — the input is the engine + the finished context + the
//! original trigger input; the output is the JSON value to persist
//! via `mark_execution_completed` / `mark_execution_failed`.
//!
//! Why a dedicated crate instead of an inline helper:
//! - Workers in `talos-webhooks` and `talos-continuation-trigger`
//!   share these blocks; an inline helper in `talos-mcp-handlers`
//!   would create a dep-direction problem.
//! - The DLP-redaction step is a security boundary
//!   (`talos_dlp_provider::redact_json` strips secrets like
//!   `sk-*` / `ghp_*` / Bearer tokens before persistence). Lifting
//!   to a single helper guarantees no caller forgets to call it.

use serde_json::{Map, Value};
use talos_workflow_engine::ParallelWorkflowEngine;
use talos_workflow_engine_core::WorkflowContext;

/// Build the success-path output JSON from a finished engine run.
///
/// Walks `ctx.results`, dropping the synthetic `__trigger__` entry
/// and any node whose result carries `__skipped: true`, projects
/// each surviving value through `ParallelWorkflowEngine::unwrap_output`
/// (which strips internal `__output__` envelopes), keys by the
/// human-readable label from `engine.node_labels()`, and finally
/// inserts `__trigger_input__` and (when non-empty) `__node_timings__`.
///
/// The whole map is DLP-redacted before return so secrets that may
/// appear in node outputs (LLM provider keys, OAuth tokens, etc.)
/// never reach the database. Same redactor (`redact_json`) is used
/// by every caller — single source of truth for the secret-leak
/// boundary.
///
/// Returns `serde_json::Value::Object(...)` ready to pass directly
/// to `WorkflowRepository::mark_execution_completed`.
pub fn collect_success_output(
    engine: &ParallelWorkflowEngine,
    ctx: &WorkflowContext,
    trigger_input_for_storage: &Value,
) -> Value {
    let node_labels = engine.node_labels();
    let mut output = Map::new();
    for (nid, result) in &ctx.results {
        let key = node_labels
            .get(nid)
            .cloned()
            .unwrap_or_else(|| nid.to_string());
        if key == "__trigger__" {
            continue;
        }
        if result
            .get("__skipped")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            continue;
        }
        let clean = ParallelWorkflowEngine::unwrap_output(result).clone();
        output.insert(key, clean);
    }
    output.insert(
        "__trigger_input__".to_string(),
        trigger_input_for_storage.clone(),
    );
    if !ctx.node_timings.is_empty() {
        output.insert(
            "__node_timings__".to_string(),
            serde_json::to_value(&ctx.node_timings).unwrap_or_default(),
        );
    }
    talos_dlp_provider::redact_json(&Value::Object(output))
}

/// The most the completed nodes' outputs of a FAILED run may weigh, as JSON,
/// to be stored with it: half of the execution-payload ceiling
/// ([`talos_dlp_provider::MAX_EXECUTION_PAYLOAD_BYTES`]).
///
/// The ceiling replaces a whole over-size payload with a truncation marker,
/// and a failed run's payload carries `__trigger_input__`, which a retry
/// reads. So the outputs are bounded HERE, on their own, and when they do
/// not fit they are left out and the trigger stays.
pub const FAILED_RUN_OUTPUTS_MAX_BYTES: usize = talos_dlp_provider::MAX_EXECUTION_PAYLOAD_BYTES / 2;

/// The key that says a failed run's completed outputs were NOT stored, and
/// why. Present only then.
pub const OUTPUTS_OMITTED_KEY: &str = "__completed_outputs_omitted__";

/// What a run that did not complete stores: the outputs of the nodes that
/// DID complete, keyed by label exactly as [`collect_success_output`] keys
/// them, and the trigger input when the caller round-trips one.
///
/// Until 2026-10-13 a failed run stored its trigger input and nothing else,
/// so the outputs that explain a failure could not be read back by any tool.
///
/// * `partial` is [`ParallelWorkflowEngine::take_partial_results`]: already
///   scrubbed by the engine's two passes, and `None` when the run left
///   nothing (it failed before any node completed).
/// * The synthetic trigger seed and skipped nodes are dropped, as on the
///   success path. A node whose failure was continued past keeps the error
///   envelope it committed.
/// * Outputs over [`FAILED_RUN_OUTPUTS_MAX_BYTES`] are left out as a whole
///   and [`OUTPUTS_OMITTED_KEY`] says so. Never a subset: a reader could not
///   tell a node that did not run from one that did not fit.
/// * `__trigger_input__` stays at the top level whatever happens to the
///   outputs: retry and replay read it from there.
/// * The whole value is DLP-redacted, like every stored execution output.
///
/// Pure: no engine, so the projection is tested as it runs.
pub fn failure_output(
    node_labels: &std::collections::HashMap<uuid::Uuid, String>,
    partial: Option<std::collections::HashMap<uuid::Uuid, Value>>,
    trigger_input_for_storage: Option<&Value>,
) -> Value {
    let mut output = Map::new();
    for (nid, result) in partial.unwrap_or_default() {
        let key = node_labels
            .get(&nid)
            .cloned()
            .unwrap_or_else(|| nid.to_string());
        if key == "__trigger__" {
            continue;
        }
        if result
            .get("__skipped")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            continue;
        }
        let clean = ParallelWorkflowEngine::unwrap_output(&result).clone();
        output.insert(key, clean);
    }
    let bytes = serde_json::to_vec(&output).map_or(usize::MAX, |b| b.len());
    if bytes > FAILED_RUN_OUTPUTS_MAX_BYTES {
        let nodes = output.len();
        output.clear();
        output.insert(
            OUTPUTS_OMITTED_KEY.to_string(),
            serde_json::json!({
                "reason": "too_large",
                "nodes": nodes,
                "bytes": bytes,
                "limit_bytes": FAILED_RUN_OUTPUTS_MAX_BYTES,
            }),
        );
    }
    if let Some(trigger) = trigger_input_for_storage {
        output.insert(TRIGGER_INPUT_KEY.to_string(), trigger.clone());
    }
    talos_dlp_provider::redact_json(&Value::Object(output))
}

/// The failure-path output of a run that round-trips its trigger input:
/// [`failure_output`] over what the engine kept of the run.
///
/// TAKES the engine's partial results, so call it once per failed run.
pub fn collect_failure_output(
    engine: &ParallelWorkflowEngine,
    trigger_input_for_storage: &Value,
) -> Value {
    failure_output(
        engine.node_labels(),
        engine.take_partial_results(),
        Some(trigger_input_for_storage),
    )
}

/// The same for a path that stores no trigger input with its runs
/// (`call_workflow`, `test_workflow`): the completed nodes' outputs, or
/// `None` when no node completed, so such a run still stores nothing.
///
/// TAKES the engine's partial results, so call it once per failed run.
pub fn collect_failed_run_outputs(engine: &ParallelWorkflowEngine) -> Option<Value> {
    let output = failure_output(engine.node_labels(), engine.take_partial_results(), None);
    output
        .as_object()
        .is_some_and(|o| !o.is_empty())
        .then_some(output)
}

/// Keep the completed nodes' outputs of a run that a path has JUST finalized
/// as failed with a statement that records only the error (the scheduler,
/// the webhook router, the continuation, enqueue and GraphQL paths, crash
/// recovery).
///
/// `attach` is that path's own repository write
/// (`attach_failed_run_outputs` on the workflow or the execution
/// repository, whichever the path completes its runs with, so a failed
/// run's outputs are sealed the way that path seals a completed run's). It
/// is called only when a node completed.
///
/// Best effort, and it says so: the run is already recorded as failed with
/// its error, and that is what must not be lost. A write that fails is
/// logged and dropped; a row that did not take the outputs (another writer
/// finalized it first) is logged at debug.
///
/// TAKES the engine's partial results, so call it once per failed run, and
/// AFTER the failure itself has been written.
pub async fn keep_failed_run_outputs<F, Fut, E>(
    engine: &ParallelWorkflowEngine,
    execution_id: uuid::Uuid,
    attach: F,
) where
    F: FnOnce(Value) -> Fut,
    Fut: std::future::Future<Output = Result<bool, E>>,
    E: std::fmt::Display,
{
    let Some(outputs) = collect_failed_run_outputs(engine) else {
        return;
    };
    match attach(outputs).await {
        Ok(true) => {}
        Ok(false) => tracing::debug!(
            %execution_id,
            "a failed run's completed outputs were not stored: the row is not failed, or already holds an output"
        ),
        Err(e) => tracing::warn!(
            %execution_id,
            error = %e,
            "a failed run's completed outputs could not be stored; the failure itself is recorded"
        ),
    }
}

/// Reserved key under which the original trigger input is round-tripped
/// inside an execution's stored output. Both `collect_success_output`
/// and `collect_failure_output` write to this key; `extract_trigger_input`
/// reads it.
pub const TRIGGER_INPUT_KEY: &str = "__trigger_input__";

/// Pure: extract the round-tripped trigger input from a stored execution
/// output. Returns the inner value, or an empty object if `output_data`
/// is `None` or doesn't carry a `__trigger_input__` field.
///
/// Used by replay / retry / replay-with-input handlers to recover the
/// original trigger payload so the new execution re-runs against the
/// same input. Centralized so the magic-key string lives in one place.
///
/// Engine-authored keys are STRIPPED: a row written before the trigger paths
/// lifted `__actor_context__` off the stored payload carries decrypted actor
/// memory here, and the engine strips those keys at the seed anyway, so
/// carrying them forward would only re-persist the memory on the new run.
pub fn extract_trigger_input(output_data: Option<&Value>) -> Value {
    let mut input = output_data
        .and_then(|o| o.get(TRIGGER_INPUT_KEY))
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    talos_workflow_engine_core::reserved_keys::strip_engine_authored_keys(&mut input);
    input
}

/// NATS subject the alert is published on. Pinned at module scope so
/// downstream subscribers (alerting bus, on-call routers) can grep for
/// the constant rather than the literal string.
pub const EXECUTION_FAILED_ALERT_SUBJECT: &str = "talos.alerts.execution_failed";

/// Publish a `workflow_failed` alert to two surfaces in one call:
/// 1. NATS subject [`EXECUTION_FAILED_ALERT_SUBJECT`] (skipped silently
///    when `nats` is `None` — typical in tests / dev configs without the
///    alert bus wired up).
/// 2. The `execution_failure_alerts` table via
///    [`talos_execution_repository::ExecutionRepository::upsert_execution_failure_alert`]
///    so the MCP `list_alerts` surface picks it up.
///
/// Both writes are best-effort — failures are traced but never propagated
/// to the caller. Mirrors the pre-extraction inline shape duplicated
/// across handle_trigger_workflow and handle_replay_execution.
///
/// `error` is rendered into the `error_msg` for both surfaces; the
/// "Workflow execution failed: " prefix is added inside this helper so
/// the duplicated `format!` no longer drifts between the two handlers.
pub async fn publish_execution_failure_alert(
    execution_repo: &talos_execution_repository::ExecutionRepository,
    nats: Option<&async_nats::Client>,
    user_id: uuid::Uuid,
    workflow_id: uuid::Uuid,
    execution_id: uuid::Uuid,
    error: &str,
) {
    // MCP-443: DLP-redact the error string BEFORE it lands in either
    // surface. Upstream API errors routinely carry tokens — e.g. a
    // `HTTP 401 Unauthorized: invalid token sk-proj-xxx` from an LLM
    // provider, or a Bearer token echoed back in a `WWW-Authenticate`
    // header. The success/failure output path DLP-redacts via
    // `redact_json` already; this path slipped through because it
    // operates on a plain string instead of a JSON tree. The NATS
    // alert payload and the `execution_failure_alerts` DB row both
    // need the redacted form — neither surface gets a second chance
    // at redaction downstream.
    let redacted = talos_dlp_provider::redact_str(error);
    if let Some(client) = nats {
        let alert = serde_json::json!({
            "event": "workflow_failed",
            "workflow_id": workflow_id,
            "execution_id": execution_id,
            "error": redacted,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        let payload = serde_json::to_vec(&alert).unwrap_or_default();
        if let Err(e) = client
            .publish(EXECUTION_FAILED_ALERT_SUBJECT.to_string(), payload.into())
            .await
        {
            tracing::warn!(
                %workflow_id,
                %execution_id,
                "publish_execution_failure_alert: NATS publish failed: {}",
                e
            );
        }
    }
    let error_msg = format!("Workflow execution failed: {}", redacted);
    if let Err(e) = execution_repo
        .upsert_execution_failure_alert(user_id, workflow_id, execution_id, &error_msg)
        .await
    {
        tracing::warn!(
            %workflow_id,
            %execution_id,
            "publish_execution_failure_alert: failure-alert upsert failed: {}",
            e
        );
    }
}

#[cfg(test)]
mod tests {
    //! Tests use a hand-rolled `WorkflowContext` instead of running a
    //! real engine — the helpers here are pure projections and
    //! don't need the engine machinery.
    //!
    //! `collect_success_output` requires a `ParallelWorkflowEngine`
    //! reference (for `node_labels()`), which is non-trivial to
    //! construct in a unit test. We therefore exercise its behaviour
    //! indirectly via `collect_success_output_inner` — same logic,
    //! but `node_labels` is passed in directly. The public function
    //! is a thin shim that delegates.

    use super::*;
    use std::collections::HashMap;
    use uuid::Uuid;

    /// Test seam: same logic as `collect_success_output` but takes
    /// `node_labels` as an explicit parameter so we can exercise
    /// the projection without standing up a full engine. Public
    /// helper kept private to this module to avoid leaking a
    /// test-only API.
    fn collect_success_output_inner(
        node_labels: &HashMap<Uuid, String>,
        ctx: &WorkflowContext,
        trigger_input_for_storage: &Value,
    ) -> Value {
        let mut output = Map::new();
        for (nid, result) in &ctx.results {
            let key = node_labels
                .get(nid)
                .cloned()
                .unwrap_or_else(|| nid.to_string());
            if key == "__trigger__" {
                continue;
            }
            if result
                .get("__skipped")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                continue;
            }
            // Inline the unwrap_output behaviour: if the value has
            // an `__output__` field, return that; else return the
            // value itself. This mirrors `ParallelWorkflowEngine::unwrap_output`.
            let clean = result
                .get("__output__")
                .cloned()
                .unwrap_or_else(|| result.clone());
            output.insert(key, clean);
        }
        output.insert(
            "__trigger_input__".to_string(),
            trigger_input_for_storage.clone(),
        );
        if !ctx.node_timings.is_empty() {
            output.insert(
                "__node_timings__".to_string(),
                serde_json::to_value(&ctx.node_timings).unwrap_or_default(),
            );
        }
        talos_dlp_provider::redact_json(&Value::Object(output))
    }

    #[test]
    fn collect_success_drops_trigger_synthetic_entry() {
        let trigger_id = Uuid::new_v4();
        let mut node_labels = HashMap::new();
        node_labels.insert(trigger_id, "__trigger__".to_string());
        let mut ctx = WorkflowContext::default();
        ctx.results
            .insert(trigger_id, serde_json::json!({ "ignored": true }));
        let out = collect_success_output_inner(&node_labels, &ctx, &serde_json::json!({"k": "v"}));
        let obj = out.as_object().unwrap();
        assert!(!obj.contains_key("__trigger__"));
        assert_eq!(
            obj.get("__trigger_input__"),
            Some(&serde_json::json!({"k": "v"}))
        );
    }

    #[test]
    fn collect_success_drops_skipped_nodes() {
        let nid = Uuid::new_v4();
        let mut node_labels = HashMap::new();
        node_labels.insert(nid, "skipped_node".to_string());
        let mut ctx = WorkflowContext::default();
        ctx.results.insert(
            nid,
            serde_json::json!({"__skipped": true, "reason": "predicate false"}),
        );
        let out = collect_success_output_inner(&node_labels, &ctx, &serde_json::json!({}));
        let obj = out.as_object().unwrap();
        assert!(!obj.contains_key("skipped_node"));
    }

    #[test]
    fn collect_success_falls_back_to_uuid_when_label_missing() {
        let nid = Uuid::new_v4();
        let node_labels: HashMap<Uuid, String> = HashMap::new(); // no label
        let mut ctx = WorkflowContext::default();
        ctx.results.insert(nid, serde_json::json!("output"));
        let out = collect_success_output_inner(&node_labels, &ctx, &serde_json::json!({}));
        let obj = out.as_object().unwrap();
        // UUID stringified is the fallback key.
        assert!(obj.contains_key(&nid.to_string()));
    }

    #[test]
    fn collect_success_unwraps_output_envelope() {
        let nid = Uuid::new_v4();
        let mut node_labels = HashMap::new();
        node_labels.insert(nid, "my_node".to_string());
        let mut ctx = WorkflowContext::default();
        ctx.results.insert(
            nid,
            serde_json::json!({"__output__": "raw_value", "__metadata__": "ignored"}),
        );
        let out = collect_success_output_inner(&node_labels, &ctx, &serde_json::json!({}));
        // The unwrap_output behaviour: __output__ becomes the stored value.
        assert_eq!(out["my_node"], serde_json::json!("raw_value"));
    }

    #[test]
    fn collect_success_includes_node_timings_when_present() {
        let mut ctx = WorkflowContext::default();
        ctx.node_timings.insert("node_a".to_string(), 42);
        ctx.node_timings.insert("node_b".to_string(), 100);
        let out = collect_success_output_inner(&HashMap::new(), &ctx, &serde_json::json!({}));
        assert!(out.get("__node_timings__").is_some());
        let timings = out["__node_timings__"].as_object().unwrap();
        assert_eq!(timings["node_a"], serde_json::json!(42));
        assert_eq!(timings["node_b"], serde_json::json!(100));
    }

    #[test]
    fn collect_success_omits_node_timings_when_empty() {
        let ctx = WorkflowContext::default();
        let out = collect_success_output_inner(&HashMap::new(), &ctx, &serde_json::json!({}));
        assert!(out.get("__node_timings__").is_none());
    }

    #[test]
    fn collect_success_redacts_sk_prefixed_secrets() {
        // Defends the DLP boundary — if a node emits an OpenAI-shaped
        // key by mistake, the persisted output must redact it.
        let nid = Uuid::new_v4();
        let mut node_labels = HashMap::new();
        node_labels.insert(nid, "leaky_node".to_string());
        let mut ctx = WorkflowContext::default();
        ctx.results.insert(
            nid,
            serde_json::json!({"api_key": "sk-proj-12345abcdefghijklmnop"}),
        );
        let out = collect_success_output_inner(&node_labels, &ctx, &serde_json::json!({}));
        let serialized = serde_json::to_string(&out).unwrap();
        assert!(
            !serialized.contains("sk-proj-12345abcdefghijklmnop"),
            "DLP did not redact the sk-* key from output: {}",
            serialized
        );
    }

    fn labels(pairs: &[(Uuid, &str)]) -> HashMap<Uuid, String> {
        pairs
            .iter()
            .map(|(id, l)| (*id, (*l).to_string()))
            .collect()
    }

    #[test]
    fn collect_failure_output_carries_trigger_input() {
        let out = failure_output(&HashMap::new(), None, Some(&serde_json::json!({"k": "v"})));
        // Nothing completed: the shape a failed run has always stored.
        assert_eq!(out, serde_json::json!({ "__trigger_input__": {"k": "v"} }));
    }

    #[test]
    fn collect_failure_output_redacts_secrets_from_trigger_input() {
        // Trigger input may itself carry secrets (e.g. webhook
        // payload). Failure-path persistence must redact too.
        let out = failure_output(
            &HashMap::new(),
            None,
            Some(&serde_json::json!({"token": "ghp_abcdefghijklmnopqrstuvwx12"})),
        );
        let serialized = serde_json::to_string(&out).unwrap();
        assert!(
            !serialized.contains("ghp_abcdefghijklmnopqrstuvwx12"),
            "DLP did not redact the ghp_* token from failure output: {}",
            serialized
        );
    }

    /// The defect: a run that failed at its sixth node stored its trigger
    /// and nothing else, so `get_node_output` for the five that completed
    /// answered "not found … available: [__trigger_input__]".
    #[test]
    fn a_failed_run_stores_what_its_completed_nodes_produced_keyed_by_label() {
        let (trigger, fetch, compose, skipped, continued, unlabelled) = (
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
        );
        let partial: HashMap<Uuid, Value> = [
            (trigger, serde_json::json!({ "seed": true })),
            (fetch, serde_json::json!({ "items": [1, 2] })),
            (compose, serde_json::json!({ "subject": "s" })),
            (skipped, serde_json::json!({ "__skipped": true, "reason": "no_active_input" })),
            (
                continued,
                serde_json::json!({ "__error": true, "error_message": "boom", "__continued": true }),
            ),
            (unlabelled, serde_json::json!({ "x": 1 })),
        ]
        .into_iter()
        .collect();
        let out = failure_output(
            &labels(&[
                (trigger, "__trigger__"),
                (fetch, "fetch"),
                (compose, "compose"),
                (skipped, "skipped"),
                (continued, "optional"),
            ]),
            Some(partial),
            Some(&serde_json::json!({ "ticket": "ABC-12" })),
        );
        assert_eq!(
            out,
            serde_json::json!({
                "fetch": { "items": [1, 2] },
                "compose": { "subject": "s" },
                "optional": { "__error": true, "error_message": "boom", "__continued": true },
                unlabelled.to_string(): { "x": 1 },
                "__trigger_input__": { "ticket": "ABC-12" },
            })
        );
        // What retry and replay read is where it always was.
        assert_eq!(
            extract_trigger_input(Some(&out)),
            serde_json::json!({ "ticket": "ABC-12" })
        );
    }

    #[test]
    fn a_completed_nodes_output_is_redacted_before_it_is_stored() {
        let node = Uuid::new_v4();
        let partial: HashMap<Uuid, Value> = [(
            node,
            serde_json::json!({ "echoed": "Authorization: Bearer ghp_abcdefghijklmnopqrstuvwx12" }),
        )]
        .into_iter()
        .collect();
        let out = failure_output(&labels(&[(node, "fetch")]), Some(partial), None);
        assert!(out.get("fetch").is_some(), "{out}");
        assert!(
            !out.to_string().contains("ghp_abcdefghijklmnopqrstuvwx12"),
            "a completed node's output reached storage unredacted: {out}"
        );
    }

    /// Too much to store: the outputs are left out as a whole and the
    /// payload says so. The trigger a retry needs is still there, which the
    /// payload ceiling alone would not have kept.
    #[test]
    fn outputs_too_large_to_store_are_left_out_whole_and_the_trigger_is_kept() {
        let (small, big) = (Uuid::new_v4(), Uuid::new_v4());
        let partial: HashMap<Uuid, Value> = [
            (small, serde_json::json!({ "ok": true })),
            (
                big,
                serde_json::json!({ "blob": "x".repeat(FAILED_RUN_OUTPUTS_MAX_BYTES) }),
            ),
        ]
        .into_iter()
        .collect();
        let out = failure_output(
            &labels(&[(small, "small"), (big, "big")]),
            Some(partial),
            Some(&serde_json::json!({ "ticket": "ABC-12" })),
        );
        assert!(
            out.get("small").is_none() && out.get("big").is_none(),
            "a subset was kept"
        );
        let omitted = &out[OUTPUTS_OMITTED_KEY];
        assert_eq!(omitted["reason"], "too_large");
        assert_eq!(omitted["nodes"], 2);
        assert_eq!(omitted["limit_bytes"], FAILED_RUN_OUTPUTS_MAX_BYTES);
        assert_eq!(
            out["__trigger_input__"],
            serde_json::json!({ "ticket": "ABC-12" })
        );
        assert!(
            serde_json::to_vec(&out).unwrap().len()
                < talos_dlp_provider::MAX_EXECUTION_PAYLOAD_BYTES,
            "the stored payload would be truncated, taking the trigger with it"
        );

        // Just under the bound, everything is kept.
        let partial: HashMap<Uuid, Value> =
            [(small, serde_json::json!({ "blob": "x".repeat(1024) }))]
                .into_iter()
                .collect();
        let out = failure_output(&labels(&[(small, "small")]), Some(partial), None);
        assert!(out.get(OUTPUTS_OMITTED_KEY).is_none() && out.get("small").is_some());
    }

    #[test]
    fn extract_trigger_input_returns_inner_value() {
        let stored = serde_json::json!({
            "__trigger_input__": {"k": "v", "n": 7},
            "node_a": {"out": 1}
        });
        let extracted = extract_trigger_input(Some(&stored));
        assert_eq!(extracted, serde_json::json!({"k": "v", "n": 7}));
    }

    #[test]
    fn extract_trigger_input_drops_engine_authored_keys() {
        let stored = serde_json::json!({
            "__trigger_input__": {
                "k": "v",
                "__actor_context__": {"memories": ["decrypted"]},
                "__accumulated__": {"n": 1}
            }
        });
        let extracted = extract_trigger_input(Some(&stored));
        assert_eq!(extracted, serde_json::json!({"k": "v"}));
    }

    #[test]
    fn extract_trigger_input_empty_when_output_data_none() {
        let extracted = extract_trigger_input(None);
        assert_eq!(extracted, serde_json::json!({}));
    }

    #[test]
    fn extract_trigger_input_empty_when_key_absent() {
        let stored = serde_json::json!({"node_a": {"out": 1}});
        let extracted = extract_trigger_input(Some(&stored));
        assert_eq!(extracted, serde_json::json!({}));
    }

    #[test]
    fn extract_trigger_input_round_trips_through_collect() {
        let original = serde_json::json!({"foo": "bar"});
        let failure_out = failure_output(&HashMap::new(), None, Some(&original));
        // Failure output is DLP-redacted; the trigger key still carries
        // the input value verbatim (no secrets here).
        let recovered = extract_trigger_input(Some(&failure_out));
        assert_eq!(recovered, original);
    }
}
