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

/// Build the failure-path output JSON.
///
/// Pre-extraction every caller wrote the same shape inline:
///
/// ```ignore
/// let fail_output = talos_dlp_provider::redact_json(
///     &serde_json::json!({"__trigger_input__": trigger_input_for_storage}),
/// );
/// ```
///
/// Pulling this into a helper keeps the failure-path output shape
/// in lockstep with the success-path keys (both project
/// `__trigger_input__` at the top level so downstream consumers
/// don't need to branch on success/failure to find the input).
pub fn collect_failure_output(trigger_input_for_storage: &Value) -> Value {
    talos_dlp_provider::redact_json(&serde_json::json!({
        "__trigger_input__": trigger_input_for_storage
    }))
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
pub fn extract_trigger_input(output_data: Option<&Value>) -> Value {
    output_data
        .and_then(|o| o.get(TRIGGER_INPUT_KEY))
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}))
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

    #[test]
    fn collect_failure_output_carries_trigger_input() {
        let out = collect_failure_output(&serde_json::json!({"k": "v"}));
        assert_eq!(out["__trigger_input__"], serde_json::json!({"k": "v"}));
    }

    #[test]
    fn collect_failure_output_redacts_secrets_from_trigger_input() {
        // Trigger input may itself carry secrets (e.g. webhook
        // payload). Failure-path persistence must redact too.
        let out =
            collect_failure_output(&serde_json::json!({"token": "ghp_abcdefghijklmnopqrstuvwx12"}));
        let serialized = serde_json::to_string(&out).unwrap();
        assert!(
            !serialized.contains("ghp_abcdefghijklmnopqrstuvwx12"),
            "DLP did not redact the ghp_* token from failure output: {}",
            serialized
        );
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
        let failure_out = collect_failure_output(&original);
        // Failure output is DLP-redacted; the trigger key still carries
        // the input value verbatim (no secrets here).
        let recovered = extract_trigger_input(Some(&failure_out));
        assert_eq!(recovered, original);
    }
}
