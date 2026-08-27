//! Pure, synchronous JSON → graph-model decoding helpers.
//!
//! The engine's [`ParallelWorkflowEngine::parse_graph_document`] method
//! reads a React-Flow-shaped graph and populates engine state. The
//! node-kind decoding (per-`kind` string → [`SystemNodeKind`]) and
//! per-node metadata parsing (retry policy with actor-budget clamping)
//! live in this module as free functions so the parsing surface is
//! auditable in one place and the method body in `engine.rs` stays
//! focused on the state-population glue.
//!
//! [`ParallelWorkflowEngine::parse_graph_document`]: crate::ParallelWorkflowEngine::parse_graph_document

use serde_json::Value as JsonValue;
use talos_workflow_engine_core::{RetryPolicy, SystemNodeKind};
use uuid::Uuid;

/// Parse a React-Flow node's retry metadata into a [`RetryPolicy`].
///
/// Accepts either top-level fields (`retry_count`, `retry_backoff_ms`,
/// `retry_condition`, `retry_delay_expression`) or the same keys nested
/// under `data` — the RF frontend emits both shapes depending on node
/// type. Returns `None` when the node has no retry config at all; the
/// engine treats that as "use the method-aware default."
///
/// # The presence test is wider than the count, deliberately
///
/// Any one of the four keys produces a policy, because a declared
/// backoff / condition / delay expression must be preserved and honoured
/// — dropping a `retry_condition` (a gate that only ever *narrows* which
/// failures retry) would make the node retry on failures its author
/// wrote that expression to exclude.
///
/// But only `retry_count` supplies [`RetryPolicy::max_retries`]; the
/// other three answer "how far apart" or "when", never "how many". When
/// it is absent the count stays `None` and the world-aware classifier
/// answers at dispatch, exactly as it does for a node with no retry keys
/// at all. This function used to synthesise `2` there, which suppressed
/// the classifier entirely and handed blind retries to governance /
/// messaging / database nodes that fail closed to 0 by design — a node
/// declaring nothing but `retry_backoff_ms` got two re-fires of a
/// non-idempotent send. Nothing here may invent a count: this parser is
/// pure JSON decoding and does not have the module's `capability_world`
/// / `allowed_methods` in scope, so it cannot answer the question.
pub(crate) fn read_node_retry_policy(node: &JsonValue) -> Option<RetryPolicy> {
    // MCP-962 sibling: saturating u64→u32 conversion. Pre-fix `as u32`
    // silently wrapped a caller-supplied `retry_count: 5_000_000_000`
    // (5B) into ~705M retries in `RetryPolicy::max_retries`. The
    // actor-budget clamp in `read_node_retry_policy_with_actor_cap`
    // only kicks in when `actor_id.is_none()`, so actor-owned
    // executions took the unbounded value straight into the engine
    // retry loop. Saturate to u32::MAX so the dashboard renders an
    // operator-recognisably absurd value (~4.3B) that triggers
    // investigation, vs. silently truncating to a plausible-looking
    // 705M.
    let retry_count = node
        .get("retry_count")
        .or_else(|| node.get("data").and_then(|d| d.get("retry_count")))
        .and_then(JsonValue::as_u64)
        .map(|v| u32::try_from(v).unwrap_or(u32::MAX));
    let retry_backoff = node
        .get("retry_backoff_ms")
        .or_else(|| node.get("data").and_then(|d| d.get("retry_backoff_ms")))
        .and_then(JsonValue::as_u64);
    let retry_condition = node
        .get("retry_condition")
        .or_else(|| node.get("data").and_then(|d| d.get("retry_condition")))
        .and_then(JsonValue::as_str)
        .map(String::from);
    let retry_delay_expression = node
        .get("retry_delay_expression")
        .or_else(|| {
            node.get("data")
                .and_then(|d| d.get("retry_delay_expression"))
        })
        .and_then(JsonValue::as_str)
        .map(String::from);

    let has_any = retry_count.is_some()
        || retry_backoff.is_some()
        || retry_condition.is_some()
        || retry_delay_expression.is_some();
    if !has_any {
        return None;
    }
    Some(RetryPolicy {
        // Verbatim, INCLUDING `None`. `None` is not "zero" and not "two" —
        // it is "the author did not say", resolved against the module at
        // dispatch by `RetryPolicy::resolved_max_retries`.
        max_retries: retry_count,
        backoff_ms: retry_backoff.unwrap_or(talos_workflow_engine_core::DEFAULT_BACKOFF_MS),
        retry_condition,
        retry_delay_expression,
    })
}

/// Actor-budget-aware wrapper around [`read_node_retry_policy`].
///
/// Executions *not* owned by an actor (`actor_id.is_none()`) can't
/// amortize retry cost against a per-actor budget, so we clamp
/// `max_retries` to a platform default to prevent a rogue workflow
/// saturating workers with a high retry count. Actor-owned executions
/// pass through to the user's declared value, which the actor's
/// budget ceiling bounds at a higher level.
///
/// Used by the unified graph-document parser — see
/// [`ParallelWorkflowEngine::parse_graph_document`](crate::ParallelWorkflowEngine::parse_graph_document).
pub(crate) fn read_node_retry_policy_with_actor_cap(
    node: &JsonValue,
    actor_id: Option<Uuid>,
) -> Option<RetryPolicy> {
    /// Max retries for workflows without an actor budget. A near-fuel-
    /// exhausting module with `retry_count=10` can otherwise saturate a
    /// worker for 15+ seconds per trigger. Defined in core so an
    /// authoring-time checker predicting the resolved count reads the same
    /// clamp this applies.
    use talos_workflow_engine_core::MAX_RETRIES_UNBUDGETED;

    let mut policy = read_node_retry_policy(node)?;
    if actor_id.is_none() {
        // Clamp only a DECLARED count. The cap exists to bound an absurd
        // author-supplied value; there is nothing to bound when the author
        // supplied nothing, and clamping `None` into a number here would
        // reintroduce exactly the invented count this parser must not
        // produce. The classifier's own answers (0 or
        // `DEFAULT_TRANSIENT_RETRIES` = 2) are already below this cap, so
        // leaving `None` alone changes no resolved value.
        policy.max_retries = policy.max_retries.map(|n| n.min(MAX_RETRIES_UNBUDGETED));
    }
    Some(policy)
}

/// Decode a [`SystemNodeKind`] from its JSON (`kind` string + `data`
/// object).
///
/// Shared between module-backed nodes (which may also carry a `kind`)
/// and system-only nodes (where `kind` comes from the `system:<kind>`
/// type prefix or an explicit field). Single implementation means the
/// builder serializer in [`crate::graph_builder`] and this decoder
/// can't drift.
///
/// Returns `None` when `k` is unknown or the `data` payload is missing
/// required fields — the caller treats that as "no system-kind
/// decoded" and the node runs as a plain module / presentation-only
/// annotation.
#[allow(clippy::too_many_lines)]
pub(crate) fn parse_system_node_kind(k: &str, node: &JsonValue) -> Option<SystemNodeKind> {
    if k == "wait" {
        Some(SystemNodeKind::Wait {
            message: node
                .get("data")
                .and_then(|d| d.get("message"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        })
    } else if k == "sub_workflow" {
        let data = node.get("data")?;
        Some(SystemNodeKind::SubWorkflow {
            workflow_id: data.get("sub_workflow_id")?.as_str()?.parse().ok()?,
            timeout_secs: data
                .get("timeout_secs")
                .and_then(|v| v.as_u64())
                .unwrap_or(30),
        })
    } else if k == "loop" {
        let data = node.get("data")?;
        Some(SystemNodeKind::Loop {
            max_iterations: data
                .get("max_iterations")
                .and_then(|v| v.as_u64())
                .unwrap_or(10)
                .min(100) as u32,
            condition: data.get("condition")?.as_str()?.to_string(),
        })
    } else if k == "while_loop" {
        // Distinct from `loop`: `while_loop` runs the body locally (no
        // module dispatch), re-evaluating the condition after each pass.
        let data = node.get("data")?;
        Some(SystemNodeKind::WhileLoop {
            condition: data.get("condition")?.as_str()?.to_string(),
            max_iterations: data
                .get("max_iterations")
                .and_then(|v| v.as_u64())
                .unwrap_or(10)
                .min(100) as u32,
        })
    } else if k == "repeat_loop" {
        let count = node
            .get("data")
            .and_then(|d| d.get("count"))
            .and_then(|v| v.as_u64())
            .unwrap_or(1)
            .min(u64::from(u32::MAX)) as u32;
        Some(SystemNodeKind::RepeatLoop { count })
    } else if k == "fan_in" {
        let data = node.get("data").cloned().unwrap_or(serde_json::json!({}));
        let join_mode = data
            .get("join_mode")
            .cloned()
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or(talos_workflow_engine_core::JoinMode::All);
        let aggregation_expr = data
            .get("aggregation_expr")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        Some(SystemNodeKind::FanIn {
            join_mode,
            aggregation_expr,
        })
    } else if k == "error_handler" {
        let error_pattern = node
            .get("data")
            .and_then(|d| d.get("error_pattern"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        Some(SystemNodeKind::ErrorHandler { error_pattern })
    } else if k == "collect" {
        Some(SystemNodeKind::Collect)
    } else if k == "assistant_report" {
        // Clamp defensively (default 7 days, cap one month).
        let days = node
            .get("data")
            .and_then(|d| d.get("days"))
            .and_then(serde_json::Value::as_u64)
            .map_or(7u32, |v| v.clamp(1, 31) as u32);
        Some(SystemNodeKind::AssistantReport { days })
    } else if k == "operator_digest" {
        // Clamp defensively (default 7 days, cap one month).
        let days = node
            .get("data")
            .and_then(|d| d.get("days"))
            .and_then(serde_json::Value::as_u64)
            .map_or(7u32, |v| v.clamp(1, 31) as u32);
        Some(SystemNodeKind::OperatorDigest { days })
    } else if k == "ops_alerts_digest" {
        // Clamp defensively at parse time so a hand-authored graph can't
        // request an unbounded verbatim-alert list (default 10, cap 25).
        let top_limit = node
            .get("data")
            .and_then(|d| d.get("top_limit"))
            .and_then(serde_json::Value::as_u64)
            .map_or(10u32, |v| v.clamp(1, 25) as u32);
        Some(SystemNodeKind::OpsAlertsDigest { top_limit })
    } else if k == "pending_approvals" {
        // Clamp defensively at parse time so a hand-authored graph can't
        // request an unbounded pending-approval list (default 10, cap 25).
        let limit = node
            .get("data")
            .and_then(|d| d.get("limit"))
            .and_then(serde_json::Value::as_u64)
            .map_or(10u32, |v| v.clamp(1, 25) as u32);
        Some(SystemNodeKind::PendingApprovals { limit })
    } else if k == "synthesize" {
        let data = node.get("data").cloned().unwrap_or(serde_json::json!({}));
        Some(SystemNodeKind::Synthesize {
            synthesis_expr: data
                .get("synthesis_expr")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        })
    } else if k == "verify" {
        let data = node.get("data")?;
        Some(SystemNodeKind::Verify {
            condition: data.get("condition")?.as_str()?.to_string(),
            check_label: data
                .get("check_label")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            on_failure: data
                .get("on_failure")
                .and_then(|v| v.as_str())
                .unwrap_or("error")
                .to_string(),
        })
    } else if k == "dispatch" {
        let data = node.get("data")?;
        Some(SystemNodeKind::DynamicDispatch {
            dispatch_expression: data.get("dispatch_expression")?.as_str()?.to_string(),
            timeout_secs: data
                .get("timeout_secs")
                .and_then(|v| v.as_u64())
                .unwrap_or(30),
        })
    } else if k == "capability_dispatch" {
        let data = node.get("data")?;
        let caps = data
            .get("required_capabilities")?
            .as_array()?
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect::<Vec<String>>();
        if caps.is_empty() {
            return None;
        }
        let fallback_workflow_id = data
            .get("fallback_workflow_id")
            .and_then(|v| v.as_str())
            .and_then(|s| uuid::Uuid::parse_str(s).ok());
        Some(SystemNodeKind::CapabilityDispatch {
            required_capabilities: caps,
            fallback_workflow_id,
            timeout_secs: data
                .get("timeout_secs")
                .and_then(|v| v.as_u64())
                .unwrap_or(30),
        })
    } else {
        // LLM/agent-specific kinds (feature-gated).
        parse_llm_system_node_kind(k, node)
    }
}

/// Parse an LLM/agent-specific [`SystemNodeKind`] from a React-Flow
/// node's `kind` + `data` fields. Returns `None` for kinds this helper
/// doesn't recognize.
///
/// Lives in its own function so the LLM parsing surface can be
/// cfg-gated as a single unit. When `llm-primitives` is disabled, the
/// stub body returns `None` for every kind — graphs that reference
/// these kinds parse as `None`-kind nodes and the engine rejects them
/// at execution time.
#[cfg(feature = "llm-primitives")]
#[allow(clippy::too_many_lines)]
fn parse_llm_system_node_kind(k: &str, node: &JsonValue) -> Option<SystemNodeKind> {
    if k == "agent_loop" {
        let data = node.get("data")?;
        Some(SystemNodeKind::AgentLoop {
            body_workflow_id: data.get("body_workflow_id")?.as_str()?.parse().ok()?,
            max_iterations: data
                .get("max_iterations")
                .and_then(|v| v.as_u64())
                .unwrap_or(10)
                .min(50) as u32,
            inject_history: data
                .get("inject_history")
                .and_then(|v| v.as_bool())
                .unwrap_or(true),
            timeout_secs: data
                .get("timeout_secs")
                .and_then(|v| v.as_u64())
                .unwrap_or(60),
        })
    } else if k == "judge" {
        let data = node.get("data").unwrap_or(&JsonValue::Null);
        let judge_workflow_id = data
            .get("judge_workflow_id")
            .and_then(|v| v.as_str())
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .unwrap_or_else(uuid::Uuid::nil);
        let rubric = data
            .get("rubric")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let pass_threshold = data.get("pass_threshold").and_then(|v| v.as_f64());
        let timeout_secs = data
            .get("timeout_secs")
            .and_then(|v| v.as_u64())
            .unwrap_or(60);
        let on_failure = data
            .get("on_failure")
            .and_then(|v| v.as_str())
            .unwrap_or("error")
            .to_string();
        Some(SystemNodeKind::Judge {
            judge_workflow_id,
            rubric,
            pass_threshold,
            on_failure,
            timeout_secs,
        })
    } else if k == "inline_judge" {
        let data = node.get("data").unwrap_or(&JsonValue::Null);
        let verdict_expr = data
            .get("verdict_expr")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        // Reject empty expressions at parse time so the dispatch
        // handler doesn't have to special-case them later.
        if verdict_expr.is_empty() {
            return None;
        }
        let pass_threshold = data.get("pass_threshold").and_then(|v| v.as_f64());
        let on_failure = data
            .get("on_failure")
            .and_then(|v| v.as_str())
            .unwrap_or("error")
            .to_string();
        Some(SystemNodeKind::InlineJudge {
            verdict_expr,
            pass_threshold,
            on_failure,
        })
    } else if k == "ensemble" {
        let data = node.get("data").unwrap_or(&JsonValue::Null);
        let child_workflow_id = data
            .get("child_workflow_id")
            .and_then(|v| v.as_str())
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .unwrap_or_else(uuid::Uuid::nil);
        let count = data
            .get("count")
            .and_then(|v| v.as_u64())
            .unwrap_or(3)
            .min(10)
            .max(2) as u32;
        let consensus = data
            .get("consensus")
            .and_then(|v| v.as_str())
            .unwrap_or("majority_vote")
            .to_string();
        let judge_workflow_id = data
            .get("judge_workflow_id")
            .and_then(|v| v.as_str())
            .and_then(|s| uuid::Uuid::parse_str(s).ok());
        let timeout_secs = data
            .get("timeout_secs")
            .and_then(|v| v.as_u64())
            .unwrap_or(60);
        Some(SystemNodeKind::Ensemble {
            child_workflow_id,
            count,
            consensus,
            judge_workflow_id,
            timeout_secs,
        })
    } else if k == "confidence_gate" {
        let data = node.get("data").unwrap_or(&JsonValue::Null);
        let threshold = data
            .get("threshold")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.7)
            .clamp(0.0, 1.0);
        let confidence_path = data
            .get("confidence_path")
            .and_then(|v| v.as_str())
            .unwrap_or("__confidence__")
            .to_string();
        let on_low_confidence = data
            .get("on_low_confidence")
            .and_then(|v| v.as_str())
            .unwrap_or("pause")
            .to_string();
        Some(SystemNodeKind::ConfidenceGate {
            threshold,
            confidence_path,
            on_low_confidence,
        })
    } else if k == "reflective_retry" {
        let data = node.get("data").unwrap_or(&JsonValue::Null);
        let child_workflow_id = data
            .get("child_workflow_id")
            .and_then(|v| v.as_str())
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .unwrap_or_else(uuid::Uuid::nil);
        let reflection_workflow_id = data
            .get("reflection_workflow_id")
            .and_then(|v| v.as_str())
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .unwrap_or_else(uuid::Uuid::nil);
        let max_retries = data
            .get("max_retries")
            .and_then(|v| v.as_u64())
            .unwrap_or(2)
            .min(5)
            .max(1) as u32;
        let timeout_secs = data
            .get("timeout_secs")
            .and_then(|v| v.as_u64())
            .unwrap_or(60);
        Some(SystemNodeKind::ReflectiveRetry {
            child_workflow_id,
            reflection_workflow_id,
            max_retries,
            timeout_secs,
        })
    } else if k == "llm_dispatch" {
        let data = node.get("data").unwrap_or(&JsonValue::Null);
        let classifier_workflow_id = data
            .get("classifier_workflow_id")
            .and_then(|v| v.as_str())
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .unwrap_or_else(uuid::Uuid::nil);
        let routes: std::collections::HashMap<String, uuid::Uuid> = data
            .get("routes")
            .and_then(|v| v.as_object())
            .map(|map| {
                map.iter()
                    .filter_map(|(k, v)| {
                        v.as_str()
                            .and_then(|s| uuid::Uuid::parse_str(s).ok())
                            .map(|uid| (k.clone(), uid))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let fallback_workflow_id = data
            .get("fallback_workflow_id")
            .and_then(|v| v.as_str())
            .and_then(|s| uuid::Uuid::parse_str(s).ok());
        let timeout_secs = data
            .get("timeout_secs")
            .and_then(|v| v.as_u64())
            .unwrap_or(60);
        Some(SystemNodeKind::LlmDispatch {
            classifier_workflow_id,
            routes,
            fallback_workflow_id,
            timeout_secs,
        })
    } else if k == "react_loop" {
        let data = node.get("data")?;
        Some(SystemNodeKind::ReActLoop {
            body_workflow_id: data.get("body_workflow_id")?.as_str()?.parse().ok()?,
            max_iterations: data
                .get("max_iterations")
                .and_then(|v| v.as_u64())
                .unwrap_or(10)
                .min(50) as u32,
            inject_history: data
                .get("inject_history")
                .and_then(|v| v.as_bool())
                .unwrap_or(true),
            timeout_secs: data
                .get("timeout_secs")
                .and_then(|v| v.as_u64())
                .unwrap_or(60),
        })
    } else {
        None
    }
}

/// Stub that returns `None` for every input. Active when the
/// `llm-primitives` feature is disabled — graphs that reference
/// LLM-flavored kinds parse as `None`-kind nodes.
#[cfg(not(feature = "llm-primitives"))]
fn parse_llm_system_node_kind(_k: &str, _node: &JsonValue) -> Option<SystemNodeKind> {
    None
}

#[cfg(test)]
mod read_node_retry_policy_tests {
    use super::read_node_retry_policy;
    use serde_json::json;

    #[test]
    fn retry_count_within_u32_passes_through() {
        let node = json!({ "retry_count": 5 });
        let p = read_node_retry_policy(&node).unwrap();
        assert_eq!(p.max_retries, Some(5));
    }

    #[test]
    fn retry_count_above_u32_saturates_to_max() {
        // MCP-962 sibling: pre-fix `v as u32` for v = 5_000_000_000
        // silently wrapped to ~705_032_704. Saturating cast surfaces
        // an operator-recognisably absurd value (~4.3B) instead.
        let node = json!({ "retry_count": 5_000_000_000_u64 });
        let p = read_node_retry_policy(&node).unwrap();
        assert_eq!(p.max_retries, Some(u32::MAX));
    }

    #[test]
    fn retry_count_u64_max_saturates_to_u32_max() {
        let node = json!({ "retry_count": u64::MAX });
        let p = read_node_retry_policy(&node).unwrap();
        assert_eq!(p.max_retries, Some(u32::MAX));
    }

    #[test]
    fn retry_count_at_u32_max_passes_through() {
        let node = json!({ "retry_count": u64::from(u32::MAX) });
        let p = read_node_retry_policy(&node).unwrap();
        assert_eq!(p.max_retries, Some(u32::MAX));
    }

    #[test]
    fn retry_count_just_over_u32_max_saturates() {
        // Pre-fix `v as u32` for v = u32::MAX as u64 + 1 wrapped to 0
        // — silently disabling all retries.
        let node = json!({ "retry_count": u64::from(u32::MAX) + 1 });
        let p = read_node_retry_policy(&node).unwrap();
        assert_eq!(p.max_retries, Some(u32::MAX));
    }

    #[test]
    fn nested_data_retry_count_also_saturates() {
        // The parser accepts both top-level and `data.*` shapes.
        let node = json!({
            "data": { "retry_count": 10_000_000_000_u64 }
        });
        let p = read_node_retry_policy(&node).unwrap();
        assert_eq!(p.max_retries, Some(u32::MAX));
    }

    /// Read-only module: a DECLARED GET-only allowlist on an `http` world.
    fn read_only() -> (Vec<String>, Option<&'static str>) {
        (vec!["GET".to_string()], Some("http-node"))
    }

    /// Side-effect world that `default_max_retries_for_module` fails closed
    /// on — a blind retry here re-fires an approval / publish / DML.
    fn fail_closed() -> (Vec<String>, Option<&'static str>) {
        (Vec::new(), Some("governance-node"))
    }

    #[test]
    fn a_declaration_without_a_count_leaves_the_count_undeclared() {
        // Each of these three keys answers a question OTHER than "how many":
        // spacing (`retry_backoff_ms`, `retry_delay_expression`) or a
        // restricting gate (`retry_condition`). None of them may synthesise a
        // count — the parser has no module in scope and cannot answer.
        for node in [
            json!({ "retry_backoff_ms": 3_000 }),
            json!({ "retry_condition": "error_code == 429" }),
            json!({ "retry_delay_expression": "retry_after * 1000" }),
            json!({ "data": { "retry_backoff_ms": 3_000 } }),
        ] {
            let p = read_node_retry_policy(&node)
                .expect("a declared backoff/condition/delay must still produce a policy");
            assert_eq!(
                p.max_retries, None,
                "{node}: only retry_count may supply a count"
            );
        }
    }

    #[test]
    fn a_countless_declaration_resolves_world_aware_not_to_a_literal() {
        // THE REGRESSION. Pre-fix every one of these resolved to a hardcoded
        // 2 for EVERY capability world, because a non-empty presence test
        // suppressed the method-aware fallback entirely. A governance /
        // messaging / database node declaring nothing but a backoff got two
        // blind re-fires of a non-idempotent side effect.
        for node in [
            json!({ "retry_backoff_ms": 3_000 }),
            json!({ "retry_condition": "error_code == 429" }),
            json!({ "retry_delay_expression": "retry_after * 1000" }),
        ] {
            let p = read_node_retry_policy(&node).unwrap();

            let (methods, world) = fail_closed();
            assert_eq!(
                p.resolved_max_retries(&methods, world),
                0,
                "{node}: a side-effect world must still fail closed to 0"
            );

            let (methods, world) = read_only();
            assert_eq!(
                p.resolved_max_retries(&methods, world),
                talos_workflow_engine_core::DEFAULT_TRANSIENT_RETRIES,
                "{node}: a declared read-only module still earns transient retries"
            );
        }
    }

    #[test]
    fn a_countless_declaration_keeps_its_spacing_and_gate() {
        // The presence test stays four keys wide on purpose: dropping a
        // `retry_condition` would make the node retry on failures the author
        // wrote that expression to EXCLUDE, and dropping the backoff would
        // silently re-space the retries. Fixing a fail-open default must not
        // introduce a different fail-open.
        let p = read_node_retry_policy(&json!({
            "retry_backoff_ms": 3_000,
            "retry_condition": "error_code == 429",
            "retry_delay_expression": "retry_after * 1000"
        }))
        .unwrap();
        assert_eq!(p.max_retries, None);
        assert_eq!(p.backoff_ms, 3_000);
        assert_eq!(p.retry_condition.as_deref(), Some("error_code == 429"));
        assert_eq!(
            p.retry_delay_expression.as_deref(),
            Some("retry_after * 1000")
        );
    }

    #[test]
    fn an_explicit_count_still_always_wins_including_zero() {
        // Documented platform rule: the classifier never overrides an author,
        // in either direction.
        let zero = read_node_retry_policy(&json!({ "retry_count": 0, "retry_backoff_ms": 3_000 }))
            .unwrap();
        let (methods, world) = read_only();
        assert_eq!(
            zero.resolved_max_retries(&methods, world),
            0,
            "a read-only module must not upgrade an author's explicit 0"
        );

        let five = read_node_retry_policy(&json!({ "retry_count": 5 })).unwrap();
        let (methods, world) = fail_closed();
        assert_eq!(
            five.resolved_max_retries(&methods, world),
            5,
            "a fail-closed world must not downgrade an author's explicit count"
        );
    }

    #[test]
    fn a_node_with_no_retry_keys_at_all_still_yields_no_policy() {
        // Unchanged: `None` here means the dispatch site builds a fully
        // undeclared policy and resolves it the same way. The two paths are
        // deliberately identical now — that is what stopped them diverging.
        assert!(read_node_retry_policy(&json!({ "id": "n1" })).is_none());
        assert!(read_node_retry_policy(&json!({ "data": { "timeout_secs": 30 } })).is_none());
    }

    #[test]
    fn the_actor_cap_clamps_a_declared_count_but_never_invents_one() {
        use super::read_node_retry_policy_with_actor_cap;

        // Unbudgeted (no owning actor) clamps a declared count to 3 …
        let clamped =
            read_node_retry_policy_with_actor_cap(&json!({ "retry_count": 50 }), None).unwrap();
        assert_eq!(clamped.max_retries, Some(3));

        // … and an actor-owned execution passes the declared value through.
        let uncapped = read_node_retry_policy_with_actor_cap(
            &json!({ "retry_count": 50 }),
            Some(uuid::Uuid::nil()),
        )
        .unwrap();
        assert_eq!(uncapped.max_retries, Some(50));

        // But an UNDECLARED count is not clamped into existence — clamping
        // `None` to a number would reintroduce the invented count.
        let undeclared =
            read_node_retry_policy_with_actor_cap(&json!({ "retry_backoff_ms": 3_000 }), None)
                .unwrap();
        assert_eq!(undeclared.max_retries, None);
        let (methods, world) = fail_closed();
        assert_eq!(undeclared.resolved_max_retries(&methods, world), 0);
    }
}
