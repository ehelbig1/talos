//! Pure-data types for declarative Talos workflow definitions.
//!
//! Extracted from `controller::yaml_workflows`. The wire shape (the
//! YAML schema you check into git) lives here so downstream tooling
//! (CI linters, IDE plugins, third-party generators) can consume the
//! schema without depending on the controller binary.
//!
//! Parsing and per-call-site error wrapping stay in the controller —
//! those need `anyhow`, `serde_yaml`, and surface-specific error
//! semantics (GraphQL `safe_err` vs MCP JSON-RPC `-32602`). One
//! exception lives here: **pure type-level invariants** — caps and
//! validators that constrain values stored on these types and that
//! the controller's multiple write surfaces (GraphQL create_workflow,
//! MCP import_workflow, MCP import_yaml_workflow) must enforce
//! identically. Putting the canonical cap + pure validator here is
//! the cross-protocol-parity shape (sibling to
//! `talos_memory::validate_memory_key` per MCP-834). Surface-specific
//! wrappers delegate.
//!
//! See [`MAX_WORKFLOW_EXECUTION_TIMEOUT_SECS`] +
//! [`validate_graph_timeouts`] for the first exception.

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

/// MCP-1216 / MCP-1217 (2026-05-18): cap on the workflow-level
/// wall-clock timeout read from a workflow's graph_json top-level
/// `execution_timeout_secs` field.
///
/// **Why this cap exists.** `talos-workflow-engine` parses this value
/// as a `u64` and applies it via
/// `engine.set_execution_timeout_secs(secs)`. Without an API-boundary
/// bound, a caller could submit `execution_timeout_secs: 86400` and
/// pin a worker slot for 24 hours per execution × up to 100 concurrent
/// executions (the `max_concurrent_executions` cap from MCP-1182).
/// Sibling drift to MCP-584 (per-call HTTP timeout cap at 120 s) +
/// MCP-1215 (LLM streaming idle cap at 60 s) — every caller-controlled
/// wall-clock parameter needs a server-side bound or it's a DoS surface.
///
/// **3600 s (1 hour)** accommodates every legitimate workflow observed
/// in the live cluster (daily-brief uses 120 s; competitive-watch
/// workflows use ~60 s; the engine default when the field is absent
/// is 300 s). Operators legitimately needing longer-running workflows
/// should split into sub-workflows or use approval gates.
///
/// **Cross-protocol consumers.** Every write path below MUST validate
/// against this cap; new write paths must too.
/// * GraphQL `create_workflow` / `update_workflow` —
///   `talos_api::validation::validate_workflow_execution_timeout`
///   wraps with `safe_err`.
/// * MCP `import_workflow` (bundle-based) — calls
///   [`validate_graph_timeouts`] before persistence.
/// * MCP `import_yaml_workflow` — calls [`validate_graph_timeouts`]
///   post-build before persistence.
pub const MAX_WORKFLOW_EXECUTION_TIMEOUT_SECS: u64 = 3600;

/// MCP-1218 (2026-05-18): cap on the **per-node** `timeout_secs` field
/// inside `graph_json.nodes[].data.timeout_secs`.
///
/// **Why this cap exists.** `talos-workflow-engine`'s
/// `parse_system_node_kind` reads `data.timeout_secs` as a `u64` with
/// no upper bound for `sub_workflow`, `dispatch`, `capability_dispatch`,
/// `agent_loop`, `judge`, `ensemble`, and `reflective_retry` nodes.
/// MCP add-node handlers cap caller input at `[1, 600]` via
/// `validate_range_u64` — but the cap doesn't survive when a workflow
/// is created via `import_workflow` / `import_yaml_workflow` /
/// `create_workflow` with arbitrary node JSON.
///
/// **The bypass.** The workflow-level cap above is the FIRST line of
/// defense, but `execution_timeout_secs: 0` is the engine's
/// "wall-clock disabled" sentinel (legitimate state per the engine's
/// own `set_execution_timeout(None)` typed API). Pre-MCP-1218 a
/// caller could combine `execution_timeout_secs: 0` (passes the 3600
/// cap because `0 > 3600` is false) with
/// `nodes[].data.timeout_secs: 86400` and pin a worker slot for the
/// per-node value with no wall-clock override above it. The per-node
/// cap is the SECOND line of defense — always enforced, regardless
/// of whether the operator disabled wall-clock.
///
/// **600 s** matches the MCP add-node handlers' write-time validate_range_u64
/// upper bound. Engine defaults are 30 s (sub_workflow, dispatch,
/// capability_dispatch) and 60 s (agent_loop, judge, ensemble,
/// reflective_retry) — every legitimate value is well under 600 s.
pub const MAX_NODE_TIMEOUT_SECS: u64 = 600;

/// MCP-1219 (2026-05-18): cap on the per-node `retry_count` field
/// (both top-level and `data.retry_count` — `read_node_retry_policy`
/// accepts either shape).
///
/// **Why this cap exists.** `talos-workflow-engine`'s
/// `read_node_retry_policy` reads `retry_count` as `u64`, casts to
/// `u32`, with no upper bound. The actor-budget clamp at
/// `read_node_retry_policy_with_actor_cap` ONLY fires when
/// `actor_id.is_none()` (`MAX_RETRIES_UNBUDGETED = 3`); actor-bound
/// executions pass through verbatim. Combined with the per-node
/// `timeout_secs` cap from MCP-1218 (600 s), a node with
/// `retry_count: 1_000_000` triggered by an actor would hold a
/// worker slot for up to 600 s × 1M = ~19 years per node — bounded
/// only by the workflow-level `execution_timeout_secs` (which the
/// caller can set to 0/disabled per MCP-1216 semantics).
///
/// **100** matches the MCP `update_node_config` write-time cap
/// already in place at `talos-mcp-handlers/src/graph.rs:1378`
/// (`retry_count must be a non-negative integer ≤ 100`). Worst-case
/// at cap: 100 retries × 600 s timeout = 60_000 s ≈ 16.6 hours per
/// node, still bounded by the workflow-level 3600 s wall-clock cap
/// when set.
pub const MAX_NODE_RETRY_COUNT: u32 = 100;

/// MCP-1219 (2026-05-18): cap on the per-node `retry_backoff_ms`
/// field. Pre-fix unbounded — `retry_backoff_ms: 86_400_000` (24 h
/// between attempts) was accepted. Sibling write-time cap is the
/// MCP `update_node_config` `≤ 600_000` ceiling at
/// `talos-mcp-handlers/src/graph.rs:1415`.
///
/// **600_000 ms (10 minutes)** matches the MCP write-time cap.
/// Worst-case dwell at cap with MAX_NODE_RETRY_COUNT: 100 ×
/// (600 s timeout + 600 s backoff) = 120_000 s ≈ 33 hours per node;
/// the workflow-level wall-clock cap still bounds the whole workflow.
pub const MAX_NODE_RETRY_BACKOFF_MS: u64 = 600_000;

/// MCP-1220 (2026-05-18): cap on `repeat_loop` node's `data.count`
/// field. Pre-fix `graph_parser` clamped at `u32::MAX` (~4.3
/// billion) — that's type coercion, not a real safety cap. Every
/// other system-loop kind has a hard upper bound:
/// * `loop.max_iterations` — `.min(100)` clamp
/// * `agent_loop.max_iterations` — `.min(50)` clamp
/// * `react_loop.max_iterations` — `.min(50)` clamp
/// * `ensemble.count` — `.min(10).max(2)` clamp
/// * `reflective_retry.max_retries` — `.min(5).max(1)` clamp
///
/// `repeat_loop` was the unbounded holdout. **100** matches the
/// strictest sibling cap (`loop.max_iterations`) — `repeat_loop`
/// is the deterministic-N-iterations variant of the same pattern.
/// Operators legitimately needing more should orchestrate via
/// scheduled workflows or sub-workflow fan-out.
pub const MAX_REPEAT_LOOP_COUNT: u64 = 100;

/// MCP-1221 (2026-05-18): cap on `llm_dispatch.data.routes` entry
/// count. Pre-fix the engine's parser built an unbounded
/// `HashMap<String, Uuid>` from the JSON object; a malicious
/// workflow with 100k routes occupies ~5 MiB of route metadata
/// per workflow load × max_concurrent_executions (100) per workflow
/// × N workflows in the user's library — memory amplification at
/// every trigger. Real classifier dispatches use 3–20 routes
/// (one per class label).
pub const MAX_LLM_DISPATCH_ROUTES: usize = 50;

/// MCP-1221: cap on `capability_dispatch.data.required_capabilities`
/// length. Engine iterates the Vec linearly during every dispatch
/// attempt; unbounded length = unbounded CPU per dispatch. Real
/// capability dispatches require 1–5 capabilities. Sibling to
/// MAX_LLM_DISPATCH_ROUTES.
pub const MAX_REQUIRED_CAPABILITIES: usize = 20;

/// MCP-1221: cap on Rhai expression byte length for fields the
/// engine evaluates as Rhai. Applies to:
/// * `nodes[].retry_condition` (top-level + `data` shape)
/// * `nodes[].retry_delay_expression` (top-level + `data` shape)
/// * `loop.data.condition` (Rhai expr, loop body)
/// * `while_loop.data.condition`
/// * `dispatch.data.dispatch_expression`
/// * `inline_judge.data.verdict_expr`
/// * `fan_in.data.aggregation_expr`
/// * `synthesize.data.synthesis_expr`
/// * `verify.data.condition`
///
/// Pre-fix unbounded — the engine's Rhai compile cost is O(expr
/// length); a multi-MB expression could pin CPU per node evaluation.
/// `graph_json`'s 5 MiB envelope cap (in `handle_import_workflow`)
/// transitively bounds total size, but a single 5 MiB Rhai
/// expression on one node is still a real concern. **8 KiB** is
/// generous for any realistic Rhai expression (the inline_judge
/// `verdict_expr` from real workflows is typically <500 bytes;
/// retry conditions are typically <100 bytes).
pub const MAX_RHAI_EXPRESSION_BYTES: usize = 8 * 1024;

/// Pure validator for the canonical workflow timeout + retry caps.
/// Accepts a `graph_json` string (the same shape persisted to
/// `workflows.graph_json`); returns `Err(message)` on the FIRST
/// violation found, walking:
/// 1. Top-level `execution_timeout_secs` — capped at
///    [`MAX_WORKFLOW_EXECUTION_TIMEOUT_SECS`] (MCP-1216/1217).
/// 2. Each `nodes[].data.timeout_secs` — capped at
///    [`MAX_NODE_TIMEOUT_SECS`] (MCP-1218).
/// 3. Each `nodes[].retry_count` (and `nodes[].data.retry_count`)
///    — capped at [`MAX_NODE_RETRY_COUNT`] (MCP-1219).
/// 4. Each `nodes[].retry_backoff_ms` (and `nodes[].data.retry_backoff_ms`)
///    — capped at [`MAX_NODE_RETRY_BACKOFF_MS`] (MCP-1219).
/// 5. Each `repeat_loop` node's `data.count` — capped at
///    [`MAX_REPEAT_LOOP_COUNT`] (MCP-1220).
/// 6. Each `llm_dispatch.data.routes` entry count — capped at
///    [`MAX_LLM_DISPATCH_ROUTES`] (MCP-1221).
/// 7. Each `capability_dispatch.data.required_capabilities` length
///    — capped at [`MAX_REQUIRED_CAPABILITIES`] (MCP-1221).
/// 8. Each Rhai-expression field byte length (top-level
///    `retry_condition` / `retry_delay_expression` on any node,
///    plus per-kind `condition` / `dispatch_expression` /
///    `verdict_expr` / `aggregation_expr` / `synthesis_expr`) —
///    capped at [`MAX_RHAI_EXPRESSION_BYTES`] (MCP-1221).
///
/// **Encoding contract.** Matches the engine's own parser exactly:
/// only `.as_u64()` values are inspected. Floats / negative integers /
/// strings cause the engine to silently fall back to its default
/// (300 s workflow-level; 30 or 60 s per-node), so this validator
/// likewise accepts those without complaint — rejecting them here
/// would be a behavioural change beyond the timeout-cap scope. Only
/// `Some(secs) > cap` is rejected. `0` is allowed at the workflow
/// level because the engine treats it as "disabled" / "use default".
///
/// Malformed JSON returns `Ok(())` — defer to the canonical engine
/// parser for the parse error message (avoid double-failing here).
pub fn validate_graph_timeouts(graph_json: &str) -> Result<(), String> {
    let parsed: serde_json::Value = match serde_json::from_str(graph_json) {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };

    // 1. Workflow-level wall-clock cap.
    if let Some(secs) = parsed
        .get("execution_timeout_secs")
        .and_then(|v| v.as_u64())
    {
        if secs > MAX_WORKFLOW_EXECUTION_TIMEOUT_SECS {
            return Err(format!(
                "Invalid execution_timeout_secs {} in graph_json: exceeds the {} second cap. \
                 Split long-running workflows into sub-workflows or use an approval gate.",
                secs, MAX_WORKFLOW_EXECUTION_TIMEOUT_SECS
            ));
        }
    }

    // 2. Per-node caps. Walks `nodes[]` and checks each:
    //      * `data.timeout_secs` (MCP-1218)
    //      * top-level or `data.retry_count` (MCP-1219)
    //      * top-level or `data.retry_backoff_ms` (MCP-1219)
    //    Nodes without the relevant field pass through — matches
    //    the engine's `.unwrap_or(default)` behaviour. Mirrors the
    //    engine's dual-shape lookup (`read_node_retry_policy`
    //    accepts either top-level or `data` for retry fields).
    if let Some(nodes) = parsed.get("nodes").and_then(|v| v.as_array()) {
        for node in nodes {
            let node_id = node
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("<unknown>");

            // 2a. Per-node timeout_secs (MCP-1218 / MCP-1230). Dual-shape:
            //      top-level OR `data.timeout_secs`. The original MCP-1218
            //      fix only checked `data.timeout_secs`, but
            //      `add_node_to_workflow` writes `timeout_secs` at the
            //      node's top level via `build_add_node_payload` (alongside
            //      retry_count / retry_backoff_ms). Verified live on
            //      2026-05-19: `add_node_to_workflow(timeout_secs: 86400)`
            //      bypassed the validator and persisted because the
            //      top-level shape was missed; same call with
            //      `retry_count: 9000` was correctly rejected because
            //      MCP-1219 was already dual-shape. This brings
            //      timeout_secs into parity with retry_count.
            let timeout_secs = node
                .get("timeout_secs")
                .or_else(|| node.get("data").and_then(|d| d.get("timeout_secs")))
                .and_then(|v| v.as_u64());
            if let Some(secs) = timeout_secs {
                if secs > MAX_NODE_TIMEOUT_SECS {
                    return Err(format!(
                        "Invalid timeout_secs {} on node '{}' in graph_json: exceeds the {} second per-node cap. \
                         Per-node timeouts are bounded to bound worker-slot occupancy when the workflow-level \
                         execution_timeout_secs is set to 0 (disabled).",
                        secs, node_id, MAX_NODE_TIMEOUT_SECS
                    ));
                }
            }

            // 2b. Per-node retry_count (MCP-1219). Dual-shape: top-level
            //     OR `data.retry_count` (the engine's read accepts both).
            let retry_count = node
                .get("retry_count")
                .or_else(|| node.get("data").and_then(|d| d.get("retry_count")))
                .and_then(|v| v.as_u64());
            if let Some(rc) = retry_count {
                if rc > MAX_NODE_RETRY_COUNT as u64 {
                    return Err(format!(
                        "Invalid retry_count {} on node '{}' in graph_json: exceeds the {} cap. \
                         The actor-budget clamp only fires for non-actor executions; an actor-bound \
                         workflow with retry_count={} and the per-node timeout_secs at the cap would \
                         hold a worker slot for years.",
                        rc, node_id, MAX_NODE_RETRY_COUNT, rc
                    ));
                }
            }

            // 2c. Per-node retry_backoff_ms (MCP-1219). Same dual shape.
            let retry_backoff = node
                .get("retry_backoff_ms")
                .or_else(|| node.get("data").and_then(|d| d.get("retry_backoff_ms")))
                .and_then(|v| v.as_u64());
            if let Some(ms) = retry_backoff {
                if ms > MAX_NODE_RETRY_BACKOFF_MS {
                    return Err(format!(
                        "Invalid retry_backoff_ms {} on node '{}' in graph_json: exceeds the {} ms (10 min) cap. \
                         Mirrors the MCP update_node_config write-time ceiling.",
                        ms, node_id, MAX_NODE_RETRY_BACKOFF_MS
                    ));
                }
            }

            // 2d. `repeat_loop.data.count` (MCP-1220). The engine
            //     clamps with `.min(u32::MAX) as u32` — type
            //     coercion, not a safety cap. Every sibling loop
            //     kind has a real upper bound; repeat_loop was the
            //     unbounded holdout. Only enforced when the node's
            //     `kind` is `repeat_loop` (other kinds may use
            //     `data.count` for unrelated semantics — e.g.
            //     `ensemble.count` is clamped at parse time, no
            //     bypass concern).
            let kind = node.get("kind").and_then(|v| v.as_str());
            let ty = node.get("type").and_then(|v| v.as_str());
            let is_repeat_loop = kind == Some("repeat_loop") || ty == Some("system:repeat_loop");
            if is_repeat_loop {
                if let Some(data) = node.get("data") {
                    if let Some(count) = data.get("count").and_then(|v| v.as_u64()) {
                        if count > MAX_REPEAT_LOOP_COUNT {
                            return Err(format!(
                                "Invalid repeat_loop count {} on node '{}' in graph_json: exceeds the {} iteration cap. \
                                 Sibling loop kinds (loop, agent_loop, react_loop, ensemble) cap at 5-100 iterations; \
                                 repeat_loop was the unbounded holdout. Use a scheduled workflow or sub-workflow fan-out \
                                 for higher counts.",
                                count, node_id, MAX_REPEAT_LOOP_COUNT
                            ));
                        }
                    }
                }
            }

            // 2e. `llm_dispatch.data.routes` entry-count cap
            //     (MCP-1221). Engine builds an unbounded
            //     `HashMap<String, Uuid>` from the routes object.
            let is_llm_dispatch = kind == Some("llm_dispatch") || ty == Some("system:llm_dispatch");
            if is_llm_dispatch {
                if let Some(data) = node.get("data") {
                    if let Some(routes) = data.get("routes").and_then(|v| v.as_object()) {
                        if routes.len() > MAX_LLM_DISPATCH_ROUTES {
                            return Err(format!(
                                "Invalid llm_dispatch routes count {} on node '{}' in graph_json: exceeds the {} cap. \
                                 Classifier dispatches typically use 3-20 routes; values in the thousands suggest a \
                                 misuse pattern.",
                                routes.len(),
                                node_id,
                                MAX_LLM_DISPATCH_ROUTES
                            ));
                        }
                    }
                }
            }

            // 2f. `capability_dispatch.data.required_capabilities`
            //     length cap (MCP-1221). Engine iterates linearly
            //     per dispatch — unbounded length = unbounded CPU
            //     per call.
            let is_cap_dispatch =
                kind == Some("capability_dispatch") || ty == Some("system:capability_dispatch");
            if is_cap_dispatch {
                if let Some(data) = node.get("data") {
                    if let Some(caps) = data.get("required_capabilities").and_then(|v| v.as_array())
                    {
                        if caps.len() > MAX_REQUIRED_CAPABILITIES {
                            return Err(format!(
                                "Invalid required_capabilities length {} on node '{}' in graph_json: exceeds the {} cap. \
                                 Real capability dispatches require 1-5 capabilities.",
                                caps.len(),
                                node_id,
                                MAX_REQUIRED_CAPABILITIES
                            ));
                        }
                    }
                }
            }

            // 2g. Rhai-expression byte caps (MCP-1221). The engine
            //     compiles each of these expressions; unbounded
            //     length means unbounded CPU per node evaluation.
            //     Top-level retry_condition / retry_delay_expression
            //     PLUS the per-kind Rhai fields under `data`.
            for field in &["retry_condition", "retry_delay_expression"] {
                let val = node
                    .get(*field)
                    .or_else(|| node.get("data").and_then(|d| d.get(*field)))
                    .and_then(|v| v.as_str());
                if let Some(s) = val {
                    if s.len() > MAX_RHAI_EXPRESSION_BYTES {
                        return Err(format!(
                            "Invalid {} length {} bytes on node '{}' in graph_json: exceeds the {} byte cap.",
                            field,
                            s.len(),
                            node_id,
                            MAX_RHAI_EXPRESSION_BYTES
                        ));
                    }
                }
            }

            // Per-kind Rhai fields under `data`.
            let rhai_field_for_kind: &[(&str, &[&str])] = &[
                ("loop", &["condition"]),
                ("while_loop", &["condition"]),
                ("dispatch", &["dispatch_expression"]),
                ("inline_judge", &["verdict_expr"]),
                ("fan_in", &["aggregation_expr"]),
                ("synthesize", &["synthesis_expr"]),
                ("verify", &["condition"]),
            ];
            for (target_kind, fields) in rhai_field_for_kind {
                let system_ty = format!("system:{}", target_kind);
                let matches_kind = kind == Some(*target_kind) || ty == Some(system_ty.as_str());
                if !matches_kind {
                    continue;
                }
                let Some(data) = node.get("data") else {
                    continue;
                };
                for field in *fields {
                    if let Some(s) = data.get(*field).and_then(|v| v.as_str()) {
                        if s.len() > MAX_RHAI_EXPRESSION_BYTES {
                            return Err(format!(
                                "Invalid {}.{} length {} bytes on node '{}' in graph_json: exceeds the {} byte cap. \
                                 Rhai expressions in real workflows are typically <500 bytes.",
                                target_kind,
                                field,
                                s.len(),
                                node_id,
                                MAX_RHAI_EXPRESSION_BYTES
                            ));
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// Declarative YAML workflow definition.
/// Designed for version control, code review, and CI/CD pipelines.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YamlWorkflow {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub nodes: Vec<YamlNode>,
    #[serde(default)]
    pub edges: Vec<YamlEdge>,
    #[serde(default)]
    pub settings: WorkflowSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YamlNode {
    pub id: String,
    /// Module name from catalog, or "inline" for inline Rust code.
    #[serde(default)]
    pub module: String,
    /// MCP-12: Option fields skip serialization when None so the YAML
    /// export doesn't render half its body as `field: null` lines.
    /// Deserialization still accepts both omitted and explicit-null forms
    /// because `#[serde(default)]` populates with None on either.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_world: Option<String>,
    /// Inline Rust source code (when module = "inline" or omitted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rust_code: Option<String>,
    /// Inline JavaScript source (when module = "inline-js").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub js_code: Option<String>,
    /// Inline Python source (when module = "inline-py").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub python_code: Option<String>,
    /// Module configuration key-value pairs.
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub config: serde_json::Map<String, JsonValue>,
    /// System node kind (e.g., "FanIn", "SubWorkflow").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_type: Option<String>,
    /// retry_count = 0 is the default; skip when default to reduce noise.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub retry_count: u32,
    /// continue_on_error = false is the default; skip when default.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub continue_on_error: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_condition: Option<String>,
    /// Module version pin (e.g., "1.2.0" or "^1.0").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YamlEdge {
    pub from: String,
    pub to: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub edge_type: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkflowSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_timeout_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concurrency_limit: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_round_trip_through_json() {
        let wf = YamlWorkflow {
            name: "x".into(),
            description: String::new(),
            capabilities: vec![],
            nodes: vec![],
            edges: vec![],
            settings: WorkflowSettings::default(),
        };
        let json = serde_json::to_string(&wf).unwrap();
        let back: YamlWorkflow = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "x");
    }

    /// MCP-12: serialized YAML should NOT contain `field: null` for
    /// every Option<T> field on a default node. The previous behavior
    /// rendered ~12 verbose null lines per node — half the YAML body.
    #[test]
    fn yaml_node_serialize_omits_none_fields() {
        let node = YamlNode {
            id: "test-node".into(),
            module: "echo".into(),
            capability_world: None,
            rust_code: None,
            js_code: None,
            python_code: None,
            config: serde_json::Map::new(),
            node_type: None,
            retry_count: 0,
            continue_on_error: false,
            skip_condition: None,
            version: None,
        };
        let yaml = serde_yaml::to_string(&node).unwrap();
        // Required + populated fields stay
        assert!(yaml.contains("id: test-node"));
        assert!(yaml.contains("module: echo"));
        // None / default fields are absent
        assert!(!yaml.contains("capability_world"), "yaml: {yaml}");
        assert!(!yaml.contains("rust_code"), "yaml: {yaml}");
        assert!(!yaml.contains("js_code"), "yaml: {yaml}");
        assert!(!yaml.contains("python_code"), "yaml: {yaml}");
        assert!(!yaml.contains("node_type"), "yaml: {yaml}");
        assert!(!yaml.contains("skip_condition"), "yaml: {yaml}");
        assert!(!yaml.contains("version"), "yaml: {yaml}");
        // Default scalars are also absent
        assert!(!yaml.contains("retry_count"), "yaml: {yaml}");
        assert!(!yaml.contains("continue_on_error"), "yaml: {yaml}");
        // Empty config is absent
        assert!(!yaml.contains("config"), "yaml: {yaml}");
    }

    /// Round-trip: a node serialized with omitted defaults still
    /// deserializes back to the same shape (default values populated).
    #[test]
    fn yaml_node_round_trips_with_omitted_defaults() {
        let original = YamlNode {
            id: "n".into(),
            module: "m".into(),
            capability_world: None,
            rust_code: None,
            js_code: None,
            python_code: None,
            config: serde_json::Map::new(),
            node_type: None,
            retry_count: 0,
            continue_on_error: false,
            skip_condition: None,
            version: None,
        };
        let yaml = serde_yaml::to_string(&original).unwrap();
        let back: YamlNode = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(back.id, "n");
        assert_eq!(back.module, "m");
        assert!(back.capability_world.is_none());
        assert_eq!(back.retry_count, 0);
        assert!(!back.continue_on_error);
    }

    /// Round-trip: a node serialized with EXPLICIT nulls also deserializes
    /// — back-compat with pre-MCP-12 YAML files in git.
    #[test]
    fn yaml_node_accepts_explicit_nulls_on_deserialize() {
        let yaml = r#"
id: n
module: m
capability_world: null
rust_code: null
node_type: null
config: {}
retry_count: 0
continue_on_error: false
skip_condition: null
version: null
"#;
        let back: YamlNode = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(back.id, "n");
        assert!(back.capability_world.is_none());
        assert_eq!(back.retry_count, 0);
    }

    /// Edges + Settings get the same treatment.
    #[test]
    fn yaml_edge_and_settings_omit_none() {
        let edge = YamlEdge {
            from: "a".into(),
            to: "b".into(),
            condition: None,
            edge_type: None,
        };
        let yaml = serde_yaml::to_string(&edge).unwrap();
        assert!(yaml.contains("from: a"));
        assert!(yaml.contains("to: b"));
        assert!(!yaml.contains("condition"));
        assert!(!yaml.contains("type"));

        let settings = WorkflowSettings::default();
        let yaml = serde_yaml::to_string(&settings).unwrap();
        assert!(!yaml.contains("execution_timeout_secs"));
        assert!(!yaml.contains("priority"));
        assert!(!yaml.contains("concurrency_limit"));
    }

    // ────────────────────────────────────────────────────────────────
    // validate_graph_timeouts tests (MCP-1216 / MCP-1217)
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn cap_is_one_hour() {
        // Tripwire: the 1-hour ceiling matches the documented
        // operator-decision context. Bumping it past 3600 needs a
        // reviewed commit with explicit context (per-node + per-loop
        // budget interactions).
        assert_eq!(MAX_WORKFLOW_EXECUTION_TIMEOUT_SECS, 3600);
    }

    #[test]
    fn timeout_validator_accepts_missing_field() {
        let g = r#"{"nodes": [], "edges": []}"#;
        assert!(validate_graph_timeouts(g).is_ok());
    }

    #[test]
    fn timeout_validator_accepts_typical_value() {
        // daily-brief uses 120; well within cap.
        let g = r#"{"execution_timeout_secs": 120}"#;
        assert!(validate_graph_timeouts(g).is_ok());
    }

    #[test]
    fn timeout_validator_accepts_zero() {
        // 0 = "disabled" sentinel; engine falls back to default.
        let g = r#"{"execution_timeout_secs": 0}"#;
        assert!(validate_graph_timeouts(g).is_ok());
    }

    #[test]
    fn timeout_validator_accepts_at_cap() {
        let g = format!(
            r#"{{"execution_timeout_secs": {}}}"#,
            MAX_WORKFLOW_EXECUTION_TIMEOUT_SECS
        );
        assert!(validate_graph_timeouts(&g).is_ok());
    }

    #[test]
    fn timeout_validator_rejects_above_cap() {
        let g = format!(
            r#"{{"execution_timeout_secs": {}}}"#,
            MAX_WORKFLOW_EXECUTION_TIMEOUT_SECS + 1
        );
        let err = validate_graph_timeouts(&g).unwrap_err();
        assert!(err.contains("execution_timeout_secs"));
        assert!(err.contains("exceeds"));
    }

    #[test]
    fn timeout_validator_rejects_24h() {
        // The canonical attack value: 86400 = 24 hours.
        let g = r#"{"execution_timeout_secs": 86400}"#;
        let err = validate_graph_timeouts(g).unwrap_err();
        assert!(err.contains("86400"));
    }

    #[test]
    fn timeout_validator_rejects_u64_max() {
        let g = format!(r#"{{"execution_timeout_secs": {}}}"#, u64::MAX);
        assert!(validate_graph_timeouts(&g).is_err());
    }

    #[test]
    fn timeout_validator_ignores_negative() {
        // Engine's `.as_u64()` returns None for negative i64; engine
        // then falls back to default. Match that behaviour.
        let g = r#"{"execution_timeout_secs": -1}"#;
        assert!(validate_graph_timeouts(g).is_ok());
    }

    #[test]
    fn timeout_validator_ignores_float() {
        let g = r#"{"execution_timeout_secs": 60.5}"#;
        assert!(validate_graph_timeouts(g).is_ok());
    }

    #[test]
    fn timeout_validator_ignores_string() {
        let g = r#"{"execution_timeout_secs": "60"}"#;
        assert!(validate_graph_timeouts(g).is_ok());
    }

    #[test]
    fn timeout_validator_handles_malformed_json() {
        // Defer to the engine's parser for the canonical parse error.
        let g = "{not valid json";
        assert!(validate_graph_timeouts(g).is_ok());
    }

    // ────────────────────────────────────────────────────────────────
    // Per-node timeout_secs tests (MCP-1218)
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn per_node_cap_is_ten_minutes() {
        // Tripwire: 600 s matches the MCP add-node handlers' write-
        // time validate_range_u64(1, 600, 30/60) cap. Bumping past
        // 600 needs a reviewed commit.
        assert_eq!(MAX_NODE_TIMEOUT_SECS, 600);
    }

    #[test]
    fn per_node_validator_accepts_no_nodes() {
        let g = r#"{"edges": []}"#;
        assert!(validate_graph_timeouts(g).is_ok());
    }

    #[test]
    fn per_node_validator_accepts_node_without_data() {
        let g = r#"{"nodes": [{"id": "a"}]}"#;
        assert!(validate_graph_timeouts(g).is_ok());
    }

    #[test]
    fn per_node_validator_accepts_node_without_timeout_field() {
        let g = r#"{"nodes": [{"id": "a", "data": {"foo": "bar"}}]}"#;
        assert!(validate_graph_timeouts(g).is_ok());
    }

    #[test]
    fn per_node_validator_accepts_typical_value() {
        let g = r#"{"nodes": [{"id": "a", "data": {"timeout_secs": 30}}]}"#;
        assert!(validate_graph_timeouts(g).is_ok());
    }

    #[test]
    fn per_node_validator_accepts_at_cap() {
        let g = format!(
            r#"{{"nodes": [{{"id": "a", "data": {{"timeout_secs": {}}}}}]}}"#,
            MAX_NODE_TIMEOUT_SECS
        );
        assert!(validate_graph_timeouts(&g).is_ok());
    }

    #[test]
    fn per_node_validator_rejects_above_cap() {
        let g = format!(
            r#"{{"nodes": [{{"id": "sub", "data": {{"timeout_secs": {}}}}}]}}"#,
            MAX_NODE_TIMEOUT_SECS + 1
        );
        let err = validate_graph_timeouts(&g).unwrap_err();
        assert!(err.contains("timeout_secs"));
        assert!(err.contains("'sub'"));
        assert!(err.contains("per-node cap"));
    }

    #[test]
    fn per_node_validator_rejects_24h() {
        // The canonical attack value paired with execution_timeout_secs: 0
        // pre-MCP-1218.
        let g = r#"{"nodes": [{"id": "sub", "data": {"timeout_secs": 86400}}]}"#;
        let err = validate_graph_timeouts(g).unwrap_err();
        assert!(err.contains("86400"));
    }

    // MCP-1230 (2026-05-19): per-node timeout_secs validator was data-
    // shape-only; the MCP `add_node_to_workflow` tool's
    // `build_add_node_payload` writes `timeout_secs` at the top level of
    // the node (parallel to `id` and `type`), not under `data`. That
    // top-level shape bypassed the validator until MCP-1230 brought it
    // into dual-shape parity with retry_count/retry_backoff_ms. Live-
    // verified on 2026-05-19 against the production cluster:
    // `add_node_to_workflow(timeout_secs: 86400)` persisted unchecked
    // before this fix.
    #[test]
    fn per_node_validator_rejects_top_level_shape_above_cap() {
        // Shape produced by build_add_node_payload — `timeout_secs` at
        // the node's top level, NOT under `data`.
        let g = format!(
            r#"{{"nodes": [{{"id": "n2", "timeout_secs": {}}}]}}"#,
            MAX_NODE_TIMEOUT_SECS + 1
        );
        let err = validate_graph_timeouts(&g).unwrap_err();
        assert!(err.contains("timeout_secs"));
        assert!(err.contains("'n2'"));
    }

    #[test]
    fn per_node_validator_rejects_top_level_24h() {
        // Exact value caught live on 2026-05-19 bypassing the chokepoint.
        let g = r#"{"nodes": [{"id": "n2", "timeout_secs": 86400}]}"#;
        let err = validate_graph_timeouts(g).unwrap_err();
        assert!(err.contains("86400"));
    }

    #[test]
    fn per_node_validator_top_level_at_cap_accepted() {
        // 600 is at the cap — should pass through cleanly. Sibling to
        // per_node_validator_accepts_at_cap for the top-level shape.
        let g = format!(
            r#"{{"nodes": [{{"id": "n2", "timeout_secs": {}}}]}}"#,
            MAX_NODE_TIMEOUT_SECS
        );
        assert!(validate_graph_timeouts(&g).is_ok());
    }

    #[test]
    fn per_node_validator_rejects_u64_max() {
        let g = format!(
            r#"{{"nodes": [{{"id": "sub", "data": {{"timeout_secs": {}}}}}]}}"#,
            u64::MAX
        );
        assert!(validate_graph_timeouts(&g).is_err());
    }

    #[test]
    fn per_node_validator_walks_all_nodes() {
        // Second node has bad value — must still be caught even when
        // the first one is fine.
        let g = r#"{"nodes": [
            {"id": "a", "data": {"timeout_secs": 30}},
            {"id": "b", "data": {"timeout_secs": 99999}}
        ]}"#;
        let err = validate_graph_timeouts(g).unwrap_err();
        assert!(err.contains("'b'"));
        assert!(err.contains("99999"));
    }

    #[test]
    fn per_node_validator_unknown_node_id() {
        // No `id` field — placeholder used in error message so caller
        // can still locate the node by position when reading the graph.
        let g = r#"{"nodes": [{"data": {"timeout_secs": 99999}}]}"#;
        let err = validate_graph_timeouts(g).unwrap_err();
        assert!(err.contains("<unknown>"));
    }

    #[test]
    fn per_node_validator_ignores_negative() {
        // Engine's `.as_u64()` returns None for negative i64.
        let g = r#"{"nodes": [{"id": "a", "data": {"timeout_secs": -1}}]}"#;
        assert!(validate_graph_timeouts(g).is_ok());
    }

    #[test]
    fn per_node_validator_ignores_string() {
        let g = r#"{"nodes": [{"id": "a", "data": {"timeout_secs": "30"}}]}"#;
        assert!(validate_graph_timeouts(g).is_ok());
    }

    #[test]
    fn per_node_validator_catches_the_actual_bypass() {
        // The MCP-1218 reproducer: workflow-level disabled (0 passes
        // the MCP-1216 cap) + per-node 24h timeout (would have run
        // for 24h pre-fix).
        let g = r#"{
            "execution_timeout_secs": 0,
            "nodes": [{"id": "sub", "kind": "sub_workflow", "data": {"timeout_secs": 86400}}]
        }"#;
        let err = validate_graph_timeouts(g).unwrap_err();
        assert!(err.contains("86400"));
    }

    // ────────────────────────────────────────────────────────────────
    // Per-node retry_count / retry_backoff_ms tests (MCP-1219)
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn retry_caps_match_mcp_write_time_ceilings() {
        // Tripwire: caps mirror the MCP update_node_config caps
        // (talos-mcp-handlers/src/graph.rs:1378 + 1415). Diverging
        // means a future caller hits a different ceiling depending
        // on which write surface they use.
        assert_eq!(MAX_NODE_RETRY_COUNT, 100);
        assert_eq!(MAX_NODE_RETRY_BACKOFF_MS, 600_000);
    }

    #[test]
    fn retry_count_validator_accepts_default() {
        // Default 2; well under cap.
        let g = r#"{"nodes": [{"id": "n", "retry_count": 2}]}"#;
        assert!(validate_graph_timeouts(g).is_ok());
    }

    #[test]
    fn retry_count_validator_accepts_at_cap() {
        let g = format!(
            r#"{{"nodes": [{{"id": "n", "retry_count": {}}}]}}"#,
            MAX_NODE_RETRY_COUNT
        );
        assert!(validate_graph_timeouts(&g).is_ok());
    }

    #[test]
    fn retry_count_validator_rejects_above_cap() {
        let g = format!(
            r#"{{"nodes": [{{"id": "n", "retry_count": {}}}]}}"#,
            MAX_NODE_RETRY_COUNT as u64 + 1
        );
        let err = validate_graph_timeouts(&g).unwrap_err();
        assert!(err.contains("retry_count"));
        assert!(err.contains("'n'"));
        assert!(err.contains("worker slot"));
    }

    #[test]
    fn retry_count_validator_rejects_1m() {
        // The canonical attack value pre-MCP-1219.
        let g = r#"{"nodes": [{"id": "n", "retry_count": 1000000}]}"#;
        let err = validate_graph_timeouts(g).unwrap_err();
        assert!(err.contains("1000000"));
    }

    #[test]
    fn retry_count_validator_checks_data_dual_shape() {
        // graph_parser accepts `data.retry_count` too — must catch
        // there as well.
        let g = r#"{"nodes": [{"id": "n", "data": {"retry_count": 99999}}]}"#;
        let err = validate_graph_timeouts(g).unwrap_err();
        assert!(err.contains("99999"));
    }

    #[test]
    fn retry_backoff_validator_accepts_default() {
        let g = r#"{"nodes": [{"id": "n", "retry_backoff_ms": 500}]}"#;
        assert!(validate_graph_timeouts(g).is_ok());
    }

    #[test]
    fn retry_backoff_validator_accepts_at_cap() {
        let g = format!(
            r#"{{"nodes": [{{"id": "n", "retry_backoff_ms": {}}}]}}"#,
            MAX_NODE_RETRY_BACKOFF_MS
        );
        assert!(validate_graph_timeouts(&g).is_ok());
    }

    #[test]
    fn retry_backoff_validator_rejects_above_cap() {
        let g = format!(
            r#"{{"nodes": [{{"id": "n", "retry_backoff_ms": {}}}]}}"#,
            MAX_NODE_RETRY_BACKOFF_MS + 1
        );
        let err = validate_graph_timeouts(&g).unwrap_err();
        assert!(err.contains("retry_backoff_ms"));
        assert!(err.contains("'n'"));
    }

    #[test]
    fn retry_backoff_validator_rejects_24h() {
        // The canonical attack value: 86_400_000 ms = 24 hours.
        let g = r#"{"nodes": [{"id": "n", "retry_backoff_ms": 86400000}]}"#;
        let err = validate_graph_timeouts(g).unwrap_err();
        assert!(err.contains("86400000"));
    }

    #[test]
    fn retry_backoff_validator_checks_data_dual_shape() {
        let g = r#"{"nodes": [{"id": "n", "data": {"retry_backoff_ms": 86400000}}]}"#;
        let err = validate_graph_timeouts(g).unwrap_err();
        assert!(err.contains("86400000"));
    }

    #[test]
    fn retry_validator_catches_combined_bypass() {
        // The full retry-escalation reproducer.
        let g = r#"{
            "execution_timeout_secs": 0,
            "nodes": [{
                "id": "n",
                "retry_count": 1000000,
                "retry_backoff_ms": 86400000,
                "data": {"timeout_secs": 600}
            }]
        }"#;
        // First violation found wins; here retry_count fires
        // because it walks before retry_backoff_ms.
        let err = validate_graph_timeouts(g).unwrap_err();
        assert!(err.contains("retry_count"));
        assert!(err.contains("1000000"));
    }

    #[test]
    fn retry_validator_ignores_negative_and_string() {
        let g = r#"{"nodes": [
            {"id": "a", "retry_count": -1},
            {"id": "b", "retry_backoff_ms": "500"}
        ]}"#;
        assert!(validate_graph_timeouts(g).is_ok());
    }

    // ────────────────────────────────────────────────────────────────
    // repeat_loop count tests (MCP-1220)
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn repeat_loop_cap_matches_strictest_sibling() {
        // Tripwire: 100 matches `loop.max_iterations` clamp in
        // graph_parser. Bumping needs explicit context.
        assert_eq!(MAX_REPEAT_LOOP_COUNT, 100);
    }

    #[test]
    fn repeat_loop_validator_accepts_at_cap_kind_form() {
        let g = format!(
            r#"{{"nodes": [{{"id": "rl", "kind": "repeat_loop", "data": {{"count": {}}}}}]}}"#,
            MAX_REPEAT_LOOP_COUNT
        );
        assert!(validate_graph_timeouts(&g).is_ok());
    }

    #[test]
    fn repeat_loop_validator_accepts_at_cap_type_form() {
        // Engine accepts BOTH `kind: "repeat_loop"` AND
        // `type: "system:repeat_loop"` shapes. Validator must too.
        let g = format!(
            r#"{{"nodes": [{{"id": "rl", "type": "system:repeat_loop", "data": {{"count": {}}}}}]}}"#,
            MAX_REPEAT_LOOP_COUNT
        );
        assert!(validate_graph_timeouts(&g).is_ok());
    }

    #[test]
    fn repeat_loop_validator_rejects_just_over_cap() {
        let g = format!(
            r#"{{"nodes": [{{"id": "rl", "kind": "repeat_loop", "data": {{"count": {}}}}}]}}"#,
            MAX_REPEAT_LOOP_COUNT + 1
        );
        let err = validate_graph_timeouts(&g).unwrap_err();
        assert!(err.contains("repeat_loop"));
        assert!(err.contains("'rl'"));
    }

    #[test]
    fn repeat_loop_validator_rejects_4_billion() {
        // The canonical attack value (engine's u32::MAX type-coerce
        // clamp made this look bounded but isn't).
        let g =
            r#"{"nodes": [{"id": "rl", "kind": "repeat_loop", "data": {"count": 4000000000}}]}"#;
        let err = validate_graph_timeouts(g).unwrap_err();
        assert!(err.contains("4000000000"));
    }

    #[test]
    fn repeat_loop_validator_ignores_non_repeat_loop_kind() {
        // `count` is also used by `ensemble` (clamped at 10 in
        // parser). Validator must NOT reject high `count` on
        // non-repeat_loop nodes — the engine already clamps those.
        let g = r#"{"nodes": [{"id": "e", "kind": "ensemble", "data": {"count": 100}}]}"#;
        assert!(validate_graph_timeouts(g).is_ok());
    }

    #[test]
    fn repeat_loop_validator_ignores_no_kind() {
        // Plain module nodes may legitimately use `data.count` for
        // unrelated semantics.
        let g = r#"{"nodes": [{"id": "n", "data": {"count": 99999}}]}"#;
        assert!(validate_graph_timeouts(g).is_ok());
    }

    // ────────────────────────────────────────────────────────────────
    // llm_dispatch routes / capability_dispatch required_capabilities
    // / Rhai expression caps (MCP-1221 — exhaustive inventory sweep)
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn llm_dispatch_routes_cap_tripwire() {
        assert_eq!(MAX_LLM_DISPATCH_ROUTES, 50);
    }

    #[test]
    fn llm_dispatch_routes_accepts_typical() {
        let g = r#"{"nodes": [{"id": "d", "kind": "llm_dispatch", "data": {"routes": {"a": "00000000-0000-0000-0000-000000000000", "b": "00000000-0000-0000-0000-000000000000"}}}]}"#;
        assert!(validate_graph_timeouts(g).is_ok());
    }

    #[test]
    fn llm_dispatch_routes_rejects_above_cap() {
        // Generate 51 routes.
        let mut routes = String::new();
        for i in 0..=MAX_LLM_DISPATCH_ROUTES {
            if i > 0 {
                routes.push(',');
            }
            routes.push_str(&format!(
                r#""r{}": "00000000-0000-0000-0000-000000000000""#,
                i
            ));
        }
        let g = format!(
            r#"{{"nodes": [{{"id": "d", "kind": "llm_dispatch", "data": {{"routes": {{{}}}}}}}]}}"#,
            routes
        );
        let err = validate_graph_timeouts(&g).unwrap_err();
        assert!(err.contains("llm_dispatch routes"));
        assert!(err.contains("'d'"));
    }

    #[test]
    fn required_capabilities_cap_tripwire() {
        assert_eq!(MAX_REQUIRED_CAPABILITIES, 20);
    }

    #[test]
    fn required_capabilities_accepts_typical() {
        let g = r#"{"nodes": [{"id": "c", "kind": "capability_dispatch", "data": {"required_capabilities": ["send-email", "read-file"]}}]}"#;
        assert!(validate_graph_timeouts(g).is_ok());
    }

    #[test]
    fn required_capabilities_rejects_above_cap() {
        let caps: Vec<String> = (0..=MAX_REQUIRED_CAPABILITIES)
            .map(|i| format!(r#""cap{}""#, i))
            .collect();
        let g = format!(
            r#"{{"nodes": [{{"id": "c", "kind": "capability_dispatch", "data": {{"required_capabilities": [{}]}}}}]}}"#,
            caps.join(",")
        );
        let err = validate_graph_timeouts(&g).unwrap_err();
        assert!(err.contains("required_capabilities"));
    }

    #[test]
    fn rhai_cap_tripwire() {
        assert_eq!(MAX_RHAI_EXPRESSION_BYTES, 8 * 1024);
    }

    #[test]
    fn rhai_retry_condition_rejects_above_cap() {
        let big = "true ".repeat(MAX_RHAI_EXPRESSION_BYTES);
        let g = format!(
            r#"{{"nodes": [{{"id": "n", "retry_condition": "{}"}}]}}"#,
            big
        );
        let err = validate_graph_timeouts(&g).unwrap_err();
        assert!(err.contains("retry_condition"));
    }

    #[test]
    fn rhai_retry_delay_expression_data_shape_rejects_above_cap() {
        // dual-shape: nested under `data`
        let big = "1 ".repeat(MAX_RHAI_EXPRESSION_BYTES);
        let g = format!(
            r#"{{"nodes": [{{"id": "n", "data": {{"retry_delay_expression": "{}"}}}}]}}"#,
            big
        );
        let err = validate_graph_timeouts(&g).unwrap_err();
        assert!(err.contains("retry_delay_expression"));
    }

    #[test]
    fn rhai_loop_condition_rejects_above_cap() {
        let big = "x ".repeat(MAX_RHAI_EXPRESSION_BYTES);
        let g = format!(
            r#"{{"nodes": [{{"id": "n", "kind": "loop", "data": {{"condition": "{}"}}}}]}}"#,
            big
        );
        let err = validate_graph_timeouts(&g).unwrap_err();
        assert!(err.contains("loop.condition"));
    }

    #[test]
    fn rhai_dispatch_expression_rejects_above_cap() {
        let big = "z ".repeat(MAX_RHAI_EXPRESSION_BYTES);
        let g = format!(
            r#"{{"nodes": [{{"id": "n", "kind": "dispatch", "data": {{"dispatch_expression": "{}"}}}}]}}"#,
            big
        );
        let err = validate_graph_timeouts(&g).unwrap_err();
        assert!(err.contains("dispatch.dispatch_expression"));
    }

    #[test]
    fn rhai_inline_judge_verdict_expr_rejects_above_cap() {
        let big = "v ".repeat(MAX_RHAI_EXPRESSION_BYTES);
        let g = format!(
            r#"{{"nodes": [{{"id": "n", "kind": "inline_judge", "data": {{"verdict_expr": "{}"}}}}]}}"#,
            big
        );
        let err = validate_graph_timeouts(&g).unwrap_err();
        assert!(err.contains("inline_judge.verdict_expr"));
    }

    #[test]
    fn rhai_accepts_typical_expressions() {
        // Real-world examples should pass cleanly.
        let g = r#"{"nodes": [
            {"id": "a", "retry_condition": "status != 429"},
            {"id": "b", "retry_delay_expression": "if status == 429 { 5000 } else { 1000 }"},
            {"id": "c", "kind": "loop", "data": {"condition": "output.finished != true"}},
            {"id": "d", "kind": "inline_judge", "data": {"verdict_expr": "output.score >= 0.7"}},
            {"id": "e", "kind": "verify", "data": {"condition": "output.is_valid == true"}}
        ]}"#;
        assert!(validate_graph_timeouts(g).is_ok());
    }

    #[test]
    fn rhai_kind_gating_does_not_check_unrelated_node() {
        // A plain module node with a giant `condition` field
        // should NOT trip the loop.condition check.
        let big = "x ".repeat(MAX_RHAI_EXPRESSION_BYTES);
        let g = format!(
            r#"{{"nodes": [{{"id": "n", "data": {{"condition": "{}"}}}}]}}"#,
            big
        );
        // No `kind: loop` → not validated. Fine.
        assert!(validate_graph_timeouts(&g).is_ok());
    }
}
