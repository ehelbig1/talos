//! Execution failure-analysis service: loads a failed/cancelled
//! execution, gathers its `node_failed` events, classifies each failure
//! into a user-actionable bucket with matching remediation steps, and
//! optionally applies the config-field auto-fix — the orchestration that
//! previously lived inline in
//! `talos-mcp-handlers/src/executions.rs::handle_analyze_execution_failure`
//! (~740 LoC of fetch + classify + patch + suggestion shaping).
//!
//! Architectural pattern: matches `talos-execution-orchestration`
//! (r295), `talos-workflow-manifest` (r302), `talos-replay-service`
//! (r303), and `talos-inline-compile-service` (r304). Arc-injected
//! dependencies, `thiserror` enum mapped to JSON-RPC codes via
//! `jsonrpc_code()`, typed input + outcome structs, and a
//! `user_facing_message()` accessor that collapses internal errors to a
//! generic message so the protocol response cannot leak schema or query
//! detail.
//!
//! Every operator-recognized string (the classification descriptions,
//! remediation step text, error messages, and the response field names)
//! is copied verbatim from the pre-extraction handler and locked by the
//! unit tests below.

#![forbid(unsafe_code)]

use std::sync::Arc;

use thiserror::Error;
use uuid::Uuid;

use talos_execution_repository::ExecutionRepository;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Service-level errors. Every variant maps to JSON-RPC `-32000` (the
/// pre-extraction handler emitted all of these through
/// `mcp_error(req_id, -32000, ...)`); the argument-shape errors
/// (`-32602`) stay in the protocol handler where `require_uuid` /
/// `validate_optional_bool` already own them.
#[derive(Debug, Error)]
pub enum FailureAnalysisError {
    /// Execution row missing or owned by a different user. Message is
    /// the literal pre-extraction string.
    #[error("Execution not found or access denied")]
    NotFound,

    /// Execution is not in a terminal-failure state. Message is the
    /// literal pre-extraction string (status echoed).
    #[error(
        "Execution status is '{status}' — only failed or cancelled executions can be analyzed."
    )]
    NotAnalyzable { status: String },

    /// The execution-row fetch failed. Detail is logged by the service;
    /// callers see the literal pre-extraction generic string.
    #[error("Database error fetching execution")]
    ExecutionFetch(#[source] anyhow::Error),

    /// The execution-events fetch failed. Detail is logged by the
    /// service; callers see the literal pre-extraction generic string.
    #[error("Database error fetching execution events")]
    EventsFetch(#[source] anyhow::Error),
}

impl FailureAnalysisError {
    /// Stable JSON-RPC error code for protocol wrappers.
    pub fn jsonrpc_code(&self) -> i32 {
        match self {
            Self::NotFound
            | Self::NotAnalyzable { .. }
            | Self::ExecutionFetch(_)
            | Self::EventsFetch(_) => -32000,
        }
    }

    /// Callable-safe message for the protocol response. The two DB
    /// variants collapse to fixed generic strings (the `#[source]`
    /// detail never renders through `Display`), so the response cannot
    /// leak schema or query detail.
    pub fn user_facing_message(&self) -> String {
        self.to_string()
    }
}

// -----------------------------------------------------------------------------
// Input / outcome
// -----------------------------------------------------------------------------

/// Typed input for [`FailureAnalysisService::analyze`].
#[derive(Debug, Clone, Copy)]
pub struct AnalyzeFailureInput {
    pub execution_id: Uuid,
    pub user_id: Uuid,
    /// When true, attempt the config-field auto-fix and surface
    /// auth-error fix suggestions.
    pub apply_fix: bool,
    /// When true AND a fix was applied, stamp the auto-retry note on
    /// the report (the caller still triggers `retry_execution`
    /// explicitly).
    pub auto_retry: bool,
}

/// Analysis report. `report` is the JSON body the protocol layer
/// serializes; its shape is preserved byte-for-byte from the
/// pre-extraction handler (execution_id / workflow_id / status /
/// failed_node_count / failed_nodes / global_error /
/// apply_fix_available / tip, plus the optional fix_result /
/// auth_fix_suggestion / auto_retry_* fields).
#[derive(Debug, Clone)]
pub struct AnalyzeFailureOutcome {
    pub report: serde_json::Value,
}

// -----------------------------------------------------------------------------
// Pure helpers (unit-testable without a DB)
// -----------------------------------------------------------------------------

// MCP-1138 (2026-05-16): shared cap for the three sibling
// error-message classifiers below (`classify_error`,
// `extract_config_field`, `extract_secret_name_from_auth_error`).
// Each previously ran a full-input `to_lowercase()` clone followed
// by 4-15 substring scans on caller-controlled `raw_error` strings
// pulled from `execution_events.payload` (TEXT; Postgres caps at
// ~1 GB). A multi-MB workflow error message multiplied through
// per-failed-node iteration. 4 KiB matches the sibling cap in
// `talos_retry_intelligence::classify_error` (MCP-1135).
// Meaningful classification tokens (LLM/HTTP/host-allowlist,
// 'FIELD' / 'SECRET' identifiers) live in the first paragraph by
// construction; buried tokens past 4 KiB return the same
// "unknown" fall-through as MCP-1135.
pub fn truncate_for_classify(s: &str) -> &str {
    const MAX_BYTES: usize = 4096;
    if s.len() <= MAX_BYTES {
        return s;
    }
    let mut end = MAX_BYTES;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Classify a raw error message into a `(error_type, description)`
/// bucket. Strings preserved verbatim from the pre-extraction handler.
pub fn classify_error(msg: &str) -> (&'static str, &'static str) {
    // MCP-1138 (2026-05-16): cap input before to_lowercase to bound
    // the heap clone + per-pattern .contains scans. Same anti-pattern
    // as MCP-1135 (talos_retry_intelligence::classify_error). Error
    // messages come from `n.get("raw_error")` reads off
    // `execution_events.payload` (TEXT, ~1 GB Postgres ceiling); a
    // multi-MB workflow error message ran the full clone + 15+
    // substring scans per failed-node analysis. 4 KiB matches the
    // sibling cap; meaningful classification tokens live in the
    // first paragraph by construction (LLM/HTTP/host-allowlist
    // errors).
    let lower = truncate_for_classify(msg).to_lowercase();
    // ── Most specific gates first ────────────────────────────────────
    // Order matters: each branch is `else if`; the first match wins.
    if lower.contains("output_schema enforcement fired")
        || lower.contains("output schema enforcement fired")
        || (lower.contains("required keys") && lower.contains("got prose"))
    {
        // Strict-JSON enforcement on an LLM Inference node returned
        // prose instead of the expected JSON shape. The actionable
        // fix is to tighten the SYSTEM_PROMPT — pre-empt the generic
        // "review logs / reproduce in sandbox" advice.
        (
            "output_schema_violation",
            "The LLM Inference node's OUTPUT_SCHEMA enforcement rejected the model's response because it wasn't strict JSON matching the required keys. The model returned prose / markdown / a JSON code fence instead of the bare object the schema demanded.",
        )
    } else if lower.contains("forbiddenhost")
        || lower.contains("forbidden host")
        || lower.contains("host not allowed")
        || lower.contains("host is not in the allowlist")
        || lower.contains("not in the node's allowlist")
    {
        (
            "host_not_allowed",
            "The module tried to reach a host that's not in its allowed_hosts list.",
        )
    } else if lower.contains("compilation failed")
        || lower.contains("compile error")
        || lower.contains("failed to compile")
        || (lower.contains("cargo") && lower.contains("error"))
    {
        (
            "module_compile_error",
            "A module failed to compile — bad Rust code, dep mismatch, or WIT drift.",
        )
    } else if lower.contains("expected value")
        || lower.contains("invalid type")
        || lower.contains("invalid json")
        || lower.contains("expected ident")
        || lower.contains("trailing characters")
        || (lower.contains("from_str") && lower.contains("error"))
        || (lower.contains("serde") && lower.contains("error"))
        || (lower.contains("expected") && lower.contains("found "))
    {
        (
            "json_parse",
            "JSON parsing failed — the input shape didn't match what the module expected.",
        )
    } else if lower.contains("secret not found")
        || lower.contains("secret missing")
        || lower.contains("key not found")
        || (lower.contains("secret") && lower.contains("not found"))
        || (lower.contains("secret") && lower.contains("notfound"))
        || (lower.contains("retrieve") && lower.contains("notfound"))
    {
        (
            "missing_secret",
            "A required secret credential was not found in the vault.",
        )
    } else if lower.contains("rate limit")
        || lower.contains("429")
        || lower.contains("too many requests")
    {
        (
            "rate_limit",
            "The module hit a rate limit on an external API.",
        )
    } else if lower.contains("out of fuel")
        || lower.contains("fuel exhausted")
        || (lower.contains("fuel") && lower.contains("limit"))
    {
        (
            "fuel_exhausted",
            "The WASM module ran out of fuel (compute budget). Bump max_fuel via fuel_budget on hot_update_module.",
        )
    } else if lower.contains("wasm trap") || lower.contains("trap: ") {
        (
            "wasm_trap",
            "The WASM module hit a fatal trap (panic, OOB access, invalid op).",
        )
    } else if lower.contains("timed out")
        || lower.contains("timeout")
        || lower.contains("deadline exceeded")
        || lower.contains("execution exceeded")
    {
        (
            "timeout",
            "The module exceeded its execution-time limit. Bump timeout_secs or split the work.",
        )
    } else if lower.contains("connection refused")
        || lower.contains("connection timed out")
        || lower.contains("connectionfailed")      // redis / single-word connection error
        || lower.contains("connection failed")
        || lower.contains("dns")
        || (lower.contains("network") && lower.contains("error"))
        || lower.contains("no route to host")
        || lower.contains("failed to connect")
        || lower.contains("connect error")
    {
        (
            "network_error",
            "A network or infrastructure connection failed — the backing service may be unreachable.",
        )
    } else if lower.contains("missing field")
        || lower.contains("invalid config")
        || lower.contains("required field")
        || (lower.contains("config") && lower.contains("error"))
    {
        (
            "config_error",
            "A required configuration field is missing or invalid.",
        )
    } else if lower.contains("401") || lower.contains("invalid token") {
        (
            "http_401",
            "HTTP 401 Unauthorized — the credential is missing, expired, or rejected by the API.",
        )
    } else if lower.contains("403")
        || (lower.contains("forbidden") && !lower.contains("forbiddenhost"))
    {
        (
            "http_403",
            "HTTP 403 Forbidden — the credential is valid but lacks the required permission/scope.",
        )
    } else if lower.contains("404") || lower.contains("not found") {
        (
            "http_404",
            "HTTP 404 Not Found — the API endpoint or resource doesn't exist.",
        )
    } else if lower.contains("500")
        || lower.contains("502")
        || lower.contains("503")
        || lower.contains("504")
        || lower.contains("internal server error")
        || lower.contains("bad gateway")
        || lower.contains("gateway timeout")
    {
        (
            "http_5xx",
            "HTTP 5xx — the upstream API is unhealthy. Usually transient; retry with backoff.",
        )
    } else if lower.contains("unauthorized") || lower.contains("authentication failed") {
        // Generic Unauthorized that didn't match the more specific HTTP gates.
        // From the worker, this typically means a secrets gate failed
        // (capability world / allowlist / reserved-host). Use
        // test_secret_access(module_id, secret_path) to identify which gate.
        (
            "auth_error",
            "Authorization failed. If from a guest module's secrets call, run test_secret_access to identify whether the capability_world, allowed_secrets, or reserved-host gate failed.",
        )
    } else if lower.contains("postgres")
        || lower.contains("sqlite")
        || lower.contains("sql error")
        || lower.contains("database error")
        || lower.contains("connection pool")
    {
        ("database_error", "A database operation failed.")
    } else {
        (
            "runtime_error",
            "An unexpected runtime error occurred inside the module.",
        )
    }
}

/// Remediation-step playbook per error bucket. Strings preserved
/// verbatim from the pre-extraction handler.
pub fn remediation_steps(error_type: &str, module_label: &str) -> Vec<serde_json::Value> {
    match error_type {
        "output_schema_violation" => vec![
            serde_json::json!({ "step": 1, "action": "inspect_response", "description": format!("Pull the full LLM response that was rejected for node '{}' — get_execution_logs surfaces the model's literal output so you can see exactly which fence/prose form it returned.", module_label), "tool": "get_execution_logs" }),
            serde_json::json!({ "step": 2, "action": "tighten_system_prompt", "description": "Update the node's SYSTEM_PROMPT config to instruct STRICT JSON output: 'Output STRICT JSON with EXACTLY these top-level keys: …. No prose outside the JSON. No markdown code fence around the JSON.' Use update_node_config with the new prompt.", "tool": "update_node_config" }),
            serde_json::json!({ "step": 3, "action": "lower_temperature", "description": "If the model intermittently lapses into prose, drop TEMPERATURE to 0 (or as low as the model supports) to make schema-conformant output deterministic.", "tool": "update_node_config" }),
            serde_json::json!({ "step": 4, "action": "retry", "description": "Retry the execution after the prompt change. SCHEMA enforcement is best-effort defence; a tightened prompt usually fixes it without needing schema relaxation.", "tool": "retry_execution" }),
        ],
        "host_not_allowed" => vec![
            serde_json::json!({ "step": 1, "action": "identify_target_host", "description": format!("Inspect node '{}' source code or HTTP request URL — find the hostname it tried to reach.", module_label), "tool": "get_module_info" }),
            serde_json::json!({ "step": 2, "action": "extend_allowed_hosts", "description": "Recompile the module via hot_update_module (NOT update_node_config — allowed_hosts is a module-level setting baked at compile time). Add the host to allowed_hosts. Use ['*'] to allow all hosts (not recommended for production).", "tool": "hot_update_module" }),
            serde_json::json!({ "step": 3, "action": "retry", "description": "Retry the execution after the module recompiles.", "tool": "retry_execution" }),
        ],
        "module_compile_error" => vec![
            serde_json::json!({ "step": 1, "action": "review_error", "description": "Read the compiler error in raw_error — rustc errors include line numbers.", "tool": null }),
            serde_json::json!({ "step": 2, "action": "lint_first", "description": "Run lint_sandbox on the new source code (~3s) to catch type errors before paying the 30-60s compile.", "tool": "lint_sandbox" }),
            serde_json::json!({ "step": 3, "action": "scaffold", "description": "Compare against the canonical scaffold to spot drift.", "tool": "get_rust_scaffold" }),
        ],
        "json_parse" => vec![
            serde_json::json!({ "step": 1, "action": "inspect_input", "description": format!("Get the actual input shape that reached node '{}' — the parser expected something different.", module_label), "tool": "get_node_io" }),
            serde_json::json!({ "step": 2, "action": "check_upstream", "description": "Trace which upstream node produced this output — the shape may have changed silently.", "tool": "get_execution_status" }),
            serde_json::json!({ "step": 3, "action": "fix_parser", "description": "Either change the module's parser to match the actual shape, or fix upstream to emit the expected shape. Untyped serde_json::Value is more forgiving but burns 3-10x more fuel — use typed structs for hot paths.", "tool": null }),
        ],
        "fuel_exhausted" => vec![
            serde_json::json!({ "step": 1, "action": "estimate_payload", "description": format!("How big is the input to node '{}'? Each KB costs ~2 fuel; 60K per item baseline.", module_label), "tool": "get_node_io" }),
            serde_json::json!({ "step": 2, "action": "bump_fuel", "description": "hot_update_module with fuel_budget: {expected_items, bytes_per_item, llm_output_bytes ≈ 3000 for LLM nodes, safety_multiplier: 2.0-3.0} — formula clamps to [1M, 50M].", "tool": "hot_update_module" }),
            serde_json::json!({ "step": 3, "action": "switch_to_typed", "description": "If the module uses serde_json::Value parsing on a large payload, switching to typed #[derive(Deserialize)] structs is 3-10x cheaper than bumping fuel.", "tool": null }),
        ],
        "timeout" => vec![
            serde_json::json!({ "step": 1, "action": "review_timeout", "description": format!("Check the timeout_secs setting on node '{}'.", module_label), "tool": "get_workflow_raw_json" }),
            serde_json::json!({ "step": 2, "action": "bump_timeout", "description": "Re-add the node with a higher timeout_secs (default 60). LLM nodes typically need 30-90s; large HTTP fetches 30-60s; expensive SQL 60-120s.", "tool": "add_node_to_workflow" }),
            serde_json::json!({ "step": 3, "action": "split_work", "description": "If the timeout reflects genuine workload size (e.g., processing 1000 items), consider splitting into a loop or fan-out/fan-in pattern so each node has bounded work.", "tool": null }),
        ],
        "http_401" => vec![
            serde_json::json!({ "step": 1, "action": "verify_secret_present", "description": format!("Check that the credential node '{}' uses still exists in the vault.", module_label), "tool": "list_secrets" }),
            serde_json::json!({ "step": 2, "action": "test_secret_access", "description": "Run test_secret_access(module_id, secret_path) to confirm the module is allowed to read it.", "tool": "test_secret_access" }),
            serde_json::json!({ "step": 3, "action": "rotate", "description": "If the credential is present and allowed but still 401s, the upstream key has expired or been revoked. Rotate the secret in the dashboard (Settings → Secrets) — secret writes require 2FA and aren't available through MCP.", "tool": null }),
        ],
        "http_403" => vec![
            serde_json::json!({ "step": 1, "action": "check_scopes", "description": "403 means authn worked but the credential lacks the required scope/permission. Check the upstream API's docs for the operation's required scopes.", "tool": null }),
            serde_json::json!({ "step": 2, "action": "regenerate_token", "description": "If the scopes look right but the API disagrees, regenerate the token with the necessary scopes selected, then update the value in the dashboard (Settings → Secrets) — secret writes require 2FA and aren't available through MCP.", "tool": null }),
        ],
        "http_404" => vec![
            serde_json::json!({ "step": 1, "action": "verify_endpoint", "description": format!("Inspect node '{}' source — confirm the URL/path is correct. 404 often means a typo or stale resource id.", module_label), "tool": "get_module_info" }),
            serde_json::json!({ "step": 2, "action": "check_input", "description": "If the URL is templated from upstream input (e.g. /repos/{owner}/{repo}), the upstream may have produced a wrong/missing field.", "tool": "get_node_io" }),
        ],
        "http_5xx" => vec![
            serde_json::json!({ "step": 1, "action": "wait_and_retry", "description": "5xx is almost always upstream-side; the API is unhealthy or overloaded. Wait a minute and retry.", "tool": "retry_execution" }),
            serde_json::json!({ "step": 2, "action": "check_status_page", "description": "Check the upstream provider's status page (if any) for an ongoing incident before debugging your code.", "tool": null }),
            serde_json::json!({ "step": 3, "action": "tighten_retries", "description": "If 5xx is recurring, set retry_count: 3 and retry_backoff_ms: 2000 on the node so transient failures self-heal.", "tool": "add_node_to_workflow" }),
        ],
        "missing_secret" => vec![
            serde_json::json!({ "step": 1, "action": "identify_secret", "description": format!("Check which secret key_path node '{}' expects — use get_workflow_quickstart to list required secrets.", module_label), "tool": "get_workflow_quickstart" }),
            serde_json::json!({ "step": 2, "action": "test_gates", "description": "test_secret_access(module_id, secret_path) tells you whether the path is in the vault, in the allowlist, and within the capability world — all in one call.", "tool": "test_secret_access" }),
            serde_json::json!({ "step": 3, "action": "provision_secret", "description": "Store the credential in the dashboard (Settings → Secrets) using the correct key_path — secret writes require 2FA and aren't available through MCP.", "tool": null }),
            serde_json::json!({ "step": 4, "action": "retry", "description": "Retry the execution after provisioning the secret.", "tool": "retry_execution" }),
        ],
        "rate_limit" => vec![
            serde_json::json!({ "step": 1, "action": "check_rate_limit", "description": format!("Review the rate limit setting for node '{}' and the external API's limits.", module_label), "tool": "get_module_rate_limit" }),
            serde_json::json!({ "step": 2, "action": "adjust_rate_limit", "description": "Lower requests_per_minute with set_module_rate_limit or add a delay between executions.", "tool": "set_module_rate_limit" }),
            serde_json::json!({ "step": 3, "action": "retry", "description": "Wait for the rate limit window to reset, then retry.", "tool": "retry_execution" }),
        ],
        "wasm_trap" => vec![
            serde_json::json!({ "step": 1, "action": "increase_fuel", "description": "Increase WASM_FUEL_LIMIT env var or set a higher per-node timeout if the module was cut off mid-processing.", "tool": null }),
            serde_json::json!({ "step": 2, "action": "check_input_size", "description": "Large input payloads can exhaust fuel — verify the data passed to this node is reasonably sized.", "tool": "get_node_output" }),
            serde_json::json!({ "step": 3, "action": "test_sandbox", "description": "Test the module in isolation with run_sandbox to reproduce the trap with a minimal input.", "tool": "run_sandbox" }),
        ],
        "network_error" => vec![
            serde_json::json!({ "step": 1, "action": "check_connectivity", "description": format!("Verify the external service node '{}' connects to is reachable from the worker.", module_label), "tool": null }),
            serde_json::json!({ "step": 2, "action": "check_allowed_hosts", "description": "Ensure the module's allowed_hosts list includes the target domain.", "tool": "get_module_info" }),
            serde_json::json!({ "step": 3, "action": "retry", "description": "If the outage is transient, retry the execution.", "tool": "retry_execution" }),
        ],
        "config_error" => vec![
            serde_json::json!({ "step": 1, "action": "check_config", "description": format!("Review the config for node '{}' — a required field may be missing or set to an incorrect type.", module_label), "tool": "get_workflow_quickstart" }),
            serde_json::json!({ "step": 2, "action": "update_config", "description": "Set the missing config key with update_node_config.", "tool": "update_node_config" }),
            serde_json::json!({ "step": 3, "action": "test", "description": "Re-test the workflow after fixing the config.", "tool": "test_workflow_draft" }),
        ],
        "auth_error" => vec![
            serde_json::json!({ "step": 1, "action": "test_secret_gates", "description": format!("If node '{}' calls secrets::get_secret directly, run test_secret_access(module_id, secret_path) — it reports which of the four gates failed (capability_world, allowed_secrets, reserved-host, vault presence) without needing a redeploy.", module_label), "tool": "test_secret_access" }),
            serde_json::json!({ "step": 2, "action": "check_secret", "description": "If this is a vault:// header substitution, verify the secret is still present and not expired.", "tool": "list_secrets" }),
            serde_json::json!({ "step": 3, "action": "re_provision_secret", "description": "Generate a new token/key and update the secret in the dashboard (Settings → Secrets) — secret writes require 2FA and aren't available through MCP.", "tool": null }),
            serde_json::json!({ "step": 4, "action": "retry", "description": "Retry after updating the credential.", "tool": "retry_execution" }),
        ],
        "database_error" => vec![
            serde_json::json!({ "step": 1, "action": "check_connection", "description": format!("Verify the database connection URL secret used by node '{}' is correct and the DB is reachable.", module_label), "tool": null }),
            serde_json::json!({ "step": 2, "action": "check_secret", "description": "Confirm the database/connection_url secret is provisioned (via the dashboard Settings → Secrets — secret writes require 2FA and aren't available through MCP).", "tool": null }),
            serde_json::json!({ "step": 3, "action": "retry", "description": "Retry after fixing the connection.", "tool": "retry_execution" }),
        ],
        _ => vec![
            serde_json::json!({ "step": 1, "action": "inspect_logs", "description": format!("Review the full error message for node '{}' in get_execution_logs.", module_label), "tool": "get_execution_logs" }),
            serde_json::json!({ "step": 2, "action": "trace", "description": "Use get_execution_status(detail: true) for a full data-flow view of what succeeded before the failure.", "tool": "get_execution_status" }),
            serde_json::json!({ "step": 3, "action": "test_sandbox", "description": "Reproduce in isolation using run_sandbox with the same input data.", "tool": "run_sandbox" }),
        ],
    }
}

/// Extract a config field name from a config-error message. Returns
/// `None` when no known pattern matches.
pub fn extract_config_field(raw_error: &str) -> Option<String> {
    // Try to extract field name from patterns like:
    //   "missing field 'FIELD'"  — sqlx / serde style
    //   "Missing 'FIELD' in config" — module runtime style (most common in practice)
    //   "required field 'FIELD'"
    //   "invalid config key 'FIELD'"
    // All comparisons are case-insensitive; indexing into the original string is safe
    // because all matched characters are ASCII and byte-lengths match.
    //
    // MCP-1138: cap input before to_lowercase + repeated .find scans.
    // Same anti-pattern + cap as `classify_error` above and the
    // MCP-1135 sibling in talos_retry_intelligence. Field-extraction
    // tokens live in the first paragraph by construction; if a
    // pathological 1 MB raw_error buries the field past 4 KiB, we
    // return None and the operator falls through to the manual fix
    // path — same trade-off MCP-1135 made.
    let raw_error = truncate_for_classify(raw_error);
    let patterns = [
        "missing '",
        "missing field '",
        "missing field \"",
        "required field '",
        "required field \"",
        "invalid config key '",
        "invalid config key \"",
    ];
    let lower = raw_error.to_lowercase();
    for pat in &patterns {
        if let Some(start) = lower.find(pat) {
            let after = &raw_error[start + pat.len()..];
            let end = after.find(['\'', '"', ' ', ':']).unwrap_or(after.len());
            let field = after[..end].trim().to_string();
            if !field.is_empty() {
                return Some(field);
            }
        }
    }
    None
}

/// Auth-error auto-fix helper: extract the secret name referenced in an
/// auth-error message so the fix suggestion can name the row to touch.
pub fn extract_secret_name_from_auth_error(msg: &str) -> Option<String> {
    // MCP-1138: cap input before to_lowercase + repeated .find scans.
    // Same anti-pattern + cap as sibling `classify_error` /
    // `extract_config_field` above. Secret-name tokens live in the
    // first paragraph of an auth error; tradeoff matches MCP-1135.
    let msg = truncate_for_classify(msg);
    let lower = msg.to_lowercase();
    for pattern in &["secret '", "key '", "token '", "credential '"] {
        if let Some(start) = lower.find(pattern) {
            let after = &msg[start + pattern.len()..];
            let end = after.find(['\'', '"', ':', ' ']).unwrap_or(0);
            if end > 0 {
                let name = after[..end].trim().to_string();
                if !name.is_empty() {
                    return Some(name);
                }
            }
        }
    }
    None
}

/// Build a `SHA256-derived-UUID → display label` map from a workflow's
/// `graph_json`. `execution_events.node_id` is a SHA256-derived UUID
/// (graph nodes use string ids like `"node-1"`); the label resolved via
/// `node.data.label` is the safe bridge back to human-readable names.
pub fn build_node_display_label_map(
    graph_str: Option<String>,
) -> std::collections::HashMap<Uuid, String> {
    let mut map = std::collections::HashMap::new();
    if let Some(gj) = graph_str {
        if let Ok(graph) = serde_json::from_str::<serde_json::Value>(&gj) {
            if let Some(nodes) = graph.get("nodes").and_then(|n| n.as_array()) {
                for node in nodes {
                    if let Some(rf_id) = node.get("id").and_then(|v| v.as_str()) {
                        let node_uuid = Uuid::parse_str(rf_id).unwrap_or_else(|_| {
                            use sha2::{Digest, Sha256};
                            let hash = Sha256::digest(rf_id.as_bytes());
                            let mut bytes = [0u8; 16];
                            bytes.copy_from_slice(&hash[..16]);
                            Uuid::from_bytes(bytes)
                        });
                        let label = node
                            .get("data")
                            .and_then(|d| d.get("label"))
                            .and_then(|l| l.as_str())
                            .unwrap_or(rf_id)
                            .to_string();
                        map.insert(node_uuid, label);
                    }
                }
            }
        }
    }
    map
}

fn json_optional_string(obj: &serde_json::Value, field: &str) -> Option<String> {
    obj.get(field).and_then(|v| v.as_str()).map(String::from)
}

// -----------------------------------------------------------------------------
// Service
// -----------------------------------------------------------------------------

/// Failure-analysis orchestration. One shared instance backs the MCP
/// `analyze_execution_failure` tool and is ready to back a future
/// GraphQL surface — same Arc, same classification + fix flow.
pub struct FailureAnalysisService {
    execution_repo: Arc<ExecutionRepository>,
}

impl FailureAnalysisService {
    pub fn new(execution_repo: Arc<ExecutionRepository>) -> Self {
        Self { execution_repo }
    }

    /// Analyze a failed/cancelled execution: per-node diagnoses with
    /// remediation playbooks, optional config-field auto-fix, and
    /// auth-error fix suggestions. Report shape preserved byte-for-byte
    /// from the pre-extraction handler.
    pub async fn analyze(
        &self,
        input: AnalyzeFailureInput,
    ) -> Result<AnalyzeFailureOutcome, FailureAnalysisError> {
        let AnalyzeFailureInput {
            execution_id: exec_id,
            user_id,
            apply_fix,
            auto_retry,
        } = input;

        // ── Fetch execution record ───────────────────────────────────────────
        let exec = match self.execution_repo.get_execution(exec_id, user_id).await {
            Ok(Some(e)) => e,
            Ok(None) => return Err(FailureAnalysisError::NotFound),
            Err(e) => {
                tracing::error!("analyze_execution_failure fetch failed: {}", e);
                return Err(FailureAnalysisError::ExecutionFetch(e));
            }
        };

        let status = exec.status.clone();
        let global_error = exec.error_message.clone();
        let workflow_id = exec.workflow_id;

        if status != "failed" && status != "cancelled" {
            return Err(FailureAnalysisError::NotAnalyzable { status });
        }

        // ── Build UUID→label map from workflow graph_json ────────────────────
        // SECURITY: use get_workflow_graph_for_user to enforce user_id constraint.
        let graph_str = self
            .execution_repo
            .get_workflow_graph_for_user(workflow_id, user_id)
            .await
            .ok()
            .flatten();
        let node_labels = build_node_display_label_map(graph_str);

        // ── Fetch node_failed events ─────────────────────────────────────────
        let all_events = match self.execution_repo.list_execution_events(exec_id).await {
            Ok(evs) => evs,
            Err(e) => {
                tracing::error!("analyze_execution_failure events fetch failed: {}", e);
                return Err(FailureAnalysisError::EventsFetch(e));
            }
        };
        let events: Vec<_> = all_events
            .into_iter()
            .filter(|e| e.event_type == "node_failed")
            .collect();

        // ── Build per-node diagnoses ─────────────────────────────────────────
        let mut failed_nodes: Vec<serde_json::Value> = Vec::new();
        for ev in &events {
            let raw_node_id = ev.node_id;
            let node_id_str = raw_node_id
                .map(|u| u.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            let label = raw_node_id
                .and_then(|u| node_labels.get(&u).cloned())
                .unwrap_or_else(|| node_id_str.clone());
            let error_text = ev
                .log_message
                .as_deref()
                .unwrap_or("(no error message recorded)");

            let (error_type, description) = classify_error(error_text);
            let steps = remediation_steps(error_type, &label);

            // Surface the engine-stamped failure class alongside our string-regex
            // classification. They answer different questions:
            //   - `engine_error_class` ("non-transient", "transient", classifier
            //     tags like "not_found") tells callers WHY retries were / weren't
            //     attempted — authoritative, populated by the NATS dispatcher.
            //   - `error_type` (ours, regex-based) classifies into user-actionable
            //     buckets (missing_secret / rate_limit / wasm_trap / etc.) with
            //     matching remediation_steps.
            // Both being present lets agents pick whichever signal they need.
            let mut failed_node = serde_json::json!({
                "node_id": node_id_str,
                "label": label,
                "error_type": error_type,
                "error_description": description,
                "raw_error": error_text,
                "remediation_steps": steps,
            });
            if let Some(ref ec) = ev.error_class {
                if let Some(obj) = failed_node.as_object_mut() {
                    obj.insert("engine_error_class".to_string(), serde_json::json!(ec));
                }
            }

            // Fuel-exhaustion advisor (2026-07-18 retrospective): the
            // generic playbook explains the fuel FORMULA but never told
            // the operator what number to SET — even though the platform
            // records actual consumption per successful run in
            // `execution_cost_rollup`. When history exists, attach it plus
            // a concrete recommendation: 1.5× the observed max (headroom
            // for payload growth), floored at 2× the median, rounded up
            // to 100K, clamped to the platform's [1M, 50M] fuel window.
            // Best-effort — a history-query error never degrades the
            // analysis itself.
            if error_type == "fuel_exhausted" {
                if let Ok(Some((runs, p50, max_seen))) = self
                    .execution_repo
                    .node_fuel_history(workflow_id, &label, user_id, 30)
                    .await
                {
                    let raw = ((max_seen as f64) * 1.5).max((p50 as f64) * 2.0) as i64;
                    let recommended = ((raw + 99_999) / 100_000) * 100_000;
                    let recommended = recommended.clamp(1_000_000, 50_000_000);
                    if let Some(obj) = failed_node.as_object_mut() {
                        obj.insert(
                            "fuel_history".to_string(),
                            serde_json::json!({
                                "successful_runs_30d": runs,
                                "p50_fuel": p50,
                                "max_fuel_observed": max_seen,
                                "recommended_max_fuel": recommended,
                                "note": format!(
                                    "Successful runs of '{label}' consumed up to {max_seen} fuel \
                                     (median {p50}) in the last 30 days. Set max_fuel to \
                                     ~{recommended} via update_node_config (node-level, wins over \
                                     the module default) or hot_update_module with fuel_budget."
                                ),
                            }),
                        );
                    }
                }
            }
            failed_nodes.push(failed_node);
        }

        // If no failed node events but execution failed (e.g. workflow-level error), use global error
        if failed_nodes.is_empty() {
            let error_text = global_error
                .as_deref()
                .unwrap_or("(no error details available)");
            let (error_type, description) = classify_error(error_text);
            let steps = remediation_steps(error_type, "workflow");
            failed_nodes.push(serde_json::json!({
                "node_id": null,
                "label": "workflow-level",
                "error_type": error_type,
                "error_description": description,
                "raw_error": error_text,
                "remediation_steps": steps,
            }));
        }

        // Find first config_error node with an extractable field
        // Capture (node_id_uuid_str, node_label, field) — node_label is the reliable match key
        // because execution_events.node_id is a SHA256-derived UUID, not the graph node string id.
        let apply_fix_candidate = failed_nodes.iter().find_map(|n| {
            if n.get("error_type").and_then(|v| v.as_str()) == Some("config_error") {
                let raw = n.get("raw_error").and_then(|v| v.as_str()).unwrap_or("");
                let node_id = json_optional_string(n, "node_id");
                let node_label = json_optional_string(n, "label");
                if let Some(field) = extract_config_field(raw) {
                    return Some((node_id, node_label, field));
                }
            }
            None
        });

        let apply_fix_available = apply_fix_candidate.is_some();
        let mut fix_result: Option<serde_json::Value> = None;

        if apply_fix && apply_fix_available {
            if let Some((failed_node_id_opt, failed_node_label, field_name)) = &apply_fix_candidate
            {
                // Load graph_json (user-scoped)
                let graph_json_str = self
                    .execution_repo
                    .get_workflow_graph_for_user(workflow_id, user_id)
                    .await
                    .ok()
                    .flatten();

                if let Some(graph_json_str) = graph_json_str {
                    let mut graph: serde_json::Value = serde_json::from_str(&graph_json_str)
                        .unwrap_or(serde_json::json!({"nodes":[],"edges":[]}));

                    // Match by label (reliable) or fallback to UUID id string.
                    // execution_events.node_id is a SHA256-derived UUID; graph nodes use string ids
                    // like "node-1". The label is resolved via node_labels map and is the safe bridge.
                    let mut patched = false;
                    if let Some(nodes) = graph.get_mut("nodes").and_then(|n| n.as_array_mut()) {
                        for node in nodes.iter_mut() {
                            let nid = node.get("id").and_then(|v| v.as_str()).unwrap_or("");
                            let nlabel = node
                                .get("data")
                                .and_then(|d| d.get("label"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            let label_match = failed_node_label
                                .as_deref()
                                .map(|l| l == nlabel)
                                .unwrap_or(false);
                            let id_match = failed_node_id_opt
                                .as_deref()
                                .map(|fid| fid == nid)
                                .unwrap_or(false);
                            if label_match || id_match {
                                if let Some(data) = node.get_mut("data") {
                                    // Set to empty string as a placeholder — user must still fill the value
                                    if data.get(field_name).is_none() || data[field_name].is_null()
                                    {
                                        data[field_name] = serde_json::json!("");
                                        patched = true;
                                    }
                                }
                                break;
                            }
                        }
                    }

                    let patched_node_display = failed_node_label
                        .as_deref()
                        .or(failed_node_id_opt.as_deref())
                        .unwrap_or("unknown");

                    if patched {
                        let updated_json = graph.to_string();
                        // MCP-1227 (2026-05-18): mirror the MCP-1226 chokepoint
                        // for this auto-fix write path. `analyze_execution_failure`
                        // can only stamp a single field with `""` (no caller-
                        // injected number that could violate caps), so the
                        // only way validation fails is if the legacy graph
                        // already has over-cap timeouts/retries. Surface that
                        // as `fix_applied: false` with the validator's
                        // pointer at the offending field — operator must
                        // hand-edit the legacy values before the auto-fix
                        // can land. Sibling defense-in-depth posture to
                        // `rollback_workflow` (versions.rs).
                        if let Err(cap_msg) =
                            talos_workflow_types::validate_graph_timeouts(&updated_json)
                        {
                            fix_result = Some(serde_json::json!({
                                "fix_applied": false,
                                "error": format!(
                                    "Existing workflow graph violates per-node / per-loop / per-retry caps; auto-fix refused. Edit the offending node by hand. Detail: {}",
                                    cap_msg
                                ),
                            }));
                        } else {
                            let db_result = self
                                .execution_repo
                                .update_workflow_graph(workflow_id, user_id, &updated_json)
                                .await;
                            // MCP-882 (2026-05-14): log the underlying error
                            // before collapsing to the generic "Failed to save
                            // patched graph" response. Pre-fix `db_result.is_ok()`
                            // branched on bool without logging the sqlx error,
                            // so an operator running diagnose_and_fix_node_failure
                            // saw "fix_applied: false" with no signal whether
                            // the failure was a permission issue, FK violation,
                            // write timeout, or graph-JSON shape rejection.
                            // Operator-facing message stays generic; server log
                            // distinguishes the cause.
                            match db_result {
                                Ok(_) => {
                                    fix_result = Some(serde_json::json!({
                                        "fix_applied": true,
                                        "patched_node": patched_node_display,
                                        "patched_field": field_name,
                                        "retry_with_execution_id": exec_id.to_string(),
                                        "note": "Field initialized to empty string — call update_node_config to set the correct value, then retry."
                                    }));
                                }
                                Err(e) => {
                                    tracing::error!(
                                        workflow_id = %workflow_id,
                                        user_id = %user_id,
                                        error = %e,
                                        "handle_analyze_execution_failure: update_workflow_graph failed during auto-fix"
                                    );
                                    fix_result = Some(serde_json::json!({
                                        "fix_applied": false,
                                        "error": "Failed to save patched graph"
                                    }));
                                }
                            }
                        }
                    } else {
                        fix_result = Some(serde_json::json!({
                            "fix_applied": false,
                            "note": format!("Node '{}' or field '{}' not found in current graph", patched_node_display, field_name)
                        }));
                    }
                }
            }
        }

        // If auto_retry=true and fix was applied, spawn a background retry
        let auto_retry_triggered = auto_retry
            && fix_result
                .as_ref()
                .and_then(|f| f.get("fix_applied"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

        if auto_retry_triggered {
            tracing::info!(execution_id = %exec_id, "analyze_execution_failure: auto_retry requested after fix_applied");
        }

        // Auth-error auto-fix: when apply_fix=true and the primary failure is
        // auth_error, extract the secret name and surface it on the
        // `auth_fix_suggestion` payload so the operator knows which row to
        // touch. Pre-MCP-1201 this also pre-filled a `rotate_secret` MCP call;
        // post-MCP-1201 MCP is read-only for secrets, so the rotation happens
        // in the dashboard (Settings → Secrets) — the suggestion just names
        // the secret + describes the action.
        let auth_fix_suggestion: Option<serde_json::Value> = if apply_fix {
            failed_nodes.iter().find_map(|n| {
                let err_type = n.get("error_type").and_then(|v| v.as_str()).unwrap_or("");
                if err_type == "auth_error" || err_type == "missing_secret" {
                    let raw = n.get("raw_error").and_then(|v| v.as_str()).unwrap_or("");
                    let secret_name = extract_secret_name_from_auth_error(raw);
                    let is_missing = err_type == "missing_secret";
                    // MCP-1201 (2026-05-17): secret writes moved exclusively
                    // to the GraphQL surface (require_2fa + SecretsWrite).
                    // The auth-fix suggestion no longer carries an MCP
                    // `tool` + `prefilled_args` because no MCP tool can
                    // execute the fix. Returning the extracted secret name
                    // and a clear "do this in the dashboard" note keeps the
                    // diagnostic value (caller knows which secret to
                    // touch) while routing the actual mutation through the
                    // 2FA-gated path.
                    Some(serde_json::json!({
                        "fix_type": if is_missing { "provision_secret" } else { "rotate_secret" },
                        "tool": null,
                        "extracted_secret_name": secret_name,
                        "note": if let Some(ref sn) = secret_name {
                            if is_missing {
                                format!(
                                    "Secret '{}' was not found in the vault. Provision it in the dashboard (Settings → Secrets) using the key_path extracted from the error message — secret writes require 2FA and aren't available through MCP.",
                                    sn
                                )
                            } else {
                                format!(
                                    "Auth error detected for secret '{}'. Generate a fresh credential and rotate it in the dashboard (Settings → Secrets) — secret writes require 2FA and aren't available through MCP.",
                                    sn
                                )
                            }
                        } else {
                            "Credential reference found in error. Identify the secret name from raw_error and provision it in the dashboard (Settings → Secrets) — secret writes require 2FA and aren't available through MCP.".to_string()
                        }
                    }))
                } else {
                    None
                }
            })
        } else {
            None
        };

        let effective_fix_available = apply_fix_available || auth_fix_suggestion.is_some();
        let mut result = serde_json::json!({
            "execution_id": exec_id.to_string(),
            "workflow_id": workflow_id.to_string(),
            "status": status,
            "failed_node_count": failed_nodes.len(),
            "failed_nodes": failed_nodes,
            "global_error": global_error,
            "apply_fix_available": effective_fix_available,
            "tip": format!(
                "After applying fixes, call retry_execution with execution_id={}.",
                exec_id
            ),
        });

        if let Some(fix) = fix_result {
            result["fix_result"] = fix;
        }
        if let Some(auth_fix) = auth_fix_suggestion {
            result["auth_fix_suggestion"] = auth_fix;
        }
        if auto_retry_triggered {
            result["auto_retry_triggered"] = serde_json::json!(true);
            result["auto_retry_note"] = serde_json::json!(
                "Background retry has been enqueued. Call retry_execution explicitly to get the new execution_id."
            );
        }

        Ok(AnalyzeFailureOutcome { report: result })
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Error strings locked verbatim (r304 discipline) ────────────────────

    #[test]
    fn error_strings_locked_verbatim() {
        assert_eq!(
            FailureAnalysisError::NotFound.user_facing_message(),
            "Execution not found or access denied"
        );
        assert_eq!(
            FailureAnalysisError::NotAnalyzable {
                status: "running".to_string()
            }
            .user_facing_message(),
            "Execution status is 'running' — only failed or cancelled executions can be analyzed."
        );
        assert_eq!(
            FailureAnalysisError::ExecutionFetch(anyhow::anyhow!(
                "connection refused to db host 10.0.0.3"
            ))
            .user_facing_message(),
            "Database error fetching execution"
        );
        assert_eq!(
            FailureAnalysisError::EventsFetch(anyhow::anyhow!(
                "relation execution_events does not exist"
            ))
            .user_facing_message(),
            "Database error fetching execution events"
        );
    }

    #[test]
    fn internal_errors_never_leak_source_detail() {
        // The #[source] chain must not render through the user-facing
        // message — a sqlx error naming schema objects stays server-side.
        let err = FailureAnalysisError::ExecutionFetch(anyhow::anyhow!(
            "SELECT id FROM workflow_executions failed: column does_not_exist"
        ));
        let msg = err.user_facing_message();
        assert!(!msg.contains("SELECT"));
        assert!(!msg.contains("workflow_executions"));
        assert!(!msg.contains("column"));
    }

    #[test]
    fn jsonrpc_codes_stable() {
        assert_eq!(FailureAnalysisError::NotFound.jsonrpc_code(), -32000);
        assert_eq!(
            FailureAnalysisError::NotAnalyzable {
                status: "completed".into()
            }
            .jsonrpc_code(),
            -32000
        );
        assert_eq!(
            FailureAnalysisError::ExecutionFetch(anyhow::anyhow!("x")).jsonrpc_code(),
            -32000
        );
        assert_eq!(
            FailureAnalysisError::EventsFetch(anyhow::anyhow!("x")).jsonrpc_code(),
            -32000
        );
    }

    // ── classify_error buckets ──────────────────────────────────────────────

    #[test]
    fn classify_error_buckets() {
        assert_eq!(
            classify_error("OUTPUT_SCHEMA enforcement fired: required keys missing").0,
            "output_schema_violation"
        );
        assert_eq!(
            classify_error("ForbiddenHost: example.com").0,
            "host_not_allowed"
        );
        assert_eq!(
            classify_error("compilation failed at line 3").0,
            "module_compile_error"
        );
        assert_eq!(
            classify_error("invalid type: expected struct").0,
            "json_parse"
        );
        assert_eq!(
            classify_error("secret not found in vault").0,
            "missing_secret"
        );
        assert_eq!(classify_error("429 Too Many Requests").0, "rate_limit");
        assert_eq!(
            classify_error("out of fuel after 5M ops").0,
            "fuel_exhausted"
        );
        assert_eq!(classify_error("wasm trap: unreachable").0, "wasm_trap");
        assert_eq!(classify_error("deadline exceeded").0, "timeout");
        assert_eq!(classify_error("connection refused").0, "network_error");
        // NOTE: the module-runtime form "Missing 'X' in config" does NOT
        // hit the config_error bucket (classify_error has no "missing '"
        // gate — only extract_config_field does). Locked as-is: changing
        // the bucket would change which failures offer the auto-fix.
        assert_eq!(
            classify_error("Missing 'AUTH_HEADER' in config").0,
            "runtime_error"
        );
        assert_eq!(
            classify_error("missing field 'AUTH_HEADER'").0,
            "config_error"
        );
        assert_eq!(classify_error("HTTP 401 invalid token").0, "http_401");
        assert_eq!(classify_error("403 Forbidden").0, "http_403");
        assert_eq!(classify_error("404 endpoint missing").0, "http_404");
        assert_eq!(classify_error("502 bad gateway").0, "http_5xx");
        assert_eq!(classify_error("Unauthorized").0, "auth_error");
        assert_eq!(
            classify_error("postgres pool exhausted").0,
            "database_error"
        );
        assert_eq!(classify_error("something inexplicable").0, "runtime_error");
    }

    #[test]
    fn classify_error_descriptions_locked() {
        assert_eq!(
            classify_error("secret not found").1,
            "A required secret credential was not found in the vault."
        );
        assert_eq!(
            classify_error("something inexplicable").1,
            "An unexpected runtime error occurred inside the module."
        );
        assert_eq!(
            classify_error("missing field 'X'").1,
            "A required configuration field is missing or invalid."
        );
    }

    #[test]
    fn classify_specificity_order_forbiddenhost_beats_403() {
        // "forbidden" appears in ForbiddenHost but the host gate is more
        // specific and must win (the http_403 arm explicitly excludes it).
        assert_eq!(classify_error("ForbiddenHost").0, "host_not_allowed");
    }

    // ── truncate_for_classify ───────────────────────────────────────────────

    #[test]
    fn truncate_respects_char_boundaries() {
        // Multi-byte char straddling the 4096 boundary must not panic.
        let mut s = "a".repeat(4095);
        s.push('é'); // 2-byte char at offset 4095..4097
        s.push_str(&"b".repeat(100));
        let t = truncate_for_classify(&s);
        assert!(t.len() <= 4096);
        assert!(t.is_char_boundary(t.len()));
    }

    #[test]
    fn truncate_noop_under_cap() {
        assert_eq!(truncate_for_classify("short"), "short");
    }

    #[test]
    fn classify_ignores_tokens_buried_past_cap() {
        let mut s = "x".repeat(5000);
        s.push_str("out of fuel");
        assert_eq!(classify_error(&s).0, "runtime_error");
    }

    // ── extract_config_field ────────────────────────────────────────────────

    #[test]
    fn extract_config_field_patterns() {
        assert_eq!(
            extract_config_field("Missing 'AUTH_HEADER' in config"),
            Some("AUTH_HEADER".to_string())
        );
        assert_eq!(
            extract_config_field("missing field 'url'"),
            Some("url".to_string())
        );
        assert_eq!(
            extract_config_field("required field \"api_key\" absent"),
            Some("api_key".to_string())
        );
        assert_eq!(
            extract_config_field("invalid config key 'TIMEOUT'"),
            Some("TIMEOUT".to_string())
        );
        assert_eq!(extract_config_field("no recognizable pattern here"), None);
    }

    // ── extract_secret_name_from_auth_error ─────────────────────────────────

    #[test]
    fn extract_secret_name_patterns() {
        assert_eq!(
            extract_secret_name_from_auth_error("secret 'github/token' not found"),
            Some("github/token".to_string())
        );
        assert_eq!(
            extract_secret_name_from_auth_error("key 'anthropic/api_key' rejected"),
            Some("anthropic/api_key".to_string())
        );
        assert_eq!(
            extract_secret_name_from_auth_error("credential 'jira' expired"),
            Some("jira".to_string())
        );
        assert_eq!(extract_secret_name_from_auth_error("no names here"), None);
    }

    // ── remediation_steps shape ─────────────────────────────────────────────

    #[test]
    fn remediation_steps_known_buckets_nonempty() {
        for bucket in [
            "output_schema_violation",
            "host_not_allowed",
            "module_compile_error",
            "json_parse",
            "fuel_exhausted",
            "timeout",
            "http_401",
            "http_403",
            "http_404",
            "http_5xx",
            "missing_secret",
            "rate_limit",
            "wasm_trap",
            "network_error",
            "config_error",
            "auth_error",
            "database_error",
            "runtime_error",
        ] {
            let steps = remediation_steps(bucket, "my-node");
            assert!(!steps.is_empty(), "bucket {bucket} has no steps");
            for (i, s) in steps.iter().enumerate() {
                assert_eq!(
                    s.get("step").and_then(|v| v.as_u64()),
                    Some(i as u64 + 1),
                    "bucket {bucket} step numbering broken"
                );
                assert!(s.get("description").is_some());
                assert!(s.get("action").is_some());
            }
        }
    }

    #[test]
    fn remediation_steps_interpolate_label() {
        let steps = remediation_steps("host_not_allowed", "fetch-node");
        let first = steps[0].get("description").unwrap().as_str().unwrap();
        assert!(first.contains("'fetch-node'"));
    }

    // ── build_node_display_label_map ────────────────────────────────────────

    #[test]
    fn label_map_uses_data_label_with_id_fallback() {
        let graph = serde_json::json!({
            "nodes": [
                { "id": "node-1", "data": { "label": "Fetch Issues" } },
                { "id": "node-2", "data": {} }
            ],
            "edges": []
        });
        let map = build_node_display_label_map(Some(graph.to_string()));
        assert_eq!(map.len(), 2);
        assert!(map.values().any(|v| v == "Fetch Issues"));
        assert!(map.values().any(|v| v == "node-2"));
    }

    #[test]
    fn label_map_sha256_derivation_matches_engine() {
        // "node-1" is not a UUID → SHA256-derived UUID from its bytes.
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest("node-1".as_bytes());
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&hash[..16]);
        let expected = Uuid::from_bytes(bytes);

        let graph = serde_json::json!({
            "nodes": [{ "id": "node-1", "data": { "label": "L" } }],
            "edges": []
        });
        let map = build_node_display_label_map(Some(graph.to_string()));
        assert_eq!(map.get(&expected).map(String::as_str), Some("L"));
    }

    #[test]
    fn label_map_empty_on_none_or_malformed() {
        assert!(build_node_display_label_map(None).is_empty());
        assert!(build_node_display_label_map(Some("not json".to_string())).is_empty());
    }
}
