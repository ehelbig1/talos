use super::types::{JsonRpcError, JsonRpcResponse};

// ============================================================================
// SECURITY: Dependency allowlist for compile_custom_sandbox
// ============================================================================
// `validate_dependencies` + `get_allowed_dependencies` were moved to
// `talos_compilation::dependency_allowlist` so the compilation pipeline
// owns its own allowlist. Re-exported here for back-compat with the
// `crate::utils::validate_dependencies` import path used by existing
// handlers and unit tests in `talos-mcp-handlers/src/tests.rs`.
pub use talos_compilation::dependency_allowlist::{
    get_allowed_dependencies, validate_dependencies,
};

/// Sanitize a template name into a valid MCP tool name.
/// MCP requires: `^[a-zA-Z0-9_-]{1,64}$`
pub fn sanitize_tool_name(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    // Truncate to fit within 64 chars (with room for "-v1" suffix)
    let max_len = 60;
    if sanitized.len() > max_len {
        sanitized[..max_len].to_string()
    } else {
        sanitized
    }
}

// -----------------------------------------------------------------------------
// Graph diff helper for MCP tools
// -----------------------------------------------------------------------------

/// Compute a JSON diff between two graph JSON strings. Used by MCP tool handlers.
pub fn compute_mcp_graph_diff(graph_a_str: &str, graph_b_str: &str) -> serde_json::Value {
    let graph_a: serde_json::Value =
        serde_json::from_str(graph_a_str).unwrap_or(serde_json::json!({"nodes":[],"edges":[]}));
    let graph_b: serde_json::Value =
        serde_json::from_str(graph_b_str).unwrap_or(serde_json::json!({"nodes":[],"edges":[]}));

    let nodes_a = graph_a
        .get("nodes")
        .and_then(|n| n.as_array())
        .cloned()
        .unwrap_or_default();
    let nodes_b = graph_b
        .get("nodes")
        .and_then(|n| n.as_array())
        .cloned()
        .unwrap_or_default();
    let edges_a = graph_a
        .get("edges")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default();
    let edges_b = graph_b
        .get("edges")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default();

    let nodes_a_map: std::collections::HashMap<String, &serde_json::Value> = nodes_a
        .iter()
        .filter_map(|n| {
            n.get("id")
                .and_then(|v| v.as_str())
                .map(|id| (id.to_string(), n))
        })
        .collect();
    let nodes_b_map: std::collections::HashMap<String, &serde_json::Value> = nodes_b
        .iter()
        .filter_map(|n| {
            n.get("id")
                .and_then(|v| v.as_str())
                .map(|id| (id.to_string(), n))
        })
        .collect();

    let mut nodes_added = 0i32;
    let mut nodes_removed = 0i32;
    let mut nodes_changed = 0i32;

    for id in nodes_b_map.keys() {
        if !nodes_a_map.contains_key(id) {
            nodes_added += 1;
        }
    }
    for id in nodes_a_map.keys() {
        if !nodes_b_map.contains_key(id) {
            nodes_removed += 1;
        }
    }
    for (id, node_a) in &nodes_a_map {
        if let Some(node_b) = nodes_b_map.get(id) {
            if node_a.get("type") != node_b.get("type") || node_a.get("data") != node_b.get("data")
            {
                nodes_changed += 1;
            }
        }
    }

    let edge_key = |e: &serde_json::Value| -> String {
        let src = e.get("source").and_then(|v| v.as_str()).unwrap_or("");
        let tgt = e.get("target").and_then(|v| v.as_str()).unwrap_or("");
        format!("{}->{}", src, tgt)
    };
    let edges_a_set: std::collections::HashSet<String> = edges_a.iter().map(edge_key).collect();
    let edges_b_set: std::collections::HashSet<String> = edges_b.iter().map(edge_key).collect();

    let edges_added = edges_b_set.difference(&edges_a_set).count() as i32;
    let edges_removed = edges_a_set.difference(&edges_b_set).count() as i32;

    let mut parts = Vec::new();
    if nodes_added > 0 {
        parts.push(format!("{} node(s) added", nodes_added));
    }
    if nodes_removed > 0 {
        parts.push(format!("{} node(s) removed", nodes_removed));
    }
    if nodes_changed > 0 {
        parts.push(format!("{} node(s) changed", nodes_changed));
    }
    if edges_added > 0 {
        parts.push(format!("{} edge(s) added", edges_added));
    }
    if edges_removed > 0 {
        parts.push(format!("{} edge(s) removed", edges_removed));
    }

    let summary = if parts.is_empty() {
        "No changes".to_string()
    } else {
        parts.join(", ")
    };

    serde_json::json!({
        "summary": summary,
        "nodes_added": nodes_added,
        "nodes_removed": nodes_removed,
        "nodes_changed": nodes_changed,
        "edges_added": edges_added,
        "edges_removed": edges_removed,
    })
}

/// Build a text summary from workflow metadata for search indexing.
/// Stored in `workflows.search_text` and matched via `ILIKE` / trigram.
pub fn generate_workflow_text_for_embedding(
    name: &str,
    description: Option<&str>,
    intent: Option<&serde_json::Value>,
    capabilities: &[String],
    node_names: &[String],
) -> String {
    let mut text = format!("Workflow: {}", name);
    if let Some(desc) = description {
        text.push_str(&format!(". {}", desc));
    }
    if let Some(intent) = intent {
        if let Some(action) = intent.get("action").and_then(|v| v.as_str()) {
            text.push_str(&format!(". Action: {}", action));
        }
        if let Some(subject) = intent.get("subject").and_then(|v| v.as_str()) {
            text.push_str(&format!(". Subject: {}", subject));
        }
        if let Some(ctx) = intent.get("trigger_context").and_then(|v| v.as_str()) {
            text.push_str(&format!(". Use when: {}", ctx));
        }
    }
    if !capabilities.is_empty() {
        text.push_str(&format!(". Capabilities: {}", capabilities.join(", ")));
    }
    if !node_names.is_empty() {
        text.push_str(&format!(". Nodes: {}", node_names.join(", ")));
    }
    text
}

/// Best-effort update of the `search_text` column for a workflow.
/// Loads current metadata from DB, builds the text summary, and stores it.
pub async fn update_workflow_search_text(
    db_pool: &sqlx::PgPool,
    workflow_id: uuid::Uuid,
    user_id: uuid::Uuid,
) {
    let repo = talos_workflow_repository::WorkflowRepository::new(db_pool.clone());
    let src = match repo
        .get_workflow_for_search_text_rebuild(workflow_id, user_id)
        .await
    {
        Ok(Some(s)) => s,
        _ => return,
    };

    // Extract node names from graph_json
    let node_names: Vec<String> = src
        .graph_json
        .and_then(|gj| serde_json::from_str::<serde_json::Value>(&gj).ok())
        .and_then(|g| g.get("nodes")?.as_array().cloned())
        .map(|nodes| {
            nodes
                .iter()
                .filter_map(|n| {
                    n.get("data")
                        .and_then(|d| d.get("label"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
                .collect()
        })
        .unwrap_or_default();

    let text = generate_workflow_text_for_embedding(
        &src.name,
        src.description.as_deref(),
        src.intent.as_ref(),
        &src.capabilities,
        &node_names,
    );

    // MCP-804 (2026-05-14): log set_workflow_search_text failures.
    // Pre-fix `let _ = ...await` silently dropped the Result so a
    // systematic DB UPDATE failure (pool exhaustion, schema drift on
    // the search_text column) caused fuzzy-search to silently drift
    // out of sync with workflow content. The function is documented
    // as "best-effort" so the public signature stays `()` and callers
    // continue not handling errors — operator visibility comes from
    // the WARN log only. Same operator-visibility class as
    // MCP-733..745/774-780.
    if let Err(e) = repo.set_workflow_search_text(workflow_id, &text).await {
        tracing::warn!(
            target: "talos_audit",
            workflow_id = %workflow_id,
            user_id = %user_id,
            error = %e,
            "update_workflow_search_text: UPDATE failed — search may drift out of sync with workflow content"
        );
    }
}

/// Serialize a value to JSON without serde_json's default HTML-entity escaping.
///
/// `serde_json::to_string` escapes `<`, `>`, `&`, and `'` to `\u003c`, `\u003e`,
/// `\u0026`, `\u0027` for XSS safety in HTML contexts. MCP is not an HTML context —
/// these escapes cause LLM clients to misinterpret responses containing Rust generics
/// (`HashMap<K, V>`) or other angle-bracket syntax, introducing literal `&lt;`/`&gt;`
/// into the code they send back on the next turn.
pub fn mcp_serialize<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value)
        .unwrap_or_default()
        .replace("\\u003c", "<")
        .replace("\\u003e", ">")
        .replace("\\u0026", "&")
        .replace("\\u0027", "'")
}

// SSRF guard moved to `talos_http_utils::ssrf` so engine-layer crates
// (talos-engine, etc.) can re-use it without depending on the MCP-handlers
// tree (a layering violation). Re-exported here for back-compat with
// existing `super::utils::check_outbound_url_no_ssrf` import sites.
pub use talos_http_utils::ssrf::check_outbound_url_no_ssrf;

/// Load the worker shared HMAC key, logging the error on failure.
///
/// Replaces the previous `talos_workflow_job_protocol::load_worker_shared_key().ok()`
/// pattern that silently dropped the error string. Behavior:
/// * Key loads → `Some(key)`.
/// * Key fails to load → `None` AND ERROR-level log so the failure is
///   visible in observability instead of becoming an invisible "jobs are
///   unsigned" regression.
///
/// The hard fail-closed in production happens downstream — every NATS
/// dispatch path runs through `talos_engine::nats_run::run_with_trigger_input_via_nats`,
/// which refuses to dispatch with `None` when `RUST_ENV=production`. This
/// helper centralizes the load+log so call-sites stay one-liners.
pub fn load_worker_shared_key_logged(
    operation: &str,
) -> Option<talos_workflow_engine_core::WorkerSharedKey> {
    match talos_workflow_job_protocol::load_worker_shared_key() {
        Ok(key) => Some(key),
        Err(reason) => {
            tracing::error!(
                operation,
                reason,
                "WORKER_SHARED_KEY load failed; downstream dispatch refuses to send \
                 unsigned jobs in production. Generate one via `openssl rand -hex 32` \
                 and set WORKER_SHARED_KEY (or WORKER_SHARED_KEY_FILE) in the controller \
                 deployment."
            );
            None
        }
    }
}

// MCP response helpers — re-exported from `talos-mcp` so callers retain
// the existing `crate::utils::{mcp_error, mcp_text}` import path
// while the canonical implementation lives in the shared crate.
pub use talos_mcp::{mcp_error, mcp_text};

/// Map a `talos_execution_orchestration::OrchestrationError` to a
/// JSON-RPC error response with the canonical user-facing message
/// for each variant.
///
/// The service crate's `Display` impls produce neutral, protocol-
/// agnostic strings (e.g. "workflow execution is currently paused at
/// the platform level"); the handler layer renders the longer
/// historical messages that mention the MCP tool to call next ("Use
/// resume_executions to re-enable.") so callers see byte-identical
/// text to the pre-extraction inline handlers.
/// MCP-1226 (2026-05-18): cross-handler chokepoint that validates
/// graph_json against the canonical
/// `talos_workflow_types::validate_graph_timeouts` caps before any
/// MCP write path persists it. Originally lived in `graph.rs` as a
/// private helper used by `save_graph_json` / `save_graph_json_unchecked`;
/// promoted here so `set_workflow_priority` (configuration.rs) and
/// `rollback_workflow` (versions.rs) can call it without depending on
/// `graph.rs`. Those two paths write graph_json through
/// `update_workflow_graph_json` instead of `save_graph_json` so they
/// bypass the graph.rs chokepoint. The promotion keeps the canonical
/// validator a single import-everywhere call, mirroring the `push
/// validator into the canonical helper` pattern (MCP-1224 for
/// memory_key, MCP-1225 for memory_type enum).
pub fn ensure_graph_within_caps(
    graph_json: &str,
    req_id: &Option<serde_json::Value>,
) -> Result<(), super::types::JsonRpcResponse> {
    talos_workflow_types::validate_graph_timeouts(graph_json)
        .map_err(|msg| super::mcp_error(req_id.clone(), -32602, &msg))
}

pub fn orchestration_error_to_response(
    err: talos_execution_orchestration::OrchestrationError,
    req_id: Option<serde_json::Value>,
) -> super::types::JsonRpcResponse {
    use talos_execution_orchestration::OrchestrationError as E;
    let code = err.jsonrpc_code();
    let msg: String = match &err {
        E::ExecutionPaused => {
            "Execution queue is paused. Use resume_executions to re-enable.".to_string()
        }
        E::WorkflowDisabled(_) => {
            "Workflow is disabled. Use enable_workflow to re-enable.".to_string()
        }
        E::WorkflowNotFound(_) => "Workflow not found or access denied".to_string(),
        E::ExecutionNotFound(_) => "Execution not found or access denied".to_string(),
        E::StatusConflict(reason) => {
            // Reason already encodes "current status: X" (set by the
            // service); historical handler used the same body.
            reason.clone()
        }
        E::AuthorizationDenied(reason) => reason.clone(),
        E::ValidationFailed(reason) => format!("Input schema validation failed: {}", reason),
        E::ConcurrencyLimitExceeded(reason) => reason.clone(),
        E::DispatchFailed(reason) => reason.clone(),
        E::InvalidArgument(reason) => reason.clone(),
        // Workflow-definition error (empty/malformed graph) — surface the
        // actionable message verbatim; NOT a server-side failure, so no
        // ERROR log here (the message is already DLP-redacted upstream).
        E::GraphLoadFailed(reason) => reason.clone(),
        E::Database(_) | E::Internal(_) => {
            // Don't surface raw DB / engine error text to clients —
            // log full detail server-side, return a generic message.
            tracing::error!(error = %err, "orchestration: server-side failure");
            "Internal server error".to_string()
        }
    };
    mcp_error(req_id, code, &msg)
}

// ============================================================================
// Parameter-extraction helpers
// ============================================================================
//
// These helpers eliminate ~60+ duplicate inline match blocks across MCP
// handlers that all extracted UUIDs and strings the same way. Each helper
// returns `Result<T, JsonRpcResponse>` so callers can use `?` for concise
// dispatch:
//
//   let workflow_id = match require_uuid(&args, "workflow_id", req_id.clone()) {
//       Ok(id) => id,
//       Err(resp) => return resp,
//   };

/// Extract a required UUID from an args object. Returns an MCP error response
/// when the field is missing or not a valid UUID.
///
/// Replaces the pattern:
/// ```ignore
/// let workflow_id = match args.get("workflow_id")
///     .and_then(|v| v.as_str()).and_then(|s| s.parse().ok())
/// {
///     Some(id) => id,
///     None => return mcp_error(req_id, -32602, "Invalid or missing 'workflow_id'"),
/// };
/// ```
/// with:
/// ```ignore
/// let workflow_id = match require_uuid(args, "workflow_id", req_id.clone()) {
///     Ok(id) => id,
///     Err(resp) => return resp,
/// };
/// ```
pub fn require_uuid(
    args: &serde_json::Value,
    field: &str,
    req_id: Option<serde_json::Value>,
) -> Result<uuid::Uuid, JsonRpcResponse> {
    args.get(field)
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| mcp_error(req_id, -32602, &format!("Invalid or missing '{}'", field)))
}

/// Read an optional UUID from a JSON object's named field.
///
/// Sibling to [`require_uuid`] for cases where the field is genuinely
/// optional — returns `None` when the field is missing, non-string, or
/// fails UUID parsing. No error is reported because the caller can
/// distinguish "not provided" from "provided invalid" only if it cares
/// to (most don't).
///
/// Replaces the
/// `args.get(field).and_then(|v| v.as_str()).and_then(|s| Uuid::parse_str(s).ok())`
/// ritual that's paste-duplicated 20+ times across the handler tree.
pub fn optional_uuid(obj: &serde_json::Value, field: &str) -> Option<uuid::Uuid> {
    obj.get(field)
        .and_then(|v| v.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
}

/// MCP-309 (2026-05-11): strict-parse an OPTIONAL UUID field. Distinguishes
/// absent / null (`Ok(None)`) from wrong-type and invalid-UUID (`Err`).
///
/// Sibling to [`optional_uuid`] for cases where silent-drop hides operator
/// intent. The original `optional_uuid` returns `None` indistinguishably
/// for "field not provided" and "field provided but malformed", which is
/// fine for filter fields where dropping a typo'd filter just returns more
/// rows. It is NOT fine for fields like `continuation_workflow_id` on an
/// approval gate or workflow suspension: a typo silently drops the chain
/// so the gate resolves and nothing fires downstream. The operator only
/// notices later, when the continuation workflow never ran.
///
/// Use this when:
///   * the field is optional (caller can omit it), AND
///   * silent-drop changes behavior the operator cares about.
pub fn parse_optional_uuid_strict(
    args: &serde_json::Value,
    field: &str,
    req_id: &Option<serde_json::Value>,
) -> Result<Option<uuid::Uuid>, JsonRpcResponse> {
    match args.get(field) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => match v.as_str() {
            Some(s) => match s.parse::<uuid::Uuid>() {
                Ok(id) => Ok(Some(id)),
                Err(_) => Err(mcp_error(
                    req_id.clone(),
                    -32602,
                    &format!(
                        "'{field}' must be a valid UUID string, got '{}'",
                        talos_text_util::bounded_preview(s, 64)
                    ),
                )),
            },
            None => Err(mcp_error(
                req_id.clone(),
                -32602,
                &format!(
                    "'{field}' must be a UUID string, got {kind}",
                    kind = json_type_name(v)
                ),
            )),
        },
    }
}

/// Maximum allowed length for node_id parameters in MCP requests.
///
/// Kept as a shared constant so the length check in `require_node_id`
/// matches any other length-validating callers.  Applies to all node
/// identifier fields (`node_id`, `source_node_id`, `target_node_id`, etc.).
pub const MAX_NODE_ID_LENGTH: usize = 100;

// ============================================================================
// L T7-2: canonical input-size caps for MCP handler validation
// ============================================================================
//
// Pre-fix each handler enforced ad-hoc caps inline (`secrets.rs::set_secret`
// at 64 KiB, `sandbox.rs::compile_custom_sandbox` at 1 MB, others with no
// cap). Inconsistent caps create hidden DoS surface AND drift risk: caps
// that should match (e.g. all "description" fields) silently diverge.
//
// These constants mirror the shape of `talos-api/src/validation.rs`.
// Handlers that already cap inline keep working unchanged; new handlers
// (and audit-pass refactors) reach for these constants + the helpers
// below to stay consistent.

/// Max length for human-supplied resource names (workflow / actor / module).
/// Mirrors the GraphQL `validate_resource_name` cap so a name accepted by
/// one protocol is also accepted by the other.
pub const MAX_NAME_LENGTH: usize = 255;

/// Max length for human-supplied descriptions and short free-text fields.
pub const MAX_DESCRIPTION_LENGTH: usize = 10_000;

/// Max length for hierarchical key paths and slug-style identifiers
/// (e.g. `anthropic/api_key`, `slack/webhook/token`).
pub const MAX_KEY_PATH_LENGTH: usize = 500;

/// Max byte size for secret values, environment variable values, and
/// other "single secret" payloads. Aligns with the canonical
/// `talos_actor_memory_service::MAX_VALUE_BYTES` ceiling so secrets and
/// memory values share the same upper bound.
pub const MAX_SECRET_VALUE_BYTES: usize = 64 * 1024;

// MCP-1038 (2026-05-15): `MAX_CONFIG_BYTES` removed (it was 256 * 1024
// here, never referenced; the active `MAX_CONFIG_BYTES = 100_000` lives
// in `talos_hot_update_service::lib`, which is the only path that
// actually checks the config byte size). Same drift class as MCP-1002
// (BLOCKED_TABLES) / MCP-1019 (orphan fragment) / MCP-1037 (duplicate
// validate_payload_size): an unused-but-pub mirror of a real limit
// invites cargo-cult mismatch.

/// Max byte size for inline Rust source code passed to compile / sandbox
/// handlers. Matches the explicit limit already enforced in
/// `sandbox.rs::handle_run_sandbox` and `compile_custom_sandbox`.
///
/// MCP-1038 (2026-05-15): bumped 1_000_000 → 1_048_576 (1 MiB exact)
/// to match `talos_hot_update_service::MAX_RUST_CODE_BYTES`. Pre-fix,
/// the MCP path rejected at 1_000_001 while a hypothetical GraphQL
/// `hot_update_module` caller could submit up to 1_048_575 (the
/// service's defense-in-depth check binds for non-MCP paths). Aligned
/// to the larger value because 1 MiB is the conventional Rust source
/// limit and the service is the cross-protocol source of truth.
pub const MAX_RUST_CODE_BYTES: usize = 1_048_576;

/// MCP-1038 parity guard. Locks in alignment between the MCP-handler
/// early-exit cap and the cross-protocol service's binding cap so a
/// future bump in either crate's value fails to compile if the other
/// isn't updated.
const _MCP_1038_PARITY_GUARD: () = assert!(
    MAX_RUST_CODE_BYTES == talos_hot_update_service::MAX_RUST_CODE_BYTES,
    "MAX_RUST_CODE_BYTES drift between talos-mcp-handlers and talos-hot-update-service — \
     bump both crates' value or add a documented opt-out (MCP-1038)"
);

/// Validate an arbitrary string field against an explicit length cap.
/// Returns the validated reference on success, or a structured
/// MCP error response when the cap is exceeded. Use this from handlers
/// that need to bound a string AFTER another check has narrowed the
/// type (e.g., already-extracted `&str`).
pub fn validate_string_length<'a>(
    field: &str,
    value: &'a str,
    max_len: usize,
    req_id: Option<serde_json::Value>,
) -> Result<&'a str, JsonRpcResponse> {
    if value.len() > max_len {
        Err(mcp_error(
            req_id,
            -32602,
            &format!(
                "{} exceeds maximum length of {} characters (got {})",
                field,
                max_len,
                value.len()
            ),
        ))
    } else {
        Ok(value)
    }
}

/// MCP-410 (2026-05-11): canonical control-char / null-byte
/// validator for name-like fields. The check duplicated inline
/// across `create_workflow` / `create_actor` / `rename_workflow` /
/// `rename_module` / `set_secret` (MCP-405) / `create_webhook`
/// (MCP-406) / `create_scratch_session` (MCP-409). Centralising
/// the rule lets new name-field handlers pick it up uniformly
/// instead of recovering the pattern from scratch each time.
///
/// Rule: reject `\0` (Postgres' "invalid byte sequence" — opaque
/// error if it reaches the DB) and reject control characters
/// EXCEPT tab (`\t`), which is allowed because legitimate names
/// occasionally include it via paste.
///
/// `field_label` is the operator-facing field name interpolated
/// into the diagnostic, e.g. "Webhook name" / "Session name" /
/// "Secret name".
pub fn validate_name_no_control_chars(
    field_label: &str,
    value: &str,
    req_id: Option<serde_json::Value>,
) -> Result<(), JsonRpcResponse> {
    // Canonical single-line control-char rule lives in `talos-validation`
    // (shared with the GraphQL surface). allow-validation-predicate: thin
    // wrapper mapping the shared error into the MCP -32602 shape.
    talos_validation::reject_control_chars(
        field_label,
        value,
        talos_validation::LineMode::SingleLine,
    )
    .map_err(|e| mcp_error(req_id, -32602, &e.message))
}

/// MCP-429 (2026-05-11): canonical validator for multi-line
/// description-like fields. Triplicated inline across `create_actor`
/// (MCP-426) / `update_actor` (MCP-427) / `clone_actor` (MCP-428)
/// with identical rules: trim-then-check whitespace, length on
/// trimmed value, control-char check (allowing tab + \n + \r since
/// multi-line descriptions are legitimate).
///
/// Returns `Ok(None)` when input is absent / null / explicitly empty
/// (the "clear field" semantic). `Ok(Some(trimmed_owned_string))`
/// when input is well-formed. `Err(JsonRpcResponse)` with a
/// structured -32602 when input violates a rule.
///
/// `omit_hint` is appended to the whitespace-only error message —
/// callers differ slightly on what "omit" means (clear vs inherit).
/// Pass an empty string for the create-style "Omit the field to
/// leave it blank" default.
///
/// Use for ACTOR-style descriptions (newlines allowed). Workflow
/// descriptions have their own helper in
/// talos-workflow-creation-helpers that adds the tool-call-XML-leak
/// detector — a separate rule that doesn't apply to actor
/// descriptions.
pub fn validate_multiline_description(
    field_label: &str,
    input: Option<&str>,
    max_len: usize,
    omit_hint: &str,
    req_id: Option<serde_json::Value>,
) -> Result<Option<String>, JsonRpcResponse> {
    let Some(d) = input else {
        return Ok(None);
    };
    // Empty string is the documented "clear this field" sentinel —
    // accept and return None. Pre-empt the whitespace check since
    // empty does not pass "non-whitespace when provided".
    if d.is_empty() {
        return Ok(None);
    }
    // Canonical trim/empty/length/control-char rule lives in
    // `talos-validation` (shared with the GraphQL surface). This wrapper
    // owns only the MCP-specific Option/empty→None mapping and the
    // owned-String return. allow-validation-predicate: thin wrapper.
    match talos_validation::validate_multiline_description(field_label, d, max_len, omit_hint) {
        Ok(trimmed) => Ok(Some(trimmed.to_string())),
        Err(e) => Err(mcp_error(req_id, -32602, &e.message)),
    }
}

/// Validate a byte-bounded blob against an explicit byte cap.
/// Use for binary or pre-encoded payloads where character count
/// isn't the right unit.
pub fn validate_byte_size(
    field: &str,
    bytes: &[u8],
    max_bytes: usize,
    req_id: Option<serde_json::Value>,
) -> Result<(), JsonRpcResponse> {
    if bytes.len() > max_bytes {
        Err(mcp_error(
            req_id,
            -32602,
            &format!(
                "{} exceeds maximum size of {} bytes (got {})",
                field,
                max_bytes,
                bytes.len()
            ),
        ))
    } else {
        Ok(())
    }
}

/// MCP-10: Validate an optional integer arg against an inclusive range.
///
/// Returns `Ok(default)` when the arg is missing, `Ok(value)` when present
/// and in range, and `Err(<-32602 response>)` when present but out of range.
///
/// Replaces the silent-clamp pattern:
/// ```ignore
///   let n = args.get("n").and_then(|v| v.as_i64()).unwrap_or(D).clamp(MIN, MAX);
/// ```
/// which silently coerces typos like `n=10000` to `MAX=100`. The N-J pattern
/// surfaces the typo as an explicit -32602 with the valid range, matching
/// the precedent set by `find_unreferenced_modules` in commit `6b9a40e`.
pub fn validate_range_i64(
    args: &serde_json::Value,
    field: &str,
    min: i64,
    max: i64,
    default: i64,
    req_id: &Option<serde_json::Value>,
) -> Result<i64, JsonRpcResponse> {
    // MCP-187 (2026-05-08): distinguish "field absent / null" from
    // "field present but wrong JSON type". Pre-fix the chained
    // `.and_then(|v| v.as_i64())` returned None for both cases, so
    // `older_than_days: "60"` (string) silently fell through to
    // default. Now the absent/null path returns default (existing
    // behaviour) while wrong-type rejects loudly.
    match args.get(field) {
        None | Some(serde_json::Value::Null) => Ok(default),
        Some(v) => match v.as_i64() {
            Some(n) if !(min..=max).contains(&n) => Err(mcp_error(
                req_id.clone(),
                -32602,
                &format!("Invalid '{field}' value {n}: must be in [{min}, {max}]"),
            )),
            Some(n) => Ok(n),
            None => Err(mcp_error(
                req_id.clone(),
                -32602,
                &format!(
                    "'{field}' must be an integer in [{min}, {max}], got {kind}",
                    kind = json_type_name(v)
                ),
            )),
        },
    }
}

/// MCP-10: Validate an optional u64 arg against an inclusive range.
/// Same shape as `validate_range_i64` for unsigned numerics. Use when the
/// underlying field is naturally non-negative (counts, durations).
pub fn validate_range_u64(
    args: &serde_json::Value,
    field: &str,
    min: u64,
    max: u64,
    default: u64,
    req_id: &Option<serde_json::Value>,
) -> Result<u64, JsonRpcResponse> {
    // MCP-187: see validate_range_i64 for wrong-type handling
    // rationale. NB. `as_u64()` returns None for negative numbers,
    // so this also catches `field: -5` and reports it correctly.
    match args.get(field) {
        None | Some(serde_json::Value::Null) => Ok(default),
        Some(v) => {
            // Try as u64 first (the happy path).
            if let Some(n) = v.as_u64() {
                if !(min..=max).contains(&n) {
                    return Err(mcp_error(
                        req_id.clone(),
                        -32602,
                        &format!("Invalid '{field}' value {n}: must be in [{min}, {max}]"),
                    ));
                }
                return Ok(n);
            }
            // Negative number → echo it in the error so the caller
            // sees the actual value they passed (better than "wrong
            // type"). Non-numeric → fall through to type error.
            if let Some(neg) = v.as_i64() {
                return Err(mcp_error(
                    req_id.clone(),
                    -32602,
                    &format!("Invalid '{field}' value {neg}: must be in [{min}, {max}]"),
                ));
            }
            Err(mcp_error(
                req_id.clone(),
                -32602,
                &format!(
                    "'{field}' must be a non-negative integer in [{min}, {max}], got {kind}",
                    kind = json_type_name(v)
                ),
            ))
        }
    }
}

/// MCP-10: Validate an optional float arg against an inclusive range.
/// Used for percentages / similarity thresholds. Rejects NaN/Inf.
pub fn validate_range_f64(
    args: &serde_json::Value,
    field: &str,
    min: f64,
    max: f64,
    default: f64,
    req_id: &Option<serde_json::Value>,
) -> Result<f64, JsonRpcResponse> {
    // MCP-187: see validate_range_i64 for wrong-type handling.
    match args.get(field) {
        None | Some(serde_json::Value::Null) => Ok(default),
        Some(v) => match v.as_f64() {
            Some(n) if !n.is_finite() => Err(mcp_error(
                req_id.clone(),
                -32602,
                &format!("Invalid '{field}' value {n}: must be a finite number in [{min}, {max}]"),
            )),
            Some(n) if !(min..=max).contains(&n) => Err(mcp_error(
                req_id.clone(),
                -32602,
                &format!("Invalid '{field}' value {n}: must be in [{min}, {max}]"),
            )),
            Some(n) => Ok(n),
            None => Err(mcp_error(
                req_id.clone(),
                -32602,
                &format!(
                    "'{field}' must be a number in [{min}, {max}], got {kind}",
                    kind = json_type_name(v)
                ),
            )),
        },
    }
}

/// MCP-187 helper: human-readable name for a JSON value's type.
/// Used in error messages when a numeric field receives a wrong-type
/// input ("got string", "got bool", etc.) so the caller can correct
/// their request envelope rather than guessing.
pub fn json_type_name(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// MCP-189 (2026-05-08): validate an optional boolean arg, distinguishing
/// "field absent / null" (use default) from "field present but wrong JSON
/// type" (reject loudly with the actual type observed).
///
/// Pre-fix the inline pattern `args.get(field).and_then(|v| v.as_bool())
/// .unwrap_or(default)` returned None for both shapes, then silently
/// substituted `default` for both. So a caller passing `confirm: "true"`
/// (string) on a destructive op got `confirm = false` (the safe-fail
/// default) — operationally the action was blocked, but the caller
/// believed they had confirmed and was misled.
///
/// Strict: only accepts true / false / null / absent. Strings ("true",
/// "yes", "1") and numbers (0, 1) are rejected — JSON booleans are
/// first-class, so callers should send them. Same shape as
/// `validate_range_*`.
pub fn validate_optional_bool(
    args: &serde_json::Value,
    field: &str,
    default: bool,
    req_id: &Option<serde_json::Value>,
) -> Result<bool, JsonRpcResponse> {
    match args.get(field) {
        None | Some(serde_json::Value::Null) => Ok(default),
        Some(v) => match v.as_bool() {
            Some(b) => Ok(b),
            None => Err(mcp_error(
                req_id.clone(),
                -32602,
                &format!(
                    "'{field}' must be a boolean (true / false), got {kind}",
                    kind = json_type_name(v)
                ),
            )),
        },
    }
}

/// MCP-347 (2026-05-11): validate an optional string arg, distinguishing
/// "field absent / null" (use `default`) from "field present but wrong JSON
/// type" (reject loudly with the observed kind). When `allowed` is `Some`,
/// the resolved value must appear in the slice — else loud reject with the
/// bad value echoed AND the allowlist enumerated. When `allowed` is `None`,
/// any string is accepted (the caller does its own downstream validation,
/// e.g. charset / chrono-tz parse / model-registry lookup).
///
/// Pre-fix the inline pattern `args.get(field).and_then(|v| v.as_str())
/// .unwrap_or(default)` collapsed wrong-type into `default` silently — so
/// `on_budget_exceeded: 42` (number) was treated as "suspend" (default),
/// `namespace: ["prod"]` (array) was treated as "default" namespace, and
/// `timezone: 7` (number) was treated as UTC. Direction-class: operator
/// opts IN to a specific policy / scope, wrong-type opts them OUT — the
/// caller believed their input took effect, but the server quietly used
/// the default.
///
/// Same shape as `validate_optional_bool`. Returns an owned `String` so
/// callers don't have to thread the borrow lifetime; the cost is one
/// allocation per request, which is negligible against the JSON-RPC round
/// trip.
pub fn validate_optional_string(
    args: &serde_json::Value,
    field: &str,
    default: &str,
    allowed: Option<&[&str]>,
    req_id: &Option<serde_json::Value>,
) -> Result<String, JsonRpcResponse> {
    let resolved = match args.get(field) {
        None | Some(serde_json::Value::Null) => default.to_string(),
        Some(v) => match v.as_str() {
            Some(s) => s.to_string(),
            None => {
                return Err(mcp_error(
                    req_id.clone(),
                    -32602,
                    &format!(
                        "'{field}' must be a string, got {kind}",
                        kind = json_type_name(v)
                    ),
                ));
            }
        },
    };
    if let Some(list) = allowed {
        if !list.contains(&resolved.as_str()) {
            // MCP-1022 (2026-05-15): cap the reflected value at 64 chars.
            // Pre-fix `got '{resolved}'` echoed the caller's full input
            // back. Most fields gated by `allowed` are short enums
            // (policy / mode / on_exceeded / on_failure / model /
            // namespace / timezone) — operator-debuggable inputs are
            // always under 64 chars. A misbehaving client shipping a
            // multi-MB string into one of these fields would produce
            // a multi-MB MCP error response. Sibling reflection-class
            // defense to MCP-958/959/1020 (validate_timezone + cron).
            // Use canonical UTF-8-safe truncation helper.
            let got_preview = if resolved.len() > 64 {
                format!(
                    "{}…",
                    talos_text_util::truncate_at_char_boundary(&resolved, 60)
                )
            } else {
                resolved.clone()
            };
            return Err(mcp_error(
                req_id.clone(),
                -32602,
                &format!(
                    "'{field}' must be one of [{}], got '{got_preview}'",
                    list.join(", ")
                ),
            ));
        }
    }
    Ok(resolved)
}

/// MCP-206: Validate a REQUIRED integer field against an inclusive range,
/// narrowed to i32 (the schema type for `version_number`, `version_a`, etc.
/// in the workflow_versions table). Rejects:
///   - absent / null (required)
///   - wrong JSON type (string, bool, object, array)
///   - out-of-range values (e.g., 0 or negative for 1-indexed version numbers)
///   - i64 values that would truncate when cast `as i32`
///
/// Pre-fix call sites used `args.get(f).and_then(|v| v.as_i64())` followed
/// by `as i32`, which silently truncated and accepted negative / zero values.
/// The DB query then returned no row, surfacing as "Version N not found"
/// — masking the malformed input as a real lookup miss.
pub fn require_int_range_i32(
    args: &serde_json::Value,
    field: &str,
    min: i32,
    max: i32,
    req_id: &Option<serde_json::Value>,
) -> Result<i32, JsonRpcResponse> {
    match args.get(field) {
        None | Some(serde_json::Value::Null) => Err(mcp_error(
            req_id.clone(),
            -32602,
            &format!("Missing or null '{field}' parameter"),
        )),
        Some(v) => match v.as_i64() {
            Some(n) if !((min as i64)..=(max as i64)).contains(&n) => Err(mcp_error(
                req_id.clone(),
                -32602,
                &format!("Invalid '{field}' value {n}: must be in [{min}, {max}]"),
            )),
            // allow-as-u32-cast: range-checked by the guard arm above
            // (`contains(&n)`); reaching this branch means `min ≤ n ≤ max`
            // and both bounds fit i32.
            Some(n) => Ok(n as i32),
            None => Err(mcp_error(
                req_id.clone(),
                -32602,
                &format!(
                    "'{field}' must be an integer in [{min}, {max}], got {kind}",
                    kind = json_type_name(v)
                ),
            )),
        },
    }
}

/// Extract a required node identifier string with length validation.
///
/// Replaces this repeated inline pattern (~30+ occurrences across
/// `mcp/graph.rs`, `mcp/workflows.rs`):
/// ```ignore
/// let node_id = match args.get("node_id").and_then(|v| v.as_str()) {
///     Some(n) if n.len() > 100 => return mcp_error(req_id, -32602, "node_id must be ≤ 100 characters"),
///     Some(n) if !n.is_empty() => n.to_string(),
///     _ => return mcp_error(req_id, -32602, "Missing or empty 'node_id' parameter"),
/// };
/// ```
/// with:
/// ```ignore
/// let node_id = match require_node_id(args, "node_id", req_id.clone()) {
///     Ok(s) => s,
///     Err(resp) => return resp,
/// };
/// ```
pub fn require_node_id(
    args: &serde_json::Value,
    field: &str,
    req_id: Option<serde_json::Value>,
) -> Result<String, JsonRpcResponse> {
    // MCP-216 (2026-05-08): pre-fix `!s.is_empty()` accepted
    // whitespace-only node IDs (`"   "`, tabs, newlines). The
    // worst case is in copy_node / duplicate_node which then
    // persist a new node into the graph with `id: "   "` —
    // no later handler can address that node by id. Lookup
    // handlers (set_node_description, update_node_config) would
    // search for `"   "` and report "node not found", masking
    // the malformed input. Same family as the MCP-210 / MCP-215
    // whitespace-bypass class. The trimmed value is what gets
    // returned, so callers don't have to re-trim downstream.
    match args.get(field).and_then(|v| v.as_str()) {
        Some(s) if s.len() > MAX_NODE_ID_LENGTH => Err(mcp_error(
            req_id,
            -32602,
            &format!("{} must be ≤ {} characters", field, MAX_NODE_ID_LENGTH),
        )),
        Some(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                Err(mcp_error(
                    req_id,
                    -32602,
                    &format!("'{}' must be a non-empty, non-whitespace string", field),
                ))
            } else {
                Ok(trimmed.to_string())
            }
        }
        _ => Err(mcp_error(
            req_id,
            -32602,
            &format!("Missing or empty '{}' parameter", field),
        )),
    }
}

// ============================================================================
// Canonical error response helpers
// ============================================================================
//
// These build commonly repeated MCP error responses. Using them ensures the
// error message and code stay consistent across handlers — when the message
// text needs to change (e.g., for a security-redaction audit), it changes in
// exactly one place.

/// Standard response for "workflow not found or access denied" — used after
/// a lookup returns None, indicating either the workflow doesn't exist OR
/// it belongs to a different user. Merging both cases is intentional: it
/// prevents information disclosure (an attacker can't probe workflow IDs
/// for existence by comparing error messages).
pub fn workflow_not_found_error(req_id: Option<serde_json::Value>) -> JsonRpcResponse {
    mcp_error(req_id, -32000, "Workflow not found or access denied")
}

/// Standard response for "execution not found or access denied".
pub fn execution_not_found_error(req_id: Option<serde_json::Value>) -> JsonRpcResponse {
    mcp_error(req_id, -32000, "Execution not found or access denied")
}

/// Standard generic database error. Keep the caller's DB error in the log
/// (via tracing) but return this generic message to avoid leaking DB schema
/// details to MCP clients.
pub fn database_error(req_id: Option<serde_json::Value>) -> JsonRpcResponse {
    mcp_error(req_id, -32000, "Database error")
}

/// Block dispatch handlers when the operator has paused the execution
/// queue (`pause_executions`). Returns `Ok(())` when execution is
/// permitted; `Err(response)` carrying the canonical operator-facing
/// message when paused, or the generic database error on a repo failure.
/// Replaces the 12-line match block duplicated across every dispatch /
/// trigger / test / replay handler.
pub async fn enforce_executions_not_paused(
    workflow_repo: &talos_workflow_repository::WorkflowRepository,
    req_id: Option<serde_json::Value>,
) -> Result<(), JsonRpcResponse> {
    match workflow_repo.is_execution_paused().await {
        Ok(false) => Ok(()),
        Ok(true) => Err(mcp_error(
            req_id,
            -32000,
            "Execution queue is paused. Use resume_executions to re-enable.",
        )),
        Err(e) => {
            tracing::error!("is_execution_paused error: {}", e);
            Err(database_error(req_id))
        }
    }
}

/// Parse the optional caller-supplied actor identifier, accepting both
/// the canonical `actor_id` key and the legacy `agent_id` key for
/// backward-compatibility. `None` when neither key is present, the
/// value is not a string, or the string fails UUID parsing — callers
/// then fall back to the workflow's bound actor (if any).
pub fn parse_optional_actor_id(args: &serde_json::Value) -> Option<uuid::Uuid> {
    args.get("actor_id")
        .or_else(|| args.get("agent_id"))
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
}

/// Reject MCP request inputs whose JSON-serialized form exceeds 1 MB. Returns
/// `Ok(())` when within budget; `Err(response)` carrying the canonical
/// "input payload must be ≤ 1 MB when serialized" error otherwise. Mirrors
/// the engine's downstream cap so a noisy MCP caller fails at the protocol
/// edge instead of after we've spawned an execution. 1 MB matches
/// `JobRequest`'s 1 MiB-class wire ceiling.
pub fn enforce_payload_size_limit(
    payload: &serde_json::Value,
    req_id: Option<serde_json::Value>,
) -> Result<(), JsonRpcResponse> {
    if serde_json::to_string(payload).map(|s| s.len()).unwrap_or(0) > 1_000_000 {
        return Err(mcp_error(
            req_id,
            -32602,
            "input payload must be ≤ 1 MB when serialized",
        ));
    }
    Ok(())
}

/// Map a [`talos_workflow_manifest::ManifestError`] to its canonical
/// MCP `JsonRpcResponse`. Code mapping comes directly from the
/// service's `jsonrpc_code()`; the user-facing message comes from
/// `user_facing_message()` so internal errors collapse to the generic
/// `"Database error"` (no schema/query leakage).
pub fn manifest_error_to_response(
    err: talos_workflow_manifest::ManifestError,
    req_id: Option<serde_json::Value>,
) -> JsonRpcResponse {
    // Log the full chain for operators on the internal-error path; the
    // error response stays generic.
    if matches!(err, talos_workflow_manifest::ManifestError::Internal(_)) {
        tracing::error!(error = ?err, "manifest service internal error");
    }
    let code = err.jsonrpc_code();
    let msg = err.user_facing_message();
    mcp_error(req_id, code, &msg)
}

/// Map a [`talos_workflow_authorization::ActorDispatchLifecycle`] check
/// outcome to its canonical MCP error response. Returns `Ok(())` when the
/// actor is `Ok` to dispatch; `Err(response)` for archived / terminated /
/// not-found / DB-error cases. `log_context` prefixes the tracing line on
/// the DB-error path (e.g. `"test_workflow"`) so operators can correlate.
///
/// Used by handlers that gate on actor lifecycle WITHOUT enforcing budget
/// or capability ceilings (test paths). Production dispatch goes through
/// `talos-execution-orchestration` instead.
pub fn actor_dispatch_lifecycle_to_response(
    result: Result<talos_workflow_authorization::ActorDispatchLifecycle, anyhow::Error>,
    req_id: Option<serde_json::Value>,
    log_context: &str,
) -> Result<(), JsonRpcResponse> {
    use talos_workflow_authorization::ActorDispatchLifecycle;
    match result {
        Ok(ActorDispatchLifecycle::Ok) => Ok(()),
        Ok(ActorDispatchLifecycle::Archived) => Err(mcp_error(
            req_id,
            -32000,
            "Actor is archived — archived actors cannot dispatch executions.",
        )),
        Ok(ActorDispatchLifecycle::Terminated) => Err(mcp_error(
            req_id,
            -32000,
            "Actor is terminated — terminated actors cannot dispatch executions.",
        )),
        Ok(ActorDispatchLifecycle::NotFound) => Err(mcp_error(
            req_id,
            -32000,
            "Actor not found or access denied",
        )),
        Err(e) => {
            tracing::error!("{} actor status check error: {}", log_context, e);
            Err(database_error(req_id))
        }
    }
}

/// Map a [`talos_workflow_authorization::CreatorAuthError`] to its canonical
/// MCP `JsonRpcResponse` shape — the same wording / code triple every
/// `create_*` handler used to inline. The `Database` variant is intentionally
/// degraded to the generic [`database_error`] response to avoid leaking
/// Postgres internals; the inner error is logged at `error!` level so
/// operators can still correlate via the request id.
///
/// Variant → code:
/// * `ActorNotFoundOrInactive` → `-32002`
/// * `BudgetExhausted`         → `-32000`
/// * `CapabilityCeilingViolation` → `-32003`
/// * `Database`                → `-32000` (generic; full error logged)
pub fn creator_auth_error_to_response(
    err: talos_workflow_authorization::CreatorAuthError,
    req_id: Option<serde_json::Value>,
) -> JsonRpcResponse {
    use talos_workflow_authorization::CreatorAuthError;
    match err {
        CreatorAuthError::ActorNotFoundOrInactive => mcp_error(
            req_id,
            -32002,
            "Actor not found, not active, or belongs to a different user",
        ),
        CreatorAuthError::BudgetExhausted { limit } => mcp_error(
            req_id,
            -32000,
            &format!(
                "Actor has reached its workflow limit ({limit}). Archive unused workflows or increase the budget."
            ),
        ),
        CreatorAuthError::CapabilityCeilingViolation {
            module_id,
            module_world,
            max_world,
            req_rank,
            max_rank,
        } => mcp_error(
            req_id,
            -32003,
            &format!(
                "Capability ceiling violation: module {} uses '{}' world (rank {}) \
                 which exceeds this agent's ceiling '{}' (rank {}). \
                 Use a module within the '{}' world or ask an operator to raise the ceiling.",
                module_id, module_world, req_rank, max_world, max_rank, max_world
            ),
        ),
        CreatorAuthError::Database(err) => {
            tracing::error!("authorize_workflow_creator error: {}", err);
            database_error(req_id)
        }
    }
}

/// Map a [`talos_workflow_authorization::TriggerAuthError`] to its canonical
/// MCP `JsonRpcResponse` shape — companion to [`creator_auth_error_to_response`]
/// for the trigger-time gate. Wording is preserved verbatim from the
/// pre-extraction `handle_trigger_workflow` site so MCP clients see no change.
///
/// Variant → code:
/// * `ActorArchived` / `ActorTerminated` / `ActorNotFoundOrInactive` /
///   `ExecutionDenied(_)` → `-32000`
/// * `CapabilityCeilingViolation` → `-32003`
/// * `Database`                → `-32000` (generic; full error logged)
pub fn trigger_auth_error_to_response(
    err: talos_workflow_authorization::TriggerAuthError,
    req_id: Option<serde_json::Value>,
) -> JsonRpcResponse {
    use talos_workflow_authorization::TriggerAuthError;
    match err {
        TriggerAuthError::ActorArchived => mcp_error(
            req_id,
            -32000,
            "Actor is archived — this is an IRREVERSIBLE terminal state. \
             Archived actors cannot dispatch executions. Create a new actor instead.",
        ),
        TriggerAuthError::ActorTerminated => mcp_error(
            req_id,
            -32000,
            "Actor is terminated — this is an IRREVERSIBLE terminal state. \
             Terminated actors cannot dispatch executions. Create a new actor instead.",
        ),
        TriggerAuthError::ActorNotFoundOrInactive => {
            mcp_error(req_id, -32000, "Actor not found or access denied")
        }
        TriggerAuthError::ExecutionDenied(msg) => mcp_error(req_id, -32000, &msg),
        TriggerAuthError::CapabilityCeilingViolation {
            module_id,
            module_world,
            max_world,
            req_rank,
            max_rank,
        } => mcp_error(
            req_id,
            -32003,
            &format!(
                "Capability ceiling violation: workflow node {} uses '{}' world (rank {}) \
                 which exceeds this agent's ceiling '{}' (rank {}). \
                 Remove the node or ask an operator to raise the ceiling.",
                module_id, module_world, req_rank, max_world, max_rank
            ),
        ),
        TriggerAuthError::Database(err) => {
            tracing::error!("authorize_workflow_trigger error: {}", err);
            database_error(req_id)
        }
    }
}

pub fn resource_not_found_error(id: Option<serde_json::Value>, uri: &str) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id,
        result: None,
        error: Some(JsonRpcError {
            code: -32001,
            message: format!("Resource not found: {}", uri),
            data: None,
        }),
    }
}

/// Pure: extract a `Vec<String>` from a JSON object's named field when
/// it is an array of strings.
///
/// Iterates `obj.<field>[*]`, keeps every element that is a JSON string,
/// and returns owned `String` copies. Non-array fields, missing fields,
/// and non-string elements yield an empty `Vec`. Order is preserved.
///
/// Replaces the (`obj.get(field).and_then(|v| v.as_array()).map(|arr|
/// arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
/// .unwrap_or_default()`) ritual that's paste-duplicated whenever a
/// handler reads a `Vec<String>` from talos.json / catalog metadata.
pub fn json_string_array_field(obj: &serde_json::Value, field: &str) -> Vec<String> {
    obj.get(field)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// MCP-243 (2026-05-08): trimmed sibling of `json_string_array_field`
/// for security-sensitive caller input where whitespace entries would
/// either silently bypass an allowlist or persist as a no-match
/// allowlist entry (e.g. `allowed_hosts: ["   "]` persisting and
/// running a module that thinks it has HTTP access but never matches
/// a real host).
///
/// Strips leading/trailing whitespace from each entry and drops
/// empty-after-trim entries entirely. Use this for user-supplied
/// arrays of hostnames, vault paths, capability tags, HTTP methods,
/// or other security-allowlist values. The plain helper above is
/// fine for internal-metadata reads where the values were validated
/// upstream.
pub fn json_string_array_field_trimmed(obj: &serde_json::Value, field: &str) -> Vec<String> {
    obj.get(field)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// MCP-320 (2026-05-11): strict sibling of `json_string_array_field`
/// for user-input arrays where silent-drop of non-string elements
/// diverges from operator intent. Pre-fix sites used the silent-drop
/// helper for fields that the operator explicitly types (e.g.
/// `capabilities: ["http", 42, "secrets"]` persisted as
/// `["http", "secrets"]` — operator intended 3 caps, system stored 2,
/// no signal).
///
/// Reads `obj.<field>`:
///   * absent / null              → `Ok(None)` (caller decides default)
///   * empty array                → `Ok(Some(vec![]))`
///   * array of strings           → `Ok(Some(values))`
///   * any non-string element     → `Err` with `field[N] must be a string, got <kind>`
///   * non-array value            → `Err` with `field must be an array of strings, got <kind>`
///
/// Use this for operator-supplied arrays where the entries become
/// part of stored state (capabilities, module names, policy lists).
/// `json_string_array_field` keeps silent-drop where it's intentional
/// (metadata reads from already-validated sources).
pub fn json_string_array_field_strict(
    obj: &serde_json::Value,
    field: &str,
    req_id: &Option<serde_json::Value>,
) -> Result<Option<Vec<String>>, JsonRpcResponse> {
    match obj.get(field) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Array(arr)) => {
            let mut out: Vec<String> = Vec::with_capacity(arr.len());
            for (i, v) in arr.iter().enumerate() {
                match v.as_str() {
                    Some(s) => out.push(s.to_string()),
                    None => {
                        let kind = json_type_name(v);
                        return Err(mcp_error(
                            req_id.clone(),
                            -32602,
                            &format!("{field}[{i}] must be a string, got {kind}"),
                        ));
                    }
                }
            }
            Ok(Some(out))
        }
        Some(v) => {
            let kind = json_type_name(v);
            Err(mcp_error(
                req_id.clone(),
                -32602,
                &format!("{field} must be an array of strings, got {kind}"),
            ))
        }
    }
}

/// Pure: extract an optional owned `String` from a JSON object's named
/// field when it is a JSON string.
///
/// Returns `None` when the field is missing or non-string. Replaces the
/// `obj.get(field).and_then(|v| v.as_str()).map(String::from)` ritual,
/// useful both as a direct lookup and inside `Iterator::filter_map`
/// over edge / node arrays:
///
/// ```ignore
/// edges.iter().filter_map(|e| utils::json_optional_string(e, "source"))
/// ```
pub fn json_optional_string(obj: &serde_json::Value, field: &str) -> Option<String> {
    obj.get(field).and_then(|v| v.as_str()).map(String::from)
}

/// MCP-308 (2026-05-11): strict-parse a JSON embedding array to `Vec<f64>`.
///
/// Pre-fix the two call sites (`set_workflow_embedding` and
/// `search_workflows_semantic`) used `arr.iter().filter_map(|v| v.as_f64())
/// .collect()`, which silently dropped any non-number entries (strings,
/// `null`, booleans). The downstream dimension check then fired with a
/// misleading message — "Embedding must be exactly 1536 dimensions, got
/// 1535" — when the operator HAD passed 1536 entries but one of them was
/// the wrong JSON type, hiding the real cause from the caller.
///
/// This helper:
/// * Rejects wrong-type elements with `embedding[N] must be a number, got
///   <type>` so the caller sees exactly which index is malformed.
/// * Rejects `NaN` / `±Inf` (`as_f64()` returns `Some(NaN)` if the upstream
///   ever produces one through e.g. arbitrary_precision parsing; pgvector
///   cannot store non-finite values and the cosine score becomes
///   undefined).
/// * Does NOT check length — the caller's required dimension count is
///   provider-specific (1536 for OpenAI ada-002, 768 for nomic-embed-text),
///   so that check stays at the call site.
pub fn parse_embedding_array(arr: &[serde_json::Value]) -> Result<Vec<f64>, String> {
    let mut out = Vec::with_capacity(arr.len());
    for (idx, v) in arr.iter().enumerate() {
        let f = match v.as_f64() {
            Some(f) => f,
            None => {
                return Err(format!(
                    "embedding[{idx}] must be a number, got {kind}",
                    kind = json_type_name(v)
                ));
            }
        };
        if !f.is_finite() {
            return Err(format!("embedding[{idx}] must be a finite number, got {f}"));
        }
        out.push(f);
    }
    Ok(out)
}

/// Best-effort outbound POST to the workflow's failure webhook (if set).
///
/// Looks up `get_workflow_failure_webhook(wf_id)`; if a URL is configured,
/// re-validates it against the SSRF check (defence-in-depth: catches
/// URLs stored before the SSRF rules were tightened) and POSTs a
/// `workflow_failed` JSON payload with a 5-second timeout.
///
/// All failures are silently swallowed — this is a notification path,
/// not part of the request-response contract.
///
/// Replaces the same 25-LoC inline block that previously appeared in
/// handle_trigger_workflow, handle_call_workflow (×2), and
/// handle_replay_execution.
pub async fn dispatch_failure_webhook(
    workflow_repo: &talos_workflow_repository::WorkflowRepository,
    workflow_id: uuid::Uuid,
    execution_id: uuid::Uuid,
    error: &str,
) {
    let url = match workflow_repo
        .get_workflow_failure_webhook(workflow_id)
        .await
    {
        Ok(Some(u)) => u,
        _ => return,
    };
    if check_outbound_url_no_ssrf(&url).is_err() {
        tracing::warn!(
            workflow_id = %workflow_id,
            "Skipping failure webhook: stored URL failed SSRF validation"
        );
        return;
    }
    let alert_payload = serde_json::json!({
        "event": "workflow_failed",
        "workflow_id": workflow_id,
        "execution_id": execution_id,
        "error": error,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });
    // MCP-470: prophylactic — this helper is currently unreferenced
    // (the live failure-webhook path moved to
    // `talos-execution-orchestration::failure_webhook`) but is `pub`
    // and could be re-discovered. Built via the shared SSRF-safe builder
    // so a future caller inherits redirect(none) AND the connect-time
    // ControllerSsrfResolver (DNS-rebinding gate) — not just the
    // redirect-pivot defense MCP-469/470 added here.
    let client = match talos_http_utils::outbound::build_outbound_webhook_client_with_timeout(
        "talos-failure-webhook/1.0",
        std::time::Duration::from_secs(5),
    ) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                workflow_id = %workflow_id,
                error = %e,
                "dispatch_failure_webhook (utils): reqwest client build failed; skipping"
            );
            return;
        }
    };
    // MCP-775 (2026-05-13): log delivery failures even on this currently-
    // unreferenced helper. The comment on the helper noted it's `pub` and
    // could be re-discovered; if a future caller wires it back in, the
    // pre-fix `let _ = ...await` would silently inherit the swallowed-error
    // regression that MCP-742 closed on the LIVE
    // `talos-execution-orchestration::failure_webhook::dispatch_failure_webhook`
    // path. Same three-arm match shape: Ok/2xx → debug, Ok/non-2xx → WARN,
    // Err → WARN, all with stable `target: "talos_rpc"` so dashboards
    // correlate delivery-failure rate with controller health. Defense-in-depth
    // for the orphan; keeps the two siblings in lockstep so the next person
    // to remove the "unreferenced" comment doesn't reintroduce the gap.
    match client.post(&url).json(&alert_payload).send().await {
        Ok(resp) if resp.status().is_success() => {
            tracing::debug!(
                workflow_id = %workflow_id,
                status = resp.status().as_u16(),
                "dispatch_failure_webhook (utils) delivered"
            );
        }
        Ok(resp) => {
            tracing::warn!(
                target: "talos_rpc",
                workflow_id = %workflow_id,
                execution_id = %execution_id,
                status = resp.status().as_u16(),
                "dispatch_failure_webhook (utils) returned non-success status — operator notification may not have reached its destination"
            );
        }
        Err(e) => {
            tracing::warn!(
                target: "talos_rpc",
                workflow_id = %workflow_id,
                execution_id = %execution_id,
                error = %e,
                "dispatch_failure_webhook (utils) POST failed — operator notification undelivered"
            );
        }
    }
}

/// Project a workflow engine's `ctx.results` into the user-facing output
/// JSON map.
///
/// Iterates `(node_id, result_value)` pairs and:
///   * skips the synthetic `__trigger__` node,
///   * skips any node whose result has `__skipped: true`,
///   * unwraps the result via `ParallelWorkflowEngine::unwrap_output`,
///   * indexes by the node's label (falling back to the UUID string).
///
/// Returns a `serde_json::Map` so callers that need to add side-channel
/// keys (`__trigger_input__`, `__node_timings__`, etc.) can mutate the
/// projection without converting back from a `Value::Object`. Wrap with
/// `Value::Object(map)` to get a `Value`. Callers that persist this
/// should run the wrapped value through `talos_dlp_provider::redact_json`
/// before storage — this helper does NOT redact (so it stays a pure
/// pre-DB transform that's easy to unit-test).
pub fn project_engine_results_to_output(
    results: &std::collections::HashMap<uuid::Uuid, serde_json::Value>,
    node_labels: &std::collections::HashMap<uuid::Uuid, String>,
) -> serde_json::Map<String, serde_json::Value> {
    let mut output = serde_json::Map::new();
    for (nid, result_val) in results {
        let key = node_labels
            .get(nid)
            .cloned()
            .unwrap_or_else(|| nid.to_string());
        if key == "__trigger__" {
            continue;
        }
        if result_val
            .get("__skipped")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            continue;
        }
        let clean =
            talos_workflow_engine::ParallelWorkflowEngine::unwrap_output(result_val).clone();
        output.insert(key, clean);
    }
    output
}

/// Spawn the two best-effort post-create background tasks for a newly
/// inserted workflow:
///   * `crate::search::auto_embed_workflow` — generates an embedding so
///     the workflow shows up in semantic search.
///   * `crate::analytics::auto_suggest_capabilities` — fills in
///     capability tags when the row was inserted with empty `capabilities`.
///
/// Both helpers are idempotent and best-effort. Kept handler-side
/// (rather than service-side) because they are `pub(crate)` and pulling
/// them into a service crate would create a dep cycle through
/// `talos-search` / `talos-analytics`.
pub fn spawn_workflow_post_create_tasks(
    db_pool: &sqlx::PgPool,
    workflow_id: uuid::Uuid,
    user_id: uuid::Uuid,
) {
    {
        let db_embed = db_pool.clone();
        tokio::spawn(async move {
            crate::search::auto_embed_workflow(workflow_id, user_id, &db_embed).await;
        });
    }
    {
        let db_caps = db_pool.clone();
        tokio::spawn(async move {
            crate::analytics::auto_suggest_capabilities(workflow_id, user_id, &db_caps).await;
        });
    }
}

// ── Unknown-argument detection (tools/call) ──────────────────────────────
//
// Functional-sweep finding (2026-07-07): passing `depends_on` to
// `add_node_to_workflow` (real params: `connect_from`/`connect_to`) was
// SILENTLY ignored — the node landed disconnected, the workflow "worked"
// with the wrong semantics, and nothing hinted at the typo. Handlers read
// args field-by-field, so any unrecognized key is an invisible no-op.
//
// The fix is a central check in `handle_tools_call`: compare the caller's
// argument names against the tool's advertised `inputSchema.properties`
// (the SAME schemas `tools/list` serves, so the check can never drift from
// what clients are told). Unknown args produce a WARNING appended to the
// response — deliberately not an error: with ~280 hand-written schemas, a
// schema that under-declares a param its handler actually reads would turn
// a working call into a hard failure. The warning surfaces both caller
// typos AND schema drift without breaking either side.

/// `tool name → declared argument names`, built once on first use from the
/// same per-domain `tool_schemas()` sets the `tools/list` manifest serves.
static TOOL_ARG_INDEX: std::sync::OnceLock<
    std::collections::HashMap<String, std::collections::HashSet<String>>,
> = std::sync::OnceLock::new();

pub(crate) fn tool_arg_index(
) -> &'static std::collections::HashMap<String, std::collections::HashSet<String>> {
    TOOL_ARG_INDEX.get_or_init(|| {
        let all: Vec<serde_json::Value> = [
            crate::advanced::tool_schemas(),
            crate::platform::tool_schemas(),
            crate::search::tool_schemas(),
            crate::workflows::tool_schemas(),
            crate::modules::tool_schemas(),
            crate::sandbox::tool_schemas(),
            crate::executions::tool_schemas(),
            crate::actor::tool_schemas(),
            crate::analytics::tool_schemas(),
            crate::secrets::tool_schemas(),
            crate::schedules::tool_schemas(),
            crate::versions::tool_schemas(),
            crate::webhooks::tool_schemas(),
            crate::graph::tool_schemas(),
            crate::knowledge_graph::tool_schemas(),
            crate::alerts::tool_schemas(),
            crate::schemas::tool_schemas(),
            crate::ollama::tool_schemas(),
        ]
        .concat();
        all.iter()
            .filter_map(|t| {
                let name = t.get("name")?.as_str()?.to_string();
                let props = t.get("inputSchema")?.get("properties")?.as_object()?;
                Some((name, props.keys().cloned().collect()))
            })
            .collect()
    })
}

/// Bounded Levenshtein distance for did-you-mean suggestions. Inputs are
/// argument names (short); both sides are hard-capped so a pathological
/// key can't burn CPU — anything longer than the cap simply never
/// suggests (fine: suggestions are best-effort).
fn arg_edit_distance(a: &str, b: &str) -> usize {
    const CAP: usize = 64;
    let a: Vec<char> = a.chars().take(CAP).collect();
    let b: Vec<char> = b.chars().take(CAP).collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            cur[j + 1] = (prev[j + 1] + 1).min(cur[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

/// Best did-you-mean candidate for `unknown` among `declared`, or None
/// when nothing is close enough to be a plausible typo.
fn closest_declared_arg<'a>(
    unknown: &str,
    declared: &'a std::collections::HashSet<String>,
) -> Option<&'a str> {
    declared
        .iter()
        .map(|d| (arg_edit_distance(unknown, d), d.as_str()))
        // Threshold: ≤2 edits, or a prefix/substring relationship for
        // longer names (catches `cron` → `cron_expression`).
        .filter(|(dist, d)| {
            *dist <= 2
                || (unknown.len() >= 3 && (d.starts_with(unknown) || d.contains(unknown)))
                || (d.len() >= 3 && unknown.contains(*d))
        })
        .min_by_key(|(dist, _)| *dist)
        .map(|(_, d)| d)
}

/// Detect argument names the tool's advertised schema doesn't declare.
/// Returns a human-readable warning, or `None` when everything matches,
/// the tool isn't in the static index (dynamic `-v1` catalog tools), or
/// the tool declares no properties at all.
///
/// SECURITY: only argument NAMES are inspected and echoed — never values
/// (an unknown key's value could be a secret pasted under a typo'd name).
pub(crate) fn unknown_argument_warning(tool: &str, args: &serde_json::Value) -> Option<String> {
    let declared = tool_arg_index().get(tool)?;
    let provided = args.as_object()?;
    let mut notes: Vec<String> = provided
        .keys()
        // Underscore-prefixed keys are reserved for protocol metadata
        // (e.g. `_meta`) — never warn on them.
        .filter(|k| !k.starts_with('_') && !declared.contains(*k))
        .map(|k| match closest_declared_arg(k, declared) {
            Some(sugg) => format!("'{k}' (did you mean '{sugg}'?)"),
            None => format!("'{k}'"),
        })
        .collect();
    if notes.is_empty() {
        return None;
    }
    notes.sort();
    Some(format!(
        "⚠ unknown argument{} ignored by '{tool}': {}. Unrecognized arguments have NO effect — \
         check tools/list for the declared parameters.",
        if notes.len() == 1 { "" } else { "s" },
        notes.join(", ")
    ))
}

/// Human prose + machine-parsable JSON as two content blocks.
///
/// Sweep DX finding (2026-07-07): id-bearing responses (`trigger_workflow`,
/// `create_workflow`, `compile_custom_sandbox`) were prose-only, forcing
/// agents to regex UUIDs out of sentences. The prose stays first for
/// humans; the second block is a bare JSON object tooling can parse
/// without touching the prose. Additive — existing content[0] consumers
/// are unaffected.
pub(crate) fn mcp_text_with_json(
    id: Option<serde_json::Value>,
    text: &str,
    machine: serde_json::Value,
) -> talos_mcp::JsonRpcResponse {
    talos_mcp::JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id,
        result: Some(serde_json::json!({
            "content": [
                { "type": "text", "text": text },
                { "type": "text", "text": machine.to_string() },
            ]
        })),
        error: None,
    }
}

/// Append a warning text block to a tools/call response.
///
/// Applied to SUCCESS and TOOL-ERROR responses alike (live-proof finding:
/// `create_schedule(cron: ...)` errors with "Missing 'cron_expression'" —
/// the unknown-arg warning with its did-you-mean IS the diagnosis for that
/// error, so suppressing it on isError responses hid the answer exactly
/// when it mattered most). No-op on non-standard result shapes.
pub(crate) fn append_warning_block(resp: &mut talos_mcp::JsonRpcResponse, warning: &str) {
    if let Some(result) = resp.result.as_mut() {
        if let Some(content) = result.get_mut("content").and_then(|c| c.as_array_mut()) {
            content.push(serde_json::json!({ "type": "text", "text": warning }));
        }
    }
}

#[cfg(test)]
mod unknown_arg_tests {
    use super::*;

    #[test]
    fn index_contains_core_tools_with_declared_args() {
        let idx = tool_arg_index();
        let add_node = idx
            .get("add_node_to_workflow")
            .expect("add_node_to_workflow in index");
        assert!(add_node.contains("connect_from"));
        assert!(add_node.contains("connect_to"));
        assert!(!add_node.contains("depends_on"));
        assert!(idx.contains_key("test_module"));
        assert!(idx.contains_key("create_schedule"));
    }

    #[test]
    fn sweep_regression_depends_on_warns_with_suggestion() {
        // The exact mistake from the 2026-07-07 functional sweep.
        let w = unknown_argument_warning(
            "add_node_to_workflow",
            &serde_json::json!({"workflow_id": "x", "node_id": "n", "depends_on": ["a"]}),
        )
        .expect("must warn");
        assert!(w.contains("'depends_on'"), "warning: {w}");
        // Value must never leak into the warning.
        assert!(!w.contains("\"a\""), "arg value leaked: {w}");
    }

    #[test]
    fn cron_suggests_cron_expression() {
        let w = unknown_argument_warning(
            "create_schedule",
            &serde_json::json!({"workflow_id": "x", "cron": "* * * * *"}),
        )
        .expect("must warn");
        assert!(w.contains("did you mean 'cron_expression'"), "warning: {w}");
        assert!(!w.contains("* * * * *"), "arg value leaked: {w}");
    }

    #[test]
    fn declared_args_and_meta_keys_do_not_warn() {
        assert!(unknown_argument_warning(
            "add_node_to_workflow",
            &serde_json::json!({"workflow_id": "x", "node_id": "n", "connect_from": "a", "_meta": {}}),
        )
        .is_none());
        // Unknown TOOL (dynamic -v1 catalog route) → no warning.
        assert!(
            unknown_argument_warning("Redis_Cache-v1", &serde_json::json!({"anything": 1}))
                .is_none()
        );
    }

    #[test]
    fn append_decorates_success_and_tool_errors() {
        let mut ok = talos_mcp::mcp_text(None, "done");
        append_warning_block(&mut ok, "⚠ w");
        let content = ok.result.unwrap()["content"].clone();
        assert_eq!(content.as_array().unwrap().len(), 2);
        assert_eq!(content[1]["text"], "⚠ w");

        // Tool errors ARE decorated: when the unknown arg caused the
        // error (cron vs cron_expression), the warning is the diagnosis.
        let mut err = talos_mcp::mcp_error(None, -32602, "bad");
        append_warning_block(&mut err, "⚠ w");
        let content = err.result.unwrap()["content"].clone();
        assert_eq!(content.as_array().unwrap().len(), 2, "error decorated too");
        assert_eq!(content[1]["text"], "⚠ w");
    }

    #[test]
    fn edit_distance_bounded_on_pathological_input() {
        let long = "x".repeat(100_000);
        // Capped at 64 chars per side — must return quickly and not panic.
        assert!(arg_edit_distance(&long, "connect_from") >= 1);
    }
}

#[cfg(test)]
mod bool_validation_tests {
    use super::validate_optional_bool;
    use serde_json::json;

    #[test]
    fn absent_uses_default() {
        let args = json!({});
        assert!(validate_optional_bool(&args, "b", true, &None).unwrap());
        assert!(!validate_optional_bool(&args, "b", false, &None).unwrap());
    }

    #[test]
    fn null_uses_default() {
        let args = json!({"b": null});
        assert!(validate_optional_bool(&args, "b", true, &None).unwrap());
    }

    #[test]
    fn explicit_true_returned() {
        let args = json!({"b": true});
        assert!(validate_optional_bool(&args, "b", false, &None).unwrap());
    }

    #[test]
    fn explicit_false_returned() {
        // Distinguishes "user passed false" from "user omitted, default false".
        // The default doesn't matter here — we honour the explicit input.
        let args = json!({"b": false});
        assert!(!validate_optional_bool(&args, "b", true, &None).unwrap());
    }

    #[test]
    fn string_rejects_loudly() {
        let args = json!({"b": "true"});
        let err = validate_optional_bool(&args, "b", false, &None).unwrap_err();
        let body = serde_json::to_string(&err).unwrap();
        assert!(body.contains("got string"), "msg: {body}");
    }

    #[test]
    fn number_rejects_loudly() {
        // 0 / 1 are NOT accepted as bool — JSON has first-class bools.
        let args = json!({"b": 1});
        let err = validate_optional_bool(&args, "b", false, &None).unwrap_err();
        let body = serde_json::to_string(&err).unwrap();
        assert!(body.contains("got number"), "msg: {body}");
    }
}

#[cfg(test)]
mod optional_string_tests {
    use super::validate_optional_string;
    use serde_json::json;

    const POLICIES: &[&str] = &["suspend", "alert", "block"];

    #[test]
    fn absent_uses_default() {
        let args = json!({});
        let got =
            validate_optional_string(&args, "policy", "suspend", Some(POLICIES), &None).unwrap();
        assert_eq!(got, "suspend");
    }

    #[test]
    fn null_uses_default() {
        let args = json!({"policy": null});
        let got =
            validate_optional_string(&args, "policy", "suspend", Some(POLICIES), &None).unwrap();
        assert_eq!(got, "suspend");
    }

    #[test]
    fn valid_allowlist_value_returned() {
        let args = json!({"policy": "block"});
        let got =
            validate_optional_string(&args, "policy", "suspend", Some(POLICIES), &None).unwrap();
        assert_eq!(got, "block");
    }

    #[test]
    fn out_of_allowlist_rejects_loudly_with_value_and_list() {
        let args = json!({"policy": "ignore"});
        let err = validate_optional_string(&args, "policy", "suspend", Some(POLICIES), &None)
            .unwrap_err();
        let body = serde_json::to_string(&err).unwrap();
        assert!(body.contains("'ignore'"), "value not echoed: {body}");
        assert!(
            body.contains("suspend, alert, block"),
            "list missing: {body}"
        );
    }

    #[test]
    fn wrong_type_number_rejects_loudly_with_kind() {
        // Direction-class regression: pre-fix the operator's `policy: 42`
        // silently became the default. Now we reject loudly.
        let args = json!({"policy": 42});
        let err = validate_optional_string(&args, "policy", "suspend", Some(POLICIES), &None)
            .unwrap_err();
        let body = serde_json::to_string(&err).unwrap();
        assert!(body.contains("got number"), "kind missing: {body}");
    }

    #[test]
    fn wrong_type_array_rejects_loudly_with_kind() {
        let args = json!({"namespace": ["prod"]});
        let err = validate_optional_string(&args, "namespace", "default", None, &None).unwrap_err();
        let body = serde_json::to_string(&err).unwrap();
        assert!(body.contains("got array"), "kind missing: {body}");
    }

    #[test]
    fn no_allowlist_accepts_any_string() {
        // Open-ended strings (timezone, model name, namespace) — caller
        // does its own downstream validation. Helper just guards type.
        let args = json!({"timezone": "America/Los_Angeles"});
        let got = validate_optional_string(&args, "timezone", "UTC", None, &None).unwrap();
        assert_eq!(got, "America/Los_Angeles");
    }

    #[test]
    fn empty_string_accepted_when_no_allowlist() {
        // Some callers want absent → default but "" passed-through for
        // their own trim/length check. Helper does NOT prejudge that.
        let args = json!({"namespace": ""});
        let got = validate_optional_string(&args, "namespace", "default", None, &None).unwrap();
        assert_eq!(got, "");
    }

    /// MCP-1022: a multi-KB input to an `allowed`-gated field must not
    /// reflect verbatim in the error message. The truncated preview keeps
    /// the message under ~100 chars total regardless of input length.
    #[test]
    fn oversized_input_truncates_in_error_reflection() {
        let oversized = "x".repeat(5000);
        let args = json!({"policy": oversized});
        let err = validate_optional_string(&args, "policy", "suspend", Some(POLICIES), &None)
            .unwrap_err();
        let body = serde_json::to_string(&err).unwrap();
        // Truncation marker present, full input absent.
        assert!(
            body.contains('…'),
            "expected truncation ellipsis in error body: {body}"
        );
        assert!(
            !body.contains(&"x".repeat(100)),
            "error body must not echo 100+ chars of the rejected value"
        );
    }

    /// MCP-1022: short inputs (canonical operator typo) still echo
    /// verbatim — truncation only kicks in past 64 chars.
    #[test]
    fn short_input_echoes_verbatim_in_error() {
        let args = json!({"policy": "ignre"}); // typo of "ignore"
        let err = validate_optional_string(&args, "policy", "suspend", Some(POLICIES), &None)
            .unwrap_err();
        let body = serde_json::to_string(&err).unwrap();
        assert!(body.contains("'ignre'"), "short typo must echo: {body}");
        assert!(
            !body.contains('…'),
            "short input must not trigger truncation: {body}"
        );
    }
}

#[cfg(test)]
mod range_validation_tests {
    use super::{validate_range_f64, validate_range_i64, validate_range_u64};
    use serde_json::json;

    #[test]
    fn i64_absent_uses_default() {
        let args = json!({});
        let v = validate_range_i64(&args, "n", 1, 100, 50, &None).unwrap();
        assert_eq!(v, 50);
    }

    #[test]
    fn i64_null_uses_default() {
        let args = json!({"n": null});
        let v = validate_range_i64(&args, "n", 1, 100, 50, &None).unwrap();
        assert_eq!(v, 50);
    }

    #[test]
    fn i64_in_range_returns_value() {
        let args = json!({"n": 42});
        let v = validate_range_i64(&args, "n", 1, 100, 50, &None).unwrap();
        assert_eq!(v, 42);
    }

    #[test]
    fn i64_out_of_range_rejects() {
        let args = json!({"n": 999});
        assert!(validate_range_i64(&args, "n", 1, 100, 50, &None).is_err());
    }

    #[test]
    fn i64_string_rejects_loudly() {
        // MCP-187: "60" (string) used to silently fall through to
        // the default. Should reject with a clear "got string" error.
        let args = json!({"n": "60"});
        let err = validate_range_i64(&args, "n", 1, 100, 50, &None).unwrap_err();
        let body = serde_json::to_string(&err).unwrap();
        assert!(body.contains("got string"), "msg: {body}");
    }

    #[test]
    fn i64_bool_rejects_loudly() {
        let args = json!({"n": true});
        let err = validate_range_i64(&args, "n", 1, 100, 50, &None).unwrap_err();
        let body = serde_json::to_string(&err).unwrap();
        assert!(body.contains("got bool"), "msg: {body}");
    }

    #[test]
    fn u64_negative_echoes_value() {
        // u64.as_u64() returns None for negative numbers — the
        // helper falls back to as_i64() and echoes the actual value.
        let args = json!({"n": -5});
        let err = validate_range_u64(&args, "n", 1, 100, 50, &None).unwrap_err();
        let body = serde_json::to_string(&err).unwrap();
        assert!(body.contains("-5"), "msg: {body}");
    }

    #[test]
    fn u64_string_rejects_loudly() {
        let args = json!({"n": "50"});
        let err = validate_range_u64(&args, "n", 1, 100, 50, &None).unwrap_err();
        let body = serde_json::to_string(&err).unwrap();
        assert!(body.contains("got string"), "msg: {body}");
    }

    #[test]
    fn f64_absent_uses_default() {
        let args = json!({});
        let v = validate_range_f64(&args, "x", 0.0, 1.0, 0.5, &None).unwrap();
        assert_eq!(v, 0.5);
    }

    #[test]
    fn f64_string_rejects_loudly() {
        let args = json!({"x": "0.7"});
        let err = validate_range_f64(&args, "x", 0.0, 1.0, 0.5, &None).unwrap_err();
        let body = serde_json::to_string(&err).unwrap();
        assert!(body.contains("got string"), "msg: {body}");
    }

    #[test]
    fn f64_nan_rejects() {
        let args = json!({"x": f64::NAN});
        // Note: serde_json represents NaN as null, so this actually
        // tests the null path → default. Real NaN can't enter via
        // JSON, but the inner finite-check stays as defense-in-depth.
        let v = validate_range_f64(&args, "x", 0.0, 1.0, 0.5, &None).unwrap();
        assert_eq!(v, 0.5);
    }
}

#[cfg(test)]
mod require_int_range_i32_tests {
    use super::require_int_range_i32;
    use serde_json::json;

    #[test]
    fn absent_rejects() {
        let args = json!({});
        let err = require_int_range_i32(&args, "v", 1, i32::MAX, &None).unwrap_err();
        let body = serde_json::to_string(&err).unwrap();
        assert!(body.contains("Missing or null 'v'"), "msg: {body}");
    }

    #[test]
    fn null_rejects() {
        let args = json!({"v": null});
        let err = require_int_range_i32(&args, "v", 1, i32::MAX, &None).unwrap_err();
        let body = serde_json::to_string(&err).unwrap();
        assert!(body.contains("Missing or null 'v'"), "msg: {body}");
    }

    #[test]
    fn negative_rejects() {
        // MCP-206: pre-fix `-5 as i32` silently passed through to DB
        // and surfaced as "Version -5 not found". Now caught upfront.
        let args = json!({"v": -5});
        let err = require_int_range_i32(&args, "v", 1, i32::MAX, &None).unwrap_err();
        let body = serde_json::to_string(&err).unwrap();
        assert!(body.contains("must be in [1,"), "msg: {body}");
    }

    #[test]
    fn zero_rejects() {
        // MCP-206: version_number is 1-indexed; pre-fix accepted 0.
        let args = json!({"v": 0});
        assert!(require_int_range_i32(&args, "v", 1, i32::MAX, &None).is_err());
    }

    #[test]
    fn one_accepts() {
        let args = json!({"v": 1});
        assert_eq!(
            require_int_range_i32(&args, "v", 1, i32::MAX, &None).unwrap(),
            1
        );
    }

    #[test]
    fn i32_max_accepts() {
        let args = json!({"v": i32::MAX});
        assert_eq!(
            require_int_range_i32(&args, "v", 1, i32::MAX, &None).unwrap(),
            i32::MAX
        );
    }

    #[test]
    fn i64_overflow_rejects() {
        // MCP-206: pre-fix `(i32::MAX as i64 + 1) as i32` wrapped to
        // i32::MIN, which then bypassed any range check downstream.
        let args = json!({"v": (i32::MAX as i64) + 1});
        assert!(require_int_range_i32(&args, "v", 1, i32::MAX, &None).is_err());
    }

    #[test]
    fn string_rejects_loudly() {
        let args = json!({"v": "5"});
        let err = require_int_range_i32(&args, "v", 1, i32::MAX, &None).unwrap_err();
        let body = serde_json::to_string(&err).unwrap();
        assert!(body.contains("got string"), "msg: {body}");
    }

    #[test]
    fn bool_rejects_loudly() {
        let args = json!({"v": true});
        let err = require_int_range_i32(&args, "v", 1, i32::MAX, &None).unwrap_err();
        let body = serde_json::to_string(&err).unwrap();
        assert!(body.contains("got bool"), "msg: {body}");
    }
}

#[cfg(test)]
mod require_node_id_tests {
    use super::require_node_id;
    use serde_json::json;

    #[test]
    fn whitespace_rejects() {
        // MCP-216: pre-fix `"   "` passed `!s.is_empty()` and was
        // either persisted into the graph (copy_node / duplicate_node)
        // or sent to a node-by-id lookup that always missed.
        let args = json!({"node_id": "   "});
        let err = require_node_id(&args, "node_id", None).unwrap_err();
        let body = serde_json::to_string(&err).unwrap();
        assert!(body.contains("non-whitespace"), "msg: {body}");
    }

    #[test]
    fn tabs_and_newlines_reject() {
        let args = json!({"node_id": "\t\n  "});
        assert!(require_node_id(&args, "node_id", None).is_err());
    }

    #[test]
    fn empty_rejects() {
        let args = json!({"node_id": ""});
        assert!(require_node_id(&args, "node_id", None).is_err());
    }

    #[test]
    fn absent_rejects() {
        let args = json!({});
        assert!(require_node_id(&args, "node_id", None).is_err());
    }

    #[test]
    fn valid_id_returns_trimmed() {
        // Surrounding whitespace is normalised away — caller doesn't
        // have to re-trim before passing to the graph.
        let args = json!({"node_id": "  fetch-data  "});
        let v = require_node_id(&args, "node_id", None).unwrap();
        assert_eq!(v, "fetch-data");
    }

    #[test]
    fn over_length_rejects() {
        let s = "a".repeat(101);
        let args = json!({"node_id": s});
        assert!(require_node_id(&args, "node_id", None).is_err());
    }

    #[test]
    fn at_length_accepts() {
        let s = "a".repeat(100);
        let args = json!({"node_id": s.clone()});
        assert_eq!(require_node_id(&args, "node_id", None).unwrap(), s);
    }
}

#[cfg(test)]
mod project_results_tests {
    use super::project_engine_results_to_output;
    use std::collections::HashMap;
    use uuid::Uuid;

    fn label(name: &str) -> String {
        name.to_string()
    }

    #[test]
    fn projects_labeled_results_to_output() {
        let n1 = Uuid::new_v4();
        let n2 = Uuid::new_v4();
        let mut results = HashMap::new();
        results.insert(n1, serde_json::json!({"value": 1}));
        results.insert(n2, serde_json::json!({"value": 2}));
        let mut labels = HashMap::new();
        labels.insert(n1, label("first"));
        labels.insert(n2, label("second"));

        let obj = project_engine_results_to_output(&results, &labels);
        assert_eq!(obj.get("first"), Some(&serde_json::json!({"value": 1})));
        assert_eq!(obj.get("second"), Some(&serde_json::json!({"value": 2})));
    }

    #[test]
    fn skips_trigger_node() {
        let trigger = Uuid::new_v4();
        let other = Uuid::new_v4();
        let mut results = HashMap::new();
        results.insert(trigger, serde_json::json!({"value": "trigger-input"}));
        results.insert(other, serde_json::json!({"value": "real"}));
        let mut labels = HashMap::new();
        labels.insert(trigger, label("__trigger__"));
        labels.insert(other, label("real"));

        let obj = project_engine_results_to_output(&results, &labels);
        assert!(obj.get("__trigger__").is_none());
        assert!(obj.get("real").is_some());
    }

    #[test]
    fn skips_nodes_marked_skipped() {
        let n1 = Uuid::new_v4();
        let n2 = Uuid::new_v4();
        let mut results = HashMap::new();
        results.insert(n1, serde_json::json!({"__skipped": true, "value": 1}));
        results.insert(n2, serde_json::json!({"value": 2}));
        let mut labels = HashMap::new();
        labels.insert(n1, label("skipped"));
        labels.insert(n2, label("ran"));

        let obj = project_engine_results_to_output(&results, &labels);
        assert!(obj.get("skipped").is_none());
        assert!(obj.get("ran").is_some());
    }

    #[test]
    fn falls_back_to_uuid_string_when_label_missing() {
        let n1 = Uuid::new_v4();
        let mut results = HashMap::new();
        results.insert(n1, serde_json::json!({"value": "x"}));
        let labels = HashMap::new(); // no label registered

        let obj = project_engine_results_to_output(&results, &labels);
        assert!(obj.contains_key(&n1.to_string()));
    }

    #[test]
    fn returns_empty_map_when_no_results() {
        let results = HashMap::new();
        let labels = HashMap::new();
        let obj = project_engine_results_to_output(&results, &labels);
        assert!(obj.is_empty());
    }
}

#[cfg(test)]
mod json_string_array_tests {
    use super::json_string_array_field;
    use serde_json::json;

    #[test]
    fn extracts_string_array_field() {
        let v = json!({"hosts": ["a.com", "b.com"]});
        assert_eq!(
            json_string_array_field(&v, "hosts"),
            vec!["a.com".to_string(), "b.com".to_string()]
        );
    }

    #[test]
    fn empty_when_field_missing() {
        let v = json!({});
        assert!(json_string_array_field(&v, "hosts").is_empty());
    }

    #[test]
    fn empty_when_field_not_array() {
        let v = json!({"hosts": "not-an-array"});
        assert!(json_string_array_field(&v, "hosts").is_empty());
    }

    #[test]
    fn skips_non_string_elements() {
        let v = json!({"items": ["a", 42, true, "b", null]});
        assert_eq!(
            json_string_array_field(&v, "items"),
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn preserves_order() {
        let v = json!({"items": ["c", "a", "b"]});
        assert_eq!(
            json_string_array_field(&v, "items"),
            vec!["c".to_string(), "a".to_string(), "b".to_string()]
        );
    }
}

#[cfg(test)]
mod json_optional_string_tests {
    use super::json_optional_string;
    use serde_json::json;

    #[test]
    fn extracts_string_field() {
        let v = json!({"name": "alice"});
        assert_eq!(json_optional_string(&v, "name"), Some("alice".to_string()));
    }

    #[test]
    fn none_when_field_missing() {
        let v = json!({});
        assert_eq!(json_optional_string(&v, "name"), None);
    }

    #[test]
    fn none_when_field_not_string() {
        let v = json!({"name": 42});
        assert_eq!(json_optional_string(&v, "name"), None);
        let v = json!({"name": null});
        assert_eq!(json_optional_string(&v, "name"), None);
        let v = json!({"name": ["arr"]});
        assert_eq!(json_optional_string(&v, "name"), None);
    }

    #[test]
    fn empty_string_round_trips() {
        let v = json!({"name": ""});
        assert_eq!(json_optional_string(&v, "name"), Some(String::new()));
    }

    #[test]
    fn works_inside_filter_map_over_array() {
        let edges = json!([
            {"source": "a", "target": "b"},
            {"target": "c"},
            {"source": 42, "target": "d"},
            {"source": "e", "target": "f"},
        ]);
        let arr = edges.as_array().unwrap();
        let sources: Vec<String> = arr
            .iter()
            .filter_map(|e| json_optional_string(e, "source"))
            .collect();
        assert_eq!(sources, vec!["a".to_string(), "e".to_string()]);
    }
}

#[cfg(test)]
mod optional_uuid_tests {
    use super::optional_uuid;
    use serde_json::json;

    const VALID: &str = "00000000-0000-0000-0000-000000000001";

    #[test]
    fn parses_valid_uuid() {
        let v = json!({"workflow_id": VALID});
        assert_eq!(
            optional_uuid(&v, "workflow_id"),
            Some(uuid::Uuid::parse_str(VALID).unwrap())
        );
    }

    #[test]
    fn none_when_field_missing() {
        let v = json!({});
        assert_eq!(optional_uuid(&v, "workflow_id"), None);
    }

    #[test]
    fn none_when_field_not_string() {
        let v = json!({"workflow_id": 42});
        assert_eq!(optional_uuid(&v, "workflow_id"), None);
        let v = json!({"workflow_id": null});
        assert_eq!(optional_uuid(&v, "workflow_id"), None);
    }

    #[test]
    fn none_when_string_not_uuid() {
        let v = json!({"workflow_id": "not-a-uuid"});
        assert_eq!(optional_uuid(&v, "workflow_id"), None);
        let v = json!({"workflow_id": ""});
        assert_eq!(optional_uuid(&v, "workflow_id"), None);
    }

    #[test]
    fn accepts_uuid_with_braces_or_urn() {
        // uuid::Uuid::parse_str accepts hyphenated, simple, braced, urn forms.
        let v = json!({"workflow_id": "{00000000-0000-0000-0000-000000000001}"});
        assert!(optional_uuid(&v, "workflow_id").is_some());
        let v = json!({"workflow_id": "00000000000000000000000000000001"});
        assert!(optional_uuid(&v, "workflow_id").is_some());
    }
}

#[cfg(test)]
mod parse_optional_uuid_strict_tests {
    use super::parse_optional_uuid_strict;
    use serde_json::json;

    const VALID: &str = "00000000-0000-0000-0000-000000000001";

    fn err_text(resp: &talos_mcp::JsonRpcResponse) -> String {
        resp.result
            .as_ref()
            .and_then(|r| r["content"][0]["text"].as_str())
            .map(String::from)
            .unwrap_or_default()
    }

    #[test]
    fn absent_returns_ok_none() {
        let v = json!({});
        assert_eq!(parse_optional_uuid_strict(&v, "x", &None).unwrap(), None);
    }

    #[test]
    fn explicit_null_returns_ok_none() {
        let v = json!({"x": serde_json::Value::Null});
        assert_eq!(parse_optional_uuid_strict(&v, "x", &None).unwrap(), None);
    }

    #[test]
    fn valid_uuid_returns_ok_some() {
        let v = json!({"x": VALID});
        let got = parse_optional_uuid_strict(&v, "x", &None).unwrap();
        assert_eq!(got, Some(uuid::Uuid::parse_str(VALID).unwrap()));
    }

    #[test]
    fn invalid_uuid_string_is_rejected() {
        let v = json!({"x": "not-a-uuid"});
        let resp = parse_optional_uuid_strict(&v, "x", &None).unwrap_err();
        let text = err_text(&resp);
        assert!(text.contains("'x'"), "got: {text}");
        assert!(text.contains("valid UUID string"), "got: {text}");
        assert!(text.contains("not-a-uuid"), "got: {text}");
    }

    #[test]
    fn number_wrong_type_is_rejected() {
        let v = json!({"x": 42});
        let resp = parse_optional_uuid_strict(&v, "x", &None).unwrap_err();
        let text = err_text(&resp);
        assert!(text.contains("'x'"), "got: {text}");
        assert!(text.contains("UUID string"), "got: {text}");
        assert!(text.contains("number"), "got: {text}");
    }

    #[test]
    fn bool_wrong_type_is_rejected() {
        let v = json!({"x": true});
        let resp = parse_optional_uuid_strict(&v, "x", &None).unwrap_err();
        let text = err_text(&resp);
        assert!(text.contains("bool"), "got: {text}");
    }

    #[test]
    fn object_wrong_type_is_rejected() {
        let v = json!({"x": {"y": 1}});
        let resp = parse_optional_uuid_strict(&v, "x", &None).unwrap_err();
        let text = err_text(&resp);
        assert!(text.contains("object"), "got: {text}");
    }
}

#[cfg(test)]
mod auth_error_response_tests {
    //! Locks the wording / code mapping of [`creator_auth_error_to_response`]
    //! and [`trigger_auth_error_to_response`]. These helpers are cross-handler
    //! single-source-of-truth for two user-facing error wordings — drift
    //! shows up to MCP clients immediately, so the tests assert byte-for-byte.

    use super::{creator_auth_error_to_response, trigger_auth_error_to_response};
    use talos_workflow_authorization::{CreatorAuthError, TriggerAuthError};

    fn body(resp: &talos_mcp::JsonRpcResponse) -> (i32, String) {
        let result = resp.result.as_ref().expect("result populated");
        // allow-as-u32-cast: test helper; error codes are i16-fitting
        // RPC constants — never approach i32::MAX.
        let code = result["errorCode"].as_i64().unwrap() as i32;
        let text = result["content"][0]["text"].as_str().unwrap().to_string();
        assert_eq!(result["isError"], serde_json::Value::Bool(true));
        assert!(resp.error.is_none());
        (code, text)
    }

    // ── Creator-side ──────────────────────────────────────────────────────

    #[test]
    fn creator_actor_not_found_maps_to_minus_32002() {
        let resp = creator_auth_error_to_response(CreatorAuthError::ActorNotFoundOrInactive, None);
        let (code, text) = body(&resp);
        assert_eq!(code, -32002);
        assert_eq!(
            text,
            "Actor not found, not active, or belongs to a different user"
        );
    }

    #[test]
    fn creator_budget_exhausted_includes_limit() {
        let resp =
            creator_auth_error_to_response(CreatorAuthError::BudgetExhausted { limit: 10 }, None);
        let (code, text) = body(&resp);
        assert_eq!(code, -32000);
        assert!(text.contains("workflow limit (10)"));
        assert!(text.contains("Archive unused workflows"));
    }

    #[test]
    fn creator_capability_ceiling_includes_diagnostic_fields() {
        let module_id = uuid::Uuid::nil();
        let resp = creator_auth_error_to_response(
            CreatorAuthError::CapabilityCeilingViolation {
                module_id,
                module_world: "agent-node".to_string(),
                max_world: "automation-node".to_string(),
                req_rank: 5,
                max_rank: 3,
            },
            None,
        );
        let (code, text) = body(&resp);
        assert_eq!(code, -32003);
        assert!(text.contains("Capability ceiling violation"));
        assert!(text.contains("module 00000000-0000-0000-0000-000000000000"));
        assert!(text.contains("'agent-node' world (rank 5)"));
        assert!(text.contains("ceiling 'automation-node' (rank 3)"));
        assert!(text.contains("Use a module within the 'automation-node' world"));
    }

    #[test]
    fn creator_database_degrades_to_generic_error() {
        let resp = creator_auth_error_to_response(
            CreatorAuthError::Database(anyhow::anyhow!("table workflows row lock contention")),
            None,
        );
        let (code, text) = body(&resp);
        assert_eq!(code, -32000);
        assert_eq!(text, "Database error");
        // Crucially: does NOT echo the inner Postgres detail.
        assert!(!text.contains("workflows"));
        assert!(!text.contains("row lock"));
    }

    // ── Trigger-side ──────────────────────────────────────────────────────

    #[test]
    fn trigger_archived_distinct_from_terminated() {
        let arch = trigger_auth_error_to_response(TriggerAuthError::ActorArchived, None);
        let term = trigger_auth_error_to_response(TriggerAuthError::ActorTerminated, None);
        let (code_a, text_a) = body(&arch);
        let (code_t, text_t) = body(&term);
        assert_eq!(code_a, -32000);
        assert_eq!(code_t, -32000);
        assert!(text_a.starts_with("Actor is archived"));
        assert!(text_t.starts_with("Actor is terminated"));
        assert!(text_a.contains("IRREVERSIBLE"));
        assert!(text_t.contains("IRREVERSIBLE"));
        assert_ne!(text_a, text_t);
    }

    #[test]
    fn trigger_actor_not_found_minimal_message() {
        let resp = trigger_auth_error_to_response(TriggerAuthError::ActorNotFoundOrInactive, None);
        let (code, text) = body(&resp);
        assert_eq!(code, -32000);
        assert_eq!(text, "Actor not found or access denied");
    }

    #[test]
    fn trigger_execution_denied_passes_through_message() {
        let resp = trigger_auth_error_to_response(
            TriggerAuthError::ExecutionDenied("Suspended (cooldown 60s)".to_string()),
            None,
        );
        let (code, text) = body(&resp);
        assert_eq!(code, -32000);
        assert_eq!(text, "Suspended (cooldown 60s)");
    }

    #[test]
    fn trigger_capability_ceiling_says_workflow_node_not_module() {
        let module_id = uuid::Uuid::nil();
        let resp = trigger_auth_error_to_response(
            TriggerAuthError::CapabilityCeilingViolation {
                module_id,
                module_world: "agent-node".to_string(),
                max_world: "automation-node".to_string(),
                req_rank: 5,
                max_rank: 3,
            },
            None,
        );
        let (code, text) = body(&resp);
        assert_eq!(code, -32003);
        // Trigger-time wording differs from creator-time: refers to the
        // node in the stored graph, not the module being created.
        assert!(text.contains("workflow node"));
        assert!(text.contains("Remove the node"));
        assert!(!text.contains("Use a module within"));
    }

    #[test]
    fn trigger_database_degrades_to_generic_error() {
        let resp = trigger_auth_error_to_response(
            TriggerAuthError::Database(anyhow::anyhow!("connection pool exhausted")),
            None,
        );
        let (code, text) = body(&resp);
        assert_eq!(code, -32000);
        assert_eq!(text, "Database error");
        assert!(!text.contains("connection pool"));
    }
}

#[cfg(test)]
mod parse_embedding_array_tests {
    use super::parse_embedding_array;
    use serde_json::json;

    #[test]
    fn empty_array_returns_empty_vec() {
        let arr: Vec<serde_json::Value> = vec![];
        assert_eq!(parse_embedding_array(&arr).unwrap(), Vec::<f64>::new());
    }

    #[test]
    fn all_numbers_pass_through() {
        let arr = vec![json!(1.0), json!(2), json!(-0.5), json!(0)];
        let out = parse_embedding_array(&arr).unwrap();
        assert_eq!(out, vec![1.0, 2.0, -0.5, 0.0]);
    }

    #[test]
    fn string_element_is_rejected_with_index() {
        let arr = vec![json!(1.0), json!("oops"), json!(3.0)];
        let err = parse_embedding_array(&arr).unwrap_err();
        assert!(err.contains("embedding[1]"), "got: {err}");
        assert!(err.contains("string"), "got: {err}");
    }

    #[test]
    fn null_element_is_rejected() {
        let arr = vec![json!(1.0), serde_json::Value::Null];
        let err = parse_embedding_array(&arr).unwrap_err();
        assert!(err.contains("embedding[1]"), "got: {err}");
        assert!(err.contains("null"), "got: {err}");
    }

    #[test]
    fn bool_element_is_rejected() {
        let arr = vec![json!(true), json!(1.0)];
        let err = parse_embedding_array(&arr).unwrap_err();
        assert!(err.contains("embedding[0]"), "got: {err}");
        assert!(err.contains("bool"), "got: {err}");
    }

    #[test]
    fn object_and_array_elements_rejected() {
        let arr = vec![json!({"x": 1}), json!(1.0)];
        let err = parse_embedding_array(&arr).unwrap_err();
        assert!(err.contains("embedding[0]"), "got: {err}");
        assert!(err.contains("object"), "got: {err}");

        let arr2 = vec![json!([1.0, 2.0]), json!(1.0)];
        let err2 = parse_embedding_array(&arr2).unwrap_err();
        assert!(err2.contains("embedding[0]"), "got: {err2}");
        assert!(err2.contains("array"), "got: {err2}");
    }

    #[test]
    fn first_bad_index_wins() {
        // A run with multiple bad entries should report the first one —
        // operators fix one at a time, the index ordering is what matters.
        let arr = vec![json!(1.0), json!("a"), json!(true), json!(3.0)];
        let err = parse_embedding_array(&arr).unwrap_err();
        assert!(err.contains("embedding[1]"), "got: {err}");
    }
}

#[cfg(test)]
mod json_string_array_field_strict_tests {
    use super::json_string_array_field_strict;
    use serde_json::json;

    fn err_text(resp: &talos_mcp::JsonRpcResponse) -> String {
        resp.result
            .as_ref()
            .and_then(|r| r["content"][0]["text"].as_str())
            .map(String::from)
            .unwrap_or_default()
    }

    #[test]
    fn absent_returns_ok_none() {
        let v = json!({});
        assert_eq!(
            json_string_array_field_strict(&v, "tags", &None).unwrap(),
            None
        );
    }

    #[test]
    fn explicit_null_returns_ok_none() {
        let v = json!({"tags": serde_json::Value::Null});
        assert_eq!(
            json_string_array_field_strict(&v, "tags", &None).unwrap(),
            None
        );
    }

    #[test]
    fn empty_array_returns_ok_some_empty() {
        let v = json!({"tags": []});
        assert_eq!(
            json_string_array_field_strict(&v, "tags", &None).unwrap(),
            Some(Vec::<String>::new())
        );
    }

    #[test]
    fn all_string_array_passes_through() {
        let v = json!({"tags": ["a", "b", "c"]});
        let out = json_string_array_field_strict(&v, "tags", &None)
            .unwrap()
            .unwrap();
        assert_eq!(out, vec!["a".to_string(), "b".to_string(), "c".to_string()]);
    }

    #[test]
    fn number_element_rejected_with_index() {
        let v = json!({"tags": ["a", 42, "b"]});
        let resp = json_string_array_field_strict(&v, "tags", &None).unwrap_err();
        let text = err_text(&resp);
        assert!(text.contains("tags[1]"), "got: {text}");
        assert!(text.contains("string"), "got: {text}");
        assert!(text.contains("number"), "got: {text}");
    }

    #[test]
    fn bool_element_rejected_with_index() {
        let v = json!({"tags": [true, "ok"]});
        let resp = json_string_array_field_strict(&v, "tags", &None).unwrap_err();
        let text = err_text(&resp);
        assert!(text.contains("tags[0]"), "got: {text}");
        assert!(text.contains("bool"), "got: {text}");
    }

    #[test]
    fn null_element_rejected_with_index() {
        let v = json!({"tags": ["ok", serde_json::Value::Null]});
        let resp = json_string_array_field_strict(&v, "tags", &None).unwrap_err();
        let text = err_text(&resp);
        assert!(text.contains("tags[1]"), "got: {text}");
        assert!(text.contains("null"), "got: {text}");
    }

    #[test]
    fn outer_wrong_type_rejected() {
        let v = json!({"tags": "not-an-array"});
        let resp = json_string_array_field_strict(&v, "tags", &None).unwrap_err();
        let text = err_text(&resp);
        assert!(text.contains("must be an array"), "got: {text}");
        assert!(text.contains("string"), "got: {text}");
    }

    #[test]
    fn outer_wrong_type_object_rejected() {
        let v = json!({"tags": {"a": 1}});
        let resp = json_string_array_field_strict(&v, "tags", &None).unwrap_err();
        let text = err_text(&resp);
        assert!(text.contains("must be an array"), "got: {text}");
        assert!(text.contains("object"), "got: {text}");
    }

    #[test]
    fn first_bad_index_wins() {
        // Multiple malformed entries — should error at the first one
        // so operators fix them in order, not scan the whole array
        // to find the next problem.
        let v = json!({"tags": ["ok", 42, true, "ok"]});
        let resp = json_string_array_field_strict(&v, "tags", &None).unwrap_err();
        let text = err_text(&resp);
        assert!(text.contains("tags[1]"), "got: {text}");
    }
}

#[cfg(test)]
mod name_no_control_chars_tests {
    use super::validate_name_no_control_chars;

    fn body_text(resp: &super::JsonRpcResponse) -> String {
        resp.result
            .as_ref()
            .and_then(|r| r["content"][0]["text"].as_str())
            .map(String::from)
            .unwrap_or_default()
    }

    #[test]
    fn accepts_plain_ascii() {
        assert!(validate_name_no_control_chars("X", "hello", None).is_ok());
        assert!(validate_name_no_control_chars("X", "hello world", None).is_ok());
        assert!(validate_name_no_control_chars("X", "prod-flow", None).is_ok());
    }

    #[test]
    fn accepts_tab_explicitly() {
        // Tab is the documented exception.
        assert!(validate_name_no_control_chars("X", "a\tb", None).is_ok());
    }

    #[test]
    fn rejects_null_byte() {
        let resp = validate_name_no_control_chars("Field", "ab\0cd", None).unwrap_err();
        assert!(body_text(&resp).contains("Field"));
        assert!(body_text(&resp)
            .to_lowercase()
            .contains("control characters or null"));
    }

    #[test]
    fn rejects_newline_and_cr() {
        assert!(validate_name_no_control_chars("X", "a\nb", None).is_err());
        assert!(validate_name_no_control_chars("X", "a\rb", None).is_err());
    }

    #[test]
    fn rejects_other_control_chars() {
        // U+0007 BEL — not whitespace, but a control char.
        assert!(validate_name_no_control_chars("X", "a\u{0007}b", None).is_err());
        // U+001F UNIT SEPARATOR.
        assert!(validate_name_no_control_chars("X", "a\u{001f}b", None).is_err());
    }

    #[test]
    fn field_label_is_echoed() {
        let resp = validate_name_no_control_chars("Webhook name", "x\nx", None).unwrap_err();
        assert!(body_text(&resp).starts_with("Webhook name"));
    }

    #[test]
    fn accepts_unicode_printable() {
        // Non-ASCII printable code points are fine — the rule targets
        // C0/C1 control chars and null only.
        assert!(validate_name_no_control_chars("X", "café 🦀", None).is_ok());
        assert!(validate_name_no_control_chars("X", "日本語", None).is_ok());
    }
}

#[cfg(test)]
mod multiline_description_tests {
    use super::validate_multiline_description;

    fn body_text(resp: &super::JsonRpcResponse) -> String {
        resp.result
            .as_ref()
            .and_then(|r| r["content"][0]["text"].as_str())
            .map(String::from)
            .unwrap_or_default()
    }

    #[test]
    fn absent_returns_ok_none() {
        assert_eq!(
            validate_multiline_description("X", None, 5000, "", None).unwrap(),
            None
        );
    }

    #[test]
    fn empty_string_returns_ok_none_clear_semantic() {
        // Empty string is the documented clear-field sentinel — callers
        // distinguish via explicit Some("") if they need to.
        assert_eq!(
            validate_multiline_description("X", Some(""), 5000, "", None).unwrap(),
            None
        );
    }

    #[test]
    fn whitespace_only_rejected_with_default_hint() {
        let resp =
            validate_multiline_description("Field", Some("   "), 5000, "", None).unwrap_err();
        let text = body_text(&resp);
        assert!(text.contains("Field"));
        assert!(text.contains("Omit the field to leave it blank"));
    }

    #[test]
    fn whitespace_only_rejected_with_custom_hint() {
        let resp = validate_multiline_description(
            "Field",
            Some("   "),
            5000,
            "Omit to inherit source.",
            None,
        )
        .unwrap_err();
        let text = body_text(&resp);
        assert!(text.contains("Omit to inherit source."));
    }

    #[test]
    fn trims_returned_value() {
        let got = validate_multiline_description("X", Some("  hello  "), 5000, "", None)
            .unwrap()
            .unwrap();
        assert_eq!(got, "hello");
    }

    #[test]
    fn length_check_on_trimmed_value() {
        // 5000 visible chars + 10 padding = 5010 untrimmed, but
        // trimmed is exactly the cap — should accept.
        let body = "x".repeat(5000);
        let padded = format!("   {body}   ");
        assert!(validate_multiline_description("X", Some(&padded), 5000, "", None).is_ok());
    }

    #[test]
    fn rejects_over_length_after_trim() {
        let too_long = "x".repeat(5001);
        let resp =
            validate_multiline_description("X", Some(&too_long), 5000, "", None).unwrap_err();
        let text = body_text(&resp);
        assert!(text.contains("5000"));
    }

    #[test]
    fn allows_newline_and_tab() {
        assert!(validate_multiline_description("X", Some("line1\nline2"), 5000, "", None).is_ok());
        assert!(validate_multiline_description("X", Some("col1\tcol2"), 5000, "", None).is_ok());
        assert!(validate_multiline_description("X", Some("crlf\r\n"), 5000, "", None).is_ok());
    }

    #[test]
    fn rejects_null_byte() {
        assert!(validate_multiline_description("X", Some("ab\0cd"), 5000, "", None).is_err());
    }

    #[test]
    fn rejects_other_control_chars() {
        assert!(validate_multiline_description("X", Some("ab\u{0007}cd"), 5000, "", None).is_err());
    }
}

// MCP-1226 (2026-05-18): pin the canonical-validator chokepoint at
// the persistence boundary. Pre-fix `update_node_config` with action
// `update_config` shipped caller-controlled `timeout_secs` / `retry_count`
// / `retry_backoff_ms` straight through to graph_json (live-verified
// 86400 / 9000 / 99999999). Validating at the helper closes that
// bypass AND every future graph-mutation tool inherits the contract.
#[cfg(test)]
mod ensure_graph_within_caps_tests {
    use super::ensure_graph_within_caps;

    fn body_text(resp: &super::super::types::JsonRpcResponse) -> String {
        serde_json::to_string(resp).unwrap_or_default()
    }

    #[test]
    fn accepts_empty_graph() {
        assert!(ensure_graph_within_caps("{}", &None).is_ok());
        assert!(ensure_graph_within_caps(r#"{"nodes":[],"edges":[]}"#, &None).is_ok());
    }

    #[test]
    fn accepts_within_cap_per_node() {
        let g = r#"{
            "nodes": [{
                "id": "n1",
                "data": {"timeout_secs": 600, "retry_count": 100, "retry_backoff_ms": 600000}
            }],
            "edges": []
        }"#;
        assert!(ensure_graph_within_caps(g, &None).is_ok());
    }

    #[test]
    fn rejects_over_cap_timeout_secs() {
        let g = r#"{
            "nodes": [{"id": "n1", "data": {"timeout_secs": 86400}}],
            "edges": []
        }"#;
        let err = ensure_graph_within_caps(g, &None).unwrap_err();
        let text = body_text(&err);
        assert!(text.contains("timeout_secs"), "msg: {text}");
        // The cap is 600 (MAX_NODE_TIMEOUT_SECS); error message
        // surfaces the actual offending value.
        assert!(text.contains("86400"), "msg: {text}");
    }

    #[test]
    fn rejects_over_cap_retry_count() {
        let g = r#"{
            "nodes": [{"id": "n1", "retry_count": 9000}],
            "edges": []
        }"#;
        let err = ensure_graph_within_caps(g, &None).unwrap_err();
        let text = body_text(&err);
        assert!(text.contains("retry_count"), "msg: {text}");
        assert!(text.contains("9000"), "msg: {text}");
    }

    #[test]
    fn rejects_over_cap_retry_backoff_ms() {
        let g = r#"{
            "nodes": [{"id": "n1", "retry_backoff_ms": 99999999}],
            "edges": []
        }"#;
        let err = ensure_graph_within_caps(g, &None).unwrap_err();
        let text = body_text(&err);
        assert!(text.contains("retry_backoff_ms"), "msg: {text}");
    }

    #[test]
    fn rejects_data_shape_retry_fields() {
        // Engine reads retry from EITHER top-level OR `data.retry_*`
        // — validator must catch the bypass through either shape.
        let g = r#"{
            "nodes": [{"id": "n1", "data": {"retry_count": 9000}}],
            "edges": []
        }"#;
        let err = ensure_graph_within_caps(g, &None).unwrap_err();
        let text = body_text(&err);
        assert!(text.contains("retry_count"), "msg: {text}");
    }

    #[test]
    fn rejects_workflow_level_execution_timeout() {
        let g = r#"{
            "execution_timeout_secs": 86400,
            "nodes": [],
            "edges": []
        }"#;
        let err = ensure_graph_within_caps(g, &None).unwrap_err();
        let text = body_text(&err);
        assert!(text.contains("execution_timeout_secs"), "msg: {text}");
    }

    #[test]
    fn malformed_json_passes_through() {
        // Same surface as the underlying validator — invalid JSON
        // isn't this helper's concern (the engine / parser will
        // surface the parse error elsewhere). Validator returns Ok
        // for unparseable input.
        assert!(ensure_graph_within_caps("{not json", &None).is_ok());
    }
}
