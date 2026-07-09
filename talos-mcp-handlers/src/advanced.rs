use super::types::JsonRpcResponse;
use super::utils::{check_outbound_url_no_ssrf, mcp_error, mcp_text};
use super::{auth, McpState};
use std::sync::Arc;
use uuid::Uuid;

/// MCP-1136 (2026-05-16): cache the approval-gate notification webhook
/// HTTP client at module scope so `handle_create_approval_gate` doesn't
/// rebuild it per call. Sibling site to MCP-1116, which closed the same
/// per-call-client anti-pattern in `talos-engine::approval_gate`. The
/// MCP-1110/1111/1112/1116 sweep covered the talos-search-service /
/// talos-memory / talos-execution-orchestration / talos-engine reqwest
/// builders; this is the matching site in talos-mcp-handlers.
///
/// Hot path: fires on EVERY `create_approval_gate` MCP call that supplies
/// a `notification_webhook`. Approval-heavy workflows (review queues,
/// multi-step automation with manual gates, bulk imports) fan out many
/// gate creations; pre-fix every fire rebuilt the TLS context + connection
/// pool, defeating keep-alive reuse to the operator-facing alert target
/// (PagerDuty / Slack / OpsGenie / custom incident-mgmt API).
///
/// Parameters match the pre-fix inline values byte-for-byte:
/// - `.timeout(10s)` (MCP-1034 sweep canonical)
/// - `.connect_timeout(5s)` (MCP-1034 sweep canonical — fast-fail on
///   black-holed webhook URL)
/// - `.redirect(none)` (MCP-469: outbound webhooks MUST disable redirect
///   following — a redirect-pivot SSRF beneath `check_outbound_url_no_ssrf`
///   would otherwise reach 169.254.169.254 / internal admin ports)
/// - `.user_agent("talos-approval-gate/1.0")` (operator UA classification
///   in webhook receivers)
///
/// `.expect()` on TLS-init failure matches the sibling MCP-1110/1111/
/// 1112/1116 pattern. Pre-fix `Err(e) => tracing::error!(...)` silently
/// dropped EVERY approval notification for the pod's lifetime on TLS-init
/// failure with no operator-visible signal that the notification fire was
/// broken; loud first-call panic is the better failure mode for a
/// deployment-time TLS issue.
static APPROVAL_GATE_NOTIFY_CLIENT: std::sync::LazyLock<reqwest::Client> =
    std::sync::LazyLock::new(|| {
        // L4: built via the shared helper so it carries the connect-time
        // ControllerSsrfResolver (DNS-rebinding TOCTOU close) alongside the
        // existing timeout / connect-timeout / no-redirect posture.
        crate::ssrf_resolver::build_outbound_webhook_client("talos-approval-gate/1.0").expect(
            "talos-mcp-handlers: failed to build approval-gate notification HTTP client (TLS init)",
        )
    });

/// MCP-1002 (2026-05-15): single source of truth for the
/// `query_paginated` blocklist of auth/credential/bearer-token tables.
/// Module-scoped so both the function-level runtime guard AND the
/// precompiled `BLOCKED_TABLE_RES` regex set reference the same
/// compile-time list. Pre-fix the list was duplicated between an outer
/// function-scope `const` and an inner `const TABLES` inside the
/// LazyLock initializer — a swap between the two would have escaped
/// the `debug_assert_eq!` length-only check.
pub(crate) const BLOCKED_TABLES_LIST: &[&str] = &[
    "user_sessions",
    "mcp_agents",
    "encryption_keys",
    "oauth_accounts",
    "oauth_credential",
    "refresh_tokens",
    "users",
    "secrets",
    "secret_audit_log",
    "totp_secrets",
    "auth_events",
    "admin_event_log",
    "workflow_approval_gates",
    "api_keys",
    "oauth_state_tokens",
    "user_capability_grants",
    // MCP-1009 (2026-06-23): integration/webhook tables that still hold
    // credential-class material reachable cross-tenant by this
    // platform-admin-only tool. The OAuth *plaintext* token columns were
    // already dropped (migrations 20260310001300 + 036 + 20260413000002/3),
    // so this is NOT a plaintext leak — but the surviving columns are still
    // credential-class and no single role should bulk-exfiltrate them:
    //   * `slack_integrations` — `bot_token_enc` / `access_token_enc`
    //     (AES-256-GCM ciphertext, mig 018) + a still-PLAINTEXT
    //     `verification_token VARCHAR` (mig 004, never dropped).
    //   * `webhook_triggers` (renamed from `webhook_listeners` in mig 015)
    //     — still-PLAINTEXT `verification_token TEXT NOT NULL` (the inbound
    //     webhook bearer) + `signing_secret_enc` BYTEA / `signing_key_id`
    //     (mig 20260312000200; plaintext `signing_secret` dropped in
    //     20260408000002).
    //   * `google_calendar_watch_channels` — still-PLAINTEXT
    //     `verification_token TEXT NOT NULL` (the per-channel webhook secret,
    //     mig 010_watch_channel_security).
    //   * `workspace_oci_settings` — DROPPED as dead/never-wired schema
    //     (mig 20260627120000; it had `password_encrypted`/`password_nonce`
    //     columns but no crypto code ever populated them — OCI creds come from
    //     env vars). The deny-list entry is RETAINED as forward-protection: if
    //     the per-workspace-creds feature is ever rebuilt, it stays
    //     export-blocked by default.
    // Deliberately NOT added: `gmail_integrations` and
    // `google_calendar_integrations` — both plaintext AND encrypted token
    // columns were dropped from these (036/20260310001300 +
    // 20260413000002/3); no credential-class column survives (tokens now
    // live in `integration_state` / the `secrets` table, already blocked).
    "slack_integrations",
    "webhook_triggers",
    "google_calendar_watch_channels",
    "workspace_oci_settings",
];

/// MCP-627 / MCP-1002: the precompiled per-table word-boundary regex set
/// used by `query_paginated`'s blocklist guard. Compiled ONCE (fail-closed
/// at first use if a pattern can't compile — impossible in practice since
/// patterns are `regex::escape`d over `[a-z0-9_]` strings) and shared by
/// both the runtime guard and the unit tests so the test exercises the
/// real production matcher rather than a drifting copy (Talos testing
/// convention: extract, don't shadow).
pub(crate) static BLOCKED_TABLE_RES: std::sync::LazyLock<Vec<(&'static str, regex::Regex)>> =
    std::sync::LazyLock::new(|| {
        BLOCKED_TABLES_LIST
            .iter()
            .map(|t| {
                let pattern = format!(r"(?:^|[^a-z0-9_]){}(?:$|[^a-z0-9_])", regex::escape(t));
                let re = regex::Regex::new(&pattern)
                    .expect("BUG: BLOCKED_TABLES word-boundary regex must compile");
                (*t, re)
            })
            .collect()
    });

/// Returns `Some(table)` if `query` references a blocked credential/auth
/// table (after the same lowercase + dequote normalization the handler
/// applies), else `None`. Single source of truth for the blocklist match
/// so the `query_paginated` guard and its unit tests share one code path.
pub(crate) fn blocked_table_in_query(query: &str) -> Option<&'static str> {
    // Normalize: lowercase, then strip SQL quoted identifiers so "Users"
    // / "USERS" / `"users"` are all caught.
    let unquoted = query.to_lowercase().replace('"', " ");
    for (table, re) in BLOCKED_TABLE_RES.iter() {
        if re.is_match(&unquoted) {
            return Some(table);
        }
    }
    None
}

/// MCP-205 (2026-05-08): lightweight semver-ish check.
///
/// Returns true for strings that match the MAJOR.MINOR.PATCH shape
/// optionally followed by `-prerelease` and/or `+build` segments.
/// Each segment is restricted to ASCII alphanumerics, hyphens, and
/// dots (matching the SemVer 2.0 grammar without the full
/// canonical-form parser).
///
/// The function is deliberately permissive — we don't want to
/// reject legitimate semvers like `1.0.0-alpha.1+sha.abc` — but
/// it catches the operator-typo class (`not-a-version`,
/// `latest`, `v1`) that pre-fix would persist as a marketplace
/// listing version and break sorted-version queries downstream.
/// Pull `semver` crate later if a stricter parse is needed.
fn is_plausible_semver(s: &str) -> bool {
    // Required: digits.digits.digits prefix (at least three components).
    let mut iter = s.splitn(2, ['-', '+']);
    let core = iter.next().unwrap_or("");
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    if !parts
        .iter()
        .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
    {
        return false;
    }
    // Tail (pre-release / build metadata) — alphanumerics, hyphens, dots, plus.
    if let Some(tail) = iter.next() {
        if !tail
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '+')
        {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod semver_tests {
    use super::is_plausible_semver;

    #[test]
    fn accepts_canonical() {
        for s in [
            "0.0.0",
            "1.0.0",
            "1.2.3",
            "10.20.30",
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0+sha.abc",
            "1.0.0-beta+exp.sha.5114f85",
        ] {
            assert!(is_plausible_semver(s), "should accept {s}");
        }
    }

    #[test]
    fn rejects_obvious_garbage() {
        for s in [
            "not-a-version",
            "latest",
            "v1",
            "1",
            "1.0",
            "1.0.0.0",
            "a.b.c",
            "1..0",
            "",
            "1.0.x",
        ] {
            assert!(!is_plausible_semver(s), "should reject {s:?}");
        }
    }

    #[test]
    fn rejects_v_prefix() {
        // 'v1.0.0' is a common GitHub-tag form but NOT canonical
        // semver — semver crate would reject it too. Operators
        // wanting the prefix can wrap it on the display side.
        assert!(!is_plausible_semver("v1.0.0"));
    }
}

#[cfg(test)]
mod blocked_tables_tests {
    use super::{blocked_table_in_query, BLOCKED_TABLES_LIST, BLOCKED_TABLE_RES};

    /// The runtime guard's `debug_assert_eq!` only fires in debug builds;
    /// pin the regex-set / list lockstep here so a release build can't
    /// drift either (every list entry MUST get a compiled regex).
    #[test]
    fn regex_set_matches_list_length() {
        assert_eq!(
            BLOCKED_TABLE_RES.len(),
            BLOCKED_TABLES_LIST.len(),
            "every blocked table must have a compiled word-boundary regex"
        );
    }

    /// Every table in the canonical list must be caught when referenced
    /// in a representative SELECT — guards against a list entry whose
    /// regex somehow fails to match its own name.
    #[test]
    fn every_listed_table_is_blocked() {
        for t in BLOCKED_TABLES_LIST {
            let q = format!("SELECT * FROM {t} LIMIT 10");
            assert_eq!(
                blocked_table_in_query(&q),
                Some(*t),
                "blocklist must reject a query against {t}"
            );
        }
    }

    /// MCP-1009: the four newly-added integration/webhook credential
    /// tables must be rejected — including across casing and quoted-
    /// identifier bypass attempts the normalization is meant to defeat.
    #[test]
    fn mcp_1009_integration_tables_blocked() {
        let cases: &[(&str, &str)] = &[
            ("slack_integrations", "SELECT * FROM slack_integrations"),
            (
                "slack_integrations",
                r#"SELECT verification_token FROM "Slack_Integrations""#,
            ),
            ("webhook_triggers", "SELECT * FROM webhook_triggers"),
            (
                "webhook_triggers",
                "select signing_secret_enc from WEBHOOK_TRIGGERS where id=1",
            ),
            (
                "google_calendar_watch_channels",
                "SELECT verification_token FROM google_calendar_watch_channels",
            ),
            (
                "google_calendar_watch_channels",
                r#"SELECT * FROM "GOOGLE_CALENDAR_WATCH_CHANNELS""#,
            ),
            (
                "workspace_oci_settings",
                "SELECT password_encrypted FROM workspace_oci_settings",
            ),
            (
                "workspace_oci_settings",
                "select * from Workspace_OCI_Settings",
            ),
        ];
        for (expected, query) in cases {
            assert_eq!(
                blocked_table_in_query(query),
                Some(*expected),
                "query {query:?} must be blocked as {expected}"
            );
        }
    }

    /// Negative controls: the deliberately-NOT-blocked integration tables
    /// (no credential-class column survives the token-drop migrations) and
    /// an unrelated table must pass. A substring of a blocked name (e.g.
    /// `my_workspace_oci_settings_archive`) is intentionally NOT a
    /// word-boundary match and so is allowed.
    #[test]
    fn unrelated_and_dropped_token_tables_allowed() {
        for q in [
            "SELECT * FROM gmail_integrations",
            "SELECT * FROM google_calendar_integrations",
            "SELECT * FROM workflow_executions",
            "SELECT * FROM my_workspace_oci_settings_archive",
        ] {
            assert_eq!(
                blocked_table_in_query(q),
                None,
                "query {q:?} should NOT be blocked"
            );
        }
    }
}

/// Substantive-draft predicate (M-I, 2026-05-06). Walks `graph_json`
/// once and returns `true` iff the draft has any marker of authored
/// intent — meaning the right next step is `publish_version`, NOT
/// auto-deletion.
///
/// "Substantive" means any one of:
///   * all non-structural nodes have non-empty `data` AND node_count > 0
///   * any node has `SYSTEM_PROMPT` > 200 chars
///   * any node has `OUTPUT_SCHEMA` configured
///   * any node has `retry_count` / `retry_condition` / `retry_delay_expression`
///   * any node has `description` / `skip_condition` / `continue_on_error` set
///
/// Both `session_start` (this file's session_start handler) AND
/// `get_platform_hygiene_report fix_all` consult this helper so the
/// two surfaces never disagree about which drafts are auto-deletable.
/// Without this shared predicate, fix_all would recommend deleting
/// drafts that session_start simultaneously flags as "ready for
/// publish_version" (the M-I audit finding from 2026-05-06).
/// MCP-2 / MCP-17: count non-structural nodes whose `data` field is
/// missing or empty (`{}`). This is the *coarse, cheap* readiness
/// signal used by `session_start` to summarise drafts in batch — it
/// does NOT consult the per-module config schema, so a node with
/// no required fields will still be counted as "configured" once
/// `data` has any keys at all (or, conversely, will be counted as
/// "unconfigured" if `data` is empty even when no schema fields are
/// strictly required).
///
/// `get_workflow_quickstart` performs the strict per-schema
/// required-fields check (and per-secret provisioning check). The
/// two surfaces can disagree for the same workflow: session_start
/// says "1 unconfigured node" while quickstart says "ready_to_run".
/// Both are correct in their own mode; the divergence is documented
/// inline at each call site (`unconfigured_check_mode` field) so
/// operators reading either response know which mode is reporting.
pub(crate) fn count_nodes_with_empty_data(nodes: &[serde_json::Value]) -> usize {
    nodes
        .iter()
        .filter(|n| {
            let is_structural = n
                .get("type")
                .and_then(|v| v.as_str())
                .map(|t| t.starts_with("system:"))
                .unwrap_or(false);
            !is_structural
                && n.get("data")
                    .map(|d| d == &serde_json::json!({}))
                    .unwrap_or(true)
        })
        .count()
}

pub(crate) fn is_substantive_workflow(graph_json: Option<&str>) -> bool {
    let Some(g) = graph_json else { return false };
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(g) else {
        return false;
    };
    let nodes = match parsed.get("nodes").and_then(|n| n.as_array()) {
        Some(n) if !n.is_empty() => n,
        _ => return false,
    };

    // Branch 1: all non-structural nodes are configured.
    if count_nodes_with_empty_data(nodes) == 0 {
        return true;
    }

    // Branch 2: any node has a thoughtful authored marker.
    nodes.iter().any(|n| {
        let data = n.get("data");
        let prompt_len = data
            .and_then(|d| d.get("SYSTEM_PROMPT"))
            .and_then(|v| v.as_str())
            .map(str::len)
            .unwrap_or(0);
        let has_output_schema = data
            .and_then(|d| d.get("OUTPUT_SCHEMA"))
            .map(|v| !v.is_null())
            .unwrap_or(false);
        let has_retry = n.get("retry_count").is_some()
            || n.get("retry_condition").is_some()
            || n.get("retry_delay_expression").is_some();
        let has_per_node_meta = n.get("description").is_some()
            || n.get("skip_condition").is_some()
            || n.get("continue_on_error").is_some();
        prompt_len > 200 || has_output_schema || has_retry || has_per_node_meta
    })
}

#[cfg(test)]
mod count_nodes_with_empty_data_tests {
    use super::count_nodes_with_empty_data;

    fn nodes(json: &str) -> Vec<serde_json::Value> {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn empty_input_is_zero() {
        assert_eq!(count_nodes_with_empty_data(&[]), 0);
    }

    #[test]
    fn structural_nodes_never_count() {
        let n = nodes(r#"[{"type":"system:collect"},{"type":"system:trigger"}]"#);
        assert_eq!(count_nodes_with_empty_data(&n), 0);
    }

    #[test]
    fn missing_data_field_counts() {
        let n = nodes(r#"[{"type":"http"}]"#);
        assert_eq!(count_nodes_with_empty_data(&n), 1);
    }

    #[test]
    fn empty_data_object_counts() {
        let n = nodes(r#"[{"type":"http","data":{}}]"#);
        assert_eq!(count_nodes_with_empty_data(&n), 1);
    }

    #[test]
    fn data_with_any_keys_does_not_count() {
        let n = nodes(r#"[{"type":"http","data":{"url":"x"}}]"#);
        assert_eq!(count_nodes_with_empty_data(&n), 0);
    }

    #[test]
    fn divergence_with_quickstart_is_documented() {
        // MCP-2 / MCP-17 regression test: a node whose schema has zero
        // required fields and zero data → quickstart says ready_to_run=true,
        // session_start says unconfigured_node_count=1. This is the
        // documented divergence.
        let n = nodes(r#"[{"type":"echo","data":{}}]"#);
        assert_eq!(count_nodes_with_empty_data(&n), 1);
    }
}

#[cfg(test)]
mod is_substantive_workflow_tests {
    use super::is_substantive_workflow;

    #[test]
    fn none_or_invalid_json_is_not_substantive() {
        assert!(!is_substantive_workflow(None));
        assert!(!is_substantive_workflow(Some("not json")));
        assert!(!is_substantive_workflow(Some("{}")));
        assert!(!is_substantive_workflow(Some(r#"{"nodes":[]}"#)));
    }

    #[test]
    fn all_configured_nodes_are_substantive() {
        let g = r#"{"nodes":[{"type":"http","data":{"url":"x"}},{"type":"system:collect"}]}"#;
        assert!(is_substantive_workflow(Some(g)));
    }

    #[test]
    fn long_system_prompt_is_substantive() {
        let prompt = "x".repeat(250);
        let g = format!(r#"{{"nodes":[{{"type":"llm","data":{{"SYSTEM_PROMPT":"{prompt}"}}}}]}}"#);
        assert!(is_substantive_workflow(Some(&g)));
    }

    #[test]
    fn short_prompt_with_no_other_marker_is_not_substantive() {
        let g = r#"{"nodes":[{"type":"llm","data":{"SYSTEM_PROMPT":"short"}}]}"#;
        // Node is configured (non-empty data) so this DOES count as substantive
        // via the "all non-structural nodes configured" branch.
        assert!(is_substantive_workflow(Some(g)));
    }

    #[test]
    fn empty_data_only_node_is_not_substantive() {
        let g = r#"{"nodes":[{"type":"llm","data":{}}]}"#;
        assert!(!is_substantive_workflow(Some(g)));
    }

    #[test]
    fn output_schema_marker_is_substantive() {
        let g = r#"{"nodes":[{"type":"llm","data":{"OUTPUT_SCHEMA":{"foo":"bar"}}}]}"#;
        assert!(is_substantive_workflow(Some(g)));
    }

    #[test]
    fn retry_marker_is_substantive() {
        let g = r#"{"nodes":[{"type":"llm","data":{},"retry_count":3}]}"#;
        assert!(is_substantive_workflow(Some(g)));
    }

    #[test]
    fn description_marker_is_substantive() {
        let g = r#"{"nodes":[{"type":"llm","data":{},"description":"why"}]}"#;
        assert!(is_substantive_workflow(Some(g)));
    }
}

pub fn tool_schemas() -> Vec<serde_json::Value> {
    let worlds_csv = crate::capability_worlds::compilable_worlds_csv();
    let worlds_enum: Vec<&str> = crate::capability_worlds::compilable_worlds().to_vec();
    vec![
        serde_json::json!({
            "name": "session_start",
            "description": "Run at the start of each session. Returns a consolidated health snapshot: embedding coverage (auto-healed in background when gaps detected), unresolved draft blockers, upcoming scheduled runs, and the single most impactful next action. Replaces calling generate_workflow_embeddings + get_platform_hygiene_report + list_schedules separately. Per-draft 'unconfigured_node_count' is a coarse data-presence check (cheap, batch over 5 drafts) — for the strict required-fields-by-schema check on a single workflow call get_workflow_quickstart instead. The two checks can disagree; see each surface's 'unconfigured_check_mode' / 'ready_check_mode' label.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "auto_archive_stale_days": {
                        "type": "integer",
                        "description": "When set, automatically archive draft workflows that have never been published or executed and are older than this many days. Recommended range: 7–30. Omit to skip auto-archiving."
                    }
                }
            }
        }),
        serde_json::json!({
            "name": "query_paginated",
            "description": "Execute a SQL query with pagination support. Returns results with page metadata. \
                Runs against the platform DB pool (not subject to WASM memory limits). \
                Requires admin capability ('*' or 'admin') — non-admin agents receive a -32601 error. \
                Security controls enforced: SELECT-only (no INSERT/UPDATE/DELETE/DDL), no semicolons, \
                no UNION/INTERSECT/EXCEPT, no CTEs, no EXPLAIN, no SQL comments. \
                Access to auth/encryption tables (user_sessions, mcp_agents, encryption_keys, \
                oauth_accounts, refresh_tokens, secret_audit_log) and system schemas is blocked. \
                Queries are NOT automatically user-scoped — admin queries see all tenants' data. \
                Supports optional cursor-based pagination for efficient large-offset queries.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "SQL SELECT query to execute (SELECT only — no modifications, no CTEs, no UNION, no semicolons)" },
                    "page_size": { "type": "number", "description": "Number of rows per page (default: 100, max: 1000)" },
                    "page": { "type": "number", "description": "Page number, 1-indexed (default: 1). Ignored when cursor_column is provided." },
                    "cursor_column": { "type": "string", "description": "Column name for cursor-based pagination (e.g. 'id'). Must be alphanumeric/underscore only." },
                    "cursor_after": { "type": "string", "description": "Value to page after (rows with cursor_column > cursor_after are returned). Requires cursor_column." }
                },
                "required": ["query"]
            }
        }),
        serde_json::json!({
            "name": "create_scratch_session",
            "description": "Create or update a named scratch session (persistent sandbox). Code is stored for later re-execution.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": { "type": "string", "description": "Unique session name" },
                    "code": { "type": "string", "description": "Rust source code with pub fn run(input: String) -> Result<String, String>" },
                    "capability_world": {
                        "type": "string",
                        "enum": worlds_enum.clone(),
                        "description": format!("Capability world for the scratch session (default: 'minimal-node'). Options: {}. Both short form ('minimal') and suffixed form ('minimal-node') are accepted.", worlds_csv)
                    }
                },
                "required": ["name", "code"]
            }
        }),
        serde_json::json!({
            "name": "run_scratch_session",
            "description": "Execute a named scratch session. Optionally update the code before running.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": { "type": "string", "description": "Session name to run" },
                    "input": { "type": "object", "description": "Input data passed to the run function" },
                    "code": { "type": "string", "description": "Optional: update code before running" }
                },
                "required": ["name"]
            }
        }),
        serde_json::json!({
            "name": "list_scratch_sessions",
            "description": "List all named scratch sessions for the current user.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
        serde_json::json!({
            "name": "delete_scratch_session",
            "description": "Delete a named scratch session.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": { "type": "string", "description": "Session name to delete" }
                },
                "required": ["name"]
            }
        }),
        serde_json::json!({
            "name": "get_archive_policy",
            "description": "Get the current execution archive policy (how many days before executions are archived).",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
        serde_json::json!({
            "name": "set_archive_policy",
            "description": "Set the execution archive policy (how many days before executions are archived).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "days": { "type": "number", "description": "Archive executions older than this many days (min: 7, max: 365)" }
                },
                "required": ["days"]
            }
        }),
        serde_json::json!({
            "name": "archive_executions",
            "description": "Manually archive old completed/failed/cancelled workflow executions to the archive table. Pinned executions are never archived.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "older_than_days": {
                        "type": "number",
                        "description": "Archive executions older than this many days (default: 30, minimum: 7)"
                    }
                }
            }
        }),
        serde_json::json!({
            "name": "list_archived_executions",
            "description": "List archived workflow executions from the archive table.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": {
                        "type": "string",
                        "description": "Optional: filter by workflow UUID"
                    },
                    "limit": {
                        "type": "number",
                        "description": "Maximum number of results (default: 20, max: 100)"
                    }
                }
            }
        }),
        serde_json::json!({
            "name": "publish_to_marketplace",
            "description": "Publish a compiled module to the shared marketplace for others to discover and install.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "module_id": { "type": "string", "description": "UUID of the compiled module to publish" },
                    "description": { "type": "string", "description": "Description of what the module does" },
                    "tags": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Optional tags for discoverability (e.g. ['http', 'parser', 'csv'])"
                    },
                    "version": { "type": "string", "description": "Semver version string (default: '1.0.0')" }
                },
                "required": ["module_id", "description"]
            }
        }),
        serde_json::json!({
            "name": "search_marketplace",
            "description": "Search the module marketplace. Filter by name, capability world, or tag. Results ordered by download count.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "Search by module name (case-insensitive substring match)" },
                    "capability_world": { "type": "string", "description": "Filter by capability world — short form ('http', 'database') or suffixed form ('http-node', 'database-node'). Both are accepted." },
                    "tag": { "type": "string", "description": "Filter by tag" }
                },
            }
        }),
        serde_json::json!({
            "name": "install_from_marketplace",
            "description": "Install a module from the marketplace into your workspace. Creates a new compiled module from the published source.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "listing_id": { "type": "string", "description": "UUID of the marketplace listing to install" }
                },
                "required": ["listing_id"]
            }
        }),
        serde_json::json!({
            "name": "get_marketplace_stats",
            "description": "Get marketplace overview statistics: total listings, total downloads, unique publishers, and top 5 most downloaded modules.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
        serde_json::json!({
            "name": "create_approval_gate",
            "description": "Create a human-in-the-loop approval checkpoint. Returns a unique approval URL \
                that a human can visit to approve or reject. Optionally links to a continuation workflow \
                triggered automatically on approval. When notification_webhook is set, an HTTP POST is \
                fired immediately after gate creation so reviewers are notified without polling — \
                use test_approval_webhook to verify the endpoint first. \
                Security: the approve_url and reject_url are secured with a 256-bit cryptographically \
                random token embedded in the path — the token IS the bearer credential, no additional \
                auth is required. URLs expire when the gate reaches expires_in_hours and cannot be \
                replayed after the gate is resolved.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "title": { "type": "string", "description": "Short human-readable title shown on the approval page (max 200 chars)" },
                    "description": { "type": "string", "description": "Detailed explanation of what is being approved and why" },
                    "payload": { "type": "object", "description": "Arbitrary JSON data to store with the gate. On approval, this payload is passed as input to the continuation workflow (if set)." },
                    "continuation_workflow_id": { "type": "string", "description": "Optional UUID of a workflow to trigger automatically when this gate is approved. The gate payload is passed as the workflow input." },
                    "expires_in_hours": { "type": "number", "description": "How long the gate stays open in hours (default: 168 / 7 days, max: 720 / 30 days)" },
                    "notification_webhook": { "type": "string", "description": "Optional HTTPS URL to POST approval-required notification to when the gate is created. The payload includes approve_url, reject_url, title, and gate_id. Without this, reviewers must poll list_approval_gates." }
                },
                "required": ["title"]
            }
        }),
        serde_json::json!({
            "name": "list_approval_gates",
            "description": "List approval gate records for the current user — the broad audit surface for actor-bound approval policies (every gate that has ever been created, with all statuses: pending / approved / rejected / expired / cancelled). NOTE: list_pending_approvals is the narrower operator-action surface for execution-blocking approvals only. Use list_approval_gates(status='pending') when you want pending gates AND want to compare against history; use list_pending_approvals when you only need 'what's blocking right now'.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "status": {
                        "type": "string",
                        "description": "Filter by status: 'pending', 'approved', 'rejected', 'expired', 'cancelled'. Omit for all.",
                        "enum": ["pending", "approved", "rejected", "expired", "cancelled"]
                    },
                    "limit": { "type": "number", "description": "Maximum results (default: 20, max: 100)" }
                }
            }
        }),
        serde_json::json!({
            "name": "resolve_approval_gate",
            "description": "Programmatically approve or reject an approval gate (e.g., by an automated validation agent). Human approvals happen via the approval URL. On approval, the continuation workflow (if configured) is triggered with the gate payload.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "gate_id": { "type": "string", "description": "UUID of the approval gate to resolve" },
                    "resolution": { "type": "string", "description": "'approve' or 'reject'", "enum": ["approve", "reject"] },
                    "note": { "type": "string", "description": "Optional reason or note for the resolution" }
                },
                "required": ["gate_id", "resolution"]
            }
        }),
        serde_json::json!({
            "name": "cancel_approval_gate",
            "description": "Cancel a pending approval gate. The gate is marked as cancelled and the continuation workflow will not be triggered.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "gate_id": { "type": "string", "description": "UUID of the pending approval gate to cancel" }
                },
                "required": ["gate_id"]
            }
        }),
        serde_json::json!({
            "name": "list_published_modules",
            "description": "List all modules published to the team marketplace. Call this BEFORE compile_custom_sandbox to check if a teammate has already built what you need.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "capability_world": {
                        "type": "string",
                        "description": "Optional: filter by capability world (e.g. 'network-node', 'database-node')"
                    },
                    "limit": {
                        "type": "number",
                        "description": "Maximum number of results (default: 50, max: 200)"
                    }
                }
            }
        }),
        serde_json::json!({
            "name": "archive_workflow",
            "description": "Archive a workflow. Archived workflows are excluded from search and discovery but are not deleted. Use this instead of batch_delete_workflows for production workflows you want to retire.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to archive" }
                },
                "required": ["workflow_id"]
            }
        }),
        // MCP-568 historical note: enable_workflow / disable_workflow
        // (round-tripping `workflows.is_enabled`, read by
        // `replay_execution`'s `is_workflow_enabled` check) were first
        // wired HERE, but `workflows.rs` grew its own advertisement +
        // dispatch arms for the same names — and since
        // `workflows::dispatch` runs before `advanced::dispatch` in
        // handle_tools_call, this module's copies were dead at runtime
        // and double-advertised in tools/list (caught by
        // schema_parity_tests, 2026-07-01). The single owner is now
        // workflows.rs; do not re-add the tools here.
        serde_json::json!({
            "name": "star_module",
            "description": "Star a marketplace module to signal that it is high-quality and tested. Stars are visible to all users via list_published_modules.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "listing_id": { "type": "string", "description": "UUID of the marketplace listing (from list_published_modules)" }
                },
                "required": ["listing_id"]
            }
        }),
        serde_json::json!({
            "name": "get_config_suggestions",
            "description": "Get AI-powered suggestions for what values to put in missing node config fields. Given a workflow and a node_id with missing required fields, analyzes the upstream data flow and suggests concrete values. Call this when get_workflow_quickstart reports missing_required fields.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" },
                    "node_id": { "type": "string", "description": "Node ID with missing config (from quickstart blockers)" }
                },
                "required": ["workflow_id", "node_id"]
            }
        }),
        serde_json::json!({
            "name": "deploy_workflow",
            "description": "Deploy a workflow to production in one step: publishes the latest version, sets status to active, and optionally creates a schedule. Combines publish_version + create_schedule into a single call. Use this to graduate a draft workflow to production.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to deploy" },
                    "cron_expression": { "type": "string", "description": "Optional 5-field cron expression for scheduling (e.g. '0 9 * * 1-5'). Omit to publish without a schedule." },
                    "timezone": { "type": "string", "description": "Timezone for the schedule (default: UTC)" },
                    "version_description": { "type": "string", "description": "Optional description for the published version" }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "promote_workflow",
            "description": "Clone a workflow and promote it to production with optional config overrides (e.g. staging URL → production URL). Useful for staging→production pipelines. Creates a new workflow, optionally publishes it, and optionally schedules it.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the source workflow to promote" },
                    "target_name": { "type": "string", "description": "Name for the new workflow (defaults to '<original_name> (Production)')" },
                    "config_overrides": { "type": "object", "description": "Map of node_label → {FIELD: value} to override config in specific nodes. The key is the node's module label (the display name shown in the workflow graph), NOT the node_id string. Labels are not guaranteed unique — if multiple nodes share the same label, all will receive the override. Use duplicate_workflow.modifications.patch_node_configs (keyed by node_id) when precise single-node targeting is required. Example: {\"Fetch\": {\"URL\": \"https://api.prod.example.com\"}}" },
                    "publish": { "type": "boolean", "description": "Whether to publish the cloned workflow immediately (default: true)" },
                    "cron_expression": { "type": "string", "description": "Optional cron expression to schedule the promoted workflow" },
                    "timezone": { "type": "string", "description": "Timezone for the schedule (default: UTC). Use IANA identifier like 'UTC', 'America/New_York', 'Europe/London'." }
                },
                "required": ["workflow_id"]
            }
        }),
        // ── Round 43: SLA threshold alerts ────────────────────────────────
        serde_json::json!({
            "name": "set_workflow_sla_threshold",
            "description": "Set SLA breach alert thresholds for a workflow. When the background monitor \
                detects a breach (p95 latency > p95_latency_ms or success rate < success_rate_pct over \
                the last 24 hours), an HTTP POST is fired to notification_webhook if configured. \
                At least one of p95_latency_ms or success_rate_pct must be provided. \
                Thresholds without a notification_webhook are still visible in get_workflow_sla_report \
                and list_workflow_sla_thresholds — useful for API-polled monitoring stacks.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to monitor" },
                    "p95_latency_ms": { "type": "number", "description": "Alert if p95 latency (ms) exceeds this value. At least one of p95_latency_ms or success_rate_pct is required." },
                    "success_rate_pct": { "type": "number", "description": "Alert if success rate (%) falls below this value (0–100). At least one of p95_latency_ms or success_rate_pct is required." },
                    "notification_webhook": { "type": "string", "description": "Optional HTTPS URL to POST the breach event to. Omit to configure thresholds for API polling only (get_workflow_sla_report / list_workflow_sla_thresholds)." }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "list_workflow_sla_thresholds",
            "description": "List all SLA threshold configurations for the current user's workflows.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
        serde_json::json!({
            "name": "publish_built_in_templates",
            "description": "Publish all built-in node templates to the module marketplace that are not already listed. Requires admin capability ('*' or 'admin'). Idempotent — safe to call multiple times. Returns the count of newly published listings. Use this after deploying new module templates to make them discoverable in the marketplace without restarting the service.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
        serde_json::json!({
            "name": "test_sla_webhook",
            "description": "Fire a synthetic SLA breach event to the configured notification_webhook for a workflow. \
                Confirms the endpoint is reachable and accepts the expected payload format before a real breach \
                occurs. Returns the HTTP status code and response preview. The workflow must have a configured \
                SLA threshold (set via set_workflow_sla_threshold).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow with a configured SLA threshold" }
                },
                "required": ["workflow_id"]
            }
        }),
        // ── Suspend / Resume ──────────────────────────────────────────────
        serde_json::json!({
            "name": "create_workflow_suspension",
            "description": "Create a workflow suspension checkpoint. Returns a unique callback_url that \
                an external system can POST to in order to resume execution. The correlation_id (256-bit random) \
                IS the bearer token — no additional auth required on the callback endpoint. \
                Optionally link a continuation_workflow_id to be triggered automatically on resume.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "description": { "type": "string", "description": "Human-readable description of why execution is paused" },
                    "continuation_workflow_id": { "type": "string", "description": "Optional UUID of a workflow to trigger automatically when the suspension is resumed" },
                    "state": { "type": "object", "description": "Optional JSON state to store with the suspension (passed to continuation workflow on resume)" },
                    "timeout_hours": { "type": "number", "description": "Optional timeout in hours. If the suspension is not resumed before this time, it is marked 'expired'." }
                }
            }
        }),
        serde_json::json!({
            "name": "list_workflow_suspensions",
            "description": "List workflow suspensions for the current user.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "status": { "type": "string", "description": "Filter by status: waiting | resumed | expired | cancelled. Omit for all." }
                }
            }
        }),
        serde_json::json!({
            "name": "resume_workflow_by_correlation_id",
            "description": "Programmatically resume a waiting workflow suspension. \
                Triggers the continuation workflow (if configured) with the provided payload.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "correlation_id": { "type": "string", "description": "The 64-hex-char correlation ID of the suspension" },
                    "payload": { "type": "object", "description": "Optional JSON payload to pass to the continuation workflow" }
                },
                "required": ["correlation_id"]
            }
        }),
        serde_json::json!({
            "name": "cancel_workflow_suspension",
            "description": "Cancel a waiting workflow suspension. The continuation workflow will not be triggered.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "correlation_id": { "type": "string", "description": "The 64-hex-char correlation ID of the suspension" }
                },
                "required": ["correlation_id"]
            }
        }),
        serde_json::json!({
            "name": "test_approval_webhook",
            "description": "Fire a synthetic approval_required notification to an approval gate's configured \
                notification_webhook. Confirms the endpoint is reachable and accepts the expected payload \
                before a real gate is created. Returns HTTP status code and response preview. \
                The gate must have been created with a notification_webhook parameter. \
                Use this before relying on out-of-band approval notifications in production.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "gate_id": { "type": "string", "description": "UUID of an existing approval gate that has a notification_webhook configured" }
                },
                "required": ["gate_id"]
            }
        }),
    ]
}

pub async fn dispatch(
    name: &str,
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> Option<JsonRpcResponse> {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    // MCP-323/324/325/326/327: the deployment-wide admin handlers
    // (`query_paginated`, `set_archive_policy`, `publish_built_in_templates`,
    // plus cross-file siblings) now do their own
    // `is_platform_admin(user_id)` DB check, so the agent-level
    // `is_admin()` capability is no longer consulted here.
    match name {
        "query_paginated" => Some(handle_query_paginated(req_id, args, state, user_id).await),
        "create_scratch_session" => {
            Some(handle_create_scratch_session(req_id, args, state, user_id).await)
        }
        "run_scratch_session" => {
            Some(handle_run_scratch_session(req_id, args, state, user_id).await)
        }
        "list_scratch_sessions" => Some(handle_list_scratch_sessions(req_id, state, user_id).await),
        "delete_scratch_session" => {
            Some(handle_delete_scratch_session(req_id, args, state, user_id).await)
        }
        "get_archive_policy" => Some(handle_get_archive_policy(req_id, state).await),
        "set_archive_policy" => Some(handle_set_archive_policy(req_id, args, state, user_id).await),
        "archive_executions" => Some(handle_archive_executions(req_id, args, state, user_id).await),
        "list_archived_executions" => {
            Some(handle_list_archived_executions(req_id, args, state, user_id).await)
        }
        "publish_to_marketplace" => {
            Some(handle_publish_to_marketplace(req_id, args, state, user_id).await)
        }
        "search_marketplace" => Some(handle_search_marketplace(req_id, args, state).await),
        "install_from_marketplace" => {
            Some(handle_install_from_marketplace(req_id, args, state, user_id).await)
        }
        "get_marketplace_stats" => Some(handle_get_marketplace_stats(req_id, state).await),
        "create_approval_gate" => {
            Some(handle_create_approval_gate(req_id, args, state, user_id).await)
        }
        "list_approval_gates" => {
            Some(handle_list_approval_gates(req_id, args, state, user_id).await)
        }
        "resolve_approval_gate" => {
            Some(handle_resolve_approval_gate(req_id, args, state, user_id).await)
        }
        "cancel_approval_gate" => {
            Some(handle_cancel_approval_gate(req_id, args, state, user_id).await)
        }
        "list_published_modules" => Some(handle_list_published_modules(req_id, args, state).await),
        "archive_workflow" => Some(handle_archive_workflow(req_id, args, state, user_id).await),
        // enable_workflow / disable_workflow live in workflows.rs (see the
        // MCP-568 historical note in tool_schemas above) — arms here would
        // be dead code because workflows::dispatch runs first.
        "star_module" => Some(handle_star_module(req_id, args, state, user_id).await),
        "get_config_suggestions" => {
            Some(handle_get_config_suggestions(req_id, args, state, user_id).await)
        }
        "session_start" => Some(handle_agent_session_start(req_id, args, state, user_id).await),
        "agent_session_start" => {
            // Deprecated alias — same handler, deprecation notice injected
            let resp = handle_agent_session_start(req_id.clone(), args, state, user_id).await;
            Some(crate::actor::inject_deprecation_pub(
                resp,
                "agent_session_start",
                "session_start",
            ))
        }
        "deploy_workflow" => Some(handle_deploy_workflow(req_id, args, state, user_id).await),
        "promote_workflow" => Some(handle_promote_workflow(req_id, args, state, user_id).await),
        "set_workflow_sla_threshold" => {
            Some(handle_set_workflow_sla_threshold(req_id, args, state, user_id).await)
        }
        "list_workflow_sla_thresholds" => {
            Some(handle_list_workflow_sla_thresholds(req_id, state, user_id).await)
        }
        "publish_built_in_templates" => {
            Some(handle_publish_built_in_templates(req_id, state, user_id).await)
        }
        "test_sla_webhook" => Some(handle_test_sla_webhook(req_id, args, state, user_id).await),
        "test_approval_webhook" => {
            Some(handle_test_approval_webhook(req_id, args, state, user_id).await)
        }
        // ── Suspend / Resume ──────────────────────────────────────────────
        "create_workflow_suspension" => {
            Some(handle_create_workflow_suspension(req_id, args, state, user_id).await)
        }
        "list_workflow_suspensions" => {
            Some(handle_list_workflow_suspensions(req_id, args, state, user_id).await)
        }
        "resume_workflow_by_correlation_id" => {
            Some(handle_resume_workflow_by_correlation_id(req_id, args, state, user_id).await)
        }
        "cancel_workflow_suspension" => {
            Some(handle_cancel_workflow_suspension(req_id, args, state, user_id).await)
        }
        _ => None,
    }
}

async fn handle_query_paginated(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // SECURITY: Arbitrary SELECT access to the platform DB returns rows
    // across all tenants — every workflow, every execution, every alert.
    // MCP-323 (2026-05-11): pre-fix the gate was the agent-level
    // `is_admin` capability (per-tenant admin role). In a multi-tenant
    // deployment, an organization-scoped admin agent passes that check
    // but their admin authority is scoped to their own org; arbitrary
    // SELECT would let them read every other tenant's row. Same
    // require_platform_admin family as pause/resume_executions. Use
    // `ActorRepository::is_platform_admin(user_id)` — the
    // `users.is_platform_admin` column flagged for deployment-wide
    // operators only.
    //
    // Non-admin agents must use the user-scoped query tools
    // (list_workflows, list_executions, etc.) which enforce
    // `WHERE user_id = $N`.
    let is_platform_admin = state
        .actor_repo
        .is_platform_admin(user_id)
        .await
        .unwrap_or(false);
    if !is_platform_admin {
        return mcp_error(
            req_id,
            -32601,
            "query_paginated requires platform-admin privileges. \
             Arbitrary SELECT spans all tenants — use list_workflows / \
             list_executions / search_workflows for user-scoped reads instead.",
        );
    }

    let query_str = match args.get("query").and_then(|v| v.as_str()) {
        Some(q) if q.len() > 10_000 => {
            return mcp_error(req_id, -32602, "query must be ≤ 10 000 characters")
        }
        Some(q) if !q.is_empty() => q,
        _ => return mcp_error(req_id, -32602, "Missing or empty 'query' parameter"),
    };

    // Validate: only SELECT queries allowed
    let trimmed = query_str.trim();
    if !trimmed.to_uppercase().starts_with("SELECT") {
        return mcp_error(req_id, -32602, "Only SELECT queries are allowed");
    }

    // SECURITY: Reject queries containing semicolons (prevent statement chaining)
    if trimmed.contains(';') {
        return mcp_error(req_id, -32602, "Query must not contain semicolons");
    }

    // SECURITY: Block dangerous SQL constructs
    let query_upper = trimmed.to_uppercase();
    if query_upper.contains("UNION")
        || query_upper.contains("INTERSECT")
        || query_upper.contains("EXCEPT")
    {
        return mcp_error(
            req_id,
            -32602,
            "Query cannot contain UNION, INTERSECT, or EXCEPT clauses",
        );
    }
    if trimmed.contains("--") || trimmed.contains("/*") {
        return mcp_error(req_id, -32602, "Query cannot contain SQL comments");
    }

    // SECURITY: Block CTEs and EXPLAIN which can reveal schema or bypass table restrictions
    if query_upper.starts_with("WITH ") {
        return mcp_error(req_id, -32602, "CTEs (WITH ... AS) are not allowed");
    }
    if query_upper.starts_with("EXPLAIN") {
        return mcp_error(req_id, -32602, "EXPLAIN queries are not allowed");
    }

    // SECURITY: Block access to sensitive auth/credential tables and system schemas.
    // Note: blocklist approach is defence-in-depth; this tool is already admin-only.
    // Matching uses word-boundary regex to avoid bypasses via quoting, casing, or aliases.
    //
    // MCP-1002 (2026-05-15): four tables added to the blocklist —
    //   * `workflow_approval_gates` — the `token` column IS the bearer
    //     auth for `approval_gate_handler`. Anyone holding the
    //     64-hex-char token can approve/reject the corresponding
    //     workflow gate (no session, no API key). A platform admin
    //     listing rows from this table would gain consent-bypass over
    //     every pending approval gate across all tenants.
    //   * `api_keys` — `key_hash` is bcrypt'd but `key_prefix`,
    //     `user_id`, `scopes`, `expires_at`, `last_used_at` collectively
    //     form a reconnaissance set: who has admin scope across which
    //     tenants, which keys are stale-but-active, etc. Same blocklist
    //     class as the rest of the credential family.
    //   * `oauth_state_tokens` — `pkce_verifier` is short-lived (10 min
    //     TTL, consumed-on-first-use) credential material. Reading
    //     in-flight verifiers would let an attacker who's already
    //     intercepted the OAuth callback URL complete the
    //     code-for-token exchange.
    //   * `user_capability_grants` — cross-tenant elevation enumeration
    //     surface (the QUERY counterpart of the data MCP-998 closed on
    //     the GraphQL side). Same "list every elevated user
    //     platform-wide" reconnaissance shape, just via a different
    //     tool surface.
    //
    // Sibling drift fix: pre-MCP-1002 the BLOCKED_TABLES list was
    // duplicated between an outer `const` and an inner `const TABLES`
    // inside the LazyLock initializer. The `debug_assert_eq!` only
    // checked LENGTH parity, so a swap of one table for another would
    // pass undetected. The inner duplicate is removed — the LazyLock
    // now iterates over the outer const directly. Single source of
    // truth; no length-only-comparison drift hazard.
    // MCP-1002 / MCP-627: the per-table word-boundary regex set and the
    // match predicate now live at module scope (`BLOCKED_TABLE_RES` /
    // `blocked_table_in_query`) so the runtime guard and the unit tests
    // share ONE matcher — no drifting test-local copy. The regex set is
    // compiled once (fail-closed at first use) and the list is a single
    // module-scope `const` consumed by both, so a swap of one table for
    // another can't escape a length-only `debug_assert_eq!`.
    const BLOCKED_SCHEMAS: &[&str] = &["pg_catalog", "information_schema", "pg_toast"];
    debug_assert_eq!(
        BLOCKED_TABLE_RES.len(),
        BLOCKED_TABLES_LIST.len(),
        "BLOCKED_TABLE_RES and BLOCKED_TABLES_LIST must stay in lockstep"
    );
    if let Some(table) = blocked_table_in_query(trimmed) {
        return mcp_error(
            req_id,
            -32602,
            &format!("Access to '{}' is not permitted via query_paginated", table),
        );
    }
    // Schema check reuses the same lowercase + dequote normalization.
    let unquoted = trimmed.to_lowercase().replace('"', " ");
    for schema in BLOCKED_SCHEMAS {
        if unquoted.contains(schema) {
            return mcp_error(
                req_id,
                -32602,
                &format!(
                    "Access to '{}' schema is not permitted via query_paginated",
                    schema
                ),
            );
        }
    }

    let page_size = match crate::utils::validate_range_i64(args, "page_size", 1, 1000, 100, &req_id)
    {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // MCP-357 (2026-05-11): pre-fix `.and_then(|v| v.as_str())` on
    // BOTH cursor fields silently dropped wrong-type into None. The
    // downstream `(Some(col), Some(cursor_val))` tuple match required
    // both to be Some, so an operator passing valid `cursor_column:
    // "id"` plus wrong-type `cursor_after: 42` (number) silently fell
    // through to offset-based pagination starting at page 1 — losing
    // their cursor position with no signal. Direction-class on a
    // pagination surface: operator opted IN to cursor-from-X semantics
    // and got page-1 instead. Distinguish absent / null / wrong-type
    // / valid for each field consistently.
    let cursor_column: Option<&str> = match args.get("cursor_column") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => match v.as_str() {
            Some(s) => Some(s),
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("cursor_column must be a string, got {kind}"),
                );
            }
        },
    };
    let cursor_after: Option<&str> = match args.get("cursor_after") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => match v.as_str() {
            Some(s) => Some(s),
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("cursor_after must be a string, got {kind}"),
                );
            }
        },
    };

    // SECURITY: Validate cursor_column to prevent SQL injection — only allow alphanumeric + underscore
    if let Some(col) = cursor_column {
        if col.is_empty() || !col.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return mcp_error(
                req_id,
                -32602,
                "cursor_column must contain only alphanumeric characters and underscores",
            );
        }
        if col.len() > 64 {
            return mcp_error(
                req_id,
                -32602,
                "cursor_column name too long (max 64 characters)",
            );
        }
    }
    // MCP-357: partial-cursor guard. Pre-fix passing only one of the
    // two cursor fields (e.g. `cursor_column` without `cursor_after`)
    // silently fell back to offset pagination — operator intended
    // cursor pagination starting at the beginning, got page 1 offset
    // 0. Functionally similar but the operator's deliberate use of
    // the cursor API was dropped. Reject explicitly.
    match (cursor_column, cursor_after) {
        (Some(_), None) | (None, Some(_)) => {
            return mcp_error(
                req_id,
                -32602,
                "cursor_column and cursor_after must be provided together for cursor pagination (or omit both for offset pagination)",
            )
        }
        _ => {}
    }

    let base_query = trimmed.trim_end_matches(';');

    // Handler has done all the safety validation (admin auth, SELECT-only,
    // no semicolons / UNION / INTERSECT / EXCEPT / CTEs / EXPLAIN / SQL
    // comments, blocked tables, blocked schemas, cursor_column allowlisted to
    // [a-zA-Z0-9_]). The repo's `execute_paginated_select` only owns the
    // immutable wrapper template — see its docstring for the full contract.
    // MCP-385 (2026-05-11): pre-fix `page` was parsed independently in
    // two places (offset-mode branch + response-echo block ~80 lines
    // below), both with `.and_then(as_i64).unwrap_or(1).max(1)`.
    // Wrong-type (`page: "5"` string) silently became page 1 — operator
    // got page-1 rows with no signal they had mistyped. Worse, fractional
    // floats (`page: 1.5`) and negative numbers silently clamped to 1.
    // Hoist the parse to a single strict-parsed location; both
    // downstream sites read the same variable.
    let page: i64 = match args.get("page") {
        None | Some(serde_json::Value::Null) => 1,
        Some(v) => match v.as_i64() {
            Some(n) if n >= 1 => n,
            Some(n) => {
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("page must be a positive integer (≥ 1), got {n}"),
                )
            }
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("page must be a positive integer, got {kind}"),
                );
            }
        },
    };
    let mode = if let (Some(col), Some(cursor_val)) = (cursor_column, cursor_after) {
        talos_advanced_repository::PaginationMode::Cursor {
            column: col,
            after: cursor_val,
        }
    } else {
        talos_advanced_repository::PaginationMode::Offset {
            offset: (page - 1) * page_size,
        }
    };

    let rows = state
        .advanced_repo
        .execute_paginated_select(base_query, page_size, mode)
        .await;

    match rows {
        Ok(rows) => {
            use sqlx::{Column, Row};
            let has_more = rows.len() as i64 > page_size;
            let display_rows: Vec<&sqlx::postgres::PgRow> = if has_more {
                rows.iter().take(page_size as usize).collect()
            } else {
                rows.iter().collect()
            };

            let result_rows: Vec<serde_json::Value> = display_rows
                .iter()
                .map(|row| {
                    let columns = row.columns();
                    let mut obj = serde_json::Map::new();
                    for col in columns {
                        let name = col.name().to_string();
                        // Try common types; fall back to text representation
                        let val: serde_json::Value =
                            if let Ok(v) = row.try_get::<String, _>(col.name()) {
                                serde_json::Value::String(v)
                            } else if let Ok(v) = row.try_get::<i64, _>(col.name()) {
                                serde_json::json!(v)
                            } else if let Ok(v) = row.try_get::<i32, _>(col.name()) {
                                serde_json::json!(v)
                            } else if let Ok(v) = row.try_get::<f64, _>(col.name()) {
                                serde_json::json!(v)
                            } else if let Ok(v) = row.try_get::<bool, _>(col.name()) {
                                serde_json::json!(v)
                            } else if let Ok(v) = row.try_get::<uuid::Uuid, _>(col.name()) {
                                serde_json::Value::String(v.to_string())
                            } else if let Ok(v) =
                                row.try_get::<chrono::DateTime<chrono::Utc>, _>(col.name())
                            {
                                serde_json::Value::String(v.to_rfc3339())
                            } else if let Ok(v) = row.try_get::<serde_json::Value, _>(col.name()) {
                                v
                            } else {
                                serde_json::Value::Null
                            };
                        obj.insert(name, val);
                    }
                    serde_json::Value::Object(obj)
                })
                .collect();

            let row_count = result_rows.len();

            // Build next_cursor from the last displayed row if cursor-based.
            // `cursor_column.is_some()` is the same predicate the mode-builder above
            // used to choose the Cursor variant — they always agree.
            let next_cursor = if cursor_column.is_some() && has_more {
                if let Some(col) = cursor_column {
                    result_rows
                        .last()
                        .and_then(|r| r.get(col))
                        .map(|v| match v {
                            serde_json::Value::String(s) => s.clone(),
                            other => other.to_string(),
                        })
                } else {
                    None
                }
            } else {
                None
            };

            // MCP-385 (2026-05-11): use the hoisted `page` value parsed
            // strictly above. Echoing the same number that ran prevents
            // confusion when the response shape doesn't match the
            // (silently substituted) running value.
            let mut response = serde_json::json!({
                "page": page,
                "page_size": page_size,
                "row_count": row_count,
                "has_more": has_more,
                "rows": result_rows,
            });
            if let Some(cursor_val) = next_cursor {
                if let Some(obj) = response.as_object_mut() {
                    obj.insert("next_cursor".to_string(), serde_json::json!(cursor_val));
                }
            }
            if cursor_column.is_some() {
                if let Some(obj) = response.as_object_mut() {
                    obj.insert("pagination_mode".to_string(), serde_json::json!("cursor"));
                }
            }

            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&response).unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("query_paginated failed: {}", e);
            // SECURITY: Don't leak internal query error details
            mcp_error(
                req_id,
                -32000,
                "Query execution failed. Ensure the SQL syntax is valid.",
            )
        }
    }
}

async fn handle_create_scratch_session(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // MCP-169 (2026-05-08): reject whitespace-only session names.
    // Pre-fix `!n.is_empty()` accepted "                " and persisted
    // it in upsert_scratch_session, polluting list_scratch_sessions.
    // Same family as MCP-161/163/164/165/166.
    //
    // MCP-365 (2026-05-11): pre-fix the non-empty branch returned the
    // UNTRIMMED string. Operator passing `name: "   prod-scratch   "`
    // (whitespace from copy-paste) persisted the session with
    // surrounding whitespace, then run_scratch_session("prod-scratch")
    // missed in the lookup and the operator saw "session not found".
    // Sibling fix in run_scratch_session + delete_scratch_session below
    // so all three sites trim consistently — the stored value matches
    // what the operator sees in any editor that auto-trims.
    let session_name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) if !n.trim().is_empty() => n.trim(),
        _ => {
            return mcp_error(
                req_id,
                -32602,
                "name must be a non-empty, non-whitespace string",
            )
        }
    };
    if session_name.len() > 100 {
        return mcp_error(req_id, -32602, "Session name too long (max 100 chars)");
    }
    // MCP-409/410 (2026-05-11): name-field control-char check via
    // the canonical helper. See utils::validate_name_no_control_chars.
    if let Err(resp) =
        crate::utils::validate_name_no_control_chars("Session name", session_name, req_id.clone())
    {
        return resp;
    }
    // MCP-214 (2026-05-08): pre-fix `!c.is_empty()` accepted
    // whitespace-only `code: "   "` and persisted a broken scratch
    // session that fails at run_scratch_session time with a confusing
    // compiler error. Reject whitespace at the boundary, matching
    // the same pattern as MCP-209 lint_sandbox.
    let code = match args.get("code").and_then(|v| v.as_str()) {
        Some(c) if c.trim().is_empty() => {
            return mcp_error(req_id, -32602, "code must be non-empty and non-whitespace")
        }
        Some(c) => c,
        _ => return mcp_error(req_id, -32602, "Missing or empty 'code' parameter"),
    };
    if code.len() > 100_000 {
        return mcp_error(req_id, -32602, "Code too large (max 100KB)");
    }
    // MCP-379 (2026-05-11): strict-parse sibling. Pre-fix wrong-type
    // silently became "minimal-node" — see MCP-377/378 for the
    // direction-class rationale on capability_world surfaces.
    let world = match args.get("capability_world").or_else(|| args.get("world")) {
        None | Some(serde_json::Value::Null) => "minimal-node",
        Some(v) => match v.as_str() {
            Some(s) => s,
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("capability_world must be a string (e.g. 'agent-node'), got {kind}"),
                );
            }
        },
    };
    if world.len() > 100 {
        return mcp_error(req_id, -32602, "capability_world must be ≤ 100 characters");
    }

    match state
        .advanced_repo
        .upsert_scratch_session(user_id, session_name, code, world)
        .await
    {
        Ok(()) => mcp_text(
            req_id,
            &format!(
                "Scratch session '{}' saved (world: {})",
                session_name, world
            ),
        ),
        Err(e) => {
            tracing::error!("create_scratch_session failed: {}", e);
            mcp_error(req_id, -32000, "Failed to save scratch session")
        }
    }
}

async fn handle_run_scratch_session(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // MCP-169 (2026-05-08): reject whitespace-only session names.
    // Pre-fix `!n.is_empty()` accepted "                " and persisted
    // it in upsert_scratch_session, polluting list_scratch_sessions.
    // Same family as MCP-161/163/164/165/166.
    //
    // MCP-365 (2026-05-11): trim the lookup name so operator's
    // "   prod-scratch   " matches the trimmed-on-create row from
    // the sibling create_scratch_session fix.
    let session_name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) if !n.trim().is_empty() => n.trim(),
        _ => {
            return mcp_error(
                req_id,
                -32602,
                "name must be a non-empty, non-whitespace string",
            )
        }
    };

    // If code is provided, update it first (same 100KB cap as create path).
    //
    // MCP-338 (2026-05-11): parity with create_scratch_session's MCP-214
    // whitespace + wrong-type checks. Pre-fix:
    //   * wrong-type `code: 42` collapsed via `.as_str() → None`, the
    //     `if let Some(...)` skipped the update silently; the run path
    //     then proceeded with the OLD code while the operator believed
    //     they had updated it (configure-success-but-wrong-value class);
    //   * whitespace-only `code: "   "` passed the previous emptiness
    //     check and was silently written as the new code, then
    //     compilation failed downstream with a confusing parser error
    //     attributed to the (now blank) source. create_scratch_session
    //     already rejects this; the run path's silent acceptance was
    //     a divergence.
    match args.get("code") {
        None | Some(serde_json::Value::Null) => {}
        Some(v) => match v.as_str() {
            Some(s) if s.trim().is_empty() => {
                return mcp_error(
                    req_id,
                    -32602,
                    "code must be non-empty and non-whitespace when provided. Omit to run the saved session's code.",
                )
            }
            Some(s) if s.len() > 100_000 => {
                return mcp_error(req_id, -32602, "code exceeds 100 KB limit")
            }
            Some(s) => {
                let _ = state
                    .advanced_repo
                    .update_scratch_code(s, user_id, session_name)
                    .await;
            }
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("code must be a string, got {kind}"),
                );
            }
        },
    }

    // Load session
    let session = state
        .advanced_repo
        .get_scratch_session(user_id, session_name)
        .await
        .unwrap_or(None);

    let (code, world) = match session {
        Some(s) => s,
        None => {
            return mcp_error(
                req_id,
                -32000,
                &format!("Scratch session '{}' not found", session_name),
            )
        }
    };

    let input = args
        .get("input")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));

    // Wrap user code with #[talos_module] if not already present
    static RE_FN_RUN_SCRATCH: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"(?m)^\s*(pub\s+)?(async\s+)?fn\s+run").unwrap()
    });

    let rust_code =
        if code.contains("#[talos_node") || code.contains("talos_sdk_macros::talos_node") {
            code.clone()
        } else {
            let replacement = format!(
                "#[talos_sdk_macros::talos_module(world = \"{}\")]\n$0",
                world
            );
            RE_FN_RUN_SCRATCH
                .replace(&code, replacement.as_str())
                .to_string()
        };

    // Compile (with timeout)
    let job_id = uuid::Uuid::new_v4();
    let compilation_result = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        state.compiler.compile_to_wasm_with_config(
            user_id,
            job_id,
            "scratch_session",
            &rust_code,
            &serde_json::json!({}),
            None,
        ),
    )
    .await;

    let compilation = match compilation_result {
        Ok(r) => r,
        Err(_) => {
            let err_str = "Compilation timed out after 60 seconds";
            let _ = state
                .advanced_repo
                .update_scratch_error(err_str, user_id, session_name)
                .await;
            return mcp_error(req_id, -32000, err_str);
        }
    };

    let wasm_bytes = match compilation {
        Ok(res) if res.success => match res.wasm_bytes {
            Some(b) => b,
            None => {
                let _ = state
                    .advanced_repo
                    .update_scratch_no_wasm(
                        "Compilation succeeded but produced no WASM bytes",
                        user_id,
                        session_name,
                    )
                    .await;
                return mcp_text(req_id, "Compilation succeeded but produced no WASM bytes.");
            }
        },
        Ok(res) => {
            let error_msgs: Vec<String> = res
                .errors
                .into_iter()
                .map(|e| {
                    if let (Some(line), Some(col)) = (e.line, e.column) {
                        format!("Line {}:{}: {}", line, col, e.message)
                    } else {
                        e.message
                    }
                })
                .collect();
            let err_str = format!("Compilation failed:\n{}", error_msgs.join("\n"));
            let _ = state
                .advanced_repo
                .update_scratch_error(&err_str, user_id, session_name)
                .await;
            return mcp_text(req_id, &err_str);
        }
        Err(e) => {
            let err_str = format!("Compilation error: {}", e);
            let _ = state
                .advanced_repo
                .update_scratch_error(&err_str, user_id, session_name)
                .await;
            return mcp_text(req_id, &err_str);
        }
    };

    // Execute
    let payload = {
        let mut merged = serde_json::Map::new();
        if let Some(obj) = input.as_object() {
            for (k, v) in obj {
                merged.insert(k.clone(), v.clone());
            }
        }
        if !input.is_null() && input != serde_json::json!({}) {
            merged.insert("config".to_string(), input.clone());
        }
        serde_json::Value::Object(merged)
    };

    let execution_result = state
        .runtime
        .execute_job_with_full_features(
            &wasm_bytes,
            vec![],
            vec![],
            128,
            payload,
            None,
            None,
            std::collections::HashMap::new(),
            None,
            std::time::Duration::from_secs(30),
            worker::runtime::RetryPolicy::default(),
            None,
            worker::runtime::SecurityPolicy::default(),
            None,                                             // capability_world_hint
            None,                                             // max_fuel_override
            false,                                            // dry_run
            None,                                             // actor_id
            uuid::Uuid::nil(), // user_id (controller-internal test path)
            talos_workflow_job_protocol::LlmTier::default(), // tier2 for internal tests
            talos_workflow_job_protocol::WriteCeiling::Write, // permissive: internal test path
        )
        .await;

    match execution_result {
        Ok(val) => {
            let output = talos_workflow_engine::ParallelWorkflowEngine::unwrap_output(&val);
            let _ = state
                .advanced_repo
                .update_scratch_output(output, user_id, session_name)
                .await;
            mcp_text(req_id, &output.to_string())
        }
        Err(e) => {
            let err_str = format!("Execution error: {}", e);
            let _ = state
                .advanced_repo
                .update_scratch_error(&err_str, user_id, session_name)
                .await;
            mcp_text(req_id, &err_str)
        }
    }
}

async fn handle_list_scratch_sessions(
    req_id: Option<serde_json::Value>,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    match state.advanced_repo.list_scratch_sessions(user_id).await {
        Ok(rows) => {
            let sessions: Vec<serde_json::Value> = rows
                .into_iter()
                .map(|r| {
                    serde_json::json!({
                        "name": r.name,
                        "world": r.world,
                        "updated_at": r.updated_at.to_rfc3339(),
                        "has_error": r.has_error,
                    })
                })
                .collect();
            // MCP-138 (2026-05-08): wrap in canonical envelope. Pre-fix
            // this surface returned a bare `[]` array, breaking the
            // count-envelope convention every other list_* surface
            // follows. Defensive callers reading `response.count` on
            // every list response would crash here.
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "count": sessions.len(),
                    "sessions": sessions,
                }))
                .unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("list_scratch_sessions failed: {}", e);
            mcp_error(req_id, -32000, "Failed to list scratch sessions")
        }
    }
}

async fn handle_delete_scratch_session(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // MCP-169 (2026-05-08): reject whitespace-only session names.
    // Pre-fix `!n.is_empty()` accepted "                " and persisted
    // it in upsert_scratch_session, polluting list_scratch_sessions.
    // Same family as MCP-161/163/164/165/166.
    //
    // MCP-365 (2026-05-11): trim the delete lookup name so operator's
    // "   prod-scratch   " matches the trimmed-on-create row.
    let session_name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) if !n.trim().is_empty() => n.trim(),
        _ => {
            return mcp_error(
                req_id,
                -32602,
                "name must be a non-empty, non-whitespace string",
            )
        }
    };

    match state
        .advanced_repo
        .delete_scratch_session(user_id, session_name)
        .await
    {
        Ok(n) if n > 0 => mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "name": session_name,
                "message": format!("Scratch session '{}' deleted", session_name),
            }))
            .unwrap_or_default(),
        ),
        Ok(_) => mcp_error(
            req_id,
            -32000,
            &format!("Scratch session '{}' not found", session_name),
        ),
        Err(e) => {
            tracing::error!("delete_scratch_session failed: {}", e);
            mcp_error(req_id, -32000, "Failed to delete scratch session")
        }
    }
}

async fn handle_get_archive_policy(
    req_id: Option<serde_json::Value>,
    state: &McpState,
) -> JsonRpcResponse {
    let db_value: Option<serde_json::Value> = state
        .advanced_repo
        .get_archive_policy()
        .await
        .unwrap_or(None);
    // MCP-677 (2026-05-13): route through `positive_env_or_default` so
    // the displayed env default matches what the controller scheduler
    // actually uses (controller/src/main.rs:1292 has the canonical
    // `positive_env_or_default::<i32>("ARCHIVE_AFTER_DAYS", 30)`).
    // Pre-fix `ARCHIVE_AFTER_DAYS=0` made this handler report
    // `effective_days=0` to the operator while the archiver actually
    // used 30 (via the canonical helper's positive-substitute) — a
    // confusing display/reality drift on the same env var. Sibling to
    // the broader `=0`/empty-env footgun sweep (MCP-643/665/670/671).
    let env_default: i32 = talos_config::positive_env_or_default::<i32>("ARCHIVE_AFTER_DAYS", 30);

    // MCP-961 sibling: saturating i64→i32 conversion. The value
    // originates from the `system_config` DB row's `value` column
    // (JSON), an operator-supplied integer. A manual SQL UPDATE
    // setting value > i32::MAX would silently wrap pre-fix.
    let db_days_raw: Option<i32> = db_value.as_ref().and_then(|v| {
        v.as_i64()
            .map(|n| i32::try_from(n).unwrap_or(i32::MAX))
            .or_else(|| v.as_str().and_then(|s| s.trim_matches('"').parse().ok()))
    });

    // MCP-759 (2026-05-13): align the reporter with the archiver's
    // actual substitution behavior (MCP-758). The archiver
    // (controller/src/main.rs::execution-archival) filters
    // `Some(d) if d > 0` and falls back to env_default for any
    // non-positive DB setting. Pre-fix this reporter showed
    // `effective_days: 0, source: "database"` for a stored value of 0
    // while the archiver was actually using 30 — display/reality drift
    // that misled operators about what the system would do. Same
    // align-display-to-runtime pattern as the MCP-640 fix in
    // `handle_get_wasm_config`. Negative values get the same treatment
    // (Postgres `make_interval(days => -7)` archives "older than NOW +
    // 7 days" = everything).
    let db_days_effective: Option<i32> = db_days_raw.filter(|&d| d > 0);

    let effective_days = db_days_effective.unwrap_or(env_default);
    let response = serde_json::json!({
        "effective_days": effective_days,
        "db_setting": db_days_raw,
        "db_setting_effective": db_days_effective,
        "env_default": env_default,
        "source": if db_days_effective.is_some() { "database" } else { "environment" },
    });
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&response).unwrap_or_default(),
    )
}

async fn handle_set_archive_policy(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // MCP-326 (2026-05-11): `set_archive_policy` writes a single row
    // to `system_settings` (key='archive_policy_days') that drives
    // every tenant's `archive_executions` cadence. Pre-fix the gate
    // was the agent-level `is_admin` (per-tenant), so an organization-
    // scoped admin in a multi-tenant deployment could shorten the
    // archive window to 7 days and force every tenant's analytics
    // window to evaporate, or extend it to 365 to balloon storage.
    // Same require_platform_admin family as MCP-323/324/325 — the
    // `users.is_platform_admin` column is the deployment-wide gate.
    let is_platform_admin = state
        .actor_repo
        .is_platform_admin(user_id)
        .await
        .unwrap_or(false);
    if !is_platform_admin {
        return mcp_error(
            req_id,
            -32601,
            "set_archive_policy requires platform-admin privileges. \
             The archive-days setting is deployment-wide state — \
             every tenant's archive cadence is driven by this single row.",
        );
    }
    // MCP-281 (2026-05-10): pre-fix `as_i64()` collapsed wrong-type
    // (`days: "30"` string) into None → "Missing required 'days' parameter"
    // (misleading — operator clearly DID send the field). Distinguish
    // absent / null from wrong-type / out-of-range. Required field, so
    // no default; use validate_range_i64 with a sentinel default that
    // never fires (guard against missing manually).
    let days = match args.get("days") {
        None | Some(serde_json::Value::Null) => {
            return mcp_error(req_id, -32602, "Missing required 'days' parameter")
        }
        Some(_) => match crate::utils::validate_range_i64(args, "days", 7, 365, 7, &req_id) {
            Ok(v) => v as i32,
            Err(resp) => return resp,
        },
    };

    match state.advanced_repo.set_archive_policy(days).await {
        Ok(_) => mcp_text(req_id, &format!("Archive policy set to {} days", days)),
        Err(e) => {
            tracing::error!("set_archive_policy failed: {}", e);
            mcp_error(req_id, -32000, "Failed to set archive policy")
        }
    }
}

async fn handle_archive_executions(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // MCP-211 (2026-05-08): pre-fix `older_than_days: 7.5` silently
    // fell through to the default of 30 (`as_i64()` returns None for
    // non-integer floats), and there was no upper bound either —
    // `older_than_days: 999999999` was accepted as-is. A real probe
    // returned "Archived 0 executions older than 30 days" for a
    // caller who passed 7.5, exposing the silent default. Use
    // `validate_range_i64` for upfront wrong-type rejection plus an
    // explicit [7, 3650] window (10 years past covers every realistic
    // archive cadence; nothing older than that should ever be active
    // and a typo'd 999999 should be caught).
    let days = match crate::utils::validate_range_i64(args, "older_than_days", 7, 3650, 30, &req_id)
    {
        Ok(v) => v as i32,
        Err(resp) => return resp,
    };

    match state.advanced_repo.archive_executions(days, user_id).await {
        Ok(count) => {
            tracing::info!(count, days, "MCP archive_executions completed");
            mcp_text(
                req_id,
                &format!("Archived {} executions older than {} days.", count, days),
            )
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("column") || msg.contains("INSERT") || msg.contains("does not exist") {
                tracing::error!("archive_executions failed — archive table schema drift likely (run migrations): {}", e);
                mcp_error(req_id, -32000, "Failed to archive executions: archive table schema is out of sync. Ensure all migrations have been applied (sqlx migrate run).")
            } else {
                tracing::error!("archive_executions failed: {}", e);
                mcp_error(req_id, -32000, "Failed to archive executions")
            }
        }
    }
}

async fn handle_list_archived_executions(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // MCP-386 (2026-05-11): strict-parse so a wrong-type
    // `workflow_id` doesn't silently drop the filter and return ALL
    // archived executions for the user. Pre-fix `optional_uuid`
    // collapsed wrong-type / invalid-UUID into None — operator's
    // typed-wrong filter became "no filter", returning a confusing
    // larger result set than they asked for. MCP-157's ownership
    // gate catches the valid-UUID-but-not-owned case; this catches
    // the wrong-type case at the same boundary. Same MCP-309
    // family.
    let workflow_filter: Option<uuid::Uuid> =
        match crate::utils::parse_optional_uuid_strict(args, "workflow_id", &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    // MCP-157 (2026-05-08): when workflow_id is provided, validate it
    // resolves to a workflow this user owns. Pre-fix the surface
    // returned `count: 0, executions: []` for fake/cross-tenant UUIDs
    // — operator typing a UUID typo got back a confident "no archived
    // executions" response. Sibling list_executions correctly errors
    // with "Workflow not found or access denied"; match that.
    if let Some(wf_id) = workflow_filter {
        if !state.workflow_repo.workflow_exists(wf_id, user_id).await {
            return mcp_error(req_id, -32000, "Workflow not found or access denied");
        }
    }
    let limit = match crate::utils::validate_range_i64(args, "limit", 1, 100, 20, &req_id) {
        Ok(v) => v as i32,
        Err(resp) => return resp,
    };

    let rows = state
        .advanced_repo
        .list_archived_executions(user_id, workflow_filter, limit)
        .await;
    match rows {
        Ok(rows) => {
            let executions: Vec<serde_json::Value> = rows
                .into_iter()
                .map(|r| {
                    serde_json::json!({
                        "id": r.id,
                        "workflow_id": r.workflow_id,
                        "status": r.status,
                        "started_at": r.started_at.to_rfc3339(),
                        "completed_at": r.completed_at.map(|t| t.to_rfc3339()),
                        "error_message": r.error_message,
                    })
                })
                .collect();
            // MCP-45 (2026-05-07): structured envelope (count + items).
            let envelope = serde_json::json!({
                "count": executions.len(),
                "executions": executions,
            });
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&envelope).unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("list_archived_executions query failed: {}", e);
            mcp_error(req_id, -32000, "Failed to list archived executions")
        }
    }
}

async fn handle_publish_to_marketplace(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let module_id = match crate::utils::require_uuid(args, "module_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    // MCP-205 (2026-05-08): reject whitespace-only descriptions.
    // The description surfaces on the marketplace listing —
    // whitespace makes the listing visually empty and unhelpful
    // to other operators searching for modules to install. Same
    // family as MCP-186.
    // MCP-419 (2026-05-11): three issues on a cross-user marketplace
    // surface where the description renders to OTHER operators
    // searching the listings:
    //   (1) Stored untrimmed — `description: "   stuff   "` (operator
    //       paste from a runbook) was persisted with padding; same
    //       MCP-372 class.
    //   (2) Length check on UNTRIMMED value — a 1999-char visible
    //       description with 10 chars of padding bypassed the >2000
    //       gate even though the post-trim value is 1999.
    //   (3) No control-char check — `\0` in the description would hit
    //       Postgres' "invalid byte sequence" via an opaque -32000,
    //       and `\n` / control chars would render unpredictably on
    //       any client's marketplace listing UI. Cross-user surface
    //       so the protection matters more here than on user-private
    //       descriptions.
    // MCP-419/430 (2026-05-11): marketplace descriptions are
    // conceptually paragraph-form (a longer prose explanation of
    // what the module does). Pre-MCP-419 there was no control-char
    // check; MCP-419 added one via validate_name_no_control_chars
    // which rejects \n / \r — too strict for descriptions that
    // legitimately span multiple lines. Migrate to the canonical
    // multi-line helper (MCP-429): same trim + length + \0 +
    // control-char rules, but \n / \r kept since they're legitimate
    // in prose.
    let description = match crate::utils::validate_multiline_description(
        "Description",
        args.get("description").and_then(|v| v.as_str()),
        2000,
        "",
        req_id.clone(),
    ) {
        Ok(Some(d)) => d,
        Ok(None) => return mcp_error(req_id, -32602, "Missing required 'description' parameter"),
        Err(resp) => return resp,
    };
    // MCP-287 (2026-05-10): pre-fix `filter_map` silently dropped tag
    // entries that were non-string, empty, whitespace-only (passed
    // `!s.is_empty()` because " " is len 1), or > 50 chars. Operator's
    // intent was silently narrowed: `tags: ["http", "really-long-…"]`
    // shipped to the marketplace with one tag, not two. Trim AND
    // reject malformed entries loudly so the operator can fix the
    // typo instead of having it disappear. Same MCP-249/274/285 family.
    let tags: Vec<String> = match args.get("tags") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(serde_json::Value::Array(arr)) => {
            if arr.len() > 100 {
                return mcp_error(req_id, -32602, "tags array must contain ≤ 100 entries");
            }
            let mut out: Vec<String> = Vec::with_capacity(arr.len());
            for (i, t) in arr.iter().enumerate() {
                let s = match t.as_str() {
                    Some(s) => s,
                    None => {
                        let kind = crate::utils::json_type_name(t);
                        return mcp_error(
                            req_id,
                            -32602,
                            &format!("tags[{i}] must be a string, got {kind}"),
                        );
                    }
                };
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    return mcp_error(
                        req_id,
                        -32602,
                        &format!("tags[{i}] must be non-empty and non-whitespace"),
                    );
                }
                if trimmed.len() > 50 {
                    return mcp_error(
                        req_id,
                        -32602,
                        &format!("tags[{i}] must be ≤ 50 characters, got {}", trimmed.len()),
                    );
                }
                out.push(trimmed.to_string());
            }
            out
        }
        Some(v) => {
            let kind = crate::utils::json_type_name(v);
            return mcp_error(
                req_id,
                -32602,
                &format!("tags must be an array of strings, got {kind}"),
            );
        }
    };
    // MCP-205 (2026-05-08): reject obviously-non-semver version
    // strings. The marketplace shows the version next to the listing
    // — `version: "not-a-version"` confuses install_from_marketplace
    // consumers who expect a sortable semver. Pre-fix the only check
    // was length ≤ 50. Lightweight check (numeric.numeric.numeric
    // optional pre-release / build metadata) catches the obvious
    // garbage without pulling the full `semver` crate into the
    // dependency tree.
    let version = match args.get("version").and_then(|v| v.as_str()) {
        Some(v) if v.len() > 50 => {
            return mcp_error(req_id, -32602, "version must be ≤ 50 characters")
        }
        Some(v) if !v.is_empty() => {
            if !is_plausible_semver(v) {
                return mcp_error(
                    req_id,
                    -32602,
                    &format!(
                        "version '{v}' is not a valid semver. Use the form MAJOR.MINOR.PATCH (e.g. '1.0.0', '2.3.1-beta')"
                    ),
                );
            }
            v.to_string()
        }
        _ => "1.0.0".to_string(),
    };

    // Fetch module info and verify ownership
    match state
        .advanced_repo
        .get_wasm_module_for_marketplace(module_id, user_id)
        .await
    {
        Ok(Some(module)) => {
            let mod_name = module.name;
            let capability_world = module.capability_world;
            let source_code = module.source_code;

            if mod_name.len() > 200 {
                return mcp_error(req_id, -32602, "Module name must not exceed 200 characters");
            }

            if source_code.is_none() {
                return mcp_error(
                    req_id,
                    -32000,
                    "Module has no source code and cannot be published to the marketplace",
                );
            }

            match state.advanced_repo.publish_to_marketplace(module_id, user_id, &mod_name, &description, &capability_world, &version, &tags).await {
                Ok(listing_id) => mcp_text(req_id, &format!(
                    "Module '{}' published to marketplace.\nListing ID: {}\nVersion: {}\nWorld: {}\nTags: {:?}",
                    mod_name, listing_id, version, capability_world, tags
                )),
                Err(e) => {
                    tracing::error!("publish_to_marketplace failed: {}", e);
                    mcp_error(req_id, -32000, "Failed to publish module to marketplace")
                }
            }
        }
        Ok(None) => {
            // Not in wasm_modules — check node_templates (compile_custom_sandbox output)
            match state
                .advanced_repo
                .get_sandbox_for_marketplace(module_id, user_id)
                .await
            {
                Ok(Some(sandbox)) => {
                    let mod_name = sandbox.name;
                    let wasm_bytes = sandbox.wasm_bytes;

                    if wasm_bytes.is_none() {
                        return mcp_error(
                            req_id,
                            -32000,
                            "Sandbox module has no compiled WASM and cannot be published",
                        );
                    }

                    if mod_name.len() > 200 {
                        return mcp_error(
                            req_id,
                            -32602,
                            "Module name must not exceed 200 characters",
                        );
                    }

                    // Derive capability_world by inspecting the WASM bytes.
                    let capability_world = wasm_bytes
                        .as_deref()
                        .map(|b| worker::inspect_component(b).capability_world.to_string())
                        .unwrap_or_else(|| "unknown".to_string());

                    // module_marketplace.module_id has no FK constraint, so a node_templates.id is valid.
                    match state.advanced_repo.publish_to_marketplace(module_id, user_id, &mod_name, &description, &capability_world, &version, &tags).await {
                        Ok(listing_id) => mcp_text(req_id, &format!(
                            "Sandbox module '{}' published to marketplace.\nListing ID: {}\nVersion: {}\nWorld: {}\nTags: {:?}",
                            mod_name, listing_id, version, capability_world, tags
                        )),
                        Err(e) => {
                            tracing::error!("publish_to_marketplace (sandbox) insert failed: {}", e);
                            mcp_error(req_id, -32000, "Failed to publish sandbox module to marketplace")
                        }
                    }
                }
                Ok(None) => mcp_error(req_id, -32000, "Module not found or access denied"),
                Err(e) => {
                    tracing::error!("publish_to_marketplace sandbox lookup failed: {}", e);
                    mcp_error(req_id, -32000, "Failed to look up module")
                }
            }
        }
        Err(e) => {
            tracing::error!("publish_to_marketplace lookup failed: {}", e);
            mcp_error(req_id, -32000, "Failed to look up module")
        }
    }
}

async fn handle_search_marketplace(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
) -> JsonRpcResponse {
    let query_str = match args.get("query").and_then(|v| v.as_str()) {
        Some(q) if q.len() > 1000 => {
            return mcp_error(req_id, -32602, "query must be ≤ 1000 characters")
        }
        Some(q) => q,
        None => "",
    };
    let world_filter = args
        .get("capability_world")
        .or_else(|| args.get("world")) // legacy alias
        .and_then(|v| v.as_str())
        .map(talos_capability_world::world_short); // normalize to short form for DB match
                                                   // MCP-222 (2026-05-08): trim before length check, treat empty
                                                   // trimmed as no filter. Pre-fix `tag: "   "` was passed verbatim
                                                   // to the marketplace search filter and silently returned no
                                                   // matches. Same family as MCP-210 / MCP-221.
    let tag_filter_owned: Option<String> = match args.get("tag").and_then(|v| v.as_str()) {
        Some(t) if t.len() > 100 => {
            return mcp_error(req_id, -32602, "tag must be ≤ 100 characters")
        }
        Some(t) => {
            let trimmed = t.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        None => None,
    };
    let tag_filter: Option<&str> = tag_filter_owned.as_deref();

    let filter = talos_advanced_repository::MarketplaceSearchFilter {
        query: if query_str.is_empty() {
            None
        } else {
            Some(query_str)
        },
        world: world_filter,
        tag: tag_filter,
    };

    match state.advanced_repo.search_marketplace(filter, 50).await {
        Ok(rows) => {
            let listings: Vec<serde_json::Value> = rows
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "id": r.id.to_string(),
                        "module_id": r.module_id.to_string(),
                        "name": r.name,
                        "description": r.description,
                        "capability_world": r.capability_world,
                        "version": r.version,
                        "downloads": r.downloads,
                        "tags": r.tags,
                    })
                })
                .collect();

            let response = serde_json::json!({
                "count": listings.len(),
                "listings": listings,
            });
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&response).unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("search_marketplace failed: {:#}", e);
            mcp_error(req_id, -32000, "Failed to search marketplace")
        }
    }
}

async fn handle_install_from_marketplace(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let listing_id = match crate::utils::require_uuid(args, "listing_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // Fetch the listing
    let listing = state
        .advanced_repo
        .get_marketplace_listing(listing_id)
        .await;

    match listing {
        Ok(Some(listing_row)) => {
            let source_module_id = listing_row.module_id;
            let listing_name = listing_row.name;
            let capability_world = listing_row.capability_world;

            let install_name = format!("{} (marketplace)", listing_name);

            // Fetch the source module's full installable artifact. The repo
            // normalises empty-vec wasm_bytes to None so we don't have to
            // double-check for zero-length here.
            let source_row = state
                .advanced_repo
                .get_wasm_module_source(source_module_id)
                .await;

            match source_row {
                Ok(Some(src)) => {
                    use talos_advanced_repository::InstallDispatch;
                    match InstallDispatch::from_source(&src) {
                        InstallDispatch::Wasm => match state
                            .advanced_repo
                            .install_wasm_from_marketplace(
                                user_id,
                                listing_id,
                                &install_name,
                                &capability_world,
                                src,
                            )
                            .await
                        {
                            Ok(new_module_id) => mcp_text(
                                req_id,
                                &format!(
                                    "Module '{}' installed from marketplace.\nNew module ID: {}\nCapability world: {}",
                                    listing_name, new_module_id, capability_world
                                ),
                            ),
                            Err(e) => {
                                tracing::error!("install_from_marketplace insert failed: {}", e);
                                mcp_error(req_id, -32000, "Failed to install module")
                            }
                        },
                        InstallDispatch::Template => match state
                            .advanced_repo
                            .install_template_from_marketplace(
                                user_id,
                                listing_id,
                                &install_name,
                                &capability_world,
                                src,
                            )
                            .await
                        {
                            Ok(new_template_id) => mcp_text(
                                req_id,
                                &format!(
                                    "Sandbox module '{}' installed from marketplace (source-only — will compile on first use).\nTemplate ID: {}\nCapability world: {}\n\nUse this Template ID when adding the module to a workflow.",
                                    listing_name, new_template_id, capability_world
                                ),
                            ),
                            Err(e) => {
                                tracing::error!(
                                    "install_from_marketplace (sandbox) insert failed: {}",
                                    e
                                );
                                mcp_error(req_id, -32000, "Failed to install module")
                            }
                        },
                        InstallDispatch::Reject => mcp_error(
                            req_id,
                            -32000,
                            "Marketplace listing has no installable artifact: the source module has \
                             neither compiled WASM bytes nor source code. The publisher must republish.",
                        ),
                    }
                }
                Ok(None) => mcp_error(req_id, -32000, "Source module no longer exists"),
                Err(e) => {
                    tracing::error!("install_from_marketplace source lookup failed: {}", e);
                    mcp_error(req_id, -32000, "Failed to fetch source module")
                }
            }
        }
        Ok(None) => mcp_error(req_id, -32000, "Marketplace listing not found"),
        Err(e) => {
            tracing::error!("install_from_marketplace listing lookup failed: {}", e);
            mcp_error(req_id, -32000, "Failed to look up marketplace listing")
        }
    }
}

async fn handle_get_marketplace_stats(
    req_id: Option<serde_json::Value>,
    state: &McpState,
) -> JsonRpcResponse {
    let stats = match state.advanced_repo.get_marketplace_stats().await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("get_marketplace_stats query failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to fetch marketplace stats");
        }
    };
    let top_rows = state
        .advanced_repo
        .get_marketplace_top_modules()
        .await
        .unwrap_or_default();

    // MCP-75 (2026-05-07): filter to modules with at least one download.
    // Pre-fix the underlying SQL fell back to alphabetical order when fewer
    // than 5 modules had downloads, which surfaced 0-download entries as
    // "top" — misleading. If fewer than 5 qualify the list is shorter; the
    // tool description ("up to 5 most-downloaded") matches this behavior.
    let top_modules: Vec<serde_json::Value> = top_rows
        .into_iter()
        .filter(|r| r.downloads > 0)
        .map(|r| {
            serde_json::json!({
                "name": r.name,
                "publisher_id": r.publisher_id.to_string(),
                "downloads": r.downloads,
                "capability_world": r.capability_world,
            })
        })
        .collect();

    let result = serde_json::json!({
        "total_listings": stats.total_listings,
        "total_downloads": stats.total_downloads,
        "unique_publishers": stats.unique_publishers,
        "world_count": stats.world_count,
        "top_modules": top_modules,
        "top_modules_note": "Modules with at least one download, ordered by download count (descending). Empty if no module has been downloaded yet — that is a real signal, not an error.",
    });

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

async fn handle_list_published_modules(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
) -> JsonRpcResponse {
    // MCP-253 (2026-05-10): trim before empty check so
    // `capability_world: "   "` doesn't run SQL `WHERE capability_world = '   '`
    // and silently return zero matches. Same family as MCP-249 / MCP-251.
    let capability_world: Option<String> = args
        .get("capability_world")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from);
    let limit: i64 = match crate::utils::validate_range_i64(args, "limit", 1, 200, 50, &req_id) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let rows = match state
        .advanced_repo
        .list_published_modules(capability_world.as_deref(), limit)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("list_published_modules query failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to fetch marketplace modules");
        }
    };

    // Scan workflow-templates dir to build module_name → [pattern_name] index.
    // Offloaded to spawn_blocking: this synchronously reads + JSON-parses every
    // file in the dir (which grows with the pattern library), so running it
    // inline would block this async handler's executor thread for the whole
    // scan. Mirrors the catalog-scan offload in modules.rs. Graceful-empty on
    // any error is preserved (missing dir/files → empty index, as before).
    let pattern_refs: std::collections::HashMap<String, Vec<String>> =
        tokio::task::spawn_blocking(|| {
            let mut pattern_refs: std::collections::HashMap<String, Vec<String>> =
                Default::default();
            let patterns_dir = std::path::Path::new("/app/workflow-templates");
            if patterns_dir.is_dir() {
                if let Ok(rd) = std::fs::read_dir(patterns_dir) {
                    for entry in rd.flatten() {
                        if let Ok(content) = std::fs::read_to_string(entry.path()) {
                            if let Ok(tmpl) = serde_json::from_str::<serde_json::Value>(&content) {
                                let pat_name = tmpl
                                    .get("name")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                if let Some(nodes) = tmpl.get("nodes").and_then(|v| v.as_array()) {
                                    for node in nodes {
                                        if let Some(mn) =
                                            node.get("module_name").and_then(|v| v.as_str())
                                        {
                                            pattern_refs
                                                .entry(mn.to_string())
                                                .or_default()
                                                .push(pat_name.clone());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            pattern_refs
        })
        .await
        .unwrap_or_default();

    let total = rows.len();
    let modules: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            let listing_id = r.listing_id.to_string();
            let refs = pattern_refs.get(&r.name).cloned().unwrap_or_default();
            // star_count is INTEGER (i32 in PostgreSQL); read as i32 to avoid silent decode failure
            let star_count: i32 = r.star_count;

            let mut entry = serde_json::json!({
                "listing_id": listing_id,
                "name": &r.name,
                "description": r.description,
                "capability_world": r.capability_world,
                "version": r.version,
                "downloads": r.downloads,
                "star_count": star_count,
                "verified": r.verified,
                "tags": r.tags,
                "published_at": r.published_at.to_rfc3339(),
                "install_with": format!("install_from_marketplace with listing_id={}", listing_id),
            });
            if !refs.is_empty() {
                entry["referenced_by_patterns"] = serde_json::json!(refs);
            }
            if r.verified {
                entry["trust_note"] =
                    serde_json::json!("Platform-verified: tested and reviewed by the Talos team.");
            }
            entry
        })
        .collect();

    let result = serde_json::json!({
        "count": total,
        "total": total,
        "modules": modules,
        "tip": "Modules with verified=true or star_count>0 are trusted by other users. \
                Call install_from_marketplace with listing_id to install. \
                Call star_module to endorse a module you've tested. \
                Use compile_custom_sandbox only when nothing here fits.",
    });

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

async fn handle_archive_workflow(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    match state.advanced_repo.archive_workflow(wf_id, user_id).await {
        Ok(n) if n > 0 => mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "workflow_id": wf_id.to_string(),
                "status": "archived",
                "message": "Workflow archived. It will no longer appear in search or discovery. Use batch_delete_workflows to permanently delete.",
            }))
            .unwrap_or_default(),
        ),
        Ok(_) => mcp_error(req_id, -32000, "Workflow not found, access denied, or already archived"),
        Err(e) => {
            tracing::error!(workflow_id = %wf_id, "archive_workflow failed: {}", e);
            mcp_error(req_id, -32000, "Failed to archive workflow")
        }
    }
}

async fn handle_star_module(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let listing_id = match crate::utils::require_uuid(args, "listing_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // Reject nil user_id — agents without a bound user cannot own a star.
    if user_id == uuid::Uuid::nil() {
        return mcp_error(
            req_id,
            -32600,
            "Agent must have a bound user_id to star modules",
        );
    }

    // Verify the listing exists and is public before touching the stars table.
    let listing_exists = state.advanced_repo.check_listing_exists(listing_id).await;

    match listing_exists {
        Ok(false) | Err(_) => return mcp_error(req_id, -32000, "Listing not found or not public"),
        Ok(true) => {}
    }

    // Attempt to insert the per-user star record.
    // ON CONFLICT DO NOTHING means the INSERT is a no-op if this user already
    // starred this listing, so star_count is never double-incremented.
    let already_starred = match state.advanced_repo.insert_star(user_id, listing_id).await {
        Ok(inserted) => !inserted,
        Err(e) => {
            tracing::error!(listing_id = %listing_id, user_id = %user_id, "star_module insert failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to star module");
        }
    };

    if already_starred {
        // Return current count without re-incrementing.
        let count: i32 = state
            .advanced_repo
            .get_star_count(listing_id)
            .await
            .unwrap_or(0);

        return mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "listing_id": listing_id.to_string(),
                "star_count": count,
                "already_starred": true,
                "message": "You have already starred this module.",
            }))
            .unwrap_or_default(),
        );
    }

    // New star — atomically increment the denormalized counter and return the result.
    match state.advanced_repo.increment_star_count(listing_id).await {
        Ok(Some(new_count)) => {
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "listing_id": listing_id.to_string(),
                    "star_count": new_count,
                    "already_starred": false,
                    "message": "Module starred. Stars signal to other users that this module is tested and trustworthy.",
                }))
                .unwrap_or_default(),
            )
        }
        Ok(None) => mcp_error(req_id, -32000, "Listing not found or not public"),
        Err(e) => {
            tracing::error!(listing_id = %listing_id, "star_module update failed: {}", e);
            mcp_error(req_id, -32000, "Failed to star module")
        }
    }
}

async fn handle_get_config_suggestions(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    // MCP-226 (2026-05-08): trim node_id at the boundary; pre-fix
    // `!id.is_empty()` accepted whitespace IDs which then matched
    // no graph node (silent no-op) or got persisted in the fan-in
    // mutation path.
    let target_node_id = match args.get("node_id").and_then(|v| v.as_str()) {
        Some(id) => {
            let trimmed = id.trim();
            if trimmed.is_empty() {
                return mcp_error(req_id, -32602, "Invalid or missing 'node_id'");
            }
            trimmed.to_string()
        }
        _ => return mcp_error(req_id, -32602, "Invalid or missing 'node_id'"),
    };

    let llm = match state.llm_client.as_ref() {
        Some(c) => c.clone(),
        None => {
            return mcp_error(
                req_id,
                -32000,
                "LLM client not configured (set ANTHROPIC_API_KEY)",
            )
        }
    };

    // Fetch graph + template schemas
    let (wf_name, graph_json_str) = match state
        .advanced_repo
        .get_workflow_graph_and_name(wf_id, user_id)
        .await
    {
        Ok(Some(pair)) => pair,
        Ok(None) => return mcp_error(req_id, -32000, "Workflow not found or access denied"),
        Err(e) => {
            tracing::error!("get_config_suggestions fetch failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to fetch workflow");
        }
    };

    let graph: serde_json::Value = serde_json::from_str(&graph_json_str).unwrap_or_default();
    let nodes = graph
        .get("nodes")
        .and_then(|n| n.as_array())
        .cloned()
        .unwrap_or_default();
    let edges = graph
        .get("edges")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default();

    // Find target node and its upstream nodes
    let target_node = match talos_workflow_repository::find_node_in_array(&nodes, &target_node_id) {
        Some(n) => n.clone(),
        None => return mcp_error(req_id, -32000, "Node not found in workflow graph"),
    };

    let upstream_node_ids: Vec<String> = edges
        .iter()
        .filter(|e| e.get("target").and_then(|v| v.as_str()) == Some(&target_node_id))
        .filter_map(|e| crate::utils::json_optional_string(e, "source"))
        .collect();

    let upstream_nodes: Vec<&serde_json::Value> = nodes
        .iter()
        .filter(|n| {
            upstream_node_ids
                .iter()
                .any(|id| n.get("id").and_then(|v| v.as_str()) == Some(id.as_str()))
        })
        .collect();

    // Collect template IDs to fetch schemas + names
    let all_relevant_ids: Vec<uuid::Uuid> = nodes
        .iter()
        .filter(|n| {
            let nid = n.get("id").and_then(|v| v.as_str()).unwrap_or("");
            nid == target_node_id || upstream_node_ids.iter().any(|uid| uid == nid)
        })
        .filter_map(|n| {
            n.get("type")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
        })
        .collect();

    let tmpl_rows = state
        .advanced_repo
        .get_node_templates_for_config(&all_relevant_ids)
        .await
        .unwrap_or_default();

    let tmpl_map: std::collections::HashMap<String, (String, serde_json::Value)> = tmpl_rows
        .iter()
        .map(|r| {
            let id = r.id.to_string();
            let name = r.name.clone();
            let schema = r.config_schema.clone();
            (id, (name, schema))
        })
        .collect();

    // Canonical secret paths declared by the target module (from allowed_secrets in node_templates).
    // Use these instead of letting the LLM invent paths — prevents "pagerduty/github_repo_health_integration_key" style fabrication.
    let target_node_type_str = target_node
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let target_allowed_secrets: Vec<String> = tmpl_rows
        .iter()
        .find(|r| r.id.to_string() == target_node_type_str)
        .map(|r| r.allowed_secrets.clone())
        .unwrap_or_default();

    // Build context description for LLM
    let target_type_id = target_node
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let (target_module_name, target_schema) = tmpl_map
        .get(target_type_id)
        .cloned()
        .unwrap_or_else(|| ("Unknown".to_string(), serde_json::json!({})));

    let target_data = target_node.get("data").cloned().unwrap_or_default();
    let current_config = target_data
        .get("config")
        .cloned()
        .unwrap_or_else(|| target_data.clone());

    let required_fields = crate::utils::json_string_array_field(&target_schema, "required");

    let missing_fields: Vec<&String> = required_fields
        .iter()
        .filter(|f| {
            current_config
                .get(f.as_str())
                .map(|v| v.is_null() || v.as_str().map(|s| s.is_empty()).unwrap_or(false))
                .unwrap_or(true)
        })
        .collect();

    if missing_fields.is_empty() {
        return mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "workflow_id": wf_id.to_string(),
                "node_id": target_node_id,
                "module": target_module_name,
                "message": "No missing required fields for this node.",
                "suggestions": {},
            }))
            .unwrap_or_default(),
        );
    }

    let upstream_summary: Vec<String> = upstream_nodes
        .iter()
        .map(|n| {
            let tid = n.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let (mod_name, _) = tmpl_map.get(tid).cloned().unwrap_or_default();
            let label = n
                .get("data")
                .and_then(|d| d.get("label"))
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            format!("{} ({})", label, mod_name)
        })
        .collect();

    let schema_str = serde_json::to_string_pretty(&target_schema).unwrap_or_default();
    let current_str = serde_json::to_string_pretty(&current_config).unwrap_or_default();
    let missing_str = missing_fields
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join(", ");

    let system_prompt = "You are a workflow configuration assistant. \
        Respond ONLY with a valid JSON object mapping field_name to suggested_value. \
        No prose, no markdown fences, no explanation. \
        Example: {\"FIELD\": \"status_code\", \"CHANNEL\": \"#ops\"}. \
        For fields ending in _SECRET, _KEY, or _TOKEN: use ONLY the canonical secret paths \
        listed under 'Canonical secret paths' — do NOT invent new path names.";

    let canonical_paths_hint = if target_allowed_secrets.is_empty() {
        String::new()
    } else {
        format!("\nCanonical secret paths for this module (use these exactly for _KEY/_TOKEN/_SECRET fields): {}\n",
            target_allowed_secrets.join(", "))
    };

    let user_prompt = format!(
        "Workflow: \"{}\"\n\
         Target node (needs config): module={}\n\
         Upstream nodes feeding data into this node: {}\n\
         Module config schema: {}\n\
         Already-configured values: {}\n\
         Missing required fields to suggest values for: {}{}\n\n\
         Suggest concrete values for the missing fields.",
        wf_name,
        target_module_name,
        if upstream_summary.is_empty() {
            "(none — this is the first node)".to_string()
        } else {
            upstream_summary.join(", ")
        },
        schema_str,
        current_str,
        missing_str,
        canonical_paths_hint
    );

    let user_prompt_redacted = state.dlp_service.redact_str(&user_prompt);
    let llm_response = llm
        .generate_text(system_prompt, &user_prompt_redacted)
        .await;
    let suggestions: serde_json::Value = match llm_response {
        Ok(s) => serde_json::from_str(&s).unwrap_or(serde_json::json!({})),
        Err(e) => {
            tracing::warn!("get_config_suggestions LLM call failed: {}", e);
            serde_json::json!({})
        }
    };

    // Vault cross-reference: for any suggestion that looks like a secret reference
    // (_SECRET / _KEY / _TOKEN suffix), check whether the path is already provisioned.
    let provisioned_list: Vec<String> = state
        .advanced_repo
        .get_user_secret_paths(user_id)
        .await
        .unwrap_or_default();
    let provisioned_paths: std::collections::HashSet<String> =
        provisioned_list.iter().cloned().collect();

    // Derive module namespace prefix for fuzzy key matching (e.g. "pagerduty" from "PagerDuty Alert")
    let ns_prefix = target_module_name
        .to_lowercase()
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_string();

    let mut annotated_suggestions = serde_json::Map::new();
    if let Some(obj) = suggestions.as_object() {
        for (field, value) in obj {
            let upper = field.to_uppercase();
            let is_secret_field =
                upper.ends_with("_SECRET") || upper.ends_with("_KEY") || upper.ends_with("_TOKEN");
            if is_secret_field {
                let path = value.as_str().unwrap_or("").to_string();
                let provisioned = !path.is_empty() && provisioned_paths.contains(&path);
                let mut entry = serde_json::Map::new();
                entry.insert("value".to_string(), value.clone());
                entry.insert("provisioned".to_string(), serde_json::json!(provisioned));
                if !provisioned {
                    // Surface module's canonical paths first (highest confidence hint)
                    if !target_allowed_secrets.is_empty() {
                        // Check if any canonical path is already provisioned
                        let canonical_provisioned: Vec<&String> = target_allowed_secrets
                            .iter()
                            .filter(|p| provisioned_paths.contains(*p))
                            .collect();
                        let canonical_all: Vec<&String> = target_allowed_secrets.iter().collect();
                        entry.insert(
                            "canonical_secret_paths".to_string(),
                            serde_json::json!(canonical_all),
                        );
                        if !canonical_provisioned.is_empty() {
                            entry.insert(
                                "suggestion".to_string(),
                                serde_json::json!(format!(
                                    "Use '{}' (canonical path, already provisioned).",
                                    canonical_provisioned[0]
                                )),
                            );
                        } else {
                            entry.insert(
                                "suggestion".to_string(),
                                serde_json::json!(format!(
                                    "Use canonical path '{}' — add it in the dashboard (Settings → Secrets) with key_path='{}'.",
                                    canonical_all[0], canonical_all[0]
                                )),
                            );
                        }
                    } else {
                        // Fall back to namespace prefix matching
                        let matching: Vec<&String> = provisioned_list
                            .iter()
                            .filter(|p| !ns_prefix.is_empty() && p.starts_with(&ns_prefix))
                            .collect();
                        if !matching.is_empty() {
                            entry.insert(
                                "existing_matches".to_string(),
                                serde_json::json!(matching),
                            );
                            entry.insert(
                                "suggestion".to_string(),
                                serde_json::json!(format!(
                                    "Use '{}' (already provisioned) instead of fabricated path '{}'.",
                                    matching[0], path
                                )),
                            );
                        } else if !path.is_empty() {
                            entry.insert(
                                "warning".to_string(),
                                serde_json::json!(format!(
                                    "Secret path '{}' not yet in vault. Add it in the dashboard (Settings → Secrets) with key_path='{}'.",
                                    path, path
                                )),
                            );
                        }
                    }
                }
                annotated_suggestions.insert(field.clone(), serde_json::Value::Object(entry));
            } else {
                annotated_suggestions.insert(field.clone(), value.clone());
            }
        }
    }

    mcp_text(req_id, &serde_json::to_string_pretty(&serde_json::json!({
        "workflow_id": wf_id.to_string(),
        "node_id": target_node_id,
        "module": target_module_name,
        "missing_fields": missing_fields,
        "suggestions": serde_json::Value::Object(annotated_suggestions),
        "next_step": format!(
            "Call update_node_config with workflow_id={} node_id={} and the suggested values above.",
            wf_id, target_node_id
        ),
    })).unwrap_or_default())
}

async fn handle_agent_session_start(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // The default-None semantic differs here: missing arg → skip auto-archive
    // entirely (Some vs None matters), so we hand-code the validation rather
    // than using validate_range_i64 (which collapses None → default).
    // MCP-301 (2026-05-11): pre-fix `as_i64()` collapsed wrong-type into
    // None, the "skip" branch. `auto_archive_stale_days: "30"` (string)
    // would silently skip auto-archive when the operator clearly asked
    // for it. Distinguish absent / null (legitimate skip) from wrong-type
    // (loud reject).
    let auto_archive_days = match args.get("auto_archive_stale_days") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => match v.as_i64() {
            Some(n) if !(1..=365).contains(&n) => {
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("Invalid 'auto_archive_stale_days' value {n}: must be in [1, 365]"),
                );
            }
            Some(n) => Some(n),
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("auto_archive_stale_days must be an integer in [1, 365], got {kind}"),
                );
            }
        },
    };

    // 1. Embedding coverage
    let (total_wf, embedded_wf) = state
        .advanced_repo
        .get_embedding_coverage(user_id)
        .await
        .unwrap_or((0, 0));

    let unembedded = total_wf - embedded_wf;
    // When total_wf == 0 there are no workflows to embed — return null rather than
    // the misleading "100%" that a zero-division guard would produce.
    let embedding_pct: Option<i64> = if total_wf > 0 {
        Some(embedded_wf * 100 / total_wf)
    } else {
        None
    };

    // Auto-heal: spawn background embedding for any unembedded workflows.
    // This runs every session start — idempotent because auto_embed_workflow checks before writing.
    //
    // Gate on provider availability (added 2026-04-28, r239). Pre-r239 we
    // unconditionally spawned a per-workflow loop that all silently no-op'd
    // at DEBUG level when EMBEDDING_API_KEY / EMBEDDING_API_URL were unset
    // — operators saw "auto-embedding triggered in background" forever while
    // coverage stayed at 0/N. Now we skip the spawn AND surface the gap in
    // the response so the agent reports the misconfiguration instead of
    // promising "fully operational within seconds".
    let embedding_provider_available = crate::search::embedding_provider_available();
    let auto_healing_embeddings = unembedded > 0 && embedding_provider_available;
    if auto_healing_embeddings {
        let pool = state.db_pool.clone();
        let repo = state.advanced_repo.clone();
        tokio::spawn(async move {
            let ids = repo
                .get_ids_without_embedding(user_id)
                .await
                .unwrap_or_default();
            for wf_id in ids {
                crate::search::auto_embed_workflow(wf_id, user_id, &pool).await;
            }
        });
    }

    // 2. Draft workflows (unpublished, no executions) — recent first
    let draft_rows = state
        .advanced_repo
        .get_draft_workflows(user_id)
        .await
        .unwrap_or_default();

    // Auto-archive stale drafts if requested
    let mut auto_archived_count = 0i64;
    if let Some(stale_days) = auto_archive_days {
        if let Ok(n) = state
            .advanced_repo
            .archive_stale_drafts(user_id, stale_days as i32)
            .await
        {
            auto_archived_count = n as i64;
        }
    }

    // Drafts split by substantive-ness (pain point #1, addressed r234):
    //   * `unpublished_substantive_drafts` — workflows that are well-configured
    //     but unpublished. The right next step is publish_version, not
    //     get_workflow_quickstart. Pre-r234 these were lumped into
    //     in_progress_drafts with a misleading "0 unconfigured nodes" hint.
    //   * `in_progress_drafts` — true work-in-progress: empty graph, mostly
    //     unconfigured nodes, recently-scaffolded skeletons. The right next
    //     step is still get_workflow_quickstart.
    //
    // "Substantive" criteria (any one is enough):
    //   - all non-structural nodes have non-empty data, AND node_count > 0
    //   - any node has SYSTEM_PROMPT > 200 chars (LLM node thoughtfully prompted)
    //   - any node has OUTPUT_SCHEMA configured (structured output authored)
    //   - any node has retry_count / retry_condition / retry_delay_expression
    //   - any node has description / skip_condition / continue_on_error set
    let mut in_progress_drafts: Vec<serde_json::Value> = Vec::new();
    let mut unpublished_substantive_drafts: Vec<serde_json::Value> = Vec::new();
    for r in draft_rows.iter().take(5) {
        let id = r.id.to_string();
        let graph: serde_json::Value = r
            .graph_json
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or(serde_json::json!({"nodes":[],"edges":[]}));
        let nodes = graph
            .get("nodes")
            .and_then(|n| n.as_array())
            .cloned()
            .unwrap_or_default();
        let node_count = nodes.len();
        let unconfigured_node_count = count_nodes_with_empty_data(&nodes);
        let days_old = (chrono::Utc::now() - r.created_at).num_days();

        // Substantive detection: walk graph_json once, look for any
        // marker of authored intent. Cheap to compute (capped at 5 drafts).
        let has_thoughtful_node = nodes.iter().any(|n| {
            let data = n.get("data");
            let prompt_len = data
                .and_then(|d| d.get("SYSTEM_PROMPT"))
                .and_then(|v| v.as_str())
                .map(str::len)
                .unwrap_or(0);
            let has_output_schema = data
                .and_then(|d| d.get("OUTPUT_SCHEMA"))
                .map(|v| !v.is_null())
                .unwrap_or(false);
            let has_retry = n.get("retry_count").is_some()
                || n.get("retry_condition").is_some()
                || n.get("retry_delay_expression").is_some();
            let has_per_node_meta = n.get("description").is_some()
                || n.get("skip_condition").is_some()
                || n.get("continue_on_error").is_some();
            prompt_len > 200 || has_output_schema || has_retry || has_per_node_meta
        });
        let all_nodes_configured = node_count > 0 && unconfigured_node_count == 0;
        let is_substantive = all_nodes_configured || has_thoughtful_node;

        let next_step = if is_substantive {
            format!("publish_version with workflow_id={}", id)
        } else {
            format!("get_workflow_quickstart with workflow_id={}", id)
        };

        let entry = serde_json::json!({
            "workflow_id": id,
            "name": r.name,
            "node_count": node_count,
            "unconfigured_node_count": unconfigured_node_count,
            // MCP-2 / MCP-17: label the readiness mode so operators
            // know this is the coarse data-presence check, not the
            // strict schema-required check that get_workflow_quickstart
            // runs. The two surfaces can disagree for the same workflow.
            "unconfigured_check_mode": "data_presence_only",
            "days_old": days_old,
            "is_substantive": is_substantive,
            "next_step": next_step,
        });
        if is_substantive {
            unpublished_substantive_drafts.push(entry);
        } else {
            in_progress_drafts.push(entry);
        }
    }

    // 2b. Duplicate-name ghost workflow detection.
    // Multiple workflows with the same name indicate leftover test artifacts or
    // deliberate force=true duplicates that weren't cleaned up. Surface the
    // actual IDs + creation timestamps so the caller doesn't need a follow-up
    // list_workflows + filter pass.
    //
    // Performance: a single GROUP BY query (earlier version) avoids N+1, but
    // then forces a second query to resolve IDs. The current shape — select
    // id/name/created_at for every row in duplicate groups via a subquery —
    // stays O(duplicate_rows), which is tiny by definition (we only surface up
    // to 10 *groups*, each typically 2-3 rows).
    let duplicate_name_groups: Vec<serde_json::Value> = {
        let rows = state
            .advanced_repo
            .find_workflow_duplicate_name_groups(user_id)
            .await
            .unwrap_or_default();

        // Group rows by name. BTreeMap preserves alphabetical order for stable output.
        let mut groups: std::collections::BTreeMap<
            String,
            Vec<(uuid::Uuid, chrono::DateTime<chrono::Utc>)>,
        > = std::collections::BTreeMap::new();
        for r in rows {
            groups.entry(r.name).or_default().push((r.id, r.created_at));
        }

        groups
            .into_iter()
            .map(|(name, members)| {
                // Oldest first; recommend deleting the older duplicates (the last
                // force=true create is usually the one the author wanted to keep).
                let workflows: Vec<serde_json::Value> = members
                    .iter()
                    .map(|(id, created_at)| {
                        serde_json::json!({
                            "id": id.to_string(),
                            "created_at": created_at.to_rfc3339(),
                        })
                    })
                    .collect();
                let oldest_ids: Vec<String> = members
                    .iter()
                    .take(members.len().saturating_sub(1))
                    .map(|(id, _)| id.to_string())
                    .collect();
                serde_json::json!({
                    "name": name,
                    "count": members.len(),
                    "workflows": workflows,
                    "suggested_cleanup": format!(
                        "Consider deleting the {} older duplicate(s): {}. \
                         The newest entry is typically the one the author wanted to keep.",
                        oldest_ids.len(),
                        oldest_ids.join(", "),
                    ),
                })
            })
            .collect()
    };

    // 3. Uncapabilized workflows
    let uncap_count: i64 = state
        .advanced_repo
        .get_uncapabilized_count(user_id)
        .await
        .unwrap_or(0);

    // Auto-heal: spawn background capability tagging for any uncapabilized workflows.
    // Idempotent — auto_suggest_capabilities only applies when capabilities IS NULL or empty.
    let auto_healing_caps = uncap_count > 0;
    if auto_healing_caps {
        let pool = state.db_pool.clone();
        let repo = state.advanced_repo.clone();
        tokio::spawn(async move {
            let ids = repo
                .get_ids_without_capabilities(user_id)
                .await
                .unwrap_or_default();
            for wf_id in ids {
                crate::analytics::auto_suggest_capabilities(wf_id, user_id, &pool).await;
            }
        });
    }

    // 4. Next scheduled run.
    //
    // Pre-r234 this read from the wrong table (`schedules`) which was empty
    // in prod, so the field was always null even when active schedules existed
    // (pain point #8). Repo now queries `workflow_schedules` (the canonical
    // table since 20260309000200) and includes `next_trigger_at` so callers
    // can distinguish "no schedule" from "next firing is far out" without
    // a follow-up list_schedules call.
    let next_schedule = state
        .advanced_repo
        .get_next_scheduled_run(user_id)
        .await
        .ok()
        .flatten()
        .map(|s| {
            serde_json::json!({
                "workflow": s.workflow_name,
                "cron": s.cron_expression,
                "timezone": s.timezone,
                "next_trigger_at": s.next_trigger_at.map(|t| t.to_rfc3339()),
            })
        });

    // 4b. No-schedule health check: active workflows with no schedule
    let active_wf_count: i64 = state
        .advanced_repo
        .get_active_workflow_count(user_id)
        .await
        .unwrap_or(0);

    let active_schedule_count: i64 = state
        .advanced_repo
        .get_active_schedule_count(user_id)
        .await
        .unwrap_or(0);

    // Count of active workflows that ACTUALLY have ≥1 enabled schedule attached
    // — distinct from `active_wf_count` (every status='active' workflow) and
    // `active_schedule_count` (schedule-row count; a workflow can have several).
    // This is the field most callers think `active_workflows` means.
    let active_workflows_with_schedule: i64 = state
        .advanced_repo
        .get_active_workflows_with_schedule_count(user_id)
        .await
        .unwrap_or(0);

    let no_schedule_warning = active_wf_count > 0 && active_schedule_count == 0;

    // 5. Detect frequently-executed workflows without a schedule.
    // Condition: ≥3 executions in the last 60 days AND no active schedule
    // AND not a sub-workflow of another workflow AND not tagged `interactive`.
    // r242 renamed from `previously_scheduled_unscheduled` for honesty —
    // workflow_schedules are hard-deleted (no audit trail), so we have no
    // way to know if a workflow was ever scheduled. The pre-r242 name +
    // "may have lost their trigger" framing produced false positives for
    // pure manual-trigger utilities. The two new filters + the softer
    // framing below cut the false-positive rate sharply.
    // r243: surface query failures via tracing::warn so future schema/SQL
    // regressions are visible — pre-r243 the bare `.unwrap_or_default()`
    // swallowed the SQL error from r242's wrong JSONB path silently, and
    // session_start reported "clean" coverage while the query was broken.
    let prev_scheduled_rows = state
        .advanced_repo
        .get_frequently_executed_unscheduled(user_id)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(
                error = %e,
                "session_start: get_frequently_executed_unscheduled failed; \
                 frequently_executed_unscheduled will be reported as empty"
            );
            Vec::new()
        });

    let frequently_executed_unscheduled: Vec<serde_json::Value> = prev_scheduled_rows
        .iter()
        .map(|r| {
            let id = r.id.to_string();
            serde_json::json!({
                "workflow_id": id,
                "name": r.name,
                "recent_executions": r.exec_count,
                "tip": format!(
                    "If recurring is intended, schedule with create_schedule(workflow_id={}). \
                     If this is an on-demand utility, suppress this signal with \
                     tag_workflow(workflow_id={}, tag='interactive').",
                    id, id
                ),
            })
        })
        .collect();

    // 6. Pinned modules: check which are present vs need restore.
    // IMPORTANT: check the user's actual wasm_modules row (installed copy), not just whether
    // the system node_templates row has WASM. A deleted wasm_modules row must show as
    // needs_restore even if the catalog template still has precompiled_wasm.
    let pinned_rows = state
        .advanced_repo
        .list_pinned_modules_with_user_install_status(user_id, 200)
        .await
        .unwrap_or_default();

    let mut pinned_present: Vec<String> = Vec::new();
    let mut pinned_needs_restore: Vec<String> = Vec::new();
    for r in pinned_rows {
        if r.has_wasm {
            pinned_present.push(r.module_name);
        } else {
            pinned_needs_restore.push(r.module_name);
        }
    }

    let needs_restore_count = pinned_needs_restore.len();
    let pinned_modules_field = serde_json::json!({
        "present": pinned_present,
        "needs_restore": pinned_needs_restore,
        // Always surface the tool name so agents don't have to discover it.
        // needs_restore being empty means nothing currently requires action.
        "restore_tool": "restore_pinned_modules",
        "restore_needed": needs_restore_count > 0,
    });

    // 7. Active actors — surface identity/persona context at session start so agents
    //    know what actors exist without a separate list_actors call.
    let actor_rows = state
        .advanced_repo
        .list_active_actors_with_memory_count(user_id, 20)
        .await
        .unwrap_or_default();

    let active_actors: Vec<serde_json::Value> = actor_rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "actor_id": r.id.to_string(),
                "name": r.name,
                "description": r.description,
                "status": r.status,
                "max_capability_world": r.max_capability_world,
                "memory_count": r.memory_count,
                "tip": if r.memory_count == 0 {
                    Some(format!(
                        "No memories set — define a persona with actor_remember(actor_id: '{}', key: 'persona', value: {{...}}, memory_type: 'semantic')",
                        r.id
                    ))
                } else {
                    None
                },
            })
        })
        .collect();

    // 8. Stuck executions: running > 1 hour
    let stuck_rows = state
        .advanced_repo
        .list_stuck_executions(user_id, 1, 10)
        .await
        .unwrap_or_default();

    let stuck_executions: Vec<serde_json::Value> = stuck_rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "execution_id": r.execution_id.to_string(),
                "workflow_id": r.workflow_id.to_string(),
                "hours_stuck": r.hours_stuck,
                "tip": "cancel_execution or investigate with get_execution_status(detail: true)",
            })
        })
        .collect();

    // 8b. Recent execution activity for MCP-transport-drop awareness.
    //
    // Surfaces (a) currently-running executions of any age and
    // (b) executions that completed within the last RECENT_EXEC_WINDOW_MIN
    // minutes. The agent reads this on every session_start and can spot
    // executions it kicked off but lost the response for — preventing the
    // ghost-work pattern where a dropped MCP response is misread as
    // "execution failed", the agent retries, and the LLM provider is
    // double-billed for identical work.
    //
    // Window of 5 minutes is short enough not to be noisy on rapid
    // reconnects but long enough to catch the typical 15–30s LLM
    // workflow that the agent kicked off and immediately lost. Limit
    // of 25 caps the response size at the noisiest extreme.
    const RECENT_EXEC_WINDOW_MIN: i32 = 5;
    let recent_exec_rows = state
        .advanced_repo
        .list_recent_executions_for_session_awareness(user_id, RECENT_EXEC_WINDOW_MIN, 25)
        .await
        .unwrap_or_default();

    let recent_executions: Vec<serde_json::Value> = recent_exec_rows
        .iter()
        .map(|r| {
            let tip = match r.status.as_str() {
                "running" => "Still in flight. get_execution_status(execution_id: ...) for live state, \
                              or watch_execution to stream events. cancel_execution if you need to stop it.",
                "completed" => "Already finished. get_execution_output(execution_id: ...) for the full \
                                output — your client may have lost the response while the workflow was \
                                still running on the server.",
                "failed" | "cancelled" | "timeout" => "Reached terminal failure state. \
                                                       get_execution_status(execution_id: ..., detail: true) for the error.",
                _ => "get_execution_status(execution_id: ...) to inspect.",
            };
            serde_json::json!({
                "execution_id": r.execution_id.to_string(),
                "workflow_id": r.workflow_id.to_string(),
                "workflow_name": r.workflow_name,
                "status": r.status,
                "started_at": r.started_at.map(|t| t.to_rfc3339()),
                "completed_at": r.completed_at.map(|t| t.to_rfc3339()),
                "duration_ms": r.duration_ms,
                "tip": tip,
            })
        })
        .collect();
    let recent_executions_count = recent_executions.len();
    let recent_running_count = recent_exec_rows
        .iter()
        .filter(|r| r.status == "running")
        .count();

    // 8. Determine single most impactful action
    //
    // Priority order: pinned-restore (data loss risk) → embedding provider
    // misconfigured (whole feature silently broken — surface ABOVE the
    // auto-healing branches because we WON'T be auto-healing in that case)
    // → auto-healing in progress → drafts → schedules.
    let embedding_provider_misconfigured = unembedded > 0 && !embedding_provider_available;
    let priority_action = if !pinned_needs_restore.is_empty() {
        format!(
            "{} pinned module(s) need WASM restore: {}. Call restore_pinned_modules.",
            pinned_needs_restore.len(),
            pinned_needs_restore.join(", ")
        )
    } else if embedding_provider_misconfigured {
        format!(
            "Embedding provider not configured — {} workflow(s) are unembedded and \
             semantic search is degraded. Set EMBEDDING_API_KEY (or OPENAI_API_KEY) \
             on the controller, or set EMBEDDING_API_URL to a keyless local \
             endpoint (e.g. http://ollama:11434/v1/embeddings). Coverage will \
             auto-heal on the next session_start once configured.",
            unembedded
        )
    } else if auto_healing_embeddings && auto_healing_caps {
        format!(
            "{} workflow(s) had no embedding and {} had no capability tags — \
             both auto-healing in background. Platform will be fully indexed within seconds.",
            unembedded, uncap_count
        )
    } else if auto_healing_embeddings {
        format!(
            "{} workflow(s) had no embedding — auto-embedding triggered in background. \
             Semantic search will be fully operational within seconds.",
            unembedded
        )
    } else if auto_healing_caps {
        format!(
            "{} workflow(s) have no capability tags — auto-tagging triggered in background. \
             Capability-based discovery will be available within seconds.",
            uncap_count
        )
    } else if !unpublished_substantive_drafts.is_empty() {
        // Substantive drafts dominate priority over stub-class drafts —
        // the user has already done the work, just needs publish_version.
        format!(
            "You have {} substantive draft workflow(s) ready for publish_version. \
             See unpublished_substantive_drafts for the list.",
            unpublished_substantive_drafts.len()
        )
    } else if !in_progress_drafts.is_empty() {
        format!(
            "You have {} stub draft workflow(s) (mostly unconfigured nodes). \
             Call get_workflow_quickstart on the first one to see what's needed.",
            in_progress_drafts.len()
        )
    } else if !frequently_executed_unscheduled.is_empty() {
        format!(
            "{} active workflow(s) ran recently without a schedule — schedule with \
             create_schedule if recurring is intended, or tag 'interactive' to suppress \
             this signal for on-demand utilities. See frequently_executed_unscheduled \
             for per-workflow tips.",
            frequently_executed_unscheduled.len()
        )
    } else if no_schedule_warning {
        format!(
            "{} active workflow(s) have no scheduled trigger. \
             Call deploy_workflow with a cron_expression to automate execution.",
            active_wf_count
        )
    } else {
        "Platform looks healthy. All workflows are embedded, capabilized, and scheduled."
            .to_string()
    };

    let mut report = serde_json::json!({
        "embedding_coverage": {
            "total_workflows": total_wf,
            "embedded": embedded_wf,
            "unembedded": unembedded,
            // null when total_workflows == 0 (no workflows exist yet — not a real gap)
            "coverage_pct": embedding_pct,
            "auto_healing": auto_healing_embeddings,
            // "available" / "unavailable" — added r239 so the agent can
            // distinguish "auto-heal still running" from "provider missing,
            // nothing will ever heal". Pre-r239 the response always claimed
            // auto-heal was running even when it was a guaranteed no-op.
            "provider_status": if embedding_provider_available { "available" } else { "unavailable" },
            // r241: surface the cached `last_error` from the provider probe so the
            // agent can see "Voyage 429" or "DNS lookup failed" instead of just
            // "unavailable". Pre-r241 we couldn't distinguish "env vars unset"
            // from "URL unreachable" from "key revoked" — all collapsed to the
            // same syntactic-check failure.
            "provider_last_error": crate::search::embedding_provider_status().1,
            "provider_tip": if embedding_provider_misconfigured {
                Some("Set EMBEDDING_API_KEY (or OPENAI_API_KEY) on the controller, OR set EMBEDDING_API_URL to a reachable OpenAI-compatible endpoint. See provider_last_error for the actual failure mode the boot probe observed. Without a working provider, semantic_search and auto-embedding silently no-op.")
            } else {
                None
            },
            "note": if total_wf == 0 {
                Some("No workflows created yet — create your first workflow to start tracking coverage.")
            } else {
                None
            },
            // MCP-113 (2026-05-08): inline `field_meanings` so operators
            // reading the response don't have to guess what flags mean.
            // Same pattern as `schedule_health.field_meanings` further
            // down — applied here to embedding_coverage and below to
            // capabilities_coverage.
            "field_meanings": {
                "auto_healing": "True when an auto-heal task is currently running to embed unembedded workflows in the background. False = no heal needed (coverage is complete) OR provider is unavailable (provider_status reports which). Look at provider_status + unembedded count to disambiguate.",
                "coverage_pct": "Fraction (0–100) of workflows with usable embeddings. Below 100 means semantic_search will fall back to keyword/trigram matching for unembedded entries.",
                "provider_status": "available = embedding provider responding to probes. unavailable = provider env vars unset OR endpoint unreachable OR key revoked. See provider_last_error for the specific failure mode.",
                "unembedded": "Count of workflows whose vector embedding is missing or stale. While auto_healing is true, this number drops over time as the background task progresses.",
            },
        },
        "capabilities_coverage": {
            "uncapabilized_count": uncap_count,
            "auto_healing": auto_healing_caps,
            "tip": if uncap_count > 0 {
                "Capability tags are being auto-applied in the background. \
                 Call run_workflow_hygiene to see which workflows still lack tags, \
                 or suggest_capabilities(workflow_id) to apply them manually."
            } else {
                "All workflows have capability tags."
            },
            // MCP-113 (2026-05-08): mirror field_meanings on the
            // capabilities_coverage block.
            "field_meanings": {
                "auto_healing": "True when an auto-suggest task is currently running to populate capability tags for uncapabilized workflows in the background. False = no heal needed (every workflow has tags) OR auto-heal is disabled.",
                "uncapabilized_count": "Number of workflows with no capability tags. Workflows without tags are invisible to capability-based search and dispatch routing.",
            },
        },
        "in_progress_drafts": in_progress_drafts,
        "unpublished_substantive_drafts": unpublished_substantive_drafts,
        "duplicate_name_groups": duplicate_name_groups,
        "uncapabilized_count": uncap_count,
        "next_scheduled_run": next_schedule,
        "frequently_executed_unscheduled": frequently_executed_unscheduled,
        "schedule_health": {
            // Total count of `workflows.status='active'` — INCLUDES workflows
            // with no schedule attached (manual-trigger workflows, webhook-
            // driven workflows, etc.). Misleading legacy field name kept for
            // back-compat; prefer `workflows_with_active_schedules` for the
            // intuitive "how many active workflows are actually scheduled"
            // count.
            "active_workflows": active_wf_count,
            // Distinct count of active workflows that have at least one enabled
            // workflow_schedules row. Always ≤ active_workflows.
            "workflows_with_active_schedules": active_workflows_with_schedule,
            // Total count of enabled `workflow_schedules` rows. May exceed
            // workflows_with_active_schedules if a workflow has multiple
            // schedules attached (e.g. weekday morning + weekend evening).
            "active_schedules": active_schedule_count,
            // True when at least one workflow is active but ZERO schedules
            // are enabled across the user's namespace — a strong signal
            // that scheduling was forgotten or accidentally disabled.
            "no_schedule_warning": no_schedule_warning,
            "field_meanings": {
                "active_workflows": "All workflows with status='active' (includes manual-trigger / webhook-only workflows). Not 'workflows that have a schedule'.",
                "workflows_with_active_schedules": "Active workflows that have ≥1 enabled schedule attached.",
                "active_schedules": "Total enabled schedule rows. ≥ workflows_with_active_schedules when workflows have multiple schedules."
            },
        },
        "pinned_modules": pinned_modules_field,
        "stuck_executions": stuck_executions,
        // Recent execution activity (running of any age + completed in last
        // RECENT_EXEC_WINDOW_MIN minutes). Surfaces work that ran in the
        // gap between MCP sessions so dropped tool-call responses don't
        // translate to ghost retries. Empty when nothing recent.
        "recent_executions": {
            "count": recent_executions_count,
            "running_count": recent_running_count,
            "window_minutes": RECENT_EXEC_WINDOW_MIN,
            "items": recent_executions,
            "tip": if recent_executions_count == 0 {
                None
            } else if recent_running_count > 0 {
                Some(format!(
                    "{} execution(s) still running. If you kicked one off and lost the response, \
                     do NOT retry — get_execution_status / watch_execution / get_execution_output \
                     with the execution_id from the items array.",
                    recent_running_count
                ))
            } else {
                Some(format!(
                    "{} execution(s) completed in the last {} minute(s). \
                     If your client lost the response from a recent test_workflow / call_workflow / trigger_workflow, \
                     pull get_execution_output(execution_id: ...) from the items array instead of retrying.",
                    recent_executions_count, RECENT_EXEC_WINDOW_MIN
                ))
            },
        },
        "active_actors": active_actors,
        "priority_action": priority_action,
        // Schema staleness detection: compare this against your cached tools/list version.
        // If the version differs from what you connected with, reconnect to re-fetch the schema.
        // Composite version: pkg version + git SHA (+ "-dirty" if working
        // tree had uncommitted changes at build time). Operators can grep
        // for this exact string against `git log` to find the deployed
        // commit. Build.rs captures GIT_SHA / GIT_DIRTY / BUILD_TIME from
        // the source tree at compile time.
        "server_version": format!(
            "{}+{}{}",
            env!("CARGO_PKG_VERSION"),
            env!("GIT_SHA"),
            if env!("GIT_DIRTY") == "true" { "-dirty" } else { "" }
        ),
        "build_time": env!("BUILD_TIME"),
        // Client transport advisory: the server exposes 300+ tools via tools/list.
        // Some MCP clients (claude.ai web connector, Claude Desktop with large tool sets)
        // only make a FIXED SUBSET callable at session init, regardless of which tools appear
        // in tools/list. The callable set is client-determined and cannot be expanded server-side.
        // Symptoms: tool_search shows a tool schema but calling it returns "has not been loaded yet".
        // Resolution: use Claude Code CLI (stdio transport) for full 300+ tool access.
        // The tools/list ordering fix (session_start at index 0) ensures critical tools are
        // callable on clients that truncate by position (Claude Desktop, narrow-context clients).
        "client_compatibility": {
            "full_tool_access": "Use Claude Code CLI (claude mcp add talos ...) for all tools callable via stdio transport",
            "partial_access_clients": ["claude.ai web connector", "Claude Desktop with large tool sets"],
            "symptom": "tool_search shows schema but tool call returns 'has not been loaded yet'",
            "workaround": "Reconnect to server to reset callable set, or switch to Claude Code CLI"
        },
        // Stale-cache tripwire for the agent. The server registers this
        // many static MCP tools right now. If the agent has observed
        // fewer tools than this in `tools/list` / `tool_search`
        // since connecting, the client's tool cache is stale relative
        // to the server (the server was rebuilt with new tools after
        // the client connected). Action: prompt the user to `/mcp`
        // reconnect. See `mcp::static_tool_count` for the source of
        // truth.
        "static_tool_count": crate::static_tool_count(),
    });

    if auto_archive_days.is_some() {
        report["auto_archived_stale_drafts"] = serde_json::json!(auto_archived_count);
    }

    // #7 — hint to enable auto_archive when in-progress drafts accumulate
    let in_progress_count = report
        .get("in_progress_drafts")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    if in_progress_count > 0 && auto_archive_days.is_none() {
        report["auto_archive_hint"] = serde_json::json!(
            "Pass auto_archive_stale_days: 14 to automatically clean up drafts older than 14 days on next session_start."
        );
    }

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&report).unwrap_or_default(),
    )
}

async fn handle_create_approval_gate(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // MCP-164 (2026-05-08): reject whitespace-only and control-char
    // titles. The title surfaces on the public approval URL — a
    // 16-space title meant a reviewer would see " " on the approval
    // page with no indication of what they were approving (an
    // approval-phishing primitive). Pre-fix the check was
    // `!t.is_empty() && t.len() <= 200`, mirroring the same family
    // of bug fixed in MCP-161 (actor name) and MCP-163 (memory key).
    //
    // MCP-375 (2026-05-11): pre-fix `Some(t) => t` persisted UNTRIMMED.
    // A title like "   Deploy to prod   " rendered on the public
    // approval page with surrounding whitespace — same approval-
    // phishing surface MCP-164 closed, just with a smaller padding
    // smell. Trim post-emptiness-check; re-validate length on the
    // trimmed value so a 195-char trimmed title + padding doesn't
    // bypass the 200-char cap.
    let title = match args.get("title").and_then(|v| v.as_str()) {
        Some(t) if t.trim().is_empty() => {
            return mcp_error(
                req_id,
                -32602,
                "Title must be a non-empty, non-whitespace string",
            )
        }
        Some(t) if t.trim().len() > 200 => {
            return mcp_error(req_id, -32602, "Title must be 1-200 characters")
        }
        Some(t) => t.trim(),
        None => return mcp_error(req_id, -32602, "Missing required 'title' parameter"),
    };
    // MCP-410: migrated to canonical helper.
    if let Err(resp) = crate::utils::validate_name_no_control_chars("Title", title, req_id.clone())
    {
        return resp;
    }
    // MCP-263 (2026-05-10): reject whitespace-only descriptions on
    // approval gates. The description renders in the approval-gate UI
    // and downstream notifications; whitespace makes the gate look
    // unconfigured to reviewers.
    //
    // MCP-432 (2026-05-11): migrate to canonical helper. Pre-fix this
    // path lacked the control-char check that the broader description
    // sweep enforces. Approval gates are cross-user-visible (the
    // approver isn't necessarily the gate creator) so the protection
    // matters even more here than user-private descriptions.
    let description_owned = match crate::utils::validate_multiline_description(
        "description",
        args.get("description").and_then(|v| v.as_str()),
        5000,
        "Omit the field entirely to leave it blank.",
        req_id.clone(),
    ) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let description = description_owned.as_deref();
    let payload = {
        let p = args
            .get("payload")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        if p.to_string().len() > 100_000 {
            return mcp_error(req_id, -32602, "payload must be ≤ 100 KB when serialized");
        }
        p
    };

    // MCP-309 (2026-05-11): strict-parse so a typo'd or wrong-type
    // `continuation_workflow_id` doesn't silently drop the chain. Pre-fix
    // `.and_then(|v| v.as_str()).and_then(|s| s.parse().ok())` returned
    // None indistinguishably for absent / wrong-type / invalid-UUID; the
    // gate was created without a continuation, the reviewer approved it,
    // and the operator only noticed when nothing fired downstream.
    let continuation_workflow_id: Option<uuid::Uuid> =
        match crate::utils::parse_optional_uuid_strict(args, "continuation_workflow_id", &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };

    // Validate continuation workflow ownership if provided
    if let Some(cwf_id) = continuation_workflow_id {
        let exists: bool = state
            .advanced_repo
            .check_workflow_ownership(cwf_id, user_id)
            .await
            .unwrap_or(false);

        if !exists {
            return mcp_error(
                req_id,
                -32000,
                "continuation_workflow_id not found or access denied",
            );
        }
    }

    let expires_in_hours = match crate::utils::validate_range_f64(
        args,
        "expires_in_hours",
        1.0,
        720.0,
        168.0, // 7 days default
        &req_id,
    ) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // Validate notification_webhook if provided — length cap + full SSRF check.
    //
    // MCP-343 (2026-05-11): strict-parse. Pre-fix the `.as_str()` chain
    // collapsed wrong-type into None; the gate was created with NO
    // webhook. The operator believed they had configured out-of-band
    // notifications for approval requests and never saw alerts —
    // direction-class for a notification path. Notification webhooks
    // exist to surface approval gates beyond the API-polling fallback;
    // silently losing them defeats the entire feature.
    let notification_webhook: Option<String> = match args.get("notification_webhook") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => match v.as_str() {
            Some(s) if s.is_empty() => None,
            Some(url) if url.len() > 2048 => {
                return mcp_error(
                    req_id,
                    -32602,
                    "notification_webhook must be ≤ 2048 characters",
                )
            }
            Some(url) => {
                if let Err(reason) = check_outbound_url_no_ssrf(url) {
                    return mcp_error(req_id, -32602, reason);
                }
                Some(url.to_string())
            }
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("notification_webhook must be a string (URL), got {kind}"),
                );
            }
        },
    };

    // Generate a cryptographically random URL-safe token (32 bytes → 64 hex chars)
    let token = {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    };

    let gate_id: uuid::Uuid = match state
        .advanced_repo
        .create_approval_gate(
            user_id,
            title,
            description,
            &payload,
            &token,
            continuation_workflow_id,
            expires_in_hours,
            notification_webhook.as_deref(),
        )
        .await
    {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("create_approval_gate insert failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to create approval gate");
        }
    };

    if gate_id.is_nil() {
        return mcp_error(req_id, -32000, "Failed to create approval gate");
    }

    let base_url = talos_config::get_base_url();
    let approve_url = format!("{}/approvals/{}/approve", base_url, token);
    let reject_url = format!("{}/approvals/{}/reject", base_url, token);

    // Fire notification webhook if configured — best-effort async, gate creation succeeds regardless
    let notification_attempted = notification_webhook.is_some();
    if let Some(ref webhook_url) = notification_webhook {
        let notification_payload = serde_json::json!({
            "event": "approval_required",
            "gate_id": gate_id.to_string(),
            "title": title,
            "description": description,
            "approve_url": approve_url,
            "reject_url": reject_url,
            "expires_in_hours": expires_in_hours,
            "payload": payload,
            "source": "talos-platform",
        });
        let url = webhook_url.clone();
        let gate_id_log = gate_id;
        tokio::spawn(async move {
            // MCP-1136 (2026-05-16): use module-scope cached client.
            // MCP-1034 timeout(10s) + connect_timeout(5s) and MCP-469
            // redirect=none preserved in the LazyLock initializer above.
            match APPROVAL_GATE_NOTIFY_CLIENT
                .post(&url)
                .header("Content-Type", "application/json")
                .header("X-Talos-Event", "approval_required")
                .json(&notification_payload)
                .send()
                .await
            {
                Ok(resp) => tracing::info!(
                    gate_id = %gate_id_log,
                    status = resp.status().as_u16(),
                    "approval_gate notification webhook fired"
                ),
                Err(e) => tracing::warn!(
                    gate_id = %gate_id_log,
                    error = %e,
                    "approval_gate notification webhook delivery failed"
                ),
            }
        });
    }

    let result = serde_json::json!({
        "gate_id": gate_id.to_string(),
        "title": title,
        "status": "pending",
        "approve_url": approve_url,
        "reject_url": reject_url,
        "token": token,
        "expires_in_hours": expires_in_hours,
        "continuation_workflow_id": continuation_workflow_id.map(|u| u.to_string()),
        "notification_webhook": notification_webhook,
        "notification_attempted": notification_attempted,
        "instructions": if notification_attempted {
            "Notification dispatched to webhook. Share approve_url as backup. Use test_approval_webhook to verify delivery."
        } else {
            "No notification_webhook configured — share the approve_url with the reviewer manually. Add notification_webhook to get out-of-band alerts."
        },
    });

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

async fn handle_list_approval_gates(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // MCP-156 (2026-05-08): same silent-filter family as MCP-145 (the
    // list_workflows / list_actors / list_workflow_suspensions sweep).
    // Schema declares the enum; the handler must enforce it explicitly
    // so a typo'd status filter returns a clear error instead of an
    // empty list.
    //
    // MCP-346 (2026-05-11): also reject wrong-type loudly. Pre-fix the
    // `.as_str()` chain collapsed wrong-type into None, so the
    // `if let Some` skipped the allowlist check and the filter was
    // silently dropped — operator passing `status: 42` (number) saw
    // ALL approval gates instead of the typed-filtered subset.
    // Direction-class. Same MCP-342 family applied to the status
    // filter surface.
    let status_filter: Option<&str> = match args.get("status") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => match v.as_str() {
            Some(s)
                if matches!(
                    s,
                    "pending" | "approved" | "rejected" | "expired" | "cancelled"
                ) =>
            {
                Some(s)
            }
            Some(s) => {
                // MCP-1030: cap reflected status at 64 chars.
                let preview = talos_text_util::bounded_preview(s, 64);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!(
                        "Invalid status filter '{preview}'. Valid values: pending, approved, rejected, expired, cancelled",
                    ),
                );
            }
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("status filter must be a string, got {kind}"),
                );
            }
        },
    };
    let limit = match crate::utils::validate_range_i64(args, "limit", 1, 100, 20, &req_id) {
        Ok(v) => v as i32,
        Err(resp) => return resp,
    };

    // Expire stale pending gates before listing
    let _ = state
        .advanced_repo
        .expire_stale_approval_gates(user_id)
        .await;

    match state
        .advanced_repo
        .list_approval_gates(user_id, status_filter, limit)
        .await
    {
        Ok(rows) => {
            let gates: Vec<serde_json::Value> = rows
                .iter()
                .map(|r| {
                    // MCP-631: empty-env hardening — see talos_config::get_env.
                    let base_url = talos_config::get_base_url();

                    let mut obj = serde_json::json!({
                        "gate_id": r.id.to_string(),
                        "title": r.title,
                        "description": r.description,
                        "status": r.status,
                        "continuation_workflow_id": r.continuation_workflow_id.map(|u| u.to_string()),
                        "created_at": r.created_at.to_rfc3339(),
                        "expires_at": r.expires_at.to_rfc3339(),
                        "resolved_at": r.resolved_at.map(|t| t.to_rfc3339()),
                        "resolved_by_type": r.resolved_by_type,
                        "resolution_note": r.resolved_by_note,
                    });

                    // Only include approval URLs for pending gates (avoids leaking tokens for resolved ones)
                    if r.status == "pending" {
                        // We don't store the token in the list query for security; omit approval URL here
                        obj["approve_url_available"] = serde_json::json!(true);
                        obj["hint"] = serde_json::json!(
                            format!("{}/approvals/<token>/approve — use gate_id to retrieve the full URL via create_approval_gate", base_url)
                        );
                    }

                    obj
                })
                .collect();

            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "gates": gates,
                    "count": gates.len(),
                }))
                .unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("list_approval_gates query failed: {}", e);
            mcp_error(req_id, -32000, "Failed to list approval gates")
        }
    }
}

async fn handle_resolve_approval_gate(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let gate_id = match crate::utils::require_uuid(args, "gate_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let resolution = match args.get("resolution").and_then(|v| v.as_str()) {
        Some("approve") => "approved",
        Some("reject") => "rejected",
        _ => return mcp_error(req_id, -32602, "resolution must be 'approve' or 'reject'"),
    };

    // MCP-186 (2026-05-08): reject whitespace-only notes. The note
    // is persisted on the resolved gate and surfaces in the action
    // log — whitespace pollutes the audit trail.
    //
    // MCP-374 (2026-05-11): pre-fix `other => other` returned UNTRIMMED
    // Some(n) for storage. Audit log search missed the trimmed query.
    // Trim post-check; re-validate length on the trimmed value.
    let note = match args.get("note").and_then(|v| v.as_str()) {
        Some(n) if n.trim().is_empty() => {
            return mcp_error(
                req_id,
                -32602,
                "note must be non-empty and non-whitespace when provided. Omit the field to leave it blank.",
            )
        }
        Some(n) if n.trim().len() > 1000 => {
            return mcp_error(req_id, -32602, "note must be ≤ 1000 characters")
        }
        Some(n) => Some(n.trim()),
        None => None,
    };

    // Fetch the gate (verify ownership, check it's pending)
    let gate = match state
        .advanced_repo
        .get_approval_gate(gate_id, user_id)
        .await
    {
        Ok(Some(g)) => g,
        Ok(None) => return mcp_error(req_id, -32000, "Approval gate not found or access denied"),
        Err(e) => {
            tracing::error!("resolve_approval_gate fetch failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to fetch approval gate");
        }
    };

    if gate.status != "pending" {
        return mcp_error(
            req_id,
            -32000,
            &format!(
                "Gate is already '{}' and cannot be resolved again",
                gate.status
            ),
        );
    }

    let cwf_id = gate.continuation_workflow_id;
    let payload = gate.payload;

    // Update the gate status. The UPDATE is guarded `AND status = 'pending'`, so
    // `rows_affected == 0` means a concurrent caller resolved/cancelled/expired
    // this gate between our read above and this write (TOCTOU). Bail WITHOUT
    // firing the continuation — otherwise two concurrent approvals would both
    // pass the read-side `status != "pending"` check and both trigger the
    // continuation workflow (e.g. a payment runs twice).
    match state
        .advanced_repo
        .resolve_approval_gate(gate_id, user_id, resolution, note)
        .await
    {
        Ok(0) => {
            return mcp_error(
                req_id,
                -32000,
                "Gate was resolved by another request — not resolving again",
            );
        }
        Ok(_) => {}
        Err(e) => {
            tracing::error!("resolve_approval_gate update failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to resolve approval gate");
        }
    }

    // Reflects the gate's configuration, not whether the trigger
    // actually fired. Callers need this to distinguish "no CWF was
    // set on this gate" from "a CWF was set but we didn't trigger it
    // (rejected / failed)" — especially on the reject path, where
    // previously this always read `false` even when a CWF was set.
    let continuation_was_configured = cwf_id.is_some();
    // Trigger the continuation workflow only on approval. A failed
    // trigger returns None — caller distinguishes by
    // `continuation_was_configured == true && triggered_execution_id == null`.
    let triggered_execution = if resolution == "approved" {
        if let Some(continuation_id) = cwf_id {
            let exec_id = trigger_continuation_workflow(
                &state.db_pool,
                state.registry.clone(),
                state.nats_client.clone(),
                state.secrets_manager.clone(),
                user_id,
                continuation_id,
                &payload,
                gate_id,
                TriggerSourceKind::ApprovalGate,
            )
            .await;
            if exec_id.is_none() {
                tracing::error!(
                    gate_id = %gate_id,
                    continuation_workflow_id = %continuation_id,
                    "Approval gate approved but continuation workflow trigger failed"
                );
            }
            exec_id
        } else {
            None
        }
    } else {
        None
    };

    let message = if resolution == "approved" {
        match (triggered_execution.is_some(), continuation_was_configured) {
            (true, _) => "Gate approved. Continuation workflow has been triggered.",
            (false, true) => {
                "Gate approved, but continuation workflow trigger failed — check server logs."
            }
            (false, false) => "Gate approved. No continuation workflow configured.",
        }
    } else {
        "Gate rejected."
    };

    let result = serde_json::json!({
        "gate_id": gate_id.to_string(),
        "resolution": resolution,
        "resolved_at": chrono::Utc::now().to_rfc3339(),
        "triggered_execution_id": triggered_execution,
        "continuation_was_configured": continuation_was_configured,
        "message": message,
    });

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

async fn handle_cancel_approval_gate(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let gate_id = match crate::utils::require_uuid(args, "gate_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    match state
        .advanced_repo
        .cancel_approval_gate(gate_id, user_id)
        .await
    {
        Ok(n) if n > 0 => mcp_text(
            req_id,
            &format!("Approval gate {} has been cancelled.", gate_id),
        ),
        Ok(_) => mcp_error(
            req_id,
            -32000,
            "Gate not found, access denied, or not in pending status",
        ),
        Err(e) => {
            tracing::error!("cancel_approval_gate failed: {}", e);
            mcp_error(req_id, -32000, "Failed to cancel approval gate")
        }
    }
}

// `TriggerSourceKind` and `trigger_continuation_workflow` were lifted
// to the `talos-continuation-trigger` crate so the webhook receiver
// (which may resolve approval gates via inbound HMAC-signed POSTs)
// can dispatch continuations without reaching back into the MCP
// module tree. Re-exported here for back-compat with existing
// `crate::advanced::*` import paths used by the resolve-gate /
// resolve-suspension MCP handlers in this file.
pub(crate) use talos_continuation_trigger::{trigger_continuation_workflow, TriggerSourceKind};

async fn handle_deploy_workflow(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // MCP-370 (2026-05-11): strict-parse all three optional string args
    // on this composite-action handler. Pre-fix every chain silently
    // collapsed wrong-type into None / default, so an operator passing
    // typed-wrong `cron_expression: 42` got a workflow deployed
    // WITHOUT a schedule (silent direction-class regression — the
    // workflow needed to fire on a cadence and won't until the operator
    // notices hours/days later). `timezone: 7` (number) silently became
    // UTC — same MCP-347 family. `version_description: 42` silently
    // became None — diagnostic, not security.
    //
    // MCP-1184 (2026-05-17): bring length cap (200 → 256) and trim
    // discipline into parity with the canonical `handle_create_
    // schedule` (schedules.rs:178). Pre-fix this composite handler
    // accepted up to 200 chars while create_schedule allowed 256 —
    // a cron between 201..=256 chars succeeded via the canonical
    // tool but was rejected via deploy_workflow. Persisted value also
    // skipped `.trim()` so leading/trailing whitespace from runbook
    // paste reached `workflow_schedules.cron_expression` and produced
    // ragged dashboard rendering vs trimmed siblings. Same cross-
    // handler drift class as MCP-1183 (scaffold_actor vs
    // set_actor_budget).
    let cron_expression = match args.get("cron_expression") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => match v.as_str() {
            Some(s) if s.is_empty() => None,
            Some(s) if s.len() > 256 => {
                return mcp_error(req_id, -32602, "cron_expression must be ≤ 256 characters")
            }
            Some(s) if s.trim().is_empty() => None,
            Some(s) => Some(s.trim().to_string()),
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("cron_expression must be a string, got {kind}"),
                );
            }
        },
    };

    let timezone =
        match crate::utils::validate_optional_string(args, "timezone", "UTC", None, &req_id) {
            Ok(s) => s,
            Err(resp) => return resp,
        };

    let version_description: Option<String> = match args.get("version_description") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => match v.as_str() {
            Some(s) => Some(s.to_string()),
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("version_description must be a string, got {kind}"),
                );
            }
        },
    };

    // MCP-195 (2026-05-08): validate cron AND timezone semantically,
    // not just by field count. Pre-fix the handler accepted any
    // timezone string and any 5/6-field cron — semantic errors fell
    // through to the scheduler and silently produced
    // next_trigger_at = NULL (schedule never fires). Mirrors the
    // create_schedule validation chain.
    if let Some(ref cron) = cron_expression {
        let field_count = cron.split_whitespace().count();
        if !(5..=6).contains(&field_count) {
            return mcp_error(
                req_id,
                -32602,
                "Invalid cron_expression: must have 5 or 6 space-separated fields",
            );
        }
        if let Err(e) = talos_scheduler::validate_cron(cron) {
            return mcp_error(req_id, -32602, &e);
        }
        // MCP-618 (2026-05-12): enforce 60s minimum cron interval to
        // match `handle_create_schedule` (schedules.rs:241). Pre-fix
        // both `handle_deploy_workflow` and `handle_promote_workflow`
        // composite-action handlers accepted any parseable cron, so a
        // user could deploy a workflow that fires every second via
        // either composite path while the canonical `create_schedule`
        // tool rejected the same expression. The GraphQL surface
        // (mutations.rs:1355) already enforces the gate; bring the
        // MCP composite handlers to parity.
        if let Err(e) = talos_scheduler::validate_cron_min_interval(cron, 60) {
            return mcp_error(req_id, -32602, &e);
        }
    }
    if let Err(e) = talos_scheduler::validate_timezone(&timezone) {
        return mcp_error(
            req_id,
            -32602,
            &format!(
                "{e}. Use an IANA timezone identifier like 'UTC', 'America/New_York', or 'Europe/London'."
            ),
        );
    }

    // Verify ownership and not archived
    let (wf_name, wf_status) = match state
        .advanced_repo
        .get_workflow_name_status(wf_id, user_id)
        .await
    {
        Ok(Some(row)) => row,
        Ok(None) => return mcp_error(req_id, -32000, "Workflow not found or access denied"),
        Err(e) => {
            tracing::error!(workflow_id = %wf_id, "deploy_workflow fetch failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to fetch workflow");
        }
    };

    if wf_status.as_deref() == Some("archived") {
        return mcp_error(req_id, -32000, "Cannot deploy an archived workflow");
    }

    // Publish version
    let publish_result: Result<_, anyhow::Error> =
        talos_workflow_versions::WorkflowVersionService::publish_version(
            &state.db_pool,
            wf_id,
            user_id,
            version_description,
            Some(&state.workflow_repo),
        )
        .await;
    let (version, _warnings) = match publish_result {
        Ok(v) => v,
        Err(e) => {
            let err_str = e.to_string();
            if err_str.contains("Workflow validation failed") {
                return mcp_error(req_id, -32000, &err_str);
            }
            tracing::error!(err = ?e, workflow_id = %wf_id, "deploy_workflow publish failed");
            return mcp_error(req_id, -32000, "Failed to publish version");
        }
    };

    // Set workflow status to active
    // MCP-738 (2026-05-13): log activation failures. Pre-fix
    // `let _ = ...await` swallowed errors silently: deploy_workflow
    // returned success even when the activation UPDATE failed (DB
    // outage, deleted-mid-flight, etc.), leaving the workflow stuck
    // in its pre-deploy status. User triggers the workflow, sees
    // "not active", and is confused. Conservative fix: log at WARN
    // so operators see the gap; preserve the existing success path
    // because the version itself was already published successfully
    // (changing the deploy contract would be more invasive).
    if let Err(e) = state.advanced_repo.activate_workflow(wf_id, user_id).await {
        tracing::warn!(
            target: "talos_audit",
            workflow_id = %wf_id,
            user_id = %user_id,
            error = %e,
            "deploy_workflow: version published but activate_workflow failed — workflow may remain in pre-deploy status"
        );
    }

    // Spawn best-effort search text + embedding updates
    let db_pool = state.db_pool.clone();
    tokio::spawn(async move {
        crate::utils::update_workflow_search_text(&db_pool, wf_id, user_id).await;
    });
    let db2 = state.db_pool.clone();
    tokio::spawn(async move {
        crate::search::auto_embed_workflow(wf_id, user_id, &db2).await;
    });

    // Optionally create schedule
    let mut schedule_id_str: Option<String> = None;
    if let Some(ref cron) = cron_expression {
        let next_trigger_at = talos_scheduler::calculate_next_trigger(cron, &timezone).ok();
        let sid = Uuid::new_v4();
        let insert_result = state
            .advanced_repo
            .create_workflow_schedule(sid, wf_id, user_id, cron, &timezone, next_trigger_at)
            .await;

        match insert_result {
            Ok(_) => schedule_id_str = Some(sid.to_string()),
            Err(e) => {
                tracing::error!(workflow_id = %wf_id, "deploy_workflow schedule insert failed: {}", e);
                // Non-fatal: version is published but schedule failed
                return mcp_text(
                    req_id,
                    &serde_json::to_string_pretty(&serde_json::json!({
                        "workflow_id": wf_id.to_string(),
                        "workflow_name": wf_name,
                        "version_id": version.id,
                        "status": "active",
                        "warning": "Workflow published successfully but schedule creation failed. Use create_schedule to add scheduling.",
                        "next_steps": [
                            format!("Verify with trigger_workflow workflow_id={}", wf_id),
                            format!("Monitor with get_execution_history workflow_id={}", wf_id),
                            "Set failure alerts with create_alert_rule",
                        ]
                    }))
                    .unwrap_or_default(),
                );
            }
        }
    }

    let wf_id_str = wf_id.to_string();
    let mut result = serde_json::json!({
        "workflow_id": &wf_id_str,
        "workflow_name": wf_name,
        "version_id": version.id,
        "status": "active",
        "next_steps_checklist": [
            {
                "step": 1,
                "action": "Verify deployment",
                "tool": "test_workflow",
                "args": { "workflow_id": &wf_id_str, "assert_status": "completed" },
                "note": "Runs synchronously against the live version and validates output. Use trigger_workflow for async fire-and-forget instead.",
            },
            {
                "step": 2,
                "action": "Monitor execution history",
                "tool": "get_execution_history",
                "args": { "workflow_id": &wf_id_str },
            },
            {
                "step": 3,
                "action": "Set failure alerts (recommended for production)",
                "tool": "create_alert_rule",
                "args": { "workflow_id": &wf_id_str },
                "note": "Get notified on failures without polling get_execution_history.",
            },
        ],
    });

    if let Some(ref sid) = schedule_id_str {
        result["schedule_id"] = serde_json::json!(sid);
        result["cron_expression"] = serde_json::json!(cron_expression);
        result["timezone"] = serde_json::json!(timezone);
    }

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

async fn handle_promote_workflow(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let src_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // MCP-251 (2026-05-10): pre-fix `publish: "false"` (string) silently
    // fell through `.as_bool()` returning None and defaulted to `true` —
    // a direction-class bug where the operator explicitly opted out of
    // publishing but the system published anyway. Same family as MCP-189 /
    // MCP-229 / MCP-245 / MCP-246. validate_optional_bool rejects wrong
    // types loudly with -32602.
    let should_publish = match crate::utils::validate_optional_bool(args, "publish", true, &req_id)
    {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // MCP-371 (2026-05-11): pre-fix `.and_then(as_str).filter(!empty)`
    // silently collapsed wrong-type into None. Operator passing
    // `cron_expression: 42` on promote_workflow got the workflow
    // promoted WITHOUT a schedule when they clearly intended one.
    // Sibling fix to MCP-370 (deploy_workflow); same direction-class
    // regression on a scheduling surface.
    //
    // MCP-1184 (2026-05-17): length cap (200 → 256) and trim
    // discipline parity with canonical `handle_create_schedule`,
    // matching the same fix applied to handle_deploy_workflow above.
    let cron_expression = match args.get("cron_expression") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => match v.as_str() {
            Some(s) if s.is_empty() => None,
            Some(s) if s.len() > 256 => {
                return mcp_error(req_id, -32602, "cron_expression must be ≤ 256 characters")
            }
            Some(s) if s.trim().is_empty() => None,
            Some(s) => Some(s.trim().to_string()),
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("cron_expression must be a string, got {kind}"),
                );
            }
        },
    };

    // MCP-1185 (2026-05-17): caller-specified timezone, parity with
    // `handle_create_schedule` and `handle_deploy_workflow`. Pre-fix
    // this handler accepted `cron_expression` but hardcoded "UTC" at
    // every schedule-persistence call site below — a caller wanting
    // to promote a workflow that should fire at 9 AM PST got a
    // schedule that fires at 9 AM UTC (8 hours earlier). Silent
    // direction-class regression: the operator sees promotion
    // succeed with a schedule but the schedule fires at the wrong
    // local time, off by up to 12 hours depending on intent. Same
    // MCP-347 direction-class family applied to a scheduling
    // surface. Default to UTC for backward compatibility with
    // callers who omit the field; reject invalid IANA strings via
    // validate_timezone the same way create_schedule does.
    let timezone =
        match crate::utils::validate_optional_string(args, "timezone", "UTC", None, &req_id) {
            Ok(s) => s,
            Err(resp) => return resp,
        };
    if let Err(e) = talos_scheduler::validate_timezone(&timezone) {
        return mcp_error(
            req_id,
            -32602,
            &format!(
                "{e}. Use an IANA timezone identifier like 'UTC', 'America/New_York', or 'Europe/London'."
            ),
        );
    }

    // MCP-261 (2026-05-10): pre-fix `as_object().cloned().unwrap_or_default()`
    // silently substituted an empty map for any wrong-type value
    // (`config_overrides: "label1=val"` string, `config_overrides: [{...}]`
    // array). The promotion would proceed with NO overrides applied — the
    // operator's deliberate intent was silently dropped. Distinguish
    // absent from wrong-type so the typo is visible.
    let config_overrides = match args.get("config_overrides") {
        None | Some(serde_json::Value::Null) => serde_json::Map::new(),
        Some(serde_json::Value::Object(o)) => o.clone(),
        Some(v) => {
            let kind = crate::utils::json_type_name(v);
            return mcp_error(
                req_id,
                -32602,
                &format!("config_overrides must be an object, got {kind}"),
            );
        }
    };

    // MCP-195 (2026-05-08): semantic cron validation in addition to
    // field-count. Pre-fix `cron_expression: "5 5 5 5 99"` (invalid
    // day-of-week range) passed the 5-field check, persisted, and
    // produced a NULL next_trigger_at — the schedule never fired.
    // Mirrors create_schedule and deploy_workflow.
    if let Some(ref cron) = cron_expression {
        let field_count = cron.split_whitespace().count();
        if !(5..=6).contains(&field_count) {
            return mcp_error(
                req_id,
                -32602,
                "Invalid cron_expression: must have 5 or 6 fields",
            );
        }
        if let Err(e) = talos_scheduler::validate_cron(cron) {
            return mcp_error(req_id, -32602, &e);
        }
        // MCP-618 (2026-05-12): minimum-interval gate, same shape as
        // `handle_deploy_workflow`. The `promote_workflow` composite
        // path also creates schedules and must enforce the same 60s
        // minimum as `create_schedule`.
        if let Err(e) = talos_scheduler::validate_cron_min_interval(cron, 60) {
            return mcp_error(req_id, -32602, &e);
        }
    }

    // Fetch source workflow
    let src_row = state
        .advanced_repo
        .get_source_workflow_for_promote(src_id, user_id)
        .await;

    let src = match src_row {
        Ok(Some(r)) => r,
        Ok(None) => return mcp_error(req_id, -32000, "Source workflow not found or access denied"),
        Err(e) => {
            tracing::error!(workflow_id = %src_id, "promote_workflow fetch failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to fetch source workflow");
        }
    };
    let (src_name, graph_json_str, capabilities, intent) =
        (src.name, src.graph_json, src.capabilities, src.intent);

    // MCP-251 (2026-05-10): pre-fix `target_name: "   "` bypassed
    // `!s.is_empty()` and persisted a whitespace-only workflow name —
    // same MCP-249 family. Trim before the empty check so accidental
    // padding falls through to the "{src_name} (Production)" default.
    let target_name = args
        .get("target_name")
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("{} (Production)", src_name));

    // Parse graph and apply config overrides
    let mut graph: serde_json::Value =
        serde_json::from_str(&graph_json_str).unwrap_or(serde_json::json!({"nodes":[],"edges":[]}));

    let mut overrides_applied: Vec<String> = Vec::new();
    if !config_overrides.is_empty() {
        if let Some(nodes) = graph.get_mut("nodes").and_then(|n| n.as_array_mut()) {
            for node in nodes.iter_mut() {
                let label = node
                    .get("data")
                    .and_then(|d| d.get("label"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                if let Some(override_obj) = config_overrides.get(&label).and_then(|v| v.as_object())
                {
                    if let Some(data) = node.get_mut("data").and_then(|v| v.as_object_mut()) {
                        for (field, val) in override_obj {
                            // Remove any case-variant of this key (e.g. "url" when setting "URL")
                            // to avoid stale shadow keys left over from LLM prefill.
                            let field_lower = field.to_lowercase();
                            let stale_keys: Vec<String> = data
                                .keys()
                                .filter(|k| k.to_lowercase() == field_lower && *k != field)
                                .cloned()
                                .collect();
                            for k in stale_keys {
                                data.remove(&k);
                            }
                            data.insert(field.clone(), val.clone());
                        }
                        overrides_applied.push(label.clone());
                    }
                }
            }
        }
    }

    let new_graph_json = graph.to_string();
    let new_wf_id = Uuid::new_v4();

    // Insert new workflow
    if let Err(e) = state
        .advanced_repo
        .insert_promoted_workflow(
            new_wf_id,
            user_id,
            &target_name,
            &new_graph_json,
            &capabilities,
            intent.as_ref(),
        )
        .await
    {
        tracing::error!(source_workflow_id = %src_id, "promote_workflow insert failed: {}", e);
        return mcp_error(req_id, -32000, "Failed to create promoted workflow");
    }

    let mut version_id_str: Option<String> = None;
    if should_publish {
        match talos_workflow_versions::WorkflowVersionService::publish_version(
            &state.db_pool,
            new_wf_id,
            user_id,
            Some(format!("Promoted from {}", src_name)),
            Some(&state.workflow_repo),
        )
        .await
        {
            Ok((v, _warnings)) => {
                version_id_str = Some(v.id.to_string());
                let _ = state
                    .advanced_repo
                    .activate_workflow(new_wf_id, user_id)
                    .await;

                // Spawn background updates
                let db1 = state.db_pool.clone();
                tokio::spawn(async move {
                    crate::utils::update_workflow_search_text(&db1, new_wf_id, user_id).await;
                });
                let db2 = state.db_pool.clone();
                tokio::spawn(async move {
                    crate::search::auto_embed_workflow(new_wf_id, user_id, &db2).await;
                });
            }
            Err(e) => {
                tracing::error!(new_workflow_id = %new_wf_id, "promote_workflow publish failed: {}", e);
                // Non-fatal: workflow created but not published
            }
        }
    }

    // Optionally create schedule
    let mut schedule_id_str: Option<String> = None;
    if let Some(ref cron) = cron_expression {
        // MCP-1185: use caller-validated timezone (defaults to "UTC"
        // when omitted, matching pre-fix behaviour for backward
        // compatibility).
        let next_trigger_at = talos_scheduler::calculate_next_trigger(cron, &timezone).ok();
        let sid = Uuid::new_v4();
        if state
            .advanced_repo
            .create_workflow_schedule(sid, new_wf_id, user_id, cron, &timezone, next_trigger_at)
            .await
            .is_ok()
        {
            schedule_id_str = Some(sid.to_string());
        }
    }

    let mut result = serde_json::json!({
        "new_workflow_id": new_wf_id.to_string(),
        "name": target_name,
        "source_workflow_id": src_id.to_string(),
        "published": should_publish && version_id_str.is_some(),
        "config_overrides_applied": overrides_applied,
    });

    if let Some(ref vid) = version_id_str {
        result["version_id"] = serde_json::json!(vid);
    }
    if let Some(ref sid) = schedule_id_str {
        result["schedule_id"] = serde_json::json!(sid);
        result["cron_expression"] = serde_json::json!(cron_expression);
        // MCP-1185: echo the timezone so callers can verify the
        // schedule was created in the intended zone (silent UTC
        // default was the pre-fix direction-class regression).
        result["timezone"] = serde_json::json!(timezone);
    }

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

// ────────────────────────────────────────────────────────────────────────────
// Round 43 — SLA threshold management
// ────────────────────────────────────────────────────────────────────────────

async fn handle_set_workflow_sla_threshold(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // Verify workflow belongs to user. MCP-207 (2026-05-08): surface DB
    // errors loudly instead of `unwrap_or(false)` masking them as
    // "not found" — same swallowed-error class as MCP-188.
    let exists = match state
        .advanced_repo
        .verify_workflow_ownership_exists(wf_id, user_id)
        .await
    {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(workflow_id = %wf_id, "verify_workflow_ownership_exists failed: {:#}", e);
            return crate::utils::database_error(req_id);
        }
    };
    if !exists {
        return crate::utils::workflow_not_found_error(req_id);
    }

    // notification_webhook is optional — thresholds without a webhook are still
    // visible in get_workflow_sla_report and list_workflow_sla_thresholds.
    //
    // MCP-343 (2026-05-11): strict-parse — see create_approval_gate
    // sibling fix for the rationale. Wrong-type silently losing the
    // webhook means an operator's SLA-breach notifications never fire
    // even though the thresholds appear set; direction-class for an
    // observability path where missing alerts mean missed incidents.
    let webhook: Option<&str> = match args.get("notification_webhook") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => match v.as_str() {
            Some(s) if s.is_empty() => None,
            Some(url) if url.len() > 2048 => {
                return mcp_error(
                    req_id,
                    -32602,
                    "notification_webhook must be ≤ 2048 characters",
                )
            }
            Some(url) => Some(url),
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("notification_webhook must be a string (URL), got {kind}"),
                );
            }
        },
    };

    if let Some(url) = webhook {
        if let Err(reason) = check_outbound_url_no_ssrf(url) {
            return mcp_error(req_id, -32602, reason);
        }
    }

    // MCP-207: pre-fix `p95_latency_ms: 5000.7` (fractional) silently
    // returned None from `as_i64()`, dropping the threshold and either
    // (a) tripping the "at least one required" branch when it was the
    // only field, or (b) silently saving only the other threshold when
    // both were sent. Reject fractional / wrong-type explicitly.
    let p95_latency_ms: Option<i64> = match args.get("p95_latency_ms") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => match v.as_f64() {
            Some(f) if f.is_nan() || f.is_infinite() => {
                return mcp_error(req_id, -32602, "p95_latency_ms must be a finite integer")
            }
            Some(f) if f.fract() != 0.0 => {
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("p95_latency_ms must be an integer (no fractional part), got {f}"),
                )
            }
            _ => match v.as_i64() {
                Some(n) => Some(n),
                None => {
                    return mcp_error(
                        req_id,
                        -32602,
                        &format!(
                            "p95_latency_ms must be an integer, got {}",
                            crate::utils::json_type_name(v)
                        ),
                    )
                }
            },
        },
    };
    let success_rate_pct: Option<f64> = match args.get("success_rate_pct") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => match v.as_f64() {
            Some(f) => Some(f),
            None => {
                return mcp_error(
                    req_id,
                    -32602,
                    &format!(
                        "success_rate_pct must be a number, got {}",
                        crate::utils::json_type_name(v)
                    ),
                )
            }
        },
    };

    if let Some(ms) = p95_latency_ms {
        if ms <= 0 || ms > 86_400_000 {
            return mcp_error(
                req_id,
                -32602,
                "p95_latency_ms must be > 0 and ≤ 86400000 (24 h)",
            );
        }
    }
    if let Some(pct) = success_rate_pct {
        if pct.is_nan() || !(0.0..=100.0).contains(&pct) {
            return mcp_error(
                req_id,
                -32602,
                "success_rate_pct must be between 0.0 and 100.0",
            );
        }
    }

    if p95_latency_ms.is_none() && success_rate_pct.is_none() {
        return mcp_error(
            req_id,
            -32602,
            "At least one of p95_latency_ms or success_rate_pct is required",
        );
    }

    let threshold_id = Uuid::new_v4();
    match state
        .advanced_repo
        .upsert_sla_threshold(
            threshold_id,
            wf_id,
            user_id,
            p95_latency_ms,
            success_rate_pct,
            webhook,
        )
        .await
    {
        Ok(_) => mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "workflow_id": wf_id,
                "p95_latency_ms": p95_latency_ms,
                "success_rate_pct": success_rate_pct,
                "notification_webhook": webhook,
                "status": "saved",
            }))
            .unwrap_or_default(),
        ),
        Err(e) => {
            tracing::error!("set_workflow_sla_threshold: {}", e);
            mcp_error(req_id, -32000, "Failed to save SLA threshold")
        }
    }
}

async fn handle_list_workflow_sla_thresholds(
    req_id: Option<serde_json::Value>,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    match state.advanced_repo.list_sla_thresholds(user_id).await {
        Ok(rows) => {
            let thresholds: Vec<serde_json::Value> = rows
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "id":                   r.id.to_string(),
                        "workflow_id":          r.workflow_id.to_string(),
                        "workflow_name":        r.workflow_name,
                        "p95_latency_ms":       r.p95_latency_ms,
                        "success_rate_pct":     r.success_rate_pct,
                        "notification_webhook": r.notification_webhook,
                        "created_at":           r.created_at,
                    })
                })
                .collect();
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "thresholds": thresholds,
                    "count": thresholds.len(),
                }))
                .unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("list_workflow_sla_thresholds: {}", e);
            mcp_error(req_id, -32000, "Failed to list SLA thresholds")
        }
    }
}

async fn handle_publish_built_in_templates(
    req_id: Option<serde_json::Value>,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // MCP-327 (2026-05-11): publishing system templates to the
    // marketplace writes to a shared `marketplace_listings` namespace
    // visible to every tenant. The pre-fix gate was the agent-level
    // `is_admin` (per-tenant); an organization-scoped admin agent
    // could re-publish stale built-in templates or remove them
    // (`remove_stale_system_marketplace` runs first). Both directions
    // affect every tenant's install_from_marketplace behavior. Same
    // require_platform_admin family as MCP-323/324/325/326 — the
    // `users.is_platform_admin` column is the deployment-wide gate.
    let is_platform_admin = state
        .actor_repo
        .is_platform_admin(user_id)
        .await
        .unwrap_or(false);
    if !is_platform_admin {
        return mcp_error(
            req_id,
            -32601,
            "publish_built_in_templates requires platform-admin privileges. \
             It mutates the deployment-wide system marketplace listings \
             that every tenant browses via search_marketplace / install_from_marketplace.",
        );
    }
    // Step 1: Remove stale system-published entries linked to sandbox/QA templates.
    let removed = match state.advanced_repo.remove_stale_system_marketplace().await {
        Ok(n) => {
            if n > 0 {
                tracing::info!(
                    "publish_built_in_templates: removed {} stale sandbox/QA entries",
                    n
                );
            }
            n
        }
        Err(e) => {
            tracing::error!("publish_built_in_templates cleanup: {}", e);
            return mcp_error(
                req_id,
                -32000,
                "Failed to clean up stale marketplace entries",
            );
        }
    };

    // Step 2: Publish system-seeded (first-party) templates not yet listed.
    match state.advanced_repo.publish_system_templates().await {
        Ok(published) => {
            tracing::info!(
                "publish_built_in_templates: published {} templates (removed {} stale)",
                published,
                removed
            );
            // MCP-421 (2026-05-11): persistent audit on deployment-wide
            // marketplace mutation. Same audit-gap class as MCP-398
            // (pause/resume_executions) — platform-admin gated
            // operations that touch every tenant's view must leave a
            // permanent admin_event_log row. tracing::info! is
            // ephemeral console state. A compromised platform-admin
            // token could republish bad templates, alter what every
            // tenant sees in search_marketplace, then exit — and the
            // only forensic trail would be the rotation of marketplace
            // listings themselves (no operator-action attribution).
            crate::actor::spawn_log_admin_event(
                state.db_pool.clone(),
                user_id,
                "marketplace_built_in_templates_published",
                "system",
                None,
                format!(
                    "Built-in templates republished: {} added, {} stale removed",
                    published, removed
                ),
                Some(serde_json::json!({
                    "published": published,
                    "removed_stale": removed,
                })),
            );
            mcp_text(
                req_id,
                &serde_json::json!({
                    "published": published,
                    "removed_stale": removed,
                    "message": format!("Published {} built-in template(s) to the marketplace, removed {} stale sandbox/QA entries", published, removed)
                })
                .to_string(),
            )
        }
        Err(e) => {
            tracing::error!("publish_built_in_templates: {}", e);
            mcp_error(
                req_id,
                -32000,
                "Failed to publish built-in templates to marketplace",
            )
        }
    }
}

async fn handle_test_sla_webhook(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // Load SLA threshold config for this workflow
    let threshold_row = match state.advanced_repo.get_sla_threshold(wf_id, user_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return mcp_error(
            req_id,
            -32000,
            "No SLA threshold configured for this workflow. Use set_workflow_sla_threshold first.",
        ),
        Err(e) => {
            tracing::error!("test_sla_webhook: DB lookup failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to load SLA threshold configuration");
        }
    };

    let webhook_url = threshold_row.notification_webhook;
    let p95_latency_ms = threshold_row.p95_latency_ms;
    let success_rate_pct = threshold_row.success_rate_pct;

    // Security: only allow HTTPS webhook URLs
    if !webhook_url.starts_with("https://") {
        return mcp_error(
            req_id,
            -32602,
            "Webhook URL must use HTTPS. Update the SLA threshold with a valid HTTPS endpoint.",
        );
    }
    // Re-validate at fire time. Catches stored URLs that predate the r285
    // SSRF hardening (obfuscated IPv4 — octal/hex/integer encodings) which
    // were accepted at write time but resolve to internal IPs at fire time.
    if let Err(reason) = check_outbound_url_no_ssrf(&webhook_url) {
        tracing::warn!(
            workflow_id = %wf_id,
            "test_sla_webhook: stored URL failed SSRF re-check: {reason}"
        );
        return mcp_error(
            req_id,
            -32602,
            "Stored notification_webhook is not safe to fire. Re-create the SLA threshold with a public HTTPS endpoint.",
        );
    }

    // Build a synthetic breach payload matching what the SLA monitor would send
    let payload = serde_json::json!({
        "event": "sla_breach_test",
        "workflow_id": wf_id.to_string(),
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "breach": {
            "type": "synthetic_test",
            "message": "This is a test SLA breach event fired by test_sla_webhook. No actual breach occurred.",
        },
        "thresholds": {
            "p95_latency_ms": p95_latency_ms,
            "success_rate_pct": success_rate_pct,
        },
        "source": "talos-platform",
    });

    // Fire the HTTP POST with a strict timeout — never follow redirects (SSRF
    // mitigation). L4: shared builder adds the connect-time SSRF resolver that
    // closes the DNS-rebinding TOCTOU. MCP-1034: explicit connect_timeout for
    // fast-fail on black-holed endpoint.
    let client = match crate::ssrf_resolver::build_outbound_webhook_client("talos-sla-monitor/1.0")
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("test_sla_webhook: failed to build HTTP client: {}", e);
            return mcp_error(req_id, -32000, "Failed to build HTTP client");
        }
    };

    let response = client
        .post(&webhook_url)
        .header("Content-Type", "application/json")
        .header("X-Talos-Event", "sla_breach_test")
        .json(&payload)
        .send()
        .await;

    match response {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let success = (200..300).contains(&(status as usize));
            // MCP-1180 (2026-05-17): bound the response-body read.
            // See test_approval_webhook below for the full rationale —
            // same pattern, same threat model (user-supplied webhook
            // URL can stream unbounded bytes within the 10s timeout
            // budget; `.text().await.chars().take(500)` materialises
            // the full body first). 8 KiB cap is comfortably above
            // the 500-char × 4-byte UTF-8 worst case.
            let body_preview = read_capped_body_preview(resp, 8 * 1024).await;

            tracing::info!(
                workflow_id = %wf_id,
                webhook_url_prefix = %webhook_url.chars().take(50).collect::<String>(),
                status_code = status,
                "test_sla_webhook fired"
            );

            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "fired": true,
                    "status_code": status,
                    "success": success,
                    "response_preview": body_preview,
                    "payload_sent": payload,
                    "note": if success {
                        "Webhook endpoint responded successfully. SLA alerts will be delivered to this endpoint."
                    } else {
                        "Webhook endpoint returned a non-2xx status. Check the endpoint configuration."
                    }
                }))
                .unwrap_or_default(),
            )
        }
        Err(e) => {
            let is_timeout = e.is_timeout();
            tracing::warn!(
                workflow_id = %wf_id,
                error = %e,
                "test_sla_webhook: HTTP request failed"
            );
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "fired": false,
                    "success": false,
                    "error": if is_timeout {
                        "Request timed out after 10 seconds — endpoint is unreachable or too slow"
                    } else {
                        "HTTP request failed — check the webhook URL is correct and reachable"
                    },
                    "note": "Update the SLA threshold with set_workflow_sla_threshold if the endpoint has changed.",
                }))
                .unwrap_or_default(),
            )
        }
    }
}

/// MCP-1180 (2026-05-17): bounded HTTP response-body preview reader.
///
/// Streams chunks from a `reqwest::Response` into a `Vec<u8>` capped at
/// `max_bytes`, stops at first cap violation, and lossy-decodes to UTF-8
/// before truncating to the first 500 characters.
///
/// Shared between `test_approval_webhook` and `test_sla_webhook` —
/// both accept operator-supplied webhook URLs and were previously
/// using `resp.text().await.chars().take(500)`, which materialises
/// the FULL response body before truncating. Reqwest's request
/// `.timeout(10s)` only bounds wall-clock time; within that window
/// the operator's webhook can stream gigabytes on a fast link.
async fn read_capped_body_preview(resp: reqwest::Response, max_bytes: usize) -> String {
    let mut bytes: Vec<u8> = Vec::new();
    let mut stream = resp.bytes_stream();
    use futures::StreamExt;
    while let Some(chunk_result) = stream.next().await {
        match chunk_result {
            Ok(chunk) => {
                let remaining = max_bytes.saturating_sub(bytes.len());
                if remaining == 0 {
                    break;
                }
                if chunk.len() <= remaining {
                    bytes.extend_from_slice(&chunk);
                } else {
                    bytes.extend_from_slice(&chunk[..remaining]);
                    break;
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "webhook response-body chunk read failed mid-stream"
                );
                break;
            }
        }
    }
    String::from_utf8_lossy(&bytes)
        .chars()
        .take(500)
        .collect::<String>()
}

async fn handle_test_approval_webhook(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let gate_id = match crate::utils::require_uuid(args, "gate_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // Load the gate and its notification_webhook (must belong to user)
    let (gate_title, webhook_url) = match state
        .advanced_repo
        .get_approval_gate_webhook(gate_id, user_id)
        .await
    {
        Ok(Some((title, wh))) => (title, wh),
        Ok(None) => return mcp_error(req_id, -32000, "Approval gate not found or access denied"),
        Err(e) => {
            tracing::error!("test_approval_webhook: DB lookup failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to load approval gate");
        }
    };

    let webhook_url = match webhook_url {
        Some(url) if !url.is_empty() => url,
        _ => return mcp_error(
            req_id,
            -32000,
            "This approval gate has no notification_webhook configured. Re-create it with a notification_webhook parameter.",
        ),
    };

    // Security: HTTPS-only
    if !webhook_url.starts_with("https://") {
        return mcp_error(
            req_id,
            -32602,
            "Stored notification_webhook does not use HTTPS — update the gate configuration",
        );
    }
    // Re-validate at fire time. Catches stored URLs that predate the r285
    // SSRF hardening (obfuscated IPv4 — octal/hex/integer encodings) which
    // were accepted at write time but resolve to internal IPs at fire time.
    if let Err(reason) = check_outbound_url_no_ssrf(&webhook_url) {
        tracing::warn!(
            gate_id = %gate_id,
            "test_approval_webhook: stored URL failed SSRF re-check: {reason}"
        );
        return mcp_error(
            req_id,
            -32602,
            "Stored notification_webhook is not safe to fire. Re-create the gate with a public HTTPS endpoint.",
        );
    }

    let base_url = talos_config::get_base_url();

    // Build a synthetic approval_required payload identical to what create_approval_gate fires
    let payload = serde_json::json!({
        "event": "approval_required_test",
        "gate_id": gate_id.to_string(),
        "title": gate_title,
        "approve_url": format!("{}/approvals/test-token/approve", base_url),
        "reject_url": format!("{}/approvals/test-token/reject", base_url),
        "expires_in_hours": 168,
        "payload": {},
        "source": "talos-platform",
        "note": "This is a test notification fired by test_approval_webhook. No real gate was created.",
    });

    // MCP-1034: explicit connect_timeout for fast-fail. L4: shared builder adds
    // the connect-time SSRF resolver that closes the DNS-rebinding TOCTOU.
    let client =
        match crate::ssrf_resolver::build_outbound_webhook_client("talos-approval-gate/1.0") {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("test_approval_webhook: failed to build HTTP client: {}", e);
                return mcp_error(req_id, -32000, "Failed to build HTTP client");
            }
        };

    let response = client
        .post(&webhook_url)
        .header("Content-Type", "application/json")
        .header("X-Talos-Event", "approval_required_test")
        .json(&payload)
        .send()
        .await;

    match response {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let success = (200..300).contains(&(status as usize));
            // MCP-1180 (2026-05-17): bound the response-body read at
            // 8 KiB BEFORE decoding to UTF-8 + char-truncating to 500.
            // The prior `resp.text().await.chars().take(500)` read the
            // FULL response body into a String first, then truncated.
            // `reqwest::Client::builder().timeout(10s)` only caps wall-
            // clock time — within 10 s on a fast connection an
            // operator-controlled webhook can stream ~1 GiB. Reading
            // that into a `String` for a 500-char preview pegs heap
            // on every test_approval_webhook call and amplifies when
            // multiple gates are tested concurrently. Same truncate-
            // first-then-format discipline as MCP-1160..1167 for DLP
            // scrub sites — bound bytes AT the I/O boundary, not
            // after materialisation. 8 KiB = 16× the 500-char ceiling
            // at the worst 4-byte UTF-8 case, leaving headroom for
            // early envelope text (HTML/JSON wrapping) before the
            // operator-visible message. Canonical streaming-cap shape
            // borrowed from worker/src/host_impl.rs::wit_graphql::fetch
            // (10 MiB bound on GraphQL responses).
            let body_preview = read_capped_body_preview(resp, 8 * 1024).await;

            tracing::info!(
                gate_id = %gate_id,
                status_code = status,
                "test_approval_webhook fired"
            );

            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "fired": true,
                    "gate_id": gate_id.to_string(),
                    "status_code": status,
                    "success": success,
                    "response_preview": body_preview,
                    "payload_sent": payload,
                    "note": if success {
                        "Webhook endpoint responded successfully. Approval notifications will be delivered to this endpoint."
                    } else {
                        "Webhook endpoint returned a non-2xx status. Check the endpoint configuration before relying on approval notifications."
                    }
                }))
                .unwrap_or_default(),
            )
        }
        Err(e) => {
            let is_timeout = e.is_timeout();
            tracing::warn!(
                gate_id = %gate_id,
                error = %e,
                "test_approval_webhook: HTTP request failed"
            );
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "fired": false,
                    "gate_id": gate_id.to_string(),
                    "success": false,
                    "error": if is_timeout {
                        "Request timed out after 10 seconds — endpoint is unreachable or too slow"
                    } else {
                        "HTTP request failed — check the webhook URL is correct and reachable"
                    },
                    "note": "Re-create the approval gate with a corrected notification_webhook if the endpoint has changed.",
                }))
                .unwrap_or_default(),
            )
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Suspend / Resume handlers
// ────────────────────────────────────────────────────────────────────────────

async fn handle_create_workflow_suspension(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // Generate 256-bit random correlation_id (= bearer token for the callback URL)
    let correlation_id = {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    };

    // MCP-167 (2026-05-08): reject whitespace-only descriptions. The
    // description surfaces in operator dashboards AND in the resume
    // payload to the continuation workflow.
    //
    // MCP-433 (2026-05-11): migrate to canonical helper. Pre-fix
    // lacked the control-char check that the broader description
    // sweep enforces. Suspension descriptions flow into the resume
    // payload's continuation-workflow input — padding or control
    // chars there could break a downstream node doing exact string
    // match. Same migration as MCP-432.
    let description_owned = match crate::utils::validate_multiline_description(
        "description",
        args.get("description").and_then(|v| v.as_str()),
        2000,
        "Omit the field entirely to leave description blank.",
        req_id.clone(),
    ) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let description = description_owned.as_deref();
    let state_val = match args.get("state") {
        Some(v) => {
            if v.to_string().len() > 100_000 {
                return mcp_error(req_id, -32602, "state must be ≤ 100 KB when serialized");
            }
            Some(v.clone())
        }
        None => None,
    };
    // MCP-309 (2026-05-11): strict-parse so a typo'd or wrong-type
    // `continuation_workflow_id` surfaces loudly instead of silently
    // creating a suspension whose resume does nothing. See
    // `handle_create_approval_gate` above for the rationale.
    let continuation_workflow_id: Option<Uuid> =
        match crate::utils::parse_optional_uuid_strict(args, "continuation_workflow_id", &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };

    // Validate continuation workflow ownership if provided
    if let Some(cwf_id) = continuation_workflow_id {
        let exists = state
            .advanced_repo
            .check_workflow_ownership(cwf_id, user_id)
            .await
            .unwrap_or(false);

        if !exists {
            return mcp_error(
                req_id,
                -32000,
                "continuation_workflow_id not found or access denied",
            );
        }
    }

    // MCP-168 (2026-05-08): validate timeout_hours range. Pre-fix
    // there was no validation: timeout_hours=-5 produced a suspension
    // whose timeout_at was 5 hours BEFORE now (immediately-expired,
    // operationally useless), and timeout_hours=99999 produced a
    // timeout_at 11+ years in the future (effectively unbounded
    // suspension lifetime). Range [1, 8760] mirrors refresh_memory_ttl.
    // MCP-257 (2026-05-10): pre-fix `as_f64()` collapsed wrong-type
    // (`timeout_hours: "24"` string) into None, so the suspension was
    // created with no timeout — operator asked for 24h but got unbounded
    // lifetime. Distinguish absent from wrong-type.
    let timeout_at: Option<chrono::DateTime<chrono::Utc>> = match args.get("timeout_hours") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => match v.as_f64() {
            Some(h) if !h.is_finite() => {
                return mcp_error(req_id, -32602, "timeout_hours must be a finite number")
            }
            Some(h) if !(1.0..=8760.0).contains(&h) => {
                return mcp_error(
                    req_id,
                    -32602,
                    "timeout_hours must be between 1 and 8760 (1 hour to 1 year)",
                )
            }
            Some(h) => Some(chrono::Utc::now() + chrono::Duration::seconds((h * 3600.0) as i64)),
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("timeout_hours must be a number, got {kind}"),
                );
            }
        },
    };

    let base_url = talos_config::get_base_url();
    let callback_url = format!("{}/api/callbacks/{}", base_url, correlation_id);

    let suspension_id: Uuid = match state
        .advanced_repo
        .create_suspension(
            user_id,
            &correlation_id,
            description,
            continuation_workflow_id,
            state_val.as_ref(),
            timeout_at,
            &callback_url,
        )
        .await
    {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("create_workflow_suspension insert failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to create workflow suspension");
        }
    };

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "suspension_id": suspension_id,
            "correlation_id": correlation_id,
            "callback_url": callback_url,
            "timeout_at": timeout_at.map(|t| t.to_rfc3339()),
            "description": description,
            "instructions": [
                format!("Share '{}' with the external system", callback_url),
                "POST to callback_url with JSON payload to resume",
                "The correlation_id is the bearer token — keep it private",
                "No other auth is required on the callback endpoint",
            ]
        }))
        .unwrap_or_default(),
    )
}

async fn handle_list_workflow_suspensions(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // MCP-145 (2026-05-08): reject unknown status values explicitly
    // instead of silently passing them to the repo (which returns an
    // empty list — operator misreads as "no suspensions exist" when
    // the filter was actually invalid). Mirrors list_workflows' shape.
    //
    // MCP-346 (2026-05-11): also reject wrong-type loudly. See sibling
    // fix in handle_list_approval_gates.
    let status_filter: Option<&str> = match args.get("status") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => match v.as_str() {
            Some(s) if matches!(s, "waiting" | "resumed" | "expired" | "cancelled") => Some(s),
            Some(s) => {
                // MCP-1030: cap reflected status at 64 chars.
                let preview = talos_text_util::bounded_preview(s, 64);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!(
                        "Invalid status filter '{preview}'. Valid values: waiting, resumed, expired, cancelled",
                    ),
                );
            }
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("status filter must be a string, got {kind}"),
                );
            }
        },
    };

    match state
        .advanced_repo
        .list_suspensions(user_id, status_filter)
        .await
    {
        Ok(rows) => {
            let suspensions: Vec<serde_json::Value> = rows
                .iter()
                .map(|r| serde_json::json!({
                    "id": r.id.to_string(),
                    "correlation_id": r.correlation_id,
                    "description": r.description,
                    "status": r.status,
                    "continuation_workflow_id": r.continuation_workflow_id.map(|u| u.to_string()),
                    "callback_url": r.callback_url,
                    "timeout_at": r.timeout_at.map(|t| t.to_rfc3339()),
                    "resumed_at": r.resumed_at.map(|t| t.to_rfc3339()),
                    "resumed_by": r.resumed_by,
                    "created_at": r.created_at.to_rfc3339(),
                }))
                .collect();

            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "suspensions": suspensions,
                    "count": suspensions.len(),
                }))
                .unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("list_workflow_suspensions failed: {}", e);
            mcp_error(req_id, -32000, "Failed to list workflow suspensions")
        }
    }
}

async fn handle_resume_workflow_by_correlation_id(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let correlation_id = match args.get("correlation_id").and_then(|v| v.as_str()) {
        Some(c) if c.len() == 64 && c.chars().all(|c| c.is_ascii_hexdigit()) => c,
        Some(_) => {
            return mcp_error(
                req_id,
                -32602,
                "correlation_id must be exactly 64 hex characters",
            )
        }
        None => return mcp_error(req_id, -32602, "Missing required field: correlation_id"),
    };

    let payload = {
        let p = args
            .get("payload")
            .cloned()
            .unwrap_or(serde_json::json!({}));
        if p.to_string().len() > 100_000 {
            return mcp_error(req_id, -32602, "payload must be ≤ 100 KB when serialized");
        }
        p
    };

    // Atomic claim: matches the public /api/callbacks/{correlation_id} path's
    // pattern — UPDATE...WHERE status='waiting' RETURNING — so two concurrent
    // resume calls cannot both pass and double-fire the continuation. The
    // pre-r288 SELECT + status-check + trigger + mark sequence had a TOCTOU
    // window where a self-race (e.g. retry-on-error script) could fire the
    // continuation workflow twice.
    let (suspension_id, continuation_id) = match state
        .advanced_repo
        .claim_suspension_for_mcp_resume(correlation_id, user_id, &payload)
        .await
    {
        Ok(Some(claim)) => claim,
        Ok(None) => {
            return mcp_error(
                req_id,
                -32000,
                "Suspension not found, access denied, or no longer waiting",
            )
        }
        Err(e) => {
            tracing::error!("resume_workflow_by_correlation_id claim failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to claim suspension");
        }
    };

    // Trigger continuation workflow if configured. Mark-resumed already
    // happened atomically as part of the claim above.
    let exec_id_str = if let Some(wf_id) = continuation_id {
        trigger_continuation_workflow(
            &state.db_pool,
            state.registry.clone(),
            state.nats_client.clone(),
            state.secrets_manager.clone(),
            user_id,
            wf_id,
            &payload,
            suspension_id,
            TriggerSourceKind::WorkflowSuspension,
        )
        .await
    } else {
        None
    };

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "resumed": true,
            "suspension_id": suspension_id,
            "execution_id": exec_id_str,
            "resumed_by": "mcp_tool",
        }))
        .unwrap_or_default(),
    )
}

async fn handle_cancel_workflow_suspension(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // MCP-290 (2026-05-11): mirror resume_workflow_by_correlation_id's
    // strict 64-hex validation. Pre-fix `correlation_id: "   "` (or any
    // malformed value) was passed verbatim to the SQL filter, returning
    // a "Suspension not found, access denied, or not in waiting status"
    // error — operator's typo looked like a real not-found. Validate
    // format upfront so the error message points at the actual problem.
    let correlation_id = match args.get("correlation_id").and_then(|v| v.as_str()) {
        Some(c) if c.len() == 64 && c.chars().all(|c| c.is_ascii_hexdigit()) => c,
        Some(_) => {
            return mcp_error(
                req_id,
                -32602,
                "correlation_id must be exactly 64 hex characters",
            )
        }
        None => return mcp_error(req_id, -32602, "Missing required field: correlation_id"),
    };

    match state
        .advanced_repo
        .cancel_suspension(correlation_id, user_id)
        .await
    {
        Ok(n) if n > 0 => mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "cancelled": true,
                "correlation_id": correlation_id,
            }))
            .unwrap_or_default(),
        ),
        Ok(_) => mcp_error(
            req_id,
            -32000,
            "Suspension not found, access denied, or not in waiting status",
        ),
        Err(e) => {
            tracing::error!("cancel_workflow_suspension failed: {}", e);
            mcp_error(req_id, -32000, "Failed to cancel suspension")
        }
    }
}
