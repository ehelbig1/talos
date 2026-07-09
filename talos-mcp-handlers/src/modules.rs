use super::types::JsonRpcResponse;
use super::utils::{mcp_error, mcp_text};
use super::{auth, McpState};
use std::sync::Arc;
use tokio::sync::OnceCell;
use uuid::Uuid;

/// Process-wide cache for the module-catalog directory walk.
/// 2026-05-28 audit Perf#4: pre-fix every `list_module_catalog` call
/// re-walked `/app/module-templates/` — ~60 read_dir entries × 2 file
/// reads each = ~180 syscalls per dashboard load. The templates are
/// baked into the controller image at build time and the only
/// legitimate refresh trigger is a pod restart, so a process-lifetime
/// cache is the right shape. `tokio::sync::OnceCell` over `std::sync::
/// OnceLock` because the initializer is async (the spawn_blocking
/// catalog walk must run on the blocking pool — MCP-H8).
static CATALOG_CACHE: OnceCell<Vec<serde_json::Value>> = OnceCell::const_new();

pub fn tool_schemas() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "name": "list_templates",
            "description": "List available module templates. By default shows only first-party platform templates. Set include_sandboxes=true to also show user-created sandbox modules.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "include_sandboxes": { "type": "boolean", "description": "Include user-created sandbox templates (default: false)" }
                },
            }
        }),
        serde_json::json!({
            "name": "list_modules",
            "description": "List all compiled modules (from compile_template or compile_custom_sandbox). Returns module IDs needed for create_workflow.",
            "inputSchema": {
                "type": "object",
                "properties": {},
            }
        }),
        serde_json::json!({
            "name": "delete_module",
            "description": "Delete a compiled module from the registry. Warns if workflows or webhooks reference it.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "module_id": { "type": "string", "description": "UUID of the module to delete" },
                    "force": { "type": "boolean", "description": "Force delete even if workflows or webhooks reference this module (default: false)" }
                },
                "required": ["module_id"]
            }
        }),
        serde_json::json!({
            "name": "cleanup_modules",
            "description": "Delete compiled modules NOT referenced by any workflow, optionally scoped by name prefix. Returns count of deleted modules. WARNING: omitting prefix deletes ALL of your unreferenced modules and requires confirm: true.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "prefix": { "type": "string", "description": "Only delete unreferenced modules whose name starts with this prefix (minimum 2 characters). Omit to delete ALL unreferenced modules (requires confirm: true)." },
                    "confirm": { "type": "boolean", "description": "Must be explicitly set to true when prefix is omitted, to confirm deletion of ALL unreferenced modules. Ignored when prefix is provided." }
                }
            }
        }),
        serde_json::json!({
            "name": "get_module_info",
            "description": "Get detailed information about a compiled module: name, capability world, size, allowed hosts, allowed secrets, and whether source code is available. Never returns actual wasm bytes or source code.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "module_id": { "type": "string", "description": "UUID of the module to inspect" }
                },
                "required": ["module_id"]
            }
        }),
        serde_json::json!({
            "name": "get_module_unification_status",
            "description": "Operator health surface for the unified `modules` table (the single store backing every dispatch). Returns: (1) module counts by kind, (2) drift counters between dispatch reads and the modules table — non-zero values indicate a regression worth investigating, (3) backfill progress on optional metadata columns (dependencies, imported_interfaces), (4) read-path counters (`hit_new` should track total reads; non-zero `miss_new` indicates a dispatch lookup failure).\n\nNo arguments. Read-only. Useful for ongoing health monitoring.",
            "inputSchema": { "type": "object", "properties": {} }
        }),
        serde_json::json!({
            "name": "cleanup_module_versions",
            "description": "Clean up version sprawl from a module name prefix. Finds all modules whose name starts with `prefix`, identifies the most recently compiled one as the keeper, and deletes older versions that are NOT referenced by any non-archived workflow. Workflows that reference older versions are reported back so you can decide whether to rebind them via add_node_to_workflow.\n\nSafe by default: dry_run=true returns the plan without deleting. Older modules still in active workflow use are NEVER deleted; they're surfaced under `still_referenced` for manual handling.\n\nTypical use: `cleanup_module_versions(prefix: \"ship-fetch-github-impl\")` after a few hot_update_module iterations have left several `-v1`, `-v2`, `-v3` modules around.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "prefix": {
                        "type": "string",
                        "description": "Name prefix to group modules by (e.g. 'ship-fetch-github-impl'). Matches via SQL LIKE 'prefix%'. Min 3 chars to avoid accidental wildcard cleanup. Required."
                    },
                    "dry_run": {
                        "type": "boolean",
                        "description": "When true (default), return the plan without deleting anything. Set to false to perform the deletion."
                    }
                },
                "required": ["prefix"]
            }
        }),
        serde_json::json!({
            "name": "test_secret_access",
            "description": "Debug whether a given module would be allowed to read a given secret path WITHOUT actually executing the module. Runs the same three gates the worker enforces and reports each as PASS/FAIL with a human-readable reason:\n\n  1. capability_world — does the module's WIT world import the `secrets` interface? (must be one of: secrets, database, agent, trusted)\n  2. allowed_secrets allowlist — is the path covered by the module's grant (exact / prefix match / wildcard)?\n  3. reserved_host_path — LLM provider keys (anthropic/api_key, openai/api_key, gemini/api_key) are deny-listed for ALL guests, even with allowed_secrets: [\"*\"]; the host uses them via the llm::* interface only.\n  4. vault_presence — is the secret actually stored in the vault for this user?\n\nUse this when get_secret() is failing at runtime with `unauthorized` to identify which gate is responsible without redeploying.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "module_id": { "type": "string", "description": "Canonical module UUID from list_modules. One id per module — no separate template/wasm-module distinction." },
                    "secret_path": { "type": "string", "description": "Vault path to test (e.g. 'github/token' or 'oauth/gmail/abc/access_token'). vault:// prefix is stripped automatically." }
                },
                "required": ["module_id", "secret_path"]
            }
        }),
        serde_json::json!({
            "name": "list_module_usage",
            "description": "Show which workflows directly use a given module. Fast single-query check — critical before deleting or updating modules. For indirect sub-workflow dependencies use get_module_dependents.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "module_id": { "type": "string", "description": "UUID of the module to check" }
                },
                "required": ["module_id"]
            }
        }),
        serde_json::json!({
            "name": "find_unreferenced_modules",
            "description": "Find compiled modules not referenced by any workflow. Useful for cleanup. Optionally filter by compile age.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "days": { "type": "number", "description": "Only show modules compiled more than this many days ago (default: 30)" }
                },
            }
        }),
        serde_json::json!({
            "name": "batch_delete_modules",
            "description": "Delete multiple compiled modules at once. Skips modules referenced by workflows or webhooks unless force=true.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "module_ids": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Array of module UUID strings to delete"
                    },
                    "force": { "type": "boolean", "description": "Force delete even if workflows or webhooks reference the modules (default: false)" }
                },
                "required": ["module_ids"]
            }
        }),
        serde_json::json!({
            "name": "rename_module",
            "description": "Rename a compiled module.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "module_id": { "type": "string", "description": "UUID of the module to rename" },
                    "name": { "type": "string", "description": "New name (max 200 characters)" }
                },
                "required": ["module_id", "name"]
            }
        }),
        serde_json::json!({
            "name": "get_module_history",
            "description": "Get the hot-update history for a module, showing previous and new content hashes, sizes, and timestamps.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "module_id": { "type": "string", "description": "UUID of the module" }
                },
                "required": ["module_id"]
            }
        }),
        serde_json::json!({
            "name": "get_module_dependents",
            "description": "Show which workflows and sub-workflows depend on a given module. Returns direct users and indirect users via sub-workflow references. For a fast direct-only check use list_module_usage.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "module_id": { "type": "string", "description": "UUID of the module to check" }
                },
                "required": ["module_id"]
            }
        }),
        serde_json::json!({
            "name": "get_module_compatibility",
            "description": "Check if a module can be used in a specific capability world. Worlds form a hierarchy from least- to most-privileged: minimal (0) < http/network (1) < secrets/llm (2) < filesystem/cache/messaging (3) < database/agent (4) < governance (5) < automation/trusted (6). A target world is compatible iff its level ≥ the module's required level.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "module_id": { "type": "string", "description": "UUID of the module to check" },
                    "capability_world": { "type": "string", "description": "Target capability world — short form (e.g. 'minimal', 'http', 'secrets', 'llm', 'database', 'agent', 'governance', 'automation') or suffixed form ('http-node', 'agent-node', etc.). Both are accepted." }
                },
                "required": ["module_id", "capability_world"]
            }
        }),
        serde_json::json!({
            "name": "set_module_rate_limit",
            "description": "Set a per-module outbound HTTP rate limit (requests per minute). Set to null to clear.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "module_id": { "type": "string", "description": "UUID of the module" },
                    "requests_per_minute": { "type": ["number", "null"], "description": "Rate limit 1-1000, or null to clear" }
                },
                "required": ["module_id", "requests_per_minute"]
            }
        }),
        serde_json::json!({
            "name": "get_module_rate_limit",
            "description": "Get the current rate limit setting for a module.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "module_id": { "type": "string", "description": "UUID of the module" }
                },
                "required": ["module_id"]
            }
        }),
        serde_json::json!({
            "name": "share_module_with_org",
            "description": "Share a module with an organization. All org members will be able to use it.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "module_id": { "type": "string", "description": "UUID of the module to share" },
                    "org_id": { "type": "string", "description": "UUID of the organization" }
                },
                "required": ["module_id", "org_id"]
            }
        }),
        serde_json::json!({
            "name": "list_org_modules",
            "description": "List all modules shared with an organization.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "org_id": { "type": "string", "description": "UUID of the organization" }
                },
                "required": ["org_id"]
            }
        }),
        serde_json::json!({
            "name": "list_module_catalog",
            "description": "List built-in module templates available for installation. Returns metadata grouped by category. Each entry shows 'installed' (bool) and 'module_id' (UUID or null). Workflow authoring flow: (1) list_module_catalog — find module, note 'name' and 'installed'; (2) if not installed: install_module_from_catalog(name: '<name>') → returns module_id UUID; (3) add_node_to_workflow(module_id: '<UUID>'). PAGINATION: full unfiltered catalog is large (80KB+); prefer filtering by category/capability_world or searching by query. 'limit' caps returned modules (default 50, max 200).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "category": { "type": "string", "description": "Filter to a single category (e.g. 'Network', 'AI', 'Integration'). Case-insensitive substring match." },
                    "capability_world": { "type": "string", "description": "Filter by WIT capability world (e.g. 'http-node', 'agent-node')." },
                    "query": { "type": "string", "description": "Substring match against name / display_name / description. Case-insensitive." },
                    "installed_only": { "type": "boolean", "description": "If true, return only modules already installed by the current user. Default: false." },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 200, "description": "Max modules to return (default: 50, max: 200). matching_count = post-filter pre-pagination count; catalog_total_count = catalog-wide pre-filter; returned_count = items in this page. total_available + total are kept as deprecated aliases of matching_count + catalog_total_count." },
                    "offset": { "type": "integer", "minimum": 0, "description": "Skip the first N modules (default: 0). Combine with limit for pagination." }
                },
            }
        }),
        serde_json::json!({
            "name": "install_module_from_catalog",
            "description": "Compile and install a built-in module template from the catalog. Returns a module_id ready for use in add_node_to_workflow. Much faster than writing custom code for common patterns. Response always includes module_id, name, wasm_sha256 (hex SHA-256 of the compiled bytes), compiled_at (RFC3339 UTC of when the WASM was written), and bytes_changed (true on first install OR when the source produced different bytes than the prior install — false signals an idempotent no-op). Use bytes_changed/wasm_sha256 to verify a reinstall actually picked up new source after a platform deploy. Check for optional warning fields: grant_empty_warning (module has deny-all secret access — every vault:// config value will fail at runtime, reinstall with allowed_secrets) and wildcard_grant_warning (module has wildcard [\"*\"] secret access — consider scoping to explicit paths to limit blast radius).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": { "type": "string", "description": "Catalog module name (e.g. 'http-request', 'echo-debug'). Use list_module_catalog to see available names." },
                    "display_name": { "type": "string", "description": "Optional display name override. Defaults to the catalog template's display_name." },
                    "allowed_secrets": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Vault key paths this module is permitted to read. Values are MERGED (union) with the catalog template's required minimums — you can add paths but cannot remove the template's required ones. Pass your actual vault paths (e.g. ['anthropic/api_key', 'openai/api_key']). Use ['*'] to allow all secrets. SECURITY NOTE: empty [] does not mean deny-all for catalog modules — the template's own required_secrets are always included. If a reinstall omits this parameter, the stored list is preserved (no accidental clearing)."
                    },
                    "allowed_methods": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "HTTP method allowlist (e.g. ['GET', 'POST']). Empty = allow all methods."
                    },
                    "pin_module": { "type": "boolean", "description": "Mark module as pinned so restore_pinned_modules reinstalls it on session start. Useful for modules you always want available (e.g. llm-inference, http-request). Default: false." },
                    "fuel_budget": {
                        "type": "object",
                        "description": "Optional — declare expected payload shape so max_fuel is computed via the formula (baseline + 60K per item + 2 fuel per input byte + 2 fuel per llm_output_bytes, × safety_multiplier, clamped [1M, 50M]). Set llm_output_bytes for LLM-backed modules. Overrides the template's recommended_fuel (in talos.json) and the ~2.2M default. Mirrors the same shape used by hot_update_module and compile_custom_sandbox.",
                        "properties": {
                            "expected_items": { "type": "integer", "minimum": 0 },
                            "bytes_per_item": { "type": "integer", "minimum": 0 },
                            "llm_output_bytes": { "type": "integer", "minimum": 0 },
                            "safety_multiplier": { "type": "number", "minimum": 1.0, "maximum": 5.0 }
                        }
                    }
                },
                "required": ["name"]
            }
        }),
        serde_json::json!({
            "name": "restore_pinned_modules",
            "description": "Check which pinned modules are missing their WASM compilation and reinstall them. Call this at session start if session_start reports needs_restore modules. Returns lists of already_present, restored, and failed modules.",
            "inputSchema": {
                "type": "object",
                "properties": {},
            }
        }),
        serde_json::json!({
            "name": "find_module_alternatives",
            "description": "Find catalog modules that can substitute for a given module or that match a capability description. Use this when a workflow pattern uses a module you can't use (e.g. 'I need Teams instead of Slack') or when you want to discover modules for a specific task (e.g. 'send notifications', 'store to database'). Returns alternatives ranked by category match and description similarity, each with install instructions and config migration notes from workflow pattern alternatives.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "module_name": {
                        "type": "string",
                        "description": "Display name of the module you want to replace (e.g. 'Slack Message', 'Gmail'). Use list_module_catalog to see display names."
                    },
                    "capability": {
                        "type": "string",
                        "description": "Natural language description of what you need (e.g. 'send notifications', 'store data to a database', 'receive webhook events'). Used for discovery when you don't have a specific module to replace."
                    },
                    "limit": {
                        "type": "number",
                        "description": "Maximum number of alternatives to return (default: 5, max: 20)"
                    }
                }
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
    match name {
        "list_templates" => Some(handle_list_templates(req_id, args, state, agent).await),
        "list_modules" => Some(handle_list_modules(req_id, args, state, agent).await),
        "delete_module" => Some(handle_delete_module(req_id, args, state, agent).await),
        "cleanup_modules" => Some(handle_cleanup_modules(req_id, args, state, agent).await),
        "get_module_info" => Some(handle_get_module_info(req_id, args, state, agent).await),
        "test_secret_access" => Some(handle_test_secret_access(req_id, args, state, agent).await),
        "cleanup_module_versions" => {
            Some(handle_cleanup_module_versions(req_id, args, state, agent).await)
        }
        "get_module_unification_status" => {
            Some(handle_get_module_unification_status(req_id, state).await)
        }
        "list_module_usage" => Some(handle_list_module_usage(req_id, args, state, agent).await),
        "find_unreferenced_modules" => {
            Some(handle_find_unreferenced_modules(req_id, args, state, agent).await)
        }
        "batch_delete_modules" => {
            Some(handle_batch_delete_modules(req_id, args, state, agent).await)
        }
        "rename_module" => Some(handle_rename_module(req_id, args, state, agent).await),
        "get_module_history" => Some(handle_get_module_history(req_id, args, state, agent).await),
        "get_module_dependents" => {
            Some(handle_get_module_dependents(req_id, args, state, agent).await)
        }
        "get_module_compatibility" => {
            Some(handle_get_module_compatibility(req_id, args, state, agent).await)
        }
        "set_module_rate_limit" => {
            Some(handle_set_module_rate_limit(req_id, args, state, agent).await)
        }
        "get_module_rate_limit" => {
            Some(handle_get_module_rate_limit(req_id, args, state, agent).await)
        }
        "share_module_with_org" => {
            Some(handle_share_module_with_org(req_id, args, state, agent).await)
        }
        "list_org_modules" => Some(handle_list_org_modules(req_id, args, state, agent).await),
        "list_module_catalog" => Some(handle_list_module_catalog(req_id, args, state, agent).await),
        "install_module_from_catalog" => {
            Some(handle_install_module_from_catalog(req_id, args, state, agent).await)
        }
        "restore_pinned_modules" => Some(handle_restore_pinned_modules(req_id, state, agent).await),
        "find_module_alternatives" => {
            Some(handle_find_module_alternatives(req_id, args, state).await)
        }
        _ => None,
    }
}

// ── list_templates ──────────────────────────────────────────────────────────

async fn handle_list_templates(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    _agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    // MCP-192 (2026-05-08): reject wrong-type include_sandboxes
    // loudly. Pre-fix `include_sandboxes: "true"` (string) silently
    // became false. Same family as MCP-189.
    let include_sandboxes =
        match crate::utils::validate_optional_bool(args, "include_sandboxes", false, &req_id) {
            Ok(b) => b,
            Err(resp) => return resp,
        };
    let templates = state
        .registry
        .list_templates(None)
        .await
        .unwrap_or_default();

    // MCP-59 + MCP-60 (2026-05-07):
    //   * MCP-59: include_sandboxes=false should hide every non-platform
    //     category, not just `sandbox`. User-extracted modules sometimes
    //     land in categories like `user`/`installed` that pre-fix slipped
    //     through. Now: only treat `category` values from a small known
    //     "platform" allowlist as included by default; everything else
    //     requires include_sandboxes=true.
    //   * MCP-60: dedupe by template name. Pre-fix the listing surfaced
    //     "LLM Inference", "HTTP Request" etc. multiple times when a
    //     user-installed copy of a catalog template existed alongside the
    //     platform original. Keep the first entry (registry order — usually
    //     platform-first) and drop subsequent duplicates by name. The
    //     `duplicate_count` field tells operators how many entries were
    //     collapsed so they can detect drift in the underlying registry.
    const PLATFORM_CATEGORIES: &[&str] = &[
        "platform",
        "core",
        "io",
        "ai",
        "data",
        "monitoring",
        "communication",
        "integration",
    ];

    let is_platform = |cat: &str| -> bool { PLATFORM_CATEGORIES.contains(&cat) };

    let pre_filter: Vec<&talos_registry::NodeTemplate> = templates
        .iter()
        // Always exclude legacy workflow_template rows (feature removed).
        .filter(|t| t.category != "workflow_template")
        // include_sandboxes flag widens the set: when false, only platform
        // categories pass; when true, only legacy workflow_template is excluded.
        .filter(|t| include_sandboxes || is_platform(&t.category))
        .collect();

    let mut seen_names: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut duplicates_dropped: u32 = 0;
    let list: Vec<serde_json::Value> = pre_filter
        .iter()
        .filter(|t| {
            if seen_names.insert(t.name.clone()) {
                true
            } else {
                duplicates_dropped += 1;
                false
            }
        })
        .map(|t| {
            serde_json::json!({
                "id": t.id, "name": t.name, "category": t.category,
                "description": t.description,
                // Requirements surfaced so an agent picking a template sees,
                // BEFORE installing, the minimum actor capability ceiling
                // (`capability_world`), the vault secret paths to grant
                // (`requires_secrets`), and whether a module built from it
                // pauses for human approval (`requires_approval_for`) —
                // instead of discovering these via a ceiling-denial /
                // secret-resolution failure / unexpected suspension at run
                // time. Mirrors the GraphQL NodeTemplate fields.
                "capability_world": t.capability_world,
                "requires_secrets": t.allowed_secrets,
                "requires_approval_for": t.requires_approval_for,
            })
        })
        .collect();

    let envelope = serde_json::json!({
        "count": list.len(),
        "include_sandboxes": include_sandboxes,
        "duplicates_dropped": duplicates_dropped,
        "templates": list,
    });

    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id: req_id,
        result: Some(
            serde_json::json!({ "content": [{ "type": "text", "text": serde_json::to_string_pretty(&envelope).unwrap_or_default() }] }),
        ),
        error: None,
    }
}

// ── list_modules ─────────────────────────────────────────────────────────────

async fn handle_list_modules(
    req_id: Option<serde_json::Value>,
    _args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);

    // Query the user_modules view — a single source of truth that unions
    // wasm_modules (custom sandboxes) and user-owned node_templates (catalog
    // installs) with deduplication. This ensures list_modules, list_module_catalog,
    // and get_system_status.modules all agree on what a "module" is.
    let rows = state
        .module_repo
        .list_user_modules_view(user_id, 100)
        .await
        .unwrap_or_default();

    // Normalize capability_world to the "-node" suffix form used throughout
    // the platform. wasm_modules stores bare names ("minimal", "trusted") while
    // node_templates stores the WIT world name ("minimal-node", "automation-node").
    let normalize_world = |cap: &str| -> String {
        if cap.ends_with("-node") {
            cap.to_string()
        } else {
            format!("{}-node", cap)
        }
    };

    // MCP-26 (2026-05-07): drop the redundant `template_id` field when
    // it equals `module_id` (the Phase-5 unified state — every row in
    // the view post-consolidation). The field stayed in the wire shape
    // as a transition shim but every probe shows the two UUIDs match
    // for every row. Operators reading the response saw two identical
    // UUIDs side-by-side and thought one was wrong. Emit `template_id`
    // ONLY when it differs from `module_id` (legacy alias case) so the
    // rare divergent row is surfaced explicitly while the common case
    // shows one UUID.
    let list: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            let mut obj = serde_json::json!({
                "module_id": r.id,
                "name": r.name,
                "capability_world": normalize_world(&r.capability_world),
                "source": r.source,
            });
            if r.template_id != Some(r.id) {
                if let Some(map) = obj.as_object_mut() {
                    map.insert(
                        "template_id_legacy".to_string(),
                        serde_json::json!(r.template_id),
                    );
                }
            }
            obj
        })
        .collect();

    // MCP-45 (2026-05-07): structured envelope (count + items).
    let envelope = serde_json::json!({
        "count": list.len(),
        "modules": list,
    });
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&envelope).unwrap_or_default(),
    )
}

// ── delete_module ────────────────────────────────────────────────────────────

async fn handle_delete_module(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let mod_id = match crate::utils::require_uuid(args, "module_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    // MCP-229 (2026-05-08): pre-fix `force: "true"` (string) silently
    // became `false` via the `as_bool()`-then-unwrap_or chain. The
    // MCP-189 family fixed this for cleanup_modules.confirm via
    // validate_optional_bool — apply the same shape here. delete_module
    // is destructive enough that operators typing `force: "true"`
    // expecting force-delete should get a wrong-type error rather
    // than a misleading "module is still referenced" rejection.
    let force = match crate::utils::validate_optional_bool(args, "force", false, &req_id) {
        Ok(b) => b,
        Err(resp) => return resp,
    };

    // Check references (workflows + webhooks) before deleting
    if !force {
        let refs = state
            .module_repo
            .get_module_ref_counts(mod_id, user_id)
            .await
            .unwrap_or(talos_module_repository::ModuleRefCounts {
                workflow_count: 0,
                webhook_count: 0,
                webhook_ids_sample: vec![],
            });
        if refs.workflow_count > 0 {
            return mcp_text(req_id, &format!(
                "Module {} is referenced by {} workflow(s). Use force: true to delete anyway, or delete the workflows first.",
                mod_id, refs.workflow_count
            ));
        }
        if refs.webhook_count > 0 {
            return mcp_text(
                req_id,
                &format!(
                    "Module {} is referenced by {} active webhook(s): {}. \
                 Update or delete the webhooks first, or use force: true to delete anyway.",
                    mod_id,
                    refs.webhook_count,
                    refs.webhook_ids_sample.join(", ")
                ),
            );
        }
    }

    match state.module_repo.delete_module(mod_id, user_id).await {
        Ok(n) if n > 0 => {
            // MCP-389 (2026-05-11): close the audit-trail gap on
            // module deletion. Pre-fix a successful delete left no
            // `admin_event_log` row, and `delete_module` is more
            // destructive than `delete_workflow` because a deleted
            // module silently breaks every workflow that referenced
            // it (the ref-count gate is bypassed when `force: true`).
            // Forensics needs to be able to reconstruct "what module
            // was deleted at T, with how many references at the
            // time" — record both the module id and the `force`
            // flag in `details`. Sibling fix to the
            // `delete_workflow` audit in the same cycle.
            crate::actor::spawn_log_admin_event(
                state.db_pool.clone(),
                user_id,
                "module_deleted",
                "module",
                Some(mod_id),
                format!("Module {} deleted via MCP delete_module", mod_id),
                Some(serde_json::json!({ "force": force })),
            );
            mcp_text(req_id, &format!("Module {} deleted.", mod_id))
        }
        // MCP-159 (2026-05-08): uniform message — mirrors the
        // cycle-16 fix on rename_module (MCP-155). Pre-fix the
        // handler ran a `module_exists_elsewhere` lookup and split
        // the response into "Access denied — system-owned or
        // belongs to another user" vs "Module not found", letting
        // a caller enumerate which UUIDs existed in the platform
        // across tenants. Drop the extra DB call AND the split
        // message; return the uniform error every other module
        // surface returns.
        Ok(_) => mcp_error(req_id, -32000, "Module not found or access denied"),
        Err(e) => {
            tracing::error!(err = ?e, module_id = %mod_id, "delete_module failed");
            mcp_error(req_id, -32000, "Delete failed")
        }
    }
}

// ── cleanup_modules ──────────────────────────────────────────────────────────

async fn handle_cleanup_modules(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    // MCP-177 (2026-05-08): bring cleanup_modules' safety in line with
    // cleanup_workflows. Pre-fix:
    //  - empty-string prefix `""` reached the SQL repo and deleted ALL
    //    unreferenced modules (cycle-25 probe lost 3 real modules);
    //  - whitespace-only prefix passed the length check;
    //  - the delete-all path (omitted prefix) had no `confirm: true`
    //    requirement, unlike cleanup_workflows.
    // Treat empty / whitespace-only as "no prefix"; require min 2 chars
    // when a real prefix is given; require confirm:true for delete-all.
    // MCP-212 (2026-05-08): trim BEFORE the SQL pattern is built. The
    // pre-MCP-177 fix only used trim() in the emptiness check; the
    // un-trimmed value still flowed into `cleanup_unreferenced_modules`
    // and ran SQL `LIKE '  abc...%'`, matching nothing because no
    // module name starts with whitespace. A real probe with
    // `prefix: "  abcdefghijklmnop  "` returned `Deleted 0 module(s).`
    // — caller assumed nothing matched their abcdefghijklmnop prefix
    // when the actual issue was stray whitespace. Same family as
    // MCP-210 search and MCP-211 archive_workflows_by_prefix.
    let prefix_owned: Option<String> = match args.get("prefix").and_then(|v| v.as_str()) {
        Some(p) if p.len() > 500 => {
            return mcp_error(req_id, -32602, "prefix must be ≤ 500 characters")
        }
        Some(p) => {
            let trimmed = p.trim();
            if trimmed.is_empty() {
                None
            } else if trimmed.len() < 2 {
                return mcp_error(
                    req_id,
                    -32602,
                    "prefix must be at least 2 non-whitespace characters to avoid accidental bulk deletion. \
                     Omit prefix and pass confirm: true to delete all unreferenced modules.",
                );
            } else if trimmed.contains('%') || trimmed.contains('_') {
                // MCP-480: reject SQL LIKE wildcards in the user-supplied
                // prefix. The SQL helper builds `LIKE '<prefix>%'` —
                // a caller-supplied `%` or `_` would broaden the match
                // and (critically) bypass the `confirm: true` safety
                // gate below: a 2-char `"%%"` passes the min-length
                // check, then because `prefix.is_some()` the confirm
                // requirement is skipped, and the repo runs
                // `LIKE '%%%'` which matches every row. Same family as
                // the wildcard rejection in `handle_cleanup_module_versions`
                // and `list_modules_by_name_prefix`'s caller — kept in
                // lockstep so a future similar handler doesn't reopen
                // the gate.
                return mcp_error(
                    req_id,
                    -32602,
                    "prefix may not contain SQL LIKE wildcards ('%' or '_'). \
                     Omit prefix and pass confirm: true to delete all unreferenced modules.",
                );
            } else {
                Some(trimmed.to_string())
            }
        }
        None => None,
    };
    let prefix: Option<&str> = prefix_owned.as_deref();
    if prefix.is_none() {
        // MCP-189 (2026-05-08): reject wrong-type confirm loudly.
        // Same family as MCP-187 — pre-fix `confirm: "true"` (string)
        // silently became `false`, the safety guard fired, and the
        // caller had no signal that their input was malformed.
        let confirmed = match crate::utils::validate_optional_bool(args, "confirm", false, &req_id)
        {
            Ok(b) => b,
            Err(resp) => return resp,
        };
        if !confirmed {
            return mcp_error(
                req_id,
                -32602,
                "Refusing to delete all unreferenced modules without confirmation. \
                 Pass confirm: true to proceed, or provide a prefix to scope the deletion.",
            );
        }
    }
    // Only delete modules NOT referenced by any workflow
    match state
        .module_repo
        .cleanup_unreferenced_modules(user_id, prefix)
        .await
    {
        Ok(deleted) => {
            // MCP-399 (2026-05-11): bulk-destructive op audit, sibling
            // to cleanup_workflows / archive_workflows_by_prefix.
            // Although cleanup_modules is scoped to "unreferenced
            // modules", an attacker who first quietly detaches a
            // module from every workflow that uses it can then call
            // cleanup_modules to wipe it — leaving no trace of the
            // existence of the original module. The audit row carries
            // the deleted count and optional prefix.
            if deleted > 0 {
                crate::actor::spawn_log_admin_event(
                    state.db_pool.clone(),
                    user_id,
                    "modules_bulk_cleanup",
                    "module",
                    None,
                    format!(
                        "{} unreferenced module(s) bulk-deleted via cleanup_modules",
                        deleted
                    ),
                    Some(serde_json::json!({
                        "deleted_count": deleted,
                        "prefix": prefix,
                    })),
                );
            }
            mcp_text(req_id, &format!("Deleted {} module(s).", deleted))
        }
        Err(e) => {
            tracing::error!(err = ?e, user_id = %user_id, "cleanup_unused_modules failed");
            mcp_error(req_id, -32000, "Module cleanup failed")
        }
    }
}

// ── get_module_info ─────────────────────────────────────────────────────────

async fn handle_get_module_info(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let module_id = match crate::utils::require_uuid(args, "module_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // Try wasm_modules first — accepts EITHER wasm_modules.id OR template_id.
    // `id` stays the input the caller used (back-compat); `wasm_module_id`
    // and `template_id` are surfaced alongside so callers don't have to drop
    // into psql to find the other UUID for hot_update_module.
    if let Some(info) = state
        .module_repo
        .get_wasm_module_info(module_id, user_id)
        .await
        .unwrap_or(None)
    {
        let host_managed = host_managed_access_for_world(Some(info.capability_world.as_str()));
        // MCP-33 (2026-05-07): when size_bytes=0 on a row that claims
        // source='compiled', the underlying `wasm_bytes` column is empty
        // — usually a marketplace import that wrote the metadata row
        // without persisting bytes. Surface a `bytes_status` flag so
        // operators don't read this as a working module that simply
        // happens to have zero size.
        let bytes_status = if info.size_bytes > 0 {
            "populated"
        } else {
            "missing — module row exists but wasm_bytes is empty; module cannot be executed in this state"
        };
        // MCP-34 (2026-05-07): always emit `compiled_at` (null when
        // absent) so the response shape is consistent across all
        // module sources. Pre-fix the field was conditional on
        // `Some(_)` and operators got `undefined` vs `Date` in their
        // clients. Same for `template_id` — emit explicitly null on
        // the wasm_modules branch when not surfaced separately.
        let mut result = serde_json::json!({
            "id": module_id,
            "wasm_module_id": info.wm_id,
            "name": info.name,
            "source": "compiled",
            "capability_world": info.capability_world,
            "size_bytes": info.size_bytes,
            "bytes_status": bytes_status,
            "allowed_hosts": info.allowed_hosts,
            "allowed_secrets": info.allowed_secrets,
            "host_managed_access": host_managed,
            "has_source_code": info.has_source_code,
            "template_id": info.template_id,
            "rate_limit_per_minute": info.rate_limit_per_minute,
            "compiled_at": info.compiled_at.map(|t| t.to_rfc3339()),
        });
        // Suppress the noisy field when nothing's wrong so the operator
        // attention-budget goes to the missing-bytes case.
        if info.size_bytes > 0 {
            if let Some(map) = result.as_object_mut() {
                map.remove("bytes_status");
            }
        }
        return mcp_text(
            req_id,
            &serde_json::to_string_pretty(&result).unwrap_or_default(),
        );
    }

    // Fall back to node_templates (sandbox modules).
    // Same MCP-33 / MCP-34 invariants: surface size_bytes status
    // explicitly when zero, and always emit `compiled_at` (null when
    // the row pre-dates the column or is a never-compiled template).
    //
    // MCP-795 (2026-05-14): user-scoped fallback lookup. Pre-fix this
    // called the unscoped `get_node_template_info(module_id)` which
    // returned metadata (name, capability_world, allowed_hosts,
    // allowed_secrets, has_source_code, created_at) for EVERY user's
    // private template by UUID. The fallback design intent was
    // "catalog templates after the wasm_modules path misses", but
    // the SQL query had no `user_id IS NULL` filter so it also
    // returned private rows. Same IDOR class as MCP-793 (singular
    // get_template) and MCP-794 (plural list_templates_paginated).
    // Scoped helper gates `WHERE id = $1 AND (user_id IS NULL OR
    // user_id = $2)` — catalog rows (NULL owner) and own private
    // rows both resolve; other users' private rows do not.
    if let Some(tmpl) = state
        .module_repo
        .get_node_template_info_for_user(module_id, user_id)
        .await
        .unwrap_or(None)
    {
        let host_managed = host_managed_access_for_world(tmpl.capability_world.as_deref());
        let bytes_status = if tmpl.size_bytes > 0 {
            "populated"
        } else {
            "missing — template row exists but wasm_bytes is empty; module cannot be executed in this state"
        };
        let mut result = serde_json::json!({
            "id": module_id,
            "name": tmpl.name,
            "source": tmpl.category,
            "capability_world": tmpl.capability_world,
            "size_bytes": tmpl.size_bytes,
            "bytes_status": bytes_status,
            "allowed_hosts": tmpl.allowed_hosts,
            "allowed_secrets": tmpl.allowed_secrets,
            "host_managed_access": host_managed,
            "has_source_code": tmpl.has_source_code,
            "compiled_at": tmpl.created_at.map(|t| t.to_rfc3339()),
        });
        if tmpl.size_bytes > 0 {
            if let Some(map) = result.as_object_mut() {
                map.remove("bytes_status");
            }
        }
        return mcp_text(
            req_id,
            &serde_json::to_string_pretty(&result).unwrap_or_default(),
        );
    }

    mcp_error(req_id, -32000, "Module not found or access denied")
}

/// Surface external access that the HOST grants implicitly based on
/// the module's capability_world — i.e. resources the module can
/// reach without listing them in its `allowed_hosts` / `allowed_secrets`.
///
/// `llm-node` and `agent-node` get the LLM provider's host and vault
/// key resolved through the `llm::*` WIT interface (Tier-2 actors
/// only). Without this surface, an operator looking at LLM Inference
/// would see `allowed_hosts: []` and `allowed_secrets: []` and
/// conclude the module has zero external reach — when it actually
/// calls Anthropic / OpenAI / Gemini and uses their respective
/// vault-stored API keys.
///
/// Accepts `Option<&str>` so both repository row shapes
/// (`Option<String>` for wasm_modules, plain `String` for
/// node_templates) can be projected via `.as_deref()` without
/// cloning.
fn host_managed_access_for_world(capability_world: Option<&str>) -> serde_json::Value {
    let normalized = capability_world
        .map(|s| s.trim_end_matches("-node").to_ascii_lowercase())
        .unwrap_or_default();
    if normalized == "llm" || normalized == "agent" {
        serde_json::json!({
            "external_hosts": talos_workflow_job_protocol::EXTERNAL_LLM_HOSTS,
            "vault_keys": talos_workflow_job_protocol::LLM_PROVIDER_VAULT_PATHS,
            "tier_gate": "Tier-2 actors only — Tier-1 actors are blocked at host_impl::get_llm_api_key, wit_http::fetch, wit_graphql::execute, and wit_webhook::send (see CLAUDE.md `Per-actor LLM tier ceiling`).",
            "note": "Resolved by the host through the `llm::*` WIT interface — module never sees the plaintext key. Not in `allowed_hosts` or `allowed_secrets` because the guest doesn't request these directly.",
        })
    } else {
        serde_json::json!({
            "external_hosts": [],
            "vault_keys": [],
            "note": "This capability_world has no implicit host-managed external access — `allowed_hosts` and `allowed_secrets` are the complete picture.",
        })
    }
}

// ── test_secret_access ───────────────────────────────────────────────────────
//
// Mirrors the worker's three runtime gates (worker/src/host_impl.rs:
// `check_secret_allowlist` + capability gate + reserved-path deny-list) so
// authors can debug `unauthorized` errors without a redeploy cycle.

async fn handle_test_secret_access(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let module_id = match crate::utils::require_uuid(args, "module_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    // MCP-230 (2026-05-08): pre-fix `!s.is_empty()` accepted whitespace
    // secret_path which then got vault://-stripped (no-op) and tested
    // against the allowlist — every gate would fail with a misleading
    // "secret path '   ' not in allowlist" instead of the actionable
    // "wrong input." Same MCP-210 / MCP-216 family.
    let raw_path = match args.get("secret_path").and_then(|v| v.as_str()) {
        Some(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                return mcp_error(
                    req_id,
                    -32602,
                    "secret_path is required (non-empty, non-whitespace, e.g. 'github/token')",
                );
            }
            trimmed.to_string()
        }
        _ => {
            return mcp_error(
                req_id,
                -32602,
                "secret_path is required (string, e.g. 'github/token')",
            )
        }
    };
    // Normalize: same as worker — strip vault:// so callers can paste raw config values.
    let secret_path = raw_path
        .strip_prefix("vault://")
        .unwrap_or(&raw_path)
        .to_string();

    // Resolve module → (capability_world, allowed_secrets). Try wasm_modules first
    // (compiled path), fall back to node_templates (sandbox path).
    let (capability_world, allowed_secrets, source) = match state
        .module_repo
        .get_wasm_module_info(module_id, user_id)
        .await
        .unwrap_or(None)
    {
        Some(info) => (
            info.capability_world,
            info.allowed_secrets,
            "compiled".to_string(),
        ),
        // MCP-795 (2026-05-14): user-scoped fallback lookup — see
        // handle_get_module_info comment above. Without this gate an
        // attacker could test_secret_access against any user's
        // private template UUID and learn whether it has access to a
        // given secret path (probing allowed_secrets across the
        // tenant boundary).
        None => match state
            .module_repo
            .get_node_template_info_for_user(module_id, user_id)
            .await
            .unwrap_or(None)
        {
            Some(tmpl) => (
                tmpl.capability_world
                    .unwrap_or_else(|| "unknown".to_string()),
                tmpl.allowed_secrets,
                tmpl.category,
            ),
            None => return mcp_error(req_id, -32000, "Module not found or access denied"),
        },
    };

    // Gate 1: capability world. The worker requires one of these worlds for
    // any secrets:: import. Mirrors worker/src/host_impl.rs lines around 1374.
    let world_allowed = talos_capability_world::world_allows_secrets(&capability_world);
    let gate_capability = serde_json::json!({
        "name": "capability_world",
        "passed": world_allowed,
        "reason": if world_allowed {
            format!("World '{}' imports the secrets interface.", capability_world)
        } else {
            format!(
                "World '{}' does NOT import the secrets interface. \
                 Recompile with capability_world: secrets-node (or higher: \
                 agent-node, database-node, automation-node).",
                capability_world
            )
        },
    });

    // Gate 2: reserved-host deny-list (LLM provider keys are host-only).
    let is_reserved = talos_workflow_job_protocol::is_llm_provider_vault_path(&secret_path);
    let gate_reserved = serde_json::json!({
        "name": "reserved_host_path",
        "passed": !is_reserved,
        "reason": if is_reserved {
            format!(
                "Path '{}' is reserved for host-internal `llm::*` use and is \
                 deny-listed for ALL guest modules even with allowed_secrets: [\"*\"]. \
                 Use the talos::llm::* host functions to call LLMs without \
                 directly handling the API key.",
                secret_path
            )
        } else {
            format!("Path '{}' is not in the host-reserved set.", secret_path)
        },
    });

    // Gate 3: per-module allowlist (uses the SAME helper the worker enforces).
    let allow_pass =
        talos_workflow_job_protocol::vault_path_permitted(&allowed_secrets, &secret_path);
    let gate_allowlist = serde_json::json!({
        "name": "allowed_secrets",
        "passed": allow_pass,
        "reason": if allow_pass {
            format!(
                "Path '{}' matches the module's allowed_secrets grant {:?}.",
                secret_path, allowed_secrets
            )
        } else if allowed_secrets.is_empty() {
            format!(
                "Module's allowed_secrets list is EMPTY (deny-all). \
                 Recompile with allowed_secrets: [\"{}\"] (exact) or a prefix grant.",
                secret_path
            )
        } else {
            format!(
                "Path '{}' does not match any entry in the module's allowed_secrets {:?}. \
                 Add it (exact path or prefix) and recompile.",
                secret_path, allowed_secrets
            )
        },
    });

    // Gate 4: vault presence — the path may pass all gates but not exist.
    // Cheap existence check; never returns the value.
    let exists = state
        .secrets_manager
        .secret_exists_by_path(&secret_path, user_id)
        .await
        .unwrap_or(false);
    let gate_presence = serde_json::json!({
        "name": "vault_presence",
        "passed": exists,
        "reason": if exists {
            format!("Secret exists at path '{}' for this user.", secret_path)
        } else {
            format!(
                "No secret stored at path '{}' for this user. Add it in the dashboard (Settings → Secrets) — secret writes require 2FA and aren't available through MCP.",
                secret_path
            )
        },
    });

    let all_pass = world_allowed && !is_reserved && allow_pass && exists;
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "module_id": module_id,
            "module_source": source,
            "capability_world": capability_world,
            "allowed_secrets": allowed_secrets,
            "secret_path": secret_path,
            "would_succeed": all_pass,
            "gates": [gate_capability, gate_reserved, gate_allowlist, gate_presence],
        }))
        .unwrap_or_default(),
    )
}

// ── cleanup_module_versions ─────────────────────────────────────────────────
//
// Find every wasm_modules row whose name starts with `prefix`, designate
// the most-recently-compiled as the keeper, attempt to delete the rest.
// Older versions still referenced by a non-archived workflow are NEVER
// deleted — they're surfaced under `still_referenced` so the caller can
// rebind via add_node_to_workflow before retrying.

async fn handle_cleanup_module_versions(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    // MCP-175 / MCP-213 (2026-05-08): trim BEFORE the SQL LIKE pattern
    // is built. The pre-MCP-175 fix only used trim() in the emptiness
    // check; the un-trimmed value still flowed into the SQL pattern,
    // so `prefix: "  abc  "` ran `LIKE '  abc  %'` and returned the
    // misleading "No modules match prefix '  abc  '." even when many
    // modules with the abc prefix existed. Same family as MCP-210 /
    // MCP-211 / MCP-212. Mirrors the canonical handle_actor_forget_prefix
    // pattern: trim once, validate trimmed length, use trimmed value.
    let prefix = match args.get("prefix").and_then(|v| v.as_str()) {
        Some(p) if p.len() > 200 => {
            return mcp_error(req_id, -32602, "prefix must be ≤ 200 characters")
        }
        Some(p) => {
            let trimmed = p.trim();
            if trimmed.is_empty() {
                return mcp_error(
                    req_id,
                    -32602,
                    "prefix must be a non-empty, non-whitespace string",
                );
            }
            if trimmed.len() < 3 {
                return mcp_error(
                    req_id,
                    -32602,
                    "prefix must be at least 3 non-whitespace characters (avoid wildcard cleanup)",
                );
            }
            trimmed.to_string()
        }
        None => return mcp_error(req_id, -32602, "prefix is required"),
    };
    // Reject SQL LIKE wildcards in the user-supplied prefix; the SQL helper
    // appends '%' itself, but a caller-supplied '_' or '%' would silently
    // broaden the match.
    if prefix.contains('%') || prefix.contains('_') {
        return mcp_error(
            req_id,
            -32602,
            "prefix may not contain SQL LIKE wildcards ('%' or '_')",
        );
    }
    // MCP-270 (2026-05-10): direction-class — default true; pre-fix
    // `dry_run: "false"` (string) silently re-enabled dry-run mode
    // when the operator explicitly wanted to perform the cleanup.
    // Same family as MCP-267/268/269.
    let dry_run = match crate::utils::validate_optional_bool(args, "dry_run", true, &req_id) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // 1. List candidates sorted newest-first.
    let candidates = match state
        .module_repo
        .list_modules_by_name_prefix(user_id, &prefix)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(err = ?e, user_id = %user_id, "list_modules_by_name_prefix failed");
            return mcp_error(req_id, -32000, "Failed to list modules");
        }
    };

    if candidates.is_empty() {
        return mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "prefix": prefix,
                "dry_run": dry_run,
                "kept": null,
                "deleted": [],
                "still_referenced": [],
                "message": format!("No modules match prefix '{}'.", prefix)
            }))
            .unwrap_or_default(),
        );
    }

    // 2. Keeper = newest; older = the rest.
    let (keeper_id, keeper_name, keeper_compiled_at) = candidates[0].clone();
    let older = &candidates[1..];

    if older.is_empty() {
        return mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "prefix": prefix,
                "dry_run": dry_run,
                "kept": {
                    "module_id": keeper_id,
                    "name": keeper_name,
                    "compiled_at": keeper_compiled_at.to_rfc3339(),
                },
                "deleted": [],
                "still_referenced": [],
                "message": "Only one module matches the prefix — nothing to clean up."
            }))
            .unwrap_or_default(),
        );
    }

    // 3. Per older module: check workflow references. Only delete the
    // genuinely unreferenced ones; report the rest under
    // still_referenced so the caller can rebind manually.
    let mut deletable: Vec<(uuid::Uuid, String, chrono::DateTime<chrono::Utc>)> = Vec::new();
    let mut still_referenced: Vec<serde_json::Value> = Vec::new();
    for (id, name, compiled_at) in older {
        let refs = state
            .module_repo
            .find_workflows_referencing_module(user_id, *id, 25)
            .await
            .unwrap_or_default();
        if refs.is_empty() {
            deletable.push((*id, name.clone(), *compiled_at));
        } else {
            still_referenced.push(serde_json::json!({
                "module_id": id,
                "name": name,
                "compiled_at": compiled_at.to_rfc3339(),
                "workflow_count": refs.len(),
                "workflows": refs.iter().map(|w| serde_json::json!({
                    "workflow_id": w.id,
                    "workflow_name": w.name,
                })).collect::<Vec<_>>(),
                "rebind_hint": format!(
                    "Rebind the workflow's node to the keeper: add_node_to_workflow(workflow_id: <wf>, node_id: <node>, module_id: '{}')",
                    keeper_id
                ),
            }));
        }
    }

    // 4. Execute deletions (or skip when dry_run).
    let mut deleted_summary: Vec<serde_json::Value> = Vec::new();
    if !dry_run && !deletable.is_empty() {
        let ids: Vec<uuid::Uuid> = deletable.iter().map(|(id, _, _)| *id).collect();
        match state.module_repo.batch_delete_modules(&ids, user_id).await {
            Ok(n) => {
                tracing::info!(
                    user_id = %user_id,
                    prefix = %prefix,
                    deleted = n,
                    keeper_id = %keeper_id,
                    "cleanup_module_versions deleted older modules"
                );
            }
            Err(e) => {
                tracing::error!(err = ?e, user_id = %user_id, "batch_delete_modules failed");
                return mcp_error(req_id, -32000, "Module deletion failed");
            }
        }
    }
    for (id, name, compiled_at) in deletable {
        deleted_summary.push(serde_json::json!({
            "module_id": id,
            "name": name,
            "compiled_at": compiled_at.to_rfc3339(),
        }));
    }

    let action = if dry_run { "Plan" } else { "Cleanup complete" };
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "prefix": prefix,
            "dry_run": dry_run,
            "kept": {
                "module_id": keeper_id,
                "name": keeper_name,
                "compiled_at": keeper_compiled_at.to_rfc3339(),
            },
            "deleted": deleted_summary,
            "still_referenced": still_referenced,
            "message": format!(
                "{}: {} would be deleted, {} still referenced (kept {}).",
                action,
                deleted_summary.len(),
                still_referenced.len(),
                keeper_name
            ),
        }))
        .unwrap_or_default(),
    )
}

// ── get_module_unification_status ───────────────────────────────────────────
//
// Operator surface for monitoring the in-flight module entity unification.
// Combines DB drift counts (from ModuleRepository::module_unification_snapshot)
// with the read-path counters (from ModuleRegistry::read_path_counters) and
// computes the Phase 3.2 (stop dual-write) readiness gate. Read-only.

/// Hardcoded migration phase marker. Bump when the cutover advances.
/// Single source of truth — the operator tool's text + readiness gate
/// rendering both pivot off this. Don't compute it from runtime state
/// (e.g. presence of hit_legacy counts) because cold-start would
/// misclassify the phase before the first read.
const MIGRATION_PHASE: &str = "5.1";

async fn handle_get_module_unification_status(
    req_id: Option<serde_json::Value>,
    state: &McpState,
) -> JsonRpcResponse {
    let snapshot = match state.module_repo.module_unification_snapshot().await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(err = ?e, "module_unification_snapshot failed");
            return mcp_error(req_id, -32000, "Failed to compute unification status");
        }
    };

    let (hit_new, hit_legacy, miss_new, uptime_secs) = state.registry.read_path_counters();
    let total_reads = hit_new + hit_legacy + miss_new;

    // Phase 5.1: unification complete. The readiness gate is retired —
    // there's no further migration milestone ahead. Counters stay on
    // the response for ongoing dispatch-path health monitoring:
    // `miss_new > 0` still means "a get_module returned Module not
    // found", which is now a plain dispatch regression rather than a
    // phase-gate failure.
    let miss_pct = if total_reads > 0 {
        (miss_new as f64 / total_reads as f64) * 100.0
    } else {
        0.0
    };
    let uptime_h = uptime_secs as f64 / 3600.0;
    let uptime_days = uptime_h / 24.0;

    // Drift signals: any non-zero unmirrored count means the dual-write
    // missed something. Should be 0 within one reconciliation interval (default 600s).
    let total_drift = snapshot.wasm_unmirrored + snapshot.template_unmirrored;
    let drift_severity = if total_drift == 0 {
        "ok"
    } else if total_drift < 5 {
        "low"
    } else if total_drift < 50 {
        "medium"
    } else {
        "high"
    };

    let mut by_kind_obj = serde_json::Map::new();
    for (k, v) in &snapshot.by_kind {
        by_kind_obj.insert(k.clone(), serde_json::json!(v));
    }

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "migration_phase": MIGRATION_PHASE,
            "phase_description":
                "Modules are stored in a single canonical `modules` table; one module = one row = one UUID. Every dispatch reads and writes through this table only — there are no legacy alias columns or split id lookups. The forensic counters below are preserved so a future regression in dispatch wiring would be visible (non-zero `miss_new` or non-zero drift), not because the tables exist.",
            "schema_present": {
                "modules_table": true,
                "phase14_columns": true,
                "legacy_alias_columns": false,
            },
            "counts": {
                "modules_total": snapshot.total,
                "modules_by_kind": serde_json::Value::Object(by_kind_obj),
                "legacy_wasm_modules": snapshot.wasm_modules,
                "legacy_node_templates": snapshot.node_templates,
            },
            "drift": {
                "wasm_modules_unmirrored": snapshot.wasm_unmirrored,
                "node_templates_unmirrored": snapshot.template_unmirrored,
                "severity": drift_severity,
                "remediation": if total_drift == 0 {
                    serde_json::Value::Null
                } else {
                    serde_json::json!(
                        "Reconciliation sweep runs every MODULES_RECONCILE_INTERVAL_SECS (default 600s). \
                         Wait one interval; if drift persists, check controller logs for 'modules-table reconciliation sweep failed'."
                    )
                },
            },
            "phase14_backfill": {
                "dependencies_set_count": snapshot.phase14_dependencies_set,
                "imported_interfaces_set_count": snapshot.phase14_imports_set,
                "note": "Counts of modules rows where these optional columns are populated. Low values are normal — most modules don't carry custom dependencies or imported_interfaces."
            },
            "read_path": {
                "hit_new": hit_new,
                // hit_legacy is structurally 0 post-Phase-3.1 (the legacy
                // branch was removed). Surfaced for parity with pre-cutover
                // tooling — a non-zero value would mean someone re-added
                // the fallback as part of a rollback investigation.
                "hit_legacy": hit_legacy,
                "miss_new": miss_new,
                "total_reads": total_reads,
                // MCP-19: numeric outputs, rounded inline. Pre-fix miss_pct
                // had a "%" suffix in the string — operators using it as a
                // ratio had to strip the percent sign manually. Now a plain
                // number; the field name carries the unit.
                "miss_pct": if miss_pct.is_finite() { (miss_pct * 10000.0).round() / 10000.0 } else { 0.0 },
                "uptime_secs": uptime_secs,
                "uptime_hours": (uptime_h * 100.0).round() / 100.0,
                "uptime_days": (uptime_days * 100.0).round() / 100.0,
            },
            "unification_complete": true,
            "tip": "`modules_by_kind` and `modules_total` are the authoritative counts. The `read_path` counters surface dispatch health: a non-zero `miss_new` indicates a dispatch lookup that didn't resolve, which is worth investigating.",
        }))
        .unwrap_or_default(),
    )
}

// ── list_module_usage ───────────────────────────────────────────────────────

async fn handle_list_module_usage(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let module_id = match crate::utils::require_uuid(args, "module_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    // MCP-153 (2026-05-08): pre-flight existence check. Pre-fix the
    // surface returned `count: 0, workflows: []` for fake/cross-tenant
    // UUIDs with no signal — an operator typing a UUID typo got back
    // a confident "no usage" response. Mirrors the uniform error
    // returned by every other module-mutation surface.
    match state
        .module_repo
        .module_accessible_by_user(module_id, user_id)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return mcp_error(req_id, -32000, "Module not found or access denied");
        }
        Err(e) => {
            tracing::error!("list_module_usage existence check failed: {:#}", e);
            return mcp_error(req_id, -32000, "Failed to query module usage");
        }
    }

    match state
        .module_repo
        .find_workflows_referencing_module(user_id, module_id, 50)
        .await
    {
        Ok(rows) => {
            let workflows: Vec<serde_json::Value> = rows
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "workflow_id": r.id,
                        "workflow_name": r.name,
                    })
                })
                .collect();
            // MCP-43 (2026-05-07): emit a structured envelope so JSON
            // consumers don't have to strip a prose prefix before
            // parsing. Pre-fix the response was
            // "Module {uuid} is used in N workflow(s):\n[...JSON...]"
            // — operator-readable but a programmatic-consumer pitfall.
            //
            // MCP-107 (2026-05-08): emit canonical `count` alongside
            // legacy `usage_count` so envelope tooling that keys on
            // `count` reads this surface uniformly (same MCP-93 pattern
            // applied to list_pending_approvals).
            let body = serde_json::json!({
                "module_id": module_id.to_string(),
                "count": workflows.len(),
                "usage_count": workflows.len(),
                "workflows": workflows,
            });
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&body).unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("list_module_usage query failed: {:#}", e);
            mcp_error(req_id, -32000, "Failed to query module usage")
        }
    }
}

// ── find_unreferenced_modules ────────────────────────────────────────────────

async fn handle_find_unreferenced_modules(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    // Mirror N-J pattern (workflows.rs handle_list_workflows): a missing
    // arg defaults; a present-but-invalid arg fails fast with -32602.
    // Pre-fix, `days: 0` silently clamped to 1 and the response carried
    // `filter_days: 1` — operators saw the unexpected coercion without a
    // signal that they had passed something out of range.
    // MCP-281 (2026-05-10): pre-fix wrong-type (`days: "7"` string)
    // silently fell back to the default 30. Migrate to validate_range_i64
    // which distinguishes absent / wrong-type / out-of-range. Same
    // direction-class as MCP-187 / MCP-267.
    let days: i32 = match crate::utils::validate_range_i64(args, "days", 1, 365, 30, &req_id) {
        Ok(v) => v as i32,
        Err(resp) => return resp,
    };

    match state
        .module_repo
        .find_unreferenced_modules(user_id, days)
        .await
    {
        Ok(rows) => {
            let modules: Vec<serde_json::Value> = rows
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "module_id": r.id,
                        "name": r.name,
                        "compiled_at": r.compiled_at.to_rfc3339(),
                    })
                })
                .collect();
            let result = serde_json::json!({
                "unreferenced_modules": modules,
                "count": modules.len(),
                "filter_days": days,
            });
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&result).unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("find_unreferenced_modules query failed: {:#}", e);
            mcp_error(req_id, -32000, "Failed to query unreferenced modules")
        }
    }
}

// ── batch_delete_modules ──────────────────────────────────────────────────────

async fn handle_batch_delete_modules(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    // MCP-250 (2026-05-08): dedup module_ids upfront. MCP-249 family.
    let module_ids: Vec<uuid::Uuid> = match args.get("module_ids").and_then(|v| v.as_array()) {
        Some(arr) => {
            let mut ids = Vec::new();
            let mut seen: std::collections::HashSet<uuid::Uuid> = std::collections::HashSet::new();
            for item in arr {
                match item.as_str().and_then(|s| s.parse::<uuid::Uuid>().ok()) {
                    Some(id) => {
                        if seen.insert(id) {
                            ids.push(id);
                        }
                    }
                    None => {
                        return mcp_error(
                            req_id,
                            -32602,
                            &format!(
                                "Invalid UUID in module_ids: {}",
                                talos_text_util::bounded_preview(&item.to_string(), 64)
                            ),
                        )
                    }
                }
            }
            ids
        }
        None => return mcp_error(req_id, -32602, "Missing or invalid 'module_ids' array"),
    };

    if module_ids.is_empty() {
        return mcp_error(req_id, -32602, "module_ids array is empty");
    }
    if module_ids.len() > 500 {
        return mcp_error(req_id, -32602, "module_ids must contain ≤ 500 entries");
    }

    // MCP-229 (2026-05-08): same fix as delete_module. `force: "true"`
    // (string) was silently treated as false; the batch deletion would
    // skip every referenced module with no signal that the caller's
    // force flag was malformed.
    let force = match crate::utils::validate_optional_bool(args, "force", false, &req_id) {
        Ok(b) => b,
        Err(resp) => return resp,
    };

    let mut skipped: Vec<serde_json::Value> = Vec::new();
    let mut to_delete: Vec<uuid::Uuid> = Vec::new();

    if !force {
        // Check which modules are referenced by workflows (batch query)
        let referenced_rows = state
            .module_repo
            .find_referenced_modules_in_workflows(&module_ids, user_id)
            .await
            .unwrap_or_default();

        let referenced_set: std::collections::HashSet<uuid::Uuid> =
            referenced_rows.iter().map(|(id, _)| *id).collect();

        for mid in &module_ids {
            if referenced_set.contains(mid) {
                let workflow_names: Vec<&str> = referenced_rows
                    .iter()
                    .filter(|(id, _)| id == mid)
                    .map(|(_, name)| name.as_str())
                    .collect();
                skipped.push(serde_json::json!({
                    "module_id": mid,
                    "reason": format!("Referenced by workflows: {}", workflow_names.join(", "))
                }));
            } else {
                to_delete.push(*mid);
            }
        }
    } else {
        to_delete = module_ids;
    }

    // Pre-delete ownership check: classify each ID in to_delete as:
    //   • deletable      — exists in wasm_modules and owned by this user
    //   • access_denied  — exists in wasm_modules (other owner) OR in node_templates
    //                      (system/catalog entries that delete_module cannot reach)
    //   • not_found      — not present in either table
    // A UNION query covers both tables in one round-trip so list_modules IDs that point
    // at node_templates entries are correctly classified as access_denied, not not_found.
    let actually_delete: Vec<uuid::Uuid> = if !to_delete.is_empty() {
        // source: 'wasm' → wasm_modules row (check user_id), 'template' → node_templates row
        let existing = state
            .module_repo
            .classify_modules_for_delete(&to_delete)
            .await
            .unwrap_or_default();

        // Build a presence map: id → (source, owner). wasm_modules takes precedence
        // over node_templates when both happen to have the same UUID.
        let mut presence: std::collections::HashMap<uuid::Uuid, (String, Option<uuid::Uuid>)> =
            std::collections::HashMap::new();
        for (id, source, owner) in existing {
            presence
                .entry(id)
                .and_modify(|e| {
                    if e.0 == "template" && source == "wasm" {
                        *e = (source.clone(), owner);
                    }
                })
                .or_insert((source, owner));
        }

        let mut deletable = Vec::new();
        for mid in &to_delete {
            match presence.get(mid) {
                Some((source, Some(owner))) if source == "wasm" && *owner == user_id => {
                    deletable.push(*mid);
                }
                Some(_) => {
                    // wasm_modules with wrong owner OR node_templates entry → access_denied
                    skipped.push(serde_json::json!({
                        "module_id": mid,
                        "reason": "access_denied",
                    }));
                }
                None => {
                    skipped.push(serde_json::json!({
                        "module_id": mid,
                        "reason": "not_found",
                    }));
                }
            }
        }
        deletable
    } else {
        vec![]
    };

    // Webhook-reference guard (mirrors the workflow-reference check above).
    // Only applied when force is false — force: true bypasses both guards.
    let final_delete: Vec<uuid::Uuid> = if !force && !actually_delete.is_empty() {
        let wh_referenced = state
            .module_repo
            .find_webhook_dependencies_for_modules(&actually_delete, user_id)
            .await
            .unwrap_or_default();

        let mut keep = Vec::new();
        for mid in actually_delete {
            if let Some(webhook_ids) = wh_referenced.get(&mid) {
                skipped.push(serde_json::json!({
                    "module_id": mid,
                    "reason": format!(
                        "Referenced by {} webhook(s): {}. Use force: true to override.",
                        webhook_ids.len(),
                        webhook_ids.join(", ")
                    ),
                }));
            } else {
                keep.push(mid);
            }
        }
        keep
    } else {
        actually_delete
    };

    let deleted_count = if !final_delete.is_empty() {
        match state
            .module_repo
            .batch_delete_modules(&final_delete, user_id)
            .await
        {
            Ok(n) => n as i64,
            Err(e) => {
                tracing::error!("batch_delete_modules failed: {}", e);
                return mcp_error(req_id, -32000, "Failed to delete modules");
            }
        }
    } else {
        0
    };

    let response = serde_json::json!({
        "deleted_count": deleted_count,
        "skipped": skipped,
    });
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&response).unwrap_or_default(),
    )
}

// ── rename_module ─────────────────────────────────────────────────────────────

async fn handle_rename_module(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let module_id = match crate::utils::require_uuid(args, "module_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    // MCP-166 (2026-05-08): reject whitespace-only names and clean up
    // the dead `Some("")` arm (the prior `!n.is_empty()` arm caught
    // empty before this could fire). Mirrors the rename_workflow
    // (MCP-165) and approval-gate-title (MCP-164) hardening.
    //
    // MCP-372 (2026-05-11): pre-fix returned the UNTRIMMED `n` for
    // storage. Operator passing `name: "   foo   "` (110 chars
    // including padding) trimmed fine for the emptiness check,
    // passed the < 200 length check, and persisted WITH surrounding
    // whitespace, polluting list_modules and breaking name-keyed
    // lookups. Trim AND re-check length post-trim so a 195-char
    // visible name with 10 chars of padding doesn't slip through the
    // pre-trim length gate. Sibling fix to rename_workflow.
    // MCP-410: migrated control-char check to canonical helper; kept
    // the trim/empty/length structure since the operator-facing
    // messages are field-specific to "Module name".
    let new_name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) if n.trim().is_empty() => {
            return mcp_error(
                req_id,
                -32602,
                "Module name must be a non-empty, non-whitespace string",
            )
        }
        Some(n) if n.trim().len() > 200 => {
            return mcp_error(req_id, -32602, "Module name exceeds 200 character limit")
        }
        Some(n) => n.trim(),
        None => return mcp_error(req_id, -32602, "Missing 'name' parameter"),
    };
    if let Err(resp) =
        crate::utils::validate_name_no_control_chars("Module name", new_name, req_id.clone())
    {
        return resp;
    }

    match state
        .module_repo
        .rename_module(module_id, user_id, new_name)
        .await
    {
        Ok(n) if n > 0 => mcp_text(
            req_id,
            &format!("Module {} renamed to '{}'.", module_id, new_name),
        ),
        // MCP-155 (2026-05-08): collapse the not-found vs access-denied
        // branches to a single uniform message. The previous shape
        // exposed enough information to enumerate cross-tenant module
        // UUIDs by probing rename_module — the response told the
        // attacker whether a UUID existed in the platform. Mirrors the
        // uniform error every other module surface returns
        // ("Module not found or access denied").
        Ok(_) => mcp_error(req_id, -32000, "Module not found or access denied"),
        Err(e) => {
            tracing::error!("rename_module failed: {}", e);
            mcp_error(req_id, -32000, "Failed to rename module")
        }
    }
}

// ── get_module_history ───────────────────────────────────────────────────────

async fn handle_get_module_history(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let module_id = match crate::utils::require_uuid(args, "module_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // MCP-171 (2026-05-08): pre-check module ownership. Pre-fix the
    // handler ran the user-scoped audit-row query directly, so a
    // non-existent / cross-tenant module_id returned a synthetic
    // {change_count: 0, count: 0, history: []} envelope —
    // silent-not-found. Mirrors the cycle-16 fixes on
    // list_module_usage / get_module_dependents (MCP-153).
    match state
        .module_repo
        .module_accessible_by_user(module_id, user_id)
        .await
    {
        Ok(true) => {}
        Ok(false) => return mcp_error(req_id, -32000, "Module not found or access denied"),
        Err(e) => {
            tracing::error!("get_module_history existence check failed: {:#}", e);
            return mcp_error(req_id, -32000, "Failed to query module history");
        }
    }

    match state
        .module_repo
        .list_module_history(module_id, user_id)
        .await
    {
        Ok(rows) => {
            // MCP-3: hot_update_module records an audit row on every call,
            // including byte-identical recompiles where previous_hash ==
            // new_hash. Operators auditing a module's evolution see ~half the
            // entries as no-ops without any visual signal that they're
            // no-ops. Stamp `unchanged: true` on those rows so callers can
            // filter client-side; the row is still preserved (write-time
            // dedup is wrong — operators sometimes WANT a fresh audit row
            // even when the bytes didn't change).
            let history: Vec<serde_json::Value> = rows
                .iter()
                .map(|r| {
                    let unchanged = r
                        .previous_hash
                        .as_ref()
                        .map(|p| p == &r.new_hash)
                        .unwrap_or(false);
                    serde_json::json!({
                        "id": r.id,
                        "previous_hash": r.previous_hash,
                        "new_hash": r.new_hash,
                        "size_bytes": r.size_bytes,
                        "created_at": r.created_at.to_rfc3339(),
                        "unchanged": unchanged,
                    })
                })
                .collect();

            // MCP-95 (2026-05-07): wrap in `{count, change_count, history}`
            // envelope so the surface matches sibling list tools (post-MCP-45).
            // `change_count` is derived (entries where `unchanged: false`)
            // so operators can answer "how many real updates" at a glance.
            let change_count = history
                .iter()
                .filter(|e| {
                    !e.get("unchanged")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                })
                .count();
            // MCP-140 (2026-05-08): document the count vs change_count
            // semantics inline. Without the legend an operator reading
            // {count: 12, change_count: 5} can't tell which is "real"
            // history (the same one-letter shape that bit MCP-133 in
            // get_workflow_call_tree). Mirrors the _count_legend pattern
            // from list_module_catalog.
            let envelope = serde_json::json!({
                "module_id": module_id.to_string(),
                "count": history.len(),
                "change_count": change_count,
                "_count_legend": {
                    "count": "Total audit rows (includes byte-identical no-op recompiles where previous_hash == new_hash, stamped with `unchanged: true`).",
                    "change_count": "Subset of audit rows where the WASM hash actually changed (`unchanged: false`). Use this to count real module updates.",
                },
                "history": history,
            });
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&envelope).unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("get_module_history query failed: {:#}", e);
            mcp_error(req_id, -32000, "Failed to get module history")
        }
    }
}

// ── get_module_dependents ─────────────────────────────────────────────────

async fn handle_get_module_dependents(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);

    let module_id = match crate::utils::require_uuid(args, "module_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // MCP-153 (2026-05-08): pre-flight existence check. Pre-fix this
    // surface returned `direct_count: 0, indirect_count: 0` for
    // fake/cross-tenant UUIDs with no signal — operator typing a UUID
    // typo got back a confident empty response.
    match state
        .module_repo
        .module_accessible_by_user(module_id, user_id)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return mcp_error(req_id, -32000, "Module not found or access denied");
        }
        Err(e) => {
            tracing::error!("get_module_dependents existence check failed: {:#}", e);
            return mcp_error(req_id, -32000, "Failed to query module dependents");
        }
    }

    // Find workflows directly referencing this module
    let direct_rows = match state
        .module_repo
        .find_workflows_referencing_module(user_id, module_id, 50)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!("get_module_dependents direct query failed: {:#}", e);
            return mcp_error(req_id, -32000, "Failed to query module dependents");
        }
    };
    let direct_workflows: Vec<serde_json::Value> = direct_rows
        .iter()
        .map(|r| serde_json::json!({ "workflow_id": r.id, "workflow_name": r.name }))
        .collect();

    // Find sub-workflows: workflows that call_workflow/trigger_workflow any of
    // the direct workflows. Single batched query — replaces the per-direct
    // round-trip loop (each call did its own full table scan via LIKE-with-
    // leading-wildcard) with one CROSS-JOIN-UNNEST query that does a single
    // pass and ranks per-target via ROW_NUMBER. Same per-target limit (20)
    // enforced in SQL.
    let direct_ids: Vec<uuid::Uuid> = direct_rows.iter().map(|r| r.id).collect();
    // MCP-85 (2026-05-07): build a UUID → name map for the direct
    // workflows so the indirect projection can hydrate
    // `references_workflow` to `{id, name}` instead of a bare UUID.
    // Same MCP-44/66 pattern.
    let direct_names: std::collections::HashMap<uuid::Uuid, String> =
        direct_rows.iter().map(|r| (r.id, r.name.clone())).collect();
    let mut indirect_workflows: Vec<serde_json::Value> = Vec::new();
    let mut seen_ids: std::collections::HashSet<uuid::Uuid> = std::collections::HashSet::new();
    if let Ok(triples) = state
        .module_repo
        .find_workflows_referencing_workflows(user_id, &direct_ids, 20)
        .await
    {
        for (target_id, ref_id, ref_name) in triples {
            if seen_ids.insert(ref_id) {
                let target_name = direct_names
                    .get(&target_id)
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string());
                indirect_workflows.push(serde_json::json!({
                    "workflow_id": ref_id,
                    "workflow_name": ref_name,
                    "references_workflow": {
                        "id": target_id,
                        "name": target_name,
                    },
                }));
            }
        }
    }

    let result = serde_json::json!({
        "module_id": module_id,
        "direct_workflows": direct_workflows,
        "direct_count": direct_workflows.len(),
        "indirect_via_sub_workflows": indirect_workflows,
        "indirect_count": indirect_workflows.len(),
    });
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

// ── get_module_compatibility ──────────────────────────────────────────────────

async fn handle_get_module_compatibility(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);

    let module_id = match crate::utils::require_uuid(args, "module_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // Schema declares `capability_world` (matches every other tool in
    // this surface — `compile_custom_sandbox`, `run_sandbox`,
    // `describe_capability_world`, `create_actor`, …). Pre-fix the
    // handler read `target_world`, which no caller could discover from
    // the schema; the tool was effectively unusable. Accept both for
    // back-compat with any stale internal caller, but the schema-aligned
    // name is the documented one.
    let target_world = match args
        .get("capability_world")
        .or_else(|| args.get("target_world"))
        .and_then(|v| v.as_str())
    {
        Some(w) if !w.is_empty() => w.to_string(),
        _ => return mcp_error(req_id, -32602, "Invalid or missing 'capability_world'"),
    };

    // World hierarchy (ascending capability):
    // minimal < http/network < secrets/llm < filesystem/cache/messaging < database/agent < governance < automation
    // Worlds at the same level are compatible with each other.
    // A module compiled for a lower world can run in any higher (superset) world.
    //
    // `llm` sits at the secrets level — both resolve vault keys; llm
    // adds the `llm::*` WIT dispatch path on top. The DB stores
    // `capability_world: "llm-node"` for LLM Inference modules even
    // though `describe_capability_world(llm-node)` calls it an "actor
    // capability ceiling, NOT a compile world" (per CLAUDE.md). The
    // table needs to recognize what's actually persisted; refusing the
    // module with "Unknown module world 'llm'" was the prod bug
    // surfaced when probing get_module_compatibility on LLM Inference.
    // Check wasm_modules first, then node_templates
    let module_world: String = match state
        .module_repo
        .get_module_capability_world(module_id, user_id)
        .await
    {
        Ok(Some((world, _src))) => world,
        // MCP-159 (2026-05-08): uniform message — see delete_module fix.
        Ok(None) => return mcp_error(req_id, -32000, "Module not found or access denied"),
        Err(e) => {
            tracing::error!("get_module_compatibility query failed: {:#}", e);
            return mcp_error(req_id, -32000, "Failed to fetch module");
        }
    };
    // Normalize world names (strip "-node" suffix if present)
    let normalize_world = |w: &str| -> String { w.trim_end_matches("-node").to_lowercase() };

    let module_world_normalized = normalize_world(&module_world);
    let target_world_normalized = normalize_world(&target_world);

    let known_worlds_msg = "Known worlds: minimal, http, network, secrets, llm, filesystem, cache, messaging, database, agent, governance, automation";
    // Compatibility is a LATTICE decision (module world ⊆ target world), NOT a
    // linear level comparison. Incomparable worlds (e.g. secrets vs governance)
    // are NOT mutually compatible even though a linear rank would say so —
    // route through the canonical ceiling_permits, the same helper the
    // capability-grant gates use.
    let (compatible, reason) = if !talos_capability_world::is_lattice_world(
        &module_world_normalized,
    ) {
        (
            false,
            format!("Unknown module world '{module_world_normalized}'. {known_worlds_msg}"),
        )
    } else if !talos_capability_world::is_lattice_world(&target_world_normalized) {
        (
            false,
            format!("Unknown target world '{target_world_normalized}'. {known_worlds_msg}"),
        )
    } else if talos_capability_world::ceiling_permits(
        &target_world_normalized,
        &module_world_normalized,
    ) {
        (
            true,
            if module_world_normalized == target_world_normalized {
                format!(
                    "Module world '{module_world_normalized}' matches target world '{target_world_normalized}'"
                )
            } else {
                format!(
                    "Target world '{target_world_normalized}' is a superset of module world '{module_world_normalized}'"
                )
            },
        )
    } else {
        (
            false,
            format!(
                "Target world '{target_world_normalized}' cannot run modules compiled for \
                 '{module_world_normalized}': the module requires capabilities the target world \
                 does not provide."
            ),
        )
    };

    let result = serde_json::json!({
        "compatible": compatible,
        "module_world": module_world_normalized,
        "target_world": target_world_normalized,
        "reason": reason,
    });

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

// ── set_module_rate_limit ────────────────────────────────────────────────────

async fn handle_set_module_rate_limit(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let module_id = match crate::utils::require_uuid(args, "module_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let rpm = if args
        .get("requests_per_minute")
        .map(|v| v.is_null())
        .unwrap_or(false)
    {
        None
    } else {
        match args.get("requests_per_minute").and_then(|v| v.as_i64()) {
            Some(v) if (1..=1000).contains(&v) => Some(v as i32),
            Some(_) => {
                return mcp_error(
                    req_id,
                    -32602,
                    "requests_per_minute must be between 1 and 1000",
                )
            }
            None => return mcp_error(req_id, -32602, "Invalid 'requests_per_minute' value"),
        }
    };

    // Only a platform-admin may set the rate limit on a global CATALOG module
    // (user_id IS NULL) — that row is shared, so its rate_limit affects every
    // tenant. A normal user is scoped to modules they own; an attempt against a
    // catalog module simply matches 0 rows → "not found or access denied".
    let allow_catalog = state
        .actor_repo
        .is_platform_admin(user_id)
        .await
        .unwrap_or(false);
    let (r1_affected, r2_affected) = match state
        .module_repo
        .set_module_rate_limit(module_id, user_id, rpm, allow_catalog)
        .await
    {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("set_module_rate_limit failed: {:#}", e);
            return mcp_error(req_id, -32000, "Failed to set module rate limit");
        }
    };

    if r1_affected > 0 || r2_affected > 0 {
        let source = if r1_affected > 0 {
            "compiled module"
        } else {
            "sandbox template"
        };
        let msg = if let Some(v) = rpm {
            format!(
                "Rate limit set to {} requests/minute for {} {}",
                v, source, module_id
            )
        } else {
            format!("Rate limit cleared for {} {}", source, module_id)
        };
        mcp_text(req_id, &msg)
    } else {
        mcp_error(req_id, -32000, "Module not found or access denied")
    }
}

// ── get_module_rate_limit ────────────────────────────────────────────────────

async fn handle_get_module_rate_limit(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let module_id = match crate::utils::require_uuid(args, "module_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let rpm = state
        .module_repo
        .get_module_rate_limit(module_id, user_id)
        .await
        .unwrap_or(None);

    let result = serde_json::json!({
        "module_id": module_id.to_string(),
        "rate_limit_per_minute": rpm,
    });
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

// ── share_module_with_org ────────────────────────────────────────────────────

async fn handle_share_module_with_org(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let module_id = match crate::utils::require_uuid(args, "module_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let org_id = match crate::utils::require_uuid(args, "org_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // Sharing is a write — gate on the writable-member role set
    // (member/admin/owner). Viewer-role auditors must NOT be able to push
    // modules into the org's shared pool.
    let writable = state
        .module_repo
        .is_org_member_writable(user_id, org_id)
        .await
        .unwrap_or(false);
    if !writable {
        return mcp_error(
            req_id,
            -32003,
            "You are not a writable member of this organization",
        );
    }

    match state
        .module_repo
        .share_module_with_org(module_id, user_id, org_id)
        .await
    {
        Ok(n) if n > 0 => mcp_text(
            req_id,
            &format!("Module {} shared with organization {}", module_id, org_id),
        ),
        Ok(_) => mcp_error(req_id, -32000, "Module not found or access denied"),
        Err(e) => {
            tracing::error!("share_module_with_org update failed: {}", e);
            mcp_error(req_id, -32000, "Failed to share module")
        }
    }
}

// ── list_org_modules ────────────────────────────────────────────────────────

async fn handle_list_org_modules(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let org_id = match crate::utils::require_uuid(args, "org_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // Verify caller is a member of the organization before exposing its modules.
    let is_member = state
        .module_repo
        .check_org_membership(user_id, org_id)
        .await
        .unwrap_or(false);

    if !is_member {
        return mcp_error(req_id, -32003, "You are not a member of this organization");
    }

    match state.module_repo.list_org_modules(org_id).await {
        Ok(rows) => {
            let modules: Vec<serde_json::Value> = rows
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "id": r.id,
                        "name": r.name,
                        "capability_world": r.capability_world,
                    })
                })
                .collect();
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&modules).unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("list_org_modules query failed: {:#}", e);
            mcp_error(req_id, -32000, "Failed to list organization modules")
        }
    }
}

// ── Catalog helpers ──────────────────────────────────────────────────────────

/// Extract the capability world declared in a template source file.
/// Looks for the `#[talos_module(world = "...")]` attribute.
fn extract_world_from_source(source: &str) -> Option<String> {
    let marker = r#"talos_module(world = ""#;
    source.find(marker).and_then(|start| {
        let rest = &source[start + marker.len()..];
        rest.find('"').map(|end| rest[..end].to_string())
    })
}

/// Derive sensible allowed_hosts from a capability world string.
/// Worlds that include outbound I/O get ["*"]; compute-only worlds get [].
fn default_allowed_hosts_for_world(world: &str) -> Vec<String> {
    let needs_hosts = world.contains("network")
        || world.contains("http")
        || world.contains("automation")
        || world.contains("secrets")
        || world.contains("database");
    if needs_hosts {
        vec!["*".to_string()]
    } else {
        vec![]
    }
}

// ── list_module_catalog ──────────────────────────────────────────────────────

async fn handle_list_module_catalog(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    // ── Parse optional filter/pagination args ─────────────────────────────
    // All filters are applied after catalog load (N is small — ~60 entries —
    // so in-memory filter is cheaper than disk-level culling).
    // MCP-223 (2026-05-08): trim filters before substring match so
    // `category: "   "` and `query: "   http   "` don't silently
    // return zero matches. A real probe surfaced both. Same family
    // as MCP-210 / MCP-221 / MCP-222. Empty trimmed → no filter.
    let category_filter = args
        .get("category")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_lowercase());
    let world_filter = args
        .get("capability_world")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let query_filter = args
        .get("query")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_lowercase());
    // MCP-270 (2026-05-10): direction-class wrong-type rejection.
    let installed_only =
        match crate::utils::validate_optional_bool(args, "installed_only", false, &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    // Server-side ceiling guards against pathological limit values.
    const MAX_LIMIT: u64 = 200;
    const DEFAULT_LIMIT: u64 = 50;
    let limit =
        match crate::utils::validate_range_u64(args, "limit", 1, MAX_LIMIT, DEFAULT_LIMIT, &req_id)
        {
            Ok(v) => v as usize,
            Err(resp) => return resp,
        };
    // MCP-339 (2026-05-11): strict-parse `offset`. Pre-fix
    // `.and_then(|v| v.as_u64()).unwrap_or(0)` silently collapsed
    // wrong-type (`offset: "10"` string), fractional floats
    // (`offset: 5.5`), and negatives into the default 0 — operator
    // expecting to page past the first N entries silently saw the
    // first page repeatedly. Catalog is small enough that no upper-
    // bound is needed; just reject malformed values loudly with the
    // observed kind named. Same direction-class as MCP-209 (list_
    // executions.offset).
    let offset = match crate::utils::validate_range_u64(args, "offset", 0, 10_000, 0, &req_id) {
        Ok(v) => v as usize,
        Err(resp) => return resp,
    };

    let catalog_dir = std::path::Path::new("/app/module-templates");

    // Batch-fetch installed module names → IDs for this user so we can mark
    // catalog entries as installed without N+1 queries.
    let installed = state
        .module_repo
        .list_user_template_names(agent.user_id.unwrap_or_else(uuid::Uuid::nil))
        .await
        .unwrap_or_default();

    // MCP-H8: the catalog walk is heavy sync I/O — opendir, per-dir
    // metadata read + template.rs read. Pre-fix this ran inline on
    // the tokio async runtime thread, stalling every other handler
    // on that worker thread for the duration of the walk. Hoist into
    // `spawn_blocking` so the sync work runs on the blocking-thread
    // pool.
    //
    // 2026-05-28 audit Perf#4: cache the walk across calls via
    // CATALOG_CACHE (process-wide OnceCell). The templates are baked
    // into the controller image at build time; the only legitimate
    // refresh is a pod restart. Pre-cache the walk ran on every call
    // (~180 syscalls per dashboard load); post-cache only the FIRST
    // call pays the I/O cost.
    let catalog_dir_owned = catalog_dir.to_path_buf();
    let entries: Vec<serde_json::Value> = if catalog_dir.is_dir() {
        CATALOG_CACHE
            .get_or_init(|| async move {
                tokio::task::spawn_blocking(move || {
                    let mut items: Vec<serde_json::Value> = Vec::new();
                    if let Ok(read_dir) = std::fs::read_dir(&catalog_dir_owned) {
                        for entry in read_dir.flatten() {
                            let path = entry.path();
                            if !path.is_dir() {
                                continue;
                            }
                            let dir_name = path
                                .file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("")
                                .to_string();
                            if dir_name.is_empty() {
                                continue;
                            }

                            // Modules must have template.rs to be installable.
                            let template_path = path.join("template.rs");
                            if !template_path.exists() {
                                continue;
                            }

                            // talos.json is required for catalog entries. Directories that
                            // only contain template.rs (e.g. example-node dev placeholders)
                            // are intentionally excluded: without metadata they would appear
                            // as null entries and inflate the catalog count inconsistently
                            // with the node_templates DB count.
                            let meta_path = path.join("talos.json");
                            let meta_bytes = match std::fs::read(&meta_path) {
                                Ok(b) => b,
                                Err(_) => continue, // Skip dirs without talos.json
                            };
                            let mut item = serde_json::from_slice::<serde_json::Value>(&meta_bytes)
                                .unwrap_or(serde_json::json!({}));

                            // Ensure the `name` field matches the directory (source of truth).
                            if item.get("name").and_then(|v| v.as_str()).is_none() {
                                if let Some(obj) = item.as_object_mut() {
                                    obj.insert("name".to_string(), serde_json::json!(dir_name));
                                }
                            }

                            // If capability_world is missing from talos.json, read it from template.rs.
                            if item.get("capability_world").is_none() {
                                if let Ok(src) = std::fs::read_to_string(&template_path) {
                                    if let Some(world) = extract_world_from_source(&src) {
                                        if let Some(obj) = item.as_object_mut() {
                                            obj.insert(
                                                "capability_world".to_string(),
                                                serde_json::json!(world),
                                            );
                                        }
                                        // Also derive allowed_hosts if not set.
                                        if item.get("allowed_hosts").is_none() {
                                            let hosts = default_allowed_hosts_for_world(&world);
                                            if let Some(obj) = item.as_object_mut() {
                                                obj.insert(
                                                    "allowed_hosts".to_string(),
                                                    serde_json::json!(hosts),
                                                );
                                            }
                                        }
                                    }
                                }
                            }

                            items.push(item);
                        }
                    }
                    // Sort by category then name for stable output
                    items.sort_by(|a, b| {
                        let cat_a = a
                            .get("category")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Uncategorized");
                        let cat_b = b
                            .get("category")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Uncategorized");
                        let name_a = a.get("name").and_then(|v| v.as_str()).unwrap_or("");
                        let name_b = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
                        cat_a.cmp(cat_b).then(name_a.cmp(name_b))
                    });
                    items
                })
                .await
                .unwrap_or_default()
            })
            .await
            .clone()
    } else {
        // Test/dev environment: return a minimal representative list
        vec![
            serde_json::json!({ "name": "http-request", "display_name": "HTTP Request", "description": "Make outbound HTTP requests.", "category": "Network", "capability_world": "network-node", "allowed_hosts": ["*"], "requires_secrets": [] }),
            serde_json::json!({ "name": "echo-debug", "display_name": "Echo/Debug", "description": "Echo input back as output for debugging.", "category": "Development", "capability_world": "minimal-node", "allowed_hosts": [], "requires_secrets": [] }),
        ]
    };

    // ── Apply filters (pre-pagination) ───────────────────────────────────
    let total_before_filter = entries.len();
    let filtered: Vec<&serde_json::Value> = entries
        .iter()
        .filter(|m| {
            // Category: case-insensitive substring match
            if let Some(ref cat) = category_filter {
                let entry_cat = m
                    .get("category")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Other")
                    .to_lowercase();
                if !entry_cat.contains(cat.as_str()) {
                    return false;
                }
            }
            // Capability world: exact match
            if let Some(world) = world_filter {
                let entry_world = m
                    .get("capability_world")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if entry_world != world {
                    return false;
                }
            }
            // Text query: case-insensitive substring against name / display_name / description
            if let Some(ref q) = query_filter {
                let name = m
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_lowercase();
                let dname = m
                    .get("display_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_lowercase();
                let desc = m
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_lowercase();
                if !name.contains(q.as_str())
                    && !dname.contains(q.as_str())
                    && !desc.contains(q.as_str())
                {
                    return false;
                }
            }
            // Installed-only filter: resolved identically to the response field below.
            if installed_only {
                let display_name = m
                    .get("display_name")
                    .and_then(|v| v.as_str())
                    .or_else(|| m.get("name").and_then(|v| v.as_str()))
                    .unwrap_or("");
                let install_name = m.get("name").and_then(|v| v.as_str()).unwrap_or("");
                if !installed.contains_key(display_name) && !installed.contains_key(install_name) {
                    return false;
                }
            }
            true
        })
        .collect();

    // ── Apply pagination ─────────────────────────────────────────────────
    let total_after_filter = filtered.len();
    let paged: Vec<&serde_json::Value> = filtered.into_iter().skip(offset).take(limit).collect();
    let returned_count = paged.len();

    // Group paginated slice by category
    let mut by_category: std::collections::BTreeMap<String, Vec<&serde_json::Value>> =
        std::collections::BTreeMap::new();
    for entry in &paged {
        let cat = entry
            .get("category")
            .and_then(|v| v.as_str())
            .unwrap_or("Other")
            .to_string();
        by_category.entry(cat).or_default().push(entry);
    }

    let catalog: Vec<serde_json::Value> = by_category
        .into_iter()
        .map(|(category, items)| {
            serde_json::json!({
                "category": category,
                "modules": items.iter().map(|m| {
                    // Resolve the name that will be stored in node_templates (display_name or dir name).
                    let display_name = m.get("display_name")
                        .and_then(|v| v.as_str())
                        .or_else(|| m.get("name").and_then(|v| v.as_str()))
                        .unwrap_or("");
                    let install_name = m.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    // A module is "installed" if its display_name exists in node_templates
                    // (that is how install_module_from_catalog stores it).
                    let installed_entry = installed.get(display_name)
                        .or_else(|| installed.get(install_name));
                    let is_installed = installed_entry.is_some();
                    let module_id = installed_entry.map(|id| id.to_string());
                    // MCP-13 (closed): emit only `required_secrets` (the
                    // canonical name used everywhere else in the system —
                    // workflows.rs, talos-workflow-creation-helpers, GraphQL).
                    // Pre-fix this dual-emitted requires_secrets + required_secrets
                    // with the same value on every entry as a BC shim.
                    serde_json::json!({
                        "name": install_name,
                        "display_name": display_name,
                        "description": m.get("description"),
                        "capability_world": m.get("capability_world"),
                        "allowed_hosts": m.get("allowed_hosts"),
                        "config_schema_keys": m.get("config_schema").and_then(|s| s.get("properties")).and_then(|p| p.as_object()).map(|obj| obj.keys().cloned().collect::<Vec<_>>()),
                        "setup_instructions": m.get("setup_instructions"),
                        "required_secrets": m.get("requires_secrets"),
                        "installed": is_installed,
                        "module_id": module_id,
                    })
                }).collect::<Vec<_>>()
            })
        })
        .collect();

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            // MCP-52 (2026-05-07): explicit names — `matching_count`
            // (post-filter pre-pagination) and `catalog_total_count`
            // (catalog-wide pre-filter). Pre-fix `total_available` and
            // `total` were both noun-phrases that suggested the same
            // thing and operators had to read the docstring to know
            // which was which. Legacy names (`total_available`, `total`)
            // preserved as deprecated aliases until next wire-format
            // revision.
            "returned_count": returned_count,
            "matching_count": total_after_filter,
            "catalog_total_count": total_before_filter,
            "total_available": total_after_filter,
            "total": total_before_filter,
            "offset": offset,
            "limit": limit,
            "has_more": offset + returned_count < total_after_filter,
            // MCP-98 (2026-05-07): inline legend so a new operator reading
            // the response can see what each count field means without
            // reading the tool docstring or guessing from names. Cheap,
            // additive, no breakage. Marked with `_` prefix so it's
            // visually distinct from data fields.
            "_count_legend": {
                "catalog_total_count": "Total entries in the catalog (pre-filter).",
                "matching_count": "Entries matching the supplied filters (pre-pagination).",
                "returned_count": "Entries actually returned in this page (post-limit).",
                "has_more": "True when matching_count > offset + returned_count — call again with offset+limit to see the next page.",
                "deprecated_aliases": "`total` is an alias of `catalog_total_count`; `total_available` is an alias of `matching_count`. Prefer the explicit names in new code.",
            },
            "filters_applied": serde_json::json!({
                "category": category_filter,
                "capability_world": world_filter,
                "query": query_filter,
                "installed_only": installed_only,
            }),
            "catalog": catalog,
        }))
        .unwrap_or_default(),
    )
}

// ── install_module_from_catalog ──────────────────────────────────────────────

async fn handle_install_module_from_catalog(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return mcp_error(req_id, -32602, "Missing required argument: name"),
    };

    // SECURITY: Validate name — only alphanumeric and hyphens; no path traversal.
    if !name.chars().all(|c| c.is_alphanumeric() || c == '-') || name.is_empty() {
        return mcp_error(
            req_id,
            -32602,
            "Invalid module name: only alphanumeric characters and hyphens are allowed",
        );
    }
    if name.contains("..") || name.starts_with('/') || name.starts_with('.') {
        return mcp_error(
            req_id,
            -32602,
            "Invalid module name: path traversal detected",
        );
    }

    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);

    // Enforce per-user installed module limit to prevent storage exhaustion.
    // MCP-368 (2026-05-11): pre-fix `.unwrap_or(0)` silently bypassed
    // the cap on any DB error — count = 0 < 500, the install proceeded
    // past the gate. Fail-CLOSED on quota errors. Same MCP-366/367
    // family applied to the install_module_from_catalog quota.
    const MAX_INSTALLED_MODULES_PER_USER: i64 = 500;
    let module_count = match state.module_repo.count_user_modules(user_id).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(
                user_id = %user_id,
                error = %e,
                "count_user_modules (module quota) failed; refusing install to avoid silent cap bypass"
            );
            return mcp_error(
                req_id,
                -32000,
                "Module quota check failed (database error). Refusing install to avoid silent cap bypass; retry after the database recovers.",
            );
        }
    };
    if module_count >= MAX_INSTALLED_MODULES_PER_USER {
        return mcp_error(
            req_id,
            -32602,
            &format!(
                "Installed module limit reached ({} / {}). Delete unused modules with \
                 delete_module before installing new ones.",
                module_count, MAX_INSTALLED_MODULES_PER_USER
            ),
        );
    }

    let catalog_dir = std::path::Path::new("/app/module-templates");

    // Resolve module directory: exact slug match first, then fuzzy display_name match.
    // This handles cases where the tool name ("http-request-with-retry") differs from
    // the directory name ("http-retry") but matches the talos.json display_name.
    let module_dir = {
        fn to_slug(s: &str) -> String {
            let lowered = s.to_lowercase();
            let hyphenated: String = lowered
                .chars()
                .map(|c| if c.is_alphanumeric() { c } else { '-' })
                .collect();
            hyphenated
                .split('-')
                .filter(|p| !p.is_empty())
                .collect::<Vec<_>>()
                .join("-")
        }

        let exact = catalog_dir.join(name);
        if exact.join("talos.json").exists() {
            exact
        } else {
            let target = to_slug(name);
            let found = std::fs::read_dir(catalog_dir)
                .ok()
                .and_then(|entries| {
                    entries.flatten().find(|entry| {
                        let meta_path = entry.path().join("talos.json");
                        if let Ok(bytes) = std::fs::read(&meta_path) {
                            if let Ok(meta) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                                if let Some(display) =
                                    meta.get("display_name").and_then(|v| v.as_str())
                                {
                                    return to_slug(display) == target;
                                }
                            }
                        }
                        false
                    })
                })
                .map(|e| e.path());
            match found {
                Some(dir) => dir,
                None => {
                    return mcp_error(
                        req_id,
                        -32000,
                        &format!(
                            "Module '{}' not found in catalog. Use list_module_catalog to see available modules.",
                            name
                        ),
                    )
                }
            }
        }
    };

    // Read talos.json metadata
    let meta_path = module_dir.join("talos.json");
    let meta_bytes = match std::fs::read(&meta_path) {
        Ok(b) => b,
        Err(e) => {
            return mcp_error(
                req_id,
                -32000,
                &format!("Failed to read talos.json for '{}': {}", name, e),
            )
        }
    };
    let meta: serde_json::Value = match serde_json::from_slice(&meta_bytes) {
        Ok(v) => v,
        Err(e) => {
            return mcp_error(
                req_id,
                -32000,
                &format!("Failed to parse talos.json for '{}': {}", name, e),
            )
        }
    };

    // Read source code — catalog modules use template.rs at the module root.
    let src_path = module_dir.join("template.rs");
    let rust_code = match std::fs::read_to_string(&src_path) {
        Ok(s) => s,
        Err(_) => {
            return mcp_error(
                req_id,
                -32000,
                &format!(
                    "Source file not found for module '{}' (expected template.rs in {}).",
                    name,
                    module_dir.display()
                ),
            )
        }
    };

    // Extract metadata fields.
    // capability_world: prefer talos.json, fall back to the #[talos_module(world = "...")] attribute
    // in the source so modules without full talos.json metadata still compile to the right world.
    let capability_world_owned: String = meta
        .get("capability_world")
        .and_then(|v| v.as_str())
        .map(String::from)
        .or_else(|| extract_world_from_source(&rust_code))
        .unwrap_or_else(|| "automation-node".to_string());
    let capability_world = capability_world_owned.as_str();

    // Honor an explicit `allowed_hosts: []` (deny-all) — only fall back to
    // defaults when the field is missing or not an array.
    let allowed_hosts: Vec<String> = if meta
        .get("allowed_hosts")
        .and_then(|v| v.as_array())
        .is_some()
    {
        crate::utils::json_string_array_field(&meta, "allowed_hosts")
    } else {
        default_allowed_hosts_for_world(capability_world)
    };
    // allowed_methods from talos.json + optional caller override.
    // MCP-243: caller side trimmed; talos.json side trusted (template-author signed).
    let talos_json_methods = crate::utils::json_string_array_field(&meta, "allowed_methods");
    let caller_methods = crate::utils::json_string_array_field_trimmed(args, "allowed_methods");
    let mut allowed_methods: Vec<String> = talos_json_methods;
    for m in caller_methods {
        if !allowed_methods.contains(&m) {
            allowed_methods.push(m);
        }
    }

    // allowed_secrets: union of requires_secrets (legacy), allowed_secrets (talos.json), and
    // caller override. Empty = deny all (fail-closed after the security fix in host_impl).
    let catalog_secrets = crate::utils::json_string_array_field(&meta, "requires_secrets");
    let talos_json_secrets = crate::utils::json_string_array_field(&meta, "allowed_secrets");
    // Track whether the caller explicitly passed allowed_secrets so that a plain
    // reinstall (no parameter) does not silently clear a previously configured list.
    let caller_provided_allowed_secrets = args.get("allowed_secrets").is_some();
    // MCP-243: trim caller-supplied vault paths.
    let caller_secrets = crate::utils::json_string_array_field_trimmed(args, "allowed_secrets");
    // Captured before the moves below so the grant_empty_warning predicate
    // (further down) can tell whether the *template itself* requires any
    // secrets, not just whether the operator's grant is empty.
    let template_requires_secrets = !catalog_secrets.is_empty() || !talos_json_secrets.is_empty();

    // Principle of least privilege: if the caller explicitly provides allowed_secrets,
    // use ONLY the caller's list — do NOT merge with template defaults.
    // This lets operators restrict a module to exactly the secrets it needs for a
    // specific use case, without being over-privileged by the template's broad defaults.
    //
    // Without a caller override: build from template defaults (requires_secrets ∪ talos.json
    // allowed_secrets), which preserves backwards-compatible behaviour for plain reinstalls.
    let allowed_secrets: Vec<String> = if caller_provided_allowed_secrets {
        caller_secrets
    } else {
        let mut merged = catalog_secrets;
        for s in talos_json_secrets {
            if !merged.contains(&s) {
                merged.push(s);
            }
        }
        merged
    };
    let requires_approval_for =
        crate::utils::json_string_array_field(&meta, "requires_approval_for");
    let display_name = args
        .get("display_name")
        .and_then(|v| v.as_str())
        .or_else(|| meta.get("display_name").and_then(|v| v.as_str()))
        .unwrap_or(name)
        .to_string();
    let description = meta
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let config_schema = meta
        .get("config_schema")
        .cloned()
        .unwrap_or(serde_json::json!({}));
    let category = meta
        .get("category")
        .and_then(|v| v.as_str())
        .unwrap_or("catalog")
        .to_string();

    // Use the resolved dir name as the Cargo package name — this is always a valid slug
    // (e.g. "stripe-create-customer") even when the input was a fuzzy-matched variant
    // like "stripe--create-customer" which Cargo would reject as an invalid label.
    let compile_name = module_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(name);

    // Compile the module. Forward the template's declared `dependencies` from
    // talos.json — previously hard-coded to `None`, so a template that declared
    // e.g. `"dependencies": {"chrono": "0.4"}` and `use chrono::...` in
    // template.rs failed to install with "unresolved import `chrono`" even
    // though the manifest was correct. Templates are author-signed; the
    // compiler still gates deps through the allowlist (validate_dependencies).
    let job_id = uuid::Uuid::new_v4();
    let compilation = state
        .compiler
        .compile_to_wasm_with_config(
            user_id,
            job_id,
            compile_name,
            &rust_code,
            &serde_json::json!({}),
            meta.get("dependencies"),
        )
        .await;

    match compilation {
        Ok(res) if res.success => {
            let wasm_bytes = match res.wasm_bytes {
                Some(b) => b,
                None => {
                    return mcp_error(
                        req_id,
                        -32603,
                        "Compilation succeeded but produced no WASM output",
                    )
                }
            };

            // Phase 3.2: writes go ONLY to the unified modules table.
            // The legacy upsert_node_template_for_install + the wasm_modules
            // upsert + the mirror were collapsed into a single
            // install_catalog_module_to_modules call that has install-specific
            // UPSERT semantics (refreshes permissions on re-install, unlike
            // hot_update which preserves them).
            //
            // Variables that pre-existed only to thread results between the
            // three legacy steps (upsert_sql / wasm_module_uuid) are gone.
            let _ = caller_provided_allowed_secrets;
            let _ = (&category, &description); // metadata embedded in modules row directly

            use sha2::{Digest, Sha256};
            let content_hash = format!("{:x}", Sha256::digest(&wasm_bytes));
            let cw_short = if capability_world == "automation-node" {
                "trusted"
            } else {
                capability_world.trim_end_matches("-node")
            };

            // Resolve max_fuel with three-tier precedence:
            //   1. caller-supplied `fuel_budget` (operator override)
            //   2. template-declared `recommended_fuel` in talos.json (per-template default)
            //   3. compute_max_fuel(10, 2000, 2.0) baseline (~2.2M)
            // The hardcoded 2M was leaving LLM-backed templates fuel-starved on
            // realistic actor-context payloads — see issue #381.
            let max_fuel: i64 = if let Some(budget) = args.get("fuel_budget") {
                crate::sandbox::compute_fuel_from_budget_value(budget) as i64
            } else if let Some(rec) = meta.get("recommended_fuel") {
                crate::sandbox::compute_fuel_from_budget_value(rec) as i64
            } else {
                talos_compilation::scaffold::compute_max_fuel(10, 2000, 2.0) as i64
            };

            let install_result = match state
                .module_repo
                .install_catalog_module_to_modules(
                    agent.user_id,
                    &display_name,
                    cw_short,
                    &wasm_bytes,
                    &content_hash,
                    &rust_code,
                    max_fuel,
                    &allowed_hosts,
                    &allowed_methods,
                    &allowed_secrets,
                    &requires_approval_for,
                    &config_schema,
                )
                .await
            {
                Ok(x) => x,
                Err(e) => {
                    tracing::error!(
                        module_name = name,
                        capability_world,
                        "install_module_from_catalog: modules-table install failed: {:#}",
                        e
                    );
                    return mcp_error(
                        req_id,
                        -32000,
                        "Compilation succeeded but failed to save module",
                    );
                }
            };
            let module_uuid = install_result.module_id;
            let stored_allowed_secrets = install_result.allowed_secrets.clone();
            let stored_content_hash = install_result.content_hash.clone();
            let stored_compiled_at = install_result.compiled_at;
            let bytes_changed = install_result.bytes_changed;
            let module_id_str = module_uuid.to_string();
            let wasm_module_uuid: Option<Uuid> = Some(module_uuid);

            tracing::info!(
                module_name = name,
                module_id = %module_id_str,
                capability_world,
                "Installed module from catalog (modules-only write)"
            );

            // Pin the module if requested
            // MCP-270 (2026-05-10): direction-class wrong-type rejection.
            let pin_module =
                match crate::utils::validate_optional_bool(args, "pin_module", false, &req_id) {
                    Ok(v) => v,
                    Err(resp) => return resp,
                };
            let (pinned, pin_warning) = if pin_module {
                if let Some(uid) = agent.user_id {
                    match state.module_repo.pin_user_module(uid, &display_name).await {
                        Ok(_) => (true, None),
                        Err(e) => {
                            tracing::warn!(module_name = %display_name, "Failed to pin module: {:#}", e);
                            (false, Some("Pin failed — user_module_pins table may not exist yet. Run migrations to enable module pinning."))
                        }
                    }
                } else {
                    (
                        false,
                        Some("Cannot pin: agent is not linked to a user account"),
                    )
                }
            } else {
                (false, None)
            };

            let setup_instructions = meta
                .get("setup_instructions")
                .cloned()
                .unwrap_or(serde_json::json!([]));
            // A template that declares zero required secrets (e.g. catalog
            // llm-inference v2.0.0, which uses host-managed llm::complete) is
            // legitimately secrets-free — an empty grant is the correct state,
            // not a misconfiguration. Only fire the warning when the template
            // itself asked for at least one path. (template_requires_secrets is
            // captured up-front because catalog_secrets/talos_json_secrets are
            // moved into `allowed_secrets` earlier.)
            let grant_empty = stored_allowed_secrets.is_empty() && template_requires_secrets;
            let has_wildcard_grant = stored_allowed_secrets.iter().any(|s| s == "*");
            // setup_required: true when the operator needs to do something before secrets work.
            //   - grant_empty: true  → deny-all grant on a template that needs secrets, must reinstall
            //   - non-empty, non-wildcard → specific paths need provisioning in the vault
            //   - wildcard grant → any existing secret is accessible, no specific provisioning
            //   - template declares zero secrets → no setup needed
            let setup_required =
                grant_empty || (!has_wildcard_grant && !stored_allowed_secrets.is_empty());
            // Return wasm_modules.id when available so this response is consistent with
            // list_modules (which also returns wasm_modules.id for installed catalog modules).
            // Fall back to node_templates.id when the wasm_modules write failed.
            let final_module_id = wasm_module_uuid
                .map(|u| u.to_string())
                .unwrap_or_else(|| module_id_str.clone());
            // Recompile receipt (added 2026-04-30): wasm_sha256 +
            // compiled_at + bytes_changed let the caller verify
            // "the WASM I just installed is actually fresh" without
            // a follow-up get_module_info — needed because catalog
            // reinstalls after a platform deploy were silently
            // upserting stale source against the operator's
            // expectation that disk-based seed templates would
            // pick up the new code (real symptom 2026-04-30 during
            // r249 rollout).
            let mut resp = serde_json::json!({
                "module_id": final_module_id,
                "template_id": module_id_str,
                "name": display_name,
                "capability_world": capability_world,
                "allowed_hosts": allowed_hosts,
                "message": "Ready to use in add_node_to_workflow",
                "setup_required": setup_required,
                "setup_instructions": setup_instructions,
                "allowed_secrets": stored_allowed_secrets,
                "pinned": pinned,
                "wasm_sha256": stored_content_hash,
                "compiled_at": stored_compiled_at.to_rfc3339(),
                "bytes_changed": bytes_changed,
            });
            if grant_empty {
                resp["grant_empty_warning"] = serde_json::json!(
                    "No secrets granted — allowed_secrets is empty (deny-all). \
                     This module cannot read any vault paths. \
                     Reinstall with allowed_secrets: [\"path/to/key\"] or [\"*\"] to enable secret access."
                );
            } else if has_wildcard_grant {
                resp["wildcard_grant_warning"] = serde_json::json!(
                    "Module has wildcard secret access (allowed_secrets: [\"*\"]) — \
                     can read any vault path. Consider restricting to specific paths \
                     for least-privilege operation."
                );
            }
            if let Some(w) = pin_warning {
                resp["pin_warning"] = serde_json::json!(w);
            }
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&resp).unwrap_or_default(),
            )
        }
        Ok(res) => {
            let errors: Vec<String> = res
                .errors
                .iter()
                .map(|e| {
                    if let (Some(line), Some(col)) = (e.line, e.column) {
                        format!("Line {}:{}: {}", line, col, e.message)
                    } else {
                        e.message.clone()
                    }
                })
                .collect();
            mcp_error(
                req_id,
                -32000,
                &format!("Compilation failed for '{}':\n{}", name, errors.join("\n")),
            )
        }
        Err(e) => {
            tracing::error!(err = ?e, "compile_module: compilation service error");
            mcp_error(
                req_id,
                -32000,
                &format!("Compilation service error: {:#}", e),
            )
        }
    }
}

// ── restore_pinned_modules ────────────────────────────────────────────────────

async fn handle_restore_pinned_modules(
    req_id: Option<serde_json::Value>,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = match agent.user_id {
        Some(uid) => uid,
        None => return mcp_error(req_id, -32000, "User identity required"),
    };

    // Fetch pinned modules and whether WASM is currently present
    let rows = match state.module_repo.list_user_pinned_modules(user_id).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("restore_pinned_modules query failed: {:#}", e);
            return mcp_error(req_id, -32000, "Failed to query pinned modules");
        }
    };

    let mut already_present: Vec<String> = Vec::new();
    let mut restored: Vec<String> = Vec::new();
    let mut failed: Vec<serde_json::Value> = Vec::new();

    let catalog_dir = std::path::Path::new("/app/module-templates");

    for r in &rows {
        let module_name = r.module_name.clone();
        if r.has_wasm {
            already_present.push(module_name);
            continue;
        }

        // Need to reinstall — look up the catalog template
        let module_dir = catalog_dir.join(&module_name);
        let src_path = module_dir.join("template.rs");
        let rust_code = match std::fs::read_to_string(&src_path) {
            Ok(s) => s,
            Err(_) => {
                failed.push(serde_json::json!({
                    "module": module_name,
                    "reason": "template.rs not found in catalog — module may have been removed"
                }));
                continue;
            }
        };

        let job_id = uuid::Uuid::new_v4();
        let compilation = state
            .compiler
            .compile_to_wasm_with_config(
                user_id,
                job_id,
                &module_name,
                &rust_code,
                &serde_json::json!({}),
                None,
            )
            .await;

        match compilation {
            Ok(res) if res.success => {
                if let Some(wasm_bytes) = res.wasm_bytes {
                    match state
                        .module_repo
                        .update_template_precompiled_wasm(&module_name, &wasm_bytes)
                        .await
                    {
                        Ok(_) => restored.push(module_name.clone()),
                        Err(e) => {
                            tracing::error!(module = %module_name, "restore_pinned_modules upsert failed: {:#}", e);
                            failed.push(serde_json::json!({
                                "module": module_name,
                                "reason": "compilation succeeded but failed to save"
                            }));
                        }
                    }
                } else {
                    failed.push(serde_json::json!({
                        "module": module_name,
                        "reason": "compilation produced no WASM output"
                    }));
                }
            }
            Ok(_) => {
                failed.push(serde_json::json!({
                    "module": module_name,
                    "reason": "compilation failed"
                }));
            }
            Err(e) => {
                failed.push(serde_json::json!({
                    "module": module_name,
                    "reason": format!("compilation service error: {}", e)
                }));
            }
        }
    }

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "already_present": already_present,
            "restored": restored,
            "failed": failed,
            "total_pinned": rows.len(),
        }))
        .unwrap_or_default(),
    )
}

// ── find_module_alternatives ─────────────────────────────────────────────────

async fn handle_find_module_alternatives(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
) -> JsonRpcResponse {
    // MCP-354 (2026-05-11): pre-fix `s.chars().take(N).collect()`
    // silently truncated operator-provided search keys — a 300-char
    // `module_name` was queried as the first 200 chars, and the
    // mismatched result set (or empty result) gave no signal that
    // truncation happened. Most likely cause is a paste error or
    // wrong-field paste; either way the operator deserves a loud
    // reject so they can fix the input, not a fuzzy match against
    // their unintentional prefix. Bounds are now enforced as hard
    // rejects mirroring other length-bounded search surfaces.
    let module_name = match args
        .get("module_name")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(s) if s.chars().count() > 200 => {
            return mcp_error(req_id, -32602, "module_name must be ≤ 200 characters")
        }
        Some(s) => Some(s.to_string()),
        None => None,
    };

    let capability = match args
        .get("capability")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(s) if s.chars().count() > 500 => {
            return mcp_error(req_id, -32602, "capability must be ≤ 500 characters")
        }
        Some(s) => Some(s.to_string()),
        None => None,
    };

    if module_name.is_none() && capability.is_none() {
        return mcp_error(
            req_id,
            -32602,
            "Provide at least one of 'module_name' or 'capability'",
        );
    }

    let limit = match crate::utils::validate_range_i64(args, "limit", 1, 20, 5, &req_id) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // Build a map of display_name → catalog_slug from disk for install hints.
    // This resolves the impedance mismatch: node_templates.name = display_name,
    // but install_module_from_catalog takes the directory slug.
    // MCP-H8: sibling sync-fs catalog walk — hoist into
    // `spawn_blocking` to keep the tokio runtime worker thread
    // unblocked. Same rationale as the list_module_catalog walk above.
    let catalog_dir = std::path::Path::new("/app/module-templates").to_path_buf();
    let display_to_slug: std::collections::HashMap<String, String> = if catalog_dir.is_dir() {
        tokio::task::spawn_blocking(move || {
            let mut map: std::collections::HashMap<String, String> =
                std::collections::HashMap::new();
            if let Ok(read_dir) = std::fs::read_dir(&catalog_dir) {
                for entry in read_dir.flatten() {
                    let path = entry.path();
                    if !path.is_dir() {
                        continue;
                    }
                    let slug = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("")
                        .to_string();
                    let meta_path = path.join("talos.json");
                    if let Ok(bytes) = std::fs::read(&meta_path) {
                        if let Ok(meta) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                            // Seeder uses display_name preferentially as node_templates.name
                            let dn = meta
                                .get("display_name")
                                .or_else(|| meta.get("name"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            if !dn.is_empty() && !slug.is_empty() {
                                map.insert(dn, slug);
                            }
                        }
                    }
                }
            }
            map
        })
        .await
        .unwrap_or_default()
    } else {
        std::collections::HashMap::new()
    };

    // Helper: enrich a TemplateAlternativeRow into a result object
    let enrich = |r: &talos_module_repository::TemplateAlternativeRow,
                  score: f64,
                  match_reason: &str,
                  display_to_slug: &std::collections::HashMap<String, String>|
     -> serde_json::Value {
        let config_keys: Vec<String> = r
            .config_schema
            .get("properties")
            .and_then(|p| p.as_object())
            .map(|obj| obj.keys().cloned().collect())
            .unwrap_or_default();
        let catalog_name = display_to_slug.get(&r.name).cloned().unwrap_or_default();
        let install_hint = if catalog_name.is_empty() {
            "Use list_module_catalog to find the install name for this module".to_string()
        } else {
            format!("install_module_from_catalog with name=\"{}\"", catalog_name)
        };
        serde_json::json!({
            "module_name": r.name,
            "catalog_name": catalog_name,
            "category": r.category,
            "description": r.description,
            "required_secrets": r.allowed_secrets,
            "config_keys": config_keys,
            "match_score": (score * 10000.0).round() / 10000.0,
            "match_reason": match_reason,
            "install_with": install_hint,
        })
    };

    // ── Case A: find alternatives for a known module ─────────────────────────
    if let Some(ref target_name) = module_name {
        // Fetch target module
        let target = match state
            .module_repo
            .lookup_template_by_name_ci(target_name)
            .await
        {
            Ok(Some(r)) => r,
            Ok(None) => {
                return mcp_error(
                    req_id,
                    -32000,
                    &format!(
                        "Module '{}' not found. Use list_module_catalog to see available display names.",
                        target_name
                    ),
                )
            }
            Err(e) => {
                tracing::error!("find_module_alternatives target lookup failed: {:#}", e);
                return mcp_error(req_id, -32000, "Database error looking up module");
            }
        };

        let target_id = target.id;
        let target_category = target.category.clone();
        let target_description = target.description.clone().unwrap_or_default();
        let search_text = format!("{} {}", target_name, target_description);

        // Try pg_trgm similarity search first; fall back to category + alphabetical
        let (rows, search_method) = match state
            .module_repo
            .find_template_alternatives_trgm(target_id, &search_text, &target_category, limit)
            .await
        {
            Ok(rows) => (rows, "trigram"),
            Err(_) => {
                // pg_trgm not available — fall back to category-priority ordering
                let fallback = state
                    .module_repo
                    .find_template_alternatives_by_category(target_id, &target_category, limit)
                    .await
                    .unwrap_or_default();
                (fallback, "category")
            }
        };

        let results: Vec<serde_json::Value> = rows
            .iter()
            .map(|r| {
                let score = r.score.unwrap_or(0.0);
                let reason = if r.same_category.unwrap_or(false) {
                    "same_category"
                } else {
                    "description_match"
                };
                enrich(r, score, reason, &display_to_slug)
            })
            .collect();

        return mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "query": { "module_name": target_name },
                "target": {
                    "module_name": target_name,
                    "category": target_category,
                },
                "search_method": search_method,
                // MCP-102 (2026-05-08): canonical `count` envelope.
                "count": results.len(),
                "alternatives": results,
                "tip": "Use install_module_from_catalog(catalog_name) to install any alternative, then swap the module in your workflow with update_node_config.",
            }))
            .unwrap_or_default(),
        );
    }

    // ── Case B: capability-based discovery ───────────────────────────────────
    let cap = match capability {
        Some(c) => c,
        None => {
            return mcp_error(
                req_id,
                -32602,
                "Internal error: capability should be present at this point",
            );
        }
    };
    let ilike_pattern = format!("%{}%", cap.replace('%', "\\%").replace('_', "\\_"));

    let (rows, search_method) = match state
        .module_repo
        .find_templates_by_capability_trgm(&cap, &ilike_pattern, limit)
        .await
    {
        Ok(rows) => (rows, "trigram"),
        Err(_) => {
            let fallback = state
                .module_repo
                .find_templates_by_capability_ilike(&ilike_pattern, limit)
                .await
                .unwrap_or_default();
            (fallback, "ilike")
        }
    };

    if rows.is_empty() {
        return mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "query": { "capability": cap },
                "search_method": search_method,
                "count": 0,
                "alternatives": [],
                "tip": "No modules matched. Try list_module_catalog to browse all available modules by category.",
            }))
            .unwrap_or_default(),
        );
    }

    let results: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            enrich(
                r,
                r.score.unwrap_or(0.0),
                "capability_match",
                &display_to_slug,
            )
        })
        .collect();

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "query": { "capability": cap },
            "search_method": search_method,
            "count": results.len(),
            "alternatives": results,
            "tip": "Use install_module_from_catalog(catalog_name) to install any module, then use add_node_to_workflow to add it to your workflow.",
        }))
        .unwrap_or_default(),
    )
}

#[cfg(test)]
mod host_managed_access_tests {
    use super::host_managed_access_for_world;

    #[test]
    fn llm_node_world_surfaces_external_hosts() {
        let v = host_managed_access_for_world(Some("llm-node"));
        let hosts = v.get("external_hosts").and_then(|x| x.as_array()).unwrap();
        assert!(hosts
            .iter()
            .any(|h| h.as_str() == Some("api.anthropic.com")));
        assert!(hosts.iter().any(|h| h.as_str() == Some("api.openai.com")));
    }

    #[test]
    fn llm_node_world_surfaces_vault_keys() {
        let v = host_managed_access_for_world(Some("llm-node"));
        let keys = v.get("vault_keys").and_then(|x| x.as_array()).unwrap();
        assert!(keys.iter().any(|k| k.as_str() == Some("anthropic/api_key")));
    }

    #[test]
    fn agent_node_world_inherits_llm_access() {
        // agent-node strictly contains llm capabilities; same surface.
        let v = host_managed_access_for_world(Some("agent-node"));
        assert!(v
            .get("external_hosts")
            .and_then(|x| x.as_array())
            .map(|a| !a.is_empty())
            .unwrap_or(false));
    }

    #[test]
    fn http_node_world_has_no_implicit_access() {
        // Plain http-node modules need explicit allowed_hosts —
        // there's no implicit grant. The note guides operators.
        let v = host_managed_access_for_world(Some("http-node"));
        let hosts = v.get("external_hosts").and_then(|x| x.as_array()).unwrap();
        assert!(hosts.is_empty());
    }

    #[test]
    fn missing_capability_world_returns_empty() {
        let v = host_managed_access_for_world(None);
        let hosts = v.get("external_hosts").and_then(|x| x.as_array()).unwrap();
        assert!(hosts.is_empty());
    }

    #[test]
    fn short_form_world_works_too() {
        // Both 'llm' (post-trim short form) and 'llm-node' should
        // resolve to the same surface — the helper trims '-node'.
        let a = host_managed_access_for_world(Some("llm"));
        let b = host_managed_access_for_world(Some("llm-node"));
        assert_eq!(a.get("external_hosts"), b.get("external_hosts"));
    }
}
