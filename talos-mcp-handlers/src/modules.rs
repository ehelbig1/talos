use super::types::JsonRpcResponse;
use super::utils::{mcp_denied, mcp_error, mcp_text};
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

/// Platform-category allowlist for `list_templates`' default view.
/// Compared CASE-INSENSITIVELY: disk-seeded rows carry talos.json casing
/// ("AI", "Data"), and the original case-sensitive compare filtered every
/// seeded template out — list_templates returned 0 against a fully seeded
/// catalog (the 2026-07-13 catalog-opacity papercut, DX #12).
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

fn is_platform_category(cat: &str) -> bool {
    let lowered = cat.to_lowercase();
    PLATFORM_CATEGORIES.contains(&lowered.as_str())
}

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
                "properties": {
                    "search": { "type": "string", "description": "Case-insensitive substring filter on module name" }
                },
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
            "description": "Delete compiled modules referenced by NOTHING — no workflow graph, no webhook trigger, no push channel (Gmail / Google Calendar / Google Cloud watch), and no execution history — AND compiled more than `days` days ago, optionally scoped by name prefix. Returns count of deleted modules. WARNING: omitting prefix deletes ALL of your unreferenced modules older than `days` and requires confirm: true. Refuses (deletes nothing) if your push-channel bindings cannot be read.\n\nThe age filter and the exclusions match `find_unreferenced_modules` — survey with that tool using the SAME `days` value and this deletes what it showed you. Without the age filter this tool used to destroy modules you had just compiled and not yet wired into a workflow; without the webhook / push / history exclusions (before 2026-09-25) it deleted modules a webhook or push channel dispatches directly, and their run history with them.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "prefix": { "type": "string", "description": "Only delete unreferenced modules whose name starts with this prefix (minimum 2 characters). Omit to delete ALL unreferenced modules (requires confirm: true)." },
                    "days": { "type": "number", "description": "Only delete modules compiled more than this many days ago (default: 30). Same meaning and same default as find_unreferenced_modules' `days` — pass the value you surveyed with." },
                    "confirm": { "type": "boolean", "description": "Must be explicitly set to true when prefix is omitted, to confirm deletion of ALL unreferenced modules older than `days`. Ignored when prefix is provided." }
                }
            }
        }),
        serde_json::json!({
            "name": "get_module_info",
            "description": "Get detailed information about a compiled module: name, capability world, size, its three grants \
                (allowed hosts, allowed HTTP verbs — an empty list denies every verb — and allowed secrets), its fuel \
                limit, the crates it was compiled with, whether source code is available, and its CONFIG SCHEMA — the keys the module accepts, \
                their types, and which are required. Never returns actual wasm bytes or source code. \
                Read `config_schema_status` before `config_schema`: 'declared' means `config_keys` / `required_config_keys` \
                are authoritative; 'declared_empty' means the module genuinely takes no config; 'not_declared' means NO \
                schema was ever recorded, which is NOT the same as taking no config — catalog modules declare one in \
                talos.json, but modules built via compile_custom_sandbox / hot_update_module do not, so use \
                get_module_source to see which keys their run() reads from data[\"config\"].",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "module_id": { "type": "string", "description": "UUID of the module to inspect" },
                    "module_name": { "type": "string", "description": "Alternative to module_id: case-insensitive exact module name (your modules + catalog)" }
                },
                "required": []
            }
        }),
        serde_json::json!({
            "name": "get_module_source",
            "description": "Return a module's stored SOURCE CODE (for your own modules or catalog templates). Complements get_module_info, which only reports whether source exists (has_source_code) without returning it. Use this to inspect, maintain, or fix a DB-resident module in place, or to see how a catalog template is implemented. Returns {source, language, capability_world, kind, has_source}. A bytes-only imported module returns has_source=false with a null source.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "module_id": { "type": "string", "description": "UUID of the module whose source to retrieve" }
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
            "description": format!("Debug whether a given module would be allowed to read a given secret path WITHOUT actually executing the module. Reports FIVE gates as PASS/FAIL with a human-readable reason:\n\n  1. capability_world — can the module reach a secret AT ALL, by EITHER route: the GUEST route (`secrets::get_secret()`, which needs the secrets interface) or the HOST route (a `vault://` marker in an outbound header or JSON body, resolved by the host at the socket — available to every world above minimal, and the route every OAuth integration uses). The per-route answers are in `gates[0].routes`.\n  2. allowed_secrets allowlist — is the path covered by the module's grant (exact / prefix match / wildcard)?\n  3. reserved_host_path — LLM provider keys (anthropic/api_key, openai/api_key, gemini/api_key) are deny-listed for ALL guests, even with allowed_secrets: [\\\"*\\\"]; the host uses them via the llm::* interface only.\n  4. vault_presence — is the secret actually stored in the vault for this user?\n  5. dispatch_prefetch — will a dispatch actually DELIVER this path on the strength of the grant alone? Gates 1-4 can all pass while the module receives nothing. {}\n\nUse this when get_secret() is failing at runtime with `unauthorized` to identify which gate is responsible without redeploying. NOTE: gate 5 is deliberately NOT folded into `would_succeed`, because the config-reference delivery route is not visible from here.", talos_workflow_job_protocol::SECRET_GRANT_DELIVERY_NOTE),
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
            "description": "Find compiled modules referenced by nothing — no workflow graph, webhook trigger, push channel, or execution history. The preview for cleanup_modules (same exclusions, same `days`). Optionally filter by compile age.",
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
            "description": "Get the hot-update history for a module (previous and new content hashes, sizes, timestamps) plus the administrative actions recorded against it in admin_event_log (allowed_methods / allowed_secrets updates, deletion, bulk cleanup), each with who performed it.",
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
            "description": "List built-in module templates. Returns metadata grouped by category. \
                Read 'availability' + 'usable_module_id', NOT 'installed' — most catalog modules are shared GLOBAL rows \
                that are usable with no install step, and they report installed:false because that flag means \
                'you have your own copy'. Workflow authoring flow: (1) list_module_catalog — find the module; \
                (2) if availability is 'installed' or 'usable_shared', go straight to \
                add_node_to_workflow(module_id: '<usable_module_id>'); only availability 'needs_install' requires \
                install_module_from_catalog(name: '<name>') first. Install anyway when you want a PRIVATE copy with \
                its own hosts, secrets and fuel limit (and, where the platform compiles the template, one \
                you can modify with hot_update_module). Each entry also carries 'config_schema_keys' — the config keys the \
                module accepts; get_module_info returns the full schema with types and required-ness. \
                'module_id' is a deprecated alias of 'usable_module_id'. PAGINATION: full unfiltered catalog is large \
                (80KB+); prefer filtering by category/capability_world or searching by query. 'limit' caps returned \
                modules (default 50, max 200).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "category": { "type": "string", "description": "Filter to a single category (e.g. 'Network', 'AI', 'Integration'). Case-insensitive substring match." },
                    "capability_world": { "type": "string", "description": "Filter by WIT capability world (e.g. 'http-node', 'agent-node')." },
                    "query": { "type": "string", "description": "Substring match against name / display_name / description. Case-insensitive." },
                    "search": { "type": "string", "description": "Alias for 'query' (accepted so the sibling tools' param name also works)." },
                    "installed_only": { "type": "boolean", "description": "If true, return only modules the current user has their OWN copy of (availability 'installed'). Does NOT include shared global catalog modules, which are usable without installing. Default: false." },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 200, "description": "Max modules to return (default: 50, max: 200). matching_count = post-filter pre-pagination count; catalog_total_count = catalog-wide pre-filter; returned_count = items in this page. total_available + total are kept as deprecated aliases of matching_count + catalog_total_count." },
                    "offset": { "type": "integer", "minimum": 0, "description": "Skip the first N modules (default: 0). Combine with limit for pagination." }
                },
            }
        }),
        serde_json::json!({
            "name": "get_catalog_status",
            "description": "Catalog diagnostic: which templates are on disk vs seeded into the DB catalog, which are hidden from list_templates by the category allowlist, what each surface reads (list_templates → DB; list_module_catalog + install → disk), and how seeding works. Use when templates seem missing or surfaces disagree.",
            "inputSchema": { "type": "object", "properties": {} }
        }),
        serde_json::json!({
            "name": "install_module_from_catalog",
            "description": "Install your own copy of a catalog module. Returns a module_id ready for use in add_node_to_workflow. Much faster than writing custom code for common patterns. What the copy runs depends on where this deployment's catalog comes from, and the reply's `source` says which: `compiled` — the template shipped with the platform is compiled for you; `registry` — on a deployment whose catalog is synced from a registry, the copy references the registry's signed artifact with your grants and nothing is compiled (such a copy holds no code, so hot_update_module is refused on it). Response always includes module_id, name, source, content_hash, compiled_at (RFC3339 UTC of when the copy was written), and bytes_changed (true on first install OR when the copy now runs different code than before — false signals an idempotent no-op). wasm_sha256 is the hex SHA-256 of the compiled bytes, and null for a registry copy. Use bytes_changed/content_hash to verify a reinstall actually picked up new code after a platform deploy. Check for optional warning fields: grant_empty_warning (module has deny-all secret access — every vault:// config value will fail at runtime, reinstall with allowed_secrets) and wildcard_grant_warning (module has wildcard [\"*\"] secret access — consider scoping to explicit paths to limit blast radius). A REINSTALL keeps your installed copy's allowed_hosts / allowed_methods / allowed_secrets unless you pass them: an entry your copy inherited from the template is kept while the new template still grants it, and an entry YOU added (with update_module_hosts / update_module_methods / update_module_secrets) is kept whatever the template grants. grants_carried_from_installed_copy says whether a copy existed, grants_kept_as_owner_added lists what was kept because you added it, and grants_not_carried lists inherited entries the template no longer grants. Every install is recorded in the admin event log (module_installed_from_catalog / module_reinstalled_from_catalog) with the grants, capability world and content hash it wrote and replaced; an install that cannot be recorded is not made. FUEL: the reply's `fuel` block says what limit the copy carries and where it came from (`template`, `fuel_budget`, or `kept`). A REINSTALL keeps the copy's own limit unless `fuel_budget` is passed; when that kept limit is below what the template now recommends, the block says so (also in `dry_run`).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": { "type": "string", "description": "The catalog template to install: its slug (e.g. 'http-request', 'gmail-list-messages') or its display name as shown by list_module_catalog and get_catalog_status (e.g. 'HTTP Request', 'Gmail: List Messages')." },
                    "display_name": { "type": "string", "description": "Optional display name override. Defaults to the catalog template's display_name." },
                    "allowed_secrets": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Vault key paths this module may read. The template's own grant is the CEILING: your list can only NARROW it — an exact template path, a path under a template prefix or glob, or ['*'] meaning the template's whole list. Paths outside the template's grant are not installed and are listed in secrets_not_granted. An empty list [] installs a deny-all grant. Omitted on a FIRST install: the template's grant. Omitted on a REINSTALL: your installed copy's current grant is kept, bounded by the new template's grant (see grants_not_carried)."
                    },
                    "dry_run": {
                        "type": "boolean",
                        "description": "When true, nothing is compiled, written or recorded: the reply says which allowed_hosts / allowed_methods / allowed_secrets the install WOULD store, your copy's current ones, whether they differ, and anything that would not be carried (grants_not_carried, secrets_not_granted). Use it before reinstalling a module that live workflows use. Default false."
                    },
                    "allowed_methods": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "HTTP method allowlist (e.g. ['GET', 'POST']). EMPTY DENIES EVERY VERB at all five egress gates (http fetch / fetch_all, graphql, webhook, SSE connect) — the same rule allowed_hosts and allowed_secrets have always had; before 2026-09-24 empty meant allow-all, which made this the one grant where declaring nothing granted everything. Empty also classifies the module UNKNOWN (not read-only) for the method-aware retry default, so nodes created from it get retry_count 0. There is no wildcard: the method set is closed at five, so 'every verb' is ['GET','POST','PUT','PATCH','DELETE'] written out. Declare ['GET'] on a read-only module to enforce read-only egress AND earn transient retries. Passed: ADDED to the template's verbs. Omitted on a REINSTALL: your installed copy's current verbs are kept, bounded by the template's."
                    },
                    "pin_module": { "type": "boolean", "description": "Mark module as pinned so restore_pinned_modules reinstalls it on session start. Useful for modules you always want available (e.g. llm-inference, http-request). Default: false." },
                    "fuel_budget": {
                        "type": "object",
                        "description": "Optional — declare expected payload shape so max_fuel is computed via the formula (baseline + 60K per item + 2 fuel per input byte + 2 fuel per llm_output_bytes, × safety_multiplier, clamped [1M, 50M]). Set llm_output_bytes for LLM-backed modules. Overrides the template's recommended_fuel (in talos.json) and the ~2.2M default. Mirrors the same shape used by hot_update_module and compile_custom_sandbox.",
                        "properties": {
                            "expected_items": { "type": "integer", "minimum": 0 },
                            "bytes_per_item": { "type": "integer", "minimum": 0 },
                            "llm_output_bytes": { "type": "integer", "minimum": 0 },
                            "safety_multiplier": { "type": "number", "minimum": 1.0, "maximum": 5.0 },
                            "fuel_per_byte": { "type": "integer", "minimum": 1, "maximum": 100, "description": talos_compilation::scaffold::FUEL_PER_BYTE_GUIDANCE }
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
        "get_module_source" => Some(handle_get_module_source(req_id, args, state, agent).await),
        "test_secret_access" => Some(handle_test_secret_access(req_id, args, state, agent).await),
        "cleanup_module_versions" => {
            Some(handle_cleanup_module_versions(req_id, args, state, agent).await)
        }
        "get_module_unification_status" => {
            Some(handle_get_module_unification_status(req_id, state).await)
        }
        "get_catalog_status" => Some(handle_get_catalog_status(req_id, state, agent).await),
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
            Some(handle_find_module_alternatives(req_id, args, state, agent).await)
        }
        _ => None,
    }
}

// ── list_templates ──────────────────────────────────────────────────────────

async fn handle_list_templates(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    // MCP-192 (2026-05-08): reject wrong-type include_sandboxes
    // loudly. Pre-fix `include_sandboxes: "true"` (string) silently
    // became false. Same family as MCP-189.
    let include_sandboxes =
        match crate::utils::validate_optional_bool(args, "include_sandboxes", false, &req_id) {
            Ok(b) => b,
            Err(resp) => return resp,
        };
    // REFUSE, do not default (2026-09-07). "There are no templates" is a
    // determinate negative an operator acts on — it is the answer that sends
    // them to check whether seeding ran, whether the image carries
    // `module-templates/`, or whether the OCI sync is broken. A registry read
    // that FAILED renders identically to a genuinely empty catalog, so the
    // failure is the one thing they cannot see.
    //
    // 2026-09-10: TENANT-SCOPED and METADATA-ONLY. `list_templates(None)` read
    // every row of `modules` — every tenant's private modules, with their
    // `wasm_bytes` and `source_code` — for a listing that rendered six
    // metadata fields. An agent with no user scope passes `Uuid::nil()` and
    // sees the shared catalog alone.
    let templates = match state
        .registry
        .list_template_metadata_for_user(agent.user_id.unwrap_or_else(uuid::Uuid::nil), None)
        .await
    {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "list_templates: registry read failed");
            return mcp_error(
                req_id,
                -32000,
                "Could not read the template catalog — this is NOT a statement that \
                 the catalog is empty. Retry, and check controller logs; \
                 get_catalog_status reports the disk half separately.",
            );
        }
    };

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
    let is_platform = is_platform_category;

    let pre_filter: Vec<&talos_registry::NodeTemplateMetadata> = templates
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
        error_kind: None,
    }
}

// ── list_modules ─────────────────────────────────────────────────────────────

async fn handle_list_modules(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    // Optional substring filter — escaped (backslash first) so `%`/`_` in
    // caller input match literally, then wrapped for ILIKE.
    let name_like = args
        .get("search")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| format!("%{}%", talos_search_service::escape_like(s)));

    // Query the user_modules view — a single source of truth that unions
    // wasm_modules (custom sandboxes) and user-owned node_templates (catalog
    // installs) with deduplication. This ensures list_modules, list_module_catalog,
    // and get_system_status.modules all agree on what a "module" is.
    // REFUSE, do not default (2026-09-07): an empty `modules` list is what an
    // operator reads as "I have nothing installed", and it is the premise of
    // every next step (compile one, install from the catalog, check the other
    // tenant). A failed read must not be able to say that.
    let rows = match state
        .module_repo
        .list_user_modules_view_filtered(user_id, name_like.as_deref(), 100)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, user_id = %user_id, "list_modules: view read failed");
            return mcp_error(
                req_id,
                -32000,
                "Could not read your modules — this is NOT a statement that you have \
                 none. Retry, and check controller logs.",
            );
        }
    };

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
        // FAIL CLOSED: this is the safety guard that prevents deleting a module
        // still referenced by the user's workflows/webhooks. A transient DB
        // error must NOT default the counts to zero — that silently passes the
        // guard and orphans the referencing nodes. Refuse the delete and ask
        // for a retry (same idiom as install_module_from_catalog's quota gate).
        let refs = match state
            .module_repo
            .get_module_ref_counts(mod_id, user_id)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(module_id = %mod_id, error = %e, "delete_module reference-count guard failed");
                return mcp_error(
                    req_id,
                    -32000,
                    "Reference check failed (database error). Refusing to delete to avoid orphaning referencing workflows/webhooks; retry after the database recovers, or pass force: true to override.",
                );
            }
        };
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

    match state
        .module_repo
        .delete_module(mod_id, user_id, force)
        .await
    {
        Ok(n) if n > 0 => {
            // The `module_deleted` record (name, capability world, `force`) is
            // written by the repository inside the delete's transaction.
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
        Ok(_) => mcp_denied(req_id, -32000, "Module not found or access denied"),
        Err(e) => {
            tracing::error!(err = ?e, module_id = %mod_id, "delete_module failed");
            mcp_error(req_id, -32000, "Delete failed")
        }
    }
}

// ── cleanup_modules ──────────────────────────────────────────────────────────

/// The module ids this user's push channels dispatch (Gmail / Calendar / GCP
/// watches). Their bindings live in encrypted `integration_state`, so no SQL
/// can exclude them; the bulk-delete and its survey take this set instead.
///
/// `Err` names why the set is UNKNOWN — no inventory wired into this process,
/// or an integration that did not answer. A caller that deletes must refuse
/// on it; a gate that cannot read its rule must not grant.
async fn push_bound_modules(
    state: &McpState,
    user_id: uuid::Uuid,
) -> Result<talos_module_repository::PushBoundModules, String> {
    let Some(inventory) = state.push_channels.as_ref() else {
        return Err("no push-channel inventory is wired into this process".to_string());
    };
    inventory
        .survey(user_id)
        .await
        .bound_modules()
        .map_err(|e| e.to_string())
}

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
    // The age filter is the same one `find_unreferenced_modules` surveys with —
    // same validator, same bounds, same default — so an operator who surveys and
    // then cleans up at one `days` value acts on the set they were shown. The
    // DELETE previously had no age predicate at all, so it also destroyed
    // modules compiled minutes ago that no survey could have listed.
    let days: i32 = match crate::utils::validate_range_i64(args, "days", 1, 365, 30, &req_id) {
        Ok(v) => v as i32,
        Err(resp) => return resp,
    };
    // A module a push channel dispatches is referenced even though no
    // workflow graph names it. If the bindings cannot be read, REFUSE: deleting
    // a bound module makes every later push to its channel fail, and its run
    // history goes with it (module_executions CASCADE).
    let push_bound = match push_bound_modules(state, user_id).await {
        Ok(p) => p,
        Err(why) => {
            tracing::warn!(
                target: "talos_audit",
                %user_id,
                reason = %why,
                "cleanup_modules refused: push-channel bindings unreadable"
            );
            return mcp_error(
                req_id,
                -32000,
                "Refusing to clean up modules: could not read which modules your push channels \
                 (Gmail / Google Calendar / Google Cloud watches) dispatch, so a module one of \
                 them depends on could be deleted. Nothing was deleted; retry shortly.",
            );
        }
    };
    // Only delete modules referenced by NOTHING: no workflow graph, webhook
    // trigger, push channel, or execution history (see the repository method).
    match state
        .module_repo
        .cleanup_unreferenced_modules(user_id, prefix, days, &push_bound)
        .await
    {
        Ok(deleted) => {
            // The `modules_bulk_cleanup` record — naming every module removed —
            // is written by the repository inside the delete's transaction.
            mcp_text(
                req_id,
                &format!(
                    "Deleted {} unreferenced module(s) compiled more than {} day(s) ago. \
                     Modules bound to a webhook trigger or a push channel, and modules with \
                     execution history, are never deleted by this tool — use delete_module \
                     for those.",
                    deleted, days
                ),
            )
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
    // module_id (UUID) or module_name (case-insensitive exact) — previously
    // id-only, which forced a full list_modules pull to look up one module.
    let module_id = if args.get("module_id").is_some() {
        match crate::utils::require_uuid(args, "module_id", req_id.clone()) {
            Ok(id) => id,
            Err(resp) => return resp,
        }
    } else if let Some(name) = args
        .get("module_name")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        match state
            .module_repo
            .find_template_id_by_name_ci(name, user_id)
            .await
        {
            Ok(Some(id)) => id,
            Ok(None) => {
                return mcp_error(
                    req_id,
                    -32602,
                    &format!(
                        "No module named '{name}' (yours or catalog) — try list_modules \
                         with search, or list_module_catalog with query"
                    ),
                );
            }
            Err(e) => {
                tracing::error!(error = %e, "get_module_info name lookup failed");
                return mcp_error(req_id, -32000, "module lookup failed (see server logs)");
            }
        }
    } else {
        return mcp_error(
            req_id,
            -32602,
            "Provide module_id (UUID) or module_name (string)",
        );
    };

    // Try wasm_modules first — accepts EITHER wasm_modules.id OR template_id.
    // `id` stays the input the caller used (back-compat); `wasm_module_id`
    // and `template_id` are surfaced alongside so callers don't have to drop
    // into psql to find the other UUID for hot_update_module.
    //
    // #730: this read is NOT defaulted. `.unwrap_or(None)` fell THROUGH to the
    // template branch on a DB error, and — since both branches now read the
    // one unified `modules` table — a persistent failure ended at
    // "Module not found or access denied": a definite claim that the module is
    // gone or the caller is unauthorised, produced by never having looked.
    // Both are answers an operator acts on (recompile, re-grant), and neither
    // was true. A transient failure was worse in a quieter way — the fallback
    // succeeds and silently returns the SAME row under a DIFFERENT projection
    // (`source` from `kind` rather than "compiled", no `wasm_module_id` /
    // `template_id` / `rate_limit_per_minute`, `compiled_at` from
    // `created_at`), with nothing in the response saying so.
    let compiled = match state
        .module_repo
        .get_wasm_module_info(module_id, user_id)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(
                target: "talos_mcp_handlers::modules",
                event_kind = "get_module_info_read_failed",
                module_id = %module_id,
                error = %e,
                "get_module_info: module read failed — refusing to report 'not found'"
            );
            return mcp_error(
                req_id,
                -32000,
                "Could not read this module (see server logs). This is a read failure, \
                 NOT a statement that the module is missing or that access was denied.",
            );
        }
    };
    if let Some(info) = compiled {
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
            // The third grant. An empty list denies every verb, so a module
            // with hosts and no verbs makes no HTTP call; until 2026-10-03
            // this tool did not show it.
            "allowed_methods": info.allowed_methods,
            "allowed_secrets": info.allowed_secrets,
            "max_fuel": info.max_fuel,
            "dependencies": info.dependencies,
            "language": info.language,
            "host_managed_access": host_managed,
            "mutation_profile": mutation_profile_for_world(Some(info.capability_world.as_str())),
            "has_source_code": info.has_source_code,
            "template_id": info.template_id,
            "rate_limit_per_minute": info.rate_limit_per_minute,
            "compiled_at": info.compiled_at.map(|t| t.to_rfc3339()),
        });
        // The tool named for module info must answer "which config keys does
        // this take?" — the question every add_node_to_workflow failure
        // ("missing required config key 'SELECTOR'") asks. It previously did
        // not, and the answer was only reachable through
        // list_module_catalog.config_schema_keys.
        merge_object(
            &mut result,
            project_config_schema(info.config_schema.as_ref()),
        );
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
    //
    // #730: same rule as the compiled branch above — a failed read here used to
    // become the "Module not found or access denied" line below.
    let fallback = match state
        .module_repo
        .get_node_template_info_for_user(module_id, user_id)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(
                target: "talos_mcp_handlers::modules",
                event_kind = "get_module_info_template_read_failed",
                module_id = %module_id,
                error = %e,
                "get_module_info: template read failed — refusing to report 'not found'"
            );
            return mcp_error(
                req_id,
                -32000,
                "Could not read this module (see server logs). This is a read failure, \
                 NOT a statement that the module is missing or that access was denied.",
            );
        }
    };
    if let Some(tmpl) = fallback {
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
            "mutation_profile": mutation_profile_for_world(tmpl.capability_world.as_deref()),
            "has_source_code": tmpl.has_source_code,
            "compiled_at": tmpl.created_at.map(|t| t.to_rfc3339()),
        });
        merge_object(
            &mut result,
            project_config_schema(tmpl.config_schema.as_ref()),
        );
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

    mcp_denied(req_id, -32000, "Module not found or access denied")
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
/// Write-ceiling MUTATION PROFILE for a module's capability world: which
/// data-mutating host ops the module can reach, using the exact `op`
/// labels the worker audits with (`wasi:capability_denied`,
/// `policy = "write-ceiling"`). The op list is derived in ONE place —
/// `talos_capability_world::write_gated_ops` — so this surface can never
/// drift from the lattice. An absent/unknown world reports the FULL
/// profile (fail-closed presentation for operator review).
fn mutation_profile_for_world(capability_world: Option<&str>) -> serde_json::Value {
    let ops = talos_capability_world::write_gated_ops_str(capability_world.unwrap_or("unknown"));
    serde_json::json!({
        "write_gated_ops": ops,
        "note": "Ops a READ-ONLY actor is refused when TALOS_WRITE_CEILING_ENFORCED=1. \
                 `http-fetch`/`http-fetch-all` are gated for mutating methods only — GET \
                 passes (the ceiling is a mutation control, not an egress control; \
                 TALOS_WRITE_CEILING_STRICT_EGRESS=1 additionally restricts read-only \
                 actors' reads to hosts NAMED in allowed_hosts). Labels match the \
                 worker's write-ceiling audit events one-to-one. NOTE (#750): this \
                 list is HOST OPS only. A module ALSO reaches actor_memory by \
                 returning a `__memory_write__` envelope, which is not a host call \
                 and so appears in NO world's profile — an empty list here (every \
                 minimal-node module) does NOT mean the module cannot write memory. \
                 That route is gated by the SAME ceiling, controller-side, and \
                 audits under the same `agent-memory-set` / `write-ceiling` labels. \
                 SCOPE (#768): the ceiling governs the ACTOR's own data plane — \
                 actor_memory, integration state, and sandbox SQL. TWO further \
                 output protocols reach the database through the same node-completion \
                 hook, on the same actor binding, and are DELIBERATELY NOT \
                 ceiling-gated: `__ops_alert__` (writes `ops_alerts`) and \
                 `__ml_distill__` (appends ML dataset rows). Both are PLATFORM \
                 ingestion keyed on the actor for TENANCY only, not the actor's own \
                 data, and a `readonly` actor emitting either still lands its rows. \
                 So a module returning one of those two writes for a readonly actor \
                 by design, and this profile says nothing about it.",
    })
}

/// Project a module row's `config_schema` into the three fields
/// `get_module_info` returns for it.
///
/// The whole point is that an ABSENT declaration must be distinguishable from
/// a DECLARED-EMPTY one. Every `kind='catalog'` row carries a real schema with
/// `properties`; every `kind='sandbox'` / `kind='extracted'` row carries a
/// literal `{}` (measured: 29 of 29 on the live stack). Returning `{}` under a
/// field called `config_schema` would read as "this module takes no config",
/// which for a hand-compiled module is exactly wrong — it takes whatever its
/// `run()` reads out of `data["config"]`, and nothing recorded what that is.
///
/// So the status is the load-bearing field:
/// * `declared` — `properties` is non-empty; `config_keys` is authoritative.
/// * `declared_empty` — `properties` exists and is empty; the module really
///   does take no config.
/// * `not_declared` — no schema, or a schema with no `properties`. The module
///   MAY still require config; read its source (`get_module_source`) or its
///   `setup_instructions` in `list_module_catalog`.
fn project_config_schema(config_schema: Option<&serde_json::Value>) -> serde_json::Value {
    let properties = config_schema
        .and_then(|s| s.get("properties"))
        .and_then(|p| p.as_object());
    let required: Vec<String> = config_schema
        .and_then(|s| s.get("required"))
        .and_then(|r| r.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    match properties {
        Some(props) if !props.is_empty() => serde_json::json!({
            "config_schema_status": "declared",
            "config_schema": config_schema,
            "config_keys": props.keys().cloned().collect::<Vec<_>>(),
            "required_config_keys": required,
        }),
        Some(_) => serde_json::json!({
            "config_schema_status": "declared_empty",
            "config_schema": config_schema,
            "config_keys": Vec::<String>::new(),
            "required_config_keys": Vec::<String>::new(),
            "config_schema_note": "This module declares that it takes no config.",
        }),
        None => serde_json::json!({
            "config_schema_status": "not_declared",
            "config_schema": serde_json::Value::Null,
            "config_keys": serde_json::Value::Null,
            "required_config_keys": serde_json::Value::Null,
            "config_schema_note": "No config schema is recorded for this module — which is NOT the \
                                   same as 'takes no config'. Catalog modules declare one in their \
                                   talos.json; modules compiled through compile_custom_sandbox / \
                                   hot_update_module do not, so read the source (get_module_source) \
                                   to see which keys its run() pulls from data[\"config\"].",
        }),
    }
}

/// Copy every key of `extra` (a JSON object) into `target` (a JSON object).
/// No-op if either is not an object.
fn merge_object(target: &mut serde_json::Value, extra: serde_json::Value) {
    if let (Some(t), serde_json::Value::Object(e)) = (target.as_object_mut(), extra) {
        for (k, v) in e {
            t.insert(k, v);
        }
    }
}

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

    // This tool's whole output is a claim about a module's SECRET GRANT, so
    // every input to it is a precondition. #730: both reads were
    // `.unwrap_or(None)`, so a DB failure produced either
    // "Module not found or access denied" or — if only the first read failed —
    // a `capability_world` of "unknown", which `world_allows_secrets` then
    // reports as *"World 'unknown' does NOT import the secrets interface.
    // Recompile with capability_world: secrets-node"*. That is a specific,
    // actionable, wrong instruction about a module whose world was never read.
    let mut readings = talos_measurement::Readings::new();
    let compiled = match state
        .module_repo
        .get_wasm_module_info(module_id, user_id)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(
                target: "talos_mcp_handlers::modules",
                event_kind = "test_secret_access_read_failed",
                module_id = %module_id,
                error = %e,
                "test_secret_access: module read failed — refusing to grade a grant we could not read"
            );
            return mcp_error(
                req_id,
                -32000,
                "Could not read this module's capability world and allowed_secrets, so no \
                 gate could be evaluated (see server logs). This is a read failure, NOT a \
                 statement that the module is missing or that any gate failed.",
            );
        }
    };
    // Resolve module → (capability_world, allowed_secrets). Try the compiled
    // projection first, fall back to the template projection (sandbox path).
    let (capability_world, allowed_secrets, source) = match compiled {
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
        None => {
            let fallback = match state
                .module_repo
                .get_node_template_info_for_user(module_id, user_id)
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(
                        target: "talos_mcp_handlers::modules",
                        event_kind = "test_secret_access_template_read_failed",
                        module_id = %module_id,
                        error = %e,
                        "test_secret_access: template read failed — refusing to grade a grant we could not read"
                    );
                    return mcp_error(
                        req_id,
                        -32000,
                        "Could not read this module's capability world and allowed_secrets, so no \
                         gate could be evaluated (see server logs). This is a read failure, NOT a \
                         statement that the module is missing or that any gate failed.",
                    );
                }
            };
            match fallback {
                Some(tmpl) => (
                    tmpl.capability_world
                        .unwrap_or_else(|| "unknown".to_string()),
                    tmpl.allowed_secrets,
                    tmpl.category,
                ),
                None => return mcp_denied(req_id, -32000, "Module not found or access denied"),
            }
        }
    };

    // Gate 1: capability world. The worker requires one of these worlds for
    // any secrets:: import. Mirrors worker/src/host_impl.rs lines around 1374.
    // A secret reaches a module by one of TWO routes and this gate used to know
    // about one of them. The GUEST route is `secrets::get_secret()`, which needs
    // the `secrets` interface; the HOST route is a `vault://<path>` marker in an
    // outbound request's headers or JSON body, resolved by the host at the
    // socket so the plaintext never enters the guest at all. The host route is
    // the SAFER one and is what every OAuth integration uses.
    //
    // Testing only the guest route made this gate report `would_succeed: false`
    // for modules that work, under the reason *"World 'http-node' does NOT
    // import the secrets interface. Recompile with capability_world:
    // secrets-node"* — specific, actionable and wrong. Measured 2026-09-24: ALL
    // 38 live nodes carrying a `vault://` config reference are `http-node`
    // across 14 modules, so this gate was 0-for-38 on the fleet and its remedy
    // would have widened 14 modules' capability world for nothing. Found while
    // shipping the dispatch_prefetch gate below: `plaid-read` was fetching 14
    // accounts and 49 transactions at the moment this tool called it incapable.
    let guest_route = talos_capability_world::world_allows_secrets(&capability_world);
    let host_route = talos_capability_world::world_allows_vault_substitution(&capability_world);
    let world_allowed = guest_route || host_route;
    let gate_capability = serde_json::json!({
        "name": "capability_world",
        "passed": world_allowed,
        "routes": {
            "guest_get_secret": guest_route,
            "host_vault_substitution": host_route,
        },
        "reason": match (guest_route, host_route) {
            (true, true) => format!(
                "World '{}' imports the secrets interface, so the module may call \
                 secrets::get_secret() directly, AND it can egress, so a \
                 `vault://` marker in an outbound header or JSON body is resolved \
                 by the host. {}",
                capability_world,
                talos_workflow_job_protocol::VAULT_BODY_SUBSTITUTION_SURFACES_NOTE
            ),
            (true, false) => format!(
                "World '{}' imports the secrets interface, so the module may call \
                 secrets::get_secret() directly.",
                capability_world
            ),
            (false, true) => format!(
                "World '{}' does NOT import the secrets interface, so \
                 secrets::get_secret() is refused — but it can egress, so the \
                 module reaches this secret by putting `vault://{}` in an \
                 outbound request's headers or JSON body, which the host resolves \
                 at the socket. That is the SAFER route (the plaintext never \
                 enters the guest) and is how every OAuth integration here works, \
                 so this is NOT a reason to recompile at a higher world.",
                capability_world, secret_path
            ),
            (false, false) => format!(
                "World '{}' can reach a secret by neither route: it does not \
                 import the secrets interface (so secrets::get_secret() is \
                 refused) and it has no egress interface (so there is no outbound \
                 request for a `vault://` marker to ride). Recompile with \
                 capability_world: http-node to use the host route, or \
                 secrets-node for direct guest access.",
                capability_world
            ),
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
                 Grant it with allowed_secrets: [\"{}\"] — the EXACT path, which \
                 also makes the dispatch pre-fetch it (see the dispatch_prefetch \
                 gate below). A prefix grant would permit this path without \
                 delivering it.",
                secret_path
            )
        } else {
            format!(
                "Path '{}' does not match any entry in the module's allowed_secrets {:?}. \
                 Add the EXACT path — a prefix or glob entry permits a path without \
                 delivering it (see the dispatch_prefetch gate below).",
                secret_path, allowed_secrets
            )
        },
    });

    // Gate 5: will a dispatch actually DELIVER this path on the strength of the
    // grant alone? Gates 1-4 answer "is this permitted and does it exist" and
    // every one of them can pass while the module still gets nothing, because
    // `allowed_secrets` has two jobs with different vocabularies: the engine
    // passes the grant list VERBATIM as `extra_paths` to
    // `SecretsManager::get_secrets_by_paths`, whose non-wildcard query is
    // `WHERE key_path = ANY($1)` — exact equality, with only the literal `"*"`
    // special-cased. A prefix or glob entry therefore matches no row, an empty
    // result is `Ok`, and nothing logs. This tool's stated purpose is "use this
    // when get_secret() is failing at runtime to identify which gate is
    // responsible", so a four-PASS verdict over a path that will never be
    // delivered is the exact failure it exists to prevent.
    let prefetched =
        talos_workflow_job_protocol::vault_path_prefetched(&allowed_secrets, &secret_path);
    let gate_prefetch = serde_json::json!({
        "name": "dispatch_prefetch",
        "passed": prefetched,
        "reason": if prefetched {
            format!(
                "The grant names '{}' in a form the dispatch pre-fetches (exact path, or \"*\"), \
                 so the controller resolves it and the worker receives it.",
                secret_path
            )
        } else {
            format!(
                "The grant permits '{}' but will NOT pre-fetch it: only an exact path or \"*\" \
                 is resolved, and a prefix/glob entry is looked up verbatim against a path \
                 no secret is named. Two ways to deliver it — (a) add the EXACT path to \
                 allowed_secrets via update_module_secrets, or (b) put `vault://{}` in the \
                 node's config, which the engine extracts and resolves separately (this is \
                 how OAuth integrations work, and it is why this gate does NOT change \
                 would_succeed: whether any node carries that reference is not visible from \
                 here, and reporting failure over a route this tool cannot measure would be \
                 the same defect in the other direction).",
                secret_path, secret_path
            )
        },
    });

    // Gate 4: vault presence — the path may pass all gates but not exist.
    // Cheap existence check; never returns the value.
    //
    // #730: the DIRECTION of this default is correct and deliberately unchanged
    // — a failed read still yields `passed: false`, which costs the caller a
    // refusal (`would_succeed: false`) rather than granting anything. What was
    // wrong is that it was INDISTINGUISHABLE: the reason read "No secret stored
    // at path X … Add it in the dashboard", sending an operator to create a
    // secret that may already be there, over a vault we never reached. So the
    // read is recorded, the reason states which of the two happened, and
    // `checked` says whether the answer is evidence.
    let presence_read = readings.record(
        "gates.vault_presence",
        state
            .secrets_manager
            .secret_exists_by_path(&secret_path, user_id)
            .await,
    );
    let presence_checked = presence_read.is_some();
    let exists = presence_read.unwrap_or(false);
    let gate_presence = serde_json::json!({
        "name": "vault_presence",
        "passed": exists,
        "checked": presence_checked,
        "reason": if !presence_checked {
            format!(
                "Could NOT check whether a secret is stored at path '{}' — the vault lookup failed (see server logs). This gate is reported as not passed so the overall verdict stays conservative; it is NOT evidence that the secret is absent, so do not add one on the strength of it.",
                secret_path
            )
        } else if exists {
            format!("Secret exists at path '{}' for this user.", secret_path)
        } else {
            format!(
                "No secret stored at path '{}' for this user. Add it in the dashboard (Settings → Secrets) — secret writes require 2FA and aren't available through MCP.",
                secret_path
            )
        },
    });

    let all_pass = world_allowed && !is_reserved && allow_pass && exists;
    let mut body = serde_json::json!({
        "module_id": module_id,
        "module_source": source,
        "capability_world": capability_world,
        "allowed_secrets": allowed_secrets,
        "secret_path": secret_path,
        "would_succeed": all_pass,
        "gates": [gate_capability, gate_reserved, gate_allowlist, gate_presence, gate_prefetch],
    });
    // No-op when every read succeeded, so the healthy response is
    // byte-identical to the pre-#730 one.
    readings.attach(&mut body);
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&body).unwrap_or_default(),
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
    // Modules held back because their reference set could not be READ. UNKNOWN
    // is not zero (2026-09-07): `.unwrap_or_default()` here turned a failed
    // reference query into an EMPTY reference list, and the very next line
    // reads an empty list as "nothing points at this module, delete it". With
    // `dry_run: false` that is an irreversible delete decided by a query that
    // did not answer — the shape check 86 gates for the stale-draft sweep, on a
    // path that deletes rather than recommends. A module whose references are
    // unreadable is now EXCLUDED from `deletable` and disclosed by name.
    let mut unknown_references: Vec<serde_json::Value> = Vec::new();
    for (id, name, compiled_at) in older {
        let refs = match state
            .module_repo
            .find_workflows_referencing_module(user_id, *id, 25)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    module_id = %id,
                    user_id = %user_id,
                    "cleanup_module_versions: reference lookup failed; module held back"
                );
                unknown_references.push(serde_json::json!({
                    "module_id": id,
                    "name": name,
                    "compiled_at": compiled_at.to_rfc3339(),
                    "reason": "reference lookup failed — this module was NOT deleted and NOT \
                               reported as unreferenced. An unreadable reference set is not an \
                               empty one; re-run once the database is answering.",
                }));
                continue;
            }
        };
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
        let surface =
            talos_module_repository::ModuleDeleteSurface::McpCleanupVersions { prefix: &prefix };
        match state
            .module_repo
            .batch_delete_modules(&ids, user_id, surface)
            .await
        {
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
            "unknown_references": unknown_references,
            "message": format!(
                "{}: {} would be deleted, {} still referenced{} (kept {}).",
                action,
                deleted_summary.len(),
                still_referenced.len(),
                if unknown_references.is_empty() {
                    String::new()
                } else {
                    format!(
                        ", {} HELD BACK because their reference set could not be read \
                         (see unknown_references — this is not a claim that they are \
                         unreferenced, and they were not deleted)",
                        unknown_references.len()
                    )
                },
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
            return mcp_denied(req_id, -32000, "Module not found or access denied");
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

    // Read-only, so an unreadable push-binding set does not refuse the
    // listing — it is disclosed, and the listing is computed without that
    // exclusion (cleanup_modules itself refuses in the same state).
    let (push_bound, push_bindings_note) = match push_bound_modules(state, user_id).await {
        Ok(p) => (p, None),
        Err(why) => (
            talos_module_repository::PushBoundModules::default(),
            Some(format!(
                "push-channel bindings could not be read ({why}): this listing may include a \
                 module a push channel dispatches, and cleanup_modules will refuse to run until \
                 they can be read"
            )),
        ),
    };
    match state
        .module_repo
        .find_unreferenced_modules(user_id, days, &push_bound)
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
            // This listing is the ONLY preview an operator has for
            // `cleanup_modules`, whose DELETE is unbounded. A bare `count: 50`
            // over a capped query reads as the whole population, and the
            // operator then authorises a delete against it. Disclose the cap so
            // the number can be read as the lower bound it is.
            let coverage = talos_measurement::Coverage::new(
                i64::try_from(modules.len()).unwrap_or(i64::MAX),
                talos_module_repository::UNREFERENCED_MODULES_LIMIT,
            );
            let result = serde_json::json!({
                "unreferenced_modules": modules,
                "count": modules.len(),
                "filter_days": days,
                "excludes": "modules named in a workflow graph, bound to a webhook trigger or a \
                             push channel, or with execution history",
                "push_channel_bindings": push_bindings_note,
                "coverage": coverage.to_json(),
                "cleanup_note": format!(
                    "cleanup_modules(days: {days}) deletes unreferenced modules older than {days} \
                     day(s) — pass the SAME days value you surveyed with. It is not bounded by \
                     this listing's cap, so a truncated listing means cleanup_modules will remove \
                     more than is shown here.",
                ),
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
        // Check which modules are referenced by workflows (batch query).
        // FAIL CLOSED: a DB error must not default to "none referenced" — that
        // silently deletes referenced modules. Refuse and ask for a retry.
        let referenced_rows = match state
            .module_repo
            .find_referenced_modules_in_workflows(&module_ids, user_id)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "batch_delete: workflow-reference guard failed");
                return mcp_error(
                    req_id,
                    -32000,
                    "Reference check failed (database error). Refusing to delete to avoid orphaning referencing workflows; retry after the database recovers, or pass force: true to override.",
                );
            }
        };

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
        // REFUSE rather than default (2026-09-07). An empty classification is
        // fail-closed for the DELETE — every id falls through to the
        // `not_found` arm below and nothing is removed — but it is NOT
        // fail-closed for the REPORT: the caller is told, by name, that each of
        // their modules "not found", which is false about a module that exists
        // and unactionable during a database incident. The delete-side safety
        // is kept and the false statement is not made.
        let existing = match state
            .module_repo
            .classify_modules_for_delete(&to_delete)
            .await
        {
            Ok(rows) => rows,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    user_id = %user_id,
                    "batch_delete_modules: pre-delete classification failed"
                );
                return mcp_error(
                    req_id,
                    -32000,
                    "Could not classify the requested modules for deletion — the module \
                     registry is unavailable, so NOTHING was deleted. This is not a \
                     statement that those modules are absent; retry once the database \
                     is answering.",
                );
            }
        };

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
        // FAIL CLOSED: a DB error must not default to "no webhook deps" — that
        // silently deletes modules a webhook depends on.
        let wh_referenced = match state
            .module_repo
            .find_webhook_dependencies_for_modules(&actually_delete, user_id)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "batch_delete: webhook-dependency guard failed");
                return mcp_error(
                    req_id,
                    -32000,
                    "Webhook-dependency check failed (database error). Refusing to delete to avoid orphaning webhooks; retry after the database recovers, or pass force: true to override.",
                );
            }
        };

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
            .batch_delete_modules(
                &final_delete,
                user_id,
                talos_module_repository::ModuleDeleteSurface::McpBatch,
            )
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
        Ok(_) => mcp_denied(req_id, -32000, "Module not found or access denied"),
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
        Ok(false) => return mcp_denied(req_id, -32000, "Module not found or access denied"),
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
            // Administrative actions ON this module (`admin_event_log`,
            // resource_type = 'module'). Unreadable is disclosed as `null` +
            // a flag, never as an empty list (check 74's rule).
            let (admin_events, admin_events_unreadable) = match state
                .analytics_repo
                .list_admin_events_for_resource("module", module_id, 100)
                .await
            {
                Ok(rows) => (
                    serde_json::Value::Array(
                        rows.iter()
                            .map(|r| {
                                serde_json::json!({
                                    "admin_event_type": r.event_type,
                                    "timestamp": r.created_at.to_rfc3339(),
                                    "summary": r.summary,
                                    "by_user_id": r.user_id.map(|u| u.to_string()),
                                })
                            })
                            .collect(),
                    ),
                    false,
                ),
                Err(e) => {
                    tracing::error!("get_module_history: admin_event_log read failed: {:#}", e);
                    (serde_json::Value::Null, true)
                }
            };
            let envelope = serde_json::json!({
                "module_id": module_id.to_string(),
                "count": history.len(),
                "change_count": change_count,
                "admin_events": admin_events,
                "admin_events_unreadable": admin_events_unreadable,
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

/// Return a module's stored source code (owned or catalog). `get_module_info`
/// reports `has_source_code: true` but there was no way to retrieve it, which
/// is exactly why a DB-resident module became an unmaintainable black box.
/// Scoping is IDOR-safe (owned or `user_id IS NULL`) via the repo query.
async fn handle_get_module_source(
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

    match state
        .module_repo
        .get_module_source(module_id, user_id)
        .await
    {
        Ok(Some(src)) => {
            let result = serde_json::json!({
                "module_id": module_id.to_string(),
                "language": src.language,
                "capability_world": src.capability_world,
                "kind": src.kind,
                "has_source": src.source_code.is_some(),
                "source": src.source_code,
                "note": if src.source_code.is_none() {
                    "This module has no stored source (bytes-only import)."
                } else {
                    ""
                },
            });
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&result).unwrap_or_default(),
            )
        }
        Ok(None) => mcp_denied(req_id, -32000, "Module not found or access denied"),
        Err(e) => {
            tracing::error!("get_module_source failed: {:#}", e);
            mcp_error(req_id, -32000, "Failed to fetch module source")
        }
    }
}

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
            return mcp_denied(req_id, -32000, "Module not found or access denied");
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
    // DISCLOSED, not defaulted (2026-09-07). Operators consult this tool to
    // decide whether a module is safe to change or delete, and pre-fix
    // `if let Ok(triples)` answered a failed read with `indirect_count: 0` and
    // an empty `indirect_via_sub_workflows` — "nothing depends on this
    // indirectly", the single most reassuring thing this surface can say, from
    // a query that never ran. The two reads ABOVE it in the same function
    // already refuse on `Err`; this one did not.
    let mut readings = talos_measurement::Readings::new();
    let indirect_read = readings.record(
        "indirect_via_sub_workflows",
        state
            .module_repo
            .find_workflows_referencing_workflows(user_id, &direct_ids, 20)
            .await,
    );
    if let Some(triples) = indirect_read.clone() {
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

    // `null`, never `0`: an unreadable indirect scan is UNKNOWN, and the count
    // is what a reader compares against zero before deleting.
    let measured = indirect_read.is_some();
    let mut result = serde_json::json!({
        "module_id": module_id,
        "direct_workflows": direct_workflows,
        "direct_count": direct_workflows.len(),
        "indirect_via_sub_workflows": measured.then_some(indirect_workflows),
        "indirect_count": measured.then_some(seen_ids.len()),
    });
    readings.attach(&mut result);
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
        Ok(None) => return mcp_denied(req_id, -32000, "Module not found or access denied"),
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
    // allow-benign-default: fail-CLOSED. `false` here DENIES the catalog-module
    // write, so a database error costs the caller a refusal, never a privilege.
    // This is the canonical correct shape check 74 exists to leave alone, and
    // converting it would be a security regression in the loosening direction.
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
        mcp_denied(req_id, -32000, "Module not found or access denied")
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

    // `rate_limit_per_minute: null` is the operator-facing spelling of "this
    // module is UNTHROTTLED". The pre-2026-09-02 `.unwrap_or(None)` produced
    // that exact answer from a database error, so the one question this tool
    // exists to answer — is there a ceiling on this module? — was answered
    // "no ceiling" by an outage.
    //
    // `talos_measurement::Readings` is the house mechanism for this class, and
    // it is deliberately NOT used here: this response has exactly ONE field, so
    // a disclosure attached beside a nulled `rate_limit_per_minute` is an error
    // wearing a report's clothes. The `Readings` doctrine's own escape hatch
    // applies — when the failed read IS the response, refuse (the same call
    // `handle_get_schedule_health` makes).
    //
    // KNOWN, PRE-EXISTING and deliberately not widened here: a successful
    // `Ok(None)` still conflates "no such module / not yours" with "module
    // exists, no limit set", because the repository returns `Option<i32>` for
    // both. Separating those needs a repository signature change and is a
    // different defect from the swallowed error.
    let rpm = match state
        .module_repo
        .get_module_rate_limit(module_id, user_id)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(
                module_id = %module_id,
                error = %e,
                "get_module_rate_limit: rate-limit read failed"
            );
            return mcp_error(
                req_id,
                -32000,
                "Could not read this module's rate limit. A module with NO limit and a limit \
                 that could not be read are not the same thing — retry rather than reading \
                 this as unthrottled.",
            );
        }
    };

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
        Ok(_) => mcp_denied(req_id, -32000, "Module not found or access denied"),
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

/// The three grants an install writes, and what a reinstall could not carry.
pub(crate) struct InstallGrants {
    pub(crate) hosts: Vec<String>,
    pub(crate) methods: Vec<String>,
    pub(crate) secrets: Vec<String>,
    /// Per grant, the stored entries the new template no longer grants and
    /// the owner did not add.
    pub(crate) not_carried: serde_json::Map<String, serde_json::Value>,
    /// Per grant, the stored entries the new template does not grant that
    /// were KEPT because the owner added them.
    pub(crate) kept_as_owner_added: serde_json::Map<String, serde_json::Value>,
    /// The entries of the three lists above that are the owner's additions —
    /// written beside them, so the next reinstall keeps them too.
    pub(crate) owner_added: talos_module_repository::OwnerAddedGrants,
}

/// The entries of `list` that `granted` does not grant, per grant kind — the
/// "dropped" half of the same three matchers the reinstall rule bounds with,
/// so "beyond the template" has one meaning for a host, a verb and a vault
/// path. Passed to the repository's permission writer as its
/// [`talos_module_repository::BeyondGrant`].
pub(crate) fn hosts_beyond(granted: &[String], list: &[String]) -> Vec<String> {
    carry_host_grant(list, granted).1
}

/// See [`hosts_beyond`].
pub(crate) fn methods_beyond(granted: &[String], list: &[String]) -> Vec<String> {
    carry_method_grant(list, granted).1
}

/// See [`hosts_beyond`]. `"*"` is beyond anything but `"*"` itself.
pub(crate) fn secrets_beyond(granted: &[String], list: &[String]) -> Vec<String> {
    list.iter()
        .filter(|e| {
            if e.as_str() == "*" {
                !granted.iter().any(|g| g == "*")
            } else {
                !talos_workflow_job_protocol::vault_path_permitted(granted, e)
            }
        })
        .cloned()
        .collect()
}

/// A carried list with the owner's additions put back: `(written, dropped,
/// kept_as_owner_added, owner_added_after)`. An entry the template bound
/// dropped is kept only when it is BOTH in the stored list (it came out of
/// it) and recorded as the owner's; nothing is added that the copy did not
/// already hold.
fn keep_owner_added(
    carried: Vec<String>,
    dropped: Vec<String>,
    owner_added: &[String],
) -> (Vec<String>, Vec<String>, Vec<String>, Vec<String>) {
    let (kept, dropped): (Vec<String>, Vec<String>) =
        dropped.into_iter().partition(|e| owner_added.contains(e));
    let mut written = carried;
    for e in &kept {
        if !written.contains(e) {
            written.push(e.clone());
        }
    }
    let owner_after = owner_added
        .iter()
        .filter(|e| written.contains(e))
        .cloned()
        .collect();
    (written, dropped, kept, owner_after)
}

/// What an install does with the copy's fuel limit, for the reply and the
/// dry run.
///
/// `offered` is what a FIRST install writes: the caller's `fuel_budget` when
/// passed, else the template's `recommended_fuel`, else the baseline. A
/// REINSTALL keeps the copy's own limit unless the caller passed a
/// `fuel_budget` (so an operator's tuning survives) — which also means a limit
/// set by an older, smaller estimate stays forever, and nothing said so.
/// Measured 2026-10-01: an installed `LLM Inference` copy at 1,404,000 against
/// a template recommendation of 9,900,000, with all 18 nodes that use it
/// carrying their own `max_fuel` to get past it.
///
/// `stored` is the limit on the row: before the install for a dry run, read
/// back from the write for a real one. `None` is a first install.
///
/// `template` is what the template alone gives (its `recommended_fuel`, else
/// the baseline) and is ALWAYS reported as `template_max_fuel`. Until
/// 2026-10-02 it read `null` whenever the caller passed a `fuel_budget` — the
/// one case where the caller most needs the number to compare against.
pub(crate) fn install_fuel_report(
    stored: Option<i64>,
    offered: i64,
    template: i64,
    fuel_explicit: bool,
) -> serde_json::Value {
    let (max_fuel, source) = match stored {
        None => (
            offered,
            if fuel_explicit {
                "fuel_budget"
            } else {
                "template"
            },
        ),
        Some(_) if fuel_explicit => (offered, "fuel_budget"),
        Some(kept) => (kept, "kept"),
    };
    let mut report = serde_json::json!({
        "max_fuel": max_fuel,
        "source": source,
        "template_max_fuel": template,
    });
    if source == "fuel_budget" && max_fuel < template {
        // What gets the template's figure differs by case, so the note says
        // the one that applies. On a reinstall, omitting `fuel_budget` KEEPS
        // the copy's current limit; it does not take the template's.
        let to_take_the_templates = if stored.is_none() {
            "To take the template's, omit fuel_budget."
        } else {
            "To take the template's, pass the template's recommended_fuel as fuel_budget; \
             omitting fuel_budget on a reinstall keeps the copy's current limit."
        };
        report["note"] = format!(
            "The fuel_budget passed gives a limit ({max_fuel}) BELOW what the template recommends \
             ({template}). It is applied as given. {to_take_the_templates}"
        )
        .into();
    }
    if source == "kept" && max_fuel < offered {
        report["note"] = format!(
            "This copy keeps its own fuel limit ({max_fuel}), which is BELOW what the template now \
             recommends ({offered}). A reinstall never changes a copy's limit on its own. To adopt \
             the template's, reinstall with `fuel_budget` set to the template's `recommended_fuel`; \
             until then a node that needs more must set `max_fuel` in its config."
        )
        .into();
    }
    report
}

/// What `install_module_from_catalog` would store, for `dry_run: true`.
///
/// `grants` is the outcome of [`grants_for_install`] — the same value the real
/// install writes — so the preview cannot disagree with the install. `current`
/// is `null` on a first install. `grants_changed` compares the three lists as
/// sets, since order carries no meaning in a grant.
pub(crate) fn install_dry_run_report(
    name: &str,
    capability_world: &str,
    installed: Option<&talos_module_repository::StoredModuleGrants>,
    grants: &InstallGrants,
    secrets_not_granted: &[String],
    fuel: serde_json::Value,
) -> serde_json::Value {
    fn as_set(v: &[String]) -> std::collections::BTreeSet<&str> {
        v.iter().map(String::as_str).collect()
    }
    let grants_changed = installed.map(|cur| {
        as_set(&cur.hosts) != as_set(&grants.hosts)
            || as_set(&cur.methods) != as_set(&grants.methods)
            || as_set(&cur.secrets) != as_set(&grants.secrets)
    });
    serde_json::json!({
        "dry_run": true,
        "name": name,
        "capability_world": capability_world,
        "first_install": installed.is_none(),
        "would_install": {
            "allowed_hosts": grants.hosts,
            "allowed_methods": grants.methods,
            "allowed_secrets": grants.secrets,
        },
        "current": installed.map(|cur| serde_json::json!({
            "allowed_hosts": cur.hosts,
            "allowed_methods": cur.methods,
            "allowed_secrets": cur.secrets,
        })),
        // `null` on a first install: there is nothing to compare with.
        "grants_changed": grants_changed,
        "grants_not_carried": grants.not_carried,
        "grants_kept_as_owner_added": grants.kept_as_owner_added,
        "secrets_not_granted": secrets_not_granted,
        "fuel": fuel,
        "note": "Nothing was compiled, written or recorded. Run again without dry_run to install. \
                 The code itself is not compared here: get_catalog_status → installed_copies says \
                 whether your copy is behind the catalog.",
    })
}

/// The ONE rule for which grants an install writes (2026-09-29).
///
/// `hosts` / `methods` / `secrets` are what a FIRST install would write: the
/// template's grant, with the caller's explicit parameters already applied.
/// On a first install (`installed` is `None`) they are written as-is. On a
/// REINSTALL each grant the caller did NOT pass is the installed copy's
/// stored grant, bounded by those template values; a grant the caller did
/// pass keeps today's rule. Hosts have no caller parameter, so they are
/// always carried.
///
/// **What the owner added is kept (2026-10-04).** The bound above dropped
/// every stored entry the new template does not grant — including the host
/// and the secret an owner added on purpose to a template that installs with
/// none, so a reinstall left such a copy able to reach nothing. An entry the
/// bound drops is now kept when the copy's `owner_added` record names it.
/// Everything else still narrows with the template: an inherited entry the
/// template stops granting is dropped exactly as before, and nothing is
/// written that the copy did not already hold. `template_methods` is the
/// template's own verbs, before the caller's are added.
pub(crate) fn grants_for_install(
    installed: Option<&talos_module_repository::StoredModuleGrants>,
    hosts: Vec<String>,
    methods: Vec<String>,
    secrets: Vec<String>,
    caller_passed_methods: bool,
    caller_passed_secrets: bool,
    template_methods: &[String],
) -> InstallGrants {
    use talos_module_repository::OwnerAddedGrants;
    let mut not_carried = serde_json::Map::new();
    let mut kept_as_owner_added = serde_json::Map::new();
    // Verbs the caller passed are ADDED to the template's; the extra ones are
    // the owner's, on a first install and on a reinstall alike.
    let passed_verbs_beyond = |written: &[String]| methods_beyond(template_methods, written);
    let Some(stored) = installed else {
        let owner_added = OwnerAddedGrants {
            methods: if caller_passed_methods {
                passed_verbs_beyond(&methods)
            } else {
                Vec::new()
            },
            ..OwnerAddedGrants::default()
        };
        return InstallGrants {
            hosts,
            methods,
            secrets,
            not_carried,
            kept_as_owner_added,
            owner_added,
        };
    };
    let was = &stored.owner_added;

    let (carried, dropped) = carry_host_grant(&stored.hosts, &hosts);
    let (hosts, hosts_dropped, hosts_kept, owner_hosts) =
        keep_owner_added(carried, dropped, &was.hosts);

    let (methods, methods_dropped, methods_kept, owner_methods) = if caller_passed_methods {
        let owner = passed_verbs_beyond(&methods);
        (methods, Vec::new(), Vec::new(), owner)
    } else {
        let (carried, dropped) = carry_method_grant(&stored.methods, &methods);
        keep_owner_added(carried, dropped, &was.methods)
    };

    // An explicit `allowed_secrets` replaces the grant, and can only narrow
    // the template's: nothing in it is beyond the template.
    let (secrets, secrets_dropped, secrets_kept, owner_secrets) = if caller_passed_secrets {
        (secrets, Vec::new(), Vec::new(), Vec::new())
    } else {
        let (carried, dropped) = narrow_secret_grant(&secrets, &stored.secrets);
        keep_owner_added(carried, dropped, &was.secrets)
    };

    for (key, dropped, kept) in [
        ("allowed_hosts", hosts_dropped, hosts_kept),
        ("allowed_methods", methods_dropped, methods_kept),
        ("allowed_secrets", secrets_dropped, secrets_kept),
    ] {
        if !dropped.is_empty() {
            not_carried.insert(key.to_string(), serde_json::json!(dropped));
        }
        if !kept.is_empty() {
            kept_as_owner_added.insert(key.to_string(), serde_json::json!(kept));
        }
    }
    InstallGrants {
        hosts,
        methods,
        secrets,
        not_carried,
        kept_as_owner_added,
        owner_added: OwnerAddedGrants {
            hosts: owner_hosts,
            methods: owner_methods,
            secrets: owner_secrets,
        },
    }
}

/// One grant list carried from an installed copy onto its reinstall:
/// `(carried, not_carried)`.
type CarriedList = (Vec<String>, Vec<String>);

/// Carry an installed copy's stored HOST grant onto its reinstall, bounded
/// by the new template's grant (2026-09-29).
///
/// A reinstall used to write the template's grant over whatever the copy
/// held, so an operator's narrowing (`update_module_hosts`) was silently
/// undone. Now each stored entry is kept only if the template still grants
/// it, by the worker's own matcher: the template holds `"*"`, holds the same
/// entry, or (for an exact host) admits it through a suffix pattern. The
/// result is never wider than either list; dropped entries are returned so
/// the response can name them.
pub(crate) fn carry_host_grant(stored: &[String], template: &[String]) -> CarriedList {
    let norm = |h: &str| h.trim_end_matches('.').to_ascii_lowercase();
    let template_has_wildcard = template.iter().any(|t| t == "*");
    let (mut kept, mut dropped) = (Vec::new(), Vec::new());
    for e in stored {
        let is_exact_host = e != "*" && !e.starts_with('.');
        let admitted = template_has_wildcard
            || template.iter().any(|t| norm(t) == norm(e))
            || (is_exact_host && talos_worker_runtime::host::host_allowlist_match(template, e));
        if admitted {
            kept.push(e.clone())
        } else {
            dropped.push(e.clone())
        }
    }
    (kept, dropped)
}

/// Carry a stored METHOD grant onto a reinstall: a verb survives only if the
/// new template still grants it. See [`carry_host_grant`].
pub(crate) fn carry_method_grant(stored: &[String], template: &[String]) -> CarriedList {
    stored
        .iter()
        .cloned()
        .partition(|m| template.iter().any(|t| t.eq_ignore_ascii_case(m)))
}

/// Narrow a template's secret grant by a caller-supplied `allowed_secrets`
/// list (2026-09-10). Returns `(granted, not_granted)`.
///
/// The template's grant is the CEILING. A caller entry is honoured when it is
/// inside that ceiling by the one allowlist matcher controller and worker
/// share (`vault_path_permitted`): an exact template path, a path under a
/// template prefix or glob, or the whole grant (`"*"`, which narrows to the
/// template's own list rather than widening to every vault path). A caller
/// prefix or glob that some template paths fall UNDER is narrowed to exactly
/// those template paths. Anything else the caller asked for is returned in
/// `not_granted` so the response can say so instead of silently dropping it.
/// An empty caller list is an explicit deny-all and grants nothing.
pub(crate) fn narrow_secret_grant(
    template_secrets: &[String],
    caller_secrets: &[String],
) -> (Vec<String>, Vec<String>) {
    let mut granted: Vec<String> = Vec::new();
    let mut not_granted: Vec<String> = Vec::new();
    let push_unique = |v: &mut Vec<String>, s: &str| {
        if !v.iter().any(|x| x == s) {
            v.push(s.to_string());
        }
    };
    for c in caller_secrets {
        if c == "*" {
            for t in template_secrets {
                push_unique(&mut granted, t);
            }
            continue;
        }
        if talos_workflow_job_protocol::vault_path_permitted(template_secrets, c) {
            push_unique(&mut granted, c);
            continue;
        }
        let under_caller: Vec<&String> = template_secrets
            .iter()
            .filter(|t| {
                talos_workflow_job_protocol::vault_path_permitted(std::slice::from_ref(c), t)
            })
            .collect();
        if under_caller.is_empty() {
            push_unique(&mut not_granted, c);
        } else {
            for t in under_caller {
                push_unique(&mut granted, t);
            }
        }
    }
    (granted, not_granted)
}

#[cfg(test)]
mod catalog_template_resolver_tests {
    use super::resolve_catalog_template_dir;
    use std::fs;

    /// A throwaway catalog: `<root>/catalog/llm-inference/talos.json`, plus a
    /// directory OUTSIDE the catalog that also has a manifest, so a key that
    /// escaped the catalog would have something to find.
    fn fixture() -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("talos-resolver-{}", uuid::Uuid::new_v4()));
        let dir = root.join("catalog").join("llm-inference");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("talos.json"),
            r#"{"display_name": "LLM Inference"}"#,
        )
        .unwrap();
        let outside = root.join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("talos.json"), r#"{"display_name": "Outside"}"#).unwrap();
        root
    }

    #[test]
    fn a_slug_and_a_display_name_resolve_to_the_same_template() {
        let root = fixture();
        let catalog = root.join("catalog");
        let want = catalog.join("llm-inference");
        assert_eq!(
            resolve_catalog_template_dir(&catalog, "llm-inference"),
            Some(want.clone())
        );
        // The pin stores the DISPLAY name — the case restore used to get wrong.
        assert_eq!(
            resolve_catalog_template_dir(&catalog, "LLM Inference"),
            Some(want)
        );
        assert_eq!(
            resolve_catalog_template_dir(&catalog, "no-such-template"),
            None
        );
        fs::remove_dir_all(root).unwrap();
    }

    /// Restore rebuilds only an UNCHANGED copy: the template comes back only
    /// when its source is byte-identical to the copy's.
    #[test]
    fn only_an_unchanged_copy_is_rebuildable() {
        let root = fixture();
        let dir = root.join("catalog").join("llm-inference");
        fs::write(dir.join("template.rs"), "fn catalog_v2() {}").unwrap();
        let load = || talos_compilation::CatalogTemplate::load(&dir).unwrap();
        assert!(super::rebuildable_template("fn catalog_v2() {}", load()).is_ok());
        assert!(
            super::rebuildable_template("fn catalog_v1() {}", load()).is_err(),
            "behind"
        );
        assert!(
            super::rebuildable_template("fn mine() {}", load()).is_err(),
            "edited"
        );
        fs::remove_dir_all(root).unwrap();
    }

    /// The display names reports show — with a colon, a slash, parentheses —
    /// are accepted as keys and resolve to their template.
    #[test]
    fn a_display_name_with_punctuation_is_accepted_and_resolves() {
        let root = fixture();
        let catalog = root.join("catalog");
        for (dir, display) in [
            ("gmail-list-messages", "Gmail: List Messages"),
            ("echo-debug", "Echo/Debug"),
            ("hybrid-classify-alerts", "Hybrid Classify (Alerts)"),
        ] {
            let path = catalog.join(dir);
            fs::create_dir_all(&path).unwrap();
            fs::write(
                path.join("talos.json"),
                serde_json::json!({ "display_name": display }).to_string(),
            )
            .unwrap();
            let key = super::catalog_template_key(display).expect("accepted");
            assert_eq!(
                resolve_catalog_template_dir(&catalog, key),
                Some(path.clone())
            );
            // Padded input resolves the same way.
            let padded = format!("  {display} ");
            let key = super::catalog_template_key(&padded).expect("accepted");
            assert_eq!(
                resolve_catalog_template_dir(&catalog, key),
                Some(path.clone())
            );
            // And so does the slug.
            assert_eq!(resolve_catalog_template_dir(&catalog, dir), Some(path));
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn an_empty_oversized_or_control_character_key_is_refused() {
        for bad in ["", "   ", "a\nb", "a\0b", "a\u{1b}[31mb"] {
            assert!(super::catalog_template_key(bad).is_err(), "{bad:?}");
        }
        assert!(super::catalog_template_key(&"x".repeat(129)).is_err());
        assert!(super::catalog_template_key(&"x".repeat(128)).is_ok());
    }

    /// A path-shaped key is refused before the resolver. The resolver would
    /// not leave the catalog for one (next test), but it matches by slug, so
    /// without this `./llm-inference/..` would install LLM Inference.
    #[test]
    fn a_path_shaped_key_is_refused() {
        for key in [
            "../outside",
            "..",
            "/etc/passwd",
            "./llm-inference/..",
            "..\\outside",
            "\\share",
            ".hidden",
            "a/../b",
        ] {
            assert!(super::catalog_template_key(key).is_err(), "{key:?}");
        }
        // A slash inside a real display name is not a path.
        assert_eq!(super::catalog_template_key("Echo/Debug"), Ok("Echo/Debug"));
    }

    /// A key is never joined onto the path unless it is one safe component,
    /// so nothing outside the catalog can be reached, whatever the key.
    #[test]
    fn no_key_escapes_the_catalog() {
        let root = fixture();
        let catalog = root.join("catalog");
        for key in ["../outside", "..", "a/b", "/etc", "Outside", "outside", ""] {
            assert_eq!(
                resolve_catalog_template_dir(&catalog, key),
                None,
                "key {key:?}"
            );
        }
        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod catalog_drift_report_tests {
    use super::{catalog_drift_tip, installed_copies_json};
    use talos_module_repository::CatalogCopyRow;

    fn copy(name: &str, matches: bool, hot: bool, live: i64) -> CatalogCopyRow {
        CatalogCopyRow {
            module_id: uuid::Uuid::nil(),
            name: name.into(),
            catalog_slug: Some(name.into()),
            in_catalog: true,
            catalog_source_absent: false,
            source_matches: matches,
            artifact_matches: None,
            schema_matches: true,
            world_matches: true,
            approvals_match: true,
            hot_updated: hot,
            live_workflows: live,
            compiled_at: None,
            catalog_updated_at: None,
        }
    }

    #[test]
    fn counts_and_urgency_order() {
        let rows = vec![
            copy("current", true, false, 5),
            copy("behind-unused", false, false, 0),
            copy("edited", false, true, 1),
            copy("behind-used", false, false, 3),
        ];
        let v = installed_copies_json(&rows);
        assert_eq!(v["counts"]["behind"], 2);
        assert_eq!(v["counts"]["current"], 1);
        assert_eq!(v["counts"]["detached"], 1);
        let order: Vec<&str> = v["copies"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["name"].as_str().unwrap())
            .collect();
        assert_eq!(order, ["behind-used", "behind-unused", "edited", "current"]);
        assert_eq!(v["copies"][0]["state"], "behind");
    }

    #[test]
    fn a_schema_only_difference_is_reported_as_behind_and_named() {
        let mut schema_only = copy("llm", true, false, 16);
        schema_only.schema_matches = false;
        let rows = vec![schema_only, copy("ok", true, false, 1)];
        let v = installed_copies_json(&rows);
        assert_eq!(v["counts"]["behind"], 1);
        assert_eq!(v["copies"][0]["name"], "llm");
        assert_eq!(v["copies"][0]["state"], "behind");
        assert_eq!(
            v["copies"][0]["differs_in"],
            serde_json::json!(["config_schema"])
        );
        assert_eq!(v["copies"][1]["differs_in"], serde_json::json!([]));
        assert_eq!(super::catalog_drift_brief(&rows)["behind"], 1);
        assert!(catalog_drift_tip(&rows).is_some());
    }

    #[test]
    fn the_session_brief_counts_behind_and_names_the_used_ones() {
        let v = super::catalog_drift_brief(&[
            copy("llm", false, false, 14),
            copy("gcp", false, false, 0),
            copy("ok", true, false, 3),
        ]);
        assert_eq!(v["behind"], 2);
        assert_eq!(v["behind_in_use"], serde_json::json!(["llm"]));
        assert_eq!(v["unknown"], 0);
    }

    #[test]
    fn the_tip_names_used_copies_first_and_only_fires_when_something_is_behind() {
        assert_eq!(catalog_drift_tip(&[copy("a", true, false, 1)]), None);
        assert_eq!(
            catalog_drift_tip(&[copy("edited", false, true, 1)]),
            None,
            "a deliberately edited copy is not a finding"
        );
        let tip = catalog_drift_tip(&[copy("llm", false, false, 14), copy("gcp", false, false, 0)])
            .expect("two behind");
        assert!(tip.starts_with("2 of your installed"));
        assert!(tip.contains("llm (14 live workflow(s))"));
        assert!(tip.contains("Not used by any live workflow: gcp."));
        assert!(tip.contains("keeps the same module id and your copy's allowed_hosts"));
    }
}

#[cfg(test)]
mod carry_grant_tests {
    use super::{carry_host_grant, carry_method_grant, narrow_secret_grant};

    fn v(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| (*s).to_string()).collect()
    }

    /// The live case (2026-09-29): three installed Gmail copies are pinned to
    /// one account's token while the template grants every Gmail path. A
    /// reinstall must keep the pin, not widen it back to the template.
    #[test]
    fn a_narrowed_secret_grant_survives_a_reinstall() {
        let pinned = v(&["oauth/gmail/u1/me@example.com/access_token"]);
        let (kept, dropped) = narrow_secret_grant(&v(&["oauth/gmail/*"]), &pinned);
        assert_eq!(kept, pinned);
        assert!(dropped.is_empty());
    }

    /// The other direction: a path the new template no longer grants is not
    /// carried, and is reported.
    #[test]
    fn a_secret_the_template_dropped_is_not_carried() {
        let (kept, dropped) =
            narrow_secret_grant(&v(&["slack/token"]), &v(&["slack/token", "github/token"]));
        assert_eq!(kept, v(&["slack/token"]));
        assert_eq!(dropped, v(&["github/token"]));
    }

    #[test]
    fn a_narrowed_host_grant_survives_a_wildcard_template() {
        let (kept, dropped) = carry_host_grant(&v(&["api.example.com"]), &v(&["*"]));
        assert_eq!(kept, v(&["api.example.com"]));
        assert!(dropped.is_empty());
    }

    #[test]
    fn a_host_is_carried_only_while_the_template_grants_it() {
        let template = v(&["api.example.com", ".googleapis.com"]);
        let (kept, dropped) = carry_host_grant(
            &v(&[
                "API.example.com.",
                "gmail.googleapis.com",
                "evil.example.net",
                "*",
                ".other.com",
            ]),
            &template,
        );
        assert_eq!(kept, v(&["API.example.com.", "gmail.googleapis.com"]));
        assert_eq!(dropped, v(&["evil.example.net", "*", ".other.com"]));
    }

    /// Never wider than the stored grant: an empty stored grant stays empty
    /// even under a wildcard template.
    #[test]
    fn an_empty_stored_grant_stays_empty() {
        assert_eq!(carry_host_grant(&[], &v(&["*"])), (vec![], vec![]));
        assert_eq!(
            carry_method_grant(&[], &v(&["GET", "POST"])),
            (vec![], vec![])
        );
    }

    fn stored(h: &[&str], m: &[&str], s: &[&str]) -> talos_module_repository::StoredModuleGrants {
        talos_module_repository::StoredModuleGrants {
            max_fuel: 2_000_000,
            hosts: v(h),
            methods: v(m),
            secrets: v(s),
            owner_added: talos_module_repository::OwnerAddedGrants::default(),
        }
    }

    /// A first install writes the template's grant exactly as before.
    #[test]
    fn a_first_install_is_unchanged() {
        let g = super::grants_for_install(
            None,
            v(&["*"]),
            v(&["GET"]),
            v(&["oauth/gmail/*"]),
            false,
            false,
            &v(&["GET"]),
        );
        assert_eq!(
            (g.hosts, g.methods, g.secrets),
            (v(&["*"]), v(&["GET"]), v(&["oauth/gmail/*"]))
        );
        assert!(g.not_carried.is_empty());
    }

    /// THE defect: a plain reinstall of a copy an operator narrowed keeps
    /// every narrowing instead of writing the template's grant back.
    #[test]
    fn a_plain_reinstall_keeps_every_narrowing() {
        let copy = stored(
            &["gmail.googleapis.com"],
            &["GET"],
            &["oauth/gmail/u1/me@example.com/access_token"],
        );
        let g = super::grants_for_install(
            Some(&copy),
            v(&["*"]),
            v(&["GET", "POST"]),
            v(&["oauth/gmail/*"]),
            false,
            false,
            &v(&["GET", "POST"]),
        );
        assert_eq!(g.hosts, copy.hosts);
        assert_eq!(g.methods, copy.methods);
        assert_eq!(g.secrets, copy.secrets);
        assert!(g.not_carried.is_empty());
    }

    /// A parameter the caller passes explicitly still follows today's rule,
    /// and whatever the new template no longer grants is dropped and named.
    fn owned(
        mut copy: talos_module_repository::StoredModuleGrants,
        h: &[&str],
        m: &[&str],
        s: &[&str],
    ) -> talos_module_repository::StoredModuleGrants {
        copy.owner_added = talos_module_repository::OwnerAddedGrants {
            hosts: v(h),
            methods: v(m),
            secrets: v(s),
        };
        copy
    }

    /// The case that was live on 2026-10-04: a template that installs with no
    /// host and no secret, a copy its owner granted one of each, and a plain
    /// reinstall. The grants are the owner's, so they stay.
    #[test]
    fn what_the_owner_added_survives_a_reinstall_of_a_template_that_grants_nothing() {
        let copy = owned(
            stored(&["home.example.test"], &["POST"], &["homeassistant/token"]),
            &["home.example.test"],
            &[],
            &["homeassistant/token"],
        );
        let g = super::grants_for_install(
            Some(&copy),
            vec![],
            v(&["POST"]),
            vec![],
            false,
            false,
            &v(&["POST"]),
        );
        assert_eq!(g.hosts, v(&["home.example.test"]));
        assert_eq!(g.secrets, v(&["homeassistant/token"]));
        assert_eq!(g.methods, v(&["POST"]));
        assert!(g.not_carried.is_empty(), "{:?}", g.not_carried);
        assert_eq!(
            serde_json::Value::Object(g.kept_as_owner_added.clone()),
            serde_json::json!({ "allowed_hosts": ["home.example.test"], "allowed_secrets": ["homeassistant/token"] })
        );
        // And the record travels with them, so the NEXT reinstall keeps them too.
        assert_eq!(g.owner_added.hosts, v(&["home.example.test"]));
        assert_eq!(g.owner_added.secrets, v(&["homeassistant/token"]));
    }

    /// The 2026-09-29 rule is intact for what a copy INHERITED: a template
    /// that stops granting a host, a verb or a path narrows the copy, whether
    /// or not the owner added something else beside it.
    #[test]
    fn an_inherited_entry_still_narrows_with_the_template() {
        let copy = owned(
            stored(
                &["old.example.com", "mine.example.com"],
                &["GET", "DELETE"],
                &["legacy/key", "mine/key"],
            ),
            &["mine.example.com"],
            &[],
            &["mine/key"],
        );
        let g = super::grants_for_install(
            Some(&copy),
            v(&["api.example.com"]),
            v(&["GET"]),
            v(&["slack/token"]),
            false,
            false,
            &v(&["GET"]),
        );
        assert_eq!(g.hosts, v(&["mine.example.com"]));
        assert_eq!(g.methods, v(&["GET"]));
        assert_eq!(g.secrets, v(&["mine/key"]));
        assert_eq!(
            serde_json::Value::Object(g.not_carried.clone()),
            serde_json::json!({
                "allowed_hosts": ["old.example.com"],
                "allowed_methods": ["DELETE"],
                "allowed_secrets": ["legacy/key"],
            })
        );
    }

    /// The record cannot ADD anything: an entry named there that the copy's
    /// list does not hold is not written. A reinstall never grants what the
    /// copy did not already have.
    #[test]
    fn a_record_naming_an_entry_the_copy_does_not_hold_grants_nothing() {
        let copy = owned(
            stored(&["a.example.com"], &["GET"], &["x/y"]),
            &["evil.example.com", "*"],
            &["DELETE"],
            &["*", "anthropic/api_key"],
        );
        let g = super::grants_for_install(
            Some(&copy),
            vec![],
            v(&["GET"]),
            vec![],
            false,
            false,
            &v(&["GET"]),
        );
        assert!(g.hosts.is_empty(), "{:?}", g.hosts);
        assert!(g.secrets.is_empty(), "{:?}", g.secrets);
        assert_eq!(g.methods, v(&["GET"]));
        assert!(g.kept_as_owner_added.is_empty());
        // The record written back names only what is in the lists.
        assert_eq!(
            g.owner_added,
            talos_module_repository::OwnerAddedGrants::default()
        );
    }

    /// Verbs passed to an install are added to the template's, and the extra
    /// ones are the caller's own: recorded, so a later plain reinstall keeps
    /// them. A secrets parameter can only narrow, so it records nothing.
    #[test]
    fn verbs_passed_to_an_install_are_the_owners_and_are_kept_next_time() {
        let first = super::grants_for_install(
            None,
            vec![],
            v(&["GET", "PUT"]),
            v(&["x/y"]),
            true,
            true,
            &v(&["GET"]),
        );
        assert_eq!(first.owner_added.methods, v(&["PUT"]));
        assert!(first.owner_added.secrets.is_empty());
        let copy = owned(stored(&[], &["GET", "PUT"], &["x/y"]), &[], &["PUT"], &[]);
        let again = super::grants_for_install(
            Some(&copy),
            vec![],
            v(&["GET"]),
            v(&["x/y"]),
            false,
            false,
            &v(&["GET"]),
        );
        assert_eq!(again.methods, v(&["GET", "PUT"]));
        assert_eq!(again.owner_added.methods, v(&["PUT"]));
    }

    /// "Beyond" is decided by the same matchers the bound uses.
    #[test]
    fn beyond_uses_the_matchers_the_bound_uses() {
        use super::{hosts_beyond, methods_beyond, secrets_beyond};
        assert_eq!(
            hosts_beyond(
                &v(&[".example.com"]),
                &v(&["api.example.com", "other.test"])
            ),
            v(&["other.test"])
        );
        assert_eq!(
            hosts_beyond(&v(&["*"]), &v(&["anything.test"])),
            Vec::<String>::new()
        );
        assert_eq!(hosts_beyond(&[], &v(&["a.test"])), v(&["a.test"]));
        assert_eq!(
            methods_beyond(&v(&["GET"]), &v(&["get", "POST"])),
            v(&["POST"])
        );
        assert_eq!(
            secrets_beyond(
                &v(&["oauth/gmail/*"]),
                &v(&["oauth/gmail/u/a/access_token", "plaid/secret", "*"])
            ),
            v(&["plaid/secret", "*"])
        );
        assert_eq!(
            secrets_beyond(&v(&["*"]), &v(&["*", "x/y"])),
            Vec::<String>::new()
        );
    }

    #[test]
    fn an_explicit_parameter_wins_and_dropped_entries_are_reported() {
        let copy = stored(&["old.example.com"], &["DELETE"], &["gone/key"]);
        let g = super::grants_for_install(
            Some(&copy),
            v(&["api.example.com"]),
            v(&["GET", "PUT"]),
            v(&["slack/token"]),
            true,
            false,
            // The template grants GET; PUT is the caller's.
            &v(&["GET"]),
        );
        assert_eq!(g.methods, v(&["GET", "PUT"]), "explicit methods win");
        assert!(g.hosts.is_empty());
        assert!(g.secrets.is_empty());
        assert_eq!(
            g.not_carried["allowed_hosts"],
            serde_json::json!(["old.example.com"])
        );
        assert_eq!(
            g.not_carried["allowed_secrets"],
            serde_json::json!(["gone/key"])
        );
        assert!(!g.not_carried.contains_key("allowed_methods"));
    }

    #[test]
    fn a_method_is_carried_only_while_the_template_grants_it() {
        let (kept, dropped) = carry_method_grant(&v(&["GET", "delete"]), &v(&["get", "POST"]));
        assert_eq!(kept, v(&["GET"]));
        assert_eq!(dropped, v(&["delete"]));
    }
}

#[cfg(test)]
mod narrow_secret_grant_tests {
    use super::narrow_secret_grant;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_caller_path_outside_the_template_grant_is_not_granted() {
        let (granted, not) = narrow_secret_grant(&v(&["slack/token"]), &v(&["anthropic/api_key"]));
        assert!(granted.is_empty(), "{granted:?}");
        assert_eq!(not, v(&["anthropic/api_key"]));
    }

    #[test]
    fn a_caller_subset_narrows() {
        let (granted, not) =
            narrow_secret_grant(&v(&["slack/token", "slack/signing"]), &v(&["slack/token"]));
        assert_eq!(granted, v(&["slack/token"]));
        assert!(not.is_empty());
    }

    #[test]
    fn caller_wildcard_yields_the_template_list_not_every_path() {
        let (granted, not) = narrow_secret_grant(&v(&["slack/token", "slack/signing"]), &v(&["*"]));
        assert_eq!(granted, v(&["slack/token", "slack/signing"]));
        assert!(not.is_empty());
    }

    #[test]
    fn a_path_under_a_template_glob_is_granted_as_named() {
        let (granted, _) = narrow_secret_grant(&v(&["slack/*"]), &v(&["slack/token"]));
        assert_eq!(granted, v(&["slack/token"]));
    }

    #[test]
    fn a_caller_prefix_over_template_paths_narrows_to_those_paths() {
        let (granted, not) =
            narrow_secret_grant(&v(&["slack/token", "jira/token"]), &v(&["slack"]));
        assert_eq!(granted, v(&["slack/token"]));
        assert!(not.is_empty());
    }

    #[test]
    fn template_wildcard_honours_the_caller_list_verbatim() {
        let (granted, not) = narrow_secret_grant(&v(&["*"]), &v(&["anthropic/api_key"]));
        assert_eq!(granted, v(&["anthropic/api_key"]));
        assert!(not.is_empty());
    }

    #[test]
    fn an_empty_caller_list_is_deny_all() {
        let (granted, not) = narrow_secret_grant(&v(&["slack/token"]), &v(&[]));
        assert!(granted.is_empty());
        assert!(not.is_empty());
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
    // `search` is accepted as an alias for `query` — every sibling listing
    // tool calls it search, and the mismatch was a live papercut (callers
    // passed `search`, got the unknown-arg warning, and full output).
    let query_filter = args
        .get("query")
        .or_else(|| args.get("search"))
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

    // Batch-fetch every module VISIBLE to this user (global catalog rows +
    // their own copies) → id, so we can report the id a caller can actually
    // use without N+1 queries.
    //
    // This deliberately does NOT use `list_user_template_names`, which sees
    // only the personal half. That is what made the listing report
    // `installed: false, module_id: null` for a global catalog row that
    // `add_node_to_workflow` accepts as-is — the response withheld the very id
    // that would have avoided a pointless `install_module_from_catalog`.
    //
    // REFUSE, do not default (2026-09-08). Pre-fix `.unwrap_or_default()`
    // rendered a failed visibility read as an EMPTY map, and this map decides
    // three things a caller acts on: `installed`, `module_id` and
    // `availability`. With it empty every catalog entry reads
    // `installed: false, module_id: null, availability: "needs_install"` —
    // an instruction to run `install_module_from_catalog` for modules the
    // caller already has — and with `installed_only: true` the WHOLE listing
    // renders as `[]`, i.e. "you have installed nothing". The same refusal
    // shape as `handle_list_templates` and `handle_list_modules` above, for
    // the same reason: an emptiness claim is the premise of the caller's next
    // step, and there is no partial answer to give.
    let visible = match state
        .module_repo
        .list_visible_module_ids(agent.user_id.unwrap_or_else(uuid::Uuid::nil))
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "list_module_catalog: visibility read failed");
            return mcp_error(
                req_id,
                -32000,
                "Could not read which catalog modules you already have, so every entry's \
                 `installed` / `module_id` / `availability` would be a guess — this is NOT \
                 a statement that you have installed none of them, and it is NOT an \
                 instruction to install anything. Retry, and check controller logs.",
            );
        }
    };

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
    let entries: Vec<serde_json::Value> = if talos_config::registry_url().is_some() {
        // Registry mode: the catalog IS the shared rows the registry sync
        // wrote. The templates baked into the image are not what this
        // deployment offers — the disk seed is skipped, so listing them would
        // name modules `install_module_from_catalog` then builds from an
        // image that may be behind the registry. Not cached: a sync changes
        // it, and it is one bounded read. A failed read is refused for the
        // reason the disk walk's is, below.
        match state.module_repo.list_shared_registry_entries().await {
            Ok(rows) => registry_catalog_items(&rows),
            Err(e) => {
                tracing::error!(error = %e, "list_module_catalog: registry catalog read failed");
                return mcp_error(
                    req_id,
                    -32000,
                    "Could not read the module catalog (database error), so this listing \
                     would be empty BECAUSE NOBODY COULD LOOK — that is not a statement that \
                     the registry offers no modules. Retry, and check controller logs.",
                );
            }
        }
    } else if catalog_dir.is_dir() {
        // 2026-09-08: a FAILED walk must not be MEMOIZED.
        //
        // `get_or_init` + `.unwrap_or_default()` cached the empty vec a
        // `JoinError` produced, so ONE panicked or cancelled blocking task
        // made every later `list_module_catalog` call in this pod's lifetime
        // report `catalog_total_count: 0, catalog: []` — "this image ships no
        // modules" — with no retry path short of a restart. The inner
        // `if let Ok(read_dir)` had the same shape for an `io::Error`
        // (EACCES on the baked template directory), and it too was cached.
        //
        // `get_or_try_init` is the whole fix for the caching half: on `Err`
        // the cell stays UNINITIALISED, so the next call walks again. The
        // handler then refuses, matching the sibling visibility read ~30
        // lines above, whose refusal text this one is written against.
        match CATALOG_CACHE
            .get_or_try_init(|| async move {
                tokio::task::spawn_blocking(move || {
                    let mut items: Vec<serde_json::Value> = Vec::new();
                    let read_dir = std::fs::read_dir(&catalog_dir_owned).map_err(|e| {
                        format!("read_dir({}) failed: {e}", catalog_dir_owned.display())
                    })?;
                    {
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
                    Ok::<_, String>(items)
                })
                .await
                .map_err(|e| format!("catalog walk task failed: {e}"))?
            })
            .await
        {
            Ok(v) => v.clone(),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "list_module_catalog: the on-disk template walk failed — refusing \
                     rather than reporting an empty catalog, and NOT caching the failure"
                );
                return mcp_error(
                    req_id,
                    -32000,
                    "Could not read the on-disk module catalog, so this listing would \
                     be empty BECAUSE NOBODY COULD LOOK — that is not a statement that \
                     this deployment ships no templates. Retry, and check controller \
                     logs.",
                );
            }
        }
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
            // Installed-only filter: resolved identically to the response
            // field below. `installed` keeps its historical meaning — "this
            // user has their OWN copy" — so a global catalog row that is
            // usable but not personally installed is still excluded here.
            if installed_only {
                let display_name = m
                    .get("display_name")
                    .and_then(|v| v.as_str())
                    .or_else(|| m.get("name").and_then(|v| v.as_str()))
                    .unwrap_or("");
                let install_name = m.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let personal = |n: &str| visible.get(n).map(|v| v.personal).unwrap_or(false);
                if !personal(display_name) && !personal(install_name) {
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
                    // Resolve the module row this catalog entry maps to, over
                    // the caller's FULL visibility (global rows + own copies).
                    let visible_entry = visible.get(display_name)
                        .or_else(|| visible.get(install_name));
                    // `installed` = "I have my own copy", which is what the
                    // flag always meant and what `installed_only` filters on.
                    // It is NOT a usability signal: a global catalog row is
                    // `installed: false` and directly usable.
                    let is_installed = visible_entry.map(|v| v.personal).unwrap_or(false);
                    // The id to pass to add_node_to_workflow, present whenever
                    // ANY visible row backs this entry. Null only means the
                    // catalog directory has no seeded module row yet (its
                    // compile failed, or the seeder has not run) — in which
                    // case install_module_from_catalog IS the next step.
                    let usable_module_id = visible_entry.map(|v| v.id.to_string());
                    let availability = match &usable_module_id {
                        Some(_) if is_installed => "installed",
                        Some(_) => "usable_shared",
                        None => "needs_install",
                    };
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
                        // Back-compat alias of `usable_module_id`. Pre-fix this
                        // was null for every global catalog row, so no caller
                        // can be relying on that null to mean anything.
                        "module_id": usable_module_id,
                        "usable_module_id": usable_module_id,
                        "availability": availability,
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
            "_availability_legend": {
                "usable_module_id": "The module_id to pass to add_node_to_workflow. Present whenever a module row backs this catalog entry — including the shared global row, which needs NO install step.",
                "availability": "installed = you have your own copy, with its own grants and fuel limit (hot_update_module edits it unless it references a registry artifact). usable_shared = the global catalog row is usable as-is via usable_module_id; install only if you want a private copy. needs_install = no module row exists yet, call install_module_from_catalog.",
                "installed": "Whether YOU have your own copy. It is NOT a usability signal — `installed: false` with a non-null usable_module_id means ready to use. This is also what installed_only filters on.",
                "module_id": "Deprecated alias of usable_module_id.",
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

/// The catalog template, returned ONLY when it would rebuild exactly the
/// source the installed copy holds (2026-09-30). Taking the template by value
/// means the restore can compile nothing but what this returns: a copy that
/// is behind the catalog, or was edited in place, would otherwise be replaced
/// by different code under the same module id.
pub(crate) fn rebuildable_template(
    stored_source: &str,
    template: talos_compilation::CatalogTemplate,
) -> Result<talos_compilation::CatalogTemplate, &'static str> {
    if stored_source == template.source() {
        Ok(template)
    } else {
        Err(
            "your copy's source differs from the catalog template (it is behind the catalog, \
             or was edited in place), so restore will not rebuild it from the template. \
             Reinstall with install_module_from_catalog to take the catalog version (your \
             grants are kept), or recompile your own source with hot_update_module(module_id).",
        )
    }
}

/// The `content_hash` an installed catalog module stores: SHA-256 of the
/// compiled WASM, lowercase hex. ONE home for install and restore, so the
/// two cannot describe the same bytes differently.
pub(crate) fn catalog_wasm_content_hash(wasm: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(wasm))
}

/// Normalise a template name or display name to its slug form
/// (lowercase, non-alphanumerics folded to single hyphens).
fn catalog_slug_of(s: &str) -> String {
    s.to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

/// Longest catalog key accepted. The longest display name shipped is 32 bytes.
const MAX_CATALOG_KEY_BYTES: usize = 128;

/// The catalog key a caller passed to `install_module_from_catalog`, trimmed.
///
/// Either form a report shows is accepted: the slug (`gmail-list-messages`)
/// or the display name (`Gmail: List Messages`, `Echo/Debug`). Until
/// 2026-10-01 anything but ASCII alphanumerics and hyphens was refused here
/// as "Invalid module name", before the resolver — which has always matched
/// display names — was reached; every report names a copy by its display
/// name, so the name on screen was the one the tool rejected.
///
/// This check bounds the key, keeps control characters out of the log lines
/// and error text that echo it, and refuses a key shaped like a path. The
/// path-safety control itself is [`resolve_catalog_template_dir`], which
/// never joins a key onto the catalog path unless it is one safe component.
fn catalog_template_key(raw: &str) -> Result<&str, String> {
    let key = talos_validation::validate_display_name("name", raw, MAX_CATALOG_KEY_BYTES)
        .map_err(|e| e.message)?;
    // No template is named like a path. The resolver would not leave the
    // catalog for such a key, but it matches by slug, so `./llm-inference/..`
    // would quietly install LLM Inference; say no instead.
    if key.contains("..") || key.starts_with(['/', '\\', '.']) {
        return Err("Invalid module name: it looks like a path, not a template name".to_string());
    }
    Ok(key)
}

/// A key that is safe to join onto the catalog directory as ONE path
/// component: non-empty ASCII alphanumerics and hyphens, not starting with a
/// hyphen. Anything else (a display name with spaces, `..`, `/`) is never
/// joined; it can only be matched against the directories that exist.
fn is_safe_template_dir_name(key: &str) -> bool {
    !key.is_empty()
        && !key.starts_with('-')
        && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// The ONE resolver from a template key — a catalog directory name (slug) or
/// a template's `display_name` — to its directory under `catalog_dir`.
/// Shared by `install_module_from_catalog` and `restore_pinned_modules`
/// (2026-09-30): restore used to join the pin's DISPLAY name straight onto
/// the path (`module-templates/LLM Inference`), which exists for no
/// template, and would have joined a caller-supplied name unchecked.
///
/// An exact directory is tried only for a safe single-component key; then
/// the direct children are scanned for a `talos.json` whose `display_name`
/// has the same slug. The key is never used to build any other path.
pub(crate) fn resolve_catalog_template_dir(
    catalog_dir: &std::path::Path,
    key: &str,
) -> Option<std::path::PathBuf> {
    if is_safe_template_dir_name(key) {
        let exact = catalog_dir.join(key);
        if exact.join("talos.json").exists() {
            return Some(exact);
        }
    }
    let target = catalog_slug_of(key);
    if target.is_empty() {
        return None;
    }
    std::fs::read_dir(catalog_dir)
        .ok()?
        .flatten()
        .find(|entry| {
            std::fs::read(entry.path().join("talos.json"))
                .ok()
                .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                .and_then(|m| {
                    m.get("display_name")
                        .and_then(|v| v.as_str())
                        .map(catalog_slug_of)
                })
                .is_some_and(|slug| slug == target)
        })
        .map(|e| e.path())
}

/// Where an install's catalog entry came from.
enum InstallSource {
    /// A shared catalog row that names a registry artifact.
    Registry(talos_module_repository::SharedRegistryEntry),
    /// A template baked into the controller image.
    Disk {
        template: talos_compilation::CatalogTemplate,
        module_dir: std::path::PathBuf,
    },
}

/// A registry catalog row in the shape a template's `talos.json` has, so the
/// install's grant logic and the catalog listing read one shape whichever
/// source the entry came from. `name` is the slug and `display_name` the
/// row's name, as in a manifest.
pub(crate) fn registry_entry_manifest(
    entry: &talos_module_repository::SharedRegistryEntry,
) -> serde_json::Value {
    serde_json::json!({
        "name": entry.catalog_slug.as_deref().unwrap_or(&entry.name),
        "display_name": entry.name,
        "description": entry.description.as_deref().unwrap_or(""),
        "category": entry.category.as_deref().unwrap_or("catalog"),
        "capability_world": entry.capability_world,
        "allowed_hosts": entry.allowed_hosts,
        "allowed_methods": entry.allowed_methods,
        "allowed_secrets": entry.allowed_secrets,
        // The listing reads the manifest's older key for the same list.
        "requires_secrets": entry.allowed_secrets,
        "requires_approval_for": entry.requires_approval_for,
        "config_schema": entry.config_schema,
        "source": "registry",
    })
}

/// The catalog a registry-mode deployment offers: its shared registry rows
/// in manifest shape, ordered by category then slug — the order the listing
/// of the image's templates uses.
pub(crate) fn registry_catalog_items(
    entries: &[talos_module_repository::SharedRegistryEntry],
) -> Vec<serde_json::Value> {
    let mut items: Vec<serde_json::Value> = entries.iter().map(registry_entry_manifest).collect();
    let key = |item: &serde_json::Value, field: &str, absent: &str| {
        item.get(field)
            .and_then(|v| v.as_str())
            .unwrap_or(absent)
            .to_string()
    };
    items.sort_by(|a, b| {
        key(a, "category", "Uncategorized")
            .cmp(&key(b, "category", "Uncategorized"))
            .then(key(a, "name", "").cmp(&key(b, "name", "")))
    });
    items
}

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

    // The key is a slug or a display name. Bounded and free of control
    // characters here; `resolve_catalog_template_dir` is what keeps it inside
    // the catalog (it never joins a key that is not one safe path component).
    let name = match catalog_template_key(name) {
        Ok(key) => key,
        Err(message) => return mcp_error(req_id, -32602, &message),
    };

    // A caller's fuel budget that cannot be read is refused here, from the
    // arguments alone, before the catalog or the database is consulted.
    let budget_max_fuel: Option<i64> = match crate::sandbox::parse_fuel_budget_arg(args) {
        Ok(limit) => limit.map(|v| v as i64),
        Err(reason) => return mcp_error(req_id, -32602, &reason),
    };

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

    // What the key names. A shared catalog row that names a registry
    // artifact IS the catalog entry: the registry sync wrote it from the
    // published manifest, and the copy made here references the same signed
    // artifact — nothing is compiled. Only when no such row matches is the
    // template baked into the image read, as before. A lookup that FAILS is
    // refused: falling through to the image would install different code
    // from the one the catalog offers.
    let source = match state.module_repo.find_shared_registry_entry(name).await {
        Ok(Some(entry)) => InstallSource::Registry(entry),
        Err(e) => {
            tracing::error!(error = %e, "install_module_from_catalog: registry catalog read failed");
            return mcp_error(
                req_id,
                -32000,
                "Could not read the module catalog (database error), so the install was \
                 refused rather than guess which module the name refers to. Retry.",
            );
        }
        Ok(None) => {
            let catalog_dir = std::path::Path::new("/app/module-templates");

            // Resolve module directory: exact slug match first, then fuzzy display_name match.
            // This handles cases where the tool name ("http-request-with-retry") differs from
            // the directory name ("http-retry") but matches the talos.json display_name.
            let module_dir = match resolve_catalog_template_dir(catalog_dir, name) {
                Some(dir) => dir,
                None => {
                    return mcp_error(
                        req_id,
                        -32000,
                        &format!(
                            "Module '{}' not found in catalog: it matches no template's slug (e.g. 'http-request') \
                             and no template's display name (e.g. 'HTTP Request'). Use list_module_catalog to see \
                             available modules.",
                            name
                        ),
                    )
                }
            };

            // Metadata AND source come from the ONE catalog reader
            // (`talos_compilation::CatalogTemplate`) so this path and the disk
            // seeder cannot disagree about which source they compile or which
            // dependencies they declare. Error strings preserved verbatim.
            let template = match talos_compilation::CatalogTemplate::load(&module_dir) {
                Ok(t) => t,
                Err(talos_compilation::CatalogTemplateError::ReadManifest(e)) => {
                    return mcp_error(
                        req_id,
                        -32000,
                        &format!("Failed to read talos.json for '{}': {}", name, e),
                    )
                }
                Err(talos_compilation::CatalogTemplateError::ParseManifest(e)) => {
                    return mcp_error(
                        req_id,
                        -32000,
                        &format!("Failed to parse talos.json for '{}': {}", name, e),
                    )
                }
                Err(talos_compilation::CatalogTemplateError::ReadSource(_)) => {
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
            InstallSource::Disk {
                template,
                module_dir,
            }
        }
    };
    let meta = match &source {
        InstallSource::Registry(entry) => registry_entry_manifest(entry),
        InstallSource::Disk { template, .. } => template.manifest().clone(),
    };
    let rust_code = match &source {
        InstallSource::Registry(_) => String::new(),
        InstallSource::Disk { template, .. } => template.source().to_string(),
    };
    // The catalog slug the copy records: the registry row's, or the resolved
    // template DIR — stable under display-name renames (DX #14).
    let catalog_slug: Option<String> = match &source {
        InstallSource::Registry(entry) => entry.catalog_slug.clone(),
        InstallSource::Disk { module_dir, .. } => module_dir
            .file_name()
            .and_then(|f| f.to_str())
            .map(str::to_string),
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

    // Role RBAC gate (2026-09-10): the module this installs runs at
    // `capability_world` — defaulting to `automation-node`, the WIDEST
    // compilable world, when the manifest declares none. `compile_custom_sandbox`
    // refuses a role lacking that capability; this surface refused nothing, so
    // an `["http"]`-role agent could install and then run an automation-node
    // module. One shared predicate, same refusal.
    if let Err(resp) = crate::sandbox::require_agent_role_permits_world(
        &req_id,
        &agent,
        capability_world,
        "install a catalog module for",
    ) {
        return resp;
    }

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
    let template_methods: Vec<String> = talos_json_methods.clone();
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

    // The template's own grant: requires_secrets (legacy) ∪ talos.json
    // allowed_secrets. This is the CEILING for the installed module.
    let template_secrets: Vec<String> = {
        let mut merged = catalog_secrets;
        for s in talos_json_secrets {
            if !merged.contains(&s) {
                merged.push(s);
            }
        }
        merged
    };
    // Principle of least privilege: a caller-supplied `allowed_secrets` may
    // only NARROW the template's list, never replace it. Pre-2026-09-10 the
    // caller's list was used VERBATIM ("use ONLY the caller's list"), which
    // reads as least-privilege but is its inverse: the template author's grant
    // is the only review any of these vault paths ever had, and a caller who
    // passed `["*"]` or a path the template never named got a module that
    // could resolve it. The installed grant is therefore the INTERSECTION of
    // the caller's request with the template's grant, via the one allowlist
    // matcher both controller and worker use (`vault_path_permitted`), so a
    // caller may narrow with a glob the template's exact paths fall under but
    // can never name a path the template did not. Paths the caller asked for
    // and did not get are reported below rather than silently dropped.
    //
    // Without a caller override the template's grant is installed as-is,
    // which preserves backwards-compatible behaviour for plain reinstalls.
    let (allowed_secrets, secrets_not_granted): (Vec<String>, Vec<String>) =
        if caller_provided_allowed_secrets {
            narrow_secret_grant(&template_secrets, &caller_secrets)
        } else {
            (template_secrets, Vec::new())
        };
    let requires_approval_for =
        crate::utils::json_string_array_field(&meta, "requires_approval_for");
    let display_name = args
        .get("display_name")
        .and_then(|v| v.as_str())
        .or_else(|| meta.get("display_name").and_then(|v| v.as_str()))
        .unwrap_or(name)
        .to_string();

    // REINSTALL carries the installed copy's grants (2026-09-29). The write
    // below lands on the existing `(user_id, name)` row and overwrites all
    // three grant columns, so without this a plain reinstall silently put the
    // template's full grant back over an operator's narrowing — measured
    // live: three Gmail copies pinned to one account's token would have
    // widened to `oauth/gmail/*`. A grant the caller passes explicitly still
    // follows today's rule; an omitted one is carried, bounded by the NEW
    // template's grant (never wider than either), and whatever the template
    // no longer grants is dropped and reported. The stored grant being
    // unreadable REFUSES the reinstall: proceeding is exactly the widening.
    let caller_provided_allowed_methods = args.get("allowed_methods").is_some();
    let installed_copy = match state
        .module_repo
        .get_user_module_grants(user_id, &display_name)
        .await
    {
        Ok(g) => g,
        Err(e) => {
            tracing::error!(error = %e, module = %display_name, "install_module_from_catalog: could not read the installed copy's grants");
            return mcp_error(
                req_id,
                -32000,
                "Could not read the grants of your installed copy of this module, so the \
                 reinstall was refused rather than risk widening them. Retry.",
            );
        }
    };
    let InstallGrants {
        hosts: allowed_hosts,
        methods: allowed_methods,
        secrets: allowed_secrets,
        not_carried: grants_not_carried,
        kept_as_owner_added: grants_kept_as_owner_added,
        owner_added,
    } = grants_for_install(
        installed_copy.as_ref(),
        allowed_hosts,
        allowed_methods,
        allowed_secrets,
        caller_provided_allowed_methods,
        caller_provided_allowed_secrets,
        &template_methods,
    );
    // DRY RUN: every grant decision is made above this line, before the
    // compile and the write. Answer what the install WOULD store and stop —
    // nothing is compiled, written or recorded. Until 2026-10-01 the only way
    // to learn that a reinstall would drop a grant was to run it.
    // The fuel limit a first install would write — caller's `fuel_budget`,
    // else the template's `recommended_fuel`, else the baseline (~2.2M; the
    // hardcoded 2M left LLM-backed templates fuel-starved, issue #381).
    // Resolved here, from the arguments and the template metadata alone, so
    // the dry run and the install report the same thing.
    //
    // Both budgets go through the one strict reader. The caller's was read
    // at the top of the handler. A template whose `recommended_fuel` cannot
    // be read is a defect in the catalog: the install is refused rather than
    // sized by defaults nobody chose, and the refusal says a `fuel_budget` of
    // the caller's own installs it anyway.
    let fuel_explicit = budget_max_fuel.is_some();
    let template_fuel = match &source {
        // The catalog writer resolved this from the published manifest.
        InstallSource::Registry(entry) => Ok(Some(entry.max_fuel.max(0) as u64)),
        InstallSource::Disk { .. } => talos_compilation::recommended_max_fuel(&meta),
    };
    let template_max_fuel: i64 = match template_fuel {
        Ok(Some(limit)) => limit as i64,
        Ok(None) => talos_compilation::scaffold::compute_max_fuel(10, 2000, 2.0) as i64,
        Err(reason) if fuel_explicit => {
            tracing::warn!(template = %display_name, %reason, "catalog template's recommended_fuel cannot be read; the caller's fuel_budget is used");
            talos_compilation::scaffold::compute_max_fuel(10, 2000, 2.0) as i64
        }
        Err(reason) => {
            tracing::error!(template = %display_name, %reason, "catalog template's recommended_fuel cannot be read");
            return mcp_error(
                req_id,
                -32000,
                &format!(
                    "The catalog template '{display_name}' declares a recommended_fuel that cannot be read \
                     ({reason}). Pass a fuel_budget of your own to install it."
                ),
            );
        }
    };
    let offered_max_fuel: i64 = budget_max_fuel.unwrap_or(template_max_fuel);
    match crate::utils::validate_optional_bool(args, "dry_run", false, &req_id) {
        Ok(false) => {}
        Ok(true) => {
            let report = install_dry_run_report(
                &display_name,
                capability_world,
                installed_copy.as_ref(),
                &InstallGrants {
                    hosts: allowed_hosts,
                    methods: allowed_methods,
                    secrets: allowed_secrets,
                    not_carried: grants_not_carried,
                    kept_as_owner_added: grants_kept_as_owner_added,
                    owner_added,
                },
                &secrets_not_granted,
                install_fuel_report(
                    installed_copy.as_ref().map(|c| c.max_fuel),
                    offered_max_fuel,
                    template_max_fuel,
                    fuel_explicit,
                ),
            );
            return mcp_text(
                req_id,
                &serde_json::to_string_pretty(&report).unwrap_or_default(),
            );
        }
        Err(resp) => return resp,
    }
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

    // What the copy runs. A registry entry is referenced; a template from the
    // image is compiled. The template's declared `dependencies` ride along
    // inside `CatalogTemplate`, so this path cannot lose them the way the
    // seeder, the OCI publisher and restore_pinned_modules all did. Templates
    // are author-signed; the compiler still gates deps through the allowlist
    // (validate_dependencies) inside create_workspace.
    let compiled: Option<(Vec<u8>, String)> = match &source {
        InstallSource::Registry(_) => None,
        InstallSource::Disk {
            template,
            module_dir,
        } => {
            // The resolved dir name is the Cargo package name — always a valid
            // slug (e.g. "stripe-create-customer") even when the input was a
            // fuzzy-matched variant like "stripe--create-customer" which Cargo
            // would reject as an invalid label.
            let compile_name = module_dir
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(name);
            let job_id = uuid::Uuid::new_v4();
            match state
                .compiler
                .compile_catalog_template(user_id, job_id, compile_name, template)
                .await
            {
                Ok(res) if res.success => match res.wasm_bytes {
                    Some(bytes) => {
                        let hash = catalog_wasm_content_hash(&bytes);
                        Some((bytes, hash))
                    }
                    None => {
                        return mcp_error(
                            req_id,
                            -32603,
                            "Compilation succeeded but produced no WASM output",
                        )
                    }
                },
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
                    return mcp_error(
                        req_id,
                        -32000,
                        &format!("Compilation failed for '{}':\n{}", name, errors.join("\n")),
                    );
                }
                Err(e) => {
                    // 2026-09-10: chain logged (it can carry host paths and cargo's
                    // stderr), generic message returned — the sentence
                    // `hot_update_module` already uses.
                    tracing::error!(error = %format!("{e:#}"), "compile_module: compilation service error");
                    return mcp_error(
                        req_id,
                        -32000,
                        talos_compilation::caller_facing_service_error(&e),
                    );
                }
            }
        }
    };
    let artifact = match (&source, &compiled) {
        (InstallSource::Registry(entry), _) => {
            talos_module_repository::InstalledArtifact::Registry {
                oci_url: &entry.oci_url,
            }
        }
        (InstallSource::Disk { template, .. }, Some((bytes, hash))) => {
            talos_module_repository::InstalledArtifact::Compiled {
                wasm_bytes: bytes,
                content_hash: hash,
                source_code: &rust_code,
                // The crates it was compiled with, so a later hot_update of
                // the installed copy can rebuild it without restating them.
                dependencies: template.dependencies(),
            }
        }
        (InstallSource::Disk { .. }, None) => {
            return mcp_error(
                req_id,
                -32603,
                "Compilation succeeded but produced no WASM output",
            )
        }
    };
    let from_registry = matches!(source, InstallSource::Registry(_));

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
    // On RE-install the existing row's max_fuel is PRESERVED unless
    // the caller explicitly passed fuel_budget (fuel_explicit below) —
    // template/baseline values only apply to fresh installs. Mirrors
    // r236's hot_update fuel preservation; the reinstall path was the
    // unswept sibling (live bite 2026-07-17: tuned 10M silently reset
    // to 1.38M auto-calc).
    // (`fuel_explicit` / `offered_max_fuel` are resolved above the
    // dry-run branch.)
    let max_fuel: i64 = offered_max_fuel;

    let install_result = match state
        .module_repo
        .install_catalog_copy(
            agent.user_id,
            &display_name,
            cw_short,
            artifact,
            max_fuel,
            &allowed_hosts,
            &allowed_methods,
            &allowed_secrets,
            &requires_approval_for,
            &config_schema,
            catalog_slug.as_deref(),
            fuel_explicit,
            &owner_added,
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
                if from_registry {
                    "Failed to save the installed module"
                } else {
                    "Compilation succeeded but failed to save module"
                },
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
        from_registry,
        "Installed module from catalog (modules-only write)"
    );

    // Pin the module if requested
    // MCP-270 (2026-05-10): direction-class wrong-type rejection.
    let pin_module = match crate::utils::validate_optional_bool(args, "pin_module", false, &req_id)
    {
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
    let setup_required = grant_empty || (!has_wildcard_grant && !stored_allowed_secrets.is_empty());
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
        // A compiled copy: the sha256 of its bytes. A registry copy
        // holds no bytes; `content_hash` then names the artifact.
        "wasm_sha256": if from_registry { serde_json::Value::Null } else { serde_json::json!(stored_content_hash) },
        "content_hash": stored_content_hash,
        "compiled_at": stored_compiled_at.to_rfc3339(),
        "bytes_changed": bytes_changed,
        "source": if from_registry { "registry" } else { "compiled" },
        // What the row carries now, read back from the write: a
        // reinstall keeps the copy's own limit unless `fuel_budget`
        // was passed, so the limit offered is not always the one stored.
        "fuel": install_fuel_report(
            installed_copy.as_ref().map(|_| install_result.max_fuel),
            if installed_copy.is_some() { offered_max_fuel } else { install_result.max_fuel },
            template_max_fuel,
            fuel_explicit,
        ),
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
    resp["grants_carried_from_installed_copy"] = serde_json::json!(installed_copy.is_some());
    if !grants_not_carried.is_empty() {
        resp["grants_not_carried"] = serde_json::Value::Object(grants_not_carried);
        resp["grants_not_carried_note"] = serde_json::json!(
            "Your installed copy held these grants, the new template does not grant them, \
                     and they are not recorded as ones you added, so they were not carried onto \
                     the reinstall. Set them again with update_module_hosts / update_module_methods \
                     / update_module_secrets: a grant you add that way is kept by later reinstalls."
        );
    }
    if !grants_kept_as_owner_added.is_empty() {
        resp["grants_kept_as_owner_added"] = serde_json::Value::Object(grants_kept_as_owner_added);
        resp["grants_kept_as_owner_added_note"] = serde_json::json!(
            "The template does not grant these. They were kept because you added them to \
                     your copy; remove one with the update_module_* tool that set it."
        );
    }
    if !secrets_not_granted.is_empty() {
        resp["secrets_not_granted"] = serde_json::json!(secrets_not_granted);
        resp["secrets_not_granted_note"] = serde_json::json!(
            "These caller-supplied allowed_secrets paths are OUTSIDE the template's own \
                     grant and were not installed. A caller may only NARROW a template's secret \
                     grant, never widen it; the template author's list is the ceiling."
        );
    }
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&resp).unwrap_or_default(),
    )
}

// ── restore_pinned_modules ────────────────────────────────────────────────────

async fn handle_restore_pinned_modules(
    req_id: Option<serde_json::Value>,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = match agent.user_id {
        Some(uid) => uid,
        None => return mcp_denied(req_id, -32000, "User identity required"),
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

        // Rebuild THIS copy (2026-09-30). The pin stores the display name, so
        // the copy is found by (user, name), and its template by the copy's
        // catalog slug through the ONE resolver — never by joining the name
        // onto a path (`module-templates/LLM Inference` exists for no
        // template, and a pinned name is caller-supplied).
        let target = match state
            .module_repo
            .get_pinned_restore_target(user_id, &module_name)
            .await
        {
            Ok(Some(t)) => t,
            Ok(None) => {
                failed.push(serde_json::json!({
                    "module": module_name,
                    "reason": "no module is installed under this name for your account — \
                               run install_module_from_catalog first, then re-run restore_pinned_modules"
                }));
                continue;
            }
            Err(e) => {
                tracing::error!(module = %module_name, "restore_pinned_modules: target read failed: {:#}", e);
                failed.push(serde_json::json!({
                    "module": module_name,
                    "reason": "could not read your installed copy; nothing was changed — retry"
                }));
                continue;
            }
        };
        let key = target.catalog_slug.as_deref().unwrap_or(&module_name);
        let Some(module_dir) = resolve_catalog_template_dir(catalog_dir, key) else {
            failed.push(serde_json::json!({
                "module": module_name,
                "reason": format!("no catalog template matches '{key}' — it may have been removed from the catalog")
            }));
            continue;
        };
        // The ONE catalog reader, so the rebuild gets the template's declared
        // dependencies exactly as an install does.
        let template = match talos_compilation::CatalogTemplate::load(&module_dir) {
            Ok(t) => t,
            Err(e) => {
                failed.push(serde_json::json!({
                    "module": module_name,
                    "reason": format!("catalog template could not be read: {e}")
                }));
                continue;
            }
        };
        // A restore rebuilds the SAME source the copy holds; the template is
        // only usable past this point if the sources match.
        let template = match rebuildable_template(&target.source_code, template) {
            Ok(t) => t,
            Err(reason) => {
                failed.push(serde_json::json!({
                    "module": module_name,
                    "module_id": target.module_id,
                    "reason": reason,
                }));
                continue;
            }
        };

        let compile_name = module_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(key)
            .to_string();
        let job_id = uuid::Uuid::new_v4();
        let compilation = state
            .compiler
            .compile_catalog_template(user_id, job_id, &compile_name, &template)
            .await;

        match compilation {
            Ok(res) if res.success => {
                let Some(wasm_bytes) = res.wasm_bytes else {
                    failed.push(serde_json::json!({
                        "module": module_name,
                        "reason": "compilation produced no WASM output"
                    }));
                    continue;
                };
                // The hash that describes the bytes written, as an install
                // computes it; the old writer left the previous hash in place.
                let content_hash = catalog_wasm_content_hash(&wasm_bytes);
                match state
                    .module_repo
                    .restore_missing_module_wasm(
                        target.module_id,
                        user_id,
                        &wasm_bytes,
                        &content_hash,
                    )
                    .await
                {
                    Ok(0) => already_present.push(module_name.clone()),
                    Ok(_) => restored.push(module_name.clone()),
                    Err(e) => {
                        tracing::error!(module = %module_name, "restore_pinned_modules write failed: {:#}", e);
                        failed.push(serde_json::json!({
                            "module": module_name,
                            "reason": "compilation succeeded but failed to save"
                        }));
                    }
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
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    // Every lookup below matches on a CALLER-SUPPLIED name or capability
    // keyword, so each one needs the authenticated identity to scope by.
    // Pre-fix this handler took no `agent` at all — which is why the four
    // repository calls could not have been scoped even if someone had
    // noticed: the tenant was not in the room.
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
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
            .lookup_template_by_name_ci(target_name, user_id)
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

        // Try pg_trgm similarity search first; fall back to category +
        // alphabetical. The FALLBACK is the honest part of this shape — a
        // deployment without the `pg_trgm` extension really does have a
        // second, worse way to answer. What was not honest was the fallback's
        // OWN failure: `.unwrap_or_default()` rendered `count: 0`,
        // `alternatives: []` and a tip pointing at `list_module_catalog`, i.e.
        // "there is nothing else like this module", from two queries that
        // neither of them answered. When BOTH sources fail there is no answer
        // left to give, so the tool refuses.
        let (rows, search_method) = match state
            .module_repo
            .find_template_alternatives_trgm(
                target_id,
                &search_text,
                &target_category,
                user_id,
                limit,
            )
            .await
        {
            Ok(rows) => (rows, "trigram"),
            Err(trgm_err) => {
                // pg_trgm not available — fall back to category-priority ordering
                match state
                    .module_repo
                    .find_template_alternatives_by_category(
                        target_id,
                        &target_category,
                        user_id,
                        limit,
                    )
                    .await
                {
                    Ok(fallback) => (fallback, "category"),
                    Err(e) => {
                        tracing::error!(
                            module_name = %target_name,
                            trigram_error = %trgm_err,
                            error = %e,
                            "find_module_alternatives: both the trigram search and the category fallback failed"
                        );
                        return mcp_error(
                            req_id,
                            -32000,
                            "Could not search for alternatives — both the similarity search and the \
                             category fallback failed to read. This is a database failure, NOT a \
                             report that no alternative module exists.",
                        );
                    }
                }
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

    // Same three-valued shape as the name-based branch above: an ilike
    // fallback that itself could not be read has no answer, and rendering
    // `count: 0` with "No modules matched" is a determinate negative over two
    // queries that both failed.
    let (rows, search_method) = match state
        .module_repo
        .find_templates_by_capability_trgm(&cap, &ilike_pattern, user_id, limit)
        .await
    {
        Ok(rows) => (rows, "trigram"),
        Err(trgm_err) => {
            match state
                .module_repo
                .find_templates_by_capability_ilike(&ilike_pattern, user_id, limit)
                .await
            {
                Ok(fallback) => (fallback, "ilike"),
                Err(e) => {
                    tracing::error!(
                        capability = %cap,
                        trigram_error = %trgm_err,
                        error = %e,
                        "find_module_alternatives: both the capability trigram search and the ilike fallback failed"
                    );
                    return mcp_error(
                        req_id,
                        -32000,
                        "Could not search the module catalog by capability — both the similarity \
                         search and the ilike fallback failed to read. This is a database failure, \
                         NOT a report that no module provides this capability.",
                    );
                }
            }
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

// ── get_catalog_status (DX #12: catalog-opacity diagnostic) ──────────────────

/// One answer to "why isn't my template showing up?": diffs the three
/// catalog sources of truth (baked disk dir, DB catalog rows, and the
/// list_templates category-filtered view) and names what each MCP surface
/// reads. Deliberately UNCACHED disk read — a diagnostic must report disk
/// truth now, not the boot-time CATALOG_CACHE snapshot.
/// The `installed_copies` block of `get_catalog_status`: a count per state
/// and every copy, most urgent first (behind and used, then behind, then the
/// rest). Pure, so the rendering is tested without a database.
pub(crate) fn installed_copies_json(
    rows: &[talos_module_repository::CatalogCopyRow],
) -> serde_json::Value {
    use talos_module_repository::CatalogCopyState as S;
    let urgency = |r: &talos_module_repository::CatalogCopyRow| match S::of(r) {
        S::Behind if r.live_workflows > 0 => 0,
        S::Behind => 1,
        S::Unknown | S::NotInCatalog => 2,
        S::Detached => 3,
        S::Current => 4,
    };
    let mut sorted: Vec<&talos_module_repository::CatalogCopyRow> = rows.iter().collect();
    sorted.sort_by_key(|r| (urgency(r), r.name.clone()));
    let mut counts = serde_json::Map::new();
    for state in [
        S::Current,
        S::Behind,
        S::Detached,
        S::Unknown,
        S::NotInCatalog,
    ] {
        let n = rows.iter().filter(|r| S::of(r) == state).count();
        counts.insert(state.as_str().to_string(), serde_json::json!(n));
    }
    serde_json::json!({
        "counts": counts,
        "copies": sorted.iter().map(|r| serde_json::json!({
            "module_id": r.module_id,
            "name": r.name,
            "catalog_slug": r.catalog_slug,
            "state": S::of(r).as_str(),
            "differs_in": r.differs_in(),
            "live_workflows": r.live_workflows,
            "compiled_at": r.compiled_at.map(|t| t.to_rfc3339()),
            "catalog_updated_at": r.catalog_updated_at.map(|t| t.to_rfc3339()),
        })).collect::<Vec<_>>(),
        "states": {
            "current": "same code, config schema, capability world and approval list as the catalog (code is compared by source for a compiled copy, by registry reference for a copy that references a registry artifact)",
            "behind": "the catalog changed since this copy was installed (differs_in says what: source, artifact, config_schema, capability_world, requires_approval_for; `artifact` = the catalog now names a different registry artifact than the one this copy references); reinstall to take the change",
            "detached": "edited in place (hot_update_module), so differing from the catalog is deliberate",
            "unknown": "the copy was compiled here and the catalog row carries no source (a registry catalog), so its code cannot be compared",
            "not_in_catalog": "no catalog template maps to this copy any more",
        },
    })
}

/// The compact `catalog_drift` field of `session_start`: how many installed
/// copies are behind the catalog, which of those live workflows use, and
/// where the detail is.
pub(crate) fn catalog_drift_brief(
    rows: &[talos_module_repository::CatalogCopyRow],
) -> serde_json::Value {
    use talos_module_repository::CatalogCopyState as S;
    let behind: Vec<&talos_module_repository::CatalogCopyRow> =
        rows.iter().filter(|r| S::of(r) == S::Behind).collect();
    serde_json::json!({
        "behind": behind.len(),
        "behind_in_use": behind
            .iter()
            .filter(|r| r.live_workflows > 0)
            .map(|r| r.name.as_str())
            .collect::<Vec<_>>(),
        "unknown": rows.iter().filter(|r| S::of(r) == S::Unknown).count(),
        "detail": "get_catalog_status → installed_copies",
    })
}

/// The tip for copies that are BEHIND the catalog, or `None` when none are.
/// Names the copies live workflows use first, and says what a reinstall does
/// to their grants, because that is the question an operator must answer
/// before running it.
pub(crate) fn catalog_drift_tip(
    rows: &[talos_module_repository::CatalogCopyRow],
) -> Option<String> {
    use talos_module_repository::CatalogCopyState as S;
    let behind: Vec<&talos_module_repository::CatalogCopyRow> =
        rows.iter().filter(|r| S::of(r) == S::Behind).collect();
    if behind.is_empty() {
        return None;
    }
    let used: Vec<String> = behind
        .iter()
        .filter(|r| r.live_workflows > 0)
        .map(|r| format!("{} ({} live workflow(s))", r.name, r.live_workflows))
        .collect();
    let unused: Vec<&str> = behind
        .iter()
        .filter(|r| r.live_workflows == 0)
        .map(|r| r.name.as_str())
        .collect();
    let mut tip = format!(
        "{} of your installed catalog module(s) are BEHIND the catalog: the catalog \
         changed after you installed them, and an installed copy is never refreshed, so \
         catalog fixes (security fixes included) are not live in them until you reinstall \
         with install_module_from_catalog. A reinstall keeps the same module id and your \
         copy's allowed_hosts / allowed_methods / allowed_secrets, bounded by the \
         template's grant.",
        behind.len()
    );
    if !used.is_empty() {
        tip.push_str(&format!(" Used by live workflows: {}.", used.join(", ")));
    }
    if !unused.is_empty() {
        tip.push_str(&format!(
            " Not used by any live workflow: {}.",
            unused.join(", ")
        ));
    }
    Some(tip)
}

async fn handle_get_catalog_status(
    req_id: Option<serde_json::Value>,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);

    // Mode: OCI sync owns the DB catalog when TALOS_REGISTRY_URL is set
    // (empty string treated as unset — the MCP-598 footgun).
    let registry_url = talos_config::registry_url();
    let mode = if registry_url.is_some() {
        "oci"
    } else {
        "disk"
    };

    // Every read below is DISCLOSED, not defaulted (2026-09-07) — see the DB
    // half below for the argument. The ledger is opened HERE, above the disk
    // scan, because check 74b fired on that scan the first time this handler
    // adopted `Readings` and it was right to: a `JoinError` from the blocking
    // walk defaulted to an EMPTY template list, which reads as "this image
    // carries no catalog templates" and puts every DB row in
    // `in_db_not_on_disk`. The scan is a filesystem read rather than a query,
    // and it makes the same claim.
    let mut readings = talos_measurement::Readings::new();

    // Disk truth: slug (dir name) + display_name + category per template.
    let catalog_dir = std::path::PathBuf::from("/app/module-templates");
    let dir_exists = catalog_dir.is_dir();
    let disk_read: Option<Vec<(String, String, String)>> = if dir_exists {
        let dir = catalog_dir.clone();
        let scan = tokio::task::spawn_blocking(move || {
            let mut out = Vec::new();
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if !path.is_dir() || !path.join("template.rs").exists() {
                        continue;
                    }
                    let Ok(bytes) = std::fs::read(path.join("talos.json")) else {
                        continue;
                    };
                    let meta: serde_json::Value =
                        serde_json::from_slice(&bytes).unwrap_or(serde_json::json!({}));
                    let slug = path
                        .file_name()
                        .and_then(|f| f.to_str())
                        .unwrap_or_default()
                        .to_string();
                    let display = meta
                        .get("display_name")
                        .or_else(|| meta.get("name"))
                        .and_then(|v| v.as_str())
                        .unwrap_or(&slug)
                        .to_string();
                    let category = meta
                        .get("category")
                        .and_then(|v| v.as_str())
                        .unwrap_or("General")
                        .to_string();
                    out.push((slug, display, category));
                }
            }
            out.sort();
            out
        });
        readings.record("disk", scan.await)
    } else {
        // Not a failure: `dir_exists` is false and the report SAYS so, which is
        // a measured answer about an image with no catalog dir.
        Some(Vec::new())
    };
    let disk: Vec<(String, String, String)> = disk_read.clone().unwrap_or_default();

    // DB catalog rows (name = display_name at seed time, catalog_slug when
    // stamped) + the caller's installed catalog modules.
    //
    // DISCLOSED, not defaulted (2026-09-07). This tool's whole output is a DIFF
    // between disk and the DB, so an unreadable `list_catalog_rows` did not
    // merely blank a field: it made every disk template read as
    // `on_disk_not_in_db` and emitted the tip "N disk template(s) are not in
    // the DB catalog — restart the controller to seed", i.e. specific,
    // actionable, wrong advice about a healthy catalog, computed from a query
    // that never answered. Both halves are now nulled on failure and the diff
    // is suppressed unless BOTH answered.
    //
    // 2026-09-08: this line used to construct a SECOND ledger, which
    // SHADOWED the one built above and threw away the `disk` record with
    // it. The consequence is this file's own subject one level up: a failed
    // disk scan nulled `disk` in the body while the surviving ledger published
    // "complete: every field in this report was measured" — the exact
    // false-completeness claim check 74b exists to prevent, made by the
    // disclosure mechanism itself. 74b cannot see it (it detects a defaulted
    // read beside a ledger, not a ledger discarded by a shadow), and the disk
    // arm needs `/app/module-templates` plus a `spawn_blocking` JoinError, so
    // no test in this workspace can reach it either. ONE ledger per report.
    let db_rows_read = readings.record("db_catalog", state.module_repo.list_catalog_rows().await);
    let db_rows = db_rows_read.clone().unwrap_or_default();
    let installed = readings.record(
        "installed_by_you",
        state.module_repo.list_user_template_names(user_id).await,
    );
    // Your installed copies against the catalog (2026-09-29). A copy is a
    // frozen row that the seeder never refreshes, so a catalog fix is not
    // live until it is reinstalled; nothing reported that before.
    let copies_read = readings.record(
        "installed_copies",
        state.module_repo.list_catalog_copy_drift(user_id).await,
    );

    // Catalog rows that have NO compiled WASM. Until 2026-08-11 the only
    // evidence of this condition was a boot-time WARN whose own text
    // ("keeping existing wasm_bytes") implied there were bytes to keep —
    // there were not. Three shipped templates sat at NULL indefinitely, so
    // every workflow node pointing at one had nothing to dispatch.
    let never_compiled_read = readings.record(
        "never_compiled",
        state.module_repo.list_catalog_rows_without_wasm().await,
    );
    let never_compiled = never_compiled_read.clone().unwrap_or_default();

    // Diff disk ↔ DB. A DB row matches a disk template when its stamped
    // slug equals the dir slug, or (pre-backfill rows) its name equals the
    // template's display_name or slug.
    let db_matches = |slug: &str, display: &str| -> bool {
        db_rows.iter().any(|(name, db_slug, _)| {
            db_slug.as_deref() == Some(slug) || name == display || name == slug
        })
    };
    let on_disk_not_in_db: Vec<&str> = disk
        .iter()
        .filter(|(slug, display, _)| !db_matches(slug, display))
        .map(|(slug, _, _)| slug.as_str())
        .collect();
    let disk_matches = |name: &str, db_slug: Option<&str>| -> bool {
        disk.iter().any(|(slug, display, _)| {
            db_slug == Some(slug.as_str()) || name == display || name == slug
        })
    };
    let in_db_not_on_disk: Vec<&str> = db_rows
        .iter()
        .filter(|(name, db_slug, _)| !disk_matches(name, db_slug.as_deref()))
        .map(|(name, _, _)| name.as_str())
        .collect();

    // list_templates visibility: its default view drops categories outside
    // the platform allowlist (now case-insensitive).
    let hidden_by_category: Vec<serde_json::Value> = db_rows
        .iter()
        .filter(|(_, _, cat)| cat != "workflow_template" && !is_platform_category(cat))
        .map(|(name, _, cat)| serde_json::json!({ "name": name, "category": cat }))
        .collect();
    let visible = db_rows
        .iter()
        .filter(|(_, _, cat)| cat != "workflow_template" && is_platform_category(cat))
        .count();

    let mut tips: Vec<String> = Vec::new();
    if !dir_exists {
        tips.push(
            "module-templates/ is absent from this image — disk seeding and \
             list_module_catalog/install_module_from_catalog have nothing to read"
                .to_string(),
        );
    }
    // Gated on the DB read having ANSWERED: with `db_rows` unreadable every
    // disk template lands in `on_disk_not_in_db` and this tip would tell the
    // operator to restart a controller whose catalog is fine.
    if mode == "disk"
        && db_rows_read.is_some()
        && disk_read.is_some()
        && !on_disk_not_in_db.is_empty()
    {
        tips.push(format!(
            "{} disk template(s) are not in the DB catalog — seeding runs at \
             every controller boot (idempotent upsert); restart the controller \
             (or rebuild the image if the templates are newer than it) to seed: {}",
            on_disk_not_in_db.len(),
            on_disk_not_in_db.join(", ")
        ));
    }
    if mode == "oci" {
        tips.push(
            "OCI mode: the DB catalog is owned by the registry sync loop; \
             list_module_catalog and install still read the BAKED DISK templates, \
             so their listing can diverge from the DB"
                .to_string(),
        );
    }
    if db_rows_read.is_some() && !hidden_by_category.is_empty() {
        tips.push(format!(
            "{} seeded template(s) are hidden from list_templates' default view \
             by the platform-category allowlist — pass include_sandboxes: true \
             to see them",
            hidden_by_category.len()
        ));
    }
    if never_compiled_read.is_some() && !never_compiled.is_empty() {
        // The repository query excludes rows carrying an `oci_url`, so this
        // means the same thing in both modes: neither local bytes nor a
        // registry reference. The REMEDY differs, though — in OCI mode there
        // is no disk seeder and no local compile, so the disk-mode advice
        // below would send an operator hunting a log line that cannot exist.
        // (Before 2026-08-11 the query had no `oci_url` predicate at all and
        // this tip fired on EVERY row of a healthy OCI cluster; the adjacent
        // `on_disk_not_in_db` tip was already `mode == "disk"`-gated and this
        // one was not.)
        let cause = if mode == "disk" {
            "The seeder's background compile failed for them at every \
             controller boot. Check the controller log for 'Background \
             compilation failed' naming each one; the usual cause is a crate \
             used in template.rs that talos.json's `dependencies` does not \
             declare (talos.json is the only declaration the runtime reads)."
        } else {
            "In OCI mode nothing compiles these locally — a row with no WASM \
             and no oci_url is one the registry sync wrote without a registry \
             reference, so start at the sync loop's logs and the published \
             `_index` artifact rather than at any compiler output."
        };
        tips.push(format!(
            "{} catalog template(s) have NO compiled WASM and CANNOT RUN — {} Names: {}",
            never_compiled.len(),
            cause,
            never_compiled
                .iter()
                .map(|(n, _)| n.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    if let Some(tip) = copies_read.as_deref().and_then(catalog_drift_tip) {
        tips.push(tip);
    }

    let report = serde_json::json!({
        "mode": mode,
        "registry_url_set": registry_url.is_some(),
        "module_compilation": module_compilation_report(state.compiler.compilation_enabled()),
        "disk": disk_read.as_ref().map(|d| serde_json::json!({
            "dir_exists": dir_exists,
            "template_count": d.len(),
            "slugs": d.iter().map(|(s, _, _)| s.as_str()).collect::<Vec<_>>(),
        })),
        "db_catalog": db_rows_read.as_ref().map(|rows| serde_json::json!({
            "row_count": rows.len(),
            "list_templates_visible": visible,
            "hidden_by_category": hidden_by_category,
            // Seeded but unbuildable. A row here is strictly worse than a
            // missing row: it appears in list_templates and in the dynamic
            // tool surface, and fails only when something tries to run it.
            "never_compiled": never_compiled_read.as_ref().map(|nc| nc
                .iter()
                .map(|(name, slug)| serde_json::json!({ "name": name, "catalog_slug": slug }))
                .collect::<Vec<_>>()),
        })),
        // The diff is a statement about BOTH halves, so it is null unless both
        // halves were read — an "on disk but not in the DB" list computed
        // against a DB nobody could read is not a partial answer, it is a wrong
        // one.
        "diff": db_rows_read.as_ref().zip(disk_read.as_ref()).map(|_| serde_json::json!({
            "on_disk_not_in_db": on_disk_not_in_db,
            "in_db_not_on_disk": in_db_not_on_disk,
        })),
        "installed_by_you": installed.as_ref().map(|i| i.len()),
        // `null` when the read failed — never an empty list, which would
        // read as "nothing is behind".
        "installed_copies": copies_read.as_deref().map(installed_copies_json),
        "surfaces": catalog_surfaces(registry_url.is_some()),
        "seeding": "Disk seeding runs at EVERY controller boot as an idempotent upsert into the modules table; it is skipped only when TALOS_REGISTRY_URL is set (OCI owns the catalog) or module-templates/ is missing.",
        "tips": tips,
    });
    let mut report = report;
    readings.attach(&mut report);
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&report).unwrap_or_default(),
    )
}

/// What each catalog surface reads, by source-of-truth mode.
pub(crate) fn catalog_surfaces(registry_mode: bool) -> serde_json::Value {
    if registry_mode {
        serde_json::json!({
            "list_templates": "DB modules table (kind='catalog'); default view filters to platform categories",
            "list_module_catalog": "DB shared catalog rows that name a registry artifact (written by the registry sync)",
            "install_module_from_catalog": "the shared catalog row: your copy references the same signed registry artifact with your grants; nothing is compiled",
        })
    } else {
        serde_json::json!({
            "list_templates": "DB modules table (kind='catalog'); default view filters to platform categories",
            "list_module_catalog": "baked disk dir /app/module-templates (cached per process)",
            "install_module_from_catalog": "baked disk dir (compiles template.rs on install)",
        })
    }
}

/// What `get_catalog_status` and `get_platform_info` say about the compile
/// switch (`TALOS_MODULE_COMPILATION`). One wording for both.
pub(crate) fn module_compilation_report(enabled: bool) -> serde_json::Value {
    if enabled {
        serde_json::json!({
            "enabled": true,
            "note": "Modules can be built from source on this deployment (compile, lint, \
                     hot update, catalog install).",
        })
    } else {
        serde_json::json!({
            "enabled": false,
            "note": "Module compilation is turned off (TALOS_MODULE_COMPILATION=false). \
                     Nothing is built from source: compile_custom_sandbox, lint_sandbox, \
                     hot_update_module, run_sandbox, compile_template, scratch sessions and \
                     inline rust_code are refused. Workflows use the catalog modules the \
                     registry sync provides; install_module_from_catalog makes your own copy \
                     of one (it references the registry artifact and compiles nothing).",
        })
    }
}

#[cfg(test)]
mod config_schema_projection_tests {
    use super::project_config_schema;

    /// The whole point of the projection: `{}` (what every hand-compiled
    /// module row carries) must NOT read as "takes no config".
    #[test]
    fn empty_object_is_not_declared_not_declared_empty() {
        let p = project_config_schema(Some(&serde_json::json!({})));
        assert_eq!(p["config_schema_status"], "not_declared");
        assert!(p["config_schema"].is_null());
        assert!(p["config_keys"].is_null());
        assert!(!p["config_schema_note"].as_str().unwrap().is_empty());
    }

    #[test]
    fn absent_schema_is_not_declared() {
        let p = project_config_schema(None);
        assert_eq!(p["config_schema_status"], "not_declared");
        assert!(p["config_keys"].is_null());
    }

    /// A schema that explicitly declares an EMPTY property set is a real
    /// statement — "this module takes no config" — and must be legible as one.
    #[test]
    fn explicit_empty_properties_is_declared_empty() {
        let p = project_config_schema(Some(&serde_json::json!({
            "type": "object", "properties": {}
        })));
        assert_eq!(p["config_schema_status"], "declared_empty");
        assert_eq!(p["config_keys"], serde_json::json!([]));
        assert_eq!(p["required_config_keys"], serde_json::json!([]));
    }

    /// The catalog case — modelled on the live `HTTP Request` row, which is
    /// where the reported friction started ("missing required config key").
    #[test]
    fn declared_schema_surfaces_keys_and_requiredness() {
        let p = project_config_schema(Some(&serde_json::json!({
            "type": "object",
            "required": ["URL"],
            "properties": {
                "URL": { "type": "string" },
                "METHOD": { "type": "string", "default": "GET" },
            }
        })));
        assert_eq!(p["config_schema_status"], "declared");
        let mut keys: Vec<&str> = p["config_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["METHOD", "URL"]);
        assert_eq!(p["required_config_keys"], serde_json::json!(["URL"]));
        // The raw schema travels too, so types/defaults/enums are readable.
        assert_eq!(p["config_schema"]["properties"]["METHOD"]["default"], "GET");
    }

    /// A malformed `required` (not an array of strings) must not poison the
    /// key list — the schema is operator-supplied data, not a trusted type.
    #[test]
    fn malformed_required_degrades_to_empty_not_panic() {
        let p = project_config_schema(Some(&serde_json::json!({
            "properties": { "A": {} },
            "required": "A",
        })));
        assert_eq!(p["config_schema_status"], "declared");
        assert_eq!(p["required_config_keys"], serde_json::json!([]));
    }
}

#[cfg(test)]
mod install_dry_run_tests {
    use super::{grants_for_install, install_dry_run_report, install_fuel_report};
    use talos_module_repository::StoredModuleGrants;

    fn v(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| (*s).to_string()).collect()
    }

    /// A reinstall that would drop a stored secret the new template no longer
    /// grants says so BEFORE anything is installed, and the preview is built
    /// from the same `grants_for_install` value the real install writes.
    #[test]
    fn a_reinstall_preview_names_what_would_change_and_what_is_not_carried() {
        let stored = StoredModuleGrants {
            max_fuel: 1_404_000,
            hosts: v(&["gmail.googleapis.com"]),
            methods: v(&["GET"]),
            secrets: v(&["oauth/gmail/u/a@example.com/access_token", "legacy/key"]),
            owner_added: talos_module_repository::OwnerAddedGrants::default(),
        };
        let grants = grants_for_install(
            Some(&stored),
            v(&["gmail.googleapis.com"]),
            v(&["GET"]),
            v(&["oauth/gmail/*"]),
            false,
            false,
            &v(&["GET"]),
        );
        let r = install_dry_run_report(
            "Gmail: List Messages",
            "http-node",
            Some(&stored),
            &grants,
            &[],
            install_fuel_report(Some(stored.max_fuel), 5_850_000, 5_850_000, false),
        );
        // The copy's own limit is kept, and the preview says it is below the template's.
        assert_eq!(r["fuel"]["max_fuel"], 1_404_000);
        assert_eq!(r["fuel"]["source"], "kept");
        assert!(r["fuel"]["note"]
            .as_str()
            .unwrap()
            .contains("BELOW what the template now recommends (5850000)"));
        assert_eq!(r["dry_run"], true);
        assert_eq!(r["first_install"], false);
        assert_eq!(
            r["would_install"]["allowed_secrets"],
            serde_json::json!(["oauth/gmail/u/a@example.com/access_token"])
        );
        assert_eq!(r["current"]["allowed_secrets"].as_array().unwrap().len(), 2);
        assert_eq!(r["grants_changed"], true);
        assert_eq!(
            r["grants_not_carried"]["allowed_secrets"],
            serde_json::json!(["legacy/key"])
        );
        assert!(r["note"].as_str().unwrap().contains("Nothing was compiled"));
    }

    /// CONTROL: a reinstall that changes no grant says `false`, comparing the
    /// lists as sets; a first install has nothing to compare and says `null`.
    #[test]
    fn an_unchanged_reinstall_and_a_first_install_are_told_apart() {
        let stored = StoredModuleGrants {
            max_fuel: 2_000_000,
            hosts: v(&["b.example.com", "a.example.com"]),
            methods: v(&["GET"]),
            secrets: vec![],
            owner_added: talos_module_repository::OwnerAddedGrants::default(),
        };
        let grants = grants_for_install(
            Some(&stored),
            v(&["a.example.com", "b.example.com"]),
            v(&["GET"]),
            vec![],
            false,
            false,
            &v(&["GET"]),
        );
        let r = install_dry_run_report(
            "m",
            "http-node",
            Some(&stored),
            &grants,
            &[],
            install_fuel_report(Some(stored.max_fuel), 2_000_000, 2_000_000, false),
        );
        assert_eq!(r["grants_changed"], false, "{r}");
        assert!(r["grants_not_carried"].as_object().unwrap().is_empty());

        let first = grants_for_install(
            None,
            v(&["a.example.com"]),
            v(&["GET"]),
            v(&["x/y"]),
            false,
            false,
            &v(&["GET"]),
        );
        let r = install_dry_run_report(
            "m",
            "http-node",
            None,
            &first,
            &v(&["z/denied"]),
            install_fuel_report(None, 2_200_000, 2_200_000, false),
        );
        assert_eq!(
            r["fuel"],
            serde_json::json!({"max_fuel": 2_200_000, "source": "template", "template_max_fuel": 2_200_000})
        );
        assert_eq!(r["first_install"], true);
        assert!(r["current"].is_null());
        assert!(r["grants_changed"].is_null());
        assert_eq!(
            r["would_install"]["allowed_secrets"],
            serde_json::json!(["x/y"])
        );
        assert_eq!(r["secrets_not_granted"], serde_json::json!(["z/denied"]));
    }
}

#[cfg(test)]
mod install_fuel_report_tests {
    use super::install_fuel_report;
    use serde_json::json;

    #[test]
    fn a_first_install_takes_the_offered_limit_and_says_where_it_came_from() {
        assert_eq!(
            install_fuel_report(None, 9_900_000, 9_900_000, false),
            json!({"max_fuel": 9_900_000, "source": "template", "template_max_fuel": 9_900_000})
        );
        assert_eq!(
            install_fuel_report(None, 12_000_000, 9_900_000, true),
            json!({"max_fuel": 12_000_000, "source": "fuel_budget", "template_max_fuel": 9_900_000})
        );
    }

    #[test]
    fn a_reinstall_keeps_the_copys_limit_and_says_when_that_is_below_the_template() {
        let below = install_fuel_report(Some(1_404_000), 9_900_000, 9_900_000, false);
        assert_eq!(
            (below["max_fuel"].as_i64(), below["source"].as_str()),
            (Some(1_404_000), Some("kept"))
        );
        let note = below["note"]
            .as_str()
            .expect("a kept limit below the template is called out");
        assert!(
            note.contains("(1404000)")
                && note.contains("(9900000)")
                && note.contains("`fuel_budget`")
        );
        // At or above the template: kept, and nothing to say (an operator's tuning).
        for kept in [9_900_000, 24_000_000] {
            let r = install_fuel_report(Some(kept), 9_900_000, 9_900_000, false);
            assert_eq!(
                (r["max_fuel"].as_i64(), r["source"].as_str()),
                (Some(kept), Some("kept"))
            );
            assert!(r.get("note").is_none(), "{kept}");
        }
    }

    /// The caller passed a budget: it is applied, up or down, and the
    /// template's own figure is still reported beside it.
    #[test]
    fn a_passed_budget_is_applied_and_the_templates_figure_is_still_shown() {
        for stored in [None, Some(1_404_000)] {
            let above = install_fuel_report(stored, 12_000_000, 9_900_000, true);
            assert_eq!(
                above,
                json!({"max_fuel": 12_000_000, "source": "fuel_budget", "template_max_fuel": 9_900_000}),
                "{stored:?}"
            );
            let below = install_fuel_report(stored, 6_000_000, 9_900_000, true);
            assert_eq!(
                (
                    below["max_fuel"].as_i64(),
                    below["source"].as_str(),
                    below["template_max_fuel"].as_i64()
                ),
                (Some(6_000_000), Some("fuel_budget"), Some(9_900_000))
            );
            let note = below["note"]
                .as_str()
                .expect("a budget below the template is called out");
            assert!(
                note.contains("(6000000)") && note.contains("(9900000)"),
                "{note}"
            );
            // The way to the template's figure is the one that works here:
            // omitting the budget on a first install, passing the template's
            // on a reinstall (where omitting keeps the copy's limit).
            let keeps = note.contains("keeps the copy's current limit");
            assert_eq!(keeps, stored.is_some(), "{stored:?}: {note}");
            assert_eq!(
                note.contains("omit fuel_budget."),
                stored.is_none(),
                "{stored:?}: {note}"
            );
        }
    }

    #[test]
    fn the_tool_description_says_a_reinstall_keeps_the_limit() {
        let tools = super::tool_schemas();
        let tool = tools
            .iter()
            .find(|t| t["name"] == "install_module_from_catalog")
            .expect("declared");
        let d = tool["description"].as_str().unwrap();
        assert!(d.contains("`fuel` block") && d.contains("keeps the copy's own limit"));
    }
}
